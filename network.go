// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions of this file are based on code originally from wireguard-go,
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package noisysockets

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"

	"context"
	"regexp"
	"time"

	stdnet "net"

	miekgdns "github.com/miekg/dns"
	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/adapters/gonet"
	"github.com/noisysockets/netstack/pkg/tcpip/network/ipv4"
	"github.com/noisysockets/netstack/pkg/tcpip/network/ipv6"
	"github.com/noisysockets/netstack/pkg/tcpip/stack"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/icmp"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/tcp"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/udp"
	latestconfig "github.com/noisysockets/noisysockets/config/v1alpha2"
	"github.com/noisysockets/noisysockets/internal/conn"
	"github.com/noisysockets/noisysockets/internal/dns"
	"github.com/noisysockets/noisysockets/internal/dns/addrselect"
	"github.com/noisysockets/noisysockets/internal/transport"
	"github.com/noisysockets/noisysockets/internal/util"
	"github.com/noisysockets/noisysockets/network"
	"github.com/noisysockets/noisysockets/types"
)

var (
	ErrCanceled          = fmt.Errorf("operation was canceled")
	ErrTimeout           = fmt.Errorf("i/o timeout")
	ErrNumericPort       = fmt.Errorf("port must be numeric")
	ErrNoSuitableAddress = fmt.Errorf("no suitable address found")
	ErrMissingAddress    = fmt.Errorf("missing address")
	ErrUnknownPeer       = fmt.Errorf("unknown peer")
)

var protoSplitter = regexp.MustCompile(`^(tcp|udp)(4|6)?$`)

type NoisySocketsNetwork struct {
	logger       *slog.Logger
	peers        *peerList
	rt           *routingTable
	transport    *transport.Transport
	stack        *stack.Stack
	hostname     string
	localAddrs   []netip.Addr
	domain       string
	hasV4, hasV6 bool
	resolver     *dns.Resolver
}

// OpenNetwork creates a new network using the provided configuration.
// The returned network is a userspace WireGuard peer that exposes
// Dial() and Listen() methods compatible with the net package.
func OpenNetwork(logger *slog.Logger, conf *latestconfig.Config) (network.Network, error) {
	var privateKey types.NoisePrivateKey
	if err := privateKey.UnmarshalText([]byte(conf.PrivateKey)); err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	publicKey := privateKey.Public()

	logger = logger.With(slog.String("id", publicKey.DisplayString()))

	net := &NoisySocketsNetwork{
		logger: logger,
		peers:  newPeerList(),
		rt:     newRoutingTable(logger),
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
			HandleLocal:        true,
		}),
	}

	if conf.DNS != nil && conf.DNS.Domain != "" {
		net.domain = miekgdns.Fqdn(conf.DNS.Domain)
	}

	// Parse local addresses.
	var err error
	net.localAddrs, err = util.ParseAddrList(conf.IPs)
	if err != nil {
		return nil, fmt.Errorf("could not parse local addresses: %w", err)
	}

	// What IP versions are we using?
	for _, addr := range net.localAddrs {
		if addr.Is4() {
			net.hasV4 = true
		} else if addr.Is6() {
			net.hasV6 = true
		}
	}

	// Add the local node to the list of peers.
	net.hostname = conf.Name
	if net.hostname != "" {
		p := newPeer(nil, net.hostname, publicKey)
		p.AddAddresses(net.localAddrs...)
		net.peers.add(p)
	}

	if conf.DNS != nil {
		nameservers, err := util.ParseAddrPortList(conf.DNS.Nameservers)
		if err != nil {
			return nil, fmt.Errorf("could not parse nameserver addresses: %w", err)
		}

		net.resolver = dns.NewResolver(net, nameservers)
	}

	sourceSink, err := newSourceSink(logger, net.rt, net.stack,
		net.localAddrs, net.hasV4, net.hasV6)
	if err != nil {
		return nil, fmt.Errorf("could not create source sink: %w", err)
	}

	net.transport = transport.NewTransport(logger, sourceSink, conn.NewStdNetBind())

	net.transport.SetPrivateKey(privateKey)

	if err := net.transport.UpdatePort(conf.ListenPort); err != nil {
		return nil, fmt.Errorf("failed to update port: %w", err)
	}

	// Add peers.
	for _, peerConf := range conf.Peers {
		if err := net.AddPeer(peerConf); err != nil {
			return nil, fmt.Errorf("could not add peer %s: %w", peerConf.Name, err)
		}
	}

	// Add routes.
	for _, routeConf := range conf.Routes {
		destination, err := netip.ParsePrefix(routeConf.Destination)
		if err != nil {
			return nil, fmt.Errorf("could not parse route destination: %w", err)
		}

		if err := net.AddRoute(destination, routeConf.Via); err != nil {
			return nil, fmt.Errorf("could not add route: %w", err)
		}
	}

	logger.Debug("Bringing transport up")

	if err := net.transport.Up(); err != nil {
		return nil, fmt.Errorf("failed to bring transport up: %w", err)
	}

	return net, nil
}

func (net *NoisySocketsNetwork) Close() error {
	net.stack.Close()

	if err := net.transport.Close(); err != nil {
		return fmt.Errorf("failed to close transport: %w", err)
	}

	return nil
}

func (net *NoisySocketsNetwork) HasIPv4() bool {
	return net.hasV4
}

func (net *NoisySocketsNetwork) HasIPv6() bool {
	return net.hasV6
}

func (net *NoisySocketsNetwork) Hostname() (string, error) {
	return net.hostname, nil
}

func (net *NoisySocketsNetwork) LookupHost(host string) ([]string, error) {
	logger := net.logger.With(slog.String("host", host))

	logger.Debug("Looking up host")

	var addrs []netip.Addr

	// Host is an IP address.
	if addr, err := netip.ParseAddr(host); err == nil {
		addrs = append(addrs, addr)

		logger.Debug("Host is an IP address")

		goto LOOKUP_HOST_DONE
	}

	// Trim the domain suffix from the host (if present).
	if strings.Count(host, ".") > 1 && net.domain != "" {
		host = strings.TrimSuffix(miekgdns.Fqdn(host), net.domain)
	}

	// Host is the name of a peer.
	if p, ok := net.peers.getByName(strings.TrimSuffix(host, ".")); ok {
		addrs = p.Addresses()

		logger.Debug("Host is the name of a peer")

		goto LOOKUP_HOST_DONE
	}

	// Host is a DNS name.
	if net.resolver != nil {
		var err error
		addrs, err = net.resolver.LookupHost(host)
		if err != nil {
			return nil, err
		}

		if len(addrs) >= 0 {
			logger.Debug("Host is a DNS name")
		}
	}

LOOKUP_HOST_DONE:
	if len(addrs) == 0 {
		return nil, &stdnet.DNSError{Err: "no such host", Name: host}
	}

	addrselect.SortByRFC6724(net, addrs)

	addrsStrings := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		addrsStrings = append(addrsStrings, addr.String())
	}

	return addrsStrings, nil
}

func (net *NoisySocketsNetwork) Dial(network, address string) (stdnet.Conn, error) {
	return net.DialContext(context.Background(), network, address)
}

func (net *NoisySocketsNetwork) DialContext(ctx context.Context, network, address string) (stdnet.Conn, error) {
	net.logger.Debug("Dialing", slog.String("network", network), slog.String("address", address))

	acceptV4, acceptV6 := true, true
	matches := protoSplitter.FindStringSubmatch(network)
	if matches == nil {
		return nil, &stdnet.OpError{Op: "dial", Err: stdnet.UnknownNetworkError(network)}
	} else if len(matches[2]) != 0 {
		acceptV4 = matches[2][0] == '4'
		acceptV6 = !acceptV4
	}

	host, sport, err := stdnet.SplitHostPort(address)
	if err != nil {
		return nil, &stdnet.OpError{Op: "dial", Err: err}
	}

	port, err := strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		return nil, &stdnet.OpError{Op: "dial", Err: ErrNumericPort}
	}

	allAddr, err := net.LookupHost(host)
	if err != nil {
		return nil, &stdnet.OpError{Op: "dial", Err: err}
	}

	var addrs []netip.AddrPort
	for _, addr := range allAddr {
		ip, err := netip.ParseAddr(addr)
		if err == nil && ((ip.Is4() && acceptV4) || (ip.Is6() && acceptV6)) {
			addrs = append(addrs, netip.AddrPortFrom(ip, uint16(port)))
		}
	}
	if len(addrs) == 0 && len(allAddr) != 0 {
		return nil, &stdnet.OpError{Op: "dial", Err: ErrNoSuitableAddress}
	}

	var firstErr error
	for i, addr := range addrs {
		select {
		case <-ctx.Done():
			err := ctx.Err()
			if err == context.Canceled {
				err = ErrCanceled
			} else if err == context.DeadlineExceeded {
				err = ErrTimeout
			}
			return nil, &stdnet.OpError{Op: "dial", Err: err}
		default:
		}

		dialCtx := ctx
		if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
			partialDeadline, err := partialDeadline(time.Now(), deadline, len(addrs)-i)
			if err != nil {
				if firstErr == nil {
					firstErr = &stdnet.OpError{Op: "dial", Err: err}
				}
				break
			}
			if partialDeadline.Before(deadline) {
				var cancel context.CancelFunc
				dialCtx, cancel = context.WithDeadline(ctx, partialDeadline)
				defer cancel()
			}
		}

		fa, pn := convertToFullAddr(addr)

		var c stdnet.Conn
		switch matches[1] {
		case "tcp":
			c, err = gonet.DialContextTCP(dialCtx, net.stack, fa, pn)
		case "udp":
			c, err = gonet.DialUDP(net.stack, nil, &fa, pn)
		}
		if err == nil {
			return c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = &stdnet.OpError{Op: "dial", Err: ErrMissingAddress}
	}

	return nil, firstErr
}

func (net *NoisySocketsNetwork) Listen(network, address string) (stdnet.Listener, error) {
	net.logger.Debug("Listening",
		slog.String("network", network), slog.String("address", address))

	acceptV4, acceptV6 := true, true
	matches := protoSplitter.FindStringSubmatch(network)
	if matches == nil {
		return nil, &stdnet.OpError{Op: "listen", Err: stdnet.UnknownNetworkError(network)}
	} else if len(matches[2]) != 0 {
		acceptV4 = matches[2][0] == '4'
		acceptV6 = !acceptV4
	}

	if matches[1] != "tcp" {
		return nil, &stdnet.OpError{Op: "listen", Err: stdnet.UnknownNetworkError(network)}
	}

	host, sport, err := stdnet.SplitHostPort(address)
	if err != nil {
		return nil, &stdnet.OpError{Op: "listen", Err: err}
	}

	port, err := strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		return nil, &stdnet.OpError{Op: "listen", Err: ErrNumericPort}
	}

	var addr netip.AddrPort
	if host != "" && !(host == "0.0.0.0" || host == "[::]") {
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return nil, &stdnet.OpError{Op: "listen", Err: err}
		}

		if ip.Is4() && !acceptV4 {
			return nil, &stdnet.OpError{Op: "listen", Err: stdnet.UnknownNetworkError("tcp4")}
		}

		if ip.Is6() && !acceptV6 {
			return nil, &stdnet.OpError{Op: "listen", Err: stdnet.UnknownNetworkError("tcp6")}
		}

		addr = netip.AddrPortFrom(ip, uint16(port))
	} else {
		for _, localAddr := range net.localAddrs {
			if localAddr.Is6() && acceptV6 {
				addr = netip.AddrPortFrom(localAddr, uint16(port))
				break
			}
			if localAddr.Is4() && acceptV4 {
				addr = netip.AddrPortFrom(localAddr, uint16(port))
				break
			}
		}
	}

	fa, pn := convertToFullAddr(addr)
	lis, err := gonet.ListenTCP(net.stack, fa, pn)
	if err != nil {
		return nil, err
	}

	return &listener{Listener: lis, peers: net.peers}, nil
}

func (net *NoisySocketsNetwork) ListenPacket(network, address string) (stdnet.PacketConn, error) {
	net.logger.Debug("Listening for packets",
		slog.String("network", network), slog.String("address", address))

	acceptV4, acceptV6 := true, true
	matches := protoSplitter.FindStringSubmatch(network)
	if matches == nil {
		return nil, &stdnet.OpError{Op: "listen", Err: stdnet.UnknownNetworkError(network)}
	} else if len(matches[2]) != 0 {
		acceptV4 = matches[2][0] == '4'
		acceptV6 = !acceptV4
	}

	if matches[1] != "udp" {
		return nil, &stdnet.OpError{Op: "listen", Err: stdnet.UnknownNetworkError(network)}
	}

	host, sport, err := stdnet.SplitHostPort(address)
	if err != nil {
		return nil, &stdnet.OpError{Op: "listen", Err: err}
	}

	port, err := strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		return nil, &stdnet.OpError{Op: "listen", Err: ErrNumericPort}
	}

	var addr netip.AddrPort
	if host != "" && !(host == "0.0.0.0" || host == "[::]") {
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return nil, &stdnet.OpError{Op: "listen", Err: err}
		}

		if ip.Is4() && !acceptV4 {
			return nil, &stdnet.OpError{Op: "listen", Err: stdnet.UnknownNetworkError("udp4")}
		}

		if ip.Is6() && !acceptV6 {
			return nil, &stdnet.OpError{Op: "listen", Err: stdnet.UnknownNetworkError("udp6")}
		}

		addr = netip.AddrPortFrom(ip, uint16(port))
	} else {
		for _, localAddr := range net.localAddrs {
			if localAddr.Is6() && acceptV6 {
				addr = netip.AddrPortFrom(localAddr, uint16(port))
				break
			}
			if localAddr.Is4() && acceptV4 {
				addr = netip.AddrPortFrom(localAddr, uint16(port))
				break
			}
		}
	}

	fa, pn := convertToFullAddr(addr)
	pc, err := gonet.DialUDP(net.stack, &fa, nil, pn)
	if err != nil {
		return nil, err
	}

	return &packetConn{PacketConn: pc, peers: net.peers}, nil
}

// AddPeer adds a wireguard peer to the network.
func (net *NoisySocketsNetwork) AddPeer(peerConf latestconfig.PeerConfig) error {
	var publicKey types.NoisePublicKey
	if err := publicKey.UnmarshalText([]byte(peerConf.PublicKey)); err != nil {
		return fmt.Errorf("failed to parse peer public key: %w", err)
	}

	net.logger.Debug("Adding peer",
		slog.String("name", peerConf.Name),
		slog.String("peer", publicKey.DisplayString()))

	var addrs []netip.Addr
	for _, ip := range peerConf.IPs {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return fmt.Errorf("could not parse peer address %q: %v", ip, err)
		}
		addrs = append(addrs, addr)
	}

	transportPeer, err := net.transport.NewPeer(publicKey)
	if err != nil {
		return fmt.Errorf("failed to create transport peer: %w", err)
	}

	p := newPeer(transportPeer, peerConf.Name, publicKey)
	p.AddAddresses(addrs...)

	// Add the peer to the list of peers.
	net.peers.add(p)

	// Add the peer to the routing table.
	if err := net.rt.update(p); err != nil {
		return fmt.Errorf("could not add peer to routing table: %w", err)
	}

	// Regularly send keepalives to the peer to keep NAT mappings valid.
	// This could be configurable but I think it's a good default to avoid footguns.
	p.SetKeepAliveInterval(25 * time.Second)

	if peerConf.Endpoint != "" {
		peerEndpointHost, peerEndpointPortStr, err := stdnet.SplitHostPort(peerConf.Endpoint)
		if err != nil {
			return fmt.Errorf("failed to parse peer endpoint: %w", err)
		}

		peerEndpointAddrs, err := stdnet.LookupHost(peerEndpointHost)
		if err != nil {
			return fmt.Errorf("failed to resolve peer address: %w", err)
		}

		peerEndpointPort, err := strconv.Atoi(peerEndpointPortStr)
		if err != nil {
			return fmt.Errorf("failed to parse peer port: %w", err)
		}

		// TODO: try all resolved addresses until one works.
		p.SetEndpoint(netip.AddrPortFrom(netip.MustParseAddr(peerEndpointAddrs[0]), uint16(peerEndpointPort)))

		p.Start()

		if err := p.SendKeepalive(); err != nil {
			net.logger.Warn("Failed to send initial keepalive", "peer", peerConf.Name, "error", err)
		}
	}

	return nil
}

// RemovePeer removes a wireguard peer from the network.
func (net *NoisySocketsNetwork) RemovePeer(publicKey types.NoisePublicKey) error {
	net.logger.Debug("Removing peer", slog.String("peer", publicKey.DisplayString()))

	// Remove the peer from the transport.
	net.transport.RemovePeer(publicKey)

	// Remove the peer from the peer list.
	p, ok := net.peers.remove(publicKey)
	if !ok {
		return ErrUnknownPeer
	}

	// Remove the peer from the routing table.
	if err := net.rt.remove(p); err != nil {
		return fmt.Errorf("could not remove peer from routing table: %w", err)
	}

	return nil
}

// GetPeer returns a peer by its public key.
func (net *NoisySocketsNetwork) GetPeer(publicKey types.NoisePublicKey) (*Peer, bool) {
	return net.peers.get(publicKey)
}

// ListPeers returns a list of the public keys of all known peers.
func (net *NoisySocketsNetwork) ListPeers() []types.NoisePublicKey {
	var publicKeys []types.NoisePublicKey
	_ = net.peers.forEach(func(p *Peer) error {
		publicKeys = append(publicKeys, p.PublicKey())
		return nil
	})

	return publicKeys
}

// AddRoute adds a routing table entry for the network.
func (net *NoisySocketsNetwork) AddRoute(destination netip.Prefix, viaPeerName string) error {
	net.logger.Debug("Adding route",
		slog.String("destination", destination.String()),
		slog.String("via", viaPeerName))

	p, ok := net.peers.getByName(viaPeerName)
	if !ok {
		return ErrUnknownPeer
	}

	p.AddDestinationPrefixes(destination)

	if err := net.rt.update(p); err != nil {
		return fmt.Errorf("could not sync routing table: %w", err)
	}

	return nil
}

// RemoveRoute removes a routing table entry for the network.
func (net *NoisySocketsNetwork) RemoveRoute(destination netip.Prefix) error {
	net.logger.Debug("Removing route", slog.String("destination", destination.String()))

	p, ok := net.peers.getByDestination(destination)
	if !ok {
		return fmt.Errorf("could not find peer for destination prefix: %v", destination)
	}

	p.RemoveDestinationPrefixes(destination)

	if err := net.rt.update(p); err != nil {
		return fmt.Errorf("could not sync routing table: %w", err)
	}

	return nil
}

func convertToFullAddr(endpoint netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	if endpoint.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else {
		protoNumber = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(endpoint.Addr().AsSlice()),
		Port: endpoint.Port(),
	}, protoNumber
}

func partialDeadline(now, deadline time.Time, addrsRemaining int) (time.Time, error) {
	if deadline.IsZero() {
		return deadline, nil
	}

	timeRemaining := deadline.Sub(now)
	if timeRemaining <= 0 {
		return time.Time{}, ErrTimeout
	}

	timeout := timeRemaining / time.Duration(addrsRemaining)
	const saneMinimum = 2 * time.Second
	if timeout < saneMinimum {
		if timeRemaining < saneMinimum {
			timeout = timeRemaining
		} else {
			timeout = saneMinimum
		}
	}

	return now.Add(timeout), nil
}
