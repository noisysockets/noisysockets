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

	"context"
	"regexp"
	"time"

	stdnet "net"

	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/adapters/gonet"
	"github.com/noisysockets/netstack/pkg/tcpip/header"
	"github.com/noisysockets/netstack/pkg/tcpip/network/ipv4"
	"github.com/noisysockets/netstack/pkg/tcpip/network/ipv6"
	"github.com/noisysockets/netstack/pkg/tcpip/stack"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/icmp"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/tcp"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/udp"
	"github.com/noisysockets/noisysockets/config/v1alpha1"
	"github.com/noisysockets/noisysockets/internal/conn"
	"github.com/noisysockets/noisysockets/internal/dns"
	"github.com/noisysockets/noisysockets/internal/dns/addrselect"
	"github.com/noisysockets/noisysockets/internal/transport"
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
	transport    *transport.Transport
	stack        *stack.Stack
	hostname     string
	localAddrs   []netip.Addr
	dnsServers   []netip.AddrPort
	hasV4, hasV6 bool
}

// NewNetwork creates a new network using the provided configuration.
// The returned network is a userspace WireGuard peer that exposes
// Dial() and Listen() methods compatible with the net package.
func NewNetwork(logger *slog.Logger, conf *v1alpha1.Config) (network.Network, error) {
	var privateKey types.NoisePrivateKey
	if err := privateKey.FromString(conf.PrivateKey); err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	publicKey := privateKey.Public()

	logger = logger.With(slog.String("id", publicKey.DisplayString()))

	net := &NoisySocketsNetwork{
		logger: logger,
		peers:  newPeerList(),
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
			HandleLocal:        true,
		}),
	}

	// Parse local addresses.
	var err error
	net.localAddrs, err = parseIPList(conf.IPs)
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
		net.peers.add(&Peer{
			name:      net.hostname,
			publicKey: publicKey,
			addrs:     net.localAddrs,
		})
	}

	net.dnsServers, err = parseIPPortList(conf.DNSServers)
	if err != nil {
		return nil, fmt.Errorf("could not parse DNS servers: %w", err)
	}

	sourceSink, err := newSourceSink(logger, net.peers, net.stack, net.localAddrs)
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
		if err := net.AddRoute(routeConf); err != nil {
			return nil, fmt.Errorf("could not add route: %w", err)
		}
	}

	// Refresh addresses and routes.
	if err := net.refreshAddressesAndRoutes(); err != nil {
		return nil, fmt.Errorf("could not refresh addresses and routes: %w", err)
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

	// Host is the name of a peer.
	if p, ok := net.peers.lookupByName(host); ok {
		p.Lock()
		defer p.Unlock()

		addrs = p.addrs

		logger.Debug("Host is the name of a peer")

		goto LOOKUP_HOST_DONE
	}

	// Host is a DNS name.
	if len(net.dnsServers) > 0 {
		var err error
		addrs, err = dns.LookupHost(net, net.dnsServers, host)
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
func (net *NoisySocketsNetwork) AddPeer(peerConf v1alpha1.PeerConfig) error {
	var publicKey types.NoisePublicKey
	if err := publicKey.FromString(peerConf.PublicKey); err != nil {
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

	p := &Peer{
		name:      peerConf.Name,
		publicKey: publicKey,
		addrs:     addrs,
	}
	net.peers.add(p)

	var err error
	p.Peer, err = net.transport.NewPeer(publicKey)
	if err != nil {
		return fmt.Errorf("failed to create peer: %w", err)
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

	net.peers.remove(publicKey)

	net.transport.RemovePeer(publicKey)

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
		publicKeys = append(publicKeys, p.publicKey)
		return nil
	})

	return publicKeys
}

// AddRoute adds a routing table entry for the network.
func (net *NoisySocketsNetwork) AddRoute(routeConf v1alpha1.RouteConfig) error {
	net.logger.Debug("Adding route",
		slog.Any("destination", routeConf.Destination),
		slog.String("via", routeConf.Via))

	p, ok := net.peers.lookupByName(routeConf.Via)
	if !ok {
		return ErrUnknownPeer
	}

	p.Lock()

	destinationCIDR, err := netip.ParsePrefix(routeConf.Destination)
	if err != nil {
		p.Unlock()

		return fmt.Errorf("could not parse destination: %w", err)
	}

	p.gatewayForCIDRs = dedupNetworks(append(p.gatewayForCIDRs, destinationCIDR))

	p.Unlock()

	return net.refreshAddressesAndRoutes()
}

// RemoveRoute removes a routing table entry for the network.
func (net *NoisySocketsNetwork) RemoveRoute(destinationCIDR netip.Prefix) error {
	net.logger.Debug("Removing route", slog.String("destination", destinationCIDR.String()))

	p, ok := net.peers.lookupByAddress(destinationCIDR.Addr())
	if !ok {
		return fmt.Errorf("could not find peer for destination address: %v", destinationCIDR)
	}

	p.Lock()

	for i, cidr := range p.gatewayForCIDRs {
		if cidr.String() == destinationCIDR.String() {
			p.gatewayForCIDRs = append(p.gatewayForCIDRs[:i], p.gatewayForCIDRs[i+1:]...)
			break
		}
	}

	p.Unlock()

	return net.refreshAddressesAndRoutes()
}

func (net *NoisySocketsNetwork) refreshAddressesAndRoutes() error {
	net.logger.Debug("Refreshing addresses and routes")

	currentLocalAddrs := make(map[netip.Addr]bool)
	for _, addr := range net.localAddrs {
		currentLocalAddrs[addr] = true
	}

	existingLocalAddrs := make(map[netip.Addr]bool)
	for _, addr := range net.stack.AllAddresses()[1] {
		netipAddr, ok := netip.AddrFromSlice(addr.AddressWithPrefix.Address.AsSlice())
		if !ok {
			continue
		}

		existingLocalAddrs[netipAddr] = true
	}

	// Remove any addresses that are no longer in the configuration.
	for addr := range existingLocalAddrs {
		if _, ok := currentLocalAddrs[addr]; !ok {
			net.logger.Debug("Removing local address", slog.String("address", addr.String()))

			/*	if err := net.stack.RemoveAddress(1, tcpip.AddrFromSlice(addr.AsSlice())); err != nil {
				return fmt.Errorf("could not remove existing address: %v", err)
			}*/
		}
	}

	for _, addr := range net.localAddrs {
		if _, ok := existingLocalAddrs[addr]; !ok {
			var protoNumber tcpip.NetworkProtocolNumber
			if addr.Is4() {
				protoNumber = ipv4.ProtocolNumber
			} else if addr.Is6() {
				protoNumber = ipv6.ProtocolNumber
			}

			protoAddr := tcpip.ProtocolAddress{
				Protocol:          protoNumber,
				AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix(),
			}

			net.logger.Debug("Adding local address", slog.String("address", addr.String()))

			if err := net.stack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); err != nil {
				return fmt.Errorf("could not add address: %v", err)
			}
		}
	}

	var routes []tcpip.Route

	if net.hasV4 {
		routes = append(routes, tcpip.Route{
			NIC:         1,
			Destination: header.IPv4EmptySubnet,
		})
	}
	if net.hasV6 {
		routes = append(routes, tcpip.Route{
			NIC:         1,
			Destination: header.IPv6EmptySubnet,
		})
	}

	err := net.peers.forEach(func(p *Peer) error {
		p.Lock()
		defer p.Unlock()

		var addrV4, addrV6 tcpip.Address
		for _, addr := range p.addrs {
			if net.hasV4 && addr.Is4() {
				addrV4 = tcpip.AddrFromSlice(addr.AsSlice())
			} else if net.hasV6 && addr.Is6() {
				addrV6 = tcpip.AddrFromSlice(addr.AsSlice())
			}
		}

		for _, cidr := range p.gatewayForCIDRs {
			if net.hasV4 && cidr.Addr().Is4() {
				destinationNetwork, err := tcpip.NewSubnet(tcpip.AddrFrom4Slice(cidr.Addr().AsSlice()),
					tcpip.MaskFromBytes(cidr.Masked().Addr().AsSlice()))
				if err != nil {
					return fmt.Errorf("could not parse ipv4 subnet: %v", err)
				}

				net.logger.Debug("Registering ipv4 route",
					slog.String("via", p.name),
					slog.String("addr", addrV4.String()),
					slog.String("destination", destinationNetwork.String()))

				routes = append(routes, tcpip.Route{
					NIC:         1,
					Destination: destinationNetwork,
					Gateway:     addrV4,
				})
			} else if net.hasV6 && cidr.Addr().Is6() {
				destinationNetwork, err := tcpip.NewSubnet(tcpip.AddrFrom16Slice(cidr.Addr().AsSlice()),
					tcpip.MaskFromBytes(cidr.Masked().Addr().AsSlice()))
				if err != nil {
					return fmt.Errorf("could not parse ipv6 subnet: %v", err)
				}

				net.logger.Debug("Registering ipv6 route",
					slog.String("via", p.name),
					slog.String("addr", addrV6.String()),
					slog.String("destination", destinationNetwork.String()))

				routes = append(routes, tcpip.Route{
					NIC:         1,
					Destination: destinationNetwork,
					Gateway:     addrV6,
				})
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("could not register routes: %v", err)
	}

	net.stack.SetRouteTable(routes)

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
