// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
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
	"net"
	"net/netip"
	"strconv"

	"context"
	"errors"
	"regexp"
	"time"

	"github.com/noisysockets/noisysockets/config/v1alpha1"
	"github.com/noisysockets/noisysockets/internal/conn"
	"github.com/noisysockets/noisysockets/internal/transport"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type DialContextFn func(ctx context.Context, network, address string) (net.Conn, error)

var (
	errCanceled          = errors.New("operation was canceled")
	errTimeout           = errors.New("i/o timeout")
	errNumericPort       = errors.New("port must be numeric")
	errNoSuitableAddress = errors.New("no suitable address found")
	errMissingAddress    = errors.New("missing address")
)

// Network is a userspace WireGuard peer that exposes
// Dial() and Listen() methods compatible with the net package.
type Network struct {
	transport  *transport.Transport
	pd         *peerDirectory
	stack      *stack.Stack
	localAddrs []netip.Addr
	dnsServers []netip.Addr
}

func NewNetwork(logger *slog.Logger, conf *v1alpha1.Config) (*Network, error) {
	var privateKey transport.NoisePrivateKey
	if err := privateKey.FromString(conf.PrivateKey); err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	var localAddrs []netip.Addr
	for _, ip := range conf.IPs {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, fmt.Errorf("could not parse address: %w", err)
		}
		localAddrs = append(localAddrs, addr)
	}

	pd := newPeerDirectory()

	// Add the local node to the peer directory.
	pd.AddPeer(conf.Name, privateKey.PublicKey(), localAddrs)

	var defaultGateway *transport.NoisePublicKey
	var defaultGatewayAddrs []netip.Addr
	for _, peerConf := range conf.Peers {
		if peerConf.DefaultGateway {
			defaultGateway = &transport.NoisePublicKey{}
			if err := defaultGateway.FromString(peerConf.PublicKey); err != nil {
				return nil, fmt.Errorf("could not parse default gateway public key: %w", err)
			}

			for _, ip := range peerConf.IPs {
				addr, err := netip.ParseAddr(ip)
				if err != nil {
					return nil, fmt.Errorf("could not parse default gateway address: %w", err)
				}

				defaultGatewayAddrs = append(defaultGatewayAddrs, addr)
			}

			break
		}
	}

	var dnsServers []netip.Addr
	for _, ip := range conf.DNSServers {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, fmt.Errorf("could not parse DNS server address: %w", err)
		}

		dnsServers = append(dnsServers, addr)
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
		HandleLocal:        true,
	})

	sourceSink, err := newSourceSink(logger, pd, s, defaultGateway)
	if err != nil {
		return nil, fmt.Errorf("could not create source sink: %w", err)
	}

	var hasV4, hasV6 bool
	for _, addr := range localAddrs {
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

		if err := s.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("could not add protocol address: %v", err)
		}
		if addr.Is4() {
			hasV4 = true
		} else if addr.Is6() {
			hasV6 = true
		}
	}
	if hasV4 {
		var gatewayV4 tcpip.Address
		if defaultGateway != nil {
			for _, addr := range defaultGatewayAddrs {
				if addr.Is4() {
					gatewayV4 = tcpip.AddrFromSlice(addr.AsSlice())
					break
				}
			}
		}

		s.AddRoute(tcpip.Route{
			Destination: header.IPv4EmptySubnet,
			NIC:         1,
			Gateway:     gatewayV4,
		})
	}
	if hasV6 {
		var gatewayV6 tcpip.Address
		if defaultGateway != nil {
			for _, addr := range defaultGatewayAddrs {
				if addr.Is6() {
					gatewayV6 = tcpip.AddrFromSlice(addr.AsSlice())
					break
				}
			}
		}

		s.AddRoute(tcpip.Route{
			Destination: header.IPv6EmptySubnet,
			NIC:         1,
			Gateway:     gatewayV6,
		})
	}

	t := transport.NewTransport(sourceSink, conn.NewStdNetBind(), logger)

	t.SetPrivateKey(privateKey)

	if err := t.UpdatePort(conf.ListenPort); err != nil {
		return nil, fmt.Errorf("failed to update port: %w", err)
	}

	for _, peerConf := range conf.Peers {
		var peerPublicKey transport.NoisePublicKey
		if err := peerPublicKey.FromString(peerConf.PublicKey); err != nil {
			return nil, fmt.Errorf("failed to parse peer public key: %w", err)
		}

		var peerAddrs []netip.Addr
		for _, ip := range peerConf.IPs {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, fmt.Errorf("could not parse peer address %q: %v", ip, err)
			}
			peerAddrs = append(peerAddrs, addr)
		}

		pd.AddPeer(peerConf.Name, peerPublicKey, peerAddrs)

		peer, err := t.NewPeer(peerPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create peer: %w", err)
		}

		if peerConf.Endpoint != "" {
			peerEndpointHost, peerEndpointPortStr, err := net.SplitHostPort(peerConf.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("failed to parse peer endpoint: %w", err)
			}

			peerEndpointAddrs, err := net.LookupHost(peerEndpointHost)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve peer address: %w", err)
			}

			peerEndpointAddr, err := netip.ParseAddr(peerEndpointAddrs[0])
			if err != nil {
				return nil, fmt.Errorf("failed to parse peer address: %w", err)
			}

			peerEndpointPort, err := strconv.Atoi(peerEndpointPortStr)
			if err != nil {
				return nil, fmt.Errorf("failed to parse peer port: %w", err)
			}

			peer.SetEndpoint(&conn.StdNetEndpoint{
				AddrPort: netip.AddrPortFrom(peerEndpointAddr, uint16(peerEndpointPort)),
			})
		}
	}

	if err := t.Up(); err != nil {
		return nil, fmt.Errorf("failed to bring transport up: %w", err)
	}

	return &Network{
		transport:  t,
		pd:         pd,
		stack:      s,
		localAddrs: localAddrs,
		dnsServers: dnsServers,
	}, nil
}

// Close closes the network and releases any resources associated with it.
func (n *Network) Close() error {
	n.stack.Close()
	return n.transport.Close()
}

// LookupHost resolves host names (encoded public keys) to IP addresses.
func (n *Network) LookupHostContext(ctx context.Context, host string) ([]string, error) {
	// Host is an IP address.
	if addr, err := netip.ParseAddr(host); err == nil {
		return []string{addr.String()}, nil
	}

	// Host is the name of a peer.
	var addrs []string
	if peerAddresses, ok := n.pd.LookupPeerAddressesByName(host); ok {
		for _, addr := range peerAddresses {
			addrs = append(addrs, addr.String())
		}

		return addrs, nil
	}

	// Host is a DNS name.
	if len(n.dnsServers) > 0 {
		var err error
		addrs, err = resolveHost(ctx, n.dnsServers, host, n.DialContext)
		if err != nil {
			return nil, err
		}
	}

	if len(addrs) > 0 {
		return addrs, nil
	}

	return nil, &net.DNSError{Err: "no such host", Name: host}
}

// Dial creates a network connection.
func (n *Network) Dial(network, address string) (net.Conn, error) {
	return n.DialContext(context.Background(), network, address)
}

var protoSplitter = regexp.MustCompile(`^(tcp|udp)(4|6)?$`)

// DialContext creates a network connection with a context.
func (n *Network) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	acceptV4, acceptV6 := true, true
	matches := protoSplitter.FindStringSubmatch(network)
	if matches == nil {
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError(network)}
	} else if len(matches[2]) != 0 {
		acceptV4 = matches[2][0] == '4'
		acceptV6 = !acceptV4
	}

	host, sport, err := net.SplitHostPort(address)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: err}
	}

	port, err := strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		return nil, &net.OpError{Op: "dial", Err: errNumericPort}
	}

	allAddr, err := n.LookupHostContext(ctx, host)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: err}
	}

	var addrs []netip.AddrPort
	for _, addr := range allAddr {
		ip, err := netip.ParseAddr(addr)
		if err == nil && ((ip.Is4() && acceptV4) || (ip.Is6() && acceptV6)) {
			addrs = append(addrs, netip.AddrPortFrom(ip, uint16(port)))
		}
	}
	if len(addrs) == 0 && len(allAddr) != 0 {
		return nil, &net.OpError{Op: "dial", Err: errNoSuitableAddress}
	}

	var firstErr error
	for i, addr := range addrs {
		select {
		case <-ctx.Done():
			err := ctx.Err()
			if err == context.Canceled {
				err = errCanceled
			} else if err == context.DeadlineExceeded {
				err = errTimeout
			}
			return nil, &net.OpError{Op: "dial", Err: err}
		default:
		}

		dialCtx := ctx
		if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
			partialDeadline, err := partialDeadline(time.Now(), deadline, len(addrs)-i)
			if err != nil {
				if firstErr == nil {
					firstErr = &net.OpError{Op: "dial", Err: err}
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

		var c net.Conn
		switch matches[1] {
		case "tcp":
			c, err = gonet.DialContextTCP(dialCtx, n.stack, fa, pn)
		case "udp":
			c, err = gonet.DialUDP(n.stack, nil, &fa, pn)
		}
		if err == nil {
			return c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = &net.OpError{Op: "dial", Err: errMissingAddress}
	}

	return nil, firstErr
}

// Listen creates a network listener (only TCP is currently supported).
func (n *Network) Listen(network, address string) (net.Listener, error) {
	acceptV4, acceptV6 := true, true
	matches := protoSplitter.FindStringSubmatch(network)
	if matches == nil {
		return nil, &net.OpError{Op: "listen", Err: net.UnknownNetworkError(network)}
	} else if len(matches[2]) != 0 {
		acceptV4 = matches[2][0] == '4'
		acceptV6 = !acceptV4
	}

	if matches[1] != "tcp" {
		return nil, &net.OpError{Op: "listen", Err: net.UnknownNetworkError(network)}
	}

	host, sport, err := net.SplitHostPort(address)
	if err != nil {
		return nil, &net.OpError{Op: "listen", Err: err}
	}

	port, err := strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		return nil, &net.OpError{Op: "listen", Err: errNumericPort}
	}

	var addr netip.AddrPort
	if host != "" && !(host == "0.0.0.0" || host == "[::]") {
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return nil, &net.OpError{Op: "listen", Err: err}
		}

		if ip.Is4() && !acceptV4 {
			return nil, &net.OpError{Op: "listen", Err: net.UnknownNetworkError("tcp4")}
		}

		if ip.Is6() && !acceptV6 {
			return nil, &net.OpError{Op: "listen", Err: net.UnknownNetworkError("tcp6")}
		}

		addr = netip.AddrPortFrom(ip, uint16(port))
	} else {
		for _, localAddr := range n.localAddrs {
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
	return gonet.ListenTCP(n.stack, fa, pn)
}

// ListenPacket creates a network packet listener (only UDP is currently supported).
// Caveat: The SetDeadline, SetReadDeadline, or SetWriteDeadline f8unctions on the returned
// PacketConn may not work as expected (due to limitations in the gVisor network stack).
func (n *Network) ListenPacket(network, address string) (net.PacketConn, error) {
	acceptV4, acceptV6 := true, true
	matches := protoSplitter.FindStringSubmatch(network)
	if matches == nil {
		return nil, &net.OpError{Op: "listen", Err: net.UnknownNetworkError(network)}
	} else if len(matches[2]) != 0 {
		acceptV4 = matches[2][0] == '4'
		acceptV6 = !acceptV4
	}

	if matches[1] != "udp" {
		return nil, &net.OpError{Op: "listen", Err: net.UnknownNetworkError(network)}
	}

	host, sport, err := net.SplitHostPort(address)
	if err != nil {
		return nil, &net.OpError{Op: "listen", Err: err}
	}

	port, err := strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		return nil, &net.OpError{Op: "listen", Err: errNumericPort}
	}

	var addr netip.AddrPort
	if host != "" && !(host == "0.0.0.0" || host == "[::]") {
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return nil, &net.OpError{Op: "listen", Err: err}
		}

		if ip.Is4() && !acceptV4 {
			return nil, &net.OpError{Op: "listen", Err: net.UnknownNetworkError("udp4")}
		}

		if ip.Is6() && !acceptV6 {
			return nil, &net.OpError{Op: "listen", Err: net.UnknownNetworkError("udp6")}
		}

		addr = netip.AddrPortFrom(ip, uint16(port))
	} else {
		for _, localAddr := range n.localAddrs {
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
	return gonet.DialUDP(n.stack, &fa, nil, pn)
}

// LookupPeerByAddress returns the public key of a peer by its address.
func (n *Network) LookupPeerByAddress(addr netip.Addr) (transport.NoisePublicKey, bool) {
	return n.pd.LookupPeerByAddress(addr)
}

// GetPeerEndpoint returns the public address/endpoint of a peer (if known).
func (n *Network) GetPeerEndpoint(publicKey transport.NoisePublicKey) (netip.AddrPort, error) {
	peer := n.transport.LookupPeer(publicKey)
	if peer == nil {
		return netip.AddrPort{}, fmt.Errorf("unknown peer")
	}

	endpoint := peer.GetEndpoint()
	if endpoint == nil {
		return netip.AddrPort{}, fmt.Errorf("no known endpoint for peer")
	}

	return netip.ParseAddrPort(endpoint.DstToString())
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
		return time.Time{}, errTimeout
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
