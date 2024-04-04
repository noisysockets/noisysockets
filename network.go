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
	"net/netip"
	"strconv"

	"context"
	"errors"
	"regexp"
	"time"

	stdnet "net"

	"github.com/noisysockets/noisysockets/config/v1alpha1"
	"github.com/noisysockets/noisysockets/internal/conn"
	"github.com/noisysockets/noisysockets/internal/dns"
	"github.com/noisysockets/noisysockets/internal/dns/addrselect"
	"github.com/noisysockets/noisysockets/internal/transport"
	"github.com/noisysockets/noisysockets/network"
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

var (
	errCanceled          = errors.New("operation was canceled")
	errTimeout           = errors.New("i/o timeout")
	errNumericPort       = errors.New("port must be numeric")
	errNoSuitableAddress = errors.New("no suitable address found")
	errMissingAddress    = errors.New("missing address")
)

var protoSplitter = regexp.MustCompile(`^(tcp|udp)(4|6)?$`)

type NoisySocketsNetwork struct {
	transport    *transport.Transport
	pd           *peerDirectory
	stack        *stack.Stack
	localAddrs   []netip.Addr
	dnsServers   []netip.AddrPort
	hasV4, hasV6 bool
}

// NewNetwork creates a new network using the provided configuration.
// The returned network is a userspace WireGuard peer that exposes
// Dial() and Listen() methods compatible with the net package.
func NewNetwork(logger *slog.Logger, conf *v1alpha1.Config) (network.Network, error) {
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

	var dnsServers []netip.AddrPort
	for _, addr := range conf.DNSServers {
		var dnsServer netip.AddrPort

		// Do we have a port specified?
		if _, _, err := stdnet.SplitHostPort(addr); err == nil {
			dnsServer, err = netip.ParseAddrPort(addr)
			if err != nil {
				return nil, fmt.Errorf("could not parse DNS server address: %w", err)
			}
		} else {
			addr, err := netip.ParseAddr(addr)
			if err != nil {
				return nil, fmt.Errorf("could not parse DNS server address: %w", err)
			}

			dnsServer = netip.AddrPortFrom(addr, 0)
		}

		dnsServers = append(dnsServers, dnsServer)
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

		// Regularly send keepalives to the peer to keep NAT mappings valid.
		// This could be configurable but I think it's a good default to avoid footguns.
		peer.SetKeepAliveInterval(25 * time.Second)

		if peerConf.Endpoint != "" {
			peerEndpointHost, peerEndpointPortStr, err := stdnet.SplitHostPort(peerConf.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("failed to parse peer endpoint: %w", err)
			}

			peerEndpointAddrs, err := stdnet.LookupHost(peerEndpointHost)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve peer address: %w", err)
			}

			peerEndpointPort, err := strconv.Atoi(peerEndpointPortStr)
			if err != nil {
				return nil, fmt.Errorf("failed to parse peer port: %w", err)
			}

			peer.SetEndpoint(&conn.StdNetEndpoint{
				AddrPort: netip.AddrPortFrom(netip.MustParseAddr(peerEndpointAddrs[0]), uint16(peerEndpointPort)),
			})

			if err := peer.SendKeepalive(); err != nil {
				logger.Warn("Failed to send initial keepalive", "peer", peerConf.Name, "error", err)
			}
		}

	}

	if err := t.Up(); err != nil {
		return nil, fmt.Errorf("failed to bring transport up: %w", err)
	}

	return &NoisySocketsNetwork{
		transport:  t,
		pd:         pd,
		stack:      s,
		localAddrs: localAddrs,
		dnsServers: dnsServers,
		hasV4:      hasV4,
		hasV6:      hasV6,
	}, nil
}

func (net *NoisySocketsNetwork) Close() error {
	net.stack.Close()
	return net.transport.Close()
}

func (net *NoisySocketsNetwork) HasIPv4() bool {
	return net.hasV4
}

func (net *NoisySocketsNetwork) HasIPv6() bool {
	return net.hasV6
}

func (net *NoisySocketsNetwork) LookupHost(host string) ([]string, error) {
	var addrs []netip.Addr

	// Host is an IP address.
	if addr, err := netip.ParseAddr(host); err == nil {
		addrs = append(addrs, addr)

		goto LOOKUP_HOST_DONE
	}

	// Host is the name of a peer.
	if peerAddrs, ok := net.pd.LookupPeerAddressesByName(host); ok {
		for _, peerAddr := range peerAddrs {
			if net.hasV4 && peerAddr.Is4() {
				addrs = append(addrs, peerAddr)
			} else if net.hasV6 && peerAddr.Is6() {
				addrs = append(addrs, peerAddr)
			}
		}

		goto LOOKUP_HOST_DONE
	}

	// Host is a DNS name.
	if len(net.dnsServers) > 0 {
		var err error
		addrs, err = dns.LookupHost(net, net.dnsServers, host)
		if err != nil {
			return nil, err
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
		return nil, &stdnet.OpError{Op: "dial", Err: errNumericPort}
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
		return nil, &stdnet.OpError{Op: "dial", Err: errNoSuitableAddress}
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
		firstErr = &stdnet.OpError{Op: "dial", Err: errMissingAddress}
	}

	return nil, firstErr
}

func (net *NoisySocketsNetwork) Listen(network, address string) (stdnet.Listener, error) {
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
		return nil, &stdnet.OpError{Op: "listen", Err: errNumericPort}
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
	return gonet.ListenTCP(net.stack, fa, pn)
}

func (net *NoisySocketsNetwork) ListenPacket(network, address string) (stdnet.PacketConn, error) {
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
		return nil, &stdnet.OpError{Op: "listen", Err: errNumericPort}
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
	return gonet.DialUDP(net.stack, &fa, nil, pn)
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
