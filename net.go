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
	"context"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"time"

	"github.com/noisysockets/noisysockets/internal/transport"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type DialContextFn func(ctx context.Context, network, address string) (net.Conn, error)

var (
	errCanceled          = errors.New("operation was canceled")
	errTimeout           = errors.New("i/o timeout")
	errNumericPort       = errors.New("port must be numeric")
	errNoSuitableAddress = errors.New("no suitable address found")
	errMissingAddress    = errors.New("missing address")
)

var protoSplitter = regexp.MustCompile(`^(tcp)(4|6)?$`)

type noisyNet struct {
	stack         *stack.Stack
	localName     string
	localAddrs    []netip.Addr
	peerNames     map[string]transport.NoisePublicKey
	peerAddresses map[transport.NoisePublicKey][]netip.Addr
	dnsServers    []netip.Addr
}

// LookupHost resolves host names (encoded public keys) to IP addresses.
func (n *noisyNet) LookupHostContext(ctx context.Context, host string) ([]string, error) {
	// Host is an IP address.
	if addr, err := netip.ParseAddr(host); err == nil {
		return []string{addr.String()}, nil
	}

	// Host is the name of the local node.
	if host == n.localName {
		var addrs []string
		for _, addr := range n.localAddrs {
			addrs = append(addrs, addr.String())
		}
		return addrs, nil
	}

	// Host is the name of a peer.
	var addrs []string
	if pk, ok := n.peerNames[host]; ok {
		for _, addr := range n.peerAddresses[pk] {
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
func (n *noisyNet) Dial(network, address string) (net.Conn, error) {
	return n.DialContext(context.Background(), network, address)
}

// DialContext creates a network connection with a context.
func (n *noisyNet) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
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
		c, err := gonet.DialContextTCP(dialCtx, n.stack, fa, pn)
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

// Listen creates a network listener.
func (n *noisyNet) Listen(network, address string) (net.Listener, error) {
	acceptV4, acceptV6 := true, true
	matches := protoSplitter.FindStringSubmatch(network)
	if matches == nil {
		return nil, &net.OpError{Op: "listen", Err: net.UnknownNetworkError(network)}
	} else if len(matches[2]) != 0 {
		acceptV4 = matches[2][0] == '4'
		acceptV6 = !acceptV4
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
	if host != "" {
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
