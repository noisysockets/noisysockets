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

	"github.com/noisysockets/noisysockets/config/v1alpha1"
	"github.com/noisysockets/noisysockets/internal/conn"
	"github.com/noisysockets/noisysockets/internal/transport"
)

// NoisySocket is a noisy socket, it exposes Dial() and Listen() methods compatible with the net package.
type NoisySocket struct {
	*noisyNet
	transport *transport.Transport
}

// NewNoisySocket creates a new NoisySocket.
func NewNoisySocket(logger *slog.Logger, conf *v1alpha1.Config) (*NoisySocket, error) {
	var privateKey transport.NoisePrivateKey
	if err := privateKey.FromString(conf.PrivateKey); err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	publicKey := privateKey.PublicKey()

	var addrs []netip.Addr
	for _, ip := range conf.IPs {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, fmt.Errorf("could not parse address: %w", err)
		}
		addrs = append(addrs, addr)
	}

	var defaultGateway *transport.NoisePublicKey
	var defaultGatewayAddrs []netip.Addr
	if conf.DefaultGatewayPeerName != "" {
		var defaultGatewayPeerConf *v1alpha1.WireGuardPeerConfig
		for i := range conf.Peers {
			if conf.Peers[i].Name == conf.DefaultGatewayPeerName {
				defaultGatewayPeerConf = &conf.Peers[i]
				break
			}
		}

		if defaultGatewayPeerConf == nil {
			return nil, fmt.Errorf("could not find default gateway peer %q", conf.DefaultGatewayPeerName)
		}

		defaultGateway = &transport.NoisePublicKey{}
		if err := defaultGateway.FromString(defaultGatewayPeerConf.PublicKey); err != nil {
			return nil, fmt.Errorf("could not parse default gateway public key: %w", err)
		}

		for _, ip := range defaultGatewayPeerConf.IPs {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, fmt.Errorf("could not parse default gateway address: %w", err)
			}

			defaultGatewayAddrs = append(defaultGatewayAddrs, addr)
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

	sourceSink, n, err := newSourceSink(conf.Name, publicKey, addrs, defaultGateway, defaultGatewayAddrs, dnsServers)
	if err != nil {
		return nil, fmt.Errorf("could not create source sink: %w", err)
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

		sourceSink.AddPeer(peerConf.Name, peerPublicKey, peerAddrs)

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

			peer.SetEndpointFromPacket(&conn.StdNetEndpoint{
				AddrPort: netip.AddrPortFrom(peerEndpointAddr, uint16(peerEndpointPort)),
			})
		}
	}

	if err := t.Up(); err != nil {
		return nil, fmt.Errorf("failed to bring transport up: %w", err)
	}

	return &NoisySocket{
		noisyNet:  n,
		transport: t,
	}, nil
}

// Close closes the socket.
func (s *NoisySocket) Close() error {
	return s.transport.Close()
}
