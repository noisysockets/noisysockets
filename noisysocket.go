/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
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
func NewNoisySocket(logger *slog.Logger, conf *v1alpha1.WireGuardConfig) (*NoisySocket, error) {
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
	if conf.DefaultGatewayName != "" {
		var defaultGatewayPeerConf *v1alpha1.WireGuardPeerConfig
		for i := range conf.Peers {
			if conf.Peers[i].Name == conf.DefaultGatewayName {
				defaultGatewayPeerConf = &conf.Peers[i]
				break
			}
		}

		if defaultGatewayPeerConf == nil {
			return nil, fmt.Errorf("could not find default gateway peer %q", conf.DefaultGatewayName)
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

	sourceSink, n, err := newSourceSink(conf.Name, publicKey, addrs, defaultGateway, defaultGatewayAddrs)
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
