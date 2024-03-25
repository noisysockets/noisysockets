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

	"github.com/noisysockets/noisysockets/internal/conn"
	"github.com/noisysockets/noisysockets/internal/transport"
)

// Config is the configuration for a NoisySocket.
// It is analogous to the configuration for a WireGuard interface.
type Config struct {
	// Name is the hostname of this socket.
	Name string `yaml:"name"`
	// ListenPort is the public port on which this socket listens for incoming packets.
	ListenPort uint16 `yaml:"listenPort"`
	// PrivateKey is the private key for this socket.
	PrivateKey string `yaml:"privateKey"`
	// IPs is a list of IP addresses assigned to this socket.
	IPs []string `yaml:"ips"`
	// Peers is a list of known peers to which this socket can send and receive packets.
	Peers []PeerConfig `yaml:"peers"`
}

// PeerConfig is the configuration for a known peer.
type PeerConfig struct {
	// Name is the hostname of the peer.
	Name string `yaml:"name"`
	// PublicKey is the public key of the peer.
	PublicKey string `yaml:"publicKey"`
	// Endpoint is an optional endpoint to which the peer's packets should be sent.
	// If not specified, we will attempt to discover the peer's endpoint from its packets.
	Endpoint string `yaml:"endpoint"`
	// IPs is a list of IP addresses assigned to the peer.
	IPs []string `yaml:"ips"`
}

// NoisySocket is a noisy socket, it exposes Dial() and Listen() methods compatible with the net package.
type NoisySocket struct {
	*noisyNet
	transport *transport.Transport
}

// NewNoisySocket creates a new NoisySocket.
func NewNoisySocket(logger *slog.Logger, config *Config) (*NoisySocket, error) {
	var privateKey transport.NoisePrivateKey
	if err := privateKey.FromString(config.PrivateKey); err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	publicKey := privateKey.PublicKey()

	var addrs []netip.Addr
	for _, ip := range config.IPs {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, fmt.Errorf("could not parse address: %v", err)
		}
		addrs = append(addrs, addr)
	}

	sourceSink, n, err := newSourceSink(config.Name, publicKey, addrs)
	if err != nil {
		return nil, fmt.Errorf("could not create source sink: %v", err)
	}

	t := transport.NewTransport(sourceSink, conn.NewStdNetBind(), logger)

	t.SetPrivateKey(privateKey)

	if err := t.UpdatePort(config.ListenPort); err != nil {
		return nil, fmt.Errorf("failed to update port: %v", err)
	}

	for _, peerConfig := range config.Peers {
		var peerPublicKey transport.NoisePublicKey
		if err := peerPublicKey.FromString(peerConfig.PublicKey); err != nil {
			return nil, fmt.Errorf("failed to parse peer public key: %v", err)
		}

		var peerAddrs []netip.Addr
		for _, ip := range peerConfig.IPs {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, fmt.Errorf("could not parse peer address %q: %v", ip, err)
			}
			peerAddrs = append(peerAddrs, addr)
		}

		sourceSink.AddPeer(peerConfig.Name, peerPublicKey, peerAddrs)

		peer, err := t.NewPeer(peerPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create peer: %v", err)
		}

		if peerConfig.Endpoint != "" {
			peerEndpointHost, peerEndpointPortStr, err := net.SplitHostPort(peerConfig.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("failed to parse peer endpoint: %v", err)
			}

			peerEndpointAddrs, err := net.LookupHost(peerEndpointHost)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve peer address: %v", err)
			}

			peerEndpointAddr, err := netip.ParseAddr(peerEndpointAddrs[0])
			if err != nil {
				return nil, fmt.Errorf("failed to parse peer address: %v", err)
			}

			peerEndpointPort, err := strconv.Atoi(peerEndpointPortStr)
			if err != nil {
				return nil, fmt.Errorf("failed to parse peer port: %v", err)
			}

			peer.SetEndpointFromPacket(&conn.StdNetEndpoint{
				AddrPort: netip.AddrPortFrom(peerEndpointAddr, uint16(peerEndpointPort)),
			})
		}
	}

	if err := t.Up(); err != nil {
		return nil, fmt.Errorf("failed to bring transport up: %v", err)
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
