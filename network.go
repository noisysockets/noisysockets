// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package noisysockets

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/miekg/dns"
	"github.com/noisysockets/netutil/ptr"
	"github.com/noisysockets/network"
	"github.com/noisysockets/noisysockets/config"
	latestconfig "github.com/noisysockets/noisysockets/config/v1alpha2"
	"github.com/noisysockets/noisysockets/types"
	"github.com/noisysockets/noisysockets/util"
	"github.com/noisysockets/resolver"
)

var _ network.Network = (*NoisySocketsNetwork)(nil)

// NoisySocketsNetwork is a wrapper around a userspace WireGuard peer.
type NoisySocketsNetwork struct {
	*network.UserspaceNetwork
	logger     *slog.Logger
	packetPool *network.PacketPool
	nic        *NoisySocketsInterface
}

// OpenNetwork creates a new network using the provided configuration.
// The returned network is a userspace WireGuard peer that exposes
// Dial() and Listen() methods compatible with the net package.
func OpenNetwork(logger *slog.Logger, conf *latestconfig.Config) (*NoisySocketsNetwork, error) {
	var privateKey types.NoisePrivateKey
	if err := privateKey.UnmarshalText([]byte(conf.PrivateKey)); err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	publicKey := privateKey.Public()

	logger = logger.With(slog.String("id", publicKey.DisplayString()))

	addrs, err := util.ParseAddrList(conf.IPs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IP addresses: %w", err)
	}

	// Single IPs.
	var addrPrefixes []netip.Prefix
	for _, addr := range addrs {
		addrPrefixes = append(addrPrefixes, netip.PrefixFrom(addr, 8*len(addr.AsSlice())))
	}

	var nameservers []netip.AddrPort
	if conf.DNS != nil {
		nameservers, err = util.ParseAddrPortList(conf.DNS.Servers)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DNS nameservers: %w", err)
		}
	}

	domain := config.DefaultDomain
	if conf.DNS != nil && conf.DNS.Domain != "" {
		domain = dns.Fqdn(conf.DNS.Domain)
	}

	// Unbounded packet pool, TODO: make configurable.
	packetPool := network.NewPacketPool(0, false)

	ctx := context.Background()
	nic, err := NewNoisySocketsInterface(ctx, logger, *conf, packetPool)
	if err != nil {
		return nil, fmt.Errorf("failed to create interface: %w", err)
	}

	netConf := network.UserspaceNetworkConfig{
		Hostname:   conf.Name,
		Domain:     domain,
		Addresses:  addrPrefixes,
		PacketPool: packetPool,
		ResolverFactory: func(dialContext network.DialContextFunc) (resolver.Resolver, error) {
			relativeConf := &resolver.RelativeResolverConfig{
				Search: []string{domain, "."},
				NDots:  ptr.To(1),
			}

			var res resolver.Resolver
			if conf.DNS != nil {
				var transport resolver.DNSTransport
				switch conf.DNS.Protocol {
				case latestconfig.DNSProtocolAuto, latestconfig.DNSProtocolUDP:
					transport = resolver.DNSTransportUDP
				case latestconfig.DNSProtocolTCP:
					transport = resolver.DNSTransportTCP
				case latestconfig.DNSProtocolTLS:
					transport = resolver.DNSTransportTLS
				}

				var resolvers []resolver.Resolver
				for _, nameserver := range nameservers {
					resolvers = append(resolvers, resolver.DNS(
						resolver.DNSResolverConfig{
							Server:      nameserver,
							Transport:   ptr.To(transport),
							DialContext: resolver.DialContextFunc(dialContext),
						},
					))
				}

				res = resolver.Sequential(nic.peerNamesResolver, resolver.Retry(resolver.RoundRobin(resolvers...), nil))
			} else {
				res = nic.peerNamesResolver
			}

			return resolver.Sequential(resolver.Literal(), resolver.Relative(res, relativeConf)), nil
		},
	}

	net := &NoisySocketsNetwork{
		logger:     logger,
		packetPool: packetPool,
		nic:        nic,
	}

	net.UserspaceNetwork, err = network.Userspace(ctx, logger, net.nic, netConf)
	if err != nil {
		return nil, fmt.Errorf("failed to create userspace network: %w", err)
	}

	// Lazily set the dial context function for the peer names resolver.
	net.nic.dialContext = net.DialContext

	return net, nil
}

// Close closes the network.
func (net *NoisySocketsNetwork) Close() error {
	net.logger.Debug("Closing network")
	if err := net.UserspaceNetwork.Close(); err != nil {
		return err
	}

	net.logger.Debug("Closing interface")
	if err := net.nic.Close(); err != nil {
		return err
	}

	return nil
}

// ListenPort returns the port that wireguard is listening on.
func (net *NoisySocketsNetwork) ListenPort() uint16 {
	return net.nic.ListenPort()
}

// BufferedPacketsCount returns the number of buffered packets.
// This is exposed for leak testing purposes.
func (net *NoisySocketsNetwork) BufferedPacketsCount() int {
	return net.packetPool.Count()
}

// AddPeer adds a wireguard peer to the network.
func (net *NoisySocketsNetwork) AddPeer(peerConf latestconfig.PeerConfig) error {
	return net.nic.AddPeer(peerConf)
}

// RemovePeer removes a wireguard peer from the network.
func (net *NoisySocketsNetwork) RemovePeer(publicKey types.NoisePublicKey) {
	net.nic.RemovePeer(publicKey)
}

// AddRoute adds a route to the network.
func (net *NoisySocketsNetwork) AddRoute(routeConf latestconfig.RouteConfig) error {
	return net.nic.AddRoute(context.Background(), routeConf)
}

// RemoveRoute removes a route from the network.
func (net *NoisySocketsNetwork) RemoveRoute(destination netip.Prefix) error {
	return net.nic.RemoveRoute(destination)
}
