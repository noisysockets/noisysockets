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
	stdnet "net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/noisysockets/network"
	"github.com/noisysockets/noisysockets/config"
	latestconfig "github.com/noisysockets/noisysockets/config/v1alpha2"
	"github.com/noisysockets/noisysockets/internal/conn"
	"github.com/noisysockets/noisysockets/internal/transport"
	"github.com/noisysockets/noisysockets/types"
	"github.com/noisysockets/noisysockets/util"
	"github.com/noisysockets/resolver"
)

var (
	_ network.Network = (*NoisySocketsNetwork)(nil)
)

// NoisySocketsNetwork is a wrapper around a userspace WireGuard peer.
type NoisySocketsNetwork struct {
	*network.UserspaceNetwork
	logger            *slog.Logger
	transport         *transport.Transport
	peersByName       map[string]types.NoisePublicKey
	nameForPeer       map[types.NoisePublicKey]string
	peerNamesResolver *peerResolver
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

	peerNamesResolver := newPeerResolver(domain)

	// Add our own addresses to the resolver.
	if conf.Name != "" {
		peerNamesResolver.addPeer(conf.Name, addrs...)
	}

	netConf := &network.UserspaceNetworkConfig{
		Hostname:  conf.Name,
		Domain:    domain,
		Addresses: addrPrefixes,
		ResolverFactory: func(dialContext network.DialContextFunc) resolver.Resolver {
			peerNamesResolver.dialContext = dialContext

			relativeConf := &resolver.RelativeResolverConfig{
				Search: []string{domain, "."},
				NDots:  1,
			}

			var res resolver.Resolver
			if conf.DNS != nil {
				var dnsProtocol resolver.Protocol
				switch conf.DNS.Protocol {
				case latestconfig.DNSProtocolAuto, latestconfig.DNSProtocolUDP:
					dnsProtocol = resolver.ProtocolUDP
				case latestconfig.DNSProtocolTCP:
					dnsProtocol = resolver.ProtocolTCP
				case latestconfig.DNSProtocolTLS:
					dnsProtocol = resolver.ProtocolTLS
				}

				var dnsResolvers []resolver.Resolver
				for _, nameserver := range nameservers {
					dnsResolvers = append(dnsResolvers, resolver.DNS(
						&resolver.DNSResolverConfig{
							Protocol:    dnsProtocol,
							Server:      nameserver,
							Timeout:     util.PointerTo(5 * time.Second),
							DialContext: dialContext,
						},
					))
				}

				res = resolver.Chain(peerNamesResolver, resolver.Retry(resolver.RoundRobin(dnsResolvers...), &resolver.RetryResolverConfig{
					Attempts: 3,
				}))
			} else {
				res = peerNamesResolver
			}

			return resolver.Chain(resolver.IP(), resolver.Relative(res, relativeConf))
		},
	}

	net := &NoisySocketsNetwork{
		logger:            logger,
		peersByName:       make(map[string]types.NoisePublicKey),
		nameForPeer:       make(map[types.NoisePublicKey]string),
		peerNamesResolver: peerNamesResolver,
	}

	mtu := conf.MTU
	if mtu == 0 {
		mtu = transport.DefaultMTU
	}

	nicA, nicB := network.Pipe(mtu, conn.IdealBatchSize)

	ctx := context.Background()
	net.UserspaceNetwork, err = network.Userspace(ctx, logger, nicA, netConf)
	if err != nil {
		return nil, fmt.Errorf("failed to create userspace network: %w", err)
	}

	// TODO: Refactor the transport to directly implement network.Interface.
	// Will then be able to get rid of the pipe (and the additional copy).
	net.transport = transport.NewTransport(ctx, logger, nicB, conn.NewStdNetBind())

	net.transport.SetPrivateKey(privateKey)

	if err := net.transport.UpdatePort(conf.ListenPort); err != nil {
		return nil, fmt.Errorf("failed to update port: %w", err)
	}

	logger.Debug("Adding peers")

	for _, peerConf := range conf.Peers {
		if err := net.AddPeer(peerConf); err != nil {
			return nil, fmt.Errorf("could not add peer %s: %w", peerConf.Name, err)
		}
	}

	logger.Debug("Adding routes")

	for _, routeConf := range conf.Routes {
		if err := net.AddRoute(&routeConf); err != nil {
			return nil, fmt.Errorf("could not add route: %w", err)
		}
	}

	logger.Debug("Bringing transport up")

	if err := net.transport.Up(); err != nil {
		return nil, fmt.Errorf("failed to bring transport up: %w", err)
	}

	return net, nil
}

// Close closes the network.
func (net *NoisySocketsNetwork) Close() error {
	net.logger.Debug("Closing network")

	if err := net.UserspaceNetwork.Close(); err != nil {
		return err
	}

	net.logger.Debug("Closing transport")

	// The pipe will be closed internally by the transport.
	if err := net.transport.Close(); err != nil {
		return err
	}

	return nil
}

// ListenPort returns the port that wireguard is listening on.
func (net *NoisySocketsNetwork) ListenPort() uint16 {
	return net.transport.GetPort()
}

// AddPeer adds a wireguard peer to the network.
func (net *NoisySocketsNetwork) AddPeer(peerConf latestconfig.PeerConfig) error {
	var publicKey types.NoisePublicKey
	if err := publicKey.UnmarshalText([]byte(peerConf.PublicKey)); err != nil {
		return fmt.Errorf("failed to parse peer public key: %w", err)
	}

	net.logger.Debug("Adding peer",
		slog.String("name", peerConf.Name),
		slog.String("peer", publicKey.DisplayString()),
		slog.String("ips", strings.Join(peerConf.IPs, ",")),
		slog.String("endpoint", peerConf.Endpoint))

	peer, err := net.transport.NewPeer(publicKey)
	if err != nil {
		return fmt.Errorf("failed to create peer: %w", err)
	}

	// Regularly send keepalives to the peer to keep NAT mappings valid.
	// This could be configurable but I think it's a good default to avoid footguns.
	peer.SetKeepAliveInterval(25 * time.Second) // TODO: make this configurable?

	peerAddrs, err := util.ParseAddrList(peerConf.IPs)
	if err != nil {
		net.transport.RemovePeer(publicKey)
		return fmt.Errorf("failed to parse peer addresses: %w", err)
	}

	// Set the peer's allowed IPs.
	for _, addr := range peerAddrs {
		peer.AddAllowedIP(netip.PrefixFrom(addr, 8*len(addr.AsSlice())))
	}

	if peerConf.Endpoint != "" {
		peerEndpointHost, peerEndpointPortStr, err := stdnet.SplitHostPort(peerConf.Endpoint)
		if err != nil {
			net.transport.RemovePeer(publicKey)
			return fmt.Errorf("failed to parse peer endpoint: %w", err)
		}

		peerEndpointAddrs, err := stdnet.LookupHost(peerEndpointHost)
		if err != nil {
			net.transport.RemovePeer(publicKey)
			return fmt.Errorf("failed to resolve peer address: %w", err)
		}

		peerEndpointPort, err := strconv.Atoi(peerEndpointPortStr)
		if err != nil {
			net.transport.RemovePeer(publicKey)
			return fmt.Errorf("failed to parse peer port: %w", err)
		}

		// TODO: try all resolved addresses until one works?
		peer.SetEndpoint(&conn.StdNetEndpoint{
			AddrPort: netip.AddrPortFrom(netip.MustParseAddr(peerEndpointAddrs[0]), uint16(peerEndpointPort)),
		})

		peer.Start()

		// Send an initial keepalive so we can complete the handshake ASAP.
		if err := peer.SendKeepalive(); err != nil {
			net.logger.Warn("Failed to send initial keepalive", "peer", peerConf.Name, "error", err)
		}
	}

	if peerConf.Name != "" {
		net.peersByName[peerConf.Name] = publicKey
		net.nameForPeer[publicKey] = peerConf.Name

		net.peerNamesResolver.addPeer(peerConf.Name, peerAddrs...)
	}

	return nil
}

// RemovePeer removes a wireguard peer from the network.
func (net *NoisySocketsNetwork) RemovePeer(publicKey types.NoisePublicKey) error {
	net.logger.Debug("Removing peer", slog.String("peer", publicKey.DisplayString()))

	net.transport.RemovePeer(publicKey)

	delete(net.nameForPeer, publicKey)
	if name, ok := net.nameForPeer[publicKey]; ok {
		net.peerNamesResolver.removePeer(name)
		delete(net.peersByName, name)
	}

	return nil
}

// AddRoute adds a route to the network.
func (net *NoisySocketsNetwork) AddRoute(routeConf *latestconfig.RouteConfig) error {
	net.logger.Debug("Adding route",
		slog.String("destination", routeConf.Destination),
		slog.String("via", routeConf.Via))

	pk, ok := net.peersByName[routeConf.Via]
	if !ok {
		// Assume the peer name is actually a public key.
		if err := pk.UnmarshalText([]byte(routeConf.Via)); err != nil {
			return fmt.Errorf("failed to parse peer name: %w: %w", err, ErrUnknownPeer)
		}
	}

	peer := net.transport.LookupPeer(pk)
	if peer == nil {
		return ErrUnknownPeer
	}

	destination, err := netip.ParsePrefix(routeConf.Destination)
	if err != nil {
		return fmt.Errorf("failed to parse route destination: %w", err)
	}

	peer.AddAllowedIP(destination)

	return nil
}
