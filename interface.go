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
	"github.com/noisysockets/netutil/ptr"
	"github.com/noisysockets/network"
	"github.com/noisysockets/noisysockets/config"
	latestconfig "github.com/noisysockets/noisysockets/config/v1alpha2"
	"github.com/noisysockets/noisysockets/internal/conn"
	"github.com/noisysockets/noisysockets/internal/transport"
	"github.com/noisysockets/noisysockets/types"
	"github.com/noisysockets/noisysockets/util"
	"github.com/noisysockets/resolver"
	resolverutil "github.com/noisysockets/resolver/util"
)

var _ network.Interface = (*NoisySocketsInterface)(nil)

type NoisySocketsInterface struct {
	logger      *slog.Logger
	pipe        network.Interface
	transport   *transport.Transport
	domain      string
	nameForPeer map[types.NoisePublicKey]string
	// The underlying resolver that maps peer names to IP addresses.
	dialContext       resolver.DialContextFunc
	peerNamesResolver *resolver.HostsResolver
	// The high level resolver that does things like IP literals and search domains.
	resolver resolver.Resolver
}

// NewInterface creates a new WireGuard interface using the provided configuration.
// pr is a peer resolver that can be used to resolve peer addresses from peer names.
func NewInterface(ctx context.Context, logger *slog.Logger, conf latestconfig.Config,
	packetPool *network.PacketPool) (*NoisySocketsInterface, error) {
	nic := &NoisySocketsInterface{
		logger:      logger,
		nameForPeer: make(map[types.NoisePublicKey]string),
	}

	var privateKey types.NoisePrivateKey
	if err := privateKey.UnmarshalText([]byte(conf.PrivateKey)); err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	publicKey := privateKey.Public()

	nic.domain = config.DefaultDomain
	if conf.DNS != nil && conf.DNS.Domain != "" {
		nic.domain = dns.Fqdn(conf.DNS.Domain)
	}

	var err error
	nic.peerNamesResolver, err = resolver.Hosts(&resolver.HostsResolverConfig{
		DialContext: func(ctx context.Context, network, address string) (stdnet.Conn, error) {
			// Used for preferred address ordering so doesn't matter initially.
			if nic.dialContext == nil {
				return nil, fmt.Errorf("no dial context function set")
			}

			return nic.dialContext(ctx, network, address)
		},
		NoHostsFile: ptr.To(true),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create peer names resolver: %w", err)
	}

	nic.resolver = resolver.Sequential(resolver.Literal(), resolver.Relative(nic.peerNamesResolver, &resolver.RelativeResolverConfig{
		Search: []string{nic.domain, "."},
	}))

	// Add our own addresses to the resolver.
	if conf.Name != "" {
		addrs, err := util.ParseAddrList(conf.IPs)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IP addresses: %w", err)
		}

		nic.nameForPeer[publicKey] = conf.Name
		nic.peerNamesResolver.AddHost(resolverutil.Join(conf.Name, nic.domain), addrs...)
	}

	mtu := conf.MTU
	if mtu == 0 {
		mtu = transport.DefaultMTU
	}

	var nicB network.Interface
	nic.pipe, nicB = network.Pipe(&network.PipeConfiguration{
		MTU:        &mtu,
		BatchSize:  ptr.To(conn.IdealBatchSize),
		PacketPool: packetPool,
	})

	// TODO: Refactor the transport to directly implement network.Interface.
	// Will then be able to get rid of the pipe (and the additional copy).
	nic.transport = transport.NewTransport(ctx, logger, nicB, conn.NewStdNetBind(), packetPool)

	nic.transport.SetPrivateKey(privateKey)

	if err := nic.transport.UpdatePort(conf.ListenPort); err != nil {
		return nil, fmt.Errorf("failed to update port: %w", err)
	}

	logger.Debug("Adding peers")

	for _, peerConf := range conf.Peers {
		if err := nic.AddPeer(peerConf); err != nil {
			_ = nic.Close()
			return nil, fmt.Errorf("could not add peer %s: %w", peerConf.Name, err)
		}
	}

	logger.Debug("Adding routes")

	for _, routeConf := range conf.Routes {
		if err := nic.AddRoute(ctx, routeConf); err != nil {
			_ = nic.Close()
			return nil, fmt.Errorf("could not add route: %w", err)
		}
	}

	logger.Debug("Bringing transport up")

	if err := nic.transport.Up(); err != nil {
		_ = nic.Close()
		return nil, fmt.Errorf("failed to bring transport up: %w", err)
	}

	return nic, nil
}

func (nic *NoisySocketsInterface) Close() error {
	nic.logger.Debug("Closing transport")

	// The pipe will be closed internally by the transport.
	if err := nic.transport.Close(); err != nil {
		return err
	}

	return nil
}

func (nic *NoisySocketsInterface) MTU() int {
	return nic.pipe.MTU()
}

func (nic *NoisySocketsInterface) BatchSize() int {
	return nic.pipe.BatchSize()
}

func (nic *NoisySocketsInterface) Read(ctx context.Context, packets []*network.Packet, offset int) ([]*network.Packet, error) {
	return nic.pipe.Read(ctx, packets, offset)
}

func (nic *NoisySocketsInterface) Write(ctx context.Context, packets []*network.Packet) error {
	return nic.pipe.Write(ctx, packets)
}

// ListenPort returns the port that wireguard is listening on.
func (nic *NoisySocketsInterface) ListenPort() uint16 {
	return nic.transport.GetPort()
}

// AddPeer adds a peer to the WireGuard interface.
func (nic *NoisySocketsInterface) AddPeer(peerConf latestconfig.PeerConfig) error {
	var publicKey types.NoisePublicKey
	if err := publicKey.UnmarshalText([]byte(peerConf.PublicKey)); err != nil {
		return fmt.Errorf("failed to parse peer public key: %w", err)
	}

	nic.logger.Debug("Adding peer",
		slog.String("name", peerConf.Name),
		slog.String("peer", publicKey.DisplayString()),
		slog.String("ips", strings.Join(peerConf.IPs, ",")),
		slog.String("endpoint", peerConf.Endpoint))

	peer, err := nic.transport.NewPeer(publicKey)
	if err != nil {
		return fmt.Errorf("failed to create peer: %w", err)
	}

	// Regularly send keepalives to the peer to keep NAT mappings valid.
	// This could be configurable but I think it's a good default to avoid footguns.
	peer.SetKeepAliveInterval(25 * time.Second) // TODO: make this configurable?

	peerAddrs, err := util.ParseAddrList(peerConf.IPs)
	if err != nil {
		nic.transport.RemovePeer(publicKey)
		return fmt.Errorf("failed to parse peer addresses: %w", err)
	}

	// Set the peer's allowed IPs.
	for _, addr := range peerAddrs {
		peer.AddAllowedIP(netip.PrefixFrom(addr, 8*len(addr.AsSlice())))
	}

	if peerConf.Endpoint != "" {
		peerEndpointHost, peerEndpointPortStr, err := stdnet.SplitHostPort(peerConf.Endpoint)
		if err != nil {
			nic.transport.RemovePeer(publicKey)
			return fmt.Errorf("failed to parse peer endpoint: %w", err)
		}

		peerEndpointAddrs, err := stdnet.LookupHost(peerEndpointHost)
		if err != nil {
			nic.transport.RemovePeer(publicKey)
			return fmt.Errorf("failed to resolve peer address: %w", err)
		}

		peerEndpointPort, err := strconv.Atoi(peerEndpointPortStr)
		if err != nil {
			nic.transport.RemovePeer(publicKey)
			return fmt.Errorf("failed to parse peer port: %w", err)
		}

		// TODO: try all resolved addresses until one works?
		peer.SetEndpoint(&conn.StdNetEndpoint{
			AddrPort: netip.AddrPortFrom(netip.MustParseAddr(peerEndpointAddrs[0]), uint16(peerEndpointPort)),
		})

		peer.Start()

		// Send an initial keepalive so we can complete the handshake ASAP.
		if err := peer.SendKeepalive(); err != nil {
			nic.logger.Warn("Failed to send initial keepalive", "peer", peerConf.Name, "error", err)
		}
	}

	// Add the peer to the resolver (if it has a name).
	if peerConf.Name != "" {
		nic.nameForPeer[publicKey] = peerConf.Name
		nic.peerNamesResolver.AddHost(resolverutil.Join(peerConf.Name, nic.domain), peerAddrs...)
	}

	return nil
}

// RemovePeer removes a peer from the WireGuard interface.
func (nic *NoisySocketsInterface) RemovePeer(publicKey types.NoisePublicKey) {
	nic.logger.Debug("Removing peer", slog.String("peer", publicKey.DisplayString()))
	nic.transport.RemovePeer(publicKey)

	if name, ok := nic.nameForPeer[publicKey]; ok {
		nic.peerNamesResolver.RemoveHost(resolverutil.Join(name, nic.domain))
		delete(nic.nameForPeer, publicKey)
	}
}

// AddRoute adds a route to the WireGuard interface.
func (nic *NoisySocketsInterface) AddRoute(ctx context.Context, routeConf latestconfig.RouteConfig) error {
	nic.logger.Debug("Adding route",
		slog.String("destination", routeConf.Destination),
		slog.String("via", routeConf.Via))

	destination, err := netip.ParsePrefix(routeConf.Destination)
	if err != nil {
		return fmt.Errorf("failed to parse route destination: %w", err)
	}

	addrs, err := nic.resolver.LookupNetIP(ctx, "ip", routeConf.Via)
	if err != nil {
		return fmt.Errorf("failed to resolve peer address: %w: %w", err, ErrUnknownPeer)
	}

	// Find the peer that corresponds to the given address.
	for _, addr := range addrs {
		nic.logger.Debug("Resolved peer address", slog.String("address", addr.String()))

		peer := nic.transport.LookupPeerByAddress(addr)
		if peer == nil {
			continue
		}

		peer.AddAllowedIP(destination)

		return nil
	}

	// We couldn't find a peer for the given address.
	return ErrUnknownPeer
}

// RemoveRoute removes a route from the WireGuard interface.
func (nic *NoisySocketsInterface) RemoveRoute(destination netip.Prefix) error {
	nic.logger.Debug("Removing route", slog.String("destination", destination.String()))

	// Find the peer that corresponds to the given address.
	peer := nic.transport.LookupPeerByAddress(destination.Addr())
	if peer == nil {
		return ErrUnknownPeer
	}

	peer.RemoveAllowedIP(destination)

	return nil
}