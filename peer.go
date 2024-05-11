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
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"github.com/noisysockets/noisysockets/internal/conn"
	"github.com/noisysockets/noisysockets/internal/transport"
	"github.com/noisysockets/noisysockets/types"
)

var (
	ErrNoEndpoint = fmt.Errorf("no known endpoint for peer")
)

// Peer represents a wireguard peer in the network.
type Peer struct {
	*transport.Peer
	mu                     sync.RWMutex
	name                   string
	publicKey              types.NoisePublicKey
	addrs                  []netip.Addr
	destinationForPrefixes []netip.Prefix
}

func newPeer(transportPeer *transport.Peer, name string, publicKey types.NoisePublicKey) *Peer {
	return &Peer{
		Peer:      transportPeer,
		name:      name,
		publicKey: publicKey,
	}
}

// Name returns the human friendly name of the peer.
func (p *Peer) Name() string {
	return p.name
}

// PublicKey returns the public key of the peer.
func (p *Peer) PublicKey() types.NoisePublicKey {
	return p.publicKey
}

// Addresses returns the list of addresses of the peer.
func (p *Peer) Addresses() []netip.Addr {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.addrs
}

// AddAddress adds one or more addresses to the peer.
func (p *Peer) AddAddresses(addrs ...netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.addrs = slices.CompactFunc(append(p.addrs, addrs...), func(a, b netip.Addr) bool { return a == b })
}

// RemoveAddress removes one or more addresses from the peer.
func (p *Peer) RemoveAddresses(addrs ...netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()

	toRemove := make(map[netip.Addr]bool, len(addrs))
	for _, a := range addrs {
		toRemove[a] = true
	}

	for i, a := range p.addrs {
		if toRemove[a] {
			p.addrs = append(p.addrs[:i], p.addrs[i+1:]...)
		}
	}
}

// DestinationForPrefixes returns the list of prefixes the peer is the destination for.
func (p *Peer) DestinationForPrefixes() []netip.Prefix {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.destinationForPrefixes
}

// AddDestinationForPrefix adds one or more prefixes the peer is the destination for.
func (p *Peer) AddDestinationPrefixes(prefixes ...netip.Prefix) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.destinationForPrefixes = slices.CompactFunc(append(p.destinationForPrefixes, prefixes...),
		func(a, b netip.Prefix) bool { return a == b })
}

// RemoveDestinationForPrefix removes one or more prefixes the peer is the destination for.
func (p *Peer) RemoveDestinationPrefixes(prefixes ...netip.Prefix) {
	p.mu.Lock()
	defer p.mu.Unlock()

	toRemove := make(map[netip.Prefix]bool, len(prefixes))
	for _, prefix := range prefixes {
		toRemove[prefix] = true
	}

	for i, prefix := range p.destinationForPrefixes {
		if toRemove[prefix] {
			p.destinationForPrefixes = append(p.destinationForPrefixes[:i], p.destinationForPrefixes[i+1:]...)
		}
	}
}

// GetEndpoint returns the endpoint (public address) of the peer.
func (p *Peer) GetEndpoint() (netip.AddrPort, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	endpoint := p.Peer.GetEndpoint()
	if endpoint == nil {
		return netip.AddrPort{}, ErrNoEndpoint
	}

	return netip.ParseAddrPort(endpoint.DstToString())
}

// SetEndpoint sets the endpoint (public address) of the peer.
func (p *Peer) SetEndpoint(endpoint netip.AddrPort) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.Peer.SetEndpoint(&conn.StdNetEndpoint{AddrPort: endpoint})
}
