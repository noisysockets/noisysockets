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
	stdnet "net"
	"net/netip"
	"sync"

	"github.com/noisysockets/noisysockets/internal/transport"
	"github.com/noisysockets/noisysockets/types"
)

type peer struct {
	sync.Mutex
	*transport.Peer
	name           string
	publicKey      types.NoisePublicKey
	addrs          []netip.Addr
	defaultGateway bool
	destinations   []*stdnet.IPNet
}

type peerList struct {
	mu         sync.RWMutex
	m          map[types.NoisePublicKey]*peer
	addrToPeer map[netip.Addr]*peer
}

func newPeerList() *peerList {
	return &peerList{
		m:          make(map[types.NoisePublicKey]*peer),
		addrToPeer: make(map[netip.Addr]*peer),
	}
}

func (pl *peerList) add(peer *peer) {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	pl.m[peer.publicKey] = peer

	// invalidate the cache
	clear(pl.addrToPeer)
}

func (pl *peerList) remove(publicKey types.NoisePublicKey) {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	delete(pl.m, publicKey)

	// invalidate the cache
	clear(pl.addrToPeer)
}

func (pl *peerList) get(publicKey types.NoisePublicKey) (*peer, bool) {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	p, ok := pl.m[publicKey]
	return p, ok
}

func (pl *peerList) lookupByAddress(addr netip.Addr) (*peer, bool) {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	// Cache the expensive address to peer lookup.
	if len(pl.addrToPeer) == 0 {
		for _, p := range pl.m {
			p.Lock()
			for _, addr := range p.addrs {
				pl.addrToPeer[addr] = p
			}
			p.Unlock()
		}
	}

	// Look for a peer that has the address.
	if p, ok := pl.addrToPeer[addr]; ok {
		return p, true
	}

	// Perhaps we have a gateway peer that matches.
	for _, p := range pl.m {
		p.Lock()
		for _, n := range p.destinations {
			if n.Contains(stdnet.IP(addr.AsSlice())) {
				p.Unlock()
				return p, true
			}
		}
		p.Unlock()
	}

	return nil, false
}

func (pl *peerList) lookupByName(name string) (*peer, bool) {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	for _, p := range pl.m {
		p.Lock()
		if p.name == name || p.publicKey.String() == name {
			p.Unlock()
			return p, true
		}
		p.Unlock()
	}

	return nil, false
}

func (pl *peerList) forEach(fn func(*peer) error) error {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	for _, p := range pl.m {
		if err := fn(p); err != nil {
			return err
		}
	}

	return nil
}
