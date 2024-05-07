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
	"net/netip"
	"sync"

	"github.com/noisysockets/noisysockets/types"
)

type peerList struct {
	mu         sync.RWMutex
	m          map[types.NoisePublicKey]*Peer
	addrToPeer map[netip.Addr]*Peer
}

func newPeerList() *peerList {
	return &peerList{
		m:          make(map[types.NoisePublicKey]*Peer),
		addrToPeer: make(map[netip.Addr]*Peer),
	}
}

func (pl *peerList) add(peer *Peer) {
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

func (pl *peerList) get(publicKey types.NoisePublicKey) (*Peer, bool) {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	p, ok := pl.m[publicKey]
	return p, ok
}

func (pl *peerList) lookupByAddress(addr netip.Addr) (*Peer, bool) {
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
	var gatewayPeer *Peer

	maxPrefixLength := -1
	for _, p := range pl.m {
		p.Lock()
		for _, cidr := range p.gatewayForCIDRs {
			if cidr.Contains(addr) {
				prefixLength := cidr.Bits()
				if prefixLength > maxPrefixLength {
					gatewayPeer = p
					maxPrefixLength = prefixLength
				}
			}
		}
		p.Unlock()
	}

	if gatewayPeer != nil {
		return gatewayPeer, true
	}

	return nil, false
}

func (pl *peerList) lookupByName(name string) (*Peer, bool) {
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

func (pl *peerList) forEach(fn func(*Peer) error) error {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	for _, p := range pl.m {
		if err := fn(p); err != nil {
			return err
		}
	}

	return nil
}
