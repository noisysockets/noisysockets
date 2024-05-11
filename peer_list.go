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
	mu            sync.RWMutex
	byPublicKey   map[types.NoisePublicKey]*Peer
	byName        map[string]*Peer
	byAddr        map[netip.Addr]*Peer
	byDestination map[netip.Prefix]*Peer
}

func newPeerList() *peerList {
	return &peerList{
		byPublicKey:   make(map[types.NoisePublicKey]*Peer),
		byName:        make(map[string]*Peer),
		byAddr:        make(map[netip.Addr]*Peer),
		byDestination: make(map[netip.Prefix]*Peer),
	}
}

func (pl *peerList) add(p *Peer) {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	pl.byPublicKey[p.PublicKey()] = p

	if p.Name() != "" {
		pl.byName[p.Name()] = p
	}

	for _, addr := range p.Addresses() {
		pl.byAddr[addr] = p
	}

	for _, prefix := range p.DestinationForPrefixes() {
		pl.byDestination[prefix] = p
	}
}

func (pl *peerList) remove(publicKey types.NoisePublicKey) (*Peer, bool) {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	p, ok := pl.byPublicKey[publicKey]
	if !ok {
		return nil, false
	}

	delete(pl.byPublicKey, publicKey)

	if p.Name() != "" {
		delete(pl.byName, p.Name())
	}

	for _, addr := range p.Addresses() {
		delete(pl.byAddr, addr)
	}

	for _, prefix := range p.DestinationForPrefixes() {
		delete(pl.byDestination, prefix)
	}

	return p, true
}

func (pl *peerList) get(publicKey types.NoisePublicKey) (*Peer, bool) {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	p, ok := pl.byPublicKey[publicKey]
	return p, ok
}

func (pl *peerList) getByName(name string) (*Peer, bool) {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	p, ok := pl.byName[name]
	return p, ok
}

func (pl *peerList) getByAddress(addr netip.Addr) (*Peer, bool) {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	p, ok := pl.byAddr[addr]
	return p, ok
}

func (pl *peerList) getByDestination(prefix netip.Prefix) (*Peer, bool) {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	p, ok := pl.byDestination[prefix]
	return p, ok
}

func (pl *peerList) forEach(fn func(*Peer) error) error {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	for _, p := range pl.byPublicKey {
		if err := fn(p); err != nil {
			return err
		}
	}

	return nil
}
