// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package noisysockets

import (
	"net/netip"

	"github.com/noisysockets/noisysockets/internal/transport"
)

type peerDirectory struct {
	peerNames       map[string]transport.NoisePublicKey
	peerAddresses   map[transport.NoisePublicKey][]netip.Addr
	fromPeerAddress map[netip.Addr]transport.NoisePublicKey
}

func newPeerDirectory() *peerDirectory {
	return &peerDirectory{
		peerNames:       make(map[string]transport.NoisePublicKey),
		peerAddresses:   make(map[transport.NoisePublicKey][]netip.Addr),
		fromPeerAddress: make(map[netip.Addr]transport.NoisePublicKey),
	}
}

func (pd *peerDirectory) AddPeer(name string, publicKey transport.NoisePublicKey, addrs []netip.Addr) {
	if name != "" {
		pd.peerNames[name] = publicKey
	}
	pd.peerAddresses[publicKey] = addrs
	for _, addr := range addrs {
		pd.fromPeerAddress[addr] = publicKey
	}
}

func (pd *peerDirectory) LookupPeerAddressesByName(name string) ([]netip.Addr, bool) {
	publicKey, ok := pd.peerNames[name]
	if !ok {
		return nil, false
	}
	addrs, ok := pd.peerAddresses[publicKey]
	return addrs, ok
}

func (pd *peerDirectory) LookupPeerByAddress(addr netip.Addr) (transport.NoisePublicKey, bool) {
	publicKey, ok := pd.fromPeerAddress[addr]
	return publicKey, ok
}
