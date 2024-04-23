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
	stdnet "net"
	"net/netip"

	"github.com/noisysockets/noisysockets/types"
)

type gatewayPeer struct {
	publicKey    types.NoisePublicKey
	destinations []*stdnet.IPNet
	isDefault    bool
}

type peerDirectory struct {
	peerNames       map[string]types.NoisePublicKey
	peerAddresses   map[types.NoisePublicKey][]netip.Addr
	fromPeerAddress map[netip.Addr]types.NoisePublicKey
	gatewayPeers    map[types.NoisePublicKey]gatewayPeer
}

func newPeerDirectory() *peerDirectory {
	return &peerDirectory{
		peerNames:       make(map[string]types.NoisePublicKey),
		peerAddresses:   make(map[types.NoisePublicKey][]netip.Addr),
		fromPeerAddress: make(map[netip.Addr]types.NoisePublicKey),
		gatewayPeers:    make(map[types.NoisePublicKey]gatewayPeer),
	}
}

func (pd *peerDirectory) addPeer(name string, pk types.NoisePublicKey, addrs []netip.Addr) error {
	pd.peerNames[pk.String()] = pk

	if name != "" {
		pd.peerNames[name] = pk
	}

	pd.peerAddresses[pk] = addrs
	for _, addr := range addrs {
		if _, ok := pd.fromPeerAddress[addr]; ok {
			return fmt.Errorf("address %s already in use", addr)
		}

		pd.fromPeerAddress[addr] = pk
	}

	return nil
}

func (pd *peerDirectory) addGateway(pk types.NoisePublicKey, destinations []*stdnet.IPNet, isDefault bool) error {
	if gwPeer, ok := pd.gatewayPeers[pk]; ok {
		gwPeer.destinations = dedupNetworks(append(gwPeer.destinations, destinations...))
		if isDefault {
			gwPeer.isDefault = true
		}
		pd.gatewayPeers[pk] = gwPeer
	} else {
		pd.gatewayPeers[pk] = gatewayPeer{
			publicKey:    pk,
			destinations: dedupNetworks(destinations),
			isDefault:    isDefault,
		}
	}

	return nil
}

func (pd *peerDirectory) lookupPeerByName(name string) (types.NoisePublicKey, bool) {
	pk, ok := pd.peerNames[name]
	return pk, ok
}

func (pd *peerDirectory) lookupPeerAddressesByName(name string) ([]netip.Addr, bool) {
	pk, ok := pd.peerNames[name]
	if !ok {
		return nil, false
	}
	addrs, ok := pd.peerAddresses[pk]
	return addrs, ok
}

func (pd *peerDirectory) lookupPeerByAddress(addr netip.Addr) (types.NoisePublicKey, bool) {
	pk, ok := pd.fromPeerAddress[addr]
	return pk, ok
}

func (pd *peerDirectory) gatewayForAddress(addr netip.Addr) (pk types.NoisePublicKey, ok bool) {
	for _, gwPeer := range pd.gatewayPeers {
		for _, destination := range gwPeer.destinations {
			if destination.Contains(stdnet.IP(addr.AsSlice())) {
				return gwPeer.publicKey, true
			}
		}
	}

	return
}

func (pd *peerDirectory) forEachGateway(f func(addrs []netip.Addr, destinations []*stdnet.IPNet, isDefault bool) error) error {
	for _, gwPeer := range pd.gatewayPeers {
		addrs, ok := pd.peerAddresses[gwPeer.publicKey]
		if !ok {
			return fmt.Errorf("could not find addresses for gateway peer: %s", gwPeer.publicKey)
		}

		if err := f(addrs, gwPeer.destinations, gwPeer.isDefault); err != nil {
			return err
		}
	}

	return nil
}

func dedupNetworks(networks []*stdnet.IPNet) []*stdnet.IPNet {
	seen := make(map[string]struct{})
	var deduped []*stdnet.IPNet
	for _, net := range networks {
		key := net.String()
		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}
		deduped = append(deduped, net)
	}

	return deduped
}
