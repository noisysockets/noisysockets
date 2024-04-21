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

type peerDirectory struct {
	peerNames       map[string]types.NoisePublicKey
	peerAddresses   map[types.NoisePublicKey][]netip.Addr
	fromPeerAddress map[netip.Addr]types.NoisePublicKey
	gatewayPeers    map[types.NoisePublicKey][]*stdnet.IPNet
}

func newPeerDirectory() *peerDirectory {
	return &peerDirectory{
		peerNames:       make(map[string]types.NoisePublicKey),
		peerAddresses:   make(map[types.NoisePublicKey][]netip.Addr),
		fromPeerAddress: make(map[netip.Addr]types.NoisePublicKey),
		gatewayPeers:    make(map[types.NoisePublicKey][]*stdnet.IPNet),
	}
}

func (pd *peerDirectory) AddPeer(name string, publicKey types.NoisePublicKey, addrs []netip.Addr, defaultGateway bool) error {
	if name != "" {
		pd.peerNames[name] = publicKey
	}

	pd.peerAddresses[publicKey] = addrs
	for _, addr := range addrs {
		if _, ok := pd.fromPeerAddress[addr]; ok {
			return fmt.Errorf("address %s already in use", addr)
		}

		pd.fromPeerAddress[addr] = publicKey
	}

	// TODO: support multiple gateways/routes.
	if defaultGateway {
		pd.gatewayPeers[publicKey] = []*stdnet.IPNet{
			{
				IP:   stdnet.IPv4zero,
				Mask: stdnet.CIDRMask(0, 32),
			},
			{
				IP:   stdnet.IPv6zero,
				Mask: stdnet.CIDRMask(0, 128),
			},
		}
	}

	return nil
}

func (pd *peerDirectory) LookupPeerAddressesByName(name string) ([]netip.Addr, bool) {
	publicKey, ok := pd.peerNames[name]
	if !ok {
		return nil, false
	}
	addrs, ok := pd.peerAddresses[publicKey]
	return addrs, ok
}

func (pd *peerDirectory) LookupPeerByAddress(addr netip.Addr) (types.NoisePublicKey, bool) {
	publicKey, ok := pd.fromPeerAddress[addr]
	return publicKey, ok
}

func (pd *peerDirectory) IsGateway(publicKey types.NoisePublicKey) bool {
	_, ok := pd.gatewayPeers[publicKey]
	return ok
}

func (pd *peerDirectory) GatewayForAddress(addr netip.Addr) (pk types.NoisePublicKey, ok bool) {
	for pk, subnets := range pd.gatewayPeers {
		for _, subnet := range subnets {
			if subnet.Contains(stdnet.IP(addr.AsSlice())) {
				return pk, true
			}
		}
	}

	return
}
