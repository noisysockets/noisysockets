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
	defaultGateway  *types.NoisePublicKey
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

func (pd *peerDirectory) addPeer(name string, pk types.NoisePublicKey, addrs []netip.Addr,
	defaultGateway bool, gatewayForCIDRs []*stdnet.IPNet) error {
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

	if defaultGateway {
		pd.defaultGateway = &pk
		pd.gatewayPeers[pk] = []*stdnet.IPNet{
			{
				IP:   stdnet.IPv4zero,
				Mask: stdnet.CIDRMask(0, 32),
			},
			{
				IP:   stdnet.IPv6zero,
				Mask: stdnet.CIDRMask(0, 128),
			},
		}
	} else if len(gatewayForCIDRs) > 0 {
		pd.gatewayPeers[pk] = gatewayForCIDRs
	}

	return nil
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
	for pk, subnets := range pd.gatewayPeers {
		for _, subnet := range subnets {
			if subnet.Contains(stdnet.IP(addr.AsSlice())) {
				return pk, true
			}
		}
	}

	return
}

func (pd *peerDirectory) forEachGateway(f func(addrs []netip.Addr, subnets []*stdnet.IPNet, defaultGateway bool) error) error {
	for pk, subnets := range pd.gatewayPeers {
		addrs, ok := pd.peerAddresses[pk]
		if !ok {
			return fmt.Errorf("could not find addresses for gateway peer: %s", pk)
		}

		defaultGateway := pd.defaultGateway != nil && *pd.defaultGateway == pk

		if err := f(addrs, subnets, defaultGateway); err != nil {
			return err
		}
	}

	return nil
}
