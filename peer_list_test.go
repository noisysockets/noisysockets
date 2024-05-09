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
	"testing"

	"github.com/noisysockets/noisysockets/types"
	"github.com/stretchr/testify/require"
)

func TestPeerList(t *testing.T) {
	pl := newPeerList()

	defaultGWPrivateKey, err := types.NewPrivateKey()
	require.NoError(t, err)

	pl.add(&Peer{
		name:            "default-gateway",
		publicKey:       defaultGWPrivateKey.Public(),
		addrs:           []netip.Addr{netip.MustParseAddr("10.7.0.1")},
		gatewayForCIDRs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
	})

	privateGWPrivateKey, err := types.NewPrivateKey()
	require.NoError(t, err)

	pl.add(&Peer{
		name:            "private-gateway",
		publicKey:       privateGWPrivateKey.Public(),
		addrs:           []netip.Addr{netip.MustParseAddr("10.7.0.2")},
		gatewayForCIDRs: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
	})

	peerPrivateKey, err := types.NewPrivateKey()
	require.NoError(t, err)

	pl.add(&Peer{
		name:      "peer",
		publicKey: peerPrivateKey.Public(),
		addrs:     []netip.Addr{netip.MustParseAddr("10.7.0.3")},
	})

	// Effectively makes routing decisions for our network.
	t.Run("LookupByAddress", func(t *testing.T) {
		t.Run("Peer IP", func(t *testing.T) {
			p, ok := pl.lookupByAddress(netip.MustParseAddr("10.7.0.3"))
			require.True(t, ok)

			require.Equal(t, "peer", p.name)
		})

		t.Run("Gateway", func(t *testing.T) {
			// Should pick the private gateway due to longer prefix length.
			p, ok := pl.lookupByAddress(netip.MustParseAddr("10.8.0.1"))
			require.True(t, ok)

			require.Equal(t, "private-gateway", p.name)
		})

		t.Run("Default Gateway", func(t *testing.T) {
			p, ok := pl.lookupByAddress(netip.MustParseAddr("1.1.1.1"))
			require.True(t, ok)

			require.Equal(t, "default-gateway", p.name)
		})
	})
}
