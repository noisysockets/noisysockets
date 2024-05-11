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

	"github.com/neilotoole/slogt"
	"github.com/noisysockets/noisysockets/types"
	"github.com/stretchr/testify/require"
)

func TestRoutingTable(t *testing.T) {
	rt := newRoutingTable(slogt.New(t))

	defaultGWPrivateKey, err := types.NewPrivateKey()
	require.NoError(t, err)

	p := newPeer(nil, "default-gateway", defaultGWPrivateKey.Public())
	p.AddAddresses(netip.MustParseAddr("10.7.0.1"))
	p.AddDestinationPrefixes(netip.MustParsePrefix("0.0.0.0/0"))

	require.NoError(t, rt.update(p))

	privateGWPrivateKey, err := types.NewPrivateKey()
	require.NoError(t, err)

	p = newPeer(nil, "private-gateway", privateGWPrivateKey.Public())
	p.AddAddresses(netip.MustParseAddr("10.7.0.2"))
	p.AddDestinationPrefixes(netip.MustParsePrefix("10.8.0.0/24"))

	require.NoError(t, rt.update(p))

	peerPrivateKey, err := types.NewPrivateKey()
	require.NoError(t, err)

	p = newPeer(nil, "peer", peerPrivateKey.Public())
	p.AddAddresses(netip.MustParseAddr("10.7.0.3"))

	require.NoError(t, rt.update(p))

	t.Run("Destination", func(t *testing.T) {
		t.Run("Peer IP", func(t *testing.T) {
			p, ok := rt.destination(netip.MustParseAddr("10.7.0.3"))
			require.True(t, ok)

			require.Equal(t, "peer", p.Name())
		})

		t.Run("Gateway", func(t *testing.T) {
			// Should pick the private gateway due to longer prefix length.
			p, ok := rt.destination(netip.MustParseAddr("10.8.0.1"))
			require.True(t, ok)

			require.Equal(t, "private-gateway", p.Name())
		})

		t.Run("Default Gateway", func(t *testing.T) {
			p, ok := rt.destination(netip.MustParseAddr("1.1.1.1"))
			require.True(t, ok)

			require.Equal(t, "default-gateway", p.Name())
		})
	})
}
