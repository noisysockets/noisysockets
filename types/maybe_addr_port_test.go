// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package types

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMaybeAddrPort(t *testing.T) {
	t.Run("With Port", func(t *testing.T) {
		m := MustParseMaybeAddrPort("1.1.1.1:53")

		addrPort := netip.AddrPort(m)
		require.Equal(t, uint16(53), addrPort.Port())

		text, err := m.MarshalText()
		require.NoError(t, err)

		require.Equal(t, "1.1.1.1:53", m.String())

		require.NoError(t, m.UnmarshalText(text))
	})

	t.Run("Without Port", func(t *testing.T) {
		m := MustParseMaybeAddrPort("1.1.1.1")

		addrPort := netip.AddrPort(m)
		require.Equal(t, uint16(0), addrPort.Port())

		text, err := m.MarshalText()
		require.NoError(t, err)

		require.Equal(t, "1.1.1.1", m.String())

		require.NoError(t, m.UnmarshalText(text))
	})
}
