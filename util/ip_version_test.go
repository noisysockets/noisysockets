// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package util_test

import (
	"net/netip"
	"testing"

	"github.com/noisysockets/noisysockets/util"
	"github.com/stretchr/testify/require"
)

func TestIPVersion(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		addrs := []netip.Addr{
			netip.MustParseAddr("127.0.0.1"),
		}

		hasV4 := util.HasIPv4(addrs)
		require.True(t, hasV4)

		hasV6 := util.HasIPv6(addrs)
		require.False(t, hasV6)
	})

	t.Run("IPv6", func(t *testing.T) {
		addrs := []netip.Addr{
			netip.MustParseAddr("::1"),
		}

		hasV4 := util.HasIPv4(addrs)
		require.False(t, hasV4)

		hasV6 := util.HasIPv6(addrs)
		require.True(t, hasV6)
	})

	t.Run("Both", func(t *testing.T) {
		addrs := []netip.Addr{
			netip.MustParseAddr("127.0.0.1"),
			netip.MustParseAddr("::1"),
		}

		hasV4 := util.HasIPv4(addrs)
		require.True(t, hasV4)

		hasV6 := util.HasIPv6(addrs)
		require.True(t, hasV6)
	})
}
