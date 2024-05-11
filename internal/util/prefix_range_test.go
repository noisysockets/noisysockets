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

	"github.com/noisysockets/noisysockets/internal/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrefixRange(t *testing.T) {
	t.Run("Valid IPv4 Prefix", func(t *testing.T) {
		prefix := netip.MustParsePrefix("192.168.1.0/24")
		expectedStartAddr := netip.MustParseAddr("192.168.1.0")
		expectedEndAddr := netip.MustParseAddr("192.168.1.255")
		startAddr, endAddr, err := util.PrefixRange(prefix)
		require.NoError(t, err)

		assert.Equal(t, expectedStartAddr, startAddr)
		assert.Equal(t, expectedEndAddr, endAddr)
	})

	t.Run("Valid IPv6 Prefix", func(t *testing.T) {
		prefix := netip.MustParsePrefix("2001:db8::/32")
		expectedStartAddr := netip.MustParseAddr("2001:db8::")
		expectedEndAddr := netip.MustParseAddr("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")
		startAddr, endAddr, err := util.PrefixRange(prefix)
		require.NoError(t, err)

		assert.Equal(t, expectedStartAddr, startAddr)
		assert.Equal(t, expectedEndAddr, endAddr)
	})

	t.Run("IPv4 in IPv6 with Invalid Mask", func(t *testing.T) {
		// Invalid mask length for IPv4-mapped-to-IPv6 address.
		prefix := netip.MustParsePrefix("::ffff:192.168.1.0/95")
		_, _, err := util.PrefixRange(prefix)

		assert.Error(t, err)
	})
}
