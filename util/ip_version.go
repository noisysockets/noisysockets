// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package util

import (
	"net/netip"
)

// HasIPv4 returns true if the list of addresses contains an IPv4 address.
func HasIPv4(addrs []netip.Addr) bool {
	for _, addr := range addrs {
		if addr.Is4() {
			return true
		}
	}

	return false
}

// HasIPv6 returns true if the list of addresses contains an IPv6 address.
func HasIPv6(addrs []netip.Addr) bool {
	for _, addr := range addrs {
		if addr.Is6() {
			return true
		}
	}

	return false
}
