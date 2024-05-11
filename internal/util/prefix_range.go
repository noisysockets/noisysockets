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
	"fmt"
	"net/netip"
)

// PrefixRange takes a netip.Prefix and calculates the starting and ending IP addresses.
func PrefixRange(p netip.Prefix) (startAddr netip.Addr, endAddr netip.Addr, err error) {
	if !p.IsValid() {
		return startAddr, endAddr, fmt.Errorf("invalid prefix")
	}

	// Check for a valid mask length in case of a IPv4-mapped IPv6 address.
	if p.Addr().Is4In6() && p.Bits() < 96 {
		return startAddr, endAddr, fmt.Errorf("prefix with 4in6 address must have mask >= 96")
	}

	// Calculate the first address by applying the network mask, which zeroes out the host bits.
	startAddr = p.Masked().Addr()

	// Adjust mask bits for IPv4 addresses to accommodate the IPv4-mapped IPv6 address.
	maskBits := p.Bits()
	if startAddr.Is4() {
		maskBits += 96
	}

	// Calculate the last address by setting the host bits of the address.
	as16 := startAddr.As16()
	for b := maskBits; b < 128; b++ {
		byteIndex, bitIndex := b/8, 7-(b%8)
		as16[byteIndex] |= 1 << uint(bitIndex)
	}

	endAddr = netip.AddrFrom16(as16)

	// If the prefix is IPv4, unmap from the IPv4-mapped IPv6 address space.
	if startAddr.Is4() {
		endAddr = endAddr.Unmap()
	}

	return startAddr, endAddr, nil
}
