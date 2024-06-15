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

// ParseAddrList parses a list of IP address strings and returns a list of netip.Addr.
func ParseAddrList(addrList []string) ([]netip.Addr, error) {
	var addrs []netip.Addr
	for _, ip := range addrList {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, fmt.Errorf("could not parse address: %w", err)
		}

		addrs = append(addrs, addr)
	}

	return addrs, nil
}
