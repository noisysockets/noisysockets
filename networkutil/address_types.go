// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package networkutil

import (
	stdnet "net"
	"net/netip"
)

// ToNetIPAddrs converts a list of net.Addr to a list of netip.Addr.
func ToNetIPAddrs(addrs []stdnet.Addr) (netipAddrs []netip.Addr, ok bool) {
	netipAddrs = make([]netip.Addr, len(addrs))
	for i, a := range addrs {
		switch a := a.(type) {
		case *stdnet.IPAddr:
			if ip := a.IP.To4(); ip != nil {
				netipAddrs[i], ok = netip.AddrFromSlice(ip)
			} else {
				netipAddrs[i], ok = netip.AddrFromSlice(a.IP)
			}
			if !ok {
				return
			}
		case *stdnet.IPNet:
			if ip := a.IP.To4(); ip != nil {
				netipAddrs[i], ok = netip.AddrFromSlice(ip)
			} else {
				netipAddrs[i], ok = netip.AddrFromSlice(a.IP)
			}
			if !ok {
				return
			}
		default:
			return netipAddrs, false
		}
	}

	return netipAddrs, true
}
