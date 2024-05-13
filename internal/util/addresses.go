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
	stdnet "net"
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

// ParseAddrPortList parses a list of IP address and port strings and returns a list of netip.AddrPort.
func ParseAddrPortList(addrPortList []string) ([]netip.AddrPort, error) {
	var addrPorts []netip.AddrPort
	for _, ipPort := range addrPortList {
		var addrPort netip.AddrPort

		// Do we have a port specified?
		if _, _, err := stdnet.SplitHostPort(ipPort); err == nil {
			addrPort, err = netip.ParseAddrPort(ipPort)
			if err != nil {
				return nil, fmt.Errorf("could not parse address: %w", err)
			}
		} else {
			addr, err := netip.ParseAddr(ipPort)
			if err != nil {
				return nil, fmt.Errorf("could not parse address: %w", err)
			}

			addrPort = netip.AddrPortFrom(addr, 0)
		}

		addrPorts = append(addrPorts, addrPort)
	}

	return addrPorts, nil
}
