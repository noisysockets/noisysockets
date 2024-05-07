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
	"fmt"
	stdnet "net"
	"net/netip"
)

func parseIPList(ips []string) ([]netip.Addr, error) {
	var addrs []netip.Addr
	for _, ip := range ips {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, fmt.Errorf("could not parse address: %w", err)
		}

		addrs = append(addrs, addr)
	}

	return addrs, nil
}

func parseIPPortList(ipPorts []string) ([]netip.AddrPort, error) {
	var addrPorts []netip.AddrPort
	for _, ipPort := range ipPorts {
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

func dedupNetworks(networks []netip.Prefix) []netip.Prefix {
	seen := make(map[string]bool)
	var deduped []netip.Prefix
	for _, net := range networks {
		key := net.String()
		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = true
		deduped = append(deduped, net)
	}

	return deduped
}
