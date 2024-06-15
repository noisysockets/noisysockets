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
	"fmt"
	"net/netip"
)

// MaybeAddrPort is a type that can be either an address or an address with a port.
type MaybeAddrPort netip.AddrPort

// MustParseMaybeAddrPort is a helper function that parses a MaybeAddrPort from a string.
func MustParseMaybeAddrPort(text string) MaybeAddrPort {
	var m MaybeAddrPort
	if err := m.UnmarshalText([]byte(text)); err != nil {
		panic(err)
	}
	return m
}

// Custom unmarshal text for MaybeAddrPort, if no port is specified, a default port of '0' is used.
func (m *MaybeAddrPort) UnmarshalText(text []byte) error {
	addrPort, err := netip.ParseAddrPort(string(text))
	if err != nil {
		addr, err := netip.ParseAddr(string(text))
		if err != nil {
			return fmt.Errorf("could not parse address: %w", err)
		}

		addrPort = netip.AddrPortFrom(addr, 0)
	}

	*m = MaybeAddrPort(addrPort)
	return nil
}

// Custom marshal text for MaybeAddrPort, if the port is '0', it is omitted.
func (m MaybeAddrPort) MarshalText() ([]byte, error) {
	addrPort := netip.AddrPort(m)
	if addrPort.Port() == 0 {
		return []byte(addrPort.Addr().String()), nil
	}
	return []byte(addrPort.String()), nil
}

func (m MaybeAddrPort) String() string {
	text, _ := m.MarshalText()
	return string(text)
}
