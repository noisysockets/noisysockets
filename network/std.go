// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package network

import (
	"context"
	stdnet "net"
)

// StdNet is an implementation of the Network interface using the standard library's network operations.
// This is used in integration testing to avoid needing to interact with WireGuard directly.
type StdNet struct {
	hasV4, hasV6 *bool
}

func (net *StdNet) Close() error {
	return nil
}

func (net *StdNet) HasIPv4() bool {
	if net.hasV4 == nil {
		var hasV4 bool

		lis, err := stdnet.Listen("tcp4", "127.0.0.1:0")
		if err == nil {
			_ = lis.Close()
			hasV4 = true
		}

		net.hasV4 = &hasV4
	}

	return *net.hasV4
}

func (net *StdNet) HasIPv6() bool {
	if net.hasV6 == nil {
		var hasV6 bool

		lis, err := stdnet.Listen("tcp6", "[::1]:0")
		if err == nil {
			_ = lis.Close()
			hasV6 = true
		}

		net.hasV6 = &hasV6
	}

	return *net.hasV6
}

func (net *StdNet) LookupHost(host string) ([]string, error) {
	return stdnet.LookupHost(host)
}

func (net *StdNet) Dial(network, address string) (stdnet.Conn, error) {
	return stdnet.Dial(network, address)
}

func (net *StdNet) DialContext(ctx context.Context, network, address string) (stdnet.Conn, error) {
	var d stdnet.Dialer
	return d.DialContext(ctx, network, address)
}

func (net *StdNet) Listen(network, address string) (stdnet.Listener, error) {
	return stdnet.Listen(network, address)
}

func (net *StdNet) ListenPacket(network, address string) (stdnet.PacketConn, error) {
	return stdnet.ListenPacket(network, address)
}
