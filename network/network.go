// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

// Package network provides an interface for the standard library's network operations.
// This is defined in a separate package to avoid issues with circular imports.
package network

import (
	"context"
	"io"
	stdnet "net"
)

// Network is an interface that abstracts the standard library's network operations.
type Network interface {
	io.Closer
	// HasIPv4 returns true if the network supports IPv4.
	HasIPv4() bool
	// HasIPv6 returns true if the network supports IPv6.
	HasIPv6() bool
	// LookupHost looks up the given host using the local resolver. It returns a slice of that host's addresses.
	LookupHost(host string) ([]string, error)
	// Dial connects to the address on the named network.
	// Known networks are "tcp", "tcp4" (IPv4-only), "tcp6" (IPv6-only), "udp", "udp4" (IPv4-only), "udp6" (IPv6-only).
	Dial(network, address string) (stdnet.Conn, error)
	// DialContext connects to the address on the named network using the provided context.
	DialContext(ctx context.Context, network, address string) (stdnet.Conn, error)
	// Listen listens for incoming connections on the network address.
	// Known networks are "tcp", "tcp4" (IPv4-only), "tcp6" (IPv6-only).
	// If the address is an empty string, Listen listens on all available interfaces.
	Listen(network, address string) (stdnet.Listener, error)
	// ListenPacket listens for incoming packets addressed to the local address.
	// Known networks are "udp", "udp4" (IPv4-only), "udp6" (IPv6-only).
	// Caveat: The SetDeadline, SetReadDeadline, or SetWriteDeadline functions on the returned
	// PacketConn may not work as expected (due to gVisor issues).
	ListenPacket(network, address string) (stdnet.PacketConn, error)
}
