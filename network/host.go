// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package network

import (
	"context"
	stdnet "net"
	"os"
)

// Host returns a Network implementation that uses the standard library's network operations.
// This is used in integration testing to avoid needing to mock out WireGuard.
func Host() Network {
	return &hostNetwork{}
}

type hostNetwork struct{}

func (net *hostNetwork) Close() error {
	return nil
}

func (net *hostNetwork) InterfaceAddrs() ([]stdnet.Addr, error) {
	return stdnet.InterfaceAddrs()
}

func (net *hostNetwork) Hostname() (string, error) {
	return os.Hostname()
}

func (net *hostNetwork) LookupHost(host string) ([]string, error) {
	return stdnet.LookupHost(host)
}

func (net *hostNetwork) Dial(network, address string) (stdnet.Conn, error) {
	return stdnet.Dial(network, address)
}

func (net *hostNetwork) DialContext(ctx context.Context, network, address string) (stdnet.Conn, error) {
	var d stdnet.Dialer
	return d.DialContext(ctx, network, address)
}

func (net *hostNetwork) Listen(network, address string) (stdnet.Listener, error) {
	return stdnet.Listen(network, address)
}

func (net *hostNetwork) ListenPacket(network, address string) (stdnet.PacketConn, error) {
	return stdnet.ListenPacket(network, address)
}
