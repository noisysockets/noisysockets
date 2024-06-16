// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package packetmux_test

import (
	"net"
	"testing"

	"github.com/noisysockets/noisysockets/internal/packetmux"
	"github.com/stretchr/testify/require"
)

func TestPacketMux(t *testing.T) {
	_, err := packetmux.New()
	require.Error(t, err, "expected error when creating packet mux with no underlying packet conns")

	pc1, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)

	pc2, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)

	mux, err := packetmux.New(pc1, pc2)
	require.NoError(t, err)

	// Send a packet to pc1
	_, err = pc2.WriteTo([]byte("hello"), pc1.LocalAddr())
	require.NoError(t, err)

	// Receive the packet from the mux
	buf := make([]byte, 1024)
	n, addr, err := mux.ReadFrom(buf)
	require.NoError(t, err)

	require.Equal(t, "hello", string(buf[:n]))
	require.Equal(t, pc2.LocalAddr(), addr)

	// Send a packet to pc2
	_, err = pc1.WriteTo([]byte("world"), pc2.LocalAddr())
	require.NoError(t, err)

	// Receive the packet from the mux
	n, _, err = mux.ReadFrom(buf)
	require.NoError(t, err)

	require.Equal(t, "world", string(buf[:n]))

	// Close the mux
	require.NoError(t, mux.Close())

	// Should return an error when trying to read from the closed mux
	_, _, err = mux.ReadFrom(buf)
	require.Error(t, err)
}
