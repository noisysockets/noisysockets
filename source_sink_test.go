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
	stdnet "net"
	"net/netip"
	"testing"

	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/header"
	"github.com/noisysockets/noisysockets/types"
	"github.com/stretchr/testify/require"
)

func TestValidateSourceAddress(t *testing.T) {
	gwSK, err := types.NewPrivateKey()
	require.NoError(t, err)

	gwPK := gwSK.Public()

	peer1SK, err := types.NewPrivateKey()
	require.NoError(t, err)

	peer1PK := peer1SK.Public()

	peer2SK, err := types.NewPrivateKey()
	require.NoError(t, err)

	peer2PK := peer2SK.Public()

	peers := newPeerList()

	_, ipv4Net, err := stdnet.ParseCIDR("192.168.2.0/24")
	require.NoError(t, err)

	_, ipv6Net, err := stdnet.ParseCIDR("2001:db9::/64")
	require.NoError(t, err)

	peers.add(&peer{
		name:      "gw",
		publicKey: gwPK,
		addrs: []netip.Addr{
			netip.MustParseAddr("192.168.1.1"),
			netip.MustParseAddr("2001:db8::1"),
		},
		destinations: []*stdnet.IPNet{ipv4Net, ipv6Net},
	})

	peers.add(&peer{
		name:      "peer1",
		publicKey: peer1PK,
		addrs: []netip.Addr{
			netip.MustParseAddr("192.168.1.2"),
			netip.MustParseAddr("2001:db8::2"),
		},
	})
	require.NoError(t, err)

	peers.add(&peer{
		name:      "peer2",
		publicKey: peer2PK,
		addrs: []netip.Addr{
			netip.MustParseAddr("192.168.1.3"),
			netip.MustParseAddr("2001:db8::3"),
		},
	})

	ss := sourceSink{
		peers: peers,
	}

	t.Run("Valid (IPv4)", func(t *testing.T) {
		buf := make([]byte, header.IPv4MinimumSize)
		header.IPv4(buf).Encode(&header.IPv4Fields{
			TotalLength: header.IPv4MinimumSize,
			SrcAddr:     tcpip.AddrFrom4Slice(netip.MustParseAddr("192.168.1.2").AsSlice()),
		})

		protocolNumber, err := ss.validateSourceAddress(buf, peer1PK)
		require.NoError(t, err)

		require.Equal(t, header.IPv4ProtocolNumber, protocolNumber)
	})

	t.Run("Impersonation (IPv4)", func(t *testing.T) {
		buf := make([]byte, header.IPv4MinimumSize)
		header.IPv4(buf).Encode(&header.IPv4Fields{
			TotalLength: header.IPv4MinimumSize,
			SrcAddr:     tcpip.AddrFrom4Slice(netip.MustParseAddr("192.168.1.2").AsSlice()),
		})

		_, err := ss.validateSourceAddress(buf, peer2PK)
		require.Error(t, err)
	})

	t.Run("Unknown (IPv4)", func(t *testing.T) {
		buf := make([]byte, header.IPv4MinimumSize)
		header.IPv4(buf).Encode(&header.IPv4Fields{
			TotalLength: header.IPv4MinimumSize,
			SrcAddr:     tcpip.AddrFrom4Slice(netip.MustParseAddr("1.1.1.1").AsSlice()),
		})

		_, err := ss.validateSourceAddress(buf, peer1PK)
		require.Error(t, err)
	})

	t.Run("Gateway (IPv4)", func(t *testing.T) {
		buf := make([]byte, header.IPv4MinimumSize)
		header.IPv4(buf).Encode(&header.IPv4Fields{
			TotalLength: header.IPv4MinimumSize,
			SrcAddr:     tcpip.AddrFrom4Slice(netip.MustParseAddr("192.168.2.2").AsSlice()),
		})

		protocolNumber, err := ss.validateSourceAddress(buf, gwPK)
		require.NoError(t, err)

		require.Equal(t, header.IPv4ProtocolNumber, protocolNumber)
	})

	t.Run("Gateway Invalid (IPv4)", func(t *testing.T) {
		buf := make([]byte, header.IPv4MinimumSize)
		header.IPv4(buf).Encode(&header.IPv4Fields{
			TotalLength: header.IPv4MinimumSize,
			SrcAddr:     tcpip.AddrFrom4Slice(netip.MustParseAddr("192.168.1.10").AsSlice()),
		})

		_, err := ss.validateSourceAddress(buf, gwPK)
		require.Error(t, err)
	})

	t.Run("Gateway Impersonation (IPv4)", func(t *testing.T) {
		buf := make([]byte, header.IPv4MinimumSize)
		header.IPv4(buf).Encode(&header.IPv4Fields{
			TotalLength: header.IPv4MinimumSize,
			SrcAddr:     tcpip.AddrFrom4Slice(netip.MustParseAddr("192.168.1.2").AsSlice()),
		})

		_, err := ss.validateSourceAddress(buf, gwPK)
		require.Error(t, err)
	})

	t.Run("Valid (IPv6)", func(t *testing.T) {
		buf := make([]byte, header.IPv6MinimumSize)
		header.IPv6(buf).Encode(&header.IPv6Fields{
			SrcAddr: tcpip.AddrFrom16Slice(netip.MustParseAddr("2001:db8::2").AsSlice()),
		})

		protocolNumber, err := ss.validateSourceAddress(buf, peer1PK)
		require.NoError(t, err)

		require.Equal(t, header.IPv6ProtocolNumber, protocolNumber)
	})

	t.Run("Impersonation (IPv6)", func(t *testing.T) {
		buf := make([]byte, header.IPv6MinimumSize)
		header.IPv6(buf).Encode(&header.IPv6Fields{
			SrcAddr: tcpip.AddrFrom16Slice(netip.MustParseAddr("2001:db8::2").AsSlice()),
		})

		_, err := ss.validateSourceAddress(buf, peer2PK)
		require.Error(t, err)
	})

	t.Run("Unknown (IPv6)", func(t *testing.T) {
		buf := make([]byte, header.IPv6MinimumSize)
		header.IPv6(buf).Encode(&header.IPv6Fields{
			SrcAddr: tcpip.AddrFrom16Slice(netip.MustParseAddr("2001:db8::dead:beef").AsSlice()),
		})

		_, err := ss.validateSourceAddress(buf, peer1PK)
		require.Error(t, err)
	})

	t.Run("Gateway (IPv6)", func(t *testing.T) {
		buf := make([]byte, header.IPv6MinimumSize)
		header.IPv6(buf).Encode(&header.IPv6Fields{
			SrcAddr: tcpip.AddrFrom16Slice(netip.MustParseAddr("2001:db9::2").AsSlice()),
		})

		protocolNumber, err := ss.validateSourceAddress(buf, gwPK)
		require.NoError(t, err)

		require.Equal(t, header.IPv6ProtocolNumber, protocolNumber)
	})

	t.Run("Gateway Invalid (IPv6)", func(t *testing.T) {
		buf := make([]byte, header.IPv6MinimumSize)
		header.IPv6(buf).Encode(&header.IPv6Fields{
			SrcAddr: tcpip.AddrFrom16Slice(netip.MustParseAddr("2001:db8::10").AsSlice()),
		})

		_, err := ss.validateSourceAddress(buf, gwPK)
		require.Error(t, err)
	})

	t.Run("Gateway Impersonation (IPv6)", func(t *testing.T) {
		buf := make([]byte, header.IPv6MinimumSize)
		header.IPv6(buf).Encode(&header.IPv6Fields{
			SrcAddr: tcpip.AddrFrom16Slice(netip.MustParseAddr("2001:db8::2").AsSlice()),
		})

		_, err := ss.validateSourceAddress(buf, gwPK)
		require.Error(t, err)
	})
}
