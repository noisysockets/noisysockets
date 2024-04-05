// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package noisysockets

import (
	stdnet "net"
	"net/netip"

	"github.com/noisysockets/noisysockets/types"
)

// Addr is a wrapper around net.Addr that includes the source NoisePublicKey.
type Addr struct {
	stdnet.Addr
	pk types.NoisePublicKey
}

// PublicKey returns the NoisePublicKey of the peer.
func (a *Addr) PublicKey() types.NoisePublicKey {
	return a.pk
}

// Conn is a wrapper around net.Conn that includes the source NoisePublicKey.
type Conn struct {
	stdnet.Conn
	pd *peerDirectory
}

func (c *Conn) RemoteAddr() stdnet.Addr {
	remoteAddr := c.Conn.RemoteAddr()
	if remoteAddr == nil {
		return nil
	}

	pk, ok := c.pd.LookupPeerByAddress(netip.MustParseAddrPort(remoteAddr.String()).Addr())
	if !ok {
		return nil
	}

	return &Addr{Addr: c.Conn.RemoteAddr(), pk: pk}
}

type listener struct {
	stdnet.Listener
	pd *peerDirectory
}

func (l *listener) Accept() (stdnet.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &Conn{Conn: conn, pd: l.pd}, nil
}

type packetConn struct {
	stdnet.PacketConn
	pd *peerDirectory
}

func (pc *packetConn) ReadFrom(b []byte) (int, stdnet.Addr, error) {
	n, addr, err := pc.PacketConn.ReadFrom(b)
	if addr == nil {
		return n, nil, err
	}

	pk, ok := pc.pd.LookupPeerByAddress(netip.MustParseAddrPort(addr.String()).Addr())
	if !ok {
		return n, nil, err
	}

	return n, &Addr{Addr: addr, pk: pk}, err
}

func (pc *packetConn) WriteTo(b []byte, addr stdnet.Addr) (int, error) {
	addrPort, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return 0, err
	}

	return pc.PacketConn.WriteTo(b, &stdnet.UDPAddr{
		IP:   addrPort.Addr().AsSlice(),
		Port: int(addrPort.Port()),
	})
}
