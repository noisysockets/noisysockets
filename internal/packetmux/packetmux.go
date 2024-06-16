// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package packetmux

import (
	"errors"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"github.com/noisysockets/netutil/waitpool"
)

var _ net.PacketConn = (*packetMux)(nil)

// packetMux implements a net.PacketConn interface but multiplexes packets
// from multiple PacketConns.
type packetMux struct {
	conns         []net.PacketConn
	packetPool    *waitpool.WaitPool[*readFromResult]
	closeOnce     sync.Once
	closing       chan struct{}
	packets       chan *readFromResult
	readDeadline  *time.Timer
	writeDeadline *time.Timer
}

type readFromResult struct {
	n    int
	addr net.Addr
	buf  [65507]byte // Maximum UDP datagram size
	err  error
}

// New creates an instance of a PacketMux using the given PacketConns. You must
// pass at least one PacketConn. The new PacketMux object listens for new packets
// on all the given PacketConns.
func New(conns ...net.PacketConn) (*packetMux, error) {
	if len(conns) == 0 {
		return nil, errors.New("PacketMux requires at least 1 PacketConn")
	}

	mux := &packetMux{
		conns: conns,
		packetPool: waitpool.New(0, func() *readFromResult {
			return &readFromResult{}
		}),
		closing:       make(chan struct{}),
		packets:       make(chan *readFromResult),
		readDeadline:  time.NewTimer(math.MaxInt64),
		writeDeadline: time.NewTimer(math.MaxInt64),
	}

	for _, pc := range mux.conns {
		go mux.readLoop(pc)
	}

	return mux, nil
}

// LocalAddr returns the local address of the first PacketConn. The address of other PacketConns are not available.
func (mux *packetMux) LocalAddr() net.Addr {
	return mux.conns[0].LocalAddr()
}

// Close closes the PacketMux by shutting down all underlying PacketConns.
func (mux *packetMux) Close() error {
	var errs []error
	mux.closeOnce.Do(func() {
		close(mux.closing)
		mux.readDeadline.Reset(0)
		mux.writeDeadline.Reset(0)
		for _, conn := range mux.conns {
			if err := conn.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	})
	return errors.Join(errs...)
}

// ReadFrom waits for and returns packets from the underlying PacketConns.
func (mux *packetMux) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case packet := <-mux.packets:
		defer mux.packetPool.Put(packet)
		copy(p, packet.buf[:packet.n])
		return packet.n, packet.addr, packet.err
	case <-mux.readDeadline.C:
		return 0, nil, os.ErrDeadlineExceeded
	case <-mux.closing:
		return 0, nil, errors.New("PacketMux is closed")
	}
}

// WriteTo writes data to the specified address on the underlying PacketConns.
func (mux *packetMux) WriteTo(p []byte, addr net.Addr) (int, error) {
	var errs []error
	for _, conn := range mux.conns {
		select {
		case <-mux.writeDeadline.C:
			return 0, os.ErrDeadlineExceeded
		case <-mux.closing:
			return 0, errors.New("PacketMux is closed")
		default:
		}

		if n, err := conn.WriteTo(p, addr); err == nil {
			return n, nil
		} else {
			errs = append(errs, err)
		}
	}
	return 0, errors.Join(errs...)
}

// SetDeadline sets the read and write deadlines for the underlying PacketConns.
func (mux *packetMux) SetDeadline(t time.Time) error {
	if err := mux.SetReadDeadline(t); err != nil {
		return err
	}

	return mux.SetWriteDeadline(t)
}

// SetReadDeadline sets the read deadline for the underlying PacketConns.
func (mux *packetMux) SetReadDeadline(t time.Time) error {
	mux.readDeadline.Reset(time.Until(t))
	return nil
}

// SetWriteDeadline sets the write deadline for the underlying PacketConns.
func (mux *packetMux) SetWriteDeadline(t time.Time) error {
	mux.writeDeadline.Reset(time.Until(t))
	return nil
}

func (mux *packetMux) readLoop(pc net.PacketConn) {
	for {
		select {
		case <-mux.closing:
			return
		default:
			r := mux.packetPool.Get()
			r.n, r.addr, r.err = pc.ReadFrom(r.buf[:])
			select {
			case mux.packets <- r:
			case <-mux.closing:
				return
			}
		}
	}
}
