// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions of this file are based on code originally from wireguard-go,
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package noisysockets

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/noisysockets/noisysockets/internal/conn"
	"github.com/noisysockets/noisysockets/internal/transport"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	queueSize = 1024
)

var (
	_ transport.SourceSink = (*sourceSink)(nil)
)

type sourceSink struct {
	pd             *peerDirectory
	stack          *stack.Stack
	ep             *channel.Endpoint
	notifyHandle   *channel.NotificationHandle
	incoming       chan *stack.PacketBuffer
	defaultGateway *transport.NoisePublicKey
}

func newSourceSink(pd *peerDirectory, s *stack.Stack, defaultGateway *transport.NoisePublicKey) (*sourceSink, error) {
	ss := &sourceSink{
		pd:             pd,
		stack:          s,
		ep:             channel.New(queueSize, uint32(transport.DefaultMTU), ""),
		incoming:       make(chan *stack.PacketBuffer),
		defaultGateway: defaultGateway,
	}

	ss.notifyHandle = ss.ep.AddNotify(ss)

	if err := s.CreateNIC(1, ss.ep); err != nil {
		return nil, fmt.Errorf("could not create NIC: %v", err)
	}

	return ss, nil
}

func (ss *sourceSink) Close() error {
	ss.ep.RemoveNotify(ss.notifyHandle)
	ss.ep.Close()
	close(ss.incoming)

	ss.stack.RemoveNIC(1)

	return nil
}

func (ss *sourceSink) Read(bufs [][]byte, sizes []int, destinations []transport.NoisePublicKey, offset int) (int, error) {
	packetFn := func(idx int, pkt *stack.PacketBuffer) error {
		defer pkt.DecRef()

		// Extract the destination IP address from the packet
		var peerAddr netip.Addr
		switch pkt.NetworkProtocolNumber {
		case header.IPv4ProtocolNumber:
			hdr := header.IPv4(pkt.NetworkHeader().View().AsSlice())
			if !hdr.IsValid(pkt.Size()) {
				return fmt.Errorf("invalid IPv4 header")
			}

			peerAddr = netip.AddrFrom4(hdr.DestinationAddress().As4())
		case header.IPv6ProtocolNumber:
			hdr := header.IPv6(pkt.NetworkHeader().View().AsSlice())
			if !hdr.IsValid(pkt.Size()) {
				return fmt.Errorf("invalid IPv6 header")
			}

			peerAddr = netip.AddrFrom16(hdr.DestinationAddress().As16())
		default:
			return fmt.Errorf("unknown network protocol")
		}

		var ok bool
		destinations[idx], ok = ss.pd.LookupPeerByAddress(peerAddr)
		if !ok {
			if ss.defaultGateway == nil {
				return fmt.Errorf("unknown destination address")
			}

			destinations[idx] = *ss.defaultGateway
		}

		view := pkt.ToView()
		n, err := view.Read(bufs[idx][offset:])
		view.Release()
		if err != nil {
			return fmt.Errorf("could not read packet: %w", err)
		}

		sizes[idx] = n

		return nil
	}

	// Always block until we have at least one packet.
	var count int
	pkt, ok := <-ss.incoming
	if !ok {
		return 0, net.ErrClosed
	}

	if err := packetFn(count, pkt); err != nil {
		return count, err
	}

	count++

	for count < len(bufs) {
		select {
		case pkt, ok := <-ss.incoming:
			if !ok {
				return count, net.ErrClosed
			}

			if err := packetFn(count, pkt); err != nil {
				return count, err
			}

			count++
		default:
			return count, nil
		}
	}

	return count, nil
}

func (ss *sourceSink) Write(bufs [][]byte, _ []transport.NoisePublicKey, offset int) (int, error) {
	for _, buf := range bufs {
		if len(buf) <= offset {
			continue
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(buf[offset:])})
		switch buf[offset] >> 4 {
		case 4:
			ss.ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
		case 6:
			ss.ep.InjectInbound(header.IPv6ProtocolNumber, pkt)
		default:
			return 0, syscall.EAFNOSUPPORT
		}
	}

	return len(bufs), nil
}

func (ss *sourceSink) BatchSize() int {
	return conn.IdealBatchSize
}

func (ss *sourceSink) WriteNotify() {
	pkt := ss.ep.Read()
	if pkt.IsNil() {
		return
	}

	ss.incoming <- pkt
}
