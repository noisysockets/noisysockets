// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
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
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"net/netip"
	"syscall"

	"github.com/noisysockets/netstack/pkg/buffer"
	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/header"
	"github.com/noisysockets/netstack/pkg/tcpip/link/channel"
	"github.com/noisysockets/netstack/pkg/tcpip/network/ipv4"
	"github.com/noisysockets/netstack/pkg/tcpip/network/ipv6"
	"github.com/noisysockets/netstack/pkg/tcpip/stack"
	"github.com/noisysockets/noisysockets/internal/conn"
	"github.com/noisysockets/noisysockets/internal/transport"
	"github.com/noisysockets/noisysockets/types"
)

const (
	queueSize = 1024
)

var (
	_ transport.SourceSink = (*sourceSink)(nil)
)

type sourceSink struct {
	logger       *slog.Logger
	debugLogging bool
	peers        *peerList
	stack        *stack.Stack
	ep           *channel.Endpoint
	notifyHandle *channel.NotificationHandle
	incoming     chan *stack.PacketBuffer
	localAddrs   []netip.Addr
}

func newSourceSink(logger *slog.Logger, peers *peerList, s *stack.Stack,
	localAddrs []netip.Addr, hasV4 bool, hasV6 bool) (*sourceSink, error) {
	ss := &sourceSink{
		logger:       logger,
		debugLogging: logger.Enabled(context.Background(), slog.LevelDebug),
		peers:        peers,
		stack:        s,
		ep:           channel.New(queueSize, uint32(transport.DefaultMTU), ""),
		incoming:     make(chan *stack.PacketBuffer),
		localAddrs:   localAddrs,
	}

	ss.notifyHandle = ss.ep.AddNotify(ss)

	if err := ss.stack.CreateNIC(1, ss.ep); err != nil {
		return nil, fmt.Errorf("could not create NIC: %v", err)
	}

	// Add default routes.
	var routes []tcpip.Route
	if hasV4 {
		routes = append(routes, tcpip.Route{
			NIC:         1,
			Destination: header.IPv4EmptySubnet,
		})
	}
	if hasV6 {
		routes = append(routes, tcpip.Route{
			NIC:         1,
			Destination: header.IPv6EmptySubnet,
		})
	}
	ss.stack.SetRouteTable(routes)

	// Assign local addresses to the nic.
	for _, addr := range localAddrs {
		var protoNumber tcpip.NetworkProtocolNumber
		if addr.Is4() {
			protoNumber = ipv4.ProtocolNumber
		} else if addr.Is6() {
			protoNumber = ipv6.ProtocolNumber
		}

		protoAddr := tcpip.ProtocolAddress{
			Protocol:          protoNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix(),
		}

		logger.Debug("Adding local address", slog.String("address", addr.String()))

		if err := ss.stack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("could not add address: %v", err)
		}
	}

	return ss, nil
}

func (ss *sourceSink) Close() error {
	ss.ep.RemoveNotify(ss.notifyHandle)
	ss.ep.Close()

	ss.stack.RemoveNIC(1)

	// Drain the incoming channel before closing.
	ss.drain()

	close(ss.incoming)

	return nil
}

func (ss *sourceSink) Read(bufs [][]byte, sizes []int, destinations []types.NoisePublicKey, offset int) (int, error) {
	packetFn := func(idx int, pkt *stack.PacketBuffer) error {
		defer pkt.DecRef()

		if ss.debugLogging {
			ss.logger.Debug("Processing netstack packet",
				slog.Uint64("packetHash", hashPacketMetadata(pkt)))
		}

		// Extract the destination IP address from the packet
		var peerAddr netip.Addr
		switch pkt.NetworkProtocolNumber {
		case header.IPv4ProtocolNumber:
			hdr := header.IPv4(pkt.NetworkHeader().Slice())
			if !hdr.IsValid(pkt.Size()) {
				return fmt.Errorf("invalid IPv4 header")
			}

			peerAddr = netip.AddrFrom4(hdr.DestinationAddress().As4())
		case header.IPv6ProtocolNumber:
			hdr := header.IPv6(pkt.NetworkHeader().Slice())
			if !hdr.IsValid(pkt.Size()) {
				return fmt.Errorf("invalid IPv6 header")
			}

			peerAddr = netip.AddrFrom16(hdr.DestinationAddress().As16())
		default:
			return fmt.Errorf("unknown network protocol: %w", syscall.EAFNOSUPPORT)
		}

		logger := ss.logger.With(slog.String("address", peerAddr.String()))

		dstPeer, ok := ss.peers.lookupByAddress(peerAddr)
		if !ok {
			return fmt.Errorf("unknown destination address")
		}
		destinations[idx] = dstPeer.publicKey

		if ss.debugLogging {
			logger.Debug("Sending packet to peer",
				slog.String("destination", destinations[idx].DisplayString()))
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
		ss.logger.Warn("Failed to process packet", slog.Any("error", err))
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
				ss.logger.Warn("Failed to process packet", slog.Any("error", err))
				return count, err
			}

			count++
		default:
			return count, nil
		}
	}

	return count, nil
}

func (ss *sourceSink) Write(bufs [][]byte, sources []types.NoisePublicKey, offset int) (int, error) {
	for i, buf := range bufs {
		if len(buf) <= offset {
			continue
		}

		if ss.debugLogging {
			ss.logger.Debug("Received packet from peer", slog.String("source", sources[i].DisplayString()))
		}

		// Validate the source address (to prevent spoofing).
		protocolNumber, err := ss.validateSourceAddress(buf[offset:], sources[i])
		if err != nil {
			return i, err
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(buf[offset:])})

		if ss.debugLogging {
			ss.logger.Debug("Injecting inbound packet into netstack")
		}

		ss.ep.InjectInbound(protocolNumber, pkt)
	}

	return len(bufs), nil
}

func (ss *sourceSink) BatchSize() int {
	return conn.IdealBatchSize
}

func (ss *sourceSink) WriteNotify() {
	pkt := ss.ep.Read()
	if pkt == nil {
		return
	}

	if ss.debugLogging {
		ss.logger.Debug("Received outbound packet from netstack",
			slog.Uint64("packetHash", hashPacketMetadata(pkt)))
	}

	ss.incoming <- pkt
}

func (ss *sourceSink) drain() {
	for {
		select {
		case pkt, ok := <-ss.incoming:
			if !ok {
				return
			}

			pkt.DecRef()
		default:
			return
		}
	}
}

func (ss *sourceSink) validateSourceAddress(buf []byte, source types.NoisePublicKey) (tcpip.NetworkProtocolNumber, error) {
	var protocolNumber tcpip.NetworkProtocolNumber
	switch header.IPVersion(buf) {
	case header.IPv4Version:
		protocolNumber = header.IPv4ProtocolNumber
	case header.IPv6Version:
		protocolNumber = header.IPv6ProtocolNumber
	default:
		return 0, fmt.Errorf("unknown IP version: %w", syscall.EAFNOSUPPORT)
	}

	var addr netip.Addr
	switch protocolNumber {
	case header.IPv4ProtocolNumber:
		hdr := header.IPv4(buf)
		if !hdr.IsValid(len(buf)) {
			return protocolNumber, fmt.Errorf("invalid IPv4 header")
		}

		addr = netip.AddrFrom4(hdr.SourceAddress().As4())
	case header.IPv6ProtocolNumber:
		hdr := header.IPv6(buf)
		if !hdr.IsValid(len(buf)) {
			return protocolNumber, fmt.Errorf("invalid IPv6 header")
		}

		addr = netip.AddrFrom16(hdr.SourceAddress().As16())
	default:
		return protocolNumber, fmt.Errorf("unknown network protocol: %w", syscall.EAFNOSUPPORT)
	}

	srcPeer, ok := ss.peers.lookupByAddress(addr)
	if !ok {
		return protocolNumber, fmt.Errorf("unknown source address")
	}

	if !srcPeer.publicKey.Equals(source) {
		return protocolNumber, fmt.Errorf("invalid source address for peer")
	}

	return protocolNumber, nil
}

func hashPacketMetadata(pkt *stack.PacketBuffer) uint64 {
	h := fnv.New64a()
	_, _ = h.Write(pkt.NetworkHeader().Slice())
	_, _ = h.Write(pkt.TransportHeader().Slice())
	return h.Sum64()
}
