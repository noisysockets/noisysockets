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

package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/noisysockets/network"
	"github.com/noisysockets/noisysockets/internal/conn"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type QueueHandshakeElement struct {
	msgType  uint32
	packet   *network.Packet
	endpoint conn.Endpoint
}

type QueueInboundElement struct {
	packet   *network.Packet
	counter  uint64
	keypair  *Keypair
	endpoint conn.Endpoint
}

type QueueInboundElementsContainer struct {
	sync.Mutex
	elems []*QueueInboundElement
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueInboundElement) clearPointers() {
	elem.packet = nil
	elem.keypair = nil
	elem.endpoint = nil
}

/* Called when a new authenticated message has been received
 *
 * NOTE: Not thread safe, but called by sequential receiver!
 */
func (peer *Peer) keepKeyFreshReceiving() error {
	if peer.timers.sentLastMinuteHandshake.Load() {
		return nil
	}
	keypair := peer.keypairs.Current()
	if keypair != nil && keypair.isInitiator && time.Since(keypair.created) > (RejectAfterTime-KeepaliveTimeout-RekeyTimeout) {
		peer.timers.sentLastMinuteHandshake.Store(true)
		if err := peer.SendHandshakeInitiation(false); err != nil {
			return err
		}
	}
	return nil
}

/* Receives incoming datagrams for the device
 *
 * Every time the bind is updated a new routine is started for
 * IPv4 and IPv6 (separately)
 */
func (transport *Transport) RoutineReceiveIncoming(maxBatchSize int, recv conn.ReceiveFunc) {
	recvName := recv.PrettyName()
	defer func() {
		transport.logger.Debug("Routine: receive incoming - stopped", slog.String("recvName", recvName))
		transport.queue.decryption.wg.Done()
		transport.queue.handshake.wg.Done()
		transport.net.stopping.Done()
	}()

	transport.logger.Debug("Routine: receive incoming - started", slog.String("recvName", recvName))

	// receive datagrams until conn is closed

	var (
		packets     = make([]*network.Packet, maxBatchSize)
		bufs        = make([][]byte, maxBatchSize)
		err         error
		sizes       = make([]int, maxBatchSize)
		count       int
		endpoints   = make([]conn.Endpoint, maxBatchSize)
		deathSpiral int
		elemsByPeer = make(map[*Peer]*QueueInboundElementsContainer, maxBatchSize)
	)

	for i := range packets {
		packets[i] = transport.pool.packets.Borrow()
		bufs[i] = packets[i].Buf[:]
	}
	defer func() {
		for i, pkt := range packets {
			pkt.Release()
			packets[i] = nil
		}
	}()

	for {
		count, err = recv(bufs, sizes, endpoints)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			transport.logger.Warn("Failed to receive packet",
				slog.String("recvName", recvName),
				slog.Any("error", err))

			if !os.IsTimeout(err) {
				transport.logger.Warn("Receive error is not a timeout, stopping receive routine",
					slog.String("recvName", recvName),
					slog.Any("error", err))
				return
			}

			if deathSpiral < 10 {
				deathSpiral++
				time.Sleep(time.Second / 3)
				continue
			}
			return
		}
		deathSpiral = 0

		// handle each packet in the batch
		for i, size := range sizes[:count] {
			packets[i].Size = size

			if size < MinMessageSize {
				continue
			}

			// check size of packet

			packet := packets[i]
			buf := packet.Bytes()
			msgType := binary.LittleEndian.Uint32(buf[:4])

			switch msgType {

			// check if transport

			case MessageTransportType:

				// check size

				if packet.Size < MessageTransportSize {
					continue
				}

				// lookup key pair

				receiver := binary.LittleEndian.Uint32(
					buf[MessageTransportOffsetReceiver:MessageTransportOffsetCounter],
				)
				value := transport.indexTable.Lookup(receiver)
				keypair := value.keypair
				if keypair == nil {
					continue
				}

				// check keypair expiry

				if keypair.created.Add(RejectAfterTime).Before(time.Now()) {
					continue
				}

				// create work element
				peer := value.peer
				elem := transport.GetInboundElement()
				elem.packet = packets[i]
				elem.keypair = keypair
				elem.endpoint = endpoints[i]
				elem.counter = 0

				elemsForPeer, ok := elemsByPeer[peer]
				if !ok {
					elemsForPeer = transport.GetInboundElementsContainer()
					elemsForPeer.Lock()
					elemsByPeer[peer] = elemsForPeer
				}
				elemsForPeer.elems = append(elemsForPeer.elems, elem)
				packets[i] = transport.pool.packets.Borrow()
				bufs[i] = packets[i].Buf[:]
				continue

			// otherwise it is a fixed size & handshake related packet

			case MessageInitiationType:
				if packet.Size != MessageInitiationSize {
					continue
				}

			case MessageResponseType:
				if packet.Size != MessageResponseSize {
					continue
				}

			case MessageCookieReplyType:
				if packet.Size != MessageCookieReplySize {
					continue
				}

			default:
				transport.logger.Warn("Received message with unknown type",
					slog.Int("type", int(msgType)))
				continue
			}

			select {
			case transport.queue.handshake.c <- QueueHandshakeElement{
				msgType:  msgType,
				packet:   packet,
				endpoint: endpoints[i],
			}:
				packets[i] = transport.pool.packets.Borrow()
				bufs[i] = packets[i].Buf[:]
			default:
			}
		}
		for peer, elemsContainer := range elemsByPeer {
			if peer.isRunning.Load() {
				peer.queue.inbound.c <- elemsContainer
				transport.queue.decryption.c <- elemsContainer
			} else {
				for _, elem := range elemsContainer.elems {
					elem.packet.Release()
					elem.packet = nil
					transport.PutInboundElement(elem)
				}
				transport.PutInboundElementsContainer(elemsContainer)
			}
			delete(elemsByPeer, peer)
		}
	}
}

func (transport *Transport) RoutineDecryption(id int) {
	var nonce [chacha20poly1305.NonceSize]byte

	defer transport.logger.Debug("Routine: decryption worker - stopped", slog.Int("id", id))
	transport.logger.Debug("Routine: decryption worker - started", slog.Int("id", id))

	for elemsContainer := range transport.queue.decryption.c {
		for _, elem := range elemsContainer.elems {
			// split message into fields
			packetBuf := elem.packet.Bytes()
			counter := packetBuf[MessageTransportOffsetCounter:MessageTransportOffsetContent]
			content := packetBuf[MessageTransportOffsetContent:]

			// decrypt and release to consumer
			var err error
			elem.counter = binary.LittleEndian.Uint64(counter)
			// copy counter to nonce
			binary.LittleEndian.PutUint64(nonce[0x4:0xc], elem.counter)
			unsealed, err := elem.keypair.receive.Open(
				content[:0],
				nonce[:],
				content,
				nil,
			)
			elem.packet.Size = len(unsealed)
			elem.packet.Offset = MessageTransportOffsetContent
			if err != nil {
				elem.packet.Size = 0
			}
		}
		elemsContainer.Unlock()
	}
}

/* Handles incoming packets related to handshake
 */
func (transport *Transport) RoutineHandshake(id int) {
	logger := transport.logger.With(slog.Int("id", id))

	defer func() {
		logger.Debug("Routine: handshake worker - stopped")
		transport.queue.encryption.wg.Done()
	}()
	logger.Debug("Routine: handshake worker - started")

	for elem := range transport.queue.handshake.c {
		logger := logger.With(slog.String("from", elem.endpoint.DstToString()))

		// handle cookie fields and ratelimiting

		switch elem.msgType {

		case MessageCookieReplyType:

			// unmarshal packet

			var reply MessageCookieReply
			reader := bytes.NewReader(elem.packet.Bytes())
			err := binary.Read(reader, binary.LittleEndian, &reply)
			if err != nil {
				logger.Warn("Failed to decode cookie reply", slog.Any("error", err))
				goto skip
			}

			// lookup peer from index

			entry := transport.indexTable.Lookup(reply.Receiver)

			if entry.peer == nil {
				goto skip
			}

			// consume reply

			if peer := entry.peer; peer.isRunning.Load() {
				logger.Debug("Receiving cookie response")
				if !peer.cookieGenerator.ConsumeReply(&reply) {
					logger.Warn("Could not decrypt invalid cookie response")
				}
			}

			goto skip

		case MessageInitiationType, MessageResponseType:

			// check mac fields and maybe ratelimit

			if !transport.cookieChecker.CheckMAC1(elem.packet.Bytes()) {
				logger.Warn("Received packet with invalid mac1")
				goto skip
			}

			// endpoints destination address is the source of the datagram

			if transport.IsUnderLoad() {

				// verify MAC2 field

				if !transport.cookieChecker.CheckMAC2(elem.packet.Bytes(), elem.endpoint.DstToBytes()) {
					if err := transport.SendHandshakeCookie(&elem); err != nil {
						logger.Warn("Failed to send handshake cookie", slog.Any("error", err))
					}
					goto skip
				}

				// check ratelimiter

				if !transport.rate.limiter.Allow(elem.endpoint.DstIP()) {
					goto skip
				}
			}

		default:
			logger.Warn("Invalid packet ended up in the handshake queue")
			goto skip
		}

		// handle handshake initiation/response content

		switch elem.msgType {
		case MessageInitiationType:

			// unmarshal

			var msg MessageInitiation
			reader := bytes.NewReader(elem.packet.Bytes())
			err := binary.Read(reader, binary.LittleEndian, &msg)
			if err != nil {
				logger.Warn("Failed to decode initiation message", slog.Any("error", err))
				goto skip
			}

			// consume initiation

			peer := transport.ConsumeMessageInitiation(&msg)
			if peer == nil {
				logger.Warn("Received invalid initiation message")
				goto skip
			}

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// update endpoint
			peer.SetEndpoint(elem.endpoint)

			logger.Debug("Received handshake initiation", slog.String("peer", peer.String()))
			peer.rxBytes.Add(uint64(elem.packet.Size))

			if err := peer.SendHandshakeResponse(); err != nil {
				logger.Error("Failed to send handshake response", slog.Any("error", err))
				goto skip
			}

		case MessageResponseType:

			// unmarshal

			var msg MessageResponse
			reader := bytes.NewReader(elem.packet.Bytes())
			err := binary.Read(reader, binary.LittleEndian, &msg)
			if err != nil {
				logger.Warn("Failed to decode response message", slog.Any("error", err))
				goto skip
			}

			// consume response

			peer := transport.ConsumeMessageResponse(&msg)
			if peer == nil {
				logger.Warn("Received invalid response message")
				goto skip
			}

			// update endpoint
			peer.SetEndpoint(elem.endpoint)

			logger.Debug("Received handshake response")
			peer.rxBytes.Add(uint64(elem.packet.Size))

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// derive keypair

			err = peer.BeginSymmetricSession()

			if err != nil {
				logger.Error("Failed to derive keypair", slog.Any("error", err))
				goto skip
			}

			peer.timersSessionDerived()
			peer.timersHandshakeComplete()
			if err := peer.SendKeepalive(); err != nil {
				logger.Error("Failed to send keepalive", slog.Any("error", err))
				goto skip
			}

			logger.Debug("Handshake complete", slog.String("peer", peer.String()))
		}
	skip:
		elem.packet.Release()
		elem.packet = nil
	}
}

func (peer *Peer) RoutineSequentialReceiver(maxBatchSize int) {
	transport := peer.transport

	logger := transport.logger.With(slog.String("peer", peer.String()))

	defer func() {
		logger.Debug("Routine: sequential receiver - stopped")
		peer.stopping.Done()
	}()
	logger.Debug("Routine: sequential receiver - started")

	packets := make([]*network.Packet, 0, maxBatchSize)

	for elemsContainer := range peer.queue.inbound.c {
		if elemsContainer == nil {
			return
		}
		elemsContainer.Lock()
		validTailPacket := -1
		dataPacketReceived := false
		rxBytesLen := uint64(0)
		for i, elem := range elemsContainer.elems {
			if elem.packet == nil {
				// decryption failed
				continue
			}

			if !elem.keypair.replayFilter.ValidateCounter(elem.counter, RejectAfterMessages) {
				continue
			}

			validTailPacket = i
			if peer.ReceivedWithKeypair(elem.keypair) {
				peer.SetEndpoint(elem.endpoint)
				peer.timersHandshakeComplete()
				if err := peer.SendStagedPackets(); err != nil {
					logger.Warn("Failed to send staged packets", slog.Any("error", err))
					continue
				}
			}
			rxBytesLen += uint64(elem.packet.Size + MinMessageSize)

			if elem.packet.Size == 0 {
				logger.Debug("Receiving keepalive packet")
				continue
			}
			dataPacketReceived = true

			packetBuf := elem.packet.Bytes()
			switch packetBuf[0] >> 4 {
			case 4:
				if elem.packet.Size < ipv4.HeaderLen {
					continue
				}
				field := packetBuf[IPv4offsetTotalLength : IPv4offsetTotalLength+2]
				length := binary.BigEndian.Uint16(field)
				if int(length) > elem.packet.Size || int(length) < ipv4.HeaderLen {
					continue
				}
				elem.packet.Size = int(length)
				srcAddr := netip.AddrFrom4([4]byte(packetBuf[IPv4offsetSrc : IPv4offsetSrc+net.IPv4len]))
				if peerForSrc, ok := transport.allowedips.Get(srcAddr); !ok || peerForSrc != peer {
					logger.Warn("IPv4 packet with disallowed source address",
						slog.String("srcAddr", srcAddr.String()))
					continue
				}

			case 6:
				if elem.packet.Size < ipv6.HeaderLen {
					continue
				}
				field := packetBuf[IPv6offsetPayloadLength : IPv6offsetPayloadLength+2]
				length := binary.BigEndian.Uint16(field)
				length += ipv6.HeaderLen
				if int(length) > elem.packet.Size {
					continue
				}
				elem.packet.Size = int(length)
				srcAddr := netip.AddrFrom16([16]byte(packetBuf[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len]))
				if peerForSrc, ok := transport.allowedips.Get(srcAddr); !ok || peerForSrc != peer {
					logger.Warn("IPv6 packet with disallowed source address",
						slog.String("srcAddr", srcAddr.String()))
					continue
				}

			default:
				logger.Warn("Packet with invalid IP version")
				continue
			}

			packets = append(packets, elem.packet)
		}

		peer.rxBytes.Add(rxBytesLen)
		if validTailPacket >= 0 {
			peer.SetEndpoint(elemsContainer.elems[validTailPacket].endpoint)
			if err := peer.keepKeyFreshReceiving(); err != nil {
				logger.Warn("Failed to keep key fresh", slog.Any("error", err))
			}
			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()
		}
		if dataPacketReceived {
			peer.timersDataReceived()
		}
		if len(packets) > 0 {
			err := transport.nic.nic.Write(transport.ctx, packets)
			if err != nil && !transport.isClosed() {
				logger.Error("Failed to write packets to network interface", slog.Any("error", err))
			}
		}
		for _, elem := range elemsContainer.elems {
			elem.packet = nil // ownership transferred to nic.Write
			transport.PutInboundElement(elem)
		}
		packets = packets[:0]
		transport.PutInboundElementsContainer(elemsContainer)
	}
}
