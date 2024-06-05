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

/* Outbound flow
 *
 * 1. TUN queue
 * 2. Routing (sequential)
 * 3. Nonce assignment (sequential)
 * 4. Encryption (parallel)
 * 5. Transmission (sequential)
 *
 * The functions in this file occur (roughly) in the order in
 * which the packets are processed.
 *
 * Locking, Producers and Consumers
 *
 * The order of packets (per peer) must be maintained,
 * but encryption of packets happen out-of-order:
 *
 * The sequential consumers will attempt to take the lock,
 * workers release lock when they have completed work (encryption) on the packet.
 *
 * If the element is inserted into the "encryption queue",
 * the content is preceded by enough "junk" to contain the transport header
 * (to allow the construction of transport messages in-place)
 */

type QueueOutboundElement struct {
	packet  *network.Packet // packet to send
	nonce   uint64          // nonce for encryption
	keypair *Keypair        // keypair for encryption
	peer    *Peer           // related peer
}

type QueueOutboundElementsContainer struct {
	sync.Mutex
	elems []*QueueOutboundElement
}

func (transport *Transport) NewOutboundElement() *QueueOutboundElement {
	elem := transport.GetOutboundElement()
	elem.packet = transport.pool.packets.Borrow()
	elem.nonce = 0
	// keypair and peer were cleared (if necessary) by clearPointers.
	return elem
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueOutboundElement) clearPointers() {
	elem.packet = nil
	elem.keypair = nil
	elem.peer = nil
}

/* Queues a keepalive if no packets are queued for peer
 */
func (peer *Peer) SendKeepalive() error {
	if len(peer.queue.staged) == 0 && peer.isRunning.Load() {
		elem := peer.transport.NewOutboundElement()
		elemsContainer := peer.transport.GetOutboundElementsContainer()
		elemsContainer.elems = append(elemsContainer.elems, elem)
		select {
		case peer.queue.staged <- elemsContainer:
			peer.transport.logger.Debug("Sending keepalive packet", slog.String("peer", peer.String()))
		default:
			elem.packet.Release()
			peer.transport.PutOutboundElement(elem)
			peer.transport.PutOutboundElementsContainer(elemsContainer)
		}
	}
	return peer.SendStagedPackets()
}

func (peer *Peer) SendHandshakeInitiation(isRetry bool) error {
	logger := peer.transport.logger.With(slog.String("peer", peer.String()))

	peer.endpoint.Lock()
	endpoint := peer.endpoint.val
	peer.endpoint.Unlock()

	// If we don't have a destination endpoint, ignore the request.
	if endpoint == nil {
		return nil
	}

	if !isRetry {
		peer.timers.handshakeAttempts.Store(0)
	}

	peer.handshake.mutex.RLock()
	if time.Since(peer.handshake.lastSentHandshake) < RekeyTimeout {
		peer.handshake.mutex.RUnlock()
		return nil
	}
	peer.handshake.mutex.RUnlock()

	peer.handshake.mutex.Lock()
	if time.Since(peer.handshake.lastSentHandshake) < RekeyTimeout {
		peer.handshake.mutex.Unlock()
		return nil
	}
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	logger.Debug("Sending handshake initiation")

	msg, err := peer.transport.CreateMessageInitiation(peer)
	if err != nil {
		logger.Warn("Failed to create initiation message", slog.Any("error", err))
		return err
	}

	var buf [MessageInitiationSize]byte
	writer := bytes.NewBuffer(buf[:0])
	_ = binary.Write(writer, binary.LittleEndian, msg)
	packet := writer.Bytes()
	peer.cookieGenerator.AddMacs(packet)

	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	err = peer.SendBuffers([][]byte{packet})
	if err != nil {
		logger.Warn("Failed to send handshake initiation", slog.Any("error", err))
	}
	peer.timersHandshakeInitiated()

	return err
}

func (peer *Peer) SendHandshakeResponse() error {
	logger := peer.transport.logger.With(slog.String("peer", peer.String()))

	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	logger.Debug("Sending handshake response")

	response, err := peer.transport.CreateMessageResponse(peer)
	if err != nil {
		logger.Warn("Failed to create response message", slog.Any("error", err))
		return err
	}

	var buf [MessageResponseSize]byte
	writer := bytes.NewBuffer(buf[:0])
	_ = binary.Write(writer, binary.LittleEndian, response)
	packet := writer.Bytes()
	peer.cookieGenerator.AddMacs(packet)

	err = peer.BeginSymmetricSession()
	if err != nil {
		logger.Warn("Failed to derive keypair", slog.Any("error", err))
		return err
	}

	peer.timersSessionDerived()
	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	// TODO: allocation could be avoided
	err = peer.SendBuffers([][]byte{packet})
	if err != nil {
		logger.Warn("Failed to send handshake response", slog.Any("error", err))
		return err
	}

	return nil
}

func (transport *Transport) SendHandshakeCookie(initiatingElem *QueueHandshakeElement) error {
	logger := transport.logger.With(slog.String("source", initiatingElem.endpoint.DstToString()))

	logger.Debug("Sending cookie response for denied handshake message")

	packetBuf := initiatingElem.packet.Bytes()
	sender := binary.LittleEndian.Uint32(packetBuf[4:8])
	reply, err := transport.cookieChecker.CreateReply(packetBuf, sender, initiatingElem.endpoint.DstToBytes())
	if err != nil {
		logger.Warn("Failed to create cookie reply", slog.Any("error", err))
		return err
	}

	var buf [MessageCookieReplySize]byte
	writer := bytes.NewBuffer(buf[:0])
	_ = binary.Write(writer, binary.LittleEndian, reply)
	// TODO: allocation could be avoided
	return transport.net.bind.Send([][]byte{writer.Bytes()}, initiatingElem.endpoint)
}

func (peer *Peer) keepKeyFreshSending() error {
	keypair := peer.keypairs.Current()
	if keypair == nil {
		return nil
	}
	nonce := keypair.sendNonce.Load()
	if nonce > RekeyAfterMessages || (keypair.isInitiator && time.Since(keypair.created) > RekeyAfterTime) {
		if err := peer.SendHandshakeInitiation(false); err != nil {
			return err
		}
	}
	return nil
}

func (transport *Transport) RoutineReadFromNIC() {
	defer func() {
		transport.logger.Debug("Routine: NIC reader - stopped")
		transport.state.stopping.Done()
		transport.queue.encryption.wg.Done()
	}()

	transport.logger.Debug("Routine: NIC reader - started")

	var (
		batchSize   = transport.BatchSize()
		readErr     error
		elems       = make([]*QueueOutboundElement, batchSize)
		packets     = make([]*network.Packet, batchSize)
		elemsByPeer = make(map[*Peer]*QueueOutboundElementsContainer, batchSize)
		count       int
		offset      = MessageTransportHeaderSize
	)

	for i := range elems {
		elems[i] = transport.NewOutboundElement()
		packets[i] = elems[i].packet
	}
	defer func() {
		for _, elem := range elems {
			if elem != nil {
				elem.packet.Release()
				transport.PutOutboundElement(elem)
			}
		}
	}()

	for {
		// read packets
		count, readErr = transport.nic.nic.Read(transport.ctx, packets, offset)
		for i := 0; i < count; i++ {
			if packets[i].Size < 1 {
				continue
			}

			elem := elems[i]

			// lookup peer
			var peer *Peer
			packetBuf := elem.packet.Bytes()
			switch packetBuf[0] >> 4 {
			case 4:
				if elem.packet.Size < ipv4.HeaderLen {
					transport.logger.Warn("Received outbound IPv4 packet with invalid size")

					continue
				}

				var ok bool
				dstAddr := netip.AddrFrom4([4]byte(packetBuf[IPv4offsetDst : IPv4offsetDst+net.IPv4len]))
				peer, ok = transport.allowedips.Get(dstAddr)
				if !ok {
					transport.logger.Warn("Received outbound IPv4 packet for unknown peer",
						slog.String("dstAddr", dstAddr.String()))
					continue
				}

			case 6:
				if elem.packet.Size < ipv6.HeaderLen {
					transport.logger.Warn("Received outbound IPv6 packet with invalid size")

					continue
				}

				var ok bool
				dstAddr := netip.AddrFrom16([16]byte(packetBuf[IPv6offsetDst : IPv6offsetDst+net.IPv6len]))
				peer, ok = transport.allowedips.Get(dstAddr)
				if !ok {
					transport.logger.Warn("Received outbound IPv6 packet for unknown peer",
						slog.String("dstAddr", dstAddr.String()))
					continue
				}

			default:
				transport.logger.Warn("Received packet with unknown IP version")
			}

			elemsForPeer, ok := elemsByPeer[peer]
			if !ok {
				elemsForPeer = transport.GetOutboundElementsContainer()
				elemsByPeer[peer] = elemsForPeer
			}
			elemsForPeer.elems = append(elemsForPeer.elems, elem)
			elems[i] = transport.NewOutboundElement()
			packets[i] = elems[i].packet
		}

		for peer, elemsForPeer := range elemsByPeer {
			if peer.isRunning.Load() {
				peer.StagePackets(elemsForPeer)
				if err := peer.SendStagedPackets(); err != nil {
					transport.logger.Warn("Failed to send staged packets",
						slog.String("peer", peer.String()), slog.Any("error", err))
					continue
				}
			} else {
				for _, elem := range elemsForPeer.elems {
					elem.packet.Release()
					transport.PutOutboundElement(elem)
				}
				transport.PutOutboundElementsContainer(elemsForPeer)
			}
			delete(elemsByPeer, peer)
		}

		if readErr != nil {
			if !transport.isClosed() {
				if !errors.Is(readErr, os.ErrClosed) {
					transport.logger.Error("Failed to read packet from NIC", slog.Any("error", readErr))
				}
				go transport.Close()
			}
			return
		}
	}
}

func (peer *Peer) StagePackets(elems *QueueOutboundElementsContainer) {
	for {
		select {
		case peer.queue.staged <- elems:
			return
		default:
		}
		select {
		case tooOld := <-peer.queue.staged:
			for _, elem := range tooOld.elems {
				elem.packet.Release()
				peer.transport.PutOutboundElement(elem)
			}
			peer.transport.PutOutboundElementsContainer(tooOld)
		default:
		}
	}
}

func (peer *Peer) SendStagedPackets() error {
top:
	if len(peer.queue.staged) == 0 || !peer.transport.isUp() {
		return nil
	}

	keypair := peer.keypairs.Current()
	if keypair == nil || keypair.sendNonce.Load() >= RejectAfterMessages || time.Since(keypair.created) >= RejectAfterTime {
		peer.transport.logger.Debug("Sending initial handshake or rekey")

		return peer.SendHandshakeInitiation(false)
	}

	for {
		var elemsContainerOOO *QueueOutboundElementsContainer
		select {
		case elemsContainer := <-peer.queue.staged:
			i := 0
			for _, elem := range elemsContainer.elems {
				elem.peer = peer
				elem.nonce = keypair.sendNonce.Add(1) - 1
				if elem.nonce >= RejectAfterMessages {
					keypair.sendNonce.Store(RejectAfterMessages)
					if elemsContainerOOO == nil {
						elemsContainerOOO = peer.transport.GetOutboundElementsContainer()
					}
					elemsContainerOOO.elems = append(elemsContainerOOO.elems, elem)
					continue
				} else {
					elemsContainer.elems[i] = elem
					i++
				}

				elem.keypair = keypair
			}
			elemsContainer.Lock()
			elemsContainer.elems = elemsContainer.elems[:i]

			if elemsContainerOOO != nil {
				peer.StagePackets(elemsContainerOOO) // XXX: Out of order, but we can't front-load go chans
			}

			if len(elemsContainer.elems) == 0 {
				peer.transport.PutOutboundElementsContainer(elemsContainer)
				goto top
			}

			// add to parallel and sequential queue
			if peer.isRunning.Load() {
				peer.queue.outbound.c <- elemsContainer
				peer.transport.queue.encryption.c <- elemsContainer
			} else {
				for _, elem := range elemsContainer.elems {
					elem.packet.Release()
					peer.transport.PutOutboundElement(elem)
				}
				peer.transport.PutOutboundElementsContainer(elemsContainer)
			}

			if elemsContainerOOO != nil {
				goto top
			}
		default:
			return nil
		}
	}
}

func (peer *Peer) FlushStagedPackets() {
	for {
		select {
		case elemsContainer := <-peer.queue.staged:
			for _, elem := range elemsContainer.elems {
				elem.packet.Release()
				peer.transport.PutOutboundElement(elem)
			}
			peer.transport.PutOutboundElementsContainer(elemsContainer)
		default:
			return
		}
	}
}

func calculatePaddingSize(packetSize, mtu int) int {
	lastUnit := packetSize
	if mtu == 0 {
		return ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1)) - lastUnit
	}
	if lastUnit > mtu {
		lastUnit %= mtu
	}
	paddedSize := ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1))
	if paddedSize > mtu {
		paddedSize = mtu
	}
	return paddedSize - lastUnit
}

/* Encrypts the elements in the queue
 * and marks them for sequential consumption (by releasing the mutex)
 *
 * Obs. One instance per core
 */
func (transport *Transport) RoutineEncryption(id int) {
	var paddingZeros [PaddingMultiple]byte
	var nonce [chacha20poly1305.NonceSize]byte

	logger := transport.logger.With(slog.Int("id", id))

	defer logger.Debug("Routine: encryption worker - stopped")
	logger.Debug("Routine: encryption worker - started")

	for elemsContainer := range transport.queue.encryption.c {
		for _, elem := range elemsContainer.elems {
			// populate header fields
			header := elem.packet.Buf[:MessageTransportHeaderSize]

			fieldType := header[0:4]
			fieldReceiver := header[4:8]
			fieldNonce := header[8:16]

			binary.LittleEndian.PutUint32(fieldType, MessageTransportType)
			binary.LittleEndian.PutUint32(fieldReceiver, elem.keypair.remoteIndex)
			binary.LittleEndian.PutUint64(fieldNonce, elem.nonce)

			// pad content to multiple of 16
			paddingSize := calculatePaddingSize(elem.packet.Size, int(transport.nic.mtu.Load()))
			copy(elem.packet.Buf[elem.packet.Offset+elem.packet.Size:], paddingZeros[:paddingSize])
			elem.packet.Size += paddingSize

			// encrypt content and release to consumer

			binary.LittleEndian.PutUint64(nonce[4:], elem.nonce)

			elem.packet.Size = len(elem.keypair.send.Seal(
				header,
				nonce[:],
				elem.packet.Bytes(),
				nil,
			))
			elem.packet.Offset = 0
		}
		elemsContainer.Unlock()
	}
}

func (peer *Peer) RoutineSequentialSender(maxBatchSize int) {
	logger := peer.transport.logger.With(slog.String("peer", peer.String()))

	transport := peer.transport
	defer func() {
		defer logger.Debug("Routine: sequential sender - stopped")
		peer.stopping.Done()
	}()
	logger.Debug("Routine: sequential sender - started")

	bufs := make([][]byte, 0, maxBatchSize)

	for elemsContainer := range peer.queue.outbound.c {
		bufs = bufs[:0]
		if elemsContainer == nil {
			return
		}
		if !peer.isRunning.Load() {
			// peer has been stopped; return re-usable elems to the shared pool.
			// This is an optimization only. It is possible for the peer to be stopped
			// immediately after this check, in which case, elem will get processed.
			// The timers and SendBuffers code are resilient to a few stragglers.
			// TODO: rework peer shutdown order to ensure
			// that we never accidentally keep timers alive longer than necessary.
			elemsContainer.Lock()
			for _, elem := range elemsContainer.elems {
				elem.packet.Release()
				transport.PutOutboundElement(elem)
			}
			continue
		}
		dataSent := false
		elemsContainer.Lock()
		for _, elem := range elemsContainer.elems {
			if elem.packet.Size != MessageKeepaliveSize {
				dataSent = true
			}
			bufs = append(bufs, elem.packet.Bytes())
		}

		peer.timersAnyAuthenticatedPacketTraversal()
		peer.timersAnyAuthenticatedPacketSent()

		err := peer.SendBuffers(bufs)
		if dataSent {
			peer.timersDataSent()
		}
		for _, elem := range elemsContainer.elems {
			elem.packet.Release()
			transport.PutOutboundElement(elem)
		}
		transport.PutOutboundElementsContainer(elemsContainer)
		if err != nil {
			var errGSO conn.ErrUDPGSODisabled
			if errors.As(err, &errGSO) {
				logger.Debug("Failed to send data packets, retrying", slog.Any("error", err))
				err = errGSO.RetryErr
			}
		}
		if err != nil {
			logger.Error("Failed to send data packets", slog.Any("error", err))
			continue
		}

		if err := peer.keepKeyFreshSending(); err != nil {
			logger.Warn("Failed to keep key fresh", slog.Any("error", err))
		}
	}
}
