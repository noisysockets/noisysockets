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
	"os"
	"sync"
	"time"

	"github.com/noisysockets/noisysockets/internal/conn"
	"github.com/noisysockets/noisysockets/types"
	"golang.org/x/crypto/chacha20poly1305"
)

const DefaultMTU = 1420

/* Outbound flow
 *
 * 1. Source queue
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
	buffer  *[MaxMessageSize]byte // slice holding the packet data
	packet  []byte                // slice of "buffer" (always!)
	nonce   uint64                // nonce for encryption
	keypair *Keypair              // keypair for encryption
	peer    *Peer                 // related peer
}

type QueueOutboundElementsContainer struct {
	sync.Mutex
	elems []*QueueOutboundElement
}

func (transport *Transport) NewOutboundElement() *QueueOutboundElement {
	elem := transport.GetOutboundElement()
	elem.buffer = transport.GetMessageBuffer()
	elem.nonce = 0
	// keypair and peer were cleared (if necessary) by clearPointers.
	return elem
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueOutboundElement) clearPointers() {
	elem.buffer = nil
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
			peer.transport.log.Debug("Sending keepalive packet", "peer", peer)
		default:
			peer.transport.PutMessageBuffer(elem.buffer)
			peer.transport.PutOutboundElement(elem)
			peer.transport.PutOutboundElementsContainer(elemsContainer)
		}
	}
	return peer.SendStagedPackets()
}

func (peer *Peer) SendHandshakeInitiation(isRetry bool) error {
	peer.endpoint.Lock()
	endpoint := peer.endpoint.val
	peer.endpoint.Unlock()

	// If we don't have an endpoint, ignore the request.
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

	peer.transport.log.Debug("Sending handshake initiation", "peer", peer)

	msg, err := peer.transport.CreateMessageInitiation(peer)
	if err != nil {
		peer.transport.log.Error("Failed to create initiation message", "peer", peer, "error", err)
		return err
	}

	var buf [MessageInitiationSize]byte
	writer := bytes.NewBuffer(buf[:0])
	if err := binary.Write(writer, binary.LittleEndian, msg); err != nil {
		peer.transport.log.Error("Failed to write initiation message", "peer", peer, "error", err)
		return err
	}

	packet := writer.Bytes()
	peer.cookieGenerator.AddMacs(packet)

	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	err = peer.SendBuffers([][]byte{packet})
	if err != nil {
		peer.transport.log.Error("Failed to send handshake initiation", "peer", peer, "error", err)
	}
	peer.timersHandshakeInitiated()

	return err
}

func (peer *Peer) SendHandshakeResponse() error {
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	peer.transport.log.Debug("Sending handshake response", "peer", peer)

	response, err := peer.transport.CreateMessageResponse(peer)
	if err != nil {
		peer.transport.log.Error("Failed to create handshake response message", "peer", peer, "error", err)
		return err
	}

	var buf [MessageResponseSize]byte
	writer := bytes.NewBuffer(buf[:0])
	if err := binary.Write(writer, binary.LittleEndian, response); err != nil {
		peer.transport.log.Error("Failed to write handshake response message", "peer", peer, "error", err)
		return err
	}

	packet := writer.Bytes()
	peer.cookieGenerator.AddMacs(packet)

	err = peer.BeginSymmetricSession()
	if err != nil {
		peer.transport.log.Error("Failed to derive keypair", "peer", peer, "error", err)
		return err
	}

	peer.timersSessionDerived()
	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	// TODO: allocation could be avoided
	err = peer.SendBuffers([][]byte{packet})
	if err != nil {
		peer.transport.log.Error("Failed to send handshake response", "peer", peer, "error", err)
	}
	return err
}

func (transport *Transport) SendHandshakeCookie(initiatingElem *QueueHandshakeElement) error {
	transport.log.Debug("Sending cookie response for denied handshake message for", "source", initiatingElem.endpoint.DstToString())

	sender := binary.LittleEndian.Uint32(initiatingElem.packet[4:8])
	reply, err := transport.cookieChecker.CreateReply(initiatingElem.packet, sender, initiatingElem.endpoint.DstToBytes())
	if err != nil {
		transport.log.Error("Failed to create cookie reply", "error", err)
		return err
	}

	var buf [MessageCookieReplySize]byte
	writer := bytes.NewBuffer(buf[:0])
	if err := binary.Write(writer, binary.LittleEndian, reply); err != nil {
		transport.log.Error("Failed to write cookie reply", "error", err)
		return err
	}

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
		return peer.SendHandshakeInitiation(false)
	}

	return nil
}

func (transport *Transport) RoutineReadFromSourceSink() {
	defer func() {
		transport.log.Debug("Routine: Source reader - stopped")
		transport.state.stopping.Done()
		transport.queue.encryption.wg.Done()
	}()

	transport.log.Debug("Routine: Source reader - started")

	var (
		batchSize   = transport.BatchSize()
		readErr     error
		elems       = make([]*QueueOutboundElement, batchSize)
		bufs        = make([][]byte, batchSize)
		peers       = make([]types.NoisePublicKey, batchSize)
		elemsByPeer = make(map[*Peer]*QueueOutboundElementsContainer, batchSize)
		count       int
		sizes       = make([]int, batchSize)
		offset      = MessageTransportHeaderSize
	)

	for i := range elems {
		elems[i] = transport.NewOutboundElement()
		bufs[i] = elems[i].buffer[:]
	}

	defer func() {
		for _, elem := range elems {
			if elem != nil {
				transport.PutMessageBuffer(elem.buffer)
				transport.PutOutboundElement(elem)
			}
		}
	}()

	for {
		// read packets
		count, readErr = transport.sourceSink.Read(bufs, sizes, peers, offset)
		for i := 0; i < count; i++ {
			if sizes[i] < 1 {
				continue
			}

			elem := elems[i]
			elem.packet = bufs[i][offset : offset+sizes[i]]

			transport.peers.RLock()
			peer := transport.peers.keyMap[peers[i]]
			transport.peers.RUnlock()
			if peer == nil {
				continue
			}

			elemsForPeer, ok := elemsByPeer[peer]
			if !ok {
				elemsForPeer = transport.GetOutboundElementsContainer()
				elemsByPeer[peer] = elemsForPeer
			}
			elemsForPeer.elems = append(elemsForPeer.elems, elem)
			elems[i] = transport.NewOutboundElement()
			bufs[i] = elems[i].buffer[:]
		}

		for peer, elemsForPeer := range elemsByPeer {
			if peer.isRunning.Load() {
				peer.StagePackets(elemsForPeer)
				if err := peer.SendStagedPackets(); err != nil {
					transport.log.Warn("Failed to send staged packets", "error", err)
					continue
				}
			} else {
				for _, elem := range elemsForPeer.elems {
					transport.PutMessageBuffer(elem.buffer)
					transport.PutOutboundElement(elem)
				}
				transport.PutOutboundElementsContainer(elemsForPeer)
			}
			delete(elemsByPeer, peer)
		}

		if readErr != nil {
			if !transport.isClosed() {
				if !errors.Is(readErr, os.ErrClosed) {
					transport.log.Error("Failed to read packet from source sink", "error", readErr)
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
				peer.transport.PutMessageBuffer(elem.buffer)
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
					peer.transport.PutMessageBuffer(elem.buffer)
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
				peer.transport.PutMessageBuffer(elem.buffer)
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

	defer transport.log.Debug("Routine: encryption worker - stopped", "id", id)
	transport.log.Debug("Routine: encryption worker - started", "id", id)

	for elemsContainer := range transport.queue.encryption.c {
		for _, elem := range elemsContainer.elems {
			// populate header fields
			header := elem.buffer[:MessageTransportHeaderSize]

			fieldType := header[0:4]
			fieldReceiver := header[4:8]
			fieldNonce := header[8:16]

			binary.LittleEndian.PutUint32(fieldType, MessageTransportType)
			binary.LittleEndian.PutUint32(fieldReceiver, elem.keypair.remoteIndex)
			binary.LittleEndian.PutUint64(fieldNonce, elem.nonce)

			// pad content to multiple of 16
			paddingSize := calculatePaddingSize(len(elem.packet), DefaultMTU)
			elem.packet = append(elem.packet, paddingZeros[:paddingSize]...)

			// encrypt content and release to consumer

			binary.LittleEndian.PutUint64(nonce[4:], elem.nonce)
			elem.packet = elem.keypair.send.Seal(
				header,
				nonce[:],
				elem.packet,
				nil,
			)
		}
		elemsContainer.Unlock()
	}
}

func (peer *Peer) RoutineSequentialSender(maxBatchSize int) {
	transport := peer.transport
	defer func() {
		defer transport.log.Debug("Routine: sequential sender - stopped", "peer", peer)
		peer.stopping.Done()
	}()
	transport.log.Debug("Routine: sequential sender - started", "peer", peer)

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
				transport.PutMessageBuffer(elem.buffer)
				transport.PutOutboundElement(elem)
			}
			continue
		}
		dataSent := false
		elemsContainer.Lock()
		for _, elem := range elemsContainer.elems {
			if len(elem.packet) != MessageKeepaliveSize {
				dataSent = true
			}
			bufs = append(bufs, elem.packet)
		}

		peer.timersAnyAuthenticatedPacketTraversal()
		peer.timersAnyAuthenticatedPacketSent()

		err := peer.SendBuffers(bufs)
		if dataSent {
			peer.timersDataSent()
		}
		for _, elem := range elemsContainer.elems {
			transport.PutMessageBuffer(elem.buffer)
			transport.PutOutboundElement(elem)
		}
		transport.PutOutboundElementsContainer(elemsContainer)
		if err != nil {
			var errGSO conn.ErrUDPGSODisabled
			if errors.As(err, &errGSO) {
				transport.log.Warn("Failed to send data packets, retrying", "peer", peer, "error", err)
				err = errGSO.RetryErr
			}
		}
		if err != nil {
			transport.log.Error("Failed to send data packets", "peer", peer, "error", err)
			continue
		}

		if err := peer.keepKeyFreshSending(); err != nil {
			transport.log.Error("Failed to keep key fresh", "peer", peer, "error", err)
		}
	}
}
