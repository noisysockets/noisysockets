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

package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/noisysockets/noisysockets/internal/conn"
	"github.com/noisysockets/noisysockets/types"
	"golang.org/x/crypto/chacha20poly1305"
)

type QueueHandshakeElement struct {
	msgType  uint32
	packet   []byte
	endpoint conn.Endpoint
	buffer   *[MaxMessageSize]byte
}

type QueueInboundElement struct {
	buffer   *[MaxMessageSize]byte
	packet   []byte
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
	elem.buffer = nil
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

/* Receives incoming datagrams for the transport
 *
 * Every time the bind is updated a new routine is started for
 * IPv4 and IPv6 (separately)
 */
func (transport *Transport) RoutineReceiveIncoming(maxBatchSize int, recv conn.ReceiveFunc) {
	recvName := recv.PrettyName()
	defer func() {
		transport.log.Debug("Routine: receive incoming - stopped", "recvName", recvName)
		transport.queue.decryption.wg.Done()
		transport.queue.handshake.wg.Done()
		transport.net.stopping.Done()
	}()

	transport.log.Debug("Routine: receive incoming - started", "recvName", recvName)

	// receive datagrams until conn is closed

	var (
		bufsArrs    = make([]*[MaxMessageSize]byte, maxBatchSize)
		bufs        = make([][]byte, maxBatchSize)
		err         error
		sizes       = make([]int, maxBatchSize)
		count       int
		endpoints   = make([]conn.Endpoint, maxBatchSize)
		deathSpiral int
		elemsByPeer = make(map[*Peer]*QueueInboundElementsContainer, maxBatchSize)
	)

	for i := range bufsArrs {
		bufsArrs[i] = transport.GetMessageBuffer()
		bufs[i] = bufsArrs[i][:]
	}

	defer func() {
		for i := 0; i < maxBatchSize; i++ {
			if bufsArrs[i] != nil {
				transport.PutMessageBuffer(bufsArrs[i])
			}
		}
	}()

	for {
		count, err = recv(bufs, sizes, endpoints)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			transport.log.Warn("Failed to receive packet", "recvName", recvName, "error", err)
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
			if size < MinMessageSize {
				continue
			}

			// check size of packet

			packet := bufsArrs[i][:size]
			msgType := binary.LittleEndian.Uint32(packet[:4])

			switch msgType {

			// check if transport

			case MessageTransportType:

				// check size

				if len(packet) < MessageTransportSize {
					continue
				}

				// lookup key pair

				receiver := binary.LittleEndian.Uint32(
					packet[MessageTransportOffsetReceiver:MessageTransportOffsetCounter],
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
				elem.packet = packet
				elem.buffer = bufsArrs[i]
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
				bufsArrs[i] = transport.GetMessageBuffer()
				bufs[i] = bufsArrs[i][:]
				continue

			// otherwise it is a fixed size & handshake related packet

			case MessageInitiationType:
				if len(packet) != MessageInitiationSize {
					continue
				}

			case MessageResponseType:
				if len(packet) != MessageResponseSize {
					continue
				}

			case MessageCookieReplyType:
				if len(packet) != MessageCookieReplySize {
					continue
				}

			default:
				transport.log.Warn("Received message with unknown type", "type", msgType)
				continue
			}

			select {
			case transport.queue.handshake.c <- QueueHandshakeElement{
				msgType:  msgType,
				buffer:   bufsArrs[i],
				packet:   packet,
				endpoint: endpoints[i],
			}:
				bufsArrs[i] = transport.GetMessageBuffer()
				bufs[i] = bufsArrs[i][:]
			default:
			}
		}
		for peer, elemsContainer := range elemsByPeer {
			if peer.isRunning.Load() {
				peer.queue.inbound.c <- elemsContainer
				transport.queue.decryption.c <- elemsContainer
			} else {
				for _, elem := range elemsContainer.elems {
					transport.PutMessageBuffer(elem.buffer)
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

	defer transport.log.Debug("Routine: decryption worker - stopped", "id", id)
	transport.log.Debug("Routine: decryption worker - started", "id", id)

	for elemsContainer := range transport.queue.decryption.c {
		for _, elem := range elemsContainer.elems {
			// split message into fields
			counter := elem.packet[MessageTransportOffsetCounter:MessageTransportOffsetContent]
			content := elem.packet[MessageTransportOffsetContent:]

			// decrypt and release to consumer
			var err error
			elem.counter = binary.LittleEndian.Uint64(counter)
			// copy counter to nonce
			binary.LittleEndian.PutUint64(nonce[0x4:0xc], elem.counter)
			elem.packet, err = elem.keypair.receive.Open(
				content[:0],
				nonce[:],
				content,
				nil,
			)
			if err != nil {
				elem.packet = nil
			}
		}
		elemsContainer.Unlock()
	}
}

// Handles incoming packets related to handshake.
func (transport *Transport) RoutineHandshake(id int) {
	defer func() {
		transport.log.Debug("Routine: handshake worker - stopped", "id", id)
		transport.queue.encryption.wg.Done()
	}()
	transport.log.Debug("Routine: handshake worker - started", "id", id)

	for elem := range transport.queue.handshake.c {

		// handle cookie fields and ratelimiting

		switch elem.msgType {

		case MessageCookieReplyType:

			// unmarshal packet

			var reply MessageCookieReply
			reader := bytes.NewReader(elem.packet)
			err := binary.Read(reader, binary.LittleEndian, &reply)
			if err != nil {
				transport.log.Warn("Failed to decode cookie reply")
				goto skip
			}

			// lookup peer from index

			entry := transport.indexTable.Lookup(reply.Receiver)

			if entry.peer == nil {
				goto skip
			}

			// consume reply

			if peer := entry.peer; peer.isRunning.Load() {
				transport.log.Debug("Receiving cookie response", "from", elem.endpoint.DstToString())
				if !peer.cookieGenerator.ConsumeReply(&reply) {
					transport.log.Warn("Could not decrypt invalid cookie response")
				}
			}

			goto skip

		case MessageInitiationType, MessageResponseType:

			// check mac fields and maybe ratelimit

			if !transport.cookieChecker.CheckMAC1(elem.packet) {
				transport.log.Warn("Received packet with invalid mac1")
				goto skip
			}

			// endpoints destination address is the source of the datagram

			if transport.IsUnderLoad() {

				// verify MAC2 field

				if !transport.cookieChecker.CheckMAC2(elem.packet, elem.endpoint.DstToBytes()) {
					if err := transport.SendHandshakeCookie(&elem); err != nil {
						transport.log.Warn("Failed to send handshake cookie", "error", err)
					}
					goto skip
				}

				// check ratelimiter

				if !transport.rate.limiter.Allow(elem.endpoint.DstIP()) {
					goto skip
				}
			}

		default:
			transport.log.Warn("Invalid packet ended up in the handshake queue")
			goto skip
		}

		// handle handshake initiation/response content

		switch elem.msgType {
		case MessageInitiationType:

			// unmarshal

			var msg MessageInitiation
			reader := bytes.NewReader(elem.packet)
			err := binary.Read(reader, binary.LittleEndian, &msg)
			if err != nil {
				transport.log.Warn("Failed to decode initiation message")
				goto skip
			}

			// consume initiation

			peer := transport.ConsumeMessageInitiation(&msg)
			if peer == nil {
				transport.log.Warn("Received invalid initiation message", "from", elem.endpoint.DstToString())
				goto skip
			}

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// update endpoint
			peer.SetEndpoint(elem.endpoint)

			transport.log.Debug("Received handshake initiation", "peer", peer)
			peer.rxBytes.Add(uint64(len(elem.packet)))

			if err := peer.SendHandshakeResponse(); err != nil {
				transport.log.Error("Failed to send handshake response", "error", err)
				goto skip
			}

		case MessageResponseType:

			// unmarshal

			var msg MessageResponse
			reader := bytes.NewReader(elem.packet)
			err := binary.Read(reader, binary.LittleEndian, &msg)
			if err != nil {
				transport.log.Warn("Failed to decode response message", "error", err)
				goto skip
			}

			// consume response

			peer := transport.ConsumeMessageResponse(&msg)
			if peer == nil {
				transport.log.Warn("Received invalid response message", "from", elem.endpoint.DstToString())
				goto skip
			}

			// update endpoint
			peer.SetEndpoint(elem.endpoint)

			transport.log.Debug("Received handshake response", "peer", peer)
			peer.rxBytes.Add(uint64(len(elem.packet)))

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// derive keypair
			if err := peer.BeginSymmetricSession(); err != nil {
				transport.log.Error("Failed to derive keypair", "peer", peer, "error", err)
				goto skip
			}

			peer.timersSessionDerived()
			peer.timersHandshakeComplete()
			if err := peer.SendKeepalive(); err != nil {
				transport.log.Error("Failed to send keepalive", "peer", peer, "error", err)
				goto skip
			}
		}
	skip:
		transport.PutMessageBuffer(elem.buffer)
	}
}

func (peer *Peer) RoutineSequentialReceiver(maxBatchSize int) {
	t := peer.transport
	defer func() {
		t.log.Debug("Routine: sequential receiver - stopped", "peer", peer)
		peer.stopping.Done()
	}()
	t.log.Debug("Routine: sequential receiver - started", "peer", peer)

	bufs := make([][]byte, 0, maxBatchSize)

	peers := make([]types.NoisePublicKey, 0, maxBatchSize)
	for i := 0; i < maxBatchSize; i++ {
		peers = append(peers, peer.pk)
	}

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
					t.log.Warn("Failed to send staged packets", "peer", peer, "error", err)
					continue
				}
			}
			rxBytesLen += uint64(len(elem.packet) + MinMessageSize)

			if len(elem.packet) == 0 {
				t.log.Debug("Receiving keepalive packet", "peer", peer)
				continue
			}
			dataPacketReceived = true

			bufs = append(bufs, elem.buffer[:MessageTransportOffsetContent+len(elem.packet)])
		}

		peer.rxBytes.Add(rxBytesLen)
		if validTailPacket >= 0 {
			peer.SetEndpoint(elemsContainer.elems[validTailPacket].endpoint)
			if err := peer.keepKeyFreshReceiving(); err != nil {
				t.log.Warn("Failed to keep key fresh", "peer", peer, "error", err)
				continue
			}
			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()
		}
		if dataPacketReceived {
			peer.timersDataReceived()
		}
		if len(bufs) > 0 {
			_, err := t.sourceSink.Write(bufs, peers, MessageTransportOffsetContent)
			if err != nil && !t.isClosed() {
				t.log.Error("Failed to write packets to source sink", "peer", peer, "error", err)
			}
		}
		for _, elem := range elemsContainer.elems {
			t.PutMessageBuffer(elem.buffer)
			t.PutInboundElement(elem)
		}
		bufs = bufs[:0]
		t.PutInboundElementsContainer(elemsContainer)
	}
}
