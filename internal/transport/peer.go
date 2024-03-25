/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 * Copyright (c) 2024 Damian Peckett <damian@pecke.tt>.
 */

package transport

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/noisysockets/noisysockets/internal/conn"
)

type Peer struct {
	pk                NoisePublicKey
	isRunning         atomic.Bool
	keypairs          Keypairs
	handshake         Handshake
	transport         *Transport
	stopping          sync.WaitGroup // routines pending stop
	txBytes           atomic.Uint64  // bytes send to peer (endpoint)
	rxBytes           atomic.Uint64  // bytes received from peer
	lastHandshakeNano atomic.Int64   // nano seconds since epoch

	endpoint struct {
		sync.Mutex
		val conn.Endpoint
	}

	timers struct {
		retransmitHandshake     *Timer
		sendKeepalive           *Timer
		newHandshake            *Timer
		zeroKeyMaterial         *Timer
		persistentKeepalive     *Timer
		handshakeAttempts       atomic.Uint32
		needAnotherKeepalive    atomic.Bool
		sentLastMinuteHandshake atomic.Bool
	}

	state struct {
		sync.Mutex // protects against concurrent Start/Stop
	}

	queue struct {
		staged   chan *QueueOutboundElementsContainer // staged packets before a handshake is available
		outbound *autodrainingOutboundQueue           // sequential ordering of udp transmission
		inbound  *autodrainingInboundQueue            // sequential ordering of sink writing
	}

	cookieGenerator             CookieGenerator
	persistentKeepaliveInterval atomic.Uint32
}

func (transport *Transport) NewPeer(pk NoisePublicKey) (*Peer, error) {
	if transport.isClosed() {
		return nil, errors.New("transport closed")
	}

	// lock resources
	transport.staticIdentity.RLock()
	defer transport.staticIdentity.RUnlock()

	transport.peers.Lock()
	defer transport.peers.Unlock()

	// check if over limit
	if len(transport.peers.keyMap) >= MaxPeers {
		return nil, errors.New("too many peers")
	}

	// create peer
	peer := new(Peer)

	peer.pk = pk
	peer.cookieGenerator.Init(pk)
	peer.transport = transport
	peer.queue.outbound = newAutodrainingOutboundQueue(transport)
	peer.queue.inbound = newAutodrainingInboundQueue(transport)
	peer.queue.staged = make(chan *QueueOutboundElementsContainer, QueueStagedSize)

	// map public key
	_, ok := transport.peers.keyMap[pk]
	if ok {
		return nil, errors.New("adding existing peer")
	}

	// pre-compute DH
	handshake := &peer.handshake
	handshake.mutex.Lock()
	handshake.precomputedStaticStatic, _ = transport.staticIdentity.privateKey.sharedSecret(pk)
	handshake.remoteStatic = pk
	handshake.mutex.Unlock()

	// reset endpoint
	peer.endpoint.Lock()
	peer.endpoint.val = nil
	peer.endpoint.Unlock()

	// init timers
	peer.timersInit()

	// add
	transport.peers.keyMap[pk] = peer

	return peer, nil
}

func (peer *Peer) SendBuffers(buffers [][]byte) error {
	peer.transport.net.RLock()
	defer peer.transport.net.RUnlock()

	if peer.transport.isClosed() {
		return nil
	}

	peer.endpoint.Lock()
	endpoint := peer.endpoint.val
	if endpoint == nil {
		peer.endpoint.Unlock()
		return errors.New("no known endpoint for peer")
	}
	peer.endpoint.Unlock()

	err := peer.transport.net.bind.Send(buffers, endpoint)
	if err == nil {
		var totalLen uint64
		for _, b := range buffers {
			totalLen += uint64(len(b))
		}
		peer.txBytes.Add(totalLen)
	}
	return err
}

func (peer *Peer) String() string {
	base64Key := base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:])
	abbreviatedKey := base64Key[0:4] + "…" + base64Key[39:43]
	return fmt.Sprintf("peer(%s)", abbreviatedKey)
}

func (peer *Peer) Start() {
	// should never start a peer on a closed transport.
	if peer.transport.isClosed() {
		return
	}

	// prevent simultaneous start/stop operations
	peer.state.Lock()
	defer peer.state.Unlock()

	if peer.isRunning.Load() {
		return
	}

	transport := peer.transport
	transport.log.Debug("Starting", "peer", peer)

	// reset routine state
	peer.stopping.Wait()
	peer.stopping.Add(2)

	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	peer.handshake.mutex.Unlock()

	peer.transport.queue.encryption.wg.Add(1) // keep encryption queue open for our writes

	peer.timersStart()

	transport.flushInboundQueue(peer.queue.inbound)
	transport.flushOutboundQueue(peer.queue.outbound)

	// Use the transport batch size, not the bind batch size, as the transport size is
	// the size of the batch pools.
	batchSize := peer.transport.BatchSize()
	go peer.RoutineSequentialSender(batchSize)
	go peer.RoutineSequentialReceiver(batchSize)

	peer.isRunning.Store(true)
}

func (peer *Peer) ZeroAndFlushAll() {
	transport := peer.transport

	// clear key pairs

	keypairs := &peer.keypairs
	keypairs.Lock()
	transport.DeleteKeypair(keypairs.previous)
	transport.DeleteKeypair(keypairs.current)
	transport.DeleteKeypair(keypairs.next.Load())
	keypairs.previous = nil
	keypairs.current = nil
	keypairs.next.Store(nil)
	keypairs.Unlock()

	// clear handshake state

	handshake := &peer.handshake
	handshake.mutex.Lock()
	transport.indexTable.Delete(handshake.localIndex)
	handshake.Clear()
	handshake.mutex.Unlock()

	peer.FlushStagedPackets()
}

func (peer *Peer) ExpireCurrentKeypairs() {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	peer.transport.indexTable.Delete(handshake.localIndex)
	handshake.Clear()
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	handshake.mutex.Unlock()

	keypairs := &peer.keypairs
	keypairs.Lock()
	if keypairs.current != nil {
		keypairs.current.sendNonce.Store(RejectAfterMessages)
	}
	if next := keypairs.next.Load(); next != nil {
		next.sendNonce.Store(RejectAfterMessages)
	}
	keypairs.Unlock()
}

func (peer *Peer) Stop() {
	peer.state.Lock()
	defer peer.state.Unlock()

	if !peer.isRunning.Swap(false) {
		return
	}

	peer.transport.log.Debug("Stopping", "peer", peer)

	peer.timersStop()
	// Signal that RoutineSequentialSender and RoutineSequentialReceiver should exit.
	peer.queue.inbound.c <- nil
	peer.queue.outbound.c <- nil
	peer.stopping.Wait()
	peer.transport.queue.encryption.wg.Done() // no more writes to encryption queue from us

	peer.ZeroAndFlushAll()
}

func (peer *Peer) SetEndpointFromPacket(endpoint conn.Endpoint) {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()
	peer.endpoint.val = endpoint
}

func (peer *Peer) SetPresharedKey(psk NoisePresharedKey) {
	peer.handshake.mutex.Lock()
	peer.handshake.presharedKey = psk
	peer.handshake.mutex.Unlock()
}
