/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 * Copyright (c) 2024 Damian Peckett <damian@pecke.tt>.
 */

package transport

import (
	"runtime"
	"sync"
)

// An outboundQueue is a channel of QueueOutboundElements awaiting encryption.
// An outboundQueue is ref-counted using its wg field.
// An outboundQueue created with newOutboundQueue has one reference.
// Every additional writer must call wg.Add(1).
// Every completed writer must call wg.Done().
// When no further writers will be added,
// call wg.Done to remove the initial reference.
// When the refcount hits 0, the queue's channel is closed.
type outboundQueue struct {
	c  chan *QueueOutboundElementsContainer
	wg sync.WaitGroup
}

func newOutboundQueue() *outboundQueue {
	q := &outboundQueue{
		c: make(chan *QueueOutboundElementsContainer, QueueOutboundSize),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}

// A inboundQueue is similar to an outboundQueue; see those docs.
type inboundQueue struct {
	c  chan *QueueInboundElementsContainer
	wg sync.WaitGroup
}

func newInboundQueue() *inboundQueue {
	q := &inboundQueue{
		c: make(chan *QueueInboundElementsContainer, QueueInboundSize),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}

// A handshakeQueue is similar to an outboundQueue; see those docs.
type handshakeQueue struct {
	c  chan QueueHandshakeElement
	wg sync.WaitGroup
}

func newHandshakeQueue() *handshakeQueue {
	q := &handshakeQueue{
		c: make(chan QueueHandshakeElement, QueueHandshakeSize),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}

type autodrainingInboundQueue struct {
	c chan *QueueInboundElementsContainer
}

// newAutodrainingInboundQueue returns a channel that will be drained when it gets GC'd.
// It is useful in cases in which is it hard to manage the lifetime of the channel.
// The returned channel must not be closed. Senders should signal shutdown using
// some other means, such as sending a sentinel nil values.
func newAutodrainingInboundQueue(transport *Transport) *autodrainingInboundQueue {
	q := &autodrainingInboundQueue{
		c: make(chan *QueueInboundElementsContainer, QueueInboundSize),
	}
	runtime.SetFinalizer(q, transport.flushInboundQueue)
	return q
}

func (transport *Transport) flushInboundQueue(q *autodrainingInboundQueue) {
	for {
		select {
		case elemsContainer := <-q.c:
			elemsContainer.Lock()
			for _, elem := range elemsContainer.elems {
				transport.PutMessageBuffer(elem.buffer)
				transport.PutInboundElement(elem)
			}
			transport.PutInboundElementsContainer(elemsContainer)
		default:
			return
		}
	}
}

type autodrainingOutboundQueue struct {
	c chan *QueueOutboundElementsContainer
}

// newAutodrainingOutboundQueue returns a channel that will be drained when it gets GC'd.
// It is useful in cases in which is it hard to manage the lifetime of the channel.
// The returned channel must not be closed. Senders should signal shutdown using
// some other means, such as sending a sentinel nil values.
// All sends to the channel must be best-effort, because there may be no receivers.
func newAutodrainingOutboundQueue(transport *Transport) *autodrainingOutboundQueue {
	q := &autodrainingOutboundQueue{
		c: make(chan *QueueOutboundElementsContainer, QueueOutboundSize),
	}
	runtime.SetFinalizer(q, transport.flushOutboundQueue)
	return q
}

func (transport *Transport) flushOutboundQueue(q *autodrainingOutboundQueue) {
	for {
		select {
		case elemsContainer := <-q.c:
			elemsContainer.Lock()
			for _, elem := range elemsContainer.elems {
				transport.PutMessageBuffer(elem.buffer)
				transport.PutOutboundElement(elem)
			}
			transport.PutOutboundElementsContainer(elemsContainer)
		default:
			return
		}
	}
}
