/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 * Copyright (c) 2024 Damian Peckett <damian@pecke.tt>.
 */

package transport

import (
	"sync"
	"sync/atomic"
)

type WaitPool struct {
	pool  sync.Pool
	cond  sync.Cond
	lock  sync.Mutex
	count atomic.Uint32
	max   uint32
}

func NewWaitPool(max uint32, new func() any) *WaitPool {
	p := &WaitPool{pool: sync.Pool{New: new}, max: max}
	p.cond = sync.Cond{L: &p.lock}
	return p
}

func (p *WaitPool) Get() any {
	if p.max != 0 {
		p.lock.Lock()
		for p.count.Load() >= p.max {
			p.cond.Wait()
		}
		p.count.Add(1)
		p.lock.Unlock()
	}
	return p.pool.Get()
}

func (p *WaitPool) Put(x any) {
	p.pool.Put(x)
	if p.max == 0 {
		return
	}
	p.count.Add(^uint32(0))
	p.cond.Signal()
}

func (transport *Transport) PopulatePools() {
	transport.pool.inboundElementsContainer = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		s := make([]*QueueInboundElement, 0, transport.BatchSize())
		return &QueueInboundElementsContainer{elems: s}
	})
	transport.pool.outboundElementsContainer = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		s := make([]*QueueOutboundElement, 0, transport.BatchSize())
		return &QueueOutboundElementsContainer{elems: s}
	})
	transport.pool.messageBuffers = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new([MaxMessageSize]byte)
	})
	transport.pool.inboundElements = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new(QueueInboundElement)
	})
	transport.pool.outboundElements = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new(QueueOutboundElement)
	})
}

func (transport *Transport) GetInboundElementsContainer() *QueueInboundElementsContainer {
	c := transport.pool.inboundElementsContainer.Get().(*QueueInboundElementsContainer)
	c.Mutex = sync.Mutex{}
	return c
}

func (transport *Transport) PutInboundElementsContainer(c *QueueInboundElementsContainer) {
	for i := range c.elems {
		c.elems[i] = nil
	}
	c.elems = c.elems[:0]
	transport.pool.inboundElementsContainer.Put(c)
}

func (transport *Transport) GetOutboundElementsContainer() *QueueOutboundElementsContainer {
	c := transport.pool.outboundElementsContainer.Get().(*QueueOutboundElementsContainer)
	c.Mutex = sync.Mutex{}
	return c
}

func (transport *Transport) PutOutboundElementsContainer(c *QueueOutboundElementsContainer) {
	for i := range c.elems {
		c.elems[i] = nil
	}
	c.elems = c.elems[:0]
	transport.pool.outboundElementsContainer.Put(c)
}

func (transport *Transport) GetMessageBuffer() *[MaxMessageSize]byte {
	return transport.pool.messageBuffers.Get().(*[MaxMessageSize]byte)
}

func (transport *Transport) PutMessageBuffer(msg *[MaxMessageSize]byte) {
	transport.pool.messageBuffers.Put(msg)
}

func (transport *Transport) GetInboundElement() *QueueInboundElement {
	return transport.pool.inboundElements.Get().(*QueueInboundElement)
}

func (transport *Transport) PutInboundElement(elem *QueueInboundElement) {
	elem.clearPointers()
	transport.pool.inboundElements.Put(elem)
}

func (transport *Transport) GetOutboundElement() *QueueOutboundElement {
	return transport.pool.outboundElements.Get().(*QueueOutboundElement)
}

func (transport *Transport) PutOutboundElement(elem *QueueOutboundElement) {
	elem.clearPointers()
	transport.pool.outboundElements.Put(elem)
}
