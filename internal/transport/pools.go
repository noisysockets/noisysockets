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
	"sync"

	"github.com/noisysockets/netutil/waitpool"
)

func (transport *Transport) PopulatePools() {
	transport.pool.inboundElementsContainer = waitpool.New(PreallocatedBuffersPerPool, func() *QueueInboundElementsContainer {
		s := make([]*QueueInboundElement, 0, transport.BatchSize())
		return &QueueInboundElementsContainer{elems: s}
	})
	transport.pool.outboundElementsContainer = waitpool.New(PreallocatedBuffersPerPool, func() *QueueOutboundElementsContainer {
		s := make([]*QueueOutboundElement, 0, transport.BatchSize())
		return &QueueOutboundElementsContainer{elems: s}
	})
	transport.pool.inboundElements = waitpool.New(PreallocatedBuffersPerPool, func() *QueueInboundElement {
		return new(QueueInboundElement)
	})
	transport.pool.outboundElements = waitpool.New(PreallocatedBuffersPerPool, func() *QueueOutboundElement {
		return new(QueueOutboundElement)
	})
}

func (transport *Transport) GetInboundElementsContainer() *QueueInboundElementsContainer {
	c := transport.pool.inboundElementsContainer.Get()
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
	c := transport.pool.outboundElementsContainer.Get()
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

func (transport *Transport) GetInboundElement() *QueueInboundElement {
	return transport.pool.inboundElements.Get()
}

func (transport *Transport) PutInboundElement(elem *QueueInboundElement) {
	elem.clearPointers()
	transport.pool.inboundElements.Put(elem)
}

func (transport *Transport) GetOutboundElement() *QueueOutboundElement {
	return transport.pool.outboundElements.Get()
}

func (transport *Transport) PutOutboundElement(elem *QueueOutboundElement) {
	elem.clearPointers()
	transport.pool.outboundElements.Put(elem)
}
