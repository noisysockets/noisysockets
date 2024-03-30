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
	"crypto/rand"
	"encoding/binary"
	"sync"
)

type IndexTableEntry struct {
	peer      *Peer
	handshake *Handshake
	keypair   *Keypair
}

type IndexTable struct {
	sync.RWMutex
	table map[uint32]IndexTableEntry
}

func randUint32() (uint32, error) {
	var integer [4]byte
	_, err := rand.Read(integer[:])
	// Arbitrary endianness; both are intrinsified by the Go compiler.
	return binary.LittleEndian.Uint32(integer[:]), err
}

func (table *IndexTable) Init() {
	table.Lock()
	defer table.Unlock()
	table.table = make(map[uint32]IndexTableEntry)
}

func (table *IndexTable) Delete(index uint32) {
	table.Lock()
	defer table.Unlock()
	delete(table.table, index)
}

func (table *IndexTable) SwapIndexForKeypair(index uint32, keypair *Keypair) {
	table.Lock()
	defer table.Unlock()
	entry, ok := table.table[index]
	if !ok {
		return
	}
	table.table[index] = IndexTableEntry{
		peer:      entry.peer,
		keypair:   keypair,
		handshake: nil,
	}
}

func (table *IndexTable) NewIndexForHandshake(peer *Peer, handshake *Handshake) (uint32, error) {
	for {
		// generate random index

		index, err := randUint32()
		if err != nil {
			return index, err
		}

		// check if index used

		table.RLock()
		_, ok := table.table[index]
		table.RUnlock()
		if ok {
			continue
		}

		// check again while locked

		table.Lock()
		_, found := table.table[index]
		if found {
			table.Unlock()
			continue
		}
		table.table[index] = IndexTableEntry{
			peer:      peer,
			handshake: handshake,
			keypair:   nil,
		}
		table.Unlock()
		return index, nil
	}
}

func (table *IndexTable) Lookup(id uint32) IndexTableEntry {
	table.RLock()
	defer table.RUnlock()
	return table.table[id]
}
