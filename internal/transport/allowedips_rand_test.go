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
	"crypto/rand"
	"net"
	"net/netip"
	"sort"
	"testing"
)

const (
	NumberOfPeers        = 100
	NumberOfPeerRemovals = 4
	NumberOfAddresses    = 250
	NumberOfTests        = 10000
)

type SlowNode struct {
	peer *Peer
	cidr uint8
	bits []byte
}

type SlowRouter []*SlowNode

func (r SlowRouter) Len() int {
	return len(r)
}

func (r SlowRouter) Less(i, j int) bool {
	return r[i].cidr > r[j].cidr
}

func (r SlowRouter) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

func (r SlowRouter) Insert(addr []byte, cidr uint8, peer *Peer) SlowRouter {
	for _, t := range r {
		if t.cidr == cidr && commonBits(t.bits, addr) >= cidr {
			t.peer = peer
			t.bits = addr
			return r
		}
	}
	r = append(r, &SlowNode{
		cidr: cidr,
		bits: addr,
		peer: peer,
	})
	sort.Sort(r)
	return r
}

func (r SlowRouter) Lookup(addr []byte) *Peer {
	for _, t := range r {
		common := commonBits(t.bits, addr)
		if common >= t.cidr {
			return t.peer
		}
	}
	return nil
}

func (r SlowRouter) RemoveByPeer(peer *Peer) SlowRouter {
	n := 0
	for _, x := range r {
		if x.peer != peer {
			r[n] = x
			n++
		}
	}
	return r[:n]
}

func TestTrieRandom(t *testing.T) {
	var slow4, slow6 SlowRouter
	var peers []*Peer
	var allowedIPs AllowedIPs

	for n := 0; n < NumberOfPeers; n++ {
		peers = append(peers, &Peer{})
	}

	for n := 0; n < NumberOfAddresses; n++ {
		var addr4 [4]byte
		_, _ = rand.Read(addr4[:])
		cidr := uint8(randInt() % 32)
		index := randInt() % NumberOfPeers
		allowedIPs.Insert(netip.PrefixFrom(netip.AddrFrom4(addr4), int(cidr)), peers[index])
		slow4 = slow4.Insert(addr4[:], cidr, peers[index])

		var addr6 [16]byte
		_, _ = rand.Read(addr6[:])
		cidr = uint8(randInt() % 128)
		index = randInt() % NumberOfPeers
		allowedIPs.Insert(netip.PrefixFrom(netip.AddrFrom16(addr6), int(cidr)), peers[index])
		slow6 = slow6.Insert(addr6[:], cidr, peers[index])
	}

	var p int
	for p = 0; ; p++ {
		for n := 0; n < NumberOfTests; n++ {
			var addr4 [4]byte
			_, _ = rand.Read(addr4[:])
			peer1 := slow4.Lookup(addr4[:])
			peer2 := allowedIPs.Lookup(addr4[:])
			if peer1 != peer2 {
				t.Errorf("Trie did not match naive implementation, for %v: want %p, got %p", net.IP(addr4[:]), peer1, peer2)
			}

			var addr6 [16]byte
			_, _ = rand.Read(addr6[:])
			peer1 = slow6.Lookup(addr6[:])
			peer2 = allowedIPs.Lookup(addr6[:])
			if peer1 != peer2 {
				t.Errorf("Trie did not match naive implementation, for %v: want %p, got %p", net.IP(addr6[:]), peer1, peer2)
			}
		}
		if p >= len(peers) || p >= NumberOfPeerRemovals {
			break
		}
		allowedIPs.RemoveByPeer(peers[p])
		slow4 = slow4.RemoveByPeer(peers[p])
		slow6 = slow6.RemoveByPeer(peers[p])
	}
	for ; p < len(peers); p++ {
		allowedIPs.RemoveByPeer(peers[p])
	}

	if allowedIPs.IPv4 != nil || allowedIPs.IPv6 != nil {
		t.Error("Failed to remove all nodes from trie by peer")
	}
}
