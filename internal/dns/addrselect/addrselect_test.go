// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions of this file are based on code originally from the Go project,
 *
 * Copyright (c) 2015 The Go Authors. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following disclaimer
 *     in the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Google Inc. nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package addrselect

import (
	"context"
	stdnet "net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/stretchr/testify/mock"
)

func TestSortByRFC6724(t *testing.T) {
	tests := []struct {
		in      []netip.Addr
		srcs    []netip.Addr
		want    []netip.Addr
		reverse bool // also test it starting backwards
	}{
		// Examples from RFC 6724 section 10.2:

		// Prefer matching scope.
		{
			in: []netip.Addr{
				netip.MustParseAddr("2001:db8:1::1"),
				netip.MustParseAddr("198.51.100.121"),
			},
			srcs: []netip.Addr{
				netip.MustParseAddr("2001:db8:1::2"),
				netip.MustParseAddr("169.254.13.78"),
			},
			want: []netip.Addr{
				netip.MustParseAddr("2001:db8:1::1"),
				netip.MustParseAddr("198.51.100.121"),
			},
			reverse: true,
		},

		// Prefer matching scope.
		{
			in: []netip.Addr{
				netip.MustParseAddr("2001:db8:1::1"),
				netip.MustParseAddr("198.51.100.121"),
			},
			srcs: []netip.Addr{
				netip.MustParseAddr("fe80::1"),
				netip.MustParseAddr("198.51.100.117"),
			},
			want: []netip.Addr{
				netip.MustParseAddr("198.51.100.121"),
				netip.MustParseAddr("2001:db8:1::1"),
			},
			reverse: true,
		},

		// Prefer higher precedence.
		{
			in: []netip.Addr{
				netip.MustParseAddr("2001:db8:1::1"),
				netip.MustParseAddr("10.1.2.3"),
			},
			srcs: []netip.Addr{
				netip.MustParseAddr("2001:db8:1::2"),
				netip.MustParseAddr("10.1.2.4"),
			},
			want: []netip.Addr{
				netip.MustParseAddr("2001:db8:1::1"),
				netip.MustParseAddr("10.1.2.3"),
			},
			reverse: true,
		},

		// Prefer smaller scope.
		{
			in: []netip.Addr{
				netip.MustParseAddr("2001:db8:1::1"),
				netip.MustParseAddr("fe80::1"),
			},
			srcs: []netip.Addr{
				netip.MustParseAddr("2001:db8:1::2"),
				netip.MustParseAddr("fe80::2"),
			},
			want: []netip.Addr{
				netip.MustParseAddr("fe80::1"),
				netip.MustParseAddr("2001:db8:1::1"),
			},
			reverse: true,
		},

		// Issue 13283.  Having a 10/8 source address does not
		// mean we should prefer 23/8 destination addresses.
		{
			in: []netip.Addr{
				netip.MustParseAddr("54.83.193.112"),
				netip.MustParseAddr("184.72.238.214"),
				netip.MustParseAddr("23.23.172.185"),
				netip.MustParseAddr("75.101.148.21"),
				netip.MustParseAddr("23.23.134.56"),
				netip.MustParseAddr("23.21.50.150"),
			},
			srcs: []netip.Addr{
				netip.MustParseAddr("10.2.3.4"),
				netip.MustParseAddr("10.2.3.4"),
				netip.MustParseAddr("10.2.3.4"),
				netip.MustParseAddr("10.2.3.4"),
				netip.MustParseAddr("10.2.3.4"),
				netip.MustParseAddr("10.2.3.4"),
			},
			want: []netip.Addr{
				netip.MustParseAddr("54.83.193.112"),
				netip.MustParseAddr("184.72.238.214"),
				netip.MustParseAddr("23.23.172.185"),
				netip.MustParseAddr("75.101.148.21"),
				netip.MustParseAddr("23.23.134.56"),
				netip.MustParseAddr("23.21.50.150"),
			},
			reverse: false,
		},
	}
	for i, tt := range tests {
		inCopy := make([]netip.Addr, len(tt.in))
		copy(inCopy, tt.in)
		srcCopy := make([]netip.Addr, len(tt.in))
		copy(srcCopy, tt.srcs)
		SortByRFC6724withSrcs(&mockNet{}, inCopy, srcCopy)
		if !reflect.DeepEqual(inCopy, tt.want) {
			t.Errorf("test %d:\nin = %s\ngot: %s\nwant: %s\n", i, tt.in, inCopy, tt.want)
		}
		if tt.reverse {
			copy(inCopy, tt.in)
			copy(srcCopy, tt.srcs)
			for j := 0; j < len(inCopy)/2; j++ {
				k := len(inCopy) - j - 1
				inCopy[j], inCopy[k] = inCopy[k], inCopy[j]
				srcCopy[j], srcCopy[k] = srcCopy[k], srcCopy[j]
			}
			SortByRFC6724withSrcs(&mockNet{}, inCopy, srcCopy)
			if !reflect.DeepEqual(inCopy, tt.want) {
				t.Errorf("test %d, starting backwards:\nin = %s\ngot: %s\nwant: %s\n", i, tt.in, inCopy, tt.want)
			}
		}

	}

}

func TestRFC6724PolicyTableOrder(t *testing.T) {
	for i := 0; i < len(rfc6724policyTable)-1; i++ {
		if !(rfc6724policyTable[i].Prefix.Bits() >= rfc6724policyTable[i+1].Prefix.Bits()) {
			t.Errorf("rfc6724policyTable item number %d sorted in wrong order = %d bits, next item = %d bits;", i, rfc6724policyTable[i].Prefix.Bits(), rfc6724policyTable[i+1].Prefix.Bits())
		}
	}
}

func TestRFC6724PolicyTableContent(t *testing.T) {
	expectedRfc6724policyTable := policyTable{
		{
			Prefix:     netip.MustParsePrefix("::1/128"),
			Precedence: 50,
			Label:      0,
		},
		{
			Prefix:     netip.MustParsePrefix("::ffff:0:0/96"),
			Precedence: 35,
			Label:      4,
		},
		{
			Prefix:     netip.MustParsePrefix("::/96"),
			Precedence: 1,
			Label:      3,
		},
		{
			Prefix:     netip.MustParsePrefix("2001::/32"),
			Precedence: 5,
			Label:      5,
		},
		{
			Prefix:     netip.MustParsePrefix("2002::/16"),
			Precedence: 30,
			Label:      2,
		},
		{
			Prefix:     netip.MustParsePrefix("3ffe::/16"),
			Precedence: 1,
			Label:      12,
		},
		{
			Prefix:     netip.MustParsePrefix("fec0::/10"),
			Precedence: 1,
			Label:      11,
		},
		{
			Prefix:     netip.MustParsePrefix("fc00::/7"),
			Precedence: 3,
			Label:      13,
		},
		{
			Prefix:     netip.MustParsePrefix("::/0"),
			Precedence: 40,
			Label:      1,
		},
	}
	if !reflect.DeepEqual(rfc6724policyTable, expectedRfc6724policyTable) {
		t.Errorf("rfc6724policyTable has wrong contend = %v; want %v", rfc6724policyTable, expectedRfc6724policyTable)
	}
}

func TestRFC6724PolicyTableClassify(t *testing.T) {
	tests := []struct {
		ip   netip.Addr
		want policyTableEntry
	}{
		{
			ip: netip.MustParseAddr("127.0.0.1"),
			want: policyTableEntry{
				Prefix:     netip.MustParsePrefix("::ffff:0:0/96"),
				Precedence: 35,
				Label:      4,
			},
		},
		{
			ip: netip.MustParseAddr("2601:645:8002:a500:986f:1db8:c836:bd65"),
			want: policyTableEntry{
				Prefix:     netip.MustParsePrefix("::/0"),
				Precedence: 40,
				Label:      1,
			},
		},
		{
			ip: netip.MustParseAddr("::1"),
			want: policyTableEntry{
				Prefix:     netip.MustParsePrefix("::1/128"),
				Precedence: 50,
				Label:      0,
			},
		},
		{
			ip: netip.MustParseAddr("2002::ab12"),
			want: policyTableEntry{
				Prefix:     netip.MustParsePrefix("2002::/16"),
				Precedence: 30,
				Label:      2,
			},
		},
	}
	for i, tt := range tests {
		got := rfc6724policyTable.Classify(tt.ip)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%d. Classify(%s) = %v; want %v", i, tt.ip, got, tt.want)
		}
	}
}

func TestRFC6724ClassifyScope(t *testing.T) {
	tests := []struct {
		ip   netip.Addr
		want scope
	}{
		{netip.MustParseAddr("127.0.0.1"), scopeLinkLocal},   // rfc6724#section-3.2
		{netip.MustParseAddr("::1"), scopeLinkLocal},         // rfc4007#section-4
		{netip.MustParseAddr("169.254.1.2"), scopeLinkLocal}, // rfc6724#section-3.2
		{netip.MustParseAddr("fec0::1"), scopeSiteLocal},
		{netip.MustParseAddr("8.8.8.8"), scopeGlobal},

		{netip.MustParseAddr("ff02::"), scopeLinkLocal},  // IPv6 multicast
		{netip.MustParseAddr("ff05::"), scopeSiteLocal},  // IPv6 multicast
		{netip.MustParseAddr("ff04::"), scopeAdminLocal}, // IPv6 multicast
		{netip.MustParseAddr("ff0e::"), scopeGlobal},     // IPv6 multicast

		{netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xe0, 0, 0, 0}), scopeGlobal}, // IPv4 link-local multicast as 16 bytes
		{netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xe0, 2, 2, 2}), scopeGlobal}, // IPv4 global multicast as 16 bytes
		{netip.AddrFrom4([4]byte{0xe0, 0, 0, 0}), scopeGlobal},                                       // IPv4 link-local multicast as 4 bytes
		{netip.AddrFrom4([4]byte{0xe0, 2, 2, 2}), scopeGlobal},                                       // IPv4 global multicast as 4 bytes
	}
	for i, tt := range tests {
		got := classifyScope(tt.ip)
		if got != tt.want {
			t.Errorf("%d. classifyScope(%s) = %x; want %x", i, tt.ip, got, tt.want)
		}
	}
}

func TestRFC6724CommonPrefixLength(t *testing.T) {
	tests := []struct {
		a    netip.Addr
		b    netip.Addr
		want int
	}{
		{netip.MustParseAddr("fe80::1"), netip.MustParseAddr("fe80::2"), 64},
		{netip.MustParseAddr("fe81::1"), netip.MustParseAddr("fe80::2"), 15},
		{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("fe80::1"), 0}, // diff size
		{netip.AddrFrom4([4]byte{1, 2, 3, 4}), netip.AddrFrom4([4]byte{1, 2, 3, 4}), 32},
		{netip.AddrFrom4([4]byte{1, 2, 255, 255}), netip.AddrFrom4([4]byte{1, 2, 0, 0}), 16},
		{netip.AddrFrom4([4]byte{1, 2, 127, 255}), netip.AddrFrom4([4]byte{1, 2, 0, 0}), 17},
		{netip.AddrFrom4([4]byte{1, 2, 63, 255}), netip.AddrFrom4([4]byte{1, 2, 0, 0}), 18},
		{netip.AddrFrom4([4]byte{1, 2, 31, 255}), netip.AddrFrom4([4]byte{1, 2, 0, 0}), 19},
		{netip.AddrFrom4([4]byte{1, 2, 15, 255}), netip.AddrFrom4([4]byte{1, 2, 0, 0}), 20},
		{netip.AddrFrom4([4]byte{1, 2, 7, 255}), netip.AddrFrom4([4]byte{1, 2, 0, 0}), 21},
		{netip.AddrFrom4([4]byte{1, 2, 3, 255}), netip.AddrFrom4([4]byte{1, 2, 0, 0}), 22},
		{netip.AddrFrom4([4]byte{1, 2, 1, 255}), netip.AddrFrom4([4]byte{1, 2, 0, 0}), 23},
		{netip.AddrFrom4([4]byte{1, 2, 0, 255}), netip.AddrFrom4([4]byte{1, 2, 0, 0}), 24},
	}
	for i, tt := range tests {
		got := commonPrefixLen(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("%d. commonPrefixLen(%s, %s) = %d; want %d", i, tt.a, tt.b, got, tt.want)
		}
	}

}

type mockNet struct {
	mock.Mock
}

func (n *mockNet) Close() error { return nil }

func (n *mockNet) HasIPv4() bool { return true }

func (n *mockNet) HasIPv6() bool { return true }

func (n *mockNet) LookupHost(host string) ([]string, error) {
	args := n.Called(host)
	return args.Get(0).([]string), args.Error(1)
}

func (n *mockNet) Dial(network, address string) (stdnet.Conn, error) {
	args := n.Called(network, address)
	return args.Get(0).(stdnet.Conn), args.Error(1)
}

func (n *mockNet) DialContext(ctx context.Context, network, address string) (stdnet.Conn, error) {
	args := n.Called(ctx, network, address)
	return args.Get(0).(stdnet.Conn), args.Error(1)
}

func (n *mockNet) Listen(network, address string) (stdnet.Listener, error) {
	args := n.Called(network, address)
	return args.Get(0).(stdnet.Listener), args.Error(1)
}

func (n *mockNet) ListenPacket(network, address string) (stdnet.PacketConn, error) {
	args := n.Called(network, address)
	return args.Get(0).(stdnet.PacketConn), args.Error(1)
}
