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

package ratelimiter

import (
	"net/netip"
	"testing"
	"time"
)

type result struct {
	allowed bool
	text    string
	wait    time.Duration
}

func TestRatelimiter(t *testing.T) {
	var rate Ratelimiter
	var expectedResults []result

	nano := func(nano int64) time.Duration {
		return time.Nanosecond * time.Duration(nano)
	}

	add := func(res result) {
		expectedResults = append(
			expectedResults,
			res,
		)
	}

	for i := 0; i < packetsBurstable; i++ {
		add(result{
			allowed: true,
			text:    "initial burst",
		})
	}

	add(result{
		allowed: false,
		text:    "after burst",
	})

	add(result{
		allowed: true,
		wait:    nano(time.Second.Nanoseconds() / packetsPerSecond),
		text:    "filling tokens for single packet",
	})

	add(result{
		allowed: false,
		text:    "not having refilled enough",
	})

	add(result{
		allowed: true,
		wait:    2 * (nano(time.Second.Nanoseconds() / packetsPerSecond)),
		text:    "filling tokens for two packet burst",
	})

	add(result{
		allowed: true,
		text:    "second packet in 2 packet burst",
	})

	add(result{
		allowed: false,
		text:    "packet following 2 packet burst",
	})

	ips := []netip.Addr{
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("172.167.2.3"),
		netip.MustParseAddr("97.231.252.215"),
		netip.MustParseAddr("248.97.91.167"),
		netip.MustParseAddr("188.208.233.47"),
		netip.MustParseAddr("104.2.183.179"),
		netip.MustParseAddr("72.129.46.120"),
		netip.MustParseAddr("2001:0db8:0a0b:12f0:0000:0000:0000:0001"),
		netip.MustParseAddr("f5c2:818f:c052:655a:9860:b136:6894:25f0"),
		netip.MustParseAddr("b2d7:15ab:48a7:b07c:a541:f144:a9fe:54fc"),
		netip.MustParseAddr("a47b:786e:1671:a22b:d6f9:4ab0:abc7:c918"),
		netip.MustParseAddr("ea1e:d155:7f7a:98fb:2bf5:9483:80f6:5445"),
		netip.MustParseAddr("3f0e:54a2:f5b4:cd19:a21d:58e1:3746:84c4"),
	}

	now := time.Now()
	rate.timeNow = func() time.Time {
		return now
	}
	defer func() {
		// Lock to avoid data race with cleanup goroutine from Init.
		rate.mu.Lock()
		defer rate.mu.Unlock()

		rate.timeNow = time.Now
	}()
	timeSleep := func(d time.Duration) {
		now = now.Add(d + 1)
		rate.cleanup()
	}

	rate.Init()
	t.Cleanup(func() {
		if err := rate.Close(); err != nil {
			t.Fatalf("rate.Close()=%v, want nil", err)
		}
	})

	for i, res := range expectedResults {
		timeSleep(res.wait)
		for _, ip := range ips {
			allowed := rate.Allow(ip)
			if allowed != res.allowed {
				t.Fatalf("%d: %s: rate.Allow(%q)=%v, want %v", i, res.text, ip, allowed, res.allowed)
			}
		}
	}
}
