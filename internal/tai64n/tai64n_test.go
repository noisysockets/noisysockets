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

package tai64n

import (
	"testing"
	"time"
)

// Test that timestamps are monotonic as required by Wireguard and that
// nanosecond-level information is whitened to prevent side channel attacks.
func TestMonotonic(t *testing.T) {
	startTime := time.Unix(0, 123456789) // a nontrivial bit pattern
	// Whitening should reduce timestamp granularity
	// to more than 10 but fewer than 20 milliseconds.
	tests := []struct {
		name      string
		t1, t2    time.Time
		wantAfter bool
	}{
		{"after_10_ns", startTime, startTime.Add(10 * time.Nanosecond), false},
		{"after_10_us", startTime, startTime.Add(10 * time.Microsecond), false},
		{"after_1_ms", startTime, startTime.Add(time.Millisecond), false},
		{"after_10_ms", startTime, startTime.Add(10 * time.Millisecond), false},
		{"after_20_ms", startTime, startTime.Add(20 * time.Millisecond), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts1, ts2 := stamp(tt.t1), stamp(tt.t2)
			got := ts2.After(ts1)
			if got != tt.wantAfter {
				t.Errorf("after = %v; want %v", got, tt.wantAfter)
			}
		})
	}
}
