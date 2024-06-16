// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions of this file are based on code originally:
 *
 * Copyright (c) 2016 Daniel Garcia
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
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

package multilistener_test

import (
	"net"
	"testing"

	"github.com/noisysockets/noisysockets/internal/multilistener"
	"github.com/stretchr/testify/require"
)

func TestMultilistener(t *testing.T) {
	_, err := multilistener.New()
	require.Error(t, err, "expected error when creating listener with no underlying listeners")

	l1, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	l2, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	ml, err := multilistener.New(l1, l2)
	require.NoError(t, err)

	c1, err := net.Dial(l1.Addr().Network(), l1.Addr().String())
	require.NoError(t, err)

	n, err := c1.Write([]byte("a"))
	require.NoError(t, err)
	require.Equal(t, 1, n)

	c1_ml, err := ml.Accept()
	require.NoError(t, err)

	buf := make([]byte, 100)
	n, err = c1_ml.Read(buf)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, uint8('a'), buf[0])

	require.NoError(t, ml.Close())

	_, err = ml.Accept()
	require.Error(t, err, "expected error after closing")
}
