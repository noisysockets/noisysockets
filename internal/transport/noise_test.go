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
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/neilotoole/slogt"
	"github.com/noisysockets/noisysockets/internal/conn"
	"github.com/noisysockets/noisysockets/types"
	"github.com/stretchr/testify/require"
)

func TestCurveWrappers(t *testing.T) {
	sk1, err := types.NewPrivateKey()
	assertNil(t, err)

	sk2, err := types.NewPrivateKey()
	assertNil(t, err)

	pk1 := sk1.Public()
	pk2 := sk2.Public()

	ss1, err1 := sharedSecret(sk1, pk2)
	ss2, err2 := sharedSecret(sk2, pk1)

	if ss1 != ss2 || err1 != nil || err2 != nil {
		t.Fatal("Failed to compute shared secet")
	}
}

func randTransport(t *testing.T) *Transport {
	sk, err := types.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	logger := slogt.New(t)
	transport := NewTransport(ctx, logger, &discardingInterface{}, conn.NewStdNetBind())
	transport.SetPrivateKey(sk)
	return transport
}

func assertNil(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func assertEqual(t *testing.T, a, b []byte) {
	if !bytes.Equal(a, b) {
		t.Fatal(a, "!=", b)
	}
}

func TestNoiseHandshake(t *testing.T) {
	trans1 := randTransport(t)
	trans2 := randTransport(t)

	t.Cleanup(func() {
		require.NoError(t, trans1.Close())
		require.NoError(t, trans2.Close())

		// Time for the workers to finish.
		time.Sleep(100 * time.Millisecond)
	})

	peer1, err := trans2.NewPeer(trans1.staticIdentity.privateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	peer2, err := trans1.NewPeer(trans2.staticIdentity.privateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	peer1.Start()
	peer2.Start()

	assertEqual(
		t,
		peer1.handshake.precomputedStaticStatic[:],
		peer2.handshake.precomputedStaticStatic[:],
	)

	/* simulate handshake */

	// initiation message

	t.Log("exchange initiation message")

	msg1, err := trans1.CreateMessageInitiation(peer2)
	assertNil(t, err)

	packet := make([]byte, 0, 256)
	writer := bytes.NewBuffer(packet)
	err = binary.Write(writer, binary.LittleEndian, msg1)
	assertNil(t, err)
	peer := trans2.ConsumeMessageInitiation(msg1)
	if peer == nil {
		t.Fatal("handshake failed at initiation message")
	}

	assertEqual(
		t,
		peer1.handshake.chainKey[:],
		peer2.handshake.chainKey[:],
	)

	assertEqual(
		t,
		peer1.handshake.hash[:],
		peer2.handshake.hash[:],
	)

	// response message

	t.Log("exchange response message")

	msg2, err := trans2.CreateMessageResponse(peer1)
	assertNil(t, err)

	peer = trans1.ConsumeMessageResponse(msg2)
	if peer == nil {
		t.Fatal("handshake failed at response message")
	}

	assertEqual(
		t,
		peer1.handshake.chainKey[:],
		peer2.handshake.chainKey[:],
	)

	assertEqual(
		t,
		peer1.handshake.hash[:],
		peer2.handshake.hash[:],
	)

	// key pairs

	t.Log("deriving keys")

	err = peer1.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 1", err)
	}

	err = peer2.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 2", err)
	}

	key1 := peer1.keypairs.next.Load()
	key2 := peer2.keypairs.current

	// encrypting / decryption test

	t.Log("test key pairs")

	func() {
		testMsg := []byte("test message 1")
		var err error
		var out []byte
		var nonce [12]byte
		out = key1.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key2.receive.Open(out[:0], nonce[:], out, nil)
		assertNil(t, err)
		assertEqual(t, out, testMsg)
	}()

	func() {
		testMsg := []byte("test message 2")
		var err error
		var out []byte
		var nonce [12]byte
		out = key2.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key1.receive.Open(out[:0], nonce[:], out, nil)
		assertNil(t, err)
		assertEqual(t, out, testMsg)
	}()
}

type discardingInterface struct {
	closed bool
}

func (d *discardingInterface) Close() error {
	d.closed = true
	return nil
}

func (d *discardingInterface) Read(ctx context.Context, bufs [][]byte, sizes []int, offset int) (int, error) {
	if d.closed {
		return 0, net.ErrClosed
	}

	time.Sleep(10 * time.Millisecond)

	return 0, nil
}

func (discardingInterface) Write(ctx context.Context, bufs [][]byte, sizes []int, offset int) (int, error) {
	return 0, nil
}

func (discardingInterface) Name() string {
	return "discard0"
}

func (discardingInterface) MTU() int {
	return 1420
}

func (discardingInterface) BatchSize() int {
	return 1
}
