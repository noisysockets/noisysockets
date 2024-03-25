/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 * Copyright (c) 2024 Damian Peckett <damian@pecke.tt>.
 */

package transport

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/neilotoole/slogt"
	"github.com/noisysockets/noisysockets/internal/conn"
	"github.com/stretchr/testify/require"
)

func TestCurveWrappers(t *testing.T) {
	sk1, err := NewPrivateKey()
	assertNil(t, err)

	sk2, err := NewPrivateKey()
	assertNil(t, err)

	pk1 := sk1.PublicKey()
	pk2 := sk2.PublicKey()

	ss1, err1 := sk1.sharedSecret(pk2)
	ss2, err2 := sk2.sharedSecret(pk1)

	if ss1 != ss2 || err1 != nil || err2 != nil {
		t.Fatal("Failed to compute shared secet")
	}
}

func randTransport(t *testing.T) *Transport {
	sk, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	logger := slogt.New(t)
	transport := NewTransport(&discardingSink{}, conn.NewStdNetBind(), logger)
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

	peer1, err := trans2.NewPeer(trans1.staticIdentity.privateKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	peer2, err := trans1.NewPeer(trans2.staticIdentity.privateKey.PublicKey())
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

type discardingSink struct {
	closed bool
}

func (ss *discardingSink) Close() error {
	ss.closed = true
	return nil
}

func (ss *discardingSink) Read(bufs [][]byte, sizes []int, destinations []NoisePublicKey, offset int) (int, error) {
	if ss.closed {
		return 0, net.ErrClosed
	}

	time.Sleep(10 * time.Millisecond)

	return 0, nil
}

func (discardingSink) Write(bufs [][]byte, sources []NoisePublicKey, offset int) (int, error) {
	return 0, nil
}

func (discardingSink) BatchSize() int {
	return 1
}
