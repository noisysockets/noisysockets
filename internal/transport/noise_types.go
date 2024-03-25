/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 * Copyright (c) 2024 Damian Peckett <damian@pecke.tt>.
 */

package transport

import (
	"crypto/subtle"
	"encoding/base64"
)

const (
	NoisePublicKeySize    = 32
	NoisePrivateKeySize   = 32
	NoisePresharedKeySize = 32
)

type (
	NoisePublicKey    [NoisePublicKeySize]byte
	NoisePrivateKey   [NoisePrivateKeySize]byte
	NoisePresharedKey [NoisePresharedKeySize]byte
	NoiseNonce        uint64 // padded to 12-bytes
)

func (key *NoisePrivateKey) FromString(src string) error {
	b, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		return err
	}
	copy(key[:], b)
	return nil
}

func (key NoisePrivateKey) IsZero() bool {
	var zero NoisePrivateKey
	return key.Equals(zero)
}

func (key NoisePrivateKey) Equals(tar NoisePrivateKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func (key NoisePrivateKey) String() string {
	return base64.StdEncoding.EncodeToString(key[:])
}

func (key *NoisePublicKey) FromString(src string) error {
	b, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		return err
	}
	copy(key[:], b)
	return nil
}

func (key NoisePublicKey) IsZero() bool {
	var zero NoisePublicKey
	return key.Equals(zero)
}

func (key NoisePublicKey) Equals(tar NoisePublicKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func (key NoisePublicKey) String() string {
	return base64.StdEncoding.EncodeToString(key[:])
}
