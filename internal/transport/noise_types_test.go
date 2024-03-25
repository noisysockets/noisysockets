/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 * Copyright (c) 2024 Damian Peckett <damian@pecke.tt>.
 */

package transport

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNoisePrivateKeyEncoding(t *testing.T) {
	key, err := NewPrivateKey()
	require.NoError(t, err)

	encoded := key.String()

	var decoded NoisePrivateKey
	require.NoError(t, decoded.FromString(encoded))

	require.Equal(t, key, decoded)
}

func TestNoisePublicKeyEncoding(t *testing.T) {
	key, err := NewPrivateKey()
	require.NoError(t, err)

	pk := key.PublicKey()

	encoded := pk.String()

	var decoded NoisePublicKey
	require.NoError(t, decoded.FromString(encoded))

	require.Equal(t, pk, decoded)
}
