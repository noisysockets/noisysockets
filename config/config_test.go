/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2024 Damian Peckett <damian@pecke.tt>.
 */

package config_test

import (
	"testing"

	"github.com/noisysockets/noisysockets/config"
	"github.com/stretchr/testify/require"
)

func TestFromYAML(t *testing.T) {
	conf, err := config.FromYAML("testdata/config.yaml")
	require.NoError(t, err)

	require.Equal(t, "WireGuardConfig", conf.GetKind())
	require.Equal(t, "noisysockets.github.com/v1alpha1", conf.GetAPIVersion())

	// Just check a few fields to make sure the config was parsed correctly.
	require.Equal(t, uint16(12346), conf.ListenPort)
	require.Equal(t, "6cvvZyj+EVL4DHjUKeVF7EUBfgR2mJO4php2Gdv9FVw=", conf.Peers[0].PublicKey)
}
