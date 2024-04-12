// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package config_test

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/noisysockets/noisysockets/config"
	"github.com/stretchr/testify/require"
)

func TestFromYAML(t *testing.T) {
	configFile, err := os.Open("testdata/config.yaml")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, configFile.Close())
	})

	conf, err := config.FromYAML(configFile)
	require.NoError(t, err)

	require.Equal(t, "Config", conf.GetKind())
	require.Equal(t, "noisysockets.github.com/v1alpha1", conf.GetAPIVersion())

	// Just check a few fields to make sure the config was parsed correctly.
	require.Equal(t, uint16(12346), conf.ListenPort)
	require.Equal(t, "6cvvZyj+EVL4DHjUKeVF7EUBfgR2mJO4php2Gdv9FVw=", conf.Peers[0].PublicKey)
}

func TestSaveToYAML(t *testing.T) {
	configFile, err := os.Open("testdata/config.yaml")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, configFile.Close())
	})

	conf, err := config.FromYAML(configFile)
	require.NoError(t, err)

	savedConfigPath := filepath.Join(t.TempDir(), "config.yaml")

	savedConfigFile, err := os.OpenFile(savedConfigPath, os.O_CREATE|os.O_RDWR, 0o400)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, savedConfigFile.Close())
	})

	err = config.SaveToYAML(savedConfigFile, conf)
	require.NoError(t, err)

	_, err = savedConfigFile.Seek(0, io.SeekStart)
	require.NoError(t, err)

	conf2, err := config.FromYAML(savedConfigFile)
	require.NoError(t, err)

	require.Equal(t, conf, conf2)
}
