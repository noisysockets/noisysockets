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
	"bytes"
	"os"
	"testing"

	"github.com/noisysockets/noisysockets/config"
	"github.com/stretchr/testify/require"
)

func TestFromYAML(t *testing.T) {
	configFile, err := os.Open("testdata/config_v1alpha2.yaml")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, configFile.Close())
	})

	conf, err := config.FromYAML(configFile)
	require.NoError(t, err)

	require.Equal(t, "Config", conf.GetKind())
	require.Equal(t, "noisysockets.github.com/v1alpha2", conf.GetAPIVersion())

	// Just check a few fields to make sure the config was parsed correctly.
	require.Equal(t, uint16(12345), conf.ListenPort)
	require.Equal(t, "6cvvZyj+EVL4DHjUKeVF7EUBfgR2mJO4php2Gdv9FVw=", conf.Peers[0].PublicKey)
}

func TestToYAML(t *testing.T) {
	configFile, err := os.Open("testdata/config_v1alpha2.yaml")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, configFile.Close())
	})

	conf, err := config.FromYAML(configFile)
	require.NoError(t, err)

	var buf bytes.Buffer
	err = config.ToYAML(&buf, conf)
	require.NoError(t, err)

	conf2, err := config.FromYAML(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)

	require.Equal(t, conf, conf2)
}

func TestMigration(t *testing.T) {
	configFile, err := os.Open("testdata/config_v1alpha1.yaml")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, configFile.Close())
	})

	conf, err := config.FromYAML(configFile)
	require.NoError(t, err)

	var migratedConf bytes.Buffer
	err = config.ToYAML(&migratedConf, conf)
	require.NoError(t, err)

	expectedConf, err := os.ReadFile("testdata/migrated_v1alpha1.yaml")
	require.NoError(t, err)

	require.YAMLEq(t, string(expectedConf), migratedConf.String())
}
