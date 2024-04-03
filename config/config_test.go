// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/noisysockets/noisysockets/config"
	"github.com/stretchr/testify/require"
)

func TestFromYAML(t *testing.T) {
	conf, err := config.FromYAML("testdata/config.yaml")
	require.NoError(t, err)

	require.Equal(t, "Config", conf.GetKind())
	require.Equal(t, "noisysockets.github.com/v1alpha1", conf.GetAPIVersion())

	// Just check a few fields to make sure the config was parsed correctly.
	require.Equal(t, uint16(12346), conf.ListenPort)
	require.Equal(t, "6cvvZyj+EVL4DHjUKeVF7EUBfgR2mJO4php2Gdv9FVw=", conf.Peers[0].PublicKey)
}

func TestSaveToYAML(t *testing.T) {
	conf, err := config.FromYAML("testdata/config.yaml")
	require.NoError(t, err)

	configPath := filepath.Join(t.TempDir(), "config.yaml")

	w, err := os.Create(configPath)
	require.NoError(t, err)

	err = config.SaveToYAML(w, conf)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	conf2, err := config.FromYAML(configPath)
	require.NoError(t, err)

	require.Equal(t, conf, conf2)
}
