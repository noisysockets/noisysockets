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

func TestFromINI(t *testing.T) {
	f, err := os.Open("testdata/wg0.conf")
	require.NoError(t, err)

	conf, err := config.FromINI(f)
	require.NoError(t, err)

	var buf bytes.Buffer
	err = config.ToYAML(&buf, conf)
	require.NoError(t, err)

	expected, err := os.ReadFile("testdata/config.yaml")
	require.NoError(t, err)

	require.YAMLEq(t, string(expected), buf.String())
}

func TestToINI(t *testing.T) {
	configFile, err := os.Open("testdata/config.yaml")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, configFile.Close())
	})

	conf, err := config.FromYAML(configFile)
	require.NoError(t, err)

	var buf bytes.Buffer
	err = config.ToINI(&buf, conf)
	require.NoError(t, err)

	expected, err := os.ReadFile("testdata/wg0.conf")
	require.NoError(t, err)

	require.Equal(t, string(expected), buf.String())
}
