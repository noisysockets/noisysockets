// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package util_test

import (
	"testing"

	"github.com/noisysockets/noisysockets/util"
	"github.com/stretchr/testify/require"
)

func TestNewPrivateKey(t *testing.T) {
	privateKey, err := util.NewPrivateKey()
	require.NoError(t, err)
	require.NotEmpty(t, privateKey)
}
