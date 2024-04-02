// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package util

import "github.com/noisysockets/noisysockets/internal/transport"

// NewPrivateKey generates a new base64 encoded Curve25519 key.
func NewPrivateKey() (string, error) {
	privateKey, err := transport.NewPrivateKey()
	if err != nil {
		return "", err
	}

	return privateKey.String(), nil
}
