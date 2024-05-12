// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package util

import (
	"crypto/rand"
	"math/big"
)

// Shuffle shuffles the elements of a slice.
func Shuffle[T any](s []T) []T {
	n := len(s)
	for i := n - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			panic(err)
		}

		j := int(jBig.Int64())
		s[i], s[j] = s[j], s[i]
	}
	return s
}
