// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package util

import "fmt"

// Strings converts a slice of objects that implement fmt.Stringer to a slice of strings.
func Strings[T fmt.Stringer](s []T) []string {
	strings := make([]string, len(s))
	for i, v := range s {
		strings[i] = v.String()
	}
	return strings
}
