// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package config

const (
	// DefaultListenPort is the default port to listen on.
	DefaultListenPort = 51820
	// The default search domain to use for networks (if not specified).
	DefaultDomain = "my.nzzy.net."
	// Larger MTU's are susceptible to fragmentation on the public internet
	// (particularly when using IPv6).
	DefaultMTU = 1280
)
