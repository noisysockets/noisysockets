// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package dns

import "net/netip"

// Resolver is a DNS resolver.
type Resolver interface {
	// LookupHost looks up the IP addresses for a given host.
	LookupHost(host string) ([]netip.Addr, error)
}
