// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package dns_test

import (
	"testing"

	"github.com/noisysockets/noisysockets/internal/dns"
	"github.com/stretchr/testify/require"
)

func TestTrimSearchDomain(t *testing.T) {
	resolver := dns.NewResolver(nil, nil, []string{"example.org", "example.com"})

	trimmedHost := resolver.TrimSearchDomain("test-host.example.com")

	require.Equal(t, "test-host", trimmedHost)
}
