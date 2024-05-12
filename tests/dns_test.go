// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package noisysockets_test

import (
	"context"
	stdnet "net"
	"net/netip"
	"testing"
	"time"

	"github.com/noisysockets/noisysockets/internal/dns"
	"github.com/noisysockets/noisysockets/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestLookupHost(t *testing.T) {
	dnsReq := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context: "testdata/dns",
		},
		ExposedPorts: []string{"53/tcp", "53/udp"},
		WaitingFor:   wait.ForListeningPort("53/tcp"),
	}

	ctx := context.Background()
	dnsC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: dnsReq,
		Started:          true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, dnsC.Terminate(ctx))
	})

	// Get the dns server address / port
	dnsHost, err := dnsC.Host(ctx)
	require.NoError(t, err)

	dnsAddrs, err := stdnet.LookupHost(dnsHost)
	require.NoError(t, err)

	dnsMappedPort, err := dnsC.MappedPort(ctx, "53/udp")
	require.NoError(t, err)

	nameserver := netip.AddrPortFrom(netip.MustParseAddr(dnsAddrs[0]), uint16(dnsMappedPort.Int()))

	// Bind can be a bit funny.
	time.Sleep(time.Second)

	// Create a new DNS resolver.
	resolver := dns.NewResolver(network.Host(), []netip.AddrPort{nameserver}, nil)

	// Perform a DNS query.
	addrs, err := resolver.LookupHost("www.noisysockets.github.com")
	require.NoError(t, err)

	require.Len(t, addrs, 2)

	assert.Equal(t, "192.168.1.2", addrs[0].String())
	assert.Equal(t, "2001:db8::1", addrs[1].String())
}
