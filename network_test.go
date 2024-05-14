// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package noisysockets

import (
	stdnet "net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/neilotoole/slogt"
	latestconfig "github.com/noisysockets/noisysockets/config/v1alpha2"
	"github.com/noisysockets/noisysockets/types"
	"github.com/stretchr/testify/require"
)

func TestNetwork(t *testing.T) {
	logger := slogt.New(t)

	sk, err := types.NewPrivateKey()
	require.NoError(t, err)

	net, err := OpenNetwork(logger, &latestconfig.Config{
		Peers: []latestconfig.PeerConfig{
			{
				Name: "peer1",
				IPs: []string{
					"10.0.0.1",
					"fc00::1",
				},
				PublicKey: sk.Public().String(),
			},
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, net.Close())
	})

	net.(*NoisySocketsNetwork).resolver = &dummyDNSResolver{}

	t.Run("LookupHost", func(t *testing.T) {
		t.Run("IPv4 Address", func(t *testing.T) {
			addrs, err := net.LookupHost("127.0.0.1")
			require.NoError(t, err)

			require.Len(t, addrs, 1)
			require.Equal(t, "127.0.0.1", addrs[0])
		})

		t.Run("IPv6 Address", func(t *testing.T) {
			addrs, err := net.LookupHost("::1")
			require.NoError(t, err)

			require.Len(t, addrs, 1)
			require.Equal(t, "::1", addrs[0])
		})

		t.Run("Peer Name", func(t *testing.T) {
			addrs, err := net.LookupHost("peer1")
			require.NoError(t, err)

			require.Len(t, addrs, 2)
			require.Contains(t, addrs, "10.0.0.1")
			require.Contains(t, addrs, "fc00::1")

			// Fully qualified domain name.
			addrs, err = net.LookupHost("peer1.")
			require.NoError(t, err)

			require.Len(t, addrs, 2)
		})

		t.Run("Peer Name With Domain", func(t *testing.T) {
			addrs, err := net.LookupHost("peer1.my.nzzy.net")
			require.NoError(t, err)

			require.Len(t, addrs, 2)
			require.Contains(t, addrs, "10.0.0.1")
			require.Contains(t, addrs, "fc00::1")

			// Fully qualified domain name.
			addrs, err = net.LookupHost("peer1.my.nzzy.net.")
			require.NoError(t, err)

			require.Len(t, addrs, 2)
		})

		t.Run("Domain Name", func(t *testing.T) {
			addrs, err := net.LookupHost("host.example.com")
			require.NoError(t, err)

			require.Len(t, addrs, 2)

			require.Contains(t, addrs, "10.0.0.2")
			require.Contains(t, addrs, "fc00::2")
		})
	})
}

type dummyDNSResolver struct{}

func (r *dummyDNSResolver) LookupHost(host string) ([]netip.Addr, error) {
	if dns.Fqdn(host) == "host.example.com." {
		return []netip.Addr{
			netip.MustParseAddr("10.0.0.2"),
			netip.MustParseAddr("fc00::2"),
		}, nil
	}

	return nil, &stdnet.DNSError{Err: "no such host", Name: host}
}
