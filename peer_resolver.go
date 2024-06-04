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
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/noisysockets/netutil/addresses"
	"github.com/noisysockets/resolver"
)

var (
	_ resolver.Resolver = (*peerResolver)(nil)
)

type peerResolver struct {
	mu         sync.RWMutex
	nameToAddr map[string][]netip.Addr
	domain     string
}

func newPeerResolver(domain string) *peerResolver {
	return &peerResolver{
		nameToAddr: make(map[string][]netip.Addr),
		domain:     domain,
	}
}

func (r *peerResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	r.mu.RLock()
	addrs, ok := r.nameToAddr[dns.CanonicalName(host)]
	r.mu.RUnlock()
	if !ok {
		return nil, &net.DNSError{
			Err:        resolver.ErrNoSuchHost.Error(),
			Name:       host,
			IsNotFound: true,
		}
	}

	if network != "ip" && network != "ip4" && network != "ip6" {
		return nil, &net.DNSError{
			Err:  resolver.ErrUnsupportedNetwork.Error(),
			Name: host,
		}
	}

	addrs = addresses.FilterByNetwork(addrs, network)
	if len(addrs) == 0 {
		return nil, &net.DNSError{
			Err:  resolver.ErrNoSuchHost.Error(),
			Name: host,
		}
	}

	return addrs, nil
}

func (r *peerResolver) addPeer(name string, addrs ...netip.Addr) {
	r.mu.Lock()
	r.nameToAddr[r.canonicalName(name)] = addrs
	r.mu.Unlock()
}

func (r *peerResolver) removePeer(name string) {
	r.mu.Lock()
	delete(r.nameToAddr, r.canonicalName(name))
	r.mu.Unlock()
}

func (r *peerResolver) canonicalName(name string) string {
	return dns.CanonicalName(
		strings.Join(append(dns.SplitDomainName(name), dns.SplitDomainName(r.domain)...), "."))
}
