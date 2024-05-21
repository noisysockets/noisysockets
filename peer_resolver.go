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
	"github.com/noisysockets/network"
	"github.com/noisysockets/noisysockets/util"
	"github.com/noisysockets/resolver"
	"github.com/noisysockets/resolver/addrselect"
	resolverutil "github.com/noisysockets/resolver/util"
)

var (
	_ resolver.Resolver = (*peerResolver)(nil)
)

type peerResolver struct {
	mu          sync.RWMutex
	nameToAddr  map[string][]netip.Addr
	domain      string
	dialContext network.DialContextFunc
}

func newPeerResolver(domain string) *peerResolver {
	return &peerResolver{
		nameToAddr: make(map[string][]netip.Addr),
		domain:     domain,
	}
}

func (r *peerResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	addrs, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	return util.Strings(addrs), nil
}

func (r *peerResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	r.mu.RLock()
	allAddrs, ok := r.nameToAddr[dns.CanonicalName(host)]
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

	addrs, err := resolverutil.FilterAddresses(allAddrs, network)
	if err != nil {
		return nil, &net.DNSError{
			Err:  err.Error(),
			Name: host,
		}
	}

	dial := func(network, address string) (net.Conn, error) {
		return r.dialContext(ctx, network, address)
	}

	addrselect.SortByRFC6724(dial, addrs)

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
