// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package dns

import (
	"context"
	"errors"
	"fmt"
	stdnet "net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/noisysockets/noisysockets/internal/dns/addrselect"
	"github.com/noisysockets/noisysockets/internal/util"
	"github.com/noisysockets/noisysockets/network"
	"github.com/noisysockets/noisysockets/networkutil"
)

// udpResolver is a DNS resolver that uses DNS over UDP.
type udpResolver struct {
	net         network.Network
	nameservers []netip.AddrPort
}

// NewUDPResolver creates a new DNS resolver that uses DNS over UDP.
func NewUDPResolver(net network.Network, nameservers []netip.AddrPort) Resolver {
	// Use the default DNS port if none is specified.
	for i, ns := range nameservers {
		if ns.Port() == 0 {
			nameservers[i] = netip.AddrPortFrom(ns.Addr(), 53)
		}
	}

	return &udpResolver{
		net:         net,
		nameservers: nameservers,
	}
}

func (r *udpResolver) LookupHost(host string) ([]netip.Addr, error) {
	client := &dns.Client{
		Net:     "udp",
		Timeout: 10 * time.Second,
	}

	interfaceAddrs, err := r.net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("could not get interface addresses: %w", err)
	}

	netipAddrs, ok := networkutil.ToNetIPAddrs(interfaceAddrs)
	if !ok {
		return nil, fmt.Errorf("could not convert interface addresses")
	}

	var queryTypes []uint16
	if networkutil.HasIPv4(netipAddrs) {
		queryTypes = append(queryTypes, dns.TypeA)
	}
	if networkutil.HasIPv6(netipAddrs) {
		queryTypes = append(queryTypes, dns.TypeAAAA)
	}

	// Shuffle the nameserver list for load balancing.
	shuffledNameservers := make([]netip.AddrPort, len(r.nameservers))
	copy(shuffledNameservers, r.nameservers)
	shuffledNameservers = util.Shuffle(shuffledNameservers)

	var addrs []netip.Addr
	var queryErr error

	for _, ns := range shuffledNameservers {
		for _, queryType := range queryTypes {
			in, err := r.queryNameserver(client, ns, queryType, host)
			if err != nil {
				queryErr = errors.Join(queryErr, err)
				continue
			}

			for _, rr := range in.Answer {
				switch rr := rr.(type) {
				case *dns.A:
					addrs = append(addrs, netip.AddrFrom4([4]byte(rr.A.To4())))
				case *dns.AAAA:
					addrs = append(addrs, netip.AddrFrom16([16]byte(rr.AAAA.To16())))
				}
			}
		}

		if len(addrs) > 0 {
			addrselect.SortByRFC6724(r.net, addrs)
			return addrs, nil
		}
	}

	if queryErr != nil {
		return nil, &stdnet.DNSError{Err: queryErr.Error(), Name: host}
	}

	return nil, &stdnet.DNSError{Err: "no such host", Name: host}
}

func (r *udpResolver) queryNameserver(client *dns.Client, nameserver netip.AddrPort, queryType uint16, host string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()

	conn, err := r.net.DialContext(ctx, client.Net, nameserver.String())
	if err != nil {
		return nil, &stdnet.DNSError{
			Err:  fmt.Errorf("could not connect to DNS server %s: %w", nameserver, err).Error(),
			Name: host,
		}
	}
	defer conn.Close()

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(host), queryType)

	reply, _, err := client.ExchangeWithConn(req, &dns.Conn{Conn: conn})
	if err != nil {
		return nil, &stdnet.DNSError{
			Err:  fmt.Errorf("could not query DNS server %s: %w", nameserver.String(), err).Error(),
			Name: host,
		}
	}

	return reply, nil
}
