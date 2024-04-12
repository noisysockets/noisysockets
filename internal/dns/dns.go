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
	"fmt"
	stdnet "net"
	"net/netip"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	"github.com/noisysockets/noisysockets/internal/dns/addrselect"
	"github.com/noisysockets/noisysockets/network"
)

// LookupHost performs a DNS lookup for the given host using the provided DNS servers.
func LookupHost(net network.Network, dnsServers []netip.AddrPort, host string) ([]netip.Addr, error) {
	client := &dns.Client{
		Net:     "udp",
		Timeout: 10 * time.Second,
	}

	var queryTypes []uint16
	if net.HasIPv4() {
		queryTypes = append(queryTypes, dns.TypeA)
	}
	if net.HasIPv6() {
		queryTypes = append(queryTypes, dns.TypeAAAA)
	}

	var addrs []netip.Addr
	var queryResult *multierror.Error

	for _, dnsServer := range dnsServers {
		for _, queryType := range queryTypes {
			in, err := queryDNSServer(net, host, client, dnsServer, queryType)
			if err != nil {
				queryResult = multierror.Append(queryResult, err)
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
			addrselect.SortByRFC6724(net, addrs)
			return addrs, nil
		}
	}

	if queryResult != nil {
		return nil, &stdnet.DNSError{Err: queryResult.Error(), Name: host}
	}

	return nil, &stdnet.DNSError{Err: "no such host", Name: host}
}

func queryDNSServer(net network.Network, host string, client *dns.Client, dnsServer netip.AddrPort, queryType uint16) (*dns.Msg, error) {
	if dnsServer.Port() == 0 {
		// Use the default DNS port if none is specified.
		dnsServer = netip.AddrPortFrom(dnsServer.Addr(), 53)
	}

	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()

	conn, err := net.DialContext(ctx, client.Net, dnsServer.String())
	if err != nil {
		return nil, &stdnet.DNSError{
			Err:  fmt.Errorf("could not connect to DNS server %s: %w", dnsServer, err).Error(),
			Name: host,
		}
	}
	defer conn.Close()

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), queryType)

	r, _, err := client.ExchangeWithConn(msg, &dns.Conn{Conn: conn})
	if err != nil {
		return nil, &stdnet.DNSError{
			Err:  fmt.Errorf("could not query DNS server %s: %w", dnsServer.String(), err).Error(),
			Name: host,
		}
	}

	return r, nil
}
