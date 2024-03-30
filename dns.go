// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package noisysockets

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
)

func resolveHost(ctx context.Context, dnsServers []netip.Addr, host string, dialContext DialContextFn) ([]string, error) {
	client := &dns.Client{
		Net:     "tcp",
		Timeout: 10 * time.Second,
	}

	var addrs []string
	var queryResult *multierror.Error

	for _, server := range dnsServers {
		queries := []uint16{dns.TypeA, dns.TypeAAAA}

		for _, qtype := range queries {
			in, err := queryDNS(ctx, server, host, qtype, client, dialContext)
			if err != nil {
				queryResult = multierror.Append(queryResult, err)
				continue
			}

			for _, rr := range in.Answer {
				switch rr := rr.(type) {
				case *dns.A:
					addrs = append(addrs, rr.A.String())
				case *dns.AAAA:
					addrs = append(addrs, rr.AAAA.String())
				}
			}
		}

		if len(addrs) > 0 {
			return addrs, nil
		}
	}

	if queryResult != nil {
		return nil, &net.DNSError{Err: queryResult.Error(), Name: host}
	}

	return nil, &net.DNSError{Err: "no such host", Name: host}
}

func queryDNS(ctx context.Context, server netip.Addr, host string, qtype uint16, client *dns.Client, dialContext DialContextFn) (*dns.Msg, error) {
	serverAddr := fmt.Sprintf("%s:53", server.String())

	ctx, cancel := context.WithTimeout(ctx, client.Timeout)
	defer cancel()

	conn, err := dialContext(ctx, client.Net, serverAddr)
	if err != nil {
		return nil, &net.DNSError{
			Err:  fmt.Errorf("could not connect to DNS server %s: %w", server, err).Error(),
			Name: host,
		}
	}
	defer conn.Close()

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), qtype)

	r, _, err := client.ExchangeWithConn(msg, &dns.Conn{Conn: conn})
	if err != nil {
		return nil, &net.DNSError{
			Err:  fmt.Errorf("could not query DNS server %s: %w", serverAddr, err).Error(),
			Name: host,
		}
	}

	return r, nil
}
