/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 */

package noisysockets

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
)

func resolveHost(dnsServers []netip.Addr, host string, dialContext DialContextFn) ([]string, error) {
	client := dns.Client{
		Net:                 "tcp",
		DialContextOverride: dialContext,
	}

	var addrs []string
	var queryResult *multierror.Error

	for _, server := range dnsServers {
		queries := []uint16{dns.TypeA, dns.TypeAAAA}

		for _, qtype := range queries {
			in, err := queryDNS(server, host, qtype, &client)
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

func queryDNS(server netip.Addr, host string, qtype uint16, client *dns.Client) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), qtype)

	serverAddr := fmt.Sprintf("%s:53", server.String())
	r, _, err := client.Exchange(msg, serverAddr)
	if err != nil {
		return nil, &net.DNSError{
			Err:  fmt.Errorf("could not query DNS server %s: %w", serverAddr, err).Error(),
			Name: host,
		}
	}

	return r, nil
}
