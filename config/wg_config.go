// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package config

import (
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/noisysockets/noisysockets/config/types"
	latest "github.com/noisysockets/noisysockets/config/v1alpha1"
	"gopkg.in/ini.v1"
)

// FromINI reads a WireGuard INI configuration from the given reader and returns
// the equivalent config object. This should only be used for importing existing
// configurations.
func FromINI(r io.Reader) (conf *latest.Config, err error) {
	iniConf, err := ini.LoadSources(ini.LoadOptions{AllowNonUniqueSections: true}, r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse INI config: %w", err)
	}

	conf = &latest.Config{
		TypeMeta: types.TypeMeta{
			APIVersion: latest.ApiVersion,
			Kind:       "Config",
		},
	}

	ifaceSection := iniConf.Section("Interface")
	if ifaceSection == nil {
		return nil, fmt.Errorf("missing Interface section")
	}

	if strings.Contains(ifaceSection.Comment, "Name") {
		if fields := strings.Split(ifaceSection.Comment, "="); len(fields) == 2 {
			conf.Name = strings.TrimSpace(fields[1])
		}
	}

	key, err := ifaceSection.GetKey("Address")
	if err != nil {
		return nil, fmt.Errorf("missing address: %w", err)
	}

	for _, ip := range strings.Split(key.String(), ",") {
		conf.IPs = append(conf.IPs, strings.TrimSpace(ip))
	}

	key, err = ifaceSection.GetKey("ListenPort")
	if err == nil {
		conf.ListenPort = uint16(key.MustInt(0))
	}

	key, err = ifaceSection.GetKey("PrivateKey")
	if err != nil {
		return nil, fmt.Errorf("missing private key: %w", err)
	}
	conf.PrivateKey = key.String()

	key, err = ifaceSection.GetKey("DNS")
	if err == nil {
		for _, dns := range strings.Split(key.String(), ",") {
			conf.DNSServers = append(conf.DNSServers, strings.TrimSpace(dns))
		}
	}

	for _, section := range iniConf.Sections() {
		if section.Name() != "Peer" {
			continue
		}

		peerConf := latest.PeerConfig{}

		if strings.Contains(section.Comment, "Name") {
			if fields := strings.Split(section.Comment, "="); len(fields) == 2 {
				peerConf.Name = strings.TrimSpace(fields[1])
			}
		}

		key, err = section.GetKey("PublicKey")
		if err != nil {
			return nil, fmt.Errorf("missing peer public key: %w", err)
		}
		peerConf.PublicKey = key.String()

		key, err = section.GetKey("AllowedIPs")
		if err != nil {
			return nil, fmt.Errorf("missing peer allowed IPs: %w", err)
		}

		var destinationCIDRs []netip.Prefix
		for _, ip := range strings.Split(key.String(), ",") {
			ip = strings.TrimSpace(ip)

			// is the ip a CIDR?
			cidr, err := netip.ParsePrefix(ip)
			if err == nil {
				if cidr.IsSingleIP() {
					peerConf.IPs = append(peerConf.IPs, cidr.Addr().String())
				} else {
					destinationCIDRs = append(destinationCIDRs, cidr)
				}
				continue
			}

			peerConf.IPs = append(peerConf.IPs, ip)
		}

		for _, cidr := range destinationCIDRs {
			conf.Routes = append(conf.Routes, latest.RouteConfig{
				Destination: cidr.String(),
				Via:         peerConf.Name,
			})
		}

		key, err = section.GetKey("Endpoint")
		if err == nil {
			peerConf.Endpoint = key.String()
		}

		conf.Peers = append(conf.Peers, peerConf)
	}

	return conf, nil
}

// ToINI writes the given config object to the given writer in the WireGuard
// INI format. This should only be used for exporting configuration.
func ToINI(w io.Writer, versionedConf types.Config) error {
	var conf *latest.Config
	if versionedConf.GetAPIVersion() != latest.ApiVersion {
		var err error
		conf, err = migrate(versionedConf)
		if err != nil {
			return fmt.Errorf("failed to migrate config: %w", err)
		}
	} else {
		conf = versionedConf.(*latest.Config)
	}

	iniConf := ini.Empty(ini.LoadOptions{AllowNonUniqueSections: true})

	ifaceSection, err := iniConf.NewSection("Interface")
	if err != nil {
		return fmt.Errorf("failed to create section: %w", err)
	}

	if conf.Name != "" {
		ifaceSection.Comment = fmt.Sprintf("Name = %s", conf.Name)
	}

	if _, err := ifaceSection.NewKey("Address", strings.Join(conf.IPs, ",")); err != nil {
		return fmt.Errorf("failed to create key: %w", err)
	}

	if _, err := ifaceSection.NewKey("ListenPort", fmt.Sprintf("%d", conf.ListenPort)); err != nil {
		return fmt.Errorf("failed to create key: %w", err)
	}

	if _, err := ifaceSection.NewKey("PrivateKey", conf.PrivateKey); err != nil {
		return fmt.Errorf("failed to create key: %w", err)
	}

	if len(conf.DNSServers) > 0 {
		if _, err := ifaceSection.NewKey("DNS", strings.Join(conf.DNSServers, ",")); err != nil {
			return fmt.Errorf("failed to create key: %w", err)
		}
	}

	destinationCIDRsByPeer := make(map[string][]netip.Prefix)
	for _, route := range conf.Routes {
		destinationCIDR, err := netip.ParsePrefix(route.Destination)
		if err != nil {
			return fmt.Errorf("failed to parse route destination: %w", err)
		}

		destinationCIDRsByPeer[route.Via] = append(destinationCIDRsByPeer[route.Via], destinationCIDR)
	}

	for _, peerConf := range conf.Peers {
		peerSection, err := iniConf.NewSection("Peer")
		if err != nil {
			return fmt.Errorf("failed to create section: %w", err)
		}

		var destinationCIDRs []netip.Prefix
		if peerConf.Name != "" {
			peerSection.Comment = fmt.Sprintf("Name = %s", peerConf.Name)
			destinationCIDRs = destinationCIDRsByPeer[peerConf.Name]
		}

		var allowedIPs []string
		for _, cidr := range destinationCIDRs {
			allowedIPs = append(allowedIPs, cidr.String())
		}

		for _, ip := range peerConf.IPs {
			for _, cidr := range destinationCIDRs {
				addr, err := netip.ParseAddr(ip)
				if err != nil {
					return fmt.Errorf("failed to parse IP address: %w", err)
				}

				if cidr.Contains(addr) {
					continue
				}
			}

			allowedIPs = append(allowedIPs, ip)
		}

		if _, err := peerSection.NewKey("AllowedIPs", strings.Join(allowedIPs, ",")); err != nil {
			return fmt.Errorf("failed to create key: %w", err)
		}

		if peerConf.Endpoint != "" {
			if _, err := peerSection.NewKey("Endpoint", peerConf.Endpoint); err != nil {
				return fmt.Errorf("failed to create key: %w", err)
			}
		}

		if _, err := peerSection.NewKey("PublicKey", peerConf.PublicKey); err != nil {
			return fmt.Errorf("failed to create key: %w", err)
		}

		if _, err := peerSection.NewKey("PersistentKeepalive", "25"); err != nil {
			return fmt.Errorf("failed to create key: %w", err)
		}
	}

	if _, err := iniConf.WriteTo(w); err != nil {
		return fmt.Errorf("failed to marshal INI config: %w", err)
	}

	return nil
}
