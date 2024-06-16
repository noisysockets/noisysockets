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

	configtypes "github.com/noisysockets/noisysockets/config/types"
	latestconfig "github.com/noisysockets/noisysockets/config/v1alpha3"
	"github.com/noisysockets/noisysockets/internal/util"
	"github.com/noisysockets/noisysockets/types"
	"gopkg.in/ini.v1"
)

// FromINI reads a WireGuard INI configuration from the given reader and returns
// the equivalent config object. This should only be used for importing existing
// configurations.
func FromINI(r io.Reader) (configtypes.Config, error) {
	iniConf, err := ini.LoadSources(ini.LoadOptions{AllowNonUniqueSections: true}, r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse INI config: %w", err)
	}

	conf := &latestconfig.Config{}
	conf.PopulateTypeMeta()

	ifaceSection := iniConf.Section("Interface")
	if ifaceSection == nil {
		return nil, fmt.Errorf("missing Interface section")
	}

	key, err := ifaceSection.GetKey("Address")
	if err == nil {
		for _, ip := range key.Strings(",") {
			// Attempt to parse the IP as a CIDR prefix.
			prefix, err := netip.ParsePrefix(ip)
			if err == nil {
				conf.IPs = append(conf.IPs, prefix.Addr())

				if !prefix.IsSingleIP() {
					conf.Routes = append(conf.Routes, latestconfig.RouteConfig{
						Destination: prefix,
						Via:         prefix.Addr().String(),
					})
				}
			} else {
				addr, err := netip.ParseAddr(ip)
				if err != nil {
					return nil, fmt.Errorf("failed to parse IP address: %w", err)
				}

				conf.IPs = append(conf.IPs, addr)
			}
		}
	}

	key, err = ifaceSection.GetKey("ListenPort")
	if err == nil {
		conf.ListenPort = uint16(key.MustInt(0))
	}

	key, err = ifaceSection.GetKey("MTU")
	if err == nil {
		conf.MTU = key.MustInt(0)
	} else {
		// Given our default MTU is different from upstream wireguard,
		// We need to explicitly set it to the wireguard default it's not present
		// in the config.
		conf.MTU = 1420
	}

	key, err = ifaceSection.GetKey("PrivateKey")
	if err != nil {
		return nil, fmt.Errorf("missing private key: %w", err)
	}
	conf.PrivateKey = key.String()

	key, err = ifaceSection.GetKey("DNS")
	if err == nil {
		conf.DNS = &latestconfig.DNSConfig{}

		for _, dnsServerString := range key.Strings(",") {
			var dnsServer types.MaybeAddrPort
			if err := dnsServer.UnmarshalText([]byte(dnsServerString)); err != nil {
				return nil, fmt.Errorf("failed to parse DNS server: %w", err)
			}
			conf.DNS.Servers = append(conf.DNS.Servers, dnsServer)
		}
	}

	for _, peerSection := range iniConf.Sections() {
		if peerSection.Name() != "Peer" {
			continue
		}

		peerConf := latestconfig.PeerConfig{}

		key, err = peerSection.GetKey("PublicKey")
		if err != nil {
			return nil, fmt.Errorf("missing peer public key: %w", err)
		}
		peerConf.PublicKey = key.String()

		key, err = peerSection.GetKey("AllowedIPs")
		if err != nil {
			return nil, fmt.Errorf("missing peer allowed IPs: %w", err)
		}

		var destinations []netip.Prefix
		for _, ip := range key.Strings(",") {
			// is the ip a prefix?
			prefix, err := netip.ParsePrefix(ip)
			if err == nil {
				if prefix.IsSingleIP() {
					peerConf.IPs = append(peerConf.IPs, prefix.Addr())
				} else {
					destinations = append(destinations, prefix)
				}
			} else {
				addr, err := netip.ParseAddr(ip)
				if err != nil {
					return nil, fmt.Errorf("failed to parse oeer IP address: %w", err)
				}

				peerConf.IPs = append(peerConf.IPs, addr)
			}
		}

		for _, prefix := range destinations {
			peerName := peerConf.Name
			if peerName == "" {
				peerName = peerConf.PublicKey
			}

			conf.Routes = append(conf.Routes, latestconfig.RouteConfig{
				Destination: prefix,
				Via:         peerName,
			})
		}

		key, err = peerSection.GetKey("Endpoint")
		if err == nil {
			peerConf.Endpoint = key.String()
		}

		conf.Peers = append(conf.Peers, peerConf)
	}

	return conf, nil
}

// ToINI writes the given config object to the given writer in the WireGuard
// INI format. This should only be used for exporting configuration.
func ToINI(w io.Writer, versionedConf configtypes.Config) error {
	versionedConf, err := MigrateToLatest(versionedConf)
	if err != nil {
		return fmt.Errorf("failed to migrate config: %w", err)
	}

	conf, ok := versionedConf.(*latestconfig.Config)
	if !ok {
		return fmt.Errorf("unexpected migrated config type, this should never happen: %T", versionedConf)
	}

	iniConf := ini.Empty(ini.LoadOptions{AllowNonUniqueSections: true})

	ifaceSection, err := iniConf.NewSection("Interface")
	if err != nil {
		return fmt.Errorf("failed to create section: %w", err)
	}

	if conf.Name != "" {
		if _, err := ifaceSection.NewKey("# Name", conf.Name); err != nil {
			return fmt.Errorf("failed to create key: %w", err)
		}
	}

	if _, err := ifaceSection.NewKey("Address", strings.Join(util.Strings(conf.IPs), ",")); err != nil {
		return fmt.Errorf("failed to create key: %w", err)
	}

	listenPort := uint16(DefaultListenPort)
	if conf.ListenPort != 0 {
		listenPort = conf.ListenPort
	}

	if _, err := ifaceSection.NewKey("ListenPort", fmt.Sprintf("%d", listenPort)); err != nil {
		return fmt.Errorf("failed to create key: %w", err)
	}

	mtu := conf.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}

	if _, err := ifaceSection.NewKey("MTU", fmt.Sprintf("%d", mtu)); err != nil {
		return fmt.Errorf("failed to create key: %w", err)
	}

	if _, err := ifaceSection.NewKey("PrivateKey", conf.PrivateKey); err != nil {
		return fmt.Errorf("failed to create key: %w", err)
	}

	if conf.DNS != nil && len(conf.DNS.Servers) > 0 {
		if _, err := ifaceSection.NewKey("DNS", strings.Join(util.Strings(conf.DNS.Servers), ",")); err != nil {
			return fmt.Errorf("failed to create key: %w", err)
		}
	}

	destinationsByPeer := make(map[string][]netip.Prefix)
	for _, routeConf := range conf.Routes {
		destinationsByPeer[routeConf.Via] = append(destinationsByPeer[routeConf.Via], routeConf.Destination)
	}

	for _, peerConf := range conf.Peers {
		peerSection, err := iniConf.NewSection("Peer")
		if err != nil {
			return fmt.Errorf("failed to create section: %w", err)
		}

		var destinations []netip.Prefix
		if peerConf.Name != "" {
			if _, err := peerSection.NewKey("# Name", peerConf.Name); err != nil {
				return fmt.Errorf("failed to create key: %w", err)
			}

			destinations = destinationsByPeer[peerConf.Name]
		}

		var allowedIPs []string
		for _, prefix := range destinations {
			allowedIPs = append(allowedIPs, prefix.String())
		}

		for _, addr := range peerConf.IPs {
			var containedByPrefix bool
			for _, prefix := range destinations {
				if prefix.Contains(addr) {
					containedByPrefix = true
					break
				}
			}

			if !containedByPrefix {
				allowedIPs = append(allowedIPs, addr.String())
			}
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

		persistentKeepAlive := "25"
		if peerConf.PersistentKeepalive != nil {
			persistentKeepAlive = fmt.Sprintf("%d", int64((*peerConf.PersistentKeepalive).Seconds()))
		}

		if _, err := peerSection.NewKey("PersistentKeepalive", persistentKeepAlive); err != nil {
			return fmt.Errorf("failed to create key: %w", err)
		}
	}

	if _, err := iniConf.WriteTo(w); err != nil {
		return fmt.Errorf("failed to marshal INI config: %w", err)
	}

	return nil
}

// StripINI removes `wg-quick` specific configuration from the given INI file.
// This is analogous to the `wg-quick strip` command.
func StripINI(dst io.Writer, src io.Reader) error {
	iniConf, err := ini.LoadSources(ini.LoadOptions{AllowNonUniqueSections: true}, src)
	if err != nil {
		return fmt.Errorf("failed to parse INI config: %w", err)
	}

	ifaceSection := iniConf.Section("Interface")
	if ifaceSection == nil {
		return fmt.Errorf("missing Interface section")
	}

	wgQuickKeyNames := []string{
		"Address", "MTU", "DNS", "Table",
		"PreUp", "PreDown", "PostUp", "PostDown",
		"SaveConfig",
	}

	for _, keyName := range wgQuickKeyNames {
		ifaceSection.DeleteKey(keyName)
	}

	if _, err := iniConf.WriteTo(dst); err != nil {
		return fmt.Errorf("failed to marshal INI config: %w", err)
	}

	return nil
}
