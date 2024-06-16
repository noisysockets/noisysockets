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

	configtypes "github.com/noisysockets/noisysockets/config/types"
	"github.com/noisysockets/noisysockets/config/v1alpha1"
	"github.com/noisysockets/noisysockets/config/v1alpha2"
	latestconfig "github.com/noisysockets/noisysockets/config/v1alpha3"
	"github.com/noisysockets/noisysockets/types"
	"github.com/noisysockets/noisysockets/util"
	"gopkg.in/yaml.v3"
)

// FromYAML reads the given reader and returns a config object.
func FromYAML(r io.Reader) (configtypes.Config, error) {
	confBytes, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read config from reader: %w", err)
	}

	var typeMeta configtypes.TypeMeta
	if err := yaml.Unmarshal(confBytes, &typeMeta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal type meta from config file: %w", err)
	}

	var versionedConf configtypes.Config
	switch typeMeta.APIVersion {
	case v1alpha1.APIVersion:
		versionedConf, err = v1alpha1.GetConfigByKind(typeMeta.Kind)
	case v1alpha2.APIVersion:
		versionedConf, err = v1alpha2.GetConfigByKind(typeMeta.Kind)
	case latestconfig.APIVersion:
		versionedConf, err = latestconfig.GetConfigByKind(typeMeta.Kind)
	default:
		return nil, fmt.Errorf("unsupported api version: %s", typeMeta.APIVersion)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get config by kind %q: %w", typeMeta.Kind, err)
	}

	if err := yaml.Unmarshal(confBytes, versionedConf); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config from config file: %w", err)
	}

	versionedConf, err = MigrateToLatest(versionedConf)
	if err != nil {
		return nil, fmt.Errorf("failed to migrate config: %w", err)
	}

	return versionedConf, nil
}

// ToYAML writes the given config object to the given writer.
func ToYAML(w io.Writer, versionedConf configtypes.Config) error {
	versionedConf.PopulateTypeMeta()

	if err := yaml.NewEncoder(w).Encode(versionedConf); err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	return nil
}

// MigrateToLatest migrates the given config object to the latest version.
func MigrateToLatest(versionedConf configtypes.Config) (configtypes.Config, error) {
	switch conf := versionedConf.(type) {
	case *v1alpha1.Config:
		v1alpha2Conf, err := migrateV1Alpha1ToV1Alpha2(conf)
		if err != nil {
			return nil, fmt.Errorf("failed to migrate v1alpha1 to v1alpha2: %w", err)
		}

		return migrateV1Alpha2ToV1Alpha3(v1alpha2Conf)
	case *v1alpha2.Config:
		return migrateV1Alpha2ToV1Alpha3(conf)
	case *latestconfig.Config:
		// Nothing to do, already at the latest version.
		return conf, nil
	default:
		return nil, fmt.Errorf("unsupported config version: %s", conf.GetAPIVersion())
	}
}

func migrateV1Alpha1ToV1Alpha2(conf *v1alpha1.Config) (*v1alpha2.Config, error) {
	interfaceAddrs, err := util.ParseAddrList(conf.IPs)
	if err != nil {
		return nil, fmt.Errorf("could not parse local addresses: %w", err)
	}

	migratedConf := &v1alpha2.Config{}
	migratedConf.PopulateTypeMeta()

	migratedConf.Name = conf.Name
	migratedConf.ListenPort = conf.ListenPort
	migratedConf.PrivateKey = conf.PrivateKey
	migratedConf.IPs = conf.IPs

	migratedConf.Peers = make([]v1alpha2.PeerConfig, len(conf.Peers))
	for i, peerConf := range conf.Peers {
		migratedConf.Peers[i] = v1alpha2.PeerConfig{
			Name:      peerConf.Name,
			PublicKey: peerConf.PublicKey,
			Endpoint:  peerConf.Endpoint,
			IPs:       peerConf.IPs,
		}
	}

	if conf.DNSServers != nil {
		migratedConf.DNS = &v1alpha2.DNSConfig{
			Servers: conf.DNSServers,
		}
	}

	for _, peerConf := range conf.Peers {
		if peerConf.DefaultGateway {
			if util.HasIPv4(interfaceAddrs) {
				peerConf.GatewayForCIDRs = append(peerConf.GatewayForCIDRs, "0.0.0.0/0")
			}
			if util.HasIPv6(interfaceAddrs) {
				peerConf.GatewayForCIDRs = append(peerConf.GatewayForCIDRs, "::/0")
			}
		}

		for _, prefix := range peerConf.GatewayForCIDRs {
			routeConf := v1alpha2.RouteConfig{
				Destination: prefix,
				Via:         peerConf.PublicKey,
			}

			if peerConf.Name != "" {
				routeConf.Via = peerConf.Name
			}

			migratedConf.Routes = append(migratedConf.Routes, routeConf)
		}
	}

	return migratedConf, nil
}

func migrateV1Alpha2ToV1Alpha3(conf *v1alpha2.Config) (*latestconfig.Config, error) {
	migratedConf := &latestconfig.Config{}
	migratedConf.PopulateTypeMeta()

	migratedConf.Name = conf.Name
	migratedConf.ListenPort = conf.ListenPort
	migratedConf.PrivateKey = conf.PrivateKey
	migratedConf.MTU = conf.MTU

	var err error
	migratedConf.IPs, err = util.ParseAddrList(conf.IPs)
	if err != nil {
		return nil, fmt.Errorf("could not parse local addresses: %w", err)
	}

	migratedConf.Peers = make([]latestconfig.PeerConfig, len(conf.Peers))
	for i, peerConf := range conf.Peers {
		migratedPeerConf := latestconfig.PeerConfig{
			Name:      peerConf.Name,
			PublicKey: peerConf.PublicKey,
			Endpoint:  peerConf.Endpoint,
		}

		migratedPeerConf.IPs, err = util.ParseAddrList(peerConf.IPs)
		if err != nil {
			return nil, fmt.Errorf("could not parse peer %q addresses: %w", peerConf.Name, err)
		}

		migratedConf.Peers[i] = migratedPeerConf
	}

	if conf.DNS != nil {
		servers := make([]types.MaybeAddrPort, len(conf.DNS.Servers))
		for i, server := range conf.DNS.Servers {
			if err := servers[i].UnmarshalText([]byte(server)); err != nil {
				return nil, fmt.Errorf("could not parse DNS server: %w", err)
			}
		}

		migratedConf.DNS = &latestconfig.DNSConfig{
			Domain:   conf.DNS.Domain,
			Protocol: latestconfig.DNSProtocol(conf.DNS.Protocol),
			Servers:  servers,
		}
	}

	for _, routeConf := range conf.Routes {
		destination, err := netip.ParsePrefix(routeConf.Destination)
		if err != nil {
			return nil, fmt.Errorf("could not parse route destination: %w", err)
		}

		migratedConf.Routes = append(migratedConf.Routes, latestconfig.RouteConfig{
			Destination: destination,
			Via:         routeConf.Via,
		})
	}

	return migratedConf, nil
}
