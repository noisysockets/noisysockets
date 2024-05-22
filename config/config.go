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

	"github.com/noisysockets/noisysockets/config/types"
	"github.com/noisysockets/noisysockets/config/v1alpha1"
	latestconfig "github.com/noisysockets/noisysockets/config/v1alpha2"
	"github.com/noisysockets/noisysockets/util"
	"gopkg.in/yaml.v3"
)

// FromYAML reads the given reader and returns a config object.
func FromYAML(r io.Reader) (conf *latestconfig.Config, err error) {
	confBytes, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read config from reader: %w", err)
	}

	var typeMeta types.TypeMeta
	if err := yaml.Unmarshal(confBytes, &typeMeta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal type meta from config file: %w", err)
	}

	var versionedConf types.Config
	switch typeMeta.APIVersion {
	case v1alpha1.APIVersion:
		versionedConf, err = v1alpha1.GetConfigByKind(typeMeta.Kind)
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

	if versionedConf.GetAPIVersion() != latestconfig.APIVersion {
		conf, err = migrate(versionedConf)
		if err != nil {
			return nil, fmt.Errorf("failed to migrate config: %w", err)
		}
	} else {
		conf = versionedConf.(*latestconfig.Config)
	}

	// TODO: validate config?

	return conf, nil
}

// ToYAML writes the given config object to the given writer.
func ToYAML(w io.Writer, versionedConf types.Config) error {
	var conf *latestconfig.Config
	if versionedConf.GetAPIVersion() != latestconfig.APIVersion {
		var err error
		conf, err = migrate(versionedConf)
		if err != nil {
			return fmt.Errorf("failed to migrate config: %w", err)
		}
	} else {
		conf = versionedConf.(*latestconfig.Config)
	}

	conf.PopulateTypeMeta()

	if err := yaml.NewEncoder(w).Encode(conf); err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	return nil
}

func migrate(versionedConf types.Config) (*latestconfig.Config, error) {
	switch conf := versionedConf.(type) {
	case *v1alpha1.Config:
		return migrateV1Alpha1ToV1Alpha2(conf)
	default:
		return nil, fmt.Errorf("unsupported config version: %s", versionedConf.GetAPIVersion())
	}
}

func migrateV1Alpha1ToV1Alpha2(conf *v1alpha1.Config) (*latestconfig.Config, error) {
	interfaceAddrs, err := util.ParseAddrList(conf.IPs)
	if err != nil {
		return nil, fmt.Errorf("could not parse local addresses: %w", err)
	}

	migratedConf := &latestconfig.Config{}
	migratedConf.PopulateTypeMeta()

	migratedConf.Name = conf.Name
	migratedConf.ListenPort = conf.ListenPort
	migratedConf.PrivateKey = conf.PrivateKey
	migratedConf.IPs = conf.IPs

	migratedConf.Peers = make([]latestconfig.PeerConfig, len(conf.Peers))
	for i, peerConf := range conf.Peers {
		migratedConf.Peers[i] = latestconfig.PeerConfig{
			Name:      peerConf.Name,
			PublicKey: peerConf.PublicKey,
			Endpoint:  peerConf.Endpoint,
			IPs:       peerConf.IPs,
		}
	}

	if conf.DNSServers != nil {
		migratedConf.DNS = &latestconfig.DNSConfig{
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
			routeConf := latestconfig.RouteConfig{
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
