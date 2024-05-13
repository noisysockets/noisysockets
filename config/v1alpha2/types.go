// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package v1alpha2

import (
	"fmt"

	"github.com/noisysockets/noisysockets/config/types"
)

const APIVersion = "noisysockets.github.com/v1alpha2"

// Config is the configuration for a NoisySockets network.
// It is analogous to the configuration for a WireGuard interface.
type Config struct {
	types.TypeMeta `yaml:",inline" mapstructure:",squash"`
	// Name is the optional hostname of this peer.
	Name string `yaml:"name,omitempty" mapstructure:"name,omitempty"`
	// ListenPort is an optional port on which to listen for incoming packets.
	// If not specified, one will be chosen randomly.
	ListenPort uint16 `yaml:"listenPort,omitempty" mapstructure:"listenPort,omitempty"`
	// PrivateKey is the private key for this peer.
	PrivateKey string `yaml:"privateKey" mapstructure:"privateKey"`
	// IPs is a list of IP addresses assigned to this peer.
	IPs []string `yaml:"ips,omitempty" mapstructure:"ips,omitempty"`
	// DNS is the DNS configuration for this peer.
	DNS *DNSConfig `yaml:"dns,omitempty" mapstructure:"dns,omitempty"`
	// Routes is the routing table to use for the network.
	Routes []RouteConfig `yaml:"routes,omitempty" mapstructure:"routes,omitempty"`
	// Peers is a list of known peers to which we can send and receive packets.
	Peers []PeerConfig `yaml:"peers,omitempty" mapstructure:"peers,omitempty"`
}

// DNSConfig is the configuration for DNS resolution.
type DNSConfig struct {
	// Domain is the optional default search domain to use for this network.
	// If not specified, a default value of "my.nzzy.net." will be used.
	Domain string `yaml:"domain,omitempty" mapstructure:"domain,omitempty"`
	// Nameservers is a list of DNS servers to use for DNS resolution.
	Nameservers []string `yaml:"nameservers,omitempty" mapstructure:"nameservers,omitempty"`
}

// RouteConfig is the configuration for a route in the routing table.
type RouteConfig struct {
	// Destinations is a CIDR block for which this route should be used.
	Destination string `yaml:"destination" mapstructure:"destination"`
	// Via is the name (or public key) of the peer to use as the gateway for this route.
	Via string `yaml:"via" mapstructure:"via"`
}

// PeerConfig is the configuration for a known wireguard peer.
type PeerConfig struct {
	// Name is the optional hostname of the peer.
	Name string `yaml:"name,omitempty" mapstructure:"name,omitempty"`
	// PublicKey is the public key of the peer.
	PublicKey string `yaml:"publicKey" mapstructure:"publicKey"`
	// Endpoint is an optional endpoint to which the peer's packets should be sent.
	// If not specified, the peers endpoint will be determined from received packets.
	Endpoint string `yaml:"endpoint,omitempty" mapstructure:"endpoint,omitempty"`
	// IPs is a list of IP addresses assigned to the peer, this is optional for gateways.
	// Traffic with a source IP not in this list will be dropped.
	IPs []string `yaml:"ips,omitempty" mapstructure:"ips,omitempty"`
}

func (c *Config) GetAPIVersion() string {
	return APIVersion
}

func (c *Config) GetKind() string {
	return "Config"
}

func (c *Config) PopulateTypeMeta() {
	c.TypeMeta = types.TypeMeta{
		APIVersion: APIVersion,
		Kind:       "Config",
	}
}

func GetConfigByKind(kind string) (types.Config, error) {
	switch kind {
	case "Config":
		return &Config{}, nil
	default:
		return nil, fmt.Errorf("unsupported kind: %s", kind)
	}
}
