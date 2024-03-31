// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package v1alpha1

import (
	"fmt"

	"github.com/noisysockets/noisysockets/config/types"
)

const ApiVersion = "noisysockets.github.com/v1alpha1"

// Config is the configuration for a NoisySocket.
// It is analogous to the configuration for a WireGuard interface.
type Config struct {
	types.TypeMeta `yaml:",inline" mapstructure:",squash"`
	// Name is the hostname of this socket.
	Name string `yaml:"name" mapstructure:"name"`
	// ListenPort is an optional port on which to listen for incoming packets.
	// If not specified, one will be chosen randomly.
	ListenPort uint16 `yaml:"listenPort" mapstructure:"listenPort"`
	// PrivateKey is the private key for this socket.
	PrivateKey string `yaml:"privateKey" mapstructure:"privateKey"`
	// IPs is a list of IP addresses assigned to this socket.
	IPs []string `yaml:"ips" mapstructure:"ips"`
	// DNSServers is an optional list of DNS servers to use for host resolution.
	DNSServers []string `yaml:"dnsServers" mapstructure:"dnsServers"`
	// Peers is a list of known peers to which this socket can send and receive packets.
	Peers []WireGuardPeerConfig `yaml:"peers" mapstructure:"peers"`
}

// WireGuardPeerConfig is the configuration for a known peer.
type WireGuardPeerConfig struct {
	// Name is the hostname of the peer.
	Name string `yaml:"name" mapstructure:"name"`
	// PublicKey is the public key of the peer.
	PublicKey string `yaml:"publicKey" mapstructure:"publicKey"`
	// Endpoint is an optional endpoint to which the peer's packets should be sent.
	// If not specified, we will attempt to discover the peer's endpoint from its packets.
	Endpoint string `yaml:"endpoint" mapstructure:"endpoint"`
	// IPs is a list of IP addresses assigned to the peer.
	IPs []string `yaml:"ips" mapstructure:"ips"`
	// DefaultGateway indicates whether this peer should be used as the default gateway for traffic.
	DefaultGateway bool `yaml:"defaultGateway" mapstructure:"defaultGateway"`
}

func (c Config) GetKind() string {
	return "Config"
}

func (c Config) GetAPIVersion() string {
	return ApiVersion
}

func GetConfigByKind(kind string) (types.Config, error) {
	switch kind {
	case "Config":
		return &Config{}, nil
	default:
		return nil, fmt.Errorf("unsupported kind: %s", kind)
	}
}
