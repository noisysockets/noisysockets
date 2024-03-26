/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2024 Damian Peckett <damian@pecke.tt>.
 */

package v1alpha1

import (
	"fmt"

	"github.com/noisysockets/noisysockets/config/types"
)

const ApiVersion = "noisysockets.github.com/v1alpha1"

// WireGuardConfig is the configuration for a NoisySocket.
// It is analogous to the configuration for a WireGuard interface.
type WireGuardConfig struct {
	// Name is the hostname of this socket.
	Name string `yaml:"name" mapstructure:"name"`
	// ListenPort is the public port on which this socket listens for incoming packets.
	ListenPort uint16 `yaml:"listenPort" mapstructure:"listenPort"`
	// PrivateKey is the private key for this socket.
	PrivateKey string `yaml:"privateKey" mapstructure:"privateKey"`
	// IPs is a list of IP addresses assigned to this socket.
	IPs []string `yaml:"ips" mapstructure:"ips"`
	// DefaultGatewayName is the optional hostname of the peer to use as the default gateway for unknown traffic.
	DefaultGatewayName string `yaml:"defaultGatewayName" mapstructure:"defaultGatewayName"`
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
}

func (c WireGuardConfig) GetKind() string {
	return "WireGuardConfig"
}

func (c WireGuardConfig) GetAPIVersion() string {
	return ApiVersion
}

func GetConfigByKind(kind string) (types.Config, error) {
	switch kind {
	case "WireGuardConfig":
		return &WireGuardConfig{}, nil
	default:
		return nil, fmt.Errorf("unsupported kind: %s", kind)
	}
}
