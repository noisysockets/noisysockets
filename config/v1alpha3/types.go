// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package v1alpha3

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	configtypes "github.com/noisysockets/noisysockets/config/types"
	"github.com/noisysockets/noisysockets/types"
)

const APIVersion = "noisysockets.github.com/v1alpha3"

// Config is the configuration for a Noisy Sockets network.
// It is analogous to the configuration for a WireGuard interface.
type Config struct {
	configtypes.TypeMeta `yaml:",inline"`
	// Name is the optional hostname of this peer.
	Name string `yaml:"name,omitempty"`
	// ListenPort is an optional port on which to listen for incoming packets.
	// If not specified, one will be chosen randomly.
	ListenPort uint16 `yaml:"listenPort,omitempty"`
	// PrivateKey is the private key for this peer.
	PrivateKey string `yaml:"privateKey"`
	// MTU is the maximum transmission unit size for this network.
	// If not specified, a conservative default value of 1280 will be used.
	// This is the protocol MTU, not the media MTU, so account for 32 bytes of
	// overhead per packet.
	MTU int `yaml:"mtu,omitempty"`
	// Subnet is the optional CIDR block for the network.
	Subnet *netip.Prefix `yaml:"subnet,omitempty"`
	// IPs is a list of IP addresses assigned to this peer.
	IPs []netip.Addr `yaml:"ips,omitempty"`
	// DNS is the DNS configuration for this peer.
	DNS *DNSConfig `yaml:"dns,omitempty"`
	// Routes is the routing table to use for the network.
	Routes []RouteConfig `yaml:"routes,omitempty"`
	// Peers is a list of known peers to which we can send and receive packets.
	Peers []PeerConfig `yaml:"peers,omitempty"`
}

type DNSProtocol string

const (
	DNSProtocolAuto DNSProtocol = ""
	// DNSProtocolUDP is the UDP DNS protocol.
	DNSProtocolUDP DNSProtocol = "udp"
	// DNSProtocolTCP is the TCP DNS protocol.
	DNSProtocolTCP DNSProtocol = "tcp"
	// DNSProtocolTLS is the DNS-over-TLS protocol.
	DNSProtocolTLS DNSProtocol = "tls"
)

func (p *DNSProtocol) UnmarshalYAML(unmarshal func(any) error) error {
	var str string
	if err := unmarshal(&str); err != nil {
		return err
	}
	switch DNSProtocol(strings.ToLower(str)) {
	case DNSProtocolAuto, DNSProtocolUDP, DNSProtocolTCP, DNSProtocolTLS:
		*p = DNSProtocol(str)
		return nil
	default:
		return fmt.Errorf("unknown DNS protocol: %s", str)
	}
}

// DNSConfig is the configuration for DNS resolution.
type DNSConfig struct {
	// Domain is the optional default search domain to use for this network.
	// If not specified, a default value of "my.nzzy.net." will be used.
	Domain string `yaml:"domain,omitempty"`
	// Protocol is the DNS protocol to use for resolution.
	// If not specified, plain UDP will be used.
	Protocol DNSProtocol `yaml:"protocol,omitempty"`
	// Servers is a list of DNS servers to use for DNS resolution.
	Servers []types.MaybeAddrPort `yaml:"servers,omitempty"`
}

// RouteConfig is the configuration for a route in the routing table.
type RouteConfig struct {
	// Destinations is a CIDR block for which this route should be used.
	Destination netip.Prefix `yaml:"destination"`
	// Via is the name (or public key) of the peer to use as the gateway for this route.
	Via string `yaml:"via"`
}

// PeerConfig is the configuration for a known wireguard peer.
type PeerConfig struct {
	// Name is the optional hostname of the peer.
	Name string `yaml:"name,omitempty"`
	// PublicKey is the public key of the peer.
	PublicKey string `yaml:"publicKey"`
	// Endpoint is an optional endpoint to which the peer's packets should be sent.
	// If not specified, the peers endpoint will be determined from received packets.
	Endpoint string `yaml:"endpoint,omitempty"`
	// IPs is a list of IP addresses assigned to the peer, this is optional for gateways.
	// Traffic with a source IP not in this list will be dropped.
	IPs []netip.Addr `yaml:"ips,omitempty"`
	// PersistentKeepalive is an optional interval in seconds to send keepalive packets.
	// If not specified, a default value of 25s will be used.
	PersistentKeepalive *time.Duration `yaml:"persistentKeepalive,omitempty"`
}

func (c *Config) GetAPIVersion() string {
	return APIVersion
}

func (c *Config) GetKind() string {
	return "Config"
}

func (c *Config) PopulateTypeMeta() {
	c.TypeMeta = configtypes.TypeMeta{
		APIVersion: APIVersion,
		Kind:       "Config",
	}
}

func GetConfigByKind(kind string) (configtypes.Config, error) {
	switch kind {
	case "Config":
		return &Config{}, nil
	default:
		return nil, fmt.Errorf("unsupported kind: %s", kind)
	}
}
