// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package noisysockets

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/noisysockets/noisysockets/internal/conn"
	"github.com/noisysockets/noisysockets/internal/transport"
	"github.com/noisysockets/noisysockets/types"
)

var (
	ErrNoEndpoint = fmt.Errorf("no known endpoint for peer")
)

// Peer represents a wireguard peer in the network.
type Peer struct {
	sync.Mutex
	*transport.Peer
	name            string
	publicKey       types.NoisePublicKey
	addrs           []netip.Addr
	gatewayForCIDRs []netip.Prefix
}

// Name returns the human friendly name of the peer.
func (p *Peer) Name() string {
	return p.name
}

// PublicKey returns the public key of the peer.
func (p *Peer) PublicKey() types.NoisePublicKey {
	return p.publicKey
}

// GetEndpoint returns the endpoint (public address) of the peer.
func (p *Peer) GetEndpoint() (netip.AddrPort, error) {
	p.Lock()
	defer p.Unlock()

	endpoint := p.Peer.GetEndpoint()
	if endpoint == nil {
		return netip.AddrPort{}, ErrNoEndpoint
	}

	return netip.ParseAddrPort(endpoint.DstToString())
}

// SetEndpoint sets the endpoint (public address) of the peer.
func (p *Peer) SetEndpoint(endpoint netip.AddrPort) {
	p.Lock()
	defer p.Unlock()

	p.Peer.SetEndpoint(&conn.StdNetEndpoint{AddrPort: endpoint})
}
