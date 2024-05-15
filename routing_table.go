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
	"log/slog"
	"net/netip"
	"sync"

	"github.com/noisysockets/noisysockets/internal/uint128"
	"github.com/noisysockets/noisysockets/internal/util"
	"github.com/rdleal/intervalst/interval"
)

type peerWithPrefix struct {
	*Peer
	prefix netip.Prefix
}

type intervalRange struct {
	withPrefix *peerWithPrefix
	start      uint128.Uint128
	end        uint128.Uint128
}

// routingTable is a routing table that maps ip addresses to peers.
type routingTable struct {
	mu              sync.RWMutex
	logger          *slog.Logger
	intervalsByPeer map[*Peer][]intervalRange
	destinations    *interval.SearchTree[*peerWithPrefix, uint128.Uint128]
}

func newRoutingTable(logger *slog.Logger) *routingTable {
	return &routingTable{
		logger:          logger,
		intervalsByPeer: make(map[*Peer][]intervalRange),
		destinations: interval.NewSearchTreeWithOptions[*peerWithPrefix](func(k1, k2 uint128.Uint128) int {
			return k1.Cmp(k2)
		}, interval.TreeWithIntervalPoint()),
	}
}

func (rt *routingTable) destination(addr netip.Addr) (*Peer, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	addrInt := addrToUint128(addr)
	destinations, ok := rt.destinations.AllIntersections(addrInt, addrInt)
	if !ok {
		return nil, false
	}

	// Look for the longest prefix length.
	var destination *peerWithPrefix
	for _, p := range destinations {
		if destination == nil || p.prefix.Bits() > destination.prefix.Bits() {
			destination = p
		}
	}

	return destination.Peer, true
}

// update upserts the routing table with the peer's information.
func (rt *routingTable) update(p *Peer) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	// Compute the intervals for the peer.
	intervals, err := rt.intervals(p)
	if err != nil {
		return fmt.Errorf("failed to compute intervals for peer %s: %w", p.Name(), err)
	}

	// Update the intervals for the peer.
	for _, interval := range intervals {
		found := false
		for _, existingInterval := range rt.intervalsByPeer[p] {
			if existingInterval.start.Cmp(interval.start) == 0 && existingInterval.end.Cmp(interval.end) == 0 {
				found = true
				break
			}
		}

		if !found {
			rt.logger.Debug("Adding interval to routing table",
				slog.String("peer", p.Name()),
				slog.String("prefix", interval.withPrefix.prefix.String()))

			if err := rt.destinations.Insert(interval.start, interval.end, interval.withPrefix); err != nil {
				return fmt.Errorf("failed to add interval to routing table: %w", err)
			}
		}
	}

	// Remove existing intervals that are not needed anymore.
	for _, interval := range rt.intervalsByPeer[p] {
		found := false
		for _, newInterval := range intervals {
			if interval.start.Cmp(newInterval.start) == 0 && interval.end.Cmp(newInterval.end) == 0 {
				found = true
				break
			}
		}

		if !found {
			rt.logger.Debug("Removing prefix from routing table",
				slog.String("peer", p.Name()),
				slog.String("prefix", interval.withPrefix.prefix.String()))

			if err := rt.destinations.Delete(interval.start, interval.end); err != nil {
				return fmt.Errorf("failed to remove interval from routing table: %w", err)
			}
		}
	}

	rt.intervalsByPeer[p] = intervals

	return nil
}

// remove removes the peer from the routing table.
func (rt *routingTable) remove(p *Peer) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	for _, interval := range rt.intervalsByPeer[p] {
		rt.logger.Debug("Removing prefix from routing table",
			slog.String("peer", p.Name()),
			slog.String("prefix", interval.withPrefix.prefix.String()))

		if err := rt.destinations.Delete(interval.start, interval.end); err != nil {
			return fmt.Errorf("failed to remove interval from routing table: %w", err)
		}
	}

	delete(rt.intervalsByPeer, p)

	return nil
}

func (rt *routingTable) intervals(p *Peer) ([]intervalRange, error) {
	var intervals []intervalRange

	// Add all the peer's addresses.
	for _, addr := range p.Addresses() {
		addrInt := addrToUint128(addr)

		var prefix netip.Prefix
		if addr.Is4() {
			prefix = netip.MustParsePrefix(addr.String() + "/32")
		} else {
			prefix = netip.MustParsePrefix(addr.String() + "/128")
		}

		rt.logger.Debug("Adding address to routing table",
			slog.String("peer", p.Name()),
			slog.String("address", addr.String()))

		intervals = append(intervals, intervalRange{
			withPrefix: &peerWithPrefix{
				Peer:   p,
				prefix: prefix,
			},
			start: addrInt,
			end:   addrInt,
		})
	}

	// Add any registered routes.
	for _, prefix := range p.DestinationForPrefixes() {
		startAddr, endAddr, err := util.PrefixRange(prefix)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate range for prefix %s: %w", prefix, err)
		}

		rt.logger.Debug("Adding prefix to routing table",
			slog.String("peer", p.Name()),
			slog.String("prefix", prefix.String()))

		startAddrInt := addrToUint128(startAddr)
		endAddrInt := addrToUint128(endAddr)

		intervals = append(intervals, intervalRange{
			withPrefix: &peerWithPrefix{
				Peer:   p,
				prefix: prefix,
			},
			start: startAddrInt,
			end:   endAddrInt,
		})
	}

	return intervals, nil
}

func addrToUint128(addr netip.Addr) uint128.Uint128 {
	if addr.Is4() {
		as16 := addr.As16()
		return uint128.FromBytes(as16[:]).ReverseBytes()
	}

	return uint128.FromBytes(addr.AsSlice()).ReverseBytes()
}
