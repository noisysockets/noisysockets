/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 * Copyright (c) 2024 Damian Peckett <damian@pecke.tt>.
 */

package transport

import (
	"io"
)

type SourceSink interface {
	io.Closer

	// Read one or more packets from the Transport (without any additional headers).
	// On a successful read it returns the number of packets read, and sets
	// packet lengths within the sizes slice. len(sizes) must be >= len(bufs).
	// A nonzero offset can be used to instruct the Transport on where to begin
	// reading into each element of the bufs slice.
	Read(bufs [][]byte, sizes []int, destinations []NoisePublicKey, offset int) (int, error)

	// Write one or more packets to the transport (without any additional headers).
	// On a successful write it returns the number of packets written. A nonzero
	// offset can be used to instruct the Transport on where to begin writing from
	// each packet contained within the bufs slice.
	Write(bufs [][]byte, sources []NoisePublicKey, offset int) (int, error)

	// BatchSize returns the preferred/max number of packets that can be read or
	// written in a single read/write call. BatchSize must not change over the
	// lifetime of a Transport.
	BatchSize() int
}
