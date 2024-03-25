//go:build !linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 * Copyright (c) 2024 Damian Peckett <damian@pecke.tt>.
 */

package conn

func errShouldDisableUDPGSO(err error) bool {
	return false
}
