// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package types

type TypeMeta struct {
	// Kind is the kind of the resource.
	Kind string `yaml:"kind" mapstructure:"kind"`
	// APIVersion is the version of the API.
	APIVersion string `yaml:"apiVersion" mapstructure:"apiVersion"`
}

type Config interface {
	GetKind() string
	GetAPIVersion() string
}
