// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package types

type TypeMeta struct {
	// APIVersion is the version of the API.
	APIVersion string `yaml:"apiVersion" mapstructure:"apiVersion"`
	// Kind is the kind of the resource.
	Kind string `yaml:"kind" mapstructure:"kind"`
}

type Config interface {
	GetAPIVersion() string
	GetKind() string
	PopulateTypeMeta()
}
