/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2024 Damian Peckett <damian@pecke.tt>.
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
