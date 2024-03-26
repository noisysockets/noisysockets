/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2024 Damian Peckett <damian@pecke.tt>.
 */

package types

type TypeMeta struct {
	Kind       string `yaml:"kind" mapstructure:"kind"`
	APIVersion string `yaml:"apiVersion" mapstructure:"apiVersion"`
}

type Config interface {
	GetKind() string
	GetAPIVersion() string
}
