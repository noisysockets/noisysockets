// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package config

import (
	"fmt"
	"io"

	"github.com/noisysockets/noisysockets/config/types"
	latest "github.com/noisysockets/noisysockets/config/v1alpha1"
	"gopkg.in/yaml.v3"
)

// FromYAML reads the given reader and returns a config object.
func FromYAML(r io.Reader) (conf *latest.Config, err error) {
	confBytes, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read config from reader: %w", err)
	}

	var typeMeta types.TypeMeta
	if err := yaml.Unmarshal(confBytes, &typeMeta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal type meta from config file: %w", err)
	}

	var versionedConf types.Config
	switch typeMeta.APIVersion {
	case latest.ApiVersion:
		versionedConf, err = latest.GetConfigByKind(typeMeta.Kind)
	default:
		return nil, fmt.Errorf("unsupported api version: %s", typeMeta.APIVersion)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get config by kind %q: %w", typeMeta.Kind, err)
	}

	if err := yaml.Unmarshal(confBytes, versionedConf); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config from config file: %w", err)
	}

	if versionedConf.GetAPIVersion() != latest.ApiVersion {
		conf, err = migrate(versionedConf)
		if err != nil {
			return nil, fmt.Errorf("failed to migrate config: %w", err)
		}
	} else {
		conf = versionedConf.(*latest.Config)
	}

	// TODO: validate config.

	return conf, nil
}

// SaveToYAML writes the given config object to the given writer.
func SaveToYAML(w io.Writer, versionedConf types.Config) error {
	var conf *latest.Config
	if versionedConf.GetAPIVersion() != latest.ApiVersion {
		var err error
		conf, err = migrate(versionedConf)
		if err != nil {
			return fmt.Errorf("failed to migrate config: %w", err)
		}
	} else {
		conf = versionedConf.(*latest.Config)
	}

	if err := yaml.NewEncoder(w).Encode(conf); err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	return nil
}

func migrate(_ types.Config) (*latest.Config, error) {
	// TODO: when a breaking change is made, implement migration logic here.
	return nil, nil
}
