// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package config

import (
	"fmt"
	"os"

	"github.com/noisysockets/noisysockets/config/types"
	latest "github.com/noisysockets/noisysockets/config/v1alpha1"
	"gopkg.in/yaml.v3"
)

// FromYAML reads a config file from the given path and returns the config object.
func FromYAML(configPath string) (conf *latest.Config, err error) {
	confBytes, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", configPath, err)
	}

	var typeMeta types.TypeMeta
	if err := yaml.Unmarshal(confBytes, &typeMeta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal type meta from config file %q: %w", configPath, err)
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
		return nil, fmt.Errorf("failed to unmarshal config from config file %q: %w", configPath, err)
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

// SaveToYAML writes the config object to the given path.
func SaveToYAML(configPath string, versionedConf types.Config) error {
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

	confBytes, err := yaml.Marshal(conf)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, confBytes, 0o400); err != nil {
		return fmt.Errorf("failed to write config file %q: %w", configPath, err)
	}

	return nil
}

func migrate(_ types.Config) (*latest.Config, error) {
	// TODO: when a breaking change is made, implement migration logic here.
	return nil, nil
}
