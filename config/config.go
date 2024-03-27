/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2024 Damian Peckett <damian@pecke.tt>.
 */

package config

import (
	"fmt"
	"os"

	"github.com/noisysockets/noisysockets/config/types"
	latest "github.com/noisysockets/noisysockets/config/v1alpha1"
	"gopkg.in/yaml.v3"
)

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

func migrate(_ types.Config) (*latest.Config, error) {
	// TODO: when a breaking change is made, implement migration logic here.
	return nil, nil
}
