// SPDX-License-Identifier: MIT

package router

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	stdnet "net"

	"github.com/noisysockets/noisysockets/config"
	latestconfig "github.com/noisysockets/noisysockets/config/v1alpha2"
	"github.com/noisysockets/noisysockets/types"
	"github.com/testcontainers/testcontainers-go"
)

// Start starts a userspace WireGuard router in a Docker container.
func Start(ctx context.Context, privatekey types.NoisePrivateKey, clientPublicKey types.NoisePublicKey) (hostPort string, closer func() error, err error) {
	var wgContainer testcontainers.Container
	var confDir string

	closer = func() error {
		if wgContainer != nil {
			if err := wgContainer.Terminate(ctx); err != nil {
				return err
			}
		}

		if confDir != "" {
			if err := os.RemoveAll(confDir); err != nil {
				return err
			}
		}

		return nil
	}

	confDir, err = os.MkdirTemp("", "noisysockets-*")
	if err != nil {
		err = fmt.Errorf("failed to create config dir: %w", err)
		return
	}

	if err = os.Chmod(confDir, 0o700); err != nil {
		err = fmt.Errorf("failed to change permissions for config dir: %w", err)
		return
	}

	confPath := filepath.Join(confDir, "noisysockets.yaml")
	confFile, err := os.OpenFile(confPath, os.O_CREATE|os.O_WRONLY, 0o400)
	if err != nil {
		err = fmt.Errorf("failed to create config file: %w", err)
		return
	}

	err = config.ToYAML(confFile, &latestconfig.Config{
		ListenPort: 51820,
		PrivateKey: privatekey.String(),
		IPs:        []string{"100.64.0.1"},
		Peers: []latestconfig.PeerConfig{
			{
				PublicKey: clientPublicKey.String(),
				IPs:       []string{"100.64.0.2"},
			},
		},
	})
	_ = confFile.Close()
	if err != nil {
		err = fmt.Errorf("failed to write config: %w", err)
		return
	}

	wgReq := testcontainers.ContainerRequest{
		Image:        "ghcr.io/noisysockets/nsh:v0.5.0",
		ExposedPorts: []string{"51820/udp"},
		Cmd:          []string{"serve", "--config=/etc/nsh/noisysockets.yaml", "--enable-dns", "--enable-router"},
		// Run as root for the tests so we can avoid permission issues with the config file,
		// sadly testcontainers-go doesn't support setting uid/gid when copying files.
		User: "0:0",
		Files: []testcontainers.ContainerFile{
			{HostFilePath: confPath, ContainerFilePath: "/etc/nsh/noisysockets.yaml", FileMode: 0o400},
		},
	}

	wgContainer, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: wgReq,
		Started:          true,
	})
	if err != nil {
		err = fmt.Errorf("failed to start wireguard router: %w", err)
		return
	}

	wgHost, err := wgContainer.Host(ctx)
	if err != nil {
		err = fmt.Errorf("failed to get wireguard router host: %w", err)
		return
	}

	wgPort, err := wgContainer.MappedPort(ctx, "51820/udp")
	if err != nil {
		err = fmt.Errorf("failed to get wireguard router port: %w", err)
		return
	}

	hostPort = stdnet.JoinHostPort(wgHost, wgPort.Port())
	return
}
