// SPDX-License-Identifier: MIT

package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	stdnet "net"

	"github.com/docker/docker/api/types/container"
	"github.com/noisysockets/noisysockets/types"
	"github.com/testcontainers/testcontainers-go"
)

// Start starts a WireGuard gateway in a Docker container, this is used in place of a real WireGuard server for testing examples.
func Start(ctx context.Context, gwPrivateKey types.NoisePrivateKey, clientPublicKey types.NoisePublicKey) (hostPort string, closer func() error, err error) {
	var gwContainer testcontainers.Container
	var gwConfigDir string

	closer = func() error {
		if gwContainer != nil {
			if err := gwContainer.Terminate(ctx); err != nil {
				return err
			}
		}

		if gwConfigDir != "" {
			if err := os.RemoveAll(gwConfigDir); err != nil {
				return err
			}
		}

		return nil
	}

	wgConf := `
	[Interface]
	PrivateKey = ` + gwPrivateKey.String() + `
	ListenPort = 51820
	Address = 10.0.0.1/32
	PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
	PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

	[Peer]
	PublicKey = ` + clientPublicKey.String() + `
	AllowedIPs = 10.0.0.2/32
`

	gwConfigDir, err = os.MkdirTemp("", "wg-")
	if err != nil {
		err = fmt.Errorf("failed to create config dir: %w", err)
		return
	}

	if err = os.Chmod(gwConfigDir, 0o700); err != nil {
		err = fmt.Errorf("failed to change permissions for config dir: %w", err)
		return
	}

	wgConfPath := filepath.Join(gwConfigDir, "wg0.conf")
	if err = os.WriteFile(wgConfPath, []byte(wgConf), 0o400); err != nil {
		err = fmt.Errorf("failed to write wireguard config: %w", err)
		return
	}

	gwReq := testcontainers.ContainerRequest{
		Image:        "ghcr.io/noisysockets/gateway:v0.1.0",
		ExposedPorts: []string{"51820/udp"},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: wgConfPath, ContainerFilePath: "/etc/wireguard/wg0.conf", FileMode: 0o400},
		},
		HostConfigModifier: func(hostConfig *container.HostConfig) {
			hostConfig.CapAdd = []string{"NET_ADMIN"}

			hostConfig.Sysctls = map[string]string{
				"net.ipv4.ip_forward":              "1",
				"net.ipv4.conf.all.src_valid_mark": "1",
			}

			hostConfig.Binds = append(hostConfig.Binds, "/dev/net/tun:/dev/net/tun")
		},
	}

	gwContainer, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: gwReq,
		Started:          true,
	})
	if err != nil {
		err = fmt.Errorf("failed to start wireguard gateway: %w", err)
		return
	}

	// Time for everything to settle down.
	time.Sleep(3 * time.Second)

	wgHost, err := gwContainer.Host(ctx)
	if err != nil {
		err = fmt.Errorf("failed to get wireguard gateway host: %w", err)
		return
	}

	wgPort, err := gwContainer.MappedPort(ctx, "51820/udp")
	if err != nil {
		err = fmt.Errorf("failed to get wireguard gateway port: %w", err)
		return
	}

	hostPort = stdnet.JoinHostPort(wgHost, wgPort.Port())
	return
}
