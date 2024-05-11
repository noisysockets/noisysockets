// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/noisysockets/noisysockets"
	"github.com/noisysockets/noisysockets/config/v1alpha1"
	"github.com/noisysockets/noisysockets/examples/util/gateway"
	"github.com/noisysockets/noisysockets/types"
)

func main() {
	logger := slog.Default()

	// Generate keypair for the gateway peer.
	gatewayPrivateKey, err := types.NewPrivateKey()
	if err != nil {
		logger.Error("Failed to generate gateway private key", slog.Any("error", err))
		os.Exit(1)
	}

	// Get the public key for the gateway peer.
	gatewayPublicKey := gatewayPrivateKey.Public()

	// Generate keypair for our client peer.
	clientPrivateKey, err := types.NewPrivateKey()
	if err != nil {
		logger.Error("Failed to generate client private key", slog.Any("error", err))
		os.Exit(1)
	}

	// Usually this would be a VPN server running on a remote host. But for the
	// sake of this example, we'll spin up a local container running WireGuard.
	ctx := context.Background()
	gatewayHostPort, stopGateway, err := gateway.Start(ctx, gatewayPrivateKey, clientPrivateKey.Public())
	if err != nil {
		logger.Error("Failed to start wireguard gateway", slog.Any("error", err))
		os.Exit(1)
	}
	defer stopGateway()

	// Create a network for our "client" peer.
	net, err := noisysockets.OpenNetwork(logger, &v1alpha1.Config{
		PrivateKey: clientPrivateKey.String(),
		IPs: []string{
			"10.0.0.2",
		},
		DNSServers: []string{"10.0.0.1"},
		Routes: []v1alpha1.RouteConfig{
			{
				// Route all IPv4 traffic through the gateway.
				Destination: "0.0.0.0/0",
				Via:         "gateway",
			},
		},
		Peers: []v1alpha1.PeerConfig{
			{
				Name:      "gateway",
				PublicKey: gatewayPublicKey.String(),
				Endpoint:  gatewayHostPort,
				// Normally we wouldn't need to give the gateway peer any IPs, but
				// since its doing dual duty as the DNS server, we need to give it
				// a routable IP.
				IPs: []string{"10.0.0.1"},
			},
		},
	})
	if err != nil {
		logger.Error("Failed to create network", slog.Any("error", err))
		os.Exit(1)
	}
	defer net.Close()

	// Create a http client that will dial out through our network.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = net.DialContext

	client := *http.DefaultClient
	client.Transport = transport

	// Make a request to a public address to verify that our network/gateway is working.
	resp, err := client.Get("https://icanhazip.com")
	if err != nil {
		logger.Error("Failed to make request", slog.Any("error", err))
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Error("Request failed", slog.Any("status", resp.Status))
		os.Exit(1)
	}

	// Print the response body (in this case the public ip of the gateway).
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Failed to read response body", slog.Any("error", err))
		os.Exit(1)
	}

	logger.Info("Public address", slog.String("ip", strings.TrimSpace(string(body))))
}
