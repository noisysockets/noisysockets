// SPDX-License-Identifier: MIT

// Package main demonstrates how to use a noisy sockets router as an internet
// egress node / gateway for a wireguard network.
package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/noisysockets/noisysockets"
	latestconfig "github.com/noisysockets/noisysockets/config/v1alpha2"
	"github.com/noisysockets/noisysockets/examples/util/router"
	"github.com/noisysockets/noisysockets/types"
)

func main() {
	logger := slog.Default()

	// Generate keypair for the router.
	routerPrivateKey, err := types.NewPrivateKey()
	if err != nil {
		logger.Error("Failed to generate router private key", slog.Any("error", err))
		os.Exit(1)
	}

	// Get the public key for the router.
	routerPublicKey := routerPrivateKey.Public()

	// Generate keypair for our client peer.
	clientPrivateKey, err := types.NewPrivateKey()
	if err != nil {
		logger.Error("Failed to generate client private key", slog.Any("error", err))
		os.Exit(1)
	}

	// Usually this would be a VPN server running on a remote host.
	ctx := context.Background()
	routerEndpoint, stopRouter, err := router.Start(ctx, routerPrivateKey, clientPrivateKey.Public())
	if err != nil {
		logger.Error("Failed to start noisy sockets router", slog.Any("error", err))
		os.Exit(1)
	}
	defer stopRouter()

	// Create a network for our "client" peer.
	net, err := noisysockets.OpenNetwork(logger, &latestconfig.Config{
		PrivateKey: clientPrivateKey.String(),
		IPs: []string{
			"100.64.0.2",
		},
		DNS: &latestconfig.DNSConfig{
			Protocol: latestconfig.DNSProtocolTCP,
			Servers:  []string{"100.64.0.1"},
		},
		Routes: []latestconfig.RouteConfig{
			{
				// Route all IPv4 traffic through the router.
				Destination: "0.0.0.0/0",
				Via:         "router",
			},
		},
		Peers: []latestconfig.PeerConfig{
			{
				Name:      "router",
				PublicKey: routerPublicKey.String(),
				Endpoint:  routerEndpoint,
				// Normally we wouldn't need to give the router any IPs, but
				// since its doing dual duty as the DNS server, we need to give it
				// a routable IP.
				IPs: []string{"100.64.0.1"},
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

	// Make a request to a public address to verify that our router is working.
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

	// Print the response body (in this case the public ip of the router).
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Failed to read response body", slog.Any("error", err))
		os.Exit(1)
	}

	logger.Info("Public address", slog.String("ip", strings.TrimSpace(string(body))))
}
