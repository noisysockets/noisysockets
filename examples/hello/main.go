// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"os"

	stdnet "net"

	"github.com/noisysockets/noisysockets"
	"github.com/noisysockets/noisysockets/config/v1alpha1"
	"github.com/noisysockets/noisysockets/network"
	"github.com/noisysockets/noisysockets/types"
)

func main() {
	logger := slog.Default()

	// Generate keypair for peer that will act as TCP server.
	serverPrivateKey, err := types.NewPrivateKey()
	if err != nil {
		logger.Error("Failed to generate private key", "error", err)
		os.Exit(1)
	}

	// Generate keypair for peer that will act as TCP client.
	clientPrivateKey, err := types.NewPrivateKey()
	if err != nil {
		logger.Error("Failed to generate private key", "error", err)
		os.Exit(1)
	}

	// Create a network for "server" peer.
	serverNet, err := noisysockets.NewNetwork(logger, &v1alpha1.Config{
		Name:       "server",
		PrivateKey: serverPrivateKey.String(),
		IPs:        []string{"10.0.0.1"},
		ListenPort: 51820,
		Peers: []v1alpha1.PeerConfig{
			{
				Name:      "client1",
				PublicKey: clientPrivateKey.PublicKey().String(),
				IPs:       []string{"10.0.0.2"},
			},
		},
	})
	if err != nil {
		logger.Error("Failed to create network", "error", err)
		os.Exit(1)
	}
	defer serverNet.Close()

	// Create a network for "client" peer.
	clientNet, err := noisysockets.NewNetwork(logger, &v1alpha1.Config{
		Name:       "client1",
		PrivateKey: clientPrivateKey.String(),
		IPs:        []string{"10.0.0.2"},
		Peers: []v1alpha1.PeerConfig{
			{
				Name:      "server",
				PublicKey: serverPrivateKey.PublicKey().String(),
				IPs:       []string{"10.0.0.1"},
				// This endpoint address corresponds to the server's ListenPort.
				Endpoint: "127.0.0.1:51820",
			},
		},
	})
	if err != nil {
		logger.Error("Failed to create network", "error", err)
		os.Exit(1)
	}
	defer clientNet.Close()

	readyCh := make(chan struct{})
	go startServer(logger, serverNet, readyCh)
	<-readyCh

	startClient(logger, clientNet)
}

func startServer(logger *slog.Logger, net network.Network, readyCh chan<- struct{}) {
	// Create TCP listener on the "server" peer address.
	lis, err := net.Listen("tcp", ":8080")
	if err != nil {
		logger.Error("Failed to listen", "error", err)
		os.Exit(1)
	}

	logger.Info("Listening for connections", "address", lis.Addr().String())

	close(readyCh)

	// Use the listener just like an ordinary net.Listener.
	for {
		conn, err := lis.Accept()
		if err != nil {
			if errors.Is(err, stdnet.ErrClosed) {
				return
			}

			logger.Error("Failed to accept connection", "error", err)
			os.Exit(1)
		}

		fmt.Fprintf(conn, "Hello %s!\n", conn.RemoteAddr().String())

		_ = conn.Close()
	}
}

func startClient(logger *slog.Logger, net network.Network) {
	// Dial the "server" peer address just like an ordinary net.Dial.
	conn, err := net.Dial("tcp", "server:8080")
	if err != nil {
		logger.Error("Failed to dial", "error", err)
		os.Exit(1)
	}
	defer conn.Close()

	logger.Info("Connected to server", "address", conn.RemoteAddr().String())

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()

		logger.Info("Received message from server", "message", line)
	}

	if err := scanner.Err(); err != nil && !errors.Is(err, os.ErrClosed) {
		logger.Error("Failed to read message", "error", err)
		os.Exit(1)
	}
}
