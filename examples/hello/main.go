// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"

	stdnet "net"

	"github.com/noisysockets/network"
	"github.com/noisysockets/noisysockets"
	latestconfig "github.com/noisysockets/noisysockets/config/v1alpha2"
	"github.com/noisysockets/noisysockets/types"
)

func main() {
	logger := slog.Default()

	// Generate keypair for peer that will act as TCP server.
	serverPrivateKey, err := types.NewPrivateKey()
	if err != nil {
		logger.Error("Failed to generate private key", slog.Any("error", err))
		os.Exit(1)
	}

	// Generate keypair for peer that will act as TCP client.
	clientPrivateKey, err := types.NewPrivateKey()
	if err != nil {
		logger.Error("Failed to generate private key", slog.Any("error", err))
		os.Exit(1)
	}

	// Create a network for "server" peer.
	serverConf := &latestconfig.Config{
		Name:       "server",
		PrivateKey: serverPrivateKey.String(),
		IPs:        []string{"100.64.0.1"},
		ListenPort: 51820,
		Peers: []latestconfig.PeerConfig{
			{
				Name:      "client1",
				PublicKey: clientPrivateKey.Public().String(),
				IPs:       []string{"100.64.0.2"},
			},
		},
	}

	serverNet, err := noisysockets.OpenNetwork(logger, serverConf)
	if err != nil {
		logger.Error("Failed to create network", slog.Any("error", err))
		os.Exit(1)
	}
	defer serverNet.Close()

	// Create a network for "client" peer.
	clientNet, err := noisysockets.OpenNetwork(logger, &latestconfig.Config{
		Name:       "client1",
		PrivateKey: clientPrivateKey.String(),
		IPs:        []string{"100.64.0.2"},
		Peers: []latestconfig.PeerConfig{
			{
				Name:      "server",
				PublicKey: serverPrivateKey.Public().String(),
				IPs:       []string{"100.64.0.1"},
				Endpoint:  net.JoinHostPort("localhost", strconv.Itoa(int(serverConf.ListenPort))),
			},
		},
	})
	if err != nil {
		logger.Error("Failed to create network", slog.Any("error", err))
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
		logger.Error("Failed to listen", slog.Any("error", err))
		os.Exit(1)
	}

	logger.Info("Listening for connections", slog.String("address", lis.Addr().String()))

	close(readyCh)

	// Use the listener just like an ordinary net.Listener.
	for {
		conn, err := lis.Accept()
		if err != nil {
			if errors.Is(err, stdnet.ErrClosed) || network.IsStackClosed(err) {
				return
			}

			logger.Error("Failed to accept connection", slog.Any("error", err))
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
		logger.Error("Failed to dial", slog.Any("error", err))
		os.Exit(1)
	}
	defer conn.Close()

	logger.Info("Connected to server", slog.String("address", conn.RemoteAddr().String()))

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		msg := scanner.Text()

		logger.Info("Received message from server", slog.String("message", msg))
	}

	if err := scanner.Err(); err != nil && !errors.Is(err, os.ErrClosed) {
		logger.Error("Failed to read message", slog.Any("error", err))
		os.Exit(1)
	}
}
