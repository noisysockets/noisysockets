package main

import (
	"bufio"
	"fmt"
	"log"
	"log/slog"

	"github.com/noisysockets/noisysockets"
	"github.com/noisysockets/noisysockets/config/v1alpha1"
	"github.com/noisysockets/noisysockets/network"
	"github.com/noisysockets/noisysockets/types"
)

func main() {
	// Generate keypair for peer that will act as TCP server
	serverPK, err := types.NewPrivateKey()
	if err != nil {
		log.Fatalf("failed to generate private key: %v", err)
	}

	// Generate keypair for peer that will act as TCP client
	clientPK, err := types.NewPrivateKey()
	if err != nil {
		log.Fatalf("failed to generate private key: %v", err)
	}

	// Create network for "server" peer
	serverNetwork, err := noisysockets.NewNetwork(slog.Default(), &v1alpha1.Config{
		Name:       "server",
		PrivateKey: serverPK.String(),
		IPs:        []string{"10.0.0.1"},
		ListenPort: 8080,
		Peers: []v1alpha1.PeerConfig{
			{
				Name:      "client1",
				PublicKey: clientPK.PublicKey().String(),
				IPs:       []string{"10.0.0.2"},
			},
		},
	})
	if err != nil {
		log.Fatalf("failed to create network: %v", err)
	}
	defer serverNetwork.Close()

	// Create network for "client" peer
	clientNetwork, err := noisysockets.NewNetwork(slog.Default(), &v1alpha1.Config{
		Name:       "client1",
		PrivateKey: clientPK.String(),
		IPs:        []string{"10.0.0.2"},
		Peers: []v1alpha1.PeerConfig{
			{
				Name:      "server",
				PublicKey: serverPK.PublicKey().String(),
				IPs:       []string{"10.0.0.1"},
				// This endpoint address corresponds to the server's ListenPort
				Endpoint: "127.0.0.1:8080",
			},
		},
	})
	if err != nil {
		log.Fatalf("failed to create network: %v", err)
	}
	defer clientNetwork.Close()

	readyCh := make(chan struct{})
	go startServer(serverNetwork, readyCh)
	<-readyCh

	startClient(clientNetwork)
}

func startServer(network network.Network, readyCh chan<- struct{}) {
	// Create TCP listener on the NoisySockets "server" peer address
	l, err := network.Listen("tcp", "10.0.0.1:8080")
	if err != nil {
		log.Fatalf("failed to start network: %v", err)
	}
	log.Println("Listening @ 10.0.0.1:8080 on SERVER")

	close(readyCh)

	// Use the listener just like an ordinary net.Listener
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatalf("failed to accept connection: %v", err)
		}

		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			line := scanner.Text()

			fmt.Fprintln(conn, "Hello Joe")
			log.Println("CLIENT => SERVER |", line)
		}
	}
}

func startClient(network network.Network) {
	// Dial the NoisySockets "server" peer address
	conn, err := network.Dial("tcp", "10.0.0.1:8080")
	if err != nil {
		log.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	log.Println("Dialed 10.0.0.1:8080 on CLIENT")
	fmt.Fprintln(conn, "Hello Mike")

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()

		log.Println("CLIENT <= SERVER |", line)
	}
}
