// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	stdnet "net"

	"github.com/noisysockets/network"
	"github.com/noisysockets/network/tun"
	"github.com/noisysockets/noisysockets"
	latestconfig "github.com/noisysockets/noisysockets/config/v1alpha2"
	"github.com/noisysockets/noisysockets/examples/util/router"
	"github.com/noisysockets/noisysockets/types"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sync/errgroup"
)

const (
	reexecEnvName = "NOISYSOCKETS_REEXEC"
	nicEnvName    = "NOISYSOCKETS_NIC"
)

func main() {
	logger := slog.Default()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Catch signals to cancel the context.
	sigCh := make(chan os.Signal, 1)
	defer close(sigCh)

	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh

		logger.Info("Received signal, cancelling context")
		cancel()
	}()

	var err error
	if os.Getenv(reexecEnvName) == "" {
		if os.Geteuid() != 0 {
			logger.Error("Please run this program as root")
			os.Exit(1)
		}

		err = parent(ctx, logger)
	} else {
		err = child(logger)
	}
	if err != nil {
		logger.Error("Failed to run program", slog.Any("error", err))
		os.Exit(1)
	}
}

func parent(ctx context.Context, logger *slog.Logger) error {
	// Don't let the Go runtime schedule this goroutine on multiple threads.
	// As network namespaces are scoped to a single OS thread we don't want to
	// be moving around.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Generate keypair for the router.
	routerPrivateKey, err := types.NewPrivateKey()
	if err != nil {
		return fmt.Errorf("failed to generate router private key: %w", err)
	}

	// Get the public key for the router.
	routerPublicKey := routerPrivateKey.Public()

	// Generate keypair for our client peer.
	clientPrivateKey, err := types.NewPrivateKey()
	if err != nil {
		return fmt.Errorf("failed to generate client private key: %w", err)
	}

	logger.Info("Starting router container")

	// Usually this would be a VPN server running on a remote host.
	routerEndpoint, stopRouter, err := router.Start(ctx, routerPrivateKey, clientPrivateKey.Public())
	if err != nil {
		return fmt.Errorf("failed to start noisy sockets router: %w", err)
	}
	defer stopRouter()

	logger.Info("Connecting to WireGuard network")

	noisySocketsNIC, err := noisysockets.NewInterface(ctx, logger, latestconfig.Config{
		PrivateKey: clientPrivateKey.String(),
		IPs: []string{
			"100.64.0.2",
		},
		DNS: &latestconfig.DNSConfig{
			Protocol: latestconfig.DNSProtocolTCP,
			Servers:  []string{"100.64.0.1"},
		},
		Routes: []latestconfig.RouteConfig{
			// Route all IPv4 and IPv6 traffic through the router.
			{
				Destination: "0.0.0.0/0",
				Via:         "router",
			},
			{
				Destination: "::/0",
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
	}, network.NewPacketPool(0, false))
	if err != nil {
		return fmt.Errorf("failed to create noisy sockets interface: %w", err)
	}

	namespaceName := fmt.Sprintf("noisysockets-%d", os.Getpid())

	logger.Info("Creating network namespace", slog.String("name", namespaceName))

	if err := os.MkdirAll(filepath.Join("/etc/netns", namespaceName), 0755); err != nil {
		return fmt.Errorf("failed to create netns directory: %w", err)
	}
	defer os.RemoveAll("/etc/netns/noisysockets")

	resolvConfContent := "nameserver 100.64.0.1\n"
	if err := os.WriteFile(filepath.Join("/etc/netns", namespaceName, "resolv.conf"),
		[]byte(resolvConfContent), 0644); err != nil {
		return fmt.Errorf("failed to write resolv.conf for namespace: %w", err)
	}

	origns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get original network namespace: %w", err)
	}
	defer origns.Close()

	ns, err := netns.NewNamed(namespaceName)
	if err != nil {
		return fmt.Errorf("failed to create network namespace: %w", err)
	}
	defer func() {
		if err := ns.Close(); err != nil {
			logger.Error("Failed to close network namespace", slog.Any("error", err))
		}

		if err := netns.DeleteNamed(namespaceName); err != nil {
			logger.Error("Failed to delete network namespace", slog.Any("error", err))
		}
	}()

	// Move back to the original network namespace.
	if err := netns.Set(origns); err != nil {
		return fmt.Errorf("failed to move back to original network namespace: %w", err)
	}

	nicName := fmt.Sprintf("nsh%d", os.Getpid()%1000)

	logger.Info("Creating TUN device", slog.String("name", nicName))

	tunNIC, err := tun.Create(ctx, logger, nicName, nil)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %w", err)
	}
	defer tunNIC.Close()

	// Move the TUN device to the network namespace.
	link, err := netlink.LinkByName(nicName)
	if err != nil {
		return fmt.Errorf("failed to get TUN device: %w", err)
	}

	if err := netlink.LinkSetNsFd(link, int(ns)); err != nil {
		return fmt.Errorf("failed to move TUN device to network namespace: %w", err)
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return network.Splice(ctx, tunNIC, noisySocketsNIC, &network.SpliceConfiguration{
			PacketWriteOffset: tun.VirtioNetHdrLen,
		})
	})

	g.Go(func() error {
		args := []string{"netns", "exec", namespaceName, os.Args[0]}
		if len(os.Args) > 1 {
			args = append(args, os.Args[1:]...)
		}

		cmd := exec.Command("ip", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = append(os.Environ(), reexecEnvName+"=1", nicEnvName+"="+nicName)

		logger.Info("Running child process in network namespace", slog.String("name", namespaceName))

		if err := cmd.Run(); err != nil {
			return err
		}

		// Finish splice when the child process exits.
		return context.Canceled
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("failed to run child process: %w", err)
	}

	return nil
}

func child(logger *slog.Logger) error {
	nicName := os.Getenv(nicEnvName)
	if nicName == "" {
		return errors.New("missing NIC name")
	}

	logger.Info("Configuring TUN device", slog.String("name", nicName))

	link, err := netlink.LinkByName(nicName)
	if err != nil {
		return fmt.Errorf("failed to get TUN device: %w", err)
	}

	err = netlink.AddrAdd(link, &netlink.Addr{
		IPNet: &stdnet.IPNet{
			IP:   stdnet.ParseIP("100.64.0.2"),
			Mask: stdnet.CIDRMask(24, 32),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to assign IP address to TUN device: %w", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up TUN device: %w", err)
	}

	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &stdnet.IPNet{
			IP:   stdnet.ParseIP("0.0.0.0"),
			Mask: stdnet.CIDRMask(0, 32),
		},
		Gw: stdnet.ParseIP("100.64.0.1"),
	}); err != nil {
		return fmt.Errorf("failed to add route to router: %w", err)
	}

	logger.Info("Making request to public address")

	// Make a request to a public address to verify that our router is working.
	resp, err := http.Get("https://ipv4.icanhazip.com")
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("request failed: %s", resp.Status)
	}

	// Print the response body (in this case the public ip of the router).
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	logger.Info("Public address", slog.String("ip", strings.TrimSpace(string(body))))

	return nil
}
