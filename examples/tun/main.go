// SPDX-License-Identifier: MIT

// Package main demonstrates how to use Noisy Sockets, network namespaces, and
// a TUN interface to create a simple VPN client that routes all traffic
// through a remote VPN server.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	stdnet "net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/noisysockets/network"
	"github.com/noisysockets/network/tun"
	"github.com/noisysockets/noisysockets"
	latestconfig "github.com/noisysockets/noisysockets/config/v1alpha3"
	"github.com/noisysockets/noisysockets/examples/util/router"
	"github.com/noisysockets/noisysockets/types"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sync/errgroup"
)

// reexecEnvName is the environment variable used to detect if we are reexecing
// inside a child network namespace.
const reexecEnvName = "NOISYSOCKETS_REEXEC"

func main() {
	logger := slog.Default()

	var err error
	if os.Getenv(reexecEnvName) == "" {
		if os.Geteuid() != 0 {
			logger.Error("Please run this program as root")
			os.Exit(1)
		}

		err = parentMain(logger)
	} else {
		err = childMain(logger)
	}
	if err != nil {
		logger.Error("Failed to run program", slog.Any("error", err))
		os.Exit(1)
	}
}

// The entry point for the parent process, which will run in the host network
// namespace.
func parentMain(logger *slog.Logger) error {
	namespaceName := fmt.Sprintf("noisysockets-%d", os.Getpid())
	nicName := fmt.Sprintf("nsh%d", os.Getpid()%1000)

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

	// Usually this would be a VPN server running on a remote host.
	ctx := context.Background()
	routerEndpoint, stopRouter, err := router.Start(ctx, routerPrivateKey, clientPrivateKey.Public())
	if err != nil {
		return fmt.Errorf("failed to start noisy sockets router: %w", err)
	}
	defer stopRouter()

	// Create an interface for our client peer.
	packetPool := network.NewPacketPool(0, false)
	wgNic, err := noisysockets.NewInterface(ctx, logger, packetPool, &latestconfig.Config{
		PrivateKey: clientPrivateKey.String(),
		IPs:        []netip.Addr{netip.MustParseAddr("100.64.0.2")},
		DNS: &latestconfig.DNSConfig{
			Protocol: latestconfig.DNSProtocolTCP,
			Servers:  []types.MaybeAddrPort{types.MustParseMaybeAddrPort("100.64.0.1")},
		},
		Routes: []latestconfig.RouteConfig{
			// Route all traffic through the router.
			{Destination: netip.MustParsePrefix("0.0.0.0/0"), Via: "router"},
			{Destination: netip.MustParsePrefix("::/0"), Via: "router"},
		},
		Peers: []latestconfig.PeerConfig{
			{
				Name:      "router",
				PublicKey: routerPublicKey.String(),
				Endpoint:  routerEndpoint,
				// Normally we wouldn't need to give the router any IPs, but
				// since its doing dual duty as the DNS server, we need to give it
				// a routable IP.
				IPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create WireGuard interface: %w", err)
	}

	logger.Info("Creating child network namespace", slog.String("name", namespaceName))

	hostNetNS, childNetNS, err := createChildNamespace(namespaceName)
	if err != nil {
		return fmt.Errorf("failed to create child network namespace: %w", err)
	}
	defer hostNetNS.Close()
	defer childNetNS.Close()
	defer netns.DeleteNamed(namespaceName)

	logger.Info("Configuring child network namespace")

	if err := os.MkdirAll(filepath.Join("/etc/netns", namespaceName), 0o755); err != nil {
		return fmt.Errorf("failed to create netns directory: %w", err)
	}
	defer os.RemoveAll(filepath.Join("/etc/netns", namespaceName))

	// Tell libc to use the router as the DNS server.
	resolvConfContent := "nameserver 100.64.0.1\n"
	if err := os.WriteFile(filepath.Join("/etc/netns", namespaceName, "resolv.conf"),
		[]byte(resolvConfContent), 0o644); err != nil {
		return fmt.Errorf("failed to write resolv.conf for namespace: %w", err)
	}

	logger.Info("Creating TUN interface", slog.String("name", nicName))

	mtu, err := wgNic.MTU()
	if err != nil {
		return fmt.Errorf("failed to get MTU of WireGuard interface: %w", err)
	}

	tunNIC, err := tun.Create(ctx, logger, nicName, &tun.Configuration{
		MTU: &mtu,
	})
	if err != nil {
		return fmt.Errorf("failed to create TUN interface: %w", err)
	}
	defer tunNIC.Close()

	logger.Info("Configuring TUN interface (and moving it into child network namespace)")

	if err := configureInterface(hostNetNS, childNetNS, nicName); err != nil {
		return fmt.Errorf("failed to configure TUN interface: %w", err)
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return network.Splice(ctx, tunNIC, wgNic, &network.SpliceConfiguration{
			PacketWriteOffset: tun.VirtioNetHdrLen,
		})
	})

	g.Go(func() error {
		sigCh := make(chan os.Signal, 1)
		defer close(sigCh)

		// Forward all signals to the child process.
		signal.Notify(sigCh)
		defer signal.Stop(sigCh)

		logger.Info("Reexecing inside child network namespace")

		cmd, err := reexecInNamespace(ctx, hostNetNS, childNetNS)
		if err != nil {
			return fmt.Errorf("failed to reexec in child network namespace: %w", err)
		}

		go func() {
			for sig := range sigCh {
				cmd.Process.Signal(sig)
			}
		}()

		if err := cmd.Wait(); err != nil {
			return fmt.Errorf("child process exited with error: %w", err)
		}

		// Abort [network.Splice] when the child process exits.
		return context.Canceled
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("failed to run child process: %w", err)
	}

	return nil
}

// The entry point for the child process, which will run in the child network
// namespace.
func childMain(logger *slog.Logger) error {
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

func createChildNamespace(namespaceName string) (netns.NsHandle, netns.NsHandle, error) {
	// Don't let the Go runtime schedule this goroutine on different OS threads.
	// Network namespaces are OS thread scoped so we don't want to be moving around.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Keep a backup of the host network namespace.
	hostNetNS, err := netns.Get()
	if err != nil {
		return -1, -1, fmt.Errorf("failed to get original network namespace: %w", err)
	}

	// Create a new child network namespace (which will be immediately entered).
	childNetNS, err := netns.NewNamed(namespaceName)
	if err != nil {
		return -1, -1, fmt.Errorf("failed to create child network namespace: %w", err)
	}

	// Switch back to the host network namespace.
	if err := netns.Set(hostNetNS); err != nil {
		return -1, -1, fmt.Errorf("failed to switch to host network namespace: %w", err)
	}

	return hostNetNS, childNetNS, nil
}

func configureInterface(hostNetNS, childNetNS netns.NsHandle, nicName string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Move the TUN interface into the child network namespace.
	link, err := netlink.LinkByName(nicName)
	if err != nil {
		return fmt.Errorf("failed to get TUN interface: %w", err)
	}

	if err := netlink.LinkSetNsFd(link, int(childNetNS)); err != nil {
		return fmt.Errorf("failed to move TUN interface to network namespace: %w", err)
	}

	// Switch to the child network namespace.
	if err := netns.Set(childNetNS); err != nil {
		return fmt.Errorf("failed to switch to child network namespace: %w", err)
	}
	defer netns.Set(hostNetNS)

	err = netlink.AddrAdd(link, &netlink.Addr{
		IPNet: &stdnet.IPNet{
			IP:   stdnet.ParseIP("100.64.0.2"),
			Mask: stdnet.CIDRMask(24, 32),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to assign IP address to TUN interface: %w", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up TUN interface: %w", err)
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

	return nil
}

func reexecInNamespace(ctx context.Context, hostNetNS, childNetNS netns.NsHandle) (*exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, os.Args[0], os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), reexecEnvName+"=1")

	// Don't let the Go runtime schedule this goroutine on different OS threads.
	// Network namespaces are OS thread scoped so we don't want to be moving around.
	runtime.LockOSThread()

	// Switch to the child network namespace.
	if err := netns.Set(childNetNS); err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("failed to switch to child network namespace: %w", err)
	}

	err := cmd.Start()

	if err := netns.Set(hostNetNS); err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("failed to switch to host network namespace: %w", err)
	}

	runtime.UnlockOSThread()

	if err != nil {
		return nil, fmt.Errorf("failed to reexec current process: %w", err)
	}

	return cmd, nil
}
