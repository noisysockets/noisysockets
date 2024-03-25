/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 */

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"
	"github.com/cheggaaa/pb/v3"
	"github.com/hashicorp/go-multierror"
	"github.com/noisysockets/noisysockets/benchmark/synrequests"
	"github.com/rogpeppe/go-internal/par"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const (
	maxMessageSize = 1000000
	nRequests      = 100000
	nConcurrent    = 10
)

func main() {
	epA, epB := pipe.New(
		tcpip.LinkAddress("a9:6a:6d:50:6b:2a"),
		tcpip.LinkAddress("7e:bd:32:8f:5c:0a"),
		1500)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		defer cancel()

		s := stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, icmp.NewProtocol6},
			HandleLocal:        true,
		})
		defer s.Close()

		if err := s.CreateNIC(1, epA); err != nil {
			return fmt.Errorf("could not create NIC: %v", err)
		}
		defer s.RemoveNIC(1)

		addr, err := netip.ParseAddr("10.7.0.1")
		if err != nil {
			return fmt.Errorf("could not parse address: %v", err)
		}

		protoAddr := tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix(),
		}

		if err := s.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); err != nil {
			return fmt.Errorf("could not add protocol address: %v", err)
		}

		s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})

		randBuf := make([]byte, maxMessageSize)
		if _, err := rand.Read(randBuf); err != nil {
			return fmt.Errorf("failed to read random data: %v", err)
		}

		contentLengths := make([]int64, 1000)
		for i := range contentLengths {
			// The size of the requests are sampled from a realistic distribution.
			contentLengths[i] = min(int64(synrequests.W4.Sample()), int64(len(randBuf)))
		}

		var mux http.ServeMux
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			contentLength := contentLengths[synrequests.Intn(int64(len(contentLengths)))]
			w.Header().Set("Content-Length", fmt.Sprintf("%d", contentLength))
			if _, err := w.Write(randBuf[:contentLength]); err != nil {
				logger.Error("Failed to write response", "error", err)
			}
		})

		cert, err := generateSelfSignedCertificate()
		if err != nil {
			return fmt.Errorf("failed to generate self-signed certificate: %v", err)
		}

		srv := &http.Server{
			Handler: &mux,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
				},
			},
		}

		lis, err := gonet.ListenTCP(s, tcpip.FullAddress{
			NIC:  1,
			Addr: tcpip.AddrFrom4(addr.As4()),
			Port: 443,
		}, header.IPv4ProtocolNumber)
		if err != nil {
			return fmt.Errorf("failed to listen: %v", err)
		}
		defer lis.Close()

		logger.Info("Listening for HTTPS connections", "addr", lis.Addr())

		go func() {
			<-ctx.Done()

			if err := srv.Close(); err != nil {
				logger.Error("Failed to close server", "error", err)
			}
		}()

		if err := srv.Serve(tls.NewListener(lis, srv.TLSConfig)); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("failed to serve: %v", err)
		}

		return nil
	})

	g.Go(func() error {
		defer cancel()

		s := stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, icmp.NewProtocol6},
			HandleLocal:        true,
		})
		defer s.Close()

		if err := s.CreateNIC(1, epB); err != nil {
			return fmt.Errorf("could not create NIC: %v", err)
		}
		defer s.RemoveNIC(1)

		addr, err := netip.ParseAddr("10.7.0.2")
		if err != nil {
			return fmt.Errorf("could not parse address: %v", err)
		}

		protoAddr := tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix(),
		}

		if err := s.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); err != nil {
			return fmt.Errorf("could not add protocol address: %v", err)
		}

		s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})

		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
		t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			addrPort, err := netip.ParseAddrPort(addr)
			if err != nil {
				return nil, fmt.Errorf("could not parse address: %v", err)
			}

			return gonet.DialContextTCP(ctx, s, tcpip.FullAddress{
				NIC:  1,
				Addr: tcpip.AddrFrom4(addrPort.Addr().As4()),
				Port: 443,
			}, header.IPv4ProtocolNumber)
		}

		client := &http.Client{
			Timeout:   30 * time.Second,
			Transport: t,
		}

		doRequest := func(url string) error {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return err
			}

			res, err := client.Do(req)
			if err != nil {
				return err
			}
			defer res.Body.Close()

			if res.StatusCode != http.StatusOK {
				return fmt.Errorf("unexpected status code: %d", res.StatusCode)
			}

			if _, err = io.Copy(io.Discard, res.Body); err != nil {
				return err
			}

			return nil
		}

		var work par.Work

		for i := 0; i < nRequests; i++ {
			work.Add(fmt.Sprintf("https://10.7.0.1/?id=%d", i))
		}

		var errsMu sync.Mutex
		var errs *multierror.Error

		var requestDurationsMu sync.Mutex
		requestDurations := hdrhistogram.New(1, time.Minute.Milliseconds(), 2)

		bar := pb.StartNew(nRequests)

		startTime := time.Now()
		work.Do(nConcurrent, func(item any) {
			defer bar.Increment()

			select {
			case <-ctx.Done():
				return
			default:
				requestStartTime := time.Now()
				err := doRequest(item.(string))
				requestDuration := time.Since(requestStartTime)
				if err != nil {
					errsMu.Lock()
					errs = multierror.Append(errs, err)
					errsMu.Unlock()
					return
				}

				requestDurationsMu.Lock()
				if err := requestDurations.RecordValue(requestDuration.Milliseconds()); err != nil {
					logger.Error("Failed to record request duration", "error", err)
				}
				requestDurationsMu.Unlock()
			}
		})
		totalDuration := time.Since(startTime)

		bar.Finish()

		var nErrors int
		if errs != nil {
			nErrors = len(errs.Errors)
		}

		reqPerSec := float64(nRequests) / totalDuration.Seconds()

		fmt.Printf("Total requests: %d\n", nRequests)
		fmt.Printf("Total errors: %d\n", nErrors)
		fmt.Printf("Total duration: %.2fs\n", totalDuration.Seconds())
		fmt.Printf("Requests per second: %.2f\n", reqPerSec)

		fmt.Println("Request durations:")
		fmt.Printf("  Median: %.2fms\n", float64(requestDurations.ValueAtQuantile(50)))
		fmt.Printf("  95th: %.2fms\n", float64(requestDurations.ValueAtQuantile(95)))
		fmt.Printf("  99th: %.2fms\n", float64(requestDurations.ValueAtQuantile(99)))
		fmt.Printf("  99.9th: %.2fms\n", float64(requestDurations.ValueAtQuantile(99.9)))
		fmt.Printf("  Max: %.2fms\n", float64(requestDurations.Max()))

		return nil
	})

	g.Go(func() error {
		term := make(chan os.Signal, 1)

		signal.Notify(term, unix.SIGTERM)
		signal.Notify(term, os.Interrupt)

		select {
		case <-ctx.Done():
			return nil
		case <-term:
			logger.Info("Received signal, shutting down")

			cancel()
		}

		return nil
	})

	if err := g.Wait(); err != nil {
		logger.Error("Failed to run", "error", err)
		os.Exit(1)
	}
}

func generateSelfSignedCertificate() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Example Co"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	return cert, nil
}
