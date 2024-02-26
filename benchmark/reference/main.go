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
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"
	"github.com/cheggaaa/pb/v3"
	"github.com/dpeckett/noisysockets/benchmark/synrequests"
	"github.com/hashicorp/go-multierror"
	"github.com/rogpeppe/go-internal/par"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
)

const (
	maxMessageSize = 1000000
	nRequests      = 100000
	nConcurrent    = 10
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	sharedFlags := []cli.Flag{
		&cli.GenericFlag{
			Name:    "log-level",
			Aliases: []string{"l"},
			Usage:   "Set the log level",
			Value:   fromLogLevel(slog.LevelInfo),
		},
	}

	before := func(c *cli.Context) error {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: (*slog.Level)(c.Generic("log-level").(*logLevelFlag)),
		}))

		return nil
	}

	app := &cli.App{
		Name:  "noisysockets-benchmark",
		Usage: "Benchmark Go HTTP server",
		Commands: []*cli.Command{
			{
				Name:   "server",
				Usage:  "Run a HTTP server",
				Flags:  sharedFlags,
				Before: before,
				Action: func(c *cli.Context) error {
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

					go func() {
						lis, err := net.Listen("tcp", ":8443")
						if err != nil {
							logger.Error("Failed to listen", "error", err)
							return
						}
						defer lis.Close()

						logger.Info("Listening for HTTPS connections", "addr", lis.Addr())

						if err := srv.Serve(tls.NewListener(lis, srv.TLSConfig)); err != nil && !errors.Is(err, http.ErrServerClosed) {
							logger.Error("Failed to serve", "error", err)
							return
						}
					}()

					term := make(chan os.Signal, 1)

					signal.Notify(term, unix.SIGTERM)
					signal.Notify(term, os.Interrupt)

					<-term

					logger.Info("Received signal, shutting down")

					if err := srv.Close(); err != nil {
						logger.Error("Failed to close server", "error", err)
					}

					return nil
				},
			},
			{
				Name:   "benchmark",
				Usage:  "Run a benchmark against a HTTP server",
				Flags:  sharedFlags,
				Before: before,
				Action: func(c *cli.Context) error {
					t := http.DefaultTransport.(*http.Transport).Clone()
					t.TLSClientConfig = &tls.Config{
						InsecureSkipVerify: true,
					}

					client := &http.Client{
						Timeout:   30 * time.Second,
						Transport: t,
					}

					ctx := context.Background()
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
						work.Add(fmt.Sprintf("https://localhost:8443/?id=%d", i))
					}

					var errsMu sync.Mutex
					var errs *multierror.Error

					var requestDurationsMu sync.Mutex
					requestDurations := hdrhistogram.New(1, time.Minute.Milliseconds(), 2)

					bar := pb.StartNew(nRequests)

					startTime := time.Now()
					work.Do(nConcurrent, func(item any) {
						defer bar.Increment()

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
					})
					totalDuration := time.Since(startTime)

					bar.Finish()

					var nErrors int
					if errs != nil {
						nErrors = len(errs.Errors)
						fmt.Println("Errors:")
						for _, err := range errs.Errors {
							fmt.Println(err)
						}
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
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		logger.Error("Failed to run app", "error", err)
		os.Exit(1)
	}
}

type logLevelFlag slog.Level

func fromLogLevel(l slog.Level) *logLevelFlag {
	f := logLevelFlag(l)
	return &f
}

func (f *logLevelFlag) Set(value string) error {
	return (*slog.Level)(f).UnmarshalText([]byte(value))
}

func (f *logLevelFlag) String() string {
	return (*slog.Level)(f).String()
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
