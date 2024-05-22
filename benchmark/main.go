// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"
	"github.com/cheggaaa/pb/v3"
	"github.com/hashicorp/go-multierror"
	"github.com/noisysockets/network"
	"github.com/noisysockets/noisysockets"
	"github.com/noisysockets/noisysockets/benchmark/internal/synrequests"
	"github.com/noisysockets/noisysockets/config"
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
		Usage: "Benchmark Noisy Sockets",
		Commands: []*cli.Command{
			{
				Name:  "server",
				Usage: "Run a Noisy Sockets HTTP server",
				Flags: append([]cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Usage:   "The configuration file to use",
						Value:   "testdata/server.yaml",
					},
					&cli.StringFlag{
						Name:  "listen",
						Usage: "The address to listen on",
						Value: ":32000",
					},
					&cli.BoolFlag{
						Name:  "host-net",
						Usage: "Use the host networking stack",
					},
					&cli.BoolFlag{
						Name:  "tls",
						Usage: "Use TLS encryption",
					},
					&cli.StringFlag{
						Name:  "cert",
						Usage: "The path to the TLS certificate file",
						Value: "testdata/server.crt",
					},
					&cli.StringFlag{
						Name:  "key",
						Usage: "The path to the TLS key file",
						Value: "testdata/server.key",
					},
				}, sharedFlags...),
				Before: before,
				Action: func(c *cli.Context) error {
					var net network.Network = network.Host()
					if !c.Bool("host-net") {
						configFile, err := os.Open(c.String("config"))
						if err != nil {
							return fmt.Errorf("failed to open config file: %w", err)
						}
						defer configFile.Close()

						conf, err := config.FromYAML(configFile)
						if err != nil {
							return fmt.Errorf("failed to read config: %w", err)
						}

						net, err = noisysockets.OpenNetwork(logger, conf)
						if err != nil {
							return fmt.Errorf("failed to open network: %w", err)
						}
					}
					defer net.Close()

					randBuf := make([]byte, maxMessageSize)
					if _, err := rand.Read(randBuf); err != nil {
						return fmt.Errorf("failed to read random data: %w", err)
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

					srv := &http.Server{
						Handler: &mux,
					}

					lis, err := net.Listen("tcp", c.String("listen"))
					if err != nil {
						logger.Error("Failed to listen", "error", err)
						return err
					}
					defer lis.Close()

					if c.Bool("tls") {
						cer, err := tls.LoadX509KeyPair(c.String("cert"), c.String("key"))
						if err != nil {
							logger.Error("Failed to load key pair", "error", err)
							return err
						}

						tlsConfig := &tls.Config{
							Certificates: []tls.Certificate{cer},
						}

						lis = tls.NewListener(lis, tlsConfig)
					}

					go func() {
						scheme := "HTTP"
						if c.Bool("tls") {
							scheme = "HTTPS"
						}

						logger.Info("Listening for "+scheme+" connections", "addr", lis.Addr())

						if err := srv.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
				Name:  "benchmark",
				Usage: "Run a benchmark against a Noisy Sockets HTTP server",
				Flags: append([]cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Usage:   "The configuration file to use",
						Value:   "testdata/client.yaml",
					},
					&cli.BoolFlag{
						Name:  "host-net",
						Usage: "Use the host networking stack",
					},
					&cli.StringFlag{
						Name:  "server-address",
						Usage: "The address of the server to connect to",
						Value: "server:32000",
					},
					&cli.BoolFlag{
						Name:  "tls",
						Usage: "Use TLS encryption",
					},
				}, sharedFlags...),
				Before: before,
				Action: func(c *cli.Context) error {
					var net network.Network = network.Host()
					if !c.Bool("host-net") {
						configFile, err := os.Open(c.String("config"))
						if err != nil {
							return fmt.Errorf("failed to open config file: %w", err)
						}
						defer configFile.Close()

						conf, err := config.FromYAML(configFile)
						if err != nil {
							return fmt.Errorf("failed to read config: %w", err)
						}

						net, err = noisysockets.OpenNetwork(logger, conf)
						if err != nil {
							return fmt.Errorf("failed to open network: %w", err)
						}
					}
					defer net.Close()

					transport := http.DefaultTransport.(*http.Transport).Clone()
					transport.DialContext = net.DialContext
					transport.TLSClientConfig = &tls.Config{
						InsecureSkipVerify: true,
					}

					client := &http.Client{
						Timeout:   30 * time.Second,
						Transport: transport,
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

					serverAddress := c.String("server-address")
					scheme := "http"
					if c.Bool("tls") {
						scheme = "https"
					}

					for i := 0; i < nRequests; i++ {
						work.Add(fmt.Sprintf("%s://%s/?id=%d", scheme, serverAddress, i))
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
