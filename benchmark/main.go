// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package main

import (
	"context"
	"crypto/rand"
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
	"github.com/noisysockets/noisysockets"
	"github.com/noisysockets/noisysockets/benchmark/synrequests"
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
						Value:   "server.yaml",
					},
				}, sharedFlags...),
				Before: before,
				Action: func(c *cli.Context) error {
					conf, err := config.FromYAML(c.String("config"))
					if err != nil {
						return fmt.Errorf("failed to read config: %w", err)
					}

					net, err := noisysockets.NewNetwork(logger, conf)
					if err != nil {
						return fmt.Errorf("failed to create noisy socket: %w", err)
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

					go func() {
						lis, err := net.Listen("tcp", ":80")
						if err != nil {
							logger.Error("Failed to listen", "error", err)
							return
						}
						defer lis.Close()

						logger.Info("Listening for HTTP connections", "addr", lis.Addr())

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

					if err := net.Close(); err != nil {
						logger.Error("Failed to close", "error", err)
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
						Value:   "client.yaml",
					},
				}, sharedFlags...),
				Before: before,
				Action: func(c *cli.Context) error {
					conf, err := config.FromYAML(c.String("config"))
					if err != nil {
						return fmt.Errorf("failed to read config: %w", err)
					}

					net, err := noisysockets.NewNetwork(logger, conf)
					if err != nil {
						return fmt.Errorf("failed to create noisy socket: %w", err)
					}
					defer net.Close()

					transport := http.DefaultTransport.(*http.Transport).Clone()
					transport.DialContext = net.DialContext

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

					for i := 0; i < nRequests; i++ {
						work.Add(fmt.Sprintf("http://server/?id=%d", i))
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
