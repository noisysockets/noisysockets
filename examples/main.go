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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"

	"github.com/noisysockets/noisysockets"
	"github.com/noisysockets/noisysockets/config"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
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
		Name:  "noisysockets",
		Usage: "An example of using Noisy Sockets to create a simple HTTP server and client",
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

					var mux http.ServeMux
					mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
						fmt.Fprint(w, "Hello, world!")
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
				Name:  "client",
				Usage: "Run a Noisy Sockets HTTP client",
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

					client := &http.Client{
						Transport: &http.Transport{
							Dial: net.Dial,
						},
					}

					// Peers can be resolved by name.
					url := "http://server/"

					logger.Info("Getting", "url", url)

					resp, err := client.Get(url)
					if err != nil {
						return fmt.Errorf("failed to make request: %w", err)
					}
					defer resp.Body.Close()

					if resp.StatusCode != http.StatusOK {
						return fmt.Errorf("unexpected status code: %v", resp.StatusCode)
					}

					body, err := io.ReadAll(resp.Body)
					if err != nil {
						return fmt.Errorf("failed to read body: %w", err)
					}

					logger.Info("Got", "status", resp.Status, "body", string(body))

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
