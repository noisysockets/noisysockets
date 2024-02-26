/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
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

	"github.com/dpeckett/noisysockets"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
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
				Usage: "Run a Noisy Socket HTTP server",
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
					f, err := os.Open(c.String("config"))
					if err != nil {
						return fmt.Errorf("failed to open config: %v", err)
					}
					defer f.Close()

					var config noisysockets.Config
					if err := yaml.NewDecoder(f).Decode(&config); err != nil {
						return fmt.Errorf("failed to decode config: %v", err)
					}

					socket, err := noisysockets.NewNoisySocket(logger, &config)
					if err != nil {
						return fmt.Errorf("failed to create noisy socket: %v", err)
					}
					defer socket.Close()

					var mux http.ServeMux
					mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
						fmt.Fprint(w, "Hello, world!")
					})

					srv := &http.Server{
						Handler: &mux,
					}

					go func() {
						lis, err := socket.Listen("tcp", ":80")
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

					if err := socket.Close(); err != nil {
						logger.Error("Failed to close", "error", err)
					}

					return nil
				},
			},
			{
				Name:  "client",
				Usage: "Run a Noisy Socket HTTP client",
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
					f, err := os.Open(c.String("config"))
					if err != nil {
						return fmt.Errorf("failed to open config: %v", err)
					}
					defer f.Close()

					var config noisysockets.Config
					if err := yaml.NewDecoder(f).Decode(&config); err != nil {
						return fmt.Errorf("failed to decode config: %v", err)
					}

					socket, err := noisysockets.NewNoisySocket(logger, &config)
					if err != nil {
						return fmt.Errorf("failed to create noisy socket: %v", err)
					}
					defer socket.Close()

					client := &http.Client{
						Transport: &http.Transport{
							Dial: socket.Dial,
						},
					}

					// Peers can be resolved by name.
					url := "http://server/"

					logger.Info("Getting", "url", url)

					resp, err := client.Get(url)
					if err != nil {
						return fmt.Errorf("failed to make request: %v", err)
					}
					defer resp.Body.Close()

					if resp.StatusCode != http.StatusOK {
						return fmt.Errorf("unexpected status code: %v", resp.StatusCode)
					}

					body, err := io.ReadAll(resp.Body)
					if err != nil {
						return fmt.Errorf("failed to read body: %v", err)
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
