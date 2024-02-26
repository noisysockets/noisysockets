/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 */

package noisysockets_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/dpeckett/noisysockets"
	"github.com/dpeckett/noisytransport/transport"
	"github.com/neilotoole/slogt"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestNoisySocket(t *testing.T) {
	logger := slogt.New(t)

	serverPrivateKey, err := transport.NewPrivateKey()
	require.NoError(t, err)

	clientPrivateKey, err := transport.NewPrivateKey()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		config := noisysockets.Config{
			Name:       "server",
			ListenPort: 12345,
			PrivateKey: serverPrivateKey.String(),
			IPs:        []string{"10.7.0.1"},
			Peers: []noisysockets.PeerConfig{
				{
					PublicKey: clientPrivateKey.PublicKey().String(),
					IPs:       []string{"10.7.0.2"},
				},
			},
		}

		socket, err := noisysockets.NewNoisySocket(logger, &config)
		if err != nil {
			return err
		}
		defer socket.Close()

		var mux http.ServeMux
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "Hello, world!")
		})

		srv := &http.Server{
			Handler: &mux,
		}
		defer srv.Close()

		go func() {
			lis, err := socket.Listen("tcp", ":80")
			if err != nil {
				logger.Error("Failed to listen", "error", err)
				return
			}
			defer lis.Close()

			if err := srv.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("Failed to serve", "error", err)
				return
			}
		}()

		<-ctx.Done()

		return srv.Close()
	})

	g.Go(func() error {
		defer cancel()

		config := noisysockets.Config{
			Name:       "client",
			ListenPort: 12346,
			PrivateKey: clientPrivateKey.String(),
			IPs:        []string{"10.7.0.2"},
			Peers: []noisysockets.PeerConfig{
				{
					Name:      "server",
					PublicKey: serverPrivateKey.PublicKey().String(),
					Endpoint:  "localhost:12345",
					IPs:       []string{"10.7.0.1"},
				},
			},
		}

		socket, err := noisysockets.NewNoisySocket(logger, &config)
		if err != nil {
			return err
		}
		defer socket.Close()

		client := &http.Client{
			Transport: &http.Transport{
				Dial: socket.Dial,
			},
		}

		// Wait for server to start.
		time.Sleep(time.Second)

		resp, err := client.Get("http://server")
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if string(body) != "Hello, world!" {
			return fmt.Errorf("unexpected body: %s", string(body))
		}

		return nil
	})

	require.NoError(t, g.Wait())

	// Wait for everything to close.
	time.Sleep(time.Second)
}
