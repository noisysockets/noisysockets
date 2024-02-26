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
	"sort"
	"sync"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"
	"github.com/cheggaaa/pb/v3"
	"github.com/hashicorp/go-multierror"
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
			contentLengths[i] = min(int64(W4.sample()), int64(len(randBuf)))
		}

		var mux http.ServeMux
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			contentLength := contentLengths[Intn(int64(len(contentLengths)))]
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

var (
	W4 = probabilityDistribution{
		x: []float64{
			1.5934111171586087, 1.736181363764721, 5.649626539162342, 9.253508158569039, 10.028695764386981, 18.188043514032934,
			31.770429929625713, 53.1648008121424, 74.53229661479826, 104.48918311295222, 117.57287071403809, 128.79465782977246,
			174.83904941223136, 236.03720589446408, 265.5391146268609, 286.2205299827987, 308.3445905489566, 318.6333132498274,
			325.02736605469045, 335.577801747673, 363.43395901804354, 427.1262120202026, 457.25365357070217, 492.5203329768491,
			516.0241702112453, 534.3288692463366, 559.1076382376215, 586.0296939056761, 606.5871975873118, 635.1213508326852,
			662.5460176168092, 737.0239534084533, 793.5839681328611, 999.6624530656259, 1313.5425934961268, 1477.7444992552446,
			1584.2863626662559, 1931.3614535673369, 2664.1310157658236, 2997.6496617612174, 3301.367900912229, 4457.32019024675,
			6148.283163871896, 6917.81057013705, 7577.7368912378815, 10342.101892829543, 14498.556094393402, 16313.91356541361,
			17870.971779626998, 24259.906944445196, 33465.104600521314, 37650.16911954778, 40799.539223455075, 45881.13091867419,
			51315.4754377652, 57737.618871569895, 63245.36341832039, 76675.84590567283, 94465.0200344501, 106279.98596986844,
			115792.5915766972, 150550.34337895186, 202139.68183040826, 227424.0228086452, 249113.90724573165, 330952.40544894064,
			461456.1203848952, 519231.4057146571, 568787.561643597, 772114.0133361015, 1076605.8292008336, 1211399.1632189886,
			1334152.3585694425, 1811046.5849060207, 2511683.5486738207, 2826188.899411652, 3112601.8356925235, 4225378.858802729,
			5923660.775807548, 6665447.421250863, 7301689.697882272, 9701985.861074444,
		},
		y: []float64{
			0.002922073317044749, 0.0028996905859436595, 0.00259192803330194, 0.0024632273294699303, 0.0024422435190625436, 0.0022869633220479102,
			0.0021414755698900478, 0.0023276591967774607, 0.004856780636605862, 0.00650992337288244, 0.007376491155403215, 0.008121861535995407,
			0.011265236335021882, 0.023731400161529166, 0.03639163244065273, 0.04128607442452349, 0.07799655127190036, 0.11866702287332458,
			0.13287621009068687, 0.14656604800046608, 0.18763975849188554, 0.2256162585671747, 0.24457163396851428, 0.2904982003468156,
			0.3346693544078144, 0.3556943397142898, 0.4019642012308557, 0.4458849696834279, 0.4653674838371228, 0.4744506759021337,
			0.51130384266028074, 0.5540828374774738, 0.5727745701326695, 0.6067941692208302, 0.6334107973892112, 0.6451095896278508,
			0.6511805239152292, 0.6713739441306046, 0.6793752618008541, 0.6816519416427514, 0.6833207268558772, 0.6906958367537268,
			0.7003087110632634, 0.7039955029645373, 0.7074115401242513, 0.7106206641958877, 0.713737332327123, 0.7149243801231384,
			0.715765894507779, 0.7188589081618278, 0.7253768611981879, 0.7344477173261714, 0.7411087417971274, 0.7765070310336955,
			0.8166658473913529, 0.8209295033169168, 0.8244844151491452, 0.854193293923924, 0.8845763252985181, 0.8928780293941145,
			0.897957688477848, 0.9153569044993758, 0.9336034086327713, 0.9413282487040775, 0.9459834752493042, 0.9566866174777654,
			0.9627439440820311, 0.9643155678942401, 0.965274591617162, 0.9696602079923059, 0.9743165791090094, 0.9758882029212184,
			0.976870245248284, 0.9822169201400862, 0.9883248622385469, 0.9891273340183687, 0.9895416688929582, 0.9924835991120739,
			0.9944465391947286, 0.9948644349583569, 0.9951611333200565, 0.9964971025826601,
		},
	}
)

type probabilityDistribution struct {
	x []float64
	y []float64
}

func (p *probabilityDistribution) sample() float64 {
	r := Float64()

	i := sort.Search(len(p.y), func(i int) bool { return p.y[i] >= r })

	if i == 0 {
		return p.x[0]
	} else if i < len(p.y) {
		return p.x[i-1] + (p.x[i]-p.x[i-1])*(r-p.y[i-1])/(p.y[i]-p.y[i-1])
	} else {
		return p.x[len(p.x)-1]
	}
}

func Float64() float64 {
	return float64(Intn(1<<53)) / (1 << 53)
}

func Intn(max int64) int64 {
	nBig, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		panic(err)
	}
	return nBig.Int64()
}
