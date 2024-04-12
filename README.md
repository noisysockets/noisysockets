# Noisy Sockets

Noisy Sockets is a secure service-to-service communications library based on the [Noise Protocol Framework](https://noiseprotocol.org/). Endpoints are identified by Curve25519 public keys, traffic is encrypted and authenticated using ChaCha20-Poly1305, and sent/received as UDP packets. Noisy Sockets is wire compatible with [WireGuard](https://www.wireguard.com/).

Noisy Sockets implements a [drop-in replacement](./network/network.go) for the Go [net](https://pkg.go.dev/net) package, allowing it to be used with any existing code. This is implemented using a userspace TCP/IP stack based on [Netstack](https://gvisor.dev/docs/user_guide/networking/) from the [gVisor](https://github.com/google/gvisor) project.

## Usage

Examples of how to use Noisy Sockets can be found in the [examples](./examples) directory.

### gVisor Dependency

If you import Noisy Sockets using `go get -u` Go will attempt to use the gVisor master branch. Unfortunately the gVisor master branch cannot be imported as a library (due to be built with Bazel), instead you will need to explictly import gVisor's go branch. If you don't do this you will be greeted with some strange build errors.

```shell
go get -u gvisor.dev/gvisor@go
```

## Performance

Surprisingly decent, I've been able to saturate a 1Gbps link with approximately two CPU cores and a single noisy socket. Interestingly it appears to outperform the kernel implementation of WireGuard.

Some preliminary benchmark results can be found in the [benchmarks](https://github.com/noisysockets/benchmarks) respository.

## Credits

Noisy Sockets is based on code originally from the [wireguard-go](https://git.zx2c4.com/wireguard-go) project by Jason A. Donenfeld.

WireGuard is a registered trademark of Jason A. Donenfeld.
