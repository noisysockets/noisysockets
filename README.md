# Noisy Sockets

Noisy Sockets is a secure service-to-service communications library based on the [Noise Protocol Framework](https://noiseprotocol.org/). Endpoints are identified by Curve25519 public keys, traffic is encrypted and authenticated using ChaCha20-Poly1305, and sent/received as UDP packets. Noisy Sockets is wire compatible with [WireGuard](https://www.wireguard.com/).

Noisy Sockets implements a drop-in replacement for the Go `net` package, allowing it to be used with any existing code. This is implemented using a userspace TCP/IP stack based on [Netstack](https://gvisor.dev/docs/user_guide/networking/) from the [gVisor](https://github.com/google/gvisor) project.

## Usage

An example of how to use Noisy Sockets can be found in the [examples](./examples) directory.

### gVisor Dependency

When you import Noisy Sockets Go Modules will attempt to use the gVisor master branch. The master branch cannot be used as a library, so you will need to explictly import the synthetic go branch in your project. If you don't do this you will see some strange build errors.

```shell
go get -u gvisor.dev/gvisor@go
```

## Performance

Surprisingly good, I've been able to saturate a 1Gbps link with approximately two CPU cores and a single noisy socket. Interestingly it appears to outperform the kernel implementation of WireGuard.

Some preliminary benchmark results can be found in the [benchmark](./benchmark) directory.

## Credits

Noisy Sockets is based on code originally from the [wireguard-go](https://git.zx2c4.com/wireguard-go) project by Jason A. Donenfeld.

WireGuard is a registered trademark of Jason A. Donenfeld.