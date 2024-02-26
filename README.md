# Noisy Sockets

Userspace TCP/IP sockets for [Noisy Transport](https://github.com/dpeckett/noisytransport). Based on [Netstack](https://gvisor.dev/docs/user_guide/networking/) from the [gVisor](https://github.com/google/gvisor) project. Noisy Sockets are compatible with WireGuard and be accessed like any other peer.

## Usage

An example of how to use Noisy Sockets can be found in the [examples](./examples) directory.

## Performance

Surprisingly good, I've been able to saturate a 1Gbps link with approximately two CPU cores and a single noisy socket. Interestingly it appears to outperform the kernel implementation of WireGuard.

Some preliminary benchmark results can be found in the [benchmarks](./benchmarks) directory.