# Noisy Sockets Benchmark

## Setup

* OS: Debian 12 (Bookworm)
* CPU: Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz
* RAM: 16GB

## Reference

Using TLS and a MTU of 1500 bytes, no WireGuard encapsulation.

```
Total requests: 100000
Total errors: 0
Total duration: 12.86s
Requests per second: 7774.74
Request durations:
  Median: 0.00ms
  95th: 4.00ms
  99th: 7.00ms
  99.9th: 16.00ms
  Max: 58.00ms
```

## Noisy Sockets (golang to golang):

Golang server and client.

```
Total requests: 100000
Total errors: 0
Total duration: 38.14s
Requests per second: 2621.59
Request durations:
  Median: 1.00ms
  95th: 11.00ms
  99th: 38.00ms
  99.9th: 220.00ms
  Max: 655.00ms
```

## Noisy Sockets (golang to kmod):

Golang server and kernel module client.

```
Total requests: 100000
Total errors: 0
Total duration: 50.97s
Requests per second: 1961.95
Request durations:
  Median: 2.00ms
  95th: 19.00ms
  99th: 42.00ms
  99.9th: 86.00ms
  Max: 202.00ms
```