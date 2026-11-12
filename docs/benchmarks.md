# M3 measurements

These figures are one run of `scripts/bench.sh` on the build VM on 12 Nov 2026. They describe that run. They are not a claim about any other machine. Nothing in this file was estimated. A quantity that was not measured is not given a number.

## Machine

| | |
|---|---|
| Go | go1.27.3 linux/amd64 |
| GOMAXPROCS | 4 |
| Kernel | Linux 6.12.113+ |
| CPU | `Intel(R) Xeon(R) Processor`, as reported by `/proc/cpuinfo`. No more specific model string is present. |
| cpu MHz | 2700.000 |
| bogomips | 5400.00 |
| Processors | 4 |
| MemTotal | 16387328 kB |

This is a 4-vCPU cloud VM. It is not a named production machine. The cluster figure below is loopback TCP inside one process. It is not a measurement of a network interface.

## Method

`scripts/bench.sh` sets `SILVERGREY_BENCH=1` and runs:

```
go test -count=1 -timeout 10m -v ./internal/node/ -run '^TestBenchmarkM3$'
```

CPU is `getrusage(RUSAGE_SELF)` user time plus system time, sampled before and after the loop. Wall time is `time.Since`. The sign and verify loops use one ML-DSA-65 key, `SignDigest` / `VerifyDigest`, a 32-byte digest whose first byte is 1, and `crypto.ContextEvent`. The hash loop is SHA3-256 of a 1 MiB buffer of zeros, 64 times.

The cluster is four validators in one process, each with its own data directory, speaking TLS on `127.0.0.1`. A shared `p2p.Meter` wraps the TCP connection underneath TLS, so the counts are ciphertext, including a handshake when one happens. The test waits until some node reports commit height at least 1, then resets the meter, so the handshake is not in the window. It then submits one shipment event and waits until the proof is available. The subject is the five bytes `bench`. The document preimage is 32 bytes whose first byte is the nonce (1); the event stores the SHA3-256 of that preimage. The proof is checked with `pkg/verify`.

## Figures

Recorded from the log of that single run:

| Measurement | n | Payload | Wall | CPU (user+sys) |
|---|---|---|---|---|
| ML-DSA-65 sign | 32 | 32-byte digest | 15.112705 ms (472.272 µs/op) | 15.187 ms (474.593 µs/op) |
| ML-DSA-65 verify | 128 | 32-byte digest | 18.24411 ms (142.532 µs/op) | 18.304 ms (143 µs/op) |
| SHA3-256 | 64 | 1 MiB | 130.284158 ms (2.035689 ms/op) | 130.648 ms (2.041375 ms/op) |

Sign CPU sits slightly above wall. That is the rusage sample, not a correction.

Cluster, n=4, one event:

| | |
|---|---|
| Wall, from meter reset until the proof returned | 203.993884 ms |
| Ciphertext sent | 494868 bytes |
| Ciphertext received | 494868 bytes |
| Commit height at reset | 36 |
| Commit height of the event | 41 |
| Event id | `485d9f854c9a7db5805cb143b59b2a5c9ba5b9cc942e002cdf765da03ac77f03` |

The byte counts are every node's sends and every node's receives on the shared meter. They match on this run. The window includes the empty blocks committed while the event was in flight: height moved from 36 to 41. It is not a throughput run and it is not a count of payload bytes alone.

No NIC counter, no multi-host bandwidth, and no events-per-second figure was taken.
