# Benchmarks

These benchmarks catch regressions in the allocation and ARC (retain and release) cost of `swift-tls`.
They count allocations, retains and releases for a TLS handshake and for record protection, and
compare the counts with numbers checked in under `Thresholds/`. They are built on
[package-benchmark](https://github.com/ordo-one/package-benchmark) and live in a separate SwiftPM
package, so the benchmark dependency does not become a dependency of the library.

## Requirements

* Swift tools version 6.3 or later.
* macOS 26 or later. The package declares that platform because the library's `SwiftTLS 0.1.0`
  availability is macOS 26; an older macOS fails to build instead of running no benchmarks.
* On Linux, a Swift 6.3 or later toolchain. The package uses swift-crypto there in place of CryptoKit.
* Network access the first time, to fetch the package dependencies.

Do not clone or check out the repository into a directory named `benchmarks`, in any letter case.
SwiftPM names a path dependency after its directory, so the package's own `../` dependency would be
called `benchmarks` and the build fails with `product 'SwiftTLS' required by package 'benchmarks' ...
not found in package 'swift-tls'`.

## Quick start

Run every command from the repository root.

```sh
export SWIFT_DETERMINISTIC_HASHING=1

# List the scenarios.
swift package --package-path Benchmarks benchmark list

# Run everything and print the numbers.
swift package --package-path Benchmarks benchmark

# Run one target, or one scenario. `--filter` takes a regular expression that must match the whole name.
swift package --package-path Benchmarks benchmark --target HandshakeBenchmarks
swift package --package-path Benchmarks benchmark --filter TLSHandshake_mutual_authentication
```

Swift seeds its hash functions randomly for each process, which changes how many retains and releases
collection code performs. Set `SWIFT_DETERMINISTIC_HASHING=1` for every command in this document, as
CI does. Counts recorded or checked without it vary from run to run.

Running a benchmark needs no extra flags on macOS. Commands that write files need
`--allow-writing-to-package-directory`, because SwiftPM runs the plugin in a sandbox that cannot write
to the package directory. CI passes `--disable-sandbox`; local runs on macOS never need it.

For throughput rather than counts, run one scenario with another metric:

```sh
swift package --package-path Benchmarks benchmark --target RecordBenchmarks --metric instructions
swift package --package-path Benchmarks benchmark --target RecordBenchmarks --metric wallClock
```

## Scenarios

Each scenario wires a client to a server in memory, with no socket, and drives the public
`SwiftTLSHandshakeAndRecordManager` or `SwiftTLSHandshaker` entry points, so it runs the code a
connection runs. "TCP" below means the non-QUIC path, where `SwiftTLSHandshakeAndRecordManager` turns
a byte stream into records. "Raw public key" means the server proves its identity with a bare public
key and no X.509 certificate.

Handshake scenarios build both peers and run the complete handshake inside the measurement, so the
counts include ephemeral key generation, key agreement, signing, verification and the key schedule.
Signing keys are generated once, outside the measurement.

| Scenario | What it measures |
| --- | --- |
| `TLSHandshake_AES256GCM_P384` | A TLS 1.3 handshake over TCP with a raw public key server, P-384 key exchange and `TLS_AES_256_GCM_SHA384`. |
| `TLSHandshake_AES128GCM_X25519` | The same handshake with X25519 and `TLS_AES_128_GCM_SHA256`. |
| `TLSHandshake_AES256GCM_X25519MLKEM768` | The same handshake with the hybrid post-quantum key exchange. |
| `TLSHandshake_mutual_authentication` | A handshake in which the client also signs and the server verifies. |
| `TLSHandshake_external_pre_shared_key` | A handshake authenticated by an external pre-shared key, with no signatures. |
| `QUICTLSHandshake_AES256GCM_P384` | The handshake as QUIC drives it through `SwiftTLSHandshaker`, with P-384 and AES-256-GCM. |
| `QUICTLSHandshake_ChaCha20Poly1305_X25519` | The QUIC handshake with X25519 and ChaCha20-Poly1305. |
| `QUICTLSHandshake_mutual_authentication` | The QUIC handshake with mutual authentication. |
| `RecordTransfer_AES128GCM_1_record_1024_bytes` | 1000 writes of 1024 bytes on one established connection. |
| `RecordTransfer_AES256GCM_1_record_1024_bytes` | The same with AES-256-GCM. |
| `RecordTransfer_AES256GCM_4_records_65536_bytes` | 1000 writes of 64 KiB, each spanning four records. |

Each record scenario finishes the handshake before `benchmark.startMeasurement()`. One measurement
then protects a write on the client, delivers it to the server, unprotects it there and consumes the
received data, a thousand times. Looping makes the gated count a thousand times the per-write cost, so
one extra allocation per record moves it by about 1000 instead of 1.

The counts do not depend on the payload size up to one record, or on the cipher suite, so one size per
cipher suite gates the single-record path. A write that spans several records costs proportionally
more, which the four-record scenario gates. ChaCha20-Poly1305 appears only in the QUIC scenarios
because the TLS record layer does not support that cipher suite yet.

## Threshold files

CI compares every run with the numbers in `Thresholds/`, so a change that adds allocations or ARC
traffic shows up as a diff in a pull request. There is one JSON file per scenario, holding the `p90`
of each gated metric, for example
`Thresholds/latest-beta/HandshakeBenchmarks.TLSHandshake_AES256GCM_P384.p90.json`.

The check is two-sided. It fails when a scenario gets worse, and it also fails when a scenario gets
better, with `is BETTER than the defined absolute baseline thresholds`. A count that drifts below its
threshold leaves room for a later regression to hide under the old number, so after an improvement
record the new numbers rather than widening a tolerance.

```sh
# Check against the recorded numbers, as CI does.
swift package --package-path Benchmarks benchmark thresholds check \
    --format metricP90AbsoluteThresholds --path Benchmarks/Thresholds/latest-beta/

# Overwrite the recorded numbers with what this machine measures.
swift package --package-path Benchmarks --allow-writing-to-package-directory \
    benchmark thresholds update \
    --format metricP90AbsoluteThresholds --path Benchmarks/Thresholds/latest-beta/
```

`--path` is resolved against the directory you run the command from, which is why it repeats
`Benchmarks/`.

`thresholds update` records whatever this machine measures, on whatever toolchain it uses. An
allocation count belongs to a toolchain, standard library and platform, not to the source alone, so
a local run on a different toolchain from CI's will not match the numbers in `Thresholds/`. Take new
numbers from the failing CI job.

### Gated metrics

| Metric | Why |
| --- | --- |
| `mallocCountTotal` | The headline number. |
| `objectAllocCount`, `retainCount`, `releaseCount` | Allocation and ARC traffic move independently. Code can allocate nothing and still perform thousands of retain and release pairs. |
| `mallocFreeDelta` | Allocations in the measured region that were never freed, so a leak fails the check. It must stay at 0. |

Each metric has an allowance, in absolute counts, within which the `p90` may differ from the recorded
one. The allowances are the `Tolerance` values at the top of each target's `Benchmarks.swift`. They
are narrow because the counts do not move between runs with a fixed hash seed. The table of metrics
and the thresholds built from it are in `TLSBenchmarkSupport.swift`.

`syscalls` is not gated. The harness has no socket and makes no deliberate system calls, but the
allocator makes some as it grows the heap, and the count in the record scenarios varied from 302 to
314 across repeated runs of the four-record scenario, with no change to the code. That spread is too
wide to separate a real change from noise.

### Baselines per toolchain

`Thresholds/` has one directory per toolchain, because the same source allocates differently under
different compilers, standard libraries and crypto implementations. A directory is named for the
Swift version the job runs, such as `6.3`, or for a nightly toolchain, such as `nightly-main`.

| Directory | Used by |
| --- | --- |
| `latest-beta/` | The `benchmarks-macos` job in `.github/workflows/pull_request.yml`, which runs the latest beta Xcode on Apple silicon |
| `6.3/`, `6.4/`, `nightly-main/` | The `benchmarks-linux` job in the same file, one directory per toolchain in its matrix |

CI recorded these numbers. A toolchain with no directory fails its check until one is recorded. To
record one, open the failed job: it runs `thresholds update` after a failing check and prints the
recalculated numbers as a diff in the log. Apply that diff to `Thresholds/<toolchain>/` and commit it.
The same applies when a count moves for a reason a reviewer accepts.

## How the package is wired

The `swift-tls` library is a path dependency. The scenarios use only the `SwiftTLS` product, through
its `SwiftTLSOptions` and `SwiftTLSProtocol` SPI groups (SPI, or system programming interface, groups
are the parts of the library meant for embedding stacks), which is how such a stack uses it.

`TLSBenchmarkSupport` holds what the targets share:

* `gatedConfiguration(tolerance:)`, which gates the metrics in `gatedMetrics`.
* `HandshakeScenario`, which builds the client and server `SwiftTLSOptions` for a cipher suite, key
  exchange group, `Authentication` and `Transport`.
* `completeHandshake` and `completeQUICHandshake`, which run a handshake in memory.
* `deliver`, which moves one peer's output to the other.
* `ConnectedPair`, a client and a server that have finished a TCP handshake.

## Adding a scenario

1. Add a `Benchmark(...)` to the target's `Benchmarks.swift`, with a configuration from
   `gatedConfiguration(tolerance:)`. For a handshake, add a `handshake(_:scenario:)` call with a new
   `HandshakeScenario`. For a record scenario, add a `transfer(_:cipherSuite:payloadByteCount:)` call.
2. Keep setup outside the measurement. Record scenarios build a `ConnectedPair` before
   `benchmark.startMeasurement()`; handshake scenarios build the peers inside it on purpose.
3. Check that the counts are stable. Run the scenario several times with `SWIFT_DETERMINISTIC_HASHING=1`
   and `thresholds check` against a freshly recorded directory; every run must pass. A scenario whose
   counts move between runs cannot hold a threshold.
4. Record the numbers, and add the new files to the commit:

```sh
swift package --package-path Benchmarks --allow-writing-to-package-directory \
    benchmark thresholds update \
    --format metricP90AbsoluteThresholds --path Benchmarks/Thresholds/latest-beta/
```

## Profiling with Instruments

Each benchmark target is an ordinary executable. Build it in release mode and launch the binary from
Instruments:

```sh
swift build --package-path Benchmarks -c release --product HandshakeBenchmarks
# The binary is at Benchmarks/.build/release/HandshakeBenchmarks.
```

## Troubleshooting

* `product 'SwiftTLS' required by package 'benchmarks' ... not found in package 'swift-tls'`: the
  checkout is in a directory named `benchmarks`. See Requirements.
* `is BETTER than the defined absolute baseline thresholds`: a scenario improved. Record the new
  numbers with `thresholds update`.
* A check passes on one run and fails on the next: `SWIFT_DETERMINISTIC_HASHING=1` is probably not set.
* The sandbox refuses a write: add `--allow-writing-to-package-directory`.
