# Rust dependency upgrade audit (2026)

This checklist tracks manifest-incompatible updates reported by Cargo for the
host workspace and `rns-esp32`. Each direct dependency is upgraded only after
reviewing the upstream release/tag diff and adding focused compatibility tests.
Every completed row must have its own local commit unless the crates share an
API generation and cannot compile independently.

| Dependency | Current | Target | Kind and scope | Upgrade unit | Status |
| --- | ---: | ---: | --- | --- | --- |
| `criterion` | 0.5.1 | 0.8.2 | Direct dev dependency in `rns-core`, `rns-net`, and `rns-hooks` | Independent | Upgraded; four harness smoke tests pass |
| `bzip2` | 0.5.2 | 0.6.1 | Direct runtime dependency in `rns-net` | Independent | Upgraded; libbz2 backend and RNCP regression suite pass |
| `libloading` | 0.8.9 | 0.9.0 | Direct optional native-hook dependency in `rns-hooks` | Independent | Upgraded; native ABI/error/lifetime suite passes |
| `tikv-jemallocator` | 0.6.1 | 0.7.0 | Direct allocator dependency in `rns-cli` | Independent | Upgraded; allocator, CLI, and ARMv7 suites pass |
| `rcgen` | 0.13.2 | 0.14.9 | Direct TLS test/support dependency in `rns-ctl` | Independent | Upgraded; certificate and live TLS suites pass |
| `sha2` | 0.10.9 | 0.11.0 | Direct crypto dependency in `rns-crypto`, `rns-stats-hook`, and the stats-scraper example | Independent API generation | Pending review |
| `hmac` | 0.12.1 | 0.13.0 | Direct crypto dependency in `rns-crypto` | Independent API generation | Pending review |
| `aes` | 0.8.4 | 0.9.2 | Direct crypto dependency in `rns-crypto` | Coupled with `cbc` through the `cipher` trait generation | Pending review |
| `cbc` | 0.1.2 | 0.2.1 | Direct crypto dependency in `rns-crypto` | Coupled with `aes` through the `cipher` trait generation | Pending review |
| `ed25519-dalek` | 2.2.0 | 3.0.0 | Direct signing dependency in `rns-crypto` | Dalek compatibility group | Pending review |
| `x25519-dalek` | 2.0.1 | 3.0.0 | Direct key-agreement dependency in `rns-crypto` | Dalek compatibility group | Pending review |
| `wasmtime` | 46.0.2 | 47.0.3 | Direct optional WASM-hook runtime in `rns-hooks` | Independent, high-impact | Pending review |
| `ssd1306` | 0.9.0 | 0.10.0 | Direct optional ESP32 display dependency | Independent embedded lane | Pending review |
| `generic-array` | 0.14.7 | 0.14.9 | Transitive in both lockfiles | Do not force with a direct dependency | Awaiting direct upgrades |
| `az` | 1.2.1 | 1.3.0 | Transitive in the ESP32 lockfile | Do not force with a direct dependency | Awaiting `ssd1306` review |

## Required completion evidence

For each direct upgrade or inseparable upgrade unit:

1. Review primary upstream release notes and the source/tag diff.
2. Record API, behavior, MSRV, feature/default-feature, and safety implications.
3. Add focused tests for the repository behavior that depends on the crate.
4. Update the manifest constraint and resolve both lockfiles when shared crates
   can affect the ESP32 graph.
5. Run formatting, warning-free host Clippy, focused tests, RustSec, and the
   dependency-specific platform/feature lanes.
6. Commit locally without pushing or deploying.

Final validation repeats the full workspace, hooks, TLS, WASM, ARMv7, ESP32,
Docker, web, Python, and Backbone gates used by the preceding maintenance
series.

## Criterion 0.8 assessment

- Upstream changes reviewed: 0.6.0 through 0.8.2. The relevant breaking
  changes are an MSRV increase to Rust 1.86 and removal of async-std support.
- This workspace pins Rust 1.96 and all four benchmark harnesses are
  synchronous. The retained `html_reports` feature remains supported.
- The deprecated `criterion::black_box` re-export was replaced with
  `std::hint::black_box`, as recommended upstream.
- `scripts/test-benchmarks.sh` compiles and executes every Criterion harness
  once, exercising benchmark macros, batching, throughput configuration, and
  the optional hook-runtime benchmark paths.

## bzip2 0.6 assessment

- Upstream changes reviewed: 0.6.0 and 0.6.1 plus the complete tag diff.
  Version 0.6 raises MSRV from Rust 1.65 to 1.82 and changes the default
  backend from C `bzip2-sys` to pure-Rust `libbz2-rs-sys`; 0.6.1 adds safe
  uninitialized-output-buffer APIs used internally by vector operations.
- The workspace uses Rust 1.96, does not consume exported C symbols, and uses
  only the unchanged `read::BzEncoder`, `read::BzDecoder`, and `Compression`
  APIs. The wrapper therefore has no source-level incompatibility. The new
  pure-Rust default backend corrupted a real compressed, split RNCP transfer,
  while the same test passed before the backend change. The manifest now
  selects bzip2 0.6's static `bzip2-sys` backend explicitly.
- Focused tests pin the level-6 libbz2 wire representation, decode that fixed
  reference stream, cover empty and exact/zero bounded output, reject invalid,
  truncated, and checksum-corrupt streams, and cross the 900 KB bzip2 block
  boundary with a 1.1 MB round trip. Additional coverage exercises a maximum
  Resource segment, a compressed multi-segment disk-backed transfer with
  metadata, and the complete multi-process RNCP send/fetch path.

## libloading 0.9 assessment

- The complete 0.8.9-to-0.9.0 tag diff was reviewed. Version 0.9 raises MSRV
  from Rust 1.71 to 1.88, adds optional `no_std` support, replaces the library
  filename bound with sealed `AsFilename`, broadens symbol-name inputs, and
  restructures its public error variants.
- The workspace uses Rust 1.96 and libloading's default `std` feature. Native
  hooks pass `&Path` (supported by `AsFilename` under `std`), look up symbols
  with retained `&[u8]` support, and only format errors rather than matching
  libloading's changed error variants.
- The Linux native-hook integration suite now covers successful loading and
  execution after unlinking the shared-object file, missing libraries, each
  missing required symbol, ABI mismatch, nonzero hook returns, and invalid
  verdict values.

## tikv-jemallocator 0.7 assessment

- The 0.7 release notes and complete 0.6.1-to-0.7.0 tag diff were reviewed.
  The bundled allocator moves from jemalloc 5.3.0 to 5.3.1, build scripts gain
  improved cross-compiler and linker flag propagation, and new sized-free and
  optional libunwind-profiling APIs are added.
- `rnsd` uses only the unchanged unit `Jemalloc` type as `#[global_allocator]`
  and enables no optional allocator features, so the new FFI and profiling
  surfaces do not affect it.
- A dedicated integration-test executable installs Jemalloc globally and
  verifies 4096-byte alignment, zeroed allocation, content-preserving growth
  and shrink reallocations, and concurrent mixed-size allocation workloads.

## rcgen 0.14 assessment

- The 0.14.0 through 0.14.9 release notes and complete 0.13.2-to-0.14.9 tag
  diff were reviewed. Version 0.14 declares Rust 1.71 as its MSRV, retains the
  selected `aws_lc_rs` and `pem` features, restructures signing APIs around
  `SigningKey` and `Issuer`, and renames `CertifiedKey::key_pair` to
  `signing_key`. Version 0.14.9 corrects the DER encoding of a default false
  BasicConstraints CA flag.
- This workspace only generates simple self-signed TLS test certificates. Its
  sole source migration is the documented `signing_key` field rename; it does
  not use the changed issuer, CSR, CRL, or parameter-retention APIs.
- Focused tests parse the generated certificate and PKCS#8 PEM, load it into
  the production rustls configuration, complete a trusted DNS-name handshake,
  reject a wrong hostname and unrelated trust root, and reject a certificate
  paired with another generated private key. The existing live HTTPS endpoint
  and plaintext-rejection tests provide end-to-end coverage.
