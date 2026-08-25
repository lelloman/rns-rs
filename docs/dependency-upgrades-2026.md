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
| `sha2` | 0.10.9 | 0.11.0 | Direct crypto dependency in `rns-crypto`, `rns-stats-hook`, and the stats-scraper example | Coupled with `hmac` through `digest` 0.11 | Upgraded; vectors and host/WASM/ESP32 lanes pass |
| `hmac` | 0.12.1 | 0.13.0 | Direct crypto dependency in `rns-crypto` | Coupled with `sha2` through `digest` 0.11 | Upgraded; RFC 4231 suite passes |
| `aes` | 0.8.4 | 0.9.2 | Direct crypto dependency in `rns-crypto` | Coupled with `cbc` through the `cipher` trait generation | Upgraded; NIST, interop, token, and platform suites pass |
| `cbc` | 0.1.2 | 0.2.1 | Direct crypto dependency in `rns-crypto` | Coupled with `aes` through the `cipher` trait generation | Upgraded; no-padding CBC and edge-case suites pass |
| `ed25519-dalek` | 2.2.0 | 3.0.0 | Direct signing dependency in `rns-crypto` | Dalek compatibility group | Upgraded; RFC 8032, interop, and link suites pass |
| `x25519-dalek` | 2.0.1 | 3.0.0 | Direct key-agreement dependency in `rns-crypto` | Dalek compatibility group | Upgraded; RFC 7748, identity, and platform suites pass |
| `wasmtime` | 46.0.2 | 47.0.3 | Direct optional WASM-hook runtime in `rns-hooks` | Independent, high-impact | Upgraded; sandbox, examples, and hook E2E suites pass |
| `ssd1306` | 0.9.0 | 0.10.0 | Direct optional ESP32 display dependency | Independent embedded lane | Upgraded; wire-contract and ESP32 lanes pass |
| `generic-array` | 0.14.7 | 0.14.9 | Transitive in the host lockfile | Do not force with a direct dependency | Constrained by `crypto-common =0.14.7` |
| `az` | 1.2.1 | 1.3.0 | Transitive in the ESP32 lockfile | Do not force with a direct dependency | Constrained by embedded-graphics `~1.2.0` |

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

## sha2 0.11 and hmac 0.13 assessment

- The complete `sha2-v0.10.9...sha2-v0.11.0` and
  `hmac-v0.12.1...hmac-v0.13.0` tag diffs and upstream changelogs were
  reviewed. Both crates move to edition 2024, raise MSRV to Rust 1.85, replace
  public aliases with newtypes, and adopt `digest` 0.11. sha2 replaces its
  backend-selection features with checked configuration flags and adds new
  CPU backends; hmac removes its `std` and `reset` features and adds explicit
  reset-capable types.
- The workspace used no removed features, compression APIs, reset APIs, or
  concrete upstream output types. Direct `sha2` and `hmac` dependencies must
  move together because `Hmac<Sha256>` requires one `digest` trait generation.
  Construction now imports the documented `hmac::KeyInit` trait. sha2 0.10 is
  temporarily retained transitively by Dalek 2 and Wasmtime 46; those copies
  are owned by their separately reviewed upgrade units.
- SHA-256 and SHA-512 coverage now includes fixed empty/short/million-byte
  known answers, incremental updates across every padding boundary, and
  non-consuming state snapshots. HMAC-SHA-256 covers RFC 4231 short,
  block-crossing, nonuniform, and long-key vectors plus empty input and state
  snapshots. A fixed identity-hash truncation vector covers the stats hook;
  the stats-scraper WASM build and ESP32 release build exercise non-host
  backends and `no_std` consumers.

## aes 0.9 and cbc 0.2 assessment

- The complete `aes-v0.8.4...aes-v0.9.2` and `cbc-v0.1.2...cbc-v0.2.1`
  tag diffs and upstream changelogs were reviewed. Both crates move to edition
  2024, raise MSRV to Rust 1.85, and adopt `cipher` 0.5. AES 0.9 refactors its
  software and hardware backends and enables runtime-selected ARMv8 support by
  default; 0.9.2 fixes an x86 performance regression. CBC 0.2 removes its
  unused `std` feature and `Clone` implementation and 0.2.1 adds IV-state
  accessors.
- The workspace uses Rust 1.96, disables AES default features, and uses no
  removed features, cloning, IV-state accessors, or concrete upstream block
  types. AES and CBC must move together because their traits come from one
  `cipher` generation. The implementation now uses the supported
  `BlockModeEncrypt` and `BlockModeDecrypt` APIs with explicit `NoPadding`;
  this also removes an unsafe assumption about the representation of
  `aes::Block`. The public `Aes128` and `Aes256` APIs and their aligned-input
  behavior are unchanged.
- Focused coverage includes the four-block NIST SP 800-38A AES-128-CBC and
  AES-256-CBC encryption/decryption vectors, existing Reticulum interoperability
  fixtures, empty input, rejection of unaligned input, token authentication and
  round trips, and the complete crypto crate. Host, ARMv7, and ESP32 lanes
  exercise the applicable architecture-specific implementations.

## ed25519-dalek 3 and x25519-dalek 3 assessment

- The complete `ed25519-2.2.0...ed25519-3.0.0` and
  `x25519-2.0.1...x25519-3.0.0` tag diffs and both upstream changelogs were
  reviewed. The crates move to edition 2024 and Rust 1.85, share
  curve25519-dalek 5, and adopt the current RustCrypto signature, digest, and
  RNG trait generations. Ed25519 removes its `std` feature and adds multipart
  signing traits. X25519 removes its no-op `alloc` feature and deprecated
  constructors; secret types can no longer be explicitly zeroized but remain
  zeroized on drop.
- The workspace disables default features and uses only byte-based signing and
  verification, static Diffie-Hellman, and public/private byte conversion. It
  uses no removed features, random constructors, multipart APIs, PKCS#8,
  serde, or explicit zeroization. Both direct dependencies move together so
  they retain one curve25519-dalek generation. Their public wrapper APIs and
  wire representations require no source migration, and the upgrade removes
  the remaining transitive sha2 0.10 copy.
- Ed25519 coverage includes the first three RFC 8032 known answers, exact seed,
  public-key, and signature bytes, reconstruction from a public key, message
  and signature mutation rejection, and noncanonical scalar rejection. X25519
  coverage includes exact RFC 7748 public keys and shared secret, clamping and
  private-key serialization stability, ignored public-coordinate high bits,
  low-order-peer behavior, and symmetric exchange. Existing Python identity
  fixtures plus signing, encryption, ratchet, and full link-handshake tests
  cover the protocol consumers; ARMv7 and ESP32 builds cover non-host codegen.

## Wasmtime 47 assessment

- The official 47.0.0 through 47.0.3 release notes, complete 169-commit
  `v46.0.2...v47.0.3` comparison, crate manifests, and public embedding-source
  diff were reviewed. Wasmtime remains edition 2024 with Rust 1.94 as its MSRV.
  The `Engine`, `Config`, `Module`, `Linker`, `Store`, `Instance`, `Memory`,
  `Caller`, fuel, and typed-function APIs used here are unchanged. The release
  removes `wasi-common` and wasi-threads, neither of which the hook runtime
  uses, and updates Cranelift and wasmparser together.
- Wasmtime 47 enables the WebAssembly GC and exception-handling proposals by
  default. Hook modules use only the core-module ABI, so the runtime now
  explicitly disables both proposals to preserve the accepted-module surface
  and avoid unnecessary sandbox complexity. Existing fuel metering, one-engine
  ownership, synchronous calls, store caching, host imports, and fail-open trap
  behavior are unchanged. Version 47.0.3 includes fixes for cross-engine type
  confusion and preemption during bulk operations; this embedding uses one
  engine and no epoch callbacks, and its prior 46.0.2 version already contained
  the corresponding backports.
- New tests prove that GC and exception modules remain rejected while bulk
  memory instructions compile, exercise a 16 KiB fuel-accounted memory fill
  and copy byte-for-byte, and verify that a cached store can recover after fuel
  exhaustion with a reset budget. The complete runtime and native-hook suites,
  all nine built WASM examples, 27 example integration cases, 23 network hook
  E2E cases, the control API hook lifecycle, and the hook benchmark harness
  cover compilation, ABI validation, host calls, traps, persistence, and live
  attachment behavior.

## SSD1306 0.10 assessment

- The official 0.10.0 changelog and complete nine-commit `v0.9.0...v0.10.0`
  tag diff were reviewed. The crate remains edition 2021 with Rust 1.75 as its
  MSRV. Production changes correct the asynchronous I2C trait bounds, fix two
  terminal-mode expressions, and re-export the new 64x32 display size. The
  release also pins `maybe-async-cfg` 0.2.4; the associated lockfile changes
  are build-time macro dependencies only. SSD1306's exact pin prevents
  selecting 0.2.5, whose transformer does not compile SSD1306's combined
  sync/async API. The ESP32 manifest therefore patches the exact 0.2.4 package
  to a reviewed local copy that preserves its transformer and replaces only
  the `proc-macro-error` diagnostic dependency. RUSTSEC-2024-0370 and both
  `proc-macro-error` packages are absent from the resulting lockfile; no
  advisory ignore is used. The vendored macro doctests, SSD1306 sync and async
  expansion checks, ESP32 host/display tests, and release firmware build pass.
- The firmware uses synchronous embedded-hal 1.0 I2C, a 128x64 buffered
  graphics display, rotation zero, and the unchanged initialization,
  brightness, power, clear, flush, and embedded-graphics drawing APIs. It uses
  neither the corrected async path nor terminal mode, so no source or runtime
  migration is required.
- A host-side recording I2C implementation now pins the default 0x3c address,
  initialization sequence, firmware power and maximum-brightness commands,
  page/bit framebuffer layout, 16-byte transfer chunking, text drawing, full
  clear, and command/data bus-error propagation. The same five tests pass on
  both 0.9 and 0.10; the firmware release build validates the concrete ESP-IDF
  I2C driver and Xtensa target.

## Constrained transitive dependency assessments

- The published `generic-array` 0.14.7 and 0.14.9 source artifacts were
  compared in full. Version 0.14.9 leaves its runtime implementation unchanged
  and adds crate-level deprecation diagnostics directing consumers to 1.x.
  Wasmtime 47's Cranelift stack retains sha2 0.10, whose `crypto-common` 0.1.7
  dependency requires `generic-array =0.14.7` exactly. Cargo therefore rejects
  a precise 0.14.9 lock update. Moving it would require an upstream
  Wasmtime/Cranelift crypto-stack change or a local third-party patch, neither
  of which is a safe transitive lockfile update.
- The published `az` 1.2.1 and 1.3.0 source artifacts and 1.3.0 release notes
  were compared in full. Version 1.3 moves to edition 2024 and Rust 1.85, adds
  strict-cast replacements for APIs scheduled for future deprecation, and adds
  an optional nightly floating-point feature. The existing `SaturatingAs`
  operations used by embedded-graphics remain available, and the repository's
  Rust 1.96 toolchain satisfies the new MSRV. However, embedded-graphics 0.8.2
  and embedded-graphics-core 0.4.1 both require `az ~1.2.0`, so Cargo correctly
  excludes 1.3. Updating it must wait for a reviewed embedded-graphics release;
  adding an unused direct dependency or patching upstream manifests would not
  upgrade the code actually used by the display driver.
- A verbose dry-run resolution leaves only these two packages and SSD1306's
  exact `maybe-async-cfg` 0.2.4 pin behind newer registry releases.
  No manifest range, patch section, advisory ignore, or lockfile was changed to
  force them.
