# Rust dependency upgrade audit (2026)

This checklist tracks manifest-incompatible updates reported by Cargo for the
host workspace and `rns-esp32`. Each direct dependency is upgraded only after
reviewing the upstream release/tag diff and adding focused compatibility tests.
Every completed row must have its own local commit unless the crates share an
API generation and cannot compile independently.

| Dependency | Current | Target | Kind and scope | Upgrade unit | Status |
| --- | ---: | ---: | --- | --- | --- |
| `criterion` | 0.5.1 | 0.8.2 | Direct dev dependency in `rns-core`, `rns-net`, and `rns-hooks` | Independent | Upgraded; four harness smoke tests pass |
| `bzip2` | 0.5.2 | 0.6.1 | Direct runtime dependency in `rns-net` | Independent | Pending review |
| `libloading` | 0.8.9 | 0.9.0 | Direct optional native-hook dependency in `rns-hooks` | Independent | Pending review |
| `tikv-jemallocator` | 0.6.1 | 0.7.0 | Direct allocator dependency in `rns-cli` | Independent | Pending review |
| `rcgen` | 0.13.2 | 0.14.9 | Direct TLS test/support dependency in `rns-ctl` | Independent | Pending review |
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
