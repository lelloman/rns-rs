# Development

This page is the checklist for working on rns-rs: the commands CI runs, how
the test layers fit together, and where benchmarks and release procedures
live. Read [CONTRIBUTING.md](../CONTRIBUTING.md) first for authorship and
license rules.

## Standard checks

Run these before opening a pull request. CI runs the same set.

```bash
cargo test --workspace            # all workspace members
cargo fmt --check                 # formatting
bash scripts/lint-host.sh         # clippy, warnings are errors, native hooks enabled
```

The lint script enables `rns-hooks` coverage but deliberately avoids
`--all-features`: that would turn on `rns-crypto/espidf`, which pulls in
`esp-idf-sys` and fails on a normal host. ESP32 validation is a separate lane
under `rns-esp32/`.

## Test layers

### Unit and integration tests

```bash
cargo test                        # default workspace members
cargo test -p rns-core            # one crate
cargo test --workspace --features rns-hooks    # with native hooks, as CI does
cargo test -p rns-ctl --features tls
```

The `rns-hooks` WASM examples must be built before the hook integration tests
can load them:

```bash
./rns-hooks/build-examples.sh
cargo test -p rns-net --features rns-hooks-wasm,rns-hooks-builtin --test e2e_hooks builtin
```

### Conformance vectors

Committed fixtures under `tests/fixtures/` were generated from a pinned
Reticulum 1.4.0 checkout and keep that provenance on purpose. To regenerate:

```bash
RETICULUM_UPSTREAM_DIR=/path/to/Reticulum python3 tests/generate_vectors.py
```

### Live Python interop

These need a Python Reticulum checkout on `PYTHONPATH`. CI runs them against
Reticulum 1.4.2, 1.5.4, and 1.5.5 pinned by commit and `RNS` tree hash.

```bash
export RETICULUM_UPSTREAM_DIR=/path/to/Reticulum
export PYTHONPATH=$RETICULUM_UPSTREAM_DIR
cargo test -p rns-net --test python_interop -- --nocapture
cargo test -p rns-cli --test utility_interop -- --ignored --nocapture
```

### Docker end-to-end suites

Twenty-one numbered suites under `tests/docker/suites/` exercise multi-node
behaviour on generated chain, mesh, and star topologies: health, announces
over one and many hops, packet delivery, proofs, identity recall, path tables,
convergence, scale, link lifecycle, channels, resource transfer, concurrent
links, node restart, burst traffic, sentinel blacklisting, and stamped
announce and path request emission through the runtime `global.stamp_*`
switches. Separate
directories add shared-client reconnection, links between sibling clients of a
shared instance and from a directly adjacent peer (issue #183, run with the
daemon's transport both disabled and enabled), `rns-server`
supervision, NAT traversal for Direct Link, and the privileged Linux `rntun`
suite with real TUN devices. The shared-instance-links test also builds a
Python image with `rns==1.5.7` from PyPI (override with `RNS_VERSION`), so it
needs network access on first run.

The matrix runner prints the wall time of every round in its summary. Rounds
are the expensive unit: starting a topology and tearing it down costs more than
most suites, so every suite that needs five nodes shares one chain-5 round,
suites that skip themselves do not trigger the inter-suite settle, and
containers get a two-second stop timeout (`COMPOSE_STOP_TIMEOUT`). The
`rns-server` image shares the cargo caches of the main test image, so only its
first build compiles the dependencies.

```bash
./tests/docker/run-all.sh                                 # full matrix
./tests/docker/run.sh --topology chain-3 --suite 01       # one suite on one topology
./tests/docker/run.sh --topology chain-5 --suite 03,08    # several suites, comma-separated
./tests/docker/nat-punch/run.sh
./tests/docker/rns-server/run.sh
./tests/docker/shared-client-reconnect/run.sh
./tests/docker/shared-instance-links/run.sh
./tests/docker/rntun/run.sh                               # needs privileged containers
```

### Python tooling tests

The operator scripts have their own tests, run by CI with
`python -m unittest discover -s tests -p 'test_*.py'`.

## What CI runs

| Job | Command or scope |
|-----|------------------|
| Cargo Test | WASM example build, interface-selection `cargo check`, `cargo test --workspace` |
| Cargo Test (rns-hooks) | Workspace tests with `--features rns-hooks`, built-in hook integration tests |
| Cargo Test (rns-ctl tls) | `cargo test -p rns-ctl --features tls` |
| Reticulum Interop | Live interop against three pinned Python versions |
| Docker E2E | `./tests/docker/run-all.sh` |
| Rustfmt, Clippy | `cargo fmt --check`, `bash scripts/lint-host.sh` |
| ARMv7 Build Smoke | Cross-builds of `rnsd`, `rns-ctl`, and `rns-server` with and without hooks |
| rns-ctl-web-smoke | `node --test rns-ctl/assets/app.smoke.test.js` for the built-in UI |
| Android Client | `./gradlew testDebugUnitTest assembleDebug` in `rns-tun-android/` |
| ESP32 Lockfile | `rns-esp32/Cargo.lock` is up to date |
| Python Tools | Compile and unit-test `scripts/` and `tests/` |
| Upstream Badge | The README badge version matches `- Version:` in `UPSTREAM.md` |
| RustSec audit | `cargo audit` on both lock files, weekly and on manifest changes; `deny.toml` configures `cargo-deny` |

Workflows live in `.github/workflows/`.

## Benchmarks

The benchmark runner measures verified application work between two Rust
processes over loopback TCP, optionally through a rate-limited relay. It is
an exploratory tool, not a regression gate.

```bash
./scripts/bench doctor
./scripts/bench run --profile smoke
./scripts/bench run --suite resource-mixed --profile mixed-quick
./scripts/bench report target/bench-results/<run-id>
```

[bench/README.md](../bench/README.md) documents profiles, scenarios, the
relay and three-node harnesses, and profiling. The `*-findings.md` files next
to it record individual investigations (compression, allocation, HDLC
decoding, release profile) with their measurements. Criterion microbenchmarks
live in each crate's `benches/`.

## Upstream tracking workflow

When upstream Reticulum moves, the daily report flags drift, and the change is
audited commit by commit before `UPSTREAM.md` is promoted. The procedure, the
commit message trailer, and the templates are in the
[parity README](upstream-parity/README.md). The drift checker is
`scripts/check_upstream_drift.py`.

## Releases

- Workspace crates go to crates.io following the
  [publish runbook](crates-io-publish-runbook.md). Each crate is tagged
  `<crate>-v<version>` at the exact published commit.
- `rns-server` deployment tarballs come from
  `scripts/package-rns-server-tarball.sh`.
- The ESP32 firmware image is built by a GitHub Actions workflow on a matching
  tag; see the [ESP32 release runbook](esp32-release-runbook.md).
- The [2026 dependency upgrade audit](dependency-upgrades-2026.md) is the
  latest tree-wide dependency review.

## Repository layout

| Path | Contents |
|------|----------|
| `rns-*/` | Workspace crates, one directory each |
| `rns-hooks/examples/`, `rns-hooks/sdk/` | Example hooks and the guest SDK crates |
| `tools/rns-bench/`, `tools/vps-history-dashboard/` | Benchmark binary and the VPS dashboard |
| `bench/` | Benchmark profiles, scenarios, harnesses, and findings |
| `tests/docker/` | End-to-end suites, topologies, and per-feature Docker scenarios |
| `tests/fixtures/` | Conformance vectors |
| `scripts/` | Lint, bench wrappers, packaging, drift check, daily report, smoke tests |
| `docs/` | This wiki |
| `vendor/` | Vendored `maybe-async-cfg`, excluded from the workspace |
| `data/`, `dist/`, `.local/` | Ignored by git: operator reports and databases, built bundles, local scratch |
