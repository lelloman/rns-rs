# Reticulum 1.5.5 Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.5.4` |
| Previous normative commit | `3f95b472820ddfb27f736143fb0b4d0d3aa610f1` |
| Accepted version | `1.5.5` |
| Normative tag or ref | GitHub `1.5.5` release tag (canonical `rgit/master` extended by the two release commits) |
| Normative commit | `7f2b3b9b524c9386316379af1313b43a5e4f7a5d` |
| Root tree | `73d3c378805a380da5194a13561f904f88d07e69` |
| `RNS` tree | `192d74c76e5c56046a411492f219db1833c99365` |
| Version assertion | Exact-target Python `RNS.__version__ == "1.5.5"` |
| Audited range | `3f95b472820ddfb27f736143fb0b4d0d3aa610f1..7f2b3b9b524c9386316379af1313b43a5e4f7a5d` |
| Acceptance date | `2026-09-30` |
| Detailed audit | [reticulum-1.5.5-audit.md](reticulum-1.5.5-audit.md) |

The `1.5.5` GitHub tag is two release-only commits (`0a25e1a9`, `7f2b3b9b`)
ahead of the canonical rgit tip `ddeb44b1`; all three share the `RNS` tree
`192d74c7`, so the release tag adds no runtime change. The first `2026-09-28`
preparation targeted `cce96d38`; the `2026-09-30` daily report extended the
review to the full rgit history and the release tag. Historical fixture files
retain their original pinned 1.4.0 provenance and were not regenerated. Local
exact-target interop used a disposable worktree at `ddeb44b1`.

## Upstream Commit Audit

All forty commits in the audited ancestry range have a final disposition and one
nonempty local mapping each. Their unique, full `Upstream-Commit` trailers match
upstream ancestry order. The [audit](reticulum-1.5.5-audit.md) records changed
paths, per-commit handling, and focused evidence.

| Area | Upstream commits | Final handling |
|---|---|---|
| Interface lifecycle and management | `e68f4ff1`, `24b1ac52`, `7283cb41`, `84709ccf`, `d23261c8`, `71583c5c`, `942434b2`, `a714c200` | Integrated stop/reconnect controls, named attach/detach/reload, authenticated shared-instance RPC, and `rnstatus` commands. The Backbone client now honors a detach control; TCP was already covered structurally. |
| Discovery auto-connect | `26aec004`, `0a0e661b`, `6d1409be`, `fc95caf5`, `bb132091`, `47318034`, `1f749907` | Integrated the `autoconnect_unverified_implementations` option and the implementation/version qualification criteria; the canonical detach, idempotency, naming, and platform rationale are structurally covered by the native endpoint-keyed peer pool. |
| Discovery data and status | `2c30a88e`, `135e941f`, `d3153bd7`, `39a888c1` | Integrated I2P `.b32.i2p` snippets, IFAC sanitization, discovered-stack display, and `rnstatus --show-stale/--show-unknown`. |
| Announce and ingress correctness | `6c9d717c`, `06dc4ad5`, `4f791109`, `1d9ebe8c`, `5cdff287` | Integrated spawned-interface `announce_cap` propagation; the producer-selection, fraction-storage, initialization, and single-packet request fixes are structurally covered. |
| Git page utility | `1cf176f6`, `a93c6ba5` | Integrated readable work-document counts and scoped Markdown-to-Micron downloads. |
| Upstream documentation, version, and changelog | `c95fd8e6`, `6ecda493`, `e2ba876e`, `3b742914`, `3ad70c63`, `b8993899`, `69c425d9`, `d5962d14`, `cce96d38`, `73c60e6a`, `f25b3170`, `ddeb44b1`, `0a25e1a9`, `7f2b3b9b` | Applicable operator documentation was integrated; upstream-only generated manuals, policies, editorial changes, and release notes were audited as non-runtime. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | Historical conformance/fixture suites pass in both workspace configurations. No audited commit introduced a new wire encoding or cryptographic format. |
| Transport and interfaces | Focused lifecycle, reconnect, config-management, local immediate-connect, Backbone detach, and RPC regressions pass; complete `rns-net` suite passes. |
| Links, channels, and resources | Default and native-hook workspace end-to-end suites pass, including multihop, concurrent links, and Resources. |
| Utilities and APIs | `rnstatus` management/discovered-stack/stale-unknown and `rngit` page regressions pass; Python 1.5.5 utility interop passes. |
| Live interop | At exact `ddeb44b1`, `python_interop` passes 1/1 and ignored `utility_interop` passes 6/6; the impaired dual-VPS `--daily` smoke passes. |

## Acceptance Record

| Gate | Result |
|---|---|
| Focused regression suites | Passed for each applicable runtime change on 2026-09-30, including the new Backbone stop, IFAC sanitization, announce-cap inheritance, auto-connect criteria, and `rnstatus` filters. |
| Fixture regeneration/provenance | Historical 1.4.0 fixture suites passed; no regeneration because the audited changes do not alter fixture byte formats. |
| Exact-target Python/Rust interop | Passed 2026-09-30 at `ddeb44b1` (Python `RNS.__version__ == "1.5.5"`, `RNS` tree `192d74c7`): 1/1 `python_interop` and 6/6 `utility_interop`. |
| Workspace and feature suites | `cargo test --workspace -- --test-threads=1`: 2,545 passed, 0 failed. `cargo test --workspace --features rns-hooks -- --test-threads=1`: 2,592 passed, 0 failed. |
| Formatting and lint | `cargo fmt --all -- --check` and `bash scripts/lint-host.sh` passed on 2026-09-30. |
| Release/cross builds | Native release `rns-server`/`rns-ctl` with native hooks passed. ARMv7 (`armv7-unknown-linux-gnueabihf`, `arm-linux-gnueabihf-gcc` linker) passed for no-hook `rnsd`/`rns-ctl`, native-hook `rnsd`/`rns-ctl`, and built-in-hook `rns-server`. |
| Docker E2E | Full `./tests/docker/run-all.sh` passed 2026-09-30: 11 runs, 102 checks passed, 0 failed, 29 expected skips. |
| Hardware/manual validation | The impaired dual-VPS `--daily` Backbone smoke passed 2026-09-30 using freshly built `rns-server 0.3.1402-b37785a`, covering Resource boundaries, concurrent links, and forced reconnect. Physical serial/RNode/Android hardware was not tested. |

## Caveats and Deferred Validation

Native discovered-interface auto-connect accepts the native implementation name
`rns-rs` without the upstream protocol-version gate, because native versions
track the crate release cycle rather than the Reticulum protocol version; the
canonical `RNS` implementation still requires `>= 1.5.2`. Native Backbone is a
cross-platform transport, so the upstream Windows/macOS degradation to
`TCPClientInterface` is not ported, and native auto-connect remains
endpoint-based, accepting both `BackboneInterface` and `TCPServerInterface`
discoveries. The PR CI interop pin still tests the older mirrored `1.5.5`
snapshot `d5962d14`; it should advance to the released `7f2b3b9b`. Physical
serial/RNode/Android hardware remains unclaimed. Upstream governance, support,
and security prose was reviewed as upstream editorial material, not adopted as
this project's policy.

## Promotion Result

Baseline accepted at the GitHub `1.5.5` release tag `7f2b3b9b` (canonical `RNS`
tree `192d74c7`). [UPSTREAM.md](../../UPSTREAM.md) and the README badge are
updated to this baseline. The detailed work record remains
[reticulum-1.5.5-audit.md](reticulum-1.5.5-audit.md).
