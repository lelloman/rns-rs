# Reticulum 1.5.5 Candidate Parity Record

This record is prepared for PR validation. Baseline promotion remains pending;
`UPSTREAM.md` and the README badge still identify the accepted 1.5.4 baseline.

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.5.4` |
| Previous normative commit | `3f95b472820ddfb27f736143fb0b4d0d3aa610f1` |
| Candidate version | `1.5.5` |
| Normative ref | Canonical `rgit/master` at the fixed audit cutoff |
| Normative commit | `cce96d38c684e8d3e85e8cb311633fb2599515dd` |
| Root tree | `f5ddc7ea6dcd988fd075310159a9262a9acb3c47` |
| `RNS` tree | `f019bc58f0c19452b57b642b6170261695d8295d` |
| Version assertion | Exact-target Python `RNS.__version__ == "1.5.5"` |
| Audited range | `3f95b472820ddfb27f736143fb0b4d0d3aa610f1..cce96d38c684e8d3e85e8cb311633fb2599515dd` |
| Candidate review date | `2026-09-28` |
| Detailed audit | [reticulum-1.5.5-audit.md](reticulum-1.5.5-audit.md) |

The candidate is a canonical development tip, not a signed release tag. At the final pre-promotion refresh, both remotes fetched successfully: normative rgit was at the candidate commit and the GitHub mirror was still at `d5962d14`, two commits behind. The accepted checkout stayed pinned to 1.5.4 during review; exact-target tests used a disposable worktree. Historical fixture files retain their original pinned 1.4.0 provenance and were not regenerated for this advancement.

## Upstream Commit Audit

All nineteen commits in the audited ancestry range have a final disposition and one nonempty local mapping each. Their unique, full `Upstream-Commit` trailers match upstream ancestry order. The [audit](reticulum-1.5.5-audit.md) records changed paths, per-commit handling, and focused evidence.

| Area | Upstream commits | Final handling |
|---|---|---|
| Interface lifecycle and management | `e68f4ff1`, `24b1ac52`, `7283cb41`, `84709ccf`, `d23261c8` | Integrated stop/reconnect controls, named attach/detach/reload, authenticated shared-instance RPC, and `rnstatus` commands. Two trailer-free follow-ups corrected Python RPC socket/authentication and first-hop timeout compatibility found by exact-target interop. |
| Discovery and status | `2c30a88e`, `d3153bd7` | Integrated I2P `.b32.i2p` snippets and discovered-stack parsing, persistence, RPC, and display. |
| Git page utility | `1cf176f6`, `a93c6ba5` | Integrated readable work-document counts and scoped Markdown-to-Micron downloads. |
| Local client initialization | `71583c5c` | Structurally covered: complete immutable metadata and bitrate are built before connecting, and queued events are consumed after registration. |
| Upstream documentation, version, and changelog | `c95fd8e6`, `6ecda493`, `e2ba876e`, `3b742914`, `3ad70c63`, `b8993899`, `69c425d9`, `d5962d14`, `cce96d38` | Applicable operator documentation was integrated; upstream-only generated manuals, policies, editorial changes, and release notes were audited as non-runtime. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | Historical conformance/fixture suites pass in both workspace configurations. No new wire encoding or cryptographic format was introduced by the audited commits. |
| Transport and interfaces | Focused lifecycle, reconnect, config-management, local immediate-connect, and RPC regressions pass; complete `rns-net` suite passes. |
| Links, channels, and resources | Default and native-hook workspace end-to-end suites pass, including multihop, concurrent links, and Resources. |
| Utilities and APIs | `rnstatus` management/discovered-stack and `rngit` page regressions pass; Python 1.5.5 utility interop passes. |
| Live interop | At exact `cce96d38`, `python_interop` passes 1/1 and ignored `utility_interop` passes 6/6 with the ordinary CI-parallel test mode. |

## Validation Record

Results below were obtained on 2026-09-28 unless marked otherwise.

| Gate | Result |
|---|---|
| Focused regression suites | Passed for each applicable runtime change; final immediate-connect regression and first-hop RPC roundtrip passed. |
| Fixture regeneration/provenance | Historical 1.4.0 fixture suites passed; no regeneration because the audited changes do not alter fixture byte formats. |
| Exact-target Python/Rust interop | Passed: 1/1 `python_interop` and 6/6 `utility_interop` at the asserted 1.5.5 exact target. |
| Workspace and feature suites | `cargo test --workspace -- --test-threads=1`: 2,536 passed; `cargo test --workspace --features rns-hooks -- --test-threads=1`: 2,583 passed. Python tool tests: 19 passed; web smoke passed. |
| Formatting and lint | `cargo fmt --all -- --check`, `git diff --check`, and `bash scripts/lint-host.sh` passed. `rns-net` builds without default features. |
| Release/cross builds | Native release `rnsd` and `rns-ctl` with native hooks passed. ARMv7 release smoke passed for no-hook `rnsd`/`rns-ctl`, native-hook `rnsd`/`rns-ctl`, and built-in-hook `rns-server`. |
| Docker E2E | Interrupted at user request during `mesh-4`. Completed chain-3, two chain-5 cases, and star-5 entries reported no failures; the full matrix, including mesh and 30-node scale, has not passed. PR CI should rerun `./tests/docker/run-all.sh`. |
| Hardware/manual validation | The daily dual-VPS smoke passed before final code integration, covering impaired Resource boundaries, concurrent links, and forced reconnect recovery. This is operational evidence, not a final-revision VPS stress claim. Physical serial/RNode/Android hardware was not tested. |

## Caveats and Deferred Validation

The GitHub mirror lagged the normative tip by two commits at the final pre-promotion refresh. Its CI interop matrix remains pinned to the previously mirrored 1.5.4 baseline until the exact 1.5.5 commit is available on GitHub; ordinary PR CI therefore does not yet rerun exact-target 1.5.5 interop. Local exact-target interop used the canonical rgit object and passed. The Docker matrix was interrupted and must be rerun for acceptance. The final revision was not redeployed to the dual VPS hosts, and physical hardware validation is unclaimed. Upstream governance, support, and security prose was reviewed as upstream editorial material, not adopted as this project's policy.

## Promotion Result

Pending the full Docker result, PR checks, and final review. [UPSTREAM.md](../../UPSTREAM.md) remains at 1.5.4; this candidate record does not promote the baseline.
