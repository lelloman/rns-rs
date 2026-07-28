# Reticulum 1.4.2 Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.4.1` |
| Previous normative commit | `b2188ce9a746a35b770b10bea1b7ccbe93b4e198` |
| Accepted version | `1.4.2` |
| Normative tag or ref | Signed tag `1.4.2` |
| Normative commit | `b48b96e61676504e0a4e527b33b9a0b4495c6872` |
| Root tree | `2dfddfdd5d9b11eda628fb5b277f3ec007363c75` |
| `RNS` tree | `3286dd665827d2e591b47efaa5706b643e9b8d5a` |
| Version assertion | `RNS.__version__ == "1.4.2"` |
| Audited range | `b2188ce9a746a35b770b10bea1b7ccbe93b4e198..b48b96e61676504e0a4e527b33b9a0b4495c6872` |
| Commits audited | 6 |
| Acceptance date | `2026-07-28` |
| Detailed audit | [reticulum-1.4.2-audit.md](reticulum-1.4.2-audit.md) |

The annotated release tag resolves to the same commit on the Reticulum rgit
repository and GitHub mirror. The tag contains an SSH signature, but local
cryptographic tag verification was not available because the upstream checkout
has no `gpg.ssh.allowedSignersFile`. Historical 1.4.0 conformance fixtures keep
their original provenance; the exact live interop lane advances to 1.4.2.

## Upstream Commit Audit

Every commit in the six-commit range has a final disposition in the detailed
audit.

| Upstream commit | Local implementation commit |
|---|---|
| `4760103a` | `c855c30` — focused regression for the existing offline-interface invariant |
| `0416c419` | None — the expensive RPC pattern is structurally absent and existing cleanup coverage applies |
| `e3f1a5e7` | `1f86012` — tracking metadata and exact CI pin |
| `64fee86e` | `5d51389` — initiator lifecycle logging |
| `529a9fd4` | `351dfa0` — listener state guard and lifecycle logging |
| `b48b96e6` | No runtime commit — release notes and generated artifacts are recorded by this parity acceptance commit |

| Area | Upstream commits | Final handling |
|---|---|---|
| Recursive path-request emission | `4760103a` | Structurally covered by the driver availability guard; a focused engine-to-writer regression proves offline interfaces receive no write or transmit accounting. |
| Discovery blackhole lookup | `0416c419` | Structurally covered by in-process cleanup and a single full-set RPC query, with existing focused blackhole cleanup coverage. |
| rnsh lifecycle behavior | `64fee86e`, `529a9fd4` | INFO-default initiator logging, path/link/version/session diagnostics, listener authentication/execution logs and fatal post-handshake re-identification handling are integrated and regression tested. |
| Version and release artifacts | `e3f1a5e7`, `b48b96e6` | Tracking metadata and exact CI provenance are updated; independent Rust crate versions and generated upstream artifacts remain unchanged. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | Historical pinned fixture suites passed unchanged; no new wire or cryptographic format was introduced by the 1.4.2 range. |
| Transport and interfaces | `recursive_path_request_does_not_reach_offline_interface_writer` covers the upstream offline-interface failure at the Rust engine/driver boundary. Existing discovery blackhole cleanup regressions pass. |
| Links, channels and resources | Default and native-hooks workspace suites passed; exact 1.4.2 Python/Rust bidirectional TCP interop exercised announces and packet delivery. |
| Utilities and APIs | All 26 rnsh unit tests passed, including INFO-level defaults, denied identities, command-state enforcement and the new `WaitCommand`/`Running` re-identification regressions. Native rnsh documentation records the lifecycle behavior. |
| Live interop | Exact Reticulum 1.4.2 commit `b48b96e6` and `RNS` tree `3286dd66` passed bidirectional Python/Rust TCP interop locally on 2026-07-28. |

## Acceptance Record

| Gate | Result |
|---|---|
| Commit disposition | All six upstream commits have final implementation evidence or an explicit no-action rationale. |
| Focused regression suites | Passed locally on 2026-07-28. |
| Fixture regeneration/provenance | Historical 1.4.0 fixtures retained and passed without regeneration. |
| Exact-target Python/Rust interop | Passed locally on 2026-07-28 against `b48b96e6`; the CI lane is pinned to the same commit and tree. |
| Workspace and feature suites | `cargo test --workspace`, native hooks, WASM/built-in hooks and rns-ctl TLS passed locally; PR CI remains the final clean-environment authority. |
| Formatting and lint | `cargo fmt --check` and `scripts/lint-host.sh` passed locally; lint emitted only the accepted repository warning baseline. |
| Release/cross builds | Release `rns-server` with native hooks passed; cross builds were not rerun. |
| Docker E2E | Not rerun and not claimed by this promotion. |
| Hardware/manual validation | Physical Weave HIL was not rerun. The live dual-VPS backbone smoke passed on 2026-07-28, including announce/identity propagation, bidirectional packets, links and channel messages. |

## Caveats and Deferred Validation

- Local cryptographic verification of the upstream tag's SSH signature was not
  available without an allowed-signers file; both fetched upstream remotes and
  the annotated tag resolve to the recorded commit.
- Docker E2E, cross-compilation and physical Weave HIL were not rerun and are
  not claimed.
- Generated upstream manuals and changelog text are not vendored.

## Promotion Result

Reticulum 1.4.2 is accepted as the rns-rs upstream reference baseline at
normative commit `b48b96e61676504e0a4e527b33b9a0b4495c6872`. `UPSTREAM.md`,
the README badge and the exact CI interoperability lane record the promoted
baseline and its source-tree provenance.
