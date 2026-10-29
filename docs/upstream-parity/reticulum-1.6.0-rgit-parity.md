# Reticulum 1.6.0 rgit `5d38ce30` Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.6.0` |
| Previous normative commit | `9a01a20ce66c4146dd8f8d31f18c19fe7600739d` |
| Accepted version | `1.6.0` (unchanged; same-version rgit advancement) |
| Normative tag or ref | Canonical `rgit/master` tip (no signed `1.6.0` tag; upstream changelog still marks the release `Pending`; GitHub mirror behind at `e40191b3`) |
| Normative commit | `5d38ce3072e3cd9b4d5c05c21bf4940f866dfef5` |
| Root tree | `dd5fb64d2e3778f7f20f70db461148885ee20082` |
| `RNS` tree | `8bd88056db225a1a6bd7b0e76a1b99f3e0c667df` |
| Version assertion | `RNS.__version__ == "1.6.0"` |
| Audited range | `9a01a20ce66c4146dd8f8d31f18c19fe7600739d..5d38ce3072e3cd9b4d5c05c21bf4940f866dfef5` |
| Acceptance date | `2026-10-28` |
| Detailed audit | [reticulum-1.6.0-rgit-audit.md](reticulum-1.6.0-rgit-audit.md) |

This accepts a canonical `rgit/master` development tip without a version
bump, so it uses the qualified `-rgit` record filenames. The GitHub mirror
`master` is still at `e40191b3` (1.5.5) and contains none of the twenty
commits, so the rgit tip is the only normative target and the pinned CI interop
matrix cannot yet include 1.6.0. The twenty commits landed on rgit `master` in
two batches on 2026-10-28; the morning batch of fifteen through `ca6451a0` was
audited and interop-tested first, and the afternoon batch of five through
`5d38ce30` was audited, mapped, and gated the same day.

No conformance fixture was regenerated. The range adds a new announce
extension payload (stamp, and the 17-byte link cost anchor), 64-byte stamped
path requests, and stamped link request keys. The destination stamp encoding
carries a Python-provenance unit vector recorded in the detailed audit; all
three are exercised end to end by the live exact-target interop below, not by
the pinned fixture set.

## Upstream Commit Audit

Every commit has a final disposition and a unique non-empty mapping commit in
upstream ancestry order. The detailed audit records full hashes, changed paths,
and the mapping-hash table.

| Area | Upstream commits | Final handling |
|---|---|---|
| Destination stamps | `d1da5c3d`, `d2dd7308`, `d3ec00cd` | Integrated: announce stamp parse and strip, known-destination stamp persistence, rayon stamp generation, stamp store, RPC fields, defaults 23/23. The unexpanded-workblock divergence found by exact-target interop was fixed before promotion. |
| Path request stamps | `156c7323`, `7ec975fc`, `7c1b6486`, `8d587191`, `c3af1989`, `5d38ce30` | Integrated: 64-byte stamped path requests, validation, relay with the 0xFF unstamped-relay sentinel in both branches, unconditional transport identity, original-tag retention, oversized-tag truncation, and the upstream diagnostics. Emission stays off (`STAMP_PRS = false`). |
| Path culling | `51be88fb`, `c68066ed`, `ba3c4245` | Integrated or structurally covered: earliest-expiring unused paths culled first independent of insertion order; leaf linger 12 minutes; slow interfaces (below 25 kbps) linger ten times longer while never used; fast-interface paths culled before slow ones. |
| Link request stamps and cost | `30c6428e`, `9955e1bf`, `c37b5f7f`, `ba8c2d76`, `ca6451a0` | Integrated: link establishment cost carried in announces and persisted (SQLite user_version 2), stamped X25519 keys and stamped `Identity`, stamped link request validation, off-driver-thread stamped initiator with the 15 s timeout, default cost 11 and cap 40. Enforcement stays off (`LR_STAMPS_ENFORCED = false`). |
| Transport hop limiter | `134db17c` | Integrated: `HOP_LIMITER`, per-interface `hop_limiter_hits` counted separately from protocol violations and exported over management, RPC, and `rnstatus`. |
| Platform and cleanup | `4867e889`, `025f6d60` | Non-runtime: Python Android worker strategy (the rayon generator covers all native targets) and a log marker text. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | Destination stamp encoding verified by the Python-provenance vector `python_destination_stamp_vector_validates_with_unexpanded_workblock`; path request and link request stamps and the announce link-cost anchor verified by unit tests and by live exact-target interop (Python stamps accepted, Rust stamped link request accepted by Python); no pinned fixture changed. |
| Transport and interfaces | Hop limiter, slow-interface linger, unused-pool cull order, path request parsing, relay and truncation regressions pass in `rns-core` and the `rns-net` driver suite. Daily impaired dual-VPS Backbone smoke passes on the promoted binary. |
| Links, channels, and resources | Stamped link request handshake against a responder, deferred stamped initiator completion, timeout and shutdown cases, and the full Docker matrix including links, channels, resources, restart, scale, NAT hole punching, and shared-instance cases. |
| Utilities and APIs | `hop_limiter_hits` in management, RPC, and `rnstatus`; stamp and link-cost fields in RPC and SQLite; documented in `docs/configuration.md` (Stamps), `docs/rnstatus.md`, and `docs/interface-discovery.md`. |
| Live interop | Exact target `5d38ce30`: `python_interop` 3/3, including the new `python_rns_stamped_link_request_interop` case where Python 1.6.0 stamps its destination at value 23 and Rust answers with a cost-8 stamped link request; `utility_interop` 6/6. |

## Acceptance Record

| Gate | Result |
|---|---|
| Focused regression suites | Passed on 2026-10-28: `rns-core` (764), `rns-crypto` stamped key generation, `rns-net` stamps, link manager, driver stamped-link and hop-limiter cases, path request relay, path culling. |
| Fixture regeneration/provenance | Not applicable for the pinned fixture set; the destination stamp carries a Python-provenance unit vector and the remaining stamp surfaces are proven by live exact-target interop. |
| Exact-target Python/Rust interop | Passed on 2026-10-28 at `5d38ce30` from a disposable worktree with `import RNS` confirmed at 1.6.0: `python_interop` 3/3, `utility_interop` 6/6. |
| Workspace and feature suites | `cargo test --workspace --no-fail-fast` 2,961 passed; `cargo test --workspace --features rns-hooks` 3,020 passed; `cargo test -p rns-net --features rns-hooks-native --lib` 1,192 passed; `cargo test -p rns-ctl --features tls` 134 passed; built-in hook E2E 4/4 and the rns-ctl built-in hook API test passed. |
| Formatting and lint | `cargo fmt --all --check`, workspace `clippy --all-targets -D warnings`, and `bash scripts/lint-host.sh` passed. |
| Release/cross builds | Host native-hook builds produced `rns-server 0.6.1662-7e812d8` and `rns-ctl 0.7.1662-7e812d8`; all five ARMv7 build-smoke commands passed; `dist/rns-server-linux-x86_64.tar.gz` was produced. |
| Docker E2E | Full `tests/docker/run-all.sh` matrix passed twice on 2026-10-28: once on the pre-audit-fix tree (12 runs, 102 checks passed, 0 failed, 29 skipped, 987 s) and again on the promoted tree `7e812d8` after the Wasmtime feature trim (12 runs, 102 checks passed, 0 failed, 29 skipped, 906 s). The rns-server suite passed 84 checks, the shared-instance suites 40 each, shared-client reconnect 11, and NAT hole punching 12 in both passes. |
| Hardware/manual validation | The impaired dual-VPS `--daily` Backbone smoke passed on `rns-server 0.6.1662-7e812d8` at 2026-10-28T17:23Z (55 checks, 0 failures, 150 ms latency and 75 ms jitter per leg, forced reconnect recovered). Physical hardware validation remains unclaimed. |
| Python tools and web UI | Python tools compiled and all 19 unit tests passed; `node --test rns-ctl/assets/app.smoke.test.js` passed 4/4. |
| RustSec audit | `cargo audit` initially reported RUSTSEC-2026-0391, -0398, -0403, and -0410 in the zstd chain pulled by Wasmtime's default `cache` feature; `rns-hooks` now enables an explicit Wasmtime feature set without the cache, and the audit passes for the workspace and `rns-esp32/Cargo.lock`. |

## Caveats and Deferred Validation

- This is a canonical rgit development-tip acceptance, not a signed 1.6.0
  release acceptance. The GitHub mirror lags the accepted baseline and upstream
  still marks 1.6.0 as pending.
- The asynchronous stamper queue (`WorkerQueues`, `stamper_job`,
  `pr_stamp_cache`) was deferred at promotion and implemented the same day in a
  follow-up (`rns-net/src/stamper.rs`; see the audit's acceptance record).
  Own announces without a persisted stamp, own path requests and unstamped
  path requests forwarded for local clients are stamped on the worker thread.
  It is dormant while `STAMP_PRS` and `STAMP_DESTINATIONS` are false, as
  upstream.
- Per-destination link request cost (`Destination.set_link_cost`) and
  responder enforcement against the announced cost were deferred at promotion
  and implemented in a follow-up (`290d6cc`). `RnsNode::set_link_cost` clamps
  to `LINK_COST_CAP` like upstream, the stamped announce anchor carries the
  destination's cost (`get_link_cost`, default `LR_COST` 11), and with
  `LR_STAMPS_ENFORCED` (runtime key `global.lr_stamps_enforced`) the responder
  drops requests whose stamp value is below that cost. Evidence:
  `enforced_link_cost_drops_requests_below_the_destination_cost`,
  `enforced_link_cost_defaults_to_lr_cost_and_zero_disables`,
  `stamped_announce_carries_the_destination_link_cost`,
  `link_request_costs_default_clamp_and_share`, the rns-core clamp tests,
  e2e `test_stamped_link_cost_is_announced_ground_and_enforced`, and
  `python_rns_link_cost_announced_by_rust_interop` against Python 1.6.0 at
  `5d38ce30` (Python recalls the Rust-announced cost, grinds its request to
  it, and the enforcing Rust responder accepts the link). Enforcement stays
  off by default, as upstream.
- The 1.6.0 target cannot join the pinned CI interop matrix until the GitHub
  mirror carries it; exact-target interop remains a manual gate from a local
  rgit checkout.
- Two gate-run anomalies were recorded in the detailed audit and judged
  unrelated to the range: a one-off rustc 1.96.0 stall while compiling the
  `rns-git` test target, and a single ten second timeout in an `rns-git` test
  waiting for a spawned Python peer. Both passed on every rerun.
- No signature, signed release manifest, Android client, or ESP32 firmware
  validation is claimed by this promotion. Both VPS nodes still run `fa4936b`;
  deployment is a separate operator step.

## Promotion Result

Reticulum is accepted at `1.6.0`, normative commit
`5d38ce3072e3cd9b4d5c05c21bf4940f866dfef5`, as a same-version canonical
`rgit/master` advancement. [UPSTREAM.md](../../UPSTREAM.md) records this
baseline and links this record; the detailed work record is
[reticulum-1.6.0-rgit-audit.md](reticulum-1.6.0-rgit-audit.md).
