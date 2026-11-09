# Reticulum 1.6.0 rgit `c5d205ff` Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.6.0` (rgit `5d38ce30`) |
| Previous normative commit | `5d38ce3072e3cd9b4d5c05c21bf4940f866dfef5` |
| Accepted version | `1.6.0` (unchanged; same-version rgit advancement through the signed `1.6.0` release) |
| Normative tag or ref | Canonical `rgit/master` tip; the annotated, signed `1.6.0` tag is on `cb1260891d1b6da8f6e9b21542c4f0cc0725cac4`, three documentation-only commits earlier; the GitHub mirror agrees with rgit |
| Normative commit | `c5d205ffea16ef4519150745edf644dd03e48e5f` |
| Root tree | `3fff894a0f6a2c273cc1b03c7c884ca17bb48684` |
| `RNS` tree | `3448fb48deaf018bbe6e8a04795fa085bef2f2b9` (identical at the `1.6.0` tag) |
| Version assertion | `RNS.__version__ == "1.6.0"` |
| Audited range | `5d38ce3072e3cd9b4d5c05c21bf4940f866dfef5..c5d205ffea16ef4519150745edf644dd03e48e5f` (65 commits) |
| Acceptance date | `2026-11-09` |
| Detailed audit | [reticulum-1.6.0-rgit-2-audit.md](reticulum-1.6.0-rgit-2-audit.md) |

This is the second same-version rgit advancement for 1.6.0, so it uses the
`-rgit-2` record filenames; the earlier `1.6.0` and `-rgit` records stay
unchanged. Unlike those, the range now contains upstream's actual 1.6.0
release: commit 62 (`cb126089`, "Prepare release") carries the annotated
`1.6.0` tag with an SSH signature, which was not verified here. The accepted
commit is the rgit tip, three commits after the tag; they change
documentation only, so the `RNS` package tree at the tip is byte-identical to
the released one. The GitHub mirror, which lagged at `e40191b3` through the
previous acceptances, caught up with rgit during the range, so 1.6.0 joins the
pinned CI interop matrix with this promotion.

The range was audited in daily batches from 2026-10-29 to 2026-11-09 as rgit
advanced. No conformance fixture was regenerated. The stamp wire formats it
introduces or changes (fractional values on the 1/256 grid, the announce
extension with the destination's link cost, stamped path requests on
rediscovery) are pinned by unit vectors recorded in the audit and exercised by
live exact-target interop.

## Upstream Commit Audit

Every commit has a final disposition and a unique, non-empty mapping commit
in upstream ancestry order; the detailed audit records full hashes, changed
paths, analyses and the mapping table.

| Area | Upstream commits | Final handling |
|---|---|---|
| Stamp configuration and fractional values | 1, 3, 5, 6, 7, 8, 9, 10, 48 | Integrated: the `[stamps]` section and its runtime keys, `NodeConfig::stamps` and `global.stamps_enforced`, path request stamp timeout and cancellation, fractional costs and values on the 1/256 grid with upstream's quantisation, cost display, link request cost fallback, defaults 23.5 / 25 / 15.8 / 15.8 / 12.5 and 15 s timeouts. `75465efa` is structurally covered by native integer types. |
| Per-interface stamp costs and parameter inheritance | 13, 15 | Integrated or structurally covered: per-interface `destination_cost` and `pr_cost`, inherited by spawned interfaces, carried in discovery announces and over RPC. |
| Resources | 16, 17 | Integrated: `app_flag` signalling and getter, advertisements over the link MDU packed without their hashmap, and the `HASHMAP_IS_EMPTY` request. |
| Storage | 20, 21, 22, 23, 24, 25, 42, 43, 44, 47 | Integrated or structurally covered: SQLite schema constraint fix, pre-release migrations (one transaction, as `create_schema` already ran them), storage error handling, pragma ordering; statement caching, a stale locking comment and the ratchet directory walk do not apply to the native store. |
| Utilities, RPC and logging | 19, 26, 27, 28, 29, 30, 31, 32, 36, 38, 40, 45, 46 | Integrated or structurally covered: stamp cost and value display in `rnstatus` and `rnpath`, RPC error handling, protocol violation and diagnostic logging; Python-only log messages and an f-string quoting fix need no native change. |
| Announce processing | 33, 34, 41 | Integrated or structurally covered: announce validation caching and handler callback performance. |
| Destination type filtering and hop limiter | 35, 54 | Integrated: the `[filter]` section (`ignored_types`, `required_only`, `allowed_types`), type registration over RPC and from the utilities, and `hop_limiter` read from `[filter]` with the `0..=128` clamp. |
| Path requests and rediscovery | 39, 52 | Integrated: path request protocol violations dropped; link-table path rediscovery, missing before the baseline, ported with the stamped rediscovery requests. |
| Built-in destinations | 50 | Integrated: the published blackhole destination requires a 5.25 link cost, and built-in destination announces are stamped when destination stamping is on. |
| Links | 11, 56 | Structurally covered: a native link exists only once its keys do, so there is no pre-init `link_id` access; upstream restored the missing `not` in `Link.validate_request`; the native responder always dropped insufficient stamps, so the divergence recorded earlier in the range ended. |
| Stamp workers | 18, 37, 49, 51, 60 | Structurally covered: Python worker pooling and Android job handling have no native counterpart; destination stamps are ground per destination on the stamper, and an announce whose stamp cannot be produced is cancelled. |
| Documentation, changelog and release | 2, 4, 12, 14, 53, 55, 57, 58, 59, 61, 62, 63, 64, 65 | Non-runtime: every claim in the new "Protecting Open Networks" manual page and the 1.6.0 changelog was checked against the native code; the documented defaults, held-announce dropping and the 0.27% fractional step are pinned by tests. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | Fractional stamp grid and quantisation vectors, the announce extension's link-cost bytes pinned to upstream's for 12.5 and 14.2, the per-step difficulty test, stamped path request and link request round trips; no pinned fixture changed. |
| Transport and interfaces | Path rediscovery, hop limiter in `[filter]`, destination type filtering, held announces dropped with their interface, per-interface stamp costs and announce limits, protocol violation handling; `rns-core` and `rns-net` driver suites. The impaired dual-VPS Backbone smoke passed on the promoted binary. |
| Links, channels, and resources | Link request cost enforcement and fallback, `app_flag` and MDU-packed advertisements, the full Docker matrix including links, channels and resources. |
| Utilities and APIs | `rnstatus` and `rnpath` cost display, RPC fields, `NodeConfig::stamps`, runtime keys, destination type registration; documented in `docs/configuration.md`. |
| Live interop | Exact target `c5d205ff` on the promoted tree `0a2f98d9`: `python_interop` 4/4, `utility_interop` 12/12; the same at the previous baseline `5d38ce30`. |

## Acceptance Record

Gates were run on 2026-11-09 on the promoted tree `0a2f98d9` (`origin/master`
`39357f14`, the per-interface announce limits fix `807c62ba` and the
`rusqlite` upgrade `0a2f98d9`) unless noted.

| Gate | Result |
|---|---|
| Focused regression suites | Passed: the tests named in the audit's analyses of commits 1 to 65, and the announce limits tests. |
| Fixture regeneration/provenance | Not applicable; no pinned fixture changed. |
| Exact-target Python/Rust interop | Passed at 11:48Z against a disposable export of `c5d205ff` (`import RNS` reports 1.6.0): `python_interop` 4/4, `utility_interop` 12/12. |
| Workspace and feature suites | `cargo test --workspace` 3,208 passed; `cargo test --workspace --features rns-hooks` 3,274 passed; `cargo test -p rns-net --features rns-hooks-native --lib` 1,352 passed; `cargo test -p rns-ctl --features tls` 134 passed; `rns-net` with the four `compact-threads-*` features 1,408 passed; built-in hook E2E 4/4 and the `rns-ctl` built-in hook API test passed; the no-default-features checks passed. All with 0 failures. |
| Formatting and lint | `cargo fmt --all --check`, workspace `clippy --all-targets -D warnings` and `bash scripts/lint-host.sh` clean. |
| Release/cross builds | Host native-hook build produced `rns-server 0.6.1890-0a2f98d9` and `rns-ctl 0.8.1890-0a2f98d9`; all five ARMv7 build-smoke commands passed; `dist/rns-server-linux-x86_64.tar.gz` was produced. |
| Docker E2E | Locally, 8 of the 10 matrix runs passed (109 checks passed, 0 failed, 31 skipped, 392 s). The other two could not start on this workstation: the 30-node scale run needs host ports 8081 to 8110 and 8095 is held by an unrelated service, and the NAT hole punching network's fixed 172.22.0.0/24 subnet overlaps an unrelated Docker network. The full matrix is the CI `Docker E2E` job on the promotion pull request. |
| Hardware/manual validation | The impaired dual-VPS `--daily` Backbone smoke passed on `rns-server 0.6.1890-0a2f98d9` (55 checks, 0 failures, 150 ms latency and 75 ms jitter per leg, forced reconnect recovered). Physical hardware validation is not claimed. |
| Python tools and web UI | Python tools compiled and 19 unit tests passed; `node --test rns-ctl/assets/app.smoke.test.js` passed. |
| RustSec audit | `cargo audit` reported RUSTSEC-2026-0459 (CVE-2026-119375, medium) in the C SQLite bundled by `libsqlite3-sys` 0.38.2; `rusqlite` 0.41 brings `libsqlite3-sys` 0.39.1, after which the audit is clean for the workspace and `rns-esp32/Cargo.lock`. |

## Caveats and Deferred Validation

- The `1.6.0` tag's SSH signature was not verified (no allowed signers file
  is configured); no signature, signed release manifest, Android client or
  ESP32 firmware validation is claimed.
- The interface discovery options `publish_ifac`, `discovery_encrypt`,
  `discovery_frequency`, `discovery_bandwidth` and `bootstrap_only`, which
  upstream reads from interface sections, have no native implementation.
  They predate this range and were found by comparing the upstream interface
  parser with the native one during this audit; they remain open.
- The per-interface `announce_rate_target`, `announce_rate_grace`,
  `announce_rate_penalty` and `announce_cap` options, found missing by the
  same comparison, were ported before promotion (`807c62ba`). They add a
  public field to `InterfaceConfig`, `StartContext` and
  `DynamicInterfaceTemplate`, so `rns-net`'s next release is a minor bump.
- Two Docker matrix runs could not start locally for workstation reasons (see
  the acceptance record); the CI job is their authority.
- Upstream states that some 1.6.x release will make `required_only` the
  default for non-transport instances and that 1.6.1 and 1.6.2 will enable
  stamp emission and enforcement by default. The native defaults follow the
  current upstream ones and will change with those releases.
- Both VPS nodes run `a27e8718`, which has the range up to commit 52 and the
  proof fix but not commits 53 to 65, the announce limits fix or the
  `rusqlite` upgrade; deployment is a separate operator step.

## Promotion Result

Reticulum is accepted at `1.6.0`, normative commit
`c5d205ffea16ef4519150745edf644dd03e48e5f`, as a same-version canonical
`rgit/master` advancement that includes the signed `1.6.0` release.
[UPSTREAM.md](../../UPSTREAM.md) records this baseline and links this record;
the detailed work record is
[reticulum-1.6.0-rgit-2-audit.md](reticulum-1.6.0-rgit-2-audit.md).
