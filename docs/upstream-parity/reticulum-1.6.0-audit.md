# Reticulum 1.6.0 Upstream Audit

## Scope and Baseline

- audit date: `2026-10-25`
- previous accepted version: `1.5.7`
- previous normative commit: `ee82fa75a75ec67555126eb16796ea1a52716a2b`
- target version: `1.6.0` (upstream `Changelog.md` still marks the release `Pending`)
- target tag or ref: `rgit/master` tip (no tag contains the target)
- target normative commit: `9a01a20ce66c4146dd8f8d31f18c19fe7600739d`
- target root tree: `5c1bcc90971538c5df028fd9a40dc2e3cd1a5d94`
- target `RNS` tree: `461df28e901e3dd8ed3877a375c28e11a9fd2a0e`
- version assertion: `RNS.__version__ == "1.6.0"` at the target commit
- audited range: `ee82fa75a75ec67555126eb16796ea1a52716a2b..9a01a20ce66c4146dd8f8d31f18c19fe7600739d`
- commits in range: `8`
- repositories checked: normative `rgit` remote and the GitHub mirror
- local branch and revision inspected: detached `HEAD` at
  `ee82fa75a75ec67555126eb16796ea1a52716a2b`

The target is the fresh `rgit/master` tip, not a signed release. GitHub's tip
`e40191b3d193b46b7f2d8a44424a594cd758839b` is behind the accepted baseline and
is allowed to lag. The upstream version is known (`1.6.0`), so this audit uses
the versioned filename even though the release is still marked pending and no
tag contains the target.

This inventory was produced by the 2026-10-25 daily VPS check. All eight
mapping commits have landed in upstream ancestry order. Promotion is still
pending because upstream marks 1.6.0 as a pending release and no tag contains
the reviewed target; `UPSTREAM.md` remains on the 1.5.7 baseline.

## Audit Vocabulary

- **Needs port**: compatible behavior is absent or observably different.
- **Needs coordinated port**: related changes must be implemented together.
- **Needs decision**: architecture differs and the compatibility surface must
  be chosen explicitly.
- **Integrated**: applicable behavior is implemented with recorded evidence.
- **Structurally covered**: the Rust design already provides the behavior or
  avoids the upstream failure through a different invariant.
- **Documentation follow-up**: native documentation is required after the
  related behavior exists.
- **Deferred**: applicable work is deliberately postponed with rationale and
  impact recorded.
- **Non-runtime**: metadata, changelog, generated artifacts, or upstream-only
  tests require no independent Rust runtime change.

## Commit Inventory

| # | Upstream commit | Subject | Final disposition | Local evidence |
|---:|---|---|---|---|
| 1 | `f3ebec9cb1b93e467c0d15d56b501c7c9b350fa8` | Added ifstat parameters | Integrated | RNode phy telemetry now flows through `InterfaceTelemetry` into native status/RPC/`rns-ctl`; `signal_quality_matches_python_mapping_and_clamps`, `interface_stats_include_phy_telemetry`, and `interface_stats_pickle_format` regressions |
| 2 | `e24d2073123cd4c624b5ebd1e8b09d83fa78ceab` | Merged staging | Integrated | SQLite known-destination/ratchet and announce-cache stores with legacy import and file fallback; path usage/culling; `rnpath --usage`; expanded status counters and `link_distribution`; focused regressions |
| 3 | `af8d05819d363240c133e4bc644bfde0d4620a71` | Updated version | Non-runtime | Version metadata only; target remains `1.6.0` pending release; no Rust version change until promotion |
| 4 | `044d4c9adc4781165eea1fa223ece5ef278df787` | Added internal stamps module | Structurally covered | Native stamps in `rns-core/src/stamp.rs`, discovery validation in `rns-net/src/common/discovery.rs`, and `generated_discovery_stamp_is_accepted_without_external_stamper` |
| 5 | `156290733e50011028dc38fca14fd047dc02cb36` | Added canonical gc handling and platform-aware malloc trim | Structurally covered | Rust has no cyclic GC; the platform `malloc_trim` calls are Python-allocator-specific and have no native equivalent to port |
| 6 | `3e83fcc18b4cae4372b36b0d0cb48f2a904d0974` | Memory management | Deferred | Keep jemalloc defaults per `bench/relay/allocator-findings.md`; revisit only with native RSS evidence |
| 7 | `4ebd4dcc5b6cd3ed4683f38ac50dc60a02850e20` | Fixed invalid paths in docs | Non-runtime | Upstream documentation paths only; native `rnsh` already uses its `~/.rns` identity paths |
| 8 | `9a01a20ce66c4146dd8f8d31f18c19fe7600739d` | Cleanup | Integrated | Discovery rejects hop counts above `PATHFINDER_M-1` before stamp validation; `discovery_rejects_hop_count_at_pathfinder_limit` |

## Per-Commit Analysis

### 1. `f3ebec9` — Added ifstat parameters

**Upstream change:** Adds `rssi`, `snr`, `signal_quality`, `frequency`,
`bandwidth`, `txpower`, `sf`, `cr`, `channel`, and `modulation` to the
`ifstats` entries in the RPC/status structure, and initialises
`r_modulation = "LoRa"` on `RNodeInterface` and `RNodeMultiInterface`.

**Rust applicability:** The native RNode driver already parses RSSI, SNR,
airtime, and related statistics, but the control-plane/status output does not
publish the complete phy-stat set or the modulation label.

**Local handling and evidence:** The native RNode reader now publishes the
radio configuration and the latest RSSI/SNR through `InterfaceTelemetry`.
`signal_quality` follows Python's spreading-factor-dependent mapping and is
clamped to 0..100 with one decimal place. The driver stores the values in
`InterfaceStats`, and both the shared-instance pickle status and the remote
management msgpack status expose `rssi`, `snr`, `signal_quality`, `frequency`,
`bandwidth`, `txpower`, `sf`, `cr`, `channel`, and `modulation`; `rns-ctl`
exposes the same fields on `/api/interfaces`. Focused regressions:
`signal_quality_matches_python_mapping_and_clamps`,
`interface_stats_include_phy_telemetry`, and
`interface_stats_pickle_format` (the last now asserts the new keys).

**Final disposition:** Integrated.

### 2. `e24d207` — Merged staging

**Upstream change:** The core 1.6.0 feature commit. It adds path usage
tracking (`path_table[hash][7]`), unused-path pool monitoring and culling,
`PATH_TIMEOUT`/`UNUSED_PATH_LINGER` semantics, and an announce rate table
rewrite. It also introduces `RNS/Storage.py` with a SQLite-backed
`KnownDestinationsStore` and `AnnounceCache`, imports legacy known-destination
and ratchet files into that database, persists cached announces, adds new
status metrics (`rxpkts`, `txpkts`, announce/proof counters, link counts, path
pool counts), adds `rnpath --usage`, and adds `link_distribution` to the RPC.
It also fixes the RNode phy-stat Android regression and the `rngit` config path
typo noted in the changelog.

**Rust applicability:** This is the largest compatibility surface in the
range. The native engine already owns a typed path table, file-based known
destinations with `last_used_at`, file-based ratchets, packet hashlist, and
announce rate defaults, but the following observed behaviors are absent or
different:

- per-path usage timestamps and `rnpath --usage` output;
- unused-path pool target (`PATH_POOL_UNUSED_TARGET`) and leaf linger rules;
- SQLite managed storage with legacy import fallback;
- cached-announce persistence backed by that store;
- the expanded status counters and link/path-pool distribution fields.

**Local handling and evidence:** `rns-core/src/transport/tables.rs`
`PathEntry` has no usage field. `rns-net/src/storage.rs` implements
`KnownDestination` with `last_used_at` and an `FsRatchetStore`, not a SQLite
store. `rns-net/src/common/event.rs` has `PathTableEntry` but no usage field.
The hashlist and rate-table mechanisms exist but are not the upstream
implementations. No native `rnpath` usage flag or `link_distribution` RPC was
found.

**Local handling and evidence:** The operator chose to port the SQLite backend.
Native `rns-net/src/storage_sqlite.rs` now implements the upstream
`known_destinations` and `ratchets` schema with a `known_destination_meta`
side table for native hops/interface/retained state. It imports legacy msgpack
known-destination files and ratchet directories, falls back to the previous
file stores when SQLite cannot be opened, and enforces ratchet expiry and
unknown-destination cleanup. `rns-net/src/announce_cache.rs` now writes
`announces.db` with the upstream `cached_announces` schema, imports legacy
announce files, and retains the file backend as a fallback.

Path usage is tracked in `PathEntry.used`, set when an outbound packet uses a
path, persisted with transport state, and exposed through the path table and
`rnpath --usage`. Never-used paths linger for 1.75 hours on transport instances
(5 minutes on leaves) and the unused pool is capped at 2048 destinations.
Status responses now include total packet and announce/path-request counters,
link totals/active/pending counts, and path-pool total/unused/active counts;
`link_distribution` is available through the RPC and remote management. The
native announce rate table and packet hashlist already provide the upstream
optimizations through different data structures and need no separate port.

The native shared-instance client does not own a known-destination table; it
queries the daemon, so upstream's read-only client load has no direct native
equivalent. The `packet_hash` column is stored as zero because the native
in-memory known-destination state does not retain the announce packet hash;
RNS does not read that column for transport decisions.

Focused regressions cover the SQLite round trip, legacy known-destination and
ratchet import, read-only behavior, announce-cache store/reopen/clean/import and
file fallback, path usage marking, unused-path linger and pool culling,
`path_pool_counts`, and `link_distribution`.

**Final disposition:** Integrated.

### 3. `af8d058` — Updated version

**Upstream change:** Bumps `RNS/_version.py` from `1.5.7` to `1.6.0`.

**Rust applicability:** Version metadata only. The target version is now known,
but the upstream release is still marked pending and no target tag exists.

**Local handling and evidence:** `UPSTREAM.md` still records the 1.5.7 baseline
commit. No promotion is attempted by this audit; the target version and ref are
recorded in the scope section for the eventual promotion.

**Final disposition:** Non-runtime.

### 4. `044d4c9` — Added internal stamps module

**Upstream change:** Adds `RNS/Stamps.py` (workblock expansion, stamp value,
stamp validation, and platform-specific parallel stamp generation) and switches
interface discovery from the optional `LXMF.LXStamper` dependency to the
internal module. Removes the LXMF installation note from the discovery docs.

**Rust applicability:** The native implementation already performs the same
proof-of-work algorithm for discovery. The LXMF dependency removal is specific
to the Python package layout and has no Rust runtime equivalent.

**Local handling and evidence:** `rns-core/src/stamp.rs` implements
`stamp_workblock`, `stamp_value`, `stamp_valid`, and `leading_zeros`, with
tests. `rns-net/src/discovery.rs` generates discovery stamps with
`generate_discovery_stamp`; `rns-net/src/common/discovery.rs` validates them
before accepting an interface. Discovery uses these native functions rather
than an external LXMF module.

Mapping commit adds `generated_discovery_stamp_is_accepted_without_external_stamper`,
which generates a stamp through the native discovery path and revalidates it
with the native workblock/stamp functions.

**Final disposition:** Structurally covered.

### 5. `1562907` — Added canonical gc handling and platform-aware malloc trim

**Upstream change:** Replaces scattered `gc.collect()` calls with a single
`garbage_collect()` helper and adds a throttled, platform-aware `trim_heap()`
that calls `malloc_trim` (Linux), `malloc_zone_pressure_relief` (macOS),
`mallopt(M_PURGE)` (Android), or `HeapTrim` (Windows). It also tracks
`should_collect` and `mem_dirty` on `Transport`.

**Rust applicability:** Rust has no cyclic garbage collector and the native
crates do not manage Python objects. The observable intent is reducing RSS
after large tables are culled; whether a comparable allocator-level trim is
useful depends on the selected global allocator and deployment configuration.

**Local handling and evidence:** No native equivalent of `gc.collect()` or
`malloc_trim()` policy exists. The workspace uses Rust allocator crates
(for example `tikv-jemallocator`) in some binaries. Adopting upstream's
libc-specific calls verbatim would not be meaningful.

The operator decision is to make no production memory-policy change. Rust has
no cyclic garbage collector, so the canonical `gc.collect()` batching has no
native equivalent. The platform trim calls target CPython's allocator, while
the native daemon uses jemalloc; `bench/relay/allocator-findings.md` recommends
keeping that allocator and not tuning arena/decay settings without separate
native evidence. This commit is therefore structurally covered by the native
runtime's different memory model.

**Final disposition:** Structurally covered.

### 6. `3e83fcc` — Memory management

**Upstream change:** Refines the previous commit: raises the collection
throttle to 1440 seconds, adds `mem_trim_gate_mb = 8`, tracks the last RSS,
reads `VmRSS` from `/proc/self/status`, and only trims when RSS has grown by at
least the gate. Adds `MALLOC_ARENA_MAX=2` to the example systemd units and
documents the setting.

**Rust applicability:** The RSS-gated `malloc_trim` policy is tied to Python's
allocator behavior. A native daemon may still benefit from an arena or
allocator limit, but that is an explicit deployment choice rather than a direct
port.

**Local handling and evidence:** No `VmRSS`-gated trim logic or
`MALLOC_ARENA_MAX` guidance exists in the native runtime. The release binaries
and service packaging would need a deliberate allocator decision.

The operator decision is to defer this change. The RSS-gated `malloc_trim` and
`MALLOC_ARENA_MAX=2` guidance target glibc/Python deployments. The native
daemon's allocator findings record mixed RSS/latency results and explicitly
recommend keeping jemalloc with no production arena or decay tuning. There is
no native evidence that the upstream threshold or arena limit would improve the
daemon, so the policy remains unchanged until a native RSS regression is
measured.

**Final disposition:** Deferred.

### 7. `4ebd4dc` — Fixed invalid paths in docs

**Upstream change:** Corrects documented storage paths for `rncp`, `rnx`, and
`rnsh` (`storage/identities`, `~/.rns/identity`).

**Rust applicability:** Documentation-only change in the upstream repository.
No protocol or runtime behavior changes.

**Local handling and evidence:** No native runtime mapping is required. Native
documentation should be checked separately if it makes the same obsolete path
claims, but that is not an upstream runtime behavior.

Native `rnsh` already resolves its default initiator and listener identities
under the `~/.rns` directory and migrates the older storage path, so this
upstream documentation correction does not imply a runtime change here.

**Final disposition:** Non-runtime.

### 8. `9a01a20` — Cleanup

**Upstream change:** In `InterfaceAnnounceHandler`, computes
`hops = RNS.Transport.hops_to(destination_hash)` once and rejects the discovered
interface when `hops > RNS.Transport.PATHFINDER_M-1`, before checking caches or
validating the stamp. Reuses the computed value in the discovered-interface
entry.

**Rust applicability:** Native packet-header and inbound layers already bound
hop counts, but the discovery handler needed the same handler-level gate before
stamp work.

**Local handling and evidence:** `parse_interface_announce_with_cache` now
rejects announcements with `hops > PATHFINDER_M - 1` before consulting the stamp
cache or performing stamp validation, matching upstream's handler-level gate.
The focused `discovery_rejects_hop_count_at_pathfinder_limit` regression proves
that `PATHFINDER_M - 1` is accepted and `PATHFINDER_M` is rejected.

**Final disposition:** Integrated.

## Mapping Verification

| Upstream commit | Local mapping commit |
|---|---|
| `f3ebec9cb1b93e467c0d15d56b501c7c9b350fa8` | `e218481581d6264cfc43597a3e3ffc0d327d1b2c` |
| `e24d2073123cd4c624b5ebd1e8b09d83fa78ceab` | `2a49e91914307ff6bf4bce6d5b8e807f0d219330` |
| `af8d05819d363240c133e4bc644bfde0d4620a71` | `157513605e5b08614e07545104c75790aa7ee763` |
| `044d4c9adc4781165eea1fa223ece5ef278df787` | `f642ee2b221fa5b64b8e70f7629cce47401370e2` |
| `156290733e50011028dc38fca14fd047dc02cb36` | `5446867c9a0f8a50b1629bf328538b8189a8fba8` |
| `3e83fcc18b4cae4372b36b0d0cb48f2a904d0974` | `9ab0470d57dc172ab68eada505448147b301a440` |
| `4ebd4dcc5b6cd3ed4683f38ac50dc60a02850e20` | `217e1f7262db6655c4f234153a53cc6345ad7f0d` |
| `9a01a20ce66c4146dd8f8d31f18c19fe7600739d` | `9174bd061008459e7eb573fde5c01246796592da` |

Each mapping commit is non-empty, appears in the same ancestry order as the
upstream range, and carries exactly one `Upstream-Commit` trailer for its
reviewed hash.

## Integration Plan

All eight commits have a final disposition and a unique mapping. No mapping
work remains outstanding. Promotion is deliberately not performed: upstream
marks 1.6.0 as pending and no signed tag contains the reviewed target, so
`UPSTREAM.md`, the README badge, and the parity-record set remain at 1.5.7.

## Promotion Gates

- [x] Every upstream commit has a final disposition.
- [x] Focused regressions pass for every applicable behavior change.
- [x] No wire, crypto, or fixture format changed; transport-state and SQLite
  storage round-trip tests cover the new persistence fields.
- [x] Exact-target live Python/Rust interop passes at `9a01a20`:
  `python_interop` 2/2 and `utility_interop` 6/6.
- [x] Workspace tests, formatting, and warning-free lint pass.
- [ ] Required build, Docker, hardware, and manual gates are complete: the
  release builds, Docker E2E (84/84), and impaired dual-VPS `--daily` smoke
  passed, but physical hardware validation remains unclaimed.
- [x] Native documentation records the SQLite stores and `rnpath --usage`.
- [ ] A final parity record is created from `PARITY-TEMPLATE.md` (blocked on the
  pending 1.6.0 release target).

## Acceptance Record

- `2026-10-25`: Landed the eight mapping commits in upstream ancestry order,
  each with one full `Upstream-Commit` trailer.
- `2026-10-25`: `cargo test --workspace`, `cargo fmt --all --check`, and
  `bash scripts/lint-host.sh` passed.
- `2026-10-25`: Native-hook release builds produced
  `rns-server 0.6.1622-9174bd0` and `rns-ctl 0.7.1622-9174bd0`.
- `2026-10-25`: Exact-target interop at `9a01a20` passed: `python_interop`
  2/2 (`python_rns_bidirectional_tcp_interop`,
  `python_rns_local_ratchets_bidirectional_and_restart`) and
  `utility_interop` 6/6.
- `2026-10-25`: Docker `tests/docker/rns-server/run.sh` passed 84 checks with
  0 failures.
- `2026-10-25`: The impaired dual-VPS `--daily` Backbone smoke passed on the
  new binary at 2026-10-25T07:49:23Z; output is in
  `data/smoke-logs/integration-2026-10-25T074923Z.log`.
- `2026-10-25`: Physical hardware validation remains unclaimed. No deployment,
  restart, or reconfiguration of the VPS nodes was performed as part of this
  integration.

Evidence:

- `data/upstream-drift-2026-10-25.json`: fresh drift report with both remote
  fetch timestamps and the eight-commit inventory.
- `data/daily-report-2026-10-25.md`: daily operational report for the check that
  produced this audit.
- `data/smoke-logs/integration-2026-10-25T074923Z.log`: passing impaired
  dual-VPS `--daily` Backbone smoke run on the integrated binary.
