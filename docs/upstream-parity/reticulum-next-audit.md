# Reticulum Next Upstream Audit

## Scope and Baseline

- audit date: `2026-11-14`
- previous accepted version: `1.6.0`
- previous normative commit: `134dc6777c0dd29404e61b36d4094f4e35b88b3e`
- target version: `1.6.0` (pending: no version bump in range)
- target tag or ref: `rgit/master` (pending promotion target)
- target normative commit: `c850cdac6c8bd5422af045652216ba451e98aa33`
- target root tree: `af323f9220c51ea4925a2b2d5422a61d6f917a07`
- target `RNS` tree: `77efe59cff06d6c9c17a7ecbd9b1f53308d44759`
- version assertion: `RNS.__version__ == "1.6.0"`
- audited range: `134dc6777c0dd29404e61b36d4094f4e35b88b3e..c850cdac6c8bd5422af045652216ba451e98aa33`
- commits in range: `13`
- repositories checked: rgit `master` (normative) and the GitHub mirror `master`
- local branch and revision inspected: `dev@9aa6de76b6bc5a67042f892af4481f6d8572d554`

Found by the 2026-11-14 daily drift check (`data/upstream-drift-2026-11-14.json`),
both remotes refreshed fresh. The GitHub mirror tip `3c4b271f` lags behind the
accepted baseline; all 13 commits are reachable only from rgit `master`.
No version bump, so the target version and promotion target stay pending.

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

Every commit in the audited range appears exactly once, in ancestry order.

| # | Upstream commit | Subject | Final disposition | Local evidence |
|---:|---|---|---|---|
| 1 | `54159d1d93237612239f19653f6a99b8a62708b3` | Cleanup | Non-runtime | `InboundFrame::iface` invariant documented (`rns-core/src/transport/mod.rs`) |
| 2 | `04585ff2a8af37ee1683aca03d001cd49ae8399a` | Cleanup | Non-runtime | Formatting-only; audit records the diff review |
| 3 | `6852971d3c8e0e0d055bdb1472b51fa6de87b3a9` | Logging cleanup | Non-runtime | Log-only; no equivalent Rust log line |
| 4 | `d5f1e014dbec2921d70b8acd15c820601de6525d` | Persist and load announce rate table | Integrated | `storage/announce_rate_table` (`RNSART` v1) save/load; upstream-generated fixture `tests/fixtures/transport/announce_rate_table_d5f1e014.bin`; `announce_rate_block_survives_snapshot_restore` and storage tests |
| 5 | `01e7ed84433ee3e9a64643e40e892ccfcdb85243` | Refactored traffic accounting | Structurally covered | `every_received_frame_is_charged_once_to_received_or_filtered`; `record_filtered_inbound` doc |
| 6 | `d183791956f807c92d5eb0a9f9bc9e12f9135cd1` | Refactored traffic accounting | Pending review | Changes `RNS/Transport.py` |
| 7 | `819076c3783565dc303abb2894c99e6ce6074342` | Track filtered announce count per interface | Pending review | Changes `RNS/Interfaces/Interface.py`, `RNS/Reticulum.py`, `RNS/Transport.py`, `RNS/Utilities/rnstatus.py` |
| 8 | `daec67a116347b28e2268beb1d7b004f827eebb2` | Cleanup | Pending review | Changes `RNS/Transport.py` |
| 9 | `3281e283154af393ba1a521eaba4246a32d52f1f` | Added tunnel info to rnstatus | Pending review | Changes `RNS/Interfaces/Interface.py`, `RNS/Reticulum.py`, `RNS/Transport.py`, `RNS/Utilities/rnstatus.py` |
| 10 | `464e75986e06b4ad2050a5a4c572159ae2c2d647` | Added remote transport ID info to rnstatus | Pending review | Changes `RNS/Interfaces/BackboneInterface.py`, `RNS/Interfaces/I2PInterface.py`, `RNS/Interfaces/Interface.py`, `RNS/Interfaces/TCPInterface.py`, `RNS/Reticulum.py`, `RNS/Transport.py`, `RNS/Utilities/rnstatus.py` |
| 11 | `56b23c4810d477ed82daf06f2e34ac0a69d87bfc` | Typo | Pending review | Changes `RNS/Reticulum.py` |
| 12 | `350b7e2614960cd6f521031cec966462c9f216c9` | Added ability to blackhole remote transport nodes | Pending review | Changes `RNS/Reticulum.py`, `RNS/Transport.py`, `RNS/Utilities/rnstatus.py` |
| 13 | `c850cdac6c8bd5422af045652216ba451e98aa33` | Traffic counting | Pending review | Changes `RNS/Interfaces/Interface.py`, `RNS/Transport.py` |

## Per-Commit Analysis

### 1. `54159d1d` — Cleanup

**Upstream change:** Removes the `if packet.receiving_interface` / `!= None` guards around the oversized-announce, invalid-signature, oversized and tagless path request, and invalid path request size protocol violations, and around the `received_announce` / `received_path_request` counters in `Transport.inbound`. `preprocess_inbound` already returns early when no interface is set, so every removed guard was always true; behavior and counters are unchanged.

**Rust applicability:** `InboundFrame::iface` is a required `InterfaceId`, so the engine cannot receive an interface-less frame and has no equivalent guards to remove.

**Local handling and evidence:** Mapping commit documents the invariant on `InboundFrame::iface`. No behavior change; `cargo test -p rns-core` passes.

**Final disposition:** Non-runtime.

### 2. `04585ff2` — Cleanup

**Upstream change:** Joins `if packet.destination_type == RNS.Destination.SINGLE: return True` onto one line in `Transport.packet_filter`. The full diff contains no other change and no control-flow change.

**Rust applicability:** None; Python source formatting.

**Local handling and evidence:** Full diff reviewed; no Rust change. Audit-only mapping.

**Final disposition:** Non-runtime.

### 3. `6852971d` — Logging cleanup

**Upstream change:** In `Identity.__finalize_av` the EXTREME-level "Valid announce for ..." log block moves inside the `not cache_hit or destination unknown` branch, so it is written only when the announce is (re-)remembered, not on every signature-cache hit. A stale `# TODO` comment is dropped. Remembering, ratchets, the caches and the return value are unchanged.

**Rust applicability:** rns-rs emits no per-announce "Valid announce" log line, and log text is not a compatibility surface.

**Local handling and evidence:** Full diff and the enclosing `__finalize_av` reviewed; no Rust change. Audit-only mapping.

**Final disposition:** Non-runtime.

### 4. `d5f1e014` — Persist and load announce rate table

**Upstream change:** `AnnounceRateTable` gains `persist`/`load` for a new binary file `storage/announce_rate_table`. The format is a 16-byte header (magic `RNSART`, version 1, zero flags, ring size, key length, two reserved bytes, u32 LE entry count), then little-endian columns: keys, `last` f64, `blocked_until` f64, `rate_violations` i32, ring length u8, ring head u8, and the timestamp ring (`max_ts` f64 per entry). Loading rejects the whole file on any header, size, duplicate-key or ring-cursor inconsistency, and replays rings of a different size oldest first. `Transport` loads the file at start when transport is enabled and the node is not a shared-instance client; a load failure logs a warning and keeps an empty table. `persist_data` saves it beside the packet hashlist, path table and tunnels (no retention filter). Rate penalties and accumulated violations therefore survive a restart.

**Rust applicability:** rns-rs already persists `packet_hashlist.raw`, `destination_table` and `tunnels` in upstream layouts from `TransportEngine::persistence_snapshot`. These are written only when transport is enabled, at the same points as upstream `persist_data`. The rate table (`AnnounceRateLimiter`, `RateEntry` with oldest-first timestamps capped at `MAX_RATE_TIMESTAMPS` = 16) was not persisted, so a restart reset every penalty: needs port.

**Local handling and evidence:** `TransportStateSnapshot` gains `announce_rates` (`PersistedAnnounceRate`); `persistence_snapshot` exports every rate entry and `restore_persistence_snapshot` restores them, keeping the newest 16 timestamps (`AnnounceRateLimiter::restore`). `rns-net/src/storage.rs` writes and reads `announce_rate_table` in the exact `RNSART` v1 layout with upstream's validation. Rings are written oldest first from slot 0 with `head = len % 16`, which upstream's ring logic treats identically. An unreadable file logs a warning and restores empty without failing the other tables. Evidence: `tests/generate_announce_rate_table_fixture.py` produced the 348-byte fixture with upstream's own `persist` at `d5f1e014` (deterministic across two runs; entry A has a wrapped ring and an active block). `upstream_announce_rate_table_decodes_with_wrapped_rings_in_order` decodes it. `announce_rate_table_encoding_matches_upstream_layout` matches every byte except the re-based wrapped ring. Further tests: `announce_rate_table_rejects_inconsistent_files`, `unreadable_announce_rate_table_restores_empty_without_failing_other_state`, `announce_rate_block_survives_snapshot_restore`, and `restored_announce_rate_keeps_only_the_newest_timestamps`. Reverse direction checked once, not committed: upstream `AnnounceRateTable.load` at `d5f1e014` accepted a Rust-written table, returned identical entries, and kept entry A blocked at t=1030. `cargo test -p rns-core -p rns-net`: 2347 passed, 0 failed. `cargo fmt --check` and `cargo clippy -p rns-core -p rns-net --all-targets -D warnings` clean.

**Final disposition:** Integrated.

### 5. `01e7ed84` — Refactored traffic accounting

**Upstream change:** Interfaces stop adding received bytes to `rxb` (and to `parent_interface.rxb` or `owner.rxb`) in `process_incoming`. The changed modules are AX.25 KISS, Auto, Backbone, I2P, KISS, Local, Pipe, RNode, RNode Multi, Serial, TCP, UDP and Weave. `Transport.inbound` now charges each frame once: `accepted_inbound` adds to `rxb` (and the parent's) when `preprocess_inbound` accepts, and `filtered_inbound` adds only to `frxb`, no longer subtracting from `rxb`. The non-queued `preprocess_inbound` path no longer returns `_inbound`'s result, so it stops counting accepted packets as filtered; upstream's default `USE_INBOUND_QUEUE = True` already returned `True`. Side effects: AX.25 counts bytes after the 16-byte header, and I2P outbound peers (`parent_count = False`) now add RX bytes to the parent I2P interface (TX unchanged).

**Rust applicability:** rns-rs counts `rxb`/`rx_packets` once, when a wire frame reaches the driver (`handle_classified_frame_event`). `record_filtered_inbound` moves a frame dropped where `preprocess_inbound` drops it to `frxb`. A deferred signature failure is moved the same way; upstream rejects it inline, with the same end state. The totals therefore equal upstream's new accepted/filtered split, and no interface counts bytes on its own. AX.25 frames reach the driver already stripped by `decode_ui_frame`, matching the new upstream count. There is no non-queued `_inbound` quirk to mirror. Caveat: rns-rs reports no row for the I2P parent interface (its peers are separate dynamic interfaces), so the I2P `parent_count` RX roll-up has no surface. That is a pre-existing representation difference, not introduced here.

**Local handling and evidence:** Mapping commit refreshes the `record_filtered_inbound` doc to describe upstream's new split. It also moves the misplaced `admit_decoded_inbound` doc back onto its function. New regression `every_received_frame_is_charged_once_to_received_or_filtered` sends accepted, IFAC-flagged and undecodable frames and requires `rxb + frxb` to equal the bytes received, with every filtered frame in `frxb`. The existing 134dc677 filtered-inbound tests still pass. `cargo test -p rns-net`: 1470 passed, 0 failed; fmt and clippy clean.

**Final disposition:** Structurally covered.

### 6. `d1837919` — Refactored traffic accounting

**Upstream change:** Pending review (changes `RNS/Transport.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 7. `819076c3` — Track filtered announce count per interface

**Upstream change:** Pending review (changes `RNS/Interfaces/Interface.py`, `RNS/Reticulum.py`, `RNS/Transport.py`, `RNS/Utilities/rnstatus.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 8. `daec67a1` — Cleanup

**Upstream change:** Pending review (changes `RNS/Transport.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 9. `3281e283` — Added tunnel info to rnstatus

**Upstream change:** Pending review (changes `RNS/Interfaces/Interface.py`, `RNS/Reticulum.py`, `RNS/Transport.py`, `RNS/Utilities/rnstatus.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 10. `464e7598` — Added remote transport ID info to rnstatus

**Upstream change:** Pending review (changes `RNS/Interfaces/BackboneInterface.py`, `RNS/Interfaces/I2PInterface.py`, `RNS/Interfaces/Interface.py`, `RNS/Interfaces/TCPInterface.py`, `RNS/Reticulum.py`, `RNS/Transport.py`, `RNS/Utilities/rnstatus.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 11. `56b23c48` — Typo

**Upstream change:** Pending review (changes `RNS/Reticulum.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 12. `350b7e26` — Added ability to blackhole remote transport nodes

**Upstream change:** Pending review (changes `RNS/Reticulum.py`, `RNS/Transport.py`, `RNS/Utilities/rnstatus.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 13. `c850cdac` — Traffic counting

**Upstream change:** Pending review (changes `RNS/Interfaces/Interface.py`, `RNS/Transport.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

## Integration Plan

Review every commit above and give it a disposition.

## Promotion Gates

- [ ] Every upstream commit has a final disposition.
- [ ] Focused regressions pass for every applicable behavior change.
- [ ] Fixture provenance and byte stability are checked where applicable.
- [ ] Exact-target live Python/Rust interop passes.
- [ ] Workspace tests, feature suites, formatting, and lint pass.
- [ ] Required build, Docker, hardware, and manual gates are recorded honestly.
- [ ] Native documentation is updated for user-visible behavior.
- [ ] A final parity record is created from `PARITY-TEMPLATE.md`.

## Acceptance Record

None yet.
