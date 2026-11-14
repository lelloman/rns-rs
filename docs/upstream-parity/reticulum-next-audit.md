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
| 4 | `d5f1e014dbec2921d70b8acd15c820601de6525d` | Persist and load announce rate table | Pending review | Changes `RNS/Storage.py`, `RNS/Transport.py` |
| 5 | `01e7ed84433ee3e9a64643e40e892ccfcdb85243` | Refactored traffic accounting | Pending review | Changes `RNS/Interfaces/AX25KISSInterface.py`, `RNS/Interfaces/AutoInterface.py`, `RNS/Interfaces/BackboneInterface.py`, `RNS/Interfaces/I2PInterface.py`, `RNS/Interfaces/KISSInterface.py`, `RNS/Interfaces/LocalInterface.py`, `RNS/Interfaces/PipeInterface.py`, `RNS/Interfaces/RNodeInterface.py`, `RNS/Interfaces/RNodeMultiInterface.py`, `RNS/Interfaces/SerialInterface.py`, `RNS/Interfaces/TCPInterface.py`, `RNS/Interfaces/UDPInterface.py`, `RNS/Interfaces/WeaveInterface.py`, `RNS/Transport.py` |
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

**Upstream change:** Pending review (changes `RNS/Storage.py`, `RNS/Transport.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 5. `01e7ed84` — Refactored traffic accounting

**Upstream change:** Pending review (changes `RNS/Interfaces/AX25KISSInterface.py`, `RNS/Interfaces/AutoInterface.py`, `RNS/Interfaces/BackboneInterface.py`, `RNS/Interfaces/I2PInterface.py`, `RNS/Interfaces/KISSInterface.py`, `RNS/Interfaces/LocalInterface.py`, `RNS/Interfaces/PipeInterface.py`, `RNS/Interfaces/RNodeInterface.py`, `RNS/Interfaces/RNodeMultiInterface.py`, `RNS/Interfaces/SerialInterface.py`, `RNS/Interfaces/TCPInterface.py`, `RNS/Interfaces/UDPInterface.py`, `RNS/Interfaces/WeaveInterface.py`, `RNS/Transport.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

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
