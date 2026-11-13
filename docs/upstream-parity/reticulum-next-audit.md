# Reticulum Next Upstream Audit

## Scope and Baseline

- audit date: `2026-11-13`
- previous accepted version: `1.6.0`
- previous normative commit: `16621a78e35e2ba5156c72af7fe492458ba092d5`
- target version: `1.6.0` (pending: no version bump in range)
- target tag or ref: `rgit/master` (pending promotion target)
- target normative commit: `134dc6777c0dd29404e61b36d4094f4e35b88b3e`
- target root tree: `da30506871f4036968e0355447e3d0e79b39942d`
- target `RNS` tree: `aa29f48513fca2a1be8c9940bcee9ca7bbb074db`
- version assertion: `RNS.__version__ == "1.6.0"`
- audited range: `16621a78e35e2ba5156c72af7fe492458ba092d5..134dc6777c0dd29404e61b36d4094f4e35b88b3e`
- commits in range: `15`
- repositories checked: rgit `master` (normative) and the GitHub mirror `master`
- local branch and revision inspected: `upstream-next-audit@bf4d7bab1801c818503783fdf1a4ffcc82a535f3`

Found by the 2026-11-13 daily drift check (`data/upstream-drift-2026-11-13.json`),
both remotes refreshed fresh. The GitHub mirror tip `3c4b271f` (10 commits) is
contained in rgit `master`; rgit adds five later commits (`db67adea`, `f96cef7e`,
`9b6b724b`, `20e25a9f`, `134dc677`). No version bump, so the target version and
promotion target stay pending.

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
| 1 | `50b6733a1cc0c85cc0caa94ee2f5e38c6692e462` | Cleanup | Structurally covered | `oversized_announce_of_a_blocked_type_counts_a_protocol_violation` |
| 2 | `023849ed29e230441499f1adf6eb135696d067b6` | Improved path pool and tunnel culling | Pending review | Changes `RNS/Transport.py` |
| 3 | `3ac3236b2f11f5e58ca9d86564ee44222bfacd9b` | Updated stale doc defaults | Pending review | Changes `RNS/Interfaces/Interface.py`, `docs/source/interfaces.rst` |
| 4 | `7852f53a4c24fe7e063e02c00d35eb06568f0b15` | Always init announce_queue | Pending review | Changes `RNS/Interfaces/Interface.py`, `RNS/Transport.py` |
| 5 | `70b9d58f15d88a3e33402f06f30cad411001e0ed` | Cleaned up announce cap properties | Pending review | Changes `RNS/Interfaces/Interface.py`, `RNS/Transport.py` |
| 6 | `1855f9927fe23990c2da8d49c1409b85b1b7ef8f` | Cleanup | Pending review | Changes `RNS/Transport.py` |
| 7 | `0bc5c37c399cb6c489ade2ea3678c531bfc21390` | Reset DPEC on reconnect | Pending review | Changes `RNS/Interfaces/BackboneInterface.py` |
| 8 | `9ef6c90ea6196057278685aabab06674e73ffa44` | Use RLock in logging | Pending review | Changes `RNS/__init__.py` |
| 9 | `5f2dbc169d5b3cb497d0f7067acef823e5619f30` | Added ability to load a blocked_ips file from the current config dir | Pending review | Changes `RNS/Reticulum.py` |
| 10 | `3c4b271f4133ed1f00eae04b1f3160365f4d02ec` | Added client_limit option to BackboneInterface | Pending review | Changes `RNS/Interfaces/BackboneInterface.py` |
| 11 | `db67adea0a6cc4289580ff7a19923605d48870e8` | Fixed path usage display | Pending review | Changes `RNS/Utilities/rnpath.py` |
| 12 | `f96cef7ed94029c8028fd688c55f3af5946b5d3c` | Drop announces early when held announces is full | Pending review | Changes `RNS/Transport.py` |
| 13 | `9b6b724b08e6c8681cfb9edd34edd905fb2238b3` | Diagnostics | Pending review | Changes `RNS/Reticulum.py`, `RNS/Utilities/rnstatus.py` |
| 14 | `20e25a9f0cd4bde8958642d36690cf709849f5ee` | Filter destinations at path table load time | Pending review | Changes `RNS/Transport.py` |
| 15 | `134dc6777c0dd29404e61b36d4094f4e35b88b3e` | Added filtered traffic stats and display in rnstatus | Pending review | Changes `RNS/Interfaces/Interface.py`, `RNS/Reticulum.py`, `RNS/Transport.py`, `RNS/Utilities/rnstatus.py` |

## Per-Commit Analysis

### 1. `50b6733a` — Cleanup

**Upstream change:** `Packet.unpack` failures and the malformed-packet protocol violation log at EXTREME instead of DEBUG (counters unchanged). The oversized-announce check (`len(raw) > Reticulum.MTU`, a protocol violation) moves ahead of the `blocked_destination_types` and `required_destinations_only` filters, so an oversized announce of a blocked or not-allowed type now counts a protocol violation where it was dropped silently.

**Rust applicability:** rns-rs checks the announce frame size in the driver (`admit_decoded_inbound`, `rns-net/src/driver/events.rs`) before the engine applies its destination type filter, and logs malformed packets at trace, so it already behaves as the new upstream. One counter-only nuance predates this commit: upstream runs `packet_filter` before the size check, so an oversized announce that is also a duplicate counts a packet-filter hit upstream and a protocol violation in rns-rs.

**Local handling and evidence:** Regression `oversized_announce_of_a_blocked_type_counts_a_protocol_violation` (`rns-net/src/driver/tests.rs`) blocks the announce's name hash and still requires one protocol violation.

**Final disposition:** Structurally covered.

### 2. `023849ed` — Improved path pool and tunnel culling

**Upstream change:** Pending review (changes `RNS/Transport.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 3. `3ac3236b` — Updated stale doc defaults

**Upstream change:** Pending review (changes `RNS/Interfaces/Interface.py`, `docs/source/interfaces.rst`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 4. `7852f53a` — Always init announce_queue

**Upstream change:** Pending review (changes `RNS/Interfaces/Interface.py`, `RNS/Transport.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 5. `70b9d58f` — Cleaned up announce cap properties

**Upstream change:** Pending review (changes `RNS/Interfaces/Interface.py`, `RNS/Transport.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 6. `1855f992` — Cleanup

**Upstream change:** Pending review (changes `RNS/Transport.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 7. `0bc5c37c` — Reset DPEC on reconnect

**Upstream change:** Pending review (changes `RNS/Interfaces/BackboneInterface.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 8. `9ef6c90e` — Use RLock in logging

**Upstream change:** Pending review (changes `RNS/__init__.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 9. `5f2dbc16` — Added ability to load a blocked_ips file from the current config dir

**Upstream change:** Pending review (changes `RNS/Reticulum.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 10. `3c4b271f` — Added client_limit option to BackboneInterface

**Upstream change:** Pending review (changes `RNS/Interfaces/BackboneInterface.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 11. `db67adea` — Fixed path usage display

**Upstream change:** Pending review (changes `RNS/Utilities/rnpath.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 12. `f96cef7e` — Drop announces early when held announces is full

**Upstream change:** Pending review (changes `RNS/Transport.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 13. `9b6b724b` — Diagnostics

**Upstream change:** Pending review (changes `RNS/Reticulum.py`, `RNS/Utilities/rnstatus.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 14. `20e25a9f` — Filter destinations at path table load time

**Upstream change:** Pending review (changes `RNS/Transport.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 15. `134dc677` — Added filtered traffic stats and display in rnstatus

**Upstream change:** Pending review (changes `RNS/Interfaces/Interface.py`, `RNS/Reticulum.py`, `RNS/Transport.py`, `RNS/Utilities/rnstatus.py`).

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
