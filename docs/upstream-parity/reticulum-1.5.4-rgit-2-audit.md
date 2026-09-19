# Reticulum 1.5.4 rgit Follow-up Upstream Audit

## Scope and Baseline

- audit date: `2026-09-19`
- previous accepted version: `1.5.4`
- previous normative commit: `1565126ffd08b9d7bc750ce5df82d5aa3e38183e`
- target version: `1.5.4`
- target tag or ref: canonical `rgit/master`, mirrored by `origin/master`
- target normative commit: `e699bb23f1306ed451568d647b497791a44be95a`
- observed root tree: `654c79a2e4968c9e514f071f1074db548b680cac`
- observed `RNS` tree: `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`
- version assertion: target `RNS/_version.py` declares `1.5.4`
- audited range: `1565126ffd08b9d7bc750ce5df82d5aa3e38183e..e699bb23f1306ed451568d647b497791a44be95a`
- commits in range: `17`
- repositories checked: GitHub mirror and normative rgit remote
- local revision inspected: `4034ea7d6acf863162736a373d1b8760f28e0084`

Both remote refreshes succeeded: GitHub at `2026-09-19T09:06:00Z`,
rgit at `2026-09-19T09:06:05Z`. At the initial check their tips agreed. A post-mapping refresh at
`2026-09-19T09:19:40Z` found canonical rgit one commit ahead of GitHub:
`e699bb23f1306ed451568d647b497791a44be95a` versus
`badd850088e25df90d4d08a15a8c0ec68ea5d327`. The target and inventory
include this seventeenth commit. The configured upstream
checkout remains at the accepted baseline. This daily-report inventory starts
the audit; full per-commit diff review, ordered local mappings, and promotion
acceptance have not been performed. Per-commit evidence below is updated as review proceeds. The second qualified
filename preserves the immutable earlier 1.5.4 rgit audit and parity record.

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

Every observed commit appears once below, in ancestry order. Dispositions are
open decisions pending full review; none claims integration or acceptance.

| # | Upstream commit | Subject | Disposition | Local evidence |
|---:|---|---|---|---|
| 1 | `28eba69900bf7089a2756396f9bc3f5056f75685` | Added generation notices | Non-runtime | Complete diff reviewed; see per-commit evidence below. |
| 2 | `0bc132d7df72cdb24acf6dc86b95674a64863f2d` | Updated readme | Needs decision | Changed paths inventoried; full diff and native applicability review pending. |
| 3 | `99bfde84bf27a9f1d7ea888f8c7117be6f115dc7` | Added Brandolini's Reference chapter to the manual | Needs decision | Changed paths inventoried; full diff and native applicability review pending. |
| 4 | `b67872d946beff2af5b23b5d10228d646a02b99e` | Added Brandolini's Reference chapter to the manual | Needs decision | Changed paths inventoried; full diff and native applicability review pending. |
| 5 | `1e7432af393e2deb28cac6ccf877390e24811a89` | Added AGENTS.md | Needs decision | Changed paths inventoried; full diff and native applicability review pending. |
| 6 | `b043414add099faa588a8af4df3a002541eb24d5` | Updated readme | Needs decision | Changed paths inventoried; full diff and native applicability review pending. |
| 7 | `3b0425c8a81c86133851cdb3067cf4bb28000230` | Updated readme | Needs decision | Changed paths inventoried; full diff and native applicability review pending. |
| 8 | `b79f6e0b1ccb752167ddc895a98e1c7518e6859f` | Updated readme | Needs decision | Changed paths inventoried; full diff and native applicability review pending. |
| 9 | `032e14384f11d974e7c3eb40a5d56158aaedcd4c` | Formatting | Needs decision | Changed paths inventoried; full diff and native applicability review pending. |
| 10 | `16ba292bd08c01969e1fc678c735e0269da5e71e` | Fixed typo | Needs decision | Changed paths inventoried; full diff and native applicability review pending. |
| 11 | `9397114f56e0443f43ef27faa742966be9ecf320` | Fixed typo | Needs decision | Changed paths inventoried; full diff and native applicability review pending. |
| 12 | `900b4c607cd70cf4aa14dec7ab2a05428e7ac5e2` | Cleanup | Needs decision | Changed paths inventoried; full diff and native applicability review pending. |
| 13 | `b4c6deee787acc379a7dc1751404f3e2dcd24565` | Cleanup and formatting | Needs decision | Changed paths inventoried; full diff and native applicability review pending. |
| 14 | `d0231f6ee3a81d74bfeabb1cf2ac2f7544a8c443` | Formatting | Needs decision | Changed paths inventoried; full diff and native applicability review pending. |
| 15 | `ffad91431a6faed21b8b005e63718d30b969889b` | Formatting | Needs decision | Changed paths inventoried; full diff and native applicability review pending. |
| 16 | `badd850088e25df90d4d08a15a8c0ec68ea5d327` | Cleanup and formatting | Needs decision | Changed paths inventoried; full diff and native applicability review pending. |
| 17 | `e699bb23f1306ed451568d647b497791a44be95a` | Structural cleanup | Needs decision | Full review pending. |

## Per-Commit Analysis

### 1. `28eba699` — Added generation notices

**Changed paths:** `tests/coalesced_transmit.py`, `tests/egress.py`, `tests/hdlc.py`, `tests/hkdf.py`, `tests/ifac.py`, `tests/throughput.py`.

**Upstream change:** Adds generation and human-review attribution comments to
six existing Python tests/benchmarks. Complete diff inspection confirms that
imports, executable statements, scenarios, and assertions are unchanged.

**Rust applicability:** Attribution belongs to those upstream files, not to
native tests or Criterion benchmarks. It does not change crypto, framing,
egress behavior, throughput requirements, or fixture provenance. The local
README already distinguishes native performance evidence from upstream figures.

**Local handling and evidence:** This non-empty audit mapping records the
upstream provenance without falsely attributing native source generation or
human approval. `git diff --check` passes. No behavioral regression is needed
for comment-only additions. No dependency on an earlier unintegrated commit.

**Final disposition:** Non-runtime.

### 2. `0bc132d7` — Updated readme

**Changed paths:** `README.md`.

**Upstream change and Rust applicability:** Pending full diff review. The
subject and path inventory do not establish behavioral equivalence.

**Local handling and evidence:** No implementation mapping or focused acceptance
test claimed. Review in ancestry order under the directory workflow.

**Disposition:** Needs decision.

### 3. `99bfde84` — Added Brandolini's Reference chapter to the manual

**Changed paths:** `docs/manual/_sources/index.rst.txt`, `docs/manual/distributed.html`, `docs/manual/examples.html`, `docs/manual/forhumans.html`, `docs/manual/genindex.html`, `docs/manual/gettingstartedfast.html`, `docs/manual/git.html`, `docs/manual/hardware.html`, `docs/manual/index.html`, `docs/manual/interfaces.html`, `docs/manual/license.html`, `docs/manual/networks.html`, `docs/manual/objects.inv`, `docs/manual/reference.html`, `docs/manual/search.html`, `docs/manual/searchindex.js`, `docs/manual/software.html`, `docs/manual/support.html`, `docs/manual/understanding.html`, `docs/manual/using.html`, `docs/manual/whatis.html`, `docs/manual/zen.html`, `docs/markdown/index.md`, `docs/source/index.rst`.

**Upstream change and Rust applicability:** Pending full diff review. The
subject and path inventory do not establish behavioral equivalence.

**Local handling and evidence:** No implementation mapping or focused acceptance
test claimed. Review in ancestry order under the directory workflow.

**Disposition:** Needs decision.

### 4. `b67872d9` — Added Brandolini's Reference chapter to the manual

**Changed paths:** `docs/manual/_sources/brandolinis.rst.txt`, `docs/manual/brandolinis.html`, `docs/markdown/brandolinis.md`, `docs/source/brandolinis.rst`.

**Upstream change and Rust applicability:** Pending full diff review. The
subject and path inventory do not establish behavioral equivalence.

**Local handling and evidence:** No implementation mapping or focused acceptance
test claimed. Review in ancestry order under the directory workflow.

**Disposition:** Needs decision.

### 5. `1e7432af` — Added AGENTS.md

**Changed paths:** `AGENTS.md`.

**Upstream change and Rust applicability:** Pending full diff review. The
subject and path inventory do not establish behavioral equivalence.

**Local handling and evidence:** No implementation mapping or focused acceptance
test claimed. Review in ancestry order under the directory workflow.

**Disposition:** Needs decision.

### 6. `b043414a` — Updated readme

**Changed paths:** `README.md`.

**Upstream change and Rust applicability:** Pending full diff review. The
subject and path inventory do not establish behavioral equivalence.

**Local handling and evidence:** No implementation mapping or focused acceptance
test claimed. Review in ancestry order under the directory workflow.

**Disposition:** Needs decision.

### 7. `3b0425c8` — Updated readme

**Changed paths:** `README.md`.

**Upstream change and Rust applicability:** Pending full diff review. The
subject and path inventory do not establish behavioral equivalence.

**Local handling and evidence:** No implementation mapping or focused acceptance
test claimed. Review in ancestry order under the directory workflow.

**Disposition:** Needs decision.

### 8. `b79f6e0b` — Updated readme

**Changed paths:** `README.md`.

**Upstream change and Rust applicability:** Pending full diff review. The
subject and path inventory do not establish behavioral equivalence.

**Local handling and evidence:** No implementation mapping or focused acceptance
test claimed. Review in ancestry order under the directory workflow.

**Disposition:** Needs decision.

### 9. `032e1438` — Formatting

**Changed paths:** `docs/manual/_sources/brandolinis.rst.txt`, `docs/manual/brandolinis.html`, `docs/manual/searchindex.js`, `docs/markdown/brandolinis.md`, `docs/source/brandolinis.rst`.

**Upstream change and Rust applicability:** Pending full diff review. The
subject and path inventory do not establish behavioral equivalence.

**Local handling and evidence:** No implementation mapping or focused acceptance
test claimed. Review in ancestry order under the directory workflow.

**Disposition:** Needs decision.

### 10. `16ba292b` — Fixed typo

**Changed paths:** `docs/source/brandolinis.rst`.

**Upstream change and Rust applicability:** Pending full diff review. The
subject and path inventory do not establish behavioral equivalence.

**Local handling and evidence:** No implementation mapping or focused acceptance
test claimed. Review in ancestry order under the directory workflow.

**Disposition:** Needs decision.

### 11. `9397114f` — Fixed typo

**Changed paths:** `docs/manual/_sources/brandolinis.rst.txt`, `docs/manual/brandolinis.html`, `docs/markdown/brandolinis.md`.

**Upstream change and Rust applicability:** Pending full diff review. The
subject and path inventory do not establish behavioral equivalence.

**Local handling and evidence:** No implementation mapping or focused acceptance
test claimed. Review in ancestry order under the directory workflow.

**Disposition:** Needs decision.

### 12. `900b4c60` — Cleanup

**Changed paths:** `docs/manual/_sources/brandolinis.rst.txt`, `docs/manual/brandolinis.html`, `docs/markdown/brandolinis.md`, `docs/source/brandolinis.rst`.

**Upstream change and Rust applicability:** Pending full diff review. The
subject and path inventory do not establish behavioral equivalence.

**Local handling and evidence:** No implementation mapping or focused acceptance
test claimed. Review in ancestry order under the directory workflow.

**Disposition:** Needs decision.

### 13. `b4c6deee` — Cleanup and formatting

**Changed paths:** `docs/manual/_sources/brandolinis.rst.txt`, `docs/manual/brandolinis.html`, `docs/manual/searchindex.js`, `docs/markdown/brandolinis.md`, `docs/source/brandolinis.rst`.

**Upstream change and Rust applicability:** Pending full diff review. The
subject and path inventory do not establish behavioral equivalence.

**Local handling and evidence:** No implementation mapping or focused acceptance
test claimed. Review in ancestry order under the directory workflow.

**Disposition:** Needs decision.

### 14. `d0231f6e` — Formatting

**Changed paths:** `docs/source/brandolinis.rst`.

**Upstream change and Rust applicability:** Pending full diff review. The
subject and path inventory do not establish behavioral equivalence.

**Local handling and evidence:** No implementation mapping or focused acceptance
test claimed. Review in ancestry order under the directory workflow.

**Disposition:** Needs decision.

### 15. `ffad9143` — Formatting

**Changed paths:** `docs/manual/_sources/brandolinis.rst.txt`, `docs/manual/brandolinis.html`, `docs/manual/index.html`, `docs/manual/objects.inv`, `docs/manual/searchindex.js`, `docs/markdown/brandolinis.md`, `docs/markdown/index.md`.

**Upstream change and Rust applicability:** Pending full diff review. The
subject and path inventory do not establish behavioral equivalence.

**Local handling and evidence:** No implementation mapping or focused acceptance
test claimed. Review in ancestry order under the directory workflow.

**Disposition:** Needs decision.

### 16. `badd8500` — Cleanup and formatting

**Changed paths:** `docs/manual/_sources/brandolinis.rst.txt`, `docs/manual/brandolinis.html`, `docs/manual/searchindex.js`, `docs/markdown/brandolinis.md`, `docs/source/brandolinis.rst`.

**Upstream change and Rust applicability:** Pending full diff review. The
subject and path inventory do not establish behavioral equivalence.

**Local handling and evidence:** No implementation mapping or focused acceptance
test claimed. Review in ancestry order under the directory workflow.

**Disposition:** Needs decision.

### 17. `e699bb23` — Structural cleanup

**Changed paths:** `docs/manual/_sources/brandolinis.rst.txt`, `docs/manual/brandolinis.html`, `docs/manual/index.html`, `docs/manual/objects.inv`, `docs/manual/searchindex.js`, `docs/markdown/brandolinis.md`, `docs/markdown/index.md`, `docs/source/brandolinis.rst`.

**Upstream change and Rust applicability:** Pending review.

**Disposition:** Needs decision.

## Integration Plan

1. Review each complete upstream diff and relevant native surfaces in ancestry order.
2. Replace open decisions with evidenced dispositions and create the required
   individual local mappings during parity-update work.
3. Select the promotion target and version, then complete all applicable gates
   before creating a parity record or updating the accepted baseline.

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

The 2026-09-19 daily VPS snapshots were healthy and complete for both hosts.
The daily live Backbone smoke passed Resource boundaries through 1 MiB,
concurrent links and Resources, impairment, and forced reconnect recovery.
These operational results validate the deployed/current native revision, not
acceptance of the newly observed upstream commits. No upstream promotion,
exact-target interop, workspace acceptance suite, or hardware gate is claimed.
