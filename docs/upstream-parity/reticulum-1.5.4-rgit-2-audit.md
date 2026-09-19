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
| 2 | `0bc132d7df72cdb24acf6dc86b95674a64863f2d` | Updated readme | Non-runtime | Complete diff reviewed; see per-commit evidence below. |
| 3 | `99bfde84bf27a9f1d7ea888f8c7117be6f115dc7` | Added Brandolini's Reference chapter to the manual | Non-runtime | Complete diff reviewed; see per-commit evidence below. |
| 4 | `b67872d946beff2af5b23b5d10228d646a02b99e` | Added Brandolini's Reference chapter to the manual | Non-runtime | Complete diff reviewed; see per-commit evidence below. |
| 5 | `1e7432af393e2deb28cac6ccf877390e24811a89` | Added AGENTS.md | Non-runtime | Complete diff reviewed; see per-commit evidence below. |
| 6 | `b043414add099faa588a8af4df3a002541eb24d5` | Updated readme | Non-runtime | Complete diff reviewed; see per-commit evidence below. |
| 7 | `3b0425c8a81c86133851cdb3067cf4bb28000230` | Updated readme | Non-runtime | Complete diff reviewed; see per-commit evidence below. |
| 8 | `b79f6e0b1ccb752167ddc895a98e1c7518e6859f` | Updated readme | Non-runtime | Complete diff reviewed; see per-commit evidence below. |
| 9 | `032e14384f11d974e7c3eb40a5d56158aaedcd4c` | Formatting | Non-runtime | Complete diff reviewed; see per-commit evidence below. |
| 10 | `16ba292bd08c01969e1fc678c735e0269da5e71e` | Fixed typo | Non-runtime | Complete diff reviewed; see per-commit evidence below. |
| 11 | `9397114f56e0443f43ef27faa742966be9ecf320` | Fixed typo | Non-runtime | Complete diff reviewed; see per-commit evidence below. |
| 12 | `900b4c607cd70cf4aa14dec7ab2a05428e7ac5e2` | Cleanup | Non-runtime | Complete diff reviewed; see per-commit evidence below. |
| 13 | `b4c6deee787acc379a7dc1751404f3e2dcd24565` | Cleanup and formatting | Non-runtime | Complete diff reviewed; see per-commit evidence below. |
| 14 | `d0231f6ee3a81d74bfeabb1cf2ac2f7544a8c443` | Formatting | Non-runtime | Complete diff reviewed; see per-commit evidence below. |
| 15 | `ffad91431a6faed21b8b005e63718d30b969889b` | Formatting | Non-runtime | Complete diff reviewed; see per-commit evidence below. |
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

**Upstream change:** Adds a community-implementation list, upstream inclusion
criteria, and cautions about unreviewed or incompatible implementations to the
README. The complete diff changes prose only.

**Rust applicability:** Upstream project endorsements and eligibility criteria
are editorial decisions, not wire, API, or configuration requirements. Native
parity evidence is maintained in these audits, fixture provenance, tests, and
interop records; it does not imply upstream recognition or endorsement.

**Local handling and evidence:** Record that distinction in this audit instead
of copying the upstream list or claiming inclusion. No native runtime change
or new test is needed. `git diff --check` passes. No behavior dependency on the
preceding generation-notice commit.

**Final disposition:** Non-runtime.

### 3. `99bfde84` — Added Brandolini's Reference chapter to the manual

**Changed paths:** `docs/manual/_sources/index.rst.txt`, `docs/manual/distributed.html`, `docs/manual/examples.html`, `docs/manual/forhumans.html`, `docs/manual/genindex.html`, `docs/manual/gettingstartedfast.html`, `docs/manual/git.html`, `docs/manual/hardware.html`, `docs/manual/index.html`, `docs/manual/interfaces.html`, `docs/manual/license.html`, `docs/manual/networks.html`, `docs/manual/objects.inv`, `docs/manual/reference.html`, `docs/manual/search.html`, `docs/manual/searchindex.js`, `docs/manual/software.html`, `docs/manual/support.html`, `docs/manual/understanding.html`, `docs/manual/using.html`, `docs/manual/whatis.html`, `docs/manual/zen.html`, `docs/markdown/index.md`, `docs/source/index.rst`.

**Upstream change:** Adds the new chapter to the source TOC, generated HTML and
Markdown navigation, search data, and Sphinx object inventory. License/API pages
change navigation only. The chapter body arrives in the next commit.

**Rust applicability:** No native protocol or public API behavior changes.
The Rust repository publishes native Markdown documentation and does not vendor
upstream Sphinx navigation or its generated search index.

**Local handling and evidence:** Full textual page diffs reviewed; the search
index parses entirely as `Search.setIndex` JSON data, and the decompressed
Sphinx inventory adds chapter labels only. No executable JavaScript or license
text change is introduced. Record the generated-documentation scope here;
`git diff --check` passes. No regression or runtime port is applicable. The
new navigation depends on the following chapter-content commit for its target.

**Final disposition:** Non-runtime.

### 4. `b67872d9` — Added Brandolini's Reference chapter to the manual

**Changed paths:** `docs/manual/_sources/brandolinis.rst.txt`, `docs/manual/brandolinis.html`, `docs/markdown/brandolinis.md`, `docs/source/brandolinis.rst`.

**Upstream change:** Adds the complete Brandolini's Reference chapter in RST,
Markdown, HTML, and the generated source copy. It discusses licensing positions,
AI assistance and authorship, evaluation of implementations, a third-party
case study, benchmark methodology, and shared-network coexistence. The sole
code block contains illustrative module paths, not executable protocol code.

**Rust applicability:** This is editorial and engineering guidance, not a new
packet format, routing algorithm, cryptographic primitive, RPC, or configuration
contract. Assertions about other projects and legal interpretations are not
independently established by this parity audit and are not adopted as findings.
Our native README already identifies this implementation as a Rust port and
requires reproducible, equivalent benchmark conditions. Existing parity records
distinguish pinned fixtures, exact-target evidence, and unclaimed hardware runs.

**Local handling and evidence:** Reviewed the complete chapter source and
inspected its generated representations: the generated RST copy is byte-identical,
Markdown contains the corresponding chapter structure, and HTML uses the existing
Sphinx/Furo scripts. No native runtime port or synthetic regression is warranted.
This mapping records the scope and limits of the review; `git diff --check`
passes. Completes the chapter linked by the preceding navigation commit. No
third-party benchmark number is imported as a native result or acceptance gate.

**Final disposition:** Non-runtime.

### 5. `1e7432af` — Added AGENTS.md

**Changed paths:** `AGENTS.md`.

**Upstream change:** Adds an upstream-root AGENTS.md containing a byte-for-byte
copy of the preceding chapter's generated Markdown. It adds no runtime code.

**Rust applicability:** This is upstream repository documentation. The file is
reviewed as upstream content, not installed as instructions governing the Rust
workspace. Its commentary does not alter protocol or API compatibility.

**Local handling and evidence:** Compared the complete added blob with
`b67872d9:docs/markdown/brandolinis.md`; they are byte-identical. The content and
applicability analysis from entry 4 therefore applies without a new behavior
claim. No native AGENTS.md or runtime change is required. `git diff --check`
passes. Content dependency: the preceding chapter addition.

**Final disposition:** Non-runtime.

### 6. `b043414a` — Updated readme

**Changed paths:** `README.md`.

**Upstream change:** Repeats the implementation warning at the README opening
and links the new chapter from both the opening and community-implementation
section. The complete diff consists of four added prose/link lines.

**Rust applicability:** No protocol, runtime, CLI, or configuration change.
These links express the reference project's editorial guidance. The native
README's port identity and scoped validation records remain the applicable
local documentation; no upstream endorsement is implied.

**Local handling and evidence:** Record this independent README navigation
change without reproducing unverified third-party allegations. Depends on the
chapter introduced by entries 3–4. No runtime regression is applicable;
`git diff --check` passes.

**Final disposition:** Non-runtime.

### 7. `3b0425c8` — Updated readme

**Changed paths:** `README.md`.

**Upstream change:** Adds one sentence to the opening warning directing readers
to the README's Community Implementations section. Full diff is prose only.

**Rust applicability:** This is navigation to upstream's own endorsement list,
not a compatibility change or recognition of this port.

**Local handling and evidence:** Preserve the distinct source-history mapping
and record that no native code or user-facing API needs alteration. Depends on
the preceding README warning and the list introduced in entry 2.
`git diff --check` passes; no behavior test is applicable.

**Final disposition:** Non-runtime.

### 8. `b79f6e0b` — Updated readme

**Changed paths:** `README.md`.

**Upstream change:** Converts the preceding opening paragraph into a GitHub
Markdown warning callout. The warning's text and links are otherwise unchanged.

**Rust applicability:** Presentation-only change to upstream's README. No native
protocol, configuration, command, or application behavior changes.

**Local handling and evidence:** Complete diff reviewed and separately mapped.
The local README does not carry that upstream editorial warning, so no callout
conversion is needed here. Depends on entry 7's paragraph. `git diff --check`
passes; no runtime test is applicable.

**Final disposition:** Non-runtime.

### 9. `032e1438` — Formatting

**Changed paths:** `docs/manual/_sources/brandolinis.rst.txt`, `docs/manual/brandolinis.html`, `docs/manual/searchindex.js`, `docs/markdown/brandolinis.md`, `docs/source/brandolinis.rst`.

**Upstream change:** Splits a paragraph, fixes spacing/escaping, adds the author's
closing signature, and regenerates chapter outputs. The generated search index
also clears its `indexentries` collection (168 entries to zero); it remains
JSON search data, not runtime code.

**Rust applicability:** No Reticulum runtime change or native documentation
surface uses these Sphinx outputs. The search metadata change is recorded
explicitly rather than assuming the formatting subject describes every delta.

**Local handling and evidence:** Reviewed textual source and rendered-page
diffs, and decoded the complete search-index data change. No native port or
behavior regression is applicable; `git diff --check` passes. Depends on the
chapter addition in entry 4. Upstream authorship text is not copied into native
source or treated as approval of this work.

**Final disposition:** Non-runtime.

### 10. `16ba292b` — Fixed typo

**Changed paths:** `docs/source/brandolinis.rst`.

**Upstream change:** Removes an extraneous article from one sentence in the
chapter's RST source. Complete diff changes that sentence only.

**Rust applicability:** Grammar correction in upstream-only prose. No native
runtime or corresponding native document requires modification.

**Local handling and evidence:** Record the source-only correction independently
from the generated-output refresh that follows. Depends on the existing chapter.
`git diff --check` passes; no behavioral regression is applicable.

**Final disposition:** Non-runtime.

### 11. `9397114f` — Fixed typo

**Changed paths:** `docs/manual/_sources/brandolinis.rst.txt`, `docs/manual/brandolinis.html`, `docs/markdown/brandolinis.md`.

**Upstream change:** Propagates entry 10's single-word grammar correction into
the generated RST copy, HTML, and Markdown. Complete diffs contain no other
changes.

**Rust applicability:** Generated documentation only, with no native runtime or
vendored document to update.

**Local handling and evidence:** Keep a separate non-empty mapping for this
upstream commit despite its dependence on the preceding source correction.
`git diff --check` passes. No fixture or behavioral test change is applicable.

**Final disposition:** Non-runtime.

### 12. `900b4c60` — Cleanup

**Changed paths:** `docs/manual/_sources/brandolinis.rst.txt`, `docs/manual/brandolinis.html`, `docs/markdown/brandolinis.md`, `docs/source/brandolinis.rst`.

**Upstream change:** Cleans punctuation, duplicated words, RST escapes, and
editorial wording in the chapter and its generated copies. This includes a
wording change from documenting a record to refuting a claim, not just whitespace.

**Rust applicability:** These changes describe upstream community commentary;
no executable statements, wire contracts, or native documentation instructions
change.

**Local handling and evidence:** Complete four-file diff reviewed, including
the wording changes beyond formatting. Retain the chapter's non-runtime scope
and do not propagate its allegations as local findings. Depends on the chapter
and preceding edits. `git diff --check` passes; no runtime regression applies.

**Final disposition:** Non-runtime.

### 13. `b4c6deee` — Cleanup and formatting

**Changed paths:** `docs/manual/_sources/brandolinis.rst.txt`, `docs/manual/brandolinis.html`, `docs/manual/searchindex.js`, `docs/markdown/brandolinis.md`, `docs/source/brandolinis.rst`.

**Upstream change:** Shortens the third-party evaluation, adds mention of formal
proof claims, generalizes a source-size comparison, removes a repeated benchmark
advice bullet, and regenerates chapter outputs/search terms. This is substantive
editorial revision as well as formatting.

**Rust applicability:** No executable or protocol behavior changes. Removing a
repeated upstream prose bullet does not rescind native benchmark reproducibility
requirements or change our acceptance evidence.

**Local handling and evidence:** Complete textual diffs and JSON-only search
metadata reviewed. Native README performance guidance remains appropriate.
No runtime port or regression test is applicable; `git diff --check` passes.
Depends on the existing chapter and its earlier editorial revisions.

**Final disposition:** Non-runtime.

### 14. `d0231f6e` — Formatting

**Changed paths:** `docs/source/brandolinis.rst`.

**Upstream change:** Removes a comma from one chapter heading and adjusts its
RST underline length. Complete diff affects only those two source lines.

**Rust applicability:** Heading typography in upstream documentation, with no
native runtime or counterpart document change.

**Local handling and evidence:** Record the source heading correction separately
from its following generated-output refresh. Depends on the chapter addition;
`git diff --check` passes. No behavioral test is applicable.

**Final disposition:** Non-runtime.

### 15. `ffad9143` — Formatting

**Changed paths:** `docs/manual/_sources/brandolinis.rst.txt`, `docs/manual/brandolinis.html`, `docs/manual/index.html`, `docs/manual/objects.inv`, `docs/manual/searchindex.js`, `docs/markdown/brandolinis.md`, `docs/markdown/index.md`.

**Upstream change:** Refreshes the generated chapter, navigation, search title,
and Sphinx inventory after entry 14's heading punctuation correction. Anchor
identifiers remain unchanged.

**Rust applicability:** Generated documentation labels only. No native API,
wire behavior, or corresponding native content changes.

**Local handling and evidence:** Complete page diffs inspected; decompressed
inventory changes only the heading label and search JSON changes only titles.
Depends on entry 14; retained as a distinct mapping. `git diff --check` passes.
No behavioral regression is applicable.

**Final disposition:** Non-runtime.

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
