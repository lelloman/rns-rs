# Reticulum 1.5.4 rgit Follow-up Upstream Audit

## Scope and Baseline

- audit date: `2026-09-19`
- previous accepted version: `1.5.4`
- previous normative commit: `1565126ffd08b9d7bc750ce5df82d5aa3e38183e`
- target version: `1.5.4`
- target tag or ref: canonical `rgit/master`; GitHub mirror is one commit behind
- target normative commit: `e699bb23f1306ed451568d647b497791a44be95a`
- observed root tree: `654c79a2e4968c9e514f071f1074db548b680cac`
- observed `RNS` tree: `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`
- version assertion: target `RNS/_version.py` declares `1.5.4`
- audited range: `1565126ffd08b9d7bc750ce5df82d5aa3e38183e..e699bb23f1306ed451568d647b497791a44be95a`
- commits in range: `17`
- repositories checked: GitHub mirror and normative rgit remote
- local revision inspected: `4034ea7d6acf863162736a373d1b8760f28e0084`

The initial daily check found 16 commits on both remotes. The post-first-mapping
refresh found one further canonical commit, so this audit includes 17 commits.
The final post-mapping refresh succeeded for GitHub at `2026-09-19T09:39:45Z`
and rgit at `2026-09-19T09:39:50Z`. Canonical rgit is at the target;
GitHub remains at its parent `badd850088e25df90d4d08a15a8c0ec68ea5d327`.
This is a same-version development-tip promotion, not a signed release tag.

The configured upstream checkout stayed at the previous accepted baseline
through review. All upstream changes were inspected using Git objects. Every
commit retains the same `RNS` tree, and AST comparisons confirm the six changed
Python test files contain no executable changes. The license and packaging
source are unchanged. Native runtime source and fixtures are unchanged.

This second qualified audit preserves the immutable earlier 1.5.4 rgit records.
The `-rgit-2` suffix identifies a second same-version advancement; hashes and
dates are recorded inside the documents.

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

Every upstream commit appears once below, in ancestry order, with its final
disposition and unique local mapping. Each mapping is non-empty, carries exactly
one full `Upstream-Commit` trailer, and has no duplicate in local history.

| # | Upstream commit | Subject | Disposition | Local evidence |
|---:|---|---|---|---|
| 1 | `28eba69900bf7089a2756396f9bc3f5056f75685` | Added generation notices | Non-runtime | Mapping `95fa729`; per-commit analysis below. |
| 2 | `0bc132d7df72cdb24acf6dc86b95674a64863f2d` | Updated readme | Non-runtime | Mapping `4489db0`; per-commit analysis below. |
| 3 | `99bfde84bf27a9f1d7ea888f8c7117be6f115dc7` | Added Brandolini's Reference chapter to the manual | Non-runtime | Mapping `e6ee2a1`; per-commit analysis below. |
| 4 | `b67872d946beff2af5b23b5d10228d646a02b99e` | Added Brandolini's Reference chapter to the manual | Non-runtime | Mapping `577c80f`; per-commit analysis below. |
| 5 | `1e7432af393e2deb28cac6ccf877390e24811a89` | Added AGENTS.md | Non-runtime | Mapping `400efe5`; per-commit analysis below. |
| 6 | `b043414add099faa588a8af4df3a002541eb24d5` | Updated readme | Non-runtime | Mapping `bb61706`; per-commit analysis below. |
| 7 | `3b0425c8a81c86133851cdb3067cf4bb28000230` | Updated readme | Non-runtime | Mapping `3a35c57`; per-commit analysis below. |
| 8 | `b79f6e0b1ccb752167ddc895a98e1c7518e6859f` | Updated readme | Non-runtime | Mapping `c3a9662`; per-commit analysis below. |
| 9 | `032e14384f11d974e7c3eb40a5d56158aaedcd4c` | Formatting | Non-runtime | Mapping `947eef4`; per-commit analysis below. |
| 10 | `16ba292bd08c01969e1fc678c735e0269da5e71e` | Fixed typo | Non-runtime | Mapping `369d4d4`; per-commit analysis below. |
| 11 | `9397114f56e0443f43ef27faa742966be9ecf320` | Fixed typo | Non-runtime | Mapping `fdf0d5d`; per-commit analysis below. |
| 12 | `900b4c607cd70cf4aa14dec7ab2a05428e7ac5e2` | Cleanup | Non-runtime | Mapping `28f129d`; per-commit analysis below. |
| 13 | `b4c6deee787acc379a7dc1751404f3e2dcd24565` | Cleanup and formatting | Non-runtime | Mapping `d476528`; per-commit analysis below. |
| 14 | `d0231f6ee3a81d74bfeabb1cf2ac2f7544a8c443` | Formatting | Non-runtime | Mapping `4de1b88`; per-commit analysis below. |
| 15 | `ffad91431a6faed21b8b005e63718d30b969889b` | Formatting | Non-runtime | Mapping `22d3b94`; per-commit analysis below. |
| 16 | `badd850088e25df90d4d08a15a8c0ec68ea5d327` | Cleanup and formatting | Non-runtime | Mapping `f9e8942`; per-commit analysis below. |
| 17 | `e699bb23f1306ed451568d647b497791a44be95a` | Structural cleanup | Non-runtime | Mapping `1abd53b`; per-commit analysis below. |

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

**Local mapping:** `95fa7297c5f44e42452da806435e35e057abefd3`.

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

**Local mapping:** `4489db00944330b4c775673740624659d00fe848`.

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

**Local mapping:** `e6ee2a11eea01ea7e69fe4dfa0ba6f118303f6ad`.

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

**Local mapping:** `577c80f632a136c1fd70d9f9248a2a14bf30201a`.

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

**Local mapping:** `400efe5b8cb6a4b133b676d2c256682de7769b81`.

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

**Local mapping:** `bb61706edf52b2d8a5b4d9f81d07c3bd097c4c9a`.

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

**Local mapping:** `3a35c57d3036be2f5e40656d8a690cba8b5320d2`.

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

**Local mapping:** `c3a9662510afdd45ceae4af5ac78f264d14dd698`.

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

**Local mapping:** `947eef4f7b366739d8830c899a1a524fe330d8f9`.

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

**Local mapping:** `369d4d45c142c456e39702d00d7cc66e5a565589`.

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

**Local mapping:** `fdf0d5da139a721961facaa9047b5c8f300a97f1`.

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

**Local mapping:** `28f129df2ab6ce31a5127fc9acf061c0255c1b40`.

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

**Local mapping:** `d476528a3a00911946ba271fddac36ce0b7662ca`.

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

**Local mapping:** `4de1b88a0d1fb8abd9a4945d01496f2d5060c65c`.

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

**Local mapping:** `22d3b9480c00af56c07a881bebc56dd01c7280cf`.

**Final disposition:** Non-runtime.

### 16. `badd8500` — Cleanup and formatting

**Changed paths:** `docs/manual/_sources/brandolinis.rst.txt`, `docs/manual/brandolinis.html`, `docs/manual/searchindex.js`, `docs/markdown/brandolinis.md`, `docs/source/brandolinis.rst`.

**Upstream change:** Revises the third-party case-study quotations and wording,
renames evaluation bullet labels, formats a copyright string as literal text,
and edits/splits the network-health discussion. Generated chapter outputs and
search terms follow those editorial changes.

**Rust applicability:** No executable behavior changes. The shared-medium
paragraph edits introduce no new packet, scheduling, or rate-control contract.
The case-study claims remain upstream commentary, not this audit's findings.

**Local handling and evidence:** Complete source/rendered-page diffs and the
JSON-only search update reviewed. Preserve existing native interoperability and
benchmark evidence requirements. Depends on the chapter and preceding edits;
`git diff --check` passes. No runtime port or focused regression is applicable.

**Local mapping:** `f9e8942d601987620e802cefc3d2f09a43eeaace`.

**Final disposition:** Non-runtime.

### 17. `e699bb23` — Structural cleanup

**Changed paths:** `docs/manual/_sources/brandolinis.rst.txt`, `docs/manual/brandolinis.html`, `docs/manual/index.html`, `docs/manual/objects.inv`, `docs/manual/searchindex.js`, `docs/markdown/brandolinis.md`, `docs/markdown/index.md`, `docs/source/brandolinis.rst`.

**Upstream change:** Moves the existing third-party case study to the chapter's
end as Addendum A, changes its generated heading anchor and navigation labels,
and adjusts one paragraph to call it an addendum. Search data and the Sphinx
inventory follow the reorganization.

**Rust applicability:** Document structure only; no runtime, protocol, utility,
or configuration change. The earlier analysis of the case-study prose remains
applicable. The Rust repository does not vendor these generated pages.

**Local handling and evidence:** Inspected the move and compared all changed
text files with line multiplicities preserved to isolate additions/deletions
from relocation; only the heading, anchor/navigation, and addendum paragraph
change beyond moved content. Decompressed inventory changes one label; search
index remains JSON-only. Depends on the chapter and its preceding edits.
`git diff --check` passes. No behavioral regression is applicable.

**Local mapping:** `1abd53b4eb21e6778b6c739d5ef4e16548aef74a`.

**Final disposition:** Non-runtime.

## Integration Record

1. Committed the daily inventory before beginning ordered mappings.
2. Reviewed and committed each upstream change separately in ancestry order;
   local mappings are recorded above. No runtime source change was required.
3. Verified a clean working tree and unique, ordered trailers between mappings;
   refreshed both upstream remotes after every mapping. The final mapping is
   `1abd53b` and the final refresh still shows 17 commits since the old baseline.
4. Confirmed the unchanged `RNS` tree at every upstream commit, unchanged ASTs
   for all six touched Python tests, and unchanged license/packaging sources.
5. Completed the applicable checks below. Final acceptance authority is
   [reticulum-1.5.4-rgit-2-parity.md](reticulum-1.5.4-rgit-2-parity.md).

## Promotion Gates

- [x] All 17 upstream commits have final Non-runtime dispositions and individual
  non-empty, ordered local mappings with unique full upstream trailers.
- [x] Focused runtime regressions: not applicable; no behavior change. Complete
  diff review, tree identity, Python AST comparisons, and `git diff --check`
  provide focused evidence for the documentation/comment-only scope.
- [x] Fixture provenance and byte stability: native fixtures and generation
  inputs remain unchanged; no regeneration is required.
- [x] Exact-target live Python/Rust interop: not applicable to this advancement;
  the runtime tree is byte-identical to the previous accepted baseline. No new
  exact-target run is claimed.
- [x] `cargo test --workspace`: 2,517 passed, 0 failed, 9 ignored across 68 result
  summaries. `cargo fmt --check` and warning-free host lint passed.
  Host lint checks all workspace targets with native hooks. No separate optional
  feature test matrix was required for these documentation-only mappings.
- [x] Build, Docker, hardware, and manual scope recorded below. Docker, cross
  builds, and physical hardware were not rerun for this non-runtime advancement.
- [x] Native applicability and evidence limitations documented in each mapping;
  no new native user-visible runtime behavior needs documentation.
- [x] Final parity record created from the parity template.

## Acceptance Record

All results below are from `2026-09-19`.

- The daily VPS snapshots were healthy and complete for both hosts. The shared
  report DB was uploaded and its checksum verified.
- Release builds of `rns-server` with native hooks and `rns-ctl` passed at local
  revision `4034ea7`. The full daily live Backbone smoke passed announces,
  identity recall, bidirectional packets/Channels, Resource boundaries at
  1,024, 100,000, 1,048,575 and 1,048,576 bytes with concurrency two per direction,
  two link batches with concurrency three, and one forced reconnect/recovery
  cycle under 150 ms latency, 75 ms jitter and a 2,000 kbps rate limit per leg.
- The first sandboxed smoke attempt could not create a socket; the unrestricted
  rerun passed. These are native operational results, not new Python interop.
- `cargo test --workspace` passed (2,517 passed, 0 failed, 9 ignored). It ran
  outside the socket-restricted sandbox. Native source was unchanged throughout
  the documentation mappings. Local log: `/tmp/parity-workspace-tests.log`.
- `cargo fmt --check` passed. `bash scripts/lint-host.sh` passed with native hooks
  and warnings denied. Local log: `/tmp/parity-host-lint.log`.
- No new Docker, cross-build, exact-target Python/Rust interop, or physical
  hardware run is claimed. Existing CI interop pin and fixture provenance are
  unchanged; those limits remain explicit in the parity record.
