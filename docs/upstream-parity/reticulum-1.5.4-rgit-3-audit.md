# Reticulum 1.5.4 rgit Third Advancement Audit

## Scope and Baseline

- audit date: `2026-09-20`
- previous accepted version: `1.5.4`
- previous normative commit: `e699bb23f1306ed451568d647b497791a44be95a`
- observed upstream version: `1.5.4`
- observed refs: `origin/master`, `rgit/master` (agree)
- observed tip: `99de23c040d507e3fefca19e87b182302902725d`
- observed root tree: `42e27d27afbed126220bec5ae701a745e0568a10`
- observed `RNS` tree: `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`
- version evidence: `RNS/_version.py` contains `__version__ = "1.5.4"`
- inventoried range: `e699bb23f1306ed451568d647b497791a44be95a..99de23c040d507e3fefca19e87b182302902725d`
- commits in range: `16`
- repositories: `https://github.com/markqvist/Reticulum` and `rns://7649a50d84610232d1416b41d2896aff/reticulum/reticulum`
- local branch/revision: `dev@503d1fc6329068af0800160d3124c8fa00a1c201`
- promotion target: `99de23c040d507e3fefca19e87b182302902725d` (same-version canonical development tip)

Both refreshed remotes agree on the target. Final pre-promotion refresh:
GitHub `2026-09-20T14:21:11+00:00`; rgit
`2026-09-20T14:21:15+00:00`. The configured checkout stayed at the
accepted baseline throughout review and will move only with promotion.

All 16 full diffs were reviewed in ancestry order, including generated search
indices split losslessly for readability. Every commit retains the exact accepted
runtime tree. Each received a separate non-empty mapping commit; one-to-one
trailers, mapping order, and unchanged native source were mechanically checked.
Per-commit drift checks used explicitly cached refs between the fresh initial
and final comparisons; they are not claimed as additional network refreshes.

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

| # | Upstream commit | Subject | Disposition | Evidence / remaining work |
|---:|---|---|---|---|
| 1 | `484cf2d1a56e657e1310655e15b5a8159b71ce21` | Added history folder | Non-runtime | Paths: `docs/history/2026_09_18_Yes_I_am_Angry.md`. Full diff reviewed; runtime tree unchanged. Mapping identified by the exact upstream trailer; see analysis below. |
| 2 | `abf355b4d72d5669496dae3220bf5836c5610bcf` | Formatting, link, wording, typos | Non-runtime | Paths: `docs/history/2026_09_18_Yes_I_am_Angry.md`. Full diff reviewed; runtime tree unchanged. Mapping identified by the exact upstream trailer; see analysis below. |
| 3 | `29f6bc8652e490e6489741c16bdc2b7d142bbcc9` | Done, next chapter | Non-runtime | Paths: `docs/history/2026_09_18_Yes_I_am_Angry.md`. Full diff reviewed; runtime tree unchanged. Mapping identified by the exact upstream trailer; see analysis below. |
| 4 | `7373f813495b8134e3ca3274a1b988c1fa97b106` | Markdown is markdown | Non-runtime | Paths: `docs/history/2026_09_18_Yes_I_am_Angry.md`. Full diff reviewed; runtime tree unchanged. Mapping identified by the exact upstream trailer; see analysis below. |
| 5 | `58881af30703ad74d80e4e9135713abdba6b26dd` | Updates | Non-runtime | Paths: `docs/history/2026_09_18_Yes_I_am_Angry.md`. Full diff reviewed; runtime tree unchanged. Mapping identified by the exact upstream trailer; see analysis below. |
| 6 | `9d85931c9d85c7a6549364c572fe2532ca5a9d99` | Updates | Non-runtime | Paths: `docs/history/2026_09_18_Yes_I_am_Angry.md`. Full diff reviewed; runtime tree unchanged. Mapping identified by the exact upstream trailer; see analysis below. |
| 7 | `3c479ddb65bf86c0bbaa3565861db97171bb2a4a` | Updated readme | Non-runtime | Paths: `README.md`. Full diff reviewed; runtime tree unchanged. Mapping identified by the exact upstream trailer; see analysis below. |
| 8 | `2289a8effae984d63bc69d10aa4e1d01a3088ed3` | Updated readme | Non-runtime | Paths: `README.md`. Full diff reviewed; runtime tree unchanged. Mapping identified by the exact upstream trailer; see analysis below. |
| 9 | `23101e45f6013d0f54aa2f8651bcde271c0b7ae9` | Updated readme | Non-runtime | Paths: `README.md`. Full diff reviewed; runtime tree unchanged. Mapping identified by the exact upstream trailer; see analysis below. |
| 10 | `8743ddcbe52be7f88e764b1cdd7af009bd4d62a2` | Updated readme | Non-runtime | Paths: `README.md`. Full diff reviewed; runtime tree unchanged. Mapping identified by the exact upstream trailer; see analysis below. |
| 11 | `cb66b3d10fd34a6aedb16c78f00a720383dbb122` | Updated readme | Non-runtime | Paths: `README.md`. Full diff reviewed; runtime tree unchanged. Mapping identified by the exact upstream trailer; see analysis below. |
| 12 | `ddd55d50cc30c49bec99d359a0f73a9cc15d436d` | Updated readme | Non-runtime | Paths: `README.md`. Full diff reviewed; runtime tree unchanged. Mapping identified by the exact upstream trailer; see analysis below. |
| 13 | `34b36362ab9b2ef9b20bafb3db146261e1d75191` | Scratch that | Non-runtime | Paths: `docs/history/2026_09_18_Yes_I_am_Angry.md`. Full diff reviewed; runtime tree unchanged. Mapping identified by the exact upstream trailer; see analysis below. |
| 14 | `15e6dd4a882f0cea81b4e899120f46787aaeb8a2` | Updated docs | Non-runtime | Paths: `docs/manual/searchindex.js`. Full diff reviewed; runtime tree unchanged. Mapping identified by the exact upstream trailer; see analysis below. |
| 15 | `395241b190ae4bc6e5d8070c8ff0a01afd24bdc9` | Updated docs | Non-runtime | Paths: `docs/history/2026_09_18_Yes_I_am_Angry.md`, `docs/source/brandolinis.rst`. Full diff reviewed; runtime tree unchanged. Mapping identified by the exact upstream trailer; see analysis below. |
| 16 | `99de23c040d507e3fefca19e87b182302902725d` | Updated docs | Non-runtime | Paths: `docs/manual/_sources/brandolinis.rst.txt`, `docs/manual/brandolinis.html`, `docs/manual/searchindex.js`, `docs/markdown/brandolinis.md`. Full diff reviewed; runtime tree unchanged. Mapping identified by the exact upstream trailer; see analysis below. |

## Per-Commit Analysis

Per-commit reviews are recorded below in upstream ancestry order. The mapping
table records the resulting local commits.

### 1. `484cf2d1` — Added history folder

**Upstream change:** Adds a dated history essay responding to external commentary on licensing, project governance, distribution, and other implementations. This is an editorial archive, not a protocol or licensing-file change.

**Changed paths:** `docs/history/2026_09_18_Yes_I_am_Angry.md`.

**Dependency:** Initial history document; no earlier unintegrated dependency.

**Rust applicability and evidence:** Full diff reviewed. This changes upstream
editorial material or its generated presentation; no native protocol, API,
configuration, CLI, or persistence change is required. Every changed path is
under `docs/` or is `README.md`. The commit retains the exact accepted `RNS`
tree `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`. Existing native compatibility
claims remain governed by test and parity evidence. Upstream opinions and
third-party allegations are not adopted as independently verified findings.
No runtime regression is applicable and no generated upstream prose is vendored.

**Final disposition:** Non-runtime. This analysis is the non-empty local mapping
whose sole `Upstream-Commit` trailer is `484cf2d1a56e657e1310655e15b5a8159b71ce21`.
Local mapping: `beea0bb89e94784f05d09170a338ba14c805d06f`.

### 2. `abf355b4` — Formatting, link, wording, typos

**Upstream change:** Revises links, spelling, emphasis, attribution wording, and paragraph spacing in the archived essay. It changes no licensing file or executable source.

**Changed paths:** `docs/history/2026_09_18_Yes_I_am_Angry.md`.

**Dependency:** Follows the preceding upstream commits in ancestry order; documentation context only.

**Rust applicability and evidence:** Full diff reviewed. This changes upstream
editorial material or its generated presentation; no native protocol, API,
configuration, CLI, or persistence change is required. Every changed path is
under `docs/` or is `README.md`. The commit retains the exact accepted `RNS`
tree `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`. Existing native compatibility
claims remain governed by test and parity evidence. Upstream opinions and
third-party allegations are not adopted as independently verified findings.
No runtime regression is applicable and no generated upstream prose is vendored.

**Final disposition:** Non-runtime. This analysis is the non-empty local mapping
whose sole `Upstream-Commit` trailer is `abf355b4d72d5669496dae3220bf5836c5610bcf`.
Local mapping: `4a5ac542b78b5d4adb8fd3bb31fa1abf7e996e1d`.

### 3. `29f6bc86` — Done, next chapter

**Upstream change:** Appends a closing separator and a personal return-to-work note to the history essay.

**Changed paths:** `docs/history/2026_09_18_Yes_I_am_Angry.md`.

**Dependency:** Follows the preceding upstream commits in ancestry order; documentation context only.

**Rust applicability and evidence:** Full diff reviewed. This changes upstream
editorial material or its generated presentation; no native protocol, API,
configuration, CLI, or persistence change is required. Every changed path is
under `docs/` or is `README.md`. The commit retains the exact accepted `RNS`
tree `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`. Existing native compatibility
claims remain governed by test and parity evidence. Upstream opinions and
third-party allegations are not adopted as independently verified findings.
No runtime regression is applicable and no generated upstream prose is vendored.

**Final disposition:** Non-runtime. This analysis is the non-empty local mapping
whose sole `Upstream-Commit` trailer is `29f6bc8652e490e6489741c16bdc2b7d142bbcc9`.
Local mapping: `76be107c331043cd4a893069db42957ffbb7b75a`.

### 4. `7373f813` — Markdown is markdown

**Upstream change:** Fixes Markdown paragraph separation below two bold headings and removes a heading colon in the history essay.

**Changed paths:** `docs/history/2026_09_18_Yes_I_am_Angry.md`.

**Dependency:** Follows the preceding upstream commits in ancestry order; documentation context only.

**Rust applicability and evidence:** Full diff reviewed. This changes upstream
editorial material or its generated presentation; no native protocol, API,
configuration, CLI, or persistence change is required. Every changed path is
under `docs/` or is `README.md`. The commit retains the exact accepted `RNS`
tree `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`. Existing native compatibility
claims remain governed by test and parity evidence. Upstream opinions and
third-party allegations are not adopted as independently verified findings.
No runtime regression is applicable and no generated upstream prose is vendored.

**Final disposition:** Non-runtime. This analysis is the non-empty local mapping
whose sole `Upstream-Commit` trailer is `7373f813495b8134e3ca3274a1b988c1fa97b106`.
Local mapping: `a05fe6abf287ac8a41903ac75f19184e27b8c316`.

### 5. `58881af3` — Updates

**Upstream change:** Expands the introduction with a call for responsibility and an excerpt of the upstream editorial analysis, including a three-item characterization of ecosystem disputes.

**Changed paths:** `docs/history/2026_09_18_Yes_I_am_Angry.md`.

**Dependency:** Follows the preceding upstream commits in ancestry order; documentation context only.

**Rust applicability and evidence:** Full diff reviewed. This changes upstream
editorial material or its generated presentation; no native protocol, API,
configuration, CLI, or persistence change is required. Every changed path is
under `docs/` or is `README.md`. The commit retains the exact accepted `RNS`
tree `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`. Existing native compatibility
claims remain governed by test and parity evidence. Upstream opinions and
third-party allegations are not adopted as independently verified findings.
No runtime regression is applicable and no generated upstream prose is vendored.

**Final disposition:** Non-runtime. This analysis is the non-empty local mapping
whose sole `Upstream-Commit` trailer is `58881af30703ad74d80e4e9135713abdba6b26dd`.
Local mapping: `784bf6dbe593f9c32944120aa12a0ca23e91190d`.

### 6. `9d85931c` — Updates

**Upstream change:** Corrects a singular noun to its plural in the introductory responsibility sentence of the history essay.

**Changed paths:** `docs/history/2026_09_18_Yes_I_am_Angry.md`.

**Dependency:** Follows the preceding upstream commits in ancestry order; documentation context only.

**Rust applicability and evidence:** Full diff reviewed. This changes upstream
editorial material or its generated presentation; no native protocol, API,
configuration, CLI, or persistence change is required. Every changed path is
under `docs/` or is `README.md`. The commit retains the exact accepted `RNS`
tree `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`. Existing native compatibility
claims remain governed by test and parity evidence. Upstream opinions and
third-party allegations are not adopted as independently verified findings.
No runtime regression is applicable and no generated upstream prose is vendored.

**Final disposition:** Non-runtime. This analysis is the non-empty local mapping
whose sole `Upstream-Commit` trailer is `9d85931c9d85c7a6549364c572fe2532ca5a9d99`.
Local mapping: `d469b17464270d6bedd08b335642bcf3656dc66b`.

### 7. `3c479ddb` — Updated readme

**Upstream change:** Adds an italic link from the README warning callout to the archived personal essay. This is upstream-specific navigation and does not imply native endorsement.

**Changed paths:** `README.md`.

**Dependency:** Follows the preceding upstream commits in ancestry order; documentation context only.

**Rust applicability and evidence:** Full diff reviewed. This changes upstream
editorial material or its generated presentation; no native protocol, API,
configuration, CLI, or persistence change is required. Every changed path is
under `docs/` or is `README.md`. The commit retains the exact accepted `RNS`
tree `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`. Existing native compatibility
claims remain governed by test and parity evidence. Upstream opinions and
third-party allegations are not adopted as independently verified findings.
No runtime regression is applicable and no generated upstream prose is vendored.

**Final disposition:** Non-runtime. This analysis is the non-empty local mapping
whose sole `Upstream-Commit` trailer is `3c479ddb65bf86c0bbaa3565861db97171bb2a4a`.
Local mapping: `15a0175af554231374030539c868d15dd68a4b00`.

### 8. `2289a8ef` — Updated readme

**Upstream change:** Removes the README essay link added by 3c479ddb, restoring the prior README blob. This reverses only upstream navigation; the history essay remains present.

**Changed paths:** `README.md`.

**Dependency:** Follows the preceding upstream commits in ancestry order; documentation context only.

**Rust applicability and evidence:** Full diff reviewed. This changes upstream
editorial material or its generated presentation; no native protocol, API,
configuration, CLI, or persistence change is required. Every changed path is
under `docs/` or is `README.md`. The commit retains the exact accepted `RNS`
tree `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`. Existing native compatibility
claims remain governed by test and parity evidence. Upstream opinions and
third-party allegations are not adopted as independently verified findings.
No runtime regression is applicable and no generated upstream prose is vendored.

**Final disposition:** Non-runtime. This analysis is the non-empty local mapping
whose sole `Upstream-Commit` trailer is `2289a8effae984d63bc69d10aa4e1d01a3088ed3`.
Local mapping: `f49faa017ae15b41701fa67313610dbebfe15921`.

### 9. `23101e45` — Updated readme

**Upstream change:** Expands the Community Implementations warning with chapter context, an alternative history-essay link, and links for evaluation and impact claims. These are upstream community guidance and editorial claims, not new interoperability criteria enforced by code.

**Changed paths:** `README.md`.

**Dependency:** Follows the preceding upstream commits in ancestry order; documentation context only.

**Rust applicability and evidence:** Full diff reviewed. This changes upstream
editorial material or its generated presentation; no native protocol, API,
configuration, CLI, or persistence change is required. Every changed path is
under `docs/` or is `README.md`. The commit retains the exact accepted `RNS`
tree `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`. Existing native compatibility
claims remain governed by test and parity evidence. Upstream opinions and
third-party allegations are not adopted as independently verified findings.
No runtime regression is applicable and no generated upstream prose is vendored.

**Final disposition:** Non-runtime. This analysis is the non-empty local mapping
whose sole `Upstream-Commit` trailer is `23101e45f6013d0f54aa2f8651bcde271c0b7ae9`.
Local mapping: `9361872285ec75cdfb22e8faaf5954e8c03d0c36`.

### 10. `8743ddcb` — Updated readme

**Upstream change:** Adds horizontal rules around the Community Implementations warning paragraph in the README; presentation only.

**Changed paths:** `README.md`.

**Dependency:** Follows the preceding upstream commits in ancestry order; documentation context only.

**Rust applicability and evidence:** Full diff reviewed. This changes upstream
editorial material or its generated presentation; no native protocol, API,
configuration, CLI, or persistence change is required. Every changed path is
under `docs/` or is `README.md`. The commit retains the exact accepted `RNS`
tree `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`. Existing native compatibility
claims remain governed by test and parity evidence. Upstream opinions and
third-party allegations are not adopted as independently verified findings.
No runtime regression is applicable and no generated upstream prose is vendored.

**Final disposition:** Non-runtime. This analysis is the non-empty local mapping
whose sole `Upstream-Commit` trailer is `8743ddcbe52be7f88e764b1cdd7af009bd4d62a2`.
Local mapping: `75fa8ce86057ea2fff6f8385c1d468689323d715`.

### 11. `cb66b3d1` — Updated readme

**Upstream change:** Extends the README editorial warning to mention user-facing applications as well as implementations. No application behavior or compatibility contract changes.

**Changed paths:** `README.md`.

**Dependency:** Follows the preceding upstream commits in ancestry order; documentation context only.

**Rust applicability and evidence:** Full diff reviewed. This changes upstream
editorial material or its generated presentation; no native protocol, API,
configuration, CLI, or persistence change is required. Every changed path is
under `docs/` or is `README.md`. The commit retains the exact accepted `RNS`
tree `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`. Existing native compatibility
claims remain governed by test and parity evidence. Upstream opinions and
third-party allegations are not adopted as independently verified findings.
No runtime regression is applicable and no generated upstream prose is vendored.

**Final disposition:** Non-runtime. This analysis is the non-empty local mapping
whose sole `Upstream-Commit` trailer is `cb66b3d10fd34a6aedb16c78f00a720383dbb122`.
Local mapping: `0292821f5fc8922fe1f8352e3628a55a5559a8d7`.

### 12. `ddd55d50` — Updated readme

**Upstream change:** Replaces a numeric word-count description of the linked chapter with general length/detail wording and changes designed to intended.

**Changed paths:** `README.md`.

**Dependency:** Follows the preceding upstream commits in ancestry order; documentation context only.

**Rust applicability and evidence:** Full diff reviewed. This changes upstream
editorial material or its generated presentation; no native protocol, API,
configuration, CLI, or persistence change is required. Every changed path is
under `docs/` or is `README.md`. The commit retains the exact accepted `RNS`
tree `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`. Existing native compatibility
claims remain governed by test and parity evidence. Upstream opinions and
third-party allegations are not adopted as independently verified findings.
No runtime regression is applicable and no generated upstream prose is vendored.

**Final disposition:** Non-runtime. This analysis is the non-empty local mapping
whose sole `Upstream-Commit` trailer is `ddd55d50cc30c49bec99d359a0f73a9cc15d436d`.
Local mapping: `633f0615efb853c05a5bb44be518fceae4fad9c2`.

### 13. `34b36362` — Scratch that

**Upstream change:** Removes one personal descriptor from a paragraph in the historical essay; no executable or licensing change.

**Changed paths:** `docs/history/2026_09_18_Yes_I_am_Angry.md`.

**Dependency:** Follows the preceding upstream commits in ancestry order; documentation context only.

**Rust applicability and evidence:** Full diff reviewed. This changes upstream
editorial material or its generated presentation; no native protocol, API,
configuration, CLI, or persistence change is required. Every changed path is
under `docs/` or is `README.md`. The commit retains the exact accepted `RNS`
tree `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`. Existing native compatibility
claims remain governed by test and parity evidence. Upstream opinions and
third-party allegations are not adopted as independently verified findings.
No runtime regression is applicable and no generated upstream prose is vendored.

**Final disposition:** Non-runtime. This analysis is the non-empty local mapping
whose sole `Upstream-Commit` trailer is `34b36362ab9b2ef9b20bafb3db146261e1d75191`.
Local mapping: `f7e3c839d5249dcd9e82df2c6ed40bfc2b79625d`.

### 14. `15e6dd4a` — Updated docs

**Upstream change:** Regenerates the Sphinx search index: populates previously empty API indexentries and removes three empty term entries (etiquett, tightli, unfudg). The complete one-line artifact diff was reviewed after lossless comma-based line splitting; Python API implementations are unchanged. Native documentation does not vendor this Sphinx index.

**Changed paths:** `docs/manual/searchindex.js`.

**Dependency:** Follows the preceding upstream commits in ancestry order; documentation context only.

**Rust applicability and evidence:** Full diff reviewed. This changes upstream
editorial material or its generated presentation; no native protocol, API,
configuration, CLI, or persistence change is required. Every changed path is
under `docs/` or is `README.md`. The commit retains the exact accepted `RNS`
tree `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`. Existing native compatibility
claims remain governed by test and parity evidence. Upstream opinions and
third-party allegations are not adopted as independently verified findings.
No runtime regression is applicable and no generated upstream prose is vendored.

**Final disposition:** Non-runtime. This analysis is the non-empty local mapping
whose sole `Upstream-Commit` trailer is `15e6dd4a882f0cea81b4e899120f46787aaeb8a2`.
Local mapping: `ca20cbecee4d9ff238562fc51c8d3074fc015d20`.

### 15. `395241b1` — Updated docs

**Upstream change:** Corrects history-essay grammar and emphasis, revises an asserted request count, and expands a case-study introduction with an editorial cross-reference while removing escaped spacing. The third-party claims are not compatibility requirements or native findings.

**Changed paths:** `docs/history/2026_09_18_Yes_I_am_Angry.md`, `docs/source/brandolinis.rst`.

**Dependency:** Follows the preceding upstream commits in ancestry order; documentation context only.

**Rust applicability and evidence:** Full diff reviewed. This changes upstream
editorial material or its generated presentation; no native protocol, API,
configuration, CLI, or persistence change is required. Every changed path is
under `docs/` or is `README.md`. The commit retains the exact accepted `RNS`
tree `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`. Existing native compatibility
claims remain governed by test and parity evidence. Upstream opinions and
third-party allegations are not adopted as independently verified findings.
No runtime regression is applicable and no generated upstream prose is vendored.

**Final disposition:** Non-runtime. This analysis is the non-empty local mapping
whose sole `Upstream-Commit` trailer is `395241b190ae4bc6e5d8070c8ff0a01afd24bdc9`.
Local mapping: `20cd1e49ebfe566fa963681dfbbacb076d4c49ac`.

### 16. `99de23c0` — Updated docs

**Upstream change:** Propagates the 395241b1 chapter edit into the generated RST copy, HTML and Markdown, and adds its tactic token to the Sphinx search index. The full generated index diff was inspected with lossless comma splitting. This adds no independent runtime behavior.

**Changed paths:** `docs/manual/_sources/brandolinis.rst.txt`, `docs/manual/brandolinis.html`, `docs/manual/searchindex.js`, `docs/markdown/brandolinis.md`.

**Dependency:** Follows the preceding upstream commits in ancestry order; documentation context only.

**Rust applicability and evidence:** Full diff reviewed. This changes upstream
editorial material or its generated presentation; no native protocol, API,
configuration, CLI, or persistence change is required. Every changed path is
under `docs/` or is `README.md`. The commit retains the exact accepted `RNS`
tree `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`. Existing native compatibility
claims remain governed by test and parity evidence. Upstream opinions and
third-party allegations are not adopted as independently verified findings.
No runtime regression is applicable and no generated upstream prose is vendored.

**Final disposition:** Non-runtime. This analysis is the non-empty local mapping
whose sole `Upstream-Commit` trailer is `99de23c040d507e3fefca19e87b182302902725d`.
Local mapping: `c20ef338b88b0250f45b79e22115488a7184214c`.

## Mapping Verification

| Upstream commit | Local mapping commit |
|---|---|
| `484cf2d1a56e657e1310655e15b5a8159b71ce21` | `beea0bb89e94784f05d09170a338ba14c805d06f` |
| `abf355b4d72d5669496dae3220bf5836c5610bcf` | `4a5ac542b78b5d4adb8fd3bb31fa1abf7e996e1d` |
| `29f6bc8652e490e6489741c16bdc2b7d142bbcc9` | `76be107c331043cd4a893069db42957ffbb7b75a` |
| `7373f813495b8134e3ca3274a1b988c1fa97b106` | `a05fe6abf287ac8a41903ac75f19184e27b8c316` |
| `58881af30703ad74d80e4e9135713abdba6b26dd` | `784bf6dbe593f9c32944120aa12a0ca23e91190d` |
| `9d85931c9d85c7a6549364c572fe2532ca5a9d99` | `d469b17464270d6bedd08b335642bcf3656dc66b` |
| `3c479ddb65bf86c0bbaa3565861db97171bb2a4a` | `15a0175af554231374030539c868d15dd68a4b00` |
| `2289a8effae984d63bc69d10aa4e1d01a3088ed3` | `f49faa017ae15b41701fa67313610dbebfe15921` |
| `23101e45f6013d0f54aa2f8651bcde271c0b7ae9` | `9361872285ec75cdfb22e8faaf5954e8c03d0c36` |
| `8743ddcbe52be7f88e764b1cdd7af009bd4d62a2` | `75fa8ce86057ea2fff6f8385c1d468689323d715` |
| `cb66b3d10fd34a6aedb16c78f00a720383dbb122` | `0292821f5fc8922fe1f8352e3628a55a5559a8d7` |
| `ddd55d50cc30c49bec99d359a0f73a9cc15d436d` | `633f0615efb853c05a5bb44be518fceae4fad9c2` |
| `34b36362ab9b2ef9b20bafb3db146261e1d75191` | `f7e3c839d5249dcd9e82df2c6ed40bfc2b79625d` |
| `15e6dd4a882f0cea81b4e899120f46787aaeb8a2` | `ca20cbecee4d9ff238562fc51c8d3074fc015d20` |
| `395241b190ae4bc6e5d8070c8ff0a01afd24bdc9` | `20cd1e49ebfe566fa963681dfbbacb076d4c49ac` |
| `99de23c040d507e3fefca19e87b182302902725d` | `c20ef338b88b0250f45b79e22115488a7184214c` |

All 16 mappings are unique, non-empty, and ordered identically to upstream.
No runtime implementation or native documentation behavior remains to port.

## Promotion Gates

- [x] Every upstream commit has a final Non-runtime disposition and unique mapping.
- [x] Full diffs reviewed; focused runtime regressions are inapplicable.
- [x] Runtime-tree identity checked at every commit; fixtures and provenance unchanged.
- [x] Exact-target interop assessed as inapplicable to this byte-identical runtime delta; not rerun.
- [x] Workspace tests, formatting, and warning-free host lint passed.
- [x] Build and daily manual results recorded; Docker/cross/hardware checks explicitly unclaimed.
- [x] Native tracking documentation updated; no upstream editorial content needs vendoring.
- [x] Final acceptance record: [reticulum-1.5.4-rgit-3-parity.md](reticulum-1.5.4-rgit-3-parity.md).

## Acceptance Record

Checks performed on 2026-09-20:

- `cargo test --workspace`: 2,517 passed, 0 failed, 9 ignored (68 result groups).
- `cargo fmt --check`: passed.
- `bash scripts/lint-host.sh`: passed; all workspace targets, native hooks,
  warnings denied with the script's existing lint allowances.
- Daily release builds of native-hook `rns-server` and `rns-ctl`: passed at
  `503d1fc`; native sources are unchanged by this documentation advancement.
- Daily `scripts/manual-backbone-smoke.sh --daily`: passed, including four
  bidirectional Resource sizes through 1 MiB, concurrent Resources, two link
  batches at concurrency three, latency/jitter/bandwidth impairment, and one
  forced Backbone disconnection and end-to-end recovery cycle.
- Both VPS snapshots healthy, complete, and published to the shared report DB.
- Final refreshed GitHub and rgit tips agree on the accepted target.

Workspace tests and the smoke test used socket access outside the sandbox.
No new exact-target interop, optional-feature test matrix, fixture regeneration,
Docker E2E, cross-build, or physical hardware test is claimed for this
non-runtime advancement. Existing CI pins and fixture provenance remain intact.
Upstream editorial opinions, legal interpretations, performance claims and
third-party allegations are not independently verified or adopted as native
findings. Earlier acceptance records remain unchanged.
