# Reticulum 1.5.4 rgit `8a7ad40d` Upstream Audit

## Scope and Baseline

- audit date: `2026-09-25`
- previous accepted version: `1.5.4`
- previous normative commit: `c7be675739a26bd56fa743678d7dd80ddca39491`
- target version: `1.5.4`
- target tag or ref: `8a7ad40d649aae1cd755f060fa8f5619f7000b29` (matching GitHub and rgit tips)
- target normative commit: `8a7ad40d649aae1cd755f060fa8f5619f7000b29`
- target root tree: `d2edf15bcec20b101e6ecbdba1d2ec6d2a56aad1`
- target `RNS` tree: `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`
- version assertion: `RNS.__version__ == "1.5.4"` (unchanged from the accepted baseline)
- audited range: `c7be675739a26bd56fa743678d7dd80ddca39491..8a7ad40d649aae1cd755f060fa8f5619f7000b29`
- commits in range: `9`
- repositories checked: normative rgit repository and GitHub release mirror
- local branch and revision inspected: `dev@1253bfc529211d0b1dcb4b789a37cebce794d91f`

Both remotes refreshed successfully and point to the same commit. The target
changes upstream documentation and generated documentation artifacts only;
the `RNS` tree is byte-for-byte unchanged from the accepted baseline
(`b4c1cf368718971e1dcaf7c1cf2d1459411a360e`). The range was inventoried across
the `2026-09-23` and `2026-09-24` daily checks and is promoted on `2026-09-25`.

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

Every commit in the audited range appears exactly once.

| # | Upstream commit | Subject | Final disposition | Local evidence |
|---:|---|---|---|---|
| 1 | `192898864c008b6287dd56781d89fccef0bb5f7a` | Formatting and typos | Non-runtime | `0c00e33`; source-only review. |
| 2 | `780b7e6bfc477754b6f7cc263439ef0c7cbded06` | Updated software chapter of the manual | Non-runtime | `cb1caa1`; source-only review. |
| 3 | `ff4e04099cb180eea84635d9d3846a58dea638fe` | Updated readme | Non-runtime | `8ec3640`; source-only review. |
| 4 | `0af42a68859d9e3b54bb5040e76eca392885fb65` | Updated readme | Non-runtime | `5ad54e4`; source-only review. |
| 5 | `1f7dbe6dde57e103998a615db749e0606a48879e` | Updated readme | Non-runtime | `a6bcab5`; source-only review. |
| 6 | `c963581a6f26d9793e4b6dfe94be65cddc71bf11` | Updated readme | Non-runtime | `282452f`; source-only review. |
| 7 | `87a75c2553024d3579b152a6b7c126e0c0406839` | Added link | Non-runtime | `719defb`; source-only review. |
| 8 | `c4be063650939b9a598d58610d2e7678b4fbe1e2` | Fixed typo | Non-runtime | `e887463`; source-only review. |
| 9 | `8a7ad40d649aae1cd755f060fa8f5619f7000b29` | Fixed typo | Non-runtime | `4b02c88`; source-only review. |

## Per-Commit Analysis

### 1. `19289886` — Formatting and typos

**Upstream change:** Corrects and reformats documentation in the history,
manual, and Markdown documentation trees, including generated manual outputs.

**Rust applicability:** No runtime behavior changes. rns-rs maintains native
operator and protocol documentation and does not vendor upstream's generated
manual artifacts.

**Local handling and evidence:** No code change is required. The commit's
changed paths are all under upstream `docs/`, and `RNS` has the same tree ID at
the accepted baseline and target (`b4c1cf368718971e1dcaf7c1cf2d1459411a360e`).

**Final disposition:** Non-runtime.

### 2. `780b7e6b` — Updated software chapter of the manual

**Upstream change:** Updates the README community-software prose and the manual
software chapter, including new and replaced screenshots, in the `docs/source`
tree, then regenerates the `docs/manual` HTML/RST/search artifacts and
`docs/markdown` Markdown copies.

**Rust applicability:** No runtime, wire, configuration, RPC, or CLI behavior
changes. rns-rs keeps concise native documentation and does not vendor
upstream's generated Sphinx manual or screenshot assets.

**Local handling and evidence:** No code change is required. Every changed path
is under upstream `README.md` or `docs/`, and the `RNS` tree is unchanged.

**Final disposition:** Non-runtime.

### 3. `ff4e0409` — Updated readme

**Upstream change:** Expands the README's LLM-generated-fakes warning and adds a
pointer to the Programs Using Reticulum manual chapter.

**Rust applicability:** README prose only; no runtime surface.

**Local handling and evidence:** No code change is required. The only changed
path is `README.md`, which rns-rs does not vendor; the `RNS` tree is unchanged.

**Final disposition:** Non-runtime.

### 4. `0af42a68` — Updated readme

**Upstream change:** Adds the void-grants/licensing warning paragraphs, a new
Community Resources section, and reflows the Community Implementations prose in
`README.md`.

**Rust applicability:** README prose only; no runtime surface.

**Local handling and evidence:** No code change is required. The only changed
path is `README.md`; the `RNS` tree is unchanged.

**Final disposition:** Non-runtime.

### 5. `1f7dbe6d` — Updated readme

**Upstream change:** Refines the README Brandolini's Reference paragraph and adds
a direct Void Grants link.

**Rust applicability:** README prose only; no runtime surface.

**Local handling and evidence:** No code change is required. The only changed
path is `README.md`; the `RNS` tree is unchanged.

**Final disposition:** Non-runtime.

### 6. `c963581a` — Updated readme

**Upstream change:** Adjusts the README void-grants wording from "forgers" to
"violators" and "violating" to "infringing".

**Rust applicability:** README prose only; no runtime surface.

**Local handling and evidence:** No code change is required. The only changed
path is `README.md`; the `RNS` tree is unchanged.

**Final disposition:** Non-runtime.

### 7. `87a75c25` — Added link

**Upstream change:** Adds a Void Grants manual link to an existing passage in the
`docs/history/2026_09_18_Yes_I_am_Angry.md` essay.

**Rust applicability:** Historical essay hyperlink only; no runtime surface.

**Local handling and evidence:** No code change is required. The only changed
path is under upstream `docs/history/`; the `RNS` tree is unchanged.

**Final disposition:** Non-runtime.

### 8. `c4be0636` — Fixed typo

**Upstream change:** Corrects Ren Browser wording in `docs/source/software.rst`
("Reticulum Network using the ... stack" to "Nomad Network using the ...
implementation", and "it's embedded" to "it's own embedded").

**Rust applicability:** Manual source prose only; no runtime surface.

**Local handling and evidence:** No code change is required. The only changed
path is upstream manual source; the `RNS` tree is unchanged.

**Final disposition:** Non-runtime.

### 9. `8a7ad40d` — Fixed typo

**Upstream change:** Regenerates the corrected Ren Browser wording across the
manual source, HTML, Markdown, and search index.

**Rust applicability:** Generated manual artifacts only; no runtime surface.

**Local handling and evidence:** No code change is required. Changed paths are
confined to `docs/manual` and `docs/markdown`; the `RNS` tree is unchanged.

**Final disposition:** Non-runtime.

## Mapping Verification

| Upstream commit | Local mapping commit |
|---|---|
| `192898864c008b6287dd56781d89fccef0bb5f7a` | `0c00e33f1de2a56f4a1eba779a7b83e2c89278df` |
| `780b7e6bfc477754b6f7cc263439ef0c7cbded06` | `cb1caa1dbadcebf91737a749e5732b5d8b9fe2e1` |
| `ff4e04099cb180eea84635d9d3846a58dea638fe` | `8ec36407626888d8a0cc495f35c9d087b304b230` |
| `0af42a68859d9e3b54bb5040e76eca392885fb65` | `5ad54e46ecc4a901dc2774c39f4ae9ea415577d3` |
| `1f7dbe6dde57e103998a615db749e0606a48879e` | `a6bcab5ab4c24e20b7d40e09c5f8deff9fd4f847` |
| `c963581a6f26d9793e4b6dfe94be65cddc71bf11` | `282452f1051fe4c98fc67d7d6d6f4b08766ae187` |
| `87a75c2553024d3579b152a6b7c126e0c0406839` | `719defb6806ac58d9f9335463d1df4fde0228763` |
| `c4be063650939b9a598d58610d2e7678b4fbe1e2` | `e88746301048210bbee66220c00044969f4cdea3` |
| `8a7ad40d649aae1cd755f060fa8f5619f7000b29` | `4b02c8856fe088f67e3cecb3bc63fdfe22286e86` |

The mapping commits are non-empty, appear in the same ancestry order as the
upstream range, and each reviewed upstream hash appears exactly once in an
`Upstream-Commit` trailer.

## Integration Plan

Complete the applicable same-version rgit promotion gates.

## Promotion Gates

- [x] Every upstream commit has a final Non-runtime disposition and unique mapping.
- [x] Full diffs reviewed; focused runtime regressions are inapplicable.
- [x] Runtime-tree identity checked; fixture provenance is unchanged.
- [x] Exact-target interop assessed as inapplicable to this byte-identical runtime delta; not rerun.
- [x] Workspace tests, formatting, and warning-free host lint passed.
- [x] Release builds and daily manual results recorded; Docker, cross-build, and hardware gates explicitly unclaimed.
- [x] Native tracking documentation updated; no upstream editorial content needs vendoring.
- [x] Final acceptance record: [reticulum-1.5.4-rgit-5-parity.md](reticulum-1.5.4-rgit-5-parity.md).

## Acceptance Record

- `2026-09-23`: Both upstream remotes refreshed successfully and agreed on
  `192898864c008b6287dd56781d89fccef0bb5f7a`; one commit is ahead of the
  accepted baseline. The commit is documentation-only and the upstream `RNS`
  tree is unchanged.
- `2026-09-23`: Native-hook release builds of `rns-server` and `rns-ctl`
  succeeded. The `vps-us` daily snapshot was healthy with 28/28 public
  interfaces up, primary peer up, and live traffic queries successful.
- `2026-09-23`: The `vps-eu` snapshot did not complete: `rns-ctl status -j`
  returned `Could not connect to rnsd: authentication failed`. No complete
  `vps-eu` row was recorded for this date.
- `2026-09-23`: The impaired daily Backbone smoke failed after initial
  cross-backbone identity recall and packet delivery passed; a later packet
  was not observed on node A. Diagnostics were retained at
  `/tmp/rns-backbone-smoke.Bfhhte`.
- `2026-09-23`: A shorter, unimpeded smoke reproduced the same directional
  failure: A-to-B packet delivery passed, while B-to-A timed out. EU has both
  `rnsd.service` and `rns-server.service` active. The standalone daemon uses
  `/root/.reticulum` and owns the public Backbone listener on port 4242 and
  RPC port 37429. The intended supervised daemon uses `/var/lib/rns-node` and
  logged bind failures on both ports at startup. EU `rns-ctl`, `rns-statsd`,
  and `rns-sentineld` cannot authenticate against the standalone daemon's RPC
  server; EU stats stopped at `2026-09-22 19:13:44 UTC`. This is an operational
  service conflict, with the exact packet drop point not yet traced.
- `2026-09-23`: Stopped the extra EU `rnsd.service` and restarted the intended
  `rns-server.service`. The supervised child now owns ports 4242 and 37429,
  `rns-ctl` authenticates, and stats and sentinel hooks loaded. A fresh EU
  snapshot was healthy with 48/48 public interfaces up; the existing US
  snapshot was healthy with 28/28 up. The full impaired `--daily` smoke then
  passed bidirectional packets, channels, all four Resource sizes through
  1 MiB, concurrent links, and forced Backbone reconnect recovery. The
  reviewed two-host report database was published to `vps-eu` with matching
  local and remote SHA-256
  `30163c79d62cda1827f2b4195018998d2bf98d037675d41dad1f859a8a6ffa76`.
   EU rolling traffic totals have a collection gap between the prior stats
   stop and this restart.
- `2026-09-24`: Both upstream remotes refreshed successfully (GitHub 14:44:38
  UTC, rgit 14:45:15 UTC) and agreed on the new tip
  `8a7ad40d649aae1cd755f060fa8f5619f7000b29`. Eight commits were observed after
  the previously inventoried `192898864c008b6287dd56781d89fccef0bb5f7a`, for
  nine commits total ahead of the accepted baseline. All eight are
  documentation-only (README prose, manual source/screenshots, generated
  manual HTML/Markdown/search artifacts, one history-essay link), and the
  target `RNS` tree is unchanged at
  `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`. This inventory extension assigns
  each a `Non-runtime` disposition.
- `2026-09-24`: The daily per-host snapshots were healthy (EU 47/47 up, US
  26/26 up) and the impaired `--daily` Backbone smoke test passed announces,
  identity recall, bidirectional packets, four Resource sizes through 1 MiB,
  concurrent links, and forced Backbone reconnection recovery. The reviewed
  report database was published to `vps-eu`.
- `2026-09-25`: Both upstream remotes refreshed successfully (GitHub 06:08:49
  UTC, rgit 06:08:54 UTC) and agreed on
  `8a7ad40d649aae1cd755f060fa8f5619f7000b29`; the nine-commit range and target
  `RNS` tree (`b4c1cf368718971e1dcaf7c1cf2d1459411a360e`) were unchanged from the
  `2026-09-24` inventory, and each commit was mapped by a non-empty local commit
  carrying its unique `Upstream-Commit` trailer.
- `2026-09-25`: `cargo test --workspace` passed, `cargo fmt --check` passed, and
  `bash scripts/lint-host.sh` passed under its configured warning-denial policy.
  Native-hook `rns-server` and `rns-ctl` release builds succeeded.
- `2026-09-25`: The impaired daily dual-VPS `--daily` Backbone smoke passed
  announces, cross-backbone identity recall, bidirectional packets, four
  Resource sizes through 1 MiB, concurrent links, and forced reconnect
  recovery. The healthy per-host snapshots (EU 53/53 up, US 24/24 up) and the
  reviewed report database were published to `vps-eu`. Physical hardware
  validation remains unclaimed.

The target `RNS` tree is byte-identical to the prior accepted baseline. No new
exact-target interop, fixture regeneration, Docker E2E, cross-build, or
physical-hardware run is claimed. Upstream editorial and legal opinions are not
independently verified or adopted as native findings.
