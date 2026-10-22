# Reticulum 1.5.7 rgit `ee82fa75` Upstream Audit

## Scope and Baseline

- audit date: `2026-10-22`
- previous accepted version: `1.5.7`
- previous normative commit: `a29bfb51c468945c96a1ee22cae0114e993e2391`
- target version: `1.5.7` (unchanged from the accepted baseline)
- target tag or ref: canonical `rgit/master` tip at `ee82fa75a75ec67555126eb16796ea1a52716a2b` (GitHub mirror is behind; same-version rgit advancement)
- target normative commit: `ee82fa75a75ec67555126eb16796ea1a52716a2b`
- target root tree: `fde9c85ca4514cc3f1bd32280d19da870fad76a8`
- target `RNS` tree: `45eccb7ec1009d9b24f3d17f42d5cf8848537cec`
- version assertion: `RNS.__version__ == "1.5.7"` (unchanged from the accepted baseline)
- audited range: `a29bfb51c468945c96a1ee22cae0114e993e2391..ee82fa75a75ec67555126eb16796ea1a52716a2b`
- commits in range: `2`
- repositories checked: normative `rgit/master` and the GitHub `origin/master` mirror
- local branch and revision inspected: `upstream-parity-1.5.7-rgit@d06a2af` (mapping and mapping-evidence tip); the accepted upstream checkout remains at `a29bfb51c468945c96a1ee22cae0114e993e2391`

The 2026-10-22 daily drift check fetched both remotes successfully. The rgit
tip is ahead of the baseline by two commits. The GitHub mirror tip
`e40191b3d193b46b7f2d8a44424a594cd758839b` is behind the baseline and does not
contain either new commit, so the remotes disagree and the rgit tip is the
normative target. The upstream version was not bumped, so this is accepted as a
same-version canonical `rgit/master` advancement with the qualified `-rgit`
record filenames.

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
| 1 | `ae67448e88a8fdc185b79e694ff3ef8ba7192b4e` | `Fixed rngit default config path typo for ~/.config/rngit case` | `Structurally covered` | `f168ba2`; `default_rngit_dir_prefers_config_dir_over_legacy_path` regression |
| 2 | `ee82fa75a75ec67555126eb16796ea1a52716a2b` | `Fixed missing reports_phy_stats on Android RNodeInterface` | `Structurally covered` | `d06a2af`; `rnode_rx_metadata_reports_rssi_and_snr` regression |

## Per-Commit Analysis

### 1. `ae67448e` — `Fixed rngit default config path typo for ~/.config/rngit case`

**Upstream change:** When `~/.config/rngit` exists and contains a `config`
file, the Python rngit server now selects that directory as its configuration
directory. It previously assigned the wrong `~/.rngit/reticulum` path in that
branch.

**Rust applicability:** The Rust `rngit` binary selects its configuration
directory in `default_rngit_dir()`. It honors `RNGIT_CONFIG`, then prefers
`$XDG_CONFIG_HOME/rngit` (defaulting to `~/.config/rngit`) when that path
exists or the legacy `~/.rngit` path does not, and otherwise keeps `~/.rngit`.

**Local handling and evidence:** The native implementation does not contain the
upstream branch or path typo. Mapping commit `f168ba2` adds
`default_rngit_dir_prefers_config_dir_over_legacy_path`, which creates both
directories and requires the `.config/rngit` path to win. Existing tests cover
the XDG-preferred default and the retained legacy path.

**Final disposition:** `Structurally covered`

### 2. `ee82fa75` — `Fixed missing reports_phy_stats on Android RNodeInterface`

**Upstream change:** The upstream Python `RNS/Interfaces/Android/RNodeInterface.py`
sets `reports_phy_stats = True`. The base `Interface` class defaults the flag to
`False`, so without this assignment the Android RNode interface did not report
physical-layer statistics such as RSSI and SNR.

**Rust applicability:** rns-rs has no Python Android `RNodeInterface`; the
Android client is the native `rns-tun-android` VPN client. The native RNode
driver in `rns-net` has no `reports_phy_stats` gate: it records the latest RSSI
and SNR from RNode KISS status events and attaches them to received packets
unconditionally.

**Local handling and evidence:** Mapping commit `d06a2af` adds
`rnode_rx_metadata_reports_rssi_and_snr` to pin the RSSI offset and SNR scaling
and to prove both values are retained for the next received frame. The behavior
this commit restores is already present by construction in the native driver,
so no production code change was required.

**Final disposition:** `Structurally covered`

## Mapping Verification

| Upstream commit | Local mapping commit |
|---|---|
| `ae67448e88a8fdc185b79e694ff3ef8ba7192b4e` | `f168ba2385955b75ba006d38bf1fe83bb64ef676` |
| `ee82fa75a75ec67555126eb16796ea1a52716a2b` | `d06a2af4f3f0c837fb14066339e8e5dd0023fbb9` |

Each mapping commit is non-empty, appears in the same ancestry order as the
upstream range, and the reviewed upstream hash appears exactly once in an
`Upstream-Commit` trailer.

## Integration Plan

Both in-range commits have a final `Structurally covered` disposition and a
non-empty mapping commit. The mappings add focused regressions only; no
production Rust code changed, so no runtime port remains outstanding. The
accepted same-version record is
[reticulum-1.5.7-rgit-parity.md](reticulum-1.5.7-rgit-parity.md); this audit is
retained as the detailed pre-promotion work record.

## Promotion Gates

- [x] Every upstream commit has a final `Structurally covered` disposition and a unique mapping.
- [x] Focused regressions pass: all three `default_rngit_dir_*` tests and both RNode metadata tests passed.
- [x] No native runtime or fixture change; the durable artifacts are the two new regressions.
- [x] Exact-target interop assessed as inapplicable: the changed upstream files are Python rngit configuration selection and the Python Android RNode interface, neither of which is a wire or crypto surface, and no native runtime code changed.
- [x] Workspace tests, formatting, and warning-free host lint passed (`cargo test --workspace` 2,888 passed; `cargo fmt --all --check`; `bash scripts/lint-host.sh`, 2026-10-22).
- [x] Native-hook `rns-server` and `rns-ctl` release builds passed (`0.6.1600-d06a2af` / `0.7.1600-d06a2af`); Docker was not rerun for this test-only native delta; daily impaired dual-VPS stress passed on 2026-10-22; physical hardware validation remains unclaimed.
- [x] Native documentation records the structural coverage; no user-visible native behavior changed.
- [x] A final parity record is created from `PARITY-TEMPLATE.md`.

## Acceptance Record

- `2026-10-22`: The daily drift check fetched `rgit` and GitHub successfully
  and found two commits after `a29bfb51`. GitHub is behind the baseline, so the
  comparison is based on the rgit tip.
- `2026-10-22`: Landed mapping commits `f168ba2` and `d06a2af` in upstream
  ancestry order, each with exactly one full `Upstream-Commit` trailer.
- `2026-10-22`: `cargo test --workspace` passed (2,888 tests, 0 failed);
  `cargo fmt --all --check` and `bash scripts/lint-host.sh` passed.
- `2026-10-22`: Native-hook release builds produced
  `rns-server 0.6.1600-d06a2af` and `rns-ctl 0.7.1600-d06a2af`.
- `2026-10-22`: The daily impaired dual-VPS `--daily` Backbone smoke passed on
  the unchanged native runtime; the local operator report is
  `data/daily-report-2026-10-22.md`.

Docker, cross-builds, exact-target Python/Rust interop, and physical hardware
validation were not rerun and remain unclaimed. No planned test is counted as
passed.
