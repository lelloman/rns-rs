# Reticulum Next Upstream Audit

## Scope and Baseline

- audit date: `2026-10-22`
- previous accepted version: `1.5.7`
- previous normative commit: `a29bfb51c468945c96a1ee22cae0114e993e2391`
- target version: `pending` (the rgit tip still reports `RNS.__version__ == "1.5.7"`)
- target tag or ref: `rgit/master` (untagged) at `ee82fa75a75ec67555126eb16796ea1a52716a2b`
- target normative commit: `ee82fa75a75ec67555126eb16796ea1a52716a2b`
- target root tree: `fde9c85ca4514cc3f1bd32280d19da870fad76a8`
- target `RNS` tree: `45eccb7ec1009d9b24f3d17f42d5cf8848537cec`
- version assertion: `RNS.__version__ == "1.5.7"` at the target tip
- audited range: `a29bfb51c468945c96a1ee22cae0114e993e2391..ee82fa75a75ec67555126eb16796ea1a52716a2b`
- commits in range: `2`
- repositories checked: normative `rgit/master` and the GitHub `origin/master` mirror
- local branch and revision inspected: accepted checkout at `a29bfb51c468945c96a1ee22cae0114e993e2391`; newer objects inspected with `git show` without advancing the checkout

The 2026-10-22 daily drift check fetched both remotes successfully. The rgit
tip is ahead of the baseline by two commits. The GitHub mirror tip
`e40191b3d193b46b7f2d8a44424a594cd758839b` is behind the baseline and does not
contain either new commit, so the remotes disagree and the rgit tip is the
normative target. The upstream version was not bumped, so the eventual record is
expected to be a same-version rgit advancement rather than a new release.

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

Every commit in the audited range must appear exactly once.

| # | Upstream commit | Subject | Final disposition | Local evidence |
|---:|---|---|---|---|
| 1 | `ae67448e88a8fdc185b79e694ff3ef8ba7192b4e` | Fixed rngit default config path typo for ~/.config/rngit case | Structurally covered | `rns-git/src/util.rs:11` prefers `~/.config/rngit`; tests at `rns-git/src/util.rs:229` and `rns-git/src/util.rs:245` |
| 2 | `ee82fa75a75ec67555126eb16796ea1a52716a2b` | Fixed missing reports_phy_stats on Android RNodeInterface | Structurally covered | Native RNode driver consumes RSSI/SNR unconditionally at `rns-net/src/interface/rnode/mod.rs:444`; no Python Android `RNodeInterface` or `reports_phy_stats` gate exists |

## Per-Commit Analysis

### 1. `ae67448e` — Fixed rngit default config path typo for ~/.config/rngit case

**Upstream change:** When `~/.config/rngit` exists and contains a `config`
file, the Python rngit server now selects that directory as its configuration
directory. It previously assigned the wrong `~/.rngit/reticulum` path in that
branch.

**Rust applicability:** The Rust `rngit` binary selects its configuration
directory in `default_rngit_dir()`. It honors `RNGIT_CONFIG`, then prefers
`$XDG_CONFIG_HOME/rngit` (defaulting to `~/.config/rngit`) when that path
exists or the legacy `~/.rngit` path does not, and otherwise keeps `~/.rngit`.

**Local handling and evidence:** The native implementation does not contain the
upstream branch or path typo. Existing unit tests cover both the XDG-preferred
default and the retained legacy path.

**Final disposition:** Structurally covered.

### 2. `ee82fa75` — Fixed missing reports_phy_stats on Android RNodeInterface

**Upstream change:** The upstream Python `RNS/Interfaces/Android/RNodeInterface.py`
sets `reports_phy_stats = True`. The base `Interface` class defaults the flag to
`False`, so without this assignment the Android RNode interface did not report
physical-layer statistics such as RSSI and SNR.

**Rust applicability:** rns-rs has no Python Android `RNodeInterface`; the
Android client is the native `rns-tun-android` VPN client. The native RNode
driver in `rns-net` has no `reports_phy_stats` gate: it records the latest RSSI
and SNR from RNode KISS status events and attaches them to received packets
unconditionally.

**Local handling and evidence:** The behavior this commit restores is already
present by construction in the native driver, so no runtime change or new test
is required.

**Final disposition:** Structurally covered.

## Integration Plan

No runtime port is expected for either commit. To close the audit, add one
non-empty mapping commit per upstream commit carrying the `Upstream-Commit`
trailer that records this structural-coverage rationale, confirm the target is a
same-version rgit advancement (`reticulum-1.5.7-rgit-audit`/`-parity` naming),
then run the promotion gates.

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

- `2026-10-22`: The daily drift check fetched `rgit` and GitHub successfully
  and found two commits after `a29bfb51`. GitHub is behind the baseline, so the
  comparison is based on the rgit tip. No integration work has been performed
  yet; both commits received an initial structural-coverage disposition.
