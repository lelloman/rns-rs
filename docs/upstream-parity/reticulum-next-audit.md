# Reticulum Next Upstream Audit

## Scope and Baseline

- audit date: `2026-09-12`
- previous accepted version: `1.5.3`
- previous normative commit: `fae64abf05a0ec5afabb2def9076f70d42bfe600`
- target version: `1.5.4` (tip metadata; final release target not yet selected)
- target tag or ref: `rgit/master`
- target normative commit: `0dbc9e90a33c427befd3873aa29bd6e8463ba192`
- target root tree: `c19f02deaed560e3ac9d9ff8b78704eac3003649`
- target `RNS` tree: `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`
- version assertion: `RNS.__version__ == "1.5.4"`
- audited range: `fae64abf05a0ec5afabb2def9076f70d42bfe600..0dbc9e90a33c427befd3873aa29bd6e8463ba192`
- commits in range: `6`
- repositories checked: normative rgit repository and GitHub mirror
- local branch and revision inspected: `dev@9b6bfb431a78863c5e118d0959d42546bd6d02de`

The rgit tip is six commits ahead of the accepted baseline. The GitHub mirror
tip is `ea98db4f53dcf0defc0e71a16e60d28b1229c4e6` and remains behind the accepted
baseline. Both remotes were fetched successfully on 2026-09-12. All six commits
now have final dispositions and ordered local mappings. The target version is
`1.5.4` from the rgit tip; baseline promotion remains pending completion of the
promotion gates below.

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

| # | Upstream commit | Subject | Final disposition | Local evidence |
|---:|---|---|---|---|
| 1 | `0c97853554956bee29ab95f633642b9ce72520f9` | Fix RNode BLE device address acquisition on windows, by Nickie Deuxyeux | Non-runtime | No host-side BLE client exists; serial-only RNode; `c6f9ef10` precedent |
| 2 | `996d822393d194030b67ee176766878522f30998` | Fixed RNode BLE re-connection deadlock on desktop. Cleanup. | Non-runtime | No host-side BLE client exists; serial-only RNode; `c6f9ef10` precedent |
| 3 | `851c18bc273833e33c02f574c52ad693512b5a40` | Improved RNode BLE reconnect reliability | Non-runtime | No host-side BLE client exists; serial-only RNode; `c6f9ef10` precedent |
| 4 | `7785fd277aec1cdcfbe5d9f00c6cd104194ad865` | Updated version | Non-runtime | Full one-line diff: Python package metadata `1.5.3` → `1.5.4`; native crate versions remain independently released |
| 5 | `9199cc9e4b20189966e157d654dee1c12ea884ba` | Updated changelog | Non-runtime | Release notes only; the three listed BLE fixes map to commits 1–3; upstream changelog not vendored |
| 6 | `0dbc9e90a33c427befd3873aa29bd6e8463ba192` | Prepare release | Non-runtime | Generated `docs/manual` artifacts only; `RNS` tree identical to parent (`b4c1cf36`) |

## Per-Commit Analysis

### 1. `0c97853` — RNode BLE device address acquisition on Windows

**Upstream change:** Adds a Windows-specific paired-BLE-address lookup through
WinRT (`BluetoothLEDevice.get_device_selector_from_pairing_state` plus
`DeviceInformation.find_all_async_aqs_filter`) so that
`BLEConnection.device_bonded()` recognises paired peripherals, initializes the
`_windows_paired_addrs` cache, marks the connection job running, and corrects
two diagnostic strings. Changed path: `RNS/Interfaces/RNodeInterface.py`. Full
diff and surrounding upstream code reviewed.

**Rust applicability:** This repository implements RNode interfaces over serial
transport only (see `rns-net/src/interface/rnode/`). It has no host-side
Bluetooth/BLE client, no `bleak`-equivalent scanner, and no bonded-device
selection state. A repository-wide search for `BLE`, `bleak`, `Bluetooth` and
`device_bonded` found only unrelated substrings and no host BLE code. The ESP32
RNode support is a BLE peripheral bridge, not the affected central client.

**Local handling and evidence:** The affected `BLEConnection` client discovery
path does not exist here. The accepted audit dispositioned
`c6f9ef1047c594e9d9e800692d3a0a68bd7a0c94` ("RNodeInterface: fix stale
ble_device") as Non-runtime for the same reason. No production change or
synthetic regression is appropriate for an unimplemented platform path.

**Final disposition:** Non-runtime.

### 2. `996d822` — RNode BLE reconnect deadlock cleanup

**Upstream change:** Clears `device_disappeared` on a successful BLE connect,
switches the Windows check from `platform.system()` to
`RNS.vendor.platformutils.is_windows()`, and collapses three single-statement
`if`/`else`/`return` blocks. Changed path:
`RNS/Interfaces/RNodeInterface.py`. Full diff reviewed for hidden control-flow
changes: the only behavioral edit is the `device_disappeared` reset plus the
platform-predicate swap, both inside the desktop BLE client.

**Rust applicability:** The desktop BLE connection state machine, its
`device_disappeared` reconnect field, and the `platformutils` predicate are not
implemented locally. The collapsed `if` blocks are Python formatting and have
no Rust equivalent.

**Local handling and evidence:** Audit pending; see commit 1 for the absent
host-side BLE client. No production change or synthetic regression is
appropriate for an unimplemented platform path.

**Final disposition:** Non-runtime.

### 3. `851c18b` — RNode BLE reconnect reliability

**Upstream change:** Logs previous-BLE-connection cleanup before closing it, and
on a BLE detect timeout stops the connection run loop and requests disconnect so
the next attempt starts from clean state. Changed path:
`RNS/Interfaces/RNodeInterface.py`. Full diff and the surrounding BLE detect
sequence reviewed.

**Rust applicability:** Applies only to the desktop BLE client run loop and its
`should_run`/`must_disconnect` teardown flags, which do not exist in Rust.
Serial RNode detect, timeout and reconnect handling in
`rns-net/src/interface/rnode/` is a distinct transport and is unaffected.

**Local handling and evidence:** Audit pending; see commit 1 for the absent
host-side BLE client. No production change or synthetic regression is
appropriate for an unimplemented platform path.

**Final disposition:** Non-runtime.

### 4. `7785fd2` — Updated version

**Upstream change:** Bumps `RNS/_version.py` from `1.5.3` to `1.5.4`. Changed
path: `RNS/_version.py`. Full one-line diff reviewed; no other file changes.

**Rust applicability:** Rust crate versions are maintained independently from
the upstream Python package version and are not bumped for upstream release
markers. The version string identifies the release line, not acceptance
evidence.

**Local handling and evidence:** Verified `RNS.__version__ == "1.5.4"` at the
rgit tip. Upstream metadata only; target selection and baseline promotion
remain pending.

**Final disposition:** Non-runtime.

### 5. `9199cc9` — Updated changelog

**Upstream change:** Prepends the `2026-09-11: RNS 1.5.4` release note and moves
the `1.5.3` note down. Changed path: `Changelog.md`. Full diff reviewed.

**Rust applicability:** Upstream `Changelog.md` text is not vendored. The new
section describes only the RNode BLE connectivity changes in commits 1–3 and
identifies the release line; it is not acceptance evidence. Each listed behavior
is independently dispositioned from its source commit above and maps to the
absent host-side BLE client.

**Local handling and evidence:** No runtime code change. The changelog does not
change any compatibility surface.

**Final disposition:** Non-runtime.

### 6. `0dbc9e9` — Prepare release

**Upstream change:** Regenerates the hosted manual for the `1.5.4` release:
`docs/manual/.buildinfo`, `_static/documentation_options.js`, twenty HTML pages,
and the `objects.inv` intersphinx inventory. Full name-status diff reviewed; no
authored Markdown source is changed at this commit.

**Rust applicability:** Generated upstream manual and release artifacts are not
vendored by this repository.

**Local handling and evidence:** Verified the `RNS` tree at `0dbc9e9` is
identical to its parent (`b4c1cf368718971e1dcaf7c1cf2d1459411a360e`), so no
runtime tree change is present. The changes are version labels, the
documentation-options cache key, search-index terms and the inventory version
header only.

**Final disposition:** Non-runtime.

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

- `2026-09-12`: Both upstream remotes refreshed successfully. Daily VPS
  snapshots were healthy and complete with no query failures. The impaired
  dual-VPS `--daily` smoke run passed announces, cross-backbone identity recall,
  bidirectional packets, Links, Channels, concurrent Resources, bidirectional
  link stress, and one forced Backbone reconnect cycle.
- `2026-09-12`: All six commits dispositioned `Non-runtime` and mapped in
  ancestry order: `0c97853`→`c4eaf62`, `996d822`→`42d1aab`,
  `851c18b`→`813661d`, `7785fd2`→`89b303d`, `9199cc9`→`8afc2d2`,
  `0dbc9e9`→`455e9ad`. No Rust runtime, wire, configuration, RPC, CLI or
  persistence surface changed, so focused-regression, fixture, and exact-target
  interop gates are not applicable. The one-to-one `Upstream-Commit` trailer
  check passes with no duplicates or omissions. Baseline promotion remains
  pending the workspace gates below.
