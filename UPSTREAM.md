# Upstream Reticulum Tracking

This repository is a Rust implementation of the Python Reticulum project.

The current upstream reference baseline is:

- Project: Reticulum
- Repository: `https://github.com/markqvist/Reticulum`
- Local checkout used: `/home/lelloman/Reticulum`
- Tag: `1.2.5`
- Commit: `e8d161c0d50cc0416c98dcd1cee44807e7c52df1`
- Commit date: `2026-05-09 19:17:38 +0200`
- Subject: `Yes, that was indeed a bit overkill`

The previous recorded baseline was Reticulum `1.2.4`, with release commit
`9d076d6a194ee9675a5bf585de1b2c2a634f3946`. The upstream
`1.2.4..1.2.5` range was reviewed and the relevant path-request control,
`rnstatus`, `rnpath`, `rnid`, discovery, transport, and `rngit` changes were
ported or explicitly audited with the following local commits:

- `3bb19d7` Add path request control core
- `12a250d` Gate recursive path requests
- `a22d307` Add ingress control config defaults
- `0f5221c` Add rnstatus path request stats
- `37adc59` Validate rngit refs and SHAs
- `f9f106f` Harden rngit stats and work limits
- `8eea4e2` Reject slashed rngit release tags
- `93b97c2` Fix rngit rendering escapes
- `bba47af` Hide rngit git failure details from clients
- `1ca8cd6` Add rnid ASCII RSG output
- `e3211e5` Ignore initiator-closed remote links
- `d7cf58d` Show rnstatus per-peer rates
- `1c44a6f` Handle corrupt discovery persistence
- `9c01ad9` Sort pending announce retransmits
- `913aa49` Throttle recursive path requests
- `2a66180` Add rngit page git timeouts
- `2877408` Mark discovered transport entries as gateway

When integrating future upstream changes, compare this baseline against the new
Reticulum upstream commit, review protocol/runtime/utility changes, port or
explicitly defer each relevant item, run the interop and focused regression
tests, then update this file to the new baseline commit.

## Active 1.2.5..1.2.7 Porting Queue

The `/home/lelloman/Reticulum` checkout was advanced to upstream
`b1f522277c99b076ea4b43e9048aec8962e0e4a2` on 2026-05-17. The detailed
analysis for this range is in
`docs/reticulum-upstream-commit-analysis-2026-05-17.md`.

- [x] `0ebec014` Improved release page
  - Ported the remaining Rust-applicable rendering change: empty release
    artifact lists now use Micron emphasis.
  - Confirmed artifact ordering was already covered by `release::artifacts()`
    sorting by filename; added a page regression test to lock that behavior.
- [x] `e004e759` Added lock to interface discovery
  - Ported to `DiscoveredInterfaceStorage` with a process-wide storage mutex
    around discovery cache file reads, writes, removes, cleanup, and
    `store_received()` load-modify-store updates.
  - Added a concurrent `store_received()` regression to verify `heard_count`
    increments are not lost under simultaneous receives for the same discovery
    hash.
- [x] `32389002` Better remote monitor loop
  - Remote management link reuse is not yet applicable because Rust `rnstatus
    -R` and `rns-ctl status -R` still report remote management as not fully
    implemented.
  - Ported the applicable monitor-loop pacing: successful monitor iterations
    and monitor retry sleeps now subtract elapsed query/render time and keep the
    upstream 200 ms minimum sleep.
  - Added focused monitor sleep duration tests for both `rnstatus` and
    `rns-ctl status`.
- [x] `855ef7bf` Base256 encoding
  - Extended Rust base256 support from display-only helpers to byte
    encode/decode helpers in `rns-core`.
  - Ported `rnid` base256 RSG output/validation support, including
    character-aware ASCII wrapping so multi-byte base256 glyphs are not split.
  - Added focused base256 display, RSG unit, and CLI output-format tests.
- [x] `7d5fb6a1` Cleanup
  - Audited as not applicable to Rust behavior. The upstream commit only
    compacts Python helper formatting in `RNS/__init__.py` and refreshes
    generated manual artifacts.
- [x] `d0ceeacb` Allow setting title on workdoc edit
  - Audited as already implemented in Rust: `rngit work edit` accepts
    `--title`, includes it in the work edit request, and the server applies it.
  - Added a focused `work_cli` regression to lock the edit request payload for
    simultaneous title and content edits.
- [x] `bd0e1ad0` Better workdoc page handling
  - Ported work document page lookup semantics: missing `scope` now behaves as
    `all`, resolving an active document first and then a completed document.
  - Added page regression coverage for viewing a completed work document without
    an explicit scope.
- [x] `93ead774` Added workdoc downloads
  - Added the Nomad Network `/file/workdoc` resource endpoint and linked work
    document pages to it.
  - Reused the active/completed scope fallback logic for page rendering and
    downloads, including completed-document lookup when no scope is supplied.
  - Added focused page coverage for download links and work document resource
    responses. Rust resource metadata currently carries status only, so the
    upstream Python filename hint is not represented yet.
