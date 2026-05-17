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
- [x] `018df10a` Fixed rngit remote helper startup hang on first config
  - Audited as already implemented in Rust. `git-remote-rns` loads or creates
    `client_config` before initializing the file logger and before constructing
    the Reticulum node, then exits with the first-run edit-config message.
- [x] `eeefb60c` Added signature validation of multiple file path inputs
  - Ported `rnid -V/--validate` to validate the first flag value plus any
    trailing positional paths, matching shell-expanded multi-file usage.
  - Added a CLI regression covering successful validation of two `.rsg` files
    in one invocation.
- [x] `5c5668a4` Added signature creation for multiple file path inputs
  - Ported `rnid -s/--sign` to sign the first flag value plus any trailing
    positional paths in one invocation.
  - Added a CLI regression covering two generated `.rsg` files and validating
    them in one batch.
- [x] `54c36f51` Added file encryption for multiple file path inputs
  - Ported `rnid -e/--encrypt` to encrypt the first flag value plus any
    trailing positional paths in one invocation.
  - Added a CLI regression covering two generated `.rfe` files and decrypting
    both outputs back to their original plaintext.
- [x] `eb5d46b2` Added file decryption for multiple file path inputs
  - Ported `rnid -d/--decrypt` to decrypt the first flag value plus any
    trailing positional paths in one invocation.
  - Added a CLI regression covering batch decryption back to the default output
    filenames after the plaintext originals are removed.
- [x] `9179b914` Added embedded message signing, validation and viewing to rnid
  - Added `rnid -S/--sign-message` for embedded signed `.rsm` messages, with
    binary output via `-w` and ASCII armored output through the existing RSG
    format flags.
  - Extended validation so `rnid -V` detects `.rsm` files, verifies the
    embedded message against the signed envelope, and prints the signed text.
  - Added CLI coverage for creating, validating, and displaying an embedded
    signed message. Editor-backed message entry is supported through `$EDITOR`
    for `-S` without an inline message.
- [x] `64ebdd0e` Cleanup
  - Audited as not applicable. The upstream change only removes a stale Python
    progress-reporting comment in the `rngit` remote helper.
- [x] `c86b9c97` Fixed missing none check in interface discovery sanitizer
  - Audited Rust parsing as already defensive: non-string and missing discovery
    names are treated as empty before sanitization and fall back to the
    interface type label.
  - Added a focused discovery parser regression for a Nil discovery name.
- [x] `35c7a89b` Fixed typo
  - Audited as not applicable. The upstream typo was in Python thanks-counter
    error logging that referenced undefined group/repo variables; Rust thanks
    handling does not have that logging path.
- [x] `4c93f6c7` Added local URL resolution to repo frontpage markdown readme renderer
  - Audited README local link resolution as already implemented and covered by
    the Rust repository page test.
  - Ported the same commit's empty stats wording change to "No development
    activity..." and updated the focused stats assertion.
- [x] `a049ec8b` Updated changelog
  - Audited as documentation-only. The upstream Reticulum changelog entry is
    represented here by this porting queue and the detailed analysis document,
    not mirrored into a Rust crate changelog.
- [x] `c186a1f6` Updated version
  - Audited as release metadata only. Rust crate versions are maintained
    independently from Python `RNS/_version.py`; no Cargo version bump was
    applied for this upstream release marker.
