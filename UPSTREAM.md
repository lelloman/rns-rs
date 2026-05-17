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

The RNS 1.2.6 boundary is integrated through upstream `95502e2c` (`Prepare
release`). Later entries in the analysis document belong to the ongoing 1.2.7
queue.

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
- [x] `d731b439` Repo page rendering
  - Audited as already covered by Rust rendering. Repository README content is
    appended once and normalized to a single trailing newline, so the upstream
    Python spacing cleanup has no Rust delta.
- [x] `1d7ddc3f` Implemented rngit work document signing
  - Added client-side signing for `rngit work create` and content-changing
    `rngit work edit` requests.
  - Added server-side validation for provided work document signatures against
    the identified link public key, and stored that public key with the document
    for later validation.
  - Exposed work document `signature` and `identity` metadata in view
    responses, plus signature status in CLI and Nomad Network page rendering.
  - Kept unsigned work documents accepted for compatibility with existing Rust
    clients and persisted data; invalid provided signatures are rejected.
- [x] `3dd4145e` Updated changelog
  - Audited as documentation-only. The upstream changelog refinement is covered
    by the explicit workdoc signing tracker entry above.
- [x] `95502e2c` Prepare release
  - Audited as generated upstream manual and release artifact updates for RNS
    1.2.6. No Rust runtime, protocol, CLI, or crate documentation source files
    map directly to this generated artifact commit.
- [x] `e49f3132` Redirect blob to tree page if target is a tree
  - Added object-type detection before blob rendering so directory paths
    requested through `/page/blob.mu` are served by the existing tree page
    renderer.
  - Added a regression covering a blob-page request for `src` that renders the
    directory listing instead of raw tree output.
- [x] `ff86a1d7` Updated readme
  - Audited as upstream hosted `README.mu` content only. rns-rs renders
    repository-provided README files but does not vendor Reticulum's
    self-hosted README.mu, so there is no Rust code or local documentation delta.
- [x] `eee93546` Updated readme
  - Audited as another upstream hosted `README.mu` link/content update for the
    Reticulum repository page. No rns-rs renderer, CLI, protocol, or vendored
    documentation change is required.
- [x] `cb3ef690` Updated readme
  - Audited as upstream hosted `README.mu` wording and self-hosted manual link
    conversion. rns-rs has no vendored copy of this page, and existing README
    rendering already consumes repository content at runtime.
- [x] `358f9c3b` Updated readme
  - Audited as upstream hosted `README.mu` formatting, dependency wording, and
    internal link updates. No local port is required because rns-rs does not
    ship Reticulum's repository README.mu content.
- [x] `ea27a8b8` Updated readme
  - Audited as a single upstream hosted `README.mu` link correction for
    `HKDF.py`. No local Rust or documentation source is affected.
- [x] `6333fb39` Updated readme
  - Audited as upstream hosted `README.mu` source/thanks link polish. This does
    not map to rns-rs because the changed page content is repository data, not
    local renderer behavior.
- [x] `42b56619` Updated readme
  - Ported the markdown-to-Micron link rendering change: Markdown links now
    render bold and underlined by default, matching upstream's updated
    `README.mu` presentation.
  - Added a reusable link-style helper with optional Micron color wrapping so
    callers can disable bold/underline or apply 3/6-digit color codes as in the
    upstream converter.
  - Updated Markdown, table-width, blob, and repository README rendering tests
    for the new link output and added direct coverage for the configurable link
    style.
- [x] `6ecc8933` Updated readme
  - Audited upstream hosted `README.mu` content changes as not locally vendored.
  - Confirmed the renderer-side newline change for non-Markdown README content
    is already covered by Rust's README output normalization, and added a
    regression for a `README.mu` without a trailing newline.
- [x] `c5add012` Updated readme
  - Audited as upstream hosted `README.mu` whitespace and content shaping only.
    rns-rs does not vendor that README content, so no local code or
    documentation change is required.
- [x] `256a4d0b` Cleanup
  - Ported the non-Markdown README rendering cleanup: repository README content
    is now trimmed at the end before appending the renderer newline.
  - Added regression coverage for README.mu content without a trailing newline
    and with excessive trailing blank lines.
- [x] `d69491eb` Updated readme
  - Audited as upstream hosted `README.mu` line-wrapping/content polish only.
    No rns-rs renderer, protocol, CLI, or vendored documentation change is
    required.
- [x] `e8b236c7` Updated readme
  - Audited as a follow-up upstream hosted `README.mu` wrapping adjustment for
    application examples. No local port is required.
- [x] `102eccb7` Updated readme
  - Audited as a single upstream hosted `README.mu` line-wrap correction. No
    local code or documentation source is affected.
- [x] `bdc79b90` Updated readme
  - Audited as upstream hosted `README.mu` application-example wrapping polish.
    No local port is required.
- [x] `c15f566c` Updated readme
  - Audited as upstream hosted `README.mu` support/testnet Micron formatting.
    rns-rs passes repository README.mu content through at runtime and does not
    vendor this page.
- [x] `bdac57ec` Readme formatting
  - Audited as upstream hosted `README.mu` emphasis and wording formatting
    only. No local port is required because the formatted page content is not
    vendored in rns-rs.
- [x] `d881c111` Added latest release management to rngit
  - Added persisted latest-release marker support under the release sidecar and
    made `latest` resolution prefer the configured marker before falling back
    to the newest published release.
  - Added the release management `latest` operation on the server and CLI
    (`rngit release --yes <remote> latest <tag>`), with release-permission
    enforcement and safe tag validation.
  - Updated release list responses to the upstream map shape containing
    `releases` and `latest`, while keeping the CLI compatible with legacy array
    responses.
  - Marked configured latest releases on Nomad Network release listings and
    covered explicit latest selection for pages, downloads, protocol listing,
    invalid tags, CLI parsing, and CLI request generation.
- [x] `1a7607cb` Improved shared instance RPC error handling
  - Audited as Python `Reticulum.py` shared-instance destination/identity
    retention RPC handling. rns-rs does not expose the same retention RPC
    methods, and its existing CLI RPC callers already handle `RpcClient::call`
    failures at command boundaries.
- [x] `f744e4d9` Updated logging
  - Audited as Python transport log-level cleanup for transported link request
    proof handling. No equivalent Rust log site exists in the current transport
    implementation, so no code change is required.
- [x] `869a8031` Updated logging
  - Audited as Python `BackboneInterface` invalid file descriptor deregistration
    log-level cleanup. The Rust Backbone implementation does not have an
    equivalent epoll deregistration warning path.
- [x] `7e46422c` Auto-set latest release on creation
  - Ported auto-latest behavior when a release is finalized: the release
    sidecar `latest` marker is updated to the newly published tag.
  - Kept auto-latest marker write failures non-fatal, matching upstream, while
    explicit `latest` management requests still report failures.
  - Added tests that finalized releases write/update the latest marker and that
    explicit latest management can override the automatically selected tag.
- [x] `5667a0bb` Better transfer completed feedback in rncp, thanks to neutral
  - Audited as upstream `rncp.py` user-facing receive/fetch feedback. rns-rs
    does not currently include an `rncp` utility, so no local port is available.
- [x] `d5b64a4a` Cleaned up log/print consistency for listener/initiator modes in rncp
  - Audited as upstream `rncp.py` logging consistency cleanup. No local port is
    available because rns-rs does not currently implement rncp.
- [x] `e7a317f0` Use canonical Transport interface list add/removes. Improved announce cache cleaning. Adjusted logging.
  - Ported the announce cache cleanup fix by treating packet hashes retained in
    tunnel paths as active cache entries, even when the live path table no
    longer contains the destination.
  - Added a transport regression for a detached tunnel path whose cached
    announce packet hash must survive active-cache cleanup.
  - Audited the interface add/remove locking portion as already covered by
    Rust's driver-owned interface registry and event-based registration path;
    there is no global Python-style `Transport.interfaces` list to mutate
    directly.
- [x] `f3f4d9bc` Cleanup
  - Audited as a follow-up `rncp.py` saved-file feedback/logging cleanup. No
    local port is available because rns-rs does not currently implement rncp.
- [x] `c92872a8` Added download stats to rngit
  - Added repository `download` and `release_download` counters to persisted
    rngit stats while preserving compatibility with existing stats files that
    lack those keys.
  - Recorded successful blob and work-document downloads as normal downloads,
    and successful release artifact downloads as release downloads.
  - Rendered combined download totals and a downloads chart on repository stats
    pages, with activity scoring counting downloads at the upstream view
    weight.
  - Added integration coverage for blob and release artifact downloads updating
    separate persisted counters and the rendered combined download total.
- [x] `03cfbc2e` Added half-block chart rendering
  - Ported stats chart rendering from full-block shade glyphs to upstream-style
    half-block charts with foreground/background gradient colors.
  - Covered the rendered stats page output so the new half-block glyphs and
    peak label are exercised through a real download chart.
- [x] `9b99b72f` Cleanup
  - Ported the follow-up half-block chart label cleanup by removing the point
    count suffix from the peak line.
  - Audited the full-block chart local-variable rename as not applicable
    because rns-rs only retains the active half-block renderer.
- [x] `ba8fca6f` Nicer stats page
  - Ported the updated stats summary layout with fetches, pushes, views, and
    downloads shown in upstream order, including today and peak columns.
  - Added the upstream category color palette, per-series secondary gradient
    colors, and the stronger download chart gradient.
  - Reworked the combined activity chart to include downloads and render stacked
    half-block category colors.
  - Updated stats page regression expectations for the new layout and chart
    legend behavior.
- [x] `12e45b64` Added work document proposals
  - Added the `proposed` work-document scope to storage, listing, viewing,
    Nomad Network work pages, downloads, and CLI list output.
  - Added proposal access parsing and config support, plus the `propose` work
    operation that requires a valid content signature and stores documents in
    the proposed scope.
  - Proposal creation now writes document-local interact/write permissions for
    the proposer, and edit handling can use those local permissions.
  - Added CLI `rngit work ... propose`, updated usage text, and added protocol
    coverage for signed proposals, proposed-scope listing, local edit
    permission, and unsigned proposal rejection.
- [x] `db7359f5` Preparation for create, fork and mirror functionality. Refactored and expanded permissions system. Added group .allowed files. Prepared dynamic permissions resolution. Basic functional scaffolding for create/fork/mirror.
  - Ported the upstream permission preparation by accepting sidecar permission
    files next to repositories and groups (`<repo>.allowed` and
    `<group>.allowed`) while preserving existing rns-rs paths
    (`<repo>/.allowed` and `<group>/group.allowed`).
  - Added executable `.allowed` support so a permission file can emit dynamic
    permission rules on stdout, matching the upstream dynamic-permission
    preparation.
  - Covered sidecar repository/group permissions in ACL tests and in the
    create-on-push server path.
  - Audited the new create/fork/mirror command scaffolding: the explicit
    `/git/create` path remains for `df0b4a51`, where upstream implements the
    stubbed create behavior; fork/mirror remain preparatory only in this commit.
- [x] `df0b4a51` Implemented rngit remote repo create
  - Added the upstream `/git/create` request path and registered it on the
    repository destination.
  - Implemented explicit remote repository creation for identified peers with
    create permission, requiring an existing group directory, initializing a
    bare Git repository, and writing a sidecar admin permission for the creator.
  - Added `rngit create <rns://destination/group/repo>` client command support
    with `--config`, `--rnsconfig`, and identity override parsing.
  - Covered successful creation, creator admin grant, anonymous rejection,
    missing-group rejection, duplicate rejection, invalid nested repository
    rejection, and create CLI parsing.
- [x] `03898147` Added fork and mirroring support to rngit CLI and node
  - Added upstream `/git/fork` and `/git/mirror` request paths and registered
    repository handlers for both operations.
  - Implemented remote clone handling that validates create access, fetches all
    refs from the supplied source URL into a bare repository, records
    `repository.rngit.type` and `repository.rngit.upstream.source`, and grants
    the caller admin permissions through the sidecar `.allowed` file.
  - Added `rngit fork <source> <target>` and `rngit mirror <source> <target>`
    CLI entry points with config, RNS config, and identity override parsing.
  - Covered fork/mirror handler success against local Git sources, metadata
    persistence, missing-source rejection, duplicate-target rejection, protocol
    request round-tripping, and CLI parsing.
- [x] `0c68f649` Added fork and mirror indications to rngit page node
  - Render repository-page provenance when `repository.rngit.type` is `fork` or
    `mirror` and `repository.rngit.upstream.source` is set in Git config.
  - Kept the Rust page renderer stateless by reading provenance directly from
    repository config instead of adding an upstream-style loaded repository map.
  - Added page coverage for both `Forked from ...` and `Mirrored from ...`
    repository headers.
- [x] `b76beb60` Added scaffolding for periodic upstream mirror sync and manual fork/mirror sync
  - Added upstream `/git/sync` request path and `rngit sync <repository>` CLI
    command plumbing.
  - Ported the scaffolded sync handler checks: identified peer, read/write
    access, repository existence, and fork/mirror metadata requirement. Like
    upstream in this commit, the handler returns success without performing the
    actual upstream fetch/update yet.
  - Mirror creation now records `repository.rngit.upstream.sync` alongside the
    existing mirror source metadata.
  - Covered sync CLI parsing, sync handler success/rejection paths, and mirror
    sync timestamp metadata.
- [x] `6c7f1d06` Implemented fork and mirror sync from upstreams
  - Implemented upstream sync by fetching `+refs/*:refs/*` from the stored
    `repository.rngit.upstream.source` into existing fork or mirror
    repositories.
  - Mirror sync updates `repository.rngit.upstream.sync` after a successful
    fetch, matching upstream timestamp behavior.
  - Updated the sync handler to report fork/mirror sync failures instead of
    returning success for the previous scaffold.
  - Added coverage that advances a local source repository after fork creation
    and verifies `rngit sync` updates the target bare repository.
- [x] `b2a4ceb8` Updated default config
  - Audited as upstream embedded default-config documentation for the new
    `propose` and `admin` permission shorthands.
  - No code change was needed: rns-rs already generates explicit
    `propose = none` and `admin = none` defaults, and its default config
    template is intentionally compact rather than carrying upstream's full
    explanatory comments.
- [x] `0f29ab62` Updated rngit documentation
  - Updated local `docs/rns-git.md` with rns-rs-specific coverage for
    `rngit create`, `fork`, `mirror`, and `sync`.
  - Documented sidecar and executable permission files, `propose`/`admin`
    permission keys, proposal work-document scope, and fork/mirror provenance.
  - Did not import upstream generated manual artifacts; rns-rs keeps concise
    Markdown documentation instead of generated Sphinx output.
