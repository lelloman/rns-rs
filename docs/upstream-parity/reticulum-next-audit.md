# Reticulum Next Upstream Audit

## Scope and Baseline

- audit date: `2026-09-11`
- previous accepted version: `1.5.3`
- previous normative commit: `0bb41bf9486c1469854876a3c1d7c57324efc7c4`
- target version: `1.5.3` (tip metadata; final release target not yet selected)
- target tag or ref: `rgit/master`
- target normative commit: `fae64abf05a0ec5afabb2def9076f70d42bfe600`
- target root tree: `b604b6447b083dc3188acc76a24b7ad063f9b732`
- target `RNS` tree: `d901a4098fa0c17da8c6dc3ce36634793f71d62b`
- version assertion: `RNS.__version__ == "1.5.3"`
- audited range: `0bb41bf9486c1469854876a3c1d7c57324efc7c4..fae64abf05a0ec5afabb2def9076f70d42bfe600`
- commits in range: `9`
- repositories checked: normative rgit repository and GitHub mirror
- local branch and revision inspected: `dev@3bf97a6959ef5bc1034e7ac9bcd996b6514964df`

The rgit tip is nine commits ahead of the accepted baseline. The GitHub mirror
tip is `ea98db4f53dcf0defc0e71a16e60d28b1229c4e6` and remains behind the accepted
baseline. Both remotes were fetched successfully on 2026-09-11. The target
version and promotion commit remain provisional until the new upstream release
metadata is complete and the audit dispositions are resolved.

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
| 1 | `b0933d5c6f7fa06a5fd2a2cfa887441aa62cbbb7` | activate should work also with proposed work documents | Integrated | `d07a1c1`; regression, crate suite, live Python lifecycle |
| 2 | `409380a4581fbb15cf794778da5b45bc90e44575` | Allow admins to activate and complete work docs | Integrated | `4fae3e6`; admin/denial regression and Python lifecycle |
| 3 | `859dc8180523762310b0aa8ac22c6f9dfc8e64f4` | Cleanup, in-method atomicity of group and repository name derivation to ensure no discrepancies between request data and method invocation parameters | Structurally covered | `ca5beb6`; single owned request supplies storage and ACL context |
| 4 | `36a62e7b1a6c3b6c4d5411410f83e22c000048cd` | Cleanup, align with existing pattern of minimal information disclosure on insufficient permissions | Structurally covered | `bcfaf47`; generic response mapping and non-author regression |
| 5 | `87823c091fd6fb8788de73f4021e4ddd9d13781e` | Cleanup | Non-runtime | `129bc39`; whitespace-insensitive diff empty |
| 6 | `f231fdcb4dfc5921423b5d8ab6a3ee2bfed752da` | Added immediate permissions change activation for rngit perms | Integrated | `a0bacdb`; immediate grant/revoke, resolver guard and Python permissions |
| 7 | `e7a7c48c0a5f785049b1e35852c147840c30daff` | Added importable webp media file conversion helper | Needs decision | Audit pending |
| 8 | `7330c20c6d7e109c97f6e8783ffb321977ef0943` | Updated changelog | Non-runtime | Upstream metadata only; verify after target selection |
| 9 | `fae64abf05a0ec5afabb2def9076f70d42bfe600` | Prepare release | Needs decision | Release contents and target version pending |

## Per-Commit Analysis

### 1. `b0933d5c` — activate proposed work documents

Changed path: `RNS/Utilities/rngit/server.py`. No unintegrated dependency.
The complete diff and surrounding lifecycle code show that activation searches
completed documents first, then proposed documents, retaining the author check.
Rust previously searched only completed documents. `work::activate_document`
now performs the same ordered lookup and uses the existing authenticated move.
The regression `activate_proposed_document_preserves_author_and_content` failed
before the fix with `document not found` and passes afterward; it also checks
unauthorized activation and preservation of author/content. Disposition:
**Integrated**.

Validation: `cargo test -p rns-git` passed (207 library tests, 23 integration
tests; optional backend and Python checks excluded by default). Formatting and
`bash scripts/lint-host.sh` passed. The explicit `python_work_lifecycle_interop`
test passed with `PYTHONPATH=/tmp/rns-upstream-parity-20260911`, exercising signed
proposal activation, content/signature verification, completion and
reactivation through an actual Python/Rust link at the pinned target.

### 2. `409380a4` — administrators may transition work documents

Changed path: `RNS/Utilities/rngit/server.py`; depends on row 1's proposed
activation. The complete diff passes repository context into lifecycle handlers
and permits an author or a resolved document administrator to complete or
activate. The outer repository read/interact/write checks remain required.
Rust now resolves repository/document admin access for those two operations;
an explicit document `admin = none` overrides inherited admin authority.
Existing public author-only storage APIs retain their signatures and checks;
internal authorized transitions preserve the stored author. Edit/delete are
unaffected. Disposition: **Integrated**.

The new administrator regression failed before implementation. It covers
repository and document admins, both transitions, preservation of authorship,
explicit document denial and continued rejection of non-author edits. The
live Python lifecycle test also passed with a second administrator identity
(`RNS_WORK_ADMIN_INTEROP=1`) activating the first identity's signed proposal.
The final crate suite passed with 208 library and 23 integration tests;
formatting and warning-free host lint passed. The live administrator check
passed again after adding explicit document-denial precedence.

### 3. `859dc818` — derive permission context from the request

Changed path: `RNS/Utilities/rngit/server.py`; depends on row 2. Complete diff
and handler review shows removal of separate group/repository parameters and
derivation from the request inside each lifecycle handler. Rust already parses
one owned `WorkRequest`; `handle_work` derives `repo`, the storage path and all
permission checks from that same value. There is no independently supplied
group/repository pair to disagree with it. Disposition: **Structurally covered**.
The existing administrator transition regression was rerun and passed; the
preceding full crate/lint and live Python evidence covers this unchanged path.

### 4. `36a62e7b` — minimize permission-denial disclosure

Changed path: `RNS/Utilities/rngit/server.py`; follows rows 2–3. The full diff
only replaces the two lifecycle denial strings with `Not allowed`, retaining
status `RES_DISALLOWED`. Rust's `ensure_author` produces an internal author
error, but `server::work_error_response` already replaces it with the generic
`not allowed` response and the same status. Internal errors are not exposed by
these handlers. Disposition: **Structurally covered**. Existing server
non-author management tests and row 2's explicit admin-denial test cover the
status path; source inspection verifies the generic wire body. Capitalization
retains the established native response convention.

### 5. `87823c09` — whitespace cleanup

Changed path: `RNS/Utilities/rngit/server.py`. The entire diff removes spaces
from one blank line in `_work_activate`; no executable lines change. Verified
with `git diff --ignore-all-space <parent> <commit> --exit-code` (exit 0).
Disposition: **Non-runtime**. No native source or runtime test change required.

### 6. `f231fdcb` — immediate permissions and resolver protection

Changed path: `RNS/Utilities/rngit/server.py`. Reviewed the complete diff and
the loader, group/repository update and remote setter context. Upstream stages
group rules before applying them, factors the allowed-file loader, refreshes
cached permissions after remote writes, and rejects replacement of executable
resolvers. Rust's `Access` reads and parses sidecars on each permission check,
and its atomic rename avoids partial file contents, so it needs no cache refresh
or Python cache-update lock. New tests confirm grant/revoke visibility through
the same `Access` instance for both group and repository sidecars.

The executable-resolver regression failed before the fix. Both remote setters
now reject executable sidecars and preserve their contents and mode. Live
Python permission `set` exposed a pre-existing one-byte response ambiguity;
the endpoint now explicitly encodes its status response as MessagePack binary,
so Python receives `b"\x00"` rather than integer zero. This is covered by live
set/get and executable-resolver rejection checks. Disposition: **Integrated**.

Validation: 210 library and 23 integration tests passed, formatting and
warning-free host lint passed, and the exact-target live Python administrator
lifecycle/permissions test passed. Operator behavior is documented in
`docs/rns-git.md`.

### 7. `e7a7c48c` — importable file conversion helper

Changed paths: `RNS/Utilities/rngit/media.py`, `setup.py`. Reviewed the full
diff and the backend-selection, validation, process-wait and packaging context.
The helper adds optional clamped quality and aspect-preserving maximum size,
a default quality of 85 for standalone files, temporary output and failure
cleanup. Existing server conversion keeps encoder defaults when options are
absent. Python packaging excludes the media module from Cython compilation;
that packaging detail has no Rust counterpart.

Rust exposes `media::convert_file_to_webp` and `ConversionOptions`; returns
an owned `NamedTempFile`, uses the same backend arguments and eight-second
default, clamps quality and ignores a zero dimension. Rust types replace
Python's permissive runtime coercions. RAII deletes output on drop (callers can
persist it) and preserves the source. Existing server defaults stay unchanged.
Disposition: **Integrated**.

Validation: 211 library and 23 integration tests, both explicitly enabled real
encoder tests, formatting and host lint passed. Tests cover quality limits,
resize/no-upscale, source preservation, cleanup and malformed/missing input;
the existing process test covers nonzero exit and timeout cleanup. The exact
upstream helper produced the same expected resize dimensions, and the live
Python media client verified Rust file bytes, WebP dimensions and filename
metadata. Native API documentation was added to `docs/rns-git.md`.

## Integration Plan

1. Review the remaining work-document and permission commits individually in
   ancestry order, preserving one mapping commit per upstream commit.
2. Determine whether the WebP helper changes the already accepted media-preview
   compatibility surface.
3. Resolve release metadata and select the exact promotion target.
4. Implement applicable changes and record focused evidence per commit.

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

- `2026-09-11`: Both upstream remotes refreshed successfully. Daily VPS
  snapshots were healthy and complete. The first impaired dual-VPS smoke run
  timed out while establishing one concurrent a-to-b link; the prescribed
  `--daily --keep` reproduction passed all packet, link, Channel, Resource,
  impairment, stress, and forced-reconnect checks. Diagnostic state was kept at
  `/tmp/rns-backbone-smoke.vepGfr` and `/tmp/rns-backbone-smoke.tXn7Bt`.
