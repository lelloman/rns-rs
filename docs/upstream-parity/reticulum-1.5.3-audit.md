# Reticulum 1.5.3 Upstream Audit

## Scope and Baseline

- audit date: `2026-09-07`
- previous accepted version: `1.5.2`
- previous normative commit: `3bc149e3d587695f52e695f18edb11751b21c005`
- target version: `1.5.3`
- target tag or ref: `rgit/master`
- target normative commit: `0bb41bf9486c1469854876a3c1d7c57324efc7c4`
- target root tree: `9b8fb0e518ed627685c9508773ceca156452cad8`
- target `RNS` tree: `86976fc8b62b79d08e2174557744e636be74ed9e`
- version assertion: `RNS.__version__ == "1.5.3"`
- audited range: `3bc149e3d587695f52e695f18edb11751b21c005..0bb41bf9486c1469854876a3c1d7c57324efc7c4`
- commits in range: `9`
- repositories checked: canonical rgit repository and GitHub mirror
- local branch and revision inspected: `master@9ecf1c3ac8e1da9ca9e48ad53f1200e5feb62398`

The canonical rgit `master` tip is nine commits ahead of the accepted baseline.
The GitHub mirror remains behind the accepted baseline at
`ea98db4f53dcf0defc0e71a16e60d28b1229c4e6`. Both remote tips were refreshed
successfully on 2026-09-07 (12:15:53 UTC and 12:15:59 UTC). The configured upstream checkout remains pinned at
the accepted baseline; the target object was inspected without advancing it.

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
| 1 | `2f29b56e96bfa6fd3fc61518e4e5710ac8e92258` | Adjusted logging | Structurally covered | `4fad68c`; targeted missing/offline interfaces retain interface-specific diagnostics and never fall back to another interface. |
| 2 | `1a7e9e31a1c1682732ee84953acd3a3d758d22d5` | Fixed typo | Non-runtime | `RNS/Link.py` docstring only; ordered mapping pending. |
| 3 | `6b6dd73bc86fedb945f6d0d55d83dc8d5e4a3241` | Updated readme | Non-runtime | `README.mu` and logo asset; ordered mapping pending. |
| 4 | `5c1141d1cefd99cf17042e2b147b62abeb05526a` | Updated readme | Non-runtime | `README.mu` image path correction; ordered mapping pending. |
| 5 | `8a82a50fc96354dc9df77d95af8aca97099629d2` | Updated readme | Non-runtime | `README.mu` and smaller logo asset; ordered mapping pending. |
| 6 | `7396e3994e678a7ad009f146fca1d645b31f3e67` | Basic rngit media handling | Needs port | `RNS/Utilities/rngit/pages.py`; native `pages.rs` lacks `/media` and image previews. |
| 7 | `602d52f17813f3b55e78629cc83121349be72467` | Don't auto-compress media responses | Needs port | `pages.py`; depends on row 6; native Resource responses expose `auto_compress`. |
| 8 | `27910f25a1d028359851fb8f512254cccfece7e3` | Added rngit media conversion | Needs port | `media.py`, `pages.py`, `server.py`; depends on rows 6–7; conversion, config, lifetime and fallback handling required. |
| 9 | `0bb41bf9486c1469854876a3c1d7c57324efc7c4` | Updated version | Non-runtime | `RNS/_version.py` changes 1.5.2 to 1.5.3; ordered mapping pending; Cargo versions independent. |

The existing ordered mapping for row 1 is `c28faa11480374ae234c5534325171d9f420d568`;
`4fad68c` is the earlier implementation evidence. Do not create another mapping.

## Integration Plan

Process rows 2–9 in ancestry order, recording each exact trailer and its evidence.
Media requests must preserve repository ACLs, key/path validation, URL decoding,
filename metadata and raw-byte fidelity. Cover image previews, disabled media
compression, conversion backend selection and timeout, invalid-output fallback,
and the lifetime of conversion output. Run changed-crate suites, formatting,
warning-free lint and exact-target Python/Rust interoperability for media before
claiming acceptance. The earlier daily smoke predates this work.

## Per-Commit Analysis

### 6. `7396e399` — Basic rngit media handling

**Upstream change:** Complete `pages.py` diff and surrounding blob/ref/ACL code
reviewed. Adds `/media` with a presence-only key, repository/ref/blob path, URL
decoding, access checks, raw file responses and binary filename metadata. Binary
image blob pages emit a Micron media reference. No runtime dependency on the
README content commits.

**Local handling:** `pages::serve_media` and registered `/media` handler preserve
those semantics, including large-image previews. Media does not increment the
ordinary download counter, matching upstream. A new `RequestResponse::File`
variant sends raw bytes; existing `Resource` value-envelope semantics remain
unchanged. The live Python test exposed the need for that distinction. Git
output is spooled to owned temporary files to avoid the pipe-buffer deadlock
exposed by the large-image regression. Invalid requests return MessagePack false.

**Evidence:** Three focused media regressions pass; the complete rngit suite
passes (202 unit, 6 E2E, 11 release and 6 stats tests). The complete rns-net suite
passes (941 unit tests before the additional file-response regression, 54 E2E,
Python/IFAC interoperability and fixtures); the added raw-file response regression
also passes. The live Python client at exact target `0bb41bf` passes file bytes,
filename metadata and missing-key rejection over a Reticulum link. Command:
`RNS_MEDIA_INTEROP=1 PYTHONPATH=/tmp/rns-upstream-media-1.5.3 cargo test -p rns-git --test e2e rngit_nomadnet_pages_render_over_rns_link -- --nocapture`.

**Final disposition:** Integrated. Ordered mapping is this code/evidence commit;
the canonical trailer identifies it. Compression and conversion remain rows 7–8.

### 5. `8a82a50f` — Updated readme

**Upstream change:** Moves the Micron logo after the introduction, changes its
display width from 20 to 18, selects `rns_logo_256.webp`, and adds that asset.
Complete source diff and changed binary paths reviewed; depends on rows 3–4.

**Rust applicability and evidence:** Repository-owned presentation and asset
data, consumed through existing Micron README passthrough. There is no vendored
copy to update. The later media endpoint must serve arbitrary repository blobs;
it must not hardcode this logo path or width.

**Final disposition:** Non-runtime. This section supplies the ordered mapping.

### 4. `5c1141d1` — Updated readme

**Upstream change:** The complete diff corrects the preceding README image URL
to include `docs/source/graphics/`. Depends on row 3's content addition.

**Rust applicability and evidence:** Only repository-owned `README.mu` content
changes; native Micron passthrough requires no renderer change. Media path
resolution is tracked separately in row 6. No executable lines change.

**Final disposition:** Non-runtime. This section supplies the ordered mapping.

### 3. `6b6dd73b` — Updated readme

**Upstream change:** Adds a centered Micron image reference to `README.mu` and
the binary `docs/source/graphics/rns_logo_512.webp` asset. Complete source diff
and asset paths reviewed. The URL is repository content; serving it depends on
the later media-handler commit, row 6.

**Rust applicability and evidence:** Native `render_repo_page` preserves Micron
README content; rns-rs does not vendor this repository's README or logo assets.
The new `/media` behavior is explicitly tracked in row 6 rather than claimed here.

**Final disposition:** Non-runtime. This section supplies the ordered mapping.

### 2. `1a7e9e31` — Fixed typo

**Upstream change:** The complete `RNS/Link.py` diff removes the stray word
"packet" from `get_expected_rate()`'s return-value docstring. Its ACTIVE-state
guard and returned rate are unchanged. No earlier unintegrated dependency.

**Rust applicability and evidence:** This is Python API documentation, with no
wire, rate-estimation, configuration or native API change. Reviewed the complete
diff and surrounding accessor. No runtime tests are required for this mapping.

**Final disposition:** Non-runtime. This section is the non-empty ordered mapping;
its commit is identified by the canonical `Upstream-Commit` trailer.

### 1. `2f29b56e` — Adjusted logging

**Upstream change:** `Packet.send()` no longer emits the debug message claiming
that no interfaces could process an outbound packet when the packet has an
attached interface. The send still returns failure; only diagnostic output is
changed.

**Rust applicability:** Rust routes attached-interface traffic explicitly and
logs the resulting outbound action count, rather than emitting the same Python
failure message. The dispatch layer reports a missing target as `cannot send on
missing interface` and an offline or disabled target as `cannot send on
unavailable interface`; it never substitutes the misleading generic claim
that no interface could process the packet.

**Local handling and evidence:** Commit `4fad68c` documents the native
interface-specific diagnostic invariant and adds
`missing_attached_interface_does_not_fall_back_to_other_interfaces`, complementing
the existing offline-interface regression. The focused test passed. The full
`rns-net` suite passed with 941 unit tests, 54 network E2E tests, Python interop,
IFAC interop, and fixture suites; `cargo fmt --all -- --check` and
`cargo clippy -p rns-net --all-targets -- -D warnings` also passed.

**Final disposition:** Structurally covered.

## Promotion Gates

- [ ] Every upstream commit has a final disposition and ordered local mapping.
- [ ] Focused regressions pass for every applicable behavior change.
- [ ] Fixture provenance and byte stability are checked where applicable.
- [ ] Exact-target live Python/Rust media interop passes.
- [ ] Workspace tests, feature suites, formatting, and lint pass.
- [x] Required daily live dual-VPS manual gate is recorded honestly.
- [ ] Native documentation is updated for user-visible behavior.
- [ ] A final parity record is created from `PARITY-TEMPLATE.md`.

## Acceptance Record

- `2026-09-05`: Fresh drift inspection succeeded for both remotes and found the
  single commit inventoried above. The daily dual-VPS snapshots were healthy
  and complete. The extended live Backbone smoke passed announce and identity
  propagation, bidirectional packets, Channels, Resource boundary sizes,
  concurrent/repeated links, controlled impairment, and forced reconnect
  recovery. This operational result does not promote the new upstream commit.
- `2026-09-05`: Commit `4fad68c` mapped upstream commit
  `2f29b56e96bfa6fd3fc61518e4e5710ac8e92258` as structurally covered. The
  focused missing-attached-interface regression, the complete `rns-net` test
  suite, formatting, and warning-free host clippy all passed.
- `2026-09-06`: Both remotes refreshed successfully (GitHub at 07:03:31 UTC,
  rgit at 07:03:39 UTC); their tips and the one-commit inventory are unchanged.
  Both daily VPS snapshots were healthy and complete, with one capture per
  host and no failed-query sentinel values. The daily live Backbone smoke
  passed all Resource boundaries, two link batches at concurrency three,
  controlled impairment, and one forced disconnect/recovery cycle using
  local `master@70deb22`. Both VPS nodes still run `57d9d52`, differing from
  refreshed `origin/master` and `origin/dev`. This daily operational check
  does not complete the remaining promotion gates or advance the baseline.
- `2026-09-07`: Both remotes refreshed successfully (GitHub at 12:13:26 UTC,
  rgit at 12:13:33 UTC). GitHub remains behind the accepted baseline; rgit is
  now nine commits ahead. The newly observed rgit commits are
  `0bb41bf9486c1469854876a3c1d7c57324efc7c4`,
  `1a7e9e31a1c1682732ee84953acd3a3d758d22d5`,
  `27910f25a1d028359851fb8f512254cccfece7e3`,
  `5c1141d1cefd99cf17042e2b147b62abeb05526a`,
  `602d52f17813f3b55e78629cc83121349be72467`,
  `6b6dd73bc86fedb945f6d0d55d83dc8d5e4a3241`,
  `7396e3994e678a7ad009f146fca1d645b31f3e67`, and
  `8a82a50fc96354dc9df77d95af8aca97099629d2`; their dispositions remain to
  be inventoried. Both daily VPS snapshots were healthy and complete, with
  one capture per host and no failed-query sentinel values. The extended live
  Backbone smoke passed all Resource boundaries, two link batches at
  concurrency three, controlled impairment, and one forced
  disconnect/recovery cycle. EU runs `57d9d52`; US runs `30fb756`, matching
  the captured `origin/dev` reference. This daily
  operational check does not promote upstream or advance the baseline.
