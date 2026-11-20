# Reticulum 1.6.1 rgit `f55c0c6e` Upstream Audit

## Scope and Baseline

- audit date: `2026-11-20`
- previous accepted version: `1.6.1` (the signed `1.6.1` tag, see
  [the 1.6.1 rgit parity record](reticulum-1.6.1-rgit-parity.md))
- previous normative commit: `cff4d03fdbd6bfb63b765280cd944756ac5cce8d`
- target version: `1.6.1` (unchanged; `RNS/_version.py` is not touched by the
  range)
- target tag or ref: GitHub `master` tip, no tag
- target normative commit: `f55c0c6ea618ebae33e7d3ab2e37b200ce0b0d81`
- target root tree: `724503209ece6226bf4211b96e7dbbf894650f52`
- target `RNS` tree: `3737af213a83c4a6833a8b926bac9e72ea78156a`
- version assertion: `RNS.__version__ == "1.6.1"`
- audited range: `cff4d03fdbd6bfb63b765280cd944756ac5cce8d..f55c0c6ea618ebae33e7d3ab2e37b200ce0b0d81`
- commits in range: `2` (no merge commits; 4 files changed, +245/-13)
- repositories checked: GitHub mirror and rgit (normative), both fetched
  fresh by `scripts/check_upstream_drift.py` on 2026-11-20 20:55 UTC. The
  GitHub tip is `f55c0c6e`. The rgit tip is `606a1691` ("Require explicit
  static_transport_identity configuration to allow discoverable interfaces
  on non-transport instances", 2026-11-20 21:45 +0100), one commit past the
  target, with `f55c0c6e` as its parent; it is outside this audit and left
  for the next one.
- local branch and revision inspected: branch `upstream/f55c0c6e` from
  `dev@3d98c991`

The range is upstream's hot-patch of the 1.6.1 release: the 1.6.1 release
files were replaced on 2026-11-19 with the mitigation of commit 1, and
commit 2 publishes the security notice. The signed `1.6.1` tag still points
at `cff4d03f`; no new tag was made. This is a same-version advancement, so
the records are named `-rgit-2` and the 1.6.1 rgit records stay unchanged.

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

Every commit in the audited range appears exactly once, in ancestry order.
The 2026-11-20 diff review proposed a disposition for each; every row now
has its final disposition, recorded with its mapping commit and the
evidence that ran.

| # | Upstream commit | Date | Subject | Final disposition | Local evidence |
|---:|---|---|---|---|---|
| 1 | `840eb369` | 2026-11-19 | Added rngit media conversion max input size cap, improved logging and error handling | Integrated | `daafb06e`; `image_formats_are_classified_by_their_signatures_as_upstream`, `only_imagemagick_backends_take_the_explicit_input_coder`, `input_that_is_not_a_supported_image_never_reaches_the_encoder`, `input_over_the_size_cap_never_reaches_the_encoder`, `a_supported_image_reaches_the_encoder_whole_with_its_coder`, `encoder_failures_and_invalid_output_are_not_converted`, `encoder_runs_report_exit_status_and_timeout`, `failures_are_logged_with_upstreams_messages`, `image_paths_are_the_media_modules_supported_image_extensions`; the ignored real-backend tests pass with ImageMagick 6 `convert` and with ffmpeg |
| 2 | `f55c0c6e` | 2026-11-20 | Added security notice | Non-runtime | `a6127d80`; security note in `docs/rns-git.md` |

## Per-Commit Analysis

Each section answers the four questions of
[the parity workflow](README.md#per-commit-integration-procedure) from the
2026-11-20 review of the full diff and of the surrounding upstream
`RNS/Utilities/rngit/media.py` and `pages.py` at `f55c0c6e`, against
`dev@3d98c991`.

### 1. `840eb369` — Added rngit media conversion max input size cap, improved logging and error handling

Full hash `840eb3699bd19df68a732ce259fd61c9e1a2ff7d`; changes
`RNS/Utilities/rngit/media.py` (+152/-12) and `RNS/Utilities/rngit/pages.py`
(+2/-1). No dependency on an unintegrated commit.

**Upstream change:** The security fix for the advisory published by commit
2: ImageMagick, when it auto-detects the input format, can be made to read
arbitrary files and put them into its output. `media.py` gains:

- `SUPPORTED_IMAGE_EXTS` (`.webp .png .jpg .jpeg .gif .tiff .tif .bmp`),
  `CONV_SIZE_MAX = 32 MiB`, `SNIFF_BYTES = 64`, `RELAY_CHUNK = 256 KiB`.
- `_classify_image(data)`, exported as `detect_image_format(data)`: the first
  matching signature, in order, of `png` (`\x89PNG\r\n\x1a\n`), `jpeg`
  (`\xff\xd8\xff`), `gif` (`GIF87a`/`GIF89a`), `tiff` (`II*\0`/`MM\0*`),
  `webp` (a RIFF/WEBP header from which `_webp_info` reads non-zero
  dimensions, so at least 30 bytes) and `bmp` (`BM` with at least 18 bytes and
  a little-endian DIB header size at 14..18 of 12, 40, 52, 56, 64, 108 or 124);
  anything else is `None`.
- `_configured_backend(..., input_spec=None)`: for `magick`, `convert` and `gm`
  the first `-` argument is replaced with `input_spec`. `ffmpeg` and `avconv`
  keep `-i -`; the input spec is not applied to them.
- `convert_to_webp(input_argv, output_path, ...)`: still returns `False` first
  when no backend is available. It then reads the first 64 bytes of the
  input command's output, classifies them and, if they are not a supported
  image, logs `Media conversion failed: Input format is not supported`
  (debug) and returns `False` without starting an encoder. Otherwise the
  encoder runs with `<format>:-` and the parent relays the input to it,
  failing once more than 32 MiB have been relayed (`Media conversion failed:
  Streaming input exceeded maximum size of 33.55 MB`, debug). A relay timeout
  logs `Media conversion via <backend> timed out after <prettytime>`
  (warning) and an encoder that stops reading logs `Media conversion via
  <backend> failed: Encoder exited before input was consumed` (debug). The
  whole conversion now shares one deadline (default `CONVERSION_TIMEOUT`, 8
  seconds), and `_await` gets the time that is left.
- `_await`'s timeout line now uses `RNS.prettytime(timeout)` (`... timed out
  after 8s`) instead of `... after 8 seconds`.
- `convert_file_to_webp(source_path, ...)`: after the backend check and the
  existing missing-file warning (now `Cannot convert media: Source file does
  not exist: <path>`), a file larger than 32 MiB is refused (`Cannot convert
  media: Source file exceeds maximum size of 33.55 MB`, debug), and a file
  whose first 64 bytes are not a supported image is refused (`Cannot convert
  media: Source file is not a supported media format`, debug). The encoder
  reads the file from its start with `<format>:-`.
- `pages.py`: `IMAGE_EXTS = SUPPORTED_IMAGE_EXTS`, the same list as before.

Failed conversions still serve the original blob; nothing changes on the wire.

**Rust applicability:** rns-git has the same exposure. `rns-git/src/media.rs`
passes `-` (format auto-detection) to `magick`, `convert` and `gm`,
`[pages] media_conversion` defaults to `yes`, and
`pages/downloads.rs::media_response_data` hands every non-WebP blob with an
image extension to `media::convert_to_webp`. It has no format sniffing, no
input size cap, no `detect_image_format`, and its log lines differ: one
`Media conversion via <name> failed: <error>; serving original media` covers
timeouts, encoder failures and invalid output. `convert_file_to_webp` reads
any file whole and converts it the same way. `is_image_path` has upstream's
extension list but its own copy.

rns-git's blob reaches the encoder differently: `serve_media` already holds the
`git show` output in memory and `convert` gives the encoder a temporary file
holding it as stdin, so there is no relay. The sniff, the classification, the
size cap and the explicit coder carry over unchanged; the relay-only failures
(input read timeout, encoder exiting before the input is consumed) have no
Rust counterpart.

**Local handling and evidence:** `daafb06e`. `rns-git/src/media.rs` gains
`SUPPORTED_IMAGE_EXTS`, `CONV_SIZE_MAX` and `detect_image_format` (public)
with upstream's signature table in upstream's order, and `configured_args`
replaces the first `-` with `<format>:-` for `magick`, `convert` and `gm`
only. In-memory conversion (`convert_to_webp`, used by `/media`) selects the
backend first (the existing no-backend warning), classifies the first 64
bytes, refuses input over 32 MiB, then encodes with the coder;
`convert_file_to_webp` checks backend, missing file, size, then the
signature of the first 64 bytes, and the encoder reads the file from its
start (no longer through memory). Every outcome logs upstream's line at
upstream's level: `Media conversion failed: Input format is not supported`
and `... Streaming input exceeded maximum size of 33.55 MB` (debug),
`Cannot convert media: Source file does not exist: <path>` (warning),
`... Source file exceeds maximum size of 33.55 MB` and `... Source file is
not a supported media format` (debug), `Media conversion via <name> timed
out after <prettytime>`, `... failed.` with ` Encoder: <stderr>`, `... produced
invalid WebP output`, `Invalid media conversion output from <name>` and
`Error during media conversion: <error>` (warning), `Media converted to WebP
with <name>` (debug). The timeout text is `RNS.prettytime` of what upstream
passes: the time left of the deadline (a float) for in-memory conversion,
the configured timeout (`8s` by default) for files. `pages/downloads.rs`
`is_image_path` now derives from `SUPPORTED_IMAGE_EXTS`. The real-backend
tests use a BMP, since PPM input is now refused, as upstream refuses it.
`docs/rns-git.md` describes the check, the coder and the cap.

Tests (with `sh` stand-ins for the encoders that record their arguments and
standard input): `image_formats_are_classified_by_their_signatures_as_upstream`
(31 cases, every one also run through upstream's `detect_image_format` at
`f55c0c6e`, which agrees), `only_imagemagick_backends_take_the_explicit_input_coder`
(checked against upstream's `_configured_backend` for all five backends),
`input_that_is_not_a_supported_image_never_reaches_the_encoder` (text, PPM,
SVG, MVG and a BMP with an unknown DIB size, from memory and from a file),
`input_over_the_size_cap_never_reaches_the_encoder` (32 MiB + 1 refused,
exactly 32 MiB encoded, from memory and from a file),
`a_supported_image_reaches_the_encoder_whole_with_its_coder` (each backend,
from memory and from a file), `encoder_failures_and_invalid_output_are_not_converted`,
`encoder_runs_report_exit_status_and_timeout`,
`failures_are_logged_with_upstreams_messages` (`RNS.prettysize` and
`RNS.prettytime` values taken from upstream) and, in `pages`,
`image_paths_are_the_media_modules_supported_image_extensions`. The tests
need functions the change adds, so they cannot build before it; to show
they catch the behaviour, each guard was removed in turn and the suite run:
no signature check (1 failure), no size cap (1), no coder (2), the coder
also given to ffmpeg/avconv (2), no rewind of the source file (2). The two
ignored real-backend tests pass with this host's ImageMagick 6 `convert`
and with `RNGIT_MEDIA_BACKEND=ffmpeg`. `cargo test -p rns-git`: lib 231
passed (2 ignored), e2e 8, releases 11, stats 6, 0 failures;
`cargo fmt --all --check` and `bash scripts/lint-host.sh` clean.

Notes: rns-git resolves the backend once per conversion, where upstream
resolves it again after the sniff; the no-backend warning keeps rns-git's
earlier wording, which this commit does not touch upstream. Upstream's
relay-only failures (no input within the deadline, the encoder exiting
before the input is consumed) cannot occur, because the encoder's standard
input is a file.

**Final disposition:** Integrated.

### 2. `f55c0c6e` — Added security notice

Full hash `f55c0c6ea618ebae33e7d3ab2e37b200ce0b0d81`; changes `SECURITY.md`
(+2) and adds `docs/security/2026_11_19_Media_conversion_in_rngit_and_nomadnet.md`
(+91). Depends on commit 1, which it describes.

**Upstream change:** `SECURITY.md` points at `docs/security` for published
notices. The notice says that ImageMagick, as a media conversion backend, can
be made to read any file the serving user can read and leak it into converted
output; that anyone serving untrusted media through `rngit` or `nomadnet`
with ImageMagick installed was exposed; and that the hot-patched 1.6.1
release (commit 1) makes those code paths unreachable. No code changes.

**Rust applicability:** No runtime change. rns-rs has no `SECURITY.md`; the
operator-facing surface is the rns-git media documentation.

**Local handling and evidence:** `a6127d80`: the media section of
`docs/rns-git.md` links upstream's notice, summarises the exposure, says
that rns-git applies the same mitigation since the port of `840eb369`, and
tells operators of older builds to set `[pages] media_conversion = no` (or
run without ImageMagick) until they update. A `SECURITY.md` for rns-rs (a
reporting contact and a notices directory) would be a project decision, not
a port, and is not added.

**Final disposition:** Non-runtime.

## Integration Plan

Every commit has a final disposition and one mapping commit; no
implementation work remains. The gates are recorded below.

## Promotion Gates

- [x] Every upstream commit has a final disposition.
- [x] Focused regressions pass for every applicable behavior change.
- [x] Fixture provenance and byte stability are checked where applicable.
- [x] Exact-target live Python/Rust interop passes.
- [x] Workspace tests, feature suites, formatting, and lint pass.
- [x] Required build, Docker, hardware, and manual gates are recorded honestly.
- [x] Native documentation is updated for user-visible behavior.
- [x] A final parity record is created from `PARITY-TEMPLATE.md`.

## Acceptance Record

Gates were run on 2026-11-20 on `upstream/f55c0c6e` at `fe5f504e`
(`dev@3d98c991` plus the audit opening, the two mapping commits and the
audit update), against a disposable worktree of the Reticulum checkout at
`f55c0c6e` (`HEAD:RNS` `3737af21`, `import RNS` reports 1.6.1). The
configured checkout stayed at `cff4d03f`.

- No conformance fixture is affected: the range changes only rngit's media
  conversion and documentation, nothing on the wire. The signature table
  and the per-backend argument lists were checked against upstream's
  `detect_image_format` and `_configured_backend` at `f55c0c6e` (same
  results for all 31 classification cases and all five backends).
- Exact-target interop with CI's commands, `PYTHONPATH` and
  `RETICULUM_UPSTREAM_DIR` at the `f55c0c6e` worktree: `rns-git --lib`
  231 passed (2 ignored), with its Python-peer tests running against
  upstream's rngit; `python_interop` 6 passed (1 ignored);
  `utility_interop -- --ignored` 34 passed; `placeholders -- --ignored`
  1 passed. 0 failures.
- `cargo test --workspace`: 3,861 passed, 0 failed, 76 ignored (the known
  flaky direct-link test passed in this run).
- `cargo fmt --all --check` and `bash scripts/lint-host.sh` clean (lint run
  on the 840eb369 mapping; the later commits change only Markdown).
- The ignored real-backend media tests pass with ImageMagick 6 `convert` and
  with ffmpeg on this host.
- `scripts/check_upstream_drift.py` (2026-11-20 21:17 UTC, both remotes
  fresh) reports drift from `cff4d03f`: GitHub tip `f55c0c6e`, rgit tip
  `606a1691`, the two audited commits plus `606a1691`, which is outside this
  audit.
- Not run: `--features rns-hooks` and the other feature suites,
  `python_interop` under the compact-threads and parallel engines,
  `rnodeconf` interop, ARMv7 and ESP32 builds, Docker E2E, the dual-VPS
  Backbone smoke and hardware validation. None of them reaches rns-git's
  media code. CI's interop pin stays at the signed `1.6.1` tag commit
  `cff4d03f`, as it stayed at the signed release for the earlier
  same-version rgit advancements, so the promotion pull request's CI does
  not exercise `f55c0c6e`; the exact-target run above does.

The final record is [reticulum-1.6.1-rgit-2-parity.md](reticulum-1.6.1-rgit-2-parity.md).
