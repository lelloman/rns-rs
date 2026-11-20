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
The dispositions below are the ones proposed by the 2026-11-20 diff review;
the local evidence column is filled in as each mapping commit lands.

| # | Upstream commit | Date | Subject | Proposed disposition | Local evidence |
|---:|---|---|---|---|---|
| 1 | `840eb369` | 2026-11-19 | Added rngit media conversion max input size cap, improved logging and error handling | Needs port | pending |
| 2 | `f55c0c6e` | 2026-11-20 | Added security notice | Non-runtime | pending |

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

**Local handling and evidence:** Planned: port the constants,
`detect_image_format` and the signature table, apply `<format>:-` to the
ImageMagick and GraphicsMagick argument lists exactly as upstream does, sniff
and cap in both `convert_to_webp` and `convert_file_to_webp` in upstream's
order, take upstream's log lines and levels for every outcome, and derive
`is_image_path` from `SUPPORTED_IMAGE_EXTS`. Focused tests with fake encoder
commands: the signature table (including the DIB sizes and WebP header), the
per-backend argument lists, non-image input and oversized input never
reaching the encoder, and an accepted image reaching it with its coder.
Update the media section of `docs/rns-git.md`.

**Proposed disposition:** Needs port.

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

**Local handling and evidence:** Planned: a security note in the media
section of `docs/rns-git.md` linking upstream's notice, stating which
rns-git revision applies the same mitigation, and that older builds should
set `[pages] media_conversion = no` (or have no ImageMagick installed).

**Proposed disposition:** Non-runtime.

## Integration Plan

1. `840eb369`: port the mitigation into `rns-git/src/media.rs` and
   `pages/downloads.rs` with focused tests and `docs/rns-git.md`.
2. `f55c0c6e`: the security note in `docs/rns-git.md`.
3. Record final dispositions, local hashes and test results here, run the
   promotion gates, and write the parity record.

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

Not yet run.
