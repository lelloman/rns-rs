# Reticulum 1.6.1 rgit `f55c0c6e` Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.6.1` (the signed `1.6.1` tag at `cff4d03f`) |
| Previous normative commit | `cff4d03fdbd6bfb63b765280cd944756ac5cce8d` |
| Accepted version | `1.6.1` (unchanged; `RNS/_version.py` is not touched by the range) |
| Normative tag or ref | GitHub `master` tip, untagged; an ancestor of the rgit tip `606a1691` |
| Normative commit | `f55c0c6ea618ebae33e7d3ab2e37b200ce0b0d81` |
| Root tree | `724503209ece6226bf4211b96e7dbbf894650f52` |
| `RNS` tree | `3737af213a83c4a6833a8b926bac9e72ea78156a` |
| Version assertion | `RNS.__version__ == "1.6.1"` |
| Audited range | `cff4d03fdbd6bfb63b765280cd944756ac5cce8d..f55c0c6ea618ebae33e7d3ab2e37b200ce0b0d81` (2 commits) |
| Acceptance date | `2026-11-20` |
| Detailed audit | [reticulum-1.6.1-rgit-2-audit.md](reticulum-1.6.1-rgit-2-audit.md) |

The range is upstream's security hot-patch of the 1.6.1 release: the
release files were replaced with the mitigation of `840eb369`, and
`f55c0c6e` publishes the notice. The signed `1.6.1` tag still points at
`cff4d03f`, so this is a same-version rgit advancement and uses the
`-rgit-2` record names; the 1.6.1 rgit records stay unchanged. rgit's tip
had already moved one commit further (`606a1691`) when this was audited;
it is left for the next audit. No fixture is involved.

## Upstream Commit Audit

Both commits have a final disposition and one non-empty mapping commit in
upstream ancestry order, carrying an `Upstream-Commit` trailer: 1
Integrated, 1 Non-runtime.

| Area | Upstream commits | Final handling |
|---|---|---|
| rngit media conversion | 1 (`840eb369`) | Integrated: only input whose first 64 bytes carry a PNG, JPEG, GIF, TIFF, WebP or BMP signature (BMP with a known DIB header size) reaches an encoder; `magick`, `convert` and `gm` get `<format>:-` instead of `-`, `ffmpeg` and `avconv` keep `-i -`; input over 32 MiB is not converted; every outcome logs upstream's line at upstream's level. Applies to `/media` and to `convert_file_to_webp`; `detect_image_format`, `SUPPORTED_IMAGE_EXTS` and `CONV_SIZE_MAX` are public. |
| Security notice | 2 (`f55c0c6e`) | Non-runtime: `docs/rns-git.md` links upstream's notice, names the mitigation and gives `media_conversion = no` as the workaround for older builds. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | Unchanged; the range has no wire or cryptographic change. |
| Transport and interfaces | Unchanged by the range; workspace suite passes. |
| Links, channels, and resources | Unchanged; failed conversions still serve the original blob as before. |
| Utilities and APIs | rns-git media tests with stand-in encoders (signature table, per-backend coder, non-image and oversized input never reaching the encoder, whole input reaching it, upstream's log text), checked against upstream's `media.py` at `f55c0c6e`; real-backend tests with ImageMagick 6 and ffmpeg. Documented in `docs/rns-git.md`. |
| Live interop | Exact target `f55c0c6e` (`import RNS` reports 1.6.1 from that worktree): `rns-git` lib 231 passed with its Python-peer tests, `python_interop` 6 passed, `utility_interop` 34 passed, `placeholders` 1 passed. |

## Acceptance Record

Gates were run on 2026-11-20 on `upstream/f55c0c6e` at `fe5f504e`; see the
audit's acceptance record for details.

| Gate | Result |
|---|---|
| Focused regression suites | Passed: the tests named in the audit, run with the mapping commit and again in the suites below. Each guard removed in turn makes them fail. |
| Fixture regeneration/provenance | Not applicable: no fixture covers rngit media conversion and the range changes no wire format. |
| Exact-target Python/Rust interop | Passed against a disposable worktree at `f55c0c6e`, with CI's interop commands for the default engine and rns-git. |
| Workspace and feature suites | `cargo test --workspace` 3,861 passed, 0 failed. Feature suites were not run; the change is confined to rns-git, which has no features. |
| Formatting and lint | `cargo fmt --all --check` and `bash scripts/lint-host.sh` clean. |
| Release/cross builds | Not run; the change does not reach the ARMv7 or ESP32 targets' code. |
| Docker E2E | Not run; left to the promotion pull request's CI. |
| Hardware/manual validation | Not claimed; the dual-VPS Backbone smoke was not run on this code. |

## Caveats and Deferred Validation

- rns-git holds the blob in memory, so the 32 MiB cap is checked before the
  encoder starts rather than while relaying, and upstream's relay-only
  failures (no input within the deadline, the encoder exiting before
  reading all input) cannot occur.
- The no-backend warning keeps rns-git's earlier wording; this range does
  not change that line upstream.
- CI's 1.6.1 interop pin stays at the signed tag commit `cff4d03f`; only the
  manual exact-target run covers `f55c0c6e`. The range changes only rngit's
  media conversion and documentation upstream.
- The local upstream checkout (`/home/lelloman/Reticulum`) stays at
  `cff4d03f` until this lands; it moves to `f55c0c6e` then, for the daily
  drift check, which will still report rgit's `606a1691`.

## Promotion Result

Reticulum is accepted at `1.6.1`, normative commit
`f55c0c6ea618ebae33e7d3ab2e37b200ce0b0d81`, the GitHub `master` tip and an
ancestor of the canonical `rgit/master` tip. [UPSTREAM.md](../../UPSTREAM.md)
records this baseline and links this record; the detailed work record is
[reticulum-1.6.1-rgit-2-audit.md](reticulum-1.6.1-rgit-2-audit.md).
