# Upstream Reticulum Tracking

This repository is a Rust implementation of the Python Reticulum project.

The current upstream reference baseline is:

- Project: Reticulum
- Repository: `https://github.com/markqvist/Reticulum`
- Local checkout used: `/home/lelloman/Reticulum`
- Tag: `1.2.1`
- Commit: `1f3ce7e78f87bcc519c0ffbcdcc87ca4feccc83a`
- Commit date: `2026-05-04 01:37:51 +0200`
- Subject: `Prepare release`

The previous recorded baseline was Reticulum `1.2.0`, with release commit
`d7c3859f61a08a4330908550c8af9d57659779a6`. The upstream `1.2.0..1.2.1`
range was reviewed and the relevant `rngit` changes were ported or explicitly
deferred with the following local commits:

- `0138338` Add rngit create permission
- `9024178` Add rngit Nomad Network page scaffold
- `fb12946` Add rngit page browser routes
- `ba4b067` Improve rngit page rendering
- `6c3a17d` Add rngit Markdown readme rendering
- `6445a6f` Add rngit syntax highlighting
- `cd7f492` Add rngit repository stats
- `b821da4` Add rendered blob controls
- `d9fa30b` Add rngit page templates and icons
- `fa315b0` Improve rngit Markdown table rendering
- `bccbecc` Add rngit repository thanks counts
- `8ab43cd` Add rngit stats linebreak regression test

When integrating future upstream changes, compare this baseline against the new
Reticulum upstream commit, review protocol/runtime/utility changes, port or
explicitly defer each relevant item, run the interop and focused regression
tests, then update this file to the new baseline commit.
