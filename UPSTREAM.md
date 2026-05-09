# Upstream Reticulum Tracking

This repository is a Rust implementation of the Python Reticulum project.

The current upstream reference baseline is:

- Project: Reticulum
- Repository: `https://github.com/markqvist/Reticulum`
- Local checkout used: `/home/lelloman/Reticulum`
- Tag: `1.2.2`
- Commit: `07ff87974e3194b3c27874df2a1b813a48b33018`
- Commit date: `2026-05-05 01:19:43 +0200`
- Subject: `Prepare release`

The previous recorded baseline was Reticulum `1.2.1`, with release commit
`1f3ce7e78f87bcc519c0ffbcdcc87ca4feccc83a`. The upstream
`1.2.1..1.2.2` range was reviewed and the relevant `rngit` and transport
changes were ported or explicitly deferred with the following local commits:

- `79a93fd` Add rngit release management
- `4261468` Add rngit release CLI
- `ab2c70e` Show rngit release upload progress
- `b9cc3cc` Log tunnel synthesis failures
- `64e9827` Decode rngit artifact download names

When integrating future upstream changes, compare this baseline against the new
Reticulum upstream commit, review protocol/runtime/utility changes, port or
explicitly defer each relevant item, run the interop and focused regression
tests, then update this file to the new baseline commit.
