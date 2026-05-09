# Upstream Reticulum Tracking

This repository is a Rust implementation of the Python Reticulum project.

The current upstream reference baseline is:

- Project: Reticulum
- Repository: `https://github.com/markqvist/Reticulum`
- Local checkout used: `/home/lelloman/Reticulum`
- Tag: `1.2.3`
- Commit: `8661a3886b76cac27e5b961aa1e098f9b2be9733`
- Commit date: `2026-05-05 20:01:08 +0200`
- Subject: `Prepare release`

The previous recorded baseline was Reticulum `1.2.2`, with release commit
`07ff87974e3194b3c27874df2a1b813a48b33018`. The upstream
`1.2.2..1.2.3` range was reviewed and the relevant `rngit` and resource
cleanup changes were ported or explicitly audited with the following local
commits:

- `192fb49` Add rngit interact and admin permissions
- `caf0097` Add rngit work document storage
- `1af5baa` Add rngit work management protocol
- `4dfa266` Add rngit work document pages
- `d9950dc` Add rngit work CLI
- `63b093a` Improve rngit markdown rendering parity

When integrating future upstream changes, compare this baseline against the new
Reticulum upstream commit, review protocol/runtime/utility changes, port or
explicitly defer each relevant item, run the interop and focused regression
tests, then update this file to the new baseline commit.
