# Upstream Reticulum Tracking

This repository is a Rust implementation of the Python Reticulum project.

The current upstream reference baseline is:

- Project: Reticulum
- Repository: `https://github.com/markqvist/Reticulum`
- Local checkout used: `/home/lelloman/Reticulum`
- Tag: `1.2.4`
- Commit: `9d076d6a194ee9675a5bf585de1b2c2a634f3946`
- Commit date: `2026-05-07 20:07:21 +0200`
- Subject: `Prepare release`

The previous recorded baseline was Reticulum `1.2.3`, with release commit
`8661a3886b76cac27e5b961aa1e098f9b2be9733`. The upstream
`1.2.3..1.2.4` range was reviewed and the relevant runtime, discovery,
`rnstatus`, `rnpath`, `rnid`, identity-retention, and `rngit` changes were
ported or explicitly deferred with the following local commits:

- `cfdc447` Add rngit work document permissions
- `1d71ca0` Sort rngit work documents by latest activity
- `e71fdc3` Escape rngit rendered line-start controls
- `cf4afcf` Scope rngit markdown relative links
- `5410f01` Render rngit release preview formats
- `7982a24` Add announce-rate defaults
- `aa67f7a` Sanitize discovered interfaces
- `4b16a4f` Clear transient state on shutdown
- `2b4d6e4` Show per-client announce frequency
- `ca156fa` Retain known destinations by identity
- `27b7ad4` Fix markdown inline link ordering
- `7c3aa75` Port rnid identity signature flow
- `3cd2e18` Add rnid identity lookup E2E tests
- `827d4b5` Match rnpath time formatter boundaries

When integrating future upstream changes, compare this baseline against the new
Reticulum upstream commit, review protocol/runtime/utility changes, port or
explicitly defer each relevant item, run the interop and focused regression
tests, then update this file to the new baseline commit.
