# Upstream Reticulum Tracking

This repository is a Rust implementation of the Python Reticulum project.

The current upstream reference baseline is:

- Project: Reticulum
- Repository: `https://github.com/markqvist/Reticulum`
- Local checkout used: `/home/lelloman/Reticulum`
- Tag: `1.2.0`
- Commit: `d7c3859f61a08a4330908550c8af9d57659779a6`
- Commit date: `2026-04-28 21:54:18 +0200`
- Subject: `Prepare release`

The previous recorded baseline was Reticulum `1.1.3`, with release commit
`286a78ef8c58ca4503af2b0211b3a2d7e385467c`. The upstream `1.1.9..1.2.0`
range was reviewed in `docs/upstream-1.2.0-porting-analysis.md` and ported with
the following local commits:

- `fdcdb91` Gracefully tear down links on shutdown
- `2446e4c` Port Android local interface sleep handling
- `d343c0b` Filter Android rmnet auto interfaces
- `b0bc33f` Document startup inbound readiness behavior
- `1743069` Add persistent ratchet storage
- `7919038` Add split resource transfer progress
- `1061ed5` Add Reticulum Git transport tools
- `b7afc53` Add rnsh remote shell utility
- `6313a98` Add utility-specific log targets
- `2b49017` Add base256 display helper
- `5931ced` Document Reticulum utility ports
- `1975197` Fix utility port CI checks
- `ec5db60` Release Reticulum 1.2 utility ports
- `13c00ed` Complete rngit upstream parity gaps

When integrating future upstream changes, compare this baseline against the new
Reticulum upstream commit, review protocol/runtime/utility changes, port or
explicitly defer each relevant item, run the interop and focused regression
tests, then update this file to the new baseline commit.
