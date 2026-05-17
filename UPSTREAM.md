# Upstream Reticulum Tracking

This repository is a Rust implementation of the Python Reticulum project.

The current upstream reference baseline is:

- Project: Reticulum
- Repository: `https://github.com/markqvist/Reticulum`
- Local checkout used: `/home/lelloman/Reticulum`
- Tag: `1.2.5`
- Commit: `e8d161c0d50cc0416c98dcd1cee44807e7c52df1`
- Commit date: `2026-05-09 19:17:38 +0200`
- Subject: `Yes, that was indeed a bit overkill`

The previous recorded baseline was Reticulum `1.2.4`, with release commit
`9d076d6a194ee9675a5bf585de1b2c2a634f3946`. The upstream
`1.2.4..1.2.5` range was reviewed and the relevant path-request control,
`rnstatus`, `rnpath`, `rnid`, discovery, transport, and `rngit` changes were
ported or explicitly audited with the following local commits:

- `3bb19d7` Add path request control core
- `12a250d` Gate recursive path requests
- `a22d307` Add ingress control config defaults
- `0f5221c` Add rnstatus path request stats
- `37adc59` Validate rngit refs and SHAs
- `f9f106f` Harden rngit stats and work limits
- `8eea4e2` Reject slashed rngit release tags
- `93b97c2` Fix rngit rendering escapes
- `bba47af` Hide rngit git failure details from clients
- `1ca8cd6` Add rnid ASCII RSG output
- `e3211e5` Ignore initiator-closed remote links
- `d7cf58d` Show rnstatus per-peer rates
- `1c44a6f` Handle corrupt discovery persistence
- `9c01ad9` Sort pending announce retransmits
- `913aa49` Throttle recursive path requests
- `2a66180` Add rngit page git timeouts
- `2877408` Mark discovered transport entries as gateway

When integrating future upstream changes, compare this baseline against the new
Reticulum upstream commit, review protocol/runtime/utility changes, port or
explicitly defer each relevant item, run the interop and focused regression
tests, then update this file to the new baseline commit.

## Active 1.2.5..1.2.7 Porting Queue

The `/home/lelloman/Reticulum` checkout was advanced to upstream
`b1f522277c99b076ea4b43e9048aec8962e0e4a2` on 2026-05-17. The detailed
analysis for this range is in
`docs/reticulum-upstream-commit-analysis-2026-05-17.md`.

- [x] `0ebec014` Improved release page
  - Ported the remaining Rust-applicable rendering change: empty release
    artifact lists now use Micron emphasis.
  - Confirmed artifact ordering was already covered by `release::artifacts()`
    sorting by filename; added a page regression test to lock that behavior.
- [ ] `e004e759` Added lock to interface discovery
  - Next item to inspect for Rust applicability.
