# Reticulum 1.5.5 Upstream Audit

## Scope and Baseline

- audit opened: `2026-09-28`
- previous accepted version: `1.5.4`
- previous normative commit: `3f95b472820ddfb27f736143fb0b4d0d3aa610f1`
- target version: `1.5.5` (`RNS/_version.py`)
- target normative commit: `e2ba876ebfec386af9f97d844c39e9ca016e956c` (`rgit/master`)
- current rgit tip root tree: `187adb2d8d12578cba4a7d174c616f587d70458f`
- current rgit tip `RNS` tree: `62dc6859a28fc76b064e0c2fa062ff560ad9a343`
- candidate audited range: `3f95b472820ddfb27f736143fb0b4d0d3aa610f1..e2ba876ebfec386af9f97d844c39e9ca016e956c`
- commits in candidate range: `9`
- repositories checked: normative rgit remote and GitHub mirror, both refreshed on `2026-09-28`
- local branch and revision inspected: `dev@681e3e0ec0cc020dd9a43e8d54705a450a0db2ab`

The GitHub mirror tip is `c95fd8e6ca88c9e3b0e3306c74ff604a36894c67`, the first commit after the accepted baseline. The rgit tip is eight commits further ahead. The normative rgit tip at version 1.5.5 is the exact promotion target. Final dispositions and acceptance still require source review.

## Audit Vocabulary

- **Needs port**: compatible behavior is absent or observably different.
- **Needs coordinated port**: related changes must be implemented together.
- **Needs decision**: architecture differs and the compatibility surface must be chosen explicitly.
- **Integrated**: applicable behavior is implemented with recorded evidence.
- **Structurally covered**: the Rust design already provides the behavior or avoids the upstream failure through a different invariant.
- **Documentation follow-up**: native documentation is required after the related behavior exists.
- **Deferred**: applicable work is deliberately postponed with rationale and impact recorded.
- **Non-runtime**: metadata, changelog, generated artifacts, or upstream-only tests require no independent Rust runtime change.

## Commit Inventory

The rows are in ancestry order. `Pending review` means no final disposition has been assigned.

| # | Upstream commit | Subject | Changed paths | Final disposition | Local evidence |
|---:|---|---|---|---|---|
| 1 | `c95fd8e6ca88c9e3b0e3306c74ff604a36894c67` | Updated rngit documentation | `docs/source/git.rst`, generated manual docs | Pending review | — |
| 2 | `e68f4ff118662a9fe747f956bb96c45695a5ab20` | Prepared AutoInterface for live detach/attach | `RNS/Interfaces/AutoInterface.py`, `Interface.py` | Pending review | — |
| 3 | `24b1ac521e4a0456d41b3fdd82d4ceb4d330f905` | Prepared RNodeInterface for live detach/attach | RNode, RNodeMulti, Android, Auto, base interfaces | Pending review | — |
| 4 | `2c30a88e85693bb73e493bfaa56533774507f40d` | Fixed I2P interface discovery config snippet generation not including .b32.i2p | `RNS/Discovery.py` | Pending review | — |
| 5 | `7283cb417aebef9ef94d972ca53806a06fe37b36` | Prepared serial-based interfaces for live detach/attach | AX25 KISS, KISS, Serial, Android interfaces | Pending review | — |
| 6 | `84709ccf09fddf23a9723c6904c7678159e878af` | Prepared TCP and UDP interfaces for live detach/attach | `TCPInterface.py`, `UDPInterface.py` | Pending review | — |
| 7 | `d23261c8d92323597e567c45580bda2c588e40aa` | Added live interface attach/detach/reload | `Reticulum.py`, `rnsd.py`, `rnstatus.py`, `using.rst` | Pending review | — |
| 8 | `6ecda49394708c4d4297bb3918bc4d2b11d8e8d6` | Updated documentation | generated and Markdown using guides | Pending review | — |
| 9 | `e2ba876ebfec386af9f97d844c39e9ca016e956c` | Updated version | `RNS/_version.py` | Pending review | — |

## Integration Plan

Review each commit's full diff in ancestry order and assign a supported disposition. Complete the per-commit integration and promotion workflow in [README.md](README.md).

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

- `2026-09-28`: Daily VPS snapshots were healthy and complete on both hosts. The impaired dual-VPS `--daily` smoke passed Resource boundaries, concurrent links, and forced reconnect recovery. Both upstream remotes refreshed successfully. These are daily operational results, not promotion acceptance for the candidate target.
