# Reticulum Next Upstream Audit

## Scope and Baseline

- audit date: `2026-07-29`
- previous accepted version: `1.4.2`
- previous normative commit: `b48b96e61676504e0a4e527b33b9a0b4495c6872`
- target version: pending; the observed normative tip still asserts `1.4.2`
- target tag or ref: pending; `rgit/master` is ahead of `origin/master`
- observed normative tip: `4fc8e03d658ed87019b8ad6c7ce7827dc76f0e45`
- observed normative root tree: `866e71c8a6b3b2196476467d7aeede3f509d7fed`
- observed normative `RNS` tree: `8edc9d52943aa465c8f4e23debaaa9224c74eeb2`
- version assertion: `RNS.__version__ == "1.4.2"`
- audited range: `b48b96e61676504e0a4e527b33b9a0b4495c6872..4fc8e03d658ed87019b8ad6c7ce7827dc76f0e45`
- commits in range: `1`
- repositories checked: normative `rgit` repository and GitHub release mirror
- local branch and revision inspected: `master@5083f41515b1fe196656f330cc118ca7ad685944`

The normative `rgit/master` tip is one commit ahead of the accepted baseline,
while the GitHub `origin/master` tip remains exactly at the baseline. The next
release version and exact promotion target are therefore pending; this audit
records the observed normative delta without promoting it.

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

| # | Upstream commit | Subject | Final disposition | Local evidence |
|---:|---|---|---|---|
| 1 | `4fc8e03d658ed87019b8ad6c7ce7827dc76f0e45` | Added blocked IP listing to rnstatus | Structurally covered | `rns-sentineld` maintains dynamic blacklist state; `rns-net` enforces and exposes it; `rns-ctl backbone blacklist list/clear` provides operational inspection and control |

## Per-Commit Analysis

### 1. `4fc8e03d` — Added blocked IP listing to rnstatus

**Upstream change:** Adds `-b`/`--blocked-ips` to `rnstatus` and, when selected,
prints each address from an interface's `blocked_ip_list` below the existing
blocked-address count.

**Rust applicability:** The compatible interface statistics already expose the
list through local commit `4f2c157`. More importantly, the Rust architecture
implements dynamic application-level blacklisting through `rns-sentineld`,
enforces the resulting state in `rns-net`, and exposes list/clear operations
through `rns-ctl backbone blacklist` and the control API.

**Local handling and evidence:** No runtime port is required. Exact `rnstatus`
option spelling and text rendering are CLI presentation details, which are
outside the wire-compatibility scope defined by `docs/protocol-spec.md`. The
native operational interface is deliberately richer than the upstream status
view.

**Final disposition:** Structurally covered.

## Integration Plan

No implementation work is required for this upstream change. Continue testing
the dynamic blacklist lifecycle, enforcement, and list/clear control surfaces
as part of the existing backbone and sentinel suites.

## Promotion Gates

- [x] Every upstream commit has a final disposition.
- [x] Focused regressions pass for every applicable behavior change.
- [x] Fixture provenance and byte stability are not applicable to this CLI-only change.
- [x] Exact-target live Python/Rust interop is not applicable to this CLI-only change.
- [ ] Workspace tests, feature suites, formatting, and lint pass.
- [ ] Required build, Docker, hardware, and manual gates are recorded honestly.
- [x] Native documentation records the structural coverage decision.
- [ ] A final parity record is created from `PARITY-TEMPLATE.md`.

## Acceptance Record

- `2026-07-29`: Both upstream remotes were fetched. The accepted baseline is
  an ancestor of both tips. GitHub remains at
  `b48b96e61676504e0a4e527b33b9a0b4495c6872`; the normative rgit tip is
  `4fc8e03d658ed87019b8ad6c7ce7827dc76f0e45`, one commit ahead.
- `2026-07-29`: The daily release build and stressed dual-VPS smoke passed,
  including Resource boundaries, concurrent links and Resources, impaired
  network legs, and forced Backbone disconnect/recovery. These results validate
  the current Rust baseline; the upstream `rnstatus` option requires no native
  port because the behavior is structurally covered.
