# Reticulum Next Upstream Audit

## Scope and Baseline

- audit date: `2026-08-06`
- previous accepted version: `1.4.2`
- previous normative commit: `b48b96e61676504e0a4e527b33b9a0b4495c6872`
- target version: pending; `RNS.__version__` remains `1.4.2` at the observed tip
- target tag or ref: pending; observed `rgit/master`
- target normative commit: pending; observed tip `4fc8e03d658ed87019b8ad6c7ce7827dc76f0e45`
- observed target root tree: `866e71c8a6b3b2196476467d7aeede3f509d7fed`
- observed target `RNS` tree: `8edc9d52943aa465c8f4e23debaaa9224c74eeb2`
- version assertion at observed tip: `RNS.__version__ == "1.4.2"`
- audited range: `b48b96e61676504e0a4e527b33b9a0b4495c6872..4fc8e03d658ed87019b8ad6c7ce7827dc76f0e45`
- commits in range: `1`
- repositories checked: normative `rns://7649a50d84610232d1416b41d2896aff/reticulum/reticulum` and GitHub mirror `git@github.com:markqvist/Reticulum.git`
- local branch and revision inspected: `dev@29289864fbd958e6d8a6e0ccbd032bec3502a7e3`

On 2026-08-06, `rgit/master` was one commit ahead of the accepted baseline at
`4fc8e03d658ed87019b8ad6c7ce7827dc76f0e45`, while the GitHub mirror's
`origin/master` still pointed to the accepted baseline. The observed commit is
therefore audited here, but it is not yet promoted as a normative target.
The 2026-08-08 daily check confirmed that both remote tips and this one-commit
delta were unchanged.

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

Every commit in the audited range appears exactly once.

| # | Upstream commit | Subject | Final disposition | Local evidence |
|---:|---|---|---|---|
| 1 | `4fc8e03d658ed87019b8ad6c7ce7827dc76f0e45` | Added blocked IP listing to rnstatus | Integrated | `d91ac56` exposes `blocked_ip_list` through interface stats; `2928986` adds `rnstatus -b/--blocked-ips`, display logic, help text and tests |

## Per-Commit Analysis

### 1. `4fc8e03d` — Added blocked IP listing to rnstatus

**Upstream change:** Adds `-b`/`--blocked-ips` to `rnstatus` and, when the
option is selected, prints each address from an interface's `blocked_ip_list`
below its blocked-address count.

**Rust applicability:** The option and conditional output are part of the
user-visible `rnstatus` compatibility surface. The underlying compatible
`blocked_ip_list` interface-stat field was already available in Rust.

**Local handling and evidence:** Local commit `d91ac56` exposes the sorted,
current blocked-address list through driver queries and compatible RPC stats.
Local commit `2928986` adds the `rnstatus -b/--blocked-ips` flag, conditional
list rendering, help text and argument/display regressions. On 2026-08-06,
`cargo test -p rns-cli blocked_ips`, `cargo test -p rns-cli --bin rnstatus
blocked_ip`, and `cargo test -p rns-net blocked_ip` passed.

**Final disposition:** Integrated.

## Integration Plan

No implementation work is currently unresolved for the observed commit. Wait
for the GitHub mirror and normative rgit repository to identify a stable
promotion target and version, then rename this audit and complete the remaining
promotion gates against that exact target.

## Promotion Gates

- [x] Every currently observed upstream commit has a final disposition.
- [x] Focused regressions pass for every currently observed applicable behavior change.
- [ ] Fixture provenance and byte stability are checked where applicable.
- [ ] Exact-target live Python/Rust interop passes.
- [ ] Workspace tests, feature suites, formatting, and lint pass.
- [ ] Required build, Docker, hardware, and manual gates are recorded honestly.
- [x] Native documentation is updated for the currently observed user-visible behavior.
- [ ] A final parity record is created from `PARITY-TEMPLATE.md`.

## Acceptance Record

- `2026-08-08`: Daily VPS snapshots were healthy on `vps-eu` and `vps-us`,
  with complete announce counters and no idle-timeout events in the preceding
  24 hours. Both nodes matched the configured `origin/master` binary versions.
  The daily live Backbone stress profile passed announce propagation, identity
  recall, bidirectional packets, links, Channels, concurrent Resources across
  the 1 MiB boundary, concurrent link batches, and one forced reconnect cycle.
- `2026-08-06`: Daily VPS snapshots were healthy on `vps-eu` and `vps-us`.
  The daily live Backbone stress profile passed announce propagation, identity
  recall, bidirectional packets, links, Channels, concurrent Resources across
  the 1 MiB boundary, concurrent link batches, and one forced reconnect cycle.
- `2026-08-06`: Focused blocked-IP regressions passed as listed above.
- Promotion is not claimed: the two upstream remotes do not yet agree, the
  target version is unknown, and the remaining promotion gates have not run.
