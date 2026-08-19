# Reticulum 1.4.2 rgit Upstream Audit

## Scope and Baseline

- audit date: `2026-08-11`
- previous accepted version: `1.4.2`
- previous normative commit: `b48b96e61676504e0a4e527b33b9a0b4495c6872`
- target version: `1.4.2`
- target tag or ref: `rgit/master` at promotion time
- target normative commit: `4fc8e03d658ed87019b8ad6c7ce7827dc76f0e45`
- target root tree: `866e71c8a6b3b2196476467d7aeede3f509d7fed`
- target `RNS` tree: `8edc9d52943aa465c8f4e23debaaa9224c74eeb2`
- version assertion: `RNS.__version__ == "1.4.2"`
- audited range: `b48b96e61676504e0a4e527b33b9a0b4495c6872..4fc8e03d658ed87019b8ad6c7ce7827dc76f0e45`
- commits in range: `1`
- repositories checked: normative `rns://7649a50d84610232d1416b41d2896aff/reticulum/reticulum` and GitHub mirror `git@github.com:markqvist/Reticulum.git`
- local branch and revision inspected: `dev@bf10d9ca695298a96bb86f7df591ae90c3aabcb8`

On 2026-08-11, `rgit/master` was one commit ahead of the accepted baseline at
`4fc8e03d658ed87019b8ad6c7ce7827dc76f0e45`, while the GitHub mirror's
`origin/master` still pointed to the signed-release baseline and a clean GitHub
clone could not fetch the target by exact SHA. Upstream continued to assert
version 1.4.2. After exact-target local validation from the normative checkout,
the rgit commit is promoted as a qualified 1.4.2 rgit baseline without
rewriting the earlier signed-release acceptance.

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
| 1 | `4fc8e03d658ed87019b8ad6c7ce7827dc76f0e45` | Added blocked IP listing to rnstatus | Integrated | `d91ac56` exposes `blocked_ip_list` through interface stats; `f191fc3` adds `rnstatus -b/--blocked-ips`, display logic, help text and tests |

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
Local commit `f191fc3` adds the `rnstatus -b/--blocked-ips` flag, conditional
list rendering, help text and argument/display regressions. On 2026-08-06,
`cargo test -p rns-cli blocked_ips`, `cargo test -p rns-cli --bin rnstatus
blocked_ip`, and `cargo test -p rns-net blocked_ip` passed.

**Final disposition:** Integrated.

## Integration Plan

No implementation work is unresolved for the accepted commit. Future drift is
measured from `4fc8e03d658ed87019b8ad6c7ce7827dc76f0e45`.

## Promotion Gates

- [x] Every upstream commit has a final disposition.
- [x] Focused regressions pass for every applicable behavior change.
- [x] Fixture provenance and byte stability are unchanged; the delta is CLI-only.
- [x] Exact-target live Python/Rust interop passes.
- [x] Workspace tests, formatting, and lint pass.
- [x] Required build, Docker, hardware, and manual gates are recorded honestly.
- [x] Native documentation is updated for the user-visible behavior.
- [x] A final parity record is created from `PARITY-TEMPLATE.md`.

## Acceptance Record

- `2026-08-19`: The GitHub mirror refreshed successfully, but the canonical
  rgit endpoint could not establish an application Link after resolving
  `7649a50d84610232d1416b41d2896aff`. The failure reproduced with both the
  current Rust `git-remote-rns` helper and the original Python client from the
  accepted Reticulum checkout. Independent path lookups from the workstation,
  `vps-eu`, and `vps-us` succeeded through different next hops. Canonical rgit
  freshness is therefore unknown; the cached `rgit/master` ref at `4fc8e03d`
  is not accepted as evidence that upstream has not moved. The last successful
  local rgit fetch recorded in the reflog was `2026-07-29 17:43:02 +0200`.
- `2026-08-11`: Both upstream remotes were refreshed. Normative `rgit/master`
  remained at `4fc8e03d`; GitHub `master` remained at the signed-release
  baseline. Root-tree, `RNS`-tree and version assertions passed against the
  normative local checkout.
- `2026-08-11`: A clean GitHub Actions clone could not fetch `4fc8e03d` by
  exact SHA. The CI interop lane remains pinned to the signed-release commit
  until the mirror advances; exact-target evidence comes from the local
  normative checkout.
- `2026-08-11`: Exact-target Python/Rust bidirectional TCP packet interop and
  all five ignored `rncp`/`rnx` utility interoperability tests passed.
- `2026-08-11`: Focused blocked-IP CLI and interface regressions passed.
- `2026-08-11`: `cargo test --workspace`, `cargo fmt --all -- --check` and
  `scripts/lint-host.sh` passed. Lint retained the repository's existing warning
  baseline.
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
- Docker E2E, cross-compilation and physical Weave HIL were not rerun for this
  CLI-only advancement and are not claimed.
