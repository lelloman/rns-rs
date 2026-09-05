# Reticulum 1.5.2 Upstream Audit

## Scope and Baseline

- audit date: `2026-09-05`
- previous accepted version: `1.5.2`
- previous normative commit: `3bc149e3d587695f52e695f18edb11751b21c005`
- target version: `1.5.2`
- target tag or ref: `rgit/master`
- target normative commit: `2f29b56e96bfa6fd3fc61518e4e5710ac8e92258`
- target root tree: `42980ea74bf2d2907659a0aedce514b7cd4aa070`
- target `RNS` tree: `a2c1e238967e965a32b622b65db6e2ca346823cd`
- version assertion: `RNS.__version__ == "1.5.2"`
- audited range: `3bc149e3d587695f52e695f18edb11751b21c005..2f29b56e96bfa6fd3fc61518e4e5710ac8e92258`
- commits in range: `1`
- repositories checked: canonical rgit repository and GitHub mirror
- local branch and revision inspected: `dev@b0a656c858213c804827f1f4a4e4a32f4a1c98ed`

The canonical rgit `master` tip is one commit ahead of the accepted baseline.
The GitHub mirror remains behind the accepted baseline at
`ea98db4f53dcf0defc0e71a16e60d28b1229c4e6`. Both remote tips were refreshed
successfully on 2026-09-05. The configured upstream checkout remains pinned at
the accepted baseline; the target object was inspected without advancing it.

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
| 1 | `2f29b56e96bfa6fd3fc61518e4e5710ac8e92258` | Adjusted logging | Structurally covered | `4fad68c`; targeted missing/offline interfaces retain interface-specific diagnostics and never fall back to another interface. |

## Per-Commit Analysis

### 1. `2f29b56e` — Adjusted logging

**Upstream change:** `Packet.send()` no longer emits the debug message claiming
that no interfaces could process an outbound packet when the packet has an
attached interface. The send still returns failure; only diagnostic output is
changed.

**Rust applicability:** Rust routes attached-interface traffic explicitly and
logs the resulting outbound action count, rather than emitting the same Python
failure message. The dispatch layer reports a missing target as `cannot send on
missing interface` and an offline or disabled target as `cannot send on
unavailable interface`; it never substitutes the misleading generic claim
that no interface could process the packet.

**Local handling and evidence:** Commit `4fad68c` documents the native
interface-specific diagnostic invariant and adds
`missing_attached_interface_does_not_fall_back_to_other_interfaces`, complementing
the existing offline-interface regression. The focused test passed. The full
`rns-net` suite passed with 941 unit tests, 54 network E2E tests, Python interop,
IFAC interop, and fixture suites; `cargo fmt --all -- --check` and
`cargo clippy -p rns-net --all-targets -- -D warnings` also passed.

**Final disposition:** Structurally covered.

## Promotion Gates

- [x] Every upstream commit has a final disposition.
- [x] Focused regressions pass for every applicable behavior change.
- [x] Fixture provenance and byte stability are checked where applicable.
- [x] Exact-target live Python/Rust interop is not required for this logging-only change; the existing Python interop suite passes.
- [ ] Workspace tests, feature suites, formatting, and lint pass.
- [x] Required daily live dual-VPS manual gate is recorded honestly.
- [ ] Native documentation is updated for user-visible behavior.
- [ ] A final parity record is created from `PARITY-TEMPLATE.md`.

## Acceptance Record

- `2026-09-05`: Fresh drift inspection succeeded for both remotes and found the
  single commit inventoried above. The daily dual-VPS snapshots were healthy
  and complete. The extended live Backbone smoke passed announce and identity
  propagation, bidirectional packets, Channels, Resource boundary sizes,
  concurrent/repeated links, controlled impairment, and forced reconnect
  recovery. This operational result does not promote the new upstream commit.
- `2026-09-05`: Commit `4fad68c` mapped upstream commit
  `2f29b56e96bfa6fd3fc61518e4e5710ac8e92258` as structurally covered. The
  focused missing-attached-interface regression, the complete `rns-net` test
  suite, formatting, and warning-free host clippy all passed.
