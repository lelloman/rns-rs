# Reticulum 1.5.7 Upstream Audit

## Scope and Baseline

- audit date: `2026-10-06`
- previous accepted version: `1.5.6`
- previous normative commit: `49ae71e06cadf5d846849661578a8ad9fcede443`
- target version: `1.5.7`
- target tag or ref: `rgit` tip `a29bfb51c468945c96a1ee22cae0114e993e2391` (no signed `1.5.7` tag is published yet; nearest tag is `1.5.5`, `describe` reports `1.5.5-11-ga29bfb51`)
- target normative commit: `a29bfb51c468945c96a1ee22cae0114e993e2391`
- target root tree: `24d4c393de9fd57b933836cea68891fd953ab060`
- target `RNS` tree: `c8cde8d039e59ad1d60ec9ac28ac180b0ab5499c`
- version assertion: `RNS.__version__ == "1.5.7"` (observed in `RNS/_version.py` at the target commit)
- audited range: `49ae71e06cadf5d846849661578a8ad9fcede443..a29bfb51c468945c96a1ee22cae0114e993e2391`
- commits in range: `5`
- repositories checked: rgit normative (`rns://7649a50d84610232d1416b41d2896aff/reticulum/reticulum`) and GitHub mirror (`git@github.com:markqvist/Reticulum.git`)
- local branch and revision inspected: `dev@8841f43` (accepted upstream checkout stays at `49ae71e0`; newer objects read with `git show`/`git log`)

The five commits are all on the rgit normative remote. The GitHub mirror tip
(`e40191b3d193b46b7f2d8a44424a594cd758839b`) is still an ancestor of the accepted
baseline and is allowed to lag. Both remote refreshes succeeded during this
collection (`2026-10-06T06:59:41Z` GitHub, `2026-10-06T06:59:50Z` rgit), so the
comparison is fresh.

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

Every commit in the audited range must appear exactly once.

| # | Upstream commit | Subject | Final disposition | Local evidence |
|---:|---|---|---|---|
| 1 | `f0875ac44ee13d82160c1a0c43f2480391b8d3dc` | Fixed EC TX stall state deadlock on BackboneInterface initiator instances | Structurally covered | Fresh `TransmitBuffer`/`EgressController` per writer at `rns-net/src/interface/backbone.rs:1781` (client reconnect) and `:995` (server accept); writer dropped on teardown. Mapping commit pending. |
| 2 | `cadee01f9ee3de96e7f10b936176a4dfea7965b7` | Updated egress control test | Non-runtime | Upstream Python test for the persistent-instance reset; Rust has no persistent egress instance. Native coverage already exists in `transmit_buffer.rs` tests. Mapping commit pending. |
| 3 | `2578750bf7df7a598fc77e49212c79a2061e50e3` | Updated version | Non-runtime | `RNS/_version.py` `1.5.6` -> `1.5.7`. Mapping commit pending. |
| 4 | `318b78b416ee909f56ba83999e83c03f805747e4` | Updated changelog | Non-runtime | `Changelog.md` release note. Mapping commit pending. |
| 5 | `a29bfb51c468945c96a1ee22cae0114e993e2391` | Updated documentation | Non-runtime | Generated `docs/manual/` HTML/asset rebuild only. Mapping commit pending. |

## Per-Commit Analysis

### 1. `f0875ac4` — Fixed EC TX stall state deadlock on BackboneInterface initiator instances

**Upstream change:** At egress-control teardown, the persistent Python
`BackboneInterface` instance kept stale egress state (`_dp_ec_prev_sent`,
`_dp_ec_zero_ticks`, `_dp_ec_last_drain`, `tx_stalled`) and its old
`transmit_buffer`. Initiator interface instances are re-registered on the same
instance after reconnection, so the stale dead-drain state could immediately
re-trigger teardown (`_dp_ec_evaluate` returned `True` again on the next tick).
The fix adds `_dp_ec_reset`, which clears the counters, refreshes the drain
timestamp, installs a fresh `TransmitBuffer`, and clears `tx_stalled`, and it is
called at the escalation branch before `interface.receive(b"")`.

**Rust applicability:** rns-rs does not keep egress state on a persistent
interface instance. The `EgressController` and `TransmitBuffer` live on the
writer (`BackboneWriter`/`BackboneClientWriter`), and every new connection
constructs a fresh writer: server accept at `rns-net/src/interface/backbone.rs:995`
and client reconnect at `:1781`. A write-stall teardown
(`disconnect_for_write_stall`, `:499`) shuts the socket down and the writer is
dropped with the connection; reconnection installs a brand-new writer, so no
stale drain/zero-tick state or buffered frames can survive into the next
connection. The failure mode the upstream patch repairs cannot be expressed in
this design.

**Local handling and evidence:** Structural invariant recorded above. Native
egress lifecycle tests already exercise stall gating, release, empty reset and
dead-peer escalation in
`rns-net/src/interface/transmit_buffer.rs:474-526`; the reconnect path that
discards the writer is covered by the Backbone reconnect paths. A non-empty
mapping commit documenting this invariant is still required by the parity
procedure.

**Final disposition:** Structurally covered.

### 2. `cadee01f` — Updated egress control test

**Upstream change:** Adds `test_12_ec_state_reset_on_teardown` to
`tests/egress.py`, asserting that after `_dp_ec_evaluate` escalates and tears
down an interface, the persisted instance has reset `_dp_ec_prev_sent`,
`_dp_ec_zero_ticks`, `_dp_ec_last_drain`, `tx_stalled`, and a replaced empty
`transmit_buffer`, and that a simulated reconnection tick does not re-escalate.

**Rust applicability:** This test verifies the Python persistent-instance
invariant introduced by commit 1. rns-rs has no equivalent persistent instance;
the tested state cannot persist across reconnection because the writer owning it
is dropped and recreated.

**Local handling and evidence:** Upstream-only Python test. The relevant
native invariants (three zero-drain ticks escalate; fresh state is unstalled)
are covered by `transmit_buffer.rs` unit tests. No runtime change required. A
non-empty mapping commit is still required by the parity procedure.

**Final disposition:** Non-runtime.

### 3. `2578750b` — Updated version

**Upstream change:** `RNS/_version.py` bumped `1.5.6` -> `1.5.7`.

**Rust applicability:** Upstream packaging metadata only.

**Local handling and evidence:** Non-runtime metadata; no Rust version surface
changes until the baseline is promoted. Mapping commit pending.

**Final disposition:** Non-runtime.

### 4. `318b78b4` — Updated changelog

**Upstream change:** Prepends the `RNS 1.5.7` release section and keeps the
`1.5.6` entry, describing the egress-control deadlock fix.

**Rust applicability:** Documentation only; the changelog must not be treated as
acceptance evidence.

**Local handling and evidence:** Non-runtime. Mapping commit pending.

**Final disposition:** Non-runtime.

### 5. `a29bfb51` — Updated documentation

**Upstream change:** Rebuilds the generated `docs/manual/` Sphinx HTML and
assets (`.buildinfo`, `documentation_options.js`, HTML pages, `objects.inv`).

**Rust applicability:** Generated upstream documentation artifacts only.

**Local handling and evidence:** Non-runtime. Mapping commit pending.

**Final disposition:** Non-runtime.

## Integration Plan

No runtime behavior change is outstanding: commit 1 is structurally covered and
commits 2-5 are non-runtime. The remaining parity work is procedural:

1. Land one non-empty rns-rs mapping commit per upstream commit according to
   [README.md](README.md), each carrying the
   `Upstream-Commit: <40-character hash>` trailer (commit 1 documenting the
   writer-recreation invariant; commit 2 recording the upstream-only test and
   native coverage; commits 3-5 recording non-runtime handling).
2. Re-run `scripts/check_upstream_drift.py` after each mapping commit.
3. Complete the promotion gates below, then rename this file to
   `reticulum-1.5.7-audit.md` once the signed `1.5.7` tag or final promotion
   target is available.

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

- `2026-10-09`: Both daily VPS snapshots were healthy and complete, with one
  capture per host, all public interfaces up (EU 36/36, US 26/26), no failed
  rolling traffic queries, and zero idle timeout events over 24 hours. The
  impaired dual-VPS `--daily` smoke passed all four Resource sizes through
  1 MiB, concurrent links, and forced reconnect recovery on the same
  collection. The GitHub refresh succeeded (`06:11:17Z`), but four rgit fetch
  attempts timed out establishing the `git-remote-rns` link. The June-21
  installed binary was rebuilt from the current tree and rerun at `08:55Z`:
  the link established and both fetches went green, confirming the five-commit
  inventory and both remote tips as current. Both VPS installations remain at
  `62385c8`, behind `origin/master` (`ee3e7c4`) and `origin/dev` (`9e758f4`).
  Mapping commits and promotion acceptance remain pending.

- `2026-10-07`: Both daily VPS snapshots were healthy and complete, with one
  capture per host, all public interfaces up (EU 39/39, US 25/25), no failed
  rolling traffic queries, and zero idle timeout or provider bridge drop and
  disconnect events over 24 hours. The impaired dual-VPS `--daily` smoke
  passed all four Resource sizes through 1 MiB, concurrent links, and forced
  reconnect recovery using the freshly built `35d9fdf` working tree, including
  the existing uncommitted Resource sender change. Both upstream refreshes
  succeeded (`07:27:10Z` GitHub, `07:27:17Z` rgit); tips and the five-commit
  inventory are unchanged from October 6. Both VPS installations remain at
  `62385c8`, behind `origin/master` (`ee3e7c4`) and `origin/dev` (`9e758f4`).
  This records daily operational evidence; mapping commits and promotion
  acceptance remain pending.

- `2026-10-06`: Daily VPS collection created this active audit. Drift check
  reported 5 unintegrated commits on the rgit tip `a29bfb51`; both remote
  refreshes were fresh. Code review found the only runtime change
  (`f0875ac4`) structurally covered by per-connection writer recreation. Daily
  impaired dual-VPS Backbone smoke passed on the same collection. No
  integration mapping commits have landed yet; no `UPSTREAM.md` promotion was
  made.
