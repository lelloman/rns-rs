# Reticulum 1.5.6 Upstream Audit

## Scope and Baseline

- audit date: `2026-10-02`
- previous accepted version: `1.5.5`
- previous normative commit: `e40191b3d193b46b7f2d8a44424a594cd758839b`
- target version: `1.5.6`
- target tag or ref: `2bae9ff0dca17ba39531d7f8c3078efd3a55ad62` (canonical `rgit/master`; the GitHub mirror has not caught up yet)
- target normative commit: `2bae9ff0dca17ba39531d7f8c3078efd3a55ad62`
- target root tree: `b6719f35e27d77d87e31c7ac9591a883948dcf83`
- target `RNS` tree: `def82bf5dd3c9686e798ca032927d2e625829b50`
- version assertion: `RNS.__version__ == "1.5.6"`
- audited range: `e40191b3d193b46b7f2d8a44424a594cd758839b..2bae9ff0dca17ba39531d7f8c3078efd3a55ad62`
- commits in range: `3`
- repositories checked: normative rgit remote and GitHub release mirror
- local branch and revision inspected: `dev@24c61bb`

The canonical rgit tip advanced three commits on 2026-10-02 while the GitHub
mirror remained at the previously accepted `e40191b3`. The first two commits
are upstream discovery runtime fixes and the third bumps
`RNS/_version.py` to `1.5.6`. The version is therefore known and this is
accepted as the `1.5.6` canonical development tip.

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
| 1 | `fca509ff0418e64be5478118628c581aafc019e0` | Ensure static transport identity is enabled when discoverable interfaces are present on non-transport instances | `Integrated` | `9f71159`; integrated behavior regression. |
| 2 | `d1a7e0c8a0989ebc3bd42d24e895c2f539b8161f` | Ensure only transport-enabled interfaces are autoconnected at discovery time | `Integrated` | `6dcfc47`; integrated behavior regression. |
| 3 | `2bae9ff0dca17ba39531d7f8c3078efd3a55ad62` | Updated version | `Non-runtime` | `45d4093`; source-only review. |

## Per-Commit Analysis

### 1. `fca509ff` — Ensure static transport identity is enabled when discoverable interfaces are present on non-transport instances

**Upstream change:** While loading interface configuration, when a discoverable
interface is present on an instance that is neither transport-enabled nor
already using a static transport identity, upstream enables the static transport
identity and logs a warning. The announced and management transport identity is
then derived from the persistent network identity rather than an ephemeral
per-run identity.

**Rust applicability:** `rns-net` builds the transport identity in
`start_with_queue_config` from `transport_enabled || static_transport_identity`.
Discoverable interfaces are carried on `InterfaceConfig::discovery`. The native
mapping is to consider an enabled discoverable interface a requirement for the
static transport identity on non-transport instances.

**Local handling and evidence:** Added
`effective_static_transport_identity(configured, transport_enabled, has_discoverable)`
and wired it into transport-identity construction with the upstream warning. A
focused regression pins the decision table, including that transport-enabled
instances keep their existing identity behavior.

**Final disposition:** `Integrated`

### 2. `d1a7e0c8` — Ensure only transport-enabled interfaces are autoconnected at discovery time

**Upstream change:** `InterfaceDiscovery.autoconnect_qualified` now returns
`False` for any discovery info whose `transport` field is absent or not `True`,
before the unverified-implementation override is consulted. Only transport
nodes are auto-connected to.

**Rust applicability:** `rns-net` implements the same qualification in
`runtime_config::autoconnect_qualified`, with the unverified override applied at
the call site.

**Local handling and evidence:** `autoconnect_qualified` now takes the
unverified-override flag, rejects `!iface.transport` first, and returns early for
the override only after that gate. The call site passes
`autoconnect_unverified_implementations`. A focused regression proves a
non-transport discovered interface is rejected even with the override enabled,
and accepted once it reports transport support.

**Final disposition:** `Integrated`

### 3. `2bae9ff0` — Updated version

**Upstream change:** Bumps `RNS/_version.py` from `1.5.5` to `1.5.6`.

**Rust applicability:** None. This is upstream Python package version metadata.

**Local handling and evidence:** No code change is required. Rust crate versions
are independently versioned from upstream `RNS/_version.py`; the accepted
`RNS` tree `def82bf5` is recorded as the `1.5.6` runtime baseline.

**Final disposition:** `Non-runtime`

## Mapping Verification

| Upstream commit | Local mapping commit |
|---|---|
| `fca509ff0418e64be5478118628c581aafc019e0` | `9f711592e56eec8e79bea4d8beee5ed6f3739b81` |
| `d1a7e0c8a0989ebc3bd42d24e895c2f539b8161f` | `6dcfc473b877209d06c9a4abe76d9bfdef99dfbd` |
| `2bae9ff0dca17ba39531d7f8c3078efd3a55ad62` | `45d4093f4eb1abb09292970a6c91435735620ef4` |

The mapping commits are non-empty, appear in the same ancestry order as the
upstream range, and each reviewed upstream hash appears exactly once in an
`Upstream-Commit` trailer.

## Integration Plan

Land one non-empty ordered mapping commit per upstream commit (`fca509ff`,
`d1a7e0c8`, `2bae9ff0`), then complete the same-version promotion gates and
create the `1.5.6` parity record.

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

2026-10-02: The canonical rgit tip advanced to
`2bae9ff0dca17ba39531d7f8c3078efd3a55ad62` (three commits past the accepted
`1.5.5` rgit tip `e40191b3`). GitHub still reported `e40191b3`. The three
commits are two discovery runtime fixes and the `1.5.6` version bump.

2026-10-02: Landed the ordered mapping commits `9f71159` (`fca509ff`),
`6dcfc47` (`d1a7e0c8`), and `45d4093` (`2bae9ff0`), each carrying a unique
`Upstream-Commit` trailer. `cargo test --workspace`, `cargo fmt --check`, and
`bash scripts/lint-host.sh` passed. Native-hook `rns-server` and `rns-ctl`
release builds passed (`0.3.1413-45d4093` / `0.4.1413-45d4093`), and the
impaired `--daily` dual-VPS Backbone smoke test passed against the deployed
`1.5.5` nodes.
