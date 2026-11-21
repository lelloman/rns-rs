# Reticulum 1.6.1 rgit `606a1691` Upstream Audit

## Scope and Baseline

- audit date: `2026-11-21`
- previous accepted version: `1.6.1` (the security hot-patch past the signed
  tag, see [the 1.6.1 rgit-2 parity record](reticulum-1.6.1-rgit-2-parity.md))
- previous normative commit: `f55c0c6ea618ebae33e7d3ab2e37b200ce0b0d81`
- target version: `1.6.1` (unchanged; `RNS/_version.py` is not touched by the
  range)
- target tag or ref: rgit `master` tip, no tag
- target normative commit: `606a16911d64cdbcef8ea8babb85aa8fa2f78e79`
- target root tree: `bed2e6cabdfe543c670b346d2e9479ecd0dfc33f`
- target `RNS` tree: `4c52b05908b2484eecc2bd681f22f306207ca384`
- version assertion: `RNS.__version__ == "1.6.1"`
- audited range: `f55c0c6ea618ebae33e7d3ab2e37b200ce0b0d81..606a16911d64cdbcef8ea8babb85aa8fa2f78e79`
- commits in range: `1` (no merge commits; 1 file changed, +9/-3)
- repositories checked: rgit (normative) and the GitHub mirror, both fetched
  fresh by `scripts/check_upstream_drift.py`, first by the daily report on
  2026-11-21 07:43–07:44 UTC and again for this audit at 08:24 UTC (one
  attempt each). The GitHub tip is `f55c0c6e` (`at_baseline`); the rgit tip
  is `606a1691` (`ahead`), whose parent is `f55c0c6e`. The commit is not on
  the GitHub mirror.
- local branch and revision inspected: branch `upstream/606a1691` from
  `dev@71725ccd`; the configured upstream checkout stays at the accepted
  baseline `f55c0c6e` and the new object was read with `git show`

The target is one rgit-only commit past the accepted baseline, already named
as left for the next audit by
[the 1.6.1 rgit-2 audit](reticulum-1.6.1-rgit-2-audit.md). The daily report
opened this audit as `reticulum-next-audit.md`; the version (1.6.1) and the
promotion target (`606a1691`) are known, so it carries the qualified name.
This is a same-version advancement, so the records are named `-rgit-3` and
the earlier 1.6.1 records stay unchanged.

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

Every commit in the audited range appears exactly once, in ancestry order.
The 2026-11-21 diff review proposed `Needs port`; the row now has its final
disposition, recorded with its mapping commit and the evidence that ran.

| # | Upstream commit | Date | Subject | Final disposition | Local evidence |
|---:|---|---|---|---|---|
| 1 | `606a1691` | 2026-11-20 | Require explicit static_transport_identity configuration to allow discoverable interfaces on non-transport instances | Integrated | `cbac787e`; `discoverable_interfaces_without_transport_need_static_transport_identity` (fails before the change); upstream's log block and interface state cross-checked against a Python instance at `606a1691` |

## Per-Commit Analysis

The section answers the four questions of
[the parity workflow](README.md#per-commit-integration-procedure) from the
2026-11-21 review of the full diff and of the surrounding upstream
`RNS/Reticulum.py` (`_synthesize_interface`, `_attach_interface`,
`__apply_config`, `__init__`) and `RNS/Transport.py` (`ensure_identity`) at
`606a1691`, against `dev@71725ccd`.

### 1. `606a1691` — Require explicit static_transport_identity configuration to allow discoverable interfaces on non-transport instances

Full hash `606a16911d64cdbcef8ea8babb85aa8fa2f78e79`; parent
`f55c0c6ea618ebae33e7d3ab2e37b200ce0b0d81`; changes `RNS/Reticulum.py`
(+9/-3). No dependency on an unintegrated commit.

**Upstream change:** In `_synthesize_interface`, which sets up every
configured interface at startup and again when one is attached
(`_attach_interface`), reading `discoverable = yes` on an instance whose
`__transport_enabled` and `__static_transport_identity` are both false now
logs, at `LOG_WARNING`:

```text

The interface "<name>" was configured discoverable, but this instance has transport disabled
and is using an ephemeral transport identity. To make interfaces discoverable for non-transport
instances, you will have explicitly enable using static transport identity in the config file,
by adding "static_transport_identity = yes" to the [reticulum] section.

```

and sets `discoverable = False` for that interface. Everything under `if
discoverable:` is then skipped: `__discovery_enabled` is not set for it, its
discovery options are not read, and its mode is not moved to gateway or
access point. The interface itself is set up as usual with
`interface.discoverable = False`. The removed lines set
`__static_transport_identity = True` with the warning `Discoverable interface
was configured, enabling static transport identity on non-transport
instance`. That flag is read only by `Transport.ensure_identity`, which
`__init__` runs before it synthesizes the interfaces, so upstream's earlier
auto-enable did not change the transport identity at startup: it stayed
ephemeral while the interface announced itself. Now such an interface does
not announce at all.

**Rust applicability:** Applies, and rns-rs diverged before this commit too.
`effective_static_transport_identity` (`rns-net/src/node/identity.rs`) and
`NodeIdentities::new` (`rns-net/src/node/startup/driver_setup.rs`) turned a
discoverable interface on a non-transport instance into a static transport
identity before choosing it, so the stored identity really was used, with
the old warning. Discovery is decided per interface in two places that both
read `discoverable` from the interface's parameters:
`build_interface_configs` (`node/startup/config_steps.rs`, startup) and
`parse_managed_interface` (`node/interface_config.rs`, attach), each calling
`normalize_discovery_mode` and `extract_discovery_config`. Neither consulted
`enable_transport` or `static_transport_identity`. Interfaces built in code
(`NodeConfig::interfaces` with a `DiscoveryConfig`) have no upstream
counterpart, since upstream reads `discoverable` only from the config file.

**Local handling and evidence:** `cbac787e`.
`discoverable_on_instance` (`rns-net/src/node/interface_config.rs`) is the
check: for an interface whose `discoverable` is true on an instance with
neither `enable_transport` nor `static_transport_identity`, it logs
upstream's six lines at warning level (`log::warn!`: an empty line, the four
lines of text with the interface name, an empty line) and returns false.
`build_interface_configs` and `parse_managed_interface` call it right after
reading `discoverable`, so the false value then skips
`normalize_discovery_mode` (the interface keeps its configured mode) and
`extract_discovery_config` (no discovery config, so no discovery announces,
and the runtime `discoverable` key of a TCP server or Backbone listener
starts false). The startup path reads the two flags from the config; the
attach path reads them from `InterfaceManagementConfig`, which gains
`static_transport_identity` and replaces `parse_managed_interface`'s
`storage_dir` argument. `NodeIdentities::new` chooses the stored transport
identity only for `transport_enabled || static_transport_identity`;
`effective_static_transport_identity`, its warning and its unit test are
removed. `docs/configuration.md`, `docs/interface-discovery.md` and
`docs/protocol-spec.md` state the requirement and the change.

Test: `discoverable_interfaces_without_transport_need_static_transport_identity`
(`rns-net/src/node/tests.rs`) starts a node from a config file with a
discoverable TCP server enabled at startup and a second one attached through
interface management, for `enable_transport = no`, `enable_transport = no`
with `static_transport_identity = yes`, and `enable_transport = yes`. Only
in the first case are both interfaces up without discovery (runtime
`discoverable` false) and in full mode, the transport identity differs from
`storage/transport_identity`, and each interface's name is logged in the
exact six-line warning block, contiguous on the thread that set it up
(startup thread, driver thread for the attach). In the other two cases both
are discoverable in gateway mode, the stored identity is used and no
warning is logged; no case logs the removed warning. The log capture of the
RNode tests moved to `test_support` and now records the logging thread, as
the crate's tests can install a single logger. Before the change the test
fails at the first case (the stored transport identity was used); with the
gate removed from the attach path only, it fails on `Ephemeral Attached`
(runtime `discoverable` true).

Cross-check against upstream: a Python instance from a disposable worktree at
`606a1691` with the same TCP server config logs the same six lines at
`[Warning]`, reports `discoverable False`, mode 1 (full) and an ephemeral
transport identity, and with `static_transport_identity = yes` reports
`discoverable True`, mode 6 (gateway) and the stored identity.

`cargo test -p rns-net`: lib 1,608 passed, e2e 74 (1 ignored),
e2e_direct_connect 19, python_interop 6 (1 ignored, against the configured
checkout at `f55c0c6e`), the fixture and vector tests, 0 failures.
`cargo fmt --all --check` and `bash scripts/lint-host.sh` clean.

Notes: interfaces built in code (`NodeConfig::interfaces` with a
`DiscoveryConfig`) are not checked, as upstream has no such path; a node
configured that way without transport or `static_transport_identity` now
announces with an ephemeral transport identity, as upstream did before this
commit. The runtime `discoverable` key of TCP server and Backbone listeners
(an rns-rs extension) can still turn discovery on at runtime on such an
instance; it is not touched by this port. rns-rs logs
`Bringing up system interfaces...` and `System interfaces are ready` before
it builds the interface configs, so at startup the warning block follows
those lines instead of falling between them as upstream's does; that order
predates this commit and applies to every per-interface log line.
`rns-esp32` has no interface discovery and is unaffected.

**Final disposition:** Integrated.

## Integration Plan

The commit has its final disposition and one mapping commit; no
implementation work remains. The gates are recorded below.

## Promotion Gates

- [x] Every upstream commit has a final disposition.
- [x] Focused regressions pass for every applicable behavior change.
- [x] Fixture provenance and byte stability are checked where applicable.
- [x] Exact-target live Python/Rust interop passes.
- [x] Workspace tests, feature suites, formatting, and lint pass.
- [x] Required build, Docker, hardware, and manual gates are recorded honestly.
- [x] Native documentation is updated for user-visible behavior.
- [x] A final parity record is created from `PARITY-TEMPLATE.md`.

## Acceptance Record

Gates were run on 2026-11-21 on `upstream/606a1691` at `55f988d2`
(`dev@71725ccd` plus the audit opening, the mapping commit and the audit
update), against a disposable worktree of the Reticulum checkout at
`606a1691` (`HEAD:RNS` `4c52b059`, `import RNS` from it reports 1.6.1). The
configured checkout stayed at `f55c0c6e`.

- No conformance fixture is affected: the commit changes how an interface
  section is applied, nothing on the wire. The warning text, the interface
  state and the transport identity were compared with a Python instance at
  `606a1691` (see the per-commit analysis).
- Exact-target interop with CI's commands, `PYTHONPATH` and
  `RETICULUM_UPSTREAM_DIR` at the `606a1691` worktree: `python_interop`
  6 passed (1 ignored) under the default engine, `compact-threads` and
  `engine-parallel`; `utility_interop -- --ignored` 34 passed;
  `placeholders -- --ignored` 1 passed; `rnodeconf -- --ignored` 32 passed;
  `rns-git --lib` 231 passed (2 ignored). 0 failures.
- `cargo test --workspace`: 3,861 passed, 0 failed, 76 ignored (the known
  flaky direct-link test passed in this run).
- `cargo fmt --all --check` and `bash scripts/lint-host.sh` clean (lint run
  on the mapping commit's code; the later commits change only Markdown).
- `scripts/check_upstream_drift.py` (2026-11-21 08:50 UTC, both remotes
  fresh, one attempt each) reports drift from `f55c0c6e`: GitHub tip at the
  baseline, rgit tip `606a1691`, the one audited commit and nothing else.
  It names `reticulum-next-audit.md` as the active audit to create; this
  audit carries the qualified name instead, as the rgit-2 audit did, and
  the drift clears once `606a1691` is accepted.
- Not run: `--features rns-hooks` and the other feature suites besides the
  two interop engines, ARMv7 and ESP32 builds (`rns-esp32` has no
  interface discovery), Docker E2E, the dual-VPS Backbone smoke and
  hardware validation. CI's interop pin stays at the signed `1.6.1` tag
  commit `cff4d03f`, as it did for the earlier same-version rgit
  advancements, so the promotion pull request's CI does not exercise
  `606a1691`; the exact-target run above does.

The final record is [reticulum-1.6.1-rgit-3-parity.md](reticulum-1.6.1-rgit-3-parity.md).
