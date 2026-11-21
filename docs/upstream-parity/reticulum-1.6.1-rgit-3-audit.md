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
The disposition below is the one proposed by the 2026-11-21 diff review; the
local evidence column is filled in when the mapping commit lands.

| # | Upstream commit | Date | Subject | Proposed disposition | Local evidence |
|---:|---|---|---|---|---|
| 1 | `606a1691` | 2026-11-20 | Require explicit static_transport_identity configuration to allow discoverable interfaces on non-transport instances | Needs port | pending |

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

**Planned handling:** One check shared by both paths, placed where upstream
places it (right after `discoverable` is read, before the mode is
normalized and the discovery options are read), logging upstream's six
lines at warning level and returning false; the startup path takes
`enable_transport` and `static_transport_identity` from the config, the
attach path from the running instance (`InterfaceManagementConfig`), as
upstream reads its class flags rather than the reread file. The transport
identity is chosen from `enable_transport` and `static_transport_identity`
alone, and `effective_static_transport_identity` with its warning goes.
Its unit test, which asserted the old behaviour, is replaced by a node-level
regression over startup and attach for the three cases.
`docs/configuration.md`, `docs/interface-discovery.md` and
`docs/protocol-spec.md` describe the requirement.

**Proposed disposition:** Needs port.

## Integration Plan

1. `606a1691`: the check, the identity choice, the regression and the
   documentation, in one mapping commit.
2. Record the final disposition, local hash and test results here, run the
   promotion gates, and write the parity record.

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

Not yet run.
