# Reticulum 1.6.1 rgit `606a1691` Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.6.1` (the security hot-patch `f55c0c6e`, past the signed tag at `cff4d03f`) |
| Previous normative commit | `f55c0c6ea618ebae33e7d3ab2e37b200ce0b0d81` |
| Accepted version | `1.6.1` (unchanged; `RNS/_version.py` is not touched by the range) |
| Normative tag or ref | rgit `master` tip, untagged; not on the GitHub mirror when accepted |
| Normative commit | `606a16911d64cdbcef8ea8babb85aa8fa2f78e79` |
| Root tree | `bed2e6cabdfe543c670b346d2e9479ecd0dfc33f` |
| `RNS` tree | `4c52b05908b2484eecc2bd681f22f306207ca384` |
| Version assertion | `RNS.__version__ == "1.6.1"` |
| Audited range | `f55c0c6ea618ebae33e7d3ab2e37b200ce0b0d81..606a16911d64cdbcef8ea8babb85aa8fa2f78e79` (1 commit) |
| Acceptance date | `2026-11-21` |
| Detailed audit | [reticulum-1.6.1-rgit-3-audit.md](reticulum-1.6.1-rgit-3-audit.md) |

The range is one rgit-only commit on top of the 1.6.1 security hot-patch,
without a version bump or a tag, so this is a same-version rgit
advancement and uses the `-rgit-3` record names; the earlier 1.6.1 records
stay unchanged. The GitHub mirror's tip was still `f55c0c6e`. No fixture
is involved.

## Upstream Commit Audit

The commit has a final disposition and one non-empty mapping commit
carrying an `Upstream-Commit` trailer: 1 Integrated.

| Area | Upstream commits | Final handling |
|---|---|---|
| Interface discovery on instances without transport | 1 (`606a1691`) | Integrated: an interface configured `discoverable` on an instance with neither `enable_transport` nor `static_transport_identity` is set up without discovery and keeps its configured mode, at startup and when attached, and upstream's six-line warning naming it is logged at warning level. A discoverable interface no longer turns on the static transport identity. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | Unchanged; the commit has no wire or cryptographic change. |
| Transport and interfaces | `discoverable_interfaces_without_transport_need_static_transport_identity` over startup and attach for the three configurations (fails before the change); interface state, mode, transport identity and warning text compared with a Python instance at `606a1691`. |
| Links, channels, and resources | Unchanged. |
| Utilities and APIs | Configuration semantics only; documented in `docs/configuration.md`, `docs/interface-discovery.md` and `docs/protocol-spec.md`. |
| Live interop | Exact target `606a1691` (`import RNS` reports 1.6.1 from that worktree): `python_interop` 6 passed under each of the three engines, `utility_interop` 34, `placeholders` 1, `rnodeconf` 32, `rns-git` lib 231. |

## Acceptance Record

Gates were run on 2026-11-21 on `upstream/606a1691` at `55f988d2`; see the
audit's acceptance record for details.

| Gate | Result |
|---|---|
| Focused regression suites | Passed: the test named in the audit, run with the mapping commit and again in the suites below. It fails before the change and with the attach-path check removed. |
| Fixture regeneration/provenance | Not applicable: no fixture covers interface configuration and the range changes no wire format. |
| Exact-target Python/Rust interop | Passed against a disposable worktree at `606a1691`, with CI's interop commands. |
| Workspace and feature suites | `cargo test --workspace` 3,861 passed, 0 failed; `python_interop` also under `compact-threads` and `engine-parallel`. Other feature suites were not run. |
| Formatting and lint | `cargo fmt --all --check` and `bash scripts/lint-host.sh` clean. |
| Release/cross builds | Not run; `rns-esp32` has no interface discovery and the ARMv7 build is not affected by configuration semantics. |
| Docker E2E | Not run; left to the promotion pull request's CI. |
| Hardware/manual validation | Not claimed; the dual-VPS Backbone smoke was not run on this code. |

## Caveats and Deferred Validation

- Operators: a node with transport disabled and a `discoverable = yes`
  interface but no `static_transport_identity = yes` stops announcing that
  interface for discovery, keeps the interface's configured mode instead of
  moving it to gateway or access point, and now uses an ephemeral transport
  identity; rns-rs used the stored identity in that case before. Adding
  `static_transport_identity = yes` to `[reticulum]` restores discovery
  with the stored identity.
- Interfaces built in code (`NodeConfig::interfaces` with a discovery
  config) and the runtime `discoverable` key of TCP server and Backbone
  listeners, both rns-rs extensions without an upstream counterpart, are
  not checked.
- At startup rns-rs logs `Bringing up system interfaces...` and `System
  interfaces are ready` before it builds the interface configs, so the
  warning block follows them; that order predates this range.
- CI's 1.6.1 interop pin stays at the signed tag commit `cff4d03f`; only the
  manual exact-target run covers `606a1691`.
- The local upstream checkout (`/home/lelloman/Reticulum`) stays at
  `f55c0c6e` until this lands; it moves to `606a1691` then, for the daily
  drift check.

## Promotion Result

Reticulum is accepted at `1.6.1`, normative commit
`606a16911d64cdbcef8ea8babb85aa8fa2f78e79`, the canonical `rgit/master`
tip. [UPSTREAM.md](../../UPSTREAM.md) records this baseline and links this
record; the detailed work record is
[reticulum-1.6.1-rgit-3-audit.md](reticulum-1.6.1-rgit-3-audit.md).
