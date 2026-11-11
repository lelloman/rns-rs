# Reticulum 1.6.0 rgit `16621a78` Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.6.0` (rgit `c5d205ff`) |
| Previous normative commit | `c5d205ffea16ef4519150745edf644dd03e48e5f` |
| Accepted version | `1.6.0` (unchanged; same-version rgit advancement) |
| Normative tag or ref | Canonical `rgit/master` tip, untagged; the GitHub mirror agrees with rgit |
| Normative commit | `16621a78e35e2ba5156c72af7fe492458ba092d5` |
| Root tree | `6c5840333260cb243b6f370a406c0f8400140763` |
| `RNS` tree | `f8979745d08eef46ce1c494b721cb67e5302f36f` |
| Version assertion | `RNS.__version__ == "1.6.0"` |
| Audited range | `c5d205ffea16ef4519150745edf644dd03e48e5f..16621a78e35e2ba5156c72af7fe492458ba092d5` (4 commits) |
| Acceptance date | `2026-11-11` |
| Detailed audit | [reticulum-1.6.0-rgit-3-audit.md](reticulum-1.6.0-rgit-3-audit.md) |

This is the third same-version rgit advancement for 1.6.0, so it uses the
`-rgit-3` record filenames. The signed `1.6.0` release stays the commit CI
runs live interop against; this tip is verified from a local export.

## Upstream Commit Audit

| Area | Upstream commits | Final handling |
|---|---|---|
| Memory-hard workblock expansion | 1 (`2c7cf827`) | Deferred: `_stamp_workblock_future` has no caller at the target, and the workblock every stamp uses is unchanged. It is ported when upstream uses it. |
| Discovery stamp validation | 2 (`aaf08e61`) | Integrated: discovery stamps are accepted against the unexpanded workblock or, failing that, the expanded one, with the value taken from the one they are valid against. |
| Stamp worker limits | 4 (`16621a78`) | Integrated: `[stamps] max_workers` and `worker_niceness`, upstream's worker count, and stamp search threads reniced (default 16) on Linux. |
| Cleanup | 3 (`132ec70f`) | Non-runtime. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | Discovery stamps against both workblocks; no pinned fixture changed. |
| Transport and interfaces | `rns-net` driver and discovery suites; the dual-VPS Backbone smoke on the promoted binary. |
| Utilities and APIs | `[stamps]` parsing of the two new keys; documented in `docs/configuration.md`. |
| Live interop | Exact target `16621a78`: `python_interop` 4/4, `utility_interop` 21/21. |

## Acceptance Record

Gates were run on 2026-11-11 on `b81a1098`; see the audit's acceptance
record.

| Gate | Result |
|---|---|
| Focused regression suites | Passed: the tests named in the audit. |
| Fixture regeneration/provenance | Not applicable; no pinned fixture changed. |
| Exact-target Python/Rust interop | Passed against a disposable export of `16621a78`. |
| Workspace and feature suites | `cargo test --workspace` 3,230 passed; `--features rns-hooks` 3,296 passed; the `compact-threads-*` suite passed. 0 failures. |
| Formatting and lint | Clean. |
| Release/cross builds | Host native-hook build `rns-server 0.6.1912-b81a1098`; ARMv7 delegated to CI. |
| Docker E2E | Delegated to the promotion pull request's CI. |
| Hardware/manual validation | The impaired dual-VPS `--daily` Backbone smoke passed (55 checks, 0 failures). Physical hardware validation is not claimed. |

## Caveats and Deferred Validation

- `_stamp_workblock_future` is not ported. When upstream switches a stamp
  type to it, rns-rs needs the new expansion with Python-generated vectors.
- `max_workers` and `worker_niceness` apply to the parallel engine; the
  compact engine grinds on the calling thread, as upstream's single-process
  job does.
- `bootstrap_only` remains open; it lands with autoconnect (gap plan phase 3).
- Both VPS nodes still run `a27e8718`; deployment is a separate operator step.

## Promotion Result

Reticulum is accepted at `1.6.0`, normative commit
`16621a78e35e2ba5156c72af7fe492458ba092d5`, as a same-version canonical
`rgit/master` advancement. [UPSTREAM.md](../../UPSTREAM.md) records this
baseline and links this record; the detailed work record is
[reticulum-1.6.0-rgit-3-audit.md](reticulum-1.6.0-rgit-3-audit.md).
