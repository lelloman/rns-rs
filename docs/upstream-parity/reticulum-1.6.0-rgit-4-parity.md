# Reticulum 1.6.0 rgit `134dc677` Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.6.0` (rgit `16621a78`) |
| Previous normative commit | `16621a78e35e2ba5156c72af7fe492458ba092d5` |
| Accepted version | `1.6.0` (unchanged; same-version rgit advancement) |
| Normative tag or ref | Canonical `rgit/master` tip, untagged; the GitHub mirror is at `3c4b271f`, contained in it |
| Normative commit | `134dc6777c0dd29404e61b36d4094f4e35b88b3e` |
| Root tree | `da30506871f4036968e0355447e3d0e79b39942d` |
| `RNS` tree | `aa29f48513fca2a1be8c9940bcee9ca7bbb074db` |
| Version assertion | `RNS.__version__ == "1.6.0"` |
| Audited range | `16621a78e35e2ba5156c72af7fe492458ba092d5..134dc6777c0dd29404e61b36d4094f4e35b88b3e` (15 commits) |
| Acceptance date | `2026-11-13` |
| Detailed audit | [reticulum-1.6.0-rgit-4-audit.md](reticulum-1.6.0-rgit-4-audit.md) |

This is the fourth same-version rgit advancement for 1.6.0, so it uses the
`-rgit-4` record filenames. The signed `1.6.0` release stays the commit CI
runs live interop against; this tip is verified from a local export.

## Upstream Commit Audit

| Area | Upstream commits | Final handling |
|---|---|---|
| Path pool and tunnels | 2 (`023849ed`) | Integrated: 180 s reverse table timeout, the unused path pool target that shrinks as used paths grow, and a 600 s reconnect window for tunnels whose interface went away. |
| Held announces | 3 (`3ac3236b`), 12 (`f96cef7e`) | Integrated: default `ic_max_held_announces` 64; announces dropped early once an interface's held announces are full; paths beyond the hop limiter culled. |
| Backbone listeners | 9 (`5f2dbc16`), 10 (`3c4b271f`) | Integrated: the `blocked_ips` file in the config directory, and `client_limit` (default 500; rns-rs's `max_connections` still takes precedence). |
| Diagnostics and statistics | 11 (`db67adea`), 13 (`9b6b724b`), 15 (`134dc677`) | Integrated: `rnpath -u` against Python daemons, `tunnel_id` in interface stats, filtered traffic counters and `rnstatus -F`. |
| Path table load filtering | 14 (`20e25a9f`) | Integrated: restored paths go through the destination type filter. |
| Structurally covered | 1, 4, 5, 7, 8 | Pinned by tests or documented invariants; see the audit. |
| Cleanup | 6 (`1855f992`) | Non-runtime. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | No wire change in the range; no pinned fixture changed. |
| Transport and interfaces | `rns-core` jobs, tunnel and persistence suites; `rns-net` driver, Backbone and management suites. |
| Utilities and APIs | RPC pickle and management `/status` carry `tunnel_id`, `frxb`, `ftxb`, `frxs`, `ftxs`; `rnstatus -F`; `rnpath -u`. Documented in `docs/configuration.md`, `docs/rnstatus.md` and `docs/rns-server-operator-runbook.md`. |
| Live interop | Exact target `134dc677`: `python_interop` 4/4, `utility_interop` 24/24, including Python `rnstatus -F -t -s frx` and `rnpath -t -u` against a Rust daemon. |

## Acceptance Record

Gates were run on 2026-11-13 on the mapping commits, and again after
rebasing them onto `dev` `eee13176`; see the audit's acceptance record.

| Gate | Result |
|---|---|
| Focused regression suites | Passed: the tests named in the audit. |
| Fixture regeneration/provenance | Not applicable; no pinned fixture changed. |
| Exact-target Python/Rust interop | Passed against a disposable export of `134dc677`, and against `16621a78`, 1.5.4 and 1.4.2. |
| Workspace and feature suites | `cargo test --workspace` 3,316 passed (3,330 after the rebase onto `dev`); `--features rns-hooks` 3,382 passed; the `compact-threads-*` suite 1,455 passed. 0 failures. |
| Formatting and lint | Clean. |
| Release/cross builds | Not run locally; ARMv7 delegated to CI. |
| Docker E2E | Delegated to the promotion pull request's CI. |
| Hardware/manual validation | The dual-VPS Backbone smoke was not run. Physical hardware validation is not claimed. |

## Caveats and Deferred Validation

- A Backbone listener without `max_connections` now accepts at most 500
  clients (upstream's `client_limit` default). Both VPS listeners set
  `max_connections = 512`, so they are unaffected.
- An interface with `ic_max_held_announces = 0` now accepts no announces, as
  upstream; in `[reticulum]` 0 still keeps the default.
- Filtered frames leave the received bytes and packets. Frames a `PreIngress`
  hook drops count as filtered (rns-rs only). A queued signature check that
  fails moves the announce's size when it completes. As upstream, nothing is
  ever counted as filtered on transmit.
- rns-rs `rnstatus` still lacks upstream's `rxs` and `txs` sort keys, which
  predate this range.
- Both VPS nodes still run their current builds; deployment is a separate
  operator step.

## Promotion Result

Reticulum is accepted at `1.6.0`, normative commit
`134dc6777c0dd29404e61b36d4094f4e35b88b3e`, as a same-version canonical
`rgit/master` advancement. [UPSTREAM.md](../../UPSTREAM.md) records this
baseline and links this record; the detailed work record is
[reticulum-1.6.0-rgit-4-audit.md](reticulum-1.6.0-rgit-4-audit.md).
