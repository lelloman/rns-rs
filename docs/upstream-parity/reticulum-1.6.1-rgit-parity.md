# Reticulum 1.6.1 rgit `cff4d03f` Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.6.1` (untagged rgit `884f109b`) |
| Previous normative commit | `884f109b2b821638c7addd456a52a2cd5bb8c5b1` |
| Accepted version | `1.6.1` (unchanged; `RNS/_version.py` is not touched by the range) |
| Normative tag or ref | The signed `1.6.1` release tag (tag object `bde4cd790a78b5ed285243fcc17f6439bb582288`), on the canonical `rgit/master` tip, equal to the GitHub mirror `master` |
| Normative commit | `cff4d03fdbd6bfb63b765280cd944756ac5cce8d` |
| Root tree | `4e52b7a767251df1d5ce74f32383e207565169f9` |
| `RNS` tree | `bcab6ab7ff72c4315aceda97267ea9af4fcccbc4` |
| Version assertion | `RNS.__version__ == "1.6.1"` |
| Audited range | `884f109b2b821638c7addd456a52a2cd5bb8c5b1..cff4d03fdbd6bfb63b765280cd944756ac5cce8d` (34 commits) |
| Acceptance date | `2026-11-20` |
| Detailed audit | [reticulum-1.6.1-rgit-audit.md](reticulum-1.6.1-rgit-audit.md) |

The previous acceptance took 1.6.1 at an untagged tip. Upstream then signed
the `1.6.1` tag on 2026-11-18 at `cff4d03f`, 34 commits later, without a
version bump, so this is a same-version rgit advancement and uses the
`-rgit` record names; the earlier 1.6.1 records stay unchanged. The tag is
the target and the tip of both remotes. Its SSH signature was not verified
here (no allowed signers file is configured). The range's last commit is
the 1.6.1 changelog, which identifies the tag target but was not taken as
evidence: the audit checks each of its bullets against the commits behind
it.

The `rnstatus` fixtures were regenerated with upstream's own `rnstatus` at
`f876ed8d`, `ef3e8086` and `e8b3b14b`, and the argparse table and `rnpath`
fixtures at `9568b704`, `1a71073c`, `b9903c53` and `1f7cd145`, as the
mapping commits landed. Rerun against `cff4d03f`, every generator that
asserts 1.6.1 reproduces the committed fixtures byte for byte.

## Upstream Commit Audit

Every commit has a final disposition and one non-empty mapping commit in
upstream ancestry order, carrying an `Upstream-Commit` trailer: 21
Integrated, 9 Structurally covered, 4 Non-runtime. Five further commits
without a trailer carry decisions and follow-ups: decisions 7 and 8, the
dynamic interface IFAC ordering, the `[filter]` logging, and the lint fix
found by the gates.

| Area | Upstream commits | Final handling |
|---|---|---|
| Announce rebroadcast | 1 (`da368e05`) | Integrated: an announce waiting for rebroadcast records the non-shared-medium interfaces a copy of it arrived on, and the rebroadcast leaves them out. `InterfaceInfo` gains `shared_medium`, set for upstream's shared-medium classes. |
| Interface discovery | 2 (`aecc1547`), 3 (`338df096`) | Integrated: under `autoconnect_policy = upstream` the auto-connect count is capped at 12, with upstream's warnings above 6 and 12, unless `autoconnect_discovered_interfaces_disable_caps` comes before the count in the file, as upstream reads it. The manual's sizing advice is in `docs/interface-discovery.md`. |
| Tunnel synthesis | 4 (`2b1a984c`), 5 (`25cce0a8`), 10 (`f876ed8d`) | Structurally covered for 4 and 5: the synthesis is always IFAC-masked and signed by the transport identity; a latent ordering for dynamic interfaces was closed separately. Integrated for 10: `rnstatus -T` shows the remote transport status, fixtures regenerated with upstream's `rnstatus`. |
| Links | 6 (`cc5d6dd0`), 7 (`12b2b8c0`), 8 (`4916017a`) | Structurally covered or non-runtime: every outbound link is AES-256-CBC. Decision 7 makes AES-256-CBC the only enabled mode, as upstream: AES-128-CBC and the reserved modes are refused by initiator and responder without a proof or a protocol violation, and a transport node that must lower the MTU of a request in a mode that is not enabled drops it as undecodable. |
| Known destinations | 9 (`48c77061`), 18 (`4a058544`) | Integrated: a split-mode client loads the instance's known destinations over RPC. `known_destinations` answers upstream's dict (decision 1), with the announce packet hash now kept; the native list is `known_destination_entries`. Commit 18 is structurally covered. |
| Process and listeners | 11 (`0123133e`), 33 (`52898683`) | Structurally covered: rns-rs's stamp workers are threads and its forks only exec, and every listener it binds already queues at least upstream's new backlog. |
| rngit | 12 (`05ac4bba`) | Integrated: `link_cost` (default 18.0) and `stamp_value` in `[rngit]` and `[pages]`, quantised as upstream; an invalid value is a startup error (decision 5). |
| Path responsiveness | 13 (`833f6cf2`), 14 (`d72cfdd7`), 15 (`5bd93ad9`), 16 (`70eb417d`), 17 (`8c73e203`) | Integrated or structurally covered: instance-local paths survive culling and are never rediscovered through links, a local client's path response marks its path responsive and answers only the requesting interface, and a replacement accepted only because a path is unresponsive is not rebroadcast. Decision 8 adds `unresponsive_path_recovery`. |
| Interface properties | 19 (`8e7dc8b7`) | Integrated: `lossless_medium()` with upstream's per-class values, unread as upstream (decision 6). |
| rnpath and path tables | 20 (`9568b704`), 24 (`1a71073c`), 25 (`b9903c53`), 26 (`1f7cd145`), 27 (`41260ea1`), 28 (`48ba76df`), 31 (`eb00622f`) | Integrated: upstream's display and filter options, `--capture`, the path `state` key and the ` (R)`/` (u)`/` (?)` marker, and the analysis mode as it is at each commit, ending at 31's `Not yet implemented` (decision 3); 28's guard never fires. |
| Destination types | 21 (`c90a5d58`), 22 (`3f55e9eb`), 23 (`f7b54ccc`) | Integrated or non-runtime: the `known_destination_types` and `flagged_destination_types` files name types in logs; `link_distribution` follows upstream's shape at each commit (decision 2). |
| Link traffic | 22 (`3f55e9eb`), 29 (`ef3e8086`), 30 (`e8b3b14b`), 32 (`01ffb98e`) | Integrated: relayed and own link traffic, counted as upstream counts it (a resend once), reported as `lrxb`, `ltxb`, `lrxs`, `ltxs` and in `rnstatus -l -t`. |
| Changelog | 34 (`cff4d03f`) | Non-runtime: each bullet was checked against its source commit across the six records since `cb126089`. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | No packet format changes. Link mode handling now matches upstream exactly; the AES-128 codec and vectors stay, as upstream keeps the mode defined. Announce stamps and the tunnel synthesis extension are unchanged from 1.6.1 at `884f109b`. |
| Transport and interfaces | `rns-core` transport suites (rebroadcast deduplication, unresponsive path decisions in both modes, instance-local path culling, link request MTU clamps) and `rns-net` driver, config and node suites; focused tests named per commit in the audit. |
| Links, channels, and resources | Refused link modes on both sides, local link traffic with resends counted once, requested resource parts reported as resent. |
| Utilities and APIs | `rnstatus` against upstream-generated fixtures (links totals, remote transport); `rnpath` option parsing, help and errors against the argparse fixtures, display against upstream's renderer; RPC `known_destinations`, `link_distribution`, path `state` and link traffic keys in upstream's shape. Documented in `docs/configuration.md`, `docs/cli-tools.md`, `docs/rnstatus.md`, `docs/rns-git.md`, `docs/getting-started.md`, `docs/protocol-spec.md` and `docs/interoperability.md`. |
| Live interop | Exact target `cff4d03f` (`import RNS` reports 1.6.1 from that worktree): `python_interop` 6/6 under each I/O model, `utility_interop` 34/34, `placeholders` 1/1, `rnodeconf` 32/32, `rns-git` lib 223 passed with its Python-peer test. |

## Acceptance Record

Gates were run on 2026-11-20 on `upstream/1.6.1-rgit` rebased onto
`dev@51ccbcc5` (`c3401435`); see the audit's acceptance record for commands
and the rebase.

| Gate | Result |
|---|---|
| Focused regression suites | Passed: the tests named in the audit, run with each mapping commit and again in the suites below. |
| Fixture regeneration/provenance | The `rnstatus` generator names `e8b3b14b`, where it last ran; the argparse generator pins version 1.6.1 only. Both, and the default config, example config and discovery record generators, reproduce the committed fixtures at `cff4d03f`. |
| Exact-target Python/Rust interop | Passed against a disposable worktree at `cff4d03f`, with CI's interop commands. |
| Workspace and feature suites | `cargo test --workspace` 3,846 passed; `--features rns-hooks` 3,913 passed; `rns-hooks` both backends 85; `e2e_hooks` under three engines and the rns-ctl built-in hook test 76; `rns-ctl --features tls` 139; compact engine 3,496; rns-esp32 host lane 68; Python tools 47. 0 failures. |
| Formatting and lint | `cargo fmt --check` and `bash scripts/lint-host.sh` clean, after one fix (a scoped allow for an `expect` that `dev`'s new lint rejected). |
| Release/cross builds | The five ARMv7 release build-smoke commands built. The ESP32 firmware, which the branch edits in `driver.rs` and `main.rs`, was not built (no ESP toolchain here); the host library lane passed but does not compile those files. |
| Docker E2E | Not run; left to the promotion pull request's CI. |
| Hardware/manual validation | The dual-VPS Backbone smoke was not run on this code. Physical hardware validation is not claimed. |

## Caveats and Deferred Validation

- `unresponsive_path_recovery` defaults to `native`, which keeps rns-rs's
  own recovery of unresponsive paths (decision 8): an already-heard
  announce through a new next hop does not replace the path, it is taken
  over the same or fewer hops and for an expired path, and the emission
  time compared is the newest random blob. `upstream` decides as
  Transport.py at `cff4d03f`, except that `prefer_shorter_path` still takes
  a strictly shorter announce and `max_paths_per_destination` above 1
  changes when a path is unresponsive. Documented in
  `docs/interoperability.md` and `docs/configuration.md`.
- In both modes rns-rs keeps distrusting announce emission times
  implausibly far in the future (`MAX_EMISSION_TIME_SKEW_SECS`), which
  upstream does not.
- `rnpath -t` prints ` (?)` for a path entry without `state` (from an older
  daemon) where upstream raises `KeyError`.
- Link modes now match upstream (only AES-256-CBC, AES-128 and reserved
  modes refused without a protocol violation). Two link request
  differences outside link modes remain: rns-rs counts a protocol violation
  for a request payload of the wrong size, which upstream drops silently,
  and upstream's MTU clamp fails on an interface without a hardware MTU,
  which rns-rs interfaces do not have.
- Rebroadcast deduplication does not see a copy from the same neighbour
  heard on a second interface while still in the verify queue, which
  collapses same-sender copies; with `prefer_shorter_path` a shorter copy
  replaces the waiting entry instead.
- The per-link `rx`/`tx` statistics still count resends and every packet
  type, as before; only the transport link totals follow upstream's
  counting. rns-rs's Direct Link signalling packets count as link traffic,
  and so does its resend of outstanding channel messages when a direct
  path falls back, counted once as upstream counts resends.
- `link_distribution` lists destinations in link table insertion order;
  the native `total` key is gone.
- rns-rs's own path destination cap can still evict an instance-local
  (hops 0) path when the table is full.
- Not run live: a Python client against an rns-rs instance with a relayed
  link (commit 22).
- rns-rs's `rnpath -A` exits 1 with `Could not connect to rnsd` when no
  shared instance runs, as every local mode does, where upstream starts its
  own instance.
- The ESP32 firmware edits (`shared_medium` on the LoRa interface, the new
  `TransportConfig` field) are unbuilt.
- The `1.6.1` tag signature is unverified, and the drift check used refs
  cached on 2026-11-20 05:56 UTC.
- The local upstream checkout (`/home/lelloman/Reticulum`) stays at
  `884f109b` until this lands; it moves to `cff4d03f` then, for the daily
  drift check.

## Promotion Result

Reticulum is accepted at `1.6.1`, normative commit
`cff4d03fdbd6bfb63b765280cd944756ac5cce8d`, the target of the signed `1.6.1`
tag and the canonical `rgit/master` tip. CI's 1.6.1 interop pin moves to
that commit. [UPSTREAM.md](../../UPSTREAM.md) records this baseline and links
this record; the detailed work record is
[reticulum-1.6.1-rgit-audit.md](reticulum-1.6.1-rgit-audit.md).
