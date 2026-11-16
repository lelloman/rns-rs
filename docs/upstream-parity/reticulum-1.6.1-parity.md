# Reticulum 1.6.1 Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.6.0` (rgit `c850cdac`) |
| Previous normative commit | `c850cdac6c8bd5422af045652216ba451e98aa33` |
| Accepted version | `1.6.1` (version bumped in `fd36a972`) |
| Normative tag or ref | Canonical `rgit/master` tip, equal to the GitHub mirror `master`; untagged, no `1.6.1` tag on either remote |
| Normative commit | `884f109b2b821638c7addd456a52a2cd5bb8c5b1` |
| Root tree | `353dfad65ab6f5db19a15962923a39586db82207` |
| `RNS` tree | `00ef77fcbaadad0ce252306c26bebaa301b77366` |
| Version assertion | `RNS.__version__ == "1.6.1"` |
| Audited range | `c850cdac6c8bd5422af045652216ba451e98aa33..884f109b2b821638c7addd456a52a2cd5bb8c5b1` (17 commits) |
| Acceptance date | `2026-11-16` |
| Detailed audit | [reticulum-1.6.1-audit.md](reticulum-1.6.1-audit.md) |

Upstream bumped the version to 1.6.1 without tagging it. The target is the
untagged tip, which both remotes agree on; CI runs live interop against it
from the GitHub mirror alongside the signed 1.6.0 release. When upstream tags
1.6.1, a tag on `884f109b` needs only the CI pin updated, and a tag on a later
commit is audited as a same-version rgit advancement.

## Upstream Commit Audit

| Area | Upstream commits | Final handling |
|---|---|---|
| Announce ingress | 1 (`29dc449a`), 2 (`85d36979`), 4 (`096e6726`) | Integrated: a held announce's frame counts as filtered and again on release, as received or filtered; announces that cannot update a known path are prefiltered before holding and culled from the held queue; an announce payload too short to hold one is a protocol violation. Path responses, waiting path requests and rebroadcasts are exempt. |
| Validation cache | 3 (`a450be5d`) | Structurally covered: rns-rs's announce signature cache already holds 2,000 entries for 600 s, configurable. |
| Tunnel synthesis | 5 (`f361a354`), 6 (`ad6c709e`), 13 (`13b98a6b`), 14 (`b7a93b9b`) | Integrated: a dialing interface synthesizes before it is reported up; a second synthesis, an established tunnel, or one too short or over the MDU is a protocol violation; the synthesis carries a signed extension with implementation, version, transport status and stamp costs, answered by a reverse synthesis. Stats, RPC and `rnstatus -T` report the remote transport (`Rem.Tr.ID`, `Rem.Vers.`, `Rem.Csts.`); the `tunnels` fixture was regenerated with upstream's `rnstatus`. |
| Shared instance exit | 7 (`29ce7ca5`), 12 (`e35bd08f`) | Integrated: withdrawing a client's destination types is bounded at 500 ms. Teardown only from the main process is structurally covered: rns-rs forks no instances. |
| Filters and limits | 8 (`e96c81c3`), 9 (`bb63dd44`) | Integrated: `[filter]` types take `<hex>` name hashes; interfaces take `hop_limiter`, inherited by spawned TCP, Backbone, I2P and Weave interfaces and checked before the transport limiter. |
| Transport insertion room | 10 (`d077d1ab`), 11 (`715707b1`) | Integrated: a HEADER_1 announce must leave 16 bytes for a transport id when packed, and one received without that room is a protocol violation. |
| Stamping by default | 15 (`51fa8413`) | Integrated: announces and path requests a node emits are stamped by default. The config file only enables, as upstream; the runtime keys turn emission off. A node without a stamp store announces unstamped instead of failing. |
| Version | 16 (`fd36a972`) | Integrated: the fixture generators pin 1.6.1 and reproduce the existing fixtures. rns-rs reports its own version. |
| Discovery | 17 (`884f109b`) | Integrated: a node discovering interfaces registers `rnstransport.discovery.interface` as wanted, so `required_only` keeps discovery announces. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | Two wire changes: the tunnel synthesis extension, interoperating with Python 1.6.1 in both directions, and the 16-byte transport insertion room for HEADER_1 announces. Stamps are the 1.6.0 format, now emitted by default. |
| Transport and interfaces | `rns-core` transport, ingress control and codec property suites; `rns-net` driver, interface, shared client, config and node suites (focused tests named in the audit). |
| Utilities and APIs | `rnstatus -T` remote transport lines byte for byte against upstream's output; RPC `rem_*` keys; `[filter]` hash types; per-interface `hop_limiter`; stamp runtime keys with the new defaults. Documented in `docs/rnstatus.md`, `docs/configuration.md` and `docs/engines.md`. |
| Live interop | Exact target `884f109b`: `python_interop` 6/6 and `utility_interop` 24/24 ignored-gated. The same suites pass against `c850cdac` (1.6.0), 1.5.4 and 1.4.2. |

## Acceptance Record

Gates were run on 2026-11-16 on `upstream-1.6.1@0ac3ab7f`, rebased onto
`dev@17e0fec0`; see the audit's acceptance record.

| Gate | Result |
|---|---|
| Focused regression suites | Passed: the tests named in the audit. |
| Fixture regeneration/provenance | `rnstatus` `tunnels` regenerated with upstream's `rnstatus` at `884f109b`; the config, argparse and discovery fixtures regenerate unchanged at 1.6.1. |
| Exact-target Python/Rust interop | Passed against a disposable export of `884f109b`, and against `c850cdac`, 1.5.4 and 1.4.2. |
| Workspace and feature suites | `cargo test --workspace` 3,379 passed; `--features rns-hooks` 3,446 passed; the `compact-threads-*` suite 1,595 passed. 0 failures. |
| Formatting and lint | Clean. |
| Release/cross builds | Not run locally; ARMv7 delegated to CI. |
| Docker E2E | Delegated to the promotion pull request's CI. |
| Hardware/manual validation | The dual-VPS Backbone smoke was not run on this code. Physical hardware validation is not claimed. |

## Caveats and Deferred Validation

- Stamping by default costs CPU. A node grinds a 25-bit stamp for each of
  its destinations the first time it announces them (seconds to minutes),
  and a transport node grinds one per egress interface for every unstamped
  path request it forwards, as upstream does. The deployed VPS nodes will do
  this once they run this code; `global.stamp_destinations` and
  `global.stamp_path_requests` turn it off at runtime.
- rns-rs shared instance clients have no stamp store and announce unstamped;
  upstream clients stamp their own. Unstamped announces are accepted until
  enforcement, which upstream plans for 1.6.2.
- Reticulum before 1.6.1 ignores a tunnel synthesis with an extension, so it
  records no tunnel from an rns-rs client any more, as from a 1.6.1 Python
  client.
- A dialing interface clears the remote transport report on reconnect;
  upstream keeps the previous one until the next arrives.
- A Python TCP client connecting to a Rust server is not exercised by the
  interop suite; the reverse synthesis is tested Rust to Rust and Python
  server to Rust client.
- Both VPS nodes still run their current builds; deployment is a separate
  operator step.

## Promotion Result

Reticulum is accepted at `1.6.1`, normative commit
`884f109b2b821638c7addd456a52a2cd5bb8c5b1`, the untagged canonical
`rgit/master` tip. [UPSTREAM.md](../../UPSTREAM.md) records this baseline and
links this record; the detailed work record is
[reticulum-1.6.1-audit.md](reticulum-1.6.1-audit.md).
