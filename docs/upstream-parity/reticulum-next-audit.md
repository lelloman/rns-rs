# Reticulum Next Upstream Audit

## Scope and Baseline

- audit date: `2026-10-28`
- previous accepted version: `1.6.0`
- previous normative commit: `9a01a20ce66c4146dd8f8d31f18c19fe7600739d`
- target version: pending (upstream `RNS.__version__` is still `1.6.0`)
- target tag or ref: `rgit:master` tip `ca6451a02aead88734e47193dc228055d42c9854`
- target normative commit: `ca6451a02aead88734e47193dc228055d42c9854`
- target root tree: `a3b5484c6f56df70832deeaf725a42bda8abb63b`
- target `RNS` tree: `ff3e6127789b6111f265055fea7593f903feccfe`
- version assertion: `RNS.__version__ == "1.6.0"` (unchanged; no version bump yet)
- audited range: `9a01a20ce66c4146dd8f8d31f18c19fe7600739d..ca6451a02aead88734e47193dc228055d42c9854`
- commits in range: `15`
- repositories checked: rgit (normative) and GitHub mirror
- local branch and revision inspected: local `dev` from accepted `74bef18`

The GitHub `master` tip is `e40191b3d193b46b7f2d8a44424a594cd758839b`, which
is `behind` the accepted baseline and is allowed mirror lag. The normative rgit
`master` tip `ca6451a0` (committed 2026-10-28T01:22Z) is `ahead` of the baseline
by the 15 commits inventoried below. Both refreshes succeeded at
2026-10-28T06:16Z. The new commits implement announcement, path-request and
link-request stamps and landed on `master`; the `dev_pr_stamps` name only
survives in the subject of the historical merge commit `c68066ed`. No new tag
or version bump identifies a promotion target yet, so a versioned parity record
is not created.

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
| 1 | `d1da5c3d67dc30e9af300d5776c7e94c42b5a33b` | Implemented destination stamps | Integrated | `0eaf7dd`; announce stamp parse/strip, known-destination stamp persistence, rayon generation, `data/stamps` store, RPC fields |
| 2 | `d2dd730801ca91197f22be56c85d5d855d97faed` | Adjusted stamp defaults | Integrated | `ca33cdb`; destination defaults 20 and PR defaults 19 |
| 3 | `d3ec00cd510e7f8b72e3249a8a74a0d60f5c9f42` | Cleanup | Integrated | `8231a7e`; destination defaults 23; PR tag propagation landed in #4 |
| 4 | `156c7323a510f1be3adfb8288e521559599d3809` | Implemented path request stamps | Integrated | `2c4a936`; 64-byte PR parsing, validation, relay, outbound emission gate |
| 5 | `7ec975fc886de62c80bfebf1b2b108991ea75204` | Cleanup | Non-runtime | `f67dac1`; `ext_payload` naming already native, invariant documented |
| 6 | `51be88fbd83417c8d21d2ce74922faa401658cee` | Fixed unused path cull order | Structurally covered | `5992827`; `cull_path_table` takes earliest-expiring unused paths |
| 7 | `c68066edffd14c3755ceb181c621a4f806ddfd46` | Merge branch 'master' into dev_pr_stamps | Structurally covered | `512b234`; cull-order regression independent of insertion order |
| 8 | `7c1b648607a13d9d7517f5a82c9a59c1bd776935` | Improved PR stamp handling | Integrated | `0979c93`; 0xFF relaying sentinel for unstamped requests to local clients |
| 9 | `8d5871915a4a0b846d2c7e637842ed0c8916425c` | Cleanup | Non-runtime | `5e3b1b3`; constant-order invariant documented |
| 10 | `c3af19893f7e056bbe04f53f57133eddadc4ed71` | Cleanup | Non-runtime | `cc23e6f`; legacy derived-key constant never existed natively |
| 11 | `30c6428e0b59bfc05563167c72c2e0f21ef015c0` | Added link establishment cost to announces | Integrated | `f712c8f`; 17-byte announce extension anchor, `lr_cost` persistence, SQLite v2 migration |
| 12 | `9955e1bf6777a1e5cddfd423de86b5a6824a64cc` | Implemented Identity stamps and added stamp key generation to stamper | Integrated | `6816147`; stamped X25519 keys and stamped `Identity` constructor |
| 13 | `c37b5f7f44900e1d80c166678d8bac565f238046` | Cleanup | Non-runtime | `970eae8`; idempotent migration comment |
| 14 | `ba8c2d76db20be55a22578b840f78ef0489ef053` | Implemented link request stamps | Integrated | `5fe5f87`; X25519 key stamp validation, stamped initiator, recalled cost |
| 15 | `ca6451a02aead88734e47193dc228055d42c9854` | Parameter tuning | Integrated | `6bd6601`; link cost 11 and stamp timeout 15 |

## Per-Commit Analysis

### 1. `d1da5c3d` — Implemented destination stamps

**Upstream change:** Adds optional 14-byte detached stamps to destination
announces, including stamp material, validation, storage and transport
handling.

**Rust applicability:** The generic stamp primitives existed in
`rns-core/src/stamp.rs` but not the announce policy or persistence.

**Local handling and evidence:** `ValidatedAnnounce::apply_stamp` parses and
validates the extension after signature verification, strips it only when
valid, and records the value. Known destinations persist `stamp` and
`stamp_value` through the msgpack and SQLite stores and expose them over RPC.
Emission generates over `destination_hash || public_key || name_hash`, stores
`storage/stamps/<hash>.dstamp`, and remains disabled by the upstream default
`STAMP_DESTINATIONS = false`. Evidence:
`test_announce_stamp_valid_is_stripped_and_valued`,
`announce_stamp_is_stored_and_recalled`,
`generated_destination_stamp_validates_and_roundtrips`, and the storage
round-trips.

**Final disposition:** Integrated.

### 2. `d2dd7308` — Adjusted stamp defaults

**Upstream change:** Retunes announce and path request stamp defaults.

**Rust applicability:** Native constants mirror the same knobs.

**Local handling and evidence:** `DESTINATION_STAMP_COST`/`VALUE` became 20 and
`PATH_REQUEST_STAMP_COST`/`VALUE` were introduced at 19;
`stamp_defaults_match_upstream_parameters`.

**Final disposition:** Integrated.

### 3. `d3ec00cd` — Cleanup

**Upstream change:** Despite the subject, raises `DESTINATION_COST` and
`DESTINATION_VALUE` from 20 to 23, initializes `blocked_if`, propagates a shared
request tag when replaying path requests, and reformats log lines.

**Rust applicability:** Default tuning and stamped-request tag propagation are
applicable; the unbound-variable fix has no native equivalent.

**Local handling and evidence:** Destination defaults raised to 23. Relaying a
stamped path request with its original tag and extension landed with the
path-request mapping (#4) because the native tag path did not exist earlier.

**Final disposition:** Integrated.

### 4. `156c7323` — Implemented path request stamps

**Upstream change:** Adds stamp generation and validation for path requests,
including ingress and egress limiting integration and a large Transport
restructure.

**Rust applicability:** Native path requests are a fixed 48-byte frame; the
64-byte stamped form and extension payload were absent.

**Local handling and evidence:** `parse_path_request` accepts the 64-byte form,
validates over `destination_hash || tag`, and rejects oversized non-stamped
requests. Stamped requests relay verbatim with their original tag; outbound
emission is gated by `STAMP_PRS` (default false). Evidence:
`stamped_path_request_is_forwarded_without_treating_extension_as_tag` and
`path_request_with_oversized_non_stamped_length_is_dropped`.

**Final disposition:** Integrated.

### 5. `7ec975fc` — Cleanup

**Upstream change:** Renames the internal `stamped_ext` parameter to
`ext_payload`, updates the docstring, and normalizes `RNS.Transport` references.

**Rust applicability:** Internal naming only; the native engine already used
`ext_payload`.

**Local handling and evidence:** Documented the relay invariant that the exact
extension bytes are preserved. `f67dac1`.

**Final disposition:** Non-runtime.

### 6. `51be88fb` — Fixed unused path cull order

**Upstream change:** Fixes culling to remove the earliest-expiring unused paths
instead of the latest.

**Rust applicability:** `cull_path_table` already sorts unused paths ascending
by expiry and takes the first `remove_count`.

**Local handling and evidence:** Existing regression retained; invariant
documented in `rns-core/src/transport/jobs.rs`. `5992827`.

**Final disposition:** Structurally covered.

### 7. `c68066ed` — Merge branch 'master' into dev_pr_stamps

**Upstream change:** Merge of the cull-order fix into `dev_pr_stamps`; the
merge-resolution delta is patch-equivalent to #6.

**Rust applicability:** No independent behavior.

**Local handling and evidence:** Added
`unused_path_pool_order_is_by_expiry_not_insertion`, which makes insertion order
disagree with expiry order. `512b234`.

**Final disposition:** Structurally covered.

### 8. `7c1b6486` — Improved PR stamp handling

**Upstream change:** Adds transitional diagnostics distinguishing unstamped
relayed path requests from invalid stamps, gates debug work, and marks
unstamped requests relayed to local clients with a sentinel extension.

**Rust applicability:** The native relay needed the same transition marker.

**Local handling and evidence:** `unstamped_relay_payload()` emits marker
`0xC1`, flags `0xFF`, zero stamp, and is used only when `STAMP_PRS` is enabled
and enforcement is off. `0979c93`;
`unstamped_relay_payload_has_marker_and_sentinel_flags`.

**Final disposition:** Integrated.

### 9. `8d587191` — Cleanup

**Upstream change:** Reorders the `NAME_HASH_LENGTH` declaration.

**Rust applicability:** None; no value or behavior change.

**Local handling and evidence:** Identity size block documented. `5e3b1b3`.

**Final disposition:** Non-runtime.

### 10. `c3af1989` — Cleanup

**Upstream change:** Removes the unused `DERIVED_KEY_LENGTH_LEGACY` constant.

**Rust applicability:** None; the legacy constant never existed natively.

**Local handling and evidence:** Documented the current 64-byte derived-key
length. `cc23e6f`.

**Final disposition:** Non-runtime.

### 11. `30c6428e` — Added link establishment cost to announces

**Upstream change:** Adds an announced link-request cost (`lr_cost`) to
destination announces and persists it in the known-destination store (schema
version 2).

**Rust applicability:** The announce extension grew from 16 to 17 bytes and the
known-destination stores had no link-cost field.

**Local handling and evidence:** The trailing anchor byte carries the cost in
its low seven bits; an extended-format high bit is not interpreted. `lr_cost`
is persisted in msgpack and SQLite, with a version-2 migration that names target
columns. Evidence: `test_announce_stamp_valid_is_stripped_and_valued`,
`sqlite_migrates_v1_schema_and_adds_lr_cost`, and the storage round-trips.
`f712c8f`.

**Final disposition:** Integrated.

### 12. `9955e1bf` — Implemented Identity stamps and added stamp key generation to stamper

**Upstream change:** Adds identity-level stamp keys, stamp material/key
generation, and expanded `Stamps` helpers.

**Rust applicability:** The native crypto crate had stateless stamp primitives
but no stamped key generation.

**Local handling and evidence:** `rns_crypto::identity::generate_stamped_key`
grinds an X25519 keypair over arbitrary material; `Identity::new_stamped` binds
the X25519 half to the Ed25519 public key and `get_value` reports it. Evidence:
`stamped_identity_carries_required_value` and
`stamped_key_public_half_validates_against_material`. `6816147`.

**Final disposition:** Integrated.

### 13. `c37b5f7f` — Cleanup

**Upstream change:** Collapses the schema-migration branch onto one line.

**Rust applicability:** None.

**Local handling and evidence:** Documented that the version-2 migration is a
single idempotent step. `970eae8`.

**Final disposition:** Non-runtime.

### 14. `ba8c2d76` — Implemented link request stamps

**Upstream change:** Adds link-request stamp emission/validation with timeout
handling across `Link`, `Destination` and `Transport`, plus an example update.

**Rust applicability:** Link requests carried no stamp semantics; the initiator
always generated an unconstrained X25519 key.

**Local handling and evidence:** Incoming requests compute the value of the
X25519 key over `destination_hash || ed25519_public_key` and enforce the
announced cost only when `LR_STAMPS_ENFORCED` (off). The initiator generates a
stamped key when the destination announced a non-zero cost and `STAMP_LRS` is
enabled (default true). Evidence:
`stamped_link_request_carries_required_value` and
`create_link_with_cost_stamps_the_link_request`. `5fe5f87`.

**Final disposition:** Integrated.

### 15. `ca6451a0` — Parameter tuning

**Upstream change:** Lowers `LR_COST` from 14 to 11 and
`LINK_STAMP_TIMEOUT` from 16 to 15.

**Rust applicability:** Native constants mirror the same knobs.

**Local handling and evidence:** `LINK_REQUEST_STAMP_COST = 11` and
`LINK_STAMP_TIMEOUT = 15`; `stamp_defaults_match_upstream_parameters`.
`6bd6601`.

**Final disposition:** Integrated.

## Remaining Work

All fifteen commits have a final disposition and a mapping commit. Before a
versioned parity record can be created:

- run exact-target Python/Rust interoperability against `ca6451a0`;
- run the workspace-wide test, feature, formatting, and host lint gates;
- record build, Docker, hardware, and manual gates honestly (the daily
  dual-VPS Backbone smoke is operational evidence, not promotion acceptance);
- document the user-visible stamp knobs natively.

No version bump exists upstream, so `UPSTREAM.md` remains at `9a01a20c` and
this file stays the active audit.

## Acceptance Record

- `2026-10-28`: Daily drift check found rgit `master` at `ca6451a0`, 15 commits
  past the accepted `9a01a20c` baseline. GitHub `master` at `e40191b3` was
  `behind` and fresh. All 15 mapping commits landed in upstream ancestry order
  with `Upstream-Commit` trailers. `rns-crypto`, `rns-core`, and `rns-net`
  tests passed, and formatting plus `clippy -D warnings` passed for those
  crates. No deployment, restart, or reconfiguration of the VPS nodes was
  performed.
