# Reticulum 1.5.0 Upstream Audit

## Scope and Baseline

- audit date: `2026-08-20`
- previous accepted version: `1.4.2`
- previous normative commit: `4fc8e03d658ed87019b8ad6c7ce7827dc76f0e45`
- target version: `1.5.0`
- target tag or ref: `rgit/master`
- target normative commit: `4ab0755d0acc19eb45f729257b8976fde61146bf`
- target root tree: `120e47a62072c34108b582c8569b807bd2143636`
- target `RNS` tree: `fd4c58a1048681afab8d159b7ea64ec180d3aa85`
- version assertion: `RNS.__version__ == "1.5.0"`
- audited range: `4fc8e03d658ed87019b8ad6c7ce7827dc76f0e45..4ab0755d0acc19eb45f729257b8976fde61146bf`
- commits in range: `63`
- repositories checked: canonical rGit `rgit/master` and GitHub mirror `origin/master`
- local branch and revision inspected: `dev@53b458ec00c175257b866fae1df261b9ace37d59`

The canonical rGit tip is 63 commits ahead of the accepted baseline. The GitHub
mirror tip `b48b96e61676504e0a4e527b33b9a0b4495c6872` is behind the accepted
baseline, so the remotes do not agree. This initial daily inventory records all
canonical commits conservatively as **Needs decision**; it does not claim that
any behavior has already been integrated.

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

Every commit in the audited range appears once. Dispositions are intentionally
conservative until the corresponding diffs and Rust code paths are reviewed.

| # | Upstream commit | Subject | Final disposition | Local evidence |
|---:|---|---|---|---|
| 1 | `ebd9b862e976bc06185499e3f644f25e92df374a` | Fixed rnodeconf config summary print | Non-runtime | No `rnodeconf` utility or configuration-summary renderer exists in this repository; no Rust behavior is affected |
| 2 | `38a73f9508bb9d3aa43da00306868fce6cd9e382` | Added ability to include operator LXMF address in interface discovery info | Integrated | Operator address wire/config/persistence/RPC/CLI tests; unsafe endpoint and missing-address regressions; complete `rns-net --all-features` suite |
| 3 | `3db15dae44a03079da570c9d05efdafb0d09bd44` | Updated identity test | Integrated | Token HMAC verification uses the MAC crate's constant-time verifier; all tag positions and invalid lengths are covered |
| 4 | `ce81b339dcbf36137b12a87b5b149bcff7e7f36a` | This will have *zero* effect on any actual, real-world or otherwise just tangentially relevant physically viable situation, but at this point I am fed up with receiving a daily dose of overly verbose machine soup from yet another random LLM-bro who's playing security researcher, so there you have it, now ffs leave me in peace to do some *actual* work, and keep your tech-fantasy wanking to yourself, thank you very much. | Integrated | Local `085b396` uses constant-time MAC verification and covers every tag position plus invalid lengths |
| 5 | `6c1182c2c2043a0e9cb7b8fab3c3980e633f3556` | Packet: reticulum variable is not defined | Structurally covered | Inbound events explicitly propagate RSSI/SNR into announced identities; focused regression asserts both values |
| 6 | `72ba27d63c634e1f37ec74488e9bde02da436cd2` | Link: fix resource cancellation | Structurally covered | Rust cancels resources in place before retaining completed entries; bidirectional multi-transfer regression verifies none are skipped |
| 7 | `55755c6b3c243a6d3e607f0f9d36cd5e538c9033` | Transport: fix check for r_stat_snr | Structurally covered | RNode receive handling records SNR independently of RSSI; focused absent-RSSI regression pins the behavior |
| 8 | `0ec51cce67e890abd0301f2134c82dd05c2fa127` | Link: fix constant name | Integrated | Zero MTU signalling falls back to the protocol MTU for initiator, responder, and proof confirmation; full handshake regression |
| 9 | `691211bf0dbcfb6f964f9037fb82bcae26fbb453` | BackboneInterface: remove unused poll | Structurally covered | Rust performs one poll wait and consumes that batch; existing simultaneous two-client multiplexing regression passes |
| 10 | `0c41027765a6c2e47660caca1b75bcf8c01d96d5` | Resource: avoid rebind of data variable | Structurally covered | Immutable original payload and separate parts storage; multipart regression verifies full-payload resource hash and proof |
| 11 | `90ac62620dd35b84249c2bc0006477cc727363aa` | Transport: fix pending_links items removal while being iterated | Structurally covered | Closed link IDs are collected before removal; four-pending-link regression verifies complete cleanup and deregistration |
| 12 | `c6f9ef1047c594e9d9e800692d3a0a68bd7a0c94` | RNodeInterface: fix stale ble_device | Non-runtime | No Android/Bluetooth RNode client or BLE discovery state exists locally; ESP32 BLE support is a peripheral bridge |
| 13 | `0d9bf5b862bb2a340fe92ee7ab966fbacafb9e03` | rncp: fix variable name | Structurally covered | Rust's typed, lexically scoped transfer/link identifiers cannot produce the Python undefined-local failure; existing rncp unit tests pass |
| 14 | `9b4947ef4607113b5e4c48d1f38d37b500524f44` | Destination: clean ratchets to retained_ratchets | Deferred | Depends on locally generated destination ratchet history, which is not yet implemented; received-remote-ratchet storage is a different path |
| 15 | `e31c570d2be8a3e07c5c10b8f1ea4252abfd5031` | Transport: fix rebind of expires variable | Structurally covered | Typed tunnel/path expiry fields remain distinct; persistence round-trip asserts differing values survive snapshot and restore |
| 16 | `31298e5edad07d8a7029c5fe126d092200d6a3e0` | Fixed speedtest TX abort on link stale status | Non-runtime | Upstream-only Speedtest example; no equivalent Rust example or speed-test utility exists |
| 17 | `bbc1a0d06b1bce3750935d1fd5787cca063be62c` | BackboneInterface: fix epoll RX starvation | Structurally covered | Separate read poll loop and writer socket preserve readable interest; forced outbound-backpressure regression receives inbound traffic |
| 18 | `9ebcb55cb5de86b6089b1c3dcb8e9f5728b43039` | Cleanup | Non-runtime | Parentheses-only Python cleanup around the existing EPOLLHUP bit test; no semantic change |
| 19 | `2d7f858a5498795b53218f422099bbd87c1ac078` | Transport: fix deadlock on receipts_lock  when callback sends message | Structurally covered | Driver-owned receipt state is removed before `on_proof`; callback-driven outbound send regression completes and dispatches its packet |
| 20 | `e46496032c8845fc8312060e682627d416ab77d9` | Contention comments | Non-runtime | Adds only Python TODO comments about possible receipt list and lock contention improvements |
| 21 | `c2eac12ff55e78b4180777e13527d4e0c1a9642c` | Added burst count stat to interfaces | Integrated | Dynamic child→listener ownership is retained; Backbone aggregate accessor counts independent announce/PR burst states and cleans up disconnected children |
| 22 | `fc0f84f23e803ba40ae678ce179c3767ebe8c89e` | Added prioritized inbound traffic processing | Integrated | Four independently bounded inbound classes with strict priority, control barriers, ingress-limited PR demotion, RPC queue pressure, and saturation/order regressions |
| 23 | `7a1291d53069d2b495d02ab7266443f4d5c87527` | Added inbound queue pressure statistics to rnstatus | Integrated | `-q`/`--queues`, correct per-class pressure rendering, Backbone burst counts/durations, parser/format/RPC regressions |
| 24 | `d41afd2d8151206994cd6e06b363a00072722f7d` | Updated rnstatus docs | Documentation follow-up | Native `rnstatus` guide documents current flags, filtering, queue classes, Backbone counts, and remote management |
| 25 | `e81532f541ef5747b5309459edaaec89c03aeffa` | Updated version | Non-runtime | Baseline now records upstream 1.5.0 development metadata; independently versioned Rust crates are unchanged |
| 26 | `0d15cfc134129ab7b90fda42c88f3445a458ba39` | Fixed f-string for old snakes | Non-runtime | Python-only quote compatibility; Rust's compiled invalid-endpoint diagnostic and endpoint rejection are already covered |
| 27 | `f366dd9cf214859a0ea82047f4625e06a8239cc2` | Cleanup | Integrated | Tagless path-request rejection now logs on the dedicated pathing target; removed Python queue block has no Rust equivalent |
| 28 | `efb8c8500d87df13d42011cc5c1595beebe44837` | Made queue lengths configurable | Integrated | Four positive `qlen_in_*` settings, upstream defaults, legacy scalar compatibility, private startup wiring, and independent saturation regressions |
| 29 | `8c08b9ce09ee79117020cf58686bcce953d0d5e9` | Added queue config to documentation | Documentation follow-up | README documents queue priority, all four keys/defaults, full-queue drops, and Rust control barriers |
| 30 | `01a78bee2a0a1e780e058a4d9edcdc0f4416547b` | Fixed typo | Structurally covered | Rust has no per-packet exception handler or mislabeled outbound-queue diagnostic in its inbound event loop |
| 31 | `1809461a07bdb4530529d44c668742b6e26aefa5` | Early filtering note | Non-runtime | Adds only a TODO proposing future non-transport path-request filtering; executable behavior is unchanged |
| 32 | `1c488947bdc8eae32f55736679856064580e1631` | Fixed typo | Structurally covered | Documentation-only grammar correction; native queue-tuning wording does not contain the typo |
| 33 | `e1b7bc316c289a72ba9c7f7ad0b00558845b52a7` | Fixed typo | Structurally covered | Native documentation already labels `qlen_in_pr` and `qlen_in_il` as path-request and ingress-limited queues |
| 34 | `636012bbe515be1692e03a78fe7e55363d0753c1` | Cleanup | Needs decision | Pending per-commit analysis |
| 35 | `1a70bd3cd1390c0e27edc0f5ec1626553e84c17d` | Added queue drop stats | Needs decision | Pending per-commit analysis |
| 36 | `503bd6c87bda7780f613255257ab0095eb57661d` | Improved PR ingress limiter | Needs decision | Pending per-commit analysis |
| 37 | `7c912d0936be42bccb75163c8914991de42fbf8e` | rnstatus: use proper stats | Needs decision | Pending per-commit analysis |
| 38 | `731a63b01b255e270f9a4a962b7b837950863235` | Transport: update interface_hashes_updated_at timestamp | Needs decision | Pending per-commit analysis |
| 39 | `d825e39379ebee2c69f0197567045eb5bd0e56e0` | Transport: fix updating announce_queue | Needs decision | Pending per-commit analysis |
| 40 | `40a862acbd870cec0c803ed8726027b94a0e4150` | Break loop on existing entry in announce queue | Needs decision | Pending per-commit analysis |
| 41 | `338173802d5a0e21515036512180d421c7d3544a` | Transport: fix destination_hash check in pending_discovery_prs | Needs decision | Pending per-commit analysis |
| 42 | `0e2041c8372b33fd9d60114b0b1305cff836eef4` | BackboneInterface: update timestamps in ic checks | Needs decision | Pending per-commit analysis |
| 43 | `6cd5be18ec69a3f5e4dcd7e9ff12fa78eb21f5ef` | Transport: slice discovery_pr_tags to the end | Needs decision | Pending per-commit analysis |
| 44 | `39e3854daca7b29c585ebaa0dee412ccd429d1e0` | Link: reset watchdog if exception happens in receive | Needs decision | Pending per-commit analysis |
| 45 | `acecc1f4907483927ed001d5c09ef8e61278dd96` | Error logging | Needs decision | Pending per-commit analysis |
| 46 | `c95bb551ab2c5e702efe4fa77ae35c568e607b3b` | Transport: handle exceptions in inbound() | Needs decision | Pending per-commit analysis |
| 47 | `db7daa4d9412e98273ce58d47286f36afce1d5ae` | Method naming | Needs decision | Pending per-commit analysis |
| 48 | `65222e0de8355fa4e7bfd6fe6ad76116b155aeeb` | Resource: align indexes in receive_part with request_next | Needs decision | Pending per-commit analysis |
| 49 | `2e9443ffe2f6e130cae094ebc898c02d8cbde56e` | Fixed typo | Needs decision | Pending per-commit analysis |
| 50 | `0c0034f1ae81e2475c6f43dee6537b6d29e7691b` | Tuned burst stats throttle | Needs decision | Pending per-commit analysis |
| 51 | `df80181006882f035e36a6e4673118bd7d13191c` | Utilize full link MDU in RawChannelWriter | Needs decision | Pending per-commit analysis |
| 52 | `77a1bb9b194a0e1199131c3ca9f1f01b42885526` | Consistency | Needs decision | Pending per-commit analysis |
| 53 | `954567c581f63b20b85863f1ecf2fa3044d64ebe` | Allow disabling link MTU discovery | Needs decision | Pending per-commit analysis |
| 54 | `49918c7e1d524e4abf61b5714b3b5bd66350ae1b` | Updated docs | Needs decision | Pending per-commit analysis |
| 55 | `6738db54378821f27e2224bb014d6f5b04e9bc54` | Cleaned up deprecated logic block indent in relation to inbound processing refactor | Needs decision | Pending per-commit analysis |
| 56 | `49073fcca59561ce5ecbe56c99b36816ecbacfde` | Fixed invalid interface basis for extra link proof timeout calculation, thanks to Zenith | Needs decision | Pending per-commit analysis |
| 57 | `bde5611a0d6651e5c9e6357d7259770fdb4ff7d0` | Fixed missing interface.bitrate validation in extra link proof timeout calculation, thanks to Zenith | Needs decision | Pending per-commit analysis |
| 58 | `4b914fb9a4973b5b1452875b8d514876c85b89ae` | Include extra timeout for discovery PRs when slow interfaces are online, thanks to Zenith | Needs decision | Pending per-commit analysis |
| 59 | `68cda4a8557f223ed2ac8e4907968a0037424c30` | Added discovery_lxmf_address to documentation | Needs decision | Pending per-commit analysis |
| 60 | `9ae3db169ed464d37f90ac6371af09708ca96eda` | Fixed medium_timeout init | Needs decision | Pending per-commit analysis |
| 61 | `05e6717d210aa330a0ed6def109c47d3f3cfc71d` | Fixed rngit file resource operations failing on Windows | Needs decision | Pending per-commit analysis |
| 62 | `d478e380c93dc892879d3800adee321a6b5733aa` | Use sets for discovery pr tags | Needs decision | Pending per-commit analysis |
| 63 | `4ab0755d0acc19eb45f729257b8976fde61146bf` | Changed PR ingress accounting point | Needs decision | Pending per-commit analysis |

## Per-Commit Analysis

### 1. `ebd9b862` — Fixed rnodeconf config summary print

**Upstream change:** Changes the WiFi station/AP summary branches in Python's
`rnodeconf` utility from two independent conditions to one `if`/`elif`/`else`
chain. Before the fix, station mode printed both "Enabled (Station)" and
"Disabled".

**Rust applicability:** This repository implements RNode framing, interfaces,
and runtime configuration, but it does not implement the `rnodeconf`
device-management utility or expose an equivalent device configuration-summary
renderer. The changed presentation path therefore has no Rust compatibility
surface.

**Local handling and evidence:** No production change or regression test is
appropriate because there is no corresponding output path to exercise. A
repository-wide search confirmed that RNode code is limited to protocol,
interface, runtime configuration, ESP32 bridge, and hardware examples.

**Final disposition:** Non-runtime.

### 2. `38a73f95` — Added ability to include operator LXMF address in interface discovery info

**Upstream change:** Adds discovery field `0xF0` for an optional 16-byte
operator LXMF destination hash, parses `discovery_lxmf_address` from interface
configuration, persists and exposes the received address, and prints it in
`rnstatus -D`. The same commit suppresses Backbone/TCP-server discovery without
a reachable address and prevents autoconnection to onion, loopback, and
unspecified-IP endpoints while retaining those announcements for inspection.

**Rust applicability:** Interface discovery wire metadata, configuration,
persistence, compatible RPC output, `rnstatus`, and discovered Backbone peer
autoconnection are all implemented locally and require matching behavior.

**Local handling and evidence:** Added the `0xF0` wire field and exact 16-byte
validation, optional configuration parsing, discovery persistence, compatible
lowercase-hex RPC representation, and `rnstatus -D` display. Network discovery
packing now rejects missing `reachable_on`; unsafe endpoints remain visible but
do not produce autoconnect configuration. The detailed-display separator also
matches upstream's widened 47-column layout. Tests cover valid, malformed-type,
wrong-length, packing, missing-address, onion/loopback/unspecified endpoints,
configuration parsing, persistence, RPC, and CLI extraction. `cargo test -p
rns-net --all-features` and `cargo test -p rns-cli --bin rnstatus` passed on
2026-08-20.

**Final disposition:** Integrated.

### 3. `3db15dae` — Updated identity test

**Upstream change:** Adds a diagnostic timing loop that invokes
`Token.verify_hmac()` one million times over random 64-byte inputs and reports
the observed min/mean/median/max timings. It adds no assertion and changes no
runtime code.

**Rust applicability:** Token HMAC verification is part of the compatible
identity encryption path. Rust previously calculated the expected tag and used
ordinary slice equality, which does not express the constant-time verification
invariant being probed upstream.

**Local handling and evidence:** Added an HMAC-SHA256 verification helper backed
by the HMAC crate's constant-time `verify_slice` primitive and routed
`Token::verify_hmac` through it. Deterministic regressions reject wrong-length
tags and mutations at every one of the 32 tag positions; this avoids a flaky
wall-clock timing threshold while pinning the intended implementation shape.
`cargo test -p rns-crypto` passed 71 unit tests, 11 crypto exercise tests, 11
Python-compatible interoperability tests, and doc tests on 2026-08-20.

**Final disposition:** Integrated.

### 4. `ce81b339` — Constant-time HMAC comparison

**Upstream change:** Exposes Python's `hmac.compare_digest` through the bundled
HMAC module, with an equality fallback for old interpreters, and replaces the
ordinary tag equality in `Token.verify_hmac` with that helper.

**Rust applicability:** Directly applicable to the compatible Token HMAC
verification path.

**Local handling and evidence:** Already integrated in local commit `085b396`
while processing the immediately preceding upstream timing test. Rust uses the
HMAC crate's constant-time `verify_slice` primitive and deterministically tests
all 32 possible single-byte tag mismatch positions and invalid tag length. No
additional production or test change is necessary for this commit.

**Final disposition:** Integrated.

### 5. `6c1182c2` — Packet radio-metadata fallback

**Upstream change:** Replaces references to an undefined module-level
`reticulum` variable in `Packet.get_rssi()`, `get_snr()`, and `get_q()` with
the active `RNS.Reticulum` instance. The affected branch is the fallback used
when metadata is not already stored directly on the Python packet.

**Rust applicability:** Rust does not expose these Python packet getters or a
process-global Reticulum instance. Receive metadata is owned by the inbound
driver event and explicitly copied into the validated announced identity. No
late global lookup exists, so the undefined-variable failure mode cannot occur.
The local interface layer currently supplies RSSI and SNR; it has no equivalent
link-quality (`q`) metric.

**Local handling and evidence:** Extended the existing inbound-announce test to
assert that its synthetic `-100` RSSI and `10.5` SNR values survive validation
and storage in `known_destinations`. The focused
`announce_received_populates_known_destinations` regression passed against the
exact upstream reference checkout on 2026-08-20. No production change is
required.

**Final disposition:** Structurally covered.

### 6. `72ba27d6` — Link resource cancellation

**Upstream change:** Iterates over copies of a link's incoming and outgoing
resource lists during shutdown. In Python, each `Resource.cancel()` call removes
the resource from the original list, so direct iteration skipped every second
entry.

**Rust applicability:** Link shutdown and resource cancellation are compatible
runtime behavior. Rust's `cancel_all_resources()` does not remove entries from
the vectors while iterating: it first invokes `cancel()` through mutable
references, then retains only non-terminal entries after both loops. The Python
iterator-invalidation defect is therefore structurally absent.

**Local handling and evidence:** Added a bidirectional regression with four
simultaneous incoming and four simultaneous outgoing resources on each peer.
Cancellation produces four initiator-cancel and four receiver-cancel packets
per peer and leaves no active transfers, proving that neither vector skips
alternating entries. The focused regression passed against the exact upstream
reference checkout on 2026-08-20. No production change is required.

**Final disposition:** Structurally covered.

### 7. `55755c6b` — Independent SNR propagation

**Upstream change:** Corrects the condition guarding Python's assignment of
received SNR metadata. The code mistakenly checked that RSSI was non-null, so a
valid `r_stat_snr` was not copied to the packet when RSSI was unavailable.

**Rust applicability:** RNode receive metadata feeds compatible packet and
announce telemetry. Rust already matches `StatRssi` and `StatSnr` as independent
events and stores either value without consulting the other, so it does not
have the cross-field guard defect.

**Local handling and evidence:** Extracted the existing independent metadata
updates into a small helper used by the reader loop. A focused regression feeds
an SNR value while RSSI remains absent and verifies that SNR is converted and
retained. The test passed against the exact upstream reference checkout on
2026-08-20.

**Final disposition:** Structurally covered.

### 8. `0ec51cce` — Default MTU fallback

**Upstream change:** Qualifies the default-MTU constant used when an incoming
link request signals a zero MTU. The prior `Reticulum.MTU` name was undefined in
that scope; the exception handler happened to recover using the correctly
qualified constant. The same fallback is used when processing link proofs.

**Rust applicability:** Rust parses the same link-request and link-proof MTU
signalling. It treated a present zero as a real MTU, which caused debug builds
to panic while calculating the link MDU instead of falling back to the protocol
default as Python does.

**Local handling and evidence:** Added one MTU normalization function and use it
for link initiation, incoming link requests, and confirmed link proofs. A full
initiator/responder handshake regression with zero signalling first reproduced
the MDU underflow, then passed with both peers using the default MTU and MDU.
The focused test passed against the exact upstream reference checkout on
2026-08-20.

**Final disposition:** Integrated.

### 9. `691211bf` — Remove discarded Backbone poll

**Upstream change:** Removes an extra `epoll.poll(1)` call whose returned event
batch was assigned but never processed immediately before the real polling
loop. This avoids discarding readiness notifications and an unnecessary system
call or timeout.

**Rust applicability:** Backbone server event polling is compatible runtime
behavior, but Rust's loop already clears its event buffer, performs exactly one
`Poller::wait()`, and iterates over that same returned buffer. It has no
discarded preliminary poll.

**Local handling and evidence:** No production change is required. The existing
`backbone_epoll_multiplexing` regression connects two clients, makes both
sockets ready together, and requires both payloads to be delivered. It passed
against the exact upstream reference checkout on 2026-08-20.

**Final disposition:** Structurally covered.

### 10. `0c410277` — Preserve full resource data during part mapping

**Upstream change:** Renames the per-part slice from `data` to `part_data` while
building a resource hashmap. Previously, that loop rebound the constructor's
full payload variable; if a map-hash collision restarted the outer loop, the
resource hash and expected proof were recomputed from a part instead of the
complete original data.

**Rust applicability:** Resource identity, proof generation, part splitting,
and collision retry behavior are protocol-compatible. Rust stores the immutable
complete payload as `uncompressed_data` and generated slices as `parts_data`;
the collision loop always hashes the former and cannot rebind it.

**Local handling and evidence:** Added a multipart resource regression that
recomputes the sender's resource hash and expected proof from the full original
payload and verifies that hashing the first generated part does not match. The
focused test passed against the exact upstream reference checkout on
2026-08-20. No production change is required.

**Final disposition:** Structurally covered.

### 11. `90ac6262` — Pending-link cleanup iteration

**Upstream change:** Collects closed pending links in a temporary list and
removes them only after iterating. Removing directly from Python's
`pending_links` list skipped alternating closed entries and their associated
path rediscovery handling.

**Rust applicability:** Pending link lifecycle and cleanup are compatible
runtime behavior. Rust snapshots all link IDs before ticking and then collects
all closed IDs into another vector before removing any map entry. Mutation never
occurs through the active iterator.

**Local handling and evidence:** Added a regression that creates and closes four
pending links before one tick, then requires four distinct deregistration
actions and an empty LinkManager. The focused test passed against the exact
upstream reference checkout on 2026-08-20. No production change is required.

**Final disposition:** Structurally covered.

### 12. `c6f9ef10` — Clear stale Android BLE device

**Upstream change:** Corrects an equality expression to an assignment when an
Android RNode BLE scan finds no target devices. The typo left a previously
selected `ble_device` in place and allowed reconnect logic to reuse stale state.

**Rust applicability:** This repository supports serial RNode interfaces and an
ESP32 BLE peripheral bridge, but it does not implement Reticulum's Android
Bluetooth RNode client, BLE scanning, or a selected-device reconnect field. The
ESP32 peripheral waits for central connections and is not the affected client
discovery path.

**Local handling and evidence:** A repository-wide search confirmed there is no
equivalent Android/Bluetooth dispatcher or BLE device-selection state. No
production change or regression test is appropriate for an absent platform
implementation.

**Final disposition:** Non-runtime.

### 13. `0d9bf5b8` — rncp interrupt cleanup variable

**Upstream change:** Changes `resource` to `current_resource` in Python
`rncp`'s `KeyboardInterrupt` handler so an active transfer can be cancelled
before its link is torn down. The old undefined name raised `NameError` during
cleanup.

**Rust applicability:** This repository implements `rncp`, but its active
transfer and link IDs are statically typed lexical bindings in the send and
fetch loops. Rust cannot compile a reference to an undefined local variable, so
the Python name-resolution failure mode is structurally absent.

**Local handling and evidence:** No production change or synthetic runtime test
is appropriate for compile-time name resolution. The existing `rncp` unit tests
passed against the exact upstream reference checkout on 2026-08-20, and host
Clippy validates all identifiers and branches with warnings denied.

**Final disposition:** Structurally covered.

### 14. `9b4947ef` — Configurable generated-ratchet retention

**Upstream change:** Truncates a destination's locally generated ratchet history
to its configured `retained_ratchets` value instead of the global default of
512. Custom lower retention limits were therefore previously ignored.

**Rust applicability:** The changed behavior belongs to inbound destinations
that generate, rotate, advertise, and retain their own ratchet key history.
Rust currently consumes and persists the latest ratchet announced by a remote
destination for outbound encryption, but it does not yet generate or rotate
ratchets for local destinations. The local singleton `RatchetStore` is the
opposite direction of the affected feature and is not valid evidence here.

**Local handling and evidence:** Deferred until local destination ratchet
generation and rotation are ported as a cohesive feature. At that point, the
retention limit must be configurable and tested below, at, and above the limit,
including persistence/reload. No unrelated received-ratchet test is added for
this commit.

**Final disposition:** Deferred. Impact: local destinations still cannot offer
ratcheted encryption, so custom generated-ratchet history limits are not
exposed.

### 15. `e31c570d` — Preserve tunnel expiry during persistence

**Upstream change:** Renames the inner path expiry binding while loading and
saving tunnel tables. Reusing `expires` for each path overwrote the containing
tunnel's expiry, so the serialized or restored tunnel inherited its last path's
deadline.

**Rust applicability:** Tunnel and path persistence is compatible runtime state.
Rust models the deadlines as separate typed fields on `PersistedTunnel` and
`PersistedPath`; snapshot and restore copy each field independently, so lexical
rebinding cannot conflate them.

**Local handling and evidence:** Extended the detached-tunnel persistence test
to use a tunnel expiry derived from `TUNNEL_TIMEOUT` and a distinct path expiry
of `500.0`. Both values remain distinct in the initial snapshot and after
restore/resnapshot. The focused regression passed against the exact upstream
reference checkout on 2026-08-20. No production change is required.

**Final disposition:** Structurally covered.

### 16. `31298e5e` — Speedtest stale-link transmit loop

**Upstream change:** Changes the Python Speedtest example's transmit loop from
running only while a link is `ACTIVE` to running until it is `CLOSED`. A
temporary `STALE` state therefore no longer aborts an in-progress benchmark.

**Rust applicability:** The change is confined to `Examples/Speedtest.py`.
This repository has link lifecycle support but no Speedtest example, benchmark
CLI, or equivalent transmit loop.

**Local handling and evidence:** A repository-wide example and utility search
confirmed there is no corresponding code path. No production change or test is
appropriate for an absent example.

**Final disposition:** Non-runtime.

### 17. `bbc1a0d0` — Backbone RX under write backpressure

**Upstream change:** Keeps `EPOLLIN` registered when a Backbone peer also needs
`EPOLLOUT`, and processes read and write readiness independently when both flags
are returned. Previously, changing interest to write-only could starve RX during
large full-duplex transfers.

**Rust applicability:** Full-duplex Backbone behavior under socket backpressure
is directly applicable. Rust uses a dedicated writer-side socket clone while
the server poll loop keeps the original stream registered as readable; writer
backpressure never modifies the poller's read interest.

**Local handling and evidence:** Added a loopback regression that shrinks the
client receive buffer, writes from the server until `WouldBlock`, then sends a
client frame without draining outbound data. The server still emits the exact
inbound frame within the timeout. The focused test passed against the exact
upstream reference checkout on 2026-08-20. No production change is required.

**Final disposition:** Structurally covered.

### 18. `9ebcb55c` — Parenthesize Backbone hangup test

**Upstream change:** Adds parentheses around `event & select.EPOLLHUP` in the
Backbone poll loop. Python's operator precedence and the evaluated condition are
unchanged.

**Rust applicability:** None. This is a source-style clarification with no wire,
lifecycle, polling, or disconnect behavior change.

**Local handling and evidence:** No code or test change is appropriate. The
complete 40-test Backbone suite, including disconnect and backpressure cases,
passed for the immediately preceding runtime commit.

**Final disposition:** Non-runtime.

### 19. `2d7f858a` — Release receipt state before proof callbacks

**Upstream change:** Copies candidate packet receipts while holding
`receipts_lock`, then validates them and invokes their callbacks after releasing
the lock. Previously, a delivery callback that sent another packet could try to
acquire the same non-reentrant receipt lock and deadlock.

**Rust applicability:** Callback-driven sends are directly applicable, but the
Python lock failure is structurally absent. The Rust driver exclusively owns
`sent_packets` and `completed_proofs`; `handle_inbound_proof` removes the tracked
send and records completion before invoking `on_proof`, without a receipt mutex
held across the callback.

**Local handling and evidence:** Added a proof callback that synchronously
enqueues a valid outbound packet through the bounded driver event channel. The
driver returns from the callback, consumes the queued send, and writes the exact
packet. The focused regression passed against the exact upstream reference on
2026-08-20.

**Final disposition:** Structurally covered.

### 20. `e4649603` — Document possible receipt contention improvements

**Upstream change:** Adds TODO comments around receipt culling, timeout scans,
and proof candidate selection. It suggests future list/data-structure changes
to reduce time spent under `receipts_lock` but changes no executable statement.

**Rust applicability:** None for this commit. Rust's driver-owned hash maps and
single-owner event loop differ from the commented Python list-and-lock design;
any future queue or contention work must be evaluated when upstream implements
it, not inferred from speculative comments.

**Local handling and evidence:** No production or test change is appropriate
for a comments-only upstream commit. The exact diff and `RNS` tree were recorded
in the moving baseline.

**Final disposition:** Non-runtime.

### 21. `c2eac12f` — Count burst-limited Backbone clients

**Upstream change:** Adds `ic_burst_count` and `ic_pr_burst_count` properties.
Base interfaces return no aggregate, while a Backbone listener counts spawned
client interfaces with active announce or path-request ingress limiting.

**Rust applicability:** Directly applicable. Rust already tracks both burst
states per concrete child interface, but previously discarded the dynamic
child-to-listener relationship after registration, so listener-level counts
could not be reconstructed reliably.

**Local handling and evidence:** The driver now retains dynamic interface
parent IDs, removes them with disconnected children, and exposes a non-breaking
Backbone count accessor without changing the published `SingleInterfaceStat`
layout. A focused regression activates different announce and path-request
bursts across two listeners, verifies parent scoping, disconnects one child,
and verifies both its ownership and count disappear.

**Final disposition:** Integrated.

### 22. `fc0f84f2` — Prioritize bounded inbound traffic classes

**Upstream change:** Replaces direct inbound processing with four independently
bounded queues, drained in DATA, ANNOUNCE, PATH REQUEST, then INGRESS-LIMITED
order. Packet parsing, announce validation/limiting, and path-request duplicate
and ingress checks move before queue insertion. Interface stats gain listener
burst counts and inbound queue height/pressure keys. Outbound queue support is
left disabled and unimplemented upstream.

**Rust applicability:** Directly applicable. Rust previously used one bounded
`SyncSender<Event>` for frames and driver control, so one traffic category could
consume all queue capacity and all inbound frames were processed FIFO. Rust's
engine already performs packet filtering, announce validation, duplicate path
request suppression, and ingress control at its single-owner boundary; moving
those mutable tables into reader threads would violate that ownership model.

**Local handling and evidence:** Replaced the concrete event channel with a
method-compatible sender/receiver pair that classifies valid frame headers into
the four upstream classes, gives each an independent bound, and drains strict
class priority. Control events retain FIFO barriers, preserving established
frame-before-query/shutdown behavior. Once the engine activates path-request
ingress limiting, subsequent frames on that interface enter the lowest class.
Full queues drop inbound frames without blocking interface readers, while
control sends retain bounded backpressure. RPC dictionaries now include
`rxqt`, per-class heights, pressure ratios, `txq`, and Backbone burst counts;
published Rust status struct layouts remain unchanged.

Focused regressions cover all four-class ordering, isolation of path-request
capacity under data saturation, consistent queue snapshots, independent burst
states and cleanup, and RPC pressure/count encoding. The complete 868-test
`rns-net` unit suite passed with loopback access.

**Final disposition:** Integrated.

### 23. `7a1291d5` — Display inbound queue pressure in rnstatus

**Upstream change:** Adds `-q`/`--queues` and renders total, data, announce,
path-request, and ingress-limited inbound queue pressure and packet counts.
Active burst descriptions also include the number of limited Backbone child
interfaces. The upstream diff accidentally reads `dqpressure` for its announce
and path-request lines.

**Rust applicability:** Directly applicable. The preceding integration exposes
all queue height and pressure keys through the local and remote status RPC
dictionaries. Dynamic Backbone children also have independent burst state, but
the listener needs the earliest active timestamp to describe aggregate burst
duration accurately.

**Local handling and evidence:** `rnstatus` accepts both queue flags and prints
all five classes. It deliberately reads `aqpressure` and `pqpressure` for the
corresponding lines instead of reproducing the upstream copy-and-paste defect.
Backbone RPC enrichment now reports aggregate active state, child counts, and
the earliest activation time for each burst class without changing public Rust
statistics structs. Focused parser, formatter, event aggregation, and RPC tests
cover missing statistics, distinct pressure values, counts, timestamps, and
cleanup.

**Final disposition:** Integrated.

### 24. `d41afd2d` — Document expanded rnstatus options

**Upstream change:** Updates the `rnstatus` usage block with path-request,
burst-only, blocked-IP, and queue-statistics flags and expands the documented
sort keys.

**Rust applicability:** The option surface is user-visible and directly
applicable, although this repository maintains Markdown documentation rather
than upstream's Sphinx source.

**Local handling and evidence:** Added a native `rnstatus` guide containing the
actual Rust utility's current help surface, queue-class output, filter behavior,
Backbone burst counts, and remote-management identity requirement, and linked
it from the README. This is documentation-only, so no synthetic test was added;
formatting, warning-free host lint, and exact baseline checks remain the
acceptance gates.

**Final disposition:** Documentation follow-up.

### 25. `e81532f5` — Assert upstream version 1.5.0

**Upstream change:** Changes `RNS.__version__` from 1.4.2 to 1.5.0. No runtime,
protocol, or packaging code changes, and no 1.5.0 tag accompanies this commit.

**Rust applicability:** The asserted upstream version belongs in the normative
baseline. Rust workspace crates have independent package versions and release
histories, so changing them to 1.5.0 would be inaccurate and would create an
unrelated publication change.

**Local handling and evidence:** Updated `UPSTREAM.md` to record the 1.5.0
development assertion and its exact metadata commit while retaining the signed
1.4.2 tag as the GitHub/CI reference. No production code or test changes are
appropriate for upstream-only Python version metadata.

**Final disposition:** Non-runtime.

### 26. `0d15cfc1` — Keep discovery diagnostic compatible with older Python

**Upstream change:** Changes nested double quotes to single quotes inside one
f-string expression so the invalid-discovery-endpoint diagnostic parses on
older Python interpreters. The message and endpoint rejection are unchanged.

**Rust applicability:** The interpreter grammar issue is Python-only. Rust's
format string and indexed endpoint value are statically compiled, and the
corresponding unsafe IP, loopback, onion, and unspecified endpoint behavior was
already covered while integrating discovery metadata.

**Local handling and evidence:** No production or synthetic test change is
appropriate. The exact diff is recorded as non-runtime, while the existing
discovery endpoint-safety regression and warning-free compilation cover the
equivalent Rust path.

**Final disposition:** Non-runtime.

### 27. `f366dd9c` — Clean inbound queue path and pathing diagnostic

**Upstream change:** Removes an obsolete commented copy of inbound queue
insertion, marks early path-request limiting as implemented, and changes the
tagless path-request rejection diagnostic from debug to the dedicated pathing
log level. Packet acceptance and wire behavior are unchanged.

**Rust applicability:** Rust has only one active prioritized queue insertion
implementation and no deprecated commented block. It already rejects tagless
path requests, but previously did so silently rather than at the pathing log
level.

**Local handling and evidence:** Added a trace on `PATHING_LOG_TARGET` at the
existing tagless rejection branch. The established logging regressions prove
that this target is hidden at debug, enabled at pathing, and enabled by extreme
verbosity. No synthetic packet-behavior test was added because rejection itself
did not change.

**Final disposition:** Integrated.

### 28. `efb8c850` — Configure inbound traffic-class queue lengths

**Upstream change:** Lowers default DATA, ANNOUNCE, PATH REQUEST, and
INGRESS-LIMITED capacities to 4096, 256, 256, and 128, respectively, and adds
positive `qlen_in_data`, `qlen_in_announce`, `qlen_in_pr`, and `qlen_in_il`
configuration settings. A released held announce is explicitly classified as
ingress-limited when it re-enters Python's inbound queue.

**Rust applicability:** Independent capacity configuration is directly
applicable to the prioritized event queues. Rust's released held announces are
processed as maintenance actions inside the single-owner engine rather than
re-entering the external event queue, so they cannot consume announce queue
capacity and need no synthetic traffic-class marker.

**Local handling and evidence:** Added a named public capacity value, adopted
the four upstream defaults, parsed and positively validated all upstream keys,
and wired file-based startup through a private queue context. The legacy
`driver_event_queue_capacity` setting and public `NodeConfig` layout remain
compatible; direct API callers retain the prior shared-capacity behavior.
Regressions cover exact defaults, four distinct configured values, zero,
negative and non-integer rejection, legacy scaling, and independent saturation
at four deliberately different bounds.

**Final disposition:** Integrated.

### 29. `8c08b9ce` — Document inbound queue tuning

**Upstream change:** Adds an ingress-queue tuning section describing priority
order, the four `qlen_in_*` settings and defaults, full-queue packet drops, and
strict draining of higher-priority queues. It also regenerates upstream's
manual artifacts for version 1.5.0.

**Rust applicability:** The configuration and runtime behavior from the prior
commit are user-facing and need native documentation. Generated Sphinx and
Markdown copies are upstream publication artifacts and are not vendored.

**Local handling and evidence:** Added the four settings and exact defaults to
the README beside ingress control, together with priority, saturation, and
control-barrier semantics. The labels correctly identify path-request and
ingress-limited queues instead of repeating upstream's “data queue” wording.
No test is appropriate for this documentation-only change.

**Final disposition:** Documentation follow-up.

### 30. `01a78bee` — Correct inbound queue exception label

**Upstream change:** Changes “outbound queue” to “inbound queue” in the
exception message emitted by Python's inbound queue worker. Runtime behavior is
unchanged.

**Rust applicability:** Rust's event loop receives typed events and dispatches
them without a Python-style catch-all exception boundary. A disconnected event
channel ends the loop normally, and there is no inbound-worker diagnostic that
misnames an outbound queue.

**Local handling and evidence:** A repository search and inspection of the
driver loop confirmed the incorrect diagnostic is structurally absent. No code
change or synthetic test is appropriate for a nonexistent message.

**Final disposition:** Structurally covered.

### 31. `1809461a` — Note possible early path-request filtering

**Upstream change:** Adds a TODO suggesting that non-transport nodes could
discard path requests earlier when the destination is not local, potentially
with a new local-client destination map. No statement executes differently.

**Rust applicability:** None for this commit. The proposal calls out unresolved
state design and must be evaluated if upstream implements it; inferring and
shipping speculative filtering now could change path-request routing ahead of
the normative implementation.

**Local handling and evidence:** Recorded the exact comments-only diff and
advanced the baseline. No production code or synthetic test is appropriate.

**Final disposition:** Non-runtime.

### 32. `1c488947` — Correct queue-documentation grammar

**Upstream change:** Rephrases “if you're setup” as “if you're running a
setup” in source and generated queue-tuning documentation. No configuration or
runtime behavior changes.

**Rust applicability:** The native README describes the same tuning scenario
without the incorrect phrase. Generated upstream manual artifacts are not
vendored.

**Local handling and evidence:** Confirmed the native documentation is already
grammatically correct. No file or test change is required beyond the audit and
baseline record.

**Final disposition:** Structurally covered.

### 33. `e1b7bc31` — Correct path-request and ingress queue labels

**Upstream change:** Replaces two copied “data queue” descriptions with “path
request queue” and “ingress limiter queue” in source and generated manuals.
Runtime behavior is unchanged.

**Rust applicability:** The native queue-tuning section already calls these
classes path requests and ingress-limited traffic. Upstream's generated manuals
are not vendored.

**Local handling and evidence:** Confirmed both native labels were correct when
the queue documentation was introduced. No local prose or test change is
needed.

**Final disposition:** Structurally covered.

Detailed analysis for the remaining commits is pending. As each commit is
reviewed, replace its provisional **Needs decision** inventory entry and add a
numbered analysis section here.

## Integration Plan

1. Group the 63 commits into protocol/runtime, interfaces, utilities,
   documentation, tests, and non-runtime changes.
2. Review each upstream diff against the corresponding Rust implementation.
3. Add focused regression tests before porting applicable behavior.
4. Record local implementation commits and evidence, then run promotion gates.

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

- `2026-08-21`: Commit `e1b7bc31` corrects queue-class labels that were already
  correct in native documentation. Its unchanged `RNS` tree, exact checkout,
  formatting, host lint, and drift check passed, leaving 30 commits.
- `2026-08-21`: Commit `1c488947` corrects grammar absent from the native queue
  documentation. Its unchanged `RNS` tree, exact checkout, formatting, host
  lint, and drift check passed, leaving 31 commits.
- `2026-08-21`: Commit `1809461a` adds only a speculative early-filtering TODO.
  The exact checkout and drift checker resolved to `1809461a`, leaving 32
  commits; formatting and warning-free host lint passed.
- `2026-08-21`: Commit `01a78bee` fixes a Python-only exception label that has
  no Rust equivalent. The exact checkout and drift checker resolved to
  `01a78bee`, leaving 33 commits; formatting and warning-free host lint passed.
- `2026-08-20`: Commit `8c08b9ce` is covered by native inbound-queue tuning
  documentation with correct class labels and Rust barrier semantics. No test
  was added for documentation-only content; formatting, host lint, and the
  exact drift check passed, leaving 34 commits.
- `2026-08-20`: Commit `efb8c850` adds independently configurable inbound
  queue lengths with upstream defaults while preserving legacy scalar/API
  behavior. Config parsing/validation and four-class saturation regressions,
  the full `rns-net` unit suite, formatting, host lint, and exact drift checks
  passed, leaving 35 commits.
- `2026-08-20`: Commit `f366dd9c` aligns the tagless path-request diagnostic
  with the dedicated pathing target; obsolete Python queue code has no local
  equivalent. Pathing-filter tests, formatting, host lint, and exact drift
  checks passed, leaving 36 commits.
- `2026-08-20`: Commit `0d15cfc1` is Python-parser compatibility only. The
  existing compiled Rust diagnostic and endpoint-safety coverage remain
  applicable; the exact checkout and drift checker resolved to `0d15cfc1`,
  leaving 37 commits, and warning-free host lint passed.
- `2026-08-20`: Commit `e81532f5` advances upstream's development version
  assertion to 1.5.0 without changing independently versioned Rust crates. The
  exact checkout and drift checker resolved to `e81532f5`, leaving 38 commits;
  formatting and warning-free host lint passed.
- `2026-08-20`: Commit `d41afd2d` is covered by the new native `rnstatus`
  utility guide and README link. No test was added for documentation-only
  content; formatting, warning-free host lint, and the drift checker passed,
  with the exact accepted checkout leaving 39 commits.
- `2026-08-20`: Commit `7a1291d5` is integrated with `rnstatus -q/--queues`,
  correct independent class pressure rendering, and aggregate Backbone burst
  counts/durations. Focused CLI, parser, event, and RPC tests passed; the
  accepted checkout and drift checker resolved exactly to `7a1291d5`, leaving
  40 commits.
- `2026-08-20`: Commit `fc0f84f2` is integrated with independently bounded,
  prioritized inbound queues and RPC pressure/count reporting. Focused queue
  and RPC tests plus all 868 `rns-net` unit tests passed; the accepted checkout
  and drift checker resolved exactly to `fc0f84f2`, leaving 41 commits.
- `2026-08-20`: Commit `c2eac12f` is integrated with retained dynamic-parent
  ownership and Backbone burst-count aggregation. The mixed-parent and cleanup
  regression passed; the accepted checkout and drift checker resolved exactly
  to `c2eac12f`, leaving 42 commits.
- `2026-08-20`: Commit `e4649603` adds only TODO comments about receipt
  contention. The reference checkout and drift checker resolved exactly to
  `e4649603`, leaving 43 commits; formatting and warning-free host lint passed.
- `2026-08-20`: Commit `2d7f858a` is structurally covered by driver-owned
  receipt state that is released before `on_proof`. The callback-driven
  outbound-send regression passed; the accepted reference checkout and drift
  checker resolved exactly to `2d7f858a`, leaving 44 commits.
- `2026-08-20`: Commit `9ebcb55c` is a semantics-neutral parentheses cleanup.
  The reference checkout and drift checker resolved exactly to `9ebcb55c`,
  leaving 45 commits; formatting and warning-free host lint passed.
- `2026-08-20`: Commit `bbc1a0d0` is structurally covered by Rust's separate
  Backbone read poll and writer socket. The forced-`WouldBlock` inbound-delivery
  regression passed; the accepted reference checkout and drift checker resolved
  exactly to `bbc1a0d0`, leaving 46 commits.
- `2026-08-20`: Commit `31298e5e` affects only an upstream Speedtest example
  with no Rust equivalent. The reference checkout and drift checker resolved
  exactly to `31298e5e`, leaving 47 commits; the unchanged `RNS` tree remained
  `c0308afed73dfe6aa997117428c614b5f7ab47ff`.
- `2026-08-20`: Commit `e31c570d` is structurally covered by distinct typed
  tunnel/path expiry fields. The differing-expiry persistence round-trip passed;
  the accepted reference checkout and drift checker resolved exactly to
  `e31c570d`, leaving 48 commits.
- `2026-08-20`: Commit `9b4947ef` is deferred with explicit scope: generated
  local destination ratchets are not yet implemented, while the existing
  received-ratchet store is a different protocol direction. The reference
  checkout and drift checker resolved exactly to `9b4947ef`, leaving 49
  commits; formatting and warning-free host lint passed.
- `2026-08-20`: Commit `0d9bf5b8` is structurally covered by Rust's compile-time
  local-name checking and typed rncp transfer state. Existing rncp tests passed;
  the accepted reference checkout and drift checker resolved exactly to
  `0d9bf5b8`, leaving 50 commits.
- `2026-08-20`: Commit `c6f9ef10` has no local Android BLE client equivalent.
  The reference checkout and drift checker resolved exactly to `c6f9ef10`,
  leaving 51 commits; formatting and warning-free host lint passed.
- `2026-08-20`: Commit `90ac6262` is structurally covered by Rust's collect-then-
  remove link cleanup. The four-pending-link regression passed with every
  deregistration observed; the accepted reference checkout and drift checker
  resolved exactly to `90ac6262`, leaving 52 commits.
- `2026-08-20`: Commit `0c410277` is structurally covered by Rust's separate
  immutable payload and generated-part bindings. The multipart identity/proof
  regression passed; the accepted reference checkout and drift checker resolved
  exactly to `0c410277`, leaving 53 commits.
- `2026-08-20`: Commit `691211bf` is structurally covered by Rust's single-wait
  Backbone poll loop. The simultaneous two-client multiplexing regression
  passed; the accepted reference checkout and drift checker resolved exactly to
  `691211bf`, leaving 54 commits.
- `2026-08-20`: Commit `0ec51cce` integration reproduced Rust's zero-MTU MDU
  underflow before the fix. The full zero-signalling handshake then passed with
  default MTU/MDU on both peers; the accepted reference checkout and drift
  checker resolved exactly to `0ec51cce`, leaving 55 commits.
- `2026-08-20`: Commit `55755c6b` is structurally covered by independent RNode
  RSSI/SNR event handling. The SNR-without-RSSI regression passed; the accepted
  reference checkout and drift checker resolved exactly to `55755c6b`, leaving
  56 commits.
- `2026-08-20`: Commit `72ba27d6` is structurally covered by Rust's two-phase
  cancel-then-retain implementation. The bidirectional multi-resource
  regression passed; the accepted reference checkout and drift checker resolved
  exactly to `72ba27d6`, leaving 57 commits.
- `2026-08-20`: Commit `6c1182c2` is structurally covered by Rust's explicit
  inbound-event metadata propagation. The focused known-destination regression
  passed with RSSI and SNR assertions; the accepted reference checkout and
  drift checker resolved exactly to `6c1182c2`, leaving 58 commits.
- `2026-08-20`: Commit `ce81b339` required no additional code beyond local
  `085b396`; the all-tag-position HMAC regression passed with the exact
  reference checkout at `ce81b339`, and the drift checker reported 59 commits
  remaining.
- `2026-08-20`: Commit `3db15dae` integration passed all 71 `rns-crypto` unit
  tests, 11 crypto exercise tests, 11 interoperability tests, doc tests,
  formatting, and warning-free host lint. The accepted reference checkout and
  drift checker both resolved exactly to `3db15dae`, leaving 60 commits.
- `2026-08-20`: Commit `38a73f95` integration passed `cargo test -p rns-net
  --all-features` (864 unit tests, 54 network E2E tests, 23 hook E2E tests,
  IFAC/Python interop, fixture suites and doc tests), `cargo test -p rns-cli
  --bin rnstatus`, exact-target Python/Rust TCP interop with the reference
  checkout at `38a73f95`, and warning-free `scripts/lint-host.sh`.
- `2026-08-20`: Daily drift check refreshed both remotes successfully through
  R-Net Istanbul. Canonical rGit was 63 commits ahead; the GitHub mirror was
  behind the accepted baseline. Audit inventory opened; no parity acceptance
  or implementation claim was made.
