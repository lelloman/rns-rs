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
| 34 | `636012bbe515be1692e03a78fe7e55363d0753c1` | Cleanup | Integrated | Successful authenticated LRPROOF path rebalances now log on the dedicated pathing target |
| 35 | `1a70bd3cd1390c0e27edc0f5ec1626553e84c17d` | Added queue drop stats | Integrated | Cumulative total and per-class drops are exposed as upstream-compatible RPC fields and rendered by `rnstatus` |
| 36 | `503bd6c87bda7780f613255257ab0095eb57661d` | Improved PR ingress limiter | Integrated | PR burst deactivation has cooldown hysteresis and queued ingress-limited classification survives through dispatch |
| 37 | `7c912d0936be42bccb75163c8914991de42fbf8e` | rnstatus: use proper stats | Structurally covered | Native `rnstatus` already renders announce and path-request pressure from `aqpressure` and `pqpressure` with distinct-value coverage |
| 38 | `731a63b01b255e270f9a4a962b7b837950863235` | Transport: update interface_hashes_updated_at timestamp | Structurally covered | Rust maintains an interface-ID→hash map on registration/removal and snapshots it directly, with no throttled full lookup or timestamp |
| 39 | `d825e39379ebee2c69f0197567045eb5bd0e56e0` | Transport: fix updating announce_queue | Structurally covered | Rust replaces the matched queue vector slot directly; a multi-entry regression proves a newer duplicate cannot overwrite the trailing entry |
| 40 | `40a862acbd870cec0c803ed8726027b94a0e4150` | Break loop on existing entry in announce queue | Structurally covered | Rust's `.position()` stops at the first destination match; a corruption-tolerance regression pins first-match replacement |
| 41 | `338173802d5a0e21515036512180d421c7d3544a` | Transport: fix destination_hash check in pending_discovery_prs | Structurally covered | Rust has no compound-entry pending transmit deque; exact duplicate tags are suppressed and discovery response state is keyed directly by destination hash |
| 42 | `0e2041c8372b33fd9d60114b0b1305cff836eef4` | BackboneInterface: update timestamps in ic checks | Structurally covered | Backbone child burst counts, active state, and earliest activation are computed fresh under the queue-state lock with no timestamped caches |
| 43 | `6cd5be18ec69a3f5e4dcd7e9ff12fa78eb21f5ef` | Transport: slice discovery_pr_tags to the end | Structurally covered | Rust evicts one oldest tag before appending and retains exactly the configured capacity; the FIFO regression now asserts every surviving tag including newest |
| 44 | `39e3854daca7b29c585ebaa0dee412ccd429d1e0` | Link: reset watchdog if exception happens in receive | Structurally covered | Rust has no receive watchdog mutex; malformed packets return normally, and a regression proves a subsequent valid packet is accepted on the same link |
| 45 | `acecc1f4907483927ed001d5c09ef8e61278dd96` | Error logging | Structurally covered | The changed message belongs to Python's catch-all Link receive exception boundary; Rust uses typed error branches and has no equivalent diagnostic |
| 46 | `c95bb551ab2c5e702efe4fa77ae35c568e607b3b` | Transport: handle exceptions in inbound() | Structurally covered | Rust rejects malformed frames through typed parser branches; an event-loop regression proves the immediately following valid frame is still dispatched |
| 47 | `db7daa4d9412e98273ce58d47286f36afce1d5ae` | Method naming | Structurally covered | Private Python `process_inbound` becomes `preprocess_inbound`; Rust's private boundary is independently named `handle_classified_frame_event` |
| 48 | `65222e0de8355fa4e7bfd6fe6ad76116b155aeeb` | Resource: align indexes in receive_part with request_next | Integrated | Resource part matching now searches from `consecutive_completed_height + 1`, exactly matching the requested window and including its tail |
| 49 | `2e9443ffe2f6e130cae094ebc898c02d8cbde56e` | Fixed typo | Structurally covered | Corrects `EPOLL_IN` to `EPOLLIN` in a Python Backbone warning; native diagnostics contain neither spelling |
| 50 | `0c0034f1ae81e2475c6f43dee6537b6d29e7691b` | Tuned burst stats throttle | Structurally covered | Python's cached aggregate refresh drops from 2.0s to 0.95s; Rust computes every Backbone child aggregate live with no throttle |
| 51 | `df80181006882f035e36a6e4673118bd7d13191c` | Utilize full link MDU in RawChannelWriter | Structurally covered | Rust's writer accepts Link MDU and subtracts the 6-byte channel envelope plus 2-byte stream header exactly once; an exact-boundary regression pins full utilization |
| 52 | `77a1bb9b194a0e1199131c3ca9f1f01b42885526` | Consistency | Structurally covered | Native `rnsh` already deducts the channel envelope and stream header once; its chunking regression now asserts that a full packed message exactly fills Link MDU |
| 53 | `954567c581f63b20b85863f1ecf2fa3044d64ebe` | Allow disabling link MTU discovery | Integrated | `[reticulum] link_mtu_discovery = No` now omits MTU signalling while default/true retain it, without changing public programmatic constructors |
| 54 | `49918c7e1d524e4abf61b5714b3b5bd66350ae1b` | Updated docs | Non-runtime | Adds Python API documentation for the existing per-hop timeout constant and first-hop estimator; Rust already documents its corresponding constant and formula |
| 55 | `6738db54378821f27e2224bb014d6f5b04e9bc54` | Cleaned up deprecated logic block indent in relation to inbound processing refactor | Non-runtime | Removes an unconditional Python `if True:` wrapper and dedents its body; whitespace-insensitive diff contains no executable change |
| 56 | `49073fcca59561ce5ecbe56c99b36816ecbacfde` | Fixed invalid interface basis for extra link proof timeout calculation, thanks to Zenith | Integrated | Transported link tracking adds one MTU of serialization time from the outbound next-hop bitrate, not the receiving interface bitrate |
| 57 | `bde5611a0d6651e5c9e6357d7259770fdb4ff7d0` | Fixed missing interface.bitrate validation in extra link proof timeout calculation, thanks to Zenith | Integrated | The private timeout helper returns zero for absent interfaces, missing bitrate, and zero bitrate, and computes serialization time only for positive rates |
| 58 | `4b914fb9a4973b5b1452875b8d514876c85b89ae` | Include extra timeout for discovery PRs when slow interfaces are online, thanks to Zenith | Integrated | Recursive discovery PR retention uses the slowest positive interface bitrate for an MTU round trip plus per-hop allowance, with fixed-floor, missing-rate, zero-rate, clamp, and lifecycle coverage |
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

### 34. `636012bb` — Move link rebalance diagnostics to pathing

**Upstream change:** Changes the successful LRPROOF path-rebalance diagnostic
from generic debug logging to Reticulum's dedicated pathing level. Routing and
wire behavior are unchanged.

**Rust applicability:** Rust performs the same authenticated hop-count
rebalance and emitted the corresponding diagnostic at ordinary debug level.

**Local handling and evidence:** The successful rebalance now uses
`PATHING_LOG_TARGET` at trace, which models Reticulum's numeric pathing level.
The focused logging regression verifies that the event is hidden at numeric
debug level 6 and enabled at pathing level 7.

**Final disposition:** Integrated.

### 35. `1a70bd3c` — Add inbound queue drop statistics

**Upstream change:** Counts every insertion rejected by a full inbound queue,
exports cumulative total and per-class drop fields in management statistics,
and appends nonzero drop counts to `rnstatus` queue lines.

**Rust applicability:** Rust has the same four bounded inbound traffic classes,
management pickle dictionary, and queue-status formatter. Full-queue drops were
enforced but not counted or visible to operators.

**Local handling and evidence:** Added saturating cumulative counters under the
queue-state lock and exported `rxqtd`, `rxqdd`, `rxqad`, `rxqpd`, and `rxqild`.
Both silently dropped blocking sends and failed nonblocking sends are counted,
matching upstream's queue insertion point. Saturation regressions cover every
class, independent counters, totals, and persistence across a drain; RPC and
CLI regressions cover all five fields, zero suppression, and compatibility
when an older remote omits them. Native `rnstatus` documentation records the
new output.

**Final disposition:** Integrated.

### 36. `503bd6c8` — Improve path-request ingress limiting

**Upstream change:** Requires four consecutive below-threshold evaluations
after the hold period before a path-request burst becomes inactive, resetting
that cooldown when traffic rises again. It also carries ingress-limited queue
classification into path-request handling so queued work cannot escape if live
interface state changes before it drains.

**Rust applicability:** Rust independently classified inbound queues and later
re-evaluated ingress control during recursive path discovery. Queue class was
not retained by the public `Event` representation, and path-request bursts
deactivated on the first low evaluation after their hold period.

**Local handling and evidence:** Added the matching three-count cooldown state,
including upstream's fourth limited call that deactivates the state, and reset
it on renewed traffic. A private classified receive/dispatch handoff preserves
the queue class without changing the public `Event` enum or existing receiver
methods. The existing public path-request handler remains source-compatible and
delegates to a hidden classified entry point. Focused regressions cover full
cooldown, partial-cooldown reset, classification surviving state removal,
forced engine suppression with no live burst, and end-to-end driver dispatch
without an escaped recursive request.

**Final disposition:** Integrated.

### 37. `7c912d09` — Use independent queue pressure fields

**Upstream change:** Fixes two `rnstatus` copy-and-paste errors that rendered
announce and path-request pressure from the data queue's `dqpressure` field
instead of `aqpressure` and `pqpressure`.

**Rust applicability:** The native formatter already maps all five queue lines
to independent pressure fields. Its regression intentionally uses different
values for total, data, announce, path-request, and ingress-limited pressure,
so substituting the data field would fail both affected assertions.

**Local handling and evidence:** Re-ran the focused `rnstatus` queue formatter
tests without changing code. No additional regression would cover a distinct
behavioral branch.

**Final disposition:** Structurally covered.

### 38. `731a63b0` — Refresh persistence interface-hash throttle

**Upstream change:** Updates a local timestamp after refreshing the set of live
interface hashes during path-table persistence. Without it, every later entry
after the two-second boundary recomputes all interface hashes instead of
honoring the intended throttle. Persisted content is unchanged.

**Rust applicability:** Rust maintains interface hashes incrementally in a
`BTreeMap` as interfaces register and deregister. A persistence snapshot looks
up each path's receiving interface directly in that map; there is no full hash
scan, throttle timestamp, or equivalent stale-cache control flow.

**Local handling and evidence:** The existing snapshot regression proves that
registered paths receive the correct interface hash, while a path whose
interface is absent is skipped. No code or new test is needed for the
Python-only recomputation bug.

**Final disposition:** Structurally covered.

### 39. `d825e393` — Update the matched queued announce

**Upstream change:** When a newer announce duplicates a queued destination,
updates `existing_entry` instead of the loop variable left pointing at the
last queue item. The bug could overwrite an unrelated trailing announce while
leaving the intended entry stale.

**Rust applicability:** Rust locates the duplicate's vector index and assigns
the replacement to that exact slot. It never retains or mutates a loop binding.
The prior deduplication test used only one destination and therefore did not
pin the specific multi-entry failure shape.

**Local handling and evidence:** Added a regression with a matching first entry
and unrelated trailing entry. A newer duplicate must replace the matched
entry's time, hops, emission timestamp, and raw bytes while leaving every field
of the trailing entry unchanged.

**Final disposition:** Structurally covered.

### 40. `40a862ac` — Stop queued-announce lookup at first match

**Upstream change:** Breaks the announce-queue scan immediately after finding a
matching destination, avoiding needless traversal and ensuring the first match
is the selected entry if duplicate corruption is already present.

**Rust applicability:** Rust uses iterator `.position()`, which stops at the
first matching vector element by definition. Normal insertion prevents new
duplicates, but the public queue entries can represent pre-existing corrupted
state in tests or callers.

**Local handling and evidence:** Added a corruption-tolerance regression with
two pre-existing entries for the same destination. Inserting a newer announce
must update only the first entry while leaving the second duplicate unchanged.

**Final disposition:** Structurally covered.

### 41. `33817380` — Compare pending discovery destinations correctly

**Upstream change:** Builds a destination-only view of compound
`[destination_hash, blocked_interface]` pending transmission entries before
testing membership. Comparing a bare hash to whole list entries never matched,
so duplicate destinations could consume queue capacity and be retransmitted.

**Rust applicability:** Rust does not stage recursive discovery transmissions
in a compound-entry deque. Eligible interface actions are emitted directly;
the discovery-tag set rejects an exact repeated request before forwarding, and
outstanding response state is a `BTreeMap` keyed directly by destination hash.
The representation mismatch that caused the Python bug does not exist.

**Local handling and evidence:** Re-ran the focused duplicate discovery request
regression, which proves the repeated tag emits no second action and occupies a
single tag entry. No production or new test change is required.

**Final disposition:** Structurally covered.

### 42. `0e2041c8` — Refresh Backbone ingress-control cache timestamps

**Upstream change:** Updates six two-second cache timestamps after computing
Backbone child announce/path-request burst counts, active states, and earliest
activation times. Missing assignments caused every call after the first cache
window to rescan all spawned interfaces.

**Rust applicability:** Rust stores dynamic child ownership and burst activation
state in the prioritized queue. Every Backbone aggregate query takes the state
lock and computes current counts and minimum activation times directly. There
are no cached aggregate fields or refresh timestamps.

**Local handling and evidence:** The existing mixed-parent regression covers
independent announce/path-request counts, earliest activation selection,
unrelated parents, and immediate disconnect cleanup. No code or new test is
needed for the absent cache mechanism.

**Final disposition:** Structurally covered.

### 43. `6cd5be18` — Retain the newest discovery request tag

**Upstream change:** Removes an end index of `len-1` from the discovery-tag
retention slice. The old exclusive bound retained only `max-1` entries and
discarded the newest tag; slicing to the end preserves exactly the newest
configured maximum.

**Rust applicability:** Rust uses a `VecDeque` plus membership set. At capacity
it pops exactly one oldest tag, removes that tag from the set, then appends the
new tag. No slicing or exclusive-end arithmetic is involved.

**Local handling and evidence:** Strengthened the bounded FIFO regression to
assert that the newest tag survives the first eviction and remains present
after a second eviction, while precisely the expected oldest tag is absent.
The test also pins the exact configured length after each insertion.

**Final disposition:** Structurally covered.

### 44. `39e3854d` — Release the Link receive watchdog after exceptions

**Upstream change:** Wraps Python's internal link receive implementation in a
`try`/`finally` boundary so `watchdog_lock` is cleared even when packet handling
raises. Previously an exception could leave the watchdog permanently locked
and prevent its maintenance loop from progressing.

**Rust applicability:** Rust has no receive watchdog lock or per-link receive
worker. `LinkManager::handle_local_delivery()` runs synchronously on the driver
thread, rejects malformed packet framing with an empty action set, and maps
fallible link parsing and decryption to explicit error branches. Returning from
one delivery therefore leaves no lock state that can block a later delivery.

**Local handling and evidence:** Strengthened the invalid-encrypted-context
regression to deliver malformed ciphertext across every encrypted receive
context and then deliver a correctly encrypted generic packet through the same
link manager. The valid payload must still produce `LinkDataReceived`, pinning
the recovery property addressed upstream.

**Final disposition:** Structurally covered.

### 45. `acecc1f4` — Include the Link in receive exception logging

**Upstream change:** Adds the Python Link object's identity to the catch-all
receive exception message introduced by the preceding commit. Control flow and
protocol behavior are unchanged.

**Rust applicability:** Rust has no catch-all Link receive exception boundary
or its associated generic log message. Packet framing, link parsing, and
decryption failures are handled by typed result branches, with context-specific
diagnostics where useful. There is therefore no corresponding string to amend.

**Local handling and evidence:** No production code or new test is appropriate
for a diagnostic that does not exist. The preceding malformed-then-valid
same-link regression continues to cover the underlying receive recovery
behavior.

**Final disposition:** Structurally covered.

### 46. `c95bb551` — Contain failures at the Transport inbound boundary

**Upstream change:** Splits Python's inbound processing into a wrapper and
internal implementation, catching and logging exceptions at the wrapper so a
malformed or otherwise failing packet cannot escape the inbound callback.

**Rust applicability:** Rust's inbound pipeline does not raise language-level
exceptions for packet parsing or validation. The driver constructs a borrowed
`InboundFrame`, and `TransportEngine` rejects malformed bytes through explicit
empty-action and result branches. The driver event loop therefore remains
available for the next queued frame.

**Local handling and evidence:** Strengthened the driver inbound regression to
queue a one-byte malformed frame immediately before a valid signed announce on
the same interface. Running the driver must still dispatch exactly one announce
callback, demonstrating that invalid input is contained to its own delivery.

**Final disposition:** Structurally covered.

### 47. `db7daa4d` — Rename the private inbound implementation method

**Upstream change:** Renames the private implementation called by Python's
exception-handling `inbound()` wrapper from `process_inbound()` to
`preprocess_inbound()`. The body and behavior are unchanged.

**Rust applicability:** Rust does not expose either Python method. Its private
driver entry is `handle_classified_frame_event()`, named for the additional
ingress-classification state it accepts. Renaming it to mirror a private Python
identifier would not improve source or protocol compatibility.

**Local handling and evidence:** No production or test change is appropriate
for a private, language-specific rename with an unchanged upstream `RNS`
behavioral tree aside from the identifier edit. The preceding driver recovery
regression remains valid.

**Final disposition:** Structurally covered.

### 48. `65222e0d` — Align received Resource part indexes with requests

**Upstream change:** Starts `receive_part()` hash matching one index after the
consecutive completed height, matching `request_next()`. The previous window
included the already-completed index and excluded the requested tail; it also
removes a redundant one-step height update before the existing forward scan.

**Rust applicability:** Rust carried the same arithmetic: `request_next()`
started at `consecutive_completed_height + 1`, while `receive_part()` started
at the completed index (or zero). A part at the inclusive tail of the requested
window could therefore be ignored, leaving outstanding progress inconsistent.

**Local handling and evidence:** Changed receive matching to use the exact
request start and retained the single forward scan that advances completed
height. A focused multi-part regression completes part zero, requests the next
window, delivers its tail before the intervening parts, and verifies that the
tail is stored and reported without incorrectly advancing contiguous height.

**Final disposition:** Integrated.

### 49. `2e9443ff` — Correct the EPOLLIN diagnostic spelling

**Upstream change:** Changes `EPOLL_IN` to the actual `EPOLLIN` constant name
in the warning emitted when Python Backbone file-descriptor registration fails.
Runtime behavior is unchanged.

**Rust applicability:** Rust's Backbone listener uses its own poll-loop error
handling and does not emit the changed Python sentence or the misspelled token.

**Local handling and evidence:** No production or test change is appropriate
for an absent diagnostic typo.

**Final disposition:** Structurally covered.

### 50. `0c0034f1` — Reduce the Backbone burst-stat cache throttle

**Upstream change:** Introduces a shared 0.95-second throttle for six Python
Backbone child burst aggregate properties, replacing their two-second refresh
intervals.

**Rust applicability:** Rust has no cached burst-stat property or refresh
interval. Each listener aggregate query reads current child queue state and
computes counts, active flags, and earliest activation immediately.

**Local handling and evidence:** No code change is needed for the absent cache.
The existing mixed-parent and disconnect-cleanup regressions pin immediate
visibility of state changes, a stronger freshness property than either Python
throttle.

**Final disposition:** Structurally covered.

### 51. `df801810` — Use the full Link MDU in RawChannelWriter

**Upstream change:** Changes Python's writer limit from `channel.mdu` minus the
combined stream-and-channel overhead to `channel.mdu` minus only the stream
header. Since `channel.mdu` already excludes its envelope, this removes a
second six-byte deduction. Compression and raw chunk limits now use the
per-channel result.

**Rust applicability:** Rust's `BufferWriter::write()` accepts the Link MDU,
not the already-reduced Channel MDU. `StreamDataMessage::max_data_len()`
subtracts `STREAM_DATA_OVERHEAD`, defined as the two-byte stream header plus
the six-byte channel envelope, exactly once. It therefore already implements
the corrected capacity and also naturally honors negotiated Link MDU values.

**Local handling and evidence:** Added an exact-boundary chunk regression. For
a deliberately small Link MDU, the first packed stream message plus the channel
envelope must equal the Link MDU exactly, while the next byte begins a second
message. All buffer tests cover reassembly and compression alongside it.

**Final disposition:** Structurally covered.

### 52. `77a1bb9b` — Use the full Link MDU in rnsh streams

**Upstream change:** Applies the preceding buffer fix to Python `rnsh` on both
initiator and listener sides, subtracting only the stream header from the
already-reduced Channel MDU when sizing compressed chunks.

**Rust applicability:** Native `rnsh` defines `CHANNEL_PAYLOAD_MAX` as Link MDU
minus the six-byte channel envelope, then `STREAM_CHUNK_MAX` as that value minus
the two-byte stream header. The overheads are already deducted exactly once,
and the same helper sends stdin, stdout, and stderr for both roles.

**Local handling and evidence:** Strengthened the large-payload chunking test
to assert that the first packed `StreamDataMessage` plus its channel envelope
equals Link MDU exactly. Existing assertions still prove complete payload
reassembly and EOF placement across multiple chunks.

**Final disposition:** Structurally covered.

### 53. `954567c5` — Allow disabling Link MTU discovery

**Upstream change:** Assigns both true and false values from the
`link_mtu_discovery` configuration option. Previously only true was applied, so
an explicit false could not override enabled process state.

**Rust applicability:** Rust always included the selected interface MTU in
outbound link requests and did not consume this upstream configuration key.
The core handshake already supports an absent MTU signal and falls back to the
protocol MTU, so only configuration and link creation needed wiring.

**Local handling and evidence:** Config-file startup now reads the option with
a true default, validates both boolean values, and configures the private link
manager. Disabled discovery passes `None` into the existing initiator engine,
omitting the three signalling bytes and retaining the protocol-default MTU.
Focused tests cover default, true, false, invalid, wrong-section, and packed
LINKREQUEST behavior. Public `NodeConfig` and `LinkManager::create_link()`
representations remain unchanged.

**Final disposition:** Integrated.

### 54. `49918c7e` — Document first-hop timeout estimation

**Upstream change:** Adds docstrings and generated API documentation for
Python's existing six-second default per-hop timeout and
`get_first_hop_timeout()` method, plus punctuation in `get_instance()`. No
executable expressions change.

**Rust applicability:** Rust already documents
`LINK_ESTABLISHMENT_TIMEOUT_PER_HOP` as six seconds and the public
`compute_establishment_timeout()` formula. Python's instance-oriented
first-hop estimator has no source-compatible Rust API, and this commit does not
introduce its behavior.

**Local handling and evidence:** No production code or test is appropriate for
an upstream documentation-only commit. Existing rustdoc accurately describes
the native timeout primitives.

**Final disposition:** Non-runtime.

### 55. `6738db54` — Remove the deprecated inbound wrapper indentation

**Upstream change:** Removes an unconditional `if True:` and its cleanup TODO,
then dedents roughly 750 lines of Python Transport inbound handling.

**Rust applicability:** A whitespace-insensitive diff reduces the commit to
only the two removed wrapper lines. Rust's inbound implementation is already
split across cohesive modules and has no unconditional wrapper block.

**Local handling and evidence:** No production or test change is appropriate
for a mechanically removed no-op branch. Formatting and existing Transport
coverage remain the relevant gates.

**Final disposition:** Non-runtime.

### 56. `49073fcc` — Base extra link-proof timeout on the outbound interface

**Upstream change:** Passes the outbound next-hop interface, rather than the
packet's receiving interface, to the extra link-proof timeout calculation for a
transported LINKREQUEST. The extra term is one MTU of serialization time at the
interface bitrate.

**Rust applicability:** Rust's transported-link proof timeout previously used
only the fixed per-hop term and omitted interface serialization time entirely.
Its interface table already carries the required bitrate and the forwarding
branch has resolved the outbound interface.

**Local handling and evidence:** Added the serialization term using the
outbound interface's positive bitrate. A focused transported LINKREQUEST
regression assigns deliberately different ingress and egress rates, verifies
both recorded interface roles, and pins the exact timeout to the slower
outbound rate.

**Final disposition:** Integrated.

### 57. `bde5611a` — Validate bitrate before calculating extra timeout

**Upstream change:** Requires both an interface and a truthy bitrate before
dividing to calculate extra link-proof timeout. Missing or zero rates now add no
extra term instead of raising or dividing by zero.

**Rust applicability:** The preceding native integration used `Option<u64>` and
already filtered zero, safely covering the upstream correction while adding
the timeout feature.

**Local handling and evidence:** Extracted the calculation into a private
transport helper and added direct boundary assertions for no interface,
`bitrate = None`, zero, and a positive rate with an exact result. The
end-to-end outbound-interface regression continues to cover call-site choice.

**Final disposition:** Integrated.

### 58. `4b914fb9` — Extend discovery PR timeout for slow interfaces

**Upstream change:** Records a per-request deadline for recursive discovery
path requests. When online interfaces advertise a bitrate, the deadline covers
an MTU round trip on the slowest medium plus the default per-hop timeout, while
never dropping below the existing fixed discovery timeout.

**Rust applicability:** Rust previously retained every recursive discovery
request for the fixed 15-second interval. On a sufficiently slow interface,
the forwarded request and returning announce can legitimately require longer,
causing the pending response route to be discarded prematurely.

**Local handling and evidence:** Added private per-destination deadlines without
changing the public `DiscoveryPathRequest` layout. The timeout uses the slowest
positive registered bitrate, clamps it to the protocol's five-bit minimum, and
safely falls back to the fixed timeout when no usable bitrate is known. Focused
tests pin fast, absent, zero, below-minimum, and mixed-interface calculations,
then prove a slow-medium request survives the old cutoff and is removed with
its deadline after the extended cutoff.

**Final disposition:** Integrated.

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

- `2026-08-21`: Commit `4b914fb9` extends recursive discovery-path-request
  retention for slow interfaces. Exact timeout boundaries and lifecycle
  cleanup, formatting, transport tests, host lint, exact checkout, and drift
  checks passed, leaving 5 commits.
- `2026-08-21`: Commit `bde5611a` validates bitrate before extra timeout
  division. Missing, zero, positive, and end-to-end interface-basis tests,
  formatting, host lint, exact checkout, and drift checks passed, leaving 6
  commits.
- `2026-08-21`: Commit `49073fcc` fixes the interface basis for transported
  link-proof timeouts. The distinct-ingress/egress bitrate regression,
  formatting, host lint, exact checkout, and drift checks passed, leaving 7
  commits.
- `2026-08-21`: Commit `6738db54` only removes an unconditional Python wrapper
  and dedents its body; the whitespace-insensitive diff confirms no behavior
  change. Formatting, host lint, exact checkout, and drift checks passed,
  leaving 8 commits.
- `2026-08-21`: Commit `49918c7e` only documents existing Python timeout APIs;
  native timeout rustdoc already covers its corresponding constant and formula.
  Formatting, host lint, exact checkout, and drift checks passed, leaving 9
  commits.
- `2026-08-21`: Commit `954567c5` makes false Link MTU discovery configuration
  effective. Config and packed-LINKREQUEST regressions, formatting, host lint,
  exact checkout, and drift checks passed, leaving 10 commits.
- `2026-08-21`: Commit `77a1bb9b` applies full-MDU sizing to Python `rnsh`,
  already present in native `rnsh`. The strengthened chunk/reassembly test,
  formatting, host lint, exact checkout, and drift checks passed, leaving 11
  commits.
- `2026-08-21`: Commit `df801810` removes a duplicate channel-overhead
  deduction already absent from Rust's Link-MDU-based writer. The exact-boundary
  regression, full buffer tests, formatting, host lint, exact checkout, and
  drift checks passed, leaving 12 commits.
- `2026-08-21`: Commit `0c0034f1` reduces Python's Backbone cache throttle,
  absent from Rust's live aggregate computation. Dynamic-state tests,
  formatting, host lint, exact checkout, and drift checks passed, leaving 13
  commits.
- `2026-08-21`: Commit `2e9443ff` only corrects a Python Backbone warning's
  `EPOLLIN` spelling, absent from Rust. Formatting, host lint, exact checkout,
  and drift checks passed, leaving 14 commits.
- `2026-08-21`: Commit `65222e0d` fixes Resource receive-window indexing that
  was also present in Rust. The new out-of-order tail regression, full receiver
  tests, formatting, host lint, exact checkout, and drift checks passed, leaving
  15 commits.
- `2026-08-21`: Commit `db7daa4d` only renames Python's private inbound
  implementation method. Formatting, host lint, exact checkout, and drift
  checks passed, leaving 16 commits.
- `2026-08-21`: Commit `c95bb551` contains Python exceptions at the Transport
  inbound boundary. Rust's typed rejection path plus the malformed-then-valid
  driver regression, formatting, host lint, exact checkout, and drift checks
  passed, leaving 17 commits.
- `2026-08-21`: Commit `acecc1f4` only enriches Python's catch-all Link receive
  exception message, which has no native equivalent. Formatting, host lint,
  exact checkout, and drift checks passed, leaving 18 commits.
- `2026-08-21`: Commit `39e3854d` guarantees Python's receive watchdog unlock
  after an exception. Rust has no equivalent lock; the malformed-then-valid
  same-link regression, formatting, host lint, exact checkout, and drift checks
  passed, leaving 19 commits.
- `2026-08-21`: Commit `6cd5be18` fixes an off-by-one retention slice absent
  from Rust's pop-front/append FIFO. The strengthened complete-set regression,
  formatting, host lint, exact checkout, and drift checks passed, leaving 20
  commits.
- `2026-08-21`: Commit `0e2041c8` fixes stale Backbone aggregate cache
  timestamps absent from Rust's live-state computation. Dynamic parent burst
  and cleanup tests, formatting, host lint, exact checkout, and drift checks
  passed, leaving 21 commits.
- `2026-08-21`: Commit `33817380` fixes compound-entry membership in a pending
  transmit deque absent from Rust. The duplicate discovery-request regression,
  formatting, host lint, exact checkout, and drift checks passed, leaving 22
  commits.
- `2026-08-21`: Commit `40a862ac` adds first-match loop termination already
  provided by Rust's `.position()`. The new duplicate-corruption regression,
  full announce-queue tests, formatting, host lint, exact checkout, and drift
  checks passed, leaving 23 commits.
- `2026-08-21`: Commit `d825e393` fixes wrong-entry queued-announce mutation
  already absent from Rust's indexed replacement. The new multi-entry
  regression, full announce-queue tests, formatting, host lint, exact checkout,
  and drift checks passed, leaving 24 commits.
- `2026-08-21`: Commit `731a63b0` fixes a Python persistence scan throttle that
  has no native equivalent. Snapshot interface-presence tests, formatting, host
  lint, exact checkout, and drift checks passed, leaving 25 commits.
- `2026-08-21`: Commit `7c912d09` fixes copied pressure keys already absent
  from native `rnstatus`. Distinct-value formatter tests, formatting, host lint,
  exact checkout, and drift checks passed, leaving 26 commits.
- `2026-08-21`: Commit `503bd6c8` adds PR limiter cooldown hysteresis and
  preserves queued ingress-limited classification through dispatch. Focused
  state, queue, engine, and driver regressions, full core/net library suites,
  formatting, host lint, exact checkout, and drift checks passed, leaving 27
  commits.
- `2026-08-21`: Commit `1a70bd3c` adds cumulative inbound queue-drop accounting,
  management fields, and `rnstatus` rendering. Per-class saturation, cumulative
  drain, RPC, CLI, formatting, host lint, exact checkout, and drift checks
  passed, leaving 28 commits.
- `2026-08-21`: Commit `636012bb` routes authenticated LRPROOF rebalance
  diagnostics through the dedicated pathing target. The focused filter
  regression, formatting, host lint, exact checkout, and drift check passed,
  leaving 29 commits.
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
