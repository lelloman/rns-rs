# Reticulum 1.5.0 Upstream Audit

## Scope and Baseline

- audit date: `2026-08-24`
- previous accepted version: `1.4.2`
- previous normative commit: `4fc8e03d658ed87019b8ad6c7ce7827dc76f0e45`
- target version: `1.5.0`
- target tag or ref: `rgit/master`
- target normative commit: `b3ef214e7257a1e5b674f8b1f002f05e78b090b8`
- target root tree: `63406bb90d4d3125a9cba3b0811297d58435f4e2`
- target `RNS` tree: `6aa6691d8dcca0d9aa7b6f7affed803185d20e69`
- version assertion: `RNS.__version__ == "1.5.0"`
- audited range: `4fc8e03d658ed87019b8ad6c7ce7827dc76f0e45..b3ef214e7257a1e5b674f8b1f002f05e78b090b8`
- commits in range: `73`
- repositories checked: canonical rGit `rgit/master` and GitHub mirror `origin/master`
- local integration range: `88b7098..2e67683` on `dev`

All 73 canonical commits are integrated, structurally covered, deferred,
or non-runtime as recorded below, and the accepted baseline is
`b3ef214e7257a1e5b674f8b1f002f05e78b090b8`. A fresh 2026-08-21 refresh found
five newer rGit commits after commit 68 through
`b3ef214e7257a1e5b674f8b1f002f05e78b090b8`; all five now have final
dispositions below. The GitHub mirror tip
`b48b96e61676504e0a4e527b33b9a0b4495c6872` remains behind the accepted
baseline, so the remotes do not agree.

A fresh 2026-08-22 refresh found eight additional canonical rGit commits after
the accepted baseline, through
`fc69f323a82a0f3d76b2b3b90d16850ff25b4cf1`. The GitHub mirror remains at
`b48b96e61676504e0a4e527b33b9a0b4495c6872`, behind the baseline. All eight
have now been reviewed in ancestry order and have final dispositions below.
Each maps to exactly one ancestry-ordered rns-rs commit in
`88b7098..2e67683`. This does not promote the accepted baseline or claim that
the complete promotion gates have passed.

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
| 59 | `68cda4a8557f223ed2ac8e4907968a0037424c30` | Added discovery_lxmf_address to documentation | Integrated | Native interface-discovery documentation explains the optional operator LXMF hash, format, remote display, coordination purpose, and invalid-value behavior |
| 60 | `9ae3db169ed464d37f90ac6371af09708ca96eda` | Fixed medium_timeout init | Structurally covered | Rust represents the optional bitrate before calculating a numeric timeout and safely records the fixed 15-second deadline when no interface reports a usable rate; direct and end-to-end regressions cover the boundary |
| 61 | `05e6717d210aa330a0ed6def109c47d3f3cfc71d` | Fixed rngit file resource operations failing on Windows | Structurally covered | Native resource callbacks deliver owned bytes, so `rns-git` never moves an open transport temporary file; fetch E2E writes the materialized bundle and validates its refs |
| 62 | `d478e380c93dc892879d3800adee321a6b5733aa` | Use sets for discovery pr tags | Structurally covered | Rust already combines a `BTreeSet` membership index with an exact bounded FIFO; the regression proves duplicates neither grow nor refresh retention order |
| 63 | `4ab0755d0acc19eb45f729257b8976fde61146bf` | Changed PR ingress accounting point | Integrated | Driver ingress statistics are recorded only after core accepts a valid unique tag, preventing duplicate replays from inflating frequency or triggering limiting |
| 64 | `386ef1f370c4f9cdb38957c7119c3cdf3abb6d8e` | Transport jobs optimizations | Integrated | Path-request gate state is registered before later processing, expires after 45 seconds, and refreshes for local outbound requests; unique-tag retention is 8,192, while Python lock/thread changes are structurally absent |
| 65 | `614e7bd834fb69675965094cd01ed9255f36d6aa` | Improved path request handling, batch same-destination PRs when existing in-flight path request exists | Integrated | Same-destination unique requests share one recursive search, retain all non-limited requester interfaces, and fan the path response back to each; tag retention is 16,000 |
| 66 | `74883369858303e89aa7861bdb64b1755b92a1c4` | Use test runner config loglevel setting | Non-runtime | Removes a hard-coded verbosity override from one upstream Python test fixture; native Rust tests have no equivalent override |
| 67 | `5f2f4438d0412843167f43091f54af7fe39a8ed9` | Added detailed announce and path request traffic stats | Integrated | Accepted announce/unique-PR byte accounting, current-window rate sampling, listener aggregation, local/remote status fields, and `rnstatus` flow percentages/totals with focused regressions |
| 68 | `880db0a7b7776d407e44bb0a93541317a1f75487` | Added active links stat to rnstatus | Integrated | Separate total and validated/established active counts across transport and managed links, local RPC, and accurate `rnstatus -l` rendering with state/display regressions |
| 69 | `6ba7cc8cb451b4e187abe7c1a2ee8bf0480086f8` | Added data flow speeds to rnstatus | Integrated | Detailed totals derive clamped directional non-pathing data percentages and speeds from total minus announce/PR current rates, with enabled/disabled rendering coverage |
| 70 | `42f6d64b9cc379aad73a6a8927dadec91f7031d7` | Implemented per-interface protocol violation tracking | Integrated | Per-interface protocol/IFAC/filter counters at typed rejection boundaries, pre-validation link forwarding guard, listener aggregation, status/RPC fields, CLI rendering/sorting, and focused rejection regressions |
| 71 | `60eb0509f25632dbc6e4cea07751eca70b80a8a5` | Signal blackholed status in validate_announce | Integrated | Invalid-announce accounting distinguishes blackhole policy drops for synchronous and asynchronous verification; tampered blackholed announce regression |
| 72 | `cab513fa31c70e52ba735ec0668d22b148522679` | Logging | Structurally covered | Native code has no misleading batching diagnostic and already restricts batching to non-ingress-limited requests, covered by limiter/batching regressions |
| 73 | `b3ef214e7257a1e5b674f8b1f002f05e78b090b8` | Added total announce/pr frequency stats | Integrated | Aggregate announce/PR RX/TX frequencies from existing bounded interface estimators, local/remote status fields, and detailed CLI totals with query/RPC/formatter regressions |

### Post-baseline drift observed 2026-08-22

| # | Upstream commit | Subject | Final disposition | Local evidence |
|---:|---|---|---|---|
| 74 | `7b8923b61f2d075ac6819cfd2cccf3f7d93df1a4` | Added protocol violations | Integrated | Local `88b7098`; packet-filter rejections distinguish protocol-invalid announce/transport combinations from duplicate-filter hits |
| 75 | `378840a6bf827063d7558417301d00a33ea9eeb5` | Added total announce/pr count stats per interface | Integrated | Local `8176dfb`; saturating interface counts, aggregation, RPC/remote status, `rnstatus`, and sustained burst timing |
| 76 | `2b1b9589f1341dc8adca42b210bab48c6e19789b` | Added medium bitrate based timeout calculation helpers and RPC functions and added dynamic timeout calculation to rngit, by Zenith | Integrated | Local `131b4d8`; slowest-interface and timeout core/query/RPC APIs plus dynamic `rns-git` deadlines |
| 77 | `4c69b376b2a7ef8cf5771ab62034428a7cf77a2a` | Added adaptive timeouts to utilities, by Zenith | Integrated | Local `b331091`; adaptive `rncp`, `rnx`, `rnprobe`, and remote-management deadlines |
| 78 | `b1aa527861137e92942ab85753b99c14795cdb48` | Track in-flight path requests separately | Structurally covered | Local `447e386`; dedicated request gate and strengthened learned-path regression |
| 79 | `3885d2329350451e822705ea13b8625aedf8938a` | Added protocol violations | Integrated | Local `5bce6cd`; excess PR data, malformed link requests, and invalid tunnel synthesis count violations |
| 80 | `6b2c5bcf0bc8308f94c9387de54eba4d1122d009` | Don't reprocess IFAC for held announces | Structurally covered | Local `ddd6723`; driver-only IFAC boundary documented on held announce bytes |
| 81 | `fc69f323a82a0f3d76b2b3b90d16850ff25b4cf1` | Cleanup | Integrated | Local `2e67683`; corrected no-IFAC classification with focused regression; queued sends already use normal dispatch |

### Additional drift observed 2026-08-23

A fresh two-remote refresh found eleven commits after `fc69f323`, through
`b123a756b0e203070f7ff6325aaa2168504e0d82`. Canonical rGit and the GitHub
mirror now agree at that tip. These entries are an inventory only: their
dispositions remain provisional until each complete diff is reviewed and
mapped to exactly one rns-rs commit under the per-commit integration procedure.

| # | Upstream commit | Subject | Disposition | Evidence or review scope |
|---:|---|---|---|---|
| 82 | `091e021d0ecd121b71b288e1fd946597dac44963` | Early return on excessive hop count packets | Integrated | Local `c549c0c`; transport rejects hop counts at `PATHFINDER_M` before routing or hash-list insertion; exact boundary regression |
| 83 | `2aed542e61020ed3ad2d719e90266038f3d30f35` | Get path_entry directly in _outbound | Structurally covered | Local `02f228c`; Rust already resolves the primary path through one immutable map lookup; removed-path fallback regression |
| 84 | `6f6751d6b6b59b67698b318ae0611a7f528be441` | Fixed PR egress limiter not preemptively considering potential outbound, and added late egress check to avoid state race under high incoming PR load | Integrated | Local `576864f`; two-sample prospective-rate gate plus live pre-dispatch recursive-request check |
| 85 | `b397870c975c8d36d09153e5444c97dd9502f3c5` | Log levels | Structurally covered | Local `1985606`; absent usable interface bitrates are a normal silent `None` fallback with focused empty/zero-bitrate assertions |
| 86 | `561e2f23e11350cf0a5ad7aa5fccb566d2925242` | Updated changelog | Non-runtime | Local `6dd92d7`; upstream RNS 1.5.0 release-note text only; runbook now records changelog handling policy |
| 87 | `e32d4df754a7b87b1bf1bb0d08675d12ff505ae6` | Updated docs | Integrated | Local `26323ea`; native Rust API documentation now states bitrate and medium-timeout return/fallback semantics |
| 88 | `d25ea38c8402e67e4f458d33646d26cad2f6f6cb` | Added PPS stats to rnstatus. Don't count local shared instance in traffic totals. | Integrated | Local `ef51d1d`; sampled/aggregated PPS, RPC and remote-management fields, `rnstatus -p`, and local shared-instance exclusion |
| 89 | `26e3ca4f2beca7366a812b25f57e1033e6c23b96` | Added shared medium hints to interfaces | Integrated | Local `211e677`; native registry type classifier covers all upstream shared-medium interface classes for later metadata consumers |
| 90 | `1bad7f5807f3945b77664eb6f78de8183b21c816` | Remove from previous hashlist under transport edge case handling | Integrated | Local `fcab026`; stale-interface active-link arrivals are dropped and removed from the native bounded FIFO so the current-route copy remains admissible |
| 91 | `bfab2964b686fbed07277eab3004b4b97cdee4df` | Fixed rnstatus including not-yet-blocked IPs in blocked IP list output | Structurally covered | Local `b12b919`; native count and list both require `flap_count > grace`, with mixed blocked/grace-period regression |
| 92 | `b123a756b0e203070f7ff6325aaa2168504e0d82` | Added transport implementation name and version to discovery information requirements | Integrated | Local `14714db`; discovery announces carry `0xFD = "rns-rs"` and `0xFC = rns-net package version`, while older payloads remain accepted |

### Additional canonical drift observed 2026-08-24

A fresh two-remote refresh found 25 additional canonical rGit commits after
`b123a756`, through `0e070aacf655e1866ec1e469881dc91a2a3db89e`.
The GitHub mirror remains at `b123a756b0e203070f7ff6325aaa2168504e0d82`,
so the remotes no longer agree. The accepted baseline remains `b3ef214e`; the
drift checker therefore reports 44 commits ahead in total, comprising the eight
already mapped commits 74–81, the eleven 2026-08-23 inventory entries, and the
25 new entries below. These dispositions are provisional until each complete
diff is reviewed and mapped to exactly one rns-rs commit.

| # | Upstream commit | Subject | Provisional disposition | Review scope |
|---:|---|---|---|---|
| 93 | `2058596dd19461753d45a221de445edf0d56ca99` | Check before cancel outgoing | Structurally covered | Local `4f816a0`; manager-owned removal plus state-guarded cancellation makes a repeated all-resource cancel an explicit no-op |
| 94 | `88c629e3ad148bda4fd9b645a4075c72218fbd8f` | Logging and MTU adjustments | Integrated | Local `e12d936`; 500 Mbps/131072-byte accepted Backbone peers, 100 Mbps/1 MiB standalone clients, and 262144-byte Local metadata with focused defaults/connection tests |
| 95 | `84597f31861ee1bc85a3db4dda7acc52228c2716` | Added MTU output to rnstatus | Integrated | Local `e6a3350` exports per-interface MTU through status RPC and renders it beside bitrate while accepting older payloads without the field |
| 96 | `602085a1cd3560d3ddbdd0cce61d61942059af1c` | Extract inbound IFAC handler | Structurally covered | Local `8d1cb5f` pins the dedicated native inbound IFAC handler's stateless reject-then-accept behavior |
| 97 | `e806ae5837c768bbaa100daa88b3b66cc9881be9` | Optimized inbound IFAC handling | Structurally covered | Local `6e2ec6c` records that native inbound unmasking already performs one allocation and one linear XOR/copy pass |
| 98 | `aef9e5b41615ceb113ec8cf33cae938480855b0c` | Extract outbound IFAC handling | Structurally covered | Local `495743e` pins the dedicated native outbound helper's deterministic, input-preserving behavior |
| 99 | `7347034f9a531ea08e683b0b2d0e9e76bd3e71e1` | Optimized outbound IFAC handling | Structurally covered | Local `33fe321` records that native outbound masking already uses one allocation and one linear XOR/copy pass |
| 100 | `929aba02821a537a260f53ed59de2e9066bd0743` | Added IFAC tests | Integrated | Local `28f5c22` ports the deterministic size/tag/pattern matrix, invariants, round trips, and corruption rejection |
| 101 | `cfddb9abe6aff62ed36c80e25c8a49d43d552f6d` | Added HKDF tests | Integrated | Local `c22173b` adds all three RFC 5869 SHA-256 vectors alongside existing error and Python-fixture coverage |
| 102 | `171868c6cb0cc926f2286711d92b700002a586b6` | Added IFAC and HKDF tests to test runner | Non-runtime | Local `89d2628` records Cargo's automatic module discovery; the full workspace command executes both suites without a registry |
| 103 | `5da0870e2aa5539ee744af2ba8db242414f957f2` | Optimized HKDF | Integrated | Local `7e2224f` reuses a pre-keyed HMAC state, streams expansion inputs, and pins parity across the 256-block counter wrap |
| 104 | `1c83e732ad8ce792b33936c1d8c996c3f2468cea` | Use optimized IFAC handlers | Structurally covered | Local `9347131` exercises the driver's sole optimized IFAC helpers on actual outbound and inbound frame paths |
| 105 | `956d688e1009ee617c06c64f5f99ca41ee0b9991` | Check before cancel incoming | Structurally covered | Local `f5246d2` pins repeated manager-owned incoming cancellation as an action-free no-op |
| 106 | `a9538e9fd1291fc0bd252e409d5776b87db7e04f` | Loglevel | Structurally covered | Local `62b1937` records that native MTU is fixed before registration and no runtime selection diagnostic exists |
| 107 | `3fdfe93ec744d0cd5026c4096bca3c1092777608` | Don't loop on attached interface packets | Structurally covered | Local `99178b0` proves an offline attached target neither transmits nor falls back to another online interface |
| 108 | `1694a17a75d239e41d9a5ac5c655213d43df4fef` | Full and configurable logfile rotation. | Integrated | Local `96adade` rotates standalone service logs at 30 MiB with nine retained archives through a configurable native policy |
| 109 | `9da66649761e375ab3ad07ce651a0064005c29c0` | Move log writing to a dedicated thread. | Integrated | Local `585b046` queues service log buffers to one named writer thread and supplies an ordering/flush barrier |
| 110 | `9302415f9e61897ff07b9b7bba5083ebfb5b536f` | Add live profiling results output to rnstatus. | Integrated | Local `89dad4b` adds process-global guard-based timing, local RPC and remote-status results, plus nested `rnstatus -z` rendering |
| 111 | `cf5d6a796ef12e40e57407e4c9c2eedacd19315e` | Rework profilers for running indefinitely. | Integrated | Local `2f388ce` bounds timestamped captures per tag/thread and publishes all-time plus 1/5/30/60-minute statistics and table output |
| 112 | `40281f91daac478d5ab15d36b9ac20dfa5eb5b04` | Decorator for profiling functions. | Integrated | Local `03a12ec` adds explicit-tag function/closure profiling adapters with default or custom retention and unwind-safe recording |
| 113 | `dca5b9639ea4d90b99675782eeec8ec7f797970b` | Limit total profiler captures per tag, not per thread; handle reentrant profilers; make stats time windows be non-overlapping. | Integrated | Local `45fd406` applies one shared tag limit, tracks in-flight/reentrant guards independently, and publishes disjoint live-window counts, sums, threads, and statistics |
| 114 | `9c2f424aaac0eb4a7545cb7731d630e7faf2b2a9` | Merge branch 'live_profiling' into live_profiler_merge | Structurally covered | Local `4aa1b0d` pins the merged function-to-MessagePack final profiling schema; the other-parent MTU/routing deltas remain covered by entries 106–107 |
| 115 | `1034d788286c2315e28491275f68cee87624a713` | Merge adjustments | Integrated | Local `c6e4966` mirrors the deliberate final reversal to synchronous 5 MiB/single-archive logging while retaining the merged profiling status path |
| 116 | `39899651ee5bb3de3bce49af06162329925aff12` | Merge adjustments | Non-runtime | Local `647f99d` mirrors the unused synchronization-import cleanup by narrowing the remaining daemon channel imports to the symbols actually used |
| 117 | `0e070aacf655e1866ec1e469881dc91a2a3db89e` | Ah well, of course. | Non-runtime | Local `18f1656` documents Rust's static module-resolution invariant and proves the profiler is available from the crate root without late imports |

### Subsequent canonical drift observed 2026-08-25

A fresh two-remote refresh after completing the requested 44-commit tranche
found 25 additional canonical rGit commits after the pinned target `0e070aac`,
through `d80245b62c7169f68995b2f11b30b971de7a5dbf`. The GitHub mirror remains at
`b123a756`, so the remotes still disagree. These entries are explicitly outside
the completed 44-commit target and form the next ordered tranche. They were
initially inventoried without being silently folded into entries 74–117; review
of this tranche resumed on 2026-08-26 and is complete through entry 134.

| # | Upstream commit | Subject | Provisional disposition | Review scope |
|---:|---|---|---|---|
| 118 | `7311dc85445fa13863fca288e3706d5c72abd738` | Reduced path table lock acquisitions in inbound processing | Structurally covered | Local `f330b6e`; exclusive mutable engine ownership avoids Python's path-table locks and repeated lookups, with absent-path LRPROOF rebalance regression |
| 119 | `629e4fde2d9095246952874d4b0ce3965b16d0b9` | Added hash map lookups for pending and active links | Structurally covered | Local `e7e182e`; one authoritative `HashMap<LinkId, ManagedLink>` indexes every link state and cleanup leaves no stale keyed destination |
| 120 | `d81421dad3badb7672ac2171e253af6643c5ecdd` | Avoid additional packet hashing under lock in inbound | Structurally covered | Local `7e8a4e6`; `RawPacket` computes its full hash once and derives every truncated reverse-route key from the cached prefix |
| 121 | `b9278ce352332a16508b2927e404e4f5dda806e8` | Added throughput benchmarker | Non-runtime | Local `28cc6f8`; benchmark-only mapping policy records scenario review and native Criterion evidence without treating Python private-state machinery as protocol parity |
| 122 | `5e013464da0c85f147ab8512edb93507e34e1df4` | Added throughput benchmarker | Non-runtime | Local `2781d3c`; separate upstream lineage adds the exact entry-121 benchmark blob, with policy requiring an independent mapping for patch-equivalent merge parents |
| 123 | `77f763258441fb9ce71db084703b64608559211d` | Avoid extra epoll modifies when EPOLLOUT already set | Structurally covered | Local `e095553`; native server poller tracks reads only and the cloned writer retries its own pending buffer without writable-interest modifications |
| 124 | `7e197542e52fe6af7cf4ac25bac0304b9710247b` | Updated througput bench | Non-runtime | Local `cebceae`; output-label changes and pasted machine measurements are observational unless paired with a reproducible environment and explicit regression budget |
| 125 | `516cb106c1dbd6b25475d19907a8e7435da35027` | Updated througput benchmarker | Non-runtime | Local `ecadb09`; comment-only result history is summarized with provenance in audits rather than copied into native harness source |
| 126 | `d044db29317d2a6490e21cdad5163161508a6537` | Cache announce signature validation | Integrated | Local `5037209` maps existing `b2fafb2`; bounded TTL cache skips repeat Ed25519 verification and binds cache keys to both destination and signature |
| 127 | `2d2167140dda3052c9ab468f8b38cbecc3566c94` | FP cache experiment | Structurally covered | Local `a869e2c`; exclusive native engine uses one keyed typed link entry without locks, linear searches, or denormalized cache invalidation |
| 128 | `f1117099021c357a1f9128ba8e22ef06591a46e2` | Updated througput benchmarker | Non-runtime | Local `209268b`; cross-language fast-path labels require behaviorally equivalent implementations before measurements are comparable |
| 129 | `17e980ff7982ee5e952f777488e70d11aea007e1` | Cleanup | Structurally covered | Local `5979f92`; upstream removes its denormalized forwarding-cache experiment, while native routing deliberately retains one authoritative typed link table |
| 130 | `38e9d1cdd48c83acb115bb166694409d919f2358` | Cleanup | Non-runtime | Local `1e0abaa`; complete diff is an indentation correction with no changed Python control flow or native behavior |
| 131 | `8221f82dc0439cea4009470b4a1133dd5272ca6e` | Cleanup | Structurally covered | Local `d8025d7`; exclusive engine ownership makes local-destination lookup lock-free, and an unroutable link fast-path miss is intentionally non-warning |
| 132 | `aba8d606dd0d4b1ff3be11b5b9c7d62ff25a49e5` | Cleanup | Non-runtime | Local `c4199c9`; removes only stale TODO text and whitespace around an unchanged unconditional return |
| 133 | `dea0124c5759185c60c5545601e72a9a5970f28c` | Reduced lock acquisition | Structurally covered | Local `baabb25`; announce and local-link destination reads share the native engine's exclusive processing turn and need no separate map lock |
| 134 | `d38a8de571421f4091b2e977c5864931bce4c01b` | Fixed f-strings for old snakes | Non-runtime | Local `8b75d72`; quote changes restore older-Python parsing while preserving profiler output and expose no Rust compatibility surface |
| 135 | `9f66b5a6a32bb9d2ef090c43904834828f39c49c` | Merge branch 'optimize' | Needs review | New post-target merge; complete parent/diff review required |
| 136 | `be4ee32908d2ab94a8f5de571f67a88407b1b15a` | Tuned queuelen defaults | Needs review | New post-target commit; complete diff review required |
| 137 | `dd204e11ce7aed7aa50307a67128e560477f8612` | Added 32k throughput run | Needs review | New post-target commit; complete diff review required |
| 138 | `be2ba7c2f3f7481760dd18c14aec75c86d65909a` | Tuned auto MTU configurration | Needs review | New post-target commit; complete diff review required |
| 139 | `47add6381d2a46d5b04a62e2cdcf58cf48808ad4` | Increase queues for throughput tests | Needs review | New post-target commit; complete diff review required |
| 140 | `0536b972d788e3a724393caa2d3acae2893a656a` | Tuned QUEUED_ANNOUNCES. Logging. | Needs review | New post-target commit; complete diff review required |
| 141 | `dcbc7638d07fe119a733e252d1b2c7a4691ae3fb` | Fixed RSSI/SNR reporting regression | Needs review | New post-target commit; complete diff review required |
| 142 | `d80245b62c7169f68995b2f11b30b971de7a5dbf` | Traffic class and violation handling | Needs review | New post-target commit; complete diff review required |

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

### 133. `dea0124c` — Reduced lock acquisition

**Upstream change:** Replaces two destinations-map lock/read sequences with
direct keyed lookups: one after announce validation and one while dispatching a
link request to a local destination. Lookup order and delivery conditions stay
the same.

**Rust applicability:** Native announce verification, destination-registry
reads, and local link-request delivery execute within one mutable transport
engine call. Exclusive ownership supplies the synchronization that Python's
shared class-level map otherwise needs.

**Local handling and evidence:** Local `baabb25` documents the lock-free keyed
registry invariant at announce and local-delivery lookup sites. All 653
`rns-core` unit tests and 56 crate integration tests passed, along with
formatting, diff checks, and warning-free host lint.

**Final disposition:** Structurally covered.

### 134. `d38a8de5` — Fixed f-strings for old snakes

**Upstream change:** Changes dictionary-key quotes inside six profiler
f-strings so Python versions predating relaxed f-string parsing accept the
source. Interpolated fields and rendered text are unchanged.

**Rust applicability:** This is source-language parser compatibility for an
upstream-only profiler. Rust does not parse or expose these Python f-strings,
and there is no wire, configuration, or output change to reproduce.

**Local handling and evidence:** Local `8b75d72` records how to classify
source-language compatibility fixes that preserve behavior. Complete diff
review and diff checks passed.

**Final disposition:** Non-runtime.

### 131. `8221f82d` — Cleanup

**Upstream change:** Replaces a warning for a link packet without an outbound
route with an extreme-level diagnostic and removes the destinations-map lock
around one keyed lookup. Packet routing and delivery conditions are unchanged.

**Rust applicability:** Native transport processes the destination registry
under an exclusive engine borrow, so its keyed lookup needs no independent
lock. A link entry that cannot route from the receiving interface is already a
quiet fast-path miss rather than an operator warning.

**Local handling and evidence:** Local `d8025d7` documents both invariants at
their native decision points. The cross-interface link-routing and local
delivery regressions passed, along with formatting, diff checks, and
warning-free host lint.

**Final disposition:** Structurally covered.

### 132. `aba8d606` — Cleanup

**Upstream change:** Removes blank whitespace and a stale TODO questioning an
unconditional return. The return existed before and after the commit, so no
executable control flow changes.

**Rust applicability:** Upstream comment and whitespace hygiene has no native
runtime, wire, configuration, or API surface.

**Local handling and evidence:** Local `c4199c9` records that removing stale
comments without executable changes is source hygiene rather than native
behavioral evidence. The complete diff and diff checks passed.

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

### 130. `38e9d1cd` — Cleanup

**Upstream change:** Corrects one over-indented pending-link proof block. The
stat reports broad line replacement, but the complete diff changes indentation
only; conditions, signature validation, path rebalance, hash insertion, and
proof delivery remain identical.

**Rust applicability:** Python source indentation has no native protocol or API
surface. The corresponding Rust proof handling is already expressed with
explicit lexical blocks and requires no behavioral change.

**Local handling and evidence:** Local `1e0abaa` adds workflow guidance for
classifying formatting-only cleanups only after checking their full diff for
hidden control-flow changes. Diff checks passed.

**Final disposition:** Non-runtime.

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

### 59. `68cda4a8` — Document the discovery operator LXMF address

**Upstream change:** Adds the `discovery_lxmf_address` option to the interface
discovery manual, describing it as an optional way for remote users to contact
an interface operator and coordinate interconnections or coverage.

**Rust applicability:** The wire field, configuration parser, persistence, RPC,
and detailed `rnstatus` output were integrated with upstream commit 2, but the
native operator guide did not document how to configure the address.

**Local handling and evidence:** Added the setting to the discoverable-interface
example and documented its exact 16-byte/32-hex-character representation, remote
display, purpose, and invalid-value handling. No regression test was added for
documentation-only content; the parser and display tests remain recorded under
commit 2.

**Final disposition:** Integrated.

### 60. `9ae3db16` — Initialize the no-bitrate discovery timeout

**Upstream change:** Replaces `None` with numeric zero when no interface bitrate
is available, allowing the fixed path-request timeout to win the subsequent
`max()` calculation instead of raising a type error.

**Rust applicability:** Rust's integration of commit 58 uses `Option<u64>` only
while selecting a bitrate and returns the numeric fixed timeout before the
deadline calculation when none is available. It therefore never creates the
invalid mixed numeric/optional state fixed upstream.

**Local handling and evidence:** Retained the type-safe implementation and added
an end-to-end recursive path-request regression with two interfaces that report
no bitrate. It proves request processing succeeds and records the exact fixed
15-second deadline. The direct helper test also covers an empty interface map
and zero bitrate.

**Final disposition:** Structurally covered.

### 61. `05e6717d` — Close rngit resource files before moving on Windows

**Upstream change:** Closes a Python resource-response file before moving it
into rngit's retained temporary directory. This avoids Windows rename failures
caused by the still-open file descriptor.

**Rust applicability:** Native resource callbacks deliver the complete response
as an owned `Vec<u8>`. `rns-git` decodes those owned bytes and hands the bundle
directly to Git; it neither receives a transport file handle nor moves a
transport-managed temporary path.

**Local handling and evidence:** No production change was appropriate because
the ownership boundary structurally excludes the open-file rename. The existing
repository fetch E2E exercises a resource response, extracts its owned bundle,
writes it to a fresh path, and asks Git to validate the requested ref. The full
`rns-git` test suite is the relevant regression gate.

**Final disposition:** Structurally covered.

### 62. `d478e380` — Use sets for discovery path-request tags

**Upstream change:** Replaces the linear tag list with current and previous
sets, making duplicate membership checks indexed while rotating whole
generations when the current set exceeds its configured size.

**Rust applicability:** Rust already stores tags in both a private `BTreeSet`
membership index and a `VecDeque` retention order. Membership is indexed, while
the queue keeps the configured bound exact instead of temporarily retaining up
to two upstream generations.

**Local handling and evidence:** Retained the existing indexed FIFO design and
strengthened its regression. Replaying an existing tag now explicitly proves
the index rejects it without increasing the count or refreshing its FIFO
position; inserting the next unique tag then evicts the original oldest tag.

**Final disposition:** Structurally covered.

### 63. `4ab0755d` — Account ingress only after unique-tag acceptance

**Upstream change:** Moves `received_path_request()` after discovery-tag
validation. Duplicate path-request replays no longer contribute inbound
frequency samples or influence ingress-limiter classification.

**Rust applicability:** Native driver dispatch previously recorded the incoming
sample immediately after packet decoding, before `TransportEngine` rejected a
duplicate tag. Replays therefore inflated `ip_freq` and could spuriously
activate PR burst limiting, matching the upstream defect.

**Local handling and evidence:** Added a two-phase accepted-request token while
preserving the existing public path-request methods and return representations.
Core now validates and inserts the unique tag first; only an accepted token lets
the driver record the sample, refresh core frequency state, and continue path
handling. A driver-level regression sends the same valid request twice. It
failed before the fix with two samples and now retains one tag and one sample.

**Final disposition:** Integrated.

### 64. `386ef1f3` — Optimize Transport jobs and register PRs early

**Upstream change:** Reduces the path-request gate timeout from 120 to 45
seconds and the discovery-tag limit from 32,000 to 8,192. Valid unique inbound
requests register their destination in the gate table before later filtering;
locally generated requests refresh the same table immediately before send. The
remaining changes shorten Python lock hold times and contain errors while
launching worker threads.

**Rust applicability:** Rust had indexed bounded tag retention but still used
the old limit, and it had no equivalent destination-level in-flight gate. Its
transport engine and driver are single-owner state machines, so copying tables
outside a mutex and protecting Python thread startup do not apply.

**Local handling and evidence:** Changed the tag default to 8,192 and added a
private in-flight destination table. Unique inbound tags insert without
refreshing an existing timestamp, locally generated requests refresh it, and
periodic maintenance removes entries at the 45-second boundary. Focused tests
pin both constants, early insertion, non-refresh behavior, outbound refresh,
and survival/removal around the timeout.

**Final disposition:** Integrated.

### 65. `614e7bd8` — Batch same-destination path requests

**Upstream change:** Raises discovery-tag retention from 8,192 to 16,000. When
a valid unique path request arrives for a destination already present in the
45-second in-flight gate, it does not launch another recursive search. Instead,
its receiving interface is added once to the pending discovery request unless
ingress limiting classified it as limited. The eventual matching announce is
sent as a path response to every retained requesting interface.

**Rust applicability:** Rust gained the destination-level gate in commit 64,
but still processed every different-tag request independently and retained
only one requester per discovery search. Two peers asking for the same unknown
destination could therefore duplicate recursive traffic, while only one peer
could be represented in the response state.

**Local handling and evidence:** The accepted-request token now records whether
the destination was already in flight. Later unique requests stop before path
lookup or forwarding, while non-limited requester interfaces are deduplicated
into the existing private discovery state. The first request alone engages the
recursive search. A matching announce keeps the first response in the normal
retry/queue path and emits equivalent path-response actions for every additional
requester, preserving the engine's one announce-table entry per destination.
Focused regressions prove two tags and two ingress interfaces produce one
recursive send, retain both interfaces, and answer both when the announce
arrives. A separate regression and the Rust rnx end-to-end test prove that a
second local client is answered from a newly learned cached path even while the
45-second gate timestamp remains; only unknown destinations are considered
in-flight. The constants test pins the new 16,000 tag limit.

**Final disposition:** Integrated.

### 66. `74883369` — Let the link test use configured logging

**Upstream change:** Removes the explicit `LOG_EXTREME` argument from the
Reticulum instance constructed by `tests/link.py`. The upstream link test now
uses the log level from its `tests/rnsconfig` fixture instead of overriding it
in code.

**Rust applicability:** This changes only an upstream Python test runner and
does not alter Reticulum runtime behavior or protocol output. Native link tests
run inside Cargo's standard test harness and do not construct a daemon with a
forced extreme log-level argument. Rust production configuration parsing is a
separate path with existing coverage for configured levels.

**Local handling and evidence:** No production or test change is appropriate:
there is no native hard-coded test override to remove and no compatible runtime
contract changed. Repository search confirmed that test logging is opt-in via
`RUST_LOG`, while daemon configuration tests already exercise configured
numeric log levels.

**Final disposition:** Non-runtime.

### 67. `5f2f4438` — Add detailed announce and path-request traffic statistics

**Upstream change:** Adds cumulative announce and path-request RX/TX byte
counters to every interface, samples total and class-specific bit rates once
per second, aggregates dynamically spawned interfaces into their parent
listener, exposes the values through local and remote status responses, and
shows class flow percentages and optional detailed totals in `rnstatus`.

**Rust applicability:** The native status API and CLI expose the same interface
traffic surface, so the counters, current-rate semantics, aggregation, and
rendering are directly applicable. Rust's single-owner driver does not need
upstream's per-interface speed thread or exception guards around mutable Python
attributes, but it must preserve the same accepted-packet accounting boundary.

**Local handling and evidence:** Interface statistics now retain cumulative
announce and path-request bytes plus current rates. The driver samples counter
deltas after each complete one-second-or-longer window, reports zero before the
first complete window and after idle windows, and sums child traffic for
Backbone listener rows. Inbound announce bytes are added only after signature
validation succeeds, including asynchronous verification; inbound path-request
bytes are added only after unique-tag acceptance. Outbound accounting uses the
actual transmitted length, including IFAC bytes. Local pickle RPC and remote
MessagePack status responses include all ten traffic fields, while `rnstatus`
renders independently calculated, capped RX/TX flow shares and class totals.
Focused tests cover cumulative counters and timestamp bounds, valid and async
announce acceptance, duplicate path requests, outbound packet lengths,
deterministic current/idle sampling, Backbone child aggregation, RPC field
round-trips, and CLI percentages/totals.

**Final disposition:** Integrated.

### 68. `880db0a7` — Show active links separately in `rnstatus`

**Upstream change:** Keeps the existing total link-table count, adds a count of
entries whose validation flag is set, exposes that count through the local RPC
surface, and appends the active count to `rnstatus -l` output when nonzero.

**Rust applicability:** Native `rnstatus -l` previously queried the total count
but labelled it “Active links.” The distinction is directly applicable. Rust
stores forwarded transport entries and locally terminated link state in two
typed owners, so both sources must contribute using their corresponding
validated and `Active` states.

**Local handling and evidence:** The existing `link_count` query and response
remain unchanged. A new additive `active_link_count` query counts validated
transport entries plus established `LinkManager` entries, and the local RPC
server exposes the upstream-compatible request name. The CLI now labels the
total as link-table entries and appends a positive active count; zero or an
unavailable active query leaves the total intact, including for older and
remote-management peers. Core tests distinguish validated from unvalidated
entries, LinkManager tests distinguish pending from established links, the
driver and RPC round trips cover the new variants, and CLI tests pin singular,
plural, positive-active, zero-active, and unavailable-active rendering.

**Final disposition:** Integrated.

### 69. `6ba7cc8c` — Add data-flow speeds to `rnstatus`

**Upstream change:** Extends detailed traffic totals so the non-announce,
non-path-request data share includes both a percentage and its corresponding
current bit rate in each direction.

**Rust applicability:** Native `rnstatus` gained the detailed class rates in
commit 67 and therefore has the same inputs. The display calculation is directly
applicable without changing accounting or status response formats.

**Local handling and evidence:** Detailed totals now subtract the combined
announce/path-request current rate from each total rate, clamp the residual to
zero through one hundred percent, and render its speed beside the integer data
percentage. A focused formatter regression uses distinct RX/TX totals and class
rates to pin 65%/520 b/s receive data and 55%/880 b/s transmit data, and proves
the suffix remains absent when detailed pathing display is disabled.

**Final disposition:** Integrated.

### 70. `42f6d64b` — Track per-interface protocol violations

**Upstream change:** Adds cumulative protocol, IFAC, and packet-filter rejection
counters to interfaces; records malformed/invalid packets at their rejection
boundaries; prevents link packets from forwarding before validation; exposes
the counters in status; and renders and sorts them in `rnstatus`.

**Rust applicability:** The rejection boundaries exist across the native IFAC
adapter, typed packet parser, transport filter, announce validator, and link
forwarding table. Rust's fixed-size parser already rejects malformed transport
and destination fields and its outbound packet builder enforces wire bounds,
but counters and the pre-validation forwarding guard were absent.

**Local handling and evidence:** `InterfaceStats` now separates protocol, IFAC,
and ordinary filter counts. The driver records malformed frames, unexpected or
invalid IFAC, tagless path requests, duplicate/filter rejection, invalid sync
and async announces, and pre-validation link packets. The transport engine now
refuses to forward an unvalidated link entry. Dynamic child counters aggregate
into Backbone listener rows, local pickle and remote MessagePack status include
the fields, and `rnstatus` renders nonzero counters and supports `pvs`, `ivs`,
and `flt` sorting. Focused tests independently trigger malformed parsing, IFAC
failure, tagless requests, duplicate filtering, invalid signatures, pending-link
state, RPC values, and CLI rendering/sorting.

**Final disposition:** Integrated.

### 71. `60eb0509` — Signal blackholed announce validation

**Upstream change:** Adds a distinct blackholed result to announce validation so
early ingress validation can drop a blackholed identity without recording it as
an interface protocol violation.

**Rust applicability:** Native announce validation already checks the engine's
blackhole table after signature verification. Commit 70's new violation action
made the earlier rejection reason observable, so the same policy distinction is
required for both synchronous and queued verification.

**Local handling and evidence:** Invalid-announce accounting derives the
announced identity hash from its public key and consults the current blackhole
table before emitting a protocol-violation action. The asynchronous failure path
retains enough pending announce context to apply the same check before removing
the verification entry. A focused test tampers two otherwise valid announces:
the ordinary identity increments the counter, while the blackholed identity is
dropped with the counter unchanged.

**Final disposition:** Integrated.

### 72. `cab513fa` — Restrict batching diagnostic to actual batching

**Upstream change:** Moves the “already in-flight, batching” pathing log inside
the non-ingress-limited branch. Ingress-limited requests were already excluded
from the batch; only the diagnostic was misleading.

**Rust applicability:** Native path-request batching already tests the traffic
class before retaining a requester and emits no corresponding batching message.
There is therefore no diagnostic placement bug to port and no runtime behavior
change.

**Local handling and evidence:** Repository search confirms no equivalent log.
The existing queued ingress-limited regression proves that a request classified
as limited remains suppressed during dispatch, while the same-destination batch
tests prove ordinary requests are retained and answered. No additional code or
duplicative test is appropriate.

**Final disposition:** Structurally covered.

### 73. `b3ef214e` — Add aggregate announce and path-request frequencies

**Upstream change:** Sums incoming/outgoing announce and path-request frequency
estimators across interfaces, exposes four top-level status fields (`arxf`,
`atxf`, `prxf`, and `ptxf`), and appends the formatted frequencies to detailed
`rnstatus` traffic totals.

**Rust applicability:** Native interfaces already retain the bounded timestamp
samples and compute the same four directional estimators. Only aggregate status
transport and total rendering were missing.

**Local handling and evidence:** `TrafficDetail` transparently carries the four
aggregate frequencies. The driver sums every real interface once, which is
equivalent to upstream's parent aggregation for dynamic children without
double-counting synthetic listener rows. Local pickle RPC and remote MessagePack
status include the new top-level keys. Detailed path-request and announce totals
append `prettyfrequency` output when the peer supplies the keys and remain
compatible with older peers when it does not. A deterministic query test pins
all four sample-derived totals, the RPC round trip pins distinct values, and the
CLI formatter test pins directional frequencies alongside bytes, speeds, and
flow shares.

**Final disposition:** Integrated.

### 74. `7b8923b6` — Classify more packet-filter protocol violations

**Upstream change:** Counts invalid announce context/header combinations and
transported plain/group packets with an impossible hop count as protocol
violations instead of ordinary duplicate-filter rejections.

**Local handling and evidence:** Added a pure core classifier and used it at
the driver's packet-filter boundary, preserving the duplicate filter counter
for ordinary repeats. A focused driver regression exercises each invalid class
and a true duplicate. **Final disposition:** Integrated.

### 75. `378840a6` — Add packet counts and sustained burst timing

**Upstream change:** Adds cumulative announce/path-request RX/TX counts to each
interface and status output. It also keeps burst state active for a full hold
interval after the last above-threshold sample.

**Local handling and evidence:** Interface statistics now increment four
saturating counts alongside the existing byte totals. Driver queries, listener
aggregation, pickle RPC, remote MessagePack status, and `rnstatus` totals/sort
keys expose them. Announce and PR ingress state separately tracks the last
sustained sample. Interface, RPC, CLI, and cooldown regressions cover the new
behavior. **Final disposition:** Integrated.

### 76. `2b1b9589` — Expose medium-bitrate adaptive timeouts

**Upstream change:** Calculates a medium path timeout from the slowest usable
interface bitrate, exposes the bitrate and timeout over RPC, and uses adaptive
path/link deadlines in `rngit`.

**Local handling and evidence:** Core exposes the slowest positive bitrate and
compatible timeout formula; node queries and pickle RPC expose both values.
`rns-git` now raises path and link deadlines to those calculated bounds. Core
formula and RPC round-trip regressions passed. **Final disposition:** Integrated.

### 77. `4c69b376` — Use adaptive timeouts in utilities

**Upstream change:** Applies the new path timeout and per-hop link-establishment
timeout to client utilities, while retaining an explicitly supplied probe
timeout.

**Local handling and evidence:** Shared helpers apply the medium path bound and
the existing link per-hop formula. `rncp`, `rnx`, `rnprobe`, and remote
management use those bounds; `rnprobe` only adapts its default. The complete
`rns-cli` suite, including native rncp/rnx E2E, passed. `rnpath` has no
link-establishing client operation to change locally. **Final disposition:**
Integrated.

### 78. `b1aa5278` — Separate in-flight path-request state

**Upstream change:** Separates path-request batching gates from discovered path
state so a retained request timestamp cannot make a known destination appear
in flight.

**Local handling and evidence:** Rust already stores request gates in the
dedicated `path_requests` map and checks actual path/local state before
batching. The existing learned-path regression keeps the gate timestamp and
still answers immediately. **Final disposition:** Structurally covered.

### 79. `3885d232` — Count additional protocol and IFAC violations

**Upstream change:** Extends violation accounting to oversized path requests,
malformed link requests, tunnel synthesis failures, invalid frame sizes, and
IFAC failures, while ensuring cached announce replay is not authenticated
twice.

**Local handling and evidence:** The driver counts excessive PR data and
invalid tunnel synthesis; LinkManager reports malformed link requests back to
the receiving interface. Per-interface decoders already enforce exact frame
bounds, and the driver/core split performs IFAC handling only before core
ingress. Focused driver and LinkManager regressions passed. **Final
disposition:** Integrated.

### 80. `6b2c5bcf` — Do not reprocess IFAC for held announces

**Upstream change:** Marks held announces as already IFAC-processed before
reinjection.

**Local handling and evidence:** Native IFAC authentication and mask removal
belong exclusively to the network driver. The transport core stores and
reinjects decoded announce bytes and preserved reception metadata, never
calling the IFAC layer. Existing held/cached announce regressions pin this
boundary. **Final disposition:** Structurally covered.

### 81. `fc69f323` — Route queued announces normally and correct IFAC category

**Upstream change:** Sends queued announces through the standard Transport
transmit path and classifies an IFAC flag received on a non-IFAC interface as
an IFAC violation.

**Local handling and evidence:** Core queued announces already emit the same
`SendOnInterface` action used by ordinary traffic, after which the driver
performs outbound IFAC and accounting. The inbound category is now corrected
to the interface IFAC counter; the focused rejection regression covers it.
**Final disposition:** Integrated.

### 82. `091e021d` — Reject excessive outbound hop counts

**Upstream change:** `Packet.send()` now returns before packing or Transport
outbound processing when the packet's hop count is at or above
`PATHFINDER_M`. The same commit enriches the no-interface debug message.

**Rust applicability:** Native internal and shared-client send paths normally
originate packets at hop zero, but raw and relayed packets enter the common
`TransportEngine::handle_outbound` boundary with their existing hop count.
Before this port, a packet at hop 128 was routed and inserted into the packet
hash list.

**Local handling and evidence:** Local `c549c0c` rejects the packet at the
common outbound boundary before route selection, announce queuing, or hash-list
mutation. The focused regression reproduced the pre-port transmission at hop
128, then proves hop 127 is routed and recorded while hop 128 produces no
action and no hash-list entry. `cargo test -p rns-core` passed 649 unit tests
plus all core interoperability/integration suites; formatting, diff checks,
and warning-free host lint passed.

**Final disposition:** Integrated.

### 83. `2aed542e` — Resolve the outbound path entry directly

**Upstream change:** Replaces a path-table membership check followed by a
locked second membership check and index operation with one `.get()` lookup.
If the entry disappeared between the earlier outbound condition and the
lookup, the packet is dropped instead of indexing missing state.

**Rust applicability:** Rust's outbound router already performs one
`BTreeMap::get()` and derives the primary path from the returned borrow. It has
no separate membership preflight, global mutable table, or second index
operation. A missing path falls through to the normal broadcast behavior.

**Local handling and evidence:** Local `02f228c` documents the single-lookup
invariant and strengthens the focused unit test by inserting and removing a
path before routing, then proving the current missing state broadcasts without
a stale access. The focused test, all 649 core unit tests, core
interoperability/integration suites, formatting, diff checks, and warning-free
host lint passed.

**Final disposition:** Structurally covered.

### 84. `6f6751d6` — Apply prospective and late recursive path-request egress limits

**Upstream change:** Renames the egress minimum-sample constant and lowers it
from six samples to two, calculates outgoing path-request frequency as though
the candidate request had already been sent, and repeats the limit check at
the final recursive-request send boundary. The late check closes a race where
queued incoming requests can all pass an earlier decision made against stale
outgoing state.

**Rust applicability:** The transport engine already filtered each recursive
egress candidate, but used the sampled `n/span` rate and required six samples.
The network driver updated live outgoing samples only while dispatching and did
not re-check the gate immediately before writing a previously created action.
Both upstream defects therefore applied across the engine/driver boundary.

**Local handling and evidence:** Local `576864f` introduces the two-sample
egress constant, evaluates `(n+1)/span` from the sampled rate and count, and
exposes the same engine gate for the driver's live pre-dispatch check. Focused
regressions first reproduced both the missed prospective threshold and a state
change between action creation and writer dispatch. All 649 `rns-core` and 885
`rns-net` unit tests, 54 network E2E tests, the affected integration and
Python/IFAC interoperability suites, formatting, diff checks, and warning-free
host lint passed.

**Final disposition:** Integrated.

### 85. `b397870c` — Silence unavailable interface-bitrate diagnostics

**Upstream change:** Demotes failures while calculating the lowest and highest
online interface bitrates from debug to extreme logging. An empty set of
online interfaces with configured bitrates is expected and should not create
routine diagnostic noise.

**Rust applicability:** Rust calculates the lowest usable bitrate with an
iterator returning `Option<u64>`. Empty and zero-only sets produce `None`
without exceptions or logging, and path timeout calculation silently uses its
fixed fallback. There is no cached highest-bitrate calculation in the native
transport path and therefore no equivalent noisy diagnostic.

**Local handling and evidence:** Local `1985606` documents that missing usable
bitrates are intentionally silent and strengthens the timeout regression with
direct assertions for empty and zero-bitrate inputs. The focused test, all 649
core unit tests, core interoperability/integration suites, formatting, diff
checks, and warning-free host lint passed.

**Final disposition:** Structurally covered.

### 86. `561e2f23` — Record the upstream 1.5.0 changelog boundary

**Upstream change:** Adds the RNS 1.5.0 release notes to upstream
`Changelog.md` and restores headings in older release entries. It changes no
Python runtime, protocol, configuration, RPC, utility, or generated artifact.

**Rust applicability:** rns-rs does not vendor the Python project's changelog.
The listed behaviors remain subject to their individual source commits and
cannot serve as parity evidence by themselves. The 1.5.0 label informs the
eventual audit name only once the canonical promotion target is also known.

**Local handling and evidence:** Local `6dd92d7` strengthens the integration
runbook to state that version/changelog metadata identifies a target but is not
vendored or accepted in place of source-level review. The complete diff was
reviewed and `git diff --check` passed.

**Final disposition:** Non-runtime.

### 87. `e32d4df7` — Document adaptive path-timeout query APIs

**Upstream change:** Adds source and generated API documentation for
`get_lowest_interface_bitrate()` and `get_medium_path_timeout()`, including
their return units and unavailable-bitrate fallbacks.

**Rust applicability:** Equivalent public queries already exist on
`TransportEngine` and `Node`, and their RPC forms were mapped with the earlier
runtime commit. The engine methods lacked Rustdoc; the node documentation did
not spell out the `None`/zero fallback or calculation scope.

**Local handling and evidence:** Local `26323ea` documents the public engine
and node APIs, positive-bitrate selection, MTU round-trip estimate, per-hop
allowance, and unavailable-data behavior. `cargo doc -p rns-core -p rns-net
--no-deps` completed (with existing unrelated broken-link warnings), formatting
and diff checks passed, and warning-free host lint passed.

**Final disposition:** Integrated documentation.

### 88. `d25ea38c` — Add packet-rate totals and exclude shared-instance traffic

**Upstream change:** Counts accepted RX and dispatched TX packets, samples
aggregate receive/transmit packets per second, exposes `rxpps` and `txpps` in
status data, adds `rnstatus -p/--pps`, and excludes the local shared-instance
interface from traffic totals to prevent internal forwarding from inflating
network traffic.

**Rust applicability:** Rust already retained per-interface packet counts and
sampled byte/class rates, but did not sample PPS, expose aggregate PPS, render
it in `rnstatus`, or exclude local shared-server connections from aggregate
byte/rate/class totals.

**Local handling and evidence:** Local `ef51d1d` samples per-interface packet
deltas in the same current window as byte rates, aggregates them while
excluding `is_local_client` server-side shared connections, carries `rxpps` and
`txpps` through local RPC and remote management, and renders rounded PPS with
`rnstatus -p/--pps`. Per-interface rows remain visible. Focused sampler,
aggregation/exclusion, RPC, management, and CLI regressions passed. All 885
`rns-net` unit tests, 54 network E2E tests, interoperability/fixture suites,
all `rns-cli` tests, formatting, diff checks, and warning-free host lint passed.

**Final disposition:** Integrated.

### 89. `26e3ca4f` — Classify shared-medium interface types

**Upstream change:** Adds a default-false `shared_medium` hint to the base
interface and marks AX.25/KISS, Pipe, RNode, RNode Multi/subinterface, Serial,
and UDP interface classes true. The commit does not serialize or consume the
hint; it establishes interface-class metadata for later behavior.

**Rust applicability:** Rust interfaces are selected through a named factory
registry instead of inheriting a mutable Python base class. The stable native
equivalent is therefore classification by registry type name, which can be
reused by discovery/capability consumers without adding duplicated flags to
every interface constructor.

**Local handling and evidence:** Local `211e677` adds the documented
`shared_medium_hint()` classifier. Its focused matrix proves all seven upstream
shared-medium families true and Auto, Backbone, I2P, Local and TCP families
false. All 886 `rns-net` unit tests, 54 network E2E tests,
interoperability/fixture suites, formatting, diff checks, and warning-free host
lint passed.

**Final disposition:** Integrated.

### 90. `1bad7f58` — Release stale-route active-link packet hashes

**Upstream change:** When an active-link packet arrives on an interface other
than the link's attached interface during a transport failover edge case,
upstream drops that arrival and removes its hash from both the current and
previous deduplication lists. The same packet can then be accepted when it
finally arrives over the link's current path.

**Rust applicability:** Rust keeps one bounded FIFO/set deduplication structure
instead of rotating current and previous Python lists. Inbound packets are
remembered before local driver delivery, and the link manager owns the active
link's route hint, so a stale-interface arrival could suppress the later
current-route copy. The failure mode therefore applied across the core/driver
boundary.

**Local handling and evidence:** Local `fcab026` adds arbitrary native FIFO/set
removal while preserving order, detects DATA/LINK packets whose receiving
interface differs from the active link route, drops that stale arrival, and
forgets its packet hash. Focused regressions cover wrapped-FIFO removal and
prove that the same raw packet is admissible on the current interface after
the stale arrival. All 650 `rns-core` and 887 `rns-net` unit tests, 54 network
E2E tests, Python/IFAC interoperability and fixture suites, formatting, diff
checks, and warning-free host lint passed.

**Final disposition:** Integrated.

### 91. `bfab2964` — Exclude grace-period peers from blocked-IP status

**Upstream change:** Changes the Backbone blocked-IP list from every tracked
fast-flapping address to only addresses whose flap count exceeds the configured
grace allowance. This keeps `rnstatus --blocked-ips` consistent with the
blocked-IP count and actual connection rejection.

**Rust applicability:** Rust's `blocked_ip_count()` and `blocked_ip_list()`
already share the exact strict `flap_count > grace` predicate after expiring
old state. The driver derives the RPC count from that filtered list, and native
`rnstatus` renders the returned list without broadening it, so the upstream bug
is structurally absent.

**Local handling and evidence:** Local `b12b919` strengthens the existing
mixed-peer boundary regression: one peer exceeds grace, another remains
tracked within grace, the count is one, and the list contains only the actually
blocked peer. The focused test, all 887 `rns-net` unit tests, 54 network E2E
tests, Python/IFAC interoperability and fixture suites, formatting, diff checks,
and warning-free host lint passed. A sandbox-only full-suite attempt failed to
create sockets; the identical permitted rerun passed completely.

**Final disposition:** Structurally covered.

### 92. `b123a756` — Identify the transport implementation in discovery metadata

**Upstream change:** Reserves discovery metadata keys `0xFD` and `0xFC` and
includes the short transport implementation identifier `RNS` plus the upstream
RNS version in every discoverable-interface announcement.

**Rust applicability:** Native discovery announcements used the same numeric
MessagePack map but omitted both newly required fields. The receiving parser
already ignores unknown fields, as upstream does, so accepting pre-1.5.0
announces remains necessary for backward compatibility; no persistence, RPC,
or CLI expansion is introduced by this upstream commit.

**Local handling and evidence:** Local `14714db` defines the exact `0xFD` and
`0xFC` wire keys and emits `rns-rs` plus the compiled `rns-net` package version
from every discovery announcement. The focused decoded-map regression verifies
both exact keys and values. All 888 `rns-net` unit tests, 54 network E2E tests,
Python/IFAC interoperability and fixture suites, formatting, diff checks, and
warning-free host lint passed; the discovery E2E suite also confirms native
receivers continue accepting the augmented payload.

**Final disposition:** Integrated.

### 93. `2058596d` — Guard repeated outgoing resource cancellation

**Upstream change:** Checks that a resource is still present in the link's
`outgoing_resources` collection before asking the link to remove it from
`cancel()` and `reject()`. This prevents duplicate or callback-reentrant
cancellation from attempting to remove an already-removed Python object.

**Rust applicability:** A native `ResourceSender` never removes itself from its
owning link. `LinkManager` owns collection mutation, marks cancellation as a
terminal sender state, then retains only active entries after processing all
actions. A later cancellation sees no collection entry, and cancelling a
terminal sender directly emits no second action, so the Python membership race
has no native equivalent.

**Local handling and evidence:** Local `4f816a0` extends the manager-level
cancellation regression to call `cancel_all_resources()` again after the first
call removed the outgoing sender. The second call produces no actions and the
transfer count remains zero. The focused test, all 888 `rns-net` unit tests, 54
network E2E tests, Python/IFAC interoperability and fixture suites, formatting,
diff checks, and warning-free host lint passed.

**Final disposition:** Structurally covered.

### 94. `88c629e3` — Align Local and Backbone bitrate/MTU metadata

**Upstream change:** Lowers a Backbone listener's bitrate estimate from 1 Gbps
to 500 Mbps, which makes accepted peers select a 131072-byte hardware MTU;
assigns the Local server an explicit 262144-byte hardware MTU; demotes MTU
selection diagnostics from pathing to debug; makes keepalive logging extreme;
and avoids formatting a disabled Local sleep-pause debug message.

**Rust applicability:** Native interface metadata still reported 1 Gbps and a
65535-byte placeholder for accepted Backbone peers and Local connections. It
also incorrectly applied the listener estimate to standalone Backbone clients,
whose upstream class retains a separate 100 Mbps estimate and 1 MiB maximum.
Rust has no MTU-selection diagnostic, no per-keepalive diagnostic, and its
`log::debug!` macro performs level filtering before message formatting, so the
logging adjustments require no additional runtime path.

**Local handling and evidence:** Local `e12d936` centralizes the class defaults:
500 Mbps and 131072 bytes for listener-accepted Backbone peers, 100 Mbps and 1
MiB for standalone/pool Backbone clients, and 1 Gbps plus 262144 bytes for both
sides of Local/shared-instance connections. Focused constant, metadata, and
live accepted-connection regressions passed. All 890 `rns-net` unit tests, 54
network E2E tests, Python/IFAC interoperability and fixture suites, formatting,
diff checks, and warning-free host lint passed.

**Final disposition:** Integrated.

### 95. `84597f31` — Add MTU to interface status output

**Upstream change:** Adds each interface's hardware MTU to Reticulum's status
dictionary and displays it beside the bitrate in `rnstatus`.

**Rust applicability:** Native interface statistics and their Python-compatible
RPC encoding exposed bitrate but omitted MTU, so `rnstatus` could not report the
effective interface limit. Remote status responses can come from older peers,
which still requires the CLI parser to tolerate an absent field.

**Local handling and evidence:** Local `e6a3350` carries the registered
interface MTU into `SingleInterfaceStat`, exports it under the compatible `mtu`
RPC key, supplies the Backbone aggregate MTU, and renders `MTU <bytes>` beside
the rate. Focused RPC and formatter regressions verify the exact values and the
legacy field-absent case. All 890 `rns-net` unit tests, 54 network E2E tests,
the complete `rns-cli` suites, formatting, diff checks, and warning-free host
lint passed.

**Final disposition:** Integrated.

### 96. `602085a1` — Extract inbound IFAC handling

**Upstream change:** Moves the existing inbound IFAC extraction, HKDF unmasking,
flag removal, and signature verification from `preprocess_inbound()` into a
dedicated `handle_ifac_legacy()` helper without changing the algorithm.

**Rust applicability:** Native code already isolates this operation in
`ifac::unmask_inbound()`, called by the driver before packet parsing. The helper
uses only the supplied packet and immutable IFAC state, returning the recovered
packet or rejection without retaining per-packet state.

**Local handling and evidence:** Local `8d1cb5f` adds a focused regression that
feeds an invalid IFAC packet followed by its valid counterpart through the
dedicated native helper, proving rejection cannot affect subsequent handling.
The focused test, all 891 `rns-net` unit tests, 54 network E2E tests, formatting,
diff checks, and warning-free host lint passed.

**Final disposition:** Structurally covered.

### 97. `e806ae58` — Optimize inbound IFAC handling

**Upstream change:** Adds a second, not-yet-selected inbound IFAC helper that
replaces Python's byte-at-a-time immutable-byte concatenation with one
big-integer XOR while preserving the clear tag, cleared flag, signature check,
and violation behavior.

**Rust applicability:** Native `ifac::unmask_inbound()` already allocates its
output buffers once and traverses the received frame once, XORing header and
payload bytes while copying the IFAC tag unchanged. Rust does not have the
quadratic immutable-concatenation behavior or a legacy handler to replace.

**Local handling and evidence:** Local `6e2ec6c` documents the native one-pass
equivalence at the implementation boundary. The focused mask/unmask round trip,
all 891 `rns-net` unit tests, 54 network E2E tests, formatting, diff checks, and
warning-free host lint passed. Activation remains a separate upstream change
at entry 104 and is not claimed here.

**Final disposition:** Structurally covered.

### 98. `aef9e5b4` — Extract outbound IFAC handling

**Upstream change:** Moves the existing outbound IFAC signing, insertion, HKDF
masking, and flag handling from `transmit()` into
`handle_outgoing_ifac_legacy()` without changing the selected algorithm.

**Rust applicability:** Native code already isolates the same transformation in
`ifac::mask_outbound()`. Driver dispatch calls that helper before handing the
owned frame to each interface, and the helper accepts an immutable plaintext
slice, so extraction cannot mutate queued or reusable packet data.

**Local handling and evidence:** Local `495743e` adds a focused regression that
calls the dedicated helper twice, verifies byte-identical output, and confirms
the plaintext input remains unchanged. The focused test, all 892 `rns-net` unit
tests, 54 network E2E tests, formatting, diff checks, and warning-free host lint
passed.

**Final disposition:** Structurally covered.

### 99. `7347034f` — Optimize outbound IFAC handling

**Upstream change:** Adds a second, not-yet-selected outbound IFAC helper that
replaces Python's immutable byte concatenation and byte-wise output building
with a big-integer XOR while preserving the clear tag and forced IFAC flag.

**Rust applicability:** Native `ifac::mask_outbound()` already preallocates the
tagged frame and masked output and performs one linear XOR/copy pass. It has no
quadratic concatenation behavior and no separate legacy implementation.

**Local handling and evidence:** Local `33fe321` documents the native one-pass
equivalence at the outbound implementation boundary. The focused deterministic
outbound-helper regression, all 892 `rns-net` unit tests, 54 network E2E tests,
formatting, diff checks, and warning-free host lint passed. Upstream does not
select the new helper until entry 104.

**Final disposition:** Structurally covered.

### 100. `929aba02` — Add IFAC tests

**Upstream change:** Adds deterministic parity, round-trip, invariant,
corruption, and benchmark coverage for the legacy and optimized inbound and
outbound IFAC handlers across multiple frame and tag sizes.

**Rust applicability:** Rust has one already-linear implementation rather than
parallel legacy/optimized handlers, so implementation-to-implementation parity
and Python-specific benchmarks do not translate directly. The protocol matrix,
clear-tag/flag invariants, exact recovery, and corruption rejection do.

**Local handling and evidence:** Local `28f5c22` adds 96 deterministic
size/tag/pattern round trips covering 8 through 16384-byte frames and 1-, 8-,
and 16-byte IFACs. It verifies encoded length, forced and cleared flags, the
clear signature suffix, exact recovery, and rejection after second-header,
tag, or payload corruption. Both focused tests, all 894 `rns-net` unit tests,
54 network E2E tests, Python IFAC interoperability, formatting, diff checks,
and warning-free host lint passed.

**Final disposition:** Integrated.

### 101. `cfddb9ab` — Add HKDF tests

**Upstream change:** Adds the three RFC 5869 SHA-256 vectors, a deterministic
length/input/salt/context parity matrix including the Reticulum counter-wrap
extension, invalid-argument parity, and performance comparisons between the
legacy and optimized Python implementations.

**Rust applicability:** Native HKDF already has typed invalid-length and
empty-input tests, empty/absent salt equivalence, context coverage, generated
Python fixture interoperability, and benchmark exercises. It lacked the three
published RFC vectors that directly pin the standard-length output bytes.
Legacy-vs-optimized comparison is Python-specific because Rust has one
implementation.

**Local handling and evidence:** Local `c22173b` adds all three RFC 5869
SHA-256 vectors, including long input/output and empty salt/context cases. The
focused test, all 72 `rns-crypto` unit tests, 11 crypto exercise tests, 11
Python-fixture interoperability tests, formatting, diff checks, and warning-free
host lint passed.

**Final disposition:** Integrated.

### 102. `171868c6` — Add IFAC and HKDF tests to the test runner

**Upstream change:** Imports the new IFAC and HKDF `unittest` classes into
Python's manually maintained aggregate `tests/all.py` runner.

**Rust applicability:** Rust's module-local `#[cfg(test)]` suites are discovered
automatically by each crate harness, and `cargo test --workspace` invokes both
crates. There is no aggregate source registry to update; protocol coverage
belongs to entries 100 and 101.

**Local handling and evidence:** Local `89d2628` documents automatic Cargo
discovery at both test-module boundaries. A complete `cargo test --workspace`
run executed and passed the 72-test `rns-crypto` unit suite, its exercise and
interop suites, the 894-test `rns-net` unit suite, its 54 E2E tests, and all
other workspace suites. Formatting, diff checks, and warning-free host lint
also passed.

**Final disposition:** Non-runtime.

### 103. `5da0870e` — Optimize HKDF

**Upstream change:** Replaces per-expansion-block Python HMAC construction with
cloned pre-keyed SHA-256 inner/outer states and precomputed counter bytes. It
retains the legacy validation, salt/context normalization, output, and
Reticulum's modulo-256 counter extension.

**Rust applicability:** Native HKDF reconstructed an HMAC key schedule and an
owned concatenated input vector for every 32-byte expansion block. The HMAC
wrapper is cloneable after key initialization, allowing the same optimization
without exposing hash internals or changing the public API.

**Local handling and evidence:** Local `7e2224f` initializes one expansion HMAC
from the PRK, clones it per block, and streams the previous block, context, and
counter directly. A focused slow-reference regression verifies 8191-, 8192-,
and 8193-byte outputs across counter wrap. All three RFC vectors, all 73
`rns-crypto` unit tests, 11 exercise tests, 11 Python-fixture interoperability
tests, formatting, diff checks, and warning-free host lint passed.

**Final disposition:** Integrated.

### 104. `1c83e732` — Use optimized IFAC handlers

**Upstream change:** Switches Python's live transmit and inbound-preprocessing
call sites from the legacy IFAC helpers to the optimized alternatives added in
entries 97 and 99.

**Rust applicability:** Rust never retained parallel legacy and optimized
implementations. All outbound driver dispatch paths already call the sole
linear `mask_outbound()` helper, and the inbound driver boundary calls the sole
linear `unmask_inbound()` helper before packet parsing.

**Local handling and evidence:** Local `9347131` adds a driver-level regression
that sends a real packet through an IFAC-enabled interface, verifies the emitted
frame recovers exactly through the native inbound helper, then feeds that frame
back through driver preprocessing with no IFAC or protocol violation. The
focused test, all 895 `rns-net` unit tests, 54 network E2E tests, formatting,
diff checks, and warning-free host lint passed.

**Final disposition:** Structurally covered.

### 105. `956d688e` — Guard repeated incoming resource cancellation

**Upstream change:** Checks that a receiver still belongs to its link's
`incoming_resources` collection before removing it on corruption or explicit
cancellation, avoiding duplicate/callback-reentrant Python list removal.

**Rust applicability:** A native `ResourceReceiver` does not remove itself from
the owning link. `LinkManager` marks it cancelled, removes terminal receivers
after collecting their actions, and later cancellation traverses no receiver,
so the Python membership race is absent by ownership design.

**Local handling and evidence:** Local `f5246d2` extends the active receiver
cancellation regression with a second `cancel_all_resources()` call, verifying
that it emits no action and leaves the transfer count at zero. The focused test,
all 895 `rns-net` unit tests, 54 network E2E tests, formatting, diff checks, and
warning-free host lint passed.

**Final disposition:** Structurally covered.

### 106. `a9538e9f` — Lower the MTU selection log level

**Upstream change:** Demotes the Python diagnostic emitted after automatic
hardware-MTU selection from debug to extreme verbosity.

**Rust applicability:** Native interfaces select an explicit MTU while building
their immutable registration metadata. The transport core neither recalculates
that value nor emits an MTU-selection diagnostic, so there is no noisy message
whose level must change.

**Local handling and evidence:** Local `62b1937` documents the registration-time
MTU ownership and no-log invariant on `InterfaceInfo`. All 650 `rns-core` unit
tests and its integration suites, formatting, diff checks, and warning-free
host lint passed.

**Final disposition:** Structurally covered.

### 107. `3fdfe93e` — Do not loop attached-interface packets

**Upstream change:** Restricts packets with `attached_interface` to that single
candidate instead of iterating every interface, and requires the selected
interface to be online before transmission. This prevents attached traffic from
looping or falling back elsewhere.

**Rust applicability:** Native outbound routing already emits exactly one
`SendOnInterface` action when an attachment is present. Driver dispatch checks
that exact interface's enabled/online state and drops it when unavailable; it
does not reinterpret the action as a broadcast.

**Local handling and evidence:** Local `99178b0` adds a driver-level regression
with an offline attached interface and a second online interface, verifying
that neither writer receives the packet. The focused test, all 896 `rns-net`
unit tests, 54 network E2E tests, formatting, diff checks, and warning-free host
lint passed.

**Final disposition:** Structurally covered.

### 108. `1694a17a` — Add full and configurable logfile rotation

**Upstream change:** Raises the default logfile limit from 5 MiB to 30 MiB,
retains nine numbered archives instead of only one, and rotates existing
archives from newest to oldest while pruning the retention boundary.

**Rust applicability:** Supervised `rns-server` child logs already have a
separately configurable rotating store, but standalone `rnsd -s` handed one
permanently open append-only file to `env_logger` and therefore grew without a
bound. That service-mode path requires the upstream retention behavior.

**Local handling and evidence:** Local `96adade` adds a configurable rotating
writer to standalone `rnsd`, using the upstream 30 MiB and nine-archive defaults.
It reopens for each write so renaming the active file cannot strand later output
in an archive, prunes the oldest generation, shifts numbered archives, and
starts a new active log. Focused default and retention tests, all 118 `rns-cli`
unit tests and its integration suites, formatting, diff checks, and warning-free
host lint passed.

**Final disposition:** Integrated.

### 109. `9da66649` — Move log writing to a dedicated thread

**Upstream change:** Queues formatted log records and drains them on one daemon
thread, moving stdout, callback, file I/O, and rotation away from logging caller
threads while preserving FIFO ordering.

**Rust applicability:** `env_logger` serializes access to its target but calls
the target writer from the producer thread. After entry 108, standalone service
logging still performed file open/write/flush/rotation synchronously and thus
needed a dedicated consumer boundary.

**Local handling and evidence:** Local `585b046` wraps the rotating service
writer in an unbounded FIFO channel drained by one named `rns-log-writer`
thread. Writes enqueue owned buffers; `flush()` is an ordering barrier that
waits until prior records have been handled and propagates worker I/O failures.
A focused recorder test proves the actual write runs on a thread other than the
caller. All 119 `rns-cli` unit tests and its integration suites, formatting,
diff checks, and warning-free host lint passed.

**Final disposition:** Integrated.

### 110. `9302415f` — Add live profiling results output to rnstatus

**Upstream change:** Makes the existing process profiler return a stable results
dictionary, exposes it through the shared-instance `profiling_results` RPC and
the optional second `/status` request flag, and adds `rnstatus -z` recursive
profiling output. The remote response remains the upstream positional array of
status, optional link count, and optional profiling results.

**Rust applicability:** Rust had neither a public timing collector nor either
status surface. The status request and local RPC codecs are compatibility
boundaries used by Python and Rust peers, and the user-visible CLI flag is
directly applicable. Upstream has no production profiling call sites in this
commit, so the native collector likewise remains opt-in rather than adding
unrelated instrumentation.

**Local handling and evidence:** Local `89dad4b` adds process-global RAII timing
guards with tag/parent aggregation and stable mean, median, sample-deviation
results. It serializes the exact upstream dictionary field names through local
pickle RPC and remote MessagePack status, preserves the existing native
two-argument status API while adding an opt-in profiling method, and renders
nested results through `rnstatus -z`. Focused collector, RPC, management,
decoder, and CLI formatting regressions passed, as did all 901 `rns-net` unit
tests, 54 network integration tests, all 120 `rns-cli` unit tests and its
integration suites, formatting, diff checks, and warning-free host lint. A
disposable worktree at exact upstream `9302415f` also verified the request
bytes, result dictionary, MessagePack response position, statistics, and
formatted output with upstream Python.

**Final disposition:** Integrated.

### 111. `cf5d6a79` — Rework profilers for running indefinitely

**Upstream change:** Replaces unbounded duration lists with timestamped deques
limited to 10,000 samples per tag and thread, reports thread counts and
all-time plus cumulative 1/5/30/60-minute mean, median, minimum, maximum, and
sample-deviation windows, and reformats `rnstatus` as a compact statistics
table. It also traces exceptions escaping the local RPC dispatcher.

**Rust applicability:** The entry-110 native collector was likewise unbounded
and therefore unsuitable for indefinite daemon operation. Its local and remote
wire dictionaries and CLI renderer must evolve with upstream. Native RPC
workers already report every escaping dispatcher error at their connection
boundary; no additional traceback facility exists, and that temporary upstream
trace call is removed by entry 115.

**Local handling and evidence:** Local `2f388ce` stores timestamped samples in
per-thread bounded deques using the upstream default and configurable limits,
merges them into stable per-tag snapshots, and publishes the exact upstream
`count`, `threads`, `stats_all`, and four live-window fields through both
existing status codecs. `rnstatus` renders the new table with tight time units,
including fractional microseconds. Focused regressions cover eviction,
independent per-thread limits, window statistics, dictionary shape, nested
rendering, and tight formatting. All 902 `rns-net` unit tests, 54 network
integration tests, all 120 then-current `rns-cli` unit tests and its integration
suites, formatting, diff checks, and warning-free host lint passed. An exact
`cf5d6a79` disposable worktree verified Python field shape, statistics,
MessagePack round trip, and formatted output.

**Final disposition:** Integrated.

### 112. `40281f91` — Decorator for profiling functions

**Upstream change:** Adds a decorator that wraps a Python function in a
profiler context, selects its qualified name by default or accepts an explicit
tag/profiler, forwards arguments and return values, and supports a custom
capture limit.

**Rust applicability:** Rust has no runtime-equivalent decorator or stable
automatic qualified function-name reflection, but the observable ergonomic
contract is a wrapper that times an entire call without changing its result.
An explicit tag is the idiomatic native equivalent and avoids a procedural
macro dependency for a two-line operation.

**Local handling and evidence:** Local `03a12ec` adds `profile_function()` and
`profile_function_with_limit()` public adapters. Both retain the RAII guard
across the closure call, return its value unchanged, and record the elapsed
sample during unwinding just as Python's context-manager exit runs on an
exception. Focused tests prove result forwarding, default/custom retention,
and caught-panic recording. All 904 `rns-net` unit tests, 54 network integration
tests, formatting, diff checks, and warning-free host lint passed.

**Final disposition:** Integrated.

### 113. `dca5b963` — Limit total profiler captures per tag, handle reentrancy, and split windows

**Upstream change:** Moves the 10,000-sample bound from every tag/thread pair
to one deque per tag, inserts mutable in-flight captures at context entry so a
thread can reenter the same profiler safely, excludes incomplete captures from
statistics, moves sample/thread counts into `stats_all`, adds per-window count
and sum fields, and makes the 0–1/1–5/5–30/30–60 minute windows disjoint.

**Rust applicability:** All retention, aggregation, RPC/MessagePack fields, and
CLI presentation introduced by entries 110–112 are directly affected. A guard
that records only on drop is naturally reentrant but does not reproduce
upstream's bounded in-flight ordering, so the native lifecycle also needed to
register captures before the profiled call begins.

**Local handling and evidence:** Local `45fd406` assigns each guard a capture
ID, inserts it into a single bounded per-tag deque at start, and completes that
exact record at drop. Evicted or still-running captures are safely absent from
snapshots, nested same-tag guards complete independently, and all-time thread
cardinality plus disjoint window count/sum/statistics use the final upstream
wire shape. `rnstatus` reads counts from `stats_all` and renders the six-column
table with the four range labels. Focused tests cover cross-thread shared
eviction, active/reentrant guards, all four disjoint windows, RPC shape, and CLI
output. All 904 `rns-net` unit tests, 54 network integration tests, all 121
`rns-cli` unit tests and its integration suites, formatting, diff checks, and
warning-free host lint passed. An exact `dca5b963` worktree verified the Python
dictionary fields, two-thread aggregate, four non-overlapping windows,
MessagePack round trip, and renderer labels.

**Final disposition:** Integrated.

### 114. `9c2f424a` — Merge branch `live_profiling` into `live_profiler_merge`

**Upstream change:** Merges the live-profiling lineage through entry 113 with
the other branch carrying the already-inventoried MTU log-level and
attached-interface routing changes. Relative to the profiling parent, the merge
adds only the entry-106/107 deltas; it introduces no third profiling behavior.

**Rust applicability:** Rust integrated both sides in upstream ancestry order:
entries 106–107 pin fixed-MTU/noisy-log and offline attached-interface
invariants, while entries 108–113 supply logging and the complete profiling
pipeline. The merge still requires a non-empty mapping commit and evidence that
the composed profiling API reaches its final wire schema.

**Local handling and evidence:** Local `4aa1b0d` adds a merge-boundary
regression that profiles a function through the public adapter, serializes the
snapshot to MessagePack, locates the tag, and requires all seven final top-level
fields. Existing entry-106 and entry-107 regressions continue to cover the
other-parent changes. The focused merge regression, all 905 `rns-net` unit
tests, 54 network integration tests, formatting, diff checks, and warning-free
host lint passed.

**Final disposition:** Structurally covered.

### 115. `1034d788` — Merge adjustments

**Upstream change:** Cleans up the merge, removes the temporary RPC traceback,
and deliberately reverses entries 108–109's 30 MiB/nine-generation dedicated
logging thread. Final logging is serialized synchronously, reopens the file for
each record, rotates at 5 MiB, and retains only `logfile.1`. Import placement is
temporarily moved to the module top and the profiling RPC alignment is cosmetic.

**Rust applicability:** The native entry-108/109 writer was intentionally
modeled on those upstream commits, so preserving it would diverge from the
reviewed target. `env_logger` already serializes target writes, and the native
RPC worker reports escaping errors once at its connection boundary; the final
observable logging policy therefore requires the same explicit reversal.

**Local handling and evidence:** Local `c6e4966` removes `AsyncLogWriter` and
its worker/barrier protocol, restores direct `RotatingLogWriter` use, changes
the threshold to 5 MiB, and simplifies rotation to replacement of one `.1`
archive. Focused tests prove the final defaults, single-archive retention, and
immediate visibility without an asynchronous flush barrier. All 121 `rns-cli`
unit tests and its integration suites, formatting, diff checks, and
warning-free host lint passed. This entry supersedes the runtime policies from
entries 108–109 without rewriting or squashing their required mapping commits.

**Final disposition:** Integrated.

### 116. `39899651` — Merge adjustments

**Upstream change:** Removes the now-unused `Lock` and `Condition` imports left
after entry 115 deleted the asynchronous logging implementation. There is no
runtime, protocol, configuration, or output change.

**Rust applicability:** Removing the native async writer likewise left only the
daemon shutdown channel using `std::sync::mpsc`; no lock/condition imports were
present. The corresponding cleanup is to stop importing the module namespace
and name only the three channel symbols that remain in use.

**Local handling and evidence:** Local `647f99d` replaces the broad `mpsc`
module import and qualified uses with `channel`, `RecvTimeoutError`, and
`Sender`. The generated behavior is unchanged, while the source now documents
the exact post-merge synchronization surface. All 121 `rns-cli` unit tests and
its integration suites, formatting, diff checks, and warning-free host lint
passed.

**Final disposition:** Non-runtime.

### 117. `0e070aac` — Ah well, of course

**Upstream change:** Moves Reticulum's public class/module imports from the top
of `RNS/__init__.py` back to the bottom. This restores the late-import ordering
needed for Python package initialization after entry 115 temporarily moved them
above profiler and utility definitions. There is no protocol or runtime feature
change after successful import.

**Rust applicability:** Rust resolves module declarations and crate paths
statically instead of executing package imports in source order. The native
`profiling` module can refer to `crate::pickle` and be re-exported from the crate
root without a late-import block or circular initialization risk.

**Local handling and evidence:** Local `18f1656` documents that invariant on
the public profiling module and adds a crate-root regression that constructs a
guard, completes it, and retrieves its result through the exported module. The
focused regression, all 906 `rns-net` unit tests, 54 network integration tests,
formatting, diff checks, and warning-free host lint passed.

**Final disposition:** Non-runtime.

### 118. `7311dc85` — Reduced path table lock acquisitions in inbound processing

**Upstream change:** Reuses one destination path entry during transported
packet routing and removes several short path-table lock scopes around route
timestamp and authenticated LRPROOF hop updates. Missing paths remain valid
no-op cases for the path mutation.

**Rust applicability:** Rust routes outbound packets through one immutable
`BTreeMap` lookup and owns transport state behind one exclusive mutable engine
borrow during link/path rebalancing. It therefore has neither Python's shared
list-entry mutation nor its independently acquired path-table locks.

**Local handling and evidence:** Local `f330b6e` documents the ownership and
lookup invariant and adds a focused regression proving that a valid LRPROOF
still updates the link route when the optional destination path has disappeared.
Both focused rebalance tests, all 651 `rns-core` unit tests, 56 integration
tests, formatting, diff checks, and warning-free host lint passed.

**Final disposition:** Structurally covered.

### 119. `629e4fde` — Added hash map lookups for pending and active links

**Upstream change:** Adds link-ID maps alongside Python's pending and active
link lists, replaces linear inbound lookups with keyed access, and synchronizes
the maps during registration, activation, and closed-link cleanup.

**Rust applicability:** `LinkManager` already stores every pending, active, and
closing `ManagedLink` in one `HashMap<LinkId, ManagedLink>`. Link state is held
inside the indexed value, so activation requires no move between collections
and cleanup removes the only authoritative entry.

**Local handling and evidence:** Local `e7e182e` documents the single-map
lifecycle invariant and strengthens the multi-link cleanup regression to prove
all keyed destination lookups exist before teardown and disappear afterward.
The focused regression, all 906 `rns-net` unit tests, 60 integration and
interoperability tests, formatting, diff checks, and warning-free host lint
passed.

**Final disposition:** Structurally covered.

### 120. `d81421da` — Avoid additional packet hashing under lock in inbound

**Upstream change:** Caches the Python packet hash and exposes its truncated
prefix so receipts, proof destinations, and reverse-route insertion no longer
rehash the packet, particularly while holding the reverse-table lock.

**Rust applicability:** `RawPacket` already computes and stores its SHA-256
packet hash exactly once during construction or unpacking. Reverse-route keys
come from `get_truncated_hash()`, which copies the first 16 cached bytes and
performs no hashing or locking.

**Local handling and evidence:** Local `7e8a4e6` documents the cached-prefix
invariant and adds a regression that mutates the retained wire buffer after
construction, proving truncated lookup remains derived from the cached hash.
The focused regression, all 652 `rns-core` unit tests, 56 integration tests,
formatting, diff checks, and warning-free host lint passed.

**Final disposition:** Structurally covered.

### 121. `b9278ce3` — Added throughput benchmarker

**Upstream change:** Adds an 883-line Python benchmark harness for inline and
drainer throughput across transported SINGLE/LINK packets, terminus delivery,
announce ingress, and known-path outbound insertion. It constructs extensive
private Python transport and link state and changes no runtime module.

**Rust applicability:** This is performance tooling rather than observable
Reticulum behavior. Native Criterion harnesses already exercise link, request,
resource, and shared-client dispatch, but their architecture and measurements
do not map one-to-one to Python's threads, locks, or drainer implementation.

**Local handling and evidence:** Local `28cc6f8` adds the audit policy for
benchmark-only commits: review scenarios, cite native evidence, and port only
protocol invariants or explicitly accepted performance requirements. The full
upstream diff was reviewed; diff checks and warning-free host lint passed.

**Final disposition:** Non-runtime.

### 122. `5e013464` — Added throughput benchmarker

**Upstream change:** Adds `tests/throughput.py` on a separate upstream parent
lineage. Its complete 883-line contents and resulting blob
`7112eaf0` are identical to entry 121; it adds no different scenario, runtime
module, or tree effect on that lineage.

**Rust applicability:** The same benchmark-only analysis as entry 121 applies,
but the separate upstream commit still requires its own ordered mapping so the
later merge ancestry remains auditable.

**Local handling and evidence:** Local `2781d3c` extends the workflow policy to
require independent mappings for patch-equivalent commits on different merge
parents while explicitly recording their identical tree effect. The complete
diff and blob identity were reviewed, and diff checks passed.

**Final disposition:** Non-runtime.

### 123. `77f76325` — Avoid extra epoll modifies when EPOLLOUT already set

**Upstream change:** Checks whether the Python Backbone transmit buffer was
empty before asking the shared epoll loop to enable writable interest. Further
enqueues while EPOLLOUT is already armed no longer repeat `epoll.modify()`.

**Rust applicability:** The native server poller registers only the original
client stream for readable events. Each dynamic peer owns an independent cloned
`BackboneWriter`; it retries its private pending buffer directly and never
enables or re-arms writable poll interest, so the redundant operation cannot
occur.

**Local handling and evidence:** Local `e095553` documents the poller/writer
separation. The focused outbound-backpressure/read-starvation and write-stall
disconnect regressions, formatting, diff checks, and warning-free host lint
passed.

**Final disposition:** Structurally covered.

### 124. `7e197542` — Updated througput bench

**Upstream change:** Relabels inline benchmark output as `direct`, shortens the
matrix title, and appends commented fastpath/no-fastpath measurements. No
runtime or benchmark workload behavior changes.

**Rust applicability:** Output wording and measurements from an unspecified
Python benchmark host are not protocol behavior or portable Rust performance
requirements.

**Local handling and evidence:** Local `cebceae` requires fixed hardware,
build profile, workload, sampling method, and regression budget before pasted
measurements become acceptance thresholds. The complete diff and diff checks
passed.

**Final disposition:** Non-runtime.

### 125. `516cb106` — Updated througput benchmarker

**Upstream change:** Adds a third commented throughput-results block labelled
`Pre` and normalizes blank comment lines. The executable benchmark is unchanged.

**Rust applicability:** Historical measurements from an unspecified Python
environment add neither runtime behavior nor a reproducible native threshold.

**Local handling and evidence:** Local `ecadb09` records that comment-only
measurement archives should be summarized with provenance in the audit rather
than copied into Criterion source. The complete diff and diff checks passed.

**Final disposition:** Non-runtime.

### 126. `d044db29` — Cache announce signature validation

**Upstream change:** Adds a per-Packet flag after successful announce signature
validation so repeated validation of that Python object skips Ed25519 work.

**Rust applicability:** Native production work in `b2fafb2` already implements
a stronger bounded cross-packet `AnnounceSignatureCache`, keyed by
`SHA-256(destination_hash || signature)`, with configurable capacity and TTL.
Only successful validation inserts a key; synchronous and asynchronous announce
paths consume the same cache.

**Local handling and evidence:** Local `5037209` adds the ordered upstream
mapping and a security regression proving that changing either destination or
signature changes the cache key. Existing cache hit, insertion, TTL, capacity,
disablement, unchecked reconstruction, and async completion tests also passed.
The focused regression, all 653 `rns-core` unit tests, 56 integration tests,
formatting, diff checks, and warning-free host lint passed.

**Final disposition:** Integrated.

### 127. `2d216714` — FP cache experiment

**Upstream change:** Adds an experimental Python link-forwarding cache holding
same-interface state, both hop counts, both interfaces, and the local-hop
rewrite target. Cache hits bypass normal inbound classification and link-table
interpretation. The same commit also removes an active-link lock around an
already keyed lookup.

**Rust applicability:** Native inbound routing already owns the transport
engine mutably, performs one keyed link-table lookup, and feeds the typed entry
to a small routing helper. It has no list scan or per-lookup lock to remove. A
second denormalized cache would instead require invalidation whenever link
state changes.

**Local handling and evidence:** Local `a869e2c` documents the single-lookup
fast-path invariant. Focused tests passed for both cross-interface directions,
local-client hop rewriting, and instance-local hop preservation, along with
formatting, diff checks, and warning-free host lint.

**Final disposition:** Structurally covered.

### 128. `f1117099` — Updated througput benchmarker

**Upstream change:** Detects the experimental Python fast-path flag under its
actual name, removes the `informational` qualifier, and changes one usage line
from repeatable to singular. Benchmark workloads and runtime code are unchanged.

**Rust applicability:** These are Python harness presentation details. Native
routing is structurally fast without the named Python cache switch, so identical
label text would not describe identical implementation modes.

**Local handling and evidence:** Local `209268b` records that cross-language
benchmark feature labels require behaviorally equivalent implementations before
measurements can be compared. The complete diff and diff checks passed.

**Final disposition:** Non-runtime.

### 129. `17e980ff` — Cleanup

**Upstream change:** Removes the experimental forwarding-cache read path,
population logic, feature switch, and diagnostic output introduced by entry
127. Link forwarding again derives its decision from the authoritative link
table.

**Rust applicability:** Native routing never introduced the denormalized cache:
its exclusive engine ownership and keyed typed entry already provide the useful
fast path without duplicate state or invalidation hazards. This cleanup confirms
that the authoritative-table design is the durable behavior to preserve.

**Local handling and evidence:** Local `5979f92` makes the no-secondary-cache
invariant explicit beside the routing lookup. Cross-interface forwarding,
local-client hop rewriting, and instance-local hop preservation tests passed,
along with formatting, diff checks, and warning-free host lint.

**Final disposition:** Structurally covered.

All 117 inventoried commits through the original target `0e070aac` have a final
disposition. This completes all 44 commits after accepted baseline `b3ef214e`
that were in the requested tranche. The accepted baseline remains commit 73:
the final promotion gates are still being evaluated, and fresh drift now
contains the separately inventoried entries 118–142.

## Original 44-Commit Tranche Finalization

1. Verify all 44 target hashes have exactly one ordered, non-empty mapping
   commit and that every mapping carries exactly one full trailer.
2. Run workspace tests, formatting, host lint, feature/interoperability checks,
   and record any unavailable hardware/manual gates honestly.
3. Reconcile the audit and decide whether a target-specific parity record is
   appropriate while 25 newer commits remain outstanding.

The new entries 118–142 are a subsequent tranche and are not part of this
44-commit completion claim.

### Verification result (2026-08-25)

- The pinned upstream range
  `b3ef214e7257a1e5b674f8b1f002f05e78b090b8..0e070aacf655e1866ec1e469881dc91a2a3db89e`
  contains exactly 44 commits. On `dev`, all 44 hashes occur exactly once as
  full `Upstream-Commit` trailers, in upstream ancestry order; every mapping
  commit is non-empty and carries exactly one such trailer.
- `cargo test --workspace --features rns-hooks` passed, including all 54
  `rns-net` E2E tests. The initial unfeatured workspace run had one
  timing-sensitive keepalive E2E miss under full-suite load; that test passed
  immediately in isolation and again in the complete hook-enabled workspace
  run. No code change was required.
- Live `rns-net` and `rns-cli` Python/Rust interoperability passed against a
  detached exact-target worktree at `0e070aac` (`RNS.__version__ == 1.5.0`).
  `cargo fmt --all -- --check`, `scripts/lint-host.sh`, and `git diff --check`
  passed.
- A fresh drift check succeeded for both upstream remotes. Canonical rgit is
  now 69 commits ahead of the accepted baseline: the completed 44-commit
  tranche plus 25 newer commits inventoried separately as entries 118–142.
- Docker, cross-build, hardware, and manual promotion gates were not rerun for
  this tranche-only completion. No parity record or `UPSTREAM.md` promotion is
  claimed while the newer 25-commit tranche remains outstanding.
- Mapping uniqueness above is scoped to the active `dev` integration history.
  The pre-existing auxiliary worktree branch `codex/session-20260824` retains
  superseded copies of mappings 82–91 and has unrelated untracked work, so it
  was deliberately left untouched rather than destructively cleaned up.

The accepted baseline remains commit 73 until the full
promotion gates pass.

## Integration Plan

1. Complete the original 44-commit tranche verification above.
2. Continue entries 135–142 as the next ordered review tranche; entries
   118–134 are complete in local mappings `f330b6e..8b75d72`.
3. Leave baseline promotion for the complete parity-gate workflow.

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

- `2026-08-26`: Commit `d38a8de5` restores old-Python parsing by changing
  profiler f-string quote style without changing output. Local mapping
  `8b75d72` records the language-specific disposition; complete diff review and
  diff checks passed. Entry 135 is next.
- `2026-08-26`: Commit `dea0124c` removes destination-map locks from upstream
  announce and local link-request lookups. Local mapping `baabb25` records the
  native exclusive-engine invariant; all `rns-core` tests, formatting, host
  lint, and diff checks passed. Entry 134 is next.
- `2026-08-26`: Commit `aba8d606` removes a stale TODO and whitespace around
  an unchanged return. Local mapping `c4199c9` classifies the source-only
  cleanup; complete diff review and diff checks passed. Entry 133 is next.
- `2026-08-26`: Commit `8221f82d` removes a Python destination-map lock and
  demotes a no-route link diagnostic. Local mapping `d8025d7` documents the
  native lock-free lookup and quiet fast-path miss; focused tests, formatting,
  host lint, and diff checks passed. Entry 132 is next.
- `2026-08-26`: Commit `38e9d1cd` corrects Python indentation without changing
  control flow. Local mapping `1e0abaa` records the required full-diff check for
  formatting-only cleanups; diff checks passed. Entry 131 is next.
- `2026-08-26`: Commit `17e980ff` removes upstream's experimental denormalized
  forwarding cache. Local mapping `5979f92` records the native invariant of one
  authoritative typed link table; focused routing tests, formatting, host lint,
  and diff checks passed. Entry 130 is next.
- `2026-08-26`: Commit `f1117099` updates Python benchmark fast-path and usage
  labels only. Local mapping `209268b` requires behavioral equivalence before
  cross-language feature-labelled measurements are compared. Complete diff
  review and diff checks passed. Entry 129 is next.
- `2026-08-26`: Commit `2d216714` adds an experimental denormalized Python link
  forwarding cache. Native routing already uses one lock-free keyed typed
  entry; local mapping `a869e2c` documents that safer fast-path invariant.
  Focused routing, formatting, diff, and host-lint checks passed. Entry 128 is
  next.
- `2026-08-26`: Commit `d044db29` caches successful announce signature
  validation. Existing native `b2fafb2` provides a bounded cross-packet TTL
  cache; local mapping `5037209` pins destination/signature key separation.
  Focused and complete `rns-core`, formatting, diff, and host-lint checks
  passed. Entry 127 is next.
- `2026-08-26`: Commit `516cb106` adds only a third commented benchmark-result
  block and comment formatting. Local mapping `ecadb09` keeps such raw result
  archives in provenance-aware audits rather than native harness source.
  Complete diff review and diff checks passed. Entry 126 is next.
- `2026-08-26`: Commit `7e197542` changes benchmark labels and pastes
  machine-specific throughput results. Local mapping `cebceae` records the
  reproducibility requirements for treating such measurements as thresholds.
  Complete diff review and diff checks passed. Entry 125 is next.
- `2026-08-26`: Commit `77f76325` avoids repeated Python EPOLLOUT interest
  modifications. Rust's read-only server poller and independent cloned writer
  make that state structurally absent; local mapping `e095553` documents the
  invariant. Focused backpressure/write-stall, formatting, diff, and host-lint
  checks passed. Entry 124 is next.
- `2026-08-26`: Commit `5e013464` adds the exact entry-121 throughput benchmark
  blob on a separate upstream parent lineage. Local mapping `2781d3c` records
  the patch-equivalent merge-parent policy and preserves its independent audit
  identity. Complete diff/blob review and diff checks passed. Entry 123 is next.
- `2026-08-26`: Commit `b9278ce3` adds a Python-only throughput benchmarker.
  It changes no runtime behavior; local mapping `28cc6f8` records how benchmark
  scenarios map to native Criterion evidence without conflating private Python
  machinery with protocol parity. Diff and host-lint checks passed. Entry 122
  is next.
- `2026-08-26`: Commit `d81421da` avoids rehashing packets during inbound
  reverse-route insertion. Rust already caches the full packet hash and copies
  its truncated prefix; local mapping `7e8a4e6` documents and pins that
  invariant. Focused and complete `rns-core`, formatting, diff, and host-lint
  checks passed. Entry 121 is next.
- `2026-08-26`: Commit `629e4fde` adds keyed Python pending/active-link maps.
  Rust already uses one authoritative hash map for every link state; local
  mapping `e7e182e` documents that lifecycle and proves multi-link cleanup
  leaves no stale keyed destinations. Focused and complete `rns-net`,
  formatting, diff, and host-lint checks passed. Entry 120 is next.
- `2026-08-26`: Commit `7311dc85` reduces Python path-table lock acquisitions
  and repeated lookups during inbound processing. Rust already owns the engine
  mutably for the corresponding mutations; local mapping `f330b6e` documents
  that invariant and proves authenticated LRPROOF link rebalancing survives an
  absent destination path. Focused and complete `rns-core`, formatting, diff,
  and host-lint checks passed. Entry 119 is next.
- `2026-08-25`: Commit `0e070aac` restores late Python imports to avoid package
  initialization cycles. Rust resolves modules statically; local mapping
  `18f1656` documents that difference and proves crate-root profiler access.
  Focused and complete `rns-net`, formatting, diff and host-lint checks passed.
  All 44 commits in the pinned tranche now have mapping commits; final tranche
  verification is next, while entries 118–142 remain a separate new drift.
- `2026-08-25`: Commit `39899651` removes synchronization imports made unused
  by the logging reversal. Local mapping `647f99d` narrows the native daemon's
  remaining channel imports without runtime change. Complete `rns-cli`,
  formatting, diff and host-lint checks passed. Entry 117 is next.
- `2026-08-25`: Commit `1034d788` applies the post-merge logging reversal.
  Local mapping `c6e4966` removes the dedicated writer, restores synchronous
  writes, and adopts the final 5 MiB/one-archive policy without altering prior
  history. Focused and complete `rns-cli`, formatting, diff and host-lint checks
  passed. Entry 116 is next.
- `2026-08-25`: Merge `9c2f424a` combines the completed profiler lineage with
  the already-reviewed MTU and attached-interface branch. Local mapping
  `4aa1b0d` pins the composed function-to-MessagePack schema; existing
  entry-106/107 regressions cover the other parent. Focused and complete
  `rns-net`, formatting, diff and host-lint checks passed. Entry 115 is next.
- `2026-08-25`: Commit `dca5b963` moves retention to a shared per-tag bound,
  handles reentrant/in-flight captures, and makes live windows disjoint. Local
  mapping `45fd406` ports the lifecycle, evolved wire schema, and six-column
  `rnstatus` table. Focused and complete affected-crate tests, formatting, diff
  and host-lint checks, plus exact-target Python interoperability passed. Entry
  114 is next.
- `2026-08-25`: Commit `40281f91` adds decorator-based function profiling.
  Local mapping `03a12ec` provides the native explicit-tag closure/function
  adapters, including custom retention, return forwarding, and unwind
  recording. Focused and complete `rns-net`, formatting, diff and host-lint
  checks passed. Entry 113 is next.
- `2026-08-25`: Commit `cf5d6a79` makes live profiling safe for indefinite
  operation. Local mapping `2f388ce` adds bounded timestamped per-thread
  retention, cumulative live windows, the evolved wire dictionary, and compact
  statistics rendering. Focused and complete affected-crate tests, formatting,
  diff and host-lint checks, plus exact-target Python interoperability passed.
  Entry 112 is next.
- `2026-08-24`: Commit `9302415f` exposes live profiler snapshots through
  local and remote status and adds `rnstatus -z`. Local mapping `89dad4b` adds
  the native guard collector, both wire surfaces, and recursive renderer.
  Focused tests, complete affected-crate suites, formatting, diff and host-lint
  checks, plus exact-target Python MessagePack/profile interoperability passed.
  Entry 111 is next.
- `2026-08-24`: Commit `9da66649` moves Python logging I/O to a dedicated
  thread. Local mapping `585b046` queues standalone service log buffers to one
  named FIFO writer thread and provides a synchronous flush/error barrier. The
  focused thread-identity regression, complete `rns-cli`, formatting, diff and
  host-lint checks passed. Entry 110 is next.
- `2026-08-24`: Commit `1694a17a` expands Python logfile rotation to 30 MiB
  and nine archives. Local mapping `96adade` replaces standalone `rnsd -s`'s
  unbounded append file with a configurable rotating writer using those
  defaults; archive retention and rollover tests plus the complete `rns-cli`,
  formatting, diff and host-lint checks passed. Entry 109 is next.
- `2026-08-24`: Commit `3fdfe93e` restricts attached-interface packets to one
  online target. Native routing already emits one exact-interface action and
  driver dispatch drops unavailable targets without broadcast fallback; local
  mapping `99178b0` pins the offline/other-online case. Focused and complete
  `rns-net`, E2E, formatting, diff and host-lint checks passed. Entry 108 is
  next.
- `2026-08-24`: Commit `a9538e9f` demotes Python's automatic MTU-selection
  diagnostic. Native interfaces register an already-selected MTU and emit no
  equivalent runtime message; local mapping `62b1937` records that invariant.
  Complete `rns-core`, formatting, diff and host-lint checks passed. Entry 107
  is next.
- `2026-08-24`: Commit `956d688e` guards Python incoming-resource removal
  against duplicate/reentrant cancellation. Rust centralizes collection removal
  in `LinkManager`; local mapping `f5246d2` pins repeated receiver cancellation
  as an action-free no-op. Focused and complete `rns-net`, E2E, formatting,
  diff and host-lint checks passed. Entry 106 is next.
- `2026-08-24`: Commit `1c83e732` activates Python's optimized IFAC helpers.
  Rust has only the linear helpers already audited in entries 97 and 99; local
  mapping `9347131` exercises them through live driver outbound and inbound
  boundaries. Focused and complete `rns-net`, E2E, formatting, diff and
  host-lint checks passed. Entry 105 is next.
- `2026-08-24`: Commit `5da0870e` optimizes Python HKDF by cloning pre-keyed
  hash states. Local mapping `7e2224f` similarly clones one pre-keyed HMAC per
  expansion block and avoids concatenated input allocation, with reference
  parity across the modulo-256 counter wrap. Complete `rns-crypto`, RFC,
  Python-fixture interop, formatting, diff and host-lint checks passed. Entry
  104 is next.
- `2026-08-24`: Commit `171868c6` registers Python's IFAC and HKDF suites in a
  manual aggregate runner. Cargo already discovers both native test modules;
  local mapping `89d2628` records that invariant. The full workspace suite,
  formatting, diff and host-lint checks passed. Entry 103 is next.
- `2026-08-24`: Commit `cfddb9ab` adds HKDF reference, parity, error, and
  benchmark tests. Local mapping `c22173b` adds all three RFC 5869 SHA-256
  vectors to the existing native error, fixture-interoperability, and benchmark
  coverage. Complete `rns-crypto` unit/exercise/interop, formatting, diff and
  host-lint checks passed. Entry 102 is next.
- `2026-08-24`: Commit `929aba02` adds deterministic IFAC parity, invariant,
  corruption, and benchmark tests. Local mapping `28f5c22` ports the applicable
  protocol matrix and corruption coverage to Rust's single linear handler.
  Both focused tests, all 894 `rns-net` unit tests, 54 E2E tests, Python IFAC
  interop, formatting, diff and host-lint checks passed. Entry 101 is next.
- `2026-08-24`: Commit `7347034f` adds an inactive optimized Python outbound
  IFAC helper. Rust's sole outbound helper already preallocates and performs a
  single linear XOR/copy pass; local mapping `33fe321` records that invariant.
  Focused and complete `rns-net`, E2E, formatting, diff and host-lint checks
  passed. Entry 100 is next.
- `2026-08-24`: Commit `aef9e5b4` extracts Python's outbound IFAC transform
  into a helper without changing behavior. Rust already uses the dedicated
  `ifac::mask_outbound()` boundary; local mapping `495743e` pins deterministic
  output and immutable plaintext input. Focused and complete `rns-net`, E2E,
  formatting, diff and host-lint checks passed. Entry 99 is next.
- `2026-08-24`: Commit `e806ae58` adds an inactive optimized Python inbound
  IFAC helper. Rust's sole inbound helper already allocates once and performs a
  single linear XOR/copy pass; local mapping `6e2ec6c` records that invariant.
  Focused and complete `rns-net`, E2E, formatting, diff and host-lint checks
  passed. Entry 98 is next.
- `2026-08-24`: Commit `602085a1` extracts Python's legacy inbound IFAC
  algorithm into a helper without changing behavior. Rust already has the
  dedicated stateless `ifac::unmask_inbound()` boundary; local mapping
  `8d1cb5f` proves an invalid packet cannot affect a following valid packet.
  Focused and complete `rns-net`, E2E, formatting, diff and host-lint checks
  passed. Entry 97 is next.
- `2026-08-24`: Commit `84597f31` adds interface hardware MTU to status RPC and
  `rnstatus`. Local mapping `e6a3350` carries normal and Backbone aggregate MTU
  metadata through the Python-compatible response and renders it beside rate,
  while retaining compatibility with older field-absent payloads. Focused RPC
  and CLI regressions, complete `rns-net` and `rns-cli` suites, E2E tests,
  formatting, diff and host-lint checks passed. Entry 96 is next.
- `2026-08-24`: Commit `88c629e3` adjusts Backbone bitrate/auto-MTU defaults,
  gives Local servers an explicit hardware MTU, and lowers noisy diagnostics.
  Local mapping `e12d936` aligns server peers, standalone clients, Local and
  shared-client metadata; native logging already supplies the intended level
  behavior. Focused and complete `rns-net`, E2E/interoperability, formatting,
  diff and host-lint checks passed. Entry 95 is next.
- `2026-08-24`: Commit `2058596d` guards Python outgoing-resource removal
  against duplicate/reentrant cancellation. Rust centralizes removal in the
  link manager and terminal cancellation is already idempotent; local mapping
  `4f816a0` pins a repeated all-resource cancel as a no-op. Complete `rns-net`,
  E2E/interoperability, formatting, diff and host-lint checks passed. Entry 94
  is next.
- `2026-08-24`: Commit `b123a756` requires discovery announcements to identify
  their transport implementation and version. Local mapping `14714db` emits
  `rns-rs` and the compiled native version under the exact `0xFD`/`0xFC` keys,
  with decoded-map coverage and backward-compatible receiving behavior.
  Complete `rns-net`, E2E/interoperability, formatting, diff and host-lint
  checks passed. Entry 93 is next.
- `2026-08-24`: Commit `bfab2964` excludes tracked peers still within the
  fast-flap grace allowance from blocked-IP status output. Rust already shares
  the strict blocked predicate across count and list; local mapping `b12b919`
  pins the mixed blocked/grace-period boundary. Complete `rns-net`,
  E2E/interoperability, formatting, diff and host-lint checks passed. Entry 92
  is next.
- `2026-08-24`: Commit `1bad7f58` removes a stale-interface active-link packet
  from both Python dedup generations during a failover race. Local mapping
  `fcab026` implements native bounded-FIFO removal and releases the hash at the
  driver/link-route boundary. Focused regressions and complete core/net,
  E2E/interoperability, formatting, diff and host-lint checks passed. Entry 91
  is next.
- `2026-08-24`: Commit `26e3ca4f` adds shared-medium interface-class hints.
  Local mapping `211e677` supplies the native registry classifier with a full
  positive/negative type matrix. Complete `rns-net`, E2E/interoperability,
  formatting, diff and host-lint checks passed. Entry 90 is next.
- `2026-08-24`: Commit `d25ea38c` adds PPS sampling/status output and excludes
  local shared-server traffic from aggregate totals. Local mapping `ef51d1d`
  covers sampling, aggregation, RPC, remote management and `rnstatus -p` with
  focused regressions. Complete `rns-net`/`rns-cli`, E2E/interoperability,
  formatting, diff and host-lint checks passed. Entry 89 is next.
- `2026-08-24`: Commit `e32d4df7` documents the bitrate and adaptive path
  timeout query APIs. Local mapping `26323ea` adds equivalent native Rustdoc;
  documentation generation, formatting, diff checks, and warning-free host
  lint passed. Entry 88 is next.
- `2026-08-24`: Commit `561e2f23` changes only upstream RNS 1.5.0 changelog
  text. Local mapping `6dd92d7` records the reusable non-vendoring and
  source-verification policy in the integration runbook. The full diff and
  diff checks passed. Entry 87 is next.
- `2026-08-24`: Commit `b397870c` is structurally covered by Rust's silent
  optional bitrate calculation and fixed timeout fallback. Local mapping
  `1985606` documents the invariant and strengthens empty/zero-bitrate
  assertions. The focused test, all core tests, formatting, diff checks, and
  warning-free host lint passed. Entry 86 is next.
- `2026-08-24`: Commit `6f6751d6` now applies the egress limiter after two
  samples, preemptively includes the candidate request in its rate, and checks
  live state again at recursive-request dispatch. Local mapping `576864f`
  carries the exact upstream trailer. Focused pre-port failures, all
  `rns-core`/`rns-net` tests and interoperability suites, formatting, diff
  checks, and warning-free host lint passed. Entry 85 is next.
- `2026-08-24`: Commit `2aed542e` is structurally covered by Rust's existing
  single borrowed path lookup. Local mapping `02f228c` documents the invariant
  and strengthens the removed-path fallback regression. The focused test, all
  649 core unit tests, core interoperability/integration suites, formatting,
  diff checks, and warning-free host lint passed. Entry 84 is next.
- `2026-08-24`: Commit `091e021d` rejects outbound packets at the Pathfinder
  hop limit before routing or packet-hash retention. Local mapping `c549c0c`
  carries the exact upstream trailer. The focused pre-port failure, all 649
  core unit tests, core interoperability/integration suites, formatting, diff
  checks, and warning-free host lint passed. Entry 82 is final; entry 83 is the
  next outstanding commit.
- `2026-08-24`: Daily VPS snapshots were healthy: `vps-eu` had 40/40
  public interfaces up and 209,849 announces in the rolling 24-hour summary;
  `vps-us` had 26/26 up and 225,175 announces. Both primary peers were up,
  every packet-traffic query succeeded, and neither host recorded an idle
  timeout event. The impaired daily Backbone smoke passed bidirectional
  packets/channels, four concurrent Resource boundaries, concurrent link
  batches, and forced reconnect recovery. Both deployed binary pairs remain
  behind current `origin/master` and `origin/dev`. Fresh upstream fetches found
  canonical rGit at `0e070aac`, 25 commits beyond the GitHub tip `b123a756`;
  entries 93–117 are inventoried without an integration claim. The reviewed
  report database was published to `vps-eu` with matching local/remote SHA-256
  `623f0932e4947f14698aeb1dcb3416f31f0602abead30229c116ff8156c5be52`.
- `2026-08-23`: Daily refresh succeeded for both remotes. Canonical rGit and
  GitHub now agree at `b123a756`, nineteen commits beyond accepted `b3ef214e`:
  the eight previously mapped commits plus eleven newly inventoried entries
  82–92. Both VPS snapshots were healthy with every public interface up and no
  failed 24-hour traffic query. The impaired daily Backbone smoke passed
  announce/identity propagation, packets, all Resource boundaries, concurrent
  links, and forced reconnect recovery. Both VPS binary installations remain
  behind current `origin/master` and `origin/dev`.
- `2026-08-22`: Commits `7b8923b6..fc69f323` were reviewed in ancestry
  order. Packet classification and violation accounting, cumulative
  announce/PR counts, sustained burst timing, timeout RPC and adaptive utility
  deadlines were integrated; separate in-flight state and held-announce IFAC
  behavior are structurally covered. `cargo test -p rns-core`, `cargo test -p
  rns-net --all-features`, `cargo test -p rns-cli`, and `cargo test -p
  rns-git` passed, as did formatting, diff checks, and warning-free host lint.
  A fresh two-remote drift check still resolves canonical rGit to `fc69f323`
  with exactly these eight commits; GitHub remains behind at `b48b96e6`.
- `2026-08-21`: Commit `b3ef214e` adds aggregate announce/path-request
  frequencies to local and remote status and detailed `rnstatus` totals.
  Deterministic query, RPC, remote-status, CLI, relevant full suites, formatting,
  host lint, exact checkout, and fresh drift checks passed, leaving 0 commits.
- `2026-08-21`: Commit `cab513fa` only corrects placement of a Python batching
  diagnostic. Native code has no equivalent message and already excludes
  ingress-limited requesters; existing limiter and batching regressions,
  formatting, host lint, exact checkout, and drift checks passed, leaving 1
  commit.
- `2026-08-21`: Commit `60eb0509` distinguishes blackhole policy drops from
  invalid announce violations in synchronous and queued verification. The
  tampered ordinary/blackholed announce regression, relevant suites, formatting,
  host lint, exact checkout, and drift checks passed, leaving 2 commits.
- `2026-08-21`: Commit `42f6d64b` adds per-interface protocol, IFAC, and
  packet-filter counters plus the pre-validation link forwarding guard. Focused
  rejection, status/RPC, listener, and CLI tests, full relevant suites,
  formatting, host lint, exact checkout, and drift checks passed, leaving 3
  commits.
- `2026-08-21`: Commit `6ba7cc8c` adds non-pathing data speeds to detailed
  `rnstatus` totals. Directionally distinct percentage/speed and disabled-detail
  regressions, CLI tests, formatting, host lint, exact checkout, and drift checks
  passed, leaving 4 commits.
- `2026-08-21`: Commit `880db0a7` separates total link-table entries from
  validated or established active links. Core, LinkManager, driver-query, local
  RPC, and CLI display regressions passed; the accepted checkout and drift
  checker resolved exactly to the canonical tip, leaving 0 commits.
- `2026-08-21`: Commit `5f2f4438` adds detailed announce and path-request byte
  counters, current-window rates, listener aggregation, status response fields,
  and `rnstatus` flow shares/totals. Focused accounting, duplicate, sampling,
  listener, RPC, remote-management, and CLI tests plus all 879 `rns-net` unit
  tests passed, leaving 1 commit.
- `2026-08-21`: PR #123 exposed a completed-search edge case in commit 65: a
  second rnx client was batched behind a retained gate timestamp after the path
  was already learned. The focused cached-path regression and exact failing
  rnx Resource E2E now pass with batching restricted to unknown destinations.
- `2026-08-21`: Commit `74883369` only removes a hard-coded Python link-test
  log-level override. Native tests have no equivalent override; formatting,
  warning-free host lint, exact checkout, and drift checks passed, leaving 2
  commits.
- `2026-08-21`: Commit `614e7bd8` batches different-tag requests for an
  already in-flight destination. Focused tests prove one recursive search and
  path responses to both requesters, while ingress limiting and tag retention
  remain bounded; formatting, transport tests, host lint, exact checkout, and
  drift checks passed, leaving 3 commits.
- `2026-08-21`: Commit `386ef1f3` adds early path-request gate registration,
  the 45-second lifecycle, local outbound refresh, and the upstream 8,192 tag
  limit. Focused boundary tests, formatting, transport tests, host lint, exact
  checkout, and drift checks passed, leaving 4 commits.
- `2026-08-21`: Daily refresh succeeded for both remotes. Canonical rGit moved
  five commits beyond accepted `4ab0755d`; GitHub remains behind at signed
  `b48b96e6`. Both VPS snapshots were healthy with every public interface up,
  and the daily impaired Backbone smoke passed packets, channels, concurrent
  Resources/links, and forced reconnect recovery. Commits 64–68 are inventoried
  without an integration claim.
- `2026-08-21`: Commit `4ab0755d` moves PR ingress accounting after unique-tag
  acceptance. The driver regression reproduced two samples before the fix and
  one after it; full relevant tests, formatting, host lint, exact checkout, and
  zero-rgit-drift checks passed, leaving 0 commits.
- `2026-08-21`: Commit `d478e380` switches Python discovery-tag lookup to sets.
  Rust's existing indexed bounded FIFO and strengthened duplicate-order
  regression, formatting, transport tests, host lint, exact checkout, and drift
  checks passed, leaving 1 commit.
- `2026-08-21`: Commit `05e6717d` closes Python's temporary response file before
  a Windows move. Native owned-byte responses have no open-file move; the full
  `rns-git` suite, formatting, host lint, exact checkout, and drift checks
  passed, leaving 2 commits.
- `2026-08-21`: Commit `9ae3db16` fixes Python's invalid no-bitrate timeout
  initialization. Rust's type-safe fallback plus a new end-to-end fixed-deadline
  regression, formatting, transport tests, host lint, exact checkout, and drift
  checks passed, leaving 3 commits.
- `2026-08-21`: Commit `68cda4a8` documents the already integrated optional
  discovery operator LXMF address. Native documentation, formatting, host lint,
  exact checkout, and drift checks passed, leaving 4 commits.
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
