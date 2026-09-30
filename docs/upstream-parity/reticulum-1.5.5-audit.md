# Reticulum 1.5.5 Upstream Audit

## Scope and Baseline

- audit opened: `2026-09-28`
- previous accepted version: `1.5.4`
- previous normative commit: `3f95b472820ddfb27f736143fb0b4d0d3aa610f1`
- target version: `1.5.5` (`RNS/_version.py`)
- target normative commit: `cce96d38c684e8d3e85e8cb311633fb2599515dd` (`rgit/master` snapshot cutoff)
- target root tree: `f5ddc7ea6dcd988fd075310159a9262a9acb3c47`
- target `RNS` tree: `f019bc58f0c19452b57b642b6170261695d8295d`
- candidate audited range: `3f95b472820ddfb27f736143fb0b4d0d3aa610f1..cce96d38c684e8d3e85e8cb311633fb2599515dd`
- commits in candidate range: `19`
- repositories checked: normative rgit remote and GitHub mirror, both refreshed on `2026-09-28`; rgit reached `cce96d38` while the mirror remained at `d5962d14`
- local branch and revision inspected: `dev@681e3e0ec0cc020dd9a43e8d54705a450a0db2ab`

The initial `2026-09-28` audit pinned `e2ba876ebfec386af9f97d844c39e9ca016e956c` as the nine-commit 1.5.5 target while the GitHub mirror stopped at the first commit. Fresh fetches extended the candidate through `b8993899`, `d3153bd7`, and finally `cce96d38`. The latter is the fixed cutoff for this advancement. The GitHub mirror lagged by two commits at the final complete pre-mapping refresh; the normative rgit history contains all nineteen in ancestry order.

## Audit Vocabulary

- **Needs port**: compatible behavior is absent or observably different.
- **Needs coordinated port**: related changes must be implemented together.
- **Needs decision**: architecture differs and the compatibility surface must be chosen explicitly.
- **Integrated**: applicable behavior is implemented with recorded evidence.
- **Structurally covered**: the Rust design already provides the behavior or avoids the upstream failure through a different invariant.
- **Documentation follow-up**: native documentation is required after the related behavior exists.
- **Deferred**: applicable work is deliberately postponed with rationale and impact recorded.
- **Non-runtime**: metadata, changelog, generated artifacts, or upstream-only tests require no independent Rust runtime change.

## Commit Inventory

The rows are in ancestry order. `Pending review` means no final disposition has been assigned.

| # | Upstream commit | Subject | Changed paths | Final disposition | Local evidence |
|---:|---|---|---|---|---|
| 1 | `c95fd8e6ca88c9e3b0e3306c74ff604a36894c67` | Updated rngit documentation | `docs/source/git.rst`, generated manual docs | Integrated | `b6cc476`: `docs/rns-git.md` documents changing bare `HEAD` before first push. |
| 2 | `e68f4ff118662a9fe747f956bb96c45695a5ab20` | Prepared AutoInterface for live detach/attach | `RNS/Interfaces/AutoInterface.py`, `Interface.py` | Integrated | `b0bb443`: AutoInterface exposes listener control that stops its supervisor and workers. |
| 3 | `24b1ac521e4a0456d41b3fdd82d4ceb4d330f905` | Prepared RNodeInterface for live detach/attach | RNode, RNodeMulti, Android, Auto, base interfaces | Integrated | `3629e4f`: RNode reader and keepalive stop without reconnecting on intentional detach. |
| 4 | `2c30a88e85693bb73e493bfaa56533774507f40d` | Fixed I2P interface discovery config snippet generation not including .b32.i2p | `RNS/Discovery.py` | Integrated | `e6691b5`: discovery snippets add `.b32.i2p`; focused regression. |
| 5 | `7283cb417aebef9ef94d972ca53806a06fe37b36` | Prepared serial-based interfaces for live detach/attach | AX25 KISS, KISS, Serial, Android interfaces | Integrated | `3c67396`: native Serial/KISS/AX25 reader stop and reconnect control, including late port recovery. |
| 6 | `84709ccf09fddf23a9723c6904c7678159e878af` | Prepared TCP and UDP interfaces for live detach/attach | `TCPInterface.py`, `UDPInterface.py` | Integrated | `4ade531`: TCP reconnect guard and UDP listener stop, with idle detach regressions. |
| 7 | `d23261c8d92323597e567c45580bda2c588e40aa` | Added live interface attach/detach/reload | `Reticulum.py`, `rnsd.py`, `rnstatus.py`, `using.rst` | Integrated | `66e0a2c`: config-backed attach/detach/reload, authenticated shared-instance RPC, `rnstatus` commands, TCP child shutdown, docs, and focused regressions. |
| 8 | `6ecda49394708c4d4297bb3918bc4d2b11d8e8d6` | Updated documentation | generated and Markdown using guides | Non-runtime | `5ee1ac0`: native `rnstatus` guide adds an operator example; command reference landed with row 7. |
| 9 | `e2ba876ebfec386af9f97d844c39e9ca016e956c` | Updated version | `RNS/_version.py` | Non-runtime | `52e87d0`: records the exact upstream version assertion and keeps the accepted native baseline unchanged pending gates. |
| 10 | `3b7429149e8fcf13c4310df32264c58647b6e983` | Fixed outdated meta-docs | `Contributing.md`, `Roadmap.md`, `SECURITY.md`, `This Is Not a Teahouse.md`, `docs/source/support.rst` | Non-runtime | `1791004`: records upstream-only governance and editorial changes without altering native project policies. |
| 11 | `3ad70c63ea87e94f9dc32486af7845ded9c0e852` | Fixed outdated meta-docs | `Contributing.md` | Non-runtime | `364bc8f`: records the upstream-only Markdown link correction. |
| 12 | `b899389956041693d1cbeee698bcbef2bc1b8858` | Fixed outdated meta-docs | `README.md`, `README.mu` | Non-runtime | `a5c3dd3`: records README reflow and project-specific editorial corrections; native badge remains gated. |
| 13 | `1cf176f6e5785f62a87ed0ebe7e5d12dcf3f4bc6` | Added work doc counts to filter links | `RNS/Utilities/rngit/pages.py` | Integrated | `c286997`: readable scope counts on work-page tabs, with document-level read denial applied to list, detail, and download. |
| 14 | `a93c6ba5be384558371e24f110c13d61e8a40ef2` | Added ability to download markdown files as converted micron to rngit | `RNS/Utilities/rngit/pages.py` | Integrated | `c4da0a9`: Markdown blob pages link to scoped Micron conversion; downloads include `.mu` name metadata. |
| 15 | `69c425d9ae024f00f01ec07656abf8c05c35cafd` | Updated changelog | `Changelog.md` | Non-runtime | `2e5e580`: audit-only mapping records the upstream 1.5.5 release description without copying its claims as acceptance evidence. |
| 16 | `d3153bd7784c6c6d08346b7e3e393bb0007e557f` | Added stack info to rnstatus discovered interfaces output | `RNS/Discovery.py`, `RNS/Utilities/rnstatus.py` | Integrated | `978d5e6`: discovery stack fields survive parsing, persistence and RPC; `rnstatus` shows Stack/Running with a legacy fallback. |
| 17 | `d5962d14eb4fbf4a34a0b83e6942534a4965dd17` | Updated documentation | generated manual and Markdown support page | Non-runtime | `bef4b04`: audit-only review of generated manual and removed upstream support appeal. |
| 18 | `71583c5c2d3e953c15ac7a6ce9aef62b3780d186` | Set interface owner before connect | `RNS/Interfaces/LocalInterface.py` | Structurally covered | `53aebeb`: documents complete native interface metadata before local connect; focused and full crate suites passed. |
| 19 | `cce96d38c684e8d3e85e8cb311633fb2599515dd` | Updated changelog | `Changelog.md` | Non-runtime | `c7b92e0`: audit-only release-note review linked to row 18. |

All nineteen canonical commits have one nonempty local mapping with exactly one
full `Upstream-Commit` trailer each. The local trailer order matches upstream
ancestry. The local hashes above identify the commits on `master` after PR #168
was rebased on merge. The upstream trailers were checked again after that
history rewrite; the mapped code and test evidence did not change.

## Integration Plan

Per-commit review, dispositions, and mappings are complete. The remaining
promotion work follows [README.md](README.md) and the candidate parity record.

The `e2ba876e` commit asserts upstream version `1.5.5` by changing only
`RNS/_version.py`. Native crate package versions are independent of that
upstream marker. Keep `UPSTREAM.md` and the README badge at the accepted 1.5.4
baseline until the final 1.5.5 parity record passes its promotion gates.

## Per-Commit Analysis

### 1. `c95fd8e6` — Updated rngit documentation

**Upstream change:** Adds an operator tip for selecting a primary branch other than `master` by changing the bare repository's `HEAD`. The other changed files are generated manuals and search data.

**Rust applicability:** Native `rngit` also creates and serves bare Git repositories, so the operator tip applies.

**Local handling and evidence:** `b6cc476` adds the command to `docs/rns-git.md` in the repository management section. This is documentation only; no runtime behavior changed.

**Final disposition:** Integrated.

### 2. `e68f4ff1` — Prepared AutoInterface for live detach/attach

**Upstream change:** Tracks AutoInterface discovery sockets and makes its worker loops stop on detach, closing listeners and sockets so the interface can be attached again.

**Rust applicability:** Native AutoInterface already has per-worker stop flags, but its top-level supervisor's running flag was not exposed to the node lifecycle.

**Local handling and evidence:** `b0bb443` connects the AutoInterface running flag to the listener control returned by the factory. A stop request ends supervision, which stops workers and drops their owned sockets. The focused AutoInterface tests (41) passed. The complete `rns-net` crate suite passed when run serially (959 unit tests, 56 E2E tests, and interop/fixture suites); `cargo fmt --all -- --check` and `cargo clippy -p rns-net --all-targets -- -D warnings` passed. The first parallel E2E attempt hit an unrelated address-in-use conflict in the multihop test; that test passed alone and in the serial suite.

**Final disposition:** Integrated. Runtime interface management will consume this control in the later attach/detach commit.

### 3. `24b1ac52` — Prepared RNodeInterface for live detach/attach

**Upstream change:** On intentional detach, RNode closes its serial/TCP/BLE connections, stops BLE activity, and avoids classifying the closure as a hardware failure. Multi-RNode closes its serial connection. Copyright-only changes elsewhere have no runtime effect.

**Rust applicability:** Native RNode readers and keepalive workers previously had no lifecycle stop signal. A live detach could leave the reader reconnecting and the keepalive holding its transport.

**Local handling and evidence:** `3629e4f` returns a control for multi-interface RNode startup, uses it to stop the reader and keepalive workers, and polls the reader so a quiet port can stop promptly. The existing reconnect PTY test now also verifies that intentional stop does not produce another disconnect event. The focused RNode tests (15), full serial `rns-net` suite (959 unit tests, 56 E2E tests, interop and fixture suites), formatting, and warning-free `rns-net` clippy passed. The native Android BLE RNode transport does not exist and is outside this implementation.

**Final disposition:** Integrated for the supported serial and TCP RNode transports. Runtime interface management will consume the control in the later attach/detach commit.

### 4. `2c30a88e` — Fixed I2P interface discovery config snippet generation not including .b32.i2p

**Upstream change:** Appends `.b32.i2p` to the advertised I2P destination when generating a peer configuration snippet. The additional license header does not change behavior.

**Rust applicability:** Native discovery generated the same incomplete `peers` value.

**Local handling and evidence:** `e6691b5` adds the suffix and a focused regression. The regression failed before the fix and passed afterward. The full `rns-net` suite passed (960 unit tests, 56 E2E tests, interop and fixture suites), as did formatting and warning-free clippy.

**Final disposition:** Integrated.

### 5. `7283cb41` — Prepared serial-based interfaces for live detach/attach

**Upstream change:** Serial, KISS, and AX.25 KISS close their ports on detach, stop reconnecting after intentional removal, and retry initial port-open failures. Android serial/KISS counterparts receive the same preparation; Android RNode has only a copyright change.

**Rust applicability:** Native Serial and KISS readers previously reconnected forever, and a missing port prevented startup. AX.25 KISS uses the same native KISS implementation. The upstream Android-specific classes have no separate native implementation.

**Local handling and evidence:** `3c67396` gives Simple interfaces a lifecycle control, makes serial and KISS readers poll for input so a quiet port can stop, guards reconnect loops against detachment, and treats an initially missing port or failed KISS configuration as an offline interface that retries. Focused PTY tests verify idle detach and recovery when each port appears later. The full `rns-net` suite passed (964 unit tests, 56 E2E tests, interop and fixture suites). Formatting and warning-free clippy passed; the 964 unit tests were also rerun after the final KISS failure-path adjustment.

**Final disposition:** Integrated for native Serial, KISS, and AX.25 KISS transports.

### 6. `84709ccf` — Prepared TCP and UDP interfaces for live detach/attach

**Upstream change:** Prevents a detached TCP client from reconnecting and closes a detached UDP listener. Other edits are formatting and copyright updates.

**Rust applicability:** The native TCP client reader and reconnect loop, and the UDP listener thread, previously lacked an interface-specific stop signal.

**Local handling and evidence:** `4ade531` returns lifecycle controls for TCP and UDP, checks them in idle readers and before TCP reconnect, and gives UDP a bounded receive timeout so its socket is dropped promptly. Focused tests stop both idle readers without a spurious down event. The full `rns-net` suite passed (966 unit tests, 56 E2E tests, interop and fixture suites), as did formatting and warning-free clippy.

**Final disposition:** Integrated. The live management command will invoke these controls in the next mapping.

### 7. `d23261c8` — Added live interface attach/detach/reload

**Upstream change:** Adds the default-enabled `enable_interface_management` setting, named attach/detach/reload operations that reread the config on attach, shared-instance `manage` RPC commands, and `rnstatus --attach/--detach/--reload`. Disabled interface sections can be attached explicitly. I2P and local shared-instance interfaces cannot be detached. The documentation and example config describe the commands and control setting.

**Rust applicability:** The native node had no named live-management API or matching RPC/CLI commands. Its interface factories already started each transport, and the preceding mapping commits added stop controls, but listener-only interfaces and spawned clients needed tracking by configured parent name.

**Local handling and evidence:** `66e0a2c` tracks each configured interface's parent ID, static IDs, type and control, rereads the current config for attach/reload, retires late child events, removes dynamic children and interface runtime state on detach, and updates discovery metadata. An accepted TCP server client now observes the listener stop signal and closes its socket. The node exposes named methods; the authenticated shared-instance RPC accepts the upstream `manage` map and returns the upstream tri-state result; `rnstatus` has matching options. Focused tests cover attaching a disabled UDP section, duplicate/missing names, reload from disk, disabled management, listener port and client-socket release, and actual authenticated RPC calls. The complete elevated `rns-net` suite passed (970 unit tests, 56 E2E tests, and interop/fixture suites); the elevated `rns-cli` suite passed. Formatting, staged diff checks, and warning-free clippy for both changed crates passed. Initial sandboxed full-suite attempts failed in unrelated localhost socket tests with `EPERM`; the complete reruns outside that sandbox passed.

**Post-mapping interop correction:** An exact-target `rnstatus --attach` check against native `rnsd` found that Python 1.5.5 uses an abstract Unix RPC socket on Linux and authenticates both peers with the key derived from `storage/transport_identity`. The native daemon previously exposed TCP RPC only, used its own separate identity for the key, and completed only the first half of the `multiprocessing.connection` authentication exchange. Follow-up `9baa221` adds the Unix endpoint, persists or reads the Python-compatible RPC identity with owner-only permissions, and completes mutual authentication for both native and Python clients. The exact Python 1.5.5 `rnstatus` CLI then successfully attached, reloaded, and detached a disabled UDP interface through the Rust daemon; that sequence is now an ignored exact-target CI interop regression. The final default workspace suite passed 2,532 tests, the hook-enabled suite passed 2,579 tests, and host lint passed. This follow-up has no `Upstream-Commit` trailer and does not change the one-to-one mapping.

An exact-target utility interop rerun subsequently found that Python `rncp` and `rnx` clients call `get_first_hop_timeout` through that newly working RPC transport. An unknown query returned `None` and prevented link setup. Follow-up `51f1d96` serves the numeric first-hop timeout from the selected outbound interface bitrate, falling back to the upstream six-second default. The RPC regression, complete changed-crate suite, warning-free lint, and all six exact-target utility interop cases (serial and CI-parallel) passed. This compatibility correction also has no upstream trailer.

**Final disposition:** Integrated. Final workspace, build, Docker, and promotion gates are tracked below.

### 8. `6ecda493` — Updated documentation

**Upstream change:** Copies the new `rnstatus` description and attach/detach/reload options into the published manual source, rendered HTML, search index, and Markdown using guide. The full diff contains no executable changes.

**Rust applicability:** The native command reference and control behavior were added with row 7. Native documentation is maintained as Markdown rather than copying upstream's generated manual artifacts.

**Local handling and evidence:** `5ee1ac0` adds a concrete attach/detach/reload example to `docs/rnstatus.md`. The command list and management setting were documented in `66e0a2c`. The mapping is documentation-only; the complete `rns-net` and `rns-cli` suites passed on the preceding runtime mapping. No additional runtime test is applicable.

**Final disposition:** Non-runtime.

### 9. `e2ba876e` — Updated version

**Upstream change:** Changes only `RNS/_version.py` from `1.5.4` to `1.5.5`. It changes no protocol or interface behavior. The later three meta-documentation commits retain this version and the same `RNS` tree.

**Rust applicability:** Native crate package versions follow their own release cycle. `UPSTREAM.md` and the README badge describe an accepted upstream baseline, so changing them before parity acceptance would incorrectly claim completion.

**Local handling and evidence:** `52e87d0` records the exact version assertion and the hold on baseline promotion in this active audit. The one-line upstream diff was reviewed; no additional runtime test is applicable. The preceding runtime mapping passed the complete changed-crate suites. The drift checker was rerun after row 8, but repeated rgit link timeouts left those checks incomplete; a fresh complete result remains required for promotion.

**Final disposition:** Non-runtime.

### 10. `3b742914` — Fixed outdated meta-docs

**Upstream change:** Replaces the upstream contributor guidance with current project communication and contribution policies, adds a security-reporting contact, removes the public roadmap, adjusts a support appeal, and edits a project essay. The full diff changes no `RNS` source, protocol, release version, or wire-facing documentation.

**Rust applicability:** These are policies and editorial choices of the upstream Reticulum project. This repository has its own `CONTRIBUTING.md`; copying the upstream contact, CLA, or contribution restrictions here would misstate this project's governance. The removed roadmap included a live interface control aspiration, which rows 2–7 already address as implemented behavior rather than a policy promise.

**Local handling and evidence:** This audit records the policy boundary and the full changed-path review. No native runtime change or test is applicable. The current 1.5.5 `RNS` tree remains unchanged.

**Final disposition:** Non-runtime.

### 11. `3ad70c63` — Fixed outdated meta-docs

**Upstream change:** Escapes spaces in two links from upstream `Contributing.md` to `This Is Not a Teahouse.md`. The full diff changes only the Markdown destinations; it does not alter the linked document, executable code, or network behavior.

**Rust applicability:** This repository does not carry those upstream policy pages. Its own contribution guide has separate links and governance.

**Local handling and evidence:** This audit records the exact link correction and the absence of a native target. The source-only change needs no runtime test or copied upstream policy.

**Final disposition:** Non-runtime.

### 12. `b8993899` — Fixed outdated meta-docs

**Upstream change:** Reflows much of the upstream README, revises its custom-interface contribution wording, notes that RNode can connect over USB, WiFi, or Bluetooth, and replaces an outdated statement about external security audits with a more general security caution. `README.mu` receives the same caution. The complete diff contains no executable lines; the `RNS` tree is identical to the preceding version commit.

**Rust applicability:** The native README describes a different implementation and release process. It does not repeat the changed RNode connectivity or upstream audit claims, and its contribution policy is independent. Its 1.5.4 badge and reference remain correct until the 1.5.5 promotion gates pass.

**Local handling and evidence:** This audit records the substantive editorial changes and the independent-documentation boundary. No native runtime test is applicable; the README badge and accepted-reference text will be updated by the final promotion commit only after the parity record is complete.

**Final disposition:** Non-runtime.

### 13. `1cf176f6` — Added work doc counts to filter links

**Upstream change:** Counts readable active, completed, and proposed work documents for each filter link and moves counts out of section headings. A document with denied read access must not contribute to a visible count.

**Rust applicability:** Native `rngit` already lists these scopes but its filter links did not show counts. Its work page also listed documents with explicit document-level read denial despite repository-level read access.

**Local handling and evidence:** `c286997` lists all scopes for counts, filters explicit document-level read denials from the visible lists, and applies the same denial to detail and download handlers. The focused page regression passed, including counts before and after `read = none`; the complete `rns-git` suite passed (234 tests across eight suites), as did formatting and warning-free crate lint.

**Final disposition:** Integrated.

### 14. `a93c6ba5` — Added ability to download markdown files as converted micron to rngit

**Upstream change:** Offers an `as micron` link on Markdown blob pages and converts a requested `.md` Git blob to Micron with relative links scoped to that blob's directory. The response is named with a `.mu` extension; unrelated files and formats cannot request conversion.

**Rust applicability:** Native `rngit` already converts Markdown for page display but offered only raw blob download. Its download handler did not accept a conversion format or attach a converted filename.

**Local handling and evidence:** `c4da0a9` shares the existing scoped Markdown renderer with the download path, adds the converted link and `.mu` filename metadata, and keeps the original download available. A focused regression verifies rendered-page controls, converted content and link scope, filename metadata, and raw download bytes. The complete `rns-git` suite passed (235 tests across eight suites), as did formatting and warning-free crate lint. `docs/rns-git.md` describes the new option.

**Final disposition:** Integrated.

### 15. `69c425d9` — Updated changelog

**Upstream change:** Retitles the current changelog entry as RNS 1.5.5, preserves the prior 1.5.4 entry below it, and lists live interface management, Micron-converted `rngit` downloads, work-document counts, I2P discovery snippet correction, and documentation updates. It changes no executable source or wire format.

**Rust applicability:** The changelog is upstream release communication. The applicable runtime changes are reviewed and mapped under their own source commits. Native crate versions and historical fixture provenance do not change because of an upstream prose entry.

**Local handling and evidence:** This audit-only mapping records the full changed-path review and cross-checks the enumerated behavior against rows 4, 7, 13, and 14. The upstream release description is not counted as proof of compatibility; each behavior retains its own test evidence. No independent runtime test applies to this commit.

**Final disposition:** Non-runtime.

### 16. `d3153bd7` — Added stack info to rnstatus discovered interfaces output

**Upstream change:** Reads the optional discovery `TRANSPORT_IMPL` and `TRANSPORT_VERS` fields, includes them in discovery logs and status data, and shows a `Stack` line in detailed `rnstatus` output or a `Running` column in its table. Missing fields display as unknown.

**Rust applicability:** Native announcements already transmitted both fields, but the receiver discarded them. Persistence, RPC, and `rnstatus` therefore could not display the announcing implementation or version.

**Local handling and evidence:** `978d5e6` retains optional fields during announcement parsing, persists them compatibly with older records, includes them in the shared-instance RPC, and adds the detailed and table displays with an `Unknown` fallback. Focused tests cover wire parsing and absent fields, persistence roundtrip, RPC serialization, and CLI formatting. The complete `rns-net` and `rns-cli` suites passed (1,251 tests across 24 suites); formatting and warning-free changed-crate lint passed. `docs/rnstatus.md` describes the output.

**Final disposition:** Integrated.

### 17. `d5962d14` — Updated documentation

**Upstream change:** Regenerates the published 1.5.5 manual, its search assets and page metadata, removes two unreferenced images, and removes an outdated support appeal from the Markdown and generated support pages. The complete commit contains no `RNS` source change.

**Rust applicability:** The native documentation is maintained independently and does not carry that support appeal or the upstream generated manual. The accepted-version references remain gated on this audit's final parity checks.

**Local handling and evidence:** This audit-only mapping records the generated-document review and the absence of a native runtime or support-page counterpart. No executable test applies to this commit.

**Final disposition:** Non-runtime.

### 18. `71583c5c` — Set interface owner before connect

**Upstream change:** Initializes the Python local client's owner and 1 Gbit/s bitrate before `connect()` can invoke a callback. Previously an immediately connected peer could observe a partially initialized interface. No wire fields or connection sequence changed.

**Rust applicability:** Native `LocalClientFactory::start` constructs the complete `InterfaceInfo`, including bitrate, before calling `start_client`. The client config and event sender are complete values before a socket opens; the driver installs the returned interface metadata before consuming queued connection events. There is no mutable Python-style owner field to fill after connection.

**Local handling and evidence:** The mapping documents this ordering at the connection site. The existing `client_send_receive` regression observes immediate client and server `InterfaceUp` events and frame transfer; `client_reconnects_after_tcp_restart` exercises the same configured client after reconnection. The focused immediate-connect test, complete serial `rns-net` suite (971 unit tests, 56 E2E tests and interop/fixture suites), formatting, and warning-free crate lint passed.

**Final disposition:** Structurally covered.

### 19. `cce96d38` — Updated changelog

**Upstream change:** Adds one 1.5.5 release-note bullet describing the potential `LocalInterface` initialization race fixed by `71583c5c`. The complete diff touches only `Changelog.md` and changes no executable behavior.

**Rust applicability:** The preceding mapping establishes the native initialization invariant and its regression evidence. The upstream release note is not an independent compatibility claim or native crate release instruction.

**Local handling and evidence:** This audit-only mapping records the full changelog diff and its dependency on row 18. No separate runtime test applies; row 18 carries the relevant complete crate suite and focused evidence.

**Final disposition:** Non-runtime.

### 20. `73c60e6a` — Updated contribution guidelines

**Upstream change:** Rewrites the upstream development-priorities sentence and adds a mandatory commit-signing requirement to upstream `Contributing.md`. The complete diff changes no executable source.

**Rust applicability:** This repository has its own `CONTRIBUTING.md` with an independent governance and signing policy. Copying upstream's signing mandate here would misstate this project's process.

**Local handling and evidence:** This audit-only mapping records the full changed-file review and the policy boundary. No native runtime or test change applies.

**Final disposition:** Non-runtime.

### 21. `f25b3170` — Added disclosure requirements to contribution guidelines

**Upstream change:** Adds a machine-assistance disclosure-header requirement and comment-rewrite rule to upstream `Contributing.md`. The complete diff changes no executable source.

**Rust applicability:** This is upstream contribution policy. This repository documents its own contribution process independently.

**Local handling and evidence:** This audit-only mapping records the disclosure requirement and its upstream-only scope. No native runtime or test change applies.

**Final disposition:** Non-runtime.

### 22. `6c9d717c` — Fixed ingress control producer selection

**Upstream change:** A mid-watermark producer list comprehension tested the outer `interface` variable instead of each candidate `iface`, so a `LocalClientInterface` could be selected for throttling. The fix filters each producer.

**Rust applicability:** Native Backbone dataplane producer selection (`busiest_ingress_key`) iterates only the spawned peer `ClientState` map. Local client interfaces are never entries in that map, so they cannot be selected as producers; the exclusion holds by construction rather than by a type test.

**Local handling and evidence:** The invariant is in `busiest_ingress_key` and `throttle_busiest_ingress` (`rns-net/src/interface/backbone.rs`). The existing `dataplane_ingress_selects_the_largest_packet_producer` and `backbone_gates_the_largest_producer_before_data_queue_overflow` tests exercise the selection path. No code change was required.

**Final disposition:** Structurally covered.

### 23. `06dc4ad5` — Fixed announce_cap percent/fraction mismatch

**Upstream change:** Three `hasattr` fallbacks assigned the percent value `RNS.Reticulum.ANNOUNCE_CAP` instead of `ANNOUNCE_CAP/100.0`, so an uninitialized interface could store `2` where a `0.02` fraction was expected.

**Rust applicability:** `InterfaceInfo::announce_cap` is always a fraction and defaults to the compile-time `constants::ANNOUNCE_CAP = 0.02`. There is no percent-valued constant or conversion path, so the upstream mismatch cannot occur.

**Local handling and evidence:** The unit is documented on the field and used directly by `InterfaceAnnounceQueue::calculate_next_allowed` (`rns-core/src/transport/announce_queue.rs`): `delay = time_to_send / announce_cap`. The announce-queue tests cover the cap behavior. No code change was required.

**Final disposition:** Structurally covered.

### 24. `5cdff287` — Process timeouts/rejections for single-packet requests

**Upstream change:** `request_timed_out` and `response_rejected` only acted when the request status was `DELIVERED`, so single-packet requests still in `SENT` were never concluded.

**Rust applicability:** Native link requests are not modeled with a `DELIVERED`/`SENT` status. Single-packet requests insert a `PendingRequest` with a computed deadline, and the link tick culls every expired deadline regardless of delivery state. Resource requests use a delivery-proof deadline and separately remove requests whose resource fails.

**Local handling and evidence:** `unanswered_packet_request_expires_from_pending_set` (`rns-net/src/common/link_manager/tests.rs`) sends a packet request and asserts it is removed after its deadline, proving the SENT-equivalent path is concluded. No code change was required.

**Final disposition:** Structurally covered.

### 25. `4f791109` — Ensure announce_cap is always initialized

**Upstream change:** Initializes `self.announce_cap` in `Interface.__init__` so process-announce-queue always has a value.

**Rust applicability:** `InterfaceInfo::announce_cap` is a non-optional `f64` field constructed by every interface factory, so it can never be absent.

**Local handling and evidence:** The field definition and every constructor set it to `constants::ANNOUNCE_CAP` unless overridden. No code change was required.

**Final disposition:** Structurally covered.

### 26. `1d9ebe8c` — Propagate configurable properties to spawned interfaces

**Upstream change:** Copies `recursive_prs`, `announces_from_internal`, `announces_to_internal`, and `announce_cap` from a parent interface to each AutoInterface, BackboneInterface, and TCPServerInterface child it spawns.

**Rust applicability:** Native dynamic-child registration already inherited `mode`, `gravity`, `recursive_prs`, `announces_from_internal`, `announces_to_internal`, `announce_rate_target/grace/penalty`, and `ingress_control`. It did not inherit `announce_cap`, so a spawned peer used the default cap regardless of its parent.

**Local handling and evidence:** `handle_dynamic_interface_up_event` (`rns-net/src/driver/events.rs`) now copies `announce_cap` alongside the other inherited properties. The focused `dynamic_interface_inherits_parent_announce_cap` test sets a parent cap of `0.5` and observes it on the registered child. The complete `rns-net` library suite passed serially (978 tests).

**Final disposition:** Integrated.

### 27. `135e941f` — Improve interface-discovery IFAC sanitization

**Upstream change:** Guards IFAC publication so a discoverable interface without a configured network name or passphrase disables publishing instead of advertising literal `"None"` values; the discovery handler accepts only non-empty string IFAC fields and drops persisted `"None"`; config parsing warns about and ignores the literal `"None"` network name/passphrase.

**Rust applicability:** Native discovery stringified any msgpack IFAC value (including `Nil` as `"None"`), persisted it, and republished it. Native config parsing also accepted empty and literal `"None"` values, deriving a bogus IFAC state. Native code has no separate `discovery_publish_ifac` flag: it publishes IFAC fields only when present, so the publication guard is structural.

**Local handling and evidence:** `sanitize_ifac_announce_string` in `common/discovery.rs` accepts only non-empty `Value::Str` other than `"None"`; `sanitize_persisted_ifac` drops `"None"`/empty values from stored discovery records; the announcer publishes only truthy fields; and `sanitize_ifac_config_string` in `node.rs` ignores empty and `"None"` config values with a warning. Tests `parse_accepts_valid_string_ifac_fields`, `parse_drops_nonsensical_ifac_fields`, `sanitize_persisted_ifac_drops_none_and_empty`, and the extended `test_extract_ifac_config` cover the paths. The complete `rns-net` suite passed serially (978 tests).

**Final disposition:** Integrated.

### 28. `26aec004` — Use canonical detach in auto-connect teardown

**Upstream change:** The discovery monitor's `teardown_interface` calls `Reticulum._detach_interface(name, internal_forced=True)` instead of invoking `interface.detach()` plus `Transport.remove_interface` directly.

**Rust applicability:** Native auto-connect does not spawn named monitor interfaces. Discovered backbone peers are managed as backbone peer-pool candidates, and removing a candidate goes through the pool's canonical teardown (`handle_backbone_peer_pool_down`), which deregisters the interface and clears runtime state exactly once. There is no parallel detach path to converge.

**Local handling and evidence:** The canonical teardown is exercised by the peer-pool connect/seed e2e tests (`backbone_peer_pool_connects_live_discovered_peer`, `backbone_peer_pool_seeds_from_cached_discovered_peer`). No code change was required.

**Final disposition:** Structurally covered.

### 29. `0a0e661b` — Propagate internal_forced on interface reload

**Upstream change:** `_reload_interface` forwards its `internal_forced` argument to the detach and attach calls it performs.

**Rust applicability:** Native interface reload is implemented as detach followed by attach through the shared `manage_interface` path; it has no `internal_forced` argument because the management policy is gated once by `enable_interface_management`. There is no internal monitor that bypasses the flag, so the dropped-argument bug cannot occur.

**Local handling and evidence:** The reload behavior is covered by the interface-management tests (`managed_interface_attaches_disabled_section_and_reloads_from_disk`, `shared_instance_rpc_manages_interface_by_name`). No code change was required.

**Final disposition:** Structurally covered.

### 30. `6d1409be` — Idempotent auto-connect monitoring on manual detach

**Upstream change:** The discovery monitor detects that a monitored auto-connected interface was removed from `Transport.interfaces` and drops it from monitoring before consulting its online state, and teardown only detaches when the interface is still registered.

**Rust applicability:** Native auto-connected peers are peer-pool candidates keyed by `active_id`. When a connection goes down or is removed, pool handling locates the candidate by `active_id` and clears it once; a missing registration is simply absent from the pool. The "interface no longer registered" condition is already the normal keyed lookup, so no double-detach occurs.

**Local handling and evidence:** Pool down and cull behavior is covered by `backbone_peer_pool_*` tests in `driver/tests.rs` and `tests/e2e.rs`. No code change was required.

**Final disposition:** Structurally covered.

### 31. `fc95caf5` — Atomic sequential naming on auto-connect name collisions

**Upstream change:** Adds an `autoconnect_lock` and an `autoconnect_interface_name` helper that appends ` (n)` so a discovered interface whose announced name collides with an existing interface is connected under a unique name.

**Rust applicability:** Native discovered peers are identified by transport identity and endpoint, not by display name, and the pool deduplicates candidates on the discovery hash or endpoint match. Interface names are cosmetic labels (`discovered_pool_candidate_name`), so a duplicate display name cannot cause the registration collision the upstream fix prevents; no lock or renaming is needed.

**Local handling and evidence:** Candidate deduplication and naming are exercised by `backbone_peer_pool_*` tests. No code change was required.

**Final disposition:** Structurally covered.

### 32. `bb132091` — Add discovered auto-connect criteria constants and config

**Upstream change:** Adds `AUTOCONNECT_IMPLS = ["RNS"]` and `AUTOCONNECT_MIN_V = "1.5.2"` constants and the `autoconnect_unverified_implementations` `[reticulum]` option, exposed through `should_autoconnect_unverified_implementations()`.

**Rust applicability:** Native discovery had no implementation/version policy for auto-connect. This mapping adds the configuration surface and sample-config documentation; the qualification logic itself lands with the next criteria mapping.

**Local handling and evidence:** `ReticulumConfig`, the driver, and `NodeConfig` gain the field, parsed from `autoconnect_unverified_implementations` and defaulting to `false`. The `parse_interface_gravity_defaults_and_autoconnect_options` and new `autoconnect_unverified_implementations_defaults_to_false` tests cover parsing. `rns-cli/src/rnsd.rs` documents the option. The complete `rns-net` suite passed serially (978 tests).

**Final disposition:** Integrated.

### 33. `47318034` — Auto-connect support on Windows and macOS

**Upstream change:** Detects platforms without Backbone support and auto-connects discovered Backbone peers as `TCPClientInterface` instead, narrowing `AUTOCONNECT_TYPES` to `BackboneInterface` and removing the earlier TCPClient abort branch.

**Rust applicability:** The native Backbone implementation is a cross-platform polling TCP transport and works on Windows and macOS, so no platform degradation is required. Native discovered auto-connect is endpoint-based and already accepts both `BackboneInterface` and `TCPServerInterface` discovered types.

**Local handling and evidence:** Continuing to auto-connect `TCPServerInterface` discoveries is a deliberate native difference because the native transport has no platform limitation to work around. Peer-pool e2e tests cover connection establishment. No code change was required.

**Final disposition:** Structurally covered.

## Promotion Gates

- [x] Every upstream commit has a final disposition.
- [x] Focused regressions pass for every applicable behavior change.
- [x] Fixture provenance and byte stability are checked where applicable.
- [x] Exact-target live Python/Rust interop passes.
- [x] Workspace tests, feature suites, formatting, and lint pass.
- [x] Required build, Docker, hardware, and manual gates are recorded honestly.
- [x] Native documentation is updated for user-visible behavior.
- [x] A candidate parity record is created from `PARITY-TEMPLATE.md`.

## Acceptance Record

- `2026-09-28`: Daily VPS snapshots were healthy and complete on both hosts. The impaired dual-VPS `--daily` smoke passed Resource boundaries, concurrent links, and forced reconnect recovery. Both upstream remotes refreshed successfully. These are daily operational results, not promotion acceptance for the candidate target.
- `2026-09-28`: Both remotes freshly fetched and agreed at `b899389956041693d1cbeee698bcbef2bc1b8858` after all twelve mappings. The exact-target disposable worktree asserted Python version `1.5.5`, root tree `0a29475288cefe43f7fb432ed69a93bf901ecf35`, and `RNS` tree `62dc6859a28fc76b064e0c2fa062ff560ad9a343`. Its live `rns-net` Python interop test passed (1/1), as did all five ignored `rns-cli` utility interop cases (5/5).
- `2026-09-29`: Both VPS snapshots were healthy and complete, and the impaired
  `--daily` Backbone smoke passed Resource boundaries, concurrent links, and
  forced reconnect. Fresh GitHub and rgit fetches still found the candidate
  `cce96d38` at rgit and a mirror two commits behind at `d5962d14`.
- `2026-09-29`: The complete `./tests/docker/run-all.sh` matrix passed: 11
  topology and standalone runs, 102 checks passed, 0 failed, and 29 expected
  topology-specific skips. This includes mesh-4, star-30 scale, shared-client
  reconnection, server supervision, NAT, and `rntun` tunnel/reconnect coverage.
  PR CI and final promotion review remain pending.
