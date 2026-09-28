# Reticulum 1.5.5 Upstream Audit

## Scope and Baseline

- audit opened: `2026-09-28`
- previous accepted version: `1.5.4`
- previous normative commit: `3f95b472820ddfb27f736143fb0b4d0d3aa610f1`
- target version: `1.5.5` (`RNS/_version.py`)
- target normative commit: `b899389956041693d1cbeee698bcbef2bc1b8858` (`rgit/master`)
- current rgit tip root tree: `0a29475288cefe43f7fb432ed69a93bf901ecf35`
- current rgit tip `RNS` tree: `62dc6859a28fc76b064e0c2fa062ff560ad9a343`
- candidate audited range: `3f95b472820ddfb27f736143fb0b4d0d3aa610f1..b899389956041693d1cbeee698bcbef2bc1b8858`
- commits in candidate range: `12`
- repositories checked: normative rgit remote and GitHub mirror, both refreshed on `2026-09-28`
- local branch and revision inspected: `dev@681e3e0ec0cc020dd9a43e8d54705a450a0db2ab`

The initial `2026-09-28` audit pinned `e2ba876ebfec386af9f97d844c39e9ca016e956c` as the nine-commit 1.5.5 target while the GitHub mirror stopped at the first commit. A later fresh fetch found three subsequent meta-documentation commits on both remotes, so the promotion target was extended to their shared tip `b899389956041693d1cbeee698bcbef2bc1b8858`. Its `RNS` tree remains identical to the original 1.5.5 target. Final dispositions and acceptance still require source review.

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
| 1 | `c95fd8e6ca88c9e3b0e3306c74ff604a36894c67` | Updated rngit documentation | `docs/source/git.rst`, generated manual docs | Integrated | `34a2e28`: `docs/rns-git.md` documents changing bare `HEAD` before first push. |
| 2 | `e68f4ff118662a9fe747f956bb96c45695a5ab20` | Prepared AutoInterface for live detach/attach | `RNS/Interfaces/AutoInterface.py`, `Interface.py` | Integrated | `ae72d50`: AutoInterface exposes listener control that stops its supervisor and workers. |
| 3 | `24b1ac521e4a0456d41b3fdd82d4ceb4d330f905` | Prepared RNodeInterface for live detach/attach | RNode, RNodeMulti, Android, Auto, base interfaces | Integrated | `4155535`: RNode reader and keepalive stop without reconnecting on intentional detach. |
| 4 | `2c30a88e85693bb73e493bfaa56533774507f40d` | Fixed I2P interface discovery config snippet generation not including .b32.i2p | `RNS/Discovery.py` | Integrated | `c24dc22`: discovery snippets add `.b32.i2p`; focused regression. |
| 5 | `7283cb417aebef9ef94d972ca53806a06fe37b36` | Prepared serial-based interfaces for live detach/attach | AX25 KISS, KISS, Serial, Android interfaces | Integrated | `aa1fac4`: native Serial/KISS/AX25 reader stop and reconnect control, including late port recovery. |
| 6 | `84709ccf09fddf23a9723c6904c7678159e878af` | Prepared TCP and UDP interfaces for live detach/attach | `TCPInterface.py`, `UDPInterface.py` | Integrated | `0a3b8eb`: TCP reconnect guard and UDP listener stop, with idle detach regressions. |
| 7 | `d23261c8d92323597e567c45580bda2c588e40aa` | Added live interface attach/detach/reload | `Reticulum.py`, `rnsd.py`, `rnstatus.py`, `using.rst` | Integrated | `0c7a85c`: config-backed attach/detach/reload, authenticated shared-instance RPC, `rnstatus` commands, TCP child shutdown, docs, and focused regressions. |
| 8 | `6ecda49394708c4d4297bb3918bc4d2b11d8e8d6` | Updated documentation | generated and Markdown using guides | Pending review | — |
| 9 | `e2ba876ebfec386af9f97d844c39e9ca016e956c` | Updated version | `RNS/_version.py` | Pending review | — |
| 10 | `3b7429149e8fcf13c4310df32264c58647b6e983` | Fixed outdated meta-docs | `Contributing.md`, `Roadmap.md`, `SECURITY.md`, `This Is Not a Teahouse.md`, `docs/source/support.rst` | Pending review | — |
| 11 | `3ad70c63ea87e94f9dc32486af7845ded9c0e852` | Fixed outdated meta-docs | `Contributing.md` | Pending review | — |
| 12 | `b899389956041693d1cbeee698bcbef2bc1b8858` | Fixed outdated meta-docs | `README.md`, `README.mu` | Pending review | — |

## Integration Plan

Review each commit's full diff in ancestry order and assign a supported disposition. Complete the per-commit integration and promotion workflow in [README.md](README.md).

## Per-Commit Analysis

### 1. `c95fd8e6` — Updated rngit documentation

**Upstream change:** Adds an operator tip for selecting a primary branch other than `master` by changing the bare repository's `HEAD`. The other changed files are generated manuals and search data.

**Rust applicability:** Native `rngit` also creates and serves bare Git repositories, so the operator tip applies.

**Local handling and evidence:** `34a2e28` adds the command to `docs/rns-git.md` in the repository management section. This is documentation only; no runtime behavior changed.

**Final disposition:** Integrated.

### 2. `e68f4ff1` — Prepared AutoInterface for live detach/attach

**Upstream change:** Tracks AutoInterface discovery sockets and makes its worker loops stop on detach, closing listeners and sockets so the interface can be attached again.

**Rust applicability:** Native AutoInterface already has per-worker stop flags, but its top-level supervisor's running flag was not exposed to the node lifecycle.

**Local handling and evidence:** `ae72d50` connects the AutoInterface running flag to the listener control returned by the factory. A stop request ends supervision, which stops workers and drops their owned sockets. The focused AutoInterface tests (41) passed. The complete `rns-net` crate suite passed when run serially (959 unit tests, 56 E2E tests, and interop/fixture suites); `cargo fmt --all -- --check` and `cargo clippy -p rns-net --all-targets -- -D warnings` passed. The first parallel E2E attempt hit an unrelated address-in-use conflict in the multihop test; that test passed alone and in the serial suite.

**Final disposition:** Integrated. Runtime interface management will consume this control in the later attach/detach commit.

### 3. `24b1ac52` — Prepared RNodeInterface for live detach/attach

**Upstream change:** On intentional detach, RNode closes its serial/TCP/BLE connections, stops BLE activity, and avoids classifying the closure as a hardware failure. Multi-RNode closes its serial connection. Copyright-only changes elsewhere have no runtime effect.

**Rust applicability:** Native RNode readers and keepalive workers previously had no lifecycle stop signal. A live detach could leave the reader reconnecting and the keepalive holding its transport.

**Local handling and evidence:** `4155535` returns a control for multi-interface RNode startup, uses it to stop the reader and keepalive workers, and polls the reader so a quiet port can stop promptly. The existing reconnect PTY test now also verifies that intentional stop does not produce another disconnect event. The focused RNode tests (15), full serial `rns-net` suite (959 unit tests, 56 E2E tests, interop and fixture suites), formatting, and warning-free `rns-net` clippy passed. The native Android BLE RNode transport does not exist and is outside this implementation.

**Final disposition:** Integrated for the supported serial and TCP RNode transports. Runtime interface management will consume the control in the later attach/detach commit.

### 4. `2c30a88e` — Fixed I2P interface discovery config snippet generation not including .b32.i2p

**Upstream change:** Appends `.b32.i2p` to the advertised I2P destination when generating a peer configuration snippet. The additional license header does not change behavior.

**Rust applicability:** Native discovery generated the same incomplete `peers` value.

**Local handling and evidence:** `c24dc22` adds the suffix and a focused regression. The regression failed before the fix and passed afterward. The full `rns-net` suite passed (960 unit tests, 56 E2E tests, interop and fixture suites), as did formatting and warning-free clippy.

**Final disposition:** Integrated.

### 5. `7283cb41` — Prepared serial-based interfaces for live detach/attach

**Upstream change:** Serial, KISS, and AX.25 KISS close their ports on detach, stop reconnecting after intentional removal, and retry initial port-open failures. Android serial/KISS counterparts receive the same preparation; Android RNode has only a copyright change.

**Rust applicability:** Native Serial and KISS readers previously reconnected forever, and a missing port prevented startup. AX.25 KISS uses the same native KISS implementation. The upstream Android-specific classes have no separate native implementation.

**Local handling and evidence:** `aa1fac4` gives Simple interfaces a lifecycle control, makes serial and KISS readers poll for input so a quiet port can stop, guards reconnect loops against detachment, and treats an initially missing port or failed KISS configuration as an offline interface that retries. Focused PTY tests verify idle detach and recovery when each port appears later. The full `rns-net` suite passed (964 unit tests, 56 E2E tests, interop and fixture suites). Formatting and warning-free clippy passed; the 964 unit tests were also rerun after the final KISS failure-path adjustment.

**Final disposition:** Integrated for native Serial, KISS, and AX.25 KISS transports.

### 6. `84709ccf` — Prepared TCP and UDP interfaces for live detach/attach

**Upstream change:** Prevents a detached TCP client from reconnecting and closes a detached UDP listener. Other edits are formatting and copyright updates.

**Rust applicability:** The native TCP client reader and reconnect loop, and the UDP listener thread, previously lacked an interface-specific stop signal.

**Local handling and evidence:** `0a3b8eb` returns lifecycle controls for TCP and UDP, checks them in idle readers and before TCP reconnect, and gives UDP a bounded receive timeout so its socket is dropped promptly. Focused tests stop both idle readers without a spurious down event. The full `rns-net` suite passed (966 unit tests, 56 E2E tests, interop and fixture suites), as did formatting and warning-free clippy.

**Final disposition:** Integrated. The live management command will invoke these controls in the next mapping.

### 7. `d23261c8` — Added live interface attach/detach/reload

**Upstream change:** Adds the default-enabled `enable_interface_management` setting, named attach/detach/reload operations that reread the config on attach, shared-instance `manage` RPC commands, and `rnstatus --attach/--detach/--reload`. Disabled interface sections can be attached explicitly. I2P and local shared-instance interfaces cannot be detached. The documentation and example config describe the commands and control setting.

**Rust applicability:** The native node had no named live-management API or matching RPC/CLI commands. Its interface factories already started each transport, and the preceding mapping commits added stop controls, but listener-only interfaces and spawned clients needed tracking by configured parent name.

**Local handling and evidence:** `0c7a85c` tracks each configured interface's parent ID, static IDs, type and control, rereads the current config for attach/reload, retires late child events, removes dynamic children and interface runtime state on detach, and updates discovery metadata. An accepted TCP server client now observes the listener stop signal and closes its socket. The node exposes named methods; the authenticated shared-instance RPC accepts the upstream `manage` map and returns the upstream tri-state result; `rnstatus` has matching options. Focused tests cover attaching a disabled UDP section, duplicate/missing names, reload from disk, disabled management, listener port and client-socket release, and actual authenticated RPC calls. The complete elevated `rns-net` suite passed (970 unit tests, 56 E2E tests, and interop/fixture suites); the elevated `rns-cli` suite passed. Formatting, staged diff checks, and warning-free clippy for both changed crates passed. Initial sandboxed full-suite attempts failed in unrelated localhost socket tests with `EPERM`; the complete reruns outside that sandbox passed.

**Final disposition:** Integrated. Exact-target Python/Rust interop and promotion gates remain to be run after all nine mappings are complete.

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

- `2026-09-28`: Daily VPS snapshots were healthy and complete on both hosts. The impaired dual-VPS `--daily` smoke passed Resource boundaries, concurrent links, and forced reconnect recovery. Both upstream remotes refreshed successfully. These are daily operational results, not promotion acceptance for the candidate target.
