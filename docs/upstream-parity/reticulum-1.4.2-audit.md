# Reticulum 1.4.2 Upstream Audit

## Scope and Baseline

- audit date: `2026-07-27`
- previous accepted version: `1.4.1`
- previous normative commit: `b2188ce9a746a35b770b10bea1b7ccbe93b4e198`
- target version: `1.4.2`
- target tag or ref: `1.4.2`
- target normative commit: `b48b96e61676504e0a4e527b33b9a0b4495c6872`
- target root tree: `2dfddfdd5d9b11eda628fb5b277f3ec007363c75`
- target `RNS` tree: `3286dd665827d2e591b47efaa5706b643e9b8d5a`
- version assertion: `RNS.__version__ == "1.4.2"`
- audited range: `b2188ce9a746a35b770b10bea1b7ccbe93b4e198..b48b96e61676504e0a4e527b33b9a0b4495c6872`
- commits in range: `6`
- repositories checked: Reticulum `origin/master` and `rgit/master`
- local branch and revision inspected: `dev@f8711cfb9e9f60f3338d541585ee85140250e425`

Both checked upstream remotes resolve to the same target commit. The annotated
`1.4.2` tag also resolves to that commit. The tag contains an SSH signature,
but local cryptographic verification was not possible because Git has no
`gpg.ssh.allowedSignersFile` configured. The final commit contains release
notes and generated documentation in addition to the version metadata changed
earlier in the range.

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

Every commit in the audited range appears exactly once.

| # | Upstream commit | Subject | Final disposition | Local evidence |
|---:|---|---|---|---|
| 1 | `4760103aa660f3fdd628a8124875dda672a71ac9` | Ensure interface is online at time of recursive PR emission | Structurally covered | Local `c855c30` pins the dispatch invariant with `recursive_path_request_does_not_reach_offline_interface_writer` at the complete engine-action boundary |
| 2 | `0416c419561f79d6cf6fd56af0bfd9eee9a7276a` | Faster blackhole filtering for discovered interfaces on mobile / over RPC | Structurally covered | Discovery cleanup and blackhole lookup execute inside one Rust driver process; RPC exposes the full blackhole set with one `GetBlackholed` query; cleanup behavior has a focused blackhole regression |
| 3 | `e3f1a5e7cdd6f0bf3c0c0a05b055c3f196b1fd15` | Updated version | Non-runtime | Local `1f86012` promotes `UPSTREAM.md`, README and the exact CI interop pin to 1.4.2 without changing independent Rust crate versions |
| 4 | `64fee86ebc452d2eae716e4bb894df22b1c8f91d` | Cleanup | Integrated | Local `5d51389` aligns the initiator INFO default and path, link, peer-version and session lifecycle logging with updated log-level coverage |
| 5 | `529a9fd460d8ff33a4506db79e641314744ab135` | Cleaned up dead imports. Improved logging. | Integrated | Local `351dfa0` makes post-handshake re-identification fatal, adds `WaitCommand`/`Running` regressions and aligns authentication/execution lifecycle logs |
| 6 | `b48b96e61676504e0a4e527b33b9a0b4495c6872` | Prepare release | Non-runtime | Changelog and generated upstream release/documentation artifacts |

## Per-Commit Analysis

### 1. `4760103a` — Ensure interface is online at time of recursive PR emission

**Upstream change:** Recursive path-request forwarding now skips an interface
that is not online. This prevents an uninitialised RNode interface from reaching
its transmit path and dividing by zero.

**Rust applicability:** The core transport engine deliberately does not own
live interface state, so it may still produce a `SendOnInterface` action for an
offline interface. The network driver is the sole emission boundary and checks
both `online` and `enabled` before any writer or interface-specific send logic
runs.

**Local handling and evidence:** `dispatch_send_on_interface()` returns before
transmission when either flag is false. Broadcast dispatch applies the same
guard. `recursive_path_request_does_not_reach_offline_interface_writer`
constructs the recursive action in the transport engine, dispatches it against
an offline interface, and proves the writer and transmit counters remain
untouched.

**Final disposition:** Structurally covered.

### 2. `0416c419` — Faster blackhole filtering for discovered interfaces on mobile / over RPC

**Upstream change:** Discovery cleanup snapshots the blackhole identity map for
60 seconds rather than performing two RPC-backed blackhole checks for every
discovered interface.

**Rust applicability:** Rust discovery cleanup runs in the driver process and
checks the in-memory transport engine directly. It does not make an RPC call per
identity. Remote consumers can request the active blackhole set in one
`GetBlackholed` query.

**Local handling and evidence:** `Driver::tick()` supplies an in-process
`engine.is_blackholed()` closure to `cleanup_with_blackholes()`. The regression
`cleanup_removes_discoveries_for_blackholed_network_and_transport_identities`
covers both identity fields. No equivalent cache is needed because the costly
cross-process access pattern is absent.

**Final disposition:** Structurally covered.

### 3. `e3f1a5e7` — Updated version

**Upstream change:** Advances upstream package metadata to version `1.4.2`.

**Rust applicability:** This identifies the normative compatibility target; it
does not independently change protocol or runtime behavior.

**Local handling and evidence:** The exact target commit, trees, range, and
version assertion are recorded above. Rust crate versions follow the native
project's release process and are not expected to mirror the Python package
version.

Tracking metadata and the exact CI interop pin now identify 1.4.2 without
changing independently versioned Rust crates.

**Final disposition:** Non-runtime.

### 4. `64fee86e` — Cleanup

**Upstream change:** Most edits are formatting or module export cleanup. Runtime
changes copy the listener's default command before per-session modification,
raise the initiator's default file-log threshold from ERROR to INFO, and add
more informative path, link, peer-version, and session lifecycle messages.

**Rust applicability:** `ListenerSession::start_command()` already clones its
`Vec<String>` default command, so sessions cannot mutate shared command state.
The initiator logging changes apply directly.

**Local handling and evidence:** The command clone is directly visible in
`rns-cli/src/rnsh.rs`. Initiator logging now defaults to INFO and records path
requests, link establishment, connected server version and session completion.
`rnsh_logging_uses_file_oriented_levels` pins the new default and verbosity
behavior. Python module export generation is not applicable to Rust.

**Final disposition:** Integrated.

### 5. `529a9fd4` — Cleaned up dead imports. Improved logging.

**Upstream change:** Removes dead Python code, fixes an error-message call to
`os.getlogin()`, adds authentication and remote-execution logging, and—most
importantly—returns immediately after reporting remote identification in an
invalid protocol state.

**Rust applicability:** The Rust listener already blocks command startup unless
the session is authenticated and in `WaitCommand`, and its shell fallback does
not use `os.getlogin`. The remote-identification state guard and lifecycle
logging map directly to the Rust listener.

**Local handling and evidence:** `remote_identified()` now accepts callbacks
only during `WaitIdent` and `WaitVersion`; later callbacks produce a fatal
protocol error, tear down the link and return before authentication mutation.
`listener_rejects_reidentification_after_version_handshake` and
`listener_rejects_reidentification_while_command_is_running` cover both invalid
phases. Identity authentication/denial and remote execution now emit lifecycle
logs. Existing denied-pipeline and command-state tests continue to pass. Dead
Python imports/comments require no Rust action.

**Final disposition:** Integrated.

### 6. `b48b96e6` — Prepare release

**Upstream change:** Adds the 1.4.2 changelog entry and refreshes generated
documentation/release artifacts.

**Rust applicability:** No additional runtime behavior is introduced beyond the
preceding commits.

**Local handling and evidence:** This audit and the final parity record retain
the release provenance. Generated HTML and changelog artifacts are not vendored.

**Final disposition:** Non-runtime.

## Completed Integration

The offline recursive-path-request invariant, rnsh logging alignment and
listener protocol-state guard are implemented with focused regressions. The
historical fixture set remains pinned to its original 1.4.0 provenance; exact
1.4.2 compatibility is exercised by the live interop lane.

## Promotion Gates

- [x] Every upstream commit has a final disposition.
- [x] Focused regressions pass for every applicable behavior change.
- [x] Fixture provenance and byte stability are checked where applicable.
- [x] Exact-target live Python/Rust interop passes.
- [x] Workspace tests, feature suites, formatting, and lint pass.
- [x] Required build, Docker, hardware, and manual gates are recorded honestly.
- [x] Native documentation is updated for user-visible behavior.
- [x] A final parity record is created from `PARITY-TEMPLATE.md`.

## Acceptance Record

- `2026-07-28`: The focused recursive path-request regression and all 26 rnsh
  unit tests passed, including the new `WaitCommand` and `Running`
  re-identification failures and updated initiator log-level expectations.
- `2026-07-28`: Exact-target live Python/Rust bidirectional TCP interop passed
  against `b48b96e61676504e0a4e527b33b9a0b4495c6872`, after asserting version
  1.4.2 and `RNS` tree `3286dd665827d2e591b47efaa5706b643e9b8d5a`.
- `2026-07-28`: `cargo test --workspace`, the workspace native-hooks suite,
  WASM/built-in hook tests, and the rns-ctl TLS suite passed. `cargo fmt
  --check` and `scripts/lint-host.sh` passed; lint retained only the accepted
  repository warning baseline.
- `2026-07-28`: Historical 1.4.0 fixture tests passed without regeneration.
  Docker E2E, cross-compilation and physical Weave HIL were not rerun and are
  not claimed; the release native-hooks build and live dual-VPS smoke passed.
- `2026-07-28`: Daily drift recheck fetched both upstream remotes; GitHub and
  rgit still agree on `b48b96e61676504e0a4e527b33b9a0b4495c6872`, six commits
  after the accepted 1.4.1 baseline, and the baseline remains an ancestor of
  both tips.
- `2026-07-28`: `cargo build --release --bin rns-server
  --features rns-hooks-native` passed, and `scripts/manual-backbone-smoke.sh`
  passed startup, interface-up checks, cross-identity recall, bidirectional
  packets, and bidirectional link/channel checks through the live dual-VPS
  fabric.
- `2026-07-27`: Both upstream remotes were fetched and agreed on annotated tag
  `1.4.2` at `b48b96e61676504e0a4e527b33b9a0b4495c6872`, six commits after the
  accepted 1.4.1 baseline. The baseline is an ancestor of both remote tips.
- `2026-07-27`: `cargo build --release --bin rns-server
  --features rns-hooks-native` passed on local `dev`.
- `2026-07-27`: `scripts/manual-backbone-smoke.sh` passed two-node startup,
  interface-up checks, cross-identity recall, bidirectional packets, and
  bidirectional link/channel checks.
- `2026-07-27`: The existing discovery blackhole cleanup regression and four
  relevant rnsh authentication, command-state, and log-threshold regressions
  passed. These confirm the current baseline but do not replace the new focused
  regressions required by the integration plan.
- `2026-07-27`: Exact-target Python/Rust interop, full workspace/feature suites,
  formatting, lint, Docker, and hardware validation were not run and are not
  claimed by this initial drift audit.
