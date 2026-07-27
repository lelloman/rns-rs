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
- local branch and revision inspected: `dev@7e6242f78220c284ee94a92f4e3f4665c4982ef3`

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

| # | Upstream commit | Subject | Current disposition | Local evidence |
|---:|---|---|---|---|
| 1 | `4760103aa660f3fdd628a8124875dda672a71ac9` | Ensure interface is online at time of recursive PR emission | Structurally covered | `rns-net/src/driver/dispatch.rs` rejects every `SendOnInterface` action when the interface is offline or disabled before invoking its writer |
| 2 | `0416c419561f79d6cf6fd56af0bfd9eee9a7276a` | Faster blackhole filtering for discovered interfaces on mobile / over RPC | Structurally covered | Discovery cleanup and blackhole lookup execute inside one Rust driver process; RPC exposes the full blackhole set with one `GetBlackholed` query; cleanup behavior has a focused blackhole regression |
| 3 | `e3f1a5e7cdd6f0bf3c0c0a05b055c3f196b1fd15` | Updated version | Non-runtime | Upstream package version metadata only; target version is recorded by this audit |
| 4 | `64fee86ebc452d2eae716e4bb894df22b1c8f91d` | Cleanup | Needs port | Default-command copying is structurally covered, but initiator INFO-level lifecycle logging and its default log threshold differ locally |
| 5 | `529a9fd460d8ff33a4506db79e641314744ab135` | Cleaned up dead imports. Improved logging. | Needs coordinated port | Rust rejects unauthenticated command execution, but listener re-identification in an invalid state is not protocol-errored and returned from; authentication/execution lifecycle logs also differ |
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
guard. Driver tests already exercise online/offline dispatch behavior; a
focused recursive-path-request regression should still be added before final
acceptance to lock this architectural invariant to the upstream failure mode.

**Current disposition:** Structurally covered.

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

**Current disposition:** Structurally covered.

### 3. `e3f1a5e7` — Updated version

**Upstream change:** Advances upstream package metadata to version `1.4.2`.

**Rust applicability:** This identifies the normative compatibility target; it
does not independently change protocol or runtime behavior.

**Local handling and evidence:** The exact target commit, trees, range, and
version assertion are recorded above. Rust crate versions follow the native
project's release process and are not expected to mirror the Python package
version.

**Current disposition:** Non-runtime.

### 4. `64fee86e` — Cleanup

**Upstream change:** Most edits are formatting or module export cleanup. Runtime
changes copy the listener's default command before per-session modification,
raise the initiator's default file-log threshold from ERROR to INFO, and add
more informative path, link, peer-version, and session lifecycle messages.

**Rust applicability:** `ListenerSession::start_command()` already clones its
`Vec<String>` default command, so sessions cannot mutate shared command state.
The Rust initiator still defaults to ERROR logging and does not emit equivalent
INFO lifecycle records.

**Local handling and evidence:** The command clone is directly visible in
`rns-cli/src/rnsh.rs`, and rnsh tests cover the current listener/initiator log
thresholds. The user-visible logging changes need a focused port and updated
tests; Python module export generation is not applicable to Rust.

**Current disposition:** Needs port.

### 5. `529a9fd4` — Cleaned up dead imports. Improved logging.

**Upstream change:** Removes dead Python code, fixes an error-message call to
`os.getlogin()`, adds authentication and remote-execution logging, and—most
importantly—returns immediately after reporting remote identification in an
invalid protocol state.

**Rust applicability:** The Rust listener already blocks command startup unless
the session is authenticated and in `WaitCommand`, and its shell fallback does
not use `os.getlogin`. However, `remote_identified()` accepts callbacks in any
non-closed state: it only changes state when currently in `WaitIdent`, but does
not report a protocol error and return for other states. Relevant lifecycle
logging is also absent.

**Local handling and evidence:** Existing tests cover denied pipelined traffic,
authentication, and command-state enforcement. A coordinated change should add
the invalid re-identification guard and regression first, then align the useful
authentication/execution logs without weakening the existing state checks.
Dead Python imports/comments require no Rust action.

**Current disposition:** Needs coordinated port.

### 6. `b48b96e6` — Prepare release

**Upstream change:** Adds the 1.4.2 changelog entry and refreshes generated
documentation/release artifacts.

**Rust applicability:** No additional runtime behavior is introduced beyond the
preceding commits.

**Local handling and evidence:** This audit records the release provenance and
tracks native documentation as part of the eventual implementation work.

**Current disposition:** Non-runtime.

## Integration Plan

1. Add a focused offline recursive-path-request regression proving the driver
   never reaches an interface writer, then retain the structural disposition.
2. Port the rnsh initiator's INFO default and useful path, link, peer-version,
   and session-end log messages; update logging tests.
3. Make listener re-identification outside the permitted handshake states a
   fatal protocol error with an immediate return, and add a regression covering
   callbacks during `WaitCommand` and `Running`.
4. Add authentication outcome and remote-command lifecycle logs while ensuring
   secrets and command handling remain appropriate for native logging.
5. Run focused suites, the full workspace gates, and exact 1.4.2 Python/Rust
   interoperability before promoting this audit into a parity record.

## Promotion Gates

- [x] Every upstream commit has a current disposition.
- [ ] Focused regressions pass for every applicable behavior change.
- [ ] Fixture provenance and byte stability are checked where applicable.
- [ ] Exact-target live Python/Rust interop passes.
- [ ] Workspace tests, feature suites, formatting, and lint pass.
- [x] Required build, Docker, hardware, and manual gates are recorded honestly.
- [ ] Native documentation is updated for user-visible behavior.
- [ ] A final parity record is created from `PARITY-TEMPLATE.md`.

## Acceptance Record

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
