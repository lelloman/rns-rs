# Graceful Shutdown Plan

This document turns the graceful-shutdown discussion for `rns-server` / `rnsd` into a phased implementation plan that can be delivered and tested in small portions.

The intent is not full live handoff or blue/green session migration. The target is a bounded, observable shutdown flow that:

- stops admitting new work immediately
- allows a short drain window for useful queued work
- force-closes long-lived state after a deadline
- gives `rns-server` enough control to use this path during restart and stop operations

## Goals

- Add explicit runtime lifecycle states.
- Make shutdown behavior observable through the control plane.
- Stop new inbound accepts and new mutating operations during drain.
- Drain small queues for a few seconds at most.
- Flush sidecars cleanly where that adds value.
- Force termination of links/resources/sockets after the drain deadline.

## Non-Goals

- Transparent live migration of existing Reticulum sessions between processes.
- Generic front-proxy buffering of arbitrary transport traffic.
- Full blue/green takeover of live node state.

## Lifecycle Model

Add explicit node lifecycle states:

- `Active`
- `Draining`
- `Stopping`
- `Stopped`

Suggested semantics:

- `Active`: normal operation
- `Draining`: no new work admitted; existing short-lived work may complete
- `Stopping`: drain deadline expired or graceful stop completed; remaining state is being torn down
- `Stopped`: driver exited

## Work Classification

### Disallow Immediately

These should stop as soon as drain begins:

- new inbound TCP server accepts
- new local/shared-instance accepts
- new provider-bridge consumers
- new outbound interface reconnect/dial attempts
- `SendOutbound`
- `CreateLink`
- `SendRequest`
- `IdentifyOnLink`
- `SendResource`
- `AcceptResource { accept: true }`
- `SendChannelMessage`
- `SendOnLink`
- `RequestPath`
- `SendProbe`
- `ProposeDirectConnect`
- new sidecar-originated control actions from `rns-sentineld`
- new stats ingestion work in `rns-statsd`

### Drain Briefly

These are worth a short grace period:

- interface writer queues
- packets already accepted into the driver event queue
- provider-bridge consumer queues/backlog
- `rns-statsd` final SQLite flush
- small resource transfers that are nearly complete

### Interrupt At Deadline

These should be forcibly terminated if still active at the deadline:

- active Reticulum links
- large or stalled resource transfers
- pending request/response exchanges on links
- channel traffic still in flight
- hole-punch/direct-connect operations
- remaining connected TCP peers
- stalled interface writers
- lingering provider-bridge consumers

## PR Breakdown

## PR 1: Drain State Skeleton

### Scope

Add node lifecycle state, drain metadata, and a control/query surface for drain status.

### Tasks

- Add `LifecycleState` enum in `rns-net`.
- Add driver fields:
  - `lifecycle_state`
  - `drain_started_at`
  - `drain_deadline`
- Add new event:
  - `BeginDrain { timeout: Duration }`
- Add new query:
  - `QueryDrainStatus`
- Add a drain-status response struct with:
  - state
  - drain age
  - deadline remaining
  - `drain_complete` placeholder
  - detail/reason string
- Add `RnsNode::begin_drain(timeout)` wrapper.
- Expose drain status through `rns-ctl` API/state.
- Log lifecycle transitions.

### Acceptance Criteria

- Calling drain moves node from `Active` to `Draining`.
- Query/API reports `Draining`.
- Existing tests still pass.
- New unit tests cover state transitions.

### Files

- `rns-net/src/common/event.rs`
- `rns-net/src/driver.rs`
- `rns-net/src/node.rs`
- `rns-ctl/src/state.rs`
- `rns-ctl/src/api.rs`

## PR 2: Reject New Mutating Work During Drain

### Scope

Prevent new work from entering the node while draining.

### Tasks

- In the driver, reject or ignore during `Draining`:
  - `SendOutbound`
  - `CreateLink`
  - `SendRequest`
  - `IdentifyOnLink`
  - `SendResource`
  - `AcceptResource { accept: true }`
  - `SendChannelMessage`
  - `SendOnLink`
  - `RequestPath`
  - `ProposeDirectConnect`
- Return explicit errors where a response channel exists.
- Keep read-only queries working.
- Add logs for rejected work.

### Acceptance Criteria

- New link/resource/request operations fail with a `draining` error.
- Read-only queries still succeed.
- Existing active links are not yet torn down.
- New tests cover each gated operation family.

### Files

- `rns-net/src/common/event.rs`
- `rns-net/src/driver.rs`

## PR 3: Listener Stop Handles

### Scope

Make accept loops stoppable so no new inbound connections are admitted during drain.

### Tasks

- Add stop/drain handles for:
  - TCP server listener
  - local TCP listener
  - local Unix listener
  - provider bridge listener
- Replace plain `incoming()` loops with loops that can observe a stop flag or closed listener.
- Register those handles during node startup.
- On `BeginDrain`, stop listeners immediately.

### Acceptance Criteria

- New inbound connections are refused after drain begins.
- Existing connections remain alive during the grace window.
- No listener thread leaks.
- Tests verify no new accept after drain.

### Files

- `rns-net/src/interface/tcp_server.rs`
- `rns-net/src/interface/local.rs`
- `rns-net/src/provider_bridge.rs`
- `rns-net/src/node.rs`

## PR 4: Queue Drain Accounting

### Scope

Define what “drained” means for short-lived work.

### Tasks

- Add interface writer queue metrics:
  - queued frame count
  - worker alive state
- Include provider-bridge queue/backlog stats in drain status.
- Define `drain_complete` as something like:
  - listeners stopped
  - no pending writer queue entries
  - provider-bridge queues empty or below threshold
- Expose these counters through drain status.

### Acceptance Criteria

- Drain status flips to complete when short queues empty.
- Artificial queued writes clear before timeout.
- Tests verify drain-complete transitions.

### Files

- `rns-net/src/interface/mod.rs`
- `rns-net/src/provider_bridge.rs`
- `rns-net/src/driver.rs`

## PR 5: Supervisor Uses Drain Before Stop

### Scope

Make `rns-server` use drain before child termination.

### Tasks

- Add supervisor shutdown sequence:
  - request drain from `rnsd`
  - wait up to configured timeout
  - then terminate child
- Keep hard-kill fallback.
- Log:
  - drain requested
  - drain completed
  - drain timed out

### Acceptance Criteria

- Stop/restart path attempts graceful drain first.
- Timeout fallback still works.
- `rns-server` tests continue to pass.

### Files

- `rns-server/src/supervisor.rs`
- possibly `rns-server/src/control_plane.rs`

## PR 6: `rns-statsd` Flush-On-Drain

### Scope

Make the stats sidecar drain usefully.

### Tasks

- Add a drain signal/control path.
- Stop taking new provider events once drain begins.
- Force final SQLite flush.
- Report drained/ready-to-stop.

### Acceptance Criteria

- Pending stats are flushed on drain.
- Sidecar exits cleanly after flush.
- Tests verify buffered counters are not lost.

### Files

- `rns-cli/src/statsd.rs`

## PR 7: `rns-sentineld` Quiet-On-Drain

### Scope

Make sentinel stop creating new control work during drain.

### Tasks

- Add a drain signal/control path.
- Stop issuing new blacklist/control actions after drain starts.
- Allow already-read provider events to settle briefly.
- Disconnect and exit cleanly.

### Acceptance Criteria

- No new enforcement actions after drain begins.
- Sidecar exits cleanly.
- Tests verify quiet behavior.

### Files

- `rns-cli/src/sentineld.rs`

## PR 8: Force-Close Long-Lived Work At Deadline

### Scope

Ensure shutdown completes even with stubborn sessions.

### Tasks

- At drain deadline:
  - teardown active links
  - fail or abort in-flight resources
  - cancel hole-punch/direct-connect work
  - close remaining live sockets
- Reflect forced-shutdown counts in logs/status.

### Acceptance Criteria

- Shutdown completes within bounded time.
- Active links/resources are terminated deterministically.
- Tests cover deadline-expiry behavior.

### Files

- `rns-net/src/common/link_manager.rs`
- `rns-net/src/driver.rs`
- `rns-net/src/holepunch/*`

## PR 9: End-To-End Tests

### Scope

Verify the behavior under real process restarts and stop operations.

### Tasks

- Add integration/e2e tests for:
  - drain blocks new connections
  - existing sessions survive briefly
  - writer queues flush
  - stats flushes
  - supervisor restart path uses drain
  - deadline expiry works as intended

### Acceptance Criteria

- Repeatable passing tests locally and in CI.
- Failure modes are observable through logs/API.

### Files

- `rns-net` unit/integration tests
- `rns-server` tests
- `tests/docker/rns-server/*`

## Recommended Order

Implement in this order:

1. PR 1: Drain State Skeleton
2. PR 2: Reject New Mutating Work During Drain
3. PR 3: Listener Stop Handles
4. PR 4: Queue Drain Accounting
5. PR 5: Supervisor Uses Drain Before Stop
6. PR 6: `rns-statsd` Flush-On-Drain
7. PR 7: `rns-sentineld` Quiet-On-Drain
8. PR 8: Force-Close Long-Lived Work At Deadline
9. PR 9: End-To-End Tests

## Smallest Useful First PR

If the goal is to start with the lowest-risk slice, PR 1 is the best entry point.

It gives:

- an explicit lifecycle model
- a stable drain control surface
- observability through the control plane
- a foundation for later listener/queue/sidecar work

It does not yet stop listeners or drain queues, but it establishes the control model cleanly and keeps the next PRs small.
