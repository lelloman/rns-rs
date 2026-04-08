# Graceful Shutdown Plan

This document tracks the current graceful-shutdown implementation status for
`rns-server` / `rnsd`.

The target remains a bounded, observable shutdown flow, not live blue/green
handoff or session migration.

## Scope

The feature is intended to:

- stop admitting new work when drain begins
- stop accepting new inbound connections
- expose drain state through RPC and the control plane
- let `rns-server` use drain before stop/restart
- give sidecars a chance to acknowledge drain and flush useful work
- force-close long-lived state at deadline

The feature is not intended to:

- preserve live Reticulum sessions across process replacement
- buffer arbitrary transport traffic in a generic front proxy
- transfer live node state between generations

## Current Status

### Implemented

- Explicit lifecycle state in `rns-net`:
  - `Active`
  - `Draining`
  - `Stopping`
  - `Stopped`
- Drain control/query surface:
  - `BeginDrain`
  - `QueryRequest::DrainStatus`
  - `RnsNode::begin_drain()`
  - `RnsNode::drain_status()`
  - RPC `begin_drain` / `drain_status`
- Driver-side rejection/ignoring of new work during drain for:
  - outbound sends
  - link creation
  - path requests
  - direct-connect proposals
  - channel sends
  - link requests / identify / resource send / resource accept / generic link payload
- Listener stop path during drain for:
  - TCP server listener
  - local listeners
  - provider-bridge accept side
- Tests proving listener accepts stop during drain
- `rns-server` supervisor drain orchestration:
  - requests `rnsd` drain before stop/restart
  - waits until drain completes or deadline expires
  - falls back to terminate when needed
- Sidecar shutdown ordering:
  - `rns-statsd`
  - `rns-sentineld`
  - `rnsd`
- Sidecar drain acknowledgements through ready files
- Drain status now reports:
  - active links
  - resource transfers
  - hole-punch sessions
  - interface writer queued frames
  - provider backlog events
  - provider consumer queued events
- Deadline teardown now actively aborts:
  - remaining links
  - resource transfers
  - hole-punch sessions
- Supervisor/control-plane visibility:
  - mirrors `rnsd` drain progress into process state
  - logs drain progress updates while waiting
  - exposes cumulative `drain_ack_count` and `forced_kill_count` per process
- `rns-ctl` HTTP control plane rejects new mutating work with `409 Conflict`
  while the node is draining
- `RnsNode` public API now preflights drain state and returns errors for new
  work instead of silently succeeding while the driver drops it

### Partially Implemented

- Sidecar drain behavior is observable through ready-file acknowledgements, but
  it still does not expose richer flush counts or queue-depth metrics

### Still Missing

- A final audit of any remaining public entrypoints that should reject new work
  during drain but may still rely only on lower-level behavior

## Phase Status

### Phase 1: Drain State Skeleton

Status: implemented

Delivered:

- lifecycle model
- drain metadata
- drain query surface
- RPC support
- control-plane visibility

Key commits:

- `f46a7d3` Add drain state skeleton for graceful shutdown

### Phase 2: Reject New Mutating Work During Drain

Status: largely implemented

Delivered:

- driver-side rejection/ignore for main mutating events
- explicit error path for `SendChannelMessage`
- explicit `RnsNode` API rejection for common public mutating calls
- `rns-ctl` HTTP rejection for mutating endpoints

Key commits:

- `11db1e9` Block selected new work while draining
- `aa60bb9` Reject link creation while draining
- `063b86c` Return create_link error while draining
- `038d6b0` Reject new ctl work while draining
- `4f08faa` Reject node API work while draining

Remaining:

- audit for any lower-frequency mutating paths that should be rejected earlier

### Phase 3: Listener Stop Handles

Status: implemented

Delivered:

- listener controls registered in node startup
- TCP/local/provider accept loops stop on drain
- focused tests proving no new accepts

Key commits:

- `6cb732b` Stop listener accepts during drain
- `57ab769` Test listener stop behavior during drain

### Phase 4: Queue Drain Accounting

Status: implemented for currently tracked queued work

Delivered:

- drain status accounts for links/resources/hole-punch sessions
- drain status accounts for interface writer queue depth
- drain status accounts for provider-bridge backlog and consumer queue depth
- `drain_complete` now waits for those queue counters to hit zero

Remaining:

- audit whether any other short-lived queues should also contribute to drain
  completion

Key commits:

- `70d6876` Report active links in drain status
- `04f7059` Report resource transfers in drain status
- `b139677` Track queued work in drain status

### Phase 5: Supervisor Uses Drain Before Stop

Status: implemented

Delivered:

- supervisor requests drain before `rnsd` stop/restart
- drain polling before termination
- progress reflection into process state
- progress logging while waiting

Key commits:

- `da74374` Drain rnsd before supervisor stop and restart
- `f7c78b7` Reflect rnsd drain progress in supervisor state
- `f1cc67f` Log rnsd drain progress during supervisor waits
- `403ecb8` Add drain status test coverage

### Phase 6: `rns-statsd` Flush-On-Drain

Status: mostly implemented

Delivered:

- sidecar draining acknowledgment through ready files
- shutdown ordering stops stats sidecar before `rnsd`
- stats sidecar enters draining before final shutdown work

Remaining:

- if needed, richer explicit accounting of exactly what was flushed

Key commits:

- `f9a0027` Stop sidecars before rnsd during shutdown
- `455b24c` Acknowledge sidecar drain through ready files

### Phase 7: `rns-sentineld` Quiet-On-Drain

Status: mostly implemented

Delivered:

- sidecar draining acknowledgment through ready files
- shutdown ordering stops sentinel before `rnsd`
- sentinel enters draining before final shutdown work

Remaining:

- if needed, richer metrics around queued enforcement work at stop time

Key commits:

- `f9a0027` Stop sidecars before rnsd during shutdown
- `455b24c` Acknowledge sidecar drain through ready files

### Phase 8: Force-Close Long-Lived Work At Deadline

Status: implemented for core runtime state

Delivered:

- deadline expiry advances node to `Stopping`
- remaining links are torn down
- resource transfers are cancelled
- hole-punch sessions are aborted
- supervisor stop reporting distinguishes drain acknowledgment from forced kill
- process state/API expose cumulative drain-acknowledgement and forced-kill
  counters

Key commits:

- `8c35ed7` Clarify supervisor stop outcomes during drain
- `43450a7` Tear down links when drain deadline expires
- `e78e832` Abort hole-punch sessions during drain shutdown
- `68356b8` Cancel resource transfers before link teardown

Remaining:

- add richer detail on what specific work remained active at deadline, if
  operators need more than the current counters

### Phase 9: End-To-End Tests

Status: substantially implemented for current stop/restart goals

Delivered:

- focused unit tests in `rns-net`
- focused supervisor tests in `rns-server`
- live RPC-based supervisor tests for:
  - drain request emission
  - drain completion path
  - drain timeout path
- `rns-ctl` integration coverage for drain visibility and mutating-request
  rejection during drain
- Docker `rns-server` end-to-end coverage for:
  - sidecar restart
  - `rnsd` restart through the supervisor
  - `rnsd` draining event visibility during restart
  - recovery of all three managed processes to `running` and `ready`

Remaining:

- optional additional Docker/e2e coverage for explicit `rnsd` stop/start
  separate from restart
- optional multi-node scenarios that verify traffic recovery across a drained
  `rnsd` restart, not just supervised process recovery
- optional tests around sidecar flush/ack behavior under real supervisor control

Key commits:

- `57ab769` Test listener stop behavior during drain
- `403ecb8` Add drain status test coverage
- `038d6b0` Reject new ctl work while draining
- `101653d` Expand graceful shutdown supervisor coverage
- `34c50f5` Add rnsd restart e2e coverage for graceful drain

## Recommended Next Steps

The next highest-value work is:

1. Perform a final API/control-surface audit for any remaining drain admission gaps.
2. Decide whether operators need richer sidecar flush metrics in addition to the
   current drain-acknowledgement and forced-kill counters.
3. Decide whether to add optional Docker/e2e coverage for explicit `rnsd`
   stop/start and multi-node traffic recovery through restart.

## Working Notes

For short-term handoff details and the next suggested coding step, see:

- `docs/graceful-shutdown-next-step.md`
