# Unified Control Plane Proposal

## Summary

Yes, this project should grow a proper server and web UI, but it should not be built by collapsing `rnsd`, `rns-sentineld`, and `rns-statsd` into one monolith.

The codebase already has the right nucleus for this:

- `rnsd` is the data plane and owns the network state.
- `rns-sentineld` is a policy/enforcement sidecar driven by hook/provider-bridge events.
- `rns-statsd` is a metrics/event ingestion sidecar with durable storage.
- `rns-ctl` already has an HTTP/WebSocket server, runtime config commands, and daemon-facing APIs.

The pragmatic move is to turn `rns-ctl` into the **admin plane** for the whole node:

- one server process
- one auth model
- one API surface
- one web UI
- optional supervision of `rnsd`, `rns-sentineld`, and `rns-statsd`

## Why This Shape Fits The Current Repo

### What already exists

`rns-ctl` already provides:

- HTTP API and WebSocket transport
- live event bridging from `rns-net` callbacks
- runtime config inspection and mutation
- hook management
- path, link, interface, resource, and identity endpoints

Relevant code:

- `rns-ctl/src/cmd/http.rs`
- `rns-ctl/src/server.rs`
- `rns-ctl/src/api.rs`
- `rns-ctl/src/cmd/config.rs`
- `rns-ctl/src/bridge.rs`

`rns-sentineld` and `rns-statsd` are already structured as attachable services, not core node logic:

- both connect to `rnsd` over RPC
- both consume provider-bridge events
- both can be supervised externally

Relevant code:

- `rns-cli/src/sentineld.rs`
- `rns-cli/src/statsd.rs`

### What is missing

What does **not** exist yet is:

- a first-class process model for the three services as one managed node
- a unified configuration model across static config and runtime knobs
- an API for sentinel state and statsd historical queries
- a UI-serving layer
- a proper time-series/aggregation query surface for dashboards

## Recommended Architecture

### 1. Keep the current process split

Do not merge the three services into one runtime.

Reasons:

- `rnsd` remains latency-sensitive and should stay narrowly focused on transport/data-plane work.
- `rns-statsd` does durable writes and aggregation; that is a different failure and performance profile.
- `rns-sentineld` is policy logic that should be restartable without destabilising the node.
- this matches the current hook/provider-bridge model instead of fighting it.

### 2. Make `rns-ctl` the node server

`rns-ctl` should become the single admin server for a node, with two operating modes:

- `attach` mode: connect to an already running `rnsd`, `rns-sentineld`, and `rns-statsd`
- `managed` mode: spawn and supervise those processes directly

That gives you:

- local CLI
- remote API
- browser UI
- service supervision

without forcing a rewrite of the daemon internals.

### 3. Introduce a node state model above daemon state

Right now the API is mostly `rnsd`-centric. Add a higher-level node model:

- `node.config.desired`
- `node.config.effective`
- `node.processes.rnsd`
- `node.processes.sentineld`
- `node.processes.statsd`
- `node.health`
- `node.metrics`
- `node.alerts`

This is the key conceptual shift: the UI should manage a **node appliance**, not three unrelated binaries.

### 4. Treat configuration as two layers

You mentioned both config-file editing and runtime knobs. Those need to stay separate.

Recommended split:

- **static config**: the persisted config file and sidecar config sections
- **runtime overrides**: values pushed into a live daemon over RPC

The UI should always show:

- persisted value
- live value
- source of truth (`default`, `file`, `runtime override`)
- whether restart is required

Without this separation, the UI will become confusing quickly.

## API Expansion Needed

### Process and health endpoints

Add endpoints in `rns-ctl` for:

- `GET /api/node`
- `GET /api/processes`
- `POST /api/processes/:name/start`
- `POST /api/processes/:name/stop`
- `POST /api/processes/:name/restart`
- `GET /api/processes/:name/logs`

These should expose:

- pid
- uptime
- running/stopped/failed state
- last exit status
- last heartbeat
- last error

### Unified config endpoints

Add:

- `GET /api/config/schema`
- `GET /api/config/effective`
- `GET /api/config/file`
- `PUT /api/config/file`
- `POST /api/config/runtime`
- `DELETE /api/config/runtime/:key`
- `POST /api/config/apply`

`/api/config/apply` should return a plan:

- applied live
- requires sidecar restart
- requires `rnsd` restart
- rejected with validation errors

### Sentinel endpoints

Right now sentinel behaviour is mostly implicit. Expose it directly:

- `GET /api/sentinel/policy`
- `PUT /api/sentinel/policy`
- `GET /api/sentinel/incidents`
- `GET /api/sentinel/blacklist`
- `POST /api/sentinel/blacklist`
- `DELETE /api/sentinel/blacklist/:peer`
- `GET /api/sentinel/events`

### Stats endpoints

`rns-statsd` currently writes SQLite and is useful, but it is not yet a dashboard API.

Add:

- `GET /api/stats/overview`
- `GET /api/stats/interfaces`
- `GET /api/stats/traffic`
- `GET /api/stats/announces`
- `GET /api/stats/process`
- `GET /api/stats/query?...`

The important part is server-side aggregation:

- time buckets
- group-by interface
- group-by direction
- group-by packet type
- percentile and rate calculations where useful

Do not make the browser compute everything from raw rows.

### WebSocket topics

Extend the current WS model beyond `rnsd` callback events:

- `node`
- `processes`
- `sentinel`
- `stats`
- `alerts`
- `logs`

The UI will need both:

- event streams for live updates
- snapshot endpoints for initial page load

## UI Shape

The first UI should be an operator console, not a generic website.

Suggested sections:

- Overview: process health, transport health, recent alerts, traffic summary
- Interfaces: status, throughput, packet counts, announce rates, errors
- Paths and Links: path table, link state, RTT, direct-link state
- Sentinel: blacklist, penalties, recent incidents, policy knobs
- Metrics: charts from statsd/SQLite
- Config: file-backed config plus runtime overrides
- Hooks: loaded hooks, priorities, enable/disable, reload
- Logs: recent per-process logs

## Phased Delivery

### Phase 1: make `rns-ctl` the control plane

Scope:

- add service/process registry to `rns-ctl`
- support attach mode for existing daemons
- add process health endpoints
- add sentinel and stats read APIs
- keep UI out for now

This should ship first.

### Phase 2: add managed mode

Scope:

- `rns-ctl server` or equivalent subcommand that supervises child processes
- restart policies
- pid/log management
- health probes

At this point the project starts to feel like a real node appliance.

### Phase 3: add the web UI

Scope:

- static asset serving from `rns-ctl`
- token auth reuse
- dashboard pages backed by the new APIs
- live updates over WebSocket

### Phase 4: tighten config lifecycle

Scope:

- config schema metadata
- validation errors with field paths
- restart impact preview
- save/apply/rollback semantics

## Recommended First Implementation Slice

The smallest high-value slice is:

1. extend `rns-ctl` with a `NodeSupervisor` abstraction
2. add read-only endpoints for sidecar status and statsd summaries
3. add a single `/api/node` overview endpoint
4. add a very small built-in UI page that only shows health and links to JSON endpoints

That gets you:

- a coherent server story
- a stable API contract
- a place for the UI to land

without prematurely committing to a large frontend or invasive daemon rewrite.

## What I Would Avoid

- Do not move stats storage into `rnsd`.
- Do not make the browser edit the config file directly.
- Do not blur static config and runtime overrides into one mutable blob.
- Do not start with a large SPA before the admin API and state model are stable.
- Do not make `rns-ctl` depend on internal implementation details of sidecars that are not exposed as explicit APIs.

## Concrete Next Step

If we proceed, the next engineering task should be:

> add a node-supervision and sidecar-observability layer to `rns-ctl`, then expose it through `/api/node`, `/api/processes`, `/api/sentinel/*`, and `/api/stats/*`.

That is the right foundation for the web UI you want.
