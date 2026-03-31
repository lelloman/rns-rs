# rns-server Operator Runbook

## Scope

`rns-server` is the single-node product entrypoint for a supervised RNS node. It owns:

- process lifecycle for `rnsd`, `rns-sentineld`, and `rns-statsd`
- persisted `rns-server.json` config
- the embedded `rns-ctl` HTTP API and built-in UI
- process readiness, recent lifecycle events, and durable process logs

Deployment uses one binary. At runtime, `rns-server` self-spawns its child roles from the same executable via `/proc/self/exe`, with `current_exe()` fallback.

## Build And Package

For a local release-style bundle:

```bash
bash scripts/package-rns-server-tarball.sh
```

That script builds the single deployable `rns-server` binary and writes a tarball under `dist/`.

For a direct local build without packaging:

```bash
cargo build --release --bin rns-server --features rns-hooks
```

## Files And Paths

At runtime, `rns-server` resolves a config directory and uses it for:

- `config`
  The Reticulum runtime config consumed by `rnsd` and the sidecars.
- `rns-server.json`
  Product config managed through the API/UI.
- `logs/*.log`
  Durable stdout/stderr tails for supervised processes.
- `*.ready`
  Explicit readiness files written by sidecars.
- `stats.db`
  Default SQLite path for `rns-statsd` unless overridden.

## Startup

Example startup:

```bash
rns-server start --config /path/to/node --http-host 127.0.0.1 --http-port 8080
```

Useful flags:

- `--config PATH`
  Config directory containing `config` and `rns-server.json`.
- `--http-host HOST`
  Embedded control-plane bind host.
- `--http-port PORT`
  Embedded control-plane port.
- `--http-token TOKEN`
  Fixed bearer token for the control plane.
- `--disable-auth`
  Disable control-plane auth.
- `--no-http`
  Disable the embedded control plane.
- `--dry-run`
  Print the launch plan and exit.

## Control Plane

Key endpoints:

- `GET /health`
- `GET /api/node`
- `GET /api/config`
- `GET /api/config/schema`
- `GET /api/config/status`
- `GET /api/processes`
- `GET /api/process_events`
- `GET /api/processes/:name/logs`
- `POST /api/config/validate`
- `POST /api/config`
- `POST /api/config/apply`
- `POST /api/processes/:name/start`
- `POST /api/processes/:name/stop`
- `POST /api/processes/:name/restart`

The built-in UI is served from `/`.

## Self-Spawn Runtime

By default, child processes are started by re-executing the running `rns-server` binary with hidden internal role flags. The normal deploy path does not require separate installed copies of:

- `rnsd`
- `rns-sentineld`
- `rns-statsd`

Advanced override fields in `rns-server.json` can still point a role at an external binary, but that is not the default operating mode.

## Config Apply Semantics

`rns-server` classifies config changes into explicit actions:

- `none`
  Candidate matches the current effective config.
- `reload_control_plane`
  Embedded HTTP auth changes reload in place.
- `restart_children`
  One or more managed child processes must restart.
- `restart_children_and_reload_control_plane`
  Child restart plus embedded auth reload.
- `restart_server`
  Embedded HTTP bind or enablement changes still require restarting `rns-server`.
- `restart_children_and_server`
  Child restart plus full `rns-server` restart requirement.

Use `POST /api/config/validate` before save/apply to inspect the exact plan.

## Observability

Use the UI or API first. Shell access should not be required for routine diagnosis.

- `GET /api/processes`
  Current status, readiness, PID, restart count, last error, and durable log metadata.
- `GET /api/process_events`
  Recent lifecycle transitions.
- `GET /api/processes/:name/logs`
  Recent buffered lines plus durable log metadata.

Durable log files live under the resolved config dir:

- `logs/rnsd.log`
- `logs/rns-sentineld.log`
- `logs/rns-statsd.log`

## Troubleshooting

If the node is up but not converged:

1. Check `GET /api/config/status`.
2. Inspect `pending_action`, `pending_targets`, and `blocking_reason`.
3. Inspect `/api/processes` for `ready_state`, `status_detail`, and `last_error`.
4. Inspect `/api/process_events` and per-process logs.

Common cases:

- Sidecar stuck in `waiting`
  Check the corresponding `*.ready` file expectation and the process log for RPC/provider bridge wait messages.
- `control_plane_reload_required`
  Apply the saved config.
- `control_plane_restart_required`
  Restart `rns-server`.
- Child restart still pending
  Wait for the process to return to `ready` and recheck `/api/config/status`.

## Release Smoke Checklist

Before shipping a build:

1. `cargo test -p rns-server`
2. `cargo test -p rns-cli`
3. `cargo test -p rns-ctl config_`
4. `node --test rns-ctl/assets/app.smoke.test.js`
5. `bash tests/docker/rns-server/run.sh`
6. Build a tarball with `bash scripts/package-rns-server-tarball.sh`
