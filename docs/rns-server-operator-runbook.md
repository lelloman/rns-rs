# rns-server Operator Runbook

## Scope

`rns-server` is the default single-node product entrypoint for a supervised RNS
node. It owns:

- process lifecycle for `rnsd`
- hook sidecar lifecycle for `rns-sentineld` and `rns-statsd`
- persisted `rns-server.json` config
- the embedded `rns-ctl` HTTP API and built-in UI
- process readiness, recent lifecycle events, and durable process logs

Deployment uses one binary. At runtime, hook-enabled `rns-server` builds self-spawn `rnsd`, `rns-sentineld`, and `rns-statsd` from the same executable via `/proc/self/exe`, with `current_exe()` fallback. The packaged build uses native hooks and native sidecars.

## Build And Package

For a local release-style bundle:

```bash
bash scripts/package-rns-server-tarball.sh
```

That script builds the single deployable `rns-server` binary and writes a tarball under `dist/`.

For a direct local build without packaging:

```bash
cargo build --release --bin rns-server
```

If you want native dynamic-library hooks enabled in the node runtime:

```bash
cargo build --release --bin rns-server --features rns-hooks-native
```

`rns-hooks` is a compatibility alias for the native backend:

```bash
cargo build --release --bin rns-server --features rns-hooks
```

If you need the WASM hook backend:

```bash
rustup target add wasm32-unknown-unknown
cargo build --release --bin rns-server --features rns-hooks-wasm
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

Development startup from the workspace:

```bash
cargo run --bin rns-server -- start --config /path/to/node --http-host 127.0.0.1 --http-port 8080
```

Release-style startup from a local build:

```bash
cargo build --release --bin rns-server
./target/release/rns-server start --config /path/to/node --http-host 127.0.0.1 --http-port 8080
```

If you want native dynamic-library hooks enabled:

```bash
cargo build --release --bin rns-server --features rns-hooks-native
./target/release/rns-server start --config /path/to/node --http-host 127.0.0.1 --http-port 8080
```

If you use the packaged tarball, the runtime entrypoint is still just:

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

## VPS Experiment Targets

The VPS experiment now uses two operator targets:

| Target | SSH alias | Role |
| --- | --- | --- |
| `vps-eu` | `vps-eu` | Existing European VPS, formerly documented and scripted as `vps` |
| `vps-us` | `vps-us` | New US VPS for the doubled experiment |

Keep both machines configured with the same runtime layout unless a test case
explicitly calls out a regional difference:

- config root: `/var/lib/rns-node`
- embedded control plane: `127.0.0.1:18080`
- public Reticulum listener: configured by the node `config`
- installed binary: `/usr/local/bin/rns-server`

Recommended local SSH config:

```sshconfig
Host vps-eu
  HostName <eu-address>
  User root

Host vps-us
  HostName <us-address>
  User root
```

When an operation needs to run against both machines, loop over the target names
and keep the output labelled:

```bash
for host in vps-eu vps-us; do
  echo "== $host =="
  ssh "root@$host" 'systemctl status rns-server --no-pager'
  ssh "root@$host" '/usr/local/bin/rns-server --version; /usr/local/bin/rns-ctl --version'
done
```

### VPS Binary Deployment

Build clean release binaries from the commit you want to deploy:

```bash
cargo build --release -p rns-server -p rns-ctl --features rns-hooks-native
target/release/rns-server --version
target/release/rns-ctl --version
```

Install the binaries on both VPS experiment nodes and restart the service:

```bash
for host in vps-eu vps-us; do
  echo "== $host =="
  scp target/release/rns-server target/release/rns-ctl "root@$host:/tmp/"
  ssh "root@$host" 'install -m 0755 /tmp/rns-server /usr/local/bin/rns-server'
  ssh "root@$host" 'install -m 0755 /tmp/rns-ctl /usr/local/bin/rns-ctl'
  ssh "root@$host" 'systemctl restart rns-server'
  ssh "root@$host" '/usr/local/bin/rns-server --version; /usr/local/bin/rns-ctl --version; systemctl is-active rns-server'
done
```

After deploying, run the manual backbone smoke test below.

### Manual Backbone Smoke Test

After deploying routing, path discovery or backbone config changes, run the live
manual smoke test from a workstation:

```bash
cargo build --release --bin rns-server --features rns-hooks-native
scripts/manual-backbone-smoke.sh
```

The script starts two disposable local `rns-server` nodes, connects one only to
`vps-eu` and the other only to `vps-us`, then verifies announce propagation,
identity recall, bidirectional packets, link establishment and channel messages
through the live backbone fabric. See
[docs/manual-backbone-smoke.md](manual-backbone-smoke.md) for options and
failure interpretation.

Daily VPS checks include both per-host stats snapshots and the live manual
backbone smoke test. The shared daily report database lives on `vps-eu` at
`/var/lib/rns-node/vps_daily_reports.db`, with a working copy at
`data/vps_daily_reports.db` on whichever workstation is running the report.
Pull the shared database first, check whether upstream Reticulum moved, collect
both host snapshots locally, run the smoke test from the same workstation, then
push the updated database back to `vps-eu` so the next workstation starts from
the latest history.

Run each per-host snapshot command to completion before starting another
snapshot for the same host or the same local report database. The collector
performs several remote SSH queries, including reads from the live
`/var/lib/rns-node/stats.db`, and some of those remote queries can wait for up
to 180 seconds before returning their fallback values. Starting a second
collector while the first is still running can create duplicate rows for the
same host and date. If a collector appears stuck, first check for an existing
process with:

```bash
pgrep -af vps_daily_report.py
pgrep -af "ssh root@vps-"
```

Wait for any existing collector to finish unless it is clearly wedged. If the
operator intentionally stops a collector, inspect the local database before
continuing and keep only the newest complete row per host in report summaries.

The upstream Reticulum checkout location is workstation-local. Store it in the
gitignored file `.local/reticulum-upstream.path`; the first non-empty,
non-comment line must be the absolute path to the local upstream Reticulum
repository. For this workstation that file should contain:

```text
/home/lelloman/Reticulum
```

The upstream check treats the pointed checkout's current `HEAD` as the
Reticulum baseline reviewed or integrated into `rns-rs`. Fetch both the GitHub
remote and the Reticulum `rns-git` remote, then list commits present on either
remote that are not in that local baseline. If either log prints commits, include
that in the daily report as upstream Reticulum work not integrated yet:

Refresh the local refs first when an internet connection is available; the
version check compares the remote binaries against the local `origin/master` and
`origin/dev` refs by default. Build the local smoke-test binary before running
the live fabric check:

```bash
git fetch origin
RETICULUM_UPSTREAM_DIR="$(sed -n '/^[[:space:]]*#/d; /^[[:space:]]*$/d; p; q' .local/reticulum-upstream.path)"
test -n "$RETICULUM_UPSTREAM_DIR"
test -d "$RETICULUM_UPSTREAM_DIR/.git"
RETICULUM_GITHUB_REMOTE="${RETICULUM_GITHUB_REMOTE:-origin}"
RETICULUM_RGIT_REMOTE="${RETICULUM_RGIT_REMOTE:-rgit}"
git -C "$RETICULUM_UPSTREAM_DIR" fetch "$RETICULUM_GITHUB_REMOTE"
git -C "$RETICULUM_UPSTREAM_DIR" fetch "$RETICULUM_RGIT_REMOTE"
git -C "$RETICULUM_UPSTREAM_DIR" log --oneline "HEAD..$RETICULUM_GITHUB_REMOTE/master"
git -C "$RETICULUM_UPSTREAM_DIR" log --oneline "HEAD..$RETICULUM_RGIT_REMOTE/master"
cargo build --release --bin rns-server --features rns-hooks-native

mkdir -p data
if ssh root@vps-eu 'test -f /var/lib/rns-node/vps_daily_reports.db'; then
  scp root@vps-eu:/var/lib/rns-node/vps_daily_reports.db data/vps_daily_reports.db
fi

python3 scripts/vps_daily_report.py --host vps-eu --ssh-target root@vps-eu --stdout-summary
python3 scripts/vps_daily_report.py --host vps-us --ssh-target root@vps-us --stdout-summary

sqlite3 -header -column data/vps_daily_reports.db "
WITH latest AS (
  SELECT *,
         ROW_NUMBER() OVER (PARTITION BY host ORDER BY capture_ts_utc DESC) AS rn
  FROM daily_checks
  WHERE report_date = date('now') AND host IN ('vps-eu', 'vps-us')
)
SELECT host,
       capture_ts_utc,
       health_state,
       announce_24h,
       idle_timeout_events_24h
FROM latest
WHERE rn = 1
ORDER BY host;
"

scripts/manual-backbone-smoke.sh

scp data/vps_daily_reports.db root@vps-eu:/var/lib/rns-node/vps_daily_reports.db
```

Treat the daily VPS check as incomplete if the smoke test fails, even when both
SQLite snapshots were collected successfully. On smoke failure, rerun with
`scripts/manual-backbone-smoke.sh --keep` to preserve the disposable local node
configs and logs for debugging.

Treat a snapshot field value of `-1` as "remote query failed or timed out", not
as a valid zero count. In particular, `announce_24h = -1` means the collector
could not read the host's live `stats.db` announce counters within the remote
timeout, so the daily report should call out that the host stats snapshot is
incomplete even if the row was inserted. Do not push the shared DB until both
host snapshots have been reviewed, the smoke test has passed, and any duplicate
same-day rows are understood.

The snapshot records `/usr/local/bin/rns-server --version` and
`/usr/local/bin/rns-ctl --version`, then reconstructs the expected binary
versions for the configured refs using each package's `major.minor`, the git
commit count, and the short commit hash. Use `--master-ref` and `--dev-ref` if
the local baseline refs differ from `origin/master` and `origin/dev`.

For a quick drift check after collecting both hosts:

```bash
sqlite3 -header -column data/vps_daily_reports.db "
WITH latest AS (
  SELECT *,
         ROW_NUMBER() OVER (PARTITION BY host ORDER BY capture_ts_utc DESC) AS rn
  FROM daily_checks
  WHERE report_date = date('now') AND host IN ('vps-eu', 'vps-us')
)
SELECT host,
       rns_server_version,
       rns_server_master_version,
       rns_server_matches_master AS server_master,
       rns_server_dev_version,
       rns_server_matches_dev AS server_dev,
       rns_ctl_version,
       rns_ctl_master_version,
       rns_ctl_matches_master AS ctl_master,
       rns_ctl_dev_version,
       rns_ctl_matches_dev AS ctl_dev
FROM latest
WHERE rn = 1
ORDER BY host;
"
```

The report database stores the stable host key in the `host` column, so use the
aliases above instead of raw IP addresses. This daily report database is
separate from each node's live `/var/lib/rns-node/stats.db`, which is read by
the report script but is not copied between hosts.

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

By default, child processes are started by re-executing the running `rns-server` binary with hidden internal role flags. Hook-enabled builds manage:

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
