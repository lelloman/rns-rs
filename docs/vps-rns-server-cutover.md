# VPS `rns-server` Cutover Runbook

This runbook plans the production VPS switch from standalone systemd-managed:

- `rnsd`
- `rns-statsd`
- `rns-sentineld`

to the supervised single-binary deployment model based on `rns-server`.

It is a maintenance-window cutover plan with explicit rollback.

## 1. Target state

The desired VPS operating model is:

- one installed application binary:
  `/usr/local/bin/rns-server`
- one systemd service:
  `rns-server.service`
- one node config root, for example:
  `/var/lib/rns-node`

That config root should contain:

- `config`
  Reticulum runtime config used by the child roles
- `rns-server.json`
  product/runtime config for the supervisor and control plane
- `stats.db`
  SQLite database written by the stats sidecar role
- `logs/`
  durable child-process logs
- `*.ready`
  readiness markers written by managed child roles

The old long-lived systemd services should no longer remain enabled after the
cutover:

- `rnsd.service`
- `rns-statsd.service`
- `rns-sentineld.service`

## 2. Build and package

From the repo root:

```bash
bash scripts/package-rns-server-tarball.sh
```

That produces a single deployable tarball under `dist/`.

Local release smoke before touching the VPS:

```bash
cargo test -p rns-server
cargo test -p rns-cli
cargo test -p rns-ctl config_
node --test rns-ctl/assets/app.smoke.test.js
bash tests/docker/rns-server/run.sh
```

## 3. VPS prep before the maintenance window

Upload the packaged `rns-server` binary first without touching the live
services.

Prepare the node config root:

- choose the final config directory, recommended:
  `/var/lib/rns-node`
- copy the current Reticulum `config` into that directory
- create `rns-server.json` with the intended production control-plane settings
- ensure the stats DB path resolves inside the same node root

Before the cutover, validate the binary and config non-destructively:

```bash
ssh root@vps '/usr/local/bin/rns-server --version'
ssh root@vps '/usr/local/bin/rns-server start --config /var/lib/rns-node --dry-run'
```

Expected dry-run outcome:

- launch plan renders successfully
- child roles are planned from the single binary
- no missing config-path or readiness/log path errors appear

## 4. Production systemd unit

Install a single supervisor unit:

```ini
[Unit]
Description=RNS Server Supervisor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rns-server start --config /var/lib/rns-node --http-host 127.0.0.1 --http-port 8080
Restart=always
RestartSec=5
WorkingDirectory=/var/lib/rns-node
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Keep the old standalone units on disk until the cutover is declared successful.

## 5. Maintenance-window cutover

1. Capture a fresh pre-cutover health baseline:

```bash
python3 scripts/vps_daily_report.py --stdout-summary
```

2. Stop and disable the old services:

```bash
ssh root@vps '
  systemctl stop rns-sentineld rns-statsd rnsd
  systemctl disable rns-sentineld rns-statsd rnsd
'
```

3. Install and enable `rns-server.service`.

4. Start `rns-server`:

```bash
ssh root@vps 'systemctl daemon-reload && systemctl enable --now rns-server'
```

5. Validate in this order:

- `systemctl is-active rns-server`
- `curl -fsS http://127.0.0.1:8080/health`
- `curl -fsS http://127.0.0.1:8080/api/processes`
- public listener still present on `0.0.0.0:4242`
- RPC listener still present on `127.0.0.1:37429`
- child roles report healthy / ready
- `stats.db` continues to advance
- bridge warnings remain absent
- announce and packet freshness checks remain healthy

Post-cutover acceptance should be driven by the same reporting pipeline:

```bash
python3 scripts/vps_daily_report.py --stdout-summary
```

The post-cutover check should classify the node as healthy or healthy with
blacklist pressure.

## 6. Rollback

Rollback immediately if any of the following occur:

- missing public listener on `0.0.0.0:4242`
- missing RPC listener on `127.0.0.1:37429`
- `rns-server` does not keep child roles converged
- control plane health endpoint is unavailable
- repeated provider-bridge regressions appear
- `stats.db` stops advancing
- live packet freshness or announce activity falls stale

Rollback steps:

```bash
ssh root@vps '
  systemctl stop rns-server
  systemctl disable rns-server
  systemctl enable rnsd rns-statsd rns-sentineld
  systemctl restart rnsd
  sleep 6
  systemctl restart rns-statsd
  systemctl restart rns-sentineld
'
```

Then rerun the standard health check:

```bash
python3 scripts/vps_daily_report.py --stdout-summary
```

Do not remove the old binaries or old systemd units until:

- the maintenance-window validation passes
- the next routine daily report still shows a healthy state

## 7. Notes

This runbook is intentionally separate from the older standalone VPS deploy
runbook. The old runbook still documents the current production layout; this
document defines the controlled path away from it.
