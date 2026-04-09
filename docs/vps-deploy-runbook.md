# VPS Deploy Runbook

This runbook documents the current public VPS deployment at `root@vps`.

The VPS now runs a single systemd unit:

- `rns-server`

That unit supervises:

- `rnsd`
- `rns-statsd`
- `rns-sentineld`

Historical VPS findings have been archived into:

- [vps-reports-archive.zip](/home/lelloman/lelloprojects/rns-rs/docs/vps-reports-archive.zip)

## 1. Current live layout

Live paths on the VPS:

- `/usr/local/bin/rns-server`
- `/usr/local/bin/rns-ctl`
- `/etc/systemd/system/rns-server.service`
- `/var/lib/rns-node/config`
- `/var/lib/rns-node/rns-server.json`
- `/var/lib/rns-node/stats.db`
- `/var/lib/rns-node/logs/`
- `/var/lib/rns-node/storage/identities/identity`

Important notes:

- The control plane is bound to `127.0.0.1:18080`.
- Port `8080` is already used on this VPS by `peerlo`, so do not move
  `rns-server` back to `8080` unless that conflict is removed first.
- Shell checks against the node must use:

```bash
/usr/local/bin/rns-ctl --config /var/lib/rns-node ...
```

Using plain `rns-ctl status` will hit the old default config root and fail.

## 2. Build the release binary

From the repo root:

```bash
cargo build --release --bin rns-server --features rns-hooks
target/release/rns-server --version
target/release/rns-ctl --version
```

Optional release-style tarball:

```bash
bash scripts/package-rns-server-tarball.sh
```

## 3. Upload a test binary first

Do not replace the live binary before a remote dry-run succeeds.

```bash
scp target/release/rns-server root@vps:/usr/local/bin/rns-server.new
ssh root@vps 'chmod 0755 /usr/local/bin/rns-server.new'
ssh root@vps '/usr/local/bin/rns-server.new --version'
```

## 4. Update node config before rollout

The node-facing Reticulum config is:

- `/var/lib/rns-node/config`

The product config is:

- `/var/lib/rns-node/rns-server.json`

Before restart, update these files if the rollout changes:

- public discovery name
- public peer/interface labels
- reachable address
- control-plane bind settings
- provider bridge settings
- identity or storage layout

The current public interface block is expected to advertise the fresh
`rns-server` node identity, not the old pre-cutover VPS experiment naming.

## 5. Remote dry-run

Validate the live config root non-destructively:

```bash
ssh root@vps '/usr/local/bin/rns-server.new start --config /var/lib/rns-node --http-host 127.0.0.1 --http-port 18080 --dry-run'
```

Stop here if the dry-run does not show the expected child launch plan.

## 6. Promote and restart

Back up the current live binary, then promote the new one:

```bash
ssh root@vps '
  set -e
  cp /usr/local/bin/rns-server /usr/local/bin/rns-server.bak-OLD
  install -m 0755 /usr/local/bin/rns-server.new /usr/local/bin/rns-server
  systemctl daemon-reload
  systemctl restart rns-server
'
```

Replace `OLD` with the version or commit suffix you want to keep as the backup.

## 7. Verify the live node

After restart, all of these should pass:

```bash
ssh root@vps 'systemctl is-active rns-server'
ssh root@vps 'curl -fsS http://127.0.0.1:18080/health'
ssh root@vps 'curl -fsS http://127.0.0.1:18080/api/processes'
ssh root@vps 'ss -ltnp | grep -E "18080|37429|4242"'
ssh root@vps '/usr/local/bin/rns-server --version'
ssh root@vps '/usr/local/bin/rns-ctl --config /var/lib/rns-node status | sed -n "1,120p"'
```

Healthy result:

- `rns-server` is `active`
- `GET /health` returns healthy
- `/api/processes` shows `rnsd`, `rns-statsd`, and `rns-sentineld` as
  `running` and `ready`
- listeners are present on:
  - `127.0.0.1:18080`
  - `127.0.0.1:37429`
  - `0.0.0.0:4242`

Useful logs:

```bash
ssh root@vps 'journalctl -u rns-server -n 80 --no-pager'
ssh root@vps "journalctl -u rns-server --since '1 hour ago' --no-pager | grep MEMSTATS"
```

Useful API checks:

```bash
ssh root@vps 'curl -fsS http://127.0.0.1:18080/api/processes/rnsd/logs'
ssh root@vps 'curl -fsS http://127.0.0.1:18080/api/processes/rns-statsd/logs'
ssh root@vps 'curl -fsS http://127.0.0.1:18080/api/processes/rns-sentineld/logs'
```

Operational checks:

```bash
ssh root@vps '/usr/local/bin/rns-ctl --config /var/lib/rns-node backbone blacklist list --json'
ssh root@vps "sqlite3 /var/lib/rns-node/stats.db '
  SELECT COUNT(*) FROM seen_announces WHERE seen_at_ms >= (strftime('\"'\"'%s'\"'\"','\"'\"'now'\"'\"')-86400)*1000;
'"
ssh root@vps "sqlite3 /var/lib/rns-node/stats.db '
  SELECT packet_type, direction, datetime(MAX(updated_at_ms)/1000, \"unixepoch\")
  FROM packet_counters
  GROUP BY packet_type, direction
  ORDER BY packet_type, direction;
'"
```

Important note:

- `seen_announces` uses `seen_at_ms`
- `packet_counters` uses `updated_at_ms`

Do not use the older `ts_ms` query shape against those tables.

## 8. Daily snapshot collection

Use the local collector to persist one daily VPS snapshot into a local SQLite DB:

```bash
python3 scripts/vps_daily_report.py --stdout-summary
```

Defaults:

- host: `root@vps`
- config dir: `/var/lib/rns-node`
- control plane port: `18080`
- local DB: `data/vps_daily_reports.db`

The collector stores:

- host uptime, load, memory, swap
- `rns-server` unit state and active-since timestamp
- `rns-server` and `rns-ctl` versions
- child readiness from `/api/processes`
- required listeners and session count for `4242`
- `rns-ctl --config /var/lib/rns-node status` summary
- blacklist summary counts
- provider-bridge warning counts from `journalctl -u rns-server`
- recent `MEMSTATS` samples from `journalctl -u rns-server`
- announce counts and packet freshness from `/var/lib/rns-node/stats.db`

Main tables in the local DB:

- `daily_checks`
- `memstats_samples`
- `packet_freshness`

Useful local queries:

```bash
sqlite3 data/vps_daily_reports.db '
  SELECT report_date, health_state, announce_24h, idle_timeout_events_24h
  FROM daily_checks
  ORDER BY capture_ts_utc DESC
  LIMIT 30;
'
```

```bash
sqlite3 data/vps_daily_reports.db '
  SELECT report_date, rns_server_version, child_rnsd_ready, child_rns_statsd_ready, child_rns_sentineld_ready
  FROM daily_checks
  ORDER BY capture_ts_utc DESC
  LIMIT 30;
'
```

## 9. Roll back the binary

If the new binary or config does not converge, restore the backup and restart:

```bash
ssh root@vps '
  set -e
  install -m 0755 /usr/local/bin/rns-server.bak-OLD /usr/local/bin/rns-server
  systemctl daemon-reload
  systemctl restart rns-server
'
```

Then rerun the verification commands from section 7.

## 10. Legacy rollback to old standalone units

This should only be used if `rns-server` is not recoverable quickly and the old
standalone binaries and units are still intact on the VPS.

```bash
ssh root@vps '
  set -e
  systemctl stop rns-server
  systemctl disable rns-server
  systemctl enable rnsd rns-statsd rns-sentineld
  systemctl restart rnsd
  sleep 6
  systemctl restart rns-statsd
  systemctl restart rns-sentineld
'
```

If you use this path, the VPS is back on the old deployment model and this
runbook no longer matches the live host until `rns-server` is restored.
