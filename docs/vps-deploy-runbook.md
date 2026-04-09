# VPS Deploy Runbook

This runbook documents the current deployment procedure for the public VPS
(`root@vps`) running:

- `rnsd`
- `rns-statsd`
- `rns-sentineld`

Historical VPS findings have been archived into:

- [vps-reports-archive.zip](/home/lelloman/lelloprojects/rns-rs/docs/vps-reports-archive.zip)

## 1. Build release binaries

From the repo root:

```bash
cargo build --release --bin rnsd --bin rns-statsd --bin rns-sentineld --bin rns-ctl
target/release/rnsd --version
target/release/rns-statsd --version
target/release/rns-sentineld --version
target/release/rns-ctl --version
```

Expected result: all four binaries report the same target commit.

## 2. Upload test binaries first

Do not replace the live binaries before testing startup on the VPS.

```bash
ssh root@vps 'cat > /usr/local/bin/rnsd.new' < target/release/rnsd
ssh root@vps 'cat > /usr/local/bin/rns-statsd.new' < target/release/rns-statsd
ssh root@vps 'cat > /usr/local/bin/rns-sentineld.new' < target/release/rns-sentineld
ssh root@vps 'cat > /usr/local/bin/rns-ctl.test' < target/release/rns-ctl
ssh root@vps 'chmod +x /usr/local/bin/rnsd.new /usr/local/bin/rns-statsd.new /usr/local/bin/rns-sentineld.new'
```

Verify the uploaded versions:

```bash
ssh root@vps '/usr/local/bin/rnsd.new --version'
ssh root@vps '/usr/local/bin/rns-statsd.new --version'
ssh root@vps '/usr/local/bin/rns-sentineld.new --version'
ssh root@vps '/usr/local/bin/rns-ctl.test --version'
```

## 3. Run the isolated VPS startup probe

Use the helper script:

```bash
bash scripts/bisect-vps-rpc.sh
```

The probe is considered good only if the test daemon on the VPS starts both:

- the shared-instance listener
- the RPC listener

On success, the VPS output should show listeners like:

- `127.0.0.1:47428`
- `127.0.0.1:47429`

If the probe fails, stop here. Do not touch the live services.

## 4. Check current live state

Before rollout, capture the live versions and service state:

```bash
ssh root@vps '/usr/local/bin/rnsd --version'
ssh root@vps '/usr/local/bin/rns-statsd --version'
ssh root@vps '/usr/local/bin/rns-sentineld --version'
ssh root@vps 'systemctl is-active rnsd rns-statsd rns-sentineld'
```

## 5. Back up and promote the binaries

Replace the live binaries only after the isolated probe passes.

Example using the versions that were live before the `f1ab29d` rollout:

```bash
ssh root@vps '
  set -e
  cp /usr/local/bin/rnsd /usr/local/bin/rnsd.bak-f96ef5d
  cp /usr/local/bin/rns-statsd /usr/local/bin/rns-statsd.bak-339e071
  cp /usr/local/bin/rns-sentineld /usr/local/bin/rns-sentineld.bak-339e071 2>/dev/null || true
  install -m 0755 /usr/local/bin/rnsd.new /usr/local/bin/rnsd
  install -m 0755 /usr/local/bin/rns-statsd.new /usr/local/bin/rns-statsd
  install -m 0755 /usr/local/bin/rns-sentineld.new /usr/local/bin/rns-sentineld
'
```

Adjust the backup suffixes to match the versions currently deployed.

## 6. Restart `rnsd` first

Restart the daemon before `rns-statsd`:

```bash
ssh root@vps '
  systemctl restart rnsd
  sleep 6
  systemctl --no-pager --full status rnsd | sed -n "1,40p"
  ss -ltnp | grep -E "37428|37429|4242" || true
'
```

Required checks:

- `rnsd.service` is `active (running)`
- `0.0.0.0:4242` is listening
- `127.0.0.1:37429` is listening

`127.0.0.1:37428` may also be present when the shared instance listener is up.

If the RPC port is missing, roll back immediately.

## 7. Restart `rns-statsd` and `rns-sentineld`

Once `rnsd` is confirmed healthy:

```bash
ssh root@vps '
  systemctl restart rns-statsd
  systemctl restart rns-sentineld
  sleep 6
  systemctl --no-pager --full status rns-statsd | sed -n "1,40p"
  systemctl --no-pager --full status rns-sentineld | sed -n "1,40p"
  journalctl -u rns-statsd -n 10 --no-pager
  journalctl -u rns-sentineld -n 10 --no-pager
'
```

Important behavior:

- Both `rns-statsd` and `rns-sentineld` have internal RPC retry loops (5s
  interval) and will wait for `rnsd` to become ready without crashing.
- On first deploy, `rns-sentineld` needs a systemd unit (see section 10).

The final state must be `active (running)` for all three services.

## 8. Final verification

After all services are restarted:

```bash
ssh root@vps '
  systemctl is-active rnsd rns-statsd rns-sentineld
  /usr/local/bin/rnsd --version
  /usr/local/bin/rns-statsd --version
  /usr/local/bin/rns-sentineld --version
  ss -ltnp | grep -E "37429|4242"
'
```

Healthy result:

- all three services are `active`
- all binaries report the intended release version
- `rnsd` is listening on:
  - `0.0.0.0:4242`
  - `127.0.0.1:37429`

Useful log checks:

```bash
ssh root@vps 'journalctl -u rnsd -n 20 --no-pager'
ssh root@vps 'journalctl -u rns-statsd -n 20 --no-pager'
ssh root@vps 'journalctl -u rns-sentineld -n 20 --no-pager'
ssh root@vps "journalctl -u rnsd --since '1 hour ago' --no-pager | grep MEMSTATS"
```

Provider-bridge / sidecar investigation checks:

```bash
ssh root@vps '/usr/local/bin/rns-ctl status'
ssh root@vps '/usr/local/bin/rns-ctl backbone blacklist list --json'
ssh root@vps "journalctl -u rns-statsd --since '1 hour ago' --no-pager | grep -c 'provider bridge dropped'"
ssh root@vps "journalctl -u rns-sentineld --since '24 hours ago' --no-pager | grep -c 'provider bridge disconnected'"
ssh root@vps "sqlite3 /var/lib/rns/stats.db '
  SELECT datetime(ts_ms/1000, \"unixepoch\") AS ts, dropped_events
  FROM provider_drop_samples
  ORDER BY ts_ms DESC
  LIMIT 50;
'"
```

Interpretation:

- `rns-ctl status` is the current installed command for checking live transport
  and interface state on the VPS.
- `rns-ctl backbone blacklist list --json` is the current installed command for
  checking sentinel blacklist activity and reject counts.
- `provider bridge dropped` warnings in `rns-statsd` indicate bridge loss that
  is visible in the current journal window.
- `provider bridge disconnected` warnings in `rns-sentineld` indicate bridge
  reconnect churn or a possible return to the earlier degraded state.
- `provider_drop_samples` in SQLite provide the historical drop rate seen by
  `rns-statsd`, independent of transient journal retention, when rows are
  present.

Important note:

- The `rns-ctl` binary currently deployed on the VPS does **not** provide the
  older `backbone provider` or `interfaces` subcommands that appeared in older
  operator habits. Use `rns-ctl status` instead.
- `seen_announces` now uses `seen_at_ms`, and `packet_counters` now uses
  `updated_at_ms`. Do not use the older ad hoc `ts_ms` query shape against
  those tables.

## 9. Daily snapshot collection

Use the local collector script to persist one VPS health snapshot into a local
SQLite DB:

```bash
python3 scripts/vps_daily_report.py --stdout-summary
```

Default local DB path:

- `data/vps_daily_reports.db`

The script collects:

- host uptime, load, memory, swap
- service activity and active-since timestamps
- installed versions for `rnsd`, `rns-statsd`, `rns-sentineld`, `rns-ctl`
- required listeners and established session count for `4242`
- `rns-ctl status` summary
- blacklist summary counts
- provider-bridge warning counts
- recent `MEMSTATS` rows
- announce counts and packet freshness from `/var/lib/rns/stats.db`

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
  SELECT d.report_date, m.sample_ts_utc, m.rss_mb
  FROM daily_checks AS d
  JOIN memstats_samples AS m
    ON m.capture_ts_utc = d.capture_ts_utc
  ORDER BY d.capture_ts_utc DESC, m.sample_ts_utc DESC
  LIMIT 60;
'
```

`MEMSTATS` runs every ~5 minutes inside `rnsd` and is the primary memory-growth
signal for the VPS experiment.

Relevant memory-safety config knobs in `[reticulum]`:

- `announce_queue_max_interfaces`
  Maximum number of interface-scoped announce bandwidth queues retained.
  Default: `1024`. This bounds historical dynamic-interface churn from growing
  the outer announce-queue map without limit.
- `max_path_destinations`
  Maximum number of retained path-table destinations.
  Default: `8192`. This bounds live path-table cardinality on public nodes.
- `known_destinations_max_entries`
  Maximum number of retained recalled announced identities.
  Default: `8192`. This bounds `known_destinations` in addition to its TTL
  cleanup policy.

Important fields:

- `rss_mb`, `vmrss_mb`
  Current resident memory sample.
- `vmhwm_mb`
  Peak resident set seen by the kernel.
- `vmdata_mb`
  Process data-segment size; useful for tracking heap-like growth.
- `smaps_anon_mb`
  Anonymous resident memory. If this rises while table counts stay flat, treat
  the growth as in-process memory, not filesystem cache.
- `smaps_file_est_mb`
  Approximate file-backed resident memory (`smaps_rss_mb - smaps_anon_mb`).
  If this rises with `stats.db`, page cache / file-backed mappings are likely
  part of the story.
- `smaps_private_dirty_mb`
  Private dirty resident memory. Sustained growth here is a strong signal that
  `rnsd` itself is retaining writable pages.
- `known_dest`, `path`, `announce`, `link`, `hashlist`, `sig_cache`,
  `ann_verify_q`
  Existing tracked collections and queues. If these stay flat while anonymous
  memory rises, the remaining growth is likely allocator retention or an
  untracked buffer/cache.
- `known_dest_cap_evict`
  Number of `known_destinations` evictions caused by
  `known_destinations_max_entries`. In normal VPS operation this should remain
  `0` or grow very slowly; sustained growth means the cap is actively shaping
  behavior.
- `path_cap_evict`
  Number of path-table destination evictions caused by `max_path_destinations`.
  In normal VPS operation this should remain `0` or near `0`; sustained growth
  means the configured path-table cap is too low for the observed destination
  churn.
- `ann_q_ifaces`, `ann_q_nonempty`, `ann_q_entries`, `ann_q_bytes`
  Per-interface announce bandwidth queue cardinality and buffered payload size.
  `ann_q_ifaces` should stay close to live interface churn after the queue
  cleanup fix.
- `ann_q_iface_drop`
  Number of announces dropped because creating a new interface queue would
  exceed `announce_queue_max_interfaces`. In normal VPS operation this should
  remain `0`; non-zero values mean the cap is too low for the workload.

## 10. Rollback

If the new `rnsd` does not expose the RPC listener, restore the backups and
restart in the same order:

```bash
ssh root@vps '
  set -e
  install -m 0755 /usr/local/bin/rnsd.bak-OLD /usr/local/bin/rnsd
  install -m 0755 /usr/local/bin/rns-statsd.bak-OLD /usr/local/bin/rns-statsd
  install -m 0755 /usr/local/bin/rns-sentineld.bak-OLD /usr/local/bin/rns-sentineld 2>/dev/null || true
  systemctl restart rnsd
  sleep 6
  systemctl restart rns-statsd
  systemctl restart rns-sentineld 2>/dev/null || true
'
```

Replace `OLD` with the actual backup suffixes.

Then rerun the final verification commands from section 8.

## 11. Planned `rns-server` migration

When switching the VPS from standalone systemd-managed `rnsd` /
`rns-statsd` / `rns-sentineld` to the supervised single-binary `rns-server`
model, use this sequence:

1. Build and package `rns-server`:

```bash
bash scripts/package-rns-server-tarball.sh
```

2. Prepare the target node root, recommended:

- `/var/lib/rns-node/config`
- `/var/lib/rns-node/rns-server.json`
- `/var/lib/rns-node/stats.db`
- `/var/lib/rns-node/logs/`

3. Validate non-destructively on the VPS:

```bash
ssh root@vps '/usr/local/bin/rns-server --version'
ssh root@vps '/usr/local/bin/rns-server start --config /var/lib/rns-node --dry-run'
```

4. Install a single `rns-server.service` unit that starts:

```bash
/usr/local/bin/rns-server start --config /var/lib/rns-node --http-host 127.0.0.1 --http-port 8080
```

5. During the maintenance window:

- stop and disable `rnsd`, `rns-statsd`, `rns-sentineld`
- enable and start `rns-server`
- verify:
  - `systemctl is-active rns-server`
  - `curl -fsS http://127.0.0.1:8080/health`
  - `curl -fsS http://127.0.0.1:8080/api/processes`
  - required listeners still present on `4242` and `37429`
  - stats DB is advancing
  - provider-bridge regressions remain absent
- capture a post-cutover local snapshot with:

```bash
python3 scripts/vps_daily_report.py --stdout-summary
```

6. Roll back immediately if the public listener, RPC listener, child readiness,
control plane, or packet freshness regresses.

Rollback sequence:

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

## 12. Notes

- The safest deployment path is: build locally, upload test binaries, run the
  isolated VPS probe, then promote the live binaries.
- The isolated probe exists specifically to catch startup failures where
  `rnsd` never reaches the RPC listener.
- The current live service paths are:
  - `/usr/local/bin/rnsd`
  - `/usr/local/bin/rns-statsd`
  - `/usr/local/bin/rns-sentineld`

## 13. First-time `rns-sentineld` setup

On a VPS that has never run `rns-sentineld`, create the systemd unit:

```bash
ssh root@vps 'cat > /etc/systemd/system/rns-sentineld.service' <<'EOF'
[Unit]
Description=Reticulum Backbone Peer Sentinel
After=network.target rnsd.service
Requires=rnsd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/rns-sentineld
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
ssh root@vps 'systemctl daemon-reload && systemctl enable rns-sentineld'
```

CLI options for tuning detection thresholds:

```
--write-stall-threshold N    Write stalls before blacklist (default: 2)
--idle-timeout-threshold N   Idle timeouts before blacklist (default: 4)
--event-window SECS          Sliding window for event counting (default: 300)
--base-blacklist SECS        Base blacklist duration, doubles each escalation (default: 120)
```

To customize, edit the `ExecStart` line in the unit file, e.g.:

```
ExecStart=/usr/local/bin/rns-sentineld --write-stall-threshold 3 --base-blacklist 60
```
