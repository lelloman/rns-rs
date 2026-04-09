# VPS Reporting Runbook

This runbook standardizes the daily VPS health check and the archival handling
of historical VPS reports.

The canonical daily workflow is now script-driven:

- collect a live VPS health snapshot
- persist it to the normalized daily snapshot database
- render the Markdown daily report from that snapshot

The live transport statistics database on the VPS remains
`/var/lib/rns/stats.db`. The local normalized daily snapshot history is a
separate SQLite database under `data/`.

## 1. Daily report procedure

From the repo root:

```bash
python3 scripts/vps_daily_report.py --stdout-summary
```

Default outputs:

- normalized snapshot DB:
  `data/vps_daily_reports.db`
- generated Markdown report:
  `docs/vps-production-findings-YYYY-MM-DD.md`

Default SSH target:

- `root@vps`

Override examples:

```bash
python3 scripts/vps_daily_report.py --host root@vps
python3 scripts/vps_daily_report.py --db-path /tmp/vps_daily_reports.db
python3 scripts/vps_daily_report.py --reports-dir /tmp
python3 scripts/vps_daily_report.py --date 2026-04-09
```

## 2. Collected signals

The script collects a fixed set of operational signals:

- host uptime, load, memory, swap
- service activity and `ActiveEnterTimestamp`
- installed versions for `rnsd`, `rns-statsd`, `rns-sentineld`, `rns-ctl`
- required listeners on `0.0.0.0:4242` and `127.0.0.1:37429`
- established session count for port `4242`
- `rns-ctl status` summary
- sentinel blacklist summary from
  `rns-ctl backbone blacklist list --json`
- provider-bridge warning counts from `journalctl`
- recent `MEMSTATS` samples from the `rnsd` journal
- announce totals and recent-window counts from `seen_announces`
- packet freshness from `packet_counters`

The script uses the current live schema names:

- `seen_announces.seen_at_ms`
- `packet_counters.updated_at_ms`
- `process_samples.ts_ms`
- `provider_drop_samples.ts_ms`

## 3. Normalized daily snapshot DB

The daily snapshot DB is the canonical queryable history of operator checks.

Primary table:

- `daily_checks`

Child tables:

- `daily_check_versions`
- `daily_check_service_state`
- `daily_check_listeners`
- `daily_check_packet_freshness`
- `daily_check_memstats`
- `daily_check_blacklist_examples`

Useful example queries:

```sql
SELECT report_date, health_state, announce_24h
FROM daily_checks
ORDER BY report_date DESC;
```

```sql
SELECT report_date, idle_timeout_events_24h, blacklist_active_entries
FROM daily_checks
ORDER BY report_date DESC;
```

```sql
SELECT d.report_date, m.sample_ts_utc, m.rss_mb
FROM daily_checks AS d
JOIN daily_check_memstats AS m
  ON m.capture_ts_utc = d.capture_ts_utc
ORDER BY d.report_date DESC, m.sample_ts_utc DESC;
```

## 4. Archive handling

The historical Markdown reports stay in `docs/` for normal browsing and git
history.

To generate or refresh the in-repo zip archive bundle:

```bash
python3 scripts/archive_vps_reports.py
```

Archive outputs:

- zip bundle:
  `docs/archive/vps-reports-YYYYMMDD.zip`
- manifest/index:
  `docs/archive/index.json`

The archive bundle is a convenience artifact for packaging and offline review.
The source of truth remains the tracked Markdown files plus the normalized daily
snapshot DB.

## 5. Manual fallback checks

If the script cannot be run, the old manual checks still exist as a fallback,
but the preferred path is to repair the script or its environment rather than
revert to ad hoc copy-paste reporting.

For deployment-era manual checks, see:

- [vps-deploy-runbook.md](/home/lelloman/lelloprojects/rns-rs/docs/vps-deploy-runbook.md)
- [vps-rns-server-cutover.md](/home/lelloman/lelloprojects/rns-rs/docs/vps-rns-server-cutover.md)
