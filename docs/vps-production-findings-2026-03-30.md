# VPS Production Findings — 2026-03-30 (routine health check)

Binary `rnsd 0.2.246-0eddcf1`, running since `2026-03-27 15:06 UTC`
(service restart). This report covers the **~2 day 23h service uptime mark**.

Checks were collected on `2026-03-30 14:46 UTC` from the live VPS
(`root@vps`).

---

## 1. Service health

All three services active:
- `rnsd` — active (running), pid 252168
- `rns-statsd` — active (running), pid 252261
- `rns-sentineld` — active (running), pid 252263

No restarts since startup on `2026-03-27 15:06 UTC`:
- `rnsd`: `NRestarts=0`
- `rns-statsd`: `NRestarts=0`
- `rns-sentineld`: `NRestarts=0`

Listening on:
- `0.0.0.0:4242` — public backbone entrypoint
- `127.0.0.1:37429` — RPC listener

`127.0.0.1:37428` was not present during this check. Per the deploy runbook,
that listener is optional.

System resources:
- Memory: 701 MiB used / 1.8 GiB total (1.1 GiB available)
- Swap: none
- Disk: 6.7 GiB / 77 GiB (9%)
- Load: 0.29 / 0.11 / 0.17
- `stats.db`: ~235 MiB
- `stats.db-wal`: 5.0 MiB

Per-process memory / CPU sample (`ps`):
- `rnsd`: RSS ~181 MiB, CPU 3.7%
- `rns-statsd`: RSS ~7.5 MiB, CPU 0.3%
- `rns-sentineld`: RSS ~2.7 MiB, CPU 0.2%

Systemd service accounting for `rnsd` reported:
- current memory: 500.7 MiB
- peak memory: 518.6 MiB

---

## 2. Network state

- **50 established TCP connections** on port 4242 at sample time
- **50 unique inbound peer IPs** on port 4242 at sample time

This is slightly down from the 2026-03-29 report (54 peers / 57 established
TCP connections on port 4242), but still within normal day-to-day fluctuation.

---

## 3. Backbone interface status

The config defines 1 listening interface and 6 outbound backbone connections.

| Interface | Remote | Status |
|-----------|--------|--------|
| Public Entrypoint | 0.0.0.0:4242 (listen) | **Up** — 50 inbound peers |
| Arg0net RNS-VPS Italy | 82.223.44.241:4242 | **Connected** |
| RNS.MichMesh.net ipv4 | rns.michmesh.net:7822 | **Down** — repeated `Connection refused` |
| Berlin IPv4 | 82.165.27.170:443 | **Connected** |
| RMAP World | rmap.world:4242 (217.154.9.220) | **Connected** |
| RO_RetNet Craiova TCP | 86.127.7.220:35880 | **Down** |
| brn.ch.thunderhost.net | 107.189.28.100:4242 | **Connected** |

**4 out of 6** outbound backbone connections are active.

Change since 2026-03-29:
- **Berlin outbound recovered** — `82.165.27.170:443` is now established again.
- **MichMesh remains down** — repeated reconnect failures with `Connection refused`.
- **Craiova remains down**.

---

## 4. Announce processing rates

Sampled from the live `rnsd` journal:

| Metric | Value |
|--------|-------|
| Announces validated (last 1 min) | 421 (~7.0/sec) |
| Announces validated (last 5 min) | 3,416 (~11.4/sec) |

Announce flow is healthy and materially above the 2026-03-29 sample
(~4.4/sec).

Recent `MEMSTATS` sample:

| Field | Value |
|-------|-------|
| `rss_mb` | 181.0 |
| `known_dest` | 7,992 |
| `path` | 7,454 |
| `announce` | 13 |
| `link` | 17 |
| `hashlist` | 250,000 |
| `sig_cache` | 1,403 |
| `pr_tags` | 32,000 |
| `ann_verify_q` | 0 |

The capped tables remain at their configured limits (`hashlist`, `pr_tags`).

---

## 5. Sentinel activity

The sentinel remains active and is blacklisting misbehaving peers as designed.

Recent activity included:
- escalating idle-timeout bans up to level 8 (`15,360s`)
- a short write-stall escalation sequence for `81.195.181.174`

Sample from the last ~2 hours:

| Peer | Max level seen | Max ban | Reason |
|------|----------------|---------|--------|
| 91.105.176.38 | 8 | 15,360s (~4.3h) | idle timeouts |
| 5.44.174.9 | 8 | 15,360s (~4.3h) | idle timeouts |
| 185.68.119.100 | 6 | 3,840s (~1.1h) | idle timeouts |
| 91.78.227.171 | 4 | 960s | idle timeouts |
| 81.195.181.174 | 4 | 960s | write stalls |

This differs from the 2026-03-29 report, which observed only idle-timeout
blacklisting. Write stalls are still present, but limited to a small number of
offenders.

---

## 6. `rns-statsd`

No `rns-statsd` journal output was recorded in the last 24 hours.

Stats collection still appears healthy:
- `/var/lib/rns/stats.db` timestamp updated during the check
- `/var/lib/rns/stats.db-wal` timestamp updated during the check

This matches the recent quiet pattern: the process is alive, consuming CPU over
time, and the database is continuing to grow.

---

## 7. Memory interpretation

The machine-level memory figure increased from the 2026-03-29 report
(`651 MiB used`) to `701 MiB used` today, but this should not be interpreted as
a direct `rnsd` leak.

Key points:
- `stats.db` grew from ~215 MiB to ~235 MiB, which increases filesystem cache.
- Prior investigation showed the major unbounded structures were resolved or
  bounded; the remaining `rnsd` RSS drift was ~1 MiB/h and attributed mainly to
  allocator fragmentation / unreturned freed memory rather than live table
  growth.
- The current live `rnsd` resident sample was ~181 MiB (`rss_mb=181.0`,
  matching `btop` `MemB`).

Operationally, there is no current memory pressure on the VPS.

---

## 8. Assessment

The VPS is **operationally healthy**.

Current state:
- all three services are running and have not restarted since `2026-03-27`
- required listeners are present (`:4242`, `127.0.0.1:37429`)
- announce processing is healthy
- Berlin outbound connectivity recovered
- MichMesh and Craiova remain down
- sentinel continues to contain slow or misbehaving peers

The only persistent degradations are backbone peer availability (`MichMesh`,
`Craiova`) and ongoing low-volume write-stall churn on some inbound peers.
