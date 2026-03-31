# VPS Production Findings — 2026-03-31 (routine health check)

Binary `rnsd 0.2.246-0eddcf1`, running since `2026-03-27 15:06 UTC`
(service restart). This report covers the **~4 day 1h service uptime mark**.

Checks were collected on `2026-03-31 16:37 UTC` from the live VPS
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
- Memory: 765 MiB used / 1.8 GiB total (1.0 GiB available)
- Swap: none
- Disk: 7.1 GiB / 77 GiB (10%)
- Load: 0.10 / 0.17 / 0.30
- `stats.db`: ~254 MiB
- `stats.db-wal`: 5.0 MiB

Per-process memory / CPU sample (`ps`):
- `rnsd`: RSS ~231 MiB, CPU 3.7%
- `rns-statsd`: RSS ~7.7 MiB, CPU 0.3%
- `rns-sentineld`: RSS ~2.8 MiB, CPU 0.2%

Systemd service accounting reported:
- `rnsd` current memory: 527.8 MiB
- `rnsd` peak memory: 609.9 MiB
- `rns-statsd` current memory: 58.3 MiB
- `rns-sentineld` current memory: 1.2 MiB

---

## 2. Network state

- **65 established TCP connections** on port 4242 at sample time
- **60 unique inbound peer IPs** on port 4242 at sample time

This is up from the 2026-03-30 report (50 peers / 50 established TCP
connections on port 4242), indicating stronger inbound connectivity today.

---

## 3. Backbone interface status

The config defines 1 listening interface and 6 outbound backbone connections.

| Interface | Remote | Status |
|-----------|--------|--------|
| Public Entrypoint | 0.0.0.0:4242 (listen) | **Up** — 60 inbound peers |
| Arg0net RNS-VPS Italy | 82.223.44.241:4242 | **Connected** |
| RNS.MichMesh.net | `*:7822` (IPv6) | **Connected** |
| Berlin IPv4 | 82.165.27.170:443 | **Connected** |
| RMAP World | rmap.world:4242 (217.154.9.220) | **Connected** |
| RO_RetNet Craiova TCP | 86.127.7.220:35880 | **Down** |
| brn.ch.thunderhost.net | 107.189.28.100:4242 | **Connected** |

**5 out of 6** outbound backbone connections are active.

Change since 2026-03-30:
- **MichMesh recovered** — an established IPv6 connection to port `7822` was
  present during this check.
- **Craiova remains down**.

---

## 4. Announce processing rates

Sampled from the live `rnsd` journal:

| Metric | Value |
|--------|-------|
| Announces validated (last 1 min) | 2,093 (~34.9/sec) |
| Announces validated (last 5 min) | 5,434 (~18.1/sec avg) |

Announce flow is clearly healthy. The 1-minute sample was materially above the
2026-03-30 report, suggesting a bursty but active announce period during this
check.

Recent live journal output consisted of continuous `Announce:validated` lines
and dynamic interface churn on the public listener, consistent with normal
backbone activity.

---

## 5. Sentinel activity

The sentinel remains active and is blacklisting misbehaving peers as designed.

Recent activity included:
- idle-timeout escalations up to level 13 (`491,520s`, ~5.7 days) for
  `87.117.62.81`
- continuing write-stall escalations for `45.133.243.243`
- a new write-stall escalation sequence for `5.141.100.7`

Sample from the last ~2 hours:

| Peer | Max level seen | Max ban | Reason |
|------|----------------|---------|--------|
| 87.117.62.81 | 13 | 491,520s (~5.7d) | idle timeouts |
| 31.181.60.131 | 9 | 30,720s (~8.5h) | idle timeouts |
| 104.28.230.245 | 8 | 15,360s (~4.3h) | idle timeouts |
| 128.70.144.68 | 6 | 3,840s (~1.1h) | idle timeouts |
| 178.157.134.31 | 6 | 3,840s (~1.1h) | idle timeouts |
| 5.141.100.7 | 3 | 480s | write stalls |
| 45.133.243.243 | 2 | 240s | write stalls |

This is a step up in idle-timeout escalation severity compared to the
2026-03-30 report. Write stalls are still present, but remain limited to a
small set of offenders.

---

## 6. `rns-statsd`

No recent `rns-statsd` journal output was recorded during this check.

Stats collection still appears healthy:
- `/var/lib/rns/stats.db` timestamp updated during the check
- `/var/lib/rns/stats.db-wal` timestamp updated during the check
- process CPU time continues to advance

This matches the recent quiet pattern: the process is alive and the database is
continuing to grow.

---

## 7. Memory and disk interpretation

The machine-level memory figure increased again from the 2026-03-30 report
(`701 MiB used`) to `765 MiB used` today, but this still should not be read as
clear evidence of an unbounded `rnsd` memory leak.

Key points:
- host memory usage has trended upward across recent reports (`605 MiB` on
  2026-03-28, `651 MiB` on 2026-03-29, `701 MiB` on 2026-03-30, `765 MiB`
  today)
- at least part of that growth is consistent with filesystem cache pressure as
  `stats.db` grew from ~196 MiB to ~254 MiB across the same window
- there is still no operational memory pressure on the VPS (`~1.0 GiB`
  available, no swap)
- prior investigation already found the major unbounded in-memory structures
  were fixed or capped

Disk usage needs a distinction:
- whole-filesystem usage is **not** monotonic (`8.2 GiB` on 2026-03-28,
  `6.3 GiB` on 2026-03-29, `6.7 GiB` on 2026-03-30, `7.1 GiB` today), so there
  is no evidence of runaway overall disk consumption
- `stats.db` itself **is** growing steadily (`196 MiB` → `215 MiB` → `235 MiB`
  → `254 MiB` across 2026-03-28 through 2026-03-31), which suggests the stats
  store currently has no visible retention or pruning limit

Operationally, memory is still acceptable, but disk growth in `stats.db` looks
structural rather than incidental and should be treated as an open capacity
question.

---

## 8. Assessment

The VPS is **operationally healthy**.

Current state:
- all three services are running and have not restarted since `2026-03-27`
- required listeners are present (`:4242`, `127.0.0.1:37429`)
- inbound peer count is up materially from the 2026-03-30 sample
- announce processing is healthy
- MichMesh outbound connectivity recovered
- Craiova remains down
- sentinel continues to contain slow or misbehaving peers

The only persistent degradations are:
- backbone peer availability for `Craiova`
- continued low-volume write-stall churn on some inbound peers
- steady `stats.db` growth, which may eventually require retention,
  compaction, or rotation policy
