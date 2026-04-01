# VPS Production Findings — 2026-04-01 (routine health check)

Binary `rnsd 0.2.246-0eddcf1`, running since `2026-03-27 15:06 UTC`
(service restart). This report covers the **~4 day 23h service uptime mark**.

Checks were collected on `2026-04-01 14:54 UTC` from the live VPS
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
- Memory: 797 MiB used / 1.8 GiB total (1.0 GiB available)
- Swap: none
- Disk: 7.4 GiB / 77 GiB (10%)
- Load: 0.01 / 0.04 / 0.09
- `stats.db`: ~276 MiB
- `stats.db-wal`: 5.0 MiB

Per-process memory / CPU sample (`ps`):
- `rnsd`: RSS ~276 MiB, CPU 3.9%
- `rns-statsd`: RSS ~7.7 MiB, CPU 0.3%
- `rns-sentineld`: RSS ~2.8 MiB, CPU 0.2%

Systemd service accounting reported:
- `rnsd` current memory: 605.7 MiB
- `rnsd` peak memory: 668.3 MiB
- `rns-statsd` current memory: 54.3 MiB
- `rns-sentineld` current memory: 1.2 MiB

---

## 2. Network state

- **43 established TCP connections** involving port 4242 at sample time

This is down from the 2026-03-31 report (65 established TCP connections on
port 4242), but still clearly indicates active public backbone traffic with
dozens of connected peers.

---

## 3. Backbone interface status

The config defines 1 listening interface and 6 outbound backbone connections.

| Interface | Remote | Status |
|-----------|--------|--------|
| Public Entrypoint | 0.0.0.0:4242 (listen) | **Up** — public listener active |
| Arg0net RNS-VPS Italy | 82.223.44.241:4242 | **Connected** |
| RNS.MichMesh.net ipv4 | `*:7822` (IPv6 session observed) | **Connected** |
| Berlin IPv4 | 82.165.27.170:443 | **Connected** |
| RMAP World | rmap.world:4242 (217.154.9.220) | **Connected** |
| RO_RetNet Craiova TCP | 86.127.7.220:35880 | **Down** |
| brn.ch.thunderhost.net | 107.189.28.100:4242 | **Connected** |

**5 out of 6** outbound backbone connections are active.

Change since 2026-03-31:
- MichMesh remains connected.
- Craiova remains down.
- The other four outbound peers remain established.

---

## 4. Announce processing rates

Sampled from the live `rnsd` journal:

| Metric | Value |
|--------|-------|
| Announces validated (last 1 min) | 1,034 (~17.2/sec) |
| Announces validated (last 5 min) | 3,186 (~10.6/sec avg) |
| Announces validated (last 1 hour) | 50,621 (~14.1/sec avg) |

Announce flow is healthy. The 1-hour sample shows sustained double-digit
announce throughput, while the 1-minute sample indicates a temporary burst
above the 5-minute average during collection.

Recent live journal output consisted of continuous `Announce:validated` lines
and `Announce received` lines, consistent with normal backbone activity.

---

## 5. Sentinel activity

The sentinel remains active and is blacklisting misbehaving peers as designed.

Recent activity included:
- repeated idle-timeout escalations up to level 7 (`7,680s`, ~2.1h)
- a write-stall escalation sequence for `178.178.211.131`

Sample from the last ~90 minutes:

| Peer | Max level seen | Max ban | Reason |
|------|----------------|---------|--------|
| 188.162.250.33 | 7 | 7,680s (~2.1h) | idle timeouts |
| 89.250.175.191 | 7 | 7,680s (~2.1h) | idle timeouts |
| 79.139.251.90 | 7 | 7,680s (~2.1h) | idle timeouts |
| 176.59.37.50 | 6 | 3,840s (~1.1h) | idle timeouts |
| 178.178.243.187 | 5 | 1,920s | idle timeouts |
| 178.178.211.131 | 5 | 1,920s | write stalls |
| 95.31.209.160 | 4 | 960s | idle timeouts |

This is similar to the 2026-03-31 report: idle timeouts dominate, with a small
number of peers also triggering write-stall blacklisting.

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

Memory usage increased again relative to the 2026-03-31 report:

- host used memory: `765 MiB` -> `797 MiB`
- `rnsd` RSS: ~`231 MiB` -> ~`276 MiB`
- `rnsd` systemd `MemoryCurrent`: `527.8 MiB` -> `605.7 MiB`
- `stats.db`: ~`254 MiB` -> ~`276 MiB`

This is real growth, not just measurement noise.

What remains unclear is whether the growth is:
- an unbounded `rnsd` leak
- workload-driven allocator / cache growth inside `rnsd`
- host filesystem cache pressure as `stats.db` continues to expand
- some combination of the above

Operationally, the VPS is still not under memory pressure:
- ~`1.0 GiB` remains available
- swap is disabled but not currently needed
- load is low
- there have been no service restarts or instability events

Disk usage is still comfortable at `10%`, but `stats.db` continues to grow
steadily and remains an open retention / compaction question.

---

## 8. Assessment

The VPS is **operationally healthy**.

Current state:
- all three services are running and have not restarted since `2026-03-27`
- required listeners are present (`:4242`, `127.0.0.1:37429`)
- announce processing is healthy (`50,621` validated announces in the last hour)
- 5 of 6 configured outbound backbone peers are currently connected
- Craiova remains down
- sentinel continues to contain slow or misbehaving peers

The main open concern is memory drift. The node is still stable and has ample
headroom, but both host memory and `rnsd` memory moved upward again today, so
the trend should continue to be monitored rather than dismissed.
