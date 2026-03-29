# VPS Production Findings — 2026-03-29 (routine health check)

Binary `rnsd 0.2.246-0eddcf1`, running since 2026-03-27 ~15:06 UTC (service
restart). This report covers the **~1 day 20h service uptime mark** (system
uptime 4 days 15h).

---

## 1. Service health

All three services active:
- `rnsd` — active (running), pid 252168
- `rns-statsd` — active (running), pid 252261
- `rns-sentineld` — active (running), pid 252263

No restarts since the 2026-03-28 report.

Listening on:
- `0.0.0.0:4242` — public backbone entrypoint
- `127.0.0.1:37429` — RPC listener

System resources:
- Memory: 651 MiB used / 1.8 GiB total (1.2 GiB available)
- `rnsd` resident: 469.6 MiB (peak 491.1 MiB)
- Swap: none
- Disk: 6.3 GiB / 77 GiB (9%) — down from 8.2 GiB on 2026-03-28 (log rotation)
- Load: 0.09 / 0.07 / 0.14
- `stats.db`: ~215 MiB (up from 196 MiB), WAL active (5 MiB), last write 11:44 UTC

CPU load remains negligible, consistent with the signature cache effectiveness
observed in the 2026-03-28 report.

---

## 2. Network state

- **54 unique inbound peer IPs** on port 4242 (down from 59 on 2026-03-28)
- **3 outbound backbone connections** (down from 4 on 2026-03-28)
- **57 total ESTABLISHED TCP connections** on port 4242

One peer (`78.211.8.189`) had a Send-Q of 3,290 bytes, indicating a slow or
congested connection.

---

## 3. Backbone interface status

The config defines 1 listening interface and 6 outbound backbone connections.

| Interface | Remote | Status |
|-----------|--------|--------|
| Public Entrypoint | 0.0.0.0:4242 (listen) | **Up** — 54 inbound peers |
| Arg0net RNS-VPS Italy | 82.223.44.241:4242 | **Connected** (outbound) |
| RMAP World | rmap.world:4242 (217.154.9.220) | **Connected** (outbound) |
| brn.ch.thunderhost.net | 107.189.28.100:4242 | **Connected** (outbound) — recovered from down |
| Berlin IPv4 | 82.165.27.170:443 | **Inbound only** — connecting to us on :4242, no outbound to :443 |
| RNS.MichMesh.net | rns.michmesh.net:7822 | **Down** — was connected on 2026-03-28 |
| RO_RetNet Craiova | 86.127.7.220:35880 | **Down** — persistently unreachable |

**3 out of 6** outbound backbone connections are active (down from 4/6 on
2026-03-28). Thunderhost recovered but MichMesh dropped. Berlin is present as
an inbound peer but the outbound connection to port 443 is not established.

---

## 4. Announce processing rates

| Metric | Value |
|--------|-------|
| Announces validated (last 1 min) | ~264 (~4.4/sec) |
| Announces validated (last 5 min) | 3,429 (~686/min avg) |

Announce throughput is slightly lower than the 2026-03-28 report (~4.4/sec vs
~6.6/sec), likely reflecting the reduced backbone connectivity (3/6 vs 4/6
outbound peers).

---

## 5. Sentinel activity

The sentinel continues blacklisting misbehaving peers for idle timeouts with
escalating durations. A new maximum escalation level was observed:

| Peer | Max level | Max ban | Reason |
|------|-----------|---------|--------|
| 95.27.6.199 | 10 | 61,440s (~17h) | idle timeouts |
| 85.26.232.72 | 7 | 7,680s (~2.1h) | idle timeouts |
| 93.100.207.104 | 6 | 3,840s (~1h) | idle timeouts |
| 194.28.29.162 | 6 | 3,840s (~1h) | idle timeouts (escalated 3→6 in ~13min) |
| 82.65.72.246 | 6 | 3,840s (~1h) | idle timeouts |
| 95.143.191.46 | 6 | 3,840s (~1h) | idle timeouts |

The level 10 ban for `95.27.6.199` is the highest escalation seen so far,
resulting in a ~17h ban. No write stall events observed — all blacklisting
remains behavioral (idle timeouts only).

---

## 6. `rns-statsd` — quiet

No journal output in the last hour. The burst of provider bridge drop warnings
from 2026-03-27T17:26:06Z (documented in the 2026-03-28 report) has not
recurred. Stats continue to be recorded normally (`stats.db` WAL active, size
growing from 196 → 215 MiB).

---

## 7. Assessment

The VPS is **operationally healthy**. All three services running, announces
flowing at ~4.4/sec, 54 inbound peers connected.

Key observations since 2026-03-28:
- **CPU and memory stable**: no resource pressure despite growing `stats.db`.
- **Backbone churn**: thunderhost recovered, MichMesh dropped, Craiova still
  down. Net result is 3/6 outbound backbone connections (down from 4/6).
- **Berlin anomaly**: the outbound connection to `82.165.27.170:443` is not
  established, but Berlin is connecting inbound on `:4242`. This may indicate
  a config or routing issue on one side, or the Berlin node may have changed
  its listening port.
- **Peer count dipped slightly**: 59 → 54 unique IPs, within normal
  fluctuation.
- **Sentinel escalation ceiling**: first level 10 ban observed (~17h). The
  escalation ladder appears to be working as designed for persistent offenders.
- **Announce rate down ~33%**: likely correlated with fewer backbone peers
  propagating announces.
