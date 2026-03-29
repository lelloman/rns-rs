# VPS Production Findings — 2026-03-28 (routine health check)

Binary `rnsd 0.2.246-0eddcf1`, running since 2026-03-24 ~20:14 UTC (system
reboot). This report covers the **~3.5 day uptime mark**.

---

## 1. Service health

All three services active:
- `rnsd` — active (running), pid 252168
- `rns-statsd` — active (running), pid 252261
- `rns-sentineld` — active (running), pid 252263

Uptime: 3 days, 12 hours.

Listening on:
- `0.0.0.0:4242` — public backbone entrypoint
- `127.0.0.1:37429` — RPC listener

System resources:
- Memory: 605 MiB used / 1.8 GiB total (1.2 GiB available)
- Swap: none
- Disk: 8.2 GiB / 77 GiB (11%)
- Load: 0.00 / 0.02 / 0.08
- `stats.db`: ~196 MiB (WAL active, last write 09:09 UTC)

CPU load is negligible compared to the 33% seen in the 2026-03-25 report,
suggesting the announce signature cache (`AnnounceSignatureCache`) deployed in
this version is effective.

---

## 2. Network state

- **59 unique peer IPs** connected on port 4242 (up from 39 on 2026-03-25)
- **70 ESTABLISHED TCP connections** on port 4242

---

## 3. Backbone interface status

The config defines 1 listening interface and 6 outbound backbone connections.

| Interface | Remote | Status |
|-----------|--------|--------|
| Public Entrypoint | 0.0.0.0:4242 (listen) | **Up** — 59 inbound peers |
| Arg0net RNS-VPS Italy | 82.223.44.241:4242 | **Connected** (IPv4) |
| RNS.MichMesh.net | rns.michmesh.net:7822 | **Connected** (IPv6) |
| Berlin IPv4 | 82.165.27.170:443 | **Connected** (IPv4) |
| RMAP World | rmap.world:4242 | **Connected** (IPv4, 217.154.9.220) |
| RO_RetNet Craiova | 86.127.7.220:35880 | **Down** |
| brn.ch.thunderhost.net | 107.189.28.100:4242 | **Down** |

**4 out of 6** outbound backbone connections are active. The two down peers
(Craiova and thunderhost) have no established TCP connections, suggesting they
are offline or unreachable. Since `rnsd` has reconnect logic, these have likely
been failing persistently.

---

## 4. Announce processing rates

| Metric | Value |
|--------|-------|
| Announces validated (last 1 min) | ~399 (~6.6/sec) |
| Announces validated (last 5 min) | 2,710 (~542/min avg) |
| Unique destinations (last 5 min) | 271 |

Announce throughput is healthy. With 59 peers (vs. 39 on 2026-03-25) and
significantly lower CPU, the signature cache is clearly avoiding redundant
verification work.

---

## 5. Sentinel activity

The sentinel is actively blacklisting misbehaving peers for "repeated idle
timeouts" with escalating durations. Sample from the last ~2 hours:

| Peer | Max level | Max ban | Reason |
|------|-----------|---------|--------|
| 128.71.154.51 | 8 | 15,360s (~4.3h) | idle timeouts |
| 91.228.96.31 | 7 | 7,680s (~2.1h) | idle timeouts |
| 109.248.132.238 | 6 | 3,840s (~1h) | idle timeouts |
| 91.78.229.58 | 5 | 1,920s (~32min) | idle timeouts |

No write stall events observed in this period — all blacklisting is
behavioral (idle timeouts only).

---

## 6. `rns-statsd` — provider bridge event drops

All `rns-statsd` journal output consists of a single burst of "provider bridge
dropped N event(s)" warnings, all timestamped `2026-03-27T17:26:06Z` (within
the same second). No log output before or after this burst.

Despite the drop warnings, **stats are still being recorded**: `stats.db` was
actively written at time of check (WAL modified at 09:09 UTC). The process is
alive (pid 252261, 4h26m CPU time over 3.5 days).

The burst pattern — dozens of drop warnings in a single second, then silence —
suggests a sudden event flood (likely a reconnect storm from multiple peers)
that momentarily overwhelmed the provider bridge channel. The configured
`provider_overflow_policy = drop_newest` handled the overflow as designed.

Worth investigating:
- Whether the channel capacity (default 16,384 events) is sufficient for burst
  scenarios, or if it should be increased.
- Whether the drop warning log should be rate-limited to avoid log spam during
  bursts (similar to the stall warning noise identified in the 2026-03-25
  report).

---

## 7. Assessment

The VPS is **operationally healthy**. All three services running, announces
flowing at ~6.6/sec across 271 destinations, 59 peers connected.

Key observations since 2026-03-25:
- **CPU usage resolved**: load dropped from 33% to negligible, confirming the
  announce signature cache is working as intended.
- **Peer count grew**: 39 → 59 unique peers with no resource pressure.
- **Two backbone peers down**: Craiova and thunderhost are unreachable —
  should be investigated or removed from config if permanently offline.
- **Statsd drop burst**: a one-time event, stats recording is unaffected, but
  the channel sizing and drop log rate-limiting are worth revisiting.
