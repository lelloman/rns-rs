# VPS Production Findings — 2026-03-25 (CPU profiling)

New deploy on VPS (`root@vps`), binary `rnsd 0.2.225-526c965`, running since
2026-03-24 21:52 UTC. System rebooted at 20:14 UTC the same day.

This report covers the **~10h uptime mark**, focused on an unexpectedly high
CPU usage discovered during a routine health check.

---

## 1. Service health

Both services active:
- `rnsd` — active (running), pid 3946, uptime ~10h
- `rns-statsd` — active (running), pid 4000, uptime ~10h

Listening on `0.0.0.0:4242` and `127.0.0.1:37429`.

System resources:
- CPU: 2× AMD EPYC-Milan cores
- Memory: 522 MiB used / 1.8 GiB total (1.3 GiB available)
- Swap: none
- Disk: 11 GiB / 77 GiB (15%)
- Load: 0.12 / 0.84 / 0.74
- `stats.db`: 152 MiB

---

## 2. Network state

- **39 unique peer IPs** connected on port 4242
- ~25 ESTABLISHED connections, ~15 FIN-WAIT (stale/closing)
- Network I/O since boot: 877 MB RX, 517 MB TX
- 2 peers with small send queues (234 bytes) — slow receivers, not stalled

---

## 3. `rns-statsd` restart storm

After the `rnsd` restart at 21:52, `rns-statsd` crash-looped **10 times** over
~5 minutes before successfully connecting:

```
rns-statsd: failed to load rns_statsd_pre_ingress at PreIngress: rpc call failed: failed to fill whole buffer
```

The [deploy runbook](vps-deploy-runbook.md) documents 1–2 retries as expected
during restart sequencing. 10 retries (~5 min) suggests `rnsd` took significantly
longer than expected to bring up the RPC listener — possibly delayed by the
initial announce flood from reconnecting peers.

---

## 4. Peer penalty activity

**~127 penalty events** across **~35 unique IPs** in 10 hours. Two categories:

| Reason | Count | Description |
|--------|-------|-------------|
| Repeated idle timeouts | ~110 | Peers connect then go idle immediately |
| Rapid silent reconnect churn | ~17 | Peers reconnecting in tight loops without data |

### 4.1 Instant escalation pattern

Several peers escalated through all penalty levels within seconds:

| Peer | Max level | Max ban duration | Reason |
|------|-----------|------------------|--------|
| `46.8.228.162` | 12 | 1,843,200s (~21d) | idle timeouts |
| `185.191.118.144` | 12 | 1,843,200s (~21d) | idle timeouts |
| `92.101.51.251` | 10 | 460,800s (~5d) | idle timeouts |
| `31.58.171.226` | 9 | 230,400s (~2.7d) | idle timeouts |

These are likely scanners or misconfigured clients that reconnect-and-idle in a
tight loop, triggering multiple penalty escalations within the same second. The
penalty system catches them, but each escalation step produces a separate WARN
log line, creating significant log noise.

### 4.2 Write stall event

One peer (connection 10017) stalled for 30 seconds (07:28:55–07:29:19),
producing **641 `backbone writer still stalled` warnings** (once per second)
before the stall timeout disconnected it. This single peer accounts for ~74% of
all warnings.

---

## 5. CPU profiling — the main finding

### 5.1 The problem

`rnsd` is consuming **33.4% of total CPU** (1/3 of one core, sustained over 10h).
On a 2-core VPS, this is 1/6 of total capacity — unexpectedly high for a routing
daemon.

### 5.2 Per-thread breakdown

```
  SPID   %CPU  TIME       THREAD
  3963   15.9  01:34:58   rns-driver
  3962   15.9  01:34:59   rns-driver
  3960    0.8  00:05:19   rns-driver
  3950    0.4  00:02:51   provider-bridge
  3952    0.3  00:01:50   backbone-poll-1
  3959    0.0  00:00:15   rpc-server
  ...    (all others <0.1%)
```

Two `rns-driver` threads dominate, each at 15.9%. Together they account for
virtually all of `rnsd`'s CPU usage.

### 5.3 Perf profile (5-second sample, 676 samples)

| Overhead | Symbol | Context |
|----------|--------|---------|
| 8.87% | `FieldElement2625x4::Mul` | curve25519 field multiplication |
| 2.28% | `AnnounceQueues::process_queues` | announce queue tick |
| 2.20% | `FieldElement2625x4::square_and_negate_D` | curve25519 point doubling |
| 1.54% | `FieldElement51::pow2k` | curve25519 field exponentiation |

The top call chain is:

```
Driver::run
  → TransportEngine::tick
    → AnnounceQueues::process_queues
      → EdwardsPoint::vartime_double_scalar_mul_basepoint  (signature verification)
        → FieldElement2625x4::Mul / square_and_negate_D / ...
```

### 5.4 Root cause

**The CPU is dominated by Ed25519 signature verification on inbound announces.**

The node receives announces from 39 peers, many forwarding the same destinations
at different hop counts. The logs show duplicate announces arriving for the same
destination hash within the same second (e.g., `f017bda3..` at hops 4, 5, 6 all
within 07:41:00). Each copy triggers a full cryptographic signature verification.

---

## 6. Possible mitigations

Three approaches to reduce announce verification CPU:

1. **Deduplicate before verifying** — if an announce with the same destination
   hash has already been validated recently, skip re-verification for subsequent
   copies. This is the highest-impact change since the logs show heavy
   duplication.

2. **Cache validated signatures** — maintain a bounded LRU of recently verified
   `(destination, announce_hash)` pairs. Subsequent arrivals of the same announce
   become a cheap hash lookup instead of a curve25519 operation.

3. **Rate-limit per-destination verification** — once a destination has been
   verified within a time window (e.g., the last N seconds), defer or drop
   additional announces for it.

Approach 1 and 2 are essentially the same idea at different layers. The key
insight is that on a well-connected node, **the same announce arrives N times
(once per peer) but only needs to be verified once**.

---

## 7. Warning log noise

Total warnings in 10h: **868**.

| Category | Count | Source |
|----------|-------|--------|
| Backbone writer stall (1 peer) | 641 | 30s of per-second warnings before disconnect |
| Peer penalties | ~127 | Instant escalation through multiple levels |
| Other | ~100 | Miscellaneous |

Two improvements would significantly reduce log volume:
- **Stall warnings**: log once at start + once at disconnect, not every second
- **Penalty escalation**: batch rapid escalations into a single log line
  (e.g., "penalizing peer X: level 1→12, banned 21d")

---

## 8. Assessment

The VPS is **operationally healthy** — both services up, peers connected,
announces flowing, resources within limits.

The **CPU finding is the actionable item**: 33% of a 2-core VPS spent on
redundant signature verification is wasteful and will scale poorly as peer count
grows. An announce deduplication cache before the verification step would likely
cut this by an order of magnitude, since most announces arrive as N redundant
copies from N peers.

Secondary items (log noise from stalls and penalty escalation, `rns-statsd`
restart latency) are cosmetic but worth addressing.
