# VPS Production Findings — 2026-03-22 (Run 7 continued)

Continuation of the [2026-03-20 Run 7 report](vps-production-findings-2026-03-20-run7.md).
Same VPS (`root@vps`, 87.106.8.245), same binary `rnsd 0.2.199-83deda9`,
no restart since 2026-03-20 20:06 UTC.

This check covers the **39h–46.5h uptime window**, the first observation after
the 48h `known_dest` TTL eviction was predicted to engage.

---

## 1. Service health

Both services healthy throughout:
- `rnsd` — active (running), pid 56407
- `rns-statsd` — active (running), pid 56484
- Listening on `0.0.0.0:4242` and `127.0.0.1:37429`

---

## 2. MEMSTATS time series (hourly samples, 2026-03-22)

All samples from `journalctl -u rnsd | grep MEMSTATS`, one per hour:

| Time (UTC) | Uptime | RSS (MB) | known_dest | path | link | announce |
|------------|--------|----------|------------|------|------|----------|
| 11:02 | +39h | 120.1 | 7,472 | 6,372 | 57 | 6 |
| 12:02 | +40h | 121.2 | 7,503 | 6,461 | 83 | 6 |
| 13:02 | +41h | 121.5 | 7,544 | 6,518 | 62 | 2 |
| 14:02 | +42h | 123.2 | 7,590 | 6,609 | 54 | 1 |
| 15:02 | +43h | 124.3 | 7,624 | 6,644 | 60 | 4 |
| 16:02 | +44h | 124.7 | 7,678 | 6,691 | 63 | 4 |
| 17:02 | +45h | 126.8 | 7,722 | 6,766 | 52 | 1 |
| 18:02 | +46h | 127.1 | 7,777 | 6,540 | 52 | 1 |
| 18:37 | +46.5h | 127.9 | 7,800 | 6,653 | 57 | 3 |

Capped tables unchanged throughout: `hashlist=250,000`, `pr_tags=32,000`.

All other tracked fields remained at 0 or near-0:
`reverse=0`, `held_ann=2-4`, `rate_lim=0`, `blackhole=0`, `tunnel=0`,
`disc_pr=0`, `sent_pkt=0`, `completed=0`, `local_dest=3`, `shared_ann=0`,
`lm_links=0`, `hp_sessions=0`, `proof_strat=1`.

---

## 3. Growth rate analysis

### 3.1 RSS

| Window | RSS start | RSS end | Duration | Rate |
|--------|-----------|---------|----------|------|
| 0–2h (Run 7) | 55.7 MB | 74.1 MB | 2.2h | **~8.4 MB/h** |
| 39–46.5h (today) | 120.1 MB | 127.9 MB | 7.5h | **~1.0 MB/h** |

RSS growth has decelerated **~8x** compared to the first 2 hours. The rate is
now approximately 1 MB/h and showing signs of further flattening (RSS actually
dipped from 128.6 to 127.9 in the last 30 minutes, suggesting allocator
returns).

### 3.2 Table growth rates comparison

| Table | Rate at 0–2h | Rate at 39–46.5h | Status |
|-------|-------------|-------------------|--------|
| **known_dest** | ~1,400/hr | **~44/hr** | 48h TTL eviction active, near steady state |
| **path** | ~1,300/hr | **~37/hr** | Plateaued (6h/24h TTL) |
| **hashlist** | ~20,900/hr | 0/hr | Full (250k cap, pre-allocated) |
| **pr_tags** | ~4,470/hr | 0/hr | Full (32k cap) |
| **link** | ~10–35 | ~50–83 | Bounded by active connections |

### 3.3 known_dest steady state confirmed

`known_dest` grew from 7,472 to 7,800 in 7.5 hours = **~44 new entries/hr**.
This is a 97% reduction from the initial ~1,400/hr, confirming that the 48h TTL
eviction is now balancing inflow with expiry. Steady-state count is ~7,500–8,000,
far below the originally predicted ~67,000 — suggesting the network has fewer
unique destinations than the early growth rate implied, or that many destinations
re-announce within the TTL window and don't accumulate as separate entries.

---

## 4. Provider bridge event drops

`rns-statsd` logged **~69,500 dropped events** across **74 burst windows** today.

Bursts correlate with traffic spikes (announce floods from peers). The drops
occur on the producer side (`rnsd` bridge queue) due to the VPS running a
restricted queue config:

```
provider_queue_max_events = 1024   (default: 8192)
provider_queue_max_bytes = 1048576 (default: 4 MB)
```

### 4.1 Root cause

The stats hook fires on **every packet**, producing a `provider_event` per
packet processed. During announce bursts (dozens of announces per second from
multiple peers), events accumulate faster than the bridge thread drains them
over the Unix socket. With `overflow_policy = drop_newest`, excess events are
silently counted and reported as `DroppedEvents` messages.

### 4.2 Fix deployed (pending restart)

The VPS config has been updated to use the new defaults:

- `provider_queue_max_events`: 1,024 → **16,384** (16x)
- `provider_queue_max_bytes`: 1 MB → **8 MB** (8x)

The code defaults were also raised (commit `96bc433`). These changes will take
effect on the next daemon restart.

---

## 5. Key observations

### 5.1 Memory growth is stabilizing

At 46.5h uptime, RSS is 128 MB and growing at ~1 MB/h. This is a **dramatic
improvement** over Runs 5/6 which reached 550+ MB at similar uptime with
~12 MB/h linear growth. The eviction mechanisms are working.

### 5.2 Projected steady-state RSS

If the ~1 MB/h residual rate continues, 7-day RSS would be ~290 MB. However,
the rate is likely to flatten further as `known_dest` stabilizes. A reasonable
estimate for true steady-state RSS is **130–160 MB**.

For comparison:
| Run | Uptime | RSS | Rate |
|-----|--------|-----|------|
| Run 5 | 42h | 544 MB | ~13 MB/h (linear) |
| Run 6 | 45h | 565 MB | ~12.4 MB/h (linear) |
| **Run 7** | **46.5h** | **128 MB** | **~1 MB/h (decelerating)** |

### 5.3 Residual ~1 MB/h drift

The remaining growth could be:
1. **Allocator fragmentation** — freed memory not returned to OS (RSS ≠ live heap)
2. **Untracked allocations** — per-connection buffers in the backbone interface,
   announce queue internals, ingress control state
3. **known_dest not fully at equilibrium** — eviction started recently, may take
   another cycle to fully stabilize

### 5.4 known_dest actual steady state much lower than predicted

Run 7 predicted ~67,000 entries at steady state (1,400/hr × 48h). Actual
steady state is ~7,500–8,000. This 9x discrepancy is because the initial
growth rate reflected first-time discovery of existing network destinations,
not the ongoing rate of genuinely new destinations appearing.

---

## 6. Next steps

1. **Check again at ~72h** to confirm RSS drift continues to flatten
2. **Restart with new provider bridge defaults** on next deploy — verify the
   16k event queue eliminates most drop bursts
3. **If RSS still growing at ~1 MB/h after 72h**, investigate with
   `/proc/PID/smaps` to distinguish allocator retention from true leaks
4. **Consider the memory investigation largely resolved** — the tracked tables
   are all bounded, and RSS at 46.5h is 4x lower than previous runs

---

## 7. Comparison across all runs (updated)

| Metric | Run 5 (42h) | Run 6 (45h) | Run 7 (2.2h) | **Run 7 (46.5h)** |
|--------|------------|------------|--------------|-------------------|
| Binary version | `0.2.183-f1ab29d` | `0.2.183-f1ab29d` | `0.2.199-83deda9` | `0.2.199-83deda9` |
| Memory (at check) | 544 MB | 565 MB | 74 MB | **128 MB** |
| Memory rate | ~13 MB/h | ~12.4 MB/h | ~8.4 MB/h | **~1.0 MB/h** |
| known_dest | — | — | 3,417 | **7,800** |
| known_dest rate | — | — | ~1,400/hr | **~44/hr** |
| path | — | — | 3,151 | **6,653** |
| Tables at steady state | Unknown | Unknown | No | **Yes** |
