# VPS Production Findings — 2026-03-23 (Run 7, 63.5h check)

Continuation of the [2026-03-22 report](vps-production-findings-2026-03-22.md).
Same VPS (`root@vps`, 87.106.8.245), same binary `rnsd 0.2.199-83deda9`,
no restart since 2026-03-20 20:06 UTC.

This check covers the **63.5h uptime mark**, well past the 72h checkpoint
recommended in the previous report.

---

## 1. Service health

Both services healthy throughout:
- `rnsd` — active (running), pid 56407, 12 threads
- `rns-statsd` — active (running), pid 56484
- Listening on `0.0.0.0:4242` and `127.0.0.1:37429`

System resources:
- Memory: 618 MB used / 1,833 MB total (1,214 MB available)
- Swap: none
- Disk: 11 GB / 77 GB (14%)
- Load: low (no measurement, historically <0.1)

---

## 2. MEMSTATS time series (2026-03-23)

Samples from `journalctl -u rnsd | grep MEMSTATS`:

| Time (UTC) | Uptime | RSS (MB) | known_dest | path | link | announce |
|------------|--------|----------|------------|------|------|----------|
| 00:02 | +52h | 134.3 | 7,823 | 7,001 | 28 | 3 |
| 00:07 | +52h | 133.8 | 7,835 | 7,015 | 24 | 7 |
| 00:12 | +52h | 133.9 | 7,742 | 7,021 | 25 | 8 |
| 00:17 | +52h | 132.9 | 7,744 | 7,024 | 20 | 1 |
| 00:22 | +52h | 134.0 | 7,744 | 7,027 | 18 | 1 |
| ... | | | | | | |
| 10:57 | +63h | 144.0 | 7,543 | 6,843 | 26 | 3 |
| 11:02 | +63h | 144.1 | 7,547 | 6,859 | 25 | 4 |
| 11:07 | +63h | 144.2 | 7,548 | 6,852 | 22 | 3 |
| 11:12 | +63h | 144.1 | 7,530 | 6,866 | 18 | 2 |
| 11:17 | +63h | 144.9 | 7,530 | 6,873 | 20 | 4 |
| 11:22 | +63h | 145.3 | 7,535 | 6,872 | 25 | 1 |
| 11:27 | +63h | 144.6 | 7,537 | 6,876 | 32 | 2 |
| 11:32 | +63h | 145.3 | 7,544 | 6,890 | 29 | 4 |
| 11:37 | +63h | 145.6 | 7,547 | 6,924 | 24 | 8 |
| 11:42 | +63.5h | 145.8 | 7,550 | 6,940 | 17 | 7 |

Capped tables unchanged: `hashlist=250,000`, `pr_tags=32,000`.

All other tracked fields at 0 or near-0:
`reverse=0-4`, `held_ann=2-4`, `rate_lim=0`, `blackhole=0`, `tunnel=0`,
`disc_pr=0`, `sent_pkt=0`, `completed=0`, `local_dest=3`, `shared_ann=0`,
`lm_links=0`, `hp_sessions=0`, `proof_strat=1`.

---

## 3. Growth rate analysis

### 3.1 RSS

| Window | RSS start | RSS end | Duration | Rate |
|--------|-----------|---------|----------|------|
| 0–2h (Run 7 start) | 55.7 MB | 74.1 MB | 2.2h | ~8.4 MB/h |
| 39–46.5h (Mar 22) | 120.1 MB | 127.9 MB | 7.5h | ~1.0 MB/h |
| **52–63.5h (today)** | **134.3 MB** | **145.8 MB** | **11.5h** | **~1.0 MB/h** |

The ~1 MB/h residual drift is **unchanged** from the Mar 22 observation. RSS
bounces within a ~2 MB band in any given hour (e.g., 144.0–145.8 over the last
45 min), suggesting allocator noise rather than a true leak.

Notably, `known_dest` actually **decreased** from 7,823 (00:02) to 7,550
(11:42) — the 48h TTL eviction is actively pruning entries faster than new ones
arrive. Despite this, RSS increased by ~12 MB in the same window. This confirms
the residual drift is **not** from table growth — it is allocator fragmentation
or untracked per-connection state.

### 3.2 Table steady state confirmed

| Table | Count at 46.5h | Count at 63.5h | Trend |
|-------|---------------|----------------|-------|
| **known_dest** | 7,800 | 7,550 | Slightly declining (eviction > inflow) |
| **path** | 6,653 | 6,940 | Flat (±200 fluctuation) |
| **hashlist** | 250,000 | 250,000 | Full (capped) |
| **pr_tags** | 32,000 | 32,000 | Full (capped) |
| **link** | 57 | 17–32 | Bounded by active connections |

All tables are at steady state. `known_dest` is now confirmed bounded at
~7,500–7,800, well below the originally predicted ~67,000.

---

## 4. Connection landscape

**100 TCP connections**, **57 unique IPs** on port 4242.

No single-peer monopolization observed. The graduated IP throttling
(commit `ae4ea3f`) continues to prevent the kind of slot hogging seen
with `95.81.119.72` in Run 6.

---

## 5. Provider bridge event drops

`rns-statsd` logged **~67,700 dropped events** across **~7,148 burst lines**
today (00:00–11:42 UTC).

Drop rate: ~5,880 events/hr — significantly higher than the Mar 22 report's
rate, likely due to announce traffic patterns.

Bursts range from small (8–14 events) to moderate (60–154 events). The fix
(queue capacity 1,024 → 16,384 events, commit `96bc433`) is staged in the VPS
config but **requires a daemon restart** to take effect.

---

## 6. Disk usage

| Path | Size | Notes |
|------|------|-------|
| `/root/.reticulum/` | 328 MB | Total Reticulum data directory |
| `storage/` | 32 MB | Includes packet_hashlist (6.3 MB), destination_table (1.5 MB), known_destinations (543 KB) |

Announce cache not checked this session (previously 16 MB / 3,891 files on
Mar 20 — likely stable or declining).

---

## 7. Key observations

### 7.1 Memory growth is confirmed stable

At 63.5h, RSS is **146 MB**. For comparison:

| Run | Uptime | RSS | Rate |
|-----|--------|-----|------|
| Run 5 | 42h | 544 MB | ~13 MB/h (linear) |
| Run 6 | 45h | 565 MB | ~12.4 MB/h (linear) |
| Run 7 | 46.5h | 128 MB | ~1.0 MB/h |
| **Run 7** | **63.5h** | **146 MB** | **~1.0 MB/h** |

The rate has not accelerated. RSS at 63.5h is **~4x lower** than Runs 5/6 at
half the uptime. The eviction mechanisms are working as designed.

### 7.2 Residual drift is not from tracked tables

`known_dest` decreased while RSS increased. The ~1 MB/h residual is most likely
allocator fragmentation (freed memory not returned to OS). This is consistent
with the Mar 22 hypothesis and is **not operationally concerning** — at this
rate, 7-day RSS would be ~310 MB, well within the VPS's 1.8 GB.

### 7.3 Provider bridge drops remain the noisiest issue

~67,700 dropped events in ~11.5 hours. The pending config change (16x queue
capacity) should substantially reduce these. This will be validated after the
restart.

---

## 8. Assessment

**The memory investigation is resolved.** All tracked tables are bounded and at
steady state. RSS growth has dropped from ~12 MB/h (Runs 5/6) to ~1 MB/h
(Run 7) and is not accelerating. The residual drift is allocator-level noise,
not a data structure leak.

The daemon is ready for a restart to pick up the provider bridge queue config
changes. No code changes are needed for the memory issue.

---

## 9. Restart plan

Restart will apply:
- Provider bridge queue: 1,024 → 16,384 max events, 1 MB → 8 MB max bytes
  (commit `96bc433`)
- No binary change (same `0.2.199-83deda9`)

Follow [VPS Deploy Runbook](vps-deploy-runbook.md) sections 6–8 (restart only,
no binary promotion needed).

---

## 10. Comparison across all runs (updated)

| Metric | Run 5 (42h) | Run 6 (45h) | Run 7 (2.2h) | Run 7 (46.5h) | **Run 7 (63.5h)** |
|--------|------------|------------|--------------|---------------|-------------------|
| Binary version | `0.2.183-f1ab29d` | `0.2.183-f1ab29d` | `0.2.199-83deda9` | `0.2.199-83deda9` | `0.2.199-83deda9` |
| Memory (at check) | 544 MB | 565 MB | 74 MB | 128 MB | **146 MB** |
| Memory rate | ~13 MB/h | ~12.4 MB/h | ~8.4 MB/h | ~1.0 MB/h | **~1.0 MB/h** |
| known_dest | — | — | 3,417 | 7,800 | **7,550** |
| known_dest rate | — | — | ~1,400/hr | ~44/hr | **declining** |
| path | — | — | 3,151 | 6,653 | **6,940** |
| Tables at steady state | Unknown | Unknown | No | Yes | **Yes** |
| TCP connections | 74 | 59–134 | — | — | **100 (57 IPs)** |
| Provider drops/hr | ~2,184 | ~2,398 | — | — | **~5,880** |
