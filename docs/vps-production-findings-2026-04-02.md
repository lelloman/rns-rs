# VPS Production Findings — 2026-04-02 (routine health check)

Binary `rnsd 0.2.246-0eddcf1`, running since `2026-03-27 15:06 UTC`
(`rnsd` / `rns-statsd` service restart). This report covers the **~6 day 3h
service uptime mark** for the main daemon.

Checks were collected on `2026-04-02 18:32 UTC` from the live VPS
(`root@vps`).

---

## 1. Service health

All three services active at sample time:
- `rnsd` — active (running), pid 252168
- `rns-statsd` — active (running), pid 252261
- `rns-sentineld` — active (running), pid 551474

Restart counters / start times:
- `rnsd`: `NRestarts=0`, active since `2026-03-27 15:06:00 UTC`
- `rns-statsd`: `NRestarts=0`, active since `2026-03-27 15:06:13 UTC`
- `rns-sentineld`: `NRestarts=2`, active since `2026-04-02 18:29:42 UTC`

Listening on:
- `0.0.0.0:4242` — public backbone entrypoint
- `127.0.0.1:37429` — RPC listener

`127.0.0.1:37428` was not present during this check. Per the deploy runbook,
that listener is optional.

Host identity / OS:
- hostname: `ubuntu`
- IPv4: `82.165.77.75`
- IPv6: `2a02:2479:99:7000::1`
- OS: Ubuntu `24.04.3 LTS`
- kernel: `6.8.0-106-generic`

System resources:
- Memory: `873 MiB` used / `1.8 GiB` total (`960 MiB` available)
- Swap: none
- Disk: `7.8 GiB` / `77 GiB` (`11%`)
- Load: `0.05 / 0.31 / 0.45`
- `stats.db`: `323 MiB`
- `stats.db-wal`: `11 MiB`

Per-process memory / CPU sample (`ps`):
- `rnsd`: RSS ~`346 MiB`, CPU `4.0%`
- `rns-statsd`: RSS ~`8 MiB`, CPU `0.3%`
- `rns-sentineld`: RSS below top-process cutoff at sample time, CPU negligible

Systemd service accounting reported:
- `rnsd` current memory: `636.4 MiB`
- `rnsd` peak memory: `779.8 MiB`
- `rns-statsd` current memory: `75.5 MiB`
- `rns-statsd` peak memory: `90.9 MiB`
- `rns-sentineld` current memory: `260 KiB`
- `rns-sentineld` peak memory: `772 KiB`

---

## 2. Network state

- **49 established TCP connections** involving port 4242 at sample time

This is up from the 2026-04-01 report (`43` established TCP connections on
port 4242), so the public listener is still serving active backbone traffic
with dozens of peers.

The public listener is currently exposed on host IPv4 `82.165.77.75`. Older
reports referenced `87.106.8.245`; the live host now reports `82.165.77.75`
via DHCP on `ens6`.

---

## 3. Backbone interface status

The config still appears to define 1 listening interface and 6 outbound
backbone connections.

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

Change since 2026-04-01:
- MichMesh remains connected over IPv6.
- Craiova remains down.
- The other four outbound peers remain established.

---

## 4. Announce processing rates

Sampled from the live `rnsd` journal:

| Metric | Value |
|--------|-------|
| Announces validated (last 1 min) | `0` |
| Announces validated (last 5 min) | `138` (~`0.46/sec` avg) |
| Announces validated (last 1 hour) | `5,226` (~`1.45/sec` avg) |
| Announces validated (last 24 hours) | `573,958` (~`6.64/sec` avg) |

Announce flow is still healthy over the 1-hour and 24-hour windows, but the
instantaneous rates during this sample were far lower than the bursty 2026-04-01
window.

Recent live journal output still contained normal `Announce:validated` and
`Announce received` lines, alongside hook/provider warnings described below.

---

## 5. Sentinel activity

This is the main degraded area in the current check.

Observed behavior:
- `rns-sentineld` exited twice in the last 24 hours
- both exits were preceded by blacklist RPC failures
- both exits ended with `provider bridge disconnected`
- after restart, the process spent long periods retrying RPC hook loads with
  `failed to fill whole buffer`

Relevant recent sequence:
- `2026-04-02 17:45:29 UTC` — `rns-sentineld` exited, restart counter -> `1`
- `2026-04-02 18:29:37 UTC` — `rns-sentineld` exited again, restart counter -> `2`
- `2026-04-02 18:29:42 UTC` — systemd restarted `rns-sentineld`

Recent sentinel output still showed policy action when the bridge was up:
- blacklisted `91.132.135.16` for repeated idle timeouts at `2026-04-02 18:26:44 UTC`

But operationally, the sentinel is no longer in the clean stable state seen on
2026-04-01.

---

## 6. `rns-statsd`

`rns-statsd` remains alive and the database is still advancing, but its logs now
show clear provider-bridge degradation.

Observed during the check:
- repeated `provider bridge dropped N event(s)` warnings
- `32,162` such warnings counted in the last hour
- `/var/lib/rns/stats.db` and WAL timestamps both advanced during the session

Live file state:
- `/var/lib/rns/stats.db` — `337,997,824` bytes, updated `2026-04-02 18:29:04 UTC`
- `/var/lib/rns/stats.db-wal` — `10,633,752` bytes, updated `2026-04-02 18:32:24 UTC`
- `/var/lib/rns/stats.db-shm` — `32,768` bytes, updated `2026-04-02 18:32:08 UTC`

So stats collection is degraded rather than dead: the process is running and
SQLite activity is continuing, but event delivery from the provider bridge is
dropping heavily.

---

## 7. Memory and runtime interpretation

Memory usage increased again relative to the 2026-04-01 report:

- host used memory: `797 MiB` -> `873 MiB`
- `rnsd` RSS: ~`276 MiB` -> ~`346 MiB`
- `rnsd` systemd `MemoryCurrent`: `605.7 MiB` -> `636.4 MiB`
- `stats.db`: ~`276 MiB` -> `323 MiB`
- `stats.db-wal`: `5.0 MiB` -> `11 MiB`

This is continued real growth, although the host still has comfortable headroom:

- ~`960 MiB` remains available
- swap is disabled but not currently needed
- load is still low
- `rnsd` itself has not restarted

Recent `MEMSTATS` samples from `rnsd` were in the `336`-`373 MiB` RSS range,
with tracked table counts staying broadly stable:

- `known_dest` around `9.5k`
- `path` around `9.1k`
- `hashlist` fixed at `250000`
- `ann_verify_q` usually `256`, briefly dropping to `1` in one sample

The new operational wrinkle is not just memory drift but provider-bridge churn
between `rnsd` and its helper processes.

---

## 8. `rnsd` hook / provider bridge signals

`rnsd` remained up throughout the check, but its journal shows correlated
instability with the helper processes:

- `Broken pipe` warnings on hook sends
- hook unload messages such as:
  - `Unloaded hook 'rns_sentinel_peer_connected'`
  - `Unloaded hook 'rns_sentinel_peer_disconnected'`
  - `Unloaded hook 'rns_sentinel_peer_idle_timeout'`
  - `Unloaded hook 'rns_sentinel_peer_write_stall'`
  - `Unloaded hook 'rns_sentinel_peer_penalty'`
- dynamic interface remove/register events around the same periods

24-hour counts:
- `Announce:validated`: `573,958`
- `dynamic interface registered`: `4,020`
- `Broken pipe`: `2,696`

This points to a helper-process integration problem rather than a full daemon
failure: `rnsd` kept serving peers and processing announces, but the hook/event
path to `rns-sentineld` and `rns-statsd` was noisy and partially failing.

---

## 9. Assessment

The VPS is **partially degraded but still operational**.

Current state:
- `rnsd` is healthy enough to keep the public backbone online
- required listeners are present (`:4242`, `127.0.0.1:37429`)
- 5 of 6 configured outbound backbone peers are currently connected
- Craiova remains down
- announce processing remains active over 1-hour and 24-hour windows
- memory and `stats.db` growth both continued upward

The main concern has shifted from pure memory drift to helper-process stability:

- `rns-sentineld` restarted twice today and is not maintaining a stable bridge
- `rns-statsd` stayed up but is dropping large numbers of provider-bridge events
- `rnsd` logs show corresponding `Broken pipe` and hook-unload churn

So the node is still serving traffic, but the current deploy should not be
described as fully healthy. The next step should focus on the provider-bridge /
hook path between `rnsd` and the auxiliary processes before the degraded state
turns into a broader operational failure.
