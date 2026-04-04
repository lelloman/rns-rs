# VPS Production Findings — 2026-04-04 (routine health check)

Binary `rnsd 0.2.306-ee60649`, running since `2026-04-03 20:30 UTC`
(`rnsd` / `rns-statsd` / `rns-sentineld` service restart). This report covers the
**~19.5 hour service uptime mark** for the current deploy.

Checks were collected on `2026-04-04 15:58-16:00 UTC` from the live VPS
(`root@vps`).

---

## 1. Service health

All three services were active at sample time:
- `rnsd` — active (running), pid `593677`
- `rns-statsd` — active (running), pid `593757`
- `rns-sentineld` — active (running), pid `593761`

Restart counters / start times:
- `rnsd`: `NRestarts=0`, active since `2026-04-03 20:30:48 UTC`
- `rns-statsd`: `NRestarts=0`, active since `2026-04-03 20:31:02 UTC`
- `rns-sentineld`: `NRestarts=0`, active since `2026-04-03 20:31:03 UTC`

Listening on:
- `0.0.0.0:4242` — public backbone entrypoint
- `127.0.0.1:37429` — RPC listener

`127.0.0.1:37428` was not present during this check. Per the deploy runbook,
that listener is optional.

Deployed versions:
- `rnsd 0.2.306-ee60649`
- `rns-statsd 0.2.306-ee60649`
- `rns-sentineld 0.2.306-ee60649`

Host identity / OS:
- hostname: `ubuntu`
- IPv4: `82.165.77.75`
- IPv6: `2a02:2479:99:7000::1`
- OS: Ubuntu `24.04.3 LTS`
- kernel: `6.8.0-106-generic`
- host uptime: `10 days, 19:43`

System resources:
- Memory: `644 MiB` used / `1.8 GiB` total (`1.2 GiB` available)
- Swap: none
- Disk: `8.2 GiB` / `77 GiB` (`11%`)
- Load: `0.03 / 0.06 / 0.12`
- `stats.db`: `355 MiB`
- `stats.db-wal`: `4.8 MiB`

Per-process memory / CPU sample (`ps`):
- `rnsd`: RSS ~`146 MiB`, CPU `4.2%`
- `rns-statsd`: RSS ~`6.4 MiB`, CPU `0.3%`
- `rns-sentineld`: below top-process cutoff at sample time

Systemd service accounting reported:
- `rnsd` current memory: `459.1 MiB`
- `rnsd` peak memory: `486.8 MiB`
- `rns-statsd` current memory: `82.6 MiB`
- `rns-statsd` peak memory: `96.0 MiB`
- `rns-sentineld` current memory: `1.4 MiB`
- `rns-sentineld` peak memory: `1.9 MiB`

Result / exit metadata:
- all three services reported `Result=success`
- `ExecMainCode=0`
- `ExecMainStatus=0`

---

## 2. Network state

- **72 established TCP connections** involving port `4242` at sample time

The public listener is currently exposed on:
- IPv4 `82.165.77.75/32`
- IPv6 `2a02:2479:99:7000::1/128`

This is a healthy live traffic level and is up from the `49` established
connections reported in the `2026-04-02` health check.

Archived and active system journals currently consume:
- `502.2 MiB`

This matters because journal rotation is already active and can hide earlier
startup context during retrospective checks.

---

## 3. Backbone interface status

`rns-ctl status` showed the transport instance running for `19h 28m` and the
named configured backbone peers all currently up:

| Interface | Status |
|-----------|--------|
| Public Entrypoint | **Up** — public listener active |
| Arg0net RNS-VPS Italy | **Up** |
| Berlin IPv4 | **Up** |
| RMAP World | **Up** |
| RNS.MichMesh.net ipv4 | **Up** |
| brn.ch.thunderhost.net | **Up** |

The live config at `/root/.reticulum/config` currently defines those five
outbound named peers plus the public listener. The previously reported
`RO_RetNet Craiova TCP` peer is not present in the live config sampled on
`2026-04-04`.

In addition to the named peers, `rns-ctl status` reported a large set of
dynamic `BackboneInterface/<id>` sessions on the public entrypoint, consistent
with the high established-connection count seen via `ss`.

---

## 4. Announce processing rates

Sampled from the live `rnsd` journal:

| Metric | Value |
|--------|-------|
| Announces validated (last 1 hour) | `29,365` (~`8.16/sec` avg) |
| Announces validated (last 24 hours) | `553,668` (~`6.41/sec` avg) |
| Dynamic interface registered (last 24 hours) | `12,380` |

Recent `rnsd` journal output during the live sample consisted of normal:
- `Announce:validated`
- `Announce received`
- dynamic interface connect/remove events on `Public Entrypoint`

Operationally, the backbone node is serving active traffic and continues to
participate in normal announce flow.

---

## 5. Sentinel activity

`rns-sentineld` looked materially healthier than in the `2026-04-02` report.

Observed behavior:
- `NRestarts=0` on the current uptime window
- `provider bridge disconnected` count in the last 24 hours: `0`
- no `failed to fill whole buffer` retry loop was seen in the sampled journal
- journal activity consisted primarily of normal blacklist enforcement

Recent sentinel output showed policy action such as:
- repeated idle-timeout blacklists
- repeated write-stall blacklists

The current backbone blacklist table is large and active:
- total entries: `336`
- entries with `connected_count > 0`: `66`
- entries with active timed blacklist (`blacklisted_remaining_secs != null`): `21`
- entries with `reject_count > 0`: `86`

This indicates the sentinel is not only alive but actively shaping bad peer
behavior on the public entrypoint.

---

## 6. `rns-statsd`

`rns-statsd` also looked healthier than in the `2026-04-02` report.

Observed during the check:
- `NRestarts=0` on the current uptime window
- `provider bridge dropped` warnings in the last hour: `0`
- the SQLite files were actively advancing during the session

Live file state:
- `/var/lib/rns/stats.db` — `372,330,496` bytes, updated `2026-04-04 15:58:54 UTC`
- `/var/lib/rns/stats.db-wal` — `5,014,072` bytes, updated `2026-04-04 15:59:14 UTC`
- `/var/lib/rns/stats.db-shm` — `32,768` bytes, updated `2026-04-04 15:59:14 UTC`

Database observations:
- `provider_drop_samples` currently contains `0` rows
- `process_samples` contains `342,316` rows
- latest `process_samples` rows were still being written at `2026-04-04 16:00:44 UTC`

Latest `process_samples` rows tracked the live `rnsd` process (`pid 593677`) at
roughly `149-150 MB` RSS with `18` threads and `~165-183` open file
descriptors.

So stats collection is clearly alive and persisting process telemetry. Unlike
the earlier April report, this check did not capture active provider-drop
warnings or persisted provider-drop samples.

---

## 7. Memory and runtime interpretation

The main remaining concern is still `rnsd` memory growth over uptime.

Recent `MEMSTATS` samples show steady growth within the current uptime window:

- `2026-04-03 22:10:49 UTC`: `rss_mb=87.7`, `smaps_anon_mb=77.2`
- `2026-04-04 14:10:54 UTC`: `rss_mb=136.9`, `smaps_anon_mb=132.0`
- `2026-04-04 15:55:55 UTC`: `rss_mb=142.0`, `smaps_anon_mb=137.2`

Other relevant `MEMSTATS` observations near the live sample:
- `vmdata_mb` rose to `372.5`
- `known_dest` rose to ~`6012`
- `path` rose to ~`5490`
- `hashlist` plateaued at `250000`
- `ann_q_entries` remained high, roughly `170k-178k`
- `ann_q_bytes` remained around `35-37 MB`

Interpretation:
- there is still a real upward RSS trend on the current deploy
- the growth is predominantly anonymous memory, not file-backed cache
- the host still has comfortable headroom right now, so this is not an
  immediate capacity incident

Compared with the `2026-04-02` report, the absolute `rnsd` memory level is
lower, but the monotonic-with-uptime growth pattern still deserves attention.

---

## 8. `rnsd` hook / provider bridge signals

The helper-process integration looks improved relative to `2026-04-02`, but it
is not perfectly quiet.

Counts collected during this check:
- `Broken pipe` warnings in `rnsd` over the last 24 hours: `46`
- `provider bridge dropped` warnings in `rns-statsd` over the last hour: `0`
- `provider bridge disconnected` warnings in `rns-sentineld` over the last 24 hours: `0`

The live Reticulum config still has:

```ini
provider_bridge = yes
provider_socket_path = /run/rns/provider.sock
provider_overflow_policy = drop_newest
# provider_queue_max_events: using default (16384)
# provider_queue_max_bytes: using default (8MB)
```

So the provider bridge is still enabled and using the newer default queue
sizes. The absence of recent sentinel disconnects and statsd drop warnings is a
good sign, but the residual `Broken pipe` count means the bridge/hook path
still shows some low-level noise.

---

## 9. Tooling / runbook drift

Two runbook-related mismatches were visible on the current host:

- `/usr/local/bin/rns-ctl backbone provider --json` is not available on the
  installed `rns-ctl`; the command reports `Unknown backbone subcommand:
  provider`
- `/usr/local/bin/rns-ctl interfaces` is also not available; the current tool
  uses `rns-ctl status`

This means parts of the existing VPS runbook are stale relative to the
currently deployed control binary and should be updated before the next operator
handoff.

---

## 10. Assessment

The VPS is **operational and notably healthier than the degraded state captured
on `2026-04-02`**.

Current state:
- `rnsd` is healthy enough to keep the public backbone online
- required listeners are present (`:4242`, `127.0.0.1:37429`)
- all currently configured named outbound peers were up during the check
- active backbone traffic is high (`72` established TCP sessions on `:4242`)
- announce processing remains strong over both 1-hour and 24-hour windows
- `rns-sentineld` is stable on the current uptime window and actively enforcing
  blacklist policy
- `rns-statsd` is stable on the current uptime window and still writing SQLite
  telemetry

Remaining concerns:
- `rnsd` RSS continues to climb steadily with uptime
- `rnsd` still logged `46` `Broken pipe` warnings over the last 24 hours
- operator docs no longer fully match the installed `rns-ctl` surface

So this deploy should be described as **stable but not fully cleared**:
the severe helper-process degradation seen on `2026-04-02` was not present in
this check, but memory-growth monitoring and provider-bridge observation should
continue on the current build.
