# VPS Investigation Brief — 2026-04-02

This document captures the information needed to investigate the remaining
production issues after the provider-bridge / hook-path root problem (#1) was
considered solved.

Open investigations covered here:

1. `rns-sentineld` restarts
2. `rns-statsd` provider-bridge degradation
3. `rnsd` memory growth

Scope note:
- This is an investigation brief, not a root-cause conclusion.
- It separates confirmed facts from hypotheses.
- It records the exact code paths, live config, and missing evidence needed for
  a defensible diagnosis.

---

## 1. Shared runtime context

### 1.1 Live VPS state at capture time

Sampled on `2026-04-02 18:32 UTC` from `root@vps`.

Deployed versions:
- `rnsd 0.2.246-0eddcf1`
- `rns-statsd 0.2.246-0eddcf1`
- `rns-sentineld 0.2.246-0eddcf1`

Service state:
- `rnsd`: active since `2026-03-27 15:06:00 UTC`, `NRestarts=0`
- `rns-statsd`: active since `2026-03-27 15:06:13 UTC`, `NRestarts=0`
- `rns-sentineld`: active since `2026-04-02 18:29:42 UTC`, `NRestarts=2`

Listeners:
- `0.0.0.0:4242`
- `127.0.0.1:37429`

Host:
- Ubuntu `24.04.3 LTS`
- kernel `6.8.0-106-generic`
- IPv4 `82.165.77.75`

### 1.2 Live `rnsd` config relevant to these issues

The current live config file is `/root/.reticulum/config`.

Relevant settings observed on the VPS:

```ini
[reticulum]
provider_bridge = yes
provider_socket_path = /run/rns/provider.sock
provider_overflow_policy = drop_newest
# provider_queue_max_events: using default (16384)
# provider_queue_max_bytes: using default (8MB)
```

Implications:
- provider events are enabled in `rnsd`
- both sidecars consume from the same Unix socket path
- overflow policy is explicitly `drop_newest`
- the VPS is using the newer larger queue defaults, not the older reduced
  queue settings documented in March

### 1.3 Main code paths

Provider bridge producer / queueing:
- [rns-net/src/provider_bridge.rs](/home/lelloman/lelloprojects/rns-rs/rns-net/src/provider_bridge.rs)

`rns-sentineld` runtime:
- [rns-cli/src/sentineld.rs](/home/lelloman/lelloprojects/rns-rs/rns-cli/src/sentineld.rs)

`rns-statsd` runtime:
- [rns-cli/src/statsd.rs](/home/lelloman/lelloprojects/rns-rs/rns-cli/src/statsd.rs)

`rnsd` MEMSTATS instrumentation and runtime config exposure:
- [rns-net/src/driver.rs](/home/lelloman/lelloprojects/rns-rs/rns-net/src/driver.rs)

Historical production evidence:
- [docs/vps-production-findings-2026-03-16.md](/home/lelloman/lelloprojects/rns-rs/docs/vps-production-findings-2026-03-16.md)
- [docs/vps-production-findings-2026-03-22.md](/home/lelloman/lelloprojects/rns-rs/docs/vps-production-findings-2026-03-22.md)
- [docs/vps-production-findings-2026-03-25.md](/home/lelloman/lelloprojects/rns-rs/docs/vps-production-findings-2026-03-25.md)
- [docs/vps-production-findings-2026-04-02.md](/home/lelloman/lelloprojects/rns-rs/docs/vps-production-findings-2026-04-02.md)

---

## 2. Issue: `rns-sentineld` restarts

### 2.1 Confirmed facts

Observed on the VPS on `2026-04-02`:
- `rns-sentineld` exited twice
- both exits were preceded by RPC/hook trouble
- both exits ended with `provider bridge disconnected`
- after restart, it repeatedly logged:
  `waiting for rnsd RPC: failed to load ... rpc call failed: failed to fill whole buffer`

Relevant journal sequence:
- `17:45:03 UTC`: `blacklist RPC failed ... failed to fill whole buffer`
- `17:45:29 UTC`: `provider bridge disconnected`
- systemd restart counter -> `1`
- `18:29:06 UTC`: `blacklist RPC failed ... failed to fill whole buffer`
- `18:29:37 UTC`: `provider bridge disconnected`
- systemd restart counter -> `2`

What did *not* happen:
- `rnsd` did not restart
- the public listener and RPC listener remained up

### 2.2 Relevant implementation details

`rns-sentineld` behavior from [rns-cli/src/sentineld.rs](/home/lelloman/lelloprojects/rns-rs/rns-cli/src/sentineld.rs):

- It loads 5 hook names:
  - `rns_sentinel_peer_connected`
  - `rns_sentinel_peer_disconnected`
  - `rns_sentinel_peer_idle_timeout`
  - `rns_sentinel_peer_write_stall`
  - `rns_sentinel_peer_penalty`
- Startup order:
  1. resolve runtime config
  2. wait for hooks to load through RPC
  3. connect to provider socket
  4. mark ready
- Main loop behavior:
  - reads provider envelopes from Unix socket
  - on read timeout: keep going
  - on any other socket read error:
    - logs `provider bridge disconnected`
    - retries hook loading
    - reconnects to provider socket
- The process exits non-zero if `run()` returns `Err(...)`
- Top-level `main_entry_from()` converts that into process exit code `1`

Important consequence:
- the string `provider bridge disconnected` in the journal is not itself a
  crash; it is only a warning on the reconnect path
- if the process exits after that warning, some subsequent retry step is
  returning `Err(...)` instead of looping successfully

### 2.3 What is still unknown

We do not yet know which exact call is causing `run()` to return an error:

- `wait_for_loaded_hooks(...)`
- `wait_for_provider_bridge(...)`
- readiness file / startup side effect
- blacklist worker submission path
- blacklist RPC operation itself returning a fatal error indirectly
- a panic path not visible in the sampled logs

We also do not yet know whether the immediate trigger is:
- Unix socket disconnect semantics from the provider bridge thread
- malformed / partial frame handling on the sidecar read path
- an RPC server problem in `rnsd`
- a side effect of hook unload/reload ordering

### 2.4 Minimum evidence needed for a proper diagnosis

Need to capture, at the time of failure:

1. Full `journalctl -u rns-sentineld --since ...` around one crash with enough
   prelude to see the first failing operation, not just the final disconnect line.
2. Matching `journalctl -u rnsd --since ...` in the same time window.
3. A precise exit reason from systemd:
   - `ExecMainStatus`
   - `ExecMainCode`
   - `Result`
4. Whether the process printed an `eprintln!("rns-sentineld: ...")` line on exit.
5. If possible, a local reproduction with `RUST_LOG=debug` for:
   - hook load / unload
   - provider socket connect / disconnect
   - blacklist RPC attempts

### 2.5 Concrete repo-side questions to answer

1. Under what exact conditions can `wait_for_loaded_hooks()` return a hard
   error instead of retrying forever?
2. Under what exact conditions can `wait_for_provider_bridge()` return a hard
   error instead of retrying forever?
3. Are there any code paths in the blacklist worker thread that propagate a
   fatal error back into `run()`?
4. Can partial provider frames or invalid bincode payloads surface as
   non-recoverable errors?
5. Does `HookGuard::drop()` interact badly with reconnect / hook reload cycles?

### 2.6 Most relevant files

- [rns-cli/src/sentineld.rs](/home/lelloman/lelloprojects/rns-rs/rns-cli/src/sentineld.rs)
- [rns-net/src/provider_bridge.rs](/home/lelloman/lelloprojects/rns-rs/rns-net/src/provider_bridge.rs)
- [rns-net/src/driver.rs](/home/lelloman/lelloprojects/rns-rs/rns-net/src/driver.rs)

---

## 3. Issue: `rns-statsd` provider-bridge degradation

### 3.1 Confirmed facts

Observed on the VPS on `2026-04-02`:
- `rns-statsd` remained up
- SQLite files continued to advance
- it logged heavy bridge-drop warnings
- count measured during the check:
  - `32,162` `provider bridge dropped N event(s)` warnings in the last hour

Historical context:
- dropped provider events have been a known problem since at least
  `2026-03-16`
- earlier reports attributed this to provider queue saturation
- queue defaults were later increased from the earlier restricted VPS settings
- despite that, drops are still happening in April on the current build

### 3.2 Relevant implementation details

`rns-statsd` behavior from [rns-cli/src/statsd.rs](/home/lelloman/lelloprojects/rns-rs/rns-cli/src/statsd.rs):

- It loads 3 hooks:
  - `rns_statsd_pre_ingress`
  - `rns_statsd_send_on_interface`
  - `rns_statsd_broadcast_all`
- It consumes `ProviderEnvelope` from the Unix provider socket
- On `ProviderMessage::DroppedEvents { count }`, it only logs a warning
- Dropped-event counts are now also persisted to SQLite in
  `provider_drop_samples`
- It flushes aggregates to SQLite every 5 seconds by default
- It also inserts a local process sample into SQLite on each flush

Provider bridge behavior from [rns-net/src/provider_bridge.rs](/home/lelloman/lelloprojects/rns-rs/rns-net/src/provider_bridge.rs):

- each connected consumer gets its own queue
- queue pressure is bounded by:
  - `queue_max_events`
  - `queue_max_bytes`
- overflow handling:
  - `DropNewest`: incoming events are discarded once limits are hit
  - dropped events are coalesced into a later `DroppedEvents { count }` message
- consumer stream write timeout is 1 second
- on write failure, the consumer is disconnected

Important consequence:
- repeated `provider bridge dropped` warnings do not necessarily mean the Unix
  socket disconnected
- they mean the producer could not keep the per-consumer queue within the
  configured bounds for that consumer

### 3.3 What is still unknown

We do not yet know which of these is dominant:

1. `rns-statsd` is too slow to consume the provider socket stream.
2. `rns-statsd` consumes fast enough, but SQLite flush / aggregation work makes
   it fall behind during bursts.
3. Event volume itself is simply too high for the current queue sizes.
4. The per-consumer queue is being monopolized by one class of events
   (`PreIngress` announce storms, TX fan-out, etc.).
5. The drop count is mostly noise from short bursts and does not materially
   affect the stats the product actually needs.

### 3.4 Minimum evidence needed for a proper diagnosis

Need to measure, not guess:

1. Drop rate over time, not just log-line count:
   - total dropped events per minute/hour
   - burst size distribution
2. Event mix by hook:
   - `PreIngress`
   - `SendOnInterface`
   - `BroadcastOnAllInterfaces`
3. SQLite flush latency distribution:
   - average
   - p95
   - worst-case during announce bursts
4. Consumer lag / queue depth visibility:
   - current queue size
   - current queued bytes
   - dropped count before emission
   - disconnect count
5. End-user impact:
   - which stats become inaccurate when drops happen
   - whether packet counters and announce history remain “good enough”

### 3.5 Concrete repo-side questions to answer

1. Is the provider bridge exposing enough counters to diagnose queue pressure,
   or do we need additional metrics beyond the currently exposed:
   - per-consumer queue depth
   - per-consumer queued bytes
   - per-consumer pending dropped count
   - per-consumer total dropped count
   - backlog dropped count
   - disconnect count
2. Is the new `provider_drop_samples` history granular enough to support
   diagnosis, or do we also need per-consumer / per-hook persisted loss?
3. Does `rns-statsd` need batch limits or event coalescing before SQLite flush?
4. Are all three hook streams necessary on the VPS, or can one be disabled to
   reduce event volume?
5. Are the current defaults (`16384`, `8 MB`, `drop_newest`) actually adequate
   for a public backbone node?

### 3.6 Most relevant files

- [rns-cli/src/statsd.rs](/home/lelloman/lelloprojects/rns-rs/rns-cli/src/statsd.rs)
- [rns-net/src/provider_bridge.rs](/home/lelloman/lelloprojects/rns-rs/rns-net/src/provider_bridge.rs)
- [rns-stats-hook/src/lib.rs](/home/lelloman/lelloprojects/rns-rs/rns-stats-hook/src/lib.rs)
- [docs/vps-production-findings-2026-03-16.md](/home/lelloman/lelloprojects/rns-rs/docs/vps-production-findings-2026-03-16.md)
- [docs/vps-production-findings-2026-03-22.md](/home/lelloman/lelloprojects/rns-rs/docs/vps-production-findings-2026-03-22.md)

---

## 4. Issue: `rnsd` memory growth

### 4.1 Confirmed facts

By `2026-04-02`, compared with `2026-04-01`:
- host used memory: `797 MiB` -> `873 MiB`
- `rnsd` RSS from `ps`: ~`276 MiB` -> ~`346 MiB`
- `rnsd` systemd `MemoryCurrent`: `605.7 MiB` -> `636.4 MiB`
- `stats.db`: ~`276 MiB` -> `323 MiB`
- `stats.db-wal`: `5.0 MiB` -> `11 MiB`

On the live host during the April 2 check:
- `rnsd` `MEMSTATS` samples were roughly `336`-`373 MiB` RSS
- tracked table counts were broadly stable:
  - `known_dest` around `9.5k`
  - `path` around `9.1k`
  - `hashlist` `250000`
  - `ann_verify_q` usually `256`

Historical context:
- March runs showed that earlier catastrophic memory growth was improved by
  bounding / cleaning some tracked structures
- but the residual drift never fully disappeared
- March docs already called out the possibility of untracked memory, allocator
  retention, or filesystem cache

### 4.2 Relevant implementation details

`MEMSTATS` from [rns-net/src/driver.rs](/home/lelloman/lelloprojects/rns-rs/rns-net/src/driver.rs) already logs:

- process memory:
  - `rss_mb`
  - `vmrss_mb`
  - `vmhwm_mb`
  - `vmdata_mb`
  - `vmswap_mb`
- `/proc/*/smaps`-derived fields:
  - `smaps_rss_mb`
  - `smaps_anon_mb`
  - `smaps_file_est_mb`
  - `smaps_shared_clean_mb`
  - `smaps_shared_dirty_mb`
  - `smaps_private_clean_mb`
  - `smaps_private_dirty_mb`
  - `smaps_swap_mb`
- tracked in-process collections:
  - `known_dest`
  - `path`
  - `announce`
  - `reverse`
  - `link`
  - `held_ann`
  - `hashlist`
  - `sig_cache`
  - `ann_verify_q`
  - `rate_lim`
  - `blackhole`
  - `tunnel`
  - `pr_tags`
  - `disc_pr`
  - `sent_pkt`
  - `completed`
  - `local_dest`
  - `shared_ann`
  - `lm_links`
  - `hp_sessions`
  - `proof_strat`

Important consequence:
- the memory investigation should start by using the fields already present
- adding new instrumentation only makes sense after determining which current
  fields move with RSS and which do not

### 4.3 What is still unknown

We do not yet know which bucket explains the remaining growth:

1. true `rnsd` heap/object retention not represented in current MEMSTATS counts
2. allocator retention / fragmentation after bursty allocations
3. file-backed growth from SQLite / WAL / page cache that is visible in service
   accounting but not equivalent to live heap
4. hook/provider-related allocations or per-interface buffers not currently
   tracked by MEMSTATS

### 4.4 Minimum evidence needed for a proper diagnosis

Need a time-series, not isolated snapshots:

1. `MEMSTATS` sampled over at least another 24h at steady traffic.
2. For the same timestamps:
   - `systemctl show -p MemoryCurrent -p MemoryPeak rnsd`
   - `ps` RSS
   - `free -h`
   - `stats.db`, WAL, and SHM sizes
3. Correlation analysis:
   - does `smaps_anon_mb` rise with RSS?
   - does `smaps_file_est_mb` rise with DB/WAL growth?
   - does `smaps_private_dirty_mb` track the drift?
4. If memory still rises while tracked counts stay flat:
   - `/proc/<pid>/smaps_rollup`
   - selected `/proc/<pid>/smaps` snapshots
   - jemalloc or allocator-specific stats if available

### 4.5 Concrete repo-side questions to answer

1. Which significant `rnsd` runtime structures are not represented in MEMSTATS?
2. Are per-interface buffers, provider-bridge state, hook runtime state, or
   connection write buffers omitted from the current counters?
3. Does `provider bridge` activity correlate with RSS spikes or only with sidecar
   health?
4. Should we add explicit counters for:
   - total interfaces / dynamic interfaces
   - per-interface buffer bytes
   - provider bridge queue bytes per consumer
   - hook runtime memory / program count
5. Is the observed growth mostly anonymous memory or file-backed memory?

### 4.6 Most relevant files

- [rns-net/src/driver.rs](/home/lelloman/lelloprojects/rns-rs/rns-net/src/driver.rs)
- [docs/vps-deploy-runbook.md](/home/lelloman/lelloprojects/rns-rs/docs/vps-deploy-runbook.md)
- [docs/vps-production-findings-2026-03-20-run7.md](/home/lelloman/lelloprojects/rns-rs/docs/vps-production-findings-2026-03-20-run7.md)
- [docs/vps-production-findings-2026-03-22.md](/home/lelloman/lelloprojects/rns-rs/docs/vps-production-findings-2026-03-22.md)
- [docs/vps-production-findings-2026-04-02.md](/home/lelloman/lelloprojects/rns-rs/docs/vps-production-findings-2026-04-02.md)

---

## 5. Recommended investigation order

The best order is:

1. `rns-sentineld` restart mechanism
2. `rns-statsd` drop mechanism and impact
3. memory drift correlation using existing MEMSTATS + smaps fields

Reasoning:
- #2 and #3 may both still be affected by sidecar / provider behavior
- #4 is more likely to require longer observation windows and should not block
  identifying a sharper functional fault in `rns-sentineld`

---

## 6. Practical next actions

The next concrete tasks should be:

1. Add a narrow reproduction / debug plan for `rns-sentineld` disconnects.
2. Deploy the new provider-bridge stats and `provider_drop_samples` changes,
   then capture live queue snapshots plus at least several hours of persisted
   drop history on the VPS.
3. Capture a new 24h memory series using the existing MEMSTATS fields before
   adding more memory instrumentation.
4. Decide whether `rns-statsd` drops are merely observability loss or a product
   correctness problem.

### 6.1 VPS commands for issue #2

Once the new binaries are deployed, use:

```bash
ssh root@vps '/usr/local/bin/rns-ctl backbone provider --json'
ssh root@vps "sqlite3 /var/lib/rns/stats.db '
  SELECT datetime(ts_ms/1000, \"unixepoch\") AS ts, dropped_events
  FROM provider_drop_samples
  ORDER BY ts_ms DESC
  LIMIT 50;
'"
```

What to look for:

- whether one consumer is consistently near `queue_max_events` or
  `queue_max_bytes`
- whether `dropped_pending` keeps reappearing faster than it drains
- whether `dropped_total` rises without corresponding disconnects
- whether persisted `provider_drop_samples` show short spikes or sustained loss
