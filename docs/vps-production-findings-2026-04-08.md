# VPS Production Findings — 2026-04-08 (66h stability window)

This report captures a follow-up production health check after the
`0.2.315-fed3354` rollout that entered service on the live VPS
(`root@vps`) at `2026-04-05 21:39:39 UTC`.

Checks in this report were collected directly from the live host on
`2026-04-08`, with the main sample window centered around
`15:47 UTC` through `16:08 UTC`.

---

## 1. Summary

The current `0.2.315-fed3354` deployment continues to look healthy after
roughly `66 hours` of daemon uptime:

- `rnsd`, `rns-statsd`, and `rns-sentineld` all remain `active (running)`
- required listeners remain present:
  - `0.0.0.0:4242`
  - `127.0.0.1:37429`
- the current `rnsd` instance has been continuously active since
  `2026-04-05 21:39:39 UTC`
- `rnsd` resident memory remains bounded and has flattened further below the
  earlier `2026-04-06` sample range
- provider-bridge churn signals remain absent:
  - `provider bridge dropped`: `0` in the last `24h`
  - `provider bridge disconnected`: `0` in the last `24h`
- the node continues to carry active public traffic, including non-announce
  packet classes

The main new nuance in this check is not a daemon-health regression, but
ongoing sentinel enforcement on the public listener:

- `rns-sentineld` is actively blacklisting peers for repeated idle timeouts
- this appears to be ordinary abuse / hygiene enforcement rather than a return
  of the earlier provider-bridge failure mode
- active service health, current connectivity, and packet flow remained normal
  during the same window

Operationally, the VPS experiment still looks healthy on `2026-04-08`.

---

## 2. Service And Host State

Primary host sample at `2026-04-08 15:47:07 UTC`:

- host uptime: `14 days, 19:32`
- load average: `0.02 / 0.05 / 0.17`
- memory: `621 MiB` used / `1833 MiB` total / `1212 MiB` available
- swap: none

Service state:

- `rnsd`: `active`
- `rns-statsd`: `active`
- `rns-sentineld`: `active`

Installed versions:

- `rnsd 0.2.315-fed3354`
- `rns-statsd 0.2.315-fed3354`
- `rns-sentineld 0.2.315-fed3354`
- `rns-ctl 0.2.315-fed3354`

Current listeners:

- `0.0.0.0:4242`
- `127.0.0.1:37429`

Systemd timing:

- `rnsd ActiveEnterTimestamp`: `Sun 2026-04-05 21:39:39 UTC`
- `rns-statsd active since`: `Sun 2026-04-05 21:39:45 UTC`
- `rns-sentineld active since`: `Sun 2026-04-05 21:39:45 UTC`

`rns-ctl status` reported:

- transport instance running for `2d 18h 7m` at sample time
- public entrypoint `Arg0net RNS-VPS Italy` up
- named peers such as `RMAP World`, `RNS.MichMesh.net ipv4`, and
  `brn.ch.thunderhost.net` up
- many active dynamic `BackboneInterface/<id>` sessions attached to the public
  listener

At sample time there were `48` established TCP sessions involving port `4242`.

Interpretation:

- the current production instance has remained continuously up since the April
  5 rollout window
- the live transport continues to accept and hold public peer sessions
- there is no sign of a listener-loss or restart-loop regression

---

## 3. Memory Behavior

### 3.1 Current process counters

Direct process counters from `/proc/641870/status` during the sample:

- `VmRSS`: `95,604 kB` (~`93.4 MB`)
- `VmHWM`: `108,944 kB` (~`106.4 MB`)
- `VmData`: `448,840 kB`
- `Threads`: `63`

`systemctl status rnsd` also reported:

- current cgroup memory: `361.9M`
- cgroup peak memory: `486.1M`

The cgroup number is materially larger than the direct process RSS and should
not be read as a contradiction. The direct `/proc` counters remain the more
useful signal for comparing the daemon against earlier `MEMSTATS` findings.

### 3.2 `MEMSTATS` trend

Recent `MEMSTATS` samples from `14:50 UTC` through `15:45 UTC` showed a tight,
stable band:

- `rss_mb`: roughly `93.0` -> `94.1`
- `smaps_anon_mb`: roughly `89.0` -> `90.1`
- `ann_q_bytes`: roughly `21.37 MB` -> `22.88 MB`
- `ann_q_ifaces` / `ann_q_nonempty`: roughly `44` -> `56`
- `ann_q_iface_drop`: always `0`

Representative samples:

- `2026-04-08 14:50:08 UTC`
  `rss_mb=94.1`, `smaps_anon_mb=90.1`, `ann_q_bytes=22875887`,
  `ann_q_ifaces=56`
- `2026-04-08 15:20:08 UTC`
  `rss_mb=93.3`, `smaps_anon_mb=89.2`, `ann_q_bytes=21756664`,
  `ann_q_ifaces=49`
- `2026-04-08 15:45:09 UTC`
  `rss_mb=93.1`, `smaps_anon_mb=89.1`, `ann_q_bytes=21925150`,
  `ann_q_ifaces=47`

Comparison against the `2026-04-06` report:

- `2026-04-06` sampled roughly `95.9` -> `97.7 MB` RSS
- `2026-04-08` sampled roughly `93.0` -> `94.1 MB` RSS

Interpretation:

- memory remains bounded
- the earlier runaway-memory / wedged-driver pattern still has not recurred
- the steady-state resident set now looks slightly better than the already-good
  April 6 follow-up

---

## 4. Sidecar Health

### 4.1 Provider-bridge stability

Bridge-specific regression signals remained absent:

- `rns-statsd` `provider bridge dropped` warnings in the last `24h`: `0`
- `rns-sentineld` `provider bridge disconnected` warnings in the last `24h`:
  `0`

`provider_drop_samples` returned no recent rows during this check.

Interpretation:

- there is no evidence of a return to the earlier provider-bridge churn mode
- sidecars are not repeatedly losing the daemon bridge

### 4.2 Sidecar runtime state

`systemctl status` showed:

- `rns-statsd`
  - `active (running)` since `2026-04-05 21:39:45 UTC`
  - current memory: `85.0M`
  - peak memory: `131.0M`
- `rns-sentineld`
  - `active (running)` since `2026-04-05 21:39:45 UTC`
  - current memory: `972.0K`
  - peak memory: `1.4M`

Recent `journalctl -u rns-statsd -n 20` returned no entries in the queried
window, while `rns-sentineld` showed only blacklist enforcement warnings, not
crash or bridge-loss symptoms.

### 4.3 Sentinel blacklist activity

The current live sentinel state is active and noisy on the public listener.

From `rns-ctl backbone blacklist list --json`:

- total peer records in the live view: `712`
- entries with nonzero reject history: `258`
- entries currently under an active timed blacklist: `30`

From the journal:

- `blacklisting ... repeated idle timeouts` events in the last `24h`: `406`

Recent examples included timed blacklists for:

- `31.173.83.30`
- `12.75.122.113`
- `149.88.96.227`
- `212.124.4.132`
- `198.177.93.248`
- `91.203.197.36`

Connected peers visible in the same live view included:

- `216.134.227.250 conn=3 rejects=0`
- `185.103.254.162 conn=2 rejects=0`
- several other `conn=1 rejects=0` peers

Interpretation:

- the public listener is seeing enough undesirable or nonproductive traffic for
  the sentinel to enforce repeated idle-timeout blacklists
- that enforcement activity is distinct from the earlier bridge-disconnect
  regression and does not currently correlate with service instability
- it is still worth tracking over time because a rising blacklist burden may
  become an operational pressure point even if the core transport remains
  healthy

---

## 5. RNS Activity

### 5.1 Announces

From `seen_announces` in `stats.db`:

- total retained rows: `3,712,117`
- table span:
  - earliest row: `2026-03-15 15:41:19 UTC`
  - latest row: `2026-04-08 16:08:21 UTC`
- seen announces in the last `1h`: `7,673`
- seen announces in the last `24h`: `182,872`

This keeps the current live traffic in essentially the same healthy band seen
on earlier checks, and is slightly higher than the `172,238` rows reported in
the April 6 findings for the preceding `24h` window.

### 5.2 Connections and transport activity

At sample time:

- established TCP sessions involving port `4242`: `48`
- the public entrypoint was up
- named peers were up
- many dynamic backbone sessions were up simultaneously

This continues to support the conclusion that the node is operating as a real
public transport peer rather than sitting mostly idle.

### 5.3 Non-announce traffic

The `packet_counters` table was updated during the sample window for multiple
packet classes:

- `announce rx`: latest `2026-04-08 15:47:55 UTC`
- `announce tx`: latest `2026-04-08 15:47:55 UTC`
- `data rx`: latest `2026-04-08 15:47:55 UTC`
- `data tx`: latest `2026-04-08 15:47:45 UTC`
- `linkrequest rx/tx`: latest `2026-04-08 15:47:30 UTC`
- `proof rx/tx`: latest `2026-04-08 15:47:30 UTC`

Aggregate packet totals at sample time:

- `announce rx`: `194,393,690` packets / `41,079,270,710` bytes
- `announce tx`: `128,524,566` packets / `27,154,055,017` bytes
- `data rx`: `51,210,165` packets / `4,090,066,305` bytes
- `data tx`: `1,776,837` packets / `1,090,038,210` bytes
- `linkrequest rx`: `98,224` packets / `10,011,673` bytes
- `linkrequest tx`: `87,480` packets / `8,709,518` bytes
- `proof rx`: `62,300` packets / `6,725,490` bytes
- `proof tx`: `60,295` packets / `6,488,922` bytes

Interpretation:

- the VPS is not only validating announces
- it is still carrying active non-announce RNS traffic in the current live
  window
- the transport remains meaningfully engaged with live network activity

---

## 6. Logs And Recent Runtime Behavior

Recent `rnsd` journal lines in the sample window showed normal live activity:

- repeated `Announce:validated` messages
- matching `Announce received` lines from `rns_cli::rnsd`
- no obvious panic, restart, bind failure, or blocked-listener symptoms in the
  sampled tail

Recent `rns-sentineld` logs showed only enforcement actions of the form:

- `blacklisting <ip> on Public Entrypoint for <secs> (level <n>): repeated idle timeouts`

No sampled logs showed:

- provider bridge disconnects
- provider bridge drops
- restart loops
- missing listener symptoms

---

## 7. Operational Interpretation

As of `2026-04-08`, the production VPS experiment still looks healthy and
argues further against a recurrence of the earlier severe failure mode.

The strongest signals are:

- continuous uptime since `2026-04-05 21:39:39 UTC`
- stable listener presence on the required public and RPC ports
- bounded, slightly improved RSS relative to the April 6 check
- no provider-bridge churn warnings
- active public peer connectivity
- current non-announce packet flow

The main caveat is the volume of sentinel blacklist enforcement on the public
listener:

- this does not currently look like a daemon-health regression
- it does indicate that the public entrypoint is seeing persistent low-quality
  or timeout-heavy peer traffic
- if that pressure grows, it could become its own operational issue even while
  the core transport remains stable

Current stance:

- continue periodic health checks
- keep tracking `MEMSTATS`, listener presence, and provider-bridge warnings
- add blacklist-enforcement trend monitoring to future checks
- continue gradual operational changes rather than aggressive topology jumps

On the evidence from this April 8 sample, the live VPS rollout remains healthy,
stable, and actively carrying traffic.
