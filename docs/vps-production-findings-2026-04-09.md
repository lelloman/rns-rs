# VPS Production Findings — 2026-04-09 (routine health check)

This report captures a follow-up production health check after the
`0.2.315-fed3354` rollout that entered service on the live VPS
(`root@vps`) at `2026-04-05 21:39:39 UTC`.

Checks in this report were collected directly from the live host on
`2026-04-09`, with the main sample window centered around
`14:23 UTC` through `14:24 UTC`.

---

## 1. Summary

The current `0.2.315-fed3354` deployment continues to look healthy after
roughly `88 hours` of daemon uptime:

- `rnsd`, `rns-statsd`, and `rns-sentineld` all remain `active (running)`
- required listeners remain present:
  - `0.0.0.0:4242`
  - `127.0.0.1:37429`
- the current `rnsd` instance has been continuously active since
  `2026-04-05 21:39:39 UTC`
- `rnsd` resident memory remains bounded and slightly below the already-good
  `2026-04-08` sample range
- provider-bridge churn signals remain absent:
  - `provider bridge dropped`: `0` in the last `24h`
  - `provider bridge disconnected`: `0` in the last `24h`
- the node continues to carry active public traffic, including non-announce
  packet classes

The main caveat remains sentinel enforcement on the public listener:

- `rns-sentineld` is still actively blacklisting peers for repeated idle
  timeouts
- this still looks like public-listener hygiene rather than a return of the
  earlier provider-bridge failure mode
- service uptime, listener presence, and packet flow remained normal during the
  same window

Operationally, the VPS experiment still looks healthy on `2026-04-09`.

---

## 2. Service And Host State

Primary host sample at `2026-04-09 14:23:37 UTC`:

- host uptime: `15 days, 18:08`
- load average: `0.74 / 1.01 / 0.52`
- memory: `583 MiB` used / `1833 MiB` total / `1250 MiB` available
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

- transport instance running for `3d 16h 43m` at sample time
- public entrypoint `Arg0net RNS-VPS Italy` up
- named peers such as `RMAP World`, `RNS.MichMesh.net ipv4`, and
  `brn.ch.thunderhost.net` up
- many active dynamic `BackboneInterface/<id>` sessions attached to the public
  listener

At sample time there were `49` established TCP sessions involving port `4242`.

Interpretation:

- the current production instance has remained continuously up since the April
  5 rollout window
- the live transport continues to accept and hold public peer sessions
- there is no sign of a listener-loss or restart-loop regression

---

## 3. Memory Behavior

### 3.1 `MEMSTATS` trend

Recent `MEMSTATS` samples from `13:25 UTC` through `14:20 UTC` showed a tight,
stable band:

- `rss_mb`: roughly `91.4` -> `92.4`
- `smaps_anon_mb`: roughly `87.2` -> `88.3`
- `ann_q_bytes`: roughly `19.96 MB` -> `20.70 MB`
- `ann_q_ifaces` / `ann_q_nonempty`: roughly `41` -> `54`
- `ann_q_iface_drop`: always `0`

Representative samples:

- `2026-04-09 13:25:17 UTC`
  `rss_mb=92.1`, `smaps_anon_mb=87.9`, `ann_q_bytes=20358982`,
  `ann_q_ifaces=51`
- `2026-04-09 13:45:17 UTC`
  `rss_mb=92.4`, `smaps_anon_mb=88.3`, `ann_q_bytes=20701948`,
  `ann_q_ifaces=54`
- `2026-04-09 14:20:17 UTC`
  `rss_mb=91.6`, `smaps_anon_mb=87.4`, `ann_q_bytes=20281418`,
  `ann_q_ifaces=44`

Comparison against the `2026-04-08` report:

- `2026-04-08` sampled roughly `93.0` -> `94.1 MB` RSS
- `2026-04-09` sampled roughly `91.4` -> `92.4 MB` RSS

Interpretation:

- memory remains bounded
- the earlier runaway-memory / wedged-driver pattern still has not recurred
- the steady-state resident set looks slightly better than the April 8 follow-up

---

## 4. Sidecar Health

### 4.1 Provider-bridge stability

Bridge-specific regression signals remained absent:

- `rns-statsd` `provider bridge dropped` warnings in the last `24h`: `0`
- `rns-sentineld` `provider bridge disconnected` warnings in the last `24h`:
  `0`

Interpretation:

- there is no evidence of a return to the earlier provider-bridge churn mode
- sidecars are not repeatedly losing the daemon bridge

### 4.2 Sentinel blacklist activity

The current live sentinel state remains active and somewhat noisy on the public
listener.

From `rns-ctl backbone blacklist list --json`:

- total peer records in the live view: `866`
- entries with nonzero reject history: `318`
- entries currently under an active timed blacklist: `36`
- entries currently connected: `46`

From the journal:

- `blacklisting ... repeated idle timeouts` events in the last `24h`: `257`

Examples visible in the live view included:

- `12.75.122.113 rejects=3313`
- `31.173.83.30 rejects=632`
- `198.177.93.248 rejects=1083`
- `212.124.4.132 rejects=3691`
- `193.141.60.201 rejects=21019`

Interpretation:

- the public listener continues to see enough undesirable or nonproductive
  traffic for the sentinel to enforce repeated idle-timeout blacklists
- that enforcement activity is distinct from the earlier bridge-disconnect
  regression and does not currently correlate with service instability
- compared with the `2026-04-08` check, blacklist pressure remains present but
  was lower in this `24h` journal window (`257` vs `406` events)

---

## 5. RNS Activity

### 5.1 Announces

From `seen_announces` in `stats.db`:

- total retained rows: `3,884,769`
- latest row: `2026-04-09 14:24:13 UTC`
- seen announces in the last `1h`: `8,522`
- seen announces in the last `24h`: `186,863`

This keeps the current live traffic in the same healthy range seen on recent
checks and is slightly above the `182,872` rows reported in the April 8
findings for the preceding `24h` window.

### 5.2 Connections and transport activity

At sample time:

- established TCP sessions involving port `4242`: `49`
- the public entrypoint was up
- named peers were up
- many dynamic backbone sessions were up simultaneously

This continues to support the conclusion that the node is operating as a real
public transport peer rather than sitting mostly idle.

### 5.3 Non-announce traffic

The `packet_counters` table was updated during the sample window for multiple
packet classes:

- `announce rx/tx`: latest `2026-04-09 14:24:18 UTC`
- `data rx/tx`: latest `2026-04-09 14:24:18 UTC`
- `linkrequest rx/tx`: latest `2026-04-09 14:22:42 UTC`
- `proof rx/tx`: latest `2026-04-09 14:22:02 UTC`

Interpretation:

- the VPS is not only validating announces
- it is still carrying active non-announce RNS traffic in the current live
  window
- the transport remains meaningfully engaged with live network activity

---

## 6. Tooling / Runbook Drift

One runbook-related mismatch was visible during this check:

- the live `stats.db` schema uses `seen_at_ms` in `seen_announces` and
  `updated_at_ms` in `packet_counters`
- the older ad hoc query shape using `ts_ms` no longer matches the live schema

Current live schema excerpts:

- `seen_announces(..., seen_at_ms INTEGER NOT NULL, ...)`
- `packet_counters(..., updated_at_ms INTEGER NOT NULL, ...)`

Interpretation:

- the operational signals are still available on the VPS
- but the runbook examples should be updated to reflect the current SQLite
  column names so follow-up checks do not fail on copy-paste

---

## 7. Operational Interpretation

As of `2026-04-09`, the production VPS experiment still looks healthy and
continues the stable pattern seen in the April 6 and April 8 checks.

The strongest signals are:

- continuous uptime since `2026-04-05 21:39:39 UTC`
- stable listener presence on the required public and RPC ports
- bounded RSS in the low `92 MB` range
- no provider-bridge churn warnings
- active public peer connectivity
- current non-announce packet flow

The main caveat remains the volume of sentinel blacklist enforcement on the
public listener:

- this does not currently look like a daemon-health regression
- it does indicate that the public entrypoint is seeing persistent low-quality
  or timeout-heavy peer traffic
- it is still worth tracking over time as an operational pressure signal

Current stance:

- continue periodic health checks
- keep tracking `MEMSTATS`, listener presence, and provider-bridge warnings
- keep tracking blacklist-enforcement volume
- update the SQLite query examples in the deploy runbook before the next manual
  VPS audit

On the evidence from this April 9 sample, the live VPS rollout remains healthy,
stable, and actively carrying traffic.
