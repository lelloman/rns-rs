# VPS Production Findings — 2026-04-06 (21h stability window)

This report captures a follow-up production health check after the
`0.2.315-fed3354` rollout on `2026-04-05`.

Checks were collected from the live VPS (`root@vps`) during multiple samples on
`2026-04-06`, with the latest detailed sample at `18:48 UTC`.

---

## 1. Summary

The current `0.2.315-fed3354` deploy continues to look healthy under live
traffic after roughly `21 hours` of daemon uptime:

- `rnsd`, `rns-statsd`, and `rns-sentineld` remain `active`
- required listeners remain present:
  - `0.0.0.0:4242`
  - `127.0.0.1:37429`
- `rnsd` resident memory remains bounded and has settled lower than the earlier
  post-rollout baseline
- sidecar provider-bridge churn remains absent in the sampled windows
- the node continues to carry active RNS traffic, including non-announce packet
  classes

The strongest operational result is that the earlier catastrophic
runaway-memory / wedged-driver behavior has not recurred during this uptime
window.

---

## 2. Service And Host State

Latest host sample at `2026-04-06 18:48:23 UTC`:

- host uptime: `12 days, 22:33`
- load average: `0.00 / 0.04 / 0.19`
- memory: `604 MiB` used / `1.8 GiB` total / `1.2 GiB` available
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

Listeners present:

- `0.0.0.0:4242`
- `127.0.0.1:37429`

`rns-ctl status` reported the live transport instance running for
`21h 8m 45s` at sample time.

---

## 3. Memory Behavior

### 3.1 Current process memory

Direct kernel process counters at `18:48 UTC`:

- `VmRSS`: `99,536 kB` (~`97.2 MB`)
- `VmHWM`: `108,944 kB` (~`106.4 MB`)
- `VmData`: `449,872 kB`
- `Threads`: `64`

### 3.2 `MEMSTATS` trend

Recent `MEMSTATS` samples from `17:19 UTC` through `18:44 UTC` show a stable
band rather than monotonic growth:

- `rss_mb`: roughly `95.9` -> `97.7`
- `smaps_anon_mb`: roughly `91.8` -> `93.7`
- `ann_q_bytes`: roughly `26.4 MB` -> `27.7 MB`
- `ann_q_ifaces` / `ann_q_nonempty`: generally `39` -> `62`, staying aligned
- `ann_q_iface_drop`: always `0`

Notable comparison against earlier same-day checks:

- around `10:40 UTC`, `rss_mb` was still around `103.8` -> `104.5`
- around `16:15 UTC`, `rss_mb` had dropped into the `101.6` -> `102.2` range
- by `18:48 UTC`, the daemon had settled further into the `95.9` -> `97.7`
  range

Interpretation:

- memory remains bounded
- the node is not showing the old monotonic-with-uptime runaway path
- the post-fix steady-state memory level now looks materially better than the
  first immediate post-rollout samples

---

## 4. Sidecar Health

Sidecar stability remained good in the sampled windows:

- `provider bridge dropped` warnings from `rns-statsd` in the last `6h`: `0`
- `provider bridge disconnected` warnings from `rns-sentineld` in the last
  `24h`: `0`

This is consistent with the earlier `2026-04-06` checks and continues to argue
against a return of the earlier provider-bridge degradation mode.

---

## 5. RNS Activity

### 5.1 Announces

From `stats.db`:

- `seen_announces` in the last `1h`: `7,673`
- `seen_announces` in the last `24h`: `172,238`

This is consistent with the earlier same-day checks that placed the current
announce rate in the rough band of:

- `~6.8k` -> `7.6k` announces per hour
- `~113` -> `128` announces per minute on average, depending on the sample
  window

### 5.2 Connections and transport activity

At `18:48 UTC`:

- established TCP sessions involving port `4242`: `48`

`rns-ctl status` still showed:

- the public entrypoint up
- configured named peers up
- many live dynamic `BackboneInterface/<id>` sessions on the public listener

### 5.3 Non-announce traffic

The SQLite `packet_counters` table was still being updated at sample time for:

- `announce`
- `data`
- `linkrequest`
- `proof`

Latest packet-class update timestamps at sample time:

- `announce rx/tx`: `2026-04-06 18:48:23 UTC`
- `data rx`: `2026-04-06 18:48:23 UTC`
- `data tx`: `2026-04-06 18:47:58 UTC`
- `linkrequest rx/tx`: `2026-04-06 18:48:13 UTC`
- `proof rx/tx`: `2026-04-06 18:45:17 UTC`

Interpretation:

- the node is not just validating announces
- it is still carrying active non-announce RNS traffic in the current live
  window

---

## 6. Operational Interpretation

The live VPS now has a materially stronger production story than the earlier
April checks:

- the current daemon has remained healthy for about `21 hours`
- resident memory is stable and lower than earlier same-day samples
- sidecars remain quiet
- public traffic remains active
- non-announce packet classes continue to flow

This is strong production evidence that the `fed3354` deployment fixed the
earlier severe failure mode where the main driver thread could wedge behind a
blocking interface write and allow memory to grow without bound.

The remaining stance should still be disciplined:

- continue periodic health checks
- expand backbone peers gradually rather than all at once
- keep watching `MEMSTATS`, sidecar bridge warnings, and announce / packet-rate
  behavior after any topology change

But as of this `2026-04-06` report, the live VPS experiment looks healthy and
stable.
