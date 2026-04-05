# VPS Production Findings — 2026-04-05 (deploy validation and follow-up)

Binary rollout advanced from `0.2.314-4f82180` to `0.2.315-fed3354` on
`2026-04-05`. This report covers:

- pre-rollout diagnosis on the old daemon
- immediate post-rollout validation on the new daemon
- follow-up investigation of the transient RPC short-read seen during startup

Checks were collected on `2026-04-05 16:25-21:43 UTC` from the live VPS
(`root@vps`).

---

## 1. Summary

The rollout successfully fixed the previously confirmed catastrophic failure
mode where a blocking backbone-client write could wedge the main driver thread
and allow memory to grow without bound behind an unbounded event queue.

The fresh daemon on `0.2.315-fed3354` is currently healthy:

- all four binaries are on the new build
- `rnsd` is active with `NRestarts=0`
- `rns-ctl status`, `rns-ctl config list`, `rns-ctl path -t`, and
  `rns-ctl backbone provider -j` all succeed now
- `rnsd` memory is currently low relative to the pre-rollout incident

The earlier `failed to fill whole buffer` errors on the fresh deploy were real,
but they were transient during startup rather than a persistent broken control
plane.

---

## 2. Pre-rollout incident on the old daemon

Before the `0.2.315-fed3354` rollout, the old `0.2.314-4f82180` daemon
regressed into a severe live incident:

- `rnsd` memory climbed above `1.3 GiB`
- `rns-ctl status` failed with `RPC error: failed to fill whole buffer`
- `rns-statsd` and `rns-sentineld` also logged RPC short-read failures

Live debugging on the VPS showed:

- the main `rns-driver` thread was blocked in `sendto()`
- the blocked outbound socket belonged to the configured `Berlin IPv4` peer
- interface writes were still capable of blocking the driver thread
- the driver event queue was unbounded, so backlog growth translated directly
  into process memory growth

That incident directly motivated commit `fed3354`
(`Isolate interface writes and bound event queues`).

---

## 3. Deployed fix in `0.2.315-fed3354`

The rollout on `2026-04-05` included:

- async per-interface writer workers so interface writes no longer happen on
  the main driver thread
- a bounded driver event queue
- config knobs for:
  - `driver_event_queue_capacity`
  - `interface_writer_queue_capacity`

Relevant defaults in the shipped build:

- `driver_event_queue_capacity = 8192`
- `interface_writer_queue_capacity = 256`

This deploy also included the previously implemented memory fixes:

- announce-queue interface cleanup and cap
- bounded-by-default path table
- bounded `known_destinations`

---

## 4. Immediate post-rollout state

After replacing the binaries and force-killing the stuck old `rnsd`, the new
process started cleanly:

- `rnsd 0.2.315-fed3354`
- `rns-statsd 0.2.315-fed3354`
- `rns-sentineld 0.2.315-fed3354`
- `rns-ctl 0.2.315-fed3354`

Fresh daemon state:

- new `rnsd` pid: `641870`
- active since `2026-04-05 21:39:39 UTC`
- `NRestarts=0`
- listeners present:
  - `0.0.0.0:4242`
  - `127.0.0.1:37429`

Immediately after restart, systemd memory accounting dropped back to a healthy
baseline:

- `MemoryCurrent ~45.7 MB`
- `MemoryPeak ~58.8 MB`

Later follow-up checks still looked healthy:

- `2026-04-05 21:43:31 UTC`
  - `MemoryCurrent=70701056` bytes (~`67.4 MB`)
  - `MemoryPeak=82022400` bytes (~`78.2 MB`)

This is strong evidence that the old catastrophic memory path was addressed.

---

## 5. Earlier memory fixes validated

The first post-deploy `MEMSTATS` samples from the earlier `0.2.314-4f82180`
deploy already showed that the queue-leak fix was behaving correctly:

- `2026-04-05 16:30:06 UTC`
  - `rss_mb=56.8`
  - `known_dest=385`
  - `known_dest_cap_evict=0`
  - `path=385`
  - `path_cap_evict=0`
  - `ann_q_ifaces=65`
  - `ann_q_nonempty=65`
  - `ann_q_entries=13420`
  - `ann_q_bytes=2794704`
  - `ann_q_iface_drop=0`
- `2026-04-05 16:35:06 UTC`
  - `rss_mb=52.8`
  - `known_dest=698`
  - `known_dest_cap_evict=0`
  - `path=693`
  - `path_cap_evict=0`
  - `ann_q_ifaces=67`
  - `ann_q_nonempty=67`
  - `ann_q_entries=25462`
  - `ann_q_bytes=5273719`
  - `ann_q_iface_drop=0`

Compared with the pre-fix state:

- old symptom: `ann_q_ifaces ~22k` with only `~55-60` non-empty
- fixed behavior: `ann_q_ifaces` now closely tracks `ann_q_nonempty`

So the stale dynamic-interface announce-queue leak appears fixed in production.

---

## 6. Transient RPC short-read during startup

Right after the `0.2.315-fed3354` restart, the sidecars logged:

- `rpc connect failed: Connection refused` during the earliest startup window
- then `rpc call failed: failed to fill whole buffer`

Examples observed:

- `rns-statsd` first recovered after one short-read retry
- `rns-sentineld` first recovered after one short-read retry
- after recovery, both continued operating normally

By the later follow-up check, the control plane was healthy:

- `rns-ctl status` succeeded 4/4
- `rns-ctl config list` succeeded
- `rns-ctl path -t` succeeded
- `rns-ctl backbone provider -j` succeeded

Observed latencies at the time of the successful follow-up:

- `rns-ctl status -j`: `0.14-0.18s`
- `rns-ctl config list`: `0.19s`
- `rns-ctl path -t`: `0.24s`
- `rns-ctl status`: `0.30s`

This means the startup short-read was not a persistent RPC breakage.

---

## 7. Why the RPC short-read happens

The current RPC server behavior explains the symptom precisely:

- after auth, the RPC server reads one request and calls
  `handle_rpc_request()`
- normal queries then go through `send_query()`
- `send_query()` waits up to `5s` for the driver response
- if that wait expires, the connection handler returns an error before writing
  any framed response
- the client then sees EOF / short read as:
  `failed to fill whole buffer`

Relevant code paths:

- RPC server loop:
  `rns-net/src/rpc.rs`
- `handle_connection()`:
  `rns-net/src/rpc.rs`
- `send_query()`:
  `rns-net/src/rpc.rs`
- driver handling of `Event::Query`:
  `rns-net/src/driver.rs`

The sidecar hook-loading path uses the same driver event path:

- hook load requests are sent as RPC events
- those events are also serviced by the same main driver loop
- startup retries live in:
  - `rns-cli/src/statsd.rs`
  - `rns-cli/src/sentineld.rs`

Operational interpretation:

- the startup failure window is best explained as transient control-plane
  starvation during heavy startup traffic, not a dead driver
- once the burst subsided, the same RPC commands completed normally

---

## 8. Current transport / thread state

The fresh process currently has the expected long-lived threads, including:

- `rpc-server`
- `rns-driver`
- `rns-verify`
- `rns-timer`
- `provider-bridge`
- multiple `backbone-client` threads
- multiple `iface-writer-*` threads

That confirms:

- the RPC server thread exists
- the driver thread exists
- the async writer isolation from `fed3354` is active on the live VPS

During the healthy follow-up, the daemon continued processing normal traffic:

- ongoing `Announce:validated`
- dynamic interface registrations on `Public Entrypoint`
- successful path and status RPC queries

---

## 9. Proposed next fixes

The remaining control-plane issue is not “RPC is broken,” but rather “startup
RPC requests can still starve and then fail with a misleading short-read.”

Recommended next engineering steps:

1. Separate control-plane events from general transport events.
   - give RPC queries and hook-management requests a priority lane or separate
     queue from normal packet/announce traffic

2. Return a structured RPC error on timeout.
   - do not close the connection silently when the internal query wait times
     out
   - this would turn `failed to fill whole buffer` into an explicit timeout
     result

3. Revisit the current `5s` internal RPC timeout.
   - startup hook-load operations may need a different timeout budget than
     steady-state point queries

4. Keep the bounded queues.
   - the bounded event queue and async writer workers should stay; they appear
     to have prevented the previous catastrophic driver-stall memory failure

---

## 10. Overall conclusion

As of the latest `2026-04-05 21:43 UTC` checks:

- the previously diagnosed blocking-write / unbounded-queue memory incident is
  no longer present
- the announce-queue leak fix looks validated in production
- the new path/known-destination caps are present and their counters were idle
  in sampled `MEMSTATS`
- the current daemon is healthy and the control plane is working now

The remaining issue is a startup-time control-plane starvation path that
surfaces as `failed to fill whole buffer` until the daemon settles. That is a
real bug, but it is narrower than the earlier persistent-RPC interpretation.
