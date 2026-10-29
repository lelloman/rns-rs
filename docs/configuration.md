# Configuration

A node reads a single `config` file from its config directory (default
`~/.reticulum`, or `--config PATH`). The format and keys are the same as
Python Reticulum's, so an existing Python config works as is. This page lists
the keys that are specific to rns-rs or that deserve attention when operating
a Rust node. Run `rnsd --exampleconfig` for a commented starting point that
includes an example of every interface type.

## Layout

```ini
[reticulum]
  enable_transport = false
  share_instance = true
  shared_instance_port = 37428
  instance_control_port = 37429

[logging]
  loglevel = 4

[interfaces]
  [[TCP Client]]
    type = TCPClientInterface
    target_host = amsterdam.connect.reticulum.network
    target_port = 4965
```

Interface types: `AutoInterface`, `TCPClientInterface`, `TCPServerInterface`,
`UDPInterface`, `SerialInterface`, `KISSInterface`, `AX25KISSInterface`,
`PipeInterface`, `RNodeInterface`, `BackboneInterface`, `I2PInterface`, and
`WeaveInterface`. An interface type that was not compiled into the binary is an
error; see [Building](building.md#selecting-interfaces).

## `[reticulum]` keys worth knowing

| Key | Default | Notes |
|-----|---------|-------|
| `enable_transport` | `false` | Forward traffic for other nodes |
| `static_transport_identity` | `false` | With transport disabled, the transport-facing identity is ephemeral unless this is set |
| `local_hops_delta` | `false` | Mask local zero-hop SINGLE/LINK traffic on external interfaces |
| `enable_interface_management` | `true` | Set to `false` to block `rnstatus --attach/--detach/--reload` |
| `panic_on_interface_error` | `false` | Abort instead of continuing when an interface fails |
| `packet_hashlist_max_entries` | `250000` | Size of the bounded dedup table |
| `packet_hashlist_allocation` | `eager` | `eager` prefaults the table at startup; `lazy` grows it |
| `link_mtu_discovery` | `yes` | Set to `no` to omit MTU signalling from outbound link requests |
| `hop_limiter` | `128` | Drop inbound packets whose hop count reaches this limit, counted per interface as `hop_limiter_hits` (`rnstatus` "Hop Limit"); clamped to 1-128 |
| `underlay_mark` | unset | Linux `SO_MARK` for owned IP sockets, see below |
| `probe_port`, `probe_addr`, `direct_connect_policy`, `direct_connect_allow_private_endpoints` | | [Direct Link](direct-link.md) |
| `default_gravity`, `autoconnect_interface_mode`, `autoconnect_interface_gravity`, `autoconnect_announces_to_internal`, `autoconnect_unverified_implementations` | | [Interface Discovery](interface-discovery.md) |

Log levels run from `0` (critical only) to `8` (extreme); `7` adds path
logging. `logtimestamps = no` drops timestamps when an external logger adds its
own.

## TCP interface MTU

`TCPClientInterface` and `TCPServerInterface` use a 65,535-byte hardware MTU
unless one of these keys is set:

| Key | Meaning |
|-----|---------|
| `bitrate` | Interface bitrate in bits per second. The hardware MTU follows the upstream tiers, from 1,024 bytes at 62.5 kbps to 16,384 at 10 Mbps and 524,288 at 1 Gbps; below 62.5 kbps links stay at the 500-byte base MTU |
| `fixed_mtu` | Hardware MTU in bytes, at least 500; it overrides `bitrate` |

A server applies them to every client it accepts. The link MTU signalled in
link requests is the smaller of the two ends' hardware MTUs.

## Inbound queues

Inbound packets go through four independent queues, drained in priority order:
data, announces, path requests, then ingress-limited traffic. A packet is
dropped when its class queue is full. A lower-priority queue starts draining
only after every higher-priority queue before the same control-event barrier
is empty.

```ini
[reticulum]
  qlen_in_data = 1024
  qlen_in_announce = 128
  qlen_in_pr = 128
  qlen_in_il = 8
```

The values shown are the defaults. Each must be a positive integer.

## Stamps

Reticulum 1.6.0 adds proof-of-work stamps to destination announces, path
requests, and link requests. The `[stamps]` section configures them with the
same keys and semantics as Python Reticulum:

```ini
[stamps]
  # Opt in early to generation, emission and enforcement.
  # stamp_destinations = yes
  # stamp_prs = yes
  # stamp_lrs = yes
  # enforce_stamps = yes

  # destination_cost = 23
  # destination_value = 25
  # pr_cost = 19
  # pr_value = 19
  # lr_cost = 11
  # lr_stamp_timeout = 15
  # pr_stamp_timeout = 15
```

| Key | Default | Effect |
|-----|---------|--------|
| `stamp_destinations` | `no` | Stamp announces emitted by this instance |
| `stamp_prs` | `no` | Stamp path requests emitted by this instance, and unstamped ones forwarded for local clients |
| `stamp_lrs` | `no` | Stamp outbound link requests to destinations that announced a non-zero link cost |
| `enforce_stamps` | `no` | Drop announces and path requests whose stamp is missing or below the required cost, and enforce link request stamps |
| `destination_cost` | `23` | Required stamp value of received and transported announces |
| `destination_value` | `25` | Default target value of generated destination stamps |
| `pr_cost` | `19` | Required stamp value of received path requests |
| `pr_value` | `19` | Target value of generated path request stamps |
| `lr_cost` | `11` | Link request cost announced for local destinations that set none |
| `lr_stamp_timeout` | `15` | Seconds allowed for grinding a stamped link request key before the link fails |
| `pr_stamp_timeout` | `15` | Seconds allowed for grinding a path request stamp before the request is dropped |

The four switches can only enable a feature: `no` keeps the built-in default
rather than forcing it off, as upstream applies them. During the 1.6.x
transition all four default to off; upstream plans to turn generation and
emission on by default in 1.6.1 and enforcement in 1.6.2. Costs and values are
clamped to 0-100 (`lr_cost` to 0-40), and the timeouts are floored at 20 ms.
An invalid boolean or number is a configuration error. The defaults are the
constants in `rns-core/src/constants.rs`, which mirror the upstream
`Transport` class attributes at the current parity target.

With these defaults a node validates inbound announce and path request stamps
and records announced link costs, but emits no stamps and refuses nothing for
lack of a stamp. Stamped link request keys are ground on a worker thread so the
driver stays responsive. Discovery announces have their own per-interface
`discovery_stamp_value`, described in
[Interface Discovery](interface-discovery.md#advertised-locations).

Stamps for emitted announces and path requests follow the upstream stamper
queue. A single lazily started worker thread drains two bounded queues, path
requests before announces, each holding at most 32 jobs; a newer job for the
same destination (and interface, for path requests) replaces the queued one,
and a full queue drops the job with a debug log. With `stamp_destinations` an
announce for a destination without a persisted stamp returns at once and the
worker grinds the stamp, persists it under `storage/stamps/`, and emits the
announce; later announces for that destination reuse the stored stamp
synchronously. A persisted stamp is reused only while its value reaches the
destination's target: `destination_value`, or the higher value an application
requests with `Destination::set_value` (capped at 100). Raising either target
regenerates the stamp on the next announce. With `stamp_prs` the node's own
path requests, and unstamped requests forwarded on behalf of local clients,
wait for the worker; generated path request stamps are cached by destination
and tag (256 entries) so one grind serves a request relayed on several
interfaces. A path request whose stamp is not found within `pr_stamp_timeout`
is not sent. None of this runs while the switches are off, which is the
upstream default.

The three emission switches are also runtime config keys, so a running node
can be switched to stamped emission without a restart:

```bash
rns-ctl config get global.stamp_destinations         # false by default
rns-ctl config set global.stamp_path_requests true
rns-ctl config set global.stamp_link_requests true
rns-ctl config reset global.stamp_path_requests
```

The keys apply immediately and reset to the value from the `[stamps]`
section, or to the built-in default when the section does not enable them.
A valid inbound stamp is observable on the receiving side:
`/api/identity/<hash>` (and the known-destinations RPC) report the recorded
`stamp_value` and the announced `lr_cost`, and every interface counts
validated inbound path request stamps as `stamped_path_requests` in
`/api/interfaces`, the RPC interface stats, and the management export.

A stamped announce carries the destination's link request cost: the value set
with `RnsNode::set_link_cost` (upstream `Destination.set_link_cost`, clamped to
`0..=40`), or the default 11. Initiators that see a non-zero announced cost
grind their link request key to it. Responders only check it when
`global.lr_stamps_enforced` (upstream `Transport.LR_STAMPS_ENFORCED`, off by
default) is on, dropping link requests whose stamp is below the destination's
cost; the key applies immediately and resets to the compile-time default.

## Ingress control

Any interface section accepts the Python-compatible ingress-control keys.
This example sets custom thresholds and timings:

```ini
  [[TCP Server]]
    type = TCPServerInterface
    listen_ip = 0.0.0.0
    listen_port = 4965
    ingress_control = Yes
    ic_max_held_announces = 256
    ic_burst_hold = 60
    ic_burst_freq_new = 3.5
    ic_burst_freq = 12
    ic_pr_burst_freq_new = 3.5
    ic_pr_burst_freq = 12
    egress_control = No
    ec_pr_freq = 5
    ic_new_time = 7200
    ic_burst_penalty = 300
    ic_held_release_interval = 30
```

Defaults:

| Key | Default | Meaning |
|-----|---------|---------|
| `ic_burst_hold` | `15` s | How long a bursting interface is held |
| `ic_burst_penalty` | `15` s | Extra hold added per repeated burst |
| `ic_held_release_interval` | `5` s | Interval between releasing held announces |
| `ic_burst_freq_new` | `3` /s | Announce rate that marks a new interface as bursting |
| `ic_burst_freq` | `10` /s | Announce rate that marks an established interface as bursting |
| `ic_pr_burst_freq_new` | `3` /s | Path-request rate threshold for new interfaces |
| `ic_pr_burst_freq` | `8` /s | Path-request rate threshold for established interfaces |

The remaining keys in the example already match their defaults.

Ingress control is on by default for Auto, Backbone, TCP client/server, UDP,
and I2P interfaces, and off for local, serial, KISS, RNode, and Pipe-style
interfaces. Dynamic interfaces spawned by a server inherit the full
ingress-control config of their parent.

## Linux socket marking

A node can apply one nonzero `SO_MARK` to every IP socket it owns, for routing
or firewall policy:

```ini
[reticulum]
  underlay_mark = 51820
```

The mark is set before outbound TCP connects and before UDP sends, and kept
across reconnects. It covers TCP client/server, UDP, Auto, Backbone, I2P SAM,
TCP-backed RNode, probe/STUN, and direct-UDP sockets created by `rns-net`.
Startup fails if the mark cannot be applied, so the process needs the Linux
capability for `SO_MARK` or equivalent privilege.

Only sockets owned by `rns-net` are marked. DNS resolver traffic, subprocesses
behind a `PipeInterface`, and external carriers such as an I2P router are not.
A full-tunnel application must add its own bypass rules for those, or refuse
the configuration. `rntun` does this; see the
[design document](rntun-design.md).

## Hooks

Hooks declared in a `[hooks]` section are loaded at startup from the path
given there:

```ini
[hooks]
  [[log_announce]]
    path = /opt/rns/hooks/log_announce.wasm
    type = wasm
    attach_point = AnnounceReceived
    priority = 5
    enabled = Yes
```

See [Hooks](hooks.md) for attach points, verdicts, and runtime management.

## `rns-server.json`

When the node runs under `rns-server`, a second file in the same directory
holds the product config: control-plane bind and auth, log retention,
statistics retention and database path, the hooks directory, and optional
overrides for the role binaries. It is edited through the API or UI and
described in the [operator runbook](rns-server-operator-runbook.md#files-and-paths).
