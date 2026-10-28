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
requests, and link requests. Neither Python Reticulum nor this implementation
exposes a configuration file key for them: the behaviour is fixed at build
time by constants in `rns-core/src/constants.rs` that mirror the upstream
`Transport` class attributes. The defaults match upstream at the current
parity target. The two emission flags can additionally be switched at runtime
on a running node, see below.

| Constant | Default | Effect |
|----------|---------|--------|
| `STAMP_DESTINATIONS` | `false` | Stamp announces emitted by this instance (target value `DESTINATION_STAMP_VALUE`, 23) |
| `STAMP_PRS` | `false` | Stamp path requests emitted by this instance (target value `PATH_REQUEST_STAMP_VALUE`, 19) |
| `STAMP_LRS` | `true` | Stamp outbound link requests to destinations that announced a non-zero link cost |
| `LR_STAMPS_ENFORCED` | `false` | Reject inbound link requests whose stamp is missing or below the required cost |
| `LINK_REQUEST_STAMP_COST` | `11` | Required link request cost when a destination announces none |
| `LINK_COST_CAP` | `40` | Hard cap on an announced link request cost |
| `LINK_STAMP_TIMEOUT` | `15` | Seconds allowed for grinding a stamped link request key before the link fails |

With these defaults a node validates inbound announce and path request stamps,
records announced link costs, and grinds a stamped link request key when a peer
asks for one, but emits no stamped announces or path requests and refuses
nothing for lack of a stamp. Stamped link request keys are ground on a worker
thread so the driver stays responsive. The only runtime stamp setting is the
per-interface `discovery_stamp_value` for discovery announces, described in
[Interface Discovery](interface-discovery.md#advertised-locations).

Stamps for emitted announces and path requests follow the upstream stamper
queue. A single lazily started worker thread drains two bounded queues, path
requests before announces, each holding at most 32 jobs; a newer job for the
same destination (and interface, for path requests) replaces the queued one,
and a full queue drops the job with a debug log. With `STAMP_DESTINATIONS` an
announce for a destination without a persisted stamp returns at once and the
worker grinds the stamp, persists it under `storage/stamps/`, and emits the
announce; later announces for that destination reuse the stored stamp
synchronously. With `STAMP_PRS` the node's own path requests, and unstamped
requests forwarded on behalf of local clients, wait for the worker; generated
path request stamps are cached by destination and tag (256 entries) so one
grind serves a request relayed on several interfaces. None of this runs while
both flags are off, which is the upstream default.

The two emission flags are exposed as runtime config keys so a node can be
switched to stamped emission without a rebuild, for interoperability testing
or ahead of the network turning enforcement on:

```bash
rns-ctl config get global.stamp_destinations         # false by default
rns-ctl config set global.stamp_path_requests true
rns-ctl config reset global.stamp_path_requests
```

Both keys apply immediately and reset to the compile-time default. A valid
inbound stamp is observable on the receiving side: `/api/identity/<hash>`
(and the known-destinations RPC) report the recorded `stamp_value` and the
announced `lr_cost`, and every interface counts validated inbound path request
stamps as `stamped_path_requests` in `/api/interfaces`, the RPC interface
stats, and the management export.

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
