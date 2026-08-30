# `rntun`: IP tunnelling over Reticulum

Status: implementation in progress; privileged acceptance and release hardening
remain, and unresolved product decisions are tracked below

## Purpose

`rntun` carries layer-3 IP packets between a client and an authorized gateway
over an authenticated Reticulum Link. Each `rntun` process owns a private,
in-process `RnsNode` used only by the tunnel product. Version 1 does not connect
to or depend on an existing shared `rnsd`; this gives `rntun` direct control of
its Reticulum interfaces, underlay sockets, lifecycle, and failure handling.
It does not change Reticulum routing semantics.

The implementation must compile for Linux and Android. Platform-neutral
protocol, policy, and session code must not depend on Linux TUN APIs. Linux and
Android supply separate packet-device and route-configuration adapters.

## Initial scope

Version 1 provides:

- a standalone `rntun` Linux binary with `listen` and `connect` modes;
- a private in-process Reticulum node with dedicated configuration and state;
- IPv4 layer-3 tunnelling (no Ethernet/TAP frames);
- multiple clients connected to one gateway;
- static identity-to-address assignments;
- split-tunnel routes, with full-tunnel operation requiring explicit permission
  at both endpoints;
- a deny-all gateway policy by default;
- Reticulum identity authentication and per-client authorization;
- a portable Rust library that cross-compiles for Android;
- an Android adapter contract in which `VpnService` creates the TUN file
  descriptor and passes it to Rust.

Not in version 1:

- layer-2 bridging, broadcast Ethernet, or TAP support;
- anonymous access or an implicit allow-all mode;
- dynamic address pools or a persistent lease database;
- IPv6 payloads;
- transparent DNS interception, proxying, or split-domain DNS routing;
- automatic gateway firewall/NAT mutation;
- roaming between multiple gateways;
- a user-facing Android application.

The Android library and host contract are part of version 1; packaging a full
Android UI can be a separate project or milestone.

## Process architecture

On a gateway host:

```text
rntun listen
├── private in-process RnsNode
│   ├── dedicated Reticulum configuration and state
│   └── tunnel underlay interfaces
├── gateway destination and client sessions
└── TUN file descriptor
```

On a desktop client:

```text
rntun connect <destination>
├── private in-process RnsNode
│   ├── dedicated Reticulum configuration and state
│   └── tunnel underlay interfaces
├── one gateway Link
└── TUN file descriptor
```

On Linux, the `rntun` process needs the privileges required to open and
configure the TUN device, install policy-routing rules, and apply the configured
underlay socket mark. Privileges should be minimized or dropped after setup
where the platform permits it. Running the private node as a supervised child
process, or connecting to an existing shared instance, may be considered later
as alternative backends; neither is part of the version 1 contract.

The private node must not silently discover and reuse the normal user or system
Reticulum configuration. `rntun` owns a dedicated node configuration and storage
directory, and starts only the interfaces declared there. Operators must not
configure the private node and another local node to contend for an exclusive
serial device, listener address, or other non-shareable interface resource.

## Crate and module layout

Add a workspace crate named `rns-tun`, producing a library and the `rntun`
binary:

```text
rns-tun/
├── Cargo.toml
└── src/
    ├── lib.rs                 portable public API
    ├── protocol.rs            bounded wire encoding and decoding
    ├── session.rs             client/gateway state machines
    ├── policy.rs              identity ACL and route authorization
    ├── packet.rs              IP validation and fragment reassembly
    ├── reticulum.rs           owned private RnsNode and bounded callbacks
    ├── transport.rs           packet authorization and Link fragmentation
    ├── runtime.rs             status and runtime coordination
    ├── platform.rs            packet-device/configuration traits
    ├── linux.rs               Linux TUN, routing, DNS, and ownership journal
    ├── client.rs              Linux client negotiation and forwarding
    ├── gateway.rs             Linux multi-client gateway
    └── bin/rntun.rs           desktop command-line application
```

Android C-ABI glue is isolated in the companion `rns-tun-android` crate.

The library must compile without the Linux module on Android. Android-facing
FFI/JNI glue should remain thin and must call the same portable session engine.

Two abstractions keep the core portable:

- `PacketDevice`: reads and writes complete IP packets. Linux implements it by
  opening `/dev/net/tun`; Android implements it around a file descriptor
  returned by `VpnService.Builder.establish()`.
- `TunnelConfigurator`: applies and verifies the negotiated address, MTU,
  routes, full-tunnel fail-closed state, and DNS settings. Linux and Android
  provide platform-specific implementations; Android configures these values
  through `VpnService.Builder` before establishing the descriptor.

The session engine must also be usable independently of the command-line parser
so an Android host can embed it.

## Destination and connection lifecycle

The gateway registers and announces the `rntun.gateway` destination. Its
destination hash is the client-facing connection identifier.

Client lifecycle:

1. Load the dedicated node configuration and start the private `RnsNode`.
2. Load or create the client application identity.
3. Resolve or request a path to the supplied gateway destination hash.
4. Establish a Reticulum Link.
5. Identify on the Link.
6. Send `ClientHello` with protocol capabilities and requested routes.
7. Receive `ServerAccept` or `ServerReject`.
8. Configure the packet device, routes, and any required full-tunnel DNS and
   fail-closed state only after acceptance.
9. Forward packets until the Link closes or the host stops the session.
10. Remove client-owned routes, close the packet device, and stop the private
    node deterministically.

Gateway lifecycle:

1. Load the dedicated node configuration and start the private `RnsNode`.
2. Load a stable gateway application identity.
3. Load and validate the policy. An empty policy is valid and denies everyone.
4. Register and announce the gateway destination.
5. Accept an inbound Link into a bounded, unauthenticated pending state.
6. Require `LINKIDENTIFY` before processing a tunnel handshake.
7. Look up the verified identity in the policy.
8. Intersect the client's requested routes with its authorization.
9. Reserve the statically assigned address and create the active session.
10. Reject or expire unidentified, unauthorized, duplicate, and idle sessions.

## Authorization policy

The invariant is: **no configured client means no tunnel access**.

There is no implicit anonymous mode in version 1. A development-only override,
if ever added, must require an unmistakable command-line flag, print a warning,
and be unavailable in normal configuration.

Example gateway configuration:

```toml
[gateway]
address = "10.77.0.1/24"
dns_servers = ["10.77.0.1"]
identify_timeout_seconds = 10
max_pending_links = 16
max_active_sessions = 64

[clients."a1b2c3d4..."]
enabled = true
address = "10.77.0.2"
allow_routes = ["10.20.0.0/16"]
allow_internet = false
allow_client_to_client = false
max_sessions = 1
```

Policy validation rejects duplicate addresses, invalid prefixes, addresses
outside the gateway subnet, overlapping assignments, and contradictory route
permissions.

For every packet received from a client, the gateway verifies:

- the session is active and bound to the identified Reticulum identity;
- the IPv4 source equals the address assigned to that identity;
- the destination is within an authorized route;
- internet/default-route traffic is authorized separately;
- client-to-client traffic is authorized for both the source and destination.

Packets received from the gateway TUN device are delivered only to the active
session owning the destination address. Unknown destinations are dropped. These
checks are required even when host firewall rules also exist.

Policy reload should be atomic. Removed or materially restricted identities are
disconnected; unchanged sessions remain active.

## Protocol version 1

Control and packet data use a dedicated `rntun` message namespace over a
Reticulum Link. No `rnsh` message types or stream protocol are reused.

The control state machine is:

```text
PendingLink -> Identified -> Negotiating -> DeviceSetup -> Active -> Closing
                  |              |
                  +----Reject----+
```

Control messages:

- `ClientHello`: protocol versions, capabilities, maximum IP packet size, and
  requested routes;
- `ServerAccept`: selected version, session epoch, assigned address/prefix,
  gateway address, accepted routes, accepted DNS servers, packet MTU, and timer
  values;
- `ServerReject`: stable reason code and optional bounded diagnostic text;
- `ClientReady`: confirmation that the accepted packet device and its inbound
  writer are ready;
- `ServerReady`: confirmation that the gateway processed `ClientReady` and the
  client may begin submitting outbound packet data;
- `Ping` / `Pong`: liveness and RTT sampling;
- `Close`: stable reason code.

Data messages:

- `PacketFragment`: session epoch, packet identifier, total packet length,
  fragment offset, fragment length, flags, and payload.

All decoders must impose bounds before allocation. Unknown message types and
unsupported versions fail closed. Reassembly is bounded by session count,
packet count, total bytes, maximum packet length, and expiry time.

The default Reticulum MTU is smaller than a normal IP packet, so application
fragmentation is required. Version 1 should use a conservative TUN MTU (for
example 1280) while still validating and fragmenting each packet against the
negotiated Link payload size. Fragment loss discards the incomplete IP packet;
it must not leave unbounded state.

Decision recorded 2026-08-26: control messages use a reliable, ordered Channel
over the authenticated Link. `PacketFragment` messages use direct Link data with
a dedicated `rntun` context instead of the Channel, avoiding Channel-level
head-of-line blocking between independent IP packets. Direct Link data may
require a small bounded-admission and delivery-feedback extension in `rns-net`.
The Phase 0 spike validates that API and measures loss, latency, memory pressure,
and TCP throughput over a constrained simulated Reticulum path; it does not
reopen the Channel-versus-direct-data choice.

## Concurrency and backpressure

Reticulum callbacks and the driver thread must never block on TUN I/O.

Use bounded queues between:

- Reticulum events and each session;
- packet-device reads and the encoder;
- decoded packets and packet-device writes.

Queue saturation drops complete IP packets, not arbitrary fragments. Expose
counters for malformed packets, unauthorized packets, queue drops, incomplete
reassemblies, and bytes/packets in each direction. Session teardown cancels all
workers and releases queued buffers.

## Linux integration

The Linux adapter:

- opens a TUN device in layer-3, no-packet-info mode;
- applies the negotiated address, prefix, and MTU;
- installs only routes explicitly allowed by local client configuration;
- records every route it creates and removes only those routes on teardown;
- supports receiving an already-open file descriptor for tests and service
  managers.

Gateway IP forwarding, firewalling, and NAT remain operator-controlled in
version 1. Documentation may provide `nftables` examples. `rntun` must not
silently enable forwarding or install masquerade rules.

Full-tunnel operation requires both:

- gateway policy granting `allow_internet = true`; and
- explicit client configuration such as `--default-route`.

Full-tunnel mode also has a fail-closed DNS and routing contract. `ServerAccept`
provides a bounded list of IPv4 DNS servers. The client either explicitly
permits an advertised server or selects a locally configured server; it must not
silently accept a server outside its local DNS policy. At least one approved DNS
server is required. DNS remains ordinary IP traffic over the tunnel; version 1
does not intercept port 53 or proxy DNS inside the control protocol.

The initial Linux DNS backend is `systemd-resolved`. Before `ClientReady`, the
adapter assigns the approved servers and route-only domain `~.` to the TUN link,
flushes relevant resolver caches, and verifies the resulting per-link state. A
host without the supported resolver backend cannot start version 1 full-tunnel
mode. Editing `/etc/resolv.conf` directly is not a fallback.

All unmarked IPv4 traffic uses the tunnel table. That table retains an
unreachable or blackhole default while the session reconnects so lookup cannot
fall through to the physical default route; only the marked private-node
underlay uses the preserved physical table. Because version 1 does not carry
IPv6 payloads, it also blocks unmarked IPv6 for the lifetime of a full-tunnel
session. This prevents DNS and general traffic from bypassing the IPv4 tunnel.
Intentional teardown restores only state owned by the current `rntun` instance.
Durable ownership and crash reconciliation are specified under O-13.

## Android integration

Android owns VPN consent and TUN creation. The Android host must:

1. call `VpnService.prepare()` and obtain user consent;
2. run the active VPN as a foreground service where required;
3. construct `VpnService.Builder` with the accepted address, routes, approved
   DNS servers, MTU, and optional allowed/disallowed applications;
4. call `establish()` and pass the resulting file descriptor to Rust;
5. arrange for every IP socket opened by the private `RnsNode` to be passed to
   `VpnService.protect()` before it connects or sends traffic;
6. notify Rust and close the session when permission is revoked or the service
   is destroyed.

Because Android needs negotiated configuration before it can establish the
final TUN interface, the Android host starts the Reticulum session first,
receives `ServerAccept`, builds the interface, and then marks packet forwarding
ready. The gateway must tolerate this bounded setup interval.

For a full-tunnel profile, the Android host adds every approved resolver with
`VpnService.Builder.addDnsServer()`, routes covered application traffic through
the VPN, does not enable IPv6 bypass, and keeps the established VPN in a
fail-closed state while the Reticulum session reconnects. The DNS-leak guarantee
applies to applications covered by the VPN; explicitly excluded applications
remain outside it. Failure to apply or verify any required setting prevents
`ClientReady`.

The Rust Android API must accept an owned or duplicated file descriptor with
explicit ownership rules. It must not assume `/dev/net/tun`, shell commands,
systemd, Unix signals, or writable conventional home directories.

Android build acceptance starts with:

```text
cargo check --target aarch64-linux-android -p rns-tun --lib
```

Additional Android ABIs can be added after the primary target is green. A small
instrumented Android host test should eventually establish a `VpnService`
descriptor, pass it through the native boundary, exchange a packet with the
Rust engine, and stop without leaking the descriptor or service.

## Configuration and CLI

Initial commands:

```text
rntun listen [--config PATH] [--print-destination]
rntun connect <destination-hash> [--config PATH] [--route CIDR ...]
rntun connect <destination-hash> --default-route [--dns ADDRESS ...]
rntun identity [--config PATH]
```

The application identity is separate from the private node's transport identity.
Both live under `rntun`'s dedicated state, and the node reads an explicitly
selected `rntun` Reticulum configuration rather than implicitly reusing the
user's normal `rnsd` configuration directory. Client route configuration is an
allowlist: server-advertised routes not permitted locally are not installed.

Logs and status must distinguish path discovery, Link authentication, policy
acceptance, tunnel readiness, and packet forwarding. Rejection logs include the
identity hash and stable reason but never private key material or raw packet
contents.

## Implemented wire allocation and bounds

The version 1 implementation uses Channel message type `0x5254` for every
control message and direct Link context `0x0f` for packet fragments. Both frame
families begin with ASCII magic `RNTU`, followed by version byte `1`, a kind
byte, and a big-endian zero flags field. Unknown versions, kinds, or flags fail
closed. Control kinds `1` through `9` are `ClientHello`, `ServerAccept`,
`ServerReject`, `ClientReady`, `ServerReady`, `Ping`, `Pong`, `Close`, and
`CloseAck`; direct fragment kind is `0x20`.

Version 1 bounds control frames to 384 bytes, diagnostics to 128 UTF-8 bytes,
routes to 32, DNS servers to 4, IPv4 packets to 1500 bytes, and tunnel fragments
to 32 per packet. A session retains at most 32 concurrent reassemblies and
48,000 reassembly bytes for 30 seconds, plus 1,024 completed packet identifiers
for replay rejection. Session epochs are nonzero random `u64` values. Packet
identifiers never wrap within an epoch; exhaustion requires a new session.
Duplicate fragments with identical bytes are idempotent, while partial overlap,
contradictory overlap, stale epochs, completed-identifier reuse, and invalid
ranges are rejected.

`rns-net::RnsNode::try_send_link_datagram` provides bounded driver admission.
Success means the active Link encrypted and encoded the payload and admitted it
to driver dispatch; it is not a remote-delivery acknowledgement. Queue-full,
stopped-driver, timeout, missing/inactive Link, oversized payload, encryption,
and encoding failures are distinct results. IP packets remain best effort.

## Current implementation boundary

As of 2026-08-30, the workspace contains the portable codec, policy and session
state machines; strict IPv4 validation and replay-safe reassembly; private-node
startup; Linux client reconnect and multi-client gateway forwarding; atomic
policy reload; TUN, split/full policy routing, `systemd-resolved` setup, IPv6
prohibition, durable cleanup journal, live status socket, and an Android C ABI
that negotiates before accepting an owned or duplicated `VpnService` TUN
descriptor. Android underlay sockets fail closed through an exclusive host
`VpnService.protect()` callback installed in `rns-net`.

This is not yet a release-complete claim. Linux network-namespace acceptance,
forced-crash reconciliation tests, DNS/IPv6 leak tests, constrained-link MTU
benchmarks, fuzzing, and an instrumented Android `VpnService` test remain. The
local Android Rust target is installed, but the cross-check requires an Android
NDK clang toolchain that is not present in the current development environment.

## Open design items

The overall architecture and security model are accepted as the working basis,
but the items in this section are intentionally unresolved. Each item must be
discussed and its decision recorded in this document before the stated gate.
Stable IDs allow implementation notes, tests, and later decisions to refer to an
item without relying on section line numbers.

### O-01: Linux full-tunnel underlay protection

Status: resolved; implementation and end-to-end verification remain Phase 3
work.

Installing a default route through the client TUN can also capture the traffic
used by the private node's Reticulum interfaces, recursively carrying
Reticulum's underlay inside `rntun`. Every supported platform therefore needs an
explicit underlay-protection contract.

Decide whether Linux version 1 uses policy routing and marks, explicit retained
routes to every underlay endpoint, a separate network namespace, or another
mechanism. The decision must account for underlay peers changing while the
tunnel is active. If no reliable mechanism is available, Linux full-tunnel mode
must remain unsupported rather than relying on a best-effort exception list.

Resolution gate: before Phase 3 full-tunnel implementation. Add an end-to-end
test and a Linux equivalent of the Android underlay security invariant.

Decision recorded 2026-08-25 and revised 2026-08-26: each version 1 `rntun`
process owns a private, in-process `RnsNode` used only for the tunnel. Connecting
to an existing shared `rnsd` is not a version 1 backend. `rns-net` supports a
nonzero `[reticulum] underlay_mark` that is applied with Linux `SO_MARK` to IP
underlay sockets before connect or send and across reconnects. `rntun` passes
the mark directly when starting its node, uses a separate tunnel routing table,
and installs a higher-priority mark rule that sends marked traffic through the
preserved physical table. Full-tunnel startup must fail unless the configured
mark is nonzero, the node has verified that it can apply it, and the corresponding
policy-routing rule is installed.

The mark covers sockets owned by `rns-net`; it does not automatically cover
system resolver traffic, `PipeInterface` subprocesses, or external carrier
processes such as an I2P router. Private node ownership removes the need for a
shared-daemon verification RPC, but does not by itself protect those external
traffic sources.

Final version 1 decision recorded 2026-08-26: Linux full-tunnel mode uses a
strict fail-closed interface allowlist. It permits interfaces whose IP sockets
are owned and marked by `rns-net`, plus non-IP interfaces such as directly owned
serial devices. Every configured network endpoint must be a numeric IP address;
hostnames are rejected because system resolution, including resolution during a
reconnect, does not inherit the socket mark. `PipeInterface`, external carrier
processes such as an I2P router, and unknown or unclassified interface types are
rejected. Validation occurs before the default tunnel route is installed and
identifies each unsafe interface or endpoint. Version 1 has no override that
weakens this invariant. Protected name resolution and external-carrier support
may be added later without changing the tunnel protocol.

### O-02: post-accept readiness handshake

Status: resolved; implementation and state-machine tests remain Phase 1 work.

`ServerAccept` gives the client the configuration needed to create its packet
device. Android cannot create its final TUN descriptor until that message has
arrived, so acceptance does not imply that the client can receive packets.

Decision recorded 2026-08-26: version 1 requires both `ClientReady` and
`ServerReady`. After `ServerAccept`, the gateway reserves the accepted address
and session epoch but remains in `DeviceSetup`; the reservation is not an active
packet-dispatch session. The client creates its packet device, starts the inbound
device writer, keeps outbound device reading paused, and sends `ClientReady` over
the control Channel. On valid `ClientReady`, the gateway enters `Active`, sends
`ServerReady`, and may dispatch packets to the client. The client enters `Active`
and begins outbound packet submission only after receiving `ServerReady`.

Direct Link data may overtake the control acknowledgment. This is safe after
`ClientReady` because the client inbound writer already exists; `ServerReady`
gates only client-to-gateway packet submission. Gateway packets arriving before
`ClientReady` and client packets arriving before the gateway processes readiness
are dropped and counted. There is no early-packet queue. Repeated peer violations
close the session. Duplicate readiness messages are handled idempotently. A
bounded setup timeout, whose release value is selected under O-08, closes the
Link and releases the address reservation.

Resolution gate: before freezing the control state machine and control message
encoding in Phase 1.

### O-03: bidirectional packet authorization

Status: resolved; implementation and packet-policy tests remain Phase 1 work.

The current policy precisely checks packets entering the gateway from a client,
but packets read from the gateway TUN are selected only by destination address.
That leaves the intended authorization of return traffic and unsolicited inbound
traffic undefined.

Decision recorded 2026-08-26: accepted routes authorize ordinary unicast traffic
bidirectionally. Client-to-gateway packets must use the session's assigned client
address as their source and an accepted route as their destination.
Gateway-to-client packets must use an accepted route as their source and the
session's assigned client address as their destination. The gateway enforces
these rules before dispatch and the client independently enforces them before
writing to its packet device. A full-tunnel `0.0.0.0/0` grant accepts ordinary
unicast Internet sources but does not override the special-use exclusions below.

`rntun` provides routed rather than stateful-firewall semantics. Traffic from an
accepted route may be unsolicited; version 1 does not track flows to distinguish
replies from newly initiated traffic. Host and network firewalls remain
responsible for connection-level policy.

Version 1 rejects unspecified (`0.0.0.0/8`), loopback (`127.0.0.0/8`), IPv4
link-local (`169.254.0.0/16`), multicast (`224.0.0.0/4`), reserved
(`240.0.0.0/4`), limited broadcast, and directed-broadcast traffic in either
direction. Private, shared-address, documentation, and other ordinary unicast
ranges are allowed only when covered by an accepted route. Gateway-tunnel-address
access requires an explicit `/32` grant. Client-to-client traffic requires
explicit compatible authorization for both sessions and is otherwise rejected.

Destination Unreachable, Time Exceeded, and Parameter Problem ICMP errors may
use a source outside the accepted routes only when their outer destination is
the assigned client address and their structurally valid quoted IPv4 packet has
that client address as its source and an accepted route as its destination.
Redirects, malformed or insufficient quotations, and other source-exception
traffic are rejected.

Resolution gate: before Phase 1 packet-policy implementation. Add invariants and
tests for both tunnel directions.

### O-04: wire namespace and framing allocation

Status: resolved and implemented; the allocation and bounds are normative in
the section above.

The protocol needs concrete message identifiers rather than only a conceptual
`rntun` namespace. Channel message types share a `u16` space with existing
features, and generic Link data uses a shared `u8` context space.

Reserve the exact Channel message-type range for control messages and the exact
Link context for direct `PacketFragment` data. Define a magic value or equivalent
framing, version placement, and collision rules. Record all existing reserved
ranges and ensure unknown or misrouted application traffic cannot be decoded as
`rntun`.

Resolution gate: during Phase 0, before golden wire encodings are committed.

### O-05: `LINKIDENTIFY` and `ClientHello` ordering

Status: resolved and implemented. The gateway retains one bounded encoded hello
before identification, accepts only byte-identical duplicates, rejects a
conflicting second hello, and expires the pending Link after 30 seconds.

`LINKIDENTIFY` and application control messages may use different Link delivery
paths. The gateway can therefore observe a `ClientHello` before it receives the
remote-identification callback even when the client sent identify first.

Define whether a pre-identification hello is retained in a small bounded slot,
ignored and retried after an explicit signal, or rejected with a retryable reason.
The rule must not create an unbounded unauthenticated queue or turn ordinary
reordering into a permanent authorization failure.

Resolution gate: before Phase 1 session transitions are finalized. Add explicit
reordering and identify-timeout tests.

### O-06: normative route semantics

Status: resolved and implemented. CIDR intersection selects the narrower
contained prefix, results are sorted/deduplicated and contained routes removed,
and both the configured local allowlist and the explicit request must contain
every accepted route. `allow_internet` and local `allow_default_route` are both
required for `0.0.0.0/0`. No route is implied beyond the configured TUN address;
split routes use destination policy rules. A reconnect must retain the active
address, gateway, routes, DNS, and MTU or it is rejected.

Define the route model precisely, including:

- the CIDR intersection algorithm when one prefix contains another;
- the wire and configuration representation of the bidirectional route grants
  selected under O-03;
- how `allow_internet` relates to requesting or configuring `0.0.0.0/0`;
- whether the assigned tunnel subnet and gateway address imply any route;
- normalization or rejection of duplicate, contained, and overlapping routes;
- conflicts with existing client routes, metrics, and routing tables;
- the exact meaning of the local client allowlist and its relationship to CLI
  `--route` requests; and
- whether a reconnect may replace a still-active session when `max_sessions = 1`.

Resolution gate: before Phase 1 policy types and the `ClientHello` / `ServerAccept`
route fields are frozen.

### O-07: IP parsing versus tunnel-fragment reassembly

Status: resolved and implemented. Native IPv4 fragments and options are
rejected; version, IHL, total length, header checksum, fragmentation flags,
TTL, addresses, and negotiated MTU are validated separately from bounded
`PacketFragment` reassembly.

Separate IPv4 packet validation from reassembly of `PacketFragment` messages in
terminology, modules, metrics, and limits. Decide whether native IPv4 fragments
are forwarded intact, rejected, or reassembled, and specify validation of total
length, header length, checksum, options, fragmentation fields, and the
negotiated packet MTU. Application fragmentation must never be confused with IP
fragmentation in code or operator output.

Resolution gate: before Phase 1 packet and reassembly APIs are finalized.

### O-08: protocol and capacity constants

Status: initial constants are implemented and recorded above. Constrained-link
benchmarking may still change the default requested MTU before version 1 is
declared stable, but cannot raise the wire maximum above 1500.

Choose and document hard limits for at least control-message size, diagnostic
text, requested and accepted route counts, maximum IP packet length, fragments
per packet, accepted DNS server count, concurrent reassemblies, reassembly
bytes, pending setup duration, idle duration, queue capacities, and global
versus per-session memory. State which values are wire constants, configurable
downward limits, or configurable capacity settings, and validate relationships
between them at startup.

Resolution gate: initial values are required for the Phase 0 spike; release
values must be fixed before protocol version 1 ships.

### O-09: exact wire encoding and fragment identifiers

Status: resolved and implemented by the normative allocation/bounds above and
the bounded big-endian codecs in `rns-tun/src/protocol.rs`.

Specify integer widths, byte order, field ordering, flags, canonical CIDR
encoding, optional-field encoding, and behavior for unknown capabilities and
flags. Define how session epochs and packet identifiers are generated, their
uniqueness requirements, wrap behavior, replay/stale-epoch handling, and the
rules for duplicate, overlapping, contradictory, or out-of-range fragments.

Resolution gate: during Phase 0, before golden encodings and fuzz targets become
normative.

### O-10: liveness, close, and reconnect semantics

Define which peer sends `Ping`, whether `Pong` echoes a nonce or timestamp, how
RTT is sampled, whether valid control or data traffic resets idle timers, and the
difference between idle and dead-peer timeouts. Define close acknowledgment or
timeout behavior, simultaneous close, teardown ordering, retryability by reason
code, and reconnect backoff and jitter.

Resolution gate: before Phase 1 session state machines are finalized.

### O-11: address and policy validation details

Status: resolved and implemented. Assignments reject the subnet network,
broadcast, gateway, duplicates, and addresses outside the gateway prefix.
Existing host address/route conflicts fail during typed Linux mutation rather
than being replaced. Client-to-client forwarding requires the source grant to
name the destination peer and the destination session independently to accept
the source route; either missing direction denies traffic.

In addition to duplicate client addresses, explicitly decide and validate
whether assignments may use the gateway address, subnet network address, subnet
broadcast address, or addresses conflicting with host configuration. Clarify
what "overlapping assignments" means while version 1 assigns individual IPv4
addresses. Define the precise two-sided meaning of `allow_client_to_client`.

Resolution gate: before the Phase 1 configuration schema is considered stable.

### O-12: atomic policy-reload behavior

Status: resolved and implemented. The gateway checks the policy file every two
seconds, parses and validates a complete replacement before swapping it, and
keeps the current policy on missing, unreadable, or invalid replacements.
Gateway-prefix/address changes are rejected. Any change to an active identity's
grant (including address, routes, internet, peer, enabled, or idle settings)
closes that session; additions affect only new sessions.

Define the reload trigger or triggers, parsing and validation sequence, and
behavior when a replacement policy is missing, unreadable, or invalid. The
currently active policy must remain intact on reload failure. Define which
changes are "material restrictions", how address changes are handled, and
whether newly eligible sessions are affected without reconnecting.

Resolution gate: before Phase 4 reload implementation.

### O-13: route ownership, crash recovery, and reconciliation

Status: implemented for exact-operation journaling; namespace acceptance still
needs to validate reconciliation against externally changed state.

Recording routes in process memory supports orderly teardown but cannot clean up
after `SIGKILL`, a crash, or power loss. Decide how routes and related network
objects are tagged or otherwise identified, how startup detects stale state, and
when it is safe to reconcile it. Cleanup must never remove a route that another
administrator or process now owns.

Decision in part recorded 2026-08-30: Linux full-tunnel setup writes a durable
ownership journal covering its routing rules and tables, unreachable defaults,
IPv6 block, TUN metadata, and `systemd-resolved` link settings. The exact journal
schema, object tagging, safe ownership checks, and reconciliation algorithm
remain unresolved under this item.

Implementation decision recorded 2026-08-30: schema 1 stores the owner PID,
TUN name, and the exact inverse argument vector after every successful mutation.
The mode-0600 file is atomically replaced and fsynced. Normal teardown and the
explicit `cleanup` command replay inverses in reverse order; cleanup refuses to
run while a different owning PID is alive, retains the journal if any inverse
fails, and never flushes an entire routing table. Startup refuses to overwrite
an existing journal. Privileged tests must still prove behavior when an
administrator replaces an otherwise identical object after a crash.

Resolution gate: before Phase 3 Linux acceptance tests are finalized.

### O-14: Linux privilege and configuration mechanism

Status: implemented provisionally; privileged acceptance remains. Linux uses
direct, argument-vector `ip` and `resolvectl` execution without a shell. It
supports opening `/dev/net/tun` or taking/duplicating an inherited descriptor;
the process configures either form. Deployments require access to the TUN
device and `CAP_NET_ADMIN` (including `SO_MARK`). Version 1 does not yet drop
capabilities after setup because reconnect and teardown still require them.

Choose the Linux configuration API, preferably without constructing shell
commands from configuration. Define required device permissions and capabilities,
support for an inherited descriptor, which party configures an inherited device,
and whether or when privileges are dropped after setup. Document expected
behavior under systemd and unprivileged service accounts.

Resolution gate: before Phase 3 Linux adapter implementation.

### O-15: portable crate features and Android dependency boundary

Status: resolved and implemented. Linux CLI/runtime code is target-gated;
`node-standard` and the smaller `android-node` feature sets are separate; thin
C ABI and descriptor ownership live in `rns-tun-android`.

Define Cargo features and target gates so the portable session library does not
pull Linux CLI, TUN, signal, service-manager, or unnecessary Reticulum interface
dependencies into Android builds. Decide whether JNI/C-ABI glue belongs in
`rns-tun` or a small companion crate. Verify both the default and minimal feature
sets in CI.

Resolution gate: choose the initial feature layout in Phase 0 and keep the
Android cross-check green in every later phase.

### O-16: Reticulum send admission and transport feedback

Status: resolved and implemented as driver-level admission, described above.
No per-packet delivery acknowledgement is added for best-effort IP data.

Direct Link data is selected for `PacketFragment` transport. The Phase 0 spike
must determine how the session engine learns whether a fragment was admitted,
dropped before transmission, delivered, or timed out. The current generic Link
send API can accept work into the driver queue without reporting eventual
delivery. Decide what feedback and bounded admission API `rntun` requires and
whether this needs a small `rns-net` extension.

Resolution gate: part of the Phase 0 direct-Link-data API validation.

### O-17: configuration, identity, and operational contract

Status: implemented for the version 1 CLI surface. The application config,
private-node config, state, client/gateway identities, status socket, and
mode-0600 ownership records are separate. CLI `--route`, `--default-route`, and
`--dns` narrow/request or explicitly enable configured permissions but cannot
expand the gateway policy. SIGINT/SIGTERM trigger owned-state teardown; status
is bounded JSON over a mode-0600 Unix socket.

Define default paths separately for the Reticulum configuration directory,
`rntun` application configuration, gateway identity, and client identity. Specify
creation and file-permission requirements, behavior in environments without a
conventional home directory, configuration precedence between file and CLI,
identity-hash syntax, announce cadence and app data, signal handling, and the
minimum status/counter interface promised by version 1.

Resolution gate: defaults before Phase 3 CLI implementation; the operational
surface must be fixed before Phase 6 release readiness.

### O-18: expanded regression coverage

As the preceding items are resolved, add explicit coverage for identify/hello
reordering, traffic before client readiness, inbound source authorization,
special-use IPv4 addresses, packet-identifier wrap or reuse, Linux underlay
preservation, existing-route conflicts, invalid-policy reload rollback, abrupt
process death and startup reconciliation, IPv4 checksum and header-length
validation, send-admission failure, DNS-state restoration, reconnect-time
fallback prevention, and IPv6 leak blocking. Each resolved item should link to
its corresponding tests or update the test matrix below.

Resolution gate: tests land with the phase that implements the affected item;
all are required or explicitly waived with rationale before Phase 6 exits.

### O-19: full-tunnel DNS and fallback protection

Status: resolved; Linux implementation and tests remain Phase 3 work and Android
host implementation and tests remain Phase 5 work.

Application DNS can escape a nominal IPv4 full tunnel through retained resolver
configuration, a physical-interface-specific route, reconnect fallback, or the
host's IPv6 connectivity. Resolver selection alone is therefore insufficient.

Decision recorded 2026-08-30: `ServerAccept` contains a bounded list of IPv4 DNS
servers. Full-tunnel startup requires at least one server allowed by the local
client DNS policy. DNS is carried as ordinary tunneled IP traffic; version 1 does
not transparently intercept or proxy it. The client applies and verifies DNS,
fail-closed IPv4 routing, and IPv6 blocking before sending `ClientReady`.

Linux version 1 supports `systemd-resolved` by assigning the approved servers and
route-only domain `~.` to the TUN link. It does not edit `/etc/resolv.conf` as a
fallback. Unmarked IPv4 cannot fall through to the physical routing table, an
unreachable tunnel default remains during reconnect, and unmarked IPv6 is
blocked because IPv6 payload tunnelling is not supported. Marked private-node
underlay remains able to reconnect. Android supplies the approved servers to
`VpnService.Builder`, prevents IPv6 bypass for covered applications, and retains
the VPN in a fail-closed reconnect state. Explicitly excluded Android
applications are outside the guarantee.

Orderly teardown restores only owned state. Linux persists sufficient ownership
metadata for startup reconciliation as required by O-13. Split-tunnel mode does
not change system DNS and provides no domain-based DNS isolation in version 1.

Resolution gate: before claiming full-tunnel support on either platform. Tests
must cover hard-coded IPv4 DNS, retained physical DNS, Link loss and reconnect,
IPv6 DNS and general IPv6 bypass, setup failure, orderly restoration, and stale
state reconciliation.

## Implementation phases

### Phase 0: protocol and transport spike

- Add this design document and threat/limit constants.
- Prototype control messages and bounded packet fragmentation.
- Validate direct Link data under constrained paths and define any bounded
  admission and delivery-feedback extension required in `rns-net`.
- Verify existing `rns-net` dependencies for `aarch64-linux-android`.

Exit criteria: the wire approach, hard limits, and any required `rns-net` API
extension are decided; a minimal portable crate cross-checks for Android.

### Phase 1: portable protocol, policy, and state machines

- Add bounded codecs for every version 1 message.
- Add client and gateway session state machines.
- Add static identity ACL parsing and validation.
- Add IPv4 parsing, anti-spoof checks, route authorization, fragmentation, and
  reassembly.
- Add abstract clocks and packet devices for deterministic tests.

Exit criteria: unit tests cover all state transitions and deny-by-default
behavior; malformed input cannot trigger unbounded allocation; Android library
cross-check remains green.

### Phase 2: Reticulum application integration

- Start and own a private `RnsNode` from the dedicated `rntun` node
  configuration and state directory.
- Implement gateway destination registration and announces.
- Implement path request, Link creation, `LINKIDENTIFY`, handshake, and close.
- Keep callbacks non-blocking through bounded queues.
- Implement one client and one gateway using in-memory packet devices.

Exit criteria: two local `rntun` instances, each with a private node, establish
an authorized tunnel and exchange synthetic IP packets; unidentified and
unconfigured identities are rejected; stopping either instance also stops its
node and releases its node resources.

### Phase 3: Linux TUN client

- Implement Linux `PacketDevice` and route configuration.
- Add `rntun connect`, identity handling, cleanup, reconnect, and status.
- Test split routes before full-tunnel routing.
- Implement and verify `systemd-resolved` per-link DNS, fail-closed IPv4 routing,
  reconnect protection, unmarked IPv6 blocking, and owned-state restoration.

Exit criteria: a Linux client reaches a synthetic remote subnet through the
gateway and restores its routing state on clean exit and forced Link loss. Full
tunnel is not accepted until DNS and general traffic cannot escape over physical
IPv4 or IPv6 during setup, active forwarding, or reconnect.

### Phase 4: multi-client Linux gateway

- Implement a shared gateway TUN device and destination-to-session dispatch.
- Enforce address ownership, route permissions, session limits, timeouts, and
  client isolation.
- Add atomic policy reload and operational counters.
- Document forwarding and `nftables`/NAT setup without applying it implicitly.

Exit criteria: authorized clients receive only their assigned traffic; default
deny, spoofing, duplicate-address, forbidden-route, and cross-client tests pass.

### Phase 5: Android host adapter

- Stabilize the Rust embedding API and file-descriptor ownership contract.
- Add minimal JNI or C-ABI glue without moving protocol logic out of Rust.
- Provide a reference `VpnService` integration or a dedicated Android example.
- Handle consent, foreground lifecycle, underlay protection, TUN setup, stop,
  and reconnect.
- Apply negotiated DNS and prevent IPv6 or reconnect fallback for applications
  covered by a full-tunnel VPN.

Exit criteria: Android cross-compilation is in CI and an instrumented device or
emulator test exchanges packets through a `VpnService` descriptor.

### Phase 6: hardening and release readiness

- Fuzz or property-test codecs, IP validation, and reassembly.
- Exercise slow links, loss, duplication, reordering, reconnects, and queue
  saturation.
- Add Linux network-namespace end-to-end tests for routing and optional NAT.
- Document security assumptions, capacity limits, troubleshooting, and recovery.

Exit criteria: workspace tests and formatting pass, Android cross-check passes,
privileged end-to-end tests pass in their supported environment, and every
security invariant below has a regression test.

## Required security invariants

- Empty or missing client policy denies every tunnel session.
- No address or route is granted before verified `LINKIDENTIFY` authorization.
- A session cannot change identity after negotiation starts.
- A client cannot emit a source address it does not own.
- A client cannot reach a route not granted by gateway policy.
- A gateway cannot install a client route not allowed by local client policy.
- Full-tunnel routing requires explicit authorization at both endpoints.
- Pending links, queues, packets, fragments, sessions, and diagnostics are
  bounded.
- Malformed traffic fails closed without blocking the Reticulum driver.
- Teardown removes only resources created by the current session.
- Linux underlay traffic cannot recursively enter the tunnel routing table.
- Android underlay traffic cannot recursively enter the VPN interface.
- Full-tunnel application DNS and ordinary traffic cannot fall back to physical
  IPv4 or IPv6 during setup, active forwarding, or reconnect.
- A client cannot report ready until required DNS and fail-closed routing state
  has been applied and verified.

## Test matrix

Every phase adds tests at the lowest practical layer:

- protocol: golden encodings, version mismatch, truncation, oversized fields,
  unknown types, and allocation bounds;
- policy: empty policy, unknown/disabled identity, duplicate address, route
  intersection, full-tunnel permission, and reload revocation;
- packet path: source spoofing, unauthorized destinations, fragment overlap,
  duplicate/missing fragments, expiry, and saturation;
- session: identify timeout, re-identification, duplicate session, reconnect,
  stale epoch, close ordering, and device failure;
- integration: private-node client/gateway exchange with fake devices and
  deterministic node teardown;
- Linux: TUN and network-namespace routing, cleanup, client isolation, NAT,
  hard-coded and system DNS, reconnect fallback, IPv6 blocking, and stale-state
  reconciliation;
- Android: cross-compile on every change and instrument the descriptor lifecycle
  when an Android test environment is available, including DNS selection and
  IPv6/reconnect leak prevention.

## Decisions intentionally deferred

- Dynamic address allocation and durable leases.
- IPv6 payload support.
- Split-domain and other split-tunnel DNS configuration.
- Gateway discovery aliases beyond an explicit destination hash.
- Alternative node backends, including an owned child process or connection to
  an existing shared `rnsd`.
- Supervision of the complete `rntun` process by `rns-server` or another service
  manager.
