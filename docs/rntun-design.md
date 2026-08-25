# `rntun`: IP tunnelling over Reticulum

Status: proposed implementation plan; unresolved decisions are tracked below

## Purpose

`rntun` carries layer-3 IP packets between a client and an authorized gateway
over an authenticated Reticulum Link. It follows the same deployment pattern as
other Reticulum applications: it is a separate application that connects to a
local shared Reticulum instance. It is not an `rnsd` hook and does not change
Reticulum routing semantics.

The implementation must compile for Linux and Android. Platform-neutral
protocol, policy, and session code must not depend on Linux TUN APIs. Linux and
Android supply separate packet-device and route-configuration adapters.

## Initial scope

Version 1 provides:

- a standalone `rntun` Linux binary with `listen` and `connect` modes;
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
- automatic DNS interception;
- automatic gateway firewall/NAT mutation;
- roaming between multiple gateways;
- a user-facing Android application.

The Android library and host contract are part of version 1; packaging a full
Android UI can be a separate project or milestone.

## Process architecture

On a gateway host:

```text
rns-server or another service manager
├── rnsd                      Reticulum transport and routing
└── rntun listen              application identity and TUN ownership
    ├── shared-instance connection to rnsd
    ├── gateway destination and client sessions
    └── TUN file descriptor
```

On a desktop client:

```text
rnsd
└── rntun connect <destination>
    ├── shared-instance connection to rnsd
    ├── one gateway Link
    └── TUN file descriptor
```

`rnsd` does not need `CAP_NET_ADMIN`. On Linux, only `rntun` needs permission to
open/configure the TUN device. `rns-server` may later gain an optional `rntun`
sidecar role, but supervision is independent of the tunnel protocol.

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
    ├── runtime.rs             bounded queues and Reticulum event handling
    ├── platform.rs            packet-device/configuration traits
    ├── platform/linux.rs      Linux TUN adapter
    └── bin/rntun.rs           desktop command-line application
```

The library must compile without the Linux module on Android. Android-facing
FFI/JNI glue should remain thin and must call the same portable session engine.

Two abstractions keep the core portable:

- `PacketDevice`: reads and writes complete IP packets. Linux implements it by
  opening `/dev/net/tun`; Android implements it around a file descriptor
  returned by `VpnService.Builder.establish()`.
- `TunnelConfigurator`: applies or reports the negotiated address, MTU, and
  routes. Linux can implement configuration directly or emit commands; Android
  must configure these values through `VpnService.Builder` before establishing
  the descriptor.

The session engine must also be usable independently of the command-line parser
so an Android host can embed it.

## Destination and connection lifecycle

The gateway registers and announces the `rntun.gateway` destination. Its
destination hash is the client-facing connection identifier.

Client lifecycle:

1. Connect to the configured shared Reticulum instance.
2. Load or create the client application identity.
3. Resolve or request a path to the supplied gateway destination hash.
4. Establish a Reticulum Link.
5. Identify on the Link.
6. Send `ClientHello` with protocol capabilities and requested routes.
7. Receive `ServerAccept` or `ServerReject`.
8. Configure the packet device only after acceptance.
9. Forward packets until the Link closes or the host stops the session.
10. Remove client-owned routes and close the packet device deterministically.

Gateway lifecycle:

1. Connect to the shared Reticulum instance.
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
PendingLink -> Identified -> Negotiating -> Active -> Closing
                  |              |
                  +----Reject----+
```

Control messages:

- `ClientHello`: protocol versions, capabilities, maximum IP packet size, and
  requested routes;
- `ServerAccept`: selected version, session epoch, assigned address/prefix,
  gateway address, accepted routes, packet MTU, and timer values;
- `ServerReject`: stable reason code and optional bounded diagnostic text;
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

Control messages require ordered, reliable delivery. Before finalizing the data
transport, implement a focused spike comparing:

1. existing Channel messages, which are immediately available but can impose
   head-of-line blocking; and
2. bounded link-data datagrams, which may require a small new `rns-net`
   application API but better preserve IP packet semantics.

The spike must measure loss, latency, memory pressure, and TCP throughput over a
constrained simulated Reticulum path. Record the choice in this document before
shipping protocol version 1.

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

## Android integration

Android owns VPN consent and TUN creation. The Android host must:

1. call `VpnService.prepare()` and obtain user consent;
2. run the active VPN as a foreground service where required;
3. construct `VpnService.Builder` with the accepted address, routes, MTU, and
   optional allowed/disallowed applications;
4. call `establish()` and pass the resulting file descriptor to Rust;
5. prevent Reticulum underlay sockets from being captured by the VPN, using
   `VpnService.protect()` when the sockets are owned by the VPN process or an
   application-exclusion strategy when the Reticulum daemon is separate;
6. notify Rust and close the session when permission is revoked or the service
   is destroyed.

Because Android needs negotiated configuration before it can establish the
final TUN interface, the Android host starts the Reticulum session first,
receives `ServerAccept`, builds the interface, and then marks packet forwarding
ready. The gateway must tolerate this bounded setup interval.

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
rntun connect <destination-hash> --default-route
rntun identity [--config PATH]
```

Application identity and configuration are separate from the Reticulum daemon's
transport identity and configuration. Client route configuration is an
allowlist: server-advertised routes not permitted locally are not installed.

Logs and status must distinguish path discovery, Link authentication, policy
acceptance, tunnel readiness, and packet forwarding. Rejection logs include the
identity hash and stable reason but never private key material or raw packet
contents.

## Open design items

The overall architecture and security model are accepted as the working basis,
but the items in this section are intentionally unresolved. Each item must be
discussed and its decision recorded in this document before the stated gate.
Stable IDs allow implementation notes, tests, and later decisions to refer to an
item without relying on section line numbers.

### O-01: Linux full-tunnel underlay protection

Status: mechanism selected in part; the `rntun` routing contract and external
carrier handling remain open.

Installing a default route through the client TUN can also capture the traffic
used by the local `rnsd` interfaces, recursively carrying Reticulum's underlay
inside `rntun`. The Android design has an explicit underlay-protection contract,
but the Linux design does not yet have an equivalent.

Decide whether Linux version 1 uses policy routing and marks, explicit retained
routes to every underlay endpoint, a separate network namespace, or another
mechanism. The decision must account for underlay peers changing while the
tunnel is active. If no reliable mechanism is available, Linux full-tunnel mode
must remain unsupported rather than relying on a best-effort exception list.

Resolution gate: before Phase 3 full-tunnel implementation. Add an end-to-end
test and a Linux equivalent of the Android underlay security invariant.

Decision recorded 2026-08-25: shared-instance operation remains the default.
`rns-net` and `rnsd` support a nonzero `[reticulum] underlay_mark` that is
applied with Linux `SO_MARK` to IP underlay sockets before connect or send and
across reconnects. `rntun` will use a separate tunnel routing table and a
higher-priority mark rule that sends this traffic through the preserved physical
table. Full-tunnel startup must fail unless the configured mark is nonzero, the
node has verified that it can apply it, and the corresponding policy-routing
rule is installed.

The mark covers sockets owned by `rns-net`; it does not automatically cover
system resolver traffic, `PipeInterface` subprocesses, or external carrier
processes such as an I2P router. Before O-01 can close, decide whether version 1
rejects those configurations, requires separately declared bypass identities or
routes, or adds a broader service/cgroup mechanism. An embedded Reticulum node
may be added later but is not required for the shared-instance version 1 design.

### O-02: post-accept readiness handshake

`ServerAccept` gives the client the configuration needed to create its packet
device. Android cannot create its final TUN descriptor until that message has
arrived, so acceptance does not imply that the client can receive packets.

Decide whether version 1 adds `ClientReady` and whether an acknowledgment such
as `ServerReady` is also needed. Define the intermediate state, setup timeout,
which side may send data in it, and whether early packets are dropped or held in
a strictly bounded queue. The gateway must not consider a session fully active
for packet dispatch until the readiness rule has been satisfied.

Resolution gate: before freezing the control state machine and control message
encoding in Phase 1.

### O-03: bidirectional packet authorization

The current policy precisely checks packets entering the gateway from a client,
but packets read from the gateway TUN are selected only by destination address.
That leaves the intended authorization of return traffic and unsolicited inbound
traffic undefined.

Decide whether the gateway must require the inbound source to belong to one of
the session's accepted routes, and whether the client independently validates
both source and destination. Define necessary exceptions, including ICMP errors.
Also define the treatment of traffic addressed to the gateway tunnel address,
limited and directed broadcast, multicast, loopback, unspecified, and other
special-use IPv4 ranges.

Resolution gate: before Phase 1 packet-policy implementation. Add invariants and
tests for both tunnel directions.

### O-04: wire namespace and framing allocation

The protocol needs concrete message identifiers rather than only a conceptual
`rntun` namespace. Channel message types share a `u16` space with existing
features, and generic Link data uses a shared `u8` context space.

Reserve the exact Channel message-type range and, if link-data datagrams are
selected, the exact Link context. Define a magic value or equivalent framing,
version placement, and collision rules. Record all existing reserved ranges and
ensure unknown or misrouted application traffic cannot be decoded as `rntun`.

Resolution gate: during Phase 0, before golden wire encodings are committed.

### O-05: `LINKIDENTIFY` and `ClientHello` ordering

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

Define the route model precisely, including:

- the CIDR intersection algorithm when one prefix contains another;
- whether grants describe traffic in one direction or both directions;
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

Separate IPv4 packet validation from reassembly of `PacketFragment` messages in
terminology, modules, metrics, and limits. Decide whether native IPv4 fragments
are forwarded intact, rejected, or reassembled, and specify validation of total
length, header length, checksum, options, fragmentation fields, and the
negotiated packet MTU. Application fragmentation must never be confused with IP
fragmentation in code or operator output.

Resolution gate: before Phase 1 packet and reassembly APIs are finalized.

### O-08: protocol and capacity constants

Choose and document hard limits for at least control-message size, diagnostic
text, requested and accepted route counts, maximum IP packet length, fragments
per packet, concurrent reassemblies, reassembly bytes, pending setup duration,
idle duration, queue capacities, and global versus per-session memory. State
which values are wire constants, configurable downward limits, or configurable
capacity settings, and validate relationships between them at startup.

Resolution gate: initial values are required for the Phase 0 spike; release
values must be fixed before protocol version 1 ships.

### O-09: exact wire encoding and fragment identifiers

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

In addition to duplicate client addresses, explicitly decide and validate
whether assignments may use the gateway address, subnet network address, subnet
broadcast address, or addresses conflicting with host configuration. Clarify
what "overlapping assignments" means while version 1 assigns individual IPv4
addresses. Define the precise two-sided meaning of `allow_client_to_client`.

Resolution gate: before the Phase 1 configuration schema is considered stable.

### O-12: atomic policy-reload behavior

Define the reload trigger or triggers, parsing and validation sequence, and
behavior when a replacement policy is missing, unreadable, or invalid. The
currently active policy must remain intact on reload failure. Define which
changes are "material restrictions", how address changes are handled, and
whether newly eligible sessions are affected without reconnecting.

Resolution gate: before Phase 4 reload implementation.

### O-13: route ownership, crash recovery, and reconciliation

Recording routes in process memory supports orderly teardown but cannot clean up
after `SIGKILL`, a crash, or power loss. Decide how routes and related network
objects are tagged or otherwise identified, how startup detects stale state, and
when it is safe to reconcile it. Cleanup must never remove a route that another
administrator or process now owns.

Resolution gate: before Phase 3 Linux acceptance tests are finalized.

### O-14: Linux privilege and configuration mechanism

Choose the Linux configuration API, preferably without constructing shell
commands from configuration. Define required device permissions and capabilities,
support for an inherited descriptor, which party configures an inherited device,
and whether or when privileges are dropped after setup. Document expected
behavior under systemd and unprivileged service accounts.

Resolution gate: before Phase 3 Linux adapter implementation.

### O-15: portable crate features and Android dependency boundary

Define Cargo features and target gates so the portable session library does not
pull Linux CLI, TUN, signal, service-manager, or unnecessary Reticulum interface
dependencies into Android builds. Decide whether JNI/C-ABI glue belongs in
`rns-tun` or a small companion crate. Verify both the default and minimal feature
sets in CI.

Resolution gate: choose the initial feature layout in Phase 0 and keep the
Android cross-check green in every later phase.

### O-16: Reticulum send admission and transport feedback

The Phase 0 spike must cover not only Channel versus link-data performance, but
also how the session engine learns whether a packet was admitted, dropped before
transmission, delivered, or timed out. The current generic Link send API can
accept work into the driver queue without reporting eventual delivery. Decide
what feedback and bounded admission API `rntun` requires and whether this needs a
small `rns-net` extension.

Resolution gate: part of the Phase 0 transport decision.

### O-17: configuration, identity, and operational contract

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
validation, and send-admission failure. Each resolved item should link to its
corresponding tests or update the test matrix below.

Resolution gate: tests land with the phase that implements the affected item;
all are required or explicitly waived with rationale before Phase 6 exits.

## Implementation phases

### Phase 0: protocol and transport spike

- Add this design document and threat/limit constants.
- Prototype control messages and bounded packet fragmentation.
- Compare Channel and link-datagram data transport under constrained paths.
- Decide and document the version 1 data transport.
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

- Connect through `RnsNode::connect_shared_from_config()`.
- Implement gateway destination registration and announces.
- Implement path request, Link creation, `LINKIDENTIFY`, handshake, and close.
- Keep callbacks non-blocking through bounded queues.
- Implement one client and one gateway using in-memory packet devices.

Exit criteria: two local shared-instance clients establish an authorized tunnel
and exchange synthetic IP packets; unidentified and unconfigured identities are
rejected.

### Phase 3: Linux TUN client

- Implement Linux `PacketDevice` and route configuration.
- Add `rntun connect`, identity handling, cleanup, reconnect, and status.
- Test split routes before full-tunnel routing.

Exit criteria: a Linux client reaches a synthetic remote subnet through the
gateway and restores its routing state on clean exit and forced Link loss.

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

Exit criteria: Android cross-compilation is in CI and an instrumented device or
emulator test exchanges packets through a `VpnService` descriptor.

### Phase 6: hardening and release readiness

- Fuzz or property-test codecs, IP validation, and reassembly.
- Exercise slow links, loss, duplication, reordering, reconnects, and queue
  saturation.
- Add Linux network-namespace end-to-end tests for routing and optional NAT.
- Document security assumptions, capacity limits, troubleshooting, and recovery.
- Decide whether optional `rns-server` sidecar supervision belongs in this or a
  later release.

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
- Android underlay traffic cannot recursively enter the VPN interface.

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
- integration: shared-instance client/gateway exchange with fake devices;
- Linux: TUN and network-namespace routing, cleanup, client isolation, and NAT;
- Android: cross-compile on every change and instrument the descriptor lifecycle
  when an Android test environment is available.

## Decisions intentionally deferred

- Channel versus a new link-datagram application API for packet data, pending
  the Phase 0 measurements.
- Dynamic address allocation and durable leases.
- IPv6 payload support.
- DNS configuration and leak prevention for full-tunnel profiles.
- Gateway discovery aliases beyond an explicit destination hash.
- Bundling `rntun` as an optional `rns-server` supervised sidecar.
