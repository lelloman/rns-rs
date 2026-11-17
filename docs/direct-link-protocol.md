# DirectLink Protocol

## Motivation

Reticulum nodes on the internet communicate through transport nodes that relay
traffic between peers. This works well but has two drawbacks:

1. **Latency**: every packet takes an extra hop through the transport node,
   adding round-trip delay. This matters for real-time applications like voice
   calls (LXST).
2. **Congestion**: heavy data exchanges (resource transfers, sustained voice
   calls) consume bandwidth on the transport node, which is a shared resource.

The DirectLink protocol allows two peers that already have an established
Reticulum link to **upgrade** their connection to a direct peer-to-peer UDP
channel, bypassing transport nodes entirely.

## Overview

The protocol has four stages:

1. **Capability check** — the initiator asks its link peer whether it
   implements Direct Link, in a way upstream Reticulum ignores.
2. **STUN Discovery** — the initiator learns its own public address via a
   facilitator node.
3. **Negotiation** — the peers agree to upgrade, exchanging addressing
   information over their existing Reticulum link.
4. **Hole Punch** — both peers send UDP packets to each other's public
   addresses simultaneously, punching through NATs to establish a direct
   channel.

Once established, the direct UDP channel is wrapped as a Reticulum interface
(`DirectUdpInterface`) that belongs to the upgraded link. The link's traffic,
whatever the application runs over it (LXMF, LXST, resources, channels), moves
to it transparently; nothing else does. The original path through transport
nodes remains as a fallback.

## Terminology

| Term | Definition |
|------|------------|
| **Initiator (A)** | The peer that proposes the direct link upgrade |
| **Responder (B)** | The peer that accepts or rejects the upgrade |
| **Facilitator (T)** | A publicly reachable node that provides STUN services — reflects a peer's public IP:port back to them |
| **Public address** | The IP:port as seen from the internet (the NAT's external mapping) |
| **Hole punch** | Simultaneous UDP packets from both peers that create NAT pinholes, enabling direct communication |

## Prerequisites

- A and B have an **established Reticulum link** (they can exchange messages).
- B has answered A's capability query (see [Signalling](#signalling)).
- A has a connection (e.g. TCP) to a facilitator node T.
- T is **publicly reachable** on a UDP port and supports the STUN facilitation
  protocol.

## Signalling

All Direct Link messages travel over the existing link as Reticulum link DATA
packets with packet context `0x80` (`CONTEXT_DIRECT_LINK`), encrypted with the
link key like any other link packet. They do not use the link's channel, so
the application's channel sequence and window are never touched. They are
never proven.

The decrypted payload is

```
[version: u8] [kind: u8] [body: msgpack map]
```

| Kind | Name | Body |
|------|------|------|
| `0x00` | `HELLO` | `{"v": highest version spoken, "r": reply wanted}` |
| `0x01` | `UPGRADE_REQUEST` | `{"s": session id, "f": facilitator, "a": initiator public, "p": probe protocol (omitted for RNSP), "m": largest link packet accepted on the direct path, "h": initiator host candidates (omitted when none)}` |
| `0x02` | `UPGRADE_ACCEPT` | `{"s": session id}` |
| `0x03` | `UPGRADE_REJECT` | `{"s": session id, "r": reason}` |
| `0x04` | `UPGRADE_READY` | `{"s": session id, "a": responder public, "m": largest link packet accepted on the direct path, "h": responder host candidates (omitted when none)}` |
| `0x05` | `FALLBACK` | `{"s": session id of the direct path, "r": reply wanted}` (see [Fallback](#fallback)) |

Endpoints are `[address bytes (4 or 16), port]`, and `"h"` is a list of at
most 2 of them (see [Host candidates](#host-candidates)); a receiver keeps
the first 2 well-formed entries and ignores the rest. The version is `1`. A
message framed in any other version is dropped; a later version must keep
sending `HELLO` in version 1 framing and advertise its highest version in
`v`, and fields a receiver does not know are ignored.

### Capability check

Upstream Reticulum drops a link packet whose context it does not know: it
neither replies nor proves it, and nothing reaches the application. A node
therefore asks before it signals anything:

1. A wants to propose. Unless B is already known to implement Direct Link, A
   sends `HELLO` with `r = true`, repeats it every 2.5 seconds, and waits up
   to 8 seconds.
2. A node that takes part in Direct Link (it has a facilitator configured,
   a policy other than `reject`, or an allowlist of identities) answers a
   `HELLO` with `r = true` with its own `HELLO` (`r = false`). A node that
   takes part in none of these ignores all Direct Link packets, exactly as
   upstream does.
3. When B's `HELLO` arrives, A proceeds with Phase 1. If none arrives, A treats
   B as not supporting Direct Link and reports the attempt failed with reason
   `0x03` (unsupported); B has received nothing but the ignored queries.

A node that receives any upgrade message from a peer also notes that the peer
implements Direct Link. The knowledge lasts for the life of the link.

### Retransmission

Signalling is not acknowledged. While it waits for `UPGRADE_ACCEPT` and
`UPGRADE_READY`, the initiator repeats its `UPGRADE_REQUEST` every 2 seconds.
A responder that receives a request for the session it is already running
answers with the replies it has already sent (`UPGRADE_ACCEPT`, and
`UPGRADE_READY` once it knows its endpoint) instead of treating it as a new
request; the policy and pacing checks are not applied again.

### Simultaneous proposals

If both peers propose on the same link at once, their requests cross. The
proposal of the side that initiated the Reticulum link goes ahead: that side
leaves the peer's request unanswered, and the other side, on receiving a
request while it is proposing itself (asking `HELLO` or running its own
session), drops its proposal without reporting a failure and answers the
request as the responder. Both sides end up with the same direct path.

## Protocol Flow

```
    A (initiator)               T (facilitator)              B (responder)
    │                           │                            │
    │                           │                            │
    ├── Phase 1 ────────────────┤                            │
    │   UDP probe ─────────────→│                            │
    │←── STUN response ─────────┤                            │
    │   (your addr: A_pub)      │                            │
    │                           │                            │
    ├── Phase 2 ─────────────────────────────────────────────┤
    │   UPGRADE_REQUEST ────────────────────────────────────→│
    │   { facilitator: T_pub, initiator_public: A_pub }      │
    │                                                        │
    │←─────────────────────────────────── UPGRADE_ACCEPT ────┤
    │                            or                          │
    │←─────────────────────────────────── UPGRADE_REJECT ────┤
    │                           │                            │
    │                           ├── Phase 3 ─────────────────┤
    │                           │←── UDP probe ──────────────┤
    │                           │─── STUN response ─────────→│
    │                           │   (your addr: B_pub)       │
    │                           │                            │
    ├── Phase 3 (continued) ─────────────────────────────────┤
    │←────────────────────────────────── UPGRADE_READY ──────┤
    │                                   { responder_public:  │
    │                                     B_pub }            │
    │                           │                            │
    ├── Phase 4 ─────────────────────────────────────────────┤
    │   UDP packet ─────────────────────────────────────────→│
    │←──────────────────────────────────────── UDP packet ───┤
    │                  (simultaneous hole punch)              │
    │                                                        │
    │                  ┌─────────────────┐                   │
    │                  │ Direct UDP link │                   │
    │←────────────────→│   established   │←─────────────────→│
    │                  └─────────────────┘                   │
```

Before Phase 1, A has checked that B implements Direct Link (`HELLO`, see
[Capability check](#capability-check)).

### Phase 1: STUN Discovery (A ↔ T)

A sends a UDP probe to T's public STUN port. T responds with A's public
address (IP:port) as seen from the internet.

After this phase, A knows its own public address (`A_pub`).

### Phase 2: Upgrade Negotiation (A → B, via Reticulum link)

A sends an `UPGRADE_REQUEST` to B over their existing Reticulum link containing:

| Field | Description |
|-------|-------------|
| `facilitator` | T's public IP:port (STUN endpoint) |
| `initiator_public` | A's public address as reported by T |
| `m` | The largest link packet A accepts on the direct path (see [Packet size](#packet-size)) |

B evaluates the request and responds with either:

- **`UPGRADE_ACCEPT`** — B is willing to attempt a direct link.
- **`UPGRADE_REJECT`** — B declines. Protocol ends. The existing Reticulum link
  continues unchanged.

B rejects because of its policy or because the request is out of range
(reason `0x01`), or because it is busy (reason `0x02`); after accepting, it
may still give up with reason `0x04` (Phase 3). A peer that does not
implement Direct Link never sees a request: the capability check failed
first, with reason `0x03`.

The responder decides only after fully decoding the request. A peer that has
identified on the link (`LINKIDENTIFY`) with an identity listed in
`direct_connect_allowed_identities` is accepted. Otherwise
`direct_connect_policy` decides: `reject` (the default) declines all requests,
`accept_all` accepts every well-formed request, `identified_only` accepts when
the link has completed `LINKIDENTIFY` with any identity, and `ask_app` invokes
the application callback once with the peer identity when known (or no
identity otherwise) and honors its boolean decision; the default callback
rejects. These controls are responder-side only and do not change initiation
behavior.

After the policy accepts a request, the responder also checks it before sending
anything:

- **Endpoint ranges.** `facilitator` and `initiator_public` must be globally
  routable unicast addresses with a non-zero port. Unspecified, loopback,
  multicast, broadcast, reserved, documentation and benchmarking addresses are
  always declined. Private (10/8, 172.16/12, 192.168/16), shared (100.64/10),
  link-local (169.254/16, fe80::/10) and IPv6 unique-local (fc00::/7) addresses
  are declined unless `direct_connect_allow_private_endpoints = yes` is set in
  `[reticulum]`. IPv4-mapped IPv6 addresses are checked as their IPv4 form.
  The initiator applies the same check to `responder_public` in
  `UPGRADE_READY` before punching. Out-of-range requests receive
  `UPGRADE_REJECT` with reason `0x01`.
- **Not a facilitator.** `initiator_public` must not be the facilitator
  named in the request or one of the responder's own probe servers
  (reason `0x01`).
- **Pacing.** At most one upgrade request per link is taken up per 60 seconds,
  at most 4 responder sessions run node-wide at once, and only one session at a
  time punches toward a given address. Requests over these limits receive
  `UPGRADE_REJECT` with reason `0x02` (busy).

### Phase 3: STUN Discovery + Address Exchange (B ↔ T, B → A)

B sends a UDP probe to T (using the facilitator address from the upgrade
request). T responds with B's public address (`B_pub`). If the probe fails
(3 seconds without an answer), or discovery takes over 10 seconds, B sends
`UPGRADE_REJECT` with reason `0x04` instead of leaving A waiting.

B then sends an `UPGRADE_READY` message to A over the existing Reticulum link:

| Field | Description |
|-------|-------------|
| `responder_public` | B's public address as reported by T |
| `m` | The largest link packet B accepts on the direct path |

After this phase, both A and B know each other's public addresses. T's role is
complete — it is not involved in any further communication.

### Phase 4: Hole Punch (A ↔ B, direct UDP)

Both peers simultaneously send UDP packets to each other's public addresses.
When a packet arrives at a NAT that has already seen an outgoing packet to the
same remote address, the NAT allows it through (the "pinhole").

The hole punch procedure:
1. Both sides begin sending UDP packets immediately after Phase 3 completes
   (see [Punch packets](#punch-packets)).
2. Packets are sent at a regular interval (e.g. every 100ms) for a bounded
   duration (e.g. 10 seconds). rns-rs also caps a session at 128 punch packets
   and 128 acknowledgements, sends to at most 4 candidate endpoints (the
   peer's public endpoint and its usable [host candidates](#host-candidates)),
   and never to an unspecified, multicast or broadcast address. Until a valid punch or acknowledgement has arrived
   from an endpoint's IP, that endpoint gets a burst of 16 packets and then
   one a second, at most 25 in the 10 seconds (see
   [Reflection](#reflection)).
3. Each side answers every valid punch with an acknowledgement. The punch
   has succeeded once a side has both received a valid punch and received an
   acknowledgement of one of its own punches. rns-rs only accepts punch and
   acknowledgement packets whose source IP matches the peer endpoint being
   punched (the port may differ, for a NAT that does not preserve it), and
   an acknowledgement only if it echoes the nonce of a punch it sent to that
   IP.
4. If no packet is received within the timeout, the hole punch has failed.

### Punch packets

Punch packets and their acknowledgements are raw UDP datagrams of 52 bytes:

```
[magic: 4] [session id: 16] [nonce: 16] [tag: 16]
```

| Magic | Packet | Nonce |
|-------|--------|-------|
| `"RNSH"` | Punch | 16 random bytes, fresh for every punch packet |
| `"RNSA"` | Acknowledgement | The nonce of the punch it answers |

The tag is the first 16 bytes of HMAC-SHA256 over the preceding 36 bytes,
keyed with the session's punch token,
`HKDF(ikm=derived_key, salt=session_id, info="rns-holepunch-v1")`. The
token is known only to the two link peers and never appears on the wire. A
packet with a wrong length, session id or tag is ignored.

Before it punches, each side also refuses a peer endpoint that is a
facilitator (the one its probe used, or any it has configured), its own
mapping as its probe saw it, one of its own listening ports (its probe
server) at its own public address, or of another address family than that
mapping. The punch then fails as if it had timed out (`0x10`). Another port
at the node's own public address is accepted: it is a peer behind the same
NAT.

On failure, the protocol ends gracefully. The existing Reticulum link continues
unchanged.

Each side creates its `DirectUdpInterface` as soon as its punch succeeds and
routes the link over it. There is no separate confirmation message.

### Host candidates

Two peers behind the same NAT see the same public address with different
ports, and can only reach each other's public endpoint if their NAT
forwards a packet from inside back inside ("hairpinning"), which many do
not. So each side also offers host candidates: the LAN addresses of its own
interfaces (IPv4 private, 10/8, 172.16/12 and 192.168/16, or IPv6
unique-local, fc00::/7, of the probed mapping's family, at most 2) with the
port of its punch socket. The initiator sends them in `UPGRADE_REQUEST`
(`"h"`), the responder in `UPGRADE_READY`. A node whose mapping is one of
its own addresses is not behind a NAT and offers none, and no other
address (global, shared, link-local) is ever offered.

A peer's host candidates are private addresses chosen by the peer, so a
side punches one only if all of these hold, and otherwise ignores it
(the punch goes ahead without it):

- the peer's public endpoint is at this node's own public address, as its
  probe saw it (the two are behind the same NAT);
- the candidate is a LAN address of the same family, with a non-zero port;
- it is on a network one of this node's interfaces is on (within that
  interface's prefix), and not an address of this node;
- it is not a facilitator.

Host candidates are punched after the public endpoint, under the same
per-endpoint budget (16 packets, then one a second, until one answers) and
the same cap of 4 candidates and 128 packets. A host candidate that is
acknowledged is preferred: when the punch has succeeded over the public
endpoint while a host candidate has not answered yet, the side waits up to
500 ms more for it, then uses the public endpoint. The peer's address on
the direct path is the one an acknowledgement came from.

Revealing host candidates tells the peer the node's LAN addresses; it is
sent only to a peer the node is already revealing its public endpoint to.

## DirectUdpInterface

The punched UDP socket is wrapped as a Reticulum interface, named
`DirectPeer/<first four bytes of the session id>`. It belongs to the one link
that was upgraded and carries nothing else:

| Property | Details |
|----------|---------|
| **Link traffic only** | Its reader and writer pass only HEADER_1 link DATA and PROOF packets addressed to the link's id; any other datagram from the peer, and any other frame the node would send, is dropped. Datagrams from any address but the peer's are ignored |
| **Not an outbound interface** | It is registered with `out_capable = false`, and broadcasts skip it, so the transport engine never sends announces, path requests or broadcasts on it. Since nothing but the link's packets is accepted from it, no path, announce or link request is learned through it and no other traffic is forwarded over it |
| **Packet send/receive** | One Reticulum packet per UDP datagram, no framing |
| **MTU** | 1200 bytes, raised to the largest of a short ladder of sizes the path is shown to carry (see [Path MTU](#path-mtu)) |
| **Keepalive** | Sends an authenticated keepalive every 15 seconds, which also keeps the NAT mappings open (see [Keepalives](#keepalives)) |
| **Liveness detection** | Only a valid keepalive from the peer counts as a sign of life. Without one for 45 seconds (three missed) the interface declares itself down |
| **Teardown** | It is removed when its link closes (about a second later, so the link's closing packets still leave on it), when it goes down, and when a newer upgrade of the same link replaces it |

### Keepalives

Each side sends a keepalive on the direct path every 15 seconds, the
first as soon as the interface is up. Keepalives are raw UDP datagrams of
44 bytes:

```
"RNSK" [session id: 16] [counter: u64 BE] [tag: 16]
```

The counter starts at 1 and goes up by one with every keepalive. The tag
is the first 16 bytes of HMAC-SHA256 over the preceding 28 bytes, keyed
with `HKDF(ikm=derived_key, salt=session_id,
info="rns-holepunch-keepalive-v1")`: like the punch token it comes from
the link key, is known only to the two link peers, and never appears on
the wire, but it is a different key, so a punch packet cannot pass for a
keepalive. The path MTU probes of the path use the same key under their
own magic.

A keepalive counts as a sign of life only if it comes from the peer's
address and port, has the right length, magic and session id, carries a
valid tag, and its counter is above the last one accepted. Anything else
is ignored: an off-path sender cannot forge one, and a replayed or
reordered one is stale. Link packets do not count either, so nothing but
the peer's own keepalives keeps a direct interface up. Without a valid
keepalive for 45 seconds (three missed) the interface goes down and the
link falls back (see [Fallback](#fallback)); a link with traffic usually
notices sooner, by going stale.

The interval keeps the path's NAT mappings open: NATs forget an idle UDP
mapping after as little as 30 seconds, and a keepalive every 15 seconds
refreshes it even when one is lost. Earlier builds sent one every 5
seconds and gave up after 15 seconds without one, so a direct path
between such a build and this one does not last: the earlier side
declares it down and the link falls back.

### Routing the link

When its punch succeeds, each side registers the interface and routes the
link over it: the link's outbound packets go out on the direct interface,
with no transport header. Nothing is added to the path table; other
destinations, including the peer's own, keep their paths.

The link remembers the route it had (interface and next-hop transport id) and
its MTU, and takes the direct interface's MTU while on the direct path (see
[Packet size](#packet-size)). The direct interface starts at 1200 bytes and
may move up once its path MTU is known (see [Path MTU](#path-mtu)). Its
RTT, and with it the keepalive interval and stale time, stay as measured on
the original path.

### Path MTU

A direct interface starts with an MTU of 1200 bytes of UDP payload: it fits
the IPv6 minimum link MTU of 1280 bytes less 48 bytes of IPv6 and UDP
headers, leaves room for a tunnel or PPPoE header along the way, and any
IPv4 path that carries ordinary internet traffic carries it. 1400 bytes, a
common fixed choice, does not fit an IPv6 path through a WireGuard tunnel
(1420 - 48 = 1372) or an IPv6 minimum-MTU link.

As soon as the interface is up, each side probes its own sending direction
with three sizes: 1472, 1400 and 1280 bytes toward an IPv4 peer (1472 is
the UDP payload of a 1500-byte Ethernet path), 1452, 1400 and 1280 toward
an IPv6 one. It sends one probe of each size not above the best size
acknowledged so far, three rounds one second apart, and takes the largest
size the peer acknowledged: at once when that is the largest of the
ladder, otherwise one second after the last round. That is at most 9
probes and about 3 seconds. A size never acknowledged is not used; if none
is, the interface stays at 1200. The link then uses the discovered MTU,
never above what the peer accepts (see [Packet size](#packet-size)). While probing,
the sockets send without fragmentation (on Linux, `IP_PMTUDISC_PROBE`), so
a probe larger than the local interface or the path is lost rather than
fragmented; afterwards the kernel's usual path MTU discovery applies.

Probes and acknowledgements are raw UDP datagrams, keyed like the
keepalives (`HKDF(ikm=derived_key, salt=session_id,
info="rns-holepunch-keepalive-v1")`):

```
probe:           "RNSM" [session id: 16] [nonce: 8] [size: u16 BE] [zeros] [tag: 16]
acknowledgement: "RNSN" [session id: 16] [nonce: 8] [size: u16 BE] [tag: 16]
```

The tag is the first 16 bytes of HMAC-SHA256 over everything before it. A
probe is exactly `size` bytes long, and is acknowledged only if it arrived
whole; the acknowledgement (46 bytes) echoes its nonce and size, and counts
only for a probe still outstanding with that nonce and size. A side sends
at most 32 acknowledgements over the life of the interface.

Limits: probing happens once, when the path comes up. A path whose MTU
shrinks later (a route change onto a tunnel) is not probed again; its large
packets are lost until the direct path is given up (see
[Fallback](#fallback)) and upgraded again. Each direction is probed on its
own, so the two sides of a link may end up with different MTUs; each sends
packets no larger than its own. Off Linux, probes are sent with the
platform's default fragmentation behavior.

While the link runs over the direct path, its packets are accepted on the
direct interface and on the original route (where the peer may already have
fallen back); packets on the original route keep that route current for the
fallback but do not move the link off the direct path.

On the direct path the link's responder answers every keepalive probe of the
initiator. (Elsewhere it skips the answer when it has sent something within
the keepalive interval, as upstream does; with the shortest interval that
can let an idle link go stale for a moment, which on the direct path would
read as a dead path.) A link that goes stale there is therefore one whose
direct path has stopped carrying it.

### Packet size

While the link runs over the direct path, its MTU is the direct path's,
which may be above the MTU the link was established with (500 bytes unless
the path signalled a larger one), and its MDU follows: a single link packet
and a channel message can be as large as the direct path carries, 1472
bytes of packet (an MDU of 1391 bytes, 1385 bytes of channel message) on a
plain Ethernet path. Sizes on the original path are never changed by this.

Both sides must accept the larger packets. Each side advertises in its
`UPGRADE_REQUEST` or `UPGRADE_READY` the largest link packet it accepts on
the direct path, `m`; rns-rs advertises 2048 bytes, the size its direct
interface reads, and accepts any link packet up to it there. A side sends
link packets no larger than its own path MTU and the peer's `m` (taken as
at least 500). A peer that does not advertise `m` is sent nothing larger
than the link's MTU, as before.

The link's MTU and MDU follow its current path: the direct path's while on
it, the original ones again after a fallback, and the link MDU an
application reads (`LinkInfoEntry::mdu`, `mdu` in rns-ctl's
`/api/links`) is always the current one. A channel message may be up to
that MDU less 6 bytes of envelope. A send that fits the direct path but not
the original one is refused (`PayloadTooLarge`, `MessageTooBig`) once the
link has fallen back, so an application that sends large messages reads
the MDU, or handles the refusal, instead of assuming one size.

What was sized for the direct path is never sent on the original route,
which may not carry it:

- **Channel messages.** An unacknowledged channel message too large for the
  original path is held: it stays in the channel's window, keeps its place
  in the sequence and is not resent on the original route. A late proof of
  it delivers it; a direct path that comes back (by
  [re-upgrade](#re-upgrade)) before its retries run out carries its next
  resend. Otherwise its retries run out and, as for any message a channel
  cannot deliver, the link is closed. Messages after it are resent and
  reach the peer, which delivers them in order once the held one arrives,
  so the channel never stalls for good. When the channel's retries run out
  on the direct path, the link falls back before the resends are packed,
  so they are sized for the original route.
- **Packets in flight.** A link packet packed for the direct path that has
  not left yet when the link falls back is dropped instead of being routed
  over the original path. Single packets are best effort, as on any path;
  a dropped channel message is resent (or held, as above).
- **Resources** are sized for the MTU the direct path started with (1200
  bytes), never above the link's original MTU, on both sides alike: a
  resource's part count depends on its part size, which both sides must
  compute the same way, and its parts still fit the original route after a
  fallback.

### Fallback

The link returns to its original route, and its MTU and MDU to what they
were (see [Packet size](#packet-size)), when any of these shows the direct
path failed:

- the direct interface goes down (45 seconds without a valid keepalive, or a
  socket error);
- the link goes stale (no inbound traffic for its stale time) while on the
  direct path, which on a fast link happens before the keepalive timeout;
- the link's channel runs out of retries on the direct path: instead of
  tearing the link down, as it would on any other path, the channel resends
  every outstanding message, with its tries reset, over the original route
  (once per upgrade; one too large for that route is held, see
  [Packet size](#packet-size));
- the peer says it fell back (`FALLBACK` for the path's session).

The side that falls back removes its direct interface, reports the loss to
the application (`on_direct_connect_lost`; `direct_lost` in rns-ctl's link
events) and, unless the peer told it, sends `FALLBACK` with `r = true` over
the original route. Direct Link signalling, like any link packet, is sent on
a stale link too. The peer falls back too and answers with `FALLBACK`
(`r = false`); that answer is also inbound traffic that revives a link that
went stale. The link itself is never closed by a direct-path failure, and
the application keeps using it unchanged. A new upgrade can be proposed
afterwards (subject to the usual pacing).

### Re-upgrade

The side that proposed the lost upgrade proposes again by itself (unless
`direct_connect_reupgrade = no`), with exponential backoff: the first
proposal 60 seconds after the loss (`direct_connect_reupgrade_delay`, never
less than the 60 seconds two proposals on a link must be apart), each
further one after twice the previous delay, at most 15 minutes
(`direct_connect_reupgrade_max_delay`), each delay with up to 25% added at
random so that many links that fell back together do not propose together.
A proposal that establishes a direct path ends the series; one that fails
schedules the next. It gives up after 5 proposals
(`direct_connect_reupgrade_attempts`), at once when the peer refuses by
policy (`0x01`) or does not answer `HELLO` (`0x03`), and when the link
closes or the node no longer has a facilitator. When a proposal is due on
a stale link it counts as failed; on a link that is no longer active the
series stops. A re-established path that is lost before it has lasted the
maximum delay continues the count; one that lasted longer starts it again.
The responder of the lost upgrade does not propose by itself. Each
proposal is an ordinary upgrade, reported to the application like one
(`on_direct_connect_established` or `on_direct_connect_failed`).

## Facilitator (STUN) Protocol

The facilitator provides a single service: reflecting a peer's public IP:port
back to them.

```
Client                          Facilitator
  │                                │
  │──── STUN_REQUEST ─────────────→│
  │     { transaction_id }         │
  │                                │
  │←─── STUN_RESPONSE ────────────│
  │     { transaction_id,          │
  │       public_ip,               │
  │       public_port }            │
  │                                │
```

The client side of rns-rs accepts a reply only if it comes from the exact
address and port the request was sent to and echoes the request's id: 16
random bytes for the RNSP protocol (`"RNSP"`, version 1, nonce; the reply
adds the observed address), 12 random bytes of transaction id for STUN
(RFC 5389 Binding). Any other datagram is ignored until the probe times
out after 3 seconds. A facilitator must therefore answer from the address
it is asked at (bind it to that address on a multi-homed host).

An rns-rs facilitator answers each source within a rate limit: a token
bucket per source address (an IPv4 address, or an IPv6 /64), by default
10 requests at once refilled at one a second, and at most 1000 answers a
second over all sources (`probe_source_rate`, `probe_source_burst` and
`probe_total_rate` in `[reticulum]`). A request over a limit, and any
datagram that is not a probe request, gets no answer. It tracks at most
4096 sources; when that table is full it forgets the sources whose bucket
has refilled, and refuses new sources while all are still limited. Since
a response (24 or 36 bytes) is barely larger than a request (21 bytes),
the limits keep a facilitator from being used to flood a third party with
spoofed requests.

Properties of the facilitator:
- **Stateless** — each request/response is independent. The facilitator does
  not track relationships between peers.
- **Lightweight** — the facilitator is not a relay. It handles only the initial
  address discovery; no ongoing traffic passes through it.
- **Not necessarily a Reticulum node** — the facilitator only needs to be a
  publicly reachable UDP endpoint. It can be a standalone service, a feature of
  a transport node, or any internet-reachable host.

## Failure Modes

| Failure | Phase | Recovery |
|---------|-------|----------|
| T unreachable or does not support STUN | 1 | A tries another facilitator or aborts |
| B does not implement Direct Link | 0 | B never answers `HELLO`; A fails with reason `0x03` and sends nothing else |
| B rejects the upgrade | 2 | Keep existing Reticulum link |
| B cannot reach T | 3 | B sends `UPGRADE_REJECT` (reason `0x04`), keep existing link |
| Symmetric NAT on either side | 4 | Hole punch fails (timeout), keep existing link |
| Hole punch timeout | 4 | Keep existing link. Optionally retry with a different facilitator |
| Direct path drops after establishment | after 4 | Detected by the keepalives, the link going stale, or exhausted channel retries; both sides fall back to the original route and the link stays open |
| NAT remapping (IP change, roaming) | after 4 | As above. The proposing side upgrades again by itself (see [Re-upgrade](#re-upgrade)) |

### Failure reasons

`on_direct_connect_failed` (and rns-ctl's `direct_failed` event, as
`reason_code`) reports one of these. Codes below `0x10` are reject reasons,
the ones a peer sends in `UPGRADE_REJECT` (`0x03` is reported locally when
the peer never answers `HELLO`); codes from `0x10` are local and never sent.

| Code | Name | Meaning |
|------|------|---------|
| `0x01` | `REJECT_POLICY` | The responder's policy refused, or an endpoint in the request was out of range |
| `0x02` | `REJECT_BUSY` | The responder is pacing requests on the link, has too many sessions, or is already punching toward that address |
| `0x03` | `REJECT_UNSUPPORTED` | The peer did not answer the capability query |
| `0x04` | `REJECT_NO_ENDPOINT` | The responder accepted but could not learn its endpoint from the facilitator |
| `0x10` | `FAIL_TIMEOUT` | No `UPGRADE_ACCEPT`, `UPGRADE_READY` or punch answer in time |
| `0x11` | `FAIL_PROBE` | This side could not learn its endpoint from the facilitator |
| `0x12` | `FAIL_NOT_STARTED` | The proposal could not start: no facilitator configured, the link is not active, or the link had a proposal less than 60 seconds ago |

## Security Considerations

**Public IP disclosure**: The upgrade request includes A's public address, and
accepting the upgrade reveals B's public address to A. Requests are rejected
unless the responder is configured to accept them (see Phase 2), and a node
with no Direct Link configuration does not even reveal that it implements the
protocol.

**Facilitator trust**: The facilitator sees the public IP of every peer that
probes it but does not know which peers are trying to connect to each other
(since the signaling happens over Reticulum, not through T). A malicious
facilitator could return a wrong address, but this would simply cause the hole
punch to fail — it cannot redirect traffic since the Reticulum link's
end-to-end encryption and identity verification would detect any man-in-the-middle.

<a id="reflection"></a>
**Reflection**: The facilitator and the two public endpoints are named by
the peers themselves, and nothing can authenticate them: the facilitator
is stateless and unauthenticated, and it cannot vouch for the address it
saw for the other side. A peer could therefore try to make a node send UDP
to a third party. What such a target can receive is bounded instead:

- the endpoint checks of Phase 2 (globally routable unicast only, never
  loopback; private, shared, link-local and unique-local ranges only with
  `direct_connect_allow_private_endpoints`, meant for LAN deployments where
  every host is reachable anyway; never a facilitator or the node itself);
- the pacing of Phase 2 (one request per link per 60 seconds, 4 responder
  sessions node-wide, one session per target address);
- per session, one probe request (21 bytes, or 20 for STUN) to the named
  facilitator, and at most 25 punch packets of 52 bytes (about 1.3 KB) to a
  target that never answers with a packet tagged with the session's punch
  token. Only a target that does answer, which is then the peer,
  gets the full rate of the punch;
- a peer's host candidates, the only private addresses punched without
  `direct_connect_allow_private_endpoints`, are punched only for a peer
  behind the node's own NAT and only on a network the node is on, at most
  2 of them, under the same per-target budget (see
  [Host candidates](#host-candidates)).

Loopback is always refused because it would make the node send to services
on its own host; link-local addresses are only meaningful on the local
segment and are treated as private.

**Encryption**: The direct UDP channel carries standard Reticulum packets, which
are already encrypted. The `DirectUdpInterface` does not add or remove any
encryption — it is a transparent transport, same as TCP or LoRa interfaces.

**No signaling bypass**: Direct-link negotiation travels over an established,
encrypted Reticulum link, but peer `LINKIDENTIFY` is optional and any peer can
identify with a throwaway identity. A responder therefore accepts nothing by
default: it needs an allowlist (`direct_connect_allowed_identities`), an
identity-aware `ask_app` callback, or an explicit `accept_all` or
`identified_only`, each of which discloses its public endpoint to the peers it
admits. Malformed requests are discarded before policy callbacks or hole-punch
sessions are created.

## Future Considerations

- **TCP after hole-punch**: Once public addresses are known, peers could attempt
  a TCP connection in parallel for use cases that benefit from TCP's built-in
  congestion control and reliability (e.g. large resource transfers).
- **Multiple facilitators**: A could include multiple facilitator addresses in
  the upgrade request, allowing B to choose or fall back if one is unreachable.
- **Relay fallback via facilitator**: If hole-punching fails, the facilitator
  could optionally offer to relay traffic (TURN-style), though this goes against
  the lightweight/stateless design.
- **Re-probing the path MTU**: The direct path's MTU is probed once, when
  it comes up; a path whose MTU later shrinks is only recovered by falling
  back and upgrading again.
