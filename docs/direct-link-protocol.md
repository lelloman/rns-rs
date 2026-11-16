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

Once established, the direct UDP channel is wrapped as a standard Reticulum
`DirectUdpInterface`. All existing Reticulum functionality (links, LXMF, LXST)
works over it transparently. The original path through transport nodes remains
as a fallback.

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
| `0x01` | `UPGRADE_REQUEST` | `{"s": session id, "f": facilitator, "a": initiator public, "p": probe protocol (omitted for RNSP)}` |
| `0x02` | `UPGRADE_ACCEPT` | `{"s": session id}` |
| `0x03` | `UPGRADE_REJECT` | `{"s": session id, "r": reason}` |
| `0x04` | `UPGRADE_READY` | `{"s": session id, "a": responder public}` |
| `0x05` | `FALLBACK` | `{"s": session id of the direct path, "r": reply wanted}` (see [Fallback](#fallback)) |

Endpoints are `[address bytes (4 or 16), port]`. The version is `1`. A
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
   or its policy may accept requests) answers a `HELLO` with `r = true` with
   its own `HELLO` (`r = false`). A node that takes part in neither ignores
   all Direct Link packets, exactly as upstream does.
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

B evaluates the request and responds with either:

- **`UPGRADE_ACCEPT`** — B is willing to attempt a direct link.
- **`UPGRADE_REJECT`** — B declines. Protocol ends. The existing Reticulum link
  continues unchanged.

B rejects because of its policy or because the request is out of range
(reason `0x01`), or because it is busy (reason `0x02`). A peer that does not
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
- **Pacing.** At most one upgrade request per link is taken up per 60 seconds,
  at most 4 responder sessions run node-wide at once, and only one session at a
  time punches toward a given address. Requests over these limits receive
  `UPGRADE_REJECT` with reason `0x02` (busy).

### Phase 3: STUN Discovery + Address Exchange (B ↔ T, B → A)

B sends a UDP probe to T (using the facilitator address from the upgrade
request). T responds with B's public address (`B_pub`).

B then sends an `UPGRADE_READY` message to A over the existing Reticulum link:

| Field | Description |
|-------|-------------|
| `responder_public` | B's public address as reported by T |

After this phase, both A and B know each other's public addresses. T's role is
complete — it is not involved in any further communication.

### Phase 4: Hole Punch (A ↔ B, direct UDP)

Both peers simultaneously send UDP packets to each other's public addresses.
When a packet arrives at a NAT that has already seen an outgoing packet to the
same remote address, the NAT allows it through (the "pinhole").

The hole punch procedure:
1. Both sides begin sending UDP packets immediately after Phase 3 completes.
   The punch packets carry the session id and a punch token derived from the
   link key, `HKDF(ikm=derived_key, salt=session_id, info="rns-holepunch-v1")`.
2. Packets are sent at a regular interval (e.g. every 100ms) for a bounded
   duration (e.g. 10 seconds). rns-rs also caps a session at 128 punch packets
   and 128 acknowledgements.
3. The first received packet from the peer confirms the hole punch succeeded.
   rns-rs only accepts punch and acknowledgement packets whose source IP
   matches the peer endpoint being punched (the port may differ).
4. If no packet is received within the timeout, the hole punch has failed.

On failure, the protocol ends gracefully. The existing Reticulum link continues
unchanged.

Each side creates its `DirectUdpInterface` as soon as its punch succeeds and
routes the link over it. There is no separate confirmation message.

## DirectUdpInterface

The punched UDP socket is wrapped as a Reticulum interface, named
`DirectPeer/<first four bytes of the session id>`. It belongs to the one link
that was upgraded and carries nothing else:

| Property | Details |
|----------|---------|
| **Link traffic only** | Its reader and writer pass only HEADER_1 link DATA and PROOF packets addressed to the link's id; any other datagram from the peer, and any other frame the node would send, is dropped. Datagrams from any address but the peer's are ignored |
| **Not an outbound interface** | It is registered with `out_capable = false`, and broadcasts skip it, so the transport engine never sends announces, path requests or broadcasts on it. Since nothing but the link's packets is accepted from it, no path, announce or link request is learned through it and no other traffic is forwarded over it |
| **Packet send/receive** | One Reticulum packet per UDP datagram, no framing |
| **Keepalive** | Sends an authenticated keepalive every 5 seconds, which also keeps the NAT mapping open: `"RNSK"`, the session id, a 64-bit counter and the first 16 bytes of HMAC-SHA256 over those 28 bytes, keyed with `HKDF(ikm=derived_key, salt=session_id, info="rns-holepunch-keepalive-v1")`. The key never appears on the wire (unlike the punch token) |
| **Liveness detection** | Only a valid keepalive from the peer with a counter above the last one accepted counts as a sign of life; link packets and anything forged or replayed do not. Without one for 15 seconds (three missed) the interface declares itself down |
| **Teardown** | It is removed when its link closes (about a second later, so the link's closing packets still leave on it), when it goes down, and when a newer upgrade of the same link replaces it |

### Routing the link

When its punch succeeds, each side registers the interface and routes the
link over it: the link's outbound packets go out on the direct interface,
with no transport header. Nothing is added to the path table; other
destinations, including the peer's own, keep their paths.

The link remembers the route it had (interface and next-hop transport id) and
its MTU. Its MTU is lowered to the direct interface's 1400 bytes if it was
larger, never raised, so nothing sized for the direct path is too large for
the original one. Its RTT, and with it the keepalive interval and stale time,
stay as measured on the original path.

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

### Fallback

The link returns to its original route, and its MTU to what it was, when any
of these shows the direct path failed:

- the direct interface goes down (15 seconds without a valid keepalive, or a
  socket error);
- the link goes stale (no inbound traffic for its stale time) while on the
  direct path, which on a fast link happens before the keepalive timeout;
- the link's channel runs out of retries on the direct path: instead of
  tearing the link down, as it would on any other path, the channel resends
  every outstanding message, with its tries reset, over the original route
  (once per upgrade);
- the peer says it fell back (`FALLBACK` for the path's session).

The side that falls back removes its direct interface, reports the loss to
the application (`on_direct_connect_lost`; `direct_lost` in rns-ctl's link
events) and, unless the peer told it, sends `FALLBACK` with `r = true` over
the original route. Direct Link signalling is sent on a stale link too,
which other link packets are not. The peer falls back too and answers with `FALLBACK`
(`r = false`); that answer is also inbound traffic that revives a link that
went stale. The link itself is never closed by a direct-path failure, and
the application keeps using it unchanged. A new upgrade can be proposed
afterwards (subject to the usual pacing).

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

Properties of the facilitator:
- **Stateless** — each request/response is independent. The facilitator does
  not track relationships between peers.
- **Lightweight** — the facilitator is not a relay. It handles only the initial
  address discovery; no ongoing traffic passes through it.
- **Not necessarily a Reticulum node** — the facilitator only needs to be a
  publicly reachable UDP endpoint. It can be a standalone service, a feature of
  a transport node, or any internet-reachable host.
- **Discoverable** — facilitators can advertise their STUN capability through
  Reticulum announces, allowing peers to find them dynamically.

## Failure Modes

| Failure | Phase | Recovery |
|---------|-------|----------|
| T unreachable or does not support STUN | 1 | A tries another facilitator or aborts |
| B does not implement Direct Link | 0 | B never answers `HELLO`; A fails with reason `0x03` and sends nothing else |
| B rejects the upgrade | 2 | Keep existing Reticulum link |
| B cannot reach T | 3 | B sends `UPGRADE_REJECT`, keep existing link |
| Symmetric NAT on either side | 4 | Hole punch fails (timeout), keep existing link |
| Hole punch timeout | 4 | Keep existing link. Optionally retry with a different facilitator |
| Direct path drops after establishment | after 4 | Detected by the keepalives, the link going stale, or exhausted channel retries; both sides fall back to the original route and the link stays open |
| NAT remapping (IP change, roaming) | after 4 | As above. Peers may propose again |

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
- **Link migration**: If a direct link drops and is re-established (e.g. after
  NAT remapping), existing Reticulum links could migrate to the new interface
  rather than being torn down and re-created.
