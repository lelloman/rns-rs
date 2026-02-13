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

The protocol has three stages:

1. **STUN Discovery** — the initiator learns its own public address via a
   facilitator node.
2. **Negotiation** — the peers agree to upgrade, exchanging addressing
   information over their existing Reticulum link.
3. **Hole Punch** — both peers send UDP packets to each other's public
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
- A has a connection (e.g. TCP) to a facilitator node T.
- T is **publicly reachable** on a UDP port and supports the STUN facilitation
  protocol.

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
    │                                                        │
    ├── Phase 5 ─────────────────────────────────────────────┤
    │   UPGRADE_COMPLETE ───────────────────────────────────→│
    │←──────────────────────────────── UPGRADE_COMPLETE ─────┤
    │                  (via direct UDP)                       │
    │                                                        │
```

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

Reasons B might reject:
- B does not support the DirectLink protocol.
- B is behind a network that blocks outbound UDP.
- B does not wish to reveal its public IP address.
- Policy or configuration.

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
2. Packets are sent at a regular interval (e.g. every 100ms) for a bounded
   duration (e.g. 10 seconds).
3. The first received packet from the peer confirms the hole punch succeeded.
4. If no packet is received within the timeout, the hole punch has failed.

On failure, the protocol ends gracefully. The existing Reticulum link continues
unchanged.

### Phase 5: Confirmation (A ↔ B, via direct UDP)

Both peers exchange `UPGRADE_COMPLETE` messages over the newly established
direct UDP channel. This confirms:
- Both directions of the direct link are functional.
- Both peers agree to activate the `DirectUdpInterface`.

After confirmation, a `DirectUdpInterface` is created on both sides, and
Reticulum begins routing traffic over the direct path.

## DirectUdpInterface

The direct UDP channel is wrapped as a standard Reticulum interface
(`DirectUdpInterface`). From the perspective of the Reticulum transport engine,
it is no different from a `TcpClientInterface` or any other interface.

The `DirectUdpInterface` is responsible for:

| Responsibility | Details |
|----------------|---------|
| **Packet send/receive** | Serialize Reticulum packets into UDP datagrams and vice versa |
| **NAT keepalive** | Send periodic keepalive packets (e.g. every 30 seconds) to prevent NAT pinhole expiry. Typical NAT mapping lifetimes are 30–120 seconds |
| **Liveness detection** | If no packet (including keepalives) is received within a timeout (e.g. 2 minutes), declare the interface down |
| **Congestion control** (optional) | Since there is no TCP underneath, the interface may implement simple congestion control (e.g. windowed ACKs, send-rate limiting) if needed for bulk transfers |
| **Teardown** | Clean removal of the interface when the direct link is no longer needed or has failed |

### Path Preference

When the `DirectUdpInterface` comes up, Reticulum learns a new 1-hop path to
the peer through it. Since the existing path through transport nodes is 2+ hops,
Reticulum naturally prefers the direct path. No special routing logic is needed.

### Fallback

If the `DirectUdpInterface` goes down (NAT remapping, network change, etc.),
the path through it becomes unresponsive. Reticulum automatically falls back to
the next known path — the original route through transport nodes. The
application layer (LXMF, LXST) is unaware of the change.

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
| B rejects the upgrade | 2 | Keep existing Reticulum link |
| B cannot reach T | 3 | B sends `UPGRADE_REJECT`, keep existing link |
| Symmetric NAT on either side | 4 | Hole punch fails (timeout), keep existing link |
| Hole punch timeout | 4 | Keep existing link. Optionally retry with a different facilitator |
| Direct link drops after establishment | 5+ | `DirectUdpInterface` goes down, Reticulum falls back to original path |
| NAT remapping (IP change, roaming) | 5+ | Keepalive fails, interface goes down, fallback to original path. Peers may re-initiate the protocol |

## Security Considerations

**Public IP disclosure**: The upgrade request includes A's public address, and
accepting the upgrade reveals B's public address to A. Peers that wish to remain
IP-anonymous should reject upgrade requests. This should be a configurable
policy.

**Facilitator trust**: The facilitator sees the public IP of every peer that
probes it but does not know which peers are trying to connect to each other
(since the signaling happens over Reticulum, not through T). A malicious
facilitator could return a wrong address, but this would simply cause the hole
punch to fail — it cannot redirect traffic since the Reticulum link's
end-to-end encryption and identity verification would detect any man-in-the-middle.

**Encryption**: The direct UDP channel carries standard Reticulum packets, which
are already encrypted. The `DirectUdpInterface` does not add or remove any
encryption — it is a transparent transport, same as TCP or LoRa interfaces.

**No authentication bypass**: The direct link upgrade negotiation happens over
an already-authenticated Reticulum link. An attacker cannot inject upgrade
requests without first establishing a valid Reticulum link with the target.

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
