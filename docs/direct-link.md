# Direct Link

> **rns-rs extension.** Python Reticulum has no equivalent. A node first asks
> its link peer whether it implements Direct Link, in a link packet context
> upstream drops without a reply; a peer that does not answer is never sent
> anything else, and nothing changes for it.

Reticulum peers on the internet normally talk through transport nodes. Direct
Link lets two peers with an established link upgrade it to a direct UDP path
between them, bypassing the transport node. That cuts a hop of latency and
offloads bandwidth from shared infrastructure, which matters for voice (LXST)
and large resource transfers.

The mechanism is a capability check with the link peer, a STUN-like probe to a
facilitator to learn each side's public endpoint, negotiation over the existing
link (in its own link packet context, not the link's channel, so the
application's channel is never touched), then a simultaneous hole punch from
both sides. If any step fails the original link keeps working unchanged.

## Roles

- **Facilitator**: a transport node that answers probe requests. It only
  reflects the public endpoint it saw; it never relays the direct traffic.
- **Initiator and responder**: the two link peers. Either may be behind NAT.

## Configuration

On the facilitator (transport node):

```ini
[reticulum]
  probe_port = 4343
```

On a client behind NAT that proposes upgrades, and accepts them from two
known identities:

```ini
[reticulum]
  probe_addr = <facilitator_ip>:4343
  direct_connect_allowed_identities = <identity hash>, <identity hash>
```

| Key | Values | Meaning |
|-----|--------|---------|
| `probe_port` | port | Serve STUN-like probe requests on this UDP port |
| `probe_addr` | `host:port` | Facilitator to use for endpoint discovery. Needed to propose |
| `direct_connect_policy` | `reject` (default), `accept_all`, `identified_only`, `ask_app` | How a responder treats incoming upgrade requests from peers not on the allowlist. `identified_only` accepts any peer that completed Reticulum `LINKIDENTIFY`, which anyone can do with a throwaway identity. `ask_app` asks the application callback, which rejects unless it is overridden |
| `direct_connect_allowed_identities` | comma-separated identity hashes | Peers whose upgrade requests are accepted whatever the policy, once they identify on the link with that identity |
| `direct_connect_allow_private_endpoints` | `yes`/`no` (default) | By default the facilitator and peer endpoints in an upgrade request must be globally routable unicast addresses. Enable for LAN-only deployments to also accept private, shared (100.64/10), link-local, and IPv6 unique-local addresses |

**Accepting an upgrade reveals your public IP address and port to the link
peer**, and proposing one reveals yours as well. That is why a node accepts
nothing by default: out of the box it takes no part in Direct Link at all and
does not even answer the capability query. A node takes part once it has a
`probe_addr` (it may propose), a policy other than `reject`, or an allowlist.
Prefer an allowlist of identities you trust over `accept_all` or
`identified_only`.

In `rns-net`, the same settings are the `NodeConfig` fields `probe_addrs`,
`direct_connect_policy`, `direct_connect_allowed_identities` and
`direct_connect_allow_private_endpoints`.

## Triggering an upgrade

Through the [rns-ctl](rns-ctl.md) API:

```bash
curl -H "Authorization: Bearer $TOKEN" -X POST http://localhost:8080/api/direct_connect \
     -d '{"link_id": "<hex link id>"}'
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/link_events
```

Watch `/api/link_events` for `direct_established` or `direct_failed`. Once
established, the link's traffic goes over the direct UDP interface, which
carries nothing but that link and is removed with it. If the direct path dies
(no keepalive for 15 seconds, the link going stale, or the link's channel
running out of retries), both sides move the link back to the transport path,
report `direct_lost`, and the link carries on.

## Testing

The NAT traversal Docker suite under `tests/docker/nat-punch/` builds two
NATed peers and a facilitator and asserts a successful upgrade. It runs as
part of `./tests/docker/run-all.sh`.

## Further reading

The [Direct Link Protocol](direct-link-protocol.md) document is the full
specification: terminology, the five protocol phases, the `DirectUdpInterface`
behaviour, the facilitator protocol, failure modes, and security
considerations. The hole-punch state machine itself lives in `rns-core`
(`holepunch` module) so it can be reused by embedded targets.
