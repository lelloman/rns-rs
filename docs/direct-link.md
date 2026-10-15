# Direct Link

> **rns-rs extension.** Python Reticulum has no equivalent. Peers that do not
> support Direct Link simply never receive an upgrade offer; nothing else
> changes for them.

Reticulum peers on the internet normally talk through transport nodes. Direct
Link lets two peers with an established link upgrade it to a direct UDP path
between them, bypassing the transport node. That cuts a hop of latency and
offloads bandwidth from shared infrastructure, which matters for voice (LXST)
and large resource transfers.

The mechanism is a STUN-like probe to a facilitator to learn each side's public
endpoint, negotiation over the existing link's channel, then a simultaneous
hole punch from both sides. If any step fails the original link keeps working
unchanged.

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

On a client behind NAT:

```ini
[reticulum]
  probe_addr = <facilitator_ip>:4343
  direct_connect_policy = identified_only
```

| Key | Values | Meaning |
|-----|--------|---------|
| `probe_port` | port | Serve STUN-like probe requests on this UDP port |
| `probe_addr` | `host:port` | Facilitator to use for endpoint discovery |
| `direct_connect_policy` | `identified_only` (default), `accept_all`, `reject`, `ask_app` | How a responder treats incoming upgrade requests. `identified_only` reveals the responder's public endpoint only after the peer completed Reticulum `LINKIDENTIFY`. `ask_app` fails closed unless the application callback accepts |
| `direct_connect_allow_private_endpoints` | `yes`/`no` (default) | By default the facilitator and peer endpoints in an upgrade request must be globally routable unicast addresses. Enable for LAN-only deployments to also accept private, shared (100.64/10), link-local, and IPv6 unique-local addresses |

The policy enum and the `NodeConfig::direct_connect_policy` field are public
in `rns-net` 0.7.1 and later.

## Triggering an upgrade

Through the [rns-ctl](rns-ctl.md) API:

```bash
curl -H "Authorization: Bearer $TOKEN" -X POST http://localhost:8080/api/direct_connect \
     -d '{"link_id": "<hex link id>"}'
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/link_events
```

Watch `/api/link_events` for `direct_established` or `direct_failed`. Once
established, traffic for that link prefers the direct UDP interface and falls
back to the transport path if the direct path dies.

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
