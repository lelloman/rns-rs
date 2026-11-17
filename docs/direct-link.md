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
| `probe_source_rate` | requests a second, default `1` | Requests the probe server answers per source (an IPv4 address or an IPv6 /64) once its burst is used up. `0` turns the per-source limit off |
| `probe_source_burst` | count, default `10` | Requests a source may send at once |
| `probe_total_rate` | requests a second, default `1000` | Requests the probe server answers over all sources. `0` turns the limit off |
| `probe_addr` | `host:port` | Facilitator to use for endpoint discovery. Needed to propose |
| `direct_connect_policy` | `reject` (default), `accept_all`, `identified_only`, `ask_app` | How a responder treats incoming upgrade requests from peers not on the allowlist. `identified_only` accepts any peer that completed Reticulum `LINKIDENTIFY`, which anyone can do with a throwaway identity. `ask_app` asks the application callback, which rejects unless it is overridden |
| `direct_connect_allowed_identities` | comma-separated identity hashes | Peers whose upgrade requests are accepted whatever the policy, once they identify on the link with that identity |
| `direct_connect_allow_private_endpoints` | `yes`/`no` (default) | By default the facilitator and peer endpoints in an upgrade request must be globally routable unicast addresses. Enable for LAN-only deployments to also accept private, shared (100.64/10), link-local, and IPv6 unique-local addresses |
| `direct_connect_reupgrade` | `yes` (default)/`no` | After a direct path this node proposed is lost, propose again by itself with exponential backoff while the link is active |
| `direct_connect_reupgrade_attempts` | count, default `5` | Proposals after a loss before giving up |
| `direct_connect_reupgrade_delay` | seconds, default `60` | Delay before the first proposal; doubled for each further one. Values below 60 are taken as 60, the shortest spacing of proposals on a link |
| `direct_connect_reupgrade_max_delay` | seconds, default `900` | Upper bound of the delay. Up to 25% is added to each delay at random |

**Accepting an upgrade reveals your public IP address and port to the link
peer**, and proposing one reveals yours as well. That is why a node accepts
nothing by default: out of the box it takes no part in Direct Link at all and
does not even answer the capability query. A node takes part once it has a
`probe_addr` (it may propose), a policy other than `reject`, or an allowlist.
Prefer an allowlist of identities you trust over `accept_all` or
`identified_only`.

In `rns-net`, the same settings are the `NodeConfig` fields `probe_addrs`,
`probe_rate_limit` (a `ProbeRateLimit`), `direct_connect_policy`, `direct_connect_allowed_identities`,
`direct_connect_allow_private_endpoints` and `direct_connect_reupgrade`
(a `DirectReupgradeConfig`).

## Triggering an upgrade

Through the [rns-ctl](rns-ctl.md) API:

```bash
curl -H "Authorization: Bearer $TOKEN" -X POST http://localhost:8080/api/direct_connect \
     -d '{"link_id": "<hex link id>"}'
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/link_events
```

Watch `/api/link_events` for `direct_established` or `direct_failed` (its
`reason_code` is listed under
[Failure reasons](direct-link-protocol.md#failure-reasons)). Once
established, the link's traffic goes over the direct UDP interface, which
carries nothing but that link and is removed with it. The direct path
starts with an MTU of 1200 bytes and, within about three seconds, moves to
the largest of 1472 (1452 over IPv6), 1400 and 1280 bytes that its probes
show the path carries; it is probed once, when it comes up (see
[Path MTU](direct-link-protocol.md#path-mtu) for the limits). While on the
direct path, single link packets and channel messages can be as large as
that MTU allows (a link MDU of 1391 bytes at 1472), above the 431 bytes of
a link at the base MTU, when both peers accept that, which rns-rs peers
say during the upgrade. The link MDU (`mdu` in `/api/links`, or
`LinkInfoEntry::mdu`) always reports the current value; after a fallback
it is the original one again, and larger sends are refused (see
[Packet size](direct-link-protocol.md#packet-size)). If the direct path dies
(no keepalive for 45 seconds, the link going stale, or the link's channel
running out of retries), both sides move the link back to the transport path,
report `direct_lost`, and the link carries on. The side that proposed the
upgrade then proposes again by itself, a minute later and then with
exponential backoff, a bounded number of times while the link stays active
(see [Re-upgrade](direct-link-protocol.md#re-upgrade)); turn it off with
`direct_connect_reupgrade = no`.

## Testing

The NAT traversal Docker suite under `tests/docker/nat-punch/` builds two
NATed peers and a facilitator and asserts a successful upgrade. It runs as
part of `./tests/docker/run-all.sh`.

## Further reading

The [Direct Link Protocol](direct-link-protocol.md) document is the full
specification: the signalling format and capability check, the protocol
phases, the `DirectUdpInterface` and its fallback, the facilitator protocol,
failure modes and reasons, and security considerations. The hole-punch state machine itself lives in `rns-core`
(`holepunch` module) so it can be reused by embedded targets.
