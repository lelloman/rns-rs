# Manual Backbone Smoke Test

This manual smoke test checks the VPS experiment end to end through the live
backbone fabric. It is intentionally not part of the normal automated test suite:
it reaches public backbone nodes, depends on current network conditions, and can
take a minute or two while announces and path requests propagate.

Use it after deploying routing/path changes, changing VPS Reticulum config, or
when debugging reports that a destination is visible from one entry point but not
reachable from another.

## What It Tests

`scripts/manual-backbone-smoke.sh` starts two disposable local `rns-server`
instances with fresh identities and isolated config directories:

- `node-a` connects only to backbone endpoint A, by default `vps-eu`.
- `node-b` connects only to backbone endpoint B, by default `vps-us`.

The script then verifies:

1. both local servers and their supervised child processes start;
2. `node-a` and `node-b` each create and announce a fresh destination;
3. each node can recall the other node's identity through the live backbone;
4. packets can be delivered in both directions;
5. a link can be established through the fabric;
6. channel messages can cross the link in both directions;
7. a second link can be established in the reverse direction.

This catches failures that local synthetic topologies do not cover, including
bad deployed VPS config, broken public backbone connectivity, path request
forwarding regressions, announce propagation issues and link setup problems over
independent entry points.

## Prerequisites

Required local commands:

```bash
curl
jq
python3
base64
```

Build a current `rns-server` first:

```bash
cargo build --release --bin rns-server --features rns-hooks-native
```

The script uses `target/release/rns-server` by default. If that binary is not
present, it falls back to `rns-server` from `PATH`.

## Default Run

From the repository root:

```bash
scripts/manual-backbone-smoke.sh
```

Default backbone endpoints:

| Local node | Backbone label | Host | Port |
| --- | --- | --- | --- |
| `node-a` | `vps-eu` | `82.165.77.75` | `4242` |
| `node-b` | `vps-us` | `74.208.55.138` | `4242` |

A successful run ends with:

```text
==> Smoke test passed
node-a -> vps-eu, node-b -> vps-us: announce, identity recall, packets, links and channel messages all worked.
```

## Useful Options

Use a specific binary:

```bash
scripts/manual-backbone-smoke.sh --bin /usr/local/bin/rns-server
```

Keep the temporary config and logs for debugging:

```bash
scripts/manual-backbone-smoke.sh --keep
```

Set fixed local HTTP ports:

```bash
scripts/manual-backbone-smoke.sh --http-a 18180 --http-b 18181
```

Override either backbone endpoint:

```bash
scripts/manual-backbone-smoke.sh \
  --a-name vps-eu --a-host 82.165.77.75 --a-port 4242 \
  --b-name some-peer --b-host rns.example.net --b-port 4242
```

Increase the per-step timeout when the public network is slow:

```bash
scripts/manual-backbone-smoke.sh --timeout 240
```

The same settings can be provided with environment variables:

```bash
RNS_SMOKE_A_HOST=82.165.77.75 \
RNS_SMOKE_B_HOST=74.208.55.138 \
RNS_SMOKE_TIMEOUT=180 \
scripts/manual-backbone-smoke.sh
```

## Failure Handling

On failure the script prints the failing assertion, tails both local
`rns-server` logs and preserves the temporary state automatically. Use `--keep`
to preserve the same state after successful runs too. The preserved directory
includes:

- generated Reticulum configs;
- `rns-server.json` files;
- durable supervised process logs;
- the wrapper stdout/stderr log for each local server.

The script always stops both local `rns-server` processes on exit unless the
shell is force-killed.

## Interpreting Results

If startup fails, check the selected binary and local port availability.

If identity recall fails, the likely fault is announce propagation or path
request forwarding between the two backbone entry points.

If identity recall works but packets fail, focus on path table selection and
packet forwarding.

If packets work but links fail, focus on link request routing, retained path
state and link packet forwarding.

If the first link works but the reverse link fails, check asymmetric paths,
blacklists or stale per-interface state on one backbone node.
