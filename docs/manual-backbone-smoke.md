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

The disposable nodes run with transport enabled because `rns-server` serves the HTTP API from a shared local client; transport mode allows the local-client announce and request traffic to be forwarded onto the backbone interface.

The script then verifies:

1. both local servers and their supervised child processes start;
2. `node-a` and `node-b` each create and announce a fresh destination;
3. each node can recall the other node's identity through the live backbone;
4. packets can be delivered in both directions;
5. a link can be established through the fabric;
6. channel messages can cross the link in both directions;
7. a second link can be established in the reverse direction.

Optional extended coverage also verifies:

8. Resource transfers at caller-selected size boundaries in both directions,
   including byte-for-byte SHA-256 validation and completion timing;
9. repeated link establishment in both directions to expose intermittent proof
   routing, stale link-table entries and timing-sensitive failures.
10. concurrent link establishment and concurrent bidirectional Resources on the
    same link;
11. reproducible additional delay, jitter and bandwidth pressure on both
    local-to-VPS connections through disposable user-space proxies.
12. forced Backbone TCP disconnections followed by assertions that both
    interfaces reconnect and fresh links, Channels and Resources still work.

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
sha256sum
```

Build a current `rns-server` first:

```bash
cargo build --release --bin rns-server --features rns-hooks-native
```

The script uses `target/release/rns-server` by default. If that binary is not
present, it falls back to `rns-server` from `PATH`.

## Daily Check

The operator's daily VPS check uses the extended profile:

```bash
scripts/manual-backbone-smoke.sh --daily
```

The profile currently selects:

| Setting | Daily value |
| --- | ---: |
| timeout | 300 seconds |
| Resource sizes | 1,024; 100,000; 1,048,575; 1,048,576 bytes |
| Resources per direction | 2 concurrently |
| link batches | 2 |
| links per direction and batch | 3 concurrently |
| added one-way latency per VPS leg | 150 ms |
| added jitter per VPS leg | up to 75 ms |
| approximate rate per direction and leg | 2,000 kbps |
| forced reconnect cycles | 1 |

Environment variables or explicit command-line options can override individual
daily values. A failure preserves diagnostics automatically. After reconnecting,
the profile allows replacement announces to converge and verifies ordinary
packets before starting a fresh link handshake. This distinguishes route
recovery failures from failures in retained link state.

## Default Run

From the repository root:

```bash
scripts/manual-backbone-smoke.sh
```

The default invocation remains a quick, unimpeded smoke test suitable for
ad-hoc checks. It does not select the daily stress profile.

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

Exercise Resource boundaries in both directions. Sizes are decimal bytes:

```bash
scripts/manual-backbone-smoke.sh --keep --timeout 240 \
  --resource-sizes 1024,100000,1048575,1048576
```

The `1048575`/`1048576` pair deliberately straddles Reticulum's one-megabyte
efficient-resource segmentation boundary. The test creates deterministic
payloads, verifies the received SHA-256 digest, reports elapsed time, and keeps
the generated payload and JSON request files when `--keep` is used.

Stress link establishment in both directions:

```bash
scripts/manual-backbone-smoke.sh --keep --timeout 240 \
  --link-iterations 20
```

Both extensions can be combined for a fuller live-backbone run:

```bash
scripts/manual-backbone-smoke.sh --keep --timeout 240 \
  --link-iterations 10 \
  --resource-sizes 1024,100000,1048575,1048576
```

Overlap Resources in both directions and establish links in concurrent batches:

```bash
scripts/manual-backbone-smoke.sh --keep --timeout 300 \
  --resource-sizes 1024,100000,1048576 --resource-concurrency 3 \
  --link-iterations 3 --link-concurrency 4
```

Add controlled network pressure to both VPS legs. Delay and jitter are one-way
values per leg; the end-to-end RTT includes both proxies and the real network.
The rate is an approximate limit in kilobits per second, per direction and leg:

```bash
scripts/manual-backbone-smoke.sh --keep --timeout 300 \
  --latency-ms 250 --jitter-ms 100 --rate-kbps 2000 \
  --resource-sizes 1024,100000,1048576 --resource-concurrency 2 \
  --link-iterations 2 --link-concurrency 3
```

Network impairment is implemented by `scripts/backbone-fault-proxy.py`; it does
not modify host-wide traffic control or either VPS. Sending `SIGUSR1` to a proxy
process closes its current Backbone TCP session, which is useful for manual
reconnection experiments. Proxy PIDs and logs are available in the test output
and preserved work directory while the test is running.

Automate that reconnection check instead of signalling the proxies manually:

```bash
scripts/manual-backbone-smoke.sh --keep --timeout 300 \
  --reconnect-cycles 3 --resource-sizes 100000
```

After every forced disconnect, the test waits for a new TCP session and a stable
Backbone interface, allows replacement announces to converge, verifies ordinary
packets in both directions, and only then verifies a fresh link, bidirectional
Channel messages, and the first configured Resource size in both directions.

The same settings can be provided with environment variables:

```bash
RNS_SMOKE_A_HOST=82.165.77.75 \
RNS_SMOKE_B_HOST=74.208.55.138 \
RNS_SMOKE_TIMEOUT=180 \
RNS_SMOKE_LINK_ITERATIONS=10 \
RNS_SMOKE_LINK_CONCURRENCY=4 \
RNS_SMOKE_RESOURCE_SIZES=1024,100000,1048575,1048576 \
RNS_SMOKE_RESOURCE_CONCURRENCY=3 \
RNS_SMOKE_LATENCY_MS=250 \
RNS_SMOKE_JITTER_MS=100 \
RNS_SMOKE_RATE_KBPS=2000 \
RNS_SMOKE_RECONNECT_CYCLES=3 \
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
- the wrapper stdout/stderr log for each local server;
- deterministic Resource payloads and file-backed API request bodies for any
  requested Resource sweep.
- impairment-proxy logs when controlled delay, jitter or rate limiting is used.

The script always stops both local `rns-server` processes on exit unless the
shell is force-killed.

## Interpreting Results

If startup fails, check the selected binary and local port availability.

If identity recall fails, the likely fault is announce propagation or path
request forwarding between the two backbone entry points.

If identity recall works but packets fail, focus on path table selection and
packet forwarding. Raw single-packet delivery is validated by packet hash and
destination hash because the HTTP packet list stores the raw wire packet bytes,
not the original plaintext payload.

If packets work but links fail, focus on link request routing, retained path
state and link packet forwarding.

If the first link works but the reverse link fails, check asymmetric paths,
blacklists or stale per-interface state on one backbone node.

If the impairment proxies reconnect and the interfaces report up but the
post-reconnect packet checkpoint times out, inspect announce convergence and
whether retained destination paths still reference pre-reconnect interface
state. If packets pass but the fresh link times out, focus on retained link
state. The proxy logs distinguish failure to reconnect the TCP session from
failure to route after reconnection.

If small Resources pass but a boundary size fails, compare the last passing and
first failing sizes, the negotiated link MTU/MDU, Resource progress events and
Backbone reconnect messages. A sender-side `completed` event without a matching
receiver checksum is treated as a failure. If the interface disconnects during
the transfer, the preserved endpoint and VPS logs should be correlated by UTC
time and link ID.
