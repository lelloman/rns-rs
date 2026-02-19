# rns-rs

A Rust implementation of [Reticulum](https://github.com/markqvist/Reticulum), the cryptography-based networking stack for building resilient networks with readily available hardware.

This is a faithful port of the Python reference implementation, validated against it with 900+ interop tests. `rns-crypto` and `rns-core` are `no_std`-compatible with zero external dependencies, making them suitable for embedded/microcontroller targets. rns-rs also extends Reticulum with features not present in the Python implementation, such as [Direct Link (NAT hole punching)](#direct-link-nat-hole-punching).

## Workspace Crates

| Crate | `no_std` | Description |
|-------|----------|-------------|
| `rns-crypto` | Yes | Cryptographic primitives: X25519, Ed25519, AES-256-CBC, SHA-256/512, HMAC, HKDF, Identity |
| `rns-core` | Yes | Wire protocol, transport routing engine, link/channel/buffer, resource transfers, holepunch state machine |
| `rns-net` | No | Network node: TCP/UDP/Serial/KISS/RNode/Pipe/Backbone/Auto interfaces, config parsing, driver loop, DirectLink NAT hole punching |
| `rns-cli` | No | CLI tools: `rnsd`, `rnstatus`, `rnpath`, `rnprobe`, `rnid` |
| `rns-ctl` | No | HTTP/WebSocket control server: REST API + WebSocket for monitoring and controlling RNS nodes |
| `rns-hooks` | No | WASM hook system: 16 programmable hook points across the transport pipeline, powered by wasmtime. Inspired by eBPF — fail-open, fuel-limited, hot-reloadable |
| `rns-hooks-sdk` | Yes | Guest-side SDK for writing `rns-hooks` WASM programs in `no_std` Rust |

## Building

```bash
cargo build
```

## Running Tests

Test vectors are generated from the Python RNS implementation:

```bash
# Generate test fixtures (requires Python RNS installed)
python3 tests/generate_vectors.py

# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p rns-crypto
cargo test -p rns-core
cargo test -p rns-net
cargo test -p rns-cli
cargo test -p rns-ctl
cargo test -p rns-hooks
```

## CLI Tools

Build and run the CLI binaries:

```bash
# Run the daemon
cargo run --bin rnsd -- /path/to/config

# Check network status
cargo run --bin rnstatus

# Query paths
cargo run --bin rnpath

# Probe connectivity
cargo run --bin rnprobe

# Identity management
cargo run --bin rnid
```

## rns-ctl

`rns-ctl` is a unified CLI tool that combines daemon, control server, and all CLI utilities into a single binary:

```bash
# Start the HTTP/WebSocket control server
cargo run --bin rns-ctl -- http -c /path/to/config

# Start the RNS daemon
cargo run --bin rns-ctl -- daemon -c /path/to/config

# Check network status
cargo run --bin rns-ctl -- status

# Probe path reachability
cargo run --bin rns-ctl -- probe <destination_hash>

# Display/manage path table
cargo run --bin rns-ctl -- path -t

# Identity management
cargo run --bin rns-ctl -- id -g /path/to/identity

# Manage WASM hooks
cargo run --bin rns-ctl -- hook list
```

The `http` subcommand starts an HTTP/WebSocket control server:

```bash
# Run with auth token
cargo run --bin rns-ctl -- http --token my-secret-token

# Run with disabled auth (for testing)
cargo run --bin rns-ctl -- http --disable-auth

# Run on a custom port
cargo run --bin rns-ctl -- http --port 9090
```

The server exposes:
- HTTP API on `http://localhost:8080` (configurable via `--port` or `RNSCTL_HTTP_PORT`)
- WebSocket endpoint at `ws://localhost:8080/ws`

## Direct Link (NAT Hole Punching)

> **rns-rs extension** — this feature is not present in the original Python Reticulum implementation.

rns-rs can upgrade an existing Reticulum link to a direct peer-to-peer UDP connection, bypassing transport nodes entirely. This reduces latency and offloads bandwidth from shared infrastructure.

The protocol uses a STUN-like probe to discover public endpoints, negotiates the upgrade over the existing link's channel, then both peers simultaneously punch through their NATs.

**Configuration:**
- Facilitator (transport node): `probe_port = 4343` in `[reticulum]`
- Client (behind NAT): `probe_addr = <facilitator_ip>:4343` in `[reticulum]`

**API (via rns-ctl):**
- `POST /api/direct_connect {"link_id": "..."}` — initiate upgrade
- `GET /api/link_events` — monitor for `direct_established` / `direct_failed`

See [docs/direct-link-protocol.md](docs/direct-link-protocol.md) for the full protocol specification.

## WASM Hooks

> **rns-rs extension** — this feature is not present in the original Python Reticulum implementation.

rns-rs includes an eBPF-inspired programmable hook system that lets users attach WebAssembly programs to 16 points in the transport pipeline. Hooks can inspect, filter, modify, or mirror packets, announces, links, and interfaces — without modifying rns-rs itself.

**Design principles:**

- **Fail-open** — a buggy or crashing hook never takes down the node; execution continues as if the hook returned `Continue`
- **Fuel-limited** — each invocation runs with a bounded fuel budget to prevent runaway execution
- **Instance persistence** — WASM linear memory survives across calls, so hooks can maintain counters, caches, or bloom filters
- **Hot-reload** — hooks can be reloaded at runtime without restarting the node (`rns-ctl hook reload`)
- **Zero overhead when disabled** — the entire system is behind the `rns-hooks` cargo feature flag; when disabled, no WASM runtime is compiled in

**Hook points (16 total):**

| Category | Hook Points |
|----------|------------|
| Packet lifecycle | `PreIngress`, `PreDispatch` |
| Announce processing | `AnnounceReceived`, `PathUpdated`, `AnnounceRetransmit` |
| Link lifecycle | `LinkRequestReceived`, `LinkEstablished`, `LinkClosed` |
| Interface lifecycle | `InterfaceUp`, `InterfaceDown`, `InterfaceConfigChanged` |
| Per-action | `SendOnInterface`, `BroadcastOnAllInterfaces`, `DeliverLocal`, `TunnelSynthesize` |
| Periodic | `Tick` |

**Verdicts:** each hook returns a verdict that controls what happens next:

- `Continue` — pass through normally
- `Drop` — block the packet/action
- `Modify` — replace with modified data
- `Halt` — stop the hook chain (no further hooks at this attach point are executed)

**Configuration:**

```ini
[hooks]
  [[drop_tick]]
    path = /tmp/drop_tick.wasm
    attach_point = Tick
    priority = 10
    enabled = Yes

  [[log_announce]]
    path = /tmp/log_announce.wasm
    attach_point = AnnounceReceived
    priority = 5
    enabled = Yes
```

**CLI management:**

```bash
rns-ctl hook list          # list loaded hooks and their status
rns-ctl hook load <name>   # load a hook from config
rns-ctl hook unload <name> # unload a running hook
rns-ctl hook reload        # hot-reload all hooks
```

**Writing hooks:**

Use the `rns-hooks-sdk` crate to write hooks in `no_std` Rust. Each hook exports an `on_hook` function that receives a context and returns a verdict. See the `rns-hooks/examples/` directory for complete examples:

| Example | Description |
|---------|-------------|
| `packet_logger` | Log packets passing through a hook point |
| `announce_filter` | Filter announces by destination hash prefix |
| `announce_dedup` | Deduplicate repeated announces using persistent state |
| `allowlist` | Allow only packets from known source hashes |
| `link_guard` | Guard link establishment with custom policies |
| `rate_limiter` | Rate-limit packets per interface |
| `metrics` | Collect counters and statistics across hook invocations |
| `packet_mirror` | Mirror packets to an additional destination |
| `path_modifier` | Modify path table entries on announce |

## Interoperability

rns-rs is designed to be fully interoperable with the Python Reticulum implementation. A Rust node can join an existing Reticulum network alongside Python nodes, exchange announces, establish links, and transfer resources.

## License

[Reticulum License](LICENSE)
