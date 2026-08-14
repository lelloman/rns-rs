# rns-rs

[![CI](https://github.com/lelloman/rns-rs/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/lelloman/rns-rs/actions/workflows/ci.yml)
[![rns-core](https://img.shields.io/crates/v/rns-core.svg?label=rns-core)](https://crates.io/crates/rns-core)
[![rns-net](https://img.shields.io/crates/v/rns-net.svg?label=rns-net)](https://crates.io/crates/rns-net)
[![rns-server](https://img.shields.io/crates/v/rns-server.svg?label=rns-server)](https://crates.io/crates/rns-server)
[![upstream Reticulum](https://img.shields.io/badge/upstream%20Reticulum-1.4.2-blue)](UPSTREAM.md)

A Rust implementation of [Reticulum](https://github.com/markqvist/Reticulum), the cryptography-based networking stack for building resilient networks with readily available hardware.

This is a faithful port of the Python reference implementation, validated with Python-generated conformance vectors and live Python/Rust interoperability tests. `rns-crypto` and `rns-core` are `no_std`-compatible, making them suitable for embedded/microcontroller targets. rns-rs also extends Reticulum with features not present in the Python implementation, such as [Direct Link (NAT hole punching)](#direct-link-nat-hole-punching).

## Workspace Crates

| Crate | `no_std` | Description |
|-------|----------|-------------|
| [`rns-crypto`](https://crates.io/crates/rns-crypto) | Yes | Cryptographic primitives: X25519, Ed25519, AES-128/256-CBC, SHA-256/512, HMAC, HKDF, tokens, and identities |
| [`rns-core`](https://crates.io/crates/rns-core) | Yes | Wire protocol, destinations and packets, transport routing, links, channels, buffers, resources, and the hole-punch state machine |
| [`rns-net`](https://crates.io/crates/rns-net) | No | Network node and driver with TCP, UDP, Local, Serial, KISS, AX.25, RNode, Pipe, Backbone, Auto, I2P, and Weave interfaces, configuration, discovery, and Direct Link support |
| [`rns-server`](https://crates.io/crates/rns-server) | No | Batteries-included node supervisor with an embedded control plane and optional hook, sentinel, and statistics sidecars |
| [`rns-cli`](https://crates.io/crates/rns-cli) | No | CLI programs: `rnsd`, `rnstatus`, `rnpath`, `rnprobe`, `rnid`, `rnsh`, plus feature-gated `rns-sentineld` and `rns-statsd` sidecars |
| [`rns-git`](https://crates.io/crates/rns-git) | No | Git over Reticulum: the `rngit` repository server and management client, `git-remote-rns`, and the `rngcs` signing helper |
| [`rns-ctl`](https://crates.io/crates/rns-ctl) | No | Unified daemon and control CLI with HTTP/WebSocket APIs, status, probe, path, identity, runtime configuration, backbone, and hook management |
| [`rns-hooks`](https://crates.io/crates/rns-hooks) | No | Programmable transport-pipeline hook runtime with sandboxed WASM, trusted native dynamic-library, and built-in backends |
| [`rns-hooks-abi`](https://crates.io/crates/rns-hooks-abi) | Yes | Shared ABI types and constants used by hook hosts, native hooks, and WASM guests |
| [`rns-hooks-sdk`](https://crates.io/crates/rns-hooks-sdk) | Yes | Guest-side `no_std` SDK for writing `rns-hooks` WASM programs |
| [`rns-stats-hook`](https://crates.io/crates/rns-stats-hook) | Yes | Statistics hook used by `rns-statsd`, available as a WASM guest or built-in hook |
| [`rns-sentinel-hook`](https://crates.io/crates/rns-sentinel-hook) | Yes | Sentinel policy hook used by `rns-sentineld`, available as a WASM guest or built-in hook |

## Building

```bash
cargo build
```

### Selected Workspace Feature Flags

The flags below are common selections accepted by root workspace build commands. This is not an exhaustive list: individual package manifests define additional crate-specific features, including the complete set of `rns-net` `iface-*` flags and the low-level `rns-hooks` backend features.

| Flag | Effect |
|------|--------|
| `rns-hooks` | Compatibility alias for `rns-hooks-native` |
| `rns-hooks-wasm` | Enables WASM hooks (compiles in wasmtime) |
| `rns-hooks-native` | Enables trusted native dynamic-library hooks without wasmtime |
| `rns-hooks-builtin` | Enables static built-in hooks without wasmtime or dynamic libraries |
| `tls` | Enables TLS support in rns-ctl (compiles in rustls) |
| `iface-ax25-kiss` | Enables `AX25KISSInterface` (enabled by default in `rns-net`) |
| `iface-weave` | Enables Linux `WeaveInterface` support (enabled by default in `rns-net`) |

```bash
cargo build --features rns-hooks           # Enable native dynamic-library hooks
cargo build --features rns-hooks-native    # Enable native dynamic-library hooks explicitly
cargo build --features rns-hooks-wasm      # Enable WASM hooks
cargo build --features rns-hooks-builtin   # Enable static built-in hooks
cargo build --features tls          # Enable TLS in rns-ctl
```

To compile WASM guest hooks, including the examples under `rns-hooks/examples/`, add the WASM target. The host-side Wasmtime backend itself does not require this target:

```bash
rustup target add wasm32-unknown-unknown
```

## Running Tests

Committed conformance vectors are generated from the historical, pinned Reticulum 1.4.0 baseline. The current upstream reference is Reticulum 1.4.2, which is exercised separately by the live Python/Rust interop CI lane; see [UPSTREAM.md](UPSTREAM.md) for the exact commits and acceptance scope.

```bash
# Generate fixtures from the pinned Reticulum 1.4.0 checkout
RETICULUM_UPSTREAM_DIR=/path/to/Reticulum python3 tests/generate_vectors.py

# Run tests for the default workspace members
cargo test

# Run tests for a specific crate
cargo test -p rns-crypto
cargo test -p rns-core
cargo test -p rns-net
cargo test -p rns-cli
cargo test -p rns-git
cargo test -p rns-ctl
cargo test -p rns-hooks
```

## Developer Checks

Standard host-side validation commands:

```bash
# Full workspace tests
cargo test --workspace

# Host-safe workspace lint
bash scripts/lint-host.sh
```

The lint script enables native `rns-hooks` coverage, but intentionally does not use
workspace-wide `--all-features`. That would enable `rns-crypto/espidf`, which
pulls in `esp-idf-sys` and fails on normal `x86_64-unknown-linux-gnu` host
machines. ESP32 validation remains separate under `rns-esp32/`.

### Docker E2E Tests

There are 20 numbered Docker-based end-to-end suites that validate multi-node behaviour across chain, mesh, and star topologies. The full runner also includes standalone shared-client reconnection and `rns-server` supervision scenarios:

```bash
# Run all Docker e2e tests
cd tests/docker && ./run-all.sh

# Run a specific suite on the default 3-node chain
cd tests/docker && ./run.sh --topology chain-3 --suite 01
```

## rns-server

`rns-server` is the default program to run for a single node. In the normal deployment model, it is the only binary you need to build or ship. Hook-enabled builds self-spawn `rnsd`, `rns-sentineld`, and `rns-statsd` from the same executable.

If you just want to run a node, start here.

If you want to tinker with the transport internals, build custom workflows, or run pieces independently, the lower-level binaries and hook system are still available separately.

Development startup:

```bash
cargo run --bin rns-server -- start --config /path/to/node
```

Release-style startup:

```bash
cargo build --release --bin rns-server
./target/release/rns-server start --config /path/to/node
```

If you want native dynamic-library hooks enabled in the node runtime:

```bash
cargo build --release --bin rns-server --features rns-hooks
./target/release/rns-server start --config /path/to/node
```

Useful docs:

- [docs/rns-server-operator-runbook.md](docs/rns-server-operator-runbook.md)

## Interface Ingress Control

rns-rs accepts the Python-compatible ingress-control keys in any interface
section:

```ini
ingress_control = Yes
ic_max_held_announces = 256
ic_burst_hold = 60
ic_burst_freq_new = 3.5
ic_burst_freq = 12
ic_pr_burst_freq_new = 3.5
ic_pr_burst_freq = 12
egress_control = No
ec_pr_freq = 5
ic_new_time = 7200
ic_burst_penalty = 300
ic_held_release_interval = 30
```

Ingress control defaults to enabled on Auto, Backbone, TCP client/server, UDP,
and I2P interfaces. It defaults to disabled on local/serial/KISS/RNode/Pipe-style
interfaces. Spawned dynamic interfaces inherit the full ingress-control config
from their parent interface.

## Low-Level Tools

These are lower-level building blocks for development, debugging, custom setups,
and transport tinkering. Most users should prefer `rns-server`.

Build and run the CLI binaries:

```bash
# Run the daemon directly
cargo run --bin rnsd -- /path/to/config

# Check network status
cargo run --bin rnstatus

# Query paths
cargo run --bin rnpath

# Probe connectivity
cargo run --bin rnprobe

# Identity management
cargo run --bin rnid

# Remote shell over Reticulum
cargo run --bin rnsh -- -l -n -- /bin/sh
cargo run --bin rnsh -- <destination_hash>
```

Utility docs:

- [docs/rnsh.md](docs/rnsh.md)
- [docs/rns-git.md](docs/rns-git.md)

## Git over RNS

`rns-git` provides a repository server and Git remote helper for Reticulum links:

```bash
# Print repository and client identities
cargo run -p rns-git --bin rngit -- --print-identity

# Start the repository server after editing ~/.config/rngit/server_config
cargo run -p rns-git --bin rngit

# Configure a repository remote once git-remote-rns is on PATH
git remote add origin rns://<destination_hash>/<repository>
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

# Manage hooks through an authenticated control server
cargo run --bin rns-ctl -- hook list --token "replace-with-token-printed-by-rns-ctl-http"
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
- Incoming policy: `direct_connect_policy = accept_all` (default), `reject`,
  `identified_only`, or `ask_app`. `identified_only` avoids revealing the
  responder's public endpoint until the peer has completed Reticulum
  `LINKIDENTIFY`; `ask_app` fails closed unless the application callback accepts.

The new public policy variant and `NodeConfig` field are planned for the next
`rns-net` publish as version 0.8.0; this repository change does not publish or
deploy that release.

**API (via rns-ctl):**
- `POST /api/direct_connect {"link_id": "..."}` — initiate upgrade
- `GET /api/link_events` — monitor for `direct_established` / `direct_failed`

See [docs/direct-link-protocol.md](docs/direct-link-protocol.md) for the full protocol specification.

## Hooks

> **rns-rs extension** — this feature is not present in the original Python Reticulum implementation.

rns-rs includes an eBPF-inspired programmable hook system that lets users attach WASM modules or trusted native dynamic libraries to points in the transport pipeline. Hooks can inspect, filter, modify, or mirror packets, announces, links, and interfaces — without modifying rns-rs itself.

**Design principles:**

- **Crash-safe WASM hooks** — WASM traps, invalid results, and fuel exhaustion are isolated by the runtime and fail open, so processing continues as if the hook returned `Continue`
- **Trusted native hooks** — native hooks run in-process and are not crash-safe; they can block, corrupt, or terminate the node and must only load trusted code
- **Fuel-limited WASM** — WASM invocations run with a bounded fuel budget to prevent runaway execution
- **Instance persistence** — WASM linear memory survives across calls, so hooks can maintain counters, caches, or bloom filters
- **Native backend** — native hooks are loaded with `dlopen`/`LoadLibrary` and run in-process for targets where Wasmtime is unavailable, such as ARMv7
- **Hot-reload** — hooks can be reloaded at runtime without restarting the node (`rns-ctl hook reload`)
- **Zero overhead when disabled** — hook backends are behind cargo feature flags; `rns-hooks-native` does not compile in Wasmtime

**Hook points (21 total):**

| Category | Hook Points |
|----------|------------|
| Packet lifecycle | `PreIngress`, `PreDispatch` |
| Announce processing | `AnnounceReceived`, `PathUpdated`, `AnnounceRetransmit` |
| Link lifecycle | `LinkRequestReceived`, `LinkEstablished`, `LinkClosed` |
| Interface lifecycle | `InterfaceUp`, `InterfaceDown`, `InterfaceConfigChanged` |
| Backbone peer lifecycle | `BackbonePeerConnected`, `BackbonePeerDisconnected`, `BackbonePeerIdleTimeout`, `BackbonePeerWriteStall`, `BackbonePeerPenalty` |
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
    path = /tmp/drop_tick.so
    type = native
    attach_point = Tick
    priority = 10
    enabled = Yes

  [[log_announce]]
    path = /tmp/log_announce.wasm
    type = wasm
    attach_point = AnnounceReceived
    priority = 5
    enabled = Yes
```

**CLI management:**

The hook CLI talks to the HTTP control server, which enables bearer authentication by default. Pass the token printed when `rns-ctl http` starts (or omit `--token` only when the server was explicitly started with `--disable-auth`):

```bash
RNSCTL_TOKEN="replace-with-token-printed-by-rns-ctl-http"
rns-ctl hook list --token "$RNSCTL_TOKEN"                                                # list loaded hooks and their status
rns-ctl hook load <path-or-builtin-id> --point <HookPoint> --token "$RNSCTL_TOKEN" [--type wasm|native|builtin] [--priority N] [--name name]
rns-ctl hook unload <name> --point <HookPoint> --token "$RNSCTL_TOKEN"                   # unload a running hook
rns-ctl hook reload <name> --point <HookPoint> --path <hook_file_or_builtin_id> --token "$RNSCTL_TOKEN" [--type wasm|native|builtin]
```

**Writing hooks:**

Native hooks use the ABI types from `rns-hooks-abi::native` and export `rns_hook_abi_version` plus `rns_hook_on_call`; see `rns-hooks/examples/native_noop` and [docs/native-hooks.md](docs/native-hooks.md). Use the `rns-hooks-sdk` crate to write WASM hooks in `no_std` Rust. Each WASM hook exports an `on_hook` function that receives a context and returns a verdict. Built-in hooks are linked Rust functions registered by ID; see [docs/builtin-hooks.md](docs/builtin-hooks.md).

| Example | Description |
|---------|-------------|
| `packet_logger` | Log packets passing through a hook point |
| `announce_filter` | Drop announces exceeding a configurable hop count |
| `announce_dedup` | Deduplicate repeated announces using persistent state |
| `allowlist` | Allow only packets from known source hashes |
| `link_guard` | Guard link establishment with custom policies |
| `rate_limiter` | Rate-limit packets per interface |
| `metrics` | Collect counters and statistics across hook invocations |
| `packet_mirror` | Mirror packets to an additional destination |
| `path_modifier` | Demonstrate the Modify verdict by prepending a marker byte to packet data |
| `stats_scraper` | Emit packet and announce statistics for collection by the statistics sidecar |

## Interoperability

rns-rs is designed to be fully interoperable with the Python Reticulum implementation. A Rust node can join an existing Reticulum network alongside Python nodes, exchange announces, establish links, and transfer resources.

The current wire-level protocol is described in [docs/protocol-spec.md](docs/protocol-spec.md).

## License

[Reticulum License](LICENSE)
