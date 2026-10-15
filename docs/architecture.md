# Architecture

rns-rs is a Cargo workspace. The crates form a strict layering: each layer
depends only on the layers below it, and the two lowest layers compile without
`std`.

```text
 applications and operators
 ─────────────────────────────────────────────────────────────
 rns-server      supervisor + control plane + built-in UI
 rns-ctl         unified daemon/control CLI, HTTP + WebSocket API
 rns-cli         rnsd, rnstatus, rnpath, rnprobe, rnid, rnsh, rncp, rnx,
                 rns-statsd, rns-sentineld
 rns-git         rngit, git-remote-rns, rngcs
 rns-tun         rntun (Linux)         rns-tun-android (JNI)
 ─────────────────────────────────────────────────────────────
 rns-net         node driver, interfaces, config, discovery, Direct Link
                 ├── rns-hooks        hook runtime (WASM / native / built-in)
                 │   ├── rns-hooks-abi   shared ABI types          (no_std)
                 │   └── rns-hooks-sdk   WASM guest SDK            (no_std)
                 ├── rns-stats-hook   statistics hook
                 └── rns-sentinel-hook  policy hook
 ─────────────────────────────────────────────────────────────
 rns-core        wire protocol, destinations, transport routing, links,
                 channels, buffers, resources, hole-punch state machine (no_std)
 rns-crypto      X25519, Ed25519, AES-CBC, SHA-2, HMAC, HKDF, tokens,
                 identities                                        (no_std)
```

The ESP32 firmware (`rns-esp32`) builds against `rns-crypto` and `rns-core`
but lives outside the root workspace because it needs the Espressif toolchain.

## Crates

| Crate | `no_std` | Role |
|-------|----------|------|
| [`rns-crypto`](https://crates.io/crates/rns-crypto) | Yes | Cryptographic primitives and identities. Default feature `std`; `espidf` selects the ESP-IDF backend |
| [`rns-core`](https://crates.io/crates/rns-core) | Yes | Everything that is pure protocol: packet encoding, announce validation, the `TransportEngine` routing state machine, links, channels, buffers, resources, and the Direct Link hole-punch state machine. No sockets, no threads |
| [`rns-net`](https://crates.io/crates/rns-net) | No | The node. Drives `rns-core` with real sockets and threads, reads Python-compatible config files, owns the interfaces, persists identity and known destinations, and exposes the application API (`RnsNode`) |
| [`rns-hooks`](https://crates.io/crates/rns-hooks) | No | Hook runtime with three backends: sandboxed WASM via Wasmtime, trusted native dynamic libraries, and built-in Rust functions |
| [`rns-hooks-abi`](https://crates.io/crates/rns-hooks-abi) | Yes | ABI types and constants shared by hook hosts, native hooks, and WASM guests |
| [`rns-hooks-sdk`](https://crates.io/crates/rns-hooks-sdk) | Yes | Guest-side SDK for writing WASM hooks in Rust |
| [`rns-stats-hook`](https://crates.io/crates/rns-stats-hook) | WASM builds | Statistics hook consumed by `rns-statsd` |
| [`rns-sentinel-hook`](https://crates.io/crates/rns-sentinel-hook) | WASM builds | Sentinel policy hook consumed by `rns-sentineld` |
| [`rns-cli`](https://crates.io/crates/rns-cli) | No | The classic Reticulum command-line programs plus the two sidecar daemons |
| [`rns-ctl`](https://crates.io/crates/rns-ctl) | No | One binary that can run the daemon, serve the HTTP/WebSocket control API, and act as a client for status, probe, path, identity, config, backbone, and hook management |
| [`rns-server`](https://crates.io/crates/rns-server) | No | Batteries-included entrypoint: supervises `rnsd` and the sidecars, embeds the `rns-ctl` control plane and UI, manages `rns-server.json` |
| [`rns-git`](https://crates.io/crates/rns-git) | No | Git over Reticulum: `rngit` server and management client, `git-remote-rns` remote helper, `rngcs` signing helper |
| [`rns-tun`](../rns-tun/README.md) | No | Authenticated IPv4 tunnelling over a Reticulum Link, with the Linux `rntun` CLI |
| [`rns-tun-android`](../rns-tun-android/README.md) | No | JNI boundary used by the Android VPN client |
| [`rns-bench`](../bench/README.md) | No | Benchmark workloads and measurement tooling under `tools/` |
| [`rns-esp32`](../rns-esp32/README.md) | n/a | LoRa transport node firmware, excluded from the root workspace |

Only the first two crates and the hook ABI/SDK crates are `no_std`. For
`rns-crypto` and `rns-core`, disable default features to drop `std`.

## Interfaces

`rns-net` implements the Reticulum interface types as independent Cargo
features so a deployment can compile only what it needs. The full set, all
enabled by default:

| Feature | Interface types |
|---------|-----------------|
| `iface-tcp` | `TCPClientInterface`, `TCPServerInterface` |
| `iface-udp` | `UDPInterface` |
| `iface-local` | Shared-instance `LocalInterface` and the remote-management RPC. Always present in the CLI crates |
| `iface-auto` | `AutoInterface` (IPv6 link-local discovery) |
| `iface-serial` | `SerialInterface` |
| `iface-kiss` | `KISSInterface` |
| `iface-ax25-kiss` | `AX25KISSInterface` (implies `iface-kiss`) |
| `iface-pipe` | `PipeInterface` |
| `iface-rnode` | `RNodeInterface` over serial, TCP, or BLE |
| `iface-backbone` | `BackboneInterface` with peer pool and discovery |
| `iface-i2p` | `I2PInterface` via SAM |
| `iface-weave` | `WeaveInterface` (Linux only) |

[Building](building.md) shows how to select a subset for `rns-cli` and
`rns-ctl`.

## Runtime shapes

There are three ways to run a node, all using the same config format and state
directory:

1. **`rns-server`**: the default. One binary supervises `rnsd` and the sidecars
   by re-executing itself with hidden role flags, and embeds the control plane.
   Use this unless you have a reason not to. See the
   [operator runbook](rns-server-operator-runbook.md).
2. **`rnsd` plus the CLI tools**: the Python-style layout. `rnsd` runs the node
   and exposes a shared instance; `rnstatus`, `rnpath`, `rnprobe`, `rnsh`,
   `rncp`, and `rnx` connect to it. See [CLI Tools](cli-tools.md).
3. **`rns-ctl`**: a single binary that can play either side. `rns-ctl daemon`
   runs the node, `rns-ctl http` runs the node together with the HTTP/WebSocket
   API, and the remaining subcommands are clients. See [rns-ctl](rns-ctl.md).

Applications that embed the stack depend on `rns-net` directly and construct
an `RnsNode`. `rntun` and the ESP32 firmware both do this with private nodes
rather than attaching to a shared `rnsd`.

## Extensions beyond Python Reticulum

Two subsystems have no counterpart in the reference implementation. Both are
opt-in and interoperate with Python nodes that do not know about them.

- [Hooks](hooks.md): an eBPF-inspired programmable pipeline with 21 attach
  points covering packets, announces, links, interfaces, Backbone peers,
  per-action dispatch, and a periodic tick.
- [Direct Link](direct-link.md): negotiated upgrade of an established link to
  a direct UDP path through NAT, with transport nodes acting as STUN-like
  facilitators.

Other rns-rs additions that stay within the wire protocol: local destination
[ratchets](local-ratchets.md), Linux `SO_MARK` socket marking, interface
feature gating, and the `rns-git`, `rns-tun`, and ESP32 products.
