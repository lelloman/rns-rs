# Hooks

> **rns-rs extension.** Python Reticulum has no equivalent. Hooks run only on
> the local node and never change what goes on the wire unless a hook chooses
> to drop or modify a packet, so nodes with and without hooks interoperate.

The hook system is an eBPF-inspired way to attach small programs to points in
the transport pipeline. A hook can inspect, filter, modify, or mirror packets,
announces, links, interfaces, and Backbone peer events without changing
rns-rs itself. Three backends are available, each behind a Cargo feature
(see [Building](building.md#hook-backends)):

| Backend | Trust model | Where it runs | When to use it |
|---------|-------------|---------------|----------------|
| WASM (`rns-hooks-wasm`) | Sandboxed. Traps, bad results, and fuel exhaustion fail open | Wasmtime inside the node | Untrusted or third-party hooks on hosts where Wasmtime builds |
| Native (`rns-hooks-native`) | Trusted. Can block, corrupt, or crash the node | `dlopen`/`LoadLibrary` in-process | ARMv7 and other targets without Wasmtime; first-party code |
| Built-in (`rns-hooks-builtin`) | Trusted. Linked into the binary | In-process, loaded by ID | Appliances and single-binary deployments |

## Design principles

- **Crash-safe WASM.** A trap, an invalid result, or fuel exhaustion is
  isolated by the runtime and treated as `Continue`.
- **Fuel-limited WASM.** Every invocation has a bounded fuel budget. Bytes
  copied by host functions are charged against the same budget.
- **Bounded WASM resources.** Each instance gets at most 16 MiB of linear
  memory (a failed `memory.grow` traps), 64-bit memories are rejected at load,
  and each invocation may inject at most 64 actions (256 KiB) and emit at most
  256 provider events (256 KiB). Further calls return `-3`.
- **Instance persistence.** WASM linear memory survives across calls, so hooks
  can keep counters, caches, or bloom filters.
- **Trusted native and built-in hooks.** They run with the node's privileges
  and are not crash-safe. Load only code you trust.
- **Hot reload.** `rns-ctl hook reload` swaps a hook without restarting the
  node.
- **Zero cost when disabled.** Without a hook feature, no hook code is
  compiled in. `rns-hooks-native` and `rns-hooks-builtin` do not pull in
  Wasmtime.

## Hook points

21 attach points, grouped by what they observe:

| Category | Hook points |
|----------|-------------|
| Packet lifecycle | `PreIngress`, `PreDispatch` |
| Announce processing | `AnnounceReceived`, `PathUpdated`, `AnnounceRetransmit` |
| Link lifecycle | `LinkRequestReceived`, `LinkEstablished`, `LinkClosed` |
| Interface lifecycle | `InterfaceUp`, `InterfaceDown`, `InterfaceConfigChanged` |
| Backbone peer lifecycle | `BackbonePeerConnected`, `BackbonePeerDisconnected`, `BackbonePeerIdleTimeout`, `BackbonePeerWriteStall`, `BackbonePeerPenalty` |
| Per-action | `SendOnInterface`, `BroadcastOnAllInterfaces`, `DeliverLocal`, `TunnelSynthesize` |
| Periodic | `Tick` |

## Verdicts

Each hook returns one verdict:

| Verdict | Effect |
|---------|--------|
| `Continue` | Pass through normally |
| `Drop` | Block the packet or action |
| `Modify` | Replace the packet bytes. Honoured at `PreIngress`, `SendOnInterface`, `BroadcastOnAllInterfaces`, and `DeliverLocal`; the replacement must decode as a packet and fit the interface MTU or the packet is dropped. Elsewhere it acts as `Continue` |
| `Halt` | Stop the chain. No further hooks run at this attach point |

Per-hook-point verdict handling is tabulated in
[Native Hooks](native-hooks.md#verdicts).

## Loading hooks

**At startup**, from the node config:

```ini
[hooks]
  [[drop_tick]]
    path = /opt/rns/hooks/drop_tick.so
    type = native
    attach_point = Tick
    priority = 10
    enabled = Yes

  [[log_announce]]
    path = /opt/rns/hooks/log_announce.wasm
    type = wasm
    attach_point = AnnounceReceived
    priority = 5
    enabled = Yes
```

**At runtime**, through `rns-ctl hook load|unload|reload|list` or the
`/api/hook/*` endpoints. Both need the control-plane bearer token, and native
hooks loaded at runtime must live inside the configured hooks directory. The
exact commands and path rules are in [rns-ctl](rns-ctl.md#hook-management-from-the-cli).

## Writing hooks

**WASM.** Use the `rns-hooks-sdk` crate from `rns-hooks/sdk/` in a `no_std`
`cdylib`. Export `on_hook(ctx_ptr: i32) -> i32`; read the context type with
`context::context_type`, cast to the matching context struct, call host
functions such as `host::log_str`, and return a verdict through a static
`HookResult`. Build with `./rns-hooks/build-examples.sh` or
`cargo build --target wasm32-unknown-unknown --release`.

**Native.** Use the ABI types from `rns-hooks-abi::native` and export
`rns_hook_abi_version` and `rns_hook_on_call`. The `native_noop` example is the
template; [Native Hooks](native-hooks.md) has the full contract.

**Built-in.** Register a Rust function under an ID in the host binary and load
it by that ID. See [Built-In Hooks](builtin-hooks.md).

Examples under `rns-hooks/examples/`:

| Example | Shows |
|---------|-------|
| `packet_logger` | Logging packets at a hook point |
| `announce_filter` | Dropping announces above a hop count |
| `announce_dedup` | Deduplicating announces with persistent state |
| `allowlist` | Admitting only packets from known source hashes |
| `link_guard` | Policy on link establishment |
| `rate_limiter` | Per-interface rate limiting |
| `metrics` | Counters that survive across invocations |
| `packet_mirror` | Mirroring packets to another destination |
| `path_modifier` | The `Modify` verdict, raising the hop count of announces at `PreIngress` |
| `stats_scraper` | Emitting packet and announce statistics for `rns-statsd` |
| `native_noop` | Minimal native hook |

## First-party hooks

`rns-stats-hook` and `rns-sentinel-hook` are the hooks behind the `rns-statsd`
and `rns-sentineld` sidecars. Each is published as a WASM guest and as a
built-in hook (`builtin` feature) so the same binary works with any backend.
See [CLI Tools](cli-tools.md#sidecars-rns-statsd-and-rns-sentineld).
