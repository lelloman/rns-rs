# rns-hooks: eBPF-inspired WASM Hook System for rns-rs

## Context

Implement a programmable hook system inspired by Linux eBPF, allowing users to load/unload arbitrary WASM programs that can observe, filter, modify, and inject actions at **every stage** of the RNS transport pipeline. This is not just a packet filter — it's a general-purpose programmable pipeline where hooks can attach to any event: packet processing, announce handling, link lifecycle, interface state changes, action dispatch, and periodic ticks.

**Goals:**
- Rust SDK initially (multi-language support is a future goal)
- Full Turing-complete capabilities (observe, filter, modify, inject)
- Hook into all key transport events (packet ingress/egress, announces, path updates, links, interfaces, all TransportActions)
- Safe sandboxing with resource limits (memory, execution time)
- Fail-open error handling — buggy hooks never take down the network

**Primary design constraint: Zero cost when no hooks are attached** (inspired by Linux eBPF). The entire hook system is behind an `rns-hooks` feature flag. When enabled but no hooks are loaded, the cost is a single indirect function call to a no-op per hook point. See [Performance](#performance) section.

---

## Architecture

### New Crate: `rns-hooks`

```
rns-hooks/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Public API: HookManager
│   ├── runtime.rs          # Wasmtime wrapper with fuel limits
│   ├── hooks.rs            # HookPoint enum, HookSlot, function pointer swap
│   ├── context.rs          # repr(C) context structs (arena layout)
│   ├── result.rs           # HookResult, Verdict (returned from WASM)
│   ├── wire.rs             # ActionWire (repr(C) wire types for WASM boundary)
│   ├── host_fns.rs         # Host functions exposed to WASM
│   ├── program.rs          # LoadedProgram lifecycle
│   └── error.rs            # HookError enum
├── sdk/                    # SDK crate for writing WASM hook programs
│   └── rns-hooks-sdk/
│       ├── Cargo.toml
│       └── src/
│           └── lib.rs      # repr(C) structs, arena helpers, host fn wrappers
└── examples/
    ├── packet_logger/
    ├── announce_filter/
    └── path_modifier/
```

### Feature Flag

The entire hook system is behind a feature flag. When disabled, no wasmtime dependency is compiled and hook call sites compile to nothing.

```toml
# rns-net/Cargo.toml
[features]
default = []
rns-hooks = ["dep:rns-hooks"]

[dependencies]
rns-hooks = { path = "../rns-hooks", optional = true }
```

```rust
/// Call site macro — compiles to None when feature is off.
macro_rules! run_hook {
    ($self:expr, $point:expr, $ctx:expr) => {{
        #[cfg(feature = "rns-hooks")]
        { ($self.hook_slots[$point as usize].runner)(&$self.hook_slots[$point as usize], &$ctx) }
        #[cfg(not(feature = "rns-hooks"))]
        { None::<HookResult> }
    }};
}
```

### Runtime Choice: wasmtime

- **Fuel-based execution** — prevents infinite loops with deterministic limits
- **WASI support** — optional controlled I/O
- **Native Rust integration** — `#[wasmtime::wasmexport]` macros

---

## Hook Points

```rust
pub enum HookPoint {
    // Packet lifecycle
    PreIngress,           // After IFAC, before engine (raw bytes)
    PreDispatch,          // After engine, before action dispatch

    // Announce processing
    AnnounceReceived,     // After validation, before path update
    PathUpdated,          // After path table update
    AnnounceRetransmit,   // Before retransmission (TransportAction variant)

    // Link lifecycle (TransportAction variants)
    LinkRequestReceived,
    LinkEstablished,
    LinkClosed,

    // Interface lifecycle (Event variants, not TransportAction — see note below)
    InterfaceUp,
    InterfaceDown,
    InterfaceConfigChanged,

    // Per-action hooks (existing TransportAction variants)
    SendOnInterface,
    BroadcastOnAllInterfaces,
    DeliverLocal,
    TunnelSynthesize,

    // Periodic
    Tick,
}
```

---

## WASM ABI: repr(C) Arena Layout

The WASM boundary uses `#[repr(C)]` structs with an arena layout — no serialization library needed. The host writes a contiguous block into WASM linear memory (fixed-size header + variable-length data at offsets), and the guest reads fields via pointer cast. This is the same approach as eBPF's `xdp_md` / `__sk_buff`.

### PacketContext

```rust
/// Shared between host and guest. Passed by pointer into WASM linear memory.
#[repr(C)]
pub struct PacketContext {
    pub flags: u8,
    pub hops: u8,
    pub destination_hash: [u8; 16],
    pub context: u8,
    pub packet_hash: [u8; 32],
    pub interface_id: u64,
    // Variable-length data: offset from start of this struct
    pub data_offset: u32,
    pub data_len: u32,
}
```

Arena memory layout in WASM linear memory:
```
[PacketContext header (fixed fields + offset/len)] [packet payload bytes...]
```

### ActionWire

`ActionWire` mirrors `TransportAction` with all 10 variants, using `u64` for interface IDs (with `From<InterfaceId>` / `Into<InterfaceId>` conversions on the host side).

`InterfaceId` is `pub struct InterfaceId(pub u64)` (defined in `rns-core/src/transport/types.rs:6`).

```rust
#[repr(C)]
pub enum ActionWire {
    SendOnInterface { interface: u64, raw_offset: u32, raw_len: u32 },
    BroadcastOnAllInterfaces { raw_offset: u32, raw_len: u32, exclude: u64, has_exclude: u8 },
    DeliverLocal { destination_hash: [u8; 16], raw_offset: u32, raw_len: u32, packet_hash: [u8; 32] },
    AnnounceReceived {
        destination_hash: [u8; 16],
        identity_hash: [u8; 16],
        public_key: [u8; 64],
        name_hash: [u8; 10],
        random_hash: [u8; 10],
        app_data_offset: u32,
        app_data_len: u32,   // 0 if no app_data
        hops: u8,
        receiving_interface: u64,
    },
    PathUpdated { destination_hash: [u8; 16], hops: u8, next_hop: [u8; 16], interface: u64 },
    ForwardToLocalClients { raw_offset: u32, raw_len: u32, exclude: u64, has_exclude: u8 },
    ForwardPlainBroadcast { raw_offset: u32, raw_len: u32, to_local: u8, exclude: u64, has_exclude: u8 },
    CacheAnnounce { packet_hash: [u8; 32], raw_offset: u32, raw_len: u32 },
    TunnelSynthesize { interface: u64, data_offset: u32, data_len: u32, dest_hash: [u8; 16] },
    TunnelEstablished { tunnel_id: [u8; 32], interface: u64 },
}
```

---

## Hook Result

```rust
#[repr(C)]
pub struct HookResult {
    pub verdict: u32,           // Verdict as u32 discriminant
    pub modified_data_offset: u32,
    pub modified_data_len: u32, // 0 if no modification
    pub inject_actions_offset: u32,
    pub inject_actions_count: u32, // 0 if no injections
    pub log_offset: u32,
    pub log_len: u32,           // 0 if no log message
}

pub enum Verdict {
    Continue = 0,   // Pass through normally
    Drop = 1,       // Block packet/action
    Modify = 2,     // Replace with modified data
    Halt = 3,       // Stop hook chain — no further hooks at this point are executed
}
```

---

## Hook Chain Ordering

- **Higher priority value = higher priority** (executed first)
- **Equal priority**: first-loaded program executes first (insertion order)
- `Halt` verdict stops the chain — no further hooks at this hook point are executed
- `Modify` verdict: modified data flows down to the next hook in the chain

---

## Host Functions (Exposed to WASM)

### Read-only State Access

| Function | Purpose |
|----------|---------|
| `host_log(ptr, len)` | Log message (reads string from guest memory) |
| `host_has_path(dest_ptr)` | Check if path exists for destination hash |
| `host_get_hops(dest_ptr)` | Get hop count to destination |
| `host_get_next_hop(dest_ptr, out_ptr)` | Get next hop hash, writes to out_ptr |
| `host_is_blackholed(identity_ptr)` | Check if identity is blacklisted |
| `host_get_interface_name(id, out_ptr, out_len)` | Get interface name string |
| `host_get_interface_mode(id)` | Get interface mode (ROAMING/BOUNDARY/AP/etc.) |
| `host_get_announce_rate(id)` | Get current announce frequency for interface |
| `host_get_link_state(link_hash_ptr)` | Check if a link is active |
| `host_get_transport_identity(out_ptr)` | Get this node's identity hash |

### Action Injection

| Function | Purpose |
|----------|---------|
| `host_inject_action(action_ptr, action_len)` | Inject a new TransportAction — unrestricted |

`host_inject_action` is unrestricted: hooks can inject any action type on any interface. The hook author is trusted.

---

## Error Handling

**Fail-open with auto-disable.**

| Failure | Behavior |
|---------|----------|
| Fuel exhaustion | Treat as `Verdict::Continue` — packet passes through. Log warning. |
| WASM trap (panic, OOB) | Treat as `Verdict::Continue`. Log warning. Increment trap counter. |
| Invalid return data | Treat as trap (same handling). |
| N consecutive traps | Auto-disable the hook. Log error. Default N = 10 (configurable). |

A buggy hook never takes down the network. The hook is silently bypassed on failure and automatically disabled if it keeps failing.

---

## Resource Limits

| Resource | Default |
|----------|---------|
| Memory | 16 MB (256 pages) |
| Execution fuel | 10M units (~1-10ms) |
| Stack depth | 256 frames |

---

## Performance

### Zero-Cost Design: Function Pointer Swap

Inspired by eBPF's JIT patching. Each `HookPoint` has a `HookSlot` with a function pointer. Default points to a no-op. When hooks are added or removed (rare — config load, hot reload), the pointer is swapped. The hot path is a single indirect call.

```rust
type HookFn = fn(&HookSlot, &HookContext) -> Option<HookResult>;

/// No-op — returns immediately. This is the default for all hook points.
fn hook_noop(_slot: &HookSlot, _ctx: &HookContext) -> Option<HookResult> {
    None
}

/// Runs the hook chain — only called when hooks are actually attached.
fn hook_run_chain(slot: &HookSlot, ctx: &HookContext) -> Option<HookResult> {
    // slot.programs is pre-sorted by priority (higher first)
    for program in &slot.programs {
        let result = program.invoke(ctx);
        match result.verdict {
            Verdict::Halt | Verdict::Drop => return Some(result),
            Verdict::Continue => continue,
            Verdict::Modify => { /* update ctx with modified data, continue chain */ }
        }
    }
    None
}

struct HookSlot {
    programs: Vec<LoadedProgram>,  // sorted by priority (higher first)
    runner: HookFn,               // points to hook_noop or hook_run_chain
}

impl HookSlot {
    /// Called on hook add/remove — NOT on the hot path.
    fn update(&mut self) {
        self.runner = if self.programs.is_empty() {
            hook_noop
        } else {
            hook_run_chain
        };
    }
}
```

Hot path call site (via `run_hook!` macro):
```rust
// Single indirect call — noop when empty, runs chain when populated
let result = (self.hook_slots[HookPoint::PreIngress as usize].runner)(
    &self.hook_slots[HookPoint::PreIngress as usize],
    &ctx,
);
```

### Benchmark Plan

Measure these to validate the zero-cost claim:

1. **Baseline**: Packet throughput with `rns-hooks` feature disabled (no hook code compiled)
2. **No hooks loaded**: Feature enabled, no hooks registered (should match baseline — just a noop indirect call)
3. **Trivial hook**: 1 pass-through hook attached
4. **Complex hook**: 1 filtering + logging hook attached

Compare (1) vs (2) to verify zero-cost. Compare (2) vs (3)/(4) to measure per-hook overhead.

---

## Integration Points

### 1. Driver (`rns-net/src/driver.rs`)

Add `hook_slots: [HookSlot; HookPoint::COUNT]` to `Driver` struct (behind `#[cfg(feature = "rns-hooks")]`).

Frame handling is inline in `Driver::run()` within the `Event::Frame` match arm (driver.rs ~lines 218-267). Integration points:

```rust
// In Driver::run(), Event::Frame match arm:
Event::Frame { interface_id, data } => {
    // ... existing stats update, IFAC processing ...

    // PreIngress hook (after IFAC, before engine)
    let result = run_hook!(self, HookPoint::PreIngress, &context);
    if matches!(result, Some(r) if r.verdict == Verdict::Drop) { continue; }

    // ... existing announce freq tracking ...

    let actions = self.engine.handle_inbound(
        &packet,
        interface_id,
        time::now(),
        &mut self.rng,
    );

    // PreDispatch hook
    let result = run_hook!(self, HookPoint::PreDispatch, &context);
    // Apply verdict to actions

    self.dispatch_all(actions);
}
```

### 2. TransportAction Dispatch

Each action type gets its own hook point called in `dispatch_all()` (driver.rs ~line 908).

### 3. New TransportAction Variants for Lifecycle Hook Points

`LinkRequestReceived`, `LinkEstablished`, `LinkClosed`, and `AnnounceRetransmit` are internal engine state changes that currently have no corresponding `TransportAction`. To make them available as hook points, add new `TransportAction` variants:

```rust
// rns-core/src/transport/types.rs — add to TransportAction enum:
LinkRequestReceived { link_id: [u8; 16], destination_hash: [u8; 16], receiving_interface: InterfaceId },
LinkEstablished { link_id: [u8; 16], interface: InterfaceId },
LinkClosed { link_id: [u8; 16] },
AnnounceRetransmit { destination_hash: [u8; 16], raw: Vec<u8>, interface: Option<InterfaceId> },
```

Emit these from:
- `LinkRequestReceived`: `handle_inbound()` at mod.rs:526-540 when forwarding LINKREQUEST
- `LinkEstablished`: mod.rs:908-936 when LRPROOF validates
- `LinkClosed`: `jobs::cull_link_table()` at jobs.rs:103-130 when links expire
- `AnnounceRetransmit`: `jobs::process_pending_announces()` at jobs.rs:36-53

Handle in `dispatch_all()` as no-ops (the side effects already happened in the engine) — they exist purely as hook attachment points.

### 4. InterfaceUp/Down/ConfigChanged Hooks

> **Note:** `InterfaceUp`, `InterfaceDown`, and `InterfaceConfigChanged` hooks fire in the `Event::InterfaceUp` and `Event::InterfaceDown` match arms of `Driver::run()`, not through `dispatch_all()`. These are `Event` variants (event.rs), not `TransportAction` variants. The `run_hook!` macro is used the same way.

### 5. Announce/Path Updates

Hook into `TransportEngine` via callback trait or Driver-level interception.

### 6. Future Vision: Existing Filters as WASM Plugins

Existing IFAC (Interface ACL) and ingress control filtering could eventually be converted to WASM plugins, where the hook system subsumes current hardcoded filtering. For now, hooks run **after** IFAC/ingress control as an additional layer.

---

## Hot Reload

### Server-side (`rns-ctl/src/api.rs`)

HTTP endpoints for hook management:

| Method | Endpoint | Body / Params | Description |
|--------|----------|---------------|-------------|
| `GET` | `/api/hooks` | — | List loaded hooks and status |
| `POST` | `/api/hook/load` | `{ path, attach_point, priority }` | Load and attach a WASM hook |
| `POST` | `/api/hook/reload` | `{ name }` | Reload a hook from same path |
| `DELETE` | `/api/hook/:name` | — | Unload a hook |

### Client-side (`rns-cli/src/bin/rnhook.rs`)

New CLI binary that calls the HTTP endpoints above:

```bash
rnhook list                                                    # List loaded hooks and their status
rnhook load /path/to/hook.wasm --attach PreIngress --priority 100  # Load and attach
rnhook reload packet_logger                                    # Reload from same path
rnhook unload packet_logger                                    # Remove hook
```

### Pointer Swap

On load/unload, the affected `HookSlot`'s function pointer is swapped (noop ↔ chain runner). This is the only moment the hot path is affected.

---

## Configuration

Uses ConfigObj format (matching the rest of the project). Hook sections are identified by the `hook_` prefix:

```ini
[[hook_packet_logger]]
type = wasm_hook
path = /etc/rns/hooks/packet_logger.wasm
enabled = yes
attach_point = PreIngress
priority = 100

[[hook_announce_filter]]
type = wasm_hook
path = /etc/rns/hooks/announce_filter.wasm
enabled = yes
attach_point = AnnounceReceived
priority = 200
```

Double brackets match the existing convention for subsections in ConfigObj format (used by `[[interface_name]]` sections, parsed at config.rs:132-144). This requires updating the config parser in `rns-net/src/config.rs` to recognize `hook_*` sections.

---

## SDK: `rns-hooks-sdk`

**Initial release: Rust SDK only.** The `repr(C)` tagged-union layout of `ActionWire` is Rust-specific. Multi-language support (C, AssemblyScript, TinyGo) is a future goal that may require a simpler wire format (e.g., tag byte + flat struct).

The SDK for writing WASM hook programs in Rust. Supports `#![no_std]` without `alloc` for simple hooks.

### Core (no_std, no alloc)

- `#[repr(C)]` context structs (shared with host): `PacketContext`, `ActionWire`, `HookResult`
- Helper functions for reading variable-length arena fields (e.g. `ctx.data()` → `&[u8]`)
- Host function wrappers: `host::log_str("static msg")`, `host::has_path(&hash)`, etc.
- Verdict constants

### Optional `alloc` feature

- `host::log(&format!("dynamic {}", value))` — allocates a string, passes ptr+len to host
- Dynamic `Vec<u8>` construction for modified packets

### Example: Simple filter (no alloc)

```rust
#![no_std]
use rns_hooks_sdk::*;

#[no_mangle]
pub extern "C" fn on_pre_ingress(ctx_ptr: u32) -> u32 {
    let ctx = unsafe { &*(ctx_ptr as *const PacketContext) };

    // Drop packets with excessive hops
    if ctx.hops > 32 {
        host::log_str("Dropping high-hop packet");
        return VERDICT_DROP;
    }

    VERDICT_CONTINUE
}
```

### Example: Logger (with alloc)

```rust
#![no_std]
extern crate alloc;
use alloc::format;
use rns_hooks_sdk::*;

#[no_mangle]
pub extern "C" fn on_pre_ingress(ctx_ptr: u32) -> u32 {
    let ctx = unsafe { &*(ctx_ptr as *const PacketContext) };
    host::log(&format!("Packet to {:02x?}, {} hops", &ctx.destination_hash[..4], ctx.hops));
    VERDICT_CONTINUE
}
```

---

## Implementation Steps

1. **Create `rns-hooks` crate** with basic structure and `rns-hooks` feature flag
2. **Define repr(C) types** (`PacketContext`, `ActionWire`, `HookResult`, `Verdict`) — shared between host and SDK
3. **Implement arena layout** — host-side write into WASM linear memory, SDK-side field accessors
4. **Implement WasmRuntime** wrapper around wasmtime with fuel limits
5. **Implement HookSlot + function pointer swap** — the zero-cost dispatch mechanism
6. **Implement HookManager** (load, attach, run chain, unload, auto-disable on repeated traps)
7. **Implement host functions** — all 11 read-only functions + `host_inject_action`
8. **Create `rns-hooks-sdk`** crate — no_std repr(C) structs, arena helpers, host fn wrappers
9. **Integrate with Driver** at key hook points (via `run_hook!` macro in `run()` Event::Frame arm + `dispatch_all()`)
10. **Add config parsing** for `hook_*` sections in `rns-net/src/config.rs`
11. **Add hook HTTP endpoints** to `rns-ctl/src/api.rs` and bridge commands to the node via `rns-ctl/src/bridge.rs`
12. **Create `rnhook` CLI binary** (`rns-cli/src/bin/rnhook.rs`) — list, load, reload, unload via HTTP
13. **Write example programs** (packet_logger, announce_filter)
14. **Add benchmarks** (baseline, no-hooks, trivial hook, complex hook)
15. **Add tests** — unit tests for HookManager lifecycle, integration tests with example WASM

---

## Files to Modify

| File | Changes |
|------|---------|
| `Cargo.toml` (workspace) | Add `rns-hooks` and `rns-hooks-sdk` crates |
| `rns-hooks/` (new) | Entire new crate |
| `rns-hooks/sdk/rns-hooks-sdk/` (new) | Rust-only SDK crate for WASM programs |
| `rns-core/src/transport/types.rs` | Add 4 new `TransportAction` variants + `From/Into<u64>` for `InterfaceId` |
| `rns-core/src/transport/mod.rs` | Emit `LinkRequestReceived`, `LinkEstablished` actions |
| `rns-core/src/transport/jobs.rs` | Emit `LinkClosed`, `AnnounceRetransmit` actions |
| `rns-net/Cargo.toml` | Add `rns-hooks` feature flag, optional dep on `rns-hooks` |
| `rns-net/src/driver.rs` | Add `hook_slots` (cfg-gated), `run_hook!` macro, integrate at all hook points, handle new action variants in `dispatch_all()` |
| `rns-net/src/config.rs` | Parse `[[hook_*]]` sections |
| `rns-ctl/src/api.rs` | Add hook management HTTP endpoints |
| `rns-ctl/src/bridge.rs` | Bridge hook commands to node |
| `rns-cli/src/bin/rnhook.rs` (new) | CLI binary for hook management |

---

## Verification

1. **Unit tests**: HookManager load/attach/run lifecycle, function pointer swap, auto-disable
2. **Integration tests**: Load example WASM, verify hooks fire at each hook point
3. **New action variants**: Verify `LinkRequestReceived`, `LinkEstablished`, `LinkClosed`, `AnnounceRetransmit` are emitted correctly and existing behavior is unchanged (dispatch_all handles them as no-ops)
4. **API tests**: Hook management HTTP endpoints in rns-ctl
5. **Benchmarks**: Validate zero-cost (baseline vs no-hooks vs trivial vs complex)
6. **Manual testing**: Load hooks via `rnhook` CLI, verify logging/filtering, hot-reload, auto-disable on traps
