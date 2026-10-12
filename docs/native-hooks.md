# Native Hooks

Native hooks are trusted dynamic libraries loaded into the `rnsd` process. They
exist for targets where the WASM backend is not available or is too expensive,
notably ARMv7 systems that cannot build Wasmtime/Cranelift.

Build runtime binaries with:

```bash
cargo build --release -p rns-cli --bin rnsd --features rns-hooks-native
cargo build --release -p rns-ctl --features rns-hooks-native
```

Configure a native hook with `type = native`:

```ini
[hooks]
  [[native_noop]]
    path = /opt/rns/hooks/libnative_noop.so
    type = native
    attach_point = Tick
    priority = 0
    enabled = Yes
```

Or load one at runtime:

```bash
rns-ctl hook load /opt/rns/hooks/libnative_noop.so --type native --point Tick
rns-ctl hook reload native_noop --type native --point Tick --path /opt/rns/hooks/libnative_noop.so
```

## Accepted Paths

Native hooks are loaded only from the configured hooks directory when they are
requested at runtime through the HTTP API or `rns-ctl hook load|reload`.

| Where the hook is requested | Accepted paths |
|-----------------------------|----------------|
| Node `config` file, `[hooks]` section (startup) | Any path the operator writes. Absolute paths are recommended; a bare file name is resolved against the working directory, never the dynamic loader's library search path. |
| HTTP API / `rns-ctl hook load` / `rns-ctl hook reload` | An absolute path to a regular file whose resolved location (after following symlinks) is inside the hooks directory. Relative paths, bare names, directories, and paths outside the directory are refused with `native hook path must be inside the configured hooks directory`. |

The hooks directory defaults to `<config dir>/hooks`. Set it with:

- `rns-ctl http --hooks-dir PATH` or the `RNSCTL_HOOKS_DIR` environment variable;
- `hooks_dir` in `rns-server.json` for `rns-server` (relative values resolve
  against the config directory). This key is set in the configuration file only
  and is not changeable through the config API.

The examples above therefore require `--hooks-dir /opt/rns/hooks` (or
`hooks_dir = "/opt/rns/hooks"`) when loading at runtime.

When the `type` field is omitted, the API and CLI default to `wasm` (or
`builtin` on builds without the WASM backend). Native hooks must be requested
with `--type native` / `"type": "native"`.

## ABI

Native libraries must export two C ABI symbols:

```c
int rns_hook_abi_version(void);

int rns_hook_on_call(
    const uint8_t *ctx,
    size_t ctx_len,
    const RnsNativeHostApi *host_api,
    HookResult *result
);
```

`rns_hook_abi_version` must return `rns_hooks_abi::ABI_VERSION`.
`rns_hook_on_call` receives a host-owned context byte buffer and must write a
`HookResult`. Return `0` for success; any non-zero value is treated as a hook
failure and the hook fails open.

Rust hooks should use the ABI definitions from `rns-hooks-abi::native`. See
`rns-hooks/examples/native_noop` for a minimal `cdylib` hook.

## Host API

The host API pointer exposes callbacks equivalent to the WASM host functions:

- `log`
- `has_path`
- `get_hops`
- `get_next_hop`
- `is_blackholed`
- `get_interface_name`
- `get_interface_mode`
- `get_transport_identity`
- `get_announce_rate`
- `get_link_state`
- `inject_action`
- `emit_event`
- `set_modified_data`

The `version` field is currently `1`. Hooks should check it before relying on a
callback. A callback pointer may be `NULL`.

## Verdicts

Every hook backend (WASM, native and built-in) returns one of four verdicts:

- `Continue` — pass the packet or event through unchanged.
- `Drop` — stop the packet or action at hook points that support it.
- `Modify` — replace the packet bytes. WASM hooks point
  `modified_data_offset`/`modified_data_len` at the replacement; native hooks
  call `set_modified_data`; built-in hooks call
  `BuiltinHookHost::set_modified_data`.
- `Halt` — stop the hook chain; later hooks at the same attach point do not run
  and the packet continues with its original bytes, even if an earlier hook in
  the chain returned `Modify`.

Within a chain, each hook after a `Modify` sees the replacement bytes. The
chain's final verdict decides what the node does: the replacement is used only
when the last verdict that stopped or modified the chain is `Modify`.

### Where `Modify` applies

`Modify` is applied only at hook points that hold the raw packet before acting
on it. At every other hook point it behaves exactly like `Continue` and the
replacement bytes are ignored.

| Hook point | `Modify` |
|------------|----------|
| `PreIngress` | Applied. The replacement is decoded and must pass the same admission checks as a received packet before transport processing. |
| `SendOnInterface` | Applied. The replacement is sent on the interface. |
| `BroadcastOnAllInterfaces` | Applied. The replacement is sent on every selected interface. |
| `DeliverLocal` | Applied. The replacement is delivered under its own destination hash and packet hash. |
| `PreDispatch` | Treated as `Continue`: the packet has already been processed. |
| `TunnelSynthesize` | Treated as `Continue`: the hook sees the synthesis payload, not a packet. |
| `AnnounceReceived`, `PathUpdated`, `AnnounceRetransmit` | Treated as `Continue`: no packet bytes. |
| `LinkRequestReceived`, `LinkEstablished`, `LinkClosed` | Treated as `Continue`: no packet bytes. |
| `InterfaceUp`, `InterfaceDown`, `InterfaceConfigChanged` | Treated as `Continue`: no packet bytes. |
| `BackbonePeer*` | Treated as `Continue`: no packet bytes. |
| `Tick` | Treated as `Continue`: no packet bytes. |

Where it applies, a replacement is validated before use. It must be
non-empty, no longer than the MTU of the interface the packet is handled on
(the smallest MTU among the selected interfaces for a broadcast, or the
protocol MTU when no interface is known), and decode as a packet with the same
decoder the node uses for received frames. A replacement that fails validation
is treated as `Drop`, logged at debug level and counted per hook point. A `Modify` verdict without
replacement bytes behaves as `Continue`. Packet hashes, destination hashes and
other header fields are always taken from the replacement, never from the
original packet.

`rns-hooks/examples/path_modifier` shows a `Modify` hook: attached at
`PreIngress`, it raises the hop count of every received announce by two so
paths learned through that interface are less preferred.

## Safety Model

Native hooks are not sandboxed. A native hook can crash the process, block the
driver thread, corrupt memory, or perform arbitrary system calls with the
process privileges. Use native hooks only for trusted code. Use WASM hooks when
you need sandboxing, fuel limits, and stronger isolation.

## Packaging

Dynamic-library hooks normally need to exist as files on the target filesystem
because the backend loads them with the operating system dynamic loader. If you
need a single-file product, there are two practical approaches:

- extract bundled `.so` files from the binary to a runtime directory before
  loading them;
- add a separate built-in hook backend that links selected hooks into `rnsd`
  and registers them directly without `dlopen`.

The second option is better for appliances, but it is a different backend from
dynamic-library hooks.
