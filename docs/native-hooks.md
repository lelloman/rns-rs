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
