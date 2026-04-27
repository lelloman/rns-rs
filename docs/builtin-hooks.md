# Built-In Hooks

Built-in hooks are regular Rust hook functions linked into the host binary and
loaded by ID at runtime. They are intended for first-party hooks, appliances,
and third-party binaries that want a single executable without Wasmtime,
dynamic libraries, extracted files, or duplicated embedded `.so` bytes.

They are trusted code. A built-in hook runs in-process with the same privileges
as `rnsd`.

## Registering Hooks

A plugin crate can expose a registration function:

```rust
use rns_hooks::{
    register_builtin_hook, BuiltinHookCall, BuiltinHookHost, HookError, HookResult,
};

pub fn register_hooks() -> Result<(), HookError> {
    register_builtin_hook("example.tick_logger", tick_logger)
}

fn tick_logger(
    call: BuiltinHookCall<'_>,
    _host: &mut BuiltinHookHost,
) -> Result<HookResult, HookError> {
    let _ = call;
    Ok(HookResult::continue_result())
}
```

The final binary links that crate and calls `register_hooks()` before starting
the node. This works for third-party crates published on crates.io: the plugin
crate provides hook functions, and the application binary chooses which ones to
link and register.

## Loading

Config:

```ini
[hooks]
  [[tick_logger]]
    type = builtin
    builtin = example.tick_logger
    attach_point = Tick
    priority = 0
    enabled = Yes
```

CLI:

```bash
rns-ctl hook load example.tick_logger --type builtin --point Tick --name tick_logger
```

RPC clients can call `load_builtin_hook(name, attach_point, priority,
builtin_id)`.

## Backend Comparison

- `wasm`: sandboxed, fuel-limited, compiled from bytes; best for untrusted user
  hooks.
- `native`: trusted dynamic library loaded from a path; best for external native
  extensions.
- `builtin`: trusted Rust function linked into the binary; best for single-file
  deployments and first-party hooks.
