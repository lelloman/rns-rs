# Building

```bash
cargo build                   # default workspace members, debug profile
cargo build --release         # same, optimised
```

The pinned toolchain is Rust 1.96.0 with `clippy`, `rustfmt`, and the
`wasm32-unknown-unknown` target (see `rust-toolchain.toml`). `rustup` installs
it on first use.

Default workspace members: `rns-crypto`, `rns-core`, `rns-net`, `rns-cli`,
`rns-ctl`, `rns-server`, `rns-git`, `rns-tun`. The hook crates,
`rns-tun-android`, and `rns-bench` build only when named with `-p` or when
`--workspace` is passed. `rns-esp32` is excluded entirely and has its own
[README](../rns-esp32/README.md).

## Selecting interfaces

`rns-cli` and `rns-ctl` include every network interface by default. For a
Linux server that needs TCP and shared-instance connections only:

```bash
cargo build --release -p rns-cli --bin rnsd --no-default-features --features iface-tcp
cargo build --release -p rns-ctl --no-default-features --features iface-tcp
```

Both packages expose `iface-tcp`, `iface-udp`, `iface-auto`, `iface-serial`,
`iface-kiss`, `iface-ax25-kiss`, `iface-pipe`, `iface-rnode`,
`iface-backbone`, `iface-i2p`, and `iface-weave`. AX.25 KISS also enables
KISS; Weave is Linux-only. The local interface stays enabled because the CLI
tools need the shared-instance and remote-management APIs.

Things to keep in mind:

- Configure only interfaces compiled into the binary. Disabling a feature does
  not rewrite an existing config or its default `AutoInterface`.
- Build the selected packages explicitly. Cargo unifies features across a
  build, so building other workspace packages in the same command can enable
  their interfaces too.
- `--no-default-features` removes the implicit full interface set from these
  two packages; omit it to keep the full build.
- Feature selection reduces compiled code. It does not change queue limits or
  protocol behaviour on the interfaces that remain.

## Hook backends

Hooks are opt-in. Each backend is a feature on `rns-net`, `rns-cli`,
`rns-ctl`, and `rns-server`, and can be combined with interface selection.

| Feature | Effect |
|---------|--------|
| `rns-hooks-wasm` | Sandboxed WASM hooks. Compiles in Wasmtime |
| `rns-hooks-native` | Trusted dynamic-library hooks. No Wasmtime |
| `rns-hooks-builtin` | Hooks linked into the binary and loaded by ID. No Wasmtime, no `dlopen` |
| `rns-hooks` | Compatibility alias for `rns-hooks-native` |

```bash
cargo build --release --bin rns-server --features rns-hooks-native
cargo build --release --bin rns-server --features rns-hooks-wasm
cargo build --release --bin rns-server --features rns-hooks-builtin
```

Compiling WASM guest hooks, including the examples under
`rns-hooks/examples/`, needs the WASM target. The host-side Wasmtime backend
does not:

```bash
rustup target add wasm32-unknown-unknown
./rns-hooks/build-examples.sh
```

See [Hooks](hooks.md) for what the backends do at runtime.

## Other feature flags

| Feature | Package | Effect |
|---------|---------|--------|
| `tls` | `rns-ctl` | TLS for the HTTP/WebSocket server (compiles in rustls) |
| `std` | `rns-crypto`, `rns-core` | On by default. Disable for `no_std` |
| `espidf` | `rns-crypto` | ESP-IDF crypto backend. Fails on normal hosts; used only by `rns-esp32` |
| `linux-cli`, `node-standard`, `android-node` | `rns-tun` | Select the Linux CLI or the Android node profile |
| `allocation-profiler` | `rns-bench` | Allocation accounting in benchmark runs |

This is not the full list. Each `Cargo.toml` is authoritative for its crate.

## Smaller deployment artifacts

The release profile keeps symbol names but no source-level debug info. To ship
a stripped copy while keeping the matching unstripped executable for
diagnostics (GNU binutils):

```bash
cargo build --release -p rns-cli --bin rnsd
mkdir -p dist
cp target/release/rnsd dist/rnsd.unstripped
strip --strip-all -o dist/rnsd dist/rnsd.unstripped
```

Stripping reduces disk size, not runtime memory or protocol work. Use the
`profiling` Cargo profile (release plus full debug info) when a profiler needs
source lines. Measured size and runtime tradeoffs of compiler options are in
[release-profile findings](../bench/release-profile-findings.md).

For a complete `rns-server` deployment bundle:

```bash
bash scripts/package-rns-server-tarball.sh
```

This builds the single binary and writes `dist/rns-server-<os>-<arch>.tar.gz`
together with the operator runbook.

## Cross-building for ARMv7

CI builds the runtime binaries for `armv7-unknown-linux-gnueabihf` on every
push. Wasmtime does not build there, so use the native or built-in hook
backend:

```bash
rustup target add armv7-unknown-linux-gnueabihf
sudo apt-get install gcc-arm-linux-gnueabihf libc6-dev-armhf-cross

export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc
export CC_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-gcc
export AR_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-ar

cargo build --release --target armv7-unknown-linux-gnueabihf -p rns-cli --bin rnsd --features rns-hooks-native
cargo build --release --target armv7-unknown-linux-gnueabihf -p rns-ctl --features rns-hooks-native
cargo build --release --target armv7-unknown-linux-gnueabihf --no-default-features -p rns-server --features rns-hooks-builtin
```

## Android and ESP32

- The Android client is built with Gradle from `rns-tun-android/`; it needs JDK
  17, Android SDK 36, NDK 28.2.13676358, the four Android Rust targets, and
  `cargo-ndk` 4.1.2. See its [README](../rns-tun-android/README.md).
- The ESP32 firmware needs the Espressif Rust toolchain selected by
  `rns-esp32/rust-toolchain.toml`. See its [README](../rns-esp32/README.md)
  and the [release runbook](esp32-release-runbook.md).
