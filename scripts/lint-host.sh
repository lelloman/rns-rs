#!/usr/bin/env bash

set -euo pipefail

# Warning-free host-side lint for the workspace.
#
# We intentionally do not use `--all-features` here because that enables
# `rns-crypto/espidf`, which pulls in `esp-idf-sys` and fails on normal
# x86_64 Linux/macOS development machines. ESP32 validation lives in its
# own target-specific lane under `rns-esp32/`.
# Which lints apply is set in the root Cargo.toml's [workspace.lints].
# Production targets get all of them. Test code (unit and integration
# tests, benches) is outside the code-quality lints' scope.
test_exempt=(-A unsafe_code -A clippy::undocumented_unsafe_blocks -A clippy::panic -A clippy::unwrap_used -A unreachable_pub)
lint() {
  cargo clippy "$@" ${production_targets:---lib --bins --examples} -- -D warnings
  cargo clippy "$@" --tests --benches -- -D warnings "${test_exempt[@]}"
}

lint --workspace --features rns-hooks
# rns-hooks has no backend by default; lint both of its backends too.
lint -p rns-hooks --features wasm,native
# The BLE RNode transport is not a default feature (it links libdbus).
lint -p rns-net -p rns-cli -p rns-ctl \
  --features rns-net/iface-rnode-ble,rns-cli/iface-rnode-ble,rns-ctl/iface-rnode-ble
# rns-ctl's HTTPS server is behind a feature.
lint -p rns-ctl --features tls
# rns-net's features together (its tests have code behind several).
lint -p rns-net --all-features
# rns-net with some of its interfaces only: none, and the set rns-tun-android
# builds. Code only some interfaces use is gated on their features.
cargo clippy -p rns-net --no-default-features --lib -- -D warnings
cargo clippy -p rns-net --no-default-features --features iface-tcp,iface-udp,iface-auto --lib \
  -- -D warnings
# The bench's counting allocator is behind a feature (scripts/hotpath).
production_targets=--bins lint -p rns-bench --features allocation-profiler
# The hooks' guest code exists only on wasm32, where rns-cli's build script
# compiles them for the rns-hooks-wasm feature.
cargo clippy -p rns-stats-hook -p rns-sentinel-hook --lib --target wasm32-unknown-unknown \
  -- -D warnings
