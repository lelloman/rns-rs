#!/usr/bin/env bash

set -euo pipefail

# Warning-free host-side lint for the workspace.
#
# We intentionally do not use `--all-features` here because that enables
# `rns-crypto/espidf`, which pulls in `esp-idf-sys` and fails on normal
# x86_64 Linux/macOS development machines. ESP32 validation lives in its
# own target-specific lane under `rns-esp32/`.
# Which lints apply is set in the root Cargo.toml's [workspace.lints].
cargo clippy --workspace --all-targets --features rns-hooks -- -D warnings
# rns-hooks has no backend by default; lint both of its backends too.
cargo clippy -p rns-hooks --all-targets --features wasm,native -- -D warnings
# The BLE RNode transport is not a default feature (it links libdbus).
cargo clippy -p rns-net -p rns-cli -p rns-ctl --all-targets \
  --features rns-net/iface-rnode-ble,rns-cli/iface-rnode-ble,rns-ctl/iface-rnode-ble -- -D warnings
# The bench's counting allocator is behind a feature (scripts/hotpath).
cargo clippy -p rns-bench --all-targets --features allocation-profiler -- -D warnings
