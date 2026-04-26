#!/usr/bin/env bash

set -euo pipefail

# Host-side lint baseline for the workspace.
#
# We intentionally do not use `--all-features` here because that enables
# `rns-crypto/espidf`, which pulls in `esp-idf-sys` and fails on normal
# x86_64 Linux/macOS development machines. ESP32 validation lives in its
# own target-specific lane under `rns-esp32/`.
cargo clippy \
  --workspace \
  --all-targets \
  --features rns-hooks \
  -- \
  -A clippy::approx_constant \
  -A clippy::never_loop
