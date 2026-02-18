#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="$SCRIPT_DIR/target/wasm-examples"
SHARED_TARGET="$SCRIPT_DIR/target/wasm-shared"

mkdir -p "$TARGET_DIR"

EXAMPLES=(
    announce_filter:announce-filter
    packet_logger:packet-logger
    path_modifier:path-modifier
    rate_limiter:rate-limiter
    allowlist:allowlist
    packet_mirror:packet-mirror
    link_guard:link-guard
    announce_dedup:announce-dedup
    metrics:metrics
)

for entry in "${EXAMPLES[@]}"; do
    dir="${entry%%:*}"
    crate="${entry##*:}"
    echo "Building $dir..."
    cargo build \
        --manifest-path "$SCRIPT_DIR/examples/$dir/Cargo.toml" \
        --target wasm32-unknown-unknown \
        --release \
        --target-dir "$SHARED_TARGET"

    # crate name with hyphens replaced by underscores for the .wasm filename
    wasm_name="${crate//-/_}"
    cp "$SHARED_TARGET/wasm32-unknown-unknown/release/${wasm_name}.wasm" "$TARGET_DIR/${dir}.wasm"
    echo "  -> $TARGET_DIR/${dir}.wasm"
done

echo "All examples built successfully."
