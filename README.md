# rns-rs

A Rust implementation of [Reticulum](https://github.com/markqvist/Reticulum), the cryptography-based networking stack for building resilient networks with readily available hardware.

This is a faithful port of the Python reference implementation, validated against it with 900+ interop tests. `rns-crypto` and `rns-core` are `no_std`-compatible with zero external dependencies, making them suitable for embedded/microcontroller targets.

## Workspace Crates

| Crate | `no_std` | Description |
|-------|----------|-------------|
| `rns-crypto` | Yes | Cryptographic primitives: X25519, Ed25519, AES-256-CBC, SHA-256/512, HMAC, HKDF, Identity |
| `rns-core` | Yes | Wire protocol, transport routing engine, link/channel/buffer, resource transfers |
| `rns-net` | No | Network node: TCP/UDP/Serial/KISS/RNode/Pipe/Backbone/Auto interfaces, config parsing, driver loop |
| `rns-cli` | No | CLI tools: `rnsd`, `rnstatus`, `rnpath`, `rnprobe`, `rnid` |
| `rns-ctl` | No | HTTP/WebSocket control server |

## Building

```bash
cargo build
```

## Running Tests

Test vectors are generated from the Python RNS implementation:

```bash
# Generate test fixtures (requires Python RNS installed)
python3 tests/generate_vectors.py

# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p rns-crypto
cargo test -p rns-core
cargo test -p rns-net
cargo test -p rns-cli
```

## CLI Tools

Build and run the CLI binaries:

```bash
# Run the daemon
cargo run --bin rnsd -- /path/to/config

# Check network status
cargo run --bin rnstatus

# Query paths
cargo run --bin rnpath

# Probe connectivity
cargo run --bin rnprobe

# Identity management
cargo run --bin rnid
```

## Interoperability

rns-rs is designed to be fully interoperable with the Python Reticulum implementation. A Rust node can join an existing Reticulum network alongside Python nodes, exchange announces, establish links, and transfer resources.

## License

[Reticulum License](LICENSE)
