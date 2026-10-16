# rns-rs

[![CI](https://github.com/lelloman/rns-rs/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/lelloman/rns-rs/actions/workflows/ci.yml)
[![rns-core](https://img.shields.io/crates/v/rns-core.svg?label=rns-core)](https://crates.io/crates/rns-core)
[![rns-net](https://img.shields.io/crates/v/rns-net.svg?label=rns-net)](https://crates.io/crates/rns-net)
[![rns-server](https://img.shields.io/crates/v/rns-server.svg?label=rns-server)](https://crates.io/crates/rns-server)
[![upstream Reticulum](https://img.shields.io/badge/upstream%20Reticulum-1.5.7-blue)](docs/upstream-parity/reticulum-1.5.7-parity.md)

A Rust implementation of [Reticulum](https://github.com/markqvist/Reticulum),
the cryptography-based networking stack for building resilient networks with
readily available hardware.

rns-rs is a port of the Python reference implementation. It tracks an accepted
upstream baseline commit by commit, is checked against Python-generated
conformance vectors and live Python/Rust interoperability tests, and joins
existing Reticulum networks alongside Python nodes. The protocol and
transport crates build without `std`, and the same code base runs on servers,
ARMv7 boards, Android, and an ESP32 LoRa node.

On top of the Reticulum protocol it adds two opt-in extensions: a programmable
[hook system](docs/hooks.md) for the transport pipeline, and
[Direct Link](docs/direct-link.md), which upgrades an established link to a
direct UDP path through NAT.

## Quick start

```bash
cargo build --release --bin rns-server
mkdir -p ~/.reticulum
cargo run --release --bin rnsd -- --exampleconfig > ~/.reticulum/config
# edit ~/.reticulum/config and enable at least one interface, then:
./target/release/rns-server start --config ~/.reticulum
```

`rns-server` supervises the node daemon and optional sidecars and serves a
control plane with a built-in UI on `127.0.0.1:8080`. The
[Getting Started](docs/getting-started.md) page walks through this in detail,
including a minimal config that joins a public transport node.

## What is in the box

| | |
|---|---|
| **Run a node** | `rns-server` (supervisor, control plane, UI), or `rnsd` with the classic tools, or the all-in-one `rns-ctl` |
| **Operate it** | `rnstatus`, `rnpath`, `rnprobe`, `rnid`, HTTP/WebSocket API, statistics and sentinel sidecars |
| **Use the network** | `rnsh` remote shell, `rncp` file transfer, `rnx` remote commands, `rngit` and `git-remote-rns` for Git over Reticulum, `rntun` IPv4 tunnelling on Linux and Android |
| **Build on it** | `rns-crypto`, `rns-core`, and `rns-net` crates on crates.io; `rns-hooks-sdk` for WASM hooks |
| **Embed it** | `rns-esp32` firmware for the Heltec WiFi LoRa 32 V3 |

## Documentation

The wiki lives in [`docs/`](docs/README.md). Good entry points:

- [Getting Started](docs/getting-started.md), then [Configuration](docs/configuration.md)
- [Architecture](docs/architecture.md): crates, layering, binaries, interfaces
- [Building](docs/building.md): feature flags, interface selection, hook backends, cross-building
- [CLI Tools](docs/cli-tools.md) and [rns-ctl](docs/rns-ctl.md)
- [rns-server Operator Runbook](docs/rns-server-operator-runbook.md)
- [Hooks](docs/hooks.md), [Direct Link](docs/direct-link.md), [Local Destination Ratchets](docs/local-ratchets.md)
- [Interoperability](docs/interoperability.md) and the [Protocol Specification](docs/protocol-spec.md)
- [Development](docs/development.md): tests, lint, Docker end-to-end suites, CI, benchmarks

## Upstream tracking

The accepted Python Reticulum baseline, with its commit, validation runs, and
every completed porting queue, is recorded in [UPSTREAM.md](UPSTREAM.md). Each
advancement has an audit and an acceptance record under
[docs/upstream-parity/](docs/upstream-parity/README.md). Physical radio
hardware validation remains unclaimed.

## Authorship and provenance

rns-rs is an independent reimplementation of Reticulum's reference
implementation (RNS). It is not a clean-room design: it is a derivative work
distributed under the [Reticulum License](LICENSE), retaining the original
copyright notice and crediting the reference implementation.

The project is developed with substantial machine (LLM) assistance under human
direction and review. The maintainer sets scope, makes the design decisions,
and reviews and accepts or rejects every change. The commit history, the
upstream-parity audits, and the conformance and interop fixtures document how
the implementation was produced and verified.

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Reticulum License](LICENSE)
