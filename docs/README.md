# rns-rs Documentation

This directory is the project wiki. Start with the page that matches what you
want to do, then follow the links from there. The repository
[README](../README.md) is only a landing page.

## Start here

| Page | Read it when you want to |
|------|--------------------------|
| [Getting Started](getting-started.md) | Build the project and run your first node with `rns-server` |
| [Architecture](architecture.md) | Understand the crates, how they layer, and which binaries exist |
| [Interoperability](interoperability.md) | Know how rns-rs relates to Python Reticulum and how parity is verified |

## Running a node

| Page | Covers |
|------|--------|
| [Configuration](configuration.md) | The `config` file: interfaces, ingress control, queues, link MTU, socket marking |
| [rns-server Operator Runbook](rns-server-operator-runbook.md) | Supervised deployment, control plane, files and paths, config apply semantics, troubleshooting |
| [Interface Discovery](interface-discovery.md) | Auto-connect policy and advertised locations for discovered Backbone peers |
| [Manual Backbone Smoke Test](manual-backbone-smoke.md) | End-to-end check against the live public backbone |

## Tools

| Page | Covers |
|------|--------|
| [CLI Tools](cli-tools.md) | `rnsd`, `rnstatus`, `rnpath`, `rnprobe`, `rnid`, `rnsh`, `rncp`, `rnx`, and the sidecar daemons |
| [rns-ctl](rns-ctl.md) | The unified control binary and its HTTP/WebSocket API |
| [rnstatus](rnstatus.md) | Interface status and live attach/detach/reload |
| [rnsh](rnsh.md) | Remote shell over Reticulum links |
| [rns-git](rns-git.md) | Git hosting and `git-remote-rns` over Reticulum |
| [rntun](../rns-tun/README.md) | Authenticated IPv4 tunnelling on Linux, with the [design document](rntun-design.md) |
| [rntun for Android](../rns-tun-android/README.md) | The Android VPN client built on `rns-tun` |
| [rns-esp32](../rns-esp32/README.md) | LoRa transport node firmware for the Heltec WiFi LoRa 32 V3 |

## Extensions beyond Python Reticulum

| Page | Covers |
|------|--------|
| [Hooks](hooks.md) | The programmable hook system: WASM, native, and built-in backends |
| [Native Hooks](native-hooks.md) | Writing and loading trusted dynamic-library hooks, verdict semantics per hook point |
| [Built-In Hooks](builtin-hooks.md) | Hooks linked into the host binary and loaded by ID |
| [Direct Link](direct-link.md) | Upgrading a link to a direct UDP path through NAT |
| [Direct Link Protocol](direct-link-protocol.md) | The full Direct Link wire protocol and security analysis |
| [Local Destination Ratchets](local-ratchets.md) | Rotating packet-encryption keys for an application's own destination |

## Protocol and upstream tracking

| Page | Covers |
|------|--------|
| [Protocol Specification](protocol-spec.md) | Normative wire protocol for `RNS-Compat/1` with conformance vectors |
| [UPSTREAM.md](../UPSTREAM.md) | The accepted Python Reticulum baseline and every completed porting queue |
| [Upstream Parity](upstream-parity/README.md) | Audit and acceptance records per upstream version, plus the workflow and templates |
| [Issue 152 Reproduction](issue152-reproduction.md) | What "transmission complete" means for the send APIs |

## Development and releases

| Page | Covers |
|------|--------|
| [Building](building.md) | Feature flags, interface selection, hook backends, stripping, cross-building |
| [Development](development.md) | Tests, lint, Docker end-to-end suites, interop tests, CI, benchmarks |
| [Benchmarking](../bench/README.md) | The benchmark runner, profiles, and recorded findings |
| [Dependency Upgrades 2026](dependency-upgrades-2026.md) | Audit of manifest-incompatible dependency updates |
| [crates.io Publish Runbook](crates-io-publish-runbook.md) | How workspace crates are published and tagged |
| [ESP32 Release Runbook](esp32-release-runbook.md) | How the firmware image is built and released |
| [Contributing](../CONTRIBUTING.md) | Authorship, provenance, and license conditions |

## Conventions

- Pages under `docs/` are user and operator documentation. Crate-specific
  READMEs stay next to their crate.
- Point-in-time records (audits, parity acceptances, benchmark findings) are
  not rewritten after the fact. A newer record supersedes an older one.
- Every behavioural claim should be traceable to code or to a recorded test
  run. When a page describes a validation result, it names the date and the
  record that holds the evidence.
