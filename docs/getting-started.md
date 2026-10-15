# Getting Started

This page takes you from a clean checkout to a running node. It assumes Linux
or macOS with a working Rust toolchain. The pinned toolchain in
`rust-toolchain.toml` is installed automatically by `rustup` on first build.

## 1. Build

```bash
git clone https://github.com/lelloman/rns-rs.git
cd rns-rs
cargo build --release --bin rns-server
```

`rns-server` is the single binary most deployments need. It supervises the
daemon and optional sidecars and serves a small control plane. The lower-level
binaries are described in [CLI Tools](cli-tools.md); build options such as
interface selection and hook backends are in [Building](building.md).

## 2. Create a config directory

A node keeps everything in one directory: the Reticulum `config` file,
identities, path tables, logs, and the `rns-server.json` product config. The
default is `~/.reticulum`; pass `--config PATH` to use another location.

Start from the example config shipped with `rnsd`:

```bash
mkdir -p ~/.reticulum
cargo run --release --bin rnsd -- --exampleconfig > ~/.reticulum/config
```

The example enables no interfaces. Uncomment or add at least one. A TCP client
connecting to a public transport node is the simplest way to join an existing
network:

```ini
[reticulum]
  enable_transport = false
  share_instance = true

[logging]
  loglevel = 4

[interfaces]
  [[TCP Client]]
    type = TCPClientInterface
    target_host = amsterdam.connect.reticulum.network
    target_port = 4965
```

The file uses the same format and keys as Python Reticulum, so an existing
Python config works unchanged. See [Configuration](configuration.md) for the
rns-rs specific keys. A missing `config` file is treated as empty, which gives
a node with no interfaces.

## 3. Start the node

```bash
./target/release/rns-server start --config ~/.reticulum
```

On startup `rns-server`:

- launches `rnsd` with the config directory;
- launches the `rns-sentineld` and `rns-statsd` sidecars when built with a hook
  backend;
- serves the control plane and built-in UI on `127.0.0.1:8080`;
- generates a bearer token and writes it to `<config dir>/http-token` (mode
  `0600`); it is never written to the logs.

Open `http://127.0.0.1:8080/` in a browser and paste the token from that file
to see the node, its interfaces, and process state. Useful flags: `--http-host`,
`--http-port`, `--http-token`, `--disable-auth`, `--no-http`, `--dry-run`.
The [operator runbook](rns-server-operator-runbook.md) covers the files that
appear in the config directory, the control-plane API, and troubleshooting.

## 4. Check that it works

With the node running, the CLI tools connect to it through the shared
instance:

```bash
./target/release/rnstatus              # interface status and traffic counters
./target/release/rnpath -t             # path table
./target/release/rnprobe <dest_hash>   # probe a destination and measure RTT
```

Build those binaries with `cargo build --release -p rns-cli` if you only built
`rns-server` so far.

## 5. Where to go next

- Run only the daemon or script the tools: [CLI Tools](cli-tools.md) and
  [rns-ctl](rns-ctl.md).
- Tune ingress control, queues, or socket marking:
  [Configuration](configuration.md).
- Extend the transport pipeline: [Hooks](hooks.md).
- Let two peers talk directly through NAT: [Direct Link](direct-link.md).
- Use the stack from your own Rust application: the `rns-net` crate examples
  under `rns-net/examples/` (`echo`, `message`, `tcp_connect`) show the
  application-facing API, and [Architecture](architecture.md) explains which
  crate to depend on.
- Contribute: [Development](development.md) and
  [CONTRIBUTING.md](../CONTRIBUTING.md).
