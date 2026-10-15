# CLI Tools

The `rns-cli` crate ships the Reticulum command-line programs with the same
names and roles as their Python counterparts, plus two sidecar daemons. They
are the lower-level building blocks; most deployments run
[`rns-server`](rns-server-operator-runbook.md) and reach for these when they
need to script, debug, or run pieces independently.

```bash
cargo build --release -p rns-cli
ls target/release/rn*
```

All tools accept `--config DIR` to select the config directory (default
`~/.reticulum`) and connect to the running `rnsd` through its shared instance.

| Tool | Purpose | More |
|------|---------|------|
| `rnsd` | The node daemon | below |
| `rnstatus` | Interface status, traffic counters, attach/detach/reload | [rnstatus](rnstatus.md) |
| `rnpath` | Display and manage the path table, request paths | `rnpath --help` |
| `rnprobe` | Send a probe packet to a destination and measure RTT | `rnprobe --help` |
| `rnid` | Identity creation, inspection, encryption, and signatures | `rnid --help` |
| `rnsh` | Remote shell over a Reticulum link | [rnsh](rnsh.md) |
| `rncp` | File transfer with authenticated fetch | below |
| `rnx` | Remote command execution | below |
| `rns-statsd` | Statistics sidecar, writes to a SQLite database | below |
| `rns-sentineld` | Sentinel policy sidecar | below |

## `rnsd`

```text
Usage: rnsd [OPTIONS]

Options:
  --config PATH, -c PATH  Path to config directory
  -s                      Service mode (log to file)
  --exampleconfig         Print example config and exit
  -v                      Increase verbosity (can repeat)
  -q                      Decrease verbosity (can repeat)
  --version               Print version and exit
```

In service mode the log goes to `<config dir>/logfile`, rotated at 5 MiB with
one archive kept, and the configured log level is used as is. In the
foreground, `-v` and `-q` adjust the configured level.

## `rncp`

```text
rncp [options] <file> <destination>
rncp --fetch [options] <remote-file> <destination>
rncp --listen [options]
```

Key options: `-l/--listen` to receive, `-f/--fetch` to pull a file,
`-F/--allow-fetch` to serve authenticated fetches, `-j/--jail DIR` to confine
fetches, `-s/--save DIR`, `-a/--allowed HASH` (repeatable), `-n/--no-auth`,
`-i/--identity PATH`, `-b/--announce SECONDS`, `-C/--no-compress`,
`-w/--timeout SECONDS`, `-p/--print-identity`.

## `rnx`

```text
rnx [options] <destination> <command>
rnx --listen [options]
rnx --interactive [options] <destination>
```

Key options: `-l/--listen`, `-x/--interactive`, `-a/--allowed HASH`
(repeatable), `-n/--noauth`, `-N/--noid`, `-b/--no-announce`,
`-d/--detailed`, `-m/--mirror` to mirror the remote exit status,
`-w/--timeout`, `-W/--result-timeout`, `--stdin TEXT`, `--stdout BYTES`,
`--stderr BYTES`, `-i/--identity PATH`, `-p/--print-identity`.

## Sidecars: `rns-statsd` and `rns-sentineld`

Both binaries exist only in hook-enabled builds (`rns-hooks-wasm`,
`rns-hooks-native`, or `rns-hooks-builtin` on `rns-cli`). Each attaches a hook
to the running node and consumes its events:

- `rns-statsd --db PATH [OPTIONS]` collects packet, announce, link, interface,
  and system statistics into a SQLite database. `rns-server` points it at
  `<config dir>/stats.db` by default and the control plane serves the data
  under `/api/stats/*`. Retention is described in the
  [operator runbook](rns-server-operator-runbook.md#statistics-database-retention).
- `rns-sentineld [OPTIONS]` watches Backbone peer events through the sentinel
  hook and temporarily blacklists peers that repeatedly stall on writes or
  idle out (by default two write stalls or four idle timeouts within five
  minutes, blacklisted for two minutes). Docker suite 20 exercises it.

Under `rns-server` both are started automatically by re-executing the server
binary with hidden role flags, so you rarely run them by hand.

## Examples in `rns-net`

The `rns-net` crate has runnable examples that double as API documentation:

```bash
cargo run -p rns-net --example echo          # application-facing API
cargo run -p rns-net --example message       # two clients exchanging encrypted messages via a local transport node
cargo run -p rns-net --example tcp_connect   # connect to a Python RNS TCP server and log announces
cargo run -p rns-net --example rnsd          # a minimal daemon built on the public API
RUST_LOG=info cargo run -p rns-net --example rnode_lora -- /dev/ttyUSB0   # log LoRa traffic from an RNode
```

`rnode_hil` and `weave_hil` are opt-in hardware-in-the-loop runners.

## Related

- [rns-ctl](rns-ctl.md) bundles daemon and client roles into one binary with
  an HTTP API.
- [rns-git](rns-git.md) adds `rngit`, `git-remote-rns`, and `rngcs`.
- [rntun](../rns-tun/README.md) is the Linux tunnelling CLI.
