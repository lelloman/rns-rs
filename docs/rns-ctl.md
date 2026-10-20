# rns-ctl

`rns-ctl` is one binary that can run the node, serve an HTTP/WebSocket control
API, and act as a client for everyday operations. `rns-server` embeds the same
control plane, so the API below is also what the `rns-server` UI talks to.

```bash
cargo build --release -p rns-ctl
```

## Subcommands

| Subcommand | Role |
|------------|------|
| `rns-ctl daemon -c DIR` | Run the node, like `rnsd` |
| `rns-ctl http -c DIR [...]` | Run the node and serve the HTTP/WebSocket API plus the built-in UI |
| `rns-ctl status` | Interface status, like `rnstatus` |
| `rns-ctl probe <dest>` | Probe a destination, like `rnprobe` |
| `rns-ctl path -t` | Path table, like `rnpath` |
| `rns-ctl id -g PATH` | Identity management, like `rnid` |
| `rns-ctl config ...` | Read, validate, and apply runtime configuration |
| `rns-ctl backbone ...` | Backbone peer and blacklist management |
| `rns-ctl hook ...` | Load, unload, reload, list hooks on a running node |

Run any subcommand with `--help` for its options.

The client subcommands (`status`, `probe`, `path`, `config`, `backbone`) talk
to a running node over its shared-instance RPC socket. They authenticate with
a key derived from that node's `storage/transport_identity`, so they must be
pointed at the node's config directory. Without `-c`, they use
`~/.reticulum`, which on a server running `rns-server` from another directory
holds a different identity, and the call fails authentication:

```bash
rns-ctl status -c /var/lib/rns-node
rns-ctl probe -c /var/lib/rns-node <destination_hash>
```

## The HTTP server

```bash
rns-ctl http -c /path/to/config                  # generated token, port 8080
rns-ctl http --token my-secret-token             # fixed token
rns-ctl http --port 9090                         # custom port
rns-ctl http --disable-auth                      # no auth, for testing only
```

Authentication is on by default. Without `--token` or `RNSCTL_AUTH_TOKEN`, a
bearer token is generated at startup and written to `<config dir>/http-token`
with mode `0600`, replacing any previous one. It is printed once when stdout is
a terminal and never written to the log. Clients send it as
`Authorization: Bearer <token>`.

Limits: request bodies above 4 MiB get `413`, the token is checked before any
body is read, and at most 64 concurrent connections are served (`503` beyond
that). The port can also be set with `RNSCTL_HTTP_PORT`. Build with
`--features tls` for TLS.

Endpoints:

- HTTP API at `http://localhost:8080/api/...`
- WebSocket event stream at `ws://localhost:8080/ws`
- Built-in UI at `http://localhost:8080/`

### API surface

| Area | Endpoints |
|------|-----------|
| Node | `GET /health`, `GET /api/info`, `GET /api/node`, `GET /api/interfaces` |
| Routing | `GET /api/paths`, `POST /api/path/request`, `GET /api/announces`, `POST /api/announce`, `POST /api/announce_queues/clear` |
| Destinations and identities | `GET /api/destinations`, `POST /api/destination`, `/api/identity/...` |
| Packets and links | `GET /api/packets`, `POST /api/send`, `GET /api/proofs`, `GET /api/links`, `POST /api/link`, `POST /api/link/send`, `POST /api/link/close`, `GET /api/link_events`, `POST /api/channel` |
| Resources | `GET /api/resources`, `POST /api/resource`, `GET /api/resource_events` |
| Direct Link | `POST /api/direct_connect` (see [Direct Link](direct-link.md)) |
| Backbone | `GET /api/backbone/peers`, `/api/backbone/blacklist` |
| Hooks | `GET /api/hooks`, `POST /api/hook/load`, `/unload`, `/reload`, `/enable`, `/disable`, `/priority` |
| Config | `GET /api/config`, `GET /api/config/schema`, `GET /api/config/status`, `POST /api/config/validate`, `POST /api/config`, `POST /api/config/apply` |
| Processes (`rns-server`) | `GET /api/processes`, `GET /api/process_events`, `GET /api/processes/:name/logs`, `POST /api/processes/:name/{start,stop,restart}` |
| Statistics (`rns-statsd`) | `GET /api/stats/summary`, `/packets`, `/packets/series`, `/announces`, `/links`, `/interfaces`, `/destinations`, `/system` |

The process and statistics groups are served when the control plane runs
inside `rns-server` with the sidecars enabled. Config apply semantics
(`none`, `reload_control_plane`, `restart_children`, `restart_server`, and
combinations) are described in the
[operator runbook](rns-server-operator-runbook.md#config-apply-semantics).

## Hook management from the CLI

The `hook` subcommand talks to the HTTP server, so it needs the token:

```bash
RNSCTL_TOKEN="$(cat ~/.reticulum/http-token)"
rns-ctl hook list --token "$RNSCTL_TOKEN"
rns-ctl hook load <path-or-builtin-id> --point <HookPoint> --token "$RNSCTL_TOKEN" [--type wasm|native|builtin] [--priority N] [--name NAME]
rns-ctl hook unload <name> --point <HookPoint> --token "$RNSCTL_TOKEN"
rns-ctl hook reload <name> --point <HookPoint> --path <file-or-builtin-id> --token "$RNSCTL_TOKEN" [--type wasm|native|builtin]
```

`--type` defaults to `wasm`, or to `builtin` on builds without the WASM
backend. Native hooks loaded at runtime must come from the configured hooks
directory (`<config dir>/hooks` by default, overridable with
`rns-ctl http --hooks-dir PATH`, `RNSCTL_HOOKS_DIR`, or `hooks_dir` in
`rns-server.json`); the path must be absolute and resolve inside that
directory. Hooks listed in the config file's `[hooks]` section are loaded at
startup from wherever they are. See
[Native Hooks](native-hooks.md#accepted-paths).
