# rnsh

`rnsh` opens a remote shell over Reticulum links. It has two modes:

- listener mode: exposes a command or shell through an inbound link
- initiator mode: connects to a listener destination and attaches local terminal I/O

## Listener

Start a listener with a generated or existing identity:

```bash
cargo run --bin rnsh -- -l -- /bin/sh
```

By default, listener mode requires the initiator to identify with an allowed
identity. For local testing, `-n` disables that authentication check:

```bash
cargo run --bin rnsh -- -l -n -- /bin/sh
```

Use `--print-identity` to print the listener identity and destination hash:

```bash
cargo run --bin rnsh -- -l --print-identity
```

## Initiator

Connect to a listener destination:

```bash
cargo run --bin rnsh -- <destination_hash>
```

Pass a remote command after `--`:

```bash
cargo run --bin rnsh -- <destination_hash> -- uname -a
```

## Identity and Access

Useful identity and access options:

- `-i, --identity PATH` selects the identity file.
- `-a, --allowed HASH` allows a specific initiator identity hash. Repeat it for
  multiple identities, or list them one per line in `allowed_identities` in
  the rnsh config directory.
- `-n, --no-auth` allows any initiator identity.
- `-N, --no-id` skips initiator identification.

## Config Directories

`-c, --config DIR` selects the rnsh config directory, which holds
`allowed_identities` and the logs. By default it is `~/.config/rnsh` when that
exists, otherwise `~/.rnsh`. `--rnsconfig DIR` selects the Reticulum config
directory (default `~/.reticulum`).

## Logging

`rnsh` writes utility logs to the rnsh config directory: `logfile` in listener
mode, `logfile.initiator` in initiator mode. Verbosity is controlled with
`-v` and `-q`. Both modes default to INFO. Initiator logs include path
requests, link establishment, the connected peer version and session
completion. Listener logs include identity authentication or denial and remote
command execution; an identification callback received after the version
handshake is treated as a fatal protocol error.
