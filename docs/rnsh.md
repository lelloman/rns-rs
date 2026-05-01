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
cargo run --bin rnsh -- -l --print-identity --base256
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
  multiple identities.
- `-n, --no-auth` allows any initiator identity.
- `-N, --no-id` skips initiator identification.

## Logging

`rnsh` writes utility logs to the rnsh config directory. Verbosity is controlled
with `-v` and `-q`; listener mode defaults to more useful operational logging
than initiator mode.
