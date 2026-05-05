# rns-git

`rns-git` provides Git transport tools over Reticulum:

- `rngit`: repository server
- `git-remote-rns`: Git remote helper for `rns://` URLs

## Server Setup

Initialize the default server config:

```bash
cargo run -p rns-git --bin rngit
```

The first run creates `~/.config/rngit/server_config` and exits. Edit the config,
then start the server again:

```bash
cargo run -p rns-git --bin rngit
```

Print the repository destination and client identity:

```bash
cargo run -p rns-git --bin rngit -- --print-identity
cargo run -p rns-git --bin rngit -- --print-identity --base256
```

Important config paths:

- `repositories_dir`: bare repositories served by `rngit`
- `identity_path`: repository server identity
- `client_identity_path`: local client identity used by the helper
- `allow_read`, `allow_write`, `allow_create`, and `allow_stats`: repository
  ACL rules. Creating a missing repository requires create access; pushing to
  an existing repository requires write access. Stats pages require stats
  access, which can also be granted with `stats` or `s` in repository
  `.allowed` and group `group.allowed` files.
- `node_name` and `[pages] serve_nomadnet`: optional Nomad Network page node
  with built-in Micron repository browser pages. Repository `README.md` files
  are rendered to Micron, and `README.mu` files are served as Micron content.
  Text blob pages and Markdown fenced code blocks are syntax-highlighted by
  default when the file extension or fence language is supported.
  Build with `--no-default-features` to disable syntax highlighting and render
  plain escaped literal blocks instead. Set `record_stats = yes` in `[rngit]`
  to persist front/group/repository page views plus successful fetch and push
  counters in the server config directory `stats` file. Use
  `stats_ignore_identities` to exclude specific 16-byte identity hashes from
  collection. Iconsets, custom templates, and rendered/raw blob controls are
  still pending.

## Git Remote Helper

Build or install `git-remote-rns`, then ensure the binary is on `PATH` so Git can
invoke it for `rns://` remotes.

```bash
cargo build -p rns-git --bin git-remote-rns
```

Configure a remote:

```bash
git remote add origin rns://<destination_hash>/<repository>
git fetch origin
git push origin main
```

Repository names are resolved under the server `repositories_dir`. Keep names
relative and do not include absolute paths.

## Logging

`rngit` writes `server_log` in the server config directory. `git-remote-rns`
writes `client_log`. Both use the utility config log level instead of daemon
defaults.
