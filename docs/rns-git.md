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
- `allow_read`, `allow_write`, `allow_create`, `allow_stats`, and
  `allow_release`: repository ACL rules. Creating a missing repository requires
  create access; pushing to an existing repository requires write access. Stats
  pages require stats access. Release creation and deletion require release
  access, while release listing and viewing require read access. Repository
  `.allowed` and group `group.allowed` files can grant `stats`/`s` and
  `release`/`rel`.
- `node_name` and `[pages] serve_nomadnet`: optional Nomad Network page node
  with built-in Micron repository browser pages. Repository `README.md` files
  are rendered to Micron, and `README.mu` files are served as Micron content.
  Markdown tables are rendered with Micron box-drawing table output, including
  escaped pipe support, empty cells, alignment markers, and link/code/emphasis
  width handling.
  Blob pages for `.md` and `.mu` files default to rendered output and include
  rendered/raw view controls. Unsupported text blobs remain source views, with
  binary and oversized blobs kept on safe fallback messages.
  Text blob pages and Markdown fenced code blocks are syntax-highlighted by
  default when the file extension or fence language is supported.
  Build with `--no-default-features` to disable syntax highlighting and render
  plain escaped literal blocks instead. Set `record_stats = yes` in `[rngit]`
  to persist front/group/repository page views plus successful fetch and push
  counters in the server config directory `stats` file. Use
  `stats_ignore_identities` to exclude specific 16-byte identity hashes from
  collection. Repository pages include a persistent Thanks counter stored next
  to the bare repository as `<repo>.thanks`.
  Release metadata is stored next to the bare repository as
  `<repo>.releases/<tag>/`. Published releases appear on `/page/releases.mu`
  and `/page/release.mu`, support Markdown or Micron release notes, expose
  artifact download links through `/file/download`, support `latest` release
  resolution, and keep separate release Thanks counts in each release
  directory. Custom page templates can be placed in the configured
  `templates_dir` with names such as `base.mu`, `repo.mu`, `blob.mu`,
  `releases.mu`, and `release.mu`.
  Template variables include `{PAGE_CONTENT}`, `{NODE_NAME}`, `{VERSION}`,
  `{NAVIGATION}`, and `{GEN_TIME}`. Set `unicode_icons = yes` in `[pages]` to
  add simple Unicode icons to page navigation.

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

## Release Management

`rngit release` manages release metadata and downloadable artifacts for a
repository served by `rngit`.

```bash
rngit release rns://<destination_hash>/<repository> list
rngit release rns://<destination_hash>/<repository> view v1.0.0
rngit release rns://<destination_hash>/<repository> create v1.0.0:./dist --notes ./RELEASE.md
rngit release rns://<destination_hash>/<repository> delete v1.0.0 --yes
```

The release tag must already exist in the remote bare repository. `create`
initializes the release, uploads every regular file from the artifact directory
except `RELEASE.md` and `RELEASE.mu`, then finalizes it as published. If no
`--notes` path is provided, `rngit release create` uses `RELEASE.mu` or
`RELEASE.md` from the artifact directory when present. Artifact uploads print
per-file progress as each artifact is sent.

## Logging

`rngit` writes `server_log` in the server config directory. `git-remote-rns`
writes `client_log`. Both use the utility config log level instead of daemon
defaults.
