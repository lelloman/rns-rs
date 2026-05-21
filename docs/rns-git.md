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
- `allow_read`, `allow_write`, `allow_create`, `allow_stats`, `allow_release`,
  `allow_interact`, `allow_propose`, and `allow_admin`: repository ACL rules.
  Creating a missing repository requires create access; pushing to an existing
  repository requires write access. Stats pages require stats access. Release
  creation and deletion require release access, while release listing and
  viewing require read access. Work document proposals require propose access.
  Admin identities satisfy repository permission checks. Repository permission
  files can be stored as either `<repo>/.allowed` or the upstream-style sidecar
  `<repo>.allowed`; group rules can be stored as `<group>/group.allowed` or
  `<group>.allowed`. Permission files may be executable scripts that emit rules
  on stdout. They can grant `read`/`r`, `write`/`w`, `readwrite`/`rw`,
  `create`/`c`, `stats`/`s`, `release`/`rel`, `interact`/`i`, `propose`/`p`,
  and `admin`/`adm`.
- `[aliases]`: optional local aliases for 16-byte hashes. In `server_config`,
  aliases name identities used by global ACL values and repository/group
  `.allowed` files. In `client_config`, aliases name destination hashes used in
  `rns://<destination>/<repository>` URLs. Aliases are resolved locally before a
  request is sent; fork and mirror upstream metadata stores the canonical hash.
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
  Markdown fenced code blocks tagged `rawmu` are passed through as raw Micron
  instead of being escaped or syntax-highlighted; use this only for repository
  content that intentionally needs native Micron markup.
  Build with `--no-default-features` to disable syntax highlighting and render
  plain escaped literal blocks instead. Set `record_stats = yes` in `[rngit]`
  to persist front/group/repository page views plus successful fetch and push
  counters in the server config directory `stats` file. Use
  `stats_ignore_identities` to exclude specific 16-byte identity hashes from
  all collection, or `stats_push_ignore_identities` to suppress only push
  counters for automation identities. Set `blocked_identities` to deny listed
  identities all repository, page, and management operations. Repository pages
  include a persistent Thanks counter stored next to the bare repository as
  `<repo>.thanks`.
  Release metadata is stored next to the bare repository as
  `<repo>.releases/<tag>/`. Published releases appear on `/page/releases.mu`
  and `/page/release.mu`, support Markdown or Micron release notes, expose
  artifact download links through `/file/download`, support `latest` release
  resolution, and keep separate release Thanks counts in each release
  directory. Work Documents are stored next to the bare repository as
  `<repo>.work/`; repositories with work documents link to `/page/work.mu` and
  `/page/work_doc.mu` for active/completed documents, Markdown or Micron
  content, comments, authors, and timestamps. Custom page templates can be
  placed in the configured
  `templates_dir` with names such as `base.mu`, `repo.mu`, `blob.mu`,
  `releases.mu`, `release.mu`, `work.mu`, and `work_doc.mu`.
  Template variables include `{PAGE_CONTENT}`, `{NODE_NAME}`, `{VERSION}`,
  `{NAVIGATION}`, and `{GEN_TIME}`. Set `unicode_icons = yes` in `[pages]` to
  add simple Unicode icons to page navigation.
  Repositories created with `rngit fork` or `rngit mirror` record their upstream
  source in Git config and show a `Forked from ...` or `Mirrored from ...`
  provenance line on the repository page.

## Identity And Destination Aliases

Define aliases in the `[aliases]` section of `server_config` or `client_config`:

```ini
[aliases]
alice = d09285e660cfe27cee6d9a0beb58b7e0
my_node = 063d38912bffc850af4a1b8a270a9d85
```

Server aliases are identity aliases. They can be used in ACL config values and
allowed files, for example `write = alice` or `adm:alice`. Client aliases are
destination aliases. They can be used wherever a client command accepts an
`rns://` remote URL, for example:

```bash
rngit create rns://my_node/public/project
rngit fork rns://my_node/public/project rns://my_node/forks/project
```

Aliases are not sent over the network. Client commands canonicalize aliased
`rns://` URLs to full destination hashes before sending requests, so stored fork
and mirror upstream URLs remain portable between clients.

## Repository Management

`rngit` can create empty repositories and ask a remote node to clone an
upstream Git source into a new fork or mirror. The target repository URL is
always the `rns://` URL of the server that will host the new repository.

```bash
rngit create rns://<destination_hash>/<group>/<repo>
rngit fork https://example.invalid/project.git rns://<destination_hash>/<group>/<repo>
rngit mirror https://example.invalid/project.git rns://<destination_hash>/<group>/<repo>
rngit sync rns://<destination_hash>/<group>/<repo>
rngit perms rns://<destination_hash>/<group>
rngit perms rns://<destination_hash>/<group>/<repo>
rngit perms rns://<destination_hash>/<group>/<repo> --content ./repo.allowed
```

`create`, `fork`, and `mirror` require create access in the target group. The
server initializes a bare repository and writes a sidecar `<repo>.allowed` file
granting the requester admin access. Forks and mirrors store
`repository.rngit.type` and `repository.rngit.upstream.source` in the bare
repository config. `sync` requires read and write access and fetches
`+refs/*:refs/*` from that recorded upstream source; mirror syncs also update
`repository.rngit.upstream.sync`.

`rngit perms` gets or replaces group and repository permission sidecar files over
`/mgmt/perms`. A URL ending at `<group>` targets `<group>.allowed`; a URL ending
at `<group>/<repo>` targets `<group>/<repo>.allowed`. Reading or replacing these
files requires admin access, and the server validates replacement content before
atomically writing it. Rust `rngit perms` is non-interactive: without
`--content`, it prints the current permission file; with `--content PATH`, it
replaces the remote permission file with `PATH`.

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
rngit release rns://<destination_hash>/<repository> create v1.0.0:./dist --signer ./release_identity --name package-name
rngit release rns://<destination_hash>/<repository> create v1.0.0:./dist --local
rngit release rns://<destination_hash>/<repository> fetch v1.0.0:artifact.tar.gz --signer <identity_hash>
rngit release package_v1.0.0.rsm fetch v1.0.0:all --signer <identity_hash>
rngit release package_v1.0.0.rsm fetch --offline --signer <identity_hash>
rngit release rns://<destination_hash>/<repository> delete v1.0.0 --yes
```

The release tag must already exist in the remote bare repository. `create`
initializes the release, uploads every regular file from the artifact directory
except `RELEASE.md` and `RELEASE.mu`, then finalizes it as published. If no
`--notes` path is provided, `rngit release create` uses `RELEASE.mu` or
`RELEASE.md` from the artifact directory when present. Release creation signs
each artifact with the client identity, or with `--signer PATH` when supplied,
writes local `<artifact>.rsg` files plus `manifest.rsm` into the artifact
directory, and uploads those generated signature and manifest files with the
release. Use `--name NAME` when the package name should differ from the
repository name. Use `--local` to generate the signed local files without
connecting to the remote or uploading the release. Artifact uploads print
per-file progress as each artifact is sent.

`release fetch` first validates `manifest.rsm`, saves it locally as
`<name>_<version>.rsm`, then validates each downloaded artifact against the
embedded RSG. The remote argument can also be a saved `.rsm` manifest; in that
case `rngit` validates the local manifest and uses its embedded origin metadata
to contact the release repository. Add `--offline` with a local manifest to
validate the manifest and local artifact files without opening a network link.

## Work Documents

`rngit work` manages repository Work Documents over `/mgmt/work`.

```bash
rngit work rns://<destination_hash>/<repository> list --scope all
rngit work rns://<destination_hash>/<repository> view --id 1
rngit work rns://<destination_hash>/<repository> create --title "Task" --content ./WORK.md
rngit work rns://<destination_hash>/<repository> propose --title "Idea" --content ./PROPOSAL.md
rngit work rns://<destination_hash>/<repository> comment --id 1 --content ./UPDATE.md
rngit work rns://<destination_hash>/<repository> perms --id 1
rngit work rns://<destination_hash>/<repository> perms --id 1 --content ./WORK.allowed
rngit work rns://<destination_hash>/<repository> complete --id 1
rngit work rns://<destination_hash>/<repository> delete --id 1 --yes
```

Rust `rngit work` is non-interactive: create, edit, and comment operations read
document bodies from `--content PATH`. Files ending in `.mu` are sent as Micron;
other content is sent as Markdown.

Proposals are stored in the `proposed` scope and must include a valid signature
from the submitting identity. `--scope proposed` lists or views proposed
documents, and `--scope all` includes active, completed, and proposed documents.
The server writes document-local interact/write permissions for the proposer so
they can continue updating their proposal without broader repository write
access.

Document-local permissions are stored as `<repo>.work/<id>.allowed` and use the
same syntax as repository `.allowed` files. A document-local `interact` grant
allows comments on that document without granting edit/delete access. The
document author can get or set permissions when they have repository
write+interact access; document admins can get or set the document permission
file. `rngit work perms --id N` prints the current permission file, and
`--content PATH` atomically replaces it after syntax validation.

## Logging

`rngit` writes `server_log` in the server config directory. `git-remote-rns`
writes `client_log`. Both use the utility config log level instead of daemon
defaults.
