# crates.io Publish Runbook

This runbook documents the release process for publishing crates from this
workspace to crates.io without losing source provenance.

The main rule is simple: publish only from a committed, clean tree, then tag
that exact commit per crate.

## 1. Preconditions

Start from the repo root on the branch you intend to publish from.

```bash
git status --short
```

Required state:

- no modified files
- no staged but uncommitted changes
- no untracked release-related files

Do not publish from a dirty worktree. Recent crates in this repo were published
before the matching commit existed, which makes exact release tagging
impossible after the fact.

## 2. Decide the release set

Before touching versions, write down the exact crates and versions being
released.

Common currently published crates:

- `rns-crypto`
- `rns-core`
- `rns-net`
- `rns-cli`
- `rns-ctl`
- `rns-hooks`
- `rns-stats-hook`
- `rns-hooks-sdk`
- `rns-hooks-abi`

`rns-esp32` is excluded from the workspace and is not published on crates.io.
It has its own release process — see
[esp32-release-runbook.md](esp32-release-runbook.md).

Important detail:

- `rns-crypto` uses `version.workspace = true`, so its released version comes
  from the root [Cargo.toml](/home/lelloman/lelloprojects/rns-rs/Cargo.toml)
- the other published crates use explicit crate-local versions

## 3. Bump versions

Update the versions for the crates being released and any internal dependency
constraints that must move with them.

Files commonly involved:

- [Cargo.toml](/home/lelloman/lelloprojects/rns-rs/Cargo.toml)
- [rns-crypto/Cargo.toml](/home/lelloman/lelloprojects/rns-rs/rns-crypto/Cargo.toml)
- [rns-core/Cargo.toml](/home/lelloman/lelloprojects/rns-rs/rns-core/Cargo.toml)
- [rns-net/Cargo.toml](/home/lelloman/lelloprojects/rns-rs/rns-net/Cargo.toml)
- [rns-cli/Cargo.toml](/home/lelloman/lelloprojects/rns-rs/rns-cli/Cargo.toml)
- [rns-ctl/Cargo.toml](/home/lelloman/lelloprojects/rns-rs/rns-ctl/Cargo.toml)
- [rns-hooks/Cargo.toml](/home/lelloman/lelloprojects/rns-rs/rns-hooks/Cargo.toml)
- [rns-stats-hook/Cargo.toml](/home/lelloman/lelloprojects/rns-rs/rns-stats-hook/Cargo.toml)
- [rns-hooks/sdk/rns-hooks-sdk/Cargo.toml](/home/lelloman/lelloprojects/rns-rs/rns-hooks/sdk/rns-hooks-sdk/Cargo.toml)
- [rns-hooks/sdk/rns-hooks-abi/Cargo.toml](/home/lelloman/lelloprojects/rns-rs/rns-hooks/sdk/rns-hooks-abi/Cargo.toml)

Then refresh the lockfile:

```bash
cargo check --workspace
```

## 4. Verify locally before publishing

Run the full workspace checks first:

```bash
cargo check --workspace
cargo test --workspace
```

Then run `cargo publish --dry-run` for each crate you plan to release.

Publish in dependency order so that downstream crates only reference versions
that already exist on crates.io.

Typical order for this workspace:

1. `rns-hooks-abi`
2. `rns-hooks-sdk`
3. `rns-crypto`
4. `rns-core`
5. `rns-hooks`
6. `rns-stats-hook`
7. `rns-net`
8. `rns-cli`
9. `rns-ctl`

Example:

```bash
cargo publish --dry-run -p rns-hooks-abi
cargo publish --dry-run -p rns-hooks-sdk
cargo publish --dry-run -p rns-crypto
cargo publish --dry-run -p rns-core
cargo publish --dry-run -p rns-hooks
cargo publish --dry-run -p rns-stats-hook
cargo publish --dry-run -p rns-net
cargo publish --dry-run -p rns-cli
cargo publish --dry-run -p rns-ctl
```

If only part of the workspace is being released, keep the same dependency
ordering and skip crates that are not part of that release.

## 5. Commit the release state

After all version bumps and dry runs pass, commit the exact tree that will be
published.

Example:

```bash
git status --short
git add Cargo.toml Cargo.lock \
  rns-core/Cargo.toml \
  rns-net/Cargo.toml \
  rns-cli/Cargo.toml \
  rns-ctl/Cargo.toml
git commit -m "Release selected crates"
```

Before publishing, verify that the tree is still clean:

```bash
git status --short
```

Required state: empty output.

## 6. Publish from that exact commit

Run the real publishes only after the release commit exists and the tree is
clean.

Example:

```bash
cargo publish -p rns-hooks-abi
cargo publish -p rns-hooks-sdk
cargo publish -p rns-crypto
cargo publish -p rns-core
cargo publish -p rns-hooks
cargo publish -p rns-stats-hook
cargo publish -p rns-net
cargo publish -p rns-cli
cargo publish -p rns-ctl
```

If crates.io indexing lags briefly between publishes, wait and retry only after
confirming the upstream crate version is visible.

## 7. Verify the published versions

Confirm that crates.io shows the intended version for each published crate
before tagging.

Minimal checks:

```bash
cargo search rns-core --limit 1
cargo search rns-net --limit 1
cargo search rns-cli --limit 1
```

If you want an exact machine-readable check, use the crates.io API.

Example:

```bash
curl -sS https://crates.io/api/v1/crates/rns-core | jq -r '.crate.newest_version'
curl -sS https://crates.io/api/v1/crates/rns-net | jq -r '.crate.newest_version'
curl -sS https://crates.io/api/v1/crates/rns-cli | jq -r '.crate.newest_version'
```

## 8. Tag the published commit

Use annotated per-crate tags on the commit that was actually published.

Format:

- `<crate-name>-v<version>`

Examples:

```bash
git tag -a rns-core-v0.1.5 HEAD -m "rns-core 0.1.5"
git tag -a rns-net-v0.5.1 HEAD -m "rns-net 0.5.1"
git tag -a rns-cli-v0.2.0 HEAD -m "rns-cli 0.2.0"
```

This repo should not rely on a single repo-wide release tag. The crates are
versioned independently, so release provenance must also be tracked per crate.

It is normal for one commit to receive multiple tags if several crates were
published from the same release commit.

## 9. Push the commit and tags

Push the branch and then the tags.

Example:

```bash
git push origin master
git push origin \
  rns-core-v0.1.5 \
  rns-net-v0.5.1 \
  rns-cli-v0.2.0
```

Adjust the branch and tag list to match the release.

## 10. Release checklist

Use this as the final release gate:

- `git status --short` is empty before publish
- all intended version bumps are committed
- `cargo check --workspace` passes
- `cargo test --workspace` passes
- each released crate passes `cargo publish --dry-run`
- crates are published in dependency order
- crates.io shows the intended versions
- annotated per-crate tags are created on the published commit
- branch and tags are pushed

## 11. Rules to keep

- Never publish from an uncommitted working tree
- Never publish from a dirty tree
- Never tag `HEAD` later unless `HEAD` is the exact published commit
- Never use one repo-wide tag as the only release marker
- Always use annotated crate-specific tags

Following those rules keeps crates.io releases traceable back to a precise
source snapshot.
