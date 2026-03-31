# rns-server Release Readiness

## Status

`rns-server` is now release-candidate ready for the single-node product scope.

Completed areas:

- explicit sidecar readiness contracts
- supervised durable process logs
- product-level config planning with structured apply actions
- embedded auth reload without full restart
- operator-facing config workflow and apply preview
- per-process UI detail panels
- API integration coverage for product behavior
- Docker end-to-end coverage for supervised operation
- direct control UI smoke coverage
- clearer ownership of the `rns-server` to `rns-ctl` bridge

## Remaining Caveats

The project is substantially complete for the current target, but these remain conscious limits rather than open blockers:

- embedded HTTP bind host/port and enablement still require full `rns-server` restart
- UI smoke coverage is lightweight and does not replace a full browser automation stack
- packaging is tarball-oriented rather than OS-package oriented
- multi-node or cluster-level orchestration is out of scope for this product slice

## Release Inputs

Release artifacts should include:

- `rns-server`
- [rns-server-operator-runbook.md](/home/lelloman/lelloprojects/rns-rs/docs/rns-server-operator-runbook.md)
- this readiness document

Generate the bundle with:

```bash
bash scripts/package-rns-server-tarball.sh
```

## Verification Gates

A release build should pass:

```bash
cargo test -p rns-server
cargo test -p rns-cli
cargo test -p rns-ctl config_
node --test rns-ctl/assets/app.smoke.test.js
bash tests/docker/rns-server/run.sh
```

## Exit Criteria

For the current project scope, release readiness means:

- `rns-server` is the single product entrypoint
- normal deployment ships one binary and self-spawns child roles
- supervised children have explicit readiness and durable logs
- config save/apply behavior is predictable and operator-visible
- the embedded UI covers the common operator workflow
- API, UI, and Docker verification exist for the critical paths
- a reproducible packaging path and operator docs are present
