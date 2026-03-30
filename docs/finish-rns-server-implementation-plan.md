# Finish rns-server Implementation Plan

## Goal

Finish `rns-server` as the single-node product entrypoint with trustworthy health state, operator-grade config flows, durable observability, direct UI/API coverage, and a release-ready distribution/documentation story.

## Working Rules

The remaining work should follow these rules:

1. Keep `rns-server` as the owner of lifecycle, config planning, and product behavior.
2. Keep `rns-ctl` as the embedded control-plane library, API server, and built-in UI surface.
3. Do not fork a second HTTP/API stack.
4. After each completed task:
   - run the relevant tests
   - confirm the result
   - commit the change
   - then move to the next task

## Task List

### 1. Define explicit sidecar readiness contracts

Replace heuristic sidecar readiness assumptions with explicit, documented readiness contracts for `rns-sentineld` and `rns-statsd`.

Likely touchpoints:

- `rns-server/src/supervisor.rs`
- `rns-server/src/config.rs`
- sidecar crates that can expose readiness state
- `docs/`

Done when:

- sidecar readiness no longer depends primarily on process age
- each sidecar has a clear success/failure readiness signal
- readiness detail strings are useful to operators

### 2. Wire explicit readiness probes into supervision

Consume the readiness contracts from the supervisor and surface stable readiness transitions through shared state.

Likely touchpoints:

- `rns-server/src/supervisor.rs`
- `rns-ctl/src/state.rs`
- `rns-ctl/src/api.rs`

Done when:

- readiness probing uses explicit sidecar checks
- process state transitions are reflected cleanly in API/UI data
- failures produce actionable detail

### 3. Add durable supervised-process log persistence

Persist child stdout/stderr beyond in-memory ring buffers so operators can inspect failures after restarts.

Likely touchpoints:

- `rns-server/src/supervisor.rs`
- new `rns-server/src/` log module
- `rns-ctl/src/state.rs`
- `rns-ctl/src/api.rs`

Done when:

- each supervised child has a persisted recent log source
- API responses can point to current log availability
- restart/crash diagnosis does not depend on attached terminals

### 4. Expose process log metadata and richer health detail in API/UI

Show enough observability data for operators to understand what happened without shell access.

Likely touchpoints:

- `rns-ctl/src/api.rs`
- `rns-ctl/src/state.rs`
- `rns-ctl/assets/app.js`
- `rns-ctl/assets/app.css`

Done when:

- UI/API expose readiness detail, last error, recent logs, and useful metadata
- per-process status is understandable without reading code

### 5. Classify config changes by apply action

Make config planning precise and explicit: no-op, reload, child restart, or full `rns-server` restart.

Likely touchpoints:

- `rns-server/src/config.rs`
- `rns-ctl/src/state.rs`

Done when:

- config apply planning is precise and structured
- API/UI do not have to infer restart semantics from booleans

### 6. Implement reload semantics where possible

Avoid requiring a full `rns-server` restart for settings that can be reloaded safely.

Likely touchpoints:

- `rns-server/src/main.rs`
- `rns-ctl/src/server.rs`
- `rns-server/src/config.rs`

Done when:

- reloadable settings are handled without full process replacement
- non-reloadable settings remain clearly marked as restart-required

### 7. Expand config status tracking

Track last planned action, affected processes, pending convergence, and explicit blocking reasons.

Likely touchpoints:

- `rns-ctl/src/state.rs`
- `rns-ctl/src/api.rs`

Done when:

- config status explains current convergence state in operator terms
- saved/runtime drift is clear

### 8. Promote the guided config builder to the primary workflow

Make normal configuration changes possible through structured controls, with JSON editing as an advanced path.

Likely touchpoints:

- `rns-ctl/assets/app.js`
- `rns-ctl/assets/index_auth.html`
- `rns-ctl/assets/index_noauth.html`
- `rns-ctl/assets/app.css`

Done when:

- common config tasks can be done without editing raw JSON
- the UI feels like a product workflow, not just an API shell

### 9. Add config diff and apply preview UX

Show operators exactly what will change and what restart/reload impact it will have before applying.

Likely touchpoints:

- `rns-ctl/assets/app.js`
- `rns-ctl/assets/app.css`
- `rns-ctl/src/api.rs`

Done when:

- validate/save/apply flows show concrete change impact
- the operator can review action consequences before mutating state

### 10. Add per-process operator detail panels

Give each managed process an operator-focused detail view with health, events, and logs.

Likely touchpoints:

- `rns-ctl/assets/app.js`
- `rns-ctl/assets/app.css`
- `rns-ctl/src/api.rs`

Done when:

- operators can inspect process behavior from the built-in UI
- recent errors and lifecycle transitions are easy to find

### 11. Expand API integration coverage for new product behavior

Add integration coverage for logs, readiness detail, config plan responses, and failure cases.

Likely touchpoints:

- `rns-ctl/tests/integration.rs`

Done when:

- critical product-level API flows have direct automated coverage
- key failure states are tested

### 12. Expand Docker E2E coverage for rns-server operations

Exercise supervision, readiness, restart/apply semantics, and persisted observability through Docker tests.

Likely touchpoints:

- `tests/docker/rns-server/test.sh`
- `tests/docker/rns-server/run.sh`
- `tests/docker/rns-server/docker-compose.yml`

Done when:

- the full-stack `rns-server` path is tested for real operator scenarios
- restart/recovery behavior is covered

### 13. Add browser/UI smoke coverage

Cover the critical operator flows directly in the browser instead of relying only on API and Docker checks.

Likely touchpoints:

- new browser test harness files
- UI assets under `rns-ctl/assets/`

Done when:

- page load, config validate/save/apply, and process controls are exercised through browser automation

### 14. Tighten internal ownership boundaries

Reduce accidental product-specific coupling inside `rns-ctl` without undoing the reuse strategy.

Likely touchpoints:

- `rns-ctl/src/state.rs`
- `rns-server/src/`
- `rns-ctl/src/`

Done when:

- the product-specific parts have clearer ownership
- the current split is intentional rather than expedient

### 15. Finish packaging, operator docs, and release readiness

Document install, startup, auth, config, logs, troubleshooting, and release steps, then update status docs to reflect release readiness instead of MVP status.

Likely touchpoints:

- `docs/`
- packaging/release scripts as needed
- `tests/docker/rns-server/`

Done when:

- there is a clear installation and operations path
- release smoke steps are defined
- status docs describe the final product state
