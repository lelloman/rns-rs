# Upstream Reticulum Parity

This directory contains the audit trail and final acceptance record for each
Reticulum baseline adopted by rns-rs.

## Naming Convention

Each upstream version can have two documents with stable, date-independent
filenames:

- `reticulum-next-audit.md` — the single active audit used when upstream has
  moved but the next release version or promotion target is not known yet.
- `reticulum-X.Y.Z-audit.md` — the commit-by-commit audit and integration work
  record after the target version is known and before baseline promotion.
- `reticulum-X.Y.Z-parity.md` — the concise, final acceptance record created
  when the baseline is promoted.
- `reticulum-X.Y.Z-rgit-{audit,parity}.md` — qualified records used when the
  normative rgit baseline advances without an upstream version change, so the
  signed-release records remain immutable.

Dates, commit hashes, repository tips, and local branch revisions belong inside
the documents instead of their filenames. Historical versions without a saved
working audit can have only a parity record.

## Workflow

1. When the daily operator report finds commits after the accepted baseline,
   copy [AUDIT-TEMPLATE.md](AUDIT-TEMPLATE.md) to `reticulum-next-audit.md`.
   Keep one active audit and extend it on later daily checks.
2. Pin the previous baseline, target commit or tag, tree hashes, version
   assertion, repositories, and audit date before reviewing code. If the target
   version is not known, mark those fields as pending instead of guessing.
3. Inventory every upstream commit exactly once and give it an explicit final
   disposition. Record local commits and focused test evidence as work lands.
4. Rename the active file to `reticulum-X.Y.Z-audit.md` when the upstream
   version and promotion target are known.
   Use upstream version metadata and changelog text to identify that target,
   but do not vendor the upstream changelog or treat its compatibility claims
   as acceptance evidence; verify every listed behavior from its source commit.
5. Complete the promotion gates without rewriting failures or deferred manual
   checks as passes.
6. Copy [PARITY-TEMPLATE.md](PARITY-TEMPLATE.md) to the versioned parity
   filename and summarize the final compatibility evidence, acceptance results,
   and caveats.
7. Promote `UPSTREAM.md` only after the parity record is complete. Link the
   parity record as the acceptance authority and the audit as detailed evidence.

Never edit an old audit to make its point-in-time pre-integration findings look
final. The corresponding parity record records the final outcome.

## Per-Commit Integration Procedure

Process upstream commits in ancestry order. Do not combine unrelated commits
merely because they appeared in the same drift report. Every upstream commit
must map to exactly one rns-rs commit, even when adjacent changes depend on each
other. The resulting local commits must remain in the same ancestry order as
upstream.

Start from a clean rns-rs working tree. Do not accumulate a drift report into
one working-tree bundle or use a stash as the integration record. Finish,
validate, document, and commit the current upstream change before beginning the
next one. Use the commit subject prefix `upstream:`, preserve the upstream
subject where practical, and add this trailer with the full canonical hash:

```text
Upstream-Commit: <40-character canonical commit hash>
```

An `Integrated` change gets its code and focused tests in that one mapping
commit. A `Structurally covered`, `Non-runtime`, or deliberately `Deferred`
change still gets one non-empty mapping commit that strengthens a regression,
documents the relevant invariant in code, or records its analysis. Do not use
an empty commit. If a commit cannot stand alone because an earlier dependency
is absent, integrate the dependency first; do not squash the commits together.

1. Refresh both upstream remotes with `scripts/check_upstream_drift.py` and
   require a fresh, complete result. Keep the configured checkout at the
   accepted `UPSTREAM.md` normative commit. Inspect newer objects with `git
   show`; do not advance that checkout merely to read a diff.
2. Record the full hash, subject, changed paths, and dependency on earlier
   unintegrated commits in the active audit. Read the complete diff and enough
   surrounding upstream code to identify the observable behavior, not only the
   lines changed.
3. Locate the corresponding Rust protocol, state, RPC, CLI, persistence, and
   documentation surfaces. Search for an existing invariant or test that may
   already cover the behavior before deciding that code is required.
4. Assign one explicit disposition from the audit vocabulary:
   `Integrated`, `Structurally covered`, `Non-runtime`, `Deferred`, `Needs
   port`, `Needs coordinated port`, or `Needs decision`. A subject line or
   architectural intuition alone is not evidence for `Structurally covered`.
5. For an applicable change, first add or identify a focused regression that
   fails for the missing behavior. Implement the smallest compatible Rust
   change across all affected surfaces. Preserve native APIs unless upstream
   wire, configuration, or RPC compatibility requires an observable change.
6. Run the focused test, the complete test suite for every changed crate, code
   formatting, and warning-free host lint. Run Python/Rust interoperability
   when wire encoding or externally visible protocol behavior changes. If an
   exact upstream checkout is required for that test, create a disposable
   worktree under `/tmp` at the reviewed commit instead of moving the accepted
   checkout.
7. Commit the code, focused tests, and any commit-local documentation as the
   sole rns-rs mapping for that upstream commit. Then update the audit entry
   with the resulting local hash, final disposition, exact test results, and
   any deliberate caveat. The audit update may be a separate summary commit,
   but it must not carry an `Upstream-Commit` trailer. Do not record planned
   tests as passed evidence.
8. Verify the mapping before continuing: the working tree must be clean, the
   new local commit must carry the exact `Upstream-Commit` trailer, and no other
   local commit may carry that upstream hash.
9. Re-run the drift checker after each commit. Continue with the next commit
   only after the current behavior and evidence are understood. Promote
   `UPSTREAM.md` only after every commit has a final disposition and all parity
   gates in the parity template have passed.

Benchmark-only upstream commits receive the same complete diff review, but a
Python harness that constructs private implementation state is not itself a
runtime compatibility surface. Record its scenarios and any corresponding
native Criterion coverage in the audit. Port a scenario when it exposes a
protocol invariant or an accepted performance requirement; otherwise give the
commit a `Non-runtime` disposition with a non-empty local policy or evidence
mapping instead of translating implementation-specific benchmark machinery.
Patch-equivalent commits reached through different upstream merge parents still
receive separate ordered mappings: record the identical tree effect and explain
why the later lineage adds no independent runtime behavior.
Pasted benchmark results are observational context, not acceptance thresholds,
unless the audit also fixes the hardware, build profile, workload, warm-up and
sampling method, and an explicit regression budget.
Comment-only benchmark result archives need not be copied into native harness
source; summarize their provenance and relevance in the audit instead.
When comparing upstream and native benchmark results, feature labels such as
`fast path` must identify behaviorally equivalent implementations or settings;
matching label text alone is not comparability evidence.
Formatting-only upstream cleanups are non-runtime mappings: inspect the full
diff for hidden control-flow changes, then record the source-only result instead
of manufacturing a Rust code change.
Likewise, removing stale TODOs or comments without changing executable lines is
source hygiene, not evidence that an equivalent native behavior changed.

Useful inspection commands, where `UPSTREAM_REPO` is the first active line from
`.local/reticulum-upstream.path`:

```bash
git -C "$UPSTREAM_REPO" log --reverse --format='%H %s' <baseline>..<target>
git -C "$UPSTREAM_REPO" show --stat --oneline <commit>
git -C "$UPSTREAM_REPO" show --no-ext-diff <commit> -- <changed-paths>
rg -n '<symbol-or-field>' rns-* docs scripts
```

Before moving to the next commit, the audit should answer four questions:

- What observable behavior changed upstream?
- Where is the equivalent Rust behavior, or why is there no equivalent?
- What code or invariant supplies compatibility?
- What focused evidence demonstrates the disposition?

The history should also satisfy this one-to-one check:

```bash
git log --format='%H%n%(trailers:key=Upstream-Commit,valueonly)' <range>
```

Each reviewed upstream hash must appear exactly once, and each corresponding
rns-rs commit must contain exactly one `Upstream-Commit` trailer.

## Records

| Version | Audit | Final parity record |
|---|---|---|
| 1.3.8 | Not retained | [Parity](reticulum-1.3.8-parity.md) |
| 1.3.9 | Not retained | [Parity](reticulum-1.3.9-parity.md) |
| 1.4.0 | [Audit](reticulum-1.4.0-audit.md) | [Parity](reticulum-1.4.0-parity.md) |
| 1.4.1 | [Audit](reticulum-1.4.1-audit.md) | [Parity](reticulum-1.4.1-parity.md) |
| 1.4.2 | [Audit](reticulum-1.4.2-audit.md) | [Parity](reticulum-1.4.2-parity.md) |
| 1.4.2 rgit `4fc8e03d` | [Audit](reticulum-1.4.2-rgit-audit.md) | [Parity](reticulum-1.4.2-rgit-parity.md) |
