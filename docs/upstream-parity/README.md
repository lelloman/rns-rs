# Upstream Reticulum Parity

This directory contains the audit trail and final acceptance record for each
Reticulum baseline adopted by rns-rs.

## Naming Convention

Each upstream version can have two documents with stable, date-independent
filenames:

- `reticulum-X.Y.Z-audit.md` — the commit-by-commit audit and integration work
  record created before baseline promotion.
- `reticulum-X.Y.Z-parity.md` — the concise, final acceptance record created
  when the baseline is promoted.

Dates, commit hashes, repository tips, and local branch revisions belong inside
the documents instead of their filenames. Historical versions without a saved
working audit can have only a parity record.

## Workflow

1. Copy [AUDIT-TEMPLATE.md](AUDIT-TEMPLATE.md) to the next versioned audit
   filename.
2. Pin the previous baseline, target commit or tag, tree hashes, version
   assertion, repositories, and audit date before reviewing code.
3. Inventory every upstream commit exactly once and give it an explicit final
   disposition. Record local commits and focused test evidence as work lands.
4. Complete the promotion gates without rewriting failures or deferred manual
   checks as passes.
5. Copy [PARITY-TEMPLATE.md](PARITY-TEMPLATE.md) to the versioned parity
   filename and summarize the final compatibility evidence, acceptance results,
   and caveats.
6. Promote `UPSTREAM.md` only after the parity record is complete. Link the
   parity record as the acceptance authority and the audit as detailed evidence.

Never edit an old audit to make its point-in-time pre-integration findings look
final. The corresponding parity record records the final outcome.

## Records

| Version | Audit | Final parity record |
|---|---|---|
| 1.3.8 | Not retained | [Parity](reticulum-1.3.8-parity.md) |
| 1.3.9 | Not retained | [Parity](reticulum-1.3.9-parity.md) |
| 1.4.0 | [Audit](reticulum-1.4.0-audit.md) | [Parity](reticulum-1.4.0-parity.md) |
| 1.4.1 | [Audit](reticulum-1.4.1-audit.md) | [Parity](reticulum-1.4.1-parity.md) |
