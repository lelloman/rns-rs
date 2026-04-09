# VPS Report Archive

This directory contains packaged archive artifacts for historical VPS report
documents.

Current artifacts:

- `index.json`
  manifest for the latest generated zip bundle
- `vps-reports-YYYYMMDD.zip`
  archive bundle containing tracked historical VPS report documents

The archive bundle is a convenience export. The tracked Markdown documents in
`docs/` remain the primary source of truth, and the normalized daily snapshot
DB under `data/` is the canonical queryable history for future checks.
