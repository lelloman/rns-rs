# Reticulum X.Y.Z Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `X.Y.Z` |
| Previous normative commit | `<40-character commit>` |
| Accepted version | `X.Y.Z` |
| Normative tag or ref | `<tag-or-ref>` |
| Normative commit | `<40-character commit>` |
| Root tree | `<40-character tree>` |
| `RNS` tree | `<40-character tree>` |
| Version assertion | `RNS.__version__ == "X.Y.Z"` |
| Audited range | `<previous-commit>..<target-commit>` |
| Acceptance date | `YYYY-MM-DD` |
| Detailed audit | `reticulum-X.Y.Z-audit.md` |

Explain tag-versus-tip distinctions and fixture provenance immediately below
the table.

## Upstream Commit Audit

Summarize the completed audit. Every commit must have a disposition in the
detailed audit; this final record may group related commits by subsystem.

| Area | Upstream commits | Final handling |
|---|---|---|
| `<subsystem>` | `<commits>` | `<integrated/covered/deferred rationale>` |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | `<fixtures/tests>` |
| Transport and interfaces | `<focused tests>` |
| Links, channels, and resources | `<focused tests>` |
| Utilities and APIs | `<focused tests/documentation>` |
| Live interop | `<exact target and result>` |

## Acceptance Record

| Gate | Result |
|---|---|
| Focused regression suites | `<result and date>` |
| Fixture regeneration/provenance | `<result or not applicable>` |
| Exact-target Python/Rust interop | `<result and date>` |
| Workspace and feature suites | `<result and authority>` |
| Formatting and lint | `<result and authority>` |
| Release/cross builds | `<result and authority>` |
| Docker E2E | `<result and authority>` |
| Hardware/manual validation | `<result, waiver, or explicitly unclaimed>` |

## Caveats and Deferred Validation

List every accepted divergence, deferred item, hardware gap, manual follow-up,
or validation explicitly not claimed by this promotion. Write `None` only when
the detailed audit supports that conclusion.

## Promotion Result

State whether the baseline was accepted, identify the exact normative commit,
and link the corresponding update in `UPSTREAM.md`.
