# Reticulum 1.4.2 rgit Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.4.2` signed release |
| Previous normative commit | `b48b96e61676504e0a4e527b33b9a0b4495c6872` |
| Accepted version | `1.4.2` rgit |
| Normative tag or ref | `rgit/master` at promotion time |
| Normative commit | `4fc8e03d658ed87019b8ad6c7ce7827dc76f0e45` |
| Root tree | `866e71c8a6b3b2196476467d7aeede3f509d7fed` |
| `RNS` tree | `8edc9d52943aa465c8f4e23debaaa9224c74eeb2` |
| Version assertion | `RNS.__version__ == "1.4.2"` |
| Audited range | `b48b96e61676504e0a4e527b33b9a0b4495c6872..4fc8e03d658ed87019b8ad6c7ce7827dc76f0e45` |
| Commits audited | 1 |
| Acceptance date | `2026-08-11` |
| Detailed audit | [reticulum-1.4.2-rgit-audit.md](reticulum-1.4.2-rgit-audit.md) |

The accepted commit is one commit after the signed `1.4.2` tag while retaining
the same upstream version assertion. At acceptance, normative rgit `master`
pointed to the commit and GitHub `master` remained at the signed-release target;
a clean GitHub clone could not fetch the accepted object by exact SHA. Historical
fixture provenance remains unchanged because this delta only affects `rnstatus`
output.

## Upstream Commit Audit

| Area | Upstream commits | Final handling |
|---|---|---|
| Interface status utility | `4fc8e03d` | Integrated: `rnstatus -b/--blocked-ips` conditionally renders the compatible `blocked_ip_list` interface-stat field. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | No wire or cryptographic behavior changed; historical fixtures retain their recorded provenance. |
| Transport and interfaces | Existing blocked-list driver, Backbone and RPC regressions cover sorted current statistics. |
| Links, channels and resources | Exact-target bidirectional Python/Rust TCP packet interoperability passed. |
| Utilities and APIs | Focused argument and rendering regressions passed; all five ignored `rncp`/`rnx` Python/Rust utility interoperability tests passed. |
| Live interop | Reticulum commit `4fc8e03d` and `RNS` tree `8edc9d52` passed locally on 2026-08-11. |

## Acceptance Record

| Gate | Result |
|---|---|
| Commit disposition | The single upstream commit is integrated with local implementation evidence. |
| Focused regression suites | Passed locally on 2026-08-11. |
| Fixture regeneration/provenance | Not applicable to this CLI-only delta; existing provenance was retained. |
| Exact-target Python/Rust interop | Packet and utility interoperability passed locally on 2026-08-11 against `4fc8e03d`. |
| Workspace and feature suites | Workspace tests passed locally; PR CI remains the clean-environment feature-suite authority and exercises the fetchable signed-release interop target until the mirror advances. |
| Formatting and lint | `cargo fmt --check` and host lint passed locally. |
| Release/cross builds | Not rerun for this CLI-only advancement. |
| Docker E2E | Not rerun and not claimed. |
| Hardware/manual validation | Physical Weave HIL was not rerun; healthy dual-VPS daily smoke results from 2026-08-08 are recorded in the detailed audit. |

## Caveats and Deferred Validation

- GitHub `master` had not advanced from the signed-release target at acceptance,
  and a clean GitHub clone could not fetch the accepted commit by exact SHA. CI
  therefore remains pinned to the signed-release interop target; exact rgit-tip
  interop was validated locally from the normative checkout.
- Docker E2E, cross-compilation and physical Weave HIL were not rerun.
- Generated upstream documentation is not vendored.

## Promotion Result

Reticulum 1.4.2 rgit is accepted as the rns-rs upstream reference baseline at
normative commit `4fc8e03d658ed87019b8ad6c7ce7827dc76f0e45`.
[UPSTREAM.md](../../UPSTREAM.md) records the promoted baseline and exact tree
provenance.
