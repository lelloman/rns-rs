# Upstream Reticulum Tracking

This file tracks the version of [Python Reticulum](https://github.com/markqvist/Reticulum)
that rns-rs is validated against. When the upstream project advances, compare against
this baseline to identify what needs to be integrated.

## Current Baseline

| Field              | Value                                      |
|--------------------|--------------------------------------------|
| **Upstream repo**  | https://github.com/markqvist/Reticulum     |
| **Release**        | 1.1.3                                      |
| **Release commit** | `286a78ef8c58ca4503af2b0211b3a2d7e385467c` |
| **Latest commit**  | `1bee46ed814e671d268801958bb2aa4746e4ed5e`  |
| **Commit date**    | 2026-01-25                                 |
| **Commit message** | Updated readme                             |
| **Verified date**  | 2026-02-18                                 |

## How to Update

1. Check the latest upstream commit:
   ```bash
   curl -s https://api.github.com/repos/markqvist/Reticulum/commits/master \
     | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'{d[\"sha\"]} {d[\"commit\"][\"committer\"][\"date\"]} {d[\"commit\"][\"message\"][:80]}')"
   ```

2. Compare changes since our baseline:
   ```bash
   # In your local Reticulum clone with markqvist remote added
   git log --oneline 1bee46ed..markqvist/master
   ```

3. After integrating and validating, update the table above.
