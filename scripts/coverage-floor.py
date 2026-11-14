#!/usr/bin/env python3
"""Fail when a crate's line coverage drops below its floor.

Reads `cargo llvm-cov report --summary-only` on stdin, sums line coverage
per crate (the path's first component) and compares it with FLOORS. Raise a
floor when coverage rises; never lower one to make a run pass.

    cargo llvm-cov -p rns-core -p rns-net --lib --summary-only \
        | python3 scripts/coverage-floor.py
"""

import sys

# Line coverage of the unit tests (`--lib`), percent. Measured 2026-11-14:
# rns-core 95.80, rns-net 79.70, rns-crypto 82.85.
FLOORS = {
    "rns-core": 95.5,
    "rns-net": 79.5,
    "rns-crypto": 82.5,
}


def main() -> int:
    totals = {}
    for line in sys.stdin:
        fields = line.split()
        if len(fields) < 10 or not fields[0].endswith(".rs") or "/" not in fields[0]:
            continue
        crate = fields[0].split("/")[0]
        try:
            lines, missed = int(fields[7]), int(fields[8])
        except ValueError:
            continue
        total = totals.setdefault(crate, [0, 0])
        total[0] += lines
        total[1] += missed

    failed = False
    for crate, floor in FLOORS.items():
        if crate not in totals:
            print(f"{crate}: no coverage data")
            failed = True
            continue
        lines, missed = totals[crate]
        percent = 100.0 * (lines - missed) / lines if lines else 0.0
        status = "ok" if percent >= floor else "BELOW FLOOR"
        print(f"{crate}: {percent:.2f}% of {lines} lines (floor {floor}%) {status}")
        failed |= percent < floor
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
