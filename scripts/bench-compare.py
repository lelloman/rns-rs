#!/usr/bin/env python3
"""Compare `scripts/bench run` results against a baseline taken twice.

    scripts/bench-compare.py BASE_RUN_A BASE_RUN_B CURRENT_RUN [CURRENT_RUN ...]

Each case (repetitions pooled) is summarised as median and p95 latency, CPU
time per operation (all participants, user + system) and the participants'
peak RSS. Lower is better for every metric. The allowed band for a metric is
the larger of 3 % and twice the relative gap between the two baseline runs,
so a noisy case gets a wider band than a steady one. A current value above
baseline + band is a regression; the script exits 1 if there is any.
Comparing several current runs pools them first, which steadies the check.
"""

import json
import re
import statistics
import sys
from pathlib import Path

FLOOR = 0.03


def load(run_dirs):
    cases = {}
    for run in run_dirs:
        for result in sorted(Path(run).glob("*/result.json")):
            data = json.loads(result.read_text())
            if data.get("status") != "valid":
                raise SystemExit(f"{result}: status {data.get('status')}")
            case = re.sub(r"-r\d+$", "", data["case"]["id"])
            entry = cases.setdefault(case, {"lat": [], "cpu": [], "ops": 0, "rss": []})
            entry["lat"].extend(data["latency_ns"])
            entry["ops"] += len(data["latency_ns"])
            for side in ("sender", "receiver", "relay"):
                before, after = data.get(f"{side}_before"), data.get(f"{side}_after")
                if not before or not after:
                    continue
                entry["cpu"].append(
                    after["user_cpu_seconds"] + after["system_cpu_seconds"]
                    - before["user_cpu_seconds"] - before["system_cpu_seconds"])
                if after.get("lifetime_peak_rss_bytes"):
                    entry["rss"].append(after["lifetime_peak_rss_bytes"])
    return {case: summarise(e) for case, e in cases.items()}


def summarise(entry):
    lat = sorted(entry["lat"])
    return {
        "p50_ms": statistics.median(lat) / 1e6,
        "p95_ms": lat[min(len(lat) - 1, int(0.95 * len(lat)))] / 1e6,
        "cpu_ms_per_op": 1e3 * sum(entry["cpu"]) / max(1, entry["ops"]),
        "peak_rss_mb": max(entry["rss"], default=0) / 2**20,
    }


def main():
    if len(sys.argv) < 4:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    base_a, base_b = load([sys.argv[1]]), load([sys.argv[2]])
    current = load(sys.argv[3:])
    regressions = 0
    header = f"{'case':58} {'metric':14} {'base':>10} {'current':>10} {'delta':>8} {'band':>7}"
    print(header)
    for case in sorted(set(base_a) | set(current)):
        if case not in current:
            print(f"{case:58} missing from the current run")
            regressions += 1
            continue
        if case not in base_a or case not in base_b:
            print(f"{case:58} new case, not gated")
            continue
        for metric in ("p50_ms", "p95_ms", "cpu_ms_per_op", "peak_rss_mb"):
            a, b, now = base_a[case][metric], base_b[case][metric], current[case][metric]
            base = (a + b) / 2
            if base <= 0:
                continue
            band = max(FLOOR, 2 * abs(a - b) / base)
            delta = now / base - 1
            verdict = "REGRESSION" if delta > band else ""
            regressions += bool(verdict)
            print(f"{case:58} {metric:14} {base:10.3f} {now:10.3f} "
                  f"{100 * delta:+7.1f}% {100 * band:6.1f}% {verdict}")
    print("FAIL" if regressions else "PASS")
    return 1 if regressions else 0


if __name__ == "__main__":
    sys.exit(main())
