#!/usr/bin/env python3
"""Run the host-safe Clippy command and enforce a per-crate lint baseline."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_BASELINE = ROOT / "tools" / "clippy-warning-baseline.json"
COMMAND = [
    "cargo", "clippy", "--workspace", "--all-targets", "--features", "rns-hooks",
    "--message-format=json", "--", "-A", "clippy::approx_constant", "-A",
    "clippy::never_loop",
]


def parse_diagnostics(lines: list[str]) -> tuple[dict[str, dict[str, int]], list[str]]:
    counts: dict[str, dict[str, int]] = {}
    rendered: list[str] = []
    for line in lines:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("reason") != "compiler-message":
            continue
        message = item.get("message", {})
        if message.get("level") != "warning":
            continue
        code = (message.get("code") or {}).get("code") or "rustc::unknown"
        manifest_path = item.get("manifest_path")
        package_id = str(item.get("package_id") or "unknown")
        if manifest_path:
            crate = pathlib.Path(manifest_path).parent.name
        elif "@" in package_id.rsplit("#", 1)[-1]:
            crate = package_id.rsplit("#", 1)[1].split("@", 1)[0]
        else:
            crate = package_id.split()[0]
        lint_counts = counts.setdefault(crate, {})
        lint_counts[code] = lint_counts.get(code, 0) + 1
        if message.get("rendered"):
            rendered.append(message["rendered"].rstrip())
    normalized = {
        crate: {lint: lints[lint] for lint in sorted(lints)}
        for crate, lints in sorted(counts.items())
    }
    return normalized, rendered


def regressions(
    baseline: dict[str, dict[str, int]], current: dict[str, dict[str, int]]
) -> list[str]:
    failures = []
    for crate, lints in current.items():
        for lint, count in lints.items():
            allowed = baseline.get(crate, {}).get(lint, 0)
            if count > allowed:
                failures.append(f"{crate} {lint}: {count} > {allowed}")
    return failures


def write_baseline(path: pathlib.Path, counts: dict[str, dict[str, int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(counts, indent=2, sort_keys=True) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default=str(DEFAULT_BASELINE))
    parser.add_argument("--update-baseline", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    proc = subprocess.run(COMMAND, cwd=ROOT, text=True, capture_output=True)
    counts, rendered = parse_diagnostics(proc.stdout.splitlines())
    for diagnostic in rendered:
        print(diagnostic, file=sys.stderr)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr, end="")
    if proc.returncode:
        return proc.returncode
    path = pathlib.Path(args.baseline)
    if args.update_baseline:
        write_baseline(path, counts)
        print(f"updated Clippy warning baseline: {path}")
        return 0
    if not path.is_file():
        print(f"missing Clippy warning baseline: {path}", file=sys.stderr)
        return 1
    baseline = json.loads(path.read_text())
    failures = regressions(baseline, counts)
    if failures:
        print("Clippy warning ratchet failed:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    old_total = sum(sum(lints.values()) for lints in baseline.values())
    new_total = sum(sum(lints.values()) for lints in counts.values())
    print(f"Clippy warnings: {new_total} (baseline {old_total})")
    if new_total < old_total:
        print("Warning count decreased; run --update-baseline to ratchet it down.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
