#!/usr/bin/env python3
"""Compare the accepted Reticulum baseline with both upstream remote tips."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
BASELINE_RE = re.compile(r"^- Normative commit: `([0-9a-f]{40})`$", re.MULTILINE)
ACTIVE_AUDIT = "docs/upstream-parity/reticulum-next-audit.md"


class DriftError(RuntimeError):
    pass


def git(repo: pathlib.Path, *args: str, check: bool = True) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], text=True, capture_output=True
    )
    if check and proc.returncode:
        detail = proc.stderr.strip() or proc.stdout.strip()
        raise DriftError(f"git {' '.join(args)} failed: {detail}")
    return proc.stdout.strip()


def configured_upstream(explicit: str | None) -> pathlib.Path:
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    elif os.environ.get("RETICULUM_UPSTREAM_DIR"):
        candidates.append(os.environ["RETICULUM_UPSTREAM_DIR"])
    else:
        config = ROOT / ".local" / "reticulum-upstream.path"
        if config.is_file():
            candidates.extend(
                line.strip()
                for line in config.read_text().splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            )
    for candidate in candidates:
        path = pathlib.Path(candidate).expanduser().resolve()
        if path.is_dir() and (path / ".git").exists():
            return path
    raise DriftError("no usable Reticulum checkout configured")


def accepted_baseline(override: str | None) -> str:
    if override:
        baseline = override
    else:
        match = BASELINE_RE.search((ROOT / "UPSTREAM.md").read_text())
        if not match:
            raise DriftError("could not read Normative commit from UPSTREAM.md")
        baseline = match.group(1)
    if not re.fullmatch(r"[0-9a-fA-F]{40}", baseline):
        raise DriftError("baseline must be a full 40-character commit hash")
    return baseline.lower()


def fetch_with_retry(repo: pathlib.Path, remote: str) -> None:
    failures: list[str] = []
    for _ in range(2):
        proc = subprocess.run(
            ["git", "-C", str(repo), "fetch", remote],
            text=True,
            capture_output=True,
        )
        if proc.returncode == 0:
            return
        failures.append(proc.stderr.strip() or proc.stdout.strip())
    raise DriftError(f"fetch {remote} failed twice: {failures[-1]}")


def is_ancestor(repo: pathlib.Path, older: str, newer: str) -> bool:
    return (
        subprocess.run(
            ["git", "-C", str(repo), "merge-base", "--is-ancestor", older, newer],
            capture_output=True,
        ).returncode
        == 0
    )


def inspect_remote(repo: pathlib.Path, remote: str, baseline: str) -> dict[str, object]:
    ref = f"refs/remotes/{remote}/master"
    try:
        tip = git(repo, "rev-parse", "--verify", ref)
    except DriftError as exc:
        raise DriftError(f"missing remote tracking ref {remote}/master") from exc
    if tip == baseline:
        relation = "at_baseline"
    elif is_ancestor(repo, tip, baseline):
        relation = "behind"
    elif is_ancestor(repo, baseline, tip):
        relation = "ahead"
    else:
        relation = "diverged"
    raw = git(repo, "log", "--format=%H%x09%s", tip, f"^{baseline}")
    commits = []
    for line in raw.splitlines():
        commit, subject = line.split("\t", 1)
        commits.append({"commit": commit, "subject": subject})
    return {
        "remote": remote,
        "ref": f"{remote}/master",
        "tip": tip,
        "relation": relation,
        "commits_ahead": commits,
    }


def check(args: argparse.Namespace) -> dict[str, object]:
    repo = configured_upstream(args.upstream_dir)
    baseline = accepted_baseline(args.baseline)
    try:
        head = git(repo, "rev-parse", "HEAD")
        git(repo, "cat-file", "-e", f"{baseline}^{{commit}}")
    except DriftError as exc:
        raise DriftError(f"accepted baseline is unavailable in {repo}") from exc
    if head != baseline:
        raise DriftError(f"checkout HEAD {head} does not equal accepted baseline {baseline}")

    github_remote = os.environ.get("RETICULUM_GITHUB_REMOTE", "origin")
    rgit_remote = os.environ.get("RETICULUM_RGIT_REMOTE", "rgit")
    if not args.no_fetch:
        fetch_with_retry(repo, github_remote)
        fetch_with_retry(repo, rgit_remote)

    github = inspect_remote(repo, github_remote, baseline)
    rgit = inspect_remote(repo, rgit_remote, baseline)
    union: dict[str, dict[str, str]] = {}
    for item in [*github["commits_ahead"], *rgit["commits_ahead"]]:
        union[item["commit"]] = item
    commits = [union[key] for key in sorted(union)]
    relations = {github["relation"], rgit["relation"]}
    status = "drift" if commits or "diverged" in relations else (
        "behind" if "behind" in relations else "current"
    )
    audit = ROOT / ACTIVE_AUDIT
    return {
        "status": status,
        "baseline": baseline,
        "upstream_dir": str(repo),
        "github": github,
        "rgit": rgit,
        "commits": commits,
        "commits_ahead": len(commits),
        "remotes_agree": github["tip"] == rgit["tip"],
        "fetched": not args.no_fetch,
        "active_audit": ACTIVE_AUDIT,
        "active_audit_exists": audit.is_file(),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream-dir")
    parser.add_argument("--baseline")
    parser.add_argument("--no-fetch", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--fail-on-drift", action="store_true")
    return parser.parse_args()


def render_human(result: dict[str, object]) -> None:
    print(f"Upstream parity: {result['status']}")
    print(f"Accepted baseline: {result['baseline']}")
    print(f"GitHub tip: {result['github']['tip']} ({result['github']['relation']})")
    print(f"rgit tip: {result['rgit']['tip']} ({result['rgit']['relation']})")
    print(f"Commits ahead: {result['commits_ahead']}")
    for item in result["commits"]:
        print(f"  {item['commit']} {item['subject']}")
    suffix = "exists" if result["active_audit_exists"] else "required when drift exists"
    print(f"Active audit: {result['active_audit']} ({suffix})")


def main() -> int:
    args = parse_args()
    try:
        result = check(args)
    except DriftError as exc:
        if args.json:
            print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        render_human(result)
    return 2 if args.fail_on_drift and result["status"] == "drift" else 0


if __name__ == "__main__":
    raise SystemExit(main())
