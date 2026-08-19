#!/usr/bin/env python3
"""Compare the accepted Reticulum baseline with both upstream remote tips."""

from __future__ import annotations

import argparse
import datetime
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


def utc_now() -> str:
    return datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat()


def fetch_with_retry(repo: pathlib.Path, remote: str) -> dict[str, object]:
    attempted_at = utc_now()
    failures: list[str] = []
    for attempt in range(1, 3):
        proc = subprocess.run(
            ["git", "-C", str(repo), "fetch", remote],
            text=True,
            capture_output=True,
        )
        if proc.returncode == 0:
            return {
                "status": "succeeded",
                "attempts": attempt,
                "attempted_at_utc": attempted_at,
                "completed_at_utc": utc_now(),
                "error": None,
            }
        failures.append(proc.stderr.strip() or proc.stdout.strip())
    return {
        "status": "failed",
        "attempts": 2,
        "attempted_at_utc": attempted_at,
        "completed_at_utc": utc_now(),
        "error": failures[-1],
    }


def skipped_fetch() -> dict[str, object]:
    return {
        "status": "skipped",
        "attempts": 0,
        "attempted_at_utc": None,
        "completed_at_utc": None,
        "error": None,
    }


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
        "inspection_error": None,
    }


def inspect_remote_safely(
    repo: pathlib.Path,
    remote: str,
    baseline: str,
    fetch: dict[str, object],
) -> dict[str, object]:
    try:
        result = inspect_remote(repo, remote, baseline)
    except DriftError as exc:
        result = {
            "remote": remote,
            "ref": f"{remote}/master",
            "tip": None,
            "relation": "unknown",
            "commits_ahead": [],
            "inspection_error": str(exc),
        }
    result["fetch"] = fetch
    result["fresh"] = (
        fetch["status"] == "succeeded" and result["inspection_error"] is None
    )
    return result


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
    if args.no_fetch:
        github_fetch = skipped_fetch()
        rgit_fetch = skipped_fetch()
    else:
        # Refresh independently so an unavailable transport does not conceal the
        # other remote's current state.
        github_fetch = fetch_with_retry(repo, github_remote)
        rgit_fetch = fetch_with_retry(repo, rgit_remote)

    github = inspect_remote_safely(repo, github_remote, baseline, github_fetch)
    rgit = inspect_remote_safely(repo, rgit_remote, baseline, rgit_fetch)
    union: dict[str, dict[str, str]] = {}
    for item in [*github["commits_ahead"], *rgit["commits_ahead"]]:
        union[item["commit"]] = item
    commits = [union[key] for key in sorted(union)]
    relations = {github["relation"], rgit["relation"]}
    comparison_status = "drift" if commits or "diverged" in relations else (
        "behind" if "behind" in relations else "current"
    )
    incomplete_reasons = []
    for label, remote in (("GitHub", github), ("rgit", rgit)):
        fetch = remote["fetch"]
        if fetch["status"] == "failed":
            incomplete_reasons.append(f"{label} fetch failed: {fetch['error']}")
        if remote["inspection_error"] is not None:
            incomplete_reasons.append(
                f"{label} inspection failed: {remote['inspection_error']}"
            )
    status = "incomplete" if incomplete_reasons else comparison_status
    if args.no_fetch:
        freshness = "cached"
    elif incomplete_reasons:
        freshness = "incomplete"
    else:
        freshness = "fresh"
    audit = ROOT / ACTIVE_AUDIT
    return {
        "status": status,
        "comparison_status": comparison_status,
        "freshness": freshness,
        "incomplete_reasons": incomplete_reasons,
        "baseline": baseline,
        "upstream_dir": str(repo),
        "github": github,
        "rgit": rgit,
        "commits": commits,
        "commits_ahead": len(commits),
        "remotes_agree": (
            github["tip"] is not None and github["tip"] == rgit["tip"]
        ),
        "fetched": freshness == "fresh",
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
    print(f"Comparison from available refs: {result['comparison_status']}")
    print(f"Data freshness: {result['freshness']}")
    print(f"Accepted baseline: {result['baseline']}")
    for label, remote in (("GitHub", result["github"]), ("rgit", result["rgit"])):
        tip = remote["tip"] or "unavailable"
        fetch = remote["fetch"]
        tip_freshness = "fresh" if remote["fresh"] else "cached"
        print(f"{label} tip: {tip} ({remote['relation']}; {tip_freshness})")
        if fetch["status"] == "succeeded":
            print(
                f"{label} fetch: succeeded at {fetch['completed_at_utc']} "
                f"({fetch['attempts']} attempt(s))"
            )
        elif fetch["status"] == "failed":
            print(
                f"{label} fetch: FAILED at {fetch['completed_at_utc']} "
                f"after {fetch['attempts']} attempts: {fetch['error']}"
            )
        else:
            print(f"{label} fetch: skipped (--no-fetch; tip is cached)")
        if remote["inspection_error"] is not None:
            print(f"{label} inspection: FAILED: {remote['inspection_error']}")
    print(f"Commits ahead: {result['commits_ahead']}")
    for item in result["commits"]:
        print(f"  {item['commit']} {item['subject']}")
    if result["comparison_status"] == "drift" or result["active_audit_exists"]:
        suffix = "exists" if result["active_audit_exists"] else "required"
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
    if result["status"] == "incomplete":
        return 1
    return 2 if args.fail_on_drift and result["comparison_status"] == "drift" else 0


if __name__ == "__main__":
    raise SystemExit(main())
