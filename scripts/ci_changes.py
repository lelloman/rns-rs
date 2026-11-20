#!/usr/bin/env python3
"""Decide which CI jobs a change needs to run.

Reads the files a pull request changes, maps them to workspace crates, and
expands that set through the workspace's path-dependency graph: a change to a
crate affects every crate that depends on it, through normal, build, dev and
optional dependencies alike. Each heavy job in .github/workflows/ci.yml runs
when the change reaches a crate it builds or one of its other inputs.

Paths that are not part of a crate follow the rules in classify(). A path no
rule knows runs everything: when in doubt, the job runs.

The result is printed as `key=value` lines, the format of $GITHUB_OUTPUT, and
appended to the files given with --github-output and --summary.
"""

from __future__ import annotations

import argparse
import fnmatch
import pathlib
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field


ROOT = pathlib.Path(__file__).resolve().parent.parent

# Paths that change how every job builds or what it runs.
FULL_RUN = {
    ".github/workflows/ci.yml",
    "scripts/ci_changes.py",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
}
FULL_RUN_PREFIXES = (".cargo/",)

# Files outside a crate's directory that the crate's code or tests read
# (include_str!, fixture paths). tests/test_ci_changes.py checks that every
# such reference in the workspace is covered here.
EXTERNAL_INPUTS = {
    "docs/interface-discovery.md": ("rns-net",),
}
EXTERNAL_INPUT_PREFIXES = {
    # Shared conformance, crypto, CLI and transport fixtures.
    "tests/fixtures/": ("rns-crypto", "rns-core", "rns-net", "rns-cli", "rns-bench"),
    # Benchmark scenarios and profiles, embedded by rns-bench's tests.
    "bench/": ("rns-bench",),
}

# Paths that only the always-on jobs (Rustfmt, Clippy, Python Tools,
# Upstream Badge) look at, or that other workflows own.
NO_HEAVY_JOB_PREFIXES = (
    "docs/",
    "fuzz/",  # fuzz.yml
    ".github/",  # other workflows and dependabot; ci.yml is a full run
    "scripts/",  # Python Tools and Clippy (lint-host.sh)
    "tools/vps-history-dashboard/",  # Python Tools
)
NO_HEAVY_JOB_FILES = {"LICENSE", ".gitignore", "deny.toml"}
# Python tools and fixture generators directly under tests/.
NO_HEAVY_JOB_GLOBS = ("tests/*.py",)

# Jobs gated on paths of their own, in addition to any crates.
JOB_PATH_PREFIXES = {
    "docker": ("tests/docker/",),
    "esp32": ("rns-esp32/", "vendor/"),
    "web_smoke": ("rns-ctl/assets/",),
}

# Crates whose own change runs a job (no dependency expansion).
JOB_DIRECT_CRATES: dict[str, tuple[str, ...]] = {}

# Crates a job builds or tests; the job runs when any crate they depend on,
# transitively, changes.
JOB_ROOT_CRATES = {
    # The Android client builds rns-tun-android through cargo-ndk.
    "android": ("rns-tun-android",),
    # cargo test --workspace --features rns-hooks plus the e2e_hooks and
    # rns-ctl built-in hook tests: every crate with hook code behind a
    # feature, and the hook crates themselves.
    "hooks": (
        "rns-hooks",
        "rns-hooks-abi",
        "rns-hooks-sdk",
        "rns-sentinel-hook",
        "rns-stats-hook",
        "rns-net",
        "rns-cli",
        "rns-ctl",
        "rns-server",
    ),
    # python_interop, utility_interop, placeholders, rnodeconf and rns-git's
    # Python-peer tests.
    "interop": ("rns-net", "rns-cli", "rns-rnodeconf", "rns-git"),
    # tests/docker/Dockerfile and rns-server/Dockerfile.rns-server.
    "docker": ("rns-ctl", "rns-cli", "rns-tun", "rns-server"),
    "armv7": ("rns-cli", "rns-ctl", "rns-server"),
    "ctl_tls": ("rns-ctl",),
}

JOBS = (
    "android",
    "hooks",
    "interop",
    "docker",
    "armv7",
    "ctl_tls",
    "esp32",
    "esp32_lint",
    "web_smoke",
)

DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


class SelectorError(RuntimeError):
    pass


@dataclass
class Workspace:
    root: pathlib.Path
    # crate name -> directory relative to root, posix style ("" never used).
    dirs: dict[str, str]
    # crate name -> crate names it depends on through path dependencies.
    deps: dict[str, set[str]]
    # Crates the excluded rns-esp32 firmware depends on by path.
    esp32_deps: set[str] = field(default_factory=set)

    def crate_for(self, path: str) -> str | None:
        best = None
        for name, directory in self.dirs.items():
            if path.startswith(directory + "/"):
                if best is None or len(directory) > len(self.dirs[best]):
                    best = name
        return best

    def dependents(self, crates: set[str]) -> set[str]:
        reverse: dict[str, set[str]] = {name: set() for name in self.dirs}
        for name, deps in self.deps.items():
            for dep in deps:
                reverse.setdefault(dep, set()).add(name)
        return _closure(crates, reverse)

    def dependencies(self, crates: set[str]) -> set[str]:
        return _closure(crates, self.deps)


def _closure(start: set[str], edges: dict[str, set[str]]) -> set[str]:
    seen = set(start)
    stack = list(start)
    while stack:
        for nxt in edges.get(stack.pop(), ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def _load_toml(path: pathlib.Path) -> dict:
    with path.open("rb") as fh:
        return tomllib.load(fh)


def _dep_tables(manifest: dict):
    for table in DEP_TABLES:
        yield manifest.get(table, {})
    for target in manifest.get("target", {}).values():
        for table in DEP_TABLES:
            yield target.get(table, {})


def _path_deps(
    manifest_path: pathlib.Path, manifest: dict, ws_deps: dict, root: pathlib.Path
) -> set[pathlib.Path]:
    """Directories of every path dependency a manifest declares."""
    out = set()
    for table in _dep_tables(manifest):
        for key, spec in table.items():
            if not isinstance(spec, dict):
                continue
            if spec.get("workspace") is True:
                ws_spec = ws_deps.get(key)
                if isinstance(ws_spec, dict) and "path" in ws_spec:
                    out.add((root / ws_spec["path"]).resolve())
            elif "path" in spec:
                out.add((manifest_path.parent / spec["path"]).resolve())
    return out


def load_workspace(root: pathlib.Path = ROOT) -> Workspace:
    root = root.resolve()
    top = _load_toml(root / "Cargo.toml")
    ws = top["workspace"]
    ws_deps = ws.get("dependencies", {})
    excluded = [(root / e).resolve() for e in ws.get("exclude", [])]

    def is_excluded(directory: pathlib.Path) -> bool:
        return any(directory == e or e in directory.parents for e in excluded)

    member_dirs: list[pathlib.Path] = []
    for pattern in ws.get("members", []):
        matches = sorted(root.glob(pattern)) if any(c in pattern for c in "*?[") else [root / pattern]
        member_dirs.extend(m.resolve() for m in matches if (m / "Cargo.toml").is_file())

    # Path dependencies inside the workspace root are members too.
    dirs: dict[pathlib.Path, str] = {}
    raw_deps: dict[pathlib.Path, set[pathlib.Path]] = {}
    queue = list(member_dirs)
    while queue:
        directory = queue.pop()
        if directory in dirs:
            continue
        manifest_path = directory / "Cargo.toml"
        manifest = _load_toml(manifest_path)
        dirs[directory] = manifest["package"]["name"]
        raw_deps[directory] = _path_deps(manifest_path, manifest, ws_deps, root)
        for dep in raw_deps[directory]:
            if root in dep.parents and not is_excluded(dep) and dep not in dirs:
                queue.append(dep)

    rel = {name: d.relative_to(root).as_posix() for d, name in dirs.items()}
    deps = {
        dirs[d]: {dirs[p] for p in paths if p in dirs} for d, paths in raw_deps.items()
    }

    # Standalone manifests nested in a crate (the WASM hook examples, built
    # by build-examples.sh and loaded by rns-hooks' and rns-net's tests)
    # make that crate depend on what they depend on.
    member_paths = set(dirs)
    for manifest_path in sorted(root.glob("*/**/Cargo.toml")):
        directory = manifest_path.parent.resolve()
        if directory in member_paths or "target" in directory.relative_to(root).parts:
            continue
        owner_rel = directory.relative_to(root).as_posix()
        owner = None
        for name, d in rel.items():
            if owner_rel.startswith(d + "/") and (owner is None or len(d) > len(rel[owner])):
                owner = name
        if owner is None:
            continue
        nested = _load_toml(manifest_path)
        for dep in _path_deps(manifest_path, nested, {}, root):
            if dep in dirs:
                deps[owner].add(dirs[dep])

    esp32_deps: set[str] = set()
    esp32_manifest = root / "rns-esp32" / "Cargo.toml"
    if esp32_manifest.is_file():
        for dep in _path_deps(esp32_manifest, _load_toml(esp32_manifest), {}, root):
            if dep in dirs:
                esp32_deps.add(dirs[dep])
        esp32_deps = _closure(esp32_deps, deps)

    return Workspace(root=root, dirs=rel, deps=deps, esp32_deps=esp32_deps)


@dataclass
class PathEffect:
    full: bool = False
    crates: tuple[str, ...] = ()
    jobs: tuple[str, ...] = ()


def classify(path: str, ws: Workspace) -> PathEffect:
    """What a change to one repository path needs, before crate expansion."""
    if path in FULL_RUN or path.startswith(FULL_RUN_PREFIXES):
        return PathEffect(full=True)
    if path in EXTERNAL_INPUTS:
        return PathEffect(crates=EXTERNAL_INPUTS[path])
    for prefix, crates in EXTERNAL_INPUT_PREFIXES.items():
        if path.startswith(prefix) and not (prefix == "bench/" and path.endswith(".md")):
            return PathEffect(crates=crates)

    jobs = tuple(
        job
        for job, prefixes in JOB_PATH_PREFIXES.items()
        if path.startswith(prefixes)
    )
    crate = ws.crate_for(path)
    if crate is not None:
        if path.endswith(".md"):
            return PathEffect(jobs=jobs)
        return PathEffect(crates=(crate,), jobs=jobs)
    if jobs:
        return PathEffect(jobs=jobs)

    if path.endswith(".md") or path in NO_HEAVY_JOB_FILES:
        return PathEffect()
    if path.startswith(NO_HEAVY_JOB_PREFIXES):
        return PathEffect()
    if any(fnmatch.fnmatchcase(path, g) and "/" not in path[len("tests/"):] for g in NO_HEAVY_JOB_GLOBS):
        return PathEffect()
    # Unknown: fail safe.
    return PathEffect(full=True)


def select(paths: list[str], ws: Workspace, force_full: bool = False) -> dict[str, str]:
    full = force_full
    seeds: set[str] = set()
    jobs: set[str] = set()
    reasons: list[str] = []
    for path in paths:
        effect = classify(path, ws)
        if effect.full and not full:
            reasons.append(path)
        full = full or effect.full
        seeds.update(effect.crates)
        jobs.update(effect.jobs)

    unknown = seeds - set(ws.dirs)
    if unknown:
        raise SelectorError(f"rules name crates that are not in the workspace: {sorted(unknown)}")

    for path in paths:
        crate = ws.crate_for(path)
        if crate in ws.esp32_deps and path == f"{ws.dirs[crate]}/Cargo.toml":
            jobs.add("esp32")
    # The firmware's lints and host tests also run when the code of a crate
    # it builds changes.
    if "esp32" in jobs or seeds & ws.esp32_deps:
        jobs.add("esp32_lint")

    if full:
        affected = set(ws.dirs)
        jobs = set(JOBS)
    else:
        affected = ws.dependents(seeds)
        for job, crates in JOB_DIRECT_CRATES.items():
            if seeds & set(crates):
                jobs.add(job)
        for job, roots in JOB_ROOT_CRATES.items():
            if seeds & ws.dependencies(set(roots)):
                jobs.add(job)

    out = {"full": _bool(full)}
    if full or affected == set(ws.dirs):
        out["crates"] = "all"
        out["cargo_test_args"] = "--workspace"
    else:
        out["crates"] = " ".join(sorted(affected))
        out["cargo_test_args"] = " ".join(f"-p {c}" for c in sorted(affected))
    out["cargo_test"] = _bool(bool(affected))
    out["hook_examples"] = _bool(bool(affected & {"rns-hooks", "rns-net"}))
    out["cli_features"] = _bool(bool(affected & {"rns-cli", "rns-ctl"}))
    out["no_std"] = _bool(bool(affected & {"rns-crypto", "rns-core"}))
    out["compact_engine"] = _bool("rns-net" in affected)
    for job in JOBS:
        out[job] = _bool(job in jobs)
    # One line per output: a path with a newline must not start another.
    out["full_reasons"] = " ".join(r.replace("\n", "?") for r in reasons)
    return out


def _bool(value: bool) -> str:
    return "true" if value else "false"


def changed_files(base: str, head: str, root: pathlib.Path = ROOT) -> list[str]:
    proc = subprocess.run(
        ["git", "-C", str(root), "diff", "--name-only", "--no-renames", "-z", base, head],
        capture_output=True,
    )
    if proc.returncode:
        raise SelectorError(f"git diff {base} {head} failed: {proc.stderr.decode().strip()}")
    return [p for p in proc.stdout.decode().split("\0") if p]


def merge_parents(rev: str, root: pathlib.Path = ROOT) -> list[str]:
    proc = subprocess.run(
        ["git", "-C", str(root), "rev-list", "--parents", "-n", "1", rev],
        capture_output=True,
        text=True,
    )
    if proc.returncode:
        raise SelectorError(f"git rev-list {rev} failed: {proc.stderr.strip()}")
    return proc.stdout.split()[1:]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--all", action="store_true", help="select every job")
    source.add_argument(
        "--merge",
        metavar="REV",
        help="a pull request merge commit; its changes are those against its first parent",
    )
    source.add_argument("--range", nargs=2, metavar=("BASE", "HEAD"), help="diff BASE HEAD")
    source.add_argument("--files", nargs="*", metavar="PATH", help="changed paths")
    parser.add_argument("--github-output", metavar="FILE", help="append outputs to FILE")
    parser.add_argument("--summary", metavar="FILE", help="append a Markdown summary to FILE")
    args = parser.parse_args(argv)

    ws = load_workspace()
    force_full = args.all
    paths: list[str] = []
    if args.merge:
        parents = merge_parents(args.merge)
        if len(parents) != 2:
            print(f"{args.merge} is not a two-parent merge commit; selecting every job", file=sys.stderr)
            force_full = True
        else:
            paths = changed_files(parents[0], args.merge)
    elif args.range:
        paths = changed_files(*args.range)
    elif args.files is not None:
        paths = args.files

    out = select(paths, ws, force_full=force_full)
    lines = [f"{key}={value}" for key, value in out.items()]
    print("\n".join(lines))
    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(render_summary(paths, out, force_full))
    return 0


def render_summary(paths: list[str], out: dict[str, str], forced: bool) -> str:
    lines = ["## CI job selection", ""]
    if forced:
        lines.append("Every job runs (not a pull request, or a full run was requested).")
    else:
        lines.append(f"{len(paths)} changed file(s).")
        if out["full_reasons"]:
            lines.append(f"Every job runs because of: `{out['full_reasons']}`.")
    lines += ["", "| Output | Value |", "|---|---|"]
    lines += [f"| {k} | `{v}` |" for k, v in out.items() if k != "full_reasons"]
    return "\n".join(lines) + "\n\n"


if __name__ == "__main__":
    sys.exit(main())
