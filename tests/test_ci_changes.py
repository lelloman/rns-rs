from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import ci_changes  # noqa: E402


HEAVY = (
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


class SelectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ws = ci_changes.load_workspace(ROOT)

    def select(self, *paths: str) -> dict[str, str]:
        return ci_changes.select(list(paths), self.ws)

    def jobs(self, out: dict[str, str]) -> set[str]:
        return {job for job in HEAVY if out[job] == "true"}

    def test_workspace_graph_matches_manifests(self) -> None:
        self.assertEqual(self.ws.dirs["rns-hooks-sdk"], "rns-hooks/sdk/rns-hooks-sdk")
        self.assertEqual(self.ws.deps["rns-core"], {"rns-crypto"})
        # Renamed (package = "rns-hooks") optional dependency.
        self.assertIn("rns-hooks", self.ws.deps["rns-net"])
        # The WASM hook examples build against the SDK.
        self.assertIn("rns-hooks-sdk", self.ws.deps["rns-hooks"])
        self.assertEqual(self.ws.esp32_deps, {"rns-core", "rns-crypto"})
        self.assertNotIn("esp32", " ".join(self.ws.dirs.values()))

    def test_docs_only_runs_no_heavy_job(self) -> None:
        out = self.select("docs/engines.md", "README.md", "rns-net/README.md", "bench/README.md")
        self.assertEqual(out["cargo_test"], "false")
        self.assertEqual(self.jobs(out), set())
        self.assertEqual(out["full"], "false")

    def test_doc_embedded_by_code_counts_as_its_crate(self) -> None:
        out = self.select("docs/interface-discovery.md")
        self.assertIn("rns-net", out["crates"].split())

    def test_leaf_crate_tests_only_itself(self) -> None:
        out = self.select("rns-git/src/server.rs")
        self.assertEqual(out["crates"], "rns-git")
        self.assertEqual(out["cargo_test_args"], "-p rns-git")
        # Its Python-peer tests run only in the interop jobs.
        self.assertEqual(self.jobs(out), {"interop"})
        self.assertEqual(out["no_std"], "false")
        self.assertEqual(out["compact_engine"], "false")

    def test_core_change_reaches_its_dependents(self) -> None:
        out = self.select("rns-core/src/lib.rs")
        crates = set(out["crates"].split())
        self.assertIn("rns-core", crates)
        self.assertIn("rns-net", crates)
        self.assertIn("rns-server", crates)
        self.assertNotIn("rns-crypto", crates)
        self.assertNotIn("rns-hooks", crates)
        self.assertEqual(
            self.jobs(out),
            {"android", "hooks", "interop", "docker", "armv7", "ctl_tls", "esp32_lint"},
        )
        self.assertEqual(out["no_std"], "true")
        self.assertEqual(out["esp32"], "false")

    def test_crypto_change_tests_everything_that_uses_it(self) -> None:
        out = self.select("rns-crypto/src/sha256.rs")
        self.assertNotEqual(out["crates"], "all")  # the hook crates do not use it
        self.assertIn("-p rns-crypto", out["cargo_test_args"])

    def test_android_runs_for_what_rns_tun_android_builds(self) -> None:
        self.assertIn("android", self.jobs(self.select("rns-tun-android/app/build.gradle.kts")))
        self.assertIn("android", self.jobs(self.select("rns-tun/src/lib.rs")))
        self.assertIn("android", self.jobs(self.select("rns-net/src/lib.rs")))
        self.assertNotIn("android", self.jobs(self.select("rns-git/src/lib.rs")))

    def test_hook_sdk_reaches_hook_tests(self) -> None:
        out = self.select("rns-hooks/sdk/rns-hooks-sdk/src/lib.rs")
        crates = set(out["crates"].split())
        self.assertTrue({"rns-hooks", "rns-net", "rns-stats-hook"} <= crates)
        self.assertEqual(out["hook_examples"], "true")
        self.assertIn("hooks", self.jobs(out))

    def test_esp32(self) -> None:
        both = {"esp32", "esp32_lint"}
        self.assertEqual(self.jobs(self.select("rns-esp32/src/main.rs")), both)
        self.assertEqual(self.jobs(self.select("vendor/maybe-async-cfg/src/lib.rs")), both)
        self.assertEqual(self.select("rns-esp32/src/main.rs")["cargo_test"], "false")
        self.assertIn("esp32", self.jobs(self.select("rns-core/Cargo.toml")))
        # A firmware dependency's code reaches the lints, not the lock file.
        self.assertEqual(
            self.jobs(self.select("rns-crypto/src/sha256.rs")) & both, {"esp32_lint"}
        )
        self.assertNotIn("esp32_lint", self.jobs(self.select("rns-net/src/lib.rs")))

    def test_web_assets(self) -> None:
        out = self.select("rns-ctl/assets/app.js")
        self.assertIn("web_smoke", self.jobs(out))
        self.assertIn("rns-ctl", out["crates"].split())
        self.assertNotIn("web_smoke", self.jobs(self.select("rns-ctl/src/main.rs")))

    def test_docker_suite(self) -> None:
        out = self.select("tests/docker/suites/01_health.sh")
        self.assertEqual(self.jobs(out), {"docker"})
        self.assertEqual(out["cargo_test"], "false")

    def test_fixtures_and_bench_inputs(self) -> None:
        self.assertIn("rns-cli", self.select("tests/fixtures/rnid/cases.json")["crates"].split())
        self.assertEqual(self.select("bench/profiles/smoke.toml")["crates"], "rns-bench")

    def test_python_tools_and_other_workflows_run_no_heavy_job(self) -> None:
        out = self.select(
            "scripts/mixed_mesh_soak.py",
            "tests/test_mixed_mesh_soak.py",
            "tests/generate_vectors.py",
            ".github/workflows/fuzz.yml",
            "fuzz/fuzz_targets/x.rs",
            "tools/vps-history-dashboard/app.js",
            "deny.toml",
        )
        self.assertEqual(out["cargo_test"], "false")
        self.assertEqual(self.jobs(out), set())

    def test_full_run_paths(self) -> None:
        for path in ci_changes.FULL_RUN:
            out = self.select(path)
            self.assertEqual(out["full"], "true", path)
            self.assertEqual(out["crates"], "all")
            self.assertEqual(out["cargo_test_args"], "--workspace")
            self.assertEqual(self.jobs(out), set(HEAVY))

    def test_unknown_path_fails_safe(self) -> None:
        for path in ("build/common.rs", "something-new/file", "tests/upstream/x.patch"):
            self.assertEqual(self.select(path)["full"], "true", path)

    def test_no_change(self) -> None:
        out = self.select()
        self.assertEqual(out["cargo_test"], "false")
        self.assertEqual(self.jobs(out), set())

    def test_every_external_reference_is_covered(self) -> None:
        """Crate code that reads a file outside its crate maps that file to it."""
        include = re.compile(r'include_(?:str|bytes)!\(\s*"([^"]+)"')
        literal = re.compile(r'"((?:\.\./)+[^"]+)"')
        missing = []
        checked = 0
        for crate, directory in self.ws.dirs.items():
            crate_dir = ROOT / directory
            for source in crate_dir.rglob("*.rs"):
                if "target" in source.relative_to(crate_dir).parts:
                    continue
                text = source.read_text(encoding="utf-8", errors="replace")
                refs = [(source.parent / m) for m in include.findall(text)]
                # A relative path literal may be resolved against the crate
                # (CARGO_MANIFEST_DIR) or the source file; try both.
                for m in literal.findall(text):
                    refs += [crate_dir / m, source.parent / m]
                for ref in refs:
                    ref = pathlib.Path(*_normalize(ref.parts))
                    if not ref.exists() or ROOT not in ref.parents:
                        continue
                    if ref == crate_dir or crate_dir in ref.parents or ref in crate_dir.parents:
                        continue
                    files = [ref] if ref.is_file() else [p for p in ref.rglob("*") if p.is_file()]
                    for f in files[:5]:
                        rel = f.relative_to(ROOT).as_posix()
                        out = self.select(rel)
                        checked += 1
                        if out["full"] != "true" and crate not in out["crates"].split():
                            missing.append(f"{source.relative_to(ROOT)} -> {rel}")
        self.assertEqual(missing, [])
        self.assertGreater(checked, 10)


class GitTests(unittest.TestCase):
    def test_merge_commit_diff_and_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)

            def git(*args: str) -> str:
                return subprocess.run(
                    ["git", "-C", str(repo), *args], check=True, text=True, capture_output=True
                ).stdout.strip()

            git("init", "-q", "-b", "main")
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.invalid")
            (repo / "a").write_text("a\n")
            git("add", "a")
            git("commit", "-qm", "base")
            git("checkout", "-qb", "topic")
            (repo / "b").write_text("b\n")
            git("add", "b")
            git("commit", "-qm", "topic")
            git("checkout", "-q", "main")
            (repo / "c").write_text("c\n")
            git("add", "c")
            git("commit", "-qm", "main")
            git("merge", "-q", "--no-ff", "-m", "merge", "topic")

            parents = ci_changes.merge_parents("HEAD", repo)
            self.assertEqual(len(parents), 2)
            self.assertEqual(ci_changes.changed_files(parents[0], "HEAD", repo), ["b"])
            self.assertEqual(len(ci_changes.merge_parents("HEAD~1", repo)), 1)


def _normalize(parts: tuple[str, ...]) -> list[str]:
    out: list[str] = []
    for part in parts:
        if part == "..":
            out.pop()
        elif part != ".":
            out.append(part)
    return out


if __name__ == "__main__":
    unittest.main()
