from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import check_upstream_drift as drift  # noqa: E402


def run(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, text=True, capture_output=True
    ).stdout.strip()


class DriftTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.tmp.name) / "upstream"
        run(self.repo.parent, "init", str(self.repo))
        run(self.repo, "config", "user.name", "Test")
        run(self.repo, "config", "user.email", "test@example.invalid")
        (self.repo / "file").write_text("base\n")
        run(self.repo, "add", "file")
        run(self.repo, "commit", "-m", "baseline")
        self.baseline = run(self.repo, "rev-parse", "HEAD")
        run(self.repo, "update-ref", "refs/remotes/origin/master", self.baseline)
        run(self.repo, "update-ref", "refs/remotes/rgit/master", self.baseline)
        self.args = argparse.Namespace(
            upstream_dir=str(self.repo), baseline=self.baseline, no_fetch=True
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def check(self) -> dict[str, object]:
        with mock.patch.dict(os.environ, {}, clear=True):
            return drift.check(self.args)

    def commit(self, subject: str) -> str:
        with (self.repo / "file").open("a") as handle:
            handle.write(subject + "\n")
        run(self.repo, "commit", "-am", subject)
        return run(self.repo, "rev-parse", "HEAD")

    def test_both_at_baseline(self) -> None:
        result = self.check()
        self.assertEqual(result["status"], "current")
        self.assertEqual(result["commits_ahead"], 0)

    def test_github_behind_is_current_without_unintegrated_commits(self) -> None:
        old = run(self.repo, "rev-parse", "HEAD")
        baseline = self.commit("accepted")
        self.args.baseline = baseline
        run(self.repo, "update-ref", "refs/remotes/origin/master", old)
        run(self.repo, "update-ref", "refs/remotes/rgit/master", baseline)
        result = self.check()
        self.assertEqual(result["status"], "behind")
        self.assertEqual(result["github"]["relation"], "behind")
        self.assertEqual(result["commits_ahead"], 0)

    def test_ahead_commits_are_deduplicated(self) -> None:
        tip = self.commit("new work")
        run(self.repo, "update-ref", "refs/remotes/origin/master", tip)
        run(self.repo, "update-ref", "refs/remotes/rgit/master", tip)
        run(self.repo, "checkout", "--detach", self.baseline)
        result = self.check()
        self.assertEqual(result["status"], "drift")
        self.assertEqual(result["commits_ahead"], 1)
        self.assertEqual(result["commits"][0]["subject"], "new work")

    def test_diverged_remote_is_drift(self) -> None:
        run(self.repo, "checkout", "--orphan", "other")
        run(self.repo, "rm", "-f", "file")
        (self.repo / "other").write_text("other\n")
        run(self.repo, "add", "other")
        run(self.repo, "commit", "-m", "diverged")
        tip = run(self.repo, "rev-parse", "HEAD")
        run(self.repo, "update-ref", "refs/remotes/origin/master", tip)
        run(self.repo, "checkout", "--detach", self.baseline)
        result = self.check()
        self.assertEqual(result["github"]["relation"], "diverged")
        self.assertEqual(result["status"], "drift")

    def test_wrong_head_and_missing_ref_fail(self) -> None:
        self.commit("advanced checkout")
        with self.assertRaises(drift.DriftError):
            self.check()
        run(self.repo, "checkout", "--detach", self.baseline)
        run(self.repo, "update-ref", "-d", "refs/remotes/rgit/master")
        with self.assertRaises(drift.DriftError):
            self.check()
