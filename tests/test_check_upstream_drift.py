from __future__ import annotations

import argparse
import contextlib
import io
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
        self.assertEqual(result["freshness"], "cached")
        self.assertFalse(result["fetched"])

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
        result = self.check()
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["rgit"]["relation"], "unknown")
        self.assertIn("missing remote tracking ref", result["rgit"]["inspection_error"])

    def test_fetch_retries_and_records_success_timestamp(self) -> None:
        failure = subprocess.CompletedProcess([], 1, "", "temporary failure")
        success = subprocess.CompletedProcess([], 0, "", "")
        with (
            mock.patch.object(drift.subprocess, "run", side_effect=[failure, success]),
            mock.patch.object(
                drift,
                "utc_now",
                side_effect=[
                    "2026-08-19T10:00:00+00:00",
                    "2026-08-19T10:00:05+00:00",
                ],
            ),
        ):
            result = drift.fetch_with_retry(self.repo, "origin")
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(result["completed_at_utc"], "2026-08-19T10:00:05+00:00")
        self.assertIsNone(result["error"])

    def test_fetch_failure_records_final_error(self) -> None:
        first = subprocess.CompletedProcess([], 1, "", "first failure")
        second = subprocess.CompletedProcess([], 1, "", "link establishment timed out")
        with (
            mock.patch.object(drift.subprocess, "run", side_effect=[first, second]),
            mock.patch.object(
                drift,
                "utc_now",
                side_effect=["2026-08-19T10:00:00+00:00", "2026-08-19T10:00:30+00:00"],
            ),
        ):
            result = drift.fetch_with_retry(self.repo, "rgit")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(result["error"], "link establishment timed out")

    def test_failed_rgit_fetch_preserves_fresh_github_result(self) -> None:
        self.args.no_fetch = False
        successful = {
            "status": "succeeded",
            "attempts": 1,
            "attempted_at_utc": "2026-08-19T10:00:00+00:00",
            "completed_at_utc": "2026-08-19T10:00:01+00:00",
            "error": None,
        }
        failed = {
            "status": "failed",
            "attempts": 2,
            "attempted_at_utc": "2026-08-19T10:00:01+00:00",
            "completed_at_utc": "2026-08-19T10:00:31+00:00",
            "error": "link establishment timed out",
        }
        with mock.patch.object(
            drift, "fetch_with_retry", side_effect=[successful, failed]
        ) as fetch:
            result = self.check()
        self.assertEqual(fetch.call_args_list[0].args[1], "origin")
        self.assertEqual(fetch.call_args_list[1].args[1], "rgit")
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["comparison_status"], "current")
        self.assertEqual(result["freshness"], "incomplete")
        self.assertTrue(result["github"]["fresh"])
        self.assertFalse(result["rgit"]["fresh"])
        self.assertFalse(result["fetched"])
        self.assertIn("rgit fetch failed", result["incomplete_reasons"][0])

    def test_human_output_labels_cached_and_failed_refs(self) -> None:
        self.args.no_fetch = False
        successful = {
            "status": "succeeded",
            "attempts": 1,
            "attempted_at_utc": "2026-08-19T10:00:00+00:00",
            "completed_at_utc": "2026-08-19T10:00:01+00:00",
            "error": None,
        }
        failed = {
            "status": "failed",
            "attempts": 2,
            "attempted_at_utc": "2026-08-19T10:00:01+00:00",
            "completed_at_utc": "2026-08-19T10:00:31+00:00",
            "error": "link establishment timed out",
        }
        with mock.patch.object(
            drift, "fetch_with_retry", side_effect=[successful, failed]
        ):
            result = self.check()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            drift.render_human(result)
        rendered = output.getvalue()
        self.assertIn("Upstream parity: incomplete", rendered)
        self.assertIn("GitHub fetch: succeeded", rendered)
        self.assertIn("rgit tip:", rendered)
        self.assertIn("at_baseline; cached", rendered)
        self.assertIn("rgit fetch: FAILED", rendered)
        self.assertIn("link establishment timed out", rendered)

    def test_successful_refresh_marks_both_tips_fresh(self) -> None:
        self.args.no_fetch = False
        successful = {
            "status": "succeeded",
            "attempts": 1,
            "attempted_at_utc": "2026-08-19T10:00:00+00:00",
            "completed_at_utc": "2026-08-19T10:00:01+00:00",
            "error": None,
        }
        with mock.patch.object(
            drift, "fetch_with_retry", side_effect=[successful, successful]
        ):
            result = self.check()
        self.assertEqual(result["status"], "current")
        self.assertEqual(result["freshness"], "fresh")
        self.assertTrue(result["github"]["fresh"])
        self.assertTrue(result["rgit"]["fresh"])
        self.assertTrue(result["fetched"])

    def test_main_returns_one_for_incomplete_fetch(self) -> None:
        args = argparse.Namespace(json=False, fail_on_drift=False)
        result = {
            "status": "incomplete",
            "comparison_status": "current",
        }
        with (
            mock.patch.object(drift, "parse_args", return_value=args),
            mock.patch.object(drift, "check", return_value=result),
            mock.patch.object(drift, "render_human"),
        ):
            self.assertEqual(drift.main(), 1)
