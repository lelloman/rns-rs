#!/usr/bin/env python3
"""Tests for the mixed-mesh soak harness's bookkeeping and summary."""

from __future__ import annotations

import pathlib
import sys
import tempfile
import types
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from mixed_mesh_soak import (  # noqa: E402
    Soak,
    build_parser,
    linear_slope,
    parse_duration,
    percentile,
)


def make_soak(workdir: str) -> Soak:
    args = build_parser().parse_args(
        ["--workdir", workdir, "--seed", "1", "--upstream", workdir, "--announce-interval", "60"]
    )
    args.duration = parse_duration(args.duration)
    soak = Soak(args)
    soak.nodes = [types.SimpleNamespace(name="r0", impl="rust"),
                  types.SimpleNamespace(name="p1", impl="python")]
    soak.workload_started_at = 1000.0
    return soak


def sample(t: float, rss: dict[str, float], missing: dict[str, list[str]]) -> dict:
    return {
        "t": t,
        "procs": {name: {"rss_kb": int(mb * 1024), "fds": 10, "threads": 4}
                  for name, mb in rss.items()},
        "paths": {node: {"count": 10, "added": 0, "removed": 0, "changed": 0,
                         "missing": names}
                  for node, names in missing.items()},
    }


class HelperTests(unittest.TestCase):
    def test_parse_duration(self) -> None:
        self.assertEqual(parse_duration("90"), 90)
        self.assertEqual(parse_duration("45m"), 2700)
        self.assertEqual(parse_duration("24h"), 86400)

    def test_percentile(self) -> None:
        values = list(range(1, 101))
        self.assertEqual(percentile(values, 0.5), 50)
        self.assertEqual(percentile(values, 0.95), 95)
        self.assertIsNone(percentile([], 0.5))

    def test_slope(self) -> None:
        self.assertAlmostEqual(linear_slope([(0, 1), (1, 3), (2, 5)]), 2.0)
        self.assertEqual(linear_slope([(0, 1)]), 0.0)

    def test_output_cleaning_and_cause(self) -> None:
        raw = "Path to <ab> requested  \b\b⢄ \b\b⢂ \nPath request timed out\n"
        cleaned = Soak.clean_output(raw)
        self.assertEqual(cleaned, "Path to <ab> requested\nPath request timed out")
        self.assertEqual(Soak.failure_detail(cleaned), "path request timed out")
        self.assertIsNone(Soak.failure_detail("all good"))


class SummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.soak = make_soak(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_flags_steady_rss_growth_but_not_flat_processes(self) -> None:
        self.soak.samples = [
            sample(1000 + 60 * i, {"r0-rnsd": 20 + 0.1 * i, "p1-rnsd": 40}, {})
            for i in range(60)
        ]
        summary = self.soak.summarize()
        growing = [a for a in summary["anomalies"] if "RSS growing" in a]
        self.assertEqual(len(growing), 1)
        self.assertTrue(growing[0].startswith("r0-rnsd"))
        self.assertAlmostEqual(summary["processes"]["r0-rnsd"]["rss_slope_mb_per_h"], 6.0, 1)

    def test_short_runs_do_not_judge_growth(self) -> None:
        self.soak.samples = [
            sample(1000 + 30 * i, {"r0-rnsd": 20 + 0.5 * i}, {}) for i in range(20)
        ]
        summary = self.soak.summarize()
        self.assertFalse([a for a in summary["anomalies"] if "RSS growing" in a])

    def test_reports_stalls_failure_rates_and_causes(self) -> None:
        ops = [{"op": "send", "client_impl": "rust", "target_impl": "python",
                "status": "ok", "latency": 1.0 + i / 10} for i in range(20)]
        ops.append({"op": "send", "client_impl": "python", "target_impl": "rust",
                    "status": "stall", "latency": 90.0, "detail": None, "rc": -9})
        ops.append({"op": "send", "client_impl": "python", "target_impl": "rust",
                    "status": "fail", "latency": 3.0, "detail": "hash mismatch", "rc": 0})
        self.soak.ops = ops
        self.soak.samples = [sample(1000, {}, {})]
        summary = self.soak.summarize()
        send = summary["operations"]["send"]
        self.assertEqual(send["total"], 22)
        self.assertEqual(send["status"], {"ok": 20, "stall": 1, "fail": 1})
        self.assertEqual(send["causes"], {"stall: rc -9": 1, "fail: hash mismatch": 1})
        self.assertIn("1 stalled send operation(s)", summary["anomalies"])
        self.assertTrue(any(a.startswith("send failure rate") for a in summary["anomalies"]))
        self.assertIn("send python->rust", summary["operations"])

    def test_flags_only_destinations_missing_for_a_whole_announce_interval(self) -> None:
        # Announce interval 60 s: the window is 240 s.
        self.soak.samples = [
            sample(1000 + 30 * i,
                   {},
                   {"r0": ["p1-announcer.0"],
                    "p1": ["r0-rncp"] if i in (3, 4) else []})
            for i in range(12)
        ]
        summary = self.soak.summarize()
        lost = [a for a in summary["anomalies"] if "no path" in a]
        self.assertEqual(lost, ["r0: no path to 1 announced destination(s): p1-announcer.0"])


if __name__ == "__main__":
    unittest.main()
