#!/usr/bin/env python3
"""Regression tests for the VPS daily report collector."""

from __future__ import annotations

import pathlib
import sqlite3
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from vps_daily_report import (  # noqa: E402
    parse_utc,
    pretty_duration,
    repair_packet_freshness_history,
    status_from_json,
)


class StatusJsonTests(unittest.TestCase):
    def test_derives_legacy_summary_from_json_and_skips_local(self) -> None:
        status, rows = status_from_json(
            {
                "transport_uptime": 183845.9,
                "probe_responder": "0123456789abcdef",
                "interfaces": [
                    {"id": 1, "name": "LocalInterface", "status": True},
                    {"id": 2, "name": "Primary Backbone", "status": True},
                    {"id": 3, "name": "BackboneInterface/10001", "status": True},
                    {"id": 4, "name": "Named Peer", "status": False},
                ],
            },
            parse_utc("2026-08-14 12:00:00 UTC"),
        )

        self.assertEqual(status["transport_uptime"], "2d 3h 4m")
        self.assertEqual(status["primary_peer_name"], "Primary Backbone")
        self.assertTrue(status["primary_peer_up"])
        self.assertEqual(status["backbone_up_count"], 1)
        self.assertEqual(status["named_peer_up_count"], 0)
        self.assertEqual([row["interface_kind"] for row in rows], [
            "local", "configured_public", "backbone_discovered", "configured_public"
        ])

    def test_down_primary_and_remaining_counts(self) -> None:
        status, _ = status_from_json(
            {
                "transport_uptime": 30,
                "interfaces": [
                    {"name": "Primary", "status": False},
                    {"name": "BackboneInterface/10002", "status": True},
                    {"name": "Named Peer", "status": True},
                ],
            },
            parse_utc("2026-08-14 12:00:00 UTC"),
        )
        self.assertFalse(status["primary_peer_up"])
        self.assertEqual(status["backbone_up_count"], 1)
        self.assertEqual(status["named_peer_up_count"], 1)

    def test_no_public_interfaces(self) -> None:
        status, _ = status_from_json(
            {"transport_uptime": 0, "interfaces": [{"name": "LocalInterface"}]},
            parse_utc("2026-08-14 12:00:00 UTC"),
        )
        self.assertEqual(status["transport_uptime"], "now")
        self.assertEqual(status["primary_peer_name"], "")
        self.assertFalse(status["primary_peer_up"])

    def test_rejects_malformed_required_fields(self) -> None:
        capture = parse_utc("2026-08-14 12:00:00 UTC")
        for payload in ({}, {"transport_uptime": 1}, {"transport_uptime": 1, "interfaces": [1]}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                status_from_json(payload, capture)

    def test_pretty_duration_matches_cli(self) -> None:
        self.assertEqual(pretty_duration(-1), "now")
        self.assertEqual(pretty_duration(59.9), "59s")
        self.assertEqual(pretty_duration(90061), "1d 1h 1m")


class FreshnessRepairTests(unittest.TestCase):
    def test_clamps_negative_history_and_recomputes_summary_idempotently(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.executescript(
            """
            CREATE TABLE daily_checks (
                capture_ts_utc TEXT PRIMARY KEY,
                packet_freshness_max_age_seconds INTEGER NOT NULL
            );
            CREATE TABLE packet_freshness (
                capture_ts_utc TEXT NOT NULL,
                packet_type TEXT NOT NULL,
                direction TEXT NOT NULL,
                age_seconds INTEGER NOT NULL
            );
            INSERT INTO daily_checks VALUES ('one', -5), ('two', 77);
            INSERT INTO packet_freshness VALUES
                ('one', 'announce', 'rx', -5),
                ('one', 'data', 'tx', 12);
            """
        )
        self.assertEqual(repair_packet_freshness_history(conn), 1)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM packet_freshness").fetchone()[0], 2)
        self.assertEqual(conn.execute("SELECT age_seconds FROM packet_freshness ORDER BY age_seconds").fetchall(), [(0,), (12,)])
        self.assertEqual(conn.execute("SELECT packet_freshness_max_age_seconds FROM daily_checks WHERE capture_ts_utc='one'").fetchone()[0], 12)
        self.assertEqual(conn.execute("SELECT packet_freshness_max_age_seconds FROM daily_checks WHERE capture_ts_utc='two'").fetchone()[0], 77)
        self.assertEqual(repair_packet_freshness_history(conn), 0)


if __name__ == "__main__":
    unittest.main()
