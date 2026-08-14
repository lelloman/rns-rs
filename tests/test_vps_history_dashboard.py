from __future__ import annotations

import pathlib
import sqlite3
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import vps_history_dashboard as dashboard  # noqa: E402


class DashboardHelperTests(unittest.TestCase):
    def test_parse_date_and_table_detection(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE daily_checks (capture_ts_utc TEXT)")
        self.assertTrue(dashboard.has_table(conn, "daily_checks"))
        self.assertFalse(dashboard.has_table(conn, "interface_snapshots"))
        self.assertEqual(dashboard.parse_date(None, "2026-08-14"), "2026-08-14")
        self.assertEqual(dashboard.parse_date("2026-08-01", "fallback"), "2026-08-01")
        with self.assertRaises(ValueError):
            dashboard.parse_date("14/08/2026", "fallback")

    def test_empty_metadata_has_stable_shape(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.execute(
            "CREATE TABLE daily_checks (host TEXT, report_date TEXT, capture_ts_utc TEXT)"
        )
        self.assertEqual(
            dashboard.load_meta(conn),
            {"first_date": None, "last_date": None, "hosts": []},
        )
