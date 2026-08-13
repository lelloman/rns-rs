#!/usr/bin/env python3
"""Serve a local, read-only dashboard for VPS daily report history."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import mimetypes
import pathlib
import sqlite3
import sys
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "data" / "vps_daily_reports.db"
ASSET_DIR = ROOT / "tools" / "vps-history-dashboard"
HOST_SQL = """
CASE host
  WHEN 'root@vps-eu' THEN 'vps-eu'
  WHEN 'root@vps-us' THEN 'vps-us'
  ELSE host
END
"""
METRIC_COLUMNS = (
    "load1",
    "load5",
    "load15",
    "mem_used_mb",
    "mem_total_mb",
    "mem_available_mb",
    "swap_used_mb",
    "swap_total_mb",
    "rns_server_active",
    "child_rnsd_ready",
    "child_rns_statsd_ready",
    "child_rns_sentineld_ready",
    "established_sessions_4242",
    "primary_peer_up",
    "backbone_up_count",
    "named_peer_up_count",
    "blacklist_total_entries",
    "blacklist_reject_nonzero_entries",
    "blacklist_active_entries",
    "blacklist_connected_entries",
    "provider_bridge_dropped_24h",
    "provider_bridge_disconnected_24h",
    "idle_timeout_events_24h",
    "announce_total",
    "announce_1h",
    "announce_24h",
    "packet_freshness_max_age_seconds",
    "rns_server_matches_master",
    "rns_server_matches_dev",
    "rns_ctl_matches_master",
    "rns_ctl_matches_dev",
)
TEXT_COLUMNS = (
    "capture_ts_utc",
    "report_date",
    "health_state",
    "host_uptime",
    "transport_uptime",
    "primary_peer_name",
    "rns_server_version",
    "rns_server_master_version",
    "rns_server_dev_version",
    "rns_ctl_version",
    "rns_ctl_master_version",
    "rns_ctl_dev_version",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Serve an HTML dashboard for the VPS daily-report SQLite database."
    )
    parser.add_argument("--db-path", default=str(DEFAULT_DB), help="SQLite database path")
    parser.add_argument("--host", default="127.0.0.1", help="HTTP bind host")
    parser.add_argument("--port", type=int, default=8765, help="HTTP bind port")
    parser.add_argument("--open", action="store_true", help="Open the dashboard in a browser")
    parser.add_argument(
        "--check", action="store_true", help="Validate the database and print coverage, then exit"
    )
    return parser.parse_args()


def connect_readonly(path: pathlib.Path) -> sqlite3.Connection:
    if not path.is_file():
        raise FileNotFoundError(f"database does not exist: {path}")
    uri = f"file:{urllib.parse.quote(str(path.resolve()), safe='/')}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def validate_schema(conn: sqlite3.Connection) -> None:
    tables = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    required_tables = {"daily_checks", "interface_snapshots"}
    missing_tables = sorted(required_tables - tables)
    if missing_tables:
        raise ValueError(f"database is missing tables: {', '.join(missing_tables)}")
    columns = {row[1] for row in conn.execute("PRAGMA table_info(daily_checks)")}
    required = {"host", "report_date", "capture_ts_utc", "health_state", *METRIC_COLUMNS, *TEXT_COLUMNS}
    missing = sorted(required - columns)
    if missing:
        raise ValueError(f"daily_checks is missing columns: {', '.join(missing)}")


def has_table(conn: sqlite3.Connection, table: str) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
        ).fetchone()
        is not None
    )


def load_meta(conn: sqlite3.Connection) -> dict[str, Any]:
    rows = conn.execute(
        f"""
        WITH canonical AS (
          SELECT {HOST_SQL} AS host, report_date
          FROM daily_checks
        )
        SELECT host,
               MIN(report_date) AS first_date,
               MAX(report_date) AS last_date,
               COUNT(DISTINCT report_date) AS observed_days,
               CAST(julianday(MAX(report_date)) - julianday(MIN(report_date)) + 1 AS INTEGER)
                 AS span_days
        FROM canonical
        GROUP BY host
        ORDER BY host
        """
    ).fetchall()
    hosts = [dict(row) for row in rows]
    if not hosts:
        return {"first_date": None, "last_date": None, "hosts": []}
    result: dict[str, Any] = {
        "first_date": min(row["first_date"] for row in hosts),
        "last_date": max(row["last_date"] for row in hosts),
        "hosts": hosts,
    }
    result["packet_traffic_available"] = has_table(conn, "packet_traffic_24h")
    if result["packet_traffic_available"]:
        traffic_range = conn.execute(
            """
            SELECT MIN(d.report_date), MAX(d.report_date)
            FROM packet_traffic_24h p
            JOIN daily_checks d USING (capture_ts_utc)
            WHERE p.query_ok = 1
            """
        ).fetchone()
        result["packet_traffic_first_date"] = traffic_range[0]
        result["packet_traffic_last_date"] = traffic_range[1]
    return result


def parse_date(value: str | None, fallback: str) -> str:
    if not value:
        return fallback
    try:
        return dt.date.fromisoformat(value).isoformat()
    except ValueError as exc:
        raise ValueError(f"invalid ISO date: {value}") from exc


def load_daily(
    conn: sqlite3.Connection, start: str, end: str, hosts: list[str]
) -> list[dict[str, Any]]:
    if start > end:
        raise ValueError("start date must not be after end date")
    known_hosts = {row["host"] for row in load_meta(conn)["hosts"]}
    selected_hosts = sorted(set(hosts or known_hosts))
    unknown = set(selected_hosts) - known_hosts
    if unknown:
        raise ValueError(f"unknown host: {', '.join(sorted(unknown))}")
    if not selected_hosts:
        return []

    placeholders = ",".join("?" for _ in selected_hosts)
    selected = ",\n                 ".join((*TEXT_COLUMNS, *METRIC_COLUMNS))
    rows = conn.execute(
        f"""
        WITH ranked AS (
          SELECT {HOST_SQL} AS canonical_host,
                 {selected},
                 ROW_NUMBER() OVER (
                   PARTITION BY {HOST_SQL}, report_date
                   ORDER BY capture_ts_utc DESC
                 ) AS rn
          FROM daily_checks
          WHERE report_date BETWEEN ? AND ?
            AND {HOST_SQL} IN ({placeholders})
        ), interface_totals AS (
          SELECT capture_ts_utc,
                 COUNT(*) AS interfaces_total,
                 SUM(public_candidate) AS public_interfaces_total,
                 SUM(CASE WHEN public_candidate = 1 AND status = 1 THEN 1 ELSE 0 END)
                   AS public_interfaces_up,
                 SUM(CASE WHEN interface_kind = 'backbone_discovered' THEN 1 ELSE 0 END)
                   AS discovered_backbone_interfaces
          FROM interface_snapshots
          GROUP BY capture_ts_utc
        )
        SELECT ranked.canonical_host AS host,
               {selected},
               COALESCE(interface_totals.interfaces_total, 0) AS interfaces_total,
               COALESCE(interface_totals.public_interfaces_total, 0) AS public_interfaces_total,
               COALESCE(interface_totals.public_interfaces_up, 0) AS public_interfaces_up,
               COALESCE(interface_totals.discovered_backbone_interfaces, 0)
                 AS discovered_backbone_interfaces
        FROM ranked
        LEFT JOIN interface_totals USING (capture_ts_utc)
        WHERE ranked.rn = 1
        ORDER BY report_date, host
        """,
        [start, end, *selected_hosts],
    ).fetchall()
    return [dict(row) for row in rows]


def load_traffic(
    conn: sqlite3.Connection, start: str, end: str, hosts: list[str]
) -> list[dict[str, Any]]:
    if not has_table(conn, "packet_traffic_24h"):
        return []
    if start > end:
        raise ValueError("start date must not be after end date")
    known_hosts = {row["host"] for row in load_meta(conn)["hosts"]}
    selected_hosts = sorted(set(hosts or known_hosts))
    unknown = set(selected_hosts) - known_hosts
    if unknown:
        raise ValueError(f"unknown host: {', '.join(sorted(unknown))}")
    if not selected_hosts:
        return []
    placeholders = ",".join("?" for _ in selected_hosts)
    rows = conn.execute(
        f"""
        WITH ranked AS (
          SELECT capture_ts_utc,
                 report_date,
                 {HOST_SQL} AS canonical_host,
                 ROW_NUMBER() OVER (
                   PARTITION BY {HOST_SQL}, report_date
                   ORDER BY capture_ts_utc DESC
                 ) AS rn
          FROM daily_checks
          WHERE report_date BETWEEN ? AND ?
            AND {HOST_SQL} IN ({placeholders})
        )
        SELECT ranked.canonical_host AS host,
               ranked.report_date,
               traffic.packet_type,
               traffic.direction,
               traffic.packets,
               traffic.bytes,
               traffic.query_ok
        FROM ranked
        JOIN packet_traffic_24h traffic USING (capture_ts_utc)
        WHERE ranked.rn = 1
        ORDER BY ranked.report_date, ranked.canonical_host,
                 traffic.packet_type, traffic.direction
        """,
        [start, end, *selected_hosts],
    ).fetchall()
    return [dict(row) for row in rows]


def check_database(path: pathlib.Path) -> dict[str, Any]:
    with connect_readonly(path) as conn:
        validate_schema(conn)
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise ValueError(f"SQLite integrity check failed: {integrity}")
        meta = load_meta(conn)
        meta["integrity"] = integrity
        return meta


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "VpsHistoryDashboard/1.0"

    @property
    def db_path(self) -> pathlib.Path:
        return self.server.db_path  # type: ignore[attr-defined]

    def send_json(self, value: Any, status: int = 200) -> None:
        body = json.dumps(value, separators=(",", ":"), allow_nan=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_asset(self, name: str) -> None:
        path = ASSET_DIR / name
        if not path.is_file():
            self.send_error(404)
            return
        body = path.read_bytes()
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urllib.parse.urlparse(self.path)
        try:
            if parsed.path in ("/", "/index.html"):
                self.send_asset("index.html")
                return
            if parsed.path in ("/app.js", "/styles.css"):
                self.send_asset(parsed.path[1:])
                return
            if parsed.path == "/api/meta":
                with connect_readonly(self.db_path) as conn:
                    self.send_json(load_meta(conn))
                return
            if parsed.path == "/api/daily":
                query = urllib.parse.parse_qs(parsed.query)
                with connect_readonly(self.db_path) as conn:
                    meta = load_meta(conn)
                    if not meta["first_date"]:
                        self.send_json({"rows": []})
                        return
                    start = parse_date(query.get("start", [None])[0], meta["first_date"])
                    end = parse_date(query.get("end", [None])[0], meta["last_date"])
                    rows = load_daily(conn, start, end, query.get("host", []))
                    self.send_json({"start": start, "end": end, "rows": rows})
                return
            if parsed.path == "/api/traffic":
                query = urllib.parse.parse_qs(parsed.query)
                with connect_readonly(self.db_path) as conn:
                    meta = load_meta(conn)
                    if not meta["first_date"]:
                        self.send_json({"rows": []})
                        return
                    start = parse_date(query.get("start", [None])[0], meta["first_date"])
                    end = parse_date(query.get("end", [None])[0], meta["last_date"])
                    rows = load_traffic(conn, start, end, query.get("host", []))
                    self.send_json({"start": start, "end": end, "rows": rows})
                return
            if parsed.path == "/favicon.ico":
                self.send_response(204)
                self.end_headers()
                return
            self.send_error(404)
        except (FileNotFoundError, ValueError, sqlite3.Error) as exc:
            self.send_json({"error": str(exc)}, status=400)

    def log_message(self, message: str, *args: object) -> None:
        print(f"{self.address_string()} - {message % args}", file=sys.stderr)


def main() -> int:
    args = parse_args()
    db_path = pathlib.Path(args.db_path).expanduser().resolve()
    try:
        meta = check_database(db_path)
    except (FileNotFoundError, ValueError, sqlite3.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.check:
        print(json.dumps(meta, indent=2))
        return 0

    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    server.db_path = db_path  # type: ignore[attr-defined]
    url = f"http://{args.host}:{server.server_port}/"
    print(f"VPS history dashboard: {url}")
    print(f"Database (read-only): {db_path}")
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
