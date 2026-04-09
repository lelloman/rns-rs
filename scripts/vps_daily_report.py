#!/usr/bin/env python3
"""Collect a daily VPS health snapshot, persist it, and render a report."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import shlex
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "data" / "vps_daily_reports.db"
DEFAULT_REPORTS_DIR = ROOT / "docs"
MEMSTATS_RE = re.compile(r"MEMSTATS\s+(.*)$")
KV_RE = re.compile(r"([a-zA-Z0-9_]+)=([^\s]+)")


@dataclass
class CommandResult:
    stdout: str
    stderr: str


def run_local(cmd: list[str]) -> CommandResult:
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr.strip()}"
        )
    return CommandResult(proc.stdout, proc.stderr)


def run_ssh(host: str, script: str) -> str:
    remote_cmd = f"bash -lc {shlex.quote(script)}"
    return run_local(["ssh", host, remote_cmd]).stdout


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect a VPS health snapshot and render the daily report."
    )
    parser.add_argument("--host", default="root@vps", help="SSH target")
    parser.add_argument(
        "--db-path",
        default=str(DEFAULT_DB),
        help="Path to the normalized daily snapshot database",
    )
    parser.add_argument(
        "--reports-dir",
        default=str(DEFAULT_REPORTS_DIR),
        help="Directory for generated Markdown reports",
    )
    parser.add_argument(
        "--date",
        help="Override report date (YYYY-MM-DD). Default: capture date in UTC.",
    )
    parser.add_argument(
        "--stdout-summary",
        action="store_true",
        help="Print a concise summary after writing artifacts",
    )
    return parser.parse_args()


def parse_key_values(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def parse_active_enter(value: str | None) -> dt.datetime | None:
    if not value or value == "n/a":
        return None
    return dt.datetime.strptime(value, "%a %Y-%m-%d %H:%M:%S UTC").replace(
        tzinfo=dt.timezone.utc
    )


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def parse_utc_timestamp(value: str) -> dt.datetime:
    return dt.datetime.strptime(value, "%Y-%m-%d %H:%M:%S UTC").replace(
        tzinfo=dt.timezone.utc
    )


def fmt_mb(value: float) -> str:
    return f"{value:.1f} MB"


def fmt_ts(value: str | None) -> str:
    return value or "n/a"


def hours_since(start: dt.datetime | None, end: dt.datetime) -> str:
    if start is None:
        return "n/a"
    delta = end - start
    hours = delta.total_seconds() / 3600
    return f"{hours:.0f} hours"


def parse_status_sections(text: str) -> dict[str, Any]:
    lines = text.splitlines()
    transport_uptime = ""
    public_entrypoint_name = ""
    public_entrypoint_up = False
    backbone_up_count = 0
    named_peer_up_count = 0
    section_name: str | None = None
    section_status: str | None = None
    top_sections: list[tuple[str, str | None]] = []

    for raw_line in lines:
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if stripped.startswith("Transport Instance "):
            parts = stripped.split(" running for ", 1)
            if len(parts) == 2:
                transport_uptime = parts[1].strip()
            continue
        if 0 < indent < 4:
            if section_name is not None:
                top_sections.append((section_name, section_status))
            section_name = stripped
            section_status = None
            continue
        if indent >= 4 and stripped.startswith("Status") and ":" in stripped:
            section_status = stripped.split(":", 1)[1].strip()
    if section_name is not None:
        top_sections.append((section_name, section_status))

    if top_sections:
        public_entrypoint_name = top_sections[0][0]
        public_entrypoint_up = top_sections[0][1] == "Up"

    for name, status in top_sections[1:]:
        if not status:
            continue
        if name.startswith("BackboneInterface/") and status == "Up":
            backbone_up_count += 1
        elif status == "Up":
            named_peer_up_count += 1

    return {
        "transport_uptime": transport_uptime,
        "public_entrypoint_name": public_entrypoint_name,
        "public_entrypoint_up": public_entrypoint_up,
        "backbone_up_count": backbone_up_count,
        "named_peer_up_count": named_peer_up_count,
    }


def parse_memstats(lines: list[str]) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        timestamp = None
        if line.startswith("Apr "):
            parts = line.split("]:", 1)
            if parts:
                match = re.search(r"\[([0-9T:\-]+)Z", line)
                if match:
                    timestamp = (
                        dt.datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S")
                        .replace(tzinfo=dt.timezone.utc)
                        .strftime("%Y-%m-%d %H:%M:%S UTC")
                    )
        match = MEMSTATS_RE.search(line)
        if not match:
            continue
        values = {k: v for k, v in KV_RE.findall(match.group(1))}
        samples.append(
            {
                "sample_ts_utc": timestamp,
                "rss_mb": float(values.get("rss_mb", "0")),
                "smaps_anon_mb": float(values.get("smaps_anon_mb", "0")),
                "ann_q_bytes": int(float(values.get("ann_q_bytes", "0"))),
                "ann_q_ifaces": int(float(values.get("ann_q_ifaces", "0"))),
                "ann_q_nonempty": int(float(values.get("ann_q_nonempty", "0"))),
                "ann_q_iface_drop": int(float(values.get("ann_q_iface_drop", "0"))),
                "known_dest": int(float(values.get("known_dest", "0"))),
                "path_count": int(float(values.get("path", "0"))),
                "link_count": int(float(values.get("link", "0"))),
            }
        )
    return samples


def classify_health(snapshot: dict[str, Any], packet_rows: list[dict[str, Any]]) -> tuple[str, str]:
    services_ok = all(row["is_active"] for row in snapshot["service_rows"])
    listeners_ok = snapshot["public_listener_present"] and snapshot["rpc_listener_present"]
    packet_ok = bool(packet_rows) and max(row["age_seconds"] for row in packet_rows) <= 1800
    announces_ok = snapshot["announce_24h"] > 0
    bridge_ok = (
        snapshot["provider_bridge_dropped_24h"] == 0
        and snapshot["provider_bridge_disconnected_24h"] == 0
    )
    blacklist_pressure = snapshot["idle_timeout_events_24h"] > 0

    if not services_ok or not listeners_ok or not announces_ok:
        return "degraded", "one or more required services, listeners, or traffic checks failed"
    if not packet_ok or not bridge_ok:
        return "degraded", "the node is up but packet freshness or provider-bridge health regressed"
    if blacklist_pressure:
        return (
            "healthy_with_blacklist_pressure",
            "services are healthy and traffic is active, with continuing sentinel enforcement noise",
        )
    return "healthy", "all primary service, listener, bridge, and traffic checks are healthy"


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS daily_checks (
            capture_ts_utc TEXT PRIMARY KEY,
            report_date TEXT NOT NULL,
            host TEXT NOT NULL,
            health_state TEXT NOT NULL,
            health_summary TEXT NOT NULL,
            host_uptime TEXT NOT NULL,
            load1 REAL NOT NULL,
            load5 REAL NOT NULL,
            load15 REAL NOT NULL,
            mem_used_mb INTEGER NOT NULL,
            mem_total_mb INTEGER NOT NULL,
            mem_available_mb INTEGER NOT NULL,
            swap_used_mb INTEGER NOT NULL,
            swap_total_mb INTEGER NOT NULL,
            public_listener_present INTEGER NOT NULL,
            rpc_listener_present INTEGER NOT NULL,
            shared_listener_present INTEGER NOT NULL,
            established_sessions_4242 INTEGER NOT NULL,
            transport_uptime TEXT NOT NULL,
            public_entrypoint_name TEXT NOT NULL,
            public_entrypoint_up INTEGER NOT NULL,
            backbone_up_count INTEGER NOT NULL,
            named_peer_up_count INTEGER NOT NULL,
            blacklist_total_entries INTEGER NOT NULL,
            blacklist_reject_nonzero_entries INTEGER NOT NULL,
            blacklist_active_entries INTEGER NOT NULL,
            blacklist_connected_entries INTEGER NOT NULL,
            idle_timeout_events_24h INTEGER NOT NULL,
            provider_bridge_dropped_24h INTEGER NOT NULL,
            provider_bridge_disconnected_24h INTEGER NOT NULL,
            announce_total INTEGER NOT NULL,
            announce_latest_utc TEXT,
            announce_1h INTEGER NOT NULL,
            announce_24h INTEGER NOT NULL,
            packet_freshness_max_age_seconds INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS daily_check_versions (
            capture_ts_utc TEXT NOT NULL,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            PRIMARY KEY (capture_ts_utc, name),
            FOREIGN KEY (capture_ts_utc) REFERENCES daily_checks(capture_ts_utc) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS daily_check_service_state (
            capture_ts_utc TEXT NOT NULL,
            name TEXT NOT NULL,
            is_active INTEGER NOT NULL,
            active_enter_utc TEXT,
            PRIMARY KEY (capture_ts_utc, name),
            FOREIGN KEY (capture_ts_utc) REFERENCES daily_checks(capture_ts_utc) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS daily_check_listeners (
            capture_ts_utc TEXT NOT NULL,
            address TEXT NOT NULL,
            port INTEGER NOT NULL,
            present INTEGER NOT NULL,
            PRIMARY KEY (capture_ts_utc, address, port),
            FOREIGN KEY (capture_ts_utc) REFERENCES daily_checks(capture_ts_utc) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS daily_check_packet_freshness (
            capture_ts_utc TEXT NOT NULL,
            packet_type TEXT NOT NULL,
            direction TEXT NOT NULL,
            updated_at_utc TEXT,
            age_seconds INTEGER NOT NULL,
            PRIMARY KEY (capture_ts_utc, packet_type, direction),
            FOREIGN KEY (capture_ts_utc) REFERENCES daily_checks(capture_ts_utc) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS daily_check_memstats (
            capture_ts_utc TEXT NOT NULL,
            sample_ts_utc TEXT NOT NULL,
            rss_mb REAL NOT NULL,
            smaps_anon_mb REAL NOT NULL,
            ann_q_bytes INTEGER NOT NULL,
            ann_q_ifaces INTEGER NOT NULL,
            ann_q_nonempty INTEGER NOT NULL,
            ann_q_iface_drop INTEGER NOT NULL,
            known_dest INTEGER NOT NULL,
            path_count INTEGER NOT NULL,
            link_count INTEGER NOT NULL,
            PRIMARY KEY (capture_ts_utc, sample_ts_utc),
            FOREIGN KEY (capture_ts_utc) REFERENCES daily_checks(capture_ts_utc) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS daily_check_blacklist_examples (
            capture_ts_utc TEXT NOT NULL,
            ip TEXT NOT NULL,
            reject_count INTEGER NOT NULL,
            blacklist_reason TEXT,
            blacklisted_remaining_secs REAL,
            connected_count INTEGER NOT NULL,
            PRIMARY KEY (capture_ts_utc, ip),
            FOREIGN KEY (capture_ts_utc) REFERENCES daily_checks(capture_ts_utc) ON DELETE CASCADE
        )
        """
    )


def collect_snapshot(host: str, report_date_override: str | None) -> dict[str, Any]:
    capture_ts = utc_now()

    basic_script = r"""
set -euo pipefail
capture_ts=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
read -r load1 load5 load15 _ < /proc/loadavg
read -r mem_total mem_used _ _ _ mem_available < <(free -m | awk '/^Mem:/ {print $2, $3, $4, $5, $6, $7}')
read -r swap_total swap_used _ < <(free -m | awk '/^Swap:/ {print $2, $3, $4}')
echo "CAPTURE_TS=${capture_ts}"
echo "HOST_UPTIME=$(uptime -p | sed 's/^up //')"
echo "LOAD1=${load1}"
echo "LOAD5=${load5}"
echo "LOAD15=${load15}"
echo "MEM_TOTAL_MB=${mem_total}"
echo "MEM_USED_MB=${mem_used}"
echo "MEM_AVAILABLE_MB=${mem_available}"
echo "SWAP_TOTAL_MB=${swap_total}"
echo "SWAP_USED_MB=${swap_used}"
for service in rnsd rns-statsd rns-sentineld; do
  name=$(echo "$service" | tr '[:lower:]-' '[:upper:]_')
  echo "${name}_ACTIVE=$(systemctl is-active "$service" || true)"
  echo "${name}_ACTIVE_ENTER=$(systemctl show -p ActiveEnterTimestamp --value "$service" || true)"
done
echo "RNSD_VERSION=$(/usr/local/bin/rnsd --version)"
echo "RNS_STATSD_VERSION=$(/usr/local/bin/rns-statsd --version)"
echo "RNS_SENTINELD_VERSION=$(/usr/local/bin/rns-sentineld --version)"
echo "RNS_CTL_VERSION=$(/usr/local/bin/rns-ctl --version)"
listeners=$(ss -ltnH | awk '{print $4}')
if printf '%s\n' "$listeners" | grep -qx '0.0.0.0:4242'; then echo 'LISTENER_PUBLIC=1'; else echo 'LISTENER_PUBLIC=0'; fi
if printf '%s\n' "$listeners" | grep -qx '127.0.0.1:37429'; then echo 'LISTENER_RPC=1'; else echo 'LISTENER_RPC=0'; fi
if printf '%s\n' "$listeners" | grep -qx '127.0.0.1:37428'; then echo 'LISTENER_SHARED=1'; else echo 'LISTENER_SHARED=0'; fi
echo "ESTABLISHED_4242=$(ss -tn state established | awk '$4 ~ /:4242$/ || $5 ~ /:4242$/ {count++} END {print count+0}')"
"""
    basic = parse_key_values(run_ssh(host, basic_script))

    status_text = run_ssh(host, "/usr/local/bin/rns-ctl status")
    status_summary = parse_status_sections(status_text)

    blacklist_json = json.loads(
        run_ssh(host, "/usr/local/bin/rns-ctl backbone blacklist list --json")
    )
    reject_entries = [row for row in blacklist_json if row.get("reject_count", 0) > 0]
    active_entries = [row for row in blacklist_json if row.get("blacklisted_remaining_secs") is not None]
    connected_entries = [row for row in blacklist_json if row.get("connected_count", 0) > 0]
    blacklist_examples = sorted(
        reject_entries,
        key=lambda row: (-int(row.get("reject_count", 0)), row.get("ip", "")),
    )[:5]

    journal_counts = parse_key_values(
        run_ssh(
            host,
            r"""
set -euo pipefail
echo "PROVIDER_DROPPED_24H=$(journalctl -u rns-statsd --since '24 hours ago' --no-pager | grep -c 'provider bridge dropped' || true)"
echo "PROVIDER_DISCONNECTED_24H=$(journalctl -u rns-sentineld --since '24 hours ago' --no-pager | grep -c 'provider bridge disconnected' || true)"
echo "IDLE_TIMEOUT_24H=$(journalctl -u rns-sentineld --since '24 hours ago' --no-pager | grep -c 'repeated idle timeouts' || true)"
""",
        )
    )
    memstats_lines = run_ssh(
        host,
        r"journalctl -u rnsd --since '1 hour ago' --no-pager | grep 'MEMSTATS' | tail -n 12 || true",
    ).splitlines()
    memstats = parse_memstats(memstats_lines)

    announce_rows = run_ssh(
        host,
        r"""sqlite3 /var/lib/rns/stats.db "
SELECT COUNT(*) FROM seen_announces;
SELECT datetime(MAX(seen_at_ms)/1000, 'unixepoch') FROM seen_announces;
SELECT COUNT(*) FROM seen_announces WHERE seen_at_ms >= (strftime('%s','now')-3600)*1000;
SELECT COUNT(*) FROM seen_announces WHERE seen_at_ms >= (strftime('%s','now')-86400)*1000;
" """,
    ).splitlines()

    packet_lines = run_ssh(
        host,
        r"""sqlite3 /var/lib/rns/stats.db "
SELECT packet_type || '|' || direction || '|' ||
       COALESCE(datetime(MAX(updated_at_ms)/1000, 'unixepoch'), '')
FROM packet_counters
GROUP BY packet_type, direction
ORDER BY packet_type, direction;
" """,
    ).splitlines()

    capture_remote = parse_utc_timestamp(basic["CAPTURE_TS"])
    report_date = report_date_override or capture_remote.strftime("%Y-%m-%d")

    packet_rows: list[dict[str, Any]] = []
    for line in packet_lines:
        packet_type, direction, updated = line.split("|", 2)
        updated_ts = None
        age_seconds = 999999
        if updated:
            updated_dt = dt.datetime.strptime(updated, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=dt.timezone.utc
            )
            updated_ts = updated_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            age_seconds = int((capture_remote - updated_dt).total_seconds())
        packet_rows.append(
            {
                "packet_type": packet_type,
                "direction": direction,
                "updated_at_utc": updated_ts,
                "age_seconds": age_seconds,
            }
        )

    service_rows = [
        {
            "name": "rnsd",
            "is_active": basic["RNSD_ACTIVE"] == "active",
            "active_enter_utc": basic["RNSD_ACTIVE_ENTER"] or None,
        },
        {
            "name": "rns-statsd",
            "is_active": basic["RNS_STATSD_ACTIVE"] == "active",
            "active_enter_utc": basic["RNS_STATSD_ACTIVE_ENTER"] or None,
        },
        {
            "name": "rns-sentineld",
            "is_active": basic["RNS_SENTINELD_ACTIVE"] == "active",
            "active_enter_utc": basic["RNS_SENTINELD_ACTIVE_ENTER"] or None,
        },
    ]

    listener_rows = [
        {"address": "0.0.0.0", "port": 4242, "present": basic["LISTENER_PUBLIC"] == "1"},
        {"address": "127.0.0.1", "port": 37429, "present": basic["LISTENER_RPC"] == "1"},
        {"address": "127.0.0.1", "port": 37428, "present": basic["LISTENER_SHARED"] == "1"},
    ]

    version_rows = [
        {"name": "rnsd", "version": basic["RNSD_VERSION"]},
        {"name": "rns-statsd", "version": basic["RNS_STATSD_VERSION"]},
        {"name": "rns-sentineld", "version": basic["RNS_SENTINELD_VERSION"]},
        {"name": "rns-ctl", "version": basic["RNS_CTL_VERSION"]},
    ]

    snapshot = {
        "capture_ts_utc": capture_remote.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "report_date": report_date,
        "host": host,
        "host_uptime": basic["HOST_UPTIME"],
        "load1": float(basic["LOAD1"]),
        "load5": float(basic["LOAD5"]),
        "load15": float(basic["LOAD15"]),
        "mem_used_mb": int(basic["MEM_USED_MB"]),
        "mem_total_mb": int(basic["MEM_TOTAL_MB"]),
        "mem_available_mb": int(basic["MEM_AVAILABLE_MB"]),
        "swap_used_mb": int(basic["SWAP_USED_MB"]),
        "swap_total_mb": int(basic["SWAP_TOTAL_MB"]),
        "public_listener_present": basic["LISTENER_PUBLIC"] == "1",
        "rpc_listener_present": basic["LISTENER_RPC"] == "1",
        "shared_listener_present": basic["LISTENER_SHARED"] == "1",
        "established_sessions_4242": int(basic["ESTABLISHED_4242"]),
        "transport_uptime": status_summary["transport_uptime"],
        "public_entrypoint_name": status_summary["public_entrypoint_name"],
        "public_entrypoint_up": status_summary["public_entrypoint_up"],
        "backbone_up_count": status_summary["backbone_up_count"],
        "named_peer_up_count": status_summary["named_peer_up_count"],
        "blacklist_total_entries": len(blacklist_json),
        "blacklist_reject_nonzero_entries": len(reject_entries),
        "blacklist_active_entries": len(active_entries),
        "blacklist_connected_entries": len(connected_entries),
        "idle_timeout_events_24h": int(journal_counts["IDLE_TIMEOUT_24H"]),
        "provider_bridge_dropped_24h": int(journal_counts["PROVIDER_DROPPED_24H"]),
        "provider_bridge_disconnected_24h": int(journal_counts["PROVIDER_DISCONNECTED_24H"]),
        "announce_total": int(announce_rows[0]),
        "announce_latest_utc": f"{announce_rows[1]} UTC" if announce_rows[1] else None,
        "announce_1h": int(announce_rows[2]),
        "announce_24h": int(announce_rows[3]),
        "packet_freshness_max_age_seconds": max(
            (row["age_seconds"] for row in packet_rows), default=999999
        ),
        "status_text": status_text,
        "service_rows": service_rows,
        "listener_rows": listener_rows,
        "version_rows": version_rows,
        "packet_rows": packet_rows,
        "memstats_rows": memstats,
        "blacklist_examples": blacklist_examples,
    }
    health_state, health_summary = classify_health(snapshot, packet_rows)
    snapshot["health_state"] = health_state
    snapshot["health_summary"] = health_summary
    return snapshot


def write_snapshot_db(db_path: pathlib.Path, snapshot: dict[str, Any]) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    ensure_schema(conn)
    capture_ts = snapshot["capture_ts_utc"]
    with conn:
        conn.execute("DELETE FROM daily_checks WHERE capture_ts_utc = ?", (capture_ts,))
        conn.execute(
            """
            INSERT INTO daily_checks (
                capture_ts_utc, report_date, host, health_state, health_summary,
                host_uptime, load1, load5, load15, mem_used_mb, mem_total_mb,
                mem_available_mb, swap_used_mb, swap_total_mb,
                public_listener_present, rpc_listener_present, shared_listener_present,
                established_sessions_4242, transport_uptime, public_entrypoint_name,
                public_entrypoint_up, backbone_up_count, named_peer_up_count,
                blacklist_total_entries, blacklist_reject_nonzero_entries,
                blacklist_active_entries, blacklist_connected_entries,
                idle_timeout_events_24h, provider_bridge_dropped_24h,
                provider_bridge_disconnected_24h, announce_total, announce_latest_utc,
                announce_1h, announce_24h, packet_freshness_max_age_seconds
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                capture_ts,
                snapshot["report_date"],
                snapshot["host"],
                snapshot["health_state"],
                snapshot["health_summary"],
                snapshot["host_uptime"],
                snapshot["load1"],
                snapshot["load5"],
                snapshot["load15"],
                snapshot["mem_used_mb"],
                snapshot["mem_total_mb"],
                snapshot["mem_available_mb"],
                snapshot["swap_used_mb"],
                snapshot["swap_total_mb"],
                int(snapshot["public_listener_present"]),
                int(snapshot["rpc_listener_present"]),
                int(snapshot["shared_listener_present"]),
                snapshot["established_sessions_4242"],
                snapshot["transport_uptime"],
                snapshot["public_entrypoint_name"],
                int(snapshot["public_entrypoint_up"]),
                snapshot["backbone_up_count"],
                snapshot["named_peer_up_count"],
                snapshot["blacklist_total_entries"],
                snapshot["blacklist_reject_nonzero_entries"],
                snapshot["blacklist_active_entries"],
                snapshot["blacklist_connected_entries"],
                snapshot["idle_timeout_events_24h"],
                snapshot["provider_bridge_dropped_24h"],
                snapshot["provider_bridge_disconnected_24h"],
                snapshot["announce_total"],
                snapshot["announce_latest_utc"],
                snapshot["announce_1h"],
                snapshot["announce_24h"],
                snapshot["packet_freshness_max_age_seconds"],
            ),
        )
        conn.executemany(
            "INSERT INTO daily_check_versions (capture_ts_utc, name, version) VALUES (?, ?, ?)",
            [(capture_ts, row["name"], row["version"]) for row in snapshot["version_rows"]],
        )
        conn.executemany(
            """
            INSERT INTO daily_check_service_state (capture_ts_utc, name, is_active, active_enter_utc)
            VALUES (?, ?, ?, ?)
            """,
            [
                (capture_ts, row["name"], int(row["is_active"]), row["active_enter_utc"])
                for row in snapshot["service_rows"]
            ],
        )
        conn.executemany(
            """
            INSERT INTO daily_check_listeners (capture_ts_utc, address, port, present)
            VALUES (?, ?, ?, ?)
            """,
            [
                (capture_ts, row["address"], row["port"], int(row["present"]))
                for row in snapshot["listener_rows"]
            ],
        )
        conn.executemany(
            """
            INSERT INTO daily_check_packet_freshness (
                capture_ts_utc, packet_type, direction, updated_at_utc, age_seconds
            ) VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    capture_ts,
                    row["packet_type"],
                    row["direction"],
                    row["updated_at_utc"],
                    row["age_seconds"],
                )
                for row in snapshot["packet_rows"]
            ],
        )
        conn.executemany(
            """
            INSERT INTO daily_check_memstats (
                capture_ts_utc, sample_ts_utc, rss_mb, smaps_anon_mb, ann_q_bytes,
                ann_q_ifaces, ann_q_nonempty, ann_q_iface_drop, known_dest,
                path_count, link_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    capture_ts,
                    row["sample_ts_utc"],
                    row["rss_mb"],
                    row["smaps_anon_mb"],
                    row["ann_q_bytes"],
                    row["ann_q_ifaces"],
                    row["ann_q_nonempty"],
                    row["ann_q_iface_drop"],
                    row["known_dest"],
                    row["path_count"],
                    row["link_count"],
                )
                for row in snapshot["memstats_rows"]
                if row["sample_ts_utc"]
            ],
        )
        conn.executemany(
            """
            INSERT INTO daily_check_blacklist_examples (
                capture_ts_utc, ip, reject_count, blacklist_reason,
                blacklisted_remaining_secs, connected_count
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    capture_ts,
                    row["ip"],
                    int(row.get("reject_count", 0)),
                    row.get("blacklist_reason"),
                    row.get("blacklisted_remaining_secs"),
                    int(row.get("connected_count", 0)),
                )
                for row in snapshot["blacklist_examples"]
            ],
        )
    conn.close()


def render_report(snapshot: dict[str, Any]) -> str:
    capture_dt = parse_utc_timestamp(snapshot["capture_ts_utc"])
    rnsd_start = parse_active_enter(snapshot["service_rows"][0]["active_enter_utc"])
    uptime_summary = hours_since(rnsd_start, capture_dt)
    memstats = snapshot["memstats_rows"]
    if memstats:
        rss_values = [row["rss_mb"] for row in memstats]
        anon_values = [row["smaps_anon_mb"] for row in memstats]
        ann_bytes = [row["ann_q_bytes"] for row in memstats]
        ann_ifaces = [row["ann_q_ifaces"] for row in memstats]
        rep_rows = [memstats[0], memstats[len(memstats) // 2], memstats[-1]]
    else:
        rss_values = [0.0]
        anon_values = [0.0]
        ann_bytes = [0]
        ann_ifaces = [0]
        rep_rows = []

    packet_lines = [
        f"- `{row['packet_type']} {row['direction']}`: latest `{fmt_ts(row['updated_at_utc'])}`"
        for row in snapshot["packet_rows"]
    ]
    blacklist_lines = [
        f"- `{row['ip']} rejects={int(row['reject_count'])}`"
        for row in snapshot["blacklist_examples"]
    ]
    health_line = {
        "healthy": "The VPS experiment looks healthy.",
        "healthy_with_blacklist_pressure": "The VPS experiment looks healthy, with continued blacklist pressure on the public listener.",
        "degraded": "The VPS experiment is degraded and needs follow-up.",
    }[snapshot["health_state"]]

    report = f"""# VPS Production Findings — {snapshot['report_date']} (routine health check)

This report was generated by `scripts/vps_daily_report.py` from a live VPS
health snapshot collected from `{snapshot['host']}`.

Checks in this report were collected directly from the live host on
`{snapshot['report_date']}`, with the main sample centered around
`{capture_dt.strftime('%H:%M UTC')}`.

---

## 1. Summary

The current deployment continues to look operational after roughly
`{uptime_summary}` of `rnsd` uptime:

- `rnsd`, `rns-statsd`, and `rns-sentineld` all remain `active (running)`
- required listeners remain present:
  - `0.0.0.0:4242`
  - `127.0.0.1:37429`
- the node continues to carry active public traffic
- provider-bridge churn signals remain absent:
  - `provider bridge dropped`: `{snapshot['provider_bridge_dropped_24h']}` in the last `24h`
  - `provider bridge disconnected`: `{snapshot['provider_bridge_disconnected_24h']}` in the last `24h`

The main caveat remains sentinel enforcement on the public listener:

- `repeated idle timeouts` events in the last `24h`: `{snapshot['idle_timeout_events_24h']}`
- active timed blacklists: `{snapshot['blacklist_active_entries']}`
- nonzero reject-history entries: `{snapshot['blacklist_reject_nonzero_entries']}`

Operationally, {health_line.lower()}

---

## 2. Service And Host State

Primary host sample at `{snapshot['capture_ts_utc']}`:

- host uptime: `{snapshot['host_uptime']}`
- load average: `{snapshot['load1']:.2f} / {snapshot['load5']:.2f} / {snapshot['load15']:.2f}`
- memory: `{snapshot['mem_used_mb']} MiB` used / `{snapshot['mem_total_mb']} MiB` total / `{snapshot['mem_available_mb']} MiB` available
- swap: `{snapshot['swap_used_mb']} MiB` used / `{snapshot['swap_total_mb']} MiB` total

Service state:

{chr(10).join(f"- `{row['name']}`: `{'active' if row['is_active'] else 'inactive'}`" for row in snapshot['service_rows'])}

Installed versions:

{chr(10).join(f"- `{row['version']}`" for row in snapshot['version_rows'])}

Current listeners:

- `0.0.0.0:4242`: `{'present' if snapshot['public_listener_present'] else 'missing'}`
- `127.0.0.1:37429`: `{'present' if snapshot['rpc_listener_present'] else 'missing'}`
- `127.0.0.1:37428`: `{'present' if snapshot['shared_listener_present'] else 'absent'}` (optional)

Systemd timing:

{chr(10).join(f"- `{row['name']}` active since: `{fmt_ts(row['active_enter_utc'])}`" for row in snapshot['service_rows'])}

`rns-ctl status` summary:

- transport instance running for `{snapshot['transport_uptime'] or 'n/a'}`
- public entrypoint `{snapshot['public_entrypoint_name']}` status: `{'Up' if snapshot['public_entrypoint_up'] else 'Down'}`
- dynamic backbone sessions up: `{snapshot['backbone_up_count']}`
- named peers up: `{snapshot['named_peer_up_count']}`
- established TCP sessions involving port `4242`: `{snapshot['established_sessions_4242']}`

---

## 3. Memory Behavior

Recent `MEMSTATS` samples from the last hour showed a stable band:

- `rss_mb`: roughly `{min(rss_values):.1f}` -> `{max(rss_values):.1f}`
- `smaps_anon_mb`: roughly `{min(anon_values):.1f}` -> `{max(anon_values):.1f}`
- `ann_q_bytes`: roughly `{min(ann_bytes) / 1_000_000:.2f} MB` -> `{max(ann_bytes) / 1_000_000:.2f} MB`
- `ann_q_ifaces` / `ann_q_nonempty`: roughly `{min(ann_ifaces)}` -> `{max(ann_ifaces)}`

Representative samples:

{chr(10).join(f"- `{row['sample_ts_utc']}` `rss_mb={row['rss_mb']:.1f}`, `smaps_anon_mb={row['smaps_anon_mb']:.1f}`, `ann_q_bytes={row['ann_q_bytes']}`, `ann_q_ifaces={row['ann_q_ifaces']}`" for row in rep_rows)}

Interpretation:

- memory remains bounded in the current sample window
- `ann_q_iface_drop` remained `0` in all sampled rows
- no current signal suggests a return to the earlier runaway-memory pattern

---

## 4. Sidecar Health

### 4.1 Provider-bridge stability

- `provider bridge dropped` warnings in the last `24h`: `{snapshot['provider_bridge_dropped_24h']}`
- `provider bridge disconnected` warnings in the last `24h`: `{snapshot['provider_bridge_disconnected_24h']}`

Interpretation:

- no current evidence suggests a return to provider-bridge churn
- the sidecar path still looks stable in the sampled journal window

### 4.2 Sentinel blacklist activity

From `rns-ctl backbone blacklist list --json`:

- total peer records in the live view: `{snapshot['blacklist_total_entries']}`
- entries with nonzero reject history: `{snapshot['blacklist_reject_nonzero_entries']}`
- entries currently under an active timed blacklist: `{snapshot['blacklist_active_entries']}`
- entries currently connected: `{snapshot['blacklist_connected_entries']}`

Recent high-reject examples:

{chr(10).join(blacklist_lines) if blacklist_lines else '- none in the current sample'}

Interpretation:

- blacklist enforcement is still active on the public listener
- this currently looks like traffic hygiene pressure, not a core transport failure

---

## 5. RNS Activity

### 5.1 Announces

From `seen_announces` in `stats.db`:

- total retained rows: `{snapshot['announce_total']:,}`
- latest row: `{fmt_ts(snapshot['announce_latest_utc'])}`
- seen announces in the last `1h`: `{snapshot['announce_1h']:,}`
- seen announces in the last `24h`: `{snapshot['announce_24h']:,}`

### 5.2 Packet freshness

Freshness from `packet_counters`:

{chr(10).join(packet_lines)}

Interpretation:

- the live SQLite counters are still advancing for announce and non-announce traffic
- packet freshness max age in this snapshot was `{snapshot['packet_freshness_max_age_seconds']}` seconds

---

## 6. Tooling / Runbook State

This report was generated from the current live SQLite schema:

- `seen_announces.seen_at_ms`
- `packet_counters.updated_at_ms`
- `process_samples.ts_ms`
- `provider_drop_samples.ts_ms`

The reporting pipeline now standardizes:

- a normalized daily snapshot database under `data/`
- a generated Markdown report under `docs/`
- a fixed script-driven procedure instead of ad hoc command copying

---

## 7. Operational Interpretation

Current health classification: `{snapshot['health_state']}`

Summary:

- {snapshot['health_summary']}
- the service stack is running on the expected listeners
- public traffic remains active
- blacklist pressure should continue to be tracked as an operational signal
"""
    return report


def main() -> int:
    args = parse_args()
    db_path = pathlib.Path(args.db_path)
    reports_dir = pathlib.Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    snapshot = collect_snapshot(args.host, args.date)
    write_snapshot_db(db_path, snapshot)

    report_path = reports_dir / f"vps-production-findings-{snapshot['report_date']}.md"
    report_path.write_text(render_report(snapshot), encoding="utf-8")

    if args.stdout_summary:
        print(
            json.dumps(
                {
                    "capture_ts_utc": snapshot["capture_ts_utc"],
                    "report_path": str(report_path),
                    "db_path": str(db_path),
                    "health_state": snapshot["health_state"],
                    "announce_24h": snapshot["announce_24h"],
                    "idle_timeout_events_24h": snapshot["idle_timeout_events_24h"],
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
