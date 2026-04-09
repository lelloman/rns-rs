#!/usr/bin/env python3
"""Collect a daily VPS snapshot into a local SQLite database."""

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


ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "data" / "vps_daily_reports.db"
MEMSTATS_RE = re.compile(r"MEMSTATS\s+(.*)$")
KV_RE = re.compile(r"([a-zA-Z0-9_]+)=([^\s]+)")


def run(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr.strip()}"
        )
    return proc.stdout


def run_ssh(host: str, script: str) -> str:
    remote = f"bash -lc {shlex.quote(script)}"
    return run(["ssh", host, remote])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect a VPS daily snapshot into SQLite.")
    parser.add_argument("--host", default="root@vps", help="SSH target")
    parser.add_argument(
        "--db-path",
        default=str(DEFAULT_DB),
        help="Local SQLite DB path for collected daily snapshots",
    )
    parser.add_argument(
        "--date",
        help="Override report date (YYYY-MM-DD). Default: current UTC date on the VPS capture.",
    )
    parser.add_argument(
        "--stdout-summary",
        action="store_true",
        help="Print the inserted snapshot summary as JSON",
    )
    return parser.parse_args()


def parse_kv(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def parse_utc(value: str) -> dt.datetime:
    return dt.datetime.strptime(value, "%Y-%m-%d %H:%M:%S UTC").replace(
        tzinfo=dt.timezone.utc
    )


def parse_status(text: str) -> dict[str, object]:
    transport_uptime = ""
    public_entrypoint_name = ""
    public_entrypoint_up = False
    backbone_up_count = 0
    named_peer_up_count = 0

    section_name: str | None = None
    section_status: str | None = None
    sections: list[tuple[str, str | None]] = []

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
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
                sections.append((section_name, section_status))
            section_name = stripped
            section_status = None
            continue
        if indent >= 4 and stripped.startswith("Status") and ":" in stripped:
            section_status = stripped.split(":", 1)[1].strip()
    if section_name is not None:
        sections.append((section_name, section_status))

    if sections:
        public_entrypoint_name = sections[0][0]
        public_entrypoint_up = sections[0][1] == "Up"
    for name, status in sections[1:]:
        if status != "Up":
            continue
        if name.startswith("BackboneInterface/"):
            backbone_up_count += 1
        else:
            named_peer_up_count += 1

    return {
        "transport_uptime": transport_uptime,
        "public_entrypoint_name": public_entrypoint_name,
        "public_entrypoint_up": public_entrypoint_up,
        "backbone_up_count": backbone_up_count,
        "named_peer_up_count": named_peer_up_count,
    }


def parse_memstats(lines: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line in lines.splitlines():
        match = MEMSTATS_RE.search(line)
        if not match:
            continue
        ts_match = re.search(r"\[([0-9T:\-]+)Z", line)
        if not ts_match:
            continue
        sample_ts = (
            dt.datetime.strptime(ts_match.group(1), "%Y-%m-%dT%H:%M:%S")
            .replace(tzinfo=dt.timezone.utc)
            .strftime("%Y-%m-%d %H:%M:%S UTC")
        )
        values = {k: v for k, v in KV_RE.findall(match.group(1))}
        rows.append(
            {
                "sample_ts_utc": sample_ts,
                "rss_mb": float(values.get("rss_mb", "0")),
                "smaps_anon_mb": float(values.get("smaps_anon_mb", "0")),
                "ann_q_bytes": int(float(values.get("ann_q_bytes", "0"))),
                "ann_q_ifaces": int(float(values.get("ann_q_ifaces", "0"))),
                "ann_q_nonempty": int(float(values.get("ann_q_nonempty", "0"))),
                "ann_q_iface_drop": int(float(values.get("ann_q_iface_drop", "0"))),
            }
        )
    return rows


def ensure_schema(conn: sqlite3.Connection) -> None:
    existing = {
        row[1]
        for row in conn.execute("PRAGMA table_info(daily_checks)").fetchall()
    }
    expected_core = {
        "capture_ts_utc",
        "report_date",
        "host",
        "rnsd_active",
        "announce_24h",
        "health_state",
    }
    if existing and not expected_core.issubset(existing):
        conn.executescript(
            """
            DROP TABLE IF EXISTS memstats_samples;
            DROP TABLE IF EXISTS packet_freshness;
            DROP TABLE IF EXISTS daily_checks;
            """
        )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS daily_checks (
            capture_ts_utc TEXT PRIMARY KEY,
            report_date TEXT NOT NULL,
            host TEXT NOT NULL,
            host_uptime TEXT NOT NULL,
            load1 REAL NOT NULL,
            load5 REAL NOT NULL,
            load15 REAL NOT NULL,
            mem_used_mb INTEGER NOT NULL,
            mem_total_mb INTEGER NOT NULL,
            mem_available_mb INTEGER NOT NULL,
            swap_used_mb INTEGER NOT NULL,
            swap_total_mb INTEGER NOT NULL,
            rnsd_active INTEGER NOT NULL,
            rns_statsd_active INTEGER NOT NULL,
            rns_sentineld_active INTEGER NOT NULL,
            rnsd_active_since_utc TEXT,
            rns_statsd_active_since_utc TEXT,
            rns_sentineld_active_since_utc TEXT,
            rnsd_version TEXT NOT NULL,
            rns_statsd_version TEXT NOT NULL,
            rns_sentineld_version TEXT NOT NULL,
            rns_ctl_version TEXT NOT NULL,
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
            provider_bridge_dropped_24h INTEGER NOT NULL,
            provider_bridge_disconnected_24h INTEGER NOT NULL,
            idle_timeout_events_24h INTEGER NOT NULL,
            announce_total INTEGER NOT NULL,
            announce_latest_utc TEXT,
            announce_1h INTEGER NOT NULL,
            announce_24h INTEGER NOT NULL,
            packet_freshness_max_age_seconds INTEGER NOT NULL,
            health_state TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS memstats_samples (
            capture_ts_utc TEXT NOT NULL,
            sample_ts_utc TEXT NOT NULL,
            rss_mb REAL NOT NULL,
            smaps_anon_mb REAL NOT NULL,
            ann_q_bytes INTEGER NOT NULL,
            ann_q_ifaces INTEGER NOT NULL,
            ann_q_nonempty INTEGER NOT NULL,
            ann_q_iface_drop INTEGER NOT NULL,
            PRIMARY KEY (capture_ts_utc, sample_ts_utc),
            FOREIGN KEY (capture_ts_utc) REFERENCES daily_checks(capture_ts_utc) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS packet_freshness (
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


def classify(snapshot: dict[str, object]) -> str:
    services_ok = (
        snapshot["rnsd_active"]
        and snapshot["rns_statsd_active"]
        and snapshot["rns_sentineld_active"]
    )
    listeners_ok = snapshot["public_listener_present"] and snapshot["rpc_listener_present"]
    bridge_ok = (
        snapshot["provider_bridge_dropped_24h"] == 0
        and snapshot["provider_bridge_disconnected_24h"] == 0
    )
    traffic_ok = snapshot["announce_24h"] > 0 and snapshot["packet_freshness_max_age_seconds"] <= 1800
    if not services_ok or not listeners_ok or not bridge_ok or not traffic_ok:
        return "degraded"
    if snapshot["idle_timeout_events_24h"] > 0:
        return "healthy_with_blacklist_pressure"
    return "healthy"


def collect_snapshot(host: str, report_date_override: str | None) -> tuple[dict[str, object], list[dict[str, object]], list[dict[str, object]]]:
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
    basic = parse_kv(run_ssh(host, basic_script))
    status = parse_status(run_ssh(host, "/usr/local/bin/rns-ctl status"))
    blacklist = json.loads(run_ssh(host, "/usr/local/bin/rns-ctl backbone blacklist list --json"))

    journal_counts = parse_kv(
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
    memstats = parse_memstats(
        run_ssh(
            host,
            r"journalctl -u rnsd --since '1 hour ago' --no-pager | grep 'MEMSTATS' | tail -n 12 || true",
        )
    )

    ann_rows = run_ssh(
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

    capture_ts = basic["CAPTURE_TS"]
    capture_dt = parse_utc(capture_ts)
    packet_rows: list[dict[str, object]] = []
    for line in packet_lines:
        packet_type, direction, updated = line.split("|", 2)
        updated_utc = None
        age_seconds = 999999
        if updated:
            updated_dt = dt.datetime.strptime(updated, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=dt.timezone.utc
            )
            updated_utc = updated_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            age_seconds = int((capture_dt - updated_dt).total_seconds())
        packet_rows.append(
            {
                "packet_type": packet_type,
                "direction": direction,
                "updated_at_utc": updated_utc,
                "age_seconds": age_seconds,
            }
        )

    snapshot: dict[str, object] = {
        "capture_ts_utc": capture_ts,
        "report_date": report_date_override or capture_dt.strftime("%Y-%m-%d"),
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
        "rnsd_active": int(basic["RNSD_ACTIVE"] == "active"),
        "rns_statsd_active": int(basic["RNS_STATSD_ACTIVE"] == "active"),
        "rns_sentineld_active": int(basic["RNS_SENTINELD_ACTIVE"] == "active"),
        "rnsd_active_since_utc": basic["RNSD_ACTIVE_ENTER"] or None,
        "rns_statsd_active_since_utc": basic["RNS_STATSD_ACTIVE_ENTER"] or None,
        "rns_sentineld_active_since_utc": basic["RNS_SENTINELD_ACTIVE_ENTER"] or None,
        "rnsd_version": basic["RNSD_VERSION"],
        "rns_statsd_version": basic["RNS_STATSD_VERSION"],
        "rns_sentineld_version": basic["RNS_SENTINELD_VERSION"],
        "rns_ctl_version": basic["RNS_CTL_VERSION"],
        "public_listener_present": int(basic["LISTENER_PUBLIC"] == "1"),
        "rpc_listener_present": int(basic["LISTENER_RPC"] == "1"),
        "shared_listener_present": int(basic["LISTENER_SHARED"] == "1"),
        "established_sessions_4242": int(basic["ESTABLISHED_4242"]),
        "transport_uptime": status["transport_uptime"],
        "public_entrypoint_name": status["public_entrypoint_name"],
        "public_entrypoint_up": int(status["public_entrypoint_up"]),
        "backbone_up_count": int(status["backbone_up_count"]),
        "named_peer_up_count": int(status["named_peer_up_count"]),
        "blacklist_total_entries": len(blacklist),
        "blacklist_reject_nonzero_entries": sum(1 for row in blacklist if row.get("reject_count", 0) > 0),
        "blacklist_active_entries": sum(1 for row in blacklist if row.get("blacklisted_remaining_secs") is not None),
        "blacklist_connected_entries": sum(1 for row in blacklist if row.get("connected_count", 0) > 0),
        "provider_bridge_dropped_24h": int(journal_counts["PROVIDER_DROPPED_24H"]),
        "provider_bridge_disconnected_24h": int(journal_counts["PROVIDER_DISCONNECTED_24H"]),
        "idle_timeout_events_24h": int(journal_counts["IDLE_TIMEOUT_24H"]),
        "announce_total": int(ann_rows[0]),
        "announce_latest_utc": f"{ann_rows[1]} UTC" if ann_rows[1] else None,
        "announce_1h": int(ann_rows[2]),
        "announce_24h": int(ann_rows[3]),
        "packet_freshness_max_age_seconds": max((row["age_seconds"] for row in packet_rows), default=999999),
    }
    snapshot["health_state"] = classify(snapshot)
    return snapshot, memstats, packet_rows


def write_db(db_path: pathlib.Path, snapshot: dict[str, object], memstats: list[dict[str, object]], packet_rows: list[dict[str, object]]) -> None:
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
                capture_ts_utc, report_date, host, host_uptime, load1, load5, load15,
                mem_used_mb, mem_total_mb, mem_available_mb, swap_used_mb, swap_total_mb,
                rnsd_active, rns_statsd_active, rns_sentineld_active,
                rnsd_active_since_utc, rns_statsd_active_since_utc, rns_sentineld_active_since_utc,
                rnsd_version, rns_statsd_version, rns_sentineld_version, rns_ctl_version,
                public_listener_present, rpc_listener_present, shared_listener_present,
                established_sessions_4242, transport_uptime, public_entrypoint_name,
                public_entrypoint_up, backbone_up_count, named_peer_up_count,
                blacklist_total_entries, blacklist_reject_nonzero_entries,
                blacklist_active_entries, blacklist_connected_entries,
                provider_bridge_dropped_24h, provider_bridge_disconnected_24h,
                idle_timeout_events_24h, announce_total, announce_latest_utc,
                announce_1h, announce_24h, packet_freshness_max_age_seconds, health_state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            tuple(snapshot[key] for key in [
                "capture_ts_utc", "report_date", "host", "host_uptime", "load1", "load5", "load15",
                "mem_used_mb", "mem_total_mb", "mem_available_mb", "swap_used_mb", "swap_total_mb",
                "rnsd_active", "rns_statsd_active", "rns_sentineld_active",
                "rnsd_active_since_utc", "rns_statsd_active_since_utc", "rns_sentineld_active_since_utc",
                "rnsd_version", "rns_statsd_version", "rns_sentineld_version", "rns_ctl_version",
                "public_listener_present", "rpc_listener_present", "shared_listener_present",
                "established_sessions_4242", "transport_uptime", "public_entrypoint_name",
                "public_entrypoint_up", "backbone_up_count", "named_peer_up_count",
                "blacklist_total_entries", "blacklist_reject_nonzero_entries",
                "blacklist_active_entries", "blacklist_connected_entries",
                "provider_bridge_dropped_24h", "provider_bridge_disconnected_24h",
                "idle_timeout_events_24h", "announce_total", "announce_latest_utc",
                "announce_1h", "announce_24h", "packet_freshness_max_age_seconds", "health_state"
            ]),
        )
        conn.executemany(
            """
            INSERT INTO memstats_samples (
                capture_ts_utc, sample_ts_utc, rss_mb, smaps_anon_mb,
                ann_q_bytes, ann_q_ifaces, ann_q_nonempty, ann_q_iface_drop
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
                )
                for row in memstats
            ],
        )
        conn.executemany(
            """
            INSERT INTO packet_freshness (
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
                for row in packet_rows
            ],
        )
    conn.close()


def main() -> int:
    args = parse_args()
    snapshot, memstats, packet_rows = collect_snapshot(args.host, args.date)
    db_path = pathlib.Path(args.db_path)
    write_db(db_path, snapshot, memstats, packet_rows)
    if args.stdout_summary:
        print(json.dumps({
            "capture_ts_utc": snapshot["capture_ts_utc"],
            "report_date": snapshot["report_date"],
            "db_path": str(db_path),
            "health_state": snapshot["health_state"],
            "announce_24h": snapshot["announce_24h"],
            "idle_timeout_events_24h": snapshot["idle_timeout_events_24h"],
            "public_entrypoint_name": snapshot["public_entrypoint_name"],
            "public_entrypoint_up": bool(snapshot["public_entrypoint_up"]),
        }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
