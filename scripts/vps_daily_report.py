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
DEFAULT_CONFIG_DIR = "/var/lib/rns-node"
DEFAULT_HTTP_PORT = 18080
DEFAULT_MASTER_REF = "origin/master"
DEFAULT_DEV_REF = "origin/dev"
MEMSTATS_RE = re.compile(r"MEMSTATS\s+(.*)$")
KV_RE = re.compile(r"([a-zA-Z0-9_]+)=([^\s]+)")
PACKAGE_VERSION_RE = re.compile(r'(?m)^version\s*=\s*"(\d+)\.(\d+)\.[^"]+"')
MODE_NAMES = {
    0: "Disabled",
    1: "Full",
    2: "Access Point",
    3: "Point-to-Point",
    4: "Roaming",
    5: "Boundary",
    6: "Gateway",
    7: "Internal",
}


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


def run_git(args: list[str]) -> str:
    return run(["git", "-C", str(ROOT), *args]).strip()


def expected_binary_version(binary_name: str, ref: str, manifest_path: str) -> str:
    manifest = run_git(["show", f"{ref}:{manifest_path}"])
    match = PACKAGE_VERSION_RE.search(manifest)
    if not match:
        raise RuntimeError(f"could not parse package version from {ref}:{manifest_path}")
    major, minor = match.groups()
    commit_count = run_git(["rev-list", "--count", ref])
    commit_hash = run_git(["rev-parse", "--short", ref])
    return f"{binary_name} {major}.{minor}.{commit_count}-{commit_hash}"


def expected_binary_versions(master_ref: str, dev_ref: str) -> dict[str, object]:
    return {
        "master_ref": master_ref,
        "dev_ref": dev_ref,
        "rns_server_master_version": expected_binary_version(
            "rns-server", master_ref, "rns-server/Cargo.toml"
        ),
        "rns_server_dev_version": expected_binary_version(
            "rns-server", dev_ref, "rns-server/Cargo.toml"
        ),
        "rns_ctl_master_version": expected_binary_version(
            "rns-ctl", master_ref, "rns-ctl/Cargo.toml"
        ),
        "rns_ctl_dev_version": expected_binary_version(
            "rns-ctl", dev_ref, "rns-ctl/Cargo.toml"
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect a VPS daily snapshot into SQLite.")
    parser.add_argument(
        "--host",
        default="vps-eu",
        help="Report host key. Also used as the SSH target unless --ssh-target is set.",
    )
    parser.add_argument(
        "--ssh-target",
        help="SSH target to connect to. Defaults to --host; --host is still stored in the report.",
    )
    parser.add_argument(
        "--db-path",
        default=str(DEFAULT_DB),
        help="Local SQLite DB path for collected daily snapshots",
    )
    parser.add_argument(
        "--config-dir",
        default=DEFAULT_CONFIG_DIR,
        help="Remote rns-server config root",
    )
    parser.add_argument(
        "--http-port",
        type=int,
        default=DEFAULT_HTTP_PORT,
        help="Remote embedded control-plane port",
    )
    parser.add_argument(
        "--date",
        help="Override report date (YYYY-MM-DD). Default: current UTC date on capture.",
    )
    parser.add_argument(
        "--master-ref",
        default=DEFAULT_MASTER_REF,
        help="Local git ref used as the master version baseline",
    )
    parser.add_argument(
        "--dev-ref",
        default=DEFAULT_DEV_REF,
        help="Local git ref used as the dev version baseline",
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
    primary_peer_name = ""
    primary_peer_up = False
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
        primary_peer_name = sections[0][0]
        primary_peer_up = sections[0][1] == "Up"
    for name, status in sections[1:]:
        if status != "Up":
            continue
        if name.startswith("BackboneInterface/"):
            backbone_up_count += 1
        else:
            named_peer_up_count += 1

    return {
        "transport_uptime": transport_uptime,
        "primary_peer_name": primary_peer_name,
        "primary_peer_up": primary_peer_up,
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
        "rns_server_active",
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
            config_dir TEXT NOT NULL,
            host_uptime TEXT NOT NULL,
            load1 REAL NOT NULL,
            load5 REAL NOT NULL,
            load15 REAL NOT NULL,
            mem_used_mb INTEGER NOT NULL,
            mem_total_mb INTEGER NOT NULL,
            mem_available_mb INTEGER NOT NULL,
            swap_used_mb INTEGER NOT NULL,
            swap_total_mb INTEGER NOT NULL,
            rns_server_active INTEGER NOT NULL,
            rns_server_active_since_utc TEXT,
            rns_server_version TEXT NOT NULL,
            rns_ctl_version TEXT NOT NULL,
            master_ref TEXT NOT NULL,
            dev_ref TEXT NOT NULL,
            rns_server_master_version TEXT NOT NULL,
            rns_server_dev_version TEXT NOT NULL,
            rns_server_matches_master INTEGER NOT NULL,
            rns_server_matches_dev INTEGER NOT NULL,
            rns_ctl_master_version TEXT NOT NULL,
            rns_ctl_dev_version TEXT NOT NULL,
            rns_ctl_matches_master INTEGER NOT NULL,
            rns_ctl_matches_dev INTEGER NOT NULL,
            control_plane_port INTEGER NOT NULL,
            public_listener_present INTEGER NOT NULL,
            rpc_listener_present INTEGER NOT NULL,
            control_listener_present INTEGER NOT NULL,
            child_rnsd_ready INTEGER NOT NULL,
            child_rns_statsd_ready INTEGER NOT NULL,
            child_rns_sentineld_ready INTEGER NOT NULL,
            established_sessions_4242 INTEGER NOT NULL,
            transport_uptime TEXT NOT NULL,
            primary_peer_name TEXT NOT NULL,
            primary_peer_up INTEGER NOT NULL,
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
    columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(daily_checks)").fetchall()
    }
    for column, definition in {
        "master_ref": "TEXT NOT NULL DEFAULT ''",
        "dev_ref": "TEXT NOT NULL DEFAULT ''",
        "rns_server_master_version": "TEXT NOT NULL DEFAULT ''",
        "rns_server_dev_version": "TEXT NOT NULL DEFAULT ''",
        "rns_server_matches_master": "INTEGER NOT NULL DEFAULT 0",
        "rns_server_matches_dev": "INTEGER NOT NULL DEFAULT 0",
        "rns_ctl_master_version": "TEXT NOT NULL DEFAULT ''",
        "rns_ctl_dev_version": "TEXT NOT NULL DEFAULT ''",
        "rns_ctl_matches_master": "INTEGER NOT NULL DEFAULT 0",
        "rns_ctl_matches_dev": "INTEGER NOT NULL DEFAULT 0",
    }.items():
        if column not in columns:
            conn.execute(f"ALTER TABLE daily_checks ADD COLUMN {column} {definition}")
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
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS interface_snapshots (
            capture_ts_utc TEXT NOT NULL,
            interface_id INTEGER NOT NULL,
            interface_name TEXT NOT NULL,
            interface_kind TEXT NOT NULL,
            public_candidate INTEGER NOT NULL,
            status INTEGER NOT NULL,
            mode INTEGER NOT NULL,
            mode_name TEXT NOT NULL,
            bitrate_bps INTEGER,
            rxb INTEGER NOT NULL,
            txb INTEGER NOT NULL,
            rx_packets INTEGER NOT NULL,
            tx_packets INTEGER NOT NULL,
            ia_freq REAL NOT NULL,
            oa_freq REAL NOT NULL,
            started_epoch REAL,
            uptime_seconds REAL,
            ifac_size INTEGER,
            PRIMARY KEY (capture_ts_utc, interface_id, interface_name),
            FOREIGN KEY (capture_ts_utc) REFERENCES daily_checks(capture_ts_utc) ON DELETE CASCADE
        )
        """
    )


def interface_kind(name: str) -> str:
    if name == "LocalInterface":
        return "local"
    if name.startswith("BackboneInterface/"):
        return "backbone_discovered"
    return "configured_public"


def parse_interface_snapshots(
    response: dict[str, object],
    capture_dt: dt.datetime,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    interfaces = response.get("interfaces", [])
    if not isinstance(interfaces, list):
        return rows
    capture_epoch = capture_dt.timestamp()
    for iface in interfaces:
        if not isinstance(iface, dict):
            continue
        name = str(iface.get("name") or "Unknown")
        kind = interface_kind(name)
        started_epoch = iface.get("started")
        uptime_seconds = None
        if isinstance(started_epoch, (int, float)) and started_epoch > 0:
            uptime_seconds = max(0.0, capture_epoch - float(started_epoch))
        mode = int(iface.get("mode") or 0)
        rows.append(
            {
                "interface_id": int(iface.get("id") or 0),
                "interface_name": name,
                "interface_kind": kind,
                "public_candidate": int(kind != "local"),
                "status": int(bool(iface.get("status"))),
                "mode": mode,
                "mode_name": MODE_NAMES.get(mode, "Unknown"),
                "bitrate_bps": iface.get("bitrate"),
                "rxb": int(iface.get("rxb") or 0),
                "txb": int(iface.get("txb") or 0),
                "rx_packets": int(iface.get("rx_packets") or 0),
                "tx_packets": int(iface.get("tx_packets") or 0),
                "ia_freq": float(iface.get("ia_freq") or 0.0),
                "oa_freq": float(iface.get("oa_freq") or 0.0),
                "started_epoch": float(started_epoch)
                if isinstance(started_epoch, (int, float))
                else None,
                "uptime_seconds": uptime_seconds,
                "ifac_size": iface.get("ifac_size"),
            }
        )
    return rows


def classify(snapshot: dict[str, object]) -> str:
    statsd_expected = bool(snapshot.get("child_rns_statsd_present"))
    sentineld_expected = bool(snapshot.get("child_rns_sentineld_present"))
    services_ok = (
        snapshot["rns_server_active"]
        and snapshot["child_rnsd_ready"]
        and (not statsd_expected or snapshot["child_rns_statsd_ready"])
        and (not sentineld_expected or snapshot["child_rns_sentineld_ready"])
    )
    listeners_ok = (
        snapshot["public_listener_present"]
        and snapshot["rpc_listener_present"]
        and snapshot["control_listener_present"]
    )
    bridge_ok = (
        snapshot["provider_bridge_dropped_24h"] == 0
        and snapshot["provider_bridge_disconnected_24h"] == 0
    )
    traffic_ok = snapshot["announce_24h"] > 0
    public_interfaces_total = int(snapshot.get("public_interfaces_total") or 0)
    public_interfaces_up = int(snapshot.get("public_interfaces_up") or 0)
    if not services_ok or not listeners_ok or not bridge_ok or not traffic_ok:
        return "degraded"
    if public_interfaces_total > 0 and public_interfaces_up == 0:
        return "degraded"
    if public_interfaces_total > 0 and public_interfaces_up < public_interfaces_total:
        return "healthy_with_partial_connectivity"
    if snapshot["idle_timeout_events_24h"] > 0:
        return "healthy_with_blacklist_pressure"
    return "healthy"


def collect_snapshot(
    host: str,
    ssh_target: str | None,
    config_dir: str,
    http_port: int,
    report_date_override: str | None,
    version_refs: dict[str, object],
) -> tuple[
    dict[str, object],
    list[dict[str, object]],
    list[dict[str, object]],
    list[dict[str, object]],
]:
    ssh_host = ssh_target or host
    quoted_config = shlex.quote(config_dir)
    basic_script = f"""
set -euo pipefail
capture_ts=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
read -r load1 load5 load15 _ < /proc/loadavg
read -r mem_total mem_used _ _ _ mem_available < <(free -m | awk '/^Mem:/ {{print $2, $3, $4, $5, $6, $7}}')
read -r swap_total swap_used _ < <(free -m | awk '/^Swap:/ {{print $2, $3, $4}}')
echo "CAPTURE_TS=${{capture_ts}}"
echo "HOST_UPTIME=$(uptime -p | sed 's/^up //')"
echo "LOAD1=${{load1}}"
echo "LOAD5=${{load5}}"
echo "LOAD15=${{load15}}"
echo "MEM_TOTAL_MB=${{mem_total}}"
echo "MEM_USED_MB=${{mem_used}}"
echo "MEM_AVAILABLE_MB=${{mem_available}}"
echo "SWAP_TOTAL_MB=${{swap_total}}"
echo "SWAP_USED_MB=${{swap_used}}"
echo "RNS_SERVER_ACTIVE=$(systemctl is-active rns-server || true)"
echo "RNS_SERVER_ACTIVE_ENTER=$(systemctl show -p ActiveEnterTimestamp --value rns-server || true)"
echo "RNS_SERVER_VERSION=$(/usr/local/bin/rns-server --version)"
echo "RNS_CTL_VERSION=$(/usr/local/bin/rns-ctl --version)"
listeners=$(ss -ltnH | awk '{{print $4}}')
if printf '%s\\n' "$listeners" | grep -qx '0.0.0.0:4242'; then echo 'LISTENER_PUBLIC=1'; else echo 'LISTENER_PUBLIC=0'; fi
if printf '%s\\n' "$listeners" | grep -qx '127.0.0.1:37429'; then echo 'LISTENER_RPC=1'; else echo 'LISTENER_RPC=0'; fi
if printf '%s\\n' "$listeners" | grep -qx '127.0.0.1:{http_port}'; then echo 'LISTENER_CONTROL=1'; else echo 'LISTENER_CONTROL=0'; fi
echo "ESTABLISHED_4242=$(ss -tn state established | awk '$4 ~ /:4242$/ || $5 ~ /:4242$/ {{count++}} END {{print count+0}}')"
"""
    basic = parse_kv(run_ssh(ssh_host, basic_script))
    status_text = run_ssh(ssh_host, f"/usr/local/bin/rns-ctl --config {quoted_config} status")
    status = parse_status(status_text)
    interface_payload = json.loads(
        run_ssh(ssh_host, f"/usr/local/bin/rns-ctl --config {quoted_config} status -j")
    )
    blacklist = json.loads(
        run_ssh(
            ssh_host,
            f"/usr/local/bin/rns-ctl --config {quoted_config} backbone blacklist list --json",
        )
    )
    process_payload = json.loads(
        run_ssh(ssh_host, f"curl -fsS http://127.0.0.1:{http_port}/api/processes")
    )
    processes = {
        row["name"]: row
        for row in process_payload.get("processes", [])
        if isinstance(row, dict) and "name" in row
    }
    process_names = set(processes)

    journal_counts = parse_kv(
        run_ssh(
            ssh_host,
            r"""
set -euo pipefail
count_journal() {
  local pattern="$1"
  local output
  local status
  set +e
  output=$(timeout 180s journalctl -u rns-server --since '24 hours ago' --no-pager --grep "$pattern" -q 2>/dev/null)
  status=$?
  set -e
  case "$status" in
    0|1)
      if [ -n "$output" ]; then
        printf '%s\n' "$output" | wc -l
      else
        printf '0\n'
      fi
      ;;
    *)
      printf -- '-1\n'
      ;;
  esac
}
echo "PROVIDER_DROPPED_24H=$(count_journal 'provider bridge dropped')"
echo "PROVIDER_DISCONNECTED_24H=$(count_journal 'provider bridge disconnected')"
echo "IDLE_TIMEOUT_24H=$(count_journal 'repeated idle timeouts')"
""",
        )
    )
    memstats = parse_memstats(
        run_ssh(
            ssh_host,
            r"timeout 180s journalctl -u rns-server --since '1 hour ago' --no-pager --grep 'MEMSTATS' -q | tail -n 12 || true",
        )
    )

    stats_db = f"{config_dir.rstrip('/')}/stats.db"
    ann_rows = run_ssh(
        ssh_host,
        f"""timeout 180s sqlite3 {shlex.quote(stats_db)} "
SELECT printf('%d\n%s\n%d\n%d',
       COUNT(*),
       COALESCE(datetime(MAX(seen_at_ms)/1000, 'unixepoch'), ''),
       COALESCE(SUM(CASE WHEN seen_at_ms >= (strftime('%s','now')-3600)*1000 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN seen_at_ms >= (strftime('%s','now')-86400)*1000 THEN 1 ELSE 0 END), 0))
FROM seen_announces;
" || printf '%s\n' -1 '' -1 -1""",
    ).splitlines()

    packet_lines = run_ssh(
        ssh_host,
        f"""timeout 180s sqlite3 {shlex.quote(stats_db)} "
SELECT packet_type || '|' || direction || '|' ||
       COALESCE(datetime(MAX(updated_at_ms)/1000, 'unixepoch'), '')
FROM packet_counters
GROUP BY packet_type, direction
ORDER BY packet_type, direction;
" || true""",
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

    interface_rows = parse_interface_snapshots(interface_payload, capture_dt)
    public_interfaces = [row for row in interface_rows if row["public_candidate"]]

    snapshot: dict[str, object] = {
        "capture_ts_utc": capture_ts,
        "report_date": report_date_override or capture_dt.strftime("%Y-%m-%d"),
        "host": host,
        "config_dir": config_dir,
        "host_uptime": basic["HOST_UPTIME"],
        "load1": float(basic["LOAD1"]),
        "load5": float(basic["LOAD5"]),
        "load15": float(basic["LOAD15"]),
        "mem_used_mb": int(basic["MEM_USED_MB"]),
        "mem_total_mb": int(basic["MEM_TOTAL_MB"]),
        "mem_available_mb": int(basic["MEM_AVAILABLE_MB"]),
        "swap_used_mb": int(basic["SWAP_USED_MB"]),
        "swap_total_mb": int(basic["SWAP_TOTAL_MB"]),
        "rns_server_active": int(basic["RNS_SERVER_ACTIVE"] == "active"),
        "rns_server_active_since_utc": basic["RNS_SERVER_ACTIVE_ENTER"] or None,
        "rns_server_version": basic["RNS_SERVER_VERSION"],
        "rns_ctl_version": basic["RNS_CTL_VERSION"],
        "master_ref": version_refs["master_ref"],
        "dev_ref": version_refs["dev_ref"],
        "rns_server_master_version": version_refs["rns_server_master_version"],
        "rns_server_dev_version": version_refs["rns_server_dev_version"],
        "rns_server_matches_master": int(
            basic["RNS_SERVER_VERSION"] == version_refs["rns_server_master_version"]
        ),
        "rns_server_matches_dev": int(
            basic["RNS_SERVER_VERSION"] == version_refs["rns_server_dev_version"]
        ),
        "rns_ctl_master_version": version_refs["rns_ctl_master_version"],
        "rns_ctl_dev_version": version_refs["rns_ctl_dev_version"],
        "rns_ctl_matches_master": int(
            basic["RNS_CTL_VERSION"] == version_refs["rns_ctl_master_version"]
        ),
        "rns_ctl_matches_dev": int(
            basic["RNS_CTL_VERSION"] == version_refs["rns_ctl_dev_version"]
        ),
        "control_plane_port": http_port,
        "public_listener_present": int(basic["LISTENER_PUBLIC"] == "1"),
        "rpc_listener_present": int(basic["LISTENER_RPC"] == "1"),
        "control_listener_present": int(basic["LISTENER_CONTROL"] == "1"),
        "child_rnsd_present": int("rnsd" in process_names),
        "child_rns_statsd_present": int("rns-statsd" in process_names),
        "child_rns_sentineld_present": int("rns-sentineld" in process_names),
        "child_rnsd_ready": int(bool(processes.get("rnsd", {}).get("ready"))),
        "child_rns_statsd_ready": int(bool(processes.get("rns-statsd", {}).get("ready"))),
        "child_rns_sentineld_ready": int(bool(processes.get("rns-sentineld", {}).get("ready"))),
        "established_sessions_4242": int(basic["ESTABLISHED_4242"]),
        "transport_uptime": status["transport_uptime"],
        "primary_peer_name": status["primary_peer_name"],
        "primary_peer_up": int(status["primary_peer_up"]),
        "backbone_up_count": int(status["backbone_up_count"]),
        "named_peer_up_count": int(status["named_peer_up_count"]),
        "blacklist_total_entries": len(blacklist),
        "blacklist_reject_nonzero_entries": sum(
            1 for row in blacklist if row.get("reject_count", 0) > 0
        ),
        "blacklist_active_entries": sum(
            1 for row in blacklist if row.get("blacklisted_remaining_secs") is not None
        ),
        "blacklist_connected_entries": sum(
            1 for row in blacklist if row.get("connected_count", 0) > 0
        ),
        "provider_bridge_dropped_24h": int(journal_counts["PROVIDER_DROPPED_24H"]),
        "provider_bridge_disconnected_24h": int(
            journal_counts["PROVIDER_DISCONNECTED_24H"]
        ),
        "idle_timeout_events_24h": int(journal_counts["IDLE_TIMEOUT_24H"]),
        "announce_total": int(ann_rows[0]),
        "announce_latest_utc": f"{ann_rows[1]} UTC" if ann_rows[1] else None,
        "announce_1h": int(ann_rows[2]),
        "announce_24h": int(ann_rows[3]),
        "packet_freshness_max_age_seconds": max(
            (row["age_seconds"] for row in packet_rows), default=999999
        ),
        "public_interfaces_total": len(public_interfaces),
        "public_interfaces_up": sum(1 for row in public_interfaces if row["status"]),
    }
    snapshot["health_state"] = classify(snapshot)
    return snapshot, memstats, packet_rows, interface_rows


def write_db(
    db_path: pathlib.Path,
    snapshot: dict[str, object],
    memstats: list[dict[str, object]],
    packet_rows: list[dict[str, object]],
    interface_rows: list[dict[str, object]],
) -> None:
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
                capture_ts_utc, report_date, host, config_dir, host_uptime, load1, load5,
                load15, mem_used_mb, mem_total_mb, mem_available_mb, swap_used_mb,
                swap_total_mb, rns_server_active, rns_server_active_since_utc,
                rns_server_version, rns_ctl_version, master_ref, dev_ref,
                rns_server_master_version, rns_server_dev_version,
                rns_server_matches_master, rns_server_matches_dev,
                rns_ctl_master_version, rns_ctl_dev_version, rns_ctl_matches_master,
                rns_ctl_matches_dev, control_plane_port, public_listener_present,
                rpc_listener_present, control_listener_present, child_rnsd_ready,
                child_rns_statsd_ready, child_rns_sentineld_ready,
                established_sessions_4242, transport_uptime, primary_peer_name,
                primary_peer_up, backbone_up_count, named_peer_up_count,
                blacklist_total_entries, blacklist_reject_nonzero_entries,
                blacklist_active_entries, blacklist_connected_entries,
                provider_bridge_dropped_24h, provider_bridge_disconnected_24h,
                idle_timeout_events_24h, announce_total, announce_latest_utc,
                announce_1h, announce_24h, packet_freshness_max_age_seconds,
                health_state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            tuple(
                snapshot[key]
                for key in [
                    "capture_ts_utc",
                    "report_date",
                    "host",
                    "config_dir",
                    "host_uptime",
                    "load1",
                    "load5",
                    "load15",
                    "mem_used_mb",
                    "mem_total_mb",
                    "mem_available_mb",
                    "swap_used_mb",
                    "swap_total_mb",
                    "rns_server_active",
                    "rns_server_active_since_utc",
                    "rns_server_version",
                    "rns_ctl_version",
                    "master_ref",
                    "dev_ref",
                    "rns_server_master_version",
                    "rns_server_dev_version",
                    "rns_server_matches_master",
                    "rns_server_matches_dev",
                    "rns_ctl_master_version",
                    "rns_ctl_dev_version",
                    "rns_ctl_matches_master",
                    "rns_ctl_matches_dev",
                    "control_plane_port",
                    "public_listener_present",
                    "rpc_listener_present",
                    "control_listener_present",
                    "child_rnsd_ready",
                    "child_rns_statsd_ready",
                    "child_rns_sentineld_ready",
                    "established_sessions_4242",
                    "transport_uptime",
                    "primary_peer_name",
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
                    "announce_latest_utc",
                    "announce_1h",
                    "announce_24h",
                    "packet_freshness_max_age_seconds",
                    "health_state",
                ]
            ),
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
        conn.executemany(
            """
            INSERT INTO interface_snapshots (
                capture_ts_utc, interface_id, interface_name, interface_kind,
                public_candidate, status, mode, mode_name, bitrate_bps, rxb, txb,
                rx_packets, tx_packets, ia_freq, oa_freq, started_epoch,
                uptime_seconds, ifac_size
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    capture_ts,
                    row["interface_id"],
                    row["interface_name"],
                    row["interface_kind"],
                    row["public_candidate"],
                    row["status"],
                    row["mode"],
                    row["mode_name"],
                    row["bitrate_bps"],
                    row["rxb"],
                    row["txb"],
                    row["rx_packets"],
                    row["tx_packets"],
                    row["ia_freq"],
                    row["oa_freq"],
                    row["started_epoch"],
                    row["uptime_seconds"],
                    row["ifac_size"],
                )
                for row in interface_rows
            ],
        )
    conn.close()


def main() -> int:
    args = parse_args()
    version_refs = expected_binary_versions(args.master_ref, args.dev_ref)
    snapshot, memstats, packet_rows, interface_rows = collect_snapshot(
        args.host,
        args.ssh_target,
        args.config_dir,
        args.http_port,
        args.date,
        version_refs,
    )
    db_path = pathlib.Path(args.db_path)
    write_db(db_path, snapshot, memstats, packet_rows, interface_rows)
    if args.stdout_summary:
        public_interfaces = [row for row in interface_rows if row["public_candidate"]]
        print(
            json.dumps(
                {
                    "capture_ts_utc": snapshot["capture_ts_utc"],
                    "report_date": snapshot["report_date"],
                    "db_path": str(db_path),
                    "health_state": snapshot["health_state"],
                    "version_refs": {
                        "master": snapshot["master_ref"],
                        "dev": snapshot["dev_ref"],
                    },
                    "rns_server_version": snapshot["rns_server_version"],
                    "rns_server_master_version": snapshot["rns_server_master_version"],
                    "rns_server_dev_version": snapshot["rns_server_dev_version"],
                    "rns_server_matches_master": bool(
                        snapshot["rns_server_matches_master"]
                    ),
                    "rns_server_matches_dev": bool(snapshot["rns_server_matches_dev"]),
                    "rns_ctl_version": snapshot["rns_ctl_version"],
                    "rns_ctl_master_version": snapshot["rns_ctl_master_version"],
                    "rns_ctl_dev_version": snapshot["rns_ctl_dev_version"],
                    "rns_ctl_matches_master": bool(snapshot["rns_ctl_matches_master"]),
                    "rns_ctl_matches_dev": bool(snapshot["rns_ctl_matches_dev"]),
                    "announce_24h": snapshot["announce_24h"],
                    "idle_timeout_events_24h": snapshot["idle_timeout_events_24h"],
                    "primary_peer_name": snapshot["primary_peer_name"],
                    "primary_peer_up": bool(snapshot["primary_peer_up"]),
                    "interfaces_total": len(interface_rows),
                    "public_interfaces_total": len(public_interfaces),
                    "public_interfaces_up": sum(
                        1 for row in public_interfaces if row["status"]
                    ),
                    "discovered_backbone_interfaces": sum(
                        1
                        for row in public_interfaces
                        if row["interface_kind"] == "backbone_discovered"
                    ),
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
