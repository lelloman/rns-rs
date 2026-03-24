#!/usr/bin/env python3
"""Three-node local benchmark harness for rns-rs.

Starts three plain `rns-ctl http` nodes on one machine:
- middle: transport-enabled TCP server
- edge-a: TCP client to middle
- edge-b: TCP client to middle

The harness runs a sequence of waves to surface different bottlenecks:
- convergence
- raw_small
- raw_large
- raw_burst
- proof_heavy
- link_setup
- resource_large
- link_data
- mixed

It writes a JSON report and an optional Markdown summary.
"""

from __future__ import annotations

import argparse
import atexit
import base64
import json
import math
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


WAVE_ORDER = [
    "convergence",
    "raw_small",
    "raw_large",
    "raw_burst",
    "proof_heavy",
    "link_setup",
    "resource_large",
    "link_data",
    "mixed",
]


def now() -> float:
    return time.time()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def json_request(
    method: str,
    url: str,
    body: dict[str, Any] | None = None,
    timeout: float = 10.0,
) -> Any:
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = resp.read()
    if not payload:
        return None
    return json.loads(payload.decode("utf-8"))


def wait_until(
    description: str,
    fn: Callable[[], bool],
    timeout: float,
    interval: float = 0.5,
) -> None:
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            if fn():
                return
        except Exception as exc:  # pragma: no cover - best effort diagnostics
            last_error = exc
        time.sleep(interval)
    if last_error is not None:
        raise RuntimeError(f"timeout waiting for {description}: {last_error}")
    raise RuntimeError(f"timeout waiting for {description}")


def find_repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def choose_open_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def read_proc_stats(pid: int) -> dict[str, float]:
    with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as handle:
        data = handle.read().strip().split()
    utime = float(data[13])
    stime = float(data[14])
    rss_pages = int(data[23])
    clk_tck = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
    page_size = os.sysconf("SC_PAGE_SIZE")
    return {
        "cpu_seconds": (utime + stime) / clk_tck,
        "rss_bytes": rss_pages * page_size,
    }


class PerfSampler:
    def __init__(self, enabled: bool, pid: int, duration_secs: float, output_path: Path):
        self.enabled = enabled
        self.pid = pid
        self.duration_secs = duration_secs
        self.output_path = output_path
        self.process: subprocess.Popen[str] | None = None

    def start(self) -> None:
        if not self.enabled:
            return
        if shutil.which("perf") is None:
            self.enabled = False
            return
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with self.output_path.open("w", encoding="utf-8") as handle:
            self.process = subprocess.Popen(
                [
                    "perf",
                    "stat",
                    "-d",
                    "-d",
                    "-p",
                    str(self.pid),
                    "sleep",
                    str(max(self.duration_secs, 0.1)),
                ],
                stdout=handle,
                stderr=subprocess.STDOUT,
                text=True,
            )

    def finish(self) -> dict[str, Any] | None:
        if not self.enabled or self.process is None:
            return None
        self.process.wait(timeout=max(self.duration_secs + 5.0, 10.0))
        return {
            "path": str(self.output_path),
            "returncode": self.process.returncode,
        }


@dataclass
class BenchNode:
    name: str
    http_port: int
    config_dir: Path
    log_path: Path
    process: subprocess.Popen[str] | None = None
    pid: int | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.http_port}"

    def get(self, path: str, timeout: float = 10.0) -> Any:
        return json_request("GET", self.base_url + path, timeout=timeout)

    def post(self, path: str, body: dict[str, Any], timeout: float = 10.0) -> Any:
        return json_request("POST", self.base_url + path, body=body, timeout=timeout)


@dataclass
class WaveResult:
    name: str
    started_at: float
    ended_at: float
    duration_secs: float
    notes: list[str] = field(default_factory=list)
    sender_stats: dict[str, Any] = field(default_factory=dict)
    counters: dict[str, Any] = field(default_factory=dict)
    process_stats: dict[str, Any] = field(default_factory=dict)
    perf: dict[str, Any] | None = None


class BenchmarkHarness:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.repo_root = find_repo_root()
        self.bin_path = self._resolve_binary()
        self.run_root = self._prepare_run_root()
        self.edge_a = self._make_node("edge-a")
        self.middle = self._make_node("middle")
        self.edge_b = self._make_node("edge-b")
        self.nodes = [self.edge_a, self.middle, self.edge_b]
        self.start_order = [self.middle, self.edge_a, self.edge_b]
        self.middle_tcp_port = choose_open_port()
        self._stop = False
        self.destinations: dict[str, str] = {}
        self.link_ids: dict[str, list[str]] = {"edge-a": [], "edge-b": []}
        self.proof_destinations_ready = False
        atexit.register(self.cleanup)

    def _resolve_binary(self) -> Path:
        if self.args.bin:
            return Path(self.args.bin).resolve()
        candidate = self.repo_root / "target" / "release" / "rns-ctl"
        if candidate.exists():
            return candidate
        return candidate

    def _prepare_run_root(self) -> Path:
        if self.args.run_dir:
            root = Path(self.args.run_dir).resolve()
            root.mkdir(parents=True, exist_ok=True)
            return root
        return Path(tempfile.mkdtemp(prefix="rns-three-node-bench-"))

    def _make_node(self, name: str) -> BenchNode:
        node_dir = self.run_root / name
        node_dir.mkdir(parents=True, exist_ok=True)
        return BenchNode(
            name=name,
            http_port=choose_open_port(),
            config_dir=node_dir,
            log_path=node_dir / "rns-ctl.log",
        )

    def log(self, message: str) -> None:
        print(message, flush=True)

    def ensure_binary(self) -> None:
        if self.bin_path.exists():
            return
        self.log("Building rns-ctl release binary...")
        subprocess.run(
            ["cargo", "build", "--release", "--bin", "rns-ctl"],
            cwd=self.repo_root,
            check=True,
        )
        if not self.bin_path.exists():
            raise RuntimeError(f"missing binary after build: {self.bin_path}")

    def write_configs(self) -> None:
        edge_cfg = textwrap.dedent(
            f"""\
            [reticulum]
            enable_transport = No
            share_instance = No

            [interfaces]
              [[Middle]]
                type = TCPClientInterface
                target_host = 127.0.0.1
                target_port = {self.middle_tcp_port}
            """
        )
        middle_cfg = textwrap.dedent(
            f"""\
            [reticulum]
            enable_transport = Yes
            share_instance = No

            [interfaces]
              [[Ingress]]
                type = TCPServerInterface
                listen_ip = 127.0.0.1
                listen_port = {self.middle_tcp_port}
                max_connections = 128
            """
        )
        (self.edge_a.config_dir / "config").write_text(edge_cfg, encoding="utf-8")
        (self.edge_b.config_dir / "config").write_text(edge_cfg, encoding="utf-8")
        (self.middle.config_dir / "config").write_text(middle_cfg, encoding="utf-8")

    def start_nodes(self) -> None:
        for node in self.start_order:
            cmd = [
                str(self.bin_path),
                "http",
                "--disable-auth",
                "--host",
                "127.0.0.1",
                "--port",
                str(node.http_port),
                "--config",
                str(node.config_dir),
            ]
            env = os.environ.copy()
            env.setdefault("RUST_LOG", "info")
            log_handle = node.log_path.open("w", encoding="utf-8")
            node.process = subprocess.Popen(
                cmd,
                cwd=self.repo_root,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
            )
            node.pid = node.process.pid
            wait_until(
                f"{node.name} health",
                lambda n=node: n.get("/health")["status"] == "healthy",
                timeout=self.args.start_timeout,
                interval=0.25,
            )
        for node in self.nodes:
            wait_until(
                f"{node.name} health",
                lambda n=node: n.get("/health")["status"] == "healthy",
                timeout=self.args.start_timeout,
                interval=0.25,
            )
        self.log("All nodes are healthy.")

    def cleanup(self) -> None:
        if self._stop:
            return
        self._stop = True
        for node in self.nodes:
            proc = node.process
            if proc is None or proc.poll() is not None:
                continue
            proc.send_signal(signal.SIGINT)
        deadline = time.time() + 5.0
        for node in self.nodes:
            proc = node.process
            if proc is None:
                continue
            try:
                timeout = max(0.1, deadline - time.time())
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
        if self.args.keep_artifacts:
            self.log(f"Artifacts kept under {self.run_root}")
        elif self.args.run_dir is None:
            shutil.rmtree(self.run_root, ignore_errors=True)

    def clear_event_queues(self) -> None:
        for node in self.nodes:
            for path in [
                "/api/packets?clear=true",
                "/api/proofs?clear=true",
                "/api/link_events?clear=true",
                "/api/resource_events?clear=true",
                "/api/announces?clear=true",
            ]:
                try:
                    node.get(path, timeout=5.0)
                except Exception:
                    pass

    def interfaces(self, node: BenchNode) -> dict[str, Any]:
        return node.get("/api/interfaces")

    def snapshot_nodes(self) -> dict[str, Any]:
        snapshot = {}
        for node in self.nodes:
            iface = self.interfaces(node)
            proc = read_proc_stats(node.pid) if node.pid else {}
            snapshot[node.name] = {
                "interfaces": iface,
                "process": proc,
            }
        return snapshot

    def diff_snapshots(self, before: dict[str, Any], after: dict[str, Any], duration: float) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for node in self.nodes:
            b = before[node.name]
            a = after[node.name]
            ifaces_before = b["interfaces"]
            ifaces_after = a["interfaces"]
            proc_before = b["process"]
            proc_after = a["process"]
            result[node.name] = {
                "total_rxb_delta": ifaces_after["total_rxb"] - ifaces_before["total_rxb"],
                "total_txb_delta": ifaces_after["total_txb"] - ifaces_before["total_txb"],
                "cpu_seconds_delta": proc_after["cpu_seconds"] - proc_before["cpu_seconds"],
                "cpu_percent": (
                    100.0 * (proc_after["cpu_seconds"] - proc_before["cpu_seconds"]) / max(duration, 0.1)
                ),
                "rss_bytes_after": proc_after["rss_bytes"],
            }
        return result

    def create_inbound_destination(
        self,
        node: BenchNode,
        app: str,
        aspect: str,
        proof_strategy: str,
    ) -> str:
        response = node.post(
            "/api/destination",
            {
                "type": "single",
                "app_name": app,
                "aspects": [aspect],
                "direction": "in",
                "proof_strategy": proof_strategy,
            },
        )
        return str(response["dest_hash"])

    def create_outbound_destination(
        self,
        node: BenchNode,
        app: str,
        aspect: str,
        remote_hash: str,
    ) -> str:
        response = node.post(
            "/api/destination",
            {
                "type": "single",
                "app_name": app,
                "aspects": [aspect],
                "direction": "out",
                "dest_hash": remote_hash,
            },
        )
        return str(response["dest_hash"])

    def announce(self, node: BenchNode, dest_hash: str) -> None:
        node.post("/api/announce", {"dest_hash": dest_hash})

    def recall_identity(self, node: BenchNode, dest_hash: str) -> Any:
        try:
            return node.get(f"/api/identity/{dest_hash}", timeout=5.0)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise

    def send_packet(self, node: BenchNode, dest_hash: str, payload: bytes) -> dict[str, Any]:
        return node.post("/api/send", {"dest_hash": dest_hash, "data": b64(payload)})

    def create_link(self, node: BenchNode, dest_hash: str) -> str:
        response = node.post("/api/link", {"dest_hash": dest_hash})
        return str(response["link_id"])

    def send_channel(self, node: BenchNode, link_id: str, msgtype: int, payload: bytes) -> None:
        node.post(
            "/api/channel",
            {"link_id": link_id, "msgtype": msgtype, "payload": b64(payload)},
        )

    def send_resource(
        self,
        node: BenchNode,
        link_id: str,
        data: bytes,
        metadata: bytes | None = None,
    ) -> None:
        body: dict[str, Any] = {"link_id": link_id, "data": b64(data)}
        if metadata is not None:
            body["metadata"] = b64(metadata)
        node.post("/api/resource", body)

    def close_link(self, node: BenchNode, link_id: str) -> None:
        node.post("/api/link/close", {"link_id": link_id})

    def active_links(self, node: BenchNode, initiator_only: bool = False) -> list[dict[str, Any]]:
        links = node.get("/api/links")["links"]
        active = [link for link in links if link.get("state") == "active"]
        if initiator_only:
            active = [link for link in active if link.get("is_initiator")]
        return active

    def request_path(self, node: BenchNode, dest_hash: str) -> None:
        node.post("/api/path/request", {"dest_hash": dest_hash})

    def has_path(self, node: BenchNode, dest_hash: str) -> bool:
        paths = node.get(f"/api/paths?dest_hash={dest_hash}")["paths"]
        return any(path.get("hash") == dest_hash for path in paths)

    def count_packets(self, node: BenchNode, clear: bool = False) -> int:
        suffix = "?clear=true" if clear else ""
        return len(node.get(f"/api/packets{suffix}")["packets"])

    def count_proofs(self, node: BenchNode, clear: bool = False) -> int:
        suffix = "?clear=true" if clear else ""
        return len(node.get(f"/api/proofs{suffix}")["proofs"])

    def count_link_events(self, node: BenchNode, clear: bool = False) -> list[dict[str, Any]]:
        suffix = "?clear=true" if clear else ""
        return list(node.get(f"/api/link_events{suffix}")["link_events"])

    def bootstrap_destinations(self) -> None:
        self.log("Bootstrapping destinations and path convergence...")
        self.destinations["edge_a_raw_in"] = self.create_inbound_destination(
            self.edge_a, "bench", "raw-edge-a", "none"
        )
        self.destinations["edge_b_raw_in"] = self.create_inbound_destination(
            self.edge_b, "bench", "raw-edge-b", "none"
        )
        self.announce(self.edge_a, self.destinations["edge_a_raw_in"])
        self.announce(self.edge_b, self.destinations["edge_b_raw_in"])

        wait_until(
            "middle announce cache",
            lambda: len(self.middle.get("/api/announces")["announces"]) >= 2,
            timeout=self.args.convergence_timeout,
            interval=0.5,
        )

        needed = [
            (self.edge_a, self.destinations["edge_b_raw_in"]),
            (self.edge_b, self.destinations["edge_a_raw_in"]),
        ]
        for node, dest_hash in needed:
            if self.recall_identity(node, dest_hash) is None:
                self.request_path(node, dest_hash)
                wait_until(
                    f"{node.name} path {dest_hash}",
                    lambda n=node, d=dest_hash: self.has_path(n, d),
                    timeout=self.args.convergence_timeout,
                    interval=0.5,
                )
                wait_until(
                    f"{node.name} identity {dest_hash}",
                    lambda n=node, d=dest_hash: self.recall_identity(n, d) is not None,
                    timeout=self.args.convergence_timeout,
                    interval=0.5,
                )

        self.destinations["edge_a_to_edge_b_raw"] = self.create_outbound_destination(
            self.edge_a, "bench", "raw-edge-b", self.destinations["edge_b_raw_in"]
        )
        self.destinations["edge_b_to_edge_a_raw"] = self.create_outbound_destination(
            self.edge_b, "bench", "raw-edge-a", self.destinations["edge_a_raw_in"]
        )
        self.clear_event_queues()

    def ensure_proof_destinations(self) -> None:
        if self.proof_destinations_ready:
            return
        self.destinations["edge_a_proof_in"] = self.create_inbound_destination(
            self.edge_a, "bench", "proof-edge-a", "all"
        )
        self.destinations["edge_b_proof_in"] = self.create_inbound_destination(
            self.edge_b, "bench", "proof-edge-b", "all"
        )
        self.announce(self.edge_a, self.destinations["edge_a_proof_in"])
        self.announce(self.edge_b, self.destinations["edge_b_proof_in"])
        for node, dest_hash in [
            (self.edge_a, self.destinations["edge_b_proof_in"]),
            (self.edge_b, self.destinations["edge_a_proof_in"]),
        ]:
            if self.recall_identity(node, dest_hash) is None:
                self.request_path(node, dest_hash)
                wait_until(
                    f"{node.name} proof path {dest_hash}",
                    lambda n=node, d=dest_hash: self.has_path(n, d),
                    timeout=self.args.convergence_timeout,
                    interval=0.5,
                )
                wait_until(
                    f"{node.name} proof identity {dest_hash}",
                    lambda n=node, d=dest_hash: self.recall_identity(n, d) is not None,
                    timeout=self.args.convergence_timeout,
                    interval=0.5,
                )
        self.destinations["edge_a_to_edge_b_proof"] = self.create_outbound_destination(
            self.edge_a, "bench", "proof-edge-b", self.destinations["edge_b_proof_in"]
        )
        self.destinations["edge_b_to_edge_a_proof"] = self.create_outbound_destination(
            self.edge_b, "bench", "proof-edge-a", self.destinations["edge_a_proof_in"]
        )
        self.proof_destinations_ready = True
        self.clear_event_queues()

    def sender_loop(
        self,
        name: str,
        fn: Callable[[int], None],
        rate: float,
        duration: float,
        stats: dict[str, Any],
    ) -> threading.Thread:
        def run() -> None:
            sent = 0
            errors = 0
            started = time.time()
            interval = 1.0 / rate if rate > 0 else 0.0
            next_deadline = started
            counter = 0
            while time.time() - started < duration:
                try:
                    fn(counter)
                    sent += 1
                except Exception:
                    errors += 1
                counter += 1
                if interval > 0:
                    next_deadline += interval
                    sleep_for = next_deadline - time.time()
                    if sleep_for > 0:
                        time.sleep(sleep_for)
            stats[name] = {"attempted": counter, "sent": sent, "errors": errors}

        thread = threading.Thread(target=run, name=name, daemon=True)
        thread.start()
        return thread

    def run_wave(
        self,
        name: str,
        body: Callable[[WaveResult], None],
        duration_secs: float | None = None,
        profile_middle: bool = False,
    ) -> WaveResult:
        self.log(f"Running wave: {name}")
        self.clear_event_queues()
        started = time.time()
        before = self.snapshot_nodes()
        perf = PerfSampler(
            enabled=profile_middle,
            pid=self.middle.pid or 0,
            duration_secs=duration_secs or self.args.duration_secs,
            output_path=self.run_root / f"perf-{name}.txt",
        )
        perf.start()
        result = WaveResult(name=name, started_at=started, ended_at=started, duration_secs=0.0)
        try:
            body(result)
        finally:
            ended = time.time()
            result.ended_at = ended
            result.duration_secs = ended - started
            after = self.snapshot_nodes()
            result.process_stats = self.diff_snapshots(before, after, result.duration_secs)
            result.perf = perf.finish()
        return result

    def wave_convergence(self) -> WaveResult:
        def body(result: WaveResult) -> None:
            edge_a_recalled = self.recall_identity(self.edge_a, self.destinations["edge_b_raw_in"])
            edge_b_recalled = self.recall_identity(self.edge_b, self.destinations["edge_a_raw_in"])
            result.counters = {
                "edge_a_recalled": edge_a_recalled is not None,
                "edge_b_recalled": edge_b_recalled is not None,
                "middle_links": len(self.active_links(self.middle)),
            }

        return self.run_wave("convergence", body, duration_secs=0.5, profile_middle=False)

    def wave_raw(self, wave_name: str, payload_size: int, proof: bool) -> WaveResult:
        if proof:
            self.ensure_proof_destinations()
        dest_a = (
            self.destinations["edge_a_to_edge_b_proof"] if proof else self.destinations["edge_a_to_edge_b_raw"]
        )
        dest_b = (
            self.destinations["edge_b_to_edge_a_proof"] if proof else self.destinations["edge_b_to_edge_a_raw"]
        )
        rate = self.args.raw_rate

        def body(result: WaveResult) -> None:
            stats: dict[str, Any] = {}

            def send_a(counter: int) -> None:
                payload = f"{wave_name}:a:{counter}:".encode("ascii").ljust(payload_size, b"a")
                self.send_packet(self.edge_a, dest_a, payload)

            def send_b(counter: int) -> None:
                payload = f"{wave_name}:b:{counter}:".encode("ascii").ljust(payload_size, b"b")
                self.send_packet(self.edge_b, dest_b, payload)

            threads = [
                self.sender_loop("edge_a", send_a, rate, self.args.duration_secs, stats),
                self.sender_loop("edge_b", send_b, rate, self.args.duration_secs, stats),
            ]
            for thread in threads:
                thread.join()

            result.sender_stats = stats
            result.counters = {
                "edge_a_packets_received": self.count_packets(self.edge_a, clear=True),
                "edge_b_packets_received": self.count_packets(self.edge_b, clear=True),
                "edge_a_proofs_received": self.count_proofs(self.edge_a, clear=True),
                "edge_b_proofs_received": self.count_proofs(self.edge_b, clear=True),
                "payload_size": payload_size,
                "proof_enabled": proof,
            }

        return self.run_wave(
            wave_name,
            body,
            duration_secs=self.args.duration_secs,
            profile_middle=self.args.profile in ("middle", "all"),
        )

    def wave_raw_burst(self) -> WaveResult:
        def body(result: WaveResult) -> None:
            stats = {"edge_a": {"attempted": 0, "sent": 0, "errors": 0}, "edge_b": {"attempted": 0, "sent": 0, "errors": 0}}

            def burst(node: BenchNode, dest_hash: str, prefix: str, key: str) -> None:
                for i in range(self.args.burst_count):
                    stats[key]["attempted"] += 1
                    payload = f"raw_burst:{prefix}:{i}".encode("ascii").ljust(self.args.raw_small_size, prefix.encode("ascii"))
                    try:
                        self.send_packet(node, dest_hash, payload)
                        stats[key]["sent"] += 1
                    except Exception:
                        stats[key]["errors"] += 1

            threads = [
                threading.Thread(
                    target=burst,
                    args=(self.edge_a, self.destinations["edge_a_to_edge_b_raw"], "a", "edge_a"),
                    daemon=True,
                ),
                threading.Thread(
                    target=burst,
                    args=(self.edge_b, self.destinations["edge_b_to_edge_a_raw"], "b", "edge_b"),
                    daemon=True,
                ),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            time.sleep(2.0)
            result.sender_stats = stats
            result.counters = {
                "edge_a_packets_received": self.count_packets(self.edge_a, clear=True),
                "edge_b_packets_received": self.count_packets(self.edge_b, clear=True),
                "edge_a_proofs_received": self.count_proofs(self.edge_a, clear=True),
                "edge_b_proofs_received": self.count_proofs(self.edge_b, clear=True),
                "burst_count_per_side": self.args.burst_count,
            }

        return self.run_wave(
            "raw_burst",
            body,
            duration_secs=2.0,
            profile_middle=self.args.profile in ("middle", "all"),
        )

    def wave_link_setup(self) -> WaveResult:
        def body(result: WaveResult) -> None:
            stats = {"edge_a": {"attempted": 0, "sent": 0, "errors": 0}, "edge_b": {"attempted": 0, "sent": 0, "errors": 0}}

            def create_many(node: BenchNode, remote_hash: str, key: str) -> None:
                for _ in range(self.args.link_setup_attempts):
                    stats[key]["attempted"] += 1
                    try:
                        link_id = self.create_link(node, remote_hash)
                        self.link_ids[node.name].append(link_id)
                        stats[key]["sent"] += 1
                    except Exception:
                        stats[key]["errors"] += 1

            threads = [
                threading.Thread(
                    target=create_many,
                    args=(self.edge_a, self.destinations["edge_b_raw_in"], "edge_a"),
                    daemon=True,
                ),
                threading.Thread(
                    target=create_many,
                    args=(self.edge_b, self.destinations["edge_a_raw_in"], "edge_b"),
                    daemon=True,
                ),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            wait_until(
                "link establishment",
                lambda: len(self.active_links(self.edge_a)) >= 1 and len(self.active_links(self.edge_b)) >= 1,
                timeout=self.args.link_timeout,
                interval=0.5,
            )
            link_events_a = self.count_link_events(self.edge_a, clear=True)
            link_events_b = self.count_link_events(self.edge_b, clear=True)
            result.sender_stats = stats
            result.counters = {
                "edge_a_active_links": len(self.active_links(self.edge_a)),
                "edge_b_active_links": len(self.active_links(self.edge_b)),
                "middle_active_links": len(self.active_links(self.middle)),
                "edge_a_link_events": len(link_events_a),
                "edge_b_link_events": len(link_events_b),
            }

        return self.run_wave(
            "link_setup",
            body,
            duration_secs=2.0,
            profile_middle=self.args.profile in ("middle", "all"),
        )

    def ensure_link_pool(self) -> None:
        for node, remote_hash in [
            (self.edge_a, self.destinations["edge_b_raw_in"]),
            (self.edge_b, self.destinations["edge_a_raw_in"]),
        ]:
            active = len(self.active_links(node, initiator_only=True))
            target = self.args.link_data_links
            while active < target:
                link_id = self.create_link(node, remote_hash)
                self.link_ids[node.name].append(link_id)
                active += 1
            wait_until(
                f"{node.name} active links >= {target}",
                lambda n=node, t=target: len(self.active_links(n, initiator_only=True)) >= t,
                timeout=self.args.link_timeout,
                interval=0.5,
            )
        self.clear_event_queues()

    def wave_link_data(self) -> WaveResult:
        self.ensure_link_pool()

        def body(result: WaveResult) -> None:
            stats: dict[str, Any] = {}

            edge_a_links = [
                link["link_id"]
                for link in self.active_links(self.edge_a, initiator_only=True)[: self.args.link_data_links]
            ]
            edge_b_links = [
                link["link_id"]
                for link in self.active_links(self.edge_b, initiator_only=True)[: self.args.link_data_links]
            ]

            def send_a(counter: int) -> None:
                link_id = edge_a_links[counter % len(edge_a_links)]
                payload = f"link_data:a:{counter}".encode("ascii").ljust(self.args.link_data_size, b"L")
                self.send_channel(self.edge_a, link_id, 50, payload)

            def send_b(counter: int) -> None:
                link_id = edge_b_links[counter % len(edge_b_links)]
                payload = f"link_data:b:{counter}".encode("ascii").ljust(self.args.link_data_size, b"R")
                self.send_channel(self.edge_b, link_id, 51, payload)

            threads = [
                self.sender_loop("edge_a", send_a, self.args.link_data_rate, self.args.duration_secs, stats),
                self.sender_loop("edge_b", send_b, self.args.link_data_rate, self.args.duration_secs, stats),
            ]
            for thread in threads:
                thread.join()
            result.sender_stats = stats
            packets_a = self.edge_a.get("/api/packets?clear=true")["packets"]
            packets_b = self.edge_b.get("/api/packets?clear=true")["packets"]
            link_stats_a = {
                link["link_id"]: link
                for link in self.active_links(self.edge_a, initiator_only=True)
                if link["link_id"] in edge_a_links
            }
            link_stats_b = {
                link["link_id"]: link
                for link in self.active_links(self.edge_b, initiator_only=True)
                if link["link_id"] in edge_b_links
            }
            result.counters = {
                "edge_a_packets_received": len(packets_a),
                "edge_b_packets_received": len(packets_b),
                "edge_a_channel_packets": sum(1 for pkt in packets_a if str(pkt["dest_hash"]).startswith("channel:")),
                "edge_b_channel_packets": sum(1 for pkt in packets_b if str(pkt["dest_hash"]).startswith("channel:")),
                "edge_a_channel_send_ok": sum(int(link.get("channel_send_ok", 0)) for link in link_stats_a.values()),
                "edge_b_channel_send_ok": sum(int(link.get("channel_send_ok", 0)) for link in link_stats_b.values()),
                "edge_a_channel_not_ready": sum(
                    int(link.get("channel_send_not_ready", 0)) for link in link_stats_a.values()
                ),
                "edge_b_channel_not_ready": sum(
                    int(link.get("channel_send_not_ready", 0)) for link in link_stats_b.values()
                ),
                "edge_a_channel_messages_received": sum(
                    int(link.get("channel_messages_received", 0)) for link in link_stats_a.values()
                ),
                "edge_b_channel_messages_received": sum(
                    int(link.get("channel_messages_received", 0)) for link in link_stats_b.values()
                ),
                "edge_a_channel_proofs_sent": sum(
                    int(link.get("channel_proofs_sent", 0)) for link in link_stats_a.values()
                ),
                "edge_b_channel_proofs_sent": sum(
                    int(link.get("channel_proofs_sent", 0)) for link in link_stats_b.values()
                ),
                "edge_a_channel_proofs_received": sum(
                    int(link.get("channel_proofs_received", 0)) for link in link_stats_a.values()
                ),
                "edge_b_channel_proofs_received": sum(
                    int(link.get("channel_proofs_received", 0)) for link in link_stats_b.values()
                ),
                "edge_a_pending_channel_packets": sum(
                    int(link.get("pending_channel_packets", 0)) for link in link_stats_a.values()
                ),
                "edge_b_pending_channel_packets": sum(
                    int(link.get("pending_channel_packets", 0)) for link in link_stats_b.values()
                ),
            }

        return self.run_wave(
            "link_data",
            body,
            duration_secs=self.args.duration_secs,
            profile_middle=self.args.profile in ("middle", "all"),
        )

    def wave_resource_large(self) -> WaveResult:
        self.ensure_link_pool()

        def body(result: WaveResult) -> None:
            edge_a_link = self.active_links(self.edge_a, initiator_only=True)[0]["link_id"]
            edge_b_link = self.active_links(self.edge_b, initiator_only=True)[0]["link_id"]
            self.send_resource(self.edge_a, edge_a_link, b"R" * self.args.resource_size, b"edge-a")
            self.send_resource(self.edge_b, edge_b_link, b"S" * self.args.resource_size, b"edge-b")
            time.sleep(self.args.resource_wait_secs)
            events_a = self.edge_a.get("/api/resource_events?clear=true")["resource_events"]
            events_b = self.edge_b.get("/api/resource_events?clear=true")["resource_events"]
            result.counters = {
                "resource_size": self.args.resource_size,
                "edge_a_resource_events": len(events_a),
                "edge_b_resource_events": len(events_b),
                "edge_a_received": sum(1 for event in events_a if event.get("event_type") == "received"),
                "edge_b_received": sum(1 for event in events_b if event.get("event_type") == "received"),
                "edge_a_completed": sum(1 for event in events_a if event.get("event_type") == "completed"),
                "edge_b_completed": sum(1 for event in events_b if event.get("event_type") == "completed"),
                "edge_a_failed": sum(1 for event in events_a if event.get("event_type") == "failed"),
                "edge_b_failed": sum(1 for event in events_b if event.get("event_type") == "failed"),
            }

        return self.run_wave(
            "resource_large",
            body,
            duration_secs=self.args.resource_wait_secs,
            profile_middle=self.args.profile in ("middle", "all"),
        )

    def wave_mixed(self) -> WaveResult:
        self.ensure_link_pool()

        def body(result: WaveResult) -> None:
            stats: dict[str, Any] = {}
            edge_a_links = [
                link["link_id"]
                for link in self.active_links(self.edge_a, initiator_only=True)[: self.args.link_data_links]
            ]
            edge_b_links = [
                link["link_id"]
                for link in self.active_links(self.edge_b, initiator_only=True)[: self.args.link_data_links]
            ]
            stop_at = time.time() + self.args.duration_secs
            link_stats = {"attempted": 0, "sent": 0, "errors": 0}

            def send_raw_a(counter: int) -> None:
                payload = f"mixed:raw:a:{counter}".encode("ascii").ljust(self.args.raw_small_size, b"a")
                self.send_packet(self.edge_a, self.destinations["edge_a_to_edge_b_raw"], payload)

            def send_raw_b(counter: int) -> None:
                payload = f"mixed:raw:b:{counter}".encode("ascii").ljust(self.args.raw_small_size, b"b")
                self.send_packet(self.edge_b, self.destinations["edge_b_to_edge_a_raw"], payload)

            def send_link_a(counter: int) -> None:
                link_id = edge_a_links[counter % len(edge_a_links)]
                payload = f"mixed:link:a:{counter}".encode("ascii").ljust(self.args.mixed_link_size, b"m")
                self.send_channel(self.edge_a, link_id, 60, payload)

            def send_link_b(counter: int) -> None:
                link_id = edge_b_links[counter % len(edge_b_links)]
                payload = f"mixed:link:b:{counter}".encode("ascii").ljust(self.args.mixed_link_size, b"n")
                self.send_channel(self.edge_b, link_id, 61, payload)

            def periodic_link_setup() -> None:
                while time.time() < stop_at:
                    link_stats["attempted"] += 2
                    try:
                        self.link_ids["edge-a"].append(self.create_link(self.edge_a, self.destinations["edge_b_raw_in"]))
                        self.link_ids["edge-b"].append(self.create_link(self.edge_b, self.destinations["edge_a_raw_in"]))
                        link_stats["sent"] += 2
                    except Exception:
                        link_stats["errors"] += 1
                    time.sleep(self.args.mixed_link_interval)

            creator = threading.Thread(target=periodic_link_setup, daemon=True)
            creator.start()
            threads = [
                self.sender_loop("edge_a_raw", send_raw_a, self.args.mixed_raw_rate, self.args.duration_secs, stats),
                self.sender_loop("edge_b_raw", send_raw_b, self.args.mixed_raw_rate, self.args.duration_secs, stats),
                self.sender_loop("edge_a_link", send_link_a, self.args.mixed_link_rate, self.args.duration_secs, stats),
                self.sender_loop("edge_b_link", send_link_b, self.args.mixed_link_rate, self.args.duration_secs, stats),
            ]
            for thread in threads:
                thread.join()
            creator.join(timeout=1.0)
            stats["link_setup"] = link_stats
            result.sender_stats = stats
            packets_a = self.edge_a.get("/api/packets?clear=true")["packets"]
            packets_b = self.edge_b.get("/api/packets?clear=true")["packets"]
            result.counters = {
                "edge_a_packets_received": len(packets_a),
                "edge_b_packets_received": len(packets_b),
                "edge_a_proofs_received": self.count_proofs(self.edge_a, clear=True),
                "edge_b_proofs_received": self.count_proofs(self.edge_b, clear=True),
                "middle_active_links": len(self.active_links(self.middle)),
            }

        return self.run_wave(
            "mixed",
            body,
            duration_secs=self.args.duration_secs,
            profile_middle=self.args.profile in ("middle", "all"),
        )

    def execute(self) -> dict[str, Any]:
        self.ensure_binary()
        self.write_configs()
        self.start_nodes()
        self.bootstrap_destinations()

        results: list[WaveResult] = []
        for wave in self.args.waves:
            if wave == "convergence":
                results.append(self.wave_convergence())
            elif wave == "raw_small":
                results.append(self.wave_raw("raw_small", self.args.raw_small_size, proof=False))
            elif wave == "raw_large":
                results.append(self.wave_raw("raw_large", self.args.raw_large_size, proof=False))
            elif wave == "raw_burst":
                results.append(self.wave_raw_burst())
            elif wave == "proof_heavy":
                results.append(self.wave_raw("proof_heavy", self.args.raw_small_size, proof=True))
            elif wave == "link_setup":
                results.append(self.wave_link_setup())
            elif wave == "resource_large":
                results.append(self.wave_resource_large())
            elif wave == "link_data":
                results.append(self.wave_link_data())
            elif wave == "mixed":
                results.append(self.wave_mixed())
            else:
                raise RuntimeError(f"unknown wave: {wave}")

        report = {
            "run_root": str(self.run_root),
            "started_at": min(result.started_at for result in results) if results else now(),
            "ended_at": max(result.ended_at for result in results) if results else now(),
            "limits": {
                "packet_mtu": 500,
                "plain_mdu": 464,
                "encrypted_mdu": 383,
                "tcp_interface_mtu": 65535,
            },
            "waves": [self.wave_to_dict(result) for result in results],
        }
        return report

    @staticmethod
    def wave_to_dict(result: WaveResult) -> dict[str, Any]:
        return {
            "name": result.name,
            "started_at": result.started_at,
            "ended_at": result.ended_at,
            "duration_secs": result.duration_secs,
            "notes": result.notes,
            "sender_stats": result.sender_stats,
            "counters": result.counters,
            "process_stats": result.process_stats,
            "perf": result.perf,
        }


def summarize_markdown(report: dict[str, Any]) -> str:
    lines = ["# Three-node benchmark report", ""]
    for wave in report["waves"]:
        lines.append(f"## {wave['name']}")
        lines.append(f"- Duration: {wave['duration_secs']:.2f}s")
        counters = wave.get("counters", {})
        if counters:
            for key, value in counters.items():
                lines.append(f"- {key}: {value}")
        process_stats = wave.get("process_stats", {})
        middle = process_stats.get("middle")
        if middle:
            lines.append(f"- middle cpu_percent: {middle['cpu_percent']:.2f}")
            lines.append(f"- middle total_rxb_delta: {middle['total_rxb_delta']}")
            lines.append(f"- middle total_txb_delta: {middle['total_txb_delta']}")
        lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local three-node rns-rs benchmark.")
    parser.add_argument("--bin", help="Path to rns-ctl binary")
    parser.add_argument("--run-dir", help="Directory for configs, logs, and reports")
    parser.add_argument("--keep-artifacts", action="store_true", help="Do not delete the run directory")
    parser.add_argument("--start-timeout", type=float, default=20.0)
    parser.add_argument("--convergence-timeout", type=float, default=20.0)
    parser.add_argument("--duration-secs", type=float, default=6.0)
    parser.add_argument("--raw-rate", type=float, default=25.0)
    parser.add_argument("--raw-small-size", type=int, default=96)
    parser.add_argument("--raw-large-size", type=int, default=320)
    parser.add_argument("--burst-count", type=int, default=100)
    parser.add_argument("--link-setup-attempts", type=int, default=8)
    parser.add_argument("--link-timeout", type=float, default=15.0)
    parser.add_argument("--link-data-links", type=int, default=4)
    parser.add_argument("--link-data-rate", type=float, default=15.0)
    parser.add_argument("--link-data-size", type=int, default=96)
    parser.add_argument("--resource-size", type=int, default=4096)
    parser.add_argument("--resource-wait-secs", type=float, default=4.0)
    parser.add_argument("--mixed-raw-rate", type=float, default=12.0)
    parser.add_argument("--mixed-link-rate", type=float, default=8.0)
    parser.add_argument("--mixed-link-interval", type=float, default=1.5)
    parser.add_argument("--mixed-link-size", type=int, default=64)
    parser.add_argument(
        "--profile",
        choices=["none", "middle", "all"],
        default="none",
        help="Collect perf stat for the middle node during profiled waves",
    )
    parser.add_argument(
        "--waves",
        default="all",
        help="Comma-separated subset of waves or 'all'",
    )
    parser.add_argument("--output-json", help="Write JSON report here")
    parser.add_argument("--output-md", help="Write Markdown summary here")
    args = parser.parse_args()
    if args.waves == "all":
        args.waves = list(WAVE_ORDER)
    else:
        args.waves = [wave.strip() for wave in args.waves.split(",") if wave.strip()]
    invalid = [wave for wave in args.waves if wave not in WAVE_ORDER]
    if invalid:
        parser.error(f"unknown waves: {', '.join(invalid)}")
    return args


def main() -> int:
    args = parse_args()
    harness = BenchmarkHarness(args)
    try:
        report = harness.execute()
        json_report = json.dumps(report, indent=2, sort_keys=True)
        if args.output_json:
            Path(args.output_json).write_text(json_report + "\n", encoding="utf-8")
        else:
            print(json_report)

        if args.output_md:
            Path(args.output_md).write_text(summarize_markdown(report) + "\n", encoding="utf-8")
        return 0
    finally:
        harness.cleanup()


if __name__ == "__main__":
    sys.exit(main())
