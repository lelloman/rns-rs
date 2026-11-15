#!/usr/bin/env python3
"""Mixed-mesh soak test for rns-rs.

Starts a localhost mesh of Rust and upstream Python `rnsd` transport nodes
connected over TCP, attaches long-running client programs to every node
(`rncp` listeners of both implementations, optional `rnx` listeners, and an
announcer), and then runs a continuous randomized workload for the requested
duration:

* `rncp` sends and fetches of random files of varying size between nodes,
  with every client/listener implementation combination, verified by SHA-256;
* `rnprobe` probes of remote transport nodes' probe responders;
* optional `rnx` remote command executions;
* periodic announces from client destinations.

While the workload runs, the harness samples every long-running process (RSS,
open file descriptors, threads) and every node's path table (`rnpath -t -j`,
run with the node's own implementation), and records each operation's outcome
and latency. Results go to JSONL files in the work directory and a summary is
printed at the end (and written to summary.json).

Upstream Python Reticulum must be importable; by default the harness uses
~/Reticulum (override with --upstream or RETICULUM_UPSTREAM_DIR).

Example:
    scripts/mixed_mesh_soak.py --duration 24h --workdir /var/tmp/soak
"""

import argparse
import hashlib
import json
import math
import os
import random
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import traceback

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RUST_UTILITIES = ("rnsd", "rncp", "rnprobe", "rnpath", "rnx")
LOG_MARKERS = ("panicked", "Traceback", "[Critical]", "[Error]", "ERROR")

# --------------------------------------------------------------------------
# helpers


def parse_duration(text):
    text = text.strip().lower()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if text and text[-1] in units:
        return float(text[:-1]) * units[text[-1]]
    return float(text)


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(fraction * len(ordered)) - 1))
    return ordered[index]


def proc_stats(pid):
    """RSS (kB), fd count and thread count of a live process, or None."""
    try:
        rss = threads = None
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1])
                elif line.startswith("Threads:"):
                    threads = int(line.split()[1])
        fds = len(os.listdir(f"/proc/{pid}/fd"))
        return {"rss_kb": rss, "fds": fds, "threads": threads}
    except (OSError, ValueError):
        return None


def linear_slope(points):
    """Least-squares slope of (x, y) points."""
    if len(points) < 2:
        return 0.0
    mean_x = sum(p[0] for p in points) / len(points)
    mean_y = sum(p[1] for p in points) / len(points)
    den = sum((p[0] - mean_x) ** 2 for p in points)
    if den == 0:
        return 0.0
    return sum((p[0] - mean_x) * (p[1] - mean_y) for p in points) / den


def tail(path, lines=40):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 16384))
            data = f.read().decode("utf-8", "replace")
        return "\n".join(data.splitlines()[-lines:])
    except OSError:
        return ""


# --------------------------------------------------------------------------
# harness


class Proc:
    """A long-running child process owned by the harness."""

    def __init__(self, name, role, impl, node, argv, log, env):
        self.name = name
        self.role = role
        self.impl = impl
        self.node = node
        self.argv = argv
        self.log = log
        self.logfile = open(log, "ab")
        self.popen = subprocess.Popen(
            argv,
            stdout=self.logfile,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
        )
        self.pid = self.popen.pid
        self.exit_reported = False

    def alive(self):
        return self.popen.poll() is None


class Node:
    def __init__(self, index, impl, workdir, run_id):
        self.index = index
        self.impl = impl
        self.name = f"{impl[0]}{index}"
        self.dir = os.path.join(workdir, "nodes", self.name)
        self.config = os.path.join(self.dir, "config")
        self.home = os.path.join(self.dir, "home")
        self.instance = f"soak-{run_id}-{self.name}"
        self.port = None
        self.shared_port = None
        self.control_port = None
        self.peers = []  # nodes this node connects to as a TCP client
        self.daemon = None
        self.probe_hash = None
        self.listeners = []  # dicts describing rncp/rnx listeners


class Soak:
    def __init__(self, args):
        self.args = args
        self.rng = random.Random(args.seed)
        self.rng_lock = threading.Lock()
        self.run_id = f"{os.getpid()}-{args.seed}"
        self.workdir = os.path.abspath(args.workdir)
        self.stop = threading.Event()
        self.procs = []
        self.procs_lock = threading.Lock()
        self.active_ops = {}
        self.active_lock = threading.Lock()
        self.write_lock = threading.Lock()
        self.op_counter = 0
        self.nodes = []
        self.started_at = None
        self.workload_started_at = None
        self.ops = []
        self.events = []
        self.samples = []
        self.last_paths = {}
        # Destination hash -> name of every destination the mesh announces.
        self.expected = {}
        self.env = dict(os.environ)
        self.env["PYTHONPATH"] = args.upstream + (
            os.pathsep + self.env["PYTHONPATH"] if self.env.get("PYTHONPATH") else ""
        )
        self.env["PYTHONUNBUFFERED"] = "1"
        self.bin = os.path.join(args.target_dir, "release")

    # ---------------------------------------------------------------- output

    def jsonl(self, name, record):
        with self.write_lock:
            with open(os.path.join(self.workdir, name), "a") as f:
                f.write(json.dumps(record, sort_keys=True) + "\n")

    def event(self, kind, **fields):
        record = {"t": round(time.time(), 3), "kind": kind, **fields}
        self.events.append(record)
        self.jsonl("events.jsonl", record)
        if kind not in ("path_change",):
            print(f"[{self.elapsed()}] event {kind}: "
                  + ", ".join(f"{k}={v}" for k, v in fields.items() if k != "log_tail"),
                  flush=True)

    def elapsed(self):
        if self.started_at is None:
            return "--:--:--"
        seconds = int(time.time() - self.started_at)
        return f"{seconds // 3600:02d}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}"

    # ------------------------------------------------------------- processes

    def spawn(self, name, role, impl, node, argv):
        log = os.path.join(self.workdir, "logs", f"{name}.log")
        env = dict(self.env)
        if node is not None:
            env["HOME"] = node.home
        proc = Proc(name, role, impl, node, argv, log, env)
        with self.procs_lock:
            self.procs.append(proc)
            self.write_pids()
        return proc

    def write_pids(self):
        pids = [{"pid": p.pid, "name": p.name} for p in self.procs]
        with open(os.path.join(self.workdir, "pids.json"), "w") as f:
            json.dump(pids, f)

    def kill_stale(self):
        """Kill processes recorded by an earlier run in this work directory."""
        path = os.path.join(self.workdir, "pids.json")
        try:
            with open(path) as f:
                stale = json.load(f)
        except (OSError, ValueError):
            return
        for entry in stale:
            pid = entry["pid"]
            try:
                with open(f"/proc/{pid}/environ", "rb") as f:
                    environ = f.read()
            except OSError:
                continue
            # Only kill what this harness started: its HOME is in the workdir.
            if self.workdir.encode() in environ:
                print(f"killing stale {entry['name']} (pid {pid})", flush=True)
                self.kill_group(pid, signal.SIGKILL)

    @staticmethod
    def kill_group(pid, sig):
        try:
            os.killpg(pid, sig)
        except ProcessLookupError:
            pass
        except PermissionError:
            try:
                os.kill(pid, sig)
            except OSError:
                pass

    def cleanup(self):
        self.stop.set()
        with self.active_lock:
            active = list(self.active_ops.values())
        for popen in active:
            self.kill_group(popen.pid, signal.SIGKILL)
        with self.procs_lock:
            procs = list(self.procs)
        for proc in procs:
            if proc.alive():
                self.kill_group(proc.pid, signal.SIGTERM)
        deadline = time.time() + 5
        for proc in procs:
            while proc.alive() and time.time() < deadline:
                time.sleep(0.05)
            if proc.alive():
                self.kill_group(proc.pid, signal.SIGKILL)
                proc.popen.wait()
            # Reap stragglers in the process group as well.
            self.kill_group(proc.pid, signal.SIGKILL)
            proc.logfile.close()

    # ---------------------------------------------------------------- build

    def build(self):
        if self.args.no_build:
            return
        print("building release binaries ...", flush=True)
        argv = ["cargo", "build", "--release", "-p", "rns-cli"]
        for name in RUST_UTILITIES:
            argv += ["--bin", name]
        subprocess.run(argv, cwd=REPO_ROOT, check=True,
                       env=dict(os.environ, CARGO_TARGET_DIR=self.args.target_dir))

    def rust_bin(self, name):
        return os.path.join(self.bin, name)

    def utility(self, impl, name):
        if impl == "rust":
            return [self.rust_bin(name)]
        return [sys.executable, "-m", f"RNS.Utilities.{name}"]

    # ------------------------------------------------------------- topology

    def make_nodes(self):
        layout = []
        rust, python = self.args.rust_nodes, self.args.python_nodes
        while rust or python:
            if rust:
                layout.append("rust")
                rust -= 1
            if python:
                layout.append("python")
                python -= 1
        for index, impl in enumerate(layout):
            node = Node(index, impl, self.workdir, self.run_id)
            os.makedirs(node.config, exist_ok=True)
            os.makedirs(node.home, exist_ok=True)
            node.port = free_port()
            node.shared_port = free_port()
            node.control_port = free_port()
            self.nodes.append(node)
        count = len(self.nodes)
        for i, node in enumerate(self.nodes):
            if self.args.topology == "star":
                if i > 0:
                    node.peers.append(self.nodes[0])
            else:
                if i > 0:
                    node.peers.append(self.nodes[i - 1])
                if self.args.topology == "ring" and i == 0 and count > 2:
                    node.peers.append(self.nodes[-1])
        for node in self.nodes:
            interfaces = (
                "  [[Soak Server]]\n    type = TCPServerInterface\n    enabled = Yes\n"
                f"    listen_ip = 127.0.0.1\n    listen_port = {node.port}\n"
            )
            for peer in node.peers:
                interfaces += (
                    f"  [[Soak Link {peer.name}]]\n    type = TCPClientInterface\n"
                    f"    enabled = Yes\n    target_host = 127.0.0.1\n"
                    f"    target_port = {peer.port}\n"
                )
            with open(os.path.join(node.config, "config"), "w") as f:
                f.write(
                    "[reticulum]\n  enable_transport = Yes\n  share_instance = Yes\n"
                    f"  instance_name = {node.instance}\n"
                    f"  shared_instance_port = {node.shared_port}\n"
                    f"  instance_control_port = {node.control_port}\n"
                    "  respond_to_probes = Yes\n  discover_interfaces = No\n\n"
                    f"[logging]\n  loglevel = {self.args.loglevel}\n\n"
                    "[interfaces]\n" + interfaces
                )
        desc = " ".join(
            f"{n.name}(:{n.port})<-{','.join(p.name for p in n.peers) or '-'}"
            for n in self.nodes
        )
        print(f"topology {self.args.topology}: {desc}", flush=True)
        self.event("topology", nodes=[
            {"name": n.name, "impl": n.impl, "port": n.port,
             "peers": [p.name for p in n.peers], "instance": n.instance}
            for n in self.nodes])

    def wait_for(self, predicate, timeout, what, proc=None):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return
            if proc is not None and not proc.alive():
                raise RuntimeError(f"{what}: {proc.name} exited:\n{tail(proc.log)}")
            time.sleep(0.1)
        raise RuntimeError(f"timed out waiting for {what}"
                           + (f":\n{tail(proc.log)}" if proc else ""))

    def start_daemons(self):
        import RNS  # noqa: deferred so --help works without upstream

        for node in self.nodes:
            argv = self.utility(node.impl, "rnsd") + ["--config", node.config]
            node.daemon = self.spawn(f"{node.name}-rnsd", "daemon", node.impl, node, argv)

            def port_open(port=node.port):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                        return True
                except OSError:
                    return False

            self.wait_for(port_open, 30, f"{node.name} TCP server", node.daemon)
            identity_path = os.path.join(node.config, "storage", "transport_identity")
            self.wait_for(lambda: os.path.exists(identity_path)
                          and os.path.getsize(identity_path) == 64,
                          30, f"{node.name} transport identity", node.daemon)
            identity = RNS.Identity.from_file(identity_path)
            node.probe_hash = RNS.Destination.hash_from_name_and_identity(
                "rnstransport.probe", identity).hex()
            # Give the daemon a moment to finish bringing up its shared instance.
            time.sleep(1.0)
        print("daemons up: " + ", ".join(
            f"{n.name} pid {n.daemon.pid} probe {n.probe_hash}" for n in self.nodes),
            flush=True)

    def new_identity(self, path):
        import RNS

        identity = RNS.Identity()
        identity.to_file(path)
        return identity

    def start_clients(self):
        import RNS

        for node in self.nodes:
            impls = ["rust", "python"]
            for impl in impls:
                tag = f"{node.name}-{impl[0]}rncp"
                base = os.path.join(node.dir, tag)
                save = os.path.join(base, "save")
                jail = os.path.join(base, "jail")
                os.makedirs(save, exist_ok=True)
                os.makedirs(jail, exist_ok=True)
                identity_path = os.path.join(base, "identity")
                identity = self.new_identity(identity_path)
                destination = RNS.Destination.hash_from_name_and_identity(
                    "rncp.receive", identity).hex()
                fetchables = []
                for size in self.args.fetch_sizes:
                    name = f"fetch-{size}.bin"
                    with open(os.path.join(jail, name), "wb") as f:
                        f.write(self.payload(size, compressible=size % 2 == 0))
                    fetchables.append({"name": name, "size": size,
                                       "sha256": sha256_file(os.path.join(jail, name))})
                argv = self.utility(impl, "rncp") + [
                    "--config", node.config, "-i", identity_path, "-l", "-n", "-F",
                    "-j", jail, "-s", save, "-b", str(int(self.args.announce_interval)),
                ]
                proc = self.spawn(tag, "rncp-listener", impl, node, argv)
                self.stagger()
                self.expected[destination] = tag
                node.listeners.append({
                    "kind": "rncp", "impl": impl, "node": node, "proc": proc,
                    "destination": destination, "save": save, "fetchables": fetchables,
                    "name": tag,
                })
                if self.args.rnx:
                    tag = f"{node.name}-{impl[0]}rnx"
                    base = os.path.join(node.dir, tag)
                    os.makedirs(base, exist_ok=True)
                    identity_path = os.path.join(base, "identity")
                    identity = self.new_identity(identity_path)
                    destination = RNS.Destination.hash_from_name_and_identity(
                        "rnx.execute", identity).hex()
                    argv = self.utility(impl, "rnx") + [
                        "--config", node.config, "-i", identity_path, "-l", "-n",
                    ]
                    proc = self.spawn(tag, "rnx-listener", impl, node, argv)
                    self.stagger()
                    self.expected[destination] = tag
                    node.listeners.append({
                        "kind": "rnx", "impl": impl, "node": node, "proc": proc,
                        "destination": destination, "name": tag,
                    })
            if self.args.announcers > 0:
                tag = f"{node.name}-announcer"
                base = os.path.join(node.dir, tag)
                os.makedirs(base, exist_ok=True)
                for i in range(self.args.announcers):
                    identity = self.new_identity(os.path.join(base, f"identity-{i}"))
                    self.expected[RNS.Destination.hash_from_name_and_identity(
                        f"soak.announcer.{i}", identity).hex()] = f"{tag}.{i}"
                argv = [sys.executable, os.path.join(self.workdir, "announcer.py"),
                        node.config, base, str(self.args.announcers),
                        str(self.args.announce_interval)]
                self.spawn(tag, "announcer", "python", node, argv)
                self.stagger()
        # A client identity per node and implementation for outgoing operations.
        for node in self.nodes:
            node.client_identity = os.path.join(node.dir, "client-identity")
            self.new_identity(node.client_identity)

    def stagger(self):
        # Upstream clients sharing a config directory race to create its
        # storage directories (makedirs after an isdir check), so client
        # programs are started one at a time.
        time.sleep(1.0)

    def write_announcer(self):
        with open(os.path.join(self.workdir, "announcer.py"), "w") as f:
            f.write(ANNOUNCER)

    # -------------------------------------------------------------- payload

    def payload(self, size, compressible):
        with self.rng_lock:
            if compressible:
                seed = self.rng.randbytes(64)
                return (seed * (size // 64 + 1))[:size]
            return self.rng.randbytes(size)

    def pick_size(self):
        with self.rng_lock:
            bucket = self.rng.random()
            if bucket < 0.25:
                return self.rng.randint(1, 4096)
            if bucket < 0.6:
                return self.rng.randint(4097, 128 * 1024)
            if bucket < 0.9:
                return self.rng.randint(128 * 1024 + 1, 1024 * 1024)
            return self.rng.randint(1024 * 1024 + 1, max(1024 * 1024 + 2, self.args.max_size))

    def choice(self, seq):
        with self.rng_lock:
            return self.rng.choice(seq)

    # ------------------------------------------------------------ operations

    def run_op(self, kind, argv, env_node, deadline, opdir):
        """Run a short-lived utility; returns (status, rc, latency, output)."""
        env = dict(self.env)
        env["HOME"] = env_node.home
        out_path = os.path.join(opdir, "output.log")
        started = time.time()
        with open(out_path, "wb") as out:
            popen = subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL, env=env,
                                     start_new_session=True)
            with self.active_lock:
                self.active_ops[popen.pid] = popen
            try:
                rc = popen.wait(timeout=deadline)
                status = "ok" if rc == 0 else "fail"
            except subprocess.TimeoutExpired:
                self.kill_group(popen.pid, signal.SIGKILL)
                rc = popen.wait()
                status = "stall"
            finally:
                with self.active_lock:
                    self.active_ops.pop(popen.pid, None)
        latency = time.time() - started
        with open(out_path, "rb") as f:
            output = self.clean_output(f.read().decode("utf-8", "replace"))
        return status, rc, latency, output

    @staticmethod
    def clean_output(text):
        # Drop progress spinners (backspaces and braille glyphs).
        text = re.sub(r"[\x08\u2800-\u28ff]", "", text)
        return "\n".join(re.sub(r" {2,}", " ", line).strip()
                         for line in text.splitlines() if line.strip())

    @staticmethod
    def failure_detail(output):
        lower = output.lower()
        for needle, detail in (("path request timed out", "path request timed out"),
                               ("path not found", "path not found"),
                               ("could not establish", "link not established"),
                               ("link establishment timed out", "link not established"),
                               ("timed out", "timed out"),
                               ("traceback", "traceback"),
                               ("panicked", "panic")):
            if needle in lower:
                return detail
        return None

    def next_op_id(self):
        with self.rng_lock:
            self.op_counter += 1
            return self.op_counter

    def live_listeners(self, kind, exclude_node=None):
        return [lst for node in self.nodes for lst in node.listeners
                if lst["kind"] == kind and lst["proc"].alive()
                and lst["node"] is not exclude_node]

    def op_transfer(self, op_id, opdir, fetch):
        client_node = self.choice(self.nodes)
        client_impl = self.choice(["rust", "python"])
        targets = self.live_listeners("rncp", exclude_node=client_node)
        if not targets:
            return None
        listener = self.choice(targets)
        timeout = self.args.link_timeout
        base = self.utility(client_impl, "rncp") + [
            "--config", client_node.config, "-i", client_node.client_identity,
            "-S", "-w", str(timeout)]
        if fetch:
            item = self.choice(listener["fetchables"])
            size, expected = item["size"], item["sha256"]
            save = os.path.join(opdir, "fetched")
            os.makedirs(save)
            argv = base + ["-f", "-s", save, item["name"], listener["destination"]]
            received = os.path.join(save, item["name"])
        else:
            size = self.pick_size()
            name = f"soak-{op_id}.bin"
            source = os.path.join(opdir, name)
            with open(source, "wb") as f:
                f.write(self.payload(size, compressible=self.choice([False, False, True])))
            expected = sha256_file(source)
            argv = base + [source, listener["destination"]]
            received = os.path.join(listener["save"], name)
        deadline = self.args.op_timeout + size / self.args.min_rate
        status, rc, latency, output = self.run_op(
            "fetch" if fetch else "send", argv, client_node, deadline, opdir)
        detail = None
        if status == "ok":
            # The listener writes the file when the resource concludes, which
            # can be just after the sender sees the completion proof.
            settle = time.time() + self.args.settle_timeout
            got = None
            while time.time() < settle:
                if os.path.exists(received):
                    got = sha256_file(received)
                    if got == expected:
                        break
                time.sleep(0.1)
            if got != expected:
                status = "fail"
                detail = "missing received file" if got is None else "hash mismatch"
        try:
            os.remove(received)
        except OSError:
            pass
        return {
            "op": "fetch" if fetch else "send", "client_node": client_node.name,
            "client_impl": client_impl, "target_node": listener["node"].name,
            "target_impl": listener["impl"], "size": size, "status": status,
            "rc": rc, "latency": round(latency, 3), "detail": detail,
            "output": output,
        }

    def op_probe(self, op_id, opdir):
        client_node = self.choice(self.nodes)
        client_impl = self.choice(["rust", "python"])
        target = self.choice([n for n in self.nodes if n is not client_node])
        argv = self.utility(client_impl, "rnprobe") + [
            "--config", client_node.config, "-t", str(self.args.link_timeout),
            "-n", "1", "rnstransport.probe", target.probe_hash]
        status, rc, latency, output = self.run_op(
            "probe", argv, client_node, self.args.op_timeout, opdir)
        detail = None
        if status == "ok" and "Valid reply" not in output:
            status, detail = "fail", "no valid reply"
        return {"op": "probe", "client_node": client_node.name, "client_impl": client_impl,
                "target_node": target.name, "target_impl": target.impl, "size": 0,
                "status": status, "rc": rc, "latency": round(latency, 3),
                "detail": detail, "output": output}

    def op_rnx(self, op_id, opdir):
        client_node = self.choice(self.nodes)
        client_impl = self.choice(["rust", "python"])
        targets = self.live_listeners("rnx", exclude_node=client_node)
        if not targets:
            return None
        listener = self.choice(targets)
        marker = f"soak-marker-{op_id}"
        argv = self.utility(client_impl, "rnx") + [
            "--config", client_node.config, "-i", client_node.client_identity,
            "-w", str(self.args.link_timeout), listener["destination"],
            f"/bin/echo {marker}"]
        status, rc, latency, output = self.run_op(
            "rnx", argv, client_node, self.args.op_timeout, opdir)
        detail = None
        if status == "ok" and marker not in output:
            status, detail = "fail", "marker missing from output"
        return {"op": "rnx", "client_node": client_node.name, "client_impl": client_impl,
                "target_node": listener["node"].name, "target_impl": listener["impl"],
                "size": 0, "status": status, "rc": rc, "latency": round(latency, 3),
                "detail": detail, "output": output}

    def worker(self, index):
        weights = [("send", self.args.weight_send), ("fetch", self.args.weight_fetch),
                   ("probe", self.args.weight_probe)]
        if self.args.rnx:
            weights.append(("rnx", self.args.weight_rnx))
        kinds = [k for k, _ in weights]
        cumulative = [w for _, w in weights]
        while not self.stop.is_set():
            with self.rng_lock:
                kind = self.rng.choices(kinds, cumulative)[0]
                pause = self.rng.uniform(0, 2 * self.args.op_interval)
            op_id = self.next_op_id()
            opdir = os.path.join(self.workdir, "ops", str(op_id))
            os.makedirs(opdir, exist_ok=True)
            started = time.time()
            try:
                if kind in ("send", "fetch"):
                    record = self.op_transfer(op_id, opdir, fetch=kind == "fetch")
                elif kind == "probe":
                    record = self.op_probe(op_id, opdir)
                else:
                    record = self.op_rnx(op_id, opdir)
            except Exception:
                record = {"op": kind, "status": "error", "detail": traceback.format_exc(),
                          "latency": 0, "output": ""}
            if record is None:
                shutil.rmtree(opdir, ignore_errors=True)
            else:
                if self.stop.is_set() and record["status"] != "ok":
                    # Interrupted by shutdown; not a finding.
                    shutil.rmtree(opdir, ignore_errors=True)
                    break
                record.update({"id": op_id, "t": round(started, 3), "worker": index})
                if record["status"] != "ok" and not record.get("detail"):
                    record["detail"] = self.failure_detail(record.get("output", ""))
                output = record.pop("output", "")
                if record["status"] == "ok":
                    shutil.rmtree(opdir, ignore_errors=True)
                else:
                    record["output_tail"] = "\n".join(output.splitlines()[-12:])
                    print(f"[{self.elapsed()}] op {op_id} {record['op']} "
                          f"{record.get('client_impl')}@{record.get('client_node')} -> "
                          f"{record.get('target_impl')}@{record.get('target_node')} "
                          f"size={record.get('size')} {record['status']} "
                          f"({record.get('detail') or 'rc ' + str(record.get('rc'))}) "
                          f"after {record['latency']:.1f}s; kept {opdir}", flush=True)
                self.ops.append(record)
                self.jsonl("ops.jsonl", record)
            self.stop.wait(pause)

    # ------------------------------------------------------------- sampling

    def path_table(self, node):
        argv = self.utility(node.impl, "rnpath") + ["--config", node.config, "-t", "-j"]
        env = dict(self.env)
        env["HOME"] = node.home
        try:
            result = subprocess.run(argv, capture_output=True, timeout=60, env=env,
                                    start_new_session=True)
        except subprocess.TimeoutExpired:
            return None, "rnpath timed out"
        if result.returncode != 0:
            return None, f"rnpath rc {result.returncode}: {result.stderr[-300:]!r}"
        try:
            entries = json.loads(result.stdout)
        except ValueError:
            return None, f"unparseable rnpath output: {result.stdout[:200]!r}"
        table = {}
        for entry in entries:
            table[str(entry.get("hash"))] = (str(entry.get("via")), entry.get("hops"),
                                            str(entry.get("interface")))
        return table, None

    def sample(self):
        now = time.time()
        record = {"t": round(now, 3), "procs": {}, "paths": {}}
        with self.procs_lock:
            procs = list(self.procs)
        for proc in procs:
            if not proc.alive():
                if not proc.exit_reported:
                    proc.exit_reported = True
                    self.event("process_exit", name=proc.name, role=proc.role,
                               impl=proc.impl, rc=proc.popen.returncode,
                               log_tail=tail(proc.log))
                continue
            stats = proc_stats(proc.pid)
            if stats:
                record["procs"][proc.name] = stats
        for node in self.nodes:
            if not node.daemon.alive():
                continue
            table, error = self.path_table(node)
            if table is None:
                record["paths"][node.name] = {"error": error}
                self.event("path_table_error", node=node.name, error=error)
                continue
            previous = self.last_paths.get(node.name)
            added = removed = changed = 0
            if previous is not None:
                added = len(table.keys() - previous.keys())
                removed = len(previous.keys() - table.keys())
                changed = sum(1 for k in table.keys() & previous.keys()
                              if table[k] != previous[k])
            self.last_paths[node.name] = table
            missing = sorted(name for h, name in self.expected.items() if h not in table)
            record["paths"][node.name] = {"count": len(table), "added": added,
                                          "removed": removed, "changed": changed,
                                          "missing": missing}
        self.samples.append(record)
        self.jsonl("samples.jsonl", record)
        return record

    def progress(self, record):
        counts = {}
        for op in self.ops:
            counts.setdefault(op["status"], 0)
            counts[op["status"]] += 1
        daemons = " ".join(
            f"{n.name}:{record['procs'].get(n.daemon.name, {}).get('rss_kb', 0) // 1024}MB"
            f"/{record['paths'].get(n.name, {}).get('count', '?')}p"
            for n in self.nodes)
        print(f"[{self.elapsed()}] ops={len(self.ops)} {counts} daemons(rss/paths): {daemons}",
              flush=True)

    # ----------------------------------------------------------------- main

    def run(self):
        os.makedirs(self.workdir, exist_ok=True)
        self.kill_stale()
        for sub in ("logs", "ops", "nodes"):
            os.makedirs(os.path.join(self.workdir, sub), exist_ok=True)
        for name in ("ops.jsonl", "samples.jsonl", "events.jsonl"):
            open(os.path.join(self.workdir, name), "w").close()
        self.build()
        self.started_at = time.time()
        self.write_announcer()
        self.make_nodes()
        self.start_daemons()
        self.start_clients()
        print(f"warming up for {self.args.warmup:.0f}s (announces propagate) ...", flush=True)
        self.stop.wait(self.args.warmup)
        self.sample()
        self.workload_started_at = time.time()
        end = self.workload_started_at + self.args.duration
        self.event("workload_start", duration=self.args.duration, seed=self.args.seed)
        workers = [threading.Thread(target=self.worker, args=(i,), daemon=True)
                   for i in range(self.args.workers)]
        for w in workers:
            w.start()
        next_sample = time.time() + self.args.sample_interval
        next_progress = time.time() + self.args.progress_interval
        while not self.stop.is_set() and time.time() < end:
            self.stop.wait(min(1.0, max(0.0, end - time.time())))
            if time.time() >= next_sample:
                record = self.sample()
                next_sample += self.args.sample_interval
                if time.time() >= next_progress:
                    self.progress(record)
                    next_progress += self.args.progress_interval
            if not any(n.daemon.alive() for n in self.nodes):
                self.event("all_daemons_dead")
                break
        self.event("workload_end")
        self.stop.set()
        # Let in-flight operations finish on their own deadline.
        for w in workers:
            w.join(timeout=self.args.op_timeout + self.args.max_size / self.args.min_rate + 10)
        self.sample()

    # -------------------------------------------------------------- summary

    def summarize(self):
        summary = {"seed": self.args.seed, "workdir": self.workdir,
                   "topology": self.args.topology,
                   "nodes": {n.name: n.impl for n in self.nodes},
                   "duration_s": round((self.samples[-1]["t"] - self.workload_started_at), 1)
                   if self.samples and self.workload_started_at else 0}
        anomalies = []

        # Operations.
        groups = {}
        for op in self.ops:
            for key in (op["op"], f"{op['op']} {op.get('client_impl')}->{op.get('target_impl')}"):
                groups.setdefault(key, []).append(op)
        op_summary = {}
        for key in sorted(groups):
            ops = groups[key]
            ok = [o["latency"] for o in ops if o["status"] == "ok"]
            by_status = {}
            for o in ops:
                by_status[o["status"]] = by_status.get(o["status"], 0) + 1
            op_summary[key] = {
                "total": len(ops), "status": by_status,
                "failure_rate": round(1 - len(ok) / len(ops), 4),
                "p50": percentile(ok, 0.5), "p95": percentile(ok, 0.95),
                "max": max(ok) if ok else None,
                "causes": {},
            }
            for o in ops:
                if o["status"] != "ok":
                    cause = f"{o['status']}: {o.get('detail') or 'rc ' + str(o.get('rc'))}"
                    op_summary[key]["causes"][cause] = op_summary[key]["causes"].get(cause, 0) + 1
            if " " not in key and by_status.get("stall"):
                anomalies.append(f"{by_status['stall']} stalled {key} operation(s)")
        summary["operations"] = op_summary
        failed = [o for o in self.ops if o["status"] != "ok"]
        summary["failed_ops"] = [
            {k: o.get(k) for k in ("id", "op", "client_impl", "client_node", "target_impl",
                                   "target_node", "size", "status", "detail", "latency")}
            for o in failed[:200]]
        for key, stats in op_summary.items():
            # Judge kinds from 10 operations on, implementation pairings from
            # 20, so that a pairing failing much more often stands out.
            if stats["total"] < (20 if " " in key else 10):
                continue
            if stats["failure_rate"] > self.args.max_failure_rate:
                anomalies.append(f"{key} failure rate {stats['failure_rate']:.1%}")

        # Process resources.
        proc_summary = {}
        warm = self.workload_started_at or 0
        names = sorted({name for s in self.samples for name in s["procs"]})
        for name in names:
            series = [(s["t"], s["procs"][name]) for s in self.samples if name in s["procs"]]
            rss = [(t - warm, v["rss_kb"] / 1024) for t, v in series if v.get("rss_kb")]
            fds = [(t - warm, v["fds"]) for t, v in series]
            if not rss:
                continue
            # Ignore the first fifth of the run when judging growth: buffers,
            # caches and tables fill up early.
            settled = [p for p in rss if p[0] >= 0.2 * rss[-1][0]] or rss
            slope = linear_slope(settled) * 3600
            quarter = max(1, len(settled) // 4)
            head = statistics.median(v for _, v in settled[:quarter])
            tail_rss = statistics.median(v for _, v in settled[-quarter:])
            rises = sum(1 for a, b in zip(settled, settled[1:]) if b[1] > a[1])
            falls = sum(1 for a, b in zip(settled, settled[1:]) if b[1] < a[1])
            fd_slope = linear_slope([p for p in fds if p[0] >= 0.2 * fds[-1][0]] or fds) * 3600
            entry = {
                "rss_start_mb": round(rss[0][1], 1), "rss_end_mb": round(rss[-1][1], 1),
                "rss_max_mb": round(max(v for _, v in rss), 1),
                "rss_slope_mb_per_h": round(slope, 2),
                "settled_growth_mb": round(tail_rss - head, 1),
                "rss_rises": rises, "rss_falls": falls,
                "fds_start": fds[0][1], "fds_end": fds[-1][1],
                "fds_max": max(v for _, v in fds),
                "fd_slope_per_h": round(fd_slope, 2),
            }
            proc_summary[name] = entry
            growth = tail_rss - head
            window = settled[-1][0] - settled[0][0]
            entry["settled_window_s"] = round(window)
            if (len(settled) >= 8 and window >= self.args.rss_min_window
                    and slope > self.args.rss_slope_threshold
                    and growth > max(2.0, 0.05 * head) and rises > 2 * max(1, falls)):
                anomalies.append(
                    f"{name}: RSS growing {slope:.1f} MB/h ({head:.1f} -> {tail_rss:.1f} MB, "
                    f"{rises} rises / {falls} falls)")
            if len(fds) >= 8 and fds[-1][1] - fds[0][1] > 20 and fd_slope > 10:
                anomalies.append(f"{name}: open fds growing {fds[0][1]} -> {fds[-1][1]}")
        summary["processes"] = proc_summary

        # Path tables.
        path_summary = {}
        for node in self.nodes:
            series = [s["paths"][node.name] for s in self.samples
                      if node.name in s.get("paths", {})]
            counts = [p["count"] for p in series if "count" in p]
            errors = sum(1 for p in series if "error" in p)
            if not counts:
                path_summary[node.name] = {"errors": errors}
                continue
            path_summary[node.name] = {
                "start": counts[0], "end": counts[-1], "min": min(counts),
                "max": max(counts),
                "added": sum(p.get("added", 0) for p in series),
                "removed": sum(p.get("removed", 0) for p in series),
                "changed": sum(p.get("changed", 0) for p in series),
                "errors": errors,
            }
            if errors:
                anomalies.append(f"{node.name}: {errors} path table query error(s)")
        summary["paths"] = path_summary
        # Every node should keep a path to every announced destination (probe
        # responders are not announced, they are found by path request).
        expected = len(self.expected)
        summary["expected_paths"] = expected
        for node in self.nodes:
            timed = [s for s in self.samples
                     if "missing" in s.get("paths", {}).get(node.name, {})]
            p = path_summary.get(node.name, {})
            if not timed:
                continue
            p["missing_end"] = timed[-1]["paths"][node.name]["missing"]
            # A destination missing over a whole announce interval (plus slack
            # for ingress control holds) is lost, not merely in flight.
            window = self.args.announce_interval + 180
            recent = [s["paths"][node.name]["missing"] for s in timed
                      if s["t"] >= timed[-1]["t"] - window]
            lost = set(recent[0]).intersection(*recent) if recent else set()
            if timed[-1]["t"] - timed[0]["t"] >= window and lost:
                anomalies.append(f"{node.name}: no path to {len(lost)} announced "
                                 f"destination(s): {', '.join(sorted(lost)[:6])}")
            if p.get("max", 0) > 2 * expected + 2 * len(self.nodes):
                anomalies.append(f"{node.name}: path table peaked at {p['max']} entries, "
                                 f"expected about {expected}")
            if p.get("removed", 0) or p.get("changed", 0):
                p["churn_per_h"] = round((p["removed"] + p["changed"]) * 3600
                                         / max(1, summary["duration_s"]), 1)

        # Process exits and log markers.
        exits = [e for e in self.events if e["kind"] == "process_exit"]
        for e in exits:
            anomalies.append(f"{e['name']} exited with rc {e['rc']}")
        markers = {}
        for proc in self.procs:
            try:
                with open(proc.log, "r", errors="replace") as f:
                    for line in f:
                        for marker in LOG_MARKERS:
                            if marker in line:
                                markers.setdefault(proc.name, {}).setdefault(marker, 0)
                                markers[proc.name][marker] += 1
            except OSError:
                pass
        summary["log_markers"] = markers
        for name, found in markers.items():
            if "panicked" in found or "Traceback" in found:
                anomalies.append(f"{name}: log contains {found}")
        summary["anomalies"] = anomalies
        with open(os.path.join(self.workdir, "summary.json"), "w") as f:
            json.dump(summary, f, indent=2, sort_keys=True)
        return summary


def print_summary(summary):
    print("\n==================== soak summary ====================")
    print(f"workdir {summary['workdir']}  seed {summary['seed']}  topology "
          f"{summary['topology']}  workload {summary['duration_s'] / 60:.1f} min")
    print("\noperations (latency of successful ops, seconds):")
    print(f"  {'kind':<24}{'total':>7}{'ok':>7}{'fail':>6}{'stall':>6}{'err':>5}"
          f"{'fail%':>8}{'p50':>8}{'p95':>8}{'max':>8}")
    fmt = lambda v: f"{v:8.2f}" if v is not None else f"{'-':>8}"  # noqa: E731
    for key, s in summary["operations"].items():
        st = s["status"]
        print(f"  {key:<24}{s['total']:>7}{st.get('ok', 0):>7}{st.get('fail', 0):>6}"
              f"{st.get('stall', 0):>6}{st.get('error', 0):>5}{s['failure_rate']:>8.1%}"
              f"{fmt(s['p50'])}{fmt(s['p95'])}{fmt(s['max'])}")
    causes = {k: v["causes"] for k, v in summary["operations"].items()
              if v["causes"] and " " not in k}
    if causes:
        print("\nfailure causes:")
        for key, found in causes.items():
            print(f"  {key}: " + ", ".join(f"{c} x{n}" for c, n in found.items()))
    print("\nprocesses (RSS MB, fds):")
    print(f"  {'name':<20}{'start':>8}{'end':>8}{'max':>8}{'MB/h':>8}{'growth':>8}"
          f"{'fds':>10}")
    for name, p in summary["processes"].items():
        print(f"  {name:<20}{p['rss_start_mb']:>8.1f}{p['rss_end_mb']:>8.1f}"
              f"{p['rss_max_mb']:>8.1f}{p['rss_slope_mb_per_h']:>8.2f}"
              f"{p['settled_growth_mb']:>8.1f}{str(p['fds_start']) + '->' + str(p['fds_end']):>10}")
    print("\npath tables:")
    for name, p in summary["paths"].items():
        print(f"  {name:<6} " + " ".join(
            f"{k}={len(v) if isinstance(v, list) else v}" for k, v in p.items()))
    print(f"  ({summary['expected_paths']} announced destinations, plus probe responders "
          "found by path request)")
    if summary["log_markers"]:
        print("\nlog markers:")
        for name, found in summary["log_markers"].items():
            print(f"  {name}: {found}")
    print("\nanomalies:")
    for a in summary["anomalies"] or ["none"]:
        print(f"  - {a}")
    print("=======================================================", flush=True)


ANNOUNCER = r'''
import os, sys, time, random
import RNS

config, base, count, interval = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
RNS.Reticulum(config)
destinations = []
for i in range(count):
    path = os.path.join(base, f"identity-{i}")
    identity = RNS.Identity.from_file(path) if os.path.exists(path) else None
    if identity is None:
        identity = RNS.Identity()
        identity.to_file(path)
    destinations.append(RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                                        "soak", "announcer", str(i)))
# A client registering a destination answers the shared instance with a
# path response at once; an announce emitted within the same second carries
# the same emission timestamp and would not be rebroadcast.
time.sleep(2.0)
counter = 0
while True:
    for destination in destinations:
        counter += 1
        destination.announce(app_data=f"soak {counter}".encode())
        time.sleep(random.uniform(0.2, 1.0))
    time.sleep(interval * random.uniform(0.8, 1.2))
'''


def build_parser():
    parser = argparse.ArgumentParser(
        description="Mixed Rust/upstream Reticulum mesh soak test",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--duration", default="10m", help="workload duration (e.g. 45m, 24h)")
    parser.add_argument("--workdir", default=None,
                        help="work directory (default: a new temporary directory)")
    parser.add_argument("--seed", type=int, default=None, help="random seed")
    parser.add_argument("--rust-nodes", type=int, default=2)
    parser.add_argument("--python-nodes", type=int, default=2)
    parser.add_argument("--topology", choices=["ring", "line", "star"], default="ring")
    parser.add_argument("--workers", type=int, default=4, help="concurrent operation loops")
    parser.add_argument("--op-interval", type=float, default=5.0,
                        help="mean pause between a worker's operations (s)")
    parser.add_argument("--op-timeout", type=float, default=90.0,
                        help="base deadline for an operation before it counts as stalled (s)")
    parser.add_argument("--min-rate", type=float, default=16384.0,
                        help="transfer rate below which a transfer counts as stalled (B/s)")
    parser.add_argument("--link-timeout", type=int, default=30,
                        help="path/link timeout passed to the utilities (-w/-t)")
    parser.add_argument("--settle-timeout", type=float, default=15.0,
                        help="time for a received file to appear after the sender finished")
    parser.add_argument("--max-size", type=int, default=3 * 1024 * 1024,
                        help="largest random transfer (bytes)")
    parser.add_argument("--fetch-sizes", type=lambda s: [int(x) for x in s.split(",")],
                        default=[700, 48_000, 400_000, 1_500_000],
                        help="sizes of the files each listener offers for fetch")
    parser.add_argument("--announce-interval", type=float, default=300.0,
                        help="announce interval of listeners and announcers (s)")
    parser.add_argument("--announcers", type=int, default=5,
                        help="announcing destinations per node (0 disables)")
    parser.add_argument("--no-rnx", dest="rnx", action="store_false",
                        help="do not run rnx listeners and commands")
    parser.add_argument("--weight-send", type=float, default=4)
    parser.add_argument("--weight-fetch", type=float, default=2)
    parser.add_argument("--weight-probe", type=float, default=3)
    parser.add_argument("--weight-rnx", type=float, default=1)
    parser.add_argument("--sample-interval", type=float, default=30.0)
    parser.add_argument("--progress-interval", type=float, default=300.0)
    parser.add_argument("--warmup", type=float, default=20.0)
    parser.add_argument("--loglevel", type=int, default=4, help="daemon log level")
    parser.add_argument("--rss-slope-threshold", type=float, default=1.0,
                        help="flag processes whose settled RSS grows faster (MB/h)")
    parser.add_argument("--rss-min-window", type=float, default=1200.0,
                        help="judge RSS growth only over at least this much settled time (s)")
    parser.add_argument("--max-failure-rate", type=float, default=0.02,
                        help="flag operation kinds failing more often than this")
    parser.add_argument("--upstream", default=os.environ.get(
        "RETICULUM_UPSTREAM_DIR", os.path.expanduser("~/Reticulum")),
        help="upstream Python Reticulum checkout")
    parser.add_argument("--target-dir", default=os.environ.get(
        "CARGO_TARGET_DIR", os.path.join(REPO_ROOT, "target")))
    parser.add_argument("--no-build", action="store_true", help="use existing binaries")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.duration = parse_duration(args.duration)
    args.target_dir = os.path.abspath(args.target_dir)
    if args.seed is None:
        args.seed = random.SystemRandom().randrange(1 << 31)
    if args.workdir is None:
        args.workdir = tempfile.mkdtemp(prefix="rns-soak-")
    if args.rust_nodes + args.python_nodes < 2:
        parser.error("need at least two nodes")
    sys.path.insert(0, args.upstream)

    soak = Soak(args)

    def on_signal(signum, _frame):
        raise KeyboardInterrupt(f"signal {signum}")

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGHUP, on_signal)
    interrupted = False
    try:
        soak.run()
    except KeyboardInterrupt:
        interrupted = True
        print("\ninterrupted, shutting down ...", flush=True)
        soak.event("interrupted")
    finally:
        soak.stop.set()
        soak.cleanup()
    if soak.workload_started_at:
        summary = soak.summarize()
        print_summary(summary)
        print(f"logs and records in {soak.workdir}")
        return 1 if summary["anomalies"] or interrupted else 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
