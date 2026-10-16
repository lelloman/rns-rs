#!/usr/bin/env python3
"""rns_e2e_control.py — HTTP control server for a Python Reticulum node.

Used by the shared-instance-links Docker E2E test (GitHub issue #183) to
drive real Python RNS nodes from test.sh with curl + jq, mirroring the
shape of the rns-ctl HTTP API.

The node owns one IN SINGLE destination (<app-name>.node). Inbound and
outbound links are tracked, and link establishment, link closure and
received link packets are recorded as events.

Endpoints (JSON):
  GET  /health                 {"status": "healthy"} once RNS is up
  GET  /info                   {"dest_hash", "identity_hash", "connected_to_shared_instance"}
  POST /announce               announce the destination
  GET  /identity/<hex>         {"known": bool}
  GET  /path/<hex>             {"has_path": bool, "hops": int|null}
  POST /link                   {"dest_hash", "aspects", "timeout"} -> {"link_id", "state", "rtt"}
  POST /link/send              {"link_id", "data" (base64), "timeout"} -> {"ok", "delivered"}
  POST /link/resource          {"link_id", "data" (base64), "timeout"} -> {"ok", "status"}
  POST /link/close             {"link_id"} -> {"ok"}
  GET  /links                  {"links": [{link_id, state, is_initiator, rtt}]}
  GET  /events                 {"events": [{type, link_id, is_initiator, data?}]}

Only the Python standard library and the `rns` package are used.
"""

import argparse
import base64
import json
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import RNS

STATE_NAMES = {
    RNS.Link.PENDING: "pending",
    RNS.Link.HANDSHAKE: "handshake",
    RNS.Link.ACTIVE: "active",
    RNS.Link.STALE: "stale",
    RNS.Link.CLOSED: "closed",
}


class Node:
    def __init__(self, configdir, app_name):
        self.lock = threading.Lock()
        self.links = {}  # link_id hex -> (link, is_initiator)
        self.events = []
        self.app_name = app_name
        self.reticulum = RNS.Reticulum(
            configdir=configdir, loglevel=RNS.LOG_DEBUG, logdest=RNS.LOG_STDOUT
        )
        self.identity = RNS.Identity()
        self.destination = RNS.Destination(
            self.identity, RNS.Destination.IN, RNS.Destination.SINGLE, app_name, "node"
        )
        self.destination.set_proof_strategy(RNS.Destination.PROVE_ALL)
        self.destination.set_link_established_callback(self._inbound_established)
        RNS.log(
            f"E2E control node ready, destination {RNS.prettyhexrep(self.destination.hash)}, "
            f"shared-instance client: {self.reticulum.is_connected_to_shared_instance}"
        )

    # ── event recording ──────────────────────────────────────────────────

    def _record(self, event):
        event["time"] = time.time()
        with self.lock:
            self.events.append(event)

    def _track(self, link, is_initiator):
        lid = link.link_id.hex()
        with self.lock:
            self.links[lid] = (link, is_initiator)
        link.set_packet_callback(
            lambda message, packet, lid=lid, init=is_initiator: self._record(
                {
                    "type": "packet",
                    "link_id": lid,
                    "is_initiator": init,
                    "data": base64.b64encode(message).decode(),
                }
            )
        )
        link.set_link_closed_callback(
            lambda l, init=is_initiator: self._record(
                {"type": "link_closed", "link_id": l.link_id.hex(), "is_initiator": init}
            )
        )
        link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
        link.set_resource_concluded_callback(
            lambda resource, lid=lid, init=is_initiator: self._resource_concluded(
                resource, lid, init
            )
        )

    def _resource_concluded(self, resource, lid, is_initiator):
        event = {"type": "resource", "link_id": lid, "is_initiator": is_initiator}
        if resource.status == RNS.Resource.COMPLETE and resource.data is not None:
            event["data"] = base64.b64encode(resource.data.read()).decode()
        else:
            event["status"] = resource.status
        self._record(event)

    def _inbound_established(self, link):
        self._track(link, False)
        self._record(
            {"type": "link_established", "link_id": link.link_id.hex(), "is_initiator": False}
        )

    def _outbound_established(self, link):
        self._record(
            {"type": "link_established", "link_id": link.link_id.hex(), "is_initiator": True}
        )

    # ── operations ───────────────────────────────────────────────────────

    def info(self):
        return {
            "dest_hash": self.destination.hash.hex(),
            "identity_hash": self.identity.hash.hex(),
            "connected_to_shared_instance": bool(self.reticulum.is_connected_to_shared_instance),
        }

    def announce(self):
        self.destination.announce()
        return {"ok": True, "dest_hash": self.destination.hash.hex()}

    def path(self, dest_hex):
        dest = bytes.fromhex(dest_hex)
        has = RNS.Transport.has_path(dest)
        return {"has_path": has, "hops": RNS.Transport.hops_to(dest) if has else None}

    def create_link(self, dest_hex, timeout, aspects):
        dest = bytes.fromhex(dest_hex)
        deadline = time.time() + timeout
        if not RNS.Transport.has_path(dest):
            RNS.Transport.request_path(dest)
            while not RNS.Transport.has_path(dest) and time.time() < deadline:
                time.sleep(0.1)
            if not RNS.Transport.has_path(dest):
                raise RuntimeError(f"no path to {dest_hex}")
        identity = RNS.Identity.recall(dest)
        if identity is None:
            raise RuntimeError(f"identity for {dest_hex} not known")
        out = RNS.Destination(
            identity, RNS.Destination.OUT, RNS.Destination.SINGLE, self.app_name, *aspects
        )
        if out.hash != dest:
            raise RuntimeError(
                f"{self.app_name}.{'.'.join(aspects)} for that identity is "
                f"{out.hash.hex()}, not {dest_hex}"
            )
        link = RNS.Link(out, established_callback=self._outbound_established)
        self._track(link, True)
        while link.status not in (RNS.Link.ACTIVE, RNS.Link.CLOSED) and time.time() < deadline:
            time.sleep(0.1)
        return self._link_json(link.link_id.hex(), link, True)

    def _get_link(self, lid):
        with self.lock:
            entry = self.links.get(lid)
        if entry is None:
            raise KeyError(f"unknown link {lid}")
        return entry[0]

    def link_send(self, lid, data, timeout):
        link = self._get_link(lid)
        receipt = RNS.Packet(link, data).send()
        if not receipt:
            raise RuntimeError("packet send failed")
        deadline = time.time() + timeout
        while receipt.get_status() == RNS.PacketReceipt.SENT and time.time() < deadline:
            time.sleep(0.1)
        return {"ok": True, "delivered": receipt.get_status() == RNS.PacketReceipt.DELIVERED}

    def link_resource(self, lid, data, timeout):
        link = self._get_link(lid)
        done = threading.Event()
        resource = RNS.Resource(data, link, callback=lambda r: done.set())
        done.wait(timeout)
        return {"ok": True, "status": resource.status, "complete": resource.status == RNS.Resource.COMPLETE}

    def link_close(self, lid):
        self._get_link(lid).teardown()
        return {"ok": True}

    @staticmethod
    def _link_json(lid, link, is_initiator):
        return {
            "link_id": lid,
            "state": STATE_NAMES.get(link.status, str(link.status)),
            "is_initiator": is_initiator,
            "rtt": link.rtt,
        }

    def list_links(self):
        with self.lock:
            items = list(self.links.items())
        return {"links": [self._link_json(lid, l, init) for lid, (l, init) in items]}

    def list_events(self):
        with self.lock:
            return {"events": list(self.events)}


NODE = None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # keep compose logs focused on RNS
        pass

    def _reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def _dispatch(self, method):
        path = self.path.split("?", 1)[0]
        try:
            if method == "GET" and path == "/health":
                if NODE is None:
                    return self._reply(503, {"status": "starting"})
                return self._reply(200, {"status": "healthy"})
            if NODE is None:
                return self._reply(503, {"error": "node not ready"})
            if method == "GET":
                if path == "/info":
                    return self._reply(200, NODE.info())
                if path.startswith("/identity/"):
                    dest = bytes.fromhex(path[len("/identity/"):])
                    return self._reply(200, {"known": RNS.Identity.recall(dest) is not None})
                if path.startswith("/path/"):
                    return self._reply(200, NODE.path(path[len("/path/"):]))
                if path == "/links":
                    return self._reply(200, NODE.list_links())
                if path == "/events":
                    return self._reply(200, NODE.list_events())
            elif method == "POST":
                body = self._body()
                timeout = float(body.get("timeout", 20))
                if path == "/announce":
                    return self._reply(200, NODE.announce())
                if path == "/link":
                    aspects = body.get("aspects", ["node"])
                    return self._reply(
                        200, NODE.create_link(body["dest_hash"], timeout, aspects)
                    )
                if path == "/link/send":
                    data = base64.b64decode(body["data"])
                    return self._reply(200, NODE.link_send(body["link_id"], data, timeout))
                if path == "/link/resource":
                    data = base64.b64decode(body["data"])
                    return self._reply(200, NODE.link_resource(body["link_id"], data, timeout))
                if path == "/link/close":
                    return self._reply(200, NODE.link_close(body["link_id"]))
            return self._reply(404, {"error": f"no route {method} {path}"})
        except Exception as e:  # report every failure to the caller
            traceback.print_exc()
            return self._reply(500, {"error": f"{type(e).__name__}: {e}"})

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")


def main():
    global NODE
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", required=True, help="Reticulum config directory")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--app-name", default="e2esil")
    args = parser.parse_args()

    server = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    NODE = Node(args.config, args.app_name)
    print(f"Control server listening on 0.0.0.0:{args.port}", flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
