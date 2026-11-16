#!/usr/bin/env python3
"""Generate rnstatus display fixtures from upstream's own rnstatus.

PYTHONPATH=/path/to/Reticulum python3 tests/generate_rnstatus_fixtures.py

Each case feeds a stats dict to upstream's `program_setup` through a stand-in
Reticulum instance, with `time.time()` pinned, and stores the inputs
(`<case>.pickle`) next to upstream's exact output (`<case>.txt`). The Rust
test `rnstatus_view_matches_upstream` renders the same inputs and compares
byte for byte. The checkout must be RNS 1.6.1 (rgit 884f109b).
"""
import contextlib
import copy
import io
import pickle
import shutil
import types
from pathlib import Path

import RNS
import RNS.Utilities.rnstatus as rnstatus

assert RNS.__version__ == "1.6.1", RNS.__version__

NOW = 1_763_200_000.25
OUT = Path(__file__).resolve().parent / "fixtures/rnstatus"

FULL, P2P, AP, ROAMING, BOUNDARY, GATEWAY = 1, 2, 3, 4, 5, 6


def iface(name, **kw):
    s = {
        "name": name, "short_name": name.split("[")[0], "hash": bytes(32),
        "type": name.split("[")[0], "status": True, "mode": FULL,
        "bitrate": None, "mtu": 500, "clients": None,
        "rxb": 0, "txb": 0, "rxs": 0, "txs": 0,
        "frxb": 0, "ftxb": 0, "frxs": 0, "ftxs": 0,
        "arxs": 0, "atxs": 0, "prxs": 0, "ptxs": 0,
        "announce_queue": None, "held_announces": 0,
        "incoming_announce_frequency": 0.0, "outgoing_announce_frequency": 0.0,
        "incoming_pr_frequency": 0.0, "outgoing_pr_frequency": 0.0,
        "arxc": 0, "atxc": 0, "afrxc": 0, "prxc": 0, "ptxc": 0,
        "txdrp": 0, "txdrb": 0, "txbuffered": 0, "txstalled": False,
        "protocol_violations": 0, "ifac_violations": 0, "packet_filter_hits": 0,
        "burst_active": False, "burst_activated": 0, "burst_count": 0,
        "pr_burst_active": False, "pr_burst_activated": 0, "pr_burst_count": 0,
        "ifac_signature": None, "ifac_size": None, "ifac_netname": None,
        "autoconnect_source": None, "gravity": 0, "announces_to_internal": False,
        "announce_rate_target": None, "announce_rate_grace": None,
        "announce_rate_penalty": None,
        "tunnel_id": None, "remote_transport_id": None,
        "rem_impl": None, "rem_vers": None, "rem_is_tn": None,
        "rem_dst_cost": None, "rem_pr_cost": None,
    }
    s.update(kw)
    return s


def totals(**kw):
    s = {
        "rxb": 123456789, "txb": 98765, "rxs": 12345.678, "txs": 0,
        "frxb": 4321, "ftxb": 0, "frxs": 12.5, "ftxs": 0.0,
        "prxb": 2048, "ptxb": 1024, "prxs": 800.0, "ptxs": 0.0,
        "arxb": 65536, "atxb": 512, "arxs": 3000.0, "atxs": 0.0,
        "prxf": 0.25, "ptxf": 0.0, "arxf": 1.5, "atxf": 0.0125,
        "rxpps": 12.0, "txpps": 1534.2,
        "rxqt": 10, "rxqd": 4, "rxqa": 3, "rxqp": 2, "rxqil": 1,
        "rxqtd": 0, "rxqdd": 2, "rxqad": 0, "rxqpd": 7, "rxqild": 0,
        "tqpressure": 0.125, "dqpressure": 0.0, "aqpressure": 1,
        "pqpressure": 0.33333, "ilqpressure": 0.05,
    }
    s.update(kw)
    return s


SHARED = iface("Shared Instance[rns/default]", clients=3, bitrate=1_000_000_000, mtu=262144,
               rxb=4096, txb=8192, rxs=1200.0, txs=64.0,
               incoming_announce_frequency=0.5, outgoing_announce_frequency=1.5,
               incoming_pr_frequency=0.1, outgoing_pr_frequency=3,
               arxc=12, atxc=40, afrxc=3, prxc=5, ptxc=9, arxs=600.0, atxs=60.0,
               prxs=100.0, ptxs=4.0)
TCP_SERVER = iface("TCPServerInterface[Server/0.0.0.0:4242]", clients=1, bitrate=10_000_000,
                   mtu=16384, rxb=999, txb=1000, rxs=7.5, txs=81234.0, gravity=3,
                   announces_to_internal=True, blocked_ips=2,
                   blocked_ip_list=["10.0.0.1", "10.0.0.2"],
                   ifac_signature=bytes(range(64)), ifac_size=16, ifac_netname="testnet",
                   txdrp=4, txdrb=2048, txbuffered=1500, txstalled=True,
                   protocol_violations=2, ifac_violations=0, packet_filter_hits=17,
                   incoming_announce_frequency=1234.5, outgoing_announce_frequency=0,
                   arxc=1, atxc=0, announce_queue=1, held_announces=5,
                   announce_rate_target=3600, announce_rate_penalty=7200,
                   announce_rate_grace=2,
                   burst_active=True, burst_activated=NOW - 75.5, burst_count=12,
                   pr_burst_active=True, pr_burst_activated=NOW - 3, pr_burst_count=0,
                   tunnel_id=bytes([0xAB] * 16), remote_transport_id=None,
                   rem_impl="RNS", rem_vers=(1, 6, 1), rem_is_tn=True,
                   rem_dst_cost=23.5, rem_pr_cost=15.8)
TCP_CLIENT = iface("TCPInterface[Client on Server/10.0.0.9:51000]", bitrate=10_000_000, mtu=16384,
                   rxb=10, txb=20, tunnel_id=None, remote_transport_id=bytes([0xCD] * 16))
TCP_OUT = iface("TCPInterface[Uplink/192.0.2.1:4242]", bitrate=10_000_000, mtu=16384,
                mode=GATEWAY, status=False, rxb=1_500_000_000_000, txb=1001,
                autoconnect_source="aabbccddeeff00112233445566778899",
                protocol_violations=0, ifac_violations=3,
                announce_rate_target=600.5, announce_rate_penalty=0,
                incoming_announce_frequency=5, outgoing_announce_frequency=0.00012,
                incoming_pr_frequency=0, outgoing_pr_frequency=0.75)
LOCAL = iface("LocalInterface[37428]", bitrate=1_000_000_000, mtu=262144, rxb=1, txb=2)
RNODE = iface("RNodeInterface[LoRa]", bitrate=3125, mtu=508, mode=ACCESS_POINT if False else AP,
              noise_floor=-99, interference=None, interference_last_ts=NOW - 3725,
              interference_last_dbm=-71, cpu_temp=None, battery_percent=87.9,
              battery_state="charging", airtime_short=0.53, airtime_long=1,
              channel_load_short=12.25, channel_load_long=0.0, peers=None)
RNODE2 = iface("RNodeInterface[LoRa2]", bitrate=1953.125, mtu=508, mode=ROAMING,
               noise_floor=-104, interference=-80, cpu_load=None, cpu_temp=41, mem_load=55,
               battery_percent=None)
RNODE3 = iface("RNodeInterface[LoRa3]", bitrate=None, mode=BOUNDARY, noise_floor=None,
               interference=0, cpu_load=17.5, mem_load=33.25)
RNODE4 = iface("RNodeInterface[LoRa4]", mode=P2P, noise_floor=-120, interference=0)
WEAVE = iface("WeaveInterface[Weave]", bitrate=2_000_000, mtu=1064, switch_id="sw1",
              endpoint_id=None, via_switch_id="sw0", peers=4, clients=None,
              incoming_announce_frequency=0.75, outgoing_announce_frequency=0.25,
              incoming_pr_frequency=0.2, outgoing_pr_frequency=0.4)
WEAVE_PEER = iface("WeaveInterfacePeer[abc]", rxb=1)
AUTO = iface("AutoInterface[Default]", bitrate=10_000_000, mtu=1196, peers=0, rxb=12, txb=0,
             gravity=-1)
AUTO_PEER = iface("AutoInterfacePeer[eth0/fe80::1]", rxb=3)
BACKBONE_CLIENT = iface("BackboneInterface[Client on Backbone]", rxb=4,
                        tunnel_id=bytes([0xEF] * 32), remote_transport_id=bytes([0x12] * 16))
I2P_OK = iface("I2PInterface[I2P]", clients=1, i2p_connectable=True, tunnelstate="Tunnel active",
               i2p_b32="abcdefghijklmnop.b32.i2p", bitrate=256000, mtu=1064)
I2P_MANY = iface("I2PInterface[I2P2]", clients=3, i2p_connectable=True, mtu=1064)
I2P_UNCONN = iface("I2PInterface[I2P3]", clients=0, i2p_connectable=False)
I2P_PEER = iface("I2PInterfacePeer[Connected peer 1]", rxb=9)
UDP_NOFLOW = iface("UDPInterface[UDP]", bitrate=10_000_000, mtu=1064,
                   incoming_announce_frequency=0.5, outgoing_announce_frequency=0.5)
for k in ("prxs", "ptxs"):
    del UDP_NOFLOW[k]
NO_SPEED = iface("SerialInterface[Serial]", bitrate=9600, mtu=564, rxb=5, txb=6)
for k in ("rxs", "txs", "frxs", "ftxs"):
    del NO_SPEED[k]
SHARED_ONE = iface("Shared Instance[rns/other]", clients=2, outgoing_announce_frequency=2,
                   incoming_announce_frequency=1, outgoing_pr_frequency=0.0,
                   incoming_pr_frequency=0.0)
SHARED_EMPTY = iface("Shared Instance[rns/empty]", clients=0)

ALL = [SHARED, TCP_SERVER, TCP_CLIENT, TCP_OUT, LOCAL, RNODE, RNODE2, RNODE3, RNODE4, WEAVE,
       WEAVE_PEER, AUTO, AUTO_PEER, BACKBONE_CLIENT, I2P_OK, I2P_MANY, I2P_UNCONN, I2P_PEER,
       UDP_NOFLOW, NO_SPEED, SHARED_ONE, SHARED_EMPTY]

TRANSPORT = {"transport_id": bytes(range(16)), "network_id": bytes(range(16, 32)),
             "probe_responder": bytes(range(32, 48)), "transport_uptime": 93784.5}

PROFILING = {
    "root": {"name": "root", "super": None,
             "stats_all": {"count": 120, "threads": 1, "mean": 0.000012, "median": 0.0015,
                           "min": 0.0, "max": 1.25, "stdev": None, "sum": 2.0000125},
             "stats_1m": {"count": 3, "threads": 2, "mean": 0.5, "median": 0.25,
                          "min": 0.1, "max": 0.9, "stdev": 0.01, "sum": 1.5},
             "stats_5m": None, "stats_30m": None,
             "stats_60m": {"count": 1, "threads": 1, "mean": 3.0, "median": 3.0,
                           "min": 3.0, "max": 3.0, "stdev": 0.0, "sum": 3.0}},
    "child": {"name": "child", "super": "root",
              "stats_all": {"count": 7, "threads": 0, "mean": 0.002, "median": 0.002,
                            "min": 0.001, "max": 0.004, "stdev": 0.0005, "sum": 0.014},
              "stats_1m": None, "stats_5m": None, "stats_30m": None, "stats_60m": None},
    "other": {"name": "other", "super": None,
              "stats_all": {"count": 1, "threads": 4, "mean": 61.0, "median": 61.0,
                            "min": 61.0, "max": 61.0, "stdev": 0.0, "sum": 61.0},
              "stats_1m": None, "stats_5m": None, "stats_30m": None, "stats_60m": None},
}


def stats(interfaces=ALL, transport=True, **kw):
    s = totals(**kw)
    s["interfaces"] = interfaces
    if transport:
        s.update(TRANSPORT)
    return s


CASES = {
    "default": (stats(), {}),
    "all": (stats(), {"dispall": True}),
    "announces": (stats(), {"dispall": True, "astats": True}),
    "path_requests": (stats(), {"dispall": True, "pstats": True}),
    "announces_and_path_requests": (stats(), {"dispall": True, "astats": True, "pstats": True}),
    "totals": (stats(), {"traffic_totals": True}),
    "totals_everything": (stats(), {"traffic_totals": True, "pps": True, "fstats": True,
                                    "astats": True, "pstats": True}),
    "totals_idle": (stats(rxs=0, txs=0.0, rxpps=0, txpps=0), {"traffic_totals": True,
                                                              "astats": True, "pps": True}),
    "filtered": (stats(), {"fstats": True}),
    "queues": (stats(), {"queue_stats": True}),
    "links_transport": (stats(), {"lstats": True, "link_count": 1, "active_link_count": 0}),
    "links_no_transport": (stats(transport=False),
                           {"lstats": True, "link_count": 3, "active_link_count": 2}),
    "links_none": (stats(transport=False), {"lstats": True, "link_count": None}),
    "no_transport": (stats(transport=False), {}),
    "sort_rx": (stats(), {"dispall": True, "sorting": "rx"}),
    "sort_rx_reverse": (stats(), {"dispall": True, "sorting": "RX", "sort_reverse": True}),
    "sort_traffic": (stats(), {"sorting": "traffic"}),
    "sort_announces": (stats(), {"dispall": True, "sorting": "anns"}),
    "sort_unknown": (stats(), {"sorting": "nonsense"}),
    "filter": (stats(), {"dispall": True, "name_filter": "rnode"}),
    "burst_filter": (stats(), {"dispall": True, "burst_filter": True}),
    "burst_filter_and_name": (stats(), {"dispall": True, "burst_filter": True,
                                        "name_filter": "lora2"}),
    "blocked_ips": (stats(), {"blocked_ips": True}),
    "tunnels": (stats(), {"dispall": True, "tstats": True}),
    "profiling": (stats(interfaces=[]), {"profiling": PROFILING}),
    "empty": (stats(interfaces=[], transport=False), {}),
}


def record(name, type_, status, last_heard_ago, impl=("RNS", "1.6.0"), extra=(), **kw):
    """A record as list_discovered_interfaces() returns it, in its key order."""
    r = {"type": type_, "impl_name": impl[0] if impl else None,
         "version": impl[1] if impl else None, "transport": kw.pop("transport", True),
         "name": name, "received": NOW - last_heard_ago, "stamp": bytes(range(8)),
         "value": kw.pop("value", 24.734375), "transport_id": kw.pop("transport_id", "11" * 16),
         "network_id": kw.pop("network_id", "22" * 16), "dst_cost": kw.pop("dst_cost", None),
         "pr_cost": kw.pop("pr_cost", None), "hops": kw.pop("hops", 2),
         "latitude": kw.pop("latitude", None), "longitude": kw.pop("longitude", None),
         "height": kw.pop("height", None)}
    for k, v in extra:
        r[k] = v
    if kw.pop("config", True):
        r["config_entry"] = f"[[{name}]]\n  type = {type_}\n  enabled = yes"
    r["discovery_hash"] = bytes([len(name)] * 32)
    if "lxmf" in kw:
        r["operator_lxmf_address"] = kw.pop("lxmf")
    r["discovered"] = NOW - last_heard_ago - kw.pop("age", 3600)
    r["last_heard"] = NOW - last_heard_ago
    r["heard_count"] = kw.pop("heard_count", 4)
    r["status"] = status
    r["status_code"] = {"available": 1000, "unknown": 100, "stale": 0}[status]
    assert not kw, kw
    return r


DISCOVERED = [
    record("Backbone North", "BackboneInterface", "available", 12, latitude=45.123456,
           longitude=-7.5, height=312.0, dst_cost=12.5, pr_cost=0, hops=1,
           lxmf="33" * 16, extra=[("reachable_on", "198.51.100.7"), ("port", 4242)]),
    record("A very long discovered interface name", "RNodeInterface", "available", 150,
           impl=("Reticulum Rust Implementation", "0.9.2"),
           extra=[("frequency", 868000000), ("bandwidth", 125000), ("sf", 8), ("cr", 5)]),
    record("Stale TCP", "TCPServerInterface", "stale", 4 * 86400, transport=False,
           extra=[("reachable_on", "example.org"), ("port", 4965)]),
    record("Old Weave", "WeaveInterface", "unknown", 2 * 86400, impl=None, value=0, config=False,
           extra=[("frequency", 2400000000.5), ("bandwidth", 1000000), ("channel", 3),
                  ("modulation", "GFSK")]),
    record("Same Ids", "I2PInterface", "available", 7300, transport_id="44" * 16,
           network_id="44" * 16, latitude=1, longitude=2.0,
           extra=[("reachable_on", "abc.b32.i2p")]),
    record("Kiss", "KISSInterface", "unknown", 30, impl=("RNS", ""), dst_cost=3.0,
           pr_cost=None, extra=[("frequency", 144800000), ("bandwidth", 12500),
                                ("modulation", "AFSK")]),
]

DISCOVERY_CASES = {
    "discovered": {},
    "discovered_stale_unknown": {"show_stale": True, "show_unknown": True},
    "discovered_filter": {"show_unknown": True, "name_filter": "o"},
    "discovered_details": {"config_entries": True},
    "discovered_details_all": {"config_entries": True, "show_stale": True,
                               "show_unknown": True},
    "discovered_details_filter": {"config_entries": True, "show_stale": True,
                                  "name_filter": "STALE"},
    "discovered_json": {"json": True},
    "discovered_empty": {"interfaces": []},
}


class FakeDiscovery:
    records = []

    def __init__(self, discover_interfaces=False): pass
    def list_discovered_interfaces(self): return copy.deepcopy(FakeDiscovery.records)


class FakeReticulum:
    def __init__(self, stats, link_count, active_link_count, profiling):
        self.stats, self.lc, self.alc, self.prof = stats, link_count, active_link_count, profiling

    def get_interface_stats(self): return copy.deepcopy(self.stats)
    def get_link_count(self): return self.lc
    def get_active_link_count(self): return self.alc
    def get_profiling_results(self): return self.prof


rnstatus.time = types.SimpleNamespace(time=lambda: NOW, sleep=lambda _: None)

OPTION_KEYS = ["dispall", "name_filter", "astats", "pstats", "lstats", "sorting",
               "sort_reverse", "traffic_totals", "burst_filter", "blocked_ips",
               "queue_stats", "pps", "fstats", "tstats"]

shutil.rmtree(OUT, ignore_errors=True)
OUT.mkdir(parents=True)
for case, (st, opts) in CASES.items():
    opts = dict(opts)
    link_count = opts.pop("link_count", None)
    active_link_count = opts.pop("active_link_count", None)
    profiling = opts.pop("profiling", None)
    kwargs = {k: opts.get(k, None if k in ("name_filter", "sorting") else False)
              for k in OPTION_KEYS}
    fake = FakeReticulum(st, link_count, active_link_count, profiling)
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        rnstatus.program_setup(configdir=None, json=False, remote=None, must_exit=False,
                               rns_instance=fake, profiling=profiling is not None, **kwargs)
    inputs = {"stats": st, "options": kwargs, "link_count": link_count,
              "active_link_count": active_link_count, "profiling": profiling, "now": NOW}
    (OUT / f"{case}.pickle").write_bytes(pickle.dumps(inputs, protocol=2))
    (OUT / f"{case}.txt").write_text(buffer.getvalue())
    print(f"{case}: {len(buffer.getvalue().splitlines())} lines")

rnstatus.RNS.Discovery.InterfaceDiscovery = FakeDiscovery
for case, opts in DISCOVERY_CASES.items():
    opts = dict(opts)
    FakeDiscovery.records = opts.pop("interfaces", DISCOVERED)
    kwargs = {"discovered_interfaces": True, "config_entries": False, "json": False,
              "name_filter": None, "show_stale": False, "show_unknown": False}
    kwargs.update(opts)
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        rnstatus.program_setup(configdir=None, remote=None, must_exit=False,
                               rns_instance=FakeReticulum(None, None, None, None), **kwargs)
    inputs = {"discovered": FakeDiscovery.records, "options": kwargs, "now": NOW}
    (OUT / f"{case}.pickle").write_bytes(pickle.dumps(inputs, protocol=2))
    (OUT / f"{case}.txt").write_text(buffer.getvalue())
    print(f"{case}: {len(buffer.getvalue().splitlines())} lines")
