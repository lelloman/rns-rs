#!/usr/bin/env python3
"""Generate discovered-interface records as upstream persists them.

PYTHONPATH=/path/to/Reticulum python3 tests/generate_discovery_record_fixtures.py

Builds the `info` dicts the way RNS 1.6.0's InterfaceAnnounceHandler and
InterfaceDiscovery.interface_discovered do (same keys, same order, ids as
hex strings) and packs them with upstream's umsgpack, as the files under
storage/discovery/interfaces are written. rns-net's discovery tests read
these and must serialize the same interfaces to identical bytes.
"""
from pathlib import Path

import RNS
from RNS.vendor import umsgpack as msgpack

assert RNS.__version__ == "1.6.0", RNS.__version__
OUT = Path(__file__).resolve().parent / "fixtures/discovery"
OUT.mkdir(parents=True, exist_ok=True)


def info(type_, name, transport_id, typed, impl=("RNS", "1.6.0"), dst_cost=None, pr_cost=None,
         lat=None, lon=None, height=None, netname=None, lxmf=None):
    i = {"type": type_, "impl_name": impl[0], "version": impl[1], "transport": True,
         "name": name, "received": 1700001000.5, "stamp": bytes([0x42] * 64), "value": 18.0,
         "transport_id": transport_id.hex(), "network_id": bytes([0x02] * 16).hex(),
         "dst_cost": dst_cost, "pr_cost": pr_cost, "hops": 2,
         "latitude": lat, "longitude": lon, "height": height}
    if netname:
        i["ifac_netname"] = netname
    i.update(typed)
    i["config_entry"] = f"[[{name}]]\n  type = {type_}"
    i["discovery_hash"] = RNS.Identity.full_hash((i["transport_id"] + name).encode("utf-8"))
    if lxmf:
        i["operator_lxmf_address"] = lxmf.hex()
    i["discovered"] = 1700000000.0
    i["last_heard"] = i["received"]
    i["heard_count"] = 5
    return i


records = {
    "upstream_backbone_record": info(
        "BackboneInterface", "Backbone North", bytes([0x01] * 16),
        {"reachable_on": "example.com", "port": 4242}, dst_cost=12.5, pr_cost=0.0,
        lat=45.0, lon=9.0, height=100.0, netname="mynetwork", lxmf=bytes([0xA5] * 16)),
    "upstream_rnode_record": info(
        "RNodeInterface", "LoRa South", bytes([0x03] * 16),
        {"frequency": 868000000, "bandwidth": 125000, "sf": 8, "cr": 5}, impl=(None, None)),
}
for name, record in records.items():
    (OUT / f"{name}.msgpack").write_bytes(msgpack.packb(record))
    print(name, len(msgpack.packb(record)), "bytes")
