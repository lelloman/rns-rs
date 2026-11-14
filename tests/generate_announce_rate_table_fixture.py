#!/usr/bin/env python3
"""Generate the persisted announce rate table fixture from upstream d5f1e014.

PYTHONPATH=/path/to/Reticulum python3 tests/generate_announce_rate_table_fixture.py
The checkout must be at the commit that introduced the file format. Entry A
wraps its 16-slot timestamp ring and is blocked; entry B has two timestamps.
"""
from pathlib import Path
import subprocess

import RNS
from RNS.Storage import AnnounceRateTable

REFERENCE = "d5f1e014dbec2921d70b8acd15c820601de6525d"
reference = Path(RNS.__file__).resolve().parent.parent
commit = subprocess.check_output(
    ["git", "-C", str(reference), "rev-parse", "HEAD"], text=True
).strip()
assert commit == REFERENCE, "wrong reference checkout"

table = AnnounceRateTable(max_timestamps=16)
a = bytes([0xA1]) * 16
b = bytes([0xB2]) * 16
for i in range(18):
    table.check_and_update(a, 1000.0 + i, 10, 3, 30)
table.check_and_update(b, 2000.0, 10, 3, 30)
table.check_and_update(b, 2015.5, 10, 3, 30)

out = Path(__file__).resolve().parent / "fixtures/transport/announce_rate_table_d5f1e014.bin"
assert table.persist(str(out))
print(f"wrote {out} ({out.stat().st_size} bytes)")
