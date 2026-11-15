#!/usr/bin/env python3
"""Write the config file upstream's Reticulum creates when there is none.

PYTHONPATH=/path/to/Reticulum python3 tests/generate_default_config.py

Reticulum.__create_default_config writes __default_rns_config__ through
ConfigObj, which reformats it; rns-net embeds the result byte for byte.
"""
import os
import tempfile
from pathlib import Path

import RNS
from RNS.vendor.configobj import ConfigObj
import sys
module = sys.modules["RNS.Reticulum"]

assert RNS.__version__ == "1.6.0", RNS.__version__

ROOT = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory() as tmp:
    path = os.path.join(tmp, "config")
    config = ConfigObj(module.__default_rns_config__)
    config.filename = path
    config.write()
    data = Path(path).read_bytes()
(ROOT / "rns-net/src/common/default_config").write_bytes(data)
print(f"{len(data)} bytes")
