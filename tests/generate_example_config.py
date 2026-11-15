#!/usr/bin/env python3
"""Write what upstream's `rnsd --exampleconfig` prints, for rns-cli to print.

PYTHONPATH=/path/to/Reticulum python3 tests/generate_example_config.py
"""
import contextlib
import io
import sys
from pathlib import Path

import RNS
from RNS.Utilities import rnsd

assert RNS.__version__ == "1.6.0", RNS.__version__

ROOT = Path(__file__).resolve().parent.parent
out = io.StringIO()
sys.argv = ["rnsd", "--exampleconfig"]
with contextlib.redirect_stdout(out):
    try:
        rnsd.main()
    except SystemExit:
        pass
(ROOT / "rns-cli/src/example_config").write_text(out.getvalue())
print(f"{len(out.getvalue())} characters")
