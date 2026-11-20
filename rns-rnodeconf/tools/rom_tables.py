"""Write upstream rnodeconf's device tables (`products`, `platforms`,
`mcus`, `models`) as JSON, for tests/vectors/rom_tables.json.

Usage: PYTHONPATH=<upstream Reticulum> python3 tools/rom_tables.py > tests/vectors/rom_tables.json"""
import json
from RNS.Utilities import rnodeconf as r

def table(d):
    return {"%02x" % k: v for k, v in sorted(d.items())}

print(json.dumps({
    "products": table(r.products),
    "platforms": table(r.platforms),
    "mcus": table(r.mcus),
    "models": table(r.models),
}, indent=1))
