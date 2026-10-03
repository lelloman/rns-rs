#!/usr/bin/env python3
"""Generate local-ratchet fixtures from the accepted reference checkout.

PYTHONPATH=/path/to/Reticulum python3 tests/generate_local_ratchet_vectors.py
Ciphertexts use fresh reference randomness; the keys are public test material.
"""
import json
from pathlib import Path
import subprocess

import RNS

BASELINE = "49ae71e06cadf5d846849661578a8ad9fcede443"
reference = Path(RNS.__file__).resolve().parent.parent
commit = subprocess.check_output(
    ["git", "-C", str(reference), "rev-parse", "HEAD"], text=True
).strip()
assert commit == BASELINE and RNS.__version__ == "1.5.6", "wrong reference checkout"
private = bytes([33]) * 64
identity = RNS.Identity(create_keys=False)
identity.load_private_key(private)
keys = [bytes([82]) * 32, bytes([81]) * 32]
cases = []
for name, key, plaintext in [
    ("current-empty", keys[0], b""),
    ("retained", keys[1], b"delayed message"),
    ("retired", bytes([80]) * 32, b"retired message"),
    ("identity", None, b"legacy message"),
]:
    public = RNS.Identity._ratchet_public_bytes(key) if key is not None else None
    ciphertext = identity.encrypt(plaintext, ratchet=public)
    cases.append({
        "name": name,
        "ciphertext": ciphertext.hex(),
        "plaintext": plaintext.hex(),
        "ratchet_id": RNS.Identity._get_ratchet_id(public).hex() if public else None,
        "enforced_accept": key in keys if key is not None else False,
        "fallback_accept": key in keys if key is not None else True,
    })
output = {"reference_commit": commit, "reference_version": RNS.__version__,
          "identity_private": private.hex(), "keys_newest_first": [k.hex() for k in keys],
          "cases": cases}
path = Path(__file__).parent / "fixtures/crypto/local_ratchet_1_5_6.json"
path.write_text(json.dumps(output, indent=2) + "\n")
print(path)
