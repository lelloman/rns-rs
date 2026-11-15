#!/usr/bin/env python3
"""Record upstream rnid's behaviour for rns-cli's rnid tests.

PYTHONPATH=/path/to/Reticulum python3 tests/generate_rnid_fixtures.py

Runs sequences of rnid command lines, each in a fresh directory holding the
same files, and writes tests/fixtures/rnid/cases.json: the files, and for
every step its exit code and stdout, plus the files left at the end (their
SHA-256; encrypted files, which are random, by size). Paths under the
directory read as ROOT; RNS.log lines (timestamped) are left out.
"""
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import RNS

assert RNS.__version__ == "1.6.0", RNS.__version__

ROOT = Path(__file__).resolve().parent.parent
A = RNS.Identity.from_bytes(bytes(range(64)))
B = RNS.Identity.from_bytes(bytes(range(64, 128)))
PUB, PRV, H = A.get_public_key(), A.get_private_key(), A.hash.hex()

FILES = {
    "id.rid": PRV,
    "other.rid": B.get_private_key(),
    "id.pub": PUB,
    "msg.txt": b"hello world\n",
    "msg2.txt": b"second\n",
    "body.txt": b"signed body text\n",
    "empty": b"",
    "latin1.txt": "caf\u00e9\n".encode("latin-1"),
    "meta.cfg": b"name = demo\nversion = 1.0\n[sub]\nkey = value\n",
    "typed.cfg": b"name = demo # a comment\nversion = 1.5\ntags = a, b, 'c, d'\n[sub]\nkey = value\n[[deep]]\nn = 7\n",
    "typed.cfg.spec": b"name = string\nversion = float\ncount = integer(default=3)\nflag = boolean(default=yes)\n[sub]\nkey = string\n[[deep]]\nn = integer\n",
    "bad.cfg": b"version = soon\n",
    "bad.cfg.spec": b"version = float\n",
    "broken.cfg": b"name = demo\nnonsense\n",
    "dup.cfg": b"a = 1\na = 2\n",
    "cfg/config": b"[reticulum]\n  share_instance = No\n  instance_name = rnid_fixture\n[logging]\n  loglevel = 2\n[interfaces]\n",
}

SEQS = [
    [[]], [["-p"]], [["-i", "id.rid", "-p"]], [["-i", "id.rid", "-p", "-P"]],
    [["-i", "id.rid", "-p", "-P", "-b"]], [["-i", "id.rid", "-p", "-P", "-B"]],
    [["-i", "id.rid", "-p", "-P", "-F"]], [["-i", "id.rid", "-p", "-U"]],
    [["-i", "id.rid", "-x"]], [["-i", "id.rid", "-X"]], [["-i", "id.rid", "-x", "-b"]],
    [["-i", "id.rid", "-X", "-B"]], [["-i", "id.rid", "-x", "-X", "-p"]],
    [["-i", "id.rid", "-H", "app.aspect"]], [["-i", "id.rid", "-H", "app"]],
    [["-i", "id.rid", "-H", "a.b.c"]], [["-i", "id.rid", "-H", ""]],
    [["-i", "nonexist.rid", "-p"]], [["-i", "msg.txt", "-p"]], [["-i", "id.pub", "-p"]],
    [["-i", "~/does-not-exist", "-p"]], [["-i", "~/id.rid", "-p"]], [["-i", "empty", "-x"]],
    [["-g", "id.rid"]],
    [["-m", PUB.hex(), "-p"]], [["-m", base64.b32encode(PUB).decode(), "-p"]],
    [["-m", base64.urlsafe_b64encode(PUB).decode(), "-p"]], [["-m", "garbage", "-p"]],
    [["-m", "id.pub", "-p"]], [["-m", PUB.hex(), "-p", "-P"]], [["-m", PUB.hex(), "-X"]],
    [["-m", base64.b32encode(PUB).decode().lower(), "-p"]],
    [["-M", PRV.hex(), "-p", "-P"]], [["-M", base64.b32encode(PRV).decode(), "-x"]],
    [["-M", base64.urlsafe_b64encode(PRV).decode(), "-X", "-b"]], [["-M", "zz", "-p"]],
    [["-M", "id.rid", "-p"]], [["-M", PRV.hex()[:-2] + "zz", "-p"]],
    [["-i", "id.rid", "-w", "out"], ["-i", "id.rid", "-w", "out"], ["-i", "out.pub", "-p"]],
    [["-i", "id.rid", "-X", "-w", "out.rid"], ["-i", "id.rid", "-X", "-w", "out.rid"],
     ["-i", "id.rid", "-X", "-w", "out.rid", "-f"]],
    [["-m", PUB.hex(), "-w", "imp"], ["-m", PUB.hex(), "-w", "imp.PUB"]],
    [["-M", PRV.hex(), "-X", "-w", "imp.rid"], ["-i", "imp.rid", "-p"]],
    [["-i", "id.rid", "-w", "nodir/x"]],
    [["-i", "id.rid", "-s", "msg.txt"], ["-i", "id.rid", "-s", "msg.txt"],
     ["-i", "id.rid", "-s", "msg.txt", "-f"], ["-i", "id.rid", "-V", "msg.txt"],
     ["-i", "id.rid", "-V", "msg.txt.rsg"], ["-V", "msg.txt"], ["-i", "other.rid", "-V", "msg.txt"],
     ["-i", B.hash.hex(), "-V", "msg.txt"], ["-i", H, "-V", "msg.txt"], ["-i", "abc", "-V", "msg.txt"],
     ["-i", "zz" * 16, "-V", "msg.txt"], ["-i", "id.rid", "-V", "MSG.TXT.RSG"]],
    [["-i", "id.rid", "-s", "msg.txt", "-b"]], [["-i", "id.rid", "-s", "msg.txt", "-B"]],
    [["-i", "id.rid", "-s", "msg.txt", "-F"]], [["-i", "id.rid", "-s", "msg.txt", "-U"]],
    [["-i", "id.rid", "-s", "missing"]],
    [["-i", "id.rid", "-s", "msg.txt", "msg2.txt"], ["-i", "id.rid", "-V", "msg.txt", "msg2.txt"]],
    [["-i", "id.rid", "-s", "msg.txt", "missing", "msg2.txt"]],
    [["-i", "id.rid", "-s"]], [["-i", "id.rid", "-e"]],
    [["-i", "id.pub", "-s", "msg.txt"]], [["-m", PUB.hex(), "-s", "msg.txt"]],
    [["-i", "id.rid", "-s", "msg.txt", "--raw"], ["-i", "id.rid", "-V", "msg.txt"], ["-V", "msg.txt"],
     ["-i", "other.rid", "-V", "msg.txt"]],
    [["-i", "id.rid", "-V", "missing"]], [["-i", "id.rid", "-V", "msg.txt"]],
    [["-i", "id.rid", "-s", "msg.txt"], ["-i", "id.rid", "-V", "msg2.txt.rsg"]],
    [["-i", "id.rid", "-s", "empty"], ["-V", "empty"]],
    [["-i", "id.rid", "-S", "hello there", "-w", "m"], ["-i", "id.rid", "-S", "hello there", "-w", "m"],
     ["-i", "id.rid", "-V", "m.rsm"], ["-V", "m.rsm"], ["-i", "id.rid", "-V", "m.rsm", "--meta"],
     ["-i", "other.rid", "-V", "m.rsm"], ["-i", "id.rid", "-V", "M.RSM"], ["-V", "m.rsm.rsg"],
     ["-i", B.hash.hex(), "-V", "m.rsm"]],
    [["-i", "id.rid", "-S", "hello"]], [["-i", "id.rid", "-S", "hello", "-b"]],
    [["-i", "id.rid", "-S", "hello", "-F"]], [["-i", "id.rid", "-S", "hello", "-U"]],
    [["-i", "id.rid", "-S", "hello", "-w", "x.RSM"]],
    [["-i", "id.rid", "-S", ""]],
    [["-i", "id.rid", "-S", "-r", "body.txt", "-w", "b.rsm"], ["-i", "id.rid", "-V", "b.rsm"]],
    [["-i", "id.rid", "-S", "x", "-r", "body.txt", "-w", "b"]], [["-i", "id.rid", "-S", "-r", "nope", "-w", "b"]],
    [["-i", "id.rid", "-S", "meta msg", "-E", "meta.cfg", "-w", "e.rsm"], ["-i", "id.rid", "-V", "e.rsm", "--meta"]],
    [["-i", "id.rid", "-S", "typed", "-E", "typed.cfg", "-w", "t.rsm"], ["-V", "t.rsm", "--meta"]],
    [["-i", "id.rid", "-S", "typed", "-E", "typed.cfg", "--meta-spec", "nope", "-w", "t2"], ["-V", "t2.rsm", "--meta"]],
    [["-i", "id.rid", "-S", "bad", "-E", "bad.cfg", "-w", "bad"]],
    [["-i", "id.rid", "-S", "bad", "-E", "broken.cfg", "-w", "bad"]],
    [["-i", "id.rid", "-S", "bad", "-E", "dup.cfg", "-w", "bad"]],
    [["-i", "id.rid", "-S", "x", "-E", "nometa", "-w", "e"]],
    [["-i", "id.pub", "-S", "hello", "-w", "x"]],
    [["-i", "id.rid", "-e", "msg.txt"], ["-i", "id.rid", "-e", "msg.txt"], ["-i", "id.rid", "-d", "msg.txt.rfe"],
     ["-i", "id.rid", "-d", "msg.txt.rfe", "-w", "plain.txt"], ["-i", "other.rid", "-d", "msg.txt.rfe", "-w", "p2"],
     ["-i", "id.pub", "-d", "msg.txt.rfe", "-w", "p3"], ["-i", "id.rid", "-d", "msg.txt"],
     ["-i", "id.rid", "-d", "missing.rfe"], ["-i", "id.rid", "-d", ".rfe"]],
    [["-i", "id.pub", "-e", "msg.txt", "-w", "enc.rfe"], ["-i", "id.rid", "-d", "enc.rfe", "-w", "dec"]],
    [["-m", PUB.hex(), "-e", "msg.txt", "-w", "enc.rfe"], ["-i", "id.rid", "-d", "enc.rfe", "-w", "dec"],
     ["-m", PUB.hex(), "-d", "enc.rfe", "-w", "dec2"]],
    [["-i", "id.rid", "-e", "empty"], ["-i", "id.rid", "-d", "empty.rfe", "-w", "out"]],
    [["-i", "id.rid", "-e", "missing"]], [["-i", "id.rid", "-e", "msg.txt", "msg2.txt"]],
    [["-i", "id.rid", "-e", "msg.txt", "msg2.txt", "-w", "one.rfe"]],
    [["-i", "id.rid", "-e", "msg.txt", "-w", "nodir/x.rfe"]],
    [["-i", "id.rid", "-e", "msg.txt", "-s", "msg.txt"]], [["-i", "id.rid", "-g", "x"]], [["-b", "-B"]],
    [["-F", "-U", "-p"]],
    [["--config", "cfg", "-i", "id.rid", "-a", "x"]], [["--config", "cfg", "-i", "id.rid", "-a", "app.x"]],
    [["--config", "cfg", "-i", "id.rid", "-a"]], [["--config", "cfg", "-m", PUB.hex(), "-a"]],
    [["--config", "cfg", "-i", H, "-p"]], [["--config", "cfg", "-i", H, "-H", "app.x"]],
    [["--config", "cfg", "-i", "zz" * 16, "-p"]], [["--config", "cfg", "-N", "-i", H, "-p"]],
    [["--config", "cfg", "-N", "-i", H, "-H", "app.x"]], [["-i", "abc", "-H", "app.x"]], [["-H", "app.x"]],
    [["-x"]], [["-e", "msg.txt"]], [["-d", "msg.txt.rfe"]],
]

LOGLINE = re.compile(r"^\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\] .*\n?", re.M)


def snapshot(root):
    out = {}
    for d, _, files in os.walk(root):
        rel_dir = os.path.relpath(d, root)
        if rel_dir.split(os.sep)[0] in ("cfg", ".reticulum"):
            continue
        for f in files:
            p = os.path.join(d, f)
            rel = os.path.relpath(p, root)
            data = Path(p).read_bytes()
            out[rel] = f"size:{len(data)}" if rel.endswith(".rfe") else hashlib.sha256(data).hexdigest()
    return dict(sorted(out.items()))


def main():
    cases = []
    runner = "import sys,runpy; sys.argv[0]='rnid'; runpy.run_module('RNS.Utilities.rnid', run_name='__main__')"
    for seq in SEQS:
        with tempfile.TemporaryDirectory() as root:
            for rel, data in FILES.items():
                os.makedirs(os.path.dirname(os.path.join(root, rel)) or root, exist_ok=True)
                Path(root, rel).write_bytes(data)
            steps = []
            for argv in seq:
                env = dict(os.environ, HOME=root, COLUMNS="80")
                p = subprocess.run([sys.executable, "-c", runner] + argv, cwd=root, env=env,
                                   capture_output=True, timeout=120)
                stdout = LOGLINE.sub("", p.stdout.decode().replace(root, "ROOT"))
                assert not p.stderr, (argv, p.stderr)
                steps.append({"argv": argv, "code": p.returncode, "stdout": stdout})
            cases.append({"steps": steps, "files": snapshot(root)})
    fixture = {"files": {k: v.hex() for k, v in FILES.items()}, "cases": cases}
    out = ROOT / "tests/fixtures/rnid/cases.json"
    out.write_text(json.dumps(fixture, indent=1, ensure_ascii=False) + "\n")
    print(f"{len(cases)} cases")


main()
