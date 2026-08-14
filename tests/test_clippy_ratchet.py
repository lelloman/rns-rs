from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("clippy_ratchet", ROOT / "scripts" / "clippy-ratchet.py")
ratchet = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(ratchet)


def diagnostic(crate: str, lint: str) -> str:
    return json.dumps({
        "reason": "compiler-message",
        "package_id": f"{crate} 0.1.0 (path+file:///tmp/{crate})",
        "message": {"level": "warning", "code": {"code": lint}, "rendered": "warning"},
    })


class ClippyRatchetTests(unittest.TestCase):
    def test_parses_and_counts_json_diagnostics(self) -> None:
        counts, rendered = ratchet.parse_diagnostics([
            diagnostic("rns-net", "clippy::type_complexity"),
            diagnostic("rns-net", "clippy::type_complexity"),
            "not json",
        ])
        self.assertEqual(counts, {"rns-net": {"clippy::type_complexity": 2}})
        self.assertEqual(rendered, ["warning", "warning"])

    def test_same_passes_new_or_increased_fails_and_decrease_passes(self) -> None:
        baseline = {"rns-net": {"clippy::type_complexity": 2}}
        self.assertEqual(ratchet.regressions(baseline, baseline), [])
        self.assertTrue(ratchet.regressions(baseline, {"rns-net": {"clippy::type_complexity": 3}}))
        self.assertTrue(ratchet.regressions(baseline, {"rns-core": {"clippy::new": 1}}))
        self.assertEqual(ratchet.regressions(baseline, {"rns-net": {"clippy::type_complexity": 1}}), [])

    def test_baseline_output_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "baseline.json"
            ratchet.write_baseline(path, {"z": {"b": 1}, "a": {"c": 2}})
            self.assertEqual(path.read_text(), '{\n  "a": {\n    "c": 2\n  },\n  "z": {\n    "b": 1\n  }\n}\n')
