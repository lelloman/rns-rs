"""Reject incomplete or mismatched native-profiler workloads."""
import json
from pathlib import Path
import runpy
import tempfile
import unittest

API = runpy.run_path(str(Path(__file__).resolve().parents[3] / 'scripts/bench-native-allocations'))


class NativeCompletionTests(unittest.TestCase):
    def test_completion_requires_exact_verified_work(self):
        good = dict(schema_version=1, workload_version=1, status='valid', family='seeded',
                    compression=True, sdu=16348, payload_bytes=1048576, verified_cycles=3,
                    warmup_cycles=0, compression_used_cycles=3)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.stderr'
            def validate(record):
                path.write_text(API['PREFIX'] + json.dumps(record) + '\n')
                return API['completion'](path, 'seeded', True, 3)
            self.assertEqual(validate(good), good)
            for key, value in [('verified_cycles', 2), ('verified_cycles', True),
                               ('compression_used_cycles', 4), ('compression_used_cycles', -1),
                               ('compression', 1), ('payload_bytes', 0), ('status', 'failed')]:
                with self.assertRaises(ValueError):
                    validate(dict(good, **{key: value}))
            for text in ['', (API['PREFIX'] + json.dumps(good) + '\n') * 2]:
                path.write_text(text)
                with self.assertRaises(ValueError):
                    API['completion'](path, 'seeded', True, 3)


if __name__ == '__main__':
    unittest.main()
