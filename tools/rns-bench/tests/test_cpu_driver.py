"""CPU orchestration tests that do not require perf privileges."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

API = runpy.run_path(str(Path(__file__).resolve().parents[3] / 'scripts/bench-cpu'))


class CpuDriverTests(unittest.TestCase):
    def test_outer_sudo_is_rejected_before_artifacts_or_builds(self):
        with mock.patch.object(API['os'], 'geteuid', return_value=0):
            with self.assertRaisesRegex(ValueError, 'without outer sudo'):
                API['require_user']()

    def test_cargo_discovery_handles_restricted_path(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            cargo = home / '.cargo/bin/cargo'
            cargo.parent.mkdir(parents=True)
            cargo.write_text('#!/bin/sh\nexit 0\n')
            cargo.chmod(0o755)
            with mock.patch.object(API['shutil'], 'which', return_value=None), \
                    mock.patch.object(API['pwd'], 'getpwuid', return_value=SimpleNamespace(pw_dir=str(home))), \
                    mock.patch.dict(os.environ, {'PATH': '/usr/bin'}, clear=True):
                self.assertEqual(API['discover_cargo'](), str(cargo))
                self.assertTrue(os.environ['PATH'].startswith(str(cargo.parent) + os.pathsep))

    def test_commands_keep_terminal_session_but_own_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(API['execute']([sys.executable, '-c',
                'import os; print(os.getpid(),os.getpgrp(),os.getsid(0))'], root, 'session', 5), 0)
            pid, group, session = map(int, (root / 'session.stdout').read_text().split())
            self.assertEqual(pid, group)
            self.assertEqual(session, os.getsid(0))

    def result(self):
        return dict(schema_version=1, workload_version=1, status='valid', family='seeded',
                    compression=True, sdu=16348, requested_seconds=1, payload_bytes=1048576,
                    verified_cycles=5, compression_used_cycles=5, warmup_cycles=1, elapsed_seconds=1.1)

    def test_validated_completion_rejects_missing_duplicate_and_wrong_work(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stderr'
            good = API['PREFIX'] + json.dumps(self.result()) + '\n'
            path.write_text('perf diagnostic\n' + good)
            self.assertEqual(API['completion'](path, 'seeded', True, 16348, 1)['verified_cycles'], 5)
            for text in ['', good + good, API['PREFIX'] + '{}\n']:
                path.write_text(text)
                with self.assertRaises(ValueError):
                    API['completion'](path, 'seeded', True, 16348, 1)
            for field, value in [('family', 'repeated'), ('verified_cycles', 0), ('verified_cycles', True),
                                 ('elapsed_seconds', float('nan')), ('elapsed_seconds', 0.5),
                                 ('compression_used_cycles', 6), ('status', 'failed')]:
                result = self.result()
                result[field] = value
                path.write_text(API['PREFIX'] + json.dumps(result) + '\n')
                with self.assertRaises(ValueError):
                    API['completion'](path, 'seeded', True, 16348, 1)

    def test_postprocessing_preserves_pipe_capture_and_separates_stats(self):
        with tempfile.TemporaryDirectory() as directory:
            cell = Path(directory)
            raw = b'PERFILE2 retained pipe stream'
            (cell / 'capture.stdout').write_bytes(raw)
            (cell / 'perf.data').write_bytes(b'broken conversion')
            (cell / 'capture.stderr').write_text(API['PREFIX'] + json.dumps(self.result()))
            commands = []

            def execute(command, directory, name, timeout):
                commands.append((name, command))
                output = '# Samples: 1\n# Overhead  Symbol\n100% function\n'
                if name == 'events':
                    output = 'TOTAL 1\n'
                if name == 'stacks':
                    output = 'profiler 1 0: cpu-clock:u:\n\t123 function\n\n'
                (directory / (name + '.stdout')).write_text(output)
                return 0

            with mock.patch.dict(API['postprocess'].__globals__, {'execute': execute}):
                result = API['postprocess'](cell, 'seeded', True, 16348, 1)
            self.assertEqual(result['trace_blocks'], 1)
            self.assertEqual((cell / 'capture.stdout').read_bytes(), raw)
            self.assertEqual((cell / 'perf.data').read_bytes(), raw)
            archived = list(cell.glob('perf.data.before-repair-*'))
            self.assertEqual(len(archived), 1)
            self.assertEqual(archived[0].read_bytes(), b'broken conversion')
            self.assertFalse(any('inject' in command for _, command in commands))
            self.assertEqual([name for name, command in commands if '--stats' in command], ['events'])

            def stats_only(command, directory, name, timeout):
                (directory / (name + '.stdout')).write_text('TOTAL 1\n')
                return 0

            with mock.patch.dict(API['postprocess'].__globals__, {'execute': stats_only}):
                with self.assertRaisesRegex(RuntimeError, 'missing CPU symbol report'):
                    API['postprocess'](cell, 'seeded', True, 16348, 1)
            (cell / 'capture-status.json').write_text('{"exit_code": 1}')
            with self.assertRaisesRegex(ValueError, 'recording did not complete'):
                API['postprocess'](cell, 'seeded', True, 16348, 1)

    def test_retained_matrix_validation(self):
        manifest = dict(schema_version=1, cpu_profile_version=1, family='all',
                        compression='both', sdu=16348, seconds_per_cell=3)
        self.assertEqual(len(API['matrix'](manifest)), 6)
        for key, value in [('family', 'unknown'), ('seconds_per_cell', 0),
                           ('seconds_per_cell', True), ('sdu', 1)]:
            with self.assertRaises(ValueError):
                API['matrix'](dict(manifest, **{key: value}))

    def test_failed_command_retains_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = API['execute']([sys.executable, '-c', 'import sys; print("failure",file=sys.stderr); sys.exit(7)'], root, 'failure', 5)
            self.assertEqual(code, 7)
            self.assertIn('failure', (root / 'failure.stderr').read_text())

    def test_timeout_reaps_owned_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(subprocess.TimeoutExpired):
                API['execute']([sys.executable, '-c', 'import os,time; print(os.getpid(),flush=True); time.sleep(30)'], root, 'timeout', 0.2)
            pid = int((root / 'timeout.stdout').read_text())
            self.assertFalse(Path('/proc') .joinpath(str(pid)).exists())


if __name__ == '__main__':
    unittest.main()
