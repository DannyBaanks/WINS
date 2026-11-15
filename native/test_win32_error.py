"""Independent integration oracle for the native Win32 last-error candidate."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class LastErrorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get('WINS_ERROR_RUNNER'):
            cls.runner = Path(os.environ['WINS_ERROR_RUNNER'])
            cls.good = Path(os.environ['WINS_ERROR_GOOD'])
            cls.bad = Path(os.environ['WINS_ERROR_BAD'])
            return
        base = Path(tempfile.mkdtemp(prefix='wins-last-error-'))
        cls.runner, cls.good, cls.bad = base/'runner', base/'good.so', base/'bad.so'
        for command, src, dest, flags in (
            ('build-exe', 'native/fuzz_win32_error.zig', cls.runner, []),
            ('build-lib', 'native/shims/win32_error.zig', cls.good, ['-dynamic']),
            ('build-lib', 'native/testdata/win32_error_bad.zig', cls.bad, ['-dynamic']),
        ):
            subprocess.run(['zig', command, str(ROOT/src), '-lc', '-O', 'ReleaseSafe', *flags, f'-femit-bin={dest}'], check=True)

    def run_sandbox(self, library):
        return subprocess.run(['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
            '--ro-bind', str(self.runner), '/runner', '--ro-bind', str(library), '/candidate.so',
            '--', '/runner', '/candidate.so', '100000'], capture_output=True, text=True, timeout=15)

    def test_documented_thread_local_behavior(self):
        result = self.run_sandbox(self.good)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('thread_isolation=observed', result.stderr)

    def test_control_detects_process_global_state(self):
        result = self.run_sandbox(self.bad)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('DIVERGENCE thread', result.stderr)

if __name__ == '__main__':
    unittest.main()
