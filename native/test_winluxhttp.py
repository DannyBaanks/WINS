"""winluxhttp: proxy selection, checked by metamorphic relations (see fuzz_winluxhttp.zig).

There is no real WinHTTP to compare with, so these tests prove only that the
candidate satisfies the relations a correct implementation of the documented
WINHTTP_PROXY_INFO formats must satisfy, and that two broken variants do not.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        t = Path(tempfile.mkdtemp(prefix='wins-http-'))
        cls.runner = t / 'fuzz_http'
        subprocess.run(['zig', 'build-exe', str(ROOT/'native/fuzz_winluxhttp.zig'), '-lc', '-O', 'ReleaseSafe', f'-femit-bin={cls.runner}'], check=True, capture_output=True)
        cls.libs = {}
        for name, src in (('good', 'native/shims/winluxhttp.zig'), ('scheme', 'native/winluxhttp_bad_scheme.zig'), ('case', 'native/winluxhttp_bad_case.zig')):
            lib = t / f'{name}.so'
            subprocess.run(['zig', 'build-lib', str(ROOT/src), '-dynamic', '-lc', '-O', 'ReleaseSafe', f'-femit-bin={lib}'], check=True, capture_output=True)
            cls.libs[name] = lib

    def run_fuzz(self, lib, iterations=20000):
        return subprocess.run(['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
                               '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
                               '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
                               '--ro-bind', str(self.runner), '/runner', '--ro-bind', str(lib), '/candidate.so',
                               '--', '/runner', '/candidate.so', str(iterations)],
                              capture_output=True, text=True, timeout=120)

    def test_candidate_satisfies_every_relation(self):
        r = self.run_fuzz(self.libs['good'])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('MATCHED', r.stderr)

    def test_control_ignoring_scheme_scope_is_detected(self):
        r = self.run_fuzz(self.libs['scheme'])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('relation=R3', r.stderr)

    def test_control_case_sensitive_bypass_is_detected(self):
        r = self.run_fuzz(self.libs['case'])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('relation=R6', r.stderr)


if __name__ == '__main__':
    unittest.main()
