"""Bounds checks for the synthetic Wine text oracle; Wine is not Windows."""
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def request(mode, length, size, data):
    return struct.pack('<BIiiBI', mode, 0, length, size, 0, len(data)) + data


@unittest.skipUnless(shutil.which('wine') and shutil.which('bwrap'), 'Wine and bubblewrap required')
class WineProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix='wins-wine-probe-'))
        cls.probe = cls.work / 'probe.exe'
        subprocess.run(['zig', 'build-exe', str(ROOT/'native/testdata/wine_text_probe.zig'),
                        '-target', 'x86_64-windows-gnu', '-O', 'ReleaseSmall',
                        '-fentry=wWinMainCRTStartup', '--subsystem', 'console',
                        f'-femit-bin={cls.probe}'], check=True, cwd='/tmp', capture_output=True)

    def probe_request(self, payload):
        return subprocess.run(['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--ro-bind', '/etc', '/etc',
            '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev',
            '--tmpfs', '/tmp', '--bind', str(self.work), '/work',
            '--setenv', 'HOME', '/tmp', '--setenv', 'WINEPREFIX', '/work/prefix',
            '--setenv', 'WINEDEBUG', '-all', '--', '/usr/bin/wine', '/work/probe.exe'],
            input=payload, capture_output=True, timeout=300)

    def test_valid_conversion(self):
        r = self.probe_request(request(0, 3, 8, b'abc'))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, struct.pack('<iII', 3, 0, 6) + 'abc'.encode('utf-16le'))

    def test_size_query_has_no_destination_output(self):
        r = self.probe_request(request(0, 3, 0, b'abc'))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, struct.pack('<iII', 3, 0, 0))

    def test_rejects_requests_outside_backing_buffers(self):
        cases = [request(0, 100, 8, b'a'), request(1, 2, 8, b'a\0'),
                 request(0, -1, 8, b'abc'), request(1, -1, 8, b'a\0'),
                 request(0, 1, (1 << 19) + 1, b'a'),
                 request(1, 1, (1 << 20) + 1, b'a\0')]
        for payload in cases:
            r = self.probe_request(payload)
            with self.subTest(payload=payload):
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertEqual(r.stdout, b'')


if __name__ == '__main__':
    unittest.main()
