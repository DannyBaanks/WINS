"""Exercise the native X11 primitive against an isolated, networkless Xvfb."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import random

ROOT = Path(__file__).resolve().parents[1]
BOX = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
       '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
       '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
       '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp']


class X11WindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ('zig', 'bwrap', 'Xvfb'):
            if not shutil.which(tool):
                raise unittest.SkipTest(f'{tool} is not installed')
        cls.directory = Path(tempfile.mkdtemp(prefix='wins-x11-'))
        cls.probe = cls.directory / 'probe'
        subprocess.run(['zig', 'build-exe', '-O', 'ReleaseSafe', '--dep', 'x11',
                        f'-Mroot={ROOT / "native/testdata/x11_window_probe.zig"}',
                        f'-Mx11={ROOT / "native/x11_window.zig"}', '-lc', '-lX11',
                        f'-femit-bin={cls.probe}'], check=True, capture_output=True, timeout=180)

    def test_window_round_trip_and_zero_size_rejection(self):
        # The X server, socket, and clients are inside this one new namespace.
        script = '''
mkdir -m 1777 /tmp/.X11-unix
Xvfb :91 -screen 0 640x480x24 -nolisten tcp -extension GLX -extension DRI3 > /tmp/xvfb.log 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null; wait "$server" 2>/dev/null' EXIT
i=0
while [ ! -S /tmp/.X11-unix/X91 ]; do
  kill -0 "$server" 2>/dev/null || { cat /tmp/xvfb.log >&2; exit 10; }
  [ "$i" -lt 100 ] || exit 11
  i=$((i + 1))
  sleep 0.05
done
i=0
until /probe :91 320 200 2>/tmp/probe.log; do
  kill -0 "$server" 2>/dev/null || { cat /tmp/xvfb.log >&2; exit 12; }
  [ "$i" -lt 100 ] || { cat /tmp/probe.log >&2; cat /tmp/xvfb.log >&2; exit 12; }
  i=$((i + 1))
  sleep 0.05
done
cat /tmp/probe.log >&2
/probe :91 1 1 || exit 13
if /probe :91 0 100; then exit 14; fi
'''
        # Fixed-seed sizes provide repeatable variation; the X server's
        # geometry reply is the independent oracle for each requested size.
        rng = random.Random(0x583131)
        for _ in range(32):
            script += f'/probe :91 {rng.randint(1, 640)} {rng.randint(1, 480)} || exit 15\n'
        result = subprocess.run(BOX + ['--ro-bind', str(self.probe), '/probe', '--',
                                      '/bin/sh', '-c', script], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('X11_WINDOW_OK 320x200', result.stderr)
        self.assertIn('X11_WINDOW_OK 1x1', result.stderr)
        self.assertIn('InvalidSize', result.stderr)
        self.assertEqual(result.stderr.count('X11_WINDOW_OK'), 34)

    def test_unavailable_display_fails(self):
        result = subprocess.run(BOX + ['--ro-bind', str(self.probe), '/probe', '--',
                                      '/probe', ':91', '320', '200'],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('DisplayUnavailable', result.stderr)
        self.assertNotIn('X11_WINDOW_OK', result.stderr)


if __name__ == '__main__':
    unittest.main()
