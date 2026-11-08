"""winrun (step 1): a Linux-native loader for minimal x86-64 Windows console PEs.

Everything that executes PE code runs inside bubblewrap. What is demonstrated:
  * differential fuzz: the probe PE run by winrun == the same probe built for Linux
    (stdout, stderr, termination) on random stdin;
  * three loader defects (no relocations, exit code off by one, short write count)
    are each caught by that fuzzer;
  * the loader fails closed BEFORE executing anything on: a wrong SHA-256,
    unimplemented imports (listed), and out-of-scope images (GUI subsystem, DLL,
    writable+executable section, TLS, stripped relocations, non-x86-64).
NOT demonstrated: any PE other than these synthetic fixtures; equivalence with
real Windows (the Linux reference layer models documented kernel32 behaviour).
"""
from pathlib import Path
import hashlib
import struct
import sys
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WIN = ['-target', 'x86_64-windows-gnu', '-O', 'ReleaseSmall', '-fentry=wWinMainCRTStartup', '--subsystem', 'console']
BOX = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
       '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
       '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp']


def zig(*args):
    subprocess.run(['zig', 'build-exe', *args], check=True, capture_output=True, cwd=tempfile.gettempdir())


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


class WinrunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        t = cls.dir = Path(tempfile.mkdtemp(prefix='wins-winrun-'))
        zig(str(ROOT/'native/testdata/winrun_probe.zig'), *WIN, f'-femit-bin={t/"probe.exe"}')
        zig(str(ROOT/'native/testdata/winrun_probe.zig'), '-target', 'x86_64-linux', '-O', 'ReleaseSmall', f'-femit-bin={t/"probe-linux"}')
        zig(str(ROOT/'native/testdata/winrun_unresolved.zig'), *WIN, '-luser32', f'-femit-bin={t/"unresolved.exe"}')
        zig(str(ROOT/'native/fuzz_winrun.zig'), '-O', 'ReleaseSafe', f'-femit-bin={t/"fuzz"}')
        cls.loaders = {}
        for name in ('winrun', 'winrun_bad_norelocs', 'winrun_bad_exitcode', 'winrun_bad_writecount'):
            zig(str(ROOT/f'native/{name}.zig'), '-O', 'ReleaseSafe', f'-femit-bin={t/name}')
            cls.loaders[name] = t/name

    def fuzz(self, loader, iterations):
        t = self.dir
        return subprocess.run(BOX + ['--ro-bind', str(t/'fuzz'), '/runner', '--ro-bind', str(self.loaders[loader]), '/winrun',
                                     '--ro-bind', str(t/'probe.exe'), '/probe.exe', '--ro-bind', str(t/'probe-linux'), '/probe-linux',
                                     '--', '/runner', '/winrun', '/probe.exe', sha(t/'probe.exe'), '/probe-linux', str(iterations)],
                              capture_output=True, text=True, timeout=600)

    def winrun(self, image, digest=None, extra=(), stdin=b''):
        return subprocess.run([sys.executable, str(ROOT/'native/winrun_box.py'), '--loader', str(self.loaders['winrun']),
                               '--sha256', digest or sha(image), *extra, str(image)],
                              input=stdin, capture_output=True, timeout=60)

    # --- differential fuzz -------------------------------------------------
    def test_probe_matches_native_build(self):
        r = self.fuzz('winrun', 2000)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('MATCHED iterations=2000', r.stderr)

    def test_control_without_relocations_is_detected(self):
        r = self.fuzz('winrun_bad_norelocs', 200)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('DIVERGENCE', r.stderr)

    def test_control_exit_code_off_by_one_is_detected(self):
        r = self.fuzz('winrun_bad_exitcode', 200)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('DIVERGENCE', r.stderr)

    def test_control_short_write_count_is_detected(self):
        r = self.fuzz('winrun_bad_writecount', 200)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('DIVERGENCE', r.stderr)

    # --- fail closed -------------------------------------------------------
    def test_check_mode_resolves_without_executing(self):
        r = self.winrun(self.dir/'probe.exe', extra=['--check'], stdin=b'abc')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, b'')
        self.assertIn(b'READY', r.stderr)
        self.assertIn(b'imports=6', r.stderr)
        self.assertNotIn(b'relocs=0 ', r.stderr)

    def test_box_wrapper_fails_closed_without_bubblewrap(self):
        r = subprocess.run([sys.executable, str(ROOT/'native/winrun_box.py'),
                            '--loader', str(self.loaders['winrun']), '--sha256', sha(self.dir/'probe.exe'),
                            str(self.dir/'probe.exe')], env={'PATH': '/nonexistent'},
                           capture_output=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, b'')
        self.assertIn(b'cannot start bubblewrap', r.stderr)

    def test_box_wrapper_executes_probe(self):
        data = b'hello from the boxed runner\n'
        got = self.winrun(self.dir/'probe.exe', stdin=data)
        reference = subprocess.run(BOX + ['--ro-bind', str(self.dir/'probe-linux'), '/probe-linux',
                                          '--', '/probe-linux'], input=data, capture_output=True, timeout=60)
        self.assertEqual((got.returncode, got.stdout, got.stderr),
                         (reference.returncode, reference.stdout, reference.stderr))

    def test_wrong_hash_is_refused(self):
        r = self.winrun(self.dir/'probe.exe', digest='0' * 64, stdin=b'abc')
        self.assertEqual(r.returncode, 3)
        self.assertEqual(r.stdout, b'')
        self.assertIn(b'sha256 mismatch', r.stderr)

    def test_unresolved_imports_are_listed_and_nothing_runs(self):
        r = self.winrun(self.dir/'unresolved.exe')
        self.assertEqual(r.returncode, 4, r.stderr)
        self.assertEqual(r.stdout, b'')  # "EXECUTED" would appear if the entry point ran
        self.assertIn(b'GetTickCount', r.stderr)
        self.assertIn(b'MessageBoxA', r.stderr)
        self.assertNotIn(b'WriteFile', r.stderr)  # implemented ones are not reported

    def mutate(self, name, fn):
        b = bytearray((self.dir/'probe.exe').read_bytes())
        pe = struct.unpack_from('<I', b, 0x3c)[0]
        opt = pe + 24
        fn(b, pe, opt, opt + struct.unpack_from('<H', b, pe + 20)[0])
        p = self.dir/f'mut-{name}.exe'
        p.write_bytes(bytes(b))
        return p

    def test_truncated_directories_are_rejected(self):
        for index in (1, 5):
            with self.subTest(directory=index):
                def truncate(b, pe, opt, sec):
                    struct.pack_into('<I', b, opt + 112 + index * 8 + 4, 1)
                r = self.winrun(self.mutate(f'dir-{index}', truncate), extra=['--check'])
                self.assertEqual(r.returncode, 5, r.stderr)
                self.assertNotIn(b'READY', r.stderr)

    def test_overlapping_raw_section_span_is_rejected(self):
        def overlap(b, pe, opt, sec):
            struct.pack_into('<II', b, sec + 16, 0x1100, 0)
        r = self.winrun(self.mutate('overlap', overlap), extra=['--check'])
        self.assertEqual(r.returncode, 5, r.stderr)
        self.assertNotIn(b'READY', r.stderr)

    def test_out_of_scope_images_are_refused_before_execution(self):
        def gui(b, pe, opt, sec): struct.pack_into('<H', b, opt + 68, 2)
        def dll(b, pe, opt, sec): b[pe + 22] |= 0x00; b[pe + 23] |= 0x20
        def wx(b, pe, opt, sec): struct.pack_into('<I', b, sec + 36, struct.unpack_from('<I', b, sec + 36)[0] | 0x80000000)
        def tls(b, pe, opt, sec): struct.pack_into('<II', b, opt + 112 + 9 * 8, 0x2000, 0x28)
        def stripped(b, pe, opt, sec): b[pe + 22] |= 0x01
        def i386(b, pe, opt, sec): struct.pack_into('<H', b, pe + 4, 0x14c)
        cases = {'gui': (gui, b'subsystem 2'), 'dll': (dll, b'DLL'), 'wx': (wx, b'writable and executable'),
                 'tls': (tls, b'TLS'), 'stripped': (stripped, b'relocations stripped'), 'i386': (i386, b'not x86-64')}
        for name, (fn, msg) in cases.items():
            with self.subTest(name):
                r = self.winrun(self.mutate(name, fn), stdin=b'abc')
                self.assertEqual(r.returncode, 3, r.stderr)
                self.assertEqual(r.stdout, b'')
                self.assertIn(msg, r.stderr)


if __name__ == '__main__':
    unittest.main()
