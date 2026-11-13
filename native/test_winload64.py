"""winload64: multi-image x64 DLL loader, checked against Wine (the oracle).

Builds the synthetic fixtures (native/testdata/x64dll/*.zig) and the loaders from
source into a temp dir, then:
  * the real loader's results must be byte-identical to the same calls made by a
    Windows host exe under Wine (in bubblewrap, like test_wine_text_probe.py);
  * the deliberately broken loader (winload64_bad_tls_index) must DIFFER;
  * negative controls: hash mismatch (3), unpinned DLL file (3), unimplemented
    import (4, nothing executed), DllMain FALSE (7), no box (2).
Orchestration only; all loading/execution logic under test is Zig.
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / 'native' / 'testdata' / 'x64dll'
A = 'fixture_a.dll'
SEQ = [  # (target, args, ret) - same order as fixture_host.zig
    (f'{A}!fix_version', [], 'str'), (f'{A}!fix_add', [-5, 3], 'i32'),
    (f'{A}!fix_attach_count', [], 'u32'), (f'{A}!fix_tls_callback_count', [], 'u32'),
    (f'{A}!fix_tls_get', [], 'u32'), (f'{A}!fix_tls_bump', [], 'u32'), (f'{A}!fix_tls_get', [], 'u32'),
    ('fixb_add_twice', [40, 1], 'i32'), ('fixb_tls_from_a', [], 'u32'),
    ('fixb_tls_own', [], 'u32'), ('fixb_tls_own_bump', [], 'u32'), (f'{A}!fix_tls_get', [], 'u32'),
    (f'{A}!fix_crt_format', [-7, 42], 'str'),
]


def zig(*args, cwd):
    subprocess.run(['zig', *args], check=True, cwd=cwd, capture_output=True)


@unittest.skipUnless(shutil.which('zig') and shutil.which('bwrap'), 'zig and bubblewrap required')
class WinLoad64Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix='wins-winload64-'))
        cls.dlls = cls.work / 'dlls'
        cls.dlls.mkdir()
        lib = ['-dynamic', '-target', 'x86_64-windows-gnu', '-O', 'ReleaseSmall', '-fstrip']
        # Minimal msvcrt import library (malloc/free/_snprintf) without pulling in a CRT.
        zig('dlltool', '-d', str(FIX / 'msvcrt_min.def'), '-l', str(cls.work / 'msvcrt.lib'), '-m', 'i386:x86-64', cwd=cls.work)
        zig('build-lib', *lib, str(FIX / 'fixture_a.zig'), f'-L{cls.work}', f'-femit-bin={cls.dlls / A}',
            f'-femit-implib={cls.work / "fixture_a.lib"}', cwd=cls.work)
        zig('build-lib', *lib, str(FIX / 'fixture_b.zig'), f'-L{cls.work}', '-lfixture_a',
            f'-femit-bin={cls.dlls / "fixture_b.dll"}', cwd=cls.work)
        for f in ('fixture_c', 'fixture_d'):
            zig('build-lib', *lib, str(FIX / f'{f}.zig'), f'-femit-bin={cls.dlls / (f + ".dll")}', cwd=cls.work)
        zig('build-exe', '-target', 'x86_64-windows-gnu', '-O', 'ReleaseSmall', str(FIX / 'fixture_host.zig'),
            f'-femit-bin={cls.dlls / "fixture_host.exe"}', cwd=cls.work)
        for loader in ('winload64', 'winload64_bad_tls_index'):
            zig('build-exe', str(ROOT / 'native' / f'{loader}.zig'), '-O', 'ReleaseSafe',
                f'-femit-bin={cls.work / loader}', cwd=cls.work)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    def pin(self, name):
        return ['--pin', f'{name}={sha256((self.dlls / name).read_bytes()).hexdigest()}']

    def box(self, root, *args, loader='winload64'):
        return subprocess.run(['python3', str(ROOT / 'native' / 'winload64_box.py'), '--loader',
                               str(self.work / loader), '--dll-dir', str(self.dlls), root, *args],
                              capture_output=True, text=True, timeout=120)

    def calls(self, loader):
        argv = self.pin('fixture_b.dll') + self.pin(A)
        for target, args, ret in SEQ:
            argv += ['--call', target] + [x for v in args for x in ('--arg', str(v))] + ['--ret', ret]
        r = self.box('fixture_b.dll', *argv, loader=loader)
        self.assertEqual(r.returncode, 0, r.stderr)
        return [l.replace(f'call {A}!', 'call ') for l in r.stderr.splitlines() if l.startswith('call ')]

    @unittest.skipUnless(shutil.which('wine'), 'Wine (the oracle) required')
    def test_identical_to_wine_and_defect_detected(self):
        box = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
               '--ro-bind', '/usr', '/usr', '--ro-bind', '/etc', '/etc', '--symlink', 'usr/bin', '/bin',
               '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc',
               '--dev', '/dev', '--tmpfs', '/tmp', '--bind', str(self.dlls), '/work',
               '--setenv', 'HOME', '/tmp', '--setenv', 'WINEPREFIX', '/work/prefix',
               '--setenv', 'WINEDEBUG', '-all', '--chdir', '/work', '--']
        # A brand-new prefix finishes configuring on its first run and can swallow that
        # program's output: initialise it first, then run the host.
        subprocess.run(box + ['/usr/bin/wine', 'wineboot', '-u'], capture_output=True, timeout=600)
        w = subprocess.run(box + ['/usr/bin/wine', '/work/fixture_host.exe'], capture_output=True, text=True, timeout=600)
        oracle = [l for l in (w.stdout + w.stderr).splitlines() if l.startswith('call ')]
        self.assertEqual(len(oracle), len(SEQ), w.stderr[-2000:])
        self.assertEqual(self.calls('winload64'), oracle)
        self.assertNotEqual(self.calls('winload64_bad_tls_index'), oracle,
                            'negative control: shared TLS slot must be visible to the oracle')

    def test_hash_mismatch_refused(self):
        r = self.box(A, '--pin', f'{A}={"0" * 64}', '--call', 'fix_add')
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertNotIn('call ', r.stderr)

    def test_unpinned_dll_file_refused(self):
        r = self.box('fixture_b.dll', *self.pin('fixture_b.dll'), '--call', 'fixb_add_twice')
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertIn('not pinned', r.stderr)

    def test_unimplemented_import_executes_nothing(self):
        r = self.box('fixture_c.dll', *self.pin('fixture_c.dll'), '--call', 'fixc_probe')
        self.assertEqual(r.returncode, 4, r.stderr)
        self.assertIn('GetLogicalProcessorInformation', r.stderr)
        self.assertNotIn('READY', r.stderr)

    def test_dllmain_false(self):
        r = self.box('fixture_d.dll', *self.pin('fixture_d.dll'), '--call', 'fixd_never')
        self.assertEqual(r.returncode, 7, r.stderr)
        self.assertNotIn('call ', r.stderr)

    def test_requires_box(self):
        r = subprocess.run([str(self.work / 'winload64'), *self.pin(A), '--dll-dir', str(self.dlls),
                            str(self.dlls / A), '--call', 'fix_add'], capture_output=True, text=True,
                           env={k: v for k, v in os.environ.items() if k != 'WINS_WINRUN_BOX'})
        self.assertEqual(r.returncode, 2, r.stderr)


if __name__ == '__main__':
    unittest.main()
