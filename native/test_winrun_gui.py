"""Synthetic USER32 popup through the experimental PE loader, in private Xvfb."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BOX = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
       '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
       '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
       '--ro-bind', '/etc', '/etc', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
       '--setenv', 'WINS_WINRUN_BOX', '1', '--setenv', 'HOME', '/tmp',
       '--setenv', 'WINEPREFIX', '/tmp/pfx', '--setenv', 'WINEDEBUG', '-all',
       '--setenv', 'WINEDLLOVERRIDES', 'mscoree,mshtml=d']
SERVER = '''
mkdir -m 1777 /tmp/.X11-unix
Xvfb :91 -screen 0 640x480x24 -nolisten tcp -extension GLX -extension DRI3 > /tmp/xvfb.log 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null; wait "$server" 2>/dev/null' EXIT
i=0
until xdpyinfo -display :91 >/dev/null 2>&1; do
  kill -0 "$server" 2>/dev/null || { cat /tmp/xvfb.log >&2; exit 90; }
  [ "$i" -lt 100 ] || { cat /tmp/xvfb.log >&2; exit 91; }
  i=$((i+1)); sleep 0.05
done
export DISPLAY=:91
"$@"
exit $?
'''


class WinrunGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ('zig', 'bwrap', 'Xvfb', 'xdpyinfo'):
            if not shutil.which(tool):
                raise unittest.SkipTest(f'{tool} is not installed')
        cls.directory = Path(tempfile.mkdtemp(prefix='wins-gui-'))
        cls.wine_pfx = cls.directory / 'pfx'
        cls.wine_pfx.mkdir(parents=True, exist_ok=True)
        default_wine = Path.home() / '.wine'
        if default_wine.is_dir():
            subprocess.run(['cp', '-al', str(default_wine / '.'), str(cls.wine_pfx)],
                           check=False, capture_output=True)
        cls.probe = cls.directory / 'probe.exe'
        cls.unresolved = cls.directory / 'unresolved.exe'
        cls.loader = cls.directory / 'loader'
        cls.console_loader = cls.directory / 'console-loader'
        def zig(*args):
            subprocess.run(['zig', 'build-exe', *map(str, args)], cwd=ROOT,
                           check=True, capture_output=True, timeout=180)
        zig('native/testdata/winrun_gui_probe.zig', '-target', 'x86_64-windows-gnu',
            '-O', 'ReleaseSmall', '-fentry=wWinMainCRTStartup', '--subsystem', 'windows',
            '-luser32', f'-femit-bin={cls.probe}')
        zig('native/testdata/winrun_gui_unresolved.zig', '-target', 'x86_64-windows-gnu',
            '-O', 'ReleaseSmall', '-fentry=wWinMainCRTStartup', '--subsystem', 'windows',
            '-luser32', f'-femit-bin={cls.unresolved}')
        zig('native/winrun_gui.zig', '-O', 'ReleaseSafe', '-lc', '-lX11', f'-femit-bin={cls.loader}')
        zig('native/winrun.zig', '-O', 'ReleaseSafe', f'-femit-bin={cls.console_loader}')
        def zig_cc(*args):
            subprocess.run(['zig', 'cc', *map(str, args)], cwd=ROOT,
                           check=True, capture_output=True, timeout=180)
        cls.tls_nocb = cls.directory / 'tls_nocb.exe'
        cls.tls_withcb = cls.directory / 'tls_withcb.exe'
        zig_cc('-target', 'x86_64-windows-gnu', '-O2', '-nostdlib',
               '-Wl,-e,wWinMainCRTStartup,--subsystem,console', '-lkernel32',
               'native/testdata/winrun_gui_tls.c', '-o', cls.tls_nocb)
        zig_cc('-target', 'x86_64-windows-gnu', '-O2', '-nostdlib',
               '-Wl,-e,wWinMainCRTStartup,--subsystem,windows', '-lkernel32',
               'native/testdata/winrun_gui_tls_callback.c', '-o', cls.tls_withcb)
        cls.wndproc_probe = cls.directory / 'wndproc_probe.exe'
        zig('native/testdata/winrun_gui_wndproc_probe.zig', '-target', 'x86_64-windows-gnu',
            '-O', 'ReleaseSmall', '-fentry=wWinMainCRTStartup', '--subsystem', 'windows',
            '-luser32', '-lkernel32', f'-femit-bin={cls.wndproc_probe}')
        cls.wndproc_digest = hashlib.sha256(cls.wndproc_probe.read_bytes()).hexdigest()
        cls.digest = hashlib.sha256(cls.probe.read_bytes()).hexdigest()

    def sandbox(self, loader, *args, server=False):
        argv = BOX + ['--ro-bind', str(self.probe), '/probe.exe',
                      '--ro-bind', str(loader), '/loader', '--']
        command = ['/loader', '--sha256', self.digest, *args, '/probe.exe']
        if server:
            command = ['/bin/sh', '-c', SERVER, 'private-x11', *command]
        return subprocess.run(argv + command, capture_output=True, text=True, timeout=60)

    def test_gui_probe_in_private_server(self):
        result = self.sandbox(self.loader, server=True)
        self.assertEqual(result.returncode, 41, result.stderr)

    def test_console_loader_still_refuses_gui(self):
        result = self.sandbox(self.console_loader, '--check')
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn('subsystem 2 is not console', result.stderr)

    def test_gui_fails_without_display(self):
        result = self.sandbox(self.loader)
        self.assertEqual(result.returncode, 45, result.stderr)

    def test_gui_loader_still_requires_exact_hash(self):
        argv = BOX + ['--ro-bind', str(self.probe), '/probe.exe', '--ro-bind', str(self.loader), '/loader',
                      '--', '/loader', '--sha256', '0' * 64, '/probe.exe']
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn('sha256 mismatch', result.stderr)

    def test_unimplemented_gui_import_refuses_before_entry(self):
        digest = hashlib.sha256(self.unresolved.read_bytes()).hexdigest()
        argv = BOX + ['--ro-bind', str(self.unresolved), '/probe.exe', '--ro-bind', str(self.loader), '/loader',
                      '--', '/loader', '--sha256', digest, '/probe.exe']
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn('CascadeWindows', result.stderr)

    def test_tls_data_only_probe_runs(self):
        """GUI loader must execute a PE with data-only TLS (0 callbacks)."""
        digest = hashlib.sha256(self.tls_nocb.read_bytes()).hexdigest()
        argv = BOX + ['--ro-bind', str(self.tls_nocb), '/probe.exe',
                      '--ro-bind', str(self.loader), '/loader',
                      '--', '/loader', '--sha256', digest, '/probe.exe']
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 41, result.stderr)

    def test_tls_with_callbacks_executes_before_entry(self):
        """GUI loader must execute PIMAGE_TLS_CALLBACK before entry point and reach entry (exits 41)."""
        digest = hashlib.sha256(self.tls_withcb.read_bytes()).hexdigest()
        argv = BOX + ['--ro-bind', str(self.tls_withcb), '/probe.exe',
                      '--ro-bind', str(self.loader), '/loader',
                      '--', '/loader', '--sha256', digest, '/probe.exe']
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 41, result.stderr)

    def test_console_loader_accepts_tls(self):
        """Console loader must accept and execute a PE with a valid TLS directory."""
        digest = hashlib.sha256(self.tls_nocb.read_bytes()).hexdigest()
        argv = BOX + ['--ro-bind', str(self.tls_nocb), '/probe.exe',
                      '--ro-bind', str(self.console_loader), '/loader',
                      '--', '/loader', '--sha256', digest, '--check', '/probe.exe']
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('READY', result.stderr)

    def test_same_probe_with_wine_when_available(self):
        if not shutil.which('wine'):
            self.skipTest('Wine reference unavailable')
        argv = BOX + ['--bind', str(self.wine_pfx), '/tmp/pfx',
                      '--ro-bind', str(self.probe), '/probe.exe', '--', '/bin/sh', '-c', SERVER,
                      'private-x11', '/usr/bin/wine', '/probe.exe']
        result = subprocess.run(argv, capture_output=True, text=True, timeout=180)
        self.assertEqual(result.returncode, 41, result.stderr)

    def test_wndproc_message_loop_in_private_server(self):
        """Custom window class, WndProc lifecycle (WM_CREATE, WM_PAINT, WM_CLOSE, WM_DESTROY),
        message loop and PostQuitMessage exit in private Xvfb."""
        argv = BOX + ['--ro-bind', str(self.wndproc_probe), '/probe.exe',
                      '--ro-bind', str(self.loader), '/loader', '--']
        command = ['/loader', '--sha256', self.wndproc_digest, '/probe.exe']
        result = subprocess.run(argv + ['/bin/sh', '-c', SERVER, 'private-x11', *command],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 52, result.stderr)

    def test_wndproc_matches_wine_when_available(self):
        """Compare custom WndProc message loop execution with Wine 9 reference."""
        if not shutil.which('wine'):
            self.skipTest('Wine reference unavailable')
        argv = BOX + ['--bind', str(self.wine_pfx), '/tmp/pfx',
                      '--ro-bind', str(self.wndproc_probe), '/probe.exe', '--', '/bin/sh', '-c', SERVER,
                      'private-x11', '/usr/bin/wine', '/probe.exe']
        result = subprocess.run(argv, capture_output=True, text=True, timeout=180)
        self.assertEqual(result.returncode, 52, result.stderr)


    def test_gup_corpus_check(self):
        """GUP.exe (Win64 Notepad++ updater GUI) must resolve all 298 imports and relocations in check mode."""
        gup = ROOT / 'corpus' / 'GUP.exe'
        if not gup.is_file():
            self.skipTest('corpus/GUP.exe not present')
        digest = hashlib.sha256(gup.read_bytes()).hexdigest()
        argv = BOX + ['--ro-bind', str(gup), '/probe.exe',
                      '--ro-bind', str(self.loader), '/loader',
                      '--', '/loader', '--sha256', digest, '--check', '/probe.exe']
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('READY', result.stderr)
        self.assertIn('imports=298', result.stderr)

    def test_cuphead_corpus_check(self):
        """Cuphead.exe (Unity 2017 PE binary) must resolve all 67 imports and relocations in check mode."""
        cup = ROOT / 'corpus' / 'Cuphead.exe'
        if not cup.is_file():
            self.skipTest('corpus/Cuphead.exe not present')
        digest = hashlib.sha256(cup.read_bytes()).hexdigest()
        argv = BOX + ['--ro-bind', str(cup), '/probe.exe',
                      '--ro-bind', str(self.loader), '/loader',
                      '--', '/loader', '--sha256', digest, '--check', '/probe.exe']
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('READY', result.stderr)
        self.assertIn('imports=67', result.stderr)
        self.assertIn('relocs=745', result.stderr)

    def test_unity_player_corpus_resolution(self):
        """UnityPlayer.dll (Unity 2017 Win64 engine) must achieve 100.0% import resolution (486/486)."""
        unity_dll = ROOT / 'corpus' / 'UnityPlayer.dll'
        if not unity_dll.is_file():
            self.skipTest('corpus/UnityPlayer.dll not present')
        fuzzer_bin = Path('/tmp/wins_fuzzer')
        if not fuzzer_bin.is_file():
            subprocess.run(['zig', 'build-exe', str(ROOT / 'native' / 'wins_fuzzer.zig'),
                            '-O', 'Debug', '-lc', '-lX11', '-fPIC', f'-femit-bin={fuzzer_bin}'],
                           check=True, capture_output=True)
        res = subprocess.run([str(fuzzer_bin), str(ROOT / 'corpus'), '--json'],
                             capture_output=True, text=True, check=True)
        data = json.loads(res.stdout)
        unity_entry = next((b for b in data['binaries'] if b['name'] == 'UnityPlayer.dll'), None)
        self.assertIsNotNone(unity_entry)
        self.assertEqual(unity_entry['missing'], 0, f"Missing imports in UnityPlayer: {unity_entry}")
        self.assertEqual(unity_entry['resolved'], 486)
        self.assertEqual(unity_entry['readiness_pct'], 100.0)

    def test_notepad_corpus_resolution(self):
        """notepad++.exe (Win64 text editor) must achieve 100.0% import resolution (624/624)."""
        npp = ROOT / 'corpus' / 'notepad++.exe'
        if not npp.is_file():
            self.skipTest('corpus/notepad++.exe not present')
        fuzzer_bin = Path('/tmp/wins_fuzzer')
        if not fuzzer_bin.is_file():
            subprocess.run(['zig', 'build-exe', str(ROOT / 'native' / 'wins_fuzzer.zig'),
                            '-O', 'Debug', '-lc', '-lX11', '-fPIC', f'-femit-bin={fuzzer_bin}'],
                           check=True, capture_output=True)
        res = subprocess.run([str(fuzzer_bin), str(ROOT / 'corpus'), '--json'],
                             capture_output=True, text=True, check=True)
        data = json.loads(res.stdout)
        npp_entry = next((b for b in data['binaries'] if b['name'] == 'notepad++.exe'), None)
        self.assertIsNotNone(npp_entry)
        self.assertEqual(npp_entry['missing'], 0, f"Missing imports in notepad++: {npp_entry}")
        self.assertEqual(npp_entry['resolved'], 624)
        self.assertEqual(npp_entry['readiness_pct'], 100.0)



if __name__ == '__main__':
    unittest.main()
