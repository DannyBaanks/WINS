"""Independent PE fixtures and objdump cross-check for Zig imports."""
import json
import os
import pathlib
import re
import random
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

def fixture(is64=True, fallback=False):
    b = bytearray(1024)
    b[:2] = b'MZ'
    struct.pack_into('<I', b, 0x3c, 0x80)
    b[0x80:0x84] = b'PE\0\0'
    optsize = 240 if is64 else 224
    struct.pack_into('<HHIIIHH', b, 0x84, 0x8664 if is64 else 0x14c, 1, 0, 0, 0, optsize, 2)
    opt = 0x98
    struct.pack_into('<H', b, opt, 0x20b if is64 else 0x10b)
    struct.pack_into('<I', b, opt + 60, 0x200)
    dirs = 112 if is64 else 96
    struct.pack_into('<I', b, opt + dirs - 4, 16)
    struct.pack_into('<II', b, opt + dirs + 8, 0x1000, 40)
    sec = opt + optsize
    struct.pack_into('<8sIIII', b, sec, b'.idata\0\0', 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into('<IIIII', b, 0x200, 0 if fallback else 0x1060, 0, 0, 0x1040, 0x1060)
    b[0x240:0x24d] = b'KERNEL32.dll\0'
    if is64:
        struct.pack_into('<QQQ', b, 0x260, 0x1090, (1 << 63) | 17, 0)
    else:
        struct.pack_into('<III', b, 0x260, 0x1090, (1 << 31) | 17, 0)
    struct.pack_into('<H', b, 0x290, 42)
    b[0x292:0x29e] = b'CreateFileA\0'
    return b

class PeBinaryCase(unittest.TestCase):
    __test__ = False
    @classmethod
    def setUpClass(cls):
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix='wins-pe-test-'))
        cls.exe = pathlib.Path(os.environ.get('WINS_TEST_BINARY', cls.tmp / 'wins'))
        if 'WINS_TEST_BINARY' not in os.environ:
            subprocess.run(['zig', 'build-exe', str(ROOT/'native/main.zig'), '-O', 'ReleaseSafe', f'-femit-bin={cls.exe}'], check=True)

    def run_imports(self, data):
        path = self.tmp / 'fixture.exe'
        path.write_bytes(data)
        return subprocess.run([str(self.exe), 'imports', str(path), '--json'], text=True, capture_output=True)


class ImportTests(PeBinaryCase):
    __test__ = True

    def test_32_64_named_ordinal_and_iat_fallback(self):
        for is64 in (False, True):
            for fallback in (False, True):
                with self.subTest(is64=is64, fallback=fallback):
                    result = self.run_imports(fixture(is64, fallback))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    rep = json.loads(result.stdout)['pe']
                    self.assertEqual(rep['format'], 'PE32+' if is64 else 'PE32')
                    self.assertEqual(rep['imports_count'], 2)
                    self.assertEqual(rep['libraries'][0]['name'], 'KERNEL32.dll')
                    self.assertEqual(rep['libraries'][0]['symbols'], [
                        {'name':'CreateFileA', 'ordinal':None, 'hint':42},
                        {'name':None, 'ordinal':17, 'hint':None}])

    def test_absent_import_directory_is_empty(self):
        for is64 in (False, True):
            b = fixture(is64)
            directory = 0x98 + (112 if is64 else 96)
            struct.pack_into('<II', b, directory + 8, 0, 0)
            result = self.run_imports(b)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)['pe']
            self.assertEqual(report['libraries'], [])
            self.assertEqual(report['imports_count'], 0)

    def test_invalid_rvas_and_missing_terminators_fail_closed(self):
        for offset, payload in ((0x20c, struct.pack('<I', 0x90000000)),
                                (0x260, struct.pack('<Q', 0x90000000)),
                                (0x214, b'\xff' * 20)):
            b = fixture()
            b[offset:offset+len(payload)] = payload
            with self.subTest(offset=offset):
                result = self.run_imports(b)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')

    def test_mutated_and_truncated_inputs_do_not_crash(self):
        rng = random.Random(1337)
        original = fixture()
        for case in range(150):
            data = bytearray(original)
            if case < 50:
                del data[rng.randrange(len(data)):]
            else:
                for _ in range(1 + rng.randrange(8)):
                    data[rng.randrange(len(data))] = rng.randrange(256)
            result = self.run_imports(data)
            self.assertGreaterEqual(result.returncode, 0, result.stderr)
            if result.returncode == 0:
                json.loads(result.stdout)
            else:
                self.assertEqual(result.stdout, '')

    def test_real_pe_symbols_match_objdump(self):
        samples = [pathlib.Path('/tmp/wins-guide-npp-1107/notepad++.exe'),
                   pathlib.Path('/tmp/wins-native-winmerge-1107/app/WinMergeU.exe'),
                   pathlib.Path('/home/danny/Descargas/wins-samples/npp.8.9.9.Installer.x64.exe')]
        samples = [p for p in samples if p.is_file()]
        if not samples or not shutil.which('objdump'):
            self.skipTest('samples or objdump unavailable')
        for target in samples:
            with self.subTest(target=str(target)):
                out = subprocess.run([str(self.exe), 'imports', str(target), '--json'], capture_output=True, text=True, check=True)
                report = json.loads(out.stdout)['pe']
                oracle = subprocess.run(['objdump', '-p', str(target)], capture_output=True, text=True, check=True, env={'LC_ALL': 'C', 'PATH': os.environ['PATH']}).stdout
                table = oracle.split('The Import Tables', 1)[1].split('The Function Table', 1)[0]
                expected = {}
                current = None
                for line in table.splitlines():
                    dll = re.search(r'DLL Name:\s*(\S+)', line)
                    if dll:
                        current = dll.group(1)
                        expected[current] = []
                        continue
                    symbol = re.fullmatch(r'\s*([0-9a-f]+)\s+([0-9a-f]+)\s+(\S+)\s*', line)
                    if current and symbol:
                        name = symbol.group(3)
                        expected[current].append(('ordinal', int(symbol.group(1), 16) & 0xffff) if name == '<none>' else ('name', name))
                actual = {lib['name']: [('name', s['name']) if s['name'] is not None else ('ordinal', s['ordinal']) for s in lib['symbols']] for lib in report['libraries']}
                self.assertEqual(actual, expected)
                self.assertEqual(report['imports_count'], sum(map(len, expected.values())))

def delay_fixture(is64=True, va_based=False, terminate=True, clr=False):
    """Fixture with a normal import table plus one delay-load descriptor (USER32!MessageBoxW + ordinal 9)."""
    b = fixture(is64)
    opt, dirs = 0x98, (112 if is64 else 96)
    struct.pack_into('<II', b, opt + dirs + 13 * 8, 0x10c0, 64)
    if clr:
        struct.pack_into('<II', b, opt + dirs + 14 * 8, 0x1100, 72)
    # descriptor: attrs, dll name, hmod, IAT, INT, bound IAT, unload IAT, timestamp
    struct.pack_into('<IIIIIIII', b, 0x2c0, 0 if va_based else 1, 0x1100, 0x1180, 0x1160, 0x1120, 0, 0, 0)
    if terminate:
        b[0x2e0:0x300] = bytes(32)
    else:
        b[0x2e0:0x300] = b'\x01' * 32
    b[0x300:0x30b] = b'USER32.dll\0'
    if is64:
        struct.pack_into('<QQQ', b, 0x320, 0x1140, (1 << 63) | 9, 0)
    else:
        struct.pack_into('<III', b, 0x320, 0x1140, (1 << 31) | 9, 0)
    struct.pack_into('<H', b, 0x340, 7)
    b[0x342:0x34e] = b'MessageBoxW\0'
    return b

class DelayImportTests(PeBinaryCase):
    __test__ = True

    def test_delay_imports_32_and_64(self):
        for is64 in (False, True):
            with self.subTest(is64=is64):
                result = self.run_imports(delay_fixture(is64))
                self.assertEqual(result.returncode, 0, result.stderr)
                rep = json.loads(result.stdout)['pe']
                self.assertEqual(rep['imports_count'], 2)          # normal table untouched
                self.assertEqual(rep['delay_imports_count'], 2)
                self.assertFalse(rep['managed_clr'])
                self.assertEqual(rep['delay_libraries'], [{'name': 'USER32.dll', 'symbols': [
                    {'name': 'MessageBoxW', 'ordinal': None, 'hint': 7},
                    {'name': None, 'ordinal': 9, 'hint': None}]}])

    def test_delay_absent_means_empty_not_error(self):
        result = self.run_imports(fixture(True))
        self.assertEqual(result.returncode, 0, result.stderr)
        rep = json.loads(result.stdout)['pe']
        self.assertEqual((rep['delay_libraries'], rep['delay_imports_count'], rep['managed_clr']), ([], 0, False))

    def test_clr_header_is_reported(self):
        rep = json.loads(self.run_imports(delay_fixture(True, clr=True)).stdout)['pe']
        self.assertTrue(rep['managed_clr'])

    def test_delay_unsupported_or_unterminated_fails_closed(self):
        for kwargs in ({'va_based': True}, {'terminate': False}):
            with self.subTest(**kwargs):
                result = self.run_imports(delay_fixture(True, **kwargs))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')

    def test_delay_mutations_do_not_crash(self):
        rng = random.Random(4242)
        original = delay_fixture(True, clr=True)
        for case in range(150):
            data = bytearray(original)
            if case < 40:
                del data[rng.randrange(0x200, len(data)):]
            else:
                for _ in range(1 + rng.randrange(8)):
                    data[rng.randrange(0x2c0, 0x350)] = rng.randrange(256)
            result = self.run_imports(data)
            self.assertGreaterEqual(result.returncode, 0, result.stderr)
            if result.returncode == 0:
                json.loads(result.stdout)
            else:
                self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
