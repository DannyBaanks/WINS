"""Tests for the CP_UTF8 text candidate protocol.

Three independent layers:
  1. the C oracle is cross-checked against CPython's UTF-8 codec (a third
     implementation) so the fuzzer does not compare two copies of one assumption;
  2. the real candidate must MATCH the oracle under the sandboxed fuzzer;
  3. two deliberately broken candidates must DIVERGE (negative controls).
None of this establishes equivalence with a real Windows kernel.
"""
import ctypes
from pathlib import Path
import random
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def build(cmd, *args):
    subprocess.run(['zig', *cmd, *map(str, args)], check=True, capture_output=True)


class TextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = Path(tempfile.mkdtemp(prefix='wins-text-'))
        cls.runner = base / 'runner'
        cls.oracle = base / 'oracle.so'
        cls.good = base / 'good.so'
        cls.perbyte = base / 'perbyte.so'
        cls.overrun = base / 'overrun.so'
        build(['build-exe'], ROOT / 'native/fuzz_win32_text.zig', '-lc', '-O', 'ReleaseSafe', f'-femit-bin={cls.runner}')
        build(['cc'], '-shared', '-fPIC', '-O2', ROOT / 'native/testdata/win32_text_oracle.c', '-o', cls.oracle)
        for lib, src in ((cls.good, 'native/shims/win32_text.zig'),
                         (cls.perbyte, 'native/win32_text_bad_perbyte.zig'),
                         (cls.overrun, 'native/win32_text_bad_overrun.zig')):
            build(['build-lib'], ROOT / src, '-dynamic', '-lc', '-O', 'ReleaseSafe', f'-femit-bin={lib}')
        cls.lib = ctypes.CDLL(str(cls.oracle))
        cls.lib.wins_mb2wc.argtypes = [ctypes.c_uint32, ctypes.c_char_p, ctypes.c_int32,
                                       ctypes.POINTER(ctypes.c_uint16), ctypes.c_int32, ctypes.POINTER(ctypes.c_uint32)]
        cls.lib.wins_mb2wc.restype = ctypes.c_int32
        cls.lib.wins_wc2mb.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint16), ctypes.c_int32,
                                       ctypes.c_char_p, ctypes.c_int32, ctypes.POINTER(ctypes.c_uint32)]
        cls.lib.wins_wc2mb.restype = ctypes.c_int32

    # ---- helpers around the oracle -------------------------------------------------
    def mb2wc(self, data, flags=0):
        err = ctypes.c_uint32()
        need = self.lib.wins_mb2wc(flags, data, len(data), None, 0, ctypes.byref(err))
        if need == 0:
            return None, err.value
        out = (ctypes.c_uint16 * need)()
        got = self.lib.wins_mb2wc(flags, data, len(data), out, need, ctypes.byref(err))
        self.assertEqual(got, need)
        return bytes(memoryview(out).cast('B')), 0

    def wc2mb(self, units, flags=0):
        arr = (ctypes.c_uint16 * len(units))(*units)
        err = ctypes.c_uint32()
        need = self.lib.wins_wc2mb(flags, arr, len(units), None, 0, ctypes.byref(err))
        if need == 0:
            return None, err.value
        out = ctypes.create_string_buffer(need)
        got = self.lib.wins_wc2mb(flags, arr, len(units), out, need, ctypes.byref(err))
        self.assertEqual(got, need)
        return out.raw, 0

    # ---- layer 1: oracle vs CPython ------------------------------------------------
    def test_oracle_known_vectors(self):
        self.assertEqual(self.mb2wc(b'\xe2\x82\xac')[0], '€'.encode('utf-16-le'))
        self.assertEqual(self.mb2wc(b'\xf0\x9f\x98\x80')[0], '😀'.encode('utf-16-le'))
        # E0 80 80: three maximal subparts -> three U+FFFD
        self.assertEqual(self.mb2wc(b'\xe0\x80\x80')[0], '���'.encode('utf-16-le'))
        self.assertEqual(self.mb2wc(b'\xe0\x80\x80', 8), (None, 1113))
        self.assertEqual(self.wc2mb([0xD800]), ('�'.encode(), 0))
        self.assertEqual(self.wc2mb([0xD800], 0x80), (None, 1113))

    def test_oracle_matches_cpython_utf8_decoder(self):
        rnd = random.Random(0x57494e53)
        pool = [0x41, 0x7F, 0x80, 0xBF, 0xC0, 0xC1, 0xC2, 0xDF, 0xE0, 0xE1, 0xED, 0xEF,
                0xF0, 0xF4, 0xF5, 0xFF, 0xA0, 0x9F, 0x90, 0x8F]
        for _ in range(20000):
            data = bytes(rnd.choice(pool) if rnd.random() < 0.7 else rnd.randrange(256)
                         for _ in range(rnd.randrange(1, 9)))
            replaced = data.decode('utf-8', 'replace').encode('utf-16-le')
            self.assertEqual(self.mb2wc(data)[0], replaced, data.hex())
            try:
                data.decode('utf-8')
                strict_ok = True
            except UnicodeDecodeError:
                strict_ok = False
            self.assertEqual(self.mb2wc(data, 8)[1] == 0, strict_ok, data.hex())

    def test_oracle_matches_cpython_utf16_encoder(self):
        rnd = random.Random(0xD800)
        pool = [0x41, 0xD7FF, 0xD800, 0xDBFF, 0xDC00, 0xDFFF, 0xE000, 0xFFFF, 0x20AC]
        for _ in range(20000):
            units = [rnd.choice(pool) if rnd.random() < 0.7 else rnd.randrange(65536)
                     for _ in range(rnd.randrange(1, 7))]
            raw = b''.join(u.to_bytes(2, 'little') for u in units)
            text = raw.decode('utf-16-le', 'surrogatepass')
            expected = ''.join('�' if 0xD800 <= ord(c) <= 0xDFFF else c for c in text).encode()
            self.assertEqual(self.wc2mb(units)[0], expected, units)
            lone = any(0xD800 <= ord(c) <= 0xDFFF for c in text)
            self.assertEqual(self.wc2mb(units, 0x80)[1] == 0, not lone, units)

    # ---- layers 2 and 3: sandboxed differential fuzzing ---------------------------
    def run_fuzz(self, candidate, iterations=100000):
        return subprocess.run(
            ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
             '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
             '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
             '--ro-bind', str(self.runner), '/runner', '--ro-bind', str(candidate), '/candidate.so',
             '--ro-bind', str(self.oracle), '/oracle.so',
             '--', '/runner', '/candidate.so', '/oracle.so', str(iterations)],
            capture_output=True, text=True, timeout=60)

    def test_candidate_matches_oracle_and_exercises_every_outcome(self):
        r = self.run_fuzz(self.good)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('MATCHED', r.stderr)
        for key in ('ok=', 'e87=', 'e122=', 'e1004=', 'e1113='):
            for side in r.stderr.split('mb2wc[')[1].split(']')[0], r.stderr.split('wc2mb[')[1].split(']')[0]:
                self.assertNotIn(key + '0 ', side + ' ', f'fuzzer never reached {key}: {r.stderr}')

    def test_control_per_byte_replacement_is_detected(self):
        r = self.run_fuzz(self.perbyte)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('DIVERGENCE mb2wc', r.stderr)

    def test_control_destination_overrun_is_detected(self):
        r = self.run_fuzz(self.overrun)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('DIVERGENCE', r.stderr)


if __name__ == '__main__':
    unittest.main()
