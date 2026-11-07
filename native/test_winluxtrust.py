"""Differential tests for winluxtrust (digest half of WinVerifyTrust).

Independent oracle: osslsigncode prints the digest stored in the signature
("Current") and the one it computes from the file ("Calculated"). Fixtures are
synthetic (a Zig-built PE signed with a throw-away self-signed key), so nothing
proprietary is needed. Chain/signature validity is NOT tested because it is
NOT implemented: a digest match must never be reported as success.
"""
import json
import os
from pathlib import Path
import random
import re
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TRUST_E_NOSIGNATURE, TRUST_E_FORM, TRUST_E_BAD_DIGEST = 0x800B0100, 0x800B0003, 0x80096010
MATCH = 0x20570001
OSSL = os.environ.get('WINS_OSSLSIGNCODE') or shutil.which('osslsigncode') or '/tmp/wins-authenticode-20261107/root/usr/bin/osslsigncode'


def pe_layout(b):
    e = struct.unpack_from('<I', b, 0x3c)[0]
    opt = e + 24
    dirs = 112 if struct.unpack_from('<H', b, opt)[0] == 0x20b else 96
    cert_entry = opt + dirs + 32
    off, size = struct.unpack_from('<II', b, cert_entry)
    return {'checksum': opt + 64, 'cert_entry': cert_entry, 'cert_off': off, 'cert_size': size,
            'headers': struct.unpack_from('<I', b, opt + 60)[0]}


def oracle(path):
    """(embedded, calculated) hex digests as printed by osslsigncode, or None."""
    out = subprocess.run([OSSL, 'verify', '-in', str(path)], capture_output=True, text=True, timeout=30,
                         env={'LC_ALL': 'C', 'PATH': os.environ['PATH']}).stdout
    cur = re.search(r'Current message digest\s*:\s*([0-9A-F]+)', out)
    calc = re.search(r'Calculated message digest\s*:\s*([0-9A-F]+)', out)
    return (cur.group(1).lower(), calc.group(1).lower()) if cur and calc else None


@unittest.skipUnless(os.path.exists(OSSL) and shutil.which('bwrap') and shutil.which('openssl'), 'osslsigncode/bwrap/openssl unavailable')
class TrustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix='wins-trust-'))
        t = cls.tmp
        src = t / 'hello.zig'
        src.write_text('const std = @import("std");\npub fn main() void { std.debug.print("hi\\n", .{}); }\n')
        subprocess.run(['zig', 'build-exe', str(src), '-target', 'x86_64-windows-gnu', '-O', 'ReleaseSmall', f'-femit-bin={t/"hello.exe"}'], check=True, capture_output=True)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(t/'k.pem'), '-out', str(t/'c.pem'),
                        '-days', '30', '-subj', '/CN=winlux-test'], check=True, capture_output=True)
        cls.signed = {}
        for alg in ('sha1', 'sha256', 'sha384', 'sha512'):
            out = t / f'signed-{alg}.exe'
            subprocess.run([OSSL, 'sign', '-certs', str(t/'c.pem'), '-key', str(t/'k.pem'), '-h', alg, '-in', str(t/'hello.exe'), '-out', str(out)], check=True, capture_output=True)
            cls.signed[alg] = out.read_bytes()
        cls.runner = t / 'fuzz_trust'
        subprocess.run(['zig', 'build-exe', str(ROOT/'native/fuzz_winluxtrust.zig'), '-lc', '-O', 'ReleaseSafe', f'-femit-bin={cls.runner}'], check=True, capture_output=True)
        cls.libs = {}
        for name, root in (('good', 'native/shims/winluxtrust.zig'), ('checksum', 'native/winluxtrust_bad_checksum.zig'), ('acceptall', 'native/winluxtrust_bad_acceptall.zig')):
            lib = t / f'{name}.so'
            subprocess.run(['zig', 'build-lib', str(ROOT/root), '-dynamic', '-lc', '-O', 'ReleaseSafe', f'-femit-bin={lib}'], check=True, capture_output=True)
            cls.libs[name] = lib

    def run_candidate(self, lib, files):
        d = Path(tempfile.mkdtemp(prefix='cases-', dir=self.tmp))
        for name, data in files.items():
            (d / name).write_bytes(data)
        r = subprocess.run(['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
                            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
                            '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
                            '--ro-bind', str(lib), '/candidate.so', '--ro-bind', str(d), '/cases',
                            '--ro-bind', str(ROOT/'native/testdata/winluxtrust_harness.py'), '/harness.py',
                            '--', '/usr/bin/python3', '-I', '/harness.py', '/candidate.so', '/cases'],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        return {j['file']: j for j in map(json.loads, r.stdout.splitlines())}

    _oracle_cache = {}

    def oracle_bytes(self, data):
        key = hash(data)
        if key not in self._oracle_cache:
            p = self.tmp / 'oracle.bin'
            p.write_bytes(data)
            self._oracle_cache[key] = oracle(p)
        return self._oracle_cache[key]

    def test_every_digest_algorithm_matches_the_signature_and_the_oracle(self):
        res = self.run_candidate(self.libs['good'], {f'{a}.exe': d for a, d in self.signed.items()})
        for alg, data in self.signed.items():
            with self.subTest(alg=alg):
                r = res[f'{alg}.exe']
                self.assertEqual(r['rc'], MATCH, r)
                self.assertNotEqual(r['rc'], 0, 'a digest match must never look like ERROR_SUCCESS')
                self.assertEqual(r['embedded'], r['computed'])
                cur, calc = self.oracle_bytes(data)
                self.assertEqual((r['embedded'], r['computed']), (cur, calc))

    def test_unsigned_and_not_a_pe(self):
        unsigned = (self.tmp / 'hello.exe').read_bytes()
        res = self.run_candidate(self.libs['good'], {'unsigned.exe': unsigned, 'junk.bin': bytes(range(256)) * 4, 'empty.bin': b'', 'mz.exe': b'MZ' + bytes(100)})
        self.assertEqual(res['unsigned.exe']['rc'], TRUST_E_NOSIGNATURE)
        for k in ('junk.bin', 'empty.bin', 'mz.exe'):
            self.assertEqual(res[k]['rc'], TRUST_E_FORM, k)

    def mutants(self, seed=0xA17C):
        rng = random.Random(seed)
        base = self.signed['sha256']
        lay = pe_layout(base)
        cert_end = lay['cert_off'] + lay['cert_size']
        hashed = [i for i in range(lay['cert_off'])
                  if not (lay['checksum'] <= i < lay['checksum'] + 4) and not (lay['cert_entry'] <= i < lay['cert_entry'] + 8)]
        cases = {}
        for n in range(10):  # A: flips in hashed bytes
            b = bytearray(base); i = rng.choice(hashed); b[i] ^= 1 << rng.randrange(8)
            cases[f'A{n:02d}.exe'] = ('hashed', bytes(b))
        for n in range(4):  # B: flips in the checksum field (excluded from the hash)
            b = bytearray(base); b[lay['checksum'] + rng.randrange(4)] ^= 1 << rng.randrange(8)
            cases[f'B{n:02d}.exe'] = ('excluded', bytes(b))
        for n in range(10):  # C: flips inside the signature blob
            b = bytearray(base); b[rng.randrange(lay['cert_off'], cert_end)] ^= 1 << rng.randrange(8)
            cases[f'C{n:02d}.exe'] = ('blob', bytes(b))
        for n in range(6):  # D: truncations
            cases[f'D{n:02d}.exe'] = ('truncated', base[:rng.randrange(1, len(base))])
        for n in range(3):   # E: appended garbage
            cases[f'E{n:02d}.exe'] = ('appended', base + bytes(rng.randrange(256) for _ in range(rng.randrange(1, 64))))
        return cases

    def check_invariants(self, lib_name, expect_clean):
        cases = self.mutants()
        res = self.run_candidate(self.libs[lib_name], {k: v[1] for k, v in cases.items()})
        problems = []
        orig = self.oracle_bytes(self.signed['sha256'])[0]  # digest of the untouched signed file
        for name, (kind, data) in cases.items():
            r = res[name]
            o = self.oracle_bytes(data)
            equal = o is not None and o[0] == o[1]
            # A signature-blob flip aborts osslsigncode before it prints digests, so for that class
            # the independent oracle is the original digest: the blob is not part of the hash.
            blob_ok = kind == 'blob' and r['embedded'] == orig and r['computed'] == orig
            # 'appended' bytes are trailing data covered by the hash (spec); osslsigncode refuses such files
            # outright, so it offers no digest opinion for that class.
            if kind in ('hashed', 'appended') and r['rc'] != TRUST_E_BAD_DIGEST:
                problems.append((name, kind, hex(r['rc'])))
            elif kind == 'excluded' and r['rc'] != MATCH:
                problems.append((name, kind, hex(r['rc'])))
            elif r['rc'] == MATCH and not (equal or blob_ok):
                problems.append((name, kind, 'MATCH but no oracle agrees'))
            elif r['rc'] == TRUST_E_BAD_DIGEST and kind == 'blob' and r['embedded'] == orig:
                problems.append((name, kind, 'BAD_DIGEST although the embedded digest is unchanged'))
            elif r['rc'] == TRUST_E_BAD_DIGEST and kind not in ('blob', 'appended') and (o is None or equal):
                problems.append((name, kind, 'BAD_DIGEST but oracle disagrees'))
            elif kind == 'truncated' and r['rc'] == MATCH:
                problems.append((name, kind, 'MATCH on truncated file'))
        if expect_clean:
            self.assertEqual(problems, [])
        else:
            self.assertTrue(problems, 'negative control was not detected')
        return problems

    def test_mutation_invariants_against_osslsigncode(self):
        self.check_invariants('good', True)

    def test_control_checksum_included_in_hash_is_detected(self):
        problems = self.check_invariants('checksum', False)
        self.assertTrue(any(k == 'excluded' for _, k, _ in problems))

    def test_control_accepting_any_digest_is_detected(self):
        problems = self.check_invariants('acceptall', False)
        self.assertTrue(any(k == 'hashed' for _, k, _ in problems))

    # ---- volume lives in Zig: the Python tests above only calibrate against osslsigncode ----
    def run_zig_fuzzer(self, lib, iterations=20000):
        digest = self.oracle_bytes(self.signed['sha256'])[0]
        signed = self.tmp / 'signed-sha256.exe'
        return subprocess.run(['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
                               '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
                               '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
                               '--ro-bind', str(self.runner), '/runner', '--ro-bind', str(lib), '/candidate.so',
                               '--ro-bind', str(signed), '/signed.exe', '--', '/runner', '/candidate.so', '/signed.exe',
                               digest, str(iterations)], capture_output=True, text=True, timeout=120)

    def test_zig_mutation_fuzzer_matches_spec_classes(self):
        r = self.run_zig_fuzzer(self.libs['good'], 50000)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('MATCHED', r.stderr)
        self.assertNotIn('=0 ', r.stderr.split('classes[')[1].split(']')[0] + ' ', 'a mutation class was never exercised')

    def test_zig_fuzzer_detects_both_controls(self):
        for name in ('checksum', 'acceptall'):
            with self.subTest(control=name):
                r = self.run_zig_fuzzer(self.libs[name])
                self.assertNotEqual(r.returncode, 0)
                self.assertIn('DIVERGENCE', r.stderr)


if __name__ == '__main__':
    unittest.main()
