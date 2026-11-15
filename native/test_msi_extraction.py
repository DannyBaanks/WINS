"""Regression: 7-Zip must extract the outer MSI compound, not an embedded PE."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class MsiExtractionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix='wins-msi-regression-'))
        cls.wins = Path(os.environ.get('WINS_MSI_RUNNER', cls.tmp / 'wins'))
        if 'WINS_MSI_RUNNER' not in os.environ:
            subprocess.run(['zig', 'build-exe', str(ROOT/'native/main.zig'), '-O', 'ReleaseSafe', f'-femit-bin={cls.wins}'], check=True)
        cls.fake = cls.tmp / 'extractor'
        cls.fake.write_text('''#!/bin/sh
[ "$1" = x ] && [ "$2" = -tCompound ] && [ "$3" = -y ] && [ "$4" = /input ] && [ "$5" = -o/output ] || exit 7
printf table > '/output/!File'
''')
        cls.fake.chmod(0o755)

    def test_compound_header_forces_outer_container_for_7z_and_msi(self):
        source = self.tmp / 'input.bin'
        source.write_bytes(bytes.fromhex('d0cf11e0a1b11ae1') + b'fixture')
        for kind in ('7z', 'msi'):
            with self.subTest(kind=kind):
                output = self.tmp / kind
                res = subprocess.run([str(self.wins), 'extract', str(source), str(output), str(self.fake), kind], capture_output=True, text=True)
                self.assertEqual(res.returncode, 0, res.stderr)
                self.assertEqual((output/'!File').read_text(), 'table')
                self.assertIn('payloads may be external', res.stdout)

    def test_explicit_msi_rejects_other_headers_before_creating_output(self):
        source = self.tmp / 'bad.bin'
        source.write_bytes(b'not an msi')
        output = self.tmp / 'bad-output'
        res = subprocess.run([str(self.wins), 'extract', str(source), str(output), str(self.fake), 'msi'], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('NotCompound', res.stderr)
        self.assertFalse(output.exists())

    def test_real_msi_when_fixture_is_available(self):
        path = os.environ.get('WINS_REAL_MSI')
        sevenzip = os.environ.get('WINS_7ZZ')
        if not path or not sevenzip:
            self.skipTest('supply a local MSI and 7zz')
        output = self.tmp / 'real-output'
        res = subprocess.run([str(self.wins), 'extract', path, str(output), sevenzip, 'msi'], capture_output=True, text=True, timeout=120)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue((output/'!File').is_file())
        self.assertFalse((output/'.text').exists())

if __name__ == '__main__':
    unittest.main()
