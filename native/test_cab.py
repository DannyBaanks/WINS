"""CAB metadata regression tests; no copyrighted samples are required."""
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

def fixture():
    data = bytearray(96)
    struct.pack_into('<4sIIIII BB HHHHH', data, 0, b'MSCF', 0, 256, 0, 44, 0, 3, 1, 1, 1, 0, 0, 0)
    struct.pack_into('<IHH', data, 36, 128, 1, 1)
    struct.pack_into('<IIHHHH', data, 44, 42, 7, 0, 0, 0, 0)
    data[60:69] = b'file.bin\0'
    return data

class CabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix='wins-cab-test-'))
        cls.exe = Path(os.environ.get('WINS_CAB_RUNNER', cls.tmp/'wins'))
        if 'WINS_CAB_RUNNER' not in os.environ:
            subprocess.run(['zig', 'build-exe', str(ROOT/'native/main.zig'), '-O', 'ReleaseSafe', f'-femit-bin={cls.exe}'], check=True)

    def run_cab(self, data, name='file.bin'):
        target = self.tmp/'fixture.cab'
        target.write_bytes(data)
        return subprocess.run([str(self.exe), 'cab-find', str(target), name, '--json'], capture_output=True, text=True)

    def test_finds_member_without_claiming_cab_is_complete(self):
        r = self.run_cab(fixture())
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(doc['input_length'], 96)
        self.assertEqual(doc['cabinet']['cabinet_declared_bytes'], 256)
        self.assertEqual(doc['cabinet']['folder_data_offset'], 128)
        self.assertEqual(doc['cabinet']['offset_in_uncompressed_folder'], 7)
        self.assertEqual(doc['cabinet']['uncompressed_size'], 42)
        self.assertEqual(doc['cabinet']['compression'], 'MSZIP')
        self.assertEqual(doc['cabinet']['integrity'], 'NOT_VERIFIED')

    def test_truncation_missing_and_invalid_folder_fail(self):
        bad = fixture(); struct.pack_into('<H', bad, 52, 4)
        for data, name in ((fixture()[:55], 'file.bin'), (bad, 'file.bin'), (fixture(), 'missing')):
            r = self.run_cab(data, name)
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(r.stdout, '')

    def test_rejects_multivolume_and_folder_offset_past_declared_size(self):
        multi=fixture(); struct.pack_into('<H', multi, 30, 1)
        bad=fixture(); struct.pack_into('<I', bad, 36, 256)
        for data in (multi, bad):
            r = self.run_cab(data)
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(r.stdout, '')

    def test_mutations_and_truncation_never_crash(self):
        rng = random.Random(0x434142)
        for i in range(150):
            data = fixture()
            if i < 50:
                del data[rng.randrange(len(data)):]
            else:
                for _ in range(1+rng.randrange(5)):
                    data[rng.randrange(len(data))] = rng.randrange(256)
            r = self.run_cab(data)
            self.assertGreaterEqual(r.returncode, 0, r.stderr)
            if r.returncode == 0: json.loads(r.stdout)
            else: self.assertEqual(r.stdout, '')

    def test_optional_real_cab_index(self):
        sample = os.environ.get('WINS_CAB_SAMPLE')
        if not sample: self.skipTest('supply local partial CAB')
        r = subprocess.run([str(self.exe), 'cab-find', sample, 'fil965675F3D3F24E86CBB33BA5F0DD4753', '--json'], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads(r.stdout)['cabinet']
        self.assertEqual(doc['uncompressed_size'], 11970840)
        self.assertEqual(doc['folder_data_offset'], 841987311)
        self.assertEqual(doc['integrity'], 'NOT_VERIFIED')

if __name__ == '__main__': unittest.main()
