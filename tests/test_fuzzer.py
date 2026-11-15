"""
Tests for WINS Zig Differential Fuzzer Engine
"""

import os
import sys
import unittest
import subprocess
import json

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FUZZER_BIN = os.path.join(REPO_ROOT, "bin", "wins-fuzz")
WINS_CLI = os.path.join(REPO_ROOT, "bin", "wins")

class TestDifferentialFuzzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ensure wins-fuzz is compiled
        if not os.path.isfile(FUZZER_BIN) or not os.access(FUZZER_BIN, os.X_OK):
            cmd = ["zig", "build-exe", "-O", "ReleaseFast", "core/fuzzer/src/main.zig", f"-femit-bin={FUZZER_BIN}"]
            subprocess.run(cmd, cwd=REPO_ROOT, check=True)

    def test_fuzzer_path_suite(self):
        cmd = [FUZZER_BIN, "--suite", "path", "--iterations", "10000", "--json"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(res.stdout)
        self.assertEqual(data["status"], "EQUIVALENCE_PROVEN")
        self.assertEqual(data["total_divergences"], 0)
        self.assertEqual(data["suites"]["path_normalization"]["divergences"], 0)
        self.assertEqual(data["suites"]["path_normalization"]["iterations"], 10000)

    def test_fuzzer_encoding_suite(self):
        cmd = [FUZZER_BIN, "--suite", "encoding", "--iterations", "10000", "--json"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(res.stdout)
        self.assertEqual(data["status"], "EQUIVALENCE_PROVEN")
        self.assertEqual(data["total_divergences"], 0)
        self.assertEqual(data["suites"]["utf16_utf8_transcoding"]["divergences"], 0)
        self.assertGreater(data["suites"]["utf16_utf8_transcoding"]["transcoded_bytes"], 10000)

    def test_fuzzer_registry_suite(self):
        cmd = [FUZZER_BIN, "--suite", "registry", "--iterations", "10000", "--json"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(res.stdout)
        self.assertEqual(data["status"], "EQUIVALENCE_PROVEN")
        self.assertEqual(data["total_divergences"], 0)
        self.assertEqual(data["suites"]["virtual_registry"]["divergences"], 0)

    def test_fuzzer_pixel_suite(self):
        cmd = [FUZZER_BIN, "--suite", "pixel", "--iterations", "15000", "--json"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(res.stdout)
        self.assertEqual(data["status"], "EQUIVALENCE_PROVEN")
        self.assertEqual(data["total_divergences"], 0)
        self.assertEqual(data["suites"]["pixel_graphics_math"]["divergences"], 0)
        self.assertEqual(data["suites"]["pixel_graphics_math"]["iterations"], 15000)
        self.assertGreater(data["ops_per_sec"], 1_000_000)

    def test_fuzzer_security_suite(self):
        cmd = [FUZZER_BIN, "--suite", "security", "--iterations", "15000", "--json"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(res.stdout)
        self.assertEqual(data["status"], "EQUIVALENCE_PROVEN")
        self.assertEqual(data["total_divergences"], 0)
        self.assertEqual(data["suites"]["path_security_anomalies"]["divergences"], 0)
        self.assertGreater(data["suites"]["path_security_anomalies"]["dos_devices_caught"], 100)
        self.assertGreater(data["suites"]["path_security_anomalies"]["ads_streams_caught"], 100)

    def test_fuzzer_buffer_suite(self):
        cmd = [FUZZER_BIN, "--suite", "buffer", "--iterations", "15000", "--json"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(res.stdout)
        self.assertEqual(data["status"], "EQUIVALENCE_PROVEN")
        self.assertEqual(data["total_divergences"], 0)
        self.assertEqual(data["suites"]["scintilla_text_buffer"]["divergences"], 0)
        self.assertGreater(data["suites"]["scintilla_text_buffer"]["lines_indexed"], 50000)
        self.assertGreater(data["suites"]["scintilla_text_buffer"]["multibyte_queries"], 1000)

    def test_fuzzer_all_suites_performance(self):
        cmd = [FUZZER_BIN, "--suite", "all", "--iterations", "25000", "--json"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(res.stdout)
        self.assertEqual(data["status"], "EQUIVALENCE_PROVEN")
        self.assertEqual(data["total_iterations"], 150000)
        self.assertGreater(data["ops_per_sec"], 500_000)  # Must be high-throughput

    def test_wins_cli_fuzz_integration(self):
        cmd = [sys.executable, WINS_CLI, "fuzz", "--suite", "pixel", "--iterations", "5000", "--json"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(res.stdout)
        self.assertEqual(data["status"], "EQUIVALENCE_PROVEN")
        self.assertEqual(data["suites"]["pixel_graphics_math"]["iterations"], 5000)

if __name__ == "__main__":
    unittest.main()
