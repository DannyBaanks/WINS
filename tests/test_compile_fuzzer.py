"""
Tests for WINS Autonomous E2E Compilation & Shim Synthesis Fuzzer
"""

import os
import sys
import unittest
import tempfile
import json
import subprocess

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from core.transpiler.compile_fuzzer import CompileFuzzer

class TestCompileFuzzer(unittest.TestCase):
    def test_compile_fuzzer_synthetic_apis(self):
        target_apis = {
            "KERNEL32.dll": [
                "CreateFileW", "ReadFile", "WriteFile", "CloseHandle",
                "GetLastError", "SetLastError", "GetFullPathNameW"
            ],
            "ADVAPI32.dll": [
                "RegOpenKeyExW", "RegCloseKey"
            ],
            "CUSTOM.dll": [
                "NonExistentWin32ApiAlpha", "NonExistentWin32ApiBeta"
            ]
        }

        with tempfile.TemporaryDirectory(prefix="wins-test-cf-") as tmp_dir:
            out_so = os.path.join(tmp_dir, "test_shim.so")
            fuzzer = CompileFuzzer(target_apis=target_apis, out_so=out_so, max_iterations=5)
            report = fuzzer.fuzz()

            self.assertEqual(report["status"], "COMPILE_FUZZ_PASSED")
            self.assertTrue(os.path.isfile(out_so))
            self.assertGreater(report["so_size_bytes"], 0)
            self.assertEqual(report["target_apis_count"], 11)

            # Check dynamic in-memory fuzz validation
            val = report["validation"]
            self.assertTrue(val["loaded"])
            self.assertEqual(val["symbols_verified"], 11)
            self.assertEqual(val["symbols_failed"], 0)
            self.assertEqual(val["dynamic_fuzz_passed"], 11)

    def test_compile_fuzzer_autonomous_mutation(self):
        # Include functions that conflict with Linux libc (memcpy, memset, exit)
        target_apis = {
            "VCRUNTIME140.dll": ["memcpy", "memset"],
            "MSVCRT.dll": ["_exit", "exit"],
            "KERNEL32.dll": ["CreateFileW", "CloseHandle"]
        }

        with tempfile.TemporaryDirectory(prefix="wins-test-mut-") as tmp_dir:
            out_so = os.path.join(tmp_dir, "test_mut.so")
            fuzzer = CompileFuzzer(target_apis=target_apis, out_so=out_so, max_iterations=10)
            report = fuzzer.fuzz()

            self.assertEqual(report["status"], "COMPILE_FUZZ_PASSED")
            # Should have required at least 2 iterations to auto-resolve libc conflicts
            self.assertGreaterEqual(report["iterations_executed"], 2)
            self.assertGreater(report["mutations_applied"], 0)
            self.assertTrue(os.path.isfile(out_so))

    def test_compile_fuzzer_on_pe_binary(self):
        sample_pe = "/tmp/npp_probe/notepad++.exe"
        if not os.path.isfile(sample_pe):
            self.skipTest("Sample PE binary notepad++.exe not found")

        with tempfile.TemporaryDirectory(prefix="wins-test-pe-") as tmp_dir:
            out_so = os.path.join(tmp_dir, "npp_shim.so")
            fuzzer = CompileFuzzer(target_binary=sample_pe, out_so=out_so, max_iterations=10)
            report = fuzzer.fuzz()

            self.assertEqual(report["status"], "COMPILE_FUZZ_PASSED")
            self.assertTrue(os.path.isfile(out_so))
            self.assertGreater(report["target_apis_count"], 500)
            self.assertGreater(report["validation"]["symbols_verified"], 500)

    def test_compile_fuzzer_cli(self):
        sample_pe = "/tmp/npp_probe/notepad++.exe"
        if not os.path.isfile(sample_pe):
            self.skipTest("Sample PE binary notepad++.exe not found")

        wins_bin = os.path.join(REPO_ROOT, "bin", "wins")
        cmd = [sys.executable, wins_bin, "compile-fuzz", sample_pe, "--json"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 1)
        self.assertIn("Legacy compile-fuzz disabled", res.stderr)

if __name__ == "__main__":
    unittest.main()
