#!/usr/bin/env python3
"""
WINS Test Suite - Cleanroom Tester Unit Tests
"""

import unittest
import os
import sys
import tempfile
import shutil

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from core.tester import CleanroomTester

class TestCleanroomTester(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix="wins-test-tester-")

    def tearDown(self):
        shutil.rmtree(self.scratch, ignore_errors=True)

    def test_nonexistent_target(self):
        tester = CleanroomTester("/path/to/nonexistent/app")
        report = tester.execute()
        self.assertEqual(report["status"], "ERROR_NOT_FOUND")

    def test_clean_exit_target(self):
        script_path = os.path.join(self.scratch, "quick_app.sh")
        with open(script_path, "w") as f:
            f.write("#!/bin/sh\necho 'Quick run'\nexit 0\n")
        os.chmod(script_path, 0o755)

        tester = CleanroomTester(script_path, timeout=2.0)
        report = tester.execute()
        self.assertEqual(report["status"], "CLEAN_EXIT")
        self.assertEqual(report["exit_code"], 0)

    def test_timeout_and_healthy_signal(self):
        script_path = os.path.join(self.scratch, "daemon_app.sh")
        with open(script_path, "w") as f:
            f.write("#!/bin/sh\necho 'App starting with version 1.0.0'\nsleep 5\n")
        os.chmod(script_path, 0o755)

        tester = CleanroomTester(script_path, timeout=1.0)
        report = tester.execute()
        self.assertEqual(report["status"], "HEALTHY_RUNNING")
        self.assertTrue(report["timed_out"])

    def test_critical_anomaly_detection(self):
        script_path = os.path.join(self.scratch, "crashing_app.sh")
        with open(script_path, "w") as f:
            f.write("#!/bin/sh\necho 'Error: something.node: cabecera ELF inválida' >&2\nexit 1\n")
        os.chmod(script_path, 0o755)

        tester = CleanroomTester(script_path, timeout=2.0)
        report = tester.execute()
        self.assertEqual(report["status"], "CRITICAL_ANOMALIES_DETECTED")
        self.assertTrue(len(report["anomalies"]) > 0)
        self.assertEqual(report["anomalies"][0]["type"], "WINDOWS_PE_DLOPEN_FAILURE")

if __name__ == "__main__":
    unittest.main()
