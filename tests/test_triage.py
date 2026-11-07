#!/usr/bin/env python3
"""
WINS Test Suite - Triage Engine Unit Tests
"""

import unittest
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from core.triage import BinaryTriage

class TestBinaryTriage(unittest.TestCase):
    def test_qwen_installer_probe(self):
        sample_path = os.path.expanduser("~/Descargas/Qwen-1.0.3.44-release-win-x64.exe")
        if not os.path.isfile(sample_path):
            self.skipTest(f"Sample binary not found: {sample_path}")

        triage = BinaryTriage(sample_path).probe()
        self.assertEqual(triage["envelope"]["type"], "nsis")
        self.assertEqual(triage["runtime"], "electron")
        self.assertEqual(triage["recommended_recipe"], "recipe_electron")
        self.assertTrue(triage["runtime_details"]["contains_asar"])

if __name__ == "__main__":
    unittest.main()
