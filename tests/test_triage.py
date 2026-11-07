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

    def test_notion_installer_probe(self):
        sample_path = os.path.expanduser("~/Descargas/wins-samples/Notion-Setup-7.42.3.exe")
        if not os.path.isfile(sample_path):
            self.skipTest(f"Sample binary not found: {sample_path}")

        triage = BinaryTriage(sample_path).probe()
        self.assertEqual(triage["envelope"]["type"], "nsis")
        self.assertEqual(triage["runtime"], "electron")
        self.assertEqual(triage["recommended_recipe"], "recipe_electron")

    def test_sharex_installer_probe(self):
        sample_path = os.path.expanduser("~/Descargas/wins-samples/ShareX-22.3.0-setup-x64.exe")
        if not os.path.isfile(sample_path):
            self.skipTest(f"Sample binary not found: {sample_path}")

        triage = BinaryTriage(sample_path).probe()
        self.assertEqual(triage["envelope"]["type"], "inno")
        self.assertEqual(triage["runtime"], "dotnet")
        self.assertEqual(triage["recommended_recipe"], "recipe_dotnet")

    def test_greenshot_installer_probe(self):
        sample_path = os.path.expanduser("~/Descargas/wins-samples/Greenshot-INSTALLER-1.3.328-RELEASE.exe")
        if not os.path.isfile(sample_path):
            self.skipTest(f"Sample binary not found: {sample_path}")

        triage = BinaryTriage(sample_path).probe()
        self.assertEqual(triage["envelope"]["type"], "inno")
        self.assertEqual(triage["runtime"], "dotnet_framework")
        self.assertEqual(triage["recommended_recipe"], "recipe_micro_wine")

    def test_notepad_plus_plus_installer_probe(self):
        sample_path = os.path.expanduser("~/Descargas/wins-samples/npp.8.9.9.Installer.x64.exe")
        if not os.path.isfile(sample_path):
            self.skipTest(f"Sample binary not found: {sample_path}")

        triage = BinaryTriage(sample_path).probe()
        self.assertEqual(triage["envelope"]["type"], "nsis")
        self.assertEqual(triage["runtime"], "native_pe")
        self.assertEqual(triage["recommended_recipe"], "recipe_micro_wine")

    def test_winmerge_installer_probe(self):
        sample_path = os.path.expanduser("~/Descargas/wins-samples/WinMerge-2.16.60-x64-Setup.exe")
        if not os.path.isfile(sample_path):
            self.skipTest(f"Sample binary not found: {sample_path}")

        triage = BinaryTriage(sample_path).probe()
        self.assertEqual(triage["envelope"]["type"], "inno")
        self.assertEqual(triage["runtime"], "native_pe")
        self.assertEqual(triage["recommended_recipe"], "recipe_micro_wine")

if __name__ == "__main__":
    unittest.main()
