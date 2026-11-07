#!/usr/bin/env python3
"""
WINS Test Suite - Native Module Healer Unit Tests
"""

import unittest
import os
import sys
import tempfile
import shutil

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from core.healers.native_modules import NativeModuleHealer

class TestNativeModuleHealer(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix="wins-test-healer-")
        self.healer = NativeModuleHealer()

    def tearDown(self):
        shutil.rmtree(self.scratch, ignore_errors=True)

    def test_pe_vs_elf_detection(self):
        pe_file = os.path.join(self.scratch, "mock_win.node")
        with open(pe_file, "wb") as f:
            f.write(b"MZ\x90\x00\x03\x00\x00\x00")

        elf_file = os.path.join(self.scratch, "mock_linux.node")
        with open(elf_file, "wb") as f:
            f.write(b"\x7fELF\x02\x01\x01\x00")

        self.assertTrue(NativeModuleHealer.is_pe(pe_file))
        self.assertFalse(NativeModuleHealer.is_elf(pe_file))

        self.assertTrue(NativeModuleHealer.is_elf(elf_file))
        self.assertFalse(NativeModuleHealer.is_pe(elf_file))

    def test_universal_stub_generation(self):
        pkg_dir = os.path.join(self.scratch, "node_modules", "cf-prefs")
        os.makedirs(pkg_dir, exist_ok=True)
        with open(os.path.join(pkg_dir, "package.json"), "w") as f:
            f.write('{"name": "cf-prefs", "main": "index.js"}')

        self.healer.stub_windows_package("cf-prefs", pkg_dir)

        index_js = os.path.join(pkg_dir, "index.js")
        self.assertTrue(os.path.isfile(index_js))
        with open(index_js) as f:
            content = f.read()
        self.assertIn("WINS Polyfill: cf-prefs", content)
        self.assertIn("getPreferenceValue", content)

    def test_generic_proxy_stub_generation(self):
        pkg_dir = os.path.join(self.scratch, "node_modules", "@company", "arbitrary-hook")
        os.makedirs(pkg_dir, exist_ok=True)
        with open(os.path.join(pkg_dir, "package.json"), "w") as f:
            f.write('{"name": "@company/arbitrary-hook", "main": "dist/main.js"}')

        self.healer.stub_windows_package("@company/arbitrary-hook", pkg_dir)

        dist_main = os.path.join(pkg_dir, "dist", "main.js")
        self.assertTrue(os.path.isfile(dist_main))
        with open(dist_main) as f:
            content = f.read()
        self.assertIn("WINS Universal Safe Proxy Stub", content)
        self.assertIn("Proxy", content)

if __name__ == "__main__":
    unittest.main()
