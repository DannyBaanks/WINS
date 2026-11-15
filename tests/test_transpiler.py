"""
Tests for WINS Transpiler Recipe
"""

import os
import unittest
import tempfile
import json
from core.recipes.transpiler import TranspilerRecipe
from core.triage import BinaryTriage

class TestTranspilerRecipe(unittest.TestCase):
    def test_can_handle(self):
        recipe = TranspilerRecipe()
        self.assertTrue(recipe.can_handle({"runtime": "native_pe"}))
        self.assertTrue(recipe.can_handle({"recommended_recipe": "recipe_transpiler"}))
        self.assertFalse(recipe.can_handle({"runtime": "electron"}))
        self.assertFalse(recipe.can_handle({"runtime": "dotnet"}))

    def test_transmute_notepad(self):
        sample_path = os.path.expanduser("~/Descargas/wins-samples/npp.8.9.9.Installer.x64.exe")
        if not os.path.isfile(sample_path):
            self.skipTest("Notepad++ sample installer not found.")

        triage = BinaryTriage(sample_path).probe()
        recipe = TranspilerRecipe()
        self.assertTrue(recipe.can_handle(triage))

        with tempfile.TemporaryDirectory(prefix="wins-test-npp-") as tmp_dest:
            with tempfile.TemporaryDirectory(prefix="wins-test-bin-") as tmp_bin:
                dest = os.path.join(tmp_dest, "analysis")
                success = recipe.transmute(triage, dest, {"bin_dir": tmp_bin})
                self.assertFalse(success)

                # Check manifest
                manifest_path = os.path.join(dest, "wins_harvest_manifest.json")
                self.assertTrue(os.path.isfile(manifest_path))
                with open(manifest_path, "r", encoding="utf-8") as f:
                    manifest = json.load(f)
                self.assertEqual(manifest["binary"]["name"], "notepad++.exe")
                self.assertGreater(len(manifest["embedded_libraries"]), 0)

                # Check launcher
                launcher_path = os.path.join(tmp_bin, "notepadpp")
                self.assertFalse(os.path.exists(launcher_path))

if __name__ == "__main__":
    unittest.main()
