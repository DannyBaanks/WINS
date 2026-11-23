"""Regression coverage for the Velopack/Squirrel overlay support.

The synthetic case builds a host file with a ZIP appended, exactly the shape
of a Velopack `Setup.exe`, so the test does not depend on any installer being
present on the machine. The real-installer case is skipped when the sample is
absent.
"""
import json
import os
import struct
import subprocess
import sys
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.velopack import (  # noqa: E402
    find_zip_overlay,
    nuspec_metadata,
    overlay_entries,
    read_overlay_entry,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = os.path.expanduser("~/Descargas/LuaTools-win-Setup.exe")
NUSPEC = """<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
<metadata>
<id>LuaTools</id>
<version>1.3.3</version>
<channel>win</channel>
<rid>win-x64</rid>
<os>win</os>
<mainExe>LuaTools.exe</mainExe>
<runtimeDependencies>net8-x64-desktop</runtimeDependencies>
</metadata>
</package>
"""


def build_host_with_zip(path, members):
    """Write a fake host image followed by a ZIP archive."""
    payload = open(path, "wb")
    payload.write(b"MZ" + b"\x00" * 4094)
    payload.close()
    with open(path, "ab") as handle:
        import io

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in members.items():
                archive.writestr(name, data)
        handle.write(buffer.getvalue())


class TestVelopackOverlay(unittest.TestCase):
    def test_finds_overlay_on_synthetic_host(self):
        host = "/tmp/wins-test-velopack-synthetic.exe"
        build_host_with_zip(host, {"App.nuspec": NUSPEC, "lib/app/App.dll": b"MZ managed"})
        try:
            overlay = find_zip_overlay(host)
            self.assertIsNotNone(overlay)
            self.assertGreater(overlay["archive_offset"], 4094)
            self.assertEqual(2, overlay["entry_count"])
            names = overlay_entries(host, overlay)
            self.assertIn("lib/app/App.dll", names)
            self.assertEqual(b"MZ managed", read_overlay_entry(host, overlay, "lib/app/App.dll"))
            meta = nuspec_metadata(host, overlay)
            self.assertEqual("LuaTools", meta["id"])
            self.assertEqual("1.3.3", meta["version"])
            self.assertEqual("net8-x64-desktop", meta["runtimeDependencies"])
        finally:
            if os.path.exists(host):
                os.remove(host)

    def test_ignores_file_without_archive(self):
        host = "/tmp/wins-test-velopack-empty.exe"
        with open(host, "wb") as handle:
            handle.write(b"MZ" + b"\x00" * 2048)
        try:
            self.assertIsNone(find_zip_overlay(host))
        finally:
            os.remove(host)

    @unittest.skipUnless(os.path.isfile(SAMPLE), "LuaTools installer not present")
    def test_real_installer_overlay(self):
        overlay = find_zip_overlay(SAMPLE)
        self.assertIsNotNone(overlay)
        self.assertEqual(83, overlay["entry_count"])
        meta = nuspec_metadata(SAMPLE, overlay)
        self.assertEqual("LuaTools", meta["id"])
        self.assertEqual("win-x64", meta["rid"])
        names = overlay_entries(SAMPLE, overlay)
        self.assertIn("lib/app/LuaTools.dll", names)
        self.assertIn("lib/app/LuaTools.runtimeconfig.json", names)

    @unittest.skipUnless(os.path.isfile(SAMPLE), "LuaTools installer not present")
    def test_triage_reports_velopack_envelope(self):
        from core.triage import BinaryTriage

        triage = BinaryTriage(SAMPLE).probe()
        self.assertEqual("velopack", triage["envelope"]["type"])
        self.assertEqual("dotnet", triage["runtime"])
        self.assertIn("WindowsDesktop", triage["runtime_details"]["framework"])
        self.assertIn("REQUIRES_UI_REWRITE", triage["feasibility"])

    @unittest.skipUnless(os.path.isfile(SAMPLE), "LuaTools installer not present")
    def test_native_tool_matches_python_extraction(self):
        binary = os.path.join(REPO_ROOT, "build", "wins-native")
        if not os.path.isfile(binary):
            self.skipTest("wins-native not built")
        out = "/tmp/wins-test-velopack-native"
        subprocess.run(
            [binary, "velopack-extract", SAMPLE, out],
            check=True,
            capture_output=True,
            timeout=120,
        )
        try:
            with open(os.path.join(out, "LuaTools.nuspec"), "rb") as handle:
                self.assertIn(b"<id>LuaTools</id>", handle.read())
            self.assertTrue(os.path.isfile(os.path.join(out, "lib", "app", "LuaTools.dll")))
        finally:
            subprocess.run(["rm", "-rf", out], check=False)


if __name__ == "__main__":
    unittest.main()
