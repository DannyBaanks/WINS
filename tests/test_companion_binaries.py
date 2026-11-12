#!/usr/bin/env python3
"""
WINS Test Suite - Companion Binary Healer Unit Tests
"""

import unittest
import os
import sys
import json
import tempfile
import shutil
import subprocess

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from core.healers.companion_binaries import CompanionBinaryHealer

PE_HEADER = b"MZ\x90\x00\x03\x00\x00\x00"
ELF_HEADER = b"\x7fELF\x02\x01\x01\x00"


class TestCompanionBinaryHealer(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix="wins-test-companion-")
        self.bin_dir = os.path.join(self.scratch, "resources", "bin")
        os.makedirs(self.bin_dir, exist_ok=True)
        self.healer = CompanionBinaryHealer(
            cache_dir=os.path.join(self.scratch, "cache"),
            manifest_paths=[],
        )

    def tearDown(self):
        shutil.rmtree(self.scratch, ignore_errors=True)

    def _write_pe(self, name):
        path = os.path.join(self.bin_dir, name)
        with open(path, "wb") as f:
            f.write(PE_HEADER + b"\x00" * 64)
        return path

    def _write_elf(self, path, executable=True):
        with open(path, "wb") as f:
            f.write(ELF_HEADER + b"\x00" * 64)
        if executable:
            os.chmod(path, 0o755)
        return path

    # ------------------------------------------------------------ detection
    def test_host_name_strips_exe_suffix(self):
        self.assertEqual(self.healer.host_name("/x/manus-computer-operator.exe"),
                         "manus-computer-operator")

    def test_finds_only_pe_companions(self):
        self._write_pe("agent.exe")
        self._write_pe("sidecar.exe")
        with open(os.path.join(self.bin_dir, "notes.txt"), "w") as f:
            f.write("not a binary")
        found = self.healer.find_companion_exes(self.bin_dir)
        self.assertEqual(len(found), 2)
        self.assertTrue(all(f.endswith(".exe") for f in found))

    def test_locate_bin_dir_from_install_root(self):
        self._write_pe("agent.exe")
        located = self.healer.locate_bin_dir(os.path.join(self.scratch, "resources"))
        self.assertEqual(os.path.realpath(located), os.path.realpath(self.bin_dir))

    # -------------------------------------------------------- native healing
    def test_native_elf_from_cache_is_installed(self):
        self._write_pe("agent.exe")
        cache_dir = os.path.join(self.healer.cache_dir, "myapp")
        os.makedirs(cache_dir, exist_ok=True)
        self._write_elf(os.path.join(cache_dir, "agent.linux-x64"))

        report = self.healer.heal(os.path.join(self.scratch, "resources"), app_id="myapp")

        self.assertEqual(report["scanned"], 1)
        self.assertEqual(len(report["healed_native"]), 1)
        host = os.path.join(self.bin_dir, "agent")
        self.assertTrue(os.path.isfile(host))
        self.assertTrue(self.healer.is_elf(host))
        self.assertTrue(os.access(host, os.X_OK))
        # the original PE stays untouched
        self.assertTrue(self.healer.is_pe(os.path.join(self.bin_dir, "agent.exe")))

    def test_native_elf_from_manifest(self):
        self._write_pe("agent.exe")
        native_elf = os.path.join(self.scratch, "agent-linux")
        self._write_elf(native_elf)

        manifest = os.path.join(self.scratch, "manifest.json")
        with open(manifest, "w") as f:
            json.dump({
                "apps": {
                    "myapp": {
                        "linux_package": {
                            "url": "file://" + native_elf,
                            "kind": "raw",
                        },
                        "binaries": {"agent": "agent"},
                    }
                }
            }, f)

        healer = CompanionBinaryHealer(
            cache_dir=os.path.join(self.scratch, "cache"),
            manifest_paths=[manifest],
        )
        report = healer.heal(os.path.join(self.scratch, "resources"), app_id="myapp")

        self.assertEqual(len(report["healed_native"]), 1)
        host = os.path.join(self.bin_dir, "agent")
        self.assertTrue(healer.is_elf(host))
        self.assertEqual(len(report["wine_shimmed"]), 0)

    def test_already_native_helper_is_skipped(self):
        self._write_pe("agent.exe")
        self._write_elf(os.path.join(self.bin_dir, "agent"))

        report = self.healer.heal(os.path.join(self.scratch, "resources"), app_id="myapp")

        self.assertEqual(len(report["already_native"]), 1)
        self.assertEqual(len(report["healed_native"]), 0)
        self.assertEqual(len(report["wine_shimmed"]), 0)

    # ----------------------------------------------------------- wine shim
    def test_wine_shim_generated_when_no_native_build(self):
        self._write_pe("agent.exe")

        report = self.healer.heal(os.path.join(self.scratch, "resources"), app_id="myapp")

        self.assertEqual(len(report["wine_shimmed"]), 1)
        host = os.path.join(self.bin_dir, "agent")
        self.assertTrue(os.path.isfile(host))
        self.assertTrue(os.access(host, os.X_OK))
        with open(host) as f:
            content = f.read()
        self.assertIn("WINS companion shim for agent", content)
        self.assertIn("MANUS_OPERATOR_LOCAL_API_FD", content)
        self.assertIn("PARENT_PID", content)
        self.assertIn("exec wine", content)
        # bridge helper is materialised next to the shim
        self.assertTrue(os.path.isfile(os.path.join(self.bin_dir, ".wins-bridge-agent.js")))

    def test_existing_launcher_is_backed_up_before_replacement(self):
        self._write_pe("agent.exe")
        host = os.path.join(self.bin_dir, "agent")
        with open(host, "w") as f:
            f.write("#!/bin/sh\n# hand written\n")

        self.healer.heal(os.path.join(self.scratch, "resources"), app_id="myapp")

        self.assertTrue(os.path.isfile(host + ".wins-prev"))
        with open(host + ".wins-prev") as f:
            self.assertIn("hand written", f.read())

    def test_wine_fallback_can_be_disabled(self):
        self._write_pe("agent.exe")

        report = self.healer.heal(os.path.join(self.scratch, "resources"), app_id="myapp",
                                  allow_wine_fallback=False)

        self.assertEqual(len(report["wine_shimmed"]), 0)
        self.assertEqual(len(report["errors"]), 1)
        self.assertFalse(os.path.exists(os.path.join(self.bin_dir, "agent")))

    def test_shim_is_valid_bash(self):
        self._write_pe("agent.exe")
        self.healer.heal(os.path.join(self.scratch, "resources"), app_id="myapp")
        host = os.path.join(self.bin_dir, "agent")
        res = os.system(f"bash -n '{host}'")
        self.assertEqual(res, 0, "generated shim must be syntactically valid bash")

    def test_shim_sanitizes_unsupported_native_runtime_mode(self):
        self._write_pe("agent.exe")
        self.healer.heal(os.path.join(self.scratch, "resources"), app_id="myapp")
        host = os.path.join(self.bin_dir, "agent")
        with open(host) as f:
            content = f.read()
        self.assertIn("MANUS_OPERATOR_NATIVE_RUNTIME", content)
        self.assertIn('!= "off"', content)

    def test_shim_survives_unset_path_variables(self):
        """`set -u` plus indirect expansion must not abort on unset variables."""
        self._write_pe("agent.exe")
        self.healer.heal(os.path.join(self.scratch, "resources"), app_id="myapp")
        host = os.path.join(self.bin_dir, "agent")
        # The shim would exec wine; stub wine and winepath out and assert it
        # gets past the path-conversion stage instead of dying on an unset
        # variable.
        stub_dir = os.path.join(self.scratch, "stub")
        os.makedirs(stub_dir, exist_ok=True)
        for tool in ("wine", "winepath"):
            stub = os.path.join(stub_dir, tool)
            with open(stub, "w") as f:
                f.write("#!/bin/sh\nexit 0\n")
            os.chmod(stub, 0o755)
        res = os.system(
            f"env -i PATH={stub_dir}:/usr/bin:/bin HOME={self.scratch} bash '{host}' start 2>&1 "
            f"| grep -q 'variable sin asignar'"
        )
        self.assertNotEqual(res, 0, "shim must not fail on unset variables")

    def test_bridge_helper_is_refreshed_when_content_changes(self):
        self._write_pe("agent.exe")
        self.healer.heal(os.path.join(self.scratch, "resources"), app_id="myapp")
        bridge = os.path.join(self.bin_dir, ".wins-bridge-agent.js")
        with open(bridge, "w") as f:
            f.write("// stale\n")
        self.healer.heal(os.path.join(self.scratch, "resources"), app_id="myapp")
        with open(bridge) as f:
            content = f.read()
        self.assertIn("MANUS_BRIDGE_PIPE", content)
        self.assertNotEqual(content, "// stale\n")



    def test_bridge_javascript_is_syntactically_valid(self):
        """The generated bridge must parse (a syntax error kills the operator)."""
        self._write_pe("agent.exe")
        self.healer.heal(os.path.join(self.scratch, "resources"), app_id="myapp")
        bridge = os.path.join(self.bin_dir, ".wins-bridge-agent.js")
        with open(bridge) as f:
            source = f.read()
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        res = subprocess.run([node, "--check", bridge], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr[:400])

    def test_bridge_has_no_duplicate_declarations(self):
        self._write_pe("agent.exe")
        self.healer.heal(os.path.join(self.scratch, "resources"), app_id="myapp")
        bridge = os.path.join(self.bin_dir, ".wins-bridge-agent.js")
        with open(bridge) as f:
            source = f.read()
        self.assertEqual(source.count("let connected = false;"), 1)
        self.assertEqual(source.count("const startedAt = Date.now();"), 1)

    def test_bridge_idle_timeout_only_before_connection(self):
        """An unconditional timer used to kill the bridge (and the operator)."""
        self._write_pe("agent.exe")
        self.healer.heal(os.path.join(self.scratch, "resources"), app_id="myapp")
        bridge = os.path.join(self.bin_dir, ".wins-bridge-agent.js")
        with open(bridge) as f:
            source = f.read()
        self.assertNotIn("setTimeout(() => die(0), 120000)", source)
        self.assertIn("if (connected)", source)


    def test_bridge_translates_paths_in_both_directions(self):
        """The desktop speaks POSIX, the operator speaks drive letters."""
        self._write_pe("agent.exe")
        self.healer.heal(os.path.join(self.scratch, "resources"), app_id="myapp")
        bridge = os.path.join(self.bin_dir, ".wins-bridge-agent.js")
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        script = (
            "const m = require(process.argv[1]);"
            "const out = {"
            "  op: m.toOperatorPath('/home/danny/x'),"
            "  host: m.toHostPath('Z:\\\\home\\\\danny'),"
            "  home: m.toHostPath('C:\\\\users\\\\danny'),"
            "  url: m.toHostPath('https://api.manus.im/x'),"
            "  in: JSON.parse(m.rewriteLine(JSON.stringify({params:{directory:{absolutePath:'/home/danny'}}}), true)).params.directory.absolutePath,"
            "  out: JSON.parse(m.rewriteLine(JSON.stringify({result:{roots:[{path:'Z:\\\\home\\\\danny'}]}}), false)).result.roots[0].path"
            "};"
            "process.stdout.write(JSON.stringify(out));"
        )
        res = subprocess.run([node, "-e", script, bridge], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr[:400])
        data = json.loads(res.stdout)
        self.assertEqual(data["op"], "Z:/home/danny/x")
        self.assertEqual(data["host"], "/home/danny")
        self.assertEqual(data["home"], "/home/danny")
        self.assertEqual(data["url"], "https://api.manus.im/x")
        self.assertEqual(data["in"], "Z:/home/danny")
        self.assertEqual(data["out"], "/home/danny")

if __name__ == "__main__":
    unittest.main()
