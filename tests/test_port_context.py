#!/usr/bin/env python3
"""
WINS Test Suite - Port Context Generator Unit Tests
"""

import unittest
import os
import sys
import json
import tempfile
import shutil

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from core.port_context import PortContext, COMMAND_CORPUS, WINDOWS_PITFALLS


class TestPortContext(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix="wins-test-ctx-")
        self.install_dir = os.path.join(self.scratch, "app-desktop")
        self.bin_dir = os.path.join(self.install_dir, "resources", "bin")
        os.makedirs(self.bin_dir, exist_ok=True)
        self.skills_dir = os.path.join(self.scratch, "skills")
        self.workspace = os.path.join(self.scratch, "workspace")
        os.makedirs(self.workspace, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.scratch, ignore_errors=True)

    def _context(self, **kwargs):
        params = dict(
            app_id="manus",
            app_title="Manus",
            install_dir=self.install_dir,
            skills_dir=self.skills_dir,
            workspace=self.workspace,
        )
        params.update(kwargs)
        return PortContext(**params)

    # ---------------------------------------------------------------- render
    def test_corpus_states_linux_truth(self):
        ctx = self._context()
        body = ctx.render()
        self.assertIn("private port", body)
        self.assertIn("Windows", body)
        self.assertIn("Linux", body)
        self.assertIn("not from the operating system", body)

    def test_corpus_contains_command_corpus(self):
        body = self._context().render()
        for win, lin in COMMAND_CORPUS:
            # pipes are escaped inside table cells
            self.assertIn(win.replace("|", "\\|"), body)
            self.assertIn(lin.replace("|", "\\|"), body)

    def test_table_cells_escape_pipes(self):
        body = self._context().render()
        for line in body.splitlines():
            if line.startswith("| `") and "|" in line:
                # every table row must have exactly 4 unescaped pipes
                cells = line.replace("\\|", "").split("|")
                self.assertEqual(len(cells), 4, f"malformed table row: {line}")

    def test_corpus_lists_windows_pitfalls(self):
        body = self._context().render()
        for pitfall in WINDOWS_PITFALLS:
            self.assertIn(pitfall.split(".")[0], body)

    def test_skill_has_frontmatter(self):
        skill = self._context().render_skill()
        self.assertTrue(skill.startswith("---\n"))
        self.assertIn("name: wins-port-context", skill)
        self.assertIn("description:", skill)
        self.assertIn("---", skill)

    def test_preamble_is_one_paragraph(self):
        preamble = self._context().render_preamble()
        self.assertIn("not Windows", preamble)
        self.assertIn("command corpus", preamble.lower())

    def test_facts_detected(self):
        ctx = self._context()
        self.assertEqual(ctx.facts["os"], "Linux")
        self.assertTrue(ctx.facts["home"].startswith("/"))
        self.assertIn(ctx.facts["arch"], ("x86_64", "aarch64", "arm64"))

    # ----------------------------------------------------------------- sinks
    def test_install_writes_skill_workspace_and_install_docs(self):
        report = self._context().install()
        self.assertTrue(os.path.isfile(report["skill"]))
        self.assertTrue(os.path.isfile(report["workspace_doc"]))
        self.assertTrue(os.path.isfile(report["install_doc"]))
        self.assertIn("SKILL.md", report["skill"])
        with open(report["skill"]) as f:
            self.assertIn("name: wins-port-context", f.read())

    def test_existing_agents_md_is_never_clobbered(self):
        agents = os.path.join(self.workspace, "AGENTS.md")
        with open(agents, "w") as f:
            f.write("# existing contract\n")
        report = self._context().install()
        with open(agents) as f:
            self.assertEqual(f.read(), "# existing contract\n")
        self.assertTrue(report["workspace_doc"].endswith("WINS-PORT.md"))

    def test_agents_md_written_when_absent(self):
        report = self._context().install()
        self.assertTrue(report["workspace_doc"].endswith("AGENTS.md"))

    def test_companions_listed_from_install_dir(self):
        with open(os.path.join(self.bin_dir, "manus-computer-operator.exe"), "wb") as f:
            f.write(b"MZ\x90\x00")
        body = self._context().render()
        self.assertIn("manus-computer-operator.exe", body)

    def test_json_serialisable_report(self):
        report = self._context().install()
        json.dumps(report)


if __name__ == "__main__":
    unittest.main()
