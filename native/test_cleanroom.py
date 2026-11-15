"""Integration oracle for the native WINS cleanroom (no Wine)."""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class CleanroomTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="wins-native-test-"))
        zig_exe = pathlib.Path(shutil.which("zig")).resolve()
        cls.zig_dir = zig_exe.parent
        cls.wins = cls.tmp / "wins"
        cls.runner = cls.tmp / "runner"
        for src, dest, extra in [("main.zig", cls.wins, []), ("compare.zig", cls.runner, ["-lc"])]:
            subprocess.run([str(zig_exe), "build-exe", str(ROOT / "native" / src), "-O", "ReleaseSafe", *extra, f"-femit-bin={dest}"], check=True)

    def run_wins(self, *args):
        return subprocess.run([str(self.wins), *map(str, args)], text=True, capture_output=True)

    def test_rejects_invalid_pe(self):
        bad = self.tmp / "invalid.exe"
        bad.write_bytes(b"MZ" + bytes(100))
        result = self.run_wins("inspect", bad)
        self.assertNotEqual(result.returncode, 0)

    def test_compiler_fuzzer_and_overwrite_guard(self):
        outputs = []
        for name in ("candidate", "oracle", "wrong"):
            output = self.tmp / name
            result = self.run_wins("compile-c", ROOT / "native" / "examples" / (name + ".c"), output, self.zig_dir)
            self.assertEqual(result.returncode, 0, result.stderr)
            outputs.append(output / "candidate.so")
        good = self.run_wins("compare", outputs[0], outputs[1], self.runner, "10000")
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertIn("MATCHED samples=10000", good.stdout)
        bad = self.run_wins("compare", outputs[2], outputs[1], self.runner, "10000")
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("DIVERGENCE iteration=0 input=0", bad.stdout)
        before = outputs[0].read_bytes()
        again = self.run_wins("compile-c", ROOT / "native" / "examples" / "wrong.c", outputs[0].parent, self.zig_dir)
        self.assertNotEqual(again.returncode, 0)
        self.assertEqual(before, outputs[0].read_bytes())

if __name__ == "__main__":
    unittest.main()
