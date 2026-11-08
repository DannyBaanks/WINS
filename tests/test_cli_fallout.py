"""Tests for WINS CLI fallout subcommand."""

import subprocess
import sys
from pathlib import Path
import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
FALLOUT_DIR = Path("/home/danny/.local/share/Steam/steamapps/common/Fallout New Vegas")


def test_cli_fallout_help():
    res = subprocess.run(
        [sys.executable, str(REPO_ROOT / "bin/wins"), "fallout", "--help"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "fallout" in res.stdout
    assert "--audit" in res.stdout
    assert "--openmw-cfg" in res.stdout


@pytest.mark.skipif(not (FALLOUT_DIR / "Data/FalloutNV.esm").exists(), reason="Fallout NV not installed")
def test_cli_fallout_audit_json():
    res = subprocess.run(
        [sys.executable, str(REPO_ROOT / "bin/wins"), "fallout", str(FALLOUT_DIR), "--json"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    import json
    data = json.loads(res.stdout)
    assert "esm" in data
    assert data["esm"]["file"] == "FalloutNV.esm"
    assert data["shaders"]["total_compiled_shaders"] == 15791
