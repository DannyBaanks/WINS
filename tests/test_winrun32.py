"""Tests for WINS 32-bit native PE loader (winrun32)."""

from pathlib import Path
import subprocess
import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
WINRUN32_BIN = REPO_ROOT / "bin/winrun32"
FALLOUT_EXE = Path.home() / ".local/share/Steam/steamapps/common/Fallout New Vegas/FalloutNV.exe"


def test_winrun32_binary_present():
    assert WINRUN32_BIN.exists(), f"winrun32 binary not found at {WINRUN32_BIN}"
    assert WINRUN32_BIN.stat().st_mode & 0o111, "winrun32 is not executable"


@pytest.mark.skipif(not FALLOUT_EXE.exists(), reason="FalloutNV.exe not found on system")
def test_winrun32_check_fallout_nv():
    res = subprocess.run(
        [str(WINRUN32_BIN), "--check", str(FALLOUT_EXE)],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "Architecture:    x86 32-bit (i386)" in res.stderr or "Architecture:    x86 32-bit (i386)" in res.stdout
    assert "ImageBase:       0x00400000" in res.stderr or "ImageBase:       0x00400000" in res.stdout
    assert "Check PASSED" in res.stderr or "Check PASSED" in res.stdout


@pytest.mark.skipif(not FALLOUT_EXE.exists(), reason="FalloutNV.exe not found on system")
def test_winrun32_stage_memory_fallout_nv():
    res = subprocess.run(
        [str(WINRUN32_BIN), str(FALLOUT_EXE)],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "Successfully mapped 0x00400000" in res.stderr or "Successfully mapped 0x00400000" in res.stdout
    assert "Memory staging" in res.stderr or "Memory staging" in res.stdout
