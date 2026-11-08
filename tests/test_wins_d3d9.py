"""Tests for WINS Native Direct3D 9 State Tracker (native/wins_d3d9.zig)."""

from pathlib import Path
import subprocess
import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
D3D9_SOURCE = REPO_ROOT / "native/wins_d3d9.zig"


def test_d3d9_source_exists():
    assert D3D9_SOURCE.exists(), f"wins_d3d9.zig not found at {D3D9_SOURCE}"


def test_d3d9_zig_unit_tests_host():
    res = subprocess.run(
        ["zig", "test", str(D3D9_SOURCE)],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"zig test failed:\n{res.stderr}\n{res.stdout}"
    assert "All 2 tests passed." in res.stdout or "All 2 tests passed." in res.stderr


def test_d3d9_zig_unit_tests_x86_32():
    res = subprocess.run(
        ["zig", "test", str(D3D9_SOURCE), "-target", "x86-linux-musl"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"32-bit zig test failed:\n{res.stderr}\n{res.stdout}"
    assert "All 2 tests passed." in res.stdout or "All 2 tests passed." in res.stderr
