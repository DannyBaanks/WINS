"""Tests for WINS 32-bit native PE loader (winrun32)."""

import filecmp
import os
from pathlib import Path
import subprocess
import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
WINRUN32_BIN = REPO_ROOT / "bin/winrun32"
CORPUS_7ZR = REPO_ROOT / "corpus/7zr.exe"
FALLOUT_EXE = Path.home() / ".local/share/Steam/steamapps/common/Fallout New Vegas/FalloutNV.exe"


@pytest.fixture(scope="module")
def winrun32_fresh(tmp_path_factory):
    """Return a winrun32 built from current sources (or WINS_WINRUN32)."""
    override = os.environ.get("WINS_WINRUN32")
    if override:
        p = Path(override)
        assert p.is_file() and os.access(p, os.X_OK), f"WINS_WINRUN32 not executable: {p}"
        return p

    out = tmp_path_factory.mktemp("winrun32-bin") / "winrun32"
    cmd = [
        os.environ.get("ZIG", "zig"),
        "build-exe",
        str(REPO_ROOT / "native/winrun32.zig"),
        "-target",
        "x86-linux-gnu.2.39",
        "-mcpu=i386",
        "-O",
        "ReleaseFast",
        "-lc",
        "-dynamic",
        "--image-base",
        "0x2000000",
        "--name",
        "winrun32",
        f"-femit-bin={out}",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert res.returncode == 0, f"failed to build fresh winrun32:\n{res.stderr}\n{res.stdout}"
    return out


def test_winrun32_binary_present():
    assert WINRUN32_BIN.exists(), f"winrun32 binary not found at {WINRUN32_BIN}"
    assert WINRUN32_BIN.stat().st_mode & 0o111, "winrun32 is not executable"


@pytest.mark.skipif(not CORPUS_7ZR.is_file(), reason="corpus/7zr.exe not present")
def test_winrun32_7zr_e2e_roundtrip(winrun32_fresh, tmp_path):
    """Run corpus/7zr.exe end-to-end: add, list, test integrity, extract, and byte-compare."""
    src = tmp_path / "payload.bin"
    payload = b"WINS 7zr regression test payload\n" * 64 + bytes(range(256))
    src.write_bytes(payload)

    arc = tmp_path / "archive.7z"
    out_dir = tmp_path / "extracted"

    def run_7z(*args):
        return subprocess.run(
            [str(winrun32_fresh), "--run", str(CORPUS_7ZR), *args],
            capture_output=True,
            text=True,
            timeout=60,
        )

    res_a = run_7z("a", str(arc), str(src))
    assert res_a.returncode == 0, f"7zr a failed:\n{res_a.stderr}\n{res_a.stdout}"
    assert "Everything is Ok" in res_a.stdout, res_a.stdout
    assert arc.is_file() and arc.stat().st_size > 0

    res_l = run_7z("l", str(arc))
    assert res_l.returncode == 0, f"7zr l failed:\n{res_l.stderr}\n{res_l.stdout}"
    assert "payload.bin" in res_l.stdout, res_l.stdout

    res_t = run_7z("t", str(arc))
    assert res_t.returncode == 0, f"7zr t failed:\n{res_t.stderr}\n{res_t.stdout}"
    assert "Everything is Ok" in res_t.stdout, res_t.stdout

    res_x = run_7z("x", str(arc), f"-o{out_dir}", "-y")
    assert res_x.returncode == 0, f"7zr x failed:\n{res_x.stderr}\n{res_x.stdout}"
    assert "Everything is Ok" in res_x.stdout, res_x.stdout

    extracted = out_dir / "payload.bin"
    assert extracted.is_file(), f"missing extracted file: {list(out_dir.rglob('*'))}"
    assert filecmp.cmp(src, extracted, shallow=False)


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
