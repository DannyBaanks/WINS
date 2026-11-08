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


def test_d3d9_shared_object_exports():
    so_path = REPO_ROOT / "bin/d3d9.so"
    if not so_path.exists():
        res = subprocess.run(
            ["zig", "build-lib", "-dynamic", str(D3D9_SOURCE), f"-femit-bin={so_path}"],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"zig build-lib failed:\n{res.stderr}"

    nm_res = subprocess.run(
        ["nm", "-D", "--defined-only", str(so_path)],
        capture_output=True,
        text=True,
    )
    assert nm_res.returncode == 0
    symbols = [line.split()[-1] for line in nm_res.stdout.strip().splitlines() if line.strip()]

    # Verify Direct3DCreate9 and perf functions
    assert "Direct3DCreate9" in symbols
    assert "D3DPERF_SetOptions" in symbols
    assert "D3DPERF_BeginEvent" in symbols
    assert "D3DPERF_EndEvent" in symbols

    # Verify all 25 D3DX9 exports
    expected_d3dx = [
        "D3DXAssembleShader",
        "D3DXAssembleShaderFromFileA",
        "D3DXCompileShader",
        "D3DXCompileShaderFromFileA",
        "D3DXCreateBuffer",
        "D3DXCreateCubeTextureFromFileInMemory",
        "D3DXCreateTextureFromFileInMemory",
        "D3DXCreateVolumeTextureFromFileInMemory",
        "D3DXGetImageInfoFromFileInMemory",
        "D3DXGetPixelShaderProfile",
        "D3DXGetShaderConstantTable",
        "D3DXGetVertexShaderProfile",
        "D3DXLoadSurfaceFromSurface",
        "D3DXMatrixInverse",
        "D3DXMatrixMultiply",
        "D3DXMatrixMultiplyTranspose",
        "D3DXMatrixRotationYawPitchRoll",
        "D3DXMatrixTranspose",
        "D3DXPlaneNormalize",
        "D3DXPlaneTransform",
        "D3DXSaveTextureToFileA",
        "D3DXVec3Normalize",
        "D3DXVec3TransformCoord",
        "D3DXVec3TransformNormal",
        "D3DXVec4Transform",
    ]
    for fn in expected_d3dx:
        assert fn in symbols, f"Missing D3DX export: {fn}"
