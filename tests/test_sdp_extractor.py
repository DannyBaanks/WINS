"""Unit and integration tests for Bethesda SDP shader package extractor."""

from pathlib import Path
import struct
import pytest

from core.transpiler.sdp_shader_extractor import SdpPackage, ShaderConstant


FALLOUT_DIR = Path("/home/danny/.local/share/Steam/steamapps/common/Fallout New Vegas/Data")
SDP_FILE = FALLOUT_DIR / "Shaders/shaderpackage002.sdp"


def create_synthetic_sdp(tmp_path: Path) -> Path:
    """Create a minimal valid SDP package containing a vs_3_0 shader with CTAB."""
    sdp_file = tmp_path / "test_shaders.sdp"

    # D3D9 vs_3_0 token: 0xFFFE0300
    token = struct.pack("<I", 0xFFFE0300)

    # Simple CTAB block:
    # 'CTAB' (4s)
    # Size (I), CreatorOff (I), Version (I), Constants (I), InfoOff (I)
    const_name = b"WorldViewProj\x00"
    ctab_header_size = 28
    info_size = 20
    name_offset = ctab_header_size + info_size

    # Constant info entry:
    # name_off (I), rset (H), ridx (H), rcount (H), res (H), type_off (I), def_off (I)
    info_entry = struct.pack("<IH2HHI2H", name_offset, 1, 0, 4, 0, 0, 0, 0)
    ctab_data = (
        b"CTAB" +
        struct.pack("<5I", 28, 0, 0xFFFE0300, 1, ctab_header_size) +
        b"\x00" * 4 +  # pad to 28
        info_entry +
        const_name
    )

    shader_bytecode = token + ctab_data + struct.pack("<I", 0x0000FFFF)  # End token
    shader_name = "TEST_SHADER.vso"
    name_field = shader_name.encode("ascii").ljust(256, b"\x00")

    # SDP header: version (100), count (1), total_size
    entry_total = 256 + 4 + len(shader_bytecode)
    with open(sdp_file, "wb") as f:
        f.write(struct.pack("<3I", 100, 1, entry_total))
        f.write(name_field)
        f.write(struct.pack("<I", len(shader_bytecode)))
        f.write(shader_bytecode)

    return sdp_file


def test_synthetic_sdp_parsing(tmp_path: Path):
    sdp_path = create_synthetic_sdp(tmp_path)
    pkg = SdpPackage(sdp_path)

    assert pkg.version == 100
    assert len(pkg.shaders) == 1

    shader = pkg.shaders[0]
    assert shader.name == "TEST_SHADER.vso"
    assert shader.stage == "vertex"
    assert shader.model == "vs_3_0"

    # Test extraction
    out_dir = tmp_path / "extracted"
    count = pkg.extract_all(out_dir)
    assert count == 1
    assert (out_dir / "TEST_SHADER.vso").exists()
    assert (out_dir / "test_shaders_manifest.json").exists()


@pytest.mark.skipif(not SDP_FILE.exists(), reason="shaderpackage002.sdp not found on system")
def test_real_fallout_nv_sdp(tmp_path: Path):
    pkg = SdpPackage(SDP_FILE)
    assert pkg.version == 100
    assert len(pkg.shaders) == 830

    # Verify shader types
    models = {s.model for s in pkg.shaders}
    assert "vs_2_0" in models or "vs_3_0" in models

    # Test extraction of all shaders in this package
    out_dir = tmp_path / "sdp002"
    count = pkg.extract_all(out_dir, write_manifest=True)
    assert count == 830
    assert (out_dir / "SLS1000.vso").exists()
    assert (out_dir / "shaderpackage002_manifest.json").exists()
