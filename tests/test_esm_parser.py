"""Unit and integration tests for Bethesda ESM4 master file parser."""

from pathlib import Path
import struct
import pytest

from core.transpiler.esm_parser import EsmParser


FALLOUT_DIR = Path("/home/danny/.local/share/Steam/steamapps/common/Fallout New Vegas/Data")
FALLOUT_ESM = FALLOUT_DIR / "FalloutNV.esm"


def create_synthetic_esm(tmp_path: Path) -> Path:
    """Create a minimal valid ESM4 file with TES4 and a WRLD group."""
    esm_file = tmp_path / "test.esm"

    # 1. TES4 subrecords:
    # HEDR (12 bytes), CNAM (Author), MAST (Dependency)
    hedr_data = struct.pack("<f2I", 1.0, 10, 0x00000800)
    cnam_data = b"WINS Engine\x00"
    mast_data = b"FalloutNV.esm\x00"

    tes4_payload = (
        b"HEDR" + struct.pack("<H", len(hedr_data)) + hedr_data +
        b"CNAM" + struct.pack("<H", len(cnam_data)) + cnam_data +
        b"MAST" + struct.pack("<H", len(mast_data)) + mast_data
    )

    # TES4 record header (24 bytes)
    # type (4s), data_size (I), flags (I), form_id (I), vc_info (I), form_version (H), vc_info2 (H)
    tes4_header = struct.pack("<4s4I2H", b"TES4", len(tes4_payload), 0x00000001, 0, 0, 0, 0)

    # 2. WRLD group
    # WRLD record inside the group:
    # EDID (TestWorld), FULL (Test World Name)
    edid_data = b"TestWorld\x00"
    full_data = b"Test World Name\x00"
    wrld_payload = (
        b"EDID" + struct.pack("<H", len(edid_data)) + edid_data +
        b"FULL" + struct.pack("<H", len(full_data)) + full_data
    )
    wrld_rec_hdr = struct.pack("<4s4I2H", b"WRLD", len(wrld_payload), 0, 0x00012345, 0, 0, 0)
    wrld_record = wrld_rec_hdr + wrld_payload

    # GRUP header (24 bytes):
    # tag (4s: 'GRUP'), size (I: 24 + len(wrld_record)), label (4s: 'WRLD'), type (I: 0), stamp (I: 0), vc (I: 0)
    grup_size = 24 + len(wrld_record)
    grup_header = struct.pack("<4s3I", b"GRUP", grup_size, struct.unpack("<I", b"WRLD")[0], 0) + b"\x00" * 8

    with open(esm_file, "wb") as f:
        f.write(tes4_header + tes4_payload)
        f.write(grup_header + wrld_record)

    return esm_file


def test_synthetic_esm_parsing(tmp_path: Path):
    esm_path = create_synthetic_esm(tmp_path)
    esm = EsmParser(esm_path)

    assert esm.author == "WINS Engine"
    assert esm.masters == ["FalloutNV.esm"]
    assert "WRLD" in esm.top_groups

    worldspaces = esm.get_worldspaces()
    assert len(worldspaces) == 1
    fid, edid, full = worldspaces[0]
    assert fid == 0x00012345
    assert edid == "TestWorld"
    assert full == "Test World Name"


@pytest.mark.skipif(not FALLOUT_ESM.exists(), reason="FalloutNV.esm not found on system")
def test_real_fallout_nv_esm():
    esm = EsmParser(FALLOUT_ESM)
    assert len(esm.top_groups) >= 100
    assert "WRLD" in esm.top_groups
    assert "CELL" in esm.top_groups
    assert "STAT" in esm.top_groups

    # Check Mojave Wasteland
    worldspaces = esm.get_worldspaces()
    edids = [w[1] for w in worldspaces]
    assert "WastelandNV" in edids

    # Find WastelandNV FormID
    mojave = next(w for w in worldspaces if w[1] == "WastelandNV")
    assert mojave[0] == 0x000DA726
    assert mojave[2] == "Mojave Wasteland"

    # Check Static 3D meshes
    stats = esm.get_static_meshes(limit=5)
    assert len(stats) == 5
    assert all(s[2].lower().endswith(".nif") for s in stats)
