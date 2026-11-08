"""Unit and integration tests for Bethesda BSA v104 extractor."""

from pathlib import Path
import struct
import zlib
import pytest

from core.transpiler.bsa_extractor import BsaArchive, BsaFileEntry, BSA_MAGIC


FALLOUT_DIR = Path("/home/danny/.local/share/Steam/steamapps/common/Fallout New Vegas/Data")
MISC_BSA = FALLOUT_DIR / "Fallout - Misc.bsa"


def create_synthetic_bsa(tmp_path: Path) -> Path:
    """Create a minimal valid BSA v104 archive with 1 compressed and 1 uncompressed file."""
    bsa_file = tmp_path / "test.bsa"

    # Files to pack:
    # 1. folder "test/data", file "hello.txt", uncompressed
    # 2. folder "test/data", file "compressed.txt", compressed
    f1_content = b"Hello, uncompressed BSA world!"
    f2_content = b"Repeat" * 100
    f2_comp = zlib.compress(f2_content)
    f2_payload = struct.pack("<I", len(f2_content)) + f2_comp

    folder_name = "test/data\x00"
    folder_len = len(folder_name) + 1  # 1 byte for len prefix

    file_names = b"hello.txt\x00compressed.txt\x00"
    file_names_len = len(file_names)

    # Calculate layout:
    # Header: 36 bytes
    # Folder record: 1 * 16 bytes = 16 bytes
    # Folder data: 1 byte len + folder_name (10 bytes) + 2 * 16 bytes file records = 43 bytes
    # File names block: len(file_names)
    header_size = 36
    folder_records_size = 16
    folder_data_size = 1 + len(folder_name) + (2 * 16)
    names_offset = header_size + folder_records_size + folder_data_size
    data_start = names_offset + file_names_len

    f1_offset = data_start
    f2_offset = data_start + len(f1_content)

    # Archive flags: 0x3 (named dirs, named files, uncompressed by default)
    # File 2 will have SIZE_COMPRESS_TOGGLE bit (0x40000000) set
    with open(bsa_file, "wb") as f:
        # Header (36 bytes)
        f.write(
            struct.pack(
                "<4s8I",
                BSA_MAGIC,
                104,
                36,
                0x00000003,  # flags: dirs, files, no default compress
                1,           # num_folders
                2,           # num_files
                len(folder_name) + 1,
                file_names_len,
                0,           # file_flags
            )
        )
        # Folder record (16 bytes)
        f.write(struct.pack("<Q2I", 0x12345678, 2, 0))

        # Folder data: 1 byte len + folder_name + file records
        f.write(struct.pack("B", len(folder_name)))
        f.write(folder_name.encode("ascii"))
        # File 1 record (uncompressed)
        f.write(struct.pack("<Q2I", 0x1111, len(f1_content), f1_offset))
        # File 2 record (compressed, size | 0x40000000)
        f.write(struct.pack("<Q2I", 0x2222, len(f2_payload) | 0x40000000, f2_offset))

        # File names
        f.write(file_names)

        # File data
        f.write(f1_content)
        f.write(f2_payload)

    return bsa_file


def test_synthetic_bsa_parsing(tmp_path: Path):
    bsa_path = create_synthetic_bsa(tmp_path)
    bsa = BsaArchive(bsa_path)

    assert bsa.version == 104
    assert len(bsa.files) == 2

    # Verify uncompressed read
    f1_data = bsa.read_file("test/data/hello.txt")
    assert f1_data == b"Hello, uncompressed BSA world!"

    # Verify compressed read
    f2_data = bsa.read_file("test/data/compressed.txt")
    assert f2_data == b"Repeat" * 100


def test_synthetic_bsa_extraction(tmp_path: Path):
    bsa_path = create_synthetic_bsa(tmp_path)
    bsa = BsaArchive(bsa_path)

    out_dir = tmp_path / "extracted"
    bsa.extract_file("test/data/hello.txt", out_dir / "test/data/hello.txt")
    assert (out_dir / "test/data/hello.txt").read_bytes() == b"Hello, uncompressed BSA world!"


@pytest.mark.skipif(not MISC_BSA.exists(), reason="Fallout - Misc.bsa not found on system")
def test_real_fallout_nv_misc_bsa():
    bsa = BsaArchive(MISC_BSA)
    assert bsa.version == 104
    assert len(bsa.files) > 100

    # Test reading tutorial_menu.xml
    xml_data = bsa.read_file("menus/tutorial_menu.xml")
    assert len(xml_data) == 11257
    assert b'<menu name="TutorialMenu">' in xml_data
