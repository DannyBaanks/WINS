"""
Tests for WINS Transpiler Subsystem - BinaryHarvester
"""

import os
import unittest
import struct
import tempfile
from core.transpiler.harvester import BinaryHarvester

class TestBinaryHarvester(unittest.TestCase):
    def test_invalid_file_handling(self):
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"NOT_A_PE_FILE_CORRUPTED_BYTES")
            tmp_path = f.name

        try:
            harvester = BinaryHarvester(tmp_path)
            self.assertFalse(harvester.parse_pe())
            rep = harvester.harvest()
            self.assertEqual(rep["metrics"]["total_imported_dlls"], 0)
        finally:
            os.remove(tmp_path)

    def test_domain_mapping_logic(self):
        self.assertTrue(BinaryHarvester.API_DOMAIN_MAP["KERNEL32.dll"]["transpilable_to_posix"])
        self.assertTrue(BinaryHarvester.API_DOMAIN_MAP["ADVAPI32.dll"]["transpilable_to_posix"])
        self.assertFalse(BinaryHarvester.API_DOMAIN_MAP["USER32.dll"]["transpilable_to_posix"])
        self.assertFalse(BinaryHarvester.API_DOMAIN_MAP["GDI32.dll"]["transpilable_to_posix"])

    def test_synthetic_pe_parsing(self):
        # Create a valid minimal synthetic 64-bit PE binary
        buf = bytearray(1024)
        # DOS Header
        buf[0:2] = b"MZ"
        struct.pack_into("<I", buf, 0x3C, 64)  # e_lfanew = 64

        # PE Signature
        pe_offset = 64
        buf[pe_offset:pe_offset+4] = b"PE\x00\x00"

        # COFF File Header
        coff = pe_offset + 4
        # machine=0x8664, num_sections=1, time=0, sym_ptr=0, sym_num=0, opt_hdr_size=240, chars=0x02
        struct.pack_into("<HHIIIHH", buf, coff, 0x8664, 1, 0, 0, 0, 240, 0x02)

        # Optional Header (PE32+)
        opt = coff + 20
        struct.pack_into("<H", buf, opt, 0x20B)  # Magic = PE32+
        struct.pack_into("<I", buf, opt + 16, 0x1000)  # EntryPoint RVA = 0x1000
        struct.pack_into("<Q", buf, opt + 24, 0x140000000)  # ImageBase

        # Section Header (.text)
        sec_offset = opt + 240
        sec_name = b".text\x00\x00\x00"
        struct.pack_into("<8sIIII", buf, sec_offset, sec_name, 0x1000, 0x1000, 0x200, 0x200)

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(buf)
            tmp_path = f.name

        try:
            h = BinaryHarvester(tmp_path)
            self.assertTrue(h.parse_pe())
            self.assertTrue(h.is_64bit)
            self.assertEqual(len(h.sections), 1)
            self.assertEqual(h.sections[0]["name"], ".text")
            rep = h.harvest()
            self.assertEqual(rep["binary"]["architecture"], "x86_64 (64-bit)")
        finally:
            os.remove(tmp_path)

    def test_real_notepad_harvest(self):
        npp_path = "/tmp/npp_probe/notepad++.exe"
        if not os.path.isfile(npp_path):
            self.skipTest("notepad++.exe not extracted in /tmp/npp_probe")

        h = BinaryHarvester(npp_path)
        rep = h.harvest()
        self.assertEqual(rep["binary"]["name"], "notepad++.exe")
        self.assertEqual(rep["binary"]["architecture"], "x86_64 (64-bit)")
        self.assertGreater(rep["metrics"]["total_imported_apis"], 500)
        self.assertGreater(rep["metrics"]["posix_mappable_apis"], 200)

        # Verify embedded library detections
        lib_ids = [l["id"] for l in rep["embedded_libraries"]]
        self.assertIn("scintilla", lib_ids)
        self.assertIn("boost", lib_ids)

        # Verify RTTI classes discovered
        self.assertGreater(rep["rtti_classes_count"], 100)

if __name__ == "__main__":
    unittest.main()
