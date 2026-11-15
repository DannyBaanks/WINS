"""
WINS Transpiler Subsystem - Semantic Candidate Harvester
Analyzes native Windows PE (Portable Executable) binaries, extracts their
Import Address Table (IAT), demangles C++ RTTI class symbols, fingerprints
embedded cross-platform open-source libraries, and computes Linux replacement
candidates.
"""

import os
import sys
import struct
import re
from typing import Dict, Any, List, Optional, Tuple, Set

class BinaryHarvester:
    # Library signature database: regexes -> metadata and Linux native equivalents
    KNOWN_LIBRARIES = [
        {
            "id": "scintilla",
            "name": "Scintilla Source Code Editing Engine",
            "patterns": [
                rb"Scintilla",
                rb"SCI_GETDIRECTFUNCTION",
                rb"ScintillaEditView",
                rb"Scintilla_RegisterClasses",
            ],
            "role": "Core Text Editing & Syntax Highlighting Canvas",
            "linux_candidates": [
                {"package": "libscintilla-gtk", "description": "Native GTK Scintilla shared object"},
                {"package": "qscintilla2", "description": "Native Qt Scintilla C++ library"},
                {"package": "notepadqq", "description": "Full Linux native port of Notepad++"},
            ],
        },
        {
            "id": "boost",
            "name": "Boost C++ Libraries",
            "patterns": [
                rb"boost::match_results",
                rb"boost::regex",
                rb"boost::archive",
                rb"\.?AU\?\$wrapexcept@Vruntime_error@std@@@boost@@",
            ],
            "role": "General C++ Utilities, Regex & Data Structures",
            "linux_candidates": [
                {"package": "libboost-all-dev", "description": "Standard Linux Boost C++ libraries"},
                {"package": "libboost-regex-dev", "description": "Native Linux Boost Regex runtime"},
            ],
        },
        {
            "id": "tinyxml",
            "name": "TinyXML / TinyXML-2 XML Parser",
            "patterns": [
                rb"TiXmlDocument",
                rb"TiXmlElement",
                rb"tinyxml2::XMLDocument",
                rb"TiXmlNode",
            ],
            "role": "XML Configuration & Schema Parsing",
            "linux_candidates": [
                {"package": "libtinyxml2-dev", "description": "Native Linux TinyXML2 shared library"},
                {"package": "libtinyxml-dev", "description": "Native Linux TinyXML shared library"},
            ],
        },
        {
            "id": "sqlite",
            "name": "SQLite Embedded Relational Database Engine",
            "patterns": [
                rb"SQLite format 3",
                rb"sqlite3_open",
                rb"sqlite3_exec",
                rb"sqlite3_prepare_v2",
            ],
            "role": "Embedded Data Storage & Indexing",
            "linux_candidates": [
                {"package": "libsqlite3-dev", "description": "Standard native Linux SQLite3 runtime"},
            ],
        },
        {
            "id": "zlib",
            "name": "zlib Compression Library",
            "patterns": [
                rb"deflate 1\.[0-9]+\.[0-9]+",
                rb"inflate 1\.[0-9]+\.[0-9]+",
                rb"deflateInit2_",
            ],
            "role": "DEFLATE / GZIP Compression",
            "linux_candidates": [
                {"package": "zlib1g-dev", "description": "Standard native Linux zlib compression"},
            ],
        },
        {
            "id": "openssl",
            "name": "OpenSSL Cryptography Engine",
            "patterns": [
                rb"OpenSSL [0-9]+\.[0-9]+\.[0-9]+",
                rb"EVP_DigestInit",
                rb"SSL_CTX_new",
            ],
            "role": "TLS, Hashing & Cryptography",
            "linux_candidates": [
                {"package": "libssl-dev", "description": "Standard native Linux OpenSSL"},
            ],
        },
        {
            "id": "paintdotnet",
            "name": "Paint.NET Core Graphics & Effects Architecture",
            "patterns": [
                rb"PaintDotNet",
                rb"paintdotnet",
                rb"ComputeSharp\.D2D1",
                rb"TerraFX\.Interop\.DirectX",
                rb"IDirect2DDrawer",
            ],
            "role": "Layered 2D Image Manipulation & GPU Shader Rendering",
            "linux_candidates": [
                {"package": "pinta", "description": "Native Linux Gtk/Cairo clone of Paint.NET"},
                {"package": "gimp", "description": "GNU Image Manipulation Program"},
            ],
        },
        {
            "id": "pcre",
            "name": "PCRE / PCRE2 Perl-Compatible Regular Expressions",
            "patterns": [
                rb"pcre_compile",
                rb"pcre2_compile",
                rb"PCRE2 version",
            ],
            "role": "Regular Expression Engine",
            "linux_candidates": [
                {"package": "libpcre2-dev", "description": "Standard native Linux PCRE2"},
            ],
        },
        {
            "id": "curl",
            "name": "libcurl Multi-protocol File Transfer",
            "patterns": [
                rb"curl_easy_init",
                rb"curl_easy_setopt",
                rb"libcurl/[0-9]+\.[0-9]+",
            ],
            "role": "HTTP / Network Transfer",
            "linux_candidates": [
                {"package": "libcurl4-openssl-dev", "description": "Native Linux libcurl library"},
            ],
        },
    ]

    # Categorization of Win32 DLLs and APIs
    API_DOMAIN_MAP = {
        "KERNEL32.dll": {
            "domain": "System & File I/O",
            "transpilable_to_posix": True,
            "linux_equivalent": "POSIX (open, read, write, close, mmap, pthread, getpid)",
        },
        "ADVAPI32.dll": {
            "domain": "Registry & Security",
            "transpilable_to_posix": True,
            "linux_equivalent": "XDG Base Directory (~/.config/) + JSON/INI config parser",
        },
        "CRYPT32.dll": {
            "domain": "Cryptography",
            "transpilable_to_posix": True,
            "linux_equivalent": "OpenSSL (EVP, SHA256) / libcrypto",
        },
        "bcrypt.dll": {
            "domain": "Cryptography (BCrypt)",
            "transpilable_to_posix": True,
            "linux_equivalent": "OpenSSL / Linux kernel crypto API",
        },
        "SHLWAPI.dll": {
            "domain": "Path & String Helpers",
            "transpilable_to_posix": True,
            "linux_equivalent": "glibc string & path resolution (realpath, dirname, basename)",
        },
        "SHELL32.dll": {
            "domain": "Shell Integration & Dialogs",
            "transpilable_to_posix": True,
            "linux_equivalent": "XDG specifications (xdg-open, desktop entries) + GTK FileChooser",
        },
        "USER32.dll": {
            "domain": "Windowing & GUI Message Loop",
            "transpilable_to_posix": False,
            "linux_equivalent": "X11/Wayland event loop or native widget toolkit (GTK / Qt / ImGui)",
        },
        "GDI32.dll": {
            "domain": "Graphics Device Interface (2D)",
            "transpilable_to_posix": False,
            "linux_equivalent": "Cairo 2D / Skia / Pango graphics context",
        },
        "COMCTL32.dll": {
            "domain": "Common Controls (Tree, Tab, List)",
            "transpilable_to_posix": False,
            "linux_equivalent": "Native GTK/Qt widgets",
        },
        "UxTheme.dll": {
            "domain": "Visual Styles & Theming",
            "transpilable_to_posix": False,
            "linux_equivalent": "CSS / GTK Theme engine",
        },
        "dwmapi.dll": {
            "domain": "Desktop Window Manager (DWM)",
            "transpilable_to_posix": False,
            "linux_equivalent": "Wayland / X11 Compositor Protocols",
        },
        "COMDLG32.dll": {
            "domain": "Standard Dialogs",
            "transpilable_to_posix": True,
            "linux_equivalent": "GTK/Qt Native File/Color/Print Portals (xdg-desktop-portal)",
        },
        "ole32.dll": {
            "domain": "COM / OLE Runtime",
            "transpilable_to_posix": False,
            "linux_equivalent": "C++ Interface VTable Dispatch / DBus IPC",
        },
        "OLEAUT32.dll": {
            "domain": "OLE Automation & BSTR",
            "transpilable_to_posix": True,
            "linux_equivalent": "Standard C++ std::wstring / UTF-8 strings",
        },
        "IMM32.dll": {
            "domain": "Input Method Manager",
            "transpilable_to_posix": True,
            "linux_equivalent": "IBus / Fcitx Linux input methods",
        },
        "WININET.dll": {
            "domain": "Windows Internet Client",
            "transpilable_to_posix": True,
            "linux_equivalent": "libcurl",
        },
    }

    def __init__(self, file_path: str):
        self.file_path = os.path.abspath(file_path)
        if not os.path.isfile(self.file_path):
            raise FileNotFoundError(f"Target binary not found: {self.file_path}")
        self.file_size = os.path.getsize(self.file_path)

        with open(self.file_path, "rb") as f:
            self.raw_data = f.read()

        self.sections: List[Dict[str, Any]] = []
        self.imports: Dict[str, List[str]] = {}
        self.is_64bit: bool = False
        self.entry_point_rva: int = 0
        self.image_base: int = 0

    def parse_pe(self) -> bool:
        """Parses PE/COFF structures, sections, and Import Directory Table."""
        if len(self.raw_data) < 64:
            return False

        # 1. DOS Header
        magic = self.raw_data[:2]
        if magic != b"MZ":
            return False

        pe_offset = struct.unpack_from("<I", self.raw_data, 0x3C)[0]
        if pe_offset + 24 > len(self.raw_data):
            return False

        # 2. PE Signature
        pe_sig = self.raw_data[pe_offset:pe_offset+4]
        if pe_sig != b"PE\x00\x00":
            return False

        # 3. COFF File Header
        coff_start = pe_offset + 4
        machine, num_sections, _, _, _, opt_hdr_size, characteristics = struct.unpack_from("<HHIIIHH", self.raw_data, coff_start)

        opt_start = coff_start + 20
        if opt_start + opt_hdr_size > len(self.raw_data):
            return False

        # 4. Optional Header
        opt_magic = struct.unpack_from("<H", self.raw_data, opt_start)[0]
        self.is_64bit = (opt_magic == 0x20B)  # 0x10B = PE32, 0x20B = PE32+

        if self.is_64bit:
            self.entry_point_rva = struct.unpack_from("<I", self.raw_data, opt_start + 16)[0]
            self.image_base = struct.unpack_from("<Q", self.raw_data, opt_start + 24)[0]
            data_dirs_offset = opt_start + 112
        else:
            self.entry_point_rva = struct.unpack_from("<I", self.raw_data, opt_start + 16)[0]
            self.image_base = struct.unpack_from("<I", self.raw_data, opt_start + 28)[0]
            data_dirs_offset = opt_start + 96

        # Data Directory index 1 = Import Table
        import_table_rva, import_table_size = struct.unpack_from("<II", self.raw_data, data_dirs_offset + (1 * 8))

        # 5. Section Headers
        sections_offset = opt_start + opt_hdr_size
        self.sections = []
        for i in range(num_sections):
            sec_hdr = self.raw_data[sections_offset + (i * 40): sections_offset + ((i + 1) * 40)]
            if len(sec_hdr) < 40:
                break
            name_raw, v_size, v_addr, raw_size, raw_ptr = struct.unpack_from("<8sIIII", sec_hdr, 0)
            name = name_raw.decode("latin1", "replace").rstrip("\x00")
            self.sections.append({
                "name": name,
                "virtual_size": v_size,
                "virtual_address": v_addr,
                "raw_size": raw_size,
                "raw_offset": raw_ptr,
            })

        # 6. Parse Import Directory Table
        if import_table_rva > 0:
            self._parse_imports(import_table_rva)

        return True

    def _rva_to_offset(self, rva: int) -> Optional[int]:
        for sec in self.sections:
            v_start = sec["virtual_address"]
            v_end = v_start + max(sec["virtual_size"], sec["raw_size"])
            if v_start <= rva < v_end:
                return sec["raw_offset"] + (rva - v_start)
        return None

    def _read_cstring(self, offset: int, max_len: int = 256) -> str:
        end = self.raw_data.find(b"\x00", offset, offset + max_len)
        if end != -1:
            return self.raw_data[offset:end].decode("latin1", "replace")
        return self.raw_data[offset:offset + max_len].decode("latin1", "replace")

    def _parse_imports(self, import_rva: int):
        import_offset = self._rva_to_offset(import_rva)
        if not import_offset:
            return

        pos = import_offset
        self.imports = {}

        while pos + 20 <= len(self.raw_data):
            orig_first_thunk, time_stamp, fwd_chain, name_rva, first_thunk = struct.unpack_from("<IIIII", self.raw_data, pos)
            pos += 20

            # Null descriptor marks end of Import Directory Table
            if orig_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
                break

            name_offset = self._rva_to_offset(name_rva)
            if not name_offset:
                continue
            dll_name = self._read_cstring(name_offset)

            # Read functions via ILT (OriginalFirstThunk) or fallback to IAT (FirstThunk)
            thunk_rva = orig_first_thunk if orig_first_thunk != 0 else first_thunk
            thunk_offset = self._rva_to_offset(thunk_rva)
            if not thunk_offset:
                continue

            fn_names = []
            thunk_pos = thunk_offset
            entry_size = 8 if self.is_64bit else 4
            ordinal_mask = (1 << 63) if self.is_64bit else (1 << 31)

            while thunk_pos + entry_size <= len(self.raw_data):
                val = struct.unpack_from("<Q" if self.is_64bit else "<I", self.raw_data, thunk_pos)[0]
                thunk_pos += entry_size

                if val == 0:
                    break

                if val & ordinal_mask:
                    # Imported by Ordinal
                    fn_names.append(f"Ordinal#{val & 0xFFFF}")
                else:
                    # Imported by Name (val is RVA to Hint/Name table)
                    hint_name_offset = self._rva_to_offset(val)
                    if hint_name_offset and hint_name_offset + 2 < len(self.raw_data):
                        # Skip 2-byte hint
                        fn_name = self._read_cstring(hint_name_offset + 2)
                        if fn_name:
                            fn_names.append(fn_name)

            self.imports[dll_name] = fn_names

    def extract_rtti_classes(self) -> List[str]:
        """Scans binary data for MSVC C++ RTTI type descriptors (.?AV... and .?AU...)."""
        classes = set()
        matches = re.findall(rb"\.\?A[VU]([a-zA-Z0-9_@?$]+)@@", self.raw_data)
        for m in matches:
            raw_sym = m.decode("latin1", "replace")
            # Demangle namespace separators (@)
            parts = [p for p in raw_sym.split("@") if p and not p.startswith("?")]
            if parts:
                clean_name = "::".join(reversed(parts))
                classes.add(clean_name)
        return sorted(list(classes))

    def detect_embedded_libraries(self) -> List[Dict[str, Any]]:
        """Scans binary string patterns against known cross-platform open-source libraries."""
        detected = []
        for lib in self.KNOWN_LIBRARIES:
            matched_patterns = []
            for pat in lib["patterns"]:
                if re.search(pat, self.raw_data):
                    matched_patterns.append(pat.decode("latin1", "replace"))

            if matched_patterns:
                detected.append({
                    "id": lib["id"],
                    "name": lib["name"],
                    "role": lib["role"],
                    "matched_evidence_count": len(matched_patterns),
                    "evidence_samples": matched_patterns[:3],
                    "linux_candidates": lib["linux_candidates"],
                })
        return detected

    def harvest(self) -> Dict[str, Any]:
        """Executes full harvest and computes porting feasibility metrics."""
        self.parse_pe()
        rtti_classes = self.extract_rtti_classes()
        embedded_libs = self.detect_embedded_libraries()

        # Compute API Domain Statistics
        total_apis = sum(len(fns) for fns in self.imports.values())
        posix_mappable_apis = 0
        gui_windowing_apis = 0

        domains_summary: Dict[str, Dict[str, Any]] = {}
        for dll, fns in self.imports.items():
            info = self.API_DOMAIN_MAP.get(dll, {
                "domain": "Other / Third-Party",
                "transpilable_to_posix": False,
                "linux_equivalent": "Unknown",
            })
            domain_name = info["domain"]
            if domain_name not in domains_summary:
                domains_summary[domain_name] = {
                    "dlls": [],
                    "api_count": 0,
                    "transpilable_to_posix": info["transpilable_to_posix"],
                    "linux_equivalent": info["linux_equivalent"],
                }
            domains_summary[domain_name]["dlls"].append(dll)
            domains_summary[domain_name]["api_count"] += len(fns)

            if info["transpilable_to_posix"]:
                posix_mappable_apis += len(fns)
            else:
                gui_windowing_apis += len(fns)

        posix_ratio = round((posix_mappable_apis / total_apis * 100), 1) if total_apis > 0 else 0.0

        return {
            "binary": {
                "path": self.file_path,
                "name": os.path.basename(self.file_path),
                "size_bytes": self.file_size,
                "architecture": "x86_64 (64-bit)" if self.is_64bit else "x86 (32-bit)",
                "sections": [s["name"] for s in self.sections],
            },
            "metrics": {
                "total_imported_dlls": len(self.imports),
                "total_imported_apis": total_apis,
                "posix_mappable_apis": posix_mappable_apis,
                "gui_windowing_apis": gui_windowing_apis,
                "posix_transpilability_score": f"{posix_ratio}%",
            },
            "embedded_libraries": embedded_libs,
            "rtti_classes_count": len(rtti_classes),
            "rtti_classes_sample": rtti_classes[:25],
            "api_domains": domains_summary,
            "imports_by_dll": {dll: len(fns) for dll, fns in self.imports.items()},
        }
