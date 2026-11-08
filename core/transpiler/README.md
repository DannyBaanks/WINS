# Core Transpiler Component Package

## Overview
Subsystem responsible for static PE inspection, semantic candidate harvesting, and native Linux POSIX shimming for traditional Win32 C/C++ applications. It identifies embedded open-source libraries (e.g. Scintilla, Boost) and includes an **Autonomous End-to-End Compilation & Shim Synthesis Fuzzer** (`compile_fuzzer.py`) that iteratively generates, mutates, and verifies native C/Zig shared libraries for harvested Win32 APIs using `zig cc`.

## Interface
- `BinaryHarvester(file_path: str)`: Static PE parser and symbol/lineage analyzer (`[harvester.py:BinaryHarvester]`).
  - `BinaryHarvester.parse_pe() -> bool`: Parses DOS header, COFF header, Optional Header (PE32/PE32+), Section Table, and Data Directories.
  - `BinaryHarvester._parse_imports(import_rva: int)`: Traverses the Import Directory Table to extract the full Import Address Table (IAT) grouped by DLL.
  - `BinaryHarvester.extract_rtti_classes() -> List[str]`: Demangles and extracts MSVC C++ RTTI class/struct symbols (`.?AV...`, `.?AU...`).
  - `BinaryHarvester.detect_embedded_libraries() -> List[Dict[str, Any]]`: Scans for embedded cross-platform libraries (Scintilla, Boost, TinyXML, SQLite, zlib, OpenSSL, PCRE, libcurl) and maps them to Linux native packages.
  - `BinaryHarvester.harvest() -> Dict[str, Any]`: Computes POSIX transpilability score and domain classification.
- `CompileFuzzer(target_binary: str, target_apis: Dict, out_so: str, max_iterations: int)`: Autonomous E2E Compilation & Shim Synthesis Fuzzer (`[compile_fuzzer.py:CompileFuzzer]`).
  - Synthesizes tailored C source shims mapping harvested Win32 APIs to native Linux POSIX equivalents.
  - Compiles candidate code in a fast iterative feedback loop using `zig cc -shared -fPIC`.
  - Captures compiler diagnostics (unknown types, conflicting signatures, missing headers) and mutates source generation parameters autonomously until compilation succeeds.
  - Dynamically loads the synthesized `.so` via `ctypes` and verifies exported symbols through in-memory boundary fuzz testing.
- `posix_shim.c` / `libwins_shim.so`: Native C/Zig shared library implementing zero-Win32 POSIX API mappings:
  - `wins_normalize_path(const char* win_path, char* out_buf, size_t out_max) -> int`
  - `wins_create_file(const char* win_path, unsigned int access_flags, unsigned int creation_disposition) -> int`
  - `wins_read_file(int fd, void* buffer, size_t bytes_to_read, size_t* bytes_read) -> int`
  - `wins_write_file(int fd, const void* buffer, size_t bytes_to_write, size_t* bytes_written) -> int`
  - `wins_close_file(int fd) -> int`
- `BsaArchive(archive_path)`: High-performance native reader and decompressor for Bethesda BSA v104 archives (`bsa_extractor.py`).
  - Bit-exact zlib streaming decompression without external Windows tools.
  - Sub-millisecond folder and file hash indexing across tens of thousands of entries.
- `EsmParser(esm_path)`: Stream parser for hierarchical Bethesda ESM4 master files (`esm_parser.py`).
  - Decodes `TES4`, `GRUP`, `WRLD`, `CELL`, `STAT`, and placed references.
  - Zero-Windows inspection of worldspaces, interior cells, and 3D mesh linkage (`MODL` -> `.nif`).
- `SdpPackage(sdp_path)`: Batch extractor and analyzer for Bethesda D3D9 shader packages (`sdp_shader_extractor.py`).
  - Unpacks compiled `vs_2_0`, `vs_3_0`, `ps_2_0`, `ps_3_0` bytecode.
  - Parses embedded CTAB constant tables to generate structured JSON parameter manifests.

## Invariants
- **Non-Execution Static Parsing**: `BinaryHarvester` must never execute target PE binary machine code during inspection.
- **Fail-Closed Compiler Diagnosis**: If compilation fails, the error diagnostic must trigger targeted mutations without manual intervention.
- **Dynamic In-Memory Validation**: A compiled shim is only accepted after `validate_dynamic_exports` proves all exported symbols can be safely invoked without crashing or segfaulting.
- **Path Isolation**: `wins_normalize_path` must sanitize Windows drive letters (`C:\`), escape DOS devices (`CON`, `PRN`), and map `AppData\Roaming\` to the standard XDG hierarchy (`~/.config/`).

## Verification
- Run: `bin/wins compile-fuzz /tmp/npp_probe/notepad++.exe --json`
- Run: `bin/wins compile-fuzz /tmp/pnet_probe/paintdotnet.exe --json`
- Unit Tests: `python3 -m unittest discover tests -p "test_compile_fuzzer.py"`
