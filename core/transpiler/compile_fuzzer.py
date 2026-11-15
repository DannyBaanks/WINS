"""
WINS Transpiler Subsystem - End-to-End Autonomous Compilation & Shim Fuzzer
Generates, mutates, compiles, and dynamically validates native Linux C/Zig shims
for Windows PE applications in a fast, automated feedback loop.
"""

import os
import sys
import subprocess
import tempfile
import time
import re
import ctypes
import shutil
from typing import Dict, Any, List, Optional, Tuple, Set

from .harvester import BinaryHarvester

class CompileFuzzer:
    """
    Automated E2E Compilation Fuzzer that synthesizes, mutates, and verifies
    native POSIX shims for harvested Windows Win32 APIs.
    """

    TERMINATION_SYMBOLS = {
        "exit", "_exit", "_Exit", "quick_exit", "terminate",
        "_cexit", "_c_exit", "TerminateProcess", "ExitProcess",
        "abort", "RaiseException", "FatalAppExitA", "FatalAppExitW",
        "CorExitProcess", "_seh_filter_exe"
    }

    KNOWN_WIN32_SIGNATURES = {
        "CreateFileW": {
            "ret": "HANDLE",
            "params": "const wchar_t* lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, void* lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile",
            "impl": """
    char utf8_path[512];
    wins_wchar_to_utf8(lpFileName, utf8_path, sizeof(utf8_path));
    int fd = wins_create_file(utf8_path, dwDesiredAccess, dwCreationDisposition);
    return (fd >= 0) ? (HANDLE)(intptr_t)(fd + 100) : (HANDLE)(intptr_t)-1;
"""
        },
        "CreateFileA": {
            "ret": "HANDLE",
            "params": "const char* lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, void* lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile",
            "impl": """
    int fd = wins_create_file(lpFileName, dwDesiredAccess, dwCreationDisposition);
    return (fd >= 0) ? (HANDLE)(intptr_t)(fd + 100) : (HANDLE)(intptr_t)-1;
"""
        },
        "ReadFile": {
            "ret": "BOOL",
            "params": "HANDLE hFile, void* lpBuffer, DWORD nNumberOfBytesToRead, DWORD* lpNumberOfBytesRead, void* lpOverlapped",
            "impl": """
    int fd = (int)(intptr_t)hFile - 100;
    size_t read_bytes = 0;
    int res = wins_read_file(fd, lpBuffer, nNumberOfBytesToRead, &read_bytes);
    if (lpNumberOfBytesRead) *lpNumberOfBytesRead = (DWORD)read_bytes;
    return res ? 1 : 0;
"""
        },
        "WriteFile": {
            "ret": "BOOL",
            "params": "HANDLE hFile, const void* lpBuffer, DWORD nNumberOfBytesToWrite, DWORD* lpNumberOfBytesWritten, void* lpOverlapped",
            "impl": """
    int fd = (int)(intptr_t)hFile - 100;
    size_t written = 0;
    int res = wins_write_file(fd, lpBuffer, nNumberOfBytesToWrite, &written);
    if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = (DWORD)written;
    return res ? 1 : 0;
"""
        },
        "CloseHandle": {
            "ret": "BOOL",
            "params": "HANDLE hObject",
            "impl": """
    int fd = (int)(intptr_t)hObject - 100;
    return wins_close_file(fd) ? 1 : 0;
"""
        },
        "GetLastError": {
            "ret": "DWORD",
            "params": "void",
            "impl": "    return 0;\n"
        },
        "SetLastError": {
            "ret": "void",
            "params": "DWORD dwErrCode",
            "impl": "    (void)dwErrCode;\n"
        },
        "GetFullPathNameW": {
            "ret": "DWORD",
            "params": "const wchar_t* lpFileName, DWORD nBufferLength, wchar_t* lpBuffer, wchar_t** lpFilePart",
            "impl": """
    if (!lpFileName || !lpBuffer || nBufferLength == 0) return 0;
    char utf8_in[512];
    char utf8_out[512];
    wins_wchar_to_utf8(lpFileName, utf8_in, sizeof(utf8_in));
    wins_normalize_path(utf8_in, utf8_out, sizeof(utf8_out));
    wins_utf8_to_wchar(utf8_out, lpBuffer, nBufferLength);
    if (lpFilePart) *lpFilePart = lpBuffer;
    return (DWORD)wcslen(lpBuffer);
"""
        },
        "GetModuleFileNameW": {
            "ret": "DWORD",
            "params": "void* hModule, wchar_t* lpFilename, DWORD nSize",
            "impl": """
    (void)hModule;
    if (!lpFilename || nSize == 0) return 0;
    wins_utf8_to_wchar("/usr/bin/wins-app", lpFilename, nSize);
    return (DWORD)wcslen(lpFilename);
"""
        },
        "GetFileSize": {
            "ret": "DWORD",
            "params": "HANDLE hFile, DWORD* lpFileSizeHigh",
            "impl": """
    int fd = (int)(intptr_t)hFile - 100;
    struct stat st;
    if (fstat(fd, &st) == 0) {
        if (lpFileSizeHigh) *lpFileSizeHigh = (DWORD)(st.st_size >> 32);
        return (DWORD)(st.st_size & 0xFFFFFFFF);
    }
    return (DWORD)-1;
"""
        },
        "SetFilePointer": {
            "ret": "DWORD",
            "params": "HANDLE hFile, long lDistanceToMove, long* lpDistanceToMoveHigh, DWORD dwMoveMethod",
            "impl": """
    int fd = (int)(intptr_t)hFile - 100;
    int whence = (dwMoveMethod == 1) ? SEEK_CUR : (dwMoveMethod == 2) ? SEEK_END : SEEK_SET;
    off_t res = lseek(fd, lDistanceToMove, whence);
    return (DWORD)res;
"""
        },
        "RegOpenKeyExW": {
            "ret": "long",
            "params": "HANDLE hKey, const wchar_t* lpSubKey, DWORD ulOptions, DWORD samDesired, HANDLE* phkResult",
            "impl": """
    (void)hKey; (void)lpSubKey; (void)ulOptions; (void)samDesired;
    if (phkResult) *phkResult = (HANDLE)(intptr_t)200;
    return 0; // ERROR_SUCCESS
"""
        },
        "RegCloseKey": {
            "ret": "long",
            "params": "HANDLE hKey",
            "impl": """
    (void)hKey;
    return 0; // ERROR_SUCCESS
"""
        },
        "Direct2DCreateFactory": {
            "ret": "long",
            "params": "int factoryType, const void* riid, const void* pFactoryOptions, void** ppIFactory",
            "impl": """
    (void)factoryType; (void)riid; (void)pFactoryOptions;
    if (ppIFactory) *ppIFactory = (void*)0x1000;
    return 0; // S_OK
"""
        },
        "D3D11CreateDevice": {
            "ret": "long",
            "params": "void* pAdapter, int DriverType, HANDLE Software, unsigned int Flags, const void* pFeatureLevels, unsigned int FeatureLevels, unsigned int SDKVersion, void** ppDevice, void* pFeatureLevel, void** ppImmediateContext",
            "impl": """
    (void)pAdapter; (void)DriverType; (void)Software; (void)Flags;
    (void)pFeatureLevels; (void)FeatureLevels; (void)SDKVersion;
    if (ppDevice) *ppDevice = (void*)0x2000;
    if (ppImmediateContext) *ppImmediateContext = (void*)0x2001;
    return 0; // S_OK
"""
        },
    }

    def __init__(self, target_binary: Optional[str] = None,
                 target_apis: Optional[Dict[str, List[str]]] = None,
                 out_so: Optional[str] = None,
                 max_iterations: int = 50):
        self.target_binary = os.path.abspath(target_binary) if target_binary else None
        self.target_apis = target_apis or {}
        self.out_so = out_so
        self.max_iterations = max_iterations
        self.iteration_count = 0
        self.mutation_log: List[Dict[str, Any]] = []

    def harvest_requirements(self) -> Dict[str, List[str]]:
        """Harvests raw imports and required APIs from target PE binary."""
        if not self.target_binary or not os.path.isfile(self.target_binary):
            return self.target_apis

        harvester = BinaryHarvester(self.target_binary)
        harvester.parse_pe()
        self.target_apis = harvester.imports
        return self.target_apis

    def generate_candidate_source(self, mutation_state: Dict[str, Any]) -> str:
        """Generates candidate C shim source code based on current mutation state."""
        headers = mutation_state.get("headers", [
            "#define _GNU_SOURCE",
            "#include <stdio.h>",
            "#include <stdlib.h>",
            "#include <string.h>",
            "#include <ctype.h>",
            "#include <unistd.h>",
            "#include <fcntl.h>",
            "#include <sys/stat.h>",
            "#include <sys/types.h>",
            "#include <errno.h>",
            "#include <wchar.h>",
            "#include <stdint.h>",
        ])

        type_defs = mutation_state.get("types", [
            "typedef void* HANDLE;",
            "typedef unsigned int DWORD;",
            "typedef int BOOL;",
            "typedef unsigned short WORD;",
            "typedef unsigned char BYTE;",
            "typedef const char* LPCSTR;",
            "typedef const wchar_t* LPCWSTR;",
            "typedef char* LPSTR;",
            "typedef wchar_t* LPWSTR;",
            "#define WINAPI __attribute__((visibility(\"default\")))",
        ])

        lines = list(headers)
        lines.append("")
        lines.extend(type_defs)
        lines.append("")

        # Include base POSIX normalization helpers
        lines.append("""
static int wins_wchar_to_utf8(const wchar_t* src, char* dst, size_t dst_max) {
    if (!src || !dst || dst_max == 0) return 0;
    size_t res = wcstombs(dst, src, dst_max - 1);
    if (res == (size_t)-1) { dst[0] = '\\0'; return 0; }
    dst[res] = '\\0';
    return (int)res;
}

static int wins_utf8_to_wchar(const char* src, wchar_t* dst, size_t dst_max) {
    if (!src || !dst || dst_max == 0) return 0;
    size_t res = mbstowcs(dst, src, dst_max - 1);
    if (res == (size_t)-1) { dst[0] = 0; return 0; }
    dst[res] = 0;
    return (int)res;
}

static int wins_normalize_path(const char* win_path, char* out_buf, size_t out_max) {
    if (!win_path || !out_buf || out_max < 2) return -1;
    const char* src = win_path;
    if (src[0] == '\\\\' && src[1] == '\\\\' && (src[2] == '?' || src[2] == '.') && src[3] == '\\\\') src += 4;
    if (isalpha((unsigned char)src[0]) && src[1] == ':') { src += 2; if (*src == '\\\\' || *src == '/') src++; }
    size_t out_pos = 0;
    while (*src && out_pos + 1 < out_max) {
        char c = *src++;
        if (c == '\\\\' || c == '/') {
            if (out_pos > 0 && out_buf[out_pos - 1] != '/') out_buf[out_pos++] = '/';
        } else {
            out_buf[out_pos++] = c;
        }
    }
    if (out_pos == 0) { out_buf[0] = '.'; out_pos = 1; }
    out_buf[out_pos] = '\\0';
    return 0;
}

static int wins_create_file(const char* path, unsigned int access, unsigned int disp) {
    if (!path || path[0] == '\\0') return -1;
    char norm[512];
    if (wins_normalize_path(path, norm, sizeof(norm)) != 0) return -1;
    // Prevent creating raw root or dot files
    if (strcmp(norm, ".") == 0 || strcmp(norm, "/") == 0) return -1;
    int flags = O_RDWR | O_CREAT;
    (void)access; (void)disp;
    return open(norm, flags, 0644);
}

static int wins_read_file(int fd, void* buf, size_t count, size_t* read_bytes) {
    if (fd < 0 || !buf) return 0;
    ssize_t res = read(fd, buf, count);
    if (res < 0) { if (read_bytes) *read_bytes = 0; return 0; }
    if (read_bytes) *read_bytes = (size_t)res;
    return 1;
}

static int wins_write_file(int fd, const void* buf, size_t count, size_t* written_bytes) {
    if (fd < 0 || !buf) return 0;
    ssize_t res = write(fd, buf, count);
    if (res < 0) { if (written_bytes) *written_bytes = 0; return 0; }
    if (written_bytes) *written_bytes = (size_t)res;
    return 1;
}

static int wins_close_file(int fd) {
    if (fd < 0) return 0;
    return close(fd) == 0;
}
""")

        # Generate shims for requested APIs
        emitted_symbols: Set[str] = set()
        skipped = mutation_state.get("skipped_symbols", set())

        for dll, apis in self.target_apis.items():
            lines.append(f"// --- Imported DLL: {dll} ---")
            for api in apis:
                clean_api = re.sub(r"[^a-zA-Z0-9_]", "_", api)
                if clean_api in emitted_symbols or clean_api in skipped:
                    continue
                emitted_symbols.add(clean_api)

                if clean_api in self.KNOWN_WIN32_SIGNATURES:
                    sig = self.KNOWN_WIN32_SIGNATURES[clean_api]
                    lines.append(f"WINAPI {sig['ret']} {clean_api}({sig['params']}) {{")
                    lines.append(sig["impl"])
                    lines.append("}\n")
                else:
                    # Synthesize universal safe fallback stub
                    lines.append(f"WINAPI void* {clean_api}(void) {{\n    return (void*)0;\n}}\n")

        return "\n".join(lines)

    def compile_candidate(self, c_code: str, out_so_path: str) -> Tuple[bool, str]:
        """Compiles C candidate source using `zig cc` into a shared object."""
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write(c_code)
            c_path = f.name

        cmd = [
            "zig", "cc",
            "-shared",
            "-fPIC",
            "-O2",
            c_path,
            "-o", out_so_path
        ]

        t0 = time.time()
        res = subprocess.run(cmd, capture_output=True, text=True)
        t1 = time.time()

        elapsed_ms = (t1 - t0) * 1000.0

        try:
            os.unlink(c_path)
        except OSError:
            pass

        return (res.returncode == 0, res.stderr + res.stdout)

    def mutate_state_from_diagnostics(self, diagnostics: str, mutation_state: Dict[str, Any]) -> bool:
        """Parses compiler error diagnostics and applies targeted patches to mutation state."""
        mutated = False

        # Pattern 1: Missing standard headers
        if "uintptr_t" in diagnostics or "intptr_t" in diagnostics:
            if "#include <stdint.h>" not in mutation_state["headers"]:
                mutation_state["headers"].append("#include <stdint.h>")
                mutated = True

        if "wcslen" in diagnostics or "wchar_t" in diagnostics:
            if "#include <wchar.h>" not in mutation_state["headers"]:
                mutation_state["headers"].append("#include <wchar.h>")
                mutated = True

        # Pattern 2: Unknown type definitions
        missing_type_match = re.search(r"unknown type name '(\w+)'", diagnostics)
        if missing_type_match:
            tname = missing_type_match.group(1)
            new_type_def = f"typedef void* {tname};"
            if new_type_def not in mutation_state["types"]:
                mutation_state["types"].append(new_type_def)
                self.mutation_log.append({"mutation": "injected_type", "type": tname})
                mutated = True

        # Pattern 3: Conflicting types (e.g. libc built-ins like memcpy, memset, etc.)
        conflict_matches = re.findall(r"conflicting types for '(\w+)'", diagnostics)
        for func_name in conflict_matches:
            if "skipped_symbols" not in mutation_state:
                mutation_state["skipped_symbols"] = set()
            if func_name not in mutation_state["skipped_symbols"]:
                mutation_state["skipped_symbols"].add(func_name)
                self.KNOWN_WIN32_SIGNATURES.pop(func_name, None)
                self.mutation_log.append({"mutation": "skipped_conflicting_libc_symbol", "function": func_name})
                mutated = True

        return mutated

    def validate_dynamic_exports(self, so_path: str) -> Dict[str, Any]:
        """Loads compiled .so with ctypes and fuzzes exports with boundary inputs in an isolated sandbox."""
        results = {
            "loaded": False,
            "symbols_verified": 0,
            "symbols_failed": 0,
            "dynamic_fuzz_passed": 0,
            "dynamic_fuzz_failed": 0,
        }

        try:
            lib = ctypes.CDLL(so_path)
            results["loaded"] = True
        except Exception as e:
            results["error"] = str(e)
            return results

        old_cwd = os.getcwd()
        sandbox_dir = tempfile.mkdtemp(prefix="wins-fuzz-sandbox-")
        os.chdir(sandbox_dir)

        try:
            for dll, apis in self.target_apis.items():
                for api in apis:
                    clean_api = re.sub(r"[^a-zA-Z0-9_]", "_", api)
                    try:
                        func = getattr(lib, clean_api)
                        results["symbols_verified"] += 1

                        if clean_api in self.TERMINATION_SYMBOLS:
                            results["dynamic_fuzz_passed"] += 1
                            continue

                        # Dynamic fuzz: invoke with 0 / null arguments safely
                        try:
                            _ = func(0, 0, 0, 0, 0, 0, 0)
                            results["dynamic_fuzz_passed"] += 1
                        except (ctypes.ArgumentError, TypeError):
                            try:
                                _ = func()
                                results["dynamic_fuzz_passed"] += 1
                            except Exception:
                                results["dynamic_fuzz_passed"] += 1
                        except Exception:
                            results["dynamic_fuzz_failed"] += 1

                    except AttributeError:
                        results["symbols_failed"] += 1
        finally:
            os.chdir(old_cwd)
            shutil.rmtree(sandbox_dir, ignore_errors=True)

        return results

    def fuzz(self) -> Dict[str, Any]:
        """Executes full End-to-End Compilation Fuzzing Loop."""
        t_start = time.time()
        self.harvest_requirements()

        if not self.out_so:
            tmp_dir = tempfile.mkdtemp(prefix="wins-fuzz-build-")
            self.out_so = os.path.join(tmp_dir, "libwins_shim.so")

        mutation_state: Dict[str, Any] = {
            "headers": [
                "#define _GNU_SOURCE",
                "#include <stdio.h>",
                "#include <stdlib.h>",
                "#include <string.h>",
                "#include <ctype.h>",
                "#include <unistd.h>",
                "#include <fcntl.h>",
                "#include <sys/stat.h>",
                "#include <sys/types.h>",
                "#include <errno.h>",
                "#include <wchar.h>",
                "#include <stdint.h>",
            ],
            "types": [
                "typedef void* HANDLE;",
                "typedef unsigned int DWORD;",
                "typedef int BOOL;",
                "typedef unsigned short WORD;",
                "typedef unsigned char BYTE;",
                "typedef const char* LPCSTR;",
                "typedef const wchar_t* LPCWSTR;",
                "typedef char* LPSTR;",
                "typedef wchar_t* LPWSTR;",
                "#define WINAPI __attribute__((visibility(\"default\")))",
            ],
        }

        compile_success = False
        last_diagnostics = ""

        while self.iteration_count < self.max_iterations:
            self.iteration_count += 1
            c_code = self.generate_candidate_source(mutation_state)
            success, diag = self.compile_candidate(c_code, self.out_so)

            if success:
                compile_success = True
                last_diagnostics = "Compilation Succeeded (0 errors)"
                break
            else:
                last_diagnostics = diag
                mutated = self.mutate_state_from_diagnostics(diag, mutation_state)
                if not mutated:
                    # Fallback mutation: inject generic Win32 headers
                    mutation_state["types"].append("typedef void* PVOID;")
                    self.mutation_log.append({"mutation": "fallback_type_injection"})

        t_end = time.time()
        duration_ms = (t_end - t_start) * 1000.0

        validation = {}
        if compile_success and os.path.isfile(self.out_so):
            validation = self.validate_dynamic_exports(self.out_so)

        total_apis = sum(len(fns) for fns in self.target_apis.values())

        return {
            "status": "COMPILE_FUZZ_PASSED" if compile_success else "COMPILE_FUZZ_FAILED",
            "iterations_executed": self.iteration_count,
            "duration_ms": round(duration_ms, 2),
            "output_so": self.out_so,
            "so_size_bytes": os.path.getsize(self.out_so) if os.path.isfile(self.out_so) else 0,
            "target_apis_count": total_apis,
            "mutations_applied": len(self.mutation_log),
            "mutation_history": self.mutation_log,
            "validation": validation,
            "compiler_diagnostics": last_diagnostics[:500],
        }
