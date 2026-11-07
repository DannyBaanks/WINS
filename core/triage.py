#!/usr/bin/env python3
"""
WINS Core - Binary Triage & Classifier
Analyzes Windows executables and installers to determine their true internal
runtime taxonomy (Electron, PyInstaller, .NET, JVM, or Native Win32).
"""

import sys
import os
import re
import json
import hashlib
import subprocess
import shutil
from typing import Dict, Any, Optional

class BinaryTriage:
    def __init__(self, file_path: str):
        self.file_path = os.path.abspath(file_path)
        if not os.path.isfile(self.file_path):
            raise FileNotFoundError(f"Target binary not found: {self.file_path}")
        self.file_size = os.path.getsize(self.file_path)
        self.sha256 = self._compute_sha256()

    def _compute_sha256(self) -> str:
        hasher = hashlib.sha256()
        with open(self.file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _find_7z(self) -> Optional[str]:
        for candidate in ["7zz", "7z"]:
            path = shutil.which(candidate)
            if path:
                return path
        # Check standard cache
        cached = os.path.expanduser("~/.cache/electron-builder/7zip@1.0.0/7zip-linux-x64-16wjr/bin/7zz")
        if os.path.isfile(cached) and os.access(cached, os.X_OK):
            return cached
        return None

    def probe(self) -> Dict[str, Any]:
        """Runs multi-stage static heuristic probing on the binary."""
        with open(self.file_path, "rb") as f:
            # Read first 1MB and last 1MB for envelopes and overlays
            f.seek(0)
            sample_start = f.read(1024 * 1024)
            f.seek(max(0, self.file_size - 1024 * 1024))
            sample_end = f.read(1024 * 1024)

        sample_bytes = sample_start + sample_end
        envelope = self._detect_envelope(sample_bytes)

        # Deep envelope inspection if available
        runtime_info = None
        if envelope["type"] in ["nsis", "inno", "7z_sfx"]:
            runtime_info = self._probe_installer_contents()

        if not runtime_info:
            runtime_info = self._detect_runtime(sample_bytes)

        report = {
            "target": {
                "path": self.file_path,
                "name": os.path.basename(self.file_path),
                "size_bytes": self.file_size,
                "size_human": f"{self.file_size / (1024 * 1024):.1f} MB",
                "sha256": self.sha256,
            },
            "envelope": envelope,
            "runtime": runtime_info["runtime"],
            "runtime_details": runtime_info["details"],
            "feasibility": runtime_info["feasibility"],
            "recommended_recipe": runtime_info["recipe"],
        }
        return report

    def _detect_envelope(self, data: bytes) -> Dict[str, Any]:
        if b"NullsoftInst" in data or b"Nullsoft.NSIS" in data:
            return {"type": "nsis", "name": "Nullsoft Scriptable Install System (NSIS)"}
        if b"Inno Setup" in data:
            return {"type": "inno", "name": "Inno Setup Installer"}
        if b"msi" in data[:1024].lower() or b"wix" in data[:1024].lower():
            return {"type": "wix_msi", "name": "Windows Installer (MSI/WiX)"}
        if b"7z\xbc\xaf\x27\x1c" in data:
            return {"type": "7z_sfx", "name": "7-Zip Self-Extracting Archive"}
        return {"type": "standalone_pe", "name": "Standalone Portable Executable"}

    def _probe_installer_contents(self) -> Optional[Dict[str, Any]]:
        sz = self._find_7z()
        if not sz:
            return None
        try:
            res = subprocess.run([sz, "l", self.file_path], capture_output=True, text=True, timeout=5)
            output = res.stdout
            if "app.asar" in output or "app-64.7z" in output or "app-32.7z" in output:
                return {
                    "runtime": "electron",
                    "details": {
                        "framework": "Electron (Chromium + Node.js Web Architecture)",
                        "envelope_compression": "NSIS + Embedded 7z payload",
                        "contains_asar": True,
                    },
                    "feasibility": "EXCELLENT (100% native Linux re-hosting; 0 Wine emulation required)",
                    "recipe": "recipe_electron",
                }
            if "_MEI" in output or "pyi-runtime" in output or "python" in output.lower():
                return {
                    "runtime": "pyinstaller",
                    "details": {
                        "framework": "PyInstaller Frozen Python Archive",
                    },
                    "feasibility": "HIGH (Bytecode extractable to native Linux Python 3)",
                    "recipe": "recipe_pyinstaller",
                }
        except Exception:
            pass
        return None

    def _detect_runtime(self, data: bytes) -> Dict[str, Any]:
        # 1. Electron / Web
        if b"app.asar" in data or b"Electron" in data or b"v8_context_snapshot" in data:
            version_match = re.search(rb"Electron/([0-9]+\.[0-9]+\.[0-9]+)", data)
            version = version_match.group(1).decode("utf-8") if version_match else "unknown"
            return {
                "runtime": "electron",
                "details": {
                    "framework": "Electron (Chromium + Node.js)",
                    "detected_version": version,
                    "asar_embedded": b"app.asar" in data,
                },
                "feasibility": "EXCELLENT (100% native re-hosting with 0 wine dependencies)",
                "recipe": "recipe_electron",
            }

        # 2. PyInstaller
        if b"MEI\x0c\x0b\x0a\x0b" in data or b"pyi-runtime-tmpdir" in data or b"libpython" in data:
            return {
                "runtime": "pyinstaller",
                "details": {
                    "framework": "PyInstaller Frozen Python Archive",
                    "python_target": "CPython bytecode",
                },
                "feasibility": "HIGH (Bytecode extractable to native Python 3 runtime)",
                "recipe": "recipe_pyinstaller",
            }

        # 3. .NET Core / CIL
        if b"BSJB" in data or b"mscoree.dll" in data:
            return {
                "runtime": "dotnet",
                "details": {
                    "framework": "Microsoft .NET / CIL Assembly",
                    "requires": "dotnet-runtime",
                },
                "feasibility": "HIGH (Direct execution via Linux native `dotnet` host)",
                "recipe": "recipe_dotnet",
            }

        # 4. Java / JVM
        if b"Launch4j" in data or b"META-INF/MANIFEST.MF" in data:
            return {
                "runtime": "jvm",
                "details": {
                    "framework": "Java Virtual Machine (JAR in PE wrapper)",
                    "requires": "default-jre",
                },
                "feasibility": "EXCELLENT (Extract JAR and execute via native `java -jar`)",
                "recipe": "recipe_jvm",
            }

        # 5. Native Win32 PE
        return {
            "runtime": "native_pe",
            "details": {
                "framework": "Native Compiled Win32/x86_64 Machine Code",
                "imports": "Kernel32 / User32 direct dependencies",
            },
            "feasibility": "REQUIRES_ISOLATED_EMULATION (Pure Win32 C/C++ binary)",
            "recipe": "recipe_micro_wine",
        }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: triage.py <path-to-executable.exe>")
        sys.exit(1)
    triage = BinaryTriage(sys.argv[1])
    print(json.dumps(triage.probe(), indent=2))
