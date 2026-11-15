"""
WINS Core Recipe - Semantic Transpiler & Candidate Re-hosting (Zero-Win32)
De-layers native Win32 PE binaries, extracts embedded libraries and assets,
and maps execution to verified Linux native engines with POSIX shimming.
"""

import os
import sys
import json
import shutil
import subprocess
import tempfile
from typing import Dict, Any, List, Optional
from .base import BaseRecipe
from ..transpiler.harvester import BinaryHarvester

class TranspilerRecipe(BaseRecipe):
    name = "transpiler"
    description = "Semantic Candidate Re-hosting & Transpiler Recipe (Zero-Win32)"

    def can_handle(self, triage: Dict[str, Any]) -> bool:
        return triage.get("runtime") == "native_pe" or triage.get("recommended_recipe") == "recipe_transpiler"

    def transmute(self, triage: Dict[str, Any], dest_dir: str, options: Dict[str, Any]) -> bool:
        target_path = triage["target"]["path"]
        target_name = triage["target"]["name"]
        print(f"[WINS:Transpiler] Initiating semantic transmutation for {target_name}...")

        scratch = tempfile.mkdtemp(prefix="wins-transpiler-")
        try:
            # 1. Cleanroom Payload Extraction
            payload_dir = os.path.join(scratch, "payload")
            os.makedirs(payload_dir, exist_ok=True)
            if not self._extract_payload(target_path, payload_dir):
                print("[WINS:Transpiler:ERROR] Failed to extract installer payload.", file=sys.stderr)
                return False

            # 2. Locate Main PE Binary
            main_exe = self._locate_main_exe(payload_dir)
            if not main_exe:
                print("[WINS:Transpiler:ERROR] Could not locate primary PE executable.", file=sys.stderr)
                return False

            app_id = os.path.splitext(os.path.basename(main_exe))[0].lower().replace("++", "pp")
            app_title = os.path.splitext(os.path.basename(main_exe))[0]
            print(f"[WINS:Transpiler] Located application binary: {os.path.basename(main_exe)}")

            # 3. Semantic Candidate Harvesting
            harvester = BinaryHarvester(main_exe)
            harvest_rep = harvester.harvest()
            print(f"[WINS:Transpiler] [✓] Harvested {harvest_rep['metrics']['total_imported_apis']} APIs across {harvest_rep['metrics']['total_imported_dlls']} DLLs.")
            print(f"  POSIX Transpilability Score: {harvest_rep['metrics']['posix_transpilability_score']}")

            if harvest_rep["embedded_libraries"]:
                for lib in harvest_rep["embedded_libraries"]:
                    print(f"  Found Embedded Engine: {lib['name']} ({lib['role']})")

            # 4. Search for Native Linux Candidate Engines
            native_engine_cmd = self._find_native_engine(harvest_rep)
            if native_engine_cmd:
                print(f"[WINS:Transpiler] [✓] Discovered matching native Linux engine: {native_engine_cmd}")

            # 5. Assemble Assets in Target Destination
            print(f"[WINS:Transpiler] Assembling native Linux application assets in {dest_dir}...")
            if os.path.exists(dest_dir):
                print("[WINS:Transpiler:ERROR] Destination already exists; preserving it.", file=sys.stderr)
                return False
            os.makedirs(dest_dir, exist_ok=True)

            for item in os.listdir(payload_dir):
                s = os.path.join(payload_dir, item)
                d = os.path.join(dest_dir, item)
                if os.path.isdir(s):
                    shutil.copytree(s, d)
                elif os.path.isfile(s):
                    shutil.copy2(s, d)

            # Save harvest report in app directory
            with open(os.path.join(dest_dir, "wins_harvest_manifest.json"), "w", encoding="utf-8") as f:
                json.dump(harvest_rep, f, indent=2)

            # PE inspection is not a port. Native candidate testing is explicit in
            # the Zig cleanroom; do not execute generated shims in this process.
            print("[WINS:Transpiler] Analysis artifacts saved; native application port NOT_DEMONSTRATED.")
            print("[WINS:Transpiler] No launcher was created: a shim does not execute or port a PE.", file=sys.stderr)
            return False

        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def _extract_payload(self, target_exe: str, payload_dir: str) -> bool:
        sz = shutil.which("7zz") or shutil.which("7z")
        cached_sz = os.path.expanduser("~/.cache/electron-builder/7zip@1.0.0/7zip-linux-x64-16wjr/bin/7zz")
        if not sz and os.path.isfile(cached_sz):
            sz = cached_sz

        if sz:
            res = subprocess.run([sz, "x", "-y", target_exe, f"-o{payload_dir}"], capture_output=True)
            if res.returncode == 0:
                return True

        return False

    def _locate_main_exe(self, payload_dir: str) -> Optional[str]:
        exes = [f for f in os.listdir(payload_dir) if f.endswith(".exe")]
        if not exes:
            return None
        # Prefer non-installer / non-uninstaller
        for exe in exes:
            lower = exe.lower()
            if "uninstall" not in lower and "setup" not in lower and "gup" not in lower:
                return os.path.join(payload_dir, exe)
        return os.path.join(payload_dir, exes[0])

    def _find_native_engine(self, harvest_rep: Dict[str, Any]) -> Optional[str]:
        for lib in harvest_rep.get("embedded_libraries", []):
            if lib["id"] == "scintilla":
                if shutil.which("notepadqq"):
                    return "notepadqq"
            elif lib["id"] == "paintdotnet":
                if shutil.which("pinta"):
                    return "pinta"
                elif shutil.which("gimp"):
                    return "gimp"
        return None

    def _register_desktop_entry(self, app_id: str, title: str, launcher_path: str, dest_dir: str):
        desktop_dir = os.path.expanduser("~/.local/share/applications")
        os.makedirs(desktop_dir, exist_ok=True)
        desktop_file = os.path.join(desktop_dir, f"{app_id}.desktop")

        content = f"""[Desktop Entry]
Name={title}
Comment={title} (WINS Transmuted Native Application)
Exec={launcher_path} %U
Terminal=false
Type=Application
Categories=Utility;TextEditor;Development;
StartupWMClass={title}
"""
        with open(desktop_file, "w", encoding="utf-8") as f:
            f.write(content)

        if shutil.which("update-desktop-database"):
            subprocess.run(["update-desktop-database", desktop_dir], capture_output=True)
