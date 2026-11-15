"""
WINS Core Recipe - Universal .NET / Avalonia Re-hosting Substrate
De-layers managed CIL assemblies (.NET Core / 8+), extracts payloads via
cleanroom unpacking, adapts runtime configurations, and re-hosts them on native
Linux `dotnet` with Avalonia X11/Wayland UI backends.
"""

import os
import sys
import json
import shutil
import subprocess
import tempfile
import re
from typing import Dict, Any, List, Optional, Tuple
from .base import BaseRecipe

class DotNetRecipe(BaseRecipe):
    name = "dotnet"
    description = "Universal .NET Core & Avalonia Cross-Platform Transmuter"

    def can_handle(self, triage: Dict[str, Any]) -> bool:
        return triage.get("runtime") in ["dotnet", "dotnet_core", "dotnet_avalonia"]

    def transmute(self, triage: Dict[str, Any], dest_dir: str, options: Dict[str, Any]) -> bool:
        target_path = triage["target"]["path"]
        target_name = triage["target"]["name"]
        print(f"[WINS:DotNet] Initiating transmutation for {target_name}...")

        scratch = tempfile.mkdtemp(prefix="wins-dotnet-cleanroom-")
        try:
            # 1. Cleanroom Payload Extraction
            payload_dir = os.path.join(scratch, "payload")
            os.makedirs(payload_dir, exist_ok=True)
            if not self._extract_payload(target_path, payload_dir, triage.get("envelope", {}).get("type", "unknown")):
                print("[WINS:DotNet:ERROR] Failed to extract installer payload.", file=sys.stderr)
                return False

            # 2. Locate Main Assembly and Metadata
            main_dll, runtime_cfg, deps_cfg = self._locate_net_entrypoint(payload_dir)
            if not main_dll:
                print("[WINS:DotNet:ERROR] Could not identify managed .NET entrypoint (.dll).", file=sys.stderr)
                return False

            app_id = os.path.splitext(os.path.basename(main_dll))[0].lower()
            app_title = os.path.splitext(os.path.basename(main_dll))[0]
            print(f"[WINS:DotNet] Located application entrypoint: {os.path.basename(main_dll)}")

            # 3. Analyze Framework & UI Toolkit
            has_avalonia = any("avalonia" in f.lower() for f in os.listdir(payload_dir))
            tfm = self._inspect_target_framework(runtime_cfg)
            host_dotnet_ver = self._get_host_dotnet_version()

            print(f"[WINS:DotNet] Runtime Analysis:")
            print(f"  Target Framework: {tfm or 'unspecified'}")
            print(f"  Host .NET Version: {host_dotnet_ver or 'not installed'}")
            print(f"  Avalonia X11 UI Backend: {'Detected' if has_avalonia else 'Not detected'}")

            # 4. Adapt Runtime Configuration for Linux Host
            if runtime_cfg:
                self._adapt_runtime_config(runtime_cfg, tfm)

            # 5. Wire Host Linux Native .NET Libraries
            self._link_host_net_runtimes(payload_dir)

            # 6. Assemble in Destination Directory
            print(f"[WINS:DotNet] Assembling native application in {dest_dir}...")
            if os.path.exists(dest_dir):
                shutil.rmtree(dest_dir)
            os.makedirs(dest_dir, exist_ok=True)

            for item in os.listdir(payload_dir):
                s = os.path.join(payload_dir, item)
                d = os.path.join(dest_dir, item)
                if os.path.isdir(s):
                    shutil.copytree(s, d)
                elif os.path.isfile(s) or os.path.islink(s):
                    shutil.copy2(s, d, follow_symlinks=False)

            # 7. Generate Launcher Script
            bin_dir = os.path.expanduser(options.get("bin_dir", "~/.local/bin"))
            os.makedirs(bin_dir, exist_ok=True)
            launcher_path = os.path.join(bin_dir, app_id)

            env_exports = ""
            if has_avalonia:
                env_exports = "export AVALONIA_PLATFORM=x11\nexport DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1\n"

            with open(launcher_path, "w", encoding="utf-8") as f:
                f.write(f"""#!/usr/bin/env bash
# WINS Generated Launcher for {app_title} (.NET)
APP_DIR="{dest_dir}"
{env_exports}cd "$APP_DIR" || exit 1
exec dotnet "$APP_DIR/{os.path.basename(main_dll)}" "$@"
""")
            os.chmod(launcher_path, 0o755)
            print(f"[WINS:DotNet] [✓] Launcher created: {launcher_path}")

            # 8. Register Desktop Entry
            self._register_desktop_entry(app_id, app_title, launcher_path, dest_dir)

            print(f"[WINS:DotNet] [✓] Transmutation complete! Launch with '{app_id}'.")
            return True

        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def _extract_payload(self, target_exe: str, payload_dir: str, envelope_type: str) -> bool:
        """Extracts installer using static tools first, then cleanroom sandbox."""
        # 1. Innoextract for Inno Setup
        inno = shutil.which("innoextract") or os.path.expanduser("~/.local/bin/innoextract")
        if inno and os.path.isfile(inno) and os.access(inno, os.X_OK):
            temp_extract = os.path.join(payload_dir, "_inno_tmp")
            res = subprocess.run([inno, "-d", temp_extract, target_exe], capture_output=True, timeout=15)
            if res.returncode == 0:
                app_sub = os.path.join(temp_extract, "app")
                copy_src = app_sub if os.path.isdir(app_sub) else temp_extract
                for f in os.listdir(copy_src):
                    s = os.path.join(copy_src, f)
                    d = os.path.join(payload_dir, f)
                    if os.path.isdir(s):
                        shutil.copytree(s, d)
                    else:
                        shutil.copy2(s, d)
                shutil.rmtree(temp_extract, ignore_errors=True)
                return True

        # 2. 7z extraction for NSIS / 7z
        sz = shutil.which("7zz") or shutil.which("7z")
        cached_sz = os.path.expanduser("~/.cache/electron-builder/7zip@1.0.0/7zip-linux-x64-16wjr/bin/7zz")
        if not sz and os.path.isfile(cached_sz):
            sz = cached_sz

        if sz and envelope_type != "inno":
            res = subprocess.run([sz, "x", "-y", target_exe, f"-o{payload_dir}"], capture_output=True)
            if res.returncode == 0 and any(f.endswith(".dll") for f in os.listdir(payload_dir)):
                return True

        # Unsupported installers fail closed; never execute them for extraction.
        return False

    def _locate_net_entrypoint(self, payload_dir: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        main_dll = None
        runtime_cfg = None
        deps_cfg = None

        # Look for *.runtimeconfig.json
        for f in os.listdir(payload_dir):
            if f.endswith(".runtimeconfig.json"):
                runtime_cfg = os.path.join(payload_dir, f)
                candidate_dll = os.path.join(payload_dir, f.replace(".runtimeconfig.json", ".dll"))
                if os.path.isfile(candidate_dll):
                    main_dll = candidate_dll
            elif f.endswith(".deps.json"):
                deps_cfg = os.path.join(payload_dir, f)

        # Fallback to .dll with matching .exe name
        if not main_dll:
            exes = [f for f in os.listdir(payload_dir) if f.endswith(".exe")]
            for exe in exes:
                cand = os.path.join(payload_dir, exe.replace(".exe", ".dll"))
                if os.path.isfile(cand):
                    main_dll = cand
                    break

        return main_dll, runtime_cfg, deps_cfg

    def _inspect_target_framework(self, runtime_cfg: Optional[str]) -> Optional[str]:
        if not runtime_cfg or not os.path.isfile(runtime_cfg):
            return None
        try:
            with open(runtime_cfg, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("runtimeOptions", {}).get("tfm")
        except Exception:
            return None

    def _get_host_dotnet_version(self) -> Optional[str]:
        if not shutil.which("dotnet"):
            return None
        try:
            out = subprocess.check_output(["dotnet", "--version"], text=True).strip()
            return out
        except Exception:
            return None

    def _adapt_runtime_config(self, runtime_cfg: str, tfm: Optional[str]):
        """Adjusts runtimeconfig.json for Linux execution."""
        try:
            with open(runtime_cfg, "r", encoding="utf-8") as f:
                data = json.load(f)
            ro = data.get("runtimeOptions", {})

            # Ensure host knows it can bind to Linux Microsoft.NETCore.App
            if "includedFrameworks" in ro:
                ro["framework"] = {
                    "name": "Microsoft.NETCore.App",
                    "version": "8.0.0"
                }
            if "configProperties" not in ro:
                ro["configProperties"] = {}
            ro["configProperties"]["System.Globalization.UseNls"] = False

            with open(runtime_cfg, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[WINS:DotNet:WARN] Could not adapt runtimeconfig: {e}", file=sys.stderr)

    def _link_host_net_runtimes(self, payload_dir: str):
        """Symlinks host Linux native .so libraries for .NET Core."""
        host_net_dir = "/usr/lib/dotnet/shared/Microsoft.NETCore.App"
        if not os.path.isdir(host_net_dir):
            return
        # Find latest version
        versions = sorted(os.listdir(host_net_dir))
        if not versions:
            return
        latest_ver_dir = os.path.join(host_net_dir, versions[-1])

        for f in os.listdir(latest_ver_dir):
            if f.endswith(".so"):
                target = os.path.join(payload_dir, f)
                if not os.path.exists(target):
                    try:
                        os.symlink(os.path.join(latest_ver_dir, f), target)
                    except Exception:
                        pass

    def _register_desktop_entry(self, app_id: str, title: str, launcher_path: str, app_dir: str):
        desktop_dir = os.path.expanduser("~/.local/share/applications")
        os.makedirs(desktop_dir, exist_ok=True)
        desktop_file = os.path.join(desktop_dir, f"{app_id}.desktop")

        # Find .ico or .png
        icon_path = ""
        for root, _, files in os.walk(app_dir):
            for f in files:
                if f.endswith(".png") or f.endswith(".ico"):
                    icon_path = os.path.join(root, f)
                    break
            if icon_path:
                break

        content = f"""[Desktop Entry]
Name={title}
Exec={launcher_path} %U
Terminal=false
Type=Application
Categories=Utility;Application;
"""
        if icon_path:
            content += f"Icon={icon_path}\n"

        with open(desktop_file, "w", encoding="utf-8") as f:
            f.write(content)
