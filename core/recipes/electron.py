"""
WINS Core Recipe - Universal Electron Transmuter
De-layers Electron Windows executables and re-hosts them on native Linux Electron.
"""

import os
import sys
import json
import shutil
import subprocess
import tempfile
import re
from typing import Dict, Any, List, Optional
from .base import BaseRecipe
from ..healers.native_modules import NativeModuleHealer

class ElectronRecipe(BaseRecipe):
    name = "electron"
    description = "Universal Electron De-layering & Native Re-hosting Recipe"

    def can_handle(self, triage: Dict[str, Any]) -> bool:
        return triage.get("runtime") == "electron"

    def transmute(self, triage: Dict[str, Any], dest_dir: str, options: Dict[str, Any]) -> bool:
        target_path = triage["target"]["path"]
        target_name = triage["target"]["name"]
        print(f"[WINS:Electron] Initiating transmutation for {target_name}...")

        scratch = tempfile.mkdtemp(prefix="wins-cleanroom-")
        try:
            # 1. Extract Payload
            payload_dir = os.path.join(scratch, "payload")
            os.makedirs(payload_dir, exist_ok=True)
            if not self._extract_payload(target_path, payload_dir):
                print("[WINS:Electron:ERROR] Failed to extract installer payload.", file=sys.stderr)
                return False

            # 2. Locate app.asar
            asar_path = self._find_asar(payload_dir)
            if not asar_path:
                print("[WINS:Electron:ERROR] Could not find app.asar in extracted payload.", file=sys.stderr)
                return False
            print(f"[WINS:Electron] Located application bundle: {asar_path}")

            # 3. Unpack ASAR
            app_dir = os.path.join(scratch, "app")
            os.makedirs(app_dir, exist_ok=True)
            if not self._unpack_asar(asar_path, app_dir):
                print("[WINS:Electron:ERROR] Failed to unpack app.asar.", file=sys.stderr)
                return False

            # 4. Audit & Auto-Heal Native Modules (.node)
            healer = NativeModuleHealer(target_arch=options.get("arch", "x64"))
            heal_report = healer.heal(app_dir)

            # Also heal companion unpacked resources if present
            unpacked_companion = asar_path + ".unpacked"
            if os.path.isdir(unpacked_companion):
                healer.heal(unpacked_companion)

            if heal_report["total_addons"] > 0:
                print(f"[WINS:Electron] [✓] Native Addons Healed: {len(heal_report['healed_prebuild'])} prebuilds resolved, {len(heal_report['healed_stub'])} safe stubs injected.")
            else:
                print("[WINS:Electron] [✓] Zero native C++ binary addons detected. Code is 100% portable JavaScript/TypeScript!")

            # 5. Metadata Inspection
            pkg_path = os.path.join(app_dir, "package.json")
            pkg_data = {}
            if os.path.isfile(pkg_path):
                with open(pkg_path, "r", encoding="utf-8") as f:
                    pkg_data = json.load(f)
            app_id = pkg_data.get("name", "app").lower()
            app_title = pkg_data.get("productName", pkg_data.get("description", pkg_data.get("name", "App")))
            main_script = pkg_data.get("main", "./out/main/index.js")
            if main_script.startswith("./"):
                main_script = main_script[2:]

            # 6. AST & Platform Patching
            full_main_path = os.path.join(app_dir, main_script)
            if os.path.isfile(full_main_path):
                print(f"[WINS:Electron] Applying surgical Linux platform patches to {main_script}...")
                self._patch_main_script(full_main_path)
            else:
                # Scan all JS files in main process directory
                main_dir = os.path.join(app_dir, os.path.dirname(main_script))
                if os.path.isdir(main_dir):
                    for root, _, files in os.walk(main_dir):
                        for f in files:
                            if f.endswith(".js"):
                                self._patch_main_script(os.path.join(root, f))

            # 7. Provision Native Linux Electron Runtime
            raw_electron_ver = options.get("electron_version") or pkg_data.get("devDependencies", {}).get("electron") or "35.1.4"
            electron_ver = re.sub(r'^[^\d]*', '', raw_electron_ver)
            runtime_dist = self._provision_electron_runtime(electron_ver, scratch)
            if not runtime_dist:
                print("[WINS:Electron:ERROR] Failed to provision native Electron runtime.", file=sys.stderr)
                return False

            # 8. Assemble in Target Destination
            print(f"[WINS:Electron] Assembling native Linux application in {dest_dir}...")
            if os.path.exists(dest_dir):
                shutil.rmtree(dest_dir)
            os.makedirs(dest_dir, exist_ok=True)

            # Copy runtime files
            for item in os.listdir(runtime_dist):
                src_item = os.path.join(runtime_dist, item)
                dst_item = os.path.join(dest_dir, item)
                if os.path.isdir(src_item):
                    shutil.copytree(src_item, dst_item)
                else:
                    shutil.copy2(src_item, dst_item)

            # Rename binary
            electron_bin = os.path.join(dest_dir, "electron")
            app_bin = os.path.join(dest_dir, app_id)
            if os.path.isfile(electron_bin):
                os.rename(electron_bin, app_bin)

            # Install unpacked application
            dest_resources = os.path.join(dest_dir, "resources")
            os.makedirs(dest_resources, exist_ok=True)
            default_asar = os.path.join(dest_resources, "default_app.asar")
            if os.path.isfile(default_asar):
                os.remove(default_asar)

            dest_app = os.path.join(dest_resources, "app")
            shutil.copytree(app_dir, dest_app)

            # Copy companion resources from payload (assets, i18n, etc.)
            payload_resources = os.path.dirname(asar_path)
            if os.path.isdir(payload_resources):
                for res_item in os.listdir(payload_resources):
                    if res_item == "app.asar":
                        continue
                    src_res = os.path.join(payload_resources, res_item)
                    dst_res = os.path.join(dest_resources, res_item)
                    if os.path.isdir(src_res) and not os.path.exists(dst_res):
                        shutil.copytree(src_res, dst_res)

            # Wire host MCP tools (bun, uv, uvx)
            self._wire_mcp_shims(dest_resources)

            # 8b. Heal companion PE executables shipped in resources/bin
            # (native ELF re-binding first, hardened micro-Wine shim otherwise)
            companion_report = self._heal_companion_binaries(dest_resources, app_id, options)

            # 8c. Generate the agent-facing host corpus (the agent must know it
            # drives a private Linux port, not a Windows machine)
            self._install_port_context(dest_dir, app_id, app_title, options)

            # 9. Register Launcher and Desktop Entry
            bin_dir = os.path.expanduser(options.get("bin_dir", "~/.local/bin"))
            os.makedirs(bin_dir, exist_ok=True)
            launcher_path = os.path.join(bin_dir, app_id)
            with open(launcher_path, "w", encoding="utf-8") as f:
                f.write(f"""#!/usr/bin/env bash
# WINS Generated Launcher for {app_title}
APP_DIR="{dest_dir}"
cd "$APP_DIR/resources/app" 2>/dev/null || true
exec "$APP_DIR/{app_id}" --no-sandbox "$APP_DIR/resources/app" "$@"
""")
            os.chmod(launcher_path, 0o755)
            print(f"[WINS:Electron] [✓] Launcher created: {launcher_path}")

            # Register Desktop Entry
            self._register_desktop_entry(app_id, app_title, launcher_path, dest_resources)

            print(f"[WINS:Electron] [✓] Transmutation complete! Launch with '{app_id}'.")
            return True

        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def _extract_payload(self, target_exe: str, payload_dir: str) -> bool:
        # Check for 7zz
        sz = shutil.which("7zz") or shutil.which("7z")
        cached_sz = os.path.expanduser("~/.cache/electron-builder/7zip@1.0.0/7zip-linux-x64-16wjr/bin/7zz")
        if not sz and os.path.isfile(cached_sz):
            sz = cached_sz

        if sz:
            # 1. Try extracting embedded app-64.7z
            res = subprocess.run([sz, "e", "-y", target_exe, "$PLUGINSDIR/app-64.7z", f"-o{payload_dir}"], capture_output=True)
            nested_7z = os.path.join(payload_dir, "app-64.7z")
            if os.path.isfile(nested_7z):
                res2 = subprocess.run([sz, "x", "-y", nested_7z, f"-o{payload_dir}"], capture_output=True)
                os.remove(nested_7z)
                if self._find_asar(payload_dir):
                    return True

            # 2. General extract
            subprocess.run([sz, "x", "-y", target_exe, f"-o{payload_dir}"], capture_output=True)
            if self._find_asar(payload_dir):
                return True

        # Unsupported installers fail closed; never execute them for extraction.
        return False

    def _find_asar(self, start_dir: str) -> Optional[str]:
        for root, _, files in os.walk(start_dir):
            if "app.asar" in files:
                return os.path.join(root, "app.asar")
        return None

    def _unpack_asar(self, asar_path: str, dest_dir: str) -> bool:
        cmd = None
        if shutil.which("bunx"):
            cmd = ["bunx", "@electron/asar", "extract", asar_path, dest_dir]
        elif shutil.which("npx"):
            cmd = ["npx", "-y", "@electron/asar", "extract", asar_path, dest_dir]

        if cmd:
            res = subprocess.run(cmd, cwd=os.path.dirname(asar_path), capture_output=True)
            if res.returncode == 0:
                # Sync companion unpacked directory if present
                companion = asar_path + ".unpacked"
                if os.path.isdir(companion):
                    for root, _, files in os.walk(companion):
                        for f in files:
                            src_f = os.path.join(root, f)
                            rel_p = os.path.relpath(src_f, companion)
                            dst_f = os.path.join(dest_dir, rel_p)
                            os.makedirs(os.path.dirname(dst_f), exist_ok=True)
                            shutil.copy2(src_f, dst_f)
                return True
        return False

    def _find_native_modules(self, app_dir: str) -> List[str]:
        nodes = []
        for root, _, files in os.walk(app_dir):
            for f in files:
                if f.endswith(".node"):
                    nodes.append(os.path.join(root, f))
        return nodes

    def _patch_main_script(self, script_path: str):
        with open(script_path, "r", encoding="utf-8") as f:
            code = f.read()

        modified = False

        # Pattern 1: getPlatformDir or platform switch
        p1 = r'(if\s*\(platform\s*===\s*["\']win32["\']\)\s*\{\s*return\s*["\']win-x64["\'];?\s*\})'
        if re.search(p1, code):
            code = re.sub(p1, r'\1\n  if (platform === "linux") { return arch === "arm64" ? "linux-arm64" : "linux-x64"; }', code)
            modified = True

        # Pattern 2: Darwin/Win32 auto-updater feed
        p2 = r'(if\s*\(process\.platform\s*===\s*["\']darwin["\']\)[\s\S]*?else if\s*\(process\.platform\s*===\s*["\']win32["\']\)[\s\S]*?;\s*\})'
        if re.search(p2, code):
            code = re.sub(p2, r'\1 else { return; }', code)
            modified = True

        if modified:
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(code)

    def _provision_electron_runtime(self, version: str, scratch: str) -> Optional[str]:
        primary_cache = os.path.expanduser("~/.cache/wins/runtimes/electron")
        os.makedirs(primary_cache, exist_ok=True)
        cache_dirs = [
            primary_cache,
            os.path.expanduser("~/.cache/qwen-transmuter"),
        ]

        target_dist = os.path.join(scratch, "electron_dist")
        os.makedirs(target_dist, exist_ok=True)

        zip_to_extract = None
        for cd in cache_dirs:
            cand = os.path.join(cd, f"electron-v{version}-linux-x64.zip")
            if os.path.isfile(cand):
                zip_to_extract = cand
                break

        if not zip_to_extract:
            url = f"https://github.com/electron/electron/releases/download/v{version}/electron-v{version}-linux-x64.zip"
            dl_path = os.path.join(primary_cache, f"electron-v{version}-linux-x64.zip")
            print(f"[WINS:Electron] Downloading Electron v{version} runtime...")
            res = subprocess.run(["curl", "-L", "--fail", "--progress-bar", url, "-o", dl_path])
            if res.returncode == 0 and os.path.isfile(dl_path):
                zip_to_extract = dl_path
            else:
                # Fallback to cached default runtime (e.g. 35.1.4)
                print(f"[WINS:Electron:WARN] Electron v{version} download failed. Falling back to cached v35.1.4 runtime...")
                fallback_zip = os.path.expanduser("~/.cache/qwen-transmuter/electron-v35.1.4-linux-x64.zip")
                if os.path.isfile(fallback_zip):
                    zip_to_extract = fallback_zip

        if zip_to_extract:
            subprocess.run(["unzip", "-q", zip_to_extract, "-d", target_dist])
            return target_dist
        return None

    def _heal_companion_binaries(self, resources_dir: str, app_id: str, options: Dict[str, Any]):
        """Heals the Windows-only companion executables shipped beside the app.

        Native ELF re-binding is attempted first (vendor Linux package / local
        cache). When no native build exists, a hardened micro-Wine launcher is
        generated so the helper keeps working instead of being hand-patched
        outside the toolchain.
        """
        from ..healers.companion_binaries import CompanionBinaryHealer

        healer = CompanionBinaryHealer(arch=options.get("arch", "x64"))
        report = healer.heal(
            resources_dir,
            app_id=options.get("app_id") or app_id,
            allow_wine_fallback=options.get("allow_wine_fallback", True),
        )
        if report["scanned"]:
            print(f"[WINS:Electron] [✓] Companion binaries audited: {report['scanned']} PE helper(s) | "
                  f"native: {len(report['healed_native'])} | micro-Wine shim: {len(report['wine_shimmed'])}")
        for err in report["errors"]:
            print(f"[WINS:Electron:WARN] Companion healing issue: {err}", file=sys.stderr)
        return report

    def _install_port_context(self, dest_dir: str, app_id: str, app_title: str, options: Dict[str, Any]):
        """Installs the host corpus the agent needs (real OS, port topology, commands)."""
        from ..port_context import PortContext

        context = PortContext(
            app_id=app_id,
            app_title=app_title,
            install_dir=dest_dir,
            skills_dir=options.get("skills_dir"),
            workspace=options.get("workspace"),
            slug=options.get("port_context_slug", "wins-port-context"),
        )
        report = context.install()
        installed = [p for p in (report["skill"], report["workspace_doc"], report["install_doc"]) if p]
        if installed:
            print(f"[WINS:Electron] [✓] Port context installed: {', '.join(installed)}")
        print("[WINS:Electron] Agent preamble: " + report["preamble"])
        return report

    def _wire_mcp_shims(self, resources_dir: str):
        bun_dir = os.path.join(resources_dir, "bun")
        py_dir = os.path.join(resources_dir, "python")
        os.makedirs(bun_dir, exist_ok=True)
        os.makedirs(py_dir, exist_ok=True)

        for tool, d in [("bun", bun_dir), ("uv", py_dir), ("uvx", py_dir)]:
            p = shutil.which(tool)
            if p:
                link = os.path.join(d, tool)
                if os.path.islink(link) or os.path.isfile(link):
                    os.remove(link)
                os.symlink(p, link)

    def _register_desktop_entry(self, app_id: str, title: str, launcher_path: str, resources_dir: str):
        desktop_dir = os.path.expanduser("~/.local/share/applications")
        os.makedirs(desktop_dir, exist_ok=True)
        desktop_file = os.path.join(desktop_dir, f"{app_id}.desktop")

        # Find icon
        icon_path = ""
        assets_dir = os.path.join(resources_dir, "assets")
        if os.path.isdir(assets_dir):
            for candidate in ["icon.png", "icon_dark.png", f"{app_id}.png"]:
                c_path = os.path.join(assets_dir, candidate)
                if os.path.isfile(c_path):
                    icon_path = c_path
                    break

        content = f"""[Desktop Entry]
Name={title}
Comment={title} (WINS Native Linux Transmutation)
Exec={launcher_path} %U
Icon={icon_path}
Terminal=false
Type=Application
Categories=Utility;Network;ArtificialIntelligence;
StartupWMClass={title}
"""
        with open(desktop_file, "w", encoding="utf-8") as f:
            f.write(content)

        if shutil.which("update-desktop-database"):
            subprocess.run(["update-desktop-database", desktop_dir], capture_output=True)
