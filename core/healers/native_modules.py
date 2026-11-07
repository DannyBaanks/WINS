"""
WINS Core - Native Module Healer & Polyfill Substrate
Identifies native C++ binary addons (.node), resolves Linux ELF prebuilds
from npm/GitHub when available, and synthesizes safe universal JavaScript
proxy stubs for Windows-exclusive hooks.
"""

import os
import sys
import json
import shutil
import subprocess
import tempfile
import re
from typing import Dict, Any, List, Optional, Tuple

class NativeModuleHealer:
    def __init__(self, target_arch: str = "x64"):
        self.target_arch = target_arch
        self.cache_dir = os.path.expanduser(f"~/.cache/wins/prebuilds")
        os.makedirs(self.cache_dir, exist_ok=True)

    @staticmethod
    def is_elf(path: str) -> bool:
        if not os.path.isfile(path):
            return False
        try:
            with open(path, "rb") as f:
                magic = f.read(4)
                return magic == b"\x7fELF"
        except Exception:
            return False

    @staticmethod
    def is_pe(path: str) -> bool:
        if not os.path.isfile(path):
            return False
        try:
            with open(path, "rb") as f:
                magic = f.read(2)
                return magic == b"MZ"
        except Exception:
            return False

    def find_all_native_addons(self, search_dir: str) -> List[str]:
        addons = []
        for root, _, files in os.walk(search_dir):
            for f in files:
                if f.endswith(".node"):
                    addons.append(os.path.join(root, f))
        return addons

    def resolve_package_info(self, node_path: str, root_dir: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Walks up from a .node file to locate its owning package.json."""
        curr = os.path.dirname(node_path)
        root_abs = os.path.abspath(root_dir)
        while len(curr) >= len(root_abs):
            pkg_json = os.path.join(curr, "package.json")
            if os.path.isfile(pkg_json):
                try:
                    with open(pkg_json, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    name = data.get("name")
                    version = data.get("version")
                    return name, version, curr
                except Exception:
                    pass
            parent = os.path.dirname(curr)
            if parent == curr:
                break
            curr = parent
        return None, None, None

    def fetch_linux_prebuild(self, package_name: str, version: Optional[str]) -> Optional[str]:
        """Attempts to obtain a Linux ELF .node binary from npm package prebuilds."""
        spec = f"{package_name}@{version}" if version else package_name
        safe_name = package_name.replace("/", "_")
        cached_file = os.path.join(self.cache_dir, f"{safe_name}_{version or 'latest'}_linux-{self.target_arch}.node")

        if os.path.isfile(cached_file) and self.is_elf(cached_file):
            return cached_file

        print(f"[WINS:Healer] Querying npm registry for Linux prebuilds of {spec}...")
        scratch = tempfile.mkdtemp(prefix="wins-npm-fetch-")
        try:
            res = subprocess.run(["npm", "pack", spec], cwd=scratch, capture_output=True, text=True, timeout=30)
            if res.returncode != 0:
                return None

            # Find downloaded tgz
            tgz_files = [f for f in os.listdir(scratch) if f.endswith(".tgz")]
            if not tgz_files:
                return None
            tgz_path = os.path.join(scratch, tgz_files[0])

            # Extract archive
            subprocess.run(["tar", "-xzf", tgz_path], cwd=scratch, capture_output=True)
            pkg_extracted = os.path.join(scratch, "package")

            # 1. Prioritize canonical prebuilds/linux-<arch>.node (standard GNU glibc)
            prebuilds_dir = os.path.join(pkg_extracted, "prebuilds")
            if os.path.isdir(prebuilds_dir):
                target_cand = os.path.join(prebuilds_dir, f"linux-{self.target_arch}.node")
                if os.path.isfile(target_cand) and self.is_elf(target_cand):
                    shutil.copy2(target_cand, cached_file)
                    return cached_file

            # 2. General search for linux <arch> .node binaries (strictly excluding musl libc)
            for root, _, files in os.walk(pkg_extracted):
                if "musl" in root.lower():
                    continue
                for f in files:
                    if f.endswith(".node") and "musl" not in f.lower():
                        if "linux" in f.lower() and self.target_arch in f.lower():
                            full_p = os.path.join(root, f)
                            if self.is_elf(full_p):
                                shutil.copy2(full_p, cached_file)
                                return cached_file

        except Exception as e:
            print(f"[WINS:Healer:WARN] Could not fetch prebuild for {spec}: {e}", file=sys.stderr)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

        return None

    def stub_windows_package(self, package_name: str, pkg_dir: str):
        """Applies a universal JavaScript safe proxy stub to a Windows-only native addon."""
        print(f"[WINS:Healer] Injecting safe universal stub for Windows-exclusive package: {package_name}")

        pkg_json_path = os.path.join(pkg_dir, "package.json")
        main_rel = "index.js"
        if os.path.isfile(pkg_json_path):
            try:
                with open(pkg_json_path, "r", encoding="utf-8") as f:
                    pdata = json.load(f)
                main_rel = pdata.get("main", "index.js")
            except Exception:
                pass

        main_full = os.path.join(pkg_dir, main_rel)
        os.makedirs(os.path.dirname(main_full), exist_ok=True)

        # 1. Custom Known Package Polyfills
        if "native-progress-bar" in package_name:
            stub_code = """// WINS Polyfill: @jasonscheirer/native-progress-bar
"use strict";
class ProgressBar {
  constructor(args) { this.progress = 0; this.message = ""; this.handle = 1; }
  update() {}
  close() {}
}
exports.ProgressBar = ProgressBar;
"""
            with open(main_full, "w", encoding="utf-8") as f:
                f.write(stub_code)
            return

        if "cf-prefs" in package_name:
            stub_code = """// WINS Polyfill: cf-prefs
"use strict";
const noop = () => undefined;
module.exports = {
  getPreferenceValue: noop,
  isPreferenceForced: () => false,
};
"""
            with open(main_full, "w", encoding="utf-8") as f:
                f.write(stub_code)
            return

        # 2. Universal Proxy Stub for any other arbitrary Windows addon
        universal_stub = """// WINS Universal Safe Proxy Stub
"use strict";
const noop = () => null;
const stubHandler = {
  get: (target, prop) => {
    if (prop === '__esModule') return true;
    if (prop === 'default') return stubProxy;
    if (prop === 'then') return undefined;
    return stubProxy;
  },
  apply: (target, thisArg, args) => null,
  construct: (target, args) => stubProxy,
};
const stubProxy = new Proxy(noop, stubHandler);
module.exports = stubProxy;
"""
        with open(main_full, "w", encoding="utf-8") as f:
            f.write(universal_stub)

    def heal(self, app_dir: str) -> Dict[str, Any]:
        """Scans all native modules in app_dir and applies automatic healing."""
        addons = self.find_all_native_addons(app_dir)
        report = {
            "total_addons": len(addons),
            "healed_prebuild": [],
            "healed_stub": [],
            "already_elf": [],
            "errors": [],
        }

        if not addons:
            return report

        print(f"[WINS:Healer] Auditing {len(addons)} native binary addons (.node)...")
        for addon in addons:
            rel_addon = os.path.relpath(addon, app_dir)

            if self.is_elf(addon):
                report["already_elf"].append(rel_addon)
                continue

            if not self.is_pe(addon):
                # Unknown binary or empty
                continue

            # It is a Windows PE binary!
            pkg_name, pkg_ver, pkg_dir = self.resolve_package_info(addon, app_dir)
            if not pkg_name:
                pkg_name = os.path.basename(addon).replace(".node", "")

            print(f"[WINS:Healer] Found Windows PE addon: {rel_addon} (Package: {pkg_name}@{pkg_ver or '?'})")

            # Try Prebuild Resolution first
            linux_elf = self.fetch_linux_prebuild(pkg_name, pkg_ver)
            if linux_elf and os.path.isfile(linux_elf):
                shutil.copy2(linux_elf, addon)
                print(f"[WINS:Healer] [✓] Successfully replaced {rel_addon} with Linux ELF prebuild!")
                report["healed_prebuild"].append({"addon": rel_addon, "package": pkg_name})
                continue

            # Fallback: Apply Safe JS Proxy Stubbing
            if pkg_dir:
                self.stub_windows_package(pkg_name, pkg_dir)
                report["healed_stub"].append({"addon": rel_addon, "package": pkg_name})
            else:
                report["errors"].append({"addon": rel_addon, "reason": "No owning package.json located"})

        return report
