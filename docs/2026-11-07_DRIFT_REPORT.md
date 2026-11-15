# EGM Code-to-Contract Drift Report (2026-11-07)

Audit target: Documentation contracts across `/home/danny/Development/ISyCo Git/WINS`.

---

## core/healers/README.md

No drift detected.
All public symbols (`NativeModuleHealer`, `is_elf`, `is_pe`, `find_all_native_addons`, `resolve_package_info`, `fetch_linux_prebuild`, `stub_windows_package`, `heal`), invariants, and side effects match `core/healers/native_modules.py` directly.

---

## core/recipes/README.md

* **PyInstaller Incomplete Implementation**: `PyInstallerRecipe` is documented as a preview recipe, but `transmute()` currently returns `False` immediately with console messages; extraction logic is absent.
* **Electron Regex AST Limitation**: `core/recipes/electron.py:_patch_main_script` assumes unminified JavaScript syntax for `platform === "win32"` and Darwin/Win32 updater patterns; modern bundled applications (esbuild/Terser/Webpack) bypass these regexes silently.
* **Machine-Specific Path in Fallback**: `core/recipes/electron.py:_provision_electron_runtime` contains a fallback pointing to `~/.cache/qwen-transmuter/electron-v35.1.4-linux-x64.zip`, which is host-specific rather than using the centralized `~/.cache/wins/` hierarchy.

---

## core/README.md

* **Unregistered Recipe Reference in Triage**: `BinaryTriage._probe_installer_contents` and `_detect_runtime` recommend `recipe_micro_wine` when Native Win32 PE or legacy .NET Framework binaries are detected. However, `recipe_micro_wine` is neither implemented nor registered in `bin/wins:RECIPES`.

---

## bin/README.md

No drift detected.
All CLI subcommands (`probe`, `transmute`, `test`, `list`) match parameter specifications and output constraints.

---

## README.md (Root Blueprint)

* **.NET Host Framework Dependency**: The root blueprint lists `.NET / Avalonia` under production status, but runtime execution depends on strict host SDK/runtime alignment (e.g. apps targeting `net10.0` fail with `BadImageFormatException` when run on a host providing only `net8.0`).
* **Micro-Wine Missing Execution Target**: The roadmap notes `Pure Win32 PE` as planned for v0.4, but CLI `probe` currently recommends `recipe_micro_wine` as an immediate recipe.
