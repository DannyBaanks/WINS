# Core Recipes Component Package

## Overview
Subsystem containing modular transmutation recipes that de-layer runtime-wrapped Windows application packages and re-host them natively on Linux. Each recipe targets a specific runtime category (Electron, .NET Core/Avalonia, PyInstaller) and handles payload extraction, AST/runtime patching, native dependency resolution, and desktop environment integration.

## Interface
- `BaseRecipe`: Abstract base class defining the transmutation contract (`[base.py:BaseRecipe]`).
  - `BaseRecipe.can_handle(triage: Dict[str, Any]) -> bool`: Evaluates whether the recipe supports the target binary taxonomy.
  - `BaseRecipe.transmute(triage: Dict[str, Any], dest_dir: str, options: Dict[str, Any]) -> bool`: Executes the full extraction and re-hosting pipeline.
- `ElectronRecipe`: Production recipe for Electron/Node.js Windows binaries (`[electron.py:ElectronRecipe]`).
  - Unpacks installer payload (`_extract_payload`) and extracts `app.asar` (`_unpack_asar`).
  - Delegates native C++ addon healing to [NativeModuleHealer](../healers/README.md).
  - Performs AST platform patching (`_patch_main_script`) on main-process JavaScript scripts.
  - Provisions matching native Linux Electron runtime (`_provision_electron_runtime`).
  - Wires host Model Context Protocol development tools (`_wire_mcp_shims`).
  - Generates shell launcher and `.desktop` specification (`_register_desktop_entry`).
- `DotNetRecipe`: Production recipe for modern .NET Core / CIL assemblies and Avalonia UI (`[dotnet.py:DotNetRecipe]`).
  - Extracts assemblies using `innoextract` or cleanroom ephemeral Wine sandbox (`_extract_payload`).
  - Identifies managed entrypoint (`*.dll`) and inspects Target Framework Moniker (`_locate_net_entrypoint`, `_inspect_target_framework`).
  - Modifies `runtimeconfig.json` for Linux runtime binding (`_adapt_runtime_config`).
  - Symlinks host Linux .NET shared runtime libraries (`_link_host_net_runtimes`).
  - Generates launcher with `AVALONIA_PLATFORM=x11` and globalization invariant configuration.
- `PyInstallerRecipe`: Preview recipe for frozen Python executables (`[pyinstaller.py:PyInstallerRecipe]`).
- `TranspilerRecipe`: Production recipe for Native Win32 PE binaries (`[transpiler.py:TranspilerRecipe]`).
  - Extracts installer payload via 7z cleanroom extraction (`_extract_payload`).
  - Deconstructs PE binary via [BinaryHarvester](../transpiler/README.md), discovering embedded engines (Scintilla, Boost).
  - Searches for native Linux candidate engines or configures `libwins_shim.so` POSIX execution substrate.
  - Generates launcher script in `~/.local/bin/<app_id>` and `.desktop` entry.

## Invariants
- **Cleanroom Isolation**: Every recipe must execute in an ephemeral scratchpad (`/tmp/wins-cleanroom-*` or `/tmp/wins-dotnet-cleanroom-*`) and guarantee directory cleanup upon completion or failure (`[electron.py:transmute]`, `[dotnet.py:transmute]`).
- **No Background Process Leak**: Ephemeral Wine execution for installer extraction must explicitly terminate all child processes (`killall -9`) prior to returning (`[dotnet.py:_extract_payload]`).
- **Launcher Executability**: Generated launcher scripts in `~/.local/bin` must have Unix file mode `0755` and be executable without manual intervention (`[electron.py:transmute]`, `[dotnet.py:transmute]`).
- **Idempotent Destination**: Existing destination installation directories must be completely refreshed without leaving stale or corrupted artifacts from prior runs (`[electron.py:transmute]`, `[dotnet.py:transmute]`).

## Side Effects
- Creates directories and files under user directory:
  - Application payload: `dest_dir` (default: `~/.local/share/<app>-desktop`).
  - Shell launcher: `~/.local/bin/<app_id>`.
  - Desktop entry: `~/.local/share/applications/<app_id>.desktop`.
- Downloads and caches Linux Electron runtime distributions in `~/.cache/wins/runtimes/electron/`.
- Executes external utilities: `7zz`, `bunx`/`npx`, `curl`, `unzip`, `wine`, `innoextract`, `update-desktop-database`.

## Verification
- Run: `python3 -m unittest discover tests`
