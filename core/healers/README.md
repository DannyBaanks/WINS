# Core Healers Component Package

## Overview
Subsystem responsible for auditing, resolving, and polyfilling native C++ binary addons (`.node`) in de-layered Electron applications. It prevents dynamic linker failures (`ERR_DLOPEN_FAILED`, invalid ELF header) by fetching matching Linux ELF binaries or synthesizing universal JavaScript proxy stubs for Windows-exclusive dependencies.

## Interface
- `NativeModuleHealer(target_arch: str = "x64")`: Main healer orchestrator class (`[native_modules.py:NativeModuleHealer]`).
- `NativeModuleHealer.is_elf(path: str) -> bool`: Checks if binary file has ELF magic header `\x7fELF` (`[native_modules.py:is_elf]`).
- `NativeModuleHealer.is_pe(path: str) -> bool`: Checks if binary file has Portable Executable magic header `MZ` (`[native_modules.py:is_pe]`).
- `NativeModuleHealer.find_all_native_addons(search_dir: str) -> List[str]`: Recursively locates all `.node` binary files (`[native_modules.py:find_all_native_addons]`).
- `NativeModuleHealer.resolve_package_info(node_path: str, root_dir: str) -> Tuple[Optional[str], Optional[str], Optional[str]]`: Discovers owning `package.json`, extracting package name and semver (`[native_modules.py:resolve_package_info]`).
- `NativeModuleHealer.fetch_linux_prebuild(package_name: str, version: Optional[str]) -> Optional[str]`: Downloads npm package tarball, extracts Linux ELF prebuilds, and caches them (`[native_modules.py:fetch_linux_prebuild]`).
- `NativeModuleHealer.stub_windows_package(package_name: str, pkg_dir: str)`: Generates JS polyfill or universal `Proxy(noop, handler)` stub (`[native_modules.py:stub_windows_package]`).
- `NativeModuleHealer.heal(app_dir: str) -> Dict[str, Any]`: Audits and repairs all native addons across an unpacked application tree (`[native_modules.py:heal]`).

## Invariants
- **Glibc vs Musl Isolation**: The prebuild resolver must strictly prioritize GNU glibc (`libc.so.6`) binaries and filter out Musl libc (`libc.musl-x86_64.so.1`) to prevent shared library load crashes on standard Linux distributions (`[native_modules.py:fetch_linux_prebuild]`).
- **Idempotent Healing**: Addons that are already valid ELF binaries (`is_elf == True`) must not be overwritten or modified (`[native_modules.py:heal]`).
- **Proxy Stub Contract**: Universal stubs must safely respond to property lookups (`__esModule`, `default`, arbitrary getters), function calls (`apply`), and constructor invocations (`construct`) without throwing runtime `TypeError` (`[native_modules.py:stub_windows_package]`).
- **Zero Unhandled PE Addons**: A Windows PE binary must either be substituted with a functional Linux ELF equivalent or neutralized via proxy stub; PE binaries must never reach the host runtime loader (`[native_modules.py:heal]`).

## Side Effects
- Mutates target files in-place: overwrites Windows `.node` files with Linux ELF equivalents or updates `index.js` in package directories (`[native_modules.py:heal]`).
- Spawns network and external archive processes: `npm pack`, `tar -xzf` (`[native_modules.py:fetch_linux_prebuild]`).
- Creates temporary directories in `/tmp/wins-npm-fetch-*` (cleaned up in `finally` block).
- Persists downloaded Linux `.node` binaries in local user cache directory `~/.cache/wins/prebuilds/` (`[native_modules.py:fetch_linux_prebuild]`).

## Verification
- Run: `python3 -m unittest discover tests -p "test_healer.py"`
