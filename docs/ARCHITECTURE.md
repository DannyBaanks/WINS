# WINS Architecture & Technical Specification

> **WINS Is Not a Sandbox.**  
> *A Post-Wine Architecture for Desktop Software Portability in the Age of Autonomous AI Agents.*

---

## 1. Architectural Overview

```
                      [Target Windows .exe]
                               │
                               ▼
                    ┌─────────────────────┐
                    │     WINS CLI        │
                    │   (bin/wins)        │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  core/triage.py     │
                    │  - Envelope Detect  │
                    │  - Heuristic Probe  │
                    │  - Runtime Taxonomy │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Recipe Dispatcher  │
                    └──────────┬──────────┘
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│ recipes/electron │ │ recipes/pyinst.  │ │  recipes/dotnet  │
│ - 7z / NSIS strip│ │ - pyinstxtractor │ │ - MSIL extraction│
│ - ASAR unpack    │ │ - Python3 mapping│ │ - host `dotnet`  │
│ - Native .node   │ │ - Virtualenv shim│ │ - Avalonia rebind│
│   audit          │ └──────────────────┘ └──────────────────┘
│ - AST OS patch   │
│ - Electron swap  │
│ - MCP host shims │
└─────────┬────────┘
          │
          ▼
┌─────────────────────────────────────────┐
│ Host Integration Layer                  │
│ - ~/.local/share/<app>-desktop          │
│ - ~/.local/bin/<app> (launcher)         │
│ - ~/.local/share/applications/*.desktop │
└─────────────────────────────────────────┘
```

---

## 2. Core Subsystems

### 2.1 The Triage Engine (`core/triage.py`)
The triage engine inspects target binaries in two stages:
1. **Envelope Detection:** Identifies the container/installer envelope (NSIS, InnoSetup, WiX/MSI, 7z SFX, or bare PE).
2. **Deep Heuristic Probing:**
   * Reads initial and trailing blocks of the binary for signature fingerprints (`app.asar`, `_MEI`, `BSJB`, `Launch4j`).
   * When an envelope is detected, queries the internal archive manifest without executing untrusted code.
   * Produces a structured taxonomy record detailing the detected framework, embedded payloads, feasibility rating, and recommended recipe.

### 2.2 The Cleanroom Isolation Lifecycle
* Every transmutation occurs within an ephemeral, unprivileged scratchpad (`/tmp/wins-cleanroom-XXXXXX`).
* The extraction utilizes non-destructive archive unpacking (`7zz` / native decompressors) whenever possible.
* No global state, persistent Windows registry, or `~/.wine` pollution is generated.
* On completion or failure, the cleanroom is safely purged.

### 2.3 The Universal Electron Recipe (`core/recipes/electron.py`)
1. **Extraction:** Isolates `app.asar` from the installer payload.
2. **Native Module Healing:** Integrates `NativeModuleHealer` to resolve GNU glibc prebuilds from npm/GitHub or inject safe JavaScript proxy stubs for Windows-exclusive hooks.
3. **AST Platform Patching:** Analyzes the main process scripts for OS assertion bottlenecks:
   * Expands `platform === "win32"` to support `platform === "linux"` (`linux-x64` / `linux-arm64`).
   * Neutralizes Windows-specific auto-updater feeds.
4. **Runtime Provisioning:** Binds the application logic to a verified native Linux Electron runtime (matching the upstream version).
5. **MCP Subsystem Wiring:** Automatically discovers and symlinks host development tools (`bun`, `uv`, `uvx`) into the application's internal resources path, enabling full Model Context Protocol (MCP) tool execution.
6. **Companion Binary Healing:** Audits the Windows-only companion executables shipped in `resources/bin` and restores the spawn seam they provide (native ELF re-binding, otherwise a hardened micro-Wine shim) — see §2.6.
7. **Desktop Integration:** Registers modern user-space launchers in `~/.local/bin` and desktop shortcuts with high-resolution icons in `~/.local/share/applications`.

### 2.4 The Native Module Healer (`core/healers/native_modules.py`)
Resolves native C++ binary addons (`.node`) using a dual-healing architecture:
1. **Prebuild Resolver:**
   * Distinguishes GNU glibc vs Musl libc binaries.
   * Fetches official Linux ELF `.node` prebuilds directly from npm/GitHub releases for cross-platform modules (`better-sqlite3`, `sqlite3`, `sharp`, `keytar`).
   * Replaces Windows PE `.node` files in-place with genuine Linux ELF binaries.
2. **Universal Safe Proxy Stubber:**
   * For Windows-only platform dependencies (`@vscode/windows-registry`, `@jasonscheirer/native-progress-bar`, `cf-prefs`, `@notionhq/desktop-native`), generates zero-overhead JavaScript Proxy polyfills (`Proxy(noop, handler)`).
   * Prevents `ERR_DLOPEN_FAILED` and invalid ELF header crashes, allowing apps to run continuously on Linux.

### 2.5 The .NET Core & Avalonia Recipe (`core/recipes/dotnet.py`)
1. **Cleanroom Unpacking:** Uses `innoextract` or ephemeral cleanroom Wine execution to extract managed CIL assemblies.
2. **Runtime Configuration Adaptation:** Analyzes `*.runtimeconfig.json` and updates framework bindings to point to the host Linux `Microsoft.NETCore.App` runtime.
3. **Native Host Wiring:** Symlinks host Linux native shared objects (`libhostpolicy.so`, `libcoreclr.so`, `libSystem.Native.so`).
4. **Avalonia X11 Activation:** Configures `AVALONIA_PLATFORM=x11` and globalization invariant mode for cross-platform GUI rendering.

### 2.6 The Companion Binary Healer (`core/healers/companion_binaries.py`)
Runtime-wrapped applications rarely ship a single binary: the Electron main
process spawns **companion executables** shipped beside the payload
(`resources/bin/*.exe` — device agents, sidecars, utility hosts, import
panels). On Linux the main process spawns them **without the `.exe`
extension**, so a naive transmutation silently breaks the connector (the app
reports the device as disconnected and cannot serve its local file API).

The healer restores that seam with two strategies, always native-first:
1. **Native ELF re-binding:** a Linux build of the helper is resolved (local
   cache `~/.cache/wins/companions/`, or a vendor Linux package declared in
   `core/recipes/manifests/*.json` / `~/.config/wins/native-manifest.json`)
   and installed under the extension-less host name, replacing the PE.
2. **Micro-Wine shim:** when no native build exists (pure Win32 PE helpers),
   a hardened launcher is generated that re-hosts the PE under an isolated
   Wine prefix. The shim relays the local file API that the desktop passes on
   fd 3 (`fd3 -> socat -> TCP loopback -> bridge under Wine -> named pipe`),
   hands the operator a valid Windows `PARENT_PID` from the bridge handshake
   (the desktop PID is a Linux PID and is invalid under Wine), converts the
   host path variables to Windows form and keeps the bridge alive for the
   lifetime of the helper.

Because the shim is produced by the toolchain instead of being hand-written
per application, it stays reproducible and repairable: `wins heal-bin <dir>`
re-applies it to an existing installation at any time.

### 2.7 The Cleanroom Diagnostic Engine (`core/tester.py`)
Executes transmuted applications in an isolated subprocess with telemetry logging:
* Real-time stream parsing for FFI failures, dlopen errors, missing modules, and unhandled rejections.
* Analyzes execution health (`HEALTHY_RUNNING`, `CLEAN_EXIT`, `CRITICAL_ANOMALIES_DETECTED`).
* Generates structured machine-readable JSON with actionable patch instructions for AI agents.

---

## 3. Agent Integration Interface

WINS is designed to be operated both by human engineers and by autonomous AI agents (such as Antigravity, OpenISy, and Claude Code).

Agents can invoke WINS via CLI or MCP subprocess:
```bash
# 1. Obtain machine-readable JSON taxonomy:
wins probe path/to/app.exe --json

# 2. Transmute binary to native Linux application:
wins transmute path/to/app.exe --dest ~/.local/share/app-desktop

# 3. Test and diagnose runtime telemetry:
wins test app-name --timeout 5 --json
```

Output:
```json
{
  "target": {
    "name": "Qwen-1.0.3.44-release-win-x64.exe",
    "size_human": "119.2 MB",
    "sha256": "393e4669..."
  },
  "envelope": {
    "type": "nsis",
    "name": "Nullsoft Scriptable Install System (NSIS)"
  },
  "runtime": "electron",
  "feasibility": "EXCELLENT (100% native Linux re-hosting; 0 Wine emulation required)",
  "recommended_recipe": "recipe_electron"
}
```

An agent can parse this payload, determine immediate feasibility, and trigger:
```bash
wins transmute path/to/app.exe
```
Delivering a fully functional, native Linux application within seconds.
