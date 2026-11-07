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
6. **Desktop Integration:** Registers modern user-space launchers in `~/.local/bin` and desktop shortcuts with high-resolution icons in `~/.local/share/applications`.

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

### 2.6 The Cleanroom Diagnostic Engine (`core/tester.py`)
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
