# WINS (WINS Is Not a Sandbox) 🚀

> **Post-Wine Desktop Software Re-hosting Framework for Linux**  
> *De-layer runtime-wrapped Windows binaries and re-host them natively on Linux · Zero Wine Bloat · Agentic Automation*

---

## 💡 The Philosophy: Why WINS?

In 1993, **Wine** was created for a world where Windows software was compiled in C/C++ directly against Win32 kernel and GDI DLLs. 

In **2026**, more than 65% of Windows desktop applications—including nearly all AI desktop clients, chat tools, and developer utilities—are **Runtime-Wrapped Packages**:
* **Electron / Web:** Chromium + Node.js (Qwen, Claude Desktop, ChatGPT, Slack, Discord, Obsidian).
* **Python Freezers:** Bytecode packed with PyInstaller or Nuitka.
* **Modern .NET:** Cross-platform CIL assemblies running on .NET 8/9.

Running Wine for these applications means emulating an entire virtual operating system (with fake registry, simulated system32 DLLs, and Direct3D translation) just to run a web app or a Python script that could run **natively on Linux**.

**WINS** replaces emulation with **surgical de-layering and native re-hosting**:
1. Isolates the binary in an ephemeral cleanroom (zero virtual OS pollution).
2. Probes the binary taxonomy to identify the real underlying runtime.
3. De-layers the installer envelope (NSIS, InnoSetup, etc.).
4. Patches platform assertion gates.
5. Re-binds the application to the native Linux host runtime.

The result is **100% native Linux performance**: native Wayland/X11 rendering, native GPU acceleration, native Model Context Protocol (MCP) host tool integration, and zero memory overhead.

---

## 🛠️ System Architecture

```
                    [Target Windows .exe]
                              │
                              ▼
                   ┌─────────────────────┐
                   │    WINS Engine      │
                   │  - Envelope Detect  │
                   │  - REA Heuristics   │
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
└────────┬─────────┘
         │
         ▼
[Native Linux Application in ~/.local/share/<app>-desktop]
```

---

## 🚀 Quickstart

### Prerequisites
* Linux (x86_64, tested on Ubuntu 24.04 LTS).
* `python3`, `7zz` (or `7z`), `unzip`, `curl`.
* *(For Electron recipe)*: `bunx` or `npx` (for ASAR unpacking).

### Installation
Add `bin/wins` to your `$PATH`:
```bash
git clone https://github.com/DannyBaanks/WINS.git
cd WINS
export PATH="$PWD/bin:$PATH"
```

---

## 📖 CLI Usage

### 1. Probe & Classify Binary Taxonomy
Analyze any Windows executable or installer without executing it:
```bash
wins probe Qwen-1.0.3.44-release-win-x64.exe
```

Output:
```text
[TARGET] Qwen-1.0.3.44-release-win-x64.exe (119.2 MB)
  SHA-256:  393e4669402e48f3fa6cffd0ebaadfe597b06fb26a11b6aaf03f7ee74df26e60

[ENVELOPE] Nullsoft Scriptable Install System (NSIS)

[DETECTED RUNTIME] ELECTRON
  framework: Electron (Chromium + Node.js Web Architecture)
  envelope_compression: NSIS + Embedded 7z payload
  contains_asar: True

[PORTING FEASIBILITY] EXCELLENT (100% native Linux re-hosting; 0 Wine emulation required)
[RECOMMENDED RECIPE]  recipe_electron
```

### 2. Machine-Readable JSON for AI Agents
Autonomous agents (Antigravity, OpenISy, Claude Code) can request structured JSON:
```bash
wins probe Qwen-1.0.3.44-release-win-x64.exe --json
```

### 3. Transmute into a Native Linux Application
De-layer and re-host the application automatically:
```bash
wins transmute Qwen-1.0.3.44-release-win-x64.exe
```
This single command:
1. Strips the NSIS installer in an ephemeral cleanroom.
2. Unpacks `app.asar` and audits for native C++ `.node` modules.
3. Applies AST patches to remove Windows/macOS platform gates.
4. Provisions a matching native Linux Electron runtime.
5. Wires host MCP tools (`bun`, `uv`, `uvx`).
6. Creates user-space launchers (`~/.local/bin/<app>`) and `.desktop` shortcuts with official icons.

---

## 📊 Supported Runtimes & Roadmap

| Runtime Framework | Status | Feasibility | Description |
|---|---|---|---|
| **Electron / Web** | ✅ Production | 100% Native | Full ASAR de-layering, AST patching, and Electron re-binding |
| **PyInstaller** | 🚧 Roadmap (v0.2) | 100% Native | Bytecode extraction via pyinstxtractor & native Python 3 execution |
| **.NET / CIL** | 🚧 Roadmap (v0.2) | 100% Native | MSIL assembly extraction & execution via host `dotnet` runtime |
| **JVM / Launch4j** | 📋 Planned (v0.3) | 100% Native | JAR extraction and execution via native OpenJDK |
| **Pure Win32 PE** | 📋 Planned (v0.4) | Micro-Isolated | Minimal ephemeral Wine container without host pollution |

---

## 🤖 Agentic Interoperability

WINS is engineered from the ground up to empower AI coding agents. 

When an agent encounters a Windows executable, instead of giving up or setting up a fragile Wine environment, it can:
1. Run `wins probe --json` to inspect the target.
2. Execute `wins transmute` to automatically convert it.
3. Validate GUI startup and MCP canaries.
4. Deliver a ready-to-use native Linux tool.

---

## 📄 License
WINS is open-source software licensed under the [MIT License](LICENSE).
