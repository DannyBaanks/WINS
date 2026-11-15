# WINS — WINS Is Not a Sandbox

> **Port Windows desktop apps to native Linux — no Wine, no VM, no emulated Windows.**
> Look inside the installer, find out what the app really is, and re-host it as a normal Linux program.

WINS takes a Windows installer or executable, works out what it is *made of*, and rebuilds it as something that
runs on Linux by itself. In this project, **a "port" means exactly that: a program made for Windows that now runs on
Linux** (as a launcher + app folder, or as a single AppImage).

Most "Windows-only" desktop software is not really Windows code. It is a web app in Electron, an NW.js game, a
managed .NET program, or a Python bundle, wrapped in a Windows installer. For those, WINS peels the wrapper off and
runs the real program on its native Linux runtime. For genuinely native Win32 code (C++ against `kernel32`, `user32`,
Direct3D...) WINS does not pretend: it measures how far away a Linux version is, and builds fuzz-verified Linux
replacements for the Windows APIs the program calls, one function at a time.

---

## What is ported today

Every row below was inspected on the author's machine (Ubuntu 24.04). The last column says what has actually been
demonstrated and what has **not** — a launcher existing is not the same as the app working.

| App | What it really is | Result | Demonstrated | Not demonstrated |
|---|---|---|---|---|
| **Look Outside** | RPG Maker MZ game on NW.js 0.94.0 | **Single-file Linux AppImage** (747 MB, no Wine/Proton), saves in `~/.local/share/wins/look-outside/save/`, original install and saves untouched | Opens in a virtual display, reaches the menu, takes keyboard input, `New Game` shows the first dialog; creating `config.rmmzsave` works. SHA-256 `2f239f51…3679` | A full playthrough, save/load of a real game, Steam features (Greenworks for Linux is not bundled) |
| **Notion Desktop 7.42.3** | Electron (Chromium + Node.js 22 + React 19) | Native Linux Electron app in `~/.local/share/notion-desktop`, launcher + desktop entry | Cold boot in 345 ms, `SqliteServer` started, native window created, workspace DOM rendered (`docs/BENCHMARK_5_PROGRAMS.md`). `better-sqlite3` swapped for the Linux ELF prebuild | The 4 Windows-specific native modules are stubbed, not replaced |
| **Qwen 1.0.3.44** | Electron (NSIS + 7z payload, ASAR) | Installed in `~/.local/share/qwen-desktop` (305 MB) with a launcher | Triage output recorded (see *Quickstart*); installed with a launcher | No desktop-menu entry is registered; no recorded run in this repo |
| **ShareX 22.3.0** | .NET 10 + Avalonia UI | Installed in `~/.local/share/sharex-desktop` (491 MB), launcher + desktop entry | Runtime correctly identified; Avalonia X11 assemblies present | A successful launch: it ships a Windows-targeted host, so this is not proven |
| **Notepad++ 8.9.9** | Native Win32 (C++, Scintilla) | Installed via the transpiler path (28 MB); POSIX shims for part of its API surface | Classified, API surface harvested | **The desktop entry is broken** (it points at a deleted temp directory) and a working run is not demonstrated |
| WinMerge, Greenshot | Native Win32 / legacy .NET Framework + WinForms | Classified only | Correct triage | Nothing runs: the micro-isolation recipe they are routed to is **not implemented** |

**Honest scope:** WINS reliably ports *runtime-wrapped* software (Electron, NW.js, modern .NET). It does **not** yet
run arbitrary native Win32 applications. See *How far can it go?* below for a worked example with a real, huge one.

---

## What it can do

1. **Triage** (`wins probe`) — SHA-256, installer envelope (NSIS, Inno Setup, MSI, 7z), and the real runtime
   (Electron, .NET, PyInstaller, native PE), plus a porting-feasibility verdict. Nothing is executed.
2. **Port** (`wins transmute`) — unpack, patch platform checks, replace Windows native addons with Linux
   prebuilds or safe stubs, re-bind to the Linux runtime, and install a launcher + `.desktop` entry.
3. **Look inside native binaries** (`wins harvest`, `wins-native`) — static PE analysis written in Zig: imports,
   **delay-load imports**, .NET (CLR) header, MSI tables, CAB indexes, dependency closure of a whole product.
4. **Rebuild Windows APIs for Linux, proven by fuzzing** (`winlux*`) — each replacement is differential- or
   metamorphic-fuzzed in a `bubblewrap` sandbox against an independent oracle, and ships with deliberately broken
   variants that the fuzzer **must** catch.
5. **Tell you when it will not work** — with numbers (see 3ds Max below).

---

## The native toolbox (Zig)

Build once (Zig 0.16, `bubblewrap`, and a 7-Zip binary are required):

```bash
mkdir -p build && zig build-exe native/main.zig -O ReleaseSafe -femit-bin=build/wins-native
```

| Command | What it does |
|---|---|
| `wins-native inspect FILE` | SHA-256, PE format, sections |
| `wins-native imports FILE [--json]` | Imports **and delay-load imports**, ordinals, CLR flag |
| `wins-native extract FILE NEW_DIR EXTRACTOR <7z\|inno\|msi>` | Unpack an installer inside a sandbox, into a new directory |
| `wins-native cab-find CAB MEMBER` | Locate a member in a (possibly partial) cabinet without extracting |
| `wins-native closure CAB FILE_TSV ROOT_KEY EXTRACTOR NEW_DIR` | Full dependency closure of a product: 198 PEs in seconds |
| `wins-native compile-c` / `compare` | Compile a candidate shim in a sandbox and compare it to an oracle |

Everything extracted is treated as untrusted data and never executed. Outputs always go to a **new** directory.
The Spanish step-by-step guide with real command output is [`GUIA.md`](./GUIA.md) and
[`native/shims/GUIA.md`](./native/shims/GUIA.md).

---

## Windows APIs rebuilt for Linux (`winlux*`)

| Replacement | Replaces | Oracle | Fuzz result | Must-catch bugs |
|---|---|---|---|---|
| last-error | `GetLastError` / `SetLastError` | thread-isolation observation | 100 000 iterations match | process-global state |
| text | `MultiByteToWideChar` / `WideCharToMultiByte` (CP_UTF8) | independent C table decoder, cross-checked against CPython's UTF-8 codec on 20 000 vectors | 200 000 iterations match; every outcome (ok, 87, 122, 1004, 1113) exercised | per-byte replacement, destination overrun |
| **winluxtrust** | the digest half of `WinVerifyTrust` (Authenticode) | `osslsigncode` | 200 000 mutations in 38 s, all classes match | hashing the checksum field, accepting any digest |
| **winluxhttp** | proxy selection used by Qt's `WinHttp*` calls | metamorphic relations (no real WinHTTP available) | 20 000 scenarios in 1.8 s | ignoring scheme scope, case-sensitive bypass |

What each one does **not** do is part of its contract:

- **winluxtrust never reports "trusted".** It computes the Authenticode PE hash and compares it with the digest in
  the PKCS#7 signature. A match returns `0x20570001` (*digest matches, chain unverified*), deliberately **not**
  `ERROR_SUCCESS`. Certificate chains, signature values, revocation and timestamps are not implemented.
- **winluxhttp only chooses proxies.** There is no HTTP transport, PAC script engine or WPAD detection — and none is
  needed by the Qt libraries it was built for, which only ask Windows where the proxy is. Behaviour in corners the
  documentation does not pin down is an assumption, not a verified match with Windows.
- None of these is a PE loader. Without one, no Windows executable can call them.

---

## How far can it go? A real example: Autodesk 3ds Max 2026

WINS was pointed at the full installer (5.76 GB). It deposits every file without Windows, then measures:

- 198 PE files in the dependency closure, **3 129** external API functions needed, **4** with a Linux replacement.
- The MSI runs Windows custom-action code, so extracting is not installing.
- `3dsmax_interop.dll` is a mixed-mode C++/CLI assembly, which Microsoft documents as Windows-only.
- Direct3D 9/11 and MSVC redistributables are further blockers; Autodesk licensing is untested.

**Verdict: not portable with WINS today; absolute impossibility is not claimed.** The evidence and claims table is in
[`docs/3DSMAX_FEASIBILITY_2026-11-07.md`](./docs/3DSMAX_FEASIBILITY_2026-11-07.md). The same machinery that says
"no" here is what makes the "yes" on Notion and Look Outside trustworthy.

---

## Subdirectories & System Boundaries

- **bin**: [./bin/README.md](./bin/README.md) - Unified CLI command dispatcher (`probe`, `transmute`, `harvest`, `fuzz`, `test`, `list`) providing human and agent-facing JSON interfaces.
- **core**: [./core/README.md](./core/README.md) - Central processing engine providing binary taxonomy inspection and black-box runtime diagnostic telemetry.
  - **healers**: [./core/healers/README.md](./core/healers/README.md) - Native C++ `.node` binary addon auditor, GNU glibc prebuild resolver, and universal JavaScript proxy stubber.
  - **recipes**: [./core/recipes/README.md](./core/recipes/README.md) - Modular extraction and re-hosting transmuters for Electron, .NET Core / Avalonia, PyInstaller, and Native PE.
  - **transpiler**: [./core/transpiler/README.md](./core/transpiler/README.md) - Static PE parser, IAT/RTTI lineage extractor, and zero-Win32 POSIX C/Zig shimming layer.
  - **fuzzer**: [./core/fuzzer/README.md](./core/fuzzer/README.md) - Ultra-high-throughput Zig differential fuzzing engine (>7,000,000 ops/sec) for proving API equivalence.
- **libs**: [./libs/README.md](./libs/README.md) - The Windows DLLs WINS stands in for, as versioned libraries (`wins-d3d9`, `wins-dsound`, ...), what has been run through each, and the generated gap report of the DLLs and imports WINS still lacks compared with Windows.
- **launch**: [./launch/falloutnv/README.txt](./launch/falloutnv/README.txt) - The Steam compatibility tool for Fallout: New Vegas (launcher, installer): the Play button runs the game under the WINS i386 loader.

---

## Global Invariants

1. **Cleanroom Non-Pollution**: Every extraction and transmutation must operate inside an ephemeral, unprivileged scratchpad (`/tmp/wins-cleanroom-*`). No persistent virtual Windows registry, `~/.wine` prefixes, or global OS state pollution may be retained.
2. **Dynamic Linker Safety**: Windows PE binaries (`MZ` header) must never be passed to Linux host dynamic loaders (`dlopen`, ld.so). Native addons must be substituted with Linux ELF prebuilds or neutralized via safe JavaScript proxy stubs before execution.
3. **Fail-Closed Verification**: The CLI must exit with code `0` on successful operations and code `1` upon errors. Machine-readable modes (`--json`) must emit strictly valid JSON to stdout without banner interference.
4. **Desktop Environment Protocol**: Transmuted applications must integrate natively with standard XDG specifications: launchers in `~/.local/bin/` with mode `0755` and desktop shortcuts in `~/.local/share/applications/`.

---

## Global Side Effects

- **Filesystem Writes**:
  - Application installations: `~/.local/share/<app>-desktop/`.
  - Executable launchers: `~/.local/bin/<app_id>`.
  - Desktop entries: `~/.local/share/applications/<app_id>.desktop`.
  - Local caches: `~/.cache/wins/prebuilds/` and `~/.cache/wins/runtimes/electron/`.
- **Network Access**:
  - Downloads official Linux Electron runtime binaries from GitHub releases when not cached.
  - Queries npm registry via `npm pack` to obtain official Linux ELF `.node` prebuilds.
- **Process Spawning**:
  - Unpackers: `7zz`, `innoextract`, `tar`, `unzip`.
  - Ephemeral Wine execution strictly bounded to silent extraction with explicit process group cleanup (`killall -9`).
  - Diagnostic test subprocesses launched under isolated session IDs (`os.setsid`).

---

---

## System Verification

```bash
# Python subsystems (triage, recipes, healers, transpiler, fuzzer front-end)
python3 -m unittest discover tests

# Native Zig tools and winlux replacements (need zig 0.16, bubblewrap, openssl)
python3 -m unittest native.test_pe_imports native.test_win32_text native.test_winluxhttp native.test_winluxtrust
```

`native.test_winluxtrust` also needs `osslsigncode` (set `WINS_OSSLSIGNCODE` if it is not on `PATH`) and skips itself
when it is missing.

---

## Quickstart

### Prerequisites
* Linux x86_64 (tested on Ubuntu 24.04 LTS), `python3`, `7zz` (or `7z`), `unzip`, `curl`.
* Electron apps: `bunx` or `npx` (ASAR unpacking). Native tools: Zig 0.16 and `bubblewrap`.

### Install
```bash
git clone https://github.com/DannyBaanks/WINS.git
cd WINS
export PATH="$PWD/bin:$PATH"
```

### Use
```bash
wins probe  Qwen-1.0.3.44-release-win-x64.exe          # what is it really? (add --json for agents)
wins transmute Qwen-1.0.3.44-release-win-x64.exe        # port it to a native Linux app
wins harvest npp.8.9.9.Installer.x64.exe                # inspect a native PE: APIs, embedded engines
wins fuzz --iterations 100000                           # differential fuzzer (Zig)
wins test notion --timeout 5.0                         # cleanroom run + structured diagnostics
wins list                                               # available recipes
```

Example `probe` output:

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

---

## Runtime support (what the code does today)

| Runtime | State |
|---|---|
| **Electron** | Working: ASAR de-layering, platform-check patching, `.node` healing with Linux prebuilds, runtime re-binding. Demonstrated on Notion |
| **NW.js (RPG Maker MZ games)** | No `wins` recipe yet: Look Outside was packaged as an AppImage separately (its own `GUIA.md` lives next to the AppImage in `~/Documentos/Look Outside Linux/` on the author's machine). Turning that into a recipe is the obvious next step |
| **.NET (modern) / Avalonia** | Extraction and `runtimeconfig.json` adaptation implemented; a successful launch of ShareX is not demonstrated |
| **Native Win32 PE** | Triage, API harvest and POSIX-shim launcher; no PE loader. Apps routed to `recipe_micro_wine` do not run: **that recipe is not implemented** |
| **PyInstaller** | Recipe is a stub (`transmute` returns failure) |
| **JVM / Launch4j** | Planned |

### 4. Heal Companion Binaries of an Installed App

Runtime-wrapped apps usually ship **Windows-only helper executables** next to
their payload (`resources/bin/*.exe`: device agents, sidecars, utility hosts).
On Linux the application spawns them **without the `.exe` extension**, so a
naive transmutation leaves the app with a broken connector.

```bash
wins heal-bin ~/.local/share/manus-desktop --app-id manus
```

`heal-bin` is native-first:
1. **Native re-binding** — a Linux ELF build of the helper is fetched (vendor
   Linux package or `~/.cache/wins/companions/`) and installed under the
   extension-less host name.
2. **Micro-Wine shim** — when no native build exists, WINS generates a
   hardened launcher that re-hosts the PE under an isolated Wine prefix
   (local-API fd relay, deterministic pipe handshake, no `~/.wine` pollution).

Unlike a hand-written wrapper, the shim is tracked by the toolchain, can be
re-applied at any time and is covered by the test suite.

```bash
wins heal-bin <app-dir> --dry-run --json   # report only, machine readable
```

---

## Agentic interoperability

WINS is built to be driven by coding agents: `wins probe --json` returns the structured taxonomy, `wins transmute`
performs the port, and `wins test --json` returns stderr telemetry with structured `agent_actions`. Instead of
fighting a Wine prefix, an agent can decide, port, or report why not — with evidence.

---

## Limits (NOT_DEMONSTRATED)

A PE import inventory, a compiled shim, or a finite fuzz run is not proof that a Windows program was ported or behaves
equivalently. No `winlux*` replacement has been compared with a real Windows kernel. Games and apps are verified only
as far as the table above says.

---

## License
WINS is open-source software licensed under the [MIT License](LICENSE).
