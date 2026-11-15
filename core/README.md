# Core Subsystem

## Overview
The central engine of WINS. Provides binary taxonomy classification (`BinaryTriage`), black-box runtime diagnostic telemetry (`CleanroomTester`), native addon polyfill/healing (`healers`), and runtime transmutation execution (`recipes`).

## Interface
- `BinaryTriage(file_path: str)`: Static heuristic triage and classifier (`[triage.py:BinaryTriage]`).
  - `BinaryTriage.probe() -> Dict[str, Any]`: Inspects envelope headers and PE overlays to output structured taxonomy reports.
  - `BinaryTriage._detect_envelope(data: bytes) -> Dict[str, Any]`: Identifies NSIS, Inno Setup, WiX/MSI, 7z SFX, or Standalone PE.
  - `BinaryTriage._detect_runtime(data: bytes) -> Dict[str, Any]`: Classifies runtime signature (Electron, PyInstaller, .NET, JVM, Native PE).
  - `BinaryTriage._probe_installer_contents(envelope_type: str) -> Optional[Dict[str, Any]]`: Queries internal archive listings via `7z` or `innoextract`.
- `CleanroomTester(target: str, timeout: float = 5.0, headless: bool = False)`: Telemetry and diagnostic engine (`[tester.py:CleanroomTester]`).
  - `CleanroomTester.execute() -> Dict[str, Any]`: Runs transmuted application in an isolated subprocess group, capturing stdout/stderr and classifying health status.
  - `CleanroomTester._analyze_logs(logs: str, exit_code: Optional[int], timed_out: bool) -> Dict[str, Any]`: Diagnoses FFI crashes, dlopen failures, missing modules, and emits actionable remediation items for AI agents.
- [Healers Subsystem](./healers/README.md): Resolves Linux ELF prebuilds and safe JavaScript proxy stubs for native binary addons.
- [Recipes Subsystem](./recipes/README.md): Modular extraction and re-hosting recipes for Electron, .NET Core/Avalonia, PyInstaller, and Native PE Transpilation.
- [Transpiler Subsystem](./transpiler/README.md): Static PE parsing, IAT extraction, RTTI class demangling, and POSIX zero-Win32 shimming.
- [Fuzzer Subsystem](./fuzzer/README.md): Ultra-high-throughput Zig differential fuzzing engine for proving candidate API equivalence.

## Invariants
- **Non-Execution Invariant in Triage**: `BinaryTriage.probe()` must perform static binary inspection and archive indexing without executing untrusted target machine code (`[triage.py:probe]`).
- **Telemetry Capture Invariant**: `CleanroomTester` must capture both stdout and stderr during process timeout events without losing buffer streams (`[tester.py:execute]`).
- **Process Group Cleanup**: `CleanroomTester` must use process groups (`os.setsid`, `os.killpg`) to ensure child GUI processes and daemon threads are reliably terminated when timeouts occur (`[tester.py:execute]`).

## Side Effects
- Spawns inspection and telemetry processes: `7zz`, `innoextract`, and target transmuted binaries.
- Sets environment variables for telemetry: `ELECTRON_ENABLE_LOGGING=1`, `DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1`.
- Does not modify source binary files during triage or testing.

## Verification
- Run: `python3 -m unittest discover tests`
