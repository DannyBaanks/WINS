# Binaries & CLI Component Package

## Overview
Exposes the unified command-line interface (`wins`) for developers and autonomous AI agents. Translates high-level CLI commands (`probe`, `transmute`, `test`, `list`) into WINS Core engine operations and provides both human-readable terminal output and structured JSON payloads.

## Interface
- `wins probe <target> [--json]`: Inspects a Windows binary and outputs detected envelope, runtime taxonomy, and feasibility analysis (`[wins:cmd_probe]`).
- `wins transmute <target> [--dest <dir>] [--bin-dir <dir>] [--electron-version <ver>]`: Executes the appropriate transmutation recipe to de-layer and natively re-host the application on Linux (`[wins:cmd_transmute]`).
- `wins harvest <target> [--json]`: Parses PE headers, IAT, demangles RTTI, and discovers Linux candidate engines (`[wins:cmd_harvest]`).
- `wins fuzz [--suite <all|path|encoding|registry>] [--iterations <N>] [--json]`: Runs the ultra-high-throughput Zig differential fuzzer (>7,000,000 ops/sec) (`[wins:cmd_fuzz]`).
- `wins test <target> [--timeout <sec>] [--headless] [--json]`: Executes black-box cleanroom diagnostic testing on a transmuted application, detecting runtime anomalies and emitting remediation tasks (`[wins:cmd_test]`).
- `wins list`: Displays all available transmutation recipes registered in the engine (`[wins:cmd_list]`).
- Sibling engine interface: Delegates to [Core Engine](../core/README.md).

## Invariants
- **Machine-Readable Protocol**: When `--json` is supplied to `probe` or `test`, stdout must contain strictly valid JSON with no extraneous ASCII art, logging banners, or non-JSON text (`[wins:cmd_probe]`, `[wins:cmd_test]`).
- **Fail-Closed Exit Codes**: The CLI must exit with status `0` on successful completion and `1` when transmutation, inspection, or file operations fail (`[wins:cmd_transmute]`).
- **Zero Ambiguity Target Resolution**: `wins test` must resolve targets via direct path, `~/.local/bin/<target>`, or `~/.local/share/<target>-desktop` without requiring absolute path inputs (`[wins:cmd_test]`).

## Side Effects
- Dispatches filesystem writes, network downloads, and process execution via invoked `core` recipes and testers.
- Writes diagnostic output to stdout/stderr.

## Verification
- Run: `python3 bin/wins list`
- Run: `python3 -m unittest discover tests -p "test_tester.py"`
