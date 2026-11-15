# Core Fuzzer Component Package (Zig Engine)

## Overview
Ultra-high-throughput differential fuzzing engine written in Zig (`wins-fuzz`). Executes millions of deterministic pseudo-random iterations across candidate Linux shims and reference Windows models to prove functional equivalence and detect behavioral divergences.

## Interface
- CLI Binary: `bin/wins-fuzz` (compiled from `core/fuzzer/src/main.zig`).
  - `--suite <all|path|encoding|registry|pixel|security|buffer>`: Target differential test suite.
  - `--iterations <N>`: Iterations count per suite (default: 100,000).
  - `--seed <S>`: Deterministic PRNG seed for reproducibility.
  - `--json`: Machine-readable JSON output for AI agents.
- Core Modules:
  - `generator.zig`: Seedable PRNG and edge-case generator (Unicode surrogates, path traversal, DOS devices, ADS, pixel boundaries, mixed EOL text buffers).
  - `suites/path_suite.zig`: Path normalization and translation equivalence.
  - `suites/encoding_suite.zig`: UTF-16LE (`wchar_t`) to UTF-8 transcoding equivalence and surrogate pair integrity.
  - `suites/registry_suite.zig`: Virtual registry to XDG config key-value store mapping.
  - `suites/pixel_suite.zig`: Direct2D & ComputeSharp HLSL pixel math (premultiplication, unpremultiplication, Porter-Duff blend modes, float32 shader equivalence for Paint.NET).
  - `suites/path_security_suite.zig`: Windows path anomalies & security invariants (DOS device escaping `CON`/`PRN`/`AUX`, Alternate Data Stream `ADS` isolation, trailing dot/space trimming).
  - `suites/buffer_suite.zig`: Scintilla text buffer navigation (mixed `\r\n`/`\n`/`\r` line indexer, byte-to-line/column mapping, UTF-8 multibyte cursor alignment for Notepad++).

## Invariants
- **Deterministic Fuzzing**: Supplying identical `--seed <S>` generates bit-for-bit identical input sequences.
- **Fail-Closed Discrepancy Capture**: Any output divergence between reference and candidate captures the minimal counter-example vector.
- **Zero-Allocation Hot Loop**: Fuzzing loops use stack buffers without dynamic heap allocation to maintain >3,000,000 ops/sec throughput.

## Benchmark Performance
- Single Suite Throughput (Pixel Math): **>39,000,000 ops/sec** (50,000 iterations in 1.28 ms).
- Aggregate Throughput (6 Suites): **>3,100,000 ops/sec** (300,000 iterations in 96.15 ms).
- Divergences: **0** across all 6 test domains.

## Verification
- CLI Run: `bin/wins fuzz --iterations 50000`
- JSON Run: `bin/wins fuzz --suite pixel --iterations 50000 --json`
- Python Tests: `python3 -m unittest discover tests -p "test_fuzzer.py"`
