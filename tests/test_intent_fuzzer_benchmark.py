"""
WINS & IntentLang Autonomous Fuzzer-Synthesizer Benchmark.
Evaluates the autonomy, efficiency, and compilation correctness of the
combined Fuzzer + IntentLang semantic synthesis loop across a multi-binary corpus.
"""

import os
import sys
import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INTENTLANG_SRC = "/home/danny/Development/ISyCo Git/IntentLang/src"

if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
if INTENTLANG_SRC not in sys.path:
    sys.path.insert(0, INTENTLANG_SRC)

from core.transpiler.harvester import BinaryHarvester
from intentlang.win32_system import FuzzerIntentBridge


CORPUS_TARGETS = [
    os.path.join(REPO_ROOT, "corpus", "sqlite3.exe"),
    os.path.join(REPO_ROOT, "corpus", "7zr.exe"),
    os.path.join(REPO_ROOT, "corpus", "busybox64.exe"),
    os.path.join(REPO_ROOT, "corpus", "calcbolge.exe"),
    os.path.join(REPO_ROOT, "corpus", "probe_gui_wndproc.exe"),
    "/home/danny/.local/share/Steam/steamapps/common/Fallout New Vegas/FalloutNV.exe",
]


def test_intent_fuzzer_autonomous_corpus():
    bridge = FuzzerIntentBridge()
    results = []

    for path in CORPUS_TARGETS:
        assert os.path.exists(path), f"Corpus target missing: {path}"
        name = os.path.basename(path)

        harvester = BinaryHarvester(path)
        parsed = harvester.parse_pe()
        assert parsed is True, f"Failed to parse PE: {name}"

        zig_code, report = bridge.synthesize_for_imports(name, harvester.imports, verify_zig=True)

        assert report.total_symbols > 0, f"No symbols extracted for {name}"
        assert report.autonomy_rate == 1.0, f"Autonomy dropped below 100% on {name}"
        assert report.compiles_cleanly is True, f"Compilation failed for {name}:\n{report.compiler_diagnostics}"

        results.append(report)

    # Aggregates
    total_syms = sum(r.total_symbols for r in results)
    avg_duration = sum(r.synthesis_duration_ms for r in results) / len(results)

    assert total_syms >= 900
    assert avg_duration < 500.0  # Fast sub-second synthesis
