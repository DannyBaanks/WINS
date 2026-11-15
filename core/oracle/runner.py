"""Behavioral Harness Runner.
Compiles and executes isolated Zig test binaries against runtime oracles.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional


@dataclass
class OracleResult:
    passed: bool
    test_name: str
    counterexample: Optional[str] = None
    diagnostics: str = ""
    duration_ms: float = 0.0


def run_behavioral_harness(test_name: str, harness_zig_code: str, timeout_sec: int = 10) -> OracleResult:
    """Compila y ejecuta un arnés conductual en Zig, extrayendo contraejemplos si falla."""
    with tempfile.NamedTemporaryFile("w", suffix=".zig", delete=False) as f:
        f.write(harness_zig_code)
        src_path = f.name

    bin_path = src_path + ".bin"
    try:
        # 1. Compilar con Zig nativo x86_64 o musl (-O Debug para compilación sub-segundo)
        build_cmd = ["zig", "build-exe", src_path, f"-femit-bin={bin_path}", "-O", "Debug", "-lc"]
        build_res = subprocess.run(build_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)

        if build_res.returncode != 0:
            return OracleResult(
                passed=False,
                test_name=test_name,
                counterexample="COMPILATION_FAILED",
                diagnostics=build_res.stderr or build_res.stdout,
            )

        # 2. Ejecutar arnés
        run_res = subprocess.run([bin_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout_sec)

        passed = (run_res.returncode == 0)
        output = (run_res.stdout + run_res.stderr).strip()

        counterexample = None
        if not passed:
            # Buscar línea de contraejemplo en la salida
            for line in output.split("\n"):
                if "COUNTEREXAMPLE:" in line or "FAILED:" in line or "panic:" in line:
                    counterexample = line.strip()
                    break
            if not counterexample:
                counterexample = f"Exited with code {run_res.returncode}: {output[:200]}"

        return OracleResult(
            passed=passed,
            test_name=test_name,
            counterexample=counterexample,
            diagnostics=output,
        )

    except Exception as e:
        return OracleResult(
            passed=False,
            test_name=test_name,
            counterexample=f"EXECUTION_EXCEPTION: {str(e)}",
            diagnostics=str(e),
        )
    finally:
        if os.path.isfile(src_path):
            os.remove(src_path)
        if os.path.isfile(bin_path):
            os.remove(bin_path)
        obj_path = src_path + ".o"
        if os.path.isfile(obj_path):
            os.remove(obj_path)
