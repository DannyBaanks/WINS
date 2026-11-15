"""CEGIS Autonomous Fuzzer: Integrates IntentLang Synthesis, Runtime Behavioral Oracles,
and the Mutation Gate to discover and verify Win32 shims with zero human intervention.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

WINS_DIR = "/home/danny/Development/ISyCo Git/WINS"
INTENTLANG_DIR = "/home/danny/Development/ISyCo Git/IntentLang/src"

for p in (WINS_DIR, INTENTLANG_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from core.oracle.io_oracle import IoBehavioralOracle
from core.oracle.memory_oracle import MemoryBehavioralOracle
from core.oracle.mutation_gate import MutationGate, MutationVerdict
from core.oracle.process_oracle import ProcessBehavioralOracle
from core.oracle.tls_oracle import TlsBehavioralOracle
from intentlang.win32_system.cegis_synthesizer import CegisResult, CegisSynthesizer


@dataclass
class CegisVerificationReport:
    timestamp: str
    verified_families: Dict[str, Any]
    mutation_gate_verdicts: List[Dict[str, Any]]
    mutation_rejection_rate: float
    total_apis_verified: int
    unverified_policy: str
    sha256: str


class CegisAutonomousFuzzer:
    """Fuzzer y sintetizador conductual autónomo CEGIS."""

    def __init__(self):
        self.synthesizer = CegisSynthesizer()
        self.tls_oracle = TlsBehavioralOracle()
        self.mem_oracle = MemoryBehavioralOracle()
        self.io_oracle = IoBehavioralOracle()
        self.proc_oracle = ProcessBehavioralOracle()
        self.mutation_gate = MutationGate()

    def run_autonomous_synthesis_cycle(self) -> CegisVerificationReport:
        """Ejecuta el ciclo de síntesis CEGIS completo y el Mutation Gate."""
        start_time = time.time()
        verified_families: Dict[str, Any] = {}

        # 1. Síntesis CEGIS de TLS
        tls_res = self.synthesizer.synthesize_tls(self.tls_oracle)
        verified_families["TLS"] = {
            "passed": tls_res.final_passed,
            "iterations": tls_res.iterations_count,
            "apis": ["TlsAlloc", "TlsGetValue", "TlsSetValue", "TlsFree"],
            "trace": [
                {"iter": it.iteration, "passed": it.oracle_passed, "counterexample": it.counterexample}
                for it in tls_res.trace
            ],
            "verified_code": tls_res.final_verified_code,
        }

        # 2. Síntesis CEGIS de Memoria Virtual
        mem_res = self.synthesizer.synthesize_memory(self.mem_oracle)
        verified_families["MEMORY"] = {
            "passed": mem_res.final_passed,
            "iterations": mem_res.iterations_count,
            "apis": ["VirtualAlloc", "VirtualProtect", "VirtualFree", "GetLastError", "SetLastError"],
            "trace": [
                {"iter": it.iteration, "passed": it.oracle_passed, "counterexample": it.counterexample}
                for it in mem_res.trace
            ],
            "verified_code": mem_res.final_verified_code,
        }

        # 3. Validación de Mutantes en el Mutation Gate
        mutant_verdicts = self.mutation_gate.evaluate_all()
        rejected_count = sum(1 for v in mutant_verdicts if v.rejected)
        rejection_rate = (rejected_count / len(mutant_verdicts)) * 100.0 if mutant_verdicts else 0.0

        # Formatear veredictos
        verdicts_data = [
            {
                "mutant_id": v.mutant_id,
                "description": v.description,
                "compiles_in_zig": v.compiles_in_zig,
                "detected": v.detected,
                "rejected": v.rejected,
                "counterexample": v.counterexample,
            }
            for v in mutant_verdicts
        ]

        total_apis = sum(len(f["apis"]) for f in verified_families.values() if f["passed"])

        report_dict = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "verified_families": verified_families,
            "mutation_gate_verdicts": verdicts_data,
            "mutation_rejection_rate": rejection_rate,
            "total_apis_verified": total_apis,
            "unverified_policy": "INSUFFICIENT_EVIDENCE / UNKNOWN (no unproven stub is certified as equivalent)",
        }

        # Calcular SHA-256
        content_str = json.dumps(report_dict, sort_keys=True, indent=2)
        sha256 = hashlib.sha256(content_str.encode("utf-8")).hexdigest()
        report_dict["sha256"] = sha256

        return CegisVerificationReport(
            timestamp=report_dict["timestamp"],
            verified_families=report_dict["verified_families"],
            mutation_gate_verdicts=report_dict["mutation_gate_verdicts"],
            mutation_rejection_rate=report_dict["mutation_rejection_rate"],
            total_apis_verified=report_dict["total_apis_verified"],
            unverified_policy=report_dict["unverified_policy"],
            sha256=sha256,
        )


def main():
    fuzzer = CegisAutonomousFuzzer()
    print("=== STARTING CEGIS AUTONOMOUS SYNTHESIS & MUTATION GATE ===")
    report = fuzzer.run_autonomous_synthesis_cycle()
    print(f"Verified Families: {list(report.verified_families.keys())}")
    print(f"Total APIs Conductually Proven: {report.total_apis_verified}")
    print(f"Mutation Rejection Rate: {report.mutation_rejection_rate:.1f}% ({len(report.mutation_gate_verdicts)} mutants)")
    print(f"Cryptographic Receipt SHA-256: {report.sha256}")
    print("=== CEGIS RUN COMPLETE ===")


if __name__ == "__main__":
    main()
