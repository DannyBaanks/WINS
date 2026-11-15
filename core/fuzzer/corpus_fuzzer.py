"""
WINS Corpus Fuzzer & Multi-Binary Attack Radar
Analyzes a corpus of real Windows PE binaries against winrun and winrun_gui,
extracts blocking symbols, calculates frequency Pareto rankings across binaries,
and directs automated shim synthesis to maximize binary unlock rate.
"""

import os
import sys
import glob
import json
import hashlib
import subprocess
from collections import Counter, defaultdict
from typing import Dict, Any, List, Optional, Tuple

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from core.transpiler.harvester import BinaryHarvester

BOX = [
    "bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--clearenv",
    "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
    "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
    "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"
]


class CorpusFuzzer:
    def __init__(self, corpus_dir: Optional[str] = None):
        self.corpus_dir = os.path.abspath(corpus_dir or os.path.join(REPO_ROOT, "corpus"))
        self.winrun_bin = os.path.join(REPO_ROOT, "native", "winrun")
        self.winrun_gui_bin = os.path.join(REPO_ROOT, "native", "winrun_gui")

    def ensure_loaders(self):
        """Ensures that both winrun and winrun_gui binaries are compiled."""
        if not os.path.isfile(self.winrun_bin):
            subprocess.run(["zig", "build-exe", "native/winrun.zig", "-O", "ReleaseSafe", f"-femit-bin={self.winrun_bin}"],
                           cwd=REPO_ROOT, check=True)
        if not os.path.isfile(self.winrun_gui_bin):
            subprocess.run(["zig", "build-exe", "native/winrun_gui.zig", "-O", "ReleaseSafe", "-lc", "-lX11", f"-femit-bin={self.winrun_gui_bin}"],
                           cwd=REPO_ROOT, check=True)

    def scan_corpus(self) -> List[str]:
        """Finds all PE binaries in the corpus directory."""
        if not os.path.isdir(self.corpus_dir):
            return []
        entries = []
        for name in os.listdir(self.corpus_dir):
            path = os.path.join(self.corpus_dir, name)
            if os.path.isfile(path) and (name.lower().endswith(".exe") or name.lower().endswith(".dll")):
                entries.append(path)
        return sorted(entries)

    def test_binary(self, binary_path: str) -> Dict[str, Any]:
        """Tests a single binary against winrun/winrun_gui --check inside bwrap."""
        data = open(binary_path, "rb").read()
        digest = hashlib.sha256(data).hexdigest()
        name = os.path.basename(binary_path)

        harvester = BinaryHarvester(binary_path)
        try:
            harvester.parse_pe()
            imports = harvester.imports
            total_imported = sum(len(v) for v in imports.values())
        except Exception:
            imports = {}
            total_imported = 0

        # Run check under winrun_gui (which supports both GUI and Console)
        argv = BOX + [
            "--ro-bind", binary_path, "/target.exe",
            "--ro-bind", self.winrun_gui_bin, "/loader",
            "--", "/loader", "--sha256", digest, "--check", "/target.exe"
        ]
        res = subprocess.run(argv, capture_output=True, text=True, timeout=15)

        missing_apis = []
        status = "UNKNOWN"

        if res.returncode == 0:
            status = "READY"
        elif res.returncode == 4:
            status = "UNRESOLVED_IMPORTS"
            # Parse missing lines from stderr: "  lib!sym"
            for line in res.stderr.splitlines():
                line = line.strip()
                if "!" in line and not line.startswith("winrun:"):
                    parts = line.split("!", 1)
                    dll = parts[0].strip()
                    sym = parts[1].strip()
                    missing_apis.append({"dll": dll, "symbol": sym, "full": f"{dll}!{sym}"})
        elif res.returncode == 3:
            status = f"REFUSED: {res.stderr.strip()}"
        elif res.returncode == 5:
            status = f"BAD_IMAGE: {res.stderr.strip()}"
        else:
            status = f"EXIT_{res.returncode}: {res.stderr.strip()}"

        missing_count = len(missing_apis)
        if status == "READY":
            resolved_count = total_imported
            readiness_pct = 100.0 if total_imported > 0 else 100.0
        elif status == "UNRESOLVED_IMPORTS":
            resolved_count = max(0, total_imported - missing_count)
            readiness_pct = (resolved_count / total_imported * 100.0) if total_imported > 0 else 0.0
        else:
            resolved_count = 0
            readiness_pct = 0.0

        return {
            "name": name,
            "path": binary_path,
            "sha256": digest,
            "size_bytes": len(data),
            "status": status,
            "total_imported_apis": total_imported,
            "resolved_apis": resolved_count,
            "missing_apis_count": missing_count,
            "readiness_pct": round(readiness_pct, 1),
            "missing_apis": missing_apis,
        }

    def attack(self) -> Dict[str, Any]:
        """Runs the full corpus fuzzer attack and computes Pareto ranking."""
        self.ensure_loaders()
        binaries = self.scan_corpus()

        results = []
        global_missing_counter = Counter()
        dll_missing_counter = Counter()
        binary_blockers = defaultdict(list)

        for b in binaries:
            res = self.test_binary(b)
            results.append(res)
            for m in res["missing_apis"]:
                full = m["full"]
                global_missing_counter[full] += 1
                dll_missing_counter[m["dll"]] += 1
                binary_blockers[full].append(res["name"])

        total_binaries = len(binaries)
        ready_binaries = sum(1 for r in results if r["status"] == "READY")

        # Top ranking of missing APIs
        pareto_ranking = []
        for sym, count in global_missing_counter.most_common(50):
            dll = sym.split("!")[0]
            api = sym.split("!")[1]
            pct_corpus = round(count / total_binaries * 100.0, 1) if total_binaries > 0 else 0.0
            pareto_ranking.append({
                "symbol": sym,
                "dll": dll,
                "api": api,
                "blocked_binaries_count": count,
                "corpus_block_pct": pct_corpus,
                "blocked_binaries": binary_blockers[sym]
            })

        return {
            "corpus_dir": self.corpus_dir,
            "total_binaries": total_binaries,
            "ready_binaries": ready_binaries,
            "total_unique_missing_apis": len(global_missing_counter),
            "missing_apis_by_dll": dict(dll_missing_counter.most_common()),
            "top_pareto_blockers": pareto_ranking,
            "binaries": results,
        }


def print_attack_report(report: Dict[str, Any]):
    print(f"\n=======================================================")
    print(f"       WINS CORPUS ATTACK RADAR & FUZZER REPORT        ")
    print(f"=======================================================\n")
    print(f"Corpus Directory:      {report['corpus_dir']}")
    print(f"Total Binaries Scanned:{report['total_binaries']}")
    print(f"Fully READY Binaries:  {report['ready_binaries']} / {report['total_binaries']}")
    print(f"Unique Missing APIs:   {report['total_unique_missing_apis']}")

    print(f"\n[CORPUS BINARY READINESS MATRIX]")
    print(f"{'Binary':<24} {'Status':<16} {'Imported':<10} {'Resolved':<10} {'Missing':<10} {'Readiness'}")
    print(f"{'-'*24} {'-'*16} {'-'*10} {'-'*10} {'-'*10} {'-'*10}")
    for b in report["binaries"]:
        status_disp = "READY (100%)" if b["status"] == "READY" else b["status"][:16]
        print(f"{b['name']:<24} {status_disp:<16} {b['total_imported_apis']:<10} {b['resolved_apis']:<10} {b['missing_apis_count']:<10} {b['readiness_pct']}%")

    print(f"\n[TOP MISSING APIS BY DLL]")
    for dll, count in report["missing_apis_by_dll"].items():
        print(f"  * {dll:<20} {count} missing occurrences across corpus")

    print(f"\n[PARETO ATTACK TARGETS: TOP 25 MOST-BLOCKING APIS]")
    print(f"{'Rank':<5} {'API Full Name':<38} {'Blocked Binaries':<18} {'Sample Victims'}")
    print(f"{'-'*5} {'-'*38} {'-'*18} {'-'*30}")
    for idx, item in enumerate(report["top_pareto_blockers"][:25], 1):
        victims = ", ".join(item["blocked_binaries"][:3])
        if len(item["blocked_binaries"]) > 3:
            victims += f" (+{len(item['blocked_binaries'])-3} more)"
        print(f"#{idx:<4} {item['symbol']:<38} {item['blocked_binaries_count']} ({item['corpus_block_pct']}%)        {victims}")
    print("")
