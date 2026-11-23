"""L1 wins.triage: read-only binary classification and import inspection.

Reuses existing WINS components without executing unknown binaries:
  - `core.triage.BinaryTriage` (equivalent to `wins probe --json`)
  - `build/wins-native imports --json` when available on disk
  - Optional profile log/snapshot discovery under ~/.local/{share,state}/wins/<profile>
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .security import enforce_context_budget, repo_root, sanitize_text, sha256_file, validate_path


def _find_wins_native() -> Optional[Path]:
    root = repo_root()
    for cand in (
        root / "build" / "wins-native",
        Path("/tmp/wins-build/wins-native"),
    ):
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
    return None


def _run_core_triage(target: Path) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    root_str = str(repo_root())
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    try:
        from core.triage import BinaryTriage

        return BinaryTriage(str(target)).probe(), None
    except Exception as exc:
        return None, f"BinaryTriage error: {exc}"


def _run_wins_native_imports(target: Path, timeout_s: float = 15.0) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    bin_path = _find_wins_native()
    if bin_path is None:
        return None, "build/wins-native not built; PE import table skipped (build with `zig build-exe native/main.zig -O ReleaseSafe -femit-bin=build/wins-native`)."
    try:
        proc = subprocess.run(
            [str(bin_path), "imports", str(target), "--json"],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        if proc.returncode != 0:
            return None, f"wins-native exited {proc.returncode}: {sanitize_text(proc.stderr.strip(), 240)}"
        return json.loads(proc.stdout), None
    except Exception as exc:
        return None, f"wins-native invocation failed: {exc}"


def _peek_pe_header(target: Path) -> Dict[str, Any]:
    """Minimal read-only PE/ELF/Mach-O magic and architecture check."""
    try:
        with open(target, "rb") as f:
            head = f.read(4096)
    except OSError as exc:
        return {"format": "unreadable", "error": str(exc)}

    if head.startswith(b"MZ") and len(head) >= 0x40:
        pe_off = int.from_bytes(head[0x3C:0x40], "little")
        if pe_off + 24 <= len(head) and head[pe_off : pe_off + 4] == b"PE\x00\x00":
            machine = int.from_bytes(head[pe_off + 4 : pe_off + 6], "little")
            arch = {0x014C: "i386", 0x8664: "x86_64", 0xAA64: "arm64"}.get(machine, f"0x{machine:04x}")
            opt_magic = int.from_bytes(head[pe_off + 24 : pe_off + 26], "little") if pe_off + 26 <= len(head) else 0
            fmt = "PE32+" if opt_magic == 0x20B else ("PE32" if opt_magic == 0x10B else "PE")
            return {"format": fmt, "architecture": arch}
        return {"format": "MZ_DOS_OR_INSTALLER", "architecture": "unknown"}
    if head.startswith(b"\x7fELF"):
        cls = "x86_64" if len(head) > 4 and head[4] == 2 else "i386"
        return {"format": "ELF", "architecture": cls}
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"):
        return {"format": "Mach-O", "architecture": "x86_64_or_universal"}
    return {"format": "unknown", "architecture": "unknown"}


def run_triage(
    target_path: Optional[str] = None,
    *,
    profile: Optional[str] = None,
    investigation_type: str = "general",
    allowed_roots: Optional[List[Path]] = None,
    max_imports: int = 20,
) -> Dict[str, Any]:
    """Perform read-only triage of a binary and/or WINS application profile."""
    warnings: List[str] = []
    evidence: List[str] = []
    result: Dict[str, Any] = {
        "data_trust": "UNTRUSTED_TELEMETRY",
        "read_only": True,
        "investigation_type": investigation_type,
        "format": "unknown",
        "architecture": "unknown",
        "relevant_imports": [],
        "missing_dependencies": [],
        "observed_compatibility": None,
        "existing_diagnostics": {},
        "evidence_consulted": evidence,
        "warnings": warnings,
    }

    if target_path:
        target = validate_path(target_path, allowed_roots, must_exist=True)
        if not target.is_file():
            raise ValueError(f"Target is not a regular file: {target}")
        evidence.append(f"{target.name} (sha256:{sha256_file(target)[:16]})")

        hdr = _peek_pe_header(target)
        result["format"] = hdr.get("format", "unknown")
        result["architecture"] = hdr.get("architecture", "unknown")

        probe, probe_err = _run_core_triage(target)
        if probe_err:
            warnings.append(probe_err)
        elif probe is not None:
            result["observed_compatibility"] = {
                "runtime": probe.get("runtime"),
                "envelope": (probe.get("envelope") or {}).get("name"),
                "feasibility": probe.get("feasibility"),
                "recommended_recipe": probe.get("recommended_recipe"),
            }

        if result["format"] in ("PE32", "PE32+", "PE"):
            imp_data, imp_err = _run_wins_native_imports(target)
            if imp_err:
                warnings.append(imp_err)
            elif imp_data is not None:
                dlls = imp_data.get("imports") or imp_data.get("dlls") or []
                if isinstance(dlls, dict):
                    dll_names = sorted(dlls.keys())
                elif isinstance(dlls, list):
                    dll_names = [
                        (d.get("dll") or d.get("name") or str(d)) if isinstance(d, dict) else str(d)
                        for d in dlls
                    ]
                else:
                    dll_names = []
                bounded, trunc, total = enforce_context_budget(dll_names, max_imports, hard_cap=50)
                result["relevant_imports"] = bounded
                result["imports_total"] = total
                result["imports_truncated"] = trunc

    if profile:
        if "/" in profile or "\\" in profile or ".." in profile:
            raise ValueError("profile must be a simple name (e.g. 'ds3', 'cuphead', 'falloutnv').")
        home = Path(os.environ.get("WINS_MCP_HOME") or os.path.expanduser("~")).resolve()
        share_dir = home / ".local" / "share" / "wins" / profile / "profile"
        state_dir = home / ".local" / "state" / "wins" / profile / "logs"
        diag: Dict[str, Any] = {"profile": profile}

        snap_dir = share_dir / "snap_out"
        if snap_dir.is_dir():
            draws_log = snap_dir / "draws.log"
            diag["snapshot_dir"] = str(snap_dir)
            diag["has_draws_log"] = draws_log.is_file()
            evidence.append(f"profile/{profile}/snap_out")

        if state_dir.is_dir():
            logs = sorted(state_dir.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
            diag["log_count"] = len(logs)
            if logs:
                diag["latest_log"] = str(logs[0])
                evidence.append(logs[0].name)
        else:
            warnings.append(f"No log directory found for profile '{profile}'.")

        launcher_dir = repo_root() / "launch" / profile
        if launcher_dir.is_dir():
            diag["has_steam_launcher"] = True
            diag["has_launcher_readme"] = (launcher_dir / "README.txt").is_file()
            evidence.append(f"launch/{profile}")

        result["existing_diagnostics"] = diag

    if not target_path and not profile:
        warnings.append("Provide target_path and/or profile for concrete triage output.")

    return result
