"""L1 wins.receipt: auditable investigation receipt & SHA-256 manifest generator.

Emits:
  - `receipt_<investigation_id>.json`: complete structured investigation record
  - `manifest.json`: SHA-256 integrity manifest over all referenced artifacts
  - `isymem_summary`: compact record consumable by ISyMem without modifying ISyMem
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .security import repo_root, safe_rel_label, sanitize_text, sha256_bytes, sha256_file, validate_path
from .workflow import FINAL_VERDICTS


def _git_info(cwd: Path) -> Dict[str, Any]:
    def _run(args: List[str]) -> str:
        try:
            p = subprocess.run(args, cwd=str(cwd), capture_output=True, text=True, timeout=5.0, check=False)
            return p.stdout.strip() if p.returncode == 0 else ""
        except Exception:
            return ""

    return {
        "repo": str(cwd.name),
        "branch": _run(["git", "rev-parse", "--abbrev-ref", "HEAD"]) or "unknown",
        "commit": _run(["git", "rev-parse", "--short", "HEAD"]) or "unknown",
        "dirty_files": [
            line for line in _run(["git", "status", "--short"]).splitlines() if line.strip()
        ][:30],
    }


def generate_receipt(
    investigation_id: str,
    *,
    verdict: str,
    hypothesis: str,
    out_dir: Path,
    allowed_roots: Optional[Sequence[Path]] = None,
    initial_evidence: Optional[Dict[str, Any]] = None,
    captures: Optional[List[str]] = None,
    relevant_draws: Optional[List[Dict[str, Any]]] = None,
    audited_invariants: Optional[List[Dict[str, Any]]] = None,
    patch_diff_summary: Optional[str] = None,
    tests_executed: Optional[List[Dict[str, Any]]] = None,
    counterexamples: Optional[List[str]] = None,
    limitations: Optional[List[str]] = None,
    rollback_procedure: Optional[str] = None,
    artifact_paths: Optional[List[str]] = None,
    repo_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    if verdict not in FINAL_VERDICTS:
        raise ValueError(f"verdict must be one of {sorted(FINAL_VERDICTS)}")
    if not investigation_id or "/" in investigation_id or ".." in investigation_id:
        raise ValueError("Invalid investigation_id.")

    if verdict == "DEMONSTRATED":
        # Guard: DEMONSTRATED requires at least one executed test with PASS and 0 FAIL
        tests = tests_executed or []
        has_pass = any((t.get("status") == "PASS") for t in tests if isinstance(t, dict))
        has_fail = any((t.get("status") in ("FAIL", "TIMEOUT", "CANCELLED")) for t in tests if isinstance(t, dict))
        if not has_pass or has_fail:
            raise ValueError(
                "Cannot issue verdict DEMONSTRATED without passing tests_executed and zero failures."
            )

    out_path = validate_path(out_dir, allowed_roots, must_exist=False)
    out_path.mkdir(parents=True, exist_ok=True)

    git_meta = _git_info(repo_dir or repo_root())

    manifest_entries: List[Dict[str, Any]] = []
    for raw_art in artifact_paths or []:
        art = validate_path(raw_art, allowed_roots, must_exist=True)
        if art.is_file():
            manifest_entries.append(
                {
                    "label": safe_rel_label(art),
                    "size_bytes": art.stat().st_size,
                    "sha256": sha256_file(art),
                }
            )

    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    receipt: Dict[str, Any] = {
        "schema_version": "wins-receipt/0.1",
        "investigation_id": investigation_id,
        "generated_at": ts,
        "verdict": verdict,
        "git": git_meta,
        "hypothesis": hypothesis,
        "initial_evidence": initial_evidence or {},
        "captures": captures or [],
        "relevant_draws": (relevant_draws or [])[:12],
        "audited_invariants": (audited_invariants or [])[:12],
        "patch_diff_summary": sanitize_text(patch_diff_summary or "", max_chars=2000),
        "tests_executed": tests_executed or [],
        "counterexamples": counterexamples or [],
        "limitations": limitations or [],
        "rollback_procedure": rollback_procedure or "git checkout -- <modified_paths> (no files modified if read-only).",
        "artifacts": manifest_entries,
        "isymem_summary": {
            "project": "wins",
            "anchor_kind": "state" if verdict == "DEMONSTRATED" else "fail",
            "one_liner": (
                f"[{verdict}] {investigation_id} ({git_meta['branch']}@{git_meta['commit']}): "
                f"{hypothesis[:110]}"
            ),
        },
    }

    receipt_file = out_path / f"receipt_{investigation_id}.json"
    receipt_bytes = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
    receipt_file.write_bytes(receipt_bytes)

    manifest = {
        "schema_version": "wins-manifest/0.1",
        "investigation_id": investigation_id,
        "generated_at": ts,
        "entries": [
            {
                "label": receipt_file.name,
                "size_bytes": len(receipt_bytes),
                "sha256": sha256_bytes(receipt_bytes),
            },
            *manifest_entries,
        ],
    }
    manifest_file = out_path / "manifest.json"
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    manifest_file.write_bytes(manifest_bytes)

    return {
        "investigation_id": investigation_id,
        "verdict": verdict,
        "receipt_path": str(receipt_file),
        "receipt_sha256": sha256_bytes(receipt_bytes),
        "manifest_path": str(manifest_file),
        "manifest_sha256": sha256_bytes(manifest_bytes),
        "artifact_count": len(manifest["entries"]),
        "isymem_summary": receipt["isymem_summary"],
    }


def verify_manifest(manifest_path: Path, base_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Verify SHA-256 digests listed in a receipt manifest.json."""
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    root = base_dir or manifest_path.parent
    checked = 0
    mismatches: List[Dict[str, Any]] = []
    for entry in data.get("entries", []):
        label = entry["label"]
        expected = entry["sha256"]
        cand = root / label
        if not cand.is_file():
            # Allow checking only local files present in manifest directory
            continue
        checked += 1
        actual = sha256_file(cand)
        if actual != expected:
            mismatches.append({"label": label, "expected": expected, "actual": actual})
    return {"ok": len(mismatches) == 0 and checked > 0, "checked": checked, "mismatches": mismatches}
