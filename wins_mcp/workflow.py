"""L2 wins-debug-workflow: persistent, resumable, evidence-gated state machine.

States:
  REPRODUCE -> CAPTURE -> LOCALIZE -> PATCH -> VERIFY -> RECEIPT

Key guarantees:
  - Phase transitions require explicit evidence guards (never just LLM assertion).
  - State persists atomically to JSON so any investigation can pause and resume.
  - Prior receipts/snapshots of state are preserved in `history` across transitions.
  - Final verdicts (`DEMONSTRATED`, `INFERRED`, `NOT_DEMONSTRATED`, `FALSIFIED`)
    enforce verification rules: `DEMONSTRATED` is forbidden if verify failed or
    was never run.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

STATES = ["REPRODUCE", "CAPTURE", "LOCALIZE", "PATCH", "VERIFY", "RECEIPT"]
FINAL_VERDICTS = {"DEMONSTRATED", "INFERRED", "NOT_DEMONSTRATED", "FALSIFIED"}
RE_SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def default_workflow_dir() -> Path:
    env = os.environ.get("WINS_MCP_STATE_DIR", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    home = Path(os.environ.get("WINS_MCP_HOME") or os.path.expanduser("~")).resolve()
    return (home / ".cache" / "wins" / "mcp-workflows").resolve()


def _state_path(investigation_id: str, state_dir: Optional[Path] = None) -> Path:
    if not RE_SAFE_ID.match(investigation_id):
        raise ValueError(
            "investigation_id must match ^[A-Za-z0-9._-]{1,64}$ (no path separators)."
        )
    base = (state_dir or default_workflow_dir()).resolve()
    base.mkdir(parents=True, exist_ok=True)
    return base / f"{investigation_id}.json"


def _atomic_write_json(path: Path, payload: Dict[str, Any]) -> None:
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def start_investigation(
    investigation_id: str,
    symptom: str,
    *,
    profile: Optional[str] = None,
    coords: Optional[List[List[int]]] = None,
    vision_required: bool = False,
    state_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    if not symptom or not symptom.strip():
        raise ValueError("symptom description is required to start REPRODUCE.")
    path = _state_path(investigation_id, state_dir)
    if path.exists():
        raise FileExistsError(f"Investigation '{investigation_id}' already exists; use resume/get.")

    state: Dict[str, Any] = {
        "schema_version": "wins-workflow/0.1",
        "investigation_id": investigation_id,
        "phase": "REPRODUCE",
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
        "reproduce": {
            "symptom": symptom.strip(),
            "profile": profile,
            "coords": coords or [],
            "vision_used_for_reproduce": bool(vision_required),
            "vision_required_after_reproduce": False,
        },
        "capture": None,
        "localize": {
            "audits": [],
            "blames": [],
            "shaders_inspected": [],
            "hypotheses": [],
        },
        "patch": None,
        "verify": None,
        "receipt": None,
        "prior_receipts": [],
        "history": [
            {
                "timestamp": _now_iso(),
                "from_phase": None,
                "to_phase": "REPRODUCE",
                "note": "Investigation initialized.",
            }
        ],
    }
    _atomic_write_json(path, state)
    return state


def load_investigation(investigation_id: str, state_dir: Optional[Path] = None) -> Dict[str, Any]:
    path = _state_path(investigation_id, state_dir)
    if not path.is_file():
        raise FileNotFoundError(f"Investigation '{investigation_id}' not found.")
    return json.loads(path.read_text(encoding="utf-8"))


def save_investigation(state: Dict[str, Any], state_dir: Optional[Path] = None) -> Dict[str, Any]:
    state["updated_at"] = _now_iso()
    path = _state_path(state["investigation_id"], state_dir)
    _atomic_write_json(path, state)
    return state


def advance_phase(
    investigation_id: str,
    target_phase: str,
    payload: Optional[Dict[str, Any]] = None,
    *,
    state_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Advance or record evidence for a workflow phase with strict evidence guards."""
    if target_phase not in STATES:
        raise ValueError(f"Invalid phase '{target_phase}'. Must be one of {STATES}.")

    state = load_investigation(investigation_id, state_dir)
    current = state["phase"]
    data = payload or {}

    cur_idx = STATES.index(current)
    tgt_idx = STATES.index(target_phase)

    # Preserve existing receipt before transitioning away or rewriting
    if state.get("receipt") is not None and target_phase == "RECEIPT":
        state.setdefault("prior_receipts", []).append(state["receipt"])

    # Allow staying in current phase to attach evidence, stepping +1, or rolling back
    # to an earlier phase for a new iteration while preserving history & prior receipts.
    if tgt_idx > cur_idx + 1:
        raise ValueError(
            f"Cannot jump directly from {current} to {target_phase}. "
            f"Next allowed phase is {STATES[cur_idx + 1]}."
        )

    if target_phase == "CAPTURE":
        capture_id = data.get("capture_id")
        if not capture_id:
            raise ValueError("CAPTURE requires payload.capture_id.")
        state["capture"] = {
            "capture_id": capture_id,
            "dims": data.get("dims"),
            "draws_count": data.get("draws_count"),
            "draws_log_sha256": data.get("draws_log_sha256"),
            "recorded_at": _now_iso(),
        }

    elif target_phase == "LOCALIZE":
        if state.get("capture") is None:
            raise ValueError("Cannot enter LOCALIZE without a recorded CAPTURE.")
        loc = state["localize"]
        if "audit_ref" in data:
            loc["audits"].append(data["audit_ref"])
        if "blame_ref" in data:
            loc["blames"].append(data["blame_ref"])
        if "shader_ref" in data:
            loc["shaders_inspected"].append(data["shader_ref"])
        if "hypothesis" in data:
            hyp = data["hypothesis"]
            if not isinstance(hyp, dict) or not hyp.get("statement") or not hyp.get("falsification_condition"):
                raise ValueError(
                    "Each hypothesis must include non-empty 'statement' and 'falsification_condition'."
                )
            loc["hypotheses"].append(hyp)

    elif target_phase == "PATCH":
        loc = state["localize"]
        if not loc.get("hypotheses"):
            raise ValueError(
                "Cannot enter PATCH without at least one falsifiable hypothesis recorded in LOCALIZE."
            )
        if not (loc.get("audits") or loc.get("blames")):
            raise ValueError(
                "Cannot enter PATCH without deterministic audit or blame evidence from LOCALIZE."
            )
        required_patch_fields = ("files", "contract_affected", "causal_hypothesis", "risks", "rollback_plan")
        missing = [f for f in required_patch_fields if not data.get(f)]
        if missing:
            raise ValueError(f"PATCH proposal missing required fields: {missing}")
        state["patch"] = {
            "files": list(data["files"]),
            "contract_affected": data["contract_affected"],
            "causal_hypothesis": data["causal_hypothesis"],
            "risks": data["risks"],
            "regressions": data.get("regressions", []),
            "rollback_plan": data["rollback_plan"],
            "authorized": bool(data.get("authorized", False)),
            "recorded_at": _now_iso(),
        }

    elif target_phase == "VERIFY":
        if state.get("patch") is None:
            raise ValueError("Cannot enter VERIFY without a recorded PATCH plan.")
        if not data.get("verify_result"):
            raise ValueError("VERIFY requires payload.verify_result from wins.verify.")
        state["verify"] = {
            "verify_result": data["verify_result"],
            "before_after_comparison": data.get("before_after_comparison"),
            "human_review": data.get("human_review"),
            "recorded_at": _now_iso(),
        }

    elif target_phase == "RECEIPT":
        verdict = data.get("verdict")
        if verdict not in FINAL_VERDICTS:
            raise ValueError(f"RECEIPT requires verdict in {sorted(FINAL_VERDICTS)}.")
        if verdict == "DEMONSTRATED":
            ver = state.get("verify")
            vr = (ver or {}).get("verify_result") or {}
            if vr.get("global_status") != "PASS" or not vr.get("checks_passed"):
                raise ValueError(
                    "Cannot promote verdict to DEMONSTRATED without a passing wins.verify execution."
                )
        state["receipt"] = {
            "verdict": verdict,
            "receipt_path": data.get("receipt_path"),
            "manifest_sha256": data.get("manifest_sha256"),
            "limitations": data.get("limitations", []),
            "counterexamples": data.get("counterexamples", []),
            "recorded_at": _now_iso(),
        }

    state["phase"] = target_phase
    state["history"].append(
        {
            "timestamp": _now_iso(),
            "from_phase": current,
            "to_phase": target_phase,
            "note": data.get("note", f"Transitioned to {target_phase}."),
        }
    )
    return save_investigation(state, state_dir)


WORKFLOW_PROMPT_TEXT = """# WINS Debug Workflow (`wins-debug-workflow`)

Follow this 6-phase evidence-driven debugging protocol strictly. Do not skip phases or modify production code during REPRODUCE, CAPTURE, or LOCALIZE.

1. **REPRODUCE**: Confirm the symptom and (if visual) record screen coordinates `(x, y)` supplied by the user or a vision check. Vision is NOT required for phases 2–4.
2. **CAPTURE**: Call `wins.capture_frame` on the snapshot directory or profile. Verify resolution, coordinate bounds, and `draws.log` integrity.
3. **LOCALIZE**: Call `wins.audit_frame`, `wins.blame_pixel` (for the reported coordinates), and `wins.inspect_shader` on suspicious `prog_id`s. Formulate ranked hypotheses with explicit `falsification_condition`s. Distinguish `OBSERVED_WRITE`, `INFERRED_CANDIDATE`, and `INSUFFICIENT_EVIDENCE`.
4. **PATCH**: Propose the minimal fix (files, affected contract, causal hypothesis, risks, regressions, rollback plan). Do NOT apply code edits or install binaries without explicit user authorization.
5. **VERIFY**: Run `wins.verify` (read-only tests/gates/builds). Never claim PASS for skipped checks. Compare before/after under matching scene/conditions or declare differences.
6. **RECEIPT**: Call `wins.receipt` to emit an auditable receipt + SHA-256 `manifest.json` with final verdict (`DEMONSTRATED`, `INFERRED`, `NOT_DEMONSTRATED`, or `FALSIFIED`), preserving negative results and rollback instructions.
"""
