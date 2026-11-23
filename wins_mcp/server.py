"""L1 MCP JSON-RPC 2.0 stdio server for WINS-MCP v0.1.

Zero heavy external dependencies (Python stdlib only). Speaks MCP protocol
version 2024-11-05 over newline-delimited JSON-RPC 2.0 on stdin/stdout;
diagnostics go strictly to stderr.

Exposed tools:
  1. wins.triage          (read-only)
  2. wins.capture_frame   (read-only by default; trigger requires live profile)
  3. wins.blame_pixel     (read-only)
  4. wins.audit_frame     (read-only)
  5. wins.inspect_shader  (read-only)
  6. wins.verify          (read-only checks; install gated by explicit auth)
  7. wins.receipt         (writes only to authorized receipt output dir)
  8. wins.workflow        (L2 persistent state machine: start/get/advance)

Exposed prompts:
  - wins-debug-workflow
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .auditors import run_frame_audit
from .blame import blame_pixels
from .receipt import generate_receipt
from .security import SecurityError, default_allowed_roots, repo_root, sanitize_text, sha256_bytes, validate_path
from .snapshot import SnapshotData, load_snapshot, read_glsl_slice
from .triage import run_triage
from .verify import READONLY_CHECKS, run_verify
from .workflow import STATES, WORKFLOW_PROMPT_TEXT, advance_phase, load_investigation, start_investigation

PROTOCOL_VERSION = "2024-11-05"


TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "name": "wins.triage",
        "description": "Read-only initial classification of a target binary and/or WINS app profile (reuses core/triage and wins-native imports --json). Never executes unknown binaries.",
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {"type": "string", "description": "Authorized path to binary/installer to inspect."},
                "profile": {"type": "string", "description": "Optional WINS profile name (e.g. 'ds3', 'cuphead', 'falloutnv')."},
                "investigation_type": {"type": "string", "default": "general"},
                "max_imports": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "wins.capture_frame",
        "description": "Load an existing WINS D3D11 snapshot directory (default) or trigger a new 1-frame capture via snap_req on a running WINS_D3D11_SNAP_TRIG=1 profile. Returns compact metadata, dimensions, hashes, and capture_id (never embeds large base64 images).",
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "snapshot_dir": {"type": "string", "description": "Authorized path to existing snap_out directory."},
                "profile": {"type": "string", "description": "WINS profile name (e.g. 'ds3') used to resolve ~/.local/share/wins/<profile>/profile/snap_out."},
                "mode": {"type": "string", "enum": ["read_existing", "trigger_new"], "default": "read_existing"},
                "trigger_timeout_s": {"type": "number", "minimum": 0.5, "maximum": 30.0, "default": 5.0},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "wins.blame_pixel",
        "description": "Identify draws modifying specified (x, y) coordinates. Strictly distinguishes OBSERVED_WRITE (glReadPixels CHG probes), INFERRED_CANDIDATE (no before/after fabricated), and INSUFFICIENT_EVIDENCE.",
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
        "inputSchema": {
            "type": "object",
            "required": ["capture_id", "coords"],
            "properties": {
                "capture_id": {"type": "string", "description": "Capture ID from wins.capture_frame or authorized snapshot directory path."},
                "coords": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 16,
                    "items": {
                        "type": "array",
                        "minItems": 2,
                        "maxItems": 2,
                        "items": {"type": "integer"},
                    },
                },
                "max_candidates": {"type": "integer", "minimum": 1, "maximum": 32, "default": 6},
                "rt_filter": {"type": "integer", "description": "Optional GL texture ID to filter rt0."},
                "allow_inferred": {"type": "boolean", "default": False},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "wins.audit_frame",
        "description": "Run deterministic D3D11/OpenGL & Steam launcher invariant checks on a snapshot and optional runtime/Steam logs. Returns PASS/FAIL/UNKNOWN findings ranked deterministically within context budget.",
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
        "inputSchema": {
            "type": "object",
            "required": ["capture_id"],
            "properties": {
                "capture_id": {"type": "string"},
                "runtime_log_path": {"type": "string", "description": "Optional authorized path to WINS runtime log."},
                "steam_log_path": {"type": "string", "description": "Optional authorized path to Steam console_log.txt."},
                "launch_dir": {"type": "string", "description": "Optional authorized directory containing launch/*/wins wrappers."},
                "max_findings": {"type": "integer", "minimum": 1, "maximum": 20, "default": 5},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "wins.inspect_shader",
        "description": "Retrieve bounded shader metadata (ISGN, OSGN, declared SV_Target outputs, bindings, related draws, and an explicitly line-bounded GLSL snippet) for one program ID.",
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
        "inputSchema": {
            "type": "object",
            "required": ["capture_id", "prog_id"],
            "properties": {
                "capture_id": {"type": "string"},
                "prog_id": {"type": "integer", "minimum": 0},
                "stage": {"type": "string", "enum": ["vs", "hs", "ds", "gs", "ps", "cs"], "default": "ps"},
                "fields": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["isgn", "osgn", "outputs", "bindings", "related_draws", "glsl", "diagnostics"],
                    },
                },
                "glsl_start_line": {"type": "integer", "minimum": 1, "default": 1},
                "glsl_max_lines": {"type": "integer", "minimum": 1, "maximum": 200, "default": 60},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "wins.verify",
        "description": "Execute allowlisted read-only verification checks (Zig unit tests, separation_gate, isolated winrun64 build) with bounded logs and artifact SHA-256 hashes. Binary install requires explicit allow_install=true + authorization_reason.",
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
        "inputSchema": {
            "type": "object",
            "required": ["checks"],
            "properties": {
                "checks": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string", "enum": sorted(READONLY_CHECKS.keys())},
                },
                "timeout_s": {"type": "number", "minimum": 1.0, "maximum": 600.0, "default": 120.0},
                "allow_install": {"type": "boolean", "default": False},
                "install_target": {"type": "string", "enum": ["ds3", "cuphead", "falloutnv"]},
                "authorization_reason": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "wins.receipt",
        "description": "Emit an auditable investigation receipt JSON + SHA-256 manifest.json and an ISyMem-compatible summary. Refuses DEMONSTRATED without passing executed tests.",
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
        "inputSchema": {
            "type": "object",
            "required": ["investigation_id", "verdict", "hypothesis", "out_dir"],
            "properties": {
                "investigation_id": {"type": "string"},
                "verdict": {"type": "string", "enum": ["DEMONSTRATED", "INFERRED", "NOT_DEMONSTRATED", "FALSIFIED"]},
                "hypothesis": {"type": "string"},
                "out_dir": {"type": "string"},
                "initial_evidence": {"type": "object"},
                "captures": {"type": "array", "items": {"type": "string"}},
                "relevant_draws": {"type": "array", "items": {"type": "object"}},
                "audited_invariants": {"type": "array", "items": {"type": "object"}},
                "patch_diff_summary": {"type": "string"},
                "tests_executed": {"type": "array", "items": {"type": "object"}},
                "counterexamples": {"type": "array", "items": {"type": "string"}},
                "limitations": {"type": "array", "items": {"type": "string"}},
                "rollback_procedure": {"type": "string"},
                "artifact_paths": {"type": "array", "items": {"type": "string"}},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "wins.workflow",
        "description": "Manage persistent L2 wins-debug-workflow investigations (start, get/resume, advance across REPRODUCE->CAPTURE->LOCALIZE->PATCH->VERIFY->RECEIPT with evidence guards).",
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
        "inputSchema": {
            "type": "object",
            "required": ["action", "investigation_id"],
            "properties": {
                "action": {"type": "string", "enum": ["start", "get", "advance"]},
                "investigation_id": {"type": "string"},
                "symptom": {"type": "string"},
                "profile": {"type": "string"},
                "coords": {
                    "type": "array",
                    "items": {"type": "array", "minItems": 2, "maxItems": 2, "items": {"type": "integer"}},
                },
                "vision_required": {"type": "boolean", "default": False},
                "target_phase": {"type": "string", "enum": STATES},
                "payload": {"type": "object"},
            },
            "additionalProperties": False,
        },
    },
]

TOOL_SCHEMA_MAP: Dict[str, Dict[str, Any]] = {t["name"]: t["inputSchema"] for t in TOOL_DEFINITIONS}


def _validate_args(tool_name: str, args: Any) -> Dict[str, Any]:
    """Strict runtime argument validation against tool JSON Schema (stdlib only)."""
    schema = TOOL_SCHEMA_MAP.get(tool_name)
    if schema is None:
        raise KeyError(f"Unknown tool: {tool_name}")
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise ValueError("Tool arguments must be a JSON object.")

    props = schema.get("properties", {})
    required = schema.get("required", [])
    if schema.get("additionalProperties") is False:
        extra = [k for k in args.keys() if k not in props]
        if extra:
            raise ValueError(f"Unexpected argument(s) for {tool_name}: {extra}")
    for req in required:
        if req not in args or args[req] is None:
            raise ValueError(f"Missing required argument '{req}' for {tool_name}.")

    for key, val in args.items():
        if val is None:
            continue
        ps = props[key]
        t = ps.get("type")
        if t == "string":
            if not isinstance(val, str):
                raise ValueError(f"Argument '{key}' must be a string.")
            if "enum" in ps and val not in ps["enum"]:
                raise ValueError(f"Argument '{key}' must be one of {ps['enum']}.")
        elif t == "integer":
            if not isinstance(val, int) or isinstance(val, bool):
                raise ValueError(f"Argument '{key}' must be an integer.")
            if "minimum" in ps and val < ps["minimum"]:
                raise ValueError(f"Argument '{key}' must be >= {ps['minimum']}.")
            if "maximum" in ps and val > ps["maximum"]:
                raise ValueError(f"Argument '{key}' must be <= {ps['maximum']}.")
        elif t == "number":
            if not isinstance(val, (int, float)) or isinstance(val, bool):
                raise ValueError(f"Argument '{key}' must be a number.")
            if "minimum" in ps and val < ps["minimum"]:
                raise ValueError(f"Argument '{key}' must be >= {ps['minimum']}.")
            if "maximum" in ps and val > ps["maximum"]:
                raise ValueError(f"Argument '{key}' must be <= {ps['maximum']}.")
        elif t == "boolean":
            if not isinstance(val, bool):
                raise ValueError(f"Argument '{key}' must be a boolean.")
        elif t == "object":
            if not isinstance(val, dict):
                raise ValueError(f"Argument '{key}' must be an object.")
        elif t == "array":
            if not isinstance(val, list):
                raise ValueError(f"Argument '{key}' must be an array.")
            if "minItems" in ps and len(val) < ps["minItems"]:
                raise ValueError(f"Argument '{key}' requires at least {ps['minItems']} item(s).")
            if "maxItems" in ps and len(val) > ps["maxItems"]:
                raise ValueError(f"Argument '{key}' allows at most {ps['maxItems']} item(s).")
            item_schema = ps.get("items", {})
            it = item_schema.get("type")
            for elem in val:
                if it == "string":
                    if not isinstance(elem, str):
                        raise ValueError(f"Elements of '{key}' must be strings.")
                    if "enum" in item_schema and elem not in item_schema["enum"]:
                        raise ValueError(f"Element '{elem}' of '{key}' must be in {item_schema['enum']}.")
                elif it == "array":
                    if not isinstance(elem, list) or len(elem) != 2 or not all(
                        isinstance(c, int) and not isinstance(c, bool) for c in elem
                    ):
                        raise ValueError(f"Elements of '{key}' must be [x, y] integer pairs.")
                elif it == "object":
                    if not isinstance(elem, dict):
                        raise ValueError(f"Elements of '{key}' must be objects.")
    return args


class WinsMcpEngine:
    """Stateful session registry + tool dispatcher (also directly testable in-process)."""

    def __init__(
        self,
        *,
        allowed_roots: Optional[List[Path]] = None,
        workflow_dir: Optional[Path] = None,
    ):
        self.allowed_roots = allowed_roots if allowed_roots is not None else default_allowed_roots()
        self.workflow_dir = workflow_dir
        self._captures: Dict[str, Path] = {}
        self._cancel_events: Dict[Any, threading.Event] = {}

    def register_cancel(self, req_id: Any) -> threading.Event:
        ev = threading.Event()
        self._cancel_events[req_id] = ev
        return ev

    def cancel_request(self, req_id: Any) -> bool:
        ev = self._cancel_events.get(req_id)
        if ev is not None:
            ev.set()
            return True
        return False

    def clear_cancel(self, req_id: Any) -> None:
        self._cancel_events.pop(req_id, None)

    def _resolve_snap_dir(self, capture_id: str) -> Path:
        if capture_id in self._captures:
            return self._captures[capture_id]
        # Allow passing an authorized snapshot directory directly (useful after resume)
        return validate_path(capture_id, self.allowed_roots, must_exist=True)

    def _load_capture(self, capture_id: str) -> Tuple[Path, SnapshotData]:
        snap_dir = self._resolve_snap_dir(capture_id)
        snap = load_snapshot(snap_dir)
        return snap_dir, snap

    def _make_capture_id(self, snap_dir: Path, snap: SnapshotData) -> str:
        seed = f"{snap_dir.resolve()}|{snap.draws_log_sha256 or 'nolog'}".encode("utf-8")
        cid = f"cap_{sha256_bytes(seed)[:12]}"
        self._captures[cid] = snap_dir.resolve()
        return cid

    def call_tool(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]],
        *,
        cancel_event: Optional[threading.Event] = None,
    ) -> Dict[str, Any]:
        args = _validate_args(name, arguments)

        if name == "wins.triage":
            return run_triage(
                args.get("target_path"),
                profile=args.get("profile"),
                investigation_type=args.get("investigation_type", "general"),
                allowed_roots=self.allowed_roots,
                max_imports=args.get("max_imports", 20),
            )

        if name == "wins.capture_frame":
            return self._tool_capture_frame(args)

        if name == "wins.blame_pixel":
            _, snap = self._load_capture(args["capture_id"])
            coords = [(int(c[0]), int(c[1])) for c in args["coords"]]
            out = blame_pixels(
                snap,
                coords,
                max_candidates=args.get("max_candidates", 6),
                rt_filter=args.get("rt_filter"),
                allow_inferred=args.get("allow_inferred", False),
            )
            out["capture_id"] = args["capture_id"]
            return out

        if name == "wins.audit_frame":
            _, snap = self._load_capture(args["capture_id"])
            rt_log = (
                validate_path(args["runtime_log_path"], self.allowed_roots, must_exist=True)
                if args.get("runtime_log_path")
                else None
            )
            st_log = (
                validate_path(args["steam_log_path"], self.allowed_roots, must_exist=True)
                if args.get("steam_log_path")
                else None
            )
            ldir = (
                validate_path(args["launch_dir"], self.allowed_roots, must_exist=True)
                if args.get("launch_dir")
                else None
            )
            out = run_frame_audit(
                snap,
                runtime_log=rt_log,
                steam_log=st_log,
                launch_dir=ldir,
                max_findings=args.get("max_findings", 5),
            )
            out["capture_id"] = args["capture_id"]
            return out

        if name == "wins.inspect_shader":
            return self._tool_inspect_shader(args)

        if name == "wins.verify":
            return run_verify(
                args["checks"],
                timeout_s=float(args.get("timeout_s", 120.0)),
                cancel_event=cancel_event,
                allow_install=bool(args.get("allow_install", False)),
                install_target=args.get("install_target"),
                authorization_reason=args.get("authorization_reason"),
                cwd=repo_root(),
            )

        if name == "wins.receipt":
            return generate_receipt(
                args["investigation_id"],
                verdict=args["verdict"],
                hypothesis=args["hypothesis"],
                out_dir=Path(args["out_dir"]),
                allowed_roots=self.allowed_roots,
                initial_evidence=args.get("initial_evidence"),
                captures=args.get("captures"),
                relevant_draws=args.get("relevant_draws"),
                audited_invariants=args.get("audited_invariants"),
                patch_diff_summary=args.get("patch_diff_summary"),
                tests_executed=args.get("tests_executed"),
                counterexamples=args.get("counterexamples"),
                limitations=args.get("limitations"),
                rollback_procedure=args.get("rollback_procedure"),
                artifact_paths=args.get("artifact_paths"),
            )

        if name == "wins.workflow":
            act = args["action"]
            inv_id = args["investigation_id"]
            if act == "start":
                return start_investigation(
                    inv_id,
                    args.get("symptom") or "",
                    profile=args.get("profile"),
                    coords=args.get("coords"),
                    vision_required=bool(args.get("vision_required", False)),
                    state_dir=self.workflow_dir,
                )
            if act == "get":
                return load_investigation(inv_id, state_dir=self.workflow_dir)
            if act == "advance":
                return advance_phase(
                    inv_id,
                    args.get("target_phase") or "",
                    args.get("payload"),
                    state_dir=self.workflow_dir,
                )

        raise KeyError(f"Unhandled tool: {name}")

    def _tool_capture_frame(self, args: Dict[str, Any]) -> Dict[str, Any]:
        mode = args.get("mode", "read_existing")
        profile = args.get("profile")
        raw_dir = args.get("snapshot_dir")

        if raw_dir:
            snap_dir = validate_path(raw_dir, self.allowed_roots, must_exist=(mode == "read_existing"))
            profile_dir = snap_dir.parent
        elif profile:
            if "/" in profile or "\\" in profile or ".." in profile:
                raise ValueError("profile must be a simple identifier (no path separators).")
            home = Path(os.environ.get("WINS_MCP_HOME") or os.path.expanduser("~")).resolve()
            profile_dir = validate_path(
                home / ".local" / "share" / "wins" / profile / "profile",
                self.allowed_roots,
                must_exist=True,
            )
            snap_dir = profile_dir / "snap_out"
        else:
            raise ValueError("Provide either snapshot_dir or profile.")

        capture_errors: List[str] = []
        if mode == "trigger_new":
            req_path = validate_path(profile_dir / "snap_req", self.allowed_roots, must_exist=False)
            draws_log = snap_dir / "draws.log"
            prev_mtime = draws_log.stat().st_mtime if draws_log.is_file() else 0.0
            req_path.touch()
            deadline = time.monotonic() + float(args.get("trigger_timeout_s", 5.0))
            updated = False
            while time.monotonic() < deadline:
                if not req_path.exists() and draws_log.is_file() and draws_log.stat().st_mtime > prev_mtime:
                    updated = True
                    break
                time.sleep(0.1)
            if not updated:
                if req_path.exists():
                    req_path.unlink(missing_ok=True)
                capture_errors.append(
                    "Timed out waiting for live WINS_D3D11_SNAP_TRIG=1 process to consume snap_req."
                )

        if not snap_dir.is_dir():
            raise FileNotFoundError(f"Snapshot directory does not exist: {snap_dir}")

        snap = load_snapshot(snap_dir)
        cid = self._make_capture_id(snap_dir, snap)
        dims = (
            [snap.bb_width, snap.bb_height]
            if snap.bb_width is not None and snap.bb_height is not None
            else (list(snap.final_image_dims) if snap.final_image_dims else None)
        )
        return {
            "data_trust": "UNTRUSTED_TELEMETRY",
            "capture_id": cid,
            "mode": mode,
            "snapshot_dir": str(snap_dir),
            "dimensions": dims,
            "backbuffer_fmt": snap.bb_fmt,
            "after_present": snap.after_present,
            "end_present": snap.end_present,
            "draws_count": len(snap.draws),
            "reported_total_draws": snap.reported_total_draws,
            "clears_count": len(snap.clears),
            "dispatches_count": len(snap.dispatches),
            "log_complete": snap.log_complete,
            "instrumented_probes": snap.instrumented_probes(),
            "final_image": {
                "resource_uri": f"wins://captures/{cid}/final_image" if snap.final_image_path else None,
                "path": str(snap.final_image_path) if snap.final_image_path else None,
                "dims": list(snap.final_image_dims) if snap.final_image_dims else None,
                "sha256": snap.final_image_sha256,
            },
            "artifacts": {
                "has_draws_log": snap.draws_log_sha256 is not None,
                "shader_stage_count": len(snap.shader_files),
            },
            "hashes": {
                "draws_log_sha256": snap.draws_log_sha256,
                "final_image_sha256": snap.final_image_sha256,
            },
            "warnings": snap.log_warnings,
            "capture_errors": capture_errors,
            "causal_attribution_note": (
                "A final image alone cannot prove which draw modified a pixel; causal attribution "
                "uses draws.log CHG glReadPixels probes and shader signatures."
            ),
        }

    def _tool_inspect_shader(self, args: Dict[str, Any]) -> Dict[str, Any]:
        _, snap = self._load_capture(args["capture_id"])
        prog_id = int(args["prog_id"])
        stage = args.get("stage", "ps")
        fields = set(
            args.get("fields")
            or ["isgn", "osgn", "outputs", "bindings", "related_draws", "glsl", "diagnostics"]
        )

        sh = snap.get_shader(prog_id, stage)
        if sh.source == "none":
            raise FileNotFoundError(
                f"Shader p{prog_id:04d}_{stage} (.dxbc/.glsl) not found in capture {args['capture_id']}."
            )

        out: Dict[str, Any] = {
            "data_trust": "UNTRUSTED_TELEMETRY",
            "capture_id": args["capture_id"],
            "prog_id": prog_id,
            "stage": stage,
            "source": sh.source,
            "artifacts": {
                "dxbc": sh.dxbc_path.name if sh.dxbc_path else None,
                "glsl": sh.glsl_path.name if sh.glsl_path else None,
            },
        }
        if "isgn" in fields:
            out["isgn"] = [e.to_dict() for e in sh.isgn] if sh.isgn else sh.glsl_inputs
        if "osgn" in fields:
            out["osgn"] = [e.to_dict() for e in sh.osgn] if sh.osgn else sh.glsl_outputs
        if "outputs" in fields:
            out["declared_rt_slots"] = sh.declared_rt_slots()
            mask = sh.ps_out_mask()
            out["ps_out_mask"] = f"0x{mask:02x}" if mask is not None else None
        if "bindings" in fields:
            out["bindings"] = {"samplers": sh.samplers, "ubos": sh.ubos}
        if "related_draws" in fields:
            rel = [
                {
                    "draw_id": d.draw_id,
                    "stages": d.stages,
                    "nrt": d.nrt,
                    "rt0_gl": d.rt0_gl,
                    "write_mask": f"0x{d.write_mask:x}",
                    "blend_enable": d.blend_enable,
                    "evidence_id": f"draws.log:L{d.line_no}",
                }
                for d in snap.draws
                if d.prog_id == prog_id
            ]
            out["related_draws"] = rel[:12]
            out["related_draws_total"] = len(rel)
            out["related_draws_truncated"] = len(rel) > 12
        if "glsl" in fields:
            if sh.glsl_path and sh.glsl_path.is_file():
                out["glsl"] = read_glsl_slice(
                    sh.glsl_path,
                    start_line=args.get("glsl_start_line", 1),
                    max_lines=args.get("glsl_max_lines", 60),
                    hard_cap=200,
                )
            else:
                out["glsl"] = None
        if "diagnostics" in fields:
            out["diagnostics"] = sh.parse_errors
        return out

    def handle_rpc(self, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle a single JSON-RPC 2.0 request or notification."""
        req_id = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params") or {}

        # Notifications (no id)
        if method == "notifications/initialized":
            return None
        if method in ("$/cancelRequest", "notifications/cancelled"):
            target_id = params.get("id") or params.get("requestId")
            self.cancel_request(target_id)
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "serverInfo": {"name": "wins-mcp", "version": __version__},
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "prompts": {"listChanged": False},
                        "resources": {"listChanged": False},
                    },
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOL_DEFINITIONS}}

        if method == "prompts/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "prompts": [
                        {
                            "name": "wins-debug-workflow",
                            "description": "Evidence-driven 6-phase WINS debugging workflow (REPRODUCE -> CAPTURE -> LOCALIZE -> PATCH -> VERIFY -> RECEIPT).",
                            "arguments": [
                                {"name": "symptom", "description": "Observed visual or runtime defect.", "required": False},
                                {"name": "profile", "description": "WINS profile (e.g. ds3, cuphead, falloutnv).", "required": False},
                            ],
                        }
                    ]
                },
            }

        if method == "prompts/get":
            pname = params.get("name")
            if pname != "wins-debug-workflow":
                return self._rpc_error(req_id, -32602, f"Unknown prompt: {pname}")
            pargs = params.get("arguments") or {}
            extra = ""
            if pargs.get("symptom") or pargs.get("profile"):
                extra = f"\n\nTarget context: profile={pargs.get('profile', 'unspecified')}, symptom={pargs.get('symptom', 'unspecified')}\n"
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "description": "WINS evidence-driven debugging workflow",
                    "messages": [
                        {
                            "role": "user",
                            "content": {"type": "text", "text": WORKFLOW_PROMPT_TEXT + extra},
                        }
                    ],
                },
            }

        if method == "resources/list":
            resources = [
                {
                    "uri": "wins://workflow/wins-debug-workflow",
                    "name": "wins-debug-workflow",
                    "mimeType": "text/markdown",
                    "description": "6-phase evidence-driven WINS debugging state machine specification.",
                }
            ]
            for cid, sdir in sorted(self._captures.items()):
                resources.append(
                    {
                        "uri": f"wins://captures/{cid}/metadata",
                        "name": f"capture:{cid}",
                        "mimeType": "application/json",
                        "description": f"Snapshot directory {sdir.name}",
                    }
                )
            return {"jsonrpc": "2.0", "id": req_id, "result": {"resources": resources}}

        if method == "resources/read":
            uri = params.get("uri", "")
            if uri == "wins://workflow/wins-debug-workflow":
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "contents": [
                            {"uri": uri, "mimeType": "text/markdown", "text": WORKFLOW_PROMPT_TEXT}
                        ]
                    },
                }
            return self._rpc_error(req_id, -32602, f"Unknown or unreadable resource URI: {uri}")

        if method == "tools/call":
            tname = params.get("name", "")
            targs = params.get("arguments") or {}
            cancel_ev = self.register_cancel(req_id)
            try:
                payload = self.call_tool(tname, targs, cancel_event=cancel_ev)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(payload, indent=2, sort_keys=True)}],
                        "structuredContent": payload,
                        "isError": False,
                    },
                }
            except SecurityError as exc:
                return self._tool_error(req_id, exc.code, exc.message)
            except FileNotFoundError as exc:
                return self._tool_error(req_id, "NOT_FOUND", str(exc))
            except ValueError as exc:
                return self._tool_error(req_id, "INVALID_ARGUMENT", str(exc))
            except KeyError as exc:
                return self._tool_error(req_id, "UNKNOWN_TOOL", str(exc))
            except Exception as exc:
                return self._tool_error(req_id, "INTERNAL_ERROR", sanitize_text(str(exc), 400))
            finally:
                self.clear_cancel(req_id)

        return self._rpc_error(req_id, -32601, f"Method not found: {method}")

    @staticmethod
    def _rpc_error(req_id: Any, code: int, message: str) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

    @staticmethod
    def _tool_error(req_id: Any, error_code: str, message: str) -> Dict[str, Any]:
        payload = {"error_code": error_code, "message": message}
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
                "structuredContent": payload,
                "isError": True,
            },
        }


def run_stdio_server(engine: Optional[WinsMcpEngine] = None) -> int:
    srv = engine or WinsMcpEngine()
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            resp = srv._rpc_error(None, -32700, f"Parse error: {exc}")
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
            continue

        resp = srv.handle_rpc(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0
