"""L0 deterministic invariant auditors for D3D11/OpenGL frames and Steam launchers.

Each rule returns a structured verdict:
  - PASS: invariant verified with sufficient data.
  - FAIL: contract violation observed or inferred with explicit evidence references.
  - UNKNOWN: insufficient instrumentation/artifacts to evaluate (never fakes PASS).

Ranking is strictly deterministic:
  1. FAIL before UNKNOWN before PASS
  2. Higher priority_score first (documented per rule)
  3. Earliest draw_id / line_no, then rule_id lexicographically
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .security import enforce_context_budget, repo_root, sanitize_text
from .snapshot import SnapshotData

# Deterministic priority weights by rule
RULE_PRIORITY: Dict[str, int] = {
    "D3D11_MRT_UNDECLARED_SV_TARGET": 100,
    "GL_RUNTIME_ERRORS": 95,
    "D3D11_NON_FINITE_PIXEL_VALUES": 90,
    "D3D11_CLEARED_UNWRITTEN_RT_SAMPLED": 85,
    "D3D11_ZERO_TEX_SRV_BOUND": 75,
    "SNAPSHOT_INTEGRITY": 70,
    "STEAM_INSTALL_HELPER_RELAUNCH": 65,
}


@dataclass
class AuditFinding:
    rule_id: str
    status: str  # "PASS" | "FAIL" | "UNKNOWN"
    subsystem: str
    scope: str
    certainty: str  # "OBSERVED_EVIDENCE" | "INFERRED_CANDIDATE" | "INSUFFICIENT_EVIDENCE"
    explanation: str
    evidence_refs: List[str] = field(default_factory=list)
    draws: List[int] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def sort_key(self) -> tuple:
        status_rank = {"FAIL": 0, "UNKNOWN": 1, "PASS": 2}.get(self.status, 3)
        prio = -RULE_PRIORITY.get(self.rule_id, 50)
        first_draw = self.draws[0] if self.draws else 10**9
        return (status_rank, prio, first_draw, self.rule_id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "status": self.status,
            "priority": RULE_PRIORITY.get(self.rule_id, 50),
            "subsystem": self.subsystem,
            "scope": self.scope,
            "certainty": self.certainty,
            "explanation": self.explanation,
            "draws": self.draws[:12],
            "draws_truncated": len(self.draws) > 12,
            "evidence_refs": self.evidence_refs[:12],
            "details": self.details,
        }


def _audit_snapshot_integrity(snap: SnapshotData) -> AuditFinding:
    if snap.draws_log_sha256 is None:
        return AuditFinding(
            rule_id="SNAPSHOT_INTEGRITY",
            status="FAIL",
            subsystem="snapshot",
            scope="frame",
            certainty="OBSERVED_EVIDENCE",
            explanation="Snapshot is missing draws.log; draw-level analysis cannot run.",
            evidence_refs=[str(snap.snap_dir.name)],
            details={"warnings": snap.log_warnings},
        )
    if snap.log_warnings:
        return AuditFinding(
            rule_id="SNAPSHOT_INTEGRITY",
            status="FAIL",
            subsystem="snapshot",
            scope="frame",
            certainty="OBSERVED_EVIDENCE",
            explanation="; ".join(snap.log_warnings),
            evidence_refs=["draws.log"],
            details={
                "log_complete": snap.log_complete,
                "parsed_draws": len(snap.draws),
                "reported_total_draws": snap.reported_total_draws,
                "warnings": snap.log_warnings,
            },
        )
    return AuditFinding(
        rule_id="SNAPSHOT_INTEGRITY",
        status="PASS",
        subsystem="snapshot",
        scope="frame",
        certainty="OBSERVED_EVIDENCE",
        explanation=f"Complete snapshot parsed ({len(snap.draws)} draws, {len(snap.clears)} clears, {len(snap.dispatches)} dispatches).",
        evidence_refs=["draws.log"],
        details={
            "log_complete": True,
            "parsed_draws": len(snap.draws),
            "bb": [snap.bb_width, snap.bb_height],
        },
    )


def _audit_mrt_sv_targets(snap: SnapshotData) -> AuditFinding:
    """D3D11 vs OpenGL MRT contract: every bound RT slot 0..nrt-1 must either be
    declared in PS OSGN or have its GL color write mask zeroed."""
    mrt_draws = [d for d in snap.draws if d.nrt > 1]
    if not mrt_draws:
        return AuditFinding(
            rule_id="D3D11_MRT_UNDECLARED_SV_TARGET",
            status="UNKNOWN",
            subsystem="d3d11_mrt",
            scope="frame_mrt_draws",
            certainty="INSUFFICIENT_EVIDENCE",
            explanation="No multi-RT draws (nrt > 1) present in snapshot.",
        )

    evaluated = 0
    violations: List[Dict[str, Any]] = []
    evidence: List[str] = []
    bad_draws: List[int] = []

    for d in mrt_draws:
        if d.write_mask == 0:
            evaluated += 1
            continue
        if not d.has_ps():
            evaluated += 1
            # Depth-only draw with NULL PS but non-zero write_mask on MRT
            bad_draws.append(d.draw_id)
            ev = f"draws.log:L{d.line_no}"
            evidence.append(ev)
            violations.append(
                {
                    "draw_id": d.draw_id,
                    "prog_id": d.prog_id,
                    "nrt": d.nrt,
                    "rt0_gl": d.rt0_gl,
                    "declared_sv_targets": [],
                    "missing_rt_slots": list(range(d.nrt)),
                    "write_mask": f"0x{d.write_mask:x}",
                    "shader_source": "null_ps",
                    "evidence_id": ev,
                }
            )
            continue

        sh = snap.get_shader(d.prog_id, "ps")
        declared = sh.declared_rt_slots()
        if declared is None:
            continue
        evaluated += 1
        missing = [i for i in range(d.nrt) if i not in declared]
        if missing:
            bad_draws.append(d.draw_id)
            ev_draw = f"draws.log:L{d.line_no}"
            ev_sh = sh.dxbc_path.name if sh.dxbc_path else (sh.glsl_path.name if sh.glsl_path else f"p{d.prog_id:04d}_ps")
            evidence.append(ev_draw)
            if ev_sh not in evidence:
                evidence.append(ev_sh)
            violations.append(
                {
                    "draw_id": d.draw_id,
                    "prog_id": d.prog_id,
                    "nrt": d.nrt,
                    "rt0_gl": d.rt0_gl,
                    "declared_sv_targets": declared,
                    "missing_rt_slots": missing,
                    "write_mask": f"0x{d.write_mask:x}",
                    "blend_enable": d.blend_enable,
                    "shader_source": sh.source,
                    "evidence_id": ev_draw,
                }
            )

    if evaluated == 0:
        return AuditFinding(
            rule_id="D3D11_MRT_UNDECLARED_SV_TARGET",
            status="UNKNOWN",
            subsystem="d3d11_mrt",
            scope="frame_mrt_draws",
            certainty="INSUFFICIENT_EVIDENCE",
            explanation=f"Found {len(mrt_draws)} multi-RT draws, but none had dumped PS artifacts to verify OSGN outputs.",
            details={"mrt_draws": len(mrt_draws), "evaluated": 0},
        )

    if violations:
        sample = violations[:6]
        return AuditFinding(
            rule_id="D3D11_MRT_UNDECLARED_SV_TARGET",
            status="FAIL",
            subsystem="d3d11_mrt",
            scope="frame_mrt_draws",
            certainty="OBSERVED_EVIDENCE",
            explanation=(
                f"{len(violations)} of {evaluated} evaluated MRT draws bind nrt>1 with non-zero "
                "write_mask while the active PS omits SV_Target slots from OSGN. Under OpenGL, "
                "unwritten draw buffers receive undefined values (NVIDIA duplicates vo0) unless "
                "glColorMaski masks undeclared outputs to 0."
            ),
            evidence_refs=evidence,
            draws=bad_draws,
            details={
                "mrt_draws_total": len(mrt_draws),
                "evaluated": evaluated,
                "violation_count": len(violations),
                "violations": sample,
                "violations_truncated": len(violations) > len(sample),
            },
        )

    return AuditFinding(
        rule_id="D3D11_MRT_UNDECLARED_SV_TARGET",
        status="PASS",
        subsystem="d3d11_mrt",
        scope="frame_mrt_draws",
        certainty="OBSERVED_EVIDENCE",
        explanation=f"All {evaluated} evaluated MRT draws declare matching SV_Target outputs (or mask writes to 0).",
        details={"mrt_draws_total": len(mrt_draws), "evaluated": evaluated},
    )


def _audit_cleared_unwritten_rt_sampled(snap: SnapshotData) -> AuditFinding:
    """Detect textures cleared to zero via CLEAR_RTV, never bound as rt0 of any
    draw before sampling, yet producing non-zero output when sampled by a PS.

    Because current draws.log logs rt0 (not rt1..rt7), linking the sampled
    texture to an earlier MRT draw is explicitly reported as INFERRED_CANDIDATE
    with the L0 instrumentation gap documented.
    """
    if not snap.clears or not snap.draws:
        return AuditFinding(
            rule_id="D3D11_CLEARED_UNWRITTEN_RT_SAMPLED",
            status="UNKNOWN",
            subsystem="d3d11_mrt",
            scope="frame_rt_dataflow",
            certainty="INSUFFICIENT_EVIDENCE",
            explanation="No CLEAR_RTV or draw events available to trace cleared RT dataflow.",
        )

    zero_clears: Dict[int, Any] = {}
    for c in snap.clears:
        if all(abs(x) < 1e-6 for x in c.rgba):
            zero_clears[c.gl_id] = c

    if not zero_clears:
        return AuditFinding(
            rule_id="D3D11_CLEARED_UNWRITTEN_RT_SAMPLED",
            status="UNKNOWN",
            subsystem="d3d11_mrt",
            scope="frame_rt_dataflow",
            certainty="INSUFFICIENT_EVIDENCE",
            explanation="No zero-cleared RTVs found in snapshot.",
        )

    # Track textures observed as rt0 prior to each draw
    rt0_written_order: Dict[int, int] = {}
    mrt_missing_before: List[int] = []
    suspects: List[Dict[str, Any]] = []
    evidence: List[str] = []
    draw_ids: List[int] = []

    for d in snap.draws:
        # Check if this draw samples any zero-cleared texture never seen as rt0 since its clear
        for srv in d.ps_srvs:
            clr = zero_clears.get(srv.tex_gl)
            if clr is None or clr.order >= d.order:
                continue
            last_rt0 = rt0_written_order.get(srv.tex_gl, -1)
            if last_rt0 > clr.order:
                continue
            # Never appeared as rt0 since zero-clear. Did this draw output non-zero probed RGB?
            nonzero_probes = [
                p
                for p in d.probes
                if not p.has_non_finite() and any(abs(c) > 1e-3 for c in p.after[:3])
            ]
            if nonzero_probes and mrt_missing_before:
                draw_ids.append(d.draw_id)
                ev_clr = f"draws.log:L{clr.line_no}"
                ev_drw = f"draws.log:L{d.line_no}"
                ev_srv = f"draws.log:L{srv.line_no}"
                for ev in (ev_clr, ev_drw, ev_srv):
                    if ev not in evidence:
                        evidence.append(ev)
                suspects.append(
                    {
                        "consumer_draw_id": d.draw_id,
                        "consumer_prog_id": d.prog_id,
                        "sampled_tex_gl": srv.tex_gl,
                        "clear_evidence": ev_clr,
                        "sample_evidence": ev_srv,
                        "nonzero_probe_count": len(nonzero_probes),
                        "sample_probe_after": nonzero_probes[0].to_dict(),
                        "preceding_mrt_undeclared_draws": mrt_missing_before[:6],
                    }
                )

        if d.rt0_gl != 0:
            rt0_written_order[d.rt0_gl] = d.order
        if d.nrt > 1 and d.write_mask != 0 and d.has_ps():
            sh = snap.get_shader(d.prog_id, "ps")
            decl = sh.declared_rt_slots()
            if decl is not None and any(i not in decl for i in range(d.nrt)):
                mrt_missing_before.append(d.draw_id)

    if suspects:
        return AuditFinding(
            rule_id="D3D11_CLEARED_UNWRITTEN_RT_SAMPLED",
            status="FAIL",
            subsystem="d3d11_mrt",
            scope="frame_rt_dataflow",
            certainty="INFERRED_CANDIDATE",
            explanation=(
                "A draw samples a texture that was CLEAR_RTV'd to (0,0,0,0) and never bound as rt0, "
                "yet produces non-zero probed output after preceding MRT draws with undeclared SV_Target "
                "outputs. Causal RT1 identity is INFERRED_CANDIDATE because draws.log records rt0 only "
                "(not rt1..rt7)."
            ),
            evidence_refs=evidence,
            draws=draw_ids,
            details={
                "suspect_count": len(suspects),
                "suspects": suspects[:5],
                "l0_instrumentation_gap": "draws.log logs rt0 only; logging rt1..rt7 would promote RT1 identity to OBSERVED_WRITE.",
            },
        )

    return AuditFinding(
        rule_id="D3D11_CLEARED_UNWRITTEN_RT_SAMPLED",
        status="PASS",
        subsystem="d3d11_mrt",
        scope="frame_rt_dataflow",
        certainty="OBSERVED_EVIDENCE",
        explanation="No zero-cleared non-rt0 texture produced unexpected non-zero output after undeclared-SV_Target MRT draws.",
    )


def _audit_non_finite_pixels(snap: SnapshotData) -> AuditFinding:
    total_probes = 0
    bad_draws: List[int] = []
    evidence: List[str] = []
    samples: List[Dict[str, Any]] = []
    for d in snap.draws:
        for p in d.probes:
            total_probes += 1
            if p.has_non_finite():
                if d.draw_id not in bad_draws:
                    bad_draws.append(d.draw_id)
                evidence.append(f"draws.log:L{p.line_no}")
                if len(samples) < 6:
                    samples.append({"draw_id": d.draw_id, "prog_id": d.prog_id, **p.to_dict()})

    if total_probes == 0:
        return AuditFinding(
            rule_id="D3D11_NON_FINITE_PIXEL_VALUES",
            status="UNKNOWN",
            subsystem="d3d11_shader",
            scope="probed_pixels",
            certainty="INSUFFICIENT_EVIDENCE",
            explanation="No CHG pixel probes recorded in draws.log.",
        )

    if samples:
        return AuditFinding(
            rule_id="D3D11_NON_FINITE_PIXEL_VALUES",
            status="FAIL",
            subsystem="d3d11_shader",
            scope="probed_pixels",
            certainty="OBSERVED_EVIDENCE",
            explanation=f"Non-finite (NaN/Inf) values observed in {len(bad_draws)} draw(s).",
            evidence_refs=evidence,
            draws=bad_draws,
            details={"total_probes": total_probes, "non_finite_samples": samples},
        )

    return AuditFinding(
        rule_id="D3D11_NON_FINITE_PIXEL_VALUES",
        status="PASS",
        subsystem="d3d11_shader",
        scope="probed_pixels",
        certainty="OBSERVED_EVIDENCE",
        explanation=f"All {total_probes} probed pixel transitions are finite.",
        details={"total_probes": total_probes},
    )


def _audit_zero_tex_srv(snap: SnapshotData) -> AuditFinding:
    total_srvs = 0
    bad_draws: List[int] = []
    evidence: List[str] = []
    samples: List[Dict[str, Any]] = []
    for d in snap.draws:
        for srv in d.ps_srvs:
            total_srvs += 1
            if srv.tex_gl == 0:
                if d.draw_id not in bad_draws:
                    bad_draws.append(d.draw_id)
                evidence.append(f"draws.log:L{srv.line_no}")
                if len(samples) < 6:
                    samples.append({"draw_id": d.draw_id, "prog_id": d.prog_id, **srv.to_dict()})

    if total_srvs == 0:
        return AuditFinding(
            rule_id="D3D11_ZERO_TEX_SRV_BOUND",
            status="UNKNOWN",
            subsystem="d3d11_srv",
            scope="ps_srv_bindings",
            certainty="INSUFFICIENT_EVIDENCE",
            explanation="No PS SRV bindings logged in draws.log.",
        )

    if samples:
        return AuditFinding(
            rule_id="D3D11_ZERO_TEX_SRV_BOUND",
            status="FAIL",
            subsystem="d3d11_srv",
            scope="ps_srv_bindings",
            certainty="OBSERVED_EVIDENCE",
            explanation=f"{len(bad_draws)} draw(s) bind tex=0 on a sampled PS SRV slot.",
            evidence_refs=evidence,
            draws=bad_draws,
            details={"total_srvs": total_srvs, "zero_tex_samples": samples},
        )

    return AuditFinding(
        rule_id="D3D11_ZERO_TEX_SRV_BOUND",
        status="PASS",
        subsystem="d3d11_srv",
        scope="ps_srv_bindings",
        certainty="OBSERVED_EVIDENCE",
        explanation=f"All {total_srvs} logged PS SRV bindings reference non-zero GL texture IDs.",
        details={"total_srvs": total_srvs},
    )


RE_RUNTIME_ERR = re.compile(
    r"(glError\s*=\s*0x[0-9a-fA-F]+|FBO incomplete|compile FAIL|link FAIL|unhandled opcode|CRASH|translate err=)",
    re.IGNORECASE,
)


def audit_runtime_log(log_path: Optional[Path]) -> AuditFinding:
    if log_path is None or not log_path.is_file():
        return AuditFinding(
            rule_id="GL_RUNTIME_ERRORS",
            status="UNKNOWN",
            subsystem="d3d11_gl_runtime",
            scope="runtime_log",
            certainty="INSUFFICIENT_EVIDENCE",
            explanation="No runtime log file provided or found for GL/shader error audit.",
        )

    matches: List[Dict[str, Any]] = []
    evidence: List[str] = []
    total_hits = 0
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line_no, raw in enumerate(f, start=1):
            if RE_RUNTIME_ERR.search(raw):
                total_hits += 1
                if len(matches) < 6:
                    ev = f"{log_path.name}:L{line_no}"
                    evidence.append(ev)
                    matches.append({"line": line_no, "text": sanitize_text(raw.strip(), 220), "evidence_id": ev})

    if total_hits > 0:
        return AuditFinding(
            rule_id="GL_RUNTIME_ERRORS",
            status="FAIL",
            subsystem="d3d11_gl_runtime",
            scope="runtime_log",
            certainty="OBSERVED_EVIDENCE",
            explanation=f"Detected {total_hits} GL/shader/runtime error line(s) in {log_path.name}.",
            evidence_refs=evidence,
            details={"total_hits": total_hits, "samples": matches, "truncated": total_hits > len(matches)},
        )

    return AuditFinding(
        rule_id="GL_RUNTIME_ERRORS",
        status="PASS",
        subsystem="d3d11_gl_runtime",
        scope="runtime_log",
        certainty="OBSERVED_EVIDENCE",
        explanation=f"0 GL/shader/crash errors detected in {log_path.name}.",
        evidence_refs=[log_path.name],
    )


def audit_steam_launchers(
    launch_dir: Optional[Path] = None,
    steam_log_path: Optional[Path] = None,
) -> AuditFinding:
    """Audit Steam wrapper scripts and optional Steam console logs for Install=1
    double-launch defects."""
    base = launch_dir if launch_dir is not None else (repo_root() / "launch")
    wrappers = sorted(base.glob("*/wins")) if base.is_dir() else []
    issues: List[Dict[str, Any]] = []
    evidence: List[str] = []

    for w in wrappers:
        txt = w.read_text(encoding="utf-8", errors="replace")
        accepts_run = ("waitforexitandrun|run" in txt) or ("run|waitforexitandrun" in txt)
        filters_helper = "iscriptevaluator.exe" in txt.lower()
        if accepts_run and not filters_helper:
            rel = str(w.relative_to(base.parent)) if base.parent in w.parents else str(w.name)
            evidence.append(rel)
            issues.append(
                {
                    "wrapper": rel,
                    "issue": "Accepts Steam verb `run` without filtering install-script helpers (e.g. iscriptevaluator.exe); causes game relaunch on exit.",
                }
            )

    steam_relaunch_hits = 0
    if steam_log_path is not None and steam_log_path.is_file():
        data = steam_log_path.read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="replace")
        for idx, line in enumerate(data.splitlines(), start=1):
            if "Install=1" in line and "iscriptevaluator.exe" in line.lower() and "/wins run" in line:
                steam_relaunch_hits += 1
                if len(evidence) < 8:
                    evidence.append(f"{steam_log_path.name}:L{idx}")

    if not wrappers and (steam_log_path is None or not steam_log_path.is_file()):
        return AuditFinding(
            rule_id="STEAM_INSTALL_HELPER_RELAUNCH",
            status="UNKNOWN",
            subsystem="steam_launcher",
            scope="launch_wrappers",
            certainty="INSUFFICIENT_EVIDENCE",
            explanation="No launch/*/wins wrappers or Steam logs available to audit.",
        )

    if issues:
        return AuditFinding(
            rule_id="STEAM_INSTALL_HELPER_RELAUNCH",
            status="FAIL",
            subsystem="steam_launcher",
            scope="launch_wrappers",
            certainty="OBSERVED_EVIDENCE",
            explanation=f"{len(issues)} Steam wrapper(s) accept `run` without skipping install-script helpers.",
            evidence_refs=evidence,
            details={"wrapper_issues": issues, "steam_install_eval_hits": steam_relaunch_hits},
        )

    return AuditFinding(
        rule_id="STEAM_INSTALL_HELPER_RELAUNCH",
        status="PASS",
        subsystem="steam_launcher",
        scope="launch_wrappers",
        certainty="OBSERVED_EVIDENCE",
        explanation=f"All {len(wrappers)} Steam wrapper(s) filter install-script helpers before launching the game.",
        evidence_refs=[str(w.parent.name + "/wins") for w in wrappers],
        details={"wrappers_checked": len(wrappers), "steam_install_eval_hits": steam_relaunch_hits},
    )


def run_frame_audit(
    snap: SnapshotData,
    *,
    runtime_log: Optional[Path] = None,
    steam_log: Optional[Path] = None,
    launch_dir: Optional[Path] = None,
    max_findings: int = 5,
) -> Dict[str, Any]:
    """Run all deterministic invariant checks and return a context-bounded report."""
    all_findings: List[AuditFinding] = [
        _audit_snapshot_integrity(snap),
        _audit_mrt_sv_targets(snap),
        _audit_cleared_unwritten_rt_sampled(snap),
        _audit_non_finite_pixels(snap),
        _audit_zero_tex_srv(snap),
        audit_runtime_log(runtime_log),
        audit_steam_launchers(launch_dir=launch_dir, steam_log_path=steam_log),
    ]
    all_findings.sort(key=lambda f: f.sort_key())

    counts = {
        "FAIL": sum(1 for f in all_findings if f.status == "FAIL"),
        "UNKNOWN": sum(1 for f in all_findings if f.status == "UNKNOWN"),
        "PASS": sum(1 for f in all_findings if f.status == "PASS"),
    }

    bounded, truncated, total = enforce_context_budget(
        [f.to_dict() for f in all_findings], max_findings, hard_cap=20
    )

    return {
        "data_trust": "UNTRUSTED_TELEMETRY",
        "ranking_policy": "status(FAIL<UNKNOWN<PASS), rule_priority_desc, first_draw_asc, rule_id_asc",
        "summary": counts,
        "findings": bounded,
        "total_findings": total,
        "truncated": truncated,
    }
