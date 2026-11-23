"""L1 wins.blame_pixel: causal pixel attribution over instrumented snapshots.

Strict honesty contract:
  - OBSERVED_WRITE: exact CHG probe recorded by glReadPixels for (x, y).
  - INFERRED_CANDIDATE: draw writes to a matching-size RT without a direct probe
    on (x, y) — ONLY returned when explicitly requested (`allow_inferred=True`),
    and NEVER with fabricated before/after values.
  - INSUFFICIENT_EVIDENCE: no direct probe covers (x, y).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from .security import enforce_context_budget
from .snapshot import DrawEvent, ProbeChange, SnapshotData


def _suspicion_reasons(draw: DrawEvent, probe: ProbeChange, snap: SnapshotData) -> List[str]:
    reasons: List[str] = []
    if probe.has_non_finite():
        reasons.append("non_finite_pixel_value")
    else:
        if (
            all(c >= 0.999 for c in probe.after[:3])
            and any(c < 0.98 for c in probe.before[:3])
        ):
            reasons.append("rgb_clipped_to_white_saturation")
        dl1 = probe.delta_l1()
        if dl1 is not None and dl1 >= 1.0:
            reasons.append(f"large_color_jump_l1={dl1:.3f}")
    if draw.nrt > 1 and draw.write_mask != 0 and draw.has_ps():
        sh = snap.get_shader(draw.prog_id, "ps")
        decl = sh.declared_rt_slots()
        if decl is not None:
            missing = [i for i in range(draw.nrt) if i not in decl]
            if missing:
                reasons.append(f"mrt_undeclared_sv_targets={missing}")
    if draw.blend_enable and draw.blend_dst_rgb in ("1", "01"):
        reasons.append("additive_blend_onto_rt")
    if not reasons:
        reasons.append("observed_pixel_write")
    return reasons


def blame_pixels(
    snap: SnapshotData,
    coords: Sequence[Tuple[int, int]],
    *,
    max_candidates: int = 6,
    rt_filter: Optional[int] = None,
    allow_inferred: bool = False,
) -> Dict[str, Any]:
    """Attribute pixel changes at one or more screen coordinates."""
    if not coords:
        raise ValueError("coords must be a non-empty list of [x, y] coordinates.")

    bb_w = snap.bb_width or (snap.final_image_dims[0] if snap.final_image_dims else None)
    bb_h = snap.bb_height or (snap.final_image_dims[1] if snap.final_image_dims else None)

    for x, y in coords:
        if x < 0 or y < 0:
            raise ValueError(f"Coordinate ({x}, {y}) cannot be negative.")
        if bb_w is not None and bb_h is not None and (x >= bb_w or y >= bb_h):
            raise ValueError(
                f"Coordinate ({x}, {y}) is outside frame bounds {bb_w}x{bb_h}."
            )

    instrumented = snap.instrumented_probes()
    per_coord: List[Dict[str, Any]] = []

    for x, y in coords:
        observed_hits: List[Dict[str, Any]] = []
        for d in snap.draws:
            if rt_filter is not None and d.rt0_gl != rt_filter:
                continue
            for p in d.probes:
                if p.x == x and p.y == y:
                    sh = snap.get_shader(d.prog_id, "ps") if d.has_ps() else None
                    decl_rts = sh.declared_rt_slots() if sh is not None else None
                    reasons = _suspicion_reasons(d, p, snap)
                    # Deterministic suspicion score so most anomalous writes surface first
                    # while keeping draw chronology clear.
                    score = 0
                    if "non_finite_pixel_value" in reasons:
                        score += 100
                    if any(r.startswith("mrt_undeclared_sv_targets=") for r in reasons):
                        score += 80
                    if "rgb_clipped_to_white_saturation" in reasons:
                        score += 70
                    if any(r.startswith("large_color_jump") for r in reasons):
                        score += 50
                    if "additive_blend_onto_rt" in reasons:
                        score += 20
                    observed_hits.append(
                        {
                            "_score": score,
                            "draw_id": d.draw_id,
                            "prog_id": d.prog_id,
                            "stages": d.stages,
                            "attribution_level": "OBSERVED_WRITE",
                            "fb_size": [d.fb_w, d.fb_h],
                            "nrt": d.nrt,
                            "rt0_gl": d.rt0_gl,
                            "rt0_fmt": d.rt0_fmt,
                            "ps_declared_sv_targets": decl_rts,
                            "blend": d.blend_summary(),
                            "color_write_mask": f"0x{d.write_mask:x}",
                            "before": p.to_dict()["before"],
                            "after": p.to_dict()["after"],
                            "delta_l1": p.to_dict()["delta_l1"],
                            "ps_srvs_gl": [s.tex_gl for s in d.ps_srvs[:8]],
                            "suspicion_reasons": reasons,
                            "evidence_ids": [f"draws.log:L{d.line_no}", f"draws.log:L{p.line_no}"],
                        }
                    )

        if observed_hits:
            # Rank by suspicion score desc, then draw_id asc; strip internal _score
            observed_hits.sort(key=lambda item: (-item["_score"], item["draw_id"]))
            for item in observed_hits:
                item.pop("_score", None)
            bounded, truncated, total = enforce_context_budget(
                observed_hits, max_candidates, hard_cap=32
            )
            per_coord.append(
                {
                    "coord": [x, y],
                    "attribution_level": "OBSERVED_WRITE",
                    "candidates": bounded,
                    "total_candidates": total,
                    "truncated": truncated,
                    "note": "Direct before/after pixel values observed via glReadPixels CHG probes.",
                }
            )
            continue

        # No direct probe at (x, y) — NEVER fabricate before/after!
        if allow_inferred:
            inferred: List[Dict[str, Any]] = []
            for d in snap.draws:
                if rt_filter is not None and d.rt0_gl != rt_filter:
                    continue
                if d.rt0_gl == 0 or d.write_mask == 0:
                    continue
                if bb_w is not None and bb_h is not None and (d.fb_w < 480 or d.fb_h < 270):
                    continue
                inferred.append(
                    {
                        "draw_id": d.draw_id,
                        "prog_id": d.prog_id,
                        "stages": d.stages,
                        "attribution_level": "INFERRED_CANDIDATE",
                        "fb_size": [d.fb_w, d.fb_h],
                        "nrt": d.nrt,
                        "rt0_gl": d.rt0_gl,
                        "blend": d.blend_summary(),
                        "color_write_mask": f"0x{d.write_mask:x}",
                        "before": None,
                        "after": None,
                        "suspicion_reasons": ["unprobed_coord_rt_extent_candidate"],
                        "evidence_ids": [f"draws.log:L{d.line_no}"],
                    }
                )
            bounded, truncated, total = enforce_context_budget(
                inferred, max_candidates, hard_cap=32
            )
            per_coord.append(
                {
                    "coord": [x, y],
                    "attribution_level": "INFERRED_CANDIDATE" if bounded else "INSUFFICIENT_EVIDENCE",
                    "candidates": bounded,
                    "total_candidates": total,
                    "truncated": truncated,
                    "note": (
                        f"Coordinate ({x},{y}) was not instrumented with a glReadPixels probe. "
                        "Before/after values are null (never fabricated). Re-capture with a probe at "
                        "this coordinate for OBSERVED_WRITE attribution."
                    ),
                }
            )
        else:
            per_coord.append(
                {
                    "coord": [x, y],
                    "attribution_level": "INSUFFICIENT_EVIDENCE",
                    "candidates": [],
                    "total_candidates": 0,
                    "truncated": False,
                    "note": (
                        f"No glReadPixels CHG probe exists at ({x},{y}) in draws.log. "
                        "Causal write attribution requires a probe at this coordinate (pass "
                        "allow_inferred=true only for coarse unprobed RT candidates)."
                    ),
                }
            )

    return {
        "data_trust": "UNTRUSTED_TELEMETRY",
        "frame_size": [bb_w, bb_h] if bb_w is not None and bb_h is not None else None,
        "instrumented_probes": instrumented,
        "results": per_coord,
    }
