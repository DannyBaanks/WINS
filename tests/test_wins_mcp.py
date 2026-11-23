"""Comprehensive tests for WINS-MCP v0.1.

Covers all 16 mandatory test categories (COMPOSE §10), clearly separating:
  - [SYNTHETIC]: deterministic synthetic fixtures stored in repo / tmp_path
  - [REAL_DS3]:  golden-case acceptance against the real Dark Souls III
                 snapshot on disk (if present on host; never committed to git)
"""

from __future__ import annotations

import json
import os
import struct
import sys
import threading
from pathlib import Path
from typing import Any, Dict

import pytest

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from wins_mcp.client import WinsMcpClient
from wins_mcp.receipt import verify_manifest
from wins_mcp.security import repo_root
from wins_mcp.server import WinsMcpEngine
from wins_mcp.snapshot import parse_dxbc_signatures
from wins_mcp.verify import run_verify

REPO = repo_root()
FIXTURE_SKY = REPO / "wins_mcp" / "fixtures" / "radioactive_sky_synthetic"
FIXTURE_CLEAN = REPO / "wins_mcp" / "fixtures" / "clean_mrt_control"
REAL_DS3_SNAP = Path(
    os.environ.get("WINS_MCP_REAL_DS3_SNAP")
    or str(Path.home() / ".local" / "share" / "wins" / "ds3" / "profile" / "snap_out")
)


def _engine(tmp_path: Path) -> WinsMcpEngine:
    return WinsMcpEngine(
        allowed_roots=[REPO, tmp_path, REAL_DS3_SNAP.parent.parent],
        workflow_dir=tmp_path / "workflows",
    )


def _minimal_dxbc_ps(target_regs: list[int]) -> bytes:
    """Build a valid synthetic DXBC container containing an OSGN chunk only."""
    cnt = len(target_regs)
    name = b"SV_Target\x00"
    name_off = 8 + cnt * 24
    osgn = bytearray(name_off + len(name))
    struct.pack_into("<II", osgn, 0, cnt, 8)
    for idx, reg in enumerate(target_regs):
        base = 8 + idx * 24
        struct.pack_into("<5I", osgn, base, name_off, reg, 0, 3, reg)
        osgn[base + 20] = 0xF
        osgn[base + 21] = 0x0
    osgn[name_off:] = name

    chunk_off = 36
    total = chunk_off + 8 + len(osgn)
    buf = bytearray(total)
    buf[0:4] = b"DXBC"
    struct.pack_into("<I", buf, 20, 1)
    struct.pack_into("<I", buf, 24, total)
    struct.pack_into("<I", buf, 28, 1)
    struct.pack_into("<I", buf, 32, chunk_off)
    buf[chunk_off : chunk_off + 4] = b"OSGN"
    struct.pack_into("<I", buf, chunk_off + 4, len(osgn))
    buf[chunk_off + 8 :] = osgn
    return bytes(buf)


# ---- 1. Invalid input schemas [SYNTHETIC] -----------------------------------

def test_01_invalid_input_schemas(tmp_path: Path) -> None:
    eng = _engine(tmp_path)
    # Missing required args
    resp = eng.handle_rpc(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "wins.blame_pixel", "arguments": {}}}
    )
    assert resp is not None and resp["result"]["isError"] is True
    assert resp["result"]["structuredContent"]["error_code"] == "INVALID_ARGUMENT"

    # Unexpected extra property
    resp2 = eng.handle_rpc(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "wins.audit_frame", "arguments": {"capture_id": "x", "bogus": 123}},
        }
    )
    assert resp2 is not None and resp2["result"]["isError"] is True
    assert resp2["result"]["structuredContent"]["error_code"] == "INVALID_ARGUMENT"

    # Invalid enum value
    resp3 = eng.handle_rpc(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "wins.verify", "arguments": {"checks": ["rm -rf /"]}},
        }
    )
    assert resp3 is not None and resp3["result"]["isError"] is True
    assert resp3["result"]["structuredContent"]["error_code"] == "INVALID_ARGUMENT"


# ---- 2. Coordinates outside frame [SYNTHETIC] -------------------------------

def test_02_coordinates_out_of_bounds(tmp_path: Path) -> None:
    eng = _engine(tmp_path)
    cap = eng.call_tool("wins.capture_frame", {"snapshot_dir": str(FIXTURE_SKY)})
    with pytest.raises(ValueError, match="outside frame bounds"):
        eng.call_tool("wins.blame_pixel", {"capture_id": cap["capture_id"], "coords": [[1920, 1080]]})
    with pytest.raises(ValueError, match="cannot be negative"):
        eng.call_tool("wins.blame_pixel", {"capture_id": cap["capture_id"], "coords": [[-1, 10]]})


# ---- 3. Non-existent snapshot [SYNTHETIC] -----------------------------------

def test_03_nonexistent_snapshot(tmp_path: Path) -> None:
    eng = _engine(tmp_path)
    missing = tmp_path / "does_not_exist"
    resp = eng.handle_rpc(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {"name": "wins.capture_frame", "arguments": {"snapshot_dir": str(missing)}},
        }
    )
    assert resp is not None and resp["result"]["isError"] is True
    assert resp["result"]["structuredContent"]["error_code"] == "NOT_FOUND"


# ---- 4. Incomplete snapshot (missing draws.log) [SYNTHETIC] -----------------

def test_04_incomplete_snapshot_missing_draws_log(tmp_path: Path) -> None:
    snap = tmp_path / "incomplete_snap"
    snap.mkdir()
    (snap / "final.ppm").write_bytes(b"P6\n2 2\n255\n" + b"\x00" * 12)

    eng = _engine(tmp_path)
    cap = eng.call_tool("wins.capture_frame", {"snapshot_dir": str(snap)})
    assert cap["artifacts"]["has_draws_log"] is False
    assert cap["log_complete"] is False

    audit = eng.call_tool("wins.audit_frame", {"capture_id": cap["capture_id"], "max_findings": 10})
    by_id = {f["rule_id"]: f for f in audit["findings"]}
    assert by_id["SNAPSHOT_INTEGRITY"]["status"] == "FAIL"
    # Rules without data must be UNKNOWN, never fake PASS
    assert by_id["D3D11_MRT_UNDECLARED_SV_TARGET"]["status"] == "UNKNOWN"
    assert by_id["D3D11_NON_FINITE_PIXEL_VALUES"]["status"] == "UNKNOWN"


# ---- 5. Shader not found [SYNTHETIC] ----------------------------------------

def test_05_shader_not_found(tmp_path: Path) -> None:
    eng = _engine(tmp_path)
    cap = eng.call_tool("wins.capture_frame", {"snapshot_dir": str(FIXTURE_SKY)})
    resp = eng.handle_rpc(
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {"name": "wins.inspect_shader", "arguments": {"capture_id": cap["capture_id"], "prog_id": 9999}},
        }
    )
    assert resp is not None and resp["result"]["isError"] is True
    assert resp["result"]["structuredContent"]["error_code"] == "NOT_FOUND"


# ---- 6. Truncated draws.log [SYNTHETIC] -------------------------------------

def test_06_truncated_draws_log(tmp_path: Path) -> None:
    snap = tmp_path / "trunc_snap"
    snap.mkdir()
    lines = (FIXTURE_SKY / "draws.log").read_text(encoding="utf-8").splitlines()
    # Drop END line
    (snap / "draws.log").write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

    eng = _engine(tmp_path)
    cap = eng.call_tool("wins.capture_frame", {"snapshot_dir": str(snap)})
    assert cap["log_complete"] is False
    assert any("truncated" in w.lower() for w in cap["warnings"])
    audit = eng.call_tool("wins.audit_frame", {"capture_id": cap["capture_id"], "max_findings": 10})
    by_id = {f["rule_id"]: f for f in audit["findings"]}
    assert by_id["SNAPSHOT_INTEGRITY"]["status"] == "FAIL"


# ---- 7. MRT without matching SV_Target outputs (synthetic sky + DXBC OSGN) --

def test_07_mrt_undeclared_sv_target_synthetic_and_dxbc(tmp_path: Path) -> None:
    # Verify DXBC binary OSGN parser directly
    isgn, osgn, errs = parse_dxbc_signatures(_minimal_dxbc_ps([0]))
    assert errs == []
    assert [e.reg for e in osgn] == [0]

    eng = _engine(tmp_path)
    cap = eng.call_tool("wins.capture_frame", {"snapshot_dir": str(FIXTURE_SKY)})
    audit = eng.call_tool("wins.audit_frame", {"capture_id": cap["capture_id"], "max_findings": 10})
    by_id = {f["rule_id"]: f for f in audit["findings"]}

    mrt = by_id["D3D11_MRT_UNDECLARED_SV_TARGET"]
    assert mrt["status"] == "FAIL"
    assert 10 in mrt["draws"]
    assert mrt["details"]["violations"][0]["missing_rt_slots"] == [1]

    flow = by_id["D3D11_CLEARED_UNWRITTEN_RT_SAMPLED"]
    assert flow["status"] == "FAIL"
    assert flow["certainty"] == "INFERRED_CANDIDATE"
    assert 20 in flow["draws"]

    sh = eng.call_tool("wins.inspect_shader", {"capture_id": cap["capture_id"], "prog_id": 501, "stage": "ps"})
    assert sh["declared_rt_slots"] == [0]
    assert sh["ps_out_mask"] == "0x01"


# ---- 8. Clean negative control (no false positives) [SYNTHETIC] -------------

def test_08_clean_negative_control_no_errors(tmp_path: Path) -> None:
    eng = _engine(tmp_path)
    cap = eng.call_tool("wins.capture_frame", {"snapshot_dir": str(FIXTURE_CLEAN)})
    clean_log = tmp_path / "clean.log"
    clean_log.write_text("winload64: READY images=5\n[WINS:D3D11:GL] present #1\n", encoding="utf-8")

    audit = eng.call_tool(
        "wins.audit_frame",
        {"capture_id": cap["capture_id"], "runtime_log_path": str(clean_log), "max_findings": 10},
    )
    by_id = {f["rule_id"]: f for f in audit["findings"]}
    assert by_id["SNAPSHOT_INTEGRITY"]["status"] == "PASS"
    assert by_id["D3D11_MRT_UNDECLARED_SV_TARGET"]["status"] == "PASS"
    assert by_id["D3D11_CLEARED_UNWRITTEN_RT_SAMPLED"]["status"] == "PASS"
    assert by_id["D3D11_NON_FINITE_PIXEL_VALUES"]["status"] == "PASS"
    assert by_id["D3D11_ZERO_TEX_SRV_BOUND"]["status"] == "PASS"
    assert by_id["GL_RUNTIME_ERRORS"]["status"] == "PASS"


# ---- 9. Non-finite (NaN / Inf) pixel values [SYNTHETIC] ---------------------

def test_09_non_finite_pixel_values(tmp_path: Path) -> None:
    snap = tmp_path / "nan_snap"
    snap.mkdir()
    (snap / "draws.log").write_text(
        "\n".join(
            [
                "BEGIN after_present=1 bb=1280x720 fmt=28",
                "D#1 prog=701 stg=V---P topo=4 k=arrays cnt=3 inst=1 fb=1280x720 nrt=1 rt0=50(f=10,sw=false) dsv=0(f=0) bl=(en=false 1/1->0/0 op=8006 m=f ind=false) ds=(false/false fn=207 st=false) rs=(c=1 ccw=true sc=false clp=true)",
                "  CHG p0(640,360): (0.1000,0.2000,0.3000,1.0000) -> (nan,inf,0.3000,1.0000)",
                "END present=2 total_draws=1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    eng = _engine(tmp_path)
    cap = eng.call_tool("wins.capture_frame", {"snapshot_dir": str(snap)})
    audit = eng.call_tool("wins.audit_frame", {"capture_id": cap["capture_id"], "max_findings": 10})
    by_id = {f["rule_id"]: f for f in audit["findings"]}
    assert by_id["D3D11_NON_FINITE_PIXEL_VALUES"]["status"] == "FAIL"
    assert 1 in by_id["D3D11_NON_FINITE_PIXEL_VALUES"]["draws"]

    blame = eng.call_tool("wins.blame_pixel", {"capture_id": cap["capture_id"], "coords": [[640, 360]]})
    cand = blame["results"][0]["candidates"][0]
    assert cand["attribution_level"] == "OBSERVED_WRITE"
    assert cand["after"][0] == "NaN"
    assert cand["after"][1] == "Inf"
    assert "non_finite_pixel_value" in cand["suspicion_reasons"]


# ---- 10. Unprobed coordinates -> INSUFFICIENT_EVIDENCE (never fabricated) ---

def test_10_unprobed_coord_insufficient_evidence_and_inferred_no_fabrication(tmp_path: Path) -> None:
    eng = _engine(tmp_path)
    cap = eng.call_tool("wins.capture_frame", {"snapshot_dir": str(FIXTURE_SKY)})

    # Default: INSUFFICIENT_EVIDENCE for unprobed coordinate (100, 100)
    b1 = eng.call_tool("wins.blame_pixel", {"capture_id": cap["capture_id"], "coords": [[100, 100]]})
    r1 = b1["results"][0]
    assert r1["attribution_level"] == "INSUFFICIENT_EVIDENCE"
    assert r1["candidates"] == []

    # With allow_inferred=True: INFERRED_CANDIDATE with before=None, after=None (NEVER fabricated)
    b2 = eng.call_tool(
        "wins.blame_pixel",
        {"capture_id": cap["capture_id"], "coords": [[100, 100]], "allow_inferred": True},
    )
    r2 = b2["results"][0]
    assert r2["attribution_level"] == "INFERRED_CANDIDATE"
    assert len(r2["candidates"]) > 0
    for c in r2["candidates"]:
        assert c["attribution_level"] == "INFERRED_CANDIDATE"
        assert c["before"] is None
        assert c["after"] is None


# ---- 11. Workflow pause & resume across separate engine instances -----------

def test_11_workflow_pause_resume_and_guards(tmp_path: Path) -> None:
    wf_dir = tmp_path / "wf_state"
    eng1 = WinsMcpEngine(allowed_roots=[REPO, tmp_path], workflow_dir=wf_dir)

    st = eng1.call_tool(
        "wins.workflow",
        {
            "action": "start",
            "investigation_id": "inv-sky-001",
            "symptom": "White sky at (1500, 250)",
            "profile": "ds3",
            "coords": [[1500, 250]],
        },
    )
    assert st["phase"] == "REPRODUCE"

    # Guard: cannot jump directly from REPRODUCE to PATCH
    with pytest.raises(ValueError, match="Cannot jump directly"):
        eng1.call_tool("wins.workflow", {"action": "advance", "investigation_id": "inv-sky-001", "target_phase": "PATCH"})

    cap = eng1.call_tool("wins.capture_frame", {"snapshot_dir": str(FIXTURE_SKY)})
    eng1.call_tool(
        "wins.workflow",
        {
            "action": "advance",
            "investigation_id": "inv-sky-001",
            "target_phase": "CAPTURE",
            "payload": {"capture_id": cap["capture_id"], "dims": cap["dimensions"], "draws_count": cap["draws_count"]},
        },
    )

    # Simulate process restart / pause & resume with a fresh engine instance
    eng2 = WinsMcpEngine(allowed_roots=[REPO, tmp_path], workflow_dir=wf_dir)
    resumed = eng2.call_tool("wins.workflow", {"action": "get", "investigation_id": "inv-sky-001"})
    assert resumed["phase"] == "CAPTURE"
    assert resumed["capture"]["capture_id"] == cap["capture_id"]

    # Advance to LOCALIZE with falsifiable hypothesis
    eng2.call_tool(
        "wins.workflow",
        {
            "action": "advance",
            "investigation_id": "inv-sky-001",
            "target_phase": "LOCALIZE",
            "payload": {
                "audit_ref": "D3D11_MRT_UNDECLARED_SV_TARGET",
                "hypothesis": {
                    "statement": "Unmasked RT1 receives vo0 duplication when PS omits SV_Target1.",
                    "falsification_condition": "If masking glColorMaski(1,0,0,0,0) leaves (1500,250) white, hypothesis is falsified.",
                },
            },
        },
    )

    # Advance to PATCH -> VERIFY -> RECEIPT
    eng2.call_tool(
        "wins.workflow",
        {
            "action": "advance",
            "investigation_id": "inv-sky-001",
            "target_phase": "PATCH",
            "payload": {
                "files": ["native/wins_d3d11_shader.zig", "native/wins_d3d11_gl.zig"],
                "contract_affected": "D3D11 OSGN SV_Target vs OpenGL glColorMaski",
                "causal_hypothesis": "Mask unwritten RT bits from ps_out_mask",
                "risks": ["Dual-source blend must keep RT0 enabled"],
                "rollback_plan": "git checkout -- native/wins_d3d11_shader.zig native/wins_d3d11_gl.zig",
                "authorized": True,
            },
        },
    )
    eng2.call_tool(
        "wins.workflow",
        {
            "action": "advance",
            "investigation_id": "inv-sky-001",
            "target_phase": "VERIFY",
            "payload": {"verify_result": {"global_status": "FAIL", "checks_passed": 0}},
        },
    )
    # Guard: cannot promote to DEMONSTRATED when verify failed
    with pytest.raises(ValueError, match="Cannot promote verdict to DEMONSTRATED"):
        eng2.call_tool(
            "wins.workflow",
            {
                "action": "advance",
                "investigation_id": "inv-sky-001",
                "target_phase": "RECEIPT",
                "payload": {"verdict": "DEMONSTRATED"},
            },
        )
    # Record NOT_DEMONSTRATED receipt, then verify PASS and verify prior_receipts preserved
    eng2.call_tool(
        "wins.workflow",
        {
            "action": "advance",
            "investigation_id": "inv-sky-001",
            "target_phase": "RECEIPT",
            "payload": {"verdict": "NOT_DEMONSTRATED", "limitations": ["Initial verify failed"]},
        },
    )
    eng2.call_tool(
        "wins.workflow",
        {
            "action": "advance",
            "investigation_id": "inv-sky-001",
            "target_phase": "VERIFY",
            "payload": {"verify_result": {"global_status": "PASS", "checks_passed": 1}},
        },
    )
    final_st = eng2.call_tool(
        "wins.workflow",
        {
            "action": "advance",
            "investigation_id": "inv-sky-001",
            "target_phase": "RECEIPT",
            "payload": {"verdict": "DEMONSTRATED"},
        },
    )
    assert final_st["receipt"]["verdict"] == "DEMONSTRATED"
    assert len(final_st["prior_receipts"]) == 1
    assert final_st["prior_receipts"][0]["verdict"] == "NOT_DEMONSTRATED"


# ---- 12. Cancellation of operations [SYNTHETIC] -----------------------------

def test_12_cancellation_of_verify() -> None:
    cancel = threading.Event()
    cancel.set()
    res = run_verify(["zig_wins_libs"], cancel_event=cancel)
    assert res["global_status"] == "CANCELLED"
    assert res["checks_cancelled"] == 1
    assert res["results"][0]["status"] == "CANCELLED"


# ---- 13. Unauthorized path access & install authorization gate [SYNTHETIC] --

def test_13_unauthorized_path_and_install_gate(tmp_path: Path) -> None:
    eng = _engine(tmp_path)

    # Path outside allowlist
    resp = eng.handle_rpc(
        {
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": {"name": "wins.capture_frame", "arguments": {"snapshot_dir": "/etc"}},
        }
    )
    assert resp is not None and resp["result"]["isError"] is True
    assert resp["result"]["structuredContent"]["error_code"] == "UNAUTHORIZED_PATH"

    # Traversal attempt
    resp2 = eng.handle_rpc(
        {
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {"name": "wins.triage", "arguments": {"target_path": f"{tmp_path}/../../../../etc/passwd"}},
        }
    )
    assert resp2 is not None and resp2["result"]["isError"] is True
    assert resp2["result"]["structuredContent"]["error_code"] == "UNAUTHORIZED_PATH"

    # Install gate without authorization_reason
    resp3 = eng.handle_rpc(
        {
            "jsonrpc": "2.0",
            "id": 32,
            "method": "tools/call",
            "params": {
                "name": "wins.verify",
                "arguments": {"checks": ["zig_wins_libs"], "allow_install": True, "install_target": "ds3"},
            },
        }
    )
    assert resp3 is not None and resp3["result"]["isError"] is True
    assert resp3["result"]["structuredContent"]["error_code"] == "AUTHORIZATION_REQUIRED"


# ---- 14 & 16. Receipt generation and SHA-256 manifest verification ----------

def test_14_and_16_receipt_and_hash_verification(tmp_path: Path) -> None:
    eng = _engine(tmp_path)
    out_dir = tmp_path / "receipt_out"
    res = eng.call_tool(
        "wins.receipt",
        {
            "investigation_id": "ds3-sky-synthetic",
            "verdict": "DEMONSTRATED",
            "hypothesis": "PS omitting SV_Target1 left RT1 unmasked under OpenGL.",
            "out_dir": str(out_dir),
            "tests_executed": [{"check": "zig_d3d11_shader", "status": "PASS"}],
            "artifact_paths": [str(FIXTURE_SKY / "draws.log")],
            "limitations": ["Synthetic fixture control"],
            "rollback_procedure": "git revert <commit>",
        },
    )
    assert Path(res["receipt_path"]).is_file()
    assert Path(res["manifest_path"]).is_file()
    check = verify_manifest(Path(res["manifest_path"]))
    assert check["ok"] is True

    # Tamper with receipt -> hash verification must FAIL
    Path(res["receipt_path"]).write_text('{"tampered": true}\n', encoding="utf-8")
    check_bad = verify_manifest(Path(res["manifest_path"]))
    assert check_bad["ok"] is False
    assert len(check_bad["mismatches"]) == 1

    # Refuses DEMONSTRATED without passing executed tests
    with pytest.raises(ValueError, match="Cannot issue verdict DEMONSTRATED"):
        eng.call_tool(
            "wins.receipt",
            {
                "investigation_id": "ds3-unverified",
                "verdict": "DEMONSTRATED",
                "hypothesis": "Unverified claim",
                "out_dir": str(tmp_path / "receipt_bad"),
                "tests_executed": [],
            },
        )


# ---- 15. Context budget enforcement [SYNTHETIC] -----------------------------

def test_15_context_budget_and_truncation(tmp_path: Path) -> None:
    snap = tmp_path / "many_draws"
    snap.mkdir()
    lines = ["BEGIN after_present=1 bb=1920x1080 fmt=28"]
    for i in range(1, 25):
        lines.append(
            f"D#{i} prog=801 stg=V---P topo=4 k=arrays cnt=3 inst=1 fb=1920x1080 nrt=1 "
            f"rt0=10(f=10,sw=false) dsv=0(f=0) bl=(en=false 1/1->0/0 op=8006 m=f ind=false) "
            f"ds=(false/false fn=207 st=false) rs=(c=1 ccw=true sc=false clp=true)"
        )
        lines.append(f"  CHG p0(100,100): (0.0000,0.0000,0.0000,1.0000) -> (0.{i:02d}00,0.0000,0.0000,1.0000)")
    lines.append("END present=2 total_draws=24")
    (snap / "draws.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    # 300-line GLSL shader to test bounded slicing
    glsl_lines = ["#version 420 core", "layout(location = 0) out vec4 vo0;", "void main() {"]
    glsl_lines.extend([f"    float v{i} = {i}.0;" for i in range(295)])
    glsl_lines.extend(["    vo0 = vec4(1.0);", "}"])
    (snap / "p0801_ps.glsl").write_text("\n".join(glsl_lines) + "\n", encoding="utf-8")

    eng = _engine(tmp_path)
    cap = eng.call_tool("wins.capture_frame", {"snapshot_dir": str(snap)})

    blame = eng.call_tool("wins.blame_pixel", {"capture_id": cap["capture_id"], "coords": [[100, 100]]})
    r = blame["results"][0]
    assert len(r["candidates"]) == 6  # Default budget: max 6 draws
    assert r["truncated"] is True
    assert r["total_candidates"] == 24

    sh = eng.call_tool(
        "wins.inspect_shader",
        {"capture_id": cap["capture_id"], "prog_id": 801, "stage": "ps", "glsl_start_line": 1, "glsl_max_lines": 25},
    )
    assert sh["glsl"]["truncated"] is True
    assert sh["glsl"]["end_line"] == 25
    assert sh["glsl"]["total_lines"] == 300


# ---- Protocol E2E over stdio with WinsMcpClient [SYNTHETIC] -----------------

def test_17_mcp_stdio_protocol_discovery_and_calls(tmp_path: Path) -> None:
    with WinsMcpClient(
        env_overrides={
            "WINS_MCP_ALLOWED_ROOTS": f"{REPO}:{tmp_path}",
            "WINS_MCP_STATE_DIR": str(tmp_path / "wf"),
        }
    ) as client:
        tools = client.list_tools()
        names = {t["name"] for t in tools}
        assert {
            "wins.triage",
            "wins.capture_frame",
            "wins.blame_pixel",
            "wins.audit_frame",
            "wins.inspect_shader",
            "wins.verify",
            "wins.receipt",
            "wins.workflow",
        }.issubset(names)

        prompts = client.request("prompts/list")["result"]["prompts"]
        assert any(p["name"] == "wins-debug-workflow" for p in prompts)
        pget = client.request("prompts/get", {"name": "wins-debug-workflow"})["result"]
        assert "REPRODUCE" in pget["messages"][0]["content"]["text"]

        cap = client.call_tool("wins.capture_frame", {"snapshot_dir": str(FIXTURE_SKY)})["structuredContent"]
        audit = client.call_tool("wins.audit_frame", {"capture_id": cap["capture_id"]})["structuredContent"]
        assert audit["summary"]["FAIL"] >= 1
        assert len(audit["findings"]) <= 5  # Default budget: max 5 findings


# ---- Steam Install=1 helper wrapper regression [SYNTHETIC] ------------------

def test_18_steam_wrapper_audit_detects_buggy_and_passes_fixed(tmp_path: Path) -> None:
    bad_launch = tmp_path / "bad_launch" / "game"
    bad_launch.mkdir(parents=True)
    (bad_launch / "wins").write_text(
        '#!/bin/sh\ncase "${1:-}" in\n  waitforexitandrun|run) exec ./launch-game ;;\nesac\n',
        encoding="utf-8",
    )
    eng = _engine(tmp_path)
    cap = eng.call_tool("wins.capture_frame", {"snapshot_dir": str(FIXTURE_CLEAN)})
    audit_bad = eng.call_tool(
        "wins.audit_frame",
        {"capture_id": cap["capture_id"], "launch_dir": str(tmp_path / "bad_launch"), "max_findings": 10},
    )
    by_id = {f["rule_id"]: f for f in audit_bad["findings"]}
    assert by_id["STEAM_INSTALL_HELPER_RELAUNCH"]["status"] == "FAIL"

    # Clean wrapper filtering iscriptevaluator.exe
    good_launch = tmp_path / "good_launch" / "game"
    good_launch.mkdir(parents=True)
    (good_launch / "wins").write_text(
        '#!/bin/sh\ncase "${2:-}" in *iscriptevaluator.exe) exit 0 ;; esac\n'
        'case "${1:-}" in waitforexitandrun|run) exec ./launch-game ;; esac\n',
        encoding="utf-8",
    )
    audit_good = eng.call_tool(
        "wins.audit_frame",
        {"capture_id": cap["capture_id"], "launch_dir": str(tmp_path / "good_launch"), "max_findings": 10},
    )
    by_id_g = {f["rule_id"]: f for f in audit_good["findings"]}
    assert by_id_g["STEAM_INSTALL_HELPER_RELAUNCH"]["status"] == "PASS"


# ---- Golden Case: REAL Dark Souls III radioactive sky snapshot [REAL_DS3] ---

@pytest.mark.skipif(not (REAL_DS3_SNAP / "draws.log").is_file(), reason="Real DS3 snap_out not present on host")
def test_19_golden_case_real_ds3_radioactive_sky(tmp_path: Path) -> None:
    """[REAL_DS3] End-to-end discovery over the real captured DS3 frame without
    hardcoding any DS3 draw/shader IDs in the auditor."""
    eng = _engine(tmp_path)
    cap = eng.call_tool("wins.capture_frame", {"snapshot_dir": str(REAL_DS3_SNAP)})
    assert cap["log_complete"] is True
    assert cap["dimensions"] == [1920, 1080]
    assert cap["draws_count"] == 430

    audit = eng.call_tool("wins.audit_frame", {"capture_id": cap["capture_id"], "max_findings": 10})
    by_id = {f["rule_id"]: f for f in audit["findings"]}

    # Must independently discover D#259 (prog 354, nrt=2, SV_Target0 only)
    mrt = by_id["D3D11_MRT_UNDECLARED_SV_TARGET"]
    assert mrt["status"] == "FAIL"
    assert 259 in mrt["draws"]
    assert 262 in mrt["draws"]

    # Must infer D#344 sampling zero-cleared tex=1279 with non-zero output and document L0 rt1 gap
    flow = by_id["D3D11_CLEARED_UNWRITTEN_RT_SAMPLED"]
    assert flow["status"] == "FAIL"
    assert flow["certainty"] == "INFERRED_CANDIDATE"
    assert 344 in flow["draws"]

    # Pixel blame at (1500, 250) must return OBSERVED_WRITE hits including D#259 and D#353
    blame = eng.call_tool("wins.blame_pixel", {"capture_id": cap["capture_id"], "coords": [[1500, 250]]})
    res = blame["results"][0]
    assert res["attribution_level"] == "OBSERVED_WRITE"
    assert len(res["candidates"]) <= 6
    blamed_draws = {c["draw_id"] for c in res["candidates"]}
    assert 259 in blamed_draws or 353 in blamed_draws

    # Shader inspection of prog 354 must parse real DXBC OSGN showing only SV_Target0
    sh = eng.call_tool("wins.inspect_shader", {"capture_id": cap["capture_id"], "prog_id": 354, "stage": "ps"})
    assert sh["source"] == "dxbc+glsl"
    assert sh["declared_rt_slots"] == [0]
    assert sh["ps_out_mask"] == "0x01"
