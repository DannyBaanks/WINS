"""L1 wins.verify: reproducible verification runner with explicit install separation.

Security invariants:
  - Fixed allowlist of verification checks (NEVER arbitrary shell execution).
  - Read-only checks (unit tests, separation_gate, builds to /tmp/wins-mcp-build)
    are strictly separated from binary installation.
  - Installation requires BOTH `allow_install=True` AND non-empty
    `authorization_reason`; otherwise fails closed with AUTHORIZATION_REQUIRED.
  - Skipped checks are reported as SKIPPED, NEVER promoted to PASS.
"""

from __future__ import annotations

import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .security import SecurityError, repo_root, sanitize_text, sha256_file

# Fixed allowlisted read-only verification commands (relative to WINS repo root)
READONLY_CHECKS: Dict[str, Dict[str, Any]] = {
    "zig_d3d11_shader": {
        "cmd": ["zig", "test", "native/wins_d3d11_shader.zig", "-lc"],
        "description": "DXBC -> GLSL 4.20 translator unit tests",
    },
    "zig_d3d11_gl": {
        "cmd": ["zig", "test", "native/wins_d3d11_gl.zig", "-lc"],
        "description": "D3D11 OpenGL backend unit tests",
    },
    "zig_d3d11": {
        "cmd": ["zig", "test", "native/wins_d3d11.zig", "-lc", "-lX11"],
        "description": "D3D11 COM/blend/state unit tests",
    },
    "zig_wins_libs": {
        "cmd": ["zig", "test", "native/wins_libs.zig"],
        "description": "WINS library registry unit tests",
    },
    "python_mcp_tests": {
        "cmd": ["python3", "-m", "pytest", "-q", "tests/test_wins_mcp.py"],
        "description": "WINS-MCP protocol, auditor, blame, workflow, and receipt tests",
    },
    "separation_gate": {
        "cmd": ["bash", "tools/separation_gate.sh"],
        "description": "Clean build & probe-separation gate (winrun32)",
    },
    "build_winrun64": {
        "cmd": [
            "zig",
            "build-exe",
            "native/winrun64.zig",
            "-O",
            "ReleaseSafe",
            "-lc",
            "-lX11",
            "-femit-bin=/tmp/wins-mcp-build/winrun64",
        ],
        "description": "ReleaseSafe winrun64 build to isolated /tmp/wins-mcp-build",
        "artifact": "/tmp/wins-mcp-build/winrun64",
    },
}


def run_verify(
    checks: Sequence[str],
    *,
    timeout_s: float = 120.0,
    cancel_event: Optional[threading.Event] = None,
    allow_install: bool = False,
    install_target: Optional[str] = None,
    authorization_reason: Optional[str] = None,
    cwd: Optional[Path] = None,
) -> Dict[str, Any]:
    """Execute allowlisted verification checks with bounded logs and strict status reporting."""
    work_dir = (cwd or repo_root()).resolve()
    if not checks:
        raise ValueError(f"checks must be non-empty. Valid checks: {sorted(READONLY_CHECKS.keys())}")

    unknown = [c for c in checks if c not in READONLY_CHECKS]
    if unknown:
        raise ValueError(
            f"Unknown check(s): {unknown}. Allowed checks: {sorted(READONLY_CHECKS.keys())}"
        )

    if install_target is not None or allow_install:
        if not allow_install or not (authorization_reason and authorization_reason.strip()):
            raise SecurityError(
                "AUTHORIZATION_REQUIRED",
                "Binary installation is separated from read-only verification and requires "
                "explicit allow_install=true and a non-empty authorization_reason.",
            )
        if install_target not in ("ds3", "cuphead", "falloutnv"):
            raise ValueError("install_target must be one of: ds3, cuphead, falloutnv.")

    results: List[Dict[str, Any]] = []
    hashes: Dict[str, str] = {}
    failures: List[str] = []
    cancelled = False

    env = os.environ.copy()
    if "WINS_MCP_HOME" in env:
        env["HOME"] = env["WINS_MCP_HOME"]

    for name in checks:
        if cancel_event is not None and cancel_event.is_set():
            cancelled = True
            results.append(
                {
                    "check": name,
                    "status": "CANCELLED",
                    "exit_code": None,
                    "duration_s": 0.0,
                    "command": READONLY_CHECKS[name]["cmd"],
                    "output_excerpt": "Cancelled before execution.",
                }
            )
            continue

        spec = READONLY_CHECKS[name]
        cmd = list(spec["cmd"])
        if "artifact" in spec:
            Path(spec["artifact"]).parent.mkdir(parents=True, exist_ok=True)

        t0 = time.monotonic()
        proc = subprocess.Popen(
            cmd,
            cwd=str(work_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )

        timed_out = False
        was_cancelled = False
        while proc.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                was_cancelled = True
                proc.terminate()
                try:
                    proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break
            if time.monotonic() - t0 > timeout_s:
                timed_out = True
                proc.terminate()
                try:
                    proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break
            time.sleep(0.05)

        out, _ = proc.communicate()
        dur = round(time.monotonic() - t0, 3)

        if was_cancelled:
            cancelled = True
            status = "CANCELLED"
            failures.append(f"{name}: cancelled")
        elif timed_out:
            status = "TIMEOUT"
            failures.append(f"{name}: timed out after {timeout_s}s")
        elif proc.returncode == 0:
            status = "PASS"
        else:
            status = "FAIL"
            failures.append(f"{name}: exited {proc.returncode}")

        entry: Dict[str, Any] = {
            "check": name,
            "description": spec["description"],
            "command": cmd,
            "status": status,
            "exit_code": proc.returncode,
            "duration_s": dur,
            "output_excerpt": sanitize_text(out.strip(), max_chars=800),
        }

        if status == "PASS" and "artifact" in spec:
            art = Path(spec["artifact"])
            if art.is_file():
                digest = sha256_file(art)
                hashes[str(art)] = digest
                entry["artifact_sha256"] = digest

        results.append(entry)

    # Optional authorized install (only if all requested checks passed and not cancelled)
    install_result: Optional[Dict[str, Any]] = None
    if allow_install and install_target is not None:
        if failures or cancelled:
            install_result = {
                "status": "SKIPPED",
                "reason": "Skipped install because verification checks did not all pass.",
            }
        else:
            build_dir = Path("/tmp/wins-mcp-build")
            installer = work_dir / "launch" / install_target / "install.sh"
            if not installer.is_file():
                raise FileNotFoundError(f"Installer not found: {installer}")
            proc = subprocess.run(
                ["bash", str(installer), str(build_dir)],
                cwd=str(work_dir),
                capture_output=True,
                text=True,
                timeout=30.0,
                env=env,
                check=False,
            )
            install_result = {
                "status": "PASS" if proc.returncode == 0 else "FAIL",
                "target": install_target,
                "authorization_reason": authorization_reason,
                "exit_code": proc.returncode,
                "output_excerpt": sanitize_text((proc.stdout + "\n" + proc.stderr).strip(), 600),
            }
            if proc.returncode != 0:
                failures.append(f"install:{install_target} exited {proc.returncode}")

    if cancelled:
        global_status = "CANCELLED"
    elif failures:
        global_status = "FAIL"
    elif results and all(r["status"] == "PASS" for r in results):
        global_status = "PASS"
    else:
        global_status = "INCOMPLETE"

    return {
        "global_status": global_status,
        "read_only": not bool(allow_install),
        "checks_requested": list(checks),
        "checks_passed": sum(1 for r in results if r["status"] == "PASS"),
        "checks_failed": sum(1 for r in results if r["status"] in ("FAIL", "TIMEOUT")),
        "checks_cancelled": sum(1 for r in results if r["status"] == "CANCELLED"),
        "results": results,
        "artifact_hashes": hashes,
        "install_result": install_result,
        "failures": failures,
    }
