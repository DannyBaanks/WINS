# WINS-MCP v0.1 — Evidence-Driven Debugging Protocol

`wins-mcp` exposes WINS's deterministic D3D11/OpenGL, binary triage, verification, and Steam launcher telemetry as a **Model Context Protocol (MCP 2024-11-05)** stdio server with an explicit 6-phase workflow (`wins-debug-workflow`).

Its goal is **context reduction without losing falsifiability**: deterministic instrumentation narrows thousands of draw calls and shaders into bounded, verifiable JSON facts so smaller or non-vision models can localize and verify bugs reliably.

---

## Architecture (L0 / L1 / L2)

| Layer | Modules | Responsibility |
|---|---|---|
| **L0 — Deterministic instrumentation** | `native/wins_d3d11_gl.zig` (`WINS_D3D11_SNAP_TRIG=1`), `wins_mcp/snapshot.py`, `wins_mcp/auditors.py` | Captures and parses `draws.log`, DXBC `ISGN`/`OSGN`, GLSL metadata, `final.ppm`, runtime/Steam logs, and evaluates deterministic invariants (`PASS` / `FAIL` / `UNKNOWN`). Zero LLM logic. |
| **L1 — Bounded MCP tools** | `wins_mcp/server.py`, `wins_mcp/blame.py`, `wins_mcp/triage.py`, `wins_mcp/verify.py`, `wins_mcp/receipt.py`, `wins_mcp/security.py`, `bin/wins-mcp` | Exposes 8 schema-validated tools over JSON-RPC 2.0 stdio with path allowlists, read-only default posture, cancellation, and explicit context budgets. |
| **L2 — Resumable workflow** | `wins_mcp/workflow.py` (`wins.workflow` + MCP prompt `wins-debug-workflow`) | Persistent, evidence-gated state machine: `REPRODUCE → CAPTURE → LOCALIZE → PATCH → VERIFY → RECEIPT`. |

---

## Tools & Context Budgets

All tools mark telemetry responses with `"data_trust": "UNTRUSTED_TELEMETRY"` (logs/shaders are never interpreted as commands) and report `truncated: true/false` whenever results exceed budget.

| Tool | Posture | Default Budget | Purpose |
|---|---|---|---|
| `wins.triage` | Read-only | `max_imports=20` | Wraps `core/triage.py` (`wins probe --json`), `wins-native imports --json`, and profile log/snapshot discovery. Never executes unknown binaries. |
| `wins.capture_frame` | Read-only (`trigger_new` writes `snap_req`) | Metadata only (no base64 blobs) | Loads an existing `snap_out` (default) or triggers `snap_req` on a live `WINS_D3D11_SNAP_TRIG=1` run; returns `capture_id`, dims, probes, SHA-256 hashes. |
| `wins.blame_pixel` | Read-only | `max_candidates=6` (cap `32`) | Attributes pixel writes at `(x, y)`. Strictly distinguishes `OBSERVED_WRITE` (real `glReadPixels` `CHG` lines), `INFERRED_CANDIDATE` (`before=null, after=null`), and `INSUFFICIENT_EVIDENCE`. |
| `wins.audit_frame` | Read-only | `max_findings=5` (cap `20`) | Runs deterministic D3D11/GL + Steam invariant checks returning `PASS` / `FAIL` / `UNKNOWN` with deterministic ranking. |
| `wins.inspect_shader` | Read-only | `glsl_max_lines=60` (cap `200`) | Parses DXBC `ISGN`/`OSGN` (or GLSL fallback), `ps_out_mask`, samplers/UBOs, related draws, and a line-bounded GLSL slice. |
| `wins.verify` | Read-only checks; install gated | Excerpt `800` chars/check | Runs allowlisted Zig tests, `separation_gate.sh`, or isolated `/tmp/wins-mcp-build/winrun64`. Install fails closed (`AUTHORIZATION_REQUIRED`) unless `allow_install=true` + `authorization_reason`. |
| `wins.receipt` | Writes to authorized `out_dir` | Bounded lists | Emits `receipt_<id>.json`, SHA-256 `manifest.json`, and `isymem_summary`. Refuses `DEMONSTRATED` without passing executed tests. |
| `wins.workflow` | Writes state JSON to `~/.cache/wins/mcp-workflows/` | Compact state | `start`, `get` (resume), and `advance` across the 6 workflow phases, preserving `prior_receipts`. |

---

## Invocation Examples

### CLI inspection
```bash
./bin/wins-mcp --list-tools
```

### Stdio JSON-RPC client (Python)
```python
from wins_mcp.client import WinsMcpClient

with WinsMcpClient() as client:
    cap = client.call_tool("wins.capture_frame", {
        "snapshot_dir": "wins_mcp/fixtures/radioactive_sky_synthetic"
    })["structuredContent"]

    audit = client.call_tool("wins.audit_frame", {
        "capture_id": cap["capture_id"]
    })["structuredContent"]

    blame = client.call_tool("wins.blame_pixel", {
        "capture_id": cap["capture_id"],
        "coords": [[1500, 250]]
    })["structuredContent"]

    sh = client.call_tool("wins.inspect_shader", {
        "capture_id": cap["capture_id"],
        "prog_id": 501,
        "stage": "ps"
    })["structuredContent"]
```

---

## Integration with ISyMCP Hub

`wins-mcp` speaks standard newline-delimited JSON-RPC 2.0 MCP over stdio, matching the exact `servers.json` schema parsed by `chatgpt-http-mcp/hub/src/config.zig`.

A ready-to-adapt template is in [`wins_mcp/isymcp_hub_entry.json`](./isymcp_hub_entry.json):

```json
{
  "servers": {
    "wins-mcp": {
      "command": "python3",
      "args": ["<WINS_REPO_PATH>/bin/wins-mcp"],
      "env": {
        "WINS_MCP_HOME": "<USER_HOME>",
        "PATH": "/usr/local/bin:/usr/bin:/bin"
      },
      "isolation": "shared",
      "description": "WINS evidence-driven D3D11/OpenGL & Steam debugging MCP server"
    }
  }
}
```

After adding the entry to `servers.json`, reload **only the main hub process** without disrupting other TUI backends:
```bash
systemctl --user reload isymcp-hub
```
Verified live on the host `isymcp-hub`: `hub_discover(server="wins-mcp")` reports all 8 tools (`isolation: "shared"`), and `hub_execute` runs `wins.capture_frame`, `wins.audit_frame`, and `wins.blame_pixel` end-to-end without restarting unrelated hub backends.

---

## Guide for Non-Vision Agents

Vision is only needed at two optional boundaries:
1. **`REPRODUCE`:** a human or vision model supplies coordinates `(x, y)` of the broken region (e.g. `(1500, 250)` = blown-out sky, `(960, 540)` = clean character control).
2. **`VERIFY`:** a human or vision model confirms the final after-fix screenshot.

All core debugging steps require **zero vision**:
1. Call `wins.capture_frame` → verify `log_complete == true` and check `instrumented_probes`.
2. Call `wins.audit_frame` → inspect every `FAIL` finding (sorted deterministically by severity and priority).
3. Call `wins.blame_pixel` on both the **broken coordinate** and a **clean control coordinate** → compare `before -> after`, `nrt`, `blend`, and `ps_declared_sv_targets`.
4. Call `wins.inspect_shader` on the implicated `prog_id` → confirm `OSGN` vs bound `nrt` and inspect only the relevant GLSL window.
5. Propose a minimal patch with an explicit `falsification_condition` and rollback plan; never edit or install without authorization.

---

## Guide for Adding New Deterministic Auditors

1. Open [`wins_mcp/auditors.py`](./auditors.py).
2. Add a priority weight to `RULE_PRIORITY` (higher = surfaced earlier in the 5-finding budget).
3. Write a pure function `_audit_<name>(snap: SnapshotData) -> AuditFinding`:
   - Return `status="UNKNOWN"` (with `certainty="INSUFFICIENT_EVIDENCE"`) whenever the snapshot lacks the instrumentation required to check the invariant. **Never fake `PASS`.**
   - Return `status="FAIL"` only with concrete `evidence_refs` (`draws.log:L...`, shader filename) and bounded `details`.
   - Do **not** hardcode game-specific draw IDs, program IDs, or texture IDs.
4. Register the call inside `run_frame_audit`.
5. Add both a **positive trigger test** and a **clean negative control test** in [`tests/test_wins_mcp.py`](../tests/test_wins_mcp.py).

---

## Known Limitations & L0 Gaps

1. **Multi-RT texture IDs (`rt1..rt7`):** `native/wins_d3d11_gl.zig` currently logs `nrt` and `rt0` in `draws.log`, not `rt1..rt7`. Therefore `D3D11_CLEARED_UNWRITTEN_RT_SAMPLED` honestly reports `certainty: "INFERRED_CANDIDATE"` when linking a zero-cleared texture sampled later (such as DS3's `tex=1279`) to preceding undeclared-`SV_Target` MRT draws. Logging `rt1..rt7` in `wins_d3d11_gl.zig` would promote that link to `OBSERVED_WRITE`.
2. **Fixed probe coordinates:** `wins_d3d11_gl.zig` currently probes 6 fixed coordinates (`p0..p5`). Calling `wins.blame_pixel` on unprobed coordinates honestly returns `INSUFFICIENT_EVIDENCE` (never fabricates `before/after`). Adding `WINS_D3D11_SNAP_PROBES=x1,y1;x2,y2` in L0 is the clean next step.
3. **Water splash rectangular defect:** No separate pre-fix `snap_out/` capture of the Cemetery of Ash water puddle exists on disk (the `ps_out_mask` fix resolved both the sky and the water ripples simultaneously). Therefore the water-puddle case is `NOT_DEMONSTRATED` against a real puddle snapshot, though the same `D3D11_MRT_UNDECLARED_SV_TARGET` auditor covers multi-RT decal/particle shaders.
4. **Live `isymcp-hub` integration:** Verified live via `systemctl --user reload isymcp-hub` + `hub_discover` / `hub_execute` (8 tools served in `shared` isolation without disturbing other hub backends).
5. **Local small-model benchmark (§11):** Optional evaluation (`NOT_DEMONSTRATED` until a local Ollama server/model is running).
