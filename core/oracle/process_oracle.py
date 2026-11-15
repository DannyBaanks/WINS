"""Process / Thread Behavioral Oracle.
Evaluates GetCurrentProcess, GetCurrentThread, and GetCurrentProcessId against Win32 specifications.
"""

from __future__ import annotations

from .runner import OracleResult, run_behavioral_harness


class ProcessBehavioralOracle:
    """Oráculo conductual para APIs de Proceso y Subproceso Win32."""

    @staticmethod
    def generate_harness(candidate_shim_code: str) -> str:
        return f"""
const std = @import("std");
const linux = std.os.linux;

const W = std.builtin.CallingConvention.winapi;

// ============================================================================
// CANDIDATE SHIM IMPLEMENTATION UNDER TEST
// ============================================================================
{candidate_shim_code}

pub fn main() !void {{
    // 1. Aserción 1: GetCurrentProcess debe retornar el pseudo-handle canónico 0xFFFFFFFF ((HANDLE)-1)
    const proc_handle = GetCurrentProcess();
    if (proc_handle != 0xFFFFFFFF) {{
        std.debug.print("COUNTEREXAMPLE: GetCurrentProcess returned invalid pseudo-handle 0x{{x}}! Expected 0xFFFFFFFF.\\n", .{{proc_handle}});
        linux.exit_group(101);
    }}

    // 2. Aserción 2: GetCurrentThread debe retornar el pseudo-handle canónico 0xFFFFFFFE ((HANDLE)-2)
    const thread_handle = GetCurrentThread();
    if (thread_handle != 0xFFFFFFFE) {{
        std.debug.print("COUNTEREXAMPLE: GetCurrentThread returned invalid pseudo-handle 0x{{x}}! Expected 0xFFFFFFFE.\\n", .{{thread_handle}});
        linux.exit_group(102);
    }}

    // 3. Aserción 3: GetCurrentProcessId debe retornar un PID positivo consistente con el PID del SO
    const pid = GetCurrentProcessId();
    const actual_pid: u32 = @intCast(linux.getpid());
    if (pid == 0) {{
        std.debug.print("COUNTEREXAMPLE: GetCurrentProcessId returned 0, which is invalid.\\n", .{{}});
        linux.exit_group(103);
    }}
    if (pid != actual_pid) {{
        std.debug.print("COUNTEREXAMPLE: GetCurrentProcessId mismatch: expected {{d}}, got {{d}}.\\n", .{{actual_pid, pid}});
        linux.exit_group(104);
    }}

    std.debug.print("PASS: All Process/Thread pseudo-handle and ID behavioral assertions succeeded.\\n", .{{}});
}}
"""

    @classmethod
    def evaluate(cls, candidate_shim_code: str) -> OracleResult:
        harness = cls.generate_harness(candidate_shim_code)
        return run_behavioral_harness("PROCESS_BEHAVIORAL_ORACLE", harness)

    def __call__(self, candidate_shim_code: str) -> OracleResult:
        return self.evaluate(candidate_shim_code)
