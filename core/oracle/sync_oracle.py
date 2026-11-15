"""Synchronization Behavioral Oracle.
Evaluates InitializeCriticalSection, InitializeCriticalSectionAndSpinCount,
EnterCriticalSection, TryEnterCriticalSection, and LeaveCriticalSection
against Win32 CRT multithreading contracts (preventing MSVC R6017).
"""

from __future__ import annotations

from .runner import OracleResult, run_behavioral_harness


class SyncBehavioralOracle:
    """Oráculo conductual para APIs de Sincronización (Critical Section)."""

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
    // 1. Estructura de CRITICAL_SECTION en memoria (6 dwords = 24 bytes en x86)
    var cs_mem: [6]u32 = [_]u32{{0xAAAAAAAA}} ** 6;
    const cs_ptr: ?*anyopaque = @ptrCast(&cs_mem);

    // 2. Aserción 1: InitializeCriticalSectionAndSpinCount debe recibir 2 parámetros
    // y dejar LockCount en -1 (0xFFFFFFFF) y RecursionCount en 0
    const init_res = InitializeCriticalSectionAndSpinCount(cs_ptr, 1000);
    if (init_res != 1) {{
        std.debug.print("COUNTEREXAMPLE: InitializeCriticalSectionAndSpinCount returned 0! Expected TRUE (1).\\n", .{{}});
        linux.exit_group(101);
    }}

    // LockCount (offset 4 bytes = index 1) DEBE ser -1
    const lock_count: i32 = @bitCast(cs_mem[1]);
    if (lock_count != -1) {{
        std.debug.print("COUNTEREXAMPLE: Uninitialized CriticalSection: LockCount is {{d}}, expected -1.\\n", .{{lock_count}});
        linux.exit_group(102);
    }}

    // 3. Aserción 2: EnterCriticalSection debe reclamar la sección
    EnterCriticalSection(cs_ptr);
    const rec_count: u32 = cs_mem[2];
    if (rec_count != 1) {{
        std.debug.print("COUNTEREXAMPLE: EnterCriticalSection failed to set RecursionCount to 1 (got {{d}}).\\n", .{{rec_count}});
        linux.exit_group(103);
    }}

    // 4. Aserción 3: Re-entrada recursiva en el mismo hilo
    EnterCriticalSection(cs_ptr);
    const rec_count_2: u32 = cs_mem[2];
    if (rec_count_2 != 2) {{
        std.debug.print("COUNTEREXAMPLE: Recursive EnterCriticalSection failed: expected RecursionCount=2, got {{d}}.\\n", .{{rec_count_2}});
        linux.exit_group(104);
    }}

    // 5. Aserción 4: LeaveCriticalSection debe decrementar la recursión
    LeaveCriticalSection(cs_ptr);
    if (cs_mem[2] != 1) {{
        std.debug.print("COUNTEREXAMPLE: First LeaveCriticalSection failed: expected RecursionCount=1, got {{d}}.\\n", .{{cs_mem[2]}});
        linux.exit_group(105);
    }}

    // 6. Aserción 5: LeaveCriticalSection final debe liberar el lock (LockCount = -1, RecursionCount = 0)
    LeaveCriticalSection(cs_ptr);
    const final_lock: i32 = @bitCast(cs_mem[1]);
    if (final_lock != -1 or cs_mem[2] != 0) {{
        std.debug.print("COUNTEREXAMPLE: Final LeaveCriticalSection failed to reset lock state: LockCount={{d}}, RecCount={{d}}.\\n", .{{final_lock, cs_mem[2]}});
        linux.exit_group(106);
    }}

    // 7. Aserción 6: TryEnterCriticalSection
    const try_res = TryEnterCriticalSection(cs_ptr);
    if (try_res != 1 or cs_mem[2] != 1) {{
        std.debug.print("COUNTEREXAMPLE: TryEnterCriticalSection failed to acquire free lock.\\n", .{{}});
        linux.exit_group(107);
    }}
    LeaveCriticalSection(cs_ptr);

    // 8. Aserción 7: DeleteCriticalSection
    DeleteCriticalSection(cs_ptr);

    std.debug.print("PASS: All CriticalSection multithread synchronization assertions succeeded.\\n", .{{}});
}}
"""

    @classmethod
    def evaluate(cls, candidate_shim_code: str) -> OracleResult:
        harness = cls.generate_harness(candidate_shim_code)
        return run_behavioral_harness("SYNC_BEHAVIORAL_ORACLE", harness)

    def __call__(self, candidate_shim_code: str) -> OracleResult:
        return self.evaluate(candidate_shim_code)
