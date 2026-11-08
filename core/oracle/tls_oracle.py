"""TLS Behavioral Oracle.
Generates an isolated, multi-threaded Zig test harness to evaluate
candidate TlsAlloc, TlsGetValue, TlsSetValue, and TlsFree shims.
"""

from __future__ import annotations

from .runner import OracleResult, run_behavioral_harness


class TlsBehavioralOracle:
    """Oráculo conductual para APIs de Thread-Local Storage."""

    @staticmethod
    def generate_harness(candidate_shim_code: str) -> str:
        """Embebe el código candidato en un arnés conductual con aserciones de aislamiento."""
        return f"""
const std = @import("std");
const linux = std.os.linux;

const W = std.builtin.CallingConvention.winapi;

// ============================================================================
// CANDIDATE SHIM IMPLEMENTATION UNDER TEST
// ============================================================================
{candidate_shim_code}

// ============================================================================
// BEHAVIORAL ASSERTION HARNESS
// ============================================================================
var g_thread_tested = false;
var g_thread_failed: ?[:0]const u8 = null;

fn workerThread(slot: u32) void {{
    // Aserción 4a: En un hilo nuevo, el valor del slot DEBE ser null inicialmente
    const init_val = TlsGetValue(slot);
    if (init_val != null) {{
        g_thread_failed = "COUNTEREXAMPLE: Thread isolation failure: newly spawned thread observed non-null value from parent thread!";
        return;
    }}

    // Aserción 4b: Modificar el slot en este hilo
    const thread_val: ?*anyopaque = @ptrFromInt(0xBBBB0000);
    const set_res = TlsSetValue(slot, thread_val);
    if (set_res != 1) {{
        g_thread_failed = "COUNTEREXAMPLE: TlsSetValue failed inside worker thread";
        return;
    }}

    if (TlsGetValue(slot) != thread_val) {{
        g_thread_failed = "COUNTEREXAMPLE: Worker thread failed to read its own TLS value";
        return;
    }}

    g_thread_tested = true;
}}

pub fn main() !void {{
    // 1. Probar asignación secuencial distinta
    const s1 = TlsAlloc();
    const s2 = TlsAlloc();

    if (s1 == 0xFFFFFFFF or s2 == 0xFFFFFFFF) {{
        std.debug.print("COUNTEREXAMPLE: TlsAlloc returned TLS_OUT_OF_INDEXES (0xFFFFFFFF) prematurely.\\n", .{{}});
        linux.exit_group(101);
    }}

    if (s1 == s2) {{
        std.debug.print("COUNTEREXAMPLE: Consecutive TlsAlloc returned identical slot index {{d}}! Collisions detected.\\n", .{{s1}});
        linux.exit_group(102);
    }}

    // 2. Probar Roundtrip en un solo hilo
    const val1: ?*anyopaque = @ptrFromInt(0x12345678);
    const val2: ?*anyopaque = @ptrFromInt(0x87654321);

    _ = TlsSetValue(s1, val1);
    _ = TlsSetValue(s2, val2);

    if (TlsGetValue(s1) != val1) {{
        std.debug.print("COUNTEREXAMPLE: TlsGetValue roundtrip mismatch for slot {{d}}.\\n", .{{s1}});
        linux.exit_group(103);
    }}

    if (TlsGetValue(s2) != val2) {{
        std.debug.print("COUNTEREXAMPLE: Multi-slot cross-talk: slot {{d}} overwritten by slot {{d}}.\\n", .{{s1, s2}});
        linux.exit_group(104);
    }}

    // 3. Probar Aislamiento Multihilo Concurrente
    const thread = try std.Thread.spawn(.{{}}, workerThread, .{{s1}});
    thread.join();

    if (g_thread_failed) |err| {{
        std.debug.print("{{s}}\\n", .{{err}});
        linux.exit_group(105);
    }}

    // El hilo principal debe conservar intacto su propio valor (0x12345678)
    if (TlsGetValue(s1) != val1) {{
        std.debug.print("COUNTEREXAMPLE: Parent thread value was clobbered by worker thread! Zero thread-isolation.\\n", .{{}});
        linux.exit_group(106);
    }}

    // 4. Probar liberación y reuso de ciclo de vida
    _ = TlsFree(s1);
    const s_reused = TlsAlloc();
    _ = s_reused;

    std.debug.print("PASS: All TLS behavioral assertions succeeded with multi-threaded isolation.\\n", .{{}});
}}
"""

    @classmethod
    def evaluate(cls, candidate_shim_code: str) -> OracleResult:
        harness = cls.generate_harness(candidate_shim_code)
        return run_behavioral_harness("TLS_BEHAVIORAL_ORACLE", harness)

    def __call__(self, candidate_shim_code: str) -> OracleResult:
        return self.evaluate(candidate_shim_code)
