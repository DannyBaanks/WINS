"""Memory Behavioral Oracle.
Evaluates VirtualAlloc, VirtualProtect, and VirtualFree against
Win32 memory specifications and error code conventions.
"""

from __future__ import annotations

from .runner import OracleResult, run_behavioral_harness


class MemoryBehavioralOracle:
    """Oráculo conductual para APIs de Memoria Virtual."""

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
    // 1. Aserción: VirtualAlloc con size=0 debe fallar con NULL y GetLastError = 87
    SetLastError(0);
    const zero_alloc = VirtualAlloc(null, 0, 0x1000, 0x04);
    if (zero_alloc != null) {{
        std.debug.print("COUNTEREXAMPLE: VirtualAlloc(0, 0) returned non-null pointer {{*}}! Expected NULL.\\n", .{{zero_alloc}});
        linux.exit_group(101);
    }}
    if (GetLastError() != 87) {{
        std.debug.print("COUNTEREXAMPLE: VirtualAlloc(0, 0) failed to set GetLastError to ERROR_INVALID_PARAMETER (87). Got {{d}}.\\n", .{{GetLastError()}});
        linux.exit_group(102);
    }}

    // 2. Aserción: VirtualAlloc de 4KB con PAGE_READWRITE debe permitir lectura y escritura
    const page = VirtualAlloc(null, 4096, 0x1000, 0x04);
    if (page == null) {{
        std.debug.print("COUNTEREXAMPLE: VirtualAlloc(4096) failed to allocate valid memory page.\\n", .{{}});
        linux.exit_group(103);
    }}

    const byte_slice: [*]u8 = @ptrCast(page.?);
    for (0..4096) |i| {{
        byte_slice[i] = @intCast(i & 0xFF);
    }}
    for (0..4096) |i| {{
        if (byte_slice[i] != @as(u8, @intCast(i & 0xFF))) {{
            std.debug.print("COUNTEREXAMPLE: Memory write/read verification mismatch at byte {{d}}.\\n", .{{i}});
            linux.exit_group(104);
        }}
    }}

    // 3. Aserción: VirtualProtect debe reportar la protección previa PAGE_READWRITE (0x04)
    var old_protect: u32 = 0;
    const prot_res = VirtualProtect(page, 4096, 0x02, &old_protect); // PAGE_READONLY
    if (prot_res != 1) {{
        std.debug.print("COUNTEREXAMPLE: VirtualProtect failed to apply protection.\\n", .{{}});
        linux.exit_group(105);
    }}
    if (old_protect != 0x04) {{
        std.debug.print("COUNTEREXAMPLE: VirtualProtect returned wrong previous protection: expected 0x04, got 0x{{x}}.\\n", .{{old_protect}});
        linux.exit_group(106);
    }}

    // 4. Aserción: VirtualFree debe liberar exitosamente
    const free_res = VirtualFree(page, 0, 0x8000); // MEM_RELEASE
    if (free_res != 1) {{
        std.debug.print("COUNTEREXAMPLE: VirtualFree failed to release page.\\n", .{{}});
        linux.exit_group(107);
    }}

    std.debug.print("PASS: All VirtualAlloc/VirtualProtect/VirtualFree behavioral assertions succeeded.\\n", .{{}});
}}
"""

    @classmethod
    def evaluate(cls, candidate_shim_code: str) -> OracleResult:
        harness = cls.generate_harness(candidate_shim_code)
        return run_behavioral_harness("MEMORY_BEHAVIORAL_ORACLE", harness)

    def __call__(self, candidate_shim_code: str) -> OracleResult:
        return self.evaluate(candidate_shim_code)
