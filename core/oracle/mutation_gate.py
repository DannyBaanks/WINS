"""Mutation Gate: Evaluates candidate shims and Behavioral Oracles against the 5 canonical mutants from ISY-AUTO-FALSIFY-01.

Ensures that no semantically corrupt shim can bypass the verification boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from .io_oracle import IoBehavioralOracle
from .memory_oracle import MemoryBehavioralOracle
from .process_oracle import ProcessBehavioralOracle
from .tls_oracle import TlsBehavioralOracle


@dataclass
class MutationVerdict:
    mutant_id: str
    description: str
    compiles_in_zig: bool
    detected: bool
    rejected: bool
    counterexample: str


class MutationGate:
    """Verificador adversarial de mutaciones semánticas."""

    @staticmethod
    def get_canonical_mutants() -> List[Dict[str, str]]:
        return [
            {
                "id": "MUTANT_01_RET_SUCCESS_ON_FAIL",
                "target_oracle": "MEMORY",
                "description": "VirtualAlloc returns 0x1000 unconditionally on size=0, suppressing ERROR_INVALID_PARAMETER",
                "code": """
threadlocal var g_last_error: u32 = 0;
fn GetLastError() callconv(W) u32 { return g_last_error; }
fn SetLastError(e: u32) callconv(W) void { g_last_error = e; }
var g_alloc_prot: u32 = 0x04;
fn VirtualAlloc(lpAddress: ?*anyopaque, dwSize: usize, flAllocationType: u32, flProtect: u32) callconv(W) ?*anyopaque {
    _ = lpAddress; _ = dwSize; _ = flAllocationType; _ = flProtect;
    return @ptrFromInt(0x1000); // MUTATION: Always returns non-null dummy pointer
}
fn VirtualProtect(lpAddress: ?*anyopaque, dwSize: usize, flNewProtect: u32, lpflOldProtect: ?*u32) callconv(W) i32 {
    _ = lpAddress; _ = dwSize; _ = flNewProtect;
    if (lpflOldProtect) |old| old.* = 0x04;
    return 1;
}
fn VirtualFree(lpAddress: ?*anyopaque, dwSize: usize, dwFreeType: u32) callconv(W) i32 {
    _ = lpAddress; _ = dwSize; _ = dwFreeType;
    return 1;
}
""",
            },
            {
                "id": "MUTANT_02_INVERT_BOUNDARY_CHECK",
                "target_oracle": "IO",
                "description": "WriteFile inverts boundary check: only attempts write if nNumberOfBytesToWrite == 0",
                "code": """
fn WriteFile(hFile: usize, lpBuffer: ?[*]const u8, nNumberOfBytesToWrite: u32, lpNumberOfBytesWritten: ?*u32, lpOverlapped: ?*anyopaque) callconv(W) i32 {
    _ = lpOverlapped;
    // MUTATION: Inverted boundary check (only executes when size is 0!)
    if (nNumberOfBytesToWrite != 0) {
        if (lpNumberOfBytesWritten) |w| w.* = 0;
        return 0;
    }
    if (lpBuffer) |buf| {
        const res = linux.write(@intCast(hFile), buf, nNumberOfBytesToWrite);
        if (linux.errno(res) == .SUCCESS) {
            if (lpNumberOfBytesWritten) |w| w.* = @intCast(res);
            return 1;
        }
    }
    return 0;
}
fn ReadFile(hFile: usize, lpBuffer: ?[*]u8, nNumberOfBytesToRead: u32, lpNumberOfBytesRead: ?*u32, lpOverlapped: ?*anyopaque) callconv(W) i32 {
    _ = lpOverlapped;
    if (lpBuffer) |buf| {
        const res = linux.read(@intCast(hFile), buf, nNumberOfBytesToRead);
        if (linux.errno(res) == .SUCCESS) {
            if (lpNumberOfBytesRead) |r| r.* = @intCast(res);
            return 1;
        }
    }
    return 0;
}
""",
            },
            {
                "id": "MUTANT_03_OMIT_REQUIRED_SIDE_EFFECT",
                "target_oracle": "IO",
                "description": "ReadFile reads data but omits populating lpNumberOfBytesRead",
                "code": """
fn WriteFile(hFile: usize, lpBuffer: ?[*]const u8, nNumberOfBytesToWrite: u32, lpNumberOfBytesWritten: ?*u32, lpOverlapped: ?*anyopaque) callconv(W) i32 {
    _ = lpOverlapped;
    if (lpBuffer) |buf| {
        const res = linux.write(@intCast(hFile), buf, nNumberOfBytesToWrite);
        if (linux.errno(res) == .SUCCESS) {
            if (lpNumberOfBytesWritten) |w| w.* = @intCast(res);
            return 1;
        }
    }
    return 0;
}
fn ReadFile(hFile: usize, lpBuffer: ?[*]u8, nNumberOfBytesToRead: u32, lpNumberOfBytesRead: ?*u32, lpOverlapped: ?*anyopaque) callconv(W) i32 {
    _ = lpOverlapped;
    if (lpBuffer) |buf| {
        const res = linux.read(@intCast(hFile), buf, nNumberOfBytesToRead);
        if (linux.errno(res) == .SUCCESS) {
            _ = lpNumberOfBytesRead; // MUTATION: Omit side effect!
            return 1;
        }
    }
    return 0;
}
""",
            },
            {
                "id": "MUTANT_04_MUTATE_RETURN_VALUE",
                "target_oracle": "PROCESS",
                "description": "GetCurrentProcess returns 0x00000000 instead of Win32 pseudo-handle 0xFFFFFFFF",
                "code": """
fn GetCurrentProcess() callconv(W) usize {
    return 0x00000000; // MUTATION: Wrong return value
}
fn GetCurrentThread() callconv(W) usize {
    return 0xFFFFFFFE;
}
fn GetCurrentProcessId() callconv(W) u32 {
    return @intCast(linux.getpid());
}
""",
            },
            {
                "id": "MUTANT_05_BREAK_THREAD_ISOLATION",
                "target_oracle": "TLS",
                "description": "TlsSetValue/TlsGetValue use a shared non-threadlocal global pointer, collapsing threads",
                "code": """
var g_single_global_val: ?*anyopaque = null;
var g_single_slot: u32 = 0;

fn TlsAlloc() callconv(W) u32 {
    g_single_slot += 1;
    return g_single_slot;
}
fn TlsGetValue(dwTlsIndex: u32) callconv(W) ?*anyopaque {
    _ = dwTlsIndex;
    return g_single_global_val; // MUTATION: Shared global collapses all threads
}
fn TlsSetValue(dwTlsIndex: u32, lpTlsValue: ?*anyopaque) callconv(W) i32 {
    _ = dwTlsIndex;
    g_single_global_val = lpTlsValue;
    return 1;
}
fn TlsFree(dwTlsIndex: u32) callconv(W) i32 {
    _ = dwTlsIndex;
    g_single_global_val = null;
    return 1;
}
""",
            },
        ]

    def evaluate_all(self) -> List[MutationVerdict]:
        """Ejecuta los 5 mutantes contra sus respectivos oráculos conductuales."""
        results: List[MutationVerdict] = []
        oracles = {
            "MEMORY": MemoryBehavioralOracle(),
            "IO": IoBehavioralOracle(),
            "PROCESS": ProcessBehavioralOracle(),
            "TLS": TlsBehavioralOracle(),
        }

        for mutant in self.get_canonical_mutants():
            oracle = oracles[mutant["target_oracle"]]
            oracle_res = oracle.evaluate(mutant["code"])
            # El mutante compila si el arnés no falló por compilación
            compiles = (oracle_res.counterexample != "COMPILATION_FAILED")
            # El mutante es DETECTADO y RECHAZADO si el arnés conductual falló (oracle_res.passed is False)
            rejected = not oracle_res.passed
            detected = rejected

            results.append(
                MutationVerdict(
                    mutant_id=mutant["id"],
                    description=mutant["description"],
                    compiles_in_zig=compiles,
                    detected=detected,
                    rejected=rejected,
                    counterexample=oracle_res.counterexample or "NONE",
                )
            )

        return results
