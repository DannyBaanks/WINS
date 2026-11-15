"""I/O Behavioral Oracle.
Evaluates WriteFile and ReadFile against Win32 I/O specifications and side-effect guarantees.
"""

from __future__ import annotations

from .runner import OracleResult, run_behavioral_harness


class IoBehavioralOracle:
    """Oráculo conductual para APIs de File I/O (ReadFile, WriteFile)."""

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
    // 1. Crear un pipe en Linux para probar WriteFile y ReadFile conductualmente
    var pipe_fds: [2]i32 = undefined;
    const pipe_rc = linux.pipe(&pipe_fds);
    if (pipe_rc != 0) {{
        std.debug.print("HARNESS_INIT_FAIL: Failed to create test pipe.\\n", .{{}});
        linux.exit_group(200);
    }}
    const read_fd: usize = @intCast(pipe_fds[0]);
    const write_fd: usize = @intCast(pipe_fds[1]);

    // 2. Aserción 1: WriteFile con 11 bytes debe retornar 1 y establecer lpNumberOfBytesWritten = 11
    const test_msg = "Hello Win32";
    var bytes_written: u32 = 0;
    const write_res = WriteFile(write_fd, test_msg.ptr, test_msg.len, &bytes_written, null);

    if (write_res != 1) {{
        std.debug.print("COUNTEREXAMPLE: WriteFile returned 0 for valid pipe write.\\n", .{{}});
        linux.exit_group(101);
    }}

    if (bytes_written != test_msg.len) {{
        std.debug.print("COUNTEREXAMPLE: Omitted or wrong side effect: expected lpNumberOfBytesWritten={{d}}, got {{d}}.\\n", .{{test_msg.len, bytes_written}});
        linux.exit_group(102);
    }}

    // 3. Aserción 2: ReadFile debe recuperar exactamente los bytes escritos
    var read_buf: [32]u8 = undefined;
    var bytes_read: u32 = 0;
    const read_res = ReadFile(read_fd, &read_buf, 11, &bytes_read, null);

    if (read_res != 1) {{
        std.debug.print("COUNTEREXAMPLE: ReadFile returned 0 for valid pipe read.\\n", .{{}});
        linux.exit_group(103);
    }}

    if (bytes_read != 11) {{
        std.debug.print("COUNTEREXAMPLE: ReadFile side effect failure: expected lpNumberOfBytesRead=11, got {{d}}.\\n", .{{bytes_read}});
        linux.exit_group(104);
    }}

    if (!std.mem.eql(u8, read_buf[0..11], test_msg)) {{
        std.debug.print("COUNTEREXAMPLE: ReadFile data corruption: payload content mismatch.\\n", .{{}});
        linux.exit_group(105);
    }}

    // 4. Aserción 3: Boundary check con nNumberOfBytesToWrite = 0
    var zero_written: u32 = 999;
    const zero_res = WriteFile(write_fd, test_msg.ptr, 0, &zero_written, null);
    if (zero_res != 1 or zero_written != 0) {{
        std.debug.print("COUNTEREXAMPLE: Boundary condition failure on zero-byte write: res={{d}}, written={{d}}.\\n", .{{zero_res, zero_written}});
        linux.exit_group(106);
    }}

    _ = linux.close(pipe_fds[0]);
    _ = linux.close(pipe_fds[1]);

    std.debug.print("PASS: All WriteFile and ReadFile behavioral assertions succeeded.\\n", .{{}});
}}
"""

    @classmethod
    def evaluate(cls, candidate_shim_code: str) -> OracleResult:
        harness = cls.generate_harness(candidate_shim_code)
        return run_behavioral_harness("IO_BEHAVIORAL_ORACLE", harness)

    def __call__(self, candidate_shim_code: str) -> OracleResult:
        return self.evaluate(candidate_shim_code)
