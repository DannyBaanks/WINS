//! Probe program for winrun (step 1). The SAME logic is compiled twice:
//!   * x86_64-windows-gnu PE (imports only kernel32: GetStdHandle, ReadFile,
//!     WriteFile, GetLastError, SetLastError, ExitProcess, GetCurrentProcessId), run by winrun;
//!   * x86_64-linux ELF, whose tiny OS layer below maps those calls to syscalls.
//! The Linux build is the reference for the differential fuzzer (fuzz_winrun.zig).
//!
//! The logic deliberately leans on absolute pointers stored in writable data
//! (a function-pointer table and slices of strings): in the PE they become
//! DIR64 base relocations, so a loader that skips or botches relocations
//! diverges or faults instead of passing silently.
//!
//! Build (outputs are synthetic and redistributable):
//!   zig build-exe native/testdata/winrun_probe.zig -target x86_64-windows-gnu -O ReleaseSmall \
//!       -fentry=wWinMainCRTStartup --subsystem console -femit-bin=/tmp/probe.exe
//!   zig build-exe native/testdata/winrun_probe.zig -target x86_64-linux -O ReleaseSmall -femit-bin=/tmp/probe-linux
const std = @import("std");
const builtin = @import("builtin");

const is_windows = builtin.os.tag == .windows;
const W: std.builtin.CallingConvention = if (is_windows) .{ .x86_64_win = .{} } else .c;

const STD_INPUT_HANDLE: u32 = @bitCast(@as(i32, -10));
const STD_OUTPUT_HANDLE: u32 = @bitCast(@as(i32, -11));

const os = if (is_windows) struct {
    extern "kernel32" fn GetStdHandle(n: u32) callconv(W) usize;
    extern "kernel32" fn ReadFile(h: usize, buf: ?[*]u8, n: u32, read: *u32, ov: ?*anyopaque) callconv(W) i32;
    extern "kernel32" fn WriteFile(h: usize, buf: [*]const u8, n: u32, written: *u32, ov: ?*anyopaque) callconv(W) i32;
    extern "kernel32" fn GetLastError() callconv(W) u32;
    extern "kernel32" fn SetLastError(v: u32) callconv(W) void;
    extern "kernel32" fn GetCurrentProcessId() callconv(W) u32;
    extern "kernel32" fn ExitProcess(code: u32) callconv(W) noreturn;
} else struct {
    // Reference layer: the documented Windows behaviour for the subset used here.
    const linux = std.os.linux;
    var last_error: u32 = 0;
    fn GetStdHandle(n: u32) usize {
        return if (n == STD_INPUT_HANDLE) 0x1000 else 0x1001;
    }
    fn ReadFile(h: usize, buf: ?[*]u8, n: u32, read: *u32, ov: ?*anyopaque) i32 {
        _ = h;
        _ = ov;
        if (n == 0) {
            read.* = 0;
            return 1;
        }
        const rc = linux.read(0, buf.?, n);
        if (linux.errno(rc) != .SUCCESS) {
            read.* = 0;
            return 0;
        }
        read.* = @intCast(rc);
        return 1;
    }
    fn WriteFile(h: usize, buf: [*]const u8, n: u32, written: *u32, ov: ?*anyopaque) i32 {
        _ = h;
        _ = ov;
        var done: usize = 0;
        while (done < n) {
            const rc = linux.write(1, buf + done, n - done);
            if (linux.errno(rc) != .SUCCESS or rc == 0) break;
            done += rc;
        }
        written.* = @intCast(done);
        return if (done == n) 1 else 0;
    }
    fn GetLastError() u32 {
        return last_error;
    }
    fn SetLastError(v: u32) void {
        last_error = v;
    }
    fn GetCurrentProcessId() u32 {
        return @intCast(linux.getpid());
    }
    fn ExitProcess(code: u32) noreturn {
        linux.exit_group(@bitCast(code));
    }
};

fn rot13(c: u8) u8 {
    return switch (c) {
        'a'...'z' => 'a' + (c - 'a' + 13) % 26,
        'A'...'Z' => 'A' + (c - 'A' + 13) % 26,
        else => c,
    };
}
fn upper(c: u8) u8 {
    return std.ascii.toUpper(c);
}
fn hexlo(c: u8) u8 {
    return "0123456789abcdef"[c & 15];
}
fn printable(c: u8) u8 {
    return if (c >= 0x20 and c < 0x7f) c else '.';
}

// Writable on purpose: absolute addresses here need DIR64 relocations in the PE.
var ops = [_]*const fn (u8) u8{ rot13, upper, hexlo, printable };
var words = [_][]const u8{ "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta" };

var inbuf: [1 << 16]u8 = undefined;
var outbuf: [1 << 18]u8 = undefined;

fn outByte(n: *usize, c: u8) void {
    if (n.* < outbuf.len) {
        outbuf[n.*] = c;
        n.* += 1;
    }
}
fn outStr(n: *usize, s: []const u8) void {
    for (s) |c| outByte(n, c);
}
fn outHex32(n: *usize, v: u32) void {
    var i: u5 = 28;
    while (true) : (i -= 4) {
        outByte(n, hexlo(@truncate(v >> i)));
        if (i == 0) break;
    }
}

/// Returns the exit code; `ret_by_return` tells the entry to return it instead of calling ExitProcess.
fn run(ret_by_return: *bool) u32 {
    const hin = os.GetStdHandle(STD_INPUT_HANDLE);
    const hout = os.GetStdHandle(STD_OUTPUT_HANDLE);

    var len: usize = 0;
    while (len < inbuf.len) {
        var got: u32 = 0;
        const want: u32 = @intCast(@min(inbuf.len - len, 4093)); // odd size: several reads
        if (os.ReadFile(hin, inbuf[len..].ptr, want, &got, null) == 0) return 90;
        if (got == 0) break;
        if (got > want) return 91;
        len += got;
    }
    const in = inbuf[0..len];

    // The two builds run in different processes, so compare invariants, not
    // their numeric IDs. The sentinel depends on the fuzzer's input.
    const pid_sentinel: u32 = if (len == 0) 123 else 0x200 + @as(u32, in[0]);
    os.SetLastError(pid_sentinel);
    const pid = os.GetCurrentProcessId();
    if (pid == 0 or pid != os.GetCurrentProcessId() or os.GetLastError() != pid_sentinel) return 95;

    // Exercise the zero-byte/null-buffer edge for a subset of generated inputs.
    if (len == 0 or in[0] % 2 == 0) {
        const sentinel: u32 = if (len == 0) 123 else 0x100 + @as(u32, in[0]);
        var got: u32 = 0xdeadbeef;
        os.SetLastError(sentinel);
        if (os.ReadFile(hin, null, 0, &got, null) != 1 or got != 0 or os.GetLastError() != sentinel) return 94;
    }

    var n: usize = 0;
    var sum: u32 = 0x811c9dc5;
    for (in, 0..) |c, i| {
        sum = (sum ^ c) *% 16777619;
        outByte(&n, ops[c % ops.len](c));
        if (i % 16 == 15) {
            outByte(&n, ' ');
            outStr(&n, words[(c +% @as(u8, @truncate(i))) % words.len]);
            outByte(&n, '\n');
        }
    }
    // Last-error round trip with an input-derived value.
    os.SetLastError(sum);
    outStr(&n, "\nlen=");
    outHex32(&n, @intCast(len));
    outStr(&n, " fnv=");
    outHex32(&n, sum);
    outStr(&n, " le=");
    outHex32(&n, os.GetLastError());
    outByte(&n, '\n');

    // Write in chunks whose size depends on the input; verify each count.
    const chunk: usize = 1 + (if (len > 0) @as(usize, in[0]) else 0) % 61;
    var off: usize = 0;
    while (off < n) {
        const k: u32 = @intCast(@min(chunk, n - off));
        var wrote: u32 = 0xdeadbeef;
        if (os.WriteFile(hout, outbuf[off..].ptr, k, &wrote, null) == 0) return 92;
        if (wrote != k) return 93;
        off += k;
    }
    ret_by_return.* = len > 1 and in[1] % 5 == 0;
    return sum & 0x7f; // < 90, so loader/IO failures stay distinguishable
}

pub const panic = std.debug.no_panic;

pub fn wWinMainCRTStartup() callconv(W) u32 {
    var by_return = false;
    const code = run(&by_return);
    if (by_return) return code;
    os.ExitProcess(code);
}

comptime {
    if (is_windows) @export(&wWinMainCRTStartup, .{ .name = "wWinMainCRTStartup" });
}

pub fn main() u8 {
    var by_return = false;
    const code = run(&by_return);
    if (by_return) return @truncate(code);
    os.ExitProcess(code);
}
