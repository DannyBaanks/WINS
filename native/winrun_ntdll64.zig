//! ntdll.dll entry points for winload64 (x86-64, Win64 ABI) that loader stubs and
//! DRM wrappers (SteamStub's in-memory SteamDRMP module, Arxan) resolve by name.
//!
//! Every answer describes this process as it really is: no debugger is attached
//! (WINS never attaches one), so the debug-port / debug-object / debug-flags
//! queries report exactly that. Classes WINS does not model fail with
//! STATUS_INVALID_INFO_CLASS rather than inventing data.
const std = @import("std");
const linux = std.os.linux;
const W: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

pub const STATUS_SUCCESS: i32 = 0;
pub const STATUS_INFO_LENGTH_MISMATCH: i32 = @bitCast(@as(u32, 0xC0000004));
pub const STATUS_INVALID_INFO_CLASS: i32 = @bitCast(@as(u32, 0xC0000003));
pub const STATUS_PORT_NOT_SET: i32 = @bitCast(@as(u32, 0xC0000353));
pub const STATUS_INVALID_HANDLE: i32 = @bitCast(@as(u32, 0xC0000008));

/// Set by winrun64 once the PEB exists (ProcessBasicInformation needs it).
pub var peb_ptr: usize = 0;

const CURRENT_PROCESS: usize = @bitCast(@as(isize, -1));
const CURRENT_THREAD: usize = @bitCast(@as(isize, -2));

/// Threads that set ThreadHideFromDebugger. Windows keeps the flag per thread
/// (ETHREAD.HideFromDebugger) and NtQueryInformationThread reports it back;
/// protectors set it and then read it to detect a hooked ntdll, so the bit
/// must stick. Keyed by Linux tid for the current-thread pseudo handle, by
/// handle value otherwise.
var hidden_threads: [256]std.atomic.Value(usize) = [_]std.atomic.Value(usize){std.atomic.Value(usize).init(0)} ** 256;

fn threadKey(thread: usize) usize {
    return if (thread == CURRENT_THREAD) @as(usize, @intCast(linux.gettid())) | (@as(usize, 1) << 63) else thread;
}

fn isHidden(thread: usize) bool {
    const k = threadKey(thread);
    for (&hidden_threads) |*slot| if (slot.load(.acquire) == k) return true;
    return false;
}

fn traceOn() bool {
    if (comptime !@import("builtin").link_libc) return false;
    return std.c.getenv("WINS_TRACE") != null;
}

/// ThreadHideFromDebugger (0x11) with no buffer is the only class a caller can
/// set meaningfully here: there is no debugger to hide from, so it only records
/// the flag (see `hidden_threads`) and succeeds, as on Windows. Other classes
/// are not modelled.
fn NtSetInformationThread(thread: usize, class: u32, info: ?*anyopaque, len: u32) callconv(W) i32 {
    if (traceOn()) std.debug.print("[WINS:ntdll] NtSetInformationThread(0x{x}, class=0x{x}, info={?*}, len={d})\n", .{ thread, class, info, len });
    if (class == 0x11) {
        if (info != null or len != 0) return STATUS_INFO_LENGTH_MISMATCH;
        if (!isHidden(thread)) {
            const k = threadKey(thread);
            for (&hidden_threads) |*slot| if (slot.cmpxchgStrong(0, k, .acq_rel, .acquire) == null) break;
        }
        return STATUS_SUCCESS;
    }
    return STATUS_INVALID_INFO_CLASS;
}

fn put(comptime T: type, info: ?*anyopaque, len: u32, ret_len: ?*u32, v: T) i32 {
    if (ret_len) |r| r.* = @sizeOf(T);
    if (len != @sizeOf(T)) return STATUS_INFO_LENGTH_MISMATCH;
    const p = info orelse return STATUS_INFO_LENGTH_MISMATCH;
    @as(*align(1) T, @ptrCast(p)).* = v;
    return STATUS_SUCCESS;
}

fn NtQueryInformationProcess(proc: usize, class: u32, info: ?*anyopaque, len: u32, ret_len: ?*u32) callconv(W) i32 {
    if (traceOn()) std.debug.print("[WINS:ntdll] NtQueryInformationProcess(0x{x}, class=0x{x}, len={d})\n", .{ proc, class, len });
    if (proc != CURRENT_PROCESS) return STATUS_INVALID_HANDLE;
    switch (class) {
        0 => { // ProcessBasicInformation
            const PBI = extern struct { exit_status: i32, peb: usize, affinity: usize, base_prio: i32, pid: usize, parent: usize };
            return put(PBI, info, len, ret_len, .{
                .exit_status = 0x103, // STILL_ACTIVE
                .peb = peb_ptr,
                .affinity = 1,
                .base_prio = 8,
                .pid = @intCast(linux.getpid()),
                .parent = @intCast(linux.getppid()),
            });
        },
        7 => return put(usize, info, len, ret_len, 0), // ProcessDebugPort: none
        0x1e => { // ProcessDebugObjectHandle: no debug object exists
            if (len != @sizeOf(usize)) return STATUS_INFO_LENGTH_MISMATCH;
            if (info) |p| @as(*align(1) usize, @ptrCast(p)).* = 0;
            if (ret_len) |r| r.* = @sizeOf(usize);
            return STATUS_PORT_NOT_SET;
        },
        0x1f => return put(u32, info, len, ret_len, 1), // ProcessDebugFlags: NoDebugInherit set = not debugged
        else => return STATUS_INVALID_INFO_CLASS,
    }
}

fn NtQueryInformationThread(thread: usize, class: u32, info: ?*anyopaque, len: u32, ret_len: ?*u32) callconv(W) i32 {
    if (traceOn()) std.debug.print("[WINS:ntdll] NtQueryInformationThread(0x{x}, class=0x{x}, len={d})\n", .{ thread, class, len });
    if (class == 0x11) return put(u8, info, len, ret_len, @intFromBool(isHidden(thread))); // ThreadHideFromDebugger
    return STATUS_INVALID_INFO_CLASS;
}

fn NtClose(h: usize) callconv(W) i32 {
    _ = h;
    return STATUS_SUCCESS;
}

/// RtlGetVersion: the same Windows 10 version the kernel32 shims report.
fn RtlGetVersion(vi: ?*anyopaque) callconv(W) i32 {
    const p: [*]u8 = @ptrCast(vi orelse return STATUS_INVALID_INFO_CLASS);
    const size = std.mem.readInt(u32, p[0..4], .little);
    if (size < 20) return STATUS_INFO_LENGTH_MISMATCH;
    std.mem.writeInt(u32, p[4..8], 10, .little); // major
    std.mem.writeInt(u32, p[8..12], 0, .little); // minor
    std.mem.writeInt(u32, p[12..16], 19045, .little); // build
    std.mem.writeInt(u32, p[16..20], 2, .little); // VER_PLATFORM_WIN32_NT
    if (size > 20) @memset(p[20..@min(size, 276)], 0);
    return STATUS_SUCCESS;
}

pub fn lookup(sym: []const u8) ?usize {
    const table = .{
        .{ "NtSetInformationThread", &NtSetInformationThread },
        .{ "ZwSetInformationThread", &NtSetInformationThread },
        .{ "NtQueryInformationProcess", &NtQueryInformationProcess },
        .{ "ZwQueryInformationProcess", &NtQueryInformationProcess },
        .{ "NtQueryInformationThread", &NtQueryInformationThread },
        .{ "ZwQueryInformationThread", &NtQueryInformationThread },
        .{ "NtClose", &NtClose },
        .{ "RtlGetVersion", &RtlGetVersion },
    };
    inline for (table) |e| if (std.mem.eql(u8, sym, e[0])) return @intFromPtr(e[1]);
    return null;
}

test "debug queries describe an undebugged process" {
    var port: usize = 99;
    try std.testing.expectEqual(STATUS_SUCCESS, NtQueryInformationProcess(CURRENT_PROCESS, 7, &port, 8, null));
    try std.testing.expectEqual(@as(usize, 0), port);
    var obj: usize = 99;
    try std.testing.expectEqual(STATUS_PORT_NOT_SET, NtQueryInformationProcess(CURRENT_PROCESS, 0x1e, &obj, 8, null));
    try std.testing.expectEqual(@as(usize, 0), obj);
    var flags: u32 = 0;
    try std.testing.expectEqual(STATUS_SUCCESS, NtQueryInformationProcess(CURRENT_PROCESS, 0x1f, &flags, 4, null));
    try std.testing.expectEqual(@as(u32, 1), flags);
    // wrong length is refused, never written
    var small: u32 = 7;
    try std.testing.expectEqual(STATUS_INFO_LENGTH_MISMATCH, NtQueryInformationProcess(CURRENT_PROCESS, 7, &small, 4, null));
    try std.testing.expectEqual(@as(u32, 7), small);
    var hidden: u8 = 7;
    try std.testing.expectEqual(STATUS_SUCCESS, NtQueryInformationThread(CURRENT_THREAD, 0x11, &hidden, 1, null));
    try std.testing.expectEqual(@as(u8, 0), hidden);
    try std.testing.expectEqual(STATUS_SUCCESS, NtSetInformationThread(CURRENT_THREAD, 0x11, null, 0));
    try std.testing.expectEqual(STATUS_SUCCESS, NtQueryInformationThread(CURRENT_THREAD, 0x11, &hidden, 1, null));
    try std.testing.expectEqual(@as(u8, 1), hidden); // the flag sticks, as on Windows
    try std.testing.expectEqual(STATUS_INVALID_INFO_CLASS, NtSetInformationThread(CURRENT_THREAD, 0x99, null, 0));
}
