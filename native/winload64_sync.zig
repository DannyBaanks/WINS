//! Windows synchronization primitives over Linux futexes, for winload64 (x86-64).
//! winrun's versions are single-threaded no-ops; these are real, so they stay
//! correct once loaded code starts threads (Cronet/Rust runtimes do).
//!
//!   SRWLOCK (pointer-sized):    bit0 = exclusive owner, bits1.. = shared count * 2
//!   CONDITION_VARIABLE:         32-bit sequence number (futex word)
//!   CRITICAL_SECTION (40 B):    LockCount (offset 8) = futex word 0/1/2,
//!                               RecursionCount (12), OwningThread (16)
//!   INIT_ONCE (pointer-sized):  0 = new, 1 = running, 2 = done
const std = @import("std");
const linux = std.os.linux;
const W: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

const FUTEX_WAIT_PRIVATE: usize = 0 | 128;
const FUTEX_WAKE_PRIVATE: usize = 1 | 128;
const INFINITE: u32 = 0xFFFF_FFFF;
const ERROR_TIMEOUT: u32 = 1460;

pub var set_last_error: ?*const fn (u32) callconv(W) void = null;

fn futexWait(word: *const u32, expect: u32, ms: u32) bool {
    var ts: linux.timespec = .{ .sec = @intCast(ms / 1000), .nsec = @intCast(@as(u64, ms % 1000) * 1_000_000) };
    const rc = linux.syscall4(.futex, @intFromPtr(word), FUTEX_WAIT_PRIVATE, expect, if (ms == INFINITE) 0 else @intFromPtr(&ts));
    return linux.errno(rc) != .TIMEDOUT;
}
fn futexWake(word: *const u32, n: u32) void {
    _ = linux.syscall3(.futex, @intFromPtr(word), FUTEX_WAKE_PRIVATE, n);
}
fn low32(p: *usize) *u32 {
    return @ptrCast(p); // little-endian: the futex word is the low half of the SRW word
}

// ------------------------------------------------------------------ SRW locks
fn InitializeSRWLock(l: *usize) callconv(W) void {
    @atomicStore(usize, l, 0, .release);
}
fn TryAcquireSRWLockExclusive(l: *usize) callconv(W) u8 {
    return @intFromBool(@cmpxchgStrong(usize, l, 0, 1, .acquire, .monotonic) == null);
}
fn AcquireSRWLockExclusive(l: *usize) callconv(W) void {
    while (true) {
        const v = @atomicLoad(usize, l, .monotonic);
        if (v == 0 and @cmpxchgWeak(usize, l, 0, 1, .acquire, .monotonic) == null) return;
        _ = futexWait(low32(l), @truncate(v), INFINITE);
    }
}
fn ReleaseSRWLockExclusive(l: *usize) callconv(W) void {
    @atomicStore(usize, l, 0, .release);
    futexWake(low32(l), std.math.maxInt(i32));
}
fn TryAcquireSRWLockShared(l: *usize) callconv(W) u8 {
    const v = @atomicLoad(usize, l, .monotonic);
    if (v & 1 != 0) return 0;
    return @intFromBool(@cmpxchgStrong(usize, l, v, v + 2, .acquire, .monotonic) == null);
}
fn AcquireSRWLockShared(l: *usize) callconv(W) void {
    while (true) {
        const v = @atomicLoad(usize, l, .monotonic);
        if (v & 1 == 0) {
            if (@cmpxchgWeak(usize, l, v, v + 2, .acquire, .monotonic) == null) return;
            continue;
        }
        _ = futexWait(low32(l), @truncate(v), INFINITE);
    }
}
fn ReleaseSRWLockShared(l: *usize) callconv(W) void {
    if (@atomicRmw(usize, l, .Sub, 2, .release) == 2) futexWake(low32(l), std.math.maxInt(i32));
}

// ------------------------------------------------------------ critical sections
const CS = extern struct { debug: usize, lock: u32, recursion: i32, owner: usize, sem: usize, spin: usize };

fn tid() usize {
    return @intCast(linux.gettid());
}
fn InitializeCriticalSection(cs: *CS) callconv(W) void {
    cs.* = .{ .debug = 0, .lock = 0, .recursion = 0, .owner = 0, .sem = 0, .spin = 0 };
}
fn InitializeCriticalSectionAndSpinCount(cs: *CS, spin: u32) callconv(W) i32 {
    InitializeCriticalSection(cs);
    cs.spin = spin;
    return 1;
}
fn InitializeCriticalSectionEx(cs: *CS, spin: u32, flags: u32) callconv(W) i32 {
    _ = flags;
    return InitializeCriticalSectionAndSpinCount(cs, spin);
}
fn DeleteCriticalSection(cs: *CS) callconv(W) void {
    _ = cs;
}
fn TryEnterCriticalSection(cs: *CS) callconv(W) i32 {
    const me = tid();
    if (@atomicLoad(usize, &cs.owner, .monotonic) == me) {
        cs.recursion += 1;
        return 1;
    }
    if (@cmpxchgStrong(u32, &cs.lock, 0, 1, .acquire, .monotonic) != null) return 0;
    @atomicStore(usize, &cs.owner, me, .monotonic);
    cs.recursion = 1;
    return 1;
}
fn EnterCriticalSection(cs: *CS) callconv(W) void {
    const me = tid();
    if (@atomicLoad(usize, &cs.owner, .monotonic) == me) {
        cs.recursion += 1;
        return;
    }
    // Drepper's mutex: 0 free, 1 locked, 2 locked with waiters.
    var c = @cmpxchgStrong(u32, &cs.lock, 0, 1, .acquire, .monotonic) orelse 0;
    if (c != 0) {
        if (c != 2) c = @atomicRmw(u32, &cs.lock, .Xchg, 2, .acquire);
        while (c != 0) {
            _ = futexWait(&cs.lock, 2, INFINITE);
            c = @atomicRmw(u32, &cs.lock, .Xchg, 2, .acquire);
        }
    }
    @atomicStore(usize, &cs.owner, me, .monotonic);
    cs.recursion = 1;
}
fn LeaveCriticalSection(cs: *CS) callconv(W) void {
    cs.recursion -= 1;
    if (cs.recursion > 0) return;
    @atomicStore(usize, &cs.owner, 0, .monotonic);
    if (@atomicRmw(u32, &cs.lock, .Xchg, 0, .release) == 2) futexWake(&cs.lock, 1);
}

// ---------------------------------------------------------- condition variables
fn InitializeConditionVariable(cv: *u32) callconv(W) void {
    @atomicStore(u32, cv, 0, .release);
}
fn WakeConditionVariable(cv: *u32) callconv(W) void {
    _ = @atomicRmw(u32, cv, .Add, 1, .release);
    futexWake(cv, 1);
}
fn WakeAllConditionVariable(cv: *u32) callconv(W) void {
    _ = @atomicRmw(u32, cv, .Add, 1, .release);
    futexWake(cv, std.math.maxInt(i32));
}
fn timedOut() i32 {
    if (set_last_error) |f| f(ERROR_TIMEOUT);
    return 0;
}
fn SleepConditionVariableSRW(cv: *u32, l: *usize, ms: u32, flags: u32) callconv(W) i32 {
    const shared = flags & 1 != 0; // CONDITION_VARIABLE_LOCKMODE_SHARED
    const seq = @atomicLoad(u32, cv, .acquire);
    if (shared) ReleaseSRWLockShared(l) else ReleaseSRWLockExclusive(l);
    const woke = futexWait(cv, seq, ms);
    if (shared) AcquireSRWLockShared(l) else AcquireSRWLockExclusive(l);
    return if (woke) 1 else timedOut();
}
fn SleepConditionVariableCS(cv: *u32, cs: *CS, ms: u32) callconv(W) i32 {
    const seq = @atomicLoad(u32, cv, .acquire);
    const depth = cs.recursion;
    cs.recursion = 1;
    LeaveCriticalSection(cs);
    const woke = futexWait(cv, seq, ms);
    EnterCriticalSection(cs);
    cs.recursion = depth;
    return if (woke) 1 else timedOut();
}

// --------------------------------------------------------------------- init-once
const InitFn = *const fn (*usize, ?*anyopaque, ?*?*anyopaque) callconv(W) i32;
fn InitOnceExecuteOnce(once: *usize, f: InitFn, param: ?*anyopaque, ctx: ?*?*anyopaque) callconv(W) i32 {
    while (true) {
        switch (@atomicLoad(usize, once, .acquire)) {
            2 => return 1,
            0 => if (@cmpxchgStrong(usize, once, 0, 1, .acquire, .monotonic) == null) {
                const ok = f(once, param, ctx);
                @atomicStore(usize, once, if (ok != 0) 2 else 0, .release);
                futexWake(low32(once), std.math.maxInt(i32));
                return ok;
            },
            else => _ = futexWait(low32(once), 1, INFINITE),
        }
    }
}

// ------------------------------------------------------------------------ misc
/// RTL_OSVERSIONINFOW: report Windows 10 22H2 (build 19045), what the vendor builds target.
fn RtlGetVersion(info: *extern struct { size: u32, major: u32, minor: u32, build: u32, platform: u32 }) callconv(W) i32 {
    info.major = 10;
    info.minor = 0;
    info.build = 19045;
    info.platform = 2; // VER_PLATFORM_WIN32_NT
    return 0; // STATUS_SUCCESS
}
/// FILETIME: 100 ns ticks since 1601-01-01.
fn GetSystemTimePreciseAsFileTime(ft: *u64) callconv(W) void {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &ts);
    ft.* = @as(u64, @intCast(ts.sec)) * 10_000_000 + @as(u64, @intCast(ts.nsec)) / 100 + 116_444_736_000_000_000;
}

// --------------------------------------------------------------- wait on address
// WaitOnAddress compares `size` bytes; futexes wait on the aligned 32-bit word that
// contains the address, so wake-ups are delivered to that word as well.
fn wordOf(addr: usize) *u32 {
    return @ptrFromInt(addr & ~@as(usize, 3));
}
fn WaitOnAddress(addr: *const anyopaque, cmp: *const anyopaque, size: usize, ms: u32) callconv(W) i32 {
    const a = @intFromPtr(addr);
    const same = switch (size) {
        1 => @as(*const volatile u8, @ptrCast(addr)).* == @as(*const u8, @ptrCast(cmp)).*,
        2 => @as(*const volatile u16, @ptrCast(@alignCast(addr))).* == @as(*const u16, @ptrCast(@alignCast(cmp))).*,
        4 => @as(*const volatile u32, @ptrCast(@alignCast(addr))).* == @as(*const u32, @ptrCast(@alignCast(cmp))).*,
        8 => @as(*const volatile u64, @ptrCast(@alignCast(addr))).* == @as(*const u64, @ptrCast(@alignCast(cmp))).*,
        else => return 0,
    };
    if (!same) return 1;
    const w = wordOf(a);
    return if (futexWait(w, @atomicLoad(u32, w, .acquire), ms)) 1 else timedOut();
}
fn WakeByAddressSingle(addr: *const anyopaque) callconv(W) void {
    futexWake(wordOf(@intFromPtr(addr)), 1);
}
fn WakeByAddressAll(addr: *const anyopaque) callconv(W) void {
    futexWake(wordOf(@intFromPtr(addr)), std.math.maxInt(i32));
}

// ------------------------------------------------------------- small kernel32
fn DisableThreadLibraryCalls(h: usize) callconv(W) i32 {
    _ = h;
    return 1; // winload64 never sends DLL_THREAD_* notifications anyway
}
fn SetThreadStackGuarantee(size: ?*u32) callconv(W) i32 {
    if (size) |s| s.* = 0; // previous guarantee
    return 1;
}
fn SetThreadErrorMode(mode: u32, old: ?*u32) callconv(W) i32 {
    _ = mode;
    if (old) |o| o.* = 0;
    return 1;
}
fn GetThreadId(h: usize) callconv(W) u32 {
    // Only the current-thread pseudo handle (-2) is known; other handles: 0 (failure).
    return if (h == @as(usize, @bitCast(@as(isize, -2)))) @intCast(linux.gettid()) else 0;
}
fn GetThreadPriority(h: usize) callconv(W) i32 {
    _ = h;
    return 0; // THREAD_PRIORITY_NORMAL
}
fn putW(buf: ?[*]u16, cap: u32, s: []const u8) u32 {
    if (buf == null or cap <= s.len) return @intCast(s.len + 1); // required size incl. NUL
    for (s, 0..) |c, i| buf.?[i] = c;
    buf.?[s.len] = 0;
    return @intCast(s.len);
}
fn GetSystemDirectoryW(buf: ?[*]u16, cap: u32) callconv(W) u32 {
    return putW(buf, cap, "C:\\Windows\\system32");
}
fn GetComputerNameExW(kind: u32, buf: ?[*]u16, size: *u32) callconv(W) i32 {
    _ = kind;
    const name = "WINS-CLEANROOM";
    if (buf == null or size.* <= name.len) {
        size.* = name.len + 1;
        if (set_last_error) |f| f(234); // ERROR_MORE_DATA
        return 0;
    }
    size.* = putW(buf, size.*, name);
    return 1;
}
/// No unwinder yet: report zero captured frames (callers treat it as "no trace").
fn RtlCaptureStackBackTrace(skip: u32, n: u32, frames: ?*anyopaque, hash: ?*u32) callconv(W) u16 {
    _ = skip;
    _ = n;
    _ = frames;
    if (hash) |h| h.* = 0;
    return 0;
}

pub fn lookup(lib: []const u8, sym: []const u8) ?usize {
    const k32 = std.ascii.eqlIgnoreCase(lib, "kernel32.dll") or std.ascii.eqlIgnoreCase(lib, "kernelbase.dll");
    if (std.ascii.eqlIgnoreCase(lib, "ntdll.dll")) {
        if (std.mem.eql(u8, sym, "RtlGetVersion")) return @intFromPtr(&RtlGetVersion);
        if (std.mem.eql(u8, sym, "RtlCaptureStackBackTrace")) return @intFromPtr(&RtlCaptureStackBackTrace);
        return null;
    }
    if (!k32) return null;
    const table = .{
        .{ "InitializeSRWLock", &InitializeSRWLock },                         .{ "AcquireSRWLockExclusive", &AcquireSRWLockExclusive },
        .{ "ReleaseSRWLockExclusive", &ReleaseSRWLockExclusive },             .{ "TryAcquireSRWLockExclusive", &TryAcquireSRWLockExclusive },
        .{ "AcquireSRWLockShared", &AcquireSRWLockShared },                   .{ "ReleaseSRWLockShared", &ReleaseSRWLockShared },
        .{ "TryAcquireSRWLockShared", &TryAcquireSRWLockShared },             .{ "InitializeCriticalSection", &InitializeCriticalSection },
        .{ "InitializeCriticalSectionAndSpinCount", &InitializeCriticalSectionAndSpinCount }, .{ "InitializeCriticalSectionEx", &InitializeCriticalSectionEx },
        .{ "DeleteCriticalSection", &DeleteCriticalSection },                 .{ "EnterCriticalSection", &EnterCriticalSection },
        .{ "LeaveCriticalSection", &LeaveCriticalSection },                   .{ "TryEnterCriticalSection", &TryEnterCriticalSection },
        .{ "InitializeConditionVariable", &InitializeConditionVariable },     .{ "WakeConditionVariable", &WakeConditionVariable },
        .{ "WakeAllConditionVariable", &WakeAllConditionVariable },           .{ "SleepConditionVariableSRW", &SleepConditionVariableSRW },
        .{ "SleepConditionVariableCS", &SleepConditionVariableCS },           .{ "InitOnceExecuteOnce", &InitOnceExecuteOnce },
        .{ "GetSystemTimePreciseAsFileTime", &GetSystemTimePreciseAsFileTime }, .{ "WaitOnAddress", &WaitOnAddress },
        .{ "WakeByAddressSingle", &WakeByAddressSingle },                     .{ "WakeByAddressAll", &WakeByAddressAll },
        .{ "DisableThreadLibraryCalls", &DisableThreadLibraryCalls },         .{ "SetThreadStackGuarantee", &SetThreadStackGuarantee },
        .{ "SetThreadErrorMode", &SetThreadErrorMode },                       .{ "GetThreadId", &GetThreadId },
        .{ "GetThreadPriority", &GetThreadPriority },                         .{ "GetSystemDirectoryW", &GetSystemDirectoryW },
        .{ "GetComputerNameExW", &GetComputerNameExW },                       .{ "RtlCaptureStackBackTrace", &RtlCaptureStackBackTrace },
    };
    inline for (table) |e| if (std.mem.eql(u8, sym, e[0])) return @intFromPtr(e[1]);
    return null;
}
