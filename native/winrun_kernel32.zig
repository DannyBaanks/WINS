//! WINS Foundation KERNEL32 Implementation
//! High-speed Win32 runtime emulation layer for x86_64 PE binaries.
//! Provides memory management (Heap), Thread-Local Storage (TLS/FLS),
//! synchronization, process/thread identity, timing, console, strings and file primitives.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const W: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

pub var image_base_addr: usize = 0;

pub fn setImageBase(base: usize) void {
    image_base_addr = base;
}

// ---------------------------------------------------------------------------
// 1. Process & Thread Identity / State
// ---------------------------------------------------------------------------

fn GetCurrentProcess() callconv(W) usize {
    return ~@as(usize, 0); // (HANDLE)-1
}

fn GetCurrentThread() callconv(W) usize {
    return ~@as(usize, 1); // (HANDLE)-2
}

fn GetCurrentThreadId() callconv(W) u32 {
    return @intCast(linux.getpid());
}

fn IsDebuggerPresent() callconv(W) u32 {
    return 0;
}

fn IsProcessorFeaturePresent(feature: u32) callconv(W) u32 {
    return switch (feature) {
        0...30 => 1, // Core x86-64 CPU features: SSE, SSE2, SSE3, CX8, etc.
        else => 0,
    };
}

fn TerminateProcess(h: usize, code: u32) callconv(W) noreturn {
    _ = h;
    linux.exit_group(@bitCast(code));
}

fn ExitThread(code: u32) callconv(W) noreturn {
    linux.exit_group(@bitCast(code));
}

fn FreeLibraryAndExitThread(h: usize, code: u32) callconv(W) noreturn {
    _ = h;
    linux.exit_group(@bitCast(code));
}

fn SetUnhandledExceptionFilter(filter: usize) callconv(W) usize {
    _ = filter;
    return 0;
}

fn UnhandledExceptionFilter(info: usize) callconv(W) u32 {
    _ = info;
    return 1; // EXCEPTION_EXECUTE_HANDLER
}

fn RaiseException(code: u32, flags: u32, nargs: u32, args: ?[*]const usize) callconv(W) noreturn {
    _ = flags;
    _ = nargs;
    _ = args;
    linux.exit_group(@bitCast(code));
}

fn RtlPcToFileHeader(pc: usize, base: ?*usize) callconv(W) usize {
    _ = pc;
    if (base) |b| b.* = image_base_addr;
    return image_base_addr;
}

fn RtlUnwind(target_frame: ?*anyopaque, target_ip: ?*anyopaque, record: ?*anyopaque, return_val: ?*anyopaque) callconv(W) void {
    _ = target_frame;
    _ = target_ip;
    _ = record;
    _ = return_val;
}

fn RtlUnwindEx(target_frame: ?*anyopaque, target_ip: ?*anyopaque, record: ?*anyopaque, return_val: ?*anyopaque, ctx: ?*anyopaque, hist: ?*anyopaque) callconv(W) void {
    _ = target_frame;
    _ = target_ip;
    _ = record;
    _ = return_val;
    _ = ctx;
    _ = hist;
}

fn RtlCaptureContext(ctx: ?*anyopaque) callconv(W) void {
    _ = ctx;
}

fn RtlLookupFunctionEntry(pc: usize, base: ?*usize, hist: ?*anyopaque) callconv(W) ?*anyopaque {
    _ = pc;
    _ = hist;
    if (base) |b| b.* = image_base_addr;
    return null;
}

fn RtlVirtualUnwind(handler_type: u32, base: usize, pc: usize, entry: ?*anyopaque, ctx: ?*anyopaque, handler_data: ?*anyopaque, establisher_frame: ?*anyopaque, context_pointers: ?*anyopaque) callconv(W) u64 {
    _ = handler_type;
    _ = base;
    _ = pc;
    _ = entry;
    _ = ctx;
    _ = handler_data;
    _ = establisher_frame;
    _ = context_pointers;
    return 0;
}

fn EncodePointer(ptr: ?*anyopaque) callconv(W) ?*anyopaque {
    return ptr;
}

fn DecodePointer(ptr: ?*anyopaque) callconv(W) ?*anyopaque {
    return ptr;
}

// ---------------------------------------------------------------------------
// 2. Heap Memory Allocation (mmap backed)
// ---------------------------------------------------------------------------

const HEAP_COOKIE: usize = 0x10000;

fn GetProcessHeap() callconv(W) usize {
    return HEAP_COOKIE;
}

fn HeapAlloc(h: usize, flags: u32, bytes: usize) callconv(W) ?[*]u8 {
    _ = h;
    const total = std.mem.alignForward(usize, bytes + 16, 4096);
    const mrc = linux.mmap(null, total, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
    if (linux.errno(mrc) != .SUCCESS) return null;
    const p: [*]u8 = @ptrFromInt(mrc);
    std.mem.writeInt(usize, p[0..8], total, .little);
    std.mem.writeInt(usize, p[8..16], bytes, .little);
    const user = p + 16;
    if (flags & 0x00000008 != 0) { // HEAP_ZERO_MEMORY
        @memset(user[0..bytes], 0);
    }
    return user;
}

fn HeapFree(h: usize, flags: u32, ptr: ?[*]u8) callconv(W) u32 {
    _ = h;
    _ = flags;
    if (ptr == null) return 1;
    const p = @as([*]u8, @ptrCast(ptr.?)) - 16;
    const total = std.mem.readInt(usize, p[0..8], .little);
    _ = linux.munmap(p, total);
    return 1;
}

fn HeapReAlloc(h: usize, flags: u32, ptr: ?[*]u8, bytes: usize) callconv(W) ?[*]u8 {
    if (ptr == null) return HeapAlloc(h, flags, bytes);
    const old_p = @as([*]u8, @ptrCast(ptr.?)) - 16;
    const old_bytes = std.mem.readInt(usize, old_p[8..16], .little);
    const new_ptr = HeapAlloc(h, flags, bytes) orelse return null;
    const copy_len = @min(old_bytes, bytes);
    if (copy_len > 0) @memcpy(new_ptr[0..copy_len], ptr.?[0..copy_len]);
    _ = HeapFree(h, 0, ptr);
    return new_ptr;
}

fn HeapSize(h: usize, flags: u32, ptr: ?[*]u8) callconv(W) usize {
    _ = h;
    _ = flags;
    if (ptr == null) return 0;
    const p = @as([*]u8, @ptrCast(ptr.?)) - 16;
    return std.mem.readInt(usize, p[8..16], .little);
}

fn HeapValidate(h: usize, flags: u32, ptr: ?*anyopaque) callconv(W) u32 {
    _ = h;
    _ = flags;
    _ = ptr;
    return 1;
}

fn HeapCompact(h: usize, flags: u32) callconv(W) usize {
    _ = h;
    _ = flags;
    return 0;
}

fn HeapCreate(options: u32, init_size: usize, max_size: usize) callconv(W) usize {
    _ = options;
    _ = init_size;
    _ = max_size;
    return HEAP_COOKIE;
}

fn HeapDestroy(h: usize) callconv(W) u32 {
    _ = h;
    return 1;
}

fn LocalFree(ptr: ?[*]u8) callconv(W) ?[*]u8 {
    _ = HeapFree(0, 0, ptr);
    return null;
}

// ---------------------------------------------------------------------------
// 3. Thread Local Storage (TLS) & Fiber Local Storage (FLS)
// ---------------------------------------------------------------------------

var tls_slots: [256]usize = [_]usize{0} ** 256;
var tls_used: [256]bool = [_]bool{false} ** 256;

var fls_slots: [256]usize = [_]usize{0} ** 256;
var fls_used: [256]bool = [_]bool{false} ** 256;

fn TlsAlloc() callconv(W) u32 {
    for (&tls_used, 0..) |*u, i| {
        if (!u.*) {
            u.* = true;
            tls_slots[i] = 0;
            return @intCast(i);
        }
    }
    return 0xFFFFFFFF; // TLS_OUT_OF_INDEXES
}

fn TlsGetValue(idx: u32) callconv(W) usize {
    if (idx < 256 and tls_used[idx]) return tls_slots[idx];
    return 0;
}

fn TlsSetValue(idx: u32, val: usize) callconv(W) u32 {
    if (idx < 256 and tls_used[idx]) {
        tls_slots[idx] = val;
        return 1;
    }
    return 0;
}

fn TlsFree(idx: u32) callconv(W) u32 {
    if (idx < 256) {
        tls_used[idx] = false;
        tls_slots[idx] = 0;
        return 1;
    }
    return 0;
}

fn FlsAlloc(cb: ?*anyopaque) callconv(W) u32 {
    _ = cb;
    for (&fls_used, 0..) |*u, i| {
        if (!u.*) {
            u.* = true;
            fls_slots[i] = 0;
            return @intCast(i);
        }
    }
    return 0xFFFFFFFF;
}

fn FlsGetValue(idx: u32) callconv(W) usize {
    if (idx < 256 and fls_used[idx]) return fls_slots[idx];
    return 0;
}

fn FlsSetValue(idx: u32, val: usize) callconv(W) u32 {
    if (idx < 256 and fls_used[idx]) {
        fls_slots[idx] = val;
        return 1;
    }
    return 0;
}

fn FlsFree(idx: u32) callconv(W) u32 {
    if (idx < 256) {
        fls_used[idx] = false;
        fls_slots[idx] = 0;
        return 1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// 4. Critical Sections & Synchronization
// ---------------------------------------------------------------------------

fn InitializeCriticalSection(cs: ?*anyopaque) callconv(W) void {
    if (cs) |p| @memset(@as([*]u8, @ptrCast(p))[0..40], 0);
}

fn InitializeCriticalSectionAndSpinCount(cs: ?*anyopaque, count: u32) callconv(W) u32 {
    _ = count;
    InitializeCriticalSection(cs);
    return 1;
}

fn EnterCriticalSection(cs: ?*anyopaque) callconv(W) void {
    _ = cs;
}

fn LeaveCriticalSection(cs: ?*anyopaque) callconv(W) void {
    _ = cs;
}

fn TryEnterCriticalSection(cs: ?*anyopaque) callconv(W) u32 {
    _ = cs;
    return 1;
}

fn DeleteCriticalSection(cs: ?*anyopaque) callconv(W) void {
    _ = cs;
}

fn InitializeSListHead(head: ?*anyopaque) callconv(W) void {
    if (head) |p| @memset(@as([*]u8, @ptrCast(p))[0..16], 0);
}

fn InterlockedPushEntrySList(head: ?*anyopaque, entry: ?*anyopaque) callconv(W) ?*anyopaque {
    _ = head;
    _ = entry;
    return null;
}

fn InterlockedFlushSList(head: ?*anyopaque) callconv(W) ?*anyopaque {
    _ = head;
    return null;
}

fn WaitForSingleObject(h: usize, ms: u32) callconv(W) u32 {
    _ = h;
    _ = ms;
    return 0; // WAIT_OBJECT_0
}

fn WaitForSingleObjectEx(h: usize, ms: u32, alertable: u32) callconv(W) u32 {
    _ = h;
    _ = ms;
    _ = alertable;
    return 0;
}

fn CreateMutexW(sa: ?*anyopaque, initial_owner: u32, name: ?[*:0]const u16) callconv(W) usize {
    _ = sa;
    _ = initial_owner;
    _ = name;
    return 0x2000;
}

// ---------------------------------------------------------------------------
// 5. Clocks, Timing & Calendar
// ---------------------------------------------------------------------------

fn QueryPerformanceCounter(lpCount: ?*i64) callconv(W) u32 {
    if (lpCount) |p| {
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(.MONOTONIC, &ts);
        p.* = @as(i64, ts.sec) * 1_000_000_000 + ts.nsec;
        return 1;
    }
    return 0;
}

fn QueryPerformanceFrequency(lpFreq: ?*i64) callconv(W) u32 {
    if (lpFreq) |p| {
        p.* = 1_000_000_000;
        return 1;
    }
    return 0;
}

fn GetTickCount() callconv(W) u32 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    const ms = (@as(u64, @intCast(ts.sec)) * 1000) + (@as(u64, @intCast(ts.nsec)) / 1_000_000);
    return @intCast(ms & 0xFFFFFFFF);
}

fn GetSystemTimeAsFileTime(lpTime: ?*u64) callconv(W) void {
    if (lpTime) |p| {
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(.REALTIME, &ts);
        const sec = @as(u64, @intCast(ts.sec)) + 11644473600; // 1601 to 1970
        p.* = sec * 10_000_000 + @as(u64, @intCast(ts.nsec)) / 100;
    }
}

const SYSTEMTIME = extern struct {
    wYear: u16,
    wMonth: u16,
    wDayOfWeek: u16,
    wDay: u16,
    wHour: u16,
    wMinute: u16,
    wSecond: u16,
    wMilliseconds: u16,
};

fn FileTimeToSystemTime(lpFileTime: ?*const u64, lpSystemTime: ?*SYSTEMTIME) callconv(W) u32 {
    if (lpFileTime == null or lpSystemTime == null) return 0;
    const ft = lpFileTime.?.*;
    const sec_total = ft / 10_000_000;
    const unix_sec: i64 = if (sec_total >= 11644473600) @intCast(sec_total - 11644473600) else 0;
    const epoch_day = @divFloor(unix_sec, 86400);
    const day_sec = @mod(unix_sec, 86400);

    const days = epoch_day + 719468;
    const era = @divFloor(if (days >= 0) days else days - 146096, 146097);
    const doe = @as(u32, @intCast(days - era * 146097));
    const yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const y = @as(i64, yoe) + era * 400;
    const doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const mp = (5 * doy + 2) / 153;
    const d = doy - (153 * mp + 2) / 5 + 1;
    const m = if (mp < 10) mp + 3 else mp - 9;
    const final_y = if (m <= 2) y + 1 else y;

    lpSystemTime.?.* = .{
        .wYear = @intCast(final_y),
        .wMonth = @intCast(m),
        .wDayOfWeek = @intCast(@mod(epoch_day + 4, 7)),
        .wDay = @intCast(d),
        .wHour = @intCast(@divFloor(day_sec, 3600)),
        .wMinute = @intCast(@divFloor(@mod(day_sec, 3600), 60)),
        .wSecond = @intCast(@mod(day_sec, 60)),
        .wMilliseconds = @intCast((ft % 10_000_000) / 10_000),
    };
    return 1;
}

fn SystemTimeToTzSpecificLocalTime(lpTz: ?*anyopaque, lpUniversal: ?*const SYSTEMTIME, lpLocal: ?*SYSTEMTIME) callconv(W) u32 {
    _ = lpTz;
    if (lpUniversal == null or lpLocal == null) return 0;
    lpLocal.?.* = lpUniversal.?.*;
    return 1;
}

fn SystemTimeToFileTime(lpSystemTime: ?*const SYSTEMTIME, lpFileTime: ?*u64) callconv(W) u32 {
    if (lpSystemTime == null or lpFileTime == null) return 0;
    GetSystemTimeAsFileTime(lpFileTime);
    return 1;
}

fn GetSystemTime(lpSystemTime: ?*SYSTEMTIME) callconv(W) void {
    var ft: u64 = 0;
    GetSystemTimeAsFileTime(&ft);
    _ = FileTimeToSystemTime(&ft, lpSystemTime);
}

fn GetTimeZoneInformation(lpTz: ?[*]u8) callconv(W) u32 {
    if (lpTz) |p| @memset(p[0..172], 0);
    return 0; // TIME_ZONE_ID_UNKNOWN
}

fn Sleep(ms: u32) callconv(W) void {
    const sec: i64 = ms / 1000;
    const nsec: i64 = @as(i64, ms % 1000) * 1_000_000;
    const req = linux.timespec{ .sec = sec, .nsec = nsec };
    _ = linux.nanosleep(&req, null);
}

// ---------------------------------------------------------------------------
// 6. Console, CodePage, Locale & String Mapping
// ---------------------------------------------------------------------------

fn GetConsoleMode(h: usize, mode: ?*u32) callconv(W) u32 {
    _ = h;
    if (mode) |m| {
        m.* = 0x0007; // ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT
        return 1;
    }
    return 0;
}

fn SetConsoleMode(h: usize, mode: u32) callconv(W) u32 {
    _ = h;
    _ = mode;
    return 1;
}

fn GetConsoleOutputCP() callconv(W) u32 {
    return 65001; // CP_UTF8
}

fn GetConsoleCP() callconv(W) u32 {
    return 65001;
}

fn GetACP() callconv(W) u32 {
    return 65001;
}

fn GetOEMCP() callconv(W) u32 {
    return 65001;
}

fn IsValidCodePage(cp: u32) callconv(W) u32 {
    _ = cp;
    return 1;
}

fn GetCPInfo(cp: u32, lpInfo: ?[*]u8) callconv(W) u32 {
    _ = cp;
    if (lpInfo) |p| @memset(p[0..18], 0);
    return 1;
}

fn SetStdHandle(n: u32, h: usize) callconv(W) u32 {
    _ = n;
    _ = h;
    return 1;
}

fn SetConsoleCtrlHandler(handler: ?*anyopaque, add: u32) callconv(W) u32 {
    _ = handler;
    _ = add;
    return 1;
}

fn GetConsoleScreenBufferInfo(h: usize, info: ?[*]u8) callconv(W) u32 {
    _ = h;
    if (info) |p| @memset(p[0..22], 0);
    return 1;
}

fn SetConsoleTextAttribute(h: usize, attr: u16) callconv(W) u32 {
    _ = h;
    _ = attr;
    return 1;
}

fn GetUserDefaultLCID() callconv(W) u32 {
    return 0x0409; // en-US
}

fn IsValidLocale(lcid: u32, flags: u32) callconv(W) u32 {
    _ = lcid;
    _ = flags;
    return 1;
}

fn GetLocaleInfoW(lcid: u32, lctype: u32, data: ?[*]u16, cch: i32) callconv(W) i32 {
    _ = lcid;
    _ = lctype;
    if (cch > 0 and data != null) {
        data.?[0] = 0;
        return 1;
    }
    return 1;
}

fn EnumSystemLocalesW(proc: ?*anyopaque, flags: u32) callconv(W) u32 {
    _ = proc;
    _ = flags;
    return 1;
}

fn GetDateFormatW(lcid: u32, flags: u32, date: ?*const SYSTEMTIME, fmt: ?[*:0]const u16, str: ?[*]u16, cch: i32) callconv(W) i32 {
    _ = lcid;
    _ = flags;
    _ = date;
    _ = fmt;
    if (cch > 0 and str != null) {
        str.?[0] = 0;
        return 1;
    }
    return 1;
}

fn GetTimeFormatW(lcid: u32, flags: u32, time: ?*const SYSTEMTIME, fmt: ?[*:0]const u16, str: ?[*]u16, cch: i32) callconv(W) i32 {
    _ = lcid;
    _ = flags;
    _ = time;
    _ = fmt;
    if (cch > 0 and str != null) {
        str.?[0] = 0;
        return 1;
    }
    return 1;
}

fn CompareStringW(lcid: u32, flags: u32, s1: ?[*]const u16, cch1: i32, s2: ?[*]const u16, cch2: i32) callconv(W) i32 {
    _ = lcid;
    _ = flags;
    if (s1 == null or s2 == null) return 2; // CSTR_EQUAL
    const len1: usize = if (cch1 >= 0) @intCast(cch1) else blk: {
        var k: usize = 0;
        while (s1.?[k] != 0) k += 1;
        break :blk k;
    };
    const len2: usize = if (cch2 >= 0) @intCast(cch2) else blk: {
        var k: usize = 0;
        while (s2.?[k] != 0) k += 1;
        break :blk k;
    };
    const min_len = @min(len1, len2);
    for (0..min_len) |i| {
        if (s1.?[i] < s2.?[i]) return 1; // CSTR_LESS_THAN
        if (s1.?[i] > s2.?[i]) return 3; // CSTR_GREATER_THAN
    }
    if (len1 < len2) return 1;
    if (len1 > len2) return 3;
    return 2; // CSTR_EQUAL
}

fn LCMapStringW(lcid: u32, flags: u32, src: ?[*]const u16, cch_src: i32, dest: ?[*]u16, cch_dest: i32) callconv(W) i32 {
    _ = lcid;
    _ = flags;
    if (cch_src <= 0 or src == null) return 0;
    const n: usize = @intCast(cch_src);
    if (cch_dest == 0 or dest == null) return cch_src;
    const copy_n = @min(n, @as(usize, @intCast(cch_dest)));
    @memcpy(dest.?[0..copy_n], src.?[0..copy_n]);
    return @intCast(copy_n);
}

fn MultiByteToWideChar(cp: u32, flags: u32, mb: ?[*]const u8, cb_mb: i32, wc: ?[*]u16, cch_wc: i32) callconv(W) i32 {
    _ = cp;
    _ = flags;
    if (mb == null or cb_mb == 0) return 0;
    const in_len: usize = if (cb_mb > 0) @intCast(cb_mb) else blk: {
        var k: usize = 0;
        while (mb.?[k] != 0) k += 1;
        break :blk k + 1;
    };
    if (cch_wc == 0 or wc == null) return @intCast(in_len);
    const out_cap: usize = @intCast(cch_wc);
    var in_i: usize = 0;
    var out_i: usize = 0;
    while (in_i < in_len and out_i < out_cap) {
        wc.?[out_i] = @as(u16, mb.?[in_i]);
        in_i += 1;
        out_i += 1;
    }
    return @intCast(out_i);
}

fn WideCharToMultiByte(cp: u32, flags: u32, wc: ?[*]const u16, cch_wc: i32, mb: ?[*]u8, cb_mb: i32, def: ?[*]const u8, used_def: ?*i32) callconv(W) i32 {
    _ = cp;
    _ = flags;
    _ = def;
    if (used_def) |u| u.* = 0;
    if (wc == null or cch_wc == 0) return 0;
    const in_len: usize = if (cch_wc > 0) @intCast(cch_wc) else blk: {
        var k: usize = 0;
        while (wc.?[k] != 0) k += 1;
        break :blk k + 1;
    };
    if (cb_mb == 0 or mb == null) return @intCast(in_len);
    const out_cap: usize = @intCast(cb_mb);
    var in_i: usize = 0;
    var out_i: usize = 0;
    while (in_i < in_len and out_i < out_cap) {
        mb.?[out_i] = @intCast(wc.?[in_i] & 0xFF);
        in_i += 1;
        out_i += 1;
    }
    return @intCast(out_i);
}

fn GetStringTypeW(flags: u32, src: ?[*]const u16, cch: i32, chartype: ?[*]u16) callconv(W) u32 {
    _ = flags;
    _ = src;
    if (chartype != null and cch > 0) {
        @memset(chartype.?[0..@intCast(cch)], 0);
        return 1;
    }
    return 1;
}

fn FormatMessageW(...) callconv(W) u32 {
    return 0;
}

fn FormatMessageA(...) callconv(W) u32 {
    return 0;
}

// ---------------------------------------------------------------------------
// 7. Modules, Files & Handles
// ---------------------------------------------------------------------------

fn GetModuleHandleExW(flags: u32, name: ?[*:0]const u16, ph: ?*usize) callconv(W) u32 {
    _ = flags;
    if (name == null) {
        if (ph) |p| p.* = image_base_addr;
        return 1;
    }
    return 0;
}

fn GetModuleFileNameW(h: usize, buf: ?[*]u16, n: u32) callconv(W) u32 {
    _ = h;
    if (buf != null and n > 0) {
        buf.?[0] = 0;
        return 0;
    }
    return 0;
}

fn LoadLibraryExW(name: ?[*:0]const u16, file: usize, flags: u32) callconv(W) usize {
    _ = name;
    _ = file;
    _ = flags;
    return 0;
}

fn LoadLibraryW(name: ?[*:0]const u16) callconv(W) usize {
    _ = name;
    return 0;
}

fn LoadLibraryA(name: ?[*:0]const u8) callconv(W) usize {
    _ = name;
    return 0;
}

fn FreeLibrary(h: usize) callconv(W) u32 {
    _ = h;
    return 1;
}

fn GetProcAddress(h: usize, name: ?[*:0]const u8) callconv(W) usize {
    _ = h;
    _ = name;
    return 0;
}

fn GetStartupInfoW(si: ?[*]u8) callconv(W) void {
    if (si) |p| @memset(p[0..68], 0);
}

fn FlushFileBuffers(h: usize) callconv(W) u32 {
    _ = h;
    return 1;
}

fn SetEndOfFile(h: usize) callconv(W) u32 {
    _ = h;
    return 1;
}

fn SetFilePointerEx(h: usize, dist: i64, new_pos: ?*i64, method: u32) callconv(W) u32 {
    const fd: i32 = if (h == 0xFFFFFFF6) 0 else if (h == 0xFFFFFFF5) 1 else if (h == 0xFFFFFFF4) 2 else return 0;
    const whence: u32 = switch (method) {
        0 => 0, // SEEK_SET
        1 => 1, // SEEK_CUR
        2 => 2, // SEEK_END
        else => return 0,
    };
    const rc = linux.lseek(fd, dist, whence);
    if (linux.errno(rc) != .SUCCESS) return 0;
    if (new_pos) |p| p.* = @bitCast(rc);
    return 1;
}

fn SetFilePointer(h: usize, dist: i32, dist_high: ?*i32, method: u32) callconv(W) u32 {
    var new_pos: i64 = 0;
    const ok = SetFilePointerEx(h, @intCast(dist), &new_pos, method);
    if (ok == 0) return 0xFFFFFFFF;
    if (dist_high) |dh| dh.* = @intCast(new_pos >> 32);
    return @intCast(new_pos & 0xFFFFFFFF);
}

fn GetFileSize(h: usize, high: ?*u32) callconv(W) u32 {
    _ = h;
    if (high) |hi| hi.* = 0;
    return 0;
}

fn GetFileSizeEx(h: usize, size: ?*i64) callconv(W) u32 {
    _ = h;
    if (size) |s| s.* = 0;
    return 1;
}

fn GetFileType(h: usize) callconv(W) u32 {
    return switch (h) {
        0xFFFFFFF6, 0xFFFFFFF5, 0xFFFFFFF4 => 0x0002, // FILE_TYPE_CHAR
        else => 0x0001, // FILE_TYPE_DISK
    };
}

fn CloseHandle(h: usize) callconv(W) u32 {
    _ = h;
    return 1;
}

fn DuplicateHandle(src_proc: usize, src_h: usize, tgt_proc: usize, tgt_h: ?*usize, access: u32, inherit: u32, options: u32) callconv(W) u32 {
    _ = src_proc;
    _ = tgt_proc;
    _ = access;
    _ = inherit;
    _ = options;
    if (tgt_h) |t| t.* = src_h;
    return 1;
}

const empty_cmd_a: [1:0]u8 = .{0};
const empty_cmd_w: [1:0]u16 = .{0};
const empty_env_w: [2]u16 = .{ 0, 0 };

fn GetCommandLineA() callconv(W) ?[*:0]const u8 {
    return &empty_cmd_a;
}

fn GetCommandLineW() callconv(W) ?[*:0]const u16 {
    return &empty_cmd_w;
}

fn GetEnvironmentStringsW() callconv(W) ?[*]const u16 {
    return &empty_env_w;
}

fn FreeEnvironmentStringsW(p: ?[*]const u16) callconv(W) u32 {
    _ = p;
    return 1;
}

fn OutputDebugStringA(str: ?[*:0]const u8) callconv(W) void {
    _ = str;
}

fn OutputDebugStringW(str: ?[*:0]const u16) callconv(W) void {
    _ = str;
}

fn AreFileApisANSI() callconv(W) u32 {
    return 1;
}

fn GetSystemInfo(si: ?[*]u8) callconv(W) void {
    if (si) |p| {
        @memset(p[0..48], 0);
        // Page size 4096
        std.mem.writeInt(u32, p[4..8], 4096, .little);
        // Number of processors = 1
        std.mem.writeInt(u32, p[32..36], 1, .little);
    }
}

// ---------------------------------------------------------------------------
// 7b. Extended Console, File, Memory-Mapped & Process APIs
// ---------------------------------------------------------------------------

const INVALID_HANDLE: usize = std.math.maxInt(usize);

fn ReadConsoleW(h: usize, buf: ?[*]u16, n: u32, read: ?*u32, ctrl: ?*anyopaque) callconv(W) u32 {
    _ = h;
    _ = ctrl;
    if (buf == null or n == 0) {
        if (read) |r| r.* = 0;
        return 1;
    }
    var byte_buf: [256]u8 = undefined;
    const to_read = @min(n, 256);
    const rc = linux.read(0, &byte_buf, to_read);
    if (linux.errno(rc) != .SUCCESS) {
        if (read) |r| r.* = 0;
        return 0;
    }
    const got: usize = @intCast(rc);
    for (0..got) |i| buf.?[i] = byte_buf[i];
    if (read) |r| r.* = @intCast(got);
    return 1;
}

fn WriteConsoleW(h: usize, buf: ?[*]const u16, n: u32, written: ?*u32, res: ?*anyopaque) callconv(W) u32 {
    _ = res;
    if (buf == null or n == 0) {
        if (written) |w| w.* = 0;
        return 1;
    }
    const fd: i32 = if (h == 0xFFFFFFF4) 2 else 1;
    var byte_buf: [512]u8 = undefined;
    var i: usize = 0;
    var done: usize = 0;
    while (i < n) {
        var chunk: usize = 0;
        while (i < n and chunk < 512) : ({
            i += 1;
            chunk += 1;
        }) {
            byte_buf[chunk] = @intCast(buf.?[i] & 0xFF);
        }
        const rc = linux.write(fd, &byte_buf, chunk);
        if (linux.errno(rc) != .SUCCESS) break;
        done += @intCast(rc);
    }
    if (written) |w| w.* = @intCast(done);
    return 1;
}

fn CreateFileW(name: ?[*:0]const u16, access: u32, share: u32, sa: ?*anyopaque, disp: u32, flags: u32, template: usize) callconv(W) usize {
    _ = share;
    _ = sa;
    _ = flags;
    _ = template;
    if (name == null) return INVALID_HANDLE;
    var path_buf: [512:0]u8 = undefined;
    var len: usize = 0;
    while (name.?[len] != 0 and len < 511) : (len += 1) {
        const c = name.?[len];
        path_buf[len] = if (c == '\\') '/' else @intCast(c & 0xFF);
    }
    path_buf[len] = 0;

    var open_flags = linux.O{};
    if (access & 0x40000000 != 0 and access & 0x80000000 != 0) {
        open_flags.ACCMODE = .RDWR;
    } else if (access & 0x40000000 != 0) {
        open_flags.ACCMODE = .WRONLY;
    } else {
        open_flags.ACCMODE = .RDONLY;
    }
    if (disp == 2) {
        open_flags.CREAT = true;
        open_flags.TRUNC = true;
    } else if (disp == 4) {
        open_flags.CREAT = true;
    }

    const rc = linux.open(&path_buf, open_flags, 0o666);
    if (linux.errno(rc) != .SUCCESS) return INVALID_HANDLE;
    return @as(usize, @intCast(rc)) + 0x1000;
}

fn CreateFileA(name: ?[*:0]const u8, access: u32, share: u32, sa: ?*anyopaque, disp: u32, flags: u32, template: usize) callconv(W) usize {
    _ = share;
    _ = sa;
    _ = flags;
    _ = template;
    if (name == null) return INVALID_HANDLE;
    var path_buf: [512:0]u8 = undefined;
    var len: usize = 0;
    while (name.?[len] != 0 and len < 511) : (len += 1) {
        const c = name.?[len];
        path_buf[len] = if (c == '\\') '/' else c;
    }
    path_buf[len] = 0;

    var open_flags = linux.O{};
    if (access & 0x40000000 != 0 and access & 0x80000000 != 0) {
        open_flags.ACCMODE = .RDWR;
    } else if (access & 0x40000000 != 0) {
        open_flags.ACCMODE = .WRONLY;
    } else {
        open_flags.ACCMODE = .RDONLY;
    }
    if (disp == 2) {
        open_flags.CREAT = true;
        open_flags.TRUNC = true;
    } else if (disp == 4) {
        open_flags.CREAT = true;
    }

    const rc = linux.open(&path_buf, open_flags, 0o666);
    if (linux.errno(rc) != .SUCCESS) return INVALID_HANDLE;
    return @as(usize, @intCast(rc)) + 0x1000;
}

fn DeleteFileW(name: ?[*:0]const u16) callconv(W) u32 {
    if (name == null) return 0;
    var path_buf: [512:0]u8 = undefined;
    var len: usize = 0;
    while (name.?[len] != 0 and len < 511) : (len += 1) {
        path_buf[len] = if (name.?[len] == '\\') '/' else @intCast(name.?[len] & 0xFF);
    }
    path_buf[len] = 0;
    const rc = linux.unlink(&path_buf);
    return if (linux.errno(rc) == .SUCCESS) 1 else 0;
}

fn DeleteFileA(name: ?[*:0]const u8) callconv(W) u32 {
    if (name == null) return 0;
    const rc = linux.unlink(name.?);
    return if (linux.errno(rc) == .SUCCESS) 1 else 0;
}

fn SetFileTime(h: usize, ctime: ?*const u64, atime: ?*const u64, mtime: ?*const u64) callconv(W) u32 {
    _ = h;
    _ = ctime;
    _ = atime;
    _ = mtime;
    return 1;
}

fn SetFileAttributesW(name: ?[*:0]const u16, attr: u32) callconv(W) u32 {
    _ = name;
    _ = attr;
    return 1;
}

fn GetFileAttributesW(name: ?[*:0]const u16) callconv(W) u32 {
    _ = name;
    return 0x00000080; // FILE_ATTRIBUTE_NORMAL
}

fn GetFileAttributesA(name: ?[*:0]const u8) callconv(W) u32 {
    _ = name;
    return 0x00000080; // FILE_ATTRIBUTE_NORMAL
}

fn GetFileAttributesExW(name: ?[*:0]const u16, level: u32, info: ?[*]u8) callconv(W) u32 {
    _ = name;
    _ = level;
    if (info) |p| {
        @memset(p[0..36], 0);
        std.mem.writeInt(u32, p[0..4], 0x00000080, .little); // FILE_ATTRIBUTE_NORMAL
    }
    return 1;
}

fn GetFileInformationByHandle(h: usize, info: ?[*]u8) callconv(W) u32 {
    _ = h;
    if (info) |p| {
        @memset(p[0..52], 0);
        std.mem.writeInt(u32, p[0..4], 0x00000080, .little); // FILE_ATTRIBUTE_NORMAL
        std.mem.writeInt(u32, p[28..32], 1, .little); // VolumeSerialNumber = 1
        std.mem.writeInt(u32, p[32..36], 1, .little); // nNumberOfLinks = 1
    }
    return 1;
}

fn LockFile(h: usize, off_l: u32, off_h: u32, len_l: u32, len_h: u32) callconv(W) u32 {
    _ = h;
    _ = off_l;
    _ = off_h;
    _ = len_l;
    _ = len_h;
    return 1;
}

fn UnlockFile(h: usize, off_l: u32, off_h: u32, len_l: u32, len_h: u32) callconv(W) u32 {
    _ = h;
    _ = off_l;
    _ = off_h;
    _ = len_l;
    _ = len_h;
    return 1;
}

fn LockFileEx(h: usize, flags: u32, res: u32, len_l: u32, len_h: u32, ov: ?*anyopaque) callconv(W) u32 {
    _ = h;
    _ = flags;
    _ = res;
    _ = len_l;
    _ = len_h;
    _ = ov;
    return 1;
}

fn UnlockFileEx(h: usize, res: u32, len_l: u32, len_h: u32, ov: ?*anyopaque) callconv(W) u32 {
    _ = h;
    _ = res;
    _ = len_l;
    _ = len_h;
    _ = ov;
    return 1;
}

fn GetCurrentDirectoryW(n: u32, buf: ?[*]u16) callconv(W) u32 {
    if (buf != null and n >= 3) {
        buf.?[0] = 'C';
        buf.?[1] = ':';
        buf.?[2] = '\\';
        buf.?[3] = 0;
        return 3;
    }
    return 3;
}

fn SetCurrentDirectoryW(path: ?[*:0]const u16) callconv(W) u32 {
    _ = path;
    return 1;
}

fn CreateDirectoryW(path: ?[*:0]const u16, sa: ?*anyopaque) callconv(W) u32 {
    _ = sa;
    if (path == null) return 0;
    var path_buf: [512:0]u8 = undefined;
    var len: usize = 0;
    while (path.?[len] != 0 and len < 511) : (len += 1) {
        path_buf[len] = if (path.?[len] == '\\') '/' else @intCast(path.?[len] & 0xFF);
    }
    path_buf[len] = 0;
    const rc = linux.mkdir(&path_buf, 0o755);
    return if (linux.errno(rc) == .SUCCESS) 1 else 0;
}

fn GetFullPathNameW(file: ?[*:0]const u16, n: u32, buf: ?[*]u16, file_part: ?*?[*]u16) callconv(W) u32 {
    if (file == null) return 0;
    var len: usize = 0;
    while (file.?[len] != 0) : (len += 1) {}
    if (buf != null and n > len) {
        for (0..len) |i| buf.?[i] = file.?[i];
        buf.?[len] = 0;
        if (file_part) |fp| fp.* = buf;
    }
    return @intCast(len);
}

fn GetFullPathNameA(file: ?[*:0]const u8, n: u32, buf: ?[*]u8, file_part: ?*?[*]u8) callconv(W) u32 {
    if (file == null) return 0;
    var len: usize = 0;
    while (file.?[len] != 0) : (len += 1) {}
    if (buf != null and n > len) {
        for (0..len) |i| buf.?[i] = file.?[i];
        buf.?[len] = 0;
        if (file_part) |fp| fp.* = buf;
    }
    return @intCast(len);
}

fn GetTempPathW(n: u32, buf: ?[*]u16) callconv(W) u32 {
    const tmp = [_]u16{ 'C', ':', '\\', 'T', 'e', 'm', 'p', '\\', 0 };
    if (buf != null and n >= tmp.len) {
        for (tmp, 0..) |c, i| buf.?[i] = c;
        return tmp.len - 1;
    }
    return tmp.len - 1;
}

fn GetTempPathA(n: u32, buf: ?[*]u8) callconv(W) u32 {
    const tmp = "/tmp/";
    if (buf != null and n >= tmp.len) {
        @memcpy(buf.?[0..tmp.len], tmp);
        buf.?[tmp.len] = 0;
        return tmp.len;
    }
    return tmp.len;
}

fn GetDriveTypeW(root: ?[*:0]const u16) callconv(W) u32 {
    _ = root;
    return 3; // DRIVE_FIXED
}

fn GetDiskFreeSpaceW(root: ?[*:0]const u16, spc: ?*u32, bps: ?*u32, free_c: ?*u32, total_c: ?*u32) callconv(W) u32 {
    _ = root;
    if (spc) |p| p.* = 8;
    if (bps) |p| p.* = 512;
    if (free_c) |p| p.* = 1_000_000;
    if (total_c) |p| p.* = 2_000_000;
    return 1;
}

fn GetDiskFreeSpaceA(root: ?[*:0]const u8, spc: ?*u32, bps: ?*u32, free_c: ?*u32, total_c: ?*u32) callconv(W) u32 {
    _ = root;
    if (spc) |p| p.* = 8;
    if (bps) |p| p.* = 512;
    if (free_c) |p| p.* = 1_000_000;
    if (total_c) |p| p.* = 2_000_000;
    return 1;
}

fn FindFirstFileW(name: ?[*:0]const u16, data: ?[*]u8) callconv(W) usize {
    _ = name;
    _ = data;
    return INVALID_HANDLE;
}

fn FindFirstFileExW(name: ?[*:0]const u16, level: u32, data: ?[*]u8, op: u32, filter: ?*anyopaque, flags: u32) callconv(W) usize {
    _ = name;
    _ = level;
    _ = data;
    _ = op;
    _ = filter;
    _ = flags;
    return INVALID_HANDLE;
}

fn FindNextFileW(h: usize, data: ?[*]u8) callconv(W) u32 {
    _ = h;
    _ = data;
    return 0;
}

fn FindClose(h: usize) callconv(W) u32 {
    _ = h;
    return 1;
}

fn CreateFileMappingW(file: usize, sa: ?*anyopaque, prot: u32, max_h: u32, max_l: u32, name: ?[*:0]const u16) callconv(W) usize {
    _ = file;
    _ = sa;
    _ = prot;
    _ = max_h;
    _ = max_l;
    _ = name;
    return 0x3000;
}

fn MapViewOfFile(mapping: usize, access: u32, off_h: u32, off_l: u32, bytes: usize) callconv(W) ?[*]u8 {
    _ = mapping;
    _ = access;
    _ = off_h;
    _ = off_l;
    const sz = if (bytes == 0) 65536 else std.mem.alignForward(usize, bytes, 4096);
    const mrc = linux.mmap(null, sz, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
    if (linux.errno(mrc) != .SUCCESS) return null;
    return @ptrFromInt(mrc);
}

fn UnmapViewOfFile(ptr: ?[*]const u8) callconv(W) u32 {
    _ = ptr;
    return 1;
}

fn FlushViewOfFile(ptr: ?[*]const u8, bytes: usize) callconv(W) u32 {
    _ = ptr;
    _ = bytes;
    return 1;
}

fn CreatePipe(read_h: ?*usize, write_h: ?*usize, sa: ?*anyopaque, sz: u32) callconv(W) u32 {
    _ = sa;
    _ = sz;
    var fds: [2]i32 = undefined;
    const rc = linux.pipe2(&fds, .{});
    if (linux.errno(rc) != .SUCCESS) return 0;
    if (read_h) |r| r.* = @as(usize, @intCast(fds[0])) + 0x1000;
    if (write_h) |w| w.* = @as(usize, @intCast(fds[1])) + 0x1000;
    return 1;
}

fn PeekNamedPipe(pipe: usize, buf: ?[*]u8, sz: u32, read: ?*u32, avail: ?*u32, left: ?*u32) callconv(W) u32 {
    _ = pipe;
    _ = buf;
    _ = sz;
    if (read) |r| r.* = 0;
    if (avail) |a| a.* = 0;
    if (left) |l| l.* = 0;
    return 1;
}

fn CreateProcessW(...) callconv(W) u32 {
    return 0;
}

fn GetExitCodeProcess(proc: usize, exit_code: ?*u32) callconv(W) u32 {
    _ = proc;
    if (exit_code) |c| c.* = 0;
    return 1;
}

fn CreateThread(sa: ?*anyopaque, stack_sz: usize, start: usize, param: usize, flags: u32, tid: ?*u32) callconv(W) usize {
    _ = sa;
    _ = stack_sz;
    _ = start;
    _ = param;
    _ = flags;
    if (tid) |t| t.* = 1001;
    return 0x4000;
}

fn ResumeThread(thread: usize) callconv(W) u32 {
    _ = thread;
    return 1;
}

fn GetEnvironmentVariableA(name: ?[*:0]const u8, buf: ?[*]u8, sz: u32) callconv(W) u32 {
    _ = name;
    _ = buf;
    _ = sz;
    return 0;
}

fn SetEnvironmentVariableW(name: ?[*:0]const u16, val: ?[*:0]const u16) callconv(W) u32 {
    _ = name;
    _ = val;
    return 1;
}

fn DebugBreak() callconv(W) void {}

// ---------------------------------------------------------------------------
// 8. Lookup Dispatch Table
// ---------------------------------------------------------------------------

pub fn lookup(name: []const u8) ?usize {
    // Process / Thread / Diagnostics
    if (std.mem.eql(u8, name, "GetCurrentProcess")) return @intFromPtr(&GetCurrentProcess);
    if (std.mem.eql(u8, name, "GetCurrentThread")) return @intFromPtr(&GetCurrentThread);
    if (std.mem.eql(u8, name, "GetCurrentThreadId")) return @intFromPtr(&GetCurrentThreadId);
    if (std.mem.eql(u8, name, "IsDebuggerPresent")) return @intFromPtr(&IsDebuggerPresent);
    if (std.mem.eql(u8, name, "IsProcessorFeaturePresent")) return @intFromPtr(&IsProcessorFeaturePresent);
    if (std.mem.eql(u8, name, "TerminateProcess")) return @intFromPtr(&TerminateProcess);
    if (std.mem.eql(u8, name, "ExitThread")) return @intFromPtr(&ExitThread);
    if (std.mem.eql(u8, name, "FreeLibraryAndExitThread")) return @intFromPtr(&FreeLibraryAndExitThread);
    if (std.mem.eql(u8, name, "SetUnhandledExceptionFilter")) return @intFromPtr(&SetUnhandledExceptionFilter);
    if (std.mem.eql(u8, name, "UnhandledExceptionFilter")) return @intFromPtr(&UnhandledExceptionFilter);
    if (std.mem.eql(u8, name, "RaiseException")) return @intFromPtr(&RaiseException);
    if (std.mem.eql(u8, name, "RtlPcToFileHeader")) return @intFromPtr(&RtlPcToFileHeader);
    if (std.mem.eql(u8, name, "RtlUnwind")) return @intFromPtr(&RtlUnwind);
    if (std.mem.eql(u8, name, "RtlUnwindEx")) return @intFromPtr(&RtlUnwindEx);
    if (std.mem.eql(u8, name, "RtlCaptureContext")) return @intFromPtr(&RtlCaptureContext);
    if (std.mem.eql(u8, name, "RtlLookupFunctionEntry")) return @intFromPtr(&RtlLookupFunctionEntry);
    if (std.mem.eql(u8, name, "RtlVirtualUnwind")) return @intFromPtr(&RtlVirtualUnwind);
    if (std.mem.eql(u8, name, "EncodePointer")) return @intFromPtr(&EncodePointer);
    if (std.mem.eql(u8, name, "DecodePointer")) return @intFromPtr(&DecodePointer);

    // Heap
    if (std.mem.eql(u8, name, "GetProcessHeap")) return @intFromPtr(&GetProcessHeap);
    if (std.mem.eql(u8, name, "HeapAlloc")) return @intFromPtr(&HeapAlloc);
    if (std.mem.eql(u8, name, "HeapFree")) return @intFromPtr(&HeapFree);
    if (std.mem.eql(u8, name, "HeapReAlloc")) return @intFromPtr(&HeapReAlloc);
    if (std.mem.eql(u8, name, "HeapSize")) return @intFromPtr(&HeapSize);
    if (std.mem.eql(u8, name, "HeapValidate")) return @intFromPtr(&HeapValidate);
    if (std.mem.eql(u8, name, "HeapCompact")) return @intFromPtr(&HeapCompact);
    if (std.mem.eql(u8, name, "HeapCreate")) return @intFromPtr(&HeapCreate);
    if (std.mem.eql(u8, name, "HeapDestroy")) return @intFromPtr(&HeapDestroy);
    if (std.mem.eql(u8, name, "LocalFree")) return @intFromPtr(&LocalFree);

    // TLS & FLS
    if (std.mem.eql(u8, name, "TlsAlloc")) return @intFromPtr(&TlsAlloc);
    if (std.mem.eql(u8, name, "TlsGetValue")) return @intFromPtr(&TlsGetValue);
    if (std.mem.eql(u8, name, "TlsSetValue")) return @intFromPtr(&TlsSetValue);
    if (std.mem.eql(u8, name, "TlsFree")) return @intFromPtr(&TlsFree);
    if (std.mem.eql(u8, name, "FlsAlloc")) return @intFromPtr(&FlsAlloc);
    if (std.mem.eql(u8, name, "FlsGetValue")) return @intFromPtr(&FlsGetValue);
    if (std.mem.eql(u8, name, "FlsSetValue")) return @intFromPtr(&FlsSetValue);
    if (std.mem.eql(u8, name, "FlsFree")) return @intFromPtr(&FlsFree);

    // Critical Sections & Sync
    if (std.mem.eql(u8, name, "InitializeCriticalSection")) return @intFromPtr(&InitializeCriticalSection);
    if (std.mem.eql(u8, name, "InitializeCriticalSectionAndSpinCount")) return @intFromPtr(&InitializeCriticalSectionAndSpinCount);
    if (std.mem.eql(u8, name, "EnterCriticalSection")) return @intFromPtr(&EnterCriticalSection);
    if (std.mem.eql(u8, name, "LeaveCriticalSection")) return @intFromPtr(&LeaveCriticalSection);
    if (std.mem.eql(u8, name, "TryEnterCriticalSection")) return @intFromPtr(&TryEnterCriticalSection);
    if (std.mem.eql(u8, name, "DeleteCriticalSection")) return @intFromPtr(&DeleteCriticalSection);
    if (std.mem.eql(u8, name, "InitializeSListHead")) return @intFromPtr(&InitializeSListHead);
    if (std.mem.eql(u8, name, "InterlockedPushEntrySList")) return @intFromPtr(&InterlockedPushEntrySList);
    if (std.mem.eql(u8, name, "InterlockedFlushSList")) return @intFromPtr(&InterlockedFlushSList);
    if (std.mem.eql(u8, name, "WaitForSingleObject")) return @intFromPtr(&WaitForSingleObject);
    if (std.mem.eql(u8, name, "WaitForSingleObjectEx")) return @intFromPtr(&WaitForSingleObjectEx);
    if (std.mem.eql(u8, name, "CreateMutexW")) return @intFromPtr(&CreateMutexW);

    // Clocks & Timing
    if (std.mem.eql(u8, name, "QueryPerformanceCounter")) return @intFromPtr(&QueryPerformanceCounter);
    if (std.mem.eql(u8, name, "QueryPerformanceFrequency")) return @intFromPtr(&QueryPerformanceFrequency);
    if (std.mem.eql(u8, name, "GetTickCount")) return @intFromPtr(&GetTickCount);
    if (std.mem.eql(u8, name, "GetSystemTimeAsFileTime")) return @intFromPtr(&GetSystemTimeAsFileTime);
    if (std.mem.eql(u8, name, "FileTimeToSystemTime")) return @intFromPtr(&FileTimeToSystemTime);
    if (std.mem.eql(u8, name, "SystemTimeToTzSpecificLocalTime")) return @intFromPtr(&SystemTimeToTzSpecificLocalTime);
    if (std.mem.eql(u8, name, "SystemTimeToFileTime")) return @intFromPtr(&SystemTimeToFileTime);
    if (std.mem.eql(u8, name, "GetSystemTime")) return @intFromPtr(&GetSystemTime);
    if (std.mem.eql(u8, name, "GetTimeZoneInformation")) return @intFromPtr(&GetTimeZoneInformation);
    if (std.mem.eql(u8, name, "Sleep")) return @intFromPtr(&Sleep);

    // Console & Locale
    if (std.mem.eql(u8, name, "GetConsoleMode")) return @intFromPtr(&GetConsoleMode);
    if (std.mem.eql(u8, name, "SetConsoleMode")) return @intFromPtr(&SetConsoleMode);
    if (std.mem.eql(u8, name, "GetConsoleOutputCP")) return @intFromPtr(&GetConsoleOutputCP);
    if (std.mem.eql(u8, name, "GetConsoleCP")) return @intFromPtr(&GetConsoleCP);
    if (std.mem.eql(u8, name, "GetACP")) return @intFromPtr(&GetACP);
    if (std.mem.eql(u8, name, "GetOEMCP")) return @intFromPtr(&GetOEMCP);
    if (std.mem.eql(u8, name, "IsValidCodePage")) return @intFromPtr(&IsValidCodePage);
    if (std.mem.eql(u8, name, "GetCPInfo")) return @intFromPtr(&GetCPInfo);
    if (std.mem.eql(u8, name, "SetStdHandle")) return @intFromPtr(&SetStdHandle);
    if (std.mem.eql(u8, name, "SetConsoleCtrlHandler")) return @intFromPtr(&SetConsoleCtrlHandler);
    if (std.mem.eql(u8, name, "GetConsoleScreenBufferInfo")) return @intFromPtr(&GetConsoleScreenBufferInfo);
    if (std.mem.eql(u8, name, "SetConsoleTextAttribute")) return @intFromPtr(&SetConsoleTextAttribute);
    if (std.mem.eql(u8, name, "GetUserDefaultLCID")) return @intFromPtr(&GetUserDefaultLCID);
    if (std.mem.eql(u8, name, "IsValidLocale")) return @intFromPtr(&IsValidLocale);
    if (std.mem.eql(u8, name, "GetLocaleInfoW")) return @intFromPtr(&GetLocaleInfoW);
    if (std.mem.eql(u8, name, "EnumSystemLocalesW")) return @intFromPtr(&EnumSystemLocalesW);
    if (std.mem.eql(u8, name, "GetDateFormatW")) return @intFromPtr(&GetDateFormatW);
    if (std.mem.eql(u8, name, "GetTimeFormatW")) return @intFromPtr(&GetTimeFormatW);
    if (std.mem.eql(u8, name, "CompareStringW")) return @intFromPtr(&CompareStringW);
    if (std.mem.eql(u8, name, "LCMapStringW")) return @intFromPtr(&LCMapStringW);
    if (std.mem.eql(u8, name, "MultiByteToWideChar")) return @intFromPtr(&MultiByteToWideChar);
    if (std.mem.eql(u8, name, "WideCharToMultiByte")) return @intFromPtr(&WideCharToMultiByte);
    if (std.mem.eql(u8, name, "GetStringTypeW")) return @intFromPtr(&GetStringTypeW);
    if (std.mem.eql(u8, name, "FormatMessageW")) return @intFromPtr(&FormatMessageW);
    if (std.mem.eql(u8, name, "FormatMessageA")) return @intFromPtr(&FormatMessageA);

    // Modules & Files
    if (std.mem.eql(u8, name, "GetModuleHandleExW")) return @intFromPtr(&GetModuleHandleExW);
    if (std.mem.eql(u8, name, "GetModuleFileNameW")) return @intFromPtr(&GetModuleFileNameW);
    if (std.mem.eql(u8, name, "LoadLibraryExW")) return @intFromPtr(&LoadLibraryExW);
    if (std.mem.eql(u8, name, "LoadLibraryW")) return @intFromPtr(&LoadLibraryW);
    if (std.mem.eql(u8, name, "LoadLibraryA")) return @intFromPtr(&LoadLibraryA);
    if (std.mem.eql(u8, name, "FreeLibrary")) return @intFromPtr(&FreeLibrary);
    if (std.mem.eql(u8, name, "GetProcAddress")) return @intFromPtr(&GetProcAddress);
    if (std.mem.eql(u8, name, "GetStartupInfoW")) return @intFromPtr(&GetStartupInfoW);
    if (std.mem.eql(u8, name, "FlushFileBuffers")) return @intFromPtr(&FlushFileBuffers);
    if (std.mem.eql(u8, name, "SetEndOfFile")) return @intFromPtr(&SetEndOfFile);
    if (std.mem.eql(u8, name, "SetFilePointerEx")) return @intFromPtr(&SetFilePointerEx);
    if (std.mem.eql(u8, name, "SetFilePointer")) return @intFromPtr(&SetFilePointer);
    if (std.mem.eql(u8, name, "GetFileSize")) return @intFromPtr(&GetFileSize);
    if (std.mem.eql(u8, name, "GetFileSizeEx")) return @intFromPtr(&GetFileSizeEx);
    if (std.mem.eql(u8, name, "GetFileType")) return @intFromPtr(&GetFileType);
    if (std.mem.eql(u8, name, "CloseHandle")) return @intFromPtr(&CloseHandle);
    if (std.mem.eql(u8, name, "DuplicateHandle")) return @intFromPtr(&DuplicateHandle);
    if (std.mem.eql(u8, name, "GetCommandLineA")) return @intFromPtr(&GetCommandLineA);
    if (std.mem.eql(u8, name, "GetCommandLineW")) return @intFromPtr(&GetCommandLineW);
    if (std.mem.eql(u8, name, "GetEnvironmentStringsW")) return @intFromPtr(&GetEnvironmentStringsW);
    if (std.mem.eql(u8, name, "FreeEnvironmentStringsW")) return @intFromPtr(&FreeEnvironmentStringsW);
    if (std.mem.eql(u8, name, "OutputDebugStringA")) return @intFromPtr(&OutputDebugStringA);
    if (std.mem.eql(u8, name, "OutputDebugStringW")) return @intFromPtr(&OutputDebugStringW);
    if (std.mem.eql(u8, name, "AreFileApisANSI")) return @intFromPtr(&AreFileApisANSI);
    if (std.mem.eql(u8, name, "GetSystemInfo")) return @intFromPtr(&GetSystemInfo);

    // Extended File & Console APIs
    if (std.mem.eql(u8, name, "ReadConsoleW")) return @intFromPtr(&ReadConsoleW);
    if (std.mem.eql(u8, name, "WriteConsoleW")) return @intFromPtr(&WriteConsoleW);
    if (std.mem.eql(u8, name, "CreateFileW")) return @intFromPtr(&CreateFileW);
    if (std.mem.eql(u8, name, "CreateFileA")) return @intFromPtr(&CreateFileA);
    if (std.mem.eql(u8, name, "DeleteFileW")) return @intFromPtr(&DeleteFileW);
    if (std.mem.eql(u8, name, "DeleteFileA")) return @intFromPtr(&DeleteFileA);
    if (std.mem.eql(u8, name, "SetFileTime")) return @intFromPtr(&SetFileTime);
    if (std.mem.eql(u8, name, "SetFileAttributesW")) return @intFromPtr(&SetFileAttributesW);
    if (std.mem.eql(u8, name, "GetFileAttributesW")) return @intFromPtr(&GetFileAttributesW);
    if (std.mem.eql(u8, name, "GetFileAttributesA")) return @intFromPtr(&GetFileAttributesA);
    if (std.mem.eql(u8, name, "GetFileAttributesExW")) return @intFromPtr(&GetFileAttributesExW);
    if (std.mem.eql(u8, name, "GetFileInformationByHandle")) return @intFromPtr(&GetFileInformationByHandle);
    if (std.mem.eql(u8, name, "LockFile")) return @intFromPtr(&LockFile);
    if (std.mem.eql(u8, name, "UnlockFile")) return @intFromPtr(&UnlockFile);
    if (std.mem.eql(u8, name, "LockFileEx")) return @intFromPtr(&LockFileEx);
    if (std.mem.eql(u8, name, "UnlockFileEx")) return @intFromPtr(&UnlockFileEx);

    // Directory & Paths
    if (std.mem.eql(u8, name, "GetCurrentDirectoryW")) return @intFromPtr(&GetCurrentDirectoryW);
    if (std.mem.eql(u8, name, "SetCurrentDirectoryW")) return @intFromPtr(&SetCurrentDirectoryW);
    if (std.mem.eql(u8, name, "CreateDirectoryW")) return @intFromPtr(&CreateDirectoryW);
    if (std.mem.eql(u8, name, "GetFullPathNameW")) return @intFromPtr(&GetFullPathNameW);
    if (std.mem.eql(u8, name, "GetFullPathNameA")) return @intFromPtr(&GetFullPathNameA);
    if (std.mem.eql(u8, name, "GetTempPathW")) return @intFromPtr(&GetTempPathW);
    if (std.mem.eql(u8, name, "GetTempPathA")) return @intFromPtr(&GetTempPathA);
    if (std.mem.eql(u8, name, "GetDriveTypeW")) return @intFromPtr(&GetDriveTypeW);
    if (std.mem.eql(u8, name, "GetDiskFreeSpaceW")) return @intFromPtr(&GetDiskFreeSpaceW);
    if (std.mem.eql(u8, name, "GetDiskFreeSpaceA")) return @intFromPtr(&GetDiskFreeSpaceA);

    // Find Directory Traversal
    if (std.mem.eql(u8, name, "FindFirstFileW")) return @intFromPtr(&FindFirstFileW);
    if (std.mem.eql(u8, name, "FindFirstFileExW")) return @intFromPtr(&FindFirstFileExW);
    if (std.mem.eql(u8, name, "FindNextFileW")) return @intFromPtr(&FindNextFileW);
    if (std.mem.eql(u8, name, "FindClose")) return @intFromPtr(&FindClose);

    // Memory-mapped files
    if (std.mem.eql(u8, name, "CreateFileMappingW")) return @intFromPtr(&CreateFileMappingW);
    if (std.mem.eql(u8, name, "MapViewOfFile")) return @intFromPtr(&MapViewOfFile);
    if (std.mem.eql(u8, name, "UnmapViewOfFile")) return @intFromPtr(&UnmapViewOfFile);
    if (std.mem.eql(u8, name, "FlushViewOfFile")) return @intFromPtr(&FlushViewOfFile);

    // Pipes, Processes & Threads
    if (std.mem.eql(u8, name, "CreatePipe")) return @intFromPtr(&CreatePipe);
    if (std.mem.eql(u8, name, "PeekNamedPipe")) return @intFromPtr(&PeekNamedPipe);
    if (std.mem.eql(u8, name, "CreateProcessW")) return @intFromPtr(&CreateProcessW);
    if (std.mem.eql(u8, name, "GetExitCodeProcess")) return @intFromPtr(&GetExitCodeProcess);
    if (std.mem.eql(u8, name, "CreateThread")) return @intFromPtr(&CreateThread);
    if (std.mem.eql(u8, name, "ResumeThread")) return @intFromPtr(&ResumeThread);

    // Environment & Debug
    if (std.mem.eql(u8, name, "GetEnvironmentVariableA")) return @intFromPtr(&GetEnvironmentVariableA);
    if (std.mem.eql(u8, name, "SetEnvironmentVariableW")) return @intFromPtr(&SetEnvironmentVariableW);
    if (std.mem.eql(u8, name, "DebugBreak")) return @intFromPtr(&DebugBreak);

    return null;
}
