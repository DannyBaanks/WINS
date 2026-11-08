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

var cmdline_storage_a: [2048:0]u8 = undefined;
var cmdline_storage_w: [2048:0]u16 = undefined;
var cmdline_initialized: bool = false;

pub fn setCommandLine(args: []const []const u8) void {
    if (args.len == 0) return;
    var out_pos: usize = 0;
    for (args, 0..) |arg, idx| {
        if (idx > 0 and out_pos < 2047) {
            cmdline_storage_a[out_pos] = ' ';
            out_pos += 1;
        }
        for (arg) |c| {
            if (out_pos >= 2047) break;
            cmdline_storage_a[out_pos] = c;
            out_pos += 1;
        }
    }
    cmdline_storage_a[out_pos] = 0;
    for (0..out_pos + 1) |i| {
        cmdline_storage_w[i] = cmdline_storage_a[i];
    }
    cmdline_initialized = true;
}

fn GetCommandLineA() callconv(W) ?[*:0]const u8 {
    if (cmdline_initialized) return &cmdline_storage_a;
    return &empty_cmd_a;
}

fn GetCommandLineW() callconv(W) ?[*:0]const u16 {
    if (cmdline_initialized) return &cmdline_storage_w;
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

fn CreateProcessW(
    app: ?[*:0]const u16,
    cmd: ?[*:0]u16,
    pa: ?*anyopaque,
    ta: ?*anyopaque,
    inh: u32,
    flags: u32,
    env: ?*anyopaque,
    dir: ?[*:0]const u16,
    si: ?*anyopaque,
    pi: ?*anyopaque,
) callconv(W) u32 {
    _ = app; _ = pa; _ = ta; _ = inh; _ = flags; _ = env; _ = dir; _ = si;
    if (cmd) |c| {
        var utf8_buf: [1024]u8 = undefined;
        var i: usize = 0;
        while (c[i] != 0 and i < 1023) : (i += 1) {
            utf8_buf[i] = @truncate(c[i]);
        }
        utf8_buf[i] = 0;
        _ = @import("wins_graph.zig").translateCommandLine(utf8_buf[0..i]);
    }
    if (pi) |p| {
        const ptr: [*]u8 = @ptrCast(p);
        std.mem.writeInt(usize, ptr[0..8], 0x6001, .little);
        std.mem.writeInt(usize, ptr[8..16], 0x6002, .little);
        std.mem.writeInt(u32, ptr[16..20], 1234, .little);
        std.mem.writeInt(u32, ptr[20..24], 1235, .little);
    }
    return 1;
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

fn IsDBCSLeadByteEx(cp: u32, test_char: u8) callconv(W) i32 {
    _ = cp;
    _ = test_char;
    return 0;
}

fn VirtualQuery(addr: ?*const anyopaque, buf: ?[*]u8, len: usize) callconv(W) usize {
    if (buf == null or len < 48) return 0;
    const raw_addr: usize = if (addr) |p| @intFromPtr(p) else image_base_addr;
    const base_page = raw_addr & ~@as(usize, 0xFFF);
    const alloc_base = if (image_base_addr != 0) image_base_addr else base_page;
    @memset(buf.?[0..48], 0);
    std.mem.writeInt(u64, buf.?[0..8], base_page, .little); // BaseAddress
    std.mem.writeInt(u64, buf.?[8..16], alloc_base, .little); // AllocationBase
    std.mem.writeInt(u32, buf.?[16..20], 0x04, .little); // AllocationProtect = PAGE_READWRITE
    std.mem.writeInt(u64, buf.?[24..32], 0x10000, .little); // RegionSize
    std.mem.writeInt(u32, buf.?[32..36], 0x1000, .little); // State = MEM_COMMIT
    std.mem.writeInt(u32, buf.?[36..40], 0x04, .little); // Protect = PAGE_READWRITE
    std.mem.writeInt(u32, buf.?[40..44], 0x1000000, .little); // Type = MEM_IMAGE
    return 48;
}

fn VirtualProtect(addr: ?*anyopaque, sz: usize, new_prot: u32, old_prot: ?*u32) callconv(W) i32 {
    if (old_prot) |p| p.* = 0x04; // PAGE_READWRITE
    if (addr != null and sz > 0) {
        const raw = @intFromPtr(addr.?);
        const page_start = raw & ~@as(usize, 0xFFF);
        const page_end = std.mem.alignForward(usize, raw + sz, 4096);
        const exec = (new_prot & 0xF0) != 0;
        const write = (new_prot & 0xCC) != 0;
        _ = linux.mprotect(@ptrFromInt(page_start), page_end - page_start, .{
            .READ = true,
            .WRITE = write or !exec,
            .EXEC = exec,
        });
    }
    return 1;
}

// --- Additional Console, Process, File & Sync APIs for Multi-call Binaries ---

fn CreateConsoleScreenBuffer(access: u32, share: u32, sa: ?*anyopaque, flags: u32, data: ?*anyopaque) callconv(W) usize {
    _ = access; _ = share; _ = sa; _ = flags; _ = data;
    return 0x2001;
}

fn SetConsoleActiveScreenBuffer(h: usize) callconv(W) u32 {
    _ = h;
    return 1;
}

fn SetConsoleScreenBufferSize(h: usize, size: u32) callconv(W) u32 {
    _ = h; _ = size;
    return 1;
}

fn SetConsoleCursorPosition(h: usize, coord: u32) callconv(W) u32 {
    _ = h; _ = coord;
    return 1;
}

fn SetConsoleTitleA(title: ?[*:0]const u8) callconv(W) u32 {
    _ = title;
    return 1;
}

fn GetConsoleTitleA(buf: ?[*]u8, sz: u32) callconv(W) u32 {
    if (buf != null and sz > 0) buf.?[0] = 0;
    return 0;
}

fn GetConsoleWindow() callconv(W) usize {
    return 0;
}

fn FillConsoleOutputCharacterA(h: usize, ch: u8, len: u32, coord: u32, written: ?*u32) callconv(W) u32 {
    _ = h; _ = ch; _ = coord;
    if (written) |w| w.* = len;
    return 1;
}

fn FillConsoleOutputAttribute(h: usize, attr: u16, len: u32, coord: u32, written: ?*u32) callconv(W) u32 {
    _ = h; _ = attr; _ = coord;
    if (written) |w| w.* = len;
    return 1;
}

fn GetNumberOfConsoleInputEvents(h: usize, num: ?*u32) callconv(W) u32 {
    _ = h;
    if (num) |n| n.* = 0;
    return 1;
}

fn PeekConsoleInputW(h: usize, buf: ?[*]u8, len: u32, read: ?*u32) callconv(W) u32 {
    _ = h; _ = buf; _ = len;
    if (read) |r| r.* = 0;
    return 1;
}

fn ReadConsoleInputA(h: usize, buf: ?[*]u8, len: u32, read: ?*u32) callconv(W) u32 {
    _ = h; _ = buf; _ = len;
    if (read) |r| r.* = 0;
    return 1;
}

fn ReadConsoleInputW(h: usize, buf: ?[*]u8, len: u32, read: ?*u32) callconv(W) u32 {
    _ = h; _ = buf; _ = len;
    if (read) |r| r.* = 0;
    return 1;
}

fn SetConsoleCP(cp: u32) callconv(W) u32 {
    _ = cp;
    return 1;
}

fn SetConsoleOutputCP(cp: u32) callconv(W) u32 {
    _ = cp;
    return 1;
}

fn GenerateConsoleCtrlEvent(ctrl: u32, proc_grp: u32) callconv(W) u32 {
    _ = ctrl; _ = proc_grp;
    return 1;
}

fn CreateEventA(sa: ?*anyopaque, manual_reset: u32, initial_state: u32, name: ?[*:0]const u8) callconv(W) usize {
    _ = sa; _ = manual_reset; _ = initial_state; _ = name;
    return 0x6001;
}

fn ResetEvent(h: usize) callconv(W) u32 {
    _ = h;
    return 1;
}

fn WaitForMultipleObjects(count: u32, handles: ?*const usize, wait_all: u32, ms: u32) callconv(W) u32 {
    _ = count; _ = handles; _ = wait_all; _ = ms;
    return 0; // WAIT_OBJECT_0
}

fn SleepEx(ms: u32, alertable: u32) callconv(W) u32 {
    _ = alertable;
    Sleep(ms);
    return 0;
}

fn CreateNamedPipeA(name: ?[*:0]const u8, open_mode: u32, pipe_mode: u32, max_inst: u32, out_sz: u32, in_sz: u32, timeout: u32, sa: ?*anyopaque) callconv(W) usize {
    _ = name; _ = open_mode; _ = pipe_mode; _ = max_inst; _ = out_sz; _ = in_sz; _ = timeout; _ = sa;
    return INVALID_HANDLE;
}

fn CreateFileMappingA(file: usize, sa: ?*anyopaque, prot: u32, max_h: u32, max_l: u32, name: ?[*:0]const u8) callconv(W) usize {
    _ = file; _ = sa; _ = prot; _ = max_h; _ = max_l; _ = name;
    return 0x3000;
}

fn CreateProcessA(
    app: ?[*:0]const u8,
    cmd: ?[*:0]u8,
    pa: ?*anyopaque,
    ta: ?*anyopaque,
    inh: u32,
    flags: u32,
    env: ?*anyopaque,
    dir: ?[*:0]const u8,
    si: ?*anyopaque,
    pi: ?*anyopaque,
) callconv(W) u32 {
    _ = pa; _ = ta; _ = inh; _ = flags; _ = env; _ = dir; _ = si;
    const cmd_str: []const u8 = if (cmd) |c| std.mem.span(c) else if (app) |a| std.mem.span(a) else "";
    if (cmd_str.len > 0) {
        _ = @import("wins_graph.zig").translateCommandLine(cmd_str);
    }
    if (pi) |p| {
        const ptr: [*]u8 = @ptrCast(p);
        std.mem.writeInt(usize, ptr[0..8], 0x6001, .little);
        std.mem.writeInt(usize, ptr[8..16], 0x6002, .little);
        std.mem.writeInt(u32, ptr[16..20], 1234, .little);
        std.mem.writeInt(u32, ptr[20..24], 1235, .little);
    }
    return 1;
}

fn CreateRemoteThread(proc: usize, sa: ?*anyopaque, stack_sz: usize, start: usize, param: usize, flags: u32, tid: ?*u32) callconv(W) usize {
    _ = proc; _ = sa; _ = stack_sz; _ = start; _ = param; _ = flags;
    if (tid) |t| t.* = 1002;
    return 0x4001;
}

fn CreateToolhelp32Snapshot(flags: u32, pid: u32) callconv(W) usize {
    _ = flags; _ = pid;
    return 0x5001;
}

fn Process32First(h: usize, pe: ?[*]u8) callconv(W) u32 {
    _ = h; _ = pe;
    return 0;
}

fn Process32Next(h: usize, pe: ?[*]u8) callconv(W) u32 {
    _ = h; _ = pe;
    return 0;
}

fn DeviceIoControl(h: usize, code: u32, in_buf: ?*anyopaque, in_sz: u32, out_buf: ?*anyopaque, out_sz: u32, ret_bytes: ?*u32, ov: ?*anyopaque) callconv(W) u32 {
    _ = h; _ = code; _ = in_buf; _ = in_sz; _ = out_buf; _ = out_sz; _ = ov;
    if (ret_bytes) |b| b.* = 0;
    return 1;
}

fn FindFirstFileA(name: ?[*:0]const u8, data: ?[*]u8) callconv(W) usize {
    _ = name; _ = data;
    return INVALID_HANDLE;
}

fn FindNextFileA(h: usize, data: ?[*]u8) callconv(W) u32 {
    _ = h; _ = data;
    return 0;
}

fn FindFirstVolumeW(name: ?[*]u16, len: u32) callconv(W) usize {
    _ = name; _ = len;
    return INVALID_HANDLE;
}

fn FindNextVolumeW(h: usize, name: ?[*]u16, len: u32) callconv(W) u32 {
    _ = h; _ = name; _ = len;
    return 0;
}

fn FindVolumeClose(h: usize) callconv(W) u32 {
    _ = h;
    return 1;
}

fn GetCompressedFileSizeA(name: ?[*:0]const u8, high: ?*u32) callconv(W) u32 {
    _ = name;
    if (high) |h| h.* = 0;
    return 0;
}

fn GetDiskFreeSpaceExA(dir: ?[*:0]const u8, free_caller: ?*u64, total: ?*u64, total_free: ?*u64) callconv(W) u32 {
    _ = dir;
    if (free_caller) |p| p.* = 10_000_000_000;
    if (total) |p| p.* = 20_000_000_000;
    if (total_free) |p| p.* = 10_000_000_000;
    return 1;
}

fn GetDiskFreeSpaceExW(dir: ?[*:0]const u16, free_caller: ?*u64, total: ?*u64, total_free: ?*u64) callconv(W) u32 {
    _ = dir;
    if (free_caller) |p| p.* = 10_000_000_000;
    if (total) |p| p.* = 20_000_000_000;
    if (total_free) |p| p.* = 10_000_000_000;
    return 1;
}

fn GetDriveTypeA(root: ?[*:0]const u8) callconv(W) u32 {
    _ = root;
    return 3; // DRIVE_FIXED
}

fn GetEnvironmentVariableW(name: ?[*:0]const u16, buf: ?[*]u16, sz: u32) callconv(W) u32 {
    _ = name; _ = buf; _ = sz;
    return 0;
}

fn SetEnvironmentVariableA(name: ?[*:0]const u8, val: ?[*:0]const u8) callconv(W) u32 {
    _ = name; _ = val;
    return 1;
}

fn GetFileAttributesExA(file: ?[*:0]const u8, level: u32, info: ?[*]u8) callconv(W) u32 {
    _ = file; _ = level;
    if (info) |p| @memset(p[0..36], 0);
    return 1;
}

fn SetFileAttributesA(file: ?[*:0]const u8, attr: u32) callconv(W) u32 {
    _ = file; _ = attr;
    return 1;
}

fn GetLogicalDrives() callconv(W) u32 {
    return 0x0c; // C: and D:
}

fn GetModuleFileNameA(mod: usize, buf: ?[*]u8, sz: u32) callconv(W) u32 {
    _ = mod;
    const name = "busybox.exe";
    if (buf != null and sz > name.len) {
        @memcpy(buf.?[0..name.len], name);
        buf.?[name.len] = 0;
        return name.len;
    }
    return 0;
}

fn GetProcessAffinityMask(proc: usize, proc_mask: ?*usize, sys_mask: ?*usize) callconv(W) u32 {
    _ = proc;
    if (proc_mask) |p| p.* = 1;
    if (sys_mask) |s| s.* = 1;
    return 1;
}

fn GetProcessId(proc: usize) callconv(W) u32 {
    _ = proc;
    return @intCast(linux.getpid());
}

fn GetProcessTimes(proc: usize, ct: ?*anyopaque, et: ?*anyopaque, kt: ?*anyopaque, ut: ?*anyopaque) callconv(W) u32 {
    _ = proc; _ = ct; _ = et; _ = kt; _ = ut;
    return 1;
}

fn GetSystemDirectoryA(buf: ?[*]u8, sz: u32) callconv(W) u32 {
    const sys = "C:\\Windows\\System32";
    if (buf != null and sz > sys.len) {
        @memcpy(buf.?[0..sys.len], sys);
        buf.?[sys.len] = 0;
        return sys.len;
    }
    return 0;
}

fn GetVersionExA(osvi: ?[*]u8) callconv(W) u32 {
    if (osvi == null) return 0;
    @memset(osvi.?[0..148], 0);
    std.mem.writeInt(u32, osvi.?[0..4], 148, .little);
    std.mem.writeInt(u32, osvi.?[4..8], 6, .little);
    std.mem.writeInt(u32, osvi.?[8..12], 1, .little);
    std.mem.writeInt(u32, osvi.?[12..16], 7601, .little);
    std.mem.writeInt(u32, osvi.?[16..20], 2, .little);
    return 1;
}

fn GetVolumeInformationA(root: ?[*:0]const u8, vname: ?[*]u8, vn_sz: u32, vsn: ?*u32, mcl: ?*u32, fsf: ?*u32, fsname: ?[*]u8, fsn_sz: u32) callconv(W) u32 {
    _ = root;
    if (vname != null and vn_sz > 0) vname.?[0] = 0;
    if (vsn) |v| v.* = 0x12345678;
    if (mcl) |m| m.* = 255;
    if (fsf) |f| f.* = 0x00000003;
    if (fsname != null and fsn_sz >= 5) {
        @memcpy(fsname.?[0..5], "NTFS\x00");
    }
    return 1;
}

fn GetVolumeInformationW(root: ?[*:0]const u16, vname: ?[*]u16, vn_sz: u32, vsn: ?*u32, mcl: ?*u32, fsf: ?*u32, fsname: ?[*]u16, fsn_sz: u32) callconv(W) u32 {
    _ = root;
    if (vname != null and vn_sz > 0) vname.?[0] = 0;
    if (vsn) |v| v.* = 0x12345678;
    if (mcl) |m| m.* = 255;
    if (fsf) |f| f.* = 0x00000003;
    if (fsname != null and fsn_sz >= 5) {
        fsname.?[0] = 'N'; fsname.?[1] = 'T'; fsname.?[2] = 'F'; fsname.?[3] = 'S'; fsname.?[4] = 0;
    }
    return 1;
}

fn IsWow64Process(proc: usize, wow64: ?*i32) callconv(W) u32 {
    _ = proc;
    if (wow64) |w| w.* = 0;
    return 1;
}

fn LoadLibraryExA(name: ?[*:0]const u8, file: usize, flags: u32) callconv(W) usize {
    _ = name; _ = file; _ = flags;
    return 0;
}

fn MoveFileExA(from: ?[*:0]const u8, to: ?[*:0]const u8, flags: u32) callconv(W) u32 {
    _ = from; _ = to; _ = flags;
    return 1;
}

fn OpenProcess(access: u32, inherit: u32, pid: u32) callconv(W) usize {
    _ = access; _ = inherit;
    return 0x1000 + pid;
}

fn ReadDirectoryChangesW(h: usize, buf: ?[*]u8, len: u32, sub: u32, filter: u32, ret: ?*u32, ov: ?*anyopaque, cr: ?*anyopaque) callconv(W) u32 {
    _ = h; _ = buf; _ = len; _ = sub; _ = filter; _ = ret; _ = ov; _ = cr;
    return 0;
}

fn ReadProcessMemory(proc: usize, base: ?*const anyopaque, buf: ?[*]u8, sz: usize, num_read: ?*usize) callconv(W) u32 {
    _ = proc; _ = base; _ = buf; _ = sz;
    if (num_read) |r| r.* = 0;
    return 0;
}

fn SetErrorMode(mode: u32) callconv(W) u32 {
    _ = mode;
    return 0;
}

fn SetHandleInformation(h: usize, mask: u32, flags: u32) callconv(W) u32 {
    _ = h; _ = mask; _ = flags;
    return 1;
}

fn SetSystemTime(st: ?*const SYSTEMTIME) callconv(W) u32 {
    _ = st;
    return 1;
}

fn CreateEventW(sa: ?*anyopaque, manual_reset: u32, initial_state: u32, name: ?[*:0]const u16) callconv(W) usize {
    _ = sa; _ = manual_reset; _ = initial_state; _ = name;
    return 0x6001;
}

fn SetEvent(h: usize) callconv(W) u32 {
    _ = h;
    return 1;
}

fn CreateSemaphoreW(sa: ?*anyopaque, init_cnt: i32, max_cnt: i32, name: ?[*:0]const u16) callconv(W) usize {
    _ = sa; _ = init_cnt; _ = max_cnt; _ = name;
    return 0x6002;
}

fn ReleaseSemaphore(h: usize, rel_cnt: i32, prev_cnt: ?*i32) callconv(W) u32 {
    _ = h; _ = rel_cnt;
    if (prev_cnt) |p| p.* = 1;
    return 1;
}

fn OpenMutexW(access: u32, inh: u32, name: ?[*:0]const u16) callconv(W) usize {
    _ = access; _ = inh; _ = name;
    return 0;
}

fn AcquireSRWLockExclusive(srw: ?*anyopaque) callconv(W) void {
    _ = srw;
}

fn ReleaseSRWLockExclusive(srw: ?*anyopaque) callconv(W) void {
    _ = srw;
}

fn TryAcquireSRWLockExclusive(srw: ?*anyopaque) callconv(W) u8 {
    _ = srw;
    return 1;
}

fn SleepConditionVariableSRW(cv: ?*anyopaque, srw: ?*anyopaque, ms: u32, flags: u32) callconv(W) u32 {
    _ = cv; _ = srw; _ = ms; _ = flags;
    return 1;
}

fn WakeConditionVariable(cv: ?*anyopaque) callconv(W) void {
    _ = cv;
}

fn WakeAllConditionVariable(cv: ?*anyopaque) callconv(W) void {
    _ = cv;
}

fn InitializeCriticalSectionEx(cs: ?*anyopaque, spin: u32, flags: u32) callconv(W) u32 {
    _ = spin; _ = flags;
    InitializeCriticalSection(cs);
    return 1;
}

fn GetExitCodeThread(h: usize, code: ?*u32) callconv(W) u32 {
    _ = h;
    if (code) |c| c.* = 0;
    return 1;
}

fn VerSetConditionMask(cond: u64, type_mask: u32, condition: u8) callconv(W) u64 {
    _ = type_mask; _ = condition;
    return cond | 1;
}

fn VerifyVersionInfoW(vi: ?*anyopaque, mask: u32, cond: u64) callconv(W) u32 {
    _ = vi; _ = mask; _ = cond;
    return 1;
}

fn lstrlenW(s: ?[*:0]const u16) callconv(W) i32 {
    if (s == null) return 0;
    var len: i32 = 0;
    while (s.?[@intCast(len)] != 0) : (len += 1) {}
    return len;
}

fn lstrcpyW(dst: ?[*]u16, src: ?[*:0]const u16) callconv(W) ?[*]u16 {
    if (dst == null or src == null) return dst;
    var i: usize = 0;
    while (true) : (i += 1) {
        dst.?[i] = src.?[i];
        if (src.?[i] == 0) break;
    }
    return dst;
}

fn lstrcmpW(s1: ?[*:0]const u16, s2: ?[*:0]const u16) callconv(W) i32 {
    if (s1 == null and s2 == null) return 0;
    if (s1 == null) return -1;
    if (s2 == null) return 1;
    var i: usize = 0;
    while (s1.?[i] != 0 and s1.?[i] == s2.?[i]) : (i += 1) {}
    if (s1.?[i] < s2.?[i]) return -1;
    if (s1.?[i] > s2.?[i]) return 1;
    return 0;
}

fn MulDiv(nNumber: i32, nNumerator: i32, nDenominator: i32) callconv(W) i32 {
    if (nDenominator == 0) return -1;
    const prod: i64 = @as(i64, nNumber) * @as(i64, nNumerator);
    const half: i64 = @divTrunc(nDenominator, 2);
    const res = @divTrunc(prod + half, nDenominator);
    if (res > std.math.maxInt(i32) or res < std.math.minInt(i32)) return -1;
    return @intCast(res);
}

fn MoveFileW(from: ?[*:0]const u16, to: ?[*:0]const u16) callconv(W) u32 {
    _ = from; _ = to;
    return 1;
}

fn MoveFileExW(from: ?[*:0]const u16, to: ?[*:0]const u16, flags: u32) callconv(W) u32 {
    _ = from; _ = to; _ = flags;
    return 1;
}

fn GetWindowsDirectoryW(buf: ?[*]u16, sz: u32) callconv(W) u32 {
    const win_dir = [_]u16{ 'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's' };
    if (buf == null or sz < win_dir.len + 1) return win_dir.len + 1;
    @memcpy(buf.?[0..win_dir.len], &win_dir);
    buf.?[win_dir.len] = 0;
    return win_dir.len;
}

fn ExpandEnvironmentStringsW(src: ?[*:0]const u16, dst: ?[*]u16, sz: u32) callconv(W) u32 {
    if (src == null) return 0;
    const len: u32 = @intCast(lstrlenW(src));
    if (dst == null or sz < len + 1) return len + 1;
    @memcpy(dst.?[0..len], src.?[0..len]);
    dst.?[len] = 0;
    return len + 1;
}

fn CompareFileTime(t1: ?*const u64, t2: ?*const u64) callconv(W) i32 {
    if (t1 == null or t2 == null) return 0;
    if (t1.?.* < t2.?.*) return -1;
    if (t1.?.* > t2.?.*) return 1;
    return 0;
}

fn GetLocalTime(st: ?*SYSTEMTIME) callconv(W) void {
    GetSystemTime(st);
}

fn GetDateFormatEx(locale: ?[*:0]const u16, flags: u32, date: ?*const SYSTEMTIME, fmt: ?[*:0]const u16, str: ?[*]u16, cch: i32, cal: ?*anyopaque) callconv(W) i32 {
    _ = locale; _ = cal;
    return GetDateFormatW(0, flags, date, fmt, str, cch);
}

fn GetTimeFormatEx(locale: ?[*:0]const u16, flags: u32, time: ?*const SYSTEMTIME, fmt: ?[*:0]const u16, str: ?[*]u16, cch: i32) callconv(W) i32 {
    _ = locale;
    return GetTimeFormatW(0, flags, time, fmt, str, cch);
}

fn GetLocaleInfoEx(locale: ?[*:0]const u16, lctype: u32, lpData: ?[*]u16, cchData: i32) callconv(W) i32 {
    _ = locale;
    return GetLocaleInfoW(0, lctype, lpData, cchData);
}

fn LCMapStringEx(locale: ?[*:0]const u16, flags: u32, src: ?[*]const u16, src_len: i32, dst: ?[*]u16, dst_len: i32, ver: ?*anyopaque, res: ?*anyopaque, handle: isize) callconv(W) i32 {
    _ = locale; _ = ver; _ = res; _ = handle;
    return LCMapStringW(0, flags, src, src_len, dst, dst_len);
}

fn LocalAlloc(flags: u32, bytes: usize) callconv(W) ?[*]u8 {
    _ = flags;
    return HeapAlloc(HEAP_COOKIE, 0, bytes);
}

fn GetFileInformationByHandleEx(h: usize, class: u32, buf: ?*anyopaque, sz: u32) callconv(W) u32 {
    _ = h; _ = class;
    if (buf != null and sz > 0) @memset(@as([*]u8, @ptrCast(buf.?))[0..sz], 0);
    return 1;
}

fn SetFileInformationByHandle(h: usize, class: u32, buf: ?*const anyopaque, sz: u32) callconv(W) u32 {
    _ = h; _ = class; _ = buf; _ = sz;
    return 1;
}

// ---------------------------------------------------------------------------
// 8. Lookup Dispatch Table
// ---------------------------------------------------------------------------

fn GlobalAlloc(uFlags: u32, dwBytes: usize) callconv(W) ?*anyopaque {
    _ = uFlags;
    return HeapAlloc(HEAP_COOKIE, 0, dwBytes);
}

fn GlobalLock(hMem: ?*anyopaque) callconv(W) ?*anyopaque {
    return hMem;
}

fn GlobalUnlock(hMem: ?*anyopaque) callconv(W) i32 {
    _ = hMem;
    return 1;
}

fn GlobalFree(hMem: ?*anyopaque) callconv(W) ?*anyopaque {
    _ = HeapFree(HEAP_COOKIE, 0, if (hMem) |p| @ptrCast(p) else null);
    return null;
}

fn CopyFileW(lpExisting: ?[*:0]const u16, lpNew: ?[*:0]const u16, bFailIfExists: u32) callconv(W) u32 {
    _ = lpExisting; _ = lpNew; _ = bFailIfExists;
    return 1;
}

fn ReleaseMutex(hMutex: usize) callconv(W) u32 {
    _ = hMutex;
    return 1;
}

fn CreateIoCompletionPort(FileHandle: usize, ExistingCompletionPort: usize, CompletionKey: usize, NumberOfConcurrentThreads: u32) callconv(W) usize {
    _ = FileHandle; _ = ExistingCompletionPort; _ = CompletionKey; _ = NumberOfConcurrentThreads;
    return 0x9001;
}

fn GetQueuedCompletionStatus(CompletionPort: usize, lpNumberOfBytesTransferred: ?*u32, lpCompletionKey: ?*usize, lpOverlapped: ?*?*anyopaque, dwMilliseconds: u32) callconv(W) u32 {
    _ = CompletionPort; _ = dwMilliseconds;
    if (lpNumberOfBytesTransferred) |p| p.* = 0;
    if (lpCompletionKey) |p| p.* = 0;
    if (lpOverlapped) |p| p.* = null;
    return 0;
}

fn VirtualAlloc(lpAddress: ?*anyopaque, dwSize: usize, flAllocationType: u32, flProtect: u32) callconv(W) ?*anyopaque {
    _ = flAllocationType; _ = flProtect;
    const rounded = (dwSize + 4095) & ~@as(usize, 4095);
    const sz = if (rounded == 0) 4096 else rounded;
    const hint: ?[*]align(4096) u8 = if (lpAddress) |addr| @ptrCast(@alignCast(addr)) else null;
    const mrc = linux.mmap(hint, sz, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
    const signed: isize = @bitCast(mrc);
    if (signed < 0 and signed >= -4095) return null;
    return @ptrFromInt(mrc);
}

fn VirtualFree(lpAddress: ?*anyopaque, dwSize: usize, dwFreeType: u32) callconv(W) i32 {
    _ = dwFreeType;
    if (lpAddress) |addr| {
        _ = linux.munmap(@ptrCast(@alignCast(addr)), dwSize);
    }
    return 1;
}

fn GetThreadContext(hThread: usize, lpContext: ?*anyopaque) callconv(W) i32 {
    _ = hThread; _ = lpContext;
    return 1;
}

fn SuspendThread(hThread: usize) callconv(W) u32 {
    _ = hThread;
    return 0;
}

fn CreateMutexA(lpMutexAttributes: ?*anyopaque, bInitialOwner: i32, lpName: ?[*:0]const u8) callconv(W) usize {
    _ = lpMutexAttributes; _ = bInitialOwner; _ = lpName;
    return 0x5001;
}

fn CreateSemaphoreA(lpSemaphoreAttributes: ?*anyopaque, lInitialCount: i32, lMaximumCount: i32, lpName: ?[*:0]const u8) callconv(W) usize {
    _ = lpSemaphoreAttributes; _ = lInitialCount; _ = lMaximumCount; _ = lpName;
    return 0x5002;
}

fn OpenEventA(dwDesiredAccess: u32, bInheritHandle: i32, lpName: ?[*:0]const u8) callconv(W) usize {
    _ = dwDesiredAccess; _ = bInheritHandle; _ = lpName;
    return 0x5003;
}

fn SetWaitableTimer(hTimer: usize, lpDueTime: ?*const anyopaque, lPeriod: i32, pfnCompletionRoutine: ?*anyopaque, lpArgToCompletionRoutine: ?*anyopaque, fResume: i32) callconv(W) i32 {
    _ = hTimer; _ = lpDueTime; _ = lPeriod; _ = pfnCompletionRoutine; _ = lpArgToCompletionRoutine; _ = fResume;
    return 1;
}

fn CreateWaitableTimerA(lpTimerAttributes: ?*anyopaque, bManualReset: i32, lpTimerName: ?[*:0]const u8) callconv(W) usize {
    _ = lpTimerAttributes; _ = bManualReset; _ = lpTimerName;
    return 0x5004;
}

fn SignalObjectAndWait(hObjectToSignal: usize, hObjectToWaitOn: usize, dwMilliseconds: u32, bAlertable: i32) callconv(W) u32 {
    _ = hObjectToSignal; _ = hObjectToWaitOn; _ = dwMilliseconds; _ = bAlertable;
    return 0;
}

fn SetThreadPriority(hThread: usize, nPriority: i32) callconv(W) i32 {
    _ = hThread; _ = nPriority;
    return 1;
}

fn SetThreadAffinityMask(hThread: usize, dwThreadAffinityMask: usize) callconv(W) usize {
    _ = hThread;
    return dwThreadAffinityMask;
}

fn SwitchToThread() callconv(W) i32 {
    return 1;
}

fn InterlockedPopEntrySList(ListHead: ?*anyopaque) callconv(W) ?*anyopaque {
    _ = ListHead;
    return null;
}

const MemoryStatusEx = extern struct {
    dwLength: u32,
    dwMemoryLoad: u32,
    ullTotalPhys: u64,
    ullAvailPhys: u64,
    ullTotalPageFile: u64,
    ullAvailPageFile: u64,
    ullTotalVirtual: u64,
    ullAvailVirtual: u64,
    ullAvailExtendedVirtual: u64,
};

fn GlobalMemoryStatusEx(lpBuffer: ?*MemoryStatusEx) callconv(W) i32 {
    if (lpBuffer) |b| {
        b.dwMemoryLoad = 25;
        b.ullTotalPhys = 16 * 1024 * 1024 * 1024;
        b.ullAvailPhys = 12 * 1024 * 1024 * 1024;
        b.ullTotalPageFile = 16 * 1024 * 1024 * 1024;
        b.ullAvailPageFile = 12 * 1024 * 1024 * 1024;
        b.ullTotalVirtual = 128 * 1024 * 1024 * 1024 * 1024;
        b.ullAvailVirtual = 127 * 1024 * 1024 * 1024 * 1024;
        b.ullAvailExtendedVirtual = 0;
    }
    return 1;
}

const MemoryStatus = extern struct {
    dwLength: u32,
    dwMemoryLoad: u32,
    dwTotalPhys: usize,
    dwAvailPhys: usize,
    dwTotalPageFile: usize,
    dwAvailPageFile: usize,
    dwTotalVirtual: usize,
    dwAvailVirtual: usize,
};

fn GlobalMemoryStatus(lpBuffer: ?*MemoryStatus) callconv(W) void {
    if (lpBuffer) |b| {
        b.dwMemoryLoad = 25;
        b.dwTotalPhys = 4 * 1024 * 1024 * 1024;
        b.dwAvailPhys = 3 * 1024 * 1024 * 1024;
        b.dwTotalPageFile = 4 * 1024 * 1024 * 1024;
        b.dwAvailPageFile = 3 * 1024 * 1024 * 1024;
        b.dwTotalVirtual = 2 * 1024 * 1024 * 1024;
        b.dwAvailVirtual = 2 * 1024 * 1024 * 1024;
    }
}

const SystemPowerStatus = extern struct {
    ACLineStatus: u8,
    BatteryFlag: u8,
    BatteryLifePercent: u8,
    SystemStatusFlag: u8,
    BatteryLifeTime: u32,
    BatteryFullLifeTime: u32,
};

fn GetSystemPowerStatus(lpSystemPowerStatus: ?*SystemPowerStatus) callconv(W) i32 {
    if (lpSystemPowerStatus) |s| {
        s.ACLineStatus = 1;
        s.BatteryFlag = 0;
        s.BatteryLifePercent = 100;
        s.SystemStatusFlag = 0;
        s.BatteryLifeTime = 0xFFFFFFFF;
        s.BatteryFullLifeTime = 0xFFFFFFFF;
    }
    return 1;
}

fn GetComputerNameW(lpBuffer: ?[*]u16, nSize: ?*u32) callconv(W) i32 {
    const name_w = [_]u16{ 'W', 'I', 'N', 'S', '-', 'P', 'C', 0 };
    if (lpBuffer != null and nSize != null and nSize.?.* >= name_w.len) {
        @memcpy(lpBuffer.?[0..name_w.len], &name_w);
        nSize.?.* = name_w.len - 1;
        return 1;
    }
    if (nSize) |s| s.* = name_w.len;
    return 0;
}

fn GetVersionExW(lpVersionInformation: ?*anyopaque) callconv(W) i32 {
    if (lpVersionInformation) |info| {
        const p: [*]u32 = @ptrCast(@alignCast(info));
        p[1] = 10;
        p[2] = 0;
        p[3] = 19045;
        p[4] = 2;
    }
    return 1;
}

fn GetUserDefaultUILanguage() callconv(W) u16 {
    return 0x0409;
}

fn GetStartupInfoA(lpStartupInfo: ?*anyopaque) callconv(W) void {
    if (lpStartupInfo) |si| {
        @memset(@as([*]u8, @ptrCast(si))[0..68], 0);
    }
}

fn GetTempFileNameW(lpPathName: ?*const u16, lpPrefixString: ?*const u16, uUnique: u32, lpTempFileName: ?[*]u16) callconv(W) u32 {
    _ = lpPathName; _ = lpPrefixString;
    const name_w = [_]u16{ 'C', ':', '\\', 'T', 'e', 'm', 'p', '\\', 'w', 'i', 'n', 's', '.', 't', 'm', 'p', 0 };
    if (lpTempFileName) |p| {
        @memcpy(p[0..name_w.len], &name_w);
    }
    return if (uUnique != 0) uUnique else 1;
}

fn GetCurrentDirectoryA(nBufferLength: u32, lpBuffer: ?[*]u8) callconv(W) u32 {
    const dir = "C:\\WINS";
    if (lpBuffer != null and nBufferLength >= dir.len + 1) {
        @memcpy(lpBuffer.?[0..dir.len], dir);
        lpBuffer.?[dir.len] = 0;
        return dir.len;
    }
    return dir.len + 1;
}

fn RemoveDirectoryW(lpPathName: ?*const u16) callconv(W) i32 {
    _ = lpPathName;
    return 1;
}

fn ReplaceFileW(lpReplacedFileName: ?*const u16, lpReplacementFileName: ?*const u16, lpBackupFileName: ?*const u16, dwReplaceFlags: u32, lpExclude: ?*anyopaque, lpReserved: ?*anyopaque) callconv(W) i32 {
    _ = lpReplacedFileName; _ = lpReplacementFileName; _ = lpBackupFileName; _ = dwReplaceFlags; _ = lpExclude; _ = lpReserved;
    return 1;
}

fn GetOverlappedResult(hFile: usize, lpOverlapped: ?*anyopaque, lpNumberOfBytesTransferred: ?*u32, bWait: i32) callconv(W) i32 {
    _ = hFile; _ = lpOverlapped; _ = bWait;
    if (lpNumberOfBytesTransferred) |p| p.* = 0;
    return 1;
}

fn CancelIo(hFile: usize) callconv(W) i32 {
    _ = hFile;
    return 1;
}

fn GetFileTime(hFile: usize, lpCreationTime: ?*anyopaque, lpLastAccessTime: ?*anyopaque, lpLastWriteTime: ?*anyopaque) callconv(W) i32 {
    _ = hFile; _ = lpCreationTime; _ = lpLastAccessTime; _ = lpLastWriteTime;
    return 1;
}

fn FileTimeToLocalFileTime(lpFileTime: ?*const u64, lpLocalFileTime: ?*u64) callconv(W) i32 {
    if (lpFileTime != null and lpLocalFileTime != null) {
        lpLocalFileTime.?.* = lpFileTime.?.*;
    }
    return 1;
}

fn FileTimeToDosDateTime(lpFileTime: ?*const u64, lpFatDate: ?*u16, lpFatTime: ?*u16) callconv(W) i32 {
    _ = lpFileTime;
    if (lpFatDate) |d| d.* = 0x5821;
    if (lpFatTime) |t| t.* = 0x6000;
    return 1;
}

fn FindFirstFileExA(lpFileName: ?[*:0]const u8, fInfoLevelId: u32, lpFindFileData: ?*anyopaque, fSearchOp: u32, lpSearchFilter: ?*anyopaque, dwAdditionalFlags: u32) callconv(W) usize {
    _ = lpFileName; _ = fInfoLevelId; _ = lpFindFileData; _ = fSearchOp; _ = lpSearchFilter; _ = dwAdditionalFlags;
    return ~@as(usize, 0);
}

fn FlushConsoleInputBuffer(hConsoleInput: usize) callconv(W) i32 {
    _ = hConsoleInput;
    return 1;
}

fn FlushInstructionCache(hProcess: usize, lpBaseAddress: ?*const anyopaque, dwSize: usize) callconv(W) i32 {
    _ = hProcess; _ = lpBaseAddress; _ = dwSize;
    return 1;
}

fn HeapQueryInformation(HeapHandle: usize, HeapInformationClass: u32, HeapInformation: ?*anyopaque, HeapInformationLength: usize, ReturnLength: ?*usize) callconv(W) i32 {
    _ = HeapHandle; _ = HeapInformationClass; _ = HeapInformation; _ = HeapInformationLength;
    if (ReturnLength) |p| p.* = 0;
    return 1;
}

fn VerifyVersionInfoA(lpVersionInformation: ?*anyopaque, dwTypeMask: u32, dwlConditionMask: u64) callconv(W) i32 {
    _ = lpVersionInformation; _ = dwTypeMask; _ = dwlConditionMask;
    return 1;
}

fn ExpandEnvironmentStringsA(lpSrc: ?[*:0]const u8, lpDst: ?[*]u8, nSize: u32) callconv(W) u32 {
    if (lpSrc == null) return 0;
    var len: u32 = 0;
    while (lpSrc.?[len] != 0) : (len += 1) {}
    if (lpDst != null and nSize >= len + 1) {
        @memcpy(lpDst.?[0..len], lpSrc.?[0..len]);
        lpDst.?[len] = 0;
        return len + 1;
    }
    return len + 1;
}

fn SetDllDirectoryW(lpPathName: ?*const u16) callconv(W) i32 {
    _ = lpPathName;
    return 1;
}

fn lstrcpyA(lpString1: ?[*]u8, lpString2: ?[*:0]const u8) callconv(W) ?[*]u8 {
    if (lpString1 == null or lpString2 == null) return lpString1;
    var i: usize = 0;
    while (lpString2.?[i] != 0) : (i += 1) {
        lpString1.?[i] = lpString2.?[i];
    }
    lpString1.?[i] = 0;
    return lpString1;
}

fn lstrlenA(lpString: ?[*:0]const u8) callconv(W) i32 {
    if (lpString == null) return 0;
    var len: i32 = 0;
    while (lpString.?[@intCast(len)] != 0) : (len += 1) {}
    return len;
}

pub fn lookup(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "VirtualAlloc")) return @intFromPtr(&VirtualAlloc);
    if (std.mem.eql(u8, name, "VirtualFree")) return @intFromPtr(&VirtualFree);
    if (std.mem.eql(u8, name, "GetThreadContext")) return @intFromPtr(&GetThreadContext);
    if (std.mem.eql(u8, name, "SuspendThread")) return @intFromPtr(&SuspendThread);
    if (std.mem.eql(u8, name, "CreateMutexA")) return @intFromPtr(&CreateMutexA);
    if (std.mem.eql(u8, name, "CreateSemaphoreA")) return @intFromPtr(&CreateSemaphoreA);
    if (std.mem.eql(u8, name, "OpenEventA")) return @intFromPtr(&OpenEventA);
    if (std.mem.eql(u8, name, "SetWaitableTimer")) return @intFromPtr(&SetWaitableTimer);
    if (std.mem.eql(u8, name, "CreateWaitableTimerA")) return @intFromPtr(&CreateWaitableTimerA);
    if (std.mem.eql(u8, name, "SignalObjectAndWait")) return @intFromPtr(&SignalObjectAndWait);
    if (std.mem.eql(u8, name, "SetThreadPriority")) return @intFromPtr(&SetThreadPriority);
    if (std.mem.eql(u8, name, "SetThreadAffinityMask")) return @intFromPtr(&SetThreadAffinityMask);
    if (std.mem.eql(u8, name, "SwitchToThread")) return @intFromPtr(&SwitchToThread);
    if (std.mem.eql(u8, name, "InterlockedPopEntrySList")) return @intFromPtr(&InterlockedPopEntrySList);
    if (std.mem.eql(u8, name, "GlobalMemoryStatusEx")) return @intFromPtr(&GlobalMemoryStatusEx);
    if (std.mem.eql(u8, name, "GlobalMemoryStatus")) return @intFromPtr(&GlobalMemoryStatus);
    if (std.mem.eql(u8, name, "GetSystemPowerStatus")) return @intFromPtr(&GetSystemPowerStatus);
    if (std.mem.eql(u8, name, "GetComputerNameW")) return @intFromPtr(&GetComputerNameW);
    if (std.mem.eql(u8, name, "GetVersionExW")) return @intFromPtr(&GetVersionExW);
    if (std.mem.eql(u8, name, "GetUserDefaultUILanguage")) return @intFromPtr(&GetUserDefaultUILanguage);
    if (std.mem.eql(u8, name, "GetStartupInfoA")) return @intFromPtr(&GetStartupInfoA);
    if (std.mem.eql(u8, name, "GetTempFileNameW")) return @intFromPtr(&GetTempFileNameW);
    if (std.mem.eql(u8, name, "GetCurrentDirectoryA")) return @intFromPtr(&GetCurrentDirectoryA);
    if (std.mem.eql(u8, name, "RemoveDirectoryW")) return @intFromPtr(&RemoveDirectoryW);
    if (std.mem.eql(u8, name, "ReplaceFileW")) return @intFromPtr(&ReplaceFileW);
    if (std.mem.eql(u8, name, "GetOverlappedResult")) return @intFromPtr(&GetOverlappedResult);
    if (std.mem.eql(u8, name, "CancelIo")) return @intFromPtr(&CancelIo);
    if (std.mem.eql(u8, name, "GetFileTime")) return @intFromPtr(&GetFileTime);
    if (std.mem.eql(u8, name, "FileTimeToLocalFileTime")) return @intFromPtr(&FileTimeToLocalFileTime);
    if (std.mem.eql(u8, name, "FileTimeToDosDateTime")) return @intFromPtr(&FileTimeToDosDateTime);
    if (std.mem.eql(u8, name, "FindFirstFileExA")) return @intFromPtr(&FindFirstFileExA);
    if (std.mem.eql(u8, name, "FlushConsoleInputBuffer")) return @intFromPtr(&FlushConsoleInputBuffer);
    if (std.mem.eql(u8, name, "FlushInstructionCache")) return @intFromPtr(&FlushInstructionCache);
    if (std.mem.eql(u8, name, "HeapQueryInformation")) return @intFromPtr(&HeapQueryInformation);
    if (std.mem.eql(u8, name, "VerifyVersionInfoA")) return @intFromPtr(&VerifyVersionInfoA);
    if (std.mem.eql(u8, name, "ExpandEnvironmentStringsA")) return @intFromPtr(&ExpandEnvironmentStringsA);
    if (std.mem.eql(u8, name, "SetDllDirectoryW")) return @intFromPtr(&SetDllDirectoryW);
    if (std.mem.eql(u8, name, "lstrcpyA")) return @intFromPtr(&lstrcpyA);
    if (std.mem.eql(u8, name, "lstrlenA")) return @intFromPtr(&lstrlenA);
    if (std.mem.eql(u8, name, "GlobalAlloc")) return @intFromPtr(&GlobalAlloc);
    if (std.mem.eql(u8, name, "GlobalLock")) return @intFromPtr(&GlobalLock);
    if (std.mem.eql(u8, name, "GlobalUnlock")) return @intFromPtr(&GlobalUnlock);
    if (std.mem.eql(u8, name, "GlobalFree")) return @intFromPtr(&GlobalFree);
    if (std.mem.eql(u8, name, "CopyFileW")) return @intFromPtr(&CopyFileW);
    if (std.mem.eql(u8, name, "ReleaseMutex")) return @intFromPtr(&ReleaseMutex);
    if (std.mem.eql(u8, name, "CreateIoCompletionPort")) return @intFromPtr(&CreateIoCompletionPort);
    if (std.mem.eql(u8, name, "GetQueuedCompletionStatus")) return @intFromPtr(&GetQueuedCompletionStatus);
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
    if (std.mem.eql(u8, name, "IsDBCSLeadByteEx")) return @intFromPtr(&IsDBCSLeadByteEx);
    if (std.mem.eql(u8, name, "VirtualQuery")) return @intFromPtr(&VirtualQuery);
    if (std.mem.eql(u8, name, "VirtualProtect")) return @intFromPtr(&VirtualProtect);

    // Multi-call console & utility extensions
    if (std.mem.eql(u8, name, "CreateConsoleScreenBuffer")) return @intFromPtr(&CreateConsoleScreenBuffer);
    if (std.mem.eql(u8, name, "SetConsoleActiveScreenBuffer")) return @intFromPtr(&SetConsoleActiveScreenBuffer);
    if (std.mem.eql(u8, name, "SetConsoleScreenBufferSize")) return @intFromPtr(&SetConsoleScreenBufferSize);
    if (std.mem.eql(u8, name, "SetConsoleCursorPosition")) return @intFromPtr(&SetConsoleCursorPosition);
    if (std.mem.eql(u8, name, "SetConsoleTitleA")) return @intFromPtr(&SetConsoleTitleA);
    if (std.mem.eql(u8, name, "GetConsoleTitleA")) return @intFromPtr(&GetConsoleTitleA);
    if (std.mem.eql(u8, name, "GetConsoleWindow")) return @intFromPtr(&GetConsoleWindow);
    if (std.mem.eql(u8, name, "FillConsoleOutputCharacterA")) return @intFromPtr(&FillConsoleOutputCharacterA);
    if (std.mem.eql(u8, name, "FillConsoleOutputAttribute")) return @intFromPtr(&FillConsoleOutputAttribute);
    if (std.mem.eql(u8, name, "GetNumberOfConsoleInputEvents")) return @intFromPtr(&GetNumberOfConsoleInputEvents);
    if (std.mem.eql(u8, name, "PeekConsoleInputW")) return @intFromPtr(&PeekConsoleInputW);
    if (std.mem.eql(u8, name, "ReadConsoleInputA")) return @intFromPtr(&ReadConsoleInputA);
    if (std.mem.eql(u8, name, "ReadConsoleInputW")) return @intFromPtr(&ReadConsoleInputW);
    if (std.mem.eql(u8, name, "SetConsoleCP")) return @intFromPtr(&SetConsoleCP);
    if (std.mem.eql(u8, name, "SetConsoleOutputCP")) return @intFromPtr(&SetConsoleOutputCP);
    if (std.mem.eql(u8, name, "GenerateConsoleCtrlEvent")) return @intFromPtr(&GenerateConsoleCtrlEvent);
    if (std.mem.eql(u8, name, "CreateEventA")) return @intFromPtr(&CreateEventA);
    if (std.mem.eql(u8, name, "ResetEvent")) return @intFromPtr(&ResetEvent);
    if (std.mem.eql(u8, name, "WaitForMultipleObjects")) return @intFromPtr(&WaitForMultipleObjects);
    if (std.mem.eql(u8, name, "SleepEx")) return @intFromPtr(&SleepEx);
    if (std.mem.eql(u8, name, "CreateNamedPipeA")) return @intFromPtr(&CreateNamedPipeA);
    if (std.mem.eql(u8, name, "CreateFileMappingA")) return @intFromPtr(&CreateFileMappingA);
    if (std.mem.eql(u8, name, "CreateProcessA")) return @intFromPtr(&CreateProcessA);
    if (std.mem.eql(u8, name, "CreateRemoteThread")) return @intFromPtr(&CreateRemoteThread);
    if (std.mem.eql(u8, name, "CreateToolhelp32Snapshot")) return @intFromPtr(&CreateToolhelp32Snapshot);
    if (std.mem.eql(u8, name, "Process32First")) return @intFromPtr(&Process32First);
    if (std.mem.eql(u8, name, "Process32Next")) return @intFromPtr(&Process32Next);
    if (std.mem.eql(u8, name, "DeviceIoControl")) return @intFromPtr(&DeviceIoControl);
    if (std.mem.eql(u8, name, "FindFirstFileA")) return @intFromPtr(&FindFirstFileA);
    if (std.mem.eql(u8, name, "FindNextFileA")) return @intFromPtr(&FindNextFileA);
    if (std.mem.eql(u8, name, "FindFirstVolumeW")) return @intFromPtr(&FindFirstVolumeW);
    if (std.mem.eql(u8, name, "FindNextVolumeW")) return @intFromPtr(&FindNextVolumeW);
    if (std.mem.eql(u8, name, "FindVolumeClose")) return @intFromPtr(&FindVolumeClose);
    if (std.mem.eql(u8, name, "GetCompressedFileSizeA")) return @intFromPtr(&GetCompressedFileSizeA);
    if (std.mem.eql(u8, name, "GetDiskFreeSpaceExA")) return @intFromPtr(&GetDiskFreeSpaceExA);
    if (std.mem.eql(u8, name, "GetDiskFreeSpaceExW")) return @intFromPtr(&GetDiskFreeSpaceExW);
    if (std.mem.eql(u8, name, "GetDriveTypeA")) return @intFromPtr(&GetDriveTypeA);
    if (std.mem.eql(u8, name, "GetEnvironmentVariableW")) return @intFromPtr(&GetEnvironmentVariableW);
    if (std.mem.eql(u8, name, "SetEnvironmentVariableA")) return @intFromPtr(&SetEnvironmentVariableA);
    if (std.mem.eql(u8, name, "GetFileAttributesExA")) return @intFromPtr(&GetFileAttributesExA);
    if (std.mem.eql(u8, name, "SetFileAttributesA")) return @intFromPtr(&SetFileAttributesA);
    if (std.mem.eql(u8, name, "GetLogicalDrives")) return @intFromPtr(&GetLogicalDrives);
    if (std.mem.eql(u8, name, "GetModuleFileNameA")) return @intFromPtr(&GetModuleFileNameA);
    if (std.mem.eql(u8, name, "GetProcessAffinityMask")) return @intFromPtr(&GetProcessAffinityMask);
    if (std.mem.eql(u8, name, "GetProcessId")) return @intFromPtr(&GetProcessId);
    if (std.mem.eql(u8, name, "GetProcessTimes")) return @intFromPtr(&GetProcessTimes);
    if (std.mem.eql(u8, name, "GetSystemDirectoryA")) return @intFromPtr(&GetSystemDirectoryA);
    if (std.mem.eql(u8, name, "GetVersionExA")) return @intFromPtr(&GetVersionExA);
    if (std.mem.eql(u8, name, "GetVolumeInformationA")) return @intFromPtr(&GetVolumeInformationA);
    if (std.mem.eql(u8, name, "GetVolumeInformationW")) return @intFromPtr(&GetVolumeInformationW);
    if (std.mem.eql(u8, name, "IsWow64Process")) return @intFromPtr(&IsWow64Process);
    if (std.mem.eql(u8, name, "LoadLibraryExA")) return @intFromPtr(&LoadLibraryExA);
    if (std.mem.eql(u8, name, "MoveFileExA")) return @intFromPtr(&MoveFileExA);
    if (std.mem.eql(u8, name, "OpenProcess")) return @intFromPtr(&OpenProcess);
    if (std.mem.eql(u8, name, "ReadDirectoryChangesW")) return @intFromPtr(&ReadDirectoryChangesW);
    if (std.mem.eql(u8, name, "ReadProcessMemory")) return @intFromPtr(&ReadProcessMemory);
    if (std.mem.eql(u8, name, "SetErrorMode")) return @intFromPtr(&SetErrorMode);
    if (std.mem.eql(u8, name, "SetHandleInformation")) return @intFromPtr(&SetHandleInformation);
    if (std.mem.eql(u8, name, "SetSystemTime")) return @intFromPtr(&SetSystemTime);
    if (std.mem.eql(u8, name, "CreateEventW")) return @intFromPtr(&CreateEventW);
    if (std.mem.eql(u8, name, "SetEvent")) return @intFromPtr(&SetEvent);
    if (std.mem.eql(u8, name, "CreateSemaphoreW")) return @intFromPtr(&CreateSemaphoreW);
    if (std.mem.eql(u8, name, "ReleaseSemaphore")) return @intFromPtr(&ReleaseSemaphore);
    if (std.mem.eql(u8, name, "OpenMutexW")) return @intFromPtr(&OpenMutexW);
    if (std.mem.eql(u8, name, "AcquireSRWLockExclusive")) return @intFromPtr(&AcquireSRWLockExclusive);
    if (std.mem.eql(u8, name, "ReleaseSRWLockExclusive")) return @intFromPtr(&ReleaseSRWLockExclusive);
    if (std.mem.eql(u8, name, "TryAcquireSRWLockExclusive")) return @intFromPtr(&TryAcquireSRWLockExclusive);
    if (std.mem.eql(u8, name, "SleepConditionVariableSRW")) return @intFromPtr(&SleepConditionVariableSRW);
    if (std.mem.eql(u8, name, "WakeConditionVariable")) return @intFromPtr(&WakeConditionVariable);
    if (std.mem.eql(u8, name, "WakeAllConditionVariable")) return @intFromPtr(&WakeAllConditionVariable);
    if (std.mem.eql(u8, name, "InitializeCriticalSectionEx")) return @intFromPtr(&InitializeCriticalSectionEx);
    if (std.mem.eql(u8, name, "GetExitCodeThread")) return @intFromPtr(&GetExitCodeThread);
    if (std.mem.eql(u8, name, "VerSetConditionMask")) return @intFromPtr(&VerSetConditionMask);
    if (std.mem.eql(u8, name, "VerifyVersionInfoW")) return @intFromPtr(&VerifyVersionInfoW);
    if (std.mem.eql(u8, name, "lstrlenW")) return @intFromPtr(&lstrlenW);
    if (std.mem.eql(u8, name, "lstrcpyW")) return @intFromPtr(&lstrcpyW);
    if (std.mem.eql(u8, name, "lstrcmpW")) return @intFromPtr(&lstrcmpW);
    if (std.mem.eql(u8, name, "MulDiv")) return @intFromPtr(&MulDiv);
    if (std.mem.eql(u8, name, "MoveFileW")) return @intFromPtr(&MoveFileW);
    if (std.mem.eql(u8, name, "MoveFileExW")) return @intFromPtr(&MoveFileExW);
    if (std.mem.eql(u8, name, "GetWindowsDirectoryW")) return @intFromPtr(&GetWindowsDirectoryW);
    if (std.mem.eql(u8, name, "ExpandEnvironmentStringsW")) return @intFromPtr(&ExpandEnvironmentStringsW);
    if (std.mem.eql(u8, name, "CompareFileTime")) return @intFromPtr(&CompareFileTime);
    if (std.mem.eql(u8, name, "GetLocalTime")) return @intFromPtr(&GetLocalTime);
    if (std.mem.eql(u8, name, "GetDateFormatEx")) return @intFromPtr(&GetDateFormatEx);
    if (std.mem.eql(u8, name, "GetTimeFormatEx")) return @intFromPtr(&GetTimeFormatEx);
    if (std.mem.eql(u8, name, "GetLocaleInfoEx")) return @intFromPtr(&GetLocaleInfoEx);
    if (std.mem.eql(u8, name, "LCMapStringEx")) return @intFromPtr(&LCMapStringEx);
    if (std.mem.eql(u8, name, "LocalAlloc")) return @intFromPtr(&LocalAlloc);
    if (std.mem.eql(u8, name, "GetFileInformationByHandleEx")) return @intFromPtr(&GetFileInformationByHandleEx);
    if (std.mem.eql(u8, name, "SetFileInformationByHandle")) return @intFromPtr(&SetFileInformationByHandle);

    return null;
}
