//! WINS Foundation KERNEL32 Implementation
//! High-speed Win32 runtime emulation layer for x86_64 PE binaries.
//! Provides memory management (Heap), Thread-Local Storage (TLS/FLS),
//! synchronization, process/thread identity, timing, console, strings and file primitives.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const W: std.builtin.CallingConvention = .winapi;

const seh64 = if (builtin.cpu.arch == .x86_64) @import("winrun_seh64.zig") else struct {
    pub fn setExceptionTable(_: usize, _: usize, _: u32, _: u32) void {}
};

pub var image_base_addr: usize = 0;

/// The thread's Win32 last-error slot lives in winrun_impl (one per Impl mode);
/// its lookup() installs SetLastError here so kernel32 shims can report errors.
pub var last_error_hook: ?*const fn (u32) callconv(W) void = null;

fn setLastError(code: u32) void {
    if (last_error_hook) |f| f(code);
}

pub fn setImageBase(base: usize) void {
    image_base_addr = base;
}

pub fn setExceptionTable(base: usize, image_len: usize, pdata_rva: u32, pdata_size: u32) void {
    image_base_addr = base;
    seh64.setExceptionTable(base, image_len, pdata_rva, pdata_size);
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

/// MS_VC_EXCEPTION (0x406d1388) is how MSVC names threads: it is raised and
/// handled in-process, and execution continues after the call site. Ending
/// the guest on it kills every program that sets a thread name.
pub fn isThreadNamingException(code: u32) bool {
    return code == 0x406d1388;
}

fn RaiseException(code: u32, flags: u32, nargs: u32, args: ?[*]const usize) callconv(W) void {
    _ = flags;
    _ = args;
    if (isThreadNamingException(code)) return; // handled in-process; continue
    if (comptime builtin.link_libc) {
        if (std.c.getenv("WINS_TRACE") != null) {
            const ra = @returnAddress();
            const rva = if (image_base_addr != 0 and ra >= image_base_addr) ra - image_base_addr else 0;
            std.debug.print("[WINS:K32] RaiseException code=0x{x:0>8} nargs={d} ra=0x{x} rva=0x{x}\n", .{ code, nargs, ra, rva });
        }
    }
    linux.exit_group(@bitCast(code));
}

fn raiseExceptionAddr() usize {
    return if (builtin.cpu.arch == .x86_64) @intFromPtr(&seh64.raiseExceptionEntry) else @intFromPtr(&RaiseException);
}

fn RtlPcToFileHeader(pc: usize, base: ?*usize) callconv(W) usize {
    if (comptime builtin.cpu.arch == .x86_64) {
        _ = seh64.lookupFunctionEntry(pc, base, null);
        return if (base) |b| b.* else image_base_addr;
    } else {
        if (base) |b| b.* = image_base_addr;
        return image_base_addr;
    }
}

fn RtlUnwind(target_frame: ?*anyopaque, target_ip: ?*anyopaque, record: ?*anyopaque, return_val: ?*anyopaque) callconv(W) void {
    if (comptime builtin.cpu.arch == .x86_64) {
        seh64.unwindEx(@intFromPtr(target_frame), @intFromPtr(target_ip), @ptrCast(@alignCast(record)), @intFromPtr(return_val), null, null);
    }
}

fn RtlUnwindEx(target_frame: ?*anyopaque, target_ip: ?*anyopaque, record: ?*anyopaque, return_val: ?*anyopaque, ctx: ?*anyopaque, hist: ?*anyopaque) callconv(W) void {
    if (comptime builtin.cpu.arch == .x86_64) {
        seh64.unwindEx(@intFromPtr(target_frame), @intFromPtr(target_ip), @ptrCast(@alignCast(record)), @intFromPtr(return_val), @ptrCast(ctx), hist);
    }
}

fn RtlCaptureContext(ctx: ?*anyopaque) callconv(W) void {
    if (comptime builtin.cpu.arch == .x86_64) {
        if (ctx) |c| {
            seh64.callCaptureContext(@ptrCast(c));
        }
    }
}

fn rtlCaptureContextAddr() usize {
    return if (builtin.cpu.arch == .x86_64) @intFromPtr(&seh64.captureContextNaked) else @intFromPtr(&RtlCaptureContext);
}

fn RtlLookupFunctionEntry(pc: usize, base: ?*usize, hist: ?*anyopaque) callconv(W) ?*anyopaque {
    if (comptime builtin.cpu.arch == .x86_64) {
        return @ptrCast(@constCast(seh64.lookupFunctionEntry(pc, base, hist)));
    } else {
        if (base) |b| b.* = image_base_addr;
        return null;
    }
}

fn RtlVirtualUnwind(handler_type: u32, base: usize, pc: usize, entry: ?*anyopaque, ctx: ?*anyopaque, handler_data: ?*anyopaque, establisher_frame: ?*anyopaque, context_pointers: ?*anyopaque) callconv(W) usize {
    if (comptime builtin.cpu.arch == .x86_64) {
        const c = ctx orelse return 0;
        return seh64.virtualUnwind(
            handler_type,
            base,
            pc,
            @ptrCast(@alignCast(entry)),
            @ptrCast(c),
            @ptrCast(@alignCast(handler_data)),
            @ptrCast(@alignCast(establisher_frame)),
            context_pointers,
        );
    } else {
        return 0;
    }
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

/// The process heap handle (PEB.ProcessHeap must hold the same value).
pub fn processHeapHandle() usize {
    return HEAP_COOKIE;
}

/// Shared with winrun32.zig: a block is ours only if this magic is in front
/// of it. A free that cannot find the magic must not unmap: the address may
/// belong to the real Steam client.
const HEAP_MAGIC: u32 = 0x57494E53; // "WINS"
const HeapHeader = extern struct {
    magic: u32,
    total: u32,
    bytes: u32,
    pad: u32,
};

fn HeapAlloc(h: usize, flags: u32, bytes: usize) callconv(W) ?[*]u8 {
    _ = h;
    const total = std.mem.alignForward(usize, bytes + @sizeOf(HeapHeader), 4096);
    const mrc = linux.mmap(null, total, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
    if (linux.errno(mrc) != .SUCCESS) return null;
    const p: [*]u8 = @ptrFromInt(mrc);
    const hdr: *HeapHeader = @ptrCast(@alignCast(p));
    hdr.magic = HEAP_MAGIC;
    hdr.total = @intCast(total);
    hdr.bytes = @intCast(bytes);
    hdr.pad = 0;
    const user = p + @sizeOf(HeapHeader);
    if (flags & 0x00000008 != 0) { // HEAP_ZERO_MEMORY
        @memset(user[0..bytes], 0);
    }
    return user;
}

fn heapHeaderFromUser(ptr: ?[*]u8) ?struct { base: [*]u8, hdr: *const HeapHeader } {
    const p_user = ptr orelse return null;
    const addr = @intFromPtr(p_user);
    if (addr < 0x10000 + @sizeOf(HeapHeader)) return null;
    const base_addr = addr - @sizeOf(HeapHeader);
    // HeapAlloc is mmap-backed so every header sits on a 4 KiB page boundary.
    if ((base_addr & 0xfff) != 0) return null;
    const p: [*]u8 = @ptrFromInt(base_addr);
    const hdr: *const HeapHeader = @ptrCast(@alignCast(p));
    if (hdr.magic != HEAP_MAGIC) return null;
    return .{ .base = p, .hdr = hdr };
}

fn HeapFree(h: usize, flags: u32, ptr: ?[*]u8) callconv(W) u32 {
    _ = h;
    _ = flags;
    if (ptr == null) return 1;
    const info = heapHeaderFromUser(ptr) orelse return 0;
    _ = linux.munmap(info.base, info.hdr.total);
    return 1;
}

fn HeapReAlloc(h: usize, flags: u32, ptr: ?[*]u8, bytes: usize) callconv(W) ?[*]u8 {
    if (ptr == null) return HeapAlloc(h, flags, bytes);
    const info = heapHeaderFromUser(ptr) orelse return null;
    const old_bytes = info.hdr.bytes;
    const new_ptr = HeapAlloc(h, flags, bytes) orelse return null;
    const copy_len = @min(old_bytes, bytes);
    if (copy_len > 0) @memcpy(new_ptr[0..copy_len], ptr.?[0..copy_len]);
    _ = HeapFree(h, 0, ptr);
    return new_ptr;
}

fn HeapSize(h: usize, flags: u32, ptr: ?[*]u8) callconv(W) usize {
    _ = h;
    _ = flags;
    const info = heapHeaderFromUser(ptr) orelse return 0;
    return info.hdr.bytes;
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

pub var teb_tls_enabled: bool = false;
var tls_alloc_lock: std.atomic.Value(bool) = .init(false);
var tls_used: [256]bool = [_]bool{false} ** 256;
threadlocal var tls_ext_slots: [256]usize = [_]usize{0} ** 256;

var fls_used: [256]bool = [_]bool{false} ** 256;
threadlocal var fls_slots: [256]usize = [_]usize{0} ** 256;

fn lockTlsAlloc() void {
    while (tls_alloc_lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
        std.atomic.spinLoopHint();
    }
}

fn unlockTlsAlloc() void {
    tls_alloc_lock.store(false, .release);
}

fn currentTebAddr() usize {
    if (!teb_tls_enabled) return 0;
    var teb: usize = 0;
    asm volatile ("mov %%gs:0x30, %[out]" : [out] "=r" (teb));
    return teb;
}

fn TlsAlloc() callconv(W) u32 {
    lockTlsAlloc();
    defer unlockTlsAlloc();
    for (&tls_used, 0..) |*u, i| {
        if (!u.*) {
            u.* = true;
            if (i < 64) {
                const teb = currentTebAddr();
                if (teb != 0) @as(*usize, @ptrFromInt(teb + 0x1480 + i * 8)).* = 0;
            }
            tls_ext_slots[i] = 0;
            return @intCast(i);
        }
    }
    return 0xFFFFFFFF; // TLS_OUT_OF_INDEXES
}

fn TlsGetValue(idx: u32) callconv(W) usize {
    if (idx < 256 and tls_used[idx]) {
        if (idx < 64) {
            const teb = currentTebAddr();
            if (teb != 0) return @as(*const usize, @ptrFromInt(teb + 0x1480 + @as(usize, idx) * 8)).*;
        }
        return tls_ext_slots[idx];
    }
    return 0;
}

fn TlsSetValue(idx: u32, val: usize) callconv(W) u32 {
    if (idx < 256 and tls_used[idx]) {
        if (idx < 64) {
            const teb = currentTebAddr();
            if (teb != 0) {
                @as(*usize, @ptrFromInt(teb + 0x1480 + @as(usize, idx) * 8)).* = val;
            }
        }
        tls_ext_slots[idx] = val;
        return 1;
    }
    return 0;
}

fn TlsFree(idx: u32) callconv(W) u32 {
    lockTlsAlloc();
    defer unlockTlsAlloc();
    if (idx < 256) {
        tls_used[idx] = false;
        if (idx < 64) {
            const teb = currentTebAddr();
            if (teb != 0) @as(*usize, @ptrFromInt(teb + 0x1480 + @as(usize, idx) * 8)).* = 0;
        }
        tls_ext_slots[idx] = 0;
        return 1;
    }
    return 0;
}

fn FlsAlloc(cb: ?*anyopaque) callconv(W) u32 {
    _ = cb;
    lockTlsAlloc();
    defer unlockTlsAlloc();
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
    lockTlsAlloc();
    defer unlockTlsAlloc();
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
    // timespec's field width follows the target, so derive it instead of forcing i64.
    const Sec = @typeInfo(@TypeOf(@as(linux.timespec, undefined).sec)).int.signedness;
    _ = Sec;
    const sec: @TypeOf(@as(linux.timespec, undefined).sec) = @intCast(ms / 1000);
    const nsec: @TypeOf(@as(linux.timespec, undefined).nsec) = @intCast(ms % 1000 * 1_000_000);
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

/// CPINFO { UINT MaxCharSize; BYTE DefaultChar[2]; BYTE LeadByte[12]; }.
/// MaxCharSize must be real: the MSVC CRT derives MB_CUR_MAX from it and
/// mbtowc(n = 0) fails, so a zeroed CPINFO broke every "%hS" in DS3 (its
/// Scaleform image URLs all came out as L"S").
fn GetCPInfo(cp: u32, lpInfo: ?[*]u8) callconv(W) u32 {
    const p = lpInfo orelse return 0;
    @memset(p[0..18], 0);
    const real = switch (cp) {
        0, 1, 2, 3 => GetACP(), // CP_ACP, CP_OEMCP, CP_MACCP, CP_THREAD_ACP
        else => cp,
    };
    const max: u32 = switch (real) {
        65001 => 4, // UTF-8
        65000 => 5, // UTF-7
        932, 936, 949, 950, 1361 => 2, // DBCS
        else => 1,
    };
    std.mem.writeInt(u32, p[0..4], max, .little);
    p[4] = '?';
    switch (real) { // DBCS lead-byte ranges, terminated by a zero pair
        932 => { p[6] = 0x81; p[7] = 0x9F; p[8] = 0xE0; p[9] = 0xFC; },
        936, 949, 950 => { p[6] = 0x81; p[7] = 0xFE; },
        else => {},
    }
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
    const in = src orelse return 0;
    if (cch_src == 0) return 0;
    const n: usize = if (cch_src > 0) @intCast(cch_src) else blk: {
        var k: usize = 0;
        while (in[k] != 0) k += 1;
        break :blk k + 1;
    };
    if (cch_dest == 0 or dest == null) return @intCast(n);
    if (@as(usize, @intCast(cch_dest)) < n) return 0; // ERROR_INSUFFICIENT_BUFFER
    const LOWER: u32 = 0x100;
    const UPPER: u32 = 0x200;
    for (0..n) |i| {
        var c = in[i];
        if (flags & UPPER != 0) {
            if ((c >= 'a' and c <= 'z') or (c >= 0xE0 and c <= 0xFE and c != 0xF7)) c -= 0x20;
        } else if (flags & LOWER != 0) {
            if ((c >= 'A' and c <= 'Z') or (c >= 0xC0 and c <= 0xDE and c != 0xD7)) c += 0x20;
        }
        dest.?[i] = c;
    }
    return @intCast(n);
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

/// CT_CTYPE1 classes for one UTF-16 unit (ASCII + Latin-1; other letters as
/// C1_ALPHA). The MSVC CRT builds its ctype tables from this.
fn ctype1(c: u16) u16 {
    const UPPER: u16 = 0x1;
    const LOWER: u16 = 0x2;
    const DIGIT: u16 = 0x4;
    const SPACE: u16 = 0x8;
    const PUNCT: u16 = 0x10;
    const CNTRL: u16 = 0x20;
    const BLANK: u16 = 0x40;
    const XDIGIT: u16 = 0x80;
    const ALPHA: u16 = 0x100;
    const DEFINED: u16 = 0x200;
    var t: u16 = DEFINED;
    switch (c) {
        'A'...'Z' => t |= UPPER | ALPHA | (if (c <= 'F') XDIGIT else 0),
        'a'...'z' => t |= LOWER | ALPHA | (if (c <= 'f') XDIGIT else 0),
        '0'...'9' => t |= DIGIT | XDIGIT,
        ' ' => t |= SPACE | BLANK,
        '\t' => t |= SPACE | BLANK | CNTRL,
        0x0A, 0x0B, 0x0C, 0x0D => t |= SPACE | CNTRL,
        0x00...0x08, 0x0E...0x1F, 0x7F...0x9F => t |= CNTRL,
        0xA0 => t |= SPACE | BLANK,
        0xC0...0xD6, 0xD8...0xDE => t |= UPPER | ALPHA,
        0xDF...0xF6, 0xF8...0xFF => t |= LOWER | ALPHA,
        0x21...0x2F, 0x3A...0x40, 0x5B...0x60, 0x7B...0x7E, 0xA1...0xBF, 0xD7, 0xF7 => t |= PUNCT,
        else => t |= ALPHA,
    }
    return t;
}

fn GetStringTypeW(flags: u32, src: ?[*]const u16, cch: i32, chartype: ?[*]u16) callconv(W) u32 {
    const in = src orelse return 0;
    const out = chartype orelse return 0;
    const n: usize = if (cch >= 0) @intCast(cch) else blk: {
        var k: usize = 0;
        while (in[k] != 0) k += 1;
        break :blk k + 1;
    };
    for (0..n) |i| {
        const c = in[i];
        out[i] = switch (flags) {
            1 => ctype1(c), // CT_CTYPE1
            2 => if (c < 0x80) (if (c >= '0' and c <= '9') @as(u16, 3) else if (ctype1(c) & 0x100 != 0) @as(u16, 1) else if (c == ' ') @as(u16, 10) else @as(u16, 0)) else 1, // CT_CTYPE2: L1 / EN / WS
            4 => if (ctype1(c) & 0x100 != 0) @as(u16, 0x8000) else 0, // CT_CTYPE3: C3_ALPHA
            else => 0,
        };
    }
    return 1;
}

fn formatErrorText(dwMessageId: u32, buf: []u8) []const u8 {
    return switch (dwMessageId) {
        0 => "The operation completed successfully.",
        2 => "The system cannot find the file specified.",
        3 => "The system cannot find the path specified.",
        5 => "Access is denied.",
        6 => "The handle is invalid.",
        8 => "Not enough storage is available to process this command.",
        87 => "The parameter is incorrect.",
        126 => "The specified module could not be found.",
        127 => "The specified procedure could not be found.",
        else => std.fmt.bufPrint(buf, "Win32 error {d}.", .{dwMessageId}) catch "Win32 error.",
    };
}

// x86_stdcall cannot be variadic (Zig rejects it), and 7zr never calls these
// with more than the first four arguments, so a fixed signature is faithful here.
fn FormatMessageW(dwFlags: u32, lpSource: ?*const anyopaque, dwMessageId: u32, dwLanguageId: u32, lpBuffer: ?[*]u16, nSize: u32, Arguments: ?*const anyopaque) callconv(W) u32 {
    _ = lpSource;
    _ = dwLanguageId;
    _ = Arguments;
    const buf_ptr = lpBuffer orelse return 0;
    const FORMAT_MESSAGE_ALLOCATE_BUFFER: u32 = 0x0100;
    var tmp: [128]u8 = undefined;
    const msg = formatErrorText(dwMessageId, &tmp);
    if ((dwFlags & FORMAT_MESSAGE_ALLOCATE_BUFFER) != 0) {
        const cap = @max(msg.len + 1, @as(usize, nSize));
        const raw = LocalAlloc(0, cap * 2) orelse return 0;
        const out: [*]u16 = @ptrCast(@alignCast(raw));
        for (msg, 0..) |ch, i| out[i] = ch;
        out[msg.len] = 0;
        const pp: *[*]u16 = @ptrCast(@alignCast(buf_ptr));
        pp.* = out;
        return @intCast(msg.len);
    }
    if (nSize == 0) return 0;
    const copy_len = @min(msg.len, @as(usize, nSize) - 1);
    for (msg[0..copy_len], 0..) |ch, i| buf_ptr[i] = ch;
    buf_ptr[copy_len] = 0;
    return @intCast(copy_len);
}

fn FormatMessageA(dwFlags: u32, lpSource: ?*const anyopaque, dwMessageId: u32, dwLanguageId: u32, lpBuffer: ?[*]u8, nSize: u32, Arguments: ?*const anyopaque) callconv(W) u32 {
    _ = lpSource;
    _ = dwLanguageId;
    _ = Arguments;
    const buf_ptr = lpBuffer orelse return 0;
    const FORMAT_MESSAGE_ALLOCATE_BUFFER: u32 = 0x0100;
    var tmp: [128]u8 = undefined;
    const msg = formatErrorText(dwMessageId, &tmp);
    if ((dwFlags & FORMAT_MESSAGE_ALLOCATE_BUFFER) != 0) {
        const cap = @max(msg.len + 1, @as(usize, nSize));
        const out = LocalAlloc(0, cap) orelse return 0;
        @memcpy(out[0..msg.len], msg);
        out[msg.len] = 0;
        const pp: *[*]u8 = @ptrCast(@alignCast(buf_ptr));
        pp.* = out;
        return @intCast(msg.len);
    }
    if (nSize == 0) return 0;
    const copy_len = @min(msg.len, @as(usize, nSize) - 1);
    @memcpy(buf_ptr[0..copy_len], msg[0..copy_len]);
    buf_ptr[copy_len] = 0;
    return @intCast(copy_len);
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
    if (h != 0 and h != image_base_addr) return 0;
    if (!module_path_initialized) return 0;
    const mlen: usize = @min(module_path_len, if (n > 0) @as(usize, n) - 1 else 0);
    if (buf != null and n > 0) {
        for (0..mlen) |i| buf.?[i] = module_path_a[i];
        buf.?[mlen] = 0;
    }
    return @intCast(mlen);
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


/// The four names 7zr resolves dynamically through GetProcAddress. Without
/// them it gets NULL for all of them and takes the pre-Vista code paths, which
/// is not what the binary was built for.
fn SetDefaultDllDirectories(directoryFlags: u32) callconv(W) i32 {
    // The DLL search-path hardening this API controls is not modelled here, so
    // reporting failure lets the caller keep the default search order -- which
    // is exactly what this loader does anyway. Claiming success would be a lie.
    _ = directoryFlags;
    return 0; // failure: search-path hardening is not modelled
}

fn FindNextStreamW(findStreamHandle: usize, lpFindStreamData: ?*anyopaque) callconv(W) i32 {
    _ = findStreamHandle;
    // No alternate data streams are modelled; the call reports "no more" the way
    // a file with a single unnamed stream would.
    if (lpFindStreamData) |p| @memset(@as([*]u8, @ptrCast(p))[0..96], 0);
    return 0; // no further streams
}

fn NtSetInformationFile(handle: usize, ioStatus: ?*anyopaque, fileInformation: ?*const anyopaque, length: u32, fileInformationClass: u32) callconv(W) i32 {
    _ = handle;
    _ = ioStatus;
    _ = fileInformation;
    _ = length;
    _ = fileInformationClass;
    return 0; // STATUS_SUCCESS
}

fn RtlNtStatusToDosError(status: u32) callconv(W) u32 {
    return status; // pass through; no NTSTATUS table is modelled
}

// ---------------------------------------------------------------------------
// 7b. Remaining KERNEL32 imports 7zr.exe needs.
// Each is implemented or explicitly documented as a no-op.
// ---------------------------------------------------------------------------

fn SetFileApisToOEM() callconv(W) void {}

fn CreateHardLinkW(name: ?[*:0]const u16, existing: ?[*:0]const u16, sa: ?*const anyopaque) callconv(W) i32 {
    _ = name;
    _ = existing;
    _ = sa;
    return 0; // failure: hard links are not emulated
}

fn MoveFileWithProgressW(src: ?[*:0]const u16, dst: ?[*:0]const u16, progress: ?*const anyopaque, flags: u32) callconv(W) i32 {
    // Moves are not emulated; failing is the honest answer. Returning success
    // would make the guest believe it moved a file it did not move.
    _ = src;
    _ = dst;
    _ = progress;
    _ = flags;
    return 0;
}

fn SetProcessAffinityMask(hProc: usize, mask: usize) callconv(W) i32 {
    _ = hProc;
    _ = mask;
    return 1; // accepted; the affinity is not actually applied
}

fn GetLogicalDriveStringsW(n: u32, buf: ?[*]u16) callconv(W) u32 {
    _ = n;
    // "c:\" then a final empty string is the minimum honest drive table.
    if (buf) |b| {
        b[0] = 'c';
        b[1] = ':';
        b[2] = '\\';
        b[3] = 0;
        b[4] = 0;
    }
    return 7;
}

/// OpenEventW: no named events exist in this loader, so every query fails.
fn OpenEventW(access: u32, inherit: i32, name: ?[*:0]const u16) callconv(W) usize {
    _ = access;
    _ = inherit;
    _ = name;
    return 0;
}

/// OpenFileMappingW: same reasoning as OpenEventW. The SteamStart_* names the
/// i386 loader special-cases live in winrun32.zig's local table, not here.
fn OpenFileMappingW(access: u32, inherit: i32, name: ?[*:0]const u16) callconv(W) usize {
    _ = access;
    _ = inherit;
    _ = name;
    return 0;
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
    if (fdFromHandle(h)) |fd| _ = linux.fsync(fd);
    return 1;
}

fn SetEndOfFile(h: usize) callconv(W) u32 {
    const fd = fdFromHandle(h) orelse {
        setLastError(6);
        return 0;
    };
    const pos = hostLseek(fd, 0, 1) orelse return 0; // SEEK_CUR
    const e = linux.errno(linux.ftruncate(fd, pos));
    if (e == .SUCCESS) return 1;
    setLastError(win32ErrorFromErrno(e));
    return 0;
}

/// std's linux.lseek is 64-bit only: it bitcasts the i64 offset straight into
/// the syscall's offset slot, which does not compile for a 32-bit target. On
/// i386 use _llseek (140), which takes the offset as high/low halves plus a
/// result pointer, so 64-bit file offsets stay correct on both ABIs.
fn hostLseek(fd: i32, offset: i64, whence: usize) ?i64 {
    if (@sizeOf(usize) == 8) {
        const rc = linux.lseek(fd, offset, whence);
        if (linux.errno(rc) != .SUCCESS) return null;
        return @intCast(rc);
    }
    var result: i64 = 0;
    const raw: u64 = @bitCast(offset);
    const rc = linux.syscall5(
        .llseek,
        @as(usize, @bitCast(@as(isize, fd))),
        @as(usize, @truncate(raw >> 32)),
        @as(usize, @truncate(raw)),
        @intFromPtr(&result),
        whence,
    );
    if (linux.errno(rc) != .SUCCESS) return null;
    return result;
}

fn fdFromHandle(h: usize) ?i32 {
    if (h == 0xFFFFFFF6) return 0;
    if (h == 0xFFFFFFF5) return 1;
    if (h == 0xFFFFFFF4) return 2;
    if (h >= 0x1000 and h < 0x5000) return @intCast(h - 0x1000);
    return null;
}

fn SetFilePointerEx(h: usize, dist: i64, new_pos: ?*i64, method: u32) callconv(W) u32 {
    const fd = fdFromHandle(h) orelse return 0;
    const whence: u32 = switch (method) {
        0 => 0, // SEEK_SET
        1 => 1, // SEEK_CUR
        2 => 2, // SEEK_END
        else => return 0,
    };
    const pos = hostLseek(fd, dist, whence) orelse return 0;
    if (new_pos) |p| p.* = pos;
    return 1;
}

fn SetFilePointer(h: usize, dist: i32, dist_high: ?*i32, method: u32) callconv(W) u32 {
    var d: i64 = dist;
    if (dist_high) |dh| {
        d = (@as(i64, dh.*) << 32) | @as(u32, @bitCast(dist));
    }
    var new_pos: i64 = 0;
    const ok = SetFilePointerEx(h, d, &new_pos, method);
    if (ok == 0) return 0xFFFFFFFF;
    if (dist_high) |dh| dh.* = @intCast(new_pos >> 32);
    return @intCast(@as(u64, @bitCast(new_pos)) & 0xFFFFFFFF);
}

fn GetFileSize(h: usize, high: ?*u32) callconv(W) u32 {
    var sz: i64 = 0;
    if (GetFileSizeEx(h, &sz) == 0) return 0xFFFFFFFF;
    const u: u64 = @bitCast(sz);
    if (high) |hi| hi.* = @truncate(u >> 32);
    return @truncate(u);
}

fn GetFileSizeEx(h: usize, size: ?*i64) callconv(W) u32 {
    const fd = fdFromHandle(h) orelse return 0;
    var stx: linux.Statx = undefined;
    const rc = linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .SIZE = true }, &stx);
    if (linux.errno(rc) != .SUCCESS) return 0;
    if (size) |s| s.* = @intCast(stx.size);
    return 1;
}

fn GetFileType(h: usize) callconv(W) u32 {
    return switch (h) {
        0xFFFFFFF6, 0xFFFFFFF5, 0xFFFFFFF4 => 0x0002, // FILE_TYPE_CHAR
        else => 0x0001, // FILE_TYPE_DISK
    };
}

pub var close_handle_hook: ?*const fn (usize) bool = null;

fn CloseHandle(h: usize) callconv(W) u32 {
    if (close_handle_hook) |hook| {
        if (hook(h)) return 1;
    }
    if (closeMappingHandle(h)) return 1;
    if (h >= 0x1003 and h < 0x5000) {
        _ = linux.close(@intCast(h - 0x1000));
    }
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
var module_path_a: [512:0]u8 = [_:0]u8{0} ** 512;
var module_path_len: usize = 0;
var module_path_initialized: bool = false;

pub fn setCommandLine(args: []const []const u8) void {
    if (args.len == 0) return;
    // Record canonical Windows-mapped module path for GetModuleFileNameA/W.
    {
        const raw = args[0];
        var mpos: usize = 0;
        const prefix = if (raw.len >= 2 and raw[1] == ':') "" else if (raw.len > 0 and raw[0] == '/') "Z:" else "Z:\\";
        for (prefix) |c| {
            if (mpos < module_path_a.len - 1) {
                module_path_a[mpos] = c;
                mpos += 1;
            }
        }
        for (raw) |c| {
            if (mpos < module_path_a.len - 1) {
                module_path_a[mpos] = if (c == '/') '\\' else c;
                mpos += 1;
            }
        }
        module_path_a[mpos] = 0;
        module_path_len = mpos;
        module_path_initialized = true;
    }
    var out_pos: usize = 0;
    const cap = cmdline_storage_a.len - 1;
    const push = struct {
        fn byte(pos: *usize, max_cap: usize, b: u8) void {
            if (pos.* < max_cap) {
                cmdline_storage_a[pos.*] = b;
                pos.* += 1;
            }
        }
    }.byte;
    for (args, 0..) |arg, idx| {
        if (idx > 0) push(&out_pos, cap, ' ');
        const needs_quotes = arg.len == 0 or
            std.mem.indexOfAny(u8, arg, " \t\"") != null;
        if (!needs_quotes) {
            for (arg) |c| push(&out_pos, cap, c);
            continue;
        }
        push(&out_pos, cap, '"');
        var backslashes: usize = 0;
        for (arg) |c| {
            if (c == '\\') {
                backslashes += 1;
            } else if (c == '"') {
                for (0..(backslashes * 2 + 1)) |_| push(&out_pos, cap, '\\');
                push(&out_pos, cap, '"');
                backslashes = 0;
            } else {
                for (0..backslashes) |_| push(&out_pos, cap, '\\');
                push(&out_pos, cap, c);
                backslashes = 0;
            }
        }
        for (0..(backslashes * 2)) |_| push(&out_pos, cap, '\\');
        push(&out_pos, cap, '"');
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

fn firstWinCommandToken(input: []const u8) []const u8 {
    var start: usize = 0;
    while (start < input.len and (input[start] == ' ' or input[start] == '\t')) : (start += 1) {}
    if (start == input.len) return input[0..0];
    if (input[start] == '"') {
        start += 1;
        const end = std.mem.indexOfScalarPos(u8, input, start, '"') orelse input.len;
        return input[start..end];
    }
    var end = start;
    while (end < input.len and input[end] != ' ' and input[end] != '\t') : (end += 1) {}
    return input[start..end];
}

fn GetEnvironmentStringsW() callconv(W) ?[*]const u16 {
    rebuildEnvironmentBlocks();
    return &env_block_w;
}

fn FreeEnvironmentStringsW(p: ?[*]const u16) callconv(W) u32 {
    _ = p;
    return 1;
}

const EnvEntry = struct { name: []u8, value: ?[]u8 };
var env_entries: std.ArrayListUnmanaged(EnvEntry) = .empty;
var env_lock = std.atomic.Value(u32).init(0);
var env_block_w: [32768]u16 = [_]u16{0} ** 32768;
fn lockEnv() void { while (env_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint(); }
fn unlockEnv() void { env_lock.store(0, .release); }
fn envNameEq(a: []const u8, b: []const u8) bool { return std.ascii.eqlIgnoreCase(a, b); }
fn setEnvValue(name: []const u8, value: ?[]const u8) bool {
    if (name.len == 0 or std.mem.indexOfScalar(u8, name, '=') != null) { setLastError(87); return false; }
    if (name.len > 512 or (if (value) |v| v.len > 1023 else false)) { setLastError(203); return false; }
    lockEnv(); defer unlockEnv();
    const alloc = std.heap.page_allocator;
    for (env_entries.items) |*e| if (envNameEq(e.name, name)) {
        if (value) |v| { e.value = alloc.dupe(u8, v) catch { setLastError(8); return false; }; } else e.value = null;
        return true;
    };
    env_entries.append(alloc, .{ .name = alloc.dupe(u8, name) catch { setLastError(8); return false; }, .value = if (value) |v| alloc.dupe(u8, v) catch { setLastError(8); return false; } else null }) catch { setLastError(8); return false; };
    return true;
}
fn getEnvA(name: []const u8, buf: ?[*]u8, size: u32) u32 {
    lockEnv(); defer unlockEnv();
    for (env_entries.items) |e| if (e.value) |v| if (envNameEq(e.name, name)) {
        if (buf == null or size <= v.len) return @intCast(v.len + 1);
        @memcpy(buf.?[0..v.len], v); buf.?[v.len] = 0; return @intCast(v.len);
    };
    return 0;
}
fn rebuildEnvironmentBlocks() void {
    lockEnv(); defer unlockEnv();
    @memset(&env_block_w, 0);
    var at: usize = 0;
    for (env_entries.items) |e| if (e.value) |v| {
        if (at + e.name.len + v.len + 1 >= env_block_w.len - 2) break;
        var text: [1536]u8 = undefined;
        @memcpy(text[0..e.name.len], e.name); text[e.name.len] = '='; @memcpy(text[e.name.len + 1 ..][0..v.len], v);
        const n = std.unicode.utf8ToUtf16Le(env_block_w[at .. env_block_w.len - 2 - at], text[0 .. e.name.len + v.len + 1]) catch continue;
        at += n; if (at + 1 >= env_block_w.len) break; env_block_w[at] = 0; at += 1;
    };
}

/// WINS_DEBUGSTR=1: print the game's OutputDebugString text (first 400 lines).
var g_dbgstr_n = std.atomic.Value(u32).init(0);
fn dbgStrOn() bool {
    const C = struct { var init = false; var on = false; };
    if (!C.init) {
        C.init = true;
        C.on = std.c.getenv("WINS_DEBUGSTR") != null;
    }
    return C.on and g_dbgstr_n.fetchAdd(1, .monotonic) < 400;
}

fn OutputDebugStringA(str: ?[*:0]const u8) callconv(W) void {
    const z = str orelse return;
    if (!dbgStrOn()) return;
    std.debug.print("[GAME_DEBUG] {s}\n", .{std.mem.trimEnd(u8, std.mem.sliceTo(z, 0), "\r\n")});
}

fn OutputDebugStringW(str: ?[*:0]const u16) callconv(W) void {
    const z = str orelse return;
    if (!dbgStrOn()) return;
    var buf: [1024]u8 = undefined;
    var n: usize = 0;
    for (std.mem.sliceTo(z, 0)) |c| {
        if (n >= buf.len) break;
        buf[n] = if (c < 0x80) @intCast(c) else '?';
        n += 1;
    }
    std.debug.print("[GAME_DEBUG] {s}\n", .{std.mem.trimEnd(u8, buf[0..n], "\r\n")});
}

fn AreFileApisANSI() callconv(W) u32 {
    return 1;
}

/// Logical CPUs this process may run on (sched_getaffinity), clamped to one
/// processor group (1..64). DS3 sizes its per-worker D3D11 deferred-context
/// array from this and its render-job pool always takes 6 of them: the old
/// hardcoded 4 left the pool reading past the array end (garbage contexts).
pub fn cpuCount() u32 {
    var set: linux.cpu_set_t = undefined;
    @memset(std.mem.asBytes(&set), 0);
    const rc = linux.syscall3(.sched_getaffinity, 0, @sizeOf(linux.cpu_set_t), @intFromPtr(&set));
    if (linux.errno(rc) != .SUCCESS) return 4;
    var n: u32 = 0;
    for (set) |w| n += @popCount(w);
    return std.math.clamp(n, 1, 64);
}
fn cpuMask(n: u32) u64 {
    return if (n >= 64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(n)) - 1;
}

fn GetSystemInfo(si: ?[*]u8) callconv(W) void {
    if (si) |p| {
        @memset(p[0..48], 0);
        std.mem.writeInt(u16, p[0..2], 9, .little); // PROCESSOR_ARCHITECTURE_AMD64
        std.mem.writeInt(u32, p[4..8], 4096, .little); // dwPageSize
        std.mem.writeInt(u64, p[8..16], 0x10000, .little); // lpMinimumApplicationAddress
        std.mem.writeInt(u64, p[16..24], 0x00007FFFFFFEFFFF, .little); // lpMaximumApplicationAddress
        const n = cpuCount();
        std.mem.writeInt(u64, p[24..32], cpuMask(n), .little); // dwActiveProcessorMask
        std.mem.writeInt(u32, p[32..36], n, .little); // dwNumberOfProcessors
        std.mem.writeInt(u32, p[36..40], 8664, .little); // PROCESSOR_AMD_X8664
        std.mem.writeInt(u32, p[40..44], 65536, .little); // dwAllocationGranularity
        std.mem.writeInt(u16, p[44..46], 6, .little); // wProcessorLevel
        std.mem.writeInt(u16, p[46..48], 0x0101, .little); // wProcessorRevision
    }
}

fn GetLogicalProcessorInformation(buf: ?[*]u8, ret_len: ?*u32) callconv(W) i32 {
    const rl = ret_len orelse {
        setLastError(87);
        return 0;
    };
    // n RelationProcessorCore (one logical each) + 1 RelationNumaNode + 1 RelationProcessorPackage (x64 = 32 B each)
    const n = cpuCount();
    const need: u32 = (n + 2) * 32;
    const avail = rl.*;
    rl.* = need;
    if (buf == null or avail < need) {
        setLastError(122); // ERROR_INSUFFICIENT_BUFFER
        return 0;
    }
    const p = buf.?;
    @memset(p[0..need], 0);
    for (0..n) |i| {
        const off = i * 32;
        std.mem.writeInt(u64, p[off..][0..8], @as(u64, 1) << @intCast(i), .little);
        std.mem.writeInt(u32, p[off + 8 ..][0..4], 0, .little); // RelationProcessorCore
    }
    const numa = n * 32;
    std.mem.writeInt(u64, p[numa..][0..8], cpuMask(n), .little);
    std.mem.writeInt(u32, p[numa + 8 ..][0..4], 1, .little); // RelationNumaNode
    const pkg = numa + 32;
    std.mem.writeInt(u64, p[pkg..][0..8], cpuMask(n), .little);
    std.mem.writeInt(u32, p[pkg + 8 ..][0..4], 3, .little); // RelationProcessorPackage
    return 1;
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

fn asciiPrefixIgnoreCase(hay: []const u8, prefix: []const u8) bool {
    if (hay.len < prefix.len) return false;
    for (prefix, 0..) |p, idx| {
        if (std.ascii.toLower(hay[idx]) != std.ascii.toLower(p)) return false;
    }
    return true;
}

fn envOr(name: [*:0]const u8, fallback: []const u8) []const u8 {
    if (comptime builtin.link_libc) {
        if (std.c.getenv(name)) |v| return std.mem.span(v);
    }
    return fallback;
}

/// Translate Windows PE paths (UNC/\\?\ prefixes, Z:\ -> /, C:\Users\User\AppData\Roaming -> $APPDATA,
/// C:\Users\User\AppData\Local -> $LOCALAPPDATA, C:\Temp -> /tmp, C:\ -> /tmp/wins-c/) to Linux paths.
pub fn translateWinPath(raw_utf8: []const u8, out: *[1024]u8) ?[:0]const u8 {
    var norm: [1024]u8 = undefined;
    var nlen: usize = 0;
    for (raw_utf8) |ch| {
        if (nlen >= norm.len - 1) break;
        norm[nlen] = if (ch == '\\') '/' else ch;
        nlen += 1;
    }
    var s = norm[0..nlen];
    if (std.mem.startsWith(u8, s, "//?/") or std.mem.startsWith(u8, s, "//./")) {
        s = s[4..];
    }
    if (s.len == 0) return null;

    var pos: usize = 0;
    const append = struct {
        fn slice(dst: *[1024]u8, p: *usize, src: []const u8) void {
            const avail = (dst.len - 1) -| p.*;
            const n = @min(avail, src.len);
            @memcpy(dst[p.*..][0..n], src[0..n]);
            p.* += n;
        }
    }.slice;

    if (s.len >= 2 and s[1] == ':' and std.ascii.isAlphabetic(s[0])) {
        const drive = std.ascii.toLower(s[0]);
        const rest = s[2..];
        if (drive == 'z') {
            if (rest.len == 0) {
                append(out, &pos, "/");
            } else {
                append(out, &pos, rest);
            }
        } else if (drive == 'c') {
            if (asciiPrefixIgnoreCase(rest, "/Users/User/AppData/Roaming")) {
                append(out, &pos, envOr("APPDATA", "/tmp/wins-appdata"));
                append(out, &pos, rest["/Users/User/AppData/Roaming".len..]);
            } else if (asciiPrefixIgnoreCase(rest, "/Users/User/AppData/Local")) {
                append(out, &pos, envOr("LOCALAPPDATA", "/tmp/wins-localappdata"));
                append(out, &pos, rest["/Users/User/AppData/Local".len..]);
            } else if (asciiPrefixIgnoreCase(rest, "/Users/User")) {
                append(out, &pos, envOr("USERPROFILE", "/tmp"));
                append(out, &pos, rest["/Users/User".len..]);
            } else if (asciiPrefixIgnoreCase(rest, "/Temp") and (rest.len == 5 or rest[5] == '/')) {
                append(out, &pos, "/tmp");
                append(out, &pos, rest[5..]);
            } else {
                append(out, &pos, "/tmp/wins-c");
                append(out, &pos, rest);
            }
        } else {
            append(out, &pos, "/tmp/wins-drive-");
            const d: [1]u8 = .{drive};
            append(out, &pos, &d);
            append(out, &pos, rest);
        }
    } else {
        append(out, &pos, s);
    }
    out[pos] = 0;
    return resolveCaseInsensitiveInPlace(out, pos);
}

/// If `out[0..pos]` exists as-is, return it immediately; otherwise walk
/// existing parent directories matching components case-insensitively on Linux.
fn resolveCaseInsensitiveInPlace(out: *[1024]u8, len_in: usize) [:0]const u8 {
    if (len_in == 0) return out[0..0 :0];
    var stx: linux.Statx = undefined;
    if (linux.errno(linux.statx(linux.AT.FDCWD, @ptrCast(out), 0, .{}, &stx)) == .SUCCESS) {
        return out[0..len_in :0];
    }
    var src_copy: [1024]u8 = undefined;
    @memcpy(src_copy[0..len_in], out[0..len_in]);
    src_copy[len_in] = 0;
    const src = src_copy[0..len_in];

    var resolved: [1024]u8 = undefined;
    var rlen: usize = 0;
    var i: usize = 0;
    if (src[0] == '/') {
        resolved[0] = '/';
        rlen = 1;
        i = 1;
    } else {
        resolved[0] = '.';
        rlen = 1;
    }

    while (i < src.len) {
        while (i < src.len and src[i] == '/') : (i += 1) {}
        if (i >= src.len) break;
        const start = i;
        while (i < src.len and src[i] != '/') : (i += 1) {}
        const seg = src[start..i];
        if (std.mem.eql(u8, seg, ".")) continue;

        resolved[rlen] = 0;
        var matched: ?[256]u8 = null;
        var matched_len: usize = 0;
        const dir_fd_rc = linux.open(@ptrCast(&resolved), .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
        if (linux.errno(dir_fd_rc) == .SUCCESS) {
            const dir_fd: i32 = @intCast(dir_fd_rc);
            defer _ = linux.close(dir_fd);
            var dbuf: [4096]u8 align(8) = undefined;
            outer: while (true) {
                const n = linux.getdents64(dir_fd, &dbuf, dbuf.len);
                if (linux.errno(n) != .SUCCESS or n == 0) break;
                var off: usize = 0;
                while (off < n) {
                    const ent: *align(1) const linux.dirent64 = @ptrCast(&dbuf[off]);
                    const name_ptr: [*:0]const u8 = @ptrCast(&ent.name);
                    const ename = std.mem.span(name_ptr);
                    if (std.ascii.eqlIgnoreCase(ename, seg) and ename.len < 256) {
                        matched = [_]u8{0} ** 256;
                        @memcpy(matched.?[0..ename.len], ename);
                        matched_len = ename.len;
                        break :outer;
                    }
                    off += ent.reclen;
                }
            }
        }
        const chosen = if (matched) |*m| m[0..matched_len] else seg;
        if (rlen > 1 or resolved[0] != '/') {
            if (rlen < resolved.len - 2) {
                resolved[rlen] = '/';
                rlen += 1;
            }
        }
        const copy_n = @min(chosen.len, resolved.len - 1 - rlen);
        @memcpy(resolved[rlen..][0..copy_n], chosen[0..copy_n]);
        rlen += copy_n;
    }
    const final_len = if (src[0] != '/' and rlen > 2 and std.mem.startsWith(u8, resolved[0..rlen], "./")) blk: {
        const sub = rlen - 2;
        @memcpy(out[0..sub], resolved[2..rlen]);
        break :blk sub;
    } else blk: {
        @memcpy(out[0..rlen], resolved[0..rlen]);
        break :blk rlen;
    };
    out[final_len] = 0;
    return out[0..final_len :0];
}

fn wideToTranslatedPath(name: ?[*:0]const u16, out: *[1024]u8) ?[:0]const u8 {
    if (name == null) return null;
    var tmp: [1024]u8 = undefined;
    var len: usize = 0;
    while (name.?[len] != 0 and len < tmp.len - 1) : (len += 1) {
        tmp[len] = @intCast(name.?[len] & 0xFF);
    }
    return translateWinPath(tmp[0..len], out);
}

fn narrowToTranslatedPath(name: ?[*:0]const u8, out: *[1024]u8) ?[:0]const u8 {
    if (name == null) return null;
    return translateWinPath(std.mem.span(name.?), out);
}

var file_trace_state: i8 = -1;
fn fileTrace(comptime fmt: []const u8, args: anytype) void {
    if (file_trace_state < 0) file_trace_state = if (std.c.getenv("WINS_FILE_TRACE") != null) 1 else 0;
    if (file_trace_state == 1) std.debug.print("[WINS:File] " ++ fmt ++ "\n", args);
}

/// Dispositions: 1 CREATE_NEW, 2 CREATE_ALWAYS, 3 OPEN_EXISTING, 4 OPEN_ALWAYS,
/// 5 TRUNCATE_EXISTING. Like Windows, CREATE_ALWAYS/OPEN_ALWAYS on an existing
/// file succeed with last error ERROR_ALREADY_EXISTS, and failures set it too.
fn CreateFileW(name: ?[*:0]const u16, access: u32, share: u32, sa: ?*anyopaque, disp: u32, flags: u32, template: usize) callconv(W) usize {
    _ = share;
    _ = sa;
    _ = template;
    var path_buf: [1024]u8 = undefined;
    const host_path = wideToTranslatedPath(name, &path_buf) orelse {
        setLastError(3);
        return INVALID_HANDLE;
    };

    var open_flags = linux.O{};
    if (access & 0x40000000 != 0 and access & 0x80000000 != 0) {
        open_flags.ACCMODE = .RDWR;
    } else if (access & 0x40000000 != 0) {
        open_flags.ACCMODE = .WRONLY;
    } else {
        open_flags.ACCMODE = .RDONLY;
    }
    const existed = linux.errno(linux.faccessat(linux.AT.FDCWD, host_path.ptr, 0, 0)) == .SUCCESS;
    switch (disp) {
        1 => {
            open_flags.CREAT = true;
            open_flags.EXCL = true;
        },
        2 => {
            open_flags.CREAT = true;
            open_flags.TRUNC = true;
        },
        4 => open_flags.CREAT = true,
        5 => open_flags.TRUNC = true,
        else => {},
    }

    const rc = linux.open(host_path.ptr, open_flags, 0o666);
    const e = linux.errno(rc);
    fileTrace("CreateFileW {s} access 0x{x} disp {d} flags 0x{x} -> {s}", .{ host_path, access, disp, flags, @tagName(e) });
    if (e != .SUCCESS) {
        setLastError(if (e == .EXIST) 80 else win32ErrorFromErrno(e)); // ERROR_FILE_EXISTS for CREATE_NEW
        return INVALID_HANDLE;
    }
    setLastError(if (existed and (disp == 2 or disp == 4)) 183 else 0);
    return @as(usize, @intCast(rc)) + 0x1000;
}

fn CreateFileA(name: ?[*:0]const u8, access: u32, share: u32, sa: ?*anyopaque, disp: u32, flags: u32, template: usize) callconv(W) usize {
    _ = share;
    _ = sa;
    _ = flags;
    _ = template;
    var path_buf: [1024]u8 = undefined;
    const host_path = narrowToTranslatedPath(name, &path_buf) orelse return INVALID_HANDLE;

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

    const rc = linux.open(host_path.ptr, open_flags, 0o666);
    if (linux.errno(rc) != .SUCCESS) return INVALID_HANDLE;
    return @as(usize, @intCast(rc)) + 0x1000;
}

fn DeleteFileW(name: ?[*:0]const u16) callconv(W) u32 {
    var path_buf: [1024]u8 = undefined;
    const host_path = wideToTranslatedPath(name, &path_buf) orelse return 0;
    const e = linux.errno(linux.unlink(host_path.ptr));
    fileTrace("DeleteFileW {s} -> {s}", .{ host_path, @tagName(e) });
    if (e == .SUCCESS) return 1;
    setLastError(win32ErrorFromErrno(e));
    return 0;
}

fn DeleteFileA(name: ?[*:0]const u8) callconv(W) u32 {
    var path_buf: [1024]u8 = undefined;
    const host_path = narrowToTranslatedPath(name, &path_buf) orelse return 0;
    const rc = linux.unlink(host_path.ptr);
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

fn statHostPath(host_path: [:0]const u8) ?u32 {
    var stx: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, host_path.ptr, 0, .{ .TYPE = true }, &stx);
    if (linux.errno(rc) != .SUCCESS) return null;
    return if ((stx.mode & linux.S.IFMT) == linux.S.IFDIR) 0x00000010 else 0x00000080;
}

pub fn queryWinPathAttrsW(name: ?[*:0]const u16) u32 {
    var path_buf: [1024]u8 = undefined;
    const host_path = wideToTranslatedPath(name, &path_buf) orelse return 0xFFFFFFFF;
    const attrs = statHostPath(host_path) orelse 0xFFFFFFFF;
    if (comptime builtin.link_libc) {
        if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:K32] attrs({s}) = 0x{x}\n", .{ host_path, attrs });
    }
    return attrs;
}

pub fn queryWinPathAttrsA(name: ?[*:0]const u8) u32 {
    var path_buf: [1024]u8 = undefined;
    const host_path = narrowToTranslatedPath(name, &path_buf) orelse return 0xFFFFFFFF;
    return statHostPath(host_path) orelse 0xFFFFFFFF;
}

fn GetFileAttributesW(name: ?[*:0]const u16) callconv(W) u32 {
    return queryWinPathAttrsW(name);
}

fn GetFileAttributesA(name: ?[*:0]const u8) callconv(W) u32 {
    return queryWinPathAttrsA(name);
}

fn GetFileAttributesExW(name: ?[*:0]const u16, level: u32, info: ?[*]u8) callconv(W) u32 {
    _ = level;
    var path_buf: [1024]u8 = undefined;
    const host_path = wideToTranslatedPath(name, &path_buf) orelse return 0;
    var stx: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, host_path.ptr, 0, .{ .TYPE = true, .SIZE = true }, &stx);
    if (linux.errno(rc) != .SUCCESS) return 0;
    if (info) |p| {
        @memset(p[0..36], 0);
        const attrs: u32 = if ((stx.mode & linux.S.IFMT) == linux.S.IFDIR) 0x00000010 else 0x00000080;
        std.mem.writeInt(u32, p[0..4], attrs, .little);
        std.mem.writeInt(u32, p[28..32], @truncate(stx.size >> 32), .little);
        std.mem.writeInt(u32, p[32..36], @truncate(stx.size), .little);
    }
    return 1;
}

fn GetFileInformationByHandle(h: usize, info: ?[*]u8) callconv(W) u32 {
    const fd = fdFromHandle(h) orelse return 0;
    var stx: linux.Statx = undefined;
    const rc = linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true, .SIZE = true, .INO = true, .NLINK = true, .MTIME = true }, &stx);
    if (linux.errno(rc) != .SUCCESS) return 0;
    if (info) |p| {
        @memset(p[0..52], 0);
        const attrs: u32 = if ((stx.mode & linux.S.IFMT) == linux.S.IFDIR) 0x00000010 else 0x00000080;
        const mtime_sec: u64 = if (stx.mtime.sec > 0) @intCast(stx.mtime.sec) else 0;
        const ft: u64 = (mtime_sec + 11644473600) * 10_000_000;
        std.mem.writeInt(u32, p[0..4], attrs, .little);
        std.mem.writeInt(u64, p[4..12], ft, .little); // ftCreationTime
        std.mem.writeInt(u64, p[12..20], ft, .little); // ftLastAccessTime
        std.mem.writeInt(u64, p[20..28], ft, .little); // ftLastWriteTime
        std.mem.writeInt(u32, p[28..32], 1, .little); // dwVolumeSerialNumber
        std.mem.writeInt(u32, p[32..36], @truncate(stx.size >> 32), .little); // nFileSizeHigh
        std.mem.writeInt(u32, p[36..40], @truncate(stx.size), .little); // nFileSizeLow
        std.mem.writeInt(u32, p[40..44], stx.nlink, .little); // nNumberOfLinks
        std.mem.writeInt(u32, p[44..48], @truncate(stx.ino >> 32), .little); // nFileIndexHigh
        std.mem.writeInt(u32, p[48..52], @truncate(stx.ino), .little); // nFileIndexLow
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
    var cwd_buf: [1024]u8 = undefined;
    const rc = linux.getcwd(&cwd_buf, cwd_buf.len);
    const cwd = if (linux.errno(rc) == .SUCCESS) std.mem.sliceTo(&cwd_buf, 0) else "/";
    const needed: usize = 2 + cwd.len; // "Z:" + cwd
    if (buf != null and n > needed) {
        buf.?[0] = 'Z';
        buf.?[1] = ':';
        for (cwd, 0..) |ch, idx| buf.?[2 + idx] = if (ch == '/') '\\' else ch;
        buf.?[needed] = 0;
        return @intCast(needed);
    }
    return @intCast(needed + 1);
}

fn SetCurrentDirectoryW(path: ?[*:0]const u16) callconv(W) u32 {
    var path_buf: [1024]u8 = undefined;
    const host_path = wideToTranslatedPath(path, &path_buf) orelse return 0;
    const rc = linux.chdir(host_path.ptr);
    return if (linux.errno(rc) == .SUCCESS) 1 else 0;
}

/// Win32 error for a failed Linux file-system call (the codes Win32 callers test for).
pub fn win32ErrorFromErrno(e: linux.E) u32 {
    return switch (e) {
        .SUCCESS => 0,
        .EXIST => 183, // ERROR_ALREADY_EXISTS
        .NOENT, .NOTDIR => 3, // ERROR_PATH_NOT_FOUND
        .ACCES, .PERM, .ROFS => 5, // ERROR_ACCESS_DENIED
        .NOTEMPTY => 145, // ERROR_DIR_NOT_EMPTY
        .NAMETOOLONG => 206, // ERROR_FILENAME_EXCED_RANGE
        .NOSPC, .DQUOT => 112, // ERROR_DISK_FULL
        .BUSY => 32, // ERROR_SHARING_VIOLATION
        .INVAL => 87, // ERROR_INVALID_PARAMETER
        else => 31, // ERROR_GEN_FAILURE
    };
}

fn CreateDirectoryW(path: ?[*:0]const u16, sa: ?*anyopaque) callconv(W) u32 {
    _ = sa;
    var path_buf: [1024]u8 = undefined;
    const host_path = wideToTranslatedPath(path, &path_buf) orelse {
        setLastError(3); // ERROR_PATH_NOT_FOUND
        return 0;
    };
    // Ensure intermediate parents exist when mapping into /tmp/wins-* sandbox trees.
    if (std.mem.startsWith(u8, host_path, "/tmp/")) {
        var idx: usize = 5;
        while (idx < host_path.len) : (idx += 1) {
            if (host_path[idx] == '/') {
                path_buf[idx] = 0;
                _ = linux.mkdir(@ptrCast(&path_buf), 0o755);
                path_buf[idx] = '/';
            }
        }
    }
    const rc = linux.mkdir(host_path.ptr, 0o755);
    const e = linux.errno(rc);
    if (e == .SUCCESS) return 1;
    // Mono's Directory.CreateDirectory creates every component and treats
    // ERROR_ALREADY_EXISTS as success; a stale or generic code makes it throw.
    setLastError(win32ErrorFromErrno(e));
    return 0;
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

const FIND_MAGIC: u64 = 0x57494E53_46494E44;
const FindState = struct {
    magic: u64 = FIND_MAGIC,
    dir_fd: i32 = -1,
    pat: [260]u8 = [_]u8{0} ** 260,
    pat_len: usize = 0,
    buf: [4096]u8 align(8) = undefined,
    pos: usize = 0,
    end: usize = 0,
};

fn wildMatchIgnoreCase(pat: []const u8, s: []const u8) bool {
    // Win32 "*.*" matches any name (even without a dot).
    if (std.mem.eql(u8, pat, "*.*") or std.mem.eql(u8, pat, "*")) return true;
    var pi: usize = 0;
    var si: usize = 0;
    var star_pi: ?usize = null;
    var star_si: usize = 0;
    while (si < s.len) {
        if (pi < pat.len and (pat[pi] == '?' or std.ascii.toLower(pat[pi]) == std.ascii.toLower(s[si]))) {
            pi += 1;
            si += 1;
        } else if (pi < pat.len and pat[pi] == '*') {
            star_pi = pi;
            star_si = si;
            pi += 1;
        } else if (star_pi) |sp| {
            pi = sp + 1;
            star_si += 1;
            si = star_si;
        } else {
            return false;
        }
    }
    while (pi < pat.len and pat[pi] == '*') : (pi += 1) {}
    return pi == pat.len;
}

fn fillFindData(dir_fd: i32, ename: [:0]const u8, dtype: u8, data: [*]u8, wide: bool) void {
    const struct_sz: usize = if (wide) 592 else 320;
    @memset(data[0..struct_sz], 0);
    var stx: linux.Statx = undefined;
    var attrs: u32 = if (dtype == 4) 0x10 else 0x80; // DT_DIR=4 -> FILE_ATTRIBUTE_DIRECTORY
    var size: u64 = 0;
    if (linux.errno(linux.statx(dir_fd, ename.ptr, 0, .{ .TYPE = true, .SIZE = true }, &stx)) == .SUCCESS) {
        attrs = if ((stx.mode & linux.S.IFMT) == linux.S.IFDIR) 0x10 else 0x80;
        size = stx.size;
    }
    std.mem.writeInt(u32, data[0..4], attrs, .little);
    std.mem.writeInt(u32, data[28..32], @truncate(size >> 32), .little);
    std.mem.writeInt(u32, data[32..36], @truncate(size), .little);
    if (wide) {
        const wptr: [*]u16 = @ptrCast(@alignCast(data + 44));
        const n = @min(ename.len, 259);
        for (ename[0..n], 0..) |ch, idx| wptr[idx] = ch;
        wptr[n] = 0;
    } else {
        const n = @min(ename.len, 259);
        @memcpy(data[44..][0..n], ename[0..n]);
        data[44 + n] = 0;
    }
}

fn findStep(fs: *FindState, data: [*]u8, wide: bool) bool {
    const pat = fs.pat[0..fs.pat_len];
    while (true) {
        if (fs.pos >= fs.end) {
            const n = linux.getdents64(fs.dir_fd, &fs.buf, fs.buf.len);
            if (linux.errno(n) != .SUCCESS or n == 0) return false;
            fs.pos = 0;
            fs.end = n;
        }
        const ent: *align(1) const linux.dirent64 = @ptrCast(&fs.buf[fs.pos]);
        fs.pos += ent.reclen;
        const nptr: [*:0]const u8 = @ptrCast(&ent.name);
        const ename = std.mem.span(nptr);
        if (!wildMatchIgnoreCase(pat, ename)) continue;
        fillFindData(fs.dir_fd, ename, ent.type, data, wide);
        return true;
    }
}

fn findStart(host_pat: [:0]const u8, data_opt: ?[*]u8, wide: bool) usize {
    const data = data_opt orelse return INVALID_HANDLE;
    const slash = std.mem.lastIndexOfScalar(u8, host_pat, '/');
    var dir_buf: [1024]u8 = undefined;
    var dir_z: [:0]const u8 = undefined;
    var pat: []const u8 = undefined;
    if (slash) |idx| {
        const dlen = if (idx == 0) 1 else idx;
        @memcpy(dir_buf[0..dlen], if (idx == 0) "/" else host_pat[0..idx]);
        dir_buf[dlen] = 0;
        dir_z = resolveCaseInsensitiveInPlace(&dir_buf, dlen);
        pat = host_pat[idx + 1 ..];
    } else {
        dir_buf[0] = '.';
        dir_buf[1] = 0;
        dir_z = dir_buf[0..1 :0];
        pat = host_pat;
    }
    const fd_rc = linux.open(dir_z.ptr, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return INVALID_HANDLE;
    const fs = std.heap.page_allocator.create(FindState) catch {
        _ = linux.close(@intCast(fd_rc));
        return INVALID_HANDLE;
    };
    fs.* = .{ .dir_fd = @intCast(fd_rc) };
    const pn = @min(pat.len, fs.pat.len - 1);
    @memcpy(fs.pat[0..pn], pat[0..pn]);
    fs.pat_len = pn;
    if (!findStep(fs, data, wide)) {
        _ = linux.close(fs.dir_fd);
        std.heap.page_allocator.destroy(fs);
        return INVALID_HANDLE;
    }
    return @intFromPtr(fs);
}

fn FindFirstFileW(name: ?[*:0]const u16, data: ?[*]u8) callconv(W) usize {
    var raw_buf: [1024]u8 = undefined;
    var tmp: [1024]u8 = undefined;
    const n = name orelse return INVALID_HANDLE;
    var len: usize = 0;
    while (n[len] != 0 and len < tmp.len - 1) : (len += 1) tmp[len] = @intCast(n[len] & 0xFF);
    // Translate prefix only (don't try case-insensitivity on the trailing wildcard component yet).
    const tr = translateWinPathNoCi(tmp[0..len], &raw_buf) orelse return INVALID_HANDLE;
    return findStart(tr, data, true);
}

fn translateWinPathNoCi(raw_utf8: []const u8, out: *[1024]u8) ?[:0]const u8 {
    var norm: [1024]u8 = undefined;
    var nlen: usize = 0;
    for (raw_utf8) |ch| {
        if (nlen >= norm.len - 1) break;
        norm[nlen] = if (ch == '\\') '/' else ch;
        nlen += 1;
    }
    var s = norm[0..nlen];
    if (std.mem.startsWith(u8, s, "//?/") or std.mem.startsWith(u8, s, "//./")) s = s[4..];
    if (s.len == 0) return null;
    var pos: usize = 0;
    const append = struct {
        fn slice(dst: *[1024]u8, p: *usize, src: []const u8) void {
            const avail = (dst.len - 1) -| p.*;
            const n = @min(avail, src.len);
            @memcpy(dst[p.*..][0..n], src[0..n]);
            p.* += n;
        }
    }.slice;
    if (s.len >= 2 and s[1] == ':' and std.ascii.isAlphabetic(s[0])) {
        const drive = std.ascii.toLower(s[0]);
        const rest = s[2..];
        if (drive == 'z') {
            append(out, &pos, if (rest.len == 0) "/" else rest);
        } else if (drive == 'c') {
            if (asciiPrefixIgnoreCase(rest, "/Users/User/AppData/Roaming")) {
                append(out, &pos, envOr("APPDATA", "/tmp/wins-appdata"));
                append(out, &pos, rest["/Users/User/AppData/Roaming".len..]);
            } else if (asciiPrefixIgnoreCase(rest, "/Users/User/AppData/Local")) {
                append(out, &pos, envOr("LOCALAPPDATA", "/tmp/wins-localappdata"));
                append(out, &pos, rest["/Users/User/AppData/Local".len..]);
            } else if (asciiPrefixIgnoreCase(rest, "/Users/User")) {
                append(out, &pos, envOr("USERPROFILE", "/tmp"));
                append(out, &pos, rest["/Users/User".len..]);
            } else if (asciiPrefixIgnoreCase(rest, "/Temp") and (rest.len == 5 or rest[5] == '/')) {
                append(out, &pos, "/tmp");
                append(out, &pos, rest[5..]);
            } else {
                append(out, &pos, "/tmp/wins-c");
                append(out, &pos, rest);
            }
        } else {
            append(out, &pos, s[2..]);
        }
    } else {
        append(out, &pos, s);
    }
    out[pos] = 0;
    return out[0..pos :0];
}

fn FindFirstFileExW(name: ?[*:0]const u16, level: u32, data: ?[*]u8, op: u32, filter: ?*anyopaque, flags: u32) callconv(W) usize {
    _ = level;
    _ = op;
    _ = filter;
    _ = flags;
    return FindFirstFileW(name, data);
}

fn FindNextFileW(h: usize, data: ?[*]u8) callconv(W) u32 {
    if (h == 0 or h == INVALID_HANDLE) return 0;
    const d = data orelse return 0;
    const fs: *FindState = @ptrFromInt(h);
    if (fs.magic != FIND_MAGIC) return 0;
    return if (findStep(fs, d, true)) 1 else 0;
}

fn FindClose(h: usize) callconv(W) u32 {
    if (h == 0 or h == INVALID_HANDLE) return 1;
    if (h >= 0x10000) {
        const fs: *FindState = @ptrFromInt(h);
        if (fs.magic == FIND_MAGIC) {
            fs.magic = 0;
            _ = linux.close(fs.dir_fd);
            std.heap.page_allocator.destroy(fs);
        }
    }
    return 1;
}

const MAP_HANDLE_BASE: usize = 0x30000;
const MAX_MAPPINGS: usize = 512;
const MAX_VIEWS: usize = 1024;
const FileMapping = struct {
    in_use: bool = false,
    fd: i32 = -1,
    max_size: u64 = 0,
    prot: u32 = 0,
    sec_image: bool = false,
};
const MappedView = struct {
    in_use: bool = false,
    ptr: usize = 0,
    len: usize = 0,
};
var g_mappings: [MAX_MAPPINGS]FileMapping = [_]FileMapping{.{}} ** MAX_MAPPINGS;
var g_views: [MAX_VIEWS]MappedView = [_]MappedView{.{}} ** MAX_VIEWS;
var g_map_lock: std.atomic.Mutex = .unlocked;

fn lockMaps() void {
    while (!g_map_lock.tryLock()) std.atomic.spinLoopHint();
}

pub fn closeMappingHandle(h: usize) bool {
    if (h < MAP_HANDLE_BASE or h >= MAP_HANDLE_BASE + MAX_MAPPINGS) return false;
    const idx = h - MAP_HANDLE_BASE;
    lockMaps();
    defer g_map_lock.unlock();
    if (!g_mappings[idx].in_use) return false;
    if (g_mappings[idx].fd >= 3) _ = linux.close(g_mappings[idx].fd);
    g_mappings[idx] = .{};
    return true;
}

fn CreateFileMappingW(file: usize, sa: ?*anyopaque, prot: u32, max_h: u32, max_l: u32, name: ?[*:0]const u16) callconv(W) usize {
    _ = sa;
    _ = name;
    var fd: i32 = -1;
    var size: u64 = (@as(u64, max_h) << 32) | max_l;
    if (file != INVALID_HANDLE) {
        const orig_fd = fdFromHandle(file) orelse return 0;
        const dup_rc = linux.dup(orig_fd);
        if (linux.errno(dup_rc) != .SUCCESS) return 0;
        fd = @intCast(dup_rc);
        if (size == 0) {
            var stx: linux.Statx = undefined;
            if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .SIZE = true }, &stx)) == .SUCCESS) {
                size = stx.size;
            }
        }
    }
    lockMaps();
    defer g_map_lock.unlock();
    for (&g_mappings, 0..) |*m, idx| {
        if (!m.in_use) {
            m.* = .{
                .in_use = true,
                .fd = fd,
                .max_size = if (size == 0) 65536 else size,
                .prot = prot,
                .sec_image = (prot & 0x01000000) != 0,
            };
            return MAP_HANDLE_BASE + idx;
        }
    }
    if (fd >= 3) _ = linux.close(fd);
    return 0;
}

fn mapSecImage(fd: i32, file_sz: u64) ?[*]u8 {
    if (file_sz < 64 or file_sz > 256 * 1024 * 1024) return null;
    const fbuf = std.heap.page_allocator.alloc(u8, @intCast(file_sz)) catch return null;
    defer std.heap.page_allocator.free(fbuf);
    var done: usize = 0;
    while (done < fbuf.len) {
        const rc = linux.pread(fd, fbuf.ptr + done, fbuf.len - done, @intCast(done));
        if (linux.errno(rc) != .SUCCESS or rc == 0) break;
        done += rc;
    }
    if (done < 64 or fbuf[0] != 'M' or fbuf[1] != 'Z') return null;
    const pe = std.mem.readInt(u32, fbuf[0x3c..][0..4], .little);
    if (@as(u64, pe) + 24 + 64 > done) return null;
    const nsec = std.mem.readInt(u16, fbuf[pe + 6 ..][0..2], .little);
    const opt_sz = std.mem.readInt(u16, fbuf[pe + 20 ..][0..2], .little);
    const opt = pe + 24;
    const size_of_image = std.mem.readInt(u32, fbuf[opt + 56 ..][0..4], .little);
    const size_of_headers = std.mem.readInt(u32, fbuf[opt + 60 ..][0..4], .little);
    if (size_of_image == 0 or size_of_image > 256 * 1024 * 1024) return null;
    const map_len = std.mem.alignForward(usize, size_of_image, 4096);
    const mrc = linux.mmap(null, map_len, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
    if (linux.errno(mrc) != .SUCCESS) return null;
    const dst: [*]u8 = @ptrFromInt(mrc);
    const hdr_n = @min(@as(usize, size_of_headers), done);
    @memcpy(dst[0..hdr_n], fbuf[0..hdr_n]);
    const sec_off = opt + opt_sz;
    var k: usize = 0;
    while (k < nsec) : (k += 1) {
        const o = sec_off + k * 40;
        if (o + 40 > done) break;
        const vsize = std.mem.readInt(u32, fbuf[o + 8 ..][0..4], .little);
        const va = std.mem.readInt(u32, fbuf[o + 12 ..][0..4], .little);
        const rsz = std.mem.readInt(u32, fbuf[o + 16 ..][0..4], .little);
        const rptr = std.mem.readInt(u32, fbuf[o + 20 ..][0..4], .little);
        const copy_n = @min(@as(usize, if (vsize != 0) @min(rsz, vsize) else rsz), done -| rptr);
        if (copy_n > 0 and @as(u64, va) + copy_n <= map_len) {
            @memcpy(dst[va..][0..copy_n], fbuf[rptr..][0..copy_n]);
        }
    }
    lockMaps();
    defer g_map_lock.unlock();
    for (&g_views) |*v| {
        if (!v.in_use) {
            v.* = .{ .in_use = true, .ptr = mrc, .len = map_len };
            break;
        }
    }
    return dst;
}

fn MapViewOfFile(mapping: usize, access: u32, off_h: u32, off_l: u32, bytes: usize) callconv(W) ?[*]u8 {
    if (mapping < MAP_HANDLE_BASE or mapping >= MAP_HANDLE_BASE + MAX_MAPPINGS) return null;
    lockMaps();
    const m = g_mappings[mapping - MAP_HANDLE_BASE];
    g_map_lock.unlock();
    if (!m.in_use) return null;
    const offset: u64 = (@as(u64, off_h) << 32) | off_l;
    if (m.fd >= 0 and m.sec_image and offset == 0) {
        if (mapSecImage(m.fd, m.max_size)) |p| return p;
    }
    const raw_len: usize = if (bytes != 0) bytes else if (m.max_size > offset) @intCast(m.max_size - offset) else 4096;
    const sz = std.mem.alignForward(usize, @max(raw_len, 1), 4096);
    const want_write = (access & 0x0002 != 0) or (access == 0x001f); // FILE_MAP_WRITE or FILE_MAP_ALL_ACCESS
    const prot: linux.PROT = .{
        .READ = true,
        .WRITE = want_write or (access & 0x0001 != 0) or (m.fd < 0),
        .EXEC = (access & 0x0020 != 0) or (m.prot & 0xF0 != 0),
    };
    const mflags: linux.MAP = if (m.fd >= 0)
        .{ .TYPE = if (want_write) .SHARED else .PRIVATE }
    else
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true };
    const mrc = linux.mmap(null, sz, prot, mflags, m.fd, @intCast(offset));
    if (linux.errno(mrc) != .SUCCESS) return null;
    lockMaps();
    for (&g_views) |*v| {
        if (!v.in_use) {
            v.* = .{ .in_use = true, .ptr = mrc, .len = sz };
            break;
        }
    }
    g_map_lock.unlock();
    return @ptrFromInt(mrc);
}

fn UnmapViewOfFile(ptr: ?[*]const u8) callconv(W) u32 {
    const p = ptr orelse return 1;
    const addr = @intFromPtr(p);
    lockMaps();
    defer g_map_lock.unlock();
    for (&g_views) |*v| {
        if (v.in_use and v.ptr == addr) {
            _ = linux.munmap(@ptrFromInt(v.ptr), v.len);
            v.* = .{};
            return 1;
        }
    }
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
    _ = pa; _ = ta; _ = inh; _ = flags; _ = env; _ = dir; _ = si;
    if (pi) |p| @memset(@as([*]u8, @ptrCast(p))[0 .. 2 * @sizeOf(usize) + 8], 0);
    var path_buf: [1024]u8 = undefined;
    const image = wideToTranslatedPath(app, &path_buf) orelse blk: {
        if (cmd) |line| {
            var b: [1024]u8 = undefined;
            var n: usize = 0;
            while (line[n] != 0 and n < b.len - 1) : (n += 1) b[n] = @truncate(line[n]);
            break :blk translateWinPath(firstWinCommandToken(b[0..n]), &path_buf);
        }
        break :blk null;
    };
    if (image) |p| {
        const fd = linux.open(@ptrCast(p), .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (linux.errno(fd) != .SUCCESS) { setLastError(2); return 0; }
        _ = linux.close(@intCast(fd));
    }
    setLastError(50);
    return 0;
}

fn GetExitCodeProcess(proc: usize, exit_code: ?*u32) callconv(W) u32 {
    if (exit_code == null) { setLastError(87); return 0; }
    if (proc == ~@as(usize, 0)) { exit_code.?.* = 259; return 1; }
    setLastError(6);
    return 0;
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
    const n = name orelse { setLastError(87); return 0; };
    return getEnvA(std.mem.span(n), buf, sz);
}

fn SetEnvironmentVariableW(name: ?[*:0]const u16, val: ?[*:0]const u16) callconv(W) u32 {
    const n = name orelse { setLastError(87); return 0; };
    var nb: [512]u8 = undefined;
    const nbytes = std.unicode.utf16LeToUtf8(&nb, std.mem.span(n)) catch { setLastError(87); return 0; };
    var vb: [1024]u8 = undefined;
    const v: ?[]const u8 = if (val) |x| blk: { const vbytes = std.unicode.utf16LeToUtf8(&vb, std.mem.span(x)) catch { setLastError(87); return 0; }; break :blk vb[0..vbytes]; } else null;
    return if (setEnvValue(nb[0..nbytes], v)) 1 else 0;
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
    _ = name;
    return CreateFileMappingW(file, sa, prot, max_h, max_l, null);
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
    if (pi) |p| @memset(@as([*]u8, @ptrCast(p))[0 .. 2 * @sizeOf(usize) + 8], 0);
    var path_buf: [1024]u8 = undefined;
    const image = if (app) |a| narrowToTranslatedPath(a, &path_buf) else if (cmd) |c| blk: {
        break :blk translateWinPath(firstWinCommandToken(std.mem.span(c)), &path_buf);
    } else null;
    if (image) |p| {
        const fd = linux.open(@ptrCast(p), .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (linux.errno(fd) != .SUCCESS) { setLastError(2); return 0; }
        _ = linux.close(@intCast(fd));
    }
    setLastError(50);
    return 0;
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
    var raw_buf: [1024]u8 = undefined;
    const p = name orelse return INVALID_HANDLE;
    const tr = translateWinPathNoCi(std.mem.span(p), &raw_buf) orelse return INVALID_HANDLE;
    return findStart(tr, data, false);
}

fn FindNextFileA(h: usize, data: ?[*]u8) callconv(W) u32 {
    if (h == 0 or h == INVALID_HANDLE) return 0;
    const d = data orelse return 0;
    const fs: *FindState = @ptrFromInt(h);
    if (fs.magic != FIND_MAGIC) return 0;
    return if (findStep(fs, d, false)) 1 else 0;
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
    const n = name orelse { setLastError(87); return 0; };
    var nb: [512]u8 = undefined;
    const nbytes = std.unicode.utf16LeToUtf8(&nb, std.mem.span(n)) catch { setLastError(87); return 0; };
    const ns = nb[0..nbytes];
    var val: [1024]u8 = undefined;
    const len = getEnvA(ns, &val, val.len);
    if (len == 0) return 0;
    const need = len + 1;
    if (buf == null or sz < need) return need;
    const written = std.unicode.utf8ToUtf16Le(buf.?[0 .. sz - 1], val[0..len]) catch { setLastError(87); return 0; };
    buf.?[written] = 0;
    return len;
}

fn SetEnvironmentVariableA(name: ?[*:0]const u8, val: ?[*:0]const u8) callconv(W) u32 {
    const n = name orelse { setLastError(87); return 0; };
    return if (setEnvValue(std.mem.span(n), if (val) |v| std.mem.span(v) else null)) 1 else 0;
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
    if (mod == 0 or mod == image_base_addr) {
        if (module_path_initialized) {
            const mlen: usize = @min(module_path_len, if (sz > 0) @as(usize, sz) - 1 else 0);
            if (buf != null and sz > 0) {
                @memcpy(buf.?[0..mlen], module_path_a[0..mlen]);
                buf.?[mlen] = 0;
            }
            return @intCast(mlen);
        }
    }
    return 0;
}

fn GetProcessAffinityMask(proc: usize, proc_mask: ?*usize, sys_mask: ?*usize) callconv(W) u32 {
    _ = proc;
    const m: usize = cpuMask(cpuCount());
    if (proc_mask) |p| p.* = m;
    if (sys_mask) |s| s.* = m;
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

/// ReadProcessMemory: the current process ((HANDLE)-1 or OpenProcess(own pid))
/// and other processes opened with OpenProcess (handle = 0x1000 + pid) are read
/// with process_vm_readv, so an unmapped or PROT_NONE range fails with
/// ERROR_PARTIAL_COPY (or ERROR_NOACCESS for nothing read) instead of faulting,
/// as on Windows. Protectors read their own image this way.
fn ReadProcessMemory(proc: usize, base: ?*const anyopaque, buf: ?[*]u8, sz: usize, num_read: ?*usize) callconv(W) u32 {
    if (num_read) |r| r.* = 0;
    const self_pid: usize = @intCast(std.os.linux.getpid());
    const pid: usize = if (proc == ~@as(usize, 0)) self_pid else if (proc > 0x1000 and proc < 0x1000 + (1 << 22)) proc - 0x1000 else {
        setLastError(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    const dst = buf orelse {
        setLastError(998); // ERROR_NOACCESS
        return 0;
    };
    if (sz == 0) return 1;
    var local = [_]std.posix.iovec{.{ .base = dst, .len = sz }};
    var remote = [_]std.posix.iovec_const{.{ .base = @ptrCast(base orelse {
        setLastError(998);
        return 0;
    }), .len = sz }};
    const got = std.os.linux.process_vm_readv(@intCast(pid), &local, &remote, 0);
    const n: usize = if (std.os.linux.errno(got) == .SUCCESS) got else 0;
    if (comptime @import("builtin").link_libc) if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:trace] ReadProcessMemory(pid={d}, 0x{x}, {d}) -> {d} bytes ret=0x{x}\n", .{ pid, @intFromPtr(base), sz, n, @returnAddress() });
    if (num_read) |r| r.* = n;
    if (n == sz) return 1;
    setLastError(if (n == 0) 998 else 299); // ERROR_NOACCESS / ERROR_PARTIAL_COPY
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
    return MoveFileExW(from, to, 0);
}

/// MOVEFILE_REPLACE_EXISTING (1) lets rename(2) overwrite; without it an existing
/// target fails with ERROR_ALREADY_EXISTS like Windows. A null target
/// (MOVEFILE_DELAY_UNTIL_REBOOT deletion) is accepted and ignored.
fn MoveFileExW(from: ?[*:0]const u16, to: ?[*:0]const u16, flags: u32) callconv(W) u32 {
    var from_buf: [1024]u8 = undefined;
    var to_buf: [1024]u8 = undefined;
    const src = wideToTranslatedPath(from, &from_buf) orelse {
        setLastError(2);
        return 0;
    };
    if (to == null) return 1;
    const dst = wideToTranslatedPath(to, &to_buf) orelse {
        setLastError(3);
        return 0;
    };
    if (flags & 1 == 0) {
        if (linux.errno(linux.faccessat(linux.AT.FDCWD, dst.ptr, 0, 0)) == .SUCCESS) {
            setLastError(183); // ERROR_ALREADY_EXISTS
            return 0;
        }
    }
    const e = linux.errno(linux.rename(src.ptr, dst.ptr));
    fileTrace("MoveFileExW {s} -> {s} flags 0x{x}: {s}", .{ src, dst, flags, @tagName(e) });
    if (e == .SUCCESS) return 1;
    setLastError(win32ErrorFromErrno(e));
    return 0;
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
    const ptr = HeapAlloc(HEAP_COOKIE, 0, dwBytes) orelse return null;
    for (&global_locks) |*e| if (e.ptr == 0) { e.ptr = @intFromPtr(ptr); e.count = 0; break; };
    return ptr;
}

fn GlobalLock(hMem: ?*anyopaque) callconv(W) ?*anyopaque {
    const p = hMem orelse return null;
    for (&global_locks) |*e| if (e.ptr == @intFromPtr(p)) { e.count +|= 1; return p; };
    return null;
}

fn GlobalUnlock(hMem: ?*anyopaque) callconv(W) i32 {
    const p = hMem orelse { setLastError(6); return 0; };
    for (&global_locks) |*e| if (e.ptr == @intFromPtr(p)) { if (e.count == 0) { setLastError(158); return 0; } e.count -= 1; if (e.count == 0) { setLastError(0); return 0; } return 1; };
    setLastError(6); return 0;
}

const GlobalLockEntry = struct { ptr: usize = 0, count: u32 = 0 };
var global_locks: [256]GlobalLockEntry = [_]GlobalLockEntry{.{}} ** 256;

fn GlobalFree(hMem: ?*anyopaque) callconv(W) ?*anyopaque {
    if (hMem) |p| for (&global_locks) |*e| if (e.ptr == @intFromPtr(p)) { e.* = .{}; break; };
    _ = HeapFree(HEAP_COOKIE, 0, if (hMem) |p| @ptrCast(p) else null);
    return null;
}

fn CopyFileW(lpExisting: ?[*:0]const u16, lpNew: ?[*:0]const u16, bFailIfExists: u32) callconv(W) u32 {
    var src_buf: [1024]u8 = undefined; var dst_buf: [1024]u8 = undefined;
    const src = wideToTranslatedPath(lpExisting, &src_buf) orelse { setLastError(87); return 0; };
    const dst = wideToTranslatedPath(lpNew, &dst_buf) orelse { setLastError(87); return 0; };
    return copyHostFile(src, dst, bFailIfExists != 0);
}
fn CopyFileA(src: ?[*:0]const u8, dst: ?[*:0]const u8, fail: u32) callconv(W) u32 {
    var src_buf: [1024]u8 = undefined; var dst_buf: [1024]u8 = undefined;
    const s = narrowToTranslatedPath(src, &src_buf) orelse { setLastError(87); return 0; };
    const d = narrowToTranslatedPath(dst, &dst_buf) orelse { setLastError(87); return 0; };
    return copyHostFile(s, d, fail != 0);
}

fn copyHostFile(src: [:0]const u8, dst: [:0]const u8, fail_exists: bool) u32 {
    const in = linux.open(@ptrCast(src), .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(in) != .SUCCESS) { setLastError(2); return 0; }
    defer _ = linux.close(@intCast(in));
    const out = linux.open(@ptrCast(dst), .{ .ACCMODE = .WRONLY, .CREAT = true, .CLOEXEC = true, .EXCL = fail_exists, .TRUNC = !fail_exists }, 0o666);
    if (linux.errno(out) != .SUCCESS) { setLastError(if (fail_exists) 80 else 5); return 0; }
    defer _ = linux.close(@intCast(out));
    var buf: [16384]u8 = undefined;
    while (true) {
        const n = linux.read(@intCast(in), &buf, buf.len);
        if (linux.errno(n) != .SUCCESS) { setLastError( readErr(n)); return 0; }
        if (n == 0) break;
        var off: usize = 0;
        while (off < n) { const w = linux.write(@intCast(out), buf[off..n].ptr, n - off); if (linux.errno(w) != .SUCCESS or w == 0) { setLastError(5); return 0; } off += w; }
    }
    return 1;
}
fn readErr(rc: usize) u32 { _ = rc; return 5; }

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

/// Installed by the loader: release a block only if the loader can prove it
/// owns it. A free that cannot prove ownership must not unmap -- the address
/// may belong to the real Steam client, and unmapping it is what made the
/// client abort with "malloc(): unaligned tcache chunk detected".
pub var release_hook: ?*const fn (usize, usize) bool = null;

fn VirtualFree(lpAddress: ?*anyopaque, dwSize: usize, dwFreeType: u32) callconv(W) i32 {
    _ = dwFreeType;
    if (lpAddress) |addr| {
        const base = @intFromPtr(addr);
        std.debug.print("[WINS:Kernel32] VirtualFree(0x{x}, size={d})\n", .{ base, dwSize });
        if (release_hook) |hook| {
            if (hook(base, dwSize)) return 1;
        }
        std.debug.print("[WINS:Kernel32] VirtualFree: 0x{x} is not one of our allocations; refusing to release it\n", .{base});
    }
    return 0;
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
    if (comptime builtin.link_libc) {
        return if (@import("winrun_threads.zig").setThreadPriority(hThread, nPriority)) 1 else blk: { setLastError(6); break :blk 0; };
    } else {
        if (hThread == ~@as(usize, 1) and nPriority >= -15 and nPriority <= 15) { current_thread_priority = nPriority; return 1; }
        setLastError(6); return 0;
    }
}
threadlocal var current_thread_priority: i32 = 0;

fn SetThreadAffinityMask(hThread: usize, dwThreadAffinityMask: usize) callconv(W) usize {
    const tid: ?u32 = if (comptime builtin.link_libc) @import("winrun_threads.zig").threadTid(hThread) else if (hThread == ~@as(usize, 1)) @intCast(linux.gettid()) else null;
    if (tid == null) { setLastError(6); return 0; }
    if (dwThreadAffinityMask == 0) { setLastError(87); return 0; }
    var old: [16]u64 = [_]u64{0} ** 16; var new: [16]u64 = [_]u64{0} ** 16;
    const which: i32 = @intCast(tid.?);
    const get = linux.syscall3(.sched_getaffinity, @intCast(which), @sizeOf(@TypeOf(old)), @intFromPtr(&old));
    if (linux.errno(get) != .SUCCESS) { setLastError(87); return 0; }
    const previous = old[0]; new = old; new[0] = dwThreadAffinityMask;
    const set = linux.syscall3(.sched_setaffinity, @intCast(which), @sizeOf(@TypeOf(new)), @intFromPtr(&new));
    if (linux.errno(set) != .SUCCESS) { setLastError(87); return 0; }
    return @intCast(previous);
}

fn GetThreadPriority(hThread: usize) callconv(W) i32 {
    if (comptime builtin.link_libc) {
        return @import("winrun_threads.zig").getThreadPriority(hThread) orelse blk: { setLastError(6); break :blk 0x7FFFFFFF; };
    } else {
        if (hThread == ~@as(usize, 1)) return current_thread_priority;
        setLastError(6); return 0x7FFFFFFF;
    }
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
        // These fields are usize; 4 GiB does not fit a 32-bit target, so clamp.
        const gib: usize = @min(1024 * 1024 * 1024, std.math.maxInt(usize) / 4);
        b.dwTotalPhys = 4 * gib;
        b.dwAvailPhys = @min(3 * gib, b.dwTotalPhys);
        b.dwTotalPageFile = b.dwTotalPhys;
        b.dwAvailPageFile = b.dwAvailPhys;
        b.dwTotalVirtual = @min(2 * gib, b.dwTotalPhys);
        b.dwAvailVirtual = b.dwTotalVirtual;
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
    const s = lpSystemPowerStatus orelse { setLastError(87); return 0; };
    s.* = .{ .ACLineStatus = 255, .BatteryFlag = 255, .BatteryLifePercent = 255, .SystemStatusFlag = 0, .BatteryLifeTime = 0xFFFFFFFF, .BatteryFullLifeTime = 0xFFFFFFFF };
    // Read common sysfs names. Missing devices remain honestly unknown (255).
    for ([_][]const u8{"/sys/class/power_supply/AC/online", "/sys/class/power_supply/ACAD/online", "/sys/class/power_supply/ADP0/online"}) |path| {
        var p: [128]u8 = [_]u8{0} ** 128; @memcpy(p[0..path.len], path);
        const fd = linux.open(@ptrCast(&p), .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (linux.errno(fd) == .SUCCESS) { defer _ = linux.close(@intCast(fd)); var b: [8]u8 = undefined; const n = linux.read(@intCast(fd), &b, b.len); if (n > 0) s.ACLineStatus = if (b[0] == '1') 1 else 0; break; }
    }
    for ([_][]const u8{"/sys/class/power_supply/BAT0/capacity", "/sys/class/power_supply/BAT1/capacity"}) |path| {
        var p: [128]u8 = [_]u8{0} ** 128; @memcpy(p[0..path.len], path);
        const fd = linux.open(@ptrCast(&p), .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (linux.errno(fd) == .SUCCESS) {
            defer _ = linux.close(@intCast(fd)); var b: [8]u8 = undefined; const n = linux.read(@intCast(fd), &b, b.len);
            if (n > 0) { var pct: u32 = 0; for (b[0..n]) |ch| { if (ch < '0' or ch > '9') break; pct = pct * 10 + ch - '0'; } s.BatteryLifePercent = @intCast(@min(pct, 100)); s.BatteryFlag = if (s.ACLineStatus == 1) 8 else 0; }
            break;
        }
    }
    return 1;
}

test "environment A/W setters and getters share process state" {
    const name_a = "WINS_KSTUB_TEST";
    const value_a = "cafe";
    try std.testing.expectEqual(@as(u32, 1), SetEnvironmentVariableA(name_a, value_a));
    var out_a: [16]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 4), GetEnvironmentVariableA(name_a, &out_a, out_a.len));
    try std.testing.expectEqualStrings("cafe", out_a[0..4]);
    const name_w = [_:0]u16{ 'W','I','N','S','_','K','S','T','U','B','_','T','E','S','T' };
    const value_w = [_:0]u16{ 'r','e','a','l' };
    try std.testing.expectEqual(@as(u32, 1), SetEnvironmentVariableW(&name_w, &value_w));
    var out_w: [16]u16 = undefined;
    try std.testing.expectEqual(@as(u32, 4), GetEnvironmentVariableW(&name_w, &out_w, out_w.len));
    try std.testing.expectEqualSlices(u16, &[_]u16{'r','e','a','l'}, out_w[0..4]);
    const block = GetEnvironmentStringsW().?;
    try std.testing.expectEqualSlices(u16, &[_]u16{'W','I','N','S','_','K','S','T','U','B','_','T','E','S','T','=','r','e','a','l'}, block[0..20]);
    try std.testing.expectEqual(@as(u32, 1), SetEnvironmentVariableA(name_a, null));
    try std.testing.expectEqual(@as(u32, 0), GetEnvironmentVariableA(name_a, &out_a, out_a.len));
}

test "process creation fails honestly, clears output, and process pseudo-handle remains active" {
    var pi: [2 * @sizeOf(usize) + 8]u8 = [_]u8{0xAA} ** (2 * @sizeOf(usize) + 8);
    const app = [_:0]u16{'Z',':','\\','n','o','-','s','u','c','h','.','e','x','e'};
    try std.testing.expectEqual(@as(u32, 0), CreateProcessW(&app, null, null, null, 0, 0, null, null, null, &pi));
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** (2 * @sizeOf(usize) + 8)), &pi);
    var pia: [2 * @sizeOf(usize) + 8]u8 = [_]u8{0xAA} ** (2 * @sizeOf(usize) + 8);
    const app_a: [*:0]const u8 = "Z:\\no-such.exe";
    try std.testing.expectEqual(@as(u32, 0), CreateProcessA(app_a, null, null, null, 0, 0, null, null, null, &pia));
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** (2 * @sizeOf(usize) + 8)), &pia);
    var code: u32 = 0;
    try std.testing.expectEqual(@as(u32, 1), GetExitCodeProcess(~@as(usize, 0), &code));
    try std.testing.expectEqual(@as(u32, 259), code);
    try std.testing.expectEqual(@as(u32, 0), GetExitCodeProcess(0x12345, &code));
}

test "global lock count follows Windows last-unlock return" {
    const p = GlobalAlloc(0, 32) orelse return error.OutOfMemory;
    try std.testing.expect(GlobalLock(p) == p);
    try std.testing.expect(GlobalLock(p) == p);
    try std.testing.expectEqual(@as(i32, 1), GlobalUnlock(p));
    try std.testing.expectEqual(@as(i32, 0), GlobalUnlock(p));
    _ = GlobalFree(p);
}

test "CopyFile A and W honor translated paths and fail-if-exists" {
    const src_path = "/tmp/wins-kstub-copy-src";
    const dst_path = "/tmp/wins-kstub-copy-dst";
    const srcfd = linux.open(@ptrCast(src_path.ptr), .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
    try std.testing.expect(linux.errno(srcfd) == .SUCCESS);
    _ = linux.write(@intCast(srcfd), "copy-content".ptr, 12); _ = linux.close(@intCast(srcfd));
    const src_w = [_:0]u16{'Z',':','\\','t','m','p','\\','w','i','n','s','-','k','s','t','u','b','-','c','o','p','y','-','s','r','c'};
    const dst_w = [_:0]u16{'Z',':','\\','t','m','p','\\','w','i','n','s','-','k','s','t','u','b','-','c','o','p','y','-','d','s','t'};
    _ = linux.unlink(@ptrCast(dst_path.ptr));
    try std.testing.expectEqual(@as(u32, 1), CopyFileW(&src_w, &dst_w, 1));
    try std.testing.expectEqual(@as(u32, 0), CopyFileW(&src_w, &dst_w, 1));
    _ = linux.unlink(@ptrCast(dst_path.ptr));
    const src_a_buf = "Z:\\tmp\\wins-kstub-copy-src";
    const dst_a_buf = "Z:\\tmp\\wins-kstub-copy-dst";
    try std.testing.expectEqual(@as(u32, 1), CopyFileA(src_a_buf, dst_a_buf, 0));
    _ = linux.unlink(@ptrCast(src_path.ptr)); _ = linux.unlink(@ptrCast(dst_path.ptr));
}

test "power status succeeds with explicit unknown fields when sysfs has no device" {
    var s: SystemPowerStatus = undefined;
    try std.testing.expectEqual(@as(i32, 1), GetSystemPowerStatus(&s));
    try std.testing.expect(s.ACLineStatus <= 1 or s.ACLineStatus == 255);
    try std.testing.expect(s.BatteryLifePercent <= 100 or s.BatteryLifePercent == 255);
}

test "thread priority APIs persist values and reject unknown handles" {
    const current = ~@as(usize, 1);
    try std.testing.expectEqual(@as(i32, 1), SetThreadPriority(current, -2));
    try std.testing.expectEqual(@as(i32, -2), GetThreadPriority(current));
    try std.testing.expectEqual(@as(i32, 0x7FFFFFFF), GetThreadPriority(0x1234));
    try std.testing.expectEqual(@as(i32, 0), SetThreadPriority(0x1234, 0));
}

test "current-thread affinity returns its previous Linux mask" {
    var mask: [16]u64 = [_]u64{0} ** 16;
    const tid: usize = @intCast(linux.gettid());
    const got = linux.syscall3(.sched_getaffinity, tid, @sizeOf(@TypeOf(mask)), @intFromPtr(&mask));
    try std.testing.expect(linux.errno(got) == .SUCCESS);
    try std.testing.expect(mask[0] != 0);
    try std.testing.expectEqual(@as(usize, @intCast(mask[0])), SetThreadAffinityMask(~@as(usize, 1), @intCast(mask[0])));
    try std.testing.expectEqual(@as(usize, 0), SetThreadAffinityMask(0x1234, 1));
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
    var path_buf: [1024]u8 = undefined;
    const p: ?[*:0]const u16 = if (lpPathName) |q| @ptrCast(q) else null;
    const host_path = wideToTranslatedPath(p, &path_buf) orelse {
        setLastError(3); // ERROR_PATH_NOT_FOUND
        return 0;
    };
    const e = linux.errno(linux.rmdir(host_path.ptr));
    if (e == .SUCCESS) return 1;
    setLastError(win32ErrorFromErrno(e));
    return 0;
}

fn ReplaceFileW(lpReplacedFileName: ?*const u16, lpReplacementFileName: ?*const u16, lpBackupFileName: ?*const u16, dwReplaceFlags: u32, lpExclude: ?*anyopaque, lpReserved: ?*anyopaque) callconv(W) i32 {
    _ = lpReplacedFileName; _ = lpReplacementFileName; _ = lpBackupFileName; _ = dwReplaceFlags; _ = lpExclude; _ = lpReserved;
    return 1;
}

/// File I/O here completes synchronously; ReadFile/WriteFile store the NTSTATUS in
/// OVERLAPPED.Internal and the byte count in InternalHigh, as Windows does.
const OverlappedHead = extern struct { Internal: usize, InternalHigh: usize };
fn GetOverlappedResult(hFile: usize, lpOverlapped: ?*anyopaque, lpNumberOfBytesTransferred: ?*u32, bWait: i32) callconv(W) i32 {
    _ = hFile; _ = bWait;
    const ov: *const OverlappedHead = @ptrCast(@alignCast(lpOverlapped orelse {
        setLastError(87);
        return 0;
    }));
    if (lpNumberOfBytesTransferred) |p| p.* = @truncate(ov.InternalHigh);
    if (ov.Internal != 0) {
        setLastError(if (ov.Internal == 0xC0000011) 38 else 31); // EOF -> ERROR_HANDLE_EOF
        return 0;
    }
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
    _ = fInfoLevelId; _ = fSearchOp; _ = lpSearchFilter; _ = dwAdditionalFlags;
    return FindFirstFileA(lpFileName, @ptrCast(lpFindFileData));
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

fn GetProductInfo(dwOSMajorVersion: u32, dwOSMinorVersion: u32, dwSpMajorVersion: u32, dwSpMinorVersion: u32, pdwReturnedProductType: ?*u32) callconv(W) i32 {
    _ = dwOSMajorVersion; _ = dwOSMinorVersion; _ = dwSpMajorVersion; _ = dwSpMinorVersion;
    if (pdwReturnedProductType) |p| p.* = 0x00000030;
    return 1;
}

fn GetTickCount64() callconv(W) u64 {
    return 1000000;
}

fn TerminateThread(hThread: usize, dwExitCode: u32) callconv(W) i32 {
    _ = hThread; _ = dwExitCode;
    return 1;
}

fn lstrcmpiW(lpString1: ?[*:0]const u16, lpString2: ?[*:0]const u16) callconv(W) i32 {
    if (lpString1 == null or lpString2 == null) return 0;
    var i: usize = 0;
    while (true) : (i += 1) {
        var c1 = lpString1.?[i];
        var c2 = lpString2.?[i];
        if (c1 >= 'A' and c1 <= 'Z') c1 += 32;
        if (c2 >= 'A' and c2 <= 'Z') c2 += 32;
        if (c1 != c2) return if (c1 < c2) -1 else 1;
        if (c1 == 0) return 0;
    }
}

fn lstrcmpiA(lpString1: ?[*:0]const u8, lpString2: ?[*:0]const u8) callconv(W) i32 {
    if (lpString1 == null or lpString2 == null) return 0;
    var i: usize = 0;
    while (true) : (i += 1) {
        var c1 = lpString1.?[i];
        var c2 = lpString2.?[i];
        if (c1 >= 'A' and c1 <= 'Z') c1 += 32;
        if (c2 >= 'A' and c2 <= 'Z') c2 += 32;
        if (c1 != c2) return if (c1 < c2) -1 else 1;
        if (c1 == 0) return 0;
    }
}

fn lstrcpynW(lpString1: ?[*:0]u16, lpString2: ?[*:0]const u16, iMaxLength: i32) callconv(W) ?[*:0]u16 {
    if (lpString1) |dst| {
        if (iMaxLength > 0) {
            var i: usize = 0;
            const max: usize = @intCast(iMaxLength - 1);
            if (lpString2) |src| {
                while (i < max and src[i] != 0) : (i += 1) {
                    dst[i] = src[i];
                }
            }
            dst[i] = 0;
        }
    }
    return lpString1;
}

fn lstrcpynA(lpString1: ?[*:0]u8, lpString2: ?[*:0]const u8, iMaxLength: i32) callconv(W) ?[*:0]u8 {
    if (lpString1) |dst| {
        if (iMaxLength > 0) {
            var i: usize = 0;
            const max: usize = @intCast(iMaxLength - 1);
            if (lpString2) |src| {
                while (i < max and src[i] != 0) : (i += 1) {
                    dst[i] = src[i];
                }
            }
            dst[i] = 0;
        }
    }
    return lpString1;
}

fn GetFinalPathNameByHandleW(hFile: usize, lpszFilePath: ?[*:0]u16, cchFilePath: u32, dwFlags: u32) callconv(W) u32 {
    _ = hFile; _ = dwFlags;
    if (lpszFilePath) |s| {
        if (cchFilePath > 0) s[0] = 0;
    }
    return 0;
}

fn FindFirstStreamW(lpFileName: ?[*:0]const u16, InfoLevel: u32, lpFindStreamData: ?*anyopaque, dwFlags: u32) callconv(W) usize {
    _ = lpFileName; _ = InfoLevel; _ = lpFindStreamData; _ = dwFlags;
    return ~@as(usize, 0);
}

const IMAGE_RESOURCE_DIRECTORY = extern struct {
    Characteristics: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    NumberOfNamedEntries: u16,
    NumberOfIdEntries: u16,
};

const IMAGE_RESOURCE_DIRECTORY_ENTRY = extern struct {
    NameOrId: u32,
    OffsetToData: u32,
};

pub const IMAGE_RESOURCE_DATA_ENTRY = extern struct {
    OffsetToData: u32,
    Size: u32,
    CodePage: u32,
    Reserved: u32,
};

fn peResourceDirSlice(base: usize) ?struct { base: usize, img_size: usize, rsrc: []const u8 } {
    if (base < 0x10000) return null;
    const mem: [*]const u8 = @ptrFromInt(base);
    if (mem[0] != 'M' or mem[1] != 'Z') return null;
    const e_lfanew = std.mem.readInt(u32, mem[0x3c..][0..4], .little);
    if (e_lfanew > 0x4000) return null;
    const pe = mem + e_lfanew;
    if (pe[0] != 'P' or pe[1] != 'E' or pe[2] != 0 or pe[3] != 0) return null;
    const magic = std.mem.readInt(u16, pe[24..][0..2], .little);
    const img_size = std.mem.readInt(u32, pe[24 + 56 ..][0..4], .little);
    const dd_off: usize = if (magic == 0x20b) 24 + 112 else if (magic == 0x10b) 24 + 96 else return null;
    // DataDirectory[2] = IMAGE_DIRECTORY_ENTRY_RESOURCE
    const rsrc_rva = std.mem.readInt(u32, pe[dd_off + 2 * 8 ..][0..4], .little);
    const rsrc_sz = std.mem.readInt(u32, pe[dd_off + 2 * 8 + 4 ..][0..4], .little);
    if (rsrc_rva == 0 or rsrc_sz < @sizeOf(IMAGE_RESOURCE_DIRECTORY)) return null;
    if (@as(u64, rsrc_rva) + rsrc_sz > img_size) return null;
    return .{ .base = base, .img_size = img_size, .rsrc = mem[rsrc_rva .. rsrc_rva + rsrc_sz] };
}

fn rsrcMatchNameW(rsrc: []const u8, name_off: u32, target: []const u16) bool {
    const off: usize = name_off & 0x7fffffff;
    if (off + 2 > rsrc.len) return false;
    const nchars = std.mem.readInt(u16, rsrc[off..][0..2], .little);
    if (nchars != target.len or off + 2 + @as(usize, nchars) * 2 > rsrc.len) return false;
    for (0..nchars) |i| {
        const c = std.mem.readInt(u16, rsrc[off + 2 + i * 2 ..][0..2], .little);
        const lc: u16 = if (c >= 'a' and c <= 'z') c - 32 else c;
        const tc: u16 = if (target[i] >= 'a' and target[i] <= 'z') target[i] - 32 else target[i];
        if (lc != tc) return false;
    }
    return true;
}

fn rsrcLookupLevel(rsrc: []const u8, dir_off: usize, key: ?*const anyopaque, ascii_key: ?[*:0]const u8) ?u32 {
    if (dir_off + @sizeOf(IMAGE_RESOURCE_DIRECTORY) > rsrc.len) return null;
    const dir: *const IMAGE_RESOURCE_DIRECTORY = @ptrCast(@alignCast(rsrc.ptr + dir_off));
    const n_named: usize = dir.NumberOfNamedEntries;
    const n_id: usize = dir.NumberOfIdEntries;
    const ents_off = dir_off + @sizeOf(IMAGE_RESOURCE_DIRECTORY);
    if (ents_off + (n_named + n_id) * @sizeOf(IMAGE_RESOURCE_DIRECTORY_ENTRY) > rsrc.len) return null;
    const ents: [*]const IMAGE_RESOURCE_DIRECTORY_ENTRY = @ptrCast(@alignCast(rsrc.ptr + ents_off));

    const raw_addr = if (key) |k| @intFromPtr(k) else @intFromPtr(ascii_key orelse return null);
    if (raw_addr < 0x10000) {
        const id: u32 = @intCast(raw_addr);
        for (ents[n_named .. n_named + n_id]) |ent| {
            if (ent.NameOrId == id) return ent.OffsetToData;
        }
        return null;
    }
    var wbuf: [128]u16 = undefined;
    var wlen: usize = 0;
    if (key != null) {
        const ws: [*:0]const u16 = @ptrCast(@alignCast(key.?));
        while (wlen < wbuf.len and ws[wlen] != 0) : (wlen += 1) wbuf[wlen] = ws[wlen];
    } else if (ascii_key) |as| {
        while (wlen < wbuf.len and as[wlen] != 0) : (wlen += 1) wbuf[wlen] = as[wlen];
    }
    for (ents[0..n_named]) |ent| {
        if ((ent.NameOrId & 0x80000000) != 0 and rsrcMatchNameW(rsrc, ent.NameOrId, wbuf[0..wlen])) {
            return ent.OffsetToData;
        }
    }
    return null;
}

pub fn findResourceBytes(hModule: usize, lpName: ?*const anyopaque, lpType: ?*const anyopaque) ?[]const u8 {
    const base = if (hModule == 0) image_base_addr else hModule;
    const info = peResourceDirSlice(base) orelse return null;
    const data_ent_ptr = FindResourceExInternal(info.rsrc, lpName, null, lpType, null, 0) orelse return null;
    if (@as(u64, data_ent_ptr.OffsetToData) + data_ent_ptr.Size > info.img_size) return null;
    const mem: [*]const u8 = @ptrFromInt(base);
    return mem[data_ent_ptr.OffsetToData .. data_ent_ptr.OffsetToData + data_ent_ptr.Size];
}

fn FindResourceExInternal(
    rsrc: []const u8,
    lpNameW: ?*const anyopaque,
    lpNameA: ?[*:0]const u8,
    lpTypeW: ?*const anyopaque,
    lpTypeA: ?[*:0]const u8,
    lang: u16,
) ?*const IMAGE_RESOURCE_DATA_ENTRY {
    const type_off = rsrcLookupLevel(rsrc, 0, lpTypeW, lpTypeA) orelse return null;
    if ((type_off & 0x80000000) == 0) return null;
    const name_off = rsrcLookupLevel(rsrc, type_off & 0x7fffffff, lpNameW, lpNameA) orelse return null;
    if ((name_off & 0x80000000) == 0) return null;
    const lang_dir_off: usize = name_off & 0x7fffffff;
    if (lang_dir_off + @sizeOf(IMAGE_RESOURCE_DIRECTORY) > rsrc.len) return null;
    const lang_dir: *const IMAGE_RESOURCE_DIRECTORY = @ptrCast(@alignCast(rsrc.ptr + lang_dir_off));
    const total = @as(usize, lang_dir.NumberOfNamedEntries) + lang_dir.NumberOfIdEntries;
    const ents_off = lang_dir_off + @sizeOf(IMAGE_RESOURCE_DIRECTORY);
    if (total == 0 or ents_off + total * @sizeOf(IMAGE_RESOURCE_DIRECTORY_ENTRY) > rsrc.len) return null;
    const ents: [*]const IMAGE_RESOURCE_DIRECTORY_ENTRY = @ptrCast(@alignCast(rsrc.ptr + ents_off));
    var chosen = ents[0].OffsetToData;
    if (lang != 0) {
        for (ents[0..total]) |e| {
            if (e.NameOrId == lang) {
                chosen = e.OffsetToData;
                break;
            }
        }
    }
    if ((chosen & 0x80000000) != 0) return null;
    if (@as(usize, chosen) + @sizeOf(IMAGE_RESOURCE_DATA_ENTRY) > rsrc.len) return null;
    return @ptrCast(@alignCast(rsrc.ptr + chosen));
}

fn FindResourceW(hModule: usize, lpName: ?*const anyopaque, lpType: ?*const anyopaque) callconv(W) usize {
    return FindResourceExW(hModule, lpType, lpName, 0);
}

fn FindResourceExW(hModule: usize, lpType: ?*const anyopaque, lpName: ?*const anyopaque, wLanguage: u16) callconv(W) usize {
    const base = if (hModule == 0) image_base_addr else hModule;
    const info = peResourceDirSlice(base) orelse return 0;
    const ent = FindResourceExInternal(info.rsrc, lpName, null, lpType, null, wLanguage) orelse return 0;
    return @intFromPtr(ent);
}

fn FindResourceA(hModule: usize, lpName: ?[*:0]const u8, lpType: ?[*:0]const u8) callconv(W) usize {
    const base = if (hModule == 0) image_base_addr else hModule;
    const info = peResourceDirSlice(base) orelse return 0;
    const ent = FindResourceExInternal(info.rsrc, null, lpName, null, lpType, 0) orelse return 0;
    return @intFromPtr(ent);
}

fn LoadResource(hModule: usize, hResInfo: usize) callconv(W) usize {
    if (hResInfo == 0) return 0;
    const base = if (hModule == 0) image_base_addr else hModule;
    const info = peResourceDirSlice(base) orelse return 0;
    const ent: *const IMAGE_RESOURCE_DATA_ENTRY = @ptrFromInt(hResInfo);
    if (@as(u64, ent.OffsetToData) + ent.Size > info.img_size) return 0;
    return base + ent.OffsetToData;
}

fn LockResource(hResData: usize) callconv(W) ?*anyopaque {
    if (hResData < 0x10000) return null;
    return @ptrFromInt(hResData);
}

fn SizeofResource(hModule: usize, hResInfo: usize) callconv(W) u32 {
    _ = hModule;
    if (hResInfo < 0x10000) return 0;
    const ent: *const IMAGE_RESOURCE_DATA_ENTRY = @ptrFromInt(hResInfo);
    return ent.Size;
}

fn GetLongPathNameW(lpszShortPath: ?[*:0]const u16, lpszLongPath: ?[*:0]u16, cchBuffer: u32) callconv(W) u32 {
    _ = cchBuffer;
    if (lpszShortPath != null and lpszLongPath != null) {
        var i: usize = 0;
        while (lpszShortPath.?[i] != 0) : (i += 1) {
            lpszLongPath.?[i] = lpszShortPath.?[i];
        }
        lpszLongPath.?[i] = 0;
        return @intCast(i);
    }
    return 0;
}

fn GetApplicationRestartSettings(hProcess: usize, pwzCommandline: ?*?*u16, pcchSize: ?*u32, pdwFlags: ?*u32) callconv(W) i32 {
    _ = hProcess; _ = pwzCommandline; _ = pcchSize; _ = pdwFlags;
    return -2147023728;
}

fn RegisterApplicationRestart(pwzCommandLine: ?[*:0]const u16, dwFlags: u32) callconv(W) i32 {
    _ = pwzCommandLine; _ = dwFlags;
    return 0;
}

fn UnregisterApplicationRestart() callconv(W) i32 {
    return 0;
}

fn QueryFullProcessImageNameW(hProcess: usize, dwFlags: u32, lpExeName: ?[*:0]u16, lpdwSize: ?*u32) callconv(W) i32 {
    _ = hProcess; _ = dwFlags;
    if (lpExeName) |s| s[0] = 0;
    if (lpdwSize) |sz| sz.* = 0;
    return 1;
}

fn GlobalSize(hMem: usize) callconv(W) usize {
    _ = hMem;
    return 4096;
}

fn CopyFileExW(lpExistingFileName: ?[*:0]const u16, lpNewFileName: ?[*:0]const u16, lpProgressRoutine: ?*anyopaque, lpData: ?*anyopaque, pbCancel: ?*i32, dwCopyFlags: u32) callconv(W) i32 {
    _ = lpExistingFileName; _ = lpNewFileName; _ = lpProgressRoutine; _ = lpData; _ = pbCancel; _ = dwCopyFlags;
    return 1;
}

fn CompareStringOrdinal(lpString1: ?*const u16, cchCount1: i32, lpString2: ?*const u16, cchCount2: i32, bIgnoreCase: i32) callconv(W) i32 {
    _ = lpString1; _ = cchCount1; _ = lpString2; _ = cchCount2; _ = bIgnoreCase;
    return 2;
}

fn CompareStringEx(lpLocaleName: ?[*:0]const u16, dwCmpFlags: u32, lpString1: ?*const u16, cchCount1: i32, lpString2: ?*const u16, cchCount2: i32, lpVersionInformation: ?*anyopaque, lpReserved: ?*anyopaque, lParam: usize) callconv(W) i32 {
    _ = lpLocaleName; _ = dwCmpFlags; _ = lpString1; _ = cchCount1; _ = lpString2; _ = cchCount2; _ = lpVersionInformation; _ = lpReserved; _ = lParam;
    return 2;
}

fn Process32FirstW(hSnapshot: usize, lppe: ?*anyopaque) callconv(W) i32 {
    _ = hSnapshot; _ = lppe;
    return 0;
}

fn Process32NextW(hSnapshot: usize, lppe: ?*anyopaque) callconv(W) i32 {
    _ = hSnapshot; _ = lppe;
    return 0;
}

fn QueueUserAPC(pfnAPC: ?*anyopaque, hThread: usize, dwData: usize) callconv(W) u32 {
    _ = pfnAPC; _ = hThread; _ = dwData;
    return 1;
}

fn GetLocaleInfoA(Locale: u32, LCType: u32, lpLCData: ?[*:0]u8, cchData: i32) callconv(W) i32 {
    _ = Locale; _ = LCType;
    if (lpLCData) |s| {
        if (cchData > 0) s[0] = 0;
    }
    return 1;
}

fn GetStringTypeExW(Locale: u32, dwInfoType: u32, lpSrcStr: ?*const u16, cchSrc: i32, lpCharType: ?*u16) callconv(W) i32 {
    _ = Locale; _ = dwInfoType; _ = lpSrcStr; _ = cchSrc;
    if (lpCharType) |ct| ct.* = 0;
    return 1;
}

fn GetStringTypeExA(Locale: u32, dwInfoType: u32, lpSrcStr: ?*const u8, cchSrc: i32, lpCharType: ?*u16) callconv(W) i32 {
    _ = Locale; _ = dwInfoType; _ = lpSrcStr; _ = cchSrc;
    if (lpCharType) |ct| ct.* = 0;
    return 1;
}

fn LCMapStringA(Locale: u32, dwMapFlags: u32, lpSrcStr: ?*const u8, cchSrc: i32, lpDestStr: ?*u8, cchDest: i32) callconv(W) i32 {
    _ = Locale; _ = dwMapFlags; _ = lpSrcStr; _ = cchSrc; _ = lpDestStr; _ = cchDest;
    return 1;
}

fn GetNativeSystemInfo(lpSystemInfo: ?*anyopaque) callconv(W) void {
    const ptr: ?[*]u8 = if (lpSystemInfo) |p| @ptrCast(p) else null;
    GetSystemInfo(ptr);
}

fn CreateThreadpoolWork(pfnwk: ?*anyopaque, pv: ?*anyopaque, pcbe: ?*anyopaque) callconv(W) usize {
    _ = pfnwk; _ = pv; _ = pcbe;
    return 0x9001;
}

fn SubmitThreadpoolWork(pwk: usize) callconv(W) void {
    _ = pwk;
}

fn CloseThreadpoolWork(pwk: usize) callconv(W) void {
    _ = pwk;
}

fn FreeLibraryWhenCallbackReturns(pci: ?*anyopaque, hLibModule: usize) callconv(W) void {
    _ = pci; _ = hLibModule;
}

fn InitOnceBeginInitialize(lpInitOnce: ?*anyopaque, dwFlags: u32, fPending: ?*i32, lpContext: ?*?*anyopaque) callconv(W) i32 {
    _ = lpInitOnce; _ = dwFlags; _ = lpContext;
    if (fPending) |p| p.* = 0;
    return 1;
}

fn InitOnceComplete(lpInitOnce: ?*anyopaque, dwFlags: u32, lpContext: ?*anyopaque) callconv(W) i32 {
    _ = lpInitOnce; _ = dwFlags; _ = lpContext;
    return 1;
}

fn GetVersion() callconv(W) u32 {
    return 0x00060001;
}

fn FatalAppExitA(uAction: u32, lpMessageText: ?[*:0]const u8) callconv(W) void {
    _ = uAction;
    if (lpMessageText) |msg| {
        std.debug.print("[WINS:FatalAppExitA] {s}\n", .{std.mem.span(msg)});
    }
    linux.exit_group(1);
}

fn SetHandleCount(uNumberOfHandles: u32) callconv(W) u32 {
    return uNumberOfHandles;
}

fn HeapSetInformation(HeapHandle: usize, HeapInformationClass: u32, HeapInformation: ?*const anyopaque, HeapInformationLength: usize) callconv(W) i32 {
    _ = HeapHandle;
    _ = HeapInformationClass;
    _ = HeapInformation;
    _ = HeapInformationLength;
    return 1;
}

fn ansiToWideBuf(src: ?[*:0]const u8, buf: []u16) ?[*:0]const u16 {
    const p = src orelse return null;
    const s = std.mem.span(p);
    const n = @min(s.len, buf.len - 1);
    for (s[0..n], 0..) |c, idx| buf[idx] = c;
    buf[n] = 0;
    return @ptrCast(buf.ptr);
}

fn CreateDirectoryA(lpPathName: ?[*:0]const u8, sa: ?*anyopaque) callconv(W) u32 {
    var wbuf: [1024]u16 = undefined;
    const wp = ansiToWideBuf(lpPathName, &wbuf) orelse {
        setLastError(3);
        return 0;
    };
    return CreateDirectoryW(wp, sa);
}

fn MoveFileA(lpExistingFileName: ?[*:0]const u8, lpNewFileName: ?[*:0]const u8) callconv(W) u32 {
    var wsrc: [1024]u16 = undefined;
    var wdst: [1024]u16 = undefined;
    const ws = ansiToWideBuf(lpExistingFileName, &wsrc) orelse return 0;
    const wd = ansiToWideBuf(lpNewFileName, &wdst) orelse return 0;
    return MoveFileW(ws, wd);
}

fn LocalFileTimeToFileTime(lpLocalFileTime: ?*const u64, lpFileTime: ?*u64) callconv(W) i32 {
    if (lpLocalFileTime == null or lpFileTime == null) return 0;
    lpFileTime.?.* = lpLocalFileTime.?.*;
    return 1;
}

fn RtlInstallFunctionTableCallback(
    TableIdentifier: usize,
    BaseAddress: usize,
    Length: u32,
    Callback: ?*const anyopaque,
    Context: ?*anyopaque,
    OutOfProcessCallbackDll: ?[*:0]const u16,
) callconv(W) u8 {
    _ = OutOfProcessCallbackDll;
    return if (comptime builtin.cpu.arch == .x86_64)
        seh64.installFunctionTableCallback(TableIdentifier, BaseAddress, Length, Callback, Context)
    else
        1;
}

fn RtlDeleteFunctionTable(FunctionTable: ?*anyopaque) callconv(W) u8 {
    return if (comptime builtin.cpu.arch == .x86_64) seh64.deleteFunctionTable(FunctionTable) else 1;
}

fn RtlAddFunctionTable(FunctionTable: ?*anyopaque, EntryCount: u32, BaseAddress: usize) callconv(W) u8 {
    return if (comptime builtin.cpu.arch == .x86_64)
        seh64.addFunctionTable(@ptrCast(@alignCast(FunctionTable)), EntryCount, BaseAddress)
    else
        1;
}

fn GlobalReAlloc(hMem: ?*anyopaque, dwBytes: usize, uFlags: u32) callconv(W) ?*anyopaque {
    _ = uFlags;
    if (hMem == null) return HeapAlloc(HEAP_COOKIE, 0, dwBytes);
    return HeapReAlloc(HEAP_COOKIE, 0, @ptrCast(hMem.?), dwBytes);
}

fn GetProcessWorkingSetSize(hProcess: usize, lpMinimumWorkingSetSize: ?*usize, lpMaximumWorkingSetSize: ?*usize) callconv(W) i32 {
    _ = hProcess;
    if (lpMinimumWorkingSetSize) |p| p.* = 1024 * 1024;
    if (lpMaximumWorkingSetSize) |p| p.* = 64 * 1024 * 1024;
    return 1;
}

fn SetProcessWorkingSetSize(hProcess: usize, dwMinimumWorkingSetSize: usize, dwMaximumWorkingSetSize: usize) callconv(W) i32 {
    _ = hProcess;
    _ = dwMinimumWorkingSetSize;
    _ = dwMaximumWorkingSetSize;
    return 1;
}

fn GetPriorityClass(hProcess: usize) callconv(W) u32 {
    _ = hProcess;
    return 0x20; // NORMAL_PRIORITY_CLASS
}

fn SetPriorityClass(hProcess: usize, dwPriorityClass: u32) callconv(W) i32 {
    _ = hProcess;
    _ = dwPriorityClass;
    return 1;
}

fn OpenSemaphoreW(dwDesiredAccess: u32, bInheritHandle: i32, lpName: ?[*:0]const u16) callconv(W) usize {
    _ = dwDesiredAccess;
    _ = bInheritHandle;
    _ = lpName;
    return 0;
}

fn OpenThread(dwDesiredAccess: u32, bInheritHandle: i32, dwThreadId: u32) callconv(W) usize {
    _ = dwDesiredAccess;
    _ = bInheritHandle;
    return 0x20000 | (@as(usize, dwThreadId) & 0xFFFF);
}

fn WaitForMultipleObjectsEx(nCount: u32, lpHandles: ?*const usize, bWaitAll: u32, dwMilliseconds: u32, bAlertable: i32) callconv(W) u32 {
    _ = bAlertable;
    return WaitForMultipleObjects(nCount, lpHandles, bWaitAll, dwMilliseconds);
}

fn FreeConsole() callconv(W) i32 {
    return 1;
}

fn AddVectoredExceptionHandler(First: u32, Handler: ?*const anyopaque) callconv(W) ?*anyopaque {
    return if (comptime builtin.cpu.arch == .x86_64)
        seh64.addVectoredExceptionHandler(First, Handler)
    else
        @constCast(Handler);
}

fn RemoveVectoredExceptionHandler(Handle: ?*anyopaque) callconv(W) u32 {
    return if (comptime builtin.cpu.arch == .x86_64) seh64.removeVectoredExceptionHandler(Handle) else 1;
}

fn EnumSystemLocalesA(lpLocaleEnumProc: ?*const anyopaque, dwFlags: u32) callconv(W) i32 {
    _ = dwFlags;
    const cb: *const fn ([*:0]const u8) callconv(W) i32 = @ptrCast(@alignCast(lpLocaleEnumProc orelse return 0));
    _ = cb("00000409");
    return 1;
}

fn VerLanguageNameW(wLang: u32, szLang: ?[*]u16, cchLang: u32) callconv(W) u32 {
    _ = wLang;
    const msg = [_]u16{ 'E', 'n', 'g', 'l', 'i', 's', 'h', ' ', '(', 'U', 'n', 'i', 't', 'e', 'd', ' ', 'S', 't', 'a', 't', 'e', 's', ')' };
    if (szLang == null or cchLang == 0) return msg.len;
    const n: u32 = @min(cchLang - 1, @as(u32, msg.len));
    @memcpy(szLang.?[0..n], msg[0..n]);
    szLang.?[n] = 0;
    return n;
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
    if (std.mem.eql(u8, name, "GetThreadPriority")) return @intFromPtr(&GetThreadPriority);
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
    if (std.mem.eql(u8, name, "CopyFileA")) return @intFromPtr(&CopyFileA);
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
    if (std.mem.eql(u8, name, "RaiseException")) return raiseExceptionAddr();
    if (std.mem.eql(u8, name, "RtlPcToFileHeader")) return @intFromPtr(&RtlPcToFileHeader);
    if (std.mem.eql(u8, name, "RtlUnwind")) return @intFromPtr(&RtlUnwind);
    if (std.mem.eql(u8, name, "RtlUnwindEx")) return @intFromPtr(&RtlUnwindEx);
    if (std.mem.eql(u8, name, "RtlCaptureContext")) return rtlCaptureContextAddr();
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
    if (std.mem.eql(u8, name, "SetFileApisToOEM")) return @intFromPtr(&SetFileApisToOEM);
    if (std.mem.eql(u8, name, "CreateHardLinkW")) return @intFromPtr(&CreateHardLinkW);
    if (std.mem.eql(u8, name, "MoveFileWithProgressW")) return @intFromPtr(&MoveFileWithProgressW);
    if (std.mem.eql(u8, name, "SetProcessAffinityMask")) return @intFromPtr(&SetProcessAffinityMask);
    if (std.mem.eql(u8, name, "GetLogicalDriveStringsW")) return @intFromPtr(&GetLogicalDriveStringsW);
    if (std.mem.eql(u8, name, "OpenEventW")) return @intFromPtr(&OpenEventW);
    if (std.mem.eql(u8, name, "OpenFileMappingW")) return @intFromPtr(&OpenFileMappingW);
    // 7zr resolves these four dynamically via GetProcAddress.
    if (std.mem.eql(u8, name, "SetDefaultDllDirectories")) return @intFromPtr(&SetDefaultDllDirectories);
    if (std.mem.eql(u8, name, "FindNextStreamW")) return @intFromPtr(&FindNextStreamW);
    if (std.mem.eql(u8, name, "NtSetInformationFile")) return @intFromPtr(&NtSetInformationFile);
    if (std.mem.eql(u8, name, "RtlNtStatusToDosError")) return @intFromPtr(&RtlNtStatusToDosError);
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
    if (std.mem.eql(u8, name, "GetLogicalProcessorInformation")) return @intFromPtr(&GetLogicalProcessorInformation);

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
    if (std.mem.eql(u8, name, "GetProductInfo")) return @intFromPtr(&GetProductInfo);
    if (std.mem.eql(u8, name, "GetTickCount64")) return @intFromPtr(&GetTickCount64);
    if (std.mem.eql(u8, name, "TerminateThread")) return @intFromPtr(&TerminateThread);
    if (std.mem.eql(u8, name, "lstrcmpiW")) return @intFromPtr(&lstrcmpiW);
    if (std.mem.eql(u8, name, "lstrcmpiA")) return @intFromPtr(&lstrcmpiA);
    if (std.mem.eql(u8, name, "lstrcpynW")) return @intFromPtr(&lstrcpynW);
    if (std.mem.eql(u8, name, "lstrcpynA")) return @intFromPtr(&lstrcpynA);
    if (std.mem.eql(u8, name, "GetFinalPathNameByHandleW")) return @intFromPtr(&GetFinalPathNameByHandleW);
    if (std.mem.eql(u8, name, "FindFirstStreamW")) return @intFromPtr(&FindFirstStreamW);
    if (std.mem.eql(u8, name, "FindResourceW")) return @intFromPtr(&FindResourceW);
    if (std.mem.eql(u8, name, "FindResourceExW")) return @intFromPtr(&FindResourceExW);
    if (std.mem.eql(u8, name, "FindResourceA")) return @intFromPtr(&FindResourceA);
    if (std.mem.eql(u8, name, "LoadResource")) return @intFromPtr(&LoadResource);
    if (std.mem.eql(u8, name, "LockResource")) return @intFromPtr(&LockResource);
    if (std.mem.eql(u8, name, "SizeofResource")) return @intFromPtr(&SizeofResource);
    if (std.mem.eql(u8, name, "GetLongPathNameW")) return @intFromPtr(&GetLongPathNameW);
    if (std.mem.eql(u8, name, "GetApplicationRestartSettings")) return @intFromPtr(&GetApplicationRestartSettings);
    if (std.mem.eql(u8, name, "RegisterApplicationRestart")) return @intFromPtr(&RegisterApplicationRestart);
    if (std.mem.eql(u8, name, "UnregisterApplicationRestart")) return @intFromPtr(&UnregisterApplicationRestart);
    if (std.mem.eql(u8, name, "QueryFullProcessImageNameW")) return @intFromPtr(&QueryFullProcessImageNameW);
    if (std.mem.eql(u8, name, "GlobalSize")) return @intFromPtr(&GlobalSize);
    if (std.mem.eql(u8, name, "CopyFileExW")) return @intFromPtr(&CopyFileExW);
    if (std.mem.eql(u8, name, "CompareStringOrdinal")) return @intFromPtr(&CompareStringOrdinal);
    if (std.mem.eql(u8, name, "CompareStringEx")) return @intFromPtr(&CompareStringEx);
    if (std.mem.eql(u8, name, "Process32FirstW")) return @intFromPtr(&Process32FirstW);
    if (std.mem.eql(u8, name, "Process32NextW")) return @intFromPtr(&Process32NextW);
    if (std.mem.eql(u8, name, "QueueUserAPC")) return @intFromPtr(&QueueUserAPC);
    if (std.mem.eql(u8, name, "GetLocaleInfoA")) return @intFromPtr(&GetLocaleInfoA);
    if (std.mem.eql(u8, name, "GetStringTypeExW")) return @intFromPtr(&GetStringTypeExW);
    if (std.mem.eql(u8, name, "GetStringTypeExA")) return @intFromPtr(&GetStringTypeExA);
    if (std.mem.eql(u8, name, "LCMapStringA")) return @intFromPtr(&LCMapStringA);
    if (std.mem.eql(u8, name, "GetNativeSystemInfo")) return @intFromPtr(&GetNativeSystemInfo);
    if (std.mem.eql(u8, name, "CreateThreadpoolWork")) return @intFromPtr(&CreateThreadpoolWork);
    if (std.mem.eql(u8, name, "SubmitThreadpoolWork")) return @intFromPtr(&SubmitThreadpoolWork);
    if (std.mem.eql(u8, name, "CloseThreadpoolWork")) return @intFromPtr(&CloseThreadpoolWork);
    if (std.mem.eql(u8, name, "FreeLibraryWhenCallbackReturns")) return @intFromPtr(&FreeLibraryWhenCallbackReturns);
    if (std.mem.eql(u8, name, "InitOnceBeginInitialize")) return @intFromPtr(&InitOnceBeginInitialize);
    if (std.mem.eql(u8, name, "InitOnceComplete")) return @intFromPtr(&InitOnceComplete);
    if (std.mem.eql(u8, name, "GetVersion")) return @intFromPtr(&GetVersion);
    if (std.mem.eql(u8, name, "FatalAppExitA")) return @intFromPtr(&FatalAppExitA);
    if (std.mem.eql(u8, name, "SetHandleCount")) return @intFromPtr(&SetHandleCount);
    if (std.mem.eql(u8, name, "HeapSetInformation")) return @intFromPtr(&HeapSetInformation);
    if (std.mem.eql(u8, name, "CreateDirectoryA")) return @intFromPtr(&CreateDirectoryA);
    if (std.mem.eql(u8, name, "MoveFileA")) return @intFromPtr(&MoveFileA);
    if (std.mem.eql(u8, name, "LocalFileTimeToFileTime")) return @intFromPtr(&LocalFileTimeToFileTime);
    if (std.mem.eql(u8, name, "RtlInstallFunctionTableCallback")) return @intFromPtr(&RtlInstallFunctionTableCallback);
    if (std.mem.eql(u8, name, "RtlDeleteFunctionTable")) return @intFromPtr(&RtlDeleteFunctionTable);
    if (std.mem.eql(u8, name, "RtlAddFunctionTable")) return @intFromPtr(&RtlAddFunctionTable);
    if (std.mem.eql(u8, name, "GlobalReAlloc")) return @intFromPtr(&GlobalReAlloc);
    if (std.mem.eql(u8, name, "GetProcessWorkingSetSize")) return @intFromPtr(&GetProcessWorkingSetSize);
    if (std.mem.eql(u8, name, "SetProcessWorkingSetSize")) return @intFromPtr(&SetProcessWorkingSetSize);
    if (std.mem.eql(u8, name, "GetPriorityClass")) return @intFromPtr(&GetPriorityClass);
    if (std.mem.eql(u8, name, "SetPriorityClass")) return @intFromPtr(&SetPriorityClass);
    if (std.mem.eql(u8, name, "OpenSemaphoreW")) return @intFromPtr(&OpenSemaphoreW);
    if (std.mem.eql(u8, name, "OpenThread")) return @intFromPtr(&OpenThread);
    if (std.mem.eql(u8, name, "WaitForMultipleObjectsEx")) return @intFromPtr(&WaitForMultipleObjectsEx);
    if (std.mem.eql(u8, name, "FreeConsole")) return @intFromPtr(&FreeConsole);
    if (std.mem.eql(u8, name, "AddVectoredExceptionHandler")) return @intFromPtr(&AddVectoredExceptionHandler);
    if (std.mem.eql(u8, name, "RemoveVectoredExceptionHandler")) return @intFromPtr(&RemoveVectoredExceptionHandler);
    if (std.mem.eql(u8, name, "EnumSystemLocalesA")) return @intFromPtr(&EnumSystemLocalesA);
    if (std.mem.eql(u8, name, "VerLanguageNameW")) return @intFromPtr(&VerLanguageNameW);

    return null;
}

test "setCommandLine quotes spaces, empty args, quotes, and trailing backslashes" {
    setCommandLine(&.{ "sqlite3.exe", ":memory:", "SELECT 40 + 2;" });
    try std.testing.expectEqualStrings(
        "sqlite3.exe :memory: \"SELECT 40 + 2;\"",
        std.mem.sliceTo(&cmdline_storage_a, 0),
    );

    setCommandLine(&.{ "app.exe", "", "say \"hi\"", "C:\\dir with space\\" });
    try std.testing.expectEqualStrings(
        "app.exe \"\" \"say \\\"hi\\\"\" \"C:\\dir with space\\\\\"",
        std.mem.sliceTo(&cmdline_storage_a, 0),
    );
}

test "findResourceBytes traverses 3-level PE .rsrc directory tree" {
    var img: [1024]u8 align(8) = [_]u8{0} ** 1024;
    img[0] = 'M';
    img[1] = 'Z';
    std.mem.writeInt(u32, img[0x3c..][0..4], 0x40, .little);
    img[0x40] = 'P';
    img[0x41] = 'E';
    std.mem.writeInt(u16, img[0x40 + 24 ..][0..2], 0x20b, .little);
    std.mem.writeInt(u32, img[0x40 + 24 + 56 ..][0..4], img.len, .little);
    const rsrc_rva: u32 = 0x180;
    std.mem.writeInt(u32, img[0x40 + 24 + 112 + 16 ..][0..4], rsrc_rva, .little);
    std.mem.writeInt(u32, img[0x40 + 24 + 112 + 20 ..][0..4], 0x100, .little);
    // Level 1 (type): 1 ID entry -> type 6 (RT_STRING) -> subdir at offset 0x20
    std.mem.writeInt(u16, img[rsrc_rva + 14 ..][0..2], 1, .little);
    std.mem.writeInt(u32, img[rsrc_rva + 16 ..][0..4], 6, .little);
    std.mem.writeInt(u32, img[rsrc_rva + 20 ..][0..4], 0x80000020, .little);
    // Level 2 (name): 1 ID entry -> id 1 -> subdir at offset 0x40
    std.mem.writeInt(u16, img[rsrc_rva + 0x20 + 14 ..][0..2], 1, .little);
    std.mem.writeInt(u32, img[rsrc_rva + 0x20 + 16 ..][0..4], 1, .little);
    std.mem.writeInt(u32, img[rsrc_rva + 0x20 + 20 ..][0..4], 0x80000040, .little);
    // Level 3 (lang): 1 ID entry -> lang 0x0409 -> data entry at offset 0x60
    std.mem.writeInt(u16, img[rsrc_rva + 0x40 + 14 ..][0..2], 1, .little);
    std.mem.writeInt(u32, img[rsrc_rva + 0x40 + 16 ..][0..4], 0x0409, .little);
    std.mem.writeInt(u32, img[rsrc_rva + 0x40 + 20 ..][0..4], 0x60, .little);
    // IMAGE_RESOURCE_DATA_ENTRY at offset 0x60: RVA=0x300, Size=4
    std.mem.writeInt(u32, img[rsrc_rva + 0x60 ..][0..4], 0x300, .little);
    std.mem.writeInt(u32, img[rsrc_rva + 0x60 + 4 ..][0..4], 4, .little);
    @memcpy(img[0x300..0x304], "WINS");

    const hit = findResourceBytes(@intFromPtr(&img), @ptrFromInt(1), @ptrFromInt(6));
    try std.testing.expect(hit != null);
    try std.testing.expectEqualStrings("WINS", hit.?);

    const miss = findResourceBytes(@intFromPtr(&img), @ptrFromInt(99), @ptrFromInt(6));
    try std.testing.expect(miss == null);
}

test "CreateDirectoryW reports ERROR_ALREADY_EXISTS and RemoveDirectoryW really removes" {
    var last: u32 = 0;
    const Hook = struct {
        var slot: *u32 = undefined;
        fn set(code: u32) callconv(W) void {
            slot.* = code;
        }
    };
    Hook.slot = &last;
    const saved = last_error_hook;
    last_error_hook = &Hook.set;
    defer last_error_hook = saved;
    var name_buf: [64]u8 = undefined;
    const name = try std.fmt.bufPrintZ(&name_buf, "/tmp/wins-k32-dirtest-{d}", .{linux.getpid()});
    var w: [64]u16 = undefined;
    for (name, 0..) |ch, i| w[i] = ch;
    w[name.len] = 0;
    const wp: [*:0]const u16 = @ptrCast(&w);
    try std.testing.expectEqual(@as(u32, 1), CreateDirectoryW(wp, null));
    try std.testing.expectEqual(@as(u32, 0), CreateDirectoryW(wp, null));
    try std.testing.expectEqual(@as(u32, 183), last);
    try std.testing.expectEqual(@as(i32, 1), RemoveDirectoryW(@ptrCast(wp)));
    try std.testing.expectEqual(@as(i32, 0), RemoveDirectoryW(@ptrCast(wp)));
    try std.testing.expectEqual(@as(u32, 3), last);
}
