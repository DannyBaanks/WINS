//! UCRT pieces (api-ms-win-crt-*) that MSVC-built DLLs need at load time, for
//! winload64 (x86-64, Win64 ABI). Startup/exit tables, a few math/time/utility
//! functions and the __stdio_common_* printf entry points (on winrun's formatter).
const std = @import("std");
const linux = std.os.linux;
const W: std.builtin.CallingConvention = .{ .x86_64_win = .{} };
const msvcrt = @import("winrun_msvcrt.zig");

// ------------------------------------------------------------- onexit tables
/// _onexit_table_t { first, last, end } of function pointers.
const OnExit = extern struct { first: ?[*]usize, last: ?[*]usize, end: ?[*]usize };
const Fn0 = *const fn () callconv(W) void;

fn _initialize_onexit_table(t: ?*OnExit) callconv(W) i32 {
    const tbl = t orelse return -1;
    tbl.* = .{ .first = null, .last = null, .end = null };
    return 0;
}
fn _register_onexit_function(t: ?*OnExit, f: ?Fn0) callconv(W) i32 {
    const tbl = t orelse return -1;
    const func = f orelse return -1;
    const used = if (tbl.first) |b| (@intFromPtr(tbl.last.?) - @intFromPtr(b)) / 8 else 0;
    const cap = if (tbl.first) |b| (@intFromPtr(tbl.end.?) - @intFromPtr(b)) / 8 else 0;
    if (used == cap) {
        const ncap = @max(cap * 2, 32);
        const mem = std.heap.page_allocator.alloc(usize, ncap) catch return -1;
        if (tbl.first) |b| {
            @memcpy(mem[0..used], b[0..used]);
            std.heap.page_allocator.free(b[0..cap]);
        }
        tbl.first = mem.ptr;
        tbl.end = mem.ptr + ncap;
    }
    tbl.first.?[used] = @intFromPtr(func);
    tbl.last = tbl.first.? + used + 1;
    return 0;
}
fn _execute_onexit_table(t: ?*OnExit) callconv(W) i32 {
    const tbl = t orelse return -1;
    const b = tbl.first orelse return 0;
    var n = (@intFromPtr(tbl.last.?) - @intFromPtr(b)) / 8;
    tbl.* = .{ .first = null, .last = null, .end = null };
    while (n > 0) { // reverse registration order
        n -= 1;
        if (b[n] != 0) (@as(Fn0, @ptrFromInt(b[n])))();
    }
    return 0;
}
var process_atexit: OnExit = .{ .first = null, .last = null, .end = null };
fn _crt_atexit(f: ?Fn0) callconv(W) i32 {
    return _register_onexit_function(&process_atexit, f);
}
const FnInt = *const fn () callconv(W) i32;
fn _initterm_e(begin: [*]const usize, end: [*]const usize) callconv(W) i32 {
    var p = begin;
    while (@intFromPtr(p) < @intFromPtr(end)) : (p += 1) {
        if (p[0] != 0) {
            const rc = (@as(FnInt, @ptrFromInt(p[0])))();
            if (rc != 0) return rc;
        }
    }
    return 0;
}
fn _seh_filter_dll(code: u32, info: ?*anyopaque) callconv(W) i32 {
    _ = code;
    _ = info;
    return 0; // EXCEPTION_CONTINUE_SEARCH
}
fn _configure_narrow_argv(mode: i32) callconv(W) i32 {
    _ = mode;
    return 0;
}
fn _initialize_narrow_environment() callconv(W) i32 {
    return 0;
}

// --------------------------------------------------------- diagnostics/abort
fn raise(sig: i32) callconv(W) i32 {
    std.debug.print("winload64: CRT raise({d})\n", .{sig});
    if (sig == 22 or sig == 6) std.process.exit(3); // SIGABRT (Windows 22): abort() exits with 3
    return 0;
}
fn _wassert(msg: [*:0]const u16, file: [*:0]const u16, line: u32) callconv(W) noreturn {
    var a: [256]u8 = undefined;
    var b: [256]u8 = undefined;
    std.debug.print("winload64: assertion failed: {s} ({s}:{d})\n", .{ narrow(&a, msg), narrow(&b, file), line });
    std.process.exit(3);
}
fn narrow(buf: []u8, w: [*:0]const u16) []const u8 {
    var n: usize = 0;
    while (w[n] != 0 and n < buf.len) : (n += 1) buf[n] = if (w[n] < 0x80) @intCast(w[n]) else '?';
    return buf[0..n];
}
fn strerror_s(buf: ?[*]u8, size: usize, errnum: i32) callconv(W) i32 {
    const b = buf orelse return 22;
    if (size == 0) return 22;
    var tmp: [64]u8 = undefined;
    const msg = std.fmt.bufPrint(&tmp, "Unknown error {d}", .{errnum}) catch "Unknown error";
    const n = @min(msg.len, size - 1);
    @memcpy(b[0..n], msg[0..n]);
    b[n] = 0;
    return 0;
}

// --------------------------------------------------------------------- math
fn ceil(x: f64) callconv(W) f64 { return @ceil(x); }
fn ceilf(x: f32) callconv(W) f32 { return @ceil(x); }
fn floor(x: f64) callconv(W) f64 { return @floor(x); }
fn floorf(x: f32) callconv(W) f32 { return @floor(x); }
fn round(x: f64) callconv(W) f64 { return @round(x); }
fn roundf(x: f32) callconv(W) f32 { return @round(x); }
fn truncf(x: f32) callconv(W) f32 { return @trunc(x); }
fn cosf(x: f32) callconv(W) f32 { return @cos(x); }
fn sinf(x: f32) callconv(W) f32 { return @sin(x); }
fn exp(x: f64) callconv(W) f64 { return @exp(x); }
fn log(x: f64) callconv(W) f64 { return @log(x); }
fn logf(x: f32) callconv(W) f32 { return @log(x); }
fn pow(x: f64, y: f64) callconv(W) f64 { return std.math.pow(f64, x, y); }
fn fmod(x: f64, y: f64) callconv(W) f64 { return @rem(x, y); }
fn _rotl64(v: u64, s: i32) callconv(W) u64 { return std.math.rotl(u64, v, @as(u32, @bitCast(s)) & 63); }

// --------------------------------------------------------------------- time
/// struct tm (9 ints). No time-zone database in the cleanroom: local time = UTC.
const Tm = extern struct { sec: i32, min: i32, hour: i32, mday: i32, mon: i32, year: i32, wday: i32, yday: i32, isdst: i32 };
fn _gmtime64_s(out: ?*Tm, t: ?*const i64) callconv(W) i32 {
    const o = out orelse return 22;
    const secs = (t orelse return 22).*;
    if (secs < 0) return 22;
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(secs) };
    const day = es.getEpochDay();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    o.* = .{ .sec = ds.getSecondsIntoMinute(), .min = ds.getMinutesIntoHour(), .hour = ds.getHoursIntoDay(), .mday = md.day_index + 1, .mon = @intFromEnum(md.month) - 1, .year = @as(i32, yd.year) - 1900, .wday = @intCast(@mod(@as(i64, day.day) + 4, 7)), .yday = yd.day, .isdst = 0 };
    return 0;
}
fn _localtime64_s(out: ?*Tm, t: ?*const i64) callconv(W) i32 {
    return _gmtime64_s(out, t);
}

// -------------------------------------------------------------------- stdio
// options bit 1 = _CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR (return the would-be length).
fn __stdio_common_vsprintf(options: u64, buf: ?[*]u8, count: usize, fmt: ?[*:0]const u8, locale: ?*anyopaque, args: ?[*]const usize) callconv(W) i32 {
    _ = locale;
    const n = msvcrt.vsnprintf_impl(buf, count, fmt, args);
    if (buf == null or options & 2 != 0) return n;
    if (n >= 0 and @as(usize, @intCast(n)) >= count) return -1; // truncated (legacy _vsnprintf)
    return n;
}
fn __stdio_common_vfprintf(options: u64, stream: ?*anyopaque, fmt: ?[*:0]const u8, locale: ?*anyopaque, args: ?[*]const usize) callconv(W) i32 {
    _ = options;
    _ = locale;
    _ = stream; // no FILE model here: diagnostics go to stderr
    var tmp: [4096]u8 = undefined;
    const n = msvcrt.vsnprintf_impl(&tmp, tmp.len, fmt, args);
    if (n > 0) _ = linux.write(2, &tmp, @min(@as(usize, @intCast(n)), tmp.len - 1));
    return n;
}

pub fn lookup(sym: []const u8) ?usize {
    const table = .{
        .{ "_initialize_onexit_table", &_initialize_onexit_table }, .{ "_register_onexit_function", &_register_onexit_function },
        .{ "_execute_onexit_table", &_execute_onexit_table },       .{ "_crt_atexit", &_crt_atexit },
        .{ "_initterm_e", &_initterm_e },                           .{ "_seh_filter_dll", &_seh_filter_dll },
        .{ "_configure_narrow_argv", &_configure_narrow_argv },     .{ "_initialize_narrow_environment", &_initialize_narrow_environment },
        .{ "raise", &raise },                                       .{ "_wassert", &_wassert },
        .{ "strerror_s", &strerror_s },                             .{ "ceil", &ceil },
        .{ "ceilf", &ceilf },                                       .{ "floor", &floor },
        .{ "floorf", &floorf },                                     .{ "round", &round },
        .{ "roundf", &roundf },                                     .{ "truncf", &truncf },
        .{ "cosf", &cosf },                                         .{ "sinf", &sinf },
        .{ "exp", &exp },                                           .{ "log", &log },
        .{ "logf", &logf },                                         .{ "pow", &pow },
        .{ "fmod", &fmod },                                         .{ "_rotl64", &_rotl64 },
        .{ "_gmtime64_s", &_gmtime64_s },                           .{ "_localtime64_s", &_localtime64_s },
        .{ "__stdio_common_vsprintf", &__stdio_common_vsprintf },   .{ "__stdio_common_vfprintf", &__stdio_common_vfprintf },
    };
    inline for (table) |e| if (std.mem.eql(u8, sym, e[0])) return @intFromPtr(e[1]);
    return null;
}
