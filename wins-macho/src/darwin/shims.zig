const std = @import("std");
const trace = @import("../runtime/trace.zig");
const fs_shim = @import("filesystem.zig");
const objc_shim = @import("objc.zig");
const foundation = @import("foundation.zig");
const swift_shim = @import("swift.zig");
const dispatch_shim = @import("dispatch.zig");

pub const ShimStatus = enum {
    NATIVE_MAPPING,
    THIN_SHIM,
    REIMPLEMENTED,
    STUB_FOR_PROBE_ONLY,
    APPLE_REQUIRED,
    UNKNOWN,
};

pub const ShimEntry = struct {
    darwin_symbol: []const u8,
    linux_equiv: []const u8,
    status: ShimStatus,
    address: usize,
};

// External Linux glibc symbols (System V AMD64 ABI)
extern "c" fn write(fd: c_int, buf: ?*const anyopaque, count: usize) isize;
extern "c" fn read(fd: c_int, buf: ?*anyopaque, count: usize) isize;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn malloc(size: usize) ?*anyopaque;
extern "c" fn calloc(nmemb: usize, size: usize) ?*anyopaque;
extern "c" fn realloc(ptr: ?*anyopaque, size: usize) ?*anyopaque;
extern "c" fn free(ptr: ?*anyopaque) void;
extern "c" fn getenv(name: [*:0]const u8) ?[*:0]u8;
extern "c" fn puts(s: [*:0]const u8) c_int;
extern "c" fn putchar(c: c_int) c_int;
extern "c" fn ceil(x: f64) f64;
extern "c" fn posix_memalign(memptr: *?*anyopaque, alignment: usize, size: usize) c_int;
extern "c" fn printf(fmt: [*:0]const u8, ...) c_int;
extern "c" fn fprintf(stream: *anyopaque, fmt: [*:0]const u8, ...) c_int;
extern "c" fn snprintf(str: [*]u8, size: usize, fmt: [*:0]const u8, ...) c_int;
extern "c" fn strlen(s: [*:0]const u8) usize;
extern "c" fn strcmp(s1: [*:0]const u8, s2: [*:0]const u8) c_int;
extern "c" fn memcpy(dst: *anyopaque, src: *const anyopaque, n: usize) *anyopaque;
extern "c" fn memmove(dst: *anyopaque, src: *const anyopaque, n: usize) *anyopaque;
extern "c" fn memcmp(s1: *const anyopaque, s2: *const anyopaque, n: usize) c_int;
extern "c" fn memset(s: *anyopaque, c: c_int, n: usize) *anyopaque;
extern "c" fn getpid() c_int;
extern "c" fn exit(status: c_int) noreturn;
extern "c" fn _exit(status: c_int) noreturn;
extern "c" fn abort() noreturn;
extern "c" fn __errno_location() *c_int;
extern "c" fn clock_gettime(clk_id: c_int, tp: *std.c.timespec) c_int;
extern "c" fn pthread_create(thread: *usize, attr: ?*const anyopaque, start_routine: *const anyopaque, arg: ?*anyopaque) c_int;
extern "c" fn pthread_join(thread: usize, retval: ?*?*anyopaque) c_int;
extern "c" fn pthread_self() usize;
extern "c" fn pthread_mutex_init(mutex: *anyopaque, attr: ?*const anyopaque) c_int;
extern "c" fn pthread_mutex_lock(mutex: *anyopaque) c_int;
extern "c" fn pthread_mutex_unlock(mutex: *anyopaque) c_int;
extern "c" fn pthread_mutex_destroy(mutex: *anyopaque) c_int;
extern "c" fn fdopen(fd: c_int, mode: [*:0]const u8) ?*anyopaque;
extern "c" fn open(path: [*:0]const u8, oflag: c_int, ...) c_int;
extern "c" fn fopen(path: [*:0]const u8, mode: [*:0]const u8) ?*anyopaque;
extern "c" fn fclose(stream: *anyopaque) c_int;
extern "c" fn fread(ptr: *anyopaque, size: usize, nmemb: usize, stream: *anyopaque) usize;
extern "c" fn fwrite(ptr: *const anyopaque, size: usize, nmemb: usize, stream: *anyopaque) usize;
extern "c" fn fflush(stream: ?*anyopaque) c_int;
extern "c" fn fseek(stream: *anyopaque, offset: c_long, whence: c_int) c_int;
extern "c" fn ftell(stream: *anyopaque) c_long;
extern "c" fn fgets(s: [*]u8, size: c_int, stream: *anyopaque) ?[*]u8;
extern "c" fn isatty(fd: c_int) c_int;
extern "c" fn access(path: [*:0]const u8, amode: c_int) c_int;
extern "c" fn getcwd(buf: [*]u8, size: usize) ?[*]u8;
extern "c" fn chdir(path: [*:0]const u8) c_int;
extern "c" fn unlink(path: [*:0]const u8) c_int;
extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;
extern "c" fn usleep(usec: u32) c_int;
extern "c" fn sleep(seconds: c_uint) c_uint;
extern "c" fn sysconf(name: c_int) c_long;
extern "c" fn atoi(nptr: [*:0]const u8) c_int;
extern "c" fn strchr(s: [*:0]const u8, c: c_int) ?[*:0]const u8;
extern "c" fn strrchr(s: [*:0]const u8, c: c_int) ?[*:0]const u8;
extern "c" fn strstr(haystack: [*:0]const u8, needle: [*:0]const u8) ?[*:0]const u8;
extern "c" fn strtok(str: ?[*:0]u8, delim: [*:0]const u8) ?[*:0]u8;
extern "c" fn strtoul(nptr: [*:0]const u8, endptr: ?*[*:0]u8, base: c_int) c_ulong;
extern "c" fn strcasecmp(s1: [*:0]const u8, s2: [*:0]const u8) c_int;
extern "c" fn strcoll(s1: [*:0]const u8, s2: [*:0]const u8) c_int;
extern "c" fn strcpy(dst: [*]u8, src: [*:0]const u8) [*]u8;
extern "c" fn strncpy(dst: [*]u8, src: [*:0]const u8, n: usize) [*]u8;
extern "c" fn strncmp(s1: [*:0]const u8, s2: [*:0]const u8, n: usize) c_int;
extern "c" fn memchr(s: *const anyopaque, c: c_int, n: usize) ?*const anyopaque;
extern "c" fn qsort(base: *anyopaque, nmemb: usize, size: usize, compar: *const anyopaque) void;
extern "c" fn fputc(c: c_int, stream: *anyopaque) c_int;
extern "c" fn fputs(s: [*:0]const u8, stream: *anyopaque) c_int;
extern "c" fn mbstowcs(pwcs: ?[*]u32, s: [*:0]const u8, n: usize) usize;
extern "c" fn time(tloc: ?*i64) i64;
extern "c" fn localtime(timep: *const i64) ?*anyopaque;
extern "c" fn strftime(s: [*]u8, max: usize, format: [*:0]const u8, tm: *const anyopaque) usize;
extern "c" fn setlocale(category: c_int, locale: ?[*:0]const u8) ?[*:0]u8;
extern "c" fn gethostname(name: [*]u8, len: usize) c_int;
extern "c" fn readlink(path: [*:0]const u8, buf: [*]u8, bufsiz: usize) isize;
extern "c" fn realpath(path: [*:0]const u8, resolved_path: ?[*]u8) ?[*]u8;
extern "c" fn nl_langinfo(item: c_int) [*:0]u8;
extern "c" fn sprintf(str: [*]u8, fmt: [*:0]const u8, ...) c_int;
extern "c" fn getpwuid(uid: u32) ?*anyopaque;
extern "c" fn getgrgid(gid: u32) ?*anyopaque;

// Data globals for Darwin ABI
var darwin_stack_chk_guard: usize = 0x595a5f4d4143484f;
var darwin_stdoutp: ?*anyopaque = null;
var darwin_stderrp: ?*anyopaque = null;
var darwin_stdinp: ?*anyopaque = null;

pub fn initGlobals() void {
    if (darwin_stdoutp == null) darwin_stdoutp = fdopen(1, "w");
    if (darwin_stderrp == null) darwin_stderrp = fdopen(2, "w");
    if (darwin_stdinp == null) darwin_stdinp = fdopen(0, "r");
}

fn record(sym: []const u8) void {
    if (trace.active_tracer) |t| {
        t.recordExternalCall(sym);
    }
}

fn shim_write(fd: c_int, buf: ?*const anyopaque, count: usize) callconv(.c) isize {
    record("_write");
    return write(fd, buf, count);
}

fn shim_read(fd: c_int, buf: ?*anyopaque, count: usize) callconv(.c) isize {
    record("_read");
    return read(fd, buf, count);
}

fn shim_close(fd: c_int) callconv(.c) c_int {
    record("_close");
    return close(fd);
}

fn shim_malloc(size: usize) callconv(.c) ?*anyopaque {
    record("_malloc");
    return malloc(size);
}

fn shim_calloc(nmemb: usize, size: usize) callconv(.c) ?*anyopaque {
    record("_calloc");
    return calloc(nmemb, size);
}

fn shim_realloc(ptr: ?*anyopaque, size: usize) callconv(.c) ?*anyopaque {
    record("_realloc");
    return realloc(ptr, size);
}

fn shim_free(ptr: ?*anyopaque) callconv(.c) void {
    record("_free");
    free(ptr);
}

fn shim_getenv(name: [*:0]const u8) callconv(.c) ?[*:0]u8 {
    record("_getenv");
    return getenv(name);
}

fn shim_puts(s: [*:0]const u8) callconv(.c) c_int {
    record("_puts");
    return puts(s);
}

fn shim_strlen(s: [*:0]const u8) callconv(.c) usize {
    record("_strlen");
    return strlen(s);
}

fn shim_strcmp(s1: [*:0]const u8, s2: [*:0]const u8) callconv(.c) c_int {
    record("_strcmp");
    return strcmp(s1, s2);
}

fn shim_getpid() callconv(.c) c_int {
    record("_getpid");
    return getpid();
}

fn shim_exit(status: c_int) callconv(.c) noreturn {
    record("_exit");
    if (trace.active_tracer) |t| {
        t.record(.EXIT, "via=_exit status={d}", .{status});
    }
    exit(status);
}

fn shim__exit(status: c_int) callconv(.c) noreturn {
    record("__exit");
    if (trace.active_tracer) |t| {
        t.record(.EXIT, "via=__exit status={d}", .{status});
    }
    _exit(status);
}

fn shim_abort() callconv(.c) noreturn {
    record("_abort");
    abort();
}

fn shim_darwin_error() callconv(.c) *c_int {
    record("___error");
    return __errno_location();
}

fn shim_stack_chk_fail() callconv(.c) noreturn {
    record("___stack_chk_fail");
    abort();
}

// Darwin CLOCK_REALTIME = 0, CLOCK_MONOTONIC = 6 (Linux = 1)
fn shim_clock_gettime(darwin_clk_id: c_int, tp: *std.c.timespec) callconv(.c) c_int {
    record("_clock_gettime");
    const linux_clk: c_int = switch (darwin_clk_id) {
        0 => 0, // CLOCK_REALTIME
        6 => 1, // Darwin CLOCK_MONOTONIC -> Linux CLOCK_MONOTONIC
        4 => 4, // CLOCK_MONOTONIC_RAW
        else => darwin_clk_id,
    };
    return clock_gettime(linux_clk, tp);
}

fn shim_pthread_create(thread: *usize, attr: ?*const anyopaque, start_routine: *const anyopaque, arg: ?*anyopaque) callconv(.c) c_int {
    record("_pthread_create");
    // Note: Darwin pthread_attr_t differs in layout from glibc; ignore non-null custom attr for minimal probe
    _ = attr;
    return pthread_create(thread, null, start_routine, arg);
}

fn shim_pthread_join(thread: usize, retval: ?*?*anyopaque) callconv(.c) c_int {
    record("_pthread_join");
    return pthread_join(thread, retval);
}

fn shim_pthread_mutex_init(mutex: *anyopaque, attr: ?*const anyopaque) callconv(.c) c_int {
    record("_pthread_mutex_init");
    _ = attr;
    return pthread_mutex_init(mutex, null);
}

fn shim_pthread_mutex_lock(mutex: *anyopaque) callconv(.c) c_int {
    record("_pthread_mutex_lock");
    // Handle Darwin static PTHREAD_MUTEX_INITIALIZER (0x32AAABA7) by zero-initializing Linux pthread_mutex_t
    const sig_ptr: *u32 = @ptrCast(@alignCast(mutex));
    if (sig_ptr.* == 0x32AAABA7) {
        @as(*[64]u8, @ptrCast(mutex)).* = .{0} ** 64;
    }
    return pthread_mutex_lock(mutex);
}

fn shim_pthread_mutex_unlock(mutex: *anyopaque) callconv(.c) c_int {
    record("_pthread_mutex_unlock");
    return pthread_mutex_unlock(mutex);
}

fn shim_pthread_mutex_destroy(mutex: *anyopaque) callconv(.c) c_int {
    record("_pthread_mutex_destroy");
    return pthread_mutex_destroy(mutex);
}

fn shim_mach_absolute_time() callconv(.c) u64 {
    record("_mach_absolute_time");
    var ts: std.c.timespec = undefined;
    _ = clock_gettime(1, &ts); // Linux CLOCK_MONOTONIC
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

const MachTimebaseInfo = extern struct {
    numer: u32,
    denom: u32,
};

fn shim_mach_timebase_info(info: *MachTimebaseInfo) callconv(.c) c_int {
    record("_mach_timebase_info");
    info.numer = 1;
    info.denom = 1;
    return 0;
}

fn shim_arc4random_buf(buf: [*]u8, nbytes: usize) callconv(.c) void {
    record("_arc4random_buf");
    _ = std.os.linux.getrandom(buf, nbytes, 0);
}

fn shim_arc4random() callconv(.c) u32 {
    record("_arc4random");
    var val: u32 = 0;
    _ = std.os.linux.getrandom(@ptrCast(&val), @sizeOf(u32), 0);
    return val;
}

fn shim_sysctlbyname(
    name: [*:0]const u8,
    oldp: ?*anyopaque,
    oldlenp: ?*usize,
    newp: ?*const anyopaque,
    newlen: usize,
) callconv(.c) c_int {
    _ = newp;
    _ = newlen;
    record("_sysctlbyname");
    const n = std.mem.span(name);
    var val64: u64 = 0;
    var is_32 = false;
    if (std.mem.eql(u8, n, "hw.ncpu") or std.mem.eql(u8, n, "hw.physicalcpu") or std.mem.eql(u8, n, "hw.logicalcpu")) {
        const cpus = sysconf(84); // _SC_NPROCESSORS_ONLN on Linux
        val64 = if (cpus > 0) @intCast(cpus) else 1;
        is_32 = true;
    } else if (std.mem.eql(u8, n, "hw.pagesize") or std.mem.eql(u8, n, "vm.pagesize")) {
        val64 = 4096;
        is_32 = true;
    } else if (std.mem.eql(u8, n, "hw.memsize")) {
        val64 = 8 * 1024 * 1024 * 1024;
    } else {
        __errno_location().* = 2; // ENOENT
        return -1;
    }

    const need: usize = if (is_32) 4 else 8;
    if (oldlenp) |lp| {
        if (oldp) |op| {
            if (lp.* < need) {
                __errno_location().* = 12; // ENOMEM
                return -1;
            }
            if (is_32) {
                @as(*u32, @ptrCast(@alignCast(op))).* = @truncate(val64);
            } else {
                @as(*u64, @ptrCast(@alignCast(op))).* = val64;
            }
        }
        lp.* = need;
    }
    return 0;
}

pub var active_executable_path: ?[]const u8 = null;

fn shim_NSGetExecutablePath(buf: [*]u8, bufsize: *u32) callconv(.c) c_int {
    record("__NSGetExecutablePath");
    const path = active_executable_path orelse "/wins-macho-target";
    const need: u32 = @intCast(path.len + 1);
    if (bufsize.* < need) {
        bufsize.* = need;
        return -1;
    }
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return 0;
}

fn shim_bzero(s: [*]u8, n: usize) callconv(.c) void {
    record("_bzero");
    _ = memset(s, 0, n);
}

fn shim_memcpy_chk(dst: *anyopaque, src: *const anyopaque, len: usize, dstlen: usize) callconv(.c) *anyopaque {
    record("___memcpy_chk");
    if (len > dstlen) abort();
    return memcpy(dst, src, len);
}

fn shim_memset_chk(dst: *anyopaque, c: c_int, len: usize, dstlen: usize) callconv(.c) *anyopaque {
    record("___memset_chk");
    if (len > dstlen) abort();
    return memset(dst, c, len);
}

fn shim_dlopen(path: ?[*:0]const u8, mode: c_int) callconv(.c) ?*anyopaque {
    _ = mode;
    record("_dlopen");
    if (path == null) return @ptrFromInt(0xDEAD0001);
    const p = std.mem.span(path.?);
    if (isDarwinSystemDylib(p)) return @ptrFromInt(0xDEAD0002);
    return null;
}

// Darwin _RuneLocale minimal ASCII table for __DefaultRuneLocale
// Layout on x86_64:
//   magic[8] + encoding[32] + sgetrune(8) + sputrune(8) + invalid_rune(4) = 60 bytes
//   __runetype[256] (u32 each) at offset 60
//   __maplower[256] (i32 each) at offset 1084
//   __mapupper[256] (i32 each) at offset 2108
const DarwinRuneLocale = extern struct {
    magic: [8]u8,
    encoding: [32]u8,
    sgetrune: usize,
    sputrune: usize,
    invalid_rune: i32,
    runetype: [256]u32,
    maplower: [256]i32,
    mapupper: [256]i32,
};

var darwin_default_rune_locale: DarwinRuneLocale = blk: {
    @setEvalBranchQuota(10000);
    var rl: DarwinRuneLocale = std.mem.zeroes(DarwinRuneLocale);
    const CT_A: u32 = 0x00000100; // alpha
    const CT_C: u32 = 0x00000200; // cntrl
    const CT_D: u32 = 0x00000400; // digit
    const CT_G: u32 = 0x00000800; // graph
    const CT_L: u32 = 0x00001000; // lower
    const CT_P: u32 = 0x00002000; // punct
    const CT_S: u32 = 0x00004000; // space
    const CT_U: u32 = 0x00008000; // upper
    const CT_X: u32 = 0x00010000; // xdigit
    const CT_B: u32 = 0x00020000; // blank
    const CT_R: u32 = 0x00040000; // print
    for (0..256) |ch| {
        rl.maplower[ch] = @intCast(ch);
        rl.mapupper[ch] = @intCast(ch);
        var rt: u32 = 0;
        if (ch < 0x20 or ch == 0x7f) rt |= CT_C;
        if (ch == ' ' or ch == '\t') rt |= CT_B | CT_S;
        if (ch >= 0x09 and ch <= 0x0d) rt |= CT_S;
        if (ch >= 0x20 and ch <= 0x7e) rt |= CT_R;
        if (ch >= 0x21 and ch <= 0x7e) rt |= CT_G;
        if (ch >= '0' and ch <= '9') rt |= CT_D | CT_X;
        if (ch >= 'A' and ch <= 'Z') {
            rt |= CT_A | CT_U;
            rl.maplower[ch] = @intCast(ch + 32);
        }
        if (ch >= 'a' and ch <= 'z') {
            rt |= CT_A | CT_L;
            rl.mapupper[ch] = @intCast(ch - 32);
        }
        if ((ch >= 'A' and ch <= 'F') or (ch >= 'a' and ch <= 'f')) rt |= CT_X;
        if (ch >= 0x21 and ch <= 0x7e and (rt & (CT_A | CT_D)) == 0) rt |= CT_P;
        rl.runetype[ch] = rt;
    }
    break :blk rl;
};

fn shim_maskrune(c: c_int, f: c_ulong) callconv(.c) c_int {
    record("___maskrune");
    if (c < 0 or c >= 256) return 0;
    return if ((darwin_default_rune_locale.runetype[@intCast(c)] & @as(u32, @truncate(f))) != 0) 1 else 0;
}

fn shim_mb_cur_max() callconv(.c) c_int {
    record("___mb_cur_max");
    return 1;
}

fn shim_tolower(c: c_int) callconv(.c) c_int {
    record("___tolower");
    if (c < 0 or c >= 256) return c;
    return darwin_default_rune_locale.maplower[@intCast(c)];
}

fn shim_chkstk_darwin() callconv(.naked) void {
    // On Linux userland with 8MB stack, return preserving rax/all registers
    asm volatile ("retq");
}

fn shim_strcpy_chk(dst: [*]u8, src: [*:0]const u8, dstlen: usize) callconv(.c) [*]u8 {
    _ = dstlen;
    record("___strcpy_chk");
    return strcpy(dst, src);
}

fn shim_nl_langinfo(item: c_int) callconv(.c) [*:0]u8 {
    record("_nl_langinfo");
    // Darwin CODESET == 0; Linux glibc _NL_CTYPE_CODESET_NAME == 14
    const linux_item: c_int = if (item == 0) 14 else item;
    return nl_langinfo(linux_item);
}

fn shim_dlsym(handle: ?*anyopaque, symbol: [*:0]const u8) callconv(.c) ?*anyopaque {
    _ = handle;
    record("_dlsym");
    const s = std.mem.span(symbol);
    // dlsym takes symbol without leading '_', whereas Mach-O shims have leading '_'
    var buf: [256]u8 = undefined;
    if (s.len + 1 < buf.len) {
        buf[0] = '_';
        @memcpy(buf[1 .. 1 + s.len], s);
        if (lookup(buf[0 .. 1 + s.len])) |sh| {
            return @ptrFromInt(sh.address);
        }
    }
    if (lookup(s)) |sh| return @ptrFromInt(sh.address);
    return null;
}

fn shim_dyld_stub_binder() callconv(.c) noreturn {
    if (trace.active_tracer) |t| {
        t.recordUnsupportedCall("dyld_stub_binder");
    }
    std.debug.print("WINS-MACHO: unexpected call to dyld_stub_binder (lazy bind was not pre-resolved)\n", .{});
    abort();
}

pub fn lookup(symbol: []const u8) ?ShimEntry {
    initGlobals();
    foundation.ensureInitialized();
    const table = [_]ShimEntry{
        .{ .darwin_symbol = "_write", .linux_equiv = "libc:write", .status = .THIN_SHIM, .address = @intFromPtr(&shim_write) },
        .{ .darwin_symbol = "_read", .linux_equiv = "libc:read", .status = .THIN_SHIM, .address = @intFromPtr(&shim_read) },
        .{ .darwin_symbol = "_close", .linux_equiv = "libc:close", .status = .THIN_SHIM, .address = @intFromPtr(&shim_close) },
        .{ .darwin_symbol = "_malloc", .linux_equiv = "libc:malloc", .status = .THIN_SHIM, .address = @intFromPtr(&shim_malloc) },
        .{ .darwin_symbol = "_calloc", .linux_equiv = "libc:calloc", .status = .THIN_SHIM, .address = @intFromPtr(&shim_calloc) },
        .{ .darwin_symbol = "_realloc", .linux_equiv = "libc:realloc", .status = .THIN_SHIM, .address = @intFromPtr(&shim_realloc) },
        .{ .darwin_symbol = "_free", .linux_equiv = "libc:free", .status = .THIN_SHIM, .address = @intFromPtr(&shim_free) },
        .{ .darwin_symbol = "_getenv", .linux_equiv = "libc:getenv", .status = .THIN_SHIM, .address = @intFromPtr(&shim_getenv) },
        .{ .darwin_symbol = "_puts", .linux_equiv = "libc:puts", .status = .THIN_SHIM, .address = @intFromPtr(&shim_puts) },
        .{ .darwin_symbol = "_printf", .linux_equiv = "libc:printf", .status = .NATIVE_MAPPING, .address = @intFromPtr(&printf) },
        .{ .darwin_symbol = "_fprintf", .linux_equiv = "libc:fprintf", .status = .NATIVE_MAPPING, .address = @intFromPtr(&fprintf) },
        .{ .darwin_symbol = "_snprintf", .linux_equiv = "libc:snprintf", .status = .NATIVE_MAPPING, .address = @intFromPtr(&snprintf) },
        .{ .darwin_symbol = "_sprintf", .linux_equiv = "libc:sprintf", .status = .NATIVE_MAPPING, .address = @intFromPtr(&sprintf) },
        .{ .darwin_symbol = "_strlen", .linux_equiv = "libc:strlen", .status = .THIN_SHIM, .address = @intFromPtr(&shim_strlen) },
        .{ .darwin_symbol = "_strcmp", .linux_equiv = "libc:strcmp", .status = .THIN_SHIM, .address = @intFromPtr(&shim_strcmp) },
        .{ .darwin_symbol = "_memcpy", .linux_equiv = "libc:memcpy", .status = .NATIVE_MAPPING, .address = @intFromPtr(&memcpy) },
        .{ .darwin_symbol = "_memmove", .linux_equiv = "libc:memmove", .status = .NATIVE_MAPPING, .address = @intFromPtr(&memmove) },
        .{ .darwin_symbol = "_memset", .linux_equiv = "libc:memset", .status = .NATIVE_MAPPING, .address = @intFromPtr(&memset) },
        .{ .darwin_symbol = "_getpid", .linux_equiv = "libc:getpid", .status = .THIN_SHIM, .address = @intFromPtr(&shim_getpid) },
        .{ .darwin_symbol = "_exit", .linux_equiv = "libc:exit", .status = .THIN_SHIM, .address = @intFromPtr(&shim_exit) },
        .{ .darwin_symbol = "__exit", .linux_equiv = "libc:_exit", .status = .THIN_SHIM, .address = @intFromPtr(&shim__exit) },
        .{ .darwin_symbol = "_abort", .linux_equiv = "libc:abort", .status = .THIN_SHIM, .address = @intFromPtr(&shim_abort) },
        .{ .darwin_symbol = "___error", .linux_equiv = "libc:__errno_location", .status = .THIN_SHIM, .address = @intFromPtr(&shim_darwin_error) },
        .{ .darwin_symbol = "___stack_chk_guard", .linux_equiv = "data:stack_chk_guard", .status = .REIMPLEMENTED, .address = @intFromPtr(&darwin_stack_chk_guard) },
        .{ .darwin_symbol = "___stack_chk_fail", .linux_equiv = "libc:abort", .status = .THIN_SHIM, .address = @intFromPtr(&shim_stack_chk_fail) },
        .{ .darwin_symbol = "___stdoutp", .linux_equiv = "data:fdopen(1)", .status = .THIN_SHIM, .address = @intFromPtr(&darwin_stdoutp) },
        .{ .darwin_symbol = "___stderrp", .linux_equiv = "data:fdopen(2)", .status = .THIN_SHIM, .address = @intFromPtr(&darwin_stderrp) },
        .{ .darwin_symbol = "___stdinp", .linux_equiv = "data:fdopen(0)", .status = .THIN_SHIM, .address = @intFromPtr(&darwin_stdinp) },
        .{ .darwin_symbol = "_clock_gettime", .linux_equiv = "libc:clock_gettime(mapped_clk_id)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_clock_gettime) },
        .{ .darwin_symbol = "_pthread_create", .linux_equiv = "libpthread:pthread_create", .status = .THIN_SHIM, .address = @intFromPtr(&shim_pthread_create) },
        .{ .darwin_symbol = "_pthread_join", .linux_equiv = "libpthread:pthread_join", .status = .THIN_SHIM, .address = @intFromPtr(&shim_pthread_join) },
        .{ .darwin_symbol = "_pthread_self", .linux_equiv = "libpthread:pthread_self", .status = .NATIVE_MAPPING, .address = @intFromPtr(&pthread_self) },
        .{ .darwin_symbol = "_pthread_mutex_init", .linux_equiv = "libpthread:pthread_mutex_init", .status = .THIN_SHIM, .address = @intFromPtr(&shim_pthread_mutex_init) },
        .{ .darwin_symbol = "_pthread_mutex_lock", .linux_equiv = "libpthread:pthread_mutex_lock", .status = .THIN_SHIM, .address = @intFromPtr(&shim_pthread_mutex_lock) },
        .{ .darwin_symbol = "_pthread_mutex_unlock", .linux_equiv = "libpthread:pthread_mutex_unlock", .status = .THIN_SHIM, .address = @intFromPtr(&shim_pthread_mutex_unlock) },
        .{ .darwin_symbol = "_pthread_mutex_destroy", .linux_equiv = "libpthread:pthread_mutex_destroy", .status = .THIN_SHIM, .address = @intFromPtr(&shim_pthread_mutex_destroy) },
        .{ .darwin_symbol = "_mach_absolute_time", .linux_equiv = "libc:clock_gettime(CLOCK_MONOTONIC)", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_mach_absolute_time) },
        .{ .darwin_symbol = "_mach_timebase_info", .linux_equiv = "reimplemented:1/1_ns", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_mach_timebase_info) },
        .{ .darwin_symbol = "_stat", .linux_equiv = "linux:stat->DarwinStat64", .status = .REIMPLEMENTED, .address = @intFromPtr(&fs_shim.shim_stat) },
        .{ .darwin_symbol = "_stat$INODE64", .linux_equiv = "linux:stat->DarwinStat64", .status = .REIMPLEMENTED, .address = @intFromPtr(&fs_shim.shim_stat) },
        .{ .darwin_symbol = "_lstat", .linux_equiv = "linux:lstat->DarwinStat64", .status = .REIMPLEMENTED, .address = @intFromPtr(&fs_shim.shim_lstat) },
        .{ .darwin_symbol = "_lstat$INODE64", .linux_equiv = "linux:lstat->DarwinStat64", .status = .REIMPLEMENTED, .address = @intFromPtr(&fs_shim.shim_lstat) },
        .{ .darwin_symbol = "_fstat", .linux_equiv = "linux:fstat->DarwinStat64", .status = .REIMPLEMENTED, .address = @intFromPtr(&fs_shim.shim_fstat) },
        .{ .darwin_symbol = "_fstat$INODE64", .linux_equiv = "linux:fstat->DarwinStat64", .status = .REIMPLEMENTED, .address = @intFromPtr(&fs_shim.shim_fstat) },
        .{ .darwin_symbol = "_open", .linux_equiv = "libc:open", .status = .NATIVE_MAPPING, .address = @intFromPtr(&open) },
        .{ .darwin_symbol = "_fopen", .linux_equiv = "libc:fopen", .status = .NATIVE_MAPPING, .address = @intFromPtr(&fopen) },
        .{ .darwin_symbol = "_fclose", .linux_equiv = "libc:fclose", .status = .NATIVE_MAPPING, .address = @intFromPtr(&fclose) },
        .{ .darwin_symbol = "_fread", .linux_equiv = "libc:fread", .status = .NATIVE_MAPPING, .address = @intFromPtr(&fread) },
        .{ .darwin_symbol = "_fwrite", .linux_equiv = "libc:fwrite", .status = .NATIVE_MAPPING, .address = @intFromPtr(&fwrite) },
        .{ .darwin_symbol = "_fflush", .linux_equiv = "libc:fflush", .status = .NATIVE_MAPPING, .address = @intFromPtr(&fflush) },
        .{ .darwin_symbol = "_fseek", .linux_equiv = "libc:fseek", .status = .NATIVE_MAPPING, .address = @intFromPtr(&fseek) },
        .{ .darwin_symbol = "_ftell", .linux_equiv = "libc:ftell", .status = .NATIVE_MAPPING, .address = @intFromPtr(&ftell) },
        .{ .darwin_symbol = "_fgets", .linux_equiv = "libc:fgets", .status = .NATIVE_MAPPING, .address = @intFromPtr(&fgets) },
        .{ .darwin_symbol = "_isatty", .linux_equiv = "libc:isatty", .status = .NATIVE_MAPPING, .address = @intFromPtr(&isatty) },
        .{ .darwin_symbol = "_access", .linux_equiv = "libc:access", .status = .NATIVE_MAPPING, .address = @intFromPtr(&access) },
        .{ .darwin_symbol = "_getcwd", .linux_equiv = "libc:getcwd", .status = .NATIVE_MAPPING, .address = @intFromPtr(&getcwd) },
        .{ .darwin_symbol = "_chdir", .linux_equiv = "libc:chdir", .status = .NATIVE_MAPPING, .address = @intFromPtr(&chdir) },
        .{ .darwin_symbol = "_unlink", .linux_equiv = "libc:unlink", .status = .NATIVE_MAPPING, .address = @intFromPtr(&unlink) },
        .{ .darwin_symbol = "_setenv", .linux_equiv = "libc:setenv", .status = .NATIVE_MAPPING, .address = @intFromPtr(&setenv) },
        .{ .darwin_symbol = "_unsetenv", .linux_equiv = "libc:unsetenv", .status = .NATIVE_MAPPING, .address = @intFromPtr(&unsetenv) },
        .{ .darwin_symbol = "_usleep", .linux_equiv = "libc:usleep", .status = .NATIVE_MAPPING, .address = @intFromPtr(&usleep) },
        .{ .darwin_symbol = "_sleep", .linux_equiv = "libc:sleep", .status = .NATIVE_MAPPING, .address = @intFromPtr(&sleep) },
        .{ .darwin_symbol = "_arc4random", .linux_equiv = "linux:getrandom", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_arc4random) },
        .{ .darwin_symbol = "_arc4random_buf", .linux_equiv = "linux:getrandom", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_arc4random_buf) },
        .{ .darwin_symbol = "_sysctlbyname", .linux_equiv = "reimplemented:hw.ncpu/pagesize/memsize", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_sysctlbyname) },
        .{ .darwin_symbol = "__NSGetExecutablePath", .linux_equiv = "runtime:target_path", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_NSGetExecutablePath) },
        .{ .darwin_symbol = "_bzero", .linux_equiv = "libc:memset(0)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_bzero) },
        .{ .darwin_symbol = "___bzero", .linux_equiv = "libc:memset(0)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_bzero) },
        .{ .darwin_symbol = "___memcpy_chk", .linux_equiv = "libc:memcpy+bounds", .status = .THIN_SHIM, .address = @intFromPtr(&shim_memcpy_chk) },
        .{ .darwin_symbol = "___memset_chk", .linux_equiv = "libc:memset+bounds", .status = .THIN_SHIM, .address = @intFromPtr(&shim_memset_chk) },
        .{ .darwin_symbol = "___strcpy_chk", .linux_equiv = "libc:strcpy", .status = .THIN_SHIM, .address = @intFromPtr(&shim_strcpy_chk) },
        .{ .darwin_symbol = "___sprintf_chk", .linux_equiv = "libc:sprintf", .status = .NATIVE_MAPPING, .address = @intFromPtr(&sprintf) },
        .{ .darwin_symbol = "__DefaultRuneLocale", .linux_equiv = "reimplemented:DarwinRuneLocale", .status = .REIMPLEMENTED, .address = @intFromPtr(&darwin_default_rune_locale) },
        .{ .darwin_symbol = "___maskrune", .linux_equiv = "reimplemented:maskrune", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_maskrune) },
        .{ .darwin_symbol = "___mb_cur_max", .linux_equiv = "reimplemented:1", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_mb_cur_max) },
        .{ .darwin_symbol = "___tolower", .linux_equiv = "reimplemented:tolower", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_tolower) },
        .{ .darwin_symbol = "____chkstk_darwin", .linux_equiv = "reimplemented:chkstk_nop", .status = .THIN_SHIM, .address = @intFromPtr(&shim_chkstk_darwin) },
        .{ .darwin_symbol = "_opendir$INODE64", .linux_equiv = "libc:opendir", .status = .THIN_SHIM, .address = @intFromPtr(&fs_shim.shim_opendir) },
        .{ .darwin_symbol = "_readdir$INODE64", .linux_equiv = "libc:readdir->DarwinDirent64", .status = .REIMPLEMENTED, .address = @intFromPtr(&fs_shim.shim_readdir) },
        .{ .darwin_symbol = "_closedir", .linux_equiv = "libc:closedir", .status = .THIN_SHIM, .address = @intFromPtr(&fs_shim.shim_closedir) },
        .{ .darwin_symbol = "_nl_langinfo", .linux_equiv = "libc:nl_langinfo(CODESET 0->14)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_nl_langinfo) },
        .{ .darwin_symbol = "_atoi", .linux_equiv = "libc:atoi", .status = .NATIVE_MAPPING, .address = @intFromPtr(&atoi) },
        .{ .darwin_symbol = "_strchr", .linux_equiv = "libc:strchr", .status = .NATIVE_MAPPING, .address = @intFromPtr(&strchr) },
        .{ .darwin_symbol = "_strrchr", .linux_equiv = "libc:strrchr", .status = .NATIVE_MAPPING, .address = @intFromPtr(&strrchr) },
        .{ .darwin_symbol = "_strstr", .linux_equiv = "libc:strstr", .status = .NATIVE_MAPPING, .address = @intFromPtr(&strstr) },
        .{ .darwin_symbol = "_strtok", .linux_equiv = "libc:strtok", .status = .NATIVE_MAPPING, .address = @intFromPtr(&strtok) },
        .{ .darwin_symbol = "_strtoul", .linux_equiv = "libc:strtoul", .status = .NATIVE_MAPPING, .address = @intFromPtr(&strtoul) },
        .{ .darwin_symbol = "_strcasecmp", .linux_equiv = "libc:strcasecmp", .status = .NATIVE_MAPPING, .address = @intFromPtr(&strcasecmp) },
        .{ .darwin_symbol = "_strcoll", .linux_equiv = "libc:strcoll", .status = .NATIVE_MAPPING, .address = @intFromPtr(&strcoll) },
        .{ .darwin_symbol = "_strcpy", .linux_equiv = "libc:strcpy", .status = .NATIVE_MAPPING, .address = @intFromPtr(&strcpy) },
        .{ .darwin_symbol = "_strncpy", .linux_equiv = "libc:strncpy", .status = .NATIVE_MAPPING, .address = @intFromPtr(&strncpy) },
        .{ .darwin_symbol = "_strncmp", .linux_equiv = "libc:strncmp", .status = .NATIVE_MAPPING, .address = @intFromPtr(&strncmp) },
        .{ .darwin_symbol = "_memchr", .linux_equiv = "libc:memchr", .status = .NATIVE_MAPPING, .address = @intFromPtr(&memchr) },
        .{ .darwin_symbol = "_memcmp", .linux_equiv = "libc:memcmp", .status = .NATIVE_MAPPING, .address = @intFromPtr(&memcmp) },
        .{ .darwin_symbol = "_qsort", .linux_equiv = "libc:qsort", .status = .NATIVE_MAPPING, .address = @intFromPtr(&qsort) },
        .{ .darwin_symbol = "_fputc", .linux_equiv = "libc:fputc", .status = .NATIVE_MAPPING, .address = @intFromPtr(&fputc) },
        .{ .darwin_symbol = "_putchar", .linux_equiv = "libc:putchar", .status = .NATIVE_MAPPING, .address = @intFromPtr(&putchar) },
        .{ .darwin_symbol = "_ceil", .linux_equiv = "libm:ceil", .status = .NATIVE_MAPPING, .address = @intFromPtr(&ceil) },
        .{ .darwin_symbol = "_posix_memalign", .linux_equiv = "libc:posix_memalign", .status = .NATIVE_MAPPING, .address = @intFromPtr(&posix_memalign) },
        .{ .darwin_symbol = "_fputs", .linux_equiv = "libc:fputs", .status = .NATIVE_MAPPING, .address = @intFromPtr(&fputs) },
        .{ .darwin_symbol = "_putc", .linux_equiv = "libc:fputc", .status = .NATIVE_MAPPING, .address = @intFromPtr(&fputc) },
        .{ .darwin_symbol = "_mbstowcs", .linux_equiv = "libc:mbstowcs", .status = .NATIVE_MAPPING, .address = @intFromPtr(&mbstowcs) },
        .{ .darwin_symbol = "_time", .linux_equiv = "libc:time", .status = .NATIVE_MAPPING, .address = @intFromPtr(&time) },
        .{ .darwin_symbol = "_localtime", .linux_equiv = "libc:localtime", .status = .NATIVE_MAPPING, .address = @intFromPtr(&localtime) },
        .{ .darwin_symbol = "_strftime", .linux_equiv = "libc:strftime", .status = .NATIVE_MAPPING, .address = @intFromPtr(&strftime) },
        .{ .darwin_symbol = "_setlocale", .linux_equiv = "libc:setlocale", .status = .NATIVE_MAPPING, .address = @intFromPtr(&setlocale) },
        .{ .darwin_symbol = "_gethostname", .linux_equiv = "libc:gethostname", .status = .NATIVE_MAPPING, .address = @intFromPtr(&gethostname) },
        .{ .darwin_symbol = "_readlink", .linux_equiv = "libc:readlink", .status = .NATIVE_MAPPING, .address = @intFromPtr(&readlink) },
        .{ .darwin_symbol = "_realpath$DARWIN_EXTSN", .linux_equiv = "libc:realpath", .status = .NATIVE_MAPPING, .address = @intFromPtr(&realpath) },
        .{ .darwin_symbol = "_getpwuid", .linux_equiv = "libc:getpwuid", .status = .NATIVE_MAPPING, .address = @intFromPtr(&getpwuid) },
        .{ .darwin_symbol = "_getgrgid", .linux_equiv = "libc:getgrgid", .status = .NATIVE_MAPPING, .address = @intFromPtr(&getgrgid) },
        .{ .darwin_symbol = "_dlopen", .linux_equiv = "dyld:shim_dlopen", .status = .THIN_SHIM, .address = @intFromPtr(&shim_dlopen) },
        .{ .darwin_symbol = "_dlsym", .linux_equiv = "dyld:shim_dlsym", .status = .THIN_SHIM, .address = @intFromPtr(&shim_dlsym) },
        .{ .darwin_symbol = "_objc_msgSend", .linux_equiv = "reimplemented:libobjc_msgSend_x86_64", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_objc_msgSend) },
        .{ .darwin_symbol = "_objc_msgSendSuper", .linux_equiv = "reimplemented:libobjc_msgSendSuper_x86_64", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_objc_msgSendSuper) },
        .{ .darwin_symbol = "_objc_msgSendSuper2", .linux_equiv = "reimplemented:libobjc_msgSendSuper2_x86_64", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_objc_msgSendSuper2) },
        .{ .darwin_symbol = "__objc_empty_cache", .linux_equiv = "data:objc_empty_cache", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.objc_empty_cache) },
        .{ .darwin_symbol = "_objc_alloc", .linux_equiv = "reimplemented:objc_alloc", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_objc_alloc) },
        .{ .darwin_symbol = "_objc_alloc_init", .linux_equiv = "reimplemented:objc_alloc_init", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_objc_alloc_init) },
        .{ .darwin_symbol = "_objc_retain", .linux_equiv = "reimplemented:objc_retain", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_objc_retain) },
        .{ .darwin_symbol = "_objc_release", .linux_equiv = "reimplemented:objc_release", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_objc_release) },
        .{ .darwin_symbol = "_objc_autorelease", .linux_equiv = "reimplemented:objc_autorelease", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_objc_autorelease) },
        .{ .darwin_symbol = "_objc_retainAutorelease", .linux_equiv = "reimplemented:objc_retainAutorelease", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_objc_retainAutorelease) },
        .{ .darwin_symbol = "_objc_retainAutoreleasedReturnValue", .linux_equiv = "reimplemented:objc_retainAutoreleasedReturnValue", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_objc_retainAutoreleasedReturnValue) },
        .{ .darwin_symbol = "_objc_autoreleaseReturnValue", .linux_equiv = "reimplemented:objc_autoreleaseReturnValue", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_objc_autoreleaseReturnValue) },
        .{ .darwin_symbol = "_objc_autoreleasePoolPush", .linux_equiv = "reimplemented:objc_autoreleasePoolPush", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_objc_autoreleasePoolPush) },
        .{ .darwin_symbol = "_objc_autoreleasePoolPop", .linux_equiv = "reimplemented:objc_autoreleasePoolPop", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_objc_autoreleasePoolPop) },
        .{ .darwin_symbol = "_objc_opt_class", .linux_equiv = "reimplemented:objc_opt_class", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_objc_opt_class) },
        .{ .darwin_symbol = "_objc_opt_isKindOfClass", .linux_equiv = "reimplemented:objc_opt_isKindOfClass", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_objc_opt_isKindOfClass) },
        .{ .darwin_symbol = "_objc_opt_respondsToSelector", .linux_equiv = "reimplemented:objc_opt_respondsToSelector", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_objc_opt_respondsToSelector) },
        .{ .darwin_symbol = "_objc_storeStrong", .linux_equiv = "reimplemented:objc_storeStrong", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_objc_storeStrong) },
        .{ .darwin_symbol = "_objc_getClass", .linux_equiv = "reimplemented:objc_getClass", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_objc_getClass) },
        .{ .darwin_symbol = "_sel_registerName", .linux_equiv = "reimplemented:sel_registerName", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_sel_registerName) },
        .{ .darwin_symbol = "_class_createInstance", .linux_equiv = "reimplemented:class_createInstance", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_class_createInstance) },
        .{ .darwin_symbol = "_object_getClass", .linux_equiv = "reimplemented:object_getClass", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_object_getClass) },
        .{ .darwin_symbol = "_objc_enumerationMutation", .linux_equiv = "reimplemented:objc_enumerationMutation", .status = .REIMPLEMENTED, .address = @intFromPtr(&objc_shim.shim_objc_enumerationMutation) },
        .{ .darwin_symbol = "___CFConstantStringClassReference", .linux_equiv = "foundation:CFConstantStringClass", .status = .REIMPLEMENTED, .address = @intFromPtr(&foundation.OBJC_CLASS_NSConstantString) },
        .{ .darwin_symbol = "_OBJC_CLASS_$_NSObject", .linux_equiv = "foundation:NSObject", .status = .REIMPLEMENTED, .address = @intFromPtr(&foundation.OBJC_CLASS_NSObject) },
        .{ .darwin_symbol = "_OBJC_METACLASS_$_NSObject", .linux_equiv = "foundation:NSObject_meta", .status = .REIMPLEMENTED, .address = @intFromPtr(&foundation.OBJC_METACLASS_NSObject) },
        .{ .darwin_symbol = "_OBJC_CLASS_$_NSString", .linux_equiv = "foundation:NSString", .status = .REIMPLEMENTED, .address = @intFromPtr(&foundation.OBJC_CLASS_NSString) },
        .{ .darwin_symbol = "_OBJC_METACLASS_$_NSString", .linux_equiv = "foundation:NSString_meta", .status = .REIMPLEMENTED, .address = @intFromPtr(&foundation.OBJC_METACLASS_NSString) },
        .{ .darwin_symbol = "_OBJC_CLASS_$_NSData", .linux_equiv = "foundation:NSData", .status = .REIMPLEMENTED, .address = @intFromPtr(&foundation.OBJC_CLASS_NSData) },
        .{ .darwin_symbol = "_OBJC_METACLASS_$_NSData", .linux_equiv = "foundation:NSData_meta", .status = .REIMPLEMENTED, .address = @intFromPtr(&foundation.OBJC_METACLASS_NSData) },
        .{ .darwin_symbol = "_OBJC_CLASS_$_NSArray", .linux_equiv = "foundation:NSArray", .status = .REIMPLEMENTED, .address = @intFromPtr(&foundation.OBJC_CLASS_NSArray) },
        .{ .darwin_symbol = "_OBJC_METACLASS_$_NSArray", .linux_equiv = "foundation:NSArray_meta", .status = .REIMPLEMENTED, .address = @intFromPtr(&foundation.OBJC_METACLASS_NSArray) },
        .{ .darwin_symbol = "_OBJC_CLASS_$_NSMutableArray", .linux_equiv = "foundation:NSMutableArray", .status = .REIMPLEMENTED, .address = @intFromPtr(&foundation.OBJC_CLASS_NSMutableArray) },
        .{ .darwin_symbol = "_OBJC_METACLASS_$_NSMutableArray", .linux_equiv = "foundation:NSMutableArray_meta", .status = .REIMPLEMENTED, .address = @intFromPtr(&foundation.OBJC_METACLASS_NSMutableArray) },
        .{ .darwin_symbol = "_OBJC_CLASS_$_NSAutoreleasePool", .linux_equiv = "foundation:NSAutoreleasePool", .status = .REIMPLEMENTED, .address = @intFromPtr(&foundation.OBJC_CLASS_NSAutoreleasePool) },
        .{ .darwin_symbol = "_OBJC_METACLASS_$_NSAutoreleasePool", .linux_equiv = "foundation:NSAutoreleasePool_meta", .status = .REIMPLEMENTED, .address = @intFromPtr(&foundation.OBJC_METACLASS_NSAutoreleasePool) },
        .{ .darwin_symbol = "_NSLog", .linux_equiv = "foundation:NSLog", .status = .REIMPLEMENTED, .address = @intFromPtr(&foundation.shim_NSLog) },
        .{ .darwin_symbol = "_swift_allocObject", .linux_equiv = "swift:swift_allocObject", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_allocObject) },
        .{ .darwin_symbol = "_swift_retain", .linux_equiv = "swift:swift_retain", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_retain) },
        .{ .darwin_symbol = "_swift_release", .linux_equiv = "swift:swift_release", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_release) },
        .{ .darwin_symbol = "_swift_retainCount", .linux_equiv = "swift:swift_retainCount", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_retainCount) },
        .{ .darwin_symbol = "_swift_deallocObject", .linux_equiv = "swift:swift_deallocObject", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_deallocObject) },
        .{ .darwin_symbol = "_swift_deallocClassInstance", .linux_equiv = "swift:swift_deallocClassInstance", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_deallocClassInstance) },
        .{ .darwin_symbol = "_swift_once", .linux_equiv = "swift:swift_once", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_once) },
        .{ .darwin_symbol = "_swift_beginAccess", .linux_equiv = "swift:swift_beginAccess", .status = .THIN_SHIM, .address = @intFromPtr(&swift_shim.shim_swift_beginAccess) },
        .{ .darwin_symbol = "_swift_endAccess", .linux_equiv = "swift:swift_endAccess", .status = .THIN_SHIM, .address = @intFromPtr(&swift_shim.shim_swift_endAccess) },
        .{ .darwin_symbol = "_swift_bridgeObjectRetain", .linux_equiv = "swift:swift_bridgeObjectRetain", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&swift_shim.shim_swift_bridgeObjectRetain) },
        .{ .darwin_symbol = "_swift_bridgeObjectRelease", .linux_equiv = "swift:swift_bridgeObjectRelease", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&swift_shim.shim_swift_bridgeObjectRelease) },
        .{ .darwin_symbol = "_swift_unknownObjectRetain", .linux_equiv = "swift:swift_unknownObjectRetain", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_unknownObjectRetain) },
        .{ .darwin_symbol = "_swift_unknownObjectRelease", .linux_equiv = "swift:swift_unknownObjectRelease", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_unknownObjectRelease) },
        .{ .darwin_symbol = "_swift_getObjectType", .linux_equiv = "swift:swift_getObjectType", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_getObjectType) },
        .{ .darwin_symbol = "_swift_deletedMethodError", .linux_equiv = "swift:swift_deletedMethodError", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_deletedMethodError) },
        .{ .darwin_symbol = "_swift_retain_n", .linux_equiv = "swift:swift_retain_n", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_retain_n) },
        .{ .darwin_symbol = "_swift_release_n", .linux_equiv = "swift:swift_release_n", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_release_n) },
        .{ .darwin_symbol = "_swift_allocBox", .linux_equiv = "swift:swift_allocBox", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_allocBox) },
        .{ .darwin_symbol = "_swift_projectBox", .linux_equiv = "swift:swift_projectBox", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_projectBox) },
        .{ .darwin_symbol = "_swift_errorRetain", .linux_equiv = "swift:swift_errorRetain", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_errorRetain) },
        .{ .darwin_symbol = "_swift_errorRelease", .linux_equiv = "swift:swift_errorRelease", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_errorRelease) },
        .{ .darwin_symbol = "_swift_willThrow", .linux_equiv = "swift:swift_willThrow", .status = .THIN_SHIM, .address = @intFromPtr(&swift_shim.shim_swift_willThrow) },
        .{ .darwin_symbol = "_swift_unexpectedError", .linux_equiv = "swift:swift_unexpectedError", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_unexpectedError) },
        .{ .darwin_symbol = "_$sSiN", .linux_equiv = "swift:Int_metadata", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.swift_meta_int) },
        .{ .darwin_symbol = "_$sSuN", .linux_equiv = "swift:UInt_metadata", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.swift_meta_uint) },
        .{ .darwin_symbol = "_$sSbN", .linux_equiv = "swift:Bool_metadata", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.swift_meta_bool) },
        .{ .darwin_symbol = "_$sSSN", .linux_equiv = "swift:String_metadata", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.swift_meta_string) },
        .{ .darwin_symbol = "_$sytN", .linux_equiv = "swift:Void_metadata", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.swift_meta_void) },
        .{ .darwin_symbol = "_$sypN", .linux_equiv = "swift:Any_metadata", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.swift_meta_any) },
        .{ .darwin_symbol = "_$sSiWV", .linux_equiv = "swift:Int_vwt", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.swift_vwt_int) },
        .{ .darwin_symbol = "_$sSbWV", .linux_equiv = "swift:Bool_vwt", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.swift_vwt_bool) },
        .{ .darwin_symbol = "_$sSSWV", .linux_equiv = "swift:String_vwt", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.swift_vwt_string) },
        .{ .darwin_symbol = "_$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC", .linux_equiv = "swift:String.init_literal", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_stringInitBuiltin) },
        .{ .darwin_symbol = "_$sSS5countSivg", .linux_equiv = "swift:String.count", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_stringCount) },
        .{ .darwin_symbol = "_$sSS2eeoiySbSS_SStFZ", .linux_equiv = "swift:String.==", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_stringEquals) },
        .{ .darwin_symbol = "_$ss27_allocateUninitializedArrayySayxG_BptBwlF", .linux_equiv = "swift:_allocateUninitializedArray", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_allocateUninitializedArray) },
        .{ .darwin_symbol = "_$ss27_finalizeUninitializedArrayySayxGABnlF", .linux_equiv = "swift:_finalizeUninitializedArray", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_finalizeUninitializedArray) },
        .{ .darwin_symbol = "_$ss5print_9separator10terminatoryypd_S2StF", .linux_equiv = "swift:print", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_print) },
        .{ .darwin_symbol = "__swift_stdlib_nfd_decompositions", .linux_equiv = "swift:unicode_nfd_table", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.swift_stdlib_nfd_decompositions) },
        .{ .darwin_symbol = "__swift_stdlib_getNormData", .linux_equiv = "swift:unicode_norm_data", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_stdlib_getNormData) },
        .{ .darwin_symbol = "__swift_stdlib_getGraphemeBreakProperty", .linux_equiv = "swift:unicode_grapheme", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_stdlib_getGraphemeBreakProperty) },
        .{ .darwin_symbol = "__swift_stdlib_isExtendedPictographic", .linux_equiv = "swift:unicode_pictographic", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_stdlib_isExtendedPictographic) },
        .{ .darwin_symbol = "__swift_stdlib_isInCB_Consonant", .linux_equiv = "swift:unicode_incb", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_stdlib_isInCB_Consonant) },
        .{ .darwin_symbol = "__swift_stdlib_getComposition", .linux_equiv = "swift:unicode_composition", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_stdlib_getComposition) },
        .{ .darwin_symbol = "__swift_stdlib_getDecompositionEntry", .linux_equiv = "swift:unicode_decomposition", .status = .REIMPLEMENTED, .address = @intFromPtr(&swift_shim.shim_swift_stdlib_getDecompositionEntry) },
        .{ .darwin_symbol = "__NSConcreteStackBlock", .linux_equiv = "blocks:NSConcreteStackBlock", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.NSConcreteStackBlock) },
        .{ .darwin_symbol = "__NSConcreteGlobalBlock", .linux_equiv = "blocks:NSConcreteGlobalBlock", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.NSConcreteGlobalBlock) },
        .{ .darwin_symbol = "__NSConcreteMallocBlock", .linux_equiv = "blocks:NSConcreteMallocBlock", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.NSConcreteMallocBlock) },
        .{ .darwin_symbol = "__Block_copy", .linux_equiv = "blocks:_Block_copy", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_Block_copy) },
        .{ .darwin_symbol = "__Block_release", .linux_equiv = "blocks:_Block_release", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_Block_release) },
        .{ .darwin_symbol = "__Block_object_assign", .linux_equiv = "blocks:_Block_object_assign", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_Block_object_assign) },
        .{ .darwin_symbol = "__Block_object_dispose", .linux_equiv = "blocks:_Block_object_dispose", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_Block_object_dispose) },
        .{ .darwin_symbol = "__dispatch_main_q", .linux_equiv = "gcd:dispatch_main_q", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.dispatch_main_q) },
        .{ .darwin_symbol = "__dispatch_queue_attr_concurrent", .linux_equiv = "gcd:dispatch_queue_attr_concurrent", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.dispatch_queue_attr_concurrent) },
        .{ .darwin_symbol = "_dispatch_get_global_queue", .linux_equiv = "gcd:dispatch_get_global_queue", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_get_global_queue) },
        .{ .darwin_symbol = "_dispatch_queue_create", .linux_equiv = "gcd:dispatch_queue_create", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_queue_create) },
        .{ .darwin_symbol = "_dispatch_queue_get_label", .linux_equiv = "gcd:dispatch_queue_get_label", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_queue_get_label) },
        .{ .darwin_symbol = "_dispatch_async_f", .linux_equiv = "gcd:dispatch_async_f", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_async_f) },
        .{ .darwin_symbol = "_dispatch_sync_f", .linux_equiv = "gcd:dispatch_sync_f", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_sync_f) },
        .{ .darwin_symbol = "_dispatch_async", .linux_equiv = "gcd:dispatch_async", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_async) },
        .{ .darwin_symbol = "_dispatch_sync", .linux_equiv = "gcd:dispatch_sync", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_sync) },
        .{ .darwin_symbol = "_dispatch_apply_f", .linux_equiv = "gcd:dispatch_apply_f", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_apply_f) },
        .{ .darwin_symbol = "_dispatch_once_f", .linux_equiv = "gcd:dispatch_once_f", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_once_f) },
        .{ .darwin_symbol = "_dispatch_once", .linux_equiv = "gcd:dispatch_once", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_once) },
        .{ .darwin_symbol = "_dispatch_group_create", .linux_equiv = "gcd:dispatch_group_create", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_group_create) },
        .{ .darwin_symbol = "_dispatch_group_enter", .linux_equiv = "gcd:dispatch_group_enter", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_group_enter) },
        .{ .darwin_symbol = "_dispatch_group_leave", .linux_equiv = "gcd:dispatch_group_leave", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_group_leave) },
        .{ .darwin_symbol = "_dispatch_group_wait", .linux_equiv = "gcd:dispatch_group_wait", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_group_wait) },
        .{ .darwin_symbol = "_dispatch_group_async_f", .linux_equiv = "gcd:dispatch_group_async_f", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_group_async_f) },
        .{ .darwin_symbol = "_dispatch_group_async", .linux_equiv = "gcd:dispatch_group_async", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_group_async) },
        .{ .darwin_symbol = "_dispatch_group_notify_f", .linux_equiv = "gcd:dispatch_group_notify_f", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_group_notify_f) },
        .{ .darwin_symbol = "_dispatch_group_notify", .linux_equiv = "gcd:dispatch_group_notify", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_group_notify) },
        .{ .darwin_symbol = "_dispatch_semaphore_create", .linux_equiv = "gcd:dispatch_semaphore_create", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_semaphore_create) },
        .{ .darwin_symbol = "_dispatch_semaphore_wait", .linux_equiv = "gcd:dispatch_semaphore_wait", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_semaphore_wait) },
        .{ .darwin_symbol = "_dispatch_semaphore_signal", .linux_equiv = "gcd:dispatch_semaphore_signal", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_semaphore_signal) },
        .{ .darwin_symbol = "_dispatch_retain", .linux_equiv = "gcd:dispatch_retain", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_retain) },
        .{ .darwin_symbol = "_dispatch_release", .linux_equiv = "gcd:dispatch_release", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_release) },
        .{ .darwin_symbol = "_dispatch_time", .linux_equiv = "gcd:dispatch_time", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_time) },
        .{ .darwin_symbol = "_dispatch_after_f", .linux_equiv = "gcd:dispatch_after_f", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_after_f) },
        .{ .darwin_symbol = "_dispatch_after", .linux_equiv = "gcd:dispatch_after", .status = .REIMPLEMENTED, .address = @intFromPtr(&dispatch_shim.shim_dispatch_after) },
        .{ .darwin_symbol = "dyld_stub_binder", .linux_equiv = "runtime:trap", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&shim_dyld_stub_binder) },
    };

    for (table) |entry| {
        if (std.mem.eql(u8, entry.darwin_symbol, symbol)) return entry;
    }
    return null;
}

pub fn isDarwinSystemDylib(path: []const u8) bool {
    return std.mem.startsWith(u8, path, "/usr/lib/libSystem") or
        std.mem.startsWith(u8, path, "/usr/lib/system/") or
        std.mem.startsWith(u8, path, "/usr/lib/libc++") or
        std.mem.startsWith(u8, path, "/System/Library/");
}
