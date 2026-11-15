// WINS — winrun_msvcrt.zig
// Native x86_64 Linux MSVCRT.dll shim for console and GUI PE32+ binaries.
// Implements the Win64 C runtime ABI (FILE streams, memory allocation, string/ctype
// routines, POSIX file I/O, filesystem, time, setjmp/longjmp, and data exports).

const std = @import("std");

// ---------------------------------------------------------------------------
// MSVC x86 C++ exception handling
//
// The three records an SEH dispatcher hands to a frame handler. Only
// EXCEPTION_RECORD needs real content; CONTEXT and DISPATCHER_CONTEXT are
// supplied so the guest handler reads a plausible frame and __CxxFrameHandler can
// fill in what its __CxxFrameHandler3 wrapper expects.
pub const EH_MAGIC: u32 = 0x19930520;
pub const EH_CODE: u32 = 0xE06D7363;

pub const ExceptionRecord = extern struct {
    exception_code: u32,
    exception_flags: u32 = 1, // EXCEPTION_NONCONTINUABLE
    exception_record: usize = 0,
    exception_address: usize = 0,
    number_parameters: u32 = 4,
    exception_information: [15]usize = [_]usize{0} ** 15,
};

pub const Disposition = enum(i32) {
    continue_search = 0,
    execute_handler = 1,
    continue_execution = -1,
};

/// The Win32 x86 CONTEXT, in field order. Offsets are load-bearing: the guest
/// handler reads registers straight out of this record.
pub const GuestContext = extern struct {
    context_flags: u32 = 0x10007, // CONTEXT_INTEGER | CONTEXT_CONTROL | CONTEXT_SEGMENTS
    dr0: u32 = 0,
    dr1: u32 = 0,
    dr2: u32 = 0,
    dr3: u32 = 0,
    dr6: u32 = 0,
    dr7: u32 = 0,
    float_save: [28]u32 = [_]u32{0} ** 28, // FLOATING_SAVE_AREA, 112 bytes
    seg_gs: u32 = 0,
    seg_fs: u32 = 0,
    seg_es: u32 = 0,
    seg_ds: u32 = 0,
    edi: u32 = 0,
    esi: u32 = 0,
    ebx: u32 = 0,
    edx: u32 = 0,
    ecx: u32 = 0,
    eax: u32 = 0,
    ebp: u32 = 0,
    eip: u32 = 0,
    seg_cs: u32 = 0,
    eflags: u32 = 0,
    esp: u32 = 0,
    seg_ss: u32 = 0,

    fn sizeOf() usize {
        return @sizeOf(GuestContext) + 512;
    }
};

/// The Win32 DISPATCHER_CONTEXT, in field order. The guest's
/// __CxxFrameHandler3 wrapper reads these before deciding a disposition; a
/// zeroed block makes every frame answer EXCEPTION_CONTINUE_SEARCH.
const DispatcherContext = extern struct {
    control_pc: usize = 0,
    image_base: usize = 0,
    function_entry: usize = 0,
    establisher_frame: usize = 0,
    target_ip: usize = 0,
    context_record: usize = 0,
    language_handler: usize = 0,
    handler_data: usize = 0,
    msvc_func_info: usize = 0,
    msvc_throw_info: usize = 0,
};

const linux = std.os.linux;

// The C runtime is cdecl, not stdcall: the CALLER pops the arguments. The
// Win32 DLL modules (kernel32, user32, ...) are stdcall instead. On i386 this
// distinction is fatal -- a stdcall shim bound into a cdecl slot leaves the
// guest's stack misaligned by the argument count and the next `ret` lands on
// garbage. On x86_64 both conventions lower to the same ABI, which is why the
// 64-bit loader never showed this.
const W: std.builtin.CallingConvention = .winapi;
const C: std.builtin.CallingConvention = .c;

// ---------------------------------------------------------------------------
// 1. Data Exports & Global CRT State
// ---------------------------------------------------------------------------

pub var msvcrt_fmode: i32 = 0;
pub var msvcrt_commode: i32 = 0;
pub var msvcrt_initenv: usize = 0;
pub var msvcrt_argv: ?[*]?[*:0]u8 = &argv_ptrs;
pub var msvcrt_environ: ?[*]?[*:0]u8 = &envp_ptrs;
pub var msvcrt_timezone: i32 = 0;
var thread_errno: i32 = 0;
var app_type: i32 = 1;

fn _errno() callconv(C) *i32 {
    return &thread_errno;
}

fn __p__fmode() callconv(C) *i32 {
    return &msvcrt_fmode;
}

fn __p__commode() callconv(C) *i32 {
    return &msvcrt_commode;
}

fn __p___argv() callconv(C) *?[*]?[*:0]u8 {
    return &msvcrt_argv;
}

fn __p___argc() callconv(C) *i32 {
    return &saved_argc;
}

fn __p__environ() callconv(C) *?[*]?[*:0]u8 {
    return &msvcrt_environ;
}

fn __set_app_type(at: i32) callconv(C) void {
    app_type = at;
}

fn __setusermatherr(handler: ?*anyopaque) callconv(C) void {
    _ = handler;
}

fn ___lc_codepage_func() callconv(C) u32 {
    return 65001; // CP_UTF8
}

fn ___mb_cur_max_func() callconv(C) i32 {
    return 4;
}

const Lconv = extern struct {
    decimal_point: [*:0]const u8 = ".",
    thousands_sep: [*:0]const u8 = "",
    grouping: [*:0]const u8 = "",
    int_curr_symbol: [*:0]const u8 = "",
    currency_symbol: [*:0]const u8 = "",
    mon_decimal_point: [*:0]const u8 = "",
    mon_thousands_sep: [*:0]const u8 = "",
    mon_grouping: [*:0]const u8 = "",
    positive_sign: [*:0]const u8 = "",
    negative_sign: [*:0]const u8 = "-",
    int_frac_digits: u8 = 127,
    frac_digits: u8 = 127,
    p_cs_precedes: u8 = 127,
    p_sep_by_space: u8 = 127,
    n_cs_precedes: u8 = 127,
    n_sep_by_space: u8 = 127,
    p_sign_posn: u8 = 127,
    n_sign_posn: u8 = 127,
    _W_decimal_point: ?*const anyopaque = null,
    _W_thousands_sep: ?*const anyopaque = null,
    _W_int_curr_symbol: ?*const anyopaque = null,
    _W_currency_symbol: ?*const anyopaque = null,
    _W_mon_decimal_point: ?*const anyopaque = null,
    _W_mon_thousands_sep: ?*const anyopaque = null,
    _W_positive_sign: ?*const anyopaque = null,
    _W_negative_sign: ?*const anyopaque = null,
};

var default_lconv: Lconv = .{};

fn localeconv() callconv(C) *Lconv {
    return &default_lconv;
}

// ---------------------------------------------------------------------------
// 2. Command-Line Arguments & CRT Initialization
// ---------------------------------------------------------------------------

var arg_storage: [32][512:0]u8 = undefined;
var argv_ptrs: [33]?[*:0]u8 = .{null} ** 33;
var envp_ptrs: [2]?[*:0]u8 = .{ null, null };
var saved_argc: i32 = 1;
var args_initialized: bool = false;

fn ensureDefaultArgs() void {
    if (args_initialized) return;
    const def = "app.exe";
    @memcpy(arg_storage[0][0..def.len], def);
    arg_storage[0][def.len] = 0;
    argv_ptrs[0] = &arg_storage[0];
    argv_ptrs[1] = null;
    saved_argc = 1;
    args_initialized = true;
}

pub fn setArgs(args: []const []const u8) void {
    const count = @min(args.len, 32);
    if (count == 0) {
        ensureDefaultArgs();
        return;
    }
    for (0..count) |i| {
        const s = args[i];
        const copy_len = @min(s.len, 511);
        @memcpy(arg_storage[i][0..copy_len], s[0..copy_len]);
        arg_storage[i][copy_len] = 0;
        argv_ptrs[i] = &arg_storage[i];
    }
    argv_ptrs[count] = null;
    saved_argc = @intCast(count);
    args_initialized = true;
}

fn __getmainargs(
    pargc: ?*i32,
    pargv: ?*?[*]?[*:0]u8,
    penv: ?*?[*]?[*:0]u8,
    dowildcard: i32,
    startinfo: ?*anyopaque,
) callconv(C) i32 {
    _ = dowildcard;
    _ = startinfo;
    ensureDefaultArgs();
    initEnvironment();
    if (pargc) |p| p.* = saved_argc;
    if (pargv) |p| p.* = &argv_ptrs;
    if (penv) |p| p.* = &env_ptrs_dyn;
    return 0;
}

const InitFunc = *const fn () callconv(C) void;

fn _initterm(begin: ?[*]const usize, end: ?[*]const usize) callconv(C) void {
    if (begin == null or end == null) return;
    var cur = @intFromPtr(begin.?);
    const stop = @intFromPtr(end.?);
    var ran: usize = 0;
    while (cur < stop) : (cur += @sizeOf(usize)) {
        const fn_addr = @as(*const usize, @ptrFromInt(cur)).*;
        if (fn_addr != 0) {
            const f: InitFunc = @ptrFromInt(fn_addr);
            // Static constructors: the only place guest vtables get filled in.
            // Traced only when the operator asks (WINS_TRACE=1), because this is
            // library code shared with the 64-bit loader.
            if (trace_static_init) std.debug.print("[msvcrt] _initterm initializer 0x{x:0>8}\n", .{fn_addr});
            f();
            ran += 1;
        }
    }
    if (trace_static_init) std.debug.print("[msvcrt] _initterm ran {d} initializer(s)\n", .{ran});
}

fn _onexit(func: ?*anyopaque) callconv(C) ?*anyopaque {
    return func;
}

fn _lock(locknum: i32) callconv(C) void {
    _ = locknum;
}

fn _unlock(locknum: i32) callconv(C) void {
    _ = locknum;
}

fn __C_specific_handler() callconv(C) i32 {
    return 1; // ExceptionContinueExecution / handler stub
}

fn signal(sig: i32, handler: ?*anyopaque) callconv(C) ?*anyopaque {
    _ = sig;
    return handler;
}

const ATEXIT_MAX = 32;
var atexit_funcs: [ATEXIT_MAX]?*const fn () callconv(C) void = .{null} ** ATEXIT_MAX;
var atexit_count: usize = 0;

fn atexit(func: ?*const fn () callconv(C) void) callconv(C) i32 {
    const f = func orelse return -1;
    if (atexit_count >= ATEXIT_MAX) return -1;
    atexit_funcs[atexit_count] = f;
    atexit_count += 1;
    return 0;
}

fn runAtExit() void {
    while (atexit_count > 0) {
        atexit_count -= 1;
        if (atexit_funcs[atexit_count]) |f| {
            f();
        }
    }
}

fn exit(status: i32) callconv(C) noreturn {
    runAtExit();
    linux.exit_group(@bitCast(status));
}

fn _exit(status: i32) callconv(C) noreturn {
    linux.exit_group(@bitCast(status));
}

fn _cexit() callconv(C) void {
    runAtExit();
}

fn _c_exit() callconv(C) void {}

fn _amsg_exit(rterrnum: i32) callconv(C) noreturn {
    linux.exit_group(@bitCast(255 + rterrnum));
}

fn abort() callconv(C) noreturn {
    linux.exit_group(3);
}

// ---------------------------------------------------------------------------
// 3. Heap Memory Management (malloc, calloc, realloc, free)
// ---------------------------------------------------------------------------

var crt_heap_base: usize = 0;
var crt_heap_off: usize = 0;
const CRT_HEAP_CAP: usize = 64 * 1024 * 1024;

fn ensureCrtHeap() bool {
    if (crt_heap_base != 0) return true;
    const rc = linux.mmap(
        null,
        CRT_HEAP_CAP,
        .{ .READ = true, .WRITE = true },
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );
    if (linux.errno(rc) != .SUCCESS) return false;
    crt_heap_base = rc;
    crt_heap_off = 0;
    return true;
}

fn malloc(size: usize) callconv(C) ?[*]u8 {
    if (!ensureCrtHeap()) return null;
    const req = if (size == 0) 16 else std.mem.alignForward(usize, size, 16);
    if (crt_heap_off + 16 + req > CRT_HEAP_CAP) return null;
    const hdr_ptr: *usize = @ptrFromInt(crt_heap_base + crt_heap_off);
    hdr_ptr.* = size;
    const user_ptr: [*]u8 = @ptrFromInt(crt_heap_base + crt_heap_off + 16);
    crt_heap_off += 16 + req;
    return user_ptr;
}

fn calloc(nmemb: usize, size: usize) callconv(C) ?[*]u8 {
    const total = nmemb *| size;
    const ptr = malloc(total) orelse return null;
    if (total > 0) @memset(ptr[0..total], 0);
    return ptr;
}

fn free(ptr: ?*anyopaque) callconv(C) void {
    _ = ptr;
}

fn realloc(ptr: ?*anyopaque, new_size: usize) callconv(C) ?[*]u8 {
    if (ptr == null) return malloc(new_size);
    if (new_size == 0) return null;
    const new_ptr = malloc(new_size) orelse return null;
    const addr = @intFromPtr(ptr.?);
    if (addr >= crt_heap_base + 16 and addr < crt_heap_base + crt_heap_off) {
        const old_size = @as(*const usize, @ptrFromInt(addr - 16)).*;
        const copy_len = @min(old_size, new_size);
        if (copy_len > 0) {
            const old_bytes: [*]const u8 = @ptrCast(ptr.?);
            @memcpy(new_ptr[0..copy_len], old_bytes[0..copy_len]);
        }
    }
    return new_ptr;
}

// ---------------------------------------------------------------------------
// 4. FILE Streams & I/O
// ---------------------------------------------------------------------------

/// The guest CRT's FILE. The two layouts are NOT the same struct with different
/// padding: the field order differs too. 64-bit UCRT puts `_cnt` right after
/// `_ptr`; 32-bit MSVCRT puts `_base` there. Pick by pointer width so i386
/// guests (winrun32) see the layout their CRT actually has.
pub const MsvcrtFile = if (@sizeOf(usize) == 8) extern struct {
    _ptr: ?[*]u8 = null, // 0x00
    _cnt: i32 = 0, // 0x08
    _pad0: i32 = 0, // 0x0c
    _base: ?[*]u8 = null, // 0x10
    _flag: i32 = 0, // 0x18
    _file: i32 = -1, // 0x1c
    _charbuf: i32 = 0, // 0x20
    _bufsiz: i32 = 0, // 0x24
    _tmpfname: ?[*]u8 = null, // 0x28
} else extern struct {
    _ptr: ?[*]u8 = null, // 0x00
    _cnt: i32 = 0, // 0x04
    _base: ?[*]u8 = null, // 0x08
    _flag: i32 = 0, // 0x0c
    _file: i32 = -1, // 0x10
    _charbuf: i32 = 0, // 0x14
    _bufsiz: i32 = 0, // 0x18
    _tmpfname: ?[*]u8 = null, // 0x1c
};

comptime {
    std.debug.assert(@sizeOf(MsvcrtFile) == if (@sizeOf(usize) == 8) 48 else 32);
}

/// Set from the loader when WINS_TRACE=1. Keeps library output clean by default.
pub var trace_static_init: bool = false;

/// Base of the guest's TIB, set by winrun32 after setupTib(). The guest stores
/// its own SEH chain head in TIB[0] (`mov %%esp, %%fs:0`), so this is the entry
/// point for walking the exception frames _CxxThrowException must unwind.
pub var guest_tib_base: usize = 0;

/// Set by _except_handler3 when a filter says EXCEPTION_EXECUTE_HANDLER: the guest
/// __except block to transfer control to, and the EBP its prologue
/// `mov -0x18(%ebp),%esp` restores from. The registration node follows
/// `push %%ebp; mov %%esp,%%ebp` plus three more pushes, so EBP == node + 12.
pub var accept_handler: usize = 0;
pub var accept_ebp: usize = 0;

/// Capture the guest's EBX/ECX/EDX from inside a shim, via inline asm. A shim is
/// host code running with the guest's register state live, so this is the only
/// place a corruption can be observed mid-run without a debugger -- gdb cannot
/// set guest breakpoints before the image is mapped.
const IOB_COUNT = 32;
var iob_table: [IOB_COUNT]MsvcrtFile = initIobTable();
var iob_in_use: [IOB_COUNT]bool = .{ true, true, true } ++ .{false} ** (IOB_COUNT - 3);
var iob_binary: [IOB_COUNT]bool = .{false} ** IOB_COUNT;
var iob_ungetc: [IOB_COUNT]i32 = .{-1} ** IOB_COUNT;

fn initIobTable() [IOB_COUNT]MsvcrtFile {
    var t: [IOB_COUNT]MsvcrtFile = .{MsvcrtFile{}} ** IOB_COUNT;
    t[0]._file = 0; // stdin
    t[0]._flag = 0x0001; // _IOREAD
    t[1]._file = 1; // stdout
    t[1]._flag = 0x0002; // _IOWRT
    t[2]._file = 2; // stderr
    t[2]._flag = 0x0002; // _IOWRT
    return t;
}

fn streamIndex(stream: ?*MsvcrtFile) ?usize {
    const s = stream orelse return null;
    const base = @intFromPtr(&iob_table[0]);
    const addr = @intFromPtr(s);
    if (addr < base) return null;
    const diff = addr - base;
    const idx = diff / @sizeOf(MsvcrtFile);
    if (idx >= IOB_COUNT) return null;
    return idx;
}

fn __iob_func() callconv(C) [*]MsvcrtFile {
    return &iob_table;
}

fn __acrt_iob_func(idx: u32) callconv(C) ?*MsvcrtFile {
    if (idx >= IOB_COUNT) return null;
    return &iob_table[idx];
}

fn normalizePathA(src: [*:0]const u8, out: *[512:0]u8) void {
    const src_slice = std.mem.span(src);
    var buf: [512]u8 = undefined;
    const res = @import("wins_graph.zig").normalizePath(&buf, src_slice);
    const copy_len = @min(res.len, 511);
    @memcpy(out[0..copy_len], res[0..copy_len]);
    out[copy_len] = 0;
}

fn fopen(filename: ?[*:0]const u8, mode: ?[*:0]const u8) callconv(C) ?*MsvcrtFile {
    if (filename == null or mode == null) return null;
    var slot: ?usize = null;
    for (3..IOB_COUNT) |i| {
        if (!iob_in_use[i]) {
            slot = i;
            break;
        }
    }
    const idx = slot orelse return null;

    var has_w = false;
    var has_a = false;
    var has_plus = false;
    var has_b = false;
    var mi: usize = 0;
    while (mode.?[mi] != 0) : (mi += 1) {
        switch (mode.?[mi]) {
            'w' => has_w = true,
            'a' => has_a = true,
            '+' => has_plus = true,
            'b' => has_b = true,
            else => {},
        }
    }

    var flags: linux.O = .{};
    if (has_plus) {
        flags.ACCMODE = .RDWR;
    } else if (has_w or has_a) {
        flags.ACCMODE = .WRONLY;
    } else {
        flags.ACCMODE = .RDONLY;
    }
    if (has_w) {
        flags.CREAT = true;
        flags.TRUNC = true;
    } else if (has_a) {
        flags.CREAT = true;
        flags.APPEND = true;
    }

    var path_buf: [512:0]u8 = undefined;
    normalizePathA(filename.?, &path_buf);

    const rc = linux.open(&path_buf, flags, 0o644);
    if (linux.errno(rc) != .SUCCESS) {
        thread_errno = @intCast(@intFromEnum(linux.errno(rc)));
        return null;
    }

    iob_table[idx] = .{
        ._file = @intCast(rc),
        ._flag = if (has_w or has_a) 0x0002 else 0x0001,
    };
    iob_in_use[idx] = true;
    iob_binary[idx] = has_b;
    iob_ungetc[idx] = -1;
    return &iob_table[idx];
}

fn fclose(stream: ?*MsvcrtFile) callconv(C) i32 {
    const idx = streamIndex(stream) orelse return -1;
    const fd = iob_table[idx]._file;
    if (fd >= 3) {
        _ = linux.close(fd);
    }
    if (idx >= 3) {
        iob_in_use[idx] = false;
        iob_table[idx]._file = -1;
    }
    iob_ungetc[idx] = -1;
    return 0;
}

fn fflush(stream: ?*MsvcrtFile) callconv(C) i32 {
    _ = stream;
    return 0;
}

fn fseek(stream: ?*MsvcrtFile, offset: i32, whence: i32) callconv(C) i32 {
    const s = stream orelse return -1;
    if (streamIndex(stream)) |idx| {
        iob_ungetc[idx] = -1;
    }
    s._flag &= ~@as(i32, 0x10);
    const pos = _lseeki64(s._file, offset, whence);
    if (pos == null) {
        thread_errno = 22; // EINVAL
        return -1;
    }
    return 0;
}

fn ftell(stream: ?*MsvcrtFile) callconv(C) i32 {
    const s = stream orelse return -1;
    const rc = _lseeki64(s._file, 0, 1); // SEEK_CUR
    if (rc == null) {
        thread_errno = 22; // EINVAL
        return -1;
    }
    var pos: i32 = @intCast(rc.?);
    if (streamIndex(stream)) |idx| {
        if (iob_ungetc[idx] >= 0 and pos > 0) pos -= 1;
    }
    return pos;
}

fn writeRawAll(fd: i32, data: []const u8) bool {
    var off: usize = 0;
    while (off < data.len) {
        const rc = linux.write(fd, data[off..].ptr, data.len - off);
        if (linux.errno(rc) != .SUCCESS) {
            thread_errno = @intCast(@intFromEnum(linux.errno(rc)));
            return false;
        }
        if (rc == 0) break;
        off += rc;
    }
    return true;
}

fn fputc(c: i32, stream: ?*MsvcrtFile) callconv(C) i32 {
    const s = stream orelse return -1;
    const is_bin = if (streamIndex(stream)) |idx| iob_binary[idx] else false;
    const byte: u8 = @intCast(c & 0xFF);
    if (!is_bin and byte == '\n') {
        const crlf = [_]u8{ '\r', '\n' };
        if (!writeRawAll(s._file, &crlf)) return -1;
        return c & 0xFF;
    }
    const one = [_]u8{byte};
    if (!writeRawAll(s._file, &one)) return -1;
    return c & 0xFF;
}

fn fwrite(ptr: ?[*]const u8, size: usize, nmemb: usize, stream: ?*MsvcrtFile) callconv(C) usize {
    if (ptr == null or stream == null or size == 0 or nmemb == 0) return 0;
    const s = stream.?;
    const total = size * nmemb;
    const is_bin = if (streamIndex(stream)) |idx| iob_binary[idx] else false;
    const slice = ptr.?[0..total];
    if (is_bin) {
        if (!writeRawAll(s._file, slice)) return 0;
        return nmemb;
    }
    var start: usize = 0;
    for (slice, 0..) |b, i| {
        if (b == '\n') {
            if (i > start) {
                if (!writeRawAll(s._file, slice[start..i])) return i / size;
            }
            const crlf = [_]u8{ '\r', '\n' };
            if (!writeRawAll(s._file, &crlf)) return i / size;
            start = i + 1;
        }
    }
    if (start < slice.len) {
        if (!writeRawAll(s._file, slice[start..])) return start / size;
    }
    return nmemb;
}

fn getc(stream: ?*MsvcrtFile) callconv(C) i32 {
    const s = stream orelse return -1;
    const idx_opt = streamIndex(stream);
    if (idx_opt) |idx| {
        if (iob_ungetc[idx] >= 0) {
            const ch = iob_ungetc[idx];
            iob_ungetc[idx] = -1;
            return ch;
        }
    }
    var b: [1]u8 = undefined;
    const rc = linux.read(s._file, &b, 1);
    if (linux.errno(rc) != .SUCCESS or rc == 0) {
        s._flag |= 0x10; // _IOEOF
        return -1;
    }
    const is_bin = if (idx_opt) |idx| iob_binary[idx] else false;
    if (!is_bin and b[0] == '\r') {
        var b2: [1]u8 = undefined;
        const rc2 = linux.read(s._file, &b2, 1);
        if (linux.errno(rc2) == .SUCCESS and rc2 == 1) {
            if (b2[0] == '\n') return '\n';
            if (idx_opt) |idx| iob_ungetc[idx] = b2[0];
        }
    }
    return b[0];
}

fn ungetc(c: i32, stream: ?*MsvcrtFile) callconv(C) i32 {
    if (c < 0) return -1;
    if (streamIndex(stream)) |idx| {
        iob_ungetc[idx] = c & 0xFF;
        stream.?._flag &= ~@as(i32, 0x10);
        return c & 0xFF;
    }
    return -1;
}

fn fread(ptr: ?[*]u8, size: usize, nmemb: usize, stream: ?*MsvcrtFile) callconv(C) usize {
    if (ptr == null or stream == null or size == 0 or nmemb == 0) return 0;
    const s = stream.?;
    const total = size * nmemb;
    const idx_opt = streamIndex(stream);
    const is_bin = if (idx_opt) |idx| iob_binary[idx] else false;
    const has_unget = if (idx_opt) |idx| (iob_ungetc[idx] >= 0) else false;

    if (is_bin and !has_unget) {
        var read_bytes: usize = 0;
        while (read_bytes < total) {
            const rc = linux.read(s._file, ptr.? + read_bytes, total - read_bytes);
            if (linux.errno(rc) != .SUCCESS or rc == 0) {
                s._flag |= 0x10;
                break;
            }
            read_bytes += rc;
        }
        return read_bytes / size;
    }

    var count: usize = 0;
    while (count < total) : (count += 1) {
        const ch = getc(stream);
        if (ch < 0) break;
        ptr.?[count] = @intCast(ch & 0xFF);
    }
    return count / size;
}

fn fgets(buf: ?[*]u8, n: i32, stream: ?*MsvcrtFile) callconv(C) ?[*]u8 {
    if (buf == null or n <= 0 or stream == null) return null;
    const limit: usize = @intCast(n - 1);
    var pos: usize = 0;
    while (pos < limit) {
        const ch = getc(stream);
        if (ch < 0) {
            if (pos == 0) return null;
            break;
        }
        buf.?[pos] = @intCast(ch & 0xFF);
        pos += 1;
        if (ch == '\n') break;
    }
    buf.?[pos] = 0;
    return buf;
}

fn fputs(s: ?[*:0]const u8, stream: ?*MsvcrtFile) callconv(C) i32 {
    const str = s orelse return -1;
    const len = strlen(str);
    if (fwrite(str, 1, len, stream) == len) return 0 else return -1;
}

fn putchar(c: i32) callconv(C) i32 {
    return fputc(c, &iob_table[1]);
}

fn feof(stream: ?*MsvcrtFile) callconv(C) i32 {
    const s = stream orelse return 0;
    return if ((s._flag & 0x10) != 0) 1 else 0;
}

fn ferror(stream: ?*MsvcrtFile) callconv(C) i32 {
    const s = stream orelse return 0;
    return if ((s._flag & 0x20) != 0) 1 else 0;
}

fn clearerr(stream: ?*MsvcrtFile) callconv(C) void {
    if (stream) |s| s._flag &= ~@as(i32, 0x30);
}

fn _filbuf(stream: ?*MsvcrtFile) callconv(C) i32 {
    return getc(stream);
}

fn _getch() callconv(C) i32 {
    return getc(&iob_table[0]);
}

fn _getche() callconv(C) i32 {
    const ch = getc(&iob_table[0]);
    if (ch >= 0) _ = fputc(ch, &iob_table[1]);
    return ch;
}

fn setbuf(stream: ?*MsvcrtFile, buffer: ?[*]u8) callconv(C) void {
    _ = stream;
    _ = buffer;
}

fn setvbuf(stream: ?*MsvcrtFile, buffer: ?[*]u8, mode: i32, size: usize) callconv(C) i32 {
    _ = stream;
    _ = buffer;
    _ = mode;
    _ = size;
    return 0;
}

// ---------------------------------------------------------------------------
// 5. Low-Level POSIX File Descriptors
// ---------------------------------------------------------------------------

const _O_RDONLY: i32 = 0x0000;
const _O_WRONLY: i32 = 0x0001;
const _O_RDWR: i32 = 0x0002;
const _O_APPEND: i32 = 0x0008;
const _O_CREAT: i32 = 0x0100;
const _O_TRUNC: i32 = 0x0200;
const _O_EXCL: i32 = 0x0400;

fn _open(filename: ?[*:0]const u8, oflag: i32, pmode: i32) callconv(C) i32 {
    const name = filename orelse return -1;
    var flags: linux.O = .{};
    const access = oflag & 0x0003;
    if (access == _O_RDONLY) {
        flags.ACCMODE = .RDONLY;
    } else if (access == _O_WRONLY) {
        flags.ACCMODE = .WRONLY;
    } else if (access == _O_RDWR) {
        flags.ACCMODE = .RDWR;
    }
    if ((oflag & _O_CREAT) != 0) flags.CREAT = true;
    if ((oflag & _O_TRUNC) != 0) flags.TRUNC = true;
    if ((oflag & _O_APPEND) != 0) flags.APPEND = true;
    if ((oflag & _O_EXCL) != 0) flags.EXCL = true;

    var path_buf: [512:0]u8 = undefined;
    normalizePathA(name, &path_buf);
    const mode: linux.mode_t = if (pmode != 0) @intCast(pmode & 0o777) else 0o644;
    const rc = linux.open(&path_buf, flags, mode);
    if (linux.errno(rc) != .SUCCESS) {
        thread_errno = @intCast(@intFromEnum(linux.errno(rc)));
        return -1;
    }
    return @intCast(rc);
}

fn _creat(filename: ?[*:0]const u8, pmode: i32) callconv(C) i32 {
    return _open(filename, _O_CREAT | _O_TRUNC | _O_WRONLY, pmode);
}

fn _close(fd: i32) callconv(C) i32 {
    if (fd < 0) return -1;
    const rc = linux.close(fd);
    if (linux.errno(rc) != .SUCCESS) {
        thread_errno = @intCast(@intFromEnum(linux.errno(rc)));
        return -1;
    }
    return 0;
}

fn _read(fd: i32, buf: ?[*]u8, count: u32) callconv(C) i32 {
    const b = buf orelse return -1;
    const rc = linux.read(fd, b, count);
    if (linux.errno(rc) != .SUCCESS) {
        thread_errno = @intCast(@intFromEnum(linux.errno(rc)));
        return -1;
    }
    return @intCast(rc);
}

fn _write(fd: i32, buf: ?[*]const u8, count: u32) callconv(C) i32 {
    const b = buf orelse return -1;
    const rc = linux.write(fd, b, count);
    if (linux.errno(rc) != .SUCCESS) {
        thread_errno = @intCast(@intFromEnum(linux.errno(rc)));
        return -1;
    }
    return @intCast(rc);
}

/// Returns the resulting offset, or null on failure. std's linux.lseek cannot
/// compile for a 32-bit target (it bitcasts an i64 into the syscall's offset
/// slot), so the i386 path goes through _llseek (140), which takes the 64-bit
/// offset as explicit high/low halves plus a result pointer.
fn _lseeki64(fd: i32, offset: i64, origin: i32) ?i64 {
    if (@sizeOf(usize) == 8) {
        const rc = linux.lseek(fd, offset, @intCast(origin));
        if (linux.errno(rc) != .SUCCESS) {
            thread_errno = @intCast(@intFromEnum(linux.errno(rc)));
            return null;
        }
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
        @as(usize, @intCast(origin)),
    );
    if (linux.errno(rc) != .SUCCESS) {
        thread_errno = @intCast(@intFromEnum(linux.errno(rc)));
        return null;
    }
    return result;
}

fn _telli64(fd: i32) i64 {
    return _lseeki64(fd, 0, 1) orelse -1; // SEEK_CUR
}

fn _dup(fd: i32) callconv(C) i32 {
    const rc = linux.dup(fd);
    if (linux.errno(rc) != .SUCCESS) {
        thread_errno = @intCast(@intFromEnum(linux.errno(rc)));
        return -1;
    }
    return @intCast(rc);
}

fn _dup2(fd1: i32, fd2: i32) callconv(C) i32 {
    const rc = linux.dup2(fd1, fd2);
    if (linux.errno(rc) != .SUCCESS) {
        thread_errno = @intCast(@intFromEnum(linux.errno(rc)));
        return -1;
    }
    return @intCast(rc);
}

fn _pipe(pfds: ?[*]i32, psize: u32, textmode: i32) callconv(C) i32 {
    _ = psize;
    _ = textmode;
    const p = pfds orelse return -1;
    var fds: [2]i32 = undefined;
    const rc = linux.pipe2(&fds, .{});
    if (linux.errno(rc) != .SUCCESS) {
        thread_errno = @intCast(@intFromEnum(linux.errno(rc)));
        return -1;
    }
    p[0] = fds[0];
    p[1] = fds[1];
    return 0;
}

const WinSize = extern struct {
    ws_row: u16 = 0,
    ws_col: u16 = 0,
    ws_xpixel: u16 = 0,
    ws_ypixel: u16 = 0,
};

fn _isatty(fd: i32) callconv(C) i32 {
    var ws: WinSize = .{};
    const rc = linux.ioctl(fd, linux.T.IOCGWINSZ, @intFromPtr(&ws));
    return if (linux.errno(rc) == .SUCCESS) 1 else 0;
}

fn _get_osfhandle(fd: i32) callconv(C) isize {
    return @intCast(fd);
}

fn _open_osfhandle(osfhandle: isize, flags: i32) callconv(C) i32 {
    _ = flags;
    return @intCast(osfhandle);
}

fn _setmode(fd: i32, mode: i32) callconv(C) i32 {
    _ = fd;
    return mode;
}

fn _fileno(stream: ?*MsvcrtFile) callconv(C) i32 {
    const s = stream orelse return -1;
    return s._file;
}

fn _fdopen(fd: i32, mode: ?[*:0]const u8) callconv(C) ?*MsvcrtFile {
    if (fd < 0) return null;
    var slot: ?usize = null;
    for (3..IOB_COUNT) |i| {
        if (!iob_in_use[i]) {
            slot = i;
            break;
        }
    }
    const idx = slot orelse return null;
    var has_w = false;
    var has_b = false;
    if (mode) |m| {
        var mi: usize = 0;
        while (m[mi] != 0) : (mi += 1) {
            if (m[mi] == 'w' or m[mi] == 'a') has_w = true;
            if (m[mi] == 'b') has_b = true;
        }
    }
    iob_table[idx] = .{
        ._file = fd,
        ._flag = if (has_w) 0x0002 else 0x0001,
    };
    iob_in_use[idx] = true;
    iob_binary[idx] = has_b;
    iob_ungetc[idx] = -1;
    return &iob_table[idx];
}

// ---------------------------------------------------------------------------
// 6. Filesystem & Paths
// ---------------------------------------------------------------------------

fn _access(path: ?[*:0]const u8, mode: i32) callconv(C) i32 {
    const p = path orelse return -1;
    var buf: [512:0]u8 = undefined;
    normalizePathA(p, &buf);
    const rc = linux.access(&buf, @intCast(mode & 0x7));
    if (linux.errno(rc) != .SUCCESS) {
        thread_errno = @intCast(@intFromEnum(linux.errno(rc)));
        return -1;
    }
    return 0;
}

fn _chmod(path: ?[*:0]const u8, mode: i32) callconv(C) i32 {
    const p = path orelse return -1;
    var buf: [512:0]u8 = undefined;
    normalizePathA(p, &buf);
    const rc = linux.chmod(&buf, @intCast(mode & 0o777));
    if (linux.errno(rc) != .SUCCESS) {
        thread_errno = @intCast(@intFromEnum(linux.errno(rc)));
        return -1;
    }
    return 0;
}

fn _unlink(path: ?[*:0]const u8) callconv(C) i32 {
    const p = path orelse return -1;
    var buf: [512:0]u8 = undefined;
    normalizePathA(p, &buf);
    const rc = linux.unlink(&buf);
    if (linux.errno(rc) != .SUCCESS) {
        thread_errno = @intCast(@intFromEnum(linux.errno(rc)));
        return -1;
    }
    return 0;
}

fn _mkdir(path: ?[*:0]const u8) callconv(C) i32 {
    const p = path orelse return -1;
    var buf: [512:0]u8 = undefined;
    normalizePathA(p, &buf);
    const rc = linux.mkdir(&buf, 0o755);
    if (linux.errno(rc) != .SUCCESS) {
        thread_errno = @intCast(@intFromEnum(linux.errno(rc)));
        return -1;
    }
    return 0;
}

fn _rmdir(path: ?[*:0]const u8) callconv(C) i32 {
    const p = path orelse return -1;
    var buf: [512:0]u8 = undefined;
    normalizePathA(p, &buf);
    const rc = linux.rmdir(&buf);
    if (linux.errno(rc) != .SUCCESS) {
        thread_errno = @intCast(@intFromEnum(linux.errno(rc)));
        return -1;
    }
    return 0;
}

fn _chdir(path: ?[*:0]const u8) callconv(C) i32 {
    const p = path orelse return -1;
    var buf: [512:0]u8 = undefined;
    normalizePathA(p, &buf);
    const rc = linux.chdir(&buf);
    if (linux.errno(rc) != .SUCCESS) {
        thread_errno = @intCast(@intFromEnum(linux.errno(rc)));
        return -1;
    }
    return 0;
}

fn _getcwd(buf: ?[*]u8, maxlen: i32) callconv(C) ?[*]u8 {
    if (maxlen <= 0) return null;
    const dest = buf orelse (malloc(@intCast(maxlen)) orelse return null);
    const rc = linux.getcwd(dest, @intCast(maxlen));
    if (linux.errno(rc) != .SUCCESS) {
        thread_errno = @intCast(@intFromEnum(linux.errno(rc)));
        return null;
    }
    return dest;
}

fn _umask(mask: i32) callconv(C) i32 {
    const rc = linux.syscall1(.umask, @as(usize, @intCast(mask & 0o777)));
    return @intCast(rc);
}

const LinuxStat = extern struct {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    __pad0: u32,
    st_rdev: u64,
    st_size: i64,
    st_blksize: i64,
    st_blocks: i64,
    st_atime: i64,
    st_atime_nsec: i64,
    st_mtime: i64,
    st_mtime_nsec: i64,
    st_ctime: i64,
    st_ctime_nsec: i64,
    __unused: [3]i64,
};

pub const StructStat64 = extern struct {
    st_dev: u32 = 0, // 0
    st_ino: u16 = 0, // 4
    st_mode: u16 = 0, // 6
    st_nlink: i16 = 1, // 8
    st_uid: i16 = 0, // 10
    st_gid: i16 = 0, // 12
    _pad0: u16 = 0, // 14
    st_rdev: u32 = 0, // 16
    _pad1: u32 = 0, // 20
    st_size: i64 = 0, // 24
    st_atime: i64 = 0, // 32
    st_mtime: i64 = 0, // 40
    st_ctime: i64 = 0, // 48
};

comptime {
    std.debug.assert(@sizeOf(StructStat64) == 56);
}

fn _fstat64(fd: i32, st_ptr: ?*StructStat64) callconv(C) i32 {
    const st = st_ptr orelse return -1;
    var kstat: LinuxStat = undefined;
    const rc = linux.syscall2(.fstat, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(&kstat));
    if (linux.errno(rc) != .SUCCESS) {
        thread_errno = @intCast(@intFromEnum(linux.errno(rc)));
        return -1;
    }
    st.* = .{
        .st_dev = @truncate(kstat.st_dev),
        .st_ino = @truncate(kstat.st_ino),
        .st_mode = @truncate(kstat.st_mode),
        .st_nlink = @truncate(@as(i64, @bitCast(kstat.st_nlink))),
        .st_uid = @truncate(@as(i32, @bitCast(kstat.st_uid))),
        .st_gid = @truncate(@as(i32, @bitCast(kstat.st_gid))),
        .st_rdev = @truncate(kstat.st_rdev),
        .st_size = kstat.st_size,
        .st_atime = kstat.st_atime,
        .st_mtime = kstat.st_mtime,
        .st_ctime = kstat.st_ctime,
    };
    return 0;
}

fn _fullpath(out_buf: ?[*]u8, rel_path: ?[*:0]const u8, max_len: usize) callconv(C) ?[*]u8 {
    const src = rel_path orelse return null;
    const dest = out_buf orelse (malloc(if (max_len == 0) 512 else max_len) orelse return null);
    var norm: [512:0]u8 = undefined;
    normalizePathA(src, &norm);
    if (norm[0] != '/') {
        var cwd: [512]u8 = undefined;
        const rc = linux.getcwd(&cwd, cwd.len);
        if (linux.errno(rc) == .SUCCESS) {
            const cwd_slice = std.mem.sliceTo(&cwd, 0);
            const norm_slice = std.mem.sliceTo(&norm, 0);
            const joined = std.fmt.bufPrint(dest[0..max_len], "{s}/{s}", .{ cwd_slice, norm_slice }) catch return null;
            dest[joined.len] = 0;
            return dest;
        }
    }
    const norm_slice = std.mem.sliceTo(&norm, 0);
    const copy_len = @min(norm_slice.len, if (max_len == 0) 511 else max_len - 1);
    @memcpy(dest[0..copy_len], norm_slice[0..copy_len]);
    dest[copy_len] = 0;
    return dest;
}

fn _mktemp(template: ?[*:0]u8) callconv(C) ?[*:0]u8 {
    const t = template orelse return null;
    var len = strlen(t);
    var xcount: usize = 0;
    while (len > 0 and t[len - 1] == 'X') {
        len -= 1;
        xcount += 1;
    }
    if (xcount == 0) return t;
    var val = rand();
    for (0..xcount) |i| {
        const ch: u8 = @intCast('a' + @mod(val, 26));
        t[len + i] = ch;
        val = @divFloor(val, 26) +% @as(i32, @bitCast(@as(u32, @truncate(i * 7 + 3))));
    }
    return t;
}

fn rename(old_path: ?[*:0]const u8, new_path: ?[*:0]const u8) callconv(C) i32 {
    const o = old_path orelse return -1;
    const n = new_path orelse return -1;
    var old_buf: [512:0]u8 = undefined;
    var new_buf: [512:0]u8 = undefined;
    normalizePathA(o, &old_buf);
    normalizePathA(n, &new_buf);
    const rc = linux.rename(&old_buf, &new_buf);
    if (linux.errno(rc) != .SUCCESS) {
        thread_errno = @intCast(@intFromEnum(linux.errno(rc)));
        return -1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// 7. Process, Signals & Environment
// ---------------------------------------------------------------------------

fn _getpid() callconv(C) i32 {
    return @intCast(linux.getpid());
}

fn _spawnve(mode: i32, cmdname: ?[*:0]const u8, argv: ?[*]const ?[*:0]const u8, envp: ?[*]const ?[*:0]const u8) callconv(C) isize {
    _ = mode;
    _ = cmdname;
    _ = argv;
    _ = envp;
    return -1;
}

var env_storage: [64][256:0]u8 = undefined;
var env_ptrs_dyn: [65]?[*:0]u8 = .{null} ** 65;
var env_initialized: bool = false;

fn initEnvironment() void {
    if (env_initialized) return;
    env_initialized = true;
    const fd = linux.open("/proc/self/environ", .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(fd) == .SUCCESS) {
        defer _ = linux.close(@intCast(fd));
        var buf: [4096]u8 = undefined;
        const rc = linux.read(@intCast(fd), &buf, buf.len);
        if (linux.errno(rc) == .SUCCESS and rc > 0) {
            var start: usize = 0;
            var idx: usize = 0;
            for (0..@intCast(rc)) |i| {
                if (buf[i] == 0) {
                    if (i > start and idx < 64) {
                        const len = @min(i - start, 255);
                        @memcpy(env_storage[idx][0..len], buf[start .. start + len]);
                        env_storage[idx][len] = 0;
                        env_ptrs_dyn[idx] = &env_storage[idx];
                        idx += 1;
                    }
                    start = i + 1;
                }
            }
            env_ptrs_dyn[idx] = null;
            msvcrt_environ = &env_ptrs_dyn;
            return;
        }
    }
    const def_env = [_][]const u8{
        "PATH=/usr/bin:/bin",
        "USER=user",
        "HOME=/tmp",
        "TMP=/tmp",
        "TEMP=/tmp",
    };
    for (def_env, 0..) |e, i| {
        @memcpy(env_storage[i][0..e.len], e);
        env_storage[i][e.len] = 0;
        env_ptrs_dyn[i] = &env_storage[i];
    }
    env_ptrs_dyn[def_env.len] = null;
    msvcrt_environ = &env_ptrs_dyn;
}

fn getenv(name: ?[*:0]const u8) callconv(C) ?[*:0]const u8 {
    initEnvironment();
    const key = name orelse return null;
    const key_len = strlen(key);
    var i: usize = 0;
    while (env_ptrs_dyn[i]) |entry| : (i += 1) {
        if (strncmp(entry, key, key_len) == 0 and entry[key_len] == '=') {
            return @ptrCast(entry + key_len + 1);
        }
    }
    return null;
}

fn _putenv(env_string: ?[*:0]const u8) callconv(C) i32 {
    initEnvironment();
    const s = env_string orelse return -1;
    const eq = strchr(s, '=') orelse return -1;
    const key_len = @intFromPtr(eq) - @intFromPtr(s);
    var i: usize = 0;
    while (env_ptrs_dyn[i]) |entry| : (i += 1) {
        if (strncmp(entry, s, key_len) == 0 and entry[key_len] == '=') {
            const copy_len = @min(strlen(s), 255);
            @memcpy(env_storage[i][0..copy_len], s[0..copy_len]);
            env_storage[i][copy_len] = 0;
            return 0;
        }
    }
    if (i < 64) {
        const copy_len = @min(strlen(s), 255);
        @memcpy(env_storage[i][0..copy_len], s[0..copy_len]);
        env_storage[i][copy_len] = 0;
        env_ptrs_dyn[i] = &env_storage[i];
        env_ptrs_dyn[i + 1] = null;
        return 0;
    }
    return -1;
}

// ---------------------------------------------------------------------------
// 8. Time & Clock
// ---------------------------------------------------------------------------

pub const StructTm = extern struct {
    tm_sec: i32 = 0,
    tm_min: i32 = 0,
    tm_hour: i32 = 0,
    tm_mday: i32 = 1,
    tm_mon: i32 = 0,
    tm_year: i32 = 70,
    tm_wday: i32 = 0,
    tm_yday: i32 = 0,
    tm_isdst: i32 = 0,
};

var global_tm: StructTm = .{};

fn fillTm(epoch: i64, tm: *StructTm) void {
    var rem = epoch;
    if (rem < 0) rem = 0;
    const sec = @mod(rem, 60);
    rem = @divFloor(rem, 60);
    const min = @mod(rem, 60);
    rem = @divFloor(rem, 60);
    const hour = @mod(rem, 24);
    var days = @divFloor(rem, 24);

    tm.tm_wday = @intCast(@mod(days + 4, 7));

    var year: i32 = 1970;
    while (true) {
        const leap = ((@mod(year, 4) == 0 and @mod(year, 100) != 0) or (@mod(year, 400) == 0));
        const days_in_year: i64 = if (leap) 366 else 365;
        if (days < days_in_year) break;
        days -= days_in_year;
        year += 1;
    }
    tm.tm_year = year - 1900;
    tm.tm_yday = @intCast(days);

    const leap = ((@mod(year, 4) == 0 and @mod(year, 100) != 0) or (@mod(year, 400) == 0));
    const month_days = [_]i32{ 31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    var mon: i32 = 0;
    while (mon < 12) : (mon += 1) {
        if (days < month_days[@intCast(mon)]) break;
        days -= month_days[@intCast(mon)];
    }
    tm.tm_mon = mon;
    tm.tm_mday = @intCast(days + 1);
    tm.tm_hour = @intCast(hour);
    tm.tm_min = @intCast(min);
    tm.tm_sec = @intCast(sec);
    tm.tm_isdst = 0;
}

fn _time64(timer: ?*i64) callconv(C) i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.REALTIME, &ts);
    const now: i64 = @intCast(ts.sec);
    if (timer) |t| t.* = now;
    return now;
}

fn _gmtime64(timer: ?*const i64) callconv(C) ?*StructTm {
    const t = timer orelse return null;
    fillTm(t.*, &global_tm);
    return &global_tm;
}

fn _localtime64(timer: ?*const i64) callconv(C) ?*StructTm {
    return _gmtime64(timer);
}

var ctime_buf: [32:0]u8 = undefined;

fn _ctime64(timer: ?*const i64) callconv(C) ?[*:0]const u8 {
    const tm = _localtime64(timer) orelse return null;
    const wdays = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    const wday_str = wdays[@min(@as(usize, @intCast(@max(0, tm.tm_wday))), 6)];
    const mon_str = months[@min(@as(usize, @intCast(@max(0, tm.tm_mon))), 11)];
    const res = std.fmt.bufPrint(&ctime_buf, "{s} {s} {d: >2} {d:0>2}:{d:0>2}:{d:0>2} {d}\n", .{
        wday_str,
        mon_str,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        tm.tm_year + 1900,
    }) catch return null;
    ctime_buf[res.len] = 0;
    return &ctime_buf;
}

fn _mktime64(timeptr: ?*StructTm) callconv(C) i64 {
    const tm = timeptr orelse return -1;
    var year = tm.tm_year + 1900;
    var mon = tm.tm_mon;
    if (mon >= 12) {
        year += @divFloor(mon, 12);
        mon = @mod(mon, 12);
    } else if (mon < 0) {
        year -= @divFloor(-mon + 11, 12);
        mon = 11 - @mod(-mon - 1, 12);
    }
    var days: i64 = 0;
    var y: i32 = 1970;
    while (y < year) : (y += 1) {
        const leap = ((@mod(y, 4) == 0 and @mod(y, 100) != 0) or (@mod(y, 400) == 0));
        days += if (leap) 366 else 365;
    }
    const leap = ((@mod(year, 4) == 0 and @mod(year, 100) != 0) or (@mod(year, 400) == 0));
    const month_days = [_]i64{ 31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    for (0..@intCast(mon)) |m| {
        days += month_days[m];
    }
    days += tm.tm_mday - 1;
    const secs = days * 86400 + @as(i64, tm.tm_hour) * 3600 + @as(i64, tm.tm_min) * 60 + @as(i64, tm.tm_sec);
    return secs;
}

fn strftime(s: ?[*]u8, maxsize: usize, format: ?[*:0]const u8, timeptr: ?*const StructTm) callconv(C) usize {
    const dest = s orelse return 0;
    const fmt = format orelse return 0;
    const tm = timeptr orelse return 0;
    if (maxsize == 0) return 0;

    var fi: usize = 0;
    var di: usize = 0;
    while (fmt[fi] != 0 and di + 1 < maxsize) {
        if (fmt[fi] != '%') {
            dest[di] = fmt[fi];
            di += 1;
            fi += 1;
            continue;
        }
        fi += 1;
        if (fmt[fi] == 0) break;
        var piece_buf: [64]u8 = undefined;
        var piece: []const u8 = "";
        switch (fmt[fi]) {
            '%' => piece = "%",
            'Y' => piece = std.fmt.bufPrint(&piece_buf, "{d:0>4}", .{tm.tm_year + 1900}) catch "",
            'y' => piece = std.fmt.bufPrint(&piece_buf, "{d:0>2}", .{@mod(tm.tm_year + 1900, 100)}) catch "",
            'm' => piece = std.fmt.bufPrint(&piece_buf, "{d:0>2}", .{tm.tm_mon + 1}) catch "",
            'd' => piece = std.fmt.bufPrint(&piece_buf, "{d:0>2}", .{tm.tm_mday}) catch "",
            'H' => piece = std.fmt.bufPrint(&piece_buf, "{d:0>2}", .{tm.tm_hour}) catch "",
            'M' => piece = std.fmt.bufPrint(&piece_buf, "{d:0>2}", .{tm.tm_min}) catch "",
            'S' => piece = std.fmt.bufPrint(&piece_buf, "{d:0>2}", .{tm.tm_sec}) catch "",
            else => {
                piece_buf[0] = fmt[fi];
                piece = piece_buf[0..1];
            },
        }
        fi += 1;
        for (piece) |b| {
            if (di + 1 >= maxsize) break;
            dest[di] = b;
            di += 1;
        }
    }
    dest[di] = 0;
    return di;
}

fn clock() callconv(C) i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.PROCESS_CPUTIME_ID, &ts);
    const ms = @as(i64, @intCast(ts.sec)) * 1000 + @divFloor(@as(i64, @intCast(ts.nsec)), 1_000_000);
    return ms;
}

fn _tzset() callconv(C) void {}

// ---------------------------------------------------------------------------
// 9. String, Memory & CType Functions
// ---------------------------------------------------------------------------

fn strlen(s: ?[*:0]const u8) callconv(C) usize {
    const p = s orelse return 0;
    var n: usize = 0;
    while (p[n] != 0) : (n += 1) {}
    return n;
}

fn wcslen(s: ?[*:0]const u16) callconv(C) usize {
    const p = s orelse return 0;
    var n: usize = 0;
    while (p[n] != 0) : (n += 1) {}
    return n;
}

fn strcmp(s1: ?[*:0]const u8, s2: ?[*:0]const u8) callconv(C) i32 {
    const a = s1 orelse return -1;
    const b = s2 orelse return 1;
    var i: usize = 0;
    while (a[i] != 0 and a[i] == b[i]) : (i += 1) {}
    return @as(i32, a[i]) - @as(i32, b[i]);
}

fn strncmp(s1: ?[*:0]const u8, s2: ?[*:0]const u8, n: usize) callconv(C) i32 {
    if (n == 0) return 0;
    const a = s1 orelse return -1;
    const b = s2 orelse return 1;
    var i: usize = 0;
    while (i + 1 < n and a[i] != 0 and a[i] == b[i]) : (i += 1) {}
    return @as(i32, a[i]) - @as(i32, b[i]);
}

fn strcspn(s: ?[*:0]const u8, reject: ?[*:0]const u8) callconv(C) usize {
    const a = s orelse return 0;
    const r = reject orelse return strlen(a);
    var i: usize = 0;
    while (a[i] != 0) : (i += 1) {
        var j: usize = 0;
        while (r[j] != 0) : (j += 1) {
            if (a[i] == r[j]) return i;
        }
    }
    return i;
}

fn strerror(errnum: i32) callconv(C) [*:0]const u8 {
    _ = errnum;
    return "Success";
}

fn memcpy(dest: ?[*]u8, src: ?[*]const u8, n: usize) callconv(C) ?[*]u8 {
    if (dest != null and src != null and n > 0) {
        @memcpy(dest.?[0..n], src.?[0..n]);
    }
    return dest;
}

fn memset(dest: ?[*]u8, c: i32, n: usize) callconv(C) ?[*]u8 {
    if (dest != null and n > 0) {
        @memset(dest.?[0..n], @intCast(c & 0xFF));
    }
    return dest;
}

fn isspace(c: i32) callconv(C) i32 {
    return switch (c) {
        ' ', '\t', '\n', '\r', 0x0b, 0x0c => 1,
        else => 0,
    };
}

fn isxdigit(c: i32) callconv(C) i32 {
    return switch (c) {
        '0'...'9', 'a'...'f', 'A'...'F' => 1,
        else => 0,
    };
}

fn tolower(c: i32) callconv(C) i32 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

fn toupper(c: i32) callconv(C) i32 {
    if (c >= 'a' and c <= 'z') return c - 32;
    return c;
}

fn isalnum(c: i32) callconv(C) i32 {
    return switch (c) {
        '0'...'9', 'a'...'z', 'A'...'Z' => 1,
        else => 0,
    };
}

fn isalpha(c: i32) callconv(C) i32 {
    return switch (c) {
        'a'...'z', 'A'...'Z' => 1,
        else => 0,
    };
}

fn iscntrl(c: i32) callconv(C) i32 {
    return if ((c >= 0 and c <= 0x1f) or c == 0x7f) 1 else 0;
}

fn isdigit(c: i32) callconv(C) i32 {
    return switch (c) {
        '0'...'9' => 1,
        else => 0,
    };
}

fn isgraph(c: i32) callconv(C) i32 {
    return if (c >= 0x21 and c <= 0x7e) 1 else 0;
}

fn islower(c: i32) callconv(C) i32 {
    return switch (c) {
        'a'...'z' => 1,
        else => 0,
    };
}

fn isprint(c: i32) callconv(C) i32 {
    return if (c >= 0x20 and c <= 0x7e) 1 else 0;
}

fn ispunct(c: i32) callconv(C) i32 {
    return if (isgraph(c) != 0 and isalnum(c) == 0) 1 else 0;
}

fn isupper(c: i32) callconv(C) i32 {
    return switch (c) {
        'A'...'Z' => 1,
        else => 0,
    };
}

fn _strdup(s: ?[*:0]const u8) callconv(C) ?[*:0]u8 {
    const str = s orelse return null;
    const len = strlen(str);
    const mem = malloc(len + 1) orelse return null;
    @memcpy(mem[0..len], str[0..len]);
    mem[len] = 0;
    return @ptrCast(mem);
}

fn _stricmp(s1: ?[*:0]const u8, s2: ?[*:0]const u8) callconv(C) i32 {
    const a = s1 orelse return -1;
    const b = s2 orelse return 1;
    var i: usize = 0;
    while (a[i] != 0 and b[i] != 0) : (i += 1) {
        const ca = tolower(a[i]);
        const cb = tolower(b[i]);
        if (ca != cb) return ca - cb;
    }
    return tolower(a[i]) - tolower(b[i]);
}

fn _strnicmp(s1: ?[*:0]const u8, s2: ?[*:0]const u8, n: usize) callconv(C) i32 {
    if (n == 0) return 0;
    const a = s1 orelse return -1;
    const b = s2 orelse return 1;
    var i: usize = 0;
    while (i < n and a[i] != 0 and b[i] != 0) : (i += 1) {
        const ca = tolower(a[i]);
        const cb = tolower(b[i]);
        if (ca != cb) return ca - cb;
    }
    if (i == n) return 0;
    return tolower(a[i]) - tolower(b[i]);
}

fn _wcsnicmp(s1: ?[*:0]const u16, s2: ?[*:0]const u16, n: usize) callconv(C) i32 {
    if (n == 0) return 0;
    const a = s1 orelse return -1;
    const b = s2 orelse return 1;
    var i: usize = 0;
    while (i < n and a[i] != 0 and b[i] != 0) : (i += 1) {
        const ca: i32 = if (a[i] >= 'A' and a[i] <= 'Z') a[i] + 32 else a[i];
        const cb: i32 = if (b[i] >= 'A' and b[i] <= 'Z') b[i] + 32 else b[i];
        if (ca != cb) return ca - cb;
    }
    if (i == n) return 0;
    const ca: i32 = if (a[i] >= 'A' and a[i] <= 'Z') a[i] + 32 else a[i];
    const cb: i32 = if (b[i] >= 'A' and b[i] <= 'Z') b[i] + 32 else b[i];
    return ca - cb;
}

fn wcscpy(dest: ?[*]u16, src: ?[*:0]const u16) callconv(C) ?[*]u16 {
    const d = dest orelse return null;
    const s = src orelse return null;
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {
        d[i] = s[i];
    }
    d[i] = 0;
    return d;
}

fn wcsncmp(s1: ?[*:0]const u16, s2: ?[*:0]const u16, n: usize) callconv(C) i32 {
    if (n == 0) return 0;
    const a = s1 orelse return -1;
    const b = s2 orelse return 1;
    var i: usize = 0;
    while (i < n and a[i] != 0 and a[i] == b[i]) : (i += 1) {}
    if (i == n) return 0;
    return @as(i32, a[i]) - @as(i32, b[i]);
}

fn strcpy(dest: ?[*]u8, src: ?[*:0]const u8) callconv(C) ?[*]u8 {
    const d = dest orelse return null;
    const s = src orelse return null;
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {
        d[i] = s[i];
    }
    d[i] = 0;
    return d;
}

fn strncpy(dest: ?[*]u8, src: ?[*]const u8, n: usize) callconv(C) ?[*]u8 {
    const d = dest orelse return null;
    const s = src orelse return null;
    var i: usize = 0;
    var hit_null = false;
    while (i < n) : (i += 1) {
        if (!hit_null and s[i] == 0) hit_null = true;
        d[i] = if (hit_null) 0 else s[i];
    }
    return d;
}

fn strcat(dest: ?[*]u8, src: ?[*:0]const u8) callconv(C) ?[*]u8 {
    const d = dest orelse return null;
    const s = src orelse return null;
    var len: usize = 0;
    while (d[len] != 0) : (len += 1) {}
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {
        d[len + i] = s[i];
    }
    d[len + i] = 0;
    return d;
}

fn strchr(s: ?[*:0]const u8, c: i32) callconv(C) ?[*:0]const u8 {
    const p = s orelse return null;
    const target: u8 = @intCast(c & 0xFF);
    var i: usize = 0;
    while (p[i] != 0) : (i += 1) {
        if (p[i] == target) return @ptrCast(p + i);
    }
    if (target == 0) return @ptrCast(p + i);
    return null;
}

fn strrchr(s: ?[*:0]const u8, c: i32) callconv(C) ?[*:0]const u8 {
    const p = s orelse return null;
    const target: u8 = @intCast(c & 0xFF);
    var last: ?usize = null;
    var i: usize = 0;
    while (p[i] != 0) : (i += 1) {
        if (p[i] == target) last = i;
    }
    if (target == 0) return @ptrCast(p + i);
    if (last) |idx| return @ptrCast(p + idx);
    return null;
}

fn strpbrk(s: ?[*:0]const u8, accept: ?[*:0]const u8) callconv(C) ?[*:0]const u8 {
    const p = s orelse return null;
    const acc = accept orelse return null;
    var i: usize = 0;
    while (p[i] != 0) : (i += 1) {
        var j: usize = 0;
        while (acc[j] != 0) : (j += 1) {
            if (p[i] == acc[j]) return @ptrCast(p + i);
        }
    }
    return null;
}

fn strspn(s: ?[*:0]const u8, accept: ?[*:0]const u8) callconv(C) usize {
    const p = s orelse return 0;
    const acc = accept orelse return 0;
    var i: usize = 0;
    while (p[i] != 0) : (i += 1) {
        var found = false;
        var j: usize = 0;
        while (acc[j] != 0) : (j += 1) {
            if (p[i] == acc[j]) {
                found = true;
                break;
            }
        }
        if (!found) break;
    }
    return i;
}

fn strstr(haystack: ?[*:0]const u8, needle: ?[*:0]const u8) callconv(C) ?[*:0]const u8 {
    const h = haystack orelse return null;
    const n = needle orelse return null;
    if (n[0] == 0) return h;
    var i: usize = 0;
    while (h[i] != 0) : (i += 1) {
        var j: usize = 0;
        while (n[j] != 0 and h[i + j] == n[j]) : (j += 1) {}
        if (n[j] == 0) return @ptrCast(h + i);
    }
    return null;
}

var strtok_saved: ?[*:0]u8 = null;

fn strtok(str: ?[*:0]u8, delim: ?[*:0]const u8) callconv(C) ?[*:0]u8 {
    const d = delim orelse return null;
    var s = str orelse (strtok_saved orelse return null);
    while (s[0] != 0) {
        var is_d = false;
        var di: usize = 0;
        while (d[di] != 0) : (di += 1) {
            if (s[0] == d[di]) {
                is_d = true;
                break;
            }
        }
        if (!is_d) break;
        s += 1;
    }
    if (s[0] == 0) {
        strtok_saved = null;
        return null;
    }
    const token_start = s;
    while (s[0] != 0) {
        var is_d = false;
        var di: usize = 0;
        while (d[di] != 0) : (di += 1) {
            if (s[0] == d[di]) {
                is_d = true;
                break;
            }
        }
        if (is_d) {
            s[0] = 0;
            strtok_saved = s + 1;
            return token_start;
        }
        s += 1;
    }
    strtok_saved = null;
    return token_start;
}

fn memchr(s: ?[*]const u8, c: i32, n: usize) callconv(C) ?[*]const u8 {
    const p = s orelse return null;
    const target: u8 = @intCast(c & 0xFF);
    for (0..n) |i| {
        if (p[i] == target) return p + i;
    }
    return null;
}

fn memcmp(s1: ?[*]const u8, s2: ?[*]const u8, n: usize) callconv(C) i32 {
    if (n == 0) return 0;
    const a = s1 orelse return -1;
    const b = s2 orelse return 1;
    for (0..n) |i| {
        if (a[i] != b[i]) return @as(i32, a[i]) - @as(i32, b[i]);
    }
    return 0;
}

fn memmove(dest: ?[*]u8, src: ?[*]const u8, n: usize) callconv(C) ?[*]u8 {
    const d = dest orelse return null;
    const s = src orelse return null;
    if (n == 0 or d == s) return d;
    const d_addr = @intFromPtr(d);
    const s_addr = @intFromPtr(s);
    if (d_addr < s_addr) {
        for (0..n) |i| d[i] = s[i];
    } else {
        var i = n;
        while (i > 0) {
            i -= 1;
            d[i] = s[i];
        }
    }
    return d;
}

fn parseUnsigned(s_opt: ?[*:0]const u8, endptr: ?*?[*:0]const u8, base_in: i32, neg_out: *bool) u64 {
    neg_out.* = false;
    const s = s_opt orelse {
        if (endptr) |ep| ep.* = null;
        return 0;
    };
    var i: usize = 0;
    while (isspace(s[i]) != 0) : (i += 1) {}
    const sign_start = i;
    if (s[i] == '-') {
        neg_out.* = true;
        i += 1;
    } else if (s[i] == '+') {
        i += 1;
    }
    var base: u32 = if (base_in < 0 or base_in == 1 or base_in > 36) 10 else @intCast(base_in);
    if (base == 0) {
        if (s[i] == '0') {
            if (s[i + 1] == 'x' or s[i + 1] == 'X') {
                base = 16;
                i += 2;
            } else {
                base = 8;
                i += 1;
            }
        } else {
            base = 10;
        }
    } else if (base == 16 and s[i] == '0' and (s[i + 1] == 'x' or s[i + 1] == 'X')) {
        i += 2;
    }

    var acc: u64 = 0;
    var any = false;
    while (s[i] != 0) : (i += 1) {
        const ch = s[i];
        const digit: u32 = if (ch >= '0' and ch <= '9')
            ch - '0'
        else if (ch >= 'a' and ch <= 'z')
            ch - 'a' + 10
        else if (ch >= 'A' and ch <= 'Z')
            ch - 'A' + 10
        else
            break;
        if (digit >= base) break;
        any = true;
        acc = acc *| base +| digit;
    }
    if (endptr) |ep| {
        const end_idx = if (any) i else sign_start;
        ep.* = @ptrCast(s + end_idx);
    }
    return acc;
}

fn _strtoui64(s: ?[*:0]const u8, endptr: ?*?[*:0]const u8, base: i32) callconv(C) u64 {
    var neg = false;
    const val = parseUnsigned(s, endptr, base, &neg);
    return if (neg) 0 -% val else val;
}

fn _strtoi64(s: ?[*:0]const u8, endptr: ?*?[*:0]const u8, base: i32) callconv(C) i64 {
    var neg = false;
    const val = parseUnsigned(s, endptr, base, &neg);
    if (neg) return -@as(i64, @intCast(@min(val, @as(u64, @intCast(std.math.maxInt(i64))))));
    return @intCast(@min(val, @as(u64, @intCast(std.math.maxInt(i64)))));
}

fn strtoul(s: ?[*:0]const u8, endptr: ?*?[*:0]const u8, base: i32) callconv(C) u32 {
    return @truncate(_strtoui64(s, endptr, base));
}

fn strtol(s: ?[*:0]const u8, endptr: ?*?[*:0]const u8, base: i32) callconv(C) i32 {
    return @truncate(_strtoi64(s, endptr, base));
}

fn atoi(s: ?[*:0]const u8) callconv(C) i32 {
    return strtol(s, null, 10);
}

fn atof(s: ?[*:0]const u8) callconv(C) f64 {
    const p = s orelse return 0.0;
    var i: usize = 0;
    while (isspace(p[i]) != 0) : (i += 1) {}
    var neg = false;
    if (p[i] == '-') {
        neg = true;
        i += 1;
    } else if (p[i] == '+') {
        i += 1;
    }
    var val: f64 = 0.0;
    while (p[i] >= '0' and p[i] <= '9') : (i += 1) {
        val = val * 10.0 + @as(f64, @floatFromInt(p[i] - '0'));
    }
    if (p[i] == '.') {
        i += 1;
        var div: f64 = 10.0;
        while (p[i] >= '0' and p[i] <= '9') : (i += 1) {
            val += @as(f64, @floatFromInt(p[i] - '0')) / div;
            div *= 10.0;
        }
    }
    if (p[i] == 'e' or p[i] == 'E') {
        i += 1;
        var exp_neg = false;
        if (p[i] == '-') {
            exp_neg = true;
            i += 1;
        } else if (p[i] == '+') {
            i += 1;
        }
        var exp_val: i32 = 0;
        while (p[i] >= '0' and p[i] <= '9') : (i += 1) {
            exp_val = exp_val * 10 + (p[i] - '0');
        }
        var factor: f64 = 1.0;
        for (0..@intCast(exp_val)) |_| factor *= 10.0;
        if (exp_neg) val /= factor else val *= factor;
    }
    return if (neg) -val else val;
}

var rand_next: u64 = 1;

fn rand() callconv(C) i32 {
    rand_next = rand_next *% 214013 +% 2531011;
    return @as(i32, @bitCast(@as(u32, @truncate((rand_next >> 16) & 0x7fff))));
}

fn srand(seed: u32) callconv(C) void {
    rand_next = seed;
}

fn bsearch(
    key: ?*const anyopaque,
    base: ?[*]const u8,
    nmemb: usize,
    size: usize,
    compar: ?*const fn (?*const anyopaque, ?*const anyopaque) callconv(C) i32,
) callconv(C) ?*const anyopaque {
    const k = key orelse return null;
    const b = base orelse return null;
    const cmp = compar orelse return null;
    if (nmemb == 0 or size == 0) return null;
    var low: usize = 0;
    var high: usize = nmemb;
    while (low < high) {
        const mid = low + (high - low) / 2;
        const elem = b + (mid * size);
        const res = cmp(k, elem);
        if (res == 0) return elem;
        if (res < 0) {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    return null;
}

fn qsort(
    base: ?[*]u8,
    nmemb: usize,
    size: usize,
    compar: ?*const fn (?*const anyopaque, ?*const anyopaque) callconv(C) i32,
) callconv(C) void {
    const b = base orelse return;
    const cmp = compar orelse return;
    if (nmemb < 2 or size == 0) return;
    var tmp_buf: [256]u8 = undefined;
    const tmp = if (size <= tmp_buf.len) tmp_buf[0..size] else (malloc(size) orelse return)[0..size];
    var i: usize = 1;
    while (i < nmemb) : (i += 1) {
        const cur = b + (i * size);
        @memcpy(tmp, cur[0..size]);
        var j = i;
        while (j > 0) {
            const prev = b + ((j - 1) * size);
            if (cmp(prev, tmp.ptr) <= 0) break;
            @memcpy(b + (j * size), prev[0..size]);
            j -= 1;
        }
        @memcpy(b + (j * size), tmp);
    }
}

fn ldexp(x: f64, exp: i32) callconv(C) f64 {
    return std.math.scalbn(x, exp);
}

// ---------------------------------------------------------------------------
// 10. Formatting & Scanning
// ---------------------------------------------------------------------------

fn vsnprintf_impl(buf: ?[*]u8, count: usize, fmt: ?[*:0]const u8, ap_raw: ?[*]const usize) i32 {
    const f = fmt orelse return -1;
    var arg_idx: usize = 0;
    var out_pos: usize = 0;

    var fi: usize = 0;
    while (f[fi] != 0) {
        if (f[fi] != '%') {
            if (buf != null and out_pos < count) {
                buf.?[out_pos] = f[fi];
            }
            out_pos += 1;
            fi += 1;
            continue;
        }
        fi += 1; // skip '%'
        if (f[fi] == '%') {
            if (buf != null and out_pos < count) {
                buf.?[out_pos] = '%';
            }
            out_pos += 1;
            fi += 1;
            continue;
        }

        var left_align = false;
        var zero_pad = false;
        while (true) {
            if (f[fi] == '-') {
                left_align = true;
                fi += 1;
            } else if (f[fi] == '0' and !left_align) {
                zero_pad = true;
                fi += 1;
            } else {
                break;
            }
        }

        var width: usize = 0;
        if (f[fi] == '*') {
            fi += 1;
            const w_arg: i32 = if (ap_raw) |ap| blk: {
                const v: i32 = @truncate(@as(isize, @bitCast(ap[arg_idx])));
                arg_idx += 1;
                break :blk v;
            } else 0;
            if (w_arg < 0) {
                left_align = true;
                width = @intCast(-w_arg);
            } else {
                width = @intCast(w_arg);
            }
        } else {
            while (f[fi] >= '0' and f[fi] <= '9') : (fi += 1) {
                width = width * 10 + (f[fi] - '0');
            }
        }

        var prec: ?usize = null;
        if (f[fi] == '.') {
            fi += 1;
            if (f[fi] == '*') {
                fi += 1;
                const p_arg: i32 = if (ap_raw) |ap| blk: {
                    const v: i32 = @truncate(@as(isize, @bitCast(ap[arg_idx])));
                    arg_idx += 1;
                    break :blk v;
                } else 0;
                if (p_arg >= 0) prec = @intCast(p_arg);
            } else {
                var p: usize = 0;
                while (f[fi] >= '0' and f[fi] <= '9') : (fi += 1) {
                    p = p * 10 + (f[fi] - '0');
                }
                prec = p;
            }
        }

        var is_long = false;
        while (f[fi] == 'l' or f[fi] == 'z' or f[fi] == 'I' or f[fi] == 'h') : (fi += 1) {
            if (f[fi] != 'h') is_long = true;
        }

        const spec = f[fi];
        if (spec != 0) fi += 1;
        const arg_val: usize = if (ap_raw) |ap| blk: {
            const v = ap[arg_idx];
            arg_idx += 1;
            break :blk v;
        } else 0;

        var tmp: [64]u8 = undefined;
        var piece: []const u8 = "";

        switch (spec) {
            's' => {
                if (arg_val == 0) {
                    piece = "(null)";
                } else {
                    const cstr: [*:0]const u8 = @ptrFromInt(arg_val);
                    piece = std.mem.span(cstr);
                    if (prec) |pr| {
                        piece = piece[0..@min(piece.len, pr)];
                    }
                }
            },
            'c' => {
                tmp[0] = @intCast(arg_val & 0xFF);
                piece = tmp[0..1];
            },
            'd', 'i' => {
                const sval: i64 = if (is_long) @as(i64, @bitCast(@as(u64, arg_val))) else @as(i64, @as(i32, @truncate(@as(isize, @bitCast(arg_val)))));
                piece = std.fmt.bufPrint(&tmp, "{d}", .{sval}) catch "";
            },
            'u' => {
                const uval: u64 = if (is_long) arg_val else @as(u32, @truncate(arg_val));
                piece = std.fmt.bufPrint(&tmp, "{d}", .{uval}) catch "";
            },
            'x', 'p' => {
                piece = std.fmt.bufPrint(&tmp, "{x}", .{arg_val}) catch "";
            },
            'X' => {
                piece = std.fmt.bufPrint(&tmp, "{X}", .{arg_val}) catch "";
            },
            'o' => {
                piece = std.fmt.bufPrint(&tmp, "{o}", .{arg_val}) catch "";
            },
            else => {},
        }

        const pad_len = if (width > piece.len) width - piece.len else 0;
        const pad_ch: u8 = if (zero_pad and !left_align) '0' else ' ';

        if (!left_align and pad_len > 0) {
            for (0..pad_len) |_| {
                if (buf != null and out_pos < count) buf.?[out_pos] = pad_ch;
                out_pos += 1;
            }
        }
        for (piece) |ch| {
            if (buf != null and out_pos < count) buf.?[out_pos] = ch;
            out_pos += 1;
        }
        if (left_align and pad_len > 0) {
            for (0..pad_len) |_| {
                if (buf != null and out_pos < count) buf.?[out_pos] = ' ';
                out_pos += 1;
            }
        }
    }

    if (buf != null and count > 0) {
        if (out_pos < count) {
            buf.?[out_pos] = 0;
        } else {
            buf.?[count - 1] = 0;
        }
    }
    return @intCast(out_pos);
}

fn _vsnprintf(buf: ?[*]u8, count: usize, fmt: ?[*:0]const u8, ap_raw: ?[*]const usize) callconv(C) i32 {
    return vsnprintf_impl(buf, count, fmt, ap_raw);
}

fn _vscprintf(fmt: ?[*:0]const u8, ap_raw: ?[*]const usize) callconv(C) i32 {
    return vsnprintf_impl(null, 0, fmt, ap_raw);
}

fn sprintf(buf: ?[*]u8, fmt: ?[*:0]const u8, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize) callconv(C) i32 {
    const args = [_]usize{ a1, a2, a3, a4, a5, a6, a7, a8 };
    return vsnprintf_impl(buf, 4096, fmt, &args);
}

fn vfprintf(stream: ?*MsvcrtFile, fmt: ?[*:0]const u8, ap_raw: ?[*]const usize) callconv(C) i32 {
    if (stream == null or fmt == null) return -1;
    var out_buf: [4096]u8 = undefined;
    const len = vsnprintf_impl(&out_buf, out_buf.len, fmt, ap_raw);
    if (len > 0) {
        const ulen: usize = @intCast(len);
        _ = fwrite(&out_buf, 1, @min(ulen, out_buf.len), stream);
    }
    return len;
}

fn fprintf(stream: ?*MsvcrtFile, fmt: ?[*:0]const u8, a1: usize, a2: usize, a3: usize, a4: usize) callconv(C) i32 {
    const args = [_]usize{ a1, a2, a3, a4 };
    return vfprintf(stream, fmt, &args);
}

fn printf(fmt: ?[*:0]const u8, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize) callconv(C) i32 {
    const args = [_]usize{ a1, a2, a3, a4, a5, a6, a7, a8 };
    return vfprintf(&iob_table[1], fmt, &args);
}

fn puts(s: ?[*:0]const u8) callconv(C) i32 {
    const str = s orelse return -1;
    const len = strlen(str);
    if (fwrite(str, 1, len, &iob_table[1]) != len) return -1;
    const nl = [_]u8{'\n'};
    if (fwrite(&nl, 1, 1, &iob_table[1]) != 1) return -1;
    return 0;
}

fn sscanf(str: ?[*:0]const u8, fmt: ?[*:0]const u8, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize) callconv(C) i32 {
    const s = str orelse return -1;
    const f = fmt orelse return -1;
    const args = [_]usize{ a1, a2, a3, a4, a5, a6, a7, a8 };
    var arg_idx: usize = 0;
    var matched: i32 = 0;

    var si: usize = 0;
    var fi: usize = 0;

    while (f[fi] != 0 and s[si] != 0) {
        if (isspace(f[fi]) != 0) {
            while (isspace(f[fi]) != 0) : (fi += 1) {}
            while (isspace(s[si]) != 0) : (si += 1) {}
            continue;
        }
        if (f[fi] != '%') {
            if (f[fi] != s[si]) break;
            fi += 1;
            si += 1;
            continue;
        }
        fi += 1; // skip '%'
        if (f[fi] == '%') {
            if (s[si] != '%') break;
            fi += 1;
            si += 1;
            continue;
        }
        if (arg_idx >= args.len) break;
        const target_ptr = args[arg_idx];
        arg_idx += 1;

        if (f[fi] != 'c') {
            while (isspace(s[si]) != 0) : (si += 1) {}
        }

        var is_long = false;
        while (f[fi] == 'l' or f[fi] == 'z' or f[fi] == 'h') : (fi += 1) {
            if (f[fi] != 'h') is_long = true;
        }

        const spec = f[fi];
        if (spec != 0) fi += 1;

        switch (spec) {
            'd', 'i' => {
                var endptr: ?[*:0]const u8 = null;
                var neg = false;
                const val = parseUnsigned(@ptrCast(s + si), &endptr, 10, &neg);
                if (endptr) |ep| {
                    const consumed = @intFromPtr(ep) - @intFromPtr(s + si);
                    if (consumed == 0) break;
                    si += consumed;
                    if (is_long) {
                        const ptr: *i64 = @ptrFromInt(target_ptr);
                        ptr.* = if (neg) -@as(i64, @intCast(val)) else @as(i64, @intCast(val));
                    } else {
                        const ptr: *i32 = @ptrFromInt(target_ptr);
                        const uval: u32 = @truncate(val);
                        ptr.* = if (neg) -@as(i32, @bitCast(uval)) else @as(i32, @bitCast(uval));
                    }
                    matched += 1;
                }
            },
            'u' => {
                var endptr: ?[*:0]const u8 = null;
                var neg = false;
                const val = parseUnsigned(@ptrCast(s + si), &endptr, 10, &neg);
                if (endptr) |ep| {
                    const consumed = @intFromPtr(ep) - @intFromPtr(s + si);
                    if (consumed == 0) break;
                    si += consumed;
                    if (is_long) {
                        const ptr: *u64 = @ptrFromInt(target_ptr);
                        ptr.* = val;
                    } else {
                        const ptr: *u32 = @ptrFromInt(target_ptr);
                        ptr.* = @truncate(val);
                    }
                    matched += 1;
                }
            },
            'x', 'X' => {
                var endptr: ?[*:0]const u8 = null;
                var neg = false;
                const val = parseUnsigned(@ptrCast(s + si), &endptr, 16, &neg);
                if (endptr) |ep| {
                    const consumed = @intFromPtr(ep) - @intFromPtr(s + si);
                    if (consumed == 0) break;
                    si += consumed;
                    const ptr: *u32 = @ptrFromInt(target_ptr);
                    ptr.* = @truncate(val);
                    matched += 1;
                }
            },
            's' => {
                const dest: [*]u8 = @ptrFromInt(target_ptr);
                var di: usize = 0;
                while (s[si] != 0 and isspace(s[si]) == 0) : (si += 1) {
                    dest[di] = s[si];
                    di += 1;
                }
                dest[di] = 0;
                if (di > 0) matched += 1;
            },
            'c' => {
                const dest: [*]u8 = @ptrFromInt(target_ptr);
                dest[0] = s[si];
                si += 1;
                matched += 1;
            },
            else => {},
        }
    }
    return matched;
}

// ---------------------------------------------------------------------------
// 11. Setjmp & Longjmp
// ---------------------------------------------------------------------------

pub fn _setjmp_impl() callconv(.naked) void {
    // i386 is deliberately unimplemented: the x86 jmp_buf layout (the
    // Registration/TryLevel C++-EH fields included) is not verified here.
    // lookup() does not export this on 32-bit, so a guest importing it shows up
    // as UNRESOLVED instead of silently corrupting a stack.
    if (@sizeOf(usize) != 8) asm volatile ("xorl %%eax, %%eax\x0a\x09ret");
    asm volatile (
        \\ movq %%rdx, 0x00(%%rcx)
        \\ movq %%rbx, 0x08(%%rcx)
        \\ leaq 8(%%rsp), %%rax
        \\ movq %%rax, 0x10(%%rcx)
        \\ movq %%rbp, 0x18(%%rcx)
        \\ movq %%rsi, 0x20(%%rcx)
        \\ movq %%rdi, 0x28(%%rcx)
        \\ movq %%r12, 0x30(%%rcx)
        \\ movq %%r13, 0x38(%%rcx)
        \\ movq %%r14, 0x40(%%rcx)
        \\ movq %%r15, 0x48(%%rcx)
        \\ movq (%%rsp), %%rax
        \\ movq %%rax, 0x50(%%rcx)
        \\ xorl %%eax, %%eax
        \\ ret
    );
}

pub fn longjmp_impl() callconv(.naked) void {
    if (@sizeOf(usize) != 8) asm volatile ("ret");
    asm volatile (
        \\ movl %%edx, %%eax
        \\ testl %%eax, %%eax
        \\ jnz 1f
        \\ movl $1, %%eax
        \\ 1:
        \\ movq 0x08(%%rcx), %%rbx
        \\ movq 0x10(%%rcx), %%rsp
        \\ movq 0x18(%%rcx), %%rbp
        \\ movq 0x20(%%rcx), %%rsi
        \\ movq 0x28(%%rcx), %%rdi
        \\ movq 0x30(%%rcx), %%r12
        \\ movq 0x38(%%rcx), %%r13
        \\ movq 0x40(%%rcx), %%r14
        \\ movq 0x48(%%rcx), %%r15
        \\ movq 0x50(%%rcx), %%r8
        \\ jmp *%%r8
    );
}

// ============================================================================
// 13. CRT startup / C++-EH surface a real MSVCRT-linked console PE needs
//
// These are the imports 7zr.exe (a genuine MSVCRT 6.0 console image) needs and
// the module did not yet provide. Each documents what it does NOT do.
// ============================================================================

/// _controlfp(new, mask). The x87 control word is not emulated: report the
/// default (RC-nearest, 64-bit precision, all exceptions masked) and never
/// actually change it. Callers that only test flags get a sane answer.
fn _controlfp(newv: i32, maskv: i32) callconv(C) i32 {
    _ = newv;
    _ = maskv;
    return 0x0009001f;
}

fn _clearfp() callconv(C) i32 {
    return 0x0009001f;
}

/// Pentium-era fdiv rounding bug. There is no fdiv bug on a real FPU, so this
/// is a no-op rather than a trap emulation.
fn _adjust_fdiv(fpu_env: ?*const anyopaque) callconv(C) void {
    _ = fpu_env;
}

/// __CxxFrameHandler and _except_handler3 returning EXCEPTION_CONTINUE_SEARCH
/// ("not mine") is the one answer that cannot misroute an exception into a
/// fabricated disposition. The full SEH-based C++ EH is NOT implemented.
/// MSVC's __CxxFrameHandler3 thunk is `mov $pFuncInfo, %%eax; jmp *__CxxFrameHandler`.
/// The FuncInfo therefore arrives in EAX, not on the stack -- a shim that only
/// reads its four pointer parameters never sees which function it is filtering
/// for, which is why every frame answered EXCEPTION_CONTINUE_SEARCH.
fn __CxxFrameHandler(rec: ?*const anyopaque, frame: ?*anyopaque, ctx: ?*anyopaque, disp: ?*const anyopaque) callconv(C) i32 {
    var func_info: usize = 0;
    if (@import("builtin").cpu.arch != .x86) return 0;
    asm volatile ("movl %%eax, %[o]"
        : [o] "=r" (func_info),
    );
    if (trace_static_init and func_info > 0x400000 and func_info < 0x4a2000) {
        // MSVC FuncInfo: magic, maxState, pUnwindMap, nTryBlocks, pTryMap,
        // nIPMapEntries, pIPMap, EHFlags.
        const fi = func_info;
        const magic: u32 = @as(*const u32, @ptrFromInt(fi)).*;
        const max_state: u32 = @as(*const u32, @ptrFromInt(fi + 4)).*;
        const p_unwind: usize = @as(*const usize, @ptrFromInt(fi + 8)).*;
        const n_try: u32 = @as(*const u32, @ptrFromInt(fi + 12)).*;
        const p_try: usize = @as(*const usize, @ptrFromInt(fi + 16)).*;
        const n_ip: u32 = @as(*const u32, @ptrFromInt(fi + 20)).*;
        const p_ip: usize = @as(*const usize, @ptrFromInt(fi + 24)).*;
        std.debug.print("[eh]   FuncInfo@0x{x}: magic=0x{x:0>8} maxState={d} nTry={d} pTry=0x{x} nIP={d} pIP=0x{x} pUnwind=0x{x}\n", .{ fi, magic, max_state, n_try, p_try, n_ip, p_ip, p_unwind });
        if (n_try > 0 and p_try > 0x400000) {
            var i: u32 = 0;
            while (i < n_try and i < 8) : (i += 1) {
                const e = p_try + i * 20;
                const try_low: u32 = @as(*const u32, @ptrFromInt(e)).*;
                const try_high: u32 = @as(*const u32, @ptrFromInt(e + 4)).*;
                const catch_high: u32 = @as(*const u32, @ptrFromInt(e + 8)).*;
                const handler: usize = @as(*const usize, @ptrFromInt(e + 12)).*;
                std.debug.print("[eh]     try[{d}]: tryLow={d} tryHigh={d} catchHigh={d} handler=0x{x}\n", .{ i, try_low, try_high, catch_high, handler });
            }
        }
    }
    if (trace_static_init) {
        std.debug.print("[eh] __CxxFrameHandler(rec=0x{x}, frame=0x{x}, ctx=0x{x}, disp=0x{x})\n", .{
            @intFromPtr(rec), @intFromPtr(frame), @intFromPtr(ctx), @intFromPtr(disp),
        });
        if (rec) |r| {
            const er: *const ExceptionRecord = @ptrCast(@alignCast(r));
            std.debug.print("[eh]   code=0x{x:0>8} nparams={d} info[0]=0x{x:0>8} info[1]=0x{x:0>8} info[2]=0x{x:0>8}\n", .{
                er.exception_code, er.number_parameters,
                er.exception_information[0], er.exception_information[1], er.exception_information[2],
            });
        }
        if (disp) |d| {
            const words: [*]const usize = @ptrCast(@alignCast(d));
            std.debug.print("[eh]   DispatcherContext[0..11]:", .{});
            var k: usize = 0;
            while (k < 12) : (k += 1) std.debug.print(" 0x{x:0>8}", .{words[k]});
            std.debug.print("\n", .{});
        }
        if (frame) |f| {
            const w: [*]const usize = @ptrCast(@alignCast(f));
            var i: usize = 0;
            std.debug.print("[eh]   frame[0..10]:", .{});
            while (i < 10) : (i += 1) std.debug.print(" 0x{x:0>8}", .{w[i]});
            std.debug.print("\n", .{});
        }
    }

    // M3-A: decide, do not stub. The FuncInfo arrives in EAX; the frame's current
    // state is the word at node+8 (measured: frame 1 holds 1, and its FuncInfo
    // says tryLow=1/tryHigh=1 -- an exact match, not a coincidence).
    if (func_info > 0x400000 and func_info < 0x4a2000) {
        const n_try: u32 = @as(*const u32, @ptrFromInt(func_info + 12)).*;
        const p_try: usize = @as(*const usize, @ptrFromInt(func_info + 16)).*;
        const nd = @intFromPtr(frame.?);
        if (trace_static_init) {
            std.debug.print("[eh]   node 0x{x} words:", .{nd});
            var z: usize = 0;
            while (z < 8) : (z += 1) std.debug.print(" [{d}]=0x{x:0>8}", .{ z, @as(*const usize, @ptrFromInt(nd + z * 4)).* });
            std.debug.print("\n", .{});
        }
        const state: i32 = @as(*const i32, @ptrFromInt(nd + 8)).*;
        if (trace_static_init) {
            std.debug.print("[eh]   decide: state={d} nTry={d} pTry=0x{x} maxState={d}\n", .{ state, n_try, p_try, @as(*const u32, @ptrFromInt(func_info + 4)).* });
        }
        if (n_try > 0 and p_try > 0x400000) {
            var e: u32 = 0;
            while (e < n_try and e < 4) : (e += 1) {
                const m = p_try + e * 20;
                const try_low: i32 = @as(*const i32, @ptrFromInt(m)).*;
                const try_high: i32 = @as(*const i32, @ptrFromInt(m + 4)).*;
                const catch_high: i32 = @as(*const i32, @ptrFromInt(m + 8)).*;
                if (trace_static_init) {
                    std.debug.print("[eh]     try[{d}]: [{d}..{d}] catchHigh={d}\n", .{ e, try_low, try_high, catch_high });
                }
                // Inside the try body the catch applies. catchHigh covers the
                // handler body itself, i.e. already unwinding, so it is excluded.
                if (state >= try_low and state <= try_high) {
                    // CatchHandlerType array: TryBlockMapEntry+16 -> pCatch,
                    // then entry+12 -> pHandler (measured on 7zr frame 1:
                    // pCatch=0x489eb0, handler=0x43d8cf, which is code that
                    // prints the message and does `push $0x7; jmp` = exit 7,
                    // matching Wine exactly).
                    const p_catch: usize = @as(*const usize, @ptrFromInt(m + 16)).*;
                    if (p_catch > 0x400000 and p_catch < 0x4a2000) {
                        const h: usize = @as(*const usize, @ptrFromInt(p_catch + 12)).*;
                        if (h > 0x400000 and h < 0x4a2000) {
                            // CatchHandlerType is {adjectives, pType, dispOfHandler,
                            // pHandler}: dispOfHandler is where the caught object goes
                            // (relative to the frame's EBP) and pHandler is the catch
                            // code. Entry 0 of this binary has dispOfHandler 0 and a
                            // handler whose global is "ERROR: Can't allocate required
                            // memory!" -> exit 8; entry 1 has dispOfHandler -0x20 and
                            // handler 0x43d8e0 -> prints "Command Line Error:" and exits
                            // 7, which is Wine's behaviour. So the entry must be matched
                            // by exception type, not taken as entry 0.
                            accept_handler = h;
                            // Match the catch entry by exception type and place the
                            // object where dispOfHandler says. Without this the
                            // catch reads an empty slot and the message is wrong.
                            const n_catches: u32 = @as(*const u32, @ptrFromInt(m + 12)).*;
                            const p_catch_arr: usize = @as(*const usize, @ptrFromInt(m + 16)).*;
                            var thrown_type: usize = 0;
                            var thrown_obj: usize = 0;
                            if (rec) |r| {
                                const er: *const ExceptionRecord = @ptrCast(@alignCast(r));
                                thrown_obj = er.exception_information[1];
                                if (er.number_parameters >= 3 and er.exception_information[2] > 0x400000) {
                                    const cta: usize = @as(*const usize, @ptrFromInt(er.exception_information[2] + 12)).*;
                                    if (cta > 0x400000 and cta < 0x4a2000) {
                                        const ct0: usize = @as(*const usize, @ptrFromInt(cta + 4)).*;
                                        if (ct0 > 0x400000 and ct0 < 0x4a2000) {
                                            thrown_type = @as(*const usize, @ptrFromInt(ct0 + 4)).*;
                                        }
                                    }
                                }
                            }
                            if (p_catch_arr > 0x400000 and p_catch_arr < 0x4a2000) {
                                var ci: u32 = 0;
                                while (ci < n_catches and ci < 12) : (ci += 1) {
                                    const ce = p_catch_arr + ci * 16;
                                    const e_type: usize = @as(*const usize, @ptrFromInt(ce + 4)).*;
                                    const e_disp: i32 = @as(*const i32, @ptrFromInt(ce + 8)).*;
                                    const e_handler: usize = @as(*const usize, @ptrFromInt(ce + 12)).*;
                                    if (e_handler < 0x400000 or e_handler >= 0x4a2000) continue;
                                    if (thrown_type != 0 and e_type == thrown_type) {
                                        accept_handler = e_handler;
                                        if (ctx) |c| {
                                            const g: *const GuestContext = @ptrCast(@alignCast(c));
                                            var f: usize = g.ebp;
                                            var hops: usize = 0;
                                            while (f > 0x1000 and f < 0xFFFFF000 and hops < 16) : (hops += 1) {
                                                if (f > @intFromPtr(frame.?)) {
                                                    accept_ebp = f;
                                                    break;
                                                }
                                                const nx: usize = @as(*const usize, @ptrFromInt(f)).*;
                                                if (nx <= 0x1000 or nx >= 0xFFFFF000 or nx <= f) break;
                                                f = nx;
                                            }
                                            const slot = @as(usize, @intCast(@as(isize, @intCast(accept_ebp)) + e_disp));
                                            if (accept_ebp != 0 and slot > 0x1000 and slot < 0xFFFFF000) {
                                                // The slot takes the exception OBJECT, not the frame: the
                                                // funclet does `mov -0x20(%%ebp),%%eax; push (%%eax)`, so it
                                                // dereferences what is stored. Writing the registration node
                                                // made it push the chain's prev pointer -- which printed as
                                                // "???G?H". info[1] is the object the throw site built from
                                                // the message.
                                                @as(*usize, @ptrFromInt(slot)).* = thrown_obj;
                                                if (trace_static_init) {
                                                    std.debug.print("[eh]     catch[{d}]: type=0x{x} disp={d} handler=0x{x}: object at ebp{d}=0x{x}\\n", .{ ci, e_type, e_disp, e_handler, e_disp, slot });
                                                }
                                            }
                                        }
                                        break;
                                    }
                                }
                            }

                            // The catch block reads [-0xNN(%ebp)], so the accepting
                            // frame's EBP must be restored. Walk the EBP chain from
                            // the captured context -- frames chain UPWARD, and the
                            // accepting frame's EBP is the first entry above its
                            // own registration node (measured: node1+12, and
                            // node2+16 for mainCRTStartup's prologue).
                            if (ctx) |c| {
                                const g: *const GuestContext = @ptrCast(@alignCast(c));
                                var f: usize = g.ebp;
                                var hops: usize = 0;
                                while (f > 0x1000 and f < 0xFFFFF000 and hops < 16) : (hops += 1) {
                                    if (f > @intFromPtr(frame.?)) {
                                        accept_ebp = f;
                                        break;
                                    }
                                    const nx: usize = @as(*const usize, @ptrFromInt(f)).*;
                                    if (nx <= 0x1000 or nx >= 0xFFFFF000 or nx <= f) break;
                                    f = nx;
                                }
                            }
                            if (trace_static_init) {
                                std.debug.print("[eh]     -> catch 0x{x} ebp=0x{x} (node=0x{x})\n", .{ h, accept_ebp, @intFromPtr(frame.?) });
                            }
                        }
                    }
                    if (trace_static_init) {
                        std.debug.print("[eh]     -> state {d} inside try[{d}]: EXCEPTION_EXECUTE_HANDLER\n", .{ state, e });
                    }
                    return 1;
                }
            }
        }
    }
    return 0; // EXCEPTION_CONTINUE_SEARCH
}

/// The C __except handler. Same EAX convention as __CxxFrameHandler: the guest's
/// _except_handler3 thunk loads the scope table into EAX before jumping to the
/// import. mainCRTStartup's __try (frame 2 of the chain, handler 0x471e8a) goes
/// through here, not through __CxxFrameHandler -- so a stubbed __CxxFrameHandler
/// alone never covers the outermost frame.
/// Call a __except filter expression. MSVC passes the ExceptionRecord in EAX.
fn callExceptFilter(filter: usize, rec: *const ExceptionRecord) i32 {
    if (@import("builtin").cpu.arch != .x86) return 0;
    var result: i32 = undefined;
    asm volatile (
        \\ movl %[r], %%eax
        \\ call *%[f]
        \\ movl %%eax, %[o]
        : [o] "=r" (result)
        : [f] "r" (filter), [r] "r" (rec)
    );
    return result;
}

fn _except_handler3(rec: ?*const anyopaque, frame: ?*anyopaque, ctx: ?*anyopaque, disp: ?*const anyopaque) callconv(C) i32 {
    _ = disp;
    const establisher = @intFromPtr(frame);
    if (rec == null or establisher <= 0x1000 or establisher + 16 >= 0xFFFFF000) return 0;

    // MSVC's EXCEPTION_REGISTRATION is {prev, handler, scopetable, ...}; the
    // guest pushes $0x483598 as that third word, and that address is the
    // _SCOPETABLE for mainCRTStartup's __try -- confirmed against the binary.
    var sc: usize = @as(*const usize, @ptrFromInt(establisher + 8)).*;
    var guard: usize = 0;
    while (sc > 0x400000 and sc + 16 < 0x4a2000 and guard < 8) : (guard += 1) {
        const try_level: i32 = @as(*const i32, @ptrFromInt(sc)).*;
        const filter: usize = @as(*const usize, @ptrFromInt(sc + 4)).*;
        const enclosing: usize = @as(*const usize, @ptrFromInt(sc + 12)).*;
        if (trace_static_init) {
            std.debug.print("[eh]   scopetable@0x{x}: tryLevel={d} filter=0x{x} enclosing=0x{x}\n", .{ sc, try_level, filter, enclosing });
        }
        // tryLevel == -1 covers the whole function body. Anything below zero
        // compares against the state number for the exact region, which this
        // guest does not use in its outermost frame.
        if (try_level <= -1 and filter > 0x400000 and filter < 0x4a2000) {
            const r: i32 = callExceptFilter(filter, @ptrCast(@alignCast(rec.?)));
            if (trace_static_init) std.debug.print("[eh]     filter -> {d}\n", .{r});
            if (r == 0) {
                accept_handler = @as(*const usize, @ptrFromInt(sc + 8)).*;
                // Calibrated: node+12 is the pExcept slot, not the frame's EBP.
                // The ContextRecord captured at throw time carries the guest EBP.
                accept_ebp = if (ctx) |c| @as(*const GuestContext, @ptrCast(@alignCast(c))).ebp else establisher + 12;
                if (trace_static_init) {
                    std.debug.print("[eh]     node neigh:", .{});
                    var q: usize = 0;
                    while (q < 0x50) : (q += 4) {
                        const a = establisher -% 0x20 + q;
                        const v: usize = @as(*const usize, @ptrFromInt(a)).*;
                        std.debug.print(" +{d}:0x{x:0>8}", .{ q, v });
                    }
                    std.debug.print("\n", .{});
                }
                if (trace_static_init) std.debug.print("[eh]     accepted: handler block 0x{x}, ebp 0x{x}\n", .{ accept_handler, accept_ebp });
            }
            // Win32 __except filter constants: 1 = EXCEPTION_EXECUTE_HANDLER,
            // 0 = EXCEPTION_CONTINUE_SEARCH, -1 = EXCEPTION_CONTINUE_EXECUTION.
            // Frame 2's filter (_XcptFilter) returns 0, i.e. "not mine", which is
            // the correct answer for a C++ exception -- the previous mapping read
            // that 0 as "accept", which is why forcing acceptance looked inert.
            return switch (r) {
                1 => @intFromEnum(Disposition.execute_handler),
                -1 => @intFromEnum(Disposition.continue_execution),
                else => 0, // EXCEPTION_CONTINUE_SEARCH
            };
        }
        if (enclosing <= 0x400000 or enclosing >= 0x4a2000) break;
        sc = enclosing;
    }
    return 0; // EXCEPTION_CONTINUE_SEARCH
}

fn _XcptFilter(xcpt: u32, exc: ?*const anyopaque) callconv(C) i32 {
    _ = xcpt;
    _ = exc;
    return 0; // EXCEPTION_CONTINUE_SEARCH
}

/// _CxxThrowException -- THE root cause of the empty-archive-name crash.
///
/// The CRT declares it noreturn, and the compiler relies on that: everything
/// after the call site is unreachable-by-contract code. This stub returns, so
/// execution falls straight through into the next basic block, which was
/// generated on the assumption that control never arrives there.
///
/// Measured on 7zr.exe:
///   * `7zr l`   calls it (in the "no archive name" path) and then dies at
///               0x411ea0 -- `mov 0x4(%ebx),%eax` on the instruction immediately
///               after the throw block, which walks a half-built object.
///               There is no jump to 0x411ea0: it is fall-through from the
///               throw at 0x411e8d/0x411e9b, reached when `ja 0x411ea0` is NOT
///               taken.
///   * `7zr i`   never calls it, and works.
///   * `7zr b`   calls it once and survives, because the code after that
///               particular throw happens to tolerate re-entry.
///
/// The real fix is C++ exception handling with unwinding: walk the guest's SEH
/// chain (the guest writes its own frame pointer into TIB[0], which is this
/// module's g_tib_buffer), call each frame's __CxxFrameHandler with an
/// EXCEPTION_RECORD whose code is 0xE06D7363, and honour the disposition. That
/// also needs __CxxFrameHandler to consult the FuncInfo scope table instead of
/// returning EXCEPTION_CONTINUE_SEARCH unconditionally, which it currently does.
/// Until then, returning is wrong but no alternative is available; a
/// non-returning stub would take `7zr b` down with it.
/// Head of the SEH chain of the thread that is running: TIB[0], read through FS on
/// the i386 loader (every guest thread has its own TIB), or from the one recorded TIB
/// elsewhere.
fn sehChainHead() usize {
    if (comptime @import("builtin").cpu.arch == .x86) {
        return asm volatile ("movl %%fs:0, %[r]"
            : [r] "=r" (-> usize),
        );
    }
    return @as(*const usize, @ptrFromInt(guest_tib_base)).*;
}

/// Walk the guest's SEH chain: TIB[0] holds the head, each registration record is
/// {prev: *const reg, handler: usize}, and the chain ends at 0xFFFFFFFF.
pub fn walkSehChain(depth_limit: usize) usize {
    if (guest_tib_base == 0) return 0;
    var node: usize = sehChainHead();
    var depth: usize = 0;
    while (node != 0xFFFFFFFF and node > 0x1000 and node + 8 < 0xFFFFF000 and depth < depth_limit) : (depth += 1) {
        const next: usize = @as(*const usize, @ptrFromInt(node)).*;
        const handler: usize = @as(*const usize, @ptrFromInt(node + 4)).*;
        if (trace_static_init) {
            std.debug.print("[eh] frame {d}: node=0x{x:0>8} prev=0x{x:0>8} handler=0x{x:0>8} (guest={})\n", .{ depth, node, next, handler, handler >= 0x400000 and handler < 0x4a2000 });
        }
        if (next == node) break;
        node = next;
    }
    return depth;
}

/// Snapshot the guest's live registers into a Win32 CONTEXT. The shim is host code
/// entered from the guest, so at this instant the general registers are still the
/// guest's -- this is the only place they can be observed.
fn captureGuestContext(ctx: *GuestContext) void {
    if (@import("builtin").cpu.arch != .x86) return;
    // Memory operands, not "=r": ten register outputs exhaust the i386 set and
    // the compiler refuses. Only two need a register.
    var edi: u32 = undefined;
    var esi: u32 = undefined;
    var ebx: u32 = undefined;
    var edx: u32 = undefined;
    var ecx: u32 = undefined;
    var eax: u32 = undefined;
    var ebp: u32 = undefined;
    var esp: u32 = undefined;
    var segss: u32 = undefined;
    var eflags: u32 = undefined;
    asm volatile (
        \\ movl %%edi, %[d]
        \\ movl %%esi, %[s]
        \\ movl %%ebx, %[b]
        \\ movl %%edx, %[x]
        \\ movl %%ecx, %[c]
        \\ movl %%eax, %[a]
        \\ movl %%ebp, %[p]
        \\ movl %%esp, %[sp]
        \\ pushfl
        \\ popl %%eax
        \\ movl %%eax, %[fl]
        \\ movl %%ss, %%eax
        \\ movl %%eax, %[ss]
        : [d] "=m" (edi),
          [s] "=m" (esi),
          [b] "=m" (ebx),
          [x] "=m" (edx),
          [c] "=m" (ecx),
          [a] "=m" (eax),
          [p] "=m" (ebp),
          [sp] "=m" (esp),
          [ss] "=m" (segss),
          [fl] "=r" (eflags),
    );
    ctx.edi = edi;
    ctx.esi = esi;
    ctx.ebx = ebx;
    ctx.edx = edx;
    ctx.ecx = ecx;
    ctx.eax = eax;
    ctx.ebp = ebp;
    ctx.esp = esp;
    ctx.seg_ss = segss;
    ctx.eflags = eflags;
    ctx.eip = @truncate(@returnAddress());
}

/// Transfer control into the guest's __except block. The block restores its own
/// ESP from EBP (`mov -0x18%(%ebp),%esp`), so only EBP and the target have to be
/// right. This does not return: the guest never comes back to the throw site.
/// The catch is a state machine, not a single block.
///
/// Measured on 7zr: the pHandler (0x43d8cf) is a funclet shaped
///     mov <global>,%%ecx ; call <print> ; mov $<next>,%%eax ; ret
/// and 0x43d8e0 is a second one, whose `mov $0x43d90c,%eax` leads to
///     push $0x7 ; jmp 0x43dafb          <- exit code 7, Wine's exact behaviour.
/// Nothing CALLs these entries, so they are reached by the dispatcher calling
/// them; the `ret` returns to it with the next state in EAX.
///
/// Therefore the correct entry is to CALL the first funclet with a live return
/// address, read EAX, and repeat. Jumping straight to the funclet made its `ret`
/// pop the guest's own stack and land EIP inside it -- which is what the SIGSEGV
/// after `transfer` was.
fn transferToHandler() noreturn {
    var state = accept_handler;
    const ebp = accept_ebp;
    var guard: usize = 0;
    while (state > 0x400000 and state < 0x4a2000 and guard < 256) : (guard += 1) {
        var next: usize = 0;
        if (trace_static_init) std.debug.print("[eh]   calling state 0x{x} with ebp=0x{x}\n", .{ state, ebp });
        // "r" for EBP, NOT "m": with a memory operand Zig emitted
        // `mov -0x64(%ebp),%ebp` -- one indirection too many -- so the funclet
        // received a stack address instead of accept_ebp. That is why the first
        // print (which does not touch EBP) succeeded and `mov -0x20(%ebp)`
        // read garbage. The target is pinned to %ecx so the caller cannot alias
        // the two inputs.
        asm volatile (
            \\ movl %[b], %%ebp
            \\ call *%[s]
            \\ movl %%eax, %[n]
            : [n] "={eax}" (next)
            : [s] "{ecx}" (state),
              [b] "r" (ebp),
        );
        if (trace_static_init) std.debug.print("[eh]   state 0x{x} -> 0x{x}\n", .{ state, next });
        if (next <= 0x400000 or next >= 0x4a2000) {
            if (trace_static_init) std.debug.print("[eh]   state machine ended at 0x{x}\n", .{next});
            break;
        }
        state = next;
    }
    // The chain ended without an exit: the last state's own code jumped away
    // (the `push $0x7; jmp` tail), so we only get here if it returned instead.
    linux.exit_group(7);
}

fn transferFailed() noreturn {
    @trap();
}

fn _CxxThrowException(exc: ?*const anyopaque, dp: ?*const anyopaque) callconv(C) void {
    // GATED. The walk below is built and works, but running it unconditionally
    // REGRESSES the loader: measured on 7zr, `b` (benchmark) dies with SIGSEGV
    // and `l` still dies, whereas without the walk `b` completes. The reason is
    // that MSVC's __CxxFrameHandler3 wrappers expect the *dispatcher* to perform
    // the jump into the __except block; walking the chain from a shim and then
    // returning leaves the guest with a mutated SEH chain and no transfer of
    // control, so the guest resumes at the throw site. Left as diagnostics under
    // WINS_TRACE until the dispatcher half exists.

    // Build the C++ EH record the dispatcher would build, then offer it to every
    // frame on the chain until one says it handles the exception.
    var rec: ExceptionRecord = .{
        .exception_code = EH_CODE,
        .exception_information = [_]usize{EH_MAGIC, @intFromPtr(exc), @intFromPtr(dp), 0} ++ [_]usize{0} ** 11,
    };
    var ctx: GuestContext = .{};
    captureGuestContext(&ctx);
    var dc: DispatcherContext = .{
        .control_pc = ctx.eip,
        .establisher_frame = 0, // filled per frame below
        .context_record = @intFromPtr(&ctx),
        .msvc_func_info = 0,
        .msvc_throw_info = @intFromPtr(dp),
    };

    if (trace_static_init) std.debug.print("[eh] throwing: exc=0x{x} throwinfo=0x{x}\n", .{ @intFromPtr(exc), @intFromPtr(dp) });

    // The chain head is re-read after EVERY call. A handler that accepts the
    // exception pops its own registration off the chain, so a node cached
    // across a call is no longer readable -- dereferencing it faults. A handler
    // that answers EXCEPTION_CONTINUE_SEARCH pops nothing, so the head is
    // unchanged and the walk must follow the saved node's own prev field.
    var node: usize = sehChainHead();
    var depth: usize = 0;
    while (depth < 16) : (depth += 1) {
        if (node == 0xFFFFFFFF or node <= 0x1000 or node + 8 >= 0xFFFFF000) {
            std.debug.print("[eh]   chain exhausted after {d} frame(s)\n", .{depth});
            return;
        }
        const handler: usize = @as(*const usize, @ptrFromInt(node + 4)).*;
        const prev: usize = @as(*const usize, @ptrFromInt(node)).*;
        std.debug.print("[eh] frame {d}: node=0x{x:0>8} handler=0x{x:0>8} prev=0x{x:0>8}\n", .{ depth, node, handler, prev });    if (trace_static_init and depth == 0) {
        // Walk the EBP chain from the throw site. Each frame saves the caller's
        // EBP at [EBP]; following it is how an unwinder reaches the accepting
        // frame's EBP, which the catch block's [-0xNN(%ebp)] locals need.
        var e: usize = ctx.ebp;
        var i: usize = 0;
        std.debug.print("[eh]   EBP chain:", .{});
        while (e > 0x1000 and e < 0xFFFFF000 and i < 12) : (i += 1) {
            std.debug.print(" 0x{x:0>8}", .{e});
            const next: usize = @as(*const usize, @ptrFromInt(e)).*;
            if (trace_static_init) std.debug.print(" [0x{x:0>8}]=0x{x:0>8}", .{ e, next });
            // Frames chain UPWARD: a caller's EBP is higher than the callee's.
            // The old `next >= e` guard stopped the walk immediately.
            if (next <= 0x1000 or next >= 0xFFFFF000 or next <= e) break;
            e = next;
        }
        std.debug.print("\n", .{});
        std.debug.print("[eh]   node0=0x{x} node1=0x{x}\n", .{ node, prev });
    }

        if (handler < 0x400000 or handler >= 0x4a2000) {
            std.debug.print("[eh]   handler outside the guest image; stopping\n", .{});
            return;
        }
        dc.establisher_frame = node;
        dc.control_pc = ctx.eip;
        const f: *const fn (*align(1) const ExceptionRecord, usize, *align(1) GuestContext, *align(1) DispatcherContext) callconv(W) i32 =
            @ptrFromInt(handler);
        const disp: i32 = f(&rec, node, &ctx, &dc);
        std.debug.print("[eh]   -> disposition {d}\n", .{disp});
        if (disp == @intFromEnum(Disposition.execute_handler)) {
            std.debug.print("[eh]   HANDLED: transferring to the __except block 0x{x}\n", .{accept_handler});
            transferToHandler();
            return; // unreachable when the transfer succeeds
        }
        // After a CONTINUE_SEARCH the frame stays on the chain, so the walk
        // follows the node's own prev. A handler that accepts pops its frame,
        // but then this function returns instead of using node again. Guard
        // against a self-referential or restored prev: 0x47a068 rewinds TIB[0]
        // after declining, which otherwise makes the walk cycle forever.
        const next = if (prev != node and prev > 0x1000 and prev < 0xFFFFF000) prev else 0xFFFFFFFF;
        if (next == 0xFFFFFFFF or next == node) {
            std.debug.print("[eh]   chain end after {d} frame(s)\n", .{depth + 1});
            return;
        }
        node = next;
    }
    std.debug.print("[eh]   no handler accepted; unhandled\n", .{});
}

/// type_info::~type_info, ?terminate@@YAXXZ and _purecall have no meaningful
/// Linux equivalent; no-ops, because aborting a guest that never reached them
/// would be strictly worse than doing nothing.
fn type_info_dtor(self: ?*anyopaque) callconv(C) void {
    _ = self;
}

fn terminate_stub() callconv(C) void {}

fn purecall_stub() callconv(C) void {}

fn __dllonexit(rec: ?*anyopaque, term: ?*anyopaque, onexit: ?*?*anyopaque) callconv(C) ?*anyopaque {
    // The CRT onexit list is not threaded through this module. Record the block
    // where the guest asked for it and hand the block back.
    _ = term;
    if (onexit) |o| {
        if (o.* == null) o.* = rec;
    }
    return rec;
}

/// __ftol, i386: truncate ST(0) to a signed 64-bit in EDX:EAX. The x87 control
/// word is saved, forced to round-toward-zero, then restored around the store.
fn _ftol_i386() callconv(.naked) void {
    asm volatile (
        \\ subl $16, %%esp
        \\ fstcw (%%esp)
        \\ fnstcw 4(%%esp)
        \\ orw $0x0c00, 4(%%esp)
        \\ fldcw 4(%%esp)
        \\ fistpq 8(%%esp)
        \\ fldcw (%%esp)
        \\ movl 8(%%esp), %%eax
        \\ movl 12(%%esp), %%edx
        \\ addl $16, %%esp
        \\ ret
    );
}

/// __ftol, x86_64: the value arrives in xmm0; no x87 dance exists there.
fn _ftol_x86_64() callconv(.naked) void {
    asm volatile (
        \\ cvttsd2siq %%xmm0, %%rax
        \\ ret
    );
}

/// _beginthreadex is deliberately NOT exported from lookup(): it would have to
/// hand the guest a thread entry on a real secondary stack, which this loader
/// does not create. An unresolved import gets reported; a fake handle does not.

fn wcscmp(a: ?[*:0]const u16, b: ?[*:0]const u16) callconv(C) i32 {
    const x = a orelse return -1;
    const y = b orelse return 1;
    var i: usize = 0;
    while (true) : (i += 1) {
        const cx = x[i];
        const cy = y[i];
        if (cx != cy) return if (cx < cy) -1 else 1;
        if (cx == 0) return 0;
    }
}

fn wcsstr(h: ?[*:0]const u16, n: ?[*:0]const u16) callconv(C) ?[*]u16 {
    const hay = h orelse return null;
    const needle = n orelse return null;
    const hlen = wcslen(hay);
    var nlen: usize = 0;
    while (needle[nlen] != 0) : (nlen += 1) {}
    if (nlen == 0) return @constCast(hay);
    if (nlen > hlen) return null;
    var i: usize = 0;
    while (i + nlen <= hlen) : (i += 1) {
        var j: usize = 0;
        while (j < nlen and needle[j] == hay[i + j]) : (j += 1) {}
        if (j == nlen) return @constCast(hay + i);
    }
    return null;
}

// ============================================================================
// 12. Lookup Dispatch Table
// ============================================================================

/// XInput9/10/13 shims. Ordinals 2 and 3 of XINPUT1_3 (derived from the real
/// DLL's export table) are XInputGetState and XInputSetState.
///
/// No gamepad is modelled, so the honest answer is ERROR_DEVICE_NOT_CONNECTED
/// (1167), which is what Windows also returns with no controller and what makes
/// the game fall back to keyboard/mouse. A zeroed "connected" state would make
/// the game sit still in its menus believing a stick was centred at 0.
pub fn lookupXinput(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "XInputGetState")) return @intFromPtr(&XInputGetState);
    if (std.mem.eql(u8, name, "XInputSetState")) return @intFromPtr(&XInputSetState);
    if (std.mem.eql(u8, name, "XInputGetCapabilities")) return @intFromPtr(&XInputGetCapabilities);
    if (std.mem.eql(u8, name, "XInputEnable")) return @intFromPtr(&XInputEnable);
    return null;
}

fn XInputGetState(dwUserIndex: u32, pState: ?*anyopaque) callconv(C) u32 {
    _ = dwUserIndex;
    if (pState) |p| @memset(@as([*]u8, @ptrCast(p))[0..12], 0);
    return 1167; // ERROR_DEVICE_NOT_CONNECTED
}

fn XInputSetState(dwUserIndex: u32, pVibration: ?*const anyopaque) callconv(C) u32 {
    _ = dwUserIndex; _ = pVibration;
    return 1167; // ERROR_DEVICE_NOT_CONNECTED
}

fn XInputGetCapabilities(dwUserIndex: u32, dwFlags: u32, pCapabilities: ?*anyopaque) callconv(C) u32 {
    _ = dwUserIndex; _ = dwFlags; _ = pCapabilities;
    return 1167; // ERROR_DEVICE_NOT_CONNECTED
}

fn XInputEnable(enable: u32) callconv(C) void {
    _ = enable;
}

/// winmm's mmio*: unbuffered RIFF file I/O. A file is read either through the
/// caller's own I/O procedure (MMIOINFO.pIOProc -- FalloutNV reads its .wav
/// effects out of the .bsa archives this way, IOProc 0xaf0400) or, without one,
/// from a real fd. Descend/Ascend walk the RIFF chunks as winmm does. With
/// MMIO_ALLOCBUF (or a caller's buffer) reads go through an I/O buffer that the
/// caller may also walk directly: mmioGetInfo hands out its pointers and
/// mmioAdvance loads the next stretch (FalloutNV reads sample data this way).
/// Writing is not modelled: a write open fails.
pub fn lookupWinmm(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "mmioClose")) return @intFromPtr(&mmioClose);
    if (std.mem.eql(u8, name, "mmioDescend")) return @intFromPtr(&mmioDescend);
    if (std.mem.eql(u8, name, "mmioAscend")) return @intFromPtr(&mmioAscend);
    if (std.mem.eql(u8, name, "mmioGetInfo")) return @intFromPtr(&mmioGetInfo);
    if (std.mem.eql(u8, name, "mmioSetInfo")) return @intFromPtr(&mmioSetInfo);
    if (std.mem.eql(u8, name, "mmioRead")) return @intFromPtr(&mmioRead);
    if (std.mem.eql(u8, name, "mmioSeek")) return @intFromPtr(&mmioSeek);
    if (std.mem.eql(u8, name, "mmioAdvance")) return @intFromPtr(&mmioAdvance);
    if (std.mem.eql(u8, name, "mmioOpenA")) return @intFromPtr(&mmioOpenA);
    return null;
}

const MMIOM_READ: u32 = 0;
const MMIOM_SEEK: u32 = 2;
const MMIOM_OPEN: u32 = 3;
const MMIOM_CLOSE: u32 = 4;
const MMIOERR_CHUNKNOTFOUND: u32 = 265;
const MMIOERR_UNBUFFERED: u32 = 266;
const MMSYSERR_INVALHANDLE: u32 = 5;
const FOURCC_RIFF: u32 = 0x46464952;
const FOURCC_LIST: u32 = 0x5453494C;

/// mmsystem.h's MMIOINFO (pack 1; 0x48 bytes on i386).
const MMIOINFO = extern struct {
    dwFlags: u32,
    fccIOProc: u32,
    pIOProc: ?*const fn (*MMIOINFO, u32, usize, usize) callconv(W) isize,
    wErrorRet: u32,
    htask: u32,
    cchBuffer: i32,
    pchBuffer: u32,
    pchNext: u32,
    pchEndRead: u32,
    pchEndWrite: u32,
    lBufOffset: i32,
    lDiskOffset: i32,
    adwInfo: [3]u32,
    dwReserved1: u32,
    dwReserved2: u32,
    hmmio: u32,
};

const MMCKINFO = extern struct {
    ckid: u32,
    cksize: u32,
    fccType: u32,
    dwDataOffset: u32,
    dwFlags: u32,
};

const MmioFile = struct {
    used: bool = false,
    fd: i32 = -1,
    /// The MMIOINFO the I/O procedure sees; it keeps its own state in adwInfo.
    /// With an I/O buffer, pchBuffer..pchEndRead holds the file bytes from
    /// lBufOffset on and pchNext is the read position inside it.
    info: MMIOINFO = std.mem.zeroes(MMIOINFO),
    /// MMIO_ALLOCBUF's buffer (MMIO_DEFAULTBUFFER bytes).
    own_buffer: [8192]u8 = undefined,
};

var g_mmio_table: [32]MmioFile = [_]MmioFile{.{}} ** 32;
const MMIO_HANDLE_BASE: usize = 0x00310000;

var mmio_trace_left: i32 = -1;
/// WINS_MMIO_TRACE=<n>: report the first n mmio opens and chunk lookups.
fn mmioTrace(comptime fmt: []const u8, args: anytype) void {
    if (mmio_trace_left < 0) {
        mmio_trace_left = 0;
        // The host's environment (libc), not the guest's CRT one above.
        const host_getenv = @extern(*const fn ([*:0]const u8) callconv(.c) ?[*:0]const u8, .{ .name = "getenv" });
        if (host_getenv("WINS_MMIO_TRACE")) |v| mmio_trace_left = std.fmt.parseInt(i32, std.mem.sliceTo(v, 0), 10) catch 0;
    }
    if (mmio_trace_left == 0) return;
    mmio_trace_left -= 1;
    std.debug.print("[WINS:winmm] " ++ fmt ++ "\n", args);
}

fn mmioFile(hmmio: usize) ?*MmioFile {
    if (hmmio <= MMIO_HANDLE_BASE or hmmio - MMIO_HANDLE_BASE > g_mmio_table.len) return null;
    const f = &g_mmio_table[hmmio - MMIO_HANDLE_BASE - 1];
    return if (f.used) f else null;
}

/// Read at the device's own position (the I/O procedure or the fd).
fn mmioRawRead(f: *MmioFile, buf: [*]u8, want: usize) isize {
    if (f.info.pIOProc) |proc| return proc(&f.info, MMIOM_READ, @intFromPtr(buf), want);
    var total: usize = 0;
    while (total < want) {
        const r = linux.read(f.fd, buf + total, want - total);
        if (linux.errno(r) != .SUCCESS) return if (total > 0) @intCast(total) else -1;
        if (r == 0) break;
        total += r;
    }
    f.info.lDiskOffset += @intCast(total);
    return @intCast(total);
}

/// Move the device's position; the new position, or -1.
fn mmioRawSeek(f: *MmioFile, offset: i32, origin: i32) i32 {
    if (f.info.pIOProc) |proc| {
        const rc = proc(&f.info, MMIOM_SEEK, @as(usize, @bitCast(@as(isize, offset))), @as(usize, @bitCast(@as(isize, origin))));
        if (rc == -1) return -1;
        // The procedure keeps lDiskOffset current; that is the position winmm
        // itself goes by. Its return value is not reliable: FalloutNV's
        // (0xaf0583) seeks, stores the position there and returns 0.
        return f.info.lDiskOffset;
    }
    if (origin < 0 or origin > 2) return -1;
    const r = linux.syscall3(.lseek, @as(usize, @bitCast(@as(isize, f.fd))), @as(usize, @bitCast(@as(isize, offset))), @as(usize, @intCast(origin)));
    if (linux.errno(r) != .SUCCESS) return -1;
    f.info.lDiskOffset = @intCast(r);
    return @intCast(r);
}

fn mmioBuffered(f: *const MmioFile) bool {
    return f.info.cchBuffer > 0 and f.info.pchBuffer != 0;
}
/// Bytes of the file held in the buffer.
fn mmioHeld(f: *const MmioFile) u32 {
    return f.info.pchEndRead - f.info.pchBuffer;
}
/// Load the buffer with the file from `offset` on. False on a device error.
fn mmioFill(f: *MmioFile, offset: i32) bool {
    if (f.info.lDiskOffset != offset and mmioRawSeek(f, offset, 0) < 0) return false;
    f.info.lBufOffset = offset;
    f.info.pchNext = f.info.pchBuffer;
    f.info.pchEndRead = f.info.pchBuffer;
    const got = mmioRawRead(f, @ptrFromInt(f.info.pchBuffer), @intCast(f.info.cchBuffer));
    if (got < 0) return false;
    f.info.pchEndRead += @intCast(got);
    return true;
}

fn mmioOpenA(szFilename: ?[*:0]const u8, pmioopen: ?*MMIOINFO, dwOpenFlags: u32) callconv(W) usize {
    var slot: ?*MmioFile = null;
    var index: usize = 0;
    for (&g_mmio_table, 0..) |*e, i| {
        if (!e.used) {
            slot = e;
            index = i;
            break;
        }
    }
    const f = slot orelse return 0;
    f.used = false;
    f.fd = -1;
    f.info = std.mem.zeroes(MMIOINFO);
    if (pmioopen) |src| f.info = src.*;
    f.info.dwFlags = dwOpenFlags;
    f.info.hmmio = @intCast(MMIO_HANDLE_BASE + index + 1);
    f.info.lDiskOffset = 0;
    f.info.lBufOffset = 0;
    if (f.info.pIOProc) |proc| {
        const rc = proc(&f.info, MMIOM_OPEN, @intFromPtr(szFilename), 0);
        if (rc != 0) {
            if (pmioopen) |src| src.wErrorRet = @truncate(@as(usize, @bitCast(rc)));
            mmioTrace("mmioOpenA(\"{s}\"): the I/O procedure refused it ({d})", .{ if (szFilename) |n| std.mem.sliceTo(n, 0) else "", rc });
            return 0;
        }
    } else {
        const path = szFilename orelse return 0;
        // MMIO_READ is 0; MMIO_WRITE (1) and MMIO_READWRITE (2) are not modelled.
        if (dwOpenFlags & 3 != 0) return 0;
        const fd = linux.open(path, .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(fd) != .SUCCESS) return 0;
        f.fd = @intCast(fd);
    }
    // The I/O buffer: the caller's, or ours for MMIO_ALLOCBUF; empty until read.
    if (!(f.info.cchBuffer > 0 and f.info.pchBuffer != 0)) {
        if (dwOpenFlags & 0x10000 != 0) { // MMIO_ALLOCBUF
            f.info.pchBuffer = @intFromPtr(&f.own_buffer);
            f.info.cchBuffer = @intCast(f.own_buffer.len);
        } else {
            f.info.pchBuffer = 0;
            f.info.cchBuffer = 0;
        }
    }
    f.info.pchNext = f.info.pchBuffer;
    f.info.pchEndRead = f.info.pchBuffer;
    f.info.pchEndWrite = f.info.pchBuffer;
    f.used = true;
    if (pmioopen) |src| src.wErrorRet = 0;
    mmioTrace("mmioOpenA(\"{s}\") -> 0x{x}", .{ if (szFilename) |n| std.mem.sliceTo(n, 0) else "", f.info.hmmio });
    return f.info.hmmio;
}

fn mmioClose(hmmio: usize, wFlags: u32) callconv(W) u32 {
    const f = mmioFile(hmmio) orelse return MMSYSERR_INVALHANDLE;
    var rc: u32 = 0;
    if (f.info.pIOProc) |proc| {
        rc = @truncate(@as(usize, @bitCast(proc(&f.info, MMIOM_CLOSE, wFlags, 0))));
    } else {
        _ = linux.close(f.fd);
    }
    f.used = false;
    return rc;
}

fn mmioRead(hmmio: usize, pch: ?[*]u8, cch: i32) callconv(W) i32 {
    const f = mmioFile(hmmio) orelse return -1;
    const buf = pch orelse return 0;
    if (cch <= 0) return 0;
    const want: usize = @intCast(cch);
    if (!mmioBuffered(f)) return @intCast(mmioRawRead(f, buf, want));
    var total: usize = 0;
    while (total < want) {
        var avail: usize = f.info.pchEndRead - f.info.pchNext;
        if (avail == 0) {
            if (!mmioFill(f, f.info.lBufOffset + @as(i32, @intCast(mmioHeld(f))))) return if (total > 0) @intCast(total) else -1;
            avail = mmioHeld(f);
            if (avail == 0) break; // end of file
        }
        const n = @min(avail, want - total);
        const src: [*]const u8 = @ptrFromInt(f.info.pchNext);
        @memcpy(buf[total .. total + n], src[0..n]);
        f.info.pchNext += @intCast(n);
        total += n;
    }
    return @intCast(total);
}

fn mmioSeek(hmmio: usize, lOffset: i32, iOrigin: i32) callconv(W) i32 {
    const f = mmioFile(hmmio) orelse return -1;
    if (!mmioBuffered(f)) return mmioRawSeek(f, lOffset, iOrigin);
    const here: i32 = f.info.lBufOffset + @as(i32, @intCast(f.info.pchNext - f.info.pchBuffer));
    const target: i32 = switch (iOrigin) {
        0 => lOffset,
        1 => here +% lOffset,
        2 => blk: {
            const end = mmioRawSeek(f, 0, 2);
            if (end < 0) return -1;
            break :blk end +% lOffset;
        },
        else => return -1,
    };
    if (target < 0) return -1;
    if (target >= f.info.lBufOffset and target <= f.info.lBufOffset + @as(i32, @intCast(mmioHeld(f)))) {
        f.info.pchNext = f.info.pchBuffer + @as(u32, @intCast(target - f.info.lBufOffset));
    } else {
        // Outside what is held: an empty buffer at the target, loaded on the next read.
        f.info.lBufOffset = target;
        f.info.pchNext = f.info.pchBuffer;
        f.info.pchEndRead = f.info.pchBuffer;
    }
    return target;
}

/// Find a chunk (optionally a given one, optionally inside `parent`) and leave
/// the file at the start of its data, as winmm's mmioDescend.
fn mmioDescend(hmmio: usize, lpck: ?*MMCKINFO, parent: ?*const MMCKINFO, wFlags: u32) callconv(W) u32 {
    if (mmioFile(hmmio) == null) return MMSYSERR_INVALHANDLE;
    const ck = lpck orelse return 11; // MMSYSERR_INVALPARAM
    const cur = mmioSeek(hmmio, 0, 1);
    if (cur < 0) return MMIOERR_CHUNKNOTFOUND;
    var pos: u32 = @intCast(cur);
    var max_pos: u32 = 0xFFFFFFFF;
    if (parent) |p| {
        const end = p.dwDataOffset +% p.cksize;
        if (pos < p.dwDataOffset or pos >= end) {
            pos = p.dwDataOffset;
            _ = mmioSeek(hmmio, @bitCast(pos), 0);
        }
        max_pos = end;
    }
    const start = pos;
    var want_id: u32 = 0;
    var want_type: u32 = 0;
    if (wFlags & 0x10 != 0) want_id = ck.ckid; // MMIO_FINDCHUNK
    if (wFlags & 0x20 != 0) { // MMIO_FINDRIFF
        want_id = FOURCC_RIFF;
        want_type = ck.fccType;
    }
    if (wFlags & 0x40 != 0) { // MMIO_FINDLIST
        want_id = FOURCC_LIST;
        want_type = ck.fccType;
    }
    while (true) {
        var head: [3]u32 = .{ 0, 0, 0 };
        const got: i32 = if (pos < max_pos) mmioRead(hmmio, @ptrCast(&head), 12) else 0;
        if (got < 8) {
            _ = mmioSeek(hmmio, @bitCast(start), 0);
            mmioTrace("mmioDescend(0x{x}, id 0x{x} type 0x{x}): not found from {d} (read {d} at {d})", .{ hmmio, want_id, want_type, start, got, pos });
            return MMIOERR_CHUNKNOTFOUND;
        }
        const is_form = head[0] == FOURCC_RIFF or head[0] == FOURCC_LIST;
        const type_ok = want_type == 0 or (is_form and got >= 12 and head[2] == want_type);
        if ((want_id == 0 or want_id == head[0]) and type_ok) {
            ck.ckid = head[0];
            ck.cksize = head[1];
            ck.dwDataOffset = pos + 8;
            ck.dwFlags = 0;
            if (is_form) {
                ck.fccType = head[2];
                _ = mmioSeek(hmmio, @bitCast(ck.dwDataOffset + 4), 0);
            } else {
                ck.fccType = 0;
                _ = mmioSeek(hmmio, @bitCast(ck.dwDataOffset), 0);
            }
            mmioTrace("mmioDescend(0x{x}): chunk 0x{x} size {d} data at {d}", .{ hmmio, ck.ckid, ck.cksize, ck.dwDataOffset });
            return 0;
        }
        pos = pos + 8 + ((head[1] +% 1) & ~@as(u32, 1));
        if (mmioSeek(hmmio, @bitCast(pos), 0) < 0) {
            _ = mmioSeek(hmmio, @bitCast(start), 0);
            return MMIOERR_CHUNKNOTFOUND;
        }
    }
}

/// Leave a chunk: seek past its (word-aligned) data.
fn mmioAscend(hmmio: usize, lpck: ?*const MMCKINFO, wFlags: u32) callconv(W) u32 {
    _ = wFlags;
    if (mmioFile(hmmio) == null) return MMSYSERR_INVALHANDLE;
    const ck = lpck orelse return 11;
    const end = ck.dwDataOffset +% ((ck.cksize +% 1) & ~@as(u32, 1));
    if (mmioSeek(hmmio, @bitCast(end), 0) < 0) return 263; // MMIOERR_CANNOTSEEK
    return 0;
}

/// Hand the caller the buffer pointers so it can read the bytes in place.
fn mmioGetInfo(hmmio: usize, pmmioinfo: ?*MMIOINFO, wFlags: u32) callconv(W) u32 {
    _ = wFlags;
    const f = mmioFile(hmmio) orelse return MMSYSERR_INVALHANDLE;
    if (pmmioinfo) |out| out.* = f.info;
    return 0;
}

/// The caller walked the buffer to its end (its pchNext says how far): load
/// the stretch of the file that follows and give it the new pointers. At the
/// end of the file the buffer comes back empty (pchNext == pchEndRead).
fn mmioAdvance(hmmio: usize, pmmioinfo: ?*MMIOINFO, wFlags: u32) callconv(W) u32 {
    const f = mmioFile(hmmio) orelse return MMSYSERR_INVALHANDLE;
    if (!mmioBuffered(f)) return MMIOERR_UNBUFFERED;
    if (wFlags & 1 != 0) return 260; // MMIO_WRITE: MMIOERR_CANNOTWRITE, writing is not modelled
    if (!mmioFill(f, f.info.lBufOffset + @as(i32, @intCast(mmioHeld(f))))) return 261; // MMIOERR_CANNOTREAD
    if (pmmioinfo) |out| {
        out.pchNext = f.info.pchNext;
        out.pchEndRead = f.info.pchEndRead;
        out.pchEndWrite = f.info.pchEndWrite;
        out.lBufOffset = f.info.lBufOffset;
        out.lDiskOffset = f.info.lDiskOffset;
    }
    return 0;
}

/// The caller is done reading in place: take its position back.
fn mmioSetInfo(hmmio: usize, pmmioinfo: ?*const MMIOINFO, wFlags: u32) callconv(W) u32 {
    _ = wFlags;
    const f = mmioFile(hmmio) orelse return MMSYSERR_INVALHANDLE;
    const in = pmmioinfo orelse return 11; // MMSYSERR_INVALPARAM
    if (!mmioBuffered(f)) return 0;
    if (in.pchNext < f.info.pchBuffer or in.pchNext > f.info.pchEndRead) return 11;
    f.info.pchNext = in.pchNext;
    return 0;
}

pub fn lookup(name: []const u8) ?usize {
    // Data exports
    if (std.mem.eql(u8, name, "_fmode")) return @intFromPtr(&msvcrt_fmode);
    if (std.mem.eql(u8, name, "_commode")) return @intFromPtr(&msvcrt_commode);
    if (std.mem.eql(u8, name, "__initenv")) return @intFromPtr(&msvcrt_initenv);
    if (std.mem.eql(u8, name, "__argv")) return @intFromPtr(&msvcrt_argv);
    if (std.mem.eql(u8, name, "_environ")) return @intFromPtr(&msvcrt_environ);
    if (std.mem.eql(u8, name, "_timezone")) return @intFromPtr(&msvcrt_timezone);

    // CRT startup & environment
    if (std.mem.eql(u8, name, "_errno")) return @intFromPtr(&_errno);
    if (std.mem.eql(u8, name, "__p__fmode")) return @intFromPtr(&__p__fmode);
    if (std.mem.eql(u8, name, "__p__commode")) return @intFromPtr(&__p__commode);
    if (std.mem.eql(u8, name, "__p___argv")) return @intFromPtr(&__p___argv);
    if (std.mem.eql(u8, name, "__p___argc")) return @intFromPtr(&__p___argc);
    if (std.mem.eql(u8, name, "__p__environ")) return @intFromPtr(&__p__environ);
    if (std.mem.eql(u8, name, "__set_app_type")) return @intFromPtr(&__set_app_type);
    if (std.mem.eql(u8, name, "_controlfp")) return @intFromPtr(&_controlfp);
    if (std.mem.eql(u8, name, "_clearfp")) return @intFromPtr(&_clearfp);
    // `_iob` must be the address of the single iob_table, not a second array.
    if (std.mem.eql(u8, name, "_iob")) return @intFromPtr(&iob_table);
    if (std.mem.eql(u8, name, "__p___initenv")) return @intFromPtr(&__p__environ);
    if (std.mem.eql(u8, name, "_XcptFilter")) return @intFromPtr(&_XcptFilter);
    if (std.mem.eql(u8, name, "__CxxFrameHandler")) return @intFromPtr(&__CxxFrameHandler);
    if (std.mem.eql(u8, name, "_except_handler3")) return @intFromPtr(&_except_handler3);
    if (std.mem.eql(u8, name, "_CxxThrowException")) return @intFromPtr(&_CxxThrowException);
    if (std.mem.eql(u8, name, "??1type_info@@UAE@XZ")) return @intFromPtr(&type_info_dtor);
    if (std.mem.eql(u8, name, "?terminate@@YAXXZ")) return @intFromPtr(&terminate_stub);
    if (std.mem.eql(u8, name, "_purecall")) return @intFromPtr(&purecall_stub);
    if (std.mem.eql(u8, name, "__dllonexit")) return @intFromPtr(&__dllonexit);
    if (std.mem.eql(u8, name, "_adjust_fdiv")) return @intFromPtr(&_adjust_fdiv);
    if (std.mem.eql(u8, name, "wcscmp")) return @intFromPtr(&wcscmp);
    if (std.mem.eql(u8, name, "wcsstr")) return @intFromPtr(&wcsstr);
    // __ftol has two ABI-specific bodies; pick the one for this target.
    if (std.mem.eql(u8, name, "_ftol")) {
        if (@sizeOf(usize) == 8) return @intFromPtr(&_ftol_x86_64);
        return @intFromPtr(&_ftol_i386);
    }
    if (std.mem.eql(u8, name, "__setusermatherr")) return @intFromPtr(&__setusermatherr);
    if (std.mem.eql(u8, name, "___lc_codepage_func")) return @intFromPtr(&___lc_codepage_func);
    if (std.mem.eql(u8, name, "___mb_cur_max_func")) return @intFromPtr(&___mb_cur_max_func);
    if (std.mem.eql(u8, name, "localeconv")) return @intFromPtr(&localeconv);
    if (std.mem.eql(u8, name, "__getmainargs")) return @intFromPtr(&__getmainargs);
    if (std.mem.eql(u8, name, "_initterm")) return @intFromPtr(&_initterm);
    if (std.mem.eql(u8, name, "_onexit")) return @intFromPtr(&_onexit);
    if (std.mem.eql(u8, name, "_lock")) return @intFromPtr(&_lock);
    if (std.mem.eql(u8, name, "_unlock")) return @intFromPtr(&_unlock);
    if (std.mem.eql(u8, name, "__C_specific_handler")) return @intFromPtr(&__C_specific_handler);
    if (std.mem.eql(u8, name, "signal")) return @intFromPtr(&signal);
    if (std.mem.eql(u8, name, "atexit")) return @intFromPtr(&atexit);
    if (std.mem.eql(u8, name, "exit")) return @intFromPtr(&exit);
    if (std.mem.eql(u8, name, "_exit")) return @intFromPtr(&_exit);
    if (std.mem.eql(u8, name, "_cexit")) return @intFromPtr(&_cexit);
    if (std.mem.eql(u8, name, "_c_exit")) return @intFromPtr(&_c_exit);
    if (std.mem.eql(u8, name, "_amsg_exit")) return @intFromPtr(&_amsg_exit);
    if (std.mem.eql(u8, name, "abort")) return @intFromPtr(&abort);

    // Heap memory
    if (std.mem.eql(u8, name, "malloc")) return @intFromPtr(&malloc);
    if (std.mem.eql(u8, name, "calloc")) return @intFromPtr(&calloc);
    if (std.mem.eql(u8, name, "realloc")) return @intFromPtr(&realloc);
    if (std.mem.eql(u8, name, "free")) return @intFromPtr(&free);

    // FILE streams & I/O
    if (std.mem.eql(u8, name, "__iob_func")) return @intFromPtr(&__iob_func);
    if (std.mem.eql(u8, name, "__acrt_iob_func")) return @intFromPtr(&__acrt_iob_func);
    if (std.mem.eql(u8, name, "fopen")) return @intFromPtr(&fopen);
    if (std.mem.eql(u8, name, "fclose")) return @intFromPtr(&fclose);
    if (std.mem.eql(u8, name, "fflush")) return @intFromPtr(&fflush);
    if (std.mem.eql(u8, name, "fseek")) return @intFromPtr(&fseek);
    if (std.mem.eql(u8, name, "ftell")) return @intFromPtr(&ftell);
    if (std.mem.eql(u8, name, "fputc")) return @intFromPtr(&fputc);
    if (std.mem.eql(u8, name, "putc")) return @intFromPtr(&fputc);
    if (std.mem.eql(u8, name, "putchar")) return @intFromPtr(&putchar);
    if (std.mem.eql(u8, name, "puts")) return @intFromPtr(&puts);
    if (std.mem.eql(u8, name, "fputs")) return @intFromPtr(&fputs);
    if (std.mem.eql(u8, name, "fwrite")) return @intFromPtr(&fwrite);
    if (std.mem.eql(u8, name, "getc")) return @intFromPtr(&getc);
    if (std.mem.eql(u8, name, "fgetc")) return @intFromPtr(&getc);
    if (std.mem.eql(u8, name, "ungetc")) return @intFromPtr(&ungetc);
    if (std.mem.eql(u8, name, "fread")) return @intFromPtr(&fread);
    if (std.mem.eql(u8, name, "fgets")) return @intFromPtr(&fgets);
    if (std.mem.eql(u8, name, "vfprintf")) return @intFromPtr(&vfprintf);
    if (std.mem.eql(u8, name, "fprintf")) return @intFromPtr(&fprintf);
    if (std.mem.eql(u8, name, "printf")) return @intFromPtr(&printf);
    if (std.mem.eql(u8, name, "feof")) return @intFromPtr(&feof);
    if (std.mem.eql(u8, name, "ferror")) return @intFromPtr(&ferror);
    if (std.mem.eql(u8, name, "clearerr")) return @intFromPtr(&clearerr);
    if (std.mem.eql(u8, name, "_filbuf")) return @intFromPtr(&_filbuf);
    if (std.mem.eql(u8, name, "_getch")) return @intFromPtr(&_getch);
    if (std.mem.eql(u8, name, "_getche")) return @intFromPtr(&_getche);
    if (std.mem.eql(u8, name, "setbuf")) return @intFromPtr(&setbuf);
    if (std.mem.eql(u8, name, "setvbuf")) return @intFromPtr(&setvbuf);

    // Low-level POSIX file I/O
    if (std.mem.eql(u8, name, "_open")) return @intFromPtr(&_open);
    if (std.mem.eql(u8, name, "_creat")) return @intFromPtr(&_creat);
    if (std.mem.eql(u8, name, "_close")) return @intFromPtr(&_close);
    if (std.mem.eql(u8, name, "_read")) return @intFromPtr(&_read);
    if (std.mem.eql(u8, name, "_write")) return @intFromPtr(&_write);
    if (std.mem.eql(u8, name, "_lseeki64")) return @intFromPtr(&_lseeki64);
    if (std.mem.eql(u8, name, "_telli64")) return @intFromPtr(&_telli64);
    if (std.mem.eql(u8, name, "_dup")) return @intFromPtr(&_dup);
    if (std.mem.eql(u8, name, "_dup2")) return @intFromPtr(&_dup2);
    if (std.mem.eql(u8, name, "_pipe")) return @intFromPtr(&_pipe);
    if (std.mem.eql(u8, name, "_isatty")) return @intFromPtr(&_isatty);
    if (std.mem.eql(u8, name, "_get_osfhandle")) return @intFromPtr(&_get_osfhandle);
    if (std.mem.eql(u8, name, "_open_osfhandle")) return @intFromPtr(&_open_osfhandle);
    if (std.mem.eql(u8, name, "_setmode")) return @intFromPtr(&_setmode);
    if (std.mem.eql(u8, name, "_fileno")) return @intFromPtr(&_fileno);
    if (std.mem.eql(u8, name, "_fdopen")) return @intFromPtr(&_fdopen);

    // Filesystem & paths
    if (std.mem.eql(u8, name, "_access")) return @intFromPtr(&_access);
    if (std.mem.eql(u8, name, "_chmod")) return @intFromPtr(&_chmod);
    if (std.mem.eql(u8, name, "_unlink")) return @intFromPtr(&_unlink);
    if (std.mem.eql(u8, name, "_mkdir")) return @intFromPtr(&_mkdir);
    if (std.mem.eql(u8, name, "_rmdir")) return @intFromPtr(&_rmdir);
    if (std.mem.eql(u8, name, "_chdir")) return @intFromPtr(&_chdir);
    if (std.mem.eql(u8, name, "_getcwd")) return @intFromPtr(&_getcwd);
    if (std.mem.eql(u8, name, "_umask")) return @intFromPtr(&_umask);
    if (std.mem.eql(u8, name, "_fstat64")) return @intFromPtr(&_fstat64);
    if (std.mem.eql(u8, name, "_fullpath")) return @intFromPtr(&_fullpath);
    if (std.mem.eql(u8, name, "_mktemp")) return @intFromPtr(&_mktemp);
    if (std.mem.eql(u8, name, "rename")) return @intFromPtr(&rename);

    // Process & environment
    if (std.mem.eql(u8, name, "_getpid")) return @intFromPtr(&_getpid);
    if (std.mem.eql(u8, name, "getenv")) return @intFromPtr(&getenv);
    if (std.mem.eql(u8, name, "_putenv")) return @intFromPtr(&_putenv);
    if (std.mem.eql(u8, name, "_spawnve")) return @intFromPtr(&_spawnve);

    // Time & clock
    if (std.mem.eql(u8, name, "_time64")) return @intFromPtr(&_time64);
    if (std.mem.eql(u8, name, "_localtime64")) return @intFromPtr(&_localtime64);
    if (std.mem.eql(u8, name, "_gmtime64")) return @intFromPtr(&_gmtime64);
    if (std.mem.eql(u8, name, "_ctime64")) return @intFromPtr(&_ctime64);
    if (std.mem.eql(u8, name, "_mktime64")) return @intFromPtr(&_mktime64);
    if (std.mem.eql(u8, name, "strftime")) return @intFromPtr(&strftime);
    if (std.mem.eql(u8, name, "clock")) return @intFromPtr(&clock);
    if (std.mem.eql(u8, name, "_tzset")) return @intFromPtr(&_tzset);

    // Strings, CType, Math & Search
    if (std.mem.eql(u8, name, "strlen")) return @intFromPtr(&strlen);
    if (std.mem.eql(u8, name, "wcslen")) return @intFromPtr(&wcslen);
    if (std.mem.eql(u8, name, "strcmp")) return @intFromPtr(&strcmp);
    if (std.mem.eql(u8, name, "strncmp")) return @intFromPtr(&strncmp);
    if (std.mem.eql(u8, name, "strcspn")) return @intFromPtr(&strcspn);
    if (std.mem.eql(u8, name, "strerror")) return @intFromPtr(&strerror);
    if (std.mem.eql(u8, name, "memcpy")) return @intFromPtr(&memcpy);
    if (std.mem.eql(u8, name, "memset")) return @intFromPtr(&memset);
    if (std.mem.eql(u8, name, "isspace")) return @intFromPtr(&isspace);
    if (std.mem.eql(u8, name, "isxdigit")) return @intFromPtr(&isxdigit);
    if (std.mem.eql(u8, name, "tolower")) return @intFromPtr(&tolower);
    if (std.mem.eql(u8, name, "toupper")) return @intFromPtr(&toupper);
    if (std.mem.eql(u8, name, "isalnum")) return @intFromPtr(&isalnum);
    if (std.mem.eql(u8, name, "isalpha")) return @intFromPtr(&isalpha);
    if (std.mem.eql(u8, name, "iscntrl")) return @intFromPtr(&iscntrl);
    if (std.mem.eql(u8, name, "isdigit")) return @intFromPtr(&isdigit);
    if (std.mem.eql(u8, name, "isgraph")) return @intFromPtr(&isgraph);
    if (std.mem.eql(u8, name, "islower")) return @intFromPtr(&islower);
    if (std.mem.eql(u8, name, "isprint")) return @intFromPtr(&isprint);
    if (std.mem.eql(u8, name, "ispunct")) return @intFromPtr(&ispunct);
    if (std.mem.eql(u8, name, "isupper")) return @intFromPtr(&isupper);
    if (std.mem.eql(u8, name, "_strdup")) return @intFromPtr(&_strdup);
    if (std.mem.eql(u8, name, "_stricmp")) return @intFromPtr(&_stricmp);
    if (std.mem.eql(u8, name, "_strnicmp")) return @intFromPtr(&_strnicmp);
    if (std.mem.eql(u8, name, "_wcsnicmp")) return @intFromPtr(&_wcsnicmp);
    if (std.mem.eql(u8, name, "wcscpy")) return @intFromPtr(&wcscpy);
    if (std.mem.eql(u8, name, "wcsncmp")) return @intFromPtr(&wcsncmp);
    if (std.mem.eql(u8, name, "strcpy")) return @intFromPtr(&strcpy);
    if (std.mem.eql(u8, name, "strncpy")) return @intFromPtr(&strncpy);
    if (std.mem.eql(u8, name, "strcat")) return @intFromPtr(&strcat);
    if (std.mem.eql(u8, name, "strchr")) return @intFromPtr(&strchr);
    if (std.mem.eql(u8, name, "strrchr")) return @intFromPtr(&strrchr);
    if (std.mem.eql(u8, name, "strpbrk")) return @intFromPtr(&strpbrk);
    if (std.mem.eql(u8, name, "strspn")) return @intFromPtr(&strspn);
    if (std.mem.eql(u8, name, "strstr")) return @intFromPtr(&strstr);
    if (std.mem.eql(u8, name, "strtok")) return @intFromPtr(&strtok);
    if (std.mem.eql(u8, name, "memchr")) return @intFromPtr(&memchr);
    if (std.mem.eql(u8, name, "memcmp")) return @intFromPtr(&memcmp);
    if (std.mem.eql(u8, name, "memmove")) return @intFromPtr(&memmove);
    if (std.mem.eql(u8, name, "_strtoui64")) return @intFromPtr(&_strtoui64);
    if (std.mem.eql(u8, name, "_strtoi64")) return @intFromPtr(&_strtoi64);
    if (std.mem.eql(u8, name, "strtoul")) return @intFromPtr(&strtoul);
    if (std.mem.eql(u8, name, "strtol")) return @intFromPtr(&strtol);
    if (std.mem.eql(u8, name, "atoi")) return @intFromPtr(&atoi);
    if (std.mem.eql(u8, name, "atof")) return @intFromPtr(&atof);
    if (std.mem.eql(u8, name, "rand")) return @intFromPtr(&rand);
    if (std.mem.eql(u8, name, "srand")) return @intFromPtr(&srand);
    if (std.mem.eql(u8, name, "bsearch")) return @intFromPtr(&bsearch);
    if (std.mem.eql(u8, name, "qsort")) return @intFromPtr(&qsort);
    if (std.mem.eql(u8, name, "ldexp")) return @intFromPtr(&ldexp);

    // Formatting & Scanning
    if (std.mem.eql(u8, name, "_vsnprintf")) return @intFromPtr(&_vsnprintf);
    if (std.mem.eql(u8, name, "_vscprintf")) return @intFromPtr(&_vscprintf);
    if (std.mem.eql(u8, name, "sprintf")) return @intFromPtr(&sprintf);
    if (std.mem.eql(u8, name, "sscanf")) return @intFromPtr(&sscanf);

    // Control flow
    // NOT exported for 32-bit guests: the x86 jmp_buf layout is unverified.
    if (@sizeOf(usize) == 8) {
        if (std.mem.eql(u8, name, "_setjmp")) return @intFromPtr(&_setjmp_impl);
        if (std.mem.eql(u8, name, "longjmp")) return @intFromPtr(&longjmp_impl);
    }

    return null;
}
