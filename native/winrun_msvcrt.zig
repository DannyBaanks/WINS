// WINS — winrun_msvcrt.zig
// Native x86_64 Linux MSVCRT.dll shim for console and GUI PE32+ binaries.
// Implements the Win64 C runtime ABI (FILE streams, memory allocation, string/ctype
// routines, CRT startup/termination hooks, and data exports).

const std = @import("std");
const linux = std.os.linux;

const W: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

// ---------------------------------------------------------------------------
// 1. Data Exports & Global CRT State
// ---------------------------------------------------------------------------

pub var msvcrt_fmode: i32 = 0;
pub var msvcrt_commode: i32 = 0;
pub var msvcrt_initenv: usize = 0;
var thread_errno: i32 = 0;
var app_type: i32 = 1;

fn _errno() callconv(W) *i32 {
    return &thread_errno;
}

fn __p__fmode() callconv(W) *i32 {
    return &msvcrt_fmode;
}

fn __p__commode() callconv(W) *i32 {
    return &msvcrt_commode;
}

fn __set_app_type(at: i32) callconv(W) void {
    app_type = at;
}

fn __setusermatherr(handler: ?*anyopaque) callconv(W) void {
    _ = handler;
}

fn ___lc_codepage_func() callconv(W) u32 {
    return 65001; // CP_UTF8
}

fn ___mb_cur_max_func() callconv(W) i32 {
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

fn localeconv() callconv(W) *Lconv {
    return &default_lconv;
}

// ---------------------------------------------------------------------------
// 2. Command-Line Arguments & CRT Initialization
// ---------------------------------------------------------------------------

var arg_storage: [16][256:0]u8 = undefined;
var argv_ptrs: [17]?[*:0]u8 = .{null} ** 17;
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
    const count = @min(args.len, 16);
    if (count == 0) {
        ensureDefaultArgs();
        return;
    }
    for (0..count) |i| {
        const s = args[i];
        const copy_len = @min(s.len, 255);
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
) callconv(W) i32 {
    _ = dowildcard;
    _ = startinfo;
    ensureDefaultArgs();
    if (pargc) |p| p.* = saved_argc;
    if (pargv) |p| p.* = &argv_ptrs;
    if (penv) |p| p.* = &envp_ptrs;
    return 0;
}

const InitFunc = *const fn () callconv(W) void;

fn _initterm(begin: ?[*]const usize, end: ?[*]const usize) callconv(W) void {
    if (begin == null or end == null) return;
    var cur = @intFromPtr(begin.?);
    const stop = @intFromPtr(end.?);
    while (cur < stop) : (cur += @sizeOf(usize)) {
        const fn_addr = @as(*const usize, @ptrFromInt(cur)).*;
        if (fn_addr != 0) {
            const f: InitFunc = @ptrFromInt(fn_addr);
            f();
        }
    }
}

fn _onexit(func: ?*anyopaque) callconv(W) ?*anyopaque {
    return func;
}

fn _lock(locknum: i32) callconv(W) void {
    _ = locknum;
}

fn _unlock(locknum: i32) callconv(W) void {
    _ = locknum;
}

fn __C_specific_handler() callconv(W) i32 {
    return 1; // ExceptionContinueExecution / handler stub
}

fn signal(sig: i32, handler: ?*anyopaque) callconv(W) ?*anyopaque {
    _ = sig;
    return handler;
}

fn exit(status: i32) callconv(W) noreturn {
    linux.exit_group(@bitCast(status));
}

fn _exit(status: i32) callconv(W) noreturn {
    linux.exit_group(@bitCast(status));
}

fn _cexit() callconv(W) void {}

fn _c_exit() callconv(W) void {}

fn _amsg_exit(rterrnum: i32) callconv(W) noreturn {
    linux.exit_group(@bitCast(255 + rterrnum));
}

fn abort() callconv(W) noreturn {
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

fn malloc(size: usize) callconv(W) ?[*]u8 {
    if (!ensureCrtHeap()) return null;
    const req = if (size == 0) 16 else std.mem.alignForward(usize, size, 16);
    if (crt_heap_off + 16 + req > CRT_HEAP_CAP) return null;
    const hdr_ptr: *usize = @ptrFromInt(crt_heap_base + crt_heap_off);
    hdr_ptr.* = size;
    const user_ptr: [*]u8 = @ptrFromInt(crt_heap_base + crt_heap_off + 16);
    crt_heap_off += 16 + req;
    return user_ptr;
}

fn calloc(nmemb: usize, size: usize) callconv(W) ?[*]u8 {
    const total = nmemb *| size;
    const ptr = malloc(total) orelse return null;
    if (total > 0) @memset(ptr[0..total], 0);
    return ptr;
}

fn free(ptr: ?*anyopaque) callconv(W) void {
    _ = ptr;
}

fn realloc(ptr: ?*anyopaque, new_size: usize) callconv(W) ?[*]u8 {
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
// 4. FILE Streams & I/O (__iob_func, fopen, fread, fwrite, fgets, fputc, etc.)
// ---------------------------------------------------------------------------

pub const MsvcrtFile = extern struct {
    _ptr: ?[*]u8 = null, // +0x00
    _cnt: i32 = 0, // +0x08
    _pad0: i32 = 0, // +0x0c
    _base: ?[*]u8 = null, // +0x10
    _flag: i32 = 0, // +0x18
    _file: i32 = -1, // +0x1c
    _charbuf: i32 = 0, // +0x20
    _bufsiz: i32 = 0, // +0x24
    _tmpfname: ?[*]u8 = null, // +0x28
};

comptime {
    std.debug.assert(@sizeOf(MsvcrtFile) == 48);
}

const IOB_COUNT = 20;
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

fn __iob_func() callconv(W) [*]MsvcrtFile {
    return &iob_table;
}

fn __acrt_iob_func(idx: u32) callconv(W) ?*MsvcrtFile {
    if (idx >= IOB_COUNT) return null;
    return &iob_table[idx];
}

fn normalizePathA(src: [*:0]const u8, out: *[512:0]u8) void {
    var i: usize = 0;
    var start: usize = 0;
    if ((src[0] == 'C' or src[0] == 'c' or src[0] == 'Z' or src[0] == 'z') and src[1] == ':' and (src[2] == '\\' or src[2] == '/')) {
        start = 2;
    }
    while (src[start + i] != 0 and i < 511) : (i += 1) {
        const ch = src[start + i];
        out[i] = if (ch == '\\') '/' else ch;
    }
    out[i] = 0;
}

fn fopen(filename: ?[*:0]const u8, mode: ?[*:0]const u8) callconv(W) ?*MsvcrtFile {
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
    if (linux.errno(rc) != .SUCCESS) return null;

    iob_table[idx] = .{
        ._file = @intCast(rc),
        ._flag = if (has_w or has_a) 0x0002 else 0x0001,
    };
    iob_in_use[idx] = true;
    iob_binary[idx] = has_b;
    iob_ungetc[idx] = -1;
    return &iob_table[idx];
}

fn fclose(stream: ?*MsvcrtFile) callconv(W) i32 {
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

fn fflush(stream: ?*MsvcrtFile) callconv(W) i32 {
    _ = stream;
    return 0;
}

fn fseek(stream: ?*MsvcrtFile, offset: i32, whence: i32) callconv(W) i32 {
    const s = stream orelse return -1;
    if (streamIndex(stream)) |idx| {
        iob_ungetc[idx] = -1;
    }
    s._flag &= ~@as(i32, 0x10);
    const rc = linux.lseek(s._file, @as(i64, offset), @intCast(whence));
    if (linux.errno(rc) != .SUCCESS) return -1;
    return 0;
}

fn ftell(stream: ?*MsvcrtFile) callconv(W) i32 {
    const s = stream orelse return -1;
    const rc = linux.lseek(s._file, 0, linux.SEEK.CUR);
    if (linux.errno(rc) != .SUCCESS) return -1;
    var pos: i32 = @intCast(rc);
    if (streamIndex(stream)) |idx| {
        if (iob_ungetc[idx] >= 0 and pos > 0) pos -= 1;
    }
    return pos;
}

fn writeRawAll(fd: i32, data: []const u8) bool {
    var off: usize = 0;
    while (off < data.len) {
        const rc = linux.write(fd, data[off..].ptr, data.len - off);
        if (linux.errno(rc) != .SUCCESS) return false;
        if (rc == 0) break;
        off += rc;
    }
    return true;
}

fn fputc(c: i32, stream: ?*MsvcrtFile) callconv(W) i32 {
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

fn fwrite(ptr: ?[*]const u8, size: usize, nmemb: usize, stream: ?*MsvcrtFile) callconv(W) usize {
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

fn getc(stream: ?*MsvcrtFile) callconv(W) i32 {
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

fn ungetc(c: i32, stream: ?*MsvcrtFile) callconv(W) i32 {
    if (c < 0) return -1;
    if (streamIndex(stream)) |idx| {
        iob_ungetc[idx] = c & 0xFF;
        stream.?._flag &= ~@as(i32, 0x10);
        return c & 0xFF;
    }
    return -1;
}

fn fread(ptr: ?[*]u8, size: usize, nmemb: usize, stream: ?*MsvcrtFile) callconv(W) usize {
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

fn fgets(buf: ?[*]u8, n: i32, stream: ?*MsvcrtFile) callconv(W) ?[*]u8 {
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

fn vfprintf(stream: ?*MsvcrtFile, fmt: ?[*:0]const u8, ap_raw: ?[*]const usize) callconv(W) i32 {
    if (stream == null or fmt == null) return -1;
    var out_buf: [4096]u8 = undefined;
    var out_len: usize = 0;
    var arg_idx: usize = 0;

    const flushBuf = struct {
        fn run(s: *MsvcrtFile, b: []const u8) void {
            _ = fwrite(b.ptr, 1, b.len, s);
        }
    }.run;

    var fi: usize = 0;
    var total_written: i32 = 0;
    while (fmt.?[fi] != 0) {
        if (fmt.?[fi] != '%') {
            if (out_len == out_buf.len) {
                flushBuf(stream.?, out_buf[0..out_len]);
                total_written += @intCast(out_len);
                out_len = 0;
            }
            out_buf[out_len] = fmt.?[fi];
            out_len += 1;
            fi += 1;
            continue;
        }
        fi += 1; // skip '%'
        if (fmt.?[fi] == '%') {
            if (out_len == out_buf.len) {
                flushBuf(stream.?, out_buf[0..out_len]);
                total_written += @intCast(out_len);
                out_len = 0;
            }
            out_buf[out_len] = '%';
            out_len += 1;
            fi += 1;
            continue;
        }

        // Parse optional zero-pad / width
        var zero_pad = false;
        if (fmt.?[fi] == '0') {
            zero_pad = true;
            fi += 1;
        }
        var width: usize = 0;
        while (fmt.?[fi] >= '0' and fmt.?[fi] <= '9') : (fi += 1) {
            width = width * 10 + (fmt.?[fi] - '0');
        }
        // Length modifiers
        var is_long = false;
        while (fmt.?[fi] == 'l' or fmt.?[fi] == 'z' or fmt.?[fi] == 'I') : (fi += 1) {
            is_long = true;
        }

        const spec = fmt.?[fi];
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
                }
            },
            'c' => {
                tmp[0] = @intCast(arg_val & 0xFF);
                piece = tmp[0..1];
            },
            'd', 'i' => {
                const sval: i64 = if (is_long) @bitCast(arg_val) else @as(i64, @as(i32, @truncate(@as(isize, @bitCast(arg_val)))));
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
            else => {},
        }

        if (width > piece.len) {
            const pad_len = width - piece.len;
            const pad_ch: u8 = if (zero_pad) '0' else ' ';
            for (0..pad_len) |_| {
                if (out_len == out_buf.len) {
                    flushBuf(stream.?, out_buf[0..out_len]);
                    total_written += @intCast(out_len);
                    out_len = 0;
                }
                out_buf[out_len] = pad_ch;
                out_len += 1;
            }
        }
        for (piece) |ch| {
            if (out_len == out_buf.len) {
                flushBuf(stream.?, out_buf[0..out_len]);
                total_written += @intCast(out_len);
                out_len = 0;
            }
            out_buf[out_len] = ch;
            out_len += 1;
        }
    }
    if (out_len > 0) {
        flushBuf(stream.?, out_buf[0..out_len]);
        total_written += @intCast(out_len);
    }
    return total_written;
}

fn fprintf(stream: ?*MsvcrtFile, fmt: ?[*:0]const u8, a1: usize, a2: usize, a3: usize, a4: usize) callconv(W) i32 {
    const args = [_]usize{ a1, a2, a3, a4 };
    return vfprintf(stream, fmt, &args);
}

// ---------------------------------------------------------------------------
// 5. String, Memory & CType Functions
// ---------------------------------------------------------------------------

fn strlen(s: ?[*:0]const u8) callconv(W) usize {
    const p = s orelse return 0;
    var n: usize = 0;
    while (p[n] != 0) : (n += 1) {}
    return n;
}

fn wcslen(s: ?[*:0]const u16) callconv(W) usize {
    const p = s orelse return 0;
    var n: usize = 0;
    while (p[n] != 0) : (n += 1) {}
    return n;
}

fn strcmp(s1: ?[*:0]const u8, s2: ?[*:0]const u8) callconv(W) i32 {
    const a = s1 orelse return -1;
    const b = s2 orelse return 1;
    var i: usize = 0;
    while (a[i] != 0 and a[i] == b[i]) : (i += 1) {}
    return @as(i32, a[i]) - @as(i32, b[i]);
}

fn strncmp(s1: ?[*:0]const u8, s2: ?[*:0]const u8, n: usize) callconv(W) i32 {
    if (n == 0) return 0;
    const a = s1 orelse return -1;
    const b = s2 orelse return 1;
    var i: usize = 0;
    while (i + 1 < n and a[i] != 0 and a[i] == b[i]) : (i += 1) {}
    return @as(i32, a[i]) - @as(i32, b[i]);
}

fn strcspn(s: ?[*:0]const u8, reject: ?[*:0]const u8) callconv(W) usize {
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

fn strerror(errnum: i32) callconv(W) [*:0]const u8 {
    _ = errnum;
    return "Success";
}

fn memcpy(dest: ?[*]u8, src: ?[*]const u8, n: usize) callconv(W) ?[*]u8 {
    if (dest != null and src != null and n > 0) {
        @memcpy(dest.?[0..n], src.?[0..n]);
    }
    return dest;
}

fn memset(dest: ?[*]u8, c: i32, n: usize) callconv(W) ?[*]u8 {
    if (dest != null and n > 0) {
        @memset(dest.?[0..n], @intCast(c & 0xFF));
    }
    return dest;
}

fn isspace(c: i32) callconv(W) i32 {
    return switch (c) {
        ' ', '\t', '\n', '\r', 0x0b, 0x0c => 1,
        else => 0,
    };
}

fn isxdigit(c: i32) callconv(W) i32 {
    return switch (c) {
        '0'...'9', 'a'...'f', 'A'...'F' => 1,
        else => 0,
    };
}

fn tolower(c: i32) callconv(W) i32 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
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

fn _strtoui64(s: ?[*:0]const u8, endptr: ?*?[*:0]const u8, base: i32) callconv(W) u64 {
    var neg = false;
    const val = parseUnsigned(s, endptr, base, &neg);
    return if (neg) 0 -% val else val;
}

fn _strtoi64(s: ?[*:0]const u8, endptr: ?*?[*:0]const u8, base: i32) callconv(W) i64 {
    var neg = false;
    const val = parseUnsigned(s, endptr, base, &neg);
    if (neg) return -@as(i64, @intCast(@min(val, @as(u64, @intCast(std.math.maxInt(i64))))));
    return @intCast(@min(val, @as(u64, @intCast(std.math.maxInt(i64)))));
}

fn strtoul(s: ?[*:0]const u8, endptr: ?*?[*:0]const u8, base: i32) callconv(W) u32 {
    return @truncate(_strtoui64(s, endptr, base));
}

fn strtol(s: ?[*:0]const u8, endptr: ?*?[*:0]const u8, base: i32) callconv(W) i32 {
    return @truncate(_strtoi64(s, endptr, base));
}

// ---------------------------------------------------------------------------
// 6. Lookup Dispatch Table
// ---------------------------------------------------------------------------

pub fn lookup(name: []const u8) ?usize {
    // Data exports
    if (std.mem.eql(u8, name, "_fmode")) return @intFromPtr(&msvcrt_fmode);
    if (std.mem.eql(u8, name, "_commode")) return @intFromPtr(&msvcrt_commode);
    if (std.mem.eql(u8, name, "__initenv")) return @intFromPtr(&msvcrt_initenv);

    // CRT startup & environment
    if (std.mem.eql(u8, name, "_errno")) return @intFromPtr(&_errno);
    if (std.mem.eql(u8, name, "__p__fmode")) return @intFromPtr(&__p__fmode);
    if (std.mem.eql(u8, name, "__p__commode")) return @intFromPtr(&__p__commode);
    if (std.mem.eql(u8, name, "__set_app_type")) return @intFromPtr(&__set_app_type);
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
    if (std.mem.eql(u8, name, "fwrite")) return @intFromPtr(&fwrite);
    if (std.mem.eql(u8, name, "getc")) return @intFromPtr(&getc);
    if (std.mem.eql(u8, name, "fgetc")) return @intFromPtr(&getc);
    if (std.mem.eql(u8, name, "ungetc")) return @intFromPtr(&ungetc);
    if (std.mem.eql(u8, name, "fread")) return @intFromPtr(&fread);
    if (std.mem.eql(u8, name, "fgets")) return @intFromPtr(&fgets);
    if (std.mem.eql(u8, name, "vfprintf")) return @intFromPtr(&vfprintf);
    if (std.mem.eql(u8, name, "fprintf")) return @intFromPtr(&fprintf);

    // Strings & CType
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
    if (std.mem.eql(u8, name, "_strtoui64")) return @intFromPtr(&_strtoui64);
    if (std.mem.eql(u8, name, "_strtoi64")) return @intFromPtr(&_strtoi64);
    if (std.mem.eql(u8, name, "strtoul")) return @intFromPtr(&strtoul);
    if (std.mem.eql(u8, name, "strtol")) return @intFromPtr(&strtol);

    return null;
}
