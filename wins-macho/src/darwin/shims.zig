const std = @import("std");
const trace = @import("../runtime/trace.zig");
const fs_shim = @import("filesystem.zig");
const objc_shim = @import("objc.zig");
const foundation = @import("foundation.zig");
const swift_shim = @import("swift.zig");
const dispatch_shim = @import("dispatch.zig");
const libcxx = @import("libcxx.zig");
const c_pwd = @cImport({
    @cInclude("pwd.h");
});

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
extern "c" fn vsprintf(str: [*]u8, fmt: [*:0]const u8, ap: *std.builtin.VaList) c_int;
extern "c" fn vsnprintf(str: [*]u8, size: usize, fmt: [*:0]const u8, ap: *std.builtin.VaList) c_int;
extern "c" fn vfprintf(stream: *anyopaque, fmt: [*:0]const u8, ap: *std.builtin.VaList) c_int;
extern "c" fn sscanf(str: [*:0]const u8, fmt: [*:0]const u8, ...) c_int;
extern "c" fn getgrgid(gid: u32) ?*anyopaque;
extern "c" fn fileno(stream: *anyopaque) c_int;
extern "c" fn ferror(stream: *anyopaque) c_int;
extern "c" fn feof(stream: *anyopaque) c_int;
extern "c" fn clearerr(stream: *anyopaque) void;
extern "c" fn fgetc(stream: *anyopaque) c_int;
extern "c" fn ungetc(c: c_int, stream: *anyopaque) c_int;
extern "c" fn rewind(stream: *anyopaque) void;
extern "c" fn setbuf(stream: *anyopaque, buf: ?[*]u8) void;
extern "c" fn perror(s: ?[*:0]const u8) void;
extern "c" fn remove(path: [*:0]const u8) c_int;
extern "c" fn strdup(s: [*:0]const u8) ?[*:0]u8;
extern "c" fn strcat(dst: [*]u8, src: [*:0]const u8) [*]u8;
extern "c" fn strtol(nptr: [*:0]const u8, endptr: ?*[*:0]u8, base: c_int) c_long;
extern "c" fn strtod(nptr: [*:0]const u8, endptr: ?*[*:0]u8) f64;
extern "c" fn strspn(s: [*:0]const u8, accept: [*:0]const u8) usize;
extern "c" fn strerror(errnum: c_int) [*:0]u8;
extern "c" fn memmem(haystack: *const anyopaque, haystacklen: usize, needle: *const anyopaque, needlelen: usize) ?*const anyopaque;
extern "c" fn dirname(path: ?[*:0]u8) [*:0]u8;
extern "c" fn atexit(func: *const fn () callconv(.c) void) c_int;
extern "c" fn fchmod(fd: c_int, mode: u32) c_int;
extern "c" fn fchown(fd: c_int, owner: u32, group: u32) c_int;
extern "c" fn utime(filename: [*:0]const u8, times: ?*const anyopaque) c_int;
extern "c" fn signal(signum: c_int, handler: ?*const anyopaque) ?*const anyopaque;
extern "c" fn raise(sig: c_int) c_int;
extern "c" fn fcntl(fd: c_int, cmd: c_int, ...) c_int;
extern "c" fn pathconf(path: [*:0]const u8, name: c_int) c_long;
extern "c" fn localtime_r(timep: *const i64, result: *anyopaque) ?*anyopaque;
extern "c" fn gmtime_r(timep: *const i64, result: *anyopaque) ?*anyopaque;
extern "c" fn gmtime(timep: *const i64) ?*anyopaque;
extern "c" fn mktime(tm: *anyopaque) i64;
extern "c" fn timegm(tm: *anyopaque) i64;
extern "c" fn strptime(s: [*:0]const u8, format: [*:0]const u8, tm: *anyopaque) ?[*:0]const u8;
extern "c" fn gettimeofday(tv: *LinuxTimeval, tz: ?*anyopaque) c_int;
extern "c" fn pthread_key_create(key: *u32, destructor: ?*const fn (?*anyopaque) callconv(.c) void) c_int;
extern "c" fn pthread_getspecific(key: u32) ?*anyopaque;
extern "c" fn pthread_setspecific(key: u32, value: ?*const anyopaque) c_int;
extern "c" fn sched_yield() c_int;
extern "c" fn dup(oldfd: c_int) c_int;
extern "c" fn dup2(oldfd: c_int, newfd: c_int) c_int;
extern "c" fn pipe(pipefd: *[2]c_int) c_int;
extern "c" fn fork() c_int;
extern "c" fn wait(wstatus: ?*c_int) c_int;
extern "c" fn waitpid(pid: c_int, wstatus: ?*c_int, options: c_int) c_int;
extern "c" fn execl(path: [*:0]const u8, arg0: ?[*:0]const u8, ...) c_int;
extern "c" fn execv(path: [*:0]const u8, argv: [*c]const [*c]u8) c_int;
extern "c" fn execvp(file: [*:0]const u8, argv: [*c]const [*c]u8) c_int;
extern "c" fn kill(pid: c_int, sig: c_int) c_int;
extern "c" fn system(command: ?[*:0]const u8) c_int;
extern "c" fn random() c_long;
extern "c" fn srandom(seed: c_uint) void;
extern "c" fn localeconv() ?*anyopaque;
extern "c" fn uselocale(newloc: ?*anyopaque) ?*anyopaque;
extern "c" fn __ctype_get_mb_cur_max() usize;
extern "c" fn flockfile(stream: *anyopaque) void;
extern "c" fn funlockfile(stream: *anyopaque) void;
extern "c" fn putc_unlocked(c: c_int, stream: *anyopaque) c_int;
extern "c" fn freopen(path: ?[*:0]const u8, mode: [*:0]const u8, stream: *anyopaque) ?*anyopaque;
extern "c" fn vprintf(fmt: [*:0]const u8, ap: *std.builtin.VaList) c_int;
extern "c" fn setvbuf(stream: *anyopaque, buf: ?[*]u8, mode: c_int, size: usize) c_int;
extern "c" fn popen(command: [*:0]const u8, mode: [*:0]const u8) ?*anyopaque;
extern "c" fn pclose(stream: *anyopaque) c_int;
extern "c" fn lseek(fd: c_int, offset: i64, whence: c_int) i64;
extern "c" fn openat(dirfd: c_int, path: [*:0]const u8, flags: c_int, ...) c_int;
extern "c" fn mkstemp(template: [*]u8) c_int;
extern "c" fn mkostemp(template: [*]u8, flags: c_int) c_int;
extern "c" fn rename(oldpath: [*:0]const u8, newpath: [*:0]const u8) c_int;
extern "c" fn chmod(path: [*:0]const u8, mode: u32) c_int;
extern "c" fn umask(mask: u32) u32;
extern "c" fn stpcpy(dst: [*]u8, src: [*:0]const u8) [*]u8;
extern "c" fn strnlen(s: [*]const u8, maxlen: usize) usize;
extern "c" fn strtoimax(nptr: [*:0]const u8, endptr: ?*[*:0]u8, base: c_int) i64;
extern "c" fn tzset() void;
extern "c" fn timespec_get(ts: *std.c.timespec, base: c_int) c_int;
extern "c" fn clock() c_long;
extern "c" fn qsort_r(base: *anyopaque, nmemb: usize, size: usize, compar: *const fn (*const anyopaque, *const anyopaque, ?*anyopaque) callconv(.c) c_int, arg: ?*anyopaque) void;
extern "c" fn pthread_cond_init(cond: *anyopaque, attr: ?*const anyopaque) c_int;
extern "c" fn pthread_cond_destroy(cond: *anyopaque) c_int;
extern "c" fn pthread_cond_wait(cond: *anyopaque, mutex: *anyopaque) c_int;
extern "c" fn pthread_cond_signal(cond: *anyopaque) c_int;
extern "c" fn pthread_cond_broadcast(cond: *anyopaque) c_int;
extern "c" fn mbrtowc(pwc: ?*u32, s: ?[*]const u8, n: usize, ps: ?*anyopaque) usize;
extern "c" fn mbsinit(ps: ?*const anyopaque) c_int;
extern "c" fn wcrtomb(s: ?[*]u8, wc: u32, ps: ?*anyopaque) usize;
extern "c" fn mbsrtowcs(dst: ?[*]u32, src: *?[*]const u8, len: usize, ps: ?*anyopaque) usize;
extern "c" fn btowc(c: c_int) u32;
extern "c" fn wctob(c: u32) c_int;
extern "c" fn wcwidth(c: u32) c_int;
extern "c" fn wctype(name: [*:0]const u8) usize;
extern "c" fn wcslen(s: [*]const u32) usize;
extern "c" fn wcscat(dst: [*]u32, src: [*]const u32) [*]u32;
extern "c" fn wmemcpy(dst: [*]u32, src: [*]const u32, n: usize) [*]u32;
extern "c" fn wmemchr(s: [*]const u32, c: u32, n: usize) ?[*]const u32;
extern "c" fn isalnum(c: c_int) c_int;
extern "c" fn isalpha(c: c_int) c_int;
extern "c" fn isblank(c: c_int) c_int;
extern "c" fn iscntrl(c: c_int) c_int;
extern "c" fn isdigit(c: c_int) c_int;
extern "c" fn isgraph(c: c_int) c_int;
extern "c" fn islower(c: c_int) c_int;
extern "c" fn isprint(c: c_int) c_int;
extern "c" fn ispunct(c: c_int) c_int;
extern "c" fn isspace(c: c_int) c_int;
extern "c" fn isupper(c: c_int) c_int;
extern "c" fn isxdigit(c: c_int) c_int;
extern "c" fn chown(path: [*:0]const u8, owner: u32, group: u32) c_int;
extern "c" fn mkdir(path: [*:0]const u8, mode: u32) c_int;
extern "c" fn setpriority(which: c_int, who: u32, prio: c_int) c_int;
extern "c" fn mmap(addr: ?*anyopaque, len: usize, prot: c_int, flags: c_int, fd: c_int, offset: i64) ?*anyopaque;
extern "c" fn munmap(addr: ?*anyopaque, len: usize) c_int;
extern "c" fn backtrace(buffer: [*]?*anyopaque, size: c_int) c_int;
extern "c" fn backtrace_symbols(buffer: [*]const ?*anyopaque, size: c_int) ?[*][*:0]u8;
extern "c" fn getopt_long(argc: c_int, argv: [*c]const [*c]u8, optstring: [*:0]const u8, longopts: ?*const anyopaque, longindex: ?*c_int) c_int;
extern "c" var optind: c_int;
extern "c" var optarg: ?[*:0]u8;
extern "c" fn dlopen(filename: ?[*:0]const u8, flags: c_int) ?*anyopaque;
extern "c" fn dlsym(handle: ?*anyopaque, symbol: [*:0]const u8) ?*anyopaque;
extern "c" var environ: [*c][*c]u8;

// libm math functions (identical System V AMD64 ABI on Darwin & Linux)
extern "c" fn sin(x: f64) f64;
extern "c" fn cos(x: f64) f64;
extern "c" fn tan(x: f64) f64;
extern "c" fn asin(x: f64) f64;
extern "c" fn acos(x: f64) f64;
extern "c" fn atan(x: f64) f64;
extern "c" fn atan2(y: f64, x: f64) f64;
extern "c" fn sinh(x: f64) f64;
extern "c" fn cosh(x: f64) f64;
extern "c" fn tanh(x: f64) f64;
extern "c" fn asinh(x: f64) f64;
extern "c" fn acosh(x: f64) f64;
extern "c" fn atanh(x: f64) f64;
extern "c" fn exp(x: f64) f64;
extern "c" fn exp2(x: f64) f64;
extern "c" fn expm1(x: f64) f64;
extern "c" fn log(x: f64) f64;
extern "c" fn log2(x: f64) f64;
extern "c" fn log10(x: f64) f64;
extern "c" fn log1p(x: f64) f64;
extern "c" fn logb(x: f64) f64;
extern "c" fn pow(x: f64, y: f64) f64;
extern "c" fn cbrt(x: f64) f64;
extern "c" fn hypot(x: f64, y: f64) f64;
extern "c" fn fmod(x: f64, y: f64) f64;
extern "c" fn remainder(x: f64, y: f64) f64;
extern "c" fn fma(x: f64, y: f64, z: f64) f64;
extern "c" fn fdim(x: f64, y: f64) f64;
extern "c" fn frexp(x: f64, exp_out: *c_int) f64;
extern "c" fn ldexp(x: f64, exp_in: c_int) f64;
extern "c" fn modf(x: f64, iptr: *f64) f64;
extern "c" fn erf(x: f64) f64;
extern "c" fn erfc(x: f64) f64;
extern "c" fn lgamma(x: f64) f64;
extern "c" fn lgamma_r(x: f64, signp: *c_int) f64;
extern "c" fn tgamma(x: f64) f64;
extern "c" fn j0(x: f64) f64;
extern "c" fn j1(x: f64) f64;
extern "c" fn jn(n: c_int, x: f64) f64;
extern "c" fn y0(x: f64) f64;
extern "c" fn y1(x: f64) f64;
extern "c" fn yn(n: c_int, x: f64) f64;
extern "c" fn nextafter(x: f64, y: f64) f64;
extern "c" fn nexttoward(x: f64, y: f80) f64;
extern "c" fn scalbln(x: f64, n: c_long) f64;
extern "c" fn scalb(x: f64, n: f64) f64;

const LinuxTimeval = extern struct {
    tv_sec: i64,
    tv_usec: i64,
};

const DarwinTimeval = extern struct {
    tv_sec: i64,
    tv_usec: i32,
    _pad: i32 = 0,
};

// Darwin x86_64 struct __sFILE wrapper around Linux glibc FILE*
// Keeps _p=null, _r=0, _w=0 so Darwin inline getc/putc macros always trap into
// ___srget / ___swbuf, and keeps _flags (__SEOF=0x20, __SERR=0x40) & _file synced
// so Darwin inline feof/ferror/fileno macros read exact real state.
const DARWIN_FILE_MAGIC: u32 = 0x4446_494C; // 'DFIL'

pub const DarwinFile = extern struct {
    _p: ?[*]u8 = null, // 0
    _r: c_int = 0, // 8
    _w: c_int = 0, // 12
    _flags: i16 = 0, // 16: __SEOF=0x20, __SERR=0x40
    _file: i16 = -1, // 18: fileno
    _pad0: u32 = 0, // 20
    _bf_base: ?[*]u8 = null, // 24
    _bf_size: c_int = 0, // 32
    _lbfsize: c_int = 0, // 36
    _cookie: ?*anyopaque = null, // 40
    _close: usize = 0, // 48
    _read: usize = 0, // 56
    _seek: usize = 0, // 64
    _write: usize = 0, // 72
    _ub_base: ?[*]u8 = null, // 80
    _ub_size: c_int = 0, // 88
    _pad1: c_int = 0, // 92
    _extra: ?*anyopaque = null, // 96
    _ur: c_int = 0, // 104
    _ubuf: [3]u8 = .{0} ** 3, // 108
    _nbuf: [1]u8 = .{0}, // 111
    _lb_base: ?[*]u8 = null, // 112
    _lb_size: c_int = 0, // 120
    _blksize: c_int = 0, // 124
    _offset: i64 = 0, // 128
    _pad_end: [16]u8 = .{0} ** 16, // 136..152
    wins_magic: u32 = DARWIN_FILE_MAGIC, // 152
    is_std: u32 = 0, // 156
    linux_fp: ?*anyopaque = null, // 160
};

comptime {
    std.debug.assert(@offsetOf(DarwinFile, "_p") == 0);
    std.debug.assert(@offsetOf(DarwinFile, "_r") == 8);
    std.debug.assert(@offsetOf(DarwinFile, "_w") == 12);
    std.debug.assert(@offsetOf(DarwinFile, "_flags") == 16);
    std.debug.assert(@offsetOf(DarwinFile, "_file") == 18);
}

var darwin_stdin_file: DarwinFile = .{ .is_std = 1 };
var darwin_stdout_file: DarwinFile = .{ .is_std = 1 };
var darwin_stderr_file: DarwinFile = .{ .is_std = 1 };

// Data globals for Darwin ABI
var darwin_stack_chk_guard: usize = 0x595a5f4d4143484f;
var darwin_stdoutp: ?*anyopaque = null;
var darwin_stderrp: ?*anyopaque = null;
var darwin_stdinp: ?*anyopaque = null;

fn syncDarwinFile(df: *DarwinFile) void {
    df._p = null;
    df._r = 0;
    df._w = 0;
    if (df.linux_fp) |lfp| {
        var fl: i16 = 0;
        if (feof(lfp) != 0) fl |= 0x0020; // __SEOF
        if (ferror(lfp) != 0) fl |= 0x0040; // __SERR
        df._flags = fl;
        df._file = @truncate(fileno(lfp));
    }
}

fn wrapLinuxFile(lx_opt: ?*anyopaque) ?*anyopaque {
    const lfp = lx_opt orelse return null;
    const raw = calloc(1, @sizeOf(DarwinFile)) orelse return null;
    const df: *DarwinFile = @ptrCast(@alignCast(raw));
    df.* = .{ .wins_magic = DARWIN_FILE_MAGIC, .is_std = 0, .linux_fp = lfp };
    syncDarwinFile(df);
    return raw;
}

fn asDarwinFile(stream: ?*anyopaque) ?*DarwinFile {
    const ptr = stream orelse return null;
    const df: *DarwinFile = @ptrCast(@alignCast(ptr));
    if (df.wins_magic == DARWIN_FILE_MAGIC) return df;
    return null;
}

fn unwrapFile(stream: *anyopaque) *anyopaque {
    if (asDarwinFile(stream)) |df| {
        if (df.linux_fp) |lfp| return lfp;
    }
    return stream;
}

fn syncMaybeDarwin(stream: ?*anyopaque) void {
    if (asDarwinFile(stream)) |df| syncDarwinFile(df);
}

pub fn initGlobals() void {
    if (darwin_stdoutp == null) {
        darwin_stdout_file.linux_fp = fdopen(1, "w");
        syncDarwinFile(&darwin_stdout_file);
        darwin_stdoutp = @ptrCast(&darwin_stdout_file);
    }
    if (darwin_stderrp == null) {
        darwin_stderr_file.linux_fp = fdopen(2, "w");
        syncDarwinFile(&darwin_stderr_file);
        darwin_stderrp = @ptrCast(&darwin_stderr_file);
    }
    if (darwin_stdinp == null) {
        darwin_stdin_file.linux_fp = fdopen(0, "r");
        syncDarwinFile(&darwin_stdin_file);
        darwin_stdinp = @ptrCast(&darwin_stdin_file);
    }
}

// Darwin FILE* shims (wrap/unwrap + sync _r/_w/_flags/_file)
fn shim_fopen(path: [*:0]const u8, mode: [*:0]const u8) callconv(.c) ?*anyopaque {
    return wrapLinuxFile(fopen(path, mode));
}

fn shim_fdopen(fd: c_int, mode: [*:0]const u8) callconv(.c) ?*anyopaque {
    return wrapLinuxFile(fdopen(fd, mode));
}

fn shim_popen(cmd: [*:0]const u8, mode: [*:0]const u8) callconv(.c) ?*anyopaque {
    return wrapLinuxFile(popen(cmd, mode));
}

fn shim_freopen(path: ?[*:0]const u8, mode: [*:0]const u8, stream: *anyopaque) callconv(.c) ?*anyopaque {
    const lfp = freopen(path, mode, unwrapFile(stream)) orelse return null;
    if (asDarwinFile(stream)) |df| {
        df.linux_fp = lfp;
        syncDarwinFile(df);
        return stream;
    }
    return wrapLinuxFile(lfp);
}

fn shim_fclose(stream: *anyopaque) callconv(.c) c_int {
    if (asDarwinFile(stream)) |df| {
        const rc = if (df.linux_fp) |lfp| fclose(lfp) else 0;
        df.linux_fp = null;
        if (df.is_std == 0) free(stream);
        return rc;
    }
    return fclose(stream);
}

fn shim_pclose(stream: *anyopaque) callconv(.c) c_int {
    if (asDarwinFile(stream)) |df| {
        const rc = if (df.linux_fp) |lfp| pclose(lfp) else -1;
        df.linux_fp = null;
        if (df.is_std == 0) free(stream);
        return rc;
    }
    return pclose(stream);
}

fn shim_fread(ptr: *anyopaque, size: usize, nmemb: usize, stream: *anyopaque) callconv(.c) usize {
    const rc = fread(ptr, size, nmemb, unwrapFile(stream));
    syncMaybeDarwin(stream);
    return rc;
}

fn shim_fwrite(ptr: *const anyopaque, size: usize, nmemb: usize, stream: *anyopaque) callconv(.c) usize {
    const rc = fwrite(ptr, size, nmemb, unwrapFile(stream));
    syncMaybeDarwin(stream);
    return rc;
}

fn shim_fflush(stream: ?*anyopaque) callconv(.c) c_int {
    if (stream == null) {
        const rc = fflush(null);
        syncDarwinFile(&darwin_stdout_file);
        syncDarwinFile(&darwin_stderr_file);
        return rc;
    }
    const rc = fflush(unwrapFile(stream.?));
    syncMaybeDarwin(stream);
    return rc;
}

fn shim_fseek(stream: *anyopaque, offset: c_long, whence: c_int) callconv(.c) c_int {
    const rc = fseek(unwrapFile(stream), offset, whence);
    syncMaybeDarwin(stream);
    return rc;
}

fn shim_ftell(stream: *anyopaque) callconv(.c) c_long {
    return ftell(unwrapFile(stream));
}

fn shim_fgets(s: [*]u8, size: c_int, stream: *anyopaque) callconv(.c) ?[*]u8 {
    const rc = fgets(s, size, unwrapFile(stream));
    syncMaybeDarwin(stream);
    return rc;
}

fn shim_fgetc(stream: *anyopaque) callconv(.c) c_int {
    const rc = fgetc(unwrapFile(stream));
    syncMaybeDarwin(stream);
    return rc;
}

fn shim_getchar() callconv(.c) c_int {
    initGlobals();
    return shim_fgetc(darwin_stdinp.?);
}

fn shim_ungetc(c: c_int, stream: *anyopaque) callconv(.c) c_int {
    const rc = ungetc(c, unwrapFile(stream));
    syncMaybeDarwin(stream);
    return rc;
}

fn shim_fputc(c: c_int, stream: *anyopaque) callconv(.c) c_int {
    const rc = fputc(c, unwrapFile(stream));
    syncMaybeDarwin(stream);
    return rc;
}

fn shim_putc_unlocked(c: c_int, stream: *anyopaque) callconv(.c) c_int {
    const rc = putc_unlocked(c, unwrapFile(stream));
    syncMaybeDarwin(stream);
    return rc;
}

fn shim_fputs(s: [*:0]const u8, stream: *anyopaque) callconv(.c) c_int {
    const rc = fputs(s, unwrapFile(stream));
    syncMaybeDarwin(stream);
    return rc;
}

fn shim_fprintf(stream: *anyopaque, fmt: [*:0]const u8, ...) callconv(.c) c_int {
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    const rc = vfprintf(unwrapFile(stream), fmt, &ap);
    syncMaybeDarwin(stream);
    return rc;
}

fn shim_vfprintf(stream: *anyopaque, fmt: [*:0]const u8, ap: *std.builtin.VaList) callconv(.c) c_int {
    const rc = vfprintf(unwrapFile(stream), fmt, ap);
    syncMaybeDarwin(stream);
    return rc;
}

fn shim_fileno(stream: *anyopaque) callconv(.c) c_int {
    return fileno(unwrapFile(stream));
}

fn shim_ferror(stream: *anyopaque) callconv(.c) c_int {
    const rc = ferror(unwrapFile(stream));
    syncMaybeDarwin(stream);
    return rc;
}

fn shim_feof(stream: *anyopaque) callconv(.c) c_int {
    const rc = feof(unwrapFile(stream));
    syncMaybeDarwin(stream);
    return rc;
}

fn shim_clearerr(stream: *anyopaque) callconv(.c) void {
    clearerr(unwrapFile(stream));
    syncMaybeDarwin(stream);
}

fn shim_rewind(stream: *anyopaque) callconv(.c) void {
    rewind(unwrapFile(stream));
    syncMaybeDarwin(stream);
}

fn shim_setbuf(stream: *anyopaque, buf: ?[*]u8) callconv(.c) void {
    setbuf(unwrapFile(stream), buf);
}

fn shim_setvbuf(stream: *anyopaque, buf: ?[*]u8, mode: c_int, size: usize) callconv(.c) c_int {
    return setvbuf(unwrapFile(stream), buf, mode, size);
}

fn shim_flockfile(stream: *anyopaque) callconv(.c) void {
    flockfile(unwrapFile(stream));
}

fn shim_funlockfile(stream: *anyopaque) callconv(.c) void {
    funlockfile(unwrapFile(stream));
}

fn shim_srget(stream: *anyopaque) callconv(.c) c_int {
    const rc = fgetc(unwrapFile(stream));
    syncMaybeDarwin(stream);
    return rc;
}

fn shim_swbuf(c: c_int, stream: *anyopaque) callconv(.c) c_int {
    const rc = fputc(c, unwrapFile(stream));
    syncMaybeDarwin(stream);
    return rc;
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

const MachoAtexitEntry = struct {
    fn_noarg: ?*const fn () callconv(.c) void = null,
    fn_cxa: ?*const fn (?*anyopaque) callconv(.c) void = null,
    arg: ?*anyopaque = null,
};

var macho_atexit_mutex: [64]u8 align(8) = .{0} ** 64;
var macho_atexit_fns: std.ArrayListUnmanaged(MachoAtexitEntry) = .empty;

fn shim_atexit(func: ?*const fn () callconv(.c) void) callconv(.c) c_int {
    record("_atexit");
    const f = func orelse return -1;
    _ = pthread_mutex_lock(&macho_atexit_mutex);
    defer _ = pthread_mutex_unlock(&macho_atexit_mutex);
    macho_atexit_fns.append(std.heap.c_allocator, .{ .fn_noarg = f }) catch return -1;
    return 0;
}

pub fn shim_cxa_atexit(func: ?*const fn (?*anyopaque) callconv(.c) void, arg: ?*anyopaque, dso_handle: ?*anyopaque) callconv(.c) c_int {
    _ = dso_handle;
    record("___cxa_atexit");
    const f = func orelse return -1;
    _ = pthread_mutex_lock(&macho_atexit_mutex);
    defer _ = pthread_mutex_unlock(&macho_atexit_mutex);
    macho_atexit_fns.append(std.heap.c_allocator, .{ .fn_cxa = f, .arg = arg }) catch return -1;
    return 0;
}

pub fn runMachoAtexitHandlers() void {
    while (true) {
        _ = pthread_mutex_lock(&macho_atexit_mutex);
        const e_opt = macho_atexit_fns.pop();
        _ = pthread_mutex_unlock(&macho_atexit_mutex);
        const e = e_opt orelse break;
        if (e.fn_noarg) |f| f();
        if (e.fn_cxa) |f| f(e.arg);
    }
}

fn shim_exit(status: c_int) callconv(.c) noreturn {
    record("_exit");
    runMachoAtexitHandlers();
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

var darwin_static_mutex_init_lock: [64]u8 align(8) = .{0} ** 64;

pub fn shim_pthread_mutex_lock(mutex: *anyopaque) callconv(.c) c_int {
    record("_pthread_mutex_lock");
    // Handle Darwin static PTHREAD_MUTEX_INITIALIZER (0x32AAABA7) race-free
    const sig_ptr: *u32 = @ptrCast(@alignCast(mutex));
    if (@atomicLoad(u32, sig_ptr, .acquire) == 0x32AAABA7) {
        _ = pthread_mutex_lock(&darwin_static_mutex_init_lock);
        if (@atomicLoad(u32, sig_ptr, .monotonic) == 0x32AAABA7) {
            var tmp: [64]u8 align(8) = .{0} ** 64;
            _ = pthread_mutex_init(&tmp, null);
            const dst: *[64]u8 = @ptrCast(mutex);
            @memcpy(dst[4..64], tmp[4..64]);
            @atomicStore(u32, sig_ptr, std.mem.readInt(u32, tmp[0..4], .little), .release);
        }
        _ = pthread_mutex_unlock(&darwin_static_mutex_init_lock);
    }
    return pthread_mutex_lock(mutex);
}

pub fn shim_pthread_mutex_unlock(mutex: *anyopaque) callconv(.c) c_int {
    record("_pthread_mutex_unlock");
    return pthread_mutex_unlock(mutex);
}

pub fn shim_pthread_mutex_destroy(mutex: *anyopaque) callconv(.c) c_int {
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
        const pages = sysconf(85); // _SC_PHYS_PAGES on Linux
        const psize = sysconf(30); // _SC_PAGESIZE on Linux
        val64 = if (pages > 0 and psize > 0) @as(u64, @intCast(pages)) * @as(u64, @intCast(psize)) else 0;
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
    record("____mb_cur_max");
    return @intCast(__ctype_get_mb_cur_max());
}

fn shim_mb_cur_max_l(loc: ?*anyopaque) callconv(.c) c_int {
    _ = loc;
    record("____mb_cur_max_l");
    return @intCast(__ctype_get_mb_cur_max());
}

fn shim_tolower(c: c_int) callconv(.c) c_int {
    record("___tolower");
    if (c < 0 or c >= 256) return c;
    return darwin_default_rune_locale.maplower[@intCast(c)];
}

fn shim_toupper(c: c_int) callconv(.c) c_int {
    record("___toupper");
    if (c < 0 or c >= 256) return c;
    return darwin_default_rune_locale.mapupper[@intCast(c)];
}

fn shim_strcat_chk(dst: [*]u8, src: [*:0]const u8, dstlen: usize) callconv(.c) [*]u8 {
    record("___strcat_chk");
    const dlen = strlen(@ptrCast(dst));
    const slen = strlen(src);
    if (dlen + slen >= dstlen) abort();
    return strcat(dst, src);
}

fn shim_assert_rtn(func: ?[*:0]const u8, file: ?[*:0]const u8, line: c_int, expr: ?[*:0]const u8) callconv(.c) noreturn {
    record("___assert_rtn");
    const f_s = if (func) |p| std.mem.span(p) else "?";
    const fi_s = if (file) |p| std.mem.span(p) else "?";
    const e_s = if (expr) |p| std.mem.span(p) else "?";
    std.debug.print("Assertion failed: ({s}), function {s}, file {s}, line {d}.\n", .{ e_s, f_s, fi_s, line });
    abort();
}

pub fn translateDarwinSignal(darwin_sig: c_int) c_int {
    return switch (darwin_sig) {
        10 => 7, // SIGBUS
        12 => 31, // SIGSYS
        16 => 23, // SIGURG
        17 => 19, // SIGSTOP
        18 => 20, // SIGTSTP
        19 => 18, // SIGCONT
        20 => 17, // SIGCHLD
        23 => 29, // SIGIO
        24 => 24, // SIGXCPU
        25 => 25, // SIGXFSZ
        26 => 26, // SIGVTALRM
        27 => 27, // SIGPROF
        28 => 28, // SIGWINCH
        30 => 10, // SIGUSR1
        31 => 12, // SIGUSR2
        else => darwin_sig,
    };
}

fn shim_signal(darwin_sig: c_int, handler: ?*const anyopaque) callconv(.c) ?*const anyopaque {
    record("_signal");
    return signal(translateDarwinSignal(darwin_sig), handler);
}

fn shim_raise(darwin_sig: c_int) callconv(.c) c_int {
    record("_raise");
    return raise(translateDarwinSignal(darwin_sig));
}

fn shim_memset_pattern16(b: ?*anyopaque, pattern16: ?*const anyopaque, len: usize) callconv(.c) void {
    record("_memset_pattern16");
    const dst_raw = b orelse return;
    const pat_raw = pattern16 orelse return;
    const dst: [*]u8 = @ptrCast(dst_raw);
    const pat: [*]const u8 = @ptrCast(pat_raw);
    var i: usize = 0;
    while (i + 16 <= len) : (i += 16) {
        @memcpy(dst[i .. i + 16], pat[0..16]);
    }
    if (i < len) {
        @memcpy(dst[i..len], pat[0 .. len - i]);
    }
}

fn shim_exp10(x: f64) callconv(.c) f64 {
    record("___exp10");
    return pow(10.0, x);
}

fn shim_gettimeofday(tv: ?*DarwinTimeval, tz: ?*anyopaque) callconv(.c) c_int {
    record("_gettimeofday");
    var lx: LinuxTimeval = undefined;
    const rc = gettimeofday(&lx, tz);
    if (rc == 0) {
        if (tv) |out| {
            out.tv_sec = lx.tv_sec;
            out.tv_usec = @intCast(lx.tv_usec);
            out._pad = 0;
        }
    }
    return rc;
}

fn shim_pthread_once(once_control: *i64, init_routine: *const fn () callconv(.c) void) callconv(.c) c_int {
    record("_pthread_once");
    const cur = @atomicLoad(i64, once_control, .acquire);
    if (cur == -1) return 0;
    // Darwin PTHREAD_ONCE_INIT has __sig = 0x30B1BCBA (or 0 if zero-init)
    if (cur == 0x30B1BCBA or cur == 0) {
        if (@cmpxchgStrong(i64, once_control, cur, 1, .acq_rel, .acquire) == null) {
            init_routine();
            @atomicStore(i64, once_control, -1, .release);
            return 0;
        }
    }
    while (@atomicLoad(i64, once_control, .acquire) != -1) {
        _ = sched_yield();
    }
    return 0;
}

fn shim_pthread_key_create(key_out: *usize, destructor: ?*const fn (?*anyopaque) callconv(.c) void) callconv(.c) c_int {
    record("_pthread_key_create");
    var lx_key: u32 = 0;
    const rc = pthread_key_create(&lx_key, destructor);
    if (rc == 0) key_out.* = @intCast(lx_key);
    return rc;
}

fn shim_pthread_getspecific(key: usize) callconv(.c) ?*anyopaque {
    return pthread_getspecific(@truncate(key));
}

fn shim_pthread_setspecific(key: usize, value: ?*const anyopaque) callconv(.c) c_int {
    return pthread_setspecific(@truncate(key), value);
}

fn shim_pthread_mach_thread_np(tid: usize) callconv(.c) u32 {
    record("_pthread_mach_thread_np");
    const h: u32 = @truncate(tid ^ (tid >> 32));
    return if (h == 0) 1 else h;
}

fn shim_aligned_alloc(alignment: usize, size: usize) callconv(.c) ?*anyopaque {
    record("_aligned_alloc");
    if (alignment == 0 or (alignment & (alignment - 1)) != 0) {
        __errno_location().* = 22; // EINVAL
        return null;
    }
    const eff_align = @max(alignment, @sizeOf(usize));
    var ptr: ?*anyopaque = null;
    const rc = posix_memalign(&ptr, eff_align, @max(size, 1));
    if (rc != 0) {
        __errno_location().* = rc;
        return null;
    }
    return ptr;
}

fn shim_pathconf(path: [*:0]const u8, darwin_name: c_int) callconv(.c) c_long {
    record("_pathconf");
    const lx_name: c_int = switch (darwin_name) {
        4 => 3, // _PC_NAME_MAX
        5 => 4, // _PC_PATH_MAX
        6 => 5, // _PC_PIPE_BUF
        else => darwin_name,
    };
    return pathconf(path, lx_name);
}

fn translateLinuxOpenFlagsToDarwin(lx_flags: c_int) c_int {
    const f: u32 = @bitCast(lx_flags);
    var out: u32 = f & 0x0003;
    if ((f & 0x0800) != 0) out |= 0x0004; // O_NONBLOCK
    if ((f & 0x0400) != 0) out |= 0x0008; // O_APPEND
    if ((f & 0x2000) != 0) out |= 0x0040; // O_ASYNC
    if ((f & 0x0040) != 0) out |= 0x0200; // O_CREAT
    if ((f & 0x0200) != 0) out |= 0x0400; // O_TRUNC
    if ((f & 0x0080) != 0) out |= 0x0800; // O_EXCL
    if ((f & 0x80000) != 0) out |= 0x1000000; // O_CLOEXEC
    return @bitCast(out);
}

fn shim_fcntl(fd: c_int, darwin_cmd: c_int, ...) callconv(.c) c_int {
    record("_fcntl");
    switch (darwin_cmd) {
        1 => return fcntl(fd, 1), // F_GETFD
        3 => { // F_GETFL
            const rc = fcntl(fd, 3);
            if (rc < 0) return rc;
            return translateLinuxOpenFlagsToDarwin(rc);
        },
        0, 2 => { // F_DUPFD, F_SETFD
            var ap = @cVaStart();
            defer @cVaEnd(&ap);
            const arg = @cVaArg(&ap, c_long);
            return fcntl(fd, darwin_cmd, arg);
        },
        4 => { // F_SETFL
            var ap = @cVaStart();
            defer @cVaEnd(&ap);
            const arg = @cVaArg(&ap, c_int);
            return fcntl(fd, 4, translateDarwinOpenFlags(arg));
        },
        67 => { // F_DUPFD_CLOEXEC (Darwin 67 -> Linux 1030)
            var ap = @cVaStart();
            defer @cVaEnd(&ap);
            const arg = @cVaArg(&ap, c_long);
            return fcntl(fd, 1030, arg);
        },
        else => return -1,
    }
}

// Real Darwin Mach-O Thread-Local Variables (__thread_vars / __thread_data / __thread_bss)
pub const TlvDescriptor = extern struct {
    thunk: *const fn (*TlvDescriptor) callconv(.c) ?*anyopaque,
    key: usize,
    offset: usize,
};

const TlvImageTemplate = struct {
    pthread_key: u32,
    init_data: ?[*]const u8,
    init_size: usize,
    total_size: usize,
};

var tlv_mutex: [64]u8 align(8) = .{0} ** 64;
var tlv_templates: std.ArrayListUnmanaged(TlvImageTemplate) = .empty;

pub fn registerTlvImage(init_data: ?[*]const u8, init_size: usize, total_size: usize) usize {
    _ = pthread_mutex_lock(&tlv_mutex);
    defer _ = pthread_mutex_unlock(&tlv_mutex);
    var key: u32 = 0;
    _ = pthread_key_create(&key, &free);
    const idx = tlv_templates.items.len;
    tlv_templates.append(std.heap.c_allocator, .{
        .pthread_key = key,
        .init_data = init_data,
        .init_size = init_size,
        .total_size = @max(total_size, 64),
    }) catch return 0;
    return idx + 1;
}

pub fn shim_tlv_get_addr(desc: *TlvDescriptor) callconv(.c) ?*anyopaque {
    if (desc.key > 0) {
        _ = pthread_mutex_lock(&tlv_mutex);
        const tpl_opt: ?TlvImageTemplate = if (desc.key - 1 < tlv_templates.items.len)
            tlv_templates.items[desc.key - 1]
        else
            null;
        _ = pthread_mutex_unlock(&tlv_mutex);

        if (tpl_opt) |tpl| {
            if (pthread_getspecific(tpl.pthread_key)) |base| {
                return @ptrFromInt(@intFromPtr(base) + desc.offset);
            }
            const sz = @max(tpl.total_size, desc.offset + 64);
            const buf = calloc(1, sz) orelse return null;
            if (tpl.init_data) |src| {
                if (tpl.init_size > 0) _ = memcpy(buf, src, tpl.init_size);
            }
            _ = pthread_setspecific(tpl.pthread_key, buf);
            return @ptrFromInt(@intFromPtr(buf) + desc.offset);
        }
    }
    // Fallback if descriptor was not registered via __thread_vars scan
    const sz = desc.offset + 64;
    var key: u32 = 0;
    _ = pthread_key_create(&key, &free);
    const buf = calloc(1, sz) orelse return null;
    _ = pthread_setspecific(key, buf);
    return @ptrFromInt(@intFromPtr(buf) + desc.offset);
}

// Native x86_64 setjmp/longjmp fitting inside Darwin's 148-byte jmp_buf (uses 64 bytes)
pub fn shim_setjmp() callconv(.naked) void {
    asm volatile (
        \\movq %%rbx, 0(%%rdi)
        \\movq %%rbp, 8(%%rdi)
        \\movq %%r12, 16(%%rdi)
        \\movq %%r13, 24(%%rdi)
        \\movq %%r14, 32(%%rdi)
        \\movq %%r15, 40(%%rdi)
        \\leaq 8(%%rsp), %%rax
        \\movq %%rax, 48(%%rdi)
        \\movq (%%rsp), %%rax
        \\movq %%rax, 56(%%rdi)
        \\xorl %%eax, %%eax
        \\retq
    );
}

pub fn shim_longjmp() callconv(.naked) void {
    asm volatile (
        \\movl %%esi, %%eax
        \\testl %%eax, %%eax
        \\jnz 1f
        \\movl $1, %%eax
        \\1:
        \\movq 0(%%rdi), %%rbx
        \\movq 8(%%rdi), %%rbp
        \\movq 16(%%rdi), %%r12
        \\movq 24(%%rdi), %%r13
        \\movq 32(%%rdi), %%r14
        \\movq 40(%%rdi), %%r15
        \\movq 48(%%rdi), %%rsp
        \\jmpq *56(%%rdi)
    );
}

// Darwin BSD qsort_r(base, nel, width, thunk, compar(thunk, a, b))
// -> Linux glibc qsort_r(base, nel, width, compar(a, b, thunk), thunk)
const QsortRAdapter = struct {
    thunk: ?*anyopaque,
    darwin_cmp: *const fn (?*anyopaque, *const anyopaque, *const anyopaque) callconv(.c) c_int,
};

fn qsortRTrampoline(a: *const anyopaque, b: *const anyopaque, raw_ctx: ?*anyopaque) callconv(.c) c_int {
    const ctx: *const QsortRAdapter = @ptrCast(@alignCast(raw_ctx.?));
    return ctx.darwin_cmp(ctx.thunk, a, b);
}

pub fn shim_qsort_r(
    base: *anyopaque,
    nel: usize,
    width: usize,
    thunk: ?*anyopaque,
    compar: *const fn (?*anyopaque, *const anyopaque, *const anyopaque) callconv(.c) c_int,
) callconv(.c) void {
    record("_qsort_r");
    var ctx = QsortRAdapter{ .thunk = thunk, .darwin_cmp = compar };
    qsort_r(base, nel, width, &qsortRTrampoline, @ptrCast(&ctx));
}

// XSI POSIX strerror_r (Darwin always uses int-returning XSI form, unlike glibc default char*)
pub fn shim_strerror_r(errnum: c_int, buf: [*]u8, buflen: usize) callconv(.c) c_int {
    record("_strerror_r");
    if (buflen == 0) return 34; // ERANGE
    const msg = std.mem.span(strerror(errnum));
    const n = @min(msg.len, buflen - 1);
    if (n > 0) @memcpy(buf[0..n], msg[0..n]);
    buf[n] = 0;
    return if (msg.len >= buflen) 34 else 0;
}

// Darwin signal set / sigaction / sigprocmask / sigaltstack / kill translators
pub fn shim_sigemptyset(set: *u32) callconv(.c) c_int {
    set.* = 0;
    return 0;
}

pub fn shim_sigaddset(set: *u32, darwin_sig: c_int) callconv(.c) c_int {
    if (darwin_sig <= 0 or darwin_sig > 32) {
        __errno_location().* = 22; // EINVAL
        return -1;
    }
    set.* |= @as(u32, 1) << @intCast(darwin_sig - 1);
    return 0;
}

pub fn shim_sigismember(set: *const u32, darwin_sig: c_int) callconv(.c) c_int {
    if (darwin_sig <= 0 or darwin_sig > 32) {
        __errno_location().* = 22;
        return -1;
    }
    return if ((set.* & (@as(u32, 1) << @intCast(darwin_sig - 1))) != 0) 1 else 0;
}

fn darwinSigsetToLinux(dset: u32) std.os.linux.sigset_t {
    var lset = std.os.linux.sigemptyset();
    var s: c_int = 1;
    while (s <= 31) : (s += 1) {
        if ((dset & (@as(u32, 1) << @intCast(s - 1))) != 0) {
            const lx_sig = translateDarwinSignal(s);
            if (lx_sig >= 1 and lx_sig <= 64) {
                std.os.linux.sigaddset(&lset, @enumFromInt(@as(u8, @intCast(lx_sig))));
            }
        }
    }
    return lset;
}

fn linuxSigsetToDarwin(lset: std.os.linux.sigset_t) u32 {
    var dset: u32 = 0;
    var s: c_int = 1;
    while (s <= 31) : (s += 1) {
        const lx_sig = translateDarwinSignal(s);
        if (lx_sig >= 1 and lx_sig <= 64) {
            if (std.os.linux.sigismember(&lset, @enumFromInt(@as(u8, @intCast(lx_sig))))) {
                dset |= @as(u32, 1) << @intCast(s - 1);
            }
        }
    }
    return dset;
}

const DarwinSigaction = extern struct {
    handler: usize,
    sa_mask: u32,
    sa_flags: c_int,
};

fn shim_sigaction(darwin_sig: c_int, act: ?*const DarwinSigaction, oact: ?*DarwinSigaction) callconv(.c) c_int {
    record("_sigaction");
    const lx_sig = translateDarwinSignal(darwin_sig);
    if (lx_sig <= 0 or lx_sig > 64) {
        __errno_location().* = 22;
        return -1;
    }
    var lx_act: std.os.linux.Sigaction = undefined;
    var lx_oact: std.os.linux.Sigaction = undefined;
    const lx_act_ptr: ?*const std.os.linux.Sigaction = if (act) |a| blk: {
        var flags: u32 = 0;
        if ((a.sa_flags & 0x0001) != 0) flags |= 0x08000000; // SA_ONSTACK
        if ((a.sa_flags & 0x0002) != 0) flags |= 0x10000000; // SA_RESTART
        if ((a.sa_flags & 0x0004) != 0) flags |= 0x80000000; // SA_RESETHAND
        if ((a.sa_flags & 0x0010) != 0) flags |= 0x40000000; // SA_NODEFER
        if ((a.sa_flags & 0x0040) != 0) flags |= 0x00000004; // SA_SIGINFO
        lx_act = .{
            .handler = .{ .handler = @ptrFromInt(a.handler) },
            .mask = darwinSigsetToLinux(a.sa_mask),
            .flags = flags,
        };
        break :blk &lx_act;
    } else null;

    const rc = std.os.linux.sigaction(@enumFromInt(@as(u8, @intCast(lx_sig))), lx_act_ptr, if (oact != null) &lx_oact else null);
    const sres: isize = @bitCast(rc);
    if (sres < 0) {
        __errno_location().* = @intCast(-sres);
        return -1;
    }
    if (oact) |oa| {
        var dflags: c_int = 0;
        if ((lx_oact.flags & 0x08000000) != 0) dflags |= 0x0001;
        if ((lx_oact.flags & 0x10000000) != 0) dflags |= 0x0002;
        if ((lx_oact.flags & 0x80000000) != 0) dflags |= 0x0004;
        if ((lx_oact.flags & 0x40000000) != 0) dflags |= 0x0010;
        if ((lx_oact.flags & 0x00000004) != 0) dflags |= 0x0040;
        oa.* = .{
            .handler = @intFromPtr(lx_oact.handler.handler),
            .sa_mask = linuxSigsetToDarwin(lx_oact.mask),
            .sa_flags = dflags,
        };
    }
    return 0;
}

fn shim_sigprocmask(darwin_how: c_int, set: ?*const u32, oset: ?*u32) callconv(.c) c_int {
    record("_sigprocmask");
    const lx_how: u32 = switch (darwin_how) {
        1 => 0, // SIG_BLOCK
        2 => 1, // SIG_UNBLOCK
        3 => 2, // SIG_SETMASK
        else => {
            __errno_location().* = 22;
            return -1;
        },
    };
    var lx_set: std.os.linux.sigset_t = undefined;
    var lx_oset: std.os.linux.sigset_t = undefined;
    const lx_set_ptr: ?*const std.os.linux.sigset_t = if (set) |s| blk: {
        lx_set = darwinSigsetToLinux(s.*);
        break :blk &lx_set;
    } else null;
    const rc = std.os.linux.sigprocmask(lx_how, lx_set_ptr, if (oset != null) &lx_oset else null);
    const sres: isize = @bitCast(rc);
    if (sres < 0) {
        __errno_location().* = @intCast(-sres);
        return -1;
    }
    if (oset) |o| o.* = linuxSigsetToDarwin(lx_oset);
    return 0;
}

const DarwinStackT = extern struct {
    ss_sp: ?*anyopaque,
    ss_size: usize,
    ss_flags: c_int,
};

const LinuxStackT = extern struct {
    ss_sp: ?*anyopaque,
    ss_flags: c_int,
    _pad: c_int = 0,
    ss_size: usize,
};

extern "c" fn sigaltstack(ss: ?*const LinuxStackT, oss: ?*LinuxStackT) c_int;

fn shim_sigaltstack(ss: ?*const DarwinStackT, oss: ?*DarwinStackT) callconv(.c) c_int {
    record("_sigaltstack");
    var lx_ss: LinuxStackT = undefined;
    var lx_oss: LinuxStackT = undefined;
    const lx_ss_ptr: ?*const LinuxStackT = if (ss) |s| blk: {
        lx_ss = .{
            .ss_sp = s.ss_sp,
            .ss_flags = s.ss_flags,
            .ss_size = s.ss_size,
        };
        break :blk &lx_ss;
    } else null;
    const rc = sigaltstack(lx_ss_ptr, if (oss != null) &lx_oss else null);
    if (rc != 0) return -1;
    if (oss) |o| {
        o.* = .{
            .ss_sp = lx_oss.ss_sp,
            .ss_size = lx_oss.ss_size,
            .ss_flags = lx_oss.ss_flags,
        };
    }
    return 0;
}

fn shim_kill(pid: c_int, darwin_sig: c_int) callconv(.c) c_int {
    record("_kill");
    return kill(pid, translateDarwinSignal(darwin_sig));
}

fn shim_openat(dirfd: c_int, path: [*:0]const u8, darwin_oflag: c_int, ...) callconv(.c) c_int {
    record("_openat");
    const lx_dirfd: c_int = if (dirfd == -2) -100 else dirfd;
    const lx_flags = translateDarwinOpenFlags(darwin_oflag);
    if ((@as(u32, @bitCast(darwin_oflag)) & 0x0200) != 0) {
        var ap = @cVaStart();
        defer @cVaEnd(&ap);
        const mode = @cVaArg(&ap, c_uint);
        return openat(lx_dirfd, path, lx_flags, mode);
    }
    return openat(lx_dirfd, path, lx_flags, @as(c_uint, 0));
}

fn shim_mkostemp(template: [*]u8, darwin_flags: c_int) callconv(.c) c_int {
    record("_mkostemp");
    return mkostemp(template, translateDarwinOpenFlags(darwin_flags));
}

fn shim_sysconf(darwin_name: c_int) callconv(.c) c_long {
    record("_sysconf");
    const lx_name: c_int = switch (darwin_name) {
        1 => 0, // _SC_ARG_MAX
        3 => 2, // _SC_CLK_TCK
        5 => 4, // _SC_OPEN_MAX
        15 => 43, // _SC_LINE_MAX
        29 => 30, // _SC_PAGESIZE
        57, 58 => 84, // _SC_NPROCESSORS_CONF / _SC_NPROCESSORS_ONLN
        else => darwin_name,
    };
    return sysconf(lx_name);
}

var progname_buf: [256]u8 = .{0} ** 256;

fn shim_getprogname() callconv(.c) [*:0]const u8 {
    record("_getprogname");
    const path = active_executable_path orelse "wins_macho";
    const base = std.fs.path.basename(path);
    const n = @min(base.len, progname_buf.len - 1);
    @memcpy(progname_buf[0..n], base[0..n]);
    progname_buf[n] = 0;
    return @ptrCast(&progname_buf);
}

var darwin_static_cond_init_lock: [64]u8 align(8) = .{0} ** 64;

fn ensureCondInit(cond: *anyopaque) void {
    const sig_ptr: *u32 = @ptrCast(@alignCast(cond));
    if (@atomicLoad(u32, sig_ptr, .acquire) == 0x3CB0B1BB) {
        _ = pthread_mutex_lock(&darwin_static_cond_init_lock);
        if (@atomicLoad(u32, sig_ptr, .monotonic) == 0x3CB0B1BB) {
            // Both Darwin pthread_cond_t and Linux glibc pthread_cond_t are 48 bytes.
            var tmp: [48]u8 align(8) = .{0} ** 48;
            _ = pthread_cond_init(&tmp, null);
            const dst: *[48]u8 = @ptrCast(cond);
            @memcpy(dst[4..48], tmp[4..48]);
            @atomicStore(u32, sig_ptr, std.mem.readInt(u32, tmp[0..4], .little), .release);
        }
        _ = pthread_mutex_unlock(&darwin_static_cond_init_lock);
    }
}

pub fn shim_pthread_cond_init(cond: *anyopaque, attr: ?*const anyopaque) callconv(.c) c_int {
    _ = attr;
    record("_pthread_cond_init");
    return pthread_cond_init(cond, null);
}

pub fn shim_pthread_cond_destroy(cond: *anyopaque) callconv(.c) c_int {
    record("_pthread_cond_destroy");
    return pthread_cond_destroy(cond);
}

pub fn shim_pthread_cond_wait(cond: *anyopaque, mutex: *anyopaque) callconv(.c) c_int {
    record("_pthread_cond_wait");
    ensureCondInit(cond);
    return pthread_cond_wait(cond, mutex);
}

pub fn shim_pthread_cond_signal(cond: *anyopaque) callconv(.c) c_int {
    record("_pthread_cond_signal");
    ensureCondInit(cond);
    return pthread_cond_signal(cond);
}

pub fn shim_pthread_cond_broadcast(cond: *anyopaque) callconv(.c) c_int {
    record("_pthread_cond_broadcast");
    ensureCondInit(cond);
    return pthread_cond_broadcast(cond);
}

// Mach VM / POSIX.1e ACL graceful fallbacks (explicitly marked STUB_FOR_PROBE_ONLY)
var darwin_mach_task_self: u32 = 1;

fn shim_mach_port_deallocate(task: u32, name: u32) callconv(.c) c_int {
    _ = task;
    _ = name;
    record("_mach_port_deallocate");
    return 0;
}

fn shim_vm_region_64(task: u32, addr: ?*usize, size: ?*usize, flavor: c_int, info: ?*anyopaque, info_cnt: ?*u32, obj_name: ?*u32) callconv(.c) c_int {
    _ = task;
    _ = addr;
    _ = size;
    _ = flavor;
    _ = info;
    _ = info_cnt;
    _ = obj_name;
    record("_vm_region_64");
    return 1; // KERN_INVALID_ADDRESS
}

fn shim_acl_unsupported_ptr() callconv(.c) ?*anyopaque {
    __errno_location().* = 95; // ENOTSUP
    return null;
}

fn shim_acl_unsupported_int() callconv(.c) c_int {
    __errno_location().* = 95; // ENOTSUP
    return -1;
}

fn shim_acl_free(obj: ?*anyopaque) callconv(.c) c_int {
    _ = obj;
    return 0;
}

// Darwin mmap MAP_* flags -> Linux MAP_* flags
fn shim_mmap(addr: ?*anyopaque, len: usize, prot: c_int, darwin_flags: c_int, fd: c_int, offset: i64) callconv(.c) ?*anyopaque {
    record("_mmap");
    const df: u32 = @bitCast(darwin_flags);
    var lf: u32 = df & 0x0003; // MAP_SHARED (1) | MAP_PRIVATE (2)
    if ((df & 0x0010) != 0) lf |= 0x0010; // MAP_FIXED
    if ((df & 0x1000) != 0) lf |= 0x0020; // Darwin MAP_ANON (0x1000) -> Linux MAP_ANONYMOUS (0x20)
    return mmap(addr, len, prot, @bitCast(lf), fd, offset);
}

fn shim_munmap(addr: ?*anyopaque, len: usize) callconv(.c) c_int {
    record("_munmap");
    return munmap(addr, len);
}

// libedit (BSD EditLine) clean implementation over DarwinFile
const DarwinEditLine = struct {
    fin: ?*anyopaque,
    fout: ?*anyopaque,
    ferr: ?*anyopaque,
    line_buf: [*]u8,
    line_cap: usize,
};

fn shim_el_init(prog: ?[*:0]const u8, fin: ?*anyopaque, fout: ?*anyopaque, ferr: ?*anyopaque) callconv(.c) ?*anyopaque {
    _ = prog;
    record("_el_init");
    const raw = calloc(1, @sizeOf(DarwinEditLine)) orelse return null;
    const el: *DarwinEditLine = @ptrCast(@alignCast(raw));
    const cap: usize = 4096;
    const buf_raw = malloc(cap) orelse {
        free(raw);
        return null;
    };
    el.* = .{
        .fin = fin,
        .fout = fout,
        .ferr = ferr,
        .line_buf = @ptrCast(buf_raw),
        .line_cap = cap,
    };
    return raw;
}

fn shim_el_end(raw: ?*anyopaque) callconv(.c) void {
    record("_el_end");
    const ptr = raw orelse return;
    const el: *DarwinEditLine = @ptrCast(@alignCast(ptr));
    free(@ptrCast(el.line_buf));
    free(ptr);
}

fn shim_el_set(raw: ?*anyopaque, op: c_int, ...) callconv(.c) c_int {
    _ = raw;
    _ = op;
    record("_el_set");
    return 0;
}

fn shim_el_source(raw: ?*anyopaque, fname: ?[*:0]const u8) callconv(.c) c_int {
    _ = raw;
    _ = fname;
    record("_el_source");
    return 0;
}

fn shim_el_gets(raw: ?*anyopaque, count_out: ?*c_int) callconv(.c) ?[*:0]const u8 {
    record("_el_gets");
    const ptr = raw orelse {
        if (count_out) |c| c.* = 0;
        return null;
    };
    const el: *DarwinEditLine = @ptrCast(@alignCast(ptr));
    const fin = el.fin orelse {
        if (count_out) |c| c.* = 0;
        return null;
    };
    var len: usize = 0;
    while (true) {
        const ch = shim_fgetc(fin);
        if (ch == -1) break;
        if (len + 2 >= el.line_cap) {
            const new_cap = el.line_cap * 2;
            const nb = realloc(@ptrCast(el.line_buf), new_cap) orelse break;
            el.line_buf = @ptrCast(nb);
            el.line_cap = new_cap;
        }
        el.line_buf[len] = @truncate(@as(u32, @bitCast(ch)));
        len += 1;
        if (ch == '\n') break;
    }
    if (len == 0) {
        if (count_out) |c| c.* = 0;
        return null;
    }
    el.line_buf[len] = 0;
    if (count_out) |c| c.* = @intCast(len);
    return @ptrCast(el.line_buf);
}

fn shim_history_init() callconv(.c) ?*anyopaque {
    record("_history_init");
    return calloc(1, 32);
}

fn shim_history_end(h: ?*anyopaque) callconv(.c) void {
    record("_history_end");
    free(h);
}

fn shim_history(h: ?*anyopaque, ev: ?*anyopaque, op: c_int, ...) callconv(.c) c_int {
    _ = h;
    _ = ev;
    _ = op;
    record("_history");
    return 0;
}

// Native Linux bridge for pure-C ABI-identical compression libraries (zlib, liblzma, liblz4)
const NativeLibMapping = struct {
    macho_base: []const u8,
    linux_so: [*:0]const u8,
};

const native_lib_mappings = [_]NativeLibMapping{
    .{ .macho_base = "libz.1.dylib", .linux_so = "libz.so.1" },
    .{ .macho_base = "liblzma.5.dylib", .linux_so = "liblzma.so.5" },
    .{ .macho_base = "liblz4.1.dylib", .linux_so = "liblz4.so.1" },
};

var native_lib_handles: [native_lib_mappings.len]?*anyopaque = .{ null, null, null };

pub fn nativeLinuxLibraryForDylib(dylib_path: []const u8) ?[*:0]const u8 {
    const base = std.fs.path.basename(dylib_path);
    for (native_lib_mappings) |m| {
        if (std.mem.eql(u8, base, m.macho_base)) return m.linux_so;
    }
    return null;
}

pub fn lookupNativeLibrarySymbol(dylib_path: []const u8, darwin_symbol: []const u8) ?usize {
    const base = std.fs.path.basename(dylib_path);
    const RTLD_LAZY: c_int = 1;
    for (native_lib_mappings, 0..) |m, idx| {
        if (!std.mem.eql(u8, base, m.macho_base)) continue;
        if (native_lib_handles[idx] == null) {
            native_lib_handles[idx] = dlopen(m.linux_so, RTLD_LAZY);
        }
        const h = native_lib_handles[idx] orelse return null;
        // Strip single leading '_' from Mach-O C symbol name
        const cname = if (darwin_symbol.len > 0 and darwin_symbol[0] == '_') darwin_symbol[1..] else darwin_symbol;
        var zbuf: [256]u8 = undefined;
        if (cname.len >= zbuf.len) return null;
        @memcpy(zbuf[0..cname.len], cname);
        zbuf[cname.len] = 0;
        if (dlsym(h, @ptrCast(&zbuf))) |addr| {
            return @intFromPtr(addr);
        }
        return null;
    }
    return null;
}

fn shim_chkstk_darwin() callconv(.naked) void {
    // On Linux userland with 8MB stack, return preserving rax/all registers
    asm volatile ("retq");
}

fn shim_strcpy_chk(dst: [*]u8, src: [*:0]const u8, dstlen: usize) callconv(.c) [*]u8 {
    record("___strcpy_chk");
    const len = strlen(src);
    if (len >= dstlen) abort();
    return strcpy(dst, src);
}

pub fn shim_sprintf_chk(str: [*]u8, flag: c_int, dstlen: usize, fmt: [*:0]const u8, ...) callconv(.c) c_int {
    _ = flag;
    record("___sprintf_chk");
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    if (dstlen != std.math.maxInt(usize)) {
        const res = vsnprintf(str, dstlen, fmt, &ap);
        if (res >= 0 and @as(usize, @intCast(res)) >= dstlen) abort();
        return res;
    }
    return vsprintf(str, fmt, &ap);
}

pub fn shim_snprintf_chk(str: [*]u8, maxlen: usize, flag: c_int, dstlen: usize, fmt: [*:0]const u8, ...) callconv(.c) c_int {
    _ = flag;
    record("___snprintf_chk");
    if (maxlen > dstlen) abort();
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    return vsnprintf(str, maxlen, fmt, &ap);
}

pub fn translateDarwinOpenFlags(darwin_flags: c_int) c_int {
    const f: u32 = @bitCast(darwin_flags);
    var out: u32 = f & 0x0003; // O_RDONLY / O_WRONLY / O_RDWR
    if ((f & 0x0004) != 0) out |= 0x0800; // O_NONBLOCK
    if ((f & 0x0008) != 0) out |= 0x0400; // O_APPEND
    if ((f & 0x0040) != 0) out |= 0x2000; // O_ASYNC
    if ((f & 0x0080) != 0) out |= 0x101000; // O_SYNC
    if ((f & 0x0100) != 0) out |= 0x20000; // O_NOFOLLOW
    if ((f & 0x0200) != 0) out |= 0x0040; // O_CREAT
    if ((f & 0x0400) != 0) out |= 0x0200; // O_TRUNC
    if ((f & 0x0800) != 0) out |= 0x0080; // O_EXCL
    if ((f & 0x20000) != 0) out |= 0x0100; // O_NOCTTY
    if ((f & 0x100000) != 0) out |= 0x10000; // O_DIRECTORY
    if ((f & 0x1000000) != 0) out |= 0x80000; // O_CLOEXEC
    return @bitCast(out);
}

fn shim_open(path: [*:0]const u8, darwin_oflag: c_int, ...) callconv(.c) c_int {
    record("_open");
    const linux_flags = translateDarwinOpenFlags(darwin_oflag);
    if ((@as(u32, @bitCast(darwin_oflag)) & 0x0200) != 0) {
        var ap = @cVaStart();
        defer @cVaEnd(&ap);
        const mode = @cVaArg(&ap, c_uint);
        return open(path, linux_flags, mode);
    }
    return open(path, linux_flags, @as(c_uint, 0));
}

pub fn translateDarwinLocaleCategory(darwin_cat: c_int) c_int {
    return switch (darwin_cat) {
        0 => 6, // LC_ALL
        1 => 3, // LC_COLLATE
        2 => 0, // LC_CTYPE
        3 => 4, // LC_MONETARY
        4 => 1, // LC_NUMERIC
        5 => 2, // LC_TIME
        6 => 5, // LC_MESSAGES
        else => darwin_cat,
    };
}

fn shim_setlocale(darwin_cat: c_int, locale: ?[*:0]const u8) callconv(.c) ?[*:0]u8 {
    record("_setlocale");
    return setlocale(translateDarwinLocaleCategory(darwin_cat), locale);
}

pub const DarwinPasswd = extern struct {
    pw_name: ?[*:0]u8,
    pw_passwd: ?[*:0]u8,
    pw_uid: u32,
    pw_gid: u32,
    pw_change: i64,
    pw_class: ?[*:0]const u8,
    pw_gecos: ?[*:0]u8,
    pw_dir: ?[*:0]u8,
    pw_shell: ?[*:0]u8,
    pw_expire: i64,
};

comptime {
    std.debug.assert(@sizeOf(DarwinPasswd) == 72);
}

threadlocal var tls_darwin_passwd: DarwinPasswd = undefined;

pub fn shim_getpwuid(uid: u32) callconv(.c) ?*DarwinPasswd {
    record("_getpwuid");
    const lx = c_pwd.getpwuid(uid) orelse return null;
    tls_darwin_passwd = .{
        .pw_name = lx.*.pw_name,
        .pw_passwd = lx.*.pw_passwd,
        .pw_uid = lx.*.pw_uid,
        .pw_gid = lx.*.pw_gid,
        .pw_change = 0,
        .pw_class = "",
        .pw_gecos = lx.*.pw_gecos,
        .pw_dir = lx.*.pw_dir,
        .pw_shell = lx.*.pw_shell,
        .pw_expire = 0,
    };
    return &tls_darwin_passwd;
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
    libcxx.ensureInitialized();
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
        .{ .darwin_symbol = "_fprintf", .linux_equiv = "libc:fprintf(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_fprintf) },
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
        .{ .darwin_symbol = "_open", .linux_equiv = "libc:open(mapped_O_flags)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_open) },
        .{ .darwin_symbol = "_open$NOCANCEL", .linux_equiv = "libc:open(mapped_O_flags)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_open) },
        .{ .darwin_symbol = "_fopen", .linux_equiv = "libc:fopen(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_fopen) },
        .{ .darwin_symbol = "_fopen$DARWIN_EXTSN", .linux_equiv = "libc:fopen(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_fopen) },
        .{ .darwin_symbol = "_fdopen", .linux_equiv = "libc:fdopen(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_fdopen) },
        .{ .darwin_symbol = "_fdopen$DARWIN_EXTSN", .linux_equiv = "libc:fdopen(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_fdopen) },
        .{ .darwin_symbol = "_fileno", .linux_equiv = "libc:fileno(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_fileno) },
        .{ .darwin_symbol = "_ferror", .linux_equiv = "libc:ferror(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_ferror) },
        .{ .darwin_symbol = "_feof", .linux_equiv = "libc:feof(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_feof) },
        .{ .darwin_symbol = "_clearerr", .linux_equiv = "libc:clearerr(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_clearerr) },
        .{ .darwin_symbol = "_fgetc", .linux_equiv = "libc:fgetc(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_fgetc) },
        .{ .darwin_symbol = "_getc", .linux_equiv = "libc:fgetc(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_fgetc) },
        .{ .darwin_symbol = "_getchar", .linux_equiv = "libc:fgetc(stdin)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_getchar) },
        .{ .darwin_symbol = "_getopt_long", .linux_equiv = "libc:getopt_long", .status = .NATIVE_MAPPING, .address = @intFromPtr(&getopt_long) },
        .{ .darwin_symbol = "_optind", .linux_equiv = "data:optind", .status = .NATIVE_MAPPING, .address = @intFromPtr(&optind) },
        .{ .darwin_symbol = "_optarg", .linux_equiv = "data:optarg", .status = .NATIVE_MAPPING, .address = @intFromPtr(&optarg) },
        .{ .darwin_symbol = "_chown", .linux_equiv = "libc:chown", .status = .NATIVE_MAPPING, .address = @intFromPtr(&chown) },
        .{ .darwin_symbol = "_mkdir", .linux_equiv = "libc:mkdir", .status = .NATIVE_MAPPING, .address = @intFromPtr(&mkdir) },
        .{ .darwin_symbol = "_setpriority", .linux_equiv = "libc:setpriority", .status = .NATIVE_MAPPING, .address = @intFromPtr(&setpriority) },
        .{ .darwin_symbol = "_mmap", .linux_equiv = "libc:mmap(mapped_MAP)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_mmap) },
        .{ .darwin_symbol = "_munmap", .linux_equiv = "libc:munmap", .status = .THIN_SHIM, .address = @intFromPtr(&shim_munmap) },
        .{ .darwin_symbol = "_backtrace", .linux_equiv = "libc:backtrace", .status = .NATIVE_MAPPING, .address = @intFromPtr(&backtrace) },
        .{ .darwin_symbol = "_backtrace_symbols", .linux_equiv = "libc:backtrace_symbols", .status = .NATIVE_MAPPING, .address = @intFromPtr(&backtrace_symbols) },
        .{ .darwin_symbol = "_el_init", .linux_equiv = "reimplemented:libedit_el_init", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_el_init) },
        .{ .darwin_symbol = "_el_end", .linux_equiv = "reimplemented:libedit_el_end", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_el_end) },
        .{ .darwin_symbol = "_el_set", .linux_equiv = "reimplemented:libedit_el_set", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_el_set) },
        .{ .darwin_symbol = "_el_source", .linux_equiv = "reimplemented:libedit_el_source", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_el_source) },
        .{ .darwin_symbol = "_el_gets", .linux_equiv = "reimplemented:libedit_el_gets", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_el_gets) },
        .{ .darwin_symbol = "_history_init", .linux_equiv = "reimplemented:libedit_history_init", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_history_init) },
        .{ .darwin_symbol = "_history_end", .linux_equiv = "reimplemented:libedit_history_end", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_history_end) },
        .{ .darwin_symbol = "_history", .linux_equiv = "reimplemented:libedit_history", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_history) },
        .{ .darwin_symbol = "_ungetc", .linux_equiv = "libc:ungetc(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_ungetc) },
        .{ .darwin_symbol = "_rewind", .linux_equiv = "libc:rewind(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_rewind) },
        .{ .darwin_symbol = "_setbuf", .linux_equiv = "libc:setbuf(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_setbuf) },
        .{ .darwin_symbol = "_perror", .linux_equiv = "libc:perror", .status = .NATIVE_MAPPING, .address = @intFromPtr(&perror) },
        .{ .darwin_symbol = "_vfprintf", .linux_equiv = "libc:vfprintf(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_vfprintf) },
        .{ .darwin_symbol = "_vsnprintf", .linux_equiv = "libc:vsnprintf", .status = .NATIVE_MAPPING, .address = @intFromPtr(&vsnprintf) },
        .{ .darwin_symbol = "_sscanf", .linux_equiv = "libc:sscanf", .status = .NATIVE_MAPPING, .address = @intFromPtr(&sscanf) },
        .{ .darwin_symbol = "_remove", .linux_equiv = "libc:remove", .status = .NATIVE_MAPPING, .address = @intFromPtr(&remove) },
        .{ .darwin_symbol = "_strdup", .linux_equiv = "libc:strdup", .status = .NATIVE_MAPPING, .address = @intFromPtr(&strdup) },
        .{ .darwin_symbol = "_strcat", .linux_equiv = "libc:strcat", .status = .NATIVE_MAPPING, .address = @intFromPtr(&strcat) },
        .{ .darwin_symbol = "___strcat_chk", .linux_equiv = "libc:strcat+bounds", .status = .THIN_SHIM, .address = @intFromPtr(&shim_strcat_chk) },
        .{ .darwin_symbol = "_strtol", .linux_equiv = "libc:strtol", .status = .NATIVE_MAPPING, .address = @intFromPtr(&strtol) },
        .{ .darwin_symbol = "_strtod", .linux_equiv = "libc:strtod", .status = .NATIVE_MAPPING, .address = @intFromPtr(&strtod) },
        .{ .darwin_symbol = "_strspn", .linux_equiv = "libc:strspn", .status = .NATIVE_MAPPING, .address = @intFromPtr(&strspn) },
        .{ .darwin_symbol = "_strerror", .linux_equiv = "libc:strerror", .status = .NATIVE_MAPPING, .address = @intFromPtr(&strerror) },
        .{ .darwin_symbol = "_memmem", .linux_equiv = "libc:memmem", .status = .NATIVE_MAPPING, .address = @intFromPtr(&memmem) },
        .{ .darwin_symbol = "_dirname", .linux_equiv = "libc:dirname", .status = .NATIVE_MAPPING, .address = @intFromPtr(&dirname) },
        .{ .darwin_symbol = "_atexit", .linux_equiv = "runtime:macho_atexit", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_atexit) },
        .{ .darwin_symbol = "___cxa_atexit", .linux_equiv = "runtime:macho_cxa_atexit", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_cxa_atexit) },
        .{ .darwin_symbol = "__Znwm", .linux_equiv = "libcxx:operator_new", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_operator_new) },
        .{ .darwin_symbol = "__Znam", .linux_equiv = "libcxx:operator_new_array", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_operator_new_array) },
        .{ .darwin_symbol = "__ZdlPv", .linux_equiv = "libcxx:operator_delete", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_operator_delete) },
        .{ .darwin_symbol = "__ZdaPv", .linux_equiv = "libcxx:operator_delete_array", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_operator_delete_array) },
        .{ .darwin_symbol = "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev", .linux_equiv = "libcxx:string_dtor", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_string_dtor) },
        .{ .darwin_symbol = "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKc", .linux_equiv = "libcxx:string_assign", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_string_assign_cstr) },
        .{ .darwin_symbol = "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2ERKS5_mmRKS4_", .linux_equiv = "libcxx:string_substr_ctor", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_string_ctor_substr) },
        .{ .darwin_symbol = "__ZNSt3__15mutex4lockEv", .linux_equiv = "libcxx:mutex_lock", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_mutex_lock) },
        .{ .darwin_symbol = "__ZNSt3__15mutex6unlockEv", .linux_equiv = "libcxx:mutex_unlock", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_mutex_unlock) },
        .{ .darwin_symbol = "__ZNSt3__15mutexD1Ev", .linux_equiv = "libcxx:mutex_dtor", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_mutex_dtor) },
        .{ .darwin_symbol = "__ZNSt3__118condition_variable4waitERNS_11unique_lockINS_5mutexEEE", .linux_equiv = "libcxx:cv_wait", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_cv_wait) },
        .{ .darwin_symbol = "__ZNSt3__118condition_variable10notify_oneEv", .linux_equiv = "libcxx:cv_notify_one", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_cv_notify_one) },
        .{ .darwin_symbol = "__ZNSt3__118condition_variable10notify_allEv", .linux_equiv = "libcxx:cv_notify_all", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_cv_notify_all) },
        .{ .darwin_symbol = "__ZNSt3__118condition_variableD1Ev", .linux_equiv = "libcxx:cv_dtor", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_cv_dtor) },
        .{ .darwin_symbol = "__ZNSt3__16thread4joinEv", .linux_equiv = "libcxx:thread_join", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_thread_join) },
        .{ .darwin_symbol = "__ZNSt3__16threadD1Ev", .linux_equiv = "libcxx:thread_dtor", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_thread_dtor) },
        .{ .darwin_symbol = "__ZNSt3__16thread20hardware_concurrencyEv", .linux_equiv = "libcxx:thread_hw_concurrency", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_thread_hardware_concurrency) },
        .{ .darwin_symbol = "__ZNSt3__115__thread_structC1Ev", .linux_equiv = "libcxx:thread_struct_ctor", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_thread_struct_ctor) },
        .{ .darwin_symbol = "__ZNSt3__115__thread_structD1Ev", .linux_equiv = "libcxx:thread_struct_dtor", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_thread_struct_dtor) },
        .{ .darwin_symbol = "__ZNSt3__119__thread_local_dataEv", .linux_equiv = "libcxx:thread_local_data", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_thread_local_data) },
        .{ .darwin_symbol = "__ZNSt3__119__shared_weak_count14__release_weakEv", .linux_equiv = "libcxx:shared_weak_release", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_shared_weak_count_release_weak) },
        .{ .darwin_symbol = "__ZNSt3__119__shared_weak_countD2Ev", .linux_equiv = "libcxx:shared_weak_dtor", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_shared_weak_count_dtor) },
        .{ .darwin_symbol = "__ZNKSt3__119__shared_weak_count13__get_deleterERKSt9type_info", .linux_equiv = "libcxx:shared_weak_get_deleter", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_shared_weak_count_get_deleter) },
        .{ .darwin_symbol = "__ZNSt3__16chrono12system_clock3nowEv", .linux_equiv = "libcxx:system_clock_now", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_system_clock_now) },
        .{ .darwin_symbol = "__ZNSt3__115system_categoryEv", .linux_equiv = "libcxx:system_category", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_system_category) },
        .{ .darwin_symbol = "__ZNSt3__116generic_categoryEv", .linux_equiv = "libcxx:generic_category", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_generic_category) },
        .{ .darwin_symbol = "__ZNSt3__120__throw_system_errorEiPKc", .linux_equiv = "libcxx:throw_system_error", .status = .THIN_SHIM, .address = @intFromPtr(&libcxx.shim_throw_system_error) },
        .{ .darwin_symbol = "__ZSt9terminatev", .linux_equiv = "libcxx:terminate", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_terminate) },
        .{ .darwin_symbol = "__ZNSt9exceptionD2Ev", .linux_equiv = "libcxx:exception_dtor", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_exception_dtor) },
        .{ .darwin_symbol = "__ZNKSt9exception4whatEv", .linux_equiv = "libcxx:exception_what", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_exception_what) },
        .{ .darwin_symbol = "__ZNSt11logic_errorC2EPKc", .linux_equiv = "libcxx:logic_error_ctor", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_logic_error_ctor) },
        .{ .darwin_symbol = "__ZNSt12out_of_rangeD1Ev", .linux_equiv = "libcxx:out_of_range_dtor", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_exception_dtor) },
        .{ .darwin_symbol = "__ZNSt12length_errorD1Ev", .linux_equiv = "libcxx:length_error_dtor", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_exception_dtor) },
        .{ .darwin_symbol = "__ZNSt20bad_array_new_lengthC1Ev", .linux_equiv = "libcxx:bad_array_new_length_ctor", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_bad_array_new_length_ctor) },
        .{ .darwin_symbol = "__ZNSt20bad_array_new_lengthD1Ev", .linux_equiv = "libcxx:bad_array_new_length_dtor", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_exception_dtor) },
        .{ .darwin_symbol = "__ZTVSt12out_of_range", .linux_equiv = "libcxx:vtable_out_of_range", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.vtable_out_of_range) },
        .{ .darwin_symbol = "__ZTVSt12length_error", .linux_equiv = "libcxx:vtable_length_error", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.vtable_length_error) },
        .{ .darwin_symbol = "__ZTVN10__cxxabiv117__class_type_infoE", .linux_equiv = "libcxx:vtable_class_ti", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.vtable_class_type_info) },
        .{ .darwin_symbol = "__ZTVN10__cxxabiv120__si_class_type_infoE", .linux_equiv = "libcxx:vtable_si_class_ti", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.vtable_si_class_type_info) },
        .{ .darwin_symbol = "__ZTISt9exception", .linux_equiv = "libcxx:ti_exception", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.ti_exception) },
        .{ .darwin_symbol = "__ZTINSt3__119__shared_weak_countE", .linux_equiv = "libcxx:ti_shared_weak_count", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.ti_shared_weak_count) },
        .{ .darwin_symbol = "__ZTISt12out_of_range", .linux_equiv = "libcxx:ti_out_of_range", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.ti_out_of_range) },
        .{ .darwin_symbol = "__ZTISt12length_error", .linux_equiv = "libcxx:ti_length_error", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.ti_length_error) },
        .{ .darwin_symbol = "__ZTISt20bad_array_new_length", .linux_equiv = "libcxx:ti_bad_array_new_length", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.ti_bad_array_new_length) },
        .{ .darwin_symbol = "___cxa_allocate_exception", .linux_equiv = "libcxxabi:cxa_alloc_exc", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_cxa_allocate_exception) },
        .{ .darwin_symbol = "___cxa_free_exception", .linux_equiv = "libcxxabi:cxa_free_exc", .status = .REIMPLEMENTED, .address = @intFromPtr(&libcxx.shim_cxa_free_exception) },
        .{ .darwin_symbol = "___cxa_throw", .linux_equiv = "libcxxabi:cxa_throw_abort", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&libcxx.shim_cxa_throw) },
        .{ .darwin_symbol = "___cxa_begin_catch", .linux_equiv = "libcxxabi:cxa_begin_catch", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&libcxx.shim_cxa_begin_catch) },
        .{ .darwin_symbol = "___cxa_end_catch", .linux_equiv = "libcxxabi:cxa_end_catch", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&libcxx.shim_cxa_end_catch) },
        .{ .darwin_symbol = "___cxa_rethrow", .linux_equiv = "libcxxabi:cxa_rethrow_abort", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&libcxx.shim_cxa_rethrow) },
        .{ .darwin_symbol = "___gxx_personality_v0", .linux_equiv = "libcxxabi:personality_stub", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&libcxx.shim_gxx_personality_v0) },
        .{ .darwin_symbol = "__Unwind_Resume", .linux_equiv = "libunwind:resume_abort", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&libcxx.shim_unwind_resume) },
        .{ .darwin_symbol = "__Unwind_RaiseException", .linux_equiv = "libunwind:raise_stub", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&libcxx.shim_unwind_raise_exception) },
        .{ .darwin_symbol = "__Unwind_GetIP", .linux_equiv = "libunwind:get_ip_stub", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&libcxx.shim_unwind_get_ip) },
        .{ .darwin_symbol = "__Unwind_SetIP", .linux_equiv = "libunwind:set_ip_stub", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&libcxx.shim_unwind_set_ip) },
        .{ .darwin_symbol = "__Unwind_SetGR", .linux_equiv = "libunwind:set_gr_stub", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&libcxx.shim_unwind_set_gr) },
        .{ .darwin_symbol = "__Unwind_GetLanguageSpecificData", .linux_equiv = "libunwind:get_lsda_stub", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&libcxx.shim_unwind_get_lsda) },
        .{ .darwin_symbol = "__Unwind_GetRegionStart", .linux_equiv = "libunwind:get_region_stub", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&libcxx.shim_unwind_get_region_start) },
        .{ .darwin_symbol = "_aligned_alloc", .linux_equiv = "libc:posix_memalign", .status = .THIN_SHIM, .address = @intFromPtr(&shim_aligned_alloc) },
        .{ .darwin_symbol = "_pthread_mach_thread_np", .linux_equiv = "reimplemented:mach_thread_id", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_pthread_mach_thread_np) },
        .{ .darwin_symbol = "_fchmod", .linux_equiv = "libc:fchmod", .status = .NATIVE_MAPPING, .address = @intFromPtr(&fchmod) },
        .{ .darwin_symbol = "_fchown", .linux_equiv = "libc:fchown", .status = .NATIVE_MAPPING, .address = @intFromPtr(&fchown) },
        .{ .darwin_symbol = "_utime", .linux_equiv = "libc:utime", .status = .NATIVE_MAPPING, .address = @intFromPtr(&utime) },
        .{ .darwin_symbol = "_signal", .linux_equiv = "libc:signal(mapped_sig)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_signal) },
        .{ .darwin_symbol = "_raise", .linux_equiv = "libc:raise(mapped_sig)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_raise) },
        .{ .darwin_symbol = "_fcntl", .linux_equiv = "libc:fcntl(mapped_cmd)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_fcntl) },
        .{ .darwin_symbol = "_pathconf", .linux_equiv = "libc:pathconf(mapped_pc)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_pathconf) },
        .{ .darwin_symbol = "___assert_rtn", .linux_equiv = "reimplemented:assert_rtn", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_assert_rtn) },
        .{ .darwin_symbol = "___toupper", .linux_equiv = "reimplemented:toupper", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_toupper) },
        .{ .darwin_symbol = "_memset_pattern16", .linux_equiv = "reimplemented:memset_pattern16", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_memset_pattern16) },
        .{ .darwin_symbol = "_gettimeofday", .linux_equiv = "libc:gettimeofday->DarwinTimeval", .status = .THIN_SHIM, .address = @intFromPtr(&shim_gettimeofday) },
        .{ .darwin_symbol = "_localtime_r", .linux_equiv = "libc:localtime_r", .status = .NATIVE_MAPPING, .address = @intFromPtr(&localtime_r) },
        .{ .darwin_symbol = "_gmtime_r", .linux_equiv = "libc:gmtime_r", .status = .NATIVE_MAPPING, .address = @intFromPtr(&gmtime_r) },
        .{ .darwin_symbol = "_gmtime", .linux_equiv = "libc:gmtime", .status = .NATIVE_MAPPING, .address = @intFromPtr(&gmtime) },
        .{ .darwin_symbol = "_mktime", .linux_equiv = "libc:mktime", .status = .NATIVE_MAPPING, .address = @intFromPtr(&mktime) },
        .{ .darwin_symbol = "_timegm", .linux_equiv = "libc:timegm", .status = .NATIVE_MAPPING, .address = @intFromPtr(&timegm) },
        .{ .darwin_symbol = "_strptime", .linux_equiv = "libc:strptime", .status = .NATIVE_MAPPING, .address = @intFromPtr(&strptime) },
        .{ .darwin_symbol = "_pthread_once", .linux_equiv = "reimplemented:pthread_once_darwin", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_pthread_once) },
        .{ .darwin_symbol = "_pthread_key_create", .linux_equiv = "libpthread:pthread_key_create(64b)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_pthread_key_create) },
        .{ .darwin_symbol = "_pthread_getspecific", .linux_equiv = "libpthread:pthread_getspecific", .status = .THIN_SHIM, .address = @intFromPtr(&shim_pthread_getspecific) },
        .{ .darwin_symbol = "_pthread_setspecific", .linux_equiv = "libpthread:pthread_setspecific", .status = .THIN_SHIM, .address = @intFromPtr(&shim_pthread_setspecific) },
        .{ .darwin_symbol = "__tlv_bootstrap", .linux_equiv = "reimplemented:macho_tlv", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_tlv_get_addr) },
        .{ .darwin_symbol = "_environ", .linux_equiv = "data:environ", .status = .NATIVE_MAPPING, .address = @intFromPtr(&environ) },
        .{ .darwin_symbol = "_dup", .linux_equiv = "libc:dup", .status = .NATIVE_MAPPING, .address = @intFromPtr(&dup) },
        .{ .darwin_symbol = "_pipe", .linux_equiv = "libc:pipe", .status = .NATIVE_MAPPING, .address = @intFromPtr(&pipe) },
        .{ .darwin_symbol = "_fork", .linux_equiv = "libc:fork", .status = .NATIVE_MAPPING, .address = @intFromPtr(&fork) },
        .{ .darwin_symbol = "_wait", .linux_equiv = "libc:wait", .status = .NATIVE_MAPPING, .address = @intFromPtr(&wait) },
        .{ .darwin_symbol = "_system", .linux_equiv = "libc:system", .status = .NATIVE_MAPPING, .address = @intFromPtr(&system) },
        .{ .darwin_symbol = "_random", .linux_equiv = "libc:random", .status = .NATIVE_MAPPING, .address = @intFromPtr(&random) },
        .{ .darwin_symbol = "_srandom", .linux_equiv = "libc:srandom", .status = .NATIVE_MAPPING, .address = @intFromPtr(&srandom) },
        .{ .darwin_symbol = "_sin", .linux_equiv = "libm:sin", .status = .NATIVE_MAPPING, .address = @intFromPtr(&sin) },
        .{ .darwin_symbol = "_cos", .linux_equiv = "libm:cos", .status = .NATIVE_MAPPING, .address = @intFromPtr(&cos) },
        .{ .darwin_symbol = "_tan", .linux_equiv = "libm:tan", .status = .NATIVE_MAPPING, .address = @intFromPtr(&tan) },
        .{ .darwin_symbol = "_asin", .linux_equiv = "libm:asin", .status = .NATIVE_MAPPING, .address = @intFromPtr(&asin) },
        .{ .darwin_symbol = "_acos", .linux_equiv = "libm:acos", .status = .NATIVE_MAPPING, .address = @intFromPtr(&acos) },
        .{ .darwin_symbol = "_atan", .linux_equiv = "libm:atan", .status = .NATIVE_MAPPING, .address = @intFromPtr(&atan) },
        .{ .darwin_symbol = "_atan2", .linux_equiv = "libm:atan2", .status = .NATIVE_MAPPING, .address = @intFromPtr(&atan2) },
        .{ .darwin_symbol = "_sinh", .linux_equiv = "libm:sinh", .status = .NATIVE_MAPPING, .address = @intFromPtr(&sinh) },
        .{ .darwin_symbol = "_cosh", .linux_equiv = "libm:cosh", .status = .NATIVE_MAPPING, .address = @intFromPtr(&cosh) },
        .{ .darwin_symbol = "_tanh", .linux_equiv = "libm:tanh", .status = .NATIVE_MAPPING, .address = @intFromPtr(&tanh) },
        .{ .darwin_symbol = "_asinh", .linux_equiv = "libm:asinh", .status = .NATIVE_MAPPING, .address = @intFromPtr(&asinh) },
        .{ .darwin_symbol = "_acosh", .linux_equiv = "libm:acosh", .status = .NATIVE_MAPPING, .address = @intFromPtr(&acosh) },
        .{ .darwin_symbol = "_atanh", .linux_equiv = "libm:atanh", .status = .NATIVE_MAPPING, .address = @intFromPtr(&atanh) },
        .{ .darwin_symbol = "_exp", .linux_equiv = "libm:exp", .status = .NATIVE_MAPPING, .address = @intFromPtr(&exp) },
        .{ .darwin_symbol = "_exp2", .linux_equiv = "libm:exp2", .status = .NATIVE_MAPPING, .address = @intFromPtr(&exp2) },
        .{ .darwin_symbol = "_expm1", .linux_equiv = "libm:expm1", .status = .NATIVE_MAPPING, .address = @intFromPtr(&expm1) },
        .{ .darwin_symbol = "___exp10", .linux_equiv = "libm:pow(10,x)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_exp10) },
        .{ .darwin_symbol = "_log", .linux_equiv = "libm:log", .status = .NATIVE_MAPPING, .address = @intFromPtr(&log) },
        .{ .darwin_symbol = "_log2", .linux_equiv = "libm:log2", .status = .NATIVE_MAPPING, .address = @intFromPtr(&log2) },
        .{ .darwin_symbol = "_log10", .linux_equiv = "libm:log10", .status = .NATIVE_MAPPING, .address = @intFromPtr(&log10) },
        .{ .darwin_symbol = "_log1p", .linux_equiv = "libm:log1p", .status = .NATIVE_MAPPING, .address = @intFromPtr(&log1p) },
        .{ .darwin_symbol = "_logb", .linux_equiv = "libm:logb", .status = .NATIVE_MAPPING, .address = @intFromPtr(&logb) },
        .{ .darwin_symbol = "_pow", .linux_equiv = "libm:pow", .status = .NATIVE_MAPPING, .address = @intFromPtr(&pow) },
        .{ .darwin_symbol = "_cbrt", .linux_equiv = "libm:cbrt", .status = .NATIVE_MAPPING, .address = @intFromPtr(&cbrt) },
        .{ .darwin_symbol = "_hypot", .linux_equiv = "libm:hypot", .status = .NATIVE_MAPPING, .address = @intFromPtr(&hypot) },
        .{ .darwin_symbol = "_fmod", .linux_equiv = "libm:fmod", .status = .NATIVE_MAPPING, .address = @intFromPtr(&fmod) },
        .{ .darwin_symbol = "_remainder", .linux_equiv = "libm:remainder", .status = .NATIVE_MAPPING, .address = @intFromPtr(&remainder) },
        .{ .darwin_symbol = "_fma", .linux_equiv = "libm:fma", .status = .NATIVE_MAPPING, .address = @intFromPtr(&fma) },
        .{ .darwin_symbol = "_fdim", .linux_equiv = "libm:fdim", .status = .NATIVE_MAPPING, .address = @intFromPtr(&fdim) },
        .{ .darwin_symbol = "_frexp", .linux_equiv = "libm:frexp", .status = .NATIVE_MAPPING, .address = @intFromPtr(&frexp) },
        .{ .darwin_symbol = "_ldexp", .linux_equiv = "libm:ldexp", .status = .NATIVE_MAPPING, .address = @intFromPtr(&ldexp) },
        .{ .darwin_symbol = "_modf", .linux_equiv = "libm:modf", .status = .NATIVE_MAPPING, .address = @intFromPtr(&modf) },
        .{ .darwin_symbol = "_erf", .linux_equiv = "libm:erf", .status = .NATIVE_MAPPING, .address = @intFromPtr(&erf) },
        .{ .darwin_symbol = "_erfc", .linux_equiv = "libm:erfc", .status = .NATIVE_MAPPING, .address = @intFromPtr(&erfc) },
        .{ .darwin_symbol = "_lgamma", .linux_equiv = "libm:lgamma", .status = .NATIVE_MAPPING, .address = @intFromPtr(&lgamma) },
        .{ .darwin_symbol = "_lgamma_r", .linux_equiv = "libm:lgamma_r", .status = .NATIVE_MAPPING, .address = @intFromPtr(&lgamma_r) },
        .{ .darwin_symbol = "_tgamma", .linux_equiv = "libm:tgamma", .status = .NATIVE_MAPPING, .address = @intFromPtr(&tgamma) },
        .{ .darwin_symbol = "_j0", .linux_equiv = "libm:j0", .status = .NATIVE_MAPPING, .address = @intFromPtr(&j0) },
        .{ .darwin_symbol = "_j1", .linux_equiv = "libm:j1", .status = .NATIVE_MAPPING, .address = @intFromPtr(&j1) },
        .{ .darwin_symbol = "_jn", .linux_equiv = "libm:jn", .status = .NATIVE_MAPPING, .address = @intFromPtr(&jn) },
        .{ .darwin_symbol = "_y0", .linux_equiv = "libm:y0", .status = .NATIVE_MAPPING, .address = @intFromPtr(&y0) },
        .{ .darwin_symbol = "_y1", .linux_equiv = "libm:y1", .status = .NATIVE_MAPPING, .address = @intFromPtr(&y1) },
        .{ .darwin_symbol = "_yn", .linux_equiv = "libm:yn", .status = .NATIVE_MAPPING, .address = @intFromPtr(&yn) },
        .{ .darwin_symbol = "_nextafter", .linux_equiv = "libm:nextafter", .status = .NATIVE_MAPPING, .address = @intFromPtr(&nextafter) },
        .{ .darwin_symbol = "_nexttoward", .linux_equiv = "libm:nexttoward", .status = .NATIVE_MAPPING, .address = @intFromPtr(&nexttoward) },
        .{ .darwin_symbol = "_scalbln", .linux_equiv = "libm:scalbln", .status = .NATIVE_MAPPING, .address = @intFromPtr(&scalbln) },
        .{ .darwin_symbol = "_scalb", .linux_equiv = "libm:scalb", .status = .NATIVE_MAPPING, .address = @intFromPtr(&scalb) },
        .{ .darwin_symbol = "_fclose", .linux_equiv = "libc:fclose(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_fclose) },
        .{ .darwin_symbol = "_fread", .linux_equiv = "libc:fread(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_fread) },
        .{ .darwin_symbol = "_fwrite", .linux_equiv = "libc:fwrite(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_fwrite) },
        .{ .darwin_symbol = "_fflush", .linux_equiv = "libc:fflush(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_fflush) },
        .{ .darwin_symbol = "_fseek", .linux_equiv = "libc:fseek(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_fseek) },
        .{ .darwin_symbol = "_ftell", .linux_equiv = "libc:ftell(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_ftell) },
        .{ .darwin_symbol = "_fgets", .linux_equiv = "libc:fgets(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_fgets) },
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
        .{ .darwin_symbol = "___sprintf_chk", .linux_equiv = "libc:vsnprintf+bounds", .status = .THIN_SHIM, .address = @intFromPtr(&shim_sprintf_chk) },
        .{ .darwin_symbol = "___snprintf_chk", .linux_equiv = "libc:vsnprintf+bounds", .status = .THIN_SHIM, .address = @intFromPtr(&shim_snprintf_chk) },
        .{ .darwin_symbol = "__DefaultRuneLocale", .linux_equiv = "reimplemented:DarwinRuneLocale", .status = .REIMPLEMENTED, .address = @intFromPtr(&darwin_default_rune_locale) },
        .{ .darwin_symbol = "___maskrune", .linux_equiv = "reimplemented:maskrune", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_maskrune) },
        .{ .darwin_symbol = "___mb_cur_max", .linux_equiv = "libc:__ctype_get_mb_cur_max", .status = .THIN_SHIM, .address = @intFromPtr(&shim_mb_cur_max) },
        .{ .darwin_symbol = "____mb_cur_max", .linux_equiv = "libc:__ctype_get_mb_cur_max", .status = .THIN_SHIM, .address = @intFromPtr(&shim_mb_cur_max) },
        .{ .darwin_symbol = "____mb_cur_max_l", .linux_equiv = "libc:__ctype_get_mb_cur_max", .status = .THIN_SHIM, .address = @intFromPtr(&shim_mb_cur_max_l) },
        .{ .darwin_symbol = "___srget", .linux_equiv = "libc:fgetc(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_srget) },
        .{ .darwin_symbol = "___swbuf", .linux_equiv = "libc:fputc(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_swbuf) },
        .{ .darwin_symbol = "_getprogname", .linux_equiv = "runtime:basename(target_path)", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_getprogname) },
        .{ .darwin_symbol = "_setjmp", .linux_equiv = "reimplemented:darwin_setjmp_x86_64", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_setjmp) },
        .{ .darwin_symbol = "_longjmp", .linux_equiv = "reimplemented:darwin_longjmp_x86_64", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_longjmp) },
        .{ .darwin_symbol = "_qsort_r", .linux_equiv = "libc:qsort_r(bsd_to_gnu)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_qsort_r) },
        .{ .darwin_symbol = "_strerror_r", .linux_equiv = "reimplemented:xsi_strerror_r", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_strerror_r) },
        .{ .darwin_symbol = "_sigemptyset", .linux_equiv = "reimplemented:darwin_sigset32", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_sigemptyset) },
        .{ .darwin_symbol = "_sigaddset", .linux_equiv = "reimplemented:darwin_sigset32", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_sigaddset) },
        .{ .darwin_symbol = "_sigismember", .linux_equiv = "reimplemented:darwin_sigset32", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_sigismember) },
        .{ .darwin_symbol = "_sigaction", .linux_equiv = "linux:sigaction(mapped)", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_sigaction) },
        .{ .darwin_symbol = "_sigprocmask", .linux_equiv = "linux:sigprocmask(mapped)", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_sigprocmask) },
        .{ .darwin_symbol = "_sigaltstack", .linux_equiv = "linux:sigaltstack(mapped)", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_sigaltstack) },
        .{ .darwin_symbol = "_kill", .linux_equiv = "libc:kill(mapped_sig)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_kill) },
        .{ .darwin_symbol = "_localeconv", .linux_equiv = "libc:localeconv", .status = .NATIVE_MAPPING, .address = @intFromPtr(&localeconv) },
        .{ .darwin_symbol = "_uselocale", .linux_equiv = "libc:uselocale", .status = .NATIVE_MAPPING, .address = @intFromPtr(&uselocale) },
        .{ .darwin_symbol = "_flockfile", .linux_equiv = "libc:flockfile(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_flockfile) },
        .{ .darwin_symbol = "_funlockfile", .linux_equiv = "libc:funlockfile(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_funlockfile) },
        .{ .darwin_symbol = "_putc_unlocked", .linux_equiv = "libc:putc_unlocked(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_putc_unlocked) },
        .{ .darwin_symbol = "_freopen", .linux_equiv = "libc:freopen(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_freopen) },
        .{ .darwin_symbol = "_vprintf", .linux_equiv = "libc:vprintf", .status = .NATIVE_MAPPING, .address = @intFromPtr(&vprintf) },
        .{ .darwin_symbol = "_setvbuf", .linux_equiv = "libc:setvbuf(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_setvbuf) },
        .{ .darwin_symbol = "_popen$DARWIN_EXTSN", .linux_equiv = "libc:popen(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_popen) },
        .{ .darwin_symbol = "_pclose", .linux_equiv = "libc:pclose(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_pclose) },
        .{ .darwin_symbol = "_lseek", .linux_equiv = "libc:lseek", .status = .NATIVE_MAPPING, .address = @intFromPtr(&lseek) },
        .{ .darwin_symbol = "_dup2", .linux_equiv = "libc:dup2", .status = .NATIVE_MAPPING, .address = @intFromPtr(&dup2) },
        .{ .darwin_symbol = "_waitpid", .linux_equiv = "libc:waitpid", .status = .NATIVE_MAPPING, .address = @intFromPtr(&waitpid) },
        .{ .darwin_symbol = "_execl", .linux_equiv = "libc:execl", .status = .NATIVE_MAPPING, .address = @intFromPtr(&execl) },
        .{ .darwin_symbol = "_execv", .linux_equiv = "libc:execv", .status = .NATIVE_MAPPING, .address = @intFromPtr(&execv) },
        .{ .darwin_symbol = "_execvp", .linux_equiv = "libc:execvp", .status = .NATIVE_MAPPING, .address = @intFromPtr(&execvp) },
        .{ .darwin_symbol = "_openat", .linux_equiv = "libc:openat(mapped)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_openat) },
        .{ .darwin_symbol = "_fstatat$INODE64", .linux_equiv = "linux:fstatat->DarwinStat64", .status = .REIMPLEMENTED, .address = @intFromPtr(&fs_shim.shim_fstatat) },
        .{ .darwin_symbol = "_fdopendir$INODE64", .linux_equiv = "libc:fdopendir", .status = .THIN_SHIM, .address = @intFromPtr(&fs_shim.shim_fdopendir) },
        .{ .darwin_symbol = "_readlinkat", .linux_equiv = "libc:readlinkat(mapped)", .status = .THIN_SHIM, .address = @intFromPtr(&fs_shim.shim_readlinkat) },
        .{ .darwin_symbol = "_mkstemp", .linux_equiv = "libc:mkstemp", .status = .NATIVE_MAPPING, .address = @intFromPtr(&mkstemp) },
        .{ .darwin_symbol = "_mkostemp", .linux_equiv = "libc:mkostemp(mapped_O)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_mkostemp) },
        .{ .darwin_symbol = "_rename", .linux_equiv = "libc:rename", .status = .NATIVE_MAPPING, .address = @intFromPtr(&rename) },
        .{ .darwin_symbol = "_chmod", .linux_equiv = "libc:chmod", .status = .NATIVE_MAPPING, .address = @intFromPtr(&chmod) },
        .{ .darwin_symbol = "_umask", .linux_equiv = "libc:umask", .status = .NATIVE_MAPPING, .address = @intFromPtr(&umask) },
        .{ .darwin_symbol = "_stpcpy", .linux_equiv = "libc:stpcpy", .status = .NATIVE_MAPPING, .address = @intFromPtr(&stpcpy) },
        .{ .darwin_symbol = "_strnlen", .linux_equiv = "libc:strnlen", .status = .NATIVE_MAPPING, .address = @intFromPtr(&strnlen) },
        .{ .darwin_symbol = "_strtoimax", .linux_equiv = "libc:strtoimax", .status = .NATIVE_MAPPING, .address = @intFromPtr(&strtoimax) },
        .{ .darwin_symbol = "_tzset", .linux_equiv = "libc:tzset", .status = .NATIVE_MAPPING, .address = @intFromPtr(&tzset) },
        .{ .darwin_symbol = "_timespec_get", .linux_equiv = "libc:timespec_get", .status = .NATIVE_MAPPING, .address = @intFromPtr(&timespec_get) },
        .{ .darwin_symbol = "_clock", .linux_equiv = "libc:clock", .status = .NATIVE_MAPPING, .address = @intFromPtr(&clock) },
        .{ .darwin_symbol = "_sysconf", .linux_equiv = "libc:sysconf(mapped_SC)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_sysconf) },
        .{ .darwin_symbol = "_pthread_cond_init", .linux_equiv = "libpthread:pthread_cond_init", .status = .THIN_SHIM, .address = @intFromPtr(&shim_pthread_cond_init) },
        .{ .darwin_symbol = "_pthread_cond_destroy", .linux_equiv = "libpthread:pthread_cond_destroy", .status = .THIN_SHIM, .address = @intFromPtr(&shim_pthread_cond_destroy) },
        .{ .darwin_symbol = "_pthread_cond_wait", .linux_equiv = "libpthread:pthread_cond_wait", .status = .THIN_SHIM, .address = @intFromPtr(&shim_pthread_cond_wait) },
        .{ .darwin_symbol = "_pthread_cond_signal", .linux_equiv = "libpthread:pthread_cond_signal", .status = .THIN_SHIM, .address = @intFromPtr(&shim_pthread_cond_signal) },
        .{ .darwin_symbol = "_pthread_cond_broadcast", .linux_equiv = "libpthread:pthread_cond_broadcast", .status = .THIN_SHIM, .address = @intFromPtr(&shim_pthread_cond_broadcast) },
        .{ .darwin_symbol = "_mbrtowc", .linux_equiv = "libc:mbrtowc", .status = .NATIVE_MAPPING, .address = @intFromPtr(&mbrtowc) },
        .{ .darwin_symbol = "_mbsinit", .linux_equiv = "libc:mbsinit", .status = .NATIVE_MAPPING, .address = @intFromPtr(&mbsinit) },
        .{ .darwin_symbol = "_wcrtomb", .linux_equiv = "libc:wcrtomb", .status = .NATIVE_MAPPING, .address = @intFromPtr(&wcrtomb) },
        .{ .darwin_symbol = "_mbsrtowcs", .linux_equiv = "libc:mbsrtowcs", .status = .NATIVE_MAPPING, .address = @intFromPtr(&mbsrtowcs) },
        .{ .darwin_symbol = "_btowc", .linux_equiv = "libc:btowc", .status = .NATIVE_MAPPING, .address = @intFromPtr(&btowc) },
        .{ .darwin_symbol = "_wctob", .linux_equiv = "libc:wctob", .status = .NATIVE_MAPPING, .address = @intFromPtr(&wctob) },
        .{ .darwin_symbol = "_wcwidth", .linux_equiv = "libc:wcwidth", .status = .NATIVE_MAPPING, .address = @intFromPtr(&wcwidth) },
        .{ .darwin_symbol = "_wctype", .linux_equiv = "libc:wctype", .status = .NATIVE_MAPPING, .address = @intFromPtr(&wctype) },
        .{ .darwin_symbol = "_wcslen", .linux_equiv = "libc:wcslen", .status = .NATIVE_MAPPING, .address = @intFromPtr(&wcslen) },
        .{ .darwin_symbol = "_wcscat", .linux_equiv = "libc:wcscat", .status = .NATIVE_MAPPING, .address = @intFromPtr(&wcscat) },
        .{ .darwin_symbol = "_wmemcpy", .linux_equiv = "libc:wmemcpy", .status = .NATIVE_MAPPING, .address = @intFromPtr(&wmemcpy) },
        .{ .darwin_symbol = "_wmemchr", .linux_equiv = "libc:wmemchr", .status = .NATIVE_MAPPING, .address = @intFromPtr(&wmemchr) },
        .{ .darwin_symbol = "_isalnum", .linux_equiv = "libc:isalnum", .status = .NATIVE_MAPPING, .address = @intFromPtr(&isalnum) },
        .{ .darwin_symbol = "_isalpha", .linux_equiv = "libc:isalpha", .status = .NATIVE_MAPPING, .address = @intFromPtr(&isalpha) },
        .{ .darwin_symbol = "_isblank", .linux_equiv = "libc:isblank", .status = .NATIVE_MAPPING, .address = @intFromPtr(&isblank) },
        .{ .darwin_symbol = "_iscntrl", .linux_equiv = "libc:iscntrl", .status = .NATIVE_MAPPING, .address = @intFromPtr(&iscntrl) },
        .{ .darwin_symbol = "_isdigit", .linux_equiv = "libc:isdigit", .status = .NATIVE_MAPPING, .address = @intFromPtr(&isdigit) },
        .{ .darwin_symbol = "_isgraph", .linux_equiv = "libc:isgraph", .status = .NATIVE_MAPPING, .address = @intFromPtr(&isgraph) },
        .{ .darwin_symbol = "_islower", .linux_equiv = "libc:islower", .status = .NATIVE_MAPPING, .address = @intFromPtr(&islower) },
        .{ .darwin_symbol = "_isprint", .linux_equiv = "libc:isprint", .status = .NATIVE_MAPPING, .address = @intFromPtr(&isprint) },
        .{ .darwin_symbol = "_ispunct", .linux_equiv = "libc:ispunct", .status = .NATIVE_MAPPING, .address = @intFromPtr(&ispunct) },
        .{ .darwin_symbol = "_isspace", .linux_equiv = "libc:isspace", .status = .NATIVE_MAPPING, .address = @intFromPtr(&isspace) },
        .{ .darwin_symbol = "_isupper", .linux_equiv = "libc:isupper", .status = .NATIVE_MAPPING, .address = @intFromPtr(&isupper) },
        .{ .darwin_symbol = "_isxdigit", .linux_equiv = "libc:isxdigit", .status = .NATIVE_MAPPING, .address = @intFromPtr(&isxdigit) },
        .{ .darwin_symbol = "_mach_task_self_", .linux_equiv = "stub:mach_task_self", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&darwin_mach_task_self) },
        .{ .darwin_symbol = "_mach_port_deallocate", .linux_equiv = "stub:mach_port_deallocate", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&shim_mach_port_deallocate) },
        .{ .darwin_symbol = "_vm_region_64", .linux_equiv = "stub:vm_region_64(KERN_INVALID_ADDRESS)", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&shim_vm_region_64) },
        .{ .darwin_symbol = "_acl_init", .linux_equiv = "stub:acl_enotsup", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&shim_acl_unsupported_ptr) },
        .{ .darwin_symbol = "_acl_get_fd", .linux_equiv = "stub:acl_enotsup", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&shim_acl_unsupported_ptr) },
        .{ .darwin_symbol = "_acl_get_file", .linux_equiv = "stub:acl_enotsup", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&shim_acl_unsupported_ptr) },
        .{ .darwin_symbol = "_acl_set_fd", .linux_equiv = "stub:acl_enotsup", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&shim_acl_unsupported_int) },
        .{ .darwin_symbol = "_acl_set_file", .linux_equiv = "stub:acl_enotsup", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&shim_acl_unsupported_int) },
        .{ .darwin_symbol = "_acl_get_entry", .linux_equiv = "stub:acl_enotsup", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&shim_acl_unsupported_int) },
        .{ .darwin_symbol = "_acl_free", .linux_equiv = "stub:acl_free_nop", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&shim_acl_free) },
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
        .{ .darwin_symbol = "_fputc", .linux_equiv = "libc:fputc(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_fputc) },
        .{ .darwin_symbol = "_putchar", .linux_equiv = "libc:putchar", .status = .NATIVE_MAPPING, .address = @intFromPtr(&putchar) },
        .{ .darwin_symbol = "_ceil", .linux_equiv = "libm:ceil", .status = .NATIVE_MAPPING, .address = @intFromPtr(&ceil) },
        .{ .darwin_symbol = "_posix_memalign", .linux_equiv = "libc:posix_memalign", .status = .NATIVE_MAPPING, .address = @intFromPtr(&posix_memalign) },
        .{ .darwin_symbol = "_fputs", .linux_equiv = "libc:fputs(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_fputs) },
        .{ .darwin_symbol = "_putc", .linux_equiv = "libc:fputc(DarwinFile)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_fputc) },
        .{ .darwin_symbol = "_mbstowcs", .linux_equiv = "libc:mbstowcs", .status = .NATIVE_MAPPING, .address = @intFromPtr(&mbstowcs) },
        .{ .darwin_symbol = "_time", .linux_equiv = "libc:time", .status = .NATIVE_MAPPING, .address = @intFromPtr(&time) },
        .{ .darwin_symbol = "_localtime", .linux_equiv = "libc:localtime", .status = .NATIVE_MAPPING, .address = @intFromPtr(&localtime) },
        .{ .darwin_symbol = "_strftime", .linux_equiv = "libc:strftime", .status = .NATIVE_MAPPING, .address = @intFromPtr(&strftime) },
        .{ .darwin_symbol = "_setlocale", .linux_equiv = "libc:setlocale(mapped_LC)", .status = .THIN_SHIM, .address = @intFromPtr(&shim_setlocale) },
        .{ .darwin_symbol = "_gethostname", .linux_equiv = "libc:gethostname", .status = .NATIVE_MAPPING, .address = @intFromPtr(&gethostname) },
        .{ .darwin_symbol = "_readlink", .linux_equiv = "libc:readlink", .status = .NATIVE_MAPPING, .address = @intFromPtr(&readlink) },
        .{ .darwin_symbol = "_realpath$DARWIN_EXTSN", .linux_equiv = "libc:realpath", .status = .NATIVE_MAPPING, .address = @intFromPtr(&realpath) },
        .{ .darwin_symbol = "_getpwuid", .linux_equiv = "linux:getpwuid->DarwinPasswd", .status = .REIMPLEMENTED, .address = @intFromPtr(&shim_getpwuid) },
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
        .{ .darwin_symbol = "__swift_stdlib_nfd_decompositions", .linux_equiv = "swift:unicode_nfd_table_stub", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&swift_shim.swift_stdlib_nfd_decompositions) },
        .{ .darwin_symbol = "__swift_stdlib_getNormData", .linux_equiv = "swift:unicode_norm_data_stub", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&swift_shim.shim_swift_stdlib_getNormData) },
        .{ .darwin_symbol = "__swift_stdlib_getGraphemeBreakProperty", .linux_equiv = "swift:unicode_grapheme_stub", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&swift_shim.shim_swift_stdlib_getGraphemeBreakProperty) },
        .{ .darwin_symbol = "__swift_stdlib_isExtendedPictographic", .linux_equiv = "swift:unicode_pictographic_stub", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&swift_shim.shim_swift_stdlib_isExtendedPictographic) },
        .{ .darwin_symbol = "__swift_stdlib_isInCB_Consonant", .linux_equiv = "swift:unicode_incb_stub", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&swift_shim.shim_swift_stdlib_isInCB_Consonant) },
        .{ .darwin_symbol = "__swift_stdlib_getComposition", .linux_equiv = "swift:unicode_composition_stub", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&swift_shim.shim_swift_stdlib_getComposition) },
        .{ .darwin_symbol = "__swift_stdlib_getDecompositionEntry", .linux_equiv = "swift:unicode_decomposition_stub", .status = .STUB_FOR_PROBE_ONLY, .address = @intFromPtr(&swift_shim.shim_swift_stdlib_getDecompositionEntry) },
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
        std.mem.startsWith(u8, path, "/usr/lib/libobjc") or
        std.mem.startsWith(u8, path, "/usr/lib/swift/") or
        std.mem.startsWith(u8, path, "/usr/lib/libc++") or
        std.mem.startsWith(u8, path, "/usr/lib/libedit") or
        std.mem.startsWith(u8, path, "/usr/lib/libncurses") or
        std.mem.startsWith(u8, path, "/usr/lib/libz.") or
        std.mem.startsWith(u8, path, "/System/Library/");
}
