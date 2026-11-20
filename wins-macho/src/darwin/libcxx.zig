//! Darwin libc++.1.dylib & Itanium C++ ABI Runtime for WINS-MachO
//!
//! Implements the exact macOS x86_64 LLVM libc++ (std::__1) ABI layouts verified
//! against real macOS Sonoma C++ Mach-O binaries (e.g. pzstd):
//! - operator new / delete
//! - std::__1::basic_string<char> (24-byte ABI v1 SSO: bit 0 of byte 0 == is_long)
//! - std::__1::mutex / condition_variable (over Darwin 0x32AAABA7 / 0x3CB0B1BB)
//! - std::__1::thread / __thread_struct / __thread_local_data
//! - std::__1::__shared_weak_count (atomic weak refcount + virtual slot 4 destroy)
//! - std::__1::chrono::system_clock::now() (microseconds)
//! - std::__1::system_category / generic_category
//! - Itanium RTTI / std::exception hierarchy / __cxa_* exception primitives

const std = @import("std");
const trace = @import("../runtime/trace.zig");
const shims = @import("shims.zig");

extern "c" fn malloc(size: usize) ?*anyopaque;
extern "c" fn calloc(nmemb: usize, size: usize) ?*anyopaque;
extern "c" fn free(ptr: ?*anyopaque) void;
extern "c" fn memcpy(dst: *anyopaque, src: *const anyopaque, n: usize) *anyopaque;
extern "c" fn strlen(s: [*:0]const u8) usize;
extern "c" fn strerror(errnum: c_int) [*:0]u8;
extern "c" fn clock_gettime(clk_id: c_int, tp: *std.c.timespec) c_int;
extern "c" fn sysconf(name: c_int) c_long;
extern "c" fn pthread_join(thread: usize, retval: ?*?*anyopaque) c_int;
extern "c" fn pthread_key_create(key: *u32, destructor: ?*const fn (?*anyopaque) callconv(.c) void) c_int;
extern "c" fn abort() noreturn;

// ============================================================================
// operator new / delete
// ============================================================================

pub fn shim_operator_new(size: usize) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("__Znwm");
    return malloc(@max(size, 1));
}

pub fn shim_operator_new_array(size: usize) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("__Znam");
    return malloc(@max(size, 1));
}

pub fn shim_operator_delete(ptr: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("__ZdlPv");
    free(ptr);
}

pub fn shim_operator_delete_array(ptr: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("__ZdaPv");
    free(ptr);
}

// ============================================================================
// std::__1::basic_string<char> (macOS x86_64 libc++ ABI v1: 24-byte SSO)
// Short: byte[0] = (len << 1) [bit 0 == 0], data = byte[1..1+len], len <= 22
// Long:  words[0] = cap | 1   [bit 0 == 1], words[1] = len, words[2] = ptr
// ============================================================================

pub const LibcxxString = extern union {
    raw: [24]u8,
    long: extern struct {
        cap_flag: usize,
        size: usize,
        data: ?[*]u8,
    },

    pub fn isLong(self: *const LibcxxString) bool {
        return (self.raw[0] & 1) != 0;
    }

    pub fn slice(self: *const LibcxxString) []const u8 {
        if (self.isLong()) {
            const p = self.long.data orelse return "";
            return p[0..self.long.size];
        }
        const len: usize = self.raw[0] >> 1;
        return self.raw[1 .. 1 + @min(len, 22)];
    }

    pub fn assignSlice(self: *LibcxxString, src: []const u8) void {
        if (self.isLong()) {
            const cap = self.long.cap_flag & ~@as(usize, 1);
            if (self.long.data != null and src.len < cap) {
                const dst = self.long.data.?;
                if (src.len > 0) _ = memcpy(@ptrCast(dst), src.ptr, src.len);
                dst[src.len] = 0;
                self.long.size = src.len;
                return;
            }
            if (self.long.data) |old| free(@ptrCast(old));
            self.raw = .{0} ** 24;
        }
        if (src.len <= 22) {
            self.raw[0] = @intCast(src.len << 1);
            if (src.len > 0) @memcpy(self.raw[1 .. 1 + src.len], src);
            self.raw[1 + src.len] = 0;
            return;
        }
        // Long allocation: align capacity up to 16-byte multiple (matches Apple libc++ (len | 15) + 1)
        const alloc_sz = (src.len | 0xf) + 1;
        const buf_raw = malloc(alloc_sz) orelse abort();
        const dst: [*]u8 = @ptrCast(buf_raw);
        if (src.len > 0) _ = memcpy(buf_raw, src.ptr, src.len);
        dst[src.len] = 0;
        self.long.cap_flag = alloc_sz | 1;
        self.long.size = src.len;
        self.long.data = dst;
    }
};

comptime {
    std.debug.assert(@sizeOf(LibcxxString) == 24);
}

pub fn shim_string_dtor(self: *LibcxxString) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev");
    if (self.isLong()) {
        if (self.long.data) |p| free(@ptrCast(p));
        self.raw = .{0} ** 24;
    }
}

pub fn shim_string_assign_cstr(self: *LibcxxString, s: ?[*:0]const u8) callconv(.c) *LibcxxString {
    if (trace.active_tracer) |t| t.recordExternalCall("__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKc");
    const cstr = s orelse {
        self.assignSlice("");
        return self;
    };
    const len = strlen(cstr);
    // Copy to temporary buffer if aliasing self
    if (len > 0) {
        const tmp = malloc(len) orelse abort();
        defer free(tmp);
        _ = memcpy(tmp, cstr, len);
        self.assignSlice(@as([*]const u8, @ptrCast(tmp))[0..len]);
    } else {
        self.assignSlice("");
    }
    return self;
}

pub fn shim_string_ctor_substr(
    self: *LibcxxString,
    other: *const LibcxxString,
    pos: usize,
    n: usize,
    alloc_unused: ?*const anyopaque,
) callconv(.c) void {
    _ = alloc_unused;
    if (trace.active_tracer) |t| t.recordExternalCall("__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2ERKS5_mmRKS4_");
    self.raw = .{0} ** 24;
    const src = other.slice();
    if (pos > src.len) {
        std.debug.print("WINS-LIBCXX: basic_string substring pos={d} > len={d}\n", .{ pos, src.len });
        abort();
    }
    const count = @min(n, src.len - pos);
    self.assignSlice(src[pos .. pos + count]);
}

// ============================================================================
// std::__1::mutex & std::__1::condition_variable (Darwin layouts)
// ============================================================================

pub fn shim_mutex_lock(mtx: *anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("__ZNSt3__15mutex4lockEv");
    const rc = shims.shim_pthread_mutex_lock(mtx);
    if (rc != 0) shim_throw_system_error(rc, "mutex lock failed");
}

pub fn shim_mutex_unlock(mtx: *anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("__ZNSt3__15mutex6unlockEv");
    _ = shims.shim_pthread_mutex_unlock(mtx);
}

pub fn shim_mutex_dtor(mtx: *anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("__ZNSt3__15mutexD1Ev");
    const sig_ptr: *const u32 = @ptrCast(@alignCast(mtx));
    if (@atomicLoad(u32, sig_ptr, .acquire) == 0x32AAABA7) return; // never initialized on Linux
    _ = shims.shim_pthread_mutex_destroy(mtx);
}

const UniqueLock = extern struct {
    mtx: *anyopaque,
    owns: bool,
};

pub fn shim_cv_wait(cv: *anyopaque, lk: *UniqueLock) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("__ZNSt3__118condition_variable4waitERNS_11unique_lockINS_5mutexEEE");
    _ = shims.shim_pthread_cond_wait(cv, lk.mtx);
}

pub fn shim_cv_notify_one(cv: *anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("__ZNSt3__118condition_variable10notify_oneEv");
    _ = shims.shim_pthread_cond_signal(cv);
}

pub fn shim_cv_notify_all(cv: *anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("__ZNSt3__118condition_variable10notify_allEv");
    _ = shims.shim_pthread_cond_broadcast(cv);
}

pub fn shim_cv_dtor(cv: *anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("__ZNSt3__118condition_variableD1Ev");
    const sig_ptr: *const u32 = @ptrCast(@alignCast(cv));
    if (@atomicLoad(u32, sig_ptr, .acquire) == 0x3CB0B1BB) return; // never initialized on Linux
    _ = shims.shim_pthread_cond_destroy(cv);
}

// ============================================================================
// std::__1::thread, __thread_struct, __thread_local_data
// ============================================================================

const LibcxxThread = extern struct {
    tid: usize,
};

pub fn shim_thread_join(self: *LibcxxThread) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("__ZNSt3__16thread4joinEv");
    if (self.tid == 0) shim_throw_system_error(22, "thread::join failed");
    const rc = pthread_join(self.tid, null);
    if (rc != 0) shim_throw_system_error(rc, "thread::join failed");
    self.tid = 0;
}

pub fn shim_thread_dtor(self: *LibcxxThread) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("__ZNSt3__16threadD1Ev");
    if (self.tid != 0) shim_terminate();
}

pub fn shim_thread_hardware_concurrency() callconv(.c) u32 {
    if (trace.active_tracer) |t| t.recordExternalCall("__ZNSt3__16thread20hardware_concurrencyEv");
    const n = sysconf(84); // _SC_NPROCESSORS_ONLN
    return if (n > 0) @intCast(n) else 1;
}

const LibcxxThreadStruct = extern struct {
    imp: ?*anyopaque,
};

pub fn shim_thread_struct_ctor(self: *LibcxxThreadStruct) callconv(.c) void {
    self.imp = null;
}

pub fn shim_thread_struct_dtor(self: *LibcxxThreadStruct) callconv(.c) void {
    self.imp = null;
}

fn threadStructAtExit(ptr: ?*anyopaque) callconv(.c) void {
    free(ptr);
}

var thread_local_data_key: usize = 0;
var thread_local_data_init_state: i64 = 0;

pub fn shim_thread_local_data() callconv(.c) *usize {
    if (@atomicLoad(i64, &thread_local_data_init_state, .acquire) != -1) {
        if (@cmpxchgStrong(i64, &thread_local_data_init_state, 0, 1, .acq_rel, .acquire) == null) {
            var lx_key: u32 = 0;
            _ = pthread_key_create(&lx_key, &threadStructAtExit);
            thread_local_data_key = @intCast(lx_key);
            @atomicStore(i64, &thread_local_data_init_state, -1, .release);
        } else {
            while (@atomicLoad(i64, &thread_local_data_init_state, .acquire) != -1) {}
        }
    }
    return &thread_local_data_key;
}

// ============================================================================
// std::__1::__shared_weak_count
// Layout: [0] vtable*, [8] __shared_owners_ (isize), [16] __shared_weak_owners_ (isize)
// Vtable: [0] D1 dtor, [1] D0 dtor, [2] __on_zero_shared, [3] __get_deleter, [4] __on_zero_shared_weak
// ============================================================================

pub const SharedWeakCount = extern struct {
    vtable: [*]const usize,
    shared_owners: isize,
    shared_weak_owners: isize,
};

pub fn shim_shared_weak_count_release_weak(self: *SharedWeakCount) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("__ZNSt3__119__shared_weak_count14__release_weakEv");
    if (@atomicLoad(isize, &self.shared_weak_owners, .acquire) == 0) {
        const on_zero_weak: *const fn (*SharedWeakCount) callconv(.c) void = @ptrFromInt(self.vtable[4]);
        on_zero_weak(self);
    } else if (@atomicRmw(isize, &self.shared_weak_owners, .Sub, 1, .acq_rel) == 0) {
        const on_zero_weak: *const fn (*SharedWeakCount) callconv(.c) void = @ptrFromInt(self.vtable[4]);
        on_zero_weak(self);
    }
}

pub fn shim_shared_weak_count_dtor(self: *SharedWeakCount) callconv(.c) void {
    _ = self;
}

pub fn shim_shared_weak_count_get_deleter(self: *const SharedWeakCount, ti: ?*const anyopaque) callconv(.c) ?*const anyopaque {
    _ = self;
    _ = ti;
    return null;
}

// ============================================================================
// std::__1::chrono::system_clock::now() (microseconds)
// ============================================================================

pub fn shim_system_clock_now() callconv(.c) i64 {
    if (trace.active_tracer) |t| t.recordExternalCall("__ZNSt3__16chrono12system_clock3nowEv");
    var ts: std.c.timespec = undefined;
    _ = clock_gettime(0, &ts); // CLOCK_REALTIME
    return @as(i64, ts.sec) * 1_000_000 + @divFloor(@as(i64, ts.nsec), 1000);
}

// ============================================================================
// Itanium C++ ABI RTTI, Exceptions, Error Categories
// ============================================================================

const TypeInfo = extern struct {
    vtable: usize,
    name: [*:0]const u8,
};

const SiTypeInfo = extern struct {
    vtable: usize,
    name: [*:0]const u8,
    base: *const TypeInfo,
};

fn rttiNoop() callconv(.c) void {}
fn rttiFalse() callconv(.c) u8 {
    return 0;
}

// Vtable arrays: C++ vtable pointer points 16 bytes past start ([0]=offset-to-top, [1]=typeinfo, [2..]=virtual funcs)
// Populated at runtime via ensureInitialized() (Zig 0.16 forbids @intFromPtr(&fn) in container-level arrays).
pub var vtable_class_type_info: [8]usize = .{0} ** 8;
pub var vtable_si_class_type_info: [8]usize = .{0} ** 8;

pub var ti_exception: TypeInfo = .{
    .vtable = 0,
    .name = "St9exception",
};

pub var ti_shared_weak_count: TypeInfo = .{
    .vtable = 0,
    .name = "NSt3__119__shared_weak_countE",
};

pub var ti_logic_error: SiTypeInfo = .{
    .vtable = 0,
    .name = "St11logic_error",
    .base = &ti_exception,
};

var ti_logic_error_as_base: TypeInfo = .{ .vtable = 0, .name = "St11logic_error" };

pub var ti_out_of_range: SiTypeInfo = .{
    .vtable = 0,
    .name = "St12out_of_range",
    .base = &ti_logic_error_as_base,
};

pub var ti_length_error: SiTypeInfo = .{
    .vtable = 0,
    .name = "St12length_error",
    .base = &ti_logic_error_as_base,
};

pub var ti_bad_array_new_length: SiTypeInfo = .{
    .vtable = 0,
    .name = "St20bad_array_new_length",
    .base = &ti_exception,
};

const StdException = extern struct {
    vtable: usize,
    msg: ?[*:0]const u8 = null,
};

pub fn shim_exception_dtor(self: *StdException) callconv(.c) void {
    _ = self;
}

pub fn shim_exception_what(self: *const StdException) callconv(.c) [*:0]const u8 {
    return self.msg orelse "std::exception";
}

fn shim_exception_del_dtor(self: *StdException) callconv(.c) void {
    free(@ptrCast(self));
}

pub var vtable_out_of_range: [5]usize = .{0} ** 5;
pub var vtable_length_error: [5]usize = .{0} ** 5;
pub var vtable_bad_array_new_length: [5]usize = .{0} ** 5;

pub fn shim_logic_error_ctor(self: *StdException, what_arg: ?[*:0]const u8) callconv(.c) void {
    ensureInitialized();
    self.vtable = @intFromPtr(&vtable_length_error) + 16;
    self.msg = what_arg orelse "std::logic_error";
}

pub fn shim_bad_array_new_length_ctor(self: *StdException) callconv(.c) void {
    ensureInitialized();
    self.vtable = @intFromPtr(&vtable_bad_array_new_length) + 16;
    self.msg = "std::bad_array_new_length";
}

// std::__1::error_category (system_category / generic_category)
fn sysCatName(_: *const anyopaque) callconv(.c) [*:0]const u8 {
    return "system";
}
fn genCatName(_: *const anyopaque) callconv(.c) [*:0]const u8 {
    return "generic";
}
fn catMessage(out: *LibcxxString, _: *const anyopaque, ev: c_int) callconv(.c) *LibcxxString {
    out.raw = .{0} ** 24;
    out.assignSlice(std.mem.span(strerror(ev)));
    return out;
}

var vtable_sys_category: [8]usize = .{0} ** 8;
var vtable_gen_category: [8]usize = .{0} ** 8;

const ErrorCategoryObj = extern struct {
    vtable: usize,
};

var g_system_category: ErrorCategoryObj = .{ .vtable = 0 };
var g_generic_category: ErrorCategoryObj = .{ .vtable = 0 };

var libcxx_initialized: bool = false;

pub fn ensureInitialized() void {
    if (libcxx_initialized) return;
    libcxx_initialized = true;

    vtable_class_type_info = .{
        0, 0,
        @intFromPtr(&rttiNoop), @intFromPtr(&rttiNoop),
        @intFromPtr(&rttiFalse), @intFromPtr(&rttiFalse),
        @intFromPtr(&rttiFalse), @intFromPtr(&rttiFalse),
    };
    vtable_si_class_type_info = .{
        0, 0,
        @intFromPtr(&rttiNoop), @intFromPtr(&rttiNoop),
        @intFromPtr(&rttiFalse), @intFromPtr(&rttiFalse),
        @intFromPtr(&rttiFalse), @intFromPtr(&rttiFalse),
    };

    const class_ti_vptr = @intFromPtr(&vtable_class_type_info) + 16;
    const si_ti_vptr = @intFromPtr(&vtable_si_class_type_info) + 16;

    ti_exception.vtable = class_ti_vptr;
    ti_shared_weak_count.vtable = class_ti_vptr;
    ti_logic_error.vtable = si_ti_vptr;
    ti_logic_error_as_base.vtable = class_ti_vptr;
    ti_out_of_range.vtable = si_ti_vptr;
    ti_length_error.vtable = si_ti_vptr;
    ti_bad_array_new_length.vtable = si_ti_vptr;

    vtable_out_of_range = .{
        0, @intFromPtr(&ti_out_of_range),
        @intFromPtr(&shim_exception_dtor),
        @intFromPtr(&shim_exception_del_dtor),
        @intFromPtr(&shim_exception_what),
    };
    vtable_length_error = .{
        0, @intFromPtr(&ti_length_error),
        @intFromPtr(&shim_exception_dtor),
        @intFromPtr(&shim_exception_del_dtor),
        @intFromPtr(&shim_exception_what),
    };
    vtable_bad_array_new_length = .{
        0, @intFromPtr(&ti_bad_array_new_length),
        @intFromPtr(&shim_exception_dtor),
        @intFromPtr(&shim_exception_del_dtor),
        @intFromPtr(&shim_exception_what),
    };

    vtable_sys_category = .{
        0, 0,
        @intFromPtr(&rttiNoop), @intFromPtr(&rttiNoop),
        @intFromPtr(&sysCatName),
        @intFromPtr(&rttiNoop),
        @intFromPtr(&rttiFalse),
        @intFromPtr(&catMessage),
    };
    vtable_gen_category = .{
        0, 0,
        @intFromPtr(&rttiNoop), @intFromPtr(&rttiNoop),
        @intFromPtr(&genCatName),
        @intFromPtr(&rttiNoop),
        @intFromPtr(&rttiFalse),
        @intFromPtr(&catMessage),
    };
    g_system_category.vtable = @intFromPtr(&vtable_sys_category) + 16;
    g_generic_category.vtable = @intFromPtr(&vtable_gen_category) + 16;
}

pub fn shim_system_category() callconv(.c) *ErrorCategoryObj {
    ensureInitialized();
    return &g_system_category;
}

pub fn shim_generic_category() callconv(.c) *ErrorCategoryObj {
    ensureInitialized();
    return &g_generic_category;
}

// Exception runtime (alloc/free real; throw/unwind fail loudly — Mach-O __unwind_info unwinding not yet implemented)
pub fn shim_cxa_allocate_exception(thrown_size: usize) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("___cxa_allocate_exception");
    const hdr_size: usize = 128;
    const raw = calloc(1, hdr_size + thrown_size) orelse abort();
    return @ptrFromInt(@intFromPtr(raw) + hdr_size);
}

pub fn shim_cxa_free_exception(thrown_obj: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("___cxa_free_exception");
    const ptr = thrown_obj orelse return;
    free(@ptrFromInt(@intFromPtr(ptr) - 128));
}

pub fn shim_cxa_throw(thrown_obj: ?*anyopaque, tinfo: ?*const TypeInfo, dest: ?*const anyopaque) callconv(.c) noreturn {
    _ = dest;
    if (trace.active_tracer) |t| t.recordUnsupportedCall("___cxa_throw");
    const name = if (tinfo) |ti| std.mem.span(ti.name) else "unknown";
    std.debug.print("WINS-LIBCXX: uncaught C++ exception (type={s}, obj=0x{x})\n", .{ name, @intFromPtr(thrown_obj) });
    abort();
}

pub fn shim_cxa_begin_catch(exc: ?*anyopaque) callconv(.c) ?*anyopaque {
    return exc;
}

pub fn shim_cxa_end_catch() callconv(.c) void {}

pub fn shim_cxa_rethrow() callconv(.c) noreturn {
    if (trace.active_tracer) |t| t.recordUnsupportedCall("___cxa_rethrow");
    std.debug.print("WINS-LIBCXX: __cxa_rethrow called (unwinding unsupported)\n", .{});
    abort();
}

pub fn shim_gxx_personality_v0() callconv(.c) c_int {
    return 8; // _URC_CONTINUE_UNWIND
}

pub fn shim_unwind_resume(exc: ?*anyopaque) callconv(.c) noreturn {
    _ = exc;
    if (trace.active_tracer) |t| t.recordUnsupportedCall("__Unwind_Resume");
    std.debug.print("WINS-LIBCXX: _Unwind_Resume called (unwinding unsupported)\n", .{});
    abort();
}

pub fn shim_unwind_raise_exception(exc: ?*anyopaque) callconv(.c) c_int {
    _ = exc;
    if (trace.active_tracer) |t| t.recordUnsupportedCall("__Unwind_RaiseException");
    std.debug.print("WINS-LIBCXX: _Unwind_RaiseException called (unwinding unsupported)\n", .{});
    return 5; // _URC_END_OF_STACK
}

pub fn shim_unwind_get_ip(ctx: ?*anyopaque) callconv(.c) usize {
    _ = ctx;
    return 0;
}

pub fn shim_unwind_set_ip(ctx: ?*anyopaque, val: usize) callconv(.c) void {
    _ = ctx;
    _ = val;
}

pub fn shim_unwind_set_gr(ctx: ?*anyopaque, index: c_int, val: usize) callconv(.c) void {
    _ = ctx;
    _ = index;
    _ = val;
}

pub fn shim_unwind_get_lsda(ctx: ?*anyopaque) callconv(.c) ?*const anyopaque {
    _ = ctx;
    return null;
}

pub fn shim_unwind_get_region_start(ctx: ?*anyopaque) callconv(.c) usize {
    _ = ctx;
    return 0;
}

pub fn shim_terminate() callconv(.c) noreturn {
    if (trace.active_tracer) |t| t.recordExternalCall("__ZSt9terminatev");
    std.debug.print("WINS-LIBCXX: std::terminate()\n", .{});
    abort();
}

pub fn shim_throw_system_error(ev: c_int, what_arg: ?[*:0]const u8) callconv(.c) noreturn {
    if (trace.active_tracer) |t| t.recordUnsupportedCall("__ZNSt3__120__throw_system_errorEiPKc");
    const msg = if (what_arg) |p| std.mem.span(p) else "system_error";
    std.debug.print("WINS-LIBCXX: std::system_error(ev={d}): {s}\n", .{ ev, msg });
    abort();
}
