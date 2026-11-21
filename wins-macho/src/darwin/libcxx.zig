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
const unwind = @import("unwind.zig");

extern "c" fn malloc(size: usize) ?*anyopaque;
extern "c" fn calloc(nmemb: usize, size: usize) ?*anyopaque;
extern "c" fn free(ptr: ?*anyopaque) void;
extern "c" fn memcpy(dst: *anyopaque, src: *const anyopaque, n: usize) *anyopaque;
extern "c" fn strlen(s: [*:0]const u8) usize;
extern "c" fn strcmp(a: [*:0]const u8, b: [*:0]const u8) c_int;
extern "c" fn strdup(s: [*:0]const u8) ?[*:0]u8;
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

pub fn shim_operator_delete_sized(ptr: ?*anyopaque, size: usize) callconv(.c) void {
    _ = size;
    if (trace.active_tracer) |t| t.recordExternalCall("__ZdlPvm");
    free(ptr);
}

pub fn shim_operator_delete_array(ptr: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("__ZdaPv");
    free(ptr);
}

pub fn shim_operator_delete_array_sized(ptr: ?*anyopaque, size: usize) callconv(.c) void {
    _ = size;
    if (trace.active_tracer) |t| t.recordExternalCall("__ZdaPvm");
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

const BaseClassTypeInfo = extern struct {
    base_type: *const TypeInfo,
    offset_flags: isize,
};

const VmiTypeInfo = extern struct {
    vtable: usize,
    name: [*:0]const u8,
    flags: u32,
    base_count: u32,
    // followed by base_count BaseClassTypeInfo entries
};

const PointerTypeInfo = extern struct {
    vtable: usize,
    name: [*:0]const u8,
    flags: u32,
    pad: u32,
    pointee: *const TypeInfo,
};

// Vtable arrays: C++ vtable pointer points 16 bytes past start ([0]=offset-to-top, [1]=typeinfo, [2..]=virtual funcs)
// Populated at runtime via ensureInitialized() (Zig 0.16 forbids @intFromPtr(&fn) in container-level arrays).
pub var vtable_class_type_info: [8]usize = .{0} ** 8;
pub var vtable_si_class_type_info: [8]usize = .{0} ** 8;
pub var vtable_vmi_class_type_info: [8]usize = .{0} ** 8;
pub var vtable_fundamental_type_info: [8]usize = .{0} ** 8;
pub var vtable_pointer_type_info: [8]usize = .{0} ** 8;

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

pub var ti_runtime_error: SiTypeInfo = .{
    .vtable = 0,
    .name = "St13runtime_error",
    .base = &ti_exception,
};

pub var ti_out_of_range: SiTypeInfo = .{
    .vtable = 0,
    .name = "St12out_of_range",
    .base = &ti_exception, // wired to &ti_logic_error in ensureInitialized()
};

pub var ti_length_error: SiTypeInfo = .{
    .vtable = 0,
    .name = "St12length_error",
    .base = &ti_exception, // wired to &ti_logic_error in ensureInitialized()
};

pub var ti_invalid_argument: SiTypeInfo = .{
    .vtable = 0,
    .name = "St16invalid_argument",
    .base = &ti_exception, // wired to &ti_logic_error in ensureInitialized()
};

pub var ti_bad_alloc: SiTypeInfo = .{
    .vtable = 0,
    .name = "St9bad_alloc",
    .base = &ti_exception,
};

pub var ti_bad_array_new_length: SiTypeInfo = .{
    .vtable = 0,
    .name = "St20bad_array_new_length",
    .base = &ti_exception,
};

pub var ti_int: TypeInfo = .{ .vtable = 0, .name = "i" };
pub var ti_char: TypeInfo = .{ .vtable = 0, .name = "c" };
pub var ti_long: TypeInfo = .{ .vtable = 0, .name = "l" };
pub var ti_double: TypeInfo = .{ .vtable = 0, .name = "d" };
pub var ti_cstr: PointerTypeInfo = .{ .vtable = 0, .name = "PKc", .flags = 1, .pad = 0, .pointee = &ti_char };

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

pub var vtable_runtime_error: [5]usize = .{0} ** 5;
pub var vtable_logic_error: [5]usize = .{0} ** 5;
pub var vtable_out_of_range: [5]usize = .{0} ** 5;
pub var vtable_length_error: [5]usize = .{0} ** 5;
pub var vtable_invalid_argument: [5]usize = .{0} ** 5;
pub var vtable_bad_alloc: [5]usize = .{0} ** 5;
pub var vtable_bad_array_new_length: [5]usize = .{0} ** 5;

pub fn shim_logic_error_ctor(self: *StdException, what_arg: ?[*:0]const u8) callconv(.c) void {
    ensureInitialized();
    self.vtable = @intFromPtr(&vtable_logic_error) + 16;
    self.msg = if (what_arg) |p| strdup(p) orelse p else "std::logic_error";
}

pub fn shim_runtime_error_ctor(self: *StdException, what_arg: ?[*:0]const u8) callconv(.c) void {
    ensureInitialized();
    self.vtable = @intFromPtr(&vtable_runtime_error) + 16;
    self.msg = if (what_arg) |p| strdup(p) orelse p else "std::runtime_error";
}

pub fn shim_runtime_error_ctor_str(self: *StdException, what_str: *const LibcxxString) callconv(.c) void {
    ensureInitialized();
    self.vtable = @intFromPtr(&vtable_runtime_error) + 16;
    const s = what_str.slice();
    if (malloc(s.len + 1)) |buf_raw| {
        const dst: [*]u8 = @ptrCast(buf_raw);
        if (s.len > 0) @memcpy(dst[0..s.len], s);
        dst[s.len] = 0;
        self.msg = @ptrCast(dst);
    } else {
        self.msg = "std::runtime_error";
    }
}

pub fn shim_logic_error_ctor_str(self: *StdException, what_str: *const LibcxxString) callconv(.c) void {
    ensureInitialized();
    self.vtable = @intFromPtr(&vtable_logic_error) + 16;
    const s = what_str.slice();
    if (malloc(s.len + 1)) |buf_raw| {
        const dst: [*]u8 = @ptrCast(buf_raw);
        if (s.len > 0) @memcpy(dst[0..s.len], s);
        dst[s.len] = 0;
        self.msg = @ptrCast(dst);
    } else {
        self.msg = "std::logic_error";
    }
}

pub fn shim_bad_array_new_length_ctor(self: *StdException) callconv(.c) void {
    ensureInitialized();
    self.vtable = @intFromPtr(&vtable_bad_array_new_length) + 16;
    self.msg = "std::bad_array_new_length";
}

pub fn shim_bad_alloc_ctor(self: *StdException) callconv(.c) void {
    ensureInitialized();
    self.vtable = @intFromPtr(&vtable_bad_alloc) + 16;
    self.msg = "std::bad_alloc";
}

fn typeNamesEqual(a: *const TypeInfo, b: *const TypeInfo) bool {
    if (a == b) return true;
    return strcmp(a.name, b.name) == 0;
}

pub fn typeInfoCanCatch(catch_type: *const TypeInfo, thrown_type: *const TypeInfo, adjusted_ptr: *?*anyopaque) bool {
    ensureInitialized();
    const ptr_vptr = @intFromPtr(&vtable_pointer_type_info) + 16;

    // Pointer type catch (Itanium C++ ABI: must dereference *(void**)adjustedPtr once!)
    if (catch_type.vtable == ptr_vptr) {
        if (thrown_type.vtable != ptr_vptr) return false;
        const cp: *const PointerTypeInfo = @ptrCast(@alignCast(catch_type));
        const tp: *const PointerTypeInfo = @ptrCast(@alignCast(thrown_type));
        if (typeNamesEqual(catch_type, thrown_type)) {
            if (adjusted_ptr.*) |p| {
                adjusted_ptr.* = @as(*const ?*anyopaque, @ptrCast(@alignCast(p))).*;
            }
            return true;
        }
        if ((tp.flags & ~cp.flags) == 0) {
            var deref_ptr: ?*anyopaque = if (adjusted_ptr.*) |p|
                @as(*const ?*anyopaque, @ptrCast(@alignCast(p))).*
            else
                null;
            if (typeInfoCanCatch(cp.pointee, tp.pointee, &deref_ptr)) {
                adjusted_ptr.* = deref_ptr;
                return true;
            }
        }
        return false;
    }

    if (typeNamesEqual(catch_type, thrown_type)) return true;

    const si_vptr = @intFromPtr(&vtable_si_class_type_info) + 16;
    const vmi_vptr = @intFromPtr(&vtable_vmi_class_type_info) + 16;

    // Single public inheritance chain
    if (thrown_type.vtable == si_vptr) {
        const si: *const SiTypeInfo = @ptrCast(@alignCast(thrown_type));
        return typeInfoCanCatch(catch_type, si.base, adjusted_ptr);
    }

    // Multiple inheritance (VMI) chain
    if (thrown_type.vtable == vmi_vptr) {
        const vmi: *const VmiTypeInfo = @ptrCast(@alignCast(thrown_type));
        const bases: [*]const BaseClassTypeInfo = @ptrFromInt(@intFromPtr(vmi) + @sizeOf(VmiTypeInfo));
        var i: u32 = 0;
        while (i < vmi.base_count) : (i += 1) {
            const bi = bases[i];
            const is_public = (bi.offset_flags & 2) != 0;
            const is_virtual = (bi.offset_flags & 1) != 0;
            if (!is_public or is_virtual) continue;
            const offset: isize = bi.offset_flags >> 8;
            var cand_ptr: ?*anyopaque = if (adjusted_ptr.*) |p|
                @ptrFromInt(@as(usize, @intCast(@as(isize, @intCast(@intFromPtr(p))) + offset)))
            else
                null;
            if (typeInfoCanCatch(catch_type, bi.base_type, &cand_ptr)) {
                adjusted_ptr.* = cand_ptr;
                return true;
            }
        }
    }

    return false;
}

fn rttiCanCatchMethod(self: *const TypeInfo, thrown: *const TypeInfo, adjusted_ptr: *?*anyopaque) callconv(.c) u8 {
    return if (typeInfoCanCatch(self, thrown, adjusted_ptr)) 1 else 0;
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

    const rtti_vtable = [8]usize{
        0, 0,
        @intFromPtr(&rttiNoop), @intFromPtr(&rttiNoop),
        @intFromPtr(&rttiNoop), @intFromPtr(&rttiNoop),
        @intFromPtr(&rttiCanCatchMethod), @intFromPtr(&rttiFalse),
    };
    vtable_class_type_info = rtti_vtable;
    vtable_si_class_type_info = rtti_vtable;
    vtable_vmi_class_type_info = rtti_vtable;
    vtable_fundamental_type_info = rtti_vtable;
    vtable_pointer_type_info = rtti_vtable;

    const class_ti_vptr = @intFromPtr(&vtable_class_type_info) + 16;
    const si_ti_vptr = @intFromPtr(&vtable_si_class_type_info) + 16;
    const fund_ti_vptr = @intFromPtr(&vtable_fundamental_type_info) + 16;
    const ptr_ti_vptr = @intFromPtr(&vtable_pointer_type_info) + 16;

    ti_exception.vtable = class_ti_vptr;
    ti_shared_weak_count.vtable = class_ti_vptr;
    ti_logic_error.vtable = si_ti_vptr;
    ti_runtime_error.vtable = si_ti_vptr;
    ti_out_of_range.vtable = si_ti_vptr;
    ti_out_of_range.base = @ptrCast(&ti_logic_error);
    ti_length_error.vtable = si_ti_vptr;
    ti_length_error.base = @ptrCast(&ti_logic_error);
    ti_invalid_argument.vtable = si_ti_vptr;
    ti_invalid_argument.base = @ptrCast(&ti_logic_error);
    ti_bad_alloc.vtable = si_ti_vptr;
    ti_bad_array_new_length.vtable = si_ti_vptr;
    ti_int.vtable = fund_ti_vptr;
    ti_char.vtable = fund_ti_vptr;
    ti_long.vtable = fund_ti_vptr;
    ti_double.vtable = fund_ti_vptr;
    ti_cstr.vtable = ptr_ti_vptr;

    vtable_runtime_error = .{
        0, @intFromPtr(&ti_runtime_error),
        @intFromPtr(&shim_exception_dtor),
        @intFromPtr(&shim_exception_del_dtor),
        @intFromPtr(&shim_exception_what),
    };
    vtable_logic_error = .{
        0, @intFromPtr(&ti_logic_error),
        @intFromPtr(&shim_exception_dtor),
        @intFromPtr(&shim_exception_del_dtor),
        @intFromPtr(&shim_exception_what),
    };
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
    vtable_invalid_argument = .{
        0, @intFromPtr(&ti_invalid_argument),
        @intFromPtr(&shim_exception_dtor),
        @intFromPtr(&shim_exception_del_dtor),
        @intFromPtr(&shim_exception_what),
    };
    vtable_bad_alloc = .{
        0, @intFromPtr(&ti_bad_alloc),
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

// ============================================================================
// Itanium C++ ABI Exception Runtime (__cxa_* + __gxx_personality_v0)
// ============================================================================

const K_OUR_EXCEPTION_CLASS: u64 = 0x434C4E47432B2B00; // "CLNGC++\0"
const K_VENDOR_LANG_MASK: u64 = 0xFFFFFFFFFFFFFF00;

pub const CxaException = extern struct {
    reserve: ?*anyopaque = null,
    reference_count: usize = 0,
    exception_type: ?*const TypeInfo = null,
    exception_destructor: ?*const fn (?*anyopaque) callconv(.c) void = null,
    unexpected_handler: ?*const anyopaque = null,
    terminate_handler: ?*const anyopaque = null,
    next_exception: ?*CxaException = null,
    handler_count: i32 = 0,
    handler_switch_value: i32 = 0,
    action_record: ?[*]const u8 = null,
    language_specific_data: ?[*]const u8 = null,
    catch_temp: ?*anyopaque = null,
    adjusted_ptr: ?*anyopaque = null,
    unwind_header: unwind.UnwindException = .{
        .exception_class = K_OUR_EXCEPTION_CLASS,
        .exception_cleanup = null,
        .private_1 = 0,
        .private_2 = 0,
    },
};

comptime {
    std.debug.assert(@sizeOf(CxaException) == 128);
    std.debug.assert(@offsetOf(CxaException, "unwind_header") == 96);
}

pub const CxaEhGlobals = extern struct {
    caught_exceptions: ?*CxaException = null,
    uncaught_exceptions: u32 = 0,
};

threadlocal var tls_eh_globals: CxaEhGlobals = .{};

pub fn shim_cxa_get_globals() callconv(.c) *CxaEhGlobals {
    return &tls_eh_globals;
}

pub fn shim_cxa_get_globals_fast() callconv(.c) *CxaEhGlobals {
    return &tls_eh_globals;
}

pub fn shim_uncaught_exception() callconv(.c) u8 {
    return if (tls_eh_globals.uncaught_exceptions != 0) 1 else 0;
}

pub fn shim_uncaught_exceptions() callconv(.c) c_int {
    return @intCast(tls_eh_globals.uncaught_exceptions);
}

fn cxaExceptionFromThrownObj(thrown_obj: *anyopaque) *CxaException {
    return @ptrFromInt(@intFromPtr(thrown_obj) - @sizeOf(CxaException));
}

fn thrownObjFromCxaException(hdr: *CxaException) *anyopaque {
    return @ptrFromInt(@intFromPtr(hdr) + @sizeOf(CxaException));
}

fn cxaExceptionFromUnwind(uexc: *unwind.UnwindException) *CxaException {
    return @ptrFromInt(@intFromPtr(uexc) - @offsetOf(CxaException, "unwind_header"));
}

fn isOurExceptionClass(cls: u64) bool {
    return (cls & K_VENDOR_LANG_MASK) == (K_OUR_EXCEPTION_CLASS & K_VENDOR_LANG_MASK);
}

fn cxaExceptionCleanup(_: c_int, uexc: *unwind.UnwindException) callconv(.c) void {
    const hdr = cxaExceptionFromUnwind(uexc);
    const obj = thrownObjFromCxaException(hdr);
    if (hdr.exception_destructor) |dtor| dtor(obj);
    free(@ptrCast(hdr));
}

pub fn shim_cxa_allocate_exception(thrown_size: usize) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("___cxa_allocate_exception");
    const raw = calloc(1, @sizeOf(CxaException) + thrown_size) orelse abort();
    return @ptrFromInt(@intFromPtr(raw) + @sizeOf(CxaException));
}

pub fn shim_cxa_free_exception(thrown_obj: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("___cxa_free_exception");
    const ptr = thrown_obj orelse return;
    free(@ptrFromInt(@intFromPtr(ptr) - @sizeOf(CxaException)));
}

fn cxaThrowImpl(
    thrown_obj: ?*anyopaque,
    tinfo: ?*const TypeInfo,
    dest: ?*const fn (?*anyopaque) callconv(.c) void,
    regs: *const unwind.UnwindRegs,
) callconv(.c) noreturn {
    if (trace.active_tracer) |t| t.recordExternalCall("___cxa_throw");
    const obj = thrown_obj orelse shim_terminate();
    const hdr = cxaExceptionFromThrownObj(obj);
    hdr.reference_count = 1;
    hdr.exception_type = tinfo;
    hdr.exception_destructor = dest;
    hdr.unwind_header.exception_class = K_OUR_EXCEPTION_CLASS;
    hdr.unwind_header.exception_cleanup = &cxaExceptionCleanup;
    tls_eh_globals.uncaught_exceptions += 1;

    _ = unwind.unwindRaiseFromRegs(&hdr.unwind_header, regs);
    const name = if (tinfo) |ti| std.mem.span(ti.name) else "unknown";
    std.debug.print("WINS-LIBCXX: uncaught C++ exception of type {s}\n", .{name});
    shim_terminate();
}

pub fn shim_cxa_throw() callconv(.naked) void {
    // Entry: rdi=thrown_obj, rsi=tinfo, rdx=dest
    asm volatile (
        \\subq $152, %%rsp
        \\movq %%rax, 0(%%rsp)
        \\movq %%rdx, 8(%%rsp)
        \\movq %%rcx, 16(%%rsp)
        \\movq %%rbx, 24(%%rsp)
        \\movq %%rsi, 32(%%rsp)
        \\movq %%rdi, 40(%%rsp)
        \\movq %%rbp, 48(%%rsp)
        \\leaq 160(%%rsp), %%r11
        \\movq %%r11, 56(%%rsp)
        \\movq %%r8, 64(%%rsp)
        \\movq %%r9, 72(%%rsp)
        \\movq %%r10, 80(%%rsp)
        \\movq %%r11, 88(%%rsp)
        \\movq %%r12, 96(%%rsp)
        \\movq %%r13, 104(%%rsp)
        \\movq %%r14, 112(%%rsp)
        \\movq %%r15, 120(%%rsp)
        \\movq 152(%%rsp), %%r11
        \\movq %%r11, 128(%%rsp)
        \\movq %%rsp, %%rcx
        \\call %[impl:P]
        \\ud2
        :
        : [impl] "X" (&cxaThrowImpl),
    );
}

fn cxaRethrowImpl(regs: *const unwind.UnwindRegs) callconv(.c) noreturn {
    if (trace.active_tracer) |t| t.recordExternalCall("___cxa_rethrow");
    const hdr = tls_eh_globals.caught_exceptions orelse shim_terminate();
    if (isOurExceptionClass(hdr.unwind_header.exception_class)) {
        hdr.handler_count = -hdr.handler_count;
        tls_eh_globals.uncaught_exceptions += 1;
    } else {
        tls_eh_globals.caught_exceptions = null;
    }
    _ = unwind.unwindRaiseFromRegs(&hdr.unwind_header, regs);
    shim_terminate();
}

pub fn shim_cxa_rethrow() callconv(.naked) void {
    asm volatile (
        \\subq $152, %%rsp
        \\movq %%rax, 0(%%rsp)
        \\movq %%rdx, 8(%%rsp)
        \\movq %%rcx, 16(%%rsp)
        \\movq %%rbx, 24(%%rsp)
        \\movq %%rsi, 32(%%rsp)
        \\movq %%rdi, 40(%%rsp)
        \\movq %%rbp, 48(%%rsp)
        \\leaq 160(%%rsp), %%r11
        \\movq %%r11, 56(%%rsp)
        \\movq %%r8, 64(%%rsp)
        \\movq %%r9, 72(%%rsp)
        \\movq %%r10, 80(%%rsp)
        \\movq %%r11, 88(%%rsp)
        \\movq %%r12, 96(%%rsp)
        \\movq %%r13, 104(%%rsp)
        \\movq %%r14, 112(%%rsp)
        \\movq %%r15, 120(%%rsp)
        \\movq 152(%%rsp), %%r11
        \\movq %%r11, 128(%%rsp)
        \\movq %%rsp, %%rdi
        \\call %[impl:P]
        \\ud2
        :
        : [impl] "X" (&cxaRethrowImpl),
    );
}

pub fn shim_cxa_begin_catch(unwind_arg: ?*anyopaque) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("___cxa_begin_catch");
    const raw = unwind_arg orelse return null;
    const uexc: *unwind.UnwindException = @ptrCast(@alignCast(raw));
    const hdr = cxaExceptionFromUnwind(uexc);
    const globals = &tls_eh_globals;

    if (isOurExceptionClass(uexc.exception_class)) {
        const count = hdr.handler_count;
        hdr.handler_count = if (count < 0) -count + 1 else count + 1;
        if (hdr != globals.caught_exceptions) {
            hdr.next_exception = globals.caught_exceptions;
            globals.caught_exceptions = hdr;
        }
        if (globals.uncaught_exceptions > 0) globals.uncaught_exceptions -= 1;
        return hdr.adjusted_ptr orelse thrownObjFromCxaException(hdr);
    }

    if (globals.caught_exceptions != null) shim_terminate();
    globals.caught_exceptions = hdr;
    return null;
}

pub fn shim_cxa_end_catch() callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("___cxa_end_catch");
    const globals = &tls_eh_globals;
    const hdr = globals.caught_exceptions orelse return;

    if (isOurExceptionClass(hdr.unwind_header.exception_class)) {
        if (hdr.handler_count < 0) {
            hdr.handler_count += 1;
            if (hdr.handler_count == 0) {
                globals.caught_exceptions = hdr.next_exception;
                hdr.next_exception = null;
            }
        } else {
            hdr.handler_count -= 1;
            if (hdr.handler_count == 0) {
                globals.caught_exceptions = hdr.next_exception;
                hdr.next_exception = null;
                if (hdr.reference_count > 0) {
                    const prev = @atomicRmw(usize, &hdr.reference_count, .Sub, 1, .acq_rel);
                    if (prev == 1) {
                        const obj = thrownObjFromCxaException(hdr);
                        if (hdr.exception_destructor) |dtor| dtor(obj);
                        free(@ptrCast(hdr));
                    }
                }
            }
        }
    } else {
        unwind.shim_unwind_delete_exception(&hdr.unwind_header);
        globals.caught_exceptions = null;
    }
}

pub fn shim_cxa_current_exception_type() callconv(.c) ?*const TypeInfo {
    const hdr = tls_eh_globals.caught_exceptions orelse return null;
    if (!isOurExceptionClass(hdr.unwind_header.exception_class)) return null;
    return hdr.exception_type;
}

pub fn shim_cxa_call_terminate(unwind_arg: ?*anyopaque) callconv(.c) noreturn {
    _ = shim_cxa_begin_catch(unwind_arg);
    shim_terminate();
}

// ============================================================================
// DWARF LSDA Parser & __gxx_personality_v0 (Itanium C++ ABI)
// ============================================================================

const DW_EH_PE_absptr: u8 = 0x00;
const DW_EH_PE_uleb128: u8 = 0x01;
const DW_EH_PE_udata2: u8 = 0x02;
const DW_EH_PE_udata4: u8 = 0x03;
const DW_EH_PE_udata8: u8 = 0x04;
const DW_EH_PE_sleb128: u8 = 0x09;
const DW_EH_PE_sdata2: u8 = 0x0A;
const DW_EH_PE_sdata4: u8 = 0x0B;
const DW_EH_PE_sdata8: u8 = 0x0C;
const DW_EH_PE_pcrel: u8 = 0x10;
const DW_EH_PE_datarel: u8 = 0x30;
const DW_EH_PE_indirect: u8 = 0x80;
const DW_EH_PE_omit: u8 = 0xFF;

fn readULEB128(p: *[*]const u8) usize {
    var result: usize = 0;
    var shift: u6 = 0;
    var ptr = p.*;
    while (true) {
        const b = ptr[0];
        ptr += 1;
        result |= @as(usize, b & 0x7F) << shift;
        if ((b & 0x80) == 0) break;
        shift +|= 7;
    }
    p.* = ptr;
    return result;
}

fn readSLEB128(p: *[*]const u8) isize {
    var result: usize = 0;
    var shift: u6 = 0;
    var ptr = p.*;
    var b: u8 = 0;
    while (true) {
        b = ptr[0];
        ptr += 1;
        result |= @as(usize, b & 0x7F) << shift;
        shift +|= 7;
        if ((b & 0x80) == 0) break;
    }
    p.* = ptr;
    if ((b & 0x40) != 0 and shift < 64) {
        result |= (~@as(usize, 0)) << shift;
    }
    return @bitCast(result);
}

fn readUnaligned(comptime T: type, ptr: [*]const u8) T {
    const p: *align(1) const T = @ptrCast(ptr);
    return p.*;
}

fn readEncodedPointer(p: *[*]const u8, encoding: u8, data_base: usize) usize {
    if (encoding == DW_EH_PE_omit) return 0;
    const start_addr = @intFromPtr(p.*);
    var ptr = p.*;
    var result: usize = switch (encoding & 0x0F) {
        DW_EH_PE_absptr => blk: {
            const v = readUnaligned(usize, ptr);
            ptr += @sizeOf(usize);
            break :blk v;
        },
        DW_EH_PE_uleb128 => readULEB128(&ptr),
        DW_EH_PE_sleb128 => @bitCast(readSLEB128(&ptr)),
        DW_EH_PE_udata2 => blk: {
            const v = readUnaligned(u16, ptr);
            ptr += 2;
            break :blk v;
        },
        DW_EH_PE_udata4 => blk: {
            const v = readUnaligned(u32, ptr);
            ptr += 4;
            break :blk v;
        },
        DW_EH_PE_udata8 => blk: {
            const v = readUnaligned(u64, ptr);
            ptr += 8;
            break :blk @intCast(v);
        },
        DW_EH_PE_sdata2 => blk: {
            const v: isize = readUnaligned(i16, ptr);
            ptr += 2;
            break :blk @bitCast(v);
        },
        DW_EH_PE_sdata4 => blk: {
            const v: isize = readUnaligned(i32, ptr);
            ptr += 4;
            break :blk @bitCast(v);
        },
        DW_EH_PE_sdata8 => blk: {
            const v: isize = @intCast(readUnaligned(i64, ptr));
            ptr += 8;
            break :blk @bitCast(v);
        },
        else => return 0,
    };

    switch (encoding & 0x70) {
        DW_EH_PE_absptr => {},
        DW_EH_PE_pcrel => {
            if (result != 0) result = start_addr +% result;
        },
        DW_EH_PE_datarel => {
            if (result != 0) result = data_base +% result;
        },
        else => {},
    }

    if (result != 0 and (encoding & DW_EH_PE_indirect) != 0) {
        const ind: *const usize = @ptrFromInt(result);
        result = ind.*;
    }

    p.* = ptr;
    return result;
}

fn getTTypeInfo(ttype_index: usize, class_info: [*]const u8, ttype_encoding: u8, data_base: usize) ?*const TypeInfo {
    const elem_size: usize = switch (ttype_encoding & 0x0F) {
        DW_EH_PE_absptr => @sizeOf(usize),
        DW_EH_PE_udata2, DW_EH_PE_sdata2 => 2,
        DW_EH_PE_udata4, DW_EH_PE_sdata4 => 4,
        DW_EH_PE_udata8, DW_EH_PE_sdata8 => 8,
        else => return null,
    };
    var ptr: [*]const u8 = @ptrFromInt(@intFromPtr(class_info) - ttype_index * elem_size);
    const addr = readEncodedPointer(&ptr, ttype_encoding, data_base);
    if (addr == 0) return null;
    return @ptrFromInt(addr);
}

const ScanResults = struct {
    ttype_index: isize = 0,
    action_record: ?[*]const u8 = null,
    lsda: ?[*]const u8 = null,
    landing_pad: usize = 0,
    adjusted_ptr: ?*anyopaque = null,
    reason: c_int = unwind.URC_FATAL_PHASE1_ERROR,
};

fn scanEhTab(
    results: *ScanResults,
    actions: c_int,
    native_exception: bool,
    uexc: *unwind.UnwindException,
    ctx: *unwind.UnwindCursor,
) void {
    results.* = .{};
    const lsda_raw = unwind.shim_unwind_get_lsda(ctx) orelse {
        results.reason = unwind.URC_CONTINUE_UNWIND;
        return;
    };
    var lsda: [*]const u8 = @ptrCast(lsda_raw);
    results.lsda = lsda;

    const ip = unwind.shim_unwind_get_ip(ctx) - 1;
    const func_start = unwind.shim_unwind_get_region_start(ctx);
    const ip_offset = ip -% func_start;
    const data_base = unwind.shim_unwind_get_data_rel_base(ctx);

    const lp_start_enc = lsda[0];
    lsda += 1;
    const lp_start: usize = if (lp_start_enc == DW_EH_PE_omit)
        func_start
    else
        readEncodedPointer(&lsda, lp_start_enc, data_base);

    const ttype_enc = lsda[0];
    lsda += 1;
    var class_info: ?[*]const u8 = null;
    if (ttype_enc != DW_EH_PE_omit) {
        const class_info_off = readULEB128(&lsda);
        class_info = lsda + class_info_off;
    }

    const call_site_enc = lsda[0];
    lsda += 1;
    const call_site_len = readULEB128(&lsda);
    var cs_ptr = lsda;
    const cs_end = lsda + call_site_len;
    const action_table_start = cs_end;

    while (@intFromPtr(cs_ptr) < @intFromPtr(cs_end)) {
        const start = readEncodedPointer(&cs_ptr, call_site_enc, data_base);
        const length = readEncodedPointer(&cs_ptr, call_site_enc, data_base);
        const lp_off = readEncodedPointer(&cs_ptr, call_site_enc, data_base);
        const action_entry = readULEB128(&cs_ptr);

        if (start <= ip_offset and ip_offset < start + length) {
            if (lp_off == 0) {
                results.reason = unwind.URC_CONTINUE_UNWIND;
                return;
            }
            results.landing_pad = lp_start + lp_off;
            if (action_entry == 0) {
                results.reason = if ((actions & unwind.UA_SEARCH_PHASE) != 0)
                    unwind.URC_CONTINUE_UNWIND
                else
                    unwind.URC_HANDLER_FOUND;
                return;
            }

            var action = action_table_start + (action_entry - 1);
            var has_cleanup = false;
            while (true) {
                const action_rec = action;
                const ttype_index = readSLEB128(&action);
                if (ttype_index > 0) {
                    const ci = class_info orelse {
                        shim_cxa_call_terminate(uexc);
                    };
                    const catch_type = getTTypeInfo(@intCast(ttype_index), ci, ttype_enc, data_base);
                    if (catch_type == null) {
                        // catch (...)
                        results.ttype_index = ttype_index;
                        results.action_record = action_rec;
                        results.adjusted_ptr = if (native_exception)
                            thrownObjFromCxaException(cxaExceptionFromUnwind(uexc))
                        else
                            null;
                        results.reason = unwind.URC_HANDLER_FOUND;
                        return;
                    } else if (native_exception) {
                        const hdr = cxaExceptionFromUnwind(uexc);
                        var adj_ptr: ?*anyopaque = thrownObjFromCxaException(hdr);
                        if (hdr.exception_type) |excp_ti| {
                            if (typeInfoCanCatch(catch_type.?, excp_ti, &adj_ptr)) {
                                results.ttype_index = ttype_index;
                                results.action_record = action_rec;
                                results.adjusted_ptr = adj_ptr;
                                results.reason = unwind.URC_HANDLER_FOUND;
                                return;
                            }
                        }
                    }
                } else if (ttype_index == 0) {
                    has_cleanup = true;
                }
                var tmp_action = action;
                const next_off = readSLEB128(&tmp_action);
                if (next_off == 0) {
                    results.reason = if (has_cleanup and (actions & unwind.UA_CLEANUP_PHASE) != 0)
                        unwind.URC_HANDLER_FOUND
                    else
                        unwind.URC_CONTINUE_UNWIND;
                    return;
                }
                action = @ptrFromInt(@as(usize, @intCast(@as(isize, @intCast(@intFromPtr(action))) + next_off)));
            }
        } else if (ip_offset < start) {
            shim_cxa_call_terminate(uexc);
        }
    }
    shim_cxa_call_terminate(uexc);
}

fn installLandingPad(uexc: *unwind.UnwindException, ctx: *unwind.UnwindCursor, results: *const ScanResults) void {
    unwind.shim_unwind_set_gr(ctx, 0, @intFromPtr(uexc)); // RAX = unwind_exception
    unwind.shim_unwind_set_gr(ctx, 1, @bitCast(results.ttype_index)); // RDX = switch selector
    unwind.shim_unwind_set_ip(ctx, results.landing_pad);
}

pub fn shim_gxx_personality_v0(
    version: c_int,
    actions: c_int,
    exception_class: u64,
    uexc: ?*unwind.UnwindException,
    ctx: ?*unwind.UnwindCursor,
) callconv(.c) c_int {
    if (version != 1 or uexc == null or ctx == null) return unwind.URC_FATAL_PHASE1_ERROR;
    const exc = uexc.?;
    const cursor = ctx.?;
    const native_exception = isOurExceptionClass(exception_class);

    // Phase 2 at the handler frame: restore cached Phase 1 scan results
    if (actions == (unwind.UA_CLEANUP_PHASE | unwind.UA_HANDLER_FRAME) and native_exception) {
        const hdr = cxaExceptionFromUnwind(exc);
        const cached = ScanResults{
            .ttype_index = hdr.handler_switch_value,
            .action_record = hdr.action_record,
            .lsda = hdr.language_specific_data,
            .landing_pad = @intFromPtr(hdr.catch_temp),
            .adjusted_ptr = hdr.adjusted_ptr,
            .reason = unwind.URC_HANDLER_FOUND,
        };
        installLandingPad(exc, cursor, &cached);
        return unwind.URC_INSTALL_CONTEXT;
    }

    var results = ScanResults{};
    scanEhTab(&results, actions, native_exception, exc, cursor);
    if (results.reason == unwind.URC_CONTINUE_UNWIND or
        results.reason == unwind.URC_FATAL_PHASE1_ERROR or
        results.reason == unwind.URC_FATAL_PHASE2_ERROR)
    {
        return results.reason;
    }

    if ((actions & unwind.UA_SEARCH_PHASE) != 0) {
        if (native_exception) {
            const hdr = cxaExceptionFromUnwind(exc);
            hdr.handler_switch_value = @intCast(results.ttype_index);
            hdr.action_record = results.action_record;
            hdr.language_specific_data = results.lsda;
            hdr.catch_temp = @ptrFromInt(results.landing_pad);
            hdr.adjusted_ptr = results.adjusted_ptr;
        }
        return unwind.URC_HANDLER_FOUND;
    }

    // Phase 2 cleanup (or foreign handler)
    installLandingPad(exc, cursor, &results);
    return unwind.URC_INSTALL_CONTEXT;
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
