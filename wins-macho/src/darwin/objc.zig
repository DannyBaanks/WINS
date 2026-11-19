const std = @import("std");
const trace = @import("../runtime/trace.zig");

pub const ObjcClass = extern struct {
    isa: usize,
    superclass: usize,
    cache_buckets: usize,
    cache_mask_vtable: usize,
    bits: usize,
};

pub const ClassRoT = extern struct {
    flags: u32,
    instanceStart: u32,
    instanceSize: u32,
    reserved: u32,
    ivarLayout: usize,
    name: ?[*:0]const u8,
    baseMethodList: ?*const MethodListT,
    baseProtocols: usize,
    ivars: usize,
    weakIvarLayout: usize,
    baseProperties: usize,
};

pub const MethodListT = extern struct {
    entsizeAndFlags: u32,
    count: u32,
};

pub const MethodLargeT = extern struct {
    name: [*:0]const u8,
    types: [*:0]const u8,
    imp: usize,
};

pub const MethodSmallT = extern struct {
    name_rel: i32,
    types_rel: i32,
    imp_rel: i32,
};

pub var objc_empty_cache: [2]usize = .{ 0, 0 };

extern "c" fn calloc(nmemb: usize, size: usize) ?*anyopaque;
extern "c" fn abort() noreturn;

fn getRo(cls: *const ObjcClass) ?*const ClassRoT {
    const ptr = cls.bits & ~@as(usize, 7);
    if (ptr == 0) return null;
    return @ptrFromInt(ptr);
}

fn lookupMethodInList(ml: *const MethodListT, sel_name: []const u8) ?usize {
    const entsize: usize = ml.entsizeAndFlags & 0xFFFF;
    const is_small: bool = (ml.entsizeAndFlags & 0x80000000) != 0;
    const base_addr: usize = @intFromPtr(ml) + @sizeOf(MethodListT);

    var i: usize = 0;
    while (i < ml.count) : (i += 1) {
        const entry_addr = base_addr + i * entsize;
        if (!is_small and entsize >= @sizeOf(MethodLargeT)) {
            const m: *const MethodLargeT = @ptrFromInt(entry_addr);
            const m_name = std.mem.span(m.name);
            if (std.mem.eql(u8, m_name, sel_name)) {
                return m.imp;
            }
        } else if (is_small and entsize >= @sizeOf(MethodSmallT)) {
            const m: *const MethodSmallT = @ptrFromInt(entry_addr);
            const name_ptr_addr: usize = @intCast(@as(isize, @intCast(entry_addr)) + m.name_rel);
            const name_ptr: [*:0]const u8 = @as(*const [*:0]const u8, @ptrFromInt(name_ptr_addr)).*;
            const m_name = std.mem.span(name_ptr);
            if (std.mem.eql(u8, m_name, sel_name)) {
                const imp_field_addr = entry_addr + 8;
                return @intCast(@as(isize, @intCast(imp_field_addr)) + m.imp_rel);
            }
        }
    }
    return null;
}

pub export fn wins_objc_lookup_imp(self_ptr: ?*anyopaque, op: ?[*:0]const u8) callconv(.c) usize {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_msgSend");
    const self = self_ptr orelse return 0;
    const sel = op orelse return 0;
    const sel_name = std.mem.span(sel);

    // For both instances and Class objects, the first word is `isa`!
    const isa_addr = @as(*const usize, @ptrCast(@alignCast(self))).*;
    var cls_addr: usize = isa_addr;
    var depth: usize = 0;
    while (cls_addr != 0 and depth < 64) : (depth += 1) {
        if ((cls_addr & 0x7) != 0) {
            std.debug.print("WINS-OBJC: unaligned cls_addr=0x{x} self=0x{x} sel={s}\n", .{ cls_addr, @intFromPtr(self), sel_name });
            abort();
        }
        const cls: *const ObjcClass = @ptrFromInt(cls_addr);
        if (getRo(cls)) |ro| {
            if (ro.baseMethodList) |ml| {
                if (lookupMethodInList(ml, sel_name)) |imp| {
                    return imp;
                }
            }
        }
        cls_addr = cls.superclass;
    }

    if (std.mem.eql(u8, sel_name, "alloc")) {
        return @intFromPtr(&shim_objc_alloc);
    }

    if (trace.active_tracer) |t| t.recordUnsupportedCall(sel_name);
    const cls: *const ObjcClass = @ptrFromInt(isa_addr);
    const cls_name = if (getRo(cls)) |ro| (if (ro.name) |n| std.mem.span(n) else "?") else "?";
    std.debug.print("WINS-OBJC: unrecognized selector '[{s} {s}]'\n", .{ cls_name, sel_name });
    abort();
}

// Naked x86_64 dispatcher: preserves all System V AMD64 arg registers (rdi..r9, xmm0..xmm7)
// and tail-jumps to the resolved IMP!
pub fn shim_objc_msgSend() callconv(.naked) void {
    asm volatile (
        \\testq %%rdi, %%rdi
        \\jz 1f
        \\pushq %%rdi
        \\pushq %%rsi
        \\pushq %%rdx
        \\pushq %%rcx
        \\pushq %%r8
        \\pushq %%r9
        \\subq $8, %%rsp
        \\call %[lookup:P]
        \\addq $8, %%rsp
        \\popq %%r9
        \\popq %%r8
        \\popq %%rcx
        \\popq %%rdx
        \\popq %%rsi
        \\popq %%rdi
        \\jmpq *%%rax
        \\1:
        \\xorl %%eax, %%eax
        \\retq
        :
        : [lookup] "X" (&wins_objc_lookup_imp),
    );
}

pub fn shim_objc_alloc(cls_ptr: ?*ObjcClass) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_alloc");
    const cls = cls_ptr orelse return null;
    const ro = getRo(cls) orelse return null;
    const sz: usize = @max(@as(usize, ro.instanceSize), @sizeOf(usize));
    const obj = calloc(1, sz) orelse return null;
    @as(*usize, @ptrCast(@alignCast(obj))).* = @intFromPtr(cls);
    return obj;
}

pub fn shim_objc_alloc_init(cls_ptr: ?*ObjcClass) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_alloc_init");
    const obj = shim_objc_alloc(cls_ptr) orelse return null;
    // Check if class implements -init
    const cls = cls_ptr.?;
    if (getRo(cls)) |ro| {
        if (ro.baseMethodList) |ml| {
            if (lookupMethodInList(ml, "init")) |imp| {
                const init_fn: *const fn (*anyopaque, [*:0]const u8) callconv(.c) ?*anyopaque = @ptrFromInt(imp);
                return init_fn(obj, "init");
            }
        }
    }
    return obj;
}

pub fn shim_objc_retain(obj: ?*anyopaque) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_retain");
    return obj;
}

pub fn shim_objc_release(obj: ?*anyopaque) callconv(.c) void {
    _ = obj;
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_release");
}

pub fn shim_objc_autorelease(obj: ?*anyopaque) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_autorelease");
    return obj;
}

pub fn shim_objc_autoreleasePoolPush() callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_autoreleasePoolPush");
    return null;
}

pub fn shim_objc_autoreleasePoolPop(pool: ?*anyopaque) callconv(.c) void {
    _ = pool;
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_autoreleasePoolPop");
}

pub fn shim_objc_opt_class(obj: ?*anyopaque) callconv(.c) usize {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_opt_class");
    const ptr = obj orelse return 0;
    return @as(*const usize, @ptrCast(@alignCast(ptr))).*;
}

pub fn shim_objc_storeStrong(location: *?*anyopaque, obj: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_storeStrong");
    location.* = obj;
}
