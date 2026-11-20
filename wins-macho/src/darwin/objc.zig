const std = @import("std");
const trace = @import("../runtime/trace.zig");

pub const ObjcClass = extern struct {
    isa: usize,
    superclass: usize,
    cache_buckets: usize,
    cache_mask_vtable: usize,
    bits: usize,
};

pub const ObjcSuper = extern struct {
    receiver: ?*anyopaque,
    super_class: usize,
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
extern "c" fn free(ptr: ?*anyopaque) void;
extern "c" fn abort() noreturn;

var retain_counts: std.AutoHashMapUnmanaged(usize, u32) = .{};
var pool_objects: std.ArrayListUnmanaged(usize) = .empty;
var pool_frames: std.ArrayListUnmanaged(usize) = .empty;
var registered_classes: std.ArrayListUnmanaged(*ObjcClass) = .empty;

pub fn registerClass(cls: *ObjcClass) void {
    const alloc = std.heap.c_allocator;
    for (registered_classes.items) |existing| {
        if (existing == cls) return;
    }
    registered_classes.append(alloc, cls) catch {};
}

pub fn getRo(cls: *const ObjcClass) ?*const ClassRoT {
    const ptr = cls.bits & ~@as(usize, 7);
    if (ptr == 0) return null;
    return @ptrFromInt(ptr);
}

pub fn getClassName(cls: *const ObjcClass) []const u8 {
    if (getRo(cls)) |ro| {
        if (ro.name) |n| return std.mem.span(n);
    }
    return "?";
}

pub fn isSubclassOf(cls_addr: usize, target_cls_addr: usize) bool {
    var cur = cls_addr;
    var depth: usize = 0;
    while (cur != 0 and depth < 64) : (depth += 1) {
        if (cur == target_cls_addr) return true;
        if ((cur & 0x7) != 0) break;
        const cls: *const ObjcClass = @ptrFromInt(cur);
        cur = cls.superclass;
    }
    return false;
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

pub fn lookupMethodInHierarchy(start_cls_addr: usize, sel_name: []const u8) ?usize {
    var cls_addr: usize = start_cls_addr;
    var depth: usize = 0;
    while (cls_addr != 0 and depth < 64) : (depth += 1) {
        if ((cls_addr & 0x7) != 0) return null;
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
    return null;
}

pub export fn wins_objc_lookup_imp(self_ptr: ?*anyopaque, op: ?[*:0]const u8) callconv(.c) usize {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_msgSend");
    const self = self_ptr orelse return 0;
    const sel = op orelse return 0;
    const sel_name = std.mem.span(sel);

    const isa_addr = @as(*const usize, @ptrCast(@alignCast(self))).*;
    if ((isa_addr & 0x7) != 0 or isa_addr == 0) {
        std.debug.print("WINS-OBJC: invalid isa=0x{x} self=0x{x} sel={s}\n", .{ isa_addr, @intFromPtr(self), sel_name });
        abort();
    }

    if (lookupMethodInHierarchy(isa_addr, sel_name)) |imp| {
        return imp;
    }

    if (std.mem.eql(u8, sel_name, "alloc")) {
        return @intFromPtr(&shim_objc_alloc);
    }

    if (trace.active_tracer) |t| t.recordUnsupportedCall(sel_name);
    const cls: *const ObjcClass = @ptrFromInt(isa_addr);
    const cls_name = getClassName(cls);
    std.debug.print("WINS-OBJC: unrecognized selector '[{s} {s}]'\n", .{ cls_name, sel_name });
    abort();
}

pub export fn wins_objc_lookup_super_imp(super_ptr: ?*const ObjcSuper, op: ?[*:0]const u8, is_super2: c_int) callconv(.c) usize {
    if (trace.active_tracer) |t| t.recordExternalCall(if (is_super2 != 0) "_objc_msgSendSuper2" else "_objc_msgSendSuper");
    const sup = super_ptr orelse return 0;
    if (sup.receiver == null) return 0;
    const sel = op orelse return 0;
    const sel_name = std.mem.span(sel);

    var start_cls = sup.super_class;
    if (is_super2 != 0 and start_cls != 0 and (start_cls & 0x7) == 0) {
        const cur_cls: *const ObjcClass = @ptrFromInt(start_cls);
        start_cls = cur_cls.superclass;
    }

    if (lookupMethodInHierarchy(start_cls, sel_name)) |imp| {
        return imp;
    }

    if (trace.active_tracer) |t| t.recordUnsupportedCall(sel_name);
    const cls_name = if (start_cls != 0 and (start_cls & 0x7) == 0)
        getClassName(@ptrFromInt(start_cls))
    else
        "?";
    std.debug.print("WINS-OBJC: unrecognized super selector '[{s} {s}]'\n", .{ cls_name, sel_name });
    abort();
}

pub export fn wins_objc_lookup_super1_imp(super_ptr: ?*const ObjcSuper, op: ?[*:0]const u8) callconv(.c) usize {
    return wins_objc_lookup_super_imp(super_ptr, op, 0);
}

pub export fn wins_objc_lookup_super2_imp(super_ptr: ?*const ObjcSuper, op: ?[*:0]const u8) callconv(.c) usize {
    return wins_objc_lookup_super_imp(super_ptr, op, 1);
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

pub fn shim_objc_msgSendSuper() callconv(.naked) void {
    asm volatile (
        \\testq %%rdi, %%rdi
        \\jz 1f
        \\movq (%%rdi), %%rax
        \\testq %%rax, %%rax
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
        \\movq (%%rdi), %%rdi
        \\jmpq *%%rax
        \\1:
        \\xorl %%eax, %%eax
        \\retq
        :
        : [lookup] "X" (&wins_objc_lookup_super1_imp),
    );
}

pub fn shim_objc_msgSendSuper2() callconv(.naked) void {
    asm volatile (
        \\testq %%rdi, %%rdi
        \\jz 1f
        \\movq (%%rdi), %%rax
        \\testq %%rax, %%rax
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
        \\movq (%%rdi), %%rdi
        \\jmpq *%%rax
        \\1:
        \\xorl %%eax, %%eax
        \\retq
        :
        : [lookup] "X" (&wins_objc_lookup_super2_imp),
    );
}

pub fn shim_objc_alloc(cls_ptr: ?*ObjcClass) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_alloc");
    return allocWithExtraBytes(cls_ptr, 0);
}

pub fn shim_class_createInstance(cls_ptr: ?*ObjcClass, extra_bytes: usize) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_class_createInstance");
    return allocWithExtraBytes(cls_ptr, extra_bytes);
}

fn allocWithExtraBytes(cls_ptr: ?*ObjcClass, extra_bytes: usize) ?*anyopaque {
    const cls = cls_ptr orelse return null;
    const ro = getRo(cls) orelse return null;
    const sz: usize = @max(@as(usize, ro.instanceSize) + extra_bytes, @sizeOf(usize));
    const obj = calloc(1, sz) orelse return null;
    @as(*usize, @ptrCast(@alignCast(obj))).* = @intFromPtr(cls);
    retain_counts.put(std.heap.c_allocator, @intFromPtr(obj), 1) catch {};
    return obj;
}

pub fn shim_objc_alloc_init(cls_ptr: ?*ObjcClass) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_alloc_init");
    const obj = shim_objc_alloc(cls_ptr) orelse return null;
    const cls = cls_ptr.?;
    if (lookupMethodInHierarchy(@intFromPtr(cls), "init")) |imp| {
        const init_fn: *const fn (*anyopaque, [*:0]const u8) callconv(.c) ?*anyopaque = @ptrFromInt(imp);
        return init_fn(obj, "init");
    }
    return obj;
}

pub fn getRetainCount(obj: ?*anyopaque) usize {
    const ptr = obj orelse return 0;
    if (retain_counts.get(@intFromPtr(ptr))) |cnt| {
        return cnt;
    }
    return 0x7fffffff; // static/constant object (immortal)
}

pub fn shim_objc_retain(obj: ?*anyopaque) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_retain");
    const ptr = obj orelse return null;
    if (retain_counts.getPtr(@intFromPtr(ptr))) |cnt_ptr| {
        cnt_ptr.* +|= 1;
    }
    return ptr;
}

pub fn shim_objc_release(obj: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_release");
    const ptr = obj orelse return;
    const addr = @intFromPtr(ptr);
    if (retain_counts.getPtr(addr)) |cnt_ptr| {
        if (cnt_ptr.* > 1) {
            cnt_ptr.* -= 1;
            return;
        }
        _ = retain_counts.remove(addr);
        const isa_addr = @as(*const usize, @ptrCast(@alignCast(ptr))).*;
        if (isa_addr != 0 and (isa_addr & 0x7) == 0) {
            if (lookupMethodInHierarchy(isa_addr, "dealloc")) |imp| {
                const dealloc_fn: *const fn (*anyopaque, [*:0]const u8) callconv(.c) void = @ptrFromInt(imp);
                dealloc_fn(ptr, "dealloc");
                return;
            }
        }
        free(ptr);
    }
}

pub fn shim_objc_autorelease(obj: ?*anyopaque) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_autorelease");
    const ptr = obj orelse return null;
    if (pool_frames.items.len > 0) {
        pool_objects.append(std.heap.c_allocator, @intFromPtr(ptr)) catch {};
    }
    return ptr;
}

pub fn shim_objc_retainAutorelease(obj: ?*anyopaque) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_retainAutorelease");
    return shim_objc_autorelease(shim_objc_retain(obj));
}

pub fn shim_objc_retainAutoreleasedReturnValue(obj: ?*anyopaque) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_retainAutoreleasedReturnValue");
    return shim_objc_retain(obj);
}

pub fn shim_objc_autoreleaseReturnValue(obj: ?*anyopaque) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_autoreleaseReturnValue");
    return shim_objc_autorelease(obj);
}

pub fn shim_objc_autoreleasePoolPush() callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_autoreleasePoolPush");
    const frame_idx = pool_frames.items.len;
    pool_frames.append(std.heap.c_allocator, pool_objects.items.len) catch return null;
    return @ptrFromInt(frame_idx + 1);
}

pub fn shim_objc_autoreleasePoolPop(pool: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_autoreleasePoolPop");
    const token = @intFromPtr(pool orelse return);
    if (token == 0) return;
    const target_frame = token - 1;
    if (target_frame >= pool_frames.items.len) return;

    const start_obj_idx = pool_frames.items[target_frame];
    pool_frames.items.len = target_frame;

    while (pool_objects.items.len > start_obj_idx) {
        const obj_addr = pool_objects.pop().?;
        shim_objc_release(@ptrFromInt(obj_addr));
    }
}

pub fn shim_objc_opt_class(obj: ?*anyopaque) callconv(.c) usize {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_opt_class");
    const ptr = obj orelse return 0;
    return @as(*const usize, @ptrCast(@alignCast(ptr))).*;
}

pub fn shim_objc_opt_isKindOfClass(obj: ?*anyopaque, cls_addr: usize) callconv(.c) u8 {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_opt_isKindOfClass");
    const ptr = obj orelse return 0;
    const isa_addr = @as(*const usize, @ptrCast(@alignCast(ptr))).*;
    return if (isSubclassOf(isa_addr, cls_addr)) 1 else 0;
}

pub fn shim_objc_opt_respondsToSelector(obj: ?*anyopaque, sel: ?[*:0]const u8) callconv(.c) u8 {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_opt_respondsToSelector");
    const ptr = obj orelse return 0;
    const op = sel orelse return 0;
    const isa_addr = @as(*const usize, @ptrCast(@alignCast(ptr))).*;
    return if (lookupMethodInHierarchy(isa_addr, std.mem.span(op)) != null) 1 else 0;
}

pub fn shim_objc_storeStrong(location: *?*anyopaque, obj: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_storeStrong");
    const prev = location.*;
    if (prev == obj) return;
    location.* = shim_objc_retain(obj);
    shim_objc_release(prev);
}

pub fn shim_objc_getClass(name: ?[*:0]const u8) callconv(.c) ?*ObjcClass {
    if (trace.active_tracer) |t| t.recordExternalCall("_objc_getClass");
    const n = name orelse return null;
    const span = std.mem.span(n);
    for (registered_classes.items) |cls| {
        if (std.mem.eql(u8, getClassName(cls), span)) return cls;
    }
    return null;
}

pub fn shim_sel_registerName(name: ?[*:0]const u8) callconv(.c) ?[*:0]const u8 {
    if (trace.active_tracer) |t| t.recordExternalCall("_sel_registerName");
    return name;
}

pub fn shim_object_getClass(obj: ?*anyopaque) callconv(.c) ?*ObjcClass {
    if (trace.active_tracer) |t| t.recordExternalCall("_object_getClass");
    const ptr = obj orelse return null;
    const isa_addr = @as(*const usize, @ptrCast(@alignCast(ptr))).*;
    if (isa_addr == 0) return null;
    return @ptrFromInt(isa_addr);
}

pub fn shim_objc_enumerationMutation(obj: ?*anyopaque) callconv(.c) noreturn {
    _ = obj;
    std.debug.print("WINS-OBJC: collection was mutated while being enumerated\n", .{});
    abort();
}
