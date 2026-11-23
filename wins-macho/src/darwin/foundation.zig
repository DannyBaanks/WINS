const std = @import("std");
const objc = @import("objc.zig");
const trace = @import("../runtime/trace.zig");

extern "c" fn malloc(size: usize) ?*anyopaque;
extern "c" fn realloc(ptr: ?*anyopaque, size: usize) ?*anyopaque;
extern "c" fn free(ptr: ?*anyopaque) void;
extern "c" fn memcpy(dst: *anyopaque, src: *const anyopaque, n: usize) *anyopaque;
extern "c" fn write(fd: c_int, buf: ?*const anyopaque, count: usize) isize;

fn MethodList(comptime count: usize) type {
    return extern struct {
        header: objc.MethodListT = .{
            .entsizeAndFlags = @sizeOf(objc.MethodLargeT),
            .count = count,
        },
        methods: [count]objc.MethodLargeT,
    };
}

fn m(name: [*:0]const u8, types: [*:0]const u8, func: anytype) objc.MethodLargeT {
    return .{
        .name = name,
        .types = types,
        .imp = @intFromPtr(func),
    };
}

// ============================================================================
// NSObject
// ============================================================================

fn nsObjectAlloc(self_cls: ?*objc.ObjcClass, _: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    return objc.shim_objc_alloc(self_cls);
}

fn nsObjectNew(self_cls: ?*objc.ObjcClass, _: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    return objc.shim_objc_alloc_init(self_cls);
}

fn nsObjectClassSelf(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    return self;
}

fn nsObjectClassSuperclass(self_cls: ?*objc.ObjcClass, _: ?[*:0]const u8) callconv(.c) usize {
    const cls = self_cls orelse return 0;
    return cls.superclass;
}

fn nsObjectInstancesRespondToSelector(self_cls: ?*objc.ObjcClass, _: ?[*:0]const u8, sel: ?[*:0]const u8) callconv(.c) u8 {
    const cls = self_cls orelse return 0;
    const s = sel orelse return 0;
    return if (objc.lookupMethodInHierarchy(@intFromPtr(cls), std.mem.span(s)) != null) 1 else 0;
}

fn nsObjectIsSubclassOfClass(self_cls: ?*objc.ObjcClass, _: ?[*:0]const u8, target: usize) callconv(.c) u8 {
    const cls = self_cls orelse return 0;
    return if (objc.isSubclassOf(@intFromPtr(cls), target)) 1 else 0;
}

fn nsObjectInit(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    return self;
}

fn nsObjectDealloc(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) void {
    free(self);
}

fn nsObjectRetain(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    return objc.shim_objc_retain(self);
}

fn nsObjectRelease(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) void {
    objc.shim_objc_release(self);
}

fn nsObjectAutorelease(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    return objc.shim_objc_autorelease(self);
}

fn nsObjectRetainCount(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) usize {
    return objc.getRetainCount(self);
}

fn nsObjectInstanceClass(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) usize {
    return objc.shim_objc_opt_class(self);
}

fn nsObjectInstanceSuperclass(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) usize {
    const isa = objc.shim_objc_opt_class(self);
    if (isa == 0 or (isa & 0x7) != 0) return 0;
    const cls: *const objc.ObjcClass = @ptrFromInt(isa);
    return cls.superclass;
}

fn nsObjectIsKindOfClass(self: ?*anyopaque, _: ?[*:0]const u8, target: usize) callconv(.c) u8 {
    return objc.shim_objc_opt_isKindOfClass(self, target);
}

fn nsObjectIsMemberOfClass(self: ?*anyopaque, _: ?[*:0]const u8, target: usize) callconv(.c) u8 {
    return if (objc.shim_objc_opt_class(self) == target) 1 else 0;
}

fn nsObjectRespondsToSelector(self: ?*anyopaque, _: ?[*:0]const u8, sel: ?[*:0]const u8) callconv(.c) u8 {
    return objc.shim_objc_opt_respondsToSelector(self, sel);
}

fn nsObjectIsEqual(self: ?*anyopaque, _: ?[*:0]const u8, other: ?*anyopaque) callconv(.c) u8 {
    return if (self == other) 1 else 0;
}

fn nsObjectHash(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) usize {
    return @intFromPtr(self);
}

fn nsObjectDescription(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    const ptr = self orelse return makeNSStringFromSlice("(null)", true);
    const isa = objc.shim_objc_opt_class(ptr);
    const name = if (isa != 0 and (isa & 0x7) == 0) objc.getClassName(@ptrFromInt(isa)) else "Object";
    var buf: [128]u8 = undefined;
    const formatted = std.fmt.bufPrint(&buf, "<{s}: 0x{x}>", .{ name, @intFromPtr(ptr) }) catch "<Object>";
    return makeNSStringFromSlice(formatted, true);
}

var nsobject_meta_methods: MethodList(6) = .{ .methods = undefined };
var nsobject_inst_methods: MethodList(14) = .{ .methods = undefined };

const nsobject_meta_ro: objc.ClassRoT = .{
    .flags = 1,
    .instanceStart = @sizeOf(objc.ObjcClass),
    .instanceSize = @sizeOf(objc.ObjcClass),
    .reserved = 0,
    .ivarLayout = 0,
    .name = "NSObject",
    .baseMethodList = &nsobject_meta_methods.header,
    .baseProtocols = 0,
    .ivars = 0,
    .weakIvarLayout = 0,
    .baseProperties = 0,
};

const nsobject_ro: objc.ClassRoT = .{
    .flags = 0,
    .instanceStart = @sizeOf(usize),
    .instanceSize = @sizeOf(usize),
    .reserved = 0,
    .ivarLayout = 0,
    .name = "NSObject",
    .baseMethodList = &nsobject_inst_methods.header,
    .baseProtocols = 0,
    .ivars = 0,
    .weakIvarLayout = 0,
    .baseProperties = 0,
};

pub var OBJC_METACLASS_NSObject: objc.ObjcClass = .{
    .isa = 0,
    .superclass = 0,
    .cache_buckets = 0,
    .cache_mask_vtable = 0,
    .bits = 0,
};

pub var OBJC_CLASS_NSObject: objc.ObjcClass = .{
    .isa = 0,
    .superclass = 0,
    .cache_buckets = 0,
    .cache_mask_vtable = 0,
    .bits = 0,
};

// ============================================================================
// NSString & __NSCFConstantString (___CFConstantStringClassReference)
// ============================================================================

pub const NSStringObject = extern struct {
    isa: usize,
    flags: u32,
    _pad: u32 = 0,
    ptr: ?[*:0]const u8,
    len: usize,
};

pub fn nsStringSlice(obj: ?*anyopaque) []const u8 {
    const ptr = obj orelse return "";
    const str_obj: *const NSStringObject = @ptrCast(@alignCast(ptr));
    const cstr = str_obj.ptr orelse return "";
    return @as([*]const u8, @ptrCast(cstr))[0..str_obj.len];
}

pub fn makeNSStringFromSlice(slice: []const u8, autorelease: bool) ?*anyopaque {
    const obj = objc.shim_objc_alloc(&OBJC_CLASS_NSString) orelse return null;
    const str_obj: *NSStringObject = @ptrCast(@alignCast(obj));
    const buf_raw = malloc(slice.len + 1) orelse {
        objc.shim_objc_release(obj);
        return null;
    };
    const buf: [*]u8 = @ptrCast(buf_raw);
    if (slice.len > 0) {
        _ = memcpy(buf_raw, slice.ptr, slice.len);
    }
    buf[slice.len] = 0;
    str_obj.flags = 0x07c8;
    str_obj._pad = 0;
    str_obj.ptr = @ptrCast(buf);
    str_obj.len = slice.len;
    if (autorelease) {
        _ = objc.shim_objc_autorelease(obj);
    }
    return obj;
}

fn nsStringClassEmpty(_: ?*objc.ObjcClass, _: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    return makeNSStringFromSlice("", true);
}

fn nsStringWithUTF8String(_: ?*objc.ObjcClass, _: ?[*:0]const u8, cstr: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    const s = cstr orelse return null;
    return makeNSStringFromSlice(std.mem.span(s), true);
}

fn nsStringWithCStringEncoding(_: ?*objc.ObjcClass, _: ?[*:0]const u8, cstr: ?[*:0]const u8, _: usize) callconv(.c) ?*anyopaque {
    const s = cstr orelse return null;
    return makeNSStringFromSlice(std.mem.span(s), true);
}

fn nsStringWithString(_: ?*objc.ObjcClass, _: ?[*:0]const u8, other: ?*anyopaque) callconv(.c) ?*anyopaque {
    return makeNSStringFromSlice(nsStringSlice(other), true);
}

fn nsStringInitWithUTF8String(self: ?*anyopaque, _: ?[*:0]const u8, cstr: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    const ptr = self orelse return null;
    const s = cstr orelse {
        objc.shim_objc_release(ptr);
        return null;
    };
    const slice = std.mem.span(s);
    const str_obj: *NSStringObject = @ptrCast(@alignCast(ptr));
    const buf_raw = malloc(slice.len + 1) orelse {
        objc.shim_objc_release(ptr);
        return null;
    };
    const buf: [*]u8 = @ptrCast(buf_raw);
    if (slice.len > 0) {
        _ = memcpy(buf_raw, slice.ptr, slice.len);
    }
    buf[slice.len] = 0;
    str_obj.flags = 0x07c8;
    str_obj._pad = 0;
    str_obj.ptr = @ptrCast(buf);
    str_obj.len = slice.len;
    return ptr;
}

fn nsStringInitWithCStringEncoding(self: ?*anyopaque, sel: ?[*:0]const u8, cstr: ?[*:0]const u8, _: usize) callconv(.c) ?*anyopaque {
    return nsStringInitWithUTF8String(self, sel, cstr);
}

fn nsStringInitWithString(self: ?*anyopaque, _: ?[*:0]const u8, other: ?*anyopaque) callconv(.c) ?*anyopaque {
    const ptr = self orelse return null;
    const slice = nsStringSlice(other);
    const str_obj: *NSStringObject = @ptrCast(@alignCast(ptr));
    const buf_raw = malloc(slice.len + 1) orelse {
        objc.shim_objc_release(ptr);
        return null;
    };
    const buf: [*]u8 = @ptrCast(buf_raw);
    if (slice.len > 0) {
        _ = memcpy(buf_raw, slice.ptr, slice.len);
    }
    buf[slice.len] = 0;
    str_obj.flags = 0x07c8;
    str_obj._pad = 0;
    str_obj.ptr = @ptrCast(buf);
    str_obj.len = slice.len;
    return ptr;
}

fn nsStringDealloc(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) void {
    const ptr = self orelse return;
    const str_obj: *NSStringObject = @ptrCast(@alignCast(ptr));
    if (str_obj.isa == @intFromPtr(&OBJC_CLASS_NSString) and str_obj.ptr != null) {
        free(@ptrCast(@constCast(str_obj.ptr.?)));
        str_obj.ptr = null;
    }
    free(ptr);
}

fn nsStringLength(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) usize {
    return nsStringSlice(self).len;
}

fn nsStringUTF8String(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) ?[*:0]const u8 {
    const ptr = self orelse return "";
    const str_obj: *const NSStringObject = @ptrCast(@alignCast(ptr));
    return str_obj.ptr orelse "";
}

fn nsStringCStringUsingEncoding(self: ?*anyopaque, sel: ?[*:0]const u8, _: usize) callconv(.c) ?[*:0]const u8 {
    return nsStringUTF8String(self, sel);
}

fn nsStringIsEqualToString(self: ?*anyopaque, _: ?[*:0]const u8, other: ?*anyopaque) callconv(.c) u8 {
    if (self == null or other == null) return 0;
    if (self == other) return 1;
    return if (std.mem.eql(u8, nsStringSlice(self), nsStringSlice(other))) 1 else 0;
}

fn nsStringIsEqual(self: ?*anyopaque, sel: ?[*:0]const u8, other: ?*anyopaque) callconv(.c) u8 {
    const o = other orelse return 0;
    const isa = objc.shim_objc_opt_class(o);
    if (objc.isSubclassOf(isa, @intFromPtr(&OBJC_CLASS_NSString))) {
        return nsStringIsEqualToString(self, sel, o);
    }
    return 0;
}

fn nsStringHash(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) usize {
    const s = nsStringSlice(self);
    var h: u64 = 14695981039346656037;
    for (s) |b| {
        h ^= b;
        h *%= 1099511628211;
    }
    return @intCast(h);
}

fn nsStringDescription(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    return self;
}

fn nsStringByAppendingString(self: ?*anyopaque, _: ?[*:0]const u8, other: ?*anyopaque) callconv(.c) ?*anyopaque {
    const a = nsStringSlice(self);
    const b = nsStringSlice(other);
    var list: std.ArrayListUnmanaged(u8) = .empty;
    defer list.deinit(std.heap.c_allocator);
    list.appendSlice(std.heap.c_allocator, a) catch return null;
    list.appendSlice(std.heap.c_allocator, b) catch return null;
    return makeNSStringFromSlice(list.items, true);
}

fn nsStringHasPrefix(self: ?*anyopaque, _: ?[*:0]const u8, prefix: ?*anyopaque) callconv(.c) u8 {
    const p = prefix orelse return 0;
    return if (std.mem.startsWith(u8, nsStringSlice(self), nsStringSlice(p))) 1 else 0;
}

fn nsStringHasSuffix(self: ?*anyopaque, _: ?[*:0]const u8, suffix: ?*anyopaque) callconv(.c) u8 {
    const s = suffix orelse return 0;
    return if (std.mem.endsWith(u8, nsStringSlice(self), nsStringSlice(s))) 1 else 0;
}

fn nsStringContainsString(self: ?*anyopaque, _: ?[*:0]const u8, sub: ?*anyopaque) callconv(.c) u8 {
    const needle = nsStringSlice(sub);
    if (needle.len == 0) return 0;
    return if (std.mem.indexOf(u8, nsStringSlice(self), needle) != null) 1 else 0;
}

fn nsStringIntegerValue(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) isize {
    const s = std.mem.trim(u8, nsStringSlice(self), " \t\n\r");
    return std.fmt.parseInt(isize, s, 10) catch 0;
}

fn nsStringIntValue(self: ?*anyopaque, sel: ?[*:0]const u8) callconv(.c) c_int {
    return @intCast(@as(i32, @truncate(nsStringIntegerValue(self, sel))));
}

fn nsStringDataUsingEncoding(self: ?*anyopaque, _: ?[*:0]const u8, _: usize) callconv(.c) ?*anyopaque {
    const s = nsStringSlice(self);
    return makeNSDataFromBytes(s.ptr, s.len, true);
}

// ============================================================================
// Formatting Engine (shared by NSString +stringWithFormat: and NSLog)
// ============================================================================

fn objectDescriptionSlice(obj: ?*anyopaque, tmp_buf: *std.ArrayListUnmanaged(u8)) []const u8 {
    const ptr = obj orelse return "(null)";
    const isa = objc.shim_objc_opt_class(ptr);
    if (objc.isSubclassOf(isa, @intFromPtr(&OBJC_CLASS_NSString))) {
        return nsStringSlice(ptr);
    }
    if (isa != 0 and (isa & 0x7) == 0) {
        if (objc.lookupMethodInHierarchy(isa, "description")) |imp| {
            const desc_fn: *const fn (*anyopaque, [*:0]const u8) callconv(.c) ?*anyopaque = @ptrFromInt(imp);
            if (desc_fn(ptr, "description")) |desc_obj| {
                const s = nsStringSlice(desc_obj);
                tmp_buf.clearRetainingCapacity();
                tmp_buf.appendSlice(std.heap.c_allocator, s) catch return "(error)";
                return tmp_buf.items;
            }
        }
    }
    return "(object)";
}

fn formatWithVaList(fmt_obj: ?*anyopaque, ap: *std.builtin.VaList, out: *std.ArrayListUnmanaged(u8)) callconv(.c) void {
    const alloc = std.heap.c_allocator;
    const fmt = nsStringSlice(fmt_obj);
    var desc_tmp: std.ArrayListUnmanaged(u8) = .empty;
    defer desc_tmp.deinit(alloc);

    var i: usize = 0;
    while (i < fmt.len) {
        if (fmt[i] != '%') {
            out.append(alloc, fmt[i]) catch return;
            i += 1;
            continue;
        }
        i += 1;
        if (i >= fmt.len) break;
        if (fmt[i] == '%') {
            out.append(alloc, '%') catch return;
            i += 1;
            continue;
        }

        // Parse optional flags/width/precision/length
        var is_long = false;
        var is_size = false;
        while (i < fmt.len and (fmt[i] == '-' or fmt[i] == '+' or fmt[i] == ' ' or fmt[i] == '#' or fmt[i] == '0' or (fmt[i] >= '1' and fmt[i] <= '9') or fmt[i] == '.')) : (i += 1) {}
        while (i < fmt.len) {
            if (fmt[i] == 'l') {
                is_long = true;
                i += 1;
            } else if (fmt[i] == 'z') {
                is_size = true;
                i += 1;
            } else {
                break;
            }
        }
        if (i >= fmt.len) break;
        const spec = fmt[i];
        i += 1;

        var num_buf: [64]u8 = undefined;
        switch (spec) {
            '@' => {
                const arg_obj = @cVaArg(ap, ?*anyopaque);
                const s = objectDescriptionSlice(arg_obj, &desc_tmp);
                out.appendSlice(alloc, s) catch return;
            },
            's' => {
                const cstr = @cVaArg(ap, ?[*:0]const u8);
                if (cstr) |p| {
                    out.appendSlice(alloc, std.mem.span(p)) catch return;
                } else {
                    out.appendSlice(alloc, "(null)") catch return;
                }
            },
            'd', 'i' => {
                const val: i64 = if (is_long or is_size) @cVaArg(ap, i64) else @cVaArg(ap, i32);
                const formatted = std.fmt.bufPrint(&num_buf, "{d}", .{val}) catch "";
                out.appendSlice(alloc, formatted) catch return;
            },
            'u' => {
                const val: u64 = if (is_long or is_size) @cVaArg(ap, u64) else @cVaArg(ap, u32);
                const formatted = std.fmt.bufPrint(&num_buf, "{d}", .{val}) catch "";
                out.appendSlice(alloc, formatted) catch return;
            },
            'x' => {
                const val: u64 = if (is_long or is_size) @cVaArg(ap, u64) else @cVaArg(ap, u32);
                const formatted = std.fmt.bufPrint(&num_buf, "{x}", .{val}) catch "";
                out.appendSlice(alloc, formatted) catch return;
            },
            'X' => {
                const val: u64 = if (is_long or is_size) @cVaArg(ap, u64) else @cVaArg(ap, u32);
                const formatted = std.fmt.bufPrint(&num_buf, "{X}", .{val}) catch "";
                out.appendSlice(alloc, formatted) catch return;
            },
            'p' => {
                const val = @cVaArg(ap, usize);
                const formatted = std.fmt.bufPrint(&num_buf, "0x{x}", .{val}) catch "";
                out.appendSlice(alloc, formatted) catch return;
            },
            'c' => {
                const ch = @cVaArg(ap, c_int);
                out.append(alloc, @truncate(@as(u32, @bitCast(ch)))) catch return;
            },
            'f' => {
                const val = @cVaArg(ap, f64);
                const formatted = std.fmt.bufPrint(&num_buf, "{d:.6}", .{val}) catch "";
                out.appendSlice(alloc, formatted) catch return;
            },
            else => {
                out.append(alloc, '%') catch return;
                out.append(alloc, spec) catch return;
            },
        }
    }
}

fn nsStringWithFormat(_: ?*objc.ObjcClass, _: ?[*:0]const u8, fmt_obj: ?*anyopaque, ...) callconv(.c) ?*anyopaque {
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(std.heap.c_allocator);
    formatWithVaList(fmt_obj, &ap, &out);
    return makeNSStringFromSlice(out.items, true);
}

pub fn shim_NSLog(fmt_obj: ?*anyopaque, ...) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_NSLog");
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(std.heap.c_allocator);
    formatWithVaList(fmt_obj, &ap, &out);
    out.append(std.heap.c_allocator, '\n') catch return;
    _ = write(2, out.items.ptr, out.items.len);
}

var nsstring_meta_methods: MethodList(5) = .{ .methods = undefined };
var nsstring_inst_methods: MethodList(18) = .{ .methods = undefined };

const nsstring_meta_ro: objc.ClassRoT = .{
    .flags = 1,
    .instanceStart = @sizeOf(objc.ObjcClass),
    .instanceSize = @sizeOf(objc.ObjcClass),
    .reserved = 0,
    .ivarLayout = 0,
    .name = "NSString",
    .baseMethodList = &nsstring_meta_methods.header,
    .baseProtocols = 0,
    .ivars = 0,
    .weakIvarLayout = 0,
    .baseProperties = 0,
};

const nsstring_ro: objc.ClassRoT = .{
    .flags = 0,
    .instanceStart = @sizeOf(usize),
    .instanceSize = @sizeOf(NSStringObject),
    .reserved = 0,
    .ivarLayout = 0,
    .name = "NSString",
    .baseMethodList = &nsstring_inst_methods.header,
    .baseProtocols = 0,
    .ivars = 0,
    .weakIvarLayout = 0,
    .baseProperties = 0,
};

pub var OBJC_METACLASS_NSString: objc.ObjcClass = .{ .isa = 0, .superclass = 0, .cache_buckets = 0, .cache_mask_vtable = 0, .bits = 0 };
pub var OBJC_CLASS_NSString: objc.ObjcClass = .{ .isa = 0, .superclass = 0, .cache_buckets = 0, .cache_mask_vtable = 0, .bits = 0 };

var nsconststring_meta_methods: MethodList(0) = .{ .methods = .{} };
var nsconststring_inst_methods: MethodList(0) = .{ .methods = .{} };

const nsconststring_meta_ro: objc.ClassRoT = .{
    .flags = 1,
    .instanceStart = @sizeOf(objc.ObjcClass),
    .instanceSize = @sizeOf(objc.ObjcClass),
    .reserved = 0,
    .ivarLayout = 0,
    .name = "__NSCFConstantString",
    .baseMethodList = &nsconststring_meta_methods.header,
    .baseProtocols = 0,
    .ivars = 0,
    .weakIvarLayout = 0,
    .baseProperties = 0,
};

const nsconststring_ro: objc.ClassRoT = .{
    .flags = 0,
    .instanceStart = @sizeOf(usize),
    .instanceSize = @sizeOf(NSStringObject),
    .reserved = 0,
    .ivarLayout = 0,
    .name = "__NSCFConstantString",
    .baseMethodList = &nsconststring_inst_methods.header,
    .baseProtocols = 0,
    .ivars = 0,
    .weakIvarLayout = 0,
    .baseProperties = 0,
};

pub var OBJC_METACLASS_NSConstantString: objc.ObjcClass = .{ .isa = 0, .superclass = 0, .cache_buckets = 0, .cache_mask_vtable = 0, .bits = 0 };
pub var OBJC_CLASS_NSConstantString: objc.ObjcClass = .{ .isa = 0, .superclass = 0, .cache_buckets = 0, .cache_mask_vtable = 0, .bits = 0 };

// ============================================================================
// NSData
// ============================================================================

pub const NSRange = extern struct {
    location: usize,
    length: usize,
};

pub const NSDataObject = extern struct {
    isa: usize,
    bytes_ptr: ?[*]const u8,
    len: usize,
    owned: bool,
};

pub fn makeNSDataFromBytes(src: ?[*]const u8, len: usize, autorelease: bool) ?*anyopaque {
    const obj = objc.shim_objc_alloc(&OBJC_CLASS_NSData) orelse return null;
    const d: *NSDataObject = @ptrCast(@alignCast(obj));
    if (len > 0 and src != null) {
        const buf_raw = malloc(len) orelse {
            objc.shim_objc_release(obj);
            return null;
        };
        _ = memcpy(buf_raw, src.?, len);
        d.bytes_ptr = @ptrCast(buf_raw);
        d.len = len;
        d.owned = true;
    } else {
        d.bytes_ptr = null;
        d.len = 0;
        d.owned = false;
    }
    if (autorelease) _ = objc.shim_objc_autorelease(obj);
    return obj;
}

fn nsDataClassEmpty(_: ?*objc.ObjcClass, _: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    return makeNSDataFromBytes(null, 0, true);
}

fn nsDataWithBytesLength(_: ?*objc.ObjcClass, _: ?[*:0]const u8, bytes: ?[*]const u8, len: usize) callconv(.c) ?*anyopaque {
    return makeNSDataFromBytes(bytes, len, true);
}

fn nsDataWithBytesNoCopyLengthFree(_: ?*objc.ObjcClass, _: ?[*:0]const u8, bytes: ?[*]const u8, len: usize, free_when_done: u8) callconv(.c) ?*anyopaque {
    const obj = objc.shim_objc_alloc(&OBJC_CLASS_NSData) orelse return null;
    const d: *NSDataObject = @ptrCast(@alignCast(obj));
    d.bytes_ptr = bytes;
    d.len = len;
    d.owned = free_when_done != 0;
    _ = objc.shim_objc_autorelease(obj);
    return obj;
}

fn nsDataWithBytesNoCopyLength(cls: ?*objc.ObjcClass, sel: ?[*:0]const u8, bytes: ?[*]const u8, len: usize) callconv(.c) ?*anyopaque {
    return nsDataWithBytesNoCopyLengthFree(cls, sel, bytes, len, 1);
}

fn nsDataInitWithBytesLength(self: ?*anyopaque, _: ?[*:0]const u8, bytes: ?[*]const u8, len: usize) callconv(.c) ?*anyopaque {
    const ptr = self orelse return null;
    const d: *NSDataObject = @ptrCast(@alignCast(ptr));
    if (len > 0 and bytes != null) {
        const buf_raw = malloc(len) orelse {
            objc.shim_objc_release(ptr);
            return null;
        };
        _ = memcpy(buf_raw, bytes.?, len);
        d.bytes_ptr = @ptrCast(buf_raw);
        d.len = len;
        d.owned = true;
    } else {
        d.bytes_ptr = null;
        d.len = 0;
        d.owned = false;
    }
    return ptr;
}

fn nsDataDealloc(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) void {
    const ptr = self orelse return;
    const d: *NSDataObject = @ptrCast(@alignCast(ptr));
    if (d.owned and d.bytes_ptr != null) {
        free(@ptrCast(@constCast(d.bytes_ptr.?)));
        d.bytes_ptr = null;
    }
    free(ptr);
}

fn nsDataLength(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) usize {
    const ptr = self orelse return 0;
    const d: *const NSDataObject = @ptrCast(@alignCast(ptr));
    return d.len;
}

fn nsDataBytes(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) ?[*]const u8 {
    const ptr = self orelse return null;
    const d: *const NSDataObject = @ptrCast(@alignCast(ptr));
    return d.bytes_ptr;
}

fn nsDataIsEqualToData(self: ?*anyopaque, _: ?[*:0]const u8, other: ?*anyopaque) callconv(.c) u8 {
    if (self == null or other == null) return 0;
    if (self == other) return 1;
    const a: *const NSDataObject = @ptrCast(@alignCast(self.?));
    const b: *const NSDataObject = @ptrCast(@alignCast(other.?));
    if (a.len != b.len) return 0;
    if (a.len == 0) return 1;
    if (a.bytes_ptr == null or b.bytes_ptr == null) return 0;
    return if (std.mem.eql(u8, a.bytes_ptr.?[0..a.len], b.bytes_ptr.?[0..b.len])) 1 else 0;
}

fn nsDataIsEqual(self: ?*anyopaque, sel: ?[*:0]const u8, other: ?*anyopaque) callconv(.c) u8 {
    const o = other orelse return 0;
    const isa = objc.shim_objc_opt_class(o);
    if (objc.isSubclassOf(isa, @intFromPtr(&OBJC_CLASS_NSData))) {
        return nsDataIsEqualToData(self, sel, o);
    }
    return 0;
}

fn nsDataSubdataWithRange(self: ?*anyopaque, _: ?[*:0]const u8, range: NSRange) callconv(.c) ?*anyopaque {
    const ptr = self orelse return null;
    const d: *const NSDataObject = @ptrCast(@alignCast(ptr));
    if (range.location > d.len or range.location + range.length > d.len) return null;
    const base = d.bytes_ptr orelse return makeNSDataFromBytes(null, 0, true);
    return makeNSDataFromBytes(base + range.location, range.length, true);
}

fn nsDataDescription(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    const ptr = self orelse return makeNSStringFromSlice("(null)", true);
    const d: *const NSDataObject = @ptrCast(@alignCast(ptr));
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(std.heap.c_allocator);
    out.append(std.heap.c_allocator, '<') catch return null;
    if (d.bytes_ptr) |bytes| {
        var idx: usize = 0;
        while (idx < d.len) : (idx += 1) {
            if (idx > 0 and idx % 4 == 0) out.append(std.heap.c_allocator, ' ') catch {};
            var hex: [2]u8 = undefined;
            _ = std.fmt.bufPrint(&hex, "{x:0>2}", .{bytes[idx]}) catch {};
            out.appendSlice(std.heap.c_allocator, &hex) catch {};
        }
    }
    out.append(std.heap.c_allocator, '>') catch return null;
    return makeNSStringFromSlice(out.items, true);
}

var nsdata_meta_methods: MethodList(4) = .{ .methods = undefined };
var nsdata_inst_methods: MethodList(8) = .{ .methods = undefined };

const nsdata_meta_ro: objc.ClassRoT = .{
    .flags = 1,
    .instanceStart = @sizeOf(objc.ObjcClass),
    .instanceSize = @sizeOf(objc.ObjcClass),
    .reserved = 0,
    .ivarLayout = 0,
    .name = "NSData",
    .baseMethodList = &nsdata_meta_methods.header,
    .baseProtocols = 0,
    .ivars = 0,
    .weakIvarLayout = 0,
    .baseProperties = 0,
};

const nsdata_ro: objc.ClassRoT = .{
    .flags = 0,
    .instanceStart = @sizeOf(usize),
    .instanceSize = @sizeOf(NSDataObject),
    .reserved = 0,
    .ivarLayout = 0,
    .name = "NSData",
    .baseMethodList = &nsdata_inst_methods.header,
    .baseProtocols = 0,
    .ivars = 0,
    .weakIvarLayout = 0,
    .baseProperties = 0,
};

pub var OBJC_METACLASS_NSData: objc.ObjcClass = .{ .isa = 0, .superclass = 0, .cache_buckets = 0, .cache_mask_vtable = 0, .bits = 0 };
pub var OBJC_CLASS_NSData: objc.ObjcClass = .{ .isa = 0, .superclass = 0, .cache_buckets = 0, .cache_mask_vtable = 0, .bits = 0 };

// ============================================================================
// NSArray & NSMutableArray
// ============================================================================

pub const NSFastEnumerationState = extern struct {
    state: usize,
    items_ptr: ?[*]?*anyopaque,
    mutations_ptr: ?*usize,
    extra: [5]usize,
};

var array_mutations_sentinel: usize = 0;

pub const NSArrayObject = extern struct {
    isa: usize,
    items: ?[*]?*anyopaque,
    count: usize,
    capacity: usize,
};

fn makeNSArrayWithItems(cls: *objc.ObjcClass, src_items: ?[*]?*anyopaque, count: usize, autorelease: bool) ?*anyopaque {
    const obj = objc.shim_objc_alloc(cls) orelse return null;
    const arr: *NSArrayObject = @ptrCast(@alignCast(obj));
    if (count > 0 and src_items != null) {
        const buf_raw = malloc(count * @sizeOf(?*anyopaque)) orelse {
            objc.shim_objc_release(obj);
            return null;
        };
        const buf: [*]?*anyopaque = @ptrCast(@alignCast(buf_raw));
        var i: usize = 0;
        while (i < count) : (i += 1) {
            buf[i] = objc.shim_objc_retain(src_items.?[i]);
        }
        arr.items = buf;
        arr.count = count;
        arr.capacity = count;
    } else {
        arr.items = null;
        arr.count = 0;
        arr.capacity = 0;
    }
    if (autorelease) _ = objc.shim_objc_autorelease(obj);
    return obj;
}

fn nsArrayEmpty(self_cls: ?*objc.ObjcClass, _: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    return makeNSArrayWithItems(self_cls orelse &OBJC_CLASS_NSArray, null, 0, true);
}

fn nsArrayWithObject(self_cls: ?*objc.ObjcClass, _: ?[*:0]const u8, item: ?*anyopaque) callconv(.c) ?*anyopaque {
    if (item == null) return makeNSArrayWithItems(self_cls orelse &OBJC_CLASS_NSArray, null, 0, true);
    var one = [_]?*anyopaque{item};
    return makeNSArrayWithItems(self_cls orelse &OBJC_CLASS_NSArray, &one, 1, true);
}

fn nsArrayWithObjectsCount(self_cls: ?*objc.ObjcClass, _: ?[*:0]const u8, items: ?[*]?*anyopaque, count: usize) callconv(.c) ?*anyopaque {
    return makeNSArrayWithItems(self_cls orelse &OBJC_CLASS_NSArray, items, count, true);
}

fn nsArrayWithObjectsVarargs(self_cls: ?*objc.ObjcClass, _: ?[*:0]const u8, first: ?*anyopaque, ...) callconv(.c) ?*anyopaque {
    var list: std.ArrayListUnmanaged(?*anyopaque) = .empty;
    defer list.deinit(std.heap.c_allocator);
    if (first) |f| {
        list.append(std.heap.c_allocator, f) catch return null;
        var ap = @cVaStart();
        defer @cVaEnd(&ap);
        while (true) {
            const next = @cVaArg(&ap, ?*anyopaque) orelse break;
            list.append(std.heap.c_allocator, next) catch return null;
        }
    }
    return makeNSArrayWithItems(self_cls orelse &OBJC_CLASS_NSArray, if (list.items.len > 0) list.items.ptr else null, list.items.len, true);
}

fn nsArrayInitWithObjectsCount(self: ?*anyopaque, _: ?[*:0]const u8, items: ?[*]?*anyopaque, count: usize) callconv(.c) ?*anyopaque {
    const ptr = self orelse return null;
    const arr: *NSArrayObject = @ptrCast(@alignCast(ptr));
    if (count > 0 and items != null) {
        const buf_raw = malloc(count * @sizeOf(?*anyopaque)) orelse {
            objc.shim_objc_release(ptr);
            return null;
        };
        const buf: [*]?*anyopaque = @ptrCast(@alignCast(buf_raw));
        var i: usize = 0;
        while (i < count) : (i += 1) {
            buf[i] = objc.shim_objc_retain(items.?[i]);
        }
        arr.items = buf;
        arr.count = count;
        arr.capacity = count;
    }
    return ptr;
}

fn nsArrayDealloc(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) void {
    const ptr = self orelse return;
    const arr: *NSArrayObject = @ptrCast(@alignCast(ptr));
    if (arr.items) |buf| {
        var i: usize = 0;
        while (i < arr.count) : (i += 1) {
            objc.shim_objc_release(buf[i]);
        }
        free(@ptrCast(buf));
        arr.items = null;
    }
    free(ptr);
}

fn nsArrayCount(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) usize {
    const ptr = self orelse return 0;
    const arr: *const NSArrayObject = @ptrCast(@alignCast(ptr));
    return arr.count;
}

fn nsArrayObjectAtIndex(self: ?*anyopaque, _: ?[*:0]const u8, idx: usize) callconv(.c) ?*anyopaque {
    const ptr = self orelse return null;
    const arr: *const NSArrayObject = @ptrCast(@alignCast(ptr));
    if (idx >= arr.count or arr.items == null) return null;
    return arr.items.?[idx];
}

fn nsArrayFirstObject(self: ?*anyopaque, sel: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    return nsArrayObjectAtIndex(self, sel, 0);
}

fn nsArrayLastObject(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    const ptr = self orelse return null;
    const arr: *const NSArrayObject = @ptrCast(@alignCast(ptr));
    if (arr.count == 0 or arr.items == null) return null;
    return arr.items.?[arr.count - 1];
}

fn objectsEqual(a: ?*anyopaque, b: ?*anyopaque) bool {
    if (a == b) return true;
    if (a == null or b == null) return false;
    const isa = objc.shim_objc_opt_class(a);
    if (isa != 0 and (isa & 0x7) == 0) {
        if (objc.lookupMethodInHierarchy(isa, "isEqual:")) |imp| {
            const eq_fn: *const fn (?*anyopaque, [*:0]const u8, ?*anyopaque) callconv(.c) u8 = @ptrFromInt(imp);
            return eq_fn(a, "isEqual:", b) != 0;
        }
    }
    return false;
}

fn nsArrayIndexOfObject(self: ?*anyopaque, _: ?[*:0]const u8, target: ?*anyopaque) callconv(.c) usize {
    const ptr = self orelse return std.math.maxInt(usize);
    const arr: *const NSArrayObject = @ptrCast(@alignCast(ptr));
    const buf = arr.items orelse return std.math.maxInt(usize);
    var i: usize = 0;
    while (i < arr.count) : (i += 1) {
        if (objectsEqual(buf[i], target)) return i;
    }
    return std.math.maxInt(usize);
}

fn nsArrayContainsObject(self: ?*anyopaque, sel: ?[*:0]const u8, target: ?*anyopaque) callconv(.c) u8 {
    return if (nsArrayIndexOfObject(self, sel, target) != std.math.maxInt(usize)) 1 else 0;
}

fn nsArrayComponentsJoinedByString(self: ?*anyopaque, _: ?[*:0]const u8, sep_obj: ?*anyopaque) callconv(.c) ?*anyopaque {
    const ptr = self orelse return makeNSStringFromSlice("", true);
    const arr: *const NSArrayObject = @ptrCast(@alignCast(ptr));
    const sep = nsStringSlice(sep_obj);
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(std.heap.c_allocator);
    var tmp: std.ArrayListUnmanaged(u8) = .empty;
    defer tmp.deinit(std.heap.c_allocator);

    if (arr.items) |buf| {
        var i: usize = 0;
        while (i < arr.count) : (i += 1) {
            if (i > 0) out.appendSlice(std.heap.c_allocator, sep) catch return null;
            out.appendSlice(std.heap.c_allocator, objectDescriptionSlice(buf[i], &tmp)) catch return null;
        }
    }
    return makeNSStringFromSlice(out.items, true);
}

fn nsArrayDescription(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    const ptr = self orelse return makeNSStringFromSlice("(null)", true);
    const arr: *const NSArrayObject = @ptrCast(@alignCast(ptr));
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(std.heap.c_allocator);
    var tmp: std.ArrayListUnmanaged(u8) = .empty;
    defer tmp.deinit(std.heap.c_allocator);

    out.appendSlice(std.heap.c_allocator, "(\n") catch return null;
    if (arr.items) |buf| {
        var i: usize = 0;
        while (i < arr.count) : (i += 1) {
            out.appendSlice(std.heap.c_allocator, "    ") catch return null;
            out.appendSlice(std.heap.c_allocator, objectDescriptionSlice(buf[i], &tmp)) catch return null;
            if (i + 1 < arr.count) out.append(std.heap.c_allocator, ',') catch return null;
            out.append(std.heap.c_allocator, '\n') catch return null;
        }
    }
    out.append(std.heap.c_allocator, ')') catch return null;
    return makeNSStringFromSlice(out.items, true);
}

fn nsArrayCountByEnumerating(self: ?*anyopaque, _: ?[*:0]const u8, state_ptr: ?*NSFastEnumerationState, _: ?[*]?*anyopaque, _: usize) callconv(.c) usize {
    const ptr = self orelse return 0;
    const state = state_ptr orelse return 0;
    if (state.state != 0) return 0;
    const arr: *const NSArrayObject = @ptrCast(@alignCast(ptr));
    state.state = 1;
    state.items_ptr = arr.items;
    state.mutations_ptr = &array_mutations_sentinel;
    return arr.count;
}

// NSMutableArray
fn nsMutableArrayWithCapacity(self_cls: ?*objc.ObjcClass, _: ?[*:0]const u8, cap: usize) callconv(.c) ?*anyopaque {
    const obj = objc.shim_objc_alloc(self_cls orelse &OBJC_CLASS_NSMutableArray) orelse return null;
    const arr: *NSArrayObject = @ptrCast(@alignCast(obj));
    if (cap > 0) {
        if (malloc(cap * @sizeOf(?*anyopaque))) |buf_raw| {
            arr.items = @ptrCast(@alignCast(buf_raw));
            arr.capacity = cap;
        }
    }
    _ = objc.shim_objc_autorelease(obj);
    return obj;
}

fn nsMutableArrayInitWithCapacity(self: ?*anyopaque, _: ?[*:0]const u8, cap: usize) callconv(.c) ?*anyopaque {
    const ptr = self orelse return null;
    const arr: *NSArrayObject = @ptrCast(@alignCast(ptr));
    if (cap > 0) {
        if (malloc(cap * @sizeOf(?*anyopaque))) |buf_raw| {
            arr.items = @ptrCast(@alignCast(buf_raw));
            arr.capacity = cap;
        }
    }
    return ptr;
}

fn nsMutableArrayAddObject(self: ?*anyopaque, _: ?[*:0]const u8, item: ?*anyopaque) callconv(.c) void {
    const ptr = self orelse return;
    const obj = item orelse return;
    const arr: *NSArrayObject = @ptrCast(@alignCast(ptr));
    if (arr.count >= arr.capacity) {
        const new_cap = if (arr.capacity == 0) 8 else arr.capacity * 2;
        const new_raw = if (arr.items) |old|
            realloc(@ptrCast(old), new_cap * @sizeOf(?*anyopaque))
        else
            malloc(new_cap * @sizeOf(?*anyopaque));
        const buf_raw = new_raw orelse return;
        arr.items = @ptrCast(@alignCast(buf_raw));
        arr.capacity = new_cap;
    }
    arr.items.?[arr.count] = objc.shim_objc_retain(obj);
    arr.count += 1;
}

fn nsMutableArrayRemoveLastObject(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) void {
    const ptr = self orelse return;
    const arr: *NSArrayObject = @ptrCast(@alignCast(ptr));
    if (arr.count == 0 or arr.items == null) return;
    arr.count -= 1;
    objc.shim_objc_release(arr.items.?[arr.count]);
}

fn nsMutableArrayRemoveObjectAtIndex(self: ?*anyopaque, _: ?[*:0]const u8, idx: usize) callconv(.c) void {
    const ptr = self orelse return;
    const arr: *NSArrayObject = @ptrCast(@alignCast(ptr));
    if (idx >= arr.count or arr.items == null) return;
    const buf = arr.items.?;
    objc.shim_objc_release(buf[idx]);
    var i: usize = idx;
    while (i + 1 < arr.count) : (i += 1) {
        buf[i] = buf[i + 1];
    }
    arr.count -= 1;
}

fn nsMutableArrayRemoveAllObjects(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) void {
    const ptr = self orelse return;
    const arr: *NSArrayObject = @ptrCast(@alignCast(ptr));
    if (arr.items) |buf| {
        var i: usize = 0;
        while (i < arr.count) : (i += 1) {
            objc.shim_objc_release(buf[i]);
        }
    }
    arr.count = 0;
}

var nsarray_meta_methods: MethodList(4) = .{ .methods = undefined };
var nsarray_inst_methods: MethodList(12) = .{ .methods = undefined };

const nsarray_meta_ro: objc.ClassRoT = .{
    .flags = 1,
    .instanceStart = @sizeOf(objc.ObjcClass),
    .instanceSize = @sizeOf(objc.ObjcClass),
    .reserved = 0,
    .ivarLayout = 0,
    .name = "NSArray",
    .baseMethodList = &nsarray_meta_methods.header,
    .baseProtocols = 0,
    .ivars = 0,
    .weakIvarLayout = 0,
    .baseProperties = 0,
};

const nsarray_ro: objc.ClassRoT = .{
    .flags = 0,
    .instanceStart = @sizeOf(usize),
    .instanceSize = @sizeOf(NSArrayObject),
    .reserved = 0,
    .ivarLayout = 0,
    .name = "NSArray",
    .baseMethodList = &nsarray_inst_methods.header,
    .baseProtocols = 0,
    .ivars = 0,
    .weakIvarLayout = 0,
    .baseProperties = 0,
};

pub var OBJC_METACLASS_NSArray: objc.ObjcClass = .{ .isa = 0, .superclass = 0, .cache_buckets = 0, .cache_mask_vtable = 0, .bits = 0 };
pub var OBJC_CLASS_NSArray: objc.ObjcClass = .{ .isa = 0, .superclass = 0, .cache_buckets = 0, .cache_mask_vtable = 0, .bits = 0 };

var nsmutablearray_meta_methods: MethodList(1) = .{ .methods = undefined };
var nsmutablearray_inst_methods: MethodList(5) = .{ .methods = undefined };

const nsmutablearray_meta_ro: objc.ClassRoT = .{
    .flags = 1,
    .instanceStart = @sizeOf(objc.ObjcClass),
    .instanceSize = @sizeOf(objc.ObjcClass),
    .reserved = 0,
    .ivarLayout = 0,
    .name = "NSMutableArray",
    .baseMethodList = &nsmutablearray_meta_methods.header,
    .baseProtocols = 0,
    .ivars = 0,
    .weakIvarLayout = 0,
    .baseProperties = 0,
};

const nsmutablearray_ro: objc.ClassRoT = .{
    .flags = 0,
    .instanceStart = @sizeOf(usize),
    .instanceSize = @sizeOf(NSArrayObject),
    .reserved = 0,
    .ivarLayout = 0,
    .name = "NSMutableArray",
    .baseMethodList = &nsmutablearray_inst_methods.header,
    .baseProtocols = 0,
    .ivars = 0,
    .weakIvarLayout = 0,
    .baseProperties = 0,
};

pub var OBJC_METACLASS_NSMutableArray: objc.ObjcClass = .{ .isa = 0, .superclass = 0, .cache_buckets = 0, .cache_mask_vtable = 0, .bits = 0 };
pub var OBJC_CLASS_NSMutableArray: objc.ObjcClass = .{ .isa = 0, .superclass = 0, .cache_buckets = 0, .cache_mask_vtable = 0, .bits = 0 };

// ============================================================================
// NSAutoreleasePool
// ============================================================================

pub const NSAutoreleasePoolObject = extern struct {
    isa: usize,
    token: ?*anyopaque,
};

fn nsAutoreleasePoolInit(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    const ptr = self orelse return null;
    const p: *NSAutoreleasePoolObject = @ptrCast(@alignCast(ptr));
    p.token = objc.shim_objc_autoreleasePoolPush();
    return ptr;
}

fn nsAutoreleasePoolDrain(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) void {
    const ptr = self orelse return;
    const p: *NSAutoreleasePoolObject = @ptrCast(@alignCast(ptr));
    if (p.token) |tok| {
        p.token = null;
        objc.shim_objc_autoreleasePoolPop(tok);
    }
    objc.shim_objc_release(ptr);
}

fn nsAutoreleasePoolDealloc(self: ?*anyopaque, _: ?[*:0]const u8) callconv(.c) void {
    const ptr = self orelse return;
    const p: *NSAutoreleasePoolObject = @ptrCast(@alignCast(ptr));
    if (p.token) |tok| {
        p.token = null;
        objc.shim_objc_autoreleasePoolPop(tok);
    }
    free(ptr);
}

var nsautoreleasepool_meta_methods: MethodList(0) = .{ .methods = .{} };
var nsautoreleasepool_inst_methods: MethodList(4) = .{ .methods = undefined };

const nsautoreleasepool_meta_ro: objc.ClassRoT = .{
    .flags = 1,
    .instanceStart = @sizeOf(objc.ObjcClass),
    .instanceSize = @sizeOf(objc.ObjcClass),
    .reserved = 0,
    .ivarLayout = 0,
    .name = "NSAutoreleasePool",
    .baseMethodList = &nsautoreleasepool_meta_methods.header,
    .baseProtocols = 0,
    .ivars = 0,
    .weakIvarLayout = 0,
    .baseProperties = 0,
};

const nsautoreleasepool_ro: objc.ClassRoT = .{
    .flags = 0,
    .instanceStart = @sizeOf(usize),
    .instanceSize = @sizeOf(NSAutoreleasePoolObject),
    .reserved = 0,
    .ivarLayout = 0,
    .name = "NSAutoreleasePool",
    .baseMethodList = &nsautoreleasepool_inst_methods.header,
    .baseProtocols = 0,
    .ivars = 0,
    .weakIvarLayout = 0,
    .baseProperties = 0,
};

pub var OBJC_METACLASS_NSAutoreleasePool: objc.ObjcClass = .{ .isa = 0, .superclass = 0, .cache_buckets = 0, .cache_mask_vtable = 0, .bits = 0 };
pub var OBJC_CLASS_NSAutoreleasePool: objc.ObjcClass = .{ .isa = 0, .superclass = 0, .cache_buckets = 0, .cache_mask_vtable = 0, .bits = 0 };

// ============================================================================
// Class Hierarchy Wiring & Registration
// ============================================================================

var foundation_initialized: bool = false;

fn wireClass(
    cls: *objc.ObjcClass,
    meta: *objc.ObjcClass,
    super_cls: ?*objc.ObjcClass,
    super_meta: ?*objc.ObjcClass,
    cls_ro: *const objc.ClassRoT,
    meta_ro: *const objc.ClassRoT,
) void {
    meta.isa = @intFromPtr(&OBJC_METACLASS_NSObject);
    meta.superclass = if (super_meta) |sm| @intFromPtr(sm) else @intFromPtr(&OBJC_CLASS_NSObject);
    meta.bits = @intFromPtr(meta_ro);

    cls.isa = @intFromPtr(meta);
    cls.superclass = if (super_cls) |sc| @intFromPtr(sc) else 0;
    cls.bits = @intFromPtr(cls_ro);

    objc.registerClass(cls);
}

pub fn ensureInitialized() void {
    if (foundation_initialized) return;
    foundation_initialized = true;

    nsobject_meta_methods.methods = .{
        m("alloc", "@16@0:8", &nsObjectAlloc),
        m("new", "@16@0:8", &nsObjectNew),
        m("class", "#16@0:8", &nsObjectClassSelf),
        m("superclass", "#16@0:8", &nsObjectClassSuperclass),
        m("instancesRespondToSelector:", "B24@0:8:16", &nsObjectInstancesRespondToSelector),
        m("isSubclassOfClass:", "B24@0:8#16", &nsObjectIsSubclassOfClass),
    };
    nsobject_inst_methods.methods = .{
        m("init", "@16@0:8", &nsObjectInit),
        m("dealloc", "v16@0:8", &nsObjectDealloc),
        m("retain", "@16@0:8", &nsObjectRetain),
        m("release", "v16@0:8", &nsObjectRelease),
        m("autorelease", "@16@0:8", &nsObjectAutorelease),
        m("retainCount", "Q16@0:8", &nsObjectRetainCount),
        m("class", "#16@0:8", &nsObjectInstanceClass),
        m("superclass", "#16@0:8", &nsObjectInstanceSuperclass),
        m("isKindOfClass:", "B24@0:8#16", &nsObjectIsKindOfClass),
        m("isMemberOfClass:", "B24@0:8#16", &nsObjectIsMemberOfClass),
        m("respondsToSelector:", "B24@0:8:16", &nsObjectRespondsToSelector),
        m("isEqual:", "B24@0:8@16", &nsObjectIsEqual),
        m("hash", "Q16@0:8", &nsObjectHash),
        m("description", "@16@0:8", &nsObjectDescription),
    };

    nsstring_meta_methods.methods = .{
        m("string", "@16@0:8", &nsStringClassEmpty),
        m("stringWithUTF8String:", "@24@0:8*16", &nsStringWithUTF8String),
        m("stringWithCString:encoding:", "@32@0:8*16Q24", &nsStringWithCStringEncoding),
        m("stringWithString:", "@24@0:8@16", &nsStringWithString),
        m("stringWithFormat:", "@24@0:8@16", &nsStringWithFormat),
    };
    nsstring_inst_methods.methods = .{
        m("initWithUTF8String:", "@24@0:8*16", &nsStringInitWithUTF8String),
        m("initWithCString:encoding:", "@32@0:8*16Q24", &nsStringInitWithCStringEncoding),
        m("initWithString:", "@24@0:8@16", &nsStringInitWithString),
        m("dealloc", "v16@0:8", &nsStringDealloc),
        m("length", "Q16@0:8", &nsStringLength),
        m("UTF8String", "*16@0:8", &nsStringUTF8String),
        m("cStringUsingEncoding:", "*24@0:8Q16", &nsStringCStringUsingEncoding),
        m("isEqualToString:", "B24@0:8@16", &nsStringIsEqualToString),
        m("isEqual:", "B24@0:8@16", &nsStringIsEqual),
        m("hash", "Q16@0:8", &nsStringHash),
        m("description", "@16@0:8", &nsStringDescription),
        m("stringByAppendingString:", "@24@0:8@16", &nsStringByAppendingString),
        m("hasPrefix:", "B24@0:8@16", &nsStringHasPrefix),
        m("hasSuffix:", "B24@0:8@16", &nsStringHasSuffix),
        m("containsString:", "B24@0:8@16", &nsStringContainsString),
        m("intValue", "i16@0:8", &nsStringIntValue),
        m("integerValue", "q16@0:8", &nsStringIntegerValue),
        m("dataUsingEncoding:", "@24@0:8Q16", &nsStringDataUsingEncoding),
    };

    nsdata_meta_methods.methods = .{
        m("data", "@16@0:8", &nsDataClassEmpty),
        m("dataWithBytes:length:", "@32@0:8r^v16Q24", &nsDataWithBytesLength),
        m("dataWithBytesNoCopy:length:", "@32@0:8^v16Q24", &nsDataWithBytesNoCopyLength),
        m("dataWithBytesNoCopy:length:freeWhenDone:", "@36@0:8^v16Q24B32", &nsDataWithBytesNoCopyLengthFree),
    };
    nsdata_inst_methods.methods = .{
        m("initWithBytes:length:", "@32@0:8r^v16Q24", &nsDataInitWithBytesLength),
        m("dealloc", "v16@0:8", &nsDataDealloc),
        m("length", "Q16@0:8", &nsDataLength),
        m("bytes", "^v16@0:8", &nsDataBytes),
        m("isEqualToData:", "B24@0:8@16", &nsDataIsEqualToData),
        m("isEqual:", "B24@0:8@16", &nsDataIsEqual),
        m("subdataWithRange:", "@32@0:8{_NSRange=QQ}16", &nsDataSubdataWithRange),
        m("description", "@16@0:8", &nsDataDescription),
    };

    nsarray_meta_methods.methods = .{
        m("array", "@16@0:8", &nsArrayEmpty),
        m("arrayWithObject:", "@24@0:8@16", &nsArrayWithObject),
        m("arrayWithObjects:", "@24@0:8@16", &nsArrayWithObjectsVarargs),
        m("arrayWithObjects:count:", "@32@0:8r^@16Q24", &nsArrayWithObjectsCount),
    };
    nsarray_inst_methods.methods = .{
        m("initWithObjects:count:", "@32@0:8r^@16Q24", &nsArrayInitWithObjectsCount),
        m("dealloc", "v16@0:8", &nsArrayDealloc),
        m("count", "Q16@0:8", &nsArrayCount),
        m("objectAtIndex:", "@24@0:8Q16", &nsArrayObjectAtIndex),
        m("objectAtIndexedSubscript:", "@24@0:8Q16", &nsArrayObjectAtIndex),
        m("firstObject", "@16@0:8", &nsArrayFirstObject),
        m("lastObject", "@16@0:8", &nsArrayLastObject),
        m("containsObject:", "B24@0:8@16", &nsArrayContainsObject),
        m("indexOfObject:", "Q24@0:8@16", &nsArrayIndexOfObject),
        m("componentsJoinedByString:", "@24@0:8@16", &nsArrayComponentsJoinedByString),
        m("description", "@16@0:8", &nsArrayDescription),
        m("countByEnumeratingWithState:objects:count:", "Q40@0:8^{?=Q^@^Q[5Q]}16^@24Q32", &nsArrayCountByEnumerating),
    };

    nsmutablearray_meta_methods.methods = .{
        m("arrayWithCapacity:", "@24@0:8Q16", &nsMutableArrayWithCapacity),
    };
    nsmutablearray_inst_methods.methods = .{
        m("initWithCapacity:", "@24@0:8Q16", &nsMutableArrayInitWithCapacity),
        m("addObject:", "v24@0:8@16", &nsMutableArrayAddObject),
        m("removeLastObject", "v16@0:8", &nsMutableArrayRemoveLastObject),
        m("removeObjectAtIndex:", "v24@0:8Q16", &nsMutableArrayRemoveObjectAtIndex),
        m("removeAllObjects", "v16@0:8", &nsMutableArrayRemoveAllObjects),
    };

    nsautoreleasepool_inst_methods.methods = .{
        m("init", "@16@0:8", &nsAutoreleasePoolInit),
        m("drain", "v16@0:8", &nsAutoreleasePoolDrain),
        m("release", "v16@0:8", &nsAutoreleasePoolDrain),
        m("dealloc", "v16@0:8", &nsAutoreleasePoolDealloc),
    };

    wireClass(&OBJC_CLASS_NSObject, &OBJC_METACLASS_NSObject, null, null, &nsobject_ro, &nsobject_meta_ro);
    wireClass(&OBJC_CLASS_NSString, &OBJC_METACLASS_NSString, &OBJC_CLASS_NSObject, &OBJC_METACLASS_NSObject, &nsstring_ro, &nsstring_meta_ro);
    wireClass(&OBJC_CLASS_NSConstantString, &OBJC_METACLASS_NSConstantString, &OBJC_CLASS_NSString, &OBJC_METACLASS_NSString, &nsconststring_ro, &nsconststring_meta_ro);
    wireClass(&OBJC_CLASS_NSData, &OBJC_METACLASS_NSData, &OBJC_CLASS_NSObject, &OBJC_METACLASS_NSObject, &nsdata_ro, &nsdata_meta_ro);
    wireClass(&OBJC_CLASS_NSArray, &OBJC_METACLASS_NSArray, &OBJC_CLASS_NSObject, &OBJC_METACLASS_NSObject, &nsarray_ro, &nsarray_meta_ro);
    wireClass(&OBJC_CLASS_NSMutableArray, &OBJC_METACLASS_NSMutableArray, &OBJC_CLASS_NSArray, &OBJC_METACLASS_NSArray, &nsmutablearray_ro, &nsmutablearray_meta_ro);
    wireClass(&OBJC_CLASS_NSAutoreleasePool, &OBJC_METACLASS_NSAutoreleasePool, &OBJC_CLASS_NSObject, &OBJC_METACLASS_NSObject, &nsautoreleasepool_ro, &nsautoreleasepool_meta_ro);
}
