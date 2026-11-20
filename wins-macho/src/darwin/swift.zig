const std = @import("std");
const trace = @import("../runtime/trace.zig");
const objc = @import("objc.zig");

extern "c" fn posix_memalign(memptr: *?*anyopaque, alignment: usize, size: usize) c_int;
extern "c" fn memset(s: *anyopaque, c: c_int, n: usize) *anyopaque;
extern "c" fn memcpy(dst: *anyopaque, src: *const anyopaque, n: usize) *anyopaque;
extern "c" fn free(ptr: ?*anyopaque) void;
extern "c" fn write(fd: c_int, buf: ?*const anyopaque, count: usize) isize;
extern "c" fn abort() noreturn;

pub const HeapObject = extern struct {
    metadata: usize,
    refCounts: u64,
};

var swift_refcounts: std.AutoHashMapUnmanaged(usize, usize) = .{};

pub fn shim_swift_allocObject(metadata: usize, required_size: usize, required_alignment_mask: usize) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_swift_allocObject");
    const align_val = @max(required_alignment_mask + 1, @sizeOf(usize));
    const alloc_size = @max(required_size, @sizeOf(HeapObject));
    var ptr: ?*anyopaque = null;
    if (posix_memalign(&ptr, align_val, alloc_size) != 0) return null;
    const obj = ptr orelse return null;
    _ = memset(obj, 0, alloc_size);
    const heap_obj: *HeapObject = @ptrCast(@alignCast(obj));
    heap_obj.metadata = metadata;
    heap_obj.refCounts = 1;
    swift_refcounts.put(std.heap.c_allocator, @intFromPtr(obj), 1) catch {};
    return obj;
}

pub fn shim_swift_retain(obj: ?*anyopaque) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_swift_retain");
    const ptr = obj orelse return null;
    if (swift_refcounts.getPtr(@intFromPtr(ptr))) |cnt| {
        cnt.* +|= 1;
    }
    return ptr;
}

pub fn shim_swift_release(obj: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_swift_release");
    const ptr = obj orelse return;
    const addr = @intFromPtr(ptr);
    if (swift_refcounts.getPtr(addr)) |cnt| {
        if (cnt.* > 1) {
            cnt.* -= 1;
            return;
        }
        _ = swift_refcounts.remove(addr);
        free(ptr);
    }
}

pub fn shim_swift_retainCount(obj: ?*anyopaque) callconv(.c) usize {
    if (trace.active_tracer) |t| t.recordExternalCall("_swift_retainCount");
    const ptr = obj orelse return 0;
    return swift_refcounts.get(@intFromPtr(ptr)) orelse 1;
}

pub fn shim_swift_deallocObject(obj: ?*anyopaque, allocated_size: usize, allocated_align_mask: usize) callconv(.c) void {
    _ = allocated_size;
    _ = allocated_align_mask;
    if (trace.active_tracer) |t| t.recordExternalCall("_swift_deallocObject");
    const ptr = obj orelse return;
    _ = swift_refcounts.remove(@intFromPtr(ptr));
    free(ptr);
}

pub fn shim_swift_deallocClassInstance(obj: ?*anyopaque, allocated_size: usize, allocated_align_mask: usize) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_swift_deallocClassInstance");
    shim_swift_deallocObject(obj, allocated_size, allocated_align_mask);
}

pub fn shim_swift_once(predicate: *isize, fn_ptr: *const fn (?*anyopaque) callconv(.c) void, context: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_swift_once");
    if (@atomicLoad(isize, predicate, .acquire) == -1) return;
    if (@cmpxchgStrong(isize, predicate, 0, -1, .seq_cst, .acquire) == null) {
        fn_ptr(context);
    }
}

pub fn shim_swift_beginAccess(pointer: ?*anyopaque, buffer: ?*anyopaque, flags: usize, pc: ?*anyopaque) callconv(.c) void {
    _ = pointer;
    _ = buffer;
    _ = flags;
    _ = pc;
    if (trace.active_tracer) |t| t.recordExternalCall("_swift_beginAccess");
}

pub fn shim_swift_endAccess(buffer: ?*anyopaque) callconv(.c) void {
    _ = buffer;
    if (trace.active_tracer) |t| t.recordExternalCall("_swift_endAccess");
}

pub fn shim_swift_bridgeObjectRetain(obj: ?*anyopaque) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_swift_bridgeObjectRetain");
    return obj;
}

pub fn shim_swift_bridgeObjectRelease(obj: ?*anyopaque) callconv(.c) void {
    _ = obj;
    if (trace.active_tracer) |t| t.recordExternalCall("_swift_bridgeObjectRelease");
}

pub fn shim_swift_unknownObjectRetain(obj: ?*anyopaque) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_swift_unknownObjectRetain");
    const ptr = obj orelse return null;
    if (swift_refcounts.contains(@intFromPtr(ptr))) {
        return shim_swift_retain(ptr);
    }
    return objc.shim_objc_retain(ptr);
}

pub fn shim_swift_unknownObjectRelease(obj: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_swift_unknownObjectRelease");
    const ptr = obj orelse return;
    if (swift_refcounts.contains(@intFromPtr(ptr))) {
        shim_swift_release(ptr);
        return;
    }
    objc.shim_objc_release(ptr);
}

pub fn shim_swift_getObjectType(obj: ?*anyopaque) callconv(.c) usize {
    if (trace.active_tracer) |t| t.recordExternalCall("_swift_getObjectType");
    const ptr = obj orelse return 0;
    return @as(*const usize, @ptrCast(@alignCast(ptr))).*;
}

pub fn shim_swift_deletedMethodError() callconv(.c) noreturn {
    std.debug.print("WINS-SWIFT: fatal error: call to deleted method\n", .{});
    abort();
}

// ============================================================================
// Swift Stdlib ABI: Boxes, Batch Refcounts, Errors, Metadata, String, Array
// ============================================================================

pub const BoxPair = extern struct {
    buffer: ?*anyopaque,
    value: ?*anyopaque,
};

pub const ValueWitnessTable = extern struct {
    initializeBufferWithCopyOfBuffer: usize = 0,
    destroy: usize = 0,
    initializeWithCopy: usize = 0,
    assignWithCopy: usize = 0,
    initializeWithTake: usize = 0,
    assignWithTake: usize = 0,
    getEnumTagSinglePayload: usize = 0,
    storeEnumTagSinglePayload: usize = 0,
    size: usize,
    stride: usize,
    flags: u32,
    extraInhabitantCount: u32 = 0,
};

pub const TypeMetadata = extern struct {
    vwt: *const ValueWitnessTable,
    kind: usize,
};

pub const swift_vwt_int: ValueWitnessTable = .{ .size = @sizeOf(isize), .stride = @sizeOf(isize), .flags = 0x0000_0007 };
pub const swift_vwt_bool: ValueWitnessTable = .{ .size = 1, .stride = 1, .flags = 0x0000_0000, .extraInhabitantCount = 254 };
pub const swift_vwt_string: ValueWitnessTable = .{ .size = 16, .stride = 16, .flags = 0x0000_0007 };
pub const swift_vwt_void: ValueWitnessTable = .{ .size = 0, .stride = 1, .flags = 0x0000_0000 };

pub const swift_meta_int: TypeMetadata = .{ .vwt = &swift_vwt_int, .kind = 0x200 }; // Struct
pub const swift_meta_uint: TypeMetadata = .{ .vwt = &swift_vwt_int, .kind = 0x200 };
pub const swift_meta_bool: TypeMetadata = .{ .vwt = &swift_vwt_bool, .kind = 0x200 };
pub const swift_meta_string: TypeMetadata = .{ .vwt = &swift_vwt_string, .kind = 0x200 };
pub const swift_meta_void: TypeMetadata = .{ .vwt = &swift_vwt_void, .kind = 0x301 }; // Tuple(0)
pub const swift_meta_any: TypeMetadata = .{ .vwt = &swift_vwt_string, .kind = 0x303 }; // Existential

pub fn shim_swift_retain_n(obj: ?*anyopaque, n: u32) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_swift_retain_n");
    const ptr = obj orelse return null;
    if (swift_refcounts.getPtr(@intFromPtr(ptr))) |cnt| {
        cnt.* +|= n;
    }
    return ptr;
}

pub fn shim_swift_release_n(obj: ?*anyopaque, n: u32) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_swift_release_n");
    const ptr = obj orelse return;
    const addr = @intFromPtr(ptr);
    if (swift_refcounts.getPtr(addr)) |cnt| {
        if (cnt.* > n) {
            cnt.* -= n;
            return;
        }
        _ = swift_refcounts.remove(addr);
        free(ptr);
    }
}

pub fn shim_swift_allocBox(metadata: ?*const TypeMetadata) callconv(.c) BoxPair {
    if (trace.active_tracer) |t| t.recordExternalCall("_swift_allocBox");
    const val_size: usize = if (metadata) |m| @max(m.vwt.size, 8) else 16;
    const total = @sizeOf(HeapObject) + val_size;
    const box = shim_swift_allocObject(@intFromPtr(metadata), total, 7) orelse return .{ .buffer = null, .value = null };
    const val_ptr: *anyopaque = @ptrFromInt(@intFromPtr(box) + @sizeOf(HeapObject));
    return .{ .buffer = box, .value = val_ptr };
}

pub fn shim_swift_projectBox(box: ?*anyopaque) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_swift_projectBox");
    const ptr = box orelse return null;
    return @ptrFromInt(@intFromPtr(ptr) + @sizeOf(HeapObject));
}

pub fn shim_swift_errorRetain(err: ?*anyopaque) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_swift_errorRetain");
    return shim_swift_retain(err);
}

pub fn shim_swift_errorRelease(err: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_swift_errorRelease");
    shim_swift_release(err);
}

pub fn shim_swift_willThrow(err: ?*anyopaque) callconv(.c) void {
    _ = err;
    if (trace.active_tracer) |t| t.recordExternalCall("_swift_willThrow");
}

pub fn shim_swift_unexpectedError(err: ?*anyopaque, filename: ?[*:0]const u8, line: usize, col: usize) callconv(.c) noreturn {
    _ = err;
    _ = filename;
    _ = line;
    _ = col;
    std.debug.print("WINS-SWIFT: fatal error: unexpected error thrown\n", .{});
    abort();
}

pub const SwiftString = extern struct {
    w0: u64,
    w1: u64,
};

pub fn makeSwiftString(slice: []const u8) SwiftString {
    if (slice.len <= 15) {
        var bytes: [16]u8 = .{0} ** 16;
        if (slice.len > 0) @memcpy(bytes[0..slice.len], slice);
        bytes[15] = 0xE0 | @as(u8, @intCast(slice.len));
        return .{
            .w0 = std.mem.readInt(u64, bytes[0..8], .little),
            .w1 = std.mem.readInt(u64, bytes[8..16], .little),
        };
    }
    var buf_ptr: ?*anyopaque = null;
    if (posix_memalign(&buf_ptr, 8, slice.len + 1) != 0 or buf_ptr == null) {
        return .{ .w0 = 0, .w1 = 0xE000_0000_0000_0000 };
    }
    const dst: [*]u8 = @ptrCast(buf_ptr.?);
    _ = memcpy(buf_ptr.?, slice.ptr, slice.len);
    dst[slice.len] = 0;
    return .{
        .w0 = slice.len,
        .w1 = @intFromPtr(buf_ptr.?) | 0x8000_0000_0000_0000,
    };
}

pub fn swiftStringSlice(s: SwiftString, scratch: *[16]u8) []const u8 {
    const top_byte: u8 = @truncate(s.w1 >> 56);
    if ((top_byte & 0xE0) == 0xE0) {
        const len: usize = @intCast(top_byte & 0x0F);
        std.mem.writeInt(u64, scratch[0..8], s.w0, .little);
        std.mem.writeInt(u64, scratch[8..16], s.w1, .little);
        return scratch[0..@min(len, 15)];
    }
    const ptr_addr: usize = @intCast(s.w1 & 0x0000_FFFF_FFFF_FFFF);
    if (ptr_addr == 0) return "";
    const len: usize = @intCast(s.w0 & 0x0000_FFFF_FFFF_FFFF);
    const ptr: [*]const u8 = @ptrFromInt(ptr_addr);
    return ptr[0..len];
}

pub fn shim_swift_stringInitBuiltin(ptr: ?[*]const u8, count: usize, is_ascii: u8) callconv(.c) SwiftString {
    _ = is_ascii;
    if (trace.active_tracer) |t| t.recordExternalCall("_$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC");
    const p = ptr orelse return makeSwiftString("");
    return makeSwiftString(p[0..count]);
}

pub fn shim_swift_stringCount(s0: u64, s1: u64) callconv(.c) usize {
    if (trace.active_tracer) |t| t.recordExternalCall("_$sSS5countSivg");
    var scratch: [16]u8 = undefined;
    return swiftStringSlice(.{ .w0 = s0, .w1 = s1 }, &scratch).len;
}

pub fn shim_swift_stringEquals(a0: u64, a1: u64, b0: u64, b1: u64) callconv(.c) u8 {
    if (trace.active_tracer) |t| t.recordExternalCall("_$sSS2eeoiySbSS_SStFZ");
    var sa: [16]u8 = undefined;
    var sb: [16]u8 = undefined;
    return if (std.mem.eql(u8, swiftStringSlice(.{ .w0 = a0, .w1 = a1 }, &sa), swiftStringSlice(.{ .w0 = b0, .w1 = b1 }, &sb))) 1 else 0;
}

pub const SwiftArrayStorage = extern struct {
    header: HeapObject,
    count: usize,
    capacity: usize,
};

pub const ArrayAllocPair = extern struct {
    array: ?*anyopaque,
    elements: ?*anyopaque,
};

pub fn shim_swift_allocateUninitializedArray(count: usize, metadata: ?*const TypeMetadata) callconv(.c) ArrayAllocPair {
    if (trace.active_tracer) |t| t.recordExternalCall("_$ss27_allocateUninitializedArrayySayxG_BptBwlF");
    const elem_stride: usize = if (metadata) |m| @max(m.vwt.stride, 1) else 8;
    const total = @sizeOf(SwiftArrayStorage) + count * elem_stride;
    const storage_raw = shim_swift_allocObject(@intFromPtr(metadata), total, 7) orelse return .{ .array = null, .elements = null };
    const storage: *SwiftArrayStorage = @ptrCast(@alignCast(storage_raw));
    storage.count = count;
    storage.capacity = count;
    const elems: *anyopaque = @ptrFromInt(@intFromPtr(storage_raw) + @sizeOf(SwiftArrayStorage));
    return .{ .array = storage_raw, .elements = elems };
}

pub fn shim_swift_finalizeUninitializedArray(arr: ?*anyopaque) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("_$ss27_finalizeUninitializedArrayySayxGABnlF");
    return arr;
}

pub fn shim_swift_print(items_arr: ?*anyopaque, sep0: u64, sep1: u64, term0: u64, term1: u64) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_$ss5print_9separator10terminatoryypd_S2StF");
    var sep_scratch: [16]u8 = undefined;
    var term_scratch: [16]u8 = undefined;
    const sep = swiftStringSlice(.{ .w0 = sep0, .w1 = sep1 }, &sep_scratch);
    const term = swiftStringSlice(.{ .w0 = term0, .w1 = term1 }, &term_scratch);
    if (items_arr) |arr_ptr| {
        const storage: *const SwiftArrayStorage = @ptrCast(@alignCast(arr_ptr));
        const base = @intFromPtr(arr_ptr) + @sizeOf(SwiftArrayStorage);
        var i: usize = 0;
        while (i < storage.count) : (i += 1) {
            if (i > 0 and sep.len > 0) _ = write(1, sep.ptr, sep.len);
            // Existential container: [3 words payload, metadata ptr] = 32 bytes
            const exist_ptr: [*]const u64 = @ptrFromInt(base + i * 32);
            const meta_addr: usize = @intCast(exist_ptr[3]);
            if (meta_addr == @intFromPtr(&swift_meta_string)) {
                var s_scratch: [16]u8 = undefined;
                const slice = swiftStringSlice(.{ .w0 = exist_ptr[0], .w1 = exist_ptr[1] }, &s_scratch);
                if (slice.len > 0) _ = write(1, slice.ptr, slice.len);
            } else if (meta_addr == @intFromPtr(&swift_meta_int)) {
                var buf: [32]u8 = undefined;
                const val: i64 = @bitCast(exist_ptr[0]);
                const txt = std.fmt.bufPrint(&buf, "{d}", .{val}) catch "";
                if (txt.len > 0) _ = write(1, txt.ptr, txt.len);
            } else if (meta_addr == @intFromPtr(&swift_meta_bool)) {
                const txt = if ((exist_ptr[0] & 1) != 0) "true" else "false";
                _ = write(1, txt.ptr, txt.len);
            }
        }
    }
    if (term.len > 0) {
        _ = write(1, term.ptr, term.len);
    } else {
        _ = write(1, "\n", 1);
    }
}

// ============================================================================
// Swift Stdlib Unicode / Normalization Support (ASCII-safe fast path)
// ============================================================================

pub var swift_stdlib_nfd_decompositions: [4096]u8 = .{0} ** 4096;

pub fn shim_swift_stdlib_getNormData(scalar: u32) callconv(.c) u32 {
    _ = scalar;
    return 0;
}

pub fn shim_swift_stdlib_getGraphemeBreakProperty(scalar: u32) callconv(.c) u8 {
    _ = scalar;
    return 0;
}

pub fn shim_swift_stdlib_isExtendedPictographic(scalar: u32) callconv(.c) u8 {
    _ = scalar;
    return 0;
}

pub fn shim_swift_stdlib_isInCB_Consonant(scalar: u32) callconv(.c) u8 {
    _ = scalar;
    return 0;
}

pub fn shim_swift_stdlib_getComposition(x: u32, y: u32) callconv(.c) u32 {
    _ = x;
    _ = y;
    return 0xFFFFFFFF;
}

pub fn shim_swift_stdlib_getDecompositionEntry(scalar: u32) callconv(.c) u32 {
    _ = scalar;
    return 0;
}
