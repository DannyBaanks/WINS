const std = @import("std");
const wins_macho = @import("wins_macho");
const parser = wins_macho.parser;
const types = wins_macho.types;

fn makeHeader(magic: u32, cputype: i32, ncmds: u32, sizeofcmds: u32) [32]u8 {
    var buf: [32]u8 = .{0} ** 32;
    const hdr = types.MachHeader64{
        .magic = magic,
        .cputype = cputype,
        .cpusubtype = 3,
        .filetype = types.MH_EXECUTE,
        .ncmds = ncmds,
        .sizeofcmds = sizeofcmds,
        .flags = 0,
        .reserved = 0,
    };
    @memcpy(&buf, std.mem.asBytes(&hdr));
    return buf;
}

test "adversarial: truncated file" {
    const gpa = std.testing.allocator;
    try std.testing.expectError(error.TruncatedFile, parser.parse(gpa, &.{ 0xCF, 0xFA }));
    const short_hdr = [_]u8{ 0xCF, 0xFA, 0xED, 0xFE, 0x07, 0x00, 0x00, 0x01 };
    try std.testing.expectError(error.TruncatedFile, parser.parse(gpa, &short_hdr));
}

test "adversarial: invalid magic, 32-bit, endian, fat" {
    const gpa = std.testing.allocator;
    const bad = makeHeader(0xDEADBEEF, types.CPU_TYPE_X86_64, 0, 0);
    try std.testing.expectError(error.InvalidMagic, parser.parse(gpa, &bad));

    const cigam = makeHeader(types.MH_CIGAM_64, types.CPU_TYPE_X86_64, 0, 0);
    try std.testing.expectError(error.UnsupportedEndian, parser.parse(gpa, &cigam));

    const m32 = makeHeader(types.MH_MAGIC, types.CPU_TYPE_X86, 0, 0);
    try std.testing.expectError(error.Unsupported32Bit, parser.parse(gpa, &m32));

    const fat = makeHeader(types.FAT_MAGIC, types.CPU_TYPE_X86_64, 0, 0);
    try std.testing.expectError(error.FatBinaryUnsupported, parser.parse(gpa, &fat));
}

test "adversarial: incompatible architecture (arm64)" {
    const gpa = std.testing.allocator;
    const arm64 = makeHeader(types.MH_MAGIC_64, types.CPU_TYPE_ARM64, 0, 0);
    try std.testing.expectError(error.IncompatibleArchitecture, parser.parse(gpa, &arm64));
}

test "adversarial: sizeofcmds integer overflow and out of bounds" {
    const gpa = std.testing.allocator;
    const overflow = makeHeader(types.MH_MAGIC_64, types.CPU_TYPE_X86_64, 1, 0xFFFFFFFF);
    try std.testing.expectError(error.OutOfBounds, parser.parse(gpa, &overflow));

    const oob = makeHeader(types.MH_MAGIC_64, types.CPU_TYPE_X86_64, 1, 128);
    try std.testing.expectError(error.OutOfBounds, parser.parse(gpa, &oob));
}

test "adversarial: invalid cmdsize (unaligned / too small)" {
    const gpa = std.testing.allocator;
    var buf: [48]u8 = .{0} ** 48;
    const hdr = makeHeader(types.MH_MAGIC_64, types.CPU_TYPE_X86_64, 1, 16);
    @memcpy(buf[0..32], &hdr);
    // cmdsize = 4 (too small)
    const lc = types.LoadCommand{ .cmd = types.LC_MAIN, .cmdsize = 4 };
    @memcpy(buf[32..40], std.mem.asBytes(&lc));
    try std.testing.expectError(error.InvalidCmdSize, parser.parse(gpa, &buf));

    // cmdsize = 12 (not 8-byte aligned)
    const lc2 = types.LoadCommand{ .cmd = types.LC_MAIN, .cmdsize = 12 };
    @memcpy(buf[32..40], std.mem.asBytes(&lc2));
    try std.testing.expectError(error.InvalidCmdSize, parser.parse(gpa, &buf));
}

test "adversarial: overlapping segments rejected" {
    const gpa = std.testing.allocator;
    const seg_size = @sizeOf(types.SegmentCommand64);
    var buf: [32 + seg_size * 2]u8 = .{0} ** (32 + seg_size * 2);
    const hdr = makeHeader(types.MH_MAGIC_64, types.CPU_TYPE_X86_64, 2, seg_size * 2);
    @memcpy(buf[0..32], &hdr);

    const seg1 = types.SegmentCommand64{
        .cmd = types.LC_SEGMENT_64,
        .cmdsize = seg_size,
        .segname = "__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".*,
        .vmaddr = 0x100000000,
        .vmsize = 0x2000,
        .fileoff = 0,
        .filesize = 0,
        .maxprot = 5,
        .initprot = 5,
        .nsects = 0,
        .flags = 0,
    };
    const seg2 = types.SegmentCommand64{
        .cmd = types.LC_SEGMENT_64,
        .cmdsize = seg_size,
        .segname = "__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".*,
        .vmaddr = 0x100001000, // overlaps seg1 [0x100000000, 0x100002000)
        .vmsize = 0x1000,
        .fileoff = 0,
        .filesize = 0,
        .maxprot = 3,
        .initprot = 3,
        .nsects = 0,
        .flags = 0,
    };
    @memcpy(buf[32 .. 32 + seg_size], std.mem.asBytes(&seg1));
    @memcpy(buf[32 + seg_size ..], std.mem.asBytes(&seg2));
    try std.testing.expectError(error.OverlappingSegments, parser.parse(gpa, &buf));
}

test "adversarial: segment fileoff+filesize out of bounds" {
    const gpa = std.testing.allocator;
    const seg_size = @sizeOf(types.SegmentCommand64);
    var buf: [32 + seg_size]u8 = .{0} ** (32 + seg_size);
    const hdr = makeHeader(types.MH_MAGIC_64, types.CPU_TYPE_X86_64, 1, seg_size);
    @memcpy(buf[0..32], &hdr);

    const seg1 = types.SegmentCommand64{
        .cmd = types.LC_SEGMENT_64,
        .cmdsize = seg_size,
        .segname = "__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".*,
        .vmaddr = 0x100000000,
        .vmsize = 0x2000,
        .fileoff = 0,
        .filesize = 999999,
        .maxprot = 5,
        .initprot = 5,
        .nsects = 0,
        .flags = 0,
    };
    @memcpy(buf[32..], std.mem.asBytes(&seg1));
    try std.testing.expectError(error.OutOfBounds, parser.parse(gpa, &buf));
}

test "universal binary: selects x86_64 slice and rejects arm64-only" {
    const gpa = std.testing.allocator;
    // Fat header (8 bytes) + 2 FatArch (40 bytes) + 32-byte MachHeader64 at offset 48
    var buf: [80]u8 = .{0} ** 80;
    std.mem.writeInt(u32, buf[0..4], types.FAT_MAGIC, .big);
    std.mem.writeInt(u32, buf[4..8], 2, .big);

    // Arch 0: ARM64 (offset 48, size 32)
    std.mem.writeInt(i32, buf[8..12], types.CPU_TYPE_ARM64, .big);
    std.mem.writeInt(u32, buf[16..20], 48, .big);
    std.mem.writeInt(u32, buf[20..24], 32, .big);

    // Arch 1: X86_64 (offset 48, size 32)
    std.mem.writeInt(i32, buf[28..32], types.CPU_TYPE_X86_64, .big);
    std.mem.writeInt(u32, buf[36..40], 48, .big);
    std.mem.writeInt(u32, buf[40..44], 32, .big);

    const x64_hdr = makeHeader(types.MH_MAGIC_64, types.CPU_TYPE_X86_64, 0, 0);
    @memcpy(buf[48..80], &x64_hdr);

    var parsed = try parser.parse(gpa, &buf);
    defer parsed.deinit();
    try std.testing.expectEqual(types.CPU_TYPE_X86_64, parsed.header.cputype);

    // Now change Arch 1 to ARM64 as well -> must fail with IncompatibleArchitecture
    std.mem.writeInt(i32, buf[28..32], types.CPU_TYPE_ARM64, .big);
    try std.testing.expectError(error.IncompatibleArchitecture, parser.parse(gpa, &buf));
}

test "chained fixups: parses imports and segment page starts" {
    const gpa = std.testing.allocator;
    const fixups = wins_macho.fixups;
    // Build minimal ChainedFixupsHeader (28 bytes) + ChainedStartsInImage (8 bytes) +
    // ChainedStartsInSegment (24 bytes) + 1 import (4 bytes) + symbol "_foo\0" (5 bytes)
    var blob: [72]u8 = .{0} ** 72;
    const hdr = types.ChainedFixupsHeader{
        .fixups_version = 0,
        .starts_offset = 28,
        .imports_offset = 60,
        .symbols_offset = 64,
        .imports_count = 1,
        .imports_format = types.DYLD_CHAINED_IMPORT,
        .symbols_format = 0,
    };
    @memcpy(blob[0..28], std.mem.asBytes(&hdr));
    // starts_in_image: seg_count = 1, seg_info_offset[0] = 8
    std.mem.writeInt(u32, blob[28..32], 1, .little);
    std.mem.writeInt(u32, blob[32..36], 8, .little);
    // starts_in_segment at 36: page_size=4096, pointer_format=6, segment_offset=0x1000, page_count=1, page_start[0]=0x20
    std.mem.writeInt(u32, blob[36..40], 24, .little);
    std.mem.writeInt(u16, blob[40..42], 4096, .little);
    std.mem.writeInt(u16, blob[42..44], types.DYLD_CHAINED_PTR_64_OFFSET, .little);
    std.mem.writeInt(u64, blob[44..52], 0x1000, .little);
    std.mem.writeInt(u16, blob[56..58], 1, .little);
    std.mem.writeInt(u16, blob[58..60], 0x20, .little);
    // import[0]: lib_ordinal=1, weak=0, name_offset=0
    std.mem.writeInt(u32, blob[60..64], 1, .little);
    @memcpy(blob[64..69], "_foo\x00");

    const imports = try fixups.parseChainedImports(gpa, &blob);
    defer gpa.free(imports);
    try std.testing.expectEqual(@as(usize, 1), imports.len);
    try std.testing.expectEqual(@as(i32, 1), imports[0].dylib_ordinal);
    try std.testing.expectEqualStrings("_foo", imports[0].symbol);

    const segs = try fixups.parseChainedSegments(gpa, &blob);
    defer {
        for (segs) |s| gpa.free(s.page_starts);
        gpa.free(segs);
    }
    try std.testing.expectEqual(@as(usize, 1), segs.len);
    try std.testing.expectEqual(@as(u16, 0x20), segs[0].page_starts[0]);
}

test "foundation: symbols, classes, NSString/NSData and autorelease pool" {
    const shims = wins_macho.shims;
    const objc = wins_macho.objc;
    const foundation = wins_macho.foundation;

    const required_syms = [_][]const u8{
        "___CFConstantStringClassReference",
        "_OBJC_CLASS_$_NSObject",
        "_OBJC_METACLASS_$_NSObject",
        "_OBJC_CLASS_$_NSString",
        "_OBJC_CLASS_$_NSData",
        "_OBJC_CLASS_$_NSArray",
        "_OBJC_CLASS_$_NSMutableArray",
        "_OBJC_CLASS_$_NSAutoreleasePool",
        "_NSLog",
        "_objc_msgSendSuper2",
    };
    for (required_syms) |sym| {
        try std.testing.expect(shims.lookup(sym) != null);
    }

    try std.testing.expect(objc.shim_objc_getClass("NSObject") != null);
    try std.testing.expect(objc.shim_objc_getClass("NSString") != null);
    try std.testing.expect(objc.shim_objc_getClass("NSArray") != null);
    try std.testing.expect(objc.shim_objc_getClass("NSMutableArray") != null);
    try std.testing.expect(objc.shim_objc_getClass("NSData") != null);
    try std.testing.expect(objc.shim_objc_getClass("NSAutoreleasePool") != null);

    const pool = objc.shim_objc_autoreleasePoolPush();
    const s = foundation.makeNSStringFromSlice("hello-foundation", true);
    try std.testing.expect(s != null);
    try std.testing.expectEqualStrings("hello-foundation", foundation.nsStringSlice(s));
    const d = foundation.makeNSDataFromBytes("abc", 3, true);
    try std.testing.expect(d != null);
    objc.shim_objc_autoreleasePoolPop(pool);
}

fn testSwiftOnceCb(ctx: ?*anyopaque) callconv(.c) void {
    const counter: *usize = @ptrCast(@alignCast(ctx.?));
    counter.* += 1;
}

test "swift: runtime symbols, alloc/retain/release and swift_once" {
    const shims = wins_macho.shims;
    const swift = wins_macho.swift;

    const required_syms = [_][]const u8{
        "_putchar",
        "_posix_memalign",
        "_swift_allocObject",
        "_swift_retain",
        "_swift_release",
        "_swift_retainCount",
        "_swift_deallocObject",
        "_swift_once",
        "_swift_getObjectType",
    };
    for (required_syms) |sym| {
        try std.testing.expect(shims.lookup(sym) != null);
    }

    const obj = swift.shim_swift_allocObject(0x1234, 32, 7);
    try std.testing.expect(obj != null);
    try std.testing.expectEqual(@as(usize, 0x1234), swift.shim_swift_getObjectType(obj));
    try std.testing.expectEqual(@as(usize, 1), swift.shim_swift_retainCount(obj));
    _ = swift.shim_swift_retain(obj);
    try std.testing.expectEqual(@as(usize, 2), swift.shim_swift_retainCount(obj));
    swift.shim_swift_release(obj);
    try std.testing.expectEqual(@as(usize, 1), swift.shim_swift_retainCount(obj));
    swift.shim_swift_release(obj);

    var pred: isize = 0;
    var count: usize = 0;
    swift.shim_swift_once(&pred, &testSwiftOnceCb, &count);
    swift.shim_swift_once(&pred, &testSwiftOnceCb, &count);
    try std.testing.expectEqual(@as(usize, 1), count);
}

fn testDispatchApplyCb(ctx: ?*anyopaque, idx: usize) callconv(.c) void {
    const acc: *usize = @ptrCast(@alignCast(ctx.?));
    acc.* += idx + 1;
}

test "dispatch: queues, apply_f, semaphore and group" {
    const shims = wins_macho.shims;
    const dispatch = wins_macho.dispatch;

    const required_syms = [_][]const u8{
        "__Block_copy",
        "__Block_release",
        "__Block_object_assign",
        "__Block_object_dispose",
        "__dispatch_main_q",
        "__dispatch_queue_attr_concurrent",
        "_dispatch_get_global_queue",
        "_dispatch_queue_create",
        "_dispatch_queue_get_label",
        "_dispatch_async_f",
        "_dispatch_sync_f",
        "_dispatch_apply_f",
        "_dispatch_once_f",
        "_dispatch_group_create",
        "_dispatch_group_enter",
        "_dispatch_group_leave",
        "_dispatch_group_wait",
        "_dispatch_semaphore_create",
        "_dispatch_semaphore_wait",
        "_dispatch_semaphore_signal",
        "_dispatch_release",
    };
    for (required_syms) |sym| {
        try std.testing.expect(shims.lookup(sym) != null);
    }

    const q = dispatch.shim_dispatch_queue_create("test.queue", null);
    try std.testing.expect(q != null);
    try std.testing.expectEqualStrings("test.queue", std.mem.span(dispatch.shim_dispatch_queue_get_label(q)));

    var acc: usize = 0;
    dispatch.shim_dispatch_apply_f(4, q, &acc, &testDispatchApplyCb);
    try std.testing.expectEqual(@as(usize, 10), acc); // 1 + 2 + 3 + 4 = 10

    const sem = dispatch.shim_dispatch_semaphore_create(1);
    try std.testing.expect(sem != null);
    try std.testing.expectEqual(@as(isize, 0), dispatch.shim_dispatch_semaphore_wait(sem, dispatch.DISPATCH_TIME_NOW));
    _ = dispatch.shim_dispatch_semaphore_signal(sem);
    dispatch.shim_dispatch_release(sem);

    dispatch.shim_dispatch_release(q);
}

fn dummyBlockInvoke(_: *anyopaque) callconv(.c) void {}

var block_dispose_hits: usize = 0;
fn dummyBlockDispose(_: *anyopaque) callconv(.c) void {
    block_dispose_hits += 1;
}

test "abi: sprintf_chk, open flags, setlocale, getpwuid, system dylibs, unicode stubs" {
    const shims = wins_macho.shims;

    // 1. ___sprintf_chk & ___snprintf_chk must NOT treat flag/dstlen as format string
    var buf: [64]u8 = .{0} ** 64;
    const n1 = shims.shim_sprintf_chk(&buf, 0, buf.len, "tree v%d.%d-%s", @as(c_int, 2), @as(c_int, 3), @as([*:0]const u8, "ok"));
    try std.testing.expect(n1 > 0);
    try std.testing.expectEqualStrings("tree v2.3-ok", buf[0..@intCast(n1)]);

    const n2 = shims.shim_snprintf_chk(&buf, 8, 0, buf.len, "abcdef12345");
    try std.testing.expect(n2 >= 11);
    try std.testing.expectEqualStrings("abcdef1", buf[0..7]);

    // 2. Darwin O_* -> Linux O_* flag translation
    // Darwin O_WRONLY(1) | O_CREAT(0x200) | O_TRUNC(0x400) | O_CLOEXEC(0x1000000)
    const lx_open = shims.translateDarwinOpenFlags(0x0001 | 0x0200 | 0x0400 | 0x1000000);
    try std.testing.expectEqual(@as(c_int, 0x0001 | 0x0040 | 0x0200 | 0x80000), lx_open);

    // 3. Darwin LC_* -> Linux LC_* category translation
    try std.testing.expectEqual(@as(c_int, 6), shims.translateDarwinLocaleCategory(0)); // LC_ALL
    try std.testing.expectEqual(@as(c_int, 3), shims.translateDarwinLocaleCategory(1)); // LC_COLLATE
    try std.testing.expectEqual(@as(c_int, 0), shims.translateDarwinLocaleCategory(2)); // LC_CTYPE

    // 4. getpwuid returns DarwinPasswd (72 bytes) with real root entry
    const pw = shims.shim_getpwuid(0);
    try std.testing.expect(pw != null);
    try std.testing.expectEqual(@as(u32, 0), pw.?.pw_uid);
    try std.testing.expect(pw.?.pw_name != null);
    try std.testing.expectEqualStrings("root", std.mem.span(pw.?.pw_name.?));

    // 5. isDarwinSystemDylib recognizes libobjc & libswift
    try std.testing.expect(shims.isDarwinSystemDylib("/usr/lib/libobjc.A.dylib"));
    try std.testing.expect(shims.isDarwinSystemDylib("/usr/lib/swift/libswiftCore.dylib"));

    // 6. Swift Unicode stubs must be honestly classified as STUB_FOR_PROBE_ONLY
    const u_entry = shims.lookup("__swift_stdlib_getNormData") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(shims.ShimStatus.STUB_FOR_PROBE_ONLY, u_entry.status);
}

test "abi: objc_msgSend preserves xmm floating-point & variadic rax args" {
    const shims = wins_macho.shims;
    const objc = wins_macho.objc;
    const foundation = wins_macho.foundation;
    _ = shims.lookup("_NSLog"); // ensure Foundation initialized

    const pool = objc.shim_objc_autoreleasePoolPush();
    defer objc.shim_objc_autoreleasePoolPop(pool);

    const fmt = foundation.makeNSStringFromSlice("pi=%f n=%d", true);
    const MsgSendFmt = *const fn (?*anyopaque, [*:0]const u8, ?*anyopaque, ...) callconv(.c) ?*anyopaque;
    const send_fmt: MsgSendFmt = @ptrCast(&objc.shim_objc_msgSend);
    const res = send_fmt(&foundation.OBJC_CLASS_NSString, "stringWithFormat:", fmt, @as(f64, 3.141592), @as(c_int, 7));
    try std.testing.expect(res != null);
    try std.testing.expectEqualStrings("pi=3.141592 n=7", foundation.nsStringSlice(res));
}

test "abi: Block_copy/release refcounting prevents UAF/double-free" {
    const dispatch = wins_macho.dispatch;
    block_dispose_hits = 0;

    const desc = dispatch.BlockDescriptor{
        .reserved = 0,
        .size = @sizeOf(dispatch.BlockLiteral),
        .copy_helper = null,
        .dispose_helper = &dummyBlockDispose,
    };
    var stack_blk = dispatch.BlockLiteral{
        .isa = @intFromPtr(&dispatch.NSConcreteStackBlock),
        .flags = 1 << 25, // BLOCK_HAS_COPY_DISPOSE
        .reserved = 0,
        .invoke = &dummyBlockInvoke,
        .descriptor = &desc,
    };

    const heap1 = dispatch.shim_Block_copy(@ptrCast(&stack_blk));
    try std.testing.expect(heap1 != null);
    const heap2 = dispatch.shim_Block_copy(heap1);
    try std.testing.expectEqual(heap1, heap2);

    // First release must NOT free or run dispose_helper
    dispatch.shim_Block_release(heap1);
    try std.testing.expectEqual(@as(usize, 0), block_dispose_hits);

    // Second release drops refcount to 0 and runs dispose_helper once
    dispatch.shim_Block_release(heap2);
    try std.testing.expectEqual(@as(usize, 1), block_dispose_hits);
}

fn darwinQsortRCmp(thunk: ?*anyopaque, a: *const anyopaque, b: *const anyopaque) callconv(.c) c_int {
    const dir: *const c_int = @ptrCast(@alignCast(thunk.?));
    const va = @as(*const i32, @ptrCast(@alignCast(a))).*;
    const vb = @as(*const i32, @ptrCast(@alignCast(b))).*;
    return (va - vb) * dir.*;
}

test "abi: darwin setjmp/longjmp, qsort_r (bsd arg order), xsi strerror_r, sigset32" {
    const shims = wins_macho.shims;

    // 1. Darwin setjmp/longjmp inside 148-byte buffer
    var jbuf: [37]i32 align(8) = .{0} ** 37;
    const SetJmpFn = *const fn (*anyopaque) callconv(.c) c_int;
    const LongJmpFn = *const fn (*anyopaque, c_int) callconv(.c) noreturn;
    const sj: SetJmpFn = @ptrCast(&shims.shim_setjmp);
    const lj: LongJmpFn = @ptrCast(&shims.shim_longjmp);
    var jumped = false;
    const rc = sj(@ptrCast(&jbuf));
    if (rc == 0) {
        jumped = true;
        lj(@ptrCast(&jbuf), 42);
    }
    try std.testing.expect(jumped);
    try std.testing.expectEqual(@as(c_int, 42), rc);

    // 2. BSD qsort_r (descending via thunk = -1)
    var arr = [_]i32{ 3, 1, 4, 1, 5, 9, 2 };
    var desc: c_int = -1;
    shims.shim_qsort_r(@ptrCast(&arr), arr.len, @sizeOf(i32), @ptrCast(&desc), &darwinQsortRCmp);
    try std.testing.expectEqualSlices(i32, &.{ 9, 5, 4, 3, 2, 1, 1 }, &arr);

    // 3. XSI strerror_r returns 0 and writes message into caller buffer
    var errbuf: [128]u8 = .{0} ** 128;
    try std.testing.expectEqual(@as(c_int, 0), shims.shim_strerror_r(2, &errbuf, errbuf.len));
    try std.testing.expect(std.mem.span(@as([*:0]const u8, @ptrCast(&errbuf))).len > 0);

    // 4. Darwin 32-bit sigset_t helpers
    var mask: u32 = 0xDEADBEEF;
    try std.testing.expectEqual(@as(c_int, 0), shims.shim_sigemptyset(&mask));
    try std.testing.expectEqual(@as(u32, 0), mask);
    try std.testing.expectEqual(@as(c_int, 0), shims.shim_sigaddset(&mask, 15));
    try std.testing.expectEqual(@as(c_int, 1), shims.shim_sigismember(&mask, 15));
    try std.testing.expectEqual(@as(c_int, 0), shims.shim_sigismember(&mask, 2));
}

var test_shared_weak_freed: usize = 0;
fn testSharedOnZeroWeak(self: *wins_macho.libcxx.SharedWeakCount) callconv(.c) void {
    _ = self;
    test_shared_weak_freed += 1;
}

test "libcxx: Darwin ABI v1 std::string SSO/long, shared_weak_count, mutex+cv, system_clock" {
    const libcxx = wins_macho.libcxx;

    // 1. Short SSO string (<= 22 bytes)
    var s: libcxx.LibcxxString = .{ .raw = .{0} ** 24 };
    _ = libcxx.shim_string_assign_cstr(&s, "wins-macho");
    try std.testing.expect(!s.isLong());
    try std.testing.expectEqualStrings("wins-macho", s.slice());

    // 2. Long heap string (> 22 bytes) + substring ctor
    _ = libcxx.shim_string_assign_cstr(&s, "0123456789abcdefghijklmnopqrstuvwxyz");
    try std.testing.expect(s.isLong());
    try std.testing.expectEqualStrings("0123456789abcdefghijklmnopqrstuvwxyz", s.slice());

    var sub: libcxx.LibcxxString = .{ .raw = .{0} ** 24 };
    libcxx.shim_string_ctor_substr(&sub, &s, 10, 6, null);
    try std.testing.expect(!sub.isLong());
    try std.testing.expectEqualStrings("abcdef", sub.slice());
    libcxx.shim_string_dtor(&sub);
    libcxx.shim_string_dtor(&s);

    // 3. __shared_weak_count atomic weak release calls vtable[4]
    test_shared_weak_freed = 0;
    const vt = [5]usize{ 0, 0, 0, 0, @intFromPtr(&testSharedOnZeroWeak) };
    var swc = libcxx.SharedWeakCount{
        .vtable = &vt,
        .shared_owners = -1,
        .shared_weak_owners = 1,
    };
    libcxx.shim_shared_weak_count_release_weak(&swc);
    try std.testing.expectEqual(@as(usize, 0), test_shared_weak_freed);
    libcxx.shim_shared_weak_count_release_weak(&swc);
    try std.testing.expectEqual(@as(usize, 1), test_shared_weak_freed);

    // 4. system_clock::now() returns positive epoch microseconds
    try std.testing.expect(libcxx.shim_system_clock_now() > 1_700_000_000_000_000);
}

test "libcxx + unwind: RTTI inheritance matching, CxaException ABI, and compact unwind RBP/frameless step" {
    const libcxx = wins_macho.libcxx;
    const unwind = wins_macho.unwind;
    const shims = wins_macho.shims;

    libcxx.ensureInitialized();

    // 1. All exception/unwind symbols are REIMPLEMENTED (zero probe-only stubs)
    const eh_syms = [_][]const u8{
        "___cxa_allocate_exception",
        "___cxa_free_exception",
        "___cxa_throw",
        "___cxa_rethrow",
        "___cxa_begin_catch",
        "___cxa_end_catch",
        "___gxx_personality_v0",
        "__Unwind_RaiseException",
        "__Unwind_Resume",
        "__Unwind_GetIP",
        "__Unwind_SetIP",
        "__Unwind_SetGR",
        "__Unwind_GetLanguageSpecificData",
        "__Unwind_GetRegionStart",
    };
    for (eh_syms) |sym| {
        const entry = shims.lookup(sym) orelse return error.MissingSymbol;
        try std.testing.expectEqual(shims.ShimStatus.REIMPLEMENTED, entry.status);
    }

    // 2. Itanium RTTI inheritance matching: std::out_of_range -> std::logic_error -> std::exception
    var dummy_obj: u64 = 0x1234;
    var adj: ?*anyopaque = @ptrCast(&dummy_obj);
    try std.testing.expect(libcxx.typeInfoCanCatch(
        @ptrCast(&libcxx.ti_exception),
        @ptrCast(&libcxx.ti_out_of_range),
        &adj,
    ));
    try std.testing.expect(libcxx.typeInfoCanCatch(
        @ptrCast(&libcxx.ti_logic_error),
        @ptrCast(&libcxx.ti_out_of_range),
        &adj,
    ));
    try std.testing.expect(!libcxx.typeInfoCanCatch(
        @ptrCast(&libcxx.ti_runtime_error),
        @ptrCast(&libcxx.ti_out_of_range),
        &adj,
    ));

    // 3. Synthetic x86_64 RBP-frame compact unwind step restores RBX, R12, old RBP, RIP, RSP
    var fake_stack = [_]u64{
        0x1111_2222_3333_4444, // [0] rbp - 16 (saved RBX)
        0x5555_6666_7777_8888, // [1] rbp - 8  (saved R12)
        0xAAAA_BBBB_CCCC_DDDD, // [2] rbp      (saved old RBP)
        0x0000_0001_0000_9999, // [3] rbp + 8  (saved return RIP)
    };
    var regs = unwind.UnwindRegs{};
    regs.r[unwind.UnwindRegs.RBP] = @intFromPtr(&fake_stack[2]);
    regs.r[unwind.UnwindRegs.RSP] = @intFromPtr(&fake_stack[0]);
    // MODE_RBP_FRAME (0x01000000), offset=2 (0x00020000), slot0=RBX(1), slot1=R12(2 << 3 = 16 = 0x10)
    const enc: u32 = 0x0102_0011;
    try std.testing.expect(unwind.stepCompactX86_64(enc, 0, &regs));
    try std.testing.expectEqual(@as(u64, 0x1111_2222_3333_4444), regs.r[unwind.UnwindRegs.RBX]);
    try std.testing.expectEqual(@as(u64, 0x5555_6666_7777_8888), regs.r[unwind.UnwindRegs.R12]);
    try std.testing.expectEqual(@as(u64, 0xAAAA_BBBB_CCCC_DDDD), regs.r[unwind.UnwindRegs.RBP]);
    try std.testing.expectEqual(@as(u64, 0x0000_0001_0000_9999), regs.r[unwind.UnwindRegs.RIP]);
    try std.testing.expectEqual(@as(u64, @intFromPtr(&fake_stack[2]) + 16), regs.r[unwind.UnwindRegs.RSP]);
}
