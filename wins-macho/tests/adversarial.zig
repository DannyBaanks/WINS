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
