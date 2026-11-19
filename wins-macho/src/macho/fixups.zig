const std = @import("std");
const types = @import("types.zig");
const exports = @import("exports.zig");
const parser = @import("parser.zig");

pub const RebaseSite = struct {
    seg_index: usize,
    seg_offset: u64,
    rebase_type: u8,
};

pub const BindSite = struct {
    seg_index: usize,
    seg_offset: u64,
    dylib_ordinal: i32,
    symbol: []const u8,
    addend: i64,
    bind_type: u8,
    is_weak: bool,
};

pub const FixupError = error{
    MalformedOpcode,
    OutOfBounds,
    UnsupportedFixupFormat,
    TruncatedLeb128,
    Leb128Overflow,
    OutOfMemory,
};

pub fn parseRebaseOpcodes(allocator: std.mem.Allocator, data: []const u8) FixupError![]RebaseSite {
    var sites: std.ArrayList(RebaseSite) = .empty;
    errdefer sites.deinit(allocator);

    var c: usize = 0;
    var seg_index: usize = 0;
    var seg_offset: u64 = 0;
    var rebase_type: u8 = types.REBASE_TYPE_POINTER;

    while (c < data.len) {
        const byte = data[c];
        c += 1;
        const opcode = byte & types.REBASE_OPCODE_MASK;
        const imm = byte & types.REBASE_IMMEDIATE_MASK;

        switch (opcode) {
            types.REBASE_OPCODE_DONE => break,
            types.REBASE_OPCODE_SET_TYPE_IMM => rebase_type = imm,
            types.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                seg_index = imm;
                seg_offset = try exports.readUleb128(data, &c);
            },
            types.REBASE_OPCODE_ADD_ADDR_ULEB => {
                const delta = try exports.readUleb128(data, &c);
                seg_offset +%= delta;
            },
            types.REBASE_OPCODE_ADD_ADDR_IMM_SCALED => {
                seg_offset +%= @as(u64, imm) * @sizeOf(u64);
            },
            types.REBASE_OPCODE_DO_REBASE_IMM_TIMES => {
                var i: u8 = 0;
                while (i < imm) : (i += 1) {
                    try sites.append(allocator, .{ .seg_index = seg_index, .seg_offset = seg_offset, .rebase_type = rebase_type });
                    seg_offset +%= @sizeOf(u64);
                }
            },
            types.REBASE_OPCODE_DO_REBASE_ULEB_TIMES => {
                const count = try exports.readUleb128(data, &c);
                var i: u64 = 0;
                while (i < count) : (i += 1) {
                    try sites.append(allocator, .{ .seg_index = seg_index, .seg_offset = seg_offset, .rebase_type = rebase_type });
                    seg_offset +%= @sizeOf(u64);
                }
            },
            types.REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB => {
                try sites.append(allocator, .{ .seg_index = seg_index, .seg_offset = seg_offset, .rebase_type = rebase_type });
                const delta = try exports.readUleb128(data, &c);
                seg_offset +%= @sizeOf(u64) +% delta;
            },
            types.REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB => {
                const count = try exports.readUleb128(data, &c);
                const skip = try exports.readUleb128(data, &c);
                var i: u64 = 0;
                while (i < count) : (i += 1) {
                    try sites.append(allocator, .{ .seg_index = seg_index, .seg_offset = seg_offset, .rebase_type = rebase_type });
                    seg_offset +%= @sizeOf(u64) +% skip;
                }
            },
            else => return error.MalformedOpcode,
        }
    }

    return sites.toOwnedSlice(allocator);
}

pub fn parseBindOpcodes(allocator: std.mem.Allocator, data: []const u8, is_weak_stream: bool) FixupError![]BindSite {
    var sites: std.ArrayList(BindSite) = .empty;
    errdefer sites.deinit(allocator);

    var c: usize = 0;
    var seg_index: usize = 0;
    var seg_offset: u64 = 0;
    var dylib_ordinal: i32 = 0;
    var symbol: []const u8 = "";
    var addend: i64 = 0;
    var bind_type: u8 = types.BIND_TYPE_POINTER;

    while (c < data.len) {
        const byte = data[c];
        c += 1;
        const opcode = byte & types.BIND_OPCODE_MASK;
        const imm = byte & types.BIND_IMMEDIATE_MASK;

        switch (opcode) {
            types.BIND_OPCODE_DONE => {
                if (is_weak_stream) continue; // lazy_bind has DONE between entries too, but let's check:
                // Actually lazy_bind also uses DONE at the end of each stub entry! Continue until c == data.len.
                continue;
            },
            types.BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => dylib_ordinal = @intCast(imm),
            types.BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                const ord = try exports.readUleb128(data, &c);
                dylib_ordinal = @intCast(ord);
            },
            types.BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {
                if (imm == 0) {
                    dylib_ordinal = 0;
                } else {
                    const signed: i8 = @bitCast(@as(u8, 0xF0 | imm));
                    dylib_ordinal = signed;
                }
            },
            types.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                const nul = std.mem.indexOfScalarPos(u8, data, c, 0) orelse return error.MalformedOpcode;
                symbol = data[c..nul];
                c = nul + 1;
            },
            types.BIND_OPCODE_SET_TYPE_IMM => bind_type = imm,
            types.BIND_OPCODE_SET_ADDEND_SLEB => addend = try exports.readSleb128(data, &c),
            types.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                seg_index = imm;
                seg_offset = try exports.readUleb128(data, &c);
            },
            types.BIND_OPCODE_ADD_ADDR_ULEB => {
                const delta = try exports.readUleb128(data, &c);
                seg_offset +%= delta;
            },
            types.BIND_OPCODE_DO_BIND => {
                try sites.append(allocator, .{
                    .seg_index = seg_index,
                    .seg_offset = seg_offset,
                    .dylib_ordinal = dylib_ordinal,
                    .symbol = symbol,
                    .addend = addend,
                    .bind_type = bind_type,
                    .is_weak = is_weak_stream,
                });
                seg_offset +%= @sizeOf(u64);
            },
            types.BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                try sites.append(allocator, .{
                    .seg_index = seg_index,
                    .seg_offset = seg_offset,
                    .dylib_ordinal = dylib_ordinal,
                    .symbol = symbol,
                    .addend = addend,
                    .bind_type = bind_type,
                    .is_weak = is_weak_stream,
                });
                const delta = try exports.readUleb128(data, &c);
                seg_offset +%= @sizeOf(u64) +% delta;
            },
            types.BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                try sites.append(allocator, .{
                    .seg_index = seg_index,
                    .seg_offset = seg_offset,
                    .dylib_ordinal = dylib_ordinal,
                    .symbol = symbol,
                    .addend = addend,
                    .bind_type = bind_type,
                    .is_weak = is_weak_stream,
                });
                seg_offset +%= @as(u64, imm + 1) * @sizeOf(u64);
            },
            types.BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                const count = try exports.readUleb128(data, &c);
                const skip = try exports.readUleb128(data, &c);
                var i: u64 = 0;
                while (i < count) : (i += 1) {
                    try sites.append(allocator, .{
                        .seg_index = seg_index,
                        .seg_offset = seg_offset,
                        .dylib_ordinal = dylib_ordinal,
                        .symbol = symbol,
                        .addend = addend,
                        .bind_type = bind_type,
                        .is_weak = is_weak_stream,
                    });
                    seg_offset +%= @sizeOf(u64) +% skip;
                }
            },
            else => return error.MalformedOpcode,
        }
    }

    return sites.toOwnedSlice(allocator);
}

pub const ChainedImport = struct {
    dylib_ordinal: i32,
    weak_import: bool,
    symbol: []const u8,
    addend: i64,
};

pub fn parseChainedImports(allocator: std.mem.Allocator, fixups_blob: []const u8) FixupError![]ChainedImport {
    if (fixups_blob.len < @sizeOf(types.ChainedFixupsHeader)) return error.OutOfBounds;
    const hdr = std.mem.bytesToValue(types.ChainedFixupsHeader, fixups_blob[0..@sizeOf(types.ChainedFixupsHeader)]);
    if (hdr.symbols_offset >= fixups_blob.len or hdr.imports_offset > fixups_blob.len) return error.OutOfBounds;

    var list = try allocator.alloc(ChainedImport, hdr.imports_count);
    errdefer allocator.free(list);

    const syms = fixups_blob[hdr.symbols_offset..];
    var cursor: usize = hdr.imports_offset;

    for (0..hdr.imports_count) |i| {
        switch (hdr.imports_format) {
            types.DYLD_CHAINED_IMPORT => {
                if (cursor + 4 > fixups_blob.len) return error.OutOfBounds;
                const raw = std.mem.readInt(u32, fixups_blob[cursor..][0..4], .little);
                cursor += 4;
                const lib_ord: u8 = @truncate(raw & 0xFF);
                const weak = ((raw >> 8) & 1) != 0;
                const name_off: usize = @intCast(raw >> 9);
                if (name_off >= syms.len) return error.OutOfBounds;
                const nul = std.mem.indexOfScalarPos(u8, syms, name_off, 0) orelse return error.OutOfBounds;
                const ord: i32 = if (lib_ord >= 0xF0) @as(i8, @bitCast(lib_ord)) else lib_ord;
                list[i] = .{ .dylib_ordinal = ord, .weak_import = weak, .symbol = syms[name_off..nul], .addend = 0 };
            },
            types.DYLD_CHAINED_IMPORT_ADDEND => {
                if (cursor + 8 > fixups_blob.len) return error.OutOfBounds;
                const raw = std.mem.readInt(u32, fixups_blob[cursor..][0..4], .little);
                const addend = std.mem.readInt(i32, fixups_blob[cursor + 4 ..][0..4], .little);
                cursor += 8;
                const lib_ord: u8 = @truncate(raw & 0xFF);
                const weak = ((raw >> 8) & 1) != 0;
                const name_off: usize = @intCast(raw >> 9);
                if (name_off >= syms.len) return error.OutOfBounds;
                const nul = std.mem.indexOfScalarPos(u8, syms, name_off, 0) orelse return error.OutOfBounds;
                const ord: i32 = if (lib_ord >= 0xF0) @as(i8, @bitCast(lib_ord)) else lib_ord;
                list[i] = .{ .dylib_ordinal = ord, .weak_import = weak, .symbol = syms[name_off..nul], .addend = addend };
            },
            else => return error.UnsupportedFixupFormat,
        }
    }
    return list;
}

pub const DYLD_CHAINED_PTR_START_NONE: u16 = 0xFFFF;

pub const ChainedSegmentInfo = struct {
    page_size: u16,
    pointer_format: u16,
    segment_offset: u64,
    page_starts: []const u16,
};

pub fn parseChainedSegments(allocator: std.mem.Allocator, fixups_blob: []const u8) FixupError![]ChainedSegmentInfo {
    if (fixups_blob.len < @sizeOf(types.ChainedFixupsHeader)) return error.OutOfBounds;
    const hdr = std.mem.bytesToValue(types.ChainedFixupsHeader, fixups_blob[0..@sizeOf(types.ChainedFixupsHeader)]);
    if (hdr.starts_offset + 4 > fixups_blob.len) return error.OutOfBounds;

    const seg_count = std.mem.readInt(u32, fixups_blob[hdr.starts_offset..][0..4], .little);
    const offs_start = hdr.starts_offset + 4;
    if (offs_start + @as(usize, seg_count) * 4 > fixups_blob.len) return error.OutOfBounds;

    var list: std.ArrayList(ChainedSegmentInfo) = .empty;
    errdefer {
        for (list.items) |item| allocator.free(item.page_starts);
        list.deinit(allocator);
    }

    for (0..seg_count) |si| {
        const seg_rel = std.mem.readInt(u32, fixups_blob[offs_start + si * 4 ..][0..4], .little);
        if (seg_rel == 0) continue;
        const seg_off = @as(usize, hdr.starts_offset) + seg_rel;
        if (seg_off + @sizeOf(types.ChainedStartsInSegment) > fixups_blob.len) return error.OutOfBounds;

        const page_size = std.mem.readInt(u16, fixups_blob[seg_off + 4 ..][0..2], .little);
        const pointer_format = std.mem.readInt(u16, fixups_blob[seg_off + 6 ..][0..2], .little);
        const segment_offset = std.mem.readInt(u64, fixups_blob[seg_off + 8 ..][0..8], .little);
        const page_count = std.mem.readInt(u16, fixups_blob[seg_off + 20 ..][0..2], .little);

        const starts_off = seg_off + 22;
        if (starts_off + @as(usize, page_count) * 2 > fixups_blob.len) return error.OutOfBounds;
        const page_starts = try allocator.alloc(u16, page_count);
        errdefer allocator.free(page_starts);
        for (0..page_count) |pi| {
            page_starts[pi] = std.mem.readInt(u16, fixups_blob[starts_off + pi * 2 ..][0..2], .little);
        }

        try list.append(allocator, .{
            .page_size = page_size,
            .pointer_format = pointer_format,
            .segment_offset = segment_offset,
            .page_starts = page_starts,
        });
    }

    return list.toOwnedSlice(allocator);
}
