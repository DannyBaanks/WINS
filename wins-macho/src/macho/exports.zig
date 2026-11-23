const std = @import("std");

pub const ExportEntry = struct {
    flags: u64,
    address_offset: u64,
    other: u64,
    import_name: ?[]const u8 = null,
};

pub fn readUleb128(data: []const u8, cursor: *usize) error{TruncatedLeb128, Leb128Overflow}!u64 {
    var result: u64 = 0;
    var shift: u6 = 0;
    while (cursor.* < data.len) {
        const byte = data[cursor.*];
        cursor.* += 1;
        const val: u64 = byte & 0x7f;
        if (shift >= 64 or (shift == 63 and val > 1)) return error.Leb128Overflow;
        result |= val << shift;
        if ((byte & 0x80) == 0) return result;
        shift += 7;
    }
    return error.TruncatedLeb128;
}

pub fn readSleb128(data: []const u8, cursor: *usize) error{TruncatedLeb128, Leb128Overflow}!i64 {
    var result: u64 = 0;
    var shift: u6 = 0;
    var byte: u8 = 0;
    while (cursor.* < data.len) {
        byte = data[cursor.*];
        cursor.* += 1;
        const val: u64 = byte & 0x7f;
        if (shift >= 64) return error.Leb128Overflow;
        result |= val << shift;
        shift += 7;
        if ((byte & 0x80) == 0) break;
    } else return error.TruncatedLeb128;

    if (shift < 64 and (byte & 0x40) != 0) {
        result |= (~@as(u64, 0)) << shift;
    }
    return @bitCast(result);
}

pub const EXPORT_SYMBOL_FLAGS_KIND_MASK: u64 = 0x03;
pub const EXPORT_SYMBOL_FLAGS_KIND_REGULAR: u64 = 0x00;
pub const EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL: u64 = 0x01;
pub const EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE: u64 = 0x02;
pub const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;
pub const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64 = 0x10;

pub fn lookupExport(trie: []const u8, symbol: []const u8) ?ExportEntry {
    if (trie.len == 0) return null;
    var node_off: usize = 0;
    var matched: usize = 0;
    var depth: usize = 0;

    while (depth < 512) : (depth += 1) {
        if (node_off >= trie.len) return null;
        var c = node_off;
        const term_size = readUleb128(trie, &c) catch return null;
        if (matched == symbol.len) {
            if (term_size == 0) return null;
            const term_end = std.math.add(usize, c, @intCast(term_size)) catch return null;
            if (term_end > trie.len) return null;
            const flags = readUleb128(trie, &c) catch return null;
            if ((flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0) {
                const ordinal = readUleb128(trie, &c) catch return null;
                const tail = trie[c..term_end];
                const nul = std.mem.indexOfScalar(u8, tail, 0) orelse tail.len;
                return .{
                    .flags = flags,
                    .address_offset = 0,
                    .other = ordinal,
                    .import_name = if (nul > 0) tail[0..nul] else symbol,
                };
            }
            const addr_off = readUleb128(trie, &c) catch return null;
            var other: u64 = 0;
            if ((flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0) {
                other = readUleb128(trie, &c) catch return null;
            }
            return .{
                .flags = flags,
                .address_offset = addr_off,
                .other = other,
            };
        }

        // Skip terminal info
        c = std.math.add(usize, c, @intCast(term_size)) catch return null;
        if (c >= trie.len) return null;
        const child_count = trie[c];
        c += 1;

        var found = false;
        var i: u8 = 0;
        while (i < child_count) : (i += 1) {
            if (c >= trie.len) return null;
            const nul = std.mem.indexOfScalarPos(u8, trie, c, 0) orelse return null;
            const edge_str = trie[c..nul];
            c = nul + 1;
            const next_off = readUleb128(trie, &c) catch return null;
            if (edge_str.len > 0 and std.mem.startsWith(u8, symbol[matched..], edge_str)) {
                matched += edge_str.len;
                node_off = @intCast(next_off);
                found = true;
                break;
            }
        }
        if (!found) return null;
    }
    return null;
}
