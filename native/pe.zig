//! Bounded, static PE import-table inspection. No target code is executed.
const std = @import("std");

pub const Import = struct { name: ?[]const u8 = null, ordinal: ?u16 = null, hint: ?u16 = null };
pub const Library = struct { name: []const u8, symbols: []const Import };
pub const Report = struct {
    format: []const u8,
    machine: u16,
    sections: u16,
    libraries: []const Library,
    imports_count: usize,
    /// Delay-load import descriptors (data directory 13). RVA-based form only.
    delay_libraries: []const Library = &.{},
    delay_imports_count: usize = 0,
    /// True when the CLR runtime header (data directory 14) is present: managed code.
    managed_clr: bool = false,
};

fn read(comptime T: type, b: []const u8, p: usize) !T {
    if (p > b.len or @sizeOf(T) > b.len - p) return error.Truncated;
    return std.mem.readInt(T, b[p..][0..@sizeOf(T)], .little);
}
const Image = struct {
    bytes: []const u8,
    section_start: usize,
    section_count: u16,
    headers_size: u32,

    // Return only file-backed data, excluding virtual zero-fill and overlays.
    fn span(self: Image, rva: u32) ![]const u8 {
        if (rva < self.headers_size) {
            const n = @min(@as(usize, self.headers_size), self.bytes.len);
            if (rva >= n) return error.InvalidRva;
            return self.bytes[rva..n];
        }
        for (0..self.section_count) |i| {
            const p = self.section_start + i * 40;
            const virtual = try read(u32, self.bytes, p + 12);
            const raw_size = try read(u32, self.bytes, p + 16);
            const raw_offset = try read(u32, self.bytes, p + 20);
            if (rva < virtual) continue;
            const delta = rva - virtual;
            if (delta >= raw_size) continue;
            const off: usize = @as(usize, raw_offset) + delta;
            if (off > self.bytes.len or raw_size - delta > self.bytes.len - off) return error.Truncated;
            return self.bytes[off..][0 .. raw_size - delta];
        }
        return error.InvalidRva;
    }
    fn string(self: Image, rva: u32) ![]const u8 {
        const s = try self.span(rva);
        const limit = @min(s.len, 4096);
        const end = std.mem.indexOfScalar(u8, s[0..limit], 0) orelse return error.UnterminatedString;
        if (end == 0) return error.EmptyName;
        // PE names are ASCII. Reject invalid bytes rather than emit malformed JSON.
        for (s[0..end]) |c| if (c < 0x20 or c > 0x7e) return error.InvalidName;
        return s[0..end];
    }
};

fn readThunks(a: std.mem.Allocator, image: Image, is64: bool, table_rva: u32, total: *usize) ![]const Import {
    const thunks = try image.span(table_rva);
    const width: usize = if (is64) 8 else 4;
    var symbols: std.ArrayList(Import) = .empty;
    var off: usize = 0;
    var terminated = false;
    while (off <= thunks.len and width <= thunks.len - off) : (off += width) {
        const value: u64 = if (is64) try read(u64, thunks, off) else try read(u32, thunks, off);
        if (value == 0) {
            terminated = true;
            break;
        }
        if (total.* >= 100_000) return error.TooManyImports;
        const mask: u64 = if (is64) @as(u64, 1) << 63 else @as(u64, 1) << 31;
        if (value & mask != 0) {
            if (value & ~(mask | 0xffff) != 0) return error.InvalidOrdinal;
            try symbols.append(a, .{ .ordinal = @intCast(value & 0xffff) });
        } else {
            if (value > std.math.maxInt(u32) - 2) return error.InvalidRva;
            const rva: u32 = @intCast(value);
            const hn = try image.span(rva);
            const hint = try read(u16, hn, 0);
            const name = try image.string(rva + 2);
            try symbols.append(a, .{ .name = name, .hint = hint });
        }
        total.* += 1;
    }
    if (!terminated) return error.UnterminatedThunks;
    return symbols.toOwnedSlice(a);
}

pub fn parse(a: std.mem.Allocator, b: []const u8) !Report {
    if (b.len < 64 or !std.mem.eql(u8, b[0..2], "MZ")) return error.NotPe;
    const pe: usize = try read(u32, b, 0x3c);
    if (pe > b.len or b.len - pe < 24 or !std.mem.eql(u8, b[pe..][0..4], "PE\x00\x00")) return error.NotPe;
    const machine = try read(u16, b, pe + 4);
    const count = try read(u16, b, pe + 6);
    const opt_size: usize = try read(u16, b, pe + 20);
    const opt = pe + 24;
    if (opt > b.len or opt_size > b.len - opt or opt_size < 2) return error.Truncated;
    const magic = try read(u16, b, opt);
    const is64 = switch (magic) {
        0x10b => false,
        0x20b => true,
        else => return error.NotPe,
    };
    const directory_start: usize = if (is64) 112 else 96;
    const number_offset: usize = if (is64) 108 else 92;
    if (opt_size < directory_start) return error.Truncated;
    const header_size = try read(u32, b, opt + 60);
    const num_dirs = try read(u32, b, opt + number_offset);
    const sections_at = opt + opt_size;
    if (sections_at > b.len or @as(usize, count) > (b.len - sections_at) / 40) return error.Truncated;
    const image = Image{ .bytes = b, .section_start = sections_at, .section_count = count, .headers_size = header_size };
    var libs: std.ArrayList(Library) = .empty;
    var total: usize = 0;
    if (num_dirs > 1) {
        if (opt_size < directory_start + 16) return error.Truncated;
        const import_rva = try read(u32, b, opt + directory_start + 8);
        const import_size: usize = try read(u32, b, opt + directory_start + 12);
        if ((import_rva == 0) != (import_size == 0)) return error.InvalidImportDirectory;
        if (import_rva != 0) {
            const directory = try image.span(import_rva);
            if (import_size > directory.len or import_size < 20) return error.Truncated;
            var pos: usize = 0;
            var terminated = false;
            while (pos + 20 <= import_size) : (pos += 20) {
                if (libs.items.len >= 4096) return error.TooManyImports;
                const ilt = try read(u32, directory, pos);
                const timestamp = try read(u32, directory, pos + 4);
                const forwarder = try read(u32, directory, pos + 8);
                const dll_rva = try read(u32, directory, pos + 12);
                const iat = try read(u32, directory, pos + 16);
                if (ilt == 0 and timestamp == 0 and forwarder == 0 and dll_rva == 0 and iat == 0) {
                    terminated = true;
                    break;
                }
                if (dll_rva == 0 or (ilt == 0 and iat == 0)) return error.InvalidImportDirectory;
                const dll = try image.string(dll_rva);
                const symbols = try readThunks(a, image, is64, if (ilt != 0) ilt else iat, &total);
                try libs.append(a, .{ .name = dll, .symbols = symbols });
            }
            if (!terminated) return error.UnterminatedImportDirectory;
        }
    }
    var delay_libs: std.ArrayList(Library) = .empty;
    var delay_total: usize = 0;
    if (num_dirs > 13) {
        if (opt_size < directory_start + 14 * 8) return error.Truncated;
        const delay_rva = try read(u32, b, opt + directory_start + 13 * 8);
        if (delay_rva != 0) {
            const directory = try image.span(delay_rva);
            var pos: usize = 0;
            var terminated = false;
            while (pos + 32 <= directory.len) : (pos += 32) {
                if (delay_libs.items.len >= 4096) return error.TooManyImports;
                const attrs = try read(u32, directory, pos);
                const dll_rva = try read(u32, directory, pos + 4);
                const int_rva = try read(u32, directory, pos + 16);
                if (attrs == 0 and dll_rva == 0 and int_rva == 0 and try read(u32, directory, pos + 8) == 0) {
                    terminated = true;
                    break;
                }
                // Old (pre-VC7) descriptors store virtual addresses: refuse rather than guess.
                if (attrs & 1 == 0) return error.UnsupportedDelayFormat;
                if (dll_rva == 0 or int_rva == 0) return error.InvalidImportDirectory;
                const dll = try image.string(dll_rva);
                const symbols = try readThunks(a, image, is64, int_rva, &delay_total);
                try delay_libs.append(a, .{ .name = dll, .symbols = symbols });
            }
            if (!terminated) return error.UnterminatedImportDirectory;
        }
    }
    var clr = false;
    if (num_dirs > 14) {
        if (opt_size < directory_start + 15 * 8) return error.Truncated;
        clr = try read(u32, b, opt + directory_start + 14 * 8) != 0;
    }
    return .{ .format = if (is64) "PE32+" else "PE32", .machine = machine, .sections = count, .libraries = try libs.toOwnedSlice(a), .imports_count = total, .delay_libraries = try delay_libs.toOwnedSlice(a), .delay_imports_count = delay_total, .managed_clr = clr };
}
