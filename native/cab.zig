//! Bounded static cabinet metadata inspection; it does not decompress files.
const std = @import("std");
pub const Result = struct {
    member: []const u8,
    uncompressed_size: u32,
    folder_index: u16,
    offset_in_uncompressed_folder: u32,
    folder_data_offset: u32,
    folder_data_blocks: u16,
    compression: []const u8,
    cabinet_declared_bytes: u32,
    integrity: []const u8 = "NOT_VERIFIED",
};
fn read(comptime T: type, b: []const u8, off: usize) !T {
    if (off > b.len or @sizeOf(T) > b.len - off) return error.Truncated;
    return std.mem.readInt(T, b[off..][0..@sizeOf(T)], .little);
}
pub fn find(input: []const u8, member: []const u8) !Result {
    if (input.len < 36 or !std.mem.eql(u8, input[0..4], "MSCF")) return error.NotCab;
    const cabinet_size = try read(u32, input, 8);
    if (cabinet_size < 36) return error.InvalidHeader;
    const b = input[0..@min(input.len, cabinet_size)];
    const file_table: usize = try read(u32, b, 16);
    const folders = try read(u16, b, 26);
    const files = try read(u16, b, 28);
    const flags = try read(u16, b, 30);
    if (cabinet_size < 36 or file_table >= cabinet_size) return error.InvalidHeader;
    if (flags & 3 != 0) return error.MultiVolumeUnsupported;
    if (flags & ~@as(u16, 7) != 0) return error.InvalidHeader;
    var pos: usize = 36;
    var folder_reserve: usize = 0;
    if (flags & 4 != 0) {
        const header_reserve = try read(u16, b, pos);
        folder_reserve = try read(u8, b, pos + 2);
        _ = try read(u8, b, pos + 3);
        pos += 4 + @as(usize, header_reserve);
    }
    const folder_size = 8 + folder_reserve;
    if (pos > b.len or @as(usize, folders) > (b.len - pos) / folder_size) return error.Truncated;
    if (pos + @as(usize, folders) * folder_size > file_table) return error.InvalidHeader;
    const folder_start = pos;
    pos = file_table;
    for (0..files) |_| {
        const size = try read(u32, b, pos);
        const offset = try read(u32, b, pos + 4);
        const folder = try read(u16, b, pos + 8);
        _ = try read(u16, b, pos + 14);
        const name_at = pos + 16;
        if (name_at >= b.len) return error.Truncated;
        const limit = @min(b.len - name_at, 32768);
        const end = std.mem.indexOfScalar(u8, b[name_at..][0..limit], 0) orelse return error.UnterminatedName;
        const name = b[name_at..][0..end];
        pos = name_at + end + 1;
        if (!std.mem.eql(u8, name, member)) continue;
        if (folder >= folders) return error.InvalidFolder;
        const fpos = folder_start + @as(usize, folder) * folder_size;
        const data_offset = try read(u32, b, fpos);
        const blocks = try read(u16, b, fpos + 4);
        const algorithm = try read(u16, b, fpos + 6);
        if (data_offset >= cabinet_size or (size > 0 and blocks == 0)) return error.InvalidFolder;
        const compression: []const u8 = switch (algorithm & 15) {
            0 => "none",
            1 => "MSZIP",
            2 => "Quantum",
            3 => "LZX",
            else => return error.UnsupportedCompression,
        };
        return .{ .member = name, .uncompressed_size = size, .folder_index = folder, .offset_in_uncompressed_folder = offset, .folder_data_offset = data_offset, .folder_data_blocks = blocks, .compression = compression, .cabinet_declared_bytes = cabinet_size };
    }
    return error.MemberNotFound;
}
