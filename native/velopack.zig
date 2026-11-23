//! Velopack / Squirrel installer overlay: static inspection and extraction.
//!
//! A Velopack `Setup.exe` is a native PE (the Rust `velopack` binary) whose
//! payload is a ZIP archive — the nupkg — appended after the last PE section.
//! Nothing here executes the installer: the overlay is parsed as data.
//!
//! The archive is self-contained: every offset inside the ZIP is relative to
//! the start of the archive, so the overlay can be parsed in place without
//! copying the bytes out first.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;

pub const Error = error{
    NotVelopack,
    InvalidArchive,
    UnsupportedCompression,
    CrcMismatch,
    UnsafePath,
    MissingNuspec,
};

pub const Entry = struct {
    name: []const u8,
    method: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    local_header_offset: u32,
};

pub const Nuspec = struct {
    id: ?[]const u8 = null,
    version: ?[]const u8 = null,
    channel: ?[]const u8 = null,
    rid: ?[]const u8 = null,
    os: ?[]const u8 = null,
    main_exe: ?[]const u8 = null,
    runtime_dependencies: ?[]const u8 = null,
};

pub const Info = struct {
    /// Offset of the ZIP archive inside the host file.
    archive_offset: usize,
    /// Bytes occupied by the archive, from its first local header to EOF.
    archive_size: usize,
    entry_count: u16,
    entries: []Entry,
    nuspec: Nuspec,
};

pub const ExtractSummary = struct {
    files_written: u32,
    bytes_written: u64,
    entries_skipped: u32,
};

fn u16le(b: []const u8, p: usize) !u16 {
    if (p > b.len or b.len - p < 2) return error.Truncated;
    return std.mem.readInt(u16, b[p..][0..2], .little);
}

fn u32le(b: []const u8, p: usize) !u32 {
    if (p > b.len or b.len - p < 4) return error.Truncated;
    return std.mem.readInt(u32, b[p..][0..4], .little);
}

/// Scan backwards for `needle`, starting at `from` and never below `floor`.
fn findSignatureBackwards(haystack: []const u8, needle: []const u8, from: usize, floor: usize) ?usize {
    if (needle.len == 0 or needle.len > haystack.len) return null;
    var i = @min(from, haystack.len);
    while (true) {
        if (i >= needle.len and haystack.len - i >= needle.len) {
            if (std.mem.eql(u8, haystack[i..][0..needle.len], needle)) return i;
        }
        if (i == 0 or i <= floor) break;
        i -= 1;
    }
    return null;
}

pub const Overlay = struct {
    /// Offset of the archive's first local header inside the host file.
    archive_offset: usize,
    /// Offset of the ZIP end-of-central-directory record.
    eocd_offset: usize,
};

/// Locate the ZIP overlay appended to a PE (or any host file).
/// Returns the offset of the archive's first local header and its EOCD.
pub fn findOverlay(input: []const u8) !Overlay {
    if (input.len < 22) return Error.NotVelopack;
    // EOCD sits at the very end; allow the maximum 64 KiB comment before it.
    const limit = if (input.len > 65557) input.len - 65557 else 0;
    var cursor = input.len;
    while (cursor > limit) {
        const pos = findSignatureBackwards(input, "PK\x05\x06", cursor, limit) orelse break;
        cursor = pos;
        const comment_len = try u16le(input, pos + 20);
        if (pos + 22 + comment_len != input.len) continue;
        const cd_size = try u32le(input, pos + 12);
        const cd_offset = try u32le(input, pos + 16);
        if (cd_size == 0 or cd_offset == 0) continue;
        if (cd_size > pos) continue;
        const cd_file_off = pos - cd_size;
        if (cd_offset > cd_file_off) continue;
        const archive_start = cd_file_off - cd_offset;
        if (std.mem.eql(u8, input[archive_start..][0..4], "PK\x03\x04")) {
            return .{ .archive_offset = archive_start, .eocd_offset = pos };
        }
    }
    return Error.NotVelopack;
}

/// Parse the central directory of the overlay.
pub fn parse(gpa: std.mem.Allocator, input: []const u8) !Info {
    const overlay = try findOverlay(input);
    const archive_start = overlay.archive_offset;
    const eocd = overlay.eocd_offset;
    const entry_count = try u16le(input, eocd + 10);
    const cd_size = try u32le(input, eocd + 12);
    const cd_file_off = eocd - cd_size;
    const entries = try gpa.alloc(Entry, entry_count);
    errdefer gpa.free(entries);

    var pos = cd_file_off;
    var i: u16 = 0;
    while (i < entry_count) : (i += 1) {
        if (!std.mem.eql(u8, input[pos..][0..4], "PK\x01\x02")) return Error.InvalidArchive;
        const method = try u16le(input, pos + 10);
        const crc = try u32le(input, pos + 16);
        const comp_size = try u32le(input, pos + 20);
        const uncomp_size = try u32le(input, pos + 24);
        const name_len = try u16le(input, pos + 28);
        const extra_len = try u16le(input, pos + 30);
        const comment_len = try u16le(input, pos + 32);
        const local_off = try u32le(input, pos + 42);
        const name_at = pos + 46;
        if (name_at + name_len > input.len) return Error.InvalidArchive;
        entries[i] = .{
            .name = input[name_at..][0..name_len],
            .method = method,
            .crc32 = crc,
            .compressed_size = comp_size,
            .uncompressed_size = uncomp_size,
            .local_header_offset = local_off,
        };
        pos = name_at + name_len + extra_len + comment_len;
    }

    var nuspec: Nuspec = .{};
    for (entries) |entry| {
        if (std.mem.endsWith(u8, entry.name, ".nuspec")) {
            const text = try readEntry(gpa, input, archive_start, entry);
            defer gpa.free(text);
            const parsed = parseNuspec(text);
            // The parsed fields point into `text`, which dies with this scope:
            // copy them so the caller owns them.
            nuspec.id = try dupOptional(gpa, parsed.id);
            nuspec.version = try dupOptional(gpa, parsed.version);
            nuspec.channel = try dupOptional(gpa, parsed.channel);
            nuspec.rid = try dupOptional(gpa, parsed.rid);
            nuspec.os = try dupOptional(gpa, parsed.os);
            nuspec.main_exe = try dupOptional(gpa, parsed.main_exe);
            nuspec.runtime_dependencies = try dupOptional(gpa, parsed.runtime_dependencies);
            break;
        }
    }

    return .{
        .archive_offset = archive_start,
        .archive_size = input.len - archive_start,
        .entry_count = entry_count,
        .entries = entries,
        .nuspec = nuspec,
    };
}

fn dataOffset(input: []const u8, archive_start: usize, entry: Entry) !usize {
    const local = archive_start + entry.local_header_offset;
    if (local + 30 > input.len) return Error.InvalidArchive;
    if (!std.mem.eql(u8, input[local..][0..4], "PK\x03\x04")) return Error.InvalidArchive;
    const name_len = try u16le(input, local + 26);
    const extra_len = try u16le(input, local + 28);
    const data_at = local + 30 + name_len + extra_len;
    if (data_at + entry.compressed_size > input.len) return Error.InvalidArchive;
    return data_at;
}

fn dupOptional(gpa: std.mem.Allocator, value: ?[]const u8) !?[]const u8 {
    if (value) |v| return try gpa.dupe(u8, v);
    return null;
}

/// Free the memory owned by a parsed `Info`.
pub fn deinitInfo(gpa: std.mem.Allocator, info: *Info) void {
    gpa.free(info.entries);
    inline for (.{
        info.nuspec.id,
        info.nuspec.version,
        info.nuspec.channel,
        info.nuspec.rid,
        info.nuspec.os,
        info.nuspec.main_exe,
        info.nuspec.runtime_dependencies,
    }) |maybe| {
        if (maybe) |v| gpa.free(v);
    }
}

/// Read one entry's uncompressed bytes.
pub fn readEntry(gpa: std.mem.Allocator, input: []const u8, archive_start: usize, entry: Entry) ![]u8 {
    const data_at = try dataOffset(input, archive_start, entry);
    const raw = input[data_at..][0..entry.compressed_size];
    switch (entry.method) {
        0 => {
            if (entry.compressed_size != entry.uncompressed_size) return Error.InvalidArchive;
            return gpa.dupe(u8, raw);
        },
        8 => {
            const out = try gpa.alloc(u8, entry.uncompressed_size);
            errdefer gpa.free(out);
            var reader = Io.Reader.fixed(raw);
            var decompressor = std.compress.flate.Decompress.init(&reader, .raw, &.{});
            var writer = Io.Writer.fixed(out);
            _ = decompressor.reader.streamRemaining(&writer) catch return Error.UnsupportedCompression;
            if (std.hash.crc.Crc32.hash(out) != entry.crc32) {
                gpa.free(out);
                return Error.CrcMismatch;
            }
            return out;
        },
        else => return Error.UnsupportedCompression,
    }
}

/// Extract every file entry of the overlay into `out_dir`.
/// Paths are validated: no absolute paths, no `..` segments, no backslashes.
pub fn extract(gpa: std.mem.Allocator, io: Io, input: []const u8, out_dir: []const u8) !ExtractSummary {
    const info = try parse(gpa, input);
    defer gpa.free(info.entries);
    try Dir.cwd().createDirPath(io, out_dir);
    var summary: ExtractSummary = .{ .files_written = 0, .bytes_written = 0, .entries_skipped = 0 };
    for (info.entries) |entry| {
        if (entry.name.len == 0 or std.mem.endsWith(u8, entry.name, "/")) {
            summary.entries_skipped += 1;
            continue;
        }
        if (!isSafeName(entry.name)) return Error.UnsafePath;
        const bytes = readEntry(gpa, input, info.archive_offset, entry) catch |err| {
            summary.entries_skipped += 1;
            return err;
        };
        defer gpa.free(bytes);
        const target = try std.fs.path.join(gpa, &.{ out_dir, entry.name });
        defer gpa.free(target);
        if (std.fs.path.dirname(entry.name)) |dir| {
            const dir_path = try std.fs.path.join(gpa, &.{ out_dir, dir });
            defer gpa.free(dir_path);
            try Dir.cwd().createDirPath(io, dir_path);
        }
        const file = try Dir.cwd().createFile(io, target, .{ .truncate = true });
        defer file.close(io);
        try file.writeStreamingAll(io, bytes);
        summary.files_written += 1;
        summary.bytes_written += bytes.len;
    }
    return summary;
}

/// Reject anything that could escape the destination directory.
pub fn isSafeName(name: []const u8) bool {
    if (name.len == 0 or name.len > 4096) return false;
    if (name[0] == '/' or name[0] == '\\') return false;
    if (std.mem.indexOfScalar(u8, name, '\\') != null) return false;
    if (name.len >= 2 and name[1] == ':') return false;
    var it = std.mem.splitScalar(u8, name, '/');
    while (it.next()) |segment| {
        if (segment.len == 0) return false;
        if (std.mem.eql(u8, segment, "..")) return false;
    }
    return true;
}

/// Pull the interesting fields out of a NuGet `.nuspec` document.
pub fn parseNuspec(text: []const u8) Nuspec {
    var result: Nuspec = .{};
    const fields = [_]struct { open: []const u8, close: []const u8, slot: *?[]const u8 }{
        .{ .open = "<id>", .close = "</id>", .slot = &result.id },
        .{ .open = "<version>", .close = "</version>", .slot = &result.version },
        .{ .open = "<channel>", .close = "</channel>", .slot = &result.channel },
        .{ .open = "<rid>", .close = "</rid>", .slot = &result.rid },
        .{ .open = "<os>", .close = "</os>", .slot = &result.os },
        .{ .open = "<mainExe>", .close = "</mainExe>", .slot = &result.main_exe },
        .{ .open = "<runtimeDependencies>", .close = "</runtimeDependencies>", .slot = &result.runtime_dependencies },
    };
    for (fields) |field| {
        const open = field.open;
        const close = field.close;
        const start = std.mem.indexOf(u8, text, open) orelse continue;
        const value_start = start + open.len;
        const end = std.mem.indexOfPos(u8, text, value_start, close) orelse continue;
        var value = text[value_start..end];
        value = std.mem.trim(u8, value, " \t\r\n");
        if (value.len > 0) field.slot.* = value;
    }
    return result;
}

test "overlay detection rejects a file without a zip" {
    try std.testing.expectError(Error.NotVelopack, findOverlay("not a pe file at all"));
}

test "overlay detection and parsing on a synthetic archive" {
    const gpa = std.testing.allocator;
    const payload = "hello velopack";
    var buf: [512]u8 = undefined;
    var len: usize = 0;

    // local file header, stored (method 0)
    @memcpy(buf[len..][0..4], "PK\x03\x04");
    len += 4;
    std.mem.writeInt(u16, buf[len..][0..2], 20, .little);
    len += 2;
    std.mem.writeInt(u16, buf[len..][0..2], 0, .little);
    len += 2;
    std.mem.writeInt(u16, buf[len..][0..2], 0, .little);
    len += 2;
    std.mem.writeInt(u16, buf[len..][0..2], 0, .little);
    len += 2;
    std.mem.writeInt(u16, buf[len..][0..2], 0, .little);
    len += 2;
    std.mem.writeInt(u32, buf[len..][0..4], std.hash.crc.Crc32.hash(payload), .little);
    len += 4;
    std.mem.writeInt(u32, buf[len..][0..4], @intCast(payload.len), .little);
    len += 4;
    std.mem.writeInt(u32, buf[len..][0..4], @intCast(payload.len), .little);
    len += 4;
    std.mem.writeInt(u16, buf[len..][0..2], 5, .little);
    len += 2;
    std.mem.writeInt(u16, buf[len..][0..2], 0, .little);
    len += 2;
    @memcpy(buf[len..][0..5], "a.txt");
    len += 5;
    @memcpy(buf[len..][0..payload.len], payload);
    len += payload.len;

    const local_size = len;
    // central directory
    const cd_start = len;
    @memcpy(buf[len..][0..4], "PK\x01\x02");
    len += 4;
    len += 4; // version made by + version needed
    len += 2; // flags
    std.mem.writeInt(u16, buf[len..][0..2], 0, .little);
    len += 2; // method
    len += 2; // time
    len += 2; // date
    std.mem.writeInt(u32, buf[len..][0..4], std.hash.crc.Crc32.hash(payload), .little);
    len += 4;
    std.mem.writeInt(u32, buf[len..][0..4], @intCast(payload.len), .little);
    len += 4;
    std.mem.writeInt(u32, buf[len..][0..4], @intCast(payload.len), .little);
    len += 4;
    std.mem.writeInt(u16, buf[len..][0..2], 5, .little);
    len += 2;
    std.mem.writeInt(u16, buf[len..][0..2], 0, .little);
    len += 2;
    std.mem.writeInt(u16, buf[len..][0..2], 0, .little);
    len += 2;
    len += 2; // disk
    len += 2; // internal attrs
    len += 4; // external attrs
    std.mem.writeInt(u32, buf[len..][0..4], 0, .little);
    len += 4;
    @memcpy(buf[len..][0..5], "a.txt");
    len += 5;
    const cd_size = len - cd_start;

    // EOCD
    @memcpy(buf[len..][0..4], "PK\x05\x06");
    len += 4;
    len += 2; // disk
    len += 2; // cd disk
    std.mem.writeInt(u16, buf[len..][0..2], 1, .little);
    len += 2;
    std.mem.writeInt(u16, buf[len..][0..2], 1, .little);
    len += 2;
    std.mem.writeInt(u32, buf[len..][0..4], @intCast(cd_size), .little);
    len += 4;
    std.mem.writeInt(u32, buf[len..][0..4], @intCast(cd_start), .little);
    len += 4;
    std.mem.writeInt(u16, buf[len..][0..2], 0, .little);
    len += 2;

    const info = try parse(gpa, buf[0..len]);
    defer gpa.free(info.entries);
    try std.testing.expectEqual(@as(usize, 0), info.archive_offset);
    try std.testing.expectEqual(@as(u16, 1), info.entry_count);
    try std.testing.expectEqualStrings("a.txt", info.entries[0].name);

    const data = try readEntry(gpa, buf[0..len], info.archive_offset, info.entries[0]);
    defer gpa.free(data);
    try std.testing.expectEqualStrings(payload, data);
    try std.testing.expectEqual(local_size - payload.len, dataOffset(buf[0..len], info.archive_offset, info.entries[0]));
}

test "path safety rejects escapes" {
    try std.testing.expect(!isSafeName("../evil"));
    try std.testing.expect(!isSafeName("/etc/passwd"));
    try std.testing.expect(!isSafeName("a\\b"));
    try std.testing.expect(!isSafeName("C:/windows"));
    try std.testing.expect(isSafeName("lib/app/LuaTools.dll"));
}
