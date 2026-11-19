const std = @import("std");
const types = @import("types.zig");

pub const ParseError = error{
    TruncatedFile,
    InvalidMagic,
    UnsupportedEndian,
    Unsupported32Bit,
    FatBinaryUnsupported,
    IncompatibleArchitecture,
    InvalidCmdSize,
    CommandCountMismatch,
    IntegerOverflow,
    OutOfBounds,
    OverlappingSegments,
    InvalidSegmentRange,
    InvalidStringOffset,
    OutOfMemory,
};

pub const ParsedSegment = struct {
    cmd: types.SegmentCommand64,
    sections: []const types.Section64,
    name: []const u8,
};

pub const ParsedDylib = struct {
    name: []const u8,
    weak: bool,
    reexport: bool,
    current_version: u32,
    compatibility_version: u32,
};

pub const ParsedMachO = struct {
    allocator: std.mem.Allocator,
    raw: []const u8,
    header: types.MachHeader64,
    segments: []ParsedSegment,
    dylibs: []ParsedDylib,
    rpaths: [][]const u8,
    main_entry: ?types.EntryPointCommand,
    dyld_info: ?types.DyldInfoCommand,
    exports_trie: ?types.LinkeditDataCommand,
    chained_fixups: ?types.LinkeditDataCommand,
    symtab: ?types.SymtabCommand,
    dysymtab: ?types.DysymtabCommand,
    dylinker: ?[]const u8,
    id_dylib: ?[]const u8,

    pub fn deinit(self: *ParsedMachO) void {
        for (self.segments) |seg| {
            self.allocator.free(seg.sections);
        }
        self.allocator.free(self.segments);
        self.allocator.free(self.dylibs);
        self.allocator.free(self.rpaths);
    }

    pub fn sliceRange(self: *const ParsedMachO, off: u32, size: u32) ParseError![]const u8 {
        const end = std.math.add(u64, off, size) catch return error.IntegerOverflow;
        if (end > self.raw.len) return error.OutOfBounds;
        return self.raw[off..@intCast(end)];
    }
};

fn readStruct(comptime T: type, data: []const u8, offset: usize) ParseError!T {
    const end = std.math.add(usize, offset, @sizeOf(T)) catch return error.IntegerOverflow;
    if (end > data.len) return error.OutOfBounds;
    return std.mem.bytesToValue(T, data[offset..end][0..@sizeOf(T)]);
}

fn readCStringInRange(slice: []const u8, offset: u32) ParseError![]const u8 {
    if (offset >= slice.len) return error.InvalidStringOffset;
    const tail = slice[offset..];
    const nul = std.mem.indexOfScalar(u8, tail, 0) orelse return error.InvalidStringOffset;
    return tail[0..nul];
}

pub fn extractThinSlice(data: []const u8) ParseError![]const u8 {
    if (data.len < 4) return error.TruncatedFile;
    const magic_le = std.mem.readInt(u32, data[0..4], .little);
    const magic_be = std.mem.readInt(u32, data[0..4], .big);

    if (magic_be == types.FAT_MAGIC or magic_le == types.FAT_MAGIC) {
        if (data.len < @sizeOf(types.FatHeader)) return error.TruncatedFile;
        const nfat = std.mem.readInt(u32, data[4..8], .big);
        if (nfat == 0 or nfat > 64) return error.FatBinaryUnsupported;
        const archs_end = std.math.add(usize, @sizeOf(types.FatHeader), @as(usize, nfat) * @sizeOf(types.FatArch)) catch return error.IntegerOverflow;
        if (archs_end > data.len) return error.OutOfBounds;

        var i: usize = 0;
        while (i < nfat) : (i += 1) {
            const off = @sizeOf(types.FatHeader) + i * @sizeOf(types.FatArch);
            const cputype = std.mem.readInt(i32, data[off..][0..4], .big);
            const slice_off = std.mem.readInt(u32, data[off + 8 ..][0..4], .big);
            const slice_size = std.mem.readInt(u32, data[off + 12 ..][0..4], .big);
            if (cputype == types.CPU_TYPE_X86_64) {
                const end = std.math.add(usize, slice_off, slice_size) catch return error.IntegerOverflow;
                if (end > data.len) return error.OutOfBounds;
                return data[slice_off..end];
            }
        }
        return error.IncompatibleArchitecture;
    }
    return data;
}

pub fn parse(allocator: std.mem.Allocator, data: []const u8) ParseError!ParsedMachO {
    return parseWithOptions(allocator, data, false);
}

pub fn parseInspect(allocator: std.mem.Allocator, data: []const u8) ParseError!ParsedMachO {
    return parseWithOptions(allocator, data, true);
}

fn parseWithOptions(allocator: std.mem.Allocator, raw_input: []const u8, allow_any_arch: bool) ParseError!ParsedMachO {
    const data = try extractThinSlice(raw_input);
    if (data.len < 4) return error.TruncatedFile;
    const magic_le = std.mem.readInt(u32, data[0..4], .little);

    if (magic_le == types.MH_CIGAM_64 or magic_le == types.MH_CIGAM) {
        return error.UnsupportedEndian;
    }
    if (magic_le == types.MH_MAGIC) {
        return error.Unsupported32Bit;
    }
    if (magic_le != types.MH_MAGIC_64) {
        return error.InvalidMagic;
    }

    if (data.len < @sizeOf(types.MachHeader64)) return error.TruncatedFile;
    const header = try readStruct(types.MachHeader64, data, 0);

    if (!allow_any_arch and header.cputype != types.CPU_TYPE_X86_64) {
        return error.IncompatibleArchitecture;
    }

    const cmds_start: usize = @sizeOf(types.MachHeader64);
    const cmds_end = std.math.add(usize, cmds_start, header.sizeofcmds) catch return error.IntegerOverflow;
    if (cmds_end > data.len) return error.OutOfBounds;

    var segments: std.ArrayList(ParsedSegment) = .empty;
    errdefer {
        for (segments.items) |seg| allocator.free(seg.sections);
        segments.deinit(allocator);
    }
    var dylibs: std.ArrayList(ParsedDylib) = .empty;
    errdefer dylibs.deinit(allocator);
    var rpaths: std.ArrayList([]const u8) = .empty;
    errdefer rpaths.deinit(allocator);

    var main_entry: ?types.EntryPointCommand = null;
    var dyld_info: ?types.DyldInfoCommand = null;
    var exports_trie: ?types.LinkeditDataCommand = null;
    var chained_fixups: ?types.LinkeditDataCommand = null;
    var symtab: ?types.SymtabCommand = null;
    var dysymtab: ?types.DysymtabCommand = null;
    var dylinker: ?[]const u8 = null;
    var id_dylib: ?[]const u8 = null;

    var cursor: usize = cmds_start;
    var cmd_idx: u32 = 0;
    while (cmd_idx < header.ncmds) : (cmd_idx += 1) {
        if (cursor + @sizeOf(types.LoadCommand) > cmds_end) return error.InvalidCmdSize;
        const lc = try readStruct(types.LoadCommand, data, cursor);
        if (lc.cmdsize < @sizeOf(types.LoadCommand) or (lc.cmdsize % 8) != 0) {
            return error.InvalidCmdSize;
        }
        const next = std.math.add(usize, cursor, lc.cmdsize) catch return error.IntegerOverflow;
        if (next > cmds_end) return error.InvalidCmdSize;

        const cmd_slice = data[cursor..next];
        switch (lc.cmd) {
            types.LC_SEGMENT_64 => {
                if (lc.cmdsize < @sizeOf(types.SegmentCommand64)) return error.InvalidCmdSize;
                const seg = try readStruct(types.SegmentCommand64, data, cursor);
                const sects_bytes = std.math.mul(usize, seg.nsects, @sizeOf(types.Section64)) catch return error.IntegerOverflow;
                const expected_size = std.math.add(usize, @sizeOf(types.SegmentCommand64), sects_bytes) catch return error.IntegerOverflow;
                if (lc.cmdsize != expected_size) return error.InvalidCmdSize;

                const file_end = std.math.add(u64, seg.fileoff, seg.filesize) catch return error.IntegerOverflow;
                if (file_end > data.len) return error.OutOfBounds;
                _ = std.math.add(u64, seg.vmaddr, seg.vmsize) catch return error.IntegerOverflow;
                if (seg.filesize > seg.vmsize and seg.vmsize != 0) return error.InvalidSegmentRange;

                const sects_start = cursor + @sizeOf(types.SegmentCommand64);
                const sections = try allocator.alloc(types.Section64, seg.nsects);
                errdefer allocator.free(sections);
                for (0..seg.nsects) |si| {
                    sections[si] = try readStruct(types.Section64, data, sects_start + si * @sizeOf(types.Section64));
                }

                // Check for overlapping VM segments (ignoring zero-vmsize)
                if (seg.vmsize > 0) {
                    const seg_vm_end = seg.vmaddr + seg.vmsize;
                    for (segments.items) |prev| {
                        if (prev.cmd.vmsize == 0) continue;
                        const prev_vm_end = prev.cmd.vmaddr + prev.cmd.vmsize;
                        if (seg.vmaddr < prev_vm_end and prev.cmd.vmaddr < seg_vm_end) {
                            return error.OverlappingSegments;
                        }
                    }
                }
                if (seg.filesize > 0) {
                    const seg_file_end = seg.fileoff + seg.filesize;
                    for (segments.items) |prev| {
                        if (prev.cmd.filesize == 0) continue;
                        const prev_file_end = prev.cmd.fileoff + prev.cmd.filesize;
                        if (seg.fileoff < prev_file_end and prev.cmd.fileoff < seg_file_end) {
                            return error.OverlappingSegments;
                        }
                    }
                }

                const seg_name_end = std.mem.indexOfScalar(u8, &seg.segname, 0) orelse seg.segname.len;
                try segments.append(allocator, .{
                    .cmd = seg,
                    .sections = sections,
                    .name = data[cursor + @offsetOf(types.SegmentCommand64, "segname") ..][0..seg_name_end],
                });
            },
            types.LC_MAIN => {
                if (lc.cmdsize != @sizeOf(types.EntryPointCommand)) return error.InvalidCmdSize;
                main_entry = try readStruct(types.EntryPointCommand, data, cursor);
            },
            types.LC_LOAD_DYLIB, types.LC_LOAD_WEAK_DYLIB, types.LC_REEXPORT_DYLIB => {
                if (lc.cmdsize < @sizeOf(types.DylibCommand)) return error.InvalidCmdSize;
                const dc = try readStruct(types.DylibCommand, data, cursor);
                const name = try readCStringInRange(cmd_slice, dc.name_offset);
                try dylibs.append(allocator, .{
                    .name = name,
                    .weak = lc.cmd == types.LC_LOAD_WEAK_DYLIB,
                    .reexport = lc.cmd == types.LC_REEXPORT_DYLIB,
                    .current_version = dc.current_version,
                    .compatibility_version = dc.compatibility_version,
                });
            },
            types.LC_ID_DYLIB => {
                if (lc.cmdsize < @sizeOf(types.DylibCommand)) return error.InvalidCmdSize;
                const dc = try readStruct(types.DylibCommand, data, cursor);
                id_dylib = try readCStringInRange(cmd_slice, dc.name_offset);
            },
            types.LC_RPATH => {
                if (lc.cmdsize < @sizeOf(types.RpathCommand)) return error.InvalidCmdSize;
                const rc = try readStruct(types.RpathCommand, data, cursor);
                const path = try readCStringInRange(cmd_slice, rc.path_offset);
                try rpaths.append(allocator, path);
            },
            types.LC_LOAD_DYLINKER => {
                if (lc.cmdsize < 12) return error.InvalidCmdSize;
                const name_off = std.mem.readInt(u32, cmd_slice[8..12], .little);
                dylinker = try readCStringInRange(cmd_slice, name_off);
            },
            types.LC_DYLD_INFO, types.LC_DYLD_INFO_ONLY => {
                if (lc.cmdsize != @sizeOf(types.DyldInfoCommand)) return error.InvalidCmdSize;
                const di = try readStruct(types.DyldInfoCommand, data, cursor);
                inline for (.{
                    .{ di.rebase_off, di.rebase_size },
                    .{ di.bind_off, di.bind_size },
                    .{ di.weak_bind_off, di.weak_bind_size },
                    .{ di.lazy_bind_off, di.lazy_bind_size },
                    .{ di.export_off, di.export_size },
                }) |pair| {
                    const end = std.math.add(u64, pair[0], pair[1]) catch return error.IntegerOverflow;
                    if (end > data.len) return error.OutOfBounds;
                }
                dyld_info = di;
            },
            types.LC_DYLD_EXPORTS_TRIE => {
                if (lc.cmdsize != @sizeOf(types.LinkeditDataCommand)) return error.InvalidCmdSize;
                const ld = try readStruct(types.LinkeditDataCommand, data, cursor);
                const end = std.math.add(u64, ld.dataoff, ld.datasize) catch return error.IntegerOverflow;
                if (end > data.len) return error.OutOfBounds;
                exports_trie = ld;
            },
            types.LC_DYLD_CHAINED_FIXUPS => {
                if (lc.cmdsize != @sizeOf(types.LinkeditDataCommand)) return error.InvalidCmdSize;
                const ld = try readStruct(types.LinkeditDataCommand, data, cursor);
                const end = std.math.add(u64, ld.dataoff, ld.datasize) catch return error.IntegerOverflow;
                if (end > data.len) return error.OutOfBounds;
                chained_fixups = ld;
            },
            types.LC_SYMTAB => {
                if (lc.cmdsize != @sizeOf(types.SymtabCommand)) return error.InvalidCmdSize;
                const st = try readStruct(types.SymtabCommand, data, cursor);
                const syms_bytes = std.math.mul(u64, st.nsyms, @sizeOf(types.Nlist64)) catch return error.IntegerOverflow;
                const syms_end = std.math.add(u64, st.symoff, syms_bytes) catch return error.IntegerOverflow;
                const strs_end = std.math.add(u64, st.stroff, st.strsize) catch return error.IntegerOverflow;
                if (syms_end > data.len or strs_end > data.len) return error.OutOfBounds;
                symtab = st;
            },
            types.LC_DYSYMTAB => {
                if (lc.cmdsize != @sizeOf(types.DysymtabCommand)) return error.InvalidCmdSize;
                dysymtab = try readStruct(types.DysymtabCommand, data, cursor);
            },
            else => {},
        }
        cursor = next;
    }

    if (cursor != cmds_end) return error.CommandCountMismatch;

    return .{
        .allocator = allocator,
        .raw = data,
        .header = header,
        .segments = try segments.toOwnedSlice(allocator),
        .dylibs = try dylibs.toOwnedSlice(allocator),
        .rpaths = try rpaths.toOwnedSlice(allocator),
        .main_entry = main_entry,
        .dyld_info = dyld_info,
        .exports_trie = exports_trie,
        .chained_fixups = chained_fixups,
        .symtab = symtab,
        .dysymtab = dysymtab,
        .dylinker = dylinker,
        .id_dylib = id_dylib,
    };
}
