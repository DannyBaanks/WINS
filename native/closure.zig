//! Static dependency closure of a PE inside an MSI's external cabinet.
//!
//! Starting from one File-table key, extracts members with an external 7-Zip
//! into a NEW directory, parses each PE with pe.zig (imports, delay imports, CLR
//! header) and follows imports that resolve to other files of the MSI. Libraries
//! with no such file are reported as `unresolved` (OS components, redistributables).
//! Nothing extracted is executed. Output is untrusted data.
const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const pe_mod = @import("pe.zig");

pub const LibFns = struct { lib: []const u8, functions: []const []const u8 };
pub const PeRec = struct {
    key: []const u8,
    name: []const u8,
    level: u32,
    machine: u16,
    managed_clr: bool,
    sha256: []const u8,
    size: usize,
    imports: []const LibFns,
    delay: []const LibFns,
};
pub const ErrRec = struct { key: []const u8, @"error": []const u8 };
pub const Report = struct { root: []const u8, pe: []const PeRec, unresolved: []const LibFns, parse_errors: []const ErrRec };

const StrSet = std.StringHashMap(void);

fn lower(a: std.mem.Allocator, s: []const u8) ![]u8 {
    return std.ascii.allocLowerString(a, s);
}

fn lessStr(_: void, x: []const u8, y: []const u8) bool {
    return std.mem.lessThan(u8, x, y);
}

fn symbolNames(a: std.mem.Allocator, syms: []const pe_mod.Import) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (syms) |s| {
        if (s.name) |n| try out.append(a, n) else try out.append(a, try std.fmt.allocPrint(a, "#{d}", .{s.ordinal.?}));
    }
    std.mem.sort([]const u8, out.items, {}, lessStr);
    return out.toOwnedSlice(a);
}

fn libFns(a: std.mem.Allocator, libs: []const pe_mod.Library) ![]const LibFns {
    var out: std.ArrayList(LibFns) = .empty;
    for (libs) |l| try out.append(a, .{ .lib = try lower(a, l.name), .functions = try symbolNames(a, l.symbols) });
    std.mem.sort(LibFns, out.items, {}, struct {
        fn lt(_: void, x: LibFns, y: LibFns) bool {
            return std.mem.lessThan(u8, x.lib, y.lib);
        }
    }.lt);
    return out.toOwnedSlice(a);
}

/// `a` should be an arena: results are not freed individually.
pub fn run(a: std.mem.Allocator, io: Io, cab: []const u8, file_tsv: []const u8, root_key: []const u8, extractor: []const u8, out_dir: []const u8) !Report {
    // MSI `File` table: key -> long file name (after '|'), lower-cased.
    const tsv = try Dir.cwd().readFileAlloc(io, file_tsv, a, .limited(64 * 1024 * 1024));
    var by_name = std.StringHashMap(std.ArrayList([]const u8)).init(a);
    var name_of = std.StringHashMap([]const u8).init(a);
    var lines = std.mem.splitScalar(u8, tsv, '\n');
    var row: usize = 0;
    while (lines.next()) |raw| : (row += 1) {
        if (row < 3) continue; // column names, types, table/primary key
        const line = std.mem.trimEnd(u8, raw, "\r");
        var cols = std.mem.splitScalar(u8, line, '\t');
        const key = cols.next() orelse continue;
        _ = cols.next() orelse continue;
        const fname = cols.next() orelse continue;
        const long = if (std.mem.lastIndexOfScalar(u8, fname, '|')) |i| fname[i + 1 ..] else fname;
        const lname = try lower(a, long);
        const gop = try by_name.getOrPut(lname);
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        try gop.value_ptr.append(a, key);
        try name_of.put(key, lname);
    }

    try Dir.cwd().createDir(io, out_dir, .default_dir); // fails if it exists: never reuse an output directory
    var seen = StrSet.init(a);
    var queue: std.ArrayList([]const u8) = .empty;
    try queue.append(a, root_key);
    var recs: std.ArrayList(PeRec) = .empty;
    var errs: std.ArrayList(ErrRec) = .empty;
    var unresolved = std.StringHashMap(StrSet).init(a);
    var level: u32 = 0;
    while (queue.items.len > 0) : (level += 1) {
        var todo: std.ArrayList([]const u8) = .empty;
        for (queue.items) |k| {
            const gop = try seen.getOrPut(k);
            if (!gop.found_existing) try todo.append(a, k);
        }
        queue.clearRetainingCapacity();
        if (todo.items.len == 0) break;
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(a, &.{ extractor, "x", try std.fmt.allocPrint(a, "-o{s}", .{out_dir}), cab });
        try argv.appendSlice(a, todo.items);
        try argv.append(a, "-y");
        const res = try std.process.run(a, io, .{ .argv = argv.items, .stdout_limit = .limited(64 * 1024 * 1024), .stderr_limit = .limited(1024 * 1024), .timeout = .{ .duration = .{ .raw = .fromSeconds(600), .clock = .awake } } });
        if (res.term != .exited or res.term.exited != 0) {
            try Io.File.stderr().writeStreamingAll(io, res.stderr);
            return error.ExtractionFailed;
        }
        for (todo.items) |k| {
            const path = try std.fmt.allocPrint(a, "{s}/{s}", .{ out_dir, k });
            const bytes = Dir.cwd().readFileAlloc(io, path, a, .limited(512 * 1024 * 1024)) catch |e| {
                try errs.append(a, .{ .key = k, .@"error" = @errorName(e) });
                continue;
            };
            const rep = pe_mod.parse(a, bytes) catch |e| {
                if (e != error.NotPe) try errs.append(a, .{ .key = k, .@"error" = @errorName(e) });
                continue;
            };
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
            const hex = std.fmt.bytesToHex(digest, .lower);
            try recs.append(a, .{
                .key = k,
                .name = name_of.get(k) orelse k,
                .level = level,
                .machine = rep.machine,
                .managed_clr = rep.managed_clr,
                .sha256 = try a.dupe(u8, &hex),
                .size = bytes.len,
                .imports = try libFns(a, rep.libraries),
                .delay = try libFns(a, rep.delay_libraries),
            });
            for ([2][]const pe_mod.Library{ rep.libraries, rep.delay_libraries }) |group| {
                for (group) |lib| {
                    const lname = try lower(a, lib.name);
                    if (by_name.get(lname)) |keys| {
                        for (keys.items) |nk| if (!seen.contains(nk)) try queue.append(a, nk);
                    } else {
                        const gop = try unresolved.getOrPut(lname);
                        if (!gop.found_existing) gop.value_ptr.* = StrSet.init(a);
                        for (lib.symbols) |s| {
                            const n = if (s.name) |nm| nm else try std.fmt.allocPrint(a, "#{d}", .{s.ordinal.?});
                            try gop.value_ptr.put(n, {});
                        }
                    }
                }
            }
        }
    }

    var un: std.ArrayList(LibFns) = .empty;
    var it = unresolved.iterator();
    while (it.next()) |e| {
        var fns: std.ArrayList([]const u8) = .empty;
        var kit = e.value_ptr.keyIterator();
        while (kit.next()) |k| try fns.append(a, k.*);
        std.mem.sort([]const u8, fns.items, {}, lessStr);
        try un.append(a, .{ .lib = e.key_ptr.*, .functions = try fns.toOwnedSlice(a) });
    }
    std.mem.sort(LibFns, un.items, {}, struct {
        fn lt(_: void, x: LibFns, y: LibFns) bool {
            return std.mem.lessThan(u8, x.lib, y.lib);
        }
    }.lt);
    return .{ .root = root_key, .pe = try recs.toOwnedSlice(a), .unresolved = try un.toOwnedSlice(a), .parse_errors = try errs.toOwnedSlice(a) };
}
