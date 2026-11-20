//! WINS-MachO Native Corpus Analyzer & Pareto Blocker Fuzzer (Zig 0.16)
//!
//! Scans real macOS Mach-O x86_64 binaries (e.g. Homebrew Sonoma bottles), parses
//! LC_LOAD_DYLIB, LC_DYLD_INFO_ONLY, and LC_DYLD_CHAINED_FIXUPS directly, checks
//! every imported symbol against wins-macho's real shim table (and flags stubs
//! honestly), computes per-binary readiness, and outputs a Pareto ranking of the
//! missing Darwin symbols that unblock the most real macOS binaries.

const std = @import("std");
const wins_macho = @import("wins_macho");
const parser = wins_macho.parser;
const exports = wins_macho.exports;
const fixups = wins_macho.fixups;
const shims = wins_macho.shims;
const types = wins_macho.types;

const c_fs = @cImport({
    @cInclude("dirent.h");
    @cInclude("sys/stat.h");
});

const BinaryReport = struct {
    name: []const u8,
    path: []const u8,
    sha256: [64]u8,
    kind: []const u8,
    total_imports: usize,
    resolved_real: usize,
    resolved_stubs: usize,
    missing_imports: usize,
    missing_dylibs: usize,
    readiness_pct: f32,
    status: []const u8,
};

const MissingRecord = struct {
    symbol: []const u8,
    provider: []const u8,
    victim: []const u8,
};

fn readWholeFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const c_path = try allocator.dupeZ(u8, path);
    defer allocator.free(c_path);
    const fd = std.c.open(c_path.ptr, .{ .ACCMODE = .RDONLY }, @as(std.c.mode_t, 0));
    if (fd < 0) return error.FileNotFound;
    defer _ = std.c.close(fd);

    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    var tmp: [32768]u8 = undefined;
    while (true) {
        const n = std.os.linux.read(fd, &tmp, tmp.len);
        const sn: isize = @bitCast(n);
        if (sn < 0) return error.ReadFailed;
        if (sn == 0) break;
        try buf.appendSlice(allocator, tmp[0..@intCast(sn)]);
    }
    return buf.toOwnedSlice(allocator);
}

fn isMachOFile(path: []const u8, allocator: std.mem.Allocator) bool {
    const c_path = allocator.dupeZ(u8, path) catch return false;
    defer allocator.free(c_path);
    const fd = std.c.open(c_path.ptr, .{ .ACCMODE = .RDONLY }, @as(std.c.mode_t, 0));
    if (fd < 0) return false;
    defer _ = std.c.close(fd);
    var hdr: [4]u8 = undefined;
    const n = std.os.linux.read(fd, &hdr, 4);
    const sn: isize = @bitCast(n);
    if (sn != 4) return false;
    const le = std.mem.readInt(u32, &hdr, .little);
    const be = std.mem.readInt(u32, &hdr, .big);
    return le == types.MH_MAGIC_64 or be == types.FAT_MAGIC or le == types.FAT_MAGIC;
}

fn collectMachOFiles(allocator: std.mem.Allocator, dir_path: []const u8, out: *std.ArrayList([]const u8)) !void {
    const c_dir = try allocator.dupeZ(u8, dir_path);
    defer allocator.free(c_dir);
    const dp = c_fs.opendir(c_dir.ptr) orelse return;
    defer _ = c_fs.closedir(dp);

    while (c_fs.readdir(dp)) |ent| {
        const name_ptr: [*:0]const u8 = @ptrCast(&ent.*.d_name);
        const name = std.mem.span(name_ptr);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;

        const full = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir_path, name });
        const c_full = try allocator.dupeZ(u8, full);
        defer allocator.free(c_full);

        var st: c_fs.struct_stat = undefined;
        if (c_fs.lstat(c_full.ptr, &st) != 0) {
            allocator.free(full);
            continue;
        }
        const ftype = st.st_mode & c_fs.S_IFMT;
        if (ftype == c_fs.S_IFDIR) {
            try collectMachOFiles(allocator, full, out);
            allocator.free(full);
        } else if (ftype == c_fs.S_IFREG) {
            if (isMachOFile(full, allocator)) {
                try out.append(allocator, full);
            } else {
                allocator.free(full);
            }
        } else {
            allocator.free(full);
        }
    }
}

fn analyzeBinary(
    allocator: std.mem.Allocator,
    path: []const u8,
    lib_dirs: []const []const u8,
    missing_all: *std.ArrayList(MissingRecord),
) !BinaryReport {
    const raw = try readWholeFile(allocator, path);
    defer allocator.free(raw);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &digest, .{});
    const sha_hex = std.fmt.bytesToHex(digest, .lower);
    const name = std.fs.path.basename(path);

    var parsed = parser.parse(allocator, raw) catch |err| {
        return .{
            .name = name,
            .path = path,
            .sha256 = sha_hex,
            .kind = "INVALID",
            .total_imports = 0,
            .resolved_real = 0,
            .resolved_stubs = 0,
            .missing_imports = 0,
            .missing_dylibs = 0,
            .readiness_pct = 0.0,
            .status = @errorName(err),
        };
    };
    defer parsed.deinit();

    const kind_str: []const u8 = switch (parsed.header.filetype) {
        types.MH_EXECUTE => "EXEC",
        types.MH_DYLIB => "DYLIB",
        types.MH_BUNDLE => "BUNDLE",
        else => "OTHER",
    };

    // Check dylib dependencies
    var missing_dylibs: usize = 0;
    var local_dylib_flags = try allocator.alloc(bool, parsed.dylibs.len);
    defer allocator.free(local_dylib_flags);
    var native_lib_flags = try allocator.alloc(bool, parsed.dylibs.len);
    defer allocator.free(native_lib_flags);
    for (parsed.dylibs, 0..) |d, di| {
        if (shims.nativeLinuxLibraryForDylib(d.name) != null) {
            local_dylib_flags[di] = false;
            native_lib_flags[di] = true;
            continue;
        }
        native_lib_flags[di] = false;
        if (shims.isDarwinSystemDylib(d.name)) {
            local_dylib_flags[di] = false;
            continue;
        }
        // Check if available in any lib_dir by basename
        var found_local = false;
        const base = std.fs.path.basename(d.name);
        for (lib_dirs) |ld| {
            const cand = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ ld, base });
            defer allocator.free(cand);
            const c_cand = try allocator.dupeZ(u8, cand);
            defer allocator.free(c_cand);
            if (std.c.access(c_cand.ptr, 0) == 0) {
                found_local = true;
                break;
            }
        }
        local_dylib_flags[di] = found_local;
        if (!found_local and !d.weak) {
            missing_dylibs += 1;
        }
    }

    // Collect unique imported symbols (from both LC_DYLD_INFO and LC_DYLD_CHAINED_FIXUPS)
    var seen: std.StringHashMapUnmanaged(i32) = .{};
    defer seen.deinit(allocator);

    if (parsed.dyld_info) |di| {
        const streams = [_]struct { off: u32, sz: u32, weak: bool }{
            .{ .off = di.bind_off, .sz = di.bind_size, .weak = false },
            .{ .off = di.lazy_bind_off, .sz = di.lazy_bind_size, .weak = false },
            .{ .off = di.weak_bind_off, .sz = di.weak_bind_size, .weak = true },
        };
        for (streams) |s| {
            if (s.sz == 0) continue;
            const blob = parsed.sliceRange(s.off, s.sz) catch continue;
            const sites = fixups.parseBindOpcodes(allocator, blob, s.weak) catch continue;
            defer allocator.free(sites);
            for (sites) |site| {
                if (site.symbol.len == 0) continue;
                try seen.put(allocator, site.symbol, site.dylib_ordinal);
            }
        }
    }

    if (parsed.chained_fixups) |cf| {
        if (parsed.sliceRange(cf.dataoff, cf.datasize)) |blob| {
            if (fixups.parseChainedImports(allocator, blob)) |imports| {
                defer allocator.free(imports);
                for (imports) |imp| {
                    if (imp.symbol.len == 0) continue;
                    try seen.put(allocator, imp.symbol, imp.dylib_ordinal);
                }
            } else |_| {}
        } else |_| {}
    }

    var total: usize = 0;
    var resolved_real: usize = 0;
    var resolved_stubs: usize = 0;
    var missing: usize = 0;

    const self_trie: ?[]const u8 = if (parsed.exports_trie) |et|
        parsed.sliceRange(et.dataoff, et.datasize) catch null
    else if (parsed.dyld_info) |di|
        (if (di.export_size > 0) parsed.sliceRange(di.export_off, di.export_size) catch null else null)
    else
        null;

    var it = seen.iterator();
    while (it.next()) |entry| {
        const sym = entry.key_ptr.*;
        const ord = entry.value_ptr.*;
        // Ignore self / main-exe bindings
        if (ord == types.BIND_SPECIAL_DYLIB_SELF or ord == types.BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE) continue;
        // Flat/weak bindings satisfied by the image's own exports trie (e.g. C++ weak RTTI/lambdas)
        if (ord == types.BIND_SPECIAL_DYLIB_FLAT_LOOKUP or ord == types.BIND_SPECIAL_DYLIB_WEAK_LOOKUP) {
            if (self_trie) |trie| {
                if (exports.lookupExport(trie, sym) != null) {
                    total += 1;
                    resolved_real += 1;
                    continue;
                }
            }
        }

        var provider_name: []const u8 = "flat_namespace";
        var is_local_dylib = false;
        var is_native_lib = false;
        if (ord > 0 and @as(usize, @intCast(ord - 1)) < parsed.dylibs.len) {
            provider_name = parsed.dylibs[@intCast(ord - 1)].name;
            is_local_dylib = local_dylib_flags[@intCast(ord - 1)];
            is_native_lib = native_lib_flags[@intCast(ord - 1)];
        }
        // Symbols from local Mach-O dylibs (like libonig, libzstd) resolve from that dylib
        if (is_local_dylib) {
            total += 1;
            resolved_real += 1;
            continue;
        }
        if (is_native_lib) {
            total += 1;
            if (shims.lookupNativeLibrarySymbol(provider_name, sym) != null) {
                resolved_real += 1;
                continue;
            }
            missing += 1;
            try missing_all.append(allocator, .{
                .symbol = try allocator.dupe(u8, sym),
                .provider = try allocator.dupe(u8, provider_name),
                .victim = try allocator.dupe(u8, name),
            });
            continue;
        }

        total += 1;
        if (shims.lookup(sym)) |sh| {
            if (sh.status == .STUB_FOR_PROBE_ONLY) {
                resolved_stubs += 1;
            } else {
                resolved_real += 1;
            }
        } else {
            missing += 1;
            try missing_all.append(allocator, .{
                .symbol = try allocator.dupe(u8, sym),
                .provider = try allocator.dupe(u8, provider_name),
                .victim = try allocator.dupe(u8, name),
            });
        }
    }

    const readiness: f32 = if (total == 0)
        100.0
    else
        @as(f32, @floatFromInt(resolved_real + resolved_stubs)) * 100.0 / @as(f32, @floatFromInt(total));

    const status: []const u8 = if (missing_dylibs > 0)
        "BLOCKED_DYLIB"
    else if (missing > 0)
        "BLOCKED_SYMBOLS"
    else if (resolved_stubs > 0)
        "READY_WITH_STUBS"
    else
        "READY";

    return .{
        .name = name,
        .path = path,
        .sha256 = sha_hex,
        .kind = kind_str,
        .total_imports = total,
        .resolved_real = resolved_real,
        .resolved_stubs = resolved_stubs,
        .missing_imports = missing,
        .missing_dylibs = missing_dylibs,
        .readiness_pct = readiness,
        .status = status,
    };
}

const ParetoEntry = struct {
    symbol: []const u8,
    count: usize,
};

fn paretoDesc(_: void, a: ParetoEntry, b: ParetoEntry) bool {
    if (a.count != b.count) return a.count > b.count;
    return std.mem.order(u8, a.symbol, b.symbol) == .lt;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var corpus_dirs: std.ArrayList([]const u8) = .empty;
    defer corpus_dirs.deinit(gpa);
    var lib_dirs: std.ArrayList([]const u8) = .empty;
    defer lib_dirs.deinit(gpa);
    var top_n: usize = 30;
    var json_mode = false;
    var filter_victim: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--lib-dir") and i + 1 < args.len) {
            i += 1;
            try lib_dirs.append(gpa, args[i]);
        } else if (std.mem.eql(u8, a, "--top") and i + 1 < args.len) {
            i += 1;
            top_n = try std.fmt.parseInt(usize, args[i], 10);
        } else if (std.mem.eql(u8, a, "--for") and i + 1 < args.len) {
            i += 1;
            filter_victim = args[i];
        } else if (std.mem.eql(u8, a, "--json")) {
            json_mode = true;
        } else {
            try corpus_dirs.append(gpa, a);
        }
    }

    if (corpus_dirs.items.len == 0) {
        std.debug.print("Usage: wins_macho_corpus [--lib-dir <dir>] [--top N] [--for <binary>] [--json] <corpus_dir> [...]\n", .{});
        std.process.exit(2);
    }

    var files: std.ArrayList([]const u8) = .empty;
    defer {
        for (files.items) |f| gpa.free(f);
        files.deinit(gpa);
    }

    for (corpus_dirs.items) |d| {
        try collectMachOFiles(gpa, d, &files);
    }

    // Automatically add every directory containing a .dylib as a lib_dir search path
    for (files.items) |f| {
        if (std.mem.endsWith(u8, f, ".dylib")) {
            if (std.fs.path.dirname(f)) |dir| {
                var exists = false;
                for (lib_dirs.items) |ld| {
                    if (std.mem.eql(u8, ld, dir)) {
                        exists = true;
                        break;
                    }
                }
                if (!exists) try lib_dirs.append(gpa, dir);
            }
        }
    }

    var reports: std.ArrayList(BinaryReport) = .empty;
    defer reports.deinit(gpa);
    var missing_all: std.ArrayList(MissingRecord) = .empty;
    defer {
        for (missing_all.items) |m| {
            gpa.free(m.symbol);
            gpa.free(m.provider);
            gpa.free(m.victim);
        }
        missing_all.deinit(gpa);
    }

    for (files.items) |f| {
        const rep = try analyzeBinary(gpa, f, lib_dirs.items, &missing_all);
        try reports.append(gpa, rep);
    }

    // Compute Pareto blocker counts
    var sym_counts: std.StringHashMapUnmanaged(usize) = .{};
    defer sym_counts.deinit(gpa);
    for (missing_all.items) |m| {
        const gop = try sym_counts.getOrPut(gpa, m.symbol);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += 1;
    }

    var pareto: std.ArrayList(ParetoEntry) = .empty;
    defer pareto.deinit(gpa);
    var sit = sym_counts.iterator();
    while (sit.next()) |e| {
        try pareto.append(gpa, .{ .symbol = e.key_ptr.*, .count = e.value_ptr.* });
    }
    std.mem.sort(ParetoEntry, pareto.items, {}, paretoDesc);

    var ready_count: usize = 0;
    var exec_count: usize = 0;
    for (reports.items) |r| {
        if (std.mem.eql(u8, r.kind, "EXEC")) exec_count += 1;
        if (std.mem.eql(u8, r.status, "READY") or std.mem.eql(u8, r.status, "READY_WITH_STUBS")) {
            ready_count += 1;
        }
    }

    if (json_mode) {
        std.debug.print("{{\n  \"total_macho\": {d},\n  \"executables\": {d},\n  \"ready\": {d},\n  \"unique_missing_symbols\": {d},\n  \"binaries\": [\n", .{
            reports.items.len,
            exec_count,
            ready_count,
            pareto.items.len,
        });
        for (reports.items, 0..) |r, idx| {
            std.debug.print("    {{\"name\": \"{s}\", \"kind\": \"{s}\", \"sha256\": \"{s}\", \"readiness_pct\": {d:.1}, \"resolved_real\": {d}, \"resolved_stubs\": {d}, \"missing_imports\": {d}, \"missing_dylibs\": {d}, \"status\": \"{s}\"}}{s}\n", .{
                r.name,
                r.kind,
                r.sha256,
                r.readiness_pct,
                r.resolved_real,
                r.resolved_stubs,
                r.missing_imports,
                r.missing_dylibs,
                r.status,
                if (idx + 1 < reports.items.len) "," else "",
            });
        }
        std.debug.print("  ],\n  \"pareto_missing\": [\n", .{});
        const limit = @min(top_n, pareto.items.len);
        for (pareto.items[0..limit], 0..) |p, idx| {
            std.debug.print("    {{\"symbol\": \"{s}\", \"affected_binaries\": {d}}}{s}\n", .{
                p.symbol,
                p.count,
                if (idx + 1 < limit) "," else "",
            });
        }
        std.debug.print("  ]\n}}\n", .{});
        return;
    }

    std.debug.print("\n=== WINS-MACHO CORPUS AUDIT ({d} Mach-O binaries: {d} exec, {d} ready) ===\n", .{
        reports.items.len,
        exec_count,
        ready_count,
    });
    std.debug.print("{s:<24} {s:<6} {s:>7} {s:>10} {s:>6} {s:>6} {s}\n", .{
        "BINARY", "KIND", "READY%", "RES/TOT", "STUBS", "MDYLIB", "STATUS",
    });
    for (reports.items) |r| {
        var frac_buf: [32]u8 = undefined;
        const frac = std.fmt.bufPrint(&frac_buf, "{d}/{d}", .{ r.resolved_real + r.resolved_stubs, r.total_imports }) catch "?";
        std.debug.print("{s:<24} {s:<6} {d:>6.1}% {s:>10} {d:>6} {d:>6} {s}\n", .{
            r.name,
            r.kind,
            r.readiness_pct,
            frac,
            r.resolved_stubs,
            r.missing_dylibs,
            r.status,
        });
    }

    std.debug.print("\n=== PARETO TOP-{d} MISSING DARWIN SYMBOLS ({d} unique) ===\n", .{
        @min(top_n, pareto.items.len),
        pareto.items.len,
    });
    for (pareto.items[0..@min(top_n, pareto.items.len)], 0..) |p, idx| {
        std.debug.print("  {d:>2}. {s:<38} blocks {d} binaries\n", .{ idx + 1, p.symbol, p.count });
    }

    if (filter_victim) |fv| {
        std.debug.print("\n=== MISSING SYMBOLS FOR '{s}' ===\n", .{fv});
        for (missing_all.items) |m| {
            if (std.mem.eql(u8, m.victim, fv)) {
                std.debug.print("  - {s} (from {s})\n", .{ m.symbol, m.provider });
            }
        }
    }
}
