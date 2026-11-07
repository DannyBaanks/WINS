const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;

fn say(io: Io, s: []const u8) !void {
    try Io.File.stdout().writeStreamingAll(io, s);
}
fn fail(io: Io, s: []const u8) noreturn {
    Io.File.stderr().writeStreamingAll(io, s) catch {};
    std.process.exit(1);
}
fn u16le(b: []const u8, p: usize) !u16 {
    if (p > b.len or b.len - p < 2) return error.Truncated;
    return std.mem.readInt(u16, b[p..][0..2], .little);
}
fn u32le(b: []const u8, p: usize) !u32 {
    if (p > b.len or b.len - p < 4) return error.Truncated;
    return std.mem.readInt(u32, b[p..][0..4], .little);
}
fn inspect(gpa: std.mem.Allocator, io: Io, path: []const u8) !void {
    const bytes = try Dir.cwd().readFileAlloc(io, path, gpa, .limited(512 * 1024 * 1024));
    defer gpa.free(bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const hash = std.fmt.bytesToHex(digest, .lower);
    if (bytes.len < 64 or !std.mem.eql(u8, bytes[0..2], "MZ")) return error.NotPe;
    const pe: usize = try u32le(bytes, 0x3c);
    if (pe > bytes.len or bytes.len - pe < 24 or !std.mem.eql(u8, bytes[pe..][0..4], "PE\x00\x00")) return error.NotPe;
    const machine = try u16le(bytes, pe + 4);
    const sections = try u16le(bytes, pe + 6);
    const opt_size = try u16le(bytes, pe + 20);
    const opt = pe + 24;
    if (opt > bytes.len or bytes.len - opt < opt_size or opt_size < 2) return error.Truncated;
    const magic = try u16le(bytes, opt);
    if (magic != 0x10b and magic != 0x20b) return error.NotPe;
    const section_start = opt + opt_size;
    if (section_start > bytes.len or @as(usize, sections) > (bytes.len - section_start) / 40) return error.Truncated;
    const output = try std.fmt.allocPrint(gpa, "SHA256: {s}\nSize: {d}\nPE: {s}, machine=0x{x}, sections={d}\n", .{ &hash, bytes.len, if (magic == 0x20b) "PE32+" else "PE32", machine, sections });
    defer gpa.free(output);
    try say(io, output);
    for (0..sections) |i| {
        const off = section_start + i * 40;
        const name = std.mem.sliceTo(bytes[off..][0..8], 0);
        const raw_size = try u32le(bytes, off + 16);
        const raw_offset = try u32le(bytes, off + 20);
        if (raw_offset > bytes.len or raw_size > bytes.len - raw_offset) return error.Truncated;
        const line = try std.fmt.allocPrint(gpa, "  {s}: offset={d} size={d}\n", .{ name, raw_offset, raw_size });
        defer gpa.free(line);
        try say(io, line);
    }
}
fn imports(gpa: std.mem.Allocator, io: Io, path: []const u8, json: bool) !void {
    const bytes = try Dir.cwd().readFileAlloc(io, path, gpa, .limited(512 * 1024 * 1024));
    defer gpa.free(bytes);
    const report = try @import("pe.zig").parse(gpa, bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const hash = std.fmt.bytesToHex(digest, .lower);
    if (json) {
        const doc = .{ .sha256 = &hash, .size_bytes = bytes.len, .pe = report };
        const output = try std.json.Stringify.valueAlloc(gpa, doc, .{ .whitespace = .indent_2 });
        defer gpa.free(output);
        try say(io, output);
        try say(io, "\n");
        return;
    }
    const header = try std.fmt.allocPrint(gpa, "SHA256: {s}\n{s} machine=0x{x}: {d} libraries, {d} imports\n", .{ &hash, report.format, report.machine, report.libraries.len, report.imports_count });
    defer gpa.free(header);
    try say(io, header);
    for (report.libraries) |lib| {
        const line = try std.fmt.allocPrint(gpa, "  {s} ({d})\n", .{ lib.name, lib.symbols.len });
        defer gpa.free(line);
        try say(io, line);
        for (lib.symbols) |sym| {
            const symbol = if (sym.name) |name| try std.fmt.allocPrint(gpa, "    {s} (hint {d})\n", .{ name, sym.hint.? }) else try std.fmt.allocPrint(gpa, "    ordinal #{d}\n", .{sym.ordinal.?});
            defer gpa.free(symbol);
            try say(io, symbol);
        }
    }
    try say(io, "Delay imports: NOT_ANALYZED\n");
}
fn cabFind(gpa: std.mem.Allocator, io: Io, path: []const u8, member: []const u8, json: bool) !void {
    const file = try Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const stat = try file.stat(io);
    const limit: usize = @intCast(@min(stat.size, 16 * 1024 * 1024));
    const data = try gpa.alloc(u8, limit);
    defer gpa.free(data);
    const n = try file.readPositionalAll(io, data, 0);
    const result = try @import("cab.zig").find(data[0..n], member);
    if (json) {
        const doc = .{ .input_length = stat.size, .metadata_bytes_read = n, .cabinet = result };
        const output = try std.json.Stringify.valueAlloc(gpa, doc, .{ .whitespace = .indent_2 });
        defer gpa.free(output);
        try say(io, output);
        try say(io, "\n");
    } else {
        const output = try std.fmt.allocPrint(gpa, "Member: {s}\nUncompressed bytes: {d}\nCAB folder: {d}, data offset: {d}, compression: {s}\nInput length: {d}; CAB declared: {d}; integrity: {s}\n", .{ result.member, result.uncompressed_size, result.folder_index, result.folder_data_offset, result.compression, stat.size, result.cabinet_declared_bytes, result.integrity });
        defer gpa.free(output);
        try say(io, output);
    }
}
fn extract(gpa: std.mem.Allocator, io: Io, input: []const u8, output: []const u8, tool: []const u8, kind: []const u8) !void {
    if (!std.mem.eql(u8, kind, "7z") and !std.mem.eql(u8, kind, "inno") and !std.mem.eql(u8, kind, "msi")) return error.InvalidExtractor;
    const in_abs = try Dir.cwd().realPathFileAlloc(io, input, gpa);
    defer gpa.free(in_abs);
    const tool_abs = try Dir.cwd().realPathFileAlloc(io, tool, gpa);
    defer gpa.free(tool_abs);
    const input_file = try Dir.cwd().openFile(io, in_abs, .{});
    defer input_file.close(io);
    var header: [8]u8 = undefined;
    const header_len = try input_file.readPositionalAll(io, &header, 0);
    const compound = header_len == header.len and std.mem.eql(u8, &header, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1");
    if (std.mem.eql(u8, kind, "msi") and !compound) return error.NotCompound;
    // A new directory avoids silently overwriting any previous evidence.
    try Dir.cwd().createDir(io, output, .default_dir);
    const out_abs = try Dir.cwd().realPathFileAlloc(io, output, gpa);
    defer gpa.free(out_abs);
    const common = [_][]const u8{ "bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--clearenv", "--setenv", "HOME", "/tmp", "--setenv", "PATH", "/usr/bin:/bin", "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--ro-bind", in_abs, "/input", "--ro-bind", tool_abs, "/extractor", "--bind", out_abs, "/output", "--chdir", "/output", "--", "/extractor" };
    var args: std.ArrayList([]const u8) = .empty;
    defer args.deinit(gpa);
    try args.appendSlice(gpa, &common);
    if (std.mem.eql(u8, kind, "inno")) {
        try args.appendSlice(gpa, &.{ "--extract", "--output-dir", "/output", "/input" });
    } else if (compound) {
        // 7-Zip's auto-detection can descend into an MSI's embedded PE.
        try args.appendSlice(gpa, &.{ "x", "-tCompound", "-y", "/input", "-o/output" });
    } else {
        try args.appendSlice(gpa, &.{ "x", "-y", "/input", "-o/output" });
    }
    const result = try std.process.run(gpa, io, .{ .argv = args.items, .stdout_limit = .limited(1024 * 1024), .stderr_limit = .limited(1024 * 1024), .timeout = .{ .duration = .{ .raw = .fromSeconds(120), .clock = .awake } } });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);
    if (result.term != .exited or result.term.exited != 0) {
        try Io.File.stderr().writeStreamingAll(io, result.stderr);
        return error.ExtractionFailed;
    }
    if (compound and !std.mem.eql(u8, kind, "inno")) {
        try say(io, "Compound streams extracted; application payloads may be external. Output is untrusted.\n");
    } else {
        try say(io, "Extraction complete. Output is untrusted; inspect before use.\n");
    }
}
fn compileC(gpa: std.mem.Allocator, io: Io, source: []const u8, output: []const u8, zig_dir: []const u8) !void {
    const src = try Dir.cwd().realPathFileAlloc(io, source, gpa);
    defer gpa.free(src);
    const zig = try Dir.cwd().realPathFileAlloc(io, zig_dir, gpa);
    defer gpa.free(zig);
    try Dir.cwd().createDir(io, output, .default_dir);
    const out = try Dir.cwd().realPathFileAlloc(io, output, gpa);
    defer gpa.free(out);
    const result = try std.process.run(gpa, io, .{ .argv = &.{
        "bwrap",           "--unshare-all", "--die-with-parent",    "--new-session", "--clearenv",
        "--setenv",        "HOME",          "/tmp",                 "--setenv",      "ZIG_GLOBAL_CACHE_DIR",
        "/tmp/zig-global", "--ro-bind",     "/usr",                 "/usr",          "--symlink",
        "usr/bin",         "/bin",          "--symlink",            "usr/lib",       "/lib",
        "--symlink",       "usr/lib64",     "/lib64",               "--proc",        "/proc",
        "--dev",           "/dev",          "--tmpfs",              "/tmp",          "--ro-bind",
        src,               "/candidate.c",  "--ro-bind",            zig,             "/zig",
        "--bind",          out,             "/output",              "--chdir",       "/tmp",
        "--",              "/zig/zig",      "cc",                   "-shared",       "-fPIC",
        "/candidate.c",    "-o",            "/output/candidate.so",
    }, .stdout_limit = .limited(1024 * 1024), .stderr_limit = .limited(1024 * 1024), .timeout = .{ .duration = .{ .raw = .fromSeconds(120), .clock = .awake } } });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);
    if (result.term != .exited or result.term.exited != 0) {
        try Io.File.stderr().writeStreamingAll(io, result.stderr);
        return error.CompilationFailed;
    }
    try say(io, "Compiled candidate.so. Compilation does not establish PE equivalence.\n");
}
fn compare(gpa: std.mem.Allocator, io: Io, candidate_path: []const u8, oracle_path: []const u8, runner_path: []const u8, iterations: []const u8) !void {
    const count = try std.fmt.parseInt(u64, iterations, 10);
    if (count < 3 or count > 100_000_000) return error.InvalidIterations;
    const candidate = try Dir.cwd().realPathFileAlloc(io, candidate_path, gpa);
    defer gpa.free(candidate);
    const oracle = try Dir.cwd().realPathFileAlloc(io, oracle_path, gpa);
    defer gpa.free(oracle);
    const runner = try Dir.cwd().realPathFileAlloc(io, runner_path, gpa);
    defer gpa.free(runner);
    const result = try std.process.run(gpa, io, .{
        .argv = &.{ "bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--clearenv", "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--chdir", "/tmp", "--ro-bind", candidate, "/candidate.so", "--ro-bind", oracle, "/oracle.so", "--ro-bind", runner, "/runner", "--", "/runner", iterations },
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(30), .clock = .awake } },
    });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);
    try say(io, result.stdout);
    try Io.File.stderr().writeStreamingAll(io, result.stderr);
    if (result.term != .exited or result.term.exited != 0) return error.FuzzFailed;
}
pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len == 3 and std.mem.eql(u8, args[1], "inspect")) {
        inspect(a, io, args[2]) catch |e| {
            std.log.err("inspection: {s}", .{@errorName(e)});
            std.process.exit(1);
        };
    } else if ((args.len == 3 or (args.len == 4 and std.mem.eql(u8, args[3], "--json"))) and std.mem.eql(u8, args[1], "imports")) {
        imports(a, io, args[2], args.len == 4) catch |e| {
            std.log.err("imports: {s}", .{@errorName(e)});
            std.process.exit(1);
        };
    } else if ((args.len == 4 or (args.len == 5 and std.mem.eql(u8, args[4], "--json"))) and std.mem.eql(u8, args[1], "cab-find")) {
        cabFind(a, io, args[2], args[3], args.len == 5) catch |e| {
            std.log.err("cab-find: {s}", .{@errorName(e)});
            std.process.exit(1);
        };
    } else if (args.len == 6 and std.mem.eql(u8, args[1], "extract")) {
        extract(a, io, args[2], args[3], args[4], args[5]) catch |e| {
            std.log.err("extraction: {s}", .{@errorName(e)});
            std.process.exit(1);
        };
    } else if (args.len == 5 and std.mem.eql(u8, args[1], "compile-c")) {
        compileC(a, io, args[2], args[3], args[4]) catch |e| {
            std.log.err("compilation: {s}", .{@errorName(e)});
            std.process.exit(1);
        };
    } else if (args.len == 6 and std.mem.eql(u8, args[1], "compare")) {
        compare(a, io, args[2], args[3], args[4], args[5]) catch |e| {
            std.log.err("comparison: {s}", .{@errorName(e)});
            std.process.exit(1);
        };
    } else fail(io, "Usage: wins-native inspect FILE | cab-find FILE MEMBER [--json] | imports FILE [--json] | extract FILE NEW_OUTPUT_DIR EXTRACTOR_PATH <7z|inno|msi> | compile-c SOURCE NEW_OUTPUT_DIR ZIG_INSTALL_DIR | compare CANDIDATE ORACLE RUNNER ITERATIONS\n");
}
