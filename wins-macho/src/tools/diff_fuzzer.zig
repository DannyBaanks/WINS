//! WINS-MachO Native Differential Execution Fuzzer (Zig 0.16)
//!
//! Mirrors WINS's native/fuzz_winrun.zig philosophy:
//! Executes a real macOS Mach-O x86_64 binary under `wins_macho --quiet --no-evidence`
//! and compares EVERY deterministic seeded fuzz iteration bit-for-bit against an
//! independent native Linux x86_64 oracle binary (exit code/signal, stdout, stderr).
//!
//! Also supports `--expect-divergence` for mandatory negative-control mutants so
//! we prove the fuzzer genuinely detects single-byte semantic divergences.

const std = @import("std");
const Io = std.Io;

const FuzzMode = enum {
    stdin,
    lines,
    json,
    math,
};

const RunResult = struct {
    term: std.process.Child.Term,
    out: []u8,
    err: []u8,
};

fn runOne(a: std.mem.Allocator, io: Io, argv: []const []const u8, in_path: []const u8, out_path: []const u8, err_path: []const u8) !RunResult {
    const cwd = Io.Dir.cwd();
    const in_f = try cwd.openFile(io, in_path, .{});
    defer in_f.close(io);
    const out_f = try cwd.createFile(io, out_path, .{ .truncate = true });
    const err_f = try cwd.createFile(io, err_path, .{ .truncate = true });
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .{ .file = in_f },
        .stdout = .{ .file = out_f },
        .stderr = .{ .file = err_f },
    });
    out_f.close(io);
    err_f.close(io);
    const term = try child.wait(io);
    return .{
        .term = term,
        .out = try cwd.readFileAlloc(io, out_path, a, .limited(1 << 23)),
        .err = try cwd.readFileAlloc(io, err_path, a, .limited(1 << 21)),
    };
}

fn genStdinBinary(r: std.Random, buf: []u8) []u8 {
    const len: usize = switch (r.uintLessThan(u8, 12)) {
        0 => 0,
        1 => r.uintLessThan(usize, 5),
        2 => 65536 + r.uintLessThan(usize, 8192), // >64 KiB boundary
        3, 4 => r.uintLessThan(usize, 8192),
        else => r.uintLessThan(usize, 512),
    };
    const s = buf[0..len];
    switch (r.uintLessThan(u8, 4)) {
        0 => r.bytes(s),
        1 => for (s) |*c| {
            c.* = 0x20 + r.uintLessThan(u8, 0x5f);
        },
        2 => for (s) |*c| {
            c.* = "\x00\n\r\t\xffAz09 \x7f"[r.uintLessThan(usize, 12)];
        },
        else => {
            // Mix ASCII + valid UTF-8 multibyte tokens
            const toks = [_][]const u8{ "alpha", "beta", "123", "\n", " ", "ñ", "€", "⚡", "WINS", "\t" };
            var pos: usize = 0;
            while (pos < len) {
                const t = toks[r.uintLessThan(usize, toks.len)];
                const take = @min(t.len, len - pos);
                @memcpy(s[pos .. pos + take], t[0..take]);
                pos += take;
            }
        },
    }
    return s;
}

fn genLines(r: std.Random, out: *std.ArrayList(u8), a: std.mem.Allocator) !void {
    const words = [_][]const u8{
        "alpha", "beta", "gamma", "delta", "wins", "macho", "linux", "darwin",
        "0", "1", "42", "-7", "999", "foo_bar", "cafe", "hello", "world", "",
    };
    const nlines = r.uintLessThan(usize, 40);
    for (0..nlines) |_| {
        const nfields = 1 + r.uintLessThan(usize, 5);
        for (0..nfields) |fi| {
            if (fi > 0) try out.append(a, if (r.boolean()) ' ' else '\t');
            try out.appendSlice(a, words[r.uintLessThan(usize, words.len)]);
        }
        try out.append(a, '\n');
    }
}

fn genJsonValue(r: std.Random, out: *std.ArrayList(u8), a: std.mem.Allocator, depth: usize) !void {
    const max_kind: u8 = if (depth >= 3) 4 else 6;
    switch (r.uintLessThan(u8, max_kind)) {
        0 => try out.appendSlice(a, if (r.boolean()) "true" else "false"),
        1 => try out.appendSlice(a, "null"),
        2 => {
            const v: i32 = r.intRangeAtMost(i32, -5000, 5000);
            var nb: [24]u8 = undefined;
            const s = std.fmt.bufPrint(&nb, "{d}", .{v}) catch "0";
            try out.appendSlice(a, s);
        },
        3 => {
            const strs = [_][]const u8{ "", "a", "wins", "mach-o", "line\\n2", "quote\\\"ok", "café", "42" };
            try out.append(a, '"');
            try out.appendSlice(a, strs[r.uintLessThan(usize, strs.len)]);
            try out.append(a, '"');
        },
        4 => {
            try out.append(a, '[');
            const n = r.uintLessThan(usize, 5);
            for (0..n) |i| {
                if (i > 0) try out.append(a, ',');
                try genJsonValue(r, out, a, depth + 1);
            }
            try out.append(a, ']');
        },
        else => {
            const keys = [_][]const u8{ "a", "b", "id", "val", "items", "meta", "x" };
            try out.append(a, '{');
            const n = r.uintLessThan(usize, 4);
            for (0..n) |i| {
                if (i > 0) try out.append(a, ',');
                try out.append(a, '"');
                try out.appendSlice(a, keys[(i + r.uintLessThan(usize, 2)) % keys.len]);
                try out.appendSlice(a, "\":");
                try genJsonValue(r, out, a, depth + 1);
            }
            try out.append(a, '}');
        },
    }
}

fn genMath(r: std.Random, out: *std.ArrayList(u8), a: std.mem.Allocator) !void {
    const lines = 1 + r.uintLessThan(usize, 8);
    if (r.boolean()) {
        try out.appendSlice(a, "scale=6\n");
    }
    const ops = [_]u8{ '+', '-', '*' };
    for (0..lines) |_| {
        const a_val = r.intRangeAtMost(u64, 1, 999999);
        const b_val = r.intRangeAtMost(u64, 1, 999999);
        const c_val = r.intRangeAtMost(u64, 1, 997);
        const op = ops[r.uintLessThan(usize, ops.len)];
        var nb: [128]u8 = undefined;
        const expr = if (r.boolean())
            std.fmt.bufPrint(&nb, "({d} {c} {d}) / {d}\n", .{ a_val, op, b_val, c_val }) catch "1+1\n"
        else
            std.fmt.bufPrint(&nb, "{d} * {d} + {d}\n", .{ a_val, b_val, c_val }) catch "2*3\n";
        try out.appendSlice(a, expr);
    }
}

fn firstDiffIndex(a: []const u8, b: []const u8) usize {
    const lim = @min(a.len, b.len);
    for (0..lim) |i| {
        if (a[i] != b[i]) return i;
    }
    return lim;
}

fn hexdumpPreview(bytes: []const u8) void {
    for (bytes[0..@min(bytes.len, 48)]) |b| std.debug.print("{x:0>2} ", .{b});
    if (bytes.len > 48) std.debug.print("... ({d}B)", .{bytes.len});
    std.debug.print("\n", .{});
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var loader_path: ?[]const u8 = null;
    var macho_path: ?[]const u8 = null;
    var oracle_path: ?[]const u8 = null;
    var mode: FuzzMode = .stdin;
    var iterations: u32 = 100;
    var seed: u64 = 0x57494e534d414348; // "WINSMACH"
    var expect_divergence = false;
    var ignore_stderr = false;
    var lib_dirs: std.ArrayList([]const u8) = .empty;
    defer lib_dirs.deinit(gpa);
    var target_args: []const []const u8 = &.{};

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--loader") and i + 1 < args.len) {
            i += 1;
            loader_path = args[i];
        } else if (std.mem.eql(u8, a, "--macho") and i + 1 < args.len) {
            i += 1;
            macho_path = args[i];
        } else if (std.mem.eql(u8, a, "--oracle") and i + 1 < args.len) {
            i += 1;
            oracle_path = args[i];
        } else if (std.mem.eql(u8, a, "--lib-dir") and i + 1 < args.len) {
            i += 1;
            try lib_dirs.append(gpa, args[i]);
        } else if (std.mem.eql(u8, a, "--mode") and i + 1 < args.len) {
            i += 1;
            if (std.mem.eql(u8, args[i], "stdin")) mode = .stdin else if (std.mem.eql(u8, args[i], "lines")) mode = .lines else if (std.mem.eql(u8, args[i], "json")) mode = .json else if (std.mem.eql(u8, args[i], "math")) mode = .math else return error.InvalidMode;
        } else if (std.mem.eql(u8, a, "--iterations") and i + 1 < args.len) {
            i += 1;
            iterations = try std.fmt.parseInt(u32, args[i], 10);
        } else if (std.mem.eql(u8, a, "--seed") and i + 1 < args.len) {
            i += 1;
            seed = try std.fmt.parseInt(u64, args[i], 0);
        } else if (std.mem.eql(u8, a, "--expect-divergence")) {
            expect_divergence = true;
        } else if (std.mem.eql(u8, a, "--ignore-stderr")) {
            ignore_stderr = true;
        } else if (std.mem.eql(u8, a, "--")) {
            target_args = args[i + 1 ..];
            break;
        }
    }

    const loader = loader_path orelse {
        std.debug.print("Usage: wins_macho_diff --loader <wins_macho> --macho <bin> --oracle <native_bin> [--mode stdin|lines|json|math] [--iterations N] [--seed S] [--lib-dir D] [--expect-divergence] [--ignore-stderr] [-- target_args...]\n", .{});
        std.process.exit(2);
    };
    const macho = macho_path orelse return error.MissingMachO;
    const oracle = oracle_path orelse return error.MissingOracle;

    // Build argv arrays
    var macho_argv: std.ArrayList([]const u8) = .empty;
    defer macho_argv.deinit(gpa);
    try macho_argv.appendSlice(gpa, &.{ loader, "--quiet", "--no-evidence" });
    for (lib_dirs.items) |ld| {
        try macho_argv.appendSlice(gpa, &.{ "--lib-dir", ld });
    }
    try macho_argv.append(gpa, macho);
    try macho_argv.appendSlice(gpa, target_args);

    var oracle_argv: std.ArrayList([]const u8) = .empty;
    defer oracle_argv.deinit(gpa);
    try oracle_argv.append(gpa, oracle);
    try oracle_argv.appendSlice(gpa, target_args);

    const pid = std.os.linux.getpid();
    const in_path = try std.fmt.allocPrint(gpa, "/tmp/wm_diff_{d}_in", .{pid});
    defer gpa.free(in_path);
    const m_out = try std.fmt.allocPrint(gpa, "/tmp/wm_diff_{d}_mout", .{pid});
    defer gpa.free(m_out);
    const m_err = try std.fmt.allocPrint(gpa, "/tmp/wm_diff_{d}_merr", .{pid});
    defer gpa.free(m_err);
    const o_out = try std.fmt.allocPrint(gpa, "/tmp/wm_diff_{d}_oout", .{pid});
    defer gpa.free(o_out);
    const o_err = try std.fmt.allocPrint(gpa, "/tmp/wm_diff_{d}_oerr", .{pid});
    defer gpa.free(o_err);

    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    const raw_buf = try gpa.alloc(u8, 80000);
    defer gpa.free(raw_buf);

    var total_stdout_bytes: usize = 0;
    var ts_start: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts_start);

    for (0..iterations) |it| {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const a = arena.allocator();

        var gen_list: std.ArrayList(u8) = .empty;
        const input: []const u8 = switch (mode) {
            .stdin => genStdinBinary(r, raw_buf),
            .lines => blk: {
                try genLines(r, &gen_list, a);
                break :blk gen_list.items;
            },
            .json => blk: {
                try genJsonValue(r, &gen_list, a, 0);
                try gen_list.append(a, '\n');
                break :blk gen_list.items;
            },
            .math => blk: {
                try genMath(r, &gen_list, a);
                break :blk gen_list.items;
            },
        };

        try Io.Dir.cwd().writeFile(io, .{ .sub_path = in_path, .data = input });
        const got = try runOne(a, io, macho_argv.items, in_path, m_out, m_err);
        const want = try runOne(a, io, oracle_argv.items, in_path, o_out, o_err);

        const same_term = std.meta.eql(got.term, want.term);
        const same_out = std.mem.eql(u8, got.out, want.out);
        const same_err = ignore_stderr or std.mem.eql(u8, got.err, want.err);

        if (!same_term or !same_out or !same_err) {
            if (expect_divergence) {
                std.debug.print("MUTANT_CAUGHT iter={d} seed=0x{x} mode={s} macho_term={any} oracle_term={any} diff_out={} diff_err={}\n", .{
                    it, seed, @tagName(mode), got.term, want.term, !same_out, !same_err,
                });
                return;
            }
            std.debug.print("DIVERGENCE iter={d} seed=0x{x} mode={s} input_len={d}\n", .{ it, seed, @tagName(mode), input.len });
            std.debug.print("  wins_macho: term={any} stdout={d}B stderr={d}B\n", .{ got.term, got.out.len, got.err.len });
            std.debug.print("  oracle:     term={any} stdout={d}B stderr={d}B\n", .{ want.term, want.out.len, want.err.len });
            if (!same_out) {
                const idx = firstDiffIndex(got.out, want.out);
                std.debug.print("  first stdout diff at byte {d}\n", .{idx});
                std.debug.print("  wins_macho stdout: {s}\n", .{got.out[0..@min(got.out.len, 240)]});
                std.debug.print("  oracle     stdout: {s}\n", .{want.out[0..@min(want.out.len, 240)]});
            }
            if (!same_err) {
                std.debug.print("  wins_macho stderr: {s}\n", .{got.err[0..@min(got.err.len, 300)]});
                std.debug.print("  oracle     stderr: {s}\n", .{want.err[0..@min(want.err.len, 300)]});
            }
            std.debug.print("  input hex: ", .{});
            hexdumpPreview(input);
            std.process.exit(1);
        }
        total_stdout_bytes += got.out.len;
    }

    var ts_end: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts_end);
    const dt_ms = @divFloor((@as(i64, ts_end.sec - ts_start.sec) * 1_000_000_000 + (ts_end.nsec - ts_start.nsec)), 1_000_000);

    if (expect_divergence) {
        std.debug.print("NEGATIVE_CONTROL_FAILED: mutant was NOT caught across {d} iterations (seed=0x{x})!\n", .{ iterations, seed });
        std.process.exit(1);
    }

    std.debug.print("MATCHED iterations={d} seed=0x{x} mode={s} stdout_bytes={d} elapsed_ms={d}\n", .{
        iterations, seed, @tagName(mode), total_stdout_bytes, dt_ms,
    });
}
