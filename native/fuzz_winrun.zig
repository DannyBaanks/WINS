//! Run ONLY within the WINS cleanroom: this spawns winrun, which executes PE code.
//!
//! Differential fuzzer for winrun (step 1). The same probe program
//! (testdata/winrun_probe.zig) is compiled twice: as a Windows PE, run through
//! winrun, and as a Linux ELF, the reference. For random stdin inputs both must
//! produce identical stdout, stderr and termination (exit code or signal).
//!   usage: fuzz_winrun WINRUN PE SHA256 REFERENCE ITERATIONS [SEED]
//! What this demonstrates is narrow: winrun maps, relocates, binds and runs THIS
//! probe like a native build does. It says nothing about other PEs, about real
//! Windows (the reference layer models the documented kernel32 behaviour) or
//! about any API outside the six kernel32 functions the probe imports.
const std = @import("std");
const Io = std.Io;

const Run = struct { term: std.process.Child.Term, out: []u8, err: []u8 };

fn runOne(a: std.mem.Allocator, io: Io, argv: []const []const u8) !Run {
    const tmp = Io.Dir.cwd();
    const in = try tmp.openFile(io, "/tmp/fz-in", .{});
    defer in.close(io);
    const out = try tmp.createFile(io, "/tmp/fz-out", .{ .truncate = true });
    const err = try tmp.createFile(io, "/tmp/fz-err", .{ .truncate = true });
    var child = try std.process.spawn(io, .{ .argv = argv, .stdin = .{ .file = in }, .stdout = .{ .file = out }, .stderr = .{ .file = err } });
    out.close(io);
    err.close(io);
    const term = try child.wait(io);
    return .{
        .term = term,
        .out = try tmp.readFileAlloc(io, "/tmp/fz-out", a, .limited(1 << 22)),
        .err = try tmp.readFileAlloc(io, "/tmp/fz-err", a, .limited(1 << 20)),
    };
}

fn termEql(x: std.process.Child.Term, y: std.process.Child.Term) bool {
    return std.meta.eql(x, y);
}

fn genInput(r: std.Random, buf: []u8) []u8 {
    const len: usize = switch (r.uintLessThan(u8, 10)) {
        0 => 0,
        1 => r.uintLessThan(usize, 4),
        2 => 65536 + r.uintLessThan(usize, 9000), // beyond the probe's 64 KiB buffer
        3, 4 => r.uintLessThan(usize, 20000),
        else => r.uintLessThan(usize, 600),
    };
    const s = buf[0..len];
    switch (r.uintLessThan(u8, 3)) {
        0 => r.bytes(s),
        1 => for (s) |*c| {
            c.* = 0x20 + r.uintLessThan(u8, 0x5f);
        },
        else => for (s) |*c| {
            c.* = "\x00\n\r\xffAz09 \x7f"[r.uintLessThan(usize, 11)];
        },
    }
    return s;
}

fn hexdump(w: anytype, b: []const u8) void {
    for (b[0..@min(b.len, 64)]) |c| w.print("{x:0>2} ", .{c});
    if (b.len > 64) w.print("... ({d} bytes)", .{b.len});
    w.print("\n", .{});
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 6 and args.len != 7) return error.InvalidArguments;
    const iterations = try std.fmt.parseInt(u32, args[5], 10);
    const seed: u64 = if (args.len == 7) try std.fmt.parseInt(u64, args[6], 0) else 0x77696e72756e;
    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    const buf = try gpa.alloc(u8, 80000);
    defer gpa.free(buf);

    const pe_argv = [_][]const u8{ args[1], "--sha256", args[3], args[2] };
    const ref_argv = [_][]const u8{args[4]};
    var by_return: usize = 0;
    var by_exitprocess: usize = 0;
    var oversized: usize = 0;
    var bytes_out: usize = 0;
    const d = std.debug;

    for (0..iterations) |it| {
        const input = genInput(r, buf);
        try Io.Dir.cwd().writeFile(io, .{ .sub_path = "/tmp/fz-in", .data = input });
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const got = try runOne(a, io, &pe_argv);
        const want = try runOne(a, io, &ref_argv);
        if (!termEql(got.term, want.term) or !std.mem.eql(u8, got.out, want.out) or !std.mem.eql(u8, got.err, want.err)) {
            d.print("DIVERGENCE iter={d} seed=0x{x} len={d}\n  winrun term={any} stdout={d}B stderr={d}B\n  native term={any} stdout={d}B stderr={d}B\n", .{ it, seed, input.len, got.term, got.out.len, got.err.len, want.term, want.out.len, want.err.len });
            if (got.err.len != 0) d.print("  winrun stderr: {s}\n", .{got.err[0..@min(got.err.len, 400)]});
            const dbg = struct {
                fn print(comptime f: []const u8, x: anytype) void {
                    std.debug.print(f, x);
                }
            };
            d.print("  input: ", .{});
            hexdump(dbg, input);
            std.process.exit(1);
        }
        if (input.len > 1 and input[1] % 5 == 0) by_return += 1 else by_exitprocess += 1;
        if (input.len > 65536) oversized += 1;
        bytes_out += got.out.len;
    }
    d.print("MATCHED iterations={d} seed=0x{x} exit_paths[return={d} ExitProcess={d}] oversized_inputs={d} stdout_bytes={d}; this probe only, not a general PE loader\n", .{ iterations, seed, by_return, by_exitprocess, oversized, bytes_out });
}
