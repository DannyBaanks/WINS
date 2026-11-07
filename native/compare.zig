const std = @import("std");
const Fn = *const fn (u64) callconv(.c) u64;
pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 2) return error.InvalidArguments;
    const count = try std.fmt.parseInt(u64, args[1], 10);
    if (count < 3 or count > 100_000_000) return error.InvalidIterations;
    var candidate = try std.DynLib.open("/candidate.so");
    defer candidate.close();
    var oracle = try std.DynLib.open("/oracle.so");
    defer oracle.close();
    const got = candidate.lookup(Fn, "wins_candidate") orelse return error.MissingCandidate;
    const expected = oracle.lookup(Fn, "wins_oracle") orelse return error.MissingOracle;
    var state: u64 = 0x9e3779b97f4a7c15;
    for (0..count) |i| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        const x: u64 = switch (i) {
            0 => 0,
            1 => 1,
            2 => std.math.maxInt(u64),
            else => state,
        };
        const want = expected(x);
        const actual = got(x);
        if (actual != want) {
            const message = try std.fmt.allocPrint(a, "DIVERGENCE iteration={d} input={d} expected={d} actual={d}\n", .{ i, x, want, actual });
            try std.Io.File.stdout().writeStreamingAll(init.io, message);
            std.process.exit(2);
        }
    }
    const message = try std.fmt.allocPrint(a, "MATCHED samples={d} seed=11400714819323198485 (not a proof of equivalence)\n", .{count});
    try std.Io.File.stdout().writeStreamingAll(init.io, message);
}
