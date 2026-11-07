//! Run ONLY within the WINS cleanroom: opening a library executes constructors.
const std = @import("std");
const Set = *const fn (u32) callconv(.c) void;
const Get = *const fn () callconv(.c) u32;
const Shared = struct {
    set: Set,
    get: Get,
    ready: std.atomic.Value(u8) = .init(0),
    release: std.atomic.Value(u8) = .init(0),
    worker_result: u32 = 0,
};
fn worker(s: *Shared) void {
    s.set(0xfedcba98);
    s.ready.store(1, .release);
    while (s.release.load(.acquire) == 0) std.atomic.spinLoopHint();
    s.worker_result = s.get();
}
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) return error.InvalidArguments;
    const iterations = try std.fmt.parseInt(u32, args[2], 10);
    if (iterations < 3 or iterations > 10_000_000) return error.InvalidIterations;
    var lib = try std.DynLib.open(args[1]);
    defer lib.close();
    const set = lib.lookup(Set, "SetLastError") orelse return error.MissingSetLastError;
    const get = lib.lookup(Get, "GetLastError") orelse return error.MissingGetLastError;
    var state: u32 = 0x6d2b79f5;
    for (0..iterations) |i| {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        const input: u32 = switch (i) {
            0 => 0,
            1 => 1,
            2 => std.math.maxInt(u32),
            else => state,
        };
        set(input);
        const got = get();
        if (got != input) {
            std.debug.print("DIVERGENCE case={d} input={d} actual={d}\n", .{ i, input, got });
            return error.ValueMismatch;
        }
    }
    var s = Shared{ .set = set, .get = get };
    set(0x12345678);
    const child = try std.Thread.spawn(.{}, worker, .{&s});
    while (s.ready.load(.acquire) == 0) std.atomic.spinLoopHint();
    const main_value = get();
    s.release.store(1, .release);
    child.join();
    if (main_value != 0x12345678 or s.worker_result != 0xfedcba98) {
        std.debug.print("DIVERGENCE thread main={x} worker={x}\n", .{ main_value, s.worker_result });
        return error.ThreadIsolationMismatch;
    }
    std.debug.print("MATCHED iterations={d} seed=0x6d2b79f5 thread_isolation=observed; not a PE port\n", .{iterations});
}
