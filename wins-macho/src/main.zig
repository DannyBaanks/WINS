const std = @import("std");
const wins_macho = @import("wins_macho");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var run_id: []const u8 = "latest";
    var inspect_only = false;
    var quiet = false;
    var write_evidence = true;
    var lib_dirs: std.ArrayList([]const u8) = .empty;
    defer lib_dirs.deinit(allocator);
    var target_path: ?[]const u8 = null;
    var target_args_start: usize = args.len;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--run-id") and i + 1 < args.len) {
            i += 1;
            run_id = args[i];
        } else if (std.mem.eql(u8, arg, "--lib-dir") and i + 1 < args.len) {
            i += 1;
            try lib_dirs.append(allocator, args[i]);
        } else if (std.mem.eql(u8, arg, "--inspect-only")) {
            inspect_only = true;
        } else if (std.mem.eql(u8, arg, "--quiet") or std.mem.eql(u8, arg, "-q")) {
            quiet = true;
        } else if (std.mem.eql(u8, arg, "--no-evidence")) {
            write_evidence = false;
        } else {
            target_path = arg;
            target_args_start = i + 1;
            break;
        }
    }

    const tp = target_path orelse {
        std.debug.print("Usage: wins_macho [--run-id <id>] [--lib-dir <dir>] [--inspect-only] [--quiet] [--no-evidence] <macho_path> [args...]\n", .{});
        std.process.exit(2);
    };

    const target_args = if (target_args_start <= args.len) args[target_args_start..] else &[_][]const u8{};
    const rc = wins_macho.runner.runTarget(allocator, init.io, .{
        .target_path = tp,
        .target_args = target_args,
        .run_id = run_id,
        .inspect_only = inspect_only,
        .write_evidence = write_evidence,
        .lib_dirs = lib_dirs.items,
    }) catch |err| {
        std.debug.print("wins_macho failed: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };

    if (!quiet) {
        std.debug.print("wins_macho: target exited with code {d}\n", .{rc});
    }
    std.process.exit(@intCast(@as(u8, @truncate(@as(u32, @bitCast(rc))))));
}
