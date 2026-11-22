//! Offline DXBC -> GLSL check for the D3D11 translator.
//! usage: dxbc2glsl OUT_DIR FILE.dxbc...   writes OUT_DIR/<name>.glsl per input
//! (or <name>.err with the translator error) and prints one summary line.
const std = @import("std");
const shader = @import("wins_d3d11_shader.zig");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3) {
        std.debug.print("usage: dxbc2glsl OUT_DIR FILE.dxbc...\n", .{});
        return;
    }
    const cwd = std.Io.Dir.cwd();
    const out_dir = try cwd.openDir(io, args[1], .{});
    var ok: usize = 0;
    var bad: usize = 0;
    for (args[2..]) |path| {
        const bytes = cwd.readFileAlloc(io, path, gpa, .limited(16 << 20)) catch |e| {
            std.debug.print("{s}: read {s}\n", .{ path, @errorName(e) });
            bad += 1;
            continue;
        };
        defer gpa.free(bytes);
        const base = std.fs.path.stem(path);
        var name_buf: [256]u8 = undefined;
        if (shader.translate(gpa, bytes)) |tr_const| {
            var tr = tr_const;
            defer tr.deinit(gpa);
            const name = try std.fmt.bufPrint(&name_buf, "{s}.{s}", .{ base, switch (tr.stage) {
                .compute => "comp",
                .pixel => "frag",
                .geometry => "geom",
                .hull => "tesc",
                .domain => "tese",
                else => "vert",
            } });
            try out_dir.writeFile(io, .{ .sub_path = name, .data = tr.glsl });
            ok += 1;
        } else |e| {
            const name = try std.fmt.bufPrint(&name_buf, "{s}.err", .{base});
            var msg_buf: [512]u8 = undefined;
            const msg = try std.fmt.bufPrint(&msg_buf, "{s}: {s}\n", .{ @errorName(e), shader.last_error });
            try out_dir.writeFile(io, .{ .sub_path = name, .data = msg });
            bad += 1;
        }
    }
    std.debug.print("translated {d}, failed {d}\n", .{ ok, bad });
}
