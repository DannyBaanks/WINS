//! Synthetic client for the X11 window primitive, run only on a private Xvfb.
const std = @import("std");
const x11 = @import("x11");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) return error.InvalidArguments;
    const display = try init.arena.allocator().dupeZ(u8, args[1]);
    const width = try std.fmt.parseInt(u32, args[2], 10);
    const height = try std.fmt.parseInt(u32, args[3], 10);
    const connection = try x11.Connection.open(display);
    defer connection.close();
    const window = try connection.create(width, height);
    defer connection.destroy(window);
    const geometry = try connection.geometry(window);
    if (geometry.width != width or geometry.height != height) return error.UnexpectedGeometry;
    std.debug.print("X11_WINDOW_OK {d}x{d}\n", .{ geometry.width, geometry.height });
}
