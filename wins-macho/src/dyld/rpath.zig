const std = @import("std");

pub fn dirname(path: []const u8) []const u8 {
    return std.fs.path.dirname(path) orelse ".";
}

pub fn expandLoadPath(
    allocator: std.mem.Allocator,
    raw_install_name: []const u8,
    executable_path: []const u8,
    loader_path: []const u8,
    rpaths: []const []const u8,
) !?[]u8 {
    const exe_dir = dirname(executable_path);
    const ldr_dir = dirname(loader_path);

    if (std.mem.startsWith(u8, raw_install_name, "@executable_path/")) {
        const rest = raw_install_name["@executable_path/".len..];
        return try std.fmt.allocPrint(allocator, "{s}/{s}", .{ exe_dir, rest });
    }
    if (std.mem.startsWith(u8, raw_install_name, "@loader_path/")) {
        const rest = raw_install_name["@loader_path/".len..];
        return try std.fmt.allocPrint(allocator, "{s}/{s}", .{ ldr_dir, rest });
    }
    if (std.mem.startsWith(u8, raw_install_name, "@rpath/")) {
        const rest = raw_install_name["@rpath/".len..];
        for (rpaths) |rp| {
            var base_buf: ?[]u8 = null;
            defer if (base_buf) |b| allocator.free(b);

            const resolved_rp: []const u8 = if (std.mem.eql(u8, rp, "@executable_path"))
                exe_dir
            else if (std.mem.eql(u8, rp, "@loader_path"))
                ldr_dir
            else if (std.mem.startsWith(u8, rp, "@executable_path/")) blk: {
                base_buf = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ exe_dir, rp["@executable_path/".len..] });
                break :blk base_buf.?;
            } else if (std.mem.startsWith(u8, rp, "@loader_path/")) blk: {
                base_buf = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ ldr_dir, rp["@loader_path/".len..] });
                break :blk base_buf.?;
            } else rp;

            const candidate = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ resolved_rp, rest });
            // Check if file exists on disk
            const c_path = try allocator.dupeZ(u8, candidate);
            defer allocator.free(c_path);
            if (std.c.access(c_path.ptr, 0) == 0) {
                return candidate;
            }
            allocator.free(candidate);
        }
        return null;
    }

    // Absolute or relative path
    const c_path = try allocator.dupeZ(u8, raw_install_name);
    defer allocator.free(c_path);
    if (std.c.access(c_path.ptr, 0) == 0) {
        return try allocator.dupe(u8, raw_install_name);
    }
    return null;
}
