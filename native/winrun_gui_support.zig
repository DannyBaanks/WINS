//! Experimental USER32 subset for one synthetic built-in STATIC popup.
//! No message loop, callbacks, controls, painting, or general HWND semantics.
const std = @import("std");
const x11 = @import("x11_window.zig");
const W: std.builtin.CallingConvention = .{ .x86_64_win = .{} };
const Rect = extern struct { left: i32, top: i32, right: i32, bottom: i32 };
var connection: ?x11.Connection = null;
var active_window: usize = 0;

fn createWindowExW(ex_style: u32, class: ?[*:0]const u16, title: ?[*:0]const u16, style: u32, x: i32, y: i32, width: i32, height: i32, parent: usize, menu: usize, instance: usize, param: usize) callconv(W) usize {
    if (ex_style != 0 or class == null or title != null or style != 0x90000000 or x != 0 or y != 0 or width <= 0 or height <= 0 or parent != 0 or menu != 0 or instance != 0 or param != 0 or active_window != 0) return 0;
    // Only the predefined STATIC class is modeled. Do not scan unbounded strings.
    if (@intFromPtr(class.?) < 65536) return 0; // integer class atoms are unsupported
    const expected = [_]u16{ 'S', 'T', 'A', 'T', 'I', 'C', 0 };
    for (expected, 0..) |c, i| if (class.?[i] != c) return 0;
    const conn = x11.Connection.open(":91") catch return 0;
    const window = conn.create(@intCast(width), @intCast(height)) catch {
        conn.close();
        return 0;
    };
    connection = conn;
    active_window = window;
    return window;
}

fn getClientRect(window: usize, rect: ?*Rect) callconv(W) i32 {
    if (window == 0 or window != active_window or rect == null) return 0;
    const geometry = connection.?.geometry(window) catch return 0;
    rect.?.* = .{ .left = 0, .top = 0, .right = @intCast(geometry.width), .bottom = @intCast(geometry.height) };
    return 1;
}

fn destroyWindow(window: usize) callconv(W) i32 {
    if (window == 0 or window != active_window) return 0;
    connection.?.destroy(window);
    connection.?.close();
    connection = null;
    active_window = 0;
    return 1;
}

pub fn lookup(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "CreateWindowExW")) return @intFromPtr(&createWindowExW);
    if (std.mem.eql(u8, name, "GetClientRect")) return @intFromPtr(&getClientRect);
    if (std.mem.eql(u8, name, "DestroyWindow")) return @intFromPtr(&destroyWindow);
    return null;
}
