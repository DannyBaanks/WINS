//! Experimental USER32 subset for synthetic Win32 GUI windows.
//! Supports class registration, WndProc dispatch, window creation, show/update,
//! message queueing, Translate/Dispatch, DefWindowProcW and PostQuitMessage.
const std = @import("std");
const x11 = @import("x11_window.zig");
const W: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

const Rect = extern struct { left: i32, top: i32, right: i32, bottom: i32 };
const Point = extern struct { x: i32, y: i32 };

const WndProcFn = *const fn (usize, u32, usize, usize) callconv(W) usize;

const WNDCLASSEXW = extern struct {
    cbSize: u32,
    style: u32,
    lpfnWndProc: ?WndProcFn,
    cbClsExtra: i32,
    cbWndExtra: i32,
    hInstance: usize,
    hIcon: usize,
    hCursor: usize,
    hbrBackground: usize,
    lpszMenuName: ?[*:0]const u16,
    lpszClassName: ?[*:0]const u16,
    hIconSm: usize,
};

const WNDCLASSW = extern struct {
    style: u32,
    lpfnWndProc: ?WndProcFn,
    cbClsExtra: i32,
    cbWndExtra: i32,
    hInstance: usize,
    hIcon: usize,
    hCursor: usize,
    hbrBackground: usize,
    lpszMenuName: ?[*:0]const u16,
    lpszClassName: ?[*:0]const u16,
};

const CREATESTRUCTW = extern struct {
    lpCreateParams: usize,
    hInstance: usize,
    hMenu: usize,
    hwndParent: usize,
    cy: i32,
    cx: i32,
    y: i32,
    x: i32,
    style: i32,
    lpszName: ?[*:0]const u16,
    lpszClass: ?[*:0]const u16,
    dwExStyle: u32,
};

const MSG = extern struct {
    hwnd: usize,
    message: u32,
    _pad: u32 = 0,
    wParam: usize,
    lParam: usize,
    time: u32,
    pt: Point,
    lPrivate: u32 = 0,
};

const WM_NULL: u32 = 0x0000;
const WM_CREATE: u32 = 0x0001;
const WM_DESTROY: u32 = 0x0002;
const WM_MOVE: u32 = 0x0003;
const WM_SIZE: u32 = 0x0005;
const WM_PAINT: u32 = 0x000F;
const WM_CLOSE: u32 = 0x0010;
const WM_QUIT: u32 = 0x0012;
const WM_SHOWWINDOW: u32 = 0x0018;
const WM_NCDESTROY: u32 = 0x0082;

var connection: ?x11.Connection = null;
var active_window: usize = 0;
var active_wndproc: ?WndProcFn = null;
var is_visible: i32 = 0;

const RegisteredClass = struct {
    name: [64]u16,
    name_len: usize,
    wndproc: WndProcFn,
    instance: usize,
    atom: u16,
};
var registered_classes: [16]RegisteredClass = undefined;
var num_registered_classes: usize = 0;

const MAX_QUEUE = 32;
var msg_queue: [MAX_QUEUE]MSG = undefined;
var queue_head: usize = 0;
var queue_tail: usize = 0;
var queue_count: usize = 0;
var quit_posted: bool = false;
var quit_exit_code: i32 = 0;

fn pushMsg(msg: MSG) bool {
    if (queue_count >= MAX_QUEUE) return false;
    msg_queue[queue_tail] = msg;
    queue_tail = (queue_tail + 1) % MAX_QUEUE;
    queue_count += 1;
    return true;
}

fn popMsg() ?MSG {
    if (queue_count == 0) return null;
    const m = msg_queue[queue_head];
    queue_head = (queue_head + 1) % MAX_QUEUE;
    queue_count -= 1;
    return m;
}

fn registerClassExW(wcex: ?*const WNDCLASSEXW) callconv(W) u16 {
    if (wcex == null) return 0;
    if (wcex.?.cbSize != @sizeOf(WNDCLASSEXW)) return 0;
    if (wcex.?.lpszClassName == null or wcex.?.lpfnWndProc == null) return 0;
    if (num_registered_classes >= registered_classes.len) return 0;
    if (@intFromPtr(wcex.?.lpszClassName.?) < 65536) return 0;

    var len: usize = 0;
    while (len < 64 and wcex.?.lpszClassName.?[len] != 0) : (len += 1) {}
    if (len == 0 or len >= 64) return 0;

    for (registered_classes[0..num_registered_classes]) |rc| {
        if (rc.name_len == len and std.mem.eql(u16, rc.name[0..len], wcex.?.lpszClassName.?[0..len])) {
            return rc.atom;
        }
    }

    const atom: u16 = @intCast(0xC001 + num_registered_classes);
    var reg = &registered_classes[num_registered_classes];
    @memcpy(reg.name[0..len], wcex.?.lpszClassName.?[0..len]);
    reg.name[len] = 0;
    reg.name_len = len;
    reg.wndproc = wcex.?.lpfnWndProc.?;
    reg.instance = wcex.?.hInstance;
    reg.atom = atom;
    num_registered_classes += 1;
    return atom;
}

fn registerClassW(wc: ?*const WNDCLASSW) callconv(W) u16 {
    if (wc == null or wc.?.lpszClassName == null or wc.?.lpfnWndProc == null) return 0;
    const wcex = WNDCLASSEXW{
        .cbSize = @sizeOf(WNDCLASSEXW),
        .style = wc.?.style,
        .lpfnWndProc = wc.?.lpfnWndProc,
        .cbClsExtra = wc.?.cbClsExtra,
        .cbWndExtra = wc.?.cbWndExtra,
        .hInstance = wc.?.hInstance,
        .hIcon = wc.?.hIcon,
        .hCursor = wc.?.hCursor,
        .hbrBackground = wc.?.hbrBackground,
        .lpszMenuName = wc.?.lpszMenuName,
        .lpszClassName = wc.?.lpszClassName,
        .hIconSm = 0,
    };
    return registerClassExW(&wcex);
}

fn createWindowExW(ex_style: u32, class: ?[*:0]const u16, title: ?[*:0]const u16, style: u32, x: i32, y: i32, width: i32, height: i32, parent: usize, menu: usize, instance: usize, param: usize) callconv(W) usize {
    if (class == null or width <= 0 or height <= 0 or active_window != 0) return 0;

    var target_wndproc: ?WndProcFn = null;
    const is_atom = @intFromPtr(class.?) < 65536;

    if (!is_atom) {
        const static_name = [_]u16{ 'S', 'T', 'A', 'T', 'I', 'C', 0 };
        var is_static = true;
        for (static_name, 0..) |c, i| {
            if (class.?[i] != c) {
                is_static = false;
                break;
            }
        }
        if (is_static) {
            target_wndproc = null;
        } else {
            var len: usize = 0;
            while (len < 64 and class.?[len] != 0) : (len += 1) {}
            var found: ?RegisteredClass = null;
            for (registered_classes[0..num_registered_classes]) |rc| {
                if (rc.name_len == len and std.mem.eql(u16, rc.name[0..len], class.?[0..len])) {
                    found = rc;
                    break;
                }
            }
            if (found) |f| {
                target_wndproc = f.wndproc;
            } else return 0;
        }
    } else {
        const atom_val: u16 = @intCast(@intFromPtr(class.?));
        var found: ?RegisteredClass = null;
        for (registered_classes[0..num_registered_classes]) |rc| {
            if (rc.atom == atom_val) {
                found = rc;
                break;
            }
        }
        if (found) |f| {
            target_wndproc = f.wndproc;
        } else return 0;
    }

    const conn = x11.Connection.open(":91") catch return 0;
    const window = conn.create(@intCast(width), @intCast(height)) catch {
        conn.close();
        return 0;
    };
    connection = conn;
    active_window = window;
    active_wndproc = target_wndproc;

    if (target_wndproc) |proc| {
        const cs = CREATESTRUCTW{
            .lpCreateParams = param,
            .hInstance = instance,
            .hMenu = menu,
            .hwndParent = parent,
            .cy = height,
            .cx = width,
            .y = y,
            .x = x,
            .style = @bitCast(style),
            .lpszName = title,
            .lpszClass = class,
            .dwExStyle = ex_style,
        };
        const res = proc(window, WM_CREATE, 0, @intFromPtr(&cs));
        if (res == @as(usize, @bitCast(@as(isize, -1)))) {
            _ = destroyWindow(window);
            return 0;
        }
    }
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
    if (active_wndproc) |proc| {
        _ = proc(window, WM_DESTROY, 0, 0);
        _ = proc(window, WM_NCDESTROY, 0, 0);
    }
    if (connection) |conn| {
        conn.destroy(window);
        conn.close();
        connection = null;
    }
    active_window = 0;
    active_wndproc = null;
    is_visible = 0;
    return 1;
}

fn showWindow(window: usize, cmd_show: i32) callconv(W) i32 {
    if (window == 0 or window != active_window) return 0;
    const was_visible = is_visible;
    if (cmd_show != 0) {
        is_visible = 1;
        if (connection) |conn| conn.map(window);
    } else {
        is_visible = 0;
        if (connection) |conn| conn.unmap(window);
    }
    return was_visible;
}

fn updateWindow(window: usize) callconv(W) i32 {
    if (window == 0 or window != active_window) return 0;
    if (active_wndproc) |proc| {
        _ = proc(window, WM_PAINT, 0, 0);
    }
    return 1;
}

fn defWindowProcW(window: usize, msg: u32, wparam: usize, lparam: usize) callconv(W) usize {
    _ = wparam;
    _ = lparam;
    if (msg == WM_CLOSE) {
        _ = destroyWindow(window);
        return 0;
    }
    return 0;
}

fn postQuitMessage(exit_code: i32) callconv(W) void {
    quit_posted = true;
    quit_exit_code = exit_code;
}

fn postMessageW(window: usize, msg: u32, wparam: usize, lparam: usize) callconv(W) i32 {
    const m = MSG{
        .hwnd = window,
        .message = msg,
        .wParam = wparam,
        .lParam = lparam,
        .time = 0,
        .pt = .{ .x = 0, .y = 0 },
    };
    return if (pushMsg(m)) 1 else 0;
}

fn sendMessageW(window: usize, msg: u32, wparam: usize, lparam: usize) callconv(W) usize {
    if (window != 0 and window == active_window and active_wndproc != null) {
        return active_wndproc.?(window, msg, wparam, lparam);
    }
    if (window == active_window and msg == WM_CLOSE) {
        _ = destroyWindow(window);
        return 0;
    }
    return 0;
}

fn getMessageW(lp_msg: ?*MSG, window: usize, min_filter: u32, max_filter: u32) callconv(W) i32 {
    _ = window;
    _ = min_filter;
    _ = max_filter;
    if (lp_msg == null) return -1;

    if (popMsg()) |m| {
        lp_msg.?.* = m;
        if (m.message == WM_QUIT) return 0;
        return 1;
    }

    if (quit_posted) {
        lp_msg.?.* = .{
            .hwnd = 0,
            .message = WM_QUIT,
            .wParam = @bitCast(@as(isize, quit_exit_code)),
            .lParam = 0,
            .time = 0,
            .pt = .{ .x = 0, .y = 0 },
        };
        quit_posted = false;
        return 0;
    }

    if (active_window == 0 and queue_count == 0) {
        lp_msg.?.* = .{
            .hwnd = 0,
            .message = WM_QUIT,
            .wParam = 0,
            .lParam = 0,
            .time = 0,
            .pt = .{ .x = 0, .y = 0 },
        };
        return 0;
    }

    return 0;
}

fn peekMessageW(lp_msg: ?*MSG, window: usize, min_filter: u32, max_filter: u32, remove_msg: u32) callconv(W) i32 {
    _ = window;
    _ = min_filter;
    _ = max_filter;
    if (lp_msg == null) return 0;
    if (queue_count > 0) {
        if (remove_msg != 0) {
            lp_msg.?.* = popMsg().?;
        } else {
            lp_msg.?.* = msg_queue[queue_head];
        }
        return 1;
    }
    if (quit_posted) {
        lp_msg.?.* = .{
            .hwnd = 0,
            .message = WM_QUIT,
            .wParam = @bitCast(@as(isize, quit_exit_code)),
            .lParam = 0,
            .time = 0,
            .pt = .{ .x = 0, .y = 0 },
        };
        if (remove_msg != 0) quit_posted = false;
        return 1;
    }
    return 0;
}

fn translateMessage(lp_msg: ?*const MSG) callconv(W) i32 {
    _ = lp_msg;
    return 0;
}

fn dispatchMessageW(lp_msg: ?*const MSG) callconv(W) usize {
    if (lp_msg == null) return 0;
    const m = lp_msg.?.*;
    if (m.hwnd != 0 and m.hwnd == active_window and active_wndproc != null) {
        return active_wndproc.?(m.hwnd, m.message, m.wParam, m.lParam);
    }
    return 0;
}

pub fn lookup(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "CreateWindowExW")) return @intFromPtr(&createWindowExW);
    if (std.mem.eql(u8, name, "GetClientRect")) return @intFromPtr(&getClientRect);
    if (std.mem.eql(u8, name, "DestroyWindow")) return @intFromPtr(&destroyWindow);
    if (std.mem.eql(u8, name, "RegisterClassExW")) return @intFromPtr(&registerClassExW);
    if (std.mem.eql(u8, name, "RegisterClassW")) return @intFromPtr(&registerClassW);
    if (std.mem.eql(u8, name, "DefWindowProcW")) return @intFromPtr(&defWindowProcW);
    if (std.mem.eql(u8, name, "ShowWindow")) return @intFromPtr(&showWindow);
    if (std.mem.eql(u8, name, "UpdateWindow")) return @intFromPtr(&updateWindow);
    if (std.mem.eql(u8, name, "GetMessageW")) return @intFromPtr(&getMessageW);
    if (std.mem.eql(u8, name, "PeekMessageW")) return @intFromPtr(&peekMessageW);
    if (std.mem.eql(u8, name, "TranslateMessage")) return @intFromPtr(&translateMessage);
    if (std.mem.eql(u8, name, "DispatchMessageW")) return @intFromPtr(&dispatchMessageW);
    if (std.mem.eql(u8, name, "PostQuitMessage")) return @intFromPtr(&postQuitMessage);
    if (std.mem.eql(u8, name, "PostMessageW")) return @intFromPtr(&postMessageW);
    if (std.mem.eql(u8, name, "SendMessageW")) return @intFromPtr(&sendMessageW);
    return null;
}
