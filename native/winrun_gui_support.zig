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

fn MessageBoxW(hwnd: usize, lpText: ?[*:0]const u16, lpCaption: ?[*:0]const u16, uType: u32) callconv(W) i32 {
    _ = hwnd; _ = lpText; _ = lpCaption; _ = uType;
    return 1;
}

fn MessageBoxA(hwnd: usize, lpText: ?[*:0]const u8, lpCaption: ?[*:0]const u8, uType: u32) callconv(W) i32 {
    _ = hwnd; _ = lpText; _ = lpCaption; _ = uType;
    return 1;
}

fn GetDC(hwnd: usize) callconv(W) usize {
    _ = hwnd;
    return 0xDC0001;
}

fn ReleaseDC(hwnd: usize, hdc: usize) callconv(W) i32 {
    _ = hwnd; _ = hdc;
    return 1;
}

fn GetSystemMetrics(nIndex: i32) callconv(W) i32 {
    return switch (nIndex) {
        0 => 1920,
        1 => 1080,
        else => 0,
    };
}

fn SetWindowPos(hwnd: usize, hwndInsertAfter: usize, x: i32, y: i32, cx: i32, cy: i32, uFlags: u32) callconv(W) i32 {
    _ = hwnd; _ = hwndInsertAfter; _ = x; _ = y; _ = cx; _ = cy; _ = uFlags;
    return 1;
}

fn GetWindowRect(hwnd: usize, lpRect: ?*Rect) callconv(W) i32 {
    _ = hwnd;
    if (lpRect) |r| {
        r.left = 0;
        r.top = 0;
        r.right = 800;
        r.bottom = 600;
    }
    return 1;
}

fn SetWindowTextW(hwnd: usize, lpString: ?[*:0]const u16) callconv(W) i32 {
    _ = hwnd; _ = lpString;
    return 1;
}

fn SetDlgItemTextW(hDlg: usize, nIDDlgItem: i32, lpString: ?[*:0]const u16) callconv(W) i32 {
    _ = hDlg; _ = nIDDlgItem; _ = lpString;
    return 1;
}

fn GetDlgItemTextW(hDlg: usize, nIDDlgItem: i32, lpString: ?[*]u16, cchMax: i32) callconv(W) i32 {
    _ = hDlg; _ = nIDDlgItem;
    if (lpString != null and cchMax > 0) lpString.?[0] = 0;
    return 0;
}

fn SendDlgItemMessageW(hDlg: usize, nIDDlgItem: i32, msg: u32, wParam: usize, lParam: usize) callconv(W) usize {
    _ = hDlg; _ = nIDDlgItem; _ = msg; _ = wParam; _ = lParam;
    return 0;
}

fn GetDlgItem(hDlg: usize, nIDDlgItem: i32) callconv(W) usize {
    _ = hDlg;
    return 0xDD0000 + @as(usize, @intCast(@max(nIDDlgItem, 0)));
}

fn GetDlgItemInt(hDlg: usize, nIDDlgItem: i32, lpTranslated: ?*i32, bSigned: i32) callconv(W) u32 {
    _ = hDlg; _ = nIDDlgItem; _ = bSigned;
    if (lpTranslated) |p| p.* = 1;
    return 0;
}

fn SetDlgItemInt(hDlg: usize, nIDDlgItem: i32, uValue: u32, bSigned: i32) callconv(W) i32 {
    _ = hDlg; _ = nIDDlgItem; _ = uValue; _ = bSigned;
    return 1;
}

fn DialogBoxParamW(hInstance: usize, lpTemplateName: ?*const anyopaque, hWndParent: usize, lpDialogFunc: ?*const anyopaque, dwInitParam: usize) callconv(W) isize {
    _ = hInstance; _ = lpTemplateName; _ = hWndParent; _ = lpDialogFunc; _ = dwInitParam;
    return 1;
}

fn EndDialog(hDlg: usize, nResult: isize) callconv(W) i32 {
    _ = hDlg; _ = nResult;
    return 1;
}

fn EnableWindow(hWnd: usize, bEnable: i32) callconv(W) i32 {
    _ = hWnd; _ = bEnable;
    return 0;
}

fn LoadImageW(hInst: usize, name: ?*const anyopaque, uType: u32, cx: i32, cy: i32, fuLoad: u32) callconv(W) usize {
    _ = hInst; _ = name; _ = uType; _ = cx; _ = cy; _ = fuLoad;
    return 0x770001;
}

fn SystemParametersInfoW(uiAction: u32, uiParam: u32, pvParam: ?*anyopaque, fWinIni: u32) callconv(W) i32 {
    _ = uiAction; _ = uiParam; _ = pvParam; _ = fWinIni;
    return 1;
}

fn FindWindowExW(hWndParent: usize, hWndChildAfter: usize, lpszClass: ?*const anyopaque, lpszWindow: ?*const anyopaque) callconv(W) usize {
    _ = hWndParent; _ = hWndChildAfter; _ = lpszClass; _ = lpszWindow;
    return 0;
}

fn SetWindowsHookExW(idHook: i32, lpfn: ?*const anyopaque, hmod: usize, dwThreadId: u32) callconv(W) usize {
    _ = idHook; _ = lpfn; _ = hmod; _ = dwThreadId;
    return 0x880001;
}

fn UnhookWindowsHookEx(hhk: usize) callconv(W) i32 {
    _ = hhk;
    return 1;
}

fn CallNextHookEx(hhk: usize, nCode: i32, wParam: usize, lParam: usize) callconv(W) isize {
    _ = hhk; _ = nCode; _ = wParam; _ = lParam;
    return 0;
}

// GDI32.dll
fn GetDeviceCaps(hdc: usize, nIndex: i32) callconv(W) i32 {
    _ = hdc;
    return switch (nIndex) {
        88 => 96,
        90 => 96,
        else => 0,
    };
}

fn CreateFontW(cHeight: i32, cWidth: i32, cEscapement: i32, cOrientation: i32, cWeight: i32, bItalic: u32, bUnderline: u32, bStrikeOut: u32, iCharSet: u32, iOutPrecision: u32, iClipPrecision: u32, iQuality: u32, iPitchAndFamily: u32, pszFaceName: ?[*:0]const u16) callconv(W) usize {
    _ = cHeight; _ = cWidth; _ = cEscapement; _ = cOrientation; _ = cWeight; _ = bItalic; _ = bUnderline; _ = bStrikeOut; _ = iCharSet; _ = iOutPrecision; _ = iClipPrecision; _ = iQuality; _ = iPitchAndFamily; _ = pszFaceName;
    return 0xF0001;
}

fn DeleteObject(ho: usize) callconv(W) i32 {
    _ = ho;
    return 1;
}

fn CreateDIBSection(hdc: usize, pbmi: ?*const anyopaque, usage: u32, ppvBits: ?*?*anyopaque, hSection: usize, offset: u32) callconv(W) usize {
    _ = hdc; _ = pbmi; _ = usage; _ = hSection; _ = offset;
    if (ppvBits) |p| p.* = @ptrFromInt(0x800000);
    return 0xB001;
}

fn SwapBuffers(hdc: usize) callconv(W) i32 {
    _ = hdc;
    return 1;
}

fn ChoosePixelFormat(hdc: usize, ppfd: ?*const anyopaque) callconv(W) i32 {
    _ = hdc; _ = ppfd;
    return 1;
}

fn SetPixelFormat(hdc: usize, format: i32, ppfd: ?*const anyopaque) callconv(W) i32 {
    _ = hdc; _ = format; _ = ppfd;
    return 1;
}

fn BitBlt(hdc: usize, x: i32, y: i32, cx: i32, cy: i32, hdcSrc: usize, x1: i32, y1: i32, rop: u32) callconv(W) i32 {
    _ = hdc; _ = x; _ = y; _ = cx; _ = cy; _ = hdcSrc; _ = x1; _ = y1; _ = rop;
    return 1;
}

fn SelectObject(hdc: usize, h: usize) callconv(W) usize {
    _ = hdc;
    return h;
}

fn CreateCompatibleDC(hdc: usize) callconv(W) usize {
    _ = hdc;
    return 0xB002;
}

fn CreateCompatibleBitmap(hdc: usize, cx: i32, cy: i32) callconv(W) usize {
    _ = hdc; _ = cx; _ = cy;
    return 0xB003;
}

fn GetObjectA(h: usize, c: i32, pv: ?*anyopaque) callconv(W) i32 {
    _ = h; _ = c; _ = pv;
    return 0;
}

fn GetObjectW(h: usize, c: i32, pv: ?*anyopaque) callconv(W) i32 {
    _ = h; _ = c; _ = pv;
    return 0;
}

fn CreateBitmap(nWidth: i32, nHeight: i32, nPlanes: u32, nBitCount: u32, lpBits: ?*const anyopaque) callconv(W) usize {
    _ = nWidth; _ = nHeight; _ = nPlanes; _ = nBitCount; _ = lpBits;
    return 0xB004;
}

fn GetStockObject(i: i32) callconv(W) usize {
    _ = i;
    return 0xB005;
}

pub fn lookupGdi32(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "BitBlt")) return @intFromPtr(&BitBlt);
    if (std.mem.eql(u8, name, "SelectObject")) return @intFromPtr(&SelectObject);
    if (std.mem.eql(u8, name, "CreateCompatibleDC")) return @intFromPtr(&CreateCompatibleDC);
    if (std.mem.eql(u8, name, "CreateCompatibleBitmap")) return @intFromPtr(&CreateCompatibleBitmap);
    if (std.mem.eql(u8, name, "GetObjectA")) return @intFromPtr(&GetObjectA);
    if (std.mem.eql(u8, name, "GetObjectW")) return @intFromPtr(&GetObjectW);
    if (std.mem.eql(u8, name, "CreateBitmap")) return @intFromPtr(&CreateBitmap);
    if (std.mem.eql(u8, name, "GetStockObject")) return @intFromPtr(&GetStockObject);
    if (std.mem.eql(u8, name, "GetDeviceCaps")) return @intFromPtr(&GetDeviceCaps);
    if (std.mem.eql(u8, name, "CreateFontW")) return @intFromPtr(&CreateFontW);
    if (std.mem.eql(u8, name, "DeleteObject")) return @intFromPtr(&DeleteObject);
    if (std.mem.eql(u8, name, "CreateDIBSection")) return @intFromPtr(&CreateDIBSection);
    if (std.mem.eql(u8, name, "SwapBuffers")) return @intFromPtr(&SwapBuffers);
    if (std.mem.eql(u8, name, "ChoosePixelFormat")) return @intFromPtr(&ChoosePixelFormat);
    if (std.mem.eql(u8, name, "SetPixelFormat")) return @intFromPtr(&SetPixelFormat);
    return null;
}

fn ClientToScreen(hwnd: usize, lpPoint: ?*anyopaque) callconv(W) i32 {
    _ = hwnd; _ = lpPoint;
    return 1;
}

fn OpenClipboard(hwnd: usize) callconv(W) i32 {
    _ = hwnd;
    return 1;
}

fn CloseClipboard() callconv(W) i32 {
    return 1;
}

fn EmptyClipboard() callconv(W) i32 {
    return 1;
}

fn GetClipboardData(uFormat: u32) callconv(W) ?*anyopaque {
    _ = uFormat;
    return null;
}

fn SetClipboardData(uFormat: u32, hMem: ?*anyopaque) callconv(W) ?*anyopaque {
    _ = uFormat;
    return hMem;
}

fn CreateDialogParamW(hInstance: usize, lpTemplateName: ?*const anyopaque, hWndParent: usize, lpDialogFunc: ?*const anyopaque, dwInitParam: usize) callconv(W) usize {
    _ = hInstance; _ = lpTemplateName; _ = hWndParent; _ = lpDialogFunc; _ = dwInitParam;
    return 0xD001;
}

fn DestroyCursor(hCursor: usize) callconv(W) i32 {
    _ = hCursor;
    return 1;
}

fn DestroyIcon(hIcon: usize) callconv(W) i32 {
    _ = hIcon;
    return 1;
}

fn GetActiveWindow() callconv(W) usize {
    return 1;
}

fn GetAncestor(hwnd: usize, gaFlags: u32) callconv(W) usize {
    _ = gaFlags;
    return hwnd;
}

fn GetFocus() callconv(W) usize {
    return 1;
}

fn GetKeyState(nVirtKey: i32) callconv(W) i16 {
    _ = nVirtKey;
    return 0;
}

fn GetMessageTime() callconv(W) i32 {
    return 1000;
}

fn PtInRect(lprc: ?*const anyopaque, pt_x: i32, pt_y: i32) callconv(W) i32 {
    _ = lprc; _ = pt_x; _ = pt_y;
    return 1;
}

fn ReleaseCapture() callconv(W) i32 {
    return 1;
}

fn SetCapture(hwnd: usize) callconv(W) usize {
    return hwnd;
}

fn GetCapture() callconv(W) usize {
    return 0;
}

fn GetCursorPos(lpPoint: ?*anyopaque) callconv(W) i32 {
    if (lpPoint) |p| {
        const pt: *Point = @ptrCast(@alignCast(p));
        pt.x = 640;
        pt.y = 360;
    }
    return 1;
}

const MonitorInfo = extern struct {
    cbSize: u32,
    rcMonitor: Rect,
    rcWork: Rect,
    dwFlags: u32,
};

fn GetMonitorInfoW(hMonitor: usize, lpmi: ?*MonitorInfo) callconv(W) i32 {
    _ = hMonitor;
    if (lpmi) |mi| {
        mi.rcMonitor = .{ .left = 0, .top = 0, .right = 1920, .bottom = 1080 };
        mi.rcWork = .{ .left = 0, .top = 0, .right = 1920, .bottom = 1040 };
        mi.dwFlags = 1;
    }
    return 1;
}

fn GetMonitorInfoA(hMonitor: usize, lpmi: ?*MonitorInfo) callconv(W) i32 {
    return GetMonitorInfoW(hMonitor, lpmi);
}

fn MonitorFromPoint(pt_x: i32, pt_y: i32, dwFlags: u32) callconv(W) usize {
    _ = pt_x; _ = pt_y; _ = dwFlags;
    return 0x10001;
}

fn MonitorFromRect(lprc: ?*const anyopaque, dwFlags: u32) callconv(W) usize {
    _ = lprc; _ = dwFlags;
    return 0x10001;
}

fn MonitorFromWindow(hwnd: usize, dwFlags: u32) callconv(W) usize {
    _ = hwnd; _ = dwFlags;
    return 0x10001;
}

fn GetParent(hwnd: usize) callconv(W) usize {
    _ = hwnd;
    return 0;
}

fn GetWindowLongPtrW(hwnd: usize, nIndex: i32) callconv(W) isize {
    _ = hwnd;
    if (nIndex == -16) return 0x10000000 | 0x00cf0000;
    return 0;
}

fn SetWindowLongPtrW(hwnd: usize, nIndex: i32, dwNewLong: isize) callconv(W) isize {
    _ = hwnd; _ = nIndex;
    return dwNewLong;
}

fn GetWindowLongW(hwnd: usize, nIndex: i32) callconv(W) i32 {
    return @truncate(GetWindowLongPtrW(hwnd, nIndex));
}

fn SetWindowLongW(hwnd: usize, nIndex: i32, dwNewLong: i32) callconv(W) i32 {
    return @truncate(SetWindowLongPtrW(hwnd, nIndex, dwNewLong));
}

fn GetWindowLongPtrA(hwnd: usize, nIndex: i32) callconv(W) isize {
    return GetWindowLongPtrW(hwnd, nIndex);
}

fn SetWindowLongPtrA(hwnd: usize, nIndex: i32, dwNewLong: isize) callconv(W) isize {
    return SetWindowLongPtrW(hwnd, nIndex, dwNewLong);
}

fn GetWindowLongA(hwnd: usize, nIndex: i32) callconv(W) i32 {
    return GetWindowLongW(hwnd, nIndex);
}

fn SetWindowLongA(hwnd: usize, nIndex: i32, dwNewLong: i32) callconv(W) i32 {
    return SetWindowLongW(hwnd, nIndex, dwNewLong);
}

const WindowPlacement = extern struct {
    length: u32,
    flags: u32,
    showCmd: u32,
    ptMinPosition: Point,
    ptMaxPosition: Point,
    rcNormalPosition: Rect,
};

fn GetWindowPlacement(hwnd: usize, lpwndpl: ?*WindowPlacement) callconv(W) i32 {
    _ = hwnd;
    if (lpwndpl) |wp| {
        wp.showCmd = 1;
        wp.rcNormalPosition = .{ .left = 0, .top = 0, .right = 1280, .bottom = 720 };
    }
    return 1;
}

fn SetWindowPlacement(hwnd: usize, lpwndpl: ?*const anyopaque) callconv(W) i32 {
    _ = hwnd; _ = lpwndpl;
    return 1;
}

fn IsDialogMessageW(hDlg: usize, lpMsg: ?*const anyopaque) callconv(W) i32 {
    _ = hDlg; _ = lpMsg;
    return 0;
}

fn SetTimer(hwnd: usize, nIDEvent: usize, uElapse: u32, lpTimerFunc: ?*const anyopaque) callconv(W) usize {
    _ = hwnd; _ = uElapse; _ = lpTimerFunc;
    return if (nIDEvent != 0) nIDEvent else 1;
}

fn KillTimer(hwnd: usize, uIDEvent: usize) callconv(W) i32 {
    _ = hwnd; _ = uIDEvent;
    return 1;
}

fn OffsetRect(lprc: ?*Rect, dx: i32, dy: i32) callconv(W) i32 {
    if (lprc) |r| {
        r.left += dx;
        r.right += dx;
        r.top += dy;
        r.bottom += dy;
    }
    return 1;
}

fn CopyRect(lprcDst: ?*Rect, lprcSrc: ?*const Rect) callconv(W) i32 {
    if (lprcDst != null and lprcSrc != null) {
        lprcDst.?.* = lprcSrc.?.*;
    }
    return 1;
}

fn ScreenToClient(hwnd: usize, lpPoint: ?*anyopaque) callconv(W) i32 {
    _ = hwnd; _ = lpPoint;
    return 1;
}

fn SetCursor(hCursor: usize) callconv(W) usize {
    return hCursor;
}

fn ShowCursor(bShow: i32) callconv(W) i32 {
    return if (bShow != 0) 1 else 0;
}

fn SetCursorPos(x: i32, y: i32) callconv(W) i32 {
    _ = x; _ = y;
    return 1;
}

fn ClipCursor(lpRect: ?*const anyopaque) callconv(W) i32 {
    _ = lpRect;
    return 1;
}

fn SetFocus(hwnd: usize) callconv(W) usize {
    return hwnd;
}

fn SetForegroundWindow(hwnd: usize) callconv(W) i32 {
    _ = hwnd;
    return 1;
}

fn TrackMouseEvent(lpEventTrack: ?*anyopaque) callconv(W) i32 {
    _ = lpEventTrack;
    return 1;
}

fn UnregisterClassW(lpClassName: ?*const u16, hInstance: usize) callconv(W) i32 {
    _ = lpClassName; _ = hInstance;
    return 1;
}

fn ValidateRect(hwnd: usize, lpRect: ?*const anyopaque) callconv(W) i32 {
    _ = hwnd; _ = lpRect;
    return 1;
}

fn RegisterRawInputDevices(pRawInputDevices: ?*const anyopaque, uiNumDevices: u32, cbSize: u32) callconv(W) i32 {
    _ = pRawInputDevices; _ = uiNumDevices; _ = cbSize;
    return 1;
}

fn GetRawInputDeviceInfoW(hDevice: usize, uiCommand: u32, pData: ?*anyopaque, pcbSize: ?*u32) callconv(W) u32 {
    _ = hDevice; _ = uiCommand; _ = pData;
    if (pcbSize) |p| p.* = 0;
    return 0;
}

fn GetRawInputData(hRawInput: usize, uiCommand: u32, pData: ?*anyopaque, pcbSize: ?*u32, cbSizeHeader: u32) callconv(W) u32 {
    _ = hRawInput; _ = uiCommand; _ = pData; _ = cbSizeHeader;
    if (pcbSize) |p| p.* = 0;
    return 0;
}

fn GetRawInputDeviceList(pRawInputDeviceList: ?*anyopaque, puiNumDevices: ?*u32, cbSize: u32) callconv(W) u32 {
    _ = pRawInputDeviceList; _ = cbSize;
    if (puiNumDevices) |p| p.* = 0;
    return 0;
}

fn RegisterDeviceNotificationW(hRecipient: usize, NotificationFilter: ?*anyopaque, Flags: u32) callconv(W) usize {
    _ = hRecipient; _ = NotificationFilter; _ = Flags;
    return 0x20001;
}

fn UnregisterDeviceNotification(Handle: usize) callconv(W) i32 {
    _ = Handle;
    return 1;
}

fn GetKeyNameTextW(lParam: i32, lpString: ?[*]u16, cchSize: i32) callconv(W) i32 {
    _ = lParam; _ = lpString; _ = cchSize;
    return 0;
}

fn GetAsyncKeyState(vKey: i32) callconv(W) i16 {
    _ = vKey;
    return 0;
}

fn GetMessagePos() callconv(W) u32 {
    return 0;
}

fn GetMessageExtraInfo() callconv(W) isize {
    return 0;
}

fn DragDetect(hwnd: usize, pt_x: i32, pt_y: i32) callconv(W) i32 {
    _ = hwnd; _ = pt_x; _ = pt_y;
    return 0;
}

fn GetMessageA(lpMsg: ?*anyopaque, hwnd: usize, wMsgFilterMin: u32, wMsgFilterMax: u32) callconv(W) i32 {
    _ = lpMsg; _ = hwnd; _ = wMsgFilterMin; _ = wMsgFilterMax;
    return 0;
}

fn CopyImage(h: usize, uType: u32, cx: i32, cy: i32, uFlags: u32) callconv(W) usize {
    _ = uType; _ = cx; _ = cy; _ = uFlags;
    return h;
}

fn wvsprintfA(lpOut: ?[*]u8, lpFmt: ?[*:0]const u8, arglist: ?*anyopaque) callconv(W) i32 {
    _ = lpFmt; _ = arglist;
    if (lpOut) |p| p[0] = 0;
    return 0;
}

fn wsprintfA(lpOut: ?[*]u8, lpFmt: ?[*:0]const u8) callconv(W) i32 {
    _ = lpFmt;
    if (lpOut) |p| p[0] = 0;
    return 0;
}

fn EnumDisplaySettingsA(lpszDeviceName: ?[*:0]const u8, iModeNum: u32, lpDevMode: ?*anyopaque) callconv(W) i32 {
    _ = lpszDeviceName; _ = iModeNum; _ = lpDevMode;
    return 0;
}

fn EnumDisplaySettingsW(lpszDeviceName: ?*const u16, iModeNum: u32, lpDevMode: ?*anyopaque) callconv(W) i32 {
    _ = lpszDeviceName; _ = iModeNum; _ = lpDevMode;
    return 0;
}

fn ChangeDisplaySettingsW(lpDevMode: ?*anyopaque, dwFlags: u32) callconv(W) i32 {
    _ = lpDevMode; _ = dwFlags;
    return 0;
}

fn EnumDisplayMonitors(hdc: usize, lprcClip: ?*const anyopaque, lpfnEnum: ?*anyopaque, dwData: usize) callconv(W) i32 {
    _ = hdc; _ = lprcClip; _ = lpfnEnum; _ = dwData;
    return 1;
}

fn EnumDisplayDevicesA(lpDevice: ?[*:0]const u8, iDevNum: u32, lpDisplayDevice: ?*anyopaque, dwFlags: u32) callconv(W) i32 {
    _ = lpDevice; _ = iDevNum; _ = lpDisplayDevice; _ = dwFlags;
    return 0;
}

fn GetCaretBlinkTime() callconv(W) u32 {
    return 530;
}

fn IsClipboardFormatAvailable(format: u32) callconv(W) i32 {
    _ = format;
    return 0;
}

fn LoadCursorA(hInstance: usize, lpCursorName: ?*const anyopaque) callconv(W) usize {
    _ = hInstance; _ = lpCursorName;
    return 0x30001;
}

fn LoadIconA(hInstance: usize, lpIconName: ?*const anyopaque) callconv(W) usize {
    _ = hInstance; _ = lpIconName;
    return 0x30002;
}

fn CreateIconIndirect(piconinfo: ?*anyopaque) callconv(W) usize {
    _ = piconinfo;
    return 0x30003;
}

fn GetThreadDesktop(dwThreadId: u32) callconv(W) usize {
    _ = dwThreadId;
    return 0x40001;
}

fn GetUserObjectInformationA(hObj: usize, nIndex: i32, pvInfo: ?*anyopaque, nLength: u32, lpnLengthNeeded: ?*u32) callconv(W) i32 {
    _ = hObj; _ = nIndex; _ = pvInfo; _ = nLength;
    if (lpnLengthNeeded) |p| p.* = 0;
    return 1;
}

fn GetUserObjectInformationW(hObj: usize, nIndex: i32, pvInfo: ?*anyopaque, nLength: u32, lpnLengthNeeded: ?*u32) callconv(W) i32 {
    _ = hObj; _ = nIndex; _ = pvInfo; _ = nLength;
    if (lpnLengthNeeded) |p| p.* = 0;
    return 1;
}

fn GetProcessWindowStation() callconv(W) usize {
    return 0x40002;
}

fn RegisterWindowMessageA(lpString: ?[*:0]const u8) callconv(W) u32 {
    _ = lpString;
    return 0xC001;
}

fn SendMessageA(hwnd: usize, msg: u32, wparam: usize, lparam: isize) callconv(W) isize {
    _ = hwnd; _ = msg; _ = wparam; _ = lparam;
    return 0;
}

fn SendMessageTimeoutA(hwnd: usize, msg: u32, wparam: usize, lparam: isize, fuFlags: u32, uTimeout: u32, lpdwResult: ?*usize) callconv(W) isize {
    _ = hwnd; _ = msg; _ = wparam; _ = lparam; _ = fuFlags; _ = uTimeout;
    if (lpdwResult) |p| p.* = 0;
    return 1;
}

fn EnumWindows(lpEnumFunc: ?*anyopaque, lParam: isize) callconv(W) i32 {
    _ = lpEnumFunc; _ = lParam;
    return 1;
}

fn CreateDialogParamA(hInstance: usize, lpTemplateName: ?*const anyopaque, hWndParent: usize, lpDialogFunc: ?*anyopaque, dwInitParam: isize) callconv(W) usize {
    _ = hInstance; _ = lpTemplateName; _ = hWndParent; _ = lpDialogFunc; _ = dwInitParam;
    return 0x50001;
}

fn DialogBoxParamA(hInstance: usize, lpTemplateName: ?*const anyopaque, hWndParent: usize, lpDialogFunc: ?*anyopaque, dwInitParam: isize) callconv(W) isize {
    _ = hInstance; _ = lpTemplateName; _ = hWndParent; _ = lpDialogFunc; _ = dwInitParam;
    return 1;
}

fn AdjustWindowRectEx(lpRect: ?*Rect, dwStyle: u32, bMenu: i32, dwExStyle: u32) callconv(W) i32 {
    _ = lpRect; _ = dwStyle; _ = bMenu; _ = dwExStyle;
    return 1;
}

fn SetDlgItemTextA(hDlg: usize, nIDDlgItem: i32, lpString: ?[*:0]const u8) callconv(W) i32 {
    _ = hDlg; _ = nIDDlgItem; _ = lpString;
    return 1;
}

fn CheckDlgButton(hDlg: usize, nIDButton: i32, uCheck: u32) callconv(W) i32 {
    _ = hDlg; _ = nIDButton; _ = uCheck;
    return 1;
}

fn IsDlgButtonChecked(hDlg: usize, nIDButton: i32) callconv(W) u32 {
    _ = hDlg; _ = nIDButton;
    return 0;
}

fn GetDesktopWindow() callconv(W) usize {
    return 0x10000;
}

pub fn lookup(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "GetCursorPos")) return @intFromPtr(&GetCursorPos);
    if (std.mem.eql(u8, name, "GetMonitorInfoW")) return @intFromPtr(&GetMonitorInfoW);
    if (std.mem.eql(u8, name, "GetMonitorInfoA")) return @intFromPtr(&GetMonitorInfoA);
    if (std.mem.eql(u8, name, "MonitorFromPoint")) return @intFromPtr(&MonitorFromPoint);
    if (std.mem.eql(u8, name, "MonitorFromRect")) return @intFromPtr(&MonitorFromRect);
    if (std.mem.eql(u8, name, "MonitorFromWindow")) return @intFromPtr(&MonitorFromWindow);
    if (std.mem.eql(u8, name, "GetParent")) return @intFromPtr(&GetParent);
    if (std.mem.eql(u8, name, "GetWindowLongPtrW")) return @intFromPtr(&GetWindowLongPtrW);
    if (std.mem.eql(u8, name, "SetWindowLongPtrW")) return @intFromPtr(&SetWindowLongPtrW);
    if (std.mem.eql(u8, name, "GetWindowLongW")) return @intFromPtr(&GetWindowLongW);
    if (std.mem.eql(u8, name, "SetWindowLongW")) return @intFromPtr(&SetWindowLongW);
    if (std.mem.eql(u8, name, "GetWindowLongPtrA")) return @intFromPtr(&GetWindowLongPtrA);
    if (std.mem.eql(u8, name, "SetWindowLongPtrA")) return @intFromPtr(&SetWindowLongPtrA);
    if (std.mem.eql(u8, name, "GetWindowLongA")) return @intFromPtr(&GetWindowLongA);
    if (std.mem.eql(u8, name, "SetWindowLongA")) return @intFromPtr(&SetWindowLongA);
    if (std.mem.eql(u8, name, "GetWindowPlacement")) return @intFromPtr(&GetWindowPlacement);
    if (std.mem.eql(u8, name, "SetWindowPlacement")) return @intFromPtr(&SetWindowPlacement);
    if (std.mem.eql(u8, name, "IsDialogMessageW")) return @intFromPtr(&IsDialogMessageW);
    if (std.mem.eql(u8, name, "SetTimer")) return @intFromPtr(&SetTimer);
    if (std.mem.eql(u8, name, "KillTimer")) return @intFromPtr(&KillTimer);
    if (std.mem.eql(u8, name, "OffsetRect")) return @intFromPtr(&OffsetRect);
    if (std.mem.eql(u8, name, "CopyRect")) return @intFromPtr(&CopyRect);
    if (std.mem.eql(u8, name, "ScreenToClient")) return @intFromPtr(&ScreenToClient);
    if (std.mem.eql(u8, name, "SetCursor")) return @intFromPtr(&SetCursor);
    if (std.mem.eql(u8, name, "ShowCursor")) return @intFromPtr(&ShowCursor);
    if (std.mem.eql(u8, name, "SetCursorPos")) return @intFromPtr(&SetCursorPos);
    if (std.mem.eql(u8, name, "ClipCursor")) return @intFromPtr(&ClipCursor);
    if (std.mem.eql(u8, name, "SetFocus")) return @intFromPtr(&SetFocus);
    if (std.mem.eql(u8, name, "SetForegroundWindow")) return @intFromPtr(&SetForegroundWindow);
    if (std.mem.eql(u8, name, "TrackMouseEvent")) return @intFromPtr(&TrackMouseEvent);
    if (std.mem.eql(u8, name, "UnregisterClassW")) return @intFromPtr(&UnregisterClassW);
    if (std.mem.eql(u8, name, "ValidateRect")) return @intFromPtr(&ValidateRect);
    if (std.mem.eql(u8, name, "RegisterRawInputDevices")) return @intFromPtr(&RegisterRawInputDevices);
    if (std.mem.eql(u8, name, "GetRawInputDeviceInfoW")) return @intFromPtr(&GetRawInputDeviceInfoW);
    if (std.mem.eql(u8, name, "GetRawInputData")) return @intFromPtr(&GetRawInputData);
    if (std.mem.eql(u8, name, "GetRawInputDeviceList")) return @intFromPtr(&GetRawInputDeviceList);
    if (std.mem.eql(u8, name, "RegisterDeviceNotificationW")) return @intFromPtr(&RegisterDeviceNotificationW);
    if (std.mem.eql(u8, name, "UnregisterDeviceNotification")) return @intFromPtr(&UnregisterDeviceNotification);
    if (std.mem.eql(u8, name, "GetKeyNameTextW")) return @intFromPtr(&GetKeyNameTextW);
    if (std.mem.eql(u8, name, "GetAsyncKeyState")) return @intFromPtr(&GetAsyncKeyState);
    if (std.mem.eql(u8, name, "GetMessagePos")) return @intFromPtr(&GetMessagePos);
    if (std.mem.eql(u8, name, "GetMessageExtraInfo")) return @intFromPtr(&GetMessageExtraInfo);
    if (std.mem.eql(u8, name, "DragDetect")) return @intFromPtr(&DragDetect);
    if (std.mem.eql(u8, name, "GetMessageA")) return @intFromPtr(&GetMessageA);
    if (std.mem.eql(u8, name, "CopyImage")) return @intFromPtr(&CopyImage);
    if (std.mem.eql(u8, name, "wvsprintfA")) return @intFromPtr(&wvsprintfA);
    if (std.mem.eql(u8, name, "wsprintfA")) return @intFromPtr(&wsprintfA);
    if (std.mem.eql(u8, name, "EnumDisplaySettingsA")) return @intFromPtr(&EnumDisplaySettingsA);
    if (std.mem.eql(u8, name, "EnumDisplaySettingsW")) return @intFromPtr(&EnumDisplaySettingsW);
    if (std.mem.eql(u8, name, "ChangeDisplaySettingsW")) return @intFromPtr(&ChangeDisplaySettingsW);
    if (std.mem.eql(u8, name, "EnumDisplayMonitors")) return @intFromPtr(&EnumDisplayMonitors);
    if (std.mem.eql(u8, name, "EnumDisplayDevicesA")) return @intFromPtr(&EnumDisplayDevicesA);
    if (std.mem.eql(u8, name, "GetCaretBlinkTime")) return @intFromPtr(&GetCaretBlinkTime);
    if (std.mem.eql(u8, name, "IsClipboardFormatAvailable")) return @intFromPtr(&IsClipboardFormatAvailable);
    if (std.mem.eql(u8, name, "LoadCursorA")) return @intFromPtr(&LoadCursorA);
    if (std.mem.eql(u8, name, "LoadIconA")) return @intFromPtr(&LoadIconA);
    if (std.mem.eql(u8, name, "CreateIconIndirect")) return @intFromPtr(&CreateIconIndirect);
    if (std.mem.eql(u8, name, "GetThreadDesktop")) return @intFromPtr(&GetThreadDesktop);
    if (std.mem.eql(u8, name, "GetUserObjectInformationA")) return @intFromPtr(&GetUserObjectInformationA);
    if (std.mem.eql(u8, name, "GetUserObjectInformationW")) return @intFromPtr(&GetUserObjectInformationW);
    if (std.mem.eql(u8, name, "GetProcessWindowStation")) return @intFromPtr(&GetProcessWindowStation);
    if (std.mem.eql(u8, name, "RegisterWindowMessageA")) return @intFromPtr(&RegisterWindowMessageA);
    if (std.mem.eql(u8, name, "SendMessageA")) return @intFromPtr(&SendMessageA);
    if (std.mem.eql(u8, name, "SendMessageTimeoutA")) return @intFromPtr(&SendMessageTimeoutA);
    if (std.mem.eql(u8, name, "EnumWindows")) return @intFromPtr(&EnumWindows);
    if (std.mem.eql(u8, name, "CreateDialogParamA")) return @intFromPtr(&CreateDialogParamA);
    if (std.mem.eql(u8, name, "DialogBoxParamA")) return @intFromPtr(&DialogBoxParamA);
    if (std.mem.eql(u8, name, "AdjustWindowRectEx")) return @intFromPtr(&AdjustWindowRectEx);
    if (std.mem.eql(u8, name, "SetDlgItemTextA")) return @intFromPtr(&SetDlgItemTextA);
    if (std.mem.eql(u8, name, "CheckDlgButton")) return @intFromPtr(&CheckDlgButton);
    if (std.mem.eql(u8, name, "IsDlgButtonChecked")) return @intFromPtr(&IsDlgButtonChecked);
    if (std.mem.eql(u8, name, "GetDesktopWindow")) return @intFromPtr(&GetDesktopWindow);
    if (std.mem.eql(u8, name, "ClientToScreen")) return @intFromPtr(&ClientToScreen);
    if (std.mem.eql(u8, name, "OpenClipboard")) return @intFromPtr(&OpenClipboard);
    if (std.mem.eql(u8, name, "CloseClipboard")) return @intFromPtr(&CloseClipboard);
    if (std.mem.eql(u8, name, "EmptyClipboard")) return @intFromPtr(&EmptyClipboard);
    if (std.mem.eql(u8, name, "GetClipboardData")) return @intFromPtr(&GetClipboardData);
    if (std.mem.eql(u8, name, "SetClipboardData")) return @intFromPtr(&SetClipboardData);
    if (std.mem.eql(u8, name, "CreateDialogParamW")) return @intFromPtr(&CreateDialogParamW);
    if (std.mem.eql(u8, name, "DestroyCursor")) return @intFromPtr(&DestroyCursor);
    if (std.mem.eql(u8, name, "DestroyIcon")) return @intFromPtr(&DestroyIcon);
    if (std.mem.eql(u8, name, "GetActiveWindow")) return @intFromPtr(&GetActiveWindow);
    if (std.mem.eql(u8, name, "GetAncestor")) return @intFromPtr(&GetAncestor);
    if (std.mem.eql(u8, name, "GetFocus")) return @intFromPtr(&GetFocus);
    if (std.mem.eql(u8, name, "GetKeyState")) return @intFromPtr(&GetKeyState);
    if (std.mem.eql(u8, name, "GetMessageTime")) return @intFromPtr(&GetMessageTime);
    if (std.mem.eql(u8, name, "PtInRect")) return @intFromPtr(&PtInRect);
    if (std.mem.eql(u8, name, "ReleaseCapture")) return @intFromPtr(&ReleaseCapture);
    if (std.mem.eql(u8, name, "SetCapture")) return @intFromPtr(&SetCapture);
    if (std.mem.eql(u8, name, "GetCapture")) return @intFromPtr(&GetCapture);
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
    if (std.mem.eql(u8, name, "MessageBoxW")) return @intFromPtr(&MessageBoxW);
    if (std.mem.eql(u8, name, "MessageBoxA")) return @intFromPtr(&MessageBoxA);
    if (std.mem.eql(u8, name, "GetDC")) return @intFromPtr(&GetDC);
    if (std.mem.eql(u8, name, "ReleaseDC")) return @intFromPtr(&ReleaseDC);
    if (std.mem.eql(u8, name, "GetSystemMetrics")) return @intFromPtr(&GetSystemMetrics);
    if (std.mem.eql(u8, name, "SetWindowPos")) return @intFromPtr(&SetWindowPos);
    if (std.mem.eql(u8, name, "GetWindowRect")) return @intFromPtr(&GetWindowRect);
    if (std.mem.eql(u8, name, "SetWindowTextW")) return @intFromPtr(&SetWindowTextW);
    if (std.mem.eql(u8, name, "SetDlgItemTextW")) return @intFromPtr(&SetDlgItemTextW);
    if (std.mem.eql(u8, name, "GetDlgItemTextW")) return @intFromPtr(&GetDlgItemTextW);
    if (std.mem.eql(u8, name, "SendDlgItemMessageW")) return @intFromPtr(&SendDlgItemMessageW);
    if (std.mem.eql(u8, name, "GetDlgItem")) return @intFromPtr(&GetDlgItem);
    if (std.mem.eql(u8, name, "GetDlgItemInt")) return @intFromPtr(&GetDlgItemInt);
    if (std.mem.eql(u8, name, "SetDlgItemInt")) return @intFromPtr(&SetDlgItemInt);
    if (std.mem.eql(u8, name, "DialogBoxParamW")) return @intFromPtr(&DialogBoxParamW);
    if (std.mem.eql(u8, name, "EndDialog")) return @intFromPtr(&EndDialog);
    if (std.mem.eql(u8, name, "EnableWindow")) return @intFromPtr(&EnableWindow);
    if (std.mem.eql(u8, name, "LoadImageW")) return @intFromPtr(&LoadImageW);
    if (std.mem.eql(u8, name, "SystemParametersInfoW")) return @intFromPtr(&SystemParametersInfoW);
    if (std.mem.eql(u8, name, "FindWindowExW")) return @intFromPtr(&FindWindowExW);
    if (std.mem.eql(u8, name, "SetWindowsHookExW")) return @intFromPtr(&SetWindowsHookExW);
    if (std.mem.eql(u8, name, "UnhookWindowsHookEx")) return @intFromPtr(&UnhookWindowsHookEx);
    if (std.mem.eql(u8, name, "CallNextHookEx")) return @intFromPtr(&CallNextHookEx);
    return null;
}
