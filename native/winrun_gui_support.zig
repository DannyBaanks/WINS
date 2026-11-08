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

fn GetDlgItemTextA(hDlg: usize, nIDDlgItem: i32, lpString: ?[*]u8, cchMax: i32) callconv(W) i32 {
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

fn CreateFontIndirectW(lplf: ?*const anyopaque) callconv(W) usize {
    _ = lplf;
    return 0xF0002;
}

fn CreateSolidBrush(color: u32) callconv(W) usize {
    _ = color;
    return 0xB006;
}

fn CreatePen(iStyle: i32, cWidth: i32, color: u32) callconv(W) usize {
    _ = iStyle; _ = cWidth; _ = color;
    return 0xB007;
}

fn CreatePatternBrush(hbm: usize) callconv(W) usize {
    _ = hbm;
    return 0xB008;
}

fn CreateHatchBrush(iHatch: i32, color: u32) callconv(W) usize {
    _ = iHatch; _ = color;
    return 0xB009;
}

fn ExtCreatePen(iPenStyle: u32, cWidth: u32, plbrush: ?*const anyopaque, cStyle: u32, pstyle: ?*const anyopaque) callconv(W) usize {
    _ = iPenStyle; _ = cWidth; _ = plbrush; _ = cStyle; _ = pstyle;
    return 0xB00A;
}

fn DeleteDC(hdc: usize) callconv(W) i32 {
    _ = hdc;
    return 1;
}

fn SaveDC(hdc: usize) callconv(W) i32 {
    _ = hdc;
    return 1;
}

fn RestoreDC(hdc: usize, nSavedDC: i32) callconv(W) i32 {
    _ = hdc; _ = nSavedDC;
    return 1;
}

fn GetROP2(hdc: usize) callconv(W) i32 {
    _ = hdc;
    return 13;
}

fn SetROP2(hdc: usize, rop2: i32) callconv(W) i32 {
    _ = hdc; _ = rop2;
    return 13;
}

fn SetBkColor(hdc: usize, color: u32) callconv(W) u32 {
    _ = hdc;
    return color;
}

fn SetBkMode(hdc: usize, mode: i32) callconv(W) i32 {
    _ = hdc;
    return mode;
}

fn SetTextColor(hdc: usize, color: u32) callconv(W) u32 {
    _ = hdc;
    return color;
}

fn CreateRectRgn(x1: i32, y1: i32, x2: i32, y2: i32) callconv(W) usize {
    _ = x1; _ = y1; _ = x2; _ = y2;
    return 0xB00B;
}

fn CreateRectRgnIndirect(lprect: ?*const anyopaque) callconv(W) usize {
    _ = lprect;
    return 0xB00C;
}

fn CombineRgn(hrgnDst: usize, hrgnSrc1: usize, hrgnSrc2: usize, iMode: i32) callconv(W) i32 {
    _ = hrgnDst; _ = hrgnSrc1; _ = hrgnSrc2; _ = iMode;
    return 2;
}

fn SelectClipRgn(hdc: usize, hrgn: usize) callconv(W) i32 {
    _ = hdc; _ = hrgn;
    return 2;
}

fn ExcludeClipRect(hdc: usize, left: i32, top: i32, right: i32, bottom: i32) callconv(W) i32 {
    _ = hdc; _ = left; _ = top; _ = right; _ = bottom;
    return 2;
}

fn IntersectClipRect(hdc: usize, left: i32, top: i32, right: i32, bottom: i32) callconv(W) i32 {
    _ = hdc; _ = left; _ = top; _ = right; _ = bottom;
    return 2;
}

fn GetClipRgn(hdc: usize, hrgn: usize) callconv(W) i32 {
    _ = hdc; _ = hrgn;
    return 0;
}

fn MoveToEx(hdc: usize, x: i32, y: i32, lppt: ?*anyopaque) callconv(W) i32 {
    _ = hdc; _ = x; _ = y; _ = lppt;
    return 1;
}

fn LineTo(hdc: usize, x: i32, y: i32) callconv(W) i32 {
    _ = hdc; _ = x; _ = y;
    return 1;
}

fn Polyline(hdc: usize, apt: ?*const anyopaque, cpt: i32) callconv(W) i32 {
    _ = hdc; _ = apt; _ = cpt;
    return 1;
}

fn Polygon(hdc: usize, apt: ?*const anyopaque, cpt: i32) callconv(W) i32 {
    _ = hdc; _ = apt; _ = cpt;
    return 1;
}

fn Rectangle(hdc: usize, left: i32, top: i32, right: i32, bottom: i32) callconv(W) i32 {
    _ = hdc; _ = left; _ = top; _ = right; _ = bottom;
    return 1;
}

fn RoundRect(hdc: usize, left: i32, top: i32, right: i32, bottom: i32, width: i32, height: i32) callconv(W) i32 {
    _ = hdc; _ = left; _ = top; _ = right; _ = bottom; _ = width; _ = height;
    return 1;
}

fn Ellipse(hdc: usize, left: i32, top: i32, right: i32, bottom: i32) callconv(W) i32 {
    _ = hdc; _ = left; _ = top; _ = right; _ = bottom;
    return 1;
}

fn PatBlt(hdc: usize, x: i32, y: i32, w: i32, h: i32, rop: u32) callconv(W) i32 {
    _ = hdc; _ = x; _ = y; _ = w; _ = h; _ = rop;
    return 1;
}

fn StretchBlt(hdcDest: usize, xDest: i32, yDest: i32, wDest: i32, hDest: i32, hdcSrc: usize, xSrc: i32, ySrc: i32, wSrc: i32, hSrc: i32, rop: u32) callconv(W) i32 {
    _ = hdcDest; _ = xDest; _ = yDest; _ = wDest; _ = hDest; _ = hdcSrc; _ = xSrc; _ = ySrc; _ = wSrc; _ = hSrc; _ = rop;
    return 1;
}

fn GdiAlphaBlend(hdcDest: usize, xDest: i32, yDest: i32, wDest: i32, hDest: i32, hdcSrc: usize, xSrc: i32, ySrc: i32, wSrc: i32, hSrc: i32, ftn: usize) callconv(W) i32 {
    _ = hdcDest; _ = xDest; _ = yDest; _ = wDest; _ = hDest; _ = hdcSrc; _ = xSrc; _ = ySrc; _ = wSrc; _ = hSrc; _ = ftn;
    return 1;
}

fn GetTextExtentPoint32W(hdc: usize, lpString: ?[*:0]const u16, c: i32, lpSize: ?*anyopaque) callconv(W) i32 {
    _ = hdc; _ = lpString;
    if (lpSize) |s| {
        const ptr: *[2]i32 = @ptrCast(@alignCast(s));
        ptr[0] = c * 8;
        ptr[1] = 16;
    }
    return 1;
}

fn GetTextExtentPoint32A(hdc: usize, lpString: ?[*:0]const u8, c: i32, lpSize: ?*anyopaque) callconv(W) i32 {
    _ = hdc; _ = lpString;
    if (lpSize) |s| {
        const ptr: *[2]i32 = @ptrCast(@alignCast(s));
        ptr[0] = c * 8;
        ptr[1] = 16;
    }
    return 1;
}

fn GetTextExtentPointW(hdc: usize, lpString: ?[*:0]const u16, c: i32, lpSize: ?*anyopaque) callconv(W) i32 {
    return GetTextExtentPoint32W(hdc, lpString, c, lpSize);
}

fn GetTextExtentExPointA(hdc: usize, lpszStr: ?[*:0]const u8, cchString: i32, nMaxExtent: i32, lpnFit: ?*i32, alpDx: ?*i32, lpSize: ?*anyopaque) callconv(W) i32 {
    _ = nMaxExtent; _ = alpDx;
    if (lpnFit) |fit| fit.* = cchString;
    return GetTextExtentPoint32A(hdc, lpszStr, cchString, lpSize);
}

fn GetTextExtentExPointW(hdc: usize, lpszStr: ?[*:0]const u16, cchString: i32, nMaxExtent: i32, lpnFit: ?*i32, alpDx: ?*i32, lpSize: ?*anyopaque) callconv(W) i32 {
    _ = nMaxExtent; _ = alpDx;
    if (lpnFit) |fit| fit.* = cchString;
    return GetTextExtentPoint32W(hdc, lpszStr, cchString, lpSize);
}

fn GetTextMetricsW(hdc: usize, lptm: ?*anyopaque) callconv(W) i32 {
    _ = hdc;
    if (lptm) |tm| {
        const bytes: [*]u8 = @ptrCast(tm);
        @memset(bytes[0..56], 0);
        const i32_ptr: *[14]i32 = @ptrCast(@alignCast(tm));
        i32_ptr[0] = 16;
        i32_ptr[7] = 8;
    }
    return 1;
}

fn ExtTextOutW(hdc: usize, x: i32, y: i32, options: u32, lprect: ?*const anyopaque, lpString: ?[*:0]const u16, c: u32, lpDx: ?*const i32) callconv(W) i32 {
    _ = hdc; _ = x; _ = y; _ = options; _ = lprect; _ = lpString; _ = c; _ = lpDx;
    return 1;
}

fn ExtTextOutA(hdc: usize, x: i32, y: i32, options: u32, lprect: ?*const anyopaque, lpString: ?[*:0]const u8, c: u32, lpDx: ?*const i32) callconv(W) i32 {
    _ = hdc; _ = x; _ = y; _ = options; _ = lprect; _ = lpString; _ = c; _ = lpDx;
    return 1;
}

fn SetTextAlign(hdc: usize, align_flags: u32) callconv(W) u32 {
    _ = hdc;
    return align_flags;
}

fn SetWindowOrgEx(hdc: usize, x: i32, y: i32, lppt: ?*anyopaque) callconv(W) i32 {
    _ = hdc; _ = x; _ = y; _ = lppt;
    return 1;
}

fn OffsetWindowOrgEx(hdc: usize, x: i32, y: i32, lppt: ?*anyopaque) callconv(W) i32 {
    _ = hdc; _ = x; _ = y; _ = lppt;
    return 1;
}

fn SetBrushOrgEx(hdc: usize, x: i32, y: i32, lppt: ?*anyopaque) callconv(W) i32 {
    _ = hdc; _ = x; _ = y; _ = lppt;
    return 1;
}

fn SetDIBits(hdc: usize, hbm: usize, start: u32, cLines: u32, lpBits: ?*const anyopaque, pbmi: ?*const anyopaque, ColorUse: u32) callconv(W) i32 {
    _ = hdc; _ = hbm; _ = start; _ = lpBits; _ = pbmi; _ = ColorUse;
    return @intCast(cLines);
}

fn GetDIBits(hdc: usize, hbm: usize, start: u32, cLines: u32, lpvBits: ?*anyopaque, pbmi: ?*anyopaque, usage: u32) callconv(W) i32 {
    _ = hdc; _ = hbm; _ = start; _ = lpvBits; _ = pbmi; _ = usage;
    return @intCast(cLines);
}

fn StretchDIBits(hdc: usize, xDest: i32, yDest: i32, DestWidth: i32, DestHeight: i32, xSrc: i32, ySrc: i32, SrcWidth: i32, SrcHeight: i32, lpBits: ?*const anyopaque, lpbmi: ?*const anyopaque, iUsage: u32, rop: u32) callconv(W) i32 {
    _ = hdc; _ = xDest; _ = yDest; _ = DestWidth; _ = xSrc; _ = ySrc; _ = SrcWidth; _ = SrcHeight; _ = lpBits; _ = lpbmi; _ = iUsage; _ = rop;
    return DestHeight;
}

fn GetPixel(hdc: usize, x: i32, y: i32) callconv(W) u32 {
    _ = hdc; _ = x; _ = y;
    return 0;
}

fn SetPixel(hdc: usize, x: i32, y: i32, color: u32) callconv(W) u32 {
    _ = hdc; _ = x; _ = y;
    return color;
}

fn SetStretchBltMode(hdc: usize, mode: i32) callconv(W) i32 {
    _ = hdc;
    return mode;
}

fn RectVisible(hdc: usize, lprect: ?*const anyopaque) callconv(W) i32 {
    _ = hdc; _ = lprect;
    return 1;
}

fn DPtoLP(hdc: usize, lppt: ?*anyopaque, c: i32) callconv(W) i32 {
    _ = hdc; _ = lppt; _ = c;
    return 1;
}

fn EnumFontFamiliesExW(hdc: usize, lpLogfont: ?*anyopaque, lpProc: ?*anyopaque, lParam: usize, dwFlags: u32) callconv(W) i32 {
    _ = hdc; _ = lpLogfont; _ = lpProc; _ = lParam; _ = dwFlags;
    return 1;
}

fn StartDocW(hdc: usize, lpdi: ?*const anyopaque) callconv(W) i32 {
    _ = hdc; _ = lpdi;
    return 1;
}

fn EndDoc(hdc: usize) callconv(W) i32 {
    _ = hdc;
    return 1;
}

fn StartPage(hdc: usize) callconv(W) i32 {
    _ = hdc;
    return 1;
}

fn EndPage(hdc: usize) callconv(W) i32 {
    _ = hdc;
    return 1;
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
    if (std.mem.eql(u8, name, "CreateFontIndirectW")) return @intFromPtr(&CreateFontIndirectW);
    if (std.mem.eql(u8, name, "CreateSolidBrush")) return @intFromPtr(&CreateSolidBrush);
    if (std.mem.eql(u8, name, "CreatePen")) return @intFromPtr(&CreatePen);
    if (std.mem.eql(u8, name, "CreatePatternBrush")) return @intFromPtr(&CreatePatternBrush);
    if (std.mem.eql(u8, name, "CreateHatchBrush")) return @intFromPtr(&CreateHatchBrush);
    if (std.mem.eql(u8, name, "ExtCreatePen")) return @intFromPtr(&ExtCreatePen);
    if (std.mem.eql(u8, name, "DeleteDC")) return @intFromPtr(&DeleteDC);
    if (std.mem.eql(u8, name, "SaveDC")) return @intFromPtr(&SaveDC);
    if (std.mem.eql(u8, name, "RestoreDC")) return @intFromPtr(&RestoreDC);
    if (std.mem.eql(u8, name, "GetROP2")) return @intFromPtr(&GetROP2);
    if (std.mem.eql(u8, name, "SetROP2")) return @intFromPtr(&SetROP2);
    if (std.mem.eql(u8, name, "SetBkColor")) return @intFromPtr(&SetBkColor);
    if (std.mem.eql(u8, name, "SetBkMode")) return @intFromPtr(&SetBkMode);
    if (std.mem.eql(u8, name, "SetTextColor")) return @intFromPtr(&SetTextColor);
    if (std.mem.eql(u8, name, "CreateRectRgn")) return @intFromPtr(&CreateRectRgn);
    if (std.mem.eql(u8, name, "CreateRectRgnIndirect")) return @intFromPtr(&CreateRectRgnIndirect);
    if (std.mem.eql(u8, name, "CombineRgn")) return @intFromPtr(&CombineRgn);
    if (std.mem.eql(u8, name, "SelectClipRgn")) return @intFromPtr(&SelectClipRgn);
    if (std.mem.eql(u8, name, "ExcludeClipRect")) return @intFromPtr(&ExcludeClipRect);
    if (std.mem.eql(u8, name, "IntersectClipRect")) return @intFromPtr(&IntersectClipRect);
    if (std.mem.eql(u8, name, "GetClipRgn")) return @intFromPtr(&GetClipRgn);
    if (std.mem.eql(u8, name, "MoveToEx")) return @intFromPtr(&MoveToEx);
    if (std.mem.eql(u8, name, "LineTo")) return @intFromPtr(&LineTo);
    if (std.mem.eql(u8, name, "Polyline")) return @intFromPtr(&Polyline);
    if (std.mem.eql(u8, name, "Polygon")) return @intFromPtr(&Polygon);
    if (std.mem.eql(u8, name, "Rectangle")) return @intFromPtr(&Rectangle);
    if (std.mem.eql(u8, name, "RoundRect")) return @intFromPtr(&RoundRect);
    if (std.mem.eql(u8, name, "Ellipse")) return @intFromPtr(&Ellipse);
    if (std.mem.eql(u8, name, "PatBlt")) return @intFromPtr(&PatBlt);
    if (std.mem.eql(u8, name, "StretchBlt")) return @intFromPtr(&StretchBlt);
    if (std.mem.eql(u8, name, "GdiAlphaBlend")) return @intFromPtr(&GdiAlphaBlend);
    if (std.mem.eql(u8, name, "GetTextExtentPoint32W")) return @intFromPtr(&GetTextExtentPoint32W);
    if (std.mem.eql(u8, name, "GetTextExtentPoint32A")) return @intFromPtr(&GetTextExtentPoint32A);
    if (std.mem.eql(u8, name, "GetTextExtentPointW")) return @intFromPtr(&GetTextExtentPointW);
    if (std.mem.eql(u8, name, "GetTextExtentExPointA")) return @intFromPtr(&GetTextExtentExPointA);
    if (std.mem.eql(u8, name, "GetTextExtentExPointW")) return @intFromPtr(&GetTextExtentExPointW);
    if (std.mem.eql(u8, name, "GetTextMetricsW")) return @intFromPtr(&GetTextMetricsW);
    if (std.mem.eql(u8, name, "ExtTextOutW")) return @intFromPtr(&ExtTextOutW);
    if (std.mem.eql(u8, name, "ExtTextOutA")) return @intFromPtr(&ExtTextOutA);
    if (std.mem.eql(u8, name, "SetTextAlign")) return @intFromPtr(&SetTextAlign);
    if (std.mem.eql(u8, name, "SetWindowOrgEx")) return @intFromPtr(&SetWindowOrgEx);
    if (std.mem.eql(u8, name, "OffsetWindowOrgEx")) return @intFromPtr(&OffsetWindowOrgEx);
    if (std.mem.eql(u8, name, "SetBrushOrgEx")) return @intFromPtr(&SetBrushOrgEx);
    if (std.mem.eql(u8, name, "SetDIBits")) return @intFromPtr(&SetDIBits);
    if (std.mem.eql(u8, name, "GetDIBits")) return @intFromPtr(&GetDIBits);
    if (std.mem.eql(u8, name, "StretchDIBits")) return @intFromPtr(&StretchDIBits);
    if (std.mem.eql(u8, name, "GetPixel")) return @intFromPtr(&GetPixel);
    if (std.mem.eql(u8, name, "SetPixel")) return @intFromPtr(&SetPixel);
    if (std.mem.eql(u8, name, "SetStretchBltMode")) return @intFromPtr(&SetStretchBltMode);
    if (std.mem.eql(u8, name, "RectVisible")) return @intFromPtr(&RectVisible);
    if (std.mem.eql(u8, name, "DPtoLP")) return @intFromPtr(&DPtoLP);
    if (std.mem.eql(u8, name, "EnumFontFamiliesExW")) return @intFromPtr(&EnumFontFamiliesExW);
    if (std.mem.eql(u8, name, "StartDocW")) return @intFromPtr(&StartDocW);
    if (std.mem.eql(u8, name, "EndDoc")) return @intFromPtr(&EndDoc);
    if (std.mem.eql(u8, name, "StartPage")) return @intFromPtr(&StartPage);
    if (std.mem.eql(u8, name, "EndPage")) return @intFromPtr(&EndPage);
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

fn BeginPaint(hwnd: usize, lpPaint: ?*anyopaque) callconv(W) usize {
    _ = hwnd; _ = lpPaint;
    return 0xB001;
}

fn EndPaint(hwnd: usize, lpPaint: ?*const anyopaque) callconv(W) i32 {
    _ = hwnd; _ = lpPaint;
    return 1;
}

fn InvalidateRect(hwnd: usize, lpRect: ?*const anyopaque, bErase: i32) callconv(W) i32 {
    _ = hwnd; _ = lpRect; _ = bErase;
    return 1;
}

fn RedrawWindow(hwnd: usize, lprcUpdate: ?*const anyopaque, hrgnUpdate: usize, flags: u32) callconv(W) i32 {
    _ = hwnd; _ = lprcUpdate; _ = hrgnUpdate; _ = flags;
    return 1;
}

fn FillRect(hdc: usize, lprc: ?*const anyopaque, hbr: usize) callconv(W) i32 {
    _ = hdc; _ = lprc; _ = hbr;
    return 1;
}

fn FrameRect(hdc: usize, lprc: ?*const anyopaque, hbr: usize) callconv(W) i32 {
    _ = hdc; _ = lprc; _ = hbr;
    return 1;
}

fn DrawEdge(hdc: usize, qrc: ?*anyopaque, edge: u32, grfFlags: u32) callconv(W) i32 {
    _ = hdc; _ = qrc; _ = edge; _ = grfFlags;
    return 1;
}

fn DrawFrameControl(hdc: usize, lprc: ?*anyopaque, uType: u32, uState: u32) callconv(W) i32 {
    _ = hdc; _ = lprc; _ = uType; _ = uState;
    return 1;
}

fn DrawFocusRect(hdc: usize, lprc: ?*const anyopaque) callconv(W) i32 {
    _ = hdc; _ = lprc;
    return 1;
}

fn DrawIconEx(hdc: usize, xLeft: i32, yTop: i32, hIcon: usize, cxWidth: i32, cyWidth: i32, istepIfAniCur: u32, hbrFlickerFreeDraw: usize, diFlags: u32) callconv(W) i32 {
    _ = hdc; _ = xLeft; _ = yTop; _ = hIcon; _ = cxWidth; _ = cyWidth; _ = istepIfAniCur; _ = hbrFlickerFreeDraw; _ = diFlags;
    return 1;
}

fn DrawTextW(hdc: usize, lpchText: ?[*:0]const u16, cchText: i32, lprc: ?*anyopaque, format: u32) callconv(W) i32 {
    _ = hdc; _ = lpchText; _ = cchText; _ = lprc; _ = format;
    return 16;
}

fn DrawTextExW(hdc: usize, lpchText: ?[*:0]const u16, cchText: i32, lprc: ?*anyopaque, format: u32, lpdtp: ?*anyopaque) callconv(W) i32 {
    _ = hdc; _ = lpchText; _ = cchText; _ = lprc; _ = format; _ = lpdtp;
    return 16;
}

fn CreateMenu() callconv(W) usize {
    return 0x90001;
}

fn CreatePopupMenu() callconv(W) usize {
    return 0x90002;
}

fn DestroyMenu(hMenu: usize) callconv(W) i32 {
    _ = hMenu;
    return 1;
}

fn GetMenu(hWnd: usize) callconv(W) usize {
    _ = hWnd;
    return 0x90001;
}

fn SetMenu(hWnd: usize, hMenu: usize) callconv(W) i32 {
    _ = hWnd; _ = hMenu;
    return 1;
}

fn DrawMenuBar(hWnd: usize) callconv(W) i32 {
    _ = hWnd;
    return 1;
}

fn GetSubMenu(hMenu: usize, nPos: i32) callconv(W) usize {
    _ = hMenu; _ = nPos;
    return 0x90002;
}

fn GetMenuItemCount(hMenu: usize) callconv(W) i32 {
    _ = hMenu;
    return 1;
}

fn GetMenuItemID(hMenu: usize, nPos: i32) callconv(W) u32 {
    _ = hMenu;
    return @intCast(nPos);
}

fn GetMenuItemInfoW(hmenu: usize, item: u32, fByPosition: i32, lpmii: ?*anyopaque) callconv(W) i32 {
    _ = hmenu; _ = item; _ = fByPosition; _ = lpmii;
    return 1;
}

fn SetMenuItemInfoW(hmenu: usize, item: u32, fByPosition: i32, lpmii: ?*const anyopaque) callconv(W) i32 {
    _ = hmenu; _ = item; _ = fByPosition; _ = lpmii;
    return 1;
}

fn GetMenuStringW(hMenu: usize, uIDItem: u32, lpString: ?[*:0]u16, cchMax: i32, flags: u32) callconv(W) i32 {
    _ = hMenu; _ = uIDItem; _ = flags;
    if (lpString) |s| {
        if (cchMax > 0) s[0] = 0;
    }
    return 0;
}

fn GetMenuState(hMenu: usize, uId: u32, uFlags: u32) callconv(W) u32 {
    _ = hMenu; _ = uId; _ = uFlags;
    return 0;
}

fn InsertMenuW(hMenu: usize, uPosition: u32, uFlags: u32, uIDNewItem: usize, lpNewItem: ?*const anyopaque) callconv(W) i32 {
    _ = hMenu; _ = uPosition; _ = uFlags; _ = uIDNewItem; _ = lpNewItem;
    return 1;
}

fn InsertMenuItemW(hmenu: usize, item: u32, fByPosition: i32, lpmi: ?*const anyopaque) callconv(W) i32 {
    _ = hmenu; _ = item; _ = fByPosition; _ = lpmi;
    return 1;
}

fn AppendMenuW(hMenu: usize, uFlags: u32, uIDNewItem: usize, lpNewItem: ?*const anyopaque) callconv(W) i32 {
    _ = hMenu; _ = uFlags; _ = uIDNewItem; _ = lpNewItem;
    return 1;
}

fn AppendMenuA(hMenu: usize, uFlags: u32, uIDNewItem: usize, lpNewItem: ?*const anyopaque) callconv(W) i32 {
    _ = hMenu; _ = uFlags; _ = uIDNewItem; _ = lpNewItem;
    return 1;
}

fn ModifyMenuW(hMnu: usize, uPosition: u32, uFlags: u32, uIDNewItem: usize, lpNewItem: ?*const anyopaque) callconv(W) i32 {
    _ = hMnu; _ = uPosition; _ = uFlags; _ = uIDNewItem; _ = lpNewItem;
    return 1;
}

fn DeleteMenu(hMenu: usize, uPosition: u32, uFlags: u32) callconv(W) i32 {
    _ = hMenu; _ = uPosition; _ = uFlags;
    return 1;
}

fn RemoveMenu(hMenu: usize, uPosition: u32, uFlags: u32) callconv(W) i32 {
    _ = hMenu; _ = uPosition; _ = uFlags;
    return 1;
}

fn EnableMenuItem(hMenu: usize, uIDEnableItem: u32, uEnable: u32) callconv(W) i32 {
    _ = hMenu; _ = uIDEnableItem; _ = uEnable;
    return 0;
}

fn CheckMenuItem(hMenu: usize, uIDCheckItem: u32, uCheck: u32) callconv(W) i32 {
    _ = hMenu; _ = uIDCheckItem; _ = uCheck;
    return 0;
}

fn CheckMenuRadioItem(hmenu: usize, first: u32, last: u32, check: u32, flags: u32) callconv(W) i32 {
    _ = hmenu; _ = first; _ = last; _ = check; _ = flags;
    return 1;
}

fn SetMenuItemBitmaps(hMenu: usize, uPosition: u32, uFlags: u32, hBitmapUnchecked: usize, hBitmapChecked: usize) callconv(W) i32 {
    _ = hMenu; _ = uPosition; _ = uFlags; _ = hBitmapUnchecked; _ = hBitmapChecked;
    return 1;
}

fn TrackPopupMenu(hMenu: usize, uFlags: u32, x: i32, y: i32, nReserved: i32, hWnd: usize, prcRect: ?*const anyopaque) callconv(W) i32 {
    _ = hMenu; _ = uFlags; _ = x; _ = y; _ = nReserved; _ = hWnd; _ = prcRect;
    return 1;
}

fn TrackPopupMenuEx(hMenu: usize, uFlags: u32, x: i32, y: i32, hwnd: usize, lptpm: ?*anyopaque) callconv(W) i32 {
    _ = hMenu; _ = uFlags; _ = x; _ = y; _ = hwnd; _ = lptpm;
    return 1;
}

fn GetMenuBarInfo(hwnd: usize, idObject: i32, idItem: i32, pmbi: ?*anyopaque) callconv(W) i32 {
    _ = hwnd; _ = idObject; _ = idItem; _ = pmbi;
    return 1;
}

fn CreateCaret(hWnd: usize, hBitmap: usize, nWidth: i32, nHeight: i32) callconv(W) i32 {
    _ = hWnd; _ = hBitmap; _ = nWidth; _ = nHeight;
    return 1;
}

fn DestroyCaret() callconv(W) i32 {
    return 1;
}

fn ShowCaret(hWnd: usize) callconv(W) i32 {
    _ = hWnd;
    return 1;
}

fn HideCaret(hWnd: usize) callconv(W) i32 {
    _ = hWnd;
    return 1;
}

fn SetCaretPos(X: i32, Y: i32) callconv(W) i32 {
    _ = X; _ = Y;
    return 1;
}

fn GetWindowTextW(hWnd: usize, lpString: ?[*:0]u16, nMaxCount: i32) callconv(W) i32 {
    _ = hWnd;
    if (lpString) |s| {
        if (nMaxCount > 0) s[0] = 0;
    }
    return 0;
}

fn GetWindowTextA(hWnd: usize, lpString: ?[*:0]u8, nMaxCount: i32) callconv(W) i32 {
    _ = hWnd;
    if (lpString) |s| {
        if (nMaxCount > 0) s[0] = 0;
    }
    return 0;
}

fn GetWindowTextLengthW(hWnd: usize) callconv(W) i32 {
    _ = hWnd;
    return 0;
}

fn IsWindow(hWnd: usize) callconv(W) i32 {
    return if (hWnd != 0) 1 else 0;
}

fn IsWindowEnabled(hWnd: usize) callconv(W) i32 {
    _ = hWnd;
    return 1;
}

fn IsWindowVisible(hWnd: usize) callconv(W) i32 {
    _ = hWnd;
    return 1;
}

fn IsIconic(hWnd: usize) callconv(W) i32 {
    _ = hWnd;
    return 0;
}

fn IsZoomed(hWnd: usize) callconv(W) i32 {
    _ = hWnd;
    return 0;
}

fn IsChild(hWndParent: usize, hWnd: usize) callconv(W) i32 {
    _ = hWndParent; _ = hWnd;
    return 0;
}

fn SetParent(hWndChild: usize, hWndNewParent: usize) callconv(W) usize {
    _ = hWndChild;
    return hWndNewParent;
}

fn MoveWindow(hWnd: usize, X: i32, Y: i32, nWidth: i32, nHeight: i32, bRepaint: i32) callconv(W) i32 {
    _ = hWnd; _ = X; _ = Y; _ = nWidth; _ = nHeight; _ = bRepaint;
    return 1;
}

fn BringWindowToTop(hWnd: usize) callconv(W) i32 {
    _ = hWnd;
    return 1;
}

fn GetLastActivePopup(hWnd: usize) callconv(W) usize {
    return hWnd;
}

fn FindWindowW(lpClassName: ?[*:0]const u16, lpWindowName: ?[*:0]const u16) callconv(W) usize {
    _ = lpClassName; _ = lpWindowName;
    return 0;
}

fn GetWindowThreadProcessId(hWnd: usize, lpdwProcessId: ?*u32) callconv(W) u32 {
    _ = hWnd;
    if (lpdwProcessId) |pid| pid.* = 1000;
    return 1001;
}

fn GetClassNameW(hWnd: usize, lpClassName: ?[*:0]u16, nMaxCount: i32) callconv(W) i32 {
    _ = hWnd;
    if (lpClassName) |s| {
        if (nMaxCount > 0) s[0] = 0;
    }
    return 0;
}

fn GetClassNameA(hWnd: usize, lpClassName: ?[*:0]u8, nMaxCount: i32) callconv(W) i32 {
    _ = hWnd;
    if (lpClassName) |s| {
        if (nMaxCount > 0) s[0] = 0;
    }
    return 0;
}

fn GetDlgCtrlID(hWnd: usize) callconv(W) i32 {
    _ = hWnd;
    return 1;
}

fn GetSysColor(nIndex: i32) callconv(W) u32 {
    return switch (nIndex) {
        5 => 0xFFFFFF,
        8 => 0x000000,
        15 => 0xF0F0F0,
        else => 0xFFFFFF,
    };
}

fn GetSysColorBrush(nIndex: i32) callconv(W) usize {
    _ = nIndex;
    return 0xB005;
}

fn SetPropW(hWnd: usize, lpString: ?[*:0]const u16, hData: usize) callconv(W) i32 {
    _ = hWnd; _ = lpString; _ = hData;
    return 1;
}

fn GetPropW(hWnd: usize, lpString: ?[*:0]const u16) callconv(W) usize {
    _ = hWnd; _ = lpString;
    return 0;
}

fn RemovePropW(hWnd: usize, lpString: ?[*:0]const u16) callconv(W) usize {
    _ = hWnd; _ = lpString;
    return 0;
}

fn SetLayeredWindowAttributes(hwnd: usize, crKey: u32, bAlpha: u8, dwFlags: u32) callconv(W) i32 {
    _ = hwnd; _ = crKey; _ = bAlpha; _ = dwFlags;
    return 1;
}

fn GetWindowDC(hWnd: usize) callconv(W) usize {
    _ = hWnd;
    return 0xB001;
}

fn GetDCEx(hWnd: usize, hrgnClip: usize, flags: u32) callconv(W) usize {
    _ = hWnd; _ = hrgnClip; _ = flags;
    return 0xB001;
}

fn MapWindowPoints(hWndFrom: usize, hWndTo: usize, lpPoints: ?*anyopaque, cPoints: u32) callconv(W) i32 {
    _ = hWndFrom; _ = hWndTo; _ = lpPoints; _ = cPoints;
    return 0;
}

fn InflateRect(lprc: ?*anyopaque, dx: i32, dy: i32) callconv(W) i32 {
    _ = dx; _ = dy;
    if (lprc == null) return 0;
    return 1;
}

fn EqualRect(lprc1: ?*const anyopaque, lprc2: ?*const anyopaque) callconv(W) i32 {
    _ = lprc1; _ = lprc2;
    return 1;
}

fn IntersectRect(lprcDst: ?*anyopaque, lprcSrc1: ?*const anyopaque, lprcSrc2: ?*const anyopaque) callconv(W) i32 {
    _ = lprcDst; _ = lprcSrc1; _ = lprcSrc2;
    return 1;
}

fn SetRectEmpty(lprc: ?*anyopaque) callconv(W) i32 {
    if (lprc) |r| {
        const ptr: *[4]i32 = @ptrCast(@alignCast(r));
        ptr.* = .{ 0, 0, 0, 0 };
    }
    return 1;
}

fn EnumChildWindows(hWndParent: usize, lpEnumFunc: ?*anyopaque, lParam: usize) callconv(W) i32 {
    _ = hWndParent; _ = lpEnumFunc; _ = lParam;
    return 1;
}

fn EnumThreadWindows(dwThreadId: u32, lpfn: ?*anyopaque, lParam: usize) callconv(W) i32 {
    _ = dwThreadId; _ = lpfn; _ = lParam;
    return 1;
}

fn GetComboBoxInfo(hwndCombo: usize, pcbi: ?*anyopaque) callconv(W) i32 {
    _ = hwndCombo; _ = pcbi;
    return 1;
}

fn GetIconInfo(hIcon: usize, piconinfo: ?*anyopaque) callconv(W) i32 {
    _ = hIcon; _ = piconinfo;
    return 1;
}

fn wsprintfW(buf: ?[*:0]u16, fmt: ?[*:0]const u16) callconv(W) i32 {
    _ = buf; _ = fmt;
    return 0;
}

fn GetScrollPos(hWnd: usize, nBar: i32) callconv(W) i32 {
    _ = hWnd; _ = nBar;
    return 0;
}

fn SetScrollPos(hWnd: usize, nBar: i32, nPos: i32, bRedraw: i32) callconv(W) i32 {
    _ = hWnd; _ = nBar; _ = bRedraw;
    return nPos;
}

fn GetScrollRange(hWnd: usize, nBar: i32, lpMinPos: ?*i32, lpMaxPos: ?*i32) callconv(W) i32 {
    _ = hWnd; _ = nBar;
    if (lpMinPos) |min| min.* = 0;
    if (lpMaxPos) |max| max.* = 100;
    return 1;
}

fn SetScrollRange(hWnd: usize, nBar: i32, nMinPos: i32, nMaxPos: i32, bRedraw: i32) callconv(W) i32 {
    _ = hWnd; _ = nBar; _ = nMinPos; _ = nMaxPos; _ = bRedraw;
    return 1;
}

fn GetScrollInfo(hwnd: usize, nBar: i32, lpsi: ?*anyopaque) callconv(W) i32 {
    _ = hwnd; _ = nBar; _ = lpsi;
    return 1;
}

fn SetScrollInfo(hwnd: usize, nBar: i32, lpsi: ?*const anyopaque, redraw: i32) callconv(W) i32 {
    _ = hwnd; _ = nBar; _ = lpsi; _ = redraw;
    return 0;
}

fn ScrollWindow(hWnd: usize, XAmount: i32, YAmount: i32, lpRect: ?*const anyopaque, lpClipRect: ?*const anyopaque) callconv(W) i32 {
    _ = hWnd; _ = XAmount; _ = YAmount; _ = lpRect; _ = lpClipRect;
    return 1;
}

fn ShowScrollBar(hWnd: usize, wBar: i32, bShow: i32) callconv(W) i32 {
    _ = hWnd; _ = wBar; _ = bShow;
    return 1;
}

fn RegisterClipboardFormatW(lpszFormat: ?[*:0]const u16) callconv(W) u32 {
    _ = lpszFormat;
    return 0xC001;
}

fn AddClipboardFormatListener(hwnd: usize) callconv(W) i32 {
    _ = hwnd;
    return 1;
}

fn RemoveClipboardFormatListener(hwnd: usize) callconv(W) i32 {
    _ = hwnd;
    return 1;
}

fn SetClipboardViewer(hWndNewViewer: usize) callconv(W) usize {
    _ = hWndNewViewer;
    return 0;
}

fn ChangeClipboardChain(hWndRemove: usize, hWndNewNext: usize) callconv(W) i32 {
    _ = hWndRemove; _ = hWndNewNext;
    return 1;
}

fn CreateAcceleratorTableW(paccel: ?*anyopaque, cAccel: i32) callconv(W) usize {
    _ = paccel; _ = cAccel;
    return 0xA001;
}

fn DestroyAcceleratorTable(hAccel: usize) callconv(W) i32 {
    _ = hAccel;
    return 1;
}

fn TranslateAcceleratorW(hWnd: usize, hAccTable: usize, lpMsg: ?*anyopaque) callconv(W) i32 {
    _ = hWnd; _ = hAccTable; _ = lpMsg;
    return 0;
}

fn RegisterWindowMessageW(lpString: ?[*:0]const u16) callconv(W) u32 {
    _ = lpString;
    return 0xC002;
}

fn FlashWindowEx(pfwi: ?*anyopaque) callconv(W) i32 {
    _ = pfwi;
    return 1;
}

fn LockWindowUpdate(hWndLock: usize) callconv(W) i32 {
    _ = hWndLock;
    return 1;
}

fn BeginDeferWindowPos(nNumWindows: i32) callconv(W) usize {
    _ = nNumWindows;
    return 0xD001;
}

fn DeferWindowPos(hWinPosInfo: usize, hWnd: usize, hWndInsertAfter: usize, x: i32, y: i32, cx: i32, cy: i32, uFlags: u32) callconv(W) usize {
    _ = hWnd; _ = hWndInsertAfter; _ = x; _ = y; _ = cx; _ = cy; _ = uFlags;
    return hWinPosInfo;
}

fn EndDeferWindowPos(hWinPosInfo: usize) callconv(W) i32 {
    _ = hWinPosInfo;
    return 1;
}

fn WindowFromPoint(point: usize) callconv(W) usize {
    _ = point;
    return 0;
}

fn ChildWindowFromPointEx(hwnd: usize, pt: usize, flags: u32) callconv(W) usize {
    _ = hwnd; _ = pt; _ = flags;
    return 0;
}

fn CreateDialogIndirectParamW(hInstance: usize, lpTemplate: ?*const anyopaque, hWndParent: usize, lpDialogFunc: ?*anyopaque, dwInitParam: usize) callconv(W) usize {
    _ = hInstance; _ = lpTemplate; _ = hWndParent; _ = lpDialogFunc; _ = dwInitParam;
    return 0x10001;
}

fn DialogBoxIndirectParamW(hInstance: usize, hDialogTemplate: ?*const anyopaque, hWndParent: usize, lpDialogFunc: ?*anyopaque, dwInitParam: usize) callconv(W) isize {
    _ = hInstance; _ = hDialogTemplate; _ = hWndParent; _ = lpDialogFunc; _ = dwInitParam;
    return 1;
}

fn mouse_event(dwFlags: u32, dx: u32, dy: u32, dwData: u32, dwExtraInfo: usize) callconv(W) void {
    _ = dwFlags; _ = dx; _ = dy; _ = dwData; _ = dwExtraInfo;
}

fn GetKeyboardState(lpKeyState: ?[*]u8) callconv(W) i32 {
    if (lpKeyState) |s| @memset(s[0..256], 0);
    return 1;
}

fn MapVirtualKeyW(uCode: u32, uMapType: u32) callconv(W) u32 {
    _ = uMapType;
    return uCode;
}

fn GetKeyboardLayout(idThread: u32) callconv(W) usize {
    _ = idThread;
    return 0x04090409;
}

fn ToAscii(uVirtKey: u32, uScanCode: u32, lpKeyState: ?*const u8, lpChar: ?*u16, uFlags: u32) callconv(W) i32 {
    _ = uScanCode; _ = lpKeyState; _ = uFlags;
    if (lpChar) |c| c.* = @intCast(uVirtKey & 0xFF);
    return 1;
}

fn IsCharLowerW(ch: u16) callconv(W) i32 {
    return if (ch >= 'a' and ch <= 'z') 1 else 0;
}

fn CharUpperW(lpsz: ?[*:0]u16) callconv(W) ?[*:0]u16 {
    if (lpsz) |s| {
        var i: usize = 0;
        while (s[i] != 0) : (i += 1) {
            if (s[i] >= 'a' and s[i] <= 'z') s[i] -= 32;
        }
    }
    return lpsz;
}

fn CharLowerW(lpsz: ?[*:0]u16) callconv(W) ?[*:0]u16 {
    if (lpsz) |s| {
        var i: usize = 0;
        while (s[i] != 0) : (i += 1) {
            if (s[i] >= 'A' and s[i] <= 'Z') s[i] += 32;
        }
    }
    return lpsz;
}

fn IsCharAlphaNumericW(ch: u16) callconv(W) i32 {
    return if ((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9')) 1 else 0;
}

fn IsCharAlphaW(ch: u16) callconv(W) i32 {
    return if ((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z')) 1 else 0;
}

fn LoadCursorW(hInstance: usize, lpCursorName: ?[*:0]const u16) callconv(W) usize {
    _ = hInstance; _ = lpCursorName;
    return 0x50001;
}

fn LoadMenuW(hInstance: usize, lpMenuName: ?[*:0]const u16) callconv(W) usize {
    _ = hInstance; _ = lpMenuName;
    return 0x90001;
}

fn LoadBitmapW(hInstance: usize, lpBitmapName: ?[*:0]const u16) callconv(W) usize {
    _ = hInstance; _ = lpBitmapName;
    return 0xB003;
}

fn LoadIconW(hInstance: usize, lpIconName: ?[*:0]const u16) callconv(W) usize {
    _ = hInstance; _ = lpIconName;
    return 0x40001;
}

fn LoadStringA(hInstance: usize, uID: u32, lpBuffer: ?[*:0]u8, cchBufferMax: i32) callconv(W) i32 {
    _ = hInstance; _ = uID;
    if (lpBuffer) |b| {
        if (cchBufferMax > 0) b[0] = 0;
    }
    return 0;
}

fn LoadStringW(hInstance: usize, uID: u32, lpBuffer: ?[*:0]u16, cchBufferMax: i32) callconv(W) i32 {
    _ = hInstance; _ = uID;
    if (lpBuffer) |b| {
        if (cchBufferMax > 0) b[0] = 0;
    }
    return 0;
}

fn MessageBeep(uType: u32) callconv(W) i32 {
    _ = uType;
    return 1;
}

fn GetUpdateRgn(hWnd: usize, hRgn: usize, bErase: i32) callconv(W) i32 {
    _ = hWnd; _ = hRgn; _ = bErase;
    return 0;
}

fn GetWindow(hWnd: usize, uCmd: u32) callconv(W) usize {
    _ = hWnd; _ = uCmd;
    return 0;
}

fn MsgWaitForMultipleObjects(nCount: u32, pHandles: ?*const usize, fWaitAll: i32, dwMilliseconds: u32, dwWakeMask: u32) callconv(W) u32 {
    _ = nCount; _ = pHandles; _ = fWaitAll; _ = dwMilliseconds; _ = dwWakeMask;
    return 0;
}

fn NotifyWinEvent(event: u32, hwnd: usize, idObject: i32, idChild: i32) callconv(W) void {
    _ = event; _ = hwnd; _ = idObject; _ = idChild;
}

fn CallWindowProcW(lpPrevWndFunc: ?*anyopaque, hWnd: usize, Msg: u32, wParam: usize, lParam: usize) callconv(W) isize {
    _ = lpPrevWndFunc; _ = hWnd; _ = Msg; _ = wParam; _ = lParam;
    return 0;
}

fn GetDoubleClickTime() callconv(W) u32 {
    return 500;
}

fn SystemParametersInfoA(uiAction: u32, uiParam: u32, pvParam: ?*anyopaque, fWinIni: u32) callconv(W) i32 {
    _ = uiAction; _ = uiParam; _ = pvParam; _ = fWinIni;
    return 1;
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
    if (std.mem.eql(u8, name, "GetDlgItemTextA")) return @intFromPtr(&GetDlgItemTextA);
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
    if (std.mem.eql(u8, name, "BeginPaint")) return @intFromPtr(&BeginPaint);
    if (std.mem.eql(u8, name, "EndPaint")) return @intFromPtr(&EndPaint);
    if (std.mem.eql(u8, name, "InvalidateRect")) return @intFromPtr(&InvalidateRect);
    if (std.mem.eql(u8, name, "RedrawWindow")) return @intFromPtr(&RedrawWindow);
    if (std.mem.eql(u8, name, "FillRect")) return @intFromPtr(&FillRect);
    if (std.mem.eql(u8, name, "FrameRect")) return @intFromPtr(&FrameRect);
    if (std.mem.eql(u8, name, "DrawEdge")) return @intFromPtr(&DrawEdge);
    if (std.mem.eql(u8, name, "DrawFrameControl")) return @intFromPtr(&DrawFrameControl);
    if (std.mem.eql(u8, name, "DrawFocusRect")) return @intFromPtr(&DrawFocusRect);
    if (std.mem.eql(u8, name, "DrawIconEx")) return @intFromPtr(&DrawIconEx);
    if (std.mem.eql(u8, name, "DrawTextW")) return @intFromPtr(&DrawTextW);
    if (std.mem.eql(u8, name, "DrawTextExW")) return @intFromPtr(&DrawTextExW);
    if (std.mem.eql(u8, name, "CreateMenu")) return @intFromPtr(&CreateMenu);
    if (std.mem.eql(u8, name, "CreatePopupMenu")) return @intFromPtr(&CreatePopupMenu);
    if (std.mem.eql(u8, name, "DestroyMenu")) return @intFromPtr(&DestroyMenu);
    if (std.mem.eql(u8, name, "GetMenu")) return @intFromPtr(&GetMenu);
    if (std.mem.eql(u8, name, "SetMenu")) return @intFromPtr(&SetMenu);
    if (std.mem.eql(u8, name, "DrawMenuBar")) return @intFromPtr(&DrawMenuBar);
    if (std.mem.eql(u8, name, "GetSubMenu")) return @intFromPtr(&GetSubMenu);
    if (std.mem.eql(u8, name, "GetMenuItemCount")) return @intFromPtr(&GetMenuItemCount);
    if (std.mem.eql(u8, name, "GetMenuItemID")) return @intFromPtr(&GetMenuItemID);
    if (std.mem.eql(u8, name, "GetMenuItemInfoW")) return @intFromPtr(&GetMenuItemInfoW);
    if (std.mem.eql(u8, name, "SetMenuItemInfoW")) return @intFromPtr(&SetMenuItemInfoW);
    if (std.mem.eql(u8, name, "GetMenuStringW")) return @intFromPtr(&GetMenuStringW);
    if (std.mem.eql(u8, name, "GetMenuState")) return @intFromPtr(&GetMenuState);
    if (std.mem.eql(u8, name, "InsertMenuW")) return @intFromPtr(&InsertMenuW);
    if (std.mem.eql(u8, name, "InsertMenuItemW")) return @intFromPtr(&InsertMenuItemW);
    if (std.mem.eql(u8, name, "AppendMenuW")) return @intFromPtr(&AppendMenuW);
    if (std.mem.eql(u8, name, "AppendMenuA")) return @intFromPtr(&AppendMenuA);
    if (std.mem.eql(u8, name, "ModifyMenuW")) return @intFromPtr(&ModifyMenuW);
    if (std.mem.eql(u8, name, "DeleteMenu")) return @intFromPtr(&DeleteMenu);
    if (std.mem.eql(u8, name, "RemoveMenu")) return @intFromPtr(&RemoveMenu);
    if (std.mem.eql(u8, name, "EnableMenuItem")) return @intFromPtr(&EnableMenuItem);
    if (std.mem.eql(u8, name, "CheckMenuItem")) return @intFromPtr(&CheckMenuItem);
    if (std.mem.eql(u8, name, "CheckMenuRadioItem")) return @intFromPtr(&CheckMenuRadioItem);
    if (std.mem.eql(u8, name, "SetMenuItemBitmaps")) return @intFromPtr(&SetMenuItemBitmaps);
    if (std.mem.eql(u8, name, "TrackPopupMenu")) return @intFromPtr(&TrackPopupMenu);
    if (std.mem.eql(u8, name, "TrackPopupMenuEx")) return @intFromPtr(&TrackPopupMenuEx);
    if (std.mem.eql(u8, name, "GetMenuBarInfo")) return @intFromPtr(&GetMenuBarInfo);
    if (std.mem.eql(u8, name, "CreateCaret")) return @intFromPtr(&CreateCaret);
    if (std.mem.eql(u8, name, "DestroyCaret")) return @intFromPtr(&DestroyCaret);
    if (std.mem.eql(u8, name, "ShowCaret")) return @intFromPtr(&ShowCaret);
    if (std.mem.eql(u8, name, "HideCaret")) return @intFromPtr(&HideCaret);
    if (std.mem.eql(u8, name, "SetCaretPos")) return @intFromPtr(&SetCaretPos);
    if (std.mem.eql(u8, name, "GetWindowTextW")) return @intFromPtr(&GetWindowTextW);
    if (std.mem.eql(u8, name, "GetWindowTextA")) return @intFromPtr(&GetWindowTextA);
    if (std.mem.eql(u8, name, "GetWindowTextLengthW")) return @intFromPtr(&GetWindowTextLengthW);
    if (std.mem.eql(u8, name, "IsWindow")) return @intFromPtr(&IsWindow);
    if (std.mem.eql(u8, name, "IsWindowEnabled")) return @intFromPtr(&IsWindowEnabled);
    if (std.mem.eql(u8, name, "IsWindowVisible")) return @intFromPtr(&IsWindowVisible);
    if (std.mem.eql(u8, name, "IsIconic")) return @intFromPtr(&IsIconic);
    if (std.mem.eql(u8, name, "IsZoomed")) return @intFromPtr(&IsZoomed);
    if (std.mem.eql(u8, name, "IsChild")) return @intFromPtr(&IsChild);
    if (std.mem.eql(u8, name, "SetParent")) return @intFromPtr(&SetParent);
    if (std.mem.eql(u8, name, "MoveWindow")) return @intFromPtr(&MoveWindow);
    if (std.mem.eql(u8, name, "BringWindowToTop")) return @intFromPtr(&BringWindowToTop);
    if (std.mem.eql(u8, name, "GetLastActivePopup")) return @intFromPtr(&GetLastActivePopup);
    if (std.mem.eql(u8, name, "FindWindowW")) return @intFromPtr(&FindWindowW);
    if (std.mem.eql(u8, name, "GetWindowThreadProcessId")) return @intFromPtr(&GetWindowThreadProcessId);
    if (std.mem.eql(u8, name, "GetClassNameW")) return @intFromPtr(&GetClassNameW);
    if (std.mem.eql(u8, name, "GetClassNameA")) return @intFromPtr(&GetClassNameA);
    if (std.mem.eql(u8, name, "GetDlgCtrlID")) return @intFromPtr(&GetDlgCtrlID);
    if (std.mem.eql(u8, name, "GetSysColor")) return @intFromPtr(&GetSysColor);
    if (std.mem.eql(u8, name, "GetSysColorBrush")) return @intFromPtr(&GetSysColorBrush);
    if (std.mem.eql(u8, name, "SetPropW")) return @intFromPtr(&SetPropW);
    if (std.mem.eql(u8, name, "GetPropW")) return @intFromPtr(&GetPropW);
    if (std.mem.eql(u8, name, "RemovePropW")) return @intFromPtr(&RemovePropW);
    if (std.mem.eql(u8, name, "SetLayeredWindowAttributes")) return @intFromPtr(&SetLayeredWindowAttributes);
    if (std.mem.eql(u8, name, "GetWindowDC")) return @intFromPtr(&GetWindowDC);
    if (std.mem.eql(u8, name, "GetDCEx")) return @intFromPtr(&GetDCEx);
    if (std.mem.eql(u8, name, "MapWindowPoints")) return @intFromPtr(&MapWindowPoints);
    if (std.mem.eql(u8, name, "InflateRect")) return @intFromPtr(&InflateRect);
    if (std.mem.eql(u8, name, "EqualRect")) return @intFromPtr(&EqualRect);
    if (std.mem.eql(u8, name, "IntersectRect")) return @intFromPtr(&IntersectRect);
    if (std.mem.eql(u8, name, "SetRectEmpty")) return @intFromPtr(&SetRectEmpty);
    if (std.mem.eql(u8, name, "EnumChildWindows")) return @intFromPtr(&EnumChildWindows);
    if (std.mem.eql(u8, name, "EnumThreadWindows")) return @intFromPtr(&EnumThreadWindows);
    if (std.mem.eql(u8, name, "GetComboBoxInfo")) return @intFromPtr(&GetComboBoxInfo);
    if (std.mem.eql(u8, name, "GetIconInfo")) return @intFromPtr(&GetIconInfo);
    if (std.mem.eql(u8, name, "wsprintfW")) return @intFromPtr(&wsprintfW);
    if (std.mem.eql(u8, name, "GetScrollPos")) return @intFromPtr(&GetScrollPos);
    if (std.mem.eql(u8, name, "SetScrollPos")) return @intFromPtr(&SetScrollPos);
    if (std.mem.eql(u8, name, "GetScrollRange")) return @intFromPtr(&GetScrollRange);
    if (std.mem.eql(u8, name, "SetScrollRange")) return @intFromPtr(&SetScrollRange);
    if (std.mem.eql(u8, name, "GetScrollInfo")) return @intFromPtr(&GetScrollInfo);
    if (std.mem.eql(u8, name, "SetScrollInfo")) return @intFromPtr(&SetScrollInfo);
    if (std.mem.eql(u8, name, "ScrollWindow")) return @intFromPtr(&ScrollWindow);
    if (std.mem.eql(u8, name, "ShowScrollBar")) return @intFromPtr(&ShowScrollBar);
    if (std.mem.eql(u8, name, "RegisterClipboardFormatW")) return @intFromPtr(&RegisterClipboardFormatW);
    if (std.mem.eql(u8, name, "AddClipboardFormatListener")) return @intFromPtr(&AddClipboardFormatListener);
    if (std.mem.eql(u8, name, "RemoveClipboardFormatListener")) return @intFromPtr(&RemoveClipboardFormatListener);
    if (std.mem.eql(u8, name, "SetClipboardViewer")) return @intFromPtr(&SetClipboardViewer);
    if (std.mem.eql(u8, name, "ChangeClipboardChain")) return @intFromPtr(&ChangeClipboardChain);
    if (std.mem.eql(u8, name, "CreateAcceleratorTableW")) return @intFromPtr(&CreateAcceleratorTableW);
    if (std.mem.eql(u8, name, "DestroyAcceleratorTable")) return @intFromPtr(&DestroyAcceleratorTable);
    if (std.mem.eql(u8, name, "TranslateAcceleratorW")) return @intFromPtr(&TranslateAcceleratorW);
    if (std.mem.eql(u8, name, "RegisterWindowMessageW")) return @intFromPtr(&RegisterWindowMessageW);
    if (std.mem.eql(u8, name, "FlashWindowEx")) return @intFromPtr(&FlashWindowEx);
    if (std.mem.eql(u8, name, "LockWindowUpdate")) return @intFromPtr(&LockWindowUpdate);
    if (std.mem.eql(u8, name, "BeginDeferWindowPos")) return @intFromPtr(&BeginDeferWindowPos);
    if (std.mem.eql(u8, name, "DeferWindowPos")) return @intFromPtr(&DeferWindowPos);
    if (std.mem.eql(u8, name, "EndDeferWindowPos")) return @intFromPtr(&EndDeferWindowPos);
    if (std.mem.eql(u8, name, "WindowFromPoint")) return @intFromPtr(&WindowFromPoint);
    if (std.mem.eql(u8, name, "ChildWindowFromPointEx")) return @intFromPtr(&ChildWindowFromPointEx);
    if (std.mem.eql(u8, name, "CreateDialogIndirectParamW")) return @intFromPtr(&CreateDialogIndirectParamW);
    if (std.mem.eql(u8, name, "DialogBoxIndirectParamW")) return @intFromPtr(&DialogBoxIndirectParamW);
    if (std.mem.eql(u8, name, "mouse_event")) return @intFromPtr(&mouse_event);
    if (std.mem.eql(u8, name, "GetKeyboardState")) return @intFromPtr(&GetKeyboardState);
    if (std.mem.eql(u8, name, "MapVirtualKeyW")) return @intFromPtr(&MapVirtualKeyW);
    if (std.mem.eql(u8, name, "GetKeyboardLayout")) return @intFromPtr(&GetKeyboardLayout);
    if (std.mem.eql(u8, name, "ToAscii")) return @intFromPtr(&ToAscii);
    if (std.mem.eql(u8, name, "IsCharLowerW")) return @intFromPtr(&IsCharLowerW);
    if (std.mem.eql(u8, name, "CharUpperW")) return @intFromPtr(&CharUpperW);
    if (std.mem.eql(u8, name, "CharLowerW")) return @intFromPtr(&CharLowerW);
    if (std.mem.eql(u8, name, "IsCharAlphaNumericW")) return @intFromPtr(&IsCharAlphaNumericW);
    if (std.mem.eql(u8, name, "IsCharAlphaW")) return @intFromPtr(&IsCharAlphaW);
    if (std.mem.eql(u8, name, "LoadCursorW")) return @intFromPtr(&LoadCursorW);
    if (std.mem.eql(u8, name, "LoadMenuW")) return @intFromPtr(&LoadMenuW);
    if (std.mem.eql(u8, name, "LoadBitmapW")) return @intFromPtr(&LoadBitmapW);
    if (std.mem.eql(u8, name, "LoadIconW")) return @intFromPtr(&LoadIconW);
    if (std.mem.eql(u8, name, "LoadStringA")) return @intFromPtr(&LoadStringA);
    if (std.mem.eql(u8, name, "LoadStringW")) return @intFromPtr(&LoadStringW);
    if (std.mem.eql(u8, name, "MessageBeep")) return @intFromPtr(&MessageBeep);
    if (std.mem.eql(u8, name, "GetUpdateRgn")) return @intFromPtr(&GetUpdateRgn);
    if (std.mem.eql(u8, name, "GetWindow")) return @intFromPtr(&GetWindow);
    if (std.mem.eql(u8, name, "MsgWaitForMultipleObjects")) return @intFromPtr(&MsgWaitForMultipleObjects);
    if (std.mem.eql(u8, name, "NotifyWinEvent")) return @intFromPtr(&NotifyWinEvent);
    if (std.mem.eql(u8, name, "CallWindowProcW")) return @intFromPtr(&CallWindowProcW);
    if (std.mem.eql(u8, name, "GetDoubleClickTime")) return @intFromPtr(&GetDoubleClickTime);
    if (std.mem.eql(u8, name, "SystemParametersInfoA")) return @intFromPtr(&SystemParametersInfoA);
    return null;
}
