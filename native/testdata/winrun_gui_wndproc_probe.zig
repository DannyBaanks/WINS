//! Synthetic Win32 GUI test with custom window class, WndProc dispatch, and message loop.
const std = @import("std");
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

const WM_CREATE: u32 = 0x0001;
const WM_DESTROY: u32 = 0x0002;
const WM_PAINT: u32 = 0x000F;
const WM_CLOSE: u32 = 0x0010;
const WM_QUIT: u32 = 0x0012;

extern "kernel32" fn GetModuleHandleW(?[*:0]const u16) callconv(W) usize;
extern "kernel32" fn ExitProcess(u32) callconv(W) noreturn;

extern "user32" fn RegisterClassExW(*const WNDCLASSEXW) callconv(W) u16;
extern "user32" fn CreateWindowExW(u32, [*:0]const u16, ?[*:0]const u16, u32, i32, i32, i32, i32, usize, usize, usize, usize) callconv(W) usize;
extern "user32" fn ShowWindow(usize, i32) callconv(W) i32;
extern "user32" fn UpdateWindow(usize) callconv(W) i32;
extern "user32" fn GetClientRect(usize, *Rect) callconv(W) i32;
extern "user32" fn DestroyWindow(usize) callconv(W) i32;
extern "user32" fn DefWindowProcW(usize, u32, usize, usize) callconv(W) usize;
extern "user32" fn PostQuitMessage(i32) callconv(W) void;
extern "user32" fn PostMessageW(usize, u32, usize, usize) callconv(W) i32;
extern "user32" fn GetMessageW(*MSG, usize, u32, u32) callconv(W) i32;
extern "user32" fn TranslateMessage(*const MSG) callconv(W) i32;
extern "user32" fn DispatchMessageW(*const MSG) callconv(W) usize;

var stage: u32 = 0;
var marker: u8 = 1;
var marker_ptr: *u8 = &marker;
const class_name = [_:0]u16{ 'W', 'I', 'N', 'S', '_', 'G', 'U', 'I', '_', 'T', 'E', 'S', 'T' };

fn customWndProc(hwnd: usize, msg: u32, wparam: usize, lparam: usize) callconv(W) usize {
    switch (msg) {
        WM_CREATE => {
            stage = 1;
            return 0;
        },
        WM_PAINT => {
            if (stage == 1) stage = 2;
            _ = PostMessageW(hwnd, WM_CLOSE, 0, 0);
            return 0;
        },
        WM_CLOSE => {
            if (stage == 2) stage = 3;
            _ = DestroyWindow(hwnd);
            return 0;
        },
        WM_DESTROY => {
            if (stage == 3) stage = 4;
            PostQuitMessage(52);
            return 0;
        },
        else => return DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

pub export fn wWinMainCRTStartup() callconv(W) noreturn {
    if (@as(*volatile *u8, &marker_ptr).*.* != 1) ExitProcess(44);
    const hinstance = GetModuleHandleW(null);
    if (hinstance == 0) ExitProcess(30);

    const wcex = WNDCLASSEXW{
        .cbSize = @sizeOf(WNDCLASSEXW),
        .style = 0,
        .lpfnWndProc = &customWndProc,
        .cbClsExtra = 0,
        .cbWndExtra = 0,
        .hInstance = hinstance,
        .hIcon = 0,
        .hCursor = 0,
        .hbrBackground = 0,
        .lpszMenuName = null,
        .lpszClassName = &class_name,
        .hIconSm = 0,
    };

    const atom = RegisterClassExW(&wcex);
    if (atom == 0) ExitProcess(31);

    const hwnd = CreateWindowExW(0, &class_name, null, 0x90000000, 0, 0, 400, 300, 0, 0, hinstance, 0);
    if (hwnd == 0) ExitProcess(32);
    if (stage != 1) ExitProcess(33);

    var rect: Rect = undefined;
    if (GetClientRect(hwnd, &rect) == 0 or rect.right != 400 or rect.bottom != 300) ExitProcess(34);

    _ = ShowWindow(hwnd, 5);
    _ = UpdateWindow(hwnd);

    var msg: MSG = undefined;
    while (GetMessageW(&msg, 0, 0, 0) != 0) {
        _ = TranslateMessage(&msg);
        _ = DispatchMessageW(&msg);
    }

    if (stage != 4) ExitProcess(35);
    ExitProcess(@intCast(msg.wParam));
}
