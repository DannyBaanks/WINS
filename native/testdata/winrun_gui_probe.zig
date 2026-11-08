//! Synthetic Win32 GUI test, not Notepad++ and not a general USER32 test.
const std = @import("std");
const W: std.builtin.CallingConvention = .{ .x86_64_win = .{} };
const Rect = extern struct { left: i32, top: i32, right: i32, bottom: i32 };
extern "user32" fn CreateWindowExW(u32, [*:0]const u16, ?[*:0]const u16, u32, i32, i32, i32, i32, usize, usize, usize, usize) callconv(W) usize;
extern "user32" fn GetClientRect(usize, *Rect) callconv(W) i32;
extern "user32" fn DestroyWindow(usize) callconv(W) i32;
extern "kernel32" fn ExitProcess(u32) callconv(W) noreturn;
var marker: u8 = 1;
var marker_ptr: *u8 = &marker;
const class = [_:0]u16{ 'S', 'T', 'A', 'T', 'I', 'C' };

pub export fn wWinMainCRTStartup() callconv(W) noreturn {
    if (@as(*volatile *u8, &marker_ptr).*.* != 1) ExitProcess(44);
    const window = CreateWindowExW(0, &class, null, 0x90000000, 0, 0, 320, 200, 0, 0, 0, 0);
    if (window == 0) ExitProcess(45);
    var rect: Rect = undefined;
    if (GetClientRect(window, &rect) == 0 or rect.left != 0 or rect.top != 0 or rect.right != 320 or rect.bottom != 200) ExitProcess(46);
    if (DestroyWindow(window) == 0) ExitProcess(47);
    if (DestroyWindow(window) != 0) ExitProcess(48);
    ExitProcess(41);
}
