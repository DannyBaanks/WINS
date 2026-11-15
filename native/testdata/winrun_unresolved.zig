//! Fail-closed fixture for winrun: imports functions winrun does NOT implement
//! (kernel32!GetTickCount and user32!MessageBoxA) next to ones it does. winrun
//! must refuse it, list both missing imports, and execute nothing — if the entry
//! point ever ran, "EXECUTED" would appear on stdout.
//!   zig build-exe native/testdata/winrun_unresolved.zig -target x86_64-windows-gnu -O ReleaseSmall \
//!       -fentry=wWinMainCRTStartup --subsystem console -luser32 -femit-bin=/tmp/unresolved.exe
const std = @import("std");
const W: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

extern "kernel32" fn GetStdHandle(n: u32) callconv(W) usize;
extern "kernel32" fn WriteFile(h: usize, buf: [*]const u8, n: u32, written: *u32, ov: ?*anyopaque) callconv(W) i32;
extern "kernel32" fn ExitProcess(code: u32) callconv(W) noreturn;
extern "kernel32" fn GetTickCount() callconv(W) u32;
extern "user32" fn MessageBoxA(hwnd: ?*anyopaque, text: [*:0]const u8, caption: [*:0]const u8, kind: u32) callconv(W) i32;

pub const panic = std.debug.no_panic;

// Absolute pointers ensure the linker emits a .reloc section with DIR64 relocations.
var words = [_][:0]const u8{ "alpha", "beta" };

pub export fn wWinMainCRTStartup() callconv(W) noreturn {
    var n: u32 = 0;
    _ = WriteFile(GetStdHandle(@bitCast(@as(i32, -11))), "EXECUTED\n", 9, &n, null);
    const w = words[n % words.len];
    if (w.len == 999) _ = MessageBoxA(null, w.ptr, "y", 0);
    if (GetTickCount() == 1) ExitProcess(1);
    ExitProcess(7);
}
