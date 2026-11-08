//! Unimplemented USER32 import: the experimental loader must refuse to run it.
const W: @import("std").builtin.CallingConvention = .{ .x86_64_win = .{} };
extern "user32" fn GetWindowRect(usize, *[4]i32) callconv(W) i32;
extern "kernel32" fn ExitProcess(u32) callconv(W) noreturn;
var marker: u8 = 1;
var marker_ptr: *u8 = &marker;
pub export fn wWinMainCRTStartup() callconv(W) noreturn {
    if (@as(*volatile *u8, &marker_ptr).*.* != 1) ExitProcess(44);
    var rect: [4]i32 = undefined;
    _ = GetWindowRect(0, &rect);
    ExitProcess(42);
}
