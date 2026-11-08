const W: @import("std").builtin.CallingConvention = .{ .x86_64_win = .{} };
extern "kernel32" fn GetStdHandle(u32) callconv(W) usize;
extern "kernel32" fn ReadFile(usize, ?[*]u8, u32, *u32, ?*anyopaque) callconv(W) i32;
extern "kernel32" fn GetLastError() callconv(W) u32;
extern "kernel32" fn SetLastError(u32) callconv(W) void;
extern "kernel32" fn ExitProcess(u32) callconv(W) noreturn;
var marker: u8 = 1;
var marker_ptr: *u8 = &marker;
pub export fn wWinMainCRTStartup() callconv(W) noreturn {
    if (@as(*volatile *u8, &marker_ptr).*.* != 1) ExitProcess(44);
    var count: u32 = 99;
    SetLastError(123);
    const result = ReadFile(GetStdHandle(0xfffffff6), null, 0, &count, null);
    const err = GetLastError();
    if (result == 1 and count == 0 and err == 123) ExitProcess(41);
    if (result == 0 and count == 0) ExitProcess(42);
    ExitProcess(43);
}
