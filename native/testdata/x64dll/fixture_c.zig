//! Negative control: imports a kernel32 function WINS does not implement
//! (GetLogicalProcessorInformation, also needed by liblark.dll). winload64 must list it
//! and exit 4 without executing anything.
const std = @import("std");
const W = std.builtin.CallingConvention.winapi;
extern "kernel32" fn GetLogicalProcessorInformation(buf: ?*anyopaque, len: *u32) callconv(W) i32;
export fn fixc_probe() callconv(W) i32 {
    var n: u32 = 0;
    return GetLogicalProcessorInformation(null, &n);
}
