//! Negative control: imports a kernel32 function WINS does not implement
//! (GetProcessorSystemCycleTime; the earlier control GetLogicalProcessorInformation
//! became a Cuphead requirement in 7354dec, so the loader resolves it now).
//! winload64 must list it and exit 4 without executing anything.
const std = @import("std");
const W = std.builtin.CallingConvention.winapi;
extern "kernel32" fn GetProcessorSystemCycleTime(group: u16, buf: ?*anyopaque, ret_len: *u32) callconv(W) u32;
export fn fixc_probe() callconv(W) i32 {
    var n: u32 = 0;
    return @bitCast(GetProcessorSystemCycleTime(0, null, &n));
}
