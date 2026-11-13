//! Negative control: DllMain refuses PROCESS_ATTACH. winload64 must exit 7.
const std = @import("std");
const win = std.os.windows;
pub fn DllMain(_: win.HINSTANCE, reason: win.DWORD, _: win.LPVOID) win.BOOL {
    return if (reason == 1) .FALSE else .TRUE;
}
export fn fixd_never() callconv(.winapi) u32 {
    return 0xBAD;
}
