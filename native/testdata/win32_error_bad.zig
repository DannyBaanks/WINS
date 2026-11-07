//! Deliberately wrong negative control: process-global state.
var last_error: u32 = 0;
export fn SetLastError(value: u32) void {
    last_error = value;
}
export fn GetLastError() u32 {
    return last_error;
}
