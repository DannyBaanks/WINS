//! Linux-native candidate for the documented Win32 last-error pair.
//! This does not load PE images or provide a Windows ABI to them.
threadlocal var last_error: u32 = 0;

export fn SetLastError(value: u32) void {
    last_error = value;
}

export fn GetLastError() u32 {
    return last_error;
}
