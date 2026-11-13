//! Synthetic x64 DLL for the WINS x64 DLL loader (winload64). Built here, no vendor code.
//! Exercises: exports, DIR64 relocations (pointers in data), implicit TLS (threadlocal),
//! DllMain (process attach), an import from kernel32, and GS-relative TEB access.
const std = @import("std");
const W = std.builtin.CallingConvention.winapi;

extern "kernel32" fn GetCurrentProcessId() callconv(W) u32;

var attach_count: u32 = 0;
var greeting: [*:0]const u8 = "wins-fixture-a 1.0"; // pointer in .data -> needs a DIR64 reloc
threadlocal var tls_value: u32 = 0x5EED_0001;

const win = std.os.windows;
/// Called by Zig's _DllMainCRTStartup (the PE entry point).
pub fn DllMain(_: win.HINSTANCE, reason: win.DWORD, _: win.LPVOID) win.BOOL {
    if (reason == 1) attach_count += 1; // DLL_PROCESS_ATTACH
    return .TRUE;
}

export fn fix_version() callconv(W) [*:0]const u8 {
    return greeting;
}
export fn fix_add(a: i32, b: i32) callconv(W) i32 {
    return a +% b;
}
export fn fix_attach_count() callconv(W) u32 {
    return attach_count;
}
export fn fix_tls_get() callconv(W) u32 {
    return tls_value;
}
export fn fix_tls_bump() callconv(W) u32 {
    tls_value +%= 1;
    return tls_value;
}
export fn fix_pid() callconv(W) u32 {
    return GetCurrentProcessId();
}
export fn fix_teb_self() callconv(W) usize {
    // NtCurrentTeb(): gs:[0x30] holds the TEB's own address.
    return asm volatile ("movq %%gs:0x30, %[r]"
        : [r] "=r" (-> usize),
    );
}

// An explicit TLS callback (.CRT$XLB sits between the CRT's XLA/XLZ markers).
var tls_callback_count: u32 = 0;
fn tlsCallback(_: ?*anyopaque, reason: u32, _: ?*anyopaque) callconv(W) void {
    if (reason == 1) tls_callback_count += 1;
}
export const fixture_tls_callback linksection(".CRT$XLB") = &tlsCallback;

export fn fix_tls_callback_count() callconv(W) u32 {
    return tls_callback_count;
}

// msvcrt through the Win64 ABI (catches a shim built with the SysV convention).
extern "msvcrt" fn malloc(n: usize) callconv(W) ?[*]u8;
extern "msvcrt" fn free(p: ?[*]u8) callconv(W) void;
extern "msvcrt" fn _snprintf(buf: [*]u8, n: usize, fmt: [*:0]const u8, ...) callconv(W) i32;

var fmt_buf: [64]u8 = undefined;
export fn fix_crt_format(a: i32, b: u32) callconv(W) [*:0]const u8 {
    const p = malloc(32) orelse return "malloc returned NULL";
    const vp: *volatile u8 = &p[0]; // volatile: the optimizer may not elide malloc/free
    vp.* = 'x';
    const c: u32 = vp.*;
    free(p);
    const n = _snprintf(&fmt_buf, fmt_buf.len, "%d|%u|%s|%x|%c", a, b, @as([*:0]const u8, "ok"), @as(u32, 0xBEEF), c);
    if (n < 0 or n >= fmt_buf.len) return "snprintf failed";
    return @ptrCast(&fmt_buf);
}
