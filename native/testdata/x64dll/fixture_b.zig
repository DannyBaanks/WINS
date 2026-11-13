//! Second synthetic x64 DLL: imports from fixture_a.dll to exercise cross-image binding.
const std = @import("std");
const W = std.builtin.CallingConvention.winapi;

extern "fixture_a" fn fix_add(a: i32, b: i32) callconv(W) i32;
extern "fixture_a" fn fix_tls_get() callconv(W) u32;

export fn fixb_add_twice(a: i32, b: i32) callconv(W) i32 {
    return fix_add(fix_add(a, b), b);
}
export fn fixb_tls_from_a() callconv(W) u32 {
    return fix_tls_get();
}

// fixture_b's own implicit TLS: a loader that gives every image the same TLS slot
// returns fixture_a's block here instead (negative control winload64_bad_tls_index).
threadlocal var own_tls: u32 = 0xB0B0_0002;
export fn fixb_tls_own() callconv(W) u32 {
    return own_tls;
}
/// Writing own_tls keeps it a real per-thread variable (otherwise the optimizer may
/// fold the never-written initializer into a constant and never touch the TLS block).
export fn fixb_tls_own_bump() callconv(W) u32 {
    own_tls +%= 1;
    return own_tls;
}
