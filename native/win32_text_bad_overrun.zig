//! NEGATIVE CONTROL: ignores the destination size and writes past it.
//! The fuzzer must report a DIVERGENCE (return value and guard canaries).
const impl = @import("shims/win32_text_impl.zig").Impl(.overrun);

comptime {
    @export(&impl.mb2wc, .{ .name = "wins_mb2wc" });
    @export(&impl.wc2mb, .{ .name = "wins_wc2mb" });
}
