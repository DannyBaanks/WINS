//! Exported entry points of the CP_UTF8 text candidate (see win32_text_impl.zig).
const impl = @import("win32_text_impl.zig").Impl(.none);

comptime {
    @export(&impl.mb2wc, .{ .name = "wins_mb2wc" });
    @export(&impl.wc2mb, .{ .name = "wins_wc2mb" });
}
