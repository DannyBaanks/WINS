//! NEGATIVE CONTROL: replaces every byte of an invalid sequence instead of its
//! maximal subpart. The fuzzer must report a DIVERGENCE for this library.
const impl = @import("shims/win32_text_impl.zig").Impl(.per_byte);

comptime {
    @export(&impl.mb2wc, .{ .name = "wins_mb2wc" });
    @export(&impl.wc2mb, .{ .name = "wins_wc2mb" });
}
