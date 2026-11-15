//! Exported entry point of the winluxhttp candidate (proxy selection only).
const impl = @import("winluxhttp_impl.zig").Impl(.none);

comptime {
    @export(&impl.select, .{ .name = "winlux_select_proxy" });
}
