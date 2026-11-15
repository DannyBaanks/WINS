//! NEGATIVE CONTROL (ignore_scheme): the fuzzer must report a divergence for this library.
const impl = @import("shims/winluxhttp_impl.zig").Impl(.ignore_scheme);

comptime {
    @export(&impl.select, .{ .name = "winlux_select_proxy" });
}
