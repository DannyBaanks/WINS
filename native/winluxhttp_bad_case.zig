//! NEGATIVE CONTROL (case_sensitive_bypass): the fuzzer must report a divergence for this library.
const impl = @import("shims/winluxhttp_impl.zig").Impl(.case_sensitive_bypass);

comptime {
    @export(&impl.select, .{ .name = "winlux_select_proxy" });
}
