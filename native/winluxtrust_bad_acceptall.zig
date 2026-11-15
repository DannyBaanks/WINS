//! NEGATIVE CONTROL (accept_any): the fuzzer must report a divergence for this library.
const impl = @import("shims/winluxtrust_impl.zig").Impl(.accept_any);

comptime {
    @export(&impl.verify, .{ .name = "winlux_verify_trust" });
}
