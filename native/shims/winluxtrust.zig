//! Exported entry point of the winluxtrust candidate (digest half of WinVerifyTrust; never reports trust).
const impl = @import("winluxtrust_impl.zig").Impl(.none);

comptime {
    @export(&impl.verify, .{ .name = "winlux_verify_trust" });
}
