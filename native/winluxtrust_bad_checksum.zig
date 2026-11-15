//! NEGATIVE CONTROL (hash_checksum): the fuzzer must report a divergence for this library.
const impl = @import("shims/winluxtrust_impl.zig").Impl(.hash_checksum);

comptime {
    @export(&impl.verify, .{ .name = "winlux_verify_trust" });
}
