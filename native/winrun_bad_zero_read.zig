//! Negative control: reject a supported zero-byte read. The fuzzer must detect it.
pub const main = @import("winrun_impl.zig").Impl(.zero_read_error).main;
