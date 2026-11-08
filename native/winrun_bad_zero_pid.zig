//! Negative control: return an invalid zero process ID; the fuzzer must catch it.
pub const main = @import("winrun_impl.zig").Impl(.zero_pid).main;
