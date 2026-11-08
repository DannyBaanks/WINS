//! NEGATIVE CONTROL for fuzz_winrun: winrun with the deliberate defect `short_write_count`.
//! The differential fuzzer must report a DIVERGENCE with this loader.
pub const main = @import("winrun_impl.zig").Impl(.short_write_count).main;
