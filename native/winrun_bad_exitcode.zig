//! NEGATIVE CONTROL for fuzz_winrun: winrun with the deliberate defect `exit_off_by_one`.
//! The differential fuzzer must report a DIVERGENCE with this loader.
pub const main = @import("winrun_impl.zig").Impl(.exit_off_by_one).main;
