//! NEGATIVE CONTROL for fuzz_winrun: winrun with the deliberate defect `skip_relocs`.
//! The differential fuzzer must report a DIVERGENCE with this loader.
pub const main = @import("winrun_impl.zig").Impl(.skip_relocs).main;
