//! winrun: the real loader (no deliberate defects). See winrun_impl.zig.
pub const main = @import("winrun_impl.zig").Impl(.none).main;
