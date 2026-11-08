//! Experimental GUI loader, separate from the normal console-only winrun.
//! Use only with a private X server inside a networkless sandbox.
pub const main = @import("winrun_impl.zig").GuiImpl(.none).main;
