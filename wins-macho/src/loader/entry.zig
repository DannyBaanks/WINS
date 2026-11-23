const std = @import("std");

pub const EntryContext = struct {
    image_base: usize,
    slide: i64,
    entryoff: u64,
    entry_address: usize,
    argc: c_int,
    argv: [*c]const [*c]const u8,
    envp: [*c]const [*c]const u8,
    apple: [*c]const [*c]const u8,
};

pub const MainFn = *const fn (
    c_int,
    [*c]const [*c]const u8,
    [*c]const [*c]const u8,
    [*c]const [*c]const u8,
) callconv(.c) c_int;

pub fn transferControl(ctx: EntryContext) c_int {
    const entry_fn: MainFn = @ptrFromInt(ctx.entry_address);
    return entry_fn(ctx.argc, ctx.argv, ctx.envp, ctx.apple);
}
