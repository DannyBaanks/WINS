//! Wine oracle for winload64: loads the same fixtures with the real Windows loader
//! (under Wine) and prints the same "call NAME = VALUE" lines.
const std = @import("std");
const W = std.builtin.CallingConvention.winapi;
extern "kernel32" fn LoadLibraryA(name: [*:0]const u8) callconv(W) ?*anyopaque;
extern "kernel32" fn GetProcAddress(h: *anyopaque, name: [*:0]const u8) callconv(W) ?*anyopaque;

const F = *const fn (u64, u64, u64, u64) callconv(W) u64;
const Ret = enum { u32, i32, str };
const Spec = struct { dll: [*:0]const u8, name: [*:0]const u8, args: [2]i64 = .{ 0, 0 }, ret: Ret };

const specs = [_]Spec{
    .{ .dll = "fixture_a.dll", .name = "fix_version", .ret = .str },
    .{ .dll = "fixture_a.dll", .name = "fix_add", .args = .{ -5, 3 }, .ret = .i32 },
    .{ .dll = "fixture_a.dll", .name = "fix_attach_count", .ret = .u32 },
    .{ .dll = "fixture_a.dll", .name = "fix_tls_callback_count", .ret = .u32 },
    .{ .dll = "fixture_a.dll", .name = "fix_tls_get", .ret = .u32 },
    .{ .dll = "fixture_a.dll", .name = "fix_tls_bump", .ret = .u32 },
    .{ .dll = "fixture_a.dll", .name = "fix_tls_get", .ret = .u32 },
    .{ .dll = "fixture_b.dll", .name = "fixb_add_twice", .args = .{ 40, 1 }, .ret = .i32 },
    .{ .dll = "fixture_b.dll", .name = "fixb_tls_from_a", .ret = .u32 },
    .{ .dll = "fixture_b.dll", .name = "fixb_tls_own", .ret = .u32 },
    .{ .dll = "fixture_b.dll", .name = "fixb_tls_own_bump", .ret = .u32 },
    .{ .dll = "fixture_a.dll", .name = "fix_tls_get", .ret = .u32 },
};

pub fn main() void {
    for (specs) |s| {
        const h = LoadLibraryA(s.dll) orelse {
            std.debug.print("LoadLibrary {s} failed\n", .{s.dll});
            std.process.exit(1);
        };
        const p = GetProcAddress(h, s.name) orelse {
            std.debug.print("no export {s}\n", .{s.name});
            std.process.exit(1);
        };
        const r = (@as(F, @ptrCast(p)))(@bitCast(s.args[0]), @bitCast(s.args[1]), 0, 0);
        switch (s.ret) {
            .u32 => std.debug.print("call {s} = {d}\n", .{ s.name, @as(u32, @truncate(r)) }),
            .i32 => std.debug.print("call {s} = {d}\n", .{ s.name, @as(i32, @bitCast(@as(u32, @truncate(r)))) }),
            .str => std.debug.print("call {s} = {s}\n", .{ s.name, std.mem.span(@as([*:0]const u8, @ptrFromInt(r))) }),
        }
    }
}
