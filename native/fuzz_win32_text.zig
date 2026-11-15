//! Run ONLY within the WINS cleanroom: opening a library executes constructors.
//!
//! Differential fuzzer for the CP_UTF8 MultiByteToWideChar / WideCharToMultiByte
//! candidate protocol (buffers, lengths, flags, error codes, guard canaries).
//!   usage: runner CANDIDATE.so ORACLE.so ITERATIONS [SEED]
//! Each case injects at most ONE fault (bad flags, bad length, ...), because the
//! precedence between simultaneous faults is not documented and must not be
//! enshrined by the oracle. A match is not a proof of equivalence and not a PE port.
const std = @import("std");

const Mb2Wc = *const fn (u32, ?[*]const u8, i32, ?[*]u16, i32, *u32) callconv(.c) i32;
const Wc2Mb = *const fn (u32, ?[*]const u16, i32, ?[*]u8, i32, *u32) callconv(.c) i32;

const BUF = 96;
const CANARY16: u16 = 0xA5A5;
const CANARY8: u8 = 0xA5;

const Stats = struct { ok: u64 = 0, e87: u64 = 0, e122: u64 = 0, e1004: u64 = 0, e1113: u64 = 0, probe_only: u64 = 0 };

const edges = [_]u32{ 0x7F, 0x80, 0x7FF, 0x800, 0xD7FF, 0xE000, 0xFFFD, 0xFFFF, 0x10000, 0x10FFFF, 0 };
const specials8 = [_]u8{ 0x80, 0xBF, 0xC0, 0xC1, 0xC2, 0xDF, 0xE0, 0xED, 0xEF, 0xF0, 0xF4, 0xF5, 0xFF, 0xA0, 0x9F, 0x90, 0x8F, 0x00 };
const specials16 = [_]u16{ 0xD800, 0xDBFF, 0xDC00, 0xDFFF, 0x0000, 0xFFFE, 0xFFFF, 0xD7FF, 0xE000 };
const bad_flags = [_]u32{ 1, 2, 4, 0x10, 0x100, 0x8000_0000, 0xFFFF_FFFF };

fn pickScalar(rnd: std.Random) u32 {
    return switch (rnd.uintLessThan(u8, 7)) {
        0 => rnd.uintLessThan(u32, 0x80),
        1 => 0x80 + rnd.uintLessThan(u32, 0x780),
        2 => blk: {
            var c = 0x800 + rnd.uintLessThan(u32, 0xF800);
            if (c >= 0xD800 and c <= 0xDFFF) c = 0xE000;
            break :blk c;
        },
        3 => 0x10000 + rnd.uintLessThan(u32, 0x100000),
        else => edges[rnd.uintLessThan(usize, edges.len)],
    };
}

fn enc8(cp: u32, o: []u8) usize {
    if (cp < 0x80) {
        o[0] = @intCast(cp);
        return 1;
    }
    if (cp < 0x800) {
        o[0] = @intCast(0xC0 | (cp >> 6));
        o[1] = @intCast(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        o[0] = @intCast(0xE0 | (cp >> 12));
        o[1] = @intCast(0x80 | ((cp >> 6) & 0x3F));
        o[2] = @intCast(0x80 | (cp & 0x3F));
        return 3;
    }
    o[0] = @intCast(0xF0 | (cp >> 18));
    o[1] = @intCast(0x80 | ((cp >> 12) & 0x3F));
    o[2] = @intCast(0x80 | ((cp >> 6) & 0x3F));
    o[3] = @intCast(0x80 | (cp & 0x3F));
    return 4;
}

/// Fills `out` (capacity 48, leaves room for a NUL) and returns the length.
fn genUtf8(rnd: std.Random, out: *[48]u8) usize {
    var n: usize = 0;
    const kind = rnd.uintLessThan(u8, 10);
    if (kind < 3) {
        n = rnd.uintLessThan(usize, 14);
        for (0..n) |i| out[i] = if (rnd.boolean()) specials8[rnd.uintLessThan(usize, specials8.len)] else rnd.int(u8);
        return n;
    }
    const count = 1 + rnd.uintLessThan(usize, 6);
    for (0..count) |_| n += enc8(pickScalar(rnd), out[n..]);
    if (kind >= 6 and n > 0) {
        switch (rnd.uintLessThan(u8, 4)) {
            0 => n = rnd.uintLessThan(usize, n + 1),
            1 => out[rnd.uintLessThan(usize, n)] = if (rnd.boolean()) specials8[rnd.uintLessThan(usize, specials8.len)] else rnd.int(u8),
            2 => {
                const at = rnd.uintLessThan(usize, n + 1);
                std.mem.copyBackwards(u8, out[at + 1 .. n + 1], out[at..n]);
                out[at] = specials8[rnd.uintLessThan(usize, specials8.len)];
                n += 1;
            },
            else => {
                const at = rnd.uintLessThan(usize, n);
                std.mem.copyForwards(u8, out[at .. n - 1], out[at + 1 .. n]);
                n -= 1;
            },
        }
    }
    return n;
}

/// Fills `out` (capacity 32, leaves room for a NUL) and returns the unit count.
fn genUtf16(rnd: std.Random, out: *[32]u16) usize {
    var n: usize = 0;
    const kind = rnd.uintLessThan(u8, 10);
    if (kind < 3) {
        n = rnd.uintLessThan(usize, 12);
        for (0..n) |i| out[i] = if (rnd.boolean()) specials16[rnd.uintLessThan(usize, specials16.len)] else rnd.int(u16);
        return n;
    }
    const count = 1 + rnd.uintLessThan(usize, 6);
    for (0..count) |_| {
        const cp = pickScalar(rnd);
        if (cp >= 0x10000) {
            const v = cp - 0x10000;
            out[n] = @intCast(0xD800 + (v >> 10));
            out[n + 1] = @intCast(0xDC00 + (v & 0x3FF));
            n += 2;
        } else {
            out[n] = @intCast(cp);
            n += 1;
        }
    }
    if (kind >= 6) {
        switch (rnd.uintLessThan(u8, 3)) {
            0 => n = rnd.uintLessThan(usize, n + 1),
            1 => out[rnd.uintLessThan(usize, n)] = specials16[rnd.uintLessThan(usize, specials16.len)],
            else => if (n >= 2) std.mem.swap(u16, &out[0], &out[1]),
        }
    }
    return n;
}

const Plan = struct { flags: u32, len: i32, size: i32, dst_null: bool };

/// Chooses flags/length/size for one case with at most one fault. `valid_flag`
/// is the single documented strict flag for the direction; `probe_err` is the
/// oracle's verdict for (valid flags, cch=0) used to size the destination.
fn plan(rnd: std.Random, natural_len: i32, n: usize, valid_flag: u32, req_by_len: [2]i32, err_by_len: [2]u32) Plan {
    var p = Plan{
        .flags = if (rnd.boolean()) 0 else valid_flag,
        .len = if (rnd.boolean() or n == 0) -1 else natural_len,
        .size = 0,
        .dst_null = false,
    };
    const idx: usize = if (p.len == -1) 0 else 1;
    const req = req_by_len[idx];
    const probe_err = err_by_len[idx];
    const choose = rnd.uintLessThan(u8, 8);
    p.size = switch (choose) {
        0 => 0,
        1, 2 => req,
        3 => req - 1,
        4 => req + 1,
        5 => req + 6,
        else => @intCast(rnd.uintLessThan(u32, 12)),
    };
    if (p.size < 0) p.size = 0;
    // Strict flag + invalid input: 1113 vs 122 precedence is undocumented. Avoid the overlap.
    if (probe_err == 1113 and p.flags == valid_flag and p.size != 0) p.size = 80;
    switch (rnd.uintLessThan(u8, 20)) {
        0 => p.flags = bad_flags[rnd.uintLessThan(usize, bad_flags.len)],
        1 => p.len = 0,
        2 => p.len = -2,
        3 => p.size = -1,
        4 => {
            p.dst_null = true;
            p.size = 5;
        },
        else => {},
    }
    return p;
}

fn hex(comptime T: type, items: []const T) void {
    for (items) |v| std.debug.print(if (T == u8) "{x:0>2} " else "{x:0>4} ", .{v});
    std.debug.print("\n", .{});
}

fn tally(stats: *Stats, ret: i32, err: u32) void {
    if (ret > 0) stats.ok += 1 else switch (err) {
        87 => stats.e87 += 1,
        122 => stats.e122 += 1,
        1004 => stats.e1004 += 1,
        1113 => stats.e1113 += 1,
        else => {},
    }
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4 and args.len != 5) return error.InvalidArguments;
    const iterations = try std.fmt.parseInt(u32, args[3], 10);
    if (iterations < 1 or iterations > 10_000_000) return error.InvalidIterations;
    const seed: u64 = if (args.len == 5) try std.fmt.parseInt(u64, args[4], 0) else 0x57494e53;
    var cand = try std.DynLib.open(args[1]);
    defer cand.close();
    var orc = try std.DynLib.open(args[2]);
    defer orc.close();
    const c_mb = cand.lookup(Mb2Wc, "wins_mb2wc") orelse return error.MissingCandidateMb2wc;
    const c_wc = cand.lookup(Wc2Mb, "wins_wc2mb") orelse return error.MissingCandidateWc2mb;
    const o_mb = orc.lookup(Mb2Wc, "wins_mb2wc") orelse return error.MissingOracleMb2wc;
    const o_wc = orc.lookup(Wc2Mb, "wins_wc2mb") orelse return error.MissingOracleWc2mb;

    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    var s_mb = Stats{};
    var s_wc = Stats{};

    for (0..iterations) |iter| {
        if (iter % 2 == 0) {
            // ---- MultiByteToWideChar ----
            var in: [48]u8 = undefined;
            const n = genUtf8(rnd, &in);
            in[n] = 0;
            const exact: i32 = @intCast(n);
            var req: [2]i32 = undefined;
            var perr: [2]u32 = undefined;
            var scratch: u32 = 0;
            for ([2]i32{ -1, exact }, 0..) |l, k| {
                if (l == 0) {
                    req[k] = 0;
                    perr[k] = 0;
                    continue;
                }
                req[k] = o_mb(0, &in, l, null, 0, &scratch);
                _ = o_mb(8, &in, l, null, 0, &perr[k]);
            }
            const p = plan(rnd, exact, n, 8, req, perr);
            var dc: [BUF]u16 = @splat(CANARY16);
            var do_: [BUF]u16 = @splat(CANARY16);
            var ec: u32 = 0;
            var eo: u32 = 0;
            const src: ?[*]const u8 = &in;
            const rc = c_mb(p.flags, src, p.len, if (p.dst_null) null else &dc, p.size, &ec);
            const ro = o_mb(p.flags, src, p.len, if (p.dst_null) null else &do_, p.size, &eo);
            tally(&s_mb, ro, eo);
            const eff: usize = if (p.size > 0) @intCast(p.size) else 0;
            var bad = rc != ro or (ro == 0 and ec != eo);
            if (!bad and ro > 0 and p.size > 0) bad = !std.mem.eql(u16, dc[0..@intCast(ro)], do_[0..@intCast(ro)]);
            if (!bad) for (eff..BUF) |i| {
                if (dc[i] != CANARY16) bad = true;
            };
            for (eff..BUF) |i| {
                if (do_[i] != CANARY16) {
                    std.debug.print("ORACLE_FAULT mb2wc wrote past its destination\n", .{});
                    return error.OracleFault;
                }
            }
            if (bad) {
                std.debug.print("DIVERGENCE mb2wc iter={d} flags=0x{x} cb={d} cch={d} dst_null={} expected={d}/err{d} actual={d}/err{d}\ninput: ", .{ iter, p.flags, p.len, p.size, p.dst_null, ro, eo, rc, ec });
                hex(u8, in[0 .. n + 1]);
                if (ro > 0 and p.size > 0) {
                    std.debug.print("expected: ", .{});
                    hex(u16, do_[0..@intCast(ro)]);
                }
                std.debug.print("actual:   ", .{});
                hex(u16, dc[0..@min(BUF, @as(usize, @intCast(@max(rc, 0))) + 2)]);
                return error.Divergence;
            }
        } else {
            // ---- WideCharToMultiByte ----
            var in: [32]u16 = undefined;
            const n = genUtf16(rnd, &in);
            in[n] = 0;
            const exact: i32 = @intCast(n);
            var req: [2]i32 = undefined;
            var perr: [2]u32 = undefined;
            var scratch: u32 = 0;
            for ([2]i32{ -1, exact }, 0..) |l, k| {
                if (l == 0) {
                    req[k] = 0;
                    perr[k] = 0;
                    continue;
                }
                req[k] = o_wc(0, &in, l, null, 0, &scratch);
                _ = o_wc(0x80, &in, l, null, 0, &perr[k]);
            }
            const p = plan(rnd, exact, n, 0x80, req, perr);
            var dc: [BUF]u8 = @splat(CANARY8);
            var do_: [BUF]u8 = @splat(CANARY8);
            var ec: u32 = 0;
            var eo: u32 = 0;
            const src: ?[*]const u16 = &in;
            const rc = c_wc(p.flags, src, p.len, if (p.dst_null) null else &dc, p.size, &ec);
            const ro = o_wc(p.flags, src, p.len, if (p.dst_null) null else &do_, p.size, &eo);
            tally(&s_wc, ro, eo);
            const eff: usize = if (p.size > 0) @intCast(p.size) else 0;
            var bad = rc != ro or (ro == 0 and ec != eo);
            if (!bad and ro > 0 and p.size > 0) bad = !std.mem.eql(u8, dc[0..@intCast(ro)], do_[0..@intCast(ro)]);
            if (!bad) for (eff..BUF) |i| {
                if (dc[i] != CANARY8) bad = true;
            };
            for (eff..BUF) |i| {
                if (do_[i] != CANARY8) {
                    std.debug.print("ORACLE_FAULT wc2mb wrote past its destination\n", .{});
                    return error.OracleFault;
                }
            }
            if (bad) {
                std.debug.print("DIVERGENCE wc2mb iter={d} flags=0x{x} cch={d} cb={d} dst_null={} expected={d}/err{d} actual={d}/err{d}\ninput: ", .{ iter, p.flags, p.len, p.size, p.dst_null, ro, eo, rc, ec });
                hex(u16, in[0 .. n + 1]);
                if (ro > 0 and p.size > 0) {
                    std.debug.print("expected: ", .{});
                    hex(u8, do_[0..@intCast(ro)]);
                }
                std.debug.print("actual:   ", .{});
                hex(u8, dc[0..@min(BUF, @as(usize, @intCast(@max(rc, 0))) + 2)]);
                return error.Divergence;
            }
        }
    }
    std.debug.print(
        "MATCHED iterations={d} seed=0x{x} cp_utf8_only mb2wc[ok={d} e87={d} e122={d} e1004={d} e1113={d}] wc2mb[ok={d} e87={d} e122={d} e1004={d} e1113={d}]; not a PE port\n",
        .{ iterations, seed, s_mb.ok, s_mb.e87, s_mb.e122, s_mb.e1004, s_mb.e1113, s_wc.ok, s_wc.e87, s_wc.e122, s_wc.e1004, s_wc.e1113 },
    );
}
