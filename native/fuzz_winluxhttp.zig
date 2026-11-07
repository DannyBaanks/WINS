//! Run ONLY within the WINS cleanroom: opening a library executes constructors.
//!
//! Metamorphic fuzzer for the winluxhttp candidate (proxy selection).
//!   usage: runner CANDIDATE.so ITERATIONS [SEED]
//! There is no real WinHTTP to compare with, so the oracle is a set of relations
//! that must hold for ANY correct implementation of the documented format:
//!   R1  empty proxy list -> no proxy               R7  separators/order of bypass entries are irrelevant
//!   R2  unscoped entry applies to http and https   R8  <local> matches only dot-less hosts
//!   R3  "scheme=server" applies to that scheme only R9  host:port bypass entries are port-specific
//!   R4  bypass "*" -> bypassed                     R10 "*.suffix" matches hosts under suffix
//!   R5  exact host in bypass -> bypassed, decoys do not   R11 small buffer -> 122, never written past cap
//!   R6  host/scheme/bypass case is irrelevant      R12 bad URLs -> 12005 / 12006;  R13 garbage never crashes
const std = @import("std");

const Select = *const fn (?[*]const u8, usize, ?[*]const u8, usize, ?[*]const u8, usize, ?[*]u8, usize, *usize) callconv(.c) u32;

const PROXY: u32 = 0;
const NO_PROXY: u32 = 1;
const BYPASSED: u32 = 2;
const E_BUF: u32 = 122;
const E_URL: u32 = 12005;
const E_SCHEME: u32 = 12006;

const Res = struct { status: u32, out: [96]u8, len: usize };

const Ctx = struct {
    sel: Select,
    rnd: std.Random,
    iter: usize = 0,
    rel: []const u8 = "",

    fn call(self: *Ctx, url: []const u8, proxy: []const u8, bypass: []const u8, cap: usize) !Res {
        var buf: [128]u8 = @splat(0xA5);
        var n: usize = 99999;
        const st = self.sel(url.ptr, url.len, proxy.ptr, proxy.len, bypass.ptr, bypass.len, &buf, cap, &n);
        if (n > cap) return self.fail("out_len exceeds capacity", url, proxy, bypass);
        for (buf[cap..]) |c| if (c != 0xA5) return self.fail("wrote past capacity", url, proxy, bypass);
        var r = Res{ .status = st, .out = undefined, .len = n };
        @memcpy(r.out[0..n], buf[0..n]);
        return r;
    }

    fn fail(self: *Ctx, why: []const u8, url: []const u8, proxy: []const u8, bypass: []const u8) error{Divergence} {
        std.debug.print("DIVERGENCE iter={d} relation={s}: {s}\n  url={s}\n  proxy={s}\n  bypass={s}\n", .{ self.iter, self.rel, why, url, proxy, bypass });
        return error.Divergence;
    }

    fn expect(self: *Ctx, want: u32, url: []const u8, proxy: []const u8, bypass: []const u8) !Res {
        const r = try self.call(url, proxy, bypass, 96);
        if (r.status != want) {
            var msg: [64]u8 = undefined;
            return self.fail(std.fmt.bufPrint(&msg, "status {d}, expected {d}", .{ r.status, want }) catch "status", url, proxy, bypass);
        }
        return r;
    }

    fn same(self: *Ctx, a: Res, b: Res, url: []const u8, proxy: []const u8, bypass: []const u8) !void {
        if (a.status != b.status or !std.mem.eql(u8, a.out[0..a.len], b.out[0..b.len])) return self.fail("transformed input changed the result", url, proxy, bypass);
    }
};

const alpha = "abcdefghijklmnopqrstuvwxyz0123456789";

fn label(rnd: std.Random, w: *std.Io.Writer) !void {
    const n = 1 + rnd.uintLessThan(usize, 6);
    for (0..n) |_| try w.writeByte(alpha[rnd.uintLessThan(usize, alpha.len)]);
}

fn randCase(rnd: std.Random, s: []const u8, out: []u8) []u8 {
    for (s, 0..) |c, i| out[i] = if (rnd.boolean()) std.ascii.toUpper(c) else c;
    return out[0..s.len];
}

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 3 and args.len != 4) return error.InvalidArguments;
    const iterations = try std.fmt.parseInt(u32, args[2], 10);
    const seed: u64 = if (args.len == 4) try std.fmt.parseInt(u64, args[3], 0) else 0x68747470;
    var lib = try std.DynLib.open(args[1]);
    defer lib.close();
    const sel = lib.lookup(Select, "winlux_select_proxy") orelse return error.MissingEntryPoint;
    var prng = std.Random.DefaultPrng.init(seed);
    var ctx = Ctx{ .sel = sel, .rnd = prng.random() };
    const rnd = ctx.rnd;
    var relations: u64 = 0;

    for (0..iterations) |iter| {
        ctx.iter = iter;
        // ---- scenario ----
        var hbuf: [64]u8 = undefined;
        var hw = std.Io.Writer.fixed(&hbuf);
        const labels = 1 + rnd.uintLessThan(usize, 3);
        for (0..labels) |k| {
            if (k > 0) try hw.writeByte('.');
            try label(rnd, &hw);
        }
        const host = hw.buffered();
        const https = rnd.boolean();
        const scheme: []const u8 = if (https) "https" else "http";
        const other: []const u8 = if (https) "http" else "https";
        const explicit = rnd.boolean();
        var port: u32 = if (https) 443 else 80;
        var ubuf: [160]u8 = undefined;
        var uw = std.Io.Writer.fixed(&ubuf);
        if (explicit) {
            port = 1 + rnd.uintLessThan(u32, 65000);
            try uw.print("{s}://{s}:{d}/p/q?x=1", .{ scheme, host, port });
        } else try uw.print("{s}://{s}/p", .{ scheme, host });
        const url = uw.buffered();
        var pbuf: [48]u8 = undefined;
        const P = try std.fmt.bufPrint(&pbuf, "px{d}.corp:{d}", .{ rnd.uintLessThan(u32, 1000), 1 + rnd.uintLessThan(u32, 65000) });
        var db: [96]u8 = undefined;
        const decoys = try std.fmt.bufPrint(&db, "d{d}.zz-decoy {s};e{d}.zz-decoy", .{ rnd.uintLessThan(u32, 99), "f.zz-decoy", rnd.uintLessThan(u32, 99) });

        ctx.rel = "R1";
        _ = try ctx.expect(NO_PROXY, url, "", decoys);
        ctx.rel = "R2";
        const r2 = try ctx.expect(PROXY, url, P, "");
        if (!std.mem.eql(u8, r2.out[0..r2.len], P)) return ctx.fail("unscoped server text changed", url, P, "");
        ctx.rel = "R3";
        var sb: [96]u8 = undefined;
        _ = try ctx.expect(NO_PROXY, url, try std.fmt.bufPrint(&sb, "{s}={s}", .{ other, P }), "");
        const r3 = try ctx.expect(PROXY, url, try std.fmt.bufPrint(&sb, "{s}={s}", .{ scheme, P }), "");
        if (!std.mem.eql(u8, r3.out[0..r3.len], P)) return ctx.fail("scoped server text changed", url, P, "");
        _ = try ctx.expect(PROXY, url, try std.fmt.bufPrint(&sb, "{s}={s}://{s} {s}={s}", .{ scheme, scheme, P, other, "zz.other:1" }), "");
        ctx.rel = "R4";
        _ = try ctx.expect(BYPASSED, url, P, "*");
        ctx.rel = "R5";
        var bb: [160]u8 = undefined;
        _ = try ctx.expect(BYPASSED, url, P, try std.fmt.bufPrint(&bb, "{s};{s}", .{ decoys, host }));
        _ = try ctx.expect(PROXY, url, P, decoys);
        ctx.rel = "R6";
        var cb: [64]u8 = undefined;
        var ub2: [200]u8 = undefined;
        var ub3: [220]u8 = undefined;
        const url_cased = blk: {
            const head = randCase(rnd, scheme, ub2[0..8]);
            const hc = randCase(rnd, host, ub2[8..]);
            break :blk try std.fmt.bufPrint(&ub3, "{s}://{s}{s}", .{ head, hc, url[scheme.len + 3 + host.len ..] });
        };
        const base6 = try ctx.expect(BYPASSED, url, P, host);
        const cased = try ctx.call(url_cased, P, randCase(rnd, host, &cb), 96);
        try ctx.same(base6, cased, url_cased, P, host);
        ctx.rel = "R7";
        var first: ?Res = null;
        for (0..3) |variant| {
            const order = rnd.uintLessThan(u8, 3);
            const toks = [3][]const u8{ "a.zz-decoy", host, "b.zz-decoy" };
            const t0 = toks[order % 3];
            const t1 = toks[(order + 1) % 3];
            const t2 = toks[(order + 2) % 3];
            const sep: []const u8 = switch (variant) {
                0 => ";",
                1 => " ",
                else => ";  \t",
            };
            const lst = try std.fmt.bufPrint(&bb, "{s}{s}{s}{s}{s}", .{ t0, sep, t1, sep, t2 });
            const r = try ctx.expect(BYPASSED, url, P, lst);
            if (first) |f| try ctx.same(f, r, url, P, lst) else first = r;
        }
        ctx.rel = "R8";
        const dotless = std.mem.indexOfScalar(u8, host, '.') == null;
        _ = try ctx.expect(if (dotless) BYPASSED else PROXY, url, P, "<local>");
        _ = try ctx.expect(if (dotless) BYPASSED else PROXY, url, P, "<LOCAL>");
        ctx.rel = "R9";
        _ = try ctx.expect(BYPASSED, url, P, try std.fmt.bufPrint(&bb, "{s}:{d}", .{ host, port }));
        _ = try ctx.expect(PROXY, url, P, try std.fmt.bufPrint(&bb, "{s}:{d}", .{ host, if (port == 65535) port - 1 else port + 1 }));
        ctx.rel = "R10";
        if (std.mem.indexOfScalar(u8, host, '.')) |dot| {
            _ = try ctx.expect(BYPASSED, url, P, try std.fmt.bufPrint(&bb, "*{s}", .{host[dot..]}));
            _ = try ctx.expect(PROXY, url, P, try std.fmt.bufPrint(&bb, "*{s}.zz-decoy", .{host[dot..]}));
        }
        ctx.rel = "R11";
        const small = try ctx.call(url, P, "", P.len - 1);
        if (small.status != E_BUF or small.len != 0) return ctx.fail("small buffer must return 122 with out_len 0", url, P, "");
        const exact = try ctx.call(url, P, "", P.len);
        if (exact.status != PROXY or exact.len != P.len) return ctx.fail("exact-size buffer must succeed", url, P, "");
        ctx.rel = "R12";
        _ = try ctx.expect(E_SCHEME, "ftp://h.example/", P, "");
        _ = try ctx.expect(E_URL, "h.example", P, "");
        _ = try ctx.expect(E_URL, "http://", P, "");
        _ = try ctx.expect(E_URL, "https://:80/", P, "");
        ctx.rel = "R13";
        var g1: [40]u8 = undefined;
        var g2: [40]u8 = undefined;
        var g3: [40]u8 = undefined;
        rnd.bytes(&g1);
        rnd.bytes(&g2);
        rnd.bytes(&g3);
        if (rnd.boolean()) @memcpy(g1[0..7], "http://");
        const gr = try ctx.call(g1[0..rnd.uintLessThan(usize, 40)], g2[0..rnd.uintLessThan(usize, 40)], g3[0..rnd.uintLessThan(usize, 40)], 16);
        switch (gr.status) {
            PROXY, NO_PROXY, BYPASSED, E_BUF, E_URL, E_SCHEME => {},
            else => return ctx.fail("unexpected status for garbage input", &g1, &g2, &g3),
        }
        relations += 31;
    }
    std.debug.print("MATCHED iterations={d} seed=0x{x} relation_checks_nominal={d}; proxy selection only, no real WinHTTP compared\n", .{ iterations, seed, relations });
}
