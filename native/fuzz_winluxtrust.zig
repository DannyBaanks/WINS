//! Run ONLY within the WINS cleanroom: opening a library executes constructors.
//!
//! Mutation fuzzer for the winluxtrust candidate (digest half of WinVerifyTrust).
//!   usage: runner CANDIDATE.so SIGNED_PE ORIGINAL_DIGEST_HEX ITERATIONS [SEED]
//! ORIGINAL_DIGEST_HEX must come from an independent tool (osslsigncode "Current
//! message digest"), so the pristine file is not judged by the candidate itself.
//! Each mutation is classified from the Authenticode layout, not from the candidate:
//!   section/trailing byte flipped -> BAD_DIGEST     (covered by the hash)
//!   header byte flipped        -> any rejection, never MATCH (a flipped structural field,
//!                                 e.g. PointerToRawData, may make the file uninterpretable)
//!   checksum field flipped     -> MATCH             (excluded from the hash)
//!   trailing bytes appended    -> BAD_DIGEST        (spec: extra data is hashed)
//!   signature blob flipped     -> MATCH only if both digests equal the original;
//!                                 BAD_DIGEST only if the embedded digest changed
//!   truncation                 -> never MATCH
//!   header/directory garbage   -> never crash
//! The return value 0 (ERROR_SUCCESS) is never acceptable: chain validation is
//! not implemented, so nothing may look "trusted".
const std = @import("std");

const Verdict = extern struct { alg: u32, digest_len: u32, embedded: [64]u8, computed: [64]u8 };
const Verify = *const fn (?[*]const u8, usize, *Verdict) callconv(.c) u32;

const BAD_DIGEST: u32 = 0x80096010;
const MATCH: u32 = 0x20570001;

fn rd32(b: []const u8, p: usize) u32 {
    return std.mem.readInt(u32, b[p..][0..4], .little);
}

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 5 and args.len != 6) return error.InvalidArguments;
    const iterations = try std.fmt.parseInt(u32, args[4], 10);
    const seed: u64 = if (args.len == 6) try std.fmt.parseInt(u64, args[5], 0) else 0x7472757374;
    var orig: [64]u8 = @splat(0);
    const orig_len = args[3].len / 2;
    if (args[3].len % 2 != 0 or orig_len == 0 or orig_len > 64) return error.InvalidDigest;
    _ = try std.fmt.hexToBytes(orig[0..orig_len], args[3]);

    var lib = try std.DynLib.open(args[1]);
    defer lib.close();
    const verify = lib.lookup(Verify, "winlux_verify_trust") orelse return error.MissingEntryPoint;

    const base_len = (try std.Io.Dir.cwd().statFile(io, args[2], .{})).size;
    const buf = try a.alloc(u8, base_len + 64);
    const base = try std.Io.Dir.cwd().readFileAlloc(io, args[2], a, .limited(64 * 1024 * 1024));
    @memcpy(buf[0..base.len], base);
    const len = base.len;

    // Independent layout read (not shared with the candidate).
    const e = rd32(base, 0x3c);
    const opt = e + 24;
    const dirs: usize = if (std.mem.readInt(u16, base[opt..][0..2], .little) == 0x20b) 112 else 96;
    const checksum = opt + 64;
    const entry = opt + dirs + 4 * 8;
    const cert_off: usize = rd32(base, entry);
    const cert_size: usize = rd32(base, entry + 4);
    if (cert_off == 0 or cert_off + cert_size != len) return error.FixtureNotSignedAtEnd;

    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    var v: Verdict = undefined;

    // Pristine file: the candidate must reproduce the independently obtained digest.
    var rc = verify(buf.ptr, len, &v);
    if (rc != MATCH or !std.mem.eql(u8, v.embedded[0..orig_len], orig[0..orig_len]) or !std.mem.eql(u8, v.computed[0..orig_len], orig[0..orig_len])) {
        std.debug.print("DIVERGENCE pristine rc=0x{x} (expected 0x{x}) digest_len={d}\n", .{ rc, MATCH, v.digest_len });
        return error.Divergence;
    }

    var counts = [_]u64{0} ** 7;
    for (0..iterations) |iter| {
        const kind = rnd.uintLessThan(u8, 10);
        var call_len = len;
        var flips: [3]usize = .{ 0, 0, 0 };
        var nflips: usize = 0;
        var expect: enum { bad_digest, match, blob, never_match, reject, anything } = .anything;
        var label: usize = 0;
        switch (kind) {
            0, 1, 2, 3 => { // hashed byte
                var i: usize = undefined;
                while (true) {
                    i = rnd.uintLessThan(usize, cert_off);
                    if ((i >= checksum and i < checksum + 4) or (i >= entry and i < entry + 8)) continue;
                    break;
                }
                flips[0] = i;
                nflips = 1;
                const in_headers = i < @as(usize, rd32(base, opt + 60));
                expect = if (in_headers) .reject else .bad_digest;
                label = if (in_headers) 6 else 0;
            },
            4 => {
                flips[0] = checksum + rnd.uintLessThan(usize, 4);
                nflips = 1;
                expect = .match;
                label = 1;
            },
            5, 6 => {
                nflips = 1 + rnd.uintLessThan(usize, 3);
                for (0..nflips) |k| flips[k] = cert_off + rnd.uintLessThan(usize, cert_size);
                expect = .blob;
                label = 2;
            },
            7 => {
                call_len = rnd.uintLessThan(usize, len);
                expect = .never_match;
                label = 3;
            },
            8 => {
                const n = 1 + rnd.uintLessThan(usize, 64);
                rnd.bytes(buf[len .. len + n]);
                call_len = len + n;
                expect = .bad_digest;
                label = 4;
            },
            else => { // structural garbage in headers / certificate directory entry
                const span: usize = rd32(base, opt + 60); // SizeOfHeaders
                nflips = 1 + rnd.uintLessThan(usize, 3);
                for (0..nflips) |k| flips[k] = if (rnd.boolean()) entry + rnd.uintLessThan(usize, 8) else rnd.uintLessThan(usize, @min(span, len));
                expect = .anything;
                label = 5;
            },
        }
        var saved: [3]u8 = undefined;
        for (0..nflips) |k| {
            saved[k] = buf[flips[k]];
            buf[flips[k]] ^= @as(u8, 1) << @intCast(rnd.uintLessThan(u8, 8));
        }
        rc = verify(buf.ptr, call_len, &v);
        // Restore in reverse so repeated indices unwind correctly.
        var k = nflips;
        while (k > 0) {
            k -= 1;
            buf[flips[k]] = saved[k];
        }
        counts[label] += 1;
        const emb_orig = std.mem.eql(u8, v.embedded[0..orig_len], orig[0..orig_len]);
        const comp_orig = std.mem.eql(u8, v.computed[0..orig_len], orig[0..orig_len]);
        const bad: ?[]const u8 = blk: {
            if (rc == 0) break :blk "returned ERROR_SUCCESS (chain is not validated)";
            switch (expect) {
                .bad_digest => if (rc != BAD_DIGEST) break :blk "expected BAD_DIGEST",
                .match => if (rc != MATCH) break :blk "expected MATCH (excluded field)",
                .never_match => if (rc == MATCH) break :blk "MATCH on truncated file",
                .reject => if (rc == MATCH) break :blk "MATCH after corrupting header bytes",
                .blob => {
                    if (rc == MATCH and !(emb_orig and comp_orig)) break :blk "MATCH but digests differ from the original";
                    if (rc == BAD_DIGEST and emb_orig) break :blk "BAD_DIGEST although the embedded digest is unchanged";
                },
                .anything => if (rc == MATCH and !std.mem.eql(u8, v.embedded[0..v.digest_len], v.computed[0..v.digest_len])) break :blk "MATCH with unequal digests",
            }
            break :blk null;
        };
        if (bad) |why| {
            std.debug.print("DIVERGENCE iter={d} class={d} rc=0x{x} len={d}/{d} flips={any}: {s}\n", .{ iter, label, rc, call_len, len, flips[0..nflips], why });
            return error.Divergence;
        }
    }
    std.debug.print("MATCHED iterations={d} seed=0x{x} classes[data={d} header={d} checksum={d} blob={d} truncated={d} appended={d} structural={d}]; digest half only, chain NOT validated\n", .{ iterations, seed, counts[0], counts[6], counts[1], counts[2], counts[3], counts[4], counts[5] });
}
