//! winluxtrust: Linux-native, PARTIAL replacement for the digest half of WinVerifyTrust.
//!
//! Implemented: Authenticode PE hashing (spec: "Windows Authenticode Portable
//! Executable Signature Format") and extraction of the digest embedded in the
//! PKCS#7 SpcIndirectDataContent, then comparison.
//! NOT implemented (so this can never report trust): certificate chain building,
//! signature-value verification, revocation, timestamps, catalog files, the
//! WTHelper* provider-data accessors, and non-PE subjects.
//!
//! A digest match therefore returns WINLUX_DIGEST_MATCH_CHAIN_UNVERIFIED, which is
//! deliberately NOT ERROR_SUCCESS (0): callers must not treat it as "trusted".
//! Windows' own HRESULTs are used only where this code is certain of their value.
const std = @import("std");
const crypto = std.crypto;

pub const TRUST_E_SUBJECT_FORM_UNKNOWN: u32 = 0x800B0003;
pub const TRUST_E_NOSIGNATURE: u32 = 0x800B0100;
pub const TRUST_E_BAD_DIGEST: u32 = 0x80096010;
/// winlux-specific (customer bit set; never produced by Windows).
pub const WINLUX_DIGEST_MATCH_CHAIN_UNVERIFIED: u32 = 0x20570001;
pub const WINLUX_E_MALFORMED_SIGNATURE: u32 = 0xA0570001;
pub const WINLUX_E_UNSUPPORTED_DIGEST: u32 = 0xA0570002;

pub const Verdict = extern struct { alg: u32, digest_len: u32, embedded: [64]u8, computed: [64]u8 };

pub const Bug = enum { none, hash_checksum, accept_any };

const Alg = enum(u32) { none = 0, sha1 = 1, sha256 = 2, sha384 = 3, sha512 = 4 };

fn rd(comptime T: type, b: []const u8, p: usize) ?T {
    if (p > b.len or @sizeOf(T) > b.len - p) return null;
    return std.mem.readInt(T, b[p..][0..@sizeOf(T)], .little);
}

const Tlv = struct { tag: u8, body: []const u8, rest: []const u8 };

/// Strict, bounds-checked DER element reader (definite lengths only, low tag numbers only).
fn tlv(b: []const u8) ?Tlv {
    if (b.len < 2 or b[0] & 0x1f == 0x1f) return null;
    var len: usize = b[1];
    var i: usize = 2;
    if (len & 0x80 != 0) {
        const n = len & 0x7f;
        if (n == 0 or n > 4 or b.len < 2 + n) return null;
        len = 0;
        for (b[2 .. 2 + n]) |x| len = (len << 8) | x;
        i = 2 + n;
    }
    if (len > b.len - i) return null;
    return .{ .tag = b[0], .body = b[i..][0..len], .rest = b[i + len ..] };
}

fn expect(b: []const u8, tag: u8) ?Tlv {
    const t = tlv(b) orelse return null;
    return if (t.tag == tag) t else null;
}

const oid_signed_data = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 };
const oid_spc_indirect = [_]u8{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04 };
const oid_sha1 = [_]u8{ 0x2B, 0x0E, 0x03, 0x02, 0x1A };
const oid_sha256 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
const oid_sha384 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
const oid_sha512 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };

const Embedded = struct { alg: Alg, digest: []const u8 };

const ParseError = enum { malformed, unsupported };
const Parsed = union(enum) { ok: Embedded, err: ParseError };

/// Walks ContentInfo{signedData} -> SignedData -> ContentInfo{SpcIndirectData} -> DigestInfo.
fn embeddedDigest(blob: []const u8) Parsed {
    const bad: Parsed = .{ .err = .malformed };
    const ci = expect(blob, 0x30) orelse return bad;
    const oid = expect(ci.body, 0x06) orelse return bad;
    if (!std.mem.eql(u8, oid.body, &oid_signed_data)) return bad;
    const wrap = expect(oid.rest, 0xA0) orelse return bad;
    const sd = expect(wrap.body, 0x30) orelse return bad;
    const version = expect(sd.body, 0x02) orelse return bad;
    const algs = expect(version.rest, 0x31) orelse return bad;
    const inner = expect(algs.rest, 0x30) orelse return bad;
    const inner_oid = expect(inner.body, 0x06) orelse return bad;
    if (!std.mem.eql(u8, inner_oid.body, &oid_spc_indirect)) return bad;
    const content = expect(inner_oid.rest, 0xA0) orelse return bad;
    var spc = tlv(content.body) orelse return bad;
    if (spc.tag == 0x04) spc = tlv(spc.body) orelse return bad; // CMS-style OCTET STRING wrapper
    if (spc.tag != 0x30) return bad;
    const data = expect(spc.body, 0x30) orelse return bad; // SpcAttributeTypeAndOptionalValue
    const di = expect(data.rest, 0x30) orelse return bad; // DigestInfo
    const aid = expect(di.body, 0x30) orelse return bad;
    const aoid = expect(aid.body, 0x06) orelse return bad;
    const dig = expect(aid.rest, 0x04) orelse return bad;
    const alg: Alg = if (std.mem.eql(u8, aoid.body, &oid_sha1)) .sha1 else if (std.mem.eql(u8, aoid.body, &oid_sha256)) .sha256 else if (std.mem.eql(u8, aoid.body, &oid_sha384)) .sha384 else if (std.mem.eql(u8, aoid.body, &oid_sha512)) .sha512 else return .{ .err = .unsupported };
    const want: usize = switch (alg) {
        .sha1 => 20,
        .sha256 => 32,
        .sha384 => 48,
        .sha512 => 64,
        .none => unreachable,
    };
    if (dig.body.len != want) return bad;
    return .{ .ok = .{ .alg = alg, .digest = dig.body } };
}

const Layout = struct {
    checksum_off: usize,
    cert_entry_off: ?usize,
    headers_size: usize,
    sections_at: usize,
    section_count: usize,
    cert_off: usize,
    cert_size: usize,
};

fn layout(pe: []const u8) ?Layout {
    if (pe.len < 64 or !std.mem.eql(u8, pe[0..2], "MZ")) return null;
    const e: usize = rd(u32, pe, 0x3c) orelse return null;
    if (e > pe.len or pe.len - e < 24 or !std.mem.eql(u8, pe[e..][0..4], "PE\x00\x00")) return null;
    const count: usize = rd(u16, pe, e + 6) orelse return null;
    const opt_size: usize = rd(u16, pe, e + 20) orelse return null;
    const opt = e + 24;
    const magic = rd(u16, pe, opt) orelse return null;
    const dirs: usize = switch (magic) {
        0x10b => 96,
        0x20b => 112,
        else => return null,
    };
    if (opt_size < dirs or opt > pe.len or opt_size > pe.len - opt) return null;
    const headers_size: usize = rd(u32, pe, opt + 60) orelse return null;
    const num_dirs: usize = rd(u32, pe, opt + dirs - 4) orelse return null;
    const sections_at = opt + opt_size;
    if (count > (pe.len -| sections_at) / 40) return null;
    var cert_entry: ?usize = null;
    var cert_off: usize = 0;
    var cert_size: usize = 0;
    if (num_dirs > 4 and opt_size >= dirs + 5 * 8) {
        cert_entry = opt + dirs + 4 * 8;
        cert_off = rd(u32, pe, cert_entry.?) orelse return null;
        cert_size = rd(u32, pe, cert_entry.? + 4) orelse return null;
    }
    if (headers_size > pe.len or headers_size < sections_at) return null;
    return .{ .checksum_off = opt + 64, .cert_entry_off = cert_entry, .headers_size = headers_size, .sections_at = sections_at, .section_count = count, .cert_off = cert_off, .cert_size = cert_size };
}

pub fn Impl(comptime bug: Bug) type {
    return struct {
        fn authenticode(comptime H: type, pe: []const u8, l: Layout, out: *[64]u8) bool {
            var h = H.init(.{});
            // 1. headers, minus checksum field and certificate directory entry
            var pos: usize = 0;
            const skips = [_]struct { off: usize, len: usize }{
                .{ .off = l.checksum_off, .len = if (bug == .hash_checksum) 0 else 4 },
                .{ .off = l.cert_entry_off orelse l.headers_size, .len = if (l.cert_entry_off != null) 8 else 0 },
            };
            for (skips) |s| {
                if (s.off < pos or s.off + s.len > l.headers_size) return false;
                h.update(pe[pos..s.off]);
                pos = s.off + s.len;
            }
            h.update(pe[pos..l.headers_size]);
            var hashed: usize = l.headers_size;
            // 2. section raw data in ascending PointerToRawData order
            var order: [96]struct { ptr: usize, size: usize } = undefined;
            if (l.section_count > order.len) return false;
            var n: usize = 0;
            for (0..l.section_count) |i| {
                const at = l.sections_at + i * 40;
                const size: usize = rd(u32, pe, at + 16) orelse return false;
                const ptr: usize = rd(u32, pe, at + 20) orelse return false;
                if (size == 0) continue;
                order[n] = .{ .ptr = ptr, .size = size };
                n += 1;
            }
            std.mem.sort(@TypeOf(order[0]), order[0..n], {}, struct {
                fn lt(_: void, a: @TypeOf(order[0]), b: @TypeOf(order[0])) bool {
                    return a.ptr < b.ptr;
                }
            }.lt);
            for (order[0..n]) |s| {
                if (s.ptr > pe.len or s.size > pe.len - s.ptr) return false;
                h.update(pe[s.ptr..][0..s.size]);
                hashed += s.size;
            }
            // 3. trailing data other than the certificate table: [end of sections, EOF) minus the table.
            var p = hashed;
            if (p > pe.len) return false;
            if (l.cert_off >= p and l.cert_size <= pe.len - l.cert_off) {
                h.update(pe[p..l.cert_off]);
                p = l.cert_off + l.cert_size;
            }
            h.update(pe[p..]);
            var tmp: [H.digest_length]u8 = undefined;
            h.final(&tmp);
            @memcpy(out[0..tmp.len], &tmp);
            return true;
        }

        pub fn verify(data: ?[*]const u8, len: usize, out: *Verdict) callconv(.c) u32 {
            out.* = std.mem.zeroes(Verdict);
            const pe = if (data) |p| p[0..len] else return TRUST_E_SUBJECT_FORM_UNKNOWN;
            const l = layout(pe) orelse return TRUST_E_SUBJECT_FORM_UNKNOWN;
            if (l.cert_entry_off == null or (l.cert_off == 0 and l.cert_size == 0)) return TRUST_E_NOSIGNATURE;
            if (l.cert_size < 8 or l.cert_off > pe.len or l.cert_size > pe.len - l.cert_off) return WINLUX_E_MALFORMED_SIGNATURE;
            const cert = pe[l.cert_off..][0..l.cert_size];
            const wlen: usize = rd(u32, cert, 0) orelse return WINLUX_E_MALFORMED_SIGNATURE;
            const rev = rd(u16, cert, 4) orelse return WINLUX_E_MALFORMED_SIGNATURE;
            const kind = rd(u16, cert, 6) orelse return WINLUX_E_MALFORMED_SIGNATURE;
            if (kind != 2 or (rev != 0x200 and rev != 0x100) or wlen < 8 or wlen > cert.len) return WINLUX_E_MALFORMED_SIGNATURE;
            const emb = switch (embeddedDigest(cert[8..wlen])) {
                .ok => |e| e,
                .err => |e| return if (e == .unsupported) WINLUX_E_UNSUPPORTED_DIGEST else WINLUX_E_MALFORMED_SIGNATURE,
            };
            out.alg = @intFromEnum(emb.alg);
            out.digest_len = @intCast(emb.digest.len);
            @memcpy(out.embedded[0..emb.digest.len], emb.digest);
            const ok = switch (emb.alg) {
                .sha1 => authenticode(crypto.hash.Sha1, pe, l, &out.computed),
                .sha256 => authenticode(crypto.hash.sha2.Sha256, pe, l, &out.computed),
                .sha384 => authenticode(crypto.hash.sha2.Sha384, pe, l, &out.computed),
                .sha512 => authenticode(crypto.hash.sha2.Sha512, pe, l, &out.computed),
                .none => unreachable,
            };
            if (!ok) return TRUST_E_SUBJECT_FORM_UNKNOWN;
            if (bug == .accept_any) return WINLUX_DIGEST_MATCH_CHAIN_UNVERIFIED;
            if (!crypto.timing_safe.eql([64]u8, out.embedded, out.computed)) return TRUST_E_BAD_DIGEST;
            return WINLUX_DIGEST_MATCH_CHAIN_UNVERIFIED;
        }
    };
}
