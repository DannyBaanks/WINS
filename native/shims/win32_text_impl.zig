//! Linux-native candidate for the documented behaviour of MultiByteToWideChar and
//! WideCharToMultiByte restricted to CP_UTF8. It is NOT a PE loader and does not
//! provide a Windows ABI: the entry points take an explicit error out-parameter
//! instead of touching GetLastError, so the fuzzer can observe the error code.
//!
//! Documented behaviour modelled here (docs.microsoft.com, CP_UTF8):
//!  * flags: 0 or MB_ERR_INVALID_CHARS (0x8) / WC_ERR_INVALID_CHARS (0x80), else 1004.
//!  * length -1 means NUL-terminated and the terminator is converted and counted.
//!  * destination size 0 returns the required size and writes nothing.
//!  * too-small destination returns 0 with 122 (ERROR_INSUFFICIENT_BUFFER).
//!  * invalid input with the strict flag returns 0 with 1113 (ERROR_NO_UNICODE_TRANSLATION);
//!    without it, invalid input becomes U+FFFD, one per "maximal subpart" (Unicode 3.9).
//!  * bad parameters return 0 with 87 (ERROR_INVALID_PARAMETER).
//! NOT modelled / NOT_DEMONSTRATED against a real Windows kernel: replacement
//! granularity of invalid sequences, and which error wins when several faults coexist.

pub const Bug = enum { none, per_byte, overrun };

const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_INVALID_FLAGS: u32 = 1004;
const ERROR_NO_UNICODE_TRANSLATION: u32 = 1113;
const MB_ERR_INVALID_CHARS: u32 = 0x8;
const WC_ERR_INVALID_CHARS: u32 = 0x80;

const Step = struct { cp: u32, len: usize, bad: bool };

fn fail(err: *u32, code: u32) i32 {
    err.* = code;
    return 0;
}

/// `bug` selects a deliberately defective variant used only as a negative control.
pub fn Impl(comptime bug: Bug) type {
    return struct {
        fn invalid8(consumed: usize) Step {
            return .{ .cp = 0xFFFD, .len = if (bug == .per_byte) 1 else consumed, .bad = true };
        }

        fn step8(s: []const u8, i: usize) Step {
            const b = s[i];
            if (b < 0x80) return .{ .cp = b, .len = 1, .bad = false };
            var need: usize = 0;
            var lo: u8 = 0x80;
            var hi: u8 = 0xBF;
            var cp: u32 = 0;
            switch (b) {
                0xC2...0xDF => {
                    need = 1;
                    cp = b & 0x1F;
                },
                0xE0 => {
                    need = 2;
                    lo = 0xA0;
                    cp = b & 0x0F;
                },
                0xE1...0xEC, 0xEE, 0xEF => {
                    need = 2;
                    cp = b & 0x0F;
                },
                0xED => {
                    need = 2;
                    hi = 0x9F;
                    cp = b & 0x0F;
                },
                0xF0 => {
                    need = 3;
                    lo = 0x90;
                    cp = b & 0x07;
                },
                0xF1...0xF3 => {
                    need = 3;
                    cp = b & 0x07;
                },
                0xF4 => {
                    need = 3;
                    hi = 0x8F;
                    cp = b & 0x07;
                },
                else => return invalid8(1),
            }
            var k: usize = 1;
            while (k <= need) : (k += 1) {
                if (i + k >= s.len) return invalid8(k);
                const c = s[i + k];
                const l: u8 = if (k == 1) lo else 0x80;
                const h: u8 = if (k == 1) hi else 0xBF;
                if (c < l or c > h) return invalid8(k);
                cp = (cp << 6) | (c & 0x3F);
            }
            return .{ .cp = cp, .len = need + 1, .bad = false };
        }

        fn step16(s: []const u16, i: usize) Step {
            const u: u32 = s[i];
            if (u >= 0xD800 and u <= 0xDBFF and i + 1 < s.len) {
                const v: u32 = s[i + 1];
                if (v >= 0xDC00 and v <= 0xDFFF) {
                    return .{ .cp = 0x10000 + ((u - 0xD800) << 10) + (v - 0xDC00), .len = 2, .bad = false };
                }
            }
            if (u >= 0xD800 and u <= 0xDFFF) return .{ .cp = 0xFFFD, .len = 1, .bad = true };
            return .{ .cp = u, .len = 1, .bad = false };
        }

        fn utf8Len(cp: u32) usize {
            return if (cp < 0x80) 1 else if (cp < 0x800) 2 else if (cp < 0x10000) 3 else 4;
        }

        pub fn mb2wc(flags: u32, src: ?[*]const u8, cb: i32, dst: ?[*]u16, cch: i32, err: *u32) callconv(.c) i32 {
            err.* = 0;
            if (flags != 0 and flags != MB_ERR_INVALID_CHARS) return fail(err, ERROR_INVALID_FLAGS);
            if (src == null or cb == 0 or cb < -1 or cch < 0 or (dst == null and cch > 0)) {
                return fail(err, ERROR_INVALID_PARAMETER);
            }
            const p = src.?;
            var n: usize = 0;
            if (cb == -1) {
                while (p[n] != 0) n += 1;
                n += 1;
            } else n = @intCast(cb);
            const s = p[0..n];
            var count: usize = 0;
            var i: usize = 0;
            while (i < n) {
                const st = step8(s, i);
                if (st.bad and flags == MB_ERR_INVALID_CHARS) return fail(err, ERROR_NO_UNICODE_TRANSLATION);
                count += if (st.cp >= 0x10000) 2 else 1;
                i += st.len;
            }
            if (cch == 0) return @intCast(count);
            if (count > @as(usize, @intCast(cch)) and bug != .overrun) return fail(err, ERROR_INSUFFICIENT_BUFFER);
            const d = dst.?;
            var o: usize = 0;
            i = 0;
            while (i < n) {
                const st = step8(s, i);
                if (st.cp >= 0x10000) {
                    const v = st.cp - 0x10000;
                    d[o] = @intCast(0xD800 + (v >> 10));
                    d[o + 1] = @intCast(0xDC00 + (v & 0x3FF));
                    o += 2;
                } else {
                    d[o] = @intCast(st.cp);
                    o += 1;
                }
                i += st.len;
            }
            return @intCast(count);
        }

        pub fn wc2mb(flags: u32, src: ?[*]const u16, cch: i32, dst: ?[*]u8, cb: i32, err: *u32) callconv(.c) i32 {
            err.* = 0;
            if (flags != 0 and flags != WC_ERR_INVALID_CHARS) return fail(err, ERROR_INVALID_FLAGS);
            if (src == null or cch == 0 or cch < -1 or cb < 0 or (dst == null and cb > 0)) {
                return fail(err, ERROR_INVALID_PARAMETER);
            }
            const p = src.?;
            var n: usize = 0;
            if (cch == -1) {
                while (p[n] != 0) n += 1;
                n += 1;
            } else n = @intCast(cch);
            const s = p[0..n];
            var count: usize = 0;
            var i: usize = 0;
            while (i < n) {
                const st = step16(s, i);
                if (st.bad and flags == WC_ERR_INVALID_CHARS) return fail(err, ERROR_NO_UNICODE_TRANSLATION);
                count += utf8Len(st.cp);
                i += st.len;
            }
            if (cb == 0) return @intCast(count);
            if (count > @as(usize, @intCast(cb)) and bug != .overrun) return fail(err, ERROR_INSUFFICIENT_BUFFER);
            const d = dst.?;
            var o: usize = 0;
            i = 0;
            while (i < n) {
                const st = step16(s, i);
                const cp = st.cp;
                switch (utf8Len(cp)) {
                    1 => {
                        d[o] = @intCast(cp);
                    },
                    2 => {
                        d[o] = @intCast(0xC0 | (cp >> 6));
                        d[o + 1] = @intCast(0x80 | (cp & 0x3F));
                    },
                    3 => {
                        d[o] = @intCast(0xE0 | (cp >> 12));
                        d[o + 1] = @intCast(0x80 | ((cp >> 6) & 0x3F));
                        d[o + 2] = @intCast(0x80 | (cp & 0x3F));
                    },
                    else => {
                        d[o] = @intCast(0xF0 | (cp >> 18));
                        d[o + 1] = @intCast(0x80 | ((cp >> 12) & 0x3F));
                        d[o + 2] = @intCast(0x80 | ((cp >> 6) & 0x3F));
                        d[o + 3] = @intCast(0x80 | (cp & 0x3F));
                    },
                }
                o += utf8Len(cp);
                i += st.len;
            }
            return @intCast(count);
        }
    };
}
