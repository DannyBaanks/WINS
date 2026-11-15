//! winluxhttp: Linux-native, PARTIAL replacement for the proxy-selection logic that
//! qt6network.dll / qt6webenginecore.dll use through WinHTTP (WinHttpOpen,
//! WinHttpGetProxyForUrl, WinHttpGetIEProxyConfigForCurrentUser, ...).
//!
//! Implemented: choosing a proxy for an http/https URL from a static proxy list
//! and a bypass list, using the documented WINHTTP_PROXY_INFO string formats
//!   proxy : ([<scheme>=][<scheme>://]<server>[:<port>][ ;])*
//!   bypass: (<host-pattern>[:<port>] | <local>)  separated by ';' or whitespace
//! NOT implemented: PAC scripts, WPAD auto-detection (a caller should report
//! ERROR_WINHTTP_AUTODETECTION_FAILED), actual HTTP transport, credentials, and
//! the HINTERNET handle API. There is no Windows kernel here to compare with, so
//! behaviour in the corners the documentation does not pin down is an ASSUMPTION
//! (listed in native/shims/GUIA.md) and is NOT_DEMONSTRATED against real WinHTTP.
const std = @import("std");

pub const PROXY: u32 = 0; // `out` holds "server[:port]"
pub const DIRECT_NO_PROXY: u32 = 1; // no proxy entry applies to this scheme
pub const DIRECT_BYPASSED: u32 = 2; // a proxy applies but the bypass list matches
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
pub const ERROR_WINHTTP_INVALID_URL: u32 = 12005;
pub const ERROR_WINHTTP_UNRECOGNIZED_SCHEME: u32 = 12006;

pub const Bug = enum { none, ignore_scheme, case_sensitive_bypass };

const Scheme = enum { http, https };

fn isSep(c: u8) bool {
    return c == ';' or c == ' ' or c == '\t' or c == '\r' or c == '\n';
}

const Url = struct { scheme: Scheme, host: []const u8, port: u16 };

fn parseUrl(url: []const u8) union(enum) { ok: Url, err: u32 } {
    const sep = std.mem.indexOf(u8, url, "://") orelse return .{ .err = ERROR_WINHTTP_INVALID_URL };
    const scheme: Scheme = if (std.ascii.eqlIgnoreCase(url[0..sep], "http")) .http else if (std.ascii.eqlIgnoreCase(url[0..sep], "https")) .https else return .{ .err = ERROR_WINHTTP_UNRECOGNIZED_SCHEME };
    var rest = url[sep + 3 ..];
    if (std.mem.indexOfAny(u8, rest, "/?#")) |i| rest = rest[0..i];
    if (std.mem.lastIndexOfScalar(u8, rest, '@')) |i| rest = rest[i + 1 ..];
    var host = rest;
    var port: u16 = if (scheme == .http) 80 else 443;
    if (rest.len > 0 and rest[0] == '[') {
        const close = std.mem.indexOfScalar(u8, rest, ']') orelse return .{ .err = ERROR_WINHTTP_INVALID_URL };
        host = rest[0 .. close + 1];
        const after = rest[close + 1 ..];
        if (after.len > 0) {
            if (after[0] != ':') return .{ .err = ERROR_WINHTTP_INVALID_URL };
            port = std.fmt.parseInt(u16, after[1..], 10) catch return .{ .err = ERROR_WINHTTP_INVALID_URL };
        }
    } else if (std.mem.lastIndexOfScalar(u8, rest, ':')) |i| {
        host = rest[0..i];
        port = std.fmt.parseInt(u16, rest[i + 1 ..], 10) catch return .{ .err = ERROR_WINHTTP_INVALID_URL };
    }
    if (host.len == 0) return .{ .err = ERROR_WINHTTP_INVALID_URL };
    return .{ .ok = .{ .scheme = scheme, .host = host, .port = port } };
}

pub fn Impl(comptime bug: Bug) type {
    return struct {
        fn eq(a: u8, b: u8) bool {
            return if (bug == .case_sensitive_bypass) a == b else std.ascii.toLower(a) == std.ascii.toLower(b);
        }

        /// '*' matches any run of characters; everything else is literal.
        fn glob(pat: []const u8, s: []const u8) bool {
            var p: usize = 0;
            var i: usize = 0;
            var star: ?usize = null;
            var mark: usize = 0;
            while (i < s.len) {
                if (p < pat.len and pat[p] == '*') {
                    star = p;
                    mark = i;
                    p += 1;
                } else if (p < pat.len and eq(pat[p], s[i])) {
                    p += 1;
                    i += 1;
                } else if (star) |st| {
                    p = st + 1;
                    mark += 1;
                    i = mark;
                } else return false;
            }
            while (p < pat.len and pat[p] == '*') p += 1;
            return p == pat.len;
        }

        fn bypassed(u: Url, bypass: []const u8) bool {
            var it = std.mem.tokenizeAny(u8, bypass, ";  \t\r\n");
            while (it.next()) |tok| {
                if (std.ascii.eqlIgnoreCase(tok, "<local>")) {
                    if (std.mem.indexOfScalar(u8, u.host, '.') == null and u.host[0] != '[') return true;
                    continue;
                }
                var pat = tok;
                var want_port: ?u16 = null;
                if (std.mem.lastIndexOfScalar(u8, tok, ':')) |i| {
                    if (i + 1 < tok.len and tok[0] != '[') {
                        if (std.fmt.parseInt(u16, tok[i + 1 ..], 10)) |pv| {
                            want_port = pv;
                            pat = tok[0..i];
                        } else |_| {}
                    }
                }
                if (want_port) |wp| if (wp != u.port) continue;
                if (glob(pat, u.host)) return true;
            }
            return false;
        }

        /// Returns the first entry that applies to `scheme` (scoped to it, or unscoped).
        fn pick(proxy: []const u8, scheme: Scheme) ?[]const u8 {
            var it = std.mem.tokenizeAny(u8, proxy, ";  \t\r\n");
            while (it.next()) |tok| {
                var server = tok;
                var scoped: ?Scheme = null;
                if (std.mem.indexOfScalar(u8, tok, '=')) |i| {
                    const key = tok[0..i];
                    scoped = if (std.ascii.eqlIgnoreCase(key, "http")) .http else if (std.ascii.eqlIgnoreCase(key, "https")) .https else continue;
                    server = tok[i + 1 ..];
                }
                if (std.mem.indexOf(u8, server, "://")) |i| server = server[i + 3 ..];
                if (server.len == 0) continue;
                if (scoped) |sc| {
                    if (sc != scheme and bug != .ignore_scheme) continue;
                }
                return server;
            }
            return null;
        }

        pub fn select(url: ?[*]const u8, url_len: usize, proxy: ?[*]const u8, proxy_len: usize, bypass: ?[*]const u8, bypass_len: usize, out: ?[*]u8, out_cap: usize, out_len: *usize) callconv(.c) u32 {
            out_len.* = 0;
            const u = switch (parseUrl(if (url) |p| p[0..url_len] else "")) {
                .ok => |v| v,
                .err => |e| return e,
            };
            const server = pick(if (proxy) |p| p[0..proxy_len] else "", u.scheme) orelse return DIRECT_NO_PROXY;
            if (bypassed(u, if (bypass) |p| p[0..bypass_len] else "")) return DIRECT_BYPASSED;
            if (server.len > out_cap or out == null) return ERROR_INSUFFICIENT_BUFFER;
            @memcpy(out.?[0..server.len], server);
            out_len.* = server.len;
            return PROXY;
        }
    };
}
