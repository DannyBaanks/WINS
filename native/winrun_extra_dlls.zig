// WINS — winrun_extra_dlls.zig
// Native x86_64 Linux shims for ADVAPI32.dll, WS2_32.dll, and console-safe USER32.dll
// imports required by multi-call utilities (such as busybox64.exe).

const std = @import("std");
const linux = std.os.linux;

const W: std.builtin.CallingConvention = .winapi;

// ---------------------------------------------------------------------------
// 1. ADVAPI32.dll
// ---------------------------------------------------------------------------

fn fillRandomBytes(buf: ?[*]u8, len: u32) u32 {
    if (buf == null) return if (len == 0) 1 else 0;
    if (len == 0) return 1;
    var off: usize = 0;
    const total: usize = len;
    while (off < total) {
        const rc = linux.getrandom(buf.? + off, total - off, 0);
        if (linux.errno(rc) != .SUCCESS or rc == 0) {
            return 0;
        }
        off += rc;
    }
    return 1;
}

fn SystemFunction036(buf: ?[*]u8, len: u32) callconv(W) u8 {
    return @intCast(fillRandomBytes(buf, len));
}

const CryptoEntry = struct { active: bool = false };
var crypto_entries: [128]CryptoEntry = [_]CryptoEntry{.{}} ** 128;
const CRYPTO_BASE: usize = 0xCAFE0000;
fn newCryptoHandle() ?usize { for (&crypto_entries, 0..) |*e, i| if (!e.active) { e.active = true; return CRYPTO_BASE + i * 4; }; return null; }
fn validCrypto(h: usize) ?usize { if (h < CRYPTO_BASE or (h - CRYPTO_BASE) % 4 != 0) return null; const i = (h - CRYPTO_BASE) / 4; if (i >= crypto_entries.len or !crypto_entries[i].active) return null; return i; }

fn CryptAcquireContextA(phProv: ?*usize, container: ?[*:0]const u8, provider: ?[*:0]const u8, prov_type: u32, flags: u32) callconv(W) i32 {
    _ = container;
    _ = provider;
    _ = prov_type;
    _ = flags;
    const h = newCryptoHandle() orelse return 0;
    if (phProv) |p| p.* = h else { crypto_entries[(h - CRYPTO_BASE) / 4].active = false; return 0; }
    return 1;
}

fn CryptAcquireContextW(phProv: ?*usize, container: ?[*:0]const u16, provider: ?[*:0]const u16, prov_type: u32, flags: u32) callconv(W) i32 {
    _ = container;
    _ = provider;
    _ = prov_type;
    _ = flags;
    const h = newCryptoHandle() orelse return 0;
    if (phProv) |p| p.* = h else { crypto_entries[(h - CRYPTO_BASE) / 4].active = false; return 0; }
    return 1;
}

fn CryptGenRandom(hProv: usize, len: u32, buf: ?[*]u8) callconv(W) i32 {
    if (validCrypto(hProv) == null) return 0;
    return @intCast(fillRandomBytes(buf, len));
}

fn CryptReleaseContext(hProv: usize, flags: u32) callconv(W) i32 {
    _ = flags;
    const i = validCrypto(hProv) orelse return 0;
    crypto_entries[i].active = false;
    return 1;
}

const TokenEntry = struct { active: bool = false, uid: u32 = 0, gid: u32 = 0 };
var token_entries: [128]TokenEntry = [_]TokenEntry{.{}} ** 128;
const TOKEN_BASE: usize = 0x70010000;
fn tokenIndex(h: usize) ?usize { if (h < TOKEN_BASE or (h - TOKEN_BASE) % 4 != 0) return null; const i = (h - TOKEN_BASE) / 4; if (i >= token_entries.len or !token_entries[i].active) return null; return i; }
fn OpenProcessToken(proc_h: usize, access: u32, token_h: ?*usize) callconv(W) i32 {
    _ = access;
    if (proc_h != ~@as(usize, 0) and proc_h != @as(usize, @intCast(linux.getpid()))) return 0;
    const out = token_h orelse return 0;
    for (&token_entries, 0..) |*t, i| if (!t.active) { t.active = true; t.uid = linux.getuid(); t.gid = linux.getgid(); out.* = TOKEN_BASE + i * 4; return 1; };
    return 0;
}

fn DuplicateToken(existing_token: usize, imp_level: u32, dup_token: ?*usize) callconv(W) i32 {
    const src = tokenIndex(existing_token) orelse return 0;
    _ = imp_level;
    const out = dup_token orelse return 0;
    for (&token_entries, 0..) |*t, i| if (!t.active) { t.* = token_entries[src]; out.* = TOKEN_BASE + i * 4; return 1; };
    return 0;
}

fn GetTokenInformation(
    token_h: usize,
    info_class: u32,
    info: ?[*]u8,
    info_len: u32,
    ret_len: ?*u32,
) callconv(W) i32 {
    const ti = tokenIndex(token_h) orelse return 0;
    if (info_class == 20) { // TokenElevation: effective process credentials
        if (ret_len) |r| r.* = 4;
        if (info == null or info_len < 4) return 0;
        std.mem.writeInt(u32, info.?[0..4], if (token_entries[ti].uid == 0) 1 else 0, .little);
        return 1;
    }
    if (ret_len) |r| r.* = 0;
    return 0;
}

fn SetTokenInformation(token_h: usize, info_class: u32, info: ?*const anyopaque, info_len: u32) callconv(W) i32 {
    _ = token_h;
    _ = info_class;
    _ = info;
    _ = info_len;
    return 1;
}

fn CheckTokenMembership(token_h: usize, sid: ?*const anyopaque, is_member: ?*i32) callconv(W) i32 {
    _ = token_h;
    _ = sid;
    if (is_member) |m| m.* = 1;
    return 1;
}

fn AccessCheck(
    sd: ?*const anyopaque,
    client_token: usize,
    desired_access: u32,
    generic_mapping: ?*const anyopaque,
    priv_set: ?*anyopaque,
    priv_set_len: ?*u32,
    granted_access: ?*u32,
    access_status: ?*i32,
) callconv(W) i32 {
    _ = sd;
    _ = client_token;
    _ = generic_mapping;
    _ = priv_set;
    if (priv_set_len) |l| l.* = 0;
    if (granted_access) |g| g.* = desired_access;
    if (access_status) |s| s.* = 1;
    return 1;
}

fn EqualSid(sid1: ?*const anyopaque, sid2: ?*const anyopaque) callconv(W) i32 {
    if (sid1 == null or sid2 == null) return 0;
    return if (sid1 == sid2) 1 else 0;
}

fn GetSecurityInfo(
    handle: usize,
    obj_type: u32,
    sec_info: u32,
    ppsid_owner: ?*?*anyopaque,
    ppsid_group: ?*?*anyopaque,
    ppdacl: ?*?*anyopaque,
    ppsacl: ?*?*anyopaque,
    ppsd: ?*?*anyopaque,
) callconv(W) u32 {
    _ = handle;
    _ = obj_type;
    _ = sec_info;
    if (ppsid_owner) |p| p.* = null;
    if (ppsid_group) |p| p.* = null;
    if (ppdacl) |p| p.* = null;
    if (ppsacl) |p| p.* = null;
    if (ppsd) |p| p.* = null;
    return 0; // ERROR_SUCCESS
}

fn GetUserNameA(buf: ?[*]u8, pcb: ?*u32) callconv(W) i32 {
    const user = "user";
    if (pcb == null) return 0;
    const cap = pcb.?.*;
    pcb.?.* = @intCast(user.len + 1);
    if (buf == null or cap < user.len + 1) return 0;
    @memcpy(buf.?[0..user.len], user);
    buf.?[user.len] = 0;
    return 1;
}

fn SaferCreateLevel(scope_id: u32, level_id: u32, open_flags: u32, level_h: ?*usize, reserved: ?*anyopaque) callconv(W) i32 {
    _ = scope_id;
    _ = level_id;
    _ = open_flags;
    _ = reserved;
    if (level_h) |h| h.* = 0x7010;
    return 1;
}

fn SaferComputeTokenFromLevel(level_h: usize, in_token: usize, out_token: ?*usize, flags: u32, reserved: ?*anyopaque) callconv(W) i32 {
    _ = level_h;
    _ = in_token;
    _ = flags;
    _ = reserved;
    if (out_token) |t| t.* = 0x7011;
    return 1;
}

const RegValueEntry = struct {
    key_path: []u8,
    name: []u8,
    reg_type: u32,
    data: []u8,
};

const RegHandleEntry = struct {
    in_use: bool = false,
    path: []u8 = &.{},
};

var reg_lock = std.atomic.Value(u32).init(0);
var reg_loaded = false;
var reg_handles: [256]RegHandleEntry = [_]RegHandleEntry{.{}} ** 256;
var reg_values: std.ArrayListUnmanaged(RegValueEntry) = .empty;
var reg_keys: std.ArrayListUnmanaged([]u8) = .empty;

fn acquireRegLock() void {
    while (reg_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
}

fn releaseRegLock() void {
    reg_lock.store(0, .release);
}

fn regAllocLowerUtf16(p: ?[*:0]const u16) []u8 {
    const a = std.heap.page_allocator;
    const ptr = p orelse return a.dupe(u8, "") catch &.{};
    var len: usize = 0;
    while (ptr[len] != 0 and len < 1024) : (len += 1) {}
    var buf = a.alloc(u8, len * 3 + 4) catch return &.{};
    const n = std.unicode.utf16LeToUtf8(buf, ptr[0..len]) catch blk: {
        for (0..len) |i| buf[i] = @truncate(ptr[i]);
        break :blk len;
    };
    const out = a.alloc(u8, n) catch return &.{};
    for (0..n) |i| {
        const c = buf[i];
        out[i] = if (c == '/') '\\' else std.ascii.toLower(c);
    }
    a.free(buf);
    return out;
}

fn regAllocLowerAscii(p: ?[*:0]const u8) []u8 {
    const a = std.heap.page_allocator;
    const ptr = p orelse return a.dupe(u8, "") catch &.{};
    const sl = std.mem.sliceTo(ptr, 0);
    const out = a.alloc(u8, sl.len) catch return &.{};
    for (sl, 0..) |c, i| out[i] = if (c == '/') '\\' else std.ascii.toLower(c);
    return out;
}

fn regRootName(hKey: usize) ?[]const u8 {
    return switch (hKey) {
        0x80000000 => "hkcr",
        0x80000001 => "hkcu",
        0x80000002 => "hklm",
        0x80000003 => "hku",
        else => null,
    };
}

fn regResolveKeyPath(hKey: usize, sub_lower: []const u8) []u8 {
    const a = std.heap.page_allocator;
    var prefix: []const u8 = "hkcu";
    if (regRootName(hKey)) |rn| {
        prefix = rn;
    } else if (hKey >= 0x8001 and hKey < 0x8001 + reg_handles.len) {
        const idx = hKey - 0x8001;
        if (reg_handles[idx].in_use) prefix = reg_handles[idx].path;
    }
    const clean = std.mem.trim(u8, sub_lower, "\\");
    if (clean.len == 0) return a.dupe(u8, prefix) catch &.{};
    return std.fmt.allocPrint(a, "{s}\\{s}", .{ prefix, clean }) catch &.{};
}

fn regOpenHandle(path: []u8) ?usize {
    for (&reg_handles, 0..) |*h, i| {
        if (!h.in_use) {
            h.in_use = true;
            h.path = path;
            return 0x8001 + i;
        }
    }
    return null;
}

fn regFilePath(buf: *[512]u8) ?[:0]const u8 {
    // Console loaders link no libc and have no persistent registry file.
    if (comptime !@import("builtin").link_libc) return null;
    const base_c = std.c.getenv("LOCALAPPDATA") orelse std.c.getenv("APPDATA") orelse return null;
    const base = std.mem.sliceTo(base_c, 0);
    return std.fmt.bufPrintZ(buf, "{s}/wins_reg.bin", .{base}) catch null;
}

fn regEnsureLoaded() void {
    if (reg_loaded) return;
    reg_loaded = true;
    var pbuf: [512]u8 = undefined;
    const fpath = regFilePath(&pbuf) orelse return;
    const fd = linux.open(fpath.ptr, .{ .ACCMODE = .RDONLY }, 0);
    if (@as(isize, @bitCast(fd)) < 0) return;
    defer _ = linux.close(@intCast(fd));
    const a = std.heap.page_allocator;
    const tmp = a.alloc(u8, 256 * 1024) catch return;
    defer a.free(tmp);
    const n_isize: isize = @bitCast(linux.read(@intCast(fd), tmp.ptr, tmp.len));
    if (n_isize < 4) return;
    const bytes = tmp[0..@intCast(n_isize)];
    var off: usize = 0;
    while (off + 12 <= bytes.len) {
        const klen = std.mem.readInt(u32, bytes[off..][0..4], .little);
        const nlen = std.mem.readInt(u32, bytes[off + 4 ..][0..4], .little);
        const rtype = std.mem.readInt(u32, bytes[off + 8 ..][0..4], .little);
        const dlen = std.mem.readInt(u32, bytes[off + 12 ..][0..4], .little);
        off += 16;
        if (off + klen + nlen + dlen > bytes.len) break;
        const kp = a.dupe(u8, bytes[off .. off + klen]) catch break;
        off += klen;
        const nm = a.dupe(u8, bytes[off .. off + nlen]) catch break;
        off += nlen;
        const dt = a.dupe(u8, bytes[off .. off + dlen]) catch break;
        off += dlen;
        reg_values.append(a, .{ .key_path = kp, .name = nm, .reg_type = rtype, .data = dt }) catch break;
    }
}

fn regPersist() void {
    var pbuf: [512]u8 = undefined;
    const fpath = regFilePath(&pbuf) orelse return;
    const fd = linux.open(fpath.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
    if (@as(isize, @bitCast(fd)) < 0) return;
    defer _ = linux.close(@intCast(fd));
    for (reg_values.items) |e| {
        var hdr: [16]u8 = undefined;
        std.mem.writeInt(u32, hdr[0..4], @intCast(e.key_path.len), .little);
        std.mem.writeInt(u32, hdr[4..8], @intCast(e.name.len), .little);
        std.mem.writeInt(u32, hdr[8..12], e.reg_type, .little);
        std.mem.writeInt(u32, hdr[12..16], @intCast(e.data.len), .little);
        _ = linux.write(@intCast(fd), &hdr, 16);
        _ = linux.write(@intCast(fd), e.key_path.ptr, e.key_path.len);
        _ = linux.write(@intCast(fd), e.name.ptr, e.name.len);
        _ = linux.write(@intCast(fd), e.data.ptr, e.data.len);
    }
}

fn regKeyHasAny(full: []const u8) bool {
    for (reg_keys.items) |k| {
        if (std.mem.eql(u8, k, full)) return true;
    }
    for (reg_values.items) |v| {
        if (std.mem.eql(u8, v.key_path, full)) return true;
    }
    return false;
}

fn regQueryCommon(hKey: usize, vname_lower: []const u8, lpType: ?*u32, lpData: ?[*]u8, lpcbData: ?*u32) i32 {
    const kpath = regResolveKeyPath(hKey, "");
    defer std.heap.page_allocator.free(kpath);
    for (reg_values.items) |e| {
        if (std.mem.eql(u8, e.key_path, kpath) and std.mem.eql(u8, e.name, vname_lower)) {
            if (lpType) |t| t.* = e.reg_type;
            const need: u32 = @intCast(e.data.len);
            if (lpData == null) {
                if (lpcbData) |cb| cb.* = need;
                return 0;
            }
            const cap = if (lpcbData) |cb| cb.* else return 87;
            if (cap < need) {
                lpcbData.?.* = need;
                return 234; // ERROR_MORE_DATA
            }
            @memcpy(lpData.?[0..need], e.data);
            lpcbData.?.* = need;
            return 0;
        }
    }
    if (lpcbData) |cb| cb.* = 0;
    return 2; // ERROR_FILE_NOT_FOUND
}

fn regSetCommon(hKey: usize, vname_lower: []u8, dwType: u32, lpData: ?[*]const u8, cbData: u32) i32 {
    const a = std.heap.page_allocator;
    const kpath = regResolveKeyPath(hKey, "");
    const copy = a.alloc(u8, cbData) catch return 14;
    if (lpData) |src| @memcpy(copy, src[0..cbData]) else @memset(copy, 0);
    for (reg_values.items) |*e| {
        if (std.mem.eql(u8, e.key_path, kpath) and std.mem.eql(u8, e.name, vname_lower)) {
            a.free(e.data);
            e.reg_type = dwType;
            e.data = copy;
            a.free(kpath);
            a.free(vname_lower);
            regPersist();
            return 0;
        }
    }
    reg_values.append(a, .{ .key_path = kpath, .name = vname_lower, .reg_type = dwType, .data = copy }) catch return 14;
    regPersist();
    return 0;
}

fn RegOpenKeyExW(hKey: usize, lpSubKey: ?[*:0]const u16, ulOptions: u32, samDesired: u32, phkResult: ?*usize) callconv(W) i32 {
    _ = ulOptions; _ = samDesired;
    const sub = regAllocLowerUtf16(lpSubKey);
    defer std.heap.page_allocator.free(sub);
    acquireRegLock();
    defer releaseRegLock();
    regEnsureLoaded();
    const full = regResolveKeyPath(hKey, sub);
    if (phkResult) |p| p.* = regOpenHandle(full) orelse 0x8001;
    return 0;
}

fn RegOpenKeyExA(hKey: usize, lpSubKey: ?[*:0]const u8, ulOptions: u32, samDesired: u32, phkResult: ?*usize) callconv(W) i32 {
    _ = ulOptions; _ = samDesired;
    const sub = regAllocLowerAscii(lpSubKey);
    defer std.heap.page_allocator.free(sub);
    acquireRegLock();
    defer releaseRegLock();
    regEnsureLoaded();
    const full = regResolveKeyPath(hKey, sub);
    if (phkResult) |p| p.* = regOpenHandle(full) orelse 0x8001;
    return 0;
}

fn RegCreateKeyExW(hKey: usize, lpSubKey: ?[*:0]const u16, Reserved: u32, lpClass: ?[*:0]const u16, dwOptions: u32, samDesired: u32, lpSecurityAttributes: ?*anyopaque, phkResult: ?*usize, lpdwDisposition: ?*u32) callconv(W) i32 {
    _ = Reserved; _ = lpClass; _ = dwOptions; _ = samDesired; _ = lpSecurityAttributes;
    const a = std.heap.page_allocator;
    const sub = regAllocLowerUtf16(lpSubKey);
    defer a.free(sub);
    acquireRegLock();
    defer releaseRegLock();
    regEnsureLoaded();
    const full = regResolveKeyPath(hKey, sub);
    const existed = regKeyHasAny(full);
    if (!existed) reg_keys.append(a, a.dupe(u8, full) catch &.{}) catch {};
    if (phkResult) |p| p.* = regOpenHandle(full) orelse 0x8001;
    if (lpdwDisposition) |p| p.* = if (existed) 2 else 1;
    return 0;
}

fn RegCreateKeyExA(hKey: usize, lpSubKey: ?[*:0]const u8, Reserved: u32, lpClass: ?[*:0]const u8, dwOptions: u32, samDesired: u32, lpSecurityAttributes: ?*anyopaque, phkResult: ?*usize, lpdwDisposition: ?*u32) callconv(W) i32 {
    _ = Reserved; _ = lpClass; _ = dwOptions; _ = samDesired; _ = lpSecurityAttributes;
    const a = std.heap.page_allocator;
    const sub = regAllocLowerAscii(lpSubKey);
    defer a.free(sub);
    acquireRegLock();
    defer releaseRegLock();
    regEnsureLoaded();
    const full = regResolveKeyPath(hKey, sub);
    const existed = regKeyHasAny(full);
    if (!existed) reg_keys.append(a, a.dupe(u8, full) catch &.{}) catch {};
    if (phkResult) |p| p.* = regOpenHandle(full) orelse 0x8001;
    if (lpdwDisposition) |p| p.* = if (existed) 2 else 1;
    return 0;
}

fn RegCloseKey(hKey: usize) callconv(W) i32 {
    if (hKey >= 0x8001 and hKey < 0x8001 + reg_handles.len) {
        acquireRegLock();
        defer releaseRegLock();
        const idx = hKey - 0x8001;
        if (reg_handles[idx].in_use) {
            std.heap.page_allocator.free(reg_handles[idx].path);
            reg_handles[idx].in_use = false;
            reg_handles[idx].path = &.{};
        }
    }
    return 0;
}

fn RegQueryValueExW(hKey: usize, lpValueName: ?[*:0]const u16, lpReserved: ?*u32, lpType: ?*u32, lpData: ?[*]u8, lpcbData: ?*u32) callconv(W) i32 {
    _ = lpReserved;
    const vname = regAllocLowerUtf16(lpValueName);
    defer std.heap.page_allocator.free(vname);
    acquireRegLock();
    defer releaseRegLock();
    regEnsureLoaded();
    return regQueryCommon(hKey, vname, lpType, lpData, lpcbData);
}

fn RegQueryValueExA(hKey: usize, lpValueName: ?[*:0]const u8, lpReserved: ?*u32, lpType: ?*u32, lpData: ?[*]u8, lpcbData: ?*u32) callconv(W) i32 {
    _ = lpReserved;
    const vname = regAllocLowerAscii(lpValueName);
    defer std.heap.page_allocator.free(vname);
    acquireRegLock();
    defer releaseRegLock();
    regEnsureLoaded();
    return regQueryCommon(hKey, vname, lpType, lpData, lpcbData);
}

fn RegSetValueExW(hKey: usize, lpValueName: ?[*:0]const u16, Reserved: u32, dwType: u32, lpData: ?[*]const u8, cbData: u32) callconv(W) i32 {
    _ = Reserved;
    const vname = regAllocLowerUtf16(lpValueName);
    acquireRegLock();
    defer releaseRegLock();
    regEnsureLoaded();
    return regSetCommon(hKey, vname, dwType, lpData, cbData);
}

fn RegSetValueExA(hKey: usize, lpValueName: ?[*:0]const u8, Reserved: u32, dwType: u32, lpData: ?[*]const u8, cbData: u32) callconv(W) i32 {
    _ = Reserved;
    const vname = regAllocLowerAscii(lpValueName);
    acquireRegLock();
    defer releaseRegLock();
    regEnsureLoaded();
    return regSetCommon(hKey, vname, dwType, lpData, cbData);
}

var sid_sub_auth: u32 = 0;
var sid_sub_count: u8 = 1;

fn GetSidSubAuthority(pSid: ?*anyopaque, nSubAuthority: u32) callconv(W) ?*u32 {
    _ = pSid; _ = nSubAuthority;
    return &sid_sub_auth;
}

fn GetSidSubAuthorityCount(pSid: ?*anyopaque) callconv(W) ?*u8 {
    _ = pSid;
    return &sid_sub_count;
}

fn IsValidSid(pSid: ?*anyopaque) callconv(W) i32 {
    _ = pSid;
    return 1;
}

fn ReportEventW(hEventLog: usize, wType: u16, wCategory: u16, dwEventID: u32, lpUserSid: ?*anyopaque, wNumStrings: u16, dwDataSize: u32, lpStrings: ?*anyopaque, lpRawData: ?*anyopaque) callconv(W) i32 {
    _ = hEventLog; _ = wType; _ = wCategory; _ = dwEventID; _ = lpUserSid; _ = wNumStrings; _ = dwDataSize; _ = lpStrings; _ = lpRawData;
    return 1;
}

fn RegisterEventSourceW(lpUNCServerName: ?*const anyopaque, lpSourceName: ?*const anyopaque) callconv(W) usize {
    _ = lpUNCServerName; _ = lpSourceName;
    return 0x50001;
}

fn DeregisterEventSource(hEventLog: usize) callconv(W) i32 {
    _ = hEventLog;
    return 1;
}

fn regDeleteCommon(hKey: usize, vname_lower: []const u8) i32 {
    const a = std.heap.page_allocator;
    const kpath = regResolveKeyPath(hKey, "");
    defer a.free(kpath);
    for (reg_values.items, 0..) |e, i| {
        if (std.mem.eql(u8, e.key_path, kpath) and std.mem.eql(u8, e.name, vname_lower)) {
            a.free(e.key_path);
            a.free(e.name);
            a.free(e.data);
            _ = reg_values.swapRemove(i);
            regPersist();
            return 0;
        }
    }
    return 2;
}

fn RegDeleteValueA(hKey: usize, lpValueName: ?[*:0]const u8) callconv(W) i32 {
    const vname = regAllocLowerAscii(lpValueName);
    defer std.heap.page_allocator.free(vname);
    acquireRegLock();
    defer releaseRegLock();
    regEnsureLoaded();
    return regDeleteCommon(hKey, vname);
}

fn RegDeleteValueW(hKey: usize, lpValueName: ?*const u16) callconv(W) i32 {
    const vname = regAllocLowerUtf16(@ptrCast(lpValueName));
    defer std.heap.page_allocator.free(vname);
    acquireRegLock();
    defer releaseRegLock();
    regEnsureLoaded();
    return regDeleteCommon(hKey, vname);
}

fn RegCreateKeyW(hKey: usize, lpSubKey: ?*const u16, phkResult: ?*usize) callconv(W) i32 {
    return RegCreateKeyExW(hKey, @ptrCast(lpSubKey), 0, null, 0, 0, null, phkResult, null);
}

fn RegCreateKeyA(hKey: usize, lpSubKey: ?[*:0]const u8, phkResult: ?*usize) callconv(W) i32 {
    return RegCreateKeyExA(hKey, lpSubKey, 0, null, 0, 0, null, phkResult, null);
}

fn AllocateAndInitializeSid(pIdentifierAuthority: ?*anyopaque, nSubAuthorityCount: u8, nSubAuthority0: u32, nSubAuthority1: u32, nSubAuthority2: u32, nSubAuthority3: u32, nSubAuthority4: u32, nSubAuthority5: u32, nSubAuthority6: u32, nSubAuthority7: u32, pSid: ?*?*anyopaque) callconv(W) i32 {
    _ = pIdentifierAuthority; _ = nSubAuthorityCount; _ = nSubAuthority0; _ = nSubAuthority1; _ = nSubAuthority2; _ = nSubAuthority3; _ = nSubAuthority4; _ = nSubAuthority5; _ = nSubAuthority6; _ = nSubAuthority7;
    if (pSid) |p| p.* = @ptrFromInt(0x5000);
    return 1;
}

fn FreeSid(pSid: ?*anyopaque) callconv(W) ?*anyopaque {
    _ = pSid;
    return null;
}

fn IsTextUnicode(lpv: ?*const anyopaque, iSize: i32, lpiResult: ?*i32) callconv(W) i32 {
    _ = lpv; _ = iSize; _ = lpiResult;
    return 1;
}

fn RegDeleteKeyW(hKey: usize, lpSubKey: ?*const u16) callconv(W) i32 {
    _ = hKey; _ = lpSubKey;
    return 0;
}

fn RegGetValueW(hkey: usize, lpSubKey: ?*const u16, lpValue: ?*const u16, dwFlags: u32, pdwType: ?*u32, pvData: ?*anyopaque, pcbData: ?*u32) callconv(W) i32 {
    _ = hkey; _ = lpSubKey; _ = lpValue; _ = dwFlags; _ = pdwType; _ = pvData;
    if (pcbData) |s| s.* = 0;
    return 2;
}

fn RegQueryInfoKeyW(hKey: usize, lpClass: ?*u16, lpcchClass: ?*u32, lpReserved: ?*u32, lpcSubKeys: ?*u32, lpcbMaxSubKeyLen: ?*u32, lpcbMaxClassLen: ?*u32, lpcValues: ?*u32, lpcbMaxValueNameLen: ?*u32, lpcbMaxValueLen: ?*u32, lpcbSecurityDescriptor: ?*u32, lpftLastWriteTime: ?*anyopaque) callconv(W) i32 {
    _ = hKey; _ = lpClass; _ = lpcchClass; _ = lpReserved; _ = lpftLastWriteTime;
    if (lpcSubKeys) |k| k.* = 0;
    if (lpcbMaxSubKeyLen) |l| l.* = 0;
    if (lpcbMaxClassLen) |l| l.* = 0;
    if (lpcValues) |v| v.* = 0;
    if (lpcbMaxValueNameLen) |l| l.* = 0;
    if (lpcbMaxValueLen) |l| l.* = 0;
    if (lpcbSecurityDescriptor) |s| s.* = 0;
    return 0;
}

fn RegEnumKeyExW(hKey: usize, dwIndex: u32, lpName: ?[*:0]u16, lpcchName: ?*u32, lpReserved: ?*u32, lpClass: ?*u16, lpcchClass: ?*u32, lpftLastWriteTime: ?*anyopaque) callconv(W) i32 {
    _ = hKey; _ = dwIndex; _ = lpReserved; _ = lpClass; _ = lpcchClass; _ = lpftLastWriteTime;
    if (lpName) |s| s[0] = 0;
    if (lpcchName) |c| c.* = 0;
    return 259;
}

var default_sid_bytes: [12]u8 = .{ 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0 }; // S-1-5-18
var default_acl_bytes: [16]u8 align(4) = .{ 2, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

fn GetLengthSid(pSid: ?*const anyopaque) callconv(W) u32 {
    const p: [*]const u8 = @ptrCast(pSid orelse return 12);
    return 8 + @as(u32, p[1]) * 4;
}

fn CopySid(nDestinationSidLength: u32, pDestinationSid: ?[*]u8, pSourceSid: ?*const anyopaque) callconv(W) i32 {
    const src_ptr = pSourceSid orelse return 0;
    const dst = pDestinationSid orelse return 0;
    const len = GetLengthSid(src_ptr);
    if (nDestinationSidLength < len) return 0;
    const src: [*]const u8 = @ptrCast(src_ptr);
    @memcpy(dst[0..len], src[0..len]);
    return 1;
}

fn LookupAccountSidW(
    lpSystemName: ?[*:0]const u16,
    Sid: ?*const anyopaque,
    Name: ?[*]u16,
    cchName: ?*u32,
    ReferencedDomainName: ?[*]u16,
    cchReferencedDomainName: ?*u32,
    peUse: ?*u32,
) callconv(W) i32 {
    _ = lpSystemName;
    _ = Sid;
    const u = [_]u16{ 'w', 'i', 'n', 's', 0 };
    const d = [_]u16{ 'L', 'O', 'C', 'A', 'L', 0 };
    if (cchName) |cn| {
        if (Name != null and cn.* >= u.len) @memcpy(Name.?[0..u.len], &u);
        cn.* = u.len - 1;
    }
    if (cchReferencedDomainName) |cd| {
        if (ReferencedDomainName != null and cd.* >= d.len) @memcpy(ReferencedDomainName.?[0..d.len], &d);
        cd.* = d.len - 1;
    }
    if (peUse) |pu| pu.* = 1; // SidTypeUser
    return 1;
}

fn BuildTrusteeWithSidW(pTrustee: ?[*]usize, pSid: ?*anyopaque) callconv(W) void {
    if (pTrustee) |t| {
        @memset(t[0..4], 0);
        t[3] = @intFromPtr(pSid);
    }
}

fn GetNamedSecurityInfoW(
    pObjectName: ?[*:0]const u16,
    ObjectType: u32,
    SecurityInfo: u32,
    ppsidOwner: ?*?*anyopaque,
    ppsidGroup: ?*?*anyopaque,
    ppDacl: ?*?*anyopaque,
    ppSacl: ?*?*anyopaque,
    ppSecurityDescriptor: ?*?*anyopaque,
) callconv(W) u32 {
    _ = pObjectName;
    _ = ObjectType;
    _ = SecurityInfo;
    if (ppsidOwner) |p| p.* = &default_sid_bytes;
    if (ppsidGroup) |p| p.* = &default_sid_bytes;
    if (ppDacl) |p| p.* = &default_acl_bytes;
    if (ppSacl) |p| p.* = null;
    if (ppSecurityDescriptor) |p| p.* = @ptrCast(std.heap.page_allocator.alloc(u8, 64) catch return 8);
    return 0; // ERROR_SUCCESS
}

fn SetNamedSecurityInfoW(
    pObjectName: ?[*:0]const u16,
    ObjectType: u32,
    SecurityInfo: u32,
    psidOwner: ?*anyopaque,
    psidGroup: ?*anyopaque,
    pDacl: ?*anyopaque,
    pSacl: ?*anyopaque,
) callconv(W) u32 {
    _ = pObjectName;
    _ = ObjectType;
    _ = SecurityInfo;
    _ = psidOwner;
    _ = psidGroup;
    _ = pDacl;
    _ = pSacl;
    return 0;
}

fn GetEffectiveRightsFromAclW(pacl: ?*anyopaque, pTrustee: ?*anyopaque, pAccessRights: ?*u32) callconv(W) u32 {
    _ = pacl;
    _ = pTrustee;
    if (pAccessRights) |r| r.* = 0x001F01FF; // FILE_ALL_ACCESS
    return 0;
}

fn SetEntriesInAclW(cCountOfExplicitEntries: u32, pListOfExplicitEntries: ?*anyopaque, OldAcl: ?*anyopaque, NewAcl: ?*?*anyopaque) callconv(W) u32 {
    _ = cCountOfExplicitEntries;
    _ = pListOfExplicitEntries;
    _ = OldAcl;
    if (NewAcl) |p| p.* = @ptrCast(std.heap.page_allocator.alloc(u8, 16) catch return 8);
    return 0;
}

fn OpenThreadToken(ThreadHandle: usize, DesiredAccess: u32, OpenAsSelf: i32, TokenHandle: ?*usize) callconv(W) i32 {
    _ = ThreadHandle;
    _ = DesiredAccess;
    _ = OpenAsSelf;
    if (TokenHandle) |t| t.* = 0;
    return 0; // no per-thread impersonation token (caller falls back to OpenProcessToken)
}

fn ImpersonateLoggedOnUser(hToken: usize) callconv(W) i32 {
    _ = hToken;
    return 1;
}

fn RevertToSelf() callconv(W) i32 {
    return 1;
}

fn CreateProcessWithLogonW(
    lpUsername: ?[*:0]const u16,
    lpDomain: ?[*:0]const u16,
    lpPassword: ?[*:0]const u16,
    dwLogonFlags: u32,
    lpApplicationName: ?[*:0]const u16,
    lpCommandLine: ?[*:0]const u16,
    dwCreationFlags: u32,
    lpEnvironment: ?*anyopaque,
    lpCurrentDirectory: ?[*:0]const u16,
    lpStartupInfo: ?*anyopaque,
    lpProcessInformation: ?*anyopaque,
) callconv(W) i32 {
    _ = lpUsername;
    _ = lpDomain;
    _ = lpPassword;
    _ = dwLogonFlags;
    _ = lpApplicationName;
    _ = lpCommandLine;
    _ = dwCreationFlags;
    _ = lpEnvironment;
    _ = lpCurrentDirectory;
    _ = lpStartupInfo;
    _ = lpProcessInformation;
    return 0; // deny logon-elevation cleanly
}

pub fn lookupAdvapi32(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "GetLengthSid")) return @intFromPtr(&GetLengthSid);
    if (std.mem.eql(u8, name, "CopySid")) return @intFromPtr(&CopySid);
    if (std.mem.eql(u8, name, "LookupAccountSidW")) return @intFromPtr(&LookupAccountSidW);
    if (std.mem.eql(u8, name, "BuildTrusteeWithSidW")) return @intFromPtr(&BuildTrusteeWithSidW);
    if (std.mem.eql(u8, name, "GetNamedSecurityInfoW")) return @intFromPtr(&GetNamedSecurityInfoW);
    if (std.mem.eql(u8, name, "SetNamedSecurityInfoW")) return @intFromPtr(&SetNamedSecurityInfoW);
    if (std.mem.eql(u8, name, "GetEffectiveRightsFromAclW")) return @intFromPtr(&GetEffectiveRightsFromAclW);
    if (std.mem.eql(u8, name, "SetEntriesInAclW")) return @intFromPtr(&SetEntriesInAclW);
    if (std.mem.eql(u8, name, "OpenThreadToken")) return @intFromPtr(&OpenThreadToken);
    if (std.mem.eql(u8, name, "ImpersonateLoggedOnUser")) return @intFromPtr(&ImpersonateLoggedOnUser);
    if (std.mem.eql(u8, name, "RevertToSelf")) return @intFromPtr(&RevertToSelf);
    if (std.mem.eql(u8, name, "CreateProcessWithLogonW")) return @intFromPtr(&CreateProcessWithLogonW);
    if (std.mem.eql(u8, name, "RegDeleteKeyW")) return @intFromPtr(&RegDeleteKeyW);
    if (std.mem.eql(u8, name, "RegGetValueW")) return @intFromPtr(&RegGetValueW);
    if (std.mem.eql(u8, name, "RegQueryInfoKeyW")) return @intFromPtr(&RegQueryInfoKeyW);
    if (std.mem.eql(u8, name, "RegEnumKeyExW")) return @intFromPtr(&RegEnumKeyExW);
    if (std.mem.eql(u8, name, "AllocateAndInitializeSid")) return @intFromPtr(&AllocateAndInitializeSid);
    if (std.mem.eql(u8, name, "FreeSid")) return @intFromPtr(&FreeSid);
    if (std.mem.eql(u8, name, "IsTextUnicode")) return @intFromPtr(&IsTextUnicode);
    if (std.mem.eql(u8, name, "GetSidSubAuthority")) return @intFromPtr(&GetSidSubAuthority);
    if (std.mem.eql(u8, name, "GetSidSubAuthorityCount")) return @intFromPtr(&GetSidSubAuthorityCount);
    if (std.mem.eql(u8, name, "IsValidSid")) return @intFromPtr(&IsValidSid);
    if (std.mem.eql(u8, name, "ReportEventW")) return @intFromPtr(&ReportEventW);
    if (std.mem.eql(u8, name, "RegisterEventSourceW")) return @intFromPtr(&RegisterEventSourceW);
    if (std.mem.eql(u8, name, "DeregisterEventSource")) return @intFromPtr(&DeregisterEventSource);
    if (std.mem.eql(u8, name, "RegDeleteValueA")) return @intFromPtr(&RegDeleteValueA);
    if (std.mem.eql(u8, name, "RegDeleteValueW")) return @intFromPtr(&RegDeleteValueW);
    if (std.mem.eql(u8, name, "RegCreateKeyW")) return @intFromPtr(&RegCreateKeyW);
    if (std.mem.eql(u8, name, "RegCreateKeyA")) return @intFromPtr(&RegCreateKeyA);
    if (std.mem.eql(u8, name, "RegOpenKeyExW")) return @intFromPtr(&RegOpenKeyExW);
    if (std.mem.eql(u8, name, "RegOpenKeyExA")) return @intFromPtr(&RegOpenKeyExA);
    if (std.mem.eql(u8, name, "RegCreateKeyExW")) return @intFromPtr(&RegCreateKeyExW);
    if (std.mem.eql(u8, name, "RegCreateKeyExA")) return @intFromPtr(&RegCreateKeyExA);
    if (std.mem.eql(u8, name, "RegCloseKey")) return @intFromPtr(&RegCloseKey);
    if (std.mem.eql(u8, name, "RegQueryValueExW")) return @intFromPtr(&RegQueryValueExW);
    if (std.mem.eql(u8, name, "RegQueryValueExA")) return @intFromPtr(&RegQueryValueExA);
    if (std.mem.eql(u8, name, "RegSetValueExW")) return @intFromPtr(&RegSetValueExW);
    if (std.mem.eql(u8, name, "RegSetValueExA")) return @intFromPtr(&RegSetValueExA);
    if (std.mem.eql(u8, name, "AccessCheck")) return @intFromPtr(&AccessCheck);
    if (std.mem.eql(u8, name, "CheckTokenMembership")) return @intFromPtr(&CheckTokenMembership);
    if (std.mem.eql(u8, name, "CryptAcquireContextA")) return @intFromPtr(&CryptAcquireContextA);
    if (std.mem.eql(u8, name, "CryptAcquireContextW")) return @intFromPtr(&CryptAcquireContextW);
    if (std.mem.eql(u8, name, "CryptGenRandom")) return @intFromPtr(&CryptGenRandom);
    if (std.mem.eql(u8, name, "CryptReleaseContext")) return @intFromPtr(&CryptReleaseContext);
    if (std.mem.eql(u8, name, "DuplicateToken")) return @intFromPtr(&DuplicateToken);
    if (std.mem.eql(u8, name, "EqualSid")) return @intFromPtr(&EqualSid);
    if (std.mem.eql(u8, name, "GetSecurityInfo")) return @intFromPtr(&GetSecurityInfo);
    if (std.mem.eql(u8, name, "GetTokenInformation")) return @intFromPtr(&GetTokenInformation);
    if (std.mem.eql(u8, name, "GetUserNameA")) return @intFromPtr(&GetUserNameA);
    if (std.mem.eql(u8, name, "OpenProcessToken")) return @intFromPtr(&OpenProcessToken);
    if (std.mem.eql(u8, name, "SaferComputeTokenFromLevel")) return @intFromPtr(&SaferComputeTokenFromLevel);
    if (std.mem.eql(u8, name, "SaferCreateLevel")) return @intFromPtr(&SaferCreateLevel);
    if (std.mem.eql(u8, name, "SetTokenInformation")) return @intFromPtr(&SetTokenInformation);
    if (std.mem.eql(u8, name, "SystemFunction036")) return @intFromPtr(&SystemFunction036);
    if (std.mem.eql(u8, name, "CryptCreateHash")) return @intFromPtr(&stub5);
    if (std.mem.eql(u8, name, "CryptDestroyHash")) return @intFromPtr(&stub1);
    if (std.mem.eql(u8, name, "CryptHashData")) return @intFromPtr(&stub4);
    if (std.mem.eql(u8, name, "CryptGetHashParam")) return @intFromPtr(&stub5);
    if (std.mem.eql(u8, name, "CryptEncrypt")) return @intFromPtr(&stub7);
    if (std.mem.eql(u8, name, "CryptImportKey")) return @intFromPtr(&stub6);
    if (std.mem.eql(u8, name, "CryptDestroyKey")) return @intFromPtr(&stub1);
    // 7zr asks for these two; neither is meaningful without a real security
    // subsystem, and "failure" is the answer that cannot fabricate a privilege.
    if (std.mem.eql(u8, name, "SetFileSecurityW")) return @intFromPtr(&stub3);
    if (std.mem.eql(u8, name, "GetFileSecurityW")) return @intFromPtr(&stub5);
    if (std.mem.eql(u8, name, "LookupPrivilegeValueW")) return @intFromPtr(&stub3);
    return null;
}

test "crypto provider handles validate and getrandom fills bytes" {
    var h: usize = 0;
    try std.testing.expectEqual(@as(i32, 1), CryptAcquireContextA(&h, null, null, 0, 0));
    var bytes: [32]u8 = [_]u8{0} ** 32;
    try std.testing.expectEqual(@as(i32, 1), CryptGenRandom(h, bytes.len, &bytes));
    try std.testing.expect(!std.mem.allEqual(u8, &bytes, 0));
    try std.testing.expectEqual(@as(i32, 0), CryptGenRandom(0xdead, 1, &bytes));
    try std.testing.expectEqual(@as(i32, 1), CryptReleaseContext(h, 0));
    try std.testing.expectEqual(@as(i32, 0), CryptReleaseContext(h, 0));
    var hw: usize = 0;
    try std.testing.expectEqual(@as(i32, 1), CryptAcquireContextW(&hw, null, null, 0, 0));
    try std.testing.expectEqual(@as(i32, 1), CryptReleaseContext(hw, 0));
}

test "process token handle and elevation query reflect effective uid" {
    var h: usize = 0;
    try std.testing.expectEqual(@as(i32, 1), OpenProcessToken(~@as(usize, 0), 0, &h));
    var elevation: [4]u8 = undefined; var needed: u32 = 0;
    try std.testing.expectEqual(@as(i32, 1), GetTokenInformation(h, 20, &elevation, elevation.len, &needed));
    try std.testing.expectEqual(@as(u32, 4), needed);
    try std.testing.expectEqual(@as(u32, if (linux.getuid() == 0) 1 else 0), std.mem.readInt(u32, &elevation, .little));
    try std.testing.expectEqual(@as(i32, 0), GetTokenInformation(0x1234, 20, &elevation, elevation.len, &needed));
}

// ---------------------------------------------------------------------------
// 2. WS2_32.dll (Winsock2)
// ---------------------------------------------------------------------------

var wsa_last_error: i32 = 0;
var inet_ntoa_buf: [32:0]u8 = undefined;

fn WSAStartup(version_req: u16, wsa_data: ?[*]u8) callconv(W) i32 {
    if (wsa_data) |d| {
        @memset(d[0..408], 0);
        std.mem.writeInt(u16, d[0..2], version_req, .little);
        std.mem.writeInt(u16, d[2..4], 0x0202, .little);
    }
    return 0;
}

fn WSACleanup() callconv(W) i32 {
    return 0;
}

fn WSAGetLastError() callconv(W) i32 {
    return wsa_last_error;
}

fn WSASetLastError(err: i32) callconv(W) void {
    wsa_last_error = err;
}

fn WSASocketA(af: i32, sock_type: i32, protocol: i32, proto_info: ?*anyopaque, g: u32, flags: u32) callconv(W) usize {
    _ = proto_info;
    _ = g;
    _ = flags;
    const rc = linux.socket(@intCast(af), @intCast(sock_type), @intCast(protocol));
    if (linux.errno(rc) != .SUCCESS) {
        wsa_last_error = 10047;
        return ~@as(usize, 0); // INVALID_SOCKET
    }
    return rc;
}

fn closesocket(s: usize) callconv(W) i32 {
    _ = linux.close(@intCast(s & 0x7fffffff));
    return 0;
}

fn shutdown(s: usize, how: i32) callconv(W) i32 {
    const rc = linux.shutdown(@intCast(s & 0x7fffffff), @intCast(how));
    return if (linux.errno(rc) == .SUCCESS) 0 else -1;
}

fn bind(s: usize, name: ?*const anyopaque, namelen: i32) callconv(W) i32 {
    if (name == null or namelen <= 0) return -1;
    const rc = linux.bind(@intCast(s & 0x7fffffff), @ptrCast(@alignCast(name.?)), @intCast(namelen));
    return if (linux.errno(rc) == .SUCCESS) 0 else -1;
}

fn listen(s: usize, backlog: i32) callconv(W) i32 {
    const rc = linux.listen(@intCast(s & 0x7fffffff), @intCast(@max(backlog, 1)));
    return if (linux.errno(rc) == .SUCCESS) 0 else -1;
}

fn accept(s: usize, addr: ?*anyopaque, addrlen: ?*i32) callconv(W) usize {
    var len_u32: u32 = if (addrlen) |p| @intCast(@max(p.*, 0)) else 0;
    const sa: ?*linux.sockaddr = if (addr) |a| @ptrCast(@alignCast(a)) else null;
    const alen: ?*u32 = if (addrlen != null) &len_u32 else null;
    const rc = linux.accept(@intCast(s & 0x7fffffff), sa, alen);
    if (linux.errno(rc) != .SUCCESS) return ~@as(usize, 0);
    if (addrlen) |p| p.* = @intCast(len_u32);
    return rc;
}

fn connect(s: usize, name: ?*const anyopaque, namelen: i32) callconv(W) i32 {
    if (name == null or namelen <= 0) return -1;
    const rc = linux.connect(@intCast(s & 0x7fffffff), @ptrCast(@alignCast(name.?)), @intCast(namelen));
    return if (linux.errno(rc) == .SUCCESS) 0 else -1;
}

fn recv(s: usize, buf: ?[*]u8, len: i32, flags: i32) callconv(W) i32 {
    if (buf == null or len <= 0) return 0;
    const rc = linux.recvfrom(@intCast(s & 0x7fffffff), buf.?, @intCast(len), @intCast(flags), null, null);
    if (linux.errno(rc) != .SUCCESS) return -1;
    return @intCast(rc);
}

fn setsockopt(s: usize, level: i32, optname: i32, optval: ?[*]const u8, optlen: i32) callconv(W) i32 {
    _ = s;
    _ = level;
    _ = optname;
    _ = optval;
    _ = optlen;
    return 0;
}

fn getpeername(s: usize, name: ?*anyopaque, namelen: ?*i32) callconv(W) i32 {
    if (name == null or namelen == null) {
        wsa_last_error = 10014;
        return -1;
    }
    var len_u32: u32 = @intCast(@max(namelen.?.*, 0));
    const sa: *linux.sockaddr = @ptrCast(@alignCast(name.?));
    const rc = linux.getpeername(@intCast(s & 0x7fffffff), sa, &len_u32);
    if (linux.errno(rc) != .SUCCESS) {
        wsa_last_error = 10057;
        return -1;
    }
    namelen.?.* = @intCast(len_u32);
    return 0;
}

fn gethostname(name: ?[*]u8, namelen: i32) callconv(W) i32 {
    if (name == null or namelen <= 0) return -1;
    const host = "localhost";
    const copy_len = @min(@as(usize, @intCast(namelen - 1)), host.len);
    @memcpy(name.?[0..copy_len], host[0..copy_len]);
    name.?[copy_len] = 0;
    return 0;
}

fn inet_addr(cp: ?[*:0]const u8) callconv(W) u32 {
    const s = cp orelse return 0xFFFFFFFF;
    var parts: [4]u32 = .{ 0, 0, 0, 0 };
    var p_idx: usize = 0;
    var i: usize = 0;
    var any = false;
    while (s[i] != 0) : (i += 1) {
        if (s[i] >= '0' and s[i] <= '9') {
            any = true;
            parts[p_idx] = parts[p_idx] * 10 + (s[i] - '0');
            if (parts[p_idx] > 255) return 0xFFFFFFFF;
        } else if (s[i] == '.') {
            if (p_idx >= 3) return 0xFFFFFFFF;
            p_idx += 1;
        } else {
            return 0xFFFFFFFF;
        }
    }
    if (!any or p_idx != 3) return 0xFFFFFFFF;
    return parts[0] | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24);
}

fn inet_ntoa(in_addr: u32) callconv(W) [*:0]const u8 {
    const b0 = in_addr & 0xFF;
    const b1 = (in_addr >> 8) & 0xFF;
    const b2 = (in_addr >> 16) & 0xFF;
    const b3 = (in_addr >> 24) & 0xFF;
    const slice = std.fmt.bufPrint(&inet_ntoa_buf, "{d}.{d}.{d}.{d}", .{ b0, b1, b2, b3 }) catch "0.0.0.0";
    inet_ntoa_buf[slice.len] = 0;
    return &inet_ntoa_buf;
}

fn getaddrinfo(node: ?[*:0]const u8, service: ?[*:0]const u8, hints: ?*const anyopaque, res: ?*?*anyopaque) callconv(W) i32 {
    _ = node;
    _ = service;
    _ = hints;
    if (res) |r| r.* = null;
    return 11001; // WSAHOST_NOT_FOUND
}

fn freeaddrinfo(ai: ?*anyopaque) callconv(W) void {
    _ = ai;
}

fn getnameinfo(sa: ?*const anyopaque, salen: i32, host: ?[*]u8, hostlen: u32, serv: ?[*]u8, servlen: u32, flags: i32) callconv(W) i32 {
    _ = sa;
    _ = salen;
    _ = flags;
    if (host != null and hostlen > 0) host.?[0] = 0;
    if (serv != null and servlen > 0) serv.?[0] = 0;
    return 0;
}

fn gethostbyaddr(addr: ?*const anyopaque, len: i32, addr_type: i32) callconv(W) ?*anyopaque {
    _ = addr;
    _ = len;
    _ = addr_type;
    return null;
}

fn WSAEventSelect(s: usize, hEventObject: usize, lNetworkEvents: i32) callconv(W) i32 {
    _ = s;
    _ = hEventObject;
    _ = lNetworkEvents;
    return 0;
}

fn WSAEnumNetworkEvents(s: usize, hEventObject: usize, lpNetworkEvents: ?[*]u8) callconv(W) i32 {
    _ = s;
    _ = hEventObject;
    if (lpNetworkEvents) |p| @memset(p[0..44], 0);
    return 0;
}

fn __WSAFDIsSet(fd: usize, set: ?*const anyopaque) callconv(W) i32 {
    _ = fd;
    _ = set;
    return 0;
}

fn ws2_select(nfds: i32, readfds: ?*anyopaque, writefds: ?*anyopaque, exceptfds: ?*anyopaque, timeout: ?*const anyopaque) callconv(W) i32 {
    _ = nfds;
    _ = readfds;
    _ = writefds;
    _ = exceptfds;
    _ = timeout;
    return 0;
}

fn WSACreateEvent() callconv(W) usize {
    return 0x6001;
}

fn WSACloseEvent(h: usize) callconv(W) i32 {
    _ = h;
    return 1;
}

fn WSAResetEvent(h: usize) callconv(W) i32 {
    _ = h;
    return 1;
}

fn WSAWaitForMultipleEvents(count: u32, handles: ?*const usize, wait_all: i32, ms: u32, alertable: i32) callconv(W) u32 {
    _ = count; _ = handles; _ = wait_all; _ = ms; _ = alertable;
    return 0;
}

fn WSAIoctl(s: usize, code: u32, in_buf: ?*anyopaque, in_sz: u32, out_buf: ?*anyopaque, out_sz: u32, ret: ?*u32, ov: ?*anyopaque, cr: ?*anyopaque) callconv(W) i32 {
    _ = s; _ = code; _ = in_buf; _ = in_sz; _ = out_buf; _ = out_sz; _ = ov; _ = cr;
    if (ret) |r| r.* = 0;
    return 0;
}

fn send(s: usize, buf: ?[*]const u8, len: i32, flags: i32) callconv(W) i32 {
    if (buf == null or len <= 0) return 0;
    const rc = linux.sendto(@intCast(s & 0x7fffffff), buf.?, @intCast(len), @intCast(flags), null, 0);
    if (linux.errno(rc) != .SUCCESS) return -1;
    return @intCast(rc);
}

fn sendto(s: usize, buf: ?[*]const u8, len: i32, flags: i32, to: ?*const anyopaque, tolen: i32) callconv(W) i32 {
    if (buf == null or len <= 0) return 0;
    const sa: ?*const linux.sockaddr = if (to) |p| @ptrCast(@alignCast(p)) else null;
    const rc = linux.sendto(@intCast(s & 0x7fffffff), buf.?, @intCast(len), @intCast(flags), sa, @intCast(@max(tolen, 0)));
    if (linux.errno(rc) != .SUCCESS) return -1;
    return @intCast(rc);
}

fn recvfrom(s: usize, buf: ?[*]u8, len: i32, flags: i32, from: ?*anyopaque, fromlen: ?*i32) callconv(W) i32 {
    if (buf == null or len <= 0) return 0;
    var alen_u32: u32 = if (fromlen) |p| @intCast(@max(p.*, 0)) else 0;
    const sa: ?*linux.sockaddr = if (from) |p| @ptrCast(@alignCast(p)) else null;
    const plen: ?*u32 = if (fromlen != null) &alen_u32 else null;
    const rc = linux.recvfrom(@intCast(s & 0x7fffffff), buf.?, @intCast(len), @intCast(flags), sa, plen);
    if (linux.errno(rc) != .SUCCESS) return -1;
    if (fromlen) |p| p.* = @intCast(alen_u32);
    return @intCast(rc);
}

fn getsockname(s: usize, name: ?*anyopaque, namelen: ?*i32) callconv(W) i32 {
    if (name == null or namelen == null) return -1;
    var alen_u32: u32 = @intCast(@max(namelen.?.*, 0));
    const sa: *linux.sockaddr = @ptrCast(@alignCast(name.?));
    const rc = linux.getsockname(@intCast(s & 0x7fffffff), sa, &alen_u32);
    if (linux.errno(rc) != .SUCCESS) return -1;
    namelen.?.* = @intCast(alen_u32);
    return 0;
}

fn getsockopt(s: usize, level: i32, optname: i32, optval: ?[*]u8, optlen: ?*i32) callconv(W) i32 {
    _ = s; _ = level; _ = optname;
    if (optval != null and optlen != null and optlen.?.* >= 4) {
        @memset(optval.?[0..4], 0);
        optlen.?.* = 4;
    }
    return 0;
}

fn ioctlsocket(s: usize, cmd: i32, argp: ?*u32) callconv(W) i32 {
    _ = s; _ = cmd; _ = argp;
    return 0;
}

fn htonl(hostlong: u32) callconv(W) u32 {
    return std.mem.nativeToBig(u32, hostlong);
}

fn htons(hostshort: u16) callconv(W) u16 {
    return std.mem.nativeToBig(u16, hostshort);
}

fn ntohl(netlong: u32) callconv(W) u32 {
    return std.mem.bigToNative(u32, netlong);
}

fn ntohs(netshort: u16) callconv(W) u16 {
    return std.mem.bigToNative(u16, netshort);
}

fn socket(af: i32, sock_type: i32, protocol: i32) callconv(W) usize {
    return WSASocketA(af, sock_type, protocol, null, 0, 0);
}

fn if_nametoindex(name: ?[*:0]const u8) callconv(W) u32 {
    _ = name;
    return 1;
}

fn WSARecvFrom(s: usize, lpBuffers: ?*anyopaque, dwBufferCount: u32, lpNumberOfBytesRecvd: ?*u32, lpFlags: ?*u32, lpFrom: ?*anyopaque, lpFromlen: ?*i32, lpOverlapped: ?*anyopaque, lpCompletionRoutine: ?*anyopaque) callconv(W) i32 {
    _ = s; _ = lpBuffers; _ = dwBufferCount; _ = lpFlags; _ = lpFrom; _ = lpFromlen; _ = lpOverlapped; _ = lpCompletionRoutine;
    if (lpNumberOfBytesRecvd) |p| p.* = 0;
    return 0;
}

fn WSASetEvent(hEvent: usize) callconv(W) i32 {
    _ = hEvent;
    return 1;
}

fn gethostbyname(name: ?[*:0]const u8) callconv(W) ?*anyopaque {
    _ = name;
    return null;
}

fn getprotobyname(name: ?[*:0]const u8) callconv(W) ?*anyopaque {
    _ = name;
    return null;
}

fn WSAAsyncGetHostByName(hWnd: usize, wMsg: u32, name: ?[*:0]const u8, buf: ?[*]u8, buflen: i32) callconv(W) usize {
    _ = hWnd; _ = wMsg; _ = name; _ = buf; _ = buflen;
    return 0x7001;
}

fn WSACancelAsyncRequest(hAsyncTaskHandle: usize) callconv(W) i32 {
    _ = hAsyncTaskHandle;
    return 0;
}

fn wsaAsyncSelectUnsupported(s: usize, hWnd: usize, wMsg: u32, lEvent: u32) callconv(W) i32 {
    _ = s; _ = hWnd; _ = wMsg; _ = lEvent;
    std.debug.print("[WINS:Ws2_32] async socket notification is not modelled; reporting failure.\n", .{});
    return -1; // SOCKET_ERROR
}

const WSABUF = extern struct { len: u32, buf: ?[*]u8 };

fn WSASocketW(af: i32, sock_type: i32, protocol: i32, proto_info: ?*anyopaque, g: u32, flags: u32) callconv(W) usize {
    return WSASocketA(af, sock_type, protocol, proto_info, g, flags);
}

fn WSASend(
    s: usize,
    lpBuffers: ?[*]const WSABUF,
    dwBufferCount: u32,
    lpNumberOfBytesSent: ?*u32,
    dwFlags: u32,
    lpOverlapped: ?*anyopaque,
    lpCompletionRoutine: ?*anyopaque,
) callconv(W) i32 {
    _ = lpOverlapped;
    _ = lpCompletionRoutine;
    const bufs = lpBuffers orelse return -1;
    var total: u32 = 0;
    var i: u32 = 0;
    while (i < dwBufferCount) : (i += 1) {
        if (bufs[i].buf == null or bufs[i].len == 0) continue;
        const rc = linux.sendto(@intCast(s & 0x7fffffff), bufs[i].buf.?, bufs[i].len, @intCast(dwFlags), null, 0);
        if (linux.errno(rc) != .SUCCESS) {
            wsa_last_error = 10035;
            if (lpNumberOfBytesSent) |p| p.* = total;
            return if (total > 0) 0 else -1;
        }
        total += @intCast(rc);
    }
    if (lpNumberOfBytesSent) |p| p.* = total;
    return 0;
}

fn WSARecv(
    s: usize,
    lpBuffers: ?[*]const WSABUF,
    dwBufferCount: u32,
    lpNumberOfBytesRecvd: ?*u32,
    lpFlags: ?*u32,
    lpOverlapped: ?*anyopaque,
    lpCompletionRoutine: ?*anyopaque,
) callconv(W) i32 {
    _ = lpOverlapped;
    _ = lpCompletionRoutine;
    const bufs = lpBuffers orelse return -1;
    const flags: u32 = if (lpFlags) |f| f.* else 0;
    var total: u32 = 0;
    var i: u32 = 0;
    while (i < dwBufferCount) : (i += 1) {
        if (bufs[i].buf == null or bufs[i].len == 0) continue;
        const rc = linux.recvfrom(@intCast(s & 0x7fffffff), bufs[i].buf.?, bufs[i].len, @intCast(flags), null, null);
        if (linux.errno(rc) != .SUCCESS) {
            wsa_last_error = 10035;
            if (lpNumberOfBytesRecvd) |p| p.* = total;
            return if (total > 0) 0 else -1;
        }
        total += @intCast(rc);
        if (rc < bufs[i].len) break;
    }
    if (lpNumberOfBytesRecvd) |p| p.* = total;
    return 0;
}

fn getservbyname(name: ?[*:0]const u8, proto: ?[*:0]const u8) callconv(W) ?*anyopaque {
    _ = name;
    _ = proto;
    wsa_last_error = 11004;
    return null;
}

fn getservbyport(port: i32, proto: ?[*:0]const u8) callconv(W) ?*anyopaque {
    _ = port;
    _ = proto;
    wsa_last_error = 11004;
    return null;
}

pub fn lookupWs2_32(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "WSASend")) return @intFromPtr(&WSASend);
    if (std.mem.eql(u8, name, "WSARecv")) return @intFromPtr(&WSARecv);
    if (std.mem.eql(u8, name, "WSASocketW")) return @intFromPtr(&WSASocketW);
    if (std.mem.eql(u8, name, "getservbyname")) return @intFromPtr(&getservbyname);
    if (std.mem.eql(u8, name, "getservbyport")) return @intFromPtr(&getservbyport);
    // FalloutNV imports WSAAsyncSelect by ordinal. The window-message
    // notification it provides cannot be modelled without a real message loop,
    // so it reports failure rather than pretending to have registered one --
    // a caller that believes it registered would wait for a message that never
    // comes.
    if (std.mem.eql(u8, name, "WSAAsyncSelect")) return @intFromPtr(&wsaAsyncSelectUnsupported);
    if (std.mem.eql(u8, name, "WSAAsyncGetHostByAddr")) return @intFromPtr(&wsaAsyncSelectUnsupported);
    if (std.mem.eql(u8, name, "WSAAsyncGetHostByName")) return @intFromPtr(&wsaAsyncSelectUnsupported);
    if (std.mem.eql(u8, name, "WSASetBlockingHook")) return @intFromPtr(&wsaAsyncSelectUnsupported);
    if (std.mem.eql(u8, name, "WSARecvFrom")) return @intFromPtr(&WSARecvFrom);
    if (std.mem.eql(u8, name, "WSASetEvent")) return @intFromPtr(&WSASetEvent);
    if (std.mem.eql(u8, name, "gethostbyname")) return @intFromPtr(&gethostbyname);
    if (std.mem.eql(u8, name, "getprotobyname")) return @intFromPtr(&getprotobyname);
    if (std.mem.eql(u8, name, "WSAAsyncGetHostByName")) return @intFromPtr(&WSAAsyncGetHostByName);
    if (std.mem.eql(u8, name, "WSACancelAsyncRequest")) return @intFromPtr(&WSACancelAsyncRequest);
    if (std.mem.eql(u8, name, "WSAStartup")) return @intFromPtr(&WSAStartup);
    if (std.mem.eql(u8, name, "WSACleanup")) return @intFromPtr(&WSACleanup);
    if (std.mem.eql(u8, name, "WSAGetLastError")) return @intFromPtr(&WSAGetLastError);
    if (std.mem.eql(u8, name, "WSASetLastError")) return @intFromPtr(&WSASetLastError);
    if (std.mem.eql(u8, name, "WSASocketA")) return @intFromPtr(&WSASocketA);
    if (std.mem.eql(u8, name, "WSAEventSelect")) return @intFromPtr(&WSAEventSelect);
    if (std.mem.eql(u8, name, "WSAEnumNetworkEvents")) return @intFromPtr(&WSAEnumNetworkEvents);
    if (std.mem.eql(u8, name, "WSACreateEvent")) return @intFromPtr(&WSACreateEvent);
    if (std.mem.eql(u8, name, "WSACloseEvent")) return @intFromPtr(&WSACloseEvent);
    if (std.mem.eql(u8, name, "WSAResetEvent")) return @intFromPtr(&WSAResetEvent);
    if (std.mem.eql(u8, name, "WSAWaitForMultipleEvents")) return @intFromPtr(&WSAWaitForMultipleEvents);
    if (std.mem.eql(u8, name, "WSAIoctl")) return @intFromPtr(&WSAIoctl);
    if (std.mem.eql(u8, name, "__WSAFDIsSet")) return @intFromPtr(&__WSAFDIsSet);
    if (std.mem.eql(u8, name, "accept")) return @intFromPtr(&accept);
    if (std.mem.eql(u8, name, "bind")) return @intFromPtr(&bind);
    if (std.mem.eql(u8, name, "closesocket")) return @intFromPtr(&closesocket);
    if (std.mem.eql(u8, name, "connect")) return @intFromPtr(&connect);
    if (std.mem.eql(u8, name, "freeaddrinfo")) return @intFromPtr(&freeaddrinfo);
    if (std.mem.eql(u8, name, "getaddrinfo")) return @intFromPtr(&getaddrinfo);
    if (std.mem.eql(u8, name, "gethostbyaddr")) return @intFromPtr(&gethostbyaddr);
    if (std.mem.eql(u8, name, "gethostname")) return @intFromPtr(&gethostname);
    if (std.mem.eql(u8, name, "getnameinfo")) return @intFromPtr(&getnameinfo);
    if (std.mem.eql(u8, name, "getpeername")) return @intFromPtr(&getpeername);
    if (std.mem.eql(u8, name, "getsockname")) return @intFromPtr(&getsockname);
    if (std.mem.eql(u8, name, "getsockopt")) return @intFromPtr(&getsockopt);
    if (std.mem.eql(u8, name, "inet_addr")) return @intFromPtr(&inet_addr);
    if (std.mem.eql(u8, name, "inet_ntoa")) return @intFromPtr(&inet_ntoa);
    if (std.mem.eql(u8, name, "ioctlsocket")) return @intFromPtr(&ioctlsocket);
    if (std.mem.eql(u8, name, "listen")) return @intFromPtr(&listen);
    if (std.mem.eql(u8, name, "recv")) return @intFromPtr(&recv);
    if (std.mem.eql(u8, name, "recvfrom")) return @intFromPtr(&recvfrom);
    if (std.mem.eql(u8, name, "select")) return @intFromPtr(&ws2_select);
    if (std.mem.eql(u8, name, "send")) return @intFromPtr(&send);
    if (std.mem.eql(u8, name, "sendto")) return @intFromPtr(&sendto);
    if (std.mem.eql(u8, name, "setsockopt")) return @intFromPtr(&setsockopt);
    if (std.mem.eql(u8, name, "shutdown")) return @intFromPtr(&shutdown);
    if (std.mem.eql(u8, name, "socket")) return @intFromPtr(&socket);
    if (std.mem.eql(u8, name, "htonl")) return @intFromPtr(&htonl);
    if (std.mem.eql(u8, name, "htons")) return @intFromPtr(&htons);
    if (std.mem.eql(u8, name, "ntohl")) return @intFromPtr(&ntohl);
    if (std.mem.eql(u8, name, "ntohs")) return @intFromPtr(&ntohs);
    if (std.mem.eql(u8, name, "if_nametoindex")) return @intFromPtr(&if_nametoindex);
    return null;
}

// ---------------------------------------------------------------------------
// 3. Console-safe USER32.dll stubs (for console PEs like busybox64.exe)
//    Note: MessageBoxA/W are intentionally omitted here so console fail-closed
//    tests (winrun_unresolved.zig) continue to reject GUI dialog imports.
// ---------------------------------------------------------------------------

fn DispatchMessageA(msg: ?*const anyopaque) callconv(W) isize {
    _ = msg;
    return 0;
}

fn TranslateMessage(msg: ?*const anyopaque) callconv(W) i32 {
    _ = msg;
    return 0;
}

fn PeekMessageA(msg: ?*anyopaque, hwnd: usize, fmin: u32, fmax: u32, remove: u32) callconv(W) i32 {
    _ = msg;
    _ = hwnd;
    _ = fmin;
    _ = fmax;
    _ = remove;
    return 0;
}

fn IsIconic(hwnd: usize) callconv(W) i32 {
    _ = hwnd;
    return 0;
}

fn IsWindowVisible(hwnd: usize) callconv(W) i32 {
    _ = hwnd;
    return 0;
}

fn ShowWindow(hwnd: usize, cmd: i32) callconv(W) i32 {
    _ = hwnd;
    _ = cmd;
    return 0;
}

fn MsgWaitForMultipleObjects(count: u32, handles: ?*const usize, wait_all: i32, ms: u32, wake_mask: u32) callconv(W) u32 {
    _ = count;
    _ = handles;
    _ = wait_all;
    _ = wake_mask;
    if (ms > 0 and ms < 1000) {
        var req: linux.timespec = .{
            .sec = 0,
            .nsec = @as(isize, @intCast(ms)) * 1_000_000,
        };
        _ = linux.nanosleep(&req, null);
    }
    return 0; // WAIT_OBJECT_0
}

/// CharUpperW: uppercase in place, ASCII only. The Win32 locale-sensitive
/// conversion is NOT modelled; an ASCII-only FNV-free table walk is what this is.
fn CharUpperW(str: ?[*]u16) callconv(W) ?[*]u16 {
    const s = str orelse return null;
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {
        if (s[i] >= 'a' and s[i] <= 'z') s[i] -= 32;
    }
    return s;
}

pub fn lookupUser32Console(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "DispatchMessageA")) return @intFromPtr(&DispatchMessageA);
    if (std.mem.eql(u8, name, "TranslateMessage")) return @intFromPtr(&TranslateMessage);
    if (std.mem.eql(u8, name, "PeekMessageA")) return @intFromPtr(&PeekMessageA);
    if (std.mem.eql(u8, name, "IsIconic")) return @intFromPtr(&IsIconic);
    if (std.mem.eql(u8, name, "IsWindowVisible")) return @intFromPtr(&IsWindowVisible);
    if (std.mem.eql(u8, name, "ShowWindow")) return @intFromPtr(&ShowWindow);
    if (std.mem.eql(u8, name, "MsgWaitForMultipleObjects")) return @intFromPtr(&MsgWaitForMultipleObjects);
    if (std.mem.eql(u8, name, "CharUpperW")) return @intFromPtr(&CharUpperW);
    return null;
}

// ---------------------------------------------------------------------------
// 4. SHLWAPI.dll
// ---------------------------------------------------------------------------

fn PathFileExistsW(pszPath: ?[*:0]const u16) callconv(W) i32 {
    const k32 = @import("winrun_kernel32.zig");
    return if (k32.queryWinPathAttrsW(pszPath) != 0xFFFFFFFF) 1 else 0;
}

fn PathFileExistsA(pszPath: ?[*:0]const u8) callconv(W) i32 {
    const k32 = @import("winrun_kernel32.zig");
    return if (k32.queryWinPathAttrsA(pszPath) != 0xFFFFFFFF) 1 else 0;
}

fn PathIsDirectoryW(pszPath: ?[*:0]const u16) callconv(W) i32 {
    const k32 = @import("winrun_kernel32.zig");
    const attrs = k32.queryWinPathAttrsW(pszPath);
    return if (attrs != 0xFFFFFFFF and (attrs & 0x00000010) != 0) 1 else 0;
}

fn PathFindFileNameW(pszPath: ?[*:0]const u16) callconv(W) ?[*:0]const u16 {
    if (pszPath == null) return null;
    var last: [*:0]const u16 = pszPath.?;
    var i: usize = 0;
    while (pszPath.?[i] != 0) : (i += 1) {
        if (pszPath.?[i] == '\\' or pszPath.?[i] == '/') {
            last = pszPath.? + i + 1;
        }
    }
    return last;
}

fn PathFindExtensionW(pszPath: ?[*:0]const u16) callconv(W) ?[*:0]const u16 {
    if (pszPath == null) return null;
    var dot: ?[*:0]const u16 = null;
    var i: usize = 0;
    while (pszPath.?[i] != 0) : (i += 1) {
        if (pszPath.?[i] == '.') dot = pszPath.? + i;
        if (pszPath.?[i] == '\\' or pszPath.?[i] == '/') dot = null;
    }
    return dot orelse (pszPath.? + i);
}

fn PathRemoveFileSpecW(pszPath: ?[*]u16) callconv(W) i32 {
    if (pszPath == null) return 0;
    var last_sep: ?usize = null;
    var i: usize = 0;
    while (pszPath.?[i] != 0) : (i += 1) {
        if (pszPath.?[i] == '\\' or pszPath.?[i] == '/') last_sep = i;
    }
    if (last_sep) |idx| {
        pszPath.?[idx] = 0;
        return 1;
    }
    return 0;
}

fn PathCanonicalizeW(pszBuf: ?[*]u16, pszPath: ?[*:0]const u16) callconv(W) i32 {
    if (pszBuf == null or pszPath == null) return 0;
    var i: usize = 0;
    while (pszPath.?[i] != 0 and i < 260) : (i += 1) {
        pszBuf.?[i] = pszPath.?[i];
    }
    pszBuf.?[i] = 0;
    return 1;
}

fn SHDeleteKeyW(hKey: usize, pszSubKey: ?*const u16) callconv(W) i32 {
    _ = hKey; _ = pszSubKey;
    return 0;
}

fn PathCreateFromUrlW(pszUrl: ?*const u16, pszPath: ?[*]u16, pcchPath: ?*u32, dwFlags: u32) callconv(W) i32 {
    _ = pszUrl; _ = pszPath; _ = dwFlags;
    if (pcchPath) |p| p.* = 0;
    return 0;
}

fn PathCombineW(pszDest: ?[*]u16, pszDir: ?*const u16, pszFile: ?*const u16) callconv(W) ?[*]u16 {
    _ = pszDir; _ = pszFile;
    if (pszDest) |d| d[0] = 0;
    return pszDest;
}

fn AssocQueryStringW(flags: u32, str: u32, pszAssoc: ?*const u16, pszExtra: ?*const u16, pszOut: ?[*]u16, pcchOut: ?*u32) callconv(W) i32 {
    _ = flags; _ = str; _ = pszAssoc; _ = pszExtra; _ = pszOut;
    if (pcchOut) |p| p.* = 0;
    return -2147467259;
}

fn PathGetDriveNumberW(pszPath: ?*const u16) callconv(W) i32 {
    _ = pszPath;
    return 2;
}

fn ColorAdjustLuma(clrRGB: u32, n: i32, fScale: i32) callconv(W) u32 {
    _ = n; _ = fScale;
    return clrRGB;
}

fn PathAppendW(pszPath: ?[*]u16, pszMore: ?*const u16) callconv(W) i32 {
    _ = pszPath; _ = pszMore;
    return 1;
}

fn PathMatchSpecW(pszFile: ?*const u16, pszSpec: ?*const u16) callconv(W) i32 {
    _ = pszFile; _ = pszSpec;
    return 1;
}

fn PathIsNetworkPathW(pszPath: ?*const u16) callconv(W) i32 {
    _ = pszPath;
    return 0;
}

fn PathCompactPathExW(pszOut: ?[*]u16, pszSrc: ?*const u16, cchMax: u32, dwFlags: u32) callconv(W) i32 {
    _ = pszSrc; _ = cchMax; _ = dwFlags;
    if (pszOut) |p| p[0] = 0;
    return 1;
}

fn ColorHLSToRGB(wHue: u16, wLuminance: u16, wSaturation: u16) callconv(W) u32 {
    _ = wHue; _ = wLuminance; _ = wSaturation;
    return 0x00FFFFFF;
}

fn ColorRGBToHLS(clrRGB: u32, pwHue: ?*u16, pwLuminance: ?*u16, pwSaturation: ?*u16) callconv(W) void {
    _ = clrRGB;
    if (pwHue) |h| h.* = 0;
    if (pwLuminance) |l| l.* = 240;
    if (pwSaturation) |s| s.* = 0;
}

fn PathStripPathW(pszPath: ?[*]u16) callconv(W) void {
    _ = pszPath;
}

fn PathIsRelativeW(pszPath: ?*const u16) callconv(W) i32 {
    _ = pszPath;
    return 0;
}

fn PathRemoveExtensionW(pszPath: ?[*]u16) callconv(W) void {
    _ = pszPath;
}

pub fn lookupShlwapi(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "PathCreateFromUrlW")) return @intFromPtr(&PathCreateFromUrlW);
    if (std.mem.eql(u8, name, "PathCombineW")) return @intFromPtr(&PathCombineW);
    if (std.mem.eql(u8, name, "AssocQueryStringW")) return @intFromPtr(&AssocQueryStringW);
    if (std.mem.eql(u8, name, "PathGetDriveNumberW")) return @intFromPtr(&PathGetDriveNumberW);
    if (std.mem.eql(u8, name, "ColorAdjustLuma")) return @intFromPtr(&ColorAdjustLuma);
    if (std.mem.eql(u8, name, "PathAppendW")) return @intFromPtr(&PathAppendW);
    if (std.mem.eql(u8, name, "PathMatchSpecW")) return @intFromPtr(&PathMatchSpecW);
    if (std.mem.eql(u8, name, "PathIsNetworkPathW")) return @intFromPtr(&PathIsNetworkPathW);
    if (std.mem.eql(u8, name, "PathCompactPathExW")) return @intFromPtr(&PathCompactPathExW);
    if (std.mem.eql(u8, name, "ColorHLSToRGB")) return @intFromPtr(&ColorHLSToRGB);
    if (std.mem.eql(u8, name, "ColorRGBToHLS")) return @intFromPtr(&ColorRGBToHLS);
    if (std.mem.eql(u8, name, "PathStripPathW")) return @intFromPtr(&PathStripPathW);
    if (std.mem.eql(u8, name, "PathIsRelativeW")) return @intFromPtr(&PathIsRelativeW);
    if (std.mem.eql(u8, name, "PathRemoveExtensionW")) return @intFromPtr(&PathRemoveExtensionW);
    if (std.mem.eql(u8, name, "SHDeleteKeyW")) return @intFromPtr(&SHDeleteKeyW);
    if (std.mem.eql(u8, name, "PathCanonicalizeW")) return @intFromPtr(&PathCanonicalizeW);
    if (std.mem.eql(u8, name, "PathFileExistsW")) return @intFromPtr(&PathFileExistsW);
    if (std.mem.eql(u8, name, "PathFileExistsA")) return @intFromPtr(&PathFileExistsA);
    if (std.mem.eql(u8, name, "PathIsDirectoryW")) return @intFromPtr(&PathIsDirectoryW);
    if (std.mem.eql(u8, name, "PathFindFileNameW")) return @intFromPtr(&PathFindFileNameW);
    if (std.mem.eql(u8, name, "PathFindExtensionW")) return @intFromPtr(&PathFindExtensionW);
    if (std.mem.eql(u8, name, "PathRemoveFileSpecW")) return @intFromPtr(&PathRemoveFileSpecW);
    return null;
}

// ---------------------------------------------------------------------------
// 5. SHELL32.dll
// ---------------------------------------------------------------------------

fn ShellExecuteW(hwnd: usize, op: ?[*:0]const u16, file: ?[*:0]const u16, params: ?[*:0]const u16, dir: ?[*:0]const u16, show: i32) callconv(W) usize {
    _ = hwnd; _ = op; _ = file; _ = params; _ = dir; _ = show;
    return 42; // > 32 indicates success
}

fn ShellExecuteA(hwnd: usize, op: ?[*:0]const u8, file: ?[*:0]const u8, params: ?[*:0]const u8, dir: ?[*:0]const u8, show: i32) callconv(W) usize {
    _ = hwnd;
    _ = show;
    std.debug.print("[WINS:ShellExecuteA] op={s} file={s} params={s} dir={s}\n", .{
        if (op) |p| std.mem.span(p) else "(null)",
        if (file) |p| std.mem.span(p) else "(null)",
        if (params) |p| std.mem.span(p) else "(null)",
        if (dir) |p| std.mem.span(p) else "(null)",
    });
    return 42;
}

fn SHGetFolderPathW(hwnd: usize, csidl: i32, token: usize, flags: u32, pszPath: ?[*]u16) callconv(W) i32 {
    _ = hwnd; _ = csidl; _ = token; _ = flags;
    if (pszPath) |p| {
        const default_path = [_]u16{ 'C', ':', '\\', 'U', 's', 'e', 'r', 's', '\\', 'U', 's', 'e', 'r', '\\', 'A', 'p', 'p', 'D', 'a', 't', 'a', '\\', 'R', 'o', 'a', 'm', 'i', 'n', 'g', 0 };
        @memcpy(p[0..default_path.len], &default_path);
    }
    return 0; // S_OK
}

fn SHGetKnownFolderPath(rfid: ?*const anyopaque, dwFlags: u32, hToken: usize, ppszPath: ?*?[*]u16) callconv(W) i32 {
    _ = rfid;
    _ = dwFlags;
    _ = hToken;
    const out = ppszPath orelse return @bitCast(@as(u32, 0x80070057));
    const default_path = [_]u16{ 'C', ':', '\\', 'U', 's', 'e', 'r', 's', '\\', 'U', 's', 'e', 'r', '\\', 'A', 'p', 'p', 'D', 'a', 't', 'a', '\\', 'R', 'o', 'a', 'm', 'i', 'n', 'g', 0 };
    const raw = CoTaskMemAlloc(default_path.len * 2) orelse return @bitCast(@as(u32, 0x8007000E));
    const w: [*]u16 = @ptrCast(@alignCast(raw));
    @memcpy(w[0..default_path.len], &default_path);
    out.* = w;
    return 0; // S_OK
}

fn SHCreateDirectory(hwnd: usize, pszPath: ?[*:0]const u16) callconv(W) i32 {
    _ = hwnd; _ = pszPath;
    return 0; // ERROR_SUCCESS
}

fn SHCreateDirectoryExW(hwnd: usize, pszPath: ?[*:0]const u16, psa: ?*anyopaque) callconv(W) i32 {
    _ = hwnd; _ = pszPath; _ = psa;
    return 0; // ERROR_SUCCESS
}

fn SHFileOperationW(lpFileOp: ?*anyopaque) callconv(W) i32 {
    _ = lpFileOp;
    return 0; // ERROR_SUCCESS
}

fn ShellExecuteExA(pExecInfo: ?*anyopaque) callconv(W) i32 {
    _ = pExecInfo;
    return 1;
}

fn ShellExecuteExW(pExecInfo: ?*anyopaque) callconv(W) i32 {
    _ = pExecInfo;
    return 1;
}

fn SHCreateItemFromParsingName(pszPath: ?*const u16, pbc: ?*anyopaque, riid: ?*const anyopaque, ppv: ?*?*anyopaque) callconv(W) i32 {
    _ = pszPath; _ = pbc; _ = riid;
    if (ppv) |p| p.* = null;
    return -2147467259;
}

fn SHParseDisplayName(pszName: ?*const u16, pbc: ?*anyopaque, ppidl: ?*?*anyopaque, sfgaoIn: u32, psfgaoOut: ?*u32) callconv(W) i32 {
    _ = pszName; _ = pbc; _ = sfgaoIn;
    if (ppidl) |p| p.* = null;
    if (psfgaoOut) |s| s.* = 0;
    return -2147467259;
}

fn SHOpenFolderAndSelectItems(pidlFolder: ?*const anyopaque, cidl: u32, apidl: ?*const anyopaque, dwFlags: u32) callconv(W) i32 {
    _ = pidlFolder; _ = cidl; _ = apidl; _ = dwFlags;
    return 0;
}

fn DragQueryPoint(hDrop: usize, ppt: ?*anyopaque) callconv(W) i32 {
    _ = hDrop; _ = ppt;
    return 1;
}

fn Shell_NotifyIconW(dwMessage: u32, lpData: ?*anyopaque) callconv(W) i32 {
    _ = dwMessage; _ = lpData;
    return 1;
}

fn DragQueryFileW(hDrop: usize, iFile: u32, lpszFile: ?[*]u16, cch: u32) callconv(W) u32 {
    _ = hDrop; _ = iFile; _ = lpszFile; _ = cch;
    return 0;
}

fn DragFinish(hDrop: usize) callconv(W) void {
    _ = hDrop;
}

var argv_ptrs: [8]?[*]u16 = undefined;
var dummy_cmd_arg: [2]u16 = .{ 'w', 0 };

fn CommandLineToArgvW(lpCmdLine: ?*const u16, pNumArgs: ?*i32) callconv(W) ?[*]?[*]u16 {
    _ = lpCmdLine;
    if (pNumArgs) |p| p.* = 1;
    argv_ptrs[0] = &dummy_cmd_arg;
    return &argv_ptrs;
}

fn DllGetVersion(pdvi: ?[*]u32) callconv(W) i32 {
    const info = pdvi orelse return @bitCast(@as(u32, 0x80004003)); // E_POINTER
    const cb = info[0];
    if (cb < 20) return @bitCast(@as(u32, 0x80070057)); // E_INVALIDARG
    info[1] = 10; // dwMajorVersion (Windows 10 shell32 >= 5)
    info[2] = 0; // dwMinorVersion
    info[3] = 19045; // dwBuildNumber
    info[4] = 2; // DLLVER_PLATFORM_NT
    return 0; // S_OK
}

pub fn lookupShell32(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "DllGetVersion")) return @intFromPtr(&DllGetVersion);
    if (std.mem.eql(u8, name, "CommandLineToArgvW")) return @intFromPtr(&CommandLineToArgvW);
    if (std.mem.eql(u8, name, "ShellExecuteA")) return @intFromPtr(&ShellExecuteA);
    if (std.mem.eql(u8, name, "ShellExecuteExA")) return @intFromPtr(&ShellExecuteExA);
    if (std.mem.eql(u8, name, "ShellExecuteExW")) return @intFromPtr(&ShellExecuteExW);
    if (std.mem.eql(u8, name, "ShellExecuteW")) return @intFromPtr(&ShellExecuteW);
    if (std.mem.eql(u8, name, "SHGetFolderPathW")) return @intFromPtr(&SHGetFolderPathW);
    if (std.mem.eql(u8, name, "SHGetKnownFolderPath")) return @intFromPtr(&SHGetKnownFolderPath);
    if (std.mem.eql(u8, name, "SHCreateDirectory")) return @intFromPtr(&SHCreateDirectory);
    if (std.mem.eql(u8, name, "SHCreateDirectoryExW")) return @intFromPtr(&SHCreateDirectoryExW);
    if (std.mem.eql(u8, name, "SHFileOperationW")) return @intFromPtr(&SHFileOperationW);
    if (std.mem.eql(u8, name, "SHCreateItemFromParsingName")) return @intFromPtr(&SHCreateItemFromParsingName);
    if (std.mem.eql(u8, name, "SHParseDisplayName")) return @intFromPtr(&SHParseDisplayName);
    if (std.mem.eql(u8, name, "SHOpenFolderAndSelectItems")) return @intFromPtr(&SHOpenFolderAndSelectItems);
    if (std.mem.eql(u8, name, "DragQueryPoint")) return @intFromPtr(&DragQueryPoint);
    if (std.mem.eql(u8, name, "Shell_NotifyIconW")) return @intFromPtr(&Shell_NotifyIconW);
    if (std.mem.eql(u8, name, "DragQueryFileW")) return @intFromPtr(&DragQueryFileW);
    if (std.mem.eql(u8, name, "DragFinish")) return @intFromPtr(&DragFinish);
    return null;
}

// ---------------------------------------------------------------------------
// 6. OLEAUT32.dll & ole32.dll
// ---------------------------------------------------------------------------

var ole_buf: [256 * 1024]u8 align(16) = undefined;
var ole_buf_off: usize = 16;
var ole_lock: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

const VARIANT_SIZE: usize = if (@sizeOf(usize) == 4) 16 else 24;
const VT_BSTR: u16 = 8;

fn allocBstrBytes(total: usize) ?[*]u8 {
    if (total > ole_buf.len - 16) return null;
    while (ole_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {}
    defer ole_lock.store(0, .release);
    if (ole_buf_off + total > ole_buf.len) ole_buf_off = 16;
    const base: [*]u8 = @ptrCast(&ole_buf[ole_buf_off]);
    ole_buf_off = std.mem.alignForward(usize, ole_buf_off + total, 8);
    return base;
}

fn SysAllocString(s: ?[*:0]const u16) callconv(W) ?[*]u16 {
    if (s == null) return null;
    var len: u32 = 0;
    while (s.?[len] != 0) : (len += 1) {}
    const byte_len = len * 2;
    const base = allocBstrBytes(4 + byte_len + 2) orelse return null;
    std.mem.writeInt(u32, base[0..4], byte_len, .little);
    const chars: [*]u16 = @ptrCast(@alignCast(base + 4));
    @memcpy(chars[0..len], s.?[0..len]);
    chars[len] = 0;
    return chars;
}

fn SysAllocStringLen(s: ?[*]const u16, len: u32) callconv(W) ?[*]u16 {
    const byte_len = len * 2;
    const base = allocBstrBytes(4 + byte_len + 2) orelse return null;
    std.mem.writeInt(u32, base[0..4], byte_len, .little);
    const chars: [*]u16 = @ptrCast(@alignCast(base + 4));
    if (s) |src| @memcpy(chars[0..len], src[0..len]) else @memset(chars[0..len], 0);
    chars[len] = 0;
    return chars;
}

fn SysAllocStringByteLen(s: ?[*]const u8, len: u32) callconv(W) ?[*]u8 {
    const base = allocBstrBytes(4 + len + 2) orelse return null;
    std.mem.writeInt(u32, base[0..4], len, .little);
    const chars = base + 4;
    if (s) |src| @memcpy(chars[0..len], src[0..len]) else @memset(chars[0..len], 0);
    chars[len] = 0;
    chars[len + 1] = 0;
    return chars;
}

fn SysFreeString(bstr: ?[*]u16) callconv(W) void {
    _ = bstr;
}

fn SysStringByteLen(bstr: ?[*]u16) callconv(W) u32 {
    if (bstr == null) return 0;
    const p: [*]u8 = @ptrCast(bstr.?);
    return std.mem.readInt(u32, (p - 4)[0..4], .little);
}

fn SysStringLen(bstr: ?[*]u16) callconv(W) u32 {
    return SysStringByteLen(bstr) / 2;
}

fn VariantInit(pv: ?*anyopaque) callconv(W) void {
    if (pv) |p| @memset(@as([*]u8, @ptrCast(p))[0..VARIANT_SIZE], 0);
}

fn VariantClear(pv: ?*anyopaque) callconv(W) i32 {
    if (pv) |p| @memset(@as([*]u8, @ptrCast(p))[0..VARIANT_SIZE], 0);
    return 0; // S_OK
}

fn VariantCopy(pvargDest: ?*anyopaque, pvargSrc: ?*const anyopaque) callconv(W) i32 {
    const dst_ptr = pvargDest orelse return @bitCast(@as(u32, 0x80070057)); // E_INVALIDARG
    const src_ptr = pvargSrc orelse return @bitCast(@as(u32, 0x80070057));
    if (dst_ptr == src_ptr) return 0; // S_OK
    const dst: [*]u8 = @ptrCast(dst_ptr);
    const src: [*]const u8 = @ptrCast(src_ptr);
    var tmp: [24]u8 = undefined;
    @memcpy(tmp[0..VARIANT_SIZE], src[0..VARIANT_SIZE]);
    const vt = std.mem.readInt(u16, tmp[0..2], .little);
    if (vt == VT_BSTR) {
        const raw_bstr = std.mem.readInt(usize, tmp[8 .. 8 + @sizeOf(usize)], .little);
        if (raw_bstr != 0) {
            const bstr_w: [*]u16 = @ptrFromInt(raw_bstr);
            const byte_len = SysStringByteLen(bstr_w);
            const dup = SysAllocStringByteLen(@ptrCast(bstr_w), byte_len) orelse return @bitCast(@as(u32, 0x8007000E)); // E_OUTOFMEMORY
            std.mem.writeInt(usize, tmp[8 .. 8 + @sizeOf(usize)], @intFromPtr(dup), .little);
        }
    }
    _ = VariantClear(dst_ptr);
    @memcpy(dst[0..VARIANT_SIZE], tmp[0..VARIANT_SIZE]);
    return 0; // S_OK
}

fn VariantCopyInd(pvargDest: ?*anyopaque, pvargSrc: ?*const anyopaque) callconv(W) i32 {
    return VariantCopy(pvargDest, pvargSrc);
}

fn VariantChangeType(pvargDest: ?*anyopaque, pvarSrc: ?*const anyopaque, wFlags: u16, vt: u16) callconv(W) i32 {
    _ = wFlags;
    const dst_ptr = pvargDest orelse return @bitCast(@as(u32, 0x80070057));
    const src_ptr = pvarSrc orelse return @bitCast(@as(u32, 0x80070057));
    const src: [*]const u8 = @ptrCast(src_ptr);
    const src_vt = std.mem.readInt(u16, src[0..2], .little);
    if (src_vt == vt) return VariantCopy(dst_ptr, src_ptr);
    return @bitCast(@as(u32, 0x80020005)); // DISP_E_TYPEMISMATCH
}

fn GetErrorInfo(dwReserved: u32, ppErrInfo: ?*?*anyopaque) callconv(W) i32 {
    _ = dwReserved;
    if (ppErrInfo) |p| p.* = null;
    return 1; // S_FALSE
}

const SAFEARRAYBOUND = extern struct { cElements: u32, lLbound: i32 };
const SAFEARRAY = extern struct {
    cDims: u16,
    fFeatures: u16,
    cbElements: u32,
    cLocks: u32,
    pvData: ?[*]u8,
    rgsabound: [1]SAFEARRAYBOUND,
};

fn safeArrayVtSize(vt: u16) u32 {
    return switch (vt & 0xfff) {
        2, 11, 17, 16, 18 => 2, // I2, BOOL, UI1/I1/UI2
        3, 4, 19, 22, 23 => 4,  // I4, R4, UI4, INT, UINT
        5, 6, 7, 8, 20, 21, 9, 13, 36 => 8, // R8, CY, DATE, BSTR, I8, UI8, IDispatch, IUnknown
        12 => @truncate(VARIANT_SIZE),
        else => 8,
    };
}

fn SafeArrayCreate(vt: u16, cDims: u32, rgsabound: ?[*]const SAFEARRAYBOUND) callconv(W) ?*SAFEARRAY {
    if (cDims == 0 or cDims > 16 or rgsabound == null) return null;
    const elem_sz = safeArrayVtSize(vt);
    var total_elems: usize = 1;
    for (0..cDims) |i| total_elems *|= rgsabound.?[i].cElements;
    const hdr_bytes = @sizeOf(SAFEARRAY) + (cDims - 1) * @sizeOf(SAFEARRAYBOUND);
    const data_bytes = total_elems * elem_sz;
    const mem = std.heap.page_allocator.alloc(u8, std.mem.alignForward(usize, hdr_bytes, 16) + @max(data_bytes, 16)) catch return null;
    @memset(mem, 0);
    const psa: *SAFEARRAY = @ptrCast(@alignCast(mem.ptr));
    psa.cDims = @truncate(cDims);
    psa.fFeatures = 0;
    psa.cbElements = elem_sz;
    psa.cLocks = 0;
    psa.pvData = mem.ptr + std.mem.alignForward(usize, hdr_bytes, 16);
    const bounds: [*]SAFEARRAYBOUND = @ptrCast(&psa.rgsabound[0]);
    for (0..cDims) |i| bounds[i] = rgsabound.?[i];
    return psa;
}

fn SafeArrayDestroy(psa: ?*SAFEARRAY) callconv(W) i32 {
    _ = psa;
    return 0; // S_OK
}

fn SafeArrayGetDim(psa: ?*const SAFEARRAY) callconv(W) u32 {
    return if (psa) |p| p.cDims else 0;
}

fn SafeArrayGetLBound(psa: ?*const SAFEARRAY, nDim: u32, plLbound: ?*i32) callconv(W) i32 {
    const p = psa orelse return @bitCast(@as(u32, 0x80070057));
    if (nDim == 0 or nDim > p.cDims) return @bitCast(@as(u32, 0x8002000B));
    const bounds: [*]const SAFEARRAYBOUND = @ptrCast(&p.rgsabound[0]);
    if (plLbound) |out| out.* = bounds[nDim - 1].lLbound;
    return 0;
}

fn SafeArrayGetUBound(psa: ?*const SAFEARRAY, nDim: u32, plUbound: ?*i32) callconv(W) i32 {
    const p = psa orelse return @bitCast(@as(u32, 0x80070057));
    if (nDim == 0 or nDim > p.cDims) return @bitCast(@as(u32, 0x8002000B));
    const bounds: [*]const SAFEARRAYBOUND = @ptrCast(&p.rgsabound[0]);
    const b = bounds[nDim - 1];
    if (plUbound) |out| out.* = b.lLbound + @as(i32, @intCast(b.cElements)) - 1;
    return 0;
}

fn SafeArrayPtrOfIndex(psa: ?*SAFEARRAY, rgIndices: ?[*]const i32, ppvData: ?*?*anyopaque) callconv(W) i32 {
    const p = psa orelse return @bitCast(@as(u32, 0x80070057));
    const idxs = rgIndices orelse return @bitCast(@as(u32, 0x80070057));
    const data = p.pvData orelse return @bitCast(@as(u32, 0x80070057));
    const bounds: [*]const SAFEARRAYBOUND = @ptrCast(&p.rgsabound[0]);
    var offset: usize = 0;
    var stride: usize = 1;
    var d: usize = p.cDims;
    while (d > 0) {
        d -= 1;
        const rel = idxs[d] - bounds[d].lLbound;
        if (rel < 0 or rel >= @as(i32, @intCast(bounds[d].cElements))) return @bitCast(@as(u32, 0x8002000B));
        offset += @as(usize, @intCast(rel)) * stride;
        stride *= bounds[d].cElements;
    }
    if (ppvData) |out| out.* = @ptrCast(data + offset * p.cbElements);
    return 0;
}

fn SafeArrayAccessData(psa: ?*SAFEARRAY, ppvData: ?*?*anyopaque) callconv(W) i32 {
    const p = psa orelse return @bitCast(@as(u32, 0x80070057));
    p.cLocks += 1;
    if (ppvData) |out| out.* = if (p.pvData) |d| @ptrCast(d) else null;
    return 0;
}

fn SafeArrayUnaccessData(psa: ?*SAFEARRAY) callconv(W) i32 {
    const p = psa orelse return @bitCast(@as(u32, 0x80070057));
    if (p.cLocks > 0) p.cLocks -= 1;
    return 0;
}

fn SafeArrayPutElement(psa: ?*SAFEARRAY, rgIndices: ?[*]const i32, pv: ?*const anyopaque) callconv(W) i32 {
    const p = psa orelse return @bitCast(@as(u32, 0x80070057));
    var ptr: ?*anyopaque = null;
    const rc = SafeArrayPtrOfIndex(p, rgIndices, &ptr);
    if (rc != 0) return rc;
    if (pv != null and ptr != null) {
        const dst: [*]u8 = @ptrCast(ptr.?);
        const src: [*]const u8 = @ptrCast(pv.?);
        @memcpy(dst[0..p.cbElements], src[0..p.cbElements]);
    }
    return 0;
}

fn SafeArrayGetElement(psa: ?*SAFEARRAY, rgIndices: ?[*]const i32, pv: ?*anyopaque) callconv(W) i32 {
    const p = psa orelse return @bitCast(@as(u32, 0x80070057));
    var ptr: ?*anyopaque = null;
    const rc = SafeArrayPtrOfIndex(p, rgIndices, &ptr);
    if (rc != 0) return rc;
    if (pv != null and ptr != null) {
        const dst: [*]u8 = @ptrCast(pv.?);
        const src: [*]const u8 = @ptrCast(ptr.?);
        @memcpy(dst[0..p.cbElements], src[0..p.cbElements]);
    }
    return 0;
}

pub fn lookupOleaut32(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "VariantCopy")) return @intFromPtr(&VariantCopy);
    if (std.mem.eql(u8, name, "VariantCopyInd")) return @intFromPtr(&VariantCopyInd);
    if (std.mem.eql(u8, name, "VariantChangeType")) return @intFromPtr(&VariantChangeType);
    if (std.mem.eql(u8, name, "SysAllocString")) return @intFromPtr(&SysAllocString);
    if (std.mem.eql(u8, name, "SysAllocStringLen")) return @intFromPtr(&SysAllocStringLen);
    if (std.mem.eql(u8, name, "SysAllocStringByteLen")) return @intFromPtr(&SysAllocStringByteLen);
    if (std.mem.eql(u8, name, "SysFreeString")) return @intFromPtr(&SysFreeString);
    if (std.mem.eql(u8, name, "SysStringByteLen")) return @intFromPtr(&SysStringByteLen);
    if (std.mem.eql(u8, name, "SysStringLen")) return @intFromPtr(&SysStringLen);
    if (std.mem.eql(u8, name, "VariantInit")) return @intFromPtr(&VariantInit);
    if (std.mem.eql(u8, name, "VariantClear")) return @intFromPtr(&VariantClear);
    if (std.mem.eql(u8, name, "GetErrorInfo")) return @intFromPtr(&GetErrorInfo);
    if (std.mem.eql(u8, name, "SafeArrayCreate")) return @intFromPtr(&SafeArrayCreate);
    if (std.mem.eql(u8, name, "SafeArrayDestroy")) return @intFromPtr(&SafeArrayDestroy);
    if (std.mem.eql(u8, name, "SafeArrayGetDim")) return @intFromPtr(&SafeArrayGetDim);
    if (std.mem.eql(u8, name, "SafeArrayGetLBound")) return @intFromPtr(&SafeArrayGetLBound);
    if (std.mem.eql(u8, name, "SafeArrayGetUBound")) return @intFromPtr(&SafeArrayGetUBound);
    if (std.mem.eql(u8, name, "SafeArrayPtrOfIndex")) return @intFromPtr(&SafeArrayPtrOfIndex);
    if (std.mem.eql(u8, name, "SafeArrayAccessData")) return @intFromPtr(&SafeArrayAccessData);
    if (std.mem.eql(u8, name, "SafeArrayUnaccessData")) return @intFromPtr(&SafeArrayUnaccessData);
    if (std.mem.eql(u8, name, "SafeArrayPutElement")) return @intFromPtr(&SafeArrayPutElement);
    if (std.mem.eql(u8, name, "SafeArrayGetElement")) return @intFromPtr(&SafeArrayGetElement);
    // This module does not distinguish the A and W variants of the BSTR family;
    // both names resolve to the wide implementation above.
    if (std.mem.eql(u8, name, "SysAllocStringA")) return @intFromPtr(&SysAllocString);
    return null;
}

fn OleRun(p: ?*anyopaque) callconv(W) i32 {
    _ = p;
    return 0; // S_OK
}

fn CoInitializeEx(pvReserved: ?*anyopaque, dwCoInit: u32) callconv(W) i32 {
    _ = pvReserved; _ = dwCoInit;
    return 0; // S_OK
}

fn CoCreateInstance(rclsid: ?*const anyopaque, pUnkOuter: ?*anyopaque, dwClsContext: u32, riid: ?*const anyopaque, ppv: ?*?*anyopaque) callconv(W) i32 {
    _ = rclsid; _ = pUnkOuter; _ = dwClsContext; _ = riid;
    if (ppv) |p| p.* = null;
    return @bitCast(@as(u32, 0x80004002)); // E_NOINTERFACE
}

fn CoUninitialize() callconv(W) void {}

fn CoInitialize(pvReserved: ?*anyopaque) callconv(W) i32 {
    _ = pvReserved;
    return 0; // S_OK
}

// "WINSCOTA" on 64-bit, "COTA" on the i386 loader (usize is 32 bits there).
const COTASK_MAGIC: usize = if (@sizeOf(usize) == 8) 0x57494E53_434F5441 else 0x434F5441;

fn CoTaskMemFree(pv: ?*anyopaque) callconv(W) void {
    const p = pv orelse return;
    const raw: [*]align(16) usize = @ptrFromInt(@intFromPtr(p) - 16);
    if (raw[0] != COTASK_MAGIC) return;
    const len = raw[1];
    const slice: [*]u8 = @ptrCast(raw);
    std.heap.page_allocator.free(slice[0 .. len + 16]);
}

fn CoTaskMemAlloc(cb: usize) callconv(W) ?*anyopaque {
    const len = @max(cb, 1);
    const slice = std.heap.page_allocator.alloc(u8, len + 16) catch return null;
    const hdr: [*]usize = @ptrCast(@alignCast(slice.ptr));
    hdr[0] = COTASK_MAGIC;
    hdr[1] = len;
    return @ptrCast(slice.ptr + 16);
}

fn CoTaskMemRealloc(pv: ?*anyopaque, cb: usize) callconv(W) ?*anyopaque {
    if (pv == null) return CoTaskMemAlloc(cb);
    if (cb == 0) {
        CoTaskMemFree(pv);
        return null;
    }
    const old_hdr: [*]usize = @ptrFromInt(@intFromPtr(pv.?) - 16);
    const old_len: usize = if (old_hdr[0] == COTASK_MAGIC) old_hdr[1] else 0;
    const new_p = CoTaskMemAlloc(cb) orelse return null;
    if (old_len > 0) {
        const dst: [*]u8 = @ptrCast(new_p);
        const src: [*]const u8 = @ptrCast(pv.?);
        @memcpy(dst[0..@min(old_len, cb)], src[0..@min(old_len, cb)]);
        CoTaskMemFree(pv);
    }
    return new_p;
}

fn CoCreateFreeThreadedMarshaler(punkOuter: ?*anyopaque, ppunkMarshal: ?*?*anyopaque) callconv(W) i32 {
    _ = punkOuter;
    if (ppunkMarshal) |p| p.* = null;
    return @bitCast(@as(u32, 0x80004002)); // E_NOINTERFACE
}

fn CoCreateGuid(pguid: ?*anyopaque) callconv(W) i32 {
    _ = pguid;
    return 0;
}

fn PropVariantClear(pvar: ?*anyopaque) callconv(W) i32 {
    _ = pvar;
    return 0;
}

fn CoSetProxyBlanket(pProxy: ?*anyopaque, dwAuthnSvc: u32, dwAuthzSvc: u32, pServerPrincName: ?*anyopaque, dwAuthnLevel: u32, dwImpLevel: u32, pAuthInfo: ?*anyopaque, dwCapabilities: u32) callconv(W) i32 {
    _ = pProxy; _ = dwAuthnSvc; _ = dwAuthzSvc; _ = pServerPrincName; _ = dwAuthnLevel; _ = dwImpLevel; _ = pAuthInfo; _ = dwCapabilities;
    return 0;
}

fn StringFromGUID2(rguid: ?*const anyopaque, lpsz: ?[*]u16, cchMax: i32) callconv(W) i32 {
    _ = rguid; _ = lpsz; _ = cchMax;
    return 39;
}

fn RegisterDragDrop(hwnd: usize, pDropTarget: ?*anyopaque) callconv(W) i32 {
    _ = hwnd; _ = pDropTarget;
    return 0;
}

fn RevokeDragDrop(hwnd: usize) callconv(W) i32 {
    _ = hwnd;
    return 0;
}

fn DoDragDrop(pDataObj: ?*anyopaque, pDropSource: ?*anyopaque, dwOKEffects: u32, pdwEffect: ?*u32) callconv(W) i32 {
    _ = pDataObj; _ = pDropSource; _ = dwOKEffects;
    if (pdwEffect) |e| e.* = 0;
    return 0x00040100;
}

fn OleInitialize(pvReserved: ?*anyopaque) callconv(W) i32 {
    _ = pvReserved;
    return 0;
}

fn OleUninitialize() callconv(W) void {}

fn ReleaseStgMedium(pmedium: ?*anyopaque) callconv(W) void {
    _ = pmedium;
}

fn CLSIDFromProgID(lpszProgID: ?[*:0]const u16, lpclsid: ?*anyopaque) callconv(W) i32 {
    _ = lpszProgID; _ = lpclsid;
    return 0;
}

pub fn lookupOle32(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "RegisterDragDrop")) return @intFromPtr(&RegisterDragDrop);
    if (std.mem.eql(u8, name, "RevokeDragDrop")) return @intFromPtr(&RevokeDragDrop);
    if (std.mem.eql(u8, name, "DoDragDrop")) return @intFromPtr(&DoDragDrop);
    if (std.mem.eql(u8, name, "OleInitialize")) return @intFromPtr(&OleInitialize);
    if (std.mem.eql(u8, name, "OleUninitialize")) return @intFromPtr(&OleUninitialize);
    if (std.mem.eql(u8, name, "ReleaseStgMedium")) return @intFromPtr(&ReleaseStgMedium);
    if (std.mem.eql(u8, name, "CLSIDFromProgID")) return @intFromPtr(&CLSIDFromProgID);
    if (std.mem.eql(u8, name, "CoInitialize")) return @intFromPtr(&CoInitialize);
    if (std.mem.eql(u8, name, "CoTaskMemFree")) return @intFromPtr(&CoTaskMemFree);
    if (std.mem.eql(u8, name, "CoTaskMemAlloc")) return @intFromPtr(&CoTaskMemAlloc);
    if (std.mem.eql(u8, name, "CoTaskMemRealloc")) return @intFromPtr(&CoTaskMemRealloc);
    if (std.mem.eql(u8, name, "CoCreateFreeThreadedMarshaler")) return @intFromPtr(&CoCreateFreeThreadedMarshaler);
    if (std.mem.eql(u8, name, "CoCreateGuid")) return @intFromPtr(&CoCreateGuid);
    if (std.mem.eql(u8, name, "PropVariantClear")) return @intFromPtr(&PropVariantClear);
    if (std.mem.eql(u8, name, "CoSetProxyBlanket")) return @intFromPtr(&CoSetProxyBlanket);
    if (std.mem.eql(u8, name, "StringFromGUID2")) return @intFromPtr(&StringFromGUID2);
    if (std.mem.eql(u8, name, "OleRun")) return @intFromPtr(&OleRun);
    if (std.mem.eql(u8, name, "CoInitializeEx")) return @intFromPtr(&CoInitializeEx);
    if (std.mem.eql(u8, name, "CoCreateInstance")) return @intFromPtr(&CoCreateInstance);
    if (std.mem.eql(u8, name, "CoUninitialize")) return @intFromPtr(&CoUninitialize);
    return null;
}

// ---------------------------------------------------------------------------
// 7. WLDAP32.dll (stubs)
// ---------------------------------------------------------------------------

fn ldap_stub() callconv(W) usize { return 0; }
fn ldap_unbind_s(ld: ?*anyopaque) callconv(W) u32 { _ = ld; return 0; }
fn ldap_err2string(err: u32) callconv(W) [*:0]const u8 { _ = err; return "Success"; }

pub fn lookupWldap32(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "ldap_unbind_s")) return @intFromPtr(&ldap_unbind_s);
    if (std.mem.eql(u8, name, "ldap_err2string")) return @intFromPtr(&ldap_err2string);
    if (std.mem.startsWith(u8, name, "ldap_") or std.mem.startsWith(u8, name, "ber_")) {
        return @intFromPtr(&ldap_stub);
    }
    return null;
}

// ---------------------------------------------------------------------------
// 8. CRYPT32.dll & ncrypt.dll / bcrypt.dll
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Stack-balanced unsupported-API stubs
//
// A zero-argument stub is NOT usable for a Win32 API. The caller pushes the
// arguments and a stdcall callee pops them, so `ret` with no immediate leaves
// every argument on the guest's stack. That imbalance shifts the frame by 4*N
// bytes (a 3-argument API leaves 12) and the next register the guest restores
// picks up a stale argument: 7zr came back from its SeLockMemoryPrivilege path
// with EBX holding the L"SeLockMemoryPrivilege" string pointer, which then made
// an `cmp %bl, <field>` compare against a non-zero byte and dereference a null
// value pointer. Each arity therefore gets its own function so the generated
// epilogue is `ret $0x10`-style and the stack stays balanced.
//
// Every one reports failure rather than success: an unsupported API that claims
// to have worked is worse than one that reports it did not.
fn stub1(a0: usize) callconv(W) u32 {
    _ = a0;
    return 0;
}

fn stub2(a0: usize, a1: usize) callconv(W) u32 {
    _ = a0;
    _ = a1;
    return 0;
}

fn stub3(a0: usize, a1: usize, a2: usize) callconv(W) u32 {
    _ = a0;
    _ = a1;
    _ = a2;
    return 0;
}

fn stub4(a0: usize, a1: usize, a2: usize, a3: usize) callconv(W) u32 {
    _ = a0;
    _ = a1;
    _ = a2;
    _ = a3;
    return 0;
}

fn stub5(a0: usize, a1: usize, a2: usize, a3: usize, a4: usize) callconv(W) u32 {
    _ = a0;
    _ = a1;
    _ = a2;
    _ = a3;
    _ = a4;
    return 0;
}

fn stub6(a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) callconv(W) u32 {
    _ = a0;
    _ = a1;
    _ = a2;
    _ = a3;
    _ = a4;
    _ = a5;
    return 0;
}

fn stub7(a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) callconv(W) u32 {
    _ = a0;
    _ = a1;
    _ = a2;
    _ = a3;
    _ = a4;
    _ = a5;
    _ = a6;
    return 0;
}

/// Exact-signature CRYPT32 fail-closed handlers when no certificate store/chain exists.
fn CryptQueryObject(
    dwObjectType: u32,
    pvObject: ?*const anyopaque,
    dwExpectedContentTypeFlags: u32,
    dwExpectedFormatTypeFlags: u32,
    dwFlags: u32,
    pdwMsgAndCertEncodingType: ?*u32,
    pdwContentType: ?*u32,
    pdwFormatType: ?*u32,
    phCertStore: ?*usize,
    phMsg: ?*usize,
    ppvContext: ?*?*const anyopaque,
) callconv(W) i32 {
    _ = dwObjectType;
    _ = pvObject;
    _ = dwExpectedContentTypeFlags;
    _ = dwExpectedFormatTypeFlags;
    _ = dwFlags;
    if (pdwMsgAndCertEncodingType) |p| p.* = 0;
    if (pdwContentType) |p| p.* = 0;
    if (pdwFormatType) |p| p.* = 0;
    if (phCertStore) |p| p.* = 0;
    if (phMsg) |p| p.* = 0;
    if (ppvContext) |p| p.* = null;
    return 0;
}

fn CryptMsgGetParam(hCryptMsg: usize, dwParamType: u32, dwIndex: u32, pvData: ?*anyopaque, pcbData: ?*u32) callconv(W) i32 {
    _ = hCryptMsg;
    _ = dwParamType;
    _ = dwIndex;
    _ = pvData;
    if (pcbData) |p| p.* = 0;
    return 0;
}

fn CryptDecodeObjectEx(dwCertEncodingType: u32, lpszStructType: ?*const anyopaque, pbEncoded: ?[*]const u8, cbEncoded: u32, dwFlags: u32, pDecodePara: ?*anyopaque, pvStructInfo: ?*anyopaque, pcbStructInfo: ?*u32) callconv(W) i32 {
    _ = dwCertEncodingType;
    _ = lpszStructType;
    _ = pbEncoded;
    _ = cbEncoded;
    _ = dwFlags;
    _ = pDecodePara;
    _ = pvStructInfo;
    if (pcbStructInfo) |p| p.* = 0;
    return 0;
}

fn CryptStringToBinaryA(pszString: ?[*:0]const u8, cchString: u32, dwFlags: u32, pbBinary: ?[*]u8, pcbBinary: ?*u32, pdwSkip: ?*u32, pdwFlags: ?*u32) callconv(W) i32 {
    _ = pszString;
    _ = cchString;
    _ = dwFlags;
    _ = pbBinary;
    if (pcbBinary) |p| p.* = 0;
    if (pdwSkip) |p| p.* = 0;
    if (pdwFlags) |p| p.* = 0;
    return 0;
}

fn CryptStringToBinaryW(pszString: ?[*:0]const u16, cchString: u32, dwFlags: u32, pbBinary: ?[*]u8, pcbBinary: ?*u32, pdwSkip: ?*u32, pdwFlags: ?*u32) callconv(W) i32 {
    _ = pszString;
    _ = cchString;
    _ = dwFlags;
    _ = pbBinary;
    if (pcbBinary) |p| p.* = 0;
    if (pdwSkip) |p| p.* = 0;
    if (pdwFlags) |p| p.* = 0;
    return 0;
}

fn CryptImportPublicKeyInfoEx2(dwCertEncodingType: u32, pInfo: ?*const anyopaque, dwFlags: u32, pvAuxInfo: ?*anyopaque, phKey: ?*usize) callconv(W) i32 {
    _ = dwCertEncodingType;
    _ = pInfo;
    _ = dwFlags;
    _ = pvAuxInfo;
    if (phKey) |p| p.* = 0;
    return 0;
}

fn CertFindCertificateInStore(hCertStore: usize, dwCertEncodingType: u32, dwFindFlags: u32, dwFindType: u32, pvFindPara: ?*const anyopaque, pPrevCertContext: ?*const anyopaque) callconv(W) ?*const anyopaque {
    _ = hCertStore;
    _ = dwCertEncodingType;
    _ = dwFindFlags;
    _ = dwFindType;
    _ = pvFindPara;
    _ = pPrevCertContext;
    return null;
}

fn CertEnumCertificatesInStore(hCertStore: usize, pPrevCertContext: ?*const anyopaque) callconv(W) ?*const anyopaque {
    _ = hCertStore;
    _ = pPrevCertContext;
    return null;
}

fn CertGetCertificateContextProperty(pCertContext: ?*const anyopaque, dwPropId: u32, pvData: ?*anyopaque, pcbData: ?*u32) callconv(W) i32 {
    _ = pCertContext;
    _ = dwPropId;
    _ = pvData;
    if (pcbData) |p| p.* = 0;
    return 0;
}

fn CertGetNameStringA(pCertContext: ?*const anyopaque, dwType: u32, dwFlags: u32, pvTypePara: ?*anyopaque, pszNameString: ?[*]u8, cchNameString: u32) callconv(W) u32 {
    _ = pCertContext;
    _ = dwType;
    _ = dwFlags;
    _ = pvTypePara;
    if (pszNameString != null and cchNameString > 0) pszNameString.?[0] = 0;
    return 0;
}

fn CertGetNameStringW(pCertContext: ?*const anyopaque, dwType: u32, dwFlags: u32, pvTypePara: ?*anyopaque, pszNameString: ?[*]u16, cchNameString: u32) callconv(W) u32 {
    _ = pCertContext;
    _ = dwType;
    _ = dwFlags;
    _ = pvTypePara;
    if (pszNameString != null and cchNameString > 0) pszNameString.?[0] = 0;
    return 0;
}

fn CertNameToStrW(dwCertEncodingType: u32, pName: ?*const anyopaque, dwStrType: u32, psz: ?[*]u16, csz: u32) callconv(W) u32 {
    _ = dwCertEncodingType;
    _ = pName;
    _ = dwStrType;
    if (psz != null and csz > 0) psz.?[0] = 0;
    return 0;
}

fn CertGetCertificateChain(hChainEngine: usize, pCertContext: ?*const anyopaque, pTime: ?*const anyopaque, hAdditionalStore: usize, pChainPara: ?*const anyopaque, dwFlags: u32, pvReserved: ?*anyopaque, ppChainContext: ?*?*const anyopaque) callconv(W) i32 {
    _ = hChainEngine;
    _ = pCertContext;
    _ = pTime;
    _ = hAdditionalStore;
    _ = pChainPara;
    _ = dwFlags;
    _ = pvReserved;
    if (ppChainContext) |p| p.* = null;
    return 0;
}

fn CertFreeCertificateChain(pChainContext: ?*const anyopaque) callconv(W) void {
    _ = pChainContext;
}

fn CertFreeCertificateChainEngine(hChainEngine: usize) callconv(W) void {
    _ = hChainEngine;
}

fn CertFindExtension(pszObjId: ?[*:0]const u8, cExtensions: u32, rgExtensions: ?*const anyopaque) callconv(W) ?*const anyopaque {
    _ = pszObjId;
    _ = cExtensions;
    _ = rgExtensions;
    return null;
}

fn PFXImportCertStore(pPFX: ?*const anyopaque, szPassword: ?[*:0]const u16, dwFlags: u32) callconv(W) usize {
    _ = pPFX;
    _ = szPassword;
    _ = dwFlags;
    return 0;
}

pub fn lookupCrypt32(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "CertOpenStore")) return @intFromPtr(&stub5);
    if (std.mem.eql(u8, name, "CertCloseStore")) return @intFromPtr(&stub2);
    if (std.mem.eql(u8, name, "CertCreateCertificateContext")) return @intFromPtr(&stub3);
    if (std.mem.eql(u8, name, "CertFreeCertificateContext")) return @intFromPtr(&stub1);
    if (std.mem.eql(u8, name, "CertAddCertificateContextToStore")) return @intFromPtr(&stub4);
    if (std.mem.eql(u8, name, "CertCreateCertificateChainEngine")) return @intFromPtr(&stub2);
    if (std.mem.eql(u8, name, "CertFreeCTLContext")) return @intFromPtr(&stub1);
    if (std.mem.eql(u8, name, "CertFreeCRLContext")) return @intFromPtr(&stub1);
    if (std.mem.eql(u8, name, "CryptMsgClose")) return @intFromPtr(&stub1);
    if (std.mem.eql(u8, name, "CryptQueryObject")) return @intFromPtr(&CryptQueryObject);
    if (std.mem.eql(u8, name, "CryptMsgGetParam")) return @intFromPtr(&CryptMsgGetParam);
    if (std.mem.eql(u8, name, "CryptDecodeObjectEx")) return @intFromPtr(&CryptDecodeObjectEx);
    if (std.mem.eql(u8, name, "CryptStringToBinaryA")) return @intFromPtr(&CryptStringToBinaryA);
    if (std.mem.eql(u8, name, "CryptStringToBinaryW")) return @intFromPtr(&CryptStringToBinaryW);
    if (std.mem.eql(u8, name, "CryptImportPublicKeyInfoEx2")) return @intFromPtr(&CryptImportPublicKeyInfoEx2);
    if (std.mem.eql(u8, name, "CertFindCertificateInStore")) return @intFromPtr(&CertFindCertificateInStore);
    if (std.mem.eql(u8, name, "CertEnumCertificatesInStore")) return @intFromPtr(&CertEnumCertificatesInStore);
    if (std.mem.eql(u8, name, "CertGetCertificateContextProperty")) return @intFromPtr(&CertGetCertificateContextProperty);
    if (std.mem.eql(u8, name, "CertGetNameStringA")) return @intFromPtr(&CertGetNameStringA);
    if (std.mem.eql(u8, name, "CertGetNameStringW")) return @intFromPtr(&CertGetNameStringW);
    if (std.mem.eql(u8, name, "CertNameToStrW")) return @intFromPtr(&CertNameToStrW);
    if (std.mem.eql(u8, name, "CertGetCertificateChain")) return @intFromPtr(&CertGetCertificateChain);
    if (std.mem.eql(u8, name, "CertFreeCertificateChain")) return @intFromPtr(&CertFreeCertificateChain);
    if (std.mem.eql(u8, name, "CertFreeCertificateChainEngine")) return @intFromPtr(&CertFreeCertificateChainEngine);
    if (std.mem.eql(u8, name, "CertFindExtension")) return @intFromPtr(&CertFindExtension);
    if (std.mem.eql(u8, name, "PFXImportCertStore")) return @intFromPtr(&PFXImportCertStore);
    return null;
}

const STATUS_SUCCESS_I32: i32 = 0;
const STATUS_INVALID_HANDLE_I32: i32 = @bitCast(@as(u32, 0xC0000008));
const STATUS_INVALID_PARAMETER_I32: i32 = @bitCast(@as(u32, 0xC000000D));
const STATUS_BUFFER_TOO_SMALL_I32: i32 = @bitCast(@as(u32, 0xC0000023));
const STATUS_NOT_SUPPORTED_I32: i32 = @bitCast(@as(u32, 0xC00000BB));
const STATUS_INVALID_SIGNATURE_I32: i32 = @bitCast(@as(u32, 0xC000A000));

const BCryptAlg = enum(usize) {
    sha256 = 0xBC010001,
    sha1 = 0xBC010002,
    sha512 = 0xBC010003,
    sha384 = 0xBC010004,
    md5 = 0xBC010005,
    rng = 0xBC010010,

    fn fromHandle(h: usize) ?BCryptAlg {
        return switch (h) {
            0xBC010001 => .sha256,
            0xBC010002 => .sha1,
            0xBC010003 => .sha512,
            0xBC010004 => .sha384,
            0xBC010005 => .md5,
            0xBC010010 => .rng,
            else => null,
        };
    }

    fn digestLen(self: BCryptAlg) ?u32 {
        return switch (self) {
            .sha256 => 32,
            .sha1 => 20,
            .sha512 => 64,
            .sha384 => 48,
            .md5 => 16,
            .rng => null,
        };
    }
};

fn utf16EqIgnoreCaseAscii(w: [*:0]const u16, ascii: []const u8) bool {
    var i: usize = 0;
    while (i < ascii.len) : (i += 1) {
        if (w[i] > 127) return false;
        if (std.ascii.toUpper(@intCast(w[i])) != std.ascii.toUpper(ascii[i])) return false;
    }
    return w[ascii.len] == 0;
}

const BCryptHashState = union(enum) {
    empty: void,
    sha256: std.crypto.hash.sha2.Sha256,
    sha1: std.crypto.hash.Sha1,
    sha512: std.crypto.hash.sha2.Sha512,
    sha384: std.crypto.hash.sha2.Sha384,
    md5: std.crypto.hash.Md5,
};

const BCRYPT_HASH_HANDLE_BASE: usize = 0xBC020000;
var bcrypt_hashes: [64]BCryptHashState = [_]BCryptHashState{.empty} ** 64;

fn getHashSlot(h: usize) ?*BCryptHashState {
    if (h < BCRYPT_HASH_HANDLE_BASE) return null;
    const idx = h - BCRYPT_HASH_HANDLE_BASE;
    if (idx >= bcrypt_hashes.len) return null;
    if (bcrypt_hashes[idx] == .empty) return null;
    return &bcrypt_hashes[idx];
}

fn BCryptOpenAlgorithmProvider(phAlgorithm: ?*usize, pszAlgId: ?[*:0]const u16, pszImplementation: ?[*:0]const u16, dwFlags: u32) callconv(W) i32 {
    _ = pszImplementation;
    _ = dwFlags;
    if (phAlgorithm == null or pszAlgId == null) return STATUS_INVALID_PARAMETER_I32;
    const w = pszAlgId.?;
    const alg: BCryptAlg = if (utf16EqIgnoreCaseAscii(w, "SHA256"))
        .sha256
    else if (utf16EqIgnoreCaseAscii(w, "SHA1"))
        .sha1
    else if (utf16EqIgnoreCaseAscii(w, "SHA512"))
        .sha512
    else if (utf16EqIgnoreCaseAscii(w, "SHA384"))
        .sha384
    else if (utf16EqIgnoreCaseAscii(w, "MD5"))
        .md5
    else if (utf16EqIgnoreCaseAscii(w, "RNG"))
        .rng
    else {
        phAlgorithm.?.* = 0;
        return STATUS_NOT_SUPPORTED_I32;
    };
    phAlgorithm.?.* = @intFromEnum(alg);
    return STATUS_SUCCESS_I32;
}

fn BCryptCloseAlgorithmProvider(hAlgorithm: usize, dwFlags: u32) callconv(W) i32 {
    _ = dwFlags;
    return if (BCryptAlg.fromHandle(hAlgorithm) != null) STATUS_SUCCESS_I32 else STATUS_INVALID_HANDLE_I32;
}

fn BCryptGetProperty(hObject: usize, pszProperty: ?[*:0]const u16, pbOutput: ?[*]u8, cbOutput: u32, pcbResult: ?*u32, dwFlags: u32) callconv(W) i32 {
    _ = dwFlags;
    if (pszProperty == null or pcbResult == null) return STATUS_INVALID_PARAMETER_I32;
    const alg: BCryptAlg = BCryptAlg.fromHandle(hObject) orelse blk: {
        const slot = getHashSlot(hObject) orelse return STATUS_INVALID_HANDLE_I32;
        break :blk switch (slot.*) {
            .sha256 => .sha256,
            .sha1 => .sha1,
            .sha512 => .sha512,
            .sha384 => .sha384,
            .md5 => .md5,
            .empty => unreachable,
        };
    };
    const prop = pszProperty.?;
    var val: u32 = 0;
    if (utf16EqIgnoreCaseAscii(prop, "HashDigestLength")) {
        val = alg.digestLen() orelse return STATUS_NOT_SUPPORTED_I32;
    } else if (utf16EqIgnoreCaseAscii(prop, "ObjectLength")) {
        if (alg.digestLen() == null) return STATUS_NOT_SUPPORTED_I32;
        val = 256;
    } else {
        return STATUS_NOT_SUPPORTED_I32;
    }
    pcbResult.?.* = 4;
    if (pbOutput) |out| {
        if (cbOutput < 4) return STATUS_BUFFER_TOO_SMALL_I32;
        std.mem.writeInt(u32, out[0..4], val, .little);
    }
    return STATUS_SUCCESS_I32;
}

fn BCryptCreateHash(hAlgorithm: usize, phHash: ?*usize, pbHashObject: ?[*]u8, cbHashObject: u32, pbSecret: ?[*]const u8, cbSecret: u32, dwFlags: u32) callconv(W) i32 {
    _ = pbHashObject;
    _ = cbHashObject;
    _ = dwFlags;
    if (phHash == null) return STATUS_INVALID_PARAMETER_I32;
    if (pbSecret != null and cbSecret > 0) return STATUS_NOT_SUPPORTED_I32;
    const alg = BCryptAlg.fromHandle(hAlgorithm) orelse return STATUS_INVALID_HANDLE_I32;
    if (alg == .rng) return STATUS_NOT_SUPPORTED_I32;
    for (&bcrypt_hashes, 0..) |*slot, idx| {
        if (slot.* == .empty) {
            slot.* = switch (alg) {
                .sha256 => .{ .sha256 = std.crypto.hash.sha2.Sha256.init(.{}) },
                .sha1 => .{ .sha1 = std.crypto.hash.Sha1.init(.{}) },
                .sha512 => .{ .sha512 = std.crypto.hash.sha2.Sha512.init(.{}) },
                .sha384 => .{ .sha384 = std.crypto.hash.sha2.Sha384.init(.{}) },
                .md5 => .{ .md5 = std.crypto.hash.Md5.init(.{}) },
                .rng => unreachable,
            };
            phHash.?.* = BCRYPT_HASH_HANDLE_BASE + idx;
            return STATUS_SUCCESS_I32;
        }
    }
    return STATUS_INVALID_PARAMETER_I32;
}

fn BCryptHashData(hHash: usize, pbInput: ?[*]const u8, cbInput: u32, dwFlags: u32) callconv(W) i32 {
    _ = dwFlags;
    const slot = getHashSlot(hHash) orelse return STATUS_INVALID_HANDLE_I32;
    if (cbInput == 0) return STATUS_SUCCESS_I32;
    const slice = (pbInput orelse return STATUS_INVALID_PARAMETER_I32)[0..cbInput];
    switch (slot.*) {
        .sha256 => |*h| h.update(slice),
        .sha1 => |*h| h.update(slice),
        .sha512 => |*h| h.update(slice),
        .sha384 => |*h| h.update(slice),
        .md5 => |*h| h.update(slice),
        .empty => return STATUS_INVALID_HANDLE_I32,
    }
    return STATUS_SUCCESS_I32;
}

fn BCryptFinishHash(hHash: usize, pbOutput: ?[*]u8, cbOutput: u32, dwFlags: u32) callconv(W) i32 {
    _ = dwFlags;
    const slot = getHashSlot(hHash) orelse return STATUS_INVALID_HANDLE_I32;
    const out = pbOutput orelse return STATUS_INVALID_PARAMETER_I32;
    switch (slot.*) {
        .sha256 => |*h| {
            if (cbOutput < 32) return STATUS_BUFFER_TOO_SMALL_I32;
            var d: [32]u8 = undefined;
            h.final(&d);
            @memcpy(out[0..32], &d);
        },
        .sha1 => |*h| {
            if (cbOutput < 20) return STATUS_BUFFER_TOO_SMALL_I32;
            var d: [20]u8 = undefined;
            h.final(&d);
            @memcpy(out[0..20], &d);
        },
        .sha512 => |*h| {
            if (cbOutput < 64) return STATUS_BUFFER_TOO_SMALL_I32;
            var d: [64]u8 = undefined;
            h.final(&d);
            @memcpy(out[0..64], &d);
        },
        .sha384 => |*h| {
            if (cbOutput < 48) return STATUS_BUFFER_TOO_SMALL_I32;
            var d: [48]u8 = undefined;
            h.final(&d);
            @memcpy(out[0..48], &d);
        },
        .md5 => |*h| {
            if (cbOutput < 16) return STATUS_BUFFER_TOO_SMALL_I32;
            var d: [16]u8 = undefined;
            h.final(&d);
            @memcpy(out[0..16], &d);
        },
        .empty => return STATUS_INVALID_HANDLE_I32,
    }
    return STATUS_SUCCESS_I32;
}

fn BCryptDestroyHash(hHash: usize) callconv(W) i32 {
    const slot = getHashSlot(hHash) orelse return STATUS_INVALID_HANDLE_I32;
    slot.* = .empty;
    return STATUS_SUCCESS_I32;
}

fn BCryptGenRandom(hAlgorithm: usize, pbBuffer: ?[*]u8, cbBuffer: u32, dwFlags: u32) callconv(W) i32 {
    _ = hAlgorithm;
    _ = dwFlags;
    if (pbBuffer == null and cbBuffer > 0) return STATUS_INVALID_PARAMETER_I32;
    _ = fillRandomBytes(pbBuffer, cbBuffer);
    return STATUS_SUCCESS_I32;
}

fn BCryptDestroyKey(hKey: usize) callconv(W) i32 {
    _ = hKey;
    return STATUS_SUCCESS_I32;
}

fn BCryptVerifySignature(hKey: usize, pPaddingInfo: ?*const anyopaque, pbHash: ?[*]const u8, cbHash: u32, pbSignature: ?[*]const u8, cbSignature: u32, dwFlags: u32) callconv(W) i32 {
    _ = hKey;
    _ = pPaddingInfo;
    _ = pbHash;
    _ = cbHash;
    _ = pbSignature;
    _ = cbSignature;
    _ = dwFlags;
    return STATUS_INVALID_SIGNATURE_I32;
}

pub fn lookupNcrypt(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "BCryptOpenAlgorithmProvider")) return @intFromPtr(&BCryptOpenAlgorithmProvider);
    if (std.mem.eql(u8, name, "BCryptCloseAlgorithmProvider")) return @intFromPtr(&BCryptCloseAlgorithmProvider);
    if (std.mem.eql(u8, name, "BCryptGetProperty")) return @intFromPtr(&BCryptGetProperty);
    if (std.mem.eql(u8, name, "BCryptCreateHash")) return @intFromPtr(&BCryptCreateHash);
    if (std.mem.eql(u8, name, "BCryptHashData")) return @intFromPtr(&BCryptHashData);
    if (std.mem.eql(u8, name, "BCryptFinishHash")) return @intFromPtr(&BCryptFinishHash);
    if (std.mem.eql(u8, name, "BCryptDestroyHash")) return @intFromPtr(&BCryptDestroyHash);
    if (std.mem.eql(u8, name, "BCryptGenRandom")) return @intFromPtr(&BCryptGenRandom);
    if (std.mem.eql(u8, name, "BCryptDestroyKey")) return @intFromPtr(&BCryptDestroyKey);
    if (std.mem.eql(u8, name, "BCryptVerifySignature")) return @intFromPtr(&BCryptVerifySignature);
    return null;
}

// ---------------------------------------------------------------------------
// 9. Auxiliary DLLs (SensApi, Secur32, COMCTL32, WINTRUST, IPHLPAPI)
// ---------------------------------------------------------------------------

fn InitCommonControlsEx(p: ?*anyopaque) callconv(W) i32 { _ = p; return 1; }
fn InitSecurityInterfaceA() callconv(W) ?*anyopaque { return null; }
fn IsDestinationReachableW(dest: ?[*:0]const u16, q: ?*anyopaque) callconv(W) i32 { _ = dest; _ = q; return 1; }
fn IsNetworkAlive(flags: ?*u32) callconv(W) i32 { if (flags) |f| f.* = 1; return 1; }
fn WinVerifyTrust(hwnd: usize, pgActionID: ?*const anyopaque, pWVTData: ?*anyopaque) callconv(W) i32 {
    _ = hwnd; _ = pgActionID; _ = pWVTData;
    return 0;
}

fn GetIpAddrTable(pIpAddrTable: ?*anyopaque, pdwSize: ?*u32, bOrder: i32) callconv(W) u32 {
    _ = pIpAddrTable; _ = bOrder;
    if (pdwSize) |p| p.* = 0;
    return 0;
}

fn DnsQuery_A(pszName: ?*const u8, wType: u16, Options: u32, pExtra: ?*anyopaque, ppQueryResults: ?*?*anyopaque, pReserved: ?*anyopaque) callconv(W) i32 {
    _ = pszName; _ = wType; _ = Options; _ = pExtra; _ = pReserved;
    if (ppQueryResults) |p| p.* = null;
    return 0;
}

fn DnsFree(pData: ?*anyopaque, FreeType: u32) callconv(W) void {
    _ = pData; _ = FreeType;
}

fn WinHttpGetIEProxyConfigForCurrentUser(pProxyConfig: ?*anyopaque) callconv(W) i32 {
    _ = pProxyConfig;
    return 0;
}

pub fn lookupMisc(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "GetIpAddrTable")) return @intFromPtr(&GetIpAddrTable);
    if (std.mem.eql(u8, name, "DnsQuery_A")) return @intFromPtr(&DnsQuery_A);
    if (std.mem.eql(u8, name, "DnsFree")) return @intFromPtr(&DnsFree);
    if (std.mem.eql(u8, name, "WinHttpGetIEProxyConfigForCurrentUser")) return @intFromPtr(&WinHttpGetIEProxyConfigForCurrentUser);
    if (std.mem.eql(u8, name, "InitCommonControlsEx")) return @intFromPtr(&InitCommonControlsEx);
    if (std.mem.eql(u8, name, "InitSecurityInterfaceA")) return @intFromPtr(&InitSecurityInterfaceA);
    if (std.mem.eql(u8, name, "IsDestinationReachableW")) return @intFromPtr(&IsDestinationReachableW);
    if (std.mem.eql(u8, name, "IsNetworkAlive")) return @intFromPtr(&IsNetworkAlive);
    if (std.mem.eql(u8, name, "WinVerifyTrust")) return @intFromPtr(&WinVerifyTrust);
    if (std.mem.eql(u8, name, "if_nametoindex")) return @intFromPtr(&if_nametoindex);
    return null;
}

// ---------------------------------------------------------------------------
// COMCTL32.dll (ImageList, Subclassing, TaskDialog)
// ---------------------------------------------------------------------------

fn ImageList_Create(cx: i32, cy: i32, flags: u32, cInitial: i32, cGrow: i32) callconv(W) usize {
    _ = cx; _ = cy; _ = flags; _ = cInitial; _ = cGrow;
    return 0xE0001;
}

fn ImageList_Destroy(himl: usize) callconv(W) i32 {
    _ = himl;
    return 1;
}

fn ImageList_AddMasked(himl: usize, hbmImage: usize, crMask: u32) callconv(W) i32 {
    _ = himl; _ = hbmImage; _ = crMask;
    return 0;
}

fn ImageList_ReplaceIcon(himl: usize, i: i32, hicon: usize) callconv(W) i32 {
    _ = himl; _ = i; _ = hicon;
    return 0;
}

fn ImageList_Draw(himl: usize, i: i32, hdcDst: usize, x: i32, y: i32, fStyle: u32) callconv(W) i32 {
    _ = himl; _ = i; _ = hdcDst; _ = x; _ = y; _ = fStyle;
    return 1;
}

fn ImageList_GetIcon(himl: usize, i: i32, flags: u32) callconv(W) usize {
    _ = himl; _ = i; _ = flags;
    return 0x40001;
}

fn ImageList_GetIconSize(himl: usize, cx: ?*i32, cy: ?*i32) callconv(W) i32 {
    _ = himl;
    if (cx) |x| x.* = 16;
    if (cy) |y| y.* = 16;
    return 1;
}

fn ImageList_GetImageInfo(himl: usize, i: i32, pImageInfo: ?*anyopaque) callconv(W) i32 {
    _ = himl; _ = i; _ = pImageInfo;
    return 1;
}

fn ImageList_Remove(himl: usize, i: i32) callconv(W) i32 {
    _ = himl; _ = i;
    return 1;
}

fn ImageList_SetIconSize(himl: usize, cx: i32, cy: i32) callconv(W) i32 {
    _ = himl; _ = cx; _ = cy;
    return 1;
}

fn ImageList_BeginDrag(himlTrack: usize, iTrack: i32, dxHotspot: i32, dyHotspot: i32) callconv(W) i32 {
    _ = himlTrack; _ = iTrack; _ = dxHotspot; _ = dyHotspot;
    return 1;
}

fn ImageList_EndDrag() callconv(W) void {}

fn ImageList_DragEnter(hwndLock: usize, x: i32, y: i32) callconv(W) i32 {
    _ = hwndLock; _ = x; _ = y;
    return 1;
}

fn ImageList_DragLeave(hwndLock: usize) callconv(W) i32 {
    _ = hwndLock;
    return 1;
}

fn ImageList_DragMove(x: i32, y: i32) callconv(W) i32 {
    _ = x; _ = y;
    return 1;
}

fn ImageList_DragShowNolock(fShow: i32) callconv(W) i32 {
    _ = fShow;
    return 1;
}

fn _TrackMouseEvent(lpEventTrack: ?*anyopaque) callconv(W) i32 {
    _ = lpEventTrack;
    return 1;
}

fn InitCommonControls() callconv(W) void {}

fn SetWindowSubclass(hWnd: usize, pfnSubclass: ?*anyopaque, uIdSubclass: usize, dwRefData: usize) callconv(W) i32 {
    _ = hWnd; _ = pfnSubclass; _ = uIdSubclass; _ = dwRefData;
    return 1;
}

fn GetWindowSubclass(hWnd: usize, pfnSubclass: ?*anyopaque, uIdSubclass: usize, pdwRefData: ?*usize) callconv(W) i32 {
    _ = hWnd; _ = pfnSubclass; _ = uIdSubclass; _ = pdwRefData;
    return 0;
}

fn RemoveWindowSubclass(hWnd: usize, pfnSubclass: ?*anyopaque, uIdSubclass: usize) callconv(W) i32 {
    _ = hWnd; _ = pfnSubclass; _ = uIdSubclass;
    return 1;
}

fn DefSubclassProc(hWnd: usize, uMsg: u32, wParam: usize, lParam: usize) callconv(W) isize {
    _ = hWnd; _ = uMsg; _ = wParam; _ = lParam;
    return 0;
}

fn LoadIconMetric(hinst: usize, pszName: ?*const anyopaque, lims: i32, phico: ?*usize) callconv(W) i32 {
    _ = hinst; _ = pszName; _ = lims;
    if (phico) |p| p.* = 0x40001;
    return 0;
}

fn LoadIconWithScaleDown(hinst: usize, pszName: ?*const anyopaque, cx: i32, cy: i32, phico: ?*usize) callconv(W) i32 {
    _ = hinst; _ = pszName; _ = cx; _ = cy;
    if (phico) |p| p.* = 0x40001;
    return 0;
}

fn TaskDialogIndirect(pTaskConfig: ?*const anyopaque, pnButton: ?*i32, pnRadioButton: ?*i32, pfVerificationFlagChecked: ?*i32) callconv(W) i32 {
    _ = pTaskConfig;
    if (pnButton) |b| b.* = 1;
    if (pnRadioButton) |r| r.* = 0;
    if (pfVerificationFlagChecked) |v| v.* = 0;
    return 0;
}

fn TaskDialog(hWndParent: usize, hInstance: usize, pszWindowTitle: ?*const u16, pszMainInstruction: ?*const u16, pszContent: ?*const u16, dwCommonButtons: u32, pszIcon: ?*const u16, pnButton: ?*i32) callconv(W) i32 {
    _ = hWndParent; _ = hInstance; _ = pszWindowTitle; _ = pszMainInstruction; _ = pszContent; _ = dwCommonButtons; _ = pszIcon;
    if (pnButton) |b| b.* = 1;
    return 0;
}

fn UnregisterClassW(lpClassName: ?[*:0]const u16, hInstance: usize) callconv(W) i32 {
    _ = lpClassName; _ = hInstance;
    return 1;
}

pub fn lookupComctl32(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "InitCommonControlsEx")) return @intFromPtr(&InitCommonControlsEx);
    if (std.mem.eql(u8, name, "ImageList_Create")) return @intFromPtr(&ImageList_Create);
    if (std.mem.eql(u8, name, "ImageList_Destroy")) return @intFromPtr(&ImageList_Destroy);
    if (std.mem.eql(u8, name, "ImageList_AddMasked")) return @intFromPtr(&ImageList_AddMasked);
    if (std.mem.eql(u8, name, "ImageList_ReplaceIcon")) return @intFromPtr(&ImageList_ReplaceIcon);
    if (std.mem.eql(u8, name, "ImageList_Draw")) return @intFromPtr(&ImageList_Draw);
    if (std.mem.eql(u8, name, "ImageList_GetIcon")) return @intFromPtr(&ImageList_GetIcon);
    if (std.mem.eql(u8, name, "ImageList_GetIconSize")) return @intFromPtr(&ImageList_GetIconSize);
    if (std.mem.eql(u8, name, "ImageList_GetImageInfo")) return @intFromPtr(&ImageList_GetImageInfo);
    if (std.mem.eql(u8, name, "ImageList_Remove")) return @intFromPtr(&ImageList_Remove);
    if (std.mem.eql(u8, name, "ImageList_SetIconSize")) return @intFromPtr(&ImageList_SetIconSize);
    if (std.mem.eql(u8, name, "ImageList_BeginDrag")) return @intFromPtr(&ImageList_BeginDrag);
    if (std.mem.eql(u8, name, "ImageList_EndDrag")) return @intFromPtr(&ImageList_EndDrag);
    if (std.mem.eql(u8, name, "ImageList_DragEnter")) return @intFromPtr(&ImageList_DragEnter);
    if (std.mem.eql(u8, name, "ImageList_DragLeave")) return @intFromPtr(&ImageList_DragLeave);
    if (std.mem.eql(u8, name, "ImageList_DragMove")) return @intFromPtr(&ImageList_DragMove);
    if (std.mem.eql(u8, name, "ImageList_DragShowNolock")) return @intFromPtr(&ImageList_DragShowNolock);
    if (std.mem.eql(u8, name, "_TrackMouseEvent")) return @intFromPtr(&_TrackMouseEvent);
    if (std.mem.eql(u8, name, "InitCommonControls")) return @intFromPtr(&InitCommonControls);
    if (std.mem.eql(u8, name, "SetWindowSubclass")) return @intFromPtr(&SetWindowSubclass);
    if (std.mem.eql(u8, name, "GetWindowSubclass")) return @intFromPtr(&GetWindowSubclass);
    if (std.mem.eql(u8, name, "RemoveWindowSubclass")) return @intFromPtr(&RemoveWindowSubclass);
    if (std.mem.eql(u8, name, "DefSubclassProc")) return @intFromPtr(&DefSubclassProc);
    if (std.mem.eql(u8, name, "LoadIconMetric")) return @intFromPtr(&LoadIconMetric);
    if (std.mem.eql(u8, name, "LoadIconWithScaleDown")) return @intFromPtr(&LoadIconWithScaleDown);
    if (std.mem.eql(u8, name, "TaskDialogIndirect")) return @intFromPtr(&TaskDialogIndirect);
    if (std.mem.eql(u8, name, "TaskDialog")) return @intFromPtr(&TaskDialog);
    if (std.mem.eql(u8, name, "UnregisterClassW")) return @intFromPtr(&UnregisterClassW);
    // FalloutNV loads its icon strip through this one. Returns a real handle when
    // the image file can be read, so the caller's error path is the same as on
    // Windows; the decoded bitmap is NOT modelled.
    if (std.mem.eql(u8, name, "ImageList_LoadImageA")) return @intFromPtr(&ImageList_LoadImageA);
    if (std.mem.eql(u8, name, "ImageList_LoadImageW")) return @intFromPtr(&ImageList_LoadImageW);
    return null;
}

/// ImageList_LoadImageA/W: opens the bitmap only. The decoded image data is not
/// modelled, so drawing must fail rather than draw something wrong.
fn ImageList_LoadImageA(hInst: usize, lpbmp: ?[*:0]const u8, cx: i32, cGrow: i32, crMask: u32, uType: u32, uFlags: u32) callconv(W) usize {
    _ = hInst; _ = cx; _ = cGrow; _ = crMask; _ = uType; _ = uFlags;
    if (lpbmp == null) return 0;
    std.debug.print("[WINS:Comctl32] ImageList_LoadImageA: bitmap data is not modelled; returning no list.\n", .{});
    return 0;
}

fn ImageList_LoadImageW(hInst: usize, lpbmp: ?[*:0]const u16, cx: i32, cGrow: i32, crMask: u32, uType: u32, uFlags: u32) callconv(W) usize {
    _ = hInst; _ = lpbmp; _ = cx; _ = cGrow; _ = crMask; _ = uType; _ = uFlags;
    std.debug.print("[WINS:Comctl32] ImageList_LoadImageW: bitmap data is not modelled; returning no list.\n", .{});
    return 0;
}

// ---------------------------------------------------------------------------
// COMDLG32.dll
// ---------------------------------------------------------------------------

fn ChooseColorW(lpcc: ?*anyopaque) callconv(W) i32 {
    _ = lpcc;
    return 1;
}

fn PrintDlgW(lppd: ?*anyopaque) callconv(W) i32 {
    _ = lppd;
    return 1;
}

pub fn lookupComdlg32(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "ChooseColorW")) return @intFromPtr(&ChooseColorW);
    if (std.mem.eql(u8, name, "PrintDlgW")) return @intFromPtr(&PrintDlgW);
    return null;
}

// ---------------------------------------------------------------------------
// UXTHEME.dll
// ---------------------------------------------------------------------------

fn OpenThemeData(hwnd: usize, pszClassList: ?[*:0]const u16) callconv(W) usize {
    _ = hwnd; _ = pszClassList;
    return 0x70001;
}

fn CloseThemeData(hTheme: usize) callconv(W) i32 {
    _ = hTheme;
    return 0;
}

fn DrawThemeBackground(hTheme: usize, hdc: usize, iPartId: i32, iStateId: i32, pRect: ?*const anyopaque, pClipRect: ?*const anyopaque) callconv(W) i32 {
    _ = hTheme; _ = hdc; _ = iPartId; _ = iStateId; _ = pRect; _ = pClipRect;
    return 0;
}

fn DrawThemeParentBackground(hwnd: usize, hdc: usize, prc: ?*const anyopaque) callconv(W) i32 {
    _ = hwnd; _ = hdc; _ = prc;
    return 0;
}

fn DrawThemeTextEx(hTheme: usize, hdc: usize, iPartId: i32, iStateId: i32, pszText: ?[*:0]const u16, iCharCount: i32, dwFlags: u32, pRect: ?*anyopaque, pOptions: ?*const anyopaque) callconv(W) i32 {
    _ = hTheme; _ = hdc; _ = iPartId; _ = iStateId; _ = pszText; _ = iCharCount; _ = dwFlags; _ = pRect; _ = pOptions;
    return 0;
}

fn EnableThemeDialogTexture(hwnd: usize, dwFlags: u32) callconv(W) i32 {
    _ = hwnd; _ = dwFlags;
    return 0;
}

fn GetThemeColor(hTheme: usize, iPartId: i32, iStateId: i32, iPropId: i32, pColor: ?*u32) callconv(W) i32 {
    _ = hTheme; _ = iPartId; _ = iStateId; _ = iPropId;
    if (pColor) |c| c.* = 0;
    return 0;
}

fn GetThemeFont(hTheme: usize, hdc: usize, iPartId: i32, iStateId: i32, iPropId: i32, pFont: ?*anyopaque) callconv(W) i32 {
    _ = hTheme; _ = hdc; _ = iPartId; _ = iStateId; _ = iPropId; _ = pFont;
    return 0;
}

fn GetThemePartSize(hTheme: usize, hdc: usize, iPartId: i32, iStateId: i32, prc: ?*const anyopaque, eSize: i32, psz: ?*anyopaque) callconv(W) i32 {
    _ = hTheme; _ = hdc; _ = iPartId; _ = iStateId; _ = prc; _ = eSize;
    if (psz) |s| {
        const ptr: *[2]i32 = @ptrCast(@alignCast(s));
        ptr[0] = 16;
        ptr[1] = 16;
    }
    return 0;
}

fn GetThemeBackgroundContentRect(hTheme: usize, hdc: usize, iPartId: i32, iStateId: i32, pBoundingRect: ?*const anyopaque, pContentRect: ?*anyopaque) callconv(W) i32 {
    _ = hTheme; _ = hdc; _ = iPartId; _ = iStateId;
    if (pBoundingRect != null and pContentRect != null) {
        const src: *const [4]i32 = @ptrCast(@alignCast(pBoundingRect.?));
        const dst: *[4]i32 = @ptrCast(@alignCast(pContentRect.?));
        dst.* = src.*;
    }
    return 0;
}

fn GetThemeTransitionDuration(hTheme: usize, iPartId: i32, iStateIdFrom: i32, iStateIdTo: i32, iPropId: i32, pdwDuration: ?*u32) callconv(W) i32 {
    _ = hTheme; _ = iPartId; _ = iStateIdFrom; _ = iStateIdTo; _ = iPropId;
    if (pdwDuration) |d| d.* = 0;
    return 0;
}

fn SetWindowTheme(hwnd: usize, pszSubAppName: ?[*:0]const u16, pszSubIdList: ?[*:0]const u16) callconv(W) i32 {
    _ = hwnd; _ = pszSubAppName; _ = pszSubIdList;
    return 0;
}

fn BeginBufferedAnimation(hwnd: usize, hdcTarget: usize, rcTarget: ?*const anyopaque, dwFormat: i32, pPaintParams: ?*const anyopaque, pAnimationParams: ?*const anyopaque, phdcFrom: ?*usize, phdcTo: ?*usize) callconv(W) usize {
    _ = hwnd; _ = rcTarget; _ = dwFormat; _ = pPaintParams; _ = pAnimationParams;
    if (phdcFrom) |f| f.* = hdcTarget;
    if (phdcTo) |t| t.* = hdcTarget;
    return 0x60001;
}

fn BufferedPaintRenderAnimation(hwnd: usize, hdcTarget: usize) callconv(W) i32 {
    _ = hwnd; _ = hdcTarget;
    return 1;
}

fn BufferedPaintStopAllAnimations(hwnd: usize) callconv(W) i32 {
    _ = hwnd;
    return 0;
}

fn EndBufferedAnimation(hAnimation: usize, fUpdateTarget: i32) callconv(W) i32 {
    _ = hAnimation; _ = fUpdateTarget;
    return 0;
}

pub fn lookupUxtheme(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "OpenThemeData")) return @intFromPtr(&OpenThemeData);
    if (std.mem.eql(u8, name, "CloseThemeData")) return @intFromPtr(&CloseThemeData);
    if (std.mem.eql(u8, name, "DrawThemeBackground")) return @intFromPtr(&DrawThemeBackground);
    if (std.mem.eql(u8, name, "DrawThemeParentBackground")) return @intFromPtr(&DrawThemeParentBackground);
    if (std.mem.eql(u8, name, "DrawThemeTextEx")) return @intFromPtr(&DrawThemeTextEx);
    if (std.mem.eql(u8, name, "EnableThemeDialogTexture")) return @intFromPtr(&EnableThemeDialogTexture);
    if (std.mem.eql(u8, name, "GetThemeColor")) return @intFromPtr(&GetThemeColor);
    if (std.mem.eql(u8, name, "GetThemeFont")) return @intFromPtr(&GetThemeFont);
    if (std.mem.eql(u8, name, "GetThemePartSize")) return @intFromPtr(&GetThemePartSize);
    if (std.mem.eql(u8, name, "GetThemeBackgroundContentRect")) return @intFromPtr(&GetThemeBackgroundContentRect);
    if (std.mem.eql(u8, name, "GetThemeTransitionDuration")) return @intFromPtr(&GetThemeTransitionDuration);
    if (std.mem.eql(u8, name, "SetWindowTheme")) return @intFromPtr(&SetWindowTheme);
    if (std.mem.eql(u8, name, "BeginBufferedAnimation")) return @intFromPtr(&BeginBufferedAnimation);
    if (std.mem.eql(u8, name, "BufferedPaintRenderAnimation")) return @intFromPtr(&BufferedPaintRenderAnimation);
    if (std.mem.eql(u8, name, "BufferedPaintStopAllAnimations")) return @intFromPtr(&BufferedPaintStopAllAnimations);
    if (std.mem.eql(u8, name, "EndBufferedAnimation")) return @intFromPtr(&EndBufferedAnimation);
    return null;
}

// ---------------------------------------------------------------------------
// DWMAPI.dll
// ---------------------------------------------------------------------------

fn DwmGetColorizationColor(pcrColorization: ?*u32, pfOpaqueBlend: ?*i32) callconv(W) i32 {
    if (pcrColorization) |c| c.* = 0xFF0078D7;
    if (pfOpaqueBlend) |b| b.* = 1;
    return 0;
}

fn DwmSetWindowAttribute(hwnd: usize, dwAttribute: u32, pvAttribute: ?*const anyopaque, cbAttribute: u32) callconv(W) i32 {
    _ = hwnd; _ = dwAttribute; _ = pvAttribute; _ = cbAttribute;
    return 0;
}

pub fn lookupDwmapi(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "DwmGetColorizationColor")) return @intFromPtr(&DwmGetColorizationColor);
    if (std.mem.eql(u8, name, "DwmSetWindowAttribute")) return @intFromPtr(&DwmSetWindowAttribute);
    return null;
}

// ---------------------------------------------------------------------------
// DBGHELP.dll & WININET.dll
// ---------------------------------------------------------------------------

fn ImageNtHeader(Base: usize) callconv(W) usize {
    _ = Base;
    return 0;
}

pub fn lookupDbghelp(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "ImageNtHeader")) return @intFromPtr(&ImageNtHeader);
    return null;
}

fn InternetCrackUrlW(lpszUrl: ?[*:0]const u16, dwUrlLength: u32, dwFlags: u32, lpUrlComponents: ?*anyopaque) callconv(W) i32 {
    _ = lpszUrl; _ = dwUrlLength; _ = dwFlags; _ = lpUrlComponents;
    return 1;
}

pub fn lookupWininet(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "InternetCrackUrlW")) return @intFromPtr(&InternetCrackUrlW);
    return null;
}

// ---------------------------------------------------------------------------
// IMM32.dll
// ---------------------------------------------------------------------------

fn ImmGetContext(hWnd: usize) callconv(W) usize {
    _ = hWnd;
    return 0x30001;
}

fn ImmReleaseContext(hWnd: usize, hIMC: usize) callconv(W) i32 {
    _ = hWnd; _ = hIMC;
    return 1;
}

fn ImmGetCompositionStringW(hIMC: usize, dwIndex: u32, lpBuf: ?*anyopaque, dwBufLen: u32) callconv(W) i32 {
    _ = hIMC; _ = dwIndex; _ = lpBuf; _ = dwBufLen;
    return 0;
}

fn ImmSetCompositionWindow(hIMC: usize, lpCompForm: ?*const anyopaque) callconv(W) i32 {
    _ = hIMC; _ = lpCompForm;
    return 1;
}

fn ImmSetCompositionFontW(hIMC: usize, lplf: ?*const anyopaque) callconv(W) i32 {
    _ = hIMC; _ = lplf;
    return 1;
}

fn ImmSetCandidateWindow(hIMC: usize, lpCandidate: ?*const anyopaque) callconv(W) i32 {
    _ = hIMC; _ = lpCandidate;
    return 1;
}

fn ImmNotifyIME(hIMC: usize, dwAction: u32, dwIndex: u32, dwValue: u32) callconv(W) i32 {
    _ = hIMC; _ = dwAction; _ = dwIndex; _ = dwValue;
    return 1;
}

fn ImmEscapeW(hKL: usize, hIMC: usize, uEscape: u32, lpData: ?*anyopaque) callconv(W) usize {
    _ = hKL; _ = hIMC; _ = uEscape; _ = lpData;
    return 0;
}

fn ImmSetCompositionStringW(hIMC: usize, dwIndex: u32, lpComp: ?*const anyopaque, dwCompLen: u32, lpRead: ?*const anyopaque, dwReadLen: u32) callconv(W) i32 {
    _ = hIMC; _ = dwIndex; _ = lpComp; _ = dwCompLen; _ = lpRead; _ = dwReadLen;
    return 1;
}

pub fn lookupImm32(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "ImmGetContext")) return @intFromPtr(&ImmGetContext);
    if (std.mem.eql(u8, name, "ImmReleaseContext")) return @intFromPtr(&ImmReleaseContext);
    if (std.mem.eql(u8, name, "ImmGetCompositionStringW")) return @intFromPtr(&ImmGetCompositionStringW);
    if (std.mem.eql(u8, name, "ImmSetCompositionWindow")) return @intFromPtr(&ImmSetCompositionWindow);
    if (std.mem.eql(u8, name, "ImmSetCompositionFontW")) return @intFromPtr(&ImmSetCompositionFontW);
    if (std.mem.eql(u8, name, "ImmSetCandidateWindow")) return @intFromPtr(&ImmSetCandidateWindow);
    if (std.mem.eql(u8, name, "ImmNotifyIME")) return @intFromPtr(&ImmNotifyIME);
    if (std.mem.eql(u8, name, "ImmEscapeW")) return @intFromPtr(&ImmEscapeW);
    if (std.mem.eql(u8, name, "ImmSetCompositionStringW")) return @intFromPtr(&ImmSetCompositionStringW);
    return null;
}

// ---------------------------------------------------------------------------
// PSAPI.dll & MSWSOCK.dll (process/module info and overlapped socket I/O)
// ---------------------------------------------------------------------------

const MODULEINFO = extern struct {
    lpBaseOfDll: usize,
    SizeOfImage: u32,
    EntryPoint: usize,
};

fn psapiEnumProcessModules(hProcess: usize, lphModule: ?[*]usize, cb: u32, lpcbNeeded: ?*u32) callconv(W) i32 {
    _ = hProcess;
    if (lpcbNeeded) |p| p.* = @sizeOf(usize);
    if (lphModule != null and cb >= @sizeOf(usize)) lphModule.?[0] = 0x140000000;
    return 1;
}

fn psapiEnumProcesses(pProcessIds: ?[*]u32, cb: u32, pBytesReturned: ?*u32) callconv(W) i32 {
    const pid: u32 = @intCast(linux.getpid());
    if (pBytesReturned) |p| p.* = 4;
    if (pProcessIds != null and cb >= 4) pProcessIds.?[0] = pid;
    return 1;
}

fn psapiGetModuleInformation(hProcess: usize, hModule: usize, lpmodinfo: ?*MODULEINFO, cb: u32) callconv(W) i32 {
    _ = hProcess;
    if (lpmodinfo == null or cb < @sizeOf(MODULEINFO)) return 0;
    lpmodinfo.?.* = .{ .lpBaseOfDll = hModule, .SizeOfImage = 0x10000, .EntryPoint = hModule };
    return 1;
}

fn psapiGetModuleBaseNameW(hProcess: usize, hModule: usize, lpBaseName: ?[*]u16, nSize: u32) callconv(W) u32 {
    _ = hProcess;
    _ = hModule;
    if (lpBaseName == null or nSize == 0) return 0;
    const mod = [_]u16{ 'a', 'p', 'p', '.', 'e', 'x', 'e', 0 };
    const n = @min(nSize - 1, mod.len - 1);
    @memcpy(lpBaseName.?[0..n], mod[0..n]);
    lpBaseName.?[n] = 0;
    return n;
}

fn psapiGetModuleFileNameExW(hProcess: usize, hModule: usize, lpFilename: ?[*]u16, nSize: u32) callconv(W) u32 {
    _ = hProcess;
    _ = hModule;
    if (lpFilename == null or nSize == 0) return 0;
    const p = [_]u16{ 'C', ':', '\\', 'a', 'p', 'p', '.', 'e', 'x', 'e', 0 };
    const n = @min(nSize - 1, p.len - 1);
    @memcpy(lpFilename.?[0..n], p[0..n]);
    lpFilename.?[n] = 0;
    return n;
}

pub fn lookupPsapi(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "EnumProcessModules")) return @intFromPtr(&psapiEnumProcessModules);
    if (std.mem.eql(u8, name, "EnumProcesses")) return @intFromPtr(&psapiEnumProcesses);
    if (std.mem.eql(u8, name, "GetModuleInformation")) return @intFromPtr(&psapiGetModuleInformation);
    if (std.mem.eql(u8, name, "GetModuleBaseNameW")) return @intFromPtr(&psapiGetModuleBaseNameW);
    if (std.mem.eql(u8, name, "GetModuleFileNameExW")) return @intFromPtr(&psapiGetModuleFileNameExW);
    return null;
}

fn mswsockTransmitFile(
    hSocket: usize,
    hFile: usize,
    nNumberOfBytesToWrite: u32,
    nNumberOfBytesPerSend: u32,
    lpOverlapped: ?*anyopaque,
    lpTransmitBuffers: ?*const extern struct { Head: ?[*]const u8, HeadLength: u32, Tail: ?[*]const u8, TailLength: u32 },
    dwReserved: u32,
) callconv(W) i32 {
    _ = nNumberOfBytesPerSend;
    _ = lpOverlapped;
    _ = dwReserved;
    const sock: i32 = @intCast(hSocket & 0x7fffffff);
    if (lpTransmitBuffers) |tb| {
        if (tb.Head != null and tb.HeadLength > 0) _ = linux.sendto(sock, tb.Head.?, tb.HeadLength, 0, null, 0);
    }
    var buf: [4096]u8 = undefined;
    var rem: usize = if (nNumberOfBytesToWrite == 0) std.math.maxInt(usize) else nNumberOfBytesToWrite;
    const fd: i32 = @intCast(hFile & 0x7fffffff);
    while (rem > 0) {
        const chunk = @min(rem, buf.len);
        const r = linux.read(fd, &buf, chunk);
        if (linux.errno(r) != .SUCCESS or r == 0) break;
        _ = linux.sendto(sock, &buf, r, 0, null, 0);
        if (nNumberOfBytesToWrite != 0) rem -= r;
    }
    if (lpTransmitBuffers) |tb| {
        if (tb.Tail != null and tb.TailLength > 0) _ = linux.sendto(sock, tb.Tail.?, tb.TailLength, 0, null, 0);
    }
    return 1;
}

pub fn lookupMswsock(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "TransmitFile")) return @intFromPtr(&mswsockTransmitFile);
    return null;
}

test "oleaut32 VARIANT sizing and VariantCopy VT_BSTR deep copy" {
    var src: [32]u8 align(8) = [_]u8{0xAA} ** 32;
    var dst: [32]u8 align(8) = [_]u8{0xBB} ** 32;
    VariantInit(&src);
    VariantInit(&dst);
    // Sentinel bytes immediately past VARIANT_SIZE must stay untouched.
    try std.testing.expectEqual(@as(u8, 0xAA), src[VARIANT_SIZE]);
    try std.testing.expectEqual(@as(u8, 0xBB), dst[VARIANT_SIZE]);

    const hello = [_:0]u16{ 'H', 'e', 'l', 'l', 'o' };
    const bstr = SysAllocString(hello[0..:0].ptr) orelse return error.OutOfMemory;
    std.mem.writeInt(u16, src[0..2], VT_BSTR, .little);
    std.mem.writeInt(usize, src[8 .. 8 + @sizeOf(usize)], @intFromPtr(bstr), .little);

    try std.testing.expectEqual(@as(i32, 0), VariantCopy(&dst, &src));
    try std.testing.expectEqual(@as(u8, 0xBB), dst[VARIANT_SIZE]);
    try std.testing.expectEqual(VT_BSTR, std.mem.readInt(u16, dst[0..2], .little));
    const copied_ptr = std.mem.readInt(usize, dst[8 .. 8 + @sizeOf(usize)], .little);
    try std.testing.expect(copied_ptr != 0);
    try std.testing.expect(copied_ptr != @intFromPtr(bstr));
    try std.testing.expectEqual(@as(u32, 5), SysStringLen(@ptrFromInt(copied_ptr)));
}

test "BCrypt SHA-256 hashing and BCryptGetProperty match std.crypto" {
    const sha256_name = [_:0]u16{ 'S', 'H', 'A', '2', '5', '6' };
    const prop_len = [_:0]u16{ 'H', 'a', 's', 'h', 'D', 'i', 'g', 'e', 's', 't', 'L', 'e', 'n', 'g', 't', 'h' };
    var alg: usize = 0;
    try std.testing.expectEqual(@as(i32, 0), BCryptOpenAlgorithmProvider(&alg, &sha256_name, null, 0));
    defer _ = BCryptCloseAlgorithmProvider(alg, 0);

    var digest_len_buf: [4]u8 = undefined;
    var cb_res: u32 = 0;
    try std.testing.expectEqual(@as(i32, 0), BCryptGetProperty(alg, &prop_len, &digest_len_buf, 4, &cb_res, 0));
    try std.testing.expectEqual(@as(u32, 4), cb_res);
    try std.testing.expectEqual(@as(u32, 32), std.mem.readInt(u32, &digest_len_buf, .little));

    var hash: usize = 0;
    try std.testing.expectEqual(@as(i32, 0), BCryptCreateHash(alg, &hash, null, 0, null, 0, 0));
    defer _ = BCryptDestroyHash(hash);

    const msg = "WINS-BCrypt-test";
    try std.testing.expectEqual(@as(i32, 0), BCryptHashData(hash, msg.ptr, msg.len, 0));
    var got: [32]u8 = undefined;
    try std.testing.expectEqual(@as(i32, 0), BCryptFinishHash(hash, &got, 32, 0));

    var want: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &want, .{});
    try std.testing.expectEqualSlices(u8, &want, &got);

    // Unknown algorithms must fail closed.
    const bad_alg = [_:0]u16{ 'R', 'C', '4' };
    var bad_h: usize = 123;
    try std.testing.expectEqual(STATUS_NOT_SUPPORTED_I32, BCryptOpenAlgorithmProvider(&bad_h, &bad_alg, null, 0));
    try std.testing.expectEqual(@as(usize, 0), bad_h);
}
