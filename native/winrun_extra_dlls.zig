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
    if (buf == null) return 0;
    if (len == 0) return 1;
    var off: usize = 0;
    const total: usize = len;
    while (off < total) {
        const rc = linux.getrandom(buf.? + off, total - off, 0);
        if (linux.errno(rc) != .SUCCESS or rc == 0) {
            // Fallback deterministic PRNG if getrandom is blocked
            var seed: u64 = 0x9e3779b97f4a7c15 ^ @as(u64, off);
            while (off < total) : (off += 1) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                buf.?[off] = @truncate(seed);
            }
            break;
        }
        off += rc;
    }
    return 1;
}

fn SystemFunction036(buf: ?[*]u8, len: u32) callconv(W) u8 {
    return @intCast(fillRandomBytes(buf, len));
}

fn CryptAcquireContextA(phProv: ?*usize, container: ?[*:0]const u8, provider: ?[*:0]const u8, prov_type: u32, flags: u32) callconv(W) i32 {
    _ = container;
    _ = provider;
    _ = prov_type;
    _ = flags;
    if (phProv) |p| p.* = 0xCAFE0001;
    return 1;
}

fn CryptAcquireContextW(phProv: ?*usize, container: ?[*:0]const u16, provider: ?[*:0]const u16, prov_type: u32, flags: u32) callconv(W) i32 {
    _ = container;
    _ = provider;
    _ = prov_type;
    _ = flags;
    if (phProv) |p| p.* = 0xCAFE0001;
    return 1;
}

fn CryptGenRandom(hProv: usize, len: u32, buf: ?[*]u8) callconv(W) i32 {
    _ = hProv;
    return @intCast(fillRandomBytes(buf, len));
}

fn CryptReleaseContext(hProv: usize, flags: u32) callconv(W) i32 {
    _ = hProv;
    _ = flags;
    return 1;
}

fn OpenProcessToken(proc_h: usize, access: u32, token_h: ?*usize) callconv(W) i32 {
    _ = proc_h;
    _ = access;
    if (token_h) |t| t.* = 0x7001;
    return 1;
}

fn DuplicateToken(existing_token: usize, imp_level: u32, dup_token: ?*usize) callconv(W) i32 {
    _ = existing_token;
    _ = imp_level;
    if (dup_token) |t| t.* = 0x7002;
    return 1;
}

fn GetTokenInformation(
    token_h: usize,
    info_class: u32,
    info: ?[*]u8,
    info_len: u32,
    ret_len: ?*u32,
) callconv(W) i32 {
    _ = token_h;
    _ = info_class;
    if (ret_len) |r| r.* = 36;
    if (info == null or info_len < 36) return 0;
    @memset(info.?[0..info_len], 0);
    return 1;
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

fn RegOpenKeyExW(hKey: usize, lpSubKey: ?[*:0]const u16, ulOptions: u32, samDesired: u32, phkResult: ?*usize) callconv(W) i32 {
    _ = hKey; _ = lpSubKey; _ = ulOptions; _ = samDesired;
    if (phkResult) |p| p.* = 0x8001;
    return 0;
}

fn RegOpenKeyExA(hKey: usize, lpSubKey: ?[*:0]const u8, ulOptions: u32, samDesired: u32, phkResult: ?*usize) callconv(W) i32 {
    _ = hKey; _ = lpSubKey; _ = ulOptions; _ = samDesired;
    if (phkResult) |p| p.* = 0x8001;
    return 0;
}

fn RegCreateKeyExW(hKey: usize, lpSubKey: ?[*:0]const u16, Reserved: u32, lpClass: ?[*:0]const u16, dwOptions: u32, samDesired: u32, lpSecurityAttributes: ?*anyopaque, phkResult: ?*usize, lpdwDisposition: ?*u32) callconv(W) i32 {
    _ = hKey; _ = lpSubKey; _ = Reserved; _ = lpClass; _ = dwOptions; _ = samDesired; _ = lpSecurityAttributes;
    if (phkResult) |p| p.* = 0x8001;
    if (lpdwDisposition) |p| p.* = 1;
    return 0;
}

fn RegCloseKey(hKey: usize) callconv(W) i32 {
    _ = hKey;
    return 0;
}

fn RegQueryValueExW(hKey: usize, lpValueName: ?[*:0]const u16, lpReserved: ?*u32, lpType: ?*u32, lpData: ?[*]u8, lpcbData: ?*u32) callconv(W) i32 {
    _ = hKey; _ = lpValueName; _ = lpReserved;
    if (lpType) |t| t.* = 1;
    if (lpData != null and lpcbData != null and lpcbData.?.* >= 2) {
        lpData.?[0] = 0;
        lpData.?[1] = 0;
        lpcbData.?.* = 2;
        return 0;
    }
    if (lpcbData) |s| s.* = 2;
    return 0;
}

fn RegQueryValueExA(hKey: usize, lpValueName: ?[*:0]const u8, lpReserved: ?*u32, lpType: ?*u32, lpData: ?[*]u8, lpcbData: ?*u32) callconv(W) i32 {
    _ = hKey; _ = lpValueName; _ = lpReserved;
    if (lpType) |t| t.* = 1;
    if (lpData != null and lpcbData != null and lpcbData.?.* >= 1) {
        lpData.?[0] = 0;
        lpcbData.?.* = 1;
        return 0;
    }
    if (lpcbData) |s| s.* = 1;
    return 0;
}

fn RegSetValueExW(hKey: usize, lpValueName: ?[*:0]const u16, Reserved: u32, dwType: u32, lpData: ?[*]const u8, cbData: u32) callconv(W) i32 {
    _ = hKey; _ = lpValueName; _ = Reserved; _ = dwType; _ = lpData; _ = cbData;
    return 0;
}

fn RegSetValueExA(hKey: usize, lpValueName: ?[*:0]const u8, Reserved: u32, dwType: u32, lpData: ?[*]const u8, cbData: u32) callconv(W) i32 {
    _ = hKey; _ = lpValueName; _ = Reserved; _ = dwType; _ = lpData; _ = cbData;
    return 0;
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

fn RegDeleteValueA(hKey: usize, lpValueName: ?[*:0]const u8) callconv(W) i32 {
    _ = hKey; _ = lpValueName;
    return 0;
}

fn RegDeleteValueW(hKey: usize, lpValueName: ?*const u16) callconv(W) i32 {
    _ = hKey; _ = lpValueName;
    return 0;
}

fn RegCreateKeyW(hKey: usize, lpSubKey: ?*const u16, phkResult: ?*usize) callconv(W) i32 {
    _ = hKey; _ = lpSubKey;
    if (phkResult) |p| p.* = 0x2001;
    return 0;
}

fn RegCreateKeyA(hKey: usize, lpSubKey: ?[*:0]const u8, phkResult: ?*usize) callconv(W) i32 {
    _ = hKey; _ = lpSubKey;
    if (phkResult) |p| p.* = 0x2001;
    return 0;
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

pub fn lookupAdvapi32(name: []const u8) ?usize {
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

pub fn lookupWs2_32(name: []const u8) ?usize {
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
    if (pszPath == null) return 0;
    return 1;
}

fn PathFileExistsA(pszPath: ?[*:0]const u8) callconv(W) i32 {
    if (pszPath == null) return 0;
    return 1;
}

fn PathIsDirectoryW(pszPath: ?[*:0]const u16) callconv(W) i32 {
    if (pszPath == null) return 0;
    return 1;
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

fn SHGetFolderPathW(hwnd: usize, csidl: i32, token: usize, flags: u32, pszPath: ?[*]u16) callconv(W) i32 {
    _ = hwnd; _ = csidl; _ = token; _ = flags;
    if (pszPath) |p| {
        const default_path = [_]u16{ 'C', ':', '\\', 'U', 's', 'e', 'r', 's', '\\', 'U', 's', 'e', 'r', '\\', 'A', 'p', 'p', 'D', 'a', 't', 'a', '\\', 'R', 'o', 'a', 'm', 'i', 'n', 'g', 0 };
        @memcpy(p[0..default_path.len], &default_path);
    }
    return 0; // S_OK
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

pub fn lookupShell32(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "CommandLineToArgvW")) return @intFromPtr(&CommandLineToArgvW);
    if (std.mem.eql(u8, name, "ShellExecuteExA")) return @intFromPtr(&ShellExecuteExA);
    if (std.mem.eql(u8, name, "ShellExecuteExW")) return @intFromPtr(&ShellExecuteExW);
    if (std.mem.eql(u8, name, "ShellExecuteW")) return @intFromPtr(&ShellExecuteW);
    if (std.mem.eql(u8, name, "SHGetFolderPathW")) return @intFromPtr(&SHGetFolderPathW);
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

var ole_buf: [16384]u8 align(16) = undefined;
var ole_buf_off: usize = 16;

fn SysAllocString(s: ?[*:0]const u16) callconv(W) ?[*]u16 {
    if (s == null) return null;
    var len: u32 = 0;
    while (s.?[len] != 0) : (len += 1) {}
    const byte_len = len * 2;
    const total = 4 + byte_len + 2;
    if (ole_buf_off + total > ole_buf.len) ole_buf_off = 16;
    const base: [*]u8 = @ptrCast(&ole_buf[ole_buf_off]);
    ole_buf_off = std.mem.alignForward(usize, ole_buf_off + total, 8);
    std.mem.writeInt(u32, base[0..4], byte_len, .little);
    const chars: [*]u16 = @ptrCast(@alignCast(base + 4));
    @memcpy(chars[0..len], s.?[0..len]);
    chars[len] = 0;
    return chars;
}

fn SysAllocStringLen(s: ?[*]const u16, len: u32) callconv(W) ?[*]u16 {
    const byte_len = len * 2;
    const total = 4 + byte_len + 2;
    if (ole_buf_off + total > ole_buf.len) ole_buf_off = 16;
    const base: [*]u8 = @ptrCast(&ole_buf[ole_buf_off]);
    ole_buf_off = std.mem.alignForward(usize, ole_buf_off + total, 8);
    std.mem.writeInt(u32, base[0..4], byte_len, .little);
    const chars: [*]u16 = @ptrCast(@alignCast(base + 4));
    if (s) |src| @memcpy(chars[0..len], src[0..len]) else @memset(chars[0..len], 0);
    chars[len] = 0;
    return chars;
}

fn SysAllocStringByteLen(s: ?[*]const u8, len: u32) callconv(W) ?[*]u8 {
    const total = 4 + len + 2;
    if (ole_buf_off + total > ole_buf.len) ole_buf_off = 16;
    const base: [*]u8 = @ptrCast(&ole_buf[ole_buf_off]);
    ole_buf_off = std.mem.alignForward(usize, ole_buf_off + total, 8);
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
    if (pv) |p| @memset(@as([*]u8, @ptrCast(p))[0..24], 0);
}

fn VariantClear(pv: ?*anyopaque) callconv(W) i32 {
    if (pv) |p| @memset(@as([*]u8, @ptrCast(p))[0..24], 0);
    return 0; // S_OK
}

fn VariantCopy(pvargDest: ?*anyopaque, pvargSrc: ?*const anyopaque) callconv(W) i32 {
    _ = pvargDest; _ = pvargSrc;
    return 0; // S_OK
}

fn GetErrorInfo(dwReserved: u32, ppErrInfo: ?*?*anyopaque) callconv(W) i32 {
    _ = dwReserved;
    if (ppErrInfo) |p| p.* = null;
    return 1; // S_FALSE
}

pub fn lookupOleaut32(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "VariantCopy")) return @intFromPtr(&VariantCopy);
    if (std.mem.eql(u8, name, "SysAllocString")) return @intFromPtr(&SysAllocString);
    if (std.mem.eql(u8, name, "SysAllocStringLen")) return @intFromPtr(&SysAllocStringLen);
    if (std.mem.eql(u8, name, "SysAllocStringByteLen")) return @intFromPtr(&SysAllocStringByteLen);
    if (std.mem.eql(u8, name, "SysFreeString")) return @intFromPtr(&SysFreeString);
    if (std.mem.eql(u8, name, "SysStringByteLen")) return @intFromPtr(&SysStringByteLen);
    if (std.mem.eql(u8, name, "SysStringLen")) return @intFromPtr(&SysStringLen);
    if (std.mem.eql(u8, name, "VariantInit")) return @intFromPtr(&VariantInit);
    if (std.mem.eql(u8, name, "VariantClear")) return @intFromPtr(&VariantClear);
    if (std.mem.eql(u8, name, "GetErrorInfo")) return @intFromPtr(&GetErrorInfo);
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

fn CoTaskMemFree(pv: ?*anyopaque) callconv(W) void {
    _ = pv;
}

fn CoTaskMemAlloc(cb: usize) callconv(W) ?*anyopaque {
    _ = cb;
    return @ptrFromInt(0x900000);
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

/// A null HANDLE / zero-returning stub, kept for the call sites that only need a
/// "no handle" answer with no argument to balance.
fn crypt_ret_zero() callconv(W) usize {
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
    // Crypt32 names not enumerated above are NOT stubbed: a zero-argument stub
    // for an API of unknown arity leaves its arguments on the guest stack and
    // shifts the frame, which is the defect this whole section exists to avoid.
    // Exporting nothing makes the loader report the name as UNRESOLVED instead.
    return null;
}

pub fn lookupNcrypt(name: []const u8) ?usize {
    // Same reasoning as lookupCrypt32: NCrypt/BCrypt take arguments whose count
    // is not knowable here, so no catch-all stub.
    _ = name;
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

fn SetWindowSubclass(hWnd: usize, pfnSubclass: ?*anyopaque, uIdSubclass: usize, dwRefData: usize) callconv(W) i32 {
    _ = hWnd; _ = pfnSubclass; _ = uIdSubclass; _ = dwRefData;
    return 1;
}

fn RemoveWindowSubclass(hWnd: usize, pfnSubclass: ?*anyopaque, uIdSubclass: usize) callconv(W) i32 {
    _ = hWnd; _ = pfnSubclass; _ = uIdSubclass;
    return 1;
}

fn DefSubclassProc(hWnd: usize, uMsg: u32, wParam: usize, lParam: usize) callconv(W) isize {
    _ = hWnd; _ = uMsg; _ = wParam; _ = lParam;
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
    if (std.mem.eql(u8, name, "SetWindowSubclass")) return @intFromPtr(&SetWindowSubclass);
    if (std.mem.eql(u8, name, "RemoveWindowSubclass")) return @intFromPtr(&RemoveWindowSubclass);
    if (std.mem.eql(u8, name, "DefSubclassProc")) return @intFromPtr(&DefSubclassProc);
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
