// WINS — winrun_extra_dlls.zig
// Native x86_64 Linux shims for ADVAPI32.dll, WS2_32.dll, and console-safe USER32.dll
// imports required by multi-call utilities (such as busybox64.exe).

const std = @import("std");
const linux = std.os.linux;

const W: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

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

pub fn lookupAdvapi32(name: []const u8) ?usize {
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
    if (std.mem.eql(u8, name, "CryptCreateHash")) return @intFromPtr(&crypt_ret_one);
    if (std.mem.eql(u8, name, "CryptDestroyHash")) return @intFromPtr(&crypt_ret_one);
    if (std.mem.eql(u8, name, "CryptHashData")) return @intFromPtr(&crypt_ret_one);
    if (std.mem.eql(u8, name, "CryptGetHashParam")) return @intFromPtr(&crypt_ret_one);
    if (std.mem.eql(u8, name, "CryptEncrypt")) return @intFromPtr(&crypt_ret_one);
    if (std.mem.eql(u8, name, "CryptImportKey")) return @intFromPtr(&crypt_ret_one);
    if (std.mem.eql(u8, name, "CryptDestroyKey")) return @intFromPtr(&crypt_ret_one);
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

pub fn lookupWs2_32(name: []const u8) ?usize {
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
            .nsec = @as(isize, ms) * 1_000_000,
        };
        _ = linux.nanosleep(&req, null);
    }
    return 0; // WAIT_OBJECT_0
}

pub fn lookupUser32Console(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "DispatchMessageA")) return @intFromPtr(&DispatchMessageA);
    if (std.mem.eql(u8, name, "TranslateMessage")) return @intFromPtr(&TranslateMessage);
    if (std.mem.eql(u8, name, "PeekMessageA")) return @intFromPtr(&PeekMessageA);
    if (std.mem.eql(u8, name, "IsIconic")) return @intFromPtr(&IsIconic);
    if (std.mem.eql(u8, name, "IsWindowVisible")) return @intFromPtr(&IsWindowVisible);
    if (std.mem.eql(u8, name, "ShowWindow")) return @intFromPtr(&ShowWindow);
    if (std.mem.eql(u8, name, "MsgWaitForMultipleObjects")) return @intFromPtr(&MsgWaitForMultipleObjects);
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

pub fn lookupShlwapi(name: []const u8) ?usize {
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

pub fn lookupShell32(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "ShellExecuteW")) return @intFromPtr(&ShellExecuteW);
    if (std.mem.eql(u8, name, "SHGetFolderPathW")) return @intFromPtr(&SHGetFolderPathW);
    if (std.mem.eql(u8, name, "SHCreateDirectoryExW")) return @intFromPtr(&SHCreateDirectoryExW);
    if (std.mem.eql(u8, name, "SHFileOperationW")) return @intFromPtr(&SHFileOperationW);
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

fn GetErrorInfo(dwReserved: u32, ppErrInfo: ?*?*anyopaque) callconv(W) i32 {
    _ = dwReserved;
    if (ppErrInfo) |p| p.* = null;
    return 1; // S_FALSE
}

pub fn lookupOleaut32(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "SysAllocString")) return @intFromPtr(&SysAllocString);
    if (std.mem.eql(u8, name, "SysAllocStringLen")) return @intFromPtr(&SysAllocStringLen);
    if (std.mem.eql(u8, name, "SysAllocStringByteLen")) return @intFromPtr(&SysAllocStringByteLen);
    if (std.mem.eql(u8, name, "SysFreeString")) return @intFromPtr(&SysFreeString);
    if (std.mem.eql(u8, name, "SysStringByteLen")) return @intFromPtr(&SysStringByteLen);
    if (std.mem.eql(u8, name, "SysStringLen")) return @intFromPtr(&SysStringLen);
    if (std.mem.eql(u8, name, "VariantInit")) return @intFromPtr(&VariantInit);
    if (std.mem.eql(u8, name, "VariantClear")) return @intFromPtr(&VariantClear);
    if (std.mem.eql(u8, name, "GetErrorInfo")) return @intFromPtr(&GetErrorInfo);
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

pub fn lookupOle32(name: []const u8) ?usize {
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

fn crypt_ret_zero() callconv(W) usize { return 0; }
fn crypt_ret_one() callconv(W) u32 { return 1; }

pub fn lookupCrypt32(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "CertOpenStore")) return @intFromPtr(&crypt_ret_one);
    if (std.mem.eql(u8, name, "CertCloseStore")) return @intFromPtr(&crypt_ret_one);
    if (std.mem.eql(u8, name, "CertCreateCertificateContext")) return @intFromPtr(&crypt_ret_one);
    if (std.mem.eql(u8, name, "CertFreeCertificateContext")) return @intFromPtr(&crypt_ret_one);
    if (std.mem.eql(u8, name, "CertAddCertificateContextToStore")) return @intFromPtr(&crypt_ret_one);
    if (std.mem.eql(u8, name, "CertCreateCertificateChainEngine")) return @intFromPtr(&crypt_ret_one);
    if (std.mem.eql(u8, name, "CertFreeCTLContext")) return @intFromPtr(&crypt_ret_one);
    if (std.mem.eql(u8, name, "CertFreeCRLContext")) return @intFromPtr(&crypt_ret_one);
    if (std.mem.eql(u8, name, "CryptMsgClose")) return @intFromPtr(&crypt_ret_one);
    if (std.mem.startsWith(u8, name, "Cert") or std.mem.startsWith(u8, name, "Crypt") or std.mem.startsWith(u8, name, "PFX")) {
        return @intFromPtr(&crypt_ret_zero);
    }
    return null;
}

pub fn lookupNcrypt(name: []const u8) ?usize {
    if (std.mem.startsWith(u8, name, "BCrypt") or std.mem.startsWith(u8, name, "NCrypt")) {
        return @intFromPtr(&crypt_ret_zero);
    }
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

pub fn lookupMisc(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "InitCommonControlsEx")) return @intFromPtr(&InitCommonControlsEx);
    if (std.mem.eql(u8, name, "InitSecurityInterfaceA")) return @intFromPtr(&InitSecurityInterfaceA);
    if (std.mem.eql(u8, name, "IsDestinationReachableW")) return @intFromPtr(&IsDestinationReachableW);
    if (std.mem.eql(u8, name, "IsNetworkAlive")) return @intFromPtr(&IsNetworkAlive);
    if (std.mem.eql(u8, name, "WinVerifyTrust")) return @intFromPtr(&WinVerifyTrust);
    if (std.mem.eql(u8, name, "if_nametoindex")) return @intFromPtr(&if_nametoindex);
    return null;
}
