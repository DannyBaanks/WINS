//! Win32 entry points winload64 (x86-64) lacked for Dark Souls III and its
//! middleware (FMOD Ex, Bink, libcurl). Every function either does the real job
//! (string/locale/GUID parsing, environment blocks, security descriptors) or
//! reports the honest Windows answer for a capability WINS does not provide:
//! no ACM codecs installed, no MCI devices, no PIX attached, no LDAP, no
//! synthetic input injection. Nothing here claims success for work not done.
const std = @import("std");
const linux = std.os.linux;
const W: std.builtin.CallingConvention = .{ .x86_64_win = .{} };
const dinput = @import("wins_dinput.zig");

pub var set_last_error: ?*const fn (u32) void = null;
fn lastError(code: u32) void {
    if (set_last_error) |f| f(code);
}
/// Resolver for functions that already exist elsewhere in winload64 (set by winrun64).
pub var resolve: ?*const fn ([]const u8, []const u8) ?usize = null;
fn other(comptime T: type, lib: []const u8, sym: []const u8) ?T {
    const r = resolve orelse return null;
    return @ptrFromInt(r(lib, sym) orelse return null);
}

const E_NOTIMPL: i32 = @bitCast(@as(u32, 0x80004001));
const E_INVALIDARG: i32 = @bitCast(@as(u32, 0x80070057));
const E_POINTER: i32 = @bitCast(@as(u32, 0x80004003));
const E_OUTOFMEMORY: i32 = @bitCast(@as(u32, 0x8007000E));

// ------------------------------------------------------------------ kernel32
var env_block_a: [32768]u8 = undefined;
/// ANSI environment block (Bink reads it at startup): the UTF-16 block the
/// kernel32 shims maintain, narrowed (non-ASCII -> '?', as CP_ACP would lose it).
fn GetEnvironmentStrings() callconv(W) ?[*]u8 {
    const getw = other(*const fn () callconv(W) ?[*]const u16, "kernel32.dll", "GetEnvironmentStringsW") orelse return null;
    const wb = getw() orelse return null;
    var k: usize = 0;
    while (k + 1 < env_block_a.len) : (k += 1) {
        const c = wb[k];
        env_block_a[k] = if (c < 0x80) @intCast(c) else '?';
        if (c == 0 and wb[k + 1] == 0) {
            env_block_a[k + 1] = 0;
            break;
        }
    }
    return &env_block_a;
}
fn FreeEnvironmentStringsA(p: ?[*]u8) callconv(W) i32 {
    _ = p;
    return 1;
}

/// GetStringTypeA, CT_CTYPE1 only (the class C runtimes ask for); ASCII rules.
fn GetStringTypeA(locale: u32, info: u32, src: ?[*]const u8, n_in: i32, out: ?[*]u16) callconv(W) i32 {
    _ = locale;
    const s = src orelse return 0;
    const o = out orelse return 0;
    if (info != 1) {
        lastError(1004); // ERROR_INVALID_FLAGS
        return 0;
    }
    const n: usize = if (n_in < 0) std.mem.len(@as([*:0]const u8, @ptrCast(s))) + 1 else @intCast(n_in);
    for (0..n) |k| o[k] = ctype1(s[k]);
    return 1;
}
fn ctype1(c: u8) u16 {
    var t: u16 = 0;
    if (std.ascii.isUpper(c)) t |= 0x001;
    if (std.ascii.isLower(c)) t |= 0x002;
    if (std.ascii.isDigit(c)) t |= 0x004;
    if (c == ' ' or (c >= 0x09 and c <= 0x0d)) t |= 0x008;
    if (std.ascii.isPunctuation(c)) t |= 0x010;
    if (c < 0x20 or c == 0x7f) t |= 0x020;
    if (c == ' ' or c == '\t') t |= 0x040;
    if (std.ascii.isHex(c)) t |= 0x080;
    if (std.ascii.isAlphabetic(c)) t |= 0x100;
    if (c >= 0x80) t = 0;
    return t;
}

// The kernel32 shims report en-US everywhere (GetUserDefaultLCID = 0x409).
fn GetSystemDefaultLangID() callconv(W) u16 {
    return 0x0409;
}
fn GetUserDefaultLangID() callconv(W) u16 {
    return 0x0409;
}
fn GetSystemDefaultLCID() callconv(W) u32 {
    return 0x0409;
}
fn GetSystemDefaultLocaleName(buf: ?[*]u16, n: i32) callconv(W) i32 {
    const name = "en-US";
    if (buf == null or n < name.len + 1) {
        lastError(122); // ERROR_INSUFFICIENT_BUFFER
        return 0;
    }
    for (name, 0..) |c, k| buf.?[k] = c;
    buf.?[name.len] = 0;
    return name.len + 1;
}

/// Scheduling hint: returns the previous ideal processor (WINS never set one: 0).
fn SetThreadIdealProcessor(thread: usize, cpu: u32) callconv(W) u32 {
    _ = thread;
    if (cpu > 64) {
        lastError(87);
        return 0xFFFFFFFF;
    }
    return 0;
}

// The shim heaps have no walkable block list: HeapWalk ends immediately, as on a
// heap with no entries. Lock/Unlock are real no-ops (each allocation is atomic).
fn HeapLock(h: usize) callconv(W) i32 {
    _ = h;
    return 1;
}
fn HeapUnlock(h: usize) callconv(W) i32 {
    _ = h;
    return 1;
}
fn HeapWalk(h: usize, entry: ?*anyopaque) callconv(W) i32 {
    _ = h;
    _ = entry;
    lastError(259); // ERROR_NO_MORE_ITEMS
    return 0;
}

fn GetWindowsDirectoryA(buf: ?[*]u8, n: u32) callconv(W) u32 {
    const dir = "C:\\Windows";
    if (buf == null or n <= dir.len) return dir.len + 1;
    @memcpy(buf.?[0..dir.len], dir);
    buf.?[dir.len] = 0;
    return dir.len;
}

/// OpenFile (16-bit era API FMOD Ex still imports). OF_EXIST is answered from the
/// host file system; opening is delegated to CreateFileA with the same access.
const OFSTRUCT = extern struct { cBytes: u8, fFixedDisk: u8, nErrCode: u16, r1: u16, r2: u16, szPathName: [128]u8 };
fn OpenFile(name: ?[*:0]const u8, of: ?*OFSTRUCT, style: u32) callconv(W) i32 {
    const n = name orelse return -1;
    const create = other(*const fn (?[*:0]const u8, u32, u32, ?*anyopaque, u32, u32, usize) callconv(W) usize, "kernel32.dll", "CreateFileA") orelse return -1;
    const close = other(*const fn (usize) callconv(W) i32, "kernel32.dll", "CloseHandle");
    const access: u32 = switch (style & 3) {
        0 => 0x80000000,
        1 => 0x40000000,
        else => 0xC0000000,
    };
    const disposition: u32 = if (style & 0x1000 != 0) 2 else 3; // OF_CREATE ? CREATE_ALWAYS : OPEN_EXISTING
    const h = create(n, access, 3, null, disposition, 0x80, 0);
    if (of) |o| {
        o.cBytes = @sizeOf(OFSTRUCT);
        o.fFixedDisk = 1;
        o.nErrCode = 0;
        const span = std.mem.span(n);
        const k = @min(span.len, o.szPathName.len - 1);
        @memcpy(o.szPathName[0..k], span[0..k]);
        o.szPathName[k] = 0;
    }
    if (h == std.math.maxInt(usize)) {
        if (of) |o| o.nErrCode = 2;
        return -1;
    }
    if (style & 0x4000 != 0) { // OF_EXIST: open, then close
        if (close) |c| _ = c(h);
        return 1;
    }
    return @intCast(@as(u32, @truncate(h)));
}

// ------------------------------------------------------------------ user32
fn activeWindow() usize {
    const f = other(*const fn () callconv(W) usize, "user32.dll", "GetActiveWindow") orelse return 0;
    return f();
}
fn GetForegroundWindow() callconv(W) usize {
    return activeWindow();
}
fn SetActiveWindow(h: usize) callconv(W) usize {
    _ = h;
    return activeWindow();
}
/// No child windows exist in a WINS process.
fn GetTopWindow(h: usize) callconv(W) usize {
    _ = h;
    return 0;
}
fn AdjustWindowRect(rect: ?*anyopaque, style: u32, menu: i32) callconv(W) i32 {
    const f = other(*const fn (?*anyopaque, u32, i32, u32) callconv(W) i32, "user32.dll", "AdjustWindowRectEx") orelse return 0;
    return f(rect, style, menu, 0);
}
/// WINS does not inject synthetic input into the host session: 0 events sent.
fn SendInput(n: u32, inputs: ?*anyopaque, size: i32) callconv(W) u32 {
    _ = n;
    _ = inputs;
    _ = size;
    lastError(5); // ERROR_ACCESS_DENIED, as UIPI reports a blocked injection
    return 0;
}
fn CharLowerBuffA(s: ?[*]u8, n: u32) callconv(W) u32 {
    const p = s orelse return 0;
    for (0..n) |k| p[k] = std.ascii.toLower(p[k]);
    return n;
}

// ------------------------------------------------------------------ gdi32
/// No GDI font rasteriser in WINS: glyph outlines fail with GDI_ERROR and fonts
/// report no kerning pairs. DS3 draws its text from its own font atlases.
fn GetGlyphOutlineW(hdc: usize, ch: u32, fmt: u32, gm: ?*anyopaque, size: u32, buf: ?*anyopaque, mat: ?*const anyopaque) callconv(W) u32 {
    _ = hdc;
    _ = ch;
    _ = fmt;
    _ = gm;
    _ = size;
    _ = buf;
    _ = mat;
    return 0xFFFFFFFF;
}
fn GetKerningPairsW(hdc: usize, n: u32, pairs: ?*anyopaque) callconv(W) u32 {
    _ = hdc;
    _ = n;
    _ = pairs;
    return 0;
}

// ------------------------------------------------------------------ advapi32
fn GetUserNameW(buf: ?[*]u16, n: ?*u32) callconv(W) i32 {
    const len = n orelse return 0;
    const user: []const u8 = if (std.c.getenv("USER")) |u| std.mem.span(u) else "wins";
    if (buf == null or len.* < user.len + 1) {
        len.* = @intCast(user.len + 1);
        lastError(122);
        return 0;
    }
    for (user, 0..) |c, k| buf.?[k] = if (c < 0x80) c else '?';
    buf.?[user.len] = 0;
    len.* = @intCast(user.len + 1);
    return 1;
}
/// SECURITY_DESCRIPTOR (absolute, x64): Revision, Sbz1, Control, Owner, Group, Sacl, Dacl.
const SecurityDescriptor = extern struct { revision: u8, sbz1: u8, control: u16, owner: usize, group: usize, sacl: usize, dacl: usize };
fn InitializeSecurityDescriptor(sd: ?*SecurityDescriptor, revision: u32) callconv(W) i32 {
    const p = sd orelse return 0;
    if (revision != 1) {
        lastError(1305); // ERROR_UNKNOWN_REVISION
        return 0;
    }
    p.* = .{ .revision = 1, .sbz1 = 0, .control = 0, .owner = 0, .group = 0, .sacl = 0, .dacl = 0 };
    return 1;
}
fn SetSecurityDescriptorDacl(sd: ?*SecurityDescriptor, present: i32, dacl: usize, defaulted: i32) callconv(W) i32 {
    const p = sd orelse return 0;
    if (p.revision != 1) {
        lastError(1305);
        return 0;
    }
    const SE_DACL_PRESENT: u16 = 0x0004;
    const SE_DACL_DEFAULTED: u16 = 0x0008;
    p.control &= ~(SE_DACL_PRESENT | SE_DACL_DEFAULTED);
    if (present != 0) {
        p.control |= SE_DACL_PRESENT;
        if (defaulted != 0) p.control |= SE_DACL_DEFAULTED;
        p.dacl = dacl;
    } else p.dacl = 0;
    return 1;
}
fn RegOpenKeyA(h: usize, sub: ?[*:0]const u8, out: ?*usize) callconv(W) i32 {
    const f = other(*const fn (usize, ?[*:0]const u8, u32, u32, ?*usize) callconv(W) i32, "advapi32.dll", "RegOpenKeyExA") orelse return 2;
    return f(h, sub, 0, 0xF003F, out);
}
fn RegEnumKeyA(h: usize, index: u32, name: ?[*]u8, cch: u32) callconv(W) i32 {
    const f = other(*const fn (usize, u32, ?[*]u16, ?*u32, ?*u32, ?[*]u16, ?*u32, ?*anyopaque) callconv(W) i32, "advapi32.dll", "RegEnumKeyExW") orelse return 259;
    var wbuf: [256]u16 = undefined;
    var wn: u32 = wbuf.len;
    const rc = f(h, index, &wbuf, &wn, null, null, null, null);
    if (rc != 0) return rc;
    const out = name orelse return 87;
    if (wn + 1 > cch) return 234; // ERROR_MORE_DATA
    for (0..wn) |k| out[k] = if (wbuf[k] < 0x80) @intCast(wbuf[k]) else '?';
    out[wn] = 0;
    return 0;
}

// ------------------------------------------------------------------ ole32
const GUID = extern struct { d1: u32, d2: u16, d3: u16, d4: [8]u8 };
/// "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}" -> CLSID. ProgIDs need the COM
/// registry, which WINS does not have: CO_E_CLASSSTRING.
fn CLSIDFromString(s: ?[*:0]const u16, out: ?*GUID) callconv(W) i32 {
    const CO_E_CLASSSTRING: i32 = @bitCast(@as(u32, 0x800401F3));
    const o = out orelse return E_INVALIDARG;
    const w = s orelse {
        o.* = std.mem.zeroes(GUID);
        return 0;
    };
    var a: [38]u8 = undefined;
    for (0..38) |k| {
        if (w[k] == 0 or w[k] >= 0x80) return CO_E_CLASSSTRING;
        a[k] = @intCast(w[k]);
    }
    if (w[38] != 0) return CO_E_CLASSSTRING;
    o.* = parseGuid(&a) orelse return CO_E_CLASSSTRING;
    return 0;
}
fn parseGuid(a: *const [38]u8) ?GUID {
    if (a[0] != '{' or a[37] != '}' or a[9] != '-' or a[14] != '-' or a[19] != '-' or a[24] != '-') return null;
    var g: GUID = undefined;
    g.d1 = std.fmt.parseInt(u32, a[1..9], 16) catch return null;
    g.d2 = std.fmt.parseInt(u16, a[10..14], 16) catch return null;
    g.d3 = std.fmt.parseInt(u16, a[15..19], 16) catch return null;
    g.d4[0] = std.fmt.parseInt(u8, a[20..22], 16) catch return null;
    g.d4[1] = std.fmt.parseInt(u8, a[22..24], 16) catch return null;
    for (0..6) |k| g.d4[2 + k] = std.fmt.parseInt(u8, a[25 + 2 * k ..][0..2], 16) catch return null;
    return g;
}

// ------------------------------------------------------------------ winmm
// waveOut* in winload64 accept data without playing it (winrun_directx); pause,
// restart and volume are consistent with that device. MCI has no devices.
fn waveOutPause(h: usize) callconv(W) u32 {
    return if (h == 0) 5 else 0; // MMSYSERR_INVALHANDLE
}
fn waveOutRestart(h: usize) callconv(W) u32 {
    return if (h == 0) 5 else 0;
}
fn waveOutSetVolume(h: usize, vol: u32) callconv(W) u32 {
    _ = h;
    _ = vol;
    return 0;
}
fn mciSendCommandA(dev: u32, msg: u32, flags: usize, param: usize) callconv(W) u32 {
    _ = dev;
    _ = msg;
    _ = flags;
    _ = param;
    return 263; // MCIERR_INVALID_DEVICE_NAME: no MCI devices are installed
}

// ------------------------------------------------------------------ msacm32
// No ACM codecs are installed: every stream request is ACMERR_NOTPOSSIBLE, as on
// Windows without the codec. FMOD Ex then uses its own decoders or reports it.
const ACMERR_NOTPOSSIBLE: u32 = 512;
fn acmStreamOpen(phas: ?*usize, had: usize, src: ?*const anyopaque, dst: ?*const anyopaque, filter: ?*const anyopaque, cb: usize, inst: usize, open: u32) callconv(W) u32 {
    _ = had;
    _ = src;
    _ = dst;
    _ = filter;
    _ = cb;
    _ = inst;
    _ = open;
    if (phas) |p| p.* = 0;
    return ACMERR_NOTPOSSIBLE;
}
fn acmFormatSuggest(had: usize, src: ?*const anyopaque, dst: ?*anyopaque, cb: u32, flags: u32) callconv(W) u32 {
    _ = had;
    _ = src;
    _ = dst;
    _ = cb;
    _ = flags;
    return ACMERR_NOTPOSSIBLE;
}
fn acmStreamNoHandle4(h: usize, a: usize, b: usize, c: usize) callconv(W) u32 {
    _ = h;
    _ = a;
    _ = b;
    _ = c;
    return 5; // MMSYSERR_INVALHANDLE: no stream can have been opened
}

// ------------------------------------------------------------------ ws2_32 / wldap32
/// inet_pton for AF_INET. AF_INET6 is not parsed yet: WSAEAFNOSUPPORT.
fn inet_pton(family: i32, src: ?[*:0]const u8, dst: ?*anyopaque) callconv(W) i32 {
    const s = src orelse return -1;
    const d = dst orelse return -1;
    if (family != 2) {
        lastError(10047); // WSAEAFNOSUPPORT
        return -1;
    }
    var out: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, std.mem.span(s), '.');
    var k: usize = 0;
    while (it.next()) |part| : (k += 1) {
        if (k == 4 or part.len == 0 or part.len > 3) return 0;
        for (part) |c| if (!std.ascii.isDigit(c)) return 0;
        out[k] = std.fmt.parseInt(u8, part, 10) catch return 0;
    }
    if (k != 4) return 0;
    @memcpy(@as([*]u8, @ptrCast(d))[0..4], &out);
    return 1;
}
/// Every wldap32 entry DS3 (its static libcurl) imports: the LDAP client is
/// absent, LDAP_UNAVAILABLE.
fn ldapUnavailable() callconv(W) usize {
    lastError(0x34);
    return 0;
}

// ------------------------------------------------------------------ d3d9 / d3dx / d3dcompiler
fn D3DPERF_GetStatus() callconv(W) u32 {
    return 0; // no PIX/profiler attached
}
fn D3DX11SaveTextureToFileW(ctx: usize, tex: usize, fmt: u32, file: ?[*:0]const u16) callconv(W) i32 {
    _ = ctx;
    _ = tex;
    _ = fmt;
    _ = file;
    return E_NOTIMPL;
}
fn D3DXCompileShader(src: usize, len: u32, defines: usize, include: usize, func: usize, profile: usize, flags: u32, shader: ?*usize, errors: ?*usize, table: ?*usize) callconv(W) i32 {
    _ = src;
    _ = len;
    _ = defines;
    _ = include;
    _ = func;
    _ = profile;
    _ = flags;
    inline for (.{ shader, errors, table }) |p| if (p) |q| {
        q.* = 0;
    };
    return E_NOTIMPL; // no HLSL compiler in WINS (shaders must ship compiled)
}
/// D3DGetBlobPart on a DXBC container: the input signature, output signature and
/// shader-bytecode chunks are copied into a new ID3DBlob; other parts E_NOTIMPL.
fn D3DGetBlobPart(src: ?[*]const u8, size: usize, part: u32, flags: u32, out: ?*?*anyopaque) callconv(W) i32 {
    _ = flags;
    const o = out orelse return E_POINTER;
    o.* = null;
    const s = src orelse return E_INVALIDARG;
    if (size < 32 or !std.mem.eql(u8, s[0..4], "DXBC")) return E_INVALIDARG;
    const tag: *const [4]u8 = switch (part) {
        0 => "ISGN", // D3D_BLOB_INPUT_SIGNATURE_BLOB
        1 => "OSGN", // D3D_BLOB_OUTPUT_SIGNATURE_BLOB
        else => return E_NOTIMPL,
    };
    const n = std.mem.readInt(u32, s[28..32], .little);
    if (32 + @as(usize, n) * 4 > size) return E_INVALIDARG;
    for (0..n) |k| {
        const off = std.mem.readInt(u32, s[32 + k * 4 ..][0..4], .little);
        if (off + 8 > size) return E_INVALIDARG;
        if (!std.mem.eql(u8, s[off..][0..4], tag)) continue;
        const len = std.mem.readInt(u32, s[off + 4 ..][0..4], .little);
        if (off + 8 + len > size) return E_INVALIDARG;
        const create = other(*const fn (usize, ?*?*anyopaque) callconv(W) i32, "d3dcompiler_47.dll", "D3DCreateBlob") orelse return E_NOTIMPL;
        var blob: ?*anyopaque = null;
        const hr = create(len + 8, &blob);
        if (hr != 0) return hr;
        // ID3DBlob::GetBufferPointer is vtable slot 3.
        const vt: [*]const usize = @ptrFromInt(@as(*const usize, @ptrCast(@alignCast(blob.?))).*);
        const ptr: *const fn (?*anyopaque) callconv(W) [*]u8 = @ptrFromInt(vt[3]);
        @memcpy(ptr(blob)[0 .. len + 8], s[off..][0 .. len + 8]);
        o.* = blob;
        return 0;
    }
    return E_INVALIDARG;
}

// ------------------------------------------------------------------ imm32
fn ImmDisableIME(tid: u32) callconv(W) i32 {
    _ = tid;
    return 1; // there is no IME in a WINS process
}

// ------------------------------------------------------------------ dinput8
// IDirectInput8 over wins_dinput.zig (keyboard, mouse, attached gamepads); the
// same object winrun32 exposes, with Win64 calling convention and pointer sizes.
const Di8Vtbl = extern struct {
    QueryInterface: *const fn (*anyopaque, ?*const anyopaque, ?*?*anyopaque) callconv(W) i32,
    AddRef: *const fn (*anyopaque) callconv(W) u32,
    Release: *const fn (*anyopaque) callconv(W) u32,
    CreateDevice: *const fn (*anyopaque, ?*const anyopaque, ?*?*anyopaque, ?*anyopaque) callconv(W) i32,
    EnumDevices: *const fn (*anyopaque, u32, ?*anyopaque, ?*anyopaque, u32) callconv(W) i32,
    GetDeviceStatus: *const fn (*anyopaque, ?*const anyopaque) callconv(W) i32,
    RunControlPanel: *const fn (*anyopaque, usize, u32) callconv(W) i32,
    Initialize: *const fn (*anyopaque, usize, u32) callconv(W) i32,
    FindDevice: *const fn (*anyopaque, ?*const anyopaque, ?*const anyopaque, ?*anyopaque) callconv(W) i32,
    EnumDevicesBySemantics: *const fn (*anyopaque, ?*const anyopaque, ?*anyopaque, ?*anyopaque, ?*anyopaque, u32) callconv(W) i32,
    ConfigureDevices: *const fn (*anyopaque, ?*anyopaque, ?*anyopaque, u32, ?*anyopaque) callconv(W) i32,
};
const Di8 = extern struct { vtbl: *const Di8Vtbl, refs: u32, wide: bool };
fn di8(this: *anyopaque) *Di8 {
    return @ptrCast(@alignCast(this));
}
fn di8QueryInterface(this: *anyopaque, riid: ?*const anyopaque, ppv: ?*?*anyopaque) callconv(W) i32 {
    _ = riid;
    const out = ppv orelse return E_POINTER;
    di8(this).refs += 1;
    out.* = this;
    return 0;
}
fn di8AddRef(this: *anyopaque) callconv(W) u32 {
    di8(this).refs += 1;
    return di8(this).refs;
}
fn di8Release(this: *anyopaque) callconv(W) u32 {
    if (di8(this).refs > 0) di8(this).refs -= 1;
    return di8(this).refs;
}
fn di8CreateDevice(this: *anyopaque, guid: ?*const anyopaque, ppv: ?*?*anyopaque, outer: ?*anyopaque) callconv(W) i32 {
    _ = outer;
    const out = ppv orelse return E_POINTER;
    return dinput.createDevice(@ptrCast(guid), di8(this).wide, out);
}
fn di8EnumDevices(this: *anyopaque, dev_type: u32, cb: ?*anyopaque, ref: ?*anyopaque, flags: u32) callconv(W) i32 {
    return dinput.enumDevices(dev_type, di8(this).wide, cb, ref, flags);
}
fn di8GetDeviceStatus(this: *anyopaque, guid: ?*const anyopaque) callconv(W) i32 {
    _ = this;
    return dinput.getDeviceStatus(@ptrCast(guid));
}
fn di8RunControlPanel(this: *anyopaque, hwnd: usize, flags: u32) callconv(W) i32 {
    _ = this;
    _ = hwnd;
    _ = flags;
    return @bitCast(@as(u32, 0x80004005)); // DIERR_GENERIC: no control panel
}
fn di8Initialize(this: *anyopaque, hinst: usize, version: u32) callconv(W) i32 {
    _ = this;
    _ = hinst;
    _ = version;
    return 0;
}
fn di8FindDevice(this: *anyopaque, guid: ?*const anyopaque, name: ?*const anyopaque, out: ?*anyopaque) callconv(W) i32 {
    return dinput.findDevice(@ptrCast(guid), name, di8(this).wide, @ptrCast(out));
}
fn di8EnumDevicesBySemantics(this: *anyopaque, name: ?*const anyopaque, fmt: ?*anyopaque, cb: ?*anyopaque, ref: ?*anyopaque, flags: u32) callconv(W) i32 {
    _ = this;
    _ = name;
    _ = fmt;
    _ = cb;
    _ = ref;
    _ = flags;
    return E_NOTIMPL; // action mapping is not implemented
}
fn di8ConfigureDevices(this: *anyopaque, cb: ?*anyopaque, params: ?*anyopaque, flags: u32, ref: ?*anyopaque) callconv(W) i32 {
    _ = this;
    _ = cb;
    _ = params;
    _ = flags;
    _ = ref;
    return E_NOTIMPL;
}
const di8_vtbl = Di8Vtbl{
    .QueryInterface = &di8QueryInterface,
    .AddRef = &di8AddRef,
    .Release = &di8Release,
    .CreateDevice = &di8CreateDevice,
    .EnumDevices = &di8EnumDevices,
    .GetDeviceStatus = &di8GetDeviceStatus,
    .RunControlPanel = &di8RunControlPanel,
    .Initialize = &di8Initialize,
    .FindDevice = &di8FindDevice,
    .EnumDevicesBySemantics = &di8EnumDevicesBySemantics,
    .ConfigureDevices = &di8ConfigureDevices,
};
fn DirectInput8Create(hinst: usize, version: u32, riid: ?*const anyopaque, ppv: ?*?*anyopaque, outer: ?*anyopaque) callconv(W) i32 {
    _ = hinst;
    _ = outer;
    const out = ppv orelse return E_INVALIDARG;
    const obj = std.heap.page_allocator.create(Di8) catch return E_OUTOFMEMORY;
    // IID_IDirectInput8W = {BF798031-...}; IID_IDirectInput8A = {BF798030-...}.
    const wide = if (riid) |r| @as(*align(1) const u32, @ptrCast(r)).* == 0xBF798031 else false;
    obj.* = .{ .vtbl = &di8_vtbl, .refs = 1, .wide = wide };
    if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:DInput64] DirectInput8Create(version 0x{x}, {s})\n", .{ version, if (wide) "W" else "A" });
    out.* = obj;
    return 0;
}

// ------------------------------------------------------------------ table
pub fn lookup(lib: []const u8, sym: []const u8) ?usize {
    const T = struct { []const u8, []const u8, *const anyopaque };
    const table = [_]T{
        .{ "kernel32.dll", "GetEnvironmentStrings", &GetEnvironmentStrings },
        .{ "kernel32.dll", "GetEnvironmentStringsA", &GetEnvironmentStrings },
        .{ "kernel32.dll", "FreeEnvironmentStringsA", &FreeEnvironmentStringsA },
        .{ "kernel32.dll", "GetStringTypeA", &GetStringTypeA },
        .{ "kernel32.dll", "GetSystemDefaultLangID", &GetSystemDefaultLangID },
        .{ "kernel32.dll", "GetUserDefaultLangID", &GetUserDefaultLangID },
        .{ "kernel32.dll", "GetSystemDefaultLCID", &GetSystemDefaultLCID },
        .{ "kernel32.dll", "GetSystemDefaultLocaleName", &GetSystemDefaultLocaleName },
        .{ "kernel32.dll", "SetThreadIdealProcessor", &SetThreadIdealProcessor },
        .{ "kernel32.dll", "HeapLock", &HeapLock },
        .{ "kernel32.dll", "HeapUnlock", &HeapUnlock },
        .{ "kernel32.dll", "HeapWalk", &HeapWalk },
        .{ "kernel32.dll", "GetWindowsDirectoryA", &GetWindowsDirectoryA },
        .{ "kernel32.dll", "OpenFile", &OpenFile },
        .{ "user32.dll", "GetForegroundWindow", &GetForegroundWindow },
        .{ "user32.dll", "SetActiveWindow", &SetActiveWindow },
        .{ "user32.dll", "GetTopWindow", &GetTopWindow },
        .{ "user32.dll", "AdjustWindowRect", &AdjustWindowRect },
        .{ "user32.dll", "SendInput", &SendInput },
        .{ "user32.dll", "CharLowerBuffA", &CharLowerBuffA },
        .{ "gdi32.dll", "GetGlyphOutlineW", &GetGlyphOutlineW },
        .{ "gdi32.dll", "GetKerningPairsW", &GetKerningPairsW },
        .{ "advapi32.dll", "GetUserNameW", &GetUserNameW },
        .{ "advapi32.dll", "InitializeSecurityDescriptor", &InitializeSecurityDescriptor },
        .{ "advapi32.dll", "SetSecurityDescriptorDacl", &SetSecurityDescriptorDacl },
        .{ "advapi32.dll", "RegOpenKeyA", &RegOpenKeyA },
        .{ "advapi32.dll", "RegEnumKeyA", &RegEnumKeyA },
        .{ "ole32.dll", "CLSIDFromString", &CLSIDFromString },
        .{ "winmm.dll", "waveOutPause", &waveOutPause },
        .{ "winmm.dll", "waveOutRestart", &waveOutRestart },
        .{ "winmm.dll", "waveOutSetVolume", &waveOutSetVolume },
        .{ "winmm.dll", "mciSendCommandA", &mciSendCommandA },
        .{ "msacm32.dll", "acmStreamOpen", &acmStreamOpen },
        .{ "msacm32.dll", "acmFormatSuggest", &acmFormatSuggest },
        .{ "msacm32.dll", "acmStreamSize", &acmStreamNoHandle4 },
        .{ "msacm32.dll", "acmStreamConvert", &acmStreamNoHandle4 },
        .{ "msacm32.dll", "acmStreamPrepareHeader", &acmStreamNoHandle4 },
        .{ "msacm32.dll", "acmStreamUnprepareHeader", &acmStreamNoHandle4 },
        .{ "msacm32.dll", "acmStreamClose", &acmStreamNoHandle4 },
        .{ "ws2_32.dll", "inet_pton", &inet_pton },
        .{ "d3d9.dll", "D3DPERF_GetStatus", &D3DPERF_GetStatus },
        .{ "d3dx11_43.dll", "D3DX11SaveTextureToFileW", &D3DX11SaveTextureToFileW },
        .{ "d3dx9_43.dll", "D3DXCompileShader", &D3DXCompileShader },
        .{ "d3dcompiler_43.dll", "D3DGetBlobPart", &D3DGetBlobPart },
        .{ "imm32.dll", "ImmDisableIME", &ImmDisableIME },
        .{ "dinput8.dll", "DirectInput8Create", &DirectInput8Create },
    };
    for (table) |e| if (std.mem.eql(u8, lib, e[0]) and std.mem.eql(u8, sym, e[1])) return @intFromPtr(e[2]);
    if (std.mem.eql(u8, lib, "wldap32.dll")) return @intFromPtr(&ldapUnavailable);
    return null;
}

test "GUID strings parse exactly" {
    const g = parseGuid("{BF798031-483A-4DA2-AA99-5D64ED369700}").?;
    try std.testing.expectEqual(@as(u32, 0xBF798031), g.d1);
    try std.testing.expectEqual(@as(u16, 0x483A), g.d2);
    try std.testing.expectEqual(@as(u8, 0xAA), g.d4[0]);
    try std.testing.expectEqual(@as(u8, 0x00), g.d4[7]);
    try std.testing.expect(parseGuid("{BF798031-483A-4DA2-AA99_5D64ED369700}") == null);
    try std.testing.expect(parseGuid("(BF798031-483A-4DA2-AA99-5D64ED369700)") == null);
}

test "inet_pton accepts dotted quads only" {
    var out: [4]u8 = undefined;
    try std.testing.expectEqual(@as(i32, 1), inet_pton(2, "192.168.0.255", &out));
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 0, 255 }, &out);
    try std.testing.expectEqual(@as(i32, 0), inet_pton(2, "256.1.1.1", &out));
    try std.testing.expectEqual(@as(i32, 0), inet_pton(2, "1.2.3", &out));
    try std.testing.expectEqual(@as(i32, 0), inet_pton(2, "1.2.3.4.5", &out));
    try std.testing.expectEqual(@as(i32, -1), inet_pton(23, "::1", &out));
}

test "security descriptor DACL bookkeeping" {
    var sd: SecurityDescriptor = undefined;
    try std.testing.expectEqual(@as(i32, 0), InitializeSecurityDescriptor(&sd, 2));
    try std.testing.expectEqual(@as(i32, 1), InitializeSecurityDescriptor(&sd, 1));
    try std.testing.expectEqual(@as(i32, 1), SetSecurityDescriptorDacl(&sd, 1, 0, 0));
    try std.testing.expectEqual(@as(u16, 0x4), sd.control);
    try std.testing.expectEqual(@as(i32, 1), SetSecurityDescriptorDacl(&sd, 0, 0x1234, 0));
    try std.testing.expectEqual(@as(u16, 0), sd.control);
}

test "GetStringTypeA CT_CTYPE1 classes" {
    var out: [4]u16 = undefined;
    try std.testing.expectEqual(@as(i32, 1), GetStringTypeA(0, 1, "A1 ,", 4, &out));
    try std.testing.expect(out[0] & 0x101 == 0x101 and out[0] & 0x080 != 0); // upper+alpha+hex
    try std.testing.expect(out[1] & 0x084 == 0x084); // digit+hex
    try std.testing.expect(out[2] & 0x048 == 0x048); // space+blank
    try std.testing.expect(out[3] & 0x010 != 0); // punct
    try std.testing.expectEqual(@as(i32, 0), GetStringTypeA(0, 2, "A", 1, &out));
}
