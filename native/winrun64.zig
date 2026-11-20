//! winload64: Linux-native loader for 64-bit Windows DLL graphs (no Wine).
//!
//! Loads a root PE32+ DLL and every DLL it imports that is present in --dll-dir,
//! binds imports across those images (by name, by ordinal, export forwarders) and
//! against the WINS shim table (winrun's kernel32/msvcrt/extra DLLs, api-set CRT),
//! gives each image its own implicit-TLS slot, sets up a GS-based TEB/PEB, runs TLS
//! callbacks and DllMain(PROCESS_ATTACH) dependencies-first, then calls the exports
//! named with --call and prints their results.
//!
//! THIS EXECUTES THE DLLS' MACHINE CODE IN THIS PROCESS. Therefore:
//!  * run ONLY inside the WINS cleanroom (winload64_box.py: bubblewrap, no network);
//!  * EVERY image must be pinned by SHA-256 (--pin NAME=HEX); an unpinned or
//!    mismatching file is refused before anything is mapped;
//!  * every import must resolve before the first instruction runs, otherwise the
//!    loader lists what is missing and exits without executing anything.
//!
//! Scope (everything else is refused, not guessed): PE32+ x86-64 DLLs, DIR64
//! relocations, images never mapped at ImageBase, no W+X sections, no CLR, no bound
//! imports. Delay imports are bound eagerly; a delay import with no implementation
//! is bound to a trap that reports it and exits only if it is actually called.
//! `.pdata` is validated and recorded but SEH dispatch is NOT implemented: a raised
//! exception still ends the process.
//!
//!   usage: winload64 --pin ROOT.dll=HEX [--pin DEP.dll=HEX ...] [--dll-dir DIR] [--check]
//!                    ROOT.dll [--call [DLL!]EXPORT [--arg N | --arg-str S ...] [--ret u32|i32|u64|str|outstr]] ...
//!   exit codes: 2 usage, 3 refused, 4 unresolved imports, 5 malformed image,
//!               6 mapping failed, 7 DllMain/TLS init failed,
//!               8 a trapped (unimplemented) import was called (--trap-unresolved),
//!               9 the loaded code crashed (crash report on stderr).
const std = @import("std");
const linux = std.os.linux;
const winrun = @import("winrun_impl.zig").GuiImpl(.none);
const threads = @import("winrun_threads.zig");
const seh64 = @import("winrun_seh64.zig");
const k32 = @import("winrun_kernel32.zig");
const steam64 = @import("winrun_steam64.zig");

const W: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

/// Deliberate defects for negative controls (winload64_bad_*.zig set `winload64_bug`
/// in their root file). The real loader has none.
pub const Bug = enum { none, shared_tls_index };
const bug: Bug = if (@hasDecl(@import("root"), "winload64_bug")) @import("root").winload64_bug else .none;

const Exit = enum(u8) { usage = 2, refused = 3, unresolved = 4, bad_image = 5, map_failed = 6, init_failed = 7 };

fn die(code: Exit, comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("winload64: " ++ fmt ++ "\n", args);
    std.process.exit(@intFromEnum(code));
}

fn rd(comptime T: type, b: []const u8, p: usize) ?T {
    if (p > b.len or @sizeOf(T) > b.len - p) return null;
    return std.mem.readInt(T, b[p..][0..@sizeOf(T)], .little);
}

fn need(comptime T: type, b: []const u8, p: usize, what: []const u8) T {
    return rd(T, b, p) orelse die(.bad_image, "truncated: {s} at 0x{x}", .{ what, p });
}

fn cstr(b: []const u8, p: usize, what: []const u8) []const u8 {
    if (p >= b.len) die(.bad_image, "{s} out of image (0x{x})", .{ what, p });
    const end = std.mem.indexOfScalarPos(u8, b, p, 0) orelse die(.bad_image, "{s} not terminated", .{what});
    if (end - p > 512) die(.bad_image, "{s} too long", .{what});
    return b[p..end];
}

const SCN_EXEC: u32 = 0x20000000;
const SCN_READ: u32 = 0x40000000;
const SCN_WRITE: u32 = 0x80000000;

const Section = struct { va: u32, vsize: u32, raw_ptr: u32, raw_size: u32, chars: u32 };
const Dir = struct { rva: u32, size: u32 };

const Image = struct {
    name: []const u8, // lower-case basename, e.g. "fixture_a.dll"
    full_path: []const u8, // Linux host path used to load this image
    is_dll: bool,
    base: usize,
    img: []u8,
    size_of_image: u32,
    size_of_headers: u32,
    entry_rva: u32,
    pdata_rva: u32 = 0,
    pdata_size: u32 = 0,
    secs: []Section,
    dirs: [16]Dir,
    deps: std.ArrayList(usize) = .empty, // indices into Loader.images
    tls_index: ?u32 = null,
    tls_template_rva: u32 = 0,
    tls_template_len: usize = 0,
    tls_zero_fill: usize = 0,
    tls_cb_rvas: std.ArrayList(u32) = .empty,
    pdata_entries: usize = 0,
    pref_base: u64 = 0, // OptionalHeader.ImageBase as linked (LDR entry OriginalBase)
    timestamp: u32 = 0,
    state: enum { mapped, binding, bound, initialized } = .mapped,
};

/// Delay imports that resolve to nothing (and, with --trap-unresolved, ANY unresolved
/// import) are bound to one of these traps; the trap reports which import was called
/// and exits 8. --trap-unresolved is a diagnostic instrument to find which missing
/// functions a DLL really calls; it never makes a run count as supported.
const max_traps = 1024;
var trap_names: [max_traps][]const u8 = undefined;
var n_traps: usize = 0;
fn trapCall(comptime k: usize) *const fn () callconv(W) noreturn {
    return &struct {
        fn f() callconv(W) noreturn {
            std.debug.print("winload64: TRAP called unimplemented import {s}\n", .{trap_names[k]});
            std.process.exit(8);
        }
    }.f;
}
const trap_table = blk: {
    @setEvalBranchQuota(20 * max_traps);
    var t: [max_traps]*const fn () callconv(W) noreturn = undefined;
    for (0..max_traps) |k| t[k] = trapCall(k);
    break :blk t;
};

var trap_all = false;

// ---------------------------------------------------------------- module registry
// GetModuleHandle*/LoadLibrary*/GetProcAddress over (a) the images winload64 mapped
// and (b) the system DLLs WINS emulates (pseudo-handles; never dereferenced by us).
// They take precedence over winrun's single-image stubs (GetProcAddress there is a
// stub that returns 0, GetModuleHandle only answers NULL).
var g_ld: ?*Loader = null;

var g_peb_ptr: usize = 0;
var g_ld_lock: std.atomic.Mutex = .unlocked;

const system_dlls = [_][]const u8{
    "kernel32.dll", "kernelbase.dll", "ntdll.dll",    "user32.dll",   "gdi32.dll",    "advapi32.dll",
    "ws2_32.dll",   "wsock32.dll",    "mswsock.dll",  "crypt32.dll",  "bcrypt.dll",   "ncrypt.dll",
    "ole32.dll",    "oleaut32.dll",   "shell32.dll",  "shlwapi.dll",  "iphlpapi.dll", "winhttp.dll",
    "dbghelp.dll",  "winmm.dll",      "powrprof.dll", "propsys.dll",  "ucrtbase.dll", "msvcrt.dll",
    "dsound.dll",
    "vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll",
    "version.dll",  "secur32.dll",    "dnsapi.dll",   "wintrust.dll", "userenv.dll",  "comctl32.dll",
    "imm32.dll",    "opengl32.dll",   "hid.dll",      "setupapi.dll", "psapi.dll",
    "xinput1_4.dll", "xinput1_3.dll", "xinput9_1_0.dll", "d3d11.dll", "dxgi.dll",
};
/// Pseudo-handle for system DLL k: high, page-aligned, distinct, never a real mapping.
fn sysHandle(k: usize) usize {
    return 0x7FFE_0000_0000 + (k << 20);
}

comptime {
    if (system_dlls.len > 64) @compileError("g_sys_loaded is a u64 bitmask");
}
/// Emulated system DLLs this process has "loaded" (imported, LoadLibrary'd or asked
/// for by GetModuleHandle). kernel32/kernelbase/ntdll are in every Windows process.
/// EnumProcessModules lists them: Mono resolves P/Invokes it cannot bind directly by
/// walking that list with GetProcAddress (Rewired's LoadLibrary P/Invoke does this).
var g_sys_loaded = std.atomic.Value(u64).init(0b111);

fn markSystemDll(raw: []const u8) void {
    var b: [272]u8 = undefined;
    const key = moduleKey(&b, raw);
    for (system_dlls, 0..) |d, k| if (std.mem.eql(u8, d, key)) {
        _ = g_sys_loaded.fetchOr(@as(u64, 1) << @intCast(k), .monotonic);
        return;
    };
}

const ERROR_MOD_NOT_FOUND: u32 = 126;
const ERROR_PROC_NOT_FOUND: u32 = 127;

fn setLastError(code: u32) void {
    const f = winrun.lookup("kernel32.dll", "SetLastError") orelse return;
    (@as(*const fn (u32) callconv(W) void, @ptrFromInt(f)))(code);
}

/// "C:\x\KERNEL32" -> "kernel32.dll"; api-sets fold onto their host DLL.
fn moduleKey(buf: []u8, raw: []const u8) []const u8 {
    var name = raw;
    if (std.mem.lastIndexOfAny(u8, name, "\\/")) |i| name = name[i + 1 ..];
    const n = @min(name.len, buf.len - 4);
    _ = std.ascii.lowerString(buf[0..n], name[0..n]);
    var out = buf[0..n];
    if (std.mem.indexOfScalar(u8, out, '.') == null) {
        @memcpy(buf[n..][0..4], ".dll");
        out = buf[0 .. n + 4];
    }
    if (std.mem.startsWith(u8, out, "api-ms-win-crt-")) return "ucrtbase.dll";
    if (std.mem.startsWith(u8, out, "api-ms-win-") or std.mem.startsWith(u8, out, "ext-ms-win-")) return "kernel32.dll";
    return out;
}

fn handleFor(key: []const u8) usize {
    if (steam64.isSteamClientDll(key)) {
        // Facade mode: like Windows, the module has no handle until loaded.
        if (g_ld) |ld| if (ld.pins.get(steam64_name) != null)
            return if (g_steam_facade_idx) |k| ld.images.items[k].base else 0;
        return steam64.getModuleHandle(key);
    }
    const ld = g_ld orelse return 0;
    if (ld.find(key)) |k| return ld.images.items[k].base;
    for (system_dlls, 0..) |d, k| if (std.mem.eql(u8, d, key)) {
        _ = g_sys_loaded.fetchOr(@as(u64, 1) << @intCast(k), .monotonic);
        return sysHandle(k);
    };
    return 0;
}

fn utf16Key(buf: []u8, w: [*:0]const u16) []const u8 {
    var tmp: [260]u8 = undefined;
    var n: usize = 0;
    while (w[n] != 0 and n < tmp.len) : (n += 1) tmp[n] = if (w[n] < 0x80) @intCast(w[n]) else '?';
    return moduleKey(buf, tmp[0..n]);
}

fn rootBase() usize {
    const ld = g_ld orelse return 0;
    return ld.images.items[0].base;
}

fn moduleByName(key: []const u8, what: []const u8) usize {
    const h = handleFor(key);
    if (h == 0) {
        std.debug.print("winload64: {s}({s}) -> not loaded/emulated (ERROR_MOD_NOT_FOUND)\n", .{ what, key });
        setLastError(ERROR_MOD_NOT_FOUND);
    }
    return h;
}

fn GetModuleHandleW(name: ?[*:0]const u16) callconv(W) usize {
    var b: [272]u8 = undefined;
    return if (name) |n| moduleByName(utf16Key(&b, n), "GetModuleHandleW") else rootBase();
}
fn GetModuleHandleA(name: ?[*:0]const u8) callconv(W) usize {
    var b: [272]u8 = undefined;
    return if (name) |n| moduleByName(moduleKey(&b, std.mem.span(n)), "GetModuleHandleA") else rootBase();
}
fn GetModuleHandleExW(flags: u32, name: ?*const anyopaque, out: ?*usize) callconv(W) i32 {
    const FROM_ADDRESS: u32 = 0x4;
    var h: usize = 0;
    if (flags & FROM_ADDRESS != 0) {
        const addr = @intFromPtr(name);
        if (g_ld) |ld| for (ld.images.items) |im| {
            if (addr >= im.base and addr < im.base + im.img.len) h = im.base;
        };
        if (h == 0) setLastError(ERROR_MOD_NOT_FOUND);
    } else h = GetModuleHandleW(@ptrCast(@alignCast(name)));
    if (out) |o| o.* = h;
    return @intFromBool(h != 0);
}
fn GetModuleHandleExA(flags: u32, name: ?*const anyopaque, out: ?*usize) callconv(W) i32 {
    const FROM_ADDRESS: u32 = 0x4;
    if (flags & FROM_ADDRESS != 0) return GetModuleHandleExW(flags, name, out);
    const h = GetModuleHandleA(@ptrCast(name));
    if (out) |o| o.* = h;
    return @intFromBool(h != 0);
}
fn wideToUtf8Tmp(w: [*:0]const u16, buf: []u8) []const u8 {
    var n: usize = 0;
    while (w[n] != 0 and n < buf.len - 1) : (n += 1) buf[n] = if (w[n] < 0x80) @intCast(w[n]) else '?';
    buf[n] = 0;
    return buf[0..n];
}

/// SetDllDirectoryW/A: one extra search directory (host path), searched after the
/// application directories. Empty = default search order. Guarded by g_ld_lock.
var g_dll_directory_buf: [1024]u8 = undefined;
var g_dll_directory_len: usize = 0;

fn setDllDirectoryUtf8(raw: ?[]const u8) i32 {
    ldLock();
    defer g_ld_lock.unlock();
    const r = raw orelse {
        g_dll_directory_len = 0;
        return 1;
    };
    if (r.len == 0) {
        g_dll_directory_len = 0;
        return 1;
    }
    var tbuf: [1024]u8 = undefined;
    const tr = k32.translateWinPath(r, &tbuf) orelse {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    };
    var t: []const u8 = tr;
    while (t.len > 1 and t[t.len - 1] == '/') t = t[0 .. t.len - 1];
    @memcpy(g_dll_directory_buf[0..t.len], t);
    g_dll_directory_len = t.len;
    return 1;
}
fn SetDllDirectoryW(name: ?[*:0]const u16) callconv(W) i32 {
    const n = name orelse return setDllDirectoryUtf8(null);
    var raw: [1024]u8 = undefined;
    return setDllDirectoryUtf8(wideToUtf8Tmp(n, &raw));
}
fn SetDllDirectoryA(name: ?[*:0]const u8) callconv(W) i32 {
    return setDllDirectoryUtf8(if (name) |n| std.mem.span(n) else null);
}

fn findDynamicDllPath(ld: *Loader, raw: []const u8, basename_key: []const u8) ?[]const u8 {
    if (ld.pins.get(basename_key) == null) return null;
    var path_buf: [1024]u8 = undefined;
    if (k32.translateWinPath(raw, &path_buf)) |tr| {
        if (std.Io.Dir.cwd().access(ld.io, tr, .{})) |_| {
            return ld.a.dupe(u8, tr) catch null;
        } else |_| {}
        // A full path whose case differs from disk (Win32 is case-insensitive).
        if (std.mem.lastIndexOfScalar(u8, tr, '/')) |slash| if (slash > 0) {
            if (ld.findInDirNoCase(tr[0..slash], basename_key)) |p| return p;
        };
    }
    if (ld.findInDllDirs(basename_key)) |p| return p;
    if (g_dll_directory_len != 0) return ld.findInDirNoCase(g_dll_directory_buf[0..g_dll_directory_len], basename_key);
    return null;
}

fn ldLock() void {
    while (!g_ld_lock.tryLock()) std.atomic.spinLoopHint();
}

// ---------------------------------------------------------------- steamclient64 facade
// Steam's DRM wrapper (SteamStub's steamdrmp.dll) resolves CreateInterface from
// steamclient64.dll, asks GetModuleHandleEx(FROM_ADDRESS) which module holds it,
// verifies Valve's signature on that file and compares the in-memory PE headers
// with it. When the launcher pins the host's real steamclient64.dll (shipped by
// Steam for Linux, the same file Proton copies into prefixes), WINS maps it as an
// image WITHOUT running any of its code -- no imports bound, no TLS callbacks, no
// DllMain -- and points every export at the Linux Steam bridge: bridged exports
// jump to SteamBridge64, the others to a trap that reports and stops. Same idea as
// Proton's steamclient trampolines, without Wine.
var g_steam_facade_idx: ?usize = null;

fn facadeTrampoline(at: [*]u8, target: usize) void {
    at[0] = 0xFF; // jmp qword [rip+0]
    at[1] = 0x25;
    std.mem.writeInt(u32, at[2..6], 0, .little);
    std.mem.writeInt(u64, at[6..14], target, .little);
}

/// Maps the pinned host steamclient64.dll as a facade. Caller holds g_ld_lock.
fn mapSteamClientFacade(ld: *Loader) usize {
    if (g_steam_facade_idx) |k| return ld.images.items[k].base;
    if (steam64.getModuleHandle(steam64_name) == 0) return 0; // no live Steam client
    var pb: [1024]u8 = undefined;
    const path = steam64.hostWindowsClientPath(&pb) orelse return 0;
    const idx = ld.map(path); // SHA-256 pin enforced by readPinned
    const im = &ld.images.items[idx];
    const d = im.dirs[0];
    if (d.size == 0) die(.bad_image, "steamclient64.dll has no exports", .{});
    const nfun = need(u32, im.img, d.rva + 20, "export functions count");
    const nnames = need(u32, im.img, d.rva + 24, "export names");
    const afun = need(u32, im.img, d.rva + 28, "export functions");
    const anames = need(u32, im.img, d.rva + 32, "export name ptrs");
    const aords = need(u32, im.img, d.rva + 36, "export ordinals");
    // Every export body must have room for the 14-byte jump before the next one.
    var rvas: [256]u32 = undefined;
    if (nfun > rvas.len) die(.refused, "steamclient64.dll: {d} exports (facade supports {d})", .{ nfun, rvas.len });
    for (0..nfun) |k| rvas[k] = need(u32, im.img, afun + k * 4, "export rva");
    std.mem.sort(u32, rvas[0..nfun], {}, std.sort.asc(u32));
    for (1..nfun) |k| if (rvas[k] != rvas[k - 1] and rvas[k] - rvas[k - 1] < 14)
        die(.refused, "steamclient64.dll: exports 0x{x}/0x{x} too close for a facade jump", .{ rvas[k - 1], rvas[k] });
    var bridged: usize = 0;
    var i: usize = 0;
    while (i < nnames) : (i += 1) {
        const n = cstr(im.img, need(u32, im.img, anames + i * 4, "export name rva"), "export name");
        const ord = need(u16, im.img, aords + i * 2, "export ordinal");
        const rva = need(u32, im.img, afun + @as(usize, ord) * 4, "export rva");
        if (!inExec(im.secs, rva) or rva + 14 > im.size_of_image) die(.refused, "steamclient64.dll: export {s} is not code", .{n});
        var target = steam64.bridgedExport(n);
        if (target != 0) {
            bridged += 1;
        } else if (n_traps < max_traps) {
            trap_names[n_traps] = std.fmt.allocPrint(ld.a, "steamclient64.dll!{s} (facade: not bridged)", .{n}) catch "?";
            target = @intFromPtr(trap_table[n_traps]);
            n_traps += 1;
        } else die(.refused, "steamclient64.dll: out of trap slots", .{});
        facadeTrampoline(im.img.ptr + rva, target);
    }
    im.state = .initialized; // its own code never runs
    ld.protectImage(idx);
    crash_images = ld.images.items;
    g_steam_facade_idx = idx;
    steam64.module_handle = im.base;
    std.debug.print("[WINS:SteamBridge64] mapped host steamclient64.dll as a facade at 0x{x} ({d}/{d} exports bridged)\n", .{ im.base, bridged, nnames });
    return im.base;
}
const steam64_name = "steamclient64.dll";

fn loadDynamicModule(raw: []const u8, what: []const u8) usize {
    if (std.c.getenv("WINS_TRACE") != null) std.debug.print("winload64: {s}(\"{s}\")\n", .{ what, raw });
    var b: [272]u8 = undefined;
    const key = moduleKey(&b, raw);
    ldLock();
    defer g_ld_lock.unlock();
    if (steam64.isSteamClientDll(key)) if (g_ld) |ld| if (ld.pins.get(steam64_name) != null) {
        const h = mapSteamClientFacade(ld);
        if (h == 0) setLastError(ERROR_MOD_NOT_FOUND);
        return h;
    };
    const h0 = handleFor(key);
    if (h0 != 0) return h0;
    if (g_ld) |ld| {
        if (findDynamicDllPath(ld, raw, key)) |disk_path| {
            const prev_count = ld.images.items.len;
            const idx = ld.map(disk_path);
            ld.bind(idx);
            if (ld.missing.items.len != 0) {
                die(.unresolved, "unresolved imports in dynamically loaded {s}:\n{s}", .{ key, ld.missing.items });
            }
            for (prev_count..ld.images.items.len) |pidx| {
                ld.protectImage(pidx);
                const im = ld.images.items[pidx];
                seh64.addExceptionTable(im.base, im.img.len, im.dirs[3].rva, im.dirs[3].size);
            }
            crash_images = ld.images.items;
            ld.initialize(idx);
            return ld.images.items[idx].base;
        }
    }
    std.debug.print("winload64: {s}({s}) -> not loaded/emulated (ERROR_MOD_NOT_FOUND) raw=\"{s}\"\n", .{ what, key, raw });
    setLastError(ERROR_MOD_NOT_FOUND);
    return 0;
}

fn LoadLibraryW(name: ?[*:0]const u16) callconv(W) usize {
    const n = name orelse return 0;
    var raw: [1024]u8 = undefined;
    return loadDynamicModule(wideToUtf8Tmp(n, &raw), "LoadLibraryW");
}
fn LoadLibraryA(name: ?[*:0]const u8) callconv(W) usize {
    const n = name orelse return 0;
    return loadDynamicModule(std.mem.span(n), "LoadLibraryA");
}
fn LoadLibraryExW(name: ?[*:0]const u16, file: usize, flags: u32) callconv(W) usize {
    _ = file;
    _ = flags;
    return LoadLibraryW(name);
}
fn LoadLibraryExA(name: ?[*:0]const u8, file: usize, flags: u32) callconv(W) usize {
    _ = file;
    _ = flags;
    return LoadLibraryA(name);
}

fn GetModuleFileNameW(h: usize, buf: ?[*]u16, n: u32) callconv(W) u32 {
    if (h == steam64.module_handle) {
        var path_buf: [2048]u8 = undefined;
        const path = steam64.fileName(h, &path_buf) orelse return 0;
        if (buf == null or n == 0) return @intCast(path.len + 1);
        const count = @min(path.len, n - 1);
        for (path[0..count], 0..) |ch, i| buf.?[i] = ch;
        buf.?[count] = 0;
        return @intCast(count);
    }
    const ld = g_ld orelse return 0;
    const host_path: []const u8 = if (h == 0) ld.images.items[0].full_path else blk: {
        for (ld.images.items) |im| if (im.base == h) break :blk im.full_path;
        for (system_dlls, 0..) |d, dk| if (sysHandle(dk) == h) break :blk d;
        setLastError(ERROR_MOD_NOT_FOUND);
        return 0;
    };
    const prefix = if (host_path.len >= 2 and host_path[1] == ':') "" else if (std.mem.startsWith(u8, host_path, "/")) "Z:" else "Z:\\";
    const total = prefix.len + host_path.len;
    if (buf == null or n == 0) return @intCast(total + 1);
    const max_copy = @min(total, n - 1);
    var i: usize = 0;
    while (i < max_copy) : (i += 1) {
        const ch = if (i < prefix.len) prefix[i] else host_path[i - prefix.len];
        buf.?[i] = if (ch == '/') '\\' else ch;
    }
    buf.?[max_copy] = 0;
    return @intCast(max_copy);
}

fn GetModuleFileNameA(h: usize, buf: ?[*]u8, n: u32) callconv(W) u32 {
    var wbuf: [1024]u16 = undefined;
    const cap = @min(n, 1024);
    const len = GetModuleFileNameW(h, &wbuf, cap);
    if (buf != null and n > 0) {
        const out_n = @min(len, n - 1);
        for (0..out_n) |i| buf.?[i] = @truncate(wbuf[i]);
        buf.?[out_n] = 0;
        return out_n;
    }
    return len;
}

const WinOverlapped = extern struct {
    Internal: usize,
    InternalHigh: usize,
    Offset: u32,
    OffsetHigh: u32,
    hEvent: usize,
};

fn fdForHandle(h: usize) ?i32 {
    return switch (h) {
        0xFFFFFFF6 => 0,
        0xFFFFFFF5 => 1,
        0xFFFFFFF4 => 2,
        else => if (h >= 0x1000 and h < 0x5000) @intCast(h - 0x1000) else null,
    };
}

fn winReadFile(h: usize, buf: ?[*]u8, n: u32, read_out: ?*u32, ov_raw: ?*WinOverlapped) callconv(W) i32 {
    if (buf == null and n != 0) {
        if (read_out) |r| r.* = 0;
        setLastError(87);
        return 0;
    }
    const fd = fdForHandle(h) orelse {
        if (read_out) |r| r.* = 0;
        setLastError(6);
        return 0;
    };
    if (n == 0) {
        if (read_out) |r| r.* = 0;
        return 1;
    }
    var done: usize = 0;
    const off_opt: ?i64 = if (ov_raw) |ov| @bitCast((@as(u64, ov.OffsetHigh) << 32) | ov.Offset) else null;
    while (done < n) {
        const rc = if (off_opt) |base_off|
            linux.pread(fd, buf.? + done, n - done, @intCast(base_off + @as(i64, @intCast(done))))
        else
            linux.read(fd, buf.? + done, n - done);
        const e = linux.errno(rc);
        if (e == .INTR) continue;
        if (e != .SUCCESS) {
            if (done > 0) break;
            if (read_out) |r| r.* = 0;
            setLastError(6);
            return 0;
        }
        if (rc == 0) break;
        done += rc;
    }
    if (ov_raw) |ov| {
        ov.Internal = 0;
        ov.InternalHigh = done;
        if (ov.hEvent != 0) _ = threads.setEvent(ov.hEvent);
    }
    if (read_out) |r| r.* = @intCast(done);
    return 1;
}

fn winWriteFile(h: usize, buf: ?[*]const u8, n: u32, written_out: ?*u32, ov_raw: ?*WinOverlapped) callconv(W) i32 {
    if (buf == null and n != 0) {
        if (written_out) |w| w.* = 0;
        setLastError(87);
        return 0;
    }
    const fd = fdForHandle(h) orelse {
        if (written_out) |w| w.* = 0;
        setLastError(6);
        return 0;
    };
    var done: usize = 0;
    const off_opt: ?i64 = if (ov_raw) |ov| @bitCast((@as(u64, ov.OffsetHigh) << 32) | ov.Offset) else null;
    while (done < n) {
        const rc = if (off_opt) |base_off|
            linux.pwrite(fd, buf.? + done, n - done, @intCast(base_off + @as(i64, @intCast(done))))
        else
            linux.write(fd, buf.? + done, n - done);
        const e = linux.errno(rc);
        if (e == .INTR) continue;
        if (e != .SUCCESS) break;
        if (rc == 0) break;
        done += rc;
    }
    if (ov_raw) |ov| {
        ov.Internal = 0;
        ov.InternalHigh = done;
        if (ov.hEvent != 0) _ = threads.setEvent(ov.hEvent);
    }
    if (written_out) |w| w.* = @intCast(done);
    return if (done == n) 1 else 0;
}

fn winCloseHandle(h: usize) callconv(W) i32 {
    if (threads.isOurs(h)) return @intFromBool(threads.closeHandle(h));
    if (k32.closeMappingHandle(h)) return 1;
    if (h >= 0x1003 and h < 0x5000) _ = linux.close(@intCast(h - 0x1000));
    return 1;
}

fn winCreateThread(sa: ?*anyopaque, stack_sz: usize, start: ?threads.StartFn, param: ?*anyopaque, flags: u32, tid: ?*u32) callconv(W) usize {
    _ = sa;
    const s = start orelse return 0;
    const h = threads.createThread(stack_sz, s, param, flags, tid);
    if (h == 0) setLastError(8);
    return h;
}
fn winBeginThreadEx(sa: ?*anyopaque, stack_sz: u32, start: ?threads.StartFn, param: ?*anyopaque, flags: u32, tid: ?*u32) callconv(W) usize {
    return winCreateThread(sa, stack_sz, start, param, flags, tid);
}
fn winEndThreadEx(code: u32) callconv(W) void {
    _ = threads.exitCurrentThread(code);
    linux.exit(@as(u8, @truncate(code)));
}
fn winExitThread(code: u32) callconv(W) noreturn {
    _ = threads.exitCurrentThread(code);
    linux.exit(@as(u8, @truncate(code)));
}
fn winGetCurrentThreadId() callconv(W) u32 {
    return threads.tidNow();
}
fn winResumeThread(h: usize) callconv(W) u32 {
    return threads.resumeThread(h);
}
fn winSuspendThread(h: usize) callconv(W) u32 {
    return threads.suspendThread(h);
}
fn winGetExitCodeThread(h: usize, code: ?*u32) callconv(W) i32 {
    const out = code orelse return 0;
    return if (threads.getExitCode(h, out)) |ok| @intFromBool(ok) else 0;
}
fn winGetThreadContext(h: usize, lp_ctx: ?*anyopaque) callconv(W) i32 {
    return @intFromBool(threads.getThreadContext(h, lp_ctx));
}
fn winOpenThread(access: u32, inherit: i32, tid: u32) callconv(W) usize {
    _ = access;
    _ = inherit;
    return threads.openThreadByTid(tid);
}
fn winDuplicateHandle(src_proc: usize, src_h: usize, tgt_proc: usize, tgt_h: ?*usize, access: u32, inherit: i32, options: u32) callconv(W) i32 {
    _ = src_proc;
    _ = tgt_proc;
    _ = access;
    _ = inherit;
    _ = options;
    const out = tgt_h orelse return 0;
    if (src_h == ~@as(usize, 1)) {
        out.* = threads.dupCurrentThread();
        return if (out.* != 0) 1 else 0;
    }
    const nh = threads.dupHandle(src_h);
    out.* = if (nh != 0) nh else src_h;
    return 1;
}
fn winCreateEventW(sa: ?*anyopaque, manual: i32, initial: i32, name: ?[*:0]const u16) callconv(W) usize {
    _ = sa;
    var tmp: [48]u8 = undefined;
    const n: ?[]const u8 = if (name) |w| wideToUtf8Tmp(w, &tmp) else null;
    return threads.createEvent(manual != 0, initial != 0, n);
}
fn winCreateEventA(sa: ?*anyopaque, manual: i32, initial: i32, name: ?[*:0]const u8) callconv(W) usize {
    _ = sa;
    return threads.createEvent(manual != 0, initial != 0, if (name) |p| std.mem.span(p) else null);
}
fn CreateEventExW(attrs: ?*anyopaque, name: ?[*:0]const u16, flags: u32, access: u32) callconv(W) usize {
    _ = access;
    return winCreateEventW(attrs, @intFromBool(flags & 1 != 0), @intFromBool(flags & 2 != 0), name);
}
fn winSetEvent(h: usize) callconv(W) i32 {
    return @intFromBool(threads.setEvent(h));
}
fn winResetEvent(h: usize) callconv(W) i32 {
    return @intFromBool(threads.resetEvent(h));
}
fn winPulseEvent(h: usize) callconv(W) i32 {
    return @intFromBool(threads.pulseEvent(h));
}
fn winCreateSemaphoreW(sa: ?*anyopaque, initial: i32, max: i32, name: ?[*:0]const u16) callconv(W) usize {
    _ = sa;
    var tmp: [48]u8 = undefined;
    const n: ?[]const u8 = if (name) |w| wideToUtf8Tmp(w, &tmp) else null;
    return threads.createSemaphore(initial, max, n);
}
fn winCreateSemaphoreA(sa: ?*anyopaque, initial: i32, max: i32, name: ?[*:0]const u8) callconv(W) usize {
    _ = sa;
    return threads.createSemaphore(initial, max, if (name) |p| std.mem.span(p) else null);
}
fn winCreateSemaphoreExW(sa: ?*anyopaque, initial: i32, max: i32, name: ?[*:0]const u16, flags: u32, access: u32) callconv(W) usize {
    _ = flags;
    _ = access;
    return winCreateSemaphoreW(sa, initial, max, name);
}
fn winReleaseSemaphore(h: usize, count: i32, prev: ?*i32) callconv(W) i32 {
    return @intFromBool(threads.releaseSemaphore(h, count, prev));
}
fn winCreateMutexW(sa: ?*anyopaque, initial_owner: i32, name: ?[*:0]const u16) callconv(W) usize {
    _ = sa;
    var tmp: [48]u8 = undefined;
    const n: ?[]const u8 = if (name) |w| wideToUtf8Tmp(w, &tmp) else null;
    return threads.createMutex(initial_owner != 0, n);
}
fn winCreateMutexA(sa: ?*anyopaque, initial_owner: i32, name: ?[*:0]const u8) callconv(W) usize {
    _ = sa;
    return threads.createMutex(initial_owner != 0, if (name) |p| std.mem.span(p) else null);
}
fn winReleaseMutex(h: usize) callconv(W) i32 {
    return @intFromBool(threads.releaseMutex(h));
}
fn winWaitForSingleObject(h: usize, ms: u32) callconv(W) u32 {
    if (std.c.getenv("WINS_TRACE") != null) {
        var b1: [128]u8 = undefined;
        const ra = @returnAddress();
        std.debug.print("[WINS:WAIT] tid={d} WFSO h=0x{x} ms={d} caller={s}\n", .{ linux.gettid(), h, ms, where(&b1, ra) });
    }
    return threads.waitOne(h, ms) orelse threads.WAIT_FAILED;
}
fn winWaitForSingleObjectEx(h: usize, ms: u32, alertable: i32) callconv(W) u32 {
    return threads.waitOneEx(h, ms, alertable != 0) orelse threads.WAIT_FAILED;
}
fn winWaitForMultipleObjects(count: u32, handles: ?[*]const usize, wait_all: i32, ms: u32) callconv(W) u32 {
    if (std.c.getenv("WINS_TRACE") != null) {
        var b1: [128]u8 = undefined;
        std.debug.print("[WINS:WAIT] tid={d} WFMO count={d} ms={d} caller={s}\n", .{ linux.gettid(), count, ms, where(&b1, @returnAddress()) });
    }
    const hs = handles orelse return threads.WAIT_FAILED;
    if (count == 0 or count > threads.MAXIMUM_WAIT_OBJECTS) return threads.WAIT_FAILED;
    return threads.waitMany(hs[0..count], wait_all != 0, ms) orelse threads.WAIT_FAILED;
}
fn winWaitForMultipleObjectsEx(count: u32, handles: ?[*]const usize, wait_all: i32, ms: u32, alertable: i32) callconv(W) u32 {
    const hs = handles orelse return threads.WAIT_FAILED;
    if (count == 0 or count > threads.MAXIMUM_WAIT_OBJECTS) return threads.WAIT_FAILED;
    return threads.waitManyEx(hs[0..count], wait_all != 0, ms, alertable != 0) orelse threads.WAIT_FAILED;
}

fn winSleepEx(ms: u32, alertable: i32) callconv(W) u32 {
    return threads.sleepEx(ms, alertable != 0);
}

fn winQueueUserAPC(callback: ?*anyopaque, h_thread: usize, data: usize) callconv(W) u32 {
    return @intFromBool(threads.queueUserApc(callback, h_thread, data));
}

fn winSignalObjectAndWait(h_signal: usize, h_wait: usize, ms: u32, alertable: i32) callconv(W) u32 {
    return threads.signalAndWait(h_signal, h_wait, ms, alertable != 0) orelse threads.WAIT_FAILED;
}

fn wideName(name: ?[*:0]const u16, tmp: *[48]u8) ?[]const u8 {
    return if (name) |w| wideToUtf8Tmp(w, tmp) else null;
}
fn openNamed(kind: threads.Kind, name: ?[]const u8) usize {
    const h = if (name) |n| threads.openNamed(kind, n) else 0;
    if (std.c.getenv("WINS_TRACE") != null) std.debug.print("winload64: Open{s}(\"{s}\") -> 0x{x}\n", .{ @tagName(kind), name orelse "(null)", h });
    if (h == 0) setLastError(2);
    return h;
}

/// IsBad*Ptr: probe every page of the range with process_vm_readv (EFAULT, never a
/// fault, when unmapped/PROT_NONE). Write access is then read from /proc/self/maps.
fn rangeReadable(p: usize, n: usize) bool {
    if (n == 0) return true;
    if (p == 0 or p +% n < p) return false;
    var byte: u8 = undefined;
    var at = p;
    while (true) {
        var local = [_]std.posix.iovec{.{ .base = @ptrCast(&byte), .len = 1 }};
        var remote = [_]std.posix.iovec_const{.{ .base = @ptrFromInt(at), .len = 1 }};
        const got = linux.process_vm_readv(linux.getpid(), &local, &remote, 0);
        if (linux.errno(got) != .SUCCESS or got != 1) return false;
        const next = (at & ~@as(usize, 4095)) + 4096;
        if (next >= p + n) return true;
        at = next;
    }
}
fn rangeWritable(p: usize, n: usize) bool {
    if (!rangeReadable(p, n)) return false;
    if (n == 0) return true;
    const fd = linux.open("/proc/self/maps", .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(fd) != .SUCCESS) return true;
    defer _ = linux.close(@intCast(fd));
    var buf: [65536]u8 = undefined;
    var carry: usize = 0;
    var want = p; // first byte not yet proven writable
    while (true) {
        const r = linux.read(@intCast(fd), buf[carry..].ptr, buf.len - carry);
        if (linux.errno(r) != .SUCCESS) return true;
        const total = carry + r;
        var it = std.mem.splitScalar(u8, buf[0..total], '\n');
        var consumed: usize = 0;
        while (it.next()) |line| {
            if (it.index == null and r != 0) break; // partial last line
            consumed = if (it.index) |ix| ix else total;
            const dash = std.mem.indexOfScalar(u8, line, '-') orelse continue;
            const sp = std.mem.indexOfScalar(u8, line, ' ') orelse continue;
            const lo = std.fmt.parseInt(usize, line[0..dash], 16) catch continue;
            const hi = std.fmt.parseInt(usize, line[dash + 1 .. sp], 16) catch continue;
            if (want >= lo and want < hi) {
                if (line.len < sp + 3 or line[sp + 2] != 'w') return false;
                want = hi;
                if (want >= p + n) return true;
            }
        }
        if (r == 0) return want >= p + n;
        carry = total - consumed;
        std.mem.copyForwards(u8, buf[0..carry], buf[consumed..total]);
    }
}
fn winIsBadReadPtr(p: usize, n: usize) callconv(W) i32 {
    const bad = !rangeReadable(p, n);
    if (std.c.getenv("WINS_TRACE") != null) {
        var b1: [128]u8 = undefined;
        var b2: [128]u8 = undefined;
        std.debug.print("winload64: IsBadReadPtr({s}, {d}) -> {} caller={s}\n", .{ where(&b2, p), n, bad, where(&b1, @returnAddress()) });
    }
    return @intFromBool(bad);
}
fn winIsBadCodePtr(p: usize) callconv(W) i32 { return @intFromBool(!rangeReadable(p, 1)); }
fn winIsBadWritePtr(p: usize, n: usize) callconv(W) i32 { return @intFromBool(!rangeWritable(p, n)); }

/// Named file mappings: none exist yet in winrun64. Report the name (WINS_TRACE)
/// and fail the way Windows does when no process created the object.
fn winOpenFileMappingA(access: u32, inherit: i32, name: ?[*:0]const u8) callconv(W) usize {
    _ = access;
    _ = inherit;
    if (std.c.getenv("WINS_TRACE") != null) std.debug.print("winload64: OpenFileMappingA(\"{s}\") -> 0\n", .{if (name) |p| std.mem.span(p) else "(null)"});
    setLastError(2);
    return 0;
}
fn winOpenFileMappingW(access: u32, inherit: i32, name: ?[*:0]const u16) callconv(W) usize {
    _ = access;
    _ = inherit;
    var b: [48]u8 = undefined;
    if (std.c.getenv("WINS_TRACE") != null) std.debug.print("winload64: OpenFileMappingW(\"{s}\") -> 0\n", .{wideName(name, &b) orelse "(null)"});
    setLastError(2);
    return 0;
}
fn winOpenEventA(access: u32, inherit: i32, name: ?[*:0]const u8) callconv(W) usize { _ = access; _ = inherit; return openNamed(.event, if (name) |p| std.mem.span(p) else null); }
fn winOpenEventW(access: u32, inherit: i32, name: ?[*:0]const u16) callconv(W) usize { _ = access; _ = inherit; var b: [48]u8 = undefined; return openNamed(.event, wideName(name, &b)); }
fn winOpenSemaphoreA(access: u32, inherit: i32, name: ?[*:0]const u8) callconv(W) usize { _ = access; _ = inherit; return openNamed(.semaphore, if (name) |p| std.mem.span(p) else null); }
fn winOpenSemaphoreW(access: u32, inherit: i32, name: ?[*:0]const u16) callconv(W) usize { _ = access; _ = inherit; var b: [48]u8 = undefined; return openNamed(.semaphore, wideName(name, &b)); }
fn winOpenMutexA(access: u32, inherit: i32, name: ?[*:0]const u8) callconv(W) usize { _ = access; _ = inherit; return openNamed(.mutex, if (name) |p| std.mem.span(p) else null); }
fn winOpenMutexW(access: u32, inherit: i32, name: ?[*:0]const u16) callconv(W) usize { _ = access; _ = inherit; var b: [48]u8 = undefined; return openNamed(.mutex, wideName(name, &b)); }
fn winCreateWaitableTimerA(attrs: ?*anyopaque, manual: i32, name: ?[*:0]const u8) callconv(W) usize { _ = attrs; const h = threads.createTimer(manual != 0, if (name) |p| std.mem.span(p) else null); if (h == 0) setLastError(8); return h; }
fn winCreateWaitableTimerW(attrs: ?*anyopaque, manual: i32, name: ?[*:0]const u16) callconv(W) usize { _ = attrs; var b: [48]u8 = undefined; const h = threads.createTimer(manual != 0, wideName(name, &b)); if (h == 0) setLastError(8); return h; }
fn winCreateWaitableTimerExW(attrs: ?*anyopaque, name: ?[*:0]const u16, flags: u32, access: u32) callconv(W) usize { _ = attrs; _ = access; var b: [48]u8 = undefined; const h = threads.createTimer(flags & 1 != 0, wideName(name, &b)); if (h == 0) setLastError(8); return h; }
fn winCreateWaitableTimerExA(attrs: ?*anyopaque, name: ?[*:0]const u8, flags: u32, access: u32) callconv(W) usize { _ = attrs; _ = access; const h = threads.createTimer(flags & 1 != 0, if (name) |p| std.mem.span(p) else null); if (h == 0) setLastError(8); return h; }
fn winSetWaitableTimer(h: usize, due: ?*const i64, period: i32, callback: ?*anyopaque, arg: ?*anyopaque, wake_resume: i32) callconv(W) i32 { _ = wake_resume; const d = due orelse { setLastError(87); return 0; }; const ok = threads.setTimer(h, d.*, period, callback, @intFromPtr(arg)); if (!ok) setLastError(6); return @intFromBool(ok); }
fn winSetWaitableTimerEx(h: usize, due: ?*const i64, period: i32, callback: ?*anyopaque, arg: ?*anyopaque, wake: ?*anyopaque, tolerable: u32) callconv(W) i32 { _ = wake; _ = tolerable; return winSetWaitableTimer(h, due, period, callback, arg, 0); }
fn winCancelWaitableTimer(h: usize) callconv(W) i32 { const ok = threads.cancelTimer(h); if (!ok) setLastError(6); return @intFromBool(ok); }

const INVALID_HANDLE_VALUE = ~@as(usize, 0);
fn winCreateIoCompletionPort(file: usize, existing: usize, key: usize, concurrent: u32) callconv(W) usize {
    _ = key; _ = concurrent;
    if (file != INVALID_HANDLE_VALUE) { setLastError(50); return 0; }
    if (existing != 0) { setLastError(87); return 0; }
    const h = threads.createCompletionPort(); if (h == 0) setLastError(8); return h;
}
fn winPostQueuedCompletionStatus(port: usize, bytes: u32, key: usize, overlapped: ?*anyopaque) callconv(W) i32 { const ok = threads.postCompletion(port, bytes, key, overlapped); if (!ok) setLastError(6); return @intFromBool(ok); }
fn winGetQueuedCompletionStatus(port: usize, bytes: ?*u32, key: ?*usize, overlapped: ?*?*anyopaque, ms: u32) callconv(W) i32 {
    if (!threads.isCompletionPort(port)) { setLastError(6); return 0; }
    const packet = threads.getCompletion(port, ms) orelse { if (bytes) |p| p.* = 0; if (key) |p| p.* = 0; if (overlapped) |p| p.* = null; setLastError(258); return 0; };
    if (bytes) |p| p.* = packet.bytes; if (key) |p| p.* = packet.key; if (overlapped) |p| p.* = packet.overlapped; return 1;
}
const OverlappedEntry = extern struct { key: usize, overlapped: ?*anyopaque, internal: usize, bytes: u32, pad: u32 = 0 };
fn winGetQueuedCompletionStatusEx(port: usize, entries: ?[*]OverlappedEntry, count: u32, removed: ?*u32, ms: u32, alertable: i32) callconv(W) i32 {
    _ = alertable; const out = entries orelse { setLastError(87); return 0; }; const nout = removed orelse { setLastError(87); return 0; };
    if (!threads.isCompletionPort(port)) { setLastError(6); return 0; }
    if (count == 0) { setLastError(87); return 0; }
    const first = threads.getCompletion(port, ms) orelse { nout.* = 0; setLastError(258); return 0; };
    out[0] = .{ .key = first.key, .overlapped = first.overlapped, .internal = 0, .bytes = first.bytes };
    var n: u32 = 1; while (n < count) : (n += 1) { const p = threads.getCompletion(port, 0) orelse break; out[n] = .{ .key = p.key, .overlapped = p.overlapped, .internal = 0, .bytes = p.bytes }; }
    nout.* = n; return 1;
}

fn winMsgWaitForMultipleObjectsEx(count: u32, handles: ?[*]const usize, ms: u32, wake_mask: u32, flags: u32) callconv(W) u32 {
    _ = wake_mask;
    const alertable = (flags & 0x2) != 0; // MWMO_ALERTABLE
    if (count == 0) {
        const result = threads.sleepEx(ms, alertable);
        return if (result == threads.WAIT_IO_COMPLETION) result else threads.WAIT_TIMEOUT;
    }
    const hs = handles orelse return threads.WAIT_FAILED;
    if (count > threads.MAXIMUM_WAIT_OBJECTS) return threads.WAIT_FAILED;
    const result = threads.waitManyEx(hs[0..count], (flags & 0x1) != 0, ms, alertable) orelse return threads.WAIT_FAILED;
    // The message queue is not implemented by this headless loader.
    return result;
}

fn psapiEnumProcessModules(hProcess: usize, lphModule: ?[*]usize, cb: u32, lpcbNeeded: ?*u32) callconv(W) i32 {
    _ = hProcess;
    const ld = g_ld orelse return 0;
    // The PE images first (the exe is entry 0, as on Windows), then the emulated system DLLs in use.
    var mods: [512]usize = undefined;
    var count: usize = 0;
    for (ld.images.items) |im| if (count < mods.len) {
        mods[count] = im.base;
        count += 1;
    };
    const sys = g_sys_loaded.load(.monotonic);
    for (0..system_dlls.len) |k| if (sys & (@as(u64, 1) << @intCast(k)) != 0 and count < mods.len) {
        mods[count] = sysHandle(k);
        count += 1;
    };
    if (lpcbNeeded) |p| p.* = @intCast(count * @sizeOf(usize));
    if (lphModule) |out| {
        const cap = cb / @sizeOf(usize);
        for (0..@min(count, cap)) |idx| out[idx] = mods[idx];
    }
    return 1;
}
fn psapiGetModuleInformation(hProcess: usize, hModule: usize, lpmodinfo: ?*extern struct { lpBaseOfDll: usize, SizeOfImage: u32, EntryPoint: usize }, cb: u32) callconv(W) i32 {
    _ = hProcess;
    const ld = g_ld orelse return 0;
    if (lpmodinfo == null or cb < 24) return 0;
    for (ld.images.items) |im| if (im.base == hModule) {
        lpmodinfo.?.* = .{ .lpBaseOfDll = im.base, .SizeOfImage = im.size_of_image, .EntryPoint = im.base + im.entry_rva };
        return 1;
    };
    return 0;
}
fn psapiGetModuleBaseNameW(hProcess: usize, hModule: usize, buf: ?[*]u16, nSize: u32) callconv(W) u32 {
    _ = hProcess;
    const ld = g_ld orelse return 0;
    if (buf == null or nSize == 0) return 0;
    const name: []const u8 = blk: {
        for (ld.images.items) |im| if (im.base == hModule) break :blk im.name;
        for (system_dlls, 0..) |d, k| if (sysHandle(k) == hModule) break :blk d;
        return 0;
    };
    const n = @min(name.len, nSize - 1);
    for (name[0..n], 0..) |ch, idx| buf.?[idx] = ch;
    buf.?[n] = 0;
    return @intCast(n);
}
fn psapiGetModuleFileNameExW(hProcess: usize, hModule: usize, buf: ?[*]u16, nSize: u32) callconv(W) u32 {
    _ = hProcess;
    return GetModuleFileNameW(hModule, buf, nSize);
}
fn FreeLibrary(h: usize) callconv(W) i32 {
    _ = h;
    return 1; // images stay mapped for the process lifetime
}
/// Diagnostic: WINS_DUMP_PE=<hex base>[,<path>] writes the in-memory PE image at
/// that base (SizeOfImage from its own header) when the guest resolves
/// MessageBoxA -- the moment a loader stub is about to report a failure.
fn dumpPeOnFailure() void {
    const spec = std.mem.span(std.c.getenv("WINS_DUMP_PE") orelse return);
    const comma = std.mem.indexOfScalar(u8, spec, ',');
    const base_s = spec[0 .. comma orelse spec.len];
    const base = if (std.mem.eql(u8, base_s, "root")) rootBase() else std.fmt.parseInt(usize, std.mem.trimStart(u8, base_s, "0x"), 16) catch return;
    const path = if (comma) |c| spec[c + 1 ..] else "/tmp/wins-pe-dump.bin";
    if (!rangeReadable(base, 0x400)) return;
    const hdr: [*]const u8 = @ptrFromInt(base);
    const e_lfanew = std.mem.readInt(u32, hdr[0x3c..0x40], .little);
    if (e_lfanew > 0x300) return;
    const size = std.mem.readInt(u32, hdr[e_lfanew + 0x50 ..][0..4], .little);
    var pz: [512]u8 = undefined;
    const path_z = std.fmt.bufPrintZ(&pz, "{s}", .{path}) catch return;
    const fd = linux.open(path_z.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
    if (linux.errno(fd) != .SUCCESS) return;
    defer _ = linux.close(@intCast(fd));
    var off: usize = 0;
    var zero: [4096]u8 = @splat(0);
    while (off < size) : (off += 4096) {
        const chunk = @min(4096, size - off);
        const src: [*]const u8 = if (rangeReadable(base + off, chunk)) @ptrFromInt(base + off) else &zero;
        _ = linux.write(@intCast(fd), src, chunk);
    }
    std.debug.print("winload64: dumped PE at 0x{x} ({d} bytes) to {s}\n", .{ base, size, path });
}

fn GetProcAddress(h: usize, name: ?[*:0]const u8) callconv(W) usize {
    if (name != null and @intFromPtr(name) >= 0x10000 and std.mem.eql(u8, std.mem.span(name.?), "MessageBoxA")) dumpPeOnFailure();
    if (h == steam64.module_handle) {
        const symbol = name orelse return 0;
        if (@intFromPtr(symbol) < 0x10000) return 0;
        const sym = std.mem.span(symbol);
        const impl = steam64.getProcAddress(h, sym);
        if (impl == 0) return 0;
        // Facade: hand out the export's address inside the real image (its jump
        // goes to `impl`), so callers that check which module holds it see Valve's.
        if (g_steam_facade_idx) |k| if (g_ld) |ld| if (ld.exportByName(k, sym, 0)) |a| return a;
        return impl;
    }
    const ld = g_ld orelse return 0;
    var symbuf: [16]u8 = undefined;
    const sym: []const u8 = if (@intFromPtr(name) < 0x10000)
        std.fmt.bufPrint(&symbuf, "#{d}", .{@intFromPtr(name)}) catch unreachable
    else
        std.mem.span(name.?);
    var lib: ?[]const u8 = null;
    for (ld.images.items) |im| if (im.base == h) {
        lib = im.name;
    };
    if (lib == null) for (system_dlls, 0..) |d, k| if (sysHandle(k) == h) {
        lib = d;
    };
    const l = lib orelse {
        setLastError(ERROR_MOD_NOT_FOUND);
        return 0;
    };
    const addr = ld.resolve(l, sym, 0) orelse {
        // Diagnostic (with --trap-unresolved): WINS_TRAP_GETPROC=<image> hands callers
        // inside that image a trap instead of NULL, so one run lists every function a
        // loader stub resolves and only the ones it really calls stop the process.
        if (trap_all and n_traps < max_traps) if (std.c.getenv("WINS_TRAP_GETPROC")) |only| {
            var b1: [128]u8 = undefined;
            if (std.ascii.startsWithIgnoreCase(where(&b1, @returnAddress()), std.mem.span(only))) {
                trap_names[n_traps] = std.fmt.allocPrint(std.heap.page_allocator, "{s}!{s} (GetProcAddress)", .{ l, sym }) catch "?";
                std.debug.print("winload64: GetProcAddress({s}, {s}) -> TRAP #{d}\n", .{ l, sym, n_traps });
                n_traps += 1;
                return @intFromPtr(trap_table[n_traps - 1]);
            }
        };
        std.debug.print("winload64: GetProcAddress({s}, {s}) -> not implemented (ERROR_PROC_NOT_FOUND)\n", .{ l, sym });
        setLastError(ERROR_PROC_NOT_FOUND);
        return 0;
    };
    if (std.c.getenv("WINS_TRACE") != null) {
        var b1: [128]u8 = undefined;
        std.debug.print("winload64: GetProcAddress({s}, {s}) -> 0x{x} caller={s}\n", .{ l, sym, addr, where(&b1, @returnAddress()) });
    }
    return addr;
}

// ---------------------------------------------------------------- virtual memory
// Windows semantics over mmap: regions reserved at 64 KiB granularity (MEM_RESERVE =
// PROT_NONE + NORESERVE), pages committed/decommitted inside a region with their own
// protection, MEM_RELEASE only at a region base, VirtualQuery/VirtualProtect answer
// from the same bookkeeping. Chromium's PartitionAlloc relies on all of it.
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_DECOMMIT: u32 = 0x4000;
const MEM_RELEASE: u32 = 0x8000;
const MEM_FREE: u32 = 0x10000;
const MEM_PRIVATE: u32 = 0x20000;
const MEM_IMAGE: u32 = 0x1000000;
const ERROR_INVALID_ADDRESS: u32 = 487;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
const GRAN: usize = 64 * 1024;
const PAGE: usize = 4096;

const Region = struct {
    base: usize,
    size: usize,
    alloc_protect: u32,
    pages: []u8, // per page: 0 = reserved, else the Windows PAGE_* protection (committed)
};
var regions: std.ArrayList(Region) = .empty;
var vm_lock: std.atomic.Mutex = .unlocked;
fn vmLock() void {
    while (!vm_lock.tryLock()) std.atomic.spinLoopHint();
}

fn vmAlloc() std.mem.Allocator {
    return std.heap.page_allocator;
}

fn linuxProt(p: u32) linux.PROT {
    return switch (p & 0xff) {
        0x01 => .{}, // PAGE_NOACCESS
        0x02 => .{ .READ = true },
        0x04, 0x08 => .{ .READ = true, .WRITE = true },
        0x10, 0x20 => .{ .READ = true, .EXEC = true },
        0x40, 0x80 => .{ .READ = true, .WRITE = true, .EXEC = true },
        else => .{ .READ = true, .WRITE = true },
    };
}

fn regionOf(addr: usize) ?*Region {
    for (regions.items) |*r| if (addr >= r.base and addr < r.base + r.size) return r;
    return null;
}

fn reserve(at: usize, size: usize, prot: u32) ?*Region {
    const len = std.mem.alignForward(usize, size, PAGE);
    var base: usize = 0;
    const flags: linux.MAP = .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .NORESERVE = true, .FIXED_NOREPLACE = at != 0 };
    if (at != 0) {
        if (at % GRAN != 0) return null;
        const rc = linux.mmap(@ptrFromInt(at), len, .{}, flags, -1, 0);
        if (linux.errno(rc) != .SUCCESS or rc != at) return null;
        base = rc;
    } else {
        // Over-reserve and trim so the region starts on the 64 KiB allocation granularity.
        const rc = linux.mmap(null, len + GRAN, .{}, flags, -1, 0);
        if (linux.errno(rc) != .SUCCESS) return null;
        base = std.mem.alignForward(usize, rc, GRAN);
        if (base > rc) _ = linux.munmap(@ptrFromInt(rc), base - rc);
        const tail = rc + len + GRAN - (base + len);
        if (tail > 0) _ = linux.munmap(@ptrFromInt(base + len), tail);
    }
    const pages = vmAlloc().alloc(u8, len / PAGE) catch {
        _ = linux.munmap(@ptrFromInt(base), len);
        return null;
    };
    @memset(pages, 0);
    regions.append(vmAlloc(), .{ .base = base, .size = len, .alloc_protect = prot, .pages = pages }) catch return null;
    return &regions.items[regions.items.len - 1];
}

fn VirtualAlloc(addr: ?*anyopaque, size: usize, kind: u32, prot: u32) callconv(W) ?*anyopaque {
    vmLock();
    defer vm_lock.unlock();
    if (size == 0 or kind & (MEM_COMMIT | MEM_RESERVE) == 0) {
        setLastError(ERROR_INVALID_PARAMETER);
        return null;
    }
    const want = @intFromPtr(addr);
    var r: *Region = undefined;
    var start: usize = undefined;
    if (want != 0 and regionOf(want) != null and kind & MEM_RESERVE == 0) {
        r = regionOf(want).?; // commit inside an existing reservation
        start = want & ~(PAGE - 1);
    } else if (kind & MEM_RESERVE != 0 or want == 0) {
        r = reserve(if (want != 0) want & ~(GRAN - 1) else 0, size + (want & (GRAN - 1)), prot) orelse {
            setLastError(if (want != 0) ERROR_INVALID_ADDRESS else ERROR_NOT_ENOUGH_MEMORY);
            return null;
        };
        start = if (want != 0) want & ~(PAGE - 1) else r.base;
        if (kind & MEM_COMMIT == 0) return @ptrFromInt(r.base);
    } else {
        setLastError(ERROR_INVALID_ADDRESS);
        return null;
    }
    const end = std.mem.alignForward(usize, (if (want != 0) want else r.base) + size, PAGE);
    if (end > r.base + r.size) {
        setLastError(ERROR_INVALID_ADDRESS);
        return null;
    }
    if (linux.errno(linux.mprotect(@ptrFromInt(start), end - start, linuxProt(prot))) != .SUCCESS) {
        setLastError(ERROR_NOT_ENOUGH_MEMORY);
        return null;
    }
    var pg = (start - r.base) / PAGE;
    while (pg < (end - r.base) / PAGE) : (pg += 1) r.pages[pg] = @truncate(if (prot & 0xff == 0) 4 else prot);
    return @ptrFromInt(if (want != 0) start else r.base);
}

fn VirtualFree(addr: ?*anyopaque, size: usize, kind: u32) callconv(W) i32 {
    vmLock();
    defer vm_lock.unlock();
    const a = @intFromPtr(addr);
    const r = regionOf(a) orelse {
        setLastError(ERROR_INVALID_ADDRESS);
        return 0;
    };
    if (kind & MEM_RELEASE != 0) {
        if (size != 0 or a != r.base) {
            setLastError(ERROR_INVALID_PARAMETER);
            return 0;
        }
        _ = linux.munmap(@ptrFromInt(r.base), r.size);
        vmAlloc().free(r.pages);
        _ = regions.swapRemove(@divExact(@intFromPtr(r) - @intFromPtr(regions.items.ptr), @sizeOf(Region)));
        return 1;
    }
    if (kind & MEM_DECOMMIT != 0) {
        const start = a & ~(PAGE - 1);
        const end = if (size == 0) r.base + r.size else std.mem.alignForward(usize, a + size, PAGE);
        if (end > r.base + r.size) {
            setLastError(ERROR_INVALID_PARAMETER);
            return 0;
        }
        // Drop the contents (next commit reads zeroes) and make the pages inaccessible.
        _ = linux.madvise(@ptrFromInt(start), end - start, linux.MADV.DONTNEED);
        _ = linux.mprotect(@ptrFromInt(start), end - start, .{});
        @memset(r.pages[(start - r.base) / PAGE .. (end - r.base) / PAGE], 0);
        return 1;
    }
    setLastError(ERROR_INVALID_PARAMETER);
    return 0;
}

fn VirtualProtect(addr: ?*anyopaque, size: usize, prot: u32, old: ?*u32) callconv(W) i32 {
    const a = @intFromPtr(addr);
    const start = a & ~(PAGE - 1);
    if (start == 0) {
        setLastError(ERROR_INVALID_ADDRESS);
        return 0;
    }
    const end = std.mem.alignForward(usize, a + @max(size, 1), PAGE);
    if (end <= start) {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    vmLock();
    defer vm_lock.unlock();
    if (regionOf(a)) |r| {
        if (end > r.base + r.size) {
            setLastError(ERROR_INVALID_ADDRESS);
            return 0;
        }
        const first = r.pages[(start - r.base) / PAGE];
        if (first == 0) {
            setLastError(ERROR_INVALID_ADDRESS); // reserved, not committed
            return 0;
        }
        if (old) |o| o.* = first;
        if (linux.errno(linux.mprotect(@ptrFromInt(start), end - start, linuxProt(prot))) != .SUCCESS) return 0;
        @memset(r.pages[(start - r.base) / PAGE .. (end - r.base) / PAGE], @truncate(prot));
        return 1;
    }
    // Outside our regions (image sections, stacks): honour it, report RW as the old value.
    if (old) |o| o.* = 0x04;
    const ok = linux.errno(linux.mprotect(@ptrFromInt(start), end - start, linuxProt(prot))) == .SUCCESS;
    if (wp_page != 0 and wp_page >= start and wp_page < end) {
        // Diagnostic watchpoint page: keep it closed, say who reprotected it.
        var wb: [128]u8 = undefined;
        std.debug.print("winload64: VirtualProtect(0x{x}, 0x{x}, 0x{x}) covers the watch page, from {s}\n", .{ a, size, prot, where(&wb, @returnAddress()) });
        _ = linux.mprotect(@ptrFromInt(wp_page), 4096, if (bp_mode) .{ .READ = true } else .{});
    }
    return @intFromBool(ok);
}

/// MEMORY_BASIC_INFORMATION (x64, 48 bytes).
const MBI = extern struct { BaseAddress: usize, AllocationBase: usize, AllocationProtect: u32, PartitionId: u16, _p: u16 = 0, RegionSize: usize, State: u32, Protect: u32, Type: u32, _q: u32 = 0 };

fn VirtualQuery(addr: ?*const anyopaque, out: ?*MBI, len: usize) callconv(W) usize {
    if (out == null or len < @sizeOf(MBI)) {
        setLastError(24); // ERROR_BAD_LENGTH
        return 0;
    }
    vmLock();
    defer vm_lock.unlock();
    const a = @intFromPtr(addr) & ~(PAGE - 1);
    var m: MBI = .{ .BaseAddress = a, .AllocationBase = 0, .AllocationProtect = 0, .PartitionId = 0, .RegionSize = PAGE, .State = MEM_FREE, .Protect = 0x01, .Type = 0 };
    if (regionOf(a)) |r| {
        var pg = (a - r.base) / PAGE;
        const st = r.pages[pg];
        const first = pg;
        while (pg < r.pages.len and r.pages[pg] == st) pg += 1; // run of identical pages
        m = .{ .BaseAddress = a, .AllocationBase = r.base, .AllocationProtect = r.alloc_protect, .PartitionId = 0, .RegionSize = (pg - first) * PAGE, .State = if (st == 0) MEM_RESERVE else MEM_COMMIT, .Protect = if (st == 0) 0 else st, .Type = MEM_PRIVATE };
    } else if (g_ld) |ld| {
        for (ld.images.items) |im| if (a >= im.base and a < im.base + im.img.len) {
            m = .{ .BaseAddress = a, .AllocationBase = im.base, .AllocationProtect = 0x80, .PartitionId = 0, .RegionSize = im.base + im.img.len - a, .State = MEM_COMMIT, .Protect = 0x20, .Type = MEM_IMAGE };
        };
        if (m.State == MEM_FREE and a != 0) {
            // Not ours: committed RW private memory if mapped (stack, heap), else free.
            const probe = linux.madvise(@ptrFromInt(a), PAGE, linux.MADV.NORMAL);
            if (linux.errno(probe) == .SUCCESS) m = .{ .BaseAddress = a, .AllocationBase = a, .AllocationProtect = 0x04, .PartitionId = 0, .RegionSize = PAGE, .State = MEM_COMMIT, .Protect = 0x04, .Type = MEM_PRIVATE };
        }
    }
    out.?.* = m;
    if (std.c.getenv("WINS_TRACE_VQ") != null) {
        var b1: [128]u8 = undefined;
        std.debug.print("winload64: VirtualQuery(0x{x}) -> base=0x{x} alloc=0x{x} size=0x{x} state=0x{x} prot=0x{x} type=0x{x} caller={s}\n", .{ @intFromPtr(addr), m.BaseAddress, m.AllocationBase, m.RegionSize, m.State, m.Protect, m.Type, where(&b1, @returnAddress()) });
    }
    return @sizeOf(MBI);
}

fn VirtualLock(addr: ?*anyopaque, size: usize) callconv(W) i32 {
    _ = addr;
    _ = size;
    return 1; // advisory: pages stay resident enough for a cleanroom process
}
fn VirtualUnlock(addr: ?*anyopaque, size: usize) callconv(W) i32 {
    _ = addr;
    _ = size;
    return 1;
}

const steam_active_process_key: usize = 0x7FFD_5354_5049_4400;
const steam_process_handle: usize = 0x7FFD_5354_5052_0001;
var steam_process_handle_pid: u32 = 0;

fn OpenProcess(access: u32, inherit: u32, pid: u32) callconv(W) usize {
    if (steam64.isSteamPidAlive(pid)) {
        steam_process_handle_pid = pid;
        return steam_process_handle;
    }
    const fallback = winrun.lookup("kernel32.dll", "OpenProcess") orelse return 0;
    const call: *const fn (u32, u32, u32) callconv(W) usize = @ptrFromInt(fallback);
    return call(access, inherit, pid);
}

fn GetExitCodeProcess(process: usize, code: ?*u32) callconv(W) u32 {
    if (process == steam_process_handle) {
        if (code == null) return 0;
        code.?.* = if (steam64.isSteamPidAlive(steam_process_handle_pid)) 259 else 0;
        return 1;
    }
    const fallback = winrun.lookup("kernel32.dll", "GetExitCodeProcess") orelse return 0;
    const call: *const fn (usize, ?*u32) callconv(W) u32 = @ptrFromInt(fallback);
    return call(process, code);
}

fn RegOpenKeyExA(hKey: usize, subKey: ?[*:0]const u8, options: u32, desired: u32, result: ?*usize) callconv(W) i32 {
    if (@as(u32, @truncate(hKey)) == 0x80000001) {
        if (subKey) |p| {
            if (std.ascii.eqlIgnoreCase(std.mem.span(p), "Software\\Valve\\Steam\\ActiveProcess")) {
                if (result) |out| out.* = steam_active_process_key;
                return 0;
            }
        }
    }
    const fallback = @import("winrun_extra_dlls.zig").lookupAdvapi32("RegOpenKeyExA") orelse return 127;
    const call: *const fn (usize, ?[*:0]const u8, u32, u32, ?*usize) callconv(W) i32 = @ptrFromInt(fallback);
    const rc = call(hKey, subKey, options, desired, result);
    regTrace("RegOpenKeyExA", hKey, if (subKey) |p| std.mem.span(p) else "", rc);
    return rc;
}

fn RegQueryValueExA(hKey: usize, name: ?[*:0]const u8, reserved: ?*u32, valueType: ?*u32, data: ?[*]u8, size: ?*u32) callconv(W) i32 {
    if (hKey == steam_active_process_key and name != null and std.ascii.eqlIgnoreCase(std.mem.span(name.?), "pid")) {
        return steam64.querySteamPidValue(steam64.steamClientPid(), valueType, data, size);
    }
    if (hKey == steam_active_process_key and name != null and std.ascii.eqlIgnoreCase(std.mem.span(name.?), "SteamClientDll64")) {
        return steam64.querySteamClientDllValue(valueType, data, size);
    }
    const fallback = @import("winrun_extra_dlls.zig").lookupAdvapi32("RegQueryValueExA") orelse return 127;
    const call: *const fn (usize, ?[*:0]const u8, ?*u32, ?*u32, ?[*]u8, ?*u32) callconv(W) i32 = @ptrFromInt(fallback);
    const rc = call(hKey, name, reserved, valueType, data, size);
    regTrace("RegQueryValueExA", hKey, if (name) |p| std.mem.span(p) else "", rc);
    return rc;
}

fn regTrace(comptime what: []const u8, hKey: usize, name: []const u8, rc: i32) void {
    if (std.c.getenv("WINS_TRACE") != null) std.debug.print("winload64: " ++ what ++ "(0x{x}, \"{s}\") -> {d}\n", .{ hKey, name, rc });
}

fn RegOpenKeyExW(hKey: usize, subKey: ?[*:0]const u16, options: u32, desired: u32, result: ?*usize) callconv(W) i32 {
    var b: [272]u8 = undefined;
    const sub: []const u8 = if (subKey) |w| wideToUtf8Tmp(w, &b) else "";
    if (@as(u32, @truncate(hKey)) == 0x80000001 and std.ascii.eqlIgnoreCase(sub, "Software\\Valve\\Steam\\ActiveProcess")) {
        if (result) |out| out.* = steam_active_process_key;
        regTrace("RegOpenKeyExW", hKey, sub, 0);
        return 0;
    }
    const fallback = @import("winrun_extra_dlls.zig").lookupAdvapi32("RegOpenKeyExW") orelse return 127;
    const call: *const fn (usize, ?[*:0]const u16, u32, u32, ?*usize) callconv(W) i32 = @ptrFromInt(fallback);
    const rc = call(hKey, subKey, options, desired, result);
    regTrace("RegOpenKeyExW", hKey, sub, rc);
    return rc;
}

/// REG_SZ as UTF-16 (RegQueryValueExW): size in bytes including the NUL.
fn writeRegSzW(value: []const u8, value_type: ?*u32, data: ?[*]u8, size: ?*u32) i32 {
    const bytes_needed: u32 = @intCast((value.len + 1) * 2);
    if (value_type) |out| out.* = 1;
    if (size) |out| {
        const supplied = out.*;
        out.* = bytes_needed;
        if (data) |dst| {
            if (supplied < bytes_needed) return 234;
            for (value, 0..) |c, k| std.mem.writeInt(u16, dst[k * 2 ..][0..2], c, .little);
            std.mem.writeInt(u16, dst[value.len * 2 ..][0..2], 0, .little);
        }
    } else if (data != null) return 87;
    return 0;
}

fn RegQueryValueExW(hKey: usize, name: ?[*:0]const u16, reserved: ?*u32, valueType: ?*u32, data: ?[*]u8, size: ?*u32) callconv(W) i32 {
    var b: [272]u8 = undefined;
    const n: []const u8 = if (name) |w| wideToUtf8Tmp(w, &b) else "";
    if (hKey == steam_active_process_key) {
        const rc: i32 = if (std.ascii.eqlIgnoreCase(n, "pid"))
            steam64.querySteamPidValue(steam64.steamClientPid(), valueType, data, size)
        else if (std.ascii.eqlIgnoreCase(n, "SteamClientDll64")) blk: {
            var path_buf: [2048]u8 = undefined;
            const path = steam64.fileName(steam64.module_handle, &path_buf) orelse break :blk 2;
            break :blk writeRegSzW(path, valueType, data, size);
        } else 2;
        regTrace("RegQueryValueExW[ActiveProcess]", hKey, n, rc);
        return rc;
    }
    const fallback = @import("winrun_extra_dlls.zig").lookupAdvapi32("RegQueryValueExW") orelse return 127;
    const call: *const fn (usize, ?[*:0]const u16, ?*u32, ?*u32, ?[*]u8, ?*u32) callconv(W) i32 = @ptrFromInt(fallback);
    const rc = call(hKey, name, reserved, valueType, data, size);
    regTrace("RegQueryValueExW", hKey, n, rc);
    return rc;
}

const gaps64 = @import("winrun_win64_gaps.zig");
fn gapsSetLastError(code: u32) void {
    setLastError(code);
}
fn gapsResolve(lib: []const u8, sym: []const u8) ?usize {
    if (registryOverride(lib, sym)) |a| return a;
    return winrun.lookup(shimLibrary(lib), sym);
}

fn registryOverride(lib: []const u8, sym: []const u8) ?usize {
    var b: [272]u8 = undefined;
    const key = moduleKey(&b, lib);
    if (std.mem.eql(u8, key, "advapi32.dll")) {
        if (std.mem.eql(u8, sym, "RegOpenKeyExA")) return @intFromPtr(&RegOpenKeyExA);
        if (std.mem.eql(u8, sym, "RegQueryValueExA")) return @intFromPtr(&RegQueryValueExA);
        if (std.mem.eql(u8, sym, "RegOpenKeyExW")) return @intFromPtr(&RegOpenKeyExW);
        if (std.mem.eql(u8, sym, "RegQueryValueExW")) return @intFromPtr(&RegQueryValueExW);
    }
    if (std.mem.eql(u8, key, "kernel32.dll") or std.mem.eql(u8, key, "kernelbase.dll")) {
        if (std.mem.eql(u8, sym, "OpenProcess")) return @intFromPtr(&OpenProcess);
        if (std.mem.eql(u8, sym, "GetExitCodeProcess")) return @intFromPtr(&GetExitCodeProcess);
    }
    if (std.mem.eql(u8, key, "ntdll.dll")) {
        if (@import("winrun_ntdll64.zig").lookup(sym)) |a| return a;
    }
    if (std.mem.eql(u8, key, "d3dcompiler_43.dll") or std.mem.eql(u8, key, "d3dcompiler_47.dll") or std.mem.eql(u8, key, "d3dcompiler.dll")) {
        // Real ID3DBlob / ID3D11ShaderReflection (winrun_directx only had NULL stubs).
        const refl = @import("wins_d3d_reflect.zig");
        if (std.mem.eql(u8, sym, "D3DCreateBlob")) return @intFromPtr(&refl.createBlob);
        if (std.mem.eql(u8, sym, "D3DReflect")) return @intFromPtr(&refl.reflect);
    }
    if (gaps64.lookup(key, sym)) |a| {
        // Only where nothing else implements it (the gaps module never shadows).
        if (winrun.lookup(shimLibrary(lib), sym) == null) return a;
    }
    if (@import("wins_audio64.zig").lookupOverride(key, sym)) |a| return a;
    if (@import("winload64_sync.zig").lookup(key, sym)) |a| return a;
    if (std.mem.eql(u8, key, "ucrtbase.dll") or std.mem.eql(u8, key, "msvcrt.dll") or std.ascii.startsWithIgnoreCase(lib, "vcruntime140")) {
        if (std.mem.eql(u8, sym, "_beginthreadex")) return @intFromPtr(&winBeginThreadEx);
        if (std.mem.eql(u8, sym, "_endthreadex")) return @intFromPtr(&winEndThreadEx);
        if (@import("winload64_ucrt.zig").lookup(sym)) |a| return a;
    }
    if (std.mem.eql(u8, key, "psapi.dll")) {
        const ptbl = .{
            .{ "EnumProcessModules", &psapiEnumProcessModules },
            .{ "GetModuleInformation", &psapiGetModuleInformation },
            .{ "GetModuleBaseNameW", &psapiGetModuleBaseNameW },
            .{ "GetModuleFileNameExW", &psapiGetModuleFileNameExW },
        };
        inline for (ptbl) |e| if (std.mem.eql(u8, sym, e[0])) return @intFromPtr(e[1]);
        return null;
    }
    if (std.mem.eql(u8, key, "user32.dll") and std.mem.eql(u8, sym, "MsgWaitForMultipleObjectsEx"))
        return @intFromPtr(&winMsgWaitForMultipleObjectsEx);
    if (!std.mem.eql(u8, key, "kernel32.dll") and !std.ascii.eqlIgnoreCase(lib, "kernelbase.dll")) return null;
    const table = .{
        .{ "GetModuleHandleW", &GetModuleHandleW },       .{ "GetModuleHandleA", &GetModuleHandleA },
        .{ "GetModuleHandleExW", &GetModuleHandleExW },   .{ "GetModuleHandleExA", &GetModuleHandleExA },
        .{ "GetModuleFileNameW", &GetModuleFileNameW },   .{ "GetModuleFileNameA", &GetModuleFileNameA },
        .{ "LoadLibraryW", &LoadLibraryW },               .{ "LoadLibraryA", &LoadLibraryA },
        .{ "LoadLibraryExW", &LoadLibraryExW },           .{ "LoadLibraryExA", &LoadLibraryExA },
        .{ "SetDllDirectoryW", &SetDllDirectoryW },       .{ "SetDllDirectoryA", &SetDllDirectoryA },
        .{ "FreeLibrary", &FreeLibrary },                 .{ "GetProcAddress", &GetProcAddress },
        .{ "VirtualAlloc", &VirtualAlloc },               .{ "VirtualFree", &VirtualFree },
        .{ "VirtualProtect", &VirtualProtect },           .{ "VirtualQuery", &VirtualQuery },
        .{ "VirtualLock", &VirtualLock },                 .{ "VirtualUnlock", &VirtualUnlock },
        .{ "ReadFile", &winReadFile },                    .{ "WriteFile", &winWriteFile },
        .{ "CloseHandle", &winCloseHandle },
        .{ "CreateThread", &winCreateThread },            .{ "ExitThread", &winExitThread },
        .{ "GetCurrentThreadId", &winGetCurrentThreadId }, .{ "ResumeThread", &winResumeThread },
        .{ "SuspendThread", &winSuspendThread },          .{ "GetExitCodeThread", &winGetExitCodeThread },
        .{ "GetThreadContext", &winGetThreadContext },    .{ "OpenThread", &winOpenThread },
        .{ "DuplicateHandle", &winDuplicateHandle },
        .{ "CreateEventW", &winCreateEventW },            .{ "CreateEventA", &winCreateEventA },
        .{ "CreateEventExW", &CreateEventExW },           .{ "SetEvent", &winSetEvent },
        .{ "ResetEvent", &winResetEvent },                .{ "PulseEvent", &winPulseEvent },
        .{ "CreateSemaphoreW", &winCreateSemaphoreW },    .{ "CreateSemaphoreA", &winCreateSemaphoreA },
        .{ "CreateSemaphoreExW", &winCreateSemaphoreExW },
        .{ "ReleaseSemaphore", &winReleaseSemaphore },    .{ "CreateMutexW", &winCreateMutexW },
        .{ "CreateMutexA", &winCreateMutexA },            .{ "ReleaseMutex", &winReleaseMutex },
        .{ "WaitForSingleObject", &winWaitForSingleObject }, .{ "WaitForSingleObjectEx", &winWaitForSingleObjectEx },
        .{ "WaitForMultipleObjects", &winWaitForMultipleObjects }, .{ "WaitForMultipleObjectsEx", &winWaitForMultipleObjectsEx },
        .{ "SleepEx", &winSleepEx }, .{ "QueueUserAPC", &winQueueUserAPC },
        .{ "SignalObjectAndWait", &winSignalObjectAndWait },
        .{ "OpenEventA", &winOpenEventA }, .{ "OpenEventW", &winOpenEventW },
        .{ "IsBadReadPtr", &winIsBadReadPtr }, .{ "IsBadWritePtr", &winIsBadWritePtr }, .{ "IsBadCodePtr", &winIsBadCodePtr },
        .{ "OpenFileMappingA", &winOpenFileMappingA }, .{ "OpenFileMappingW", &winOpenFileMappingW },
        .{ "OpenSemaphoreA", &winOpenSemaphoreA }, .{ "OpenSemaphoreW", &winOpenSemaphoreW },
        .{ "OpenMutexA", &winOpenMutexA }, .{ "OpenMutexW", &winOpenMutexW },
        .{ "CreateWaitableTimerA", &winCreateWaitableTimerA }, .{ "CreateWaitableTimerW", &winCreateWaitableTimerW },
        .{ "CreateWaitableTimerExA", &winCreateWaitableTimerExA }, .{ "CreateWaitableTimerExW", &winCreateWaitableTimerExW },
        .{ "SetWaitableTimer", &winSetWaitableTimer }, .{ "SetWaitableTimerEx", &winSetWaitableTimerEx }, .{ "CancelWaitableTimer", &winCancelWaitableTimer },
        .{ "CreateIoCompletionPort", &winCreateIoCompletionPort }, .{ "GetQueuedCompletionStatus", &winGetQueuedCompletionStatus },
        .{ "GetQueuedCompletionStatusEx", &winGetQueuedCompletionStatusEx }, .{ "PostQueuedCompletionStatus", &winPostQueuedCompletionStatus },
    };
    inline for (table) |e| if (std.mem.eql(u8, sym, e[0])) return @intFromPtr(e[1]);
    return null;
}

// ---------------------------------------------------------------- crash report
// A fault inside a loaded image (e.g. MSVC __fastfail = `int 0x29`) is reported as
// signal, RIP and fault address mapped to IMAGE+RVA, the general registers, and the
// stack words that point into executable sections (candidate return addresses).
// Exit 9. Instrument only: a crash report never makes a run count as supported.
var crash_images: []const Image = &.{};

fn where(buf: []u8, addr: u64) []const u8 {
    for (crash_images) |im| if (addr >= im.base and addr < im.base + im.img.len)
        return std.fmt.bufPrint(buf, "{s}+0x{x}", .{ im.name, addr - im.base }) catch "?";
    return std.fmt.bufPrint(buf, "0x{x}", .{addr}) catch "?";
}

// Diagnostic single-step ring (WINS_STEP_AFTER_INT2D=<steps>): rips executed
// after the first int 0x2d resumes, dumped by the crash report.
var step_ring: [4096]u64 = [_]u64{0} ** 4096;
var step_rsp: [4096]u64 = [_]u64{0} ** 4096;
var step_n: usize = 0;
var step_left: usize = 0;
var step_tid: i32 = 0; // when non-zero, only this thread records/keeps TF
// Stack write tracer (WINS_STEP_FROM_VEH=<steps>): from the first
// AddVectoredExceptionHandler, diff a stack window after every step.
const WIN_LO: usize = 0x1000;
const WIN_HI: usize = 0x3000;
var win_base: usize = 0;
var win_prev: [(WIN_LO + WIN_HI) / 8]u64 = undefined;
var wlog: [65536][4]u64 = undefined; // step, rip of writer, addr, new value
var wlog_n: usize = 0;
var prev_rip: u64 = 0;

fn armFromVeh(rsp: usize) bool {
    if (step_n != 0 or step_left != 0) return false;
    const v = std.c.getenv("WINS_STEP_FROM_VEH") orelse return false;
    step_left = std.fmt.parseInt(usize, std.mem.span(v), 10) catch 100000;
    win_base = rsp - WIN_LO;
    @memcpy(std.mem.sliceAsBytes(&win_prev), @as([*]const u8, @ptrFromInt(win_base))[0 .. WIN_LO + WIN_HI]);
    std.debug.print("winload64: stepping from AddVectoredExceptionHandler, stack window 0x{x}..0x{x}\n", .{ win_base, win_base + WIN_LO + WIN_HI });
    return true;
}

// Diagnostic read watchpoint (WINS_WATCH_RVA=<rva in the root image>): the
// page is kept PROT_NONE; each fault on it is logged (data reads of the exact
// qword start single-stepping that thread), the page is opened for one
// single-stepped instruction and closed again.
var wp_addr: usize = 0;
var wp_page: usize = 0;
var wp_reprotect = std.atomic.Value(u32).init(0); // tid that must re-close the page
var wp_hits: usize = 0;

var wp_all = false; // WINS_WATCH_ADDR: log every read of the page
var wp_all_n: usize = 0;
var bp_mode = false; // WINS_BREAK_RVA: execution breakpoint (page PROT_READ)

/// WINS_BREAK_PEEK="r14:0x50,rsp+0x20:0x10,@r14+0x10:0x40" (@ = dereference first) -- at a WINS_BREAK_RVA hit, hex
/// dump <len> bytes at register(+off) (and r10..r15/rsp/rbp always).
fn bpPeek(g: [*]const u64) void {
    std.debug.print("  r10=0x{x} r11=0x{x} r12=0x{x} r13=0x{x} r14=0x{x} r15=0x{x} rbp=0x{x} rsp=0x{x}\n", .{ g[2], g[3], g[4], g[5], g[6], g[7], g[10], g[15] });
    const spec_z = std.c.getenv("WINS_BREAK_PEEK") orelse return;
    const names = [_][]const u8{ "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rdi", "rsi", "rbp", "rbx", "rdx", "rax", "rcx", "rsp" };
    var it = std.mem.tokenizeScalar(u8, std.mem.span(spec_z), ',');
    while (it.next()) |spec| {
        const colon = std.mem.indexOfScalar(u8, spec, ':') orelse continue;
        const lhs = spec[0..colon];
        const len = @min(@as(usize, 256), std.fmt.parseInt(usize, spec[colon + 1 ..], 0) catch continue);
        var deref = false;
        var expr = lhs;
        if (expr.len > 0 and expr[0] == '@') { deref = true; expr = expr[1..]; }
        const plus = std.mem.indexOfAny(u8, expr, "+-");
        const reg = if (plus) |pi| expr[0..pi] else expr;
        const mag = if (plus) |pi| (std.fmt.parseInt(usize, expr[pi + 1 ..], 0) catch 0) else 0;
        const off: usize = if (plus != null and expr[plus.?] == '-') 0 -% mag else mag;
        var base: ?u64 = null;
        for (names, 0..) |n, i| {
            if (std.mem.eql(u8, n, reg)) base = g[i];
        }
        var addr = (base orelse continue) +% off;
        if (deref) {
            if (addr < 0x10000 or addr & 7 != 0) continue;
            addr = @as(*const u64, @ptrFromInt(addr)).*;
        }
        if (addr < 0x10000) {
            std.debug.print("  peek {s} = 0x{x} (not a pointer)\n", .{ spec, addr });
            continue;
        }
        std.debug.print("  peek {s} @0x{x}:", .{ spec, addr });
        var q: usize = 0;
        while (q < len) : (q += 8) {
            if (q % 32 == 0) std.debug.print("\n   +{x:0>3}:", .{q});
            std.debug.print(" {x:0>16}", .{@as(*align(1) const u64, @ptrFromInt(addr + q)).*});
        }
        std.debug.print("\n", .{});
    }
}

/// WINS_BREAK_SW=<rva>[,<rva>...] (up to 8): software breakpoints (ud2) armed at
/// the first Present (after SteamStub decrypted .text). Each hit prints
/// registers + WINS_BREAK_PEEK, restores the bytes, single-steps and re-arms;
/// each one disarms after WINS_BREAK_SW_MAX hits (default 20). Unlike
/// WINS_BREAK_RVA it costs nothing on the rest of the page.
const SwBp = struct { addr: usize = 0, rva: usize = 0, orig: [2]u8 = .{ 0, 0 }, armed: bool = false, hits: u32 = 0 };
var sw_bps: [8]SwBp = [_]SwBp{.{}} ** 8;
var sw_n: usize = 0;
var sw_armed_once = std.atomic.Value(bool).init(false);
var sw_rearm_tid = std.atomic.Value(u32).init(0);
var sw_rearm_idx: usize = 0;
var sw_max: u32 = 20;

fn swPatch(b: *SwBp, on: bool) void {
    const p: [*]u8 = @ptrFromInt(b.addr);
    if (on) {
        p[0] = 0x0F;
        p[1] = 0x0B;
    } else {
        p[0] = b.orig[0];
        p[1] = b.orig[1];
    }
}

fn swArmHook(n: u32) bool {
    if (n >= 0x10000 or sw_n == 0 or sw_armed_once.load(.acquire)) return false;
    for (sw_bps[0..sw_n]) |*b| {
        const page = b.addr & ~@as(usize, 4095);
        _ = linux.mprotect(@ptrFromInt(page), 8192, .{ .READ = true, .WRITE = true, .EXEC = true });
        const p: [*]const u8 = @ptrFromInt(b.addr);
        b.orig = .{ p[0], p[1] };
        b.armed = true;
        swPatch(b, true);
        std.debug.print("winload64: software breakpoint armed at rva 0x{x} (orig {x:0>2} {x:0>2}) on Present #{d}\n", .{ b.rva, b.orig[0], b.orig[1], n });
    }
    sw_armed_once.store(true, .release);
    return false;
}

/// Returns true when the signal belonged to a software breakpoint.
fn swOnSignal(sig: linux.SIG, info: *const linux.siginfo_t, g: [*]u64) bool {
    if (sw_n == 0) return false;
    const tid: u32 = @intCast(linux.gettid());
    if (sig == .ILL) {
        for (sw_bps[0..sw_n], 0..) |*b, i| {
            if (!b.armed or g[16] != b.addr) continue;
            b.hits += 1;
            std.debug.print("winload64: SWBREAK rva=0x{x} hit {d} tid={d}\n  rax=0x{x} rbx=0x{x} rcx=0x{x} rdx=0x{x} rsi=0x{x} rdi=0x{x} r8=0x{x} r9=0x{x}\n", .{
                b.rva, b.hits, tid, g[13], g[11], g[14], g[12], g[9], g[8], g[0], g[1],
            });
            bpPeek(g);
            swPatch(b, false);
            if (b.hits >= sw_max) {
                b.armed = false;
                std.debug.print("winload64: software breakpoint rva 0x{x} disarmed after {d} hits\n", .{ b.rva, b.hits });
                return true;
            }
            sw_rearm_idx = i;
            sw_rearm_tid.store(tid, .release);
            g[17] |= 0x100; // TF: step the original instruction, then re-arm
            return true;
        }
        return false;
    }
    if (sig == .TRAP and info.code == 2 and sw_rearm_tid.load(.acquire) == tid) {
        sw_rearm_tid.store(0, .release);
        const b = &sw_bps[sw_rearm_idx];
        if (b.armed) swPatch(b, true);
        if (step_left == 0) g[17] &= ~@as(u64, 0x100);
        return true;
    }
    return false;
}

fn wpInstall(root_base: usize) void {
    if (std.c.getenv("WINS_BREAK_SW")) |bv| {
        var it = std.mem.tokenizeScalar(u8, std.mem.span(bv), ',');
        while (it.next()) |tok| {
            if (sw_n >= sw_bps.len) break;
            const rva = std.fmt.parseInt(usize, tok, 0) catch continue;
            sw_bps[sw_n] = .{ .addr = root_base + rva, .rva = rva };
            sw_n += 1;
        }
        if (std.c.getenv("WINS_BREAK_SW_MAX")) |m| sw_max = std.fmt.parseInt(u32, std.mem.span(m), 10) catch sw_max;
        if (seh64.arm_hook == null) seh64.arm_hook = &swArmHook;
        std.debug.print("winload64: {d} software breakpoint(s) pending\n", .{sw_n});
        return;
    }
    if (std.c.getenv("WINS_BREAK_RVA")) |bv| {
        const rva = std.fmt.parseInt(usize, std.mem.span(bv), 0) catch return;
        wp_addr = root_base + rva;
        wp_page = wp_addr & ~@as(usize, 4095);
        bp_mode = true;
        _ = linux.mprotect(@ptrFromInt(wp_page), 4096, .{ .READ = true });
        std.debug.print("winload64: execution breakpoint on 0x{x} (page 0x{x})\n", .{ wp_addr, wp_page });
        return;
    }
    if (std.c.getenv("WINS_WATCH_ADDR")) |av| {
        // Absolute address (outside images, e.g. the process heap header): log every access to its page.
        wp_addr = std.fmt.parseInt(usize, std.mem.span(av), 0) catch return;
        wp_all = true;
    } else {
        const v = std.c.getenv("WINS_WATCH_RVA") orelse return;
        const rva = std.fmt.parseInt(usize, std.mem.span(v), 0) catch return;
        wp_addr = root_base + rva;
    }
    wp_page = wp_addr & ~@as(usize, 4095);
    _ = linux.mprotect(@ptrFromInt(wp_page), 4096, .{});
    std.debug.print("winload64: read watchpoint on 0x{x} (page 0x{x})\n", .{ wp_addr, wp_page });
}

var last_present: u32 = 0;

// Multi-thread stepping (WINS_STEP_ALL_AT_PRESENT=<n>[,<steps>]): at Present #n
// every guest thread (one with a TEB in GS) gets a real-time signal whose
// handler sets TF; each thread then fills its own ring.
const MT_SLOTS = 256;
const MT_RING = 4096;
const MtSlot = struct { tid: std.atomic.Value(u32) = std.atomic.Value(u32).init(0), left: usize = 0, n: usize = 0, ring: [MT_RING]u64 = undefined };
var mt_slots: [MT_SLOTS]MtSlot = [_]MtSlot{.{}} ** MT_SLOTS;
var mt_active = std.atomic.Value(bool).init(false);
var mt_budget: usize = 50_000_000;
const MT_SIG: u6 = 41; // SIGRTMIN+7

fn mtSlot(tid: u32, claim: bool) ?*MtSlot {
    var i: usize = (tid *% 2654435761) % MT_SLOTS;
    var probes: usize = 0;
    while (probes < MT_SLOTS) : (probes += 1) {
        const cur = mt_slots[i].tid.load(.acquire);
        if (cur == tid) return &mt_slots[i];
        if (cur == 0) {
            if (!claim) return null;
            if (mt_slots[i].tid.cmpxchgStrong(0, tid, .acq_rel, .acquire) == null) return &mt_slots[i];
            continue;
        }
        i = (i + 1) % MT_SLOTS;
    }
    return null;
}

fn onMtArm(_: linux.SIG, _: *const linux.siginfo_t, ctx: ?*anyopaque) callconv(.c) void {
    const g: [*]u64 = @ptrFromInt(@intFromPtr(ctx.?) + 40);
    var gs: usize = 0;
    _ = linux.syscall2(.arch_prctl, 0x1004, @intFromPtr(&gs)); // ARCH_GET_GS
    if (gs == 0) return; // not a guest thread (GL worker, driver, Steam)
    const sl = mtSlot(@intCast(linux.gettid()), true) orelse return;
    sl.left = mt_budget;
    g[17] |= 0x100;
}

fn mtArmAll() void {
    var act: linux.Sigaction = .{ .handler = .{ .sigaction = &onMtArm }, .mask = std.mem.zeroes(linux.sigset_t), .flags = linux.SA.SIGINFO | linux.SA.RESTART };
    _ = linux.sigaction(@enumFromInt(MT_SIG), &act, null);
    mt_active.store(true, .release);
    const fd = linux.open("/proc/self/task", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return;
    defer _ = linux.close(@intCast(fd));
    var buf: [16384]u8 align(8) = undefined;
    var sent: usize = 0;
    while (true) {
        const n = linux.getdents64(@intCast(fd), &buf, buf.len);
        if (linux.errno(n) != .SUCCESS or n == 0) break;
        var off: usize = 0;
        while (off < n) {
            const reclen = std.mem.readInt(u16, buf[off + 16 ..][0..2], .little);
            const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&buf[off + 19])), 0);
            if (std.fmt.parseInt(i32, name, 10)) |tid| {
                _ = linux.tgkill(linux.getpid(), tid, @enumFromInt(MT_SIG));
                sent += 1;
            } else |_| {}
            off += reclen;
        }
    }
    std.debug.print("winload64: multi-thread stepping armed ({d} threads signalled, budget {d})\n", .{ sent, mt_budget });
}

fn armAtPresent(n: u32) bool {
    if (n < 0x10000) last_present = n;
    if (n < 0x10000) if (std.c.getenv("WINS_STEP_ALL_AT_PRESENT")) |v| {
        const spec = std.mem.span(v);
        const comma = std.mem.indexOfScalar(u8, spec, ',');
        const at = std.fmt.parseInt(u32, spec[0 .. comma orelse spec.len], 10) catch 0;
        if (comma) |c| mt_budget = std.fmt.parseInt(usize, spec[c + 1 ..], 10) catch mt_budget;
        if (n == at and !mt_active.load(.acquire)) mtArmAll();
        return false;
    };
    if (n >= 0x10000) { // Steam slot n-0x10000: re-arm a rolling window on every call
        if (last_present < 100) return false; // steady state only (Steam's own init owns SIGTRAP early)
        const v = std.c.getenv("WINS_STEP_AT_STEAMSLOT") orelse return false;
        const want = std.fmt.parseInt(u32, std.mem.span(v), 10) catch return false;
        if (n - 0x10000 != want) return false;
        step_left = 3_000_000;
        return true;
    }
    if (std.c.getenv("WINS_STEP_AT_PRESENT") == null) return false;
    if (step_left != 0) return false;
    const want = std.fmt.parseInt(u32, std.mem.span(std.c.getenv("WINS_STEP_AT_PRESENT").?), 10) catch return false;
    if (n != want) return false;
    step_left = 200_000_000;
    std.debug.print("winload64: single-stepping the presenting thread from Present #{d}\n", .{n});
    return true;
}

var watch_addr: usize = 0;
var watch_val: u64 = 0;
var watch_events: [32][4]u64 = undefined;
var watch_n: usize = 0;

fn onCrash(sig: linux.SIG, info: *const linux.siginfo_t, ctx: ?*anyopaque) callconv(.c) void {
    const g: [*]u64 = @ptrFromInt(@intFromPtr(ctx.?) + 40); // ucontext.uc_mcontext.gregs
    if (swOnSignal(sig, info, g)) return;
    if (sig == .TRAP and info.code == 2 and wp_reprotect.load(.acquire) == linux.gettid()) {
        _ = linux.mprotect(@ptrFromInt(wp_page), 4096, if (bp_mode) .{ .READ = true } else .{});
        wp_reprotect.store(0, .release);
        if (step_left == 0 or (step_tid != 0 and step_tid != linux.gettid())) {
            g[17] &= ~@as(u64, 0x100);
            return;
        }
    }
    if (sig == .SEGV and wp_page != 0 and (g[22] & ~@as(u64, 4095)) == wp_page) {
        const fault = g[22];
        const exec = (g[16] & ~@as(u64, 4095)) == wp_page;
        if (bp_mode and exec and g[16] == wp_addr and step_left == 0) {
            wp_hits += 1;
            if (wp_hits <= 3 or wp_hits % 1000 == 0) {
                std.debug.print("winload64: BREAK hit {d} tid={d}\n  rax=0x{x} rbx=0x{x} rcx=0x{x} rdx=0x{x} rsi=0x{x} rdi=0x{x} r8=0x{x} r9=0x{x}\n", .{
                    wp_hits, linux.gettid(), g[13], g[11], g[14], g[12], g[9], g[8], g[0], g[1],
                });
                // If rcx looks like a C++/COM object, name its first vtable slots.
                if (g[14] > 0x10000 and g[14] & 7 == 0) {
                    const vt: usize = @as(*const usize, @ptrFromInt(g[14])).*;
                    if (vt > 0x10000 and vt & 7 == 0) {
                        var vi: usize = 0;
                        while (vi < 16) : (vi += 1) {
                            var wbv: [128]u8 = undefined;
                            std.debug.print("  [rcx]->vtbl[{d}] (+0x{x}) = {s}\n", .{ vi, vi * 8, where(&wbv, @as(*const usize, @ptrFromInt(vt + vi * 8)).*) });
                        }
                    }
                }
            }
            if (wp_hits <= 3 or wp_hits % 1000 == 0) bpPeek(g);
            if (std.c.getenv("WINS_BREAK_NOSTEP") == null) {
                step_left = 3_000_000;
                step_n = 0;
                step_tid = linux.gettid();
            } else {
                // Step over just the breakpoint instruction, then re-arm.
                step_left = 1;
                step_n = 0;
                step_tid = linux.gettid();
            }
        }
        const is_write = (g[19] & 2) != 0;
        if (!bp_mode and !exec and is_write) {
            var wb3: [128]u8 = undefined;
            std.debug.print("winload64: WATCH page WRITE 0x{x} (+0x{x}) by {s} tid={d}\n", .{ fault, fault - wp_page, where(&wb3, g[16]), linux.gettid() });
        }
        if (wp_all and !exec and !is_write and wp_all_n < 400) {
            wp_all_n += 1;
            var wb4: [128]u8 = undefined;
            std.debug.print("winload64: WATCH read +0x{x} by {s} tid={d}\n", .{ fault - wp_page, where(&wb4, g[16]), linux.gettid() });
        }
        if (!bp_mode and !wp_all and !exec and !is_write and wp_hits < 64 and fault + 32 > wp_addr and fault < wp_addr + 32) {
            var wb2: [128]u8 = undefined;
            std.debug.print("winload64: WATCH page data access 0x{x} (+0x{x}) by {s} tid={d}\n", .{ fault, fault - wp_page, where(&wb2, g[16]), linux.gettid() });
        }
        if (!bp_mode and !exec and fault + 16 > wp_addr and fault < wp_addr + 8) {
            wp_hits += 1;
            var wb: [128]u8 = undefined;
            std.debug.print("winload64: WATCH read of 0x{x} by {s} tid={d} (hit {d})\n", .{ fault, where(&wb, g[16]), linux.gettid(), wp_hits });
            if (step_left == 0 and wp_hits == 1) step_left = 2_000_000;
        }
        // Spin until no other thread is mid-step on this page, then open it for one instruction.
        while (wp_reprotect.cmpxchgWeak(0, @intCast(linux.gettid()), .acq_rel, .acquire) != null) {}
        _ = linux.mprotect(@ptrFromInt(wp_page), 4096, .{ .READ = true, .WRITE = true, .EXEC = true });
        g[17] |= 0x100;
        return;
    }
    if (sig == .TRAP and info.code == 2 and mt_active.load(.acquire)) {
        if (mtSlot(@intCast(linux.gettid()), false)) |sl| if (sl.left > 0) {
            sl.ring[sl.n % MT_RING] = g[16];
            sl.n += 1;
            sl.left -= 1;
            if (sl.left == 0) g[17] &= ~@as(u64, 0x100) else g[17] |= 0x100;
            return;
        };
    }
    if (sig == .TRAP and info.code == 2 and step_left > 0 and (step_tid == 0 or step_tid == linux.gettid())) { // TRAP_TRACE from our own TF
        step_ring[step_n % step_ring.len] = g[16];
        step_rsp[step_n % step_ring.len] = g[15];
        if (win_base != 0) {
            const cur: [*]const u64 = @ptrFromInt(win_base);
            for (&win_prev, 0..) |*pv, i| if (cur[i] != pv.*) {
                if (wlog_n < wlog.len) {
                    wlog[wlog_n] = .{ step_n, prev_rip, win_base + i * 8, cur[i] };
                    wlog_n += 1;
                }
                pv.* = cur[i];
            };
            prev_rip = g[16];
        }
        if (watch_addr != 0) {
            const v = @as(*const u64, @ptrFromInt(watch_addr)).*;
            if (v != watch_val and watch_n < watch_events.len) {
                watch_events[watch_n] = .{ step_n, g[16], watch_val, v };
                watch_n += 1;
            }
            watch_val = v;
        }
        step_n += 1;
        step_left -= 1;
        // keep stepping even if the program's own popf cleared TF
        if (step_left == 0) g[17] &= ~@as(u64, 0x100) else g[17] |= 0x100;
        return;
    }
    const fault_addr: usize = if (sig == .SEGV or sig == .BUS) @intFromPtr(info.fields.sigfault.addr) else @intCast(g[22]);
    const exc_code: ?u32 = switch (sig) {
        .SEGV, .BUS => 0xC0000005, // EXCEPTION_ACCESS_VIOLATION (Mono JIT null/GC trap)
        .FPE => 0xC0000094,        // EXCEPTION_INT_DIVIDE_BY_ZERO
        .ILL => 0xC000001D,        // EXCEPTION_ILLEGAL_INSTRUCTION
        else => null,
    };
    // `int 0x2d` (Windows debug service, an anti-debug probe) and `int3`:
    // Windows raises EXCEPTION_BREAKPOINT into the program's own handlers.
    // Linux delivers `int 0x2d` as #GP (trapno 13, err = vector*8+2, rip at
    // the instruction) and int3 as SIGTRAP (rip after the 0xCC). On x64
    // Windows, KiDebugServiceTrap bumps Rip past `cd 2d` by one and
    // KiDispatchException steps BREAKPOINT back by one, so the context resumes
    // right after the 2-byte instruction (the one-byte skip is x86-only), with
    // Rax/Rcx/Rdx as the three parameters. int3 resumes at the 0xCC itself.
    // Either way the dispatch runs on the thread's own stack.
    {
        const fx: ?[*]const u8 = @ptrFromInt(g[23]); // uc_mcontext.fpregs
        const rip_now = g[16];
        if (sig == .SEGV and g[20] == 13 and g[19] == 0x2d * 8 + 2) {
            const code_bytes: [*]const u8 = @ptrFromInt(rip_now);
            if (code_bytes[0] == 0xCD and code_bytes[1] == 0x2D) {
                if (std.c.getenv("WINS_TRACE") != null) std.debug.print("winload64: int 0x2d at 0x{x} -> EXCEPTION_BREAKPOINT\n", .{rip_now});
                if (step_left > 0) seh64.step_on_resume.store(true, .release);
                if (step_n == 0) if (std.c.getenv("WINS_STEP_AFTER_INT2D")) |v| {
                    step_left = std.fmt.parseInt(usize, std.mem.span(v), 10) catch 100000;
                    if (std.c.getenv("WINS_STEP_WATCH")) |wv| {
                        watch_addr = g[15] +% (std.fmt.parseInt(usize, std.mem.span(wv), 0) catch 0);
                        watch_val = @as(*const u64, @ptrFromInt(watch_addr)).*;
                        var wb: [128]u8 = undefined;
                        std.debug.print("winload64: watching [rsp+{s}] = 0x{x}: {s}\n", .{ std.mem.span(wv), watch_addr, where(&wb, watch_val) });
                    }
                    seh64.step_on_resume.store(true, .release);
                };
                seh64.raiseFromSignal(g, fx, 0x80000003, rip_now + 2, .{ g[13], g[14], g[12] });
                return;
            }
        }
        if (sig == .TRAP and info.code == 0x80 and rip_now > 0 and @as(*const u8, @ptrFromInt(rip_now - 1)).* == 0xCC) { // SI_KERNEL: int3
            seh64.raiseFromSignal(g, fx, 0x80000003, rip_now - 1, .{ 0, 0, 0 });
            return;
        }
    }
    if (exc_code) |code| {
        if (std.c.getenv("WINS_TRACE") != null) {
            var t1: [128]u8 = undefined;
            var t2: [128]u8 = undefined;
            std.debug.print("winload64: exception 0x{x} at {s} addr={s} -> SEH\n", .{ code, where(&t1, g[16]), where(&t2, fault_addr) });
        }
        if (seh64.dispatchHardwareException(code, fault_addr, g)) return;
    }
    const rip = g[16];
    const rsp = g[15];
    var b1: [128]u8 = undefined;
    var b2: [128]u8 = undefined;
    std.debug.print("winload64: CRASH signal {d} at {s} (trapno={d} err=0x{x} cr2={s})\n", .{ @intFromEnum(sig), where(&b1, rip), g[20], g[19], where(&b2, g[22]) });
    std.debug.print("  tid={d} last_present={d}\n", .{ linux.gettid(), last_present });
    for (crash_images) |im| {
        const off: i128 = @as(i128, rip) - @as(i128, im.base);
        std.debug.print("  image {s} base=0x{x} size=0x{x} rip-base={d}\n", .{ im.name, im.base, im.img.len, off });
    }
    std.debug.print("  rax=0x{x} rbx=0x{x} rcx=0x{x} rdx=0x{x}\n  rsi=0x{x} rdi=0x{x} rbp=0x{x} rsp=0x{x}\n  r8=0x{x} r9=0x{x} r10=0x{x} r11=0x{x}\n", .{ g[13], g[11], g[14], g[12], g[9], g[8], g[10], rsp, g[0], g[1], g[2], g[3] });
    if (win_base != 0) {
        const slot = rsp - 8;
        std.debug.print("  stack writes to [rsp-8]=0x{x} ({d} logged writes total, {d} steps):\n", .{ slot, wlog_n, step_n });
        for (wlog[0..wlog_n]) |e| if (e[2] == slot)
            std.debug.print("    step {d} by {s}: 0x{x}\n", .{ e[0], where(&b2, e[1]), e[3] });
    }
    for (watch_events[0..watch_n]) |e| {
        var wb: [128]u8 = undefined;
        std.debug.print("  watch: step {d} at {s}: 0x{x} -> 0x{x}\n", .{ e[0], where(&b2, e[1]), e[2], e[3] });
        _ = &wb;
    }
    if (mt_active.load(.acquire)) if (mtSlot(@intCast(linux.gettid()), false)) |sl| {
        const show = @min(sl.n, MT_RING);
        std.debug.print("  last {d} of {d} single-stepped rips of this thread:\n", .{ show, sl.n });
        var i = sl.n - show;
        while (i < sl.n) : (i += 1) std.debug.print("    {s}\n", .{where(&b2, sl.ring[i % MT_RING])});
    };
    if (step_n > 0) {
        const show = @min(step_n, step_ring.len);
        std.debug.print("  last {d} of {d} single-stepped rips:\n", .{ show, step_n });
        var i = step_n - show;
        while (i < step_n) : (i += 1) std.debug.print("    {s} rsp=0x{x}\n", .{ where(&b2, step_ring[i % step_ring.len]), step_rsp[i % step_ring.len] });
    }
    if (std.c.getenv("WINS_CRASH_PEEK")) |pv| if (crash_images.len > 0) {
        // WINS_CRASH_PEEK=<rva>[:<len>],...: hex dump of root-image bytes.
        var it = std.mem.splitScalar(u8, std.mem.span(pv), ',');
        while (it.next()) |item| {
            const colon = std.mem.indexOfScalar(u8, item, ':');
            const rva = std.fmt.parseInt(usize, item[0 .. colon orelse item.len], 0) catch continue;
            const len = if (colon) |c| (std.fmt.parseInt(usize, item[c + 1 ..], 0) catch 16) else 16;
            const im = crash_images[0];
            if (rva + len > im.img.len) continue;
            std.debug.print("  peek +0x{x}:", .{rva});
            for (im.img[rva .. rva + len]) |b| std.debug.print(" {x:0>2}", .{b});
            std.debug.print("\n", .{});
        }
    };
    if (std.c.getenv("WINS_CRASH_STACK") != null) {
        // Which mapping holds rip (and is it executable)?
        const mfd = linux.open("/proc/self/maps", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(mfd) == .SUCCESS) {
            defer _ = linux.close(@intCast(mfd));
            var mbuf: [1 << 16]u8 = undefined;
            var carry: usize = 0;
            while (true) {
                const n = linux.read(@intCast(mfd), mbuf[carry..].ptr, mbuf.len - carry);
                if (linux.errno(n) != .SUCCESS or n == 0) break;
                const have = carry + n;
                var it = std.mem.splitScalar(u8, mbuf[0..have], '\n');
                var last_start: usize = 0;
                while (it.next()) |line| {
                    if (it.index == null) {
                        last_start = @intFromPtr(line.ptr) - @intFromPtr(&mbuf);
                        break;
                    }
                    const dash = std.mem.indexOfScalar(u8, line, '-') orelse continue;
                    const sp1 = std.mem.indexOfScalar(u8, line, ' ') orelse continue;
                    const lo = std.fmt.parseInt(usize, line[0..dash], 16) catch continue;
                    const hi = std.fmt.parseInt(usize, line[dash + 1 .. sp1], 16) catch continue;
                    if (rip >= lo and rip < hi) std.debug.print("  rip mapping: {s}\n", .{line});
                }
                std.mem.copyForwards(u8, &mbuf, mbuf[last_start..have]);
                carry = have - last_start;
            }
        }
        if (std.c.getenv("WINS_CRASH_SCAN")) |sv| {
            // Scan every rw mapping for qwords equal to rip and to rip - delta.
            const delta = std.fmt.parseInt(u64, std.mem.span(sv), 0) catch 0;
            const want = [2]u64{ rip, rip -% delta };
            const mfd2 = linux.open("/proc/self/maps", .{ .ACCMODE = .RDONLY }, 0);
            if (linux.errno(mfd2) == .SUCCESS) {
                defer _ = linux.close(@intCast(mfd2));
                var mb: [1 << 20]u8 = undefined;
                var have: usize = 0;
                while (have < mb.len) {
                    const r = linux.read(@intCast(mfd2), mb[have..].ptr, mb.len - have);
                    if (linux.errno(r) != .SUCCESS or r == 0) break;
                    have += r;
                }
                var shown: usize = 0;
                var lines = std.mem.splitScalar(u8, mb[0..have], '\n');
                while (lines.next()) |line| {
                    if (line.len < 30) continue;
                    const dash = std.mem.indexOfScalar(u8, line, '-') orelse continue;
                    const sp1 = std.mem.indexOfScalar(u8, line, ' ') orelse continue;
                    if (line[sp1 + 1] != 'r' or line[sp1 + 2] != 'w') continue;
                    const lo = std.fmt.parseInt(usize, line[0..dash], 16) catch continue;
                    const hi = std.fmt.parseInt(usize, line[dash + 1 .. sp1], 16) catch continue;
                    if (hi - lo > 1 << 32) continue;
                    var at = lo;
                    while (at + 8 <= hi) : (at += 8) {
                        const v = @as(*const u64, @ptrFromInt(at)).*;
                        if (v == want[0] or v == want[1]) {
                            if (shown < 40) std.debug.print("  scan: [0x{x}] = 0x{x} ({s}) in {s}\n", .{ at, v, if (v == want[0]) "bad" else "good", line[sp1 + 1 ..] });
                            shown += 1;
                        }
                    }
                }
                std.debug.print("  scan: {d} hits\n", .{shown});
            }
        }
        {
            std.debug.print("  stale exe pointers below rsp (most recent last-called frames):\n", .{});
            var q: usize = 0x2000;
            while (q >= 8) : (q -= 8) {
                const at = rsp - q;
                if (linux.errno(linux.madvise(@ptrFromInt(at & ~@as(usize, 4095)), 4096, linux.MADV.NORMAL)) != .SUCCESS) continue;
                const v = @as(*const u64, @ptrFromInt(at)).*;
                for (crash_images) |im| if (v >= im.base and v < im.base + im.img.len and inExec(im.secs, v - im.base)) {
                    std.debug.print("    [rsp-0x{x}] {s}\n", .{ q, where(&b2, v) });
                };
                if (v == rip) std.debug.print("    [rsp-0x{x}] = crash target\n", .{q});
            }
        }
        std.debug.print("  raw stack:\n", .{});
        var q: isize = -8;
        while (q < 24) : (q += 1) {
            const at: usize = @intCast(@as(isize, @intCast(rsp)) + q * 8);
            if (linux.errno(linux.madvise(@ptrFromInt(at & ~@as(usize, 4095)), 4096, linux.MADV.NORMAL)) != .SUCCESS) continue;
            std.debug.print("    [rsp{s}0x{x}] {s}\n", .{ if (q < 0) "-" else "+", @abs(q) * 8, where(&b2, @as(*const u64, @ptrFromInt(at)).*) });
        }
    }
    std.debug.print("  unwound call chain (.pdata):\n", .{});
    seh64.backtrace(g, 32, &struct {
        fn f(k: usize, pc: usize) void {
            var bb: [128]u8 = undefined;
            std.debug.print("    #{d} {s}\n", .{ k, where(&bb, pc) });
        }
    }.f);
    std.debug.print("  stack words pointing into executable sections (candidate return addresses):\n", .{});
    var n: usize = 0;
    var k: usize = 0;
    var mapped_page: usize = 0;
    while (k < 1024 and n < 24) : (k += 1) {
        const at = rsp + k * 8;
        const page = at & ~@as(usize, 4095);
        if (page != mapped_page) { // stop at the end of the mapped stack
            if (linux.errno(linux.madvise(@ptrFromInt(page), 4096, linux.MADV.NORMAL)) != .SUCCESS) break;
            mapped_page = page;
        }
        const v = @as(*const u64, @ptrFromInt(at)).*;
        for (crash_images) |im| if (v >= im.base and v < im.base + im.img.len and inExec(im.secs, v - im.base)) {
            std.debug.print("    [rsp+0x{x}] {s}\n", .{ k * 8, where(&b1, v) });
            n += 1;
        };
    }
    dumpPeOnFailure();
    std.process.exit(9);
}

fn installCrashReport(images: []const Image) void {
    crash_images = images;
    var act: linux.Sigaction = .{ .handler = .{ .sigaction = &onCrash }, .mask = std.mem.zeroes(linux.sigset_t), .flags = linux.SA.SIGINFO };
    for ([_]linux.SIG{ .SEGV, .BUS, .ILL, .FPE, .TRAP }) |s| _ = linux.sigaction(s, &act, null);
}

const Loader = struct {
    a: std.mem.Allocator,
    io: std.Io,
    dll_dirs: std.ArrayList([]const u8) = .empty,
    pins: std.StringHashMapUnmanaged([]const u8) = .empty, // lower-case name -> hex
    images: std.ArrayList(Image) = .empty,
    missing: std.ArrayList(u8) = .empty,
    n_tls: u32 = 0,
    n_imports: usize = 0,

    fn lower(self: *Loader, s: []const u8) []const u8 {
        const out = self.a.alloc(u8, s.len) catch die(.map_failed, "out of memory", .{});
        return std.ascii.lowerString(out, s);
    }

    fn find(self: *Loader, name: []const u8) ?usize {
        for (self.images.items, 0..) |im, k| if (std.ascii.eqlIgnoreCase(im.name, name)) return k;
        return null;
    }

    /// A DLL is loaded as an image when it is pinned (or present in --dll-dir and
    /// pinned); otherwise its imports go to the shim table.
    fn isImage(self: *Loader, name: []const u8) bool {
        return self.pins.get(self.lower(name)) != null;
    }

    fn readPinned(self: *Loader, path: []const u8, name: []const u8) []u8 {
        const want = self.pins.get(name) orelse die(.refused, "{s} is not pinned (--pin {s}=SHA256)", .{ name, name });
        const file = std.Io.Dir.cwd().readFileAlloc(self.io, path, self.a, .limited(1024 * 1024 * 1024)) catch |e|
            die(.usage, "cannot read {s}: {s}", .{ path, @errorName(e) });
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(file, &digest, .{});
        const got = std.fmt.bytesToHex(digest, .lower);
        if (want.len != 64 or !std.ascii.eqlIgnoreCase(want, &got))
            die(.refused, "sha256 mismatch for {s}: file is {s}", .{ name, &got });
        return file;
    }

    fn findInDllDirs(self: *Loader, name: []const u8) ?[]const u8 {
        for (self.dll_dirs.items) |dir| {
            if (self.findInDirNoCase(dir, name)) |dp| return dp;
        }
        return null;
    }

    /// Win32 file names are case-insensitive; the host filesystem is not.
    /// Exact name first, then a case-folded scan of `dir` (CSteamworks.dll vs csteamworks.dll).
    fn findInDirNoCase(self: *Loader, dir: []const u8, name: []const u8) ?[]const u8 {
        const dp = std.fs.path.join(self.a, &.{ dir, name }) catch return null;
        if (std.Io.Dir.cwd().access(self.io, dp, .{})) |_| return dp else |_| {}
        var d = std.Io.Dir.cwd().openDir(self.io, dir, .{ .iterate = true }) catch return null;
        defer d.close(self.io);
        var it = d.iterate();
        while (it.next(self.io) catch null) |entry| {
            if (entry.kind != .file and entry.kind != .sym_link) continue;
            if (std.ascii.eqlIgnoreCase(entry.name, name))
                return std.fs.path.join(self.a, &.{ dir, entry.name }) catch null;
        }
        return null;
    }

    /// Map one image (headers, sections, relocations, TLS, .pdata). Imports later.
    fn map(self: *Loader, path: []const u8) usize {
        const name = self.lower(std.fs.path.basename(path));
        if (self.find(name)) |k| return k;
        const file = self.readPinned(path, name);

        if (file.len < 64 or !std.mem.eql(u8, file[0..2], "MZ")) die(.bad_image, "{s}: not an MZ file", .{name});
        const pe: usize = need(u32, file, 0x3c, "e_lfanew");
        if (rd(u32, file, pe) != 0x00004550) die(.bad_image, "{s}: no PE signature", .{name});
        const machine = need(u16, file, pe + 4, "machine");
        const nsec = need(u16, file, pe + 6, "section count");
        const opt_size = need(u16, file, pe + 20, "optional header size");
        const fchars = need(u16, file, pe + 22, "characteristics");
        const opt = pe + 24;
        if (machine != 0x8664) die(.refused, "{s}: machine 0x{x} is not x86-64", .{ name, machine });
        if (need(u16, file, opt, "magic") != 0x20b) die(.refused, "{s}: not PE32+", .{name});
        if (opt_size < 112 + 16 * 8) die(.bad_image, "{s}: optional header too small", .{name});
        if (self.images.items.len > 0 and (fchars & 0x2000 == 0)) die(.refused, "{s}: dependency is not a DLL", .{name});
        if (fchars & 0x0001 != 0) die(.refused, "{s}: relocations stripped", .{name});
        const entry_rva = need(u32, file, opt + 16, "entry point");
        const image_base = need(u64, file, opt + 24, "ImageBase");
        const sect_align = need(u32, file, opt + 32, "SectionAlignment");
        const size_of_image = need(u32, file, opt + 56, "SizeOfImage");
        const size_of_headers = need(u32, file, opt + 60, "SizeOfHeaders");
        const ndirs = need(u32, file, opt + 108, "NumberOfRvaAndSizes");
        if (sect_align < 4096 or sect_align % 4096 != 0) die(.refused, "{s}: SectionAlignment 0x{x}", .{ name, sect_align });
        if (size_of_image == 0 or size_of_image > 1024 * 1024 * 1024) die(.bad_image, "{s}: SizeOfImage 0x{x}", .{ name, size_of_image });
        if (size_of_headers > file.len or size_of_headers > size_of_image) die(.bad_image, "{s}: SizeOfHeaders", .{name});
        if (ndirs < 16) die(.refused, "{s}: only {d} data directories", .{ name, ndirs });

        var dirs: [16]Dir = undefined;
        for (&dirs, 0..) |*d, k| d.* = .{ .rva = need(u32, file, opt + 112 + k * 8, "dir"), .size = need(u32, file, opt + 116 + k * 8, "dir") };
        for ([_]usize{ 1, 3, 5, 9, 13 }) |k| if (dirs[k].size != 0 and @as(u64, dirs[k].rva) + dirs[k].size > size_of_image)
            die(.bad_image, "{s}: data directory {d} beyond image", .{ name, k });
        if (dirs[14].size != 0) die(.refused, "{s}: CLR header (managed code unsupported)", .{name});
        if (dirs[11].size != 0) die(.refused, "{s}: bound-import directory (unsupported)", .{name});

        const sec_off = opt + opt_size;
        if (nsec == 0 or nsec > 96) die(.bad_image, "{s}: {d} sections", .{ name, nsec });
        const secs = self.a.alloc(Section, nsec) catch die(.map_failed, "out of memory", .{});
        for (secs, 0..) |*s, k| {
            const o = sec_off + k * 40;
            if (o + 40 > file.len) die(.bad_image, "{s}: section table truncated", .{name});
            s.* = .{
                .vsize = need(u32, file, o + 8, "vsize"),
                .va = need(u32, file, o + 12, "va"),
                .raw_size = need(u32, file, o + 16, "raw size"),
                .raw_ptr = need(u32, file, o + 20, "raw ptr"),
                .chars = need(u32, file, o + 36, "section characteristics"),
            };
            if (s.chars & SCN_EXEC != 0 and s.chars & SCN_WRITE != 0) die(.refused, "{s}: a section is writable and executable", .{name});
            if (s.va % 4096 != 0 or s.va < size_of_headers) die(.bad_image, "{s}: section at 0x{x} misplaced", .{ name, s.va });
            if (@as(u64, s.va) + @max(s.vsize, s.raw_size) > size_of_image) die(.bad_image, "{s}: section beyond SizeOfImage", .{name});
            if (s.raw_size != 0 and @as(u64, s.raw_ptr) + s.raw_size > file.len) die(.bad_image, "{s}: section data beyond file", .{name});
        }

        const map_len = std.mem.alignForward(usize, size_of_image, 4096);
        const mrc = linux.mmap(null, map_len, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
        if (linux.errno(mrc) != .SUCCESS) die(.map_failed, "{s}: mmap of 0x{x} bytes failed", .{ name, map_len });
        const base: usize = mrc;
        if (base == image_base) die(.map_failed, "{s}: kernel chose ImageBase; refusing to hide relocation bugs", .{name});
        const img: []u8 = @as([*]u8, @ptrFromInt(base))[0..map_len];
        @memcpy(img[0..size_of_headers], file[0..size_of_headers]);
        for (secs) |s| {
            const n = if (s.vsize != 0) @min(s.raw_size, s.vsize) else s.raw_size;
            if (n != 0) @memcpy(img[s.va..][0..n], file[s.raw_ptr..][0..n]);
        }

        const full_path = self.a.dupe(u8, path) catch die(.map_failed, "out of memory", .{});
        var im: Image = .{ .name = name, .full_path = full_path, .is_dll = (fchars & 0x2000) != 0, .base = base, .img = img, .size_of_image = size_of_image, .size_of_headers = size_of_headers, .entry_rva = entry_rva, .pdata_rva = dirs[3].rva, .pdata_size = dirs[3].size, .secs = secs, .dirs = dirs, .pref_base = image_base, .timestamp = need(u32, file, pe + 8, "TimeDateStamp") };

        // TLS directory (VAs are still relative to ImageBase here: read before relocating).
        if (dirs[9].size != 0) {
            if (dirs[9].size < 40) die(.bad_image, "{s}: TLS directory too small", .{name});
            const td = dirs[9].rva;
            const start_va = need(u64, img, td + 0, "TLS.Start");
            const end_va = need(u64, img, td + 8, "TLS.End");
            const index_va = need(u64, img, td + 16, "TLS.AddressOfIndex");
            const cb_va = need(u64, img, td + 24, "TLS.AddressOfCallBacks");
            const zfill = need(u32, img, td + 32, "TLS.SizeOfZeroFill");
            if (start_va > end_va or end_va - start_va > 16 * 1024 * 1024 or zfill > 16 * 1024 * 1024) die(.refused, "{s}: TLS template size", .{name});
            if (start_va != 0) {
                const srva = start_va -% image_base;
                if (srva + (end_va - start_va) > size_of_image) die(.refused, "{s}: TLS template out of image", .{name});
                im.tls_template_rva = @intCast(srva);
                im.tls_template_len = @intCast(end_va - start_va);
            }
            im.tls_zero_fill = zfill;
            const irva = index_va -% image_base;
            if (irva + 4 > size_of_image) die(.refused, "{s}: TLS index out of image", .{name});
            const slot: u32 = if (bug == .shared_tls_index) 0 else self.n_tls;
            im.tls_index = slot;
            std.mem.writeInt(u32, img[@intCast(irva)..][0..4], slot, .little);
            self.n_tls += 1;
            if (cb_va != 0) {
                var crva = cb_va -% image_base;
                while (true) : (crva += 8) {
                    if (crva + 8 > size_of_image) die(.refused, "{s}: TLS callback table truncated", .{name});
                    const fva = need(u64, img, @intCast(crva), "TLS callback");
                    if (fva == 0) break;
                    const frva = fva -% image_base;
                    if (!inExec(secs, frva)) die(.refused, "{s}: TLS callback 0x{x} not in executable section", .{ name, fva });
                    im.tls_cb_rvas.append(self.a, @intCast(frva)) catch die(.map_failed, "out of memory", .{});
                }
            }
        }

        // Relocations: DIR64 only (plus ABSOLUTE padding).
        const delta: u64 = @as(u64, base) -% image_base;
        if (dirs[5].size == 0) die(.refused, "{s}: no relocation directory", .{name});
        var p: usize = dirs[5].rva;
        const rend: usize = p + dirs[5].size;
        while (p + 8 <= rend) {
            const page = need(u32, img, p, "reloc page");
            const bsize = need(u32, img, p + 4, "reloc block size");
            if (bsize < 8 or bsize % 2 != 0 or p + bsize > rend) die(.bad_image, "{s}: reloc block size {d}", .{ name, bsize });
            var q = p + 8;
            while (q < p + bsize) : (q += 2) {
                const e = need(u16, img, q, "reloc entry");
                const tgt = @as(u64, page) + (e & 0xfff);
                switch (e >> 12) {
                    0 => {},
                    10 => {
                        if (tgt + 8 > size_of_image) die(.bad_image, "{s}: DIR64 target beyond image", .{name});
                        const t: usize = @intCast(tgt);
                        std.mem.writeInt(u64, img[t..][0..8], std.mem.readInt(u64, img[t..][0..8], .little) +% delta, .little);
                    },
                    else => |k| die(.refused, "{s}: relocation type {d} unsupported", .{ name, k }),
                }
            }
            p += bsize;
        }
        if (p != rend) die(.bad_image, "{s}: truncated relocation block", .{name});
        // The Windows loader rewrites OptionalHeader.ImageBase in the mapped
        // headers to the address it actually chose; code that rebases through
        // its own header (Arxan in Dark Souls III does) relies on that.
        std.mem.writeInt(u64, img[opt + 24 ..][0..8], base, .little);

        // .pdata: validate bounds (RUNTIME_FUNCTION = 12 bytes); recorded, not dispatched.
        if (dirs[3].size != 0) {
            if (dirs[3].size % 12 != 0) die(.bad_image, "{s}: exception directory size", .{name});
            im.pdata_entries = dirs[3].size / 12;
        }

        self.images.append(self.a, im) catch die(.map_failed, "out of memory", .{});
        const idx = self.images.items.len - 1;
        // Map dependencies that are images (pinned) before binding anything.
        self.forEachImportLib(idx, struct {
            fn f(ld: *Loader, me: usize, lib: []const u8) void {
                if (!ld.isImage(lib)) return;
                const dp = ld.findInDllDirs(lib) orelse die(.usage, "{s} needs {s}: pass --dll-dir", .{ ld.images.items[me].name, lib });
                const k = ld.map(dp);
                ld.images.items[me].deps.append(ld.a, k) catch die(.map_failed, "out of memory", .{});
            }
        }.f);
        return idx;
    }

    fn forEachImportLib(self: *Loader, idx: usize, comptime f: fn (*Loader, usize, []const u8) void) void {
        for ([_]usize{ 1, 13 }) |dk| {
            const d = self.images.items[idx].dirs[dk];
            if (d.size == 0) continue;
            const stride: usize = if (dk == 1) 20 else 32;
            const name_off: usize = if (dk == 1) 12 else 4;
            var p: usize = d.rva;
            while (p + stride <= d.rva + d.size) : (p += stride) {
                const img = self.images.items[idx].img;
                const nrva = need(u32, img, p + name_off, "import name");
                if (nrva == 0) break;
                f(self, idx, cstr(img, nrva, "library name"));
            }
        }
    }

    fn exportByName(self: *Loader, k: usize, sym: []const u8, depth: u8) ?usize {
        const im = self.images.items[k];
        const d = im.dirs[0];
        if (d.size == 0) return null;
        const nnames = need(u32, im.img, d.rva + 24, "export names");
        const afun = need(u32, im.img, d.rva + 28, "export functions");
        const anames = need(u32, im.img, d.rva + 32, "export name ptrs");
        const aords = need(u32, im.img, d.rva + 36, "export ordinals");
        var i: usize = 0;
        while (i < nnames) : (i += 1) {
            const n = cstr(im.img, need(u32, im.img, anames + i * 4, "export name rva"), "export name");
            if (!std.mem.eql(u8, n, sym)) continue;
            const ord = need(u16, im.img, aords + i * 2, "export ordinal");
            return self.exportRva(k, need(u32, im.img, afun + @as(usize, ord) * 4, "export rva"), depth);
        }
        return null;
    }

    fn exportByOrdinal(self: *Loader, k: usize, ordinal: u16, depth: u8) ?usize {
        const im = self.images.items[k];
        const d = im.dirs[0];
        if (d.size == 0) return null;
        const obase = need(u32, im.img, d.rva + 16, "export ordinal base");
        const nfun = need(u32, im.img, d.rva + 20, "export count");
        const afun = need(u32, im.img, d.rva + 28, "export functions");
        if (ordinal < obase or ordinal - obase >= nfun) return null;
        return self.exportRva(k, need(u32, im.img, afun + (ordinal - obase) * 4, "export rva"), depth);
    }

    /// An export RVA inside the export directory is a forwarder "DLL.Func" / "DLL.#N".
    fn exportRva(self: *Loader, k: usize, rva: u32, depth: u8) ?usize {
        if (rva == 0) return null;
        const im = self.images.items[k];
        const d = im.dirs[0];
        if (rva >= d.rva and rva < d.rva + d.size) {
            if (depth > 8) die(.bad_image, "{s}: export forwarder chain too deep", .{im.name});
            const fwd = cstr(im.img, rva, "forwarder");
            const dot = std.mem.lastIndexOfScalar(u8, fwd, '.') orelse die(.bad_image, "{s}: bad forwarder {s}", .{ im.name, fwd });
            const lib = std.fmt.allocPrint(self.a, "{s}.dll", .{fwd[0..dot]}) catch die(.map_failed, "out of memory", .{});
            return self.resolve(lib, fwd[dot + 1 ..], depth + 1);
        }
        return im.base + rva;
    }

    /// Resolve LIB!SYM ("#N" = ordinal) against loaded images, then the shim table.
    fn resolve(self: *Loader, lib: []const u8, sym: []const u8, depth: u8) ?usize {
        if (self.find(lib)) |k| {
            if (sym.len > 1 and sym[0] == '#') {
                const ord = std.fmt.parseInt(u16, sym[1..], 10) catch return null;
                return self.exportByOrdinal(k, ord, depth);
            }
            return self.exportByName(k, sym, depth);
        }
        if (self.findInDllDirs(lib) != null) { // a real DLL file that is not pinned is refused, not shimmed
            die(.refused, "{s} is in --dll-dir but not pinned (--pin {s}=SHA256); nothing executed", .{ lib, lib });
        }
        markSystemDll(lib);
        if (registryOverride(lib, sym)) |addr| return addr;
        const shim_lib = shimLibrary(lib);
        if (sym.len > 1 and sym[0] == '#') {
            const ord = std.fmt.parseInt(u16, sym[1..], 10) catch return null;
            const nm = @import("winrun_ordinals.zig").getOrdinalName(lib, ord) orelse return null;
            return winrun.lookup(shim_lib, nm);
        }
        return winrun.lookup(shim_lib, sym);
    }

    fn bind(self: *Loader, idx: usize) void {
        if (self.images.items[idx].state != .mapped) return;
        self.images.items[idx].state = .binding;
        for (self.images.items[idx].deps.items) |dep| self.bind(dep);
        const im = self.images.items[idx];
        for ([_]usize{ 1, 13 }) |dk| {
            const d = im.dirs[dk];
            if (d.size == 0) continue;
            const delay = dk == 13;
            const stride: usize = if (delay) 32 else 20;
            var p: usize = d.rva;
            while (p + stride <= d.rva + d.size) : (p += stride) {
                const name_rva = need(u32, im.img, p + (if (delay) @as(usize, 4) else 12), "import name");
                if (name_rva == 0) break;
                const lib = cstr(im.img, name_rva, "library name");
                const iat: usize = need(u32, im.img, p + (if (delay) @as(usize, 12) else 16), "IAT");
                const int_: usize = if (delay) need(u32, im.img, p + 16, "delay INT") else blk: {
                    const oft = need(u32, im.img, p, "OFT");
                    break :blk if (oft != 0) oft else iat;
                };
                if (delay) {
                    const attrs = need(u32, im.img, p, "delay attributes");
                    if (attrs & 1 == 0) die(.refused, "{s}: VA-based (v1) delay import descriptor unsupported", .{im.name});
                }
                var lt = int_;
                var at = iat;
                while (true) : ({
                    lt += 8;
                    at += 8;
                }) {
                    const thunk = need(u64, im.img, lt, "lookup thunk");
                    if (thunk == 0) break;
                    if (at + 8 > im.size_of_image) die(.bad_image, "{s}: IAT beyond image", .{im.name});
                    var symbuf: [16]u8 = undefined;
                    const sym = if (thunk >> 63 != 0)
                        std.fmt.bufPrint(&symbuf, "#{d}", .{thunk & 0xffff}) catch unreachable
                    else
                        cstr(im.img, @intCast((thunk & 0x7fffffff) + 2), "import name");
                    if (self.resolve(lib, sym, 0)) |addr| {
                        std.mem.writeInt(u64, im.img[at..][0..8], addr, .little);
                        self.n_imports += 1;
                    } else if ((delay or trap_all) and n_traps < max_traps) {
                        trap_names[n_traps] = std.fmt.allocPrint(self.a, "{s}!{s} (from {s})", .{ lib, sym, im.name }) catch "?";
                        std.mem.writeInt(u64, im.img[at..][0..8], @intFromPtr(trap_table[n_traps]), .little);
                        n_traps += 1;
                    } else {
                        self.missing.print(self.a, "  {s}: {s}!{s}{s}\n", .{ im.name, lib, sym, if (delay) " (delay)" else "" }) catch {};
                    }
                }
            }
        }
        self.images.items[idx].state = .bound;
    }

    fn protectImage(self: *Loader, idx: usize) void {
        const im = self.images.items[idx];
        protect(im.img.ptr, std.mem.alignForward(usize, im.size_of_headers, 4096), .{ .READ = true });
        for (im.secs) |s| {
            const len = std.mem.alignForward(usize, @max(s.vsize, s.raw_size), 4096);
            if (len == 0) continue;
            protect(im.img.ptr + s.va, len, .{
                .READ = s.chars & SCN_READ != 0 or s.chars & SCN_EXEC != 0,
                .WRITE = s.chars & SCN_WRITE != 0,
                .EXEC = s.chars & SCN_EXEC != 0,
            });
        }
    }

    fn protectAll(self: *Loader) void {
        for (0..self.images.items.len) |idx| self.protectImage(idx);
    }

    /// TLS callbacks + DllMain(PROCESS_ATTACH for DLLs only), dependencies first.
    fn initialize(self: *Loader, idx: usize) void {
        if (self.images.items[idx].state == .initialized) return;
        self.images.items[idx].state = .initialized;
        for (self.images.items[idx].deps.items) |dep| self.initialize(dep);
        const im = self.images.items[idx];
        const TlsCallback = *const fn (usize, u32, usize) callconv(W) void;
        for (im.tls_cb_rvas.items) |cb| (@as(TlsCallback, @ptrFromInt(im.base + cb)))(im.base, 1, 0);
        if (im.is_dll and im.entry_rva != 0) {
            if (!inExec(im.secs, im.entry_rva)) die(.bad_image, "{s}: entry point not executable", .{im.name});
            const DllMain = *const fn (usize, u32, usize) callconv(W) i32;
            const ok = (@as(DllMain, @ptrFromInt(im.base + im.entry_rva)))(im.base, 1, 0);
            if (ok == 0) die(.init_failed, "{s}: DllMain(PROCESS_ATTACH) returned FALSE", .{im.name});
        }
    }
};

fn callTarget(ld: *Loader, root_idx: usize, spec: []const u8) ?usize {
    if (std.mem.indexOfScalar(u8, spec, '!')) |bang| {
        const k = ld.find(spec[0..bang]) orelse return null;
        return ld.exportByName(k, spec[bang + 1 ..], 0);
    }
    return ld.exportByName(root_idx, spec, 0);
}

/// The process heap handle is an opaque cookie (the shim heap hands out
/// independent mappings), but on Windows it is the address of the NT heap's
/// HEAP structure and anti-debug code reads it directly: Flags (+0x70) and
/// ForceFlags (+0x74) gain HEAP_TAIL/FREE_CHECKING and
/// HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000060) under a debugger. Map one
/// read-only page at the cookie with the header fields of an undebugged
/// Windows 10 x64 process heap. The handle value itself does not change.
fn mapProcessHeapHeader(handle: usize) void {
    const rc = linux.mmap(@ptrFromInt(handle), 4096, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .FIXED_NOREPLACE = true }, -1, 0);
    if (linux.errno(rc) != .SUCCESS or rc != handle) {
        std.debug.print("winload64: could not map the process heap header at 0x{x}\n", .{handle});
        return;
    }
    const h: [*]u8 = @ptrFromInt(handle);
    std.mem.writeInt(u32, h[0x10..][0..4], 0xFFEEFFEE, .little); // Segment.SegmentSignature
    std.mem.writeInt(u32, h[0x14..][0..4], 0x00000002, .little); // Segment.SegmentFlags (HEAP_SEGMENT_FLAGS_DEFAULT)
    std.mem.writeInt(usize, h[0x18..][0..8], handle + 0x18, .little); // SegmentListEntry (empty)
    std.mem.writeInt(usize, h[0x20..][0..8], handle + 0x18, .little);
    std.mem.writeInt(usize, h[0x28..][0..8], handle, .little); // Heap (self)
    std.mem.writeInt(usize, h[0x30..][0..8], handle, .little); // BaseAddress
    std.mem.writeInt(u32, h[0x70..][0..4], 0x00000002, .little); // Flags = HEAP_GROWABLE
    std.mem.writeInt(u32, h[0x74..][0..4], 0x00000000, .little); // ForceFlags
    _ = linux.mprotect(@ptrFromInt(handle), 4096, .{ .READ = true });
}

/// PEB.Ldr: a PEB_LDR_DATA whose three module lists hold one
/// LDR_DATA_TABLE_ENTRY (Windows 10 x64 layout, 0x120 bytes) per PE image WINS
/// mapped, root image first, in load order. Protectors walk this list (DllBase,
/// SizeOfImage, names, OriginalBase) and probe it with IsBadReadPtr; a bogus Ldr
/// pointer makes them silently compute garbage. WINS' own kernel32/ntdll are not
/// PE images and are therefore not listed.
fn buildLoaderData(a: std.mem.Allocator, ld: *Loader) !usize {
    const n = ld.images.items.len;
    const LDR_SIZE = 0x58;
    const ENTRY_SIZE = 0x120;
    const blob = try a.alignedAlloc(u8, .fromByteUnits(16), LDR_SIZE + n * ENTRY_SIZE);
    @memset(blob, 0);
    const ldr = @intFromPtr(blob.ptr);
    const entry = struct {
        fn at(l: usize, i: usize) usize {
            return l + 0x58 + i * 0x120;
        }
    }.at;
    std.mem.writeInt(u32, blob[0..4], LDR_SIZE, .little); // Length
    blob[4] = 1; // Initialized
    // Order: root (the exe) first, then the rest in mapping order.
    var order = try a.alloc(usize, n);
    var k: usize = 0;
    for (ld.images.items, 0..) |im, i| if (!im.is_dll) {
        order[k] = i;
        k += 1;
    };
    for (ld.images.items, 0..) |im, i| if (im.is_dll) {
        order[k] = i;
        k += 1;
    };
    const W64 = struct {
        fn put(addr: usize, v: u64) void {
            @as(*align(1) u64, @ptrFromInt(addr)).* = v;
        }
        fn put32(addr: usize, v: u32) void {
            @as(*align(1) u32, @ptrFromInt(addr)).* = v;
        }
        fn put16(addr: usize, v: u16) void {
            @as(*align(1) u16, @ptrFromInt(addr)).* = v;
        }
        fn ustr(al: std.mem.Allocator, at_: usize, s_: []const u8) !void {
            const w = try al.alloc(u16, s_.len + 1);
            for (s_, 0..) |c, j| w[j] = c;
            w[s_.len] = 0;
            put16(at_, @intCast(s_.len * 2)); // Length
            put16(at_ + 2, @intCast((s_.len + 1) * 2)); // MaximumLength
            put(at_ + 8, @intFromPtr(w.ptr)); // Buffer
        }
    };
    // Three circular doubly-linked lists; heads at ldr+0x10/0x20/0x30, links at
    // entry+0x00/0x10/0x20 (each list's LIST_ENTRY points at the same-offset link).
    for (0..3) |list| {
        const head = ldr + 0x10 + list * 0x10;
        const link_off = list * 0x10;
        if (n == 0) {
            W64.put(head, head);
            W64.put(head + 8, head);
            continue;
        }
        for (0..n) |pos| {
            const me = entry(ldr, pos) + link_off;
            const next = if (pos + 1 < n) entry(ldr, pos + 1) + link_off else head;
            const prev = if (pos > 0) entry(ldr, pos - 1) + link_off else head;
            W64.put(me, next);
            W64.put(me + 8, prev);
        }
        W64.put(head, entry(ldr, 0) + link_off);
        W64.put(head + 8, entry(ldr, n - 1) + link_off);
    }
    for (order, 0..) |idx, pos| {
        const im = ld.images.items[idx];
        const e = entry(ldr, pos);
        W64.put(e + 0x30, im.base); // DllBase
        W64.put(e + 0x38, if (im.entry_rva != 0) im.base + im.entry_rva else 0); // EntryPoint
        W64.put32(e + 0x40, im.size_of_image); // SizeOfImage
        // Windows shows the DOS path the program was started from; WINS maps the
        // game directory at C:\ with the original file names.
        const base_name = std.fs.path.basename(im.full_path);
        const full = try std.fmt.allocPrint(a, "C:\\{s}", .{base_name});
        try W64.ustr(a, e + 0x48, full); // FullDllName
        try W64.ustr(a, e + 0x58, base_name); // BaseDllName
        W64.put32(e + 0x68, if (im.is_dll) 0x000CC004 else 0x00004000); // Flags: ImageDll|EntryProcessed|... / exe
        W64.put16(e + 0x6C, 0xFFFF); // ObsoleteLoadCount (static)
        W64.put(e + 0x70, e + 0x70); // HashLinks: self (unhashed)
        W64.put(e + 0x78, e + 0x70);
        W64.put32(e + 0x80, im.timestamp); // TimeDateStamp
        W64.put(e + 0xA0, e + 0xA0); // NodeModuleLink: self
        W64.put(e + 0xA8, e + 0xA0);
        W64.put(e + 0xF8, im.pref_base); // OriginalBase
        W64.put32(e + 0x114, 1); // ReferenceCount
    }
    return ldr;
}

fn initGuestThread(o: *threads.Object) void {
    const ld = g_ld orelse return;
    const alloc = std.heap.page_allocator;
    const teb = alloc.alignedAlloc(u8, .fromByteUnits(4096), 8192) catch return;
    @memset(teb, 0);
    ldLock();
    const n_tls = @max(ld.n_tls, 1);
    const tls_array = alloc.alloc(usize, n_tls + 64) catch {
        g_ld_lock.unlock();
        return;
    };
    @memset(tls_array, 0);
    for (ld.images.items) |im| if (im.tls_index) |k| {
        const block = alloc.alloc(u8, @max(im.tls_template_len + im.tls_zero_fill, 16)) catch continue;
        @memset(block, 0);
        if (im.tls_template_len > 0) @memcpy(block[0..im.tls_template_len], im.img[im.tls_template_rva..][0..im.tls_template_len]);
        tls_array[k] = @intFromPtr(block.ptr);
    };
    g_ld_lock.unlock();
    var stack_probe: u8 = 0;
    const sp = @intFromPtr(&stack_probe);
    const stack_bytes = @max(o.stack_size, 4 * 1024 * 1024);
    const stack_lim = (sp -| stack_bytes) + 65536;
    std.mem.writeInt(usize, teb[0x08..][0..8], std.mem.alignForward(usize, sp, 4096) + 4096, .little);
    std.mem.writeInt(usize, teb[0x10..][0..8], stack_lim, .little);
    std.mem.writeInt(usize, teb[0x30..][0..8], @intFromPtr(teb.ptr), .little);
    std.mem.writeInt(usize, teb[0x40..][0..8], @as(usize, @intCast(linux.getpid())), .little);
    std.mem.writeInt(usize, teb[0x48..][0..8], @as(usize, @intCast(linux.gettid())), .little);
    std.mem.writeInt(usize, teb[0x58..][0..8], @intFromPtr(tls_array.ptr), .little);
    std.mem.writeInt(usize, teb[0x60..][0..8], g_peb_ptr, .little);
    _ = linux.syscall2(.arch_prctl, 0x1001, @intFromPtr(teb.ptr));
}

fn threadsCloseHook(h: usize) bool {
    if (threads.isOurs(h)) {
        _ = threads.closeHandle(h);
        return true;
    }
    return false;
}

fn inExec(secs: []const Section, rva: u64) bool {
    for (secs) |s| if (s.chars & SCN_EXEC != 0 and rva >= s.va and rva < s.va + @max(s.vsize, s.raw_size)) return true;
    return false;
}

fn protect(p: [*]u8, len: usize, prot: linux.PROT) void {
    if (linux.errno(linux.mprotect(p, len, prot)) != .SUCCESS) die(.map_failed, "mprotect failed", .{});
}

/// api-set and redistributable CRT names map onto the shim table's CRT.
fn shimLibrary(lib: []const u8) []const u8 {
    if (std.ascii.startsWithIgnoreCase(lib, "api-ms-win-crt-") or
        std.ascii.eqlIgnoreCase(lib, "vcruntime140.dll") or
        std.ascii.eqlIgnoreCase(lib, "vcruntime140_1.dll") or
        std.ascii.eqlIgnoreCase(lib, "msvcp140.dll")) return "ucrtbase.dll";
    if (std.ascii.startsWithIgnoreCase(lib, "api-ms-win-core-")) return "kernel32.dll";
    // D3DCompiler_43 (June 2010 SDK) exports the same reflection API as _47.
    if (std.ascii.eqlIgnoreCase(lib, "d3dcompiler_43.dll")) return "d3dcompiler_47.dll";
    return lib;
}

/// outstr: the export takes `const char** out` first and returns the length;
/// winload64 passes a cell, then prints `length` bytes from *out.
const Call = struct { name: []const u8, args: std.ArrayList(u64) = .empty, ret: enum { u32, i32, u64, str, outstr } = .u64 };

const usage = "usage: winload64 --pin ROOT.dll=HEX [--pin DEP.dll=HEX ...] [--dll-dir DIR] [--check] ROOT.dll [--call EXPORT [--arg N ...] [--ret u32|i32|u64|str]] ...";

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    var ld: Loader = .{ .a = a, .io = init.io };
    var root: ?[]const u8 = null;
    var check_only = false;
    var run_exe = false;
    var calls: std.ArrayList(Call) = .empty;
    var preloads: std.ArrayList([]const u8) = .empty;
    var target_args: std.ArrayList([]const u8) = .empty;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        const more = i + 1 < args.len;
        if (std.mem.eql(u8, arg, "--pin") and more) {
            i += 1;
            const eq = std.mem.indexOfScalar(u8, args[i], '=') orelse die(.usage, "--pin wants NAME=SHA256", .{});
            try ld.pins.put(a, ld.lower(std.fs.path.basename(args[i][0..eq])), args[i][eq + 1 ..]);
        } else if (std.mem.eql(u8, arg, "--dll-dir") and more) {
            i += 1;
            try ld.dll_dirs.append(a, args[i]);
        } else if (std.mem.eql(u8, arg, "--preload") and more) {
            i += 1;
            try preloads.append(a, args[i]);
        } else if (std.mem.eql(u8, arg, "--trap-unresolved")) {
            trap_all = true;
        } else if (std.mem.eql(u8, arg, "--check")) {
            check_only = true;
        } else if (std.mem.eql(u8, arg, "--run")) {
            run_exe = true;
        } else if (std.mem.eql(u8, arg, "--call") and more) {
            i += 1;
            try calls.append(a, .{ .name = args[i] });
        } else if (std.mem.eql(u8, arg, "--arg") and more and calls.items.len > 0) {
            i += 1;
            const v = std.fmt.parseInt(i64, args[i], 0) catch die(.usage, "bad --arg {s}", .{args[i]});
            try calls.items[calls.items.len - 1].args.append(a, @bitCast(v));
        } else if (std.mem.eql(u8, arg, "--arg-str") and more and calls.items.len > 0) {
            // Two args: pointer to a NUL-terminated copy of the string, then its length.
            i += 1;
            const z = try a.dupeZ(u8, args[i]);
            try calls.items[calls.items.len - 1].args.append(a, @intFromPtr(z.ptr));
            try calls.items[calls.items.len - 1].args.append(a, z.len);
        } else if (std.mem.eql(u8, arg, "--ret") and more and calls.items.len > 0) {
            i += 1;
            calls.items[calls.items.len - 1].ret = std.meta.stringToEnum(@TypeOf(calls.items[0].ret), args[i]) orelse die(.usage, "bad --ret {s}", .{args[i]});
        } else if (root == null and !std.mem.startsWith(u8, arg, "--")) {
            root = arg;
            try target_args.append(a, arg);
        } else if (root != null) {
            try target_args.append(a, arg);
        } else die(.usage, usage, .{});
    }
    if (root == null) die(.usage, usage, .{});
    if (!check_only and !std.mem.eql(u8, init.environ_map.get("WINS_WINRUN_BOX") orelse "", "1"))
        die(.usage, "execution requires the boxed launcher; use winload64_box.py", .{});

    g_ld = &ld;
    gaps64.set_last_error = &gapsSetLastError;
    gaps64.resolve = &gapsResolve;
    steam64.setIo(ld.io);
    if (winrun.lookup("kernel32.dll", "SetLastError")) |f| @import("winload64_sync.zig").set_last_error = @ptrFromInt(f);
    const root_idx = ld.map(root.?);
    for (preloads.items) |pl| {
        const dp = ld.findInDllDirs(pl) orelse pl;
        const pidx = ld.map(dp);
        try ld.images.items[root_idx].deps.append(a, pidx);
    }
    for (0..ld.images.items.len) |k| ld.bind(k);
    if (ld.missing.items.len != 0) die(.unresolved, "unresolved imports, nothing executed:\n{s}", .{ld.missing.items});
    // --call EXPORT targets the root; --call DLL!EXPORT any loaded image.
    for (calls.items) |c| if (callTarget(&ld, root_idx, c.name) == null) die(.unresolved, "no export {s}", .{c.name});

    var pdata: usize = 0;
    for (ld.images.items) |im| pdata += im.pdata_entries;
    std.debug.print("winload64: READY images={d} imports={d} tls_slots={d} delay_traps={d} pdata={d}\n", .{ ld.images.items.len, ld.n_imports, ld.n_tls, n_traps, pdata });
    for (ld.images.items) |im| std.debug.print("  {s} base=0x{x} tls={?d} tls_callbacks={d} entry=0x{x}\n", .{ im.name, im.base, im.tls_index, im.tls_cb_rvas.items.len, im.entry_rva });
    if (check_only) std.process.exit(0);

    ld.protectAll();

    // GS-based TEB/PEB (same layout winrun uses), one implicit-TLS block per image.
    const teb = try a.alignedAlloc(u8, .fromByteUnits(4096), 8192);
    const peb = try a.alignedAlloc(u8, .fromByteUnits(4096), 4096);
    const params = try a.alignedAlloc(u8, .fromByteUnits(4096), 4096);
    const tls_array = try a.alloc(usize, @max(ld.n_tls, 1) + 64);
    @memset(teb, 0);
    @memset(peb, 0);
    @memset(params, 0);
    @memset(tls_array, 0);
    for (ld.images.items) |im| if (im.tls_index) |k| {
        const block = try a.alloc(u8, @max(im.tls_template_len + im.tls_zero_fill, 16));
        @memset(block, 0);
        if (im.tls_template_len > 0) @memcpy(block[0..im.tls_template_len], im.img[im.tls_template_rva..][0..im.tls_template_len]);
        tls_array[k] = @intFromPtr(block.ptr);
    };
    var stack_probe: u8 = 0;
    const sp = @intFromPtr(&stack_probe);
    std.mem.writeInt(usize, teb[0x08..][0..8], std.mem.alignForward(usize, sp, 4096) + 4096, .little); // StackBase (approx.)
    std.mem.writeInt(usize, teb[0x10..][0..8], sp - 8 * 1024 * 1024 + 4096, .little); // StackLimit (8 MiB stack)
    std.mem.writeInt(usize, teb[0x30..][0..8], @intFromPtr(teb.ptr), .little); // NtCurrentTeb()
    std.mem.writeInt(usize, teb[0x40..][0..8], @as(usize, @intCast(linux.getpid())), .little); // ClientId.UniqueProcess
    std.mem.writeInt(usize, teb[0x48..][0..8], @as(usize, @intCast(linux.gettid())), .little); // ClientId.UniqueThread
    std.mem.writeInt(usize, teb[0x58..][0..8], @intFromPtr(tls_array.ptr), .little); // ThreadLocalStoragePointer
    std.mem.writeInt(usize, teb[0x60..][0..8], @intFromPtr(peb.ptr), .little); // ProcessEnvironmentBlock
    g_peb_ptr = @intFromPtr(peb.ptr);
    @import("winrun_ntdll64.zig").peb_ptr = g_peb_ptr;
    std.mem.writeInt(usize, peb[0x10..][0..8], ld.images.items[root_idx].base, .little); // ImageBaseAddress
    std.mem.writeInt(usize, peb[0x18..][0..8], buildLoaderData(a, &ld) catch 0, .little); // Ldr
    std.mem.writeInt(usize, peb[0x30..][0..8], k32.processHeapHandle(), .little); // ProcessHeap (== GetProcessHeap())
    mapProcessHeapHeader(k32.processHeapHandle());
    std.mem.writeInt(usize, peb[0x20..][0..8], @intFromPtr(params.ptr), .little); // ProcessParameters
    // OS version, as RtlGetVersion/GetVersionEx report it (Windows 10 22H2).
    // Left at zero, DS3's Arxan picked the pre-Vista HEAP layout (Flags +0x14,
    // ForceFlags +0x18), read a non-zero pointer there and took its tamper path.
    std.mem.writeInt(u32, peb[0x118..][0..4], 10, .little); // OSMajorVersion
    std.mem.writeInt(u32, peb[0x11c..][0..4], 0, .little); // OSMinorVersion
    std.mem.writeInt(u16, peb[0x120..][0..2], 19045, .little); // OSBuildNumber
    std.mem.writeInt(u16, peb[0x122..][0..2], 0, .little); // OSCSDVersion
    std.mem.writeInt(u32, peb[0x124..][0..4], 2, .little); // OSPlatformId = VER_PLATFORM_WIN32_NT
    if (linux.errno(linux.syscall2(.arch_prctl, 0x1001, @intFromPtr(teb.ptr))) != .SUCCESS) die(.map_failed, "arch_prctl(ARCH_SET_GS) failed", .{});
    k32.teb_tls_enabled = true;

    const crt = @import("winrun_msvcrt.zig");
    k32.setImageBase(ld.images.items[root_idx].base);
    k32.close_handle_hook = &threadsCloseHook;
    if (std.c.getenv("WINS_STEP_FROM_VEH") != null) seh64.on_add_veh = &armFromVeh;
    if (std.c.getenv("WINS_STEP_AT_PRESENT") != null or std.c.getenv("WINS_STEP_AT_STEAMSLOT") != null or std.c.getenv("WINS_STEP_ALL_AT_PRESENT") != null) seh64.arm_hook = &armAtPresent;
    threads.g_thread_init = &initGuestThread;
    for (ld.images.items) |im| seh64.addExceptionTable(im.base, im.img.len, im.dirs[3].rva, im.dirs[3].size);
    crt.setArgs(target_args.items);
    k32.setCommandLine(target_args.items);

    installCrashReport(ld.images.items);
    wpInstall(ld.images.items[root_idx].base);
    // KUSER_SHARED_DATA at 0x7FFE0000, before any guest code (DllMain included) runs.
    if (!@import("winrun_kuser64.zig").install())
        std.debug.print("winload64: KUSER_SHARED_DATA could not be mapped at 0x7ffe0000; guests reading it will fault\n", .{});
    ld.initialize(root_idx);

    if (run_exe or calls.items.len == 0) {
        const root_im = ld.images.items[root_idx];
        if (root_im.entry_rva == 0) die(.usage, "root image has no entry point; pass --call EXPORT", .{});
        const EntryFn = *const fn () callconv(W) u32;
        const rc = (@as(EntryFn, @ptrFromInt(root_im.base + root_im.entry_rva)))();
        std.process.exit(@truncate(rc));
    }

    var out: [256]u8 = undefined;
    for (calls.items) |c| {
        const addr = callTarget(&ld, root_idx, c.name).?;
        var av = [4]u64{ 0, 0, 0, 0 };
        var out_cell: u64 = 0;
        const shift: usize = if (c.ret == .outstr) 1 else 0;
        if (c.args.items.len + shift > 4) die(.usage, "--call {s}: at most 4 integer args", .{c.name});
        if (shift == 1) av[0] = @intFromPtr(&out_cell);
        for (c.args.items, 0..) |v, k| av[k + shift] = v;
        const F = *const fn (u64, u64, u64, u64) callconv(W) u64;
        const r = (@as(F, @ptrFromInt(addr)))(av[0], av[1], av[2], av[3]);
        const s = switch (c.ret) {
            .u32 => try std.fmt.bufPrint(&out, "{d}", .{@as(u32, @truncate(r))}),
            .i32 => try std.fmt.bufPrint(&out, "{d}", .{@as(i32, @bitCast(@as(u32, @truncate(r))))}),
            .u64 => try std.fmt.bufPrint(&out, "0x{x}", .{r}),
            .str => if (r == 0) "(null)" else std.mem.span(@as([*:0]const u8, @ptrFromInt(r))),
            .outstr => if (out_cell == 0) "(null)" else @as([*]const u8, @ptrFromInt(out_cell))[0..@min(@as(usize, @truncate(r)), 4096)],
        };
        std.debug.print("call {s} = {s}\n", .{ c.name, s });
    }
    std.process.exit(0);
}
