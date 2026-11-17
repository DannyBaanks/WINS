//! Win64-to-SysV bridge for the host Steam client's ISteamClient interface.
//!
//! The module handle is synthetic, but every Steam answer comes from the real
//! host steamclient.so. An explicit conflicting SteamAppId or an unavailable
//! writable Valve IPC object makes the module unavailable; when SteamAppId is
//! absent, steam_api64.dll obtains the app id from the real Steam client.
const std = @import("std");

const W = std.builtin.CallingConvention{ .x86_64_win = .{} };
const C = std.builtin.CallingConvention.c;
pub const steam_app_id: u32 = 268910;
pub const module_handle: usize = 0x7FFD_5354_0000;
const client_dll_name = "steamclient64.dll";
const ipc_marker = "ValveIPCSharedObj";
const max_slots = 40;
const adapter_capacity = 64;

extern "c" fn dlopen(path: [*:0]const u8, flags: c_int) ?*anyopaque;
extern "c" fn dlsym(handle: ?*anyopaque, name: [*:0]const u8) ?*anyopaque;
extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;
extern "c" fn open(path: [*:0]const u8, flags: c_int, ...) c_int;
extern "c" fn read(fd: c_int, buffer: [*]u8, count: usize) isize;
extern "c" fn close(fd: c_int) c_int;

const VFunc = *const fn (usize, usize, usize, usize, usize, usize, usize, usize, usize) callconv(W) usize;

const Adapter = extern struct {
    vtable: *const [max_slots]VFunc,
    real: usize,
};

var g_handle: ?*anyopaque = null;
var g_create: ?*const fn (?[*:0]const u8, ?*i32) callconv(C) ?*anyopaque = null;
var g_pipe_fn: ?*const fn () callconv(C) u32 = null;
var g_user_fn: ?*const fn (u32) callconv(C) u32 = null;
var g_client_real: usize = 0;
var g_adapters: [adapter_capacity]Adapter = undefined;
var g_adapter_count: usize = 0;
var g_ready = false;
var g_attempted = false;
var g_io: std.Io = undefined;
var g_io_ready = false;

pub fn setIo(io: std.Io) void {
    g_io = io;
    g_io_ready = true;
}

fn moduleBaseName(raw: []const u8) []const u8 {
    return if (std.mem.lastIndexOfAny(u8, raw, "\\/")) |i| raw[i + 1 ..] else raw;
}

pub fn isSteamClientDll(raw: []const u8) bool {
    return std.ascii.eqlIgnoreCase(moduleBaseName(raw), client_dll_name);
}

/// Return the PID of an actual Steam client process, as observed in /proc.
/// SteamAPI_IsSteamRunning checks this registry value with OpenProcess and
/// GetExitCodeProcess, so an absent process must produce no PID.
pub fn steamClientPid() u32 {
    if (!g_io_ready) return 0;
    var dir = std.Io.Dir.cwd().openDir(g_io, "/proc", .{ .iterate = true }) catch return 0;
    defer dir.close(g_io);
    var it = dir.iterate();
    while (it.next(g_io) catch return 0) |entry| {
        const pid = std.fmt.parseInt(u32, entry.name, 10) catch continue;
        var path: [64:0]u8 = undefined;
        const path_z = std.fmt.bufPrintZ(&path, "/proc/{d}/comm", .{pid}) catch continue;
        const fd = open(path_z, 0);
        if (fd < 0) continue;
        var comm: [64]u8 = undefined;
        const n = read(fd, &comm, comm.len);
        _ = close(fd);
        if (n <= 0) continue;
        const name = std.mem.trim(u8, comm[0..@intCast(n)], " \t\r\n");
        if (std.mem.eql(u8, name, "steam")) return pid;
    }
    return 0;
}

pub fn isSteamPidAlive(pid: u32) bool {
    return pid != 0 and steamClientPid() == pid;
}

pub fn querySteamPidValue(pid: u32, value_type: ?*u32, data: ?[*]u8, size: ?*u32) i32 {
    if (pid == 0) {
        if (size) |out| out.* = 0;
        return 2; // ERROR_FILE_NOT_FOUND
    }
    if (value_type) |out| out.* = 4; // REG_DWORD
    if (size) |out| {
        const supplied = out.*;
        out.* = @sizeOf(u32);
        if (data) |dst| {
            if (supplied < @sizeOf(u32)) return 234; // ERROR_MORE_DATA
            @memcpy(dst[0..@sizeOf(u32)], std.mem.asBytes(&pid));
        }
    } else if (data != null) {
        return 87; // ERROR_INVALID_PARAMETER
    }
    return 0;
}

pub fn appIdMatches(value: []const u8) bool {
    const parsed = std.fmt.parseInt(u32, value, 10) catch return false;
    return parsed == steam_app_id;
}

fn appIdEnvAllowed() bool {
    // steam_api64.dll obtains a missing SteamAppId from real ISteamUtils::GetAppID
    // during Init and then sets SteamAppId/SteamGameId itself. Preserve that
    // behavior; reject only an explicitly conflicting app id.
    const value = getenv("SteamAppId") orelse return true;
    return appIdMatches(std.mem.span(value));
}

fn liveValveIpc() bool {
    // Refuse stale, read-only, or absent IPC objects. Scanning /dev/shm does not
    // modify Steam; open(O_RDWR) matches the 32-bit bridge's liveness gate.
    if (!g_io_ready) return false;
    var dir = std.Io.Dir.cwd().openDir(g_io, "/dev/shm", .{ .iterate = true }) catch return false;
    defer dir.close(g_io);
    var it = dir.iterate();
    while (it.next(g_io) catch return false) |entry| {
        if (std.mem.indexOf(u8, entry.name, ipc_marker) == null) continue;
        var path_buf: [512]u8 = undefined;
        const path = std.fmt.bufPrintZ(&path_buf, "/dev/shm/{s}", .{entry.name}) catch continue;
        const fd = open(path, 2); // O_RDWR on Linux
        if (fd >= 0) {
            _ = close(fd);
            return true;
        }
    }
    return false;
}

fn hostSteamRoot(buf: []u8) ?[]const u8 {
    if (getenv("SteamPath")) |steam_path| {
        const root = std.mem.span(steam_path);
        if (std.mem.startsWith(u8, root, "/") and root.len != 0) {
            return std.fmt.bufPrint(buf, "{s}", .{root}) catch null;
        }
    }
    const home_z = getenv("HOME") orelse return null;
    const home = std.mem.span(home_z);
    if (home.len == 0) return null;
    return std.fmt.bufPrint(buf, "{s}/.local/share/Steam", .{home}) catch null;
}

pub fn nativeClientPath(buf: []u8, steam_root: []const u8) ?[:0]const u8 {
    if (steam_root.len == 0) return null;
    const sep = if (std.mem.endsWith(u8, steam_root, "/")) "" else "/";
    return std.fmt.bufPrintZ(buf, "{s}{s}linux64/steamclient.so", .{ steam_root, sep }) catch null;
}

fn hostClientPath(buf: []u8) ?[:0]const u8 {
    var root_buf: [1024]u8 = undefined;
    const root = hostSteamRoot(&root_buf) orelse return null;
    return nativeClientPath(buf, root);
}

fn adapterFor(real: usize) usize {
    if (real == 0) return 0;
    for (g_adapters[0..g_adapter_count]) |*adapter| {
        if (adapter.real == real) return @intFromPtr(adapter);
    }
    if (g_adapter_count == adapter_capacity) return 0;
    const adapter = &g_adapters[g_adapter_count];
    adapter.* = .{ .vtable = &client_vtable, .real = real };
    g_adapter_count += 1;
    return @intFromPtr(adapter);
}

fn isClientGetter(slot: usize) bool {
    // Observed ISteamClient slots in the working 32-bit bridge. These methods
    // return real subinterfaces; wrap each before exposing it to Win64 code.
    return slot == 5 or slot == 8 or slot == 9 or slot == 13 or slot == 14 or slot == 16;
}

fn dispatch(slot: usize, this: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize) usize {
    // The working 32-bit bridge measured that these initial methods crash on
    // the raw client's vtable before the client has established its own pipe.
    // Use the host client's real flat entry points for these two slots.
    if (slot == 0) return if (g_pipe_fn) |f| f() else 0;
    if (slot == 2) return if (g_user_fn) |f| f(@truncate(a1)) else 0;
    if (this == 0) return 0;
    const adapter: *const Adapter = @ptrFromInt(this);
    if (adapter.real == 0) return 0;
    const real_vtable: [*]const usize = @ptrFromInt((@as(*const usize, @ptrFromInt(adapter.real)).*));
    const address = real_vtable[slot];
    if (address == 0) return 0;
    const method: *const fn (usize, usize, usize, usize, usize, usize, usize, usize, usize) callconv(C) usize = @ptrFromInt(address);
    const result = method(adapter.real, a1, a2, a3, a4, a5, a6, a7, a8);
    return if (isClientGetter(slot)) adapterFor(result) else result;
}

fn thunk(comptime slot: usize) VFunc {
    return &struct {
        fn call(this: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize) callconv(W) usize {
            return dispatch(slot, this, a1, a2, a3, a4, a5, a6, a7, a8);
        }
    }.call;
}

const client_vtable: [max_slots]VFunc = init: {
    var table: [max_slots]VFunc = undefined;
    for (0..max_slots) |i| table[i] = thunk(i);
    break :init table;
};

fn ensureClient() bool {
    if (g_ready) return true;
    if (g_attempted) return false;
    g_attempted = true;
    if (!appIdEnvAllowed()) {
        std.debug.print("[WINS:SteamBridge64] SteamAppId conflicts with Cuphead ({d}); refusing Steam client access.\n", .{steam_app_id});
        return false;
    }
    if (!liveValveIpc()) {
        std.debug.print("[WINS:SteamBridge64] no writable ValveIPCSharedObj; Steam client is not live.\n", .{});
        return false;
    }
    var path_buf: [2048]u8 = undefined;
    const path = hostClientPath(&path_buf) orelse {
        std.debug.print("[WINS:SteamBridge64] HOME is unavailable; cannot locate host steamclient.so.\n", .{});
        return false;
    };
    g_handle = dlopen(path, 2) orelse {
        std.debug.print("[WINS:SteamBridge64] dlopen({s}) failed.\n", .{path});
        return false;
    };
    const symbol = dlsym(g_handle, "CreateInterface") orelse {
        std.debug.print("[WINS:SteamBridge64] host steamclient.so has no CreateInterface.\n", .{});
        return false;
    };
    g_create = @ptrCast(symbol);
    g_pipe_fn = if (dlsym(g_handle, "Steam_CreateSteamPipe")) |p| @ptrCast(p) else null;
    g_user_fn = if (dlsym(g_handle, "Steam_ConnectToGlobalUser")) |p| @ptrCast(p) else null;
    if (g_pipe_fn == null or g_user_fn == null) {
        std.debug.print("[WINS:SteamBridge64] host steamclient.so is missing real pipe/user entry points.\n", .{});
        return false;
    }
    var rc: i32 = -1;
    const client_name: [:0]const u8 = "SteamClient017";
    const real = g_create.?(client_name.ptr, &rc) orelse {
        std.debug.print("[WINS:SteamBridge64] real client refused SteamClient017 (rc={d}).\n", .{rc});
        return false;
    };
    g_client_real = @intFromPtr(real);
    if (adapterFor(g_client_real) == 0) {
        std.debug.print("[WINS:SteamBridge64] adapter pool exhausted.\n", .{});
        return false;
    }
    g_ready = true;
    std.debug.print("[WINS:SteamBridge64] connected to the real host SteamClient017 interface.\n", .{});
    return true;
}

pub fn getModuleHandle(raw: []const u8) usize {
    if (!isSteamClientDll(raw) or !ensureClient()) return 0;
    return module_handle;
}

pub fn loadLibrary(raw: []const u8) usize {
    return getModuleHandle(raw);
}

pub fn getProcAddress(handle: usize, raw_symbol: []const u8) usize {
    if (handle != module_handle or !ensureClient()) return 0;
    if (!std.mem.eql(u8, raw_symbol, "CreateInterface")) return 0;
    return @intFromPtr(&createInterfaceWin);
}

fn createInterfaceWin(name: ?[*:0]const u8, return_code: ?*i32) callconv(W) ?*anyopaque {
    if (return_code) |rc| rc.* = 1;
    if (name == null or !ensureClient()) return null;
    const requested = std.mem.span(name.?);
    if (!std.mem.eql(u8, requested, "SteamClient017")) return null;
    if (return_code) |rc| rc.* = 0;
    const wrapped = adapterFor(g_client_real);
    return if (wrapped == 0) null else @ptrFromInt(wrapped);
}

pub fn fileName(handle: usize, out: []u8) ?[]const u8 {
    if (handle != module_handle or !ensureClient()) return null;
    var root_buf: [1024]u8 = undefined;
    const root = hostSteamRoot(&root_buf) orelse return null;
    const suffix = "\\steamclient64.dll";
    const need = 2 + root.len + suffix.len;
    if (need > out.len) return null;
    out[0] = 'Z';
    out[1] = ':';
    for (root, 0..) |ch, i| out[2 + i] = if (ch == '/') '\\' else ch;
    @memcpy(out[2 + root.len .. need], suffix);
    return out[0..need];
}

test "Steam client module names are case insensitive and path aware" {
    try std.testing.expect(isSteamClientDll("steamclient64.dll"));
    try std.testing.expect(isSteamClientDll("C:\\Steam\\steamclient64.DLL"));
    try std.testing.expect(!isSteamClientDll("steamclient.dll"));
    try std.testing.expect(!isSteamClientDll("steam_api64.dll"));
}

test "Valve shared memory matching is literal" {
    try std.testing.expect(std.mem.indexOf(u8, "u1000-ValveIPCSharedObj-Steam", ipc_marker) != null);
    try std.testing.expect(std.mem.indexOf(u8, "SteamStart_SharedMemFile", ipc_marker) == null);
}

test "native Steam client path uses the host Steam root" {
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings(
        "/home/test/.local/share/Steam/linux64/steamclient.so",
        nativeClientPath(&buf, "/home/test/.local/share/Steam").?,
    );
    try std.testing.expectEqualStrings(
        "/home/test/.local/share/Steam/linux64/steamclient.so",
        nativeClientPath(&buf, "/home/test/.local/share/Steam/").?,
    );
    try std.testing.expect(nativeClientPath(&buf, "") == null);
}

test "Steam app id parsing is exact and rejects malformed values" {
    try std.testing.expect(appIdMatches("268910"));
    try std.testing.expect(!appIdMatches("268911"));
    try std.testing.expect(!appIdMatches("268910x"));
    try std.testing.expect(!appIdMatches(""));
}

test "missing host Steam process is never assigned a synthetic pid" {
    try std.testing.expectEqual(@as(u32, 0), steamClientPid());
    try std.testing.expect(!isSteamPidAlive(12345));
}

test "Steam PID registry values preserve Win32 size and absence semantics" {
    var size: u32 = 4;
    var kind: u32 = 0;
    var bytes: [4]u8 = .{ 0, 0, 0, 0 };
    try std.testing.expectEqual(@as(i32, 0), querySteamPidValue(4321, &kind, &bytes, &size));
    try std.testing.expectEqual(@as(u32, 4), kind);
    try std.testing.expectEqual(@as(u32, 4), size);
    try std.testing.expectEqual(@as(u32, 4321), @as(*const u32, @ptrCast(@alignCast(&bytes))).*);

    size = 3;
    try std.testing.expectEqual(@as(i32, 234), querySteamPidValue(4321, &kind, &bytes, &size));
    try std.testing.expectEqual(@as(u32, 4), size);

    size = 4;
    try std.testing.expectEqual(@as(i32, 2), querySteamPidValue(0, &kind, &bytes, &size));
    try std.testing.expectEqual(@as(u32, 0), size);
}
