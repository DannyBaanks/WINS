//! Win64-to-SysV bridge for the host Steam client's ISteamClient interface.
//!
//! The module handle is synthetic, but every Steam answer comes from the real
//! host steamclient.so. An explicit conflicting SteamAppId or an unavailable
//! writable Valve IPC object makes the module unavailable; when SteamAppId is
//! absent, steam_api64.dll obtains the app id from the real Steam client.
const std = @import("std");

const W = std.builtin.CallingConvention{ .x86_64_win = .{} };
const C = std.builtin.CallingConvention.c;
/// The app id this run belongs to: the launcher's WINS_STEAM_APP_ID, else the
/// STEAM_COMPAT_APP_ID Steam itself gives a compatibility tool, else Cuphead
/// (the first game this bridge served). A different SteamAppId is a conflict.
pub const default_steam_app_id: u32 = 268910;
pub fn expectedAppId() u32 {
    inline for (.{ "WINS_STEAM_APP_ID", "STEAM_COMPAT_APP_ID" }) |name| {
        if (getenv(name)) |v| if (std.fmt.parseInt(u32, std.mem.span(v), 10)) |id| return id else |_| {};
    }
    return default_steam_app_id;
}
/// Synthetic handle used while no steamclient64.dll image is mapped. When the
/// launcher pins the host's real (Valve-signed) steamclient64.dll, winrun64 maps
/// it as a facade image and this becomes that image's base.
pub const synthetic_module_handle: usize = 0x7FFD_5354_0000;
pub var module_handle: usize = synthetic_module_handle;
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
    kind: InterfaceKind,
    version: u32,
};

const InterfaceKind = enum(u8) { client, user, friends, utils, matchmaking, user_stats, apps, remote_storage, unknown };
const SlotAbi = enum { plain, sret8, float_xmm, float_double_xmm, reverse_warning_hook, reverse_post_result, reverse_check_callback };
const SlotSpec = struct { slot: usize, abi: SlotAbi };

// ABI-sensitive entries from the SDK vtable order. Other methods use the
// integer/pointer forwarding thunk. Getter strings are logged at runtime so
// the selected interface revision is measured rather than assumed.
const user_abi_slots = [_]SlotSpec{.{ .slot = 2, .abi = .sret8 }}; // ISteamUser::GetSteamID
const user_stats_abi_slots = [_]SlotSpec{
    .{ .slot = 4, .abi = .float_xmm }, // SetStat(const char *, float)
    .{ .slot = 5, .abi = .float_double_xmm }, // UpdateAvgRateStat(const char *, float, double)
};
const client_callback_abi_slots = [_]SlotSpec{
    .{ .slot = 21, .abi = .reverse_warning_hook },
    .{ .slot = 31, .abi = .reverse_post_result },
    .{ .slot = 32, .abi = .reverse_post_result },
    .{ .slot = 33, .abi = .reverse_check_callback },
};

var g_handle: ?*anyopaque = null;
var g_create: ?*const fn (?[*:0]const u8, ?*i32) callconv(C) ?*anyopaque = null;
var g_pipe_fn: ?*const fn () callconv(C) u32 = null;
var g_user_fn: ?*const fn (u32) callconv(C) u32 = null;
var g_bget_callback: ?*const fn (u32, *CallbackMsg) callconv(C) bool = null;
var g_free_last_callback: ?*const fn (u32) callconv(C) void = null;
var g_get_api_call_result: ?*const fn (u32, u64, [*]u8, u32, i32, *bool) callconv(C) bool = null;
var g_post_result_win: ?*const fn (u64, ?*anyopaque, u32, i32) callconv(W) void = null;
var g_check_callback_win: ?*const fn (i32) callconv(W) u32 = null;
var g_warning_hook_win: ?*const fn (i32, [*:0]const u8) callconv(W) void = null;
var g_client_real: usize = 0;
var g_adapters: [adapter_capacity]Adapter = undefined;
var g_adapter_count: usize = 0;
var g_ready = false;
var g_attempted = false;
var g_io: std.Io = undefined;
var g_io_ready = false;
var callback_data_win: [512]u8 = @splat(0);

const CallbackMsg = extern struct { user: i32, callback: i32, param: ?[*]u8, size: i32 };

const CallbackLayout = enum { same, user_stats_received, user_stats_stored, achievement_stored, remote_file_share, remote_read_complete, remote_write_complete, unsupported };

fn callbackLayout(callback: i32) CallbackLayout {
    return switch (callback) {
        1101 => .user_stats_received, // UserStatsReceived_t: CGameID, EResult, CSteamID
        1102 => .user_stats_stored,
        1103 => .achievement_stored,
        1307 => .remote_file_share,
        1331 => .remote_write_complete,
        1332 => .remote_read_complete,
        // Same field shape as UserStatsReceived_t / UserStatsStored_t, so the same conversion:
        143 => .user_stats_received, // ValidateAuthTicketResponse_t: CSteamID, EAuthSessionResponse, CSteamID
        304 => .user_stats_stored, // PersonaStateChange_t: uint64 steamID, int flags (Linux 12, Windows 16)
        // Only 1/4-byte fields, or 8-byte fields already 8-aligned with a size that is a
        // multiple of 8: identical bytes under Linux pack(4) and Windows pack(8).
        101, // SteamServersConnected_t (empty)
        102, // SteamServerConnectFailure_t: EResult, bool
        103, // SteamServersDisconnected_t: EResult
        117, // IPCFailure_t: uint8
        125, // LicensesUpdated_t (empty)
        154, // EncryptedAppTicketResponse_t: EResult
        163, // GetAuthSessionTicketResponse_t: HAuthTicket, EResult
        331, // GameOverlayActivated_t: uint8, bool, AppId_t
        701, // IPCountry_t (empty)
        702, // LowBatteryPower_t: uint8
        703, // SteamAPICallCompleted_t: SteamAPICall_t, int, uint32 (16 both)
        704, // SteamShutdown_t (empty)
        5001, // SteamParentalSettingsChanged_t (empty)
        => .same,
        else => .unsupported,
    };
}

fn callbackNativeSize(callback: i32) ?usize {
    return switch (callbackLayout(callback)) {
        .user_stats_received => 20,
        .user_stats_stored => 12,
        .achievement_stored => 148,
        .remote_file_share => 272,
        .remote_read_complete => 20,
        .remote_write_complete => 4,
        .same, .unsupported => null,
    };
}

fn callbackWindowsSize(callback: i32) ?usize {
    return switch (callbackLayout(callback)) {
        .user_stats_received => 24,
        .user_stats_stored => 16,
        .achievement_stored => 152,
        .remote_file_share => 280,
        .remote_read_complete => 24,
        .remote_write_complete => 4,
        .same, .unsupported => null,
    };
}

fn convertCallbackToWin(callback: i32, input: []const u8, output: []u8) ?usize {
    switch (callbackLayout(callback)) {
        .unsupported => return null,
        .same => {
            if (input.len > output.len) return null;
            @memcpy(output[0..input.len], input);
            return input.len;
        },
        .user_stats_received => {
            // Linux pack(4): gameID@0, result@8, userID@12, size 20.
            // Windows pack(8): gameID@0, result@8, userID@16, size 24.
            if (input.len != 20 or output.len < 24) return null;
            @memcpy(output[0..12], input[0..12]);
            @memcpy(output[16..24], input[12..20]);
            return 24;
        },
        .user_stats_stored => return paddedCopy(input, output, 12, 16),
        .achievement_stored => return paddedCopy(input, output, 148, 152),
        .remote_file_share => {
            // Result@0, UGCHandle@4/name@12 in Linux; handle@8/name@16 in Windows.
            if (input.len != 272 or output.len < 280) return null;
            @memcpy(output[0..4], input[0..4]);
            @memcpy(output[8..16], input[4..12]);
            @memcpy(output[16..276], input[12..272]);
            @memset(output[276..280], 0);
            return 280;
        },
        .remote_read_complete => return paddedCopy(input, output, 20, 24),
        .remote_write_complete => return paddedCopy(input, output, 4, 4),
    }
}

fn convertCallbackFromWin(callback: i32, input: []const u8, output: []u8) ?usize {
    switch (callbackLayout(callback)) {
        .unsupported => return null,
        .same => {
            if (input.len > output.len) return null;
            @memcpy(output[0..input.len], input);
            return input.len;
        },
        .user_stats_received => {
            if (input.len != 24 or output.len < 20) return null;
            @memcpy(output[0..12], input[0..12]);
            @memcpy(output[12..20], input[16..24]);
            return 20;
        },
        .user_stats_stored => return paddedCopy(input, output, 16, 12),
        .achievement_stored => return paddedCopy(input, output, 152, 148),
        .remote_file_share => {
            if (input.len != 280 or output.len < 272) return null;
            @memcpy(output[0..4], input[0..4]);
            @memcpy(output[4..12], input[8..16]);
            @memcpy(output[12..272], input[16..276]);
            return 272;
        },
        .remote_read_complete => return paddedCopy(input, output, 24, 20),
        .remote_write_complete => return paddedCopy(input, output, 4, 4),
    }
}

fn paddedCopy(input: []const u8, output: []u8, in_size: usize, out_size: usize) ?usize {
    if (input.len != in_size or output.len < out_size) return null;
    const copy_size = @min(in_size, out_size);
    @memcpy(output[0..copy_size], input[0..copy_size]);
    if (out_size > copy_size) @memset(output[copy_size..out_size], 0);
    return out_size;
}

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
    return parsed == expectedAppId();
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
    // Under a Steam launch HOME is the sandboxed game profile, not the user's
    // home, so the install path Steam itself exports must win over HOME.
    for ([_][*:0]const u8{ "SteamPath", "STEAM_COMPAT_CLIENT_INSTALL_PATH" }) |name| {
        if (getenv(name)) |steam_path| {
            const root = std.mem.span(steam_path);
            if (std.mem.startsWith(u8, root, "/")) {
                return std.fmt.bufPrint(buf, "{s}", .{root}) catch null;
            }
        }
    }
    const home_z = getenv("HOME") orelse return null;
    const home = std.mem.span(home_z);
    if (home.len == 0) return null;
    return std.fmt.bufPrint(buf, "{s}/.local/share/Steam", .{home}) catch null;
}

/// Host path of the Windows client DLL Steam for Linux ships (Proton copies the
/// same file into its prefixes): <SteamRoot>/steamclient64.dll.
pub fn hostWindowsClientPath(buf: []u8) ?[]const u8 {
    var root_buf: [1024]u8 = undefined;
    const root = hostSteamRoot(&root_buf) orelse return null;
    const sep = if (std.mem.endsWith(u8, root, "/")) "" else "/";
    return std.fmt.bufPrint(buf, "{s}{s}steamclient64.dll", .{ root, sep }) catch null;
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

fn versionNumber(version: []const u8) u32 {
    var i = version.len;
    while (i > 0 and version[i - 1] >= '0' and version[i - 1] <= '9') : (i -= 1) {}
    return if (i == version.len) 0 else std.fmt.parseInt(u32, version[i..], 10) catch 0;
}

fn vtableFor(kind: InterfaceKind) *const [max_slots]VFunc {
    return switch (kind) {
        .client => &client_vtable,
        .user => &user_vtable,
        .user_stats => &stats_vtable,
        else => &interface_vtable,
    };
}

fn adapterFor(real: usize, kind: InterfaceKind, version: []const u8) usize {
    if (real == 0) return 0;
    for (g_adapters[0..g_adapter_count]) |*adapter| {
        if (adapter.real == real and adapter.kind == kind and adapter.version == versionNumber(version)) return @intFromPtr(adapter);
    }
    if (g_adapter_count == adapter_capacity) return 0;
    const adapter = &g_adapters[g_adapter_count];
    adapter.* = .{ .vtable = vtableFor(kind), .real = real, .kind = kind, .version = versionNumber(version) };
    g_adapter_count += 1;
    return @intFromPtr(adapter);
}

fn traceInterface(source: []const u8, version: []const u8) void {
    if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:SteamABI64] {s} requested {s}\n", .{ source, version });
}

var steam_trace_state: i8 = -1;
var steam_seen: [16][max_slots]bool = @splat(@splat(false));
/// WINS_STEAM_TRACE: one line the first time each interface method is called, so a
/// late new call (after a menu step) stands out.
fn steamFirstCallTrace(adapter: *const Adapter, slot: usize, a1: usize, a2: usize, a3: usize, result: usize) void {
    if (steam_trace_state < 0) steam_trace_state = if (std.c.getenv("WINS_STEAM_TRACE") != null) 1 else 0;
    if (steam_trace_state != 1) return;
    const k = @intFromEnum(adapter.kind) & 15;
    if (slot >= max_slots or steam_seen[k][slot]) return;
    steam_seen[k][slot] = true;
    std.debug.print("[WINS:SteamCall] {s}{d}[{d}](0x{x}, 0x{x}, 0x{x}) -> 0x{x}\n", .{ @tagName(adapter.kind), adapter.version, slot, a1, a2, a3, result });
}

fn dispatch(slot: usize, this: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize) usize {
    if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:SteamABI64] enter slot {d} this=0x{x}\n", .{ slot, this });
    if (this == 0) return 0;
    const adapter: *const Adapter = @ptrFromInt(this);
    if (adapter.real == 0) return 0;
    // The working 32-bit bridge measured these client slots failing on the raw
    // vtable before a pipe exists. Never apply them to sub-interface slots.
    if (adapter.kind == .client and slot == 0) {
        const pipe = if (g_pipe_fn) |f| f() else 0;
        if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:SteamABI64] client{d}[0] CreateSteamPipe -> {d}\n", .{ adapter.version, pipe });
        return pipe;
    }
    if (adapter.kind == .client and slot == 2) {
        const user = if (g_user_fn) |f| f(@truncate(a1)) else 0;
        if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:SteamABI64] client{d}[2] ConnectToGlobalUser({d}) -> {d}\n", .{ adapter.version, a1, user });
        return user;
    }
    const real_vtable: [*]const usize = @ptrFromInt((@as(*const usize, @ptrFromInt(adapter.real)).*));
    const address = real_vtable[slot];
    if (address == 0) return 0;
    const method: *const fn (usize, usize, usize, usize, usize, usize, usize, usize, usize) callconv(C) usize = @ptrFromInt(address);
    const result = method(adapter.real, a1, a2, a3, a4, a5, a6, a7, a8);
    @import("winrun_seh64.zig").maybeArmStep(@intCast(0x10000 + slot));
    if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:SteamABI64] {s}{d}[{d}](0x{x}, 0x{x}, 0x{x}) -> 0x{x}\n", .{ @tagName(adapter.kind), adapter.version, slot, a1, a2, a3, result });
    steamFirstCallTrace(adapter, slot, a1, a2, a3, result);
    if (adapter.kind != .client) return result;
    if (!isClientGetter(slot)) return result;
    const version_ptr = if (slot == 9) a2 else a3;
    if (version_ptr == 0) return 0;
    const version = std.mem.span(@as([*:0]const u8, @ptrFromInt(version_ptr)));
    traceInterface("ISteamClient getter", version);
    return wrapGetterResult(adapter.kind, slot, result, version);
}

fn interfaceKindForVersion(version: []const u8) InterfaceKind {
    if (std.mem.startsWith(u8, version, "SteamUser")) return .user;
    if (std.mem.startsWith(u8, version, "SteamFriends")) return .friends;
    if (std.mem.startsWith(u8, version, "SteamUtils")) return .utils;
    if (std.mem.startsWith(u8, version, "SteamMatchMaking") or std.mem.startsWith(u8, version, "SteamMatchmaking")) return .matchmaking;
    if (std.mem.startsWith(u8, version, "STEAMUSERSTATS")) return .user_stats;
    if (std.mem.startsWith(u8, version, "SteamApps") or std.mem.startsWith(u8, version, "STEAMAPPS")) return .apps;
    if (std.mem.startsWith(u8, version, "STEAMREMOTESTORAGE")) return .remote_storage;
    return .unknown;
}

fn isClientGetter(slot: usize) bool {
    return switch (slot) {
        5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        23, 24, 25, 26, 27, 28, 29, 30, 34, 35 => true,
        else => false,
    };
}

fn wrapGetterResult(parent: InterfaceKind, slot: usize, result: usize, version: []const u8) usize {
    if (parent != .client or result == 0) return result;
    if (!isClientGetter(slot)) return result;
    return adapterFor(result, interfaceKindForVersion(version), version);
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
    for (client_callback_abi_slots) |s| {
        table[s.slot] = switch (s.abi) {
            .reverse_warning_hook => clientSetWarningHookThunk(),
            .reverse_post_result => clientSetPostResultThunk(s.slot),
            .reverse_check_callback => clientSetCheckCallbackThunk(),
            else => unreachable,
        };
    }
    break :init table;
};

const interface_vtable: [max_slots]VFunc = init: {
    var table: [max_slots]VFunc = undefined;
    for (0..max_slots) |i| table[i] = thunk(i);
    break :init table;
};

const user_vtable: [max_slots]VFunc = init: {
    var table: [max_slots]VFunc = undefined;
    for (0..max_slots) |i| table[i] = thunk(i);
    for (user_abi_slots) |s| if (s.abi == .sret8) { table[s.slot] = userGetSteamIdThunk(); };
    break :init table;
};

const stats_vtable: [max_slots]VFunc = init: {
    var table: [max_slots]VFunc = undefined;
    for (0..max_slots) |i| table[i] = thunk(i);
    for (user_stats_abi_slots) |s| {
        table[s.slot] = if (s.abi == .float_xmm) statsSetFloatThunk() else statsUpdateRateThunk();
    }
    break :init table;
};

fn userGetSteamIdThunk() VFunc {
    return @ptrCast(&struct {
        fn call(this: usize, out: ?*u64) callconv(W) usize {
            if (out == null or this == 0) return 0;
            const adapter: *const Adapter = @ptrFromInt(this);
            if (adapter.kind != .user or adapter.real == 0) return 0;
            const vt: [*]const usize = @ptrFromInt(@as(*const usize, @ptrFromInt(adapter.real)).*);
            const f: *const fn (usize) callconv(C) u64 = @ptrFromInt(vt[2]);
            out.?.* = f(adapter.real);
            return @intFromPtr(out.?);
        }
    }.call);
}

fn statsSetFloatThunk() VFunc {
    return @ptrCast(&struct {
        fn call(this: usize, name: usize, value: f32) callconv(W) u8 {
            if (this == 0) return 0;
            const adapter: *const Adapter = @ptrFromInt(this);
            if (adapter.kind != .user_stats or adapter.real == 0) return 0;
            const vt: [*]const usize = @ptrFromInt(@as(*const usize, @ptrFromInt(adapter.real)).*);
            const f: *const fn (usize, usize, f32) callconv(C) u8 = @ptrFromInt(vt[4]);
            return f(adapter.real, name, value);
        }
    }.call);
}

fn statsUpdateRateThunk() VFunc {
    return @ptrCast(&struct {
        fn call(this: usize, name: usize, count: f32, session_seconds: f64) callconv(W) u8 {
            if (this == 0) return 0;
            const adapter: *const Adapter = @ptrFromInt(this);
            if (adapter.kind != .user_stats or adapter.real == 0) return 0;
            const vt: [*]const usize = @ptrFromInt(@as(*const usize, @ptrFromInt(adapter.real)).*);
            const f: *const fn (usize, usize, f32, f64) callconv(C) u8 = @ptrFromInt(vt[5]);
            return f(adapter.real, name, count, session_seconds);
        }
    }.call);
}

fn postResultSysv(call: u64, data: ?*anyopaque, size: u32, callback: i32) callconv(C) void {
    if (g_post_result_win) |f| f(call, data, size, callback);
}

fn warningHookSysv(severity: i32, message: [*:0]const u8) callconv(C) void {
    if (g_warning_hook_win) |f| f(severity, message);
}

fn checkCallbackSysv(callback: i32) callconv(C) u32 {
    return if (g_check_callback_win) |f| f(callback) else 0;
}

fn clientSetPostResultThunk(comptime slot: usize) VFunc {
    return @ptrCast(&struct {
        fn call(this: usize, callback: usize) callconv(W) usize {
            if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:SteamABI64] callback-hook thunk this=0x{x} cb=0x{x}\n", .{ this, callback });
            if (this == 0) return 0;
            const adapter: *const Adapter = @ptrFromInt(this);
            if (adapter.kind != .client or adapter.real == 0) return 0;
            const vt: [*]const usize = @ptrFromInt(@as(*const usize, @ptrFromInt(adapter.real)).*);
            const f: *const fn (usize, usize) callconv(C) void = @ptrFromInt(vt[slot]);
            g_post_result_win = if (callback == 0) null else @ptrFromInt(callback);
            f(adapter.real, if (callback == 0) 0 else @intFromPtr(&postResultSysv));
            return 0;
        }
    }.call);
}

fn clientSetWarningHookThunk() VFunc {
    return @ptrCast(&struct {
        fn call(this: usize, callback: usize) callconv(W) usize {
            if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:SteamABI64] callback-hook thunk this=0x{x} cb=0x{x}\n", .{ this, callback });
            if (this == 0) return 0;
            const adapter: *const Adapter = @ptrFromInt(this);
            if (adapter.kind != .client or adapter.real == 0) return 0;
            const vt: [*]const usize = @ptrFromInt(@as(*const usize, @ptrFromInt(adapter.real)).*);
            const f: *const fn (usize, usize) callconv(C) void = @ptrFromInt(vt[21]);
            g_warning_hook_win = if (callback == 0) null else @ptrFromInt(callback);
            f(adapter.real, if (callback == 0) 0 else @intFromPtr(&warningHookSysv));
            return 0;
        }
    }.call);
}

fn clientSetCheckCallbackThunk() VFunc {
    return @ptrCast(&struct {
        fn call(this: usize, callback: usize) callconv(W) usize {
            if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:SteamABI64] callback-hook thunk this=0x{x} cb=0x{x}\n", .{ this, callback });
            if (this == 0) return 0;
            const adapter: *const Adapter = @ptrFromInt(this);
            if (adapter.kind != .client or adapter.real == 0) return 0;
            const vt: [*]const usize = @ptrFromInt(@as(*const usize, @ptrFromInt(adapter.real)).*);
            const f: *const fn (usize, usize) callconv(C) void = @ptrFromInt(vt[33]);
            g_check_callback_win = if (callback == 0) null else @ptrFromInt(callback);
            f(adapter.real, if (callback == 0) 0 else @intFromPtr(&checkCallbackSysv));
            return 0;
        }
    }.call);
}

fn ensureClient() bool {
    if (g_ready) return true;
    if (g_attempted) return false;
    g_attempted = true;
    if (!appIdEnvAllowed()) {
        std.debug.print("[WINS:SteamBridge64] SteamAppId conflicts with this run's app id ({d}); refusing Steam client access.\n", .{expectedAppId()});
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
    g_bget_callback = if (dlsym(g_handle, "Steam_BGetCallback")) |p| @ptrCast(p) else null;
    g_free_last_callback = if (dlsym(g_handle, "Steam_FreeLastCallback")) |p| @ptrCast(p) else null;
    g_get_api_call_result = if (dlsym(g_handle, "Steam_GetAPICallResult")) |p| @ptrCast(p) else null;
    if (g_pipe_fn == null or g_user_fn == null) {
        std.debug.print("[WINS:SteamBridge64] host steamclient.so is missing real pipe/user entry points.\n", .{});
        return false;
    }
    var rc: i32 = -1;
    const client_name: [:0]const u8 = "SteamClient017";
    traceInterface("host CreateInterface", client_name);
    const real = g_create.?(client_name.ptr, &rc) orelse {
        std.debug.print("[WINS:SteamBridge64] real client refused SteamClient017 (rc={d}).\n", .{rc});
        return false;
    };
    g_client_real = @intFromPtr(real);
    if (adapterFor(g_client_real, .client, "SteamClient017") == 0) {
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
    return bridgedExport(raw_symbol);
}

/// Win64 implementation of a steamclient64.dll export, or 0 when it is not bridged.
pub fn bridgedExport(raw_symbol: []const u8) usize {
    if (!ensureClient()) return 0;
    if (std.mem.eql(u8, raw_symbol, "CreateInterface")) return @intFromPtr(&createInterfaceWin);
    if (std.mem.eql(u8, raw_symbol, "Steam_BGetCallback") and g_bget_callback != null) return @intFromPtr(&steamBGetCallbackWin);
    if (std.mem.eql(u8, raw_symbol, "Steam_FreeLastCallback") and g_free_last_callback != null) return @intFromPtr(&steamFreeLastCallbackWin);
    if (std.mem.eql(u8, raw_symbol, "Steam_GetAPICallResult") and g_get_api_call_result != null) return @intFromPtr(&steamGetApiCallResultWin);
    traceInterface("GetProcAddress (not bridged)", raw_symbol);
    return 0;
}

fn steamBGetCallbackWin(pipe: u32, out: ?*CallbackMsg) callconv(W) bool {
    if (out == null) return false;
    const host = g_bget_callback orelse return false;
    const got = host(pipe, out.?);
    if (!got) return false;
    const msg = out.?.*;
    if (callbackLayout(msg.callback) == .unsupported) {
        // Ids >= 1000000 are steamclient-internal (k_iClient*): no game registers them.
        if (msg.callback < 1_000_000) std.debug.print("[WINS:SteamABI64] dropped unsupported callback id={d}\n", .{msg.callback});
        if (g_free_last_callback) |free| free(pipe);
        return false;
    }
    if (msg.param == null or msg.size < 0) {
        std.debug.print("[WINS:SteamABI64] dropped malformed callback id={d} size={d}\n", .{ msg.callback, msg.size });
        if (g_free_last_callback) |free| free(pipe);
        return false;
    }
    const converted = convertCallbackToWin(msg.callback, msg.param.?[0..@intCast(msg.size)], &callback_data_win);
    if (converted) |size| {
        out.?.param = &callback_data_win;
        out.?.size = @intCast(size);
        return true;
    }
    std.debug.print("[WINS:SteamABI64] dropped malformed callback id={d} size={d}\n", .{ msg.callback, msg.size });
    if (g_free_last_callback) |free| free(pipe);
    return false;
}

fn steamFreeLastCallbackWin(pipe: u32) callconv(W) void {
    if (g_free_last_callback) |free| free(pipe);
}

fn steamGetApiCallResultWin(pipe: u32, call: u64, buffer: ?[*]u8, buffer_size: i32, expected_callback: i32, failed: ?*bool) callconv(W) bool {
    if (buffer == null or buffer_size < 0 or failed == null) return false;
    const host = g_get_api_call_result orelse return false;
    const layout = callbackLayout(expected_callback);
    if (layout == .unsupported) {
        std.debug.print("[WINS:SteamABI64] rejected APICallResult callback id={d}\n", .{expected_callback});
        return false;
    }
    if (layout == .same) return host(pipe, call, buffer.?, @intCast(buffer_size), expected_callback, failed.?);
    const native_size = callbackNativeSize(expected_callback) orelse return false;
    const windows_size = callbackWindowsSize(expected_callback) orelse return false;
    if (buffer_size < windows_size) return false;
    @memset(callback_data_win[0..native_size], 0);
    var host_failed = false;
    const ok = host(pipe, call, &callback_data_win, @intCast(native_size), expected_callback, &host_failed);
    failed.?.* = host_failed;
    if (!ok) return false;
    return convertCallbackToWin(expected_callback, callback_data_win[0..native_size], buffer.?[0..@intCast(buffer_size)]) != null;
}

/// ISteamClient revisions whose vtable prefix matches 017 for every slot the
/// adapter treats specially (pipe/user 0 and 2, getters, callback hooks 21/31-33).
fn clientRevisionBridged(name: []const u8) bool {
    const revisions = [_][]const u8{ "SteamClient012", "SteamClient013", "SteamClient014", "SteamClient015", "SteamClient016" };
    for (revisions) |r| if (std.mem.eql(u8, name, r)) return true;
    return false;
}

fn createInterfaceWin(name: ?[*:0]const u8, return_code: ?*i32) callconv(W) ?*anyopaque {
    if (return_code) |rc| rc.* = 1;
    if (name == null) return null;
    const requested = std.mem.span(name.?);
    traceInterface("CreateInterface", requested);
    if (!ensureClient()) return null;
    var real = g_client_real;
    if (!std.mem.eql(u8, requested, "SteamClient017")) {
        if (!clientRevisionBridged(requested)) {
            traceInterface("CreateInterface (not bridged)", requested);
            return null;
        }
        // Another ISteamClient revision (SteamStub's DRM module asks for 014 after
        // 017): the host client still serves it; only the object differs.
        var host_rc: i32 = -1;
        const name_z = std.heap.page_allocator.dupeZ(u8, requested) catch return null;
        defer std.heap.page_allocator.free(name_z);
        const obj = g_create.?(name_z.ptr, &host_rc) orelse {
            traceInterface("CreateInterface (host refused)", requested);
            return null;
        };
        real = @intFromPtr(obj);
    }
    if (return_code) |rc| rc.* = 0;
    const wrapped = adapterFor(real, .client, requested);
    return if (wrapped == 0) null else @ptrFromInt(wrapped);
}

/// Writes `value` as a REG_SZ registry result (RegQueryValueExA semantics:
/// size includes the terminating NUL; ERROR_MORE_DATA when the buffer is short).
pub fn writeRegSz(value: []const u8, value_type: ?*u32, data: ?[*]u8, size: ?*u32) i32 {
    const need: u32 = @intCast(value.len + 1);
    if (value_type) |out| out.* = 1; // REG_SZ
    if (size) |out| {
        const supplied = out.*;
        out.* = need;
        if (data) |dst| {
            if (supplied < need) return 234; // ERROR_MORE_DATA
            @memcpy(dst[0..value.len], value);
            dst[value.len] = 0;
        }
    } else if (data != null) {
        return 87; // ERROR_INVALID_PARAMETER
    }
    return 0;
}

/// HKCU\Software\Valve\Steam\ActiveProcess\SteamClientDll64, as the real Steam
/// client writes it on Windows. steam_api64 only runs SteamAPI_IsSteamRunning and
/// loads the client when this value exists. Present only while a live host Steam
/// client is reachable; otherwise ERROR_FILE_NOT_FOUND, like a PC without Steam.
pub fn querySteamClientDllValue(value_type: ?*u32, data: ?[*]u8, size: ?*u32) i32 {
    if (steamClientPid() == 0) {
        if (size) |out| out.* = 0;
        return 2; // ERROR_FILE_NOT_FOUND
    }
    var path_buf: [2048]u8 = undefined;
    const path = fileName(module_handle, &path_buf) orelse {
        if (size) |out| out.* = 0;
        return 2;
    };
    return writeRegSz(path, value_type, data, size);
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

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

test "host Steam root prefers Steam's exported install path over a sandboxed HOME" {
    var buf: [256]u8 = undefined;
    _ = unsetenv("SteamPath");
    _ = setenv("HOME", "/tmp/wins-workspace/home", 1);
    _ = setenv("STEAM_COMPAT_CLIENT_INSTALL_PATH", "/home/test/.local/share/Steam", 1);
    try std.testing.expectEqualStrings("/home/test/.local/share/Steam", hostSteamRoot(&buf).?);
    _ = setenv("SteamPath", "/opt/steam", 1);
    try std.testing.expectEqualStrings("/opt/steam", hostSteamRoot(&buf).?);
    _ = setenv("SteamPath", "relative/steam", 1);
    try std.testing.expectEqualStrings("/home/test/.local/share/Steam", hostSteamRoot(&buf).?);
    // Negative control: with neither Steam variable, HOME is the only source.
    _ = unsetenv("SteamPath");
    _ = unsetenv("STEAM_COMPAT_CLIENT_INSTALL_PATH");
    try std.testing.expectEqualStrings("/tmp/wins-workspace/home/.local/share/Steam", hostSteamRoot(&buf).?);
}

test "Steam app id parsing is exact and rejects malformed values" {
    _ = unsetenv("WINS_STEAM_APP_ID");
    _ = unsetenv("STEAM_COMPAT_APP_ID");
    try std.testing.expect(appIdMatches("268910"));
    try std.testing.expect(!appIdMatches("268911"));
    try std.testing.expect(!appIdMatches("268910x"));
    try std.testing.expect(!appIdMatches(""));
    // Steam's compat-tool app id selects the game; the launcher's value wins over it.
    _ = setenv("STEAM_COMPAT_APP_ID", "374320", 1);
    try std.testing.expect(appIdMatches("374320"));
    try std.testing.expect(!appIdMatches("268910"));
    _ = setenv("WINS_STEAM_APP_ID", "268910", 1);
    try std.testing.expect(appIdMatches("268910"));
    try std.testing.expect(!appIdMatches("374320"));
    _ = unsetenv("WINS_STEAM_APP_ID");
    _ = unsetenv("STEAM_COMPAT_APP_ID");
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

test "REG_SZ registry results follow RegQueryValueExA size semantics" {
    var ty: u32 = 0;
    var size: u32 = 4;
    var buf: [64]u8 = undefined;
    try std.testing.expectEqual(@as(i32, 234), writeRegSz("Z:\\steam\\steamclient64.dll", &ty, &buf, &size));
    try std.testing.expectEqual(@as(u32, 27), size);
    size = buf.len;
    try std.testing.expectEqual(@as(i32, 0), writeRegSz("Z:\\steam\\steamclient64.dll", &ty, &buf, &size));
    try std.testing.expectEqual(@as(u32, 1), ty);
    try std.testing.expectEqualStrings("Z:\\steam\\steamclient64.dll", std.mem.sliceTo(&buf, 0));
    var only_size: u32 = 0;
    try std.testing.expectEqual(@as(i32, 0), writeRegSz("abc", null, null, &only_size));
    try std.testing.expectEqual(@as(u32, 4), only_size);
}

var abi_test_vtable: [max_slots]usize = @splat(0);
var abi_test_object: usize = 0;
var abi_test_float: f32 = 0;
var abi_test_double: f64 = 0;
var abi_test_name: usize = 0;
var abi_test_post: [4]u64 = @splat(0);

fn abiTestSteamId(_: usize) callconv(C) u64 {
    return 0x1122_3344_5566_7788;
}

fn abiTestSetFloat(_: usize, name: usize, value: f32) callconv(C) u8 {
    abi_test_name = name;
    abi_test_float = value;
    return 1;
}

fn abiTestUpdateRate(_: usize, name: usize, count: f32, elapsed: f64) callconv(C) u8 {
    abi_test_name = name;
    abi_test_float = count;
    abi_test_double = elapsed;
    return 1;
}

fn abiTestPostWin(call: u64, data: ?*anyopaque, size: u32, callback: i32) callconv(W) void {
    abi_test_post = .{ call, if (data) |p| @intFromPtr(p) else 0, size, @as(u64, @intCast(@as(u32, @bitCast(callback)))) };
}

fn abiTestCheckWin(callback: i32) callconv(W) u32 {
    return @as(u32, @bitCast(callback)) + 5;
}

fn abiTestWarningWin(severity: i32, message: [*:0]const u8) callconv(W) void {
    abi_test_post[0] = @as(u64, @intCast(severity));
    abi_test_post[1] = @intFromPtr(message);
}

test "SteamID sret thunk writes the SysV 8-byte return and returns out pointer" {
    abi_test_vtable = @splat(0);
    abi_test_vtable[2] = @intFromPtr(&abiTestSteamId);
    abi_test_object = @intFromPtr(&abi_test_vtable);
    const adapter = Adapter{ .vtable = &user_vtable, .real = @intFromPtr(&abi_test_object), .kind = .user, .version = 23 };
    var output: u64 = 0;
    const thunk_fn: *const fn (usize, ?*u64) callconv(W) usize = @ptrCast(userGetSteamIdThunk());
    const returned = thunk_fn(@intFromPtr(&adapter), &output);
    try std.testing.expectEqual(@as(u64, 0x1122_3344_5566_7788), output);
    try std.testing.expectEqual(@intFromPtr(&output), returned);
}

test "float stats thunk moves Win64 positional XMM argument into SysV xmm0" {
    abi_test_vtable = @splat(0);
    abi_test_vtable[4] = @intFromPtr(&abiTestSetFloat);
    abi_test_object = @intFromPtr(&abi_test_vtable);
    const adapter = Adapter{ .vtable = &stats_vtable, .real = @intFromPtr(&abi_test_object), .kind = .user_stats, .version = 12 };
    const thunk_fn: *const fn (usize, usize, f32) callconv(W) u8 = @ptrCast(statsSetFloatThunk());
    const ok = thunk_fn(@intFromPtr(&adapter), 0xabc, 3.25);
    try std.testing.expectEqual(@as(u8, 1), ok);
    try std.testing.expectEqual(@as(usize, 0xabc), abi_test_name);
    try std.testing.expectEqual(@as(f32, 3.25), abi_test_float);
}

test "float and double rate thunk repacks positional Win64 XMM arguments for SysV" {
    abi_test_vtable = @splat(0);
    abi_test_vtable[5] = @intFromPtr(&abiTestUpdateRate);
    abi_test_object = @intFromPtr(&abi_test_vtable);
    const adapter = Adapter{ .vtable = &stats_vtable, .real = @intFromPtr(&abi_test_object), .kind = .user_stats, .version = 12 };
    const thunk_fn: *const fn (usize, usize, f32, f64) callconv(W) u8 = @ptrCast(statsUpdateRateThunk());
    const ok = thunk_fn(@intFromPtr(&adapter), 0xdef, 1.75, 9.5);
    try std.testing.expectEqual(@as(u8, 1), ok);
    try std.testing.expectEqual(@as(usize, 0xdef), abi_test_name);
    try std.testing.expectEqual(@as(f32, 1.75), abi_test_float);
    try std.testing.expectEqual(@as(f64, 9.5), abi_test_double);
}

test "UserStatsReceived callback layout converts the shifted CSteamID" {
    var linux_bytes = [_]u8{0} ** 20;
    linux_bytes[0] = 1;
    linux_bytes[8] = 2;
    linux_bytes[12] = 0x88;
    linux_bytes[19] = 0x11;
    var windows_bytes = [_]u8{0} ** 24;
    try std.testing.expectEqual(@as(?usize, 24), convertCallbackToWin(1101, &linux_bytes, &windows_bytes));
    try std.testing.expectEqual(@as(u8, 0x88), windows_bytes[16]);
    try std.testing.expectEqual(@as(u8, 0x11), windows_bytes[23]);
    var roundtrip = [_]u8{0} ** 20;
    try std.testing.expectEqual(@as(?usize, 20), convertCallbackFromWin(1101, &windows_bytes, &roundtrip));
    try std.testing.expectEqualSlices(u8, &linux_bytes, &roundtrip);
}

test "known stats and cloud callback structs receive Windows pack-8 sizes" {
    var linux_bytes = [_]u8{0x5a} ** 272;
    var win_bytes = [_]u8{0} ** 512;
    try std.testing.expectEqual(@as(?usize, 16), convertCallbackToWin(1102, linux_bytes[0..12], &win_bytes));
    try std.testing.expectEqual(@as(?usize, 152), convertCallbackToWin(1103, linux_bytes[0..148], &win_bytes));
    try std.testing.expectEqual(@as(?usize, 280), convertCallbackToWin(1307, &linux_bytes, &win_bytes));
    try std.testing.expectEqual(@as(u8, 0x5a), win_bytes[8]);
    try std.testing.expectEqual(@as(u8, 0x5a), win_bytes[16]);
    try std.testing.expectEqual(@as(?usize, 24), convertCallbackToWin(1332, linux_bytes[0..20], &win_bytes));
    try std.testing.expectEqual(@as(?usize, null), convertCallbackToWin(999999, &linux_bytes, &win_bytes));
}

test "reverse callbacks translate SysV calls back to Win64 callbacks" {
    abi_test_post = @splat(0);
    g_post_result_win = &abiTestPostWin;
    defer g_post_result_win = null;
    postResultSysv(0x1234, @ptrFromInt(0x5678), 32, 1101);
    try std.testing.expectEqual([_]u64{ 0x1234, 0x5678, 32, 1101 }, abi_test_post);
    g_check_callback_win = &abiTestCheckWin;
    defer g_check_callback_win = null;
    try std.testing.expectEqual(@as(u32, 1106), checkCallbackSysv(1101));
    abi_test_post = @splat(0);
    g_warning_hook_win = &abiTestWarningWin;
    defer g_warning_hook_win = null;
    warningHookSysv(1, "warning" ++ .{0});
    try std.testing.expectEqual(@as(u64, 1), abi_test_post[0]);
    try std.testing.expectEqual(@intFromPtr("warning" ++ .{0}), abi_test_post[1]);
}

test "typed dispatch wraps only client getter methods" {
    const old_count = g_adapter_count;
    defer g_adapter_count = old_count;
    const raw = 0x1234_5678;
    const user = wrapGetterResult(.client, 5, raw, "SteamUser023");
    try std.testing.expect(user != raw);
    const adapter: *const Adapter = @ptrFromInt(user);
    try std.testing.expectEqual(InterfaceKind.user, adapter.kind);
    try std.testing.expectEqual(raw, wrapGetterResult(.client, 20, raw, "SteamUtils010"));
    try std.testing.expectEqual(raw, wrapGetterResult(.user, 5, raw, "SteamUser023"));
    try std.testing.expectEqual(raw, wrapGetterResult(.client, 4, raw, "SteamUser023"));
}
