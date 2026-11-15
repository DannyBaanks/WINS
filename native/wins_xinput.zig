//! WINS native XInput 1.3 / 1.4 / 9.1.0 shim over SDL2 GameController (via dlopen).
//!
//! Exports all documented xinput1_3 entry points (and ordinal 100 XInputGetStateEx)
//! with the Win32 `stdcall` (`winapi`) calling convention. When a real game
//! controller is attached and host `libSDL2-2.0.so.0` is available, its axes,
//! triggers, buttons and rumble are mapped live into `XINPUT_STATE` and
//! `XInputSetState`. When no controller is attached, `ERROR_DEVICE_NOT_CONNECTED`
//! (1167) is returned honestly so games fall back to keyboard and mouse.

const std = @import("std");
const linux = std.os.linux;

const W: std.builtin.CallingConvention = .winapi;

pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_BAD_ARGUMENTS: u32 = 160;
pub const ERROR_DEVICE_NOT_CONNECTED: u32 = 1167;
pub const ERROR_EMPTY: u32 = 4306;

pub const XINPUT_DEVTYPE_GAMEPAD: u8 = 0x01;
pub const XINPUT_DEVSUBTYPE_GAMEPAD: u8 = 0x01;
pub const XINPUT_CAPS_VOICE_SUPPORTED: u16 = 0x0004;

pub const BATTERY_TYPE_DISCONNECTED: u8 = 0x00;
pub const BATTERY_TYPE_WIRED: u8 = 0x01;
pub const BATTERY_LEVEL_FULL: u8 = 0x03;

pub const XINPUT_GAMEPAD = extern struct {
    wButtons: u16,
    bLeftTrigger: u8,
    bRightTrigger: u8,
    sThumbLX: i16,
    sThumbLY: i16,
    sThumbRX: i16,
    sThumbRY: i16,
};

pub const XINPUT_STATE = extern struct {
    dwPacketNumber: u32,
    Gamepad: XINPUT_GAMEPAD,
};

pub const XINPUT_VIBRATION = extern struct {
    wLeftMotorSpeed: u16,
    wRightMotorSpeed: u16,
};

pub const XINPUT_CAPABILITIES = extern struct {
    Type: u8,
    SubType: u8,
    Flags: u16,
    Gamepad: XINPUT_GAMEPAD,
    Vibration: XINPUT_VIBRATION,
};

pub const XINPUT_BATTERY_INFORMATION = extern struct {
    BatteryType: u8,
    BatteryLevel: u8,
};

pub const XINPUT_KEYSTROKE = extern struct {
    VirtualKey: u16,
    Unicode: u16,
    Flags: u16,
    UserIndex: u8,
    HidCode: u8,
};

comptime {
    if (@sizeOf(XINPUT_GAMEPAD) != 12) @compileError("XINPUT_GAMEPAD must be 12 bytes");
    if (@sizeOf(XINPUT_STATE) != 16) @compileError("XINPUT_STATE must be 16 bytes");
    if (@sizeOf(XINPUT_VIBRATION) != 4) @compileError("XINPUT_VIBRATION must be 4 bytes");
    if (@sizeOf(XINPUT_CAPABILITIES) != 20) @compileError("XINPUT_CAPABILITIES must be 20 bytes");
    if (@sizeOf(XINPUT_BATTERY_INFORMATION) != 2) @compileError("XINPUT_BATTERY_INFORMATION must be 2 bytes");
    if (@sizeOf(XINPUT_KEYSTROKE) != 8) @compileError("XINPUT_KEYSTROKE must be 8 bytes");
}

// ---- SDL2 dynamic bridge -----------------------------------------------------

extern fn dlopen(path: ?[*:0]const u8, flags: c_int) ?*anyopaque;
extern fn dlsym(handle: ?*anyopaque, name: [*:0]const u8) ?*anyopaque;

const SDL_INIT_HAPTIC: u32 = 0x00001000;
const SDL_INIT_GAMECONTROLLER: u32 = 0x00002000;

const SdlApi = struct {
    SDL_InitSubSystem: *const fn (u32) callconv(.c) c_int,
    SDL_SetHint: ?*const fn ([*:0]const u8, [*:0]const u8) callconv(.c) c_int = null,
    SDL_NumJoysticks: *const fn () callconv(.c) c_int,
    SDL_IsGameController: *const fn (c_int) callconv(.c) c_int,
    SDL_GameControllerOpen: *const fn (c_int) callconv(.c) ?*anyopaque,
    SDL_GameControllerClose: *const fn (?*anyopaque) callconv(.c) void,
    SDL_GameControllerUpdate: *const fn () callconv(.c) void,
    SDL_GameControllerGetAttached: *const fn (?*anyopaque) callconv(.c) c_int,
    SDL_GameControllerName: *const fn (?*anyopaque) callconv(.c) ?[*:0]const u8,
    SDL_GameControllerGetButton: *const fn (?*anyopaque, c_int) callconv(.c) u8,
    SDL_GameControllerGetAxis: *const fn (?*anyopaque, c_int) callconv(.c) i16,
    SDL_GameControllerRumble: ?*const fn (?*anyopaque, u16, u16, u32) callconv(.c) c_int = null,
    SDL_GameControllerGetVendor: ?*const fn (?*anyopaque) callconv(.c) u16 = null,
    SDL_GameControllerGetProduct: ?*const fn (?*anyopaque) callconv(.c) u16 = null,
};

var g_sdl: SdlApi = undefined;
var g_handles: [4]?*anyopaque = [_]?*anyopaque{null} ** 4;

fn sym(lib: ?*anyopaque, comptime T: type, name: [*:0]const u8) ?T {
    const p = dlsym(lib, name) orelse return null;
    return @ptrCast(@alignCast(p));
}

fn initSdlOnWorker() bool {
    const lib = dlopen("libSDL2-2.0.so.0", 2) orelse return false;
    const init_fn = sym(lib, *const fn (u32) callconv(.c) c_int, "SDL_InitSubSystem") orelse return false;
    const set_hint = sym(lib, *const fn ([*:0]const u8, [*:0]const u8) callconv(.c) c_int, "SDL_SetHint");
    if (set_hint) |f| _ = f("SDL_JOYSTICK_ALLOW_BACKGROUND_EVENTS", "1");
    if (init_fn(SDL_INIT_GAMECONTROLLER) < 0) return false;
    _ = init_fn(SDL_INIT_HAPTIC);
    g_sdl = .{
        .SDL_InitSubSystem = init_fn,
        .SDL_SetHint = set_hint,
        .SDL_NumJoysticks = sym(lib, *const fn () callconv(.c) c_int, "SDL_NumJoysticks") orelse return false,
        .SDL_IsGameController = sym(lib, *const fn (c_int) callconv(.c) c_int, "SDL_IsGameController") orelse return false,
        .SDL_GameControllerOpen = sym(lib, *const fn (c_int) callconv(.c) ?*anyopaque, "SDL_GameControllerOpen") orelse return false,
        .SDL_GameControllerClose = sym(lib, *const fn (?*anyopaque) callconv(.c) void, "SDL_GameControllerClose") orelse return false,
        .SDL_GameControllerUpdate = sym(lib, *const fn () callconv(.c) void, "SDL_GameControllerUpdate") orelse return false,
        .SDL_GameControllerGetAttached = sym(lib, *const fn (?*anyopaque) callconv(.c) c_int, "SDL_GameControllerGetAttached") orelse return false,
        .SDL_GameControllerName = sym(lib, *const fn (?*anyopaque) callconv(.c) ?[*:0]const u8, "SDL_GameControllerName") orelse return false,
        .SDL_GameControllerGetButton = sym(lib, *const fn (?*anyopaque, c_int) callconv(.c) u8, "SDL_GameControllerGetButton") orelse return false,
        .SDL_GameControllerGetAxis = sym(lib, *const fn (?*anyopaque, c_int) callconv(.c) i16, "SDL_GameControllerGetAxis") orelse return false,
        .SDL_GameControllerRumble = sym(lib, *const fn (?*anyopaque, u16, u16, u32) callconv(.c) c_int, "SDL_GameControllerRumble"),
        .SDL_GameControllerGetVendor = sym(lib, *const fn (?*anyopaque) callconv(.c) u16, "SDL_GameControllerGetVendor"),
        .SDL_GameControllerGetProduct = sym(lib, *const fn (?*anyopaque) callconv(.c) u16, "SDL_GameControllerGetProduct"),
    };
    return true;
}

// ---- controller state -------------------------------------------------------

const SlotState = struct {
    sdl_connected: bool = false,
    vendor: u16 = 0,
    product: u16 = 0,
    name: [64]u8 = [_]u8{0} ** 64,
    name_len: u8 = 0,
    sdl_gp: XINPUT_GAMEPAD = std.mem.zeroes(XINPUT_GAMEPAD),
    packet: u32 = 1,
    last_gp: XINPUT_GAMEPAD = std.mem.zeroes(XINPUT_GAMEPAD),
    test_active: bool = false,
    test_connected: bool = false,
    test_gp: XINPUT_GAMEPAD = std.mem.zeroes(XINPUT_GAMEPAD),
    last_left_rumble: u16 = 0,
    last_right_rumble: u16 = 0,
};

var g_lock = std.atomic.Value(u32).init(0);
var g_slots: [4]SlotState = [_]SlotState{.{}} ** 4;
var g_enabled: bool = true;

// Dedicated Linux host thread for all libSDL2 / dlopen calls (16-byte SysV stack).
const OpKind = enum(u8) { poll, rumble, stop_all };
const WorkerOp = struct { kind: OpKind = .poll, slot: usize = 0, left: u16 = 0, right: u16 = 0 };
var g_sdl_state = std.atomic.Value(u32).init(0); // 0=unstarted, 1=ready, 2=unavailable, 3=starting
var g_submit = std.atomic.Value(u32).init(0);
var g_posted = std.atomic.Value(u32).init(0);
var g_done = std.atomic.Value(u32).init(0);
var g_op: WorkerOp = .{};
var g_last_poll_ns: i128 = 0;

fn futexWait(word: *std.atomic.Value(u32), expect: u32) void {
    _ = linux.syscall4(.futex, @intFromPtr(word), 0, expect, 0);
}
fn futexWake(word: *std.atomic.Value(u32)) void {
    _ = linux.syscall3(.futex, @intFromPtr(word), 1, std.math.maxInt(i32));
}

fn nowNs() i128 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i128, ts.sec) * 1_000_000_000 + ts.nsec;
}

fn lock() void {
    while (g_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
}

fn unlock() void {
    g_lock.store(0, .release);
}

fn invertAxis(v: i16) i16 {
    return if (v == std.math.minInt(i16)) std.math.maxInt(i16) else -v;
}

fn triggerByte(v: i16) u8 {
    if (v <= 0) return 0;
    return @intCast(@min(@as(i32, 255), @as(i32, v) >> 7));
}

const ButtonMap = struct { sdl_btn: c_int, mask: u16 };
const button_map = [_]ButtonMap{
    .{ .sdl_btn = 11, .mask = 0x0001 }, // DPAD_UP
    .{ .sdl_btn = 12, .mask = 0x0002 }, // DPAD_DOWN
    .{ .sdl_btn = 13, .mask = 0x0004 }, // DPAD_LEFT
    .{ .sdl_btn = 14, .mask = 0x0008 }, // DPAD_RIGHT
    .{ .sdl_btn = 6, .mask = 0x0010 }, // START
    .{ .sdl_btn = 4, .mask = 0x0020 }, // BACK
    .{ .sdl_btn = 7, .mask = 0x0040 }, // LEFT_THUMB
    .{ .sdl_btn = 8, .mask = 0x0080 }, // RIGHT_THUMB
    .{ .sdl_btn = 9, .mask = 0x0100 }, // LEFT_SHOULDER
    .{ .sdl_btn = 10, .mask = 0x0200 }, // RIGHT_SHOULDER
    .{ .sdl_btn = 5, .mask = 0x0400 }, // GUIDE (XInputGetStateEx only)
    .{ .sdl_btn = 0, .mask = 0x1000 }, // A
    .{ .sdl_btn = 1, .mask = 0x2000 }, // B
    .{ .sdl_btn = 2, .mask = 0x4000 }, // X
    .{ .sdl_btn = 3, .mask = 0x8000 }, // Y
};

fn workerPoll() void {
    g_sdl.SDL_GameControllerUpdate();

    for (&g_handles, 0..) |*hp, idx| {
        if (hp.*) |h| {
            if (g_sdl.SDL_GameControllerGetAttached(h) == 0) {
                g_sdl.SDL_GameControllerClose(h);
                hp.* = null;
                std.debug.print("[WINS:XInput] controller {d} disconnected\n", .{idx});
            }
        }
    }

    const total = g_sdl.SDL_NumJoysticks();
    var j: c_int = 0;
    while (j < total) : (j += 1) {
        if (g_sdl.SDL_IsGameController(j) == 0) continue;
        const candidate = g_sdl.SDL_GameControllerOpen(j) orelse continue;
        var already = false;
        for (g_handles) |h| {
            if (h == candidate) {
                already = true;
                break;
            }
        }
        if (already) {
            g_sdl.SDL_GameControllerClose(candidate);
            continue;
        }
        var assigned = false;
        for (&g_handles, 0..) |*hp, idx| {
            if (hp.* == null) {
                hp.* = candidate;
                const v = if (g_sdl.SDL_GameControllerGetVendor) |f| f(candidate) else 0;
                const p = if (g_sdl.SDL_GameControllerGetProduct) |f| f(candidate) else 0;
                var nbuf: [64]u8 = [_]u8{0} ** 64;
                var nlen: u8 = 0;
                if (g_sdl.SDL_GameControllerName(candidate)) |cname| {
                    const nm = std.mem.sliceTo(cname, 0);
                    const n: usize = @min(nm.len, nbuf.len - 1);
                    @memcpy(nbuf[0..n], nm[0..n]);
                    nlen = @intCast(n);
                }
                lock();
                if (!g_slots[idx].test_active) {
                    g_slots[idx].vendor = v;
                    g_slots[idx].product = p;
                    g_slots[idx].name = nbuf;
                    g_slots[idx].name_len = nlen;
                }
                unlock();
                std.debug.print("[WINS:XInput] controller {d} connected: {s} (vid={x:0>4} pid={x:0>4})\n", .{
                    idx,
                    if (nlen > 0) nbuf[0..nlen] else "Controller",
                    v,
                    p,
                });
                assigned = true;
                break;
            }
        }
        if (!assigned) g_sdl.SDL_GameControllerClose(candidate);
    }

    var gps: [4]XINPUT_GAMEPAD = [_]XINPUT_GAMEPAD{std.mem.zeroes(XINPUT_GAMEPAD)} ** 4;
    var conns: [4]bool = [_]bool{false} ** 4;
    for (g_handles, 0..) |maybe_h, idx| {
        const h = maybe_h orelse continue;
        conns[idx] = true;
        var buttons: u16 = 0;
        for (button_map) |bm| {
            if (g_sdl.SDL_GameControllerGetButton(h, bm.sdl_btn) != 0) buttons |= bm.mask;
        }
        gps[idx] = .{
            .wButtons = buttons,
            .bLeftTrigger = triggerByte(g_sdl.SDL_GameControllerGetAxis(h, 4)),
            .bRightTrigger = triggerByte(g_sdl.SDL_GameControllerGetAxis(h, 5)),
            .sThumbLX = g_sdl.SDL_GameControllerGetAxis(h, 0),
            .sThumbLY = invertAxis(g_sdl.SDL_GameControllerGetAxis(h, 1)),
            .sThumbRX = g_sdl.SDL_GameControllerGetAxis(h, 2),
            .sThumbRY = invertAxis(g_sdl.SDL_GameControllerGetAxis(h, 3)),
        };
    }

    lock();
    for (&g_slots, 0..) |*s, idx| {
        if (s.test_active) continue;
        s.sdl_connected = conns[idx];
        s.sdl_gp = gps[idx];
        if (!conns[idx]) s.name_len = 0;
    }
    unlock();
}

fn workerMain() void {
    if (!initSdlOnWorker()) {
        g_sdl_state.store(2, .release);
        futexWake(&g_sdl_state);
        return;
    }
    workerPoll();
    g_sdl_state.store(1, .release);
    futexWake(&g_sdl_state);

    var handled: u32 = 0;
    while (true) {
        const posted = g_posted.load(.acquire);
        if (posted == handled) {
            futexWait(&g_posted, posted);
            continue;
        }
        handled = posted;
        switch (g_op.kind) {
            .poll => workerPoll(),
            .rumble => {
                if (g_handles[g_op.slot]) |h| {
                    if (g_sdl.SDL_GameControllerRumble) |rumble| _ = rumble(h, g_op.left, g_op.right, 0xFFFF);
                }
            },
            .stop_all => {
                if (g_sdl.SDL_GameControllerRumble) |rumble| {
                    for (g_handles) |maybe_h| {
                        if (maybe_h) |h| _ = rumble(h, 0, 0, 0);
                    }
                }
            },
        }
        g_done.store(handled, .release);
        futexWake(&g_done);
    }
}

fn ensureWorker() bool {
    const st = g_sdl_state.load(.acquire);
    if (st == 1) return true;
    if (st == 2) return false;
    if (g_sdl_state.cmpxchgStrong(0, 3, .acq_rel, .acquire) == null) {
        _ = std.Thread.spawn(.{}, workerMain, .{}) catch {
            g_sdl_state.store(2, .release);
            futexWake(&g_sdl_state);
            return false;
        };
    }
    while (true) {
        const cur = g_sdl_state.load(.acquire);
        if (cur == 1) return true;
        if (cur == 2) return false;
        futexWait(&g_sdl_state, cur);
    }
}

fn submitWorkerOp(op: WorkerOp) void {
    if (!ensureWorker()) return;
    while (g_submit.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) futexWait(&g_submit, 1);
    g_op = op;
    const ticket = g_posted.fetchAdd(1, .release) +% 1;
    futexWake(&g_posted);
    var spins: u32 = 0;
    while (true) {
        const done = g_done.load(.acquire);
        if (done == ticket) break;
        if (spins < 4000) {
            spins += 1;
            std.atomic.spinLoopHint();
            continue;
        }
        futexWait(&g_done, done);
    }
    g_submit.store(0, .release);
    futexWake(&g_submit);
}

fn syncSdlForSlot(slot_idx: usize) void {
    lock();
    const is_test = if (slot_idx < 4) g_slots[slot_idx].test_active else false;
    const now = nowNs();
    const need_poll = !is_test and (g_last_poll_ns == 0 or now - g_last_poll_ns >= 1_000_000);
    if (need_poll) g_last_poll_ns = now;
    unlock();
    if (need_poll) submitWorkerOp(.{ .kind = .poll });
}

fn syncSdlAll() void {
    lock();
    var any_real = false;
    for (g_slots) |s| {
        if (!s.test_active) {
            any_real = true;
            break;
        }
    }
    const now = nowNs();
    const need_poll = any_real and (g_last_poll_ns == 0 or now - g_last_poll_ns >= 1_000_000);
    if (need_poll) g_last_poll_ns = now;
    unlock();
    if (need_poll) submitWorkerOp(.{ .kind = .poll });
}

fn readSlotLocked(slot_idx: usize, include_guide: bool, out_gp: *XINPUT_GAMEPAD, out_packet: *u32) bool {
    const s = &g_slots[slot_idx];
    var raw_gp = std.mem.zeroes(XINPUT_GAMEPAD);
    if (s.test_active) {
        if (!s.test_connected) return false;
        raw_gp = s.test_gp;
    } else {
        if (!s.sdl_connected) return false;
        raw_gp = s.sdl_gp;
    }

    if (!include_guide) raw_gp.wButtons &= ~@as(u16, 0x0400);
    if (!g_enabled) raw_gp = std.mem.zeroes(XINPUT_GAMEPAD);

    if (!std.mem.eql(u8, std.mem.asBytes(&raw_gp), std.mem.asBytes(&s.last_gp))) {
        s.last_gp = raw_gp;
        s.packet +%= 1;
    }
    out_gp.* = raw_gp;
    out_packet.* = s.packet;
    return true;
}

/// Public snapshot helper used by DirectInput joystick emulation.
pub const ControllerInfo = struct {
    connected: bool,
    vendor: u16,
    product: u16,
    name: [64]u8,
    name_len: u8,
    state: XINPUT_STATE,
};

pub fn queryController(slot_idx: u32) ControllerInfo {
    var info: ControllerInfo = .{
        .connected = false,
        .vendor = 0,
        .product = 0,
        .name = [_]u8{0} ** 64,
        .name_len = 0,
        .state = std.mem.zeroes(XINPUT_STATE),
    };
    if (slot_idx >= 4) return info;
    syncSdlForSlot(slot_idx);
    lock();
    defer unlock();
    var gp: XINPUT_GAMEPAD = undefined;
    var pkt: u32 = 0;
    if (!readSlotLocked(slot_idx, false, &gp, &pkt)) return info;
    const s = &g_slots[slot_idx];
    info.connected = true;
    info.vendor = s.vendor;
    info.product = s.product;
    info.name = s.name;
    info.name_len = s.name_len;
    info.state = .{ .dwPacketNumber = pkt, .Gamepad = gp };
    return info;
}

/// Test/diagnostic helper to attach or clear a synthetic controller in slot `idx`.
pub fn setTestController(idx: u32, connected: bool, gp: XINPUT_GAMEPAD) void {
    if (idx >= 4) return;
    lock();
    defer unlock();
    g_slots[idx].test_active = true;
    g_slots[idx].test_connected = connected;
    g_slots[idx].test_gp = gp;
    if (connected) {
        const default_name = "XInput Test Gamepad";
        @memcpy(g_slots[idx].name[0..default_name.len], default_name);
        g_slots[idx].name[default_name.len] = 0;
        g_slots[idx].name_len = default_name.len;
    }
}

pub fn clearTestController(idx: u32) void {
    if (idx >= 4) return;
    lock();
    defer unlock();
    g_slots[idx].test_active = false;
    g_slots[idx].test_connected = false;
    g_slots[idx].test_gp = std.mem.zeroes(XINPUT_GAMEPAD);
    g_slots[idx].last_left_rumble = 0;
    g_slots[idx].last_right_rumble = 0;
}

// ---- Win32 XInput exports (stdcall / winapi) -------------------------------

pub fn lookupXinput(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "XInputGetState")) return @intFromPtr(&XInputGetState);
    if (std.mem.eql(u8, name, "XInputGetStateEx")) return @intFromPtr(&XInputGetStateEx);
    if (std.mem.eql(u8, name, "XInputSetState")) return @intFromPtr(&XInputSetState);
    if (std.mem.eql(u8, name, "XInputGetCapabilities")) return @intFromPtr(&XInputGetCapabilities);
    if (std.mem.eql(u8, name, "XInputEnable")) return @intFromPtr(&XInputEnable);
    if (std.mem.eql(u8, name, "XInputGetDSoundAudioDeviceGuids")) return @intFromPtr(&XInputGetDSoundAudioDeviceGuids);
    if (std.mem.eql(u8, name, "XInputGetBatteryInformation")) return @intFromPtr(&XInputGetBatteryInformation);
    if (std.mem.eql(u8, name, "XInputGetKeystroke")) return @intFromPtr(&XInputGetKeystroke);
    return null;
}

fn getStateCommon(dwUserIndex: u32, pState: ?*XINPUT_STATE, include_guide: bool) u32 {
    const out = pState orelse return ERROR_BAD_ARGUMENTS;
    out.* = std.mem.zeroes(XINPUT_STATE);
    if (dwUserIndex >= 4) return ERROR_BAD_ARGUMENTS;
    syncSdlForSlot(dwUserIndex);
    lock();
    defer unlock();
    var gp: XINPUT_GAMEPAD = undefined;
    var pkt: u32 = 0;
    if (!readSlotLocked(dwUserIndex, include_guide, &gp, &pkt)) return ERROR_DEVICE_NOT_CONNECTED;
    out.dwPacketNumber = pkt;
    out.Gamepad = gp;
    return ERROR_SUCCESS;
}

pub fn XInputGetState(dwUserIndex: u32, pState: ?*XINPUT_STATE) callconv(W) u32 {
    return getStateCommon(dwUserIndex, pState, false);
}

pub fn XInputGetStateEx(dwUserIndex: u32, pState: ?*XINPUT_STATE) callconv(W) u32 {
    return getStateCommon(dwUserIndex, pState, true);
}

pub fn XInputSetState(dwUserIndex: u32, pVibration: ?*const XINPUT_VIBRATION) callconv(W) u32 {
    const vib = pVibration orelse return ERROR_BAD_ARGUMENTS;
    if (dwUserIndex >= 4) return ERROR_BAD_ARGUMENTS;
    syncSdlForSlot(dwUserIndex);
    lock();
    const s = &g_slots[dwUserIndex];
    const left: u16 = if (g_enabled) vib.wLeftMotorSpeed else 0;
    const right: u16 = if (g_enabled) vib.wRightMotorSpeed else 0;
    if (s.test_active) {
        const conn = s.test_connected;
        if (conn) {
            s.last_left_rumble = left;
            s.last_right_rumble = right;
        }
        unlock();
        return if (conn) ERROR_SUCCESS else ERROR_DEVICE_NOT_CONNECTED;
    }
    const conn = s.sdl_connected;
    if (conn) {
        s.last_left_rumble = left;
        s.last_right_rumble = right;
    }
    unlock();
    if (!conn) return ERROR_DEVICE_NOT_CONNECTED;
    submitWorkerOp(.{ .kind = .rumble, .slot = dwUserIndex, .left = left, .right = right });
    return ERROR_SUCCESS;
}

pub fn XInputGetCapabilities(dwUserIndex: u32, dwFlags: u32, pCapabilities: ?*XINPUT_CAPABILITIES) callconv(W) u32 {
    const out = pCapabilities orelse return ERROR_BAD_ARGUMENTS;
    out.* = std.mem.zeroes(XINPUT_CAPABILITIES);
    if (dwUserIndex >= 4 or (dwFlags != 0 and dwFlags != 1)) return ERROR_BAD_ARGUMENTS;
    syncSdlForSlot(dwUserIndex);
    lock();
    defer unlock();
    var gp: XINPUT_GAMEPAD = undefined;
    var pkt: u32 = 0;
    if (!readSlotLocked(dwUserIndex, false, &gp, &pkt)) return ERROR_DEVICE_NOT_CONNECTED;
    out.* = .{
        .Type = XINPUT_DEVTYPE_GAMEPAD,
        .SubType = XINPUT_DEVSUBTYPE_GAMEPAD,
        .Flags = 0,
        .Gamepad = .{
            .wButtons = 0xF3FF,
            .bLeftTrigger = 0xFF,
            .bRightTrigger = 0xFF,
            .sThumbLX = @as(i16, @bitCast(@as(u16, 0xFFC0))),
            .sThumbLY = @as(i16, @bitCast(@as(u16, 0xFFC0))),
            .sThumbRX = @as(i16, @bitCast(@as(u16, 0xFFC0))),
            .sThumbRY = @as(i16, @bitCast(@as(u16, 0xFFC0))),
        },
        .Vibration = .{ .wLeftMotorSpeed = 0xFFFF, .wRightMotorSpeed = 0xFFFF },
    };
    return ERROR_SUCCESS;
}

pub fn XInputEnable(enable: i32) callconv(W) void {
    var stop_real = false;
    lock();
    const on = enable != 0;
    if (g_enabled and !on) {
        for (&g_slots) |*s| {
            s.last_left_rumble = 0;
            s.last_right_rumble = 0;
            if (!s.test_active and s.sdl_connected) stop_real = true;
        }
    }
    g_enabled = on;
    unlock();
    if (stop_real) submitWorkerOp(.{ .kind = .stop_all });
}

pub fn XInputGetDSoundAudioDeviceGuids(dwUserIndex: u32, pRenderGuid: ?*[16]u8, pCaptureGuid: ?*[16]u8) callconv(W) u32 {
    if (dwUserIndex >= 4 or pRenderGuid == null or pCaptureGuid == null) return ERROR_BAD_ARGUMENTS;
    pRenderGuid.?.* = [_]u8{0} ** 16;
    pCaptureGuid.?.* = [_]u8{0} ** 16;
    syncSdlForSlot(dwUserIndex);
    lock();
    defer unlock();
    var gp: XINPUT_GAMEPAD = undefined;
    var pkt: u32 = 0;
    if (!readSlotLocked(dwUserIndex, false, &gp, &pkt)) return ERROR_DEVICE_NOT_CONNECTED;
    return ERROR_SUCCESS;
}

pub fn XInputGetBatteryInformation(dwUserIndex: u32, devType: u8, pBatteryInfo: ?*XINPUT_BATTERY_INFORMATION) callconv(W) u32 {
    _ = devType;
    const out = pBatteryInfo orelse return ERROR_BAD_ARGUMENTS;
    out.* = .{ .BatteryType = BATTERY_TYPE_DISCONNECTED, .BatteryLevel = 0 };
    if (dwUserIndex >= 4) return ERROR_BAD_ARGUMENTS;
    syncSdlForSlot(dwUserIndex);
    lock();
    defer unlock();
    var gp: XINPUT_GAMEPAD = undefined;
    var pkt: u32 = 0;
    if (!readSlotLocked(dwUserIndex, false, &gp, &pkt)) return ERROR_DEVICE_NOT_CONNECTED;
    out.* = .{ .BatteryType = BATTERY_TYPE_WIRED, .BatteryLevel = BATTERY_LEVEL_FULL };
    return ERROR_SUCCESS;
}

pub fn XInputGetKeystroke(dwUserIndex: u32, dwReserved: u32, pKeystroke: ?*XINPUT_KEYSTROKE) callconv(W) u32 {
    _ = dwReserved;
    const out = pKeystroke orelse return ERROR_BAD_ARGUMENTS;
    out.* = std.mem.zeroes(XINPUT_KEYSTROKE);
    if (dwUserIndex >= 4 and dwUserIndex != 0xFF) return ERROR_BAD_ARGUMENTS;
    if (dwUserIndex < 4) syncSdlForSlot(dwUserIndex) else syncSdlAll();
    lock();
    defer unlock();
    if (dwUserIndex < 4) {
        var gp: XINPUT_GAMEPAD = undefined;
        var pkt: u32 = 0;
        if (!readSlotLocked(dwUserIndex, false, &gp, &pkt)) return ERROR_DEVICE_NOT_CONNECTED;
        return ERROR_EMPTY;
    }
    for (0..4) |i| {
        var gp: XINPUT_GAMEPAD = undefined;
        var pkt: u32 = 0;
        if (readSlotLocked(i, false, &gp, &pkt)) return ERROR_EMPTY;
    }
    return ERROR_DEVICE_NOT_CONNECTED;
}

// ---- tests ------------------------------------------------------------------

test "XInput validation matches Wine error codes" {
    var st: XINPUT_STATE = undefined;
    try std.testing.expectEqual(ERROR_BAD_ARGUMENTS, XInputGetState(4, &st));
    try std.testing.expectEqual(ERROR_BAD_ARGUMENTS, XInputGetState(0, null));
    try std.testing.expectEqual(ERROR_BAD_ARGUMENTS, XInputGetCapabilities(4, 1, null));
    try std.testing.expectEqual(ERROR_BAD_ARGUMENTS, XInputSetState(4, null));

    setTestController(0, false, std.mem.zeroes(XINPUT_GAMEPAD));
    defer clearTestController(0);
    try std.testing.expectEqual(ERROR_DEVICE_NOT_CONNECTED, XInputGetState(0, &st));
    var caps: XINPUT_CAPABILITIES = undefined;
    try std.testing.expectEqual(ERROR_DEVICE_NOT_CONNECTED, XInputGetCapabilities(0, 1, &caps));
}

test "XInput connected controller state, guide bit filtering, rumble, and XInputEnable" {
    defer clearTestController(0);
    setTestController(0, true, .{
        .wButtons = 0x1000 | 0x0400, // A + Guide
        .bLeftTrigger = 200,
        .bRightTrigger = 50,
        .sThumbLX = 12345,
        .sThumbLY = -23456,
        .sThumbRX = -500,
        .sThumbRY = 8000,
    });
    var st: XINPUT_STATE = undefined;
    try std.testing.expectEqual(ERROR_SUCCESS, XInputGetState(0, &st));
    try std.testing.expectEqual(@as(u16, 0x1000), st.Gamepad.wButtons); // guide masked out
    try std.testing.expectEqual(@as(u8, 200), st.Gamepad.bLeftTrigger);
    try std.testing.expectEqual(@as(i16, 12345), st.Gamepad.sThumbLX);
    const p1 = st.dwPacketNumber;

    // XInputGetStateEx preserves guide button bit (0x0400)
    try std.testing.expectEqual(ERROR_SUCCESS, XInputGetStateEx(0, &st));
    try std.testing.expectEqual(@as(u16, 0x1400), st.Gamepad.wButtons);
    try std.testing.expect(st.dwPacketNumber != p1);

    // Rumble sets motor speeds; XInputEnable(0) zeros both state and rumble
    const vib: XINPUT_VIBRATION = .{ .wLeftMotorSpeed = 30000, .wRightMotorSpeed = 10000 };
    try std.testing.expectEqual(ERROR_SUCCESS, XInputSetState(0, &vib));
    try std.testing.expectEqual(@as(u16, 30000), g_slots[0].last_left_rumble);

    XInputEnable(0);
    defer XInputEnable(1);
    try std.testing.expectEqual(@as(u16, 0), g_slots[0].last_left_rumble);
    try std.testing.expectEqual(ERROR_SUCCESS, XInputGetState(0, &st));
    try std.testing.expectEqual(@as(u16, 0), st.Gamepad.wButtons);
    try std.testing.expectEqual(@as(i16, 0), st.Gamepad.sThumbLX);

    var caps: XINPUT_CAPABILITIES = undefined;
    try std.testing.expectEqual(ERROR_SUCCESS, XInputGetCapabilities(0, 1, &caps));
    try std.testing.expectEqual(XINPUT_DEVTYPE_GAMEPAD, caps.Type);
    try std.testing.expectEqual(@as(u16, 0xFFFF), caps.Vibration.wLeftMotorSpeed);
}
