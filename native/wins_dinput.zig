//! DirectInput 8 keyboard, mouse and controller input fed by the host window
//! and XInput/SDL2 gamepads.
//!
//! Producer: the render thread of wins_gl.zig turns X11 events of the game
//! window into calls to `keyEvent`, `mouseMove`, `mouseButton`, `mouseWheel`
//! and `focus`. Consumers: the guest's IDirectInputDevice8 objects, which read
//! the immediate state (GetDeviceState) or a per-device event buffer
//! (GetDeviceData), as DirectInput does. Attached SDL2/XInput controllers are
//! also exposed as joystick devices.
//!
//! Only system keyboard/mouse and attached gamepads exist; force-feedback and
//! action mapping are not implemented and answer E_NOTIMPL once.

const std = @import("std");
const linux = std.os.linux;
const xinput = @import("wins_xinput.zig");

const W: std.builtin.CallingConvention = .winapi;

pub const DI_OK: i32 = 0;
const DI_NOEFFECT: i32 = 1;
const DI_BUFFEROVERFLOW: i32 = 1;
const E_NOTIMPL: i32 = @bitCast(@as(u32, 0x80004001));
const E_POINTER: i32 = @bitCast(@as(u32, 0x80004003));
const E_NOINTERFACE: i32 = @bitCast(@as(u32, 0x80004002));
const DIERR_INVALIDPARAM: i32 = @bitCast(@as(u32, 0x80070057));
const DIERR_NOTACQUIRED: i32 = @bitCast(@as(u32, 0x8007000C));
const DIERR_DEVICENOTREG: i32 = @bitCast(@as(u32, 0x80040154));
const DIERR_NOTFOUND: i32 = @bitCast(@as(u32, 0x80070002));
const DIERR_OBJECTNOTFOUND: i32 = @bitCast(@as(u32, 0x80070002));
const DIERR_NOTBUFFERED: i32 = @bitCast(@as(u32, 0x80040207));
const DIERR_OUTOFMEMORY: i32 = @bitCast(@as(u32, 0x8007000E));

pub const Kind = enum(u8) { keyboard, mouse, joystick };

// ---- shared input state (written by the render thread) ------------------------

var g_keys: [256]std.atomic.Value(u8) = [_]std.atomic.Value(u8){std.atomic.Value(u8).init(0)} ** 256;
var g_mouse_x = std.atomic.Value(i32).init(0);
var g_mouse_y = std.atomic.Value(i32).init(0);
var g_mouse_z = std.atomic.Value(i32).init(0);
var g_buttons = std.atomic.Value(u32).init(0);
var g_focused = std.atomic.Value(bool).init(false);
var g_sequence = std.atomic.Value(u32).init(0);

/// One lock for the device list and every event buffer: producers and
/// consumers hold it for a few dozen instructions.
var g_lock = std.atomic.Value(u32).init(0);
fn lock() void {
    while (g_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
}
fn unlock() void {
    g_lock.store(0, .release);
}

/// DIDEVICEOBJECTDATA (DirectInput 8, 32-bit: 20 bytes).
pub const ObjectData = extern struct {
    dwOfs: u32,
    dwData: u32,
    dwTimeStamp: u32,
    dwSequence: u32,
    uAppData: usize,
};

fn tickMs() u32 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @truncate(@as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000);
}

const max_devices = 16;
var g_devices: [max_devices]?*Device = [_]?*Device{null} ** max_devices;

fn push(kind: Kind, ofs: u32, data: u32) void {
    const ev: ObjectData = .{ .dwOfs = ofs, .dwData = data, .dwTimeStamp = tickMs(), .dwSequence = g_sequence.fetchAdd(1, .monotonic) +% 1, .uAppData = 0 };
    lock();
    defer unlock();
    for (g_devices) |maybe| {
        const d = maybe orelse continue;
        if (d.kind != kind or !d.acquired) continue;
        // Latch press edges until GetDeviceState observes them so fast taps
        // (press+release between two poll frames or inside one X11 batch) aren't lost.
        if (kind == .keyboard and data != 0 and ofs < 256) d.latched_keys[ofs] = true;
        if (kind == .mouse and data != 0 and ofs >= 12 and ofs < 17) {
            d.latched_buttons |= @as(u32, 1) << @intCast(ofs - 12);
        }
        if (d.buffer.len == 0) continue;
        if (d.count == d.buffer.len) {
            d.overflow = true;
            continue;
        }
        d.buffer[(d.head + d.count) % d.buffer.len] = ev;
        d.count += 1;
    }
}

/// Producer: a key changed (DIK scan code).
pub fn keyEvent(dik: u8, down: bool) void {
    if (dik == 0) return;
    const v: u8 = if (down) 0x80 else 0;
    if (g_keys[dik].swap(v, .monotonic) == v) return;
    push(.keyboard, dik, v);
    if (traceOn()) {
        var live: u32 = 0;
        var acq: u32 = 0;
        lock();
        for (g_devices) |m| if (m) |d| if (d.kind == .keyboard) {
            live += 1;
            if (d.acquired) acq += 1;
        };
        unlock();
        std.debug.print("[WINS:DInput] key DIK 0x{x} {s}: {d} keyboard device(s), {d} acquired\n", .{ dik, if (down) "down" else "up", live, acq });
    }
}

var g_trace: i8 = -1;
fn traceOn() bool {
    if (g_trace < 0) g_trace = if (std.c.getenv("WINS_DINPUT_TRACE") != null) 1 else 0;
    return g_trace == 1;
}

/// Producer: relative mouse motion in mickeys (pixels).
pub fn mouseMove(dx: i32, dy: i32) void {
    if (dx != 0) {
        _ = g_mouse_x.fetchAdd(dx, .monotonic);
        push(.mouse, 0, @bitCast(dx));
    }
    if (dy != 0) {
        _ = g_mouse_y.fetchAdd(dy, .monotonic);
        push(.mouse, 4, @bitCast(dy));
    }
}

/// Producer: wheel, in WHEEL_DELTA units (120 per notch).
pub fn mouseWheel(dz: i32) void {
    _ = g_mouse_z.fetchAdd(dz, .monotonic);
    push(.mouse, 8, @bitCast(dz));
}

/// Producer: button 0 left, 1 right, 2 middle, 3/4 side buttons.
pub fn mouseButton(button: u3, down: bool) void {
    const bit = @as(u32, 1) << button;
    const old = if (down) g_buttons.fetchOr(bit, .monotonic) else g_buttons.fetchAnd(~bit, .monotonic);
    if (((old & bit) != 0) == down) return;
    push(.mouse, 12 + @as(u32, button), if (down) 0x80 else 0);
}

/// Producer: the window gained or lost the keyboard focus. Losing it releases
/// every key and button, as Windows does for a background window.
pub fn focus(has: bool) void {
    g_focused.store(has, .release);
    if (has) return;
    for (0..256) |k| keyEvent(@intCast(k), false);
    for (0..5) |b| mouseButton(@intCast(b), false);
    lock();
    defer unlock();
    for (g_devices) |maybe| {
        const d = maybe orelse continue;
        @memset(&d.latched_keys, false);
        d.latched_buttons = 0;
    }
}

pub fn focused() bool {
    return g_focused.load(.acquire);
}

/// X11 keycode (evdev code + 8) -> DirectInput scan code; 0 = no mapping.
pub fn dikFromX11(keycode: u32) u8 {
    if (keycode < 8) return 0;
    const e = keycode - 8;
    if (e >= 1 and e <= 0x58) return @intCast(e); // PC set-1 scan codes coincide with evdev here
    return switch (e) {
        96 => 0x9C, // KP Enter
        97 => 0x9D, // Right Ctrl
        98 => 0xB5, // KP /
        99 => 0xB7, // SysRq
        100 => 0xB8, // Right Alt
        102 => 0xC7, // Home
        103 => 0xC8, // Up
        104 => 0xC9, // PgUp
        105 => 0xCB, // Left
        106 => 0xCD, // Right
        107 => 0xCF, // End
        108 => 0xD0, // Down
        109 => 0xD1, // PgDn
        110 => 0xD2, // Insert
        111 => 0xD3, // Delete
        119 => 0xC5, // Pause
        125 => 0xDB, // Left Win
        126 => 0xDC, // Right Win
        127 => 0xDD, // Menu
        else => 0,
    };
}

// ---- IDirectInputDevice8 ------------------------------------------------------

const GUID = extern struct { d1: u32, d2: u16, d3: u16, d4: [8]u8 };
const GUID_SysMouse = GUID{ .d1 = 0x6F1D2B60, .d2 = 0xD5A0, .d3 = 0x11CF, .d4 = .{ 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };
const GUID_SysKeyboard = GUID{ .d1 = 0x6F1D2B61, .d2 = 0xD5A0, .d3 = 0x11CF, .d4 = .{ 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };
const IID_IUnknown = GUID{ .d1 = 0, .d2 = 0, .d3 = 0, .d4 = .{ 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
const IID_IDirectInputDevice8A = GUID{ .d1 = 0x54D41080, .d2 = 0xDC15, .d3 = 0x4833, .d4 = .{ 0xA4, 0x1B, 0x74, 0x8F, 0x73, 0xA3, 0x81, 0x79 } };
const IID_IDirectInputDevice8W = GUID{ .d1 = 0x54D41081, .d2 = 0xDC15, .d3 = 0x4833, .d4 = .{ 0xA4, 0x1B, 0x74, 0x8F, 0x73, 0xA3, 0x81, 0x79 } };

const GUID_XAxis = GUID{ .d1 = 0xA36D02E0, .d2 = 0xC9F3, .d3 = 0x11CF, .d4 = .{ 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };
const GUID_YAxis = GUID{ .d1 = 0xA36D02E1, .d2 = 0xC9F3, .d3 = 0x11CF, .d4 = .{ 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };
const GUID_ZAxis = GUID{ .d1 = 0xA36D02E2, .d2 = 0xC9F3, .d3 = 0x11CF, .d4 = .{ 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };
const GUID_RxAxis = GUID{ .d1 = 0xA36D02F4, .d2 = 0xC9F3, .d3 = 0x11CF, .d4 = .{ 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };
const GUID_RyAxis = GUID{ .d1 = 0xA36D02F5, .d2 = 0xC9F3, .d3 = 0x11CF, .d4 = .{ 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };
const GUID_Button = GUID{ .d1 = 0xA36D02F0, .d2 = 0xC9F3, .d3 = 0x11CF, .d4 = .{ 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };
const GUID_Key = GUID{ .d1 = 0x55728220, .d2 = 0xD33C, .d3 = 0x11CF, .d4 = .{ 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };
const GUID_POV = GUID{ .d1 = 0xA36D02F2, .d2 = 0xC9F3, .d3 = 0x11CF, .d4 = .{ 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };

pub fn joystickGuid(slot: u8) GUID {
    return .{ .d1 = 0x57494E53, .d2 = 0x5849, .d3 = 0x0000, .d4 = .{ 0, 0, 0, 0, 0, 0, 0, slot } };
}

fn matchJoystickGuid(g: *align(1) const GUID) ?u8 {
    for (0..4) |i| {
        const jg = joystickGuid(@intCast(i));
        if (guidEql(g, &jg)) return @intCast(i);
    }
    return null;
}

fn guidEql(a: *align(1) const GUID, b: *const GUID) bool {
    return std.mem.eql(u8, std.mem.asBytes(a), std.mem.asBytes(b));
}

const Vtbl = extern struct {
    QueryInterface: *const anyopaque,
    AddRef: *const anyopaque,
    Release: *const anyopaque,
    GetCapabilities: *const anyopaque,
    EnumObjects: *const anyopaque,
    GetProperty: *const anyopaque,
    SetProperty: *const anyopaque,
    Acquire: *const anyopaque,
    Unacquire: *const anyopaque,
    GetDeviceState: *const anyopaque,
    GetDeviceData: *const anyopaque,
    SetDataFormat: *const anyopaque,
    SetEventNotification: *const anyopaque,
    SetCooperativeLevel: *const anyopaque,
    GetObjectInfo: *const anyopaque,
    GetDeviceInfo: *const anyopaque,
    RunControlPanel: *const anyopaque,
    Initialize: *const anyopaque,
    CreateEffect: *const anyopaque,
    EnumEffects: *const anyopaque,
    GetEffectInfo: *const anyopaque,
    GetForceFeedbackState: *const anyopaque,
    SendForceFeedbackCommand: *const anyopaque,
    EnumCreatedEffectObjects: *const anyopaque,
    Escape: *const anyopaque,
    Poll: *const anyopaque,
    SendDeviceData: *const anyopaque,
    EnumEffectsInFile: *const anyopaque,
    WriteEffectToFile: *const anyopaque,
    BuildActionMap: *const anyopaque,
    SetActionMap: *const anyopaque,
    GetImageInfo: *const anyopaque,
};

pub const Device = struct {
    vtbl: *const Vtbl,
    ref_count: u32,
    kind: Kind,
    wide: bool,
    joy_index: u8 = 0,
    acquired: bool = false,
    data_size: u32 = 0,
    absolute: bool = false,
    coop_flags: u32 = 0,
    range_min: i32 = -32768,
    range_max: i32 = 32767,
    deadzone: u32 = 0,
    saturation: u32 = 10000,
    /// Totals already handed out by GetDeviceState (mouse deltas are per device).
    seen_x: i32 = 0,
    seen_y: i32 = 0,
    seen_z: i32 = 0,
    buffer: []ObjectData = &.{},
    polls: u32 = 0,
    head: usize = 0,
    count: usize = 0,
    overflow: bool = false,
    latched_keys: [256]bool = [_]bool{false} ** 256,
    latched_buttons: u32 = 0,
};

var g_said: u32 = 0;
fn sayOnce(slot: u5, comptime what: []const u8, caller: usize) void {
    const m = @as(u32, 1) << slot;
    if (g_said & m != 0) return;
    g_said |= m;
    std.debug.print("[WINS:DInput] device!" ++ what ++ " (first call, caller 0x{x})\n", .{caller});
}

fn self(this: *anyopaque) *Device {
    return @ptrCast(@alignCast(this));
}

fn dev_QueryInterface(this: *anyopaque, riid: ?*align(1) const GUID, ppv: ?*?*anyopaque) callconv(W) i32 {
    const out = ppv orelse return E_POINTER;
    out.* = null;
    const id = riid orelse return E_POINTER;
    if (guidEql(id, &IID_IUnknown) or guidEql(id, &IID_IDirectInputDevice8A) or guidEql(id, &IID_IDirectInputDevice8W)) {
        self(this).ref_count += 1;
        out.* = this;
        return DI_OK;
    }
    return E_NOINTERFACE;
}
fn dev_AddRef(this: *anyopaque) callconv(W) u32 {
    self(this).ref_count += 1;
    return self(this).ref_count;
}
fn dev_Release(this: *anyopaque) callconv(W) u32 {
    const d = self(this);
    if (d.ref_count > 0) d.ref_count -= 1;
    const left = d.ref_count;
    if (traceOn()) std.debug.print("[WINS:DInput] {s} 0x{x}: Release -> {d}\n", .{ @tagName(d.kind), @intFromPtr(d), left });
    if (left == 0) {
        lock();
        for (&g_devices) |*slot| {
            if (slot.* == d) slot.* = null;
        }
        unlock();
        if (d.buffer.len != 0) std.heap.page_allocator.free(d.buffer);
        std.heap.page_allocator.destroy(d);
    }
    return left;
}

/// DIDEVCAPS: dwSize, dwFlags, dwDevType, dwAxes, dwButtons, dwPOVs, then
/// force-feedback fields.
fn dev_GetCapabilities(this: *anyopaque, caps: ?[*]u32) callconv(W) i32 {
    sayOnce(0, "GetCapabilities", @returnAddress());
    const d = self(this);
    const c = caps orelse return E_POINTER;
    const size = c[0];
    if (size != 24 and size != 44) return DIERR_INVALIDPARAM;
    @memset(std.mem.sliceAsBytes(c[1 .. size / 4]), 0);
    c[1] = 0x1 | 0x4; // DIDC_ATTACHED | DIDC_EMULATED
    switch (d.kind) {
        .keyboard => {
            c[2] = 0x13 | (4 << 8); // DI8DEVTYPE_KEYBOARD, DI8DEVTYPEKEYBOARD_PCENH
            c[4] = 128;
        },
        .mouse => {
            c[2] = 0x12 | (2 << 8); // DI8DEVTYPE_MOUSE, DI8DEVTYPEMOUSE_TRADITIONAL
            c[3] = 3;
            c[4] = 5;
        },
        .joystick => {
            c[2] = 0x15 | (2 << 8); // DI8DEVTYPE_GAMEPAD, DI8DEVTYPEGAMEPAD_STANDARD
            c[3] = 5; // X, Y, Z(triggers), Rx, Ry
            c[4] = 12;
            c[5] = 1; // 1 POV (D-pad)
        },
    }
    return DI_OK;
}

const EnumObjectCb = *const fn (*const u8, ?*anyopaque) callconv(W) i32;

fn pushObj(wide: bool, cb_fn: EnumObjectCb, ref: ?*anyopaque, guid: *const GUID, ofs: u32, obj_type: u32, flags: u32, name: []const u8) bool {
    const char_size: usize = if (wide) 2 else 1;
    var buf: [576]u8 align(4) = [_]u8{0} ** 576;
    const obj_size: u32 = if (wide) 576 else 316;
    std.mem.writeInt(u32, buf[0..4], obj_size, .little);
    @memcpy(buf[4..20], std.mem.asBytes(guid));
    std.mem.writeInt(u32, buf[20..24], ofs, .little);
    std.mem.writeInt(u32, buf[24..28], obj_type, .little);
    std.mem.writeInt(u32, buf[28..32], flags, .little);
    fillName(buf[32 .. 32 + 260 * char_size], wide, name);
    return cb_fn(&buf[0], ref) != 0; // DIENUM_STOP == 0
}

fn enumDeviceObjects(d: *const Device, cb: ?*anyopaque, ref: ?*anyopaque, flags: u32) i32 {
    const raw_cb = cb orelse return E_POINTER;
    const cb_fn: EnumObjectCb = @ptrCast(@alignCast(raw_cb));
    const want_all = flags == 0;
    const want_axis = want_all or (flags & 3) != 0; // DIDFT_AXIS (RELAXIS | ABSAXIS)
    const want_btn = want_all or (flags & 0xC) != 0; // DIDFT_BUTTON
    const want_pov = want_all or (flags & 0x10) != 0; // DIDFT_POV

    switch (d.kind) {
        .mouse => {
            if (want_axis) {
                const axes = [_]struct { g: *const GUID, o: u32, t: u32, n: []const u8 }{
                    .{ .g = &GUID_XAxis, .o = 0, .t = 0x0001, .n = "X-axis" },
                    .{ .g = &GUID_YAxis, .o = 4, .t = 0x0101, .n = "Y-axis" },
                    .{ .g = &GUID_ZAxis, .o = 8, .t = 0x0201, .n = "Wheel" },
                };
                for (axes) |a| {
                    if (!pushObj(d.wide, cb_fn, ref, a.g, a.o, a.t, 0, a.n)) return DI_OK;
                }
            }
            if (want_btn) {
                const btns = [_][]const u8{ "Button 0", "Button 1", "Button 2", "Button 3", "Button 4" };
                for (btns, 0..) |bn, i| {
                    const obj_type: u32 = (@as(u32, @intCast(3 + i)) << 8) | 0x04;
                    if (!pushObj(d.wide, cb_fn, ref, &GUID_Button, @intCast(12 + i), obj_type, 0, bn)) return DI_OK;
                }
            }
        },
        .keyboard => {
            if (!want_btn) return DI_OK;
            var k: u32 = 1;
            while (k <= 0xDD) : (k += 1) {
                if (k > 0x58 and k < 0x9C) continue;
                var nbuf: [16]u8 = undefined;
                const kn = std.fmt.bufPrint(&nbuf, "Key {d}", .{k}) catch "Key";
                const obj_type: u32 = (k << 8) | 0x04;
                if (!pushObj(d.wide, cb_fn, ref, &GUID_Key, k, obj_type, 0, kn)) return DI_OK;
            }
        },
        .joystick => {
            if (want_axis) {
                const axes = [_]struct { g: *const GUID, o: u32, inst: u32, n: []const u8 }{
                    .{ .g = &GUID_XAxis, .o = 0, .inst = 0, .n = "X Axis" },
                    .{ .g = &GUID_YAxis, .o = 4, .inst = 1, .n = "Y Axis" },
                    .{ .g = &GUID_ZAxis, .o = 8, .inst = 2, .n = "Z Axis" },
                    .{ .g = &GUID_RxAxis, .o = 12, .inst = 3, .n = "X Rotation" },
                    .{ .g = &GUID_RyAxis, .o = 16, .inst = 4, .n = "Y Rotation" },
                };
                for (axes) |a| {
                    const obj_type: u32 = (a.inst << 8) | 0x02; // DIDFT_ABSAXIS
                    if (!pushObj(d.wide, cb_fn, ref, a.g, a.o, obj_type, 0x0100, a.n)) return DI_OK;
                }
            }
            if (want_pov) {
                if (!pushObj(d.wide, cb_fn, ref, &GUID_POV, 32, (0 << 8) | 0x10, 0, "Hat Switch")) return DI_OK;
            }
            if (want_btn) {
                for (0..12) |i| {
                    var nbuf: [16]u8 = undefined;
                    const bn = std.fmt.bufPrint(&nbuf, "Button {d}", .{i}) catch "Button";
                    const obj_type: u32 = (@as(u32, @intCast(i)) << 8) | 0x04; // DIDFT_PSHBUTTON
                    if (!pushObj(d.wide, cb_fn, ref, &GUID_Button, @intCast(48 + i), obj_type, 0, bn)) return DI_OK;
                }
            }
        },
    }
    return DI_OK;
}

fn dev_EnumObjects(this: *anyopaque, cb: ?*anyopaque, ref: ?*anyopaque, flags: u32) callconv(W) i32 {
    sayOnce(1, "EnumObjects", @returnAddress());
    return enumDeviceObjects(self(this), cb, ref, flags);
}

/// Predefined properties are passed as small integers (MAKEDIPROP).
const DIPROP_BUFFERSIZE: usize = 1;
const DIPROP_AXISMODE: usize = 2;
const DIPROP_RANGE: usize = 4;
const DIPROP_DEADZONE: usize = 5;
const DIPROP_SATURATION: usize = 6;

fn dev_GetProperty(this: *anyopaque, prop: usize, ph: ?[*]u32) callconv(W) i32 {
    const d = self(this);
    const h = ph orelse return E_POINTER;
    switch (prop) {
        DIPROP_BUFFERSIZE => h[4] = @intCast(d.buffer.len),
        DIPROP_AXISMODE => h[4] = if (d.absolute) 0 else 1, // DIPROPAXISMODE_ABS=0, DIPROPAXISMODE_REL=1
        DIPROP_RANGE => {
            h[4] = @bitCast(d.range_min);
            h[5] = @bitCast(d.range_max);
        },
        DIPROP_DEADZONE => h[4] = d.deadzone,
        DIPROP_SATURATION => h[4] = d.saturation,
        else => {
            sayOnce(2, "GetProperty for an unsupported property", @returnAddress());
            return DIERR_NOTFOUND;
        },
    }
    return DI_OK;
}

fn dev_SetProperty(this: *anyopaque, prop: usize, ph: ?[*]const u32) callconv(W) i32 {
    const d = self(this);
    const h = ph orelse return E_POINTER;
    switch (prop) {
        DIPROP_BUFFERSIZE => {
            const n = @min(h[4], 4096);
            const fresh = std.heap.page_allocator.alloc(ObjectData, n) catch return DIERR_OUTOFMEMORY;
            lock();
            const old = d.buffer;
            d.buffer = fresh;
            d.head = 0;
            d.count = 0;
            d.overflow = false;
            unlock();
            if (old.len != 0) std.heap.page_allocator.free(old);
        },
        DIPROP_AXISMODE => d.absolute = h[4] == 0, // DIPROPAXISMODE_ABS=0, DIPROPAXISMODE_REL=1
        DIPROP_RANGE => {
            const rmin: i32 = @bitCast(h[4]);
            const rmax: i32 = @bitCast(h[5]);
            if (rmin > rmax) return DIERR_INVALIDPARAM;
            d.range_min = rmin;
            d.range_max = rmax;
        },
        DIPROP_DEADZONE => {
            if (h[4] > 10000) return DIERR_INVALIDPARAM;
            d.deadzone = h[4];
        },
        DIPROP_SATURATION => {
            if (h[4] > 10000) return DIERR_INVALIDPARAM;
            d.saturation = h[4];
        },
        else => {
            sayOnce(3, "SetProperty for an unsupported property (ignored)", @returnAddress());
        },
    }
    return DI_OK;
}

fn dev_Acquire(this: *anyopaque) callconv(W) i32 {
    const d = self(this);
    sayOnce(10 + @as(u5, @intCast(@intFromEnum(d.kind))), "Acquire", @returnAddress());
    if (traceOn()) std.debug.print("[WINS:DInput] {s} 0x{x}: Acquire (data size {d}, acquired {})\n", .{ @tagName(d.kind), @intFromPtr(d), d.data_size, d.acquired });
    if (d.data_size == 0) return DIERR_INVALIDPARAM; // no data format yet
    if (d.acquired) return DI_NOEFFECT;
    lock();
    d.acquired = true;
    d.head = 0;
    d.count = 0;
    @memset(&d.latched_keys, false);
    d.latched_buttons = 0;
    unlock();
    d.seen_x = g_mouse_x.load(.monotonic);
    d.seen_y = g_mouse_y.load(.monotonic);
    d.seen_z = g_mouse_z.load(.monotonic);
    return DI_OK;
}

fn dev_Unacquire(this: *anyopaque) callconv(W) i32 {
    const d = self(this);
    sayOnce(13 + @as(u5, @intCast(@intFromEnum(d.kind))), "Unacquire", @returnAddress());
    if (traceOn()) std.debug.print("[WINS:DInput] {s} 0x{x}: Unacquire\n", .{ @tagName(d.kind), @intFromPtr(d) });
    if (!d.acquired) return DI_NOEFFECT;
    lock();
    d.acquired = false;
    unlock();
    return DI_OK;
}

fn scaleJoyAxis(d: *const Device, raw_v: i16) i32 {
    var norm: f64 = if (raw_v < 0)
        @as(f64, @floatFromInt(raw_v)) / 32768.0
    else
        @as(f64, @floatFromInt(raw_v)) / 32767.0;
    const dz = @as(f64, @floatFromInt(d.deadzone)) / 10000.0;
    const sat = @as(f64, @floatFromInt(d.saturation)) / 10000.0;
    const mag = @abs(norm);
    if (mag <= dz) {
        norm = 0;
    } else if (mag >= sat or sat <= dz) {
        norm = std.math.sign(norm);
    } else {
        norm = std.math.sign(norm) * (mag - dz) / (sat - dz);
    }
    const rmin: f64 = @floatFromInt(d.range_min);
    const rmax: f64 = @floatFromInt(d.range_max);
    const mid = (rmin + rmax) * 0.5;
    const half = (rmax - rmin) * 0.5;
    return @intFromFloat(std.math.clamp(mid + norm * half, rmin, rmax));
}

fn povFromDpad(buttons: u16) u32 {
    const up = (buttons & 0x0001) != 0;
    const down = (buttons & 0x0002) != 0;
    const left = (buttons & 0x0004) != 0;
    const right = (buttons & 0x0008) != 0;
    if (up and right) return 4500;
    if (down and right) return 13500;
    if (down and left) return 22500;
    if (up and left) return 31500;
    if (up) return 0;
    if (right) return 9000;
    if (down) return 18000;
    if (left) return 27000;
    return 0xFFFFFFFF;
}

fn dev_GetDeviceState(this: *anyopaque, cb: u32, data: ?[*]u8) callconv(W) i32 {
    const d = self(this);
    const out = data orelse return E_POINTER;
    sayOnce(16 + @as(u5, @intCast(@intFromEnum(d.kind))), "GetDeviceState", @returnAddress());
    if (!d.acquired) return DIERR_NOTACQUIRED;
    if (cb != d.data_size) return DIERR_INVALIDPARAM;
    switch (d.kind) {
        .keyboard => {
            lock();
            defer unlock();
            var any: u32 = 0;
            for (0..256) |k| {
                if (g_keys[k].load(.monotonic) != 0 or d.latched_keys[k]) {
                    out[k] = 0x80;
                    d.latched_keys[k] = false;
                    any = @intCast(k);
                } else {
                    out[k] = 0;
                }
            }
            if (traceOn()) {
                d.polls += 1;
                if (any != 0 or d.polls % 600 == 1) std.debug.print("[WINS:DInput] keyboard 0x{x}: GetDeviceState poll {d} tid {d} (DIK 0x{x} down)\n", .{ @intFromPtr(d), d.polls, linux.gettid(), any });
            }
        },
        .mouse => {
            const x = g_mouse_x.load(.monotonic);
            const y = g_mouse_y.load(.monotonic);
            const z = g_mouse_z.load(.monotonic);
            const v: [3]i32 = if (d.absolute) .{ x, y, z } else .{ x -% d.seen_x, y -% d.seen_y, z -% d.seen_z };
            d.seen_x = x;
            d.seen_y = y;
            d.seen_z = z;
            @memcpy(out[0..12], std.mem.sliceAsBytes(&v));
            lock();
            const buttons = g_buttons.load(.monotonic) | d.latched_buttons;
            d.latched_buttons = 0;
            unlock();
            for (0..cb - 12) |i| out[12 + i] = if (i < 5 and (buttons >> @intCast(i)) & 1 != 0) 0x80 else 0;
        },
        .joystick => {
            @memset(out[0..cb], 0);
            for (0..4) |p| std.mem.writeInt(u32, out[32 + p * 4 ..][0..4], 0xFFFFFFFF, .little);
            const ci = xinput.queryController(d.joy_index);
            if (!ci.connected) return DI_OK;
            const gp = ci.state.Gamepad;
            const invY: i16 = if (gp.sThumbLY == std.math.minInt(i16)) std.math.maxInt(i16) else -gp.sThumbLY;
            const invRY: i16 = if (gp.sThumbRY == std.math.minInt(i16)) std.math.maxInt(i16) else -gp.sThumbRY;
            const trig_diff: i32 = (@as(i32, gp.bLeftTrigger) - @as(i32, gp.bRightTrigger)) * 128;
            const lZ_raw: i16 = @intCast(std.math.clamp(trig_diff, -32768, 32767));
            const axes = [5]i32{
                scaleJoyAxis(d, gp.sThumbLX),
                scaleJoyAxis(d, invY),
                scaleJoyAxis(d, lZ_raw),
                scaleJoyAxis(d, gp.sThumbRX),
                scaleJoyAxis(d, invRY),
            };
            for (axes, 0..) |a, idx| std.mem.writeInt(i32, out[idx * 4 ..][0..4], a, .little);
            std.mem.writeInt(u32, out[32..36], povFromDpad(gp.wButtons), .little);
            // XInput face/shoulder/system buttons mapped to DIJOYSTATE::rgbButtons[0..9]
            const di_masks = [_]u16{
                0x1000, // 0: A
                0x2000, // 1: B
                0x4000, // 2: X
                0x8000, // 3: Y
                0x0100, // 4: LB
                0x0200, // 5: RB
                0x0020, // 6: Back
                0x0010, // 7: Start
                0x0040, // 8: LS
                0x0080, // 9: RS
            };
            for (di_masks, 0..) |m, bi| {
                out[48 + bi] = if ((gp.wButtons & m) != 0) 0x80 else 0;
            }
        },
    }
    return DI_OK;
}

fn dev_GetDeviceData(this: *anyopaque, cb: u32, rgdod: ?[*]ObjectData, inout: ?*u32, flags: u32) callconv(W) i32 {
    const d = self(this);
    const n_ptr = inout orelse return E_POINTER;
    sayOnce(19 + @as(u5, @intCast(@intFromEnum(d.kind))), "GetDeviceData", @returnAddress());
    if (!d.acquired) return DIERR_NOTACQUIRED;
    if (cb != @sizeOf(ObjectData)) return DIERR_INVALIDPARAM;
    if (d.buffer.len == 0) return DIERR_NOTBUFFERED;
    const peek = flags & 1 != 0;
    lock();
    defer unlock();
    const want: usize = n_ptr.*;
    const n = @min(want, d.count);
    if (rgdod) |out| {
        for (0..n) |i| out[i] = d.buffer[(d.head + i) % d.buffer.len];
    }
    if (!peek) {
        d.head = (d.head + n) % d.buffer.len;
        d.count -= n;
    }
    n_ptr.* = @intCast(n);
    const over = d.overflow;
    if (!peek) d.overflow = false;
    return if (over) DI_BUFFEROVERFLOW else DI_OK;
}

/// DIDATAFORMAT: dwSize, dwObjSize, dwFlags, dwDataSize, dwNumObjs, rgodf.
/// The standard formats (c_dfDIKeyboard 256, c_dfDIMouse 16, c_dfDIMouse2 20,
/// c_dfDIJoystick 80, c_dfDIJoystick2 272) are recognised by their data size;
/// their object layout is the standard one.
fn dev_SetDataFormat(this: *anyopaque, fmt: ?[*]const u32) callconv(W) i32 {
    const d = self(this);
    const f = fmt orelse return E_POINTER;
    if (d.acquired) return @bitCast(@as(u32, 0x8007001E)); // DIERR_ACQUIRED
    const size = f[3];
    const ok = switch (d.kind) {
        .keyboard => size == 256,
        .mouse => size == 16 or size == 20,
        .joystick => size == 80 or size == 272,
    };
    std.debug.print("[WINS:DInput] {s}: SetDataFormat(data size {d}, flags 0x{x}, {d} objects){s}\n", .{ @tagName(d.kind), size, f[2], f[4], if (ok) "" else " -- not a standard format, refused" });
    if (!ok) return DIERR_INVALIDPARAM;
    d.data_size = size;
    d.absolute = (f[2] & 1) != 0; // DIDF_ABSAXIS
    return DI_OK;
}

fn dev_SetEventNotification(this: *anyopaque, h: usize) callconv(W) i32 {
    _ = this;
    if (h != 0) sayOnce(4, "SetEventNotification with an event (not signalled yet)", @returnAddress());
    return DI_OK;
}

fn dev_SetCooperativeLevel(this: *anyopaque, hwnd: usize, flags: u32) callconv(W) i32 {
    const d = self(this);
    d.coop_flags = flags;
    std.debug.print("[WINS:DInput] {s}: SetCooperativeLevel(hwnd 0x{x}, flags 0x{x})\n", .{ @tagName(d.kind), hwnd, flags });
    return DI_OK;
}

fn dev_GetObjectInfo(this: *anyopaque, info: ?*anyopaque, obj: u32, how: u32) callconv(W) i32 {
    _ = this;
    _ = info;
    _ = obj;
    _ = how;
    sayOnce(5, "GetObjectInfo is not implemented yet", @returnAddress());
    return E_NOTIMPL;
}

fn fillName(dst: []u8, wide: bool, name: []const u8) void {
    const cap = if (wide) dst.len / 2 else dst.len;
    if (cap == 0) return;
    const n = @min(name.len, cap - 1);
    if (wide) {
        for (name[0..n], 0..) |ch, i| {
            dst[i * 2] = ch;
            dst[i * 2 + 1] = 0;
        }
    } else @memcpy(dst[0..n], name[0..n]);
}

fn deviceName(kind: Kind, joy_index: u8, name_buf: *[64]u8) struct { name: []const u8, prod: GUID } {
    switch (kind) {
        .keyboard => return .{ .name = "Keyboard", .prod = GUID_SysKeyboard },
        .mouse => return .{ .name = "Mouse", .prod = GUID_SysMouse },
        .joystick => {
            const ci = xinput.queryController(joy_index);
            const ig = joystickGuid(joy_index);
            const prod: GUID = if (ci.vendor != 0 or ci.product != 0)
                .{ .d1 = (@as(u32, ci.product) << 16) | ci.vendor, .d2 = 0, .d3 = 0, .d4 = .{ 0, 0, 'P', 'I', 'D', 'V', 'I', 'D' } }
            else
                ig;
            if (ci.connected and ci.name_len > 0) {
                const n = @min(@as(usize, ci.name_len), name_buf.len);
                @memcpy(name_buf[0..n], ci.name[0..n]);
                return .{ .name = name_buf[0..n], .prod = prod };
            }
            return .{ .name = "XInput Controller", .prod = prod };
        },
    }
}

fn fillDeviceInstance(kind: Kind, joy_index: u8, wide: bool, p: [*]u8, size: u32) i32 {
    const char_size: usize = if (wide) 2 else 1;
    const full: u32 = @intCast(4 + 16 + 16 + 4 + 520 * char_size + 16 + 4);
    if (size != full and size != full - 20) return DIERR_INVALIDPARAM;
    std.mem.writeInt(u32, p[0..4], size, .little);
    @memset(p[4..size], 0);
    const joy_guid = joystickGuid(joy_index);
    const inst_guid: *const GUID = switch (kind) {
        .keyboard => &GUID_SysKeyboard,
        .mouse => &GUID_SysMouse,
        .joystick => &joy_guid,
    };
    var name_buf: [64]u8 = undefined;
    const info = deviceName(kind, joy_index, &name_buf);
    const dev_type: u32 = switch (kind) {
        .keyboard => 0x13 | (4 << 8),
        .mouse => 0x12 | (2 << 8),
        .joystick => 0x15 | (2 << 8),
    };
    @memcpy(p[4..20], std.mem.asBytes(inst_guid));
    @memcpy(p[20..36], std.mem.asBytes(&info.prod));
    std.mem.writeInt(u32, p[36..40], dev_type, .little);
    fillName(p[40 .. 40 + 260 * char_size], wide, info.name);
    fillName(p[40 + 260 * char_size .. 40 + 520 * char_size], wide, info.name);
    if (size == full) {
        const u = 40 + 520 * char_size + 16;
        const usage: u16 = switch (kind) {
            .keyboard => 6,
            .mouse => 2,
            .joystick => 5,
        };
        std.mem.writeInt(u16, p[u..][0..2], 1, .little); // HID usage page: generic desktop
        std.mem.writeInt(u16, p[u + 2 ..][0..2], usage, .little);
    }
    return DI_OK;
}

/// DIDEVICEINSTANCE{A,W}: dwSize, guidInstance, guidProduct, dwDevType,
/// tszInstanceName[260], tszProductName[260], guidFFDriver, wUsagePage, wUsage.
fn dev_GetDeviceInfo(this: *anyopaque, raw: ?[*]u8) callconv(W) i32 {
    const d = self(this);
    const p = raw orelse return E_POINTER;
    const size = std.mem.readInt(u32, p[0..4], .little);
    return fillDeviceInstance(d.kind, d.joy_index, d.wide, p, size);
}

fn dev_RunControlPanel(this: *anyopaque, hwnd: usize, flags: u32) callconv(W) i32 {
    _ = this;
    _ = hwnd;
    _ = flags;
    return E_NOTIMPL;
}
fn dev_Initialize(this: *anyopaque, hinst: usize, ver: u32, guid: ?*anyopaque) callconv(W) i32 {
    _ = this;
    _ = hinst;
    _ = ver;
    _ = guid;
    return DI_OK;
}
fn noFx5(this: *anyopaque, a: usize, b: usize, c: usize, e: usize) callconv(W) i32 {
    _ = this;
    _ = a;
    _ = b;
    _ = c;
    _ = e;
    sayOnce(6, "a force-feedback/effect-file method (no force feedback)", @returnAddress());
    return DIERR_DEVICENOTREG;
}
fn noFx4(this: *anyopaque, a: usize, b: usize, c: usize) callconv(W) i32 {
    _ = this;
    _ = a;
    _ = b;
    _ = c;
    sayOnce(7, "an effect/action-map method (not implemented)", @returnAddress());
    return E_NOTIMPL;
}
fn noFx3(this: *anyopaque, a: usize, b: usize) callconv(W) i32 {
    _ = this;
    _ = a;
    _ = b;
    sayOnce(8, "GetEffectInfo (no effects)", @returnAddress());
    return E_NOTIMPL;
}
fn noFx2(this: *anyopaque, a: usize) callconv(W) i32 {
    _ = this;
    _ = a;
    sayOnce(9, "a force-feedback/Escape/GetImageInfo method (not implemented)", @returnAddress());
    return E_NOTIMPL;
}
fn dev_Poll(this: *anyopaque) callconv(W) i32 {
    const d = self(this);
    if (!d.acquired) return DIERR_NOTACQUIRED;
    if (d.kind == .joystick) _ = xinput.queryController(d.joy_index);
    return DI_OK;
}

const g_vtbl: Vtbl = .{
    .QueryInterface = @ptrCast(&dev_QueryInterface),
    .AddRef = @ptrCast(&dev_AddRef),
    .Release = @ptrCast(&dev_Release),
    .GetCapabilities = @ptrCast(&dev_GetCapabilities),
    .EnumObjects = @ptrCast(&dev_EnumObjects),
    .GetProperty = @ptrCast(&dev_GetProperty),
    .SetProperty = @ptrCast(&dev_SetProperty),
    .Acquire = @ptrCast(&dev_Acquire),
    .Unacquire = @ptrCast(&dev_Unacquire),
    .GetDeviceState = @ptrCast(&dev_GetDeviceState),
    .GetDeviceData = @ptrCast(&dev_GetDeviceData),
    .SetDataFormat = @ptrCast(&dev_SetDataFormat),
    .SetEventNotification = @ptrCast(&dev_SetEventNotification),
    .SetCooperativeLevel = @ptrCast(&dev_SetCooperativeLevel),
    .GetObjectInfo = @ptrCast(&dev_GetObjectInfo),
    .GetDeviceInfo = @ptrCast(&dev_GetDeviceInfo),
    .RunControlPanel = @ptrCast(&dev_RunControlPanel),
    .Initialize = @ptrCast(&dev_Initialize),
    .CreateEffect = @ptrCast(&noFx5),
    .EnumEffects = @ptrCast(&noFx4),
    .GetEffectInfo = @ptrCast(&noFx3),
    .GetForceFeedbackState = @ptrCast(&noFx2),
    .SendForceFeedbackCommand = @ptrCast(&noFx2),
    .EnumCreatedEffectObjects = @ptrCast(&noFx4),
    .Escape = @ptrCast(&noFx2),
    .Poll = @ptrCast(&dev_Poll),
    .SendDeviceData = @ptrCast(&noFx5),
    .EnumEffectsInFile = @ptrCast(&noFx5),
    .WriteEffectToFile = @ptrCast(&noFx5),
    .BuildActionMap = @ptrCast(&noFx4),
    .SetActionMap = @ptrCast(&noFx4),
    .GetImageInfo = @ptrCast(&noFx2),
};

const EnumDeviceCb = *const fn (*const u8, ?*anyopaque) callconv(W) i32;

const DIEDFL_FORCEFEEDBACK: u32 = 0x00000100;
const DI8DEVCLASS_ALL: u32 = 0;
const DI8DEVCLASS_POINTER: u32 = 2;
const DI8DEVCLASS_KEYBOARD: u32 = 3;
const DI8DEVCLASS_GAMECTRL: u32 = 4;
const DI_NOTATTACHED: i32 = 1;

fn pushEnumDevice(kind: Kind, joy_index: u8, wide: bool, cb_fn: EnumDeviceCb, ref: ?*anyopaque) bool {
    var buf: [1100]u8 align(4) = undefined;
    const full: u32 = if (wide) 1100 else 580;
    _ = fillDeviceInstance(kind, joy_index, wide, &buf, full);
    return cb_fn(&buf[0], ref) != 0;
}

/// IDirectInput8::EnumDevices
pub fn enumDevices(dev_type: u32, wide: bool, cb: ?*anyopaque, ref: ?*anyopaque, flags: u32) i32 {
    const raw_cb = cb orelse return DIERR_INVALIDPARAM;
    const cb_fn: EnumDeviceCb = @ptrCast(@alignCast(raw_cb));
    if ((flags & DIEDFL_FORCEFEEDBACK) != 0) return DI_OK;
    const base_type = dev_type & 0xFF;
    const want_mouse = dev_type == DI8DEVCLASS_ALL or dev_type == DI8DEVCLASS_POINTER or base_type == 0x12;
    const want_kb = dev_type == DI8DEVCLASS_ALL or dev_type == DI8DEVCLASS_KEYBOARD or base_type == 0x13;
    const want_joy = dev_type == DI8DEVCLASS_ALL or dev_type == DI8DEVCLASS_GAMECTRL or (base_type >= 0x14 and base_type <= 0x1C);
    if (want_mouse) {
        if (!pushEnumDevice(.mouse, 0, wide, cb_fn, ref)) return DI_OK;
    }
    if (want_kb) {
        if (!pushEnumDevice(.keyboard, 0, wide, cb_fn, ref)) return DI_OK;
    }
    if (want_joy) {
        for (0..4) |slot| {
            const idx: u8 = @intCast(slot);
            if (!xinput.queryController(idx).connected) continue;
            if (!pushEnumDevice(.joystick, idx, wide, cb_fn, ref)) return DI_OK;
        }
    }
    return DI_OK;
}

/// IDirectInput8::GetDeviceStatus
pub fn getDeviceStatus(guid: ?*align(1) const GUID) i32 {
    const g = guid orelse return E_POINTER;
    if (guidEql(g, &GUID_SysKeyboard) or guidEql(g, &GUID_SysMouse)) return DI_OK;
    if (matchJoystickGuid(g)) |slot| {
        return if (xinput.queryController(slot).connected) DI_OK else DI_NOTATTACHED;
    }
    return DI_NOTATTACHED;
}

fn readGuestName(name_ptr: ?*const anyopaque, wide: bool, out: *[260]u8) ?[]const u8 {
    const ptr = name_ptr orelse return null;
    if (wide) {
        const wp: [*:0]const u16 = @ptrCast(@alignCast(ptr));
        var n: usize = 0;
        while (n < out.len and wp[n] != 0) : (n += 1) {
            out[n] = @truncate(wp[n]);
        }
        return out[0..n];
    } else {
        const ap: [*:0]const u8 = @ptrCast(ptr);
        const s = std.mem.sliceTo(ap, 0);
        const n = @min(s.len, out.len);
        @memcpy(out[0..n], s[0..n]);
        return out[0..n];
    }
}

/// IDirectInput8::FindDevice
pub fn findDevice(rguid_class: ?*align(1) const GUID, name_ptr: ?*const anyopaque, wide: bool, out_guid: ?*align(1) GUID) i32 {
    const dst = out_guid orelse return E_POINTER;
    var tmp: [260]u8 = undefined;
    const name = readGuestName(name_ptr, wide, &tmp) orelse return DIERR_INVALIDPARAM;
    if (rguid_class) |g| {
        if (guidEql(g, &GUID_SysKeyboard) and std.ascii.eqlIgnoreCase(name, "Keyboard")) {
            dst.* = GUID_SysKeyboard;
            return DI_OK;
        }
        if (guidEql(g, &GUID_SysMouse) and std.ascii.eqlIgnoreCase(name, "Mouse")) {
            dst.* = GUID_SysMouse;
            return DI_OK;
        }
    }
    for (0..4) |slot| {
        const idx: u8 = @intCast(slot);
        const ci = xinput.queryController(idx);
        if (!ci.connected) continue;
        const jg = joystickGuid(idx);
        if (rguid_class) |g| {
            const zero = std.mem.zeroes(GUID);
            if (!guidEql(g, &zero) and !guidEql(g, &jg)) continue;
        }
        const cname = if (ci.name_len > 0) ci.name[0..ci.name_len] else "XInput Controller";
        if (std.ascii.eqlIgnoreCase(name, cname) or std.ascii.eqlIgnoreCase(name, "XInput Controller")) {
            dst.* = jg;
            return DI_OK;
        }
    }
    return DIERR_DEVICENOTREG;
}

/// IDirectInput8::CreateDevice for the system keyboard, mouse, and attached gamepads.
pub fn createDevice(guid: ?*align(1) const GUID, wide: bool, out: *?*anyopaque) i32 {
    out.* = null;
    const g = guid orelse return E_POINTER;
    var joy_index: u8 = 0;
    const kind: Kind = if (guidEql(g, &GUID_SysKeyboard))
        .keyboard
    else if (guidEql(g, &GUID_SysMouse))
        .mouse
    else if (matchJoystickGuid(g)) |slot| blk: {
        if (!xinput.queryController(slot).connected) return DIERR_DEVICENOTREG;
        joy_index = slot;
        break :blk .joystick;
    } else {
        std.debug.print("[WINS:DInput] CreateDevice({x:0>8}-...): unknown device GUID\n", .{g.d1});
        return DIERR_DEVICENOTREG;
    };
    const d = std.heap.page_allocator.create(Device) catch return DIERR_OUTOFMEMORY;
    d.* = .{ .vtbl = &g_vtbl, .ref_count = 1, .kind = kind, .wide = wide, .joy_index = joy_index };
    lock();
    defer unlock();
    for (&g_devices) |*slot| {
        if (slot.* == null) {
            slot.* = d;
            std.debug.print("[WINS:DInput] CreateDevice({s}#{d}) -> 0x{x}\n", .{ @tagName(kind), joy_index, @intFromPtr(d) });
            out.* = d;
            return DI_OK;
        }
    }
    std.heap.page_allocator.destroy(d);
    return DIERR_OUTOFMEMORY;
}

pub fn isSystemDeviceGuid(guid: ?*align(1) const GUID) bool {
    const g = guid orelse return false;
    return guidEql(g, &GUID_SysKeyboard) or guidEql(g, &GUID_SysMouse) or matchJoystickGuid(g) != null;
}

// ---- tests --------------------------------------------------------------------

fn testCreate(kind: Kind) !*Device {
    var out: ?*anyopaque = null;
    const jg = joystickGuid(0);
    const g: *const GUID = switch (kind) {
        .keyboard => &GUID_SysKeyboard,
        .mouse => &GUID_SysMouse,
        .joystick => &jg,
    };
    try std.testing.expectEqual(DI_OK, createDevice(g, false, &out));
    return @ptrCast(@alignCast(out.?));
}

test "keyboard: state needs format + acquire, reflects key events, buffer delivers them in order" {
    const d = try testCreate(.keyboard);
    defer _ = dev_Release(d);
    var state: [256]u8 = undefined;
    try std.testing.expectEqual(DIERR_NOTACQUIRED, dev_GetDeviceState(d, 256, &state));
    try std.testing.expectEqual(DIERR_INVALIDPARAM, dev_Acquire(d));
    const fmt = [_]u32{ 24, 16, 2, 256, 256, 0 };
    try std.testing.expectEqual(DI_OK, dev_SetDataFormat(d, &fmt));
    const prop = [_]u32{ 20, 16, 0, 0, 8 };
    try std.testing.expectEqual(DI_OK, dev_SetProperty(d, DIPROP_BUFFERSIZE, &prop));
    try std.testing.expectEqual(DI_OK, dev_Acquire(d));
    keyEvent(0x1C, true); // Enter
    keyEvent(0x1C, true); // repeat: no new event
    try std.testing.expectEqual(DI_OK, dev_GetDeviceState(d, 256, &state));
    try std.testing.expectEqual(@as(u8, 0x80), state[0x1C]);
    keyEvent(0x1C, false);
    var evs: [4]ObjectData = undefined;
    var n: u32 = 4;
    try std.testing.expectEqual(DI_OK, dev_GetDeviceData(d, @sizeOf(ObjectData), &evs, &n, 0));
    try std.testing.expectEqual(@as(u32, 2), n);
    try std.testing.expectEqual(@as(u32, 0x80), evs[0].dwData);
    try std.testing.expectEqual(@as(u32, 0), evs[1].dwData);
    try std.testing.expect(evs[1].dwSequence > evs[0].dwSequence);
    n = 4;
    try std.testing.expectEqual(DI_OK, dev_GetDeviceData(d, @sizeOf(ObjectData), &evs, &n, 0));
    try std.testing.expectEqual(@as(u32, 0), n);
}

test "mouse: relative deltas are per read, buttons and wheel, DIMOUSESTATE2 size" {
    const d = try testCreate(.mouse);
    defer _ = dev_Release(d);
    const fmt = [_]u32{ 24, 16, 2, 20, 11, 0 };
    try std.testing.expectEqual(DI_OK, dev_SetDataFormat(d, &fmt));
    try std.testing.expectEqual(DI_OK, dev_Acquire(d));
    mouseMove(5, -3);
    mouseWheel(120);
    mouseButton(0, true);
    var st: [20]u8 = undefined;
    try std.testing.expectEqual(DI_OK, dev_GetDeviceState(d, 20, &st));
    try std.testing.expectEqual(@as(i32, 5), std.mem.readInt(i32, st[0..4], .little));
    try std.testing.expectEqual(@as(i32, -3), std.mem.readInt(i32, st[4..8], .little));
    try std.testing.expectEqual(@as(i32, 120), std.mem.readInt(i32, st[8..12], .little));
    try std.testing.expectEqual(@as(u8, 0x80), st[12]);
    try std.testing.expectEqual(DI_OK, dev_GetDeviceState(d, 20, &st));
    try std.testing.expectEqual(@as(i32, 0), std.mem.readInt(i32, st[0..4], .little));
    mouseButton(0, false);
    try std.testing.expectEqual(DIERR_INVALIDPARAM, dev_GetDeviceState(d, 16, &st));
}

test "X11 keycodes map to DirectInput scan codes" {
    try std.testing.expectEqual(@as(u8, 0x01), dikFromX11(9)); // Escape
    try std.testing.expectEqual(@as(u8, 0x1C), dikFromX11(36)); // Return
    try std.testing.expectEqual(@as(u8, 0xC8), dikFromX11(111)); // Up
    try std.testing.expectEqual(@as(u8, 0x9C), dikFromX11(104)); // KP Enter
    try std.testing.expectEqual(@as(u8, 0), dikFromX11(3));
}

test "joystick: EnumDevices, CreateDevice, EnumObjects, properties, and DIJOYSTATE2 readout" {
    xinput.setTestController(0, true, .{
        .wButtons = 0x1005, // A (0x1000) + UP (0x0001) + LEFT (0x0004)
        .bLeftTrigger = 200,
        .bRightTrigger = 0,
        .sThumbLX = 16384,
        .sThumbLY = -32768,
        .sThumbRX = 3000,
        .sThumbRY = 0,
    });
    defer xinput.clearTestController(0);

    try std.testing.expectEqual(DIERR_INVALIDPARAM, enumDevices(DI8DEVCLASS_ALL, false, null, null, 0));

    const Ctx = struct { count: u32 = 0, saw_pad: bool = false, saw_mouse: bool = false };
    var ctx = Ctx{};
    const cb = struct {
        fn f(raw: *const u8, ref: ?*anyopaque) callconv(W) i32 {
            const c: *Ctx = @ptrCast(@alignCast(ref.?));
            const p: [*]const u8 = @ptrCast(raw);
            c.count += 1;
            const d1 = std.mem.readInt(u32, p[4..8], .little);
            if (d1 == 0x57494E53) c.saw_pad = true;
            if (d1 == 0x6F1D2B60) c.saw_mouse = true;
            return 1;
        }
    }.f;
    try std.testing.expectEqual(DI_OK, enumDevices(DI8DEVCLASS_ALL, false, @constCast(@ptrCast(&cb)), &ctx, 0));
    try std.testing.expect(ctx.count >= 3);
    try std.testing.expect(ctx.saw_pad);
    try std.testing.expect(ctx.saw_mouse);

    const d = try testCreate(.joystick);
    defer _ = dev_Release(d);

    var info_w: [1100]u8 align(4) = [_]u8{0} ** 1100;
    std.mem.writeInt(u32, info_w[0..4], 1100, .little);
    d.wide = true;
    try std.testing.expectEqual(DI_OK, dev_GetDeviceInfo(d, &info_w));
    d.wide = false;
    try std.testing.expectEqual(@as(u8, 'X'), info_w[40]);

    var obj_count: u32 = 0;
    const obj_cb = struct {
        fn f(raw: *const u8, ref: ?*anyopaque) callconv(W) i32 {
            _ = raw;
            const c: *u32 = @ptrCast(@alignCast(ref.?));
            c.* += 1;
            return 1;
        }
    }.f;
    try std.testing.expectEqual(DI_OK, dev_EnumObjects(d, @constCast(@ptrCast(&obj_cb)), &obj_count, 0));
    try std.testing.expectEqual(@as(u32, 18), obj_count); // 5 axes + 1 POV + 12 buttons

    const fmt = [_]u32{ 24, 16, 1, 272, 0, 0 };
    try std.testing.expectEqual(DI_OK, dev_SetDataFormat(d, &fmt));
    const range_prop = [_]u32{ 24, 16, 0, 1, @bitCast(@as(i32, -1000)), @bitCast(@as(i32, 1000)) };
    try std.testing.expectEqual(DI_OK, dev_SetProperty(d, DIPROP_RANGE, &range_prop));
    const dz_prop = [_]u32{ 20, 16, 0, 1, 2000 };
    try std.testing.expectEqual(DI_OK, dev_SetProperty(d, DIPROP_DEADZONE, &dz_prop));
    try std.testing.expectEqual(DI_OK, dev_Acquire(d));
    try std.testing.expectEqual(DI_OK, dev_Poll(d));

    var st: [272]u8 align(4) = undefined;
    try std.testing.expectEqual(DI_OK, dev_GetDeviceState(d, 272, &st));
    const ly = std.mem.readInt(i32, st[4..8], .little);
    const rx = std.mem.readInt(i32, st[12..16], .little);
    const pov = std.mem.readInt(u32, st[32..36], .little);
    try std.testing.expectEqual(@as(i32, 1000), ly); // -32768 inverted -> +1000
    try std.testing.expectEqual(@as(i32, 0), rx); // 3000/32767 < 0.20 deadzone -> 0
    try std.testing.expectEqual(@as(u32, 31500), pov); // up + left -> 315 deg
    try std.testing.expectEqual(@as(u8, 0x80), st[48]); // button A

    var found_guid: GUID = undefined;
    try std.testing.expectEqual(DI_OK, findDevice(null, "XInput Test Gamepad", false, &found_guid));
    try std.testing.expect(guidEql(&found_guid, &joystickGuid(0)));
    try std.testing.expectEqual(DI_OK, getDeviceStatus(&found_guid));
}

test "fast tap latching: key and mouse button taps between GetDeviceState calls are observed once" {
    const kb = try testCreate(.keyboard);
    defer _ = dev_Release(kb);
    const kb_fmt = [_]u32{ 24, 16, 2, 256, 256, 0 };
    try std.testing.expectEqual(DI_OK, dev_SetDataFormat(kb, &kb_fmt));
    try std.testing.expectEqual(DI_OK, dev_Acquire(kb));

    // Unbuffered keyboard: Tab (DIK 0x0F) pressed and released before GetDeviceState runs.
    keyEvent(0x0F, true);
    keyEvent(0x0F, false);
    var kstate: [256]u8 = undefined;
    try std.testing.expectEqual(DI_OK, dev_GetDeviceState(kb, 256, &kstate));
    try std.testing.expectEqual(@as(u8, 0x80), kstate[0x0F]);
    try std.testing.expectEqual(DI_OK, dev_GetDeviceState(kb, 256, &kstate));
    try std.testing.expectEqual(@as(u8, 0), kstate[0x0F]);

    // Shift (0x2A) held across one poll still releases cleanly on key-up without re-latching.
    keyEvent(0x2A, true);
    try std.testing.expectEqual(DI_OK, dev_GetDeviceState(kb, 256, &kstate));
    try std.testing.expectEqual(@as(u8, 0x80), kstate[0x2A]);
    keyEvent(0x2A, false);
    try std.testing.expectEqual(DI_OK, dev_GetDeviceState(kb, 256, &kstate));
    try std.testing.expectEqual(@as(u8, 0), kstate[0x2A]);

    // Focus loss clears unconsumed latches.
    keyEvent(0x0F, true);
    keyEvent(0x0F, false);
    focus(false);
    try std.testing.expectEqual(DI_OK, dev_GetDeviceState(kb, 256, &kstate));
    try std.testing.expectEqual(@as(u8, 0), kstate[0x0F]);

    const m = try testCreate(.mouse);
    defer _ = dev_Release(m);
    const m_fmt = [_]u32{ 24, 16, 2, 20, 11, 0 };
    try std.testing.expectEqual(DI_OK, dev_SetDataFormat(m, &m_fmt));
    try std.testing.expectEqual(DI_OK, dev_Acquire(m));
    mouseButton(0, true);
    mouseButton(0, false);
    var mstate: [20]u8 = undefined;
    try std.testing.expectEqual(DI_OK, dev_GetDeviceState(m, 20, &mstate));
    try std.testing.expectEqual(@as(u8, 0x80), mstate[12]);
    try std.testing.expectEqual(DI_OK, dev_GetDeviceState(m, 20, &mstate));
    try std.testing.expectEqual(@as(u8, 0), mstate[12]);

    // DIPROP_AXISMODE: DIPROPAXISMODE_REL (1) must keep relative deltas; DIPROPAXISMODE_ABS (0) switches to absolute.
    const rel_prop = [_]u32{ 20, 16, 0, 0, 1 };
    try std.testing.expectEqual(DI_OK, dev_SetProperty(m, DIPROP_AXISMODE, &rel_prop));
    var got_prop = [_]u32{ 20, 16, 0, 0, 99 };
    try std.testing.expectEqual(DI_OK, dev_GetProperty(m, DIPROP_AXISMODE, &got_prop));
    try std.testing.expectEqual(@as(u32, 1), got_prop[4]);
    mouseMove(15, -7);
    try std.testing.expectEqual(DI_OK, dev_GetDeviceState(m, 20, &mstate));
    try std.testing.expectEqual(@as(i32, 15), std.mem.readInt(i32, mstate[0..4], .little));
    try std.testing.expectEqual(@as(i32, -7), std.mem.readInt(i32, mstate[4..8], .little));
    try std.testing.expectEqual(DI_OK, dev_GetDeviceState(m, 20, &mstate));
    try std.testing.expectEqual(@as(i32, 0), std.mem.readInt(i32, mstate[0..4], .little));
    try std.testing.expectEqual(@as(i32, 0), std.mem.readInt(i32, mstate[4..8], .little));
}
