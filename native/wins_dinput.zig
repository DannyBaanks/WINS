//! DirectInput 8 keyboard and mouse fed by the host window.
//!
//! Producer: the render thread of wins_gl.zig turns X11 events of the game
//! window into calls to `keyEvent`, `mouseMove`, `mouseButton`, `mouseWheel`
//! and `focus`. Consumers: the guest's IDirectInputDevice8 objects, which read
//! the immediate state (GetDeviceState) or a per-device event buffer
//! (GetDeviceData), as DirectInput does.
//!
//! Only GUID_SysKeyboard and GUID_SysMouse exist; joysticks are not
//! enumerated (XInput serves the gamepad). Methods outside the
//! keyboard/mouse contract answer E_NOTIMPL and say so once.

const std = @import("std");
const linux = std.os.linux;

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
const DIERR_NOTBUFFERED: i32 = @bitCast(@as(u32, 0x80040207));
const DIERR_OUTOFMEMORY: i32 = @bitCast(@as(u32, 0x8007000E));

pub const Kind = enum(u8) { keyboard, mouse };

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
        if (d.kind != kind or !d.acquired or d.buffer.len == 0) continue;
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
    acquired: bool = false,
    data_size: u32 = 0,
    absolute: bool = false,
    coop_flags: u32 = 0,
    /// Totals already handed out by GetDeviceState (mouse deltas are per device).
    seen_x: i32 = 0,
    seen_y: i32 = 0,
    seen_z: i32 = 0,
    buffer: []ObjectData = &.{},
    head: usize = 0,
    count: usize = 0,
    overflow: bool = false,
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
    const c = caps orelse return E_POINTER;
    const size = c[0];
    if (size != 24 and size != 44) return DIERR_INVALIDPARAM;
    @memset(std.mem.sliceAsBytes(c[1 .. size / 4]), 0);
    c[1] = 0x1 | 0x4; // DIDC_ATTACHED | DIDC_EMULATED
    if (self(this).kind == .keyboard) {
        c[2] = 0x13 | (4 << 8); // DI8DEVTYPE_KEYBOARD, DI8DEVTYPEKEYBOARD_PCENH
        c[4] = 128;
    } else {
        c[2] = 0x12 | (2 << 8); // DI8DEVTYPE_MOUSE, DI8DEVTYPEMOUSE_TRADITIONAL
        c[3] = 3;
        c[4] = 5;
    }
    return DI_OK;
}

fn dev_EnumObjects(this: *anyopaque, cb: ?*anyopaque, ref: ?*anyopaque, flags: u32) callconv(W) i32 {
    _ = this;
    _ = cb;
    _ = ref;
    _ = flags;
    sayOnce(1, "EnumObjects is not implemented yet", @returnAddress());
    return E_NOTIMPL;
}

/// Predefined properties are passed as small integers (MAKEDIPROP).
const DIPROP_BUFFERSIZE: usize = 1;
const DIPROP_AXISMODE: usize = 2;

fn dev_GetProperty(this: *anyopaque, prop: usize, ph: ?[*]u32) callconv(W) i32 {
    const d = self(this);
    const h = ph orelse return E_POINTER;
    switch (prop) {
        DIPROP_BUFFERSIZE => h[4] = @intCast(d.buffer.len),
        DIPROP_AXISMODE => h[4] = @intFromBool(d.absolute),
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
        DIPROP_AXISMODE => d.absolute = h[4] == 1,
        else => {
            sayOnce(3, "SetProperty for an unsupported property (ignored)", @returnAddress());
        },
    }
    return DI_OK;
}

fn dev_Acquire(this: *anyopaque) callconv(W) i32 {
    const d = self(this);
    sayOnce(10 + @as(u5, @intCast(@intFromEnum(d.kind))), "Acquire", @returnAddress());
    if (d.data_size == 0) return DIERR_INVALIDPARAM; // no data format yet
    if (d.acquired) return DI_NOEFFECT;
    lock();
    d.acquired = true;
    d.head = 0;
    d.count = 0;
    unlock();
    d.seen_x = g_mouse_x.load(.monotonic);
    d.seen_y = g_mouse_y.load(.monotonic);
    d.seen_z = g_mouse_z.load(.monotonic);
    return DI_OK;
}

fn dev_Unacquire(this: *anyopaque) callconv(W) i32 {
    const d = self(this);
    sayOnce(12 + @as(u5, @intCast(@intFromEnum(d.kind))), "Unacquire", @returnAddress());
    if (!d.acquired) return DI_NOEFFECT;
    lock();
    d.acquired = false;
    unlock();
    return DI_OK;
}

fn dev_GetDeviceState(this: *anyopaque, cb: u32, data: ?[*]u8) callconv(W) i32 {
    const d = self(this);
    const out = data orelse return E_POINTER;
    sayOnce(14 + @as(u5, @intCast(@intFromEnum(d.kind))), "GetDeviceState", @returnAddress());
    if (!d.acquired) return DIERR_NOTACQUIRED;
    if (cb != d.data_size) return DIERR_INVALIDPARAM;
    switch (d.kind) {
        .keyboard => for (0..256) |k| {
            out[k] = g_keys[k].load(.monotonic);
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
            const buttons = g_buttons.load(.monotonic);
            for (0..cb - 12) |i| out[12 + i] = if (i < 5 and (buttons >> @intCast(i)) & 1 != 0) 0x80 else 0;
        },
    }
    return DI_OK;
}

fn dev_GetDeviceData(this: *anyopaque, cb: u32, rgdod: ?[*]ObjectData, inout: ?*u32, flags: u32) callconv(W) i32 {
    const d = self(this);
    const n_ptr = inout orelse return E_POINTER;
    sayOnce(16 + @as(u5, @intCast(@intFromEnum(d.kind))), "GetDeviceData", @returnAddress());
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
/// The standard formats (c_dfDIKeyboard 256, c_dfDIMouse 16, c_dfDIMouse2 20)
/// are recognised by their data size; their object layout is the standard one.
fn dev_SetDataFormat(this: *anyopaque, fmt: ?[*]const u32) callconv(W) i32 {
    const d = self(this);
    const f = fmt orelse return E_POINTER;
    if (d.acquired) return @bitCast(@as(u32, 0x8007001E)); // DIERR_ACQUIRED
    const size = f[3];
    const ok = switch (d.kind) {
        .keyboard => size == 256,
        .mouse => size == 16 or size == 20,
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
    if (wide) {
        for (name, 0..) |ch, i| {
            dst[i * 2] = ch;
            dst[i * 2 + 1] = 0;
        }
    } else @memcpy(dst[0..name.len], name);
}

/// DIDEVICEINSTANCE{A,W}: dwSize, guidInstance, guidProduct, dwDevType,
/// tszInstanceName[260], tszProductName[260], guidFFDriver, wUsagePage, wUsage.
fn dev_GetDeviceInfo(this: *anyopaque, raw: ?[*]u8) callconv(W) i32 {
    const d = self(this);
    const p = raw orelse return E_POINTER;
    const size = std.mem.readInt(u32, p[0..4], .little);
    const char_size: usize = if (d.wide) 2 else 1;
    const full: u32 = @intCast(4 + 16 + 16 + 4 + 520 * char_size + 16 + 4);
    if (size != full and size != full - 20) return DIERR_INVALIDPARAM;
    @memset(p[4..size], 0);
    const guid = if (d.kind == .keyboard) &GUID_SysKeyboard else &GUID_SysMouse;
    @memcpy(p[4..20], std.mem.asBytes(guid));
    @memcpy(p[20..36], std.mem.asBytes(guid));
    const dev_type: u32 = if (d.kind == .keyboard) 0x13 | (4 << 8) else 0x12 | (2 << 8);
    std.mem.writeInt(u32, p[36..40], dev_type, .little);
    const name = if (d.kind == .keyboard) "Keyboard" else "Mouse";
    fillName(p[40 .. 40 + 260 * char_size], d.wide, name);
    fillName(p[40 + 260 * char_size .. 40 + 520 * char_size], d.wide, name);
    if (size == full) {
        const u = 40 + 520 * char_size + 16;
        std.mem.writeInt(u16, p[u..][0..2], 1, .little); // HID usage page: generic desktop
        std.mem.writeInt(u16, p[u + 2 ..][0..2], if (d.kind == .keyboard) 6 else 2, .little);
    }
    return DI_OK;
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
    sayOnce(6, "a force-feedback/effect-file method (keyboard and mouse have none)", @returnAddress());
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
    if (!self(this).acquired) return DIERR_NOTACQUIRED;
    return DI_NOEFFECT; // keyboard and mouse are interrupt-driven
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

/// IDirectInput8::CreateDevice for the system keyboard and mouse.
pub fn createDevice(guid: ?*align(1) const GUID, wide: bool, out: *?*anyopaque) i32 {
    out.* = null;
    const g = guid orelse return E_POINTER;
    const kind: Kind = if (guidEql(g, &GUID_SysKeyboard)) .keyboard else if (guidEql(g, &GUID_SysMouse)) .mouse else {
        std.debug.print("[WINS:DInput] CreateDevice({x:0>8}-...): only the system keyboard and mouse exist\n", .{g.d1});
        return DIERR_DEVICENOTREG;
    };
    const d = std.heap.page_allocator.create(Device) catch return DIERR_OUTOFMEMORY;
    d.* = .{ .vtbl = &g_vtbl, .ref_count = 1, .kind = kind, .wide = wide };
    lock();
    defer unlock();
    for (&g_devices) |*slot| {
        if (slot.* == null) {
            slot.* = d;
            std.debug.print("[WINS:DInput] CreateDevice({s}) -> 0x{x}\n", .{ @tagName(kind), @intFromPtr(d) });
            out.* = d;
            return DI_OK;
        }
    }
    std.heap.page_allocator.destroy(d);
    return DIERR_OUTOFMEMORY;
}

pub fn isSystemDeviceGuid(guid: ?*align(1) const GUID) bool {
    const g = guid orelse return false;
    return guidEql(g, &GUID_SysKeyboard) or guidEql(g, &GUID_SysMouse);
}

// ---- tests --------------------------------------------------------------------

fn testCreate(kind: Kind) !*Device {
    var out: ?*anyopaque = null;
    try std.testing.expectEqual(DI_OK, createDevice(if (kind == .keyboard) &GUID_SysKeyboard else &GUID_SysMouse, false, &out));
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
