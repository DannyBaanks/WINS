//! WINS Win64 keyboard input path (input team, new file wins_input64_kbd.zig).
//!
//! Bridges host X11 key events to the Win32 model the game expects:
//!   * X11 keycode -> X keysym -> Windows virtual-key code (VK_*), which is
//!     what WM_KEYDOWN/WM_KEYUP `wParam` must carry (Unity maps wParam VK ->
//!     KeyCode; the raw X11 keycode is NOT a VK).
//!   * A Win32 key-state table behind GetKeyState / GetAsyncKeyState
//!     (0x8000 = down, 0x0001 = toggled / pressed-since-last-call).
//!   * WM_CHAR generation data for TranslateMessage.
//!
//! Linux/X11 side only; imported from winrun_gui_support.zig, which is built
//! only in the gui loader (-lc -lX11), so the extern "X11" decls are fine.
//! The console winrun.zig never imports this file.

const std = @import("std");
const x11 = @import("x11_window.zig");

extern "X11" fn XKeycodeToKeysym(display: ?*anyopaque, keycode: c_uint, index: c_int) c_ulong;

const X_SHIFT_MASK: c_uint = 0x0001;
const X_LOCK_MASK: c_uint = 0x0002;

pub const VK_SHIFT: u8 = 0x10;
pub const VK_CONTROL: u8 = 0x11;
pub const VK_MENU: u8 = 0x12;

/// X keysym -> Windows virtual key (US-style OEM mapping, as Windows assigns
/// VKs for the punctuation keys). Case-insensitive for letters: both 'a' and
/// 'A' keysyms map to VK 'A' (0x41); the shift state produces the character,
/// not a different VK.
pub fn vkFromKeysym(ks: c_ulong) u8 {
    if (ks >= 'a' and ks <= 'z') return @intCast(ks - 'a' + 'A');
    if (ks >= 'A' and ks <= 'Z') return @intCast(ks);
    if (ks >= '0' and ks <= '9') return @intCast(ks);
    if (ks >= 0xffbe and ks <= 0xffc9) return @intCast(0x70 + (ks - 0xffbe)); // F1..F12
    if (ks >= 0xffb0 and ks <= 0xffb9) return @intCast(0x60 + (ks - 0xffb0)); // keypad 0..9
    if (ks >= 0xff80 and ks <= 0xffbd) return @intCast(0x60 + (ks - 0xff80)); // KP 0..9 alt range (defensive)
    return switch (ks) {
        0x20 => 0x20, // Space
        0xff08 => 0x08, // BackSpace
        0xff09 => 0x09, // Tab
        0xff0d, 0xff8d => 0x0D, // Return, KP_Enter
        0xff1b => 0x1B, // Escape
        0xff13 => 0x13, // Pause
        0xff14 => 0x14, // Scroll_Lock (some servers)
        0xff50 => 0x24, // Home
        0xff51 => 0x25, // Left
        0xff52 => 0x26, // Up
        0xff53 => 0x27, // Right
        0xff54 => 0x28, // Down
        0xff55 => 0x21, // Prior (PageUp)
        0xff56 => 0x22, // Next (PageDown)
        0xff57 => 0x23, // End
        0xff63 => 0x2D, // Insert
        0xffff => 0x2E, // Delete
        0xffe1 => 0xA0, // Shift_L
        0xffe2 => 0xA1, // Shift_R
        0xffe3 => 0xA2, // Control_L
        0xffe4 => 0xA3, // Control_R
        0xffe9, 0xff7e => 0xA4, // Alt_L, KP_00-ish AltGr stand-ins
        0xffea, 0xfe03 => 0xA5, // Alt_R / ISO_Level3_Shift (AltGr)
        0xffe5 => 0x14, // Caps_Lock
        0xffe7, 0xffe8 => 0x5B, // Meta_L/R -> VK_LWIN
        0xffeb => 0x5B, // Super_L
        0xffec => 0x5C, // Super_R
        0xff67 => 0x5D, // Menu (Apps)
        0xffaa => 0x6A, // KP_Multiply
        0xffab => 0x6B, // KP_Add
        0xffac => 0x6C, // KP_Separator
        0xffad => 0x6D, // KP_Subtract
        0xffae => 0x6E, // KP_Decimal
        0xffaf => 0x6F, // KP_Divide
        0xffb1 => 0x61, // KP_1 .. handled above by 0xffb0 range; kept defensive
        // Unshifted OEM punctuation (US layout VKs).
        ';' => 0xBA,
        '=' => 0xBB,
        ',' => 0xBC,
        '-' => 0xBD,
        '.' => 0xBE,
        '/' => 0xBF,
        '`' => 0xC0,
        '[' => 0xDB,
        '\\' => 0xDC,
        ']' => 0xDD,
        '\'' => 0xDE,
        0xf1, 0xd1 => 0xC0, // ntilde/Ntilde (Spanish layout OEM_3 key)
        // Shifted punctuation keysyms -> VK of the base key (Windows semantics:
        // ':' is VK_OEM_1, not its own VK).
        '!' => 0x31,
        '@' => 0x32,
        '#' => 0x33,
        '$' => 0x34,
        '%' => 0x35,
        '^' => 0x36,
        '&' => 0x37,
        '*' => 0x38,
        '(' => 0x39,
        ')' => 0x30,
        '_' => 0xBD,
        '+' => 0xBB,
        '{' => 0xDB,
        '}' => 0xDD,
        '|' => 0xDC,
        ':' => 0xBA,
        '"' => 0xDE,
        '~' => 0xC0,
        '<' => 0xBC,
        '>' => 0xBE,
        '?' => 0xBF,
        else => 0,
    };
}

// ---- Win32 virtual-key state table -----------------------------------------

var g_vk_down: [256]std.atomic.Value(bool) = [_]std.atomic.Value(bool){std.atomic.Value(bool).init(false)} ** 256;
var g_vk_pressed_since: [256]std.atomic.Value(bool) = [_]std.atomic.Value(bool){std.atomic.Value(bool).init(false)} ** 256;
var g_vk_toggled: [256]std.atomic.Value(bool) = [_]std.atomic.Value(bool){std.atomic.Value(bool).init(false)} ** 256;

/// Record a VK down/up transition, merging the left/right pairs into the
/// generic VK_SHIFT/VK_CONTROL/VK_MENU like Windows does.
/// Lock keys flip the toggle bit on each down (CapsLock/NumLock/ScrollLock).
fn isLockKey(vk: u8) bool {
    return vk == 0x14 or vk == 0x90 or vk == 0x91;
}

pub fn feedKey(vk: u8, down: bool) void {
    const idx: usize = vk;
    const was = g_vk_down[idx].swap(down, .monotonic);
    if (down and !was) {
        g_vk_pressed_since[idx].store(true, .monotonic);
        if (isLockKey(vk)) {
            const prev_tog = g_vk_toggled[idx].load(.monotonic);
            g_vk_toggled[idx].store(!prev_tog, .monotonic);
        }
    }
    const generic: usize = switch (vk) {
        0xA0, 0xA1 => VK_SHIFT,
        0xA2, 0xA3 => VK_CONTROL,
        0xA4, 0xA5 => VK_MENU,
        else => 0,
    };
    if (generic != 0) {
        const other: usize = idx ^ 1;
        const g_down = down or g_vk_down[other].load(.monotonic);
        const g_was = g_vk_down[generic].swap(g_down, .monotonic);
        if (g_down and !g_was) {
            g_vk_pressed_since[generic].store(true, .monotonic);
            // modifiers are not lock keys; the toggle bit stays as-is
        }
    }
}

/// Translate one X11 key event to a VK and update the key-state table.
/// Returns 0 when the keysym has no VK mapping (caller may fall back to the
/// raw keycode to preserve the old behaviour for exotic keys).
pub fn handleKeyEvent(conn: *const x11.Connection, ke: *const x11.XKeyEvent, down: bool) u8 {
    const shift = (ke.state & X_SHIFT_MASK) != 0;
    const lock = (ke.state & X_LOCK_MASK) != 0;
    // index 1 = shifted column; letters come out as 'A'..'Z' there, which
    // vkFromKeysym maps to the same VK as the unshifted letter.
    const ks = XKeycodeToKeysym(@ptrCast(conn.display), ke.keycode, if (shift) 1 else 0);
    var vk = vkFromKeysym(ks);
    if (vk == 0 and shift) vk = vkFromKeysym(XKeycodeToKeysym(@ptrCast(conn.display), ke.keycode, 0));
    _ = lock; // CapsLock affects the character, not the VK; handled in charForVk.
    if (vk != 0) feedKey(vk, down);
    return vk;
}

/// GetKeyState: high bit = currently down, low bit = toggled (CapsLock/NumLock).
pub fn getKeyState(nVirtKey: i32) i16 {
    if (nVirtKey < 0 or nVirtKey >= 256) return 0;
    const idx: usize = @intCast(nVirtKey);
    var res: u16 = if (g_vk_down[idx].load(.monotonic)) 0x8000 else 0;
    if (g_vk_toggled[idx].load(.monotonic)) res |= 0x0001;
    return @bitCast(res);
}

/// GetAsyncKeyState: high bit = down since last call OR now, low bit = pressed
/// since the last call (consumed here, as Windows does).
pub fn getAsyncKeyState(vKey: i32) i16 {
    if (vKey < 0 or vKey >= 256) return 0;
    const idx: usize = @intCast(vKey);
    var res: u16 = if (g_vk_down[idx].load(.monotonic)) 0x8000 else 0;
    if (g_vk_pressed_since[idx].swap(false, .monotonic)) res |= 0x0001;
    return @bitCast(res);
}

pub fn isShiftDown() bool {
    return g_vk_down[VK_SHIFT].load(.monotonic);
}

/// VKs that carry the "extended key" (E0) flag in a RawInput/keyboard lParam.
pub fn isExtendedVk(vk: u8) bool {
    return switch (vk) {
        0xA1, 0xA3, 0xA5 => true, // VK_RSHIFT, VK_RCONTROL, VK_RMENU
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 => true, // PgUp PgDn End Home arrows
        0x2C, 0x2D, 0x2E => true, // Snapshot, Insert, Delete
        0x6F, 0x90 => true, // VK_DIVIDE, VK_NUMLOCK
        else => false,
    };
}

/// Character produced by a VK for WM_CHAR (0 = no character, e.g. arrows).
/// `shift` and `caps` come from the live key-state table.
pub fn charForVk(vk: u8, shift: bool, caps: bool) u16 {
    if (vk >= 0x41 and vk <= 0x5A) { // A..Z
        const upper = shift != caps;
        return @intCast(if (upper) vk else vk + 0x20);
    }
    if (vk >= 0x30 and vk <= 0x39) { // 0..9
        const shifted = [_]u16{ ')', '!', '@', '#', '$', '%', '^', '&', '*', '(' };
        return if (shift) shifted[vk - 0x30] else @intCast(vk);
    }
    return switch (vk) {
        0x20 => ' ',
        0x08 => 0x08,
        0x09 => 0x09,
        0x0D => 0x0D,
        0xBA => if (shift) ':' else ';',
        0xBB => if (shift) '+' else '=',
        0xBC => if (shift) '<' else ',',
        0xBD => if (shift) '_' else '-',
        0xBE => if (shift) '>' else '.',
        0xBF => if (shift) '?' else '/',
        0xC0 => if (shift) '~' else '`',
        0xDB => if (shift) '{' else '[',
        0xDC => if (shift) '|' else '\\',
        0xDD => if (shift) '}' else ']',
        0xDE => if (shift) '"' else '\'',
        0x6A => '*',
        0x6B => '+',
        0x6D => '-',
        0x6E => '.',
        0x6F => '/',
        else => 0,
    };
}

pub fn resetKeyStateForTest() void {
    for (&g_vk_down) |*v| v.store(false, .monotonic);
    for (&g_vk_pressed_since) |*v| v.store(false, .monotonic);
    for (&g_vk_toggled) |*v| v.store(false, .monotonic);
}

// ---- tests -------------------------------------------------------------------

test "vkFromKeysym maps letters, digits, OEM keys, arrows, modifiers" {
    try std.testing.expectEqual(@as(u8, 0x41), vkFromKeysym('a'));
    try std.testing.expectEqual(@as(u8, 0x41), vkFromKeysym('A'));
    try std.testing.expectEqual(@as(u8, 0x35), vkFromKeysym('5'));
    try std.testing.expectEqual(@as(u8, 0x0D), vkFromKeysym(0xff0d)); // Return
    try std.testing.expectEqual(@as(u8, 0x25), vkFromKeysym(0xff51)); // Left
    try std.testing.expectEqual(@as(u8, 0xA0), vkFromKeysym(0xffe1)); // Shift_L
    try std.testing.expectEqual(@as(u8, 0xBA), vkFromKeysym(';'));
    try std.testing.expectEqual(@as(u8, 0xBA), vkFromKeysym(':')); // shifted -> same VK
    try std.testing.expectEqual(@as(u8, 0x31), vkFromKeysym('!'));
    try std.testing.expectEqual(@as(u8, 0x00), vkFromKeysym(0xdeadbeef));
}

test "feedKey drives GetKeyState/GetAsyncKeyState with L/R merge and toggle" {
    resetKeyStateForTest();
    try std.testing.expectEqual(@as(i16, 0), getKeyState(0x41));
    feedKey(0x41, true);
    try std.testing.expect(getKeyState(0x41) < 0);
    try std.testing.expectEqual(@as(i16, @bitCast(@as(u16, 0x8001))), getAsyncKeyState(0x41)); // down + pressed-since
    try std.testing.expectEqual(@as(i16, @bitCast(@as(u16, 0x8000))), getAsyncKeyState(0x41)); // pressed bit consumed
    feedKey(0x41, false);
    try std.testing.expectEqual(@as(i16, 0), getKeyState(0x41));

    // Left shift feeds VK_SHIFT; releasing it while right is held keeps it down.
    feedKey(0xA0, true);
    try std.testing.expect(getKeyState(VK_SHIFT) < 0);
    feedKey(0xA1, true);
    feedKey(0xA0, false);
    try std.testing.expect(getKeyState(VK_SHIFT) < 0);
    feedKey(0xA1, false);
    try std.testing.expectEqual(@as(i16, 0), getKeyState(VK_SHIFT));

    // CapsLock toggles the low bit.
    feedKey(0x14, true);
    try std.testing.expectEqual(@as(i16, @bitCast(@as(u16, 0x8001))), getKeyState(0x14));
    feedKey(0x14, false);
    try std.testing.expectEqual(@as(i16, 0x0001), getKeyState(0x14));
    resetKeyStateForTest();
}

test "charForVk honours shift and caps" {
    try std.testing.expectEqual(@as(u16, 'a'), charForVk(0x41, false, false));
    try std.testing.expectEqual(@as(u16, 'A'), charForVk(0x41, true, false));
    try std.testing.expectEqual(@as(u16, 'A'), charForVk(0x41, false, true));
    try std.testing.expectEqual(@as(u16, 'a'), charForVk(0x41, true, true));
    try std.testing.expectEqual(@as(u16, '5'), charForVk(0x35, false, false));
    try std.testing.expectEqual(@as(u16, '%'), charForVk(0x35, true, false));
    try std.testing.expectEqual(@as(u16, ';'), charForVk(0xBA, false, false));
    try std.testing.expectEqual(@as(u16, ':'), charForVk(0xBA, true, false));
    try std.testing.expectEqual(@as(u16, 0), charForVk(0x25, false, false)); // Left: no char
}
