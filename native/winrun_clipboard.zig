//! Win32 clipboard for winrun64 GUI apps, backed by the X11 CLIPBOARD selection.
//!
//! In-process it behaves like USER32: Open/Empty/Set/Close, the clipboard owns the
//! HGLOBALs handed to SetClipboardData, CF_TEXT <-> CF_UNICODETEXT are synthesized.
//! Text written by the app is published as CLIPBOARD (UTF8_STRING, CRLF -> LF);
//! when another X client owns CLIPBOARD, text formats are fetched from it on demand.
//! Not implemented: delayed rendering (WM_RENDERFORMAT), INCR transfers (> ~16 MB),
//! non-text formats across processes, clipboard viewers/listeners.
const std = @import("std");
const x11 = @import("x11_window.zig");
const k32 = @import("winrun_kernel32.zig");

pub const CF_TEXT: u32 = 1;
pub const CF_OEMTEXT: u32 = 7;
pub const CF_UNICODETEXT: u32 = 13;

const Entry = struct { fmt: u32, hmem: usize };
var entries: [16]Entry = undefined;
var count: usize = 0;
var is_open = false;
var changed = false; // EmptyClipboard/SetClipboardData since OpenClipboard
var x_owner = false; // our data is the current X CLIPBOARD
var x_window: x11.Window = 0; // window we own CLIPBOARD with / receive data on

var atoms_ready = false;
var a_clipboard: x11.Atom = 0;
var a_targets: x11.Atom = 0;
var a_utf8: x11.Atom = 0;
var a_text: x11.Atom = 0;
var a_mime_utf8: x11.Atom = 0;
var a_mime: x11.Atom = 0;
var a_prop: x11.Atom = 0;

fn initAtoms(conn: x11.Connection) void {
    if (atoms_ready) return;
    a_clipboard = conn.atom("CLIPBOARD");
    a_targets = conn.atom("TARGETS");
    a_utf8 = conn.atom("UTF8_STRING");
    a_text = conn.atom("TEXT");
    a_mime_utf8 = conn.atom("text/plain;charset=utf-8");
    a_mime = conn.atom("text/plain");
    a_prop = conn.atom("WINS_CLIPBOARD");
    atoms_ready = true;
}

fn isText(fmt: u32) bool {
    return fmt == CF_TEXT or fmt == CF_OEMTEXT or fmt == CF_UNICODETEXT;
}

fn find(fmt: u32) ?*Entry {
    for (entries[0..count]) |*e| if (e.fmt == fmt) return e;
    return null;
}

fn freeAll() void {
    for (entries[0..count]) |e| if (e.hmem != 0) {
        _ = k32.GlobalFree(@ptrFromInt(e.hmem));
    };
    count = 0;
}

fn put(fmt: u32, hmem: usize) void {
    if (find(fmt)) |e| {
        if (e.hmem != 0 and e.hmem != hmem) _ = k32.GlobalFree(@ptrFromInt(e.hmem));
        e.hmem = hmem;
        return;
    }
    if (count == entries.len) return;
    entries[count] = .{ .fmt = fmt, .hmem = hmem };
    count += 1;
}

fn globalBytes(hmem: usize) []u8 {
    if (hmem == 0) return &.{};
    const n = k32.GlobalSize(hmem);
    const p: [*]u8 = @ptrFromInt(hmem);
    return p[0..n];
}

fn newGlobal(bytes: []const u8) usize {
    const p = k32.GlobalAlloc(0x42, bytes.len) orelse return 0; // GMEM_MOVEABLE|GMEM_ZEROINIT
    const dst: [*]u8 = @ptrCast(p);
    @memcpy(dst[0..bytes.len], bytes);
    return @intFromPtr(p);
}

/// UTF-16 text of the clipboard (up to its NUL), or null.
fn unicodeText() ?[]const u16 {
    const e = find(CF_UNICODETEXT) orelse return null;
    const b = globalBytes(e.hmem);
    const w: [*]const u16 = @ptrCast(@alignCast(b.ptr));
    const n = b.len / 2;
    const end = std.mem.indexOfScalar(u16, w[0..n], 0) orelse n;
    return w[0..end];
}

fn ansiText() ?[]const u8 {
    const e = find(CF_TEXT) orelse find(CF_OEMTEXT) orelse return null;
    const b = globalBytes(e.hmem);
    return b[0 .. std.mem.indexOfScalar(u8, b, 0) orelse b.len];
}

/// Windows synthesizes the other text format on request.
fn synthesize(fmt: u32) void {
    if (find(fmt) != null) return;
    const gpa = std.heap.page_allocator;
    if (fmt == CF_UNICODETEXT) {
        const a = ansiText() orelse return;
        const w = gpa.alloc(u16, a.len + 1) catch return;
        defer gpa.free(w);
        for (a, 0..) |c, i| w[i] = c; // Latin-1 -> UTF-16
        w[a.len] = 0;
        put(fmt, newGlobal(std.mem.sliceAsBytes(w)));
    } else if (fmt == CF_TEXT or fmt == CF_OEMTEXT) {
        const u = unicodeText() orelse return;
        const a = gpa.alloc(u8, u.len + 1) catch return;
        defer gpa.free(a);
        for (u, 0..) |c, i| a[i] = if (c < 0x100) @truncate(c) else '?';
        a[u.len] = 0;
        put(fmt, newGlobal(a));
    }
}

// ---------------------------------------------------------------- X11 side

/// UTF-8 of the clipboard text with CRLF -> LF (what Linux apps expect).
fn textAsUtf8(gpa: std.mem.Allocator) ?[]u8 {
    var out: std.ArrayList(u8) = .empty;
    if (unicodeText()) |u| {
        var i: usize = 0;
        while (i < u.len) : (i += 1) {
            var cp: u21 = u[i];
            if (cp >= 0xD800 and cp < 0xDC00 and i + 1 < u.len and u[i + 1] >= 0xDC00 and u[i + 1] < 0xE000) {
                cp = 0x10000 + ((@as(u21, u[i] - 0xD800) << 10) | (u[i + 1] - 0xDC00));
                i += 1;
            } else if (cp >= 0xD800 and cp < 0xE000) cp = 0xFFFD;
            if (cp == '\r' and i + 1 < u.len and u[i + 1] == '\n') continue;
            var buf: [4]u8 = undefined;
            const n = std.unicode.utf8Encode(cp, &buf) catch continue;
            out.appendSlice(gpa, buf[0..n]) catch return null;
        }
    } else if (ansiText()) |a| {
        for (a, 0..) |c, i| {
            if (c == '\r' and i + 1 < a.len and a[i + 1] == '\n') continue;
            var buf: [4]u8 = undefined;
            const n = std.unicode.utf8Encode(c, &buf) catch continue;
            out.appendSlice(gpa, buf[0..n]) catch return null;
        }
    } else return null;
    return out.toOwnedSlice(gpa) catch null;
}

/// Answer another X client's request for our CLIPBOARD data.
pub fn handleSelectionRequest(conn: x11.Connection, req: *const x11.XSelectionRequestEvent) void {
    initAtoms(conn);
    const prop = if (req.property != 0) req.property else req.target; // obsolete clients
    var ok = false;
    if (x_owner and req.selection == a_clipboard) {
        if (req.target == a_targets) {
            const list = [_]x11.Atom{ a_targets, a_utf8, a_mime_utf8, a_text, a_mime, x11.XA_STRING };
            conn.setPropertyAtoms(req.requestor, prop, &list);
            ok = true;
        } else if (req.target == a_utf8 or req.target == a_mime_utf8 or req.target == a_text or req.target == a_mime or req.target == x11.XA_STRING) {
            const gpa = std.heap.page_allocator;
            if (textAsUtf8(gpa)) |utf8| {
                defer gpa.free(utf8);
                if (req.target == x11.XA_STRING) { // ICCCM STRING is Latin-1
                    var latin: std.ArrayList(u8) = .empty;
                    defer latin.deinit(gpa);
                    var it = std.unicode.Utf8View.initUnchecked(utf8).iterator();
                    while (it.nextCodepoint()) |cp| latin.append(gpa, if (cp < 0x100) @truncate(cp) else '?') catch break;
                    conn.setProperty8(req.requestor, prop, x11.XA_STRING, latin.items);
                } else conn.setProperty8(req.requestor, prop, if (req.target == a_text) a_utf8 else req.target, utf8);
                ok = true;
            }
        }
    }
    conn.sendSelectionNotify(req, if (ok) prop else 0);
}

pub fn handleSelectionClear(conn: x11.Connection, selection: x11.Atom) void {
    initAtoms(conn);
    if (selection == a_clipboard) x_owner = false;
}

fn publish(conn: x11.Connection, win: x11.Window) void {
    initAtoms(conn);
    if (win == 0) return;
    x_window = win;
    conn.setSelectionOwner(a_clipboard, win);
    x_owner = conn.selectionOwner(a_clipboard) == win;
}

/// Fetch text from the current X CLIPBOARD owner into the clipboard (CF_UNICODETEXT).
fn fetch(conn: x11.Connection, win: x11.Window) void {
    initAtoms(conn);
    if (x_owner or win == 0) return;
    const owner = conn.selectionOwner(a_clipboard);
    if (owner == 0) return; // nobody owns CLIPBOARD: keep what we have
    freeAll();
    const gpa = std.heap.page_allocator;
    const targets = [_]x11.Atom{ a_utf8, x11.XA_STRING };
    for (targets) |target| {
        conn.convertSelection(a_clipboard, target, a_prop, win);
        var ev: x11.XEvent = undefined;
        var got = false;
        var waited: u32 = 0;
        while (waited < 1000) : (waited += 5) { // owner answers in ms; give up after 1 s
            if (conn.takeTypedEvent(win, x11.SelectionNotify, &ev)) {
                got = true;
                break;
            }
            const req: std.os.linux.timespec = .{ .sec = 0, .nsec = 5 * std.time.ns_per_ms };
            _ = std.os.linux.nanosleep(&req, null);
        }
        if (!got) return;
        const se: *const x11.XSelectionEvent = @ptrCast(&ev);
        if (se.property == 0) continue; // owner refused this target: try the next
        const p = conn.takeProperty8(gpa, win, a_prop) orelse continue;
        defer gpa.free(p.data);
        var w: std.ArrayList(u16) = .empty;
        defer w.deinit(gpa);
        if (target == a_utf8) {
            var it = (std.unicode.Utf8View.init(p.data) catch continue).iterator();
            while (it.nextCodepoint()) |cp| {
                if (cp == '\n') w.append(gpa, '\r') catch return;
                if (cp >= 0x10000) {
                    const v = cp - 0x10000;
                    w.append(gpa, @intCast(0xD800 + (v >> 10))) catch return;
                    w.append(gpa, @intCast(0xDC00 + (v & 0x3ff))) catch return;
                } else w.append(gpa, @intCast(cp)) catch return;
            }
        } else for (p.data) |c| {
            if (c == '\n') w.append(gpa, '\r') catch return;
            w.append(gpa, c) catch return;
        }
        w.append(gpa, 0) catch return;
        put(CF_UNICODETEXT, newGlobal(std.mem.sliceAsBytes(w.items)));
        return;
    }
}

// ---------------------------------------------------------------- Win32 API
// `conn`/`win`: the app's X connection and one of its X windows (null/0 when headless:
// the clipboard then stays in-process).

pub fn open(conn: ?x11.Connection, win: x11.Window) bool {
    if (is_open) return false;
    is_open = true;
    changed = false;
    if (conn) |c| fetch(c, win);
    return true;
}

pub fn close(conn: ?x11.Connection, win: x11.Window) bool {
    if (!is_open) return false;
    is_open = false;
    if (changed) if (conn) |c| publish(c, win);
    return true;
}

pub fn empty() bool {
    if (!is_open) return false;
    freeAll();
    changed = true;
    x_owner = false;
    return true;
}

pub fn set(fmt: u32, hmem: usize) usize {
    if (!is_open) return 0;
    put(fmt, hmem);
    changed = true;
    return if (hmem != 0) hmem else 1; // delayed rendering: non-null "success"
}

pub fn get(fmt: u32) usize {
    if (!is_open) return 0;
    if (isText(fmt)) synthesize(fmt);
    const e = find(fmt) orelse return 0;
    return e.hmem;
}

/// Works without OpenClipboard, as on Windows. Text is assumed available while
/// another X client owns CLIPBOARD (checked for real on OpenClipboard).
pub fn available(conn: ?x11.Connection, fmt: u32) bool {
    if (find(fmt) != null) return true;
    if (isText(fmt)) {
        for (entries[0..count]) |e| if (isText(e.fmt)) return true;
        if (!x_owner) if (conn) |c| {
            initAtoms(c);
            return c.selectionOwner(a_clipboard) != 0;
        };
    }
    return false;
}

// ------------------------------------------------- registered formats (0xC000+)
var fmt_names: [64][64]u16 = undefined;
var fmt_count: usize = 0;

pub fn registerFormat(name: ?[*:0]const u16) u32 {
    const n = name orelse return 0;
    const s = std.mem.span(n);
    if (s.len == 0 or s.len >= 64) return 0;
    for (fmt_names[0..fmt_count], 0..) |*e, i| {
        const len = std.mem.indexOfScalar(u16, e, 0) orelse 64;
        if (len == s.len and eqlIgnoreCase(e[0..len], s)) return @intCast(0xC000 + i);
    }
    if (fmt_count == fmt_names.len) return 0;
    @memset(&fmt_names[fmt_count], 0);
    @memcpy(fmt_names[fmt_count][0..s.len], s);
    fmt_count += 1;
    return @intCast(0xC000 + fmt_count - 1);
}

fn eqlIgnoreCase(a: []const u16, b: []const u16) bool {
    for (a, b) |x, y| {
        const lx = if (x >= 'A' and x <= 'Z') x + 32 else x;
        const ly = if (y >= 'A' and y <= 'Z') y + 32 else y;
        if (lx != ly) return false;
    }
    return true;
}

test "registered formats are distinct and case-insensitive" {
    const a = registerFormat(std.unicode.utf8ToUtf16LeStringLiteral("MSDEVColumnSelect"));
    const b = registerFormat(std.unicode.utf8ToUtf16LeStringLiteral("MSDEVLineSelect"));
    const c = registerFormat(std.unicode.utf8ToUtf16LeStringLiteral("msdevcolumnselect"));
    try std.testing.expect(a >= 0xC000 and b >= 0xC000);
    try std.testing.expect(a != b);
    try std.testing.expectEqual(a, c);
}
