//! WINS wins_user32: the USER32 window manager for the i386 loader.
//!
//! The loader used to answer the window surface with constants: CreateWindowExA
//! returned HWND 0x20001 for every window, GetActiveWindow returned 0x10002,
//! PeekMessageA never had a message and no window procedure was ever called.
//! FalloutNV's main loop pumps messages and then sleeps while
//! `GetActiveWindow() != its hwnd`, so it slept at 20 Hz forever.
//!
//! This module implements the Win32 semantics in-process:
//!  - window classes (RegisterClass/Ex, Unregister, GetClassLong, GetClassName),
//!  - a window table with real HWNDs, styles, rectangles, text, extra bytes and
//!    parent/owner links, created through the window procedure exactly as
//!    Win32 does it (GETMINMAXINFO, NCCREATE, NCCALCSIZE, CREATE, SIZE/MOVE),
//!  - one message queue per thread: posted messages, WM_QUIT, synthesized
//!    WM_PAINT, cross-thread SendMessage that waits for the owner to pump,
//!  - activation, focus and foreground state with the message order Win32
//!    produces (WM_QUERYNEWPALETTE, WM_ACTIVATEAPP, WM_NCACTIVATE, WM_ACTIVATE,
//!    WM_KILLFOCUS / WM_IME_SETCONTEXT / WM_SETFOCUS),
//!  - SetWindowPos / ShowWindow / DestroyWindow with WM_WINDOWPOSCHANGING/
//!    CHANGED, and DefWindowProcA for the messages those depend on.
//! The message order and every return value are pinned against Wine by
//! native/testdata/window_probe.c (run on a bare X server, no WM).
//!
//! Frame metrics are Wine's defaults (border 1, caption 25, small caption 17,
//! menu 18), which is what the probe measured from AdjustWindowRectEx.
//!
//! NOT implemented here, deliberately and visibly:
//!  - no pixels: there is no native surface behind a window yet (D3D9 Present
//!    has nothing to show into); WM_NCPAINT / WM_ERASEBKGND carry a placeholder
//!    HDC that no GDI call accepts;
//!  - keyboard messages come from the host window (wins_gl.zig calls
//!    hostKey): WM_KEYDOWN/WM_KEYUP (WM_SYSKEY* with Alt) go to the focus
//!    window, TranslateMessage turns a key-down into WM_CHAR with the
//!    character the host keyboard layout produced, and GetKeyState /
//!    GetAsyncKeyState read the same state; no mouse messages yet;
//!  - no timers, hooks, menus, dialogs, Unicode (W) entry points, window
//!    properties, DPI, multiple monitors or z-order between sibling windows
//!    beyond "newest on top";
//!  - the foreground belongs to this process until its last active window
//!    goes away; another process's windows are not modelled.

const std = @import("std");
const linux = std.os.linux;
const c = std.c;

pub const W: std.builtin.CallingConvention = .winapi;

pub const WndProc = *const fn (usize, u32, usize, usize) callconv(W) usize;
const EnumProc = *const fn (usize, usize) callconv(W) i32;

/// Set by the loader so errors land in the guest's GetLastError.
pub var g_set_last_error: ?*const fn (u32) void = null;

fn setLastError(e: u32) void {
    if (g_set_last_error) |f| f(e);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const WM_NULL: u32 = 0x0000;
pub const WM_CREATE: u32 = 0x0001;
pub const WM_DESTROY: u32 = 0x0002;
pub const WM_MOVE: u32 = 0x0003;
pub const WM_SIZE: u32 = 0x0005;
pub const WM_ACTIVATE: u32 = 0x0006;
pub const WM_SETFOCUS: u32 = 0x0007;
pub const WM_KILLFOCUS: u32 = 0x0008;
pub const WM_SETTEXT: u32 = 0x000C;
pub const WM_GETTEXT: u32 = 0x000D;
pub const WM_GETTEXTLENGTH: u32 = 0x000E;
pub const WM_PAINT: u32 = 0x000F;
pub const WM_CLOSE: u32 = 0x0010;
pub const WM_QUIT: u32 = 0x0012;
pub const WM_ERASEBKGND: u32 = 0x0014;
pub const WM_SHOWWINDOW: u32 = 0x0018;
pub const WM_ACTIVATEAPP: u32 = 0x001C;
pub const WM_SETCURSOR: u32 = 0x0020;
pub const WM_GETMINMAXINFO: u32 = 0x0024;
pub const WM_WINDOWPOSCHANGING: u32 = 0x0046;
pub const WM_WINDOWPOSCHANGED: u32 = 0x0047;
pub const WM_STYLECHANGING: u32 = 0x007C;
pub const WM_STYLECHANGED: u32 = 0x007D;
pub const WM_GETICON: u32 = 0x007F;
pub const WM_NCCREATE: u32 = 0x0081;
pub const WM_NCDESTROY: u32 = 0x0082;
pub const WM_NCCALCSIZE: u32 = 0x0083;
pub const WM_NCHITTEST: u32 = 0x0084;
pub const WM_NCPAINT: u32 = 0x0085;
pub const WM_NCACTIVATE: u32 = 0x0086;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_KEYUP: u32 = 0x0101;
pub const WM_CHAR: u32 = 0x0102;
pub const WM_SYSKEYDOWN: u32 = 0x0104;
pub const WM_SYSKEYUP: u32 = 0x0105;
pub const WM_SYSCHAR: u32 = 0x0106;
pub const WM_SYSCOMMAND: u32 = 0x0112;
pub const WM_TIMER: u32 = 0x0113;
pub const WM_IME_SETCONTEXT: u32 = 0x0281;
pub const WM_QUERYNEWPALETTE: u32 = 0x030F;

const WS_OVERLAPPED: u32 = 0x00000000;
const WS_POPUP: u32 = 0x80000000;
const WS_CHILD: u32 = 0x40000000;
const WS_MINIMIZE: u32 = 0x20000000;
const WS_VISIBLE: u32 = 0x10000000;
const WS_DISABLED: u32 = 0x08000000;
const WS_CLIPSIBLINGS: u32 = 0x04000000;
const WS_MAXIMIZE: u32 = 0x01000000;
const WS_CAPTION: u32 = 0x00C00000;
const WS_BORDER: u32 = 0x00800000;
const WS_DLGFRAME: u32 = 0x00400000;
const WS_THICKFRAME: u32 = 0x00040000;

const WS_EX_DLGMODALFRAME: u32 = 0x00000001;
const WS_EX_TOPMOST: u32 = 0x00000008;
const WS_EX_TOOLWINDOW: u32 = 0x00000080;
const WS_EX_WINDOWEDGE: u32 = 0x00000100;
const WS_EX_CLIENTEDGE: u32 = 0x00000200;
const WS_EX_STATICEDGE: u32 = 0x00020000;

const SWP_NOSIZE: u32 = 0x0001;
const SWP_NOMOVE: u32 = 0x0002;
const SWP_NOZORDER: u32 = 0x0004;
const SWP_NOREDRAW: u32 = 0x0008;
const SWP_NOACTIVATE: u32 = 0x0010;
const SWP_FRAMECHANGED: u32 = 0x0020;
const SWP_SHOWWINDOW: u32 = 0x0040;
const SWP_HIDEWINDOW: u32 = 0x0080;
const SWP_NOSENDCHANGING: u32 = 0x0400;
const SWP_NOCLIENTSIZE: u32 = 0x0800;
const SWP_NOCLIENTMOVE: u32 = 0x1000;

const HWND_TOP: usize = 0;
const HWND_BOTTOM: usize = 1;
const HWND_TOPMOST: usize = 0xFFFFFFFF; // (HWND)-1
const HWND_NOTOPMOST: usize = 0xFFFFFFFE; // (HWND)-2
const HWND_MESSAGE_FILTER: usize = 0xFFFFFFFF; // PeekMessage: thread messages only
const HWND_BROADCAST: usize = 0xFFFF;

const SW_HIDE: i32 = 0;
const SW_SHOWNORMAL: i32 = 1;
const SW_SHOWMINIMIZED: i32 = 2;
const SW_SHOWMAXIMIZED: i32 = 3;
const SW_SHOWNOACTIVATE: i32 = 4;
const SW_SHOW: i32 = 5;
const SW_MINIMIZE: i32 = 6;
const SW_SHOWMINNOACTIVE: i32 = 7;
const SW_SHOWNA: i32 = 8;
const SW_RESTORE: i32 = 9;
const SW_SHOWDEFAULT: i32 = 10;

const WA_INACTIVE: usize = 0;
const WA_ACTIVE: usize = 1;

const PM_REMOVE: u32 = 0x0001;
const CW_USEDEFAULT: i32 = @bitCast(@as(u32, 0x80000000));
const ISC_SHOWUIALL: usize = 0xC000000F;
const ICON_SMALL: usize = 0;
const ICON_BIG: usize = 1;
const SIZE_RESTORED: usize = 0;
const HTCLIENT: usize = 1;
const SC_CLOSE: usize = 0xF060;

const ERROR_INVALID_WINDOW_HANDLE: u32 = 1400;
const ERROR_CLASS_ALREADY_EXISTS: u32 = 1410;
const ERROR_CLASS_DOES_NOT_EXIST: u32 = 1411;
const ERROR_CLASS_HAS_WINDOWS: u32 = 1412;
const ERROR_INVALID_INDEX: u32 = 1413;
const ERROR_INVALID_PARAMETER: u32 = 87;

const GWL_WNDPROC: i32 = -4;
const GWL_HINSTANCE: i32 = -6;
const GWL_HWNDPARENT: i32 = -8;
const GWL_ID: i32 = -12;
const GWL_STYLE: i32 = -16;
const GWL_EXSTYLE: i32 = -20;
const GWL_USERDATA: i32 = -21;

const GCL_MENUNAME: i32 = -8;
const GCL_HBRBACKGROUND: i32 = -10;
const GCL_HCURSOR: i32 = -12;
const GCL_HICON: i32 = -14;
const GCL_HMODULE: i32 = -16;
const GCL_CBWNDEXTRA: i32 = -18;
const GCL_CBCLSEXTRA: i32 = -20;
const GCL_WNDPROC: i32 = -24;
const GCL_STYLE: i32 = -26;
const GCW_ATOM: i32 = -32;
const GCL_HICONSM: i32 = -34;

const GW_HWNDFIRST: u32 = 0;
const GW_HWNDLAST: u32 = 1;
const GW_HWNDNEXT: u32 = 2;
const GW_HWNDPREV: u32 = 3;
const GW_OWNER: u32 = 4;
const GW_CHILD: u32 = 5;

/// The desktop window. Kept at the value the loader always used.
pub const HWND_DESKTOP: usize = 0x10001;
/// Placeholder device context handed to WM_ERASEBKGND (no GDI behind it).
const PLACEHOLDER_HDC: usize = 0x00DC0001;

// Wine's default non-client metrics (pinned by AdjustWindowRectEx in the probe).
const METRIC_BORDER: i32 = 1;
const METRIC_CAPTION: i32 = 25;
const METRIC_SMCAPTION: i32 = 17;
const METRIC_MENU: i32 = 18;
const METRIC_EDGE: i32 = 2;

pub var g_screen_w: i32 = 1920;
pub var g_screen_h: i32 = 1080;

// ---------------------------------------------------------------------------
// Guest-visible structures
// ---------------------------------------------------------------------------

pub const RECT = extern struct { left: i32, top: i32, right: i32, bottom: i32 };
const POINT = extern struct { x: i32, y: i32 };

pub const MSG = extern struct {
    hwnd: usize,
    message: u32,
    wParam: usize,
    lParam: usize,
    time: u32,
    pt: POINT,
};

const WNDCLASSA = extern struct {
    style: u32,
    lpfnWndProc: usize,
    cbClsExtra: i32,
    cbWndExtra: i32,
    hInstance: usize,
    hIcon: usize,
    hCursor: usize,
    hbrBackground: usize,
    lpszMenuName: usize,
    lpszClassName: usize,
};

const WNDCLASSEXA = extern struct {
    cbSize: u32,
    style: u32,
    lpfnWndProc: usize,
    cbClsExtra: i32,
    cbWndExtra: i32,
    hInstance: usize,
    hIcon: usize,
    hCursor: usize,
    hbrBackground: usize,
    lpszMenuName: usize,
    lpszClassName: usize,
    hIconSm: usize,
};

const CREATESTRUCTA = extern struct {
    lpCreateParams: usize,
    hInstance: usize,
    hMenu: usize,
    hwndParent: usize,
    cy: i32,
    cx: i32,
    y: i32,
    x: i32,
    style: u32,
    lpszName: usize,
    lpszClass: usize,
    dwExStyle: u32,
};

const WINDOWPOS = extern struct {
    hwnd: usize,
    hwndInsertAfter: usize,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    flags: u32,
};

const NCCALCSIZE_PARAMS = extern struct {
    rgrc: [3]RECT,
    lppos: *WINDOWPOS,
};

const MINMAXINFO = extern struct {
    ptReserved: POINT,
    ptMaxSize: POINT,
    ptMaxPosition: POINT,
    ptMinTrackSize: POINT,
    ptMaxTrackSize: POINT,
};

const STYLESTRUCT = extern struct { styleOld: u32, styleNew: u32 };

const PAINTSTRUCT = extern struct {
    hdc: usize,
    fErase: i32,
    rcPaint: RECT,
    fRestore: i32,
    fIncUpdate: i32,
    rgbReserved: [32]u8,
};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const MAX_CLASSES = 64;
const MAX_WINDOWS = 256;
const MAX_QUEUES = 64;
const QUEUE_LEN = 512;
const MAX_EXTRA = 128;

const Class = struct {
    used: bool = false,
    name: [64]u8 = [_]u8{0} ** 64,
    name_len: u8 = 0,
    atom: u16 = 0,
    style: u32 = 0,
    proc: usize = 0,
    cls_extra: i32 = 0,
    wnd_extra: i32 = 0,
    hinst: usize = 0,
    icon: usize = 0,
    icon_sm: usize = 0,
    cursor: usize = 0,
    brush: usize = 0,
    menu: usize = 0,
    extra: [MAX_EXTRA]u8 = [_]u8{0} ** MAX_EXTRA,
};

const Window = struct {
    used: bool = false,
    hwnd: usize = 0,
    class: u16 = 0,
    proc: usize = 0,
    style: u32 = 0,
    exstyle: u32 = 0,
    parent: usize = 0,
    owner: usize = 0,
    id: usize = 0,
    hinst: usize = 0,
    userdata: usize = 0,
    /// Window rectangle, in the parent's client coordinates (screen for top level).
    rect: RECT = .{ .left = 0, .top = 0, .right = 0, .bottom = 0 },
    /// Client rectangle, same coordinate space as `rect`.
    client: RECT = .{ .left = 0, .top = 0, .right = 0, .bottom = 0 },
    text: [256]u8 = [_]u8{0} ** 256,
    text_len: u16 = 0,
    tid: u32 = 0,
    /// Overlapped windows get WM_SIZE/WM_MOVE on their first ShowWindow, not at creation.
    need_size: bool = false,
    /// Needs WM_PAINT (and the erase it implies).
    invalid: bool = false,
    need_erase: bool = false,
    /// WM_GETICON is asked once, when the window is first published (shown).
    published: bool = false,
    destroying: bool = false,
    /// Creation serial: newer windows are higher in the z-order.
    serial: u32 = 0,
    extra: [MAX_EXTRA]u8 = [_]u8{0} ** MAX_EXTRA,
};

const Sent = struct {
    hwnd: usize,
    msg: u32,
    wp: usize,
    lp: usize,
    result: usize = 0,
    done: bool = false,
    next: ?*Sent = null,
};

const Queue = struct {
    used: bool = false,
    tid: u32 = 0,
    posted: [QUEUE_LEN]MSG = undefined,
    len: usize = 0,
    quit: bool = false,
    quit_code: usize = 0,
    sent: ?*Sent = null,
};

var g_mu: c.pthread_mutex_t = .{};
var g_cv: c.pthread_cond_t = .{};
var g_classes: [MAX_CLASSES]Class = [_]Class{.{}} ** MAX_CLASSES;
var g_windows: [MAX_WINDOWS]Window = [_]Window{.{}} ** MAX_WINDOWS;
var g_queues: [MAX_QUEUES]Queue = [_]Queue{.{}} ** MAX_QUEUES;
var g_next_handle: usize = 0x00030000;
var g_serial: u32 = 0;
var g_active: usize = 0;
var g_focus: usize = 0;
var g_foreground: usize = 0;
/// Whether this process may take the foreground. A new process may; it loses
/// that once its last active window goes away (the foreground then belongs to
/// another process), and a newly published window takes it back.
var g_fg_right: bool = true;

fn lock() void {
    _ = c.pthread_mutex_lock(&g_mu);
}
fn unlock() void {
    _ = c.pthread_mutex_unlock(&g_mu);
}
fn wake() void {
    _ = c.pthread_cond_broadcast(&g_cv);
}

fn tidNow() u32 {
    return @intCast(linux.gettid());
}

fn tickNow() u32 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
    return @truncate(@as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000);
}

/// The window record behind `h`, or null. Records stay put until NCDESTROY, so
/// the pointer may be used without the lock by the thread that owns the window.
fn win(h: usize) ?*Window {
    if (h == 0) return null;
    for (&g_windows) |*w| {
        if (w.used and w.hwnd == h) return w;
    }
    return null;
}

fn queueFor(tid: u32, create: bool) ?*Queue {
    for (&g_queues) |*q| {
        if (q.used and q.tid == tid) return q;
    }
    if (!create) return null;
    for (&g_queues) |*q| {
        if (!q.used) {
            q.* = .{ .used = true, .tid = tid };
            return q;
        }
    }
    return null;
}

fn isTopLevel(w: *const Window) bool {
    return (w.style & WS_CHILD) == 0;
}

fn rootOf(h: usize) usize {
    var cur = h;
    while (win(cur)) |w| {
        if (!isTopLevel(w) and w.parent != 0) cur = w.parent else break;
    }
    return cur;
}

fn isChildOf(parent: usize, h: usize) bool {
    var cur = h;
    while (win(cur)) |w| {
        if (isTopLevel(w)) return false;
        if (w.parent == parent) return true;
        cur = w.parent;
    }
    return false;
}

fn isVisible(h: usize) bool {
    var cur = h;
    while (win(cur)) |w| {
        if ((w.style & WS_VISIBLE) == 0) return false;
        if (isTopLevel(w)) return true;
        cur = w.parent;
    }
    return false;
}

fn width(r: RECT) i32 {
    return r.right - r.left;
}
fn height(r: RECT) i32 {
    return r.bottom - r.top;
}
fn makeLong(lo: i32, hi: i32) usize {
    const l: u32 = @as(u16, @truncate(@as(u32, @bitCast(lo))));
    const h: u32 = @as(u16, @truncate(@as(u32, @bitCast(hi))));
    return l | (h << 16);
}

// ---------------------------------------------------------------------------
// Non-client metrics
// ---------------------------------------------------------------------------

/// Wine's adjust_window_rect: the non-client area a style adds around a client rect.
pub fn adjustRect(r: *RECT, style: u32, menu: bool, exstyle: u32) void {
    var adjust: i32 = 0;
    if ((exstyle & (WS_EX_STATICEDGE | WS_EX_DLGMODALFRAME)) == WS_EX_STATICEDGE) {
        adjust = 1;
    } else if ((exstyle & WS_EX_DLGMODALFRAME) != 0 or (style & (WS_THICKFRAME | WS_DLGFRAME)) != 0) {
        adjust = 2;
    }
    if ((style & WS_THICKFRAME) != 0) adjust += METRIC_BORDER;
    if ((style & (WS_BORDER | WS_DLGFRAME)) != 0 or (exstyle & WS_EX_DLGMODALFRAME) != 0) adjust += 1;
    r.left -= adjust;
    r.top -= adjust;
    r.right += adjust;
    r.bottom += adjust;
    if ((style & WS_CAPTION) == WS_CAPTION) {
        r.top -= (if ((exstyle & WS_EX_TOOLWINDOW) != 0) METRIC_SMCAPTION else METRIC_CAPTION) + 1;
    }
    if (menu) r.top -= METRIC_MENU + 1;
    if ((exstyle & WS_EX_CLIENTEDGE) != 0) {
        r.left -= METRIC_EDGE;
        r.top -= METRIC_EDGE;
        r.right += METRIC_EDGE;
        r.bottom += METRIC_EDGE;
    }
}

/// The client rectangle DefWindowProc's WM_NCCALCSIZE derives from a window rectangle.
fn clientFromWindow(w: *const Window, wr: RECT) RECT {
    var nc = RECT{ .left = 0, .top = 0, .right = 0, .bottom = 0 };
    adjustRect(&nc, w.style, false, w.exstyle);
    var r = RECT{
        .left = wr.left - nc.left,
        .top = wr.top - nc.top,
        .right = wr.right - nc.right,
        .bottom = wr.bottom - nc.bottom,
    };
    if (r.right < r.left) r.right = r.left;
    if (r.bottom < r.top) r.bottom = r.top;
    return r;
}

fn fixExStyle(style: u32, exstyle: u32) u32 {
    if ((exstyle & WS_EX_DLGMODALFRAME) != 0 or
        ((exstyle & WS_EX_STATICEDGE) == 0 and (style & (WS_DLGFRAME | WS_THICKFRAME)) != 0))
        return exstyle | WS_EX_WINDOWEDGE;
    return exstyle & ~WS_EX_WINDOWEDGE;
}

fn wantsMinMax(style: u32) bool {
    return (style & WS_THICKFRAME) != 0 or (style & (WS_POPUP | WS_CHILD)) == 0;
}

// ---------------------------------------------------------------------------
// Calling the window procedure
// ---------------------------------------------------------------------------

/// Delivers a message to `h`'s window procedure. On the owner thread it is a
/// direct call; from another thread it waits until the owner pumps.
fn send(h: usize, msg: u32, wp: usize, lp: usize) usize {
    lock();
    const w = win(h) orelse {
        unlock();
        return 0;
    };
    const proc = w.proc;
    const owner = w.tid;
    if (owner == tidNow() or owner == 0) {
        unlock();
        if (proc == 0) return 0;
        const f: WndProc = @ptrFromInt(proc);
        return f(h, msg, wp, lp);
    }
    // Cross-thread: queue it on the owner and wait, serving our own sent
    // messages meanwhile (two threads sending to each other must not deadlock).
    const q = queueFor(owner, true) orelse {
        unlock();
        return 0;
    };
    var s = Sent{ .hwnd = h, .msg = msg, .wp = wp, .lp = lp };
    s.next = q.sent;
    q.sent = &s;
    wake();
    while (!s.done) {
        if (queueFor(tidNow(), false)) |mine| {
            if (mine.sent != null) {
                unlock();
                serveSent();
                lock();
                continue;
            }
        }
        // The owner may be gone; give up if its window is.
        if (win(h) == null) {
            removeSent(q, &s);
            break;
        }
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(linux.CLOCK.REALTIME, &ts);
        ts.nsec += 50 * 1_000_000;
        if (ts.nsec >= 1_000_000_000) {
            ts.sec += 1;
            ts.nsec -= 1_000_000_000;
        }
        _ = c.pthread_cond_timedwait(&g_cv, &g_mu, @ptrCast(&ts));
    }
    const r = s.result;
    unlock();
    return r;
}

fn removeSent(q: *Queue, s: *Sent) void {
    var link: *?*Sent = &q.sent;
    while (link.*) |cur| {
        if (cur == s) {
            link.* = cur.next;
            return;
        }
        link = &cur.next;
    }
}

/// Runs the messages other threads sent to windows of this thread.
fn serveSent() void {
    while (true) {
        lock();
        const q = queueFor(tidNow(), false) orelse {
            unlock();
            return;
        };
        const s = q.sent orelse {
            unlock();
            return;
        };
        q.sent = s.next;
        const w = win(s.hwnd);
        const proc: usize = if (w) |x| x.proc else 0;
        unlock();
        var r: usize = 0;
        if (proc != 0) {
            const f: WndProc = @ptrFromInt(proc);
            r = f(s.hwnd, s.msg, s.wp, s.lp);
        }
        lock();
        s.result = r;
        s.done = true;
        wake();
        unlock();
    }
}

// ---------------------------------------------------------------------------
// Activation and focus
// ---------------------------------------------------------------------------

fn setFocusInternal(h: usize) usize {
    const prev = g_focus;
    if (prev == h) return prev;
    if (prev != 0 and win(prev) != null) {
        _ = send(prev, WM_KILLFOCUS, h, 0);
        _ = send(prev, WM_IME_SETCONTEXT, 0, ISC_SHOWUIALL);
        // The message may have moved the focus elsewhere.
        if (g_focus != prev) return prev;
    }
    g_focus = h;
    if (h != 0) {
        _ = send(h, WM_IME_SETCONTEXT, 1, ISC_SHOWUIALL);
        _ = send(h, WM_SETFOCUS, prev, 0);
    }
    return prev;
}

/// Thread whose top-level windows all get WM_ACTIVATEAPP when activation crosses threads.
fn sendActivateApp(tid: u32, on: bool, other_tid: u32) void {
    if (tid == 0) return;
    var list: [MAX_WINDOWS]usize = undefined;
    const n = listTopLevel(&list, tid);
    for (list[0..n]) |h| _ = send(h, WM_ACTIVATEAPP, @intFromBool(on), other_tid);
}

/// Top-level windows of `tid` (0 = any), newest first.
fn listTopLevel(out: *[MAX_WINDOWS]usize, tid: u32) usize {
    lock();
    defer unlock();
    var n: usize = 0;
    var last: u32 = std.math.maxInt(u32);
    // Newest first: walk serials downward.
    while (true) {
        var best: ?*Window = null;
        for (&g_windows) |*w| {
            if (!w.used or w.destroying or !isTopLevel(w)) continue;
            if (tid != 0 and w.tid != tid) continue;
            if (w.serial >= last) continue;
            if (best == null or w.serial > best.?.serial) best = w;
        }
        const b = best orelse break;
        out[n] = b.hwnd;
        n += 1;
        last = b.serial;
    }
    return n;
}

fn setActiveInternal(h: usize) void {
    const prev = g_active;
    if (prev == h) return;
    const prev_ok = prev != 0 and win(prev) != null;
    if (prev_ok) {
        _ = send(prev, WM_NCACTIVATE, 0, h);
        _ = send(prev, WM_ACTIVATE, WA_INACTIVE, h);
    }
    g_active = h;
    if (h != 0) {
        g_foreground = h;
        _ = send(h, WM_QUERYNEWPALETTE, 0, 0);
        if (win(h) == null) return;
    } else {
        g_foreground = 0;
    }
    const old_tid: u32 = if (prev_ok) win(prev).?.tid else 0;
    const new_tid: u32 = if (win(h)) |w| w.tid else 0;
    if (old_tid != new_tid) {
        sendActivateApp(old_tid, false, new_tid);
        sendActivateApp(new_tid, true, old_tid);
    }
    if (h != 0 and win(h) != null) {
        _ = send(h, WM_NCACTIVATE, @intFromBool(h == g_foreground), prev);
        _ = send(h, WM_ACTIVATE, WA_ACTIVE, prev);
    }
    // Move the focus into the new active window if its procedure did not.
    if (g_active == h) {
        if (h == 0 or g_focus == 0 or rootOf(g_focus) != h) _ = setFocusInternal(h);
    }
}

/// After `gone` stops being eligible: activate the next visible top-level
/// window of ours, or nothing.
fn activateOther(gone: usize) void {
    var list: [MAX_WINDOWS]usize = undefined;
    const n = listTopLevel(&list, 0);
    for (list[0..n]) |h| {
        if (h == gone) continue;
        const w = win(h) orelse continue;
        if ((w.style & WS_VISIBLE) == 0 or (w.style & WS_DISABLED) != 0) continue;
        setActiveInternal(h);
        return;
    }
    setActiveInternal(0);
    g_fg_right = false;
}

// ---------------------------------------------------------------------------
// Painting
// ---------------------------------------------------------------------------

fn redrawFrame(h: usize) void {
    const w = win(h) orelse return;
    w.invalid = true;
    w.need_erase = true;
    _ = send(h, WM_NCPAINT, 1, 0);
    if (win(h)) |w2| {
        if (w2.need_erase) {
            w2.need_erase = false;
            _ = send(h, WM_ERASEBKGND, PLACEHOLDER_HDC, 0);
        }
    }
}

// ---------------------------------------------------------------------------
// SetWindowPos core
// ---------------------------------------------------------------------------

fn setWindowPosInternal(h: usize, after: usize, x: i32, y: i32, cx: i32, cy: i32, flags_in: u32) bool {
    const w = win(h) orelse return false;
    var flags = flags_in & 0x7FF;
    const was_visible = (w.style & WS_VISIBLE) != 0;
    if ((flags & SWP_SHOWWINDOW) != 0 and was_visible) flags &= ~SWP_SHOWWINDOW;
    if ((flags & SWP_HIDEWINDOW) != 0 and !was_visible) flags &= ~SWP_HIDEWINDOW;

    var pos = WINDOWPOS{
        .hwnd = h,
        .hwndInsertAfter = after,
        .x = if ((flags & SWP_NOMOVE) != 0) w.rect.left else x,
        .y = if ((flags & SWP_NOMOVE) != 0) w.rect.top else y,
        .cx = if ((flags & SWP_NOSIZE) != 0) width(w.rect) else cx,
        .cy = if ((flags & SWP_NOSIZE) != 0) height(w.rect) else cy,
        .flags = flags,
    };
    if ((flags_in & SWP_NOSENDCHANGING) == 0) _ = send(h, WM_WINDOWPOSCHANGING, 0, @intFromPtr(&pos));
    const w1 = win(h) orelse return false;
    flags = pos.flags & 0x7FF;

    const new_rect = RECT{ .left = pos.x, .top = pos.y, .right = pos.x + pos.cx, .bottom = pos.y + pos.cy };
    const old_client = w1.client;
    const geometry = (flags & SWP_NOSIZE) == 0 or (flags & SWP_NOMOVE) == 0 or (flags & SWP_FRAMECHANGED) != 0;
    const size_changed = width(new_rect) != width(w1.rect) or height(new_rect) != height(w1.rect);
    if (geometry) {
        var params = NCCALCSIZE_PARAMS{
            .rgrc = .{ new_rect, w1.rect, w1.client },
            .lppos = &pos,
        };
        _ = send(h, WM_NCCALCSIZE, 1, @intFromPtr(&params));
        if (win(h)) |w2| {
            w2.rect = new_rect;
            w2.client = params.rgrc[0];
        }
    }
    const w3 = win(h) orelse return false;

    // Z-order: only the topmost bit is modelled; moving to the top of an
    // unordered set changes nothing visible, so it is reported as no z change.
    var z_changed = false;
    if ((flags & SWP_NOZORDER) == 0) {
        if (after == HWND_TOPMOST) {
            if ((w3.exstyle & WS_EX_TOPMOST) == 0) z_changed = true;
            w3.exstyle |= WS_EX_TOPMOST;
            z_changed = true;
        } else if (after == HWND_NOTOPMOST) {
            w3.exstyle &= ~WS_EX_TOPMOST;
            z_changed = true;
        } else if (after != HWND_TOP) {
            z_changed = true;
        }
    }

    var showing = false;
    if ((flags & SWP_SHOWWINDOW) != 0) {
        w3.style |= WS_VISIBLE;
        showing = true;
        const first = !w3.published;
        if (first) {
            w3.published = true;
            // The native window layer asks for the icons when it publishes the window.
            _ = send(h, WM_GETICON, ICON_BIG, 0);
            _ = send(h, WM_GETICON, ICON_SMALL, 0);
        }
        if ((flags & SWP_NOACTIVATE) == 0) {
            if (win(h)) |w3b| {
                // A newly published window may take the foreground (as a new
                // window does on a desktop); a re-shown one only while this
                // process still holds it.
                if (first) g_fg_right = true;
                if (isTopLevel(w3b) and g_fg_right) setActiveInternal(h);
            }
        }
    } else if ((flags & SWP_HIDEWINDOW) != 0) {
        w3.style &= ~WS_VISIBLE;
        w3.invalid = false;
    }

    if (win(h)) |w4| {
        if ((w4.style & WS_VISIBLE) != 0 and (flags & SWP_NOREDRAW) == 0 and (showing or size_changed or (flags & SWP_FRAMECHANGED) != 0)) {
            redrawFrame(h);
        }
    }

    const w5 = win(h) orelse return true;
    var changed = flags;
    if (!z_changed) changed |= SWP_NOZORDER;
    if (width(w5.client) == width(old_client) and height(w5.client) == height(old_client)) changed |= SWP_NOCLIENTSIZE;
    if (w5.client.left == old_client.left and w5.client.top == old_client.top) changed |= SWP_NOCLIENTMOVE;
    pos.flags = changed;
    pos.x = w5.rect.left;
    pos.y = w5.rect.top;
    pos.cx = width(w5.rect);
    pos.cy = height(w5.rect);
    const noop = SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER;
    if ((changed & (noop | SWP_SHOWWINDOW | SWP_HIDEWINDOW | SWP_FRAMECHANGED)) != noop)
        _ = send(h, WM_WINDOWPOSCHANGED, 0, @intFromPtr(&pos));
    return true;
}

// ---------------------------------------------------------------------------
// Classes
// ---------------------------------------------------------------------------

fn classByName(name_ptr: usize) ?u16 {
    if (name_ptr == 0) return null;
    if (name_ptr < 0x10000) {
        const atom: u16 = @intCast(name_ptr);
        for (&g_classes, 0..) |*k, i| if (k.used and k.atom == atom) return @intCast(i);
        return null;
    }
    const name = std.mem.sliceTo(@as([*:0]const u8, @ptrFromInt(name_ptr)), 0);
    for (&g_classes, 0..) |*k, i| {
        if (k.used and std.ascii.eqlIgnoreCase(k.name[0..k.name_len], name)) return @intCast(i);
    }
    return null;
}

fn registerClass(cls: WNDCLASSEXA) u16 {
    lock();
    defer unlock();
    if (cls.lpszClassName == 0 or cls.lpszClassName < 0x10000) {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (classByName(cls.lpszClassName) != null) {
        setLastError(ERROR_CLASS_ALREADY_EXISTS);
        return 0;
    }
    const name = std.mem.sliceTo(@as([*:0]const u8, @ptrFromInt(cls.lpszClassName)), 0);
    for (&g_classes, 0..) |*k, i| {
        if (k.used) continue;
        k.* = .{
            .used = true,
            .atom = @intCast(0xC000 + i * 2 + 0x18),
            .style = cls.style,
            .proc = cls.lpfnWndProc,
            .cls_extra = @max(0, @min(cls.cbClsExtra, MAX_EXTRA)),
            .wnd_extra = @max(0, @min(cls.cbWndExtra, MAX_EXTRA)),
            .hinst = cls.hInstance,
            .icon = cls.hIcon,
            .icon_sm = cls.hIconSm,
            .cursor = cls.hCursor,
            .brush = cls.hbrBackground,
            .menu = cls.lpszMenuName,
        };
        const len = @min(name.len, k.name.len - 1);
        @memcpy(k.name[0..len], name[0..len]);
        k.name_len = @intCast(len);
        std.debug.print("[WINS:User32] RegisterClass(\"{s}\", wndproc=0x{x}) -> atom 0x{x}\n", .{ name, cls.lpfnWndProc, k.atom });
        return k.atom;
    }
    setLastError(8); // ERROR_NOT_ENOUGH_MEMORY
    return 0;
}

pub fn RegisterClassA(lpWndClass: ?*const WNDCLASSA) callconv(W) u16 {
    const wc = lpWndClass orelse {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    };
    return registerClass(.{
        .cbSize = @sizeOf(WNDCLASSEXA),
        .style = wc.style,
        .lpfnWndProc = wc.lpfnWndProc,
        .cbClsExtra = wc.cbClsExtra,
        .cbWndExtra = wc.cbWndExtra,
        .hInstance = wc.hInstance,
        .hIcon = wc.hIcon,
        .hCursor = wc.hCursor,
        .hbrBackground = wc.hbrBackground,
        .lpszMenuName = wc.lpszMenuName,
        .lpszClassName = wc.lpszClassName,
        .hIconSm = 0,
    });
}

pub fn RegisterClassExA(lpWndClass: ?*const WNDCLASSEXA) callconv(W) u16 {
    const wc = lpWndClass orelse {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if (wc.cbSize != @sizeOf(WNDCLASSEXA)) {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    return registerClass(wc.*);
}

pub fn UnregisterClassA(lpClassName: usize, hInstance: usize) callconv(W) i32 {
    _ = hInstance;
    lock();
    defer unlock();
    const idx = classByName(lpClassName) orelse {
        setLastError(ERROR_CLASS_DOES_NOT_EXIST);
        return 0;
    };
    for (&g_windows) |*w| {
        if (w.used and w.class == idx) {
            setLastError(ERROR_CLASS_HAS_WINDOWS);
            return 0;
        }
    }
    g_classes[idx].used = false;
    return 1;
}

pub fn GetClassNameA(hWnd: usize, lpClassName: ?[*]u8, nMaxCount: i32) callconv(W) i32 {
    const w = win(hWnd) orelse {
        setLastError(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    };
    const buf = lpClassName orelse return 0;
    if (nMaxCount <= 0) return 0;
    const k = &g_classes[w.class];
    const len: usize = @min(@as(usize, @intCast(nMaxCount - 1)), k.name_len);
    @memcpy(buf[0..len], k.name[0..len]);
    buf[len] = 0;
    return @intCast(len);
}

pub fn GetClassLongA(hWnd: usize, nIndex: i32) callconv(W) u32 {
    const w = win(hWnd) orelse {
        setLastError(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    };
    const k = &g_classes[w.class];
    if (nIndex >= 0) {
        const off: usize = @intCast(nIndex);
        if (off + 4 > @as(usize, @intCast(k.cls_extra))) {
            setLastError(ERROR_INVALID_INDEX);
            return 0;
        }
        return std.mem.readInt(u32, k.extra[off..][0..4], .little);
    }
    return switch (nIndex) {
        GCL_STYLE => k.style,
        GCL_WNDPROC => @intCast(k.proc),
        GCL_HBRBACKGROUND => @intCast(k.brush),
        GCL_HCURSOR => @intCast(k.cursor),
        GCL_HICON => @intCast(k.icon),
        GCL_HICONSM => @intCast(k.icon_sm),
        GCL_HMODULE => @intCast(k.hinst),
        GCL_CBWNDEXTRA => @intCast(k.wnd_extra),
        GCL_CBCLSEXTRA => @intCast(k.cls_extra),
        GCL_MENUNAME => @intCast(k.menu),
        GCW_ATOM => k.atom,
        else => blk: {
            setLastError(ERROR_INVALID_INDEX);
            break :blk 0;
        },
    };
}

// ---------------------------------------------------------------------------
// Window creation and destruction
// ---------------------------------------------------------------------------

pub fn CreateWindowExA(
    dwExStyle: u32,
    lpClassName: usize,
    lpWindowName: ?[*:0]const u8,
    dwStyle: u32,
    x_in: i32,
    y_in: i32,
    w_in: i32,
    h_in: i32,
    hWndParent: usize,
    hMenu: usize,
    hInstance: usize,
    lpParam: usize,
) callconv(W) usize {
    lock();
    const cls_idx = classByName(lpClassName) orelse {
        unlock();
        setLastError(ERROR_CLASS_DOES_NOT_EXIST);
        std.debug.print("[WINS:User32] CreateWindowExA: class not registered -> NULL\n", .{});
        return 0;
    };
    if ((dwStyle & WS_CHILD) != 0 and (hWndParent == 0 or (hWndParent != HWND_DESKTOP and win(hWndParent) == null))) {
        unlock();
        setLastError(1406); // ERROR_TLW_WITH_WSCHILD
        return 0;
    }
    var slot: ?*Window = null;
    for (&g_windows) |*w| {
        if (!w.used) {
            slot = w;
            break;
        }
    }
    const w = slot orelse {
        unlock();
        setLastError(8);
        return 0;
    };
    const k = &g_classes[cls_idx];
    g_next_handle += 2;
    g_serial += 1;
    var style = dwStyle & ~WS_VISIBLE;
    if ((dwStyle & WS_CHILD) == 0) {
        style |= WS_CLIPSIBLINGS;
        if ((dwStyle & WS_POPUP) == 0) style |= WS_CAPTION;
    }
    w.* = .{
        .used = true,
        .hwnd = g_next_handle,
        .class = cls_idx,
        .proc = k.proc,
        .style = style,
        .exstyle = fixExStyle(style, dwExStyle),
        .parent = if ((dwStyle & WS_CHILD) != 0 and hWndParent != HWND_DESKTOP) hWndParent else 0,
        .owner = if ((dwStyle & WS_CHILD) == 0 and hWndParent != HWND_DESKTOP) rootOf(hWndParent) else 0,
        .id = if ((dwStyle & WS_CHILD) != 0) hMenu else 0,
        .hinst = hInstance,
        .tid = tidNow(),
        .need_size = (dwStyle & (WS_CHILD | WS_POPUP)) == 0,
        .serial = g_serial,
    };
    const h = w.hwnd;
    _ = queueFor(w.tid, true);
    unlock();

    var x = x_in;
    var y = y_in;
    var cx = w_in;
    var cy = h_in;
    if (x == CW_USEDEFAULT) {
        x = 0;
        y = 0;
    }
    if (cx == CW_USEDEFAULT) {
        cx = @divTrunc(g_screen_w * 3, 4);
        cy = @divTrunc(g_screen_h * 3, 4);
    }
    if (wantsMinMax(dwStyle)) {
        var mmi = defaultMinMax(w);
        _ = send(h, WM_GETMINMAXINFO, 0, @intFromPtr(&mmi));
        cx = std.math.clamp(cx, mmi.ptMinTrackSize.x, @max(mmi.ptMinTrackSize.x, mmi.ptMaxTrackSize.x));
        cy = std.math.clamp(cy, mmi.ptMinTrackSize.y, @max(mmi.ptMinTrackSize.y, mmi.ptMaxTrackSize.y));
    }
    if (cx < 0) cx = 0;
    if (cy < 0) cy = 0;
    if (win(h)) |ww| {
        ww.rect = .{ .left = x, .top = y, .right = x + cx, .bottom = y + cy };
        ww.client = ww.rect;
    }

    var cs = CREATESTRUCTA{
        .lpCreateParams = lpParam,
        .hInstance = hInstance,
        .hMenu = hMenu,
        .hwndParent = hWndParent,
        .cy = cy,
        .cx = cx,
        .y = y,
        .x = x,
        .style = dwStyle,
        .lpszName = if (lpWindowName) |n| @intFromPtr(n) else 0,
        .lpszClass = lpClassName,
        .dwExStyle = dwExStyle,
    };
    const title = if (lpWindowName) |n| std.mem.sliceTo(n, 0) else "";
    if (send(h, WM_NCCREATE, 0, @intFromPtr(&cs)) == 0) {
        std.debug.print("[WINS:User32] CreateWindowExA(\"{s}\"): WM_NCCREATE refused -> NULL\n", .{title});
        freeWindow(h);
        return 0;
    }
    if (win(h)) |ww| {
        var r = ww.rect;
        _ = send(h, WM_NCCALCSIZE, 0, @intFromPtr(&r));
        if (win(h)) |w2| w2.client = r;
    }
    if (@as(isize, @bitCast(send(h, WM_CREATE, 0, @intFromPtr(&cs)))) == -1) {
        std.debug.print("[WINS:User32] CreateWindowExA(\"{s}\"): WM_CREATE refused -> NULL\n", .{title});
        _ = DestroyWindow(h);
        return 0;
    }
    const w2 = win(h) orelse return 0;
    if (!w2.need_size) sendSizeMove(h);
    std.debug.print("[WINS:User32] CreateWindowExA(\"{s}\", style=0x{x}, {}x{}) -> HWND 0x{x}\n", .{ title, dwStyle, cx, cy, h });
    if ((dwStyle & WS_VISIBLE) != 0) {
        const cmd: i32 = if ((dwStyle & WS_MINIMIZE) != 0) SW_SHOWMINIMIZED else SW_SHOW;
        _ = ShowWindow(h, cmd);
    }
    return if (win(h) != null) h else 0;
}

fn defaultMinMax(w: *const Window) MINMAXINFO {
    var nc = RECT{ .left = 0, .top = 0, .right = 0, .bottom = 0 };
    // The frame without the caption bar: what a maximized window hangs off screen.
    adjustRect(&nc, (w.style & ~WS_CAPTION) | (w.style & WS_BORDER), false, w.exstyle);
    const bx = -nc.left;
    const by = -nc.top;
    return .{
        .ptReserved = .{ .x = 0, .y = 0 },
        .ptMaxSize = .{ .x = g_screen_w + 2 * bx, .y = g_screen_h + 2 * by },
        .ptMaxPosition = .{ .x = -bx, .y = -by },
        .ptMinTrackSize = .{ .x = 0, .y = 0 },
        .ptMaxTrackSize = .{ .x = g_screen_w + 2 * bx + 12, .y = g_screen_h + 2 * by + 12 },
    };
}

fn sendSizeMove(h: usize) void {
    const w = win(h) orelse return;
    w.need_size = false;
    const cw = width(w.client);
    const ch = height(w.client);
    const cl = w.client.left;
    const ct = w.client.top;
    _ = send(h, WM_SIZE, SIZE_RESTORED, makeLong(cw, ch));
    _ = send(h, WM_MOVE, 0, makeLong(cl, ct));
}

fn freeWindow(h: usize) void {
    lock();
    defer unlock();
    const w = win(h) orelse return;
    // Drop its posted messages.
    for (&g_queues) |*q| {
        if (!q.used) continue;
        var i: usize = 0;
        var j: usize = 0;
        while (i < q.len) : (i += 1) {
            if (q.posted[i].hwnd != h) {
                q.posted[j] = q.posted[i];
                j += 1;
            }
        }
        q.len = j;
    }
    if (g_active == h) g_active = 0;
    if (g_focus == h) g_focus = 0;
    if (g_foreground == h) g_foreground = 0;
    w.used = false;
    w.hwnd = 0;
    wake();
}

pub fn DestroyWindow(hWnd: usize) callconv(W) i32 {
    const w = win(hWnd) orelse {
        setLastError(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    };
    if (w.destroying) return 1;
    std.debug.print("[WINS:User32] DestroyWindow(0x{x})\n", .{hWnd});
    const was_active = g_active == hWnd;
    if ((w.style & WS_VISIBLE) != 0) {
        _ = setWindowPosInternal(hWnd, 0, 0, 0, 0, 0, SWP_HIDEWINDOW | SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOMOVE | SWP_NOSIZE);
    }
    if (was_active and g_active == hWnd) activateOther(hWnd);
    if (g_focus == hWnd or (g_focus != 0 and isChildOf(hWnd, g_focus))) _ = setFocusInternal(0);
    if (win(hWnd)) |w2| w2.destroying = true;
    _ = send(hWnd, WM_DESTROY, 0, 0);
    // Children (and windows this one owns) go with it.
    var list: [MAX_WINDOWS]usize = undefined;
    var n: usize = 0;
    lock();
    for (&g_windows) |*x| {
        if (x.used and !x.destroying and (x.parent == hWnd or x.owner == hWnd)) {
            list[n] = x.hwnd;
            n += 1;
        }
    }
    unlock();
    for (list[0..n]) |child| _ = DestroyWindow(child);
    _ = send(hWnd, WM_NCDESTROY, 0, 0);
    freeWindow(hWnd);
    return 1;
}

// ---------------------------------------------------------------------------
// Showing, positioning, activation API
// ---------------------------------------------------------------------------

pub fn ShowWindow(hWnd: usize, nCmdShow: i32) callconv(W) i32 {
    const w = win(hWnd) orelse {
        setLastError(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    };
    const was_visible = (w.style & WS_VISIBLE) != 0;
    switch (nCmdShow) {
        SW_HIDE => {
            if (!was_visible) return 0;
            var swp: u32 = SWP_HIDEWINDOW | SWP_NOSIZE | SWP_NOMOVE;
            if (hWnd != g_active) swp |= SWP_NOACTIVATE | SWP_NOZORDER;
            _ = send(hWnd, WM_SHOWWINDOW, 0, 0);
            _ = setWindowPosInternal(hWnd, 0, 0, 0, 0, 0, swp);
            if (hWnd == g_active) activateOther(hWnd);
            if (g_focus == hWnd or (g_focus != 0 and isChildOf(hWnd, g_focus))) {
                const parent = if (win(hWnd)) |x| x.parent else 0;
                _ = setFocusInternal(parent);
            }
            return 1;
        },
        else => {
            if (was_visible) return 1;
            var swp: u32 = SWP_SHOWWINDOW | SWP_NOSIZE | SWP_NOMOVE;
            if (nCmdShow == SW_SHOWNOACTIVATE or nCmdShow == SW_SHOWNA or nCmdShow == SW_SHOWMINNOACTIVE)
                swp |= SWP_NOACTIVATE | SWP_NOZORDER;
            if ((w.style & WS_CHILD) != 0) swp |= SWP_NOACTIVATE | SWP_NOZORDER;
            _ = send(hWnd, WM_SHOWWINDOW, 1, 0);
            _ = setWindowPosInternal(hWnd, HWND_TOP, 0, 0, 0, 0, swp);
            if (win(hWnd)) |w2| {
                if (w2.need_size) sendSizeMove(hWnd);
            }
            return 0;
        },
    }
}

pub fn SetWindowPos(hWnd: usize, hWndInsertAfter: usize, X: i32, Y: i32, cx: i32, cy: i32, uFlags: u32) callconv(W) i32 {
    if (win(hWnd) == null) {
        setLastError(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }
    if (!setWindowPosInternal(hWnd, hWndInsertAfter, X, Y, cx, cy, uFlags)) return 0;
    if ((uFlags & (SWP_NOACTIVATE | SWP_HIDEWINDOW)) == 0) {
        if (win(hWnd)) |w| {
            if (isTopLevel(w) and (w.style & WS_VISIBLE) != 0 and g_active != hWnd and (g_active != 0 or g_fg_right))
                setActiveInternal(hWnd);
        }
    }
    if ((uFlags & SWP_HIDEWINDOW) != 0 and g_active == hWnd) activateOther(hWnd);
    return 1;
}

pub fn MoveWindow(hWnd: usize, X: i32, Y: i32, nWidth: i32, nHeight: i32, bRepaint: i32) callconv(W) i32 {
    var flags: u32 = SWP_NOZORDER | SWP_NOACTIVATE;
    if (bRepaint == 0) flags |= SWP_NOREDRAW;
    return SetWindowPos(hWnd, 0, X, Y, nWidth, nHeight, flags);
}

pub fn GetActiveWindow() callconv(W) usize {
    lock();
    defer unlock();
    const w = win(g_active) orelse return 0;
    return if (w.tid == tidNow()) g_active else 0;
}

pub fn GetFocus() callconv(W) usize {
    lock();
    defer unlock();
    const w = win(g_focus) orelse return 0;
    return if (w.tid == tidNow()) g_focus else 0;
}

pub fn GetForegroundWindow() callconv(W) usize {
    lock();
    defer unlock();
    return if (win(g_foreground) != null) g_foreground else 0;
}

pub fn SetForegroundWindow(hWnd: usize) callconv(W) i32 {
    const w = win(rootOf(hWnd)) orelse {
        setLastError(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    };
    // Once the foreground has passed to another process, a background process
    // may not take it back (Win32's foreground lock; measured the same in Wine).
    if (g_active == 0 and !g_fg_right) return 0;
    if (g_active != w.hwnd) setActiveInternal(w.hwnd);
    return 1;
}

pub fn SetActiveWindow(hWnd: usize) callconv(W) usize {
    const prev = GetActiveWindow();
    if (hWnd != 0) {
        const w = win(hWnd) orelse {
            setLastError(ERROR_INVALID_WINDOW_HANDLE);
            return 0;
        };
        if (!isTopLevel(w)) return 0;
    }
    setActiveInternal(hWnd);
    return prev;
}

pub fn SetFocus(hWnd: usize) callconv(W) usize {
    if (hWnd != 0) {
        const w = win(hWnd) orelse {
            setLastError(ERROR_INVALID_WINDOW_HANDLE);
            return 0;
        };
        if (w.tid != tidNow()) return 0;
        const root = rootOf(hWnd);
        if (g_active != root) setActiveInternal(root);
    }
    return setFocusInternal(hWnd);
}

pub fn GetDesktopWindow() callconv(W) usize {
    return HWND_DESKTOP;
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

pub fn IsWindow(hWnd: usize) callconv(W) i32 {
    if (hWnd == HWND_DESKTOP) return 1;
    return @intFromBool(win(hWnd) != null);
}

pub fn IsWindowVisible(hWnd: usize) callconv(W) i32 {
    if (hWnd == HWND_DESKTOP) return 1;
    return @intFromBool(isVisible(hWnd));
}

pub fn IsIconic(hWnd: usize) callconv(W) i32 {
    const w = win(hWnd) orelse return 0;
    return @intFromBool((w.style & WS_MINIMIZE) != 0);
}

pub fn IsZoomed(hWnd: usize) callconv(W) i32 {
    const w = win(hWnd) orelse return 0;
    return @intFromBool((w.style & WS_MAXIMIZE) != 0);
}

pub fn IsWindowEnabled(hWnd: usize) callconv(W) i32 {
    const w = win(hWnd) orelse return 0;
    return @intFromBool((w.style & WS_DISABLED) == 0);
}

pub fn IsChild(hWndParent: usize, hWnd: usize) callconv(W) i32 {
    return @intFromBool(isChildOf(hWndParent, hWnd));
}

pub fn GetParent(hWnd: usize) callconv(W) usize {
    const w = win(hWnd) orelse {
        setLastError(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    };
    if (!isTopLevel(w)) return w.parent;
    if ((w.style & WS_POPUP) != 0) return w.owner;
    return 0;
}

pub fn GetWindowThreadProcessId(hWnd: usize, lpdwProcessId: ?*u32) callconv(W) u32 {
    const w = win(hWnd) orelse {
        setLastError(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    };
    if (lpdwProcessId) |p| p.* = @intCast(linux.getpid());
    return w.tid;
}

pub fn GetClientRect(hWnd: usize, lpRect: ?*RECT) callconv(W) i32 {
    const r = lpRect orelse return 0;
    if (hWnd == HWND_DESKTOP) {
        r.* = .{ .left = 0, .top = 0, .right = g_screen_w, .bottom = g_screen_h };
        return 1;
    }
    const w = win(hWnd) orelse {
        setLastError(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    };
    r.* = .{ .left = 0, .top = 0, .right = width(w.client), .bottom = height(w.client) };
    return 1;
}

/// Screen origin of `h`'s client area's coordinate space (its parent's client area).
fn parentOrigin(h: usize) POINT {
    var p = POINT{ .x = 0, .y = 0 };
    var cur = h;
    while (win(cur)) |w| {
        if (isTopLevel(w)) break;
        const parent = win(w.parent) orelse break;
        p.x += parent.client.left;
        p.y += parent.client.top;
        cur = w.parent;
    }
    return p;
}

pub fn GetWindowRect(hWnd: usize, lpRect: ?*RECT) callconv(W) i32 {
    const r = lpRect orelse return 0;
    if (hWnd == HWND_DESKTOP) {
        r.* = .{ .left = 0, .top = 0, .right = g_screen_w, .bottom = g_screen_h };
        return 1;
    }
    const w = win(hWnd) orelse {
        setLastError(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    };
    const o = parentOrigin(hWnd);
    r.* = .{ .left = w.rect.left + o.x, .top = w.rect.top + o.y, .right = w.rect.right + o.x, .bottom = w.rect.bottom + o.y };
    return 1;
}

pub fn ClientToScreen(hWnd: usize, lpPoint: ?*POINT) callconv(W) i32 {
    const p = lpPoint orelse return 0;
    if (hWnd == HWND_DESKTOP) return 1;
    const w = win(hWnd) orelse return 0;
    const o = parentOrigin(hWnd);
    p.x += w.client.left + o.x;
    p.y += w.client.top + o.y;
    return 1;
}

pub fn ScreenToClient(hWnd: usize, lpPoint: ?*POINT) callconv(W) i32 {
    const p = lpPoint orelse return 0;
    if (hWnd == HWND_DESKTOP) return 1;
    const w = win(hWnd) orelse return 0;
    const o = parentOrigin(hWnd);
    p.x -= w.client.left + o.x;
    p.y -= w.client.top + o.y;
    return 1;
}

pub fn AdjustWindowRect(lpRect: ?*RECT, dwStyle: u32, bMenu: i32) callconv(W) i32 {
    return AdjustWindowRectEx(lpRect, dwStyle, bMenu, 0);
}

pub fn AdjustWindowRectEx(lpRect: ?*RECT, dwStyle: u32, bMenu: i32, dwExStyle: u32) callconv(W) i32 {
    const r = lpRect orelse return 0;
    adjustRect(r, dwStyle, bMenu != 0, dwExStyle);
    return 1;
}

pub fn GetWindowLongA(hWnd: usize, nIndex: i32) callconv(W) u32 {
    const w = win(hWnd) orelse {
        setLastError(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    };
    if (nIndex >= 0) {
        const off: usize = @intCast(nIndex);
        if (off + 4 > @as(usize, @intCast(g_classes[w.class].wnd_extra))) {
            setLastError(ERROR_INVALID_INDEX);
            return 0;
        }
        return std.mem.readInt(u32, w.extra[off..][0..4], .little);
    }
    return switch (nIndex) {
        GWL_WNDPROC => @intCast(w.proc),
        GWL_HINSTANCE => @intCast(w.hinst),
        GWL_HWNDPARENT => @intCast(if (isTopLevel(w)) w.owner else w.parent),
        GWL_ID => @intCast(w.id),
        GWL_STYLE => w.style,
        GWL_EXSTYLE => w.exstyle,
        GWL_USERDATA => @intCast(w.userdata),
        else => blk: {
            setLastError(ERROR_INVALID_INDEX);
            break :blk 0;
        },
    };
}

pub fn SetWindowLongA(hWnd: usize, nIndex: i32, dwNewLong: u32) callconv(W) u32 {
    const w = win(hWnd) orelse {
        setLastError(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    };
    if (nIndex >= 0) {
        const off: usize = @intCast(nIndex);
        if (off + 4 > @as(usize, @intCast(g_classes[w.class].wnd_extra))) {
            setLastError(ERROR_INVALID_INDEX);
            return 0;
        }
        const old = std.mem.readInt(u32, w.extra[off..][0..4], .little);
        std.mem.writeInt(u32, w.extra[off..][0..4], dwNewLong, .little);
        return old;
    }
    switch (nIndex) {
        GWL_WNDPROC => {
            const old = w.proc;
            w.proc = dwNewLong;
            return @intCast(old);
        },
        GWL_HINSTANCE => {
            const old = w.hinst;
            w.hinst = dwNewLong;
            return @intCast(old);
        },
        GWL_ID => {
            const old = w.id;
            w.id = dwNewLong;
            return @intCast(old);
        },
        GWL_USERDATA => {
            const old = w.userdata;
            w.userdata = dwNewLong;
            return @intCast(old);
        },
        GWL_STYLE, GWL_EXSTYLE => {
            const ex = nIndex == GWL_EXSTYLE;
            var ss = STYLESTRUCT{ .styleOld = if (ex) w.exstyle else w.style, .styleNew = dwNewLong };
            const which: usize = @bitCast(@as(isize, nIndex));
            _ = send(hWnd, WM_STYLECHANGING, which, @intFromPtr(&ss));
            const w2 = win(hWnd) orelse return 0;
            const old = if (ex) w2.exstyle else w2.style;
            if (ex) {
                w2.exstyle = fixExStyle(w2.style, ss.styleNew);
            } else {
                // WS_VISIBLE follows ShowWindow, not SetWindowLong, for top-level windows' activation;
                // the bit itself is taken as given.
                w2.style = ss.styleNew;
            }
            ss.styleOld = old;
            _ = send(hWnd, WM_STYLECHANGED, which, @intFromPtr(&ss));
            return old;
        },
        else => {
            setLastError(ERROR_INVALID_INDEX);
            return 0;
        },
    }
}

pub fn GetWindowTextA(hWnd: usize, lpString: ?[*]u8, nMaxCount: i32) callconv(W) i32 {
    const buf = lpString orelse return 0;
    if (nMaxCount <= 0) return 0;
    if (win(hWnd) == null) {
        setLastError(ERROR_INVALID_WINDOW_HANDLE);
        buf[0] = 0;
        return 0;
    }
    return @intCast(send(hWnd, WM_GETTEXT, @intCast(nMaxCount), @intFromPtr(buf)));
}

pub fn GetWindowTextLengthA(hWnd: usize) callconv(W) i32 {
    if (win(hWnd) == null) {
        setLastError(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }
    return @intCast(send(hWnd, WM_GETTEXTLENGTH, 0, 0));
}

pub fn SetWindowTextA(hWnd: usize, lpString: ?[*:0]const u8) callconv(W) i32 {
    if (win(hWnd) == null) {
        setLastError(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }
    return @intCast(send(hWnd, WM_SETTEXT, 0, if (lpString) |s| @intFromPtr(s) else 0));
}

fn setText(w: *Window, s: ?[*:0]const u8) void {
    const src = if (s) |p| std.mem.sliceTo(p, 0) else "";
    const len = @min(src.len, w.text.len - 1);
    @memcpy(w.text[0..len], src[0..len]);
    w.text[len] = 0;
    w.text_len = @intCast(len);
}

pub fn FindWindowA(lpClassName: usize, lpWindowName: ?[*:0]const u8) callconv(W) usize {
    var cls: ?u16 = null;
    if (lpClassName != 0) {
        lock();
        cls = classByName(lpClassName);
        unlock();
        if (cls == null) return 0;
    }
    const title = if (lpWindowName) |t| std.mem.sliceTo(t, 0) else null;
    var list: [MAX_WINDOWS]usize = undefined;
    const n = listTopLevel(&list, 0);
    for (list[0..n]) |h| {
        const w = win(h) orelse continue;
        if (cls) |k| if (w.class != k) continue;
        if (title) |t| if (!std.ascii.eqlIgnoreCase(w.text[0..w.text_len], t)) continue;
        return h;
    }
    return 0;
}

/// Children of `parent` (0 = top-level windows), newest first.
fn listChildren(out: *[MAX_WINDOWS]usize, parent: usize) usize {
    lock();
    defer unlock();
    var n: usize = 0;
    var last: u32 = std.math.maxInt(u32);
    while (true) {
        var best: ?*Window = null;
        for (&g_windows) |*w| {
            if (!w.used or w.destroying) continue;
            const p = if (isTopLevel(w)) 0 else w.parent;
            if (p != parent or w.serial >= last) continue;
            if (best == null or w.serial > best.?.serial) best = w;
        }
        const b = best orelse break;
        out[n] = b.hwnd;
        n += 1;
        last = b.serial;
    }
    return n;
}

pub fn GetWindow(hWnd: usize, uCmd: u32) callconv(W) usize {
    if (hWnd == HWND_DESKTOP) {
        if (uCmd != GW_CHILD) return 0;
        var list: [MAX_WINDOWS]usize = undefined;
        const n = listChildren(&list, 0);
        return if (n > 0) list[0] else 0;
    }
    const w = win(hWnd) orelse {
        setLastError(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    };
    var list: [MAX_WINDOWS]usize = undefined;
    switch (uCmd) {
        GW_OWNER => return if (isTopLevel(w)) w.owner else 0,
        GW_CHILD => {
            const n = listChildren(&list, hWnd);
            return if (n > 0) list[0] else 0;
        },
        GW_HWNDFIRST, GW_HWNDLAST, GW_HWNDNEXT, GW_HWNDPREV => {
            const n = listChildren(&list, if (isTopLevel(w)) 0 else w.parent);
            if (n == 0) return 0;
            if (uCmd == GW_HWNDFIRST) return list[0];
            if (uCmd == GW_HWNDLAST) return list[n - 1];
            for (list[0..n], 0..) |x, i| {
                if (x != hWnd) continue;
                if (uCmd == GW_HWNDNEXT) return if (i + 1 < n) list[i + 1] else 0;
                return if (i > 0) list[i - 1] else 0;
            }
            return 0;
        },
        else => {
            setLastError(ERROR_INVALID_PARAMETER);
            return 0;
        },
    }
}

fn enumDescendants(parent: usize, f: EnumProc, lp: usize) ?bool {
    var list: [MAX_WINDOWS]usize = undefined;
    const n = listChildren(&list, parent);
    if (n == 0) return null;
    for (list[0..n]) |h| {
        if (win(h) == null) continue;
        if (f(h, lp) == 0) return false;
        if (enumDescendants(h, f, lp)) |r| if (!r) return false;
    }
    return true;
}

pub fn EnumChildWindows(hWndParent: usize, lpEnumFunc: ?*const anyopaque, lParam: usize) callconv(W) i32 {
    const f: EnumProc = @ptrCast(lpEnumFunc orelse return 0);
    const parent = if (hWndParent == HWND_DESKTOP) 0 else hWndParent;
    // Wine answers FALSE when there is no child to enumerate.
    const r = enumDescendants(parent, f, lParam) orelse return 0;
    return @intFromBool(r);
}

pub fn EnumWindows(lpEnumFunc: ?*const anyopaque, lParam: usize) callconv(W) i32 {
    const f: EnumProc = @ptrCast(lpEnumFunc orelse return 0);
    var list: [MAX_WINDOWS]usize = undefined;
    const n = listChildren(&list, 0);
    for (list[0..n]) |h| {
        if (win(h) == null) continue;
        if (f(h, lParam) == 0) return 0;
    }
    return 1;
}

pub fn EnableWindow(hWnd: usize, bEnable: i32) callconv(W) i32 {
    const w = win(hWnd) orelse return 0;
    const was_disabled = (w.style & WS_DISABLED) != 0;
    if (bEnable != 0) w.style &= ~WS_DISABLED else w.style |= WS_DISABLED;
    return @intFromBool(was_disabled);
}

// ---------------------------------------------------------------------------
// Painting API
// ---------------------------------------------------------------------------

pub fn UpdateWindow(hWnd: usize) callconv(W) i32 {
    const w = win(hWnd) orelse {
        setLastError(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    };
    if (w.invalid and isVisible(hWnd)) _ = send(hWnd, WM_PAINT, 0, 0);
    return 1;
}

pub fn InvalidateRect(hWnd: usize, lpRect: ?*const RECT, bErase: i32) callconv(W) i32 {
    _ = lpRect;
    const w = win(hWnd) orelse return @intFromBool(hWnd == 0);
    w.invalid = true;
    if (bErase != 0) w.need_erase = true;
    wake();
    return 1;
}

pub fn ValidateRect(hWnd: usize, lpRect: ?*const RECT) callconv(W) i32 {
    _ = lpRect;
    const w = win(hWnd) orelse return @intFromBool(hWnd == 0);
    w.invalid = false;
    w.need_erase = false;
    return 1;
}

pub fn BeginPaint(hWnd: usize, lpPaint: ?*PAINTSTRUCT) callconv(W) usize {
    const w = win(hWnd) orelse return 0;
    const erase = w.need_erase;
    w.invalid = false;
    w.need_erase = false;
    var erased: usize = 0;
    if (erase) erased = send(hWnd, WM_ERASEBKGND, PLACEHOLDER_HDC, 0);
    if (lpPaint) |ps| {
        ps.* = std.mem.zeroes(PAINTSTRUCT);
        ps.hdc = PLACEHOLDER_HDC;
        ps.fErase = @intFromBool(erase and erased == 0);
        if (win(hWnd)) |w2| ps.rcPaint = .{ .left = 0, .top = 0, .right = width(w2.client), .bottom = height(w2.client) };
    }
    return PLACEHOLDER_HDC;
}

pub fn EndPaint(hWnd: usize, lpPaint: ?*const PAINTSTRUCT) callconv(W) i32 {
    _ = hWnd;
    _ = lpPaint;
    return 1;
}

// ---------------------------------------------------------------------------
// DefWindowProcA
// ---------------------------------------------------------------------------

pub fn DefWindowProcA(hWnd: usize, Msg: u32, wParam: usize, lParam: usize) callconv(W) usize {
    switch (Msg) {
        WM_NCCREATE => {
            const cs: *const CREATESTRUCTA = @ptrFromInt(lParam);
            if (win(hWnd)) |w| setText(w, if (cs.lpszName != 0 and cs.lpszName >= 0x10000) @ptrFromInt(cs.lpszName) else null);
            return 1;
        },
        WM_NCCALCSIZE => {
            const w = win(hWnd) orelse return 0;
            if (wParam != 0) {
                const p: *NCCALCSIZE_PARAMS = @ptrFromInt(lParam);
                p.rgrc[0] = clientFromWindow(w, p.rgrc[0]);
            } else {
                const r: *RECT = @ptrFromInt(lParam);
                r.* = clientFromWindow(w, r.*);
            }
            return 0;
        },
        WM_WINDOWPOSCHANGING => {
            const pos: *WINDOWPOS = @ptrFromInt(lParam);
            const w = win(hWnd) orelse return 0;
            if ((pos.flags & SWP_NOSIZE) == 0 and wantsMinMax(w.style)) {
                var mmi = defaultMinMax(w);
                _ = send(hWnd, WM_GETMINMAXINFO, 0, @intFromPtr(&mmi));
                pos.cx = std.math.clamp(pos.cx, mmi.ptMinTrackSize.x, @max(mmi.ptMinTrackSize.x, mmi.ptMaxTrackSize.x));
                pos.cy = std.math.clamp(pos.cy, mmi.ptMinTrackSize.y, @max(mmi.ptMinTrackSize.y, mmi.ptMaxTrackSize.y));
            }
            return 0;
        },
        WM_WINDOWPOSCHANGED => {
            const pos: *const WINDOWPOS = @ptrFromInt(lParam);
            const w = win(hWnd) orelse return 0;
            if ((pos.flags & SWP_NOCLIENTMOVE) == 0) _ = send(hWnd, WM_MOVE, 0, makeLong(w.client.left, w.client.top));
            if ((pos.flags & SWP_NOCLIENTSIZE) == 0) {
                if (win(hWnd)) |w2| _ = send(hWnd, WM_SIZE, SIZE_RESTORED, makeLong(width(w2.client), height(w2.client)));
            }
            return 0;
        },
        WM_GETTEXT => {
            const w = win(hWnd) orelse return 0;
            if (wParam == 0 or lParam == 0) return 0;
            const buf: [*]u8 = @ptrFromInt(lParam);
            const len: usize = @min(wParam - 1, w.text_len);
            @memcpy(buf[0..len], w.text[0..len]);
            buf[len] = 0;
            return len;
        },
        WM_GETTEXTLENGTH => {
            const w = win(hWnd) orelse return 0;
            return w.text_len;
        },
        WM_SETTEXT => {
            const w = win(hWnd) orelse return 0;
            setText(w, if (lParam != 0) @ptrFromInt(lParam) else null);
            return 1;
        },
        WM_PAINT => {
            var ps: PAINTSTRUCT = undefined;
            _ = BeginPaint(hWnd, &ps);
            _ = EndPaint(hWnd, &ps);
            return 0;
        },
        WM_ERASEBKGND => {
            const w = win(hWnd) orelse return 0;
            return @intFromBool(g_classes[w.class].brush != 0);
        },
        WM_NCACTIVATE => return 1,
        WM_ACTIVATE => {
            if ((wParam & 0xFFFF) != WA_INACTIVE and IsIconic(hWnd) == 0 and g_active == hWnd) _ = setFocusInternal(hWnd);
            return 0;
        },
        WM_CLOSE => {
            _ = DestroyWindow(hWnd);
            return 0;
        },
        WM_SYSCOMMAND => {
            if ((wParam & 0xFFF0) == SC_CLOSE) _ = send(hWnd, WM_CLOSE, 0, 0);
            return 0;
        },
        WM_NCHITTEST => return HTCLIENT,
        WM_SETCURSOR => return 0,
        WM_GETICON => return 0,
        else => return 0,
    }
}

// ---------------------------------------------------------------------------
// Message queue API
// ---------------------------------------------------------------------------

fn postTo(tid: u32, h: usize, msg: u32, wp: usize, lp: usize) bool {
    lock();
    defer unlock();
    const q = queueFor(tid, true) orelse return false;
    if (q.len >= QUEUE_LEN) {
        setLastError(1816); // ERROR_NOT_ENOUGH_QUOTA
        return false;
    }
    q.posted[q.len] = .{ .hwnd = h, .message = msg, .wParam = wp, .lParam = lp, .time = tickNow(), .pt = .{ .x = 0, .y = 0 } };
    q.len += 1;
    wake();
    return true;
}

pub fn PostMessageA(hWnd: usize, Msg: u32, wParam: usize, lParam: usize) callconv(W) i32 {
    if (hWnd == 0) return @intFromBool(postTo(tidNow(), 0, Msg, wParam, lParam));
    if (hWnd == HWND_BROADCAST) {
        var list: [MAX_WINDOWS]usize = undefined;
        const n = listTopLevel(&list, 0);
        for (list[0..n]) |h| {
            if (win(h)) |w| _ = postTo(w.tid, h, Msg, wParam, lParam);
        }
        return 1;
    }
    const w = win(hWnd) orelse {
        setLastError(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    };
    return @intFromBool(postTo(w.tid, hWnd, Msg, wParam, lParam));
}

pub fn PostThreadMessageA(idThread: u32, Msg: u32, wParam: usize, lParam: usize) callconv(W) i32 {
    return @intFromBool(postTo(idThread, 0, Msg, wParam, lParam));
}

pub fn PostQuitMessage(nExitCode: i32) callconv(W) void {
    lock();
    defer unlock();
    const q = queueFor(tidNow(), true) orelse return;
    q.quit = true;
    q.quit_code = @bitCast(@as(isize, nExitCode));
    wake();
}

pub fn SendMessageA(hWnd: usize, Msg: u32, wParam: usize, lParam: usize) callconv(W) usize {
    if (hWnd == HWND_BROADCAST) {
        var list: [MAX_WINDOWS]usize = undefined;
        const n = listTopLevel(&list, 0);
        for (list[0..n]) |h| _ = send(h, Msg, wParam, lParam);
        return 1;
    }
    if (win(hWnd) == null) {
        setLastError(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }
    return send(hWnd, Msg, wParam, lParam);
}

fn inRange(msg: u32, lo: u32, hi: u32) bool {
    if (lo == 0 and hi == 0) return true;
    if (hi < lo) return msg >= lo or msg <= hi; // Win32 wraps an inverted range
    return msg >= lo and msg <= hi;
}

fn hwndMatches(filter: usize, h: usize) bool {
    if (filter == 0) return true;
    if (filter == HWND_MESSAGE_FILTER) return h == 0;
    return h == filter or isChildOf(filter, h);
}

/// One non-blocking look at the calling thread's queue.
fn peekOnce(out: *MSG, filter: usize, lo: u32, hi: u32, remove: bool) bool {
    serveSent();
    lock();
    defer unlock();
    const tid = tidNow();
    const q = queueFor(tid, true) orelse return false;
    var i: usize = 0;
    while (i < q.len) : (i += 1) {
        const m = q.posted[i];
        if (!inRange(m.message, lo, hi) or !hwndMatches(filter, m.hwnd)) continue;
        out.* = m;
        if (remove) {
            std.mem.copyForwards(MSG, q.posted[i .. q.len - 1], q.posted[i + 1 .. q.len]);
            q.len -= 1;
        }
        return true;
    }
    if (q.quit and inRange(WM_QUIT, lo, hi)) {
        out.* = .{ .hwnd = 0, .message = WM_QUIT, .wParam = q.quit_code, .lParam = 0, .time = tickNow(), .pt = .{ .x = 0, .y = 0 } };
        if (remove) q.quit = false;
        return true;
    }
    if (inRange(WM_PAINT, lo, hi)) {
        for (&g_windows) |*w| {
            if (!w.used or w.destroying or w.tid != tid or !w.invalid) continue;
            if (!hwndMatches(filter, w.hwnd) or !isVisible(w.hwnd)) continue;
            out.* = .{ .hwnd = w.hwnd, .message = WM_PAINT, .wParam = 0, .lParam = 0, .time = tickNow(), .pt = .{ .x = 0, .y = 0 } };
            return true;
        }
    }
    return false;
}

pub fn PeekMessageA(lpMsg: ?*MSG, hWnd: usize, wMsgFilterMin: u32, wMsgFilterMax: u32, wRemoveMsg: u32) callconv(W) i32 {
    const out = lpMsg orelse return 0;
    return @intFromBool(peekOnce(out, hWnd, wMsgFilterMin, wMsgFilterMax, (wRemoveMsg & PM_REMOVE) != 0));
}

pub fn GetMessageA(lpMsg: ?*MSG, hWnd: usize, wMsgFilterMin: u32, wMsgFilterMax: u32) callconv(W) i32 {
    const out = lpMsg orelse return -1;
    if (hWnd != 0 and hWnd != HWND_MESSAGE_FILTER and win(hWnd) == null) {
        setLastError(ERROR_INVALID_WINDOW_HANDLE);
        return -1;
    }
    while (!peekOnce(out, hWnd, wMsgFilterMin, wMsgFilterMax, true)) {
        lock();
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(linux.CLOCK.REALTIME, &ts);
        ts.nsec += 100 * 1_000_000;
        if (ts.nsec >= 1_000_000_000) {
            ts.sec += 1;
            ts.nsec -= 1_000_000_000;
        }
        _ = c.pthread_cond_timedwait(&g_cv, &g_mu, @ptrCast(&ts));
        unlock();
    }
    return @intFromBool(out.message != WM_QUIT);
}

/// True when the calling thread has something PeekMessage would return.
pub fn queueHasInput() bool {
    var m: MSG = undefined;
    return peekOnce(&m, 0, 0, 0, false);
}

pub fn WaitMessage() callconv(W) i32 {
    while (!queueHasInput()) {
        lock();
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(linux.CLOCK.REALTIME, &ts);
        ts.nsec += 100 * 1_000_000;
        if (ts.nsec >= 1_000_000_000) {
            ts.sec += 1;
            ts.nsec -= 1_000_000_000;
        }
        _ = c.pthread_cond_timedwait(&g_cv, &g_mu, @ptrCast(&ts));
        unlock();
    }
    return 1;
}

/// Key state for GetKeyState/GetAsyncKeyState, indexed by virtual key.
var g_vk_down: [256]std.atomic.Value(bool) = [_]std.atomic.Value(bool){std.atomic.Value(bool).init(false)} ** 256;
/// Character the host layout produced for the last key-down of each scan
/// code (index: scan | extended << 8); 0 = none (TranslateMessage then makes
/// no WM_CHAR, as for arrows or F-keys on Windows).
var g_char_for_scan: [512]std.atomic.Value(u8) = [_]std.atomic.Value(u8){std.atomic.Value(u8).init(0)} ** 512;

const VK_SHIFT = 0x10;
const VK_CONTROL = 0x11;
const VK_MENU = 0x12;

/// Render thread: one key changed on the host window. `ch` is the
/// Windows-1252 character it types (0 for none).
pub fn hostKey(vk: u8, scan: u8, extended: bool, down: bool, ch: u8) void {
    if (vk == 0) return;
    const was = g_vk_down[vk].swap(down, .monotonic);
    if (!down and !was) return;
    const generic: u8 = switch (vk) {
        0xA0, 0xA1 => VK_SHIFT,
        0xA2, 0xA3 => VK_CONTROL,
        0xA4, 0xA5 => VK_MENU,
        else => 0,
    };
    if (generic != 0) {
        const other: u8 = vk ^ 1;
        g_vk_down[generic].store(down or g_vk_down[other].load(.monotonic), .monotonic);
    }
    const key_index: usize = @as(usize, scan) | (@as(usize, @intFromBool(extended)) << 8);
    if (down) g_char_for_scan[key_index].store(ch, .monotonic);
    const alt = g_vk_down[VK_MENU].load(.monotonic) and !g_vk_down[VK_CONTROL].load(.monotonic);
    const msg: u32 = if (down) (if (alt) WM_SYSKEYDOWN else WM_KEYDOWN) else (if (alt or generic == VK_MENU) WM_SYSKEYUP else WM_KEYUP);
    var lp: usize = 1 | (@as(usize, scan) << 16);
    if (extended) lp |= 1 << 24;
    if (alt) lp |= 1 << 29;
    if (was) lp |= 1 << 30; // previous state: down (autorepeat, or the release)
    if (!down) lp |= 1 << 31;
    const wp: usize = if (generic != 0) generic else vk;
    lock();
    const target = if (g_focus != 0) g_focus else g_active;
    const w = win(target);
    const tid = if (w) |x| x.tid else 0;
    unlock();
    if (w == null) return;
    lock();
    defer unlock();
    _ = postLocked(tid, target, msg, wp, lp);
}

fn postLocked(tid: u32, h: usize, msg: u32, wp: usize, lp: usize) bool {
    const q = queueFor(tid, true) orelse return false;
    if (q.len == QUEUE_LEN) return false;
    q.posted[q.len] = .{ .hwnd = h, .message = msg, .wParam = wp, .lParam = lp, .time = tickNow(), .pt = .{ .x = 0, .y = 0 } };
    q.len += 1;
    wake();
    return true;
}

/// WM_KEYDOWN / WM_SYSKEYDOWN with a character -> WM_CHAR / WM_SYSCHAR posted
/// to the same window, as Windows does; nonzero only when one was posted.
pub fn TranslateMessage(lpMsg: ?*const MSG) callconv(W) i32 {
    const m = lpMsg orelse return 0;
    if (m.message != WM_KEYDOWN and m.message != WM_SYSKEYDOWN) return 0;
    const key_index: usize = ((m.lParam >> 16) & 0xFF) | (((m.lParam >> 24) & 1) << 8);
    const ch = g_char_for_scan[key_index].load(.monotonic);
    if (ch == 0) return 0;
    const w = win(m.hwnd) orelse return 0;
    lock();
    defer unlock();
    return @intFromBool(postLocked(w.tid, m.hwnd, if (m.message == WM_SYSKEYDOWN) WM_SYSCHAR else WM_CHAR, ch, m.lParam));
}

pub fn GetKeyState(vk: i32) callconv(W) i16 {
    if (vk < 0 or vk > 255) return 0;
    return if (g_vk_down[@intCast(vk)].load(.monotonic)) @bitCast(@as(u16, 0x8000)) else 0;
}

pub fn GetAsyncKeyState(vk: i32) callconv(W) i16 {
    return GetKeyState(vk);
}

pub fn DispatchMessageA(lpMsg: ?*const MSG) callconv(W) usize {
    const m = lpMsg orelse return 0;
    if (m.message == WM_TIMER and m.lParam != 0) {
        const f: *const fn (usize, u32, usize, u32) callconv(W) void = @ptrFromInt(m.lParam);
        f(m.hwnd, m.message, m.wParam, tickNow());
        return 0;
    }
    if (m.hwnd == 0) return 0;
    const w = win(m.hwnd) orelse {
        setLastError(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    };
    if (w.tid != tidNow()) return 0;
    return send(m.hwnd, m.message, m.wParam, m.lParam);
}

pub fn GetQueueStatus(flags: u32) callconv(W) u32 {
    _ = flags;
    return @intFromBool(queueHasInput());
}

// ---------------------------------------------------------------------------
// Import table
// ---------------------------------------------------------------------------

pub fn lookup(name: []const u8) ?usize {
    const table = .{
        .{ "RegisterClassA", &RegisterClassA },
        .{ "RegisterClassExA", &RegisterClassExA },
        .{ "UnregisterClassA", &UnregisterClassA },
        .{ "GetClassNameA", &GetClassNameA },
        .{ "GetClassLongA", &GetClassLongA },
        .{ "CreateWindowExA", &CreateWindowExA },
        .{ "DestroyWindow", &DestroyWindow },
        .{ "DefWindowProcA", &DefWindowProcA },
        .{ "ShowWindow", &ShowWindow },
        .{ "UpdateWindow", &UpdateWindow },
        .{ "SetWindowPos", &SetWindowPos },
        .{ "MoveWindow", &MoveWindow },
        .{ "GetActiveWindow", &GetActiveWindow },
        .{ "SetActiveWindow", &SetActiveWindow },
        .{ "GetFocus", &GetFocus },
        .{ "SetFocus", &SetFocus },
        .{ "GetForegroundWindow", &GetForegroundWindow },
        .{ "SetForegroundWindow", &SetForegroundWindow },
        .{ "GetDesktopWindow", &GetDesktopWindow },
        .{ "IsWindow", &IsWindow },
        .{ "IsWindowVisible", &IsWindowVisible },
        .{ "IsIconic", &IsIconic },
        .{ "IsZoomed", &IsZoomed },
        .{ "IsWindowEnabled", &IsWindowEnabled },
        .{ "EnableWindow", &EnableWindow },
        .{ "IsChild", &IsChild },
        .{ "GetParent", &GetParent },
        .{ "GetWindowThreadProcessId", &GetWindowThreadProcessId },
        .{ "GetClientRect", &GetClientRect },
        .{ "GetWindowRect", &GetWindowRect },
        .{ "ClientToScreen", &ClientToScreen },
        .{ "ScreenToClient", &ScreenToClient },
        .{ "AdjustWindowRect", &AdjustWindowRect },
        .{ "AdjustWindowRectEx", &AdjustWindowRectEx },
        .{ "GetWindowLongA", &GetWindowLongA },
        .{ "SetWindowLongA", &SetWindowLongA },
        .{ "GetWindowTextA", &GetWindowTextA },
        .{ "GetWindowTextLengthA", &GetWindowTextLengthA },
        .{ "SetWindowTextA", &SetWindowTextA },
        .{ "FindWindowA", &FindWindowA },
        .{ "GetWindow", &GetWindow },
        .{ "EnumChildWindows", &EnumChildWindows },
        .{ "EnumWindows", &EnumWindows },
        .{ "InvalidateRect", &InvalidateRect },
        .{ "ValidateRect", &ValidateRect },
        .{ "BeginPaint", &BeginPaint },
        .{ "EndPaint", &EndPaint },
        .{ "PostMessageA", &PostMessageA },
        .{ "PostThreadMessageA", &PostThreadMessageA },
        .{ "PostQuitMessage", &PostQuitMessage },
        .{ "SendMessageA", &SendMessageA },
        .{ "PeekMessageA", &PeekMessageA },
        .{ "GetMessageA", &GetMessageA },
        .{ "WaitMessage", &WaitMessage },
        .{ "TranslateMessage", &TranslateMessage },
        .{ "DispatchMessageA", &DispatchMessageA },
        .{ "GetQueueStatus", &GetQueueStatus },
    };
    inline for (table) |e| {
        if (std.mem.eql(u8, name, e[0])) return @intFromPtr(e[1]);
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tests (host-side: the window procedure is a Zig function with the Win32 ABI)
// ---------------------------------------------------------------------------

var t_log: [64]u32 = undefined;
var t_n: usize = 0;

fn testProc(h: usize, m: u32, wp: usize, lp: usize) callconv(W) usize {
    if (t_n < t_log.len) {
        t_log[t_n] = m;
        t_n += 1;
    }
    return DefWindowProcA(h, m, wp, lp);
}

test "AdjustWindowRectEx matches Wine's metrics" {
    var r = RECT{ .left = 0, .top = 0, .right = 1280, .bottom = 720 };
    adjustRect(&r, 0x00CF0000, false, 0); // WS_OVERLAPPEDWINDOW
    try std.testing.expectEqual(RECT{ .left = -4, .top = -30, .right = 1284, .bottom = 724 }, r);
    r = .{ .left = 0, .top = 0, .right = 1280, .bottom = 720 };
    adjustRect(&r, WS_CAPTION | 0x00080000, true, 0);
    try std.testing.expectEqual(RECT{ .left = -3, .top = -48, .right = 1283, .bottom = 723 }, r);
    r = .{ .left = 0, .top = 0, .right = 1280, .bottom = 720 };
    adjustRect(&r, WS_BORDER, false, WS_EX_STATICEDGE);
    try std.testing.expectEqual(RECT{ .left = -2, .top = -2, .right = 1282, .bottom = 722 }, r);
}

test "show activates, the window procedure sees the Win32 order" {
    const name: [*:0]const u8 = "WinsTestClass";
    var wc = std.mem.zeroes(WNDCLASSA);
    wc.lpfnWndProc = @intFromPtr(&testProc);
    wc.lpszClassName = @intFromPtr(name);
    try std.testing.expect(RegisterClassA(&wc) != 0);
    const h = CreateWindowExA(0, @intFromPtr(name), "t", WS_CAPTION, 0, 0, 640, 480, 0, 0, 0, 0);
    try std.testing.expect(h != 0);
    try std.testing.expectEqual(@as(usize, 0), GetActiveWindow());
    t_n = 0;
    try std.testing.expectEqual(@as(i32, 0), ShowWindow(h, SW_SHOW));
    const want = [_]u32{ 0x18, 0x46, 0x7f, 0x7f, 0x30f, 0x1c, 0x86, 0x6, 0x281, 0x7, 0x85, 0x14, 0x47, 0x5, 0x3 };
    try std.testing.expectEqualSlices(u32, &want, t_log[0..t_n]);
    try std.testing.expectEqual(h, GetActiveWindow());
    try std.testing.expectEqual(h, GetFocus());
    try std.testing.expectEqual(@as(i32, 1), DestroyWindow(h));
    try std.testing.expectEqual(@as(usize, 0), GetActiveWindow());
}

test "host keys: GetKeyState follows down/up, left/right Shift feed VK_SHIFT, no window means no message" {
    hostKey(0xA0, 0x2A, false, true, 0); // left shift down
    hostKey(0xA1, 0x36, false, true, 0); // right shift down
    try std.testing.expect(GetKeyState(VK_SHIFT) < 0);
    hostKey(0xA0, 0x2A, false, false, 0);
    try std.testing.expect(GetKeyState(VK_SHIFT) < 0); // right still held
    hostKey(0xA1, 0x36, false, false, 0);
    try std.testing.expectEqual(@as(i16, 0), GetKeyState(VK_SHIFT));
    hostKey('A', 0x1E, false, true, 'a');
    try std.testing.expect(GetAsyncKeyState('A') < 0);
    hostKey('A', 0x1E, false, false, 0);
    try std.testing.expectEqual(@as(i16, 0), GetAsyncKeyState('A'));
    try std.testing.expectEqual(@as(i16, 0), GetKeyState(-1));
}
