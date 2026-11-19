//! Small X11 window primitive. This is not a Win32 USER32 implementation.
//! Callers must provide an isolated display; it never chooses a host display.
const std = @import("std");
const Display = opaque {};
pub const Window = c_ulong;
const GC = ?*anyopaque;
const Visual = opaque {};
const Atom = c_ulong;

pub const XEvent = extern struct {
    type: c_int,
    pad: [23]c_long,
};

pub const XAnyEvent = extern struct {
    type: c_int,
    serial: c_ulong,
    send_event: c_int,
    display: ?*Display,
    window: Window,
};

pub const XConfigureEvent = extern struct {
    type: c_int,
    serial: c_ulong,
    send_event: c_int,
    display: ?*Display,
    event: Window,
    window: Window,
    x: c_int,
    y: c_int,
    width: c_int,
    height: c_int,
    border_width: c_int,
    above: Window,
    override_redirect: c_int,
};

pub const XKeyEvent = extern struct {
    type: c_int,
    serial: c_ulong,
    send_event: c_int,
    display: ?*Display,
    window: Window,
    root: Window,
    subwindow: Window,
    time: c_ulong,
    x: c_int,
    y: c_int,
    x_root: c_int,
    y_root: c_int,
    state: c_uint,
    keycode: c_uint,
    same_screen: c_int,
};

pub const XButtonEvent = extern struct {
    type: c_int,
    serial: c_ulong,
    send_event: c_int,
    display: ?*Display,
    window: Window,
    root: Window,
    subwindow: Window,
    time: c_ulong,
    x: c_int,
    y: c_int,
    x_root: c_int,
    y_root: c_int,
    state: c_uint,
    button: c_uint,
    same_screen: c_int,
};

pub const XClientMessageEvent = extern struct {
    type: c_int,
    serial: c_ulong,
    send_event: c_int,
    display: ?*Display,
    window: Window,
    message_type: Atom,
    format: c_int,
    data: [5]c_long,
};

const XImage = extern struct {
    width: c_int,
    height: c_int,
    xoffset: c_int,
    format: c_int,
    data: ?[*]u8,
    byte_order: c_int,
    bitmap_unit: c_int,
    bitmap_bit_order: c_int,
    bitmap_pad: c_int,
    depth: c_int,
    bytes_per_line: c_int,
    bits_per_pixel: c_int,
    red_mask: c_ulong,
    green_mask: c_ulong,
    blue_mask: c_ulong,
    obdata: ?*anyopaque,
    f: [8]?*const anyopaque,
};

extern "X11" fn XInitThreads() c_int;
extern "X11" fn XOpenDisplay(?[*:0]const u8) ?*Display;
extern "X11" fn XCloseDisplay(*Display) c_int;
extern "X11" fn XDefaultRootWindow(*Display) Window;
extern "X11" fn XDefaultScreen(*Display) c_int;
extern "X11" fn XDefaultVisual(*Display, c_int) *Visual;
extern "X11" fn XDefaultDepth(*Display, c_int) c_int;
extern "X11" fn XCreateSimpleWindow(*Display, Window, c_int, c_int, c_uint, c_uint, c_uint, c_ulong, c_ulong) Window;
extern "X11" fn XMapWindow(*Display, Window) c_int;
extern "X11" fn XUnmapWindow(*Display, Window) c_int;
extern "X11" fn XDestroyWindow(*Display, Window) c_int;
extern "X11" fn XMoveResizeWindow(*Display, Window, c_int, c_int, c_uint, c_uint) c_int;
extern "X11" fn XStoreName(*Display, Window, [*:0]const u8) c_int;
extern "X11" fn XSelectInput(*Display, Window, c_long) c_int;
extern "X11" fn XInternAtom(*Display, [*:0]const u8, c_int) Atom;
extern "X11" fn XSetWMProtocols(*Display, Window, [*]Atom, c_int) c_int;
extern "X11" fn XPending(*Display) c_int;
extern "X11" fn XNextEvent(*Display, *XEvent) c_int;
extern "X11" fn XConnectionNumber(*Display) c_int;
extern "X11" fn XSync(*Display, c_int) c_int;
extern "X11" fn XFlush(*Display) c_int;
extern "X11" fn XGetGeometry(*Display, Window, *Window, *c_int, *c_int, *c_uint, *c_uint, *c_uint, *c_uint) c_int;
extern "X11" fn XCreateGC(*Display, Window, c_ulong, ?*anyopaque) GC;
extern "X11" fn XFreeGC(*Display, GC) c_int;
extern "X11" fn XCreateImage(*Display, *Visual, c_uint, c_int, c_int, ?[*]u8, c_uint, c_uint, c_int, c_int) ?*XImage;
extern "X11" fn XPutImage(*Display, Window, GC, *XImage, c_int, c_int, c_int, c_int, c_uint, c_uint) c_int;
extern "X11" fn XDestroyImage(*XImage) c_int;

var xinit_done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

pub const Geometry = struct { width: u32, height: u32 };
pub const Connection = struct {
    display: *Display,

    pub fn open(display_name: [*:0]const u8) !Connection {
        if (!xinit_done.swap(true, .acq_rel)) {
            _ = XInitThreads();
        }
        return .{ .display = XOpenDisplay(display_name) orelse return error.DisplayUnavailable };
    }

    pub fn close(self: Connection) void {
        _ = XCloseDisplay(self.display);
    }

    pub fn create(self: Connection, width: u32, height: u32) !Window {
        if (width == 0 or height == 0 or width > 65535 or height > 65535) return error.InvalidSize;
        const window = XCreateSimpleWindow(self.display, XDefaultRootWindow(self.display), 0, 0, width, height, 0, 0, 0);
        if (window == 0) return error.CreateFailed;
        _ = XMapWindow(self.display, window);
        _ = XSync(self.display, 0);
        return window;
    }

    pub fn createUnmapped(self: Connection, x: i32, y: i32, width: u32, height: u32) !Window {
        if (width == 0 or height == 0 or width > 65535 or height > 65535) return error.InvalidSize;
        const window = XCreateSimpleWindow(self.display, XDefaultRootWindow(self.display), x, y, width, height, 0, 0x000000, 0xf0f0f0);
        if (window == 0) return error.CreateFailed;
        const mask: c_long = (1 << 15) | (1 << 17) | (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 6); // Exposure | StructureNotify | Key/Button/Pointer
        _ = XSelectInput(self.display, window, mask);
        var wm_delete = XInternAtom(self.display, "WM_DELETE_WINDOW", 0);
        if (wm_delete != 0) {
            _ = XSetWMProtocols(self.display, window, @ptrCast(&wm_delete), 1);
        }
        _ = XSync(self.display, 0);
        return window;
    }

    pub fn setTitle(self: Connection, window: Window, title: [*:0]const u8) void {
        _ = XStoreName(self.display, window, title);
        _ = XFlush(self.display);
    }

    pub fn moveResize(self: Connection, window: Window, x: i32, y: i32, width: u32, height: u32) void {
        if (width == 0 or height == 0) return;
        _ = XMoveResizeWindow(self.display, window, x, y, width, height);
        _ = XFlush(self.display);
    }

    pub fn wmDeleteAtom(self: Connection) Atom {
        return XInternAtom(self.display, "WM_DELETE_WINDOW", 0);
    }

    pub fn pending(self: Connection) c_int {
        return XPending(self.display);
    }

    pub fn fd(self: Connection) c_int {
        return XConnectionNumber(self.display);
    }

    pub fn nextEvent(self: Connection, ev: *XEvent) void {
        _ = XNextEvent(self.display, ev);
    }

    pub fn flush(self: Connection) void {
        _ = XFlush(self.display);
    }

    pub fn blitBgrx32(self: Connection, window: Window, width: u32, height: u32, pixels: [*]u8) void {
        if (window == 0 or width == 0 or height == 0) return;
        const screen = XDefaultScreen(self.display);
        const visual = XDefaultVisual(self.display, screen);
        const depth = XDefaultDepth(self.display, screen);
        const img = XCreateImage(self.display, visual, @intCast(depth), 2, 0, pixels, width, height, 32, @intCast(width * 4)) orelse return;
        const gc = XCreateGC(self.display, window, 0, null);
        if (gc != null) {
            _ = XPutImage(self.display, window, gc, img, 0, 0, 0, 0, width, height);
            _ = XFreeGC(self.display, gc);
        }
        img.data = null;
        _ = XDestroyImage(img);
        _ = XFlush(self.display);
    }

    pub fn geometry(self: Connection, window: Window) !Geometry {
        var root: Window = 0;
        var x: c_int = 0;
        var y: c_int = 0;
        var width: c_uint = 0;
        var height: c_uint = 0;
        var border: c_uint = 0;
        var depth: c_uint = 0;
        if (XGetGeometry(self.display, window, &root, &x, &y, &width, &height, &border, &depth) == 0) return error.GeometryFailed;
        return .{ .width = width, .height = height };
    }

    pub fn map(self: Connection, window: Window) void {
        _ = XMapWindow(self.display, window);
        _ = XSync(self.display, 0);
    }

    pub fn unmap(self: Connection, window: Window) void {
        _ = XUnmapWindow(self.display, window);
        _ = XSync(self.display, 0);
    }

    pub fn destroy(self: Connection, window: Window) void {
        _ = XDestroyWindow(self.display, window);
        _ = XSync(self.display, 0);
    }
};
