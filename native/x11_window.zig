//! Small X11 window primitive. This is not a Win32 USER32 implementation.
//! Callers must provide an isolated display; it never chooses a host display.
const Display = opaque {};
const Window = c_ulong;
extern "X11" fn XOpenDisplay(?[*:0]const u8) ?*Display;
extern "X11" fn XCloseDisplay(*Display) c_int;
extern "X11" fn XDefaultRootWindow(*Display) Window;
extern "X11" fn XCreateSimpleWindow(*Display, Window, c_int, c_int, c_uint, c_uint, c_uint, c_ulong, c_ulong) Window;
extern "X11" fn XMapWindow(*Display, Window) c_int;
extern "X11" fn XDestroyWindow(*Display, Window) c_int;
extern "X11" fn XSync(*Display, c_int) c_int;
extern "X11" fn XGetGeometry(*Display, Window, *Window, *c_int, *c_int, *c_uint, *c_uint, *c_uint, *c_uint) c_int;

pub const Geometry = struct { width: u32, height: u32 };
pub const Connection = struct {
    display: *Display,

    pub fn open(display_name: [*:0]const u8) !Connection {
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

    pub fn destroy(self: Connection, window: Window) void {
        _ = XDestroyWindow(self.display, window);
        _ = XSync(self.display, 0);
    }
};
