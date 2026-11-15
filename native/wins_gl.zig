//! Host presentation surface: one X11 window with an OpenGL context, owned by
//! one native render thread.
//!
//! Guest threads never touch Xlib or GL. They hand a job to the render thread
//! and wait for it (`run`): the context stays on the thread that created it,
//! the host libraries run on a native, properly aligned stack, and the guest's
//! own stack is not involved at all.
//!
//! libX11 and libGL are opened with dlopen, like the audio bridges: the loader
//! still starts on a machine (or in a test) without a display.

const std = @import("std");
const linux = std.os.linux;
const input = @import("wins_dinput.zig");
const user32 = @import("wins_user32.zig");

extern fn dlopen(path: [*:0]const u8, flags: c_int) ?*anyopaque;
extern fn dlsym(handle: ?*anyopaque, name: [*:0]const u8) ?*anyopaque;

pub const GLenum = c_uint;
pub const GLuint = c_uint;
pub const GLint = c_int;
pub const GLsizei = c_int;

const Xlib = struct {
    XInitThreads: *const fn () callconv(.c) c_int,
    XOpenDisplay: *const fn (?[*:0]const u8) callconv(.c) ?*anyopaque,
    XDefaultScreen: *const fn (?*anyopaque) callconv(.c) c_int,
    XRootWindow: *const fn (?*anyopaque, c_int) callconv(.c) c_ulong,
    XCreateColormap: *const fn (?*anyopaque, c_ulong, ?*anyopaque, c_int) callconv(.c) c_ulong,
    XCreateWindow: *const fn (?*anyopaque, c_ulong, c_int, c_int, c_uint, c_uint, c_uint, c_int, c_uint, ?*anyopaque, c_ulong, *XSetWindowAttributes) callconv(.c) c_ulong,
    XMapWindow: *const fn (?*anyopaque, c_ulong) callconv(.c) c_int,
    XStoreName: *const fn (?*anyopaque, c_ulong, [*:0]const u8) callconv(.c) c_int,
    XFlush: *const fn (?*anyopaque) callconv(.c) c_int,
    XSync: *const fn (?*anyopaque, c_int) callconv(.c) c_int,
    XSelectInput: *const fn (?*anyopaque, c_ulong, c_long) callconv(.c) c_int,
    XPending: *const fn (?*anyopaque) callconv(.c) c_int,
    XNextEvent: *const fn (?*anyopaque, *XEvent) callconv(.c) c_int,
    XWarpPointer: *const fn (?*anyopaque, c_ulong, c_ulong, c_int, c_int, c_uint, c_uint, c_int, c_int) callconv(.c) c_int,
    XCreateBitmapFromData: *const fn (?*anyopaque, c_ulong, [*]const u8, c_uint, c_uint) callconv(.c) c_ulong,
    XCreatePixmapCursor: *const fn (?*anyopaque, c_ulong, c_ulong, *XColor, *XColor, c_uint, c_uint) callconv(.c) c_ulong,
    XDefineCursor: *const fn (?*anyopaque, c_ulong, c_ulong) callconv(.c) c_int,
    XkbSetDetectableAutoRepeat: *const fn (?*anyopaque, c_int, ?*c_int) callconv(.c) c_int,
    XLookupString: *const fn (*XEvent, [*]u8, c_int, ?*c_ulong, ?*anyopaque) callconv(.c) c_int,
    XLookupKeysym: *const fn (*XEvent, c_int) callconv(.c) c_ulong,
};

/// Unshifted X keysym -> Windows virtual key (US-style mapping for the
/// punctuation keys, as Windows uses for the OEM keys).
fn vkFromKeysym(ks: c_ulong) u8 {
    if (ks >= 'a' and ks <= 'z') return @intCast(ks - 'a' + 'A');
    if (ks >= 'A' and ks <= 'Z') return @intCast(ks);
    if (ks >= '0' and ks <= '9') return @intCast(ks);
    if (ks >= 0xffbe and ks <= 0xffc9) return @intCast(0x70 + (ks - 0xffbe)); // F1..F12
    if (ks >= 0xffb0 and ks <= 0xffb9) return @intCast(0x60 + (ks - 0xffb0)); // keypad 0..9
    return switch (ks) {
        0x20 => 0x20,
        0xff08 => 0x08, // BackSpace
        0xff09 => 0x09, // Tab
        0xff0d, 0xff8d => 0x0D, // Return, KP_Enter
        0xff1b => 0x1B, // Escape
        0xff13 => 0x13, // Pause
        0xff50 => 0x24, // Home
        0xff51 => 0x25, // Left
        0xff52 => 0x26, // Up
        0xff53 => 0x27, // Right
        0xff54 => 0x28, // Down
        0xff55 => 0x21, // Prior
        0xff56 => 0x22, // Next
        0xff57 => 0x23, // End
        0xff63 => 0x2D, // Insert
        0xffff => 0x2E, // Delete
        0xffe1 => 0xA0, // Shift_L
        0xffe2 => 0xA1, // Shift_R
        0xffe3 => 0xA2, // Control_L
        0xffe4 => 0xA3, // Control_R
        0xffe9, 0xff7e => 0xA4, // Alt_L
        0xffea, 0xfe03 => 0xA5, // Alt_R / ISO_Level3_Shift (AltGr)
        0xffe5 => 0x14, // Caps_Lock
        0xffeb => 0x5B, // Super_L
        0xffec => 0x5C, // Super_R
        0xff67 => 0x5D, // Menu
        0xffaa => 0x6A, // KP_Multiply
        0xffab => 0x6B, // KP_Add
        0xffad => 0x6D, // KP_Subtract
        0xffae => 0x6E, // KP_Decimal
        0xffaf => 0x6F, // KP_Divide
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
        0xf1, 0xd1 => 0xC0, // ntilde on Spanish layouts sits on the OEM_3 key
        else => 0,
    };
}

/// XEvent is a union of 24 longs; only the common key/button/motion prefix is read.
const XEvent = extern struct {
    type: c_int,
    serial: c_ulong,
    send_event: c_int,
    display: ?*anyopaque,
    window: c_ulong,
    root: c_ulong,
    subwindow: c_ulong,
    time: c_ulong,
    x: c_int,
    y: c_int,
    x_root: c_int,
    y_root: c_int,
    state: c_uint,
    detail: c_uint, // keycode or button
    pad: [24 - 14]c_long,
};

const XColor = extern struct { pixel: c_ulong = 0, red: u16 = 0, green: u16 = 0, blue: u16 = 0, flags: u8 = 0, pad: u8 = 0 };

const Glx = struct {
    glXChooseVisual: *const fn (?*anyopaque, c_int, [*]const c_int) callconv(.c) ?*XVisualInfo,
    glXCreateContext: *const fn (?*anyopaque, *XVisualInfo, ?*anyopaque, c_int) callconv(.c) ?*anyopaque,
    glXMakeCurrent: *const fn (?*anyopaque, c_ulong, ?*anyopaque) callconv(.c) c_int,
    glXSwapBuffers: *const fn (?*anyopaque, c_ulong) callconv(.c) void,
    glXGetProcAddressARB: *const fn ([*:0]const u8) callconv(.c) ?*anyopaque,
};

const XVisualInfo = extern struct {
    visual: ?*anyopaque,
    visualid: c_ulong,
    screen: c_int,
    depth: c_int,
    class: c_int,
    red_mask: c_ulong,
    green_mask: c_ulong,
    blue_mask: c_ulong,
    colormap_size: c_int,
    bits_per_rgb: c_int,
};

const XSetWindowAttributes = extern struct {
    background_pixmap: c_ulong = 0,
    background_pixel: c_ulong = 0,
    border_pixmap: c_ulong = 0,
    border_pixel: c_ulong = 0,
    bit_gravity: c_int = 0,
    win_gravity: c_int = 0,
    backing_store: c_int = 0,
    backing_planes: c_ulong = 0,
    backing_pixel: c_ulong = 0,
    save_under: c_int = 0,
    event_mask: c_long = 0,
    do_not_propagate_mask: c_long = 0,
    override_redirect: c_int = 0,
    colormap: c_ulong = 0,
    cursor: c_ulong = 0,
};

/// The OpenGL entry points the Direct3D backend uses (compatibility profile).
pub const Gl = struct {
    glGetString: *const fn (GLenum) callconv(.c) ?[*:0]const u8,
    glGetError: *const fn () callconv(.c) GLenum,
    glViewport: *const fn (GLint, GLint, GLsizei, GLsizei) callconv(.c) void,
    glScissor: *const fn (GLint, GLint, GLsizei, GLsizei) callconv(.c) void,
    glDepthRange: *const fn (f64, f64) callconv(.c) void,
    glEnable: *const fn (GLenum) callconv(.c) void,
    glDisable: *const fn (GLenum) callconv(.c) void,
    glClearColor: *const fn (f32, f32, f32, f32) callconv(.c) void,
    glClearDepth: *const fn (f64) callconv(.c) void,
    glClearStencil: *const fn (GLint) callconv(.c) void,
    glClear: *const fn (c_uint) callconv(.c) void,
    glColorMask: *const fn (u8, u8, u8, u8) callconv(.c) void,
    glDepthMask: *const fn (u8) callconv(.c) void,
    glDepthFunc: *const fn (GLenum) callconv(.c) void,
    glStencilMask: *const fn (GLuint) callconv(.c) void,
    glStencilFunc: *const fn (GLenum, GLint, GLuint) callconv(.c) void,
    glStencilOp: *const fn (GLenum, GLenum, GLenum) callconv(.c) void,
    glAlphaFunc: *const fn (GLenum, f32) callconv(.c) void,
    glBlendFuncSeparate: *const fn (GLenum, GLenum, GLenum, GLenum) callconv(.c) void,
    glBlendEquationSeparate: *const fn (GLenum, GLenum) callconv(.c) void,
    glCullFace: *const fn (GLenum) callconv(.c) void,
    glFrontFace: *const fn (GLenum) callconv(.c) void,
    glPolygonMode: *const fn (GLenum, GLenum) callconv(.c) void,
    glPixelStorei: *const fn (GLenum, GLint) callconv(.c) void,
    glReadPixels: *const fn (GLint, GLint, GLsizei, GLsizei, GLenum, GLenum, ?*anyopaque) callconv(.c) void,
    glFinish: *const fn () callconv(.c) void,
    glClipControl: *const fn (GLenum, GLenum) callconv(.c) void,

    glGenTextures: *const fn (GLsizei, *GLuint) callconv(.c) void,
    glDeleteTextures: *const fn (GLsizei, *const GLuint) callconv(.c) void,
    glBindTexture: *const fn (GLenum, GLuint) callconv(.c) void,
    glActiveTexture: *const fn (GLenum) callconv(.c) void,
    glTexParameteri: *const fn (GLenum, GLenum, GLint) callconv(.c) void,
    glTexImage2D: *const fn (GLenum, GLint, GLint, GLsizei, GLsizei, GLint, GLenum, GLenum, ?*const anyopaque) callconv(.c) void,
    glCompressedTexImage2D: *const fn (GLenum, GLint, GLenum, GLsizei, GLsizei, GLint, GLsizei, ?*const anyopaque) callconv(.c) void,

    glCreateShader: *const fn (GLenum) callconv(.c) GLuint,
    glShaderSource: *const fn (GLuint, GLsizei, *const [*:0]const u8, ?*const GLint) callconv(.c) void,
    glCompileShader: *const fn (GLuint) callconv(.c) void,
    glGetShaderiv: *const fn (GLuint, GLenum, *GLint) callconv(.c) void,
    glGetShaderInfoLog: *const fn (GLuint, GLsizei, ?*GLsizei, [*]u8) callconv(.c) void,
    glDeleteShader: *const fn (GLuint) callconv(.c) void,
    glCreateProgram: *const fn () callconv(.c) GLuint,
    glAttachShader: *const fn (GLuint, GLuint) callconv(.c) void,
    glBindAttribLocation: *const fn (GLuint, GLuint, [*:0]const u8) callconv(.c) void,
    glLinkProgram: *const fn (GLuint) callconv(.c) void,
    glGetProgramiv: *const fn (GLuint, GLenum, *GLint) callconv(.c) void,
    glGetProgramInfoLog: *const fn (GLuint, GLsizei, ?*GLsizei, [*]u8) callconv(.c) void,
    glUseProgram: *const fn (GLuint) callconv(.c) void,
    glGetUniformLocation: *const fn (GLuint, [*:0]const u8) callconv(.c) GLint,
    glUniform4fv: *const fn (GLint, GLsizei, [*]const f32) callconv(.c) void,
    glUniform4iv: *const fn (GLint, GLsizei, [*]const i32) callconv(.c) void,
    glUniform1i: *const fn (GLint, GLint) callconv(.c) void,
    glUniform2f: *const fn (GLint, f32, f32) callconv(.c) void,
    glUniformMatrix4fv: *const fn (GLint, GLsizei, u8, *const [16]f32) callconv(.c) void,

    glBindBuffer: *const fn (GLenum, GLuint) callconv(.c) void,
    glEnableVertexAttribArray: *const fn (GLuint) callconv(.c) void,
    glDisableVertexAttribArray: *const fn (GLuint) callconv(.c) void,
    glVertexAttribPointer: *const fn (GLuint, GLint, GLenum, u8, GLsizei, ?*const anyopaque) callconv(.c) void,
    glVertexAttrib4f: *const fn (GLuint, f32, f32, f32, f32) callconv(.c) void,
    glDrawArrays: *const fn (GLenum, GLint, GLsizei) callconv(.c) void,
    glDrawElements: *const fn (GLenum, GLsizei, GLenum, ?*const anyopaque) callconv(.c) void,
    glDrawRangeElements: *const fn (GLenum, GLuint, GLuint, GLsizei, GLenum, ?*const anyopaque) callconv(.c) void,

    glGenFramebuffers: *const fn (GLsizei, *GLuint) callconv(.c) void,
    glBindFramebuffer: *const fn (GLenum, GLuint) callconv(.c) void,
    glFramebufferTexture2D: *const fn (GLenum, GLenum, GLenum, GLuint, GLint) callconv(.c) void,
    glGenRenderbuffers: *const fn (GLsizei, *GLuint) callconv(.c) void,
    glBindRenderbuffer: *const fn (GLenum, GLuint) callconv(.c) void,
    glRenderbufferStorage: *const fn (GLenum, GLenum, GLsizei, GLsizei) callconv(.c) void,
    glFramebufferRenderbuffer: *const fn (GLenum, GLenum, GLenum, GLuint) callconv(.c) void,
    glCheckFramebufferStatus: *const fn (GLenum) callconv(.c) GLenum,
    glDrawBuffers: *const fn (GLsizei, [*]const GLenum) callconv(.c) void,
    glBlitFramebuffer: *const fn (GLint, GLint, GLint, GLint, GLint, GLint, GLint, GLint, c_uint, GLenum) callconv(.c) void,

    glGenQueries: *const fn (GLsizei, *GLuint) callconv(.c) void,
    glDeleteQueries: *const fn (GLsizei, *const GLuint) callconv(.c) void,
    glBeginQuery: *const fn (GLenum, GLuint) callconv(.c) void,
    glEndQuery: *const fn (GLenum) callconv(.c) void,
    glGetQueryObjectuiv: *const fn (GLuint, GLenum, *GLuint) callconv(.c) void,
};

/// Valid on the render thread once `start` returned true.
pub var gl: Gl = undefined;
var xlib: Xlib = undefined;
var glx: Glx = undefined;
var g_display: ?*anyopaque = null;
var g_window: c_ulong = 0;
pub var width: u32 = 0;
pub var height: u32 = 0;

fn loadTable(comptime T: type, table: *T, lib: ?*anyopaque, comptime what: []const u8) bool {
    inline for (std.meta.fields(T)) |f| {
        const sym = dlsym(lib, f.name ++ "") orelse {
            std.debug.print("[WINS:GL] " ++ what ++ " has no symbol " ++ f.name ++ "\n", .{});
            return false;
        };
        @field(table, f.name) = @ptrCast(@alignCast(sym));
    }
    return true;
}

fn loadGl() bool {
    inline for (std.meta.fields(Gl)) |f| {
        const sym = glx.glXGetProcAddressARB(f.name ++ "") orelse {
            std.debug.print("[WINS:GL] this OpenGL implementation has no " ++ f.name ++ "\n", .{});
            return false;
        };
        @field(gl, f.name) = @ptrCast(@alignCast(sym));
    }
    return true;
}

// ---- job hand-off -----------------------------------------------------------

pub const JobFn = *const fn (ctx: ?*anyopaque) void;

var g_job_fn: ?JobFn = null;
var g_job_ctx: ?*anyopaque = null;
/// Jobs posted / jobs finished; a waiter sleeps on the word it is waiting for.
var g_posted = std.atomic.Value(u32).init(0);
var g_done = std.atomic.Value(u32).init(0);
/// 0 free, 1 held: one guest thread hands over a job at a time.
var g_submit = std.atomic.Value(u32).init(0);
/// 0 starting, 1 ready, 2 failed.
var g_state = std.atomic.Value(u32).init(0);
var g_started = false;

fn futexWait(word: *std.atomic.Value(u32), expect: u32) void {
    _ = linux.syscall4(.futex, @intFromPtr(word), 0, expect, 0); // FUTEX_WAIT, no timeout
}
fn futexWake(word: *std.atomic.Value(u32)) void {
    _ = linux.syscall3(.futex, @intFromPtr(word), 1, std.math.maxInt(i32)); // FUTEX_WAKE
}

/// Run `func(ctx)` on the render thread and wait until it returned. No-op when
/// there is no surface.
pub fn run(func: JobFn, ctx: ?*anyopaque) void {
    if (g_state.load(.acquire) != 1) return;
    while (g_submit.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) futexWait(&g_submit, 1);
    g_job_fn = func;
    g_job_ctx = ctx;
    const ticket = g_posted.fetchAdd(1, .release) +% 1;
    futexWake(&g_posted);
    // Most jobs are a single draw that takes microseconds: look for the answer
    // a little before sleeping, since a sleep and a wake cost more than the job.
    var spins: u32 = 0;
    while (true) {
        const done = g_done.load(.acquire);
        if (done == ticket) break;
        if (spins < SPIN_SUBMIT) {
            spins += 1;
            std.atomic.spinLoopHint();
            continue;
        }
        futexWait(&g_done, done);
    }
    g_submit.store(0, .release);
    futexWake(&g_submit);
}

pub fn ready() bool {
    return g_state.load(.acquire) == 1;
}

const StartArgs = struct { w: u32, h: u32, title: [128:0]u8 };
var g_args: StartArgs = undefined;

extern fn getenv(name: [*:0]const u8) ?[*:0]const u8;
extern fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern fn access(path: [*:0]const u8, mode: c_int) c_int;

/// On a laptop with an integrated GPU driving the screen and an NVIDIA one
/// beside it, GLX renders on the integrated one unless asked otherwise (a
/// Radeon 760M ran FalloutNV's Mojave at 10-15 fps next to an idle RTX 4050).
/// Ask for the NVIDIA GPU when its device node and its GLX library for this
/// architecture are both there. WINS_GPU=integrated keeps the default, and a
/// choice already made in the environment is left alone.
fn preferDiscreteGpu() void {
    if (getenv("WINS_GPU")) |v| {
        if (std.mem.eql(u8, std.mem.sliceTo(v, 0), "integrated")) return;
    }
    if (getenv("__NV_PRIME_RENDER_OFFLOAD") != null or getenv("__GLX_VENDOR_LIBRARY_NAME") != null or getenv("DRI_PRIME") != null) return;
    if (access("/dev/nvidiactl", 6) != 0) { // R_OK | W_OK
        if (access("/sys/module/nvidia", 0) == 0) std.debug.print("[WINS:GL] an NVIDIA GPU is present but /dev/nvidiactl is not reachable here; rendering on the default GPU\n", .{});
        return;
    }
    if (dlopen("libGLX_nvidia.so.0", 2) == null) {
        std.debug.print("[WINS:GL] an NVIDIA GPU is present but libGLX_nvidia.so.0 is not installed for this architecture; rendering on the default GPU\n", .{});
        return;
    }
    _ = setenv("__NV_PRIME_RENDER_OFFLOAD", "1", 1);
    _ = setenv("__GLX_VENDOR_LIBRARY_NAME", "nvidia", 1);
    std.debug.print("[WINS:GL] NVIDIA GPU found: asking GLX to render on it (WINS_GPU=integrated to keep the default)\n", .{});
}

fn openSurface() bool {
    preferDiscreteGpu();
    const x = dlopen("libX11.so.6", 2) orelse {
        std.debug.print("[WINS:GL] libX11.so.6 is not available for this architecture; no window\n", .{});
        return false;
    };
    const g = dlopen("libGL.so.1", 2) orelse {
        std.debug.print("[WINS:GL] libGL.so.1 is not available for this architecture; no window\n", .{});
        return false;
    };
    if (!loadTable(Xlib, &xlib, x, "libX11") or !loadTable(Glx, &glx, g, "libGL")) return false;
    _ = xlib.XInitThreads();
    const dpy = xlib.XOpenDisplay(null) orelse {
        std.debug.print("[WINS:GL] no X display (DISPLAY unset or refused); the device runs without a window\n", .{});
        return false;
    };
    const screen = xlib.XDefaultScreen(dpy);
    // GLX_RGBA, GLX_DOUBLEBUFFER, 8 bits per channel; depth lives in our own framebuffer object.
    const attribs = [_]c_int{ 4, 5, 8, 8, 9, 8, 10, 8, 0 };
    const vi = glx.glXChooseVisual(dpy, screen, &attribs) orelse {
        std.debug.print("[WINS:GL] the X server offers no double-buffered RGBA GLX visual\n", .{});
        return false;
    };
    const root = xlib.XRootWindow(dpy, vi.screen);
    var swa: XSetWindowAttributes = .{};
    swa.colormap = xlib.XCreateColormap(dpy, root, vi.visual, 0); // AllocNone
    // KeyPress|KeyRelease|ButtonPress|ButtonRelease|PointerMotion|FocusChange
    swa.event_mask = 0x1 | 0x2 | 0x4 | 0x8 | 0x40 | 0x200000;
    // CWBorderPixel | CWColormap | CWEventMask
    const win = xlib.XCreateWindow(dpy, root, 0, 0, g_args.w, g_args.h, 0, vi.depth, 1, vi.visual, (1 << 3) | (1 << 13) | (1 << 11), &swa);
    if (win == 0) return false;
    _ = xlib.XStoreName(dpy, win, &g_args.title);
    // DirectInput has no autorepeat: hold keys as one press, one release.
    _ = xlib.XkbSetDetectableAutoRepeat(dpy, 1, null);
    // The game draws its own cursor; hide the host one over the window.
    const blank = [_]u8{0} ** 8;
    const pix = xlib.XCreateBitmapFromData(dpy, win, &blank, 8, 8);
    var black: XColor = .{};
    _ = xlib.XDefineCursor(dpy, win, xlib.XCreatePixmapCursor(dpy, pix, pix, &black, &black, 0, 0));
    _ = xlib.XMapWindow(dpy, win);
    const ctx = glx.glXCreateContext(dpy, vi, null, 1) orelse {
        std.debug.print("[WINS:GL] glXCreateContext failed\n", .{});
        return false;
    };
    if (glx.glXMakeCurrent(dpy, win, ctx) == 0) {
        std.debug.print("[WINS:GL] glXMakeCurrent failed\n", .{});
        return false;
    }
    if (!loadGl()) return false;
    _ = xlib.XSync(dpy, 0);
    g_display = dpy;
    g_window = win;
    width = g_args.w;
    height = g_args.h;
    std.debug.print("[WINS:GL] window {d}x{d}; renderer \"{s}\", OpenGL {s}\n", .{
        width,                                           height,
        gl.glGetString(0x1F01) orelse "?", gl.glGetString(0x1F02) orelse "?",
    });
    return true;
}

/// How long each side looks for the other before sleeping in the kernel
/// (iterations of a pause loop: roughly 0.1-0.3 ms for the render thread).
const SPIN_RENDER: u32 = 8000;
const SPIN_SUBMIT: u32 = 4000;

fn renderMain() void {
    const ok = openSurface();
    g_state.store(if (ok) 1 else 2, .release);
    futexWake(&g_state);
    if (!ok) return;
    var served: u32 = 0;
    var idle_spins: u32 = 0;
    while (true) {
        const posted = g_posted.load(.acquire);
        if (posted == served and idle_spins < SPIN_RENDER) {
            // Inside a frame the next draw arrives within microseconds; a
            // thousand draws each paying a sleep and a wake was most of the
            // frame (FalloutNV's Mojave: 20 ms of rendering in an 80 ms frame).
            idle_spins += 1;
            std.atomic.spinLoopHint();
            continue;
        }
        idle_spins = 0;
        if (posted == served) {
            // Wake at least every 10 ms to serve the window's input even while
            // the game presents nothing (loading screens, long waits).
            var ts: linux.timespec = .{ .sec = 0, .nsec = 10_000_000 };
            _ = linux.syscall4(.futex, @intFromPtr(&g_posted), 0, posted, @intFromPtr(&ts));
            if (g_posted.load(.acquire) == served) pumpInput();
            continue;
        }
        if (g_job_fn) |f| f(g_job_ctx);
        served +%= 1;
        g_done.store(served, .release);
        futexWake(&g_done);
    }
}

/// Create the window and its context (once per process). False when the host
/// has no usable display; the caller then keeps running without one.
pub fn start(w: u32, h: u32, title: []const u8) bool {
    if (!g_started) {
        g_started = true;
        g_args = .{ .w = w, .h = h, .title = undefined };
        @memset(&g_args.title, 0);
        const n = @min(title.len, g_args.title.len - 1);
        @memcpy(g_args.title[0..n], title[0..n]);
        const t = std.Thread.spawn(.{}, renderMain, .{}) catch {
            std.debug.print("[WINS:GL] could not start the render thread\n", .{});
            g_state.store(2, .release);
            return false;
        };
        t.detach();
    }
    while (g_state.load(.acquire) == 0) futexWait(&g_state, 0);
    return g_state.load(.acquire) == 1;
}

/// Render thread only: show the back buffer, then deliver the window's input.
pub fn swap() void {
    glx.glXSwapBuffers(g_display, g_window);
    pumpInput();
}

var g_last_x: c_int = 0;
var g_last_y: c_int = 0;
var g_have_last = false;
var g_seen_types: u16 = 0;
var g_keys_logged: u32 = 0;
var g_last_key_logged: c_uint = 0;
var g_last_key_type: c_int = 0;

/// Render thread: X11 events of the game window -> DirectInput state. While
/// the window has the focus the pointer is kept inside it (warped back to the
/// centre), so mouse look keeps producing motion as on Windows.
fn pumpInput() void {
    const dpy = g_display;
    var ev: XEvent = undefined;
    while (xlib.XPending(dpy) > 0) {
        _ = xlib.XNextEvent(dpy, &ev);
        // Key presses and releases, logged when the key differs from the last
        // one logged (holding W to walk would otherwise use the whole budget).
        if ((ev.type == 2 or ev.type == 3) and g_keys_logged < 600 and (ev.detail != g_last_key_logged or ev.type != g_last_key_type)) {
            g_keys_logged += 1;
            g_last_key_logged = ev.detail;
            g_last_key_type = ev.type;
            std.debug.print("[WINS:GL] Key{s} keycode {d} -> DIK 0x{x}\n", .{ if (ev.type == 2) "Press" else "Release", ev.detail, input.dikFromX11(ev.detail) });
        }
        if (ev.type >= 2 and ev.type <= 8 and g_seen_types & (@as(u16, 1) << @intCast(ev.type)) == 0) {
            g_seen_types |= @as(u16, 1) << @intCast(ev.type);
            std.debug.print("[WINS:GL] first X11 input event of type {d} (detail {d}, at {d},{d})\n", .{ ev.type, ev.detail, ev.x, ev.y });
        }
        switch (ev.type) {
            2, 3 => {
                const dik = input.dikFromX11(ev.detail);
                input.keyEvent(dik, ev.type == 2);
                var buf: [8]u8 = undefined;
                var ch: u8 = 0;
                if (ev.type == 2) {
                    // Latin-1 from the host layout; Windows-1252 agrees on it.
                    const n = xlib.XLookupString(&ev, &buf, buf.len, null, null);
                    if (n == 1) ch = buf[0];
                }
                const vk = vkFromKeysym(xlib.XLookupKeysym(&ev, 0));
                user32.hostKey(vk, dik & 0x7F, dik >= 0x80, ev.type == 2, ch);
            },
            4, 5 => {
                const down = ev.type == 4;
                switch (ev.detail) {
                    1 => input.mouseButton(0, down),
                    2 => input.mouseButton(2, down),
                    3 => input.mouseButton(1, down),
                    4 => if (down) input.mouseWheel(120),
                    5 => if (down) input.mouseWheel(-120),
                    8 => input.mouseButton(3, down),
                    9 => input.mouseButton(4, down),
                    else => {},
                }
            },
            6 => {
                if (g_have_last) input.mouseMove(ev.x - g_last_x, ev.y - g_last_y);
                g_last_x = ev.x;
                g_last_y = ev.y;
                g_have_last = true;
            },
            9 => {
                // XFocusChangeEvent: mode and detail sit where key events keep root/subwindow.
                std.debug.print("[WINS:GL] FocusIn (mode {d}, detail {d})\n", .{ ev.root, ev.subwindow });
                input.focus(true);
            },
            10 => {
                std.debug.print("[WINS:GL] FocusOut (mode {d}, detail {d})\n", .{ ev.root, ev.subwindow });
                input.focus(false);
                g_have_last = false;
            },
            else => {},
        }
    }
    if (input.focused() and g_have_last) {
        const cx: c_int = @intCast(width / 2);
        const cy: c_int = @intCast(height / 2);
        if (@abs(g_last_x - cx) > @as(c_int, @intCast(width / 4)) or @abs(g_last_y - cy) > @as(c_int, @intCast(height / 4))) {
            _ = xlib.XWarpPointer(dpy, 0, g_window, 0, 0, 0, 0, cx, cy);
            g_last_x = cx;
            g_last_y = cy;
            _ = xlib.XFlush(dpy);
        }
    }
}
