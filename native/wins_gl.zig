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
};

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

    glBindBuffer: *const fn (GLenum, GLuint) callconv(.c) void,
    glEnableVertexAttribArray: *const fn (GLuint) callconv(.c) void,
    glDisableVertexAttribArray: *const fn (GLuint) callconv(.c) void,
    glVertexAttribPointer: *const fn (GLuint, GLint, GLenum, u8, GLsizei, ?*const anyopaque) callconv(.c) void,
    glVertexAttrib4f: *const fn (GLuint, f32, f32, f32, f32) callconv(.c) void,
    glDrawArrays: *const fn (GLenum, GLint, GLsizei) callconv(.c) void,
    glDrawElements: *const fn (GLenum, GLsizei, GLenum, ?*const anyopaque) callconv(.c) void,

    glGenFramebuffers: *const fn (GLsizei, *GLuint) callconv(.c) void,
    glBindFramebuffer: *const fn (GLenum, GLuint) callconv(.c) void,
    glFramebufferTexture2D: *const fn (GLenum, GLenum, GLenum, GLuint, GLint) callconv(.c) void,
    glGenRenderbuffers: *const fn (GLsizei, *GLuint) callconv(.c) void,
    glBindRenderbuffer: *const fn (GLenum, GLuint) callconv(.c) void,
    glRenderbufferStorage: *const fn (GLenum, GLenum, GLsizei, GLsizei) callconv(.c) void,
    glFramebufferRenderbuffer: *const fn (GLenum, GLenum, GLenum, GLuint) callconv(.c) void,
    glCheckFramebufferStatus: *const fn (GLenum) callconv(.c) GLenum,
    glBlitFramebuffer: *const fn (GLint, GLint, GLint, GLint, GLint, GLint, GLint, GLint, c_uint, GLenum) callconv(.c) void,
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
    while (true) {
        const done = g_done.load(.acquire);
        if (done == ticket) break;
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

fn openSurface() bool {
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
    swa.event_mask = 0;
    // CWBorderPixel | CWColormap | CWEventMask
    const win = xlib.XCreateWindow(dpy, root, 0, 0, g_args.w, g_args.h, 0, vi.depth, 1, vi.visual, (1 << 3) | (1 << 13) | (1 << 11), &swa);
    if (win == 0) return false;
    _ = xlib.XStoreName(dpy, win, &g_args.title);
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

fn renderMain() void {
    const ok = openSurface();
    g_state.store(if (ok) 1 else 2, .release);
    futexWake(&g_state);
    if (!ok) return;
    var served: u32 = 0;
    while (true) {
        const posted = g_posted.load(.acquire);
        if (posted == served) {
            futexWait(&g_posted, posted);
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

/// Render thread only: show the back buffer.
pub fn swap() void {
    glx.glXSwapBuffers(g_display, g_window);
}
