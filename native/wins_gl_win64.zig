//! Win64 OpenGL Core (`OPENGL32.dll` + WGL + GLX) bridge for `winrun64`.
//! Maps Win64 WGL/GDI pixel-format & context creation onto real `libGL.so.1`
//! GLX contexts bound to `winrun_gui_support.zig` X11 windows, and wraps all
//! GL entry points with compiler-generated `callconv(.winapi)` -> `callconv(.c)`
//! ABI adapters so Unity GLCore runs natively on Linux.

const std = @import("std");
const gui = @import("winrun_gui_support.zig");

const W = std.builtin.CallingConvention.winapi;

extern fn dlopen(path: [*:0]const u8, flags: c_int) ?*anyopaque;
extern fn dlsym(handle: ?*anyopaque, name: [*:0]const u8) ?*anyopaque;

const RTLD_LAZY: c_int = 1;
const RTLD_GLOBAL: c_int = 0x100;

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

const XWindowAttributes = extern struct {
    x: c_int,
    y: c_int,
    width: c_int,
    height: c_int,
    border_width: c_int,
    depth: c_int,
    visual: ?*anyopaque,
    root: c_ulong,
    class: c_int,
    bit_gravity: c_int,
    win_gravity: c_int,
    backing_store: c_int,
    backing_planes: c_ulong,
    backing_pixel: c_ulong,
    save_under: c_int,
    colormap: c_ulong,
    map_installed: c_int,
    map_state: c_int,
    all_event_masks: c_long,
    your_event_mask: c_long,
    do_not_propagate_mask: c_long,
    override_redirect: c_int,
    screen: ?*anyopaque,
};

const Glx = struct {
    lib_gl: ?*anyopaque = null,
    lib_x11: ?*anyopaque = null,
    choose_fb_config: ?*const fn (?*anyopaque, c_int, ?[*]const c_int, *c_int) callconv(.c) ?[*]?*anyopaque = null,
    get_visual_from_fb_config: ?*const fn (?*anyopaque, ?*anyopaque) callconv(.c) ?*XVisualInfo = null,
    create_context: ?*const fn (?*anyopaque, *XVisualInfo, ?*anyopaque, c_int) callconv(.c) ?*anyopaque = null,
    create_context_attribs: ?*const fn (?*anyopaque, ?*anyopaque, ?*anyopaque, c_int, ?[*]const c_int) callconv(.c) ?*anyopaque = null,
    destroy_context: ?*const fn (?*anyopaque, ?*anyopaque) callconv(.c) void = null,
    make_current: ?*const fn (?*anyopaque, c_ulong, ?*anyopaque) callconv(.c) c_int = null,
    swap_buffers: ?*const fn (?*anyopaque, c_ulong) callconv(.c) void = null,
    get_proc_address: ?*const fn ([*:0]const u8) callconv(.c) ?*anyopaque = null,
    query_extensions_string: ?*const fn (?*anyopaque, c_int) callconv(.c) ?[*:0]const u8 = null,
    swap_interval_ext: ?*const fn (?*anyopaque, c_ulong, c_int) callconv(.c) void = null,
    swap_interval_mesa: ?*const fn (c_int) callconv(.c) c_int = null,
    swap_interval_sgi: ?*const fn (c_int) callconv(.c) c_int = null,
    x_default_screen: ?*const fn (?*anyopaque) callconv(.c) c_int = null,
    x_default_visual: ?*const fn (?*anyopaque, c_int) callconv(.c) ?*anyopaque = null,
    x_visual_id_from_visual: ?*const fn (?*anyopaque) callconv(.c) c_ulong = null,
    x_get_window_attributes: ?*const fn (?*anyopaque, c_ulong, *XWindowAttributes) callconv(.c) c_int = null,
    x_free: ?*const fn (?*anyopaque) callconv(.c) c_int = null,
    x_sync: ?*const fn (?*anyopaque, c_int) callconv(.c) c_int = null,
    loaded: bool = false,
};

var g_gl_lock: std.atomic.Value(bool) = .init(false);
var g_glx: Glx = .{};

fn glLock() void {
    while (g_gl_lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
        std.atomic.spinLoopHint();
    }
}

fn glUnlock() void {
    g_gl_lock.store(false, .release);
}

fn ensureGlx() bool {
    glLock();
    defer glUnlock();
    if (g_glx.loaded) return g_glx.lib_gl != null;
    g_glx.loaded = true;
    const lib = dlopen("libGL.so.1", RTLD_LAZY | RTLD_GLOBAL) orelse dlopen("libGL.so", RTLD_LAZY | RTLD_GLOBAL) orelse {
        std.debug.print("[WINS:GL] dlopen libGL.so.1 failed\n", .{});
        return false;
    };
    const lx11 = dlopen("libX11.so.6", RTLD_LAZY | RTLD_GLOBAL);
    g_glx.lib_gl = lib;
    g_glx.lib_x11 = lx11;
    g_glx.get_proc_address = @ptrCast(dlsym(lib, "glXGetProcAddressARB") orelse dlsym(lib, "glXGetProcAddress"));
    g_glx.choose_fb_config = @ptrCast(dlsym(lib, "glXChooseFBConfig"));
    g_glx.get_visual_from_fb_config = @ptrCast(dlsym(lib, "glXGetVisualFromFBConfig"));
    g_glx.create_context = @ptrCast(dlsym(lib, "glXCreateContext"));
    g_glx.destroy_context = @ptrCast(dlsym(lib, "glXDestroyContext"));
    g_glx.make_current = @ptrCast(dlsym(lib, "glXMakeCurrent"));
    g_glx.swap_buffers = @ptrCast(dlsym(lib, "glXSwapBuffers"));
    g_glx.query_extensions_string = @ptrCast(dlsym(lib, "glXQueryExtensionsString"));
    if (g_glx.get_proc_address) |gpa| {
        if (gpa("glXCreateContextAttribsARB")) |p| g_glx.create_context_attribs = @ptrCast(p);
        if (gpa("glXSwapIntervalEXT")) |p| g_glx.swap_interval_ext = @ptrCast(p);
        if (gpa("glXSwapIntervalMESA")) |p| g_glx.swap_interval_mesa = @ptrCast(p);
        if (gpa("glXSwapIntervalSGI")) |p| g_glx.swap_interval_sgi = @ptrCast(p);
    }
    if (lx11) |x| {
        g_glx.x_default_screen = @ptrCast(dlsym(x, "XDefaultScreen"));
        g_glx.x_default_visual = @ptrCast(dlsym(x, "XDefaultVisual"));
        g_glx.x_visual_id_from_visual = @ptrCast(dlsym(x, "XVisualIDFromVisual"));
        g_glx.x_get_window_attributes = @ptrCast(dlsym(x, "XGetWindowAttributes"));
        g_glx.x_free = @ptrCast(dlsym(x, "XFree"));
        g_glx.x_sync = @ptrCast(dlsym(x, "XSync"));
    }
    return true;
}

fn resolveRealGl(name: [*:0]const u8) ?*anyopaque {
    if (!ensureGlx()) return null;
    if (g_glx.get_proc_address) |gpa| {
        if (gpa(name)) |p| return p;
    }
    if (g_glx.lib_gl) |lib| {
        if (dlsym(lib, name)) |p| return p;
    }
    return null;
}

const GlCtx = struct {
    in_use: bool = false,
    handle: usize = 0,
    display: ?*anyopaque = null,
    glx_ctx: ?*anyopaque = null,
    default_xwin: c_ulong = 0,
};

const MAX_CTXS = 32;
var g_ctxs: [MAX_CTXS]GlCtx = [_]GlCtx{.{}} ** MAX_CTXS;
var g_next_ctx_handle: usize = 0x2001;

threadlocal var t_cur_hdc: usize = 0;
threadlocal var t_cur_hglrc: usize = 0;
threadlocal var t_cur_display: ?*anyopaque = null;
threadlocal var t_cur_xwin: c_ulong = 0;

fn findCtxLocked(hglrc: usize) ?*GlCtx {
    if (hglrc == 0) return null;
    for (&g_ctxs) |*c| {
        if (c.in_use and c.handle == hglrc) return c;
    }
    return null;
}

fn pickFbConfigAndVisual(dpy: *anyopaque, screen: c_int, xwin: c_ulong, out_fbcfg: *?*anyopaque, out_vis: *?*XVisualInfo) bool {
    const choose_fb = g_glx.choose_fb_config orelse return false;
    const get_vis = g_glx.get_visual_from_fb_config orelse return false;
    var target_vid: c_ulong = 0;
    if (g_glx.x_get_window_attributes) |xga| {
        if (g_glx.x_visual_id_from_visual) |xvid| {
            var attrs: XWindowAttributes = std.mem.zeroes(XWindowAttributes);
            if (xga(dpy, xwin, &attrs) != 0 and attrs.visual != null) {
                target_vid = xvid(attrs.visual);
            }
        }
    }
    // GLX_X_RENDERABLE=0x8012, GLX_DRAWABLE_TYPE=0x8010, GLX_WINDOW_BIT=1,
    // GLX_RENDER_TYPE=0x8011, GLX_RGBA_BIT=1, GLX_DOUBLEBUFFER=5,
    // GLX_RED_SIZE=8, GLX_GREEN_SIZE=9, GLX_BLUE_SIZE=10, GLX_ALPHA_SIZE=11,
    // GLX_DEPTH_SIZE=12, GLX_STENCIL_SIZE=13
    const attempts = [_][19]c_int{
        .{ 0x8012, 1, 0x8010, 1, 0x8011, 1, 5, 1, 8, 8, 9, 8, 10, 8, 11, 8, 12, 24, 0 },
        .{ 0x8012, 1, 0x8010, 1, 0x8011, 1, 5, 1, 8, 8, 9, 8, 10, 8, 12, 16, 0, 0, 0 },
        .{ 0x8012, 1, 0x8010, 1, 0x8011, 1, 8, 8, 9, 8, 10, 8, 0, 0, 0, 0, 0, 0, 0 },
    };
    for (attempts) |attribs| {
        var count: c_int = 0;
        const cfgs = choose_fb(dpy, screen, &attribs, &count) orelse continue;
        defer if (g_glx.x_free) |xf| { _ = xf(@ptrCast(cfgs)); };
        if (count <= 0) continue;
        const n: usize = @intCast(count);
        var chosen_cfg: ?*anyopaque = null;
        var chosen_vis: ?*XVisualInfo = null;
        if (target_vid != 0) {
            for (0..n) |i| {
                if (get_vis(dpy, cfgs[i])) |vi| {
                    if (vi.visualid == target_vid) {
                        chosen_cfg = cfgs[i];
                        chosen_vis = vi;
                        break;
                    }
                    if (g_glx.x_free) |xf| _ = xf(vi);
                }
            }
        }
        if (chosen_cfg == null) {
            chosen_cfg = cfgs[0];
            chosen_vis = get_vis(dpy, cfgs[0]);
        }
        if (chosen_cfg != null and chosen_vis != null) {
            out_fbcfg.* = chosen_cfg;
            out_vis.* = chosen_vis;
            return true;
        }
        if (chosen_vis) |vi| if (g_glx.x_free) |xf| { _ = xf(vi); };
    }
    return false;
}

fn createContextInternal(hdc: ?*anyopaque, share: ?*anyopaque, major: c_int, minor: c_int, profile_mask: c_int, flags: c_int) ?*anyopaque {
    if (!ensureGlx()) return null;
    const surf = gui.ensureGlSurfaceForDc(@intFromPtr(hdc)) orelse return null;
    const dpy = surf.display;
    const screen: c_int = if (g_glx.x_default_screen) |ds| ds(dpy) else 0;

    var fbcfg: ?*anyopaque = null;
    var vis: ?*XVisualInfo = null;
    if (!pickFbConfigAndVisual(dpy, screen, surf.window, &fbcfg, &vis)) {
        std.debug.print("[WINS:GL] pickFbConfigAndVisual failed\n", .{});
        return null;
    }
    defer if (vis) |vi| if (g_glx.x_free) |xf| { _ = xf(vi); };

    glLock();
    defer glUnlock();

    const share_glx: ?*anyopaque = if (findCtxLocked(@intFromPtr(share))) |sc| sc.glx_ctx else null;
    var glx_ctx: ?*anyopaque = null;
    if (g_glx.create_context_attribs) |cca| {
        // GLX_CONTEXT_MAJOR_VERSION_ARB=0x2091, MINOR=0x2092, FLAGS=0x2094, PROFILE_MASK=0x9126
        var attribs: [11]c_int = [_]c_int{0} ** 11;
        var ai: usize = 0;
        if (major > 0) {
            attribs[ai] = 0x2091; attribs[ai + 1] = major; ai += 2;
            attribs[ai] = 0x2092; attribs[ai + 1] = minor; ai += 2;
        }
        if (profile_mask != 0) {
            attribs[ai] = 0x9126; attribs[ai + 1] = profile_mask; ai += 2;
        }
        if (flags != 0) {
            attribs[ai] = 0x2094; attribs[ai + 1] = flags; ai += 2;
        }
        attribs[ai] = 0;
        glx_ctx = cca(dpy, fbcfg, share_glx, 1, &attribs);
        if (glx_ctx == null and major >= 4) {
            // Retry 3.3 Core if host/Xvfb lacks 4.x
            var fb33 = [_]c_int{ 0x2091, 3, 0x2092, 3, 0x9126, 1, 0 };
            glx_ctx = cca(dpy, fbcfg, share_glx, 1, &fb33);
        }
        if (glx_ctx == null) {
            var empty = [_]c_int{0};
            glx_ctx = cca(dpy, fbcfg, share_glx, 1, &empty);
        }
    }
    if (glx_ctx == null) {
        if (g_glx.create_context) |cc| {
            glx_ctx = cc(dpy, vis.?, share_glx, 1);
        }
    }
    if (glx_ctx == null) {
        std.debug.print("[WINS:GL] glXCreateContext failed\n", .{});
        return null;
    }

    for (&g_ctxs) |*slot| {
        if (!slot.in_use) {
            const h = g_next_ctx_handle;
            g_next_ctx_handle += 1;
            slot.* = .{
                .in_use = true,
                .handle = h,
                .display = dpy,
                .glx_ctx = glx_ctx,
                .default_xwin = surf.window,
            };
            if (std.c.getenv("WINS_TRACE") != null) {
                std.debug.print("[WINS:GL] created GLX ctx=0x{x} for hdc=0x{x} xwin=0x{x}\n", .{ h, @intFromPtr(hdc), surf.window });
            }
            return @ptrFromInt(h);
        }
    }
    if (g_glx.destroy_context) |dc| dc(dpy, glx_ctx);
    return null;
}

pub fn wglCreateContext(hdc: ?*anyopaque) callconv(W) ?*anyopaque {
    return createContextInternal(hdc, null, 0, 0, 0, 0);
}

fn wglCreateContextAttribsARB(hdc: ?*anyopaque, hShareContext: ?*anyopaque, attribList: ?[*]const i32) callconv(W) ?*anyopaque {
    var major: c_int = 0;
    var minor: c_int = 0;
    var profile: c_int = 0;
    var flags: c_int = 0;
    if (attribList) |list| {
        var i: usize = 0;
        while (i < 32 and list[i] != 0) : (i += 2) {
            const k = list[i];
            const v = list[i + 1];
            if (k == 0x2091) major = v
            else if (k == 0x2092) minor = v
            else if (k == 0x9126) profile = v
            else if (k == 0x2094) flags = v;
        }
    }
    return createContextInternal(hdc, hShareContext, major, minor, profile, flags);
}

pub fn wglDeleteContext(hglrc: ?*anyopaque) callconv(W) u32 {
    const h = @intFromPtr(hglrc);
    if (h == 0) return 0;
    glLock();
    defer glUnlock();
    const c = findCtxLocked(h) orelse return 0;
    if (t_cur_hglrc == h) {
        if (g_glx.make_current) |mc| _ = mc(c.display, 0, null);
        t_cur_hglrc = 0;
        t_cur_hdc = 0;
        t_cur_xwin = 0;
    }
    if (g_glx.destroy_context) |dc| dc(c.display, c.glx_ctx);
    c.* = .{};
    return 1;
}

pub fn wglMakeCurrent(hdc: ?*anyopaque, hglrc: ?*anyopaque) callconv(W) u32 {
    if (!ensureGlx()) return 0;
    const mc = g_glx.make_current orelse return 0;
    const h = @intFromPtr(hglrc);
    if (h == 0 or hdc == null) {
        if (t_cur_display) |dpy| _ = mc(dpy, 0, null);
        t_cur_hdc = 0;
        t_cur_hglrc = 0;
        t_cur_xwin = 0;
        return 1;
    }
    glLock();
    const ctx_copy = if (findCtxLocked(h)) |c| c.* else {
        glUnlock();
        return 0;
    };
    glUnlock();

    const surf = gui.ensureGlSurfaceForDc(@intFromPtr(hdc)) orelse return 0;
    if (g_glx.x_sync) |xs| _ = xs(ctx_copy.display, 0);
    if (mc(ctx_copy.display, surf.window, ctx_copy.glx_ctx) == 0) {
        std.debug.print("[WINS:GL] glXMakeCurrent failed hdc=0x{x} xwin=0x{x}\n", .{ @intFromPtr(hdc), surf.window });
        return 0;
    }
    t_cur_hdc = @intFromPtr(hdc);
    t_cur_hglrc = h;
    t_cur_display = ctx_copy.display;
    t_cur_xwin = surf.window;
    return 1;
}

pub fn wglGetCurrentDC() callconv(W) ?*anyopaque {
    return if (t_cur_hdc != 0) @ptrFromInt(t_cur_hdc) else null;
}

pub fn wglGetCurrentContext() callconv(W) ?*anyopaque {
    return if (t_cur_hglrc != 0) @ptrFromInt(t_cur_hglrc) else null;
}

pub fn wglShareLists(h1: ?*anyopaque, h2: ?*anyopaque) callconv(W) u32 {
    _ = h1; _ = h2;
    return 1;
}

const WGL_EXT_STR: [*:0]const u8 = "WGL_ARB_pixel_format WGL_ARB_create_context WGL_ARB_create_context_profile WGL_EXT_swap_control WGL_ARB_extensions_string";

fn wglGetExtensionsStringARB(hdc: ?*anyopaque) callconv(W) ?[*:0]const u8 {
    _ = hdc;
    return WGL_EXT_STR;
}

fn wglGetExtensionsStringEXT() callconv(W) ?[*:0]const u8 {
    return WGL_EXT_STR;
}

fn wglChoosePixelFormatARB(hdc: ?*anyopaque, piAttribIList: ?[*]const i32, pfAttribFList: ?[*]const f32, nMaxFormats: u32, piFormats: ?[*]i32, nNumFormats: ?*u32) callconv(W) u32 {
    _ = hdc; _ = piAttribIList; _ = pfAttribFList;
    if (piFormats != null and nMaxFormats >= 1) piFormats.?[0] = 1;
    if (nNumFormats) |n| n.* = if (nMaxFormats >= 1) 1 else 0;
    return 1;
}

fn attrValueForWgl(attr: i32) i32 {
    return switch (attr) {
        0x2000 => 1, // WGL_NUMBER_PIXEL_FORMATS_ARB
        0x2001 => 1, // WGL_DRAW_TO_WINDOW_ARB
        0x2002 => 0, // WGL_DRAW_TO_BITMAP_ARB
        0x2003 => 0x2027, // WGL_ACCELERATION_ARB = WGL_FULL_ACCELERATION_ARB
        0x2007 => 0x2028, // WGL_SWAP_METHOD_ARB = EXCHANGE
        0x2010 => 1, // WGL_SUPPORT_OPENGL_ARB
        0x2011 => 1, // WGL_DOUBLE_BUFFER_ARB
        0x2012 => 0, // WGL_STEREO_ARB
        0x2013 => 0x202B, // WGL_PIXEL_TYPE_ARB = WGL_TYPE_RGBA_ARB
        0x2014 => 32, // WGL_COLOR_BITS_ARB
        0x2015 => 8, // RED_BITS
        0x2017 => 8, // GREEN_BITS
        0x2019 => 8, // BLUE_BITS
        0x201B => 8, // ALPHA_BITS
        0x2022 => 24, // DEPTH_BITS
        0x2023 => 8, // STENCIL_BITS
        0x2041 => 0, // SAMPLE_BUFFERS_ARB
        0x2042 => 0, // SAMPLES_ARB
        0x20A9 => 1, // FRAMEBUFFER_SRGB_CAPABLE_ARB
        else => 0,
    };
}

fn wglGetPixelFormatAttribivARB(hdc: ?*anyopaque, iPixelFormat: i32, iLayerPlane: i32, nAttributes: u32, piAttributes: ?[*]const i32, piValues: ?[*]i32) callconv(W) u32 {
    _ = hdc; _ = iPixelFormat; _ = iLayerPlane;
    const attrs = piAttributes orelse return 0;
    const vals = piValues orelse return 0;
    for (0..nAttributes) |i| vals[i] = attrValueForWgl(attrs[i]);
    return 1;
}

fn wglGetPixelFormatAttribfvARB(hdc: ?*anyopaque, iPixelFormat: i32, iLayerPlane: i32, nAttributes: u32, piAttributes: ?[*]const i32, pfValues: ?[*]f32) callconv(W) u32 {
    _ = hdc; _ = iPixelFormat; _ = iLayerPlane;
    const attrs = piAttributes orelse return 0;
    const vals = pfValues orelse return 0;
    for (0..nAttributes) |i| vals[i] = @floatFromInt(attrValueForWgl(attrs[i]));
    return 1;
}

fn wglSwapIntervalEXT(interval: i32) callconv(W) u32 {
    if (!ensureGlx()) return 0;
    if (g_glx.swap_interval_ext) |si| {
        if (t_cur_display != null and t_cur_xwin != 0) {
            si(t_cur_display, t_cur_xwin, interval);
            return 1;
        }
    }
    if (g_glx.swap_interval_mesa) |sm| {
        _ = sm(interval);
        return 1;
    }
    if (g_glx.swap_interval_sgi) |ss| {
        if (interval >= 1) _ = ss(interval);
        return 1;
    }
    return 1;
}

pub fn swapBuffers(hdc: usize) i32 {
    if (!ensureGlx()) return 1;
    const sb = g_glx.swap_buffers orelse return 1;
    if (gui.ensureGlSurfaceForDc(hdc)) |surf| {
        sb(surf.display, surf.window);
        return 1;
    }
    if (t_cur_display != null and t_cur_xwin != 0) {
        sb(t_cur_display, t_cur_xwin);
    }
    return 1;
}

pub fn choosePixelFormat(hdc: usize, ppfd: ?*const anyopaque) i32 {
    _ = hdc; _ = ppfd;
    return 1;
}

pub fn setPixelFormat(hdc: usize, format: i32, ppfd: ?*const anyopaque) i32 {
    _ = format; _ = ppfd;
    _ = gui.ensureGlSurfaceForDc(hdc);
    return 1;
}

pub fn describePixelFormat(hdc: usize, format: i32, nbytes: u32, ppfd: ?[*]u8) i32 {
    _ = hdc; _ = format;
    if (ppfd) |p| if (nbytes >= 40) {
        @memset(p[0..40], 0);
        std.mem.writeInt(u16, p[0..2], 40, .little); // nSize
        std.mem.writeInt(u16, p[2..4], 1, .little); // nVersion
        // PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER = 0x25
        std.mem.writeInt(u32, p[4..8], 0x25, .little);
        p[8] = 0; // PFD_TYPE_RGBA
        p[9] = 32; // cColorBits
        p[23] = 24; // cDepthBits
        p[24] = 8; // cStencilBits
    };
    return 1;
}

pub fn invalidateWindow(xwin: c_ulong) void {
    if (xwin == 0) return;
    if (t_cur_xwin == xwin) {
        if (g_glx.make_current) |mc| {
            if (t_cur_display) |dpy| _ = mc(dpy, 0, null);
        }
        t_cur_xwin = 0;
        t_cur_hdc = 0;
        t_cur_hglrc = 0;
    }
}

const WinDebugProc = *const fn (u32, u32, u32, u32, i32, ?[*:0]const u8, ?*const anyopaque) callconv(W) void;
var g_debug_cb: ?WinDebugProc = null;

fn hostDebugTrampoline(src: u32, typ: u32, id: u32, sev: u32, len: i32, msg: ?[*:0]const u8, user: ?*const anyopaque) callconv(.c) void {
    if (g_debug_cb) |cb| cb(src, typ, id, sev, len, msg, user);
}

const GlKind = enum {
    v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v15,
    u8_1, i32_2, u32_0, u32_1, u32_2, u32_3, ptr_1, ptr_2, ptr_3, ptr_4,
    f_4f, f_1d, f_1f, f_2d, f_2f, f_uuf, f_u4f, f_uufi,
    debug_cb,
};

const GlSpec = struct { name: [:0]const u8, kind: GlKind };

const gl_specs = [_]GlSpec{
    .{ .name = "glActiveTexture", .kind = .v1 },
    .{ .name = "glAttachShader", .kind = .v2 },
    .{ .name = "glBeginQuery", .kind = .v2 },
    .{ .name = "glBeginQueryEXT", .kind = .v2 },
    .{ .name = "glBeginTransformFeedback", .kind = .v1 },
    .{ .name = "glBindAttribLocation", .kind = .v3 },
    .{ .name = "glBindBuffer", .kind = .v2 },
    .{ .name = "glBindBufferBase", .kind = .v3 },
    .{ .name = "glBindFramebuffer", .kind = .v2 },
    .{ .name = "glBindImageTexture", .kind = .v7 },
    .{ .name = "glBindRenderbuffer", .kind = .v2 },
    .{ .name = "glBindSampler", .kind = .v2 },
    .{ .name = "glBindTexture", .kind = .v2 },
    .{ .name = "glBindTransformFeedback", .kind = .v2 },
    .{ .name = "glBindVertexArray", .kind = .v1 },
    .{ .name = "glBindVertexArrayOES", .kind = .v1 },
    .{ .name = "glBlendBarrierKHR", .kind = .v0 },
    .{ .name = "glBlendBarrierNV", .kind = .v0 },
    .{ .name = "glBlendColor", .kind = .f_4f },
    .{ .name = "glBlendEquation", .kind = .v1 },
    .{ .name = "glBlendEquationSeparate", .kind = .v2 },
    .{ .name = "glBlendEquationSeparatei", .kind = .v3 },
    .{ .name = "glBlendEquationSeparateiARB", .kind = .v3 },
    .{ .name = "glBlendEquationi", .kind = .v2 },
    .{ .name = "glBlendEquationiARB", .kind = .v2 },
    .{ .name = "glBlendFunc", .kind = .v2 },
    .{ .name = "glBlendFuncSeparate", .kind = .v4 },
    .{ .name = "glBlendFuncSeparatei", .kind = .v5 },
    .{ .name = "glBlendFuncSeparateiARB", .kind = .v5 },
    .{ .name = "glBlitFramebuffer", .kind = .v10 },
    .{ .name = "glBlitFramebufferNV", .kind = .v10 },
    .{ .name = "glBufferData", .kind = .v4 },
    .{ .name = "glBufferSubData", .kind = .v4 },
    .{ .name = "glCheckFramebufferStatus", .kind = .u32_1 },
    .{ .name = "glClear", .kind = .v1 },
    .{ .name = "glClearBufferfi", .kind = .f_uufi },
    .{ .name = "glClearBufferfv", .kind = .v3 },
    .{ .name = "glClearBufferiv", .kind = .v3 },
    .{ .name = "glClearBufferuiv", .kind = .v3 },
    .{ .name = "glClearColor", .kind = .f_4f },
    .{ .name = "glClearDepth", .kind = .f_1d },
    .{ .name = "glClearDepthf", .kind = .f_1f },
    .{ .name = "glClearStencil", .kind = .v1 },
    .{ .name = "glClientWaitSync", .kind = .u32_3 },
    .{ .name = "glColorMask", .kind = .v4 },
    .{ .name = "glColorMaski", .kind = .v5 },
    .{ .name = "glCompileShader", .kind = .v1 },
    .{ .name = "glCompressedTexImage2D", .kind = .v8 },
    .{ .name = "glCompressedTexSubImage2D", .kind = .v9 },
    .{ .name = "glCompressedTexSubImage3D", .kind = .v11 },
    .{ .name = "glCopyBufferSubData", .kind = .v5 },
    .{ .name = "glCopyImageSubData", .kind = .v15 },
    .{ .name = "glCopyImageSubDataEXT", .kind = .v15 },
    .{ .name = "glCopyImageSubDataOES", .kind = .v15 },
    .{ .name = "glCopyTexImage2D", .kind = .v8 },
    .{ .name = "glCopyTexSubImage2D", .kind = .v8 },
    .{ .name = "glCreateProgram", .kind = .u32_0 },
    .{ .name = "glCreateShader", .kind = .u32_1 },
    .{ .name = "glCullFace", .kind = .ptr_1 },
    .{ .name = "glDebugMessageCallback", .kind = .debug_cb },
    .{ .name = "glDebugMessageCallbackKHR", .kind = .debug_cb },
    .{ .name = "glDebugMessageControl", .kind = .v6 },
    .{ .name = "glDebugMessageControlKHR", .kind = .v6 },
    .{ .name = "glDebugMessageInsert", .kind = .v6 },
    .{ .name = "glDebugMessageInsertKHR", .kind = .v6 },
    .{ .name = "glDeleteBuffers", .kind = .v2 },
    .{ .name = "glDeleteFramebuffers", .kind = .v2 },
    .{ .name = "glDeleteProgram", .kind = .v1 },
    .{ .name = "glDeleteQueries", .kind = .v2 },
    .{ .name = "glDeleteQueriesEXT", .kind = .v2 },
    .{ .name = "glDeleteRenderbuffers", .kind = .v2 },
    .{ .name = "glDeleteSamplers", .kind = .v2 },
    .{ .name = "glDeleteShader", .kind = .v1 },
    .{ .name = "glDeleteSync", .kind = .v1 },
    .{ .name = "glDeleteTextures", .kind = .v2 },
    .{ .name = "glDeleteTransformFeedbacks", .kind = .v2 },
    .{ .name = "glDeleteVertexArrays", .kind = .v2 },
    .{ .name = "glDeleteVertexArraysOES", .kind = .v2 },
    .{ .name = "glDepthFunc", .kind = .v1 },
    .{ .name = "glDepthMask", .kind = .v1 },
    .{ .name = "glDepthRange", .kind = .f_2d },
    .{ .name = "glDepthRangef", .kind = .f_2f },
    .{ .name = "glDetachShader", .kind = .v2 },
    .{ .name = "glDisable", .kind = .v1 },
    .{ .name = "glDisableVertexAttribArray", .kind = .v1 },
    .{ .name = "glDiscardFramebufferEXT", .kind = .v3 },
    .{ .name = "glDispatchCompute", .kind = .v3 },
    .{ .name = "glDispatchComputeIndirect", .kind = .v1 },
    .{ .name = "glDrawArrays", .kind = .v3 },
    .{ .name = "glDrawArraysIndirect", .kind = .v2 },
    .{ .name = "glDrawArraysInstanced", .kind = .v4 },
    .{ .name = "glDrawBuffer", .kind = .v1 },
    .{ .name = "glDrawBuffers", .kind = .v2 },
    .{ .name = "glDrawBuffersEXT", .kind = .v2 },
    .{ .name = "glDrawBuffersNV", .kind = .v2 },
    .{ .name = "glDrawElements", .kind = .v4 },
    .{ .name = "glDrawElementsBaseVertex", .kind = .v5 },
    .{ .name = "glDrawElementsBaseVertexEXT", .kind = .v5 },
    .{ .name = "glDrawElementsBaseVertexOES", .kind = .v5 },
    .{ .name = "glDrawElementsIndirect", .kind = .v3 },
    .{ .name = "glDrawElementsInstanced", .kind = .v5 },
    .{ .name = "glDrawElementsInstancedBaseVertex", .kind = .v6 },
    .{ .name = "glDrawElementsInstancedBaseVertexEXT", .kind = .v6 },
    .{ .name = "glDrawElementsInstancedBaseVertexOES", .kind = .v6 },
    .{ .name = "glEnable", .kind = .v1 },
    .{ .name = "glEnableVertexAttribArray", .kind = .v1 },
    .{ .name = "glEndQuery", .kind = .v1 },
    .{ .name = "glEndQueryEXT", .kind = .v1 },
    .{ .name = "glEndTransformFeedback", .kind = .v0 },
    .{ .name = "glFenceSync", .kind = .ptr_2 },
    .{ .name = "glFinish", .kind = .v0 },
    .{ .name = "glFlush", .kind = .v0 },
    .{ .name = "glFlushMappedBufferRange", .kind = .ptr_3 },
    .{ .name = "glFlushMappedBufferRangeEXT", .kind = .ptr_3 },
    .{ .name = "glFramebufferRenderbuffer", .kind = .v4 },
    .{ .name = "glFramebufferTexture", .kind = .v4 },
    .{ .name = "glFramebufferTexture2D", .kind = .v5 },
    .{ .name = "glFramebufferTexture2DMultisampleEXT", .kind = .v6 },
    .{ .name = "glFramebufferTexture2DMultisampleIMG", .kind = .v6 },
    .{ .name = "glFramebufferTexture3D", .kind = .v6 },
    .{ .name = "glFramebufferTextureLayer", .kind = .v5 },
    .{ .name = "glFramebufferTextureMultisampleMultiviewOVR", .kind = .v7 },
    .{ .name = "glFramebufferTextureMultiviewOVR", .kind = .v6 },
    .{ .name = "glFrontFace", .kind = .v1 },
    .{ .name = "glGenBuffers", .kind = .v2 },
    .{ .name = "glGenFramebuffers", .kind = .v2 },
    .{ .name = "glGenQueries", .kind = .v2 },
    .{ .name = "glGenQueriesEXT", .kind = .v2 },
    .{ .name = "glGenRenderbuffers", .kind = .v2 },
    .{ .name = "glGenSamplers", .kind = .v2 },
    .{ .name = "glGenTextures", .kind = .v2 },
    .{ .name = "glGenTransformFeedbacks", .kind = .v2 },
    .{ .name = "glGenVertexArrays", .kind = .v2 },
    .{ .name = "glGenVertexArraysOES", .kind = .v2 },
    .{ .name = "glGenerateMipmap", .kind = .v1 },
    .{ .name = "glGetActiveAttrib", .kind = .v7 },
    .{ .name = "glGetActiveUniform", .kind = .v7 },
    .{ .name = "glGetActiveUniformBlockName", .kind = .v5 },
    .{ .name = "glGetActiveUniformBlockiv", .kind = .v4 },
    .{ .name = "glGetActiveUniformsiv", .kind = .v5 },
    .{ .name = "glGetAttribLocation", .kind = .i32_2 },
    .{ .name = "glGetBooleanv", .kind = .v2 },
    .{ .name = "glGetError", .kind = .u32_0 },
    .{ .name = "glGetFloatv", .kind = .v2 },
    .{ .name = "glGetFramebufferAttachmentParameteriv", .kind = .v4 },
    .{ .name = "glGetInteger64v", .kind = .v2 },
    .{ .name = "glGetIntegeri_v", .kind = .v3 },
    .{ .name = "glGetIntegerv", .kind = .v2 },
    .{ .name = "glGetInternalformativ", .kind = .v5 },
    .{ .name = "glGetObjectLabel", .kind = .v5 },
    .{ .name = "glGetObjectLabelEXT", .kind = .v5 },
    .{ .name = "glGetObjectLabelKHR", .kind = .v5 },
    .{ .name = "glGetProgramBinary", .kind = .v5 },
    .{ .name = "glGetProgramBinaryOES", .kind = .v5 },
    .{ .name = "glGetProgramInfoLog", .kind = .v4 },
    .{ .name = "glGetProgramInterfaceiv", .kind = .v4 },
    .{ .name = "glGetProgramResourceName", .kind = .v6 },
    .{ .name = "glGetProgramResourceiv", .kind = .v8 },
    .{ .name = "glGetProgramiv", .kind = .v3 },
    .{ .name = "glGetQueryObjectui64v", .kind = .v3 },
    .{ .name = "glGetQueryObjectui64vEXT", .kind = .v3 },
    .{ .name = "glGetQueryObjectui64vNV", .kind = .v3 },
    .{ .name = "glGetRenderbufferParameteriv", .kind = .v3 },
    .{ .name = "glGetShaderInfoLog", .kind = .v4 },
    .{ .name = "glGetShaderPrecisionFormat", .kind = .v4 },
    .{ .name = "glGetShaderSource", .kind = .v4 },
    .{ .name = "glGetShaderiv", .kind = .v3 },
    .{ .name = "glGetString", .kind = .ptr_1 },
    .{ .name = "glGetStringi", .kind = .ptr_2 },
    .{ .name = "glGetTexLevelParameterfv", .kind = .v4 },
    .{ .name = "glGetTexParameteriv", .kind = .v3 },
    .{ .name = "glGetTextureLevelParameteriv", .kind = .v4 },
    .{ .name = "glGetTextureParameteriv", .kind = .v3 },
    .{ .name = "glGetUniformBlockIndex", .kind = .u32_2 },
    .{ .name = "glGetUniformIndices", .kind = .v4 },
    .{ .name = "glGetUniformLocation", .kind = .i32_2 },
    .{ .name = "glGetUniformiv", .kind = .v3 },
    .{ .name = "glGetVertexAttribiv", .kind = .v3 },
    .{ .name = "glHint", .kind = .v2 },
    .{ .name = "glInvalidateFramebuffer", .kind = .v3 },
    .{ .name = "glIsEnabled", .kind = .u8_1 },
    .{ .name = "glIsVertexArray", .kind = .u8_1 },
    .{ .name = "glLabelObjectEXT", .kind = .v4 },
    .{ .name = "glLineWidth", .kind = .f_1f },
    .{ .name = "glLinkProgram", .kind = .v1 },
    .{ .name = "glMapBufferOES", .kind = .ptr_2 },
    .{ .name = "glMapBufferRange", .kind = .ptr_4 },
    .{ .name = "glMapBufferRangeEXT", .kind = .ptr_4 },
    .{ .name = "glMemoryBarrier", .kind = .v1 },
    .{ .name = "glObjectLabel", .kind = .v4 },
    .{ .name = "glObjectLabelKHR", .kind = .v4 },
    .{ .name = "glPatchParameteri", .kind = .v2 },
    .{ .name = "glPatchParameteriEXT", .kind = .v2 },
    .{ .name = "glPatchParameteriOES", .kind = .v2 },
    .{ .name = "glPixelStorei", .kind = .v2 },
    .{ .name = "glPointSize", .kind = .f_1f },
    .{ .name = "glPolygonMode", .kind = .v2 },
    .{ .name = "glPolygonOffset", .kind = .f_2f },
    .{ .name = "glPopDebugGroup", .kind = .v0 },
    .{ .name = "glPopDebugGroupKHR", .kind = .v0 },
    .{ .name = "glPopGroupMarkerEXT", .kind = .v0 },
    .{ .name = "glProgramBinary", .kind = .v4 },
    .{ .name = "glProgramBinaryOES", .kind = .v4 },
    .{ .name = "glProgramParameteri", .kind = .v3 },
    .{ .name = "glProgramUniform1fv", .kind = .v4 },
    .{ .name = "glProgramUniform1iv", .kind = .v4 },
    .{ .name = "glProgramUniform1uiv", .kind = .v4 },
    .{ .name = "glProgramUniform2fv", .kind = .v4 },
    .{ .name = "glProgramUniform2iv", .kind = .v4 },
    .{ .name = "glProgramUniform2uiv", .kind = .v4 },
    .{ .name = "glProgramUniform3fv", .kind = .v4 },
    .{ .name = "glProgramUniform3iv", .kind = .v4 },
    .{ .name = "glProgramUniform3uiv", .kind = .v4 },
    .{ .name = "glProgramUniform4fv", .kind = .v4 },
    .{ .name = "glProgramUniform4iv", .kind = .v4 },
    .{ .name = "glProgramUniform4uiv", .kind = .v4 },
    .{ .name = "glProgramUniformMatrix2fv", .kind = .v5 },
    .{ .name = "glProgramUniformMatrix2x3fv", .kind = .v5 },
    .{ .name = "glProgramUniformMatrix2x4fv", .kind = .v5 },
    .{ .name = "glProgramUniformMatrix3fv", .kind = .v5 },
    .{ .name = "glProgramUniformMatrix3x2fv", .kind = .v5 },
    .{ .name = "glProgramUniformMatrix3x4fv", .kind = .v5 },
    .{ .name = "glProgramUniformMatrix4fv", .kind = .v5 },
    .{ .name = "glProgramUniformMatrix4x2fv", .kind = .v5 },
    .{ .name = "glProgramUniformMatrix4x3fv", .kind = .v5 },
    .{ .name = "glPushDebugGroup", .kind = .v4 },
    .{ .name = "glPushDebugGroupKHR", .kind = .v4 },
    .{ .name = "glPushGroupMarkerEXT", .kind = .v2 },
    .{ .name = "glReadBuffer", .kind = .v1 },
    .{ .name = "glReadBufferNV", .kind = .v1 },
    .{ .name = "glReadPixels", .kind = .v7 },
    .{ .name = "glRenderbufferStorage", .kind = .v4 },
    .{ .name = "glRenderbufferStorageMultisample", .kind = .v5 },
    .{ .name = "glRenderbufferStorageMultisampleAPPLE", .kind = .v5 },
    .{ .name = "glRenderbufferStorageMultisampleEXT", .kind = .v5 },
    .{ .name = "glRenderbufferStorageMultisampleIMG", .kind = .v5 },
    .{ .name = "glRenderbufferStorageMultisampleNV", .kind = .v5 },
    .{ .name = "glResolveMultisampleFramebufferAPPLE", .kind = .v0 },
    .{ .name = "glSamplerParameterf", .kind = .f_uuf },
    .{ .name = "glSamplerParameteri", .kind = .v3 },
    .{ .name = "glScissor", .kind = .v4 },
    .{ .name = "glShaderSource", .kind = .v4 },
    .{ .name = "glStencilFuncSeparate", .kind = .v4 },
    .{ .name = "glStencilMask", .kind = .v1 },
    .{ .name = "glStencilOpSeparate", .kind = .v4 },
    .{ .name = "glTexBuffer", .kind = .v3 },
    .{ .name = "glTexBufferEXT", .kind = .v3 },
    .{ .name = "glTexImage1D", .kind = .v8 },
    .{ .name = "glTexImage2D", .kind = .v9 },
    .{ .name = "glTexImage2DMultisample", .kind = .v6 },
    .{ .name = "glTexImage3D", .kind = .v10 },
    .{ .name = "glTexImage3DOES", .kind = .v10 },
    .{ .name = "glTexPageCommitmentARB", .kind = .v9 },
    .{ .name = "glTexPageCommitmentEXT", .kind = .v9 },
    .{ .name = "glTexParameterf", .kind = .f_uuf },
    .{ .name = "glTexParameteri", .kind = .v3 },
    .{ .name = "glTexParameteriv", .kind = .v3 },
    .{ .name = "glTexStorage2D", .kind = .v5 },
    .{ .name = "glTexStorage2DEXT", .kind = .v5 },
    .{ .name = "glTexStorage2DMultisample", .kind = .v6 },
    .{ .name = "glTexStorage3D", .kind = .v6 },
    .{ .name = "glTexStorage3DEXT", .kind = .v6 },
    .{ .name = "glTexSubImage1D", .kind = .v7 },
    .{ .name = "glTexSubImage2D", .kind = .v9 },
    .{ .name = "glTexSubImage3D", .kind = .v11 },
    .{ .name = "glTexSubImage3DOES", .kind = .v11 },
    .{ .name = "glTextureView", .kind = .v8 },
    .{ .name = "glTextureViewEXT", .kind = .v8 },
    .{ .name = "glTextureViewOES", .kind = .v8 },
    .{ .name = "glTransformFeedbackVaryings", .kind = .v4 },
    .{ .name = "glUniform1fv", .kind = .v3 },
    .{ .name = "glUniform1i", .kind = .v2 },
    .{ .name = "glUniform1iv", .kind = .v3 },
    .{ .name = "glUniform1uiv", .kind = .v3 },
    .{ .name = "glUniform2fv", .kind = .v3 },
    .{ .name = "glUniform2iv", .kind = .v3 },
    .{ .name = "glUniform2uiv", .kind = .v3 },
    .{ .name = "glUniform3fv", .kind = .v3 },
    .{ .name = "glUniform3iv", .kind = .v3 },
    .{ .name = "glUniform3uiv", .kind = .v3 },
    .{ .name = "glUniform4fv", .kind = .v3 },
    .{ .name = "glUniform4iv", .kind = .v3 },
    .{ .name = "glUniform4uiv", .kind = .v3 },
    .{ .name = "glUniformBlockBinding", .kind = .v3 },
    .{ .name = "glUniformMatrix3fv", .kind = .v4 },
    .{ .name = "glUniformMatrix4fv", .kind = .v4 },
    .{ .name = "glUnmapBuffer", .kind = .ptr_1 },
    .{ .name = "glUnmapBufferEXT", .kind = .u8_1 },
    .{ .name = "glUnmapBufferOES", .kind = .ptr_1 },
    .{ .name = "glUseProgram", .kind = .v1 },
    .{ .name = "glValidateProgram", .kind = .v1 },
    .{ .name = "glVertexAttrib4f", .kind = .f_u4f },
    .{ .name = "glVertexAttrib4fv", .kind = .v2 },
    .{ .name = "glVertexAttribIPointer", .kind = .v5 },
    .{ .name = "glVertexAttribPointer", .kind = .v6 },
    .{ .name = "glViewport", .kind = .v4 },
};

var g_gl_ptrs: [gl_specs.len]std.atomic.Value(usize) = [_]std.atomic.Value(usize){std.atomic.Value(usize).init(0)} ** gl_specs.len;

fn ptrAt(comptime idx: usize, comptime Fn: type) Fn {
    const raw = g_gl_ptrs[idx].load(.acquire);
    return @ptrFromInt(raw);
}

fn GlThunk(comptime idx: usize, comptime kind: GlKind) *const anyopaque {
    return switch (kind) {
        .v0 => @ptrCast(&(struct { fn f() callconv(W) void { ptrAt(idx, *const fn () callconv(.c) void)(); } }).f),
        .v1 => @ptrCast(&(struct { fn f(a0: usize) callconv(W) void { ptrAt(idx, *const fn (usize) callconv(.c) void)(a0); } }).f),
        .v2 => @ptrCast(&(struct { fn f(a0: usize, a1: usize) callconv(W) void { ptrAt(idx, *const fn (usize, usize) callconv(.c) void)(a0, a1); } }).f),
        .v3 => @ptrCast(&(struct { fn f(a0: usize, a1: usize, a2: usize) callconv(W) void { ptrAt(idx, *const fn (usize, usize, usize) callconv(.c) void)(a0, a1, a2); } }).f),
        .v4 => @ptrCast(&(struct { fn f(a0: usize, a1: usize, a2: usize, a3: usize) callconv(W) void { ptrAt(idx, *const fn (usize, usize, usize, usize) callconv(.c) void)(a0, a1, a2, a3); } }).f),
        .v5 => @ptrCast(&(struct { fn f(a0: usize, a1: usize, a2: usize, a3: usize, a4: usize) callconv(W) void { ptrAt(idx, *const fn (usize, usize, usize, usize, usize) callconv(.c) void)(a0, a1, a2, a3, a4); } }).f),
        .v6 => @ptrCast(&(struct { fn f(a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) callconv(W) void { ptrAt(idx, *const fn (usize, usize, usize, usize, usize, usize) callconv(.c) void)(a0, a1, a2, a3, a4, a5); } }).f),
        .v7 => @ptrCast(&(struct { fn f(a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) callconv(W) void { ptrAt(idx, *const fn (usize, usize, usize, usize, usize, usize, usize) callconv(.c) void)(a0, a1, a2, a3, a4, a5, a6); } }).f),
        .v8 => @ptrCast(&(struct { fn f(a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize) callconv(W) void { ptrAt(idx, *const fn (usize, usize, usize, usize, usize, usize, usize, usize) callconv(.c) void)(a0, a1, a2, a3, a4, a5, a6, a7); } }).f),
        .v9 => @ptrCast(&(struct { fn f(a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize) callconv(W) void { ptrAt(idx, *const fn (usize, usize, usize, usize, usize, usize, usize, usize, usize) callconv(.c) void)(a0, a1, a2, a3, a4, a5, a6, a7, a8); } }).f),
        .v10 => @ptrCast(&(struct { fn f(a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize, a9: usize) callconv(W) void { ptrAt(idx, *const fn (usize, usize, usize, usize, usize, usize, usize, usize, usize, usize) callconv(.c) void)(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9); } }).f),
        .v11 => @ptrCast(&(struct { fn f(a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize, a9: usize, a10: usize) callconv(W) void { ptrAt(idx, *const fn (usize, usize, usize, usize, usize, usize, usize, usize, usize, usize, usize) callconv(.c) void)(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10); } }).f),
        .v15 => @ptrCast(&(struct { fn f(a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize, a9: usize, a10: usize, a11: usize, a12: usize, a13: usize, a14: usize) callconv(W) void { ptrAt(idx, *const fn (usize, usize, usize, usize, usize, usize, usize, usize, usize, usize, usize, usize, usize, usize, usize) callconv(.c) void)(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14); } }).f),
        .u8_1 => @ptrCast(&(struct { fn f(a0: usize) callconv(W) u8 { return ptrAt(idx, *const fn (usize) callconv(.c) u8)(a0); } }).f),
        .i32_2 => @ptrCast(&(struct { fn f(a0: usize, a1: usize) callconv(W) i32 { return ptrAt(idx, *const fn (usize, usize) callconv(.c) i32)(a0, a1); } }).f),
        .u32_0 => @ptrCast(&(struct { fn f() callconv(W) u32 { return ptrAt(idx, *const fn () callconv(.c) u32)(); } }).f),
        .u32_1 => @ptrCast(&(struct { fn f(a0: usize) callconv(W) u32 { return ptrAt(idx, *const fn (usize) callconv(.c) u32)(a0); } }).f),
        .u32_2 => @ptrCast(&(struct { fn f(a0: usize, a1: usize) callconv(W) u32 { return ptrAt(idx, *const fn (usize, usize) callconv(.c) u32)(a0, a1); } }).f),
        .u32_3 => @ptrCast(&(struct { fn f(a0: usize, a1: usize, a2: usize) callconv(W) u32 { return ptrAt(idx, *const fn (usize, usize, usize) callconv(.c) u32)(a0, a1, a2); } }).f),
        .ptr_1 => @ptrCast(&(struct { fn f(a0: usize) callconv(W) usize { return ptrAt(idx, *const fn (usize) callconv(.c) usize)(a0); } }).f),
        .ptr_2 => @ptrCast(&(struct { fn f(a0: usize, a1: usize) callconv(W) usize { return ptrAt(idx, *const fn (usize, usize) callconv(.c) usize)(a0, a1); } }).f),
        .ptr_3 => @ptrCast(&(struct { fn f(a0: usize, a1: usize, a2: usize) callconv(W) usize { return ptrAt(idx, *const fn (usize, usize, usize) callconv(.c) usize)(a0, a1, a2); } }).f),
        .ptr_4 => @ptrCast(&(struct { fn f(a0: usize, a1: usize, a2: usize, a3: usize) callconv(W) usize { return ptrAt(idx, *const fn (usize, usize, usize, usize) callconv(.c) usize)(a0, a1, a2, a3); } }).f),
        .f_4f => @ptrCast(&(struct { fn f(a0: f32, a1: f32, a2: f32, a3: f32) callconv(W) void { ptrAt(idx, *const fn (f32, f32, f32, f32) callconv(.c) void)(a0, a1, a2, a3); } }).f),
        .f_1d => @ptrCast(&(struct { fn f(a0: f64) callconv(W) void { ptrAt(idx, *const fn (f64) callconv(.c) void)(a0); } }).f),
        .f_1f => @ptrCast(&(struct { fn f(a0: f32) callconv(W) void { ptrAt(idx, *const fn (f32) callconv(.c) void)(a0); } }).f),
        .f_2d => @ptrCast(&(struct { fn f(a0: f64, a1: f64) callconv(W) void { ptrAt(idx, *const fn (f64, f64) callconv(.c) void)(a0, a1); } }).f),
        .f_2f => @ptrCast(&(struct { fn f(a0: f32, a1: f32) callconv(W) void { ptrAt(idx, *const fn (f32, f32) callconv(.c) void)(a0, a1); } }).f),
        .f_uuf => @ptrCast(&(struct { fn f(a0: usize, a1: usize, a2: f32) callconv(W) void { ptrAt(idx, *const fn (usize, usize, f32) callconv(.c) void)(a0, a1, a2); } }).f),
        .f_u4f => @ptrCast(&(struct { fn f(a0: usize, a1: f32, a2: f32, a3: f32, a4: f32) callconv(W) void { ptrAt(idx, *const fn (usize, f32, f32, f32, f32) callconv(.c) void)(a0, a1, a2, a3, a4); } }).f),
        .f_uufi => @ptrCast(&(struct { fn f(a0: usize, a1: usize, a2: f32, a3: usize) callconv(W) void { ptrAt(idx, *const fn (usize, usize, f32, usize) callconv(.c) void)(a0, a1, a2, a3); } }).f),
        .debug_cb => @ptrCast(&(struct {
            fn f(cb: ?WinDebugProc, user: ?*const anyopaque) callconv(W) void {
                g_debug_cb = cb;
                ptrAt(idx, *const fn (?*const anyopaque, ?*const anyopaque) callconv(.c) void)(
                    if (cb != null) @ptrCast(&hostDebugTrampoline) else null,
                    user,
                );
            }
        }).f),
    };
}

pub fn wglGetProcAddress(name_opt: ?[*:0]const u8) callconv(W) ?*anyopaque {
    @setEvalBranchQuota(10000);
    const n_ptr = name_opt orelse return null;
    const name = std.mem.span(n_ptr);
    if (std.mem.eql(u8, name, "wglCreateContextAttribsARB")) return @ptrCast(@constCast(&wglCreateContextAttribsARB));
    if (std.mem.eql(u8, name, "wglChoosePixelFormatARB")) return @ptrCast(@constCast(&wglChoosePixelFormatARB));
    if (std.mem.eql(u8, name, "wglGetPixelFormatAttribivARB")) return @ptrCast(@constCast(&wglGetPixelFormatAttribivARB));
    if (std.mem.eql(u8, name, "wglGetPixelFormatAttribfvARB")) return @ptrCast(@constCast(&wglGetPixelFormatAttribfvARB));
    if (std.mem.eql(u8, name, "wglGetExtensionsStringARB")) return @ptrCast(@constCast(&wglGetExtensionsStringARB));
    if (std.mem.eql(u8, name, "wglGetExtensionsStringEXT")) return @ptrCast(@constCast(&wglGetExtensionsStringEXT));
    if (std.mem.eql(u8, name, "wglSwapIntervalEXT")) return @ptrCast(@constCast(&wglSwapIntervalEXT));

    inline for (gl_specs, 0..) |spec, idx| {
        if (std.mem.eql(u8, name, spec.name)) {
            var ptr = g_gl_ptrs[idx].load(.acquire);
            if (ptr == 0) {
                const real = resolveRealGl(spec.name) orelse return null;
                ptr = @intFromPtr(real);
                g_gl_ptrs[idx].store(ptr, .release);
            }
            return @constCast(comptime GlThunk(idx, spec.kind));
        }
    }
    if (std.c.getenv("WINS_TRACE") != null) {
        std.debug.print("[WINS:GL] wglGetProcAddress({s}) -> null\n", .{name});
    }
    return null;
}

pub fn lookupOpengl32(name: []const u8) ?usize {
    @setEvalBranchQuota(10000);
    if (std.mem.eql(u8, name, "wglCreateContext")) return @intFromPtr(&wglCreateContext);
    if (std.mem.eql(u8, name, "wglDeleteContext")) return @intFromPtr(&wglDeleteContext);
    if (std.mem.eql(u8, name, "wglMakeCurrent")) return @intFromPtr(&wglMakeCurrent);
    if (std.mem.eql(u8, name, "wglGetCurrentDC")) return @intFromPtr(&wglGetCurrentDC);
    if (std.mem.eql(u8, name, "wglGetCurrentContext")) return @intFromPtr(&wglGetCurrentContext);
    if (std.mem.eql(u8, name, "wglGetProcAddress")) return @intFromPtr(&wglGetProcAddress);
    if (std.mem.eql(u8, name, "wglShareLists")) return @intFromPtr(&wglShareLists);
    inline for (gl_specs, 0..) |spec, idx| {
        if (std.mem.eql(u8, name, spec.name)) {
            if (resolveRealGl(spec.name)) |real| {
                g_gl_ptrs[idx].store(@intFromPtr(real), .release);
                return @intFromPtr(comptime GlThunk(idx, spec.kind));
            }
            return null;
        }
    }
    return null;
}
