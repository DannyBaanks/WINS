//! IDirect3DDevice9 on the host GPU.
//!
//! The device object (wins_d3d9.zig) keeps the Direct3D state exactly as the
//! guest set it. This module executes clears, draws and presents from that
//! state with OpenGL, on the render thread of wins_gl.zig:
//!
//!   * the back buffer is a framebuffer object whose row 0 is the TOP row, as
//!     in Direct3D (glClipControl(UPPER_LEFT, ZERO_TO_ONE) gives Direct3D clip
//!     space, so no shader or state needs flipping); Present blits it,
//!     vertically mirrored, into the window;
//!   * shaders are translated to GLSL per (vertex, pixel) pair and cached;
//!   * vertex/index data is read straight from the guest-visible buffers;
//!   * textures are uploaded when first used and again after an unlock.
//!
//! What is not implemented is reported once and the draw is skipped: render
//! targets other than the back buffer, fixed-function vertex/pixel processing,
//! FVF vertex formats, cube/volume textures.

const std = @import("std");
const d3d = @import("wins_d3d9.zig");
const host = @import("wins_gl.zig");
const shader = @import("wins_d3d9_shader.zig");

const Device = d3d.WinsD3DDevice9;

/// True once a device has a host surface; the software path is then unused.
pub var active: bool = false;

/// WINS_D3D9_CAPTURE=<frame>:<path>: write that presented frame as a PPM.
pub var capture_frame: u64 = std.math.maxInt(u64);
pub var capture_path: [256:0]u8 = [_:0]u8{0} ** 256;
/// Non-zero: capture again every `capture_period` frames, as <path>-<frame>.ppm.
pub var capture_period: u64 = 0;

const alloc = std.heap.page_allocator;

var g_fbo: host.GLuint = 0;
var g_color: host.GLuint = 0;
var g_depth: host.GLuint = 0;
var g_w: u32 = 0;
var g_h: u32 = 0;

const Program = struct {
    vs: ?*const d3d.WinsShader9,
    ps: ?*const d3d.WinsShader9,
    /// Fixed-function programs: the state they were generated for.
    fixed_key: ?FixedKey = null,
    loc_wvp: host.GLint = -1,
    loc_vp: host.GLint = -1,
    loc_tfactor: host.GLint = -1,
    /// 0 when the pair could not be translated/compiled/linked.
    prog: host.GLuint,
    inputs: []shader.Input,
    samplers: [16]shader.SamplerKind,
    vs_const_count: u16,
    ps_const_count: u16,
    loc_vs_c: host.GLint,
    loc_ps_c: host.GLint,
    loc_half: host.GLint,
};
var g_programs: std.ArrayList(Program) = .empty;
var g_attrib_enabled: u16 = 0;

var g_warned: u32 = 0;
fn warnOnce(bit: u5, comptime msg: []const u8) void {
    const m = @as(u32, 1) << bit;
    if (g_warned & m != 0) return;
    g_warned |= m;
    std.debug.print("[WINS:D3D9:GL] " ++ msg ++ " (reported once)\n", .{});
}

const GL_TEXTURE_2D = 0x0DE1;
const GL_FRAMEBUFFER = 0x8D40;
const GL_READ_FRAMEBUFFER = 0x8CA8;
const GL_DRAW_FRAMEBUFFER = 0x8CA9;
const GL_RENDERBUFFER = 0x8D41;
const GL_SCISSOR_TEST = 0x0C11;
const GL_DEPTH_TEST = 0x0B71;
const GL_STENCIL_TEST = 0x0B90;
const GL_ALPHA_TEST = 0x0BC0;
const GL_BLEND = 0x0BE2;
const GL_CULL_FACE = 0x0B44;
const GL_BGRA = 0x80E1;
const GL_RGBA = 0x1908;
const GL_UNSIGNED_BYTE = 0x1401;

// ---- attach -----------------------------------------------------------------

const AttachJob = struct { ok: bool = false };

fn attachJob(raw: ?*anyopaque) void {
    const job: *AttachJob = @ptrCast(@alignCast(raw.?));
    const gl = &host.gl;
    // Direct3D clip space: +y up maps to row 0 first, depth 0..1.
    gl.glClipControl(0x8CA2, 0x935F); // GL_UPPER_LEFT, GL_ZERO_TO_ONE
    if (gl.glGetError() != 0) {
        std.debug.print("[WINS:D3D9:GL] this OpenGL has no glClipControl (needs 4.5 / ARB_clip_control); no host rendering\n", .{});
        return;
    }
    gl.glGenTextures(1, &g_color);
    gl.glBindTexture(GL_TEXTURE_2D, g_color);
    gl.glTexParameteri(GL_TEXTURE_2D, 0x2801, 0x2600); // MIN_FILTER NEAREST
    gl.glTexParameteri(GL_TEXTURE_2D, 0x2800, 0x2600); // MAG_FILTER NEAREST
    gl.glTexImage2D(GL_TEXTURE_2D, 0, 0x8058, @intCast(g_w), @intCast(g_h), 0, GL_BGRA, GL_UNSIGNED_BYTE, null); // RGBA8
    gl.glBindTexture(GL_TEXTURE_2D, 0);
    gl.glGenRenderbuffers(1, &g_depth);
    gl.glBindRenderbuffer(GL_RENDERBUFFER, g_depth);
    gl.glRenderbufferStorage(GL_RENDERBUFFER, 0x88F0, @intCast(g_w), @intCast(g_h)); // DEPTH24_STENCIL8
    gl.glGenFramebuffers(1, &g_fbo);
    gl.glBindFramebuffer(GL_FRAMEBUFFER, g_fbo);
    gl.glFramebufferTexture2D(GL_FRAMEBUFFER, 0x8CE0, GL_TEXTURE_2D, g_color, 0); // COLOR_ATTACHMENT0
    gl.glFramebufferRenderbuffer(GL_FRAMEBUFFER, 0x821A, GL_RENDERBUFFER, g_depth); // DEPTH_STENCIL_ATTACHMENT
    const status = gl.glCheckFramebufferStatus(GL_FRAMEBUFFER);
    if (status != 0x8CD5) {
        std.debug.print("[WINS:D3D9:GL] back buffer framebuffer is incomplete (0x{x}); no host rendering\n", .{status});
        return;
    }
    gl.glPixelStorei(0x0CF5, 1); // UNPACK_ALIGNMENT
    gl.glPixelStorei(0x0D05, 1); // PACK_ALIGNMENT
    gl.glClearColor(0, 0, 0, 1);
    gl.glClear(0x4000);
    job.ok = true;
}

/// Give a new device its host surface. False (and the device stays headless)
/// when the host has no display or its OpenGL lacks what the backend needs.
pub fn attach(w: u32, h: u32, title: []const u8) bool {
    if (active) return true;
    if (!host.start(w, h, title)) return false;
    g_w = w;
    g_h = h;
    var job: AttachJob = .{};
    host.run(&attachJob, &job);
    active = job.ok;
    return active;
}

// ---- state ------------------------------------------------------------------

fn cmpFunc(v: u32) host.GLenum {
    return if (v >= 1 and v <= 8) 0x0200 + (v - 1) else 0x0207; // ALWAYS
}

fn blendFactor(v: u32, comptime is_src: bool) host.GLenum {
    return switch (v) {
        1 => 0,
        2 => 1,
        3 => 0x0300,
        4 => 0x0301,
        5 => 0x0302,
        6 => 0x0303,
        7 => 0x0304,
        8 => 0x0305,
        9 => 0x0306,
        10 => 0x0307,
        11 => 0x0308,
        14 => 0x8001,
        15 => 0x8002,
        else => if (is_src) 1 else 0, // D3D defaults: ONE / ZERO
    };
}

fn blendOp(v: u32) host.GLenum {
    return switch (v) {
        2 => 0x800A,
        3 => 0x800B,
        4 => 0x8007,
        5 => 0x8008,
        else => 0x8006, // ADD
    };
}

fn stencilOp(v: u32) host.GLenum {
    return switch (v) {
        2 => 0,
        3 => 0x1E01,
        4 => 0x1E02,
        5 => 0x1E03,
        6 => 0x150A,
        7 => 0x8507,
        8 => 0x8508,
        else => 0x1E00, // KEEP
    };
}

fn setEnabled(cap: host.GLenum, on: bool) void {
    if (on) host.gl.glEnable(cap) else host.gl.glDisable(cap);
}

// ---- render targets ------------------------------------------------------------

const RtFormat = struct { internal: host.GLint, format: host.GLenum, ty: host.GLenum, channels: u8 };

/// Colour formats a render target can have, as OpenGL storage. `channels`
/// below 4 makes the missing components read as 1, as D3D9 samples them.
fn rtFormat(format: u32) RtFormat {
    return switch (format) {
        113 => .{ .internal = 0x881A, .format = GL_RGBA, .ty = 0x140B, .channels = 4 }, // A16B16G16R16F
        116 => .{ .internal = 0x8814, .format = GL_RGBA, .ty = 0x1406, .channels = 4 }, // A32B32G32R32F
        114 => .{ .internal = 0x822E, .format = 0x1903, .ty = 0x1406, .channels = 1 }, // R32F
        111 => .{ .internal = 0x822D, .format = 0x1903, .ty = 0x140B, .channels = 1 }, // R16F
        112 => .{ .internal = 0x822F, .format = 0x8227, .ty = 0x140B, .channels = 2 }, // G16R16F
        115 => .{ .internal = 0x8230, .format = 0x8227, .ty = 0x1406, .channels = 2 }, // G32R32F
        31, 35 => .{ .internal = 0x8059, .format = GL_RGBA, .ty = GL_UNSIGNED_BYTE, .channels = 4 }, // 10:10:10:2
        34 => .{ .internal = 0x805B, .format = GL_RGBA, .ty = 0x1403, .channels = 4 }, // A16B16G16R16
        else => .{ .internal = 0x8058, .format = GL_BGRA, .ty = GL_UNSIGNED_BYTE, .channels = 4 }, // 8-bit RGBA
    };
}

fn allocRtTexture(name: *host.GLuint, format: u32, w: u32, h: u32, levels: usize) void {
    const gl = &host.gl;
    const f = rtFormat(format);
    gl.glGenTextures(1, name);
    gl.glBindTexture(GL_TEXTURE_2D, name.*);
    var l: usize = 0;
    while (l < levels) : (l += 1) {
        gl.glTexImage2D(GL_TEXTURE_2D, @intCast(l), f.internal, @intCast(@max(1, w >> @intCast(l))), @intCast(@max(1, h >> @intCast(l))), 0, f.format, f.ty, null);
    }
    gl.glTexParameteri(GL_TEXTURE_2D, 0x813D, @intCast(levels - 1)); // MAX_LEVEL
    if (f.channels < 2) gl.glTexParameteri(GL_TEXTURE_2D, 0x8E43, 1); // SWIZZLE_G = ONE
    if (f.channels < 3) gl.glTexParameteri(GL_TEXTURE_2D, 0x8E44, 1); // SWIZZLE_B = ONE
    if (f.channels < 4) gl.glTexParameteri(GL_TEXTURE_2D, 0x8E45, 1); // SWIZZLE_A = ONE
    gl.glTexParameteri(GL_TEXTURE_2D, 0x2801, 0x2601);
    gl.glTexParameteri(GL_TEXTURE_2D, 0x2800, 0x2601);
}

const ColorRef = struct { tex: host.GLuint, level: host.GLint };

/// The GPU texture (and level) behind a colour surface the device renders
/// into or copies from. The back buffer is the presentation texture.
fn colorOf(dev: *Device, s: *d3d.WinsSurface9) ColorRef {
    if (d3d.deviceRenderTarget(dev)) |bb| {
        if (s == bb) return .{ .tex = g_color, .level = 0 };
    }
    if (s.parent) |t| {
        if (t.gl_name == 0) allocRtTexture(&t.gl_name, t.format, t.width, t.height, t.surfaces.len);
        return .{ .tex = t.gl_name, .level = @intCast(s.level) };
    }
    if (s.gl_name == 0) {
        allocRtTexture(&s.gl_name, s.format, s.width, s.height, 1);
        // A surface with CPU pixels (off-screen plain) starts with them.
        if (s.usage & d3d.D3DUSAGE_RENDERTARGET == 0) {
            if (texFormat(s.format)) |tf| {
                if (!tf.compressed) host.gl.glTexImage2D(GL_TEXTURE_2D, 0, @intCast(tf.internal), @intCast(s.width), @intCast(s.height), 0, tf.format, tf.ty, s.data.ptr);
            }
        }
    }
    return .{ .tex = s.gl_name, .level = 0 };
}

/// The renderbuffer behind a depth/stencil surface; the device's automatic
/// one shares the back buffer's.
fn depthOf(dev: *Device, s: *d3d.WinsSurface9) host.GLuint {
    if (d3d.deviceDepthStencil(dev)) |auto| {
        if (s == auto and s.width == g_w and s.height == g_h) return g_depth;
    }
    if (s.gl_name == 0) {
        const gl = &host.gl;
        gl.glGenRenderbuffers(1, &s.gl_name);
        gl.glBindRenderbuffer(GL_RENDERBUFFER, s.gl_name);
        gl.glRenderbufferStorage(GL_RENDERBUFFER, 0x88F0, @intCast(s.width), @intCast(s.height)); // DEPTH24_STENCIL8
    }
    return s.gl_name;
}

var g_rt_fbo: host.GLuint = 0;
var g_rt_bound: [4]ColorRef = [_]ColorRef{.{ .tex = 0, .level = 0 }} ** 4;
var g_rt_depth: host.GLuint = 0;
var g_copy_fbo: [2]host.GLuint = .{ 0, 0 };

fn bindTargets(dev: *Device) void {
    const gl = &host.gl;
    if (g_rt_fbo == 0) gl.glGenFramebuffers(1, &g_rt_fbo);
    gl.glBindFramebuffer(GL_FRAMEBUFFER, g_rt_fbo);
    var want: [4]ColorRef = [_]ColorRef{.{ .tex = 0, .level = 0 }} ** 4;
    for (0..4) |i| {
        if (dev.render_targets[i]) |s| {
            want[i] = colorOf(dev, s);
        } else if (i == 0) want[i] = .{ .tex = g_color, .level = 0 };
    }
    const ds: host.GLuint = if (d3d.deviceBoundDepthStencil(dev)) |s| depthOf(dev, s) else 0;
    var changed = false;
    for (0..4) |i| {
        if (want[i].tex != g_rt_bound[i].tex or want[i].level != g_rt_bound[i].level) {
            gl.glFramebufferTexture2D(GL_FRAMEBUFFER, 0x8CE0 + @as(host.GLenum, @intCast(i)), GL_TEXTURE_2D, want[i].tex, want[i].level);
            g_rt_bound[i] = want[i];
            changed = true;
        }
    }
    if (ds != g_rt_depth) {
        gl.glFramebufferRenderbuffer(GL_FRAMEBUFFER, 0x821A, GL_RENDERBUFFER, ds);
        g_rt_depth = ds;
        changed = true;
    }
    if (changed) {
        var bufs: [4]host.GLenum = undefined;
        var n: usize = 0;
        for (0..4) |i| {
            bufs[i] = if (want[i].tex != 0) 0x8CE0 + @as(host.GLenum, @intCast(i)) else 0; // NONE
            if (want[i].tex != 0) n = i + 1;
        }
        gl.glDrawBuffers(@intCast(@max(n, 1)), &bufs);
        const st = gl.glCheckFramebufferStatus(GL_FRAMEBUFFER);
        if (st != 0x8CD5) std.debug.print("[WINS:D3D9:GL] render-target set is incomplete (0x{x}); its draws are lost\n", .{st});
    }
}

/// Bind `s` alone to one of the two copy framebuffers (0 read, 1 draw).
fn bindCopy(dev: *Device, which: usize, s: *d3d.WinsSurface9) bool {
    const gl = &host.gl;
    if (g_copy_fbo[which] == 0) gl.glGenFramebuffers(1, &g_copy_fbo[which]);
    const target: host.GLenum = if (which == 0) GL_READ_FRAMEBUFFER else GL_DRAW_FRAMEBUFFER;
    gl.glBindFramebuffer(target, g_copy_fbo[which]);
    if (s.usage & d3d.D3DUSAGE_DEPTHSTENCIL != 0) {
        gl.glFramebufferTexture2D(target, 0x8CE0, GL_TEXTURE_2D, 0, 0);
        gl.glFramebufferRenderbuffer(target, 0x821A, GL_RENDERBUFFER, depthOf(dev, s));
    } else {
        const c = colorOf(dev, s);
        gl.glFramebufferRenderbuffer(target, 0x821A, GL_RENDERBUFFER, 0);
        gl.glFramebufferTexture2D(target, 0x8CE0, GL_TEXTURE_2D, c.tex, c.level);
    }
    return gl.glCheckFramebufferStatus(target) == 0x8CD5;
}

const StretchJob = struct { dev: *Device, src: *d3d.WinsSurface9, sr: d3d.D3DRECT, dst: *d3d.WinsSurface9, dr: d3d.D3DRECT, filter: u32 };
fn stretchJob(raw: ?*anyopaque) void {
    const j: *StretchJob = @ptrCast(@alignCast(raw.?));
    const gl = &host.gl;
    if (!bindCopy(j.dev, 0, j.src) or !bindCopy(j.dev, 1, j.dst)) return warnOnce(12, "a StretchRect between these surfaces has no OpenGL path; skipped");
    gl.glDisable(GL_SCISSOR_TEST);
    gl.glColorMask(1, 1, 1, 1);
    const depth = j.src.usage & d3d.D3DUSAGE_DEPTHSTENCIL != 0;
    const mask: c_uint = if (depth) 0x0100 | 0x0400 else 0x4000;
    const filter: host.GLenum = if (!depth and j.filter == 2) 0x2601 else 0x2600; // D3DTEXF_LINEAR
    gl.glBlitFramebuffer(j.sr.x1, j.sr.y1, j.sr.x2, j.sr.y2, j.dr.x1, j.dr.y1, j.dr.x2, j.dr.y2, mask, filter);
    // A destination with CPU pixels (off-screen plain, or a non-target texture
    // level): bring the result back to the memory the guest reads.
    const is_bb = if (d3d.deviceRenderTarget(j.dev)) |bb| bb == j.dst else false;
    if (!depth and !is_bb and j.dst.usage & d3d.D3DUSAGE_RENDERTARGET == 0) {
        gl.glBindFramebuffer(GL_READ_FRAMEBUFFER, g_copy_fbo[1]);
        if (texFormat(j.dst.format)) |tf| {
            if (!tf.compressed) gl.glReadPixels(0, 0, @intCast(j.dst.width), @intCast(j.dst.height), tf.format, tf.ty, j.dst.data.ptr);
        }
    }
}
pub fn stretchRect(dev: *Device, src: *d3d.WinsSurface9, sr: d3d.D3DRECT, dst: *d3d.WinsSurface9, dr: d3d.D3DRECT, filter: u32) void {
    var j: StretchJob = .{ .dev = dev, .src = src, .sr = sr, .dst = dst, .dr = dr, .filter = filter };
    host.run(&stretchJob, &j);
}

const FillJob = struct { dev: *Device, s: *d3d.WinsSurface9, r: d3d.D3DRECT, color: u32 };
fn fillJob(raw: ?*anyopaque) void {
    const j: *FillJob = @ptrCast(@alignCast(raw.?));
    const gl = &host.gl;
    if (!bindCopy(j.dev, 1, j.s)) return;
    gl.glBindFramebuffer(GL_FRAMEBUFFER, g_copy_fbo[1]);
    gl.glEnable(GL_SCISSOR_TEST);
    gl.glScissor(j.r.x1, j.r.y1, @max(0, j.r.x2 - j.r.x1), @max(0, j.r.y2 - j.r.y1));
    gl.glColorMask(1, 1, 1, 1);
    const c = j.color;
    gl.glClearColor(@as(f32, @floatFromInt((c >> 16) & 0xFF)) / 255.0, @as(f32, @floatFromInt((c >> 8) & 0xFF)) / 255.0, @as(f32, @floatFromInt(c & 0xFF)) / 255.0, @as(f32, @floatFromInt(c >> 24)) / 255.0);
    gl.glClear(0x4000);
}
pub fn colorFill(dev: *Device, s: *d3d.WinsSurface9, r: d3d.D3DRECT, color: u32) void {
    var j: FillJob = .{ .dev = dev, .s = s, .r = r, .color = color };
    host.run(&fillJob, &j);
}

const ReadJob = struct { dev: *Device, src: *d3d.WinsSurface9, dst: *d3d.WinsSurface9 };
fn readJob(raw: ?*anyopaque) void {
    const j: *ReadJob = @ptrCast(@alignCast(raw.?));
    const gl = &host.gl;
    if (!bindCopy(j.dev, 0, j.src)) return;
    const f = rtFormat(j.dst.format);
    gl.glReadPixels(0, 0, @intCast(j.dst.width), @intCast(j.dst.height), f.format, f.ty, j.dst.data.ptr);
}
pub fn readSurface(dev: *Device, src: *d3d.WinsSurface9, dst: *d3d.WinsSurface9) void {
    var j: ReadJob = .{ .dev = dev, .src = src, .dst = dst };
    host.run(&readJob, &j);
}

fn applyTargetState(dev: *Device) void {
    const gl = &host.gl;
    bindTargets(dev);
    const vp = dev.viewport;
    gl.glViewport(@intCast(vp.X), @intCast(vp.Y), @intCast(vp.Width), @intCast(vp.Height));
    gl.glDepthRange(vp.MinZ, vp.MaxZ);
}

fn applyRenderStates(dev: *const Device) void {
    const gl = &host.gl;
    const rs = &dev.render_states;
    const has_depth = dev.bound_ds_surface != null or !dev.depth_stencil_explicit;
    setEnabled(GL_DEPTH_TEST, rs[7] != 0 and has_depth);
    gl.glDepthFunc(cmpFunc(rs[23]));
    gl.glDepthMask(@intFromBool(rs[14] != 0));
    setEnabled(GL_ALPHA_TEST, rs[15] != 0);
    gl.glAlphaFunc(cmpFunc(rs[25]), @as(f32, @floatFromInt(rs[24] & 0xFF)) / 255.0);
    setEnabled(GL_BLEND, rs[27] != 0);
    var src = rs[19];
    var dst = rs[20];
    if (src == 12) { // BOTHSRCALPHA
        src = 5;
        dst = 6;
    } else if (src == 13) { // BOTHINVSRCALPHA
        src = 6;
        dst = 5;
    }
    const separate = rs[206] != 0;
    gl.glBlendFuncSeparate(
        blendFactor(src, true),
        blendFactor(dst, false),
        blendFactor(if (separate) rs[207] else src, true),
        blendFactor(if (separate) rs[208] else dst, false),
    );
    gl.glBlendEquationSeparate(blendOp(rs[171]), blendOp(if (separate) rs[209] else rs[171]));
    // Direct3D names the winding as seen on screen; clip control keeps OpenGL's
    // front face (counter-clockwise) meaning the same thing.
    switch (rs[22]) {
        2 => { // D3DCULL_CW
            gl.glEnable(GL_CULL_FACE);
            gl.glCullFace(0x0405); // BACK
        },
        3 => { // D3DCULL_CCW
            gl.glEnable(GL_CULL_FACE);
            gl.glCullFace(0x0404); // FRONT
        },
        else => gl.glDisable(GL_CULL_FACE),
    }
    gl.glFrontFace(0x0901); // CCW
    setEnabled(GL_SCISSOR_TEST, rs[174] != 0);
    const sc = dev.scissor;
    gl.glScissor(sc.x1, sc.y1, @max(0, sc.x2 - sc.x1), @max(0, sc.y2 - sc.y1));
    const cw = rs[168];
    gl.glColorMask(@intFromBool(cw & 1 != 0), @intFromBool(cw & 2 != 0), @intFromBool(cw & 4 != 0), @intFromBool(cw & 8 != 0));
    setEnabled(GL_STENCIL_TEST, rs[52] != 0 and has_depth);
    gl.glStencilFunc(cmpFunc(rs[56]), @bitCast(rs[57]), rs[58]);
    gl.glStencilOp(stencilOp(rs[53]), stencilOp(rs[54]), stencilOp(rs[55]));
    gl.glStencilMask(rs[59]);
    gl.glPolygonMode(0x0408, switch (rs[8]) { // FRONT_AND_BACK
        1 => 0x1B00,
        2 => 0x1B01,
        else => 0x1B02,
    });
}

// ---- clear ------------------------------------------------------------------

const ClearJob = struct {
    dev: *Device,
    count: u32,
    rects: ?[*]const d3d.D3DRECT,
    flags: u32,
    color: u32,
    z: f32,
    stencil: u32,
};

fn clearJob(raw: ?*anyopaque) void {
    const job: *ClearJob = @ptrCast(@alignCast(raw.?));
    const gl = &host.gl;
    const dev = job.dev;
    applyTargetState(dev);
    var mask: c_uint = 0;
    if (job.flags & d3d.D3DCLEAR_TARGET != 0) mask |= 0x4000;
    if (job.flags & d3d.D3DCLEAR_ZBUFFER != 0) mask |= 0x0100;
    if (job.flags & d3d.D3DCLEAR_STENCIL != 0) mask |= 0x0400;
    if (mask == 0) return;
    // Clear ignores the write masks the draw state may have left behind.
    gl.glColorMask(1, 1, 1, 1);
    gl.glDepthMask(1);
    gl.glStencilMask(0xFFFFFFFF);
    const c = job.color;
    gl.glClearColor(
        @as(f32, @floatFromInt((c >> 16) & 0xFF)) / 255.0,
        @as(f32, @floatFromInt((c >> 8) & 0xFF)) / 255.0,
        @as(f32, @floatFromInt(c & 0xFF)) / 255.0,
        @as(f32, @floatFromInt(c >> 24)) / 255.0,
    );
    gl.glClearDepth(job.z);
    gl.glClearStencil(@bitCast(job.stencil));
    // The cleared area is the viewport, cut by the scissor rectangle when the
    // scissor test is on, and by each rectangle the caller listed.
    var x1: i32 = @intCast(dev.viewport.X);
    var y1: i32 = @intCast(dev.viewport.Y);
    var x2: i32 = x1 + @as(i32, @intCast(dev.viewport.Width));
    var y2: i32 = y1 + @as(i32, @intCast(dev.viewport.Height));
    if (dev.render_states[174] != 0) {
        x1 = @max(x1, dev.scissor.x1);
        y1 = @max(y1, dev.scissor.y1);
        x2 = @min(x2, dev.scissor.x2);
        y2 = @min(y2, dev.scissor.y2);
    }
    gl.glEnable(GL_SCISSOR_TEST);
    if (job.count == 0 or job.rects == null) {
        gl.glScissor(x1, y1, @max(0, x2 - x1), @max(0, y2 - y1));
        gl.glClear(mask);
    } else {
        for (job.rects.?[0..job.count]) |r| {
            const rx1 = @max(x1, r.x1);
            const ry1 = @max(y1, r.y1);
            const rx2 = @min(x2, r.x2);
            const ry2 = @min(y2, r.y2);
            gl.glScissor(rx1, ry1, @max(0, rx2 - rx1), @max(0, ry2 - ry1));
            gl.glClear(mask);
        }
    }
}

pub fn clear(dev: *Device, count: u32, rects: ?*const d3d.D3DRECT, flags: u32, color: u32, z: f32, stencil: u32) void {
    var job: ClearJob = .{ .dev = dev, .count = count, .rects = if (rects) |r| @ptrCast(r) else null, .flags = flags, .color = color, .z = z, .stencil = stencil };
    host.run(&clearJob, &job);
}

// ---- programs ---------------------------------------------------------------

fn compile(kind: host.GLenum, source: [:0]const u8, what: []const u8) host.GLuint {
    const gl = &host.gl;
    const sh = gl.glCreateShader(kind);
    const ptr: [*:0]const u8 = source.ptr;
    gl.glShaderSource(sh, 1, &ptr, null);
    gl.glCompileShader(sh);
    var ok: host.GLint = 0;
    gl.glGetShaderiv(sh, 0x8B81, &ok); // COMPILE_STATUS
    if (ok == 0) {
        var log: [1024]u8 = undefined;
        var n: host.GLsizei = 0;
        gl.glGetShaderInfoLog(sh, log.len, &n, &log);
        std.debug.print("[WINS:D3D9:GL] translated {s} shader does not compile:\n{s}\n--- source ---\n{s}\n", .{ what, log[0..@intCast(@max(0, n))], source });
        gl.glDeleteShader(sh);
        return 0;
    }
    return sh;
}

fn buildProgram(vs: *const d3d.WinsShader9, ps: *const d3d.WinsShader9) Program {
    const gl = &host.gl;
    var p: Program = .{
        .vs = vs,
        .ps = ps,
        .prog = 0,
        .inputs = &.{},
        .samplers = [_]shader.SamplerKind{.none} ** 16,
        .vs_const_count = 0,
        .ps_const_count = 0,
        .loc_vs_c = -1,
        .loc_ps_c = -1,
        .loc_half = -1,
    };
    var tp = shader.translate(alloc, ps.tokens, &.{}) catch |e| {
        std.debug.print("[WINS:D3D9:GL] pixel shader {x} (version {x}) not translated: {s} {s}\n", .{ @intFromPtr(ps), ps.tokens[0], @errorName(e), shader.last_error });
        return p;
    };
    defer tp.deinit(alloc);
    var tv = shader.translate(alloc, vs.tokens, tp.varyings_in) catch |e| {
        std.debug.print("[WINS:D3D9:GL] vertex shader {x} (version {x}) not translated: {s} {s}\n", .{ @intFromPtr(vs), vs.tokens[0], @errorName(e), shader.last_error });
        return p;
    };
    defer tv.deinit(alloc);
    if (tp.is_pixel == false or tv.is_pixel == true) return p;
    const gv = compile(0x8B31, tv.glsl, "vertex");
    if (gv == 0) return p;
    const gp = compile(0x8B30, tp.glsl, "pixel");
    if (gp == 0) return p;
    const prog = gl.glCreateProgram();
    gl.glAttachShader(prog, gv);
    gl.glAttachShader(prog, gp);
    var name_buf: [16]u8 = undefined;
    for (tv.inputs) |in| {
        const name = std.fmt.bufPrintZ(&name_buf, "v{d}", .{in.reg}) catch continue;
        gl.glBindAttribLocation(prog, in.reg, name.ptr);
    }
    gl.glLinkProgram(prog);
    var ok: host.GLint = 0;
    gl.glGetProgramiv(prog, 0x8B82, &ok); // LINK_STATUS
    if (ok == 0) {
        var log: [1024]u8 = undefined;
        var n: host.GLsizei = 0;
        gl.glGetProgramInfoLog(prog, log.len, &n, &log);
        std.debug.print("[WINS:D3D9:GL] translated shader pair does not link:\n{s}\n--- vertex ---\n{s}\n--- pixel ---\n{s}\n", .{ log[0..@intCast(@max(0, n))], tv.glsl, tp.glsl });
        return p;
    }
    gl.glUseProgram(prog);
    for (tp.samplers, 0..) |k, i| {
        if (k == .none) continue;
        const name = std.fmt.bufPrintZ(&name_buf, "ps_s{d}", .{i}) catch continue;
        const loc = gl.glGetUniformLocation(prog, name.ptr);
        if (loc >= 0) gl.glUniform1i(loc, @intCast(i));
    }
    p.prog = prog;
    p.inputs = alloc.dupe(shader.Input, tv.inputs) catch &.{};
    p.samplers = tp.samplers;
    p.vs_const_count = tv.const_count;
    p.ps_const_count = tp.const_count;
    p.loc_vs_c = gl.glGetUniformLocation(prog, "vs_c");
    p.loc_ps_c = gl.glGetUniformLocation(prog, "ps_c");
    p.loc_half = gl.glGetUniformLocation(prog, "wins_half_pixel");
    return p;
}

fn programFor(vs: *const d3d.WinsShader9, ps: *const d3d.WinsShader9) ?*const Program {
    for (g_programs.items) |*p| {
        if (p.fixed_key == null and p.vs == vs and p.ps == ps) return if (p.prog != 0) p else null;
    }
    const built = buildProgram(vs, ps);
    g_programs.append(alloc, built) catch return null;
    const p = &g_programs.items[g_programs.items.len - 1];
    return if (p.prog != 0) p else null;
}

// ---- textures ---------------------------------------------------------------

const TexFormat = struct { internal: host.GLenum, format: host.GLenum, ty: host.GLenum, compressed: bool };

fn texFormat(format: u32) ?TexFormat {
    return switch (format) {
        d3d.D3DFMT_DXT1 => .{ .internal = 0x83F1, .format = 0, .ty = 0, .compressed = true },
        d3d.D3DFMT_DXT3 => .{ .internal = 0x83F2, .format = 0, .ty = 0, .compressed = true },
        d3d.D3DFMT_DXT5 => .{ .internal = 0x83F3, .format = 0, .ty = 0, .compressed = true },
        21 => .{ .internal = 0x8058, .format = GL_BGRA, .ty = GL_UNSIGNED_BYTE, .compressed = false }, // A8R8G8B8
        22 => .{ .internal = 0x8051, .format = GL_BGRA, .ty = GL_UNSIGNED_BYTE, .compressed = false }, // X8R8G8B8 -> RGB8
        32 => .{ .internal = 0x8058, .format = GL_RGBA, .ty = GL_UNSIGNED_BYTE, .compressed = false }, // A8B8G8R8
        33 => .{ .internal = 0x8051, .format = GL_RGBA, .ty = GL_UNSIGNED_BYTE, .compressed = false }, // X8B8G8R8
        23 => .{ .internal = 0x8051, .format = 0x1907, .ty = 0x8363, .compressed = false }, // R5G6B5
        25 => .{ .internal = 0x8057, .format = GL_BGRA, .ty = 0x8366, .compressed = false }, // A1R5G5B5
        26 => .{ .internal = 0x8056, .format = GL_BGRA, .ty = 0x8365, .compressed = false }, // A4R4G4B4
        28 => .{ .internal = 0x803C, .format = 0x1906, .ty = GL_UNSIGNED_BYTE, .compressed = false }, // A8
        50 => .{ .internal = 0x8040, .format = 0x1909, .ty = GL_UNSIGNED_BYTE, .compressed = false }, // L8
        51 => .{ .internal = 0x8045, .format = 0x190A, .ty = GL_UNSIGNED_BYTE, .compressed = false }, // A8L8
        else => null,
    };
}

/// Bind `tex` to the active unit, uploading its levels when they changed.
fn bindTexture(tex: *d3d.WinsTexture9) bool {
    const gl = &host.gl;
    if (tex.usage & d3d.D3DUSAGE_RENDERTARGET != 0) {
        // Rendered on the GPU: storage only, never uploaded from the CPU copy.
        if (tex.gl_name == 0) allocRtTexture(&tex.gl_name, tex.format, tex.width, tex.height, tex.surfaces.len);
        gl.glBindTexture(GL_TEXTURE_2D, tex.gl_name);
        return true;
    }
    const tf = texFormat(tex.format) orelse {
        warnOnce(3, "a texture format has no OpenGL upload path yet; it samples as empty");
        return false;
    };
    if (tex.gl_name == 0) {
        gl.glGenTextures(1, &tex.gl_name);
        tex.gl_dirty = true;
    }
    gl.glBindTexture(GL_TEXTURE_2D, tex.gl_name);
    if (tex.gl_dirty) {
        tex.gl_dirty = false;
        for (tex.surfaces, 0..) |s, level| {
            if (tf.compressed) {
                gl.glCompressedTexImage2D(GL_TEXTURE_2D, @intCast(level), tf.internal, @intCast(s.width), @intCast(s.height), 0, @intCast(s.data.len), s.data.ptr);
            } else {
                gl.glTexImage2D(GL_TEXTURE_2D, @intCast(level), @intCast(tf.internal), @intCast(s.width), @intCast(s.height), 0, tf.format, tf.ty, s.data.ptr);
            }
        }
        gl.glTexParameteri(GL_TEXTURE_2D, 0x813D, @intCast(tex.surfaces.len - 1)); // MAX_LEVEL
    }
    return true;
}

fn addressMode(v: u32) host.GLint {
    return switch (v) {
        2 => 0x8370, // MIRRORED_REPEAT
        3 => 0x812F, // CLAMP_TO_EDGE
        4 => 0x812D, // CLAMP_TO_BORDER
        5 => 0x8743, // MIRROR_CLAMP_TO_EDGE
        else => 0x2901, // REPEAT
    };
}

fn applySampler(dev: *const Device, unit: usize, levels: usize) void {
    const gl = &host.gl;
    const ss = &dev.sampler_states[unit];
    const mag_linear = ss[5] >= 2;
    const min_linear = ss[6] >= 2;
    const mip = if (levels > 1) ss[7] else 0;
    const min: host.GLint = switch (mip) {
        0 => if (min_linear) 0x2601 else 0x2600,
        1 => if (min_linear) 0x2701 else 0x2700, // *_MIPMAP_NEAREST
        else => if (min_linear) 0x2703 else 0x2702, // *_MIPMAP_LINEAR
    };
    gl.glTexParameteri(GL_TEXTURE_2D, 0x2800, if (mag_linear) 0x2601 else 0x2600);
    gl.glTexParameteri(GL_TEXTURE_2D, 0x2801, min);
    gl.glTexParameteri(GL_TEXTURE_2D, 0x2802, addressMode(ss[1]));
    gl.glTexParameteri(GL_TEXTURE_2D, 0x2803, addressMode(ss[2]));
}

const DeleteJob = struct { name: host.GLuint };
fn deleteTextureJob(raw: ?*anyopaque) void {
    const job: *DeleteJob = @ptrCast(@alignCast(raw.?));
    host.gl.glDeleteTextures(1, &job.name);
}

/// The guest released a texture that was uploaded.
pub fn textureGone(name: u32) void {
    if (!active or name == 0) return;
    var job: DeleteJob = .{ .name = name };
    host.run(&deleteTextureJob, &job);
}

// ---- draw -------------------------------------------------------------------

const AttribFormat = struct { size: host.GLint, ty: host.GLenum, normalized: u8, bytes: u32 };

fn attribFormat(decl_type: u8) ?AttribFormat {
    return switch (decl_type) {
        0 => .{ .size = 1, .ty = 0x1406, .normalized = 0, .bytes = 4 }, // FLOAT1
        1 => .{ .size = 2, .ty = 0x1406, .normalized = 0, .bytes = 8 },
        2 => .{ .size = 3, .ty = 0x1406, .normalized = 0, .bytes = 12 },
        3 => .{ .size = 4, .ty = 0x1406, .normalized = 0, .bytes = 16 },
        4 => .{ .size = GL_BGRA, .ty = GL_UNSIGNED_BYTE, .normalized = 1, .bytes = 4 }, // D3DCOLOR
        5 => .{ .size = 4, .ty = GL_UNSIGNED_BYTE, .normalized = 0, .bytes = 4 }, // UBYTE4
        6 => .{ .size = 2, .ty = 0x1402, .normalized = 0, .bytes = 4 }, // SHORT2
        7 => .{ .size = 4, .ty = 0x1402, .normalized = 0, .bytes = 8 }, // SHORT4
        8 => .{ .size = 4, .ty = GL_UNSIGNED_BYTE, .normalized = 1, .bytes = 4 }, // UBYTE4N
        9 => .{ .size = 2, .ty = 0x1402, .normalized = 1, .bytes = 4 }, // SHORT2N
        10 => .{ .size = 4, .ty = 0x1402, .normalized = 1, .bytes = 8 }, // SHORT4N
        11 => .{ .size = 2, .ty = 0x1403, .normalized = 1, .bytes = 4 }, // USHORT2N
        12 => .{ .size = 4, .ty = 0x1403, .normalized = 1, .bytes = 8 }, // USHORT4N
        15 => .{ .size = 2, .ty = 0x140B, .normalized = 0, .bytes = 4 }, // FLOAT16_2
        16 => .{ .size = 4, .ty = 0x140B, .normalized = 0, .bytes = 8 }, // FLOAT16_4
        else => null,
    };
}

pub const DrawJob = struct {
    dev: *Device,
    prim: u32,
    indexed: bool,
    /// Indexed: added to every index. Non-indexed: the first vertex.
    base_vertex: i64,
    /// Indexed: lowest index used and how many vertices from it.
    min_index: u32 = 0,
    num_vertices: u32 = 0,
    start_index: u32 = 0,
    prim_count: u32,
    /// Draw*PrimitiveUP: stream 0 (and the indices) live in the caller's memory.
    up_vb: ?[*]const u8 = null,
    up_stride: u32 = 0,
    up_ib: ?[*]const u8 = null,
    up_ib_format: u32 = 0,
};

fn vertexCount(prim: u32, n: u32) ?struct { mode: host.GLenum, count: u64 } {
    const c: u64 = n;
    return switch (prim) {
        1 => .{ .mode = 0, .count = c }, // POINTLIST
        2 => .{ .mode = 1, .count = c * 2 }, // LINELIST
        3 => .{ .mode = 3, .count = c + 1 }, // LINESTRIP
        4 => .{ .mode = 4, .count = c * 3 }, // TRIANGLELIST
        5 => .{ .mode = 5, .count = c + 2 }, // TRIANGLESTRIP
        6 => .{ .mode = 6, .count = c + 2 }, // TRIANGLEFAN
        else => null,
    };
}

const Source = struct { ptr: [*]const u8, len: usize, stride: u64, offset: u64 };

fn streamSource(job: *const DrawJob, stream: u16, last_vertex: u64) ?Source {
    const dev = job.dev;
    if (job.up_vb) |p| {
        if (stream != 0) return null;
        // The caller's array is exactly as long as the vertices the draw uses.
        return .{ .ptr = p, .len = @intCast((last_vertex + 1) * job.up_stride), .stride = job.up_stride, .offset = 0 };
    }
    if (stream >= 16) return null;
    const vb = dev.streams[stream] orelse return null;
    return .{ .ptr = vb.data.ptr, .len = vb.data.len, .stride = dev.stream_strides[stream], .offset = dev.stream_offsets[stream] };
}

fn drawJob(raw: ?*anyopaque) void {
    const job: *DrawJob = @ptrCast(@alignCast(raw.?));
    const gl = &host.gl;
    const dev = job.dev;
    const elements: []const d3d.D3DVERTEXELEMENT9 = if (dev.use_fvf) dev.fvf_elements[0..] else if (dev.vertex_decl) |dcl| dcl.elements else return warnOnce(2, "a draw with neither a vertex declaration nor an FVF; skipped");
    const shape = vertexCount(job.prim, job.prim_count) orelse return;
    if (shape.count == 0 or shape.count > std.math.maxInt(i32)) return;
    const prog: *const Program = blk: {
        if (dev.active_vs) |vs| {
            if (dev.active_ps) |ps| break :blk programFor(vs, ps) orelse return;
            return warnOnce(1, "a vertex shader with fixed-function texturing is not implemented; skipped");
        }
        if (dev.active_ps != null) return warnOnce(0, "fixed-function transform with a pixel shader is not implemented; skipped");
        break :blk fixedProgramFor(dev, elements) orelse return;
    };

    // The vertices this draw can touch, to keep every read inside the buffers.
    var first: i64 = job.base_vertex;
    var span: u64 = shape.count;
    if (job.indexed) {
        first += job.min_index;
        span = job.num_vertices;
    }
    if (first < 0) return;
    if (job.indexed and job.base_vertex < 0) return warnOnce(10, "indexed draws with a negative base vertex are not implemented; skipped");
    if (span == 0) return;

    applyTargetState(dev);
    applyRenderStates(dev);
    gl.glUseProgram(prog.prog);
    if (prog.loc_vs_c >= 0 and prog.vs_const_count != 0) gl.glUniform4fv(prog.loc_vs_c, prog.vs_const_count, @ptrCast(&dev.vs_consts));
    if (prog.loc_ps_c >= 0 and prog.ps_const_count != 0) gl.glUniform4fv(prog.loc_ps_c, prog.ps_const_count, @ptrCast(&dev.ps_consts));
    if (prog.loc_half >= 0) gl.glUniform2f(prog.loc_half, 1.0 / @as(f32, @floatFromInt(@max(1, dev.viewport.Width))), -1.0 / @as(f32, @floatFromInt(@max(1, dev.viewport.Height))));
    if (prog.fixed_key != null) setFixedUniforms(dev, prog);

    gl.glBindBuffer(0x8892, 0); // ARRAY_BUFFER: client memory
    gl.glBindBuffer(0x8893, 0); // ELEMENT_ARRAY_BUFFER
    const first_u: u64 = @intCast(first);
    var wanted: u16 = 0;
    for (prog.inputs) |in| {
        if (in.reg >= 16) continue;
        var found = false;
        for (elements) |e| {
            if (e.Stream == 0xFF) break;
            if (e.Usage != in.usage or e.UsageIndex != in.index) continue;
            const src = streamSource(job, e.Stream, first_u + span - 1) orelse break;
            const af = attribFormat(e.Type) orelse {
                warnOnce(6, "a vertex element type (UDEC3/DEC3N) has no OpenGL path yet; attribute left at its default");
                break;
            };
            const base: u64 = src.offset + e.Offset;
            // Last byte read: the final vertex's element.
            const end = base + (first_u + span - 1) * src.stride + af.bytes;
            if (end > src.len) {
                warnOnce(7, "a draw reads past the end of its vertex buffer; skipped");
                return;
            }
            // With client arrays index i reads base + i*stride: fold the base vertex in.
            const origin: u64 = if (job.indexed) @as(u64, @intCast(job.base_vertex)) * src.stride else 0;
            gl.glVertexAttribPointer(in.reg, af.size, af.ty, af.normalized, @intCast(src.stride), src.ptr + @as(usize, @intCast(base + origin)));
            wanted |= @as(u16, 1) << @intCast(in.reg);
            found = true;
            break;
        }
        if (!found) {
            // D3D9 defaults for a missing input: colour white, the rest (0,0,0,1).
            if (in.usage == 10 and in.index == 0) gl.glVertexAttrib4f(in.reg, 1, 1, 1, 1) else gl.glVertexAttrib4f(in.reg, 0, 0, 0, 1);
        }
    }
    var bit: u5 = 0;
    while (bit < 16) : (bit += 1) {
        const m = @as(u16, 1) << @intCast(bit);
        if (wanted & m != 0 and g_attrib_enabled & m == 0) gl.glEnableVertexAttribArray(bit);
        if (wanted & m == 0 and g_attrib_enabled & m != 0) gl.glDisableVertexAttribArray(bit);
    }
    g_attrib_enabled = wanted;

    for (prog.samplers, 0..) |kind, unit| {
        if (kind == .none) continue;
        gl.glActiveTexture(0x84C0 + @as(host.GLenum, @intCast(unit)));
        if (kind != .tex2d) {
            warnOnce(8, "cube and volume samplers are not implemented; they sample as empty");
            gl.glBindTexture(GL_TEXTURE_2D, 0);
            continue;
        }
        const tex = dev.bound_textures[unit] orelse {
            gl.glBindTexture(GL_TEXTURE_2D, 0);
            continue;
        };
        if (!bindTexture(tex)) {
            gl.glBindTexture(GL_TEXTURE_2D, 0);
            continue;
        }
        applySampler(dev, unit, tex.surfaces.len);
    }

    if (job.indexed) {
        var ptr: [*]const u8 = undefined;
        var len: u64 = 0;
        var fmt: u32 = 0;
        if (job.up_ib) |p| {
            ptr = p;
            fmt = job.up_ib_format;
            len = shape.count * @as(u64, if (fmt == d3d.D3DFMT_INDEX32) 4 else 2);
        } else {
            const ib = dev.indices orelse return;
            ptr = ib.data.ptr;
            len = ib.data.len;
            fmt = ib.format;
        }
        const width: u64 = if (fmt == d3d.D3DFMT_INDEX32) 4 else 2;
        const begin = @as(u64, job.start_index) * width;
        if (begin + shape.count * width > len) return warnOnce(9, "a draw reads past the end of its index buffer; skipped");
        gl.glDrawElements(shape.mode, @intCast(shape.count), if (width == 4) 0x1405 else 0x1403, ptr + @as(usize, @intCast(begin)));
    } else {
        gl.glDrawArrays(shape.mode, @intCast(first), @intCast(shape.count));
    }
}

// ---- fixed function ---------------------------------------------------------

/// Everything the generated fixed-function GLSL depends on.
pub const FixedKey = struct {
    pretransformed: bool,
    has_color0: bool,
    has_color1: bool,
    tex_coords: u8, // texcoord sets present in the vertex
    specular: bool,
    stages: [8][7]u8, // colorop, colorarg1, colorarg2, alphaop, alphaarg1, alphaarg2, texcoordindex | result<<4
    stage_count: u8,
    textured: u8, // stages with a bound texture
};

const TSS_COLOROP = 1;
const TSS_COLORARG1 = 2;
const TSS_COLORARG2 = 3;
const TSS_ALPHAOP = 4;
const TSS_ALPHAARG1 = 5;
const TSS_ALPHAARG2 = 6;
const TSS_TEXCOORDINDEX = 11;
const TSS_RESULTARG = 28;

fn fixedKey(dev: *const Device, elements: []const d3d.D3DVERTEXELEMENT9) FixedKey {
    var k: FixedKey = .{ .pretransformed = false, .has_color0 = false, .has_color1 = false, .tex_coords = 0, .specular = dev.render_states[29] != 0, .stages = std.mem.zeroes([8][7]u8), .stage_count = 0, .textured = 0 };
    for (elements) |e| {
        if (e.Stream == 0xFF) break;
        switch (e.Usage) {
            9 => k.pretransformed = true,
            10 => if (e.UsageIndex == 0) {
                k.has_color0 = true;
            } else {
                k.has_color1 = true;
            },
            5 => if (e.UsageIndex < 8) {
                k.tex_coords |= @as(u8, 1) << @intCast(e.UsageIndex);
            },
            else => {},
        }
    }
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const t = dev.tex_stage_states[i];
        if (t[TSS_COLOROP] == 1 or t[TSS_COLOROP] == 0) break;
        k.stages[i] = .{ @intCast(t[TSS_COLOROP] & 0xFF), @intCast(t[TSS_COLORARG1] & 0xFF), @intCast(t[TSS_COLORARG2] & 0xFF), @intCast(t[TSS_ALPHAOP] & 0xFF), @intCast(t[TSS_ALPHAARG1] & 0xFF), @intCast(t[TSS_ALPHAARG2] & 0xFF), @intCast((t[TSS_TEXCOORDINDEX] & 7) | ((t[TSS_RESULTARG] & 0xF) << 4)) };
        if (dev.bound_textures[i] != null) k.textured |= @as(u8, 1) << @intCast(i);
        k.stage_count += 1;
    }
    return k;
}

fn fixedArg(buf: *std.ArrayList(u8), code: u8, stage: usize, alpha: bool) void {
    const base: []const u8 = switch (code & 0xF) {
        0 => "diffuse",
        1 => "current",
        2 => "t",
        3 => "tfactor",
        4 => "specular",
        5 => "temp",
        else => "vec4(1.0)",
    };
    _ = stage;
    var e: [96]u8 = undefined;
    var x = std.fmt.bufPrint(&e, "{s}", .{base}) catch return;
    var e2: [128]u8 = undefined;
    if (code & 0x20 != 0) x = std.fmt.bufPrint(&e2, "vec4(({s}).a)", .{x}) catch return; // ALPHAREPLICATE
    var e3: [160]u8 = undefined;
    if (code & 0x10 != 0) x = std.fmt.bufPrint(&e3, "(vec4(1.0) - ({s}))", .{x}) catch return; // COMPLEMENT
    buf.appendSlice(alloc, x) catch {};
    buf.appendSlice(alloc, if (alpha) ".a" else ".rgb") catch {};
}

/// One texture-stage operation as a GLSL expression of a1 / a2.
fn fixedOp(op: u8) []const u8 {
    return switch (op) {
        2 => "a1",
        3 => "a2",
        4 => "a1 * a2",
        5 => "a1 * a2 * 2.0",
        6 => "a1 * a2 * 4.0",
        7 => "a1 + a2",
        8 => "a1 + a2 - 0.5",
        9 => "(a1 + a2 - 0.5) * 2.0",
        10 => "a1 - a2",
        11 => "a1 + a2 - a1 * a2",
        12 => "mix(a2, a1, diffuse.a)",
        13 => "mix(a2, a1, t.a)",
        14 => "mix(a2, a1, tfactor.a)",
        16 => "mix(a2, a1, current.a)",
        else => "a1",
    };
}

fn buildFixed(k: FixedKey) Program {
    const gl = &host.gl;
    var p: Program = .{ .vs = null, .ps = null, .fixed_key = k, .prog = 0, .inputs = &.{}, .samplers = [_]shader.SamplerKind{.none} ** 16, .vs_const_count = 0, .ps_const_count = 0, .loc_vs_c = -1, .loc_ps_c = -1, .loc_half = -1 };
    var vsb: std.ArrayList(u8) = .empty;
    defer vsb.deinit(alloc);
    var psb: std.ArrayList(u8) = .empty;
    defer psb.deinit(alloc);
    const w = struct {
        fn f(b: *std.ArrayList(u8), comptime fmt: []const u8, args: anytype) void {
            const t = std.fmt.allocPrint(alloc, fmt, args) catch return;
            defer alloc.free(t);
            b.appendSlice(alloc, t) catch {};
        }
    }.f;
    w(&vsb, "#version 120\nattribute vec4 a_pos;\nattribute vec4 a_col0;\nattribute vec4 a_col1;\n", .{});
    for (0..8) |i| w(&vsb, "attribute vec4 a_tc{d};\nvarying vec4 v_tc{d};\n", .{ i, i });
    w(&vsb, "uniform mat4 wvp;\nuniform vec4 vp;\nuniform vec2 wins_half_pixel;\nvarying vec4 v_col0;\nvarying vec4 v_col1;\nvoid main() {{\n", .{});
    if (k.pretransformed) {
        // D3DFVF_XYZRHW: screen pixels; w holds 1/w.
        w(&vsb, "    float ww = a_pos.w != 0.0 ? 1.0 / a_pos.w : 1.0;\n    vec3 ndc = vec3((a_pos.x - vp.x) / vp.z * 2.0 - 1.0, 1.0 - (a_pos.y - vp.y) / vp.w * 2.0, a_pos.z);\n    gl_Position = vec4(ndc * ww, ww);\n", .{});
    } else {
        w(&vsb, "    gl_Position = wvp * vec4(a_pos.xyz, 1.0);\n", .{});
    }
    w(&vsb, "    gl_Position.xy += wins_half_pixel * gl_Position.w;\n", .{});
    w(&vsb, "    v_col0 = {s};\n    v_col1 = {s};\n", .{ if (k.has_color0) "a_col0" else "vec4(1.0)", if (k.has_color1) "a_col1" else "vec4(0.0)" });
    for (0..8) |i| {
        if (k.tex_coords & (@as(u8, 1) << @intCast(i)) != 0) w(&vsb, "    v_tc{d} = a_tc{d};\n", .{ i, i }) else w(&vsb, "    v_tc{d} = vec4(0.0, 0.0, 0.0, 1.0);\n", .{i});
    }
    w(&vsb, "}}\n", .{});

    w(&psb, "#version 120\nuniform vec4 tfactor;\nvarying vec4 v_col0;\nvarying vec4 v_col1;\n", .{});
    for (0..8) |i| w(&psb, "varying vec4 v_tc{d};\nuniform sampler2D s{d};\n", .{ i, i });
    w(&psb, "void main() {{\n    vec4 diffuse = v_col0;\n    vec4 specular = v_col1;\n    vec4 current = diffuse;\n    vec4 temp = vec4(0.0);\n    vec4 t = vec4(1.0);\n", .{});
    for (0..k.stage_count) |i| {
        const st = k.stages[i];
        const tci = st[6] & 7;
        if (k.textured & (@as(u8, 1) << @intCast(i)) != 0) {
            w(&psb, "    t = texture2D(s{d}, v_tc{d}.xy);\n", .{ i, tci });
            p.samplers[i] = .tex2d;
        } else w(&psb, "    t = vec4(1.0);\n", .{});
        const dst: []const u8 = if ((st[6] >> 4) == 5) "temp" else "current";
        // colour
        w(&psb, "    {{ vec3 a1 = ", .{});
        fixedArg(&psb, st[1], i, false);
        w(&psb, "; vec3 a2 = ", .{});
        fixedArg(&psb, st[2], i, false);
        w(&psb, "; vec3 rc = clamp({s}, 0.0, 1.0);\n", .{fixedOp(st[0])});
        // alpha
        if (st[3] == 1 or st[3] == 0) {
            w(&psb, "      float ra = current.a;\n", .{});
        } else {
            w(&psb, "      float b1 = ", .{});
            fixedArg(&psb, st[4], i, true);
            w(&psb, "; float b2 = ", .{});
            fixedArg(&psb, st[5], i, true);
            const op = fixedOp(st[3]);
            // the same expression on floats: a1/a2 -> b1/b2
            var ob: [64]u8 = undefined;
            var n: usize = 0;
            var j: usize = 0;
            while (j < op.len) : (j += 1) {
                if (op[j] == 'a' and j + 1 < op.len and (op[j + 1] == '1' or op[j + 1] == '2')) {
                    ob[n] = 'b';
                } else ob[n] = op[j];
                n += 1;
            }
            w(&psb, "; float ra = clamp({s}, 0.0, 1.0);\n", .{ob[0..n]});
        }
        w(&psb, "      {s} = vec4(rc, ra); }}\n", .{dst});
    }
    if (k.specular) w(&psb, "    current.rgb = clamp(current.rgb + specular.rgb, 0.0, 1.0);\n", .{});
    w(&psb, "    gl_FragColor = current;\n}}\n", .{});

    vsb.append(alloc, 0) catch return p;
    psb.append(alloc, 0) catch return p;
    const gv = compile(0x8B31, vsb.items[0 .. vsb.items.len - 1 :0], "fixed-function vertex");
    if (gv == 0) return p;
    const gp = compile(0x8B30, psb.items[0 .. psb.items.len - 1 :0], "fixed-function pixel");
    if (gp == 0) return p;
    const prog = gl.glCreateProgram();
    gl.glAttachShader(prog, gv);
    gl.glAttachShader(prog, gp);
    gl.glBindAttribLocation(prog, 0, "a_pos");
    gl.glBindAttribLocation(prog, 2, "a_col0");
    gl.glBindAttribLocation(prog, 3, "a_col1");
    var name_buf: [16]u8 = undefined;
    for (0..8) |i| {
        const name = std.fmt.bufPrintZ(&name_buf, "a_tc{d}", .{i}) catch continue;
        gl.glBindAttribLocation(prog, @intCast(4 + i), name.ptr);
    }
    gl.glLinkProgram(prog);
    var ok: host.GLint = 0;
    gl.glGetProgramiv(prog, 0x8B82, &ok);
    if (ok == 0) {
        var log: [1024]u8 = undefined;
        var n: host.GLsizei = 0;
        gl.glGetProgramInfoLog(prog, log.len, &n, &log);
        std.debug.print("[WINS:D3D9:GL] fixed-function program does not link:\n{s}\n", .{log[0..@intCast(@max(0, n))]});
        return p;
    }
    gl.glUseProgram(prog);
    for (0..8) |i| {
        const name = std.fmt.bufPrintZ(&name_buf, "s{d}", .{i}) catch continue;
        const loc = gl.glGetUniformLocation(prog, name.ptr);
        if (loc >= 0) gl.glUniform1i(loc, @intCast(i));
    }
    var inputs: std.ArrayList(shader.Input) = .empty;
    inputs.append(alloc, .{ .reg = 0, .usage = if (k.pretransformed) 9 else 0, .index = 0 }) catch {};
    if (k.has_color0) inputs.append(alloc, .{ .reg = 2, .usage = 10, .index = 0 }) catch {};
    if (k.has_color1) inputs.append(alloc, .{ .reg = 3, .usage = 10, .index = 1 }) catch {};
    for (0..8) |i| {
        if (k.tex_coords & (@as(u8, 1) << @intCast(i)) != 0) inputs.append(alloc, .{ .reg = @intCast(4 + i), .usage = 5, .index = @intCast(i) }) catch {};
    }
    p.inputs = inputs.toOwnedSlice(alloc) catch &.{};
    p.prog = prog;
    p.loc_wvp = gl.glGetUniformLocation(prog, "wvp");
    p.loc_vp = gl.glGetUniformLocation(prog, "vp");
    p.loc_tfactor = gl.glGetUniformLocation(prog, "tfactor");
    p.loc_half = gl.glGetUniformLocation(prog, "wins_half_pixel");
    return p;
}

fn fixedProgramFor(dev: *const Device, elements: []const d3d.D3DVERTEXELEMENT9) ?*const Program {
    const k = fixedKey(dev, elements);
    if (!k.pretransformed and dev.render_states[137] != 0) warnOnce(11, "fixed-function lighting is not implemented; lit vertices use their own colour");
    for (g_programs.items) |*p| {
        if (p.fixed_key) |pk| {
            if (std.meta.eql(pk, k)) return if (p.prog != 0) p else null;
        }
    }
    g_programs.append(alloc, buildFixed(k)) catch return null;
    const p = &g_programs.items[g_programs.items.len - 1];
    return if (p.prog != 0) p else null;
}

fn matMul(a: [16]f32, b: [16]f32) [16]f32 {
    var r: [16]f32 = undefined;
    for (0..4) |i| {
        for (0..4) |j| {
            var acc: f32 = 0;
            for (0..4) |k| acc += a[i * 4 + k] * b[k * 4 + j];
            r[i * 4 + j] = acc;
        }
    }
    return r;
}

fn setFixedUniforms(dev: *const Device, prog: *const Program) void {
    const gl = &host.gl;
    if (prog.loc_wvp >= 0) {
        const W: [16]f32 = @bitCast(dev.transform_states[d3d.d3dTransformStateIndex(256).?]);
        const V: [16]f32 = @bitCast(dev.transform_states[d3d.d3dTransformStateIndex(2).?]);
        const P: [16]f32 = @bitCast(dev.transform_states[d3d.d3dTransformStateIndex(3).?]);
        // Row vectors: v * W * V * P; OpenGL reads the row-major array as its transpose.
        const m = matMul(matMul(W, V), P);
        glUniformMatrix4fv(prog.loc_wvp, &m);
    }
    if (prog.loc_vp >= 0) gl.glUniform4fv(prog.loc_vp, 1, &[4]f32{ @floatFromInt(dev.viewport.X), @floatFromInt(dev.viewport.Y), @floatFromInt(@max(1, dev.viewport.Width)), @floatFromInt(@max(1, dev.viewport.Height)) });
    if (prog.loc_tfactor >= 0) {
        const c = dev.render_states[60];
        gl.glUniform4fv(prog.loc_tfactor, 1, &[4]f32{
            @as(f32, @floatFromInt((c >> 16) & 0xFF)) / 255.0, @as(f32, @floatFromInt((c >> 8) & 0xFF)) / 255.0,
            @as(f32, @floatFromInt(c & 0xFF)) / 255.0,         @as(f32, @floatFromInt(c >> 24)) / 255.0,
        });
    }
}

/// glUniformMatrix4fv without transposing: the array is D3D's row-major
/// matrix, which OpenGL takes as columns, i.e. the transpose we need.
fn glUniformMatrix4fv(loc: host.GLint, m: *const [16]f32) void {
    host.gl.glUniformMatrix4fv(loc, 1, 0, m);
}

pub fn draw(job: *DrawJob) void {
    host.run(&drawJob, job);
}

// ---- present ----------------------------------------------------------------

const PresentJob = struct { frame: u64 };

fn writeCapture(frame: u64) void {
    const gl = &host.gl;
    const bytes = alloc.alloc(u8, @as(usize, g_w) * g_h * 3) catch return;
    defer alloc.free(bytes);
    gl.glBindFramebuffer(GL_READ_FRAMEBUFFER, g_fbo);
    gl.glReadPixels(0, 0, @intCast(g_w), @intCast(g_h), 0x1907, GL_UNSIGNED_BYTE, bytes.ptr); // RGB, row 0 = top
    var name_buf: [300]u8 = undefined;
    const base = std.mem.sliceTo(&capture_path, 0);
    const path_s = if (capture_period != 0) (std.fmt.bufPrintZ(&name_buf, "{s}-{d}.ppm", .{ base, frame }) catch return) else (std.fmt.bufPrintZ(&name_buf, "{s}", .{base}) catch return);
    const path: []const u8 = path_s;
    const fd = std.posix.openat(std.posix.AT.FDCWD, path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644) catch {
        std.debug.print("[WINS:D3D9:GL] capture: cannot create {s}\n", .{path});
        return;
    };
    defer _ = std.os.linux.close(fd);
    var header: [64]u8 = undefined;
    const h = std.fmt.bufPrint(&header, "P6\n{d} {d}\n255\n", .{ g_w, g_h }) catch return;
    _ = std.os.linux.write(fd, h.ptr, h.len);
    var off: usize = 0;
    while (off < bytes.len) {
        const n = std.os.linux.write(fd, bytes.ptr + off, bytes.len - off);
        if (@as(isize, @bitCast(n)) <= 0) break;
        off += n;
    }
    std.debug.print("[WINS:D3D9:GL] capture: frame {d} written to {s} ({d}x{d})\n", .{ frame, path, g_w, g_h });
}

fn presentJob(raw: ?*anyopaque) void {
    const job: *PresentJob = @ptrCast(@alignCast(raw.?));
    const gl = &host.gl;
    if (job.frame == capture_frame) {
        writeCapture(job.frame);
        if (capture_period != 0) capture_frame += capture_period;
    }
    gl.glBindFramebuffer(GL_READ_FRAMEBUFFER, g_fbo);
    gl.glBindFramebuffer(GL_DRAW_FRAMEBUFFER, 0);
    gl.glDisable(GL_SCISSOR_TEST);
    gl.glColorMask(1, 1, 1, 1);
    // Row 0 of the back buffer is the top of the picture; the window's row 0 is its bottom.
    gl.glBlitFramebuffer(0, 0, @intCast(g_w), @intCast(g_h), 0, @intCast(host.height), @intCast(host.width), 0, 0x4000, 0x2601);
    host.swap();
}

pub fn present(frame: u64) void {
    var job: PresentJob = .{ .frame = frame };
    host.run(&presentJob, &job);
}
