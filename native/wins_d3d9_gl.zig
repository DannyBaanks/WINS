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

const alloc = std.heap.page_allocator;

var g_fbo: host.GLuint = 0;
var g_color: host.GLuint = 0;
var g_depth: host.GLuint = 0;
var g_w: u32 = 0;
var g_h: u32 = 0;

const Program = struct {
    vs: *const d3d.WinsShader9,
    ps: *const d3d.WinsShader9,
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

fn applyTargetState(dev: *const Device) void {
    const gl = &host.gl;
    gl.glBindFramebuffer(GL_FRAMEBUFFER, g_fbo);
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
    dev: *const Device,
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

pub fn clear(dev: *const Device, count: u32, rects: ?*const d3d.D3DRECT, flags: u32, color: u32, z: f32, stencil: u32) void {
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
        if (p.vs == vs and p.ps == ps) return if (p.prog != 0) p else null;
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
    const tf = texFormat(tex.format) orelse {
        warnOnce(3, "a texture format has no OpenGL upload path yet; it samples as empty");
        return false;
    };
    if (tex.usage & d3d.D3DUSAGE_RENDERTARGET != 0) {
        warnOnce(4, "render-target textures are not implemented; they sample as empty");
        return false;
    }
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

fn drawJob(raw: ?*anyopaque) void {
    const job: *DrawJob = @ptrCast(@alignCast(raw.?));
    const gl = &host.gl;
    const dev = job.dev;
    const vs = dev.active_vs orelse return warnOnce(0, "draws without a vertex shader (fixed-function transform) are not implemented; skipped");
    const ps = dev.active_ps orelse return warnOnce(1, "draws without a pixel shader (fixed-function texturing) are not implemented; skipped");
    const decl = dev.vertex_decl orelse return warnOnce(2, "draws with an FVF instead of a vertex declaration are not implemented; skipped");
    if (dev.render_target_is_backbuffer == false) return warnOnce(5, "draws into a render target other than the back buffer are not implemented; skipped");
    const shape = vertexCount(job.prim, job.prim_count) orelse return;
    if (shape.count == 0 or shape.count > std.math.maxInt(i32)) return;
    const prog = programFor(vs, ps) orelse return;

    // The vertices this draw can touch, to keep every read inside the buffers.
    var first: i64 = job.base_vertex;
    var span: u64 = shape.count;
    if (job.indexed) {
        first += job.min_index;
        span = job.num_vertices;
    }
    if (first < 0) return;
    if (job.indexed and job.base_vertex < 0) return warnOnce(10, "indexed draws with a negative base vertex are not implemented; skipped");

    applyTargetState(dev);
    applyRenderStates(dev);
    gl.glUseProgram(prog.prog);
    if (prog.loc_vs_c >= 0 and prog.vs_const_count != 0) gl.glUniform4fv(prog.loc_vs_c, prog.vs_const_count, @ptrCast(&dev.vs_consts));
    if (prog.loc_ps_c >= 0 and prog.ps_const_count != 0) gl.glUniform4fv(prog.loc_ps_c, prog.ps_const_count, @ptrCast(&dev.ps_consts));
    if (prog.loc_half >= 0) gl.glUniform2f(prog.loc_half, 1.0 / @as(f32, @floatFromInt(@max(1, dev.viewport.Width))), -1.0 / @as(f32, @floatFromInt(@max(1, dev.viewport.Height))));

    gl.glBindBuffer(0x8892, 0); // ARRAY_BUFFER: client memory
    gl.glBindBuffer(0x8893, 0); // ELEMENT_ARRAY_BUFFER
    var wanted: u16 = 0;
    for (prog.inputs) |in| {
        if (in.reg >= 16) continue;
        var found = false;
        for (decl.elements) |e| {
            if (e.Stream == 0xFF) break;
            if (e.Usage != in.usage or e.UsageIndex != in.index) continue;
            if (e.Stream >= 16) break;
            const vb = dev.streams[e.Stream] orelse break;
            const af = attribFormat(e.Type) orelse {
                warnOnce(6, "a vertex element type (UDEC3/DEC3N) has no OpenGL path yet; attribute left at its default");
                break;
            };
            const stride: u64 = dev.stream_strides[e.Stream];
            const base: u64 = @as(u64, dev.stream_offsets[e.Stream]) + e.Offset;
            const first_u: u64 = @intCast(first);
            // Last byte read: the final vertex's element.
            const end = base + (first_u + span - 1) * stride + af.bytes;
            if (span == 0 or end > vb.data.len) {
                warnOnce(7, "a draw reads past the end of its vertex buffer; skipped");
                return;
            }
            // With client arrays index i reads base + i*stride: fold the base vertex in.
            const origin: u64 = if (job.indexed) @as(u64, @intCast(job.base_vertex)) * stride else 0;
            gl.glVertexAttribPointer(in.reg, af.size, af.ty, af.normalized, @intCast(stride), vb.data.ptr + @as(usize, @intCast(base + origin)));
            wanted |= @as(u16, 1) << @intCast(in.reg);
            found = true;
            break;
        }
        if (!found) gl.glVertexAttrib4f(in.reg, 0, 0, 0, 1);
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
        const ib = dev.indices orelse return;
        const width: u64 = if (ib.format == d3d.D3DFMT_INDEX32) 4 else 2;
        const begin = @as(u64, job.start_index) * width;
        if (begin + shape.count * width > ib.data.len) return warnOnce(9, "a draw reads past the end of its index buffer; skipped");
        gl.glDrawElements(shape.mode, @intCast(shape.count), if (width == 4) 0x1405 else 0x1403, ib.data.ptr + @as(usize, @intCast(begin)));
    } else {
        gl.glDrawArrays(shape.mode, @intCast(first), @intCast(shape.count));
    }
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
    const path = std.mem.sliceTo(&capture_path, 0);
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
    if (job.frame == capture_frame) writeCapture(job.frame);
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
