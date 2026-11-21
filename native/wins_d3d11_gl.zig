const std = @import("std");
const linux = std.os.linux;
const gui = @import("winrun_gui_support.zig");
const shader = @import("wins_d3d11_shader.zig");

const alloc = std.heap.page_allocator;

pub const GLenum = c_uint;
pub const GLuint = c_uint;
pub const GLint = c_int;
pub const GLsizei = c_int;
pub const GLsizeiptr = isize;
pub const GLintptr = isize;

extern fn dlopen(filename: [*:0]const u8, flags: c_int) ?*anyopaque;
extern fn dlsym(handle: ?*anyopaque, symbol: [*:0]const u8) ?*anyopaque;
extern fn getenv(name: [*:0]const u8) ?[*:0]const u8;
extern fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern fn access(path: [*:0]const u8, mode: c_int) c_int;

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

const Xlib = struct {
    XOpenDisplay: *const fn (?[*:0]const u8) callconv(.c) ?*anyopaque,
    XDefaultScreen: *const fn (?*anyopaque) callconv(.c) c_int,
    XDefaultRootWindow: *const fn (?*anyopaque) callconv(.c) c_ulong,
    XCreateSimpleWindow: *const fn (?*anyopaque, c_ulong, c_int, c_int, c_uint, c_uint, c_uint, c_ulong, c_ulong) callconv(.c) c_ulong,
    XGetWindowAttributes: *const fn (?*anyopaque, c_ulong, *XWindowAttributes) callconv(.c) c_int,
    XVisualIDFromVisual: *const fn (?*anyopaque) callconv(.c) c_ulong,
    XFree: *const fn (?*anyopaque) callconv(.c) c_int,
    XSync: *const fn (?*anyopaque, c_int) callconv(.c) c_int,
    XSetErrorHandler: *const fn (?*const fn (?*anyopaque, *const XErrorEvent) callconv(.c) c_int) callconv(.c) ?*anyopaque,
};

const XErrorEvent = extern struct {
    type: c_int,
    display: ?*anyopaque,
    resourceid: c_ulong,
    serial: c_ulong,
    error_code: u8,
    request_code: u8,
    minor_code: u8,
};

/// X window whose drawable went away (BadDrawable/BadWindow): stop presenting to it.
var g_lost_window = std.atomic.Value(c_ulong).init(0);
var g_x_error_count = std.atomic.Value(u32).init(0);

/// Xlib's default error handler calls exit(): a window the game (or the user via the
/// WM close button) destroyed while the render thread still swaps to it killed the whole
/// process. Log, remember the dead drawable, and keep going.
fn xErrorHandler(_: ?*anyopaque, e: *const XErrorEvent) callconv(.c) c_int {
    const n = g_x_error_count.fetchAdd(1, .monotonic);
    if (e.error_code == 9 or e.error_code == 3) g_lost_window.store(e.resourceid, .release); // BadDrawable / BadWindow
    if (n < 8) std.debug.print("[WINS:D3D11:GL] X error {d} (request {d}.{d}) on 0x{x} ignored\n", .{ e.error_code, e.request_code, e.minor_code, e.resourceid });
    return 0;
}

const Glx = struct {
    glXGetFBConfigs: *const fn (?*anyopaque, c_int, *c_int) callconv(.c) ?[*]?*anyopaque,
    glXGetVisualFromFBConfig: *const fn (?*anyopaque, ?*anyopaque) callconv(.c) ?*XVisualInfo,
    glXGetFBConfigAttrib: *const fn (?*anyopaque, ?*anyopaque, c_int, *c_int) callconv(.c) c_int,
    glXMakeCurrent: *const fn (?*anyopaque, c_ulong, ?*anyopaque) callconv(.c) c_int,
    glXSwapBuffers: *const fn (?*anyopaque, c_ulong) callconv(.c) void,
    glXGetProcAddressARB: *const fn ([*:0]const u8) callconv(.c) ?*anyopaque,
};

const Gl = struct {
    glGetString: *const fn (GLenum) callconv(.c) ?[*:0]const u8,
    glGetError: *const fn () callconv(.c) GLenum,
    glGetIntegerv: *const fn (GLenum, *GLint) callconv(.c) void,
    glViewport: *const fn (GLint, GLint, GLsizei, GLsizei) callconv(.c) void,
    glScissor: *const fn (GLint, GLint, GLsizei, GLsizei) callconv(.c) void,
    glDepthRange: *const fn (f64, f64) callconv(.c) void,
    glEnable: *const fn (GLenum) callconv(.c) void,
    glDisable: *const fn (GLenum) callconv(.c) void,
    glEnablei: *const fn (GLenum, GLuint) callconv(.c) void,
    glDisablei: *const fn (GLenum, GLuint) callconv(.c) void,
    glClearColor: *const fn (f32, f32, f32, f32) callconv(.c) void,
    glClearDepth: *const fn (f64) callconv(.c) void,
    glClearStencil: *const fn (GLint) callconv(.c) void,
    glClear: *const fn (c_uint) callconv(.c) void,
    glClearBufferfv: *const fn (GLenum, GLint, [*]const f32) callconv(.c) void,
    glClearBufferfi: *const fn (GLenum, GLint, f32, GLint) callconv(.c) void,
    glColorMaski: *const fn (GLuint, u8, u8, u8, u8) callconv(.c) void,
    glDepthMask: *const fn (u8) callconv(.c) void,
    glDepthFunc: *const fn (GLenum) callconv(.c) void,
    glStencilMask: *const fn (GLuint) callconv(.c) void,
    glStencilFuncSeparate: *const fn (GLenum, GLenum, GLint, GLuint) callconv(.c) void,
    glStencilOpSeparate: *const fn (GLenum, GLenum, GLenum, GLenum) callconv(.c) void,
    glBlendFuncSeparatei: *const fn (GLuint, GLenum, GLenum, GLenum, GLenum) callconv(.c) void,
    glBlendEquationSeparatei: *const fn (GLuint, GLenum, GLenum) callconv(.c) void,
    glBlendColor: *const fn (f32, f32, f32, f32) callconv(.c) void,
    glCullFace: *const fn (GLenum) callconv(.c) void,
    glFrontFace: *const fn (GLenum) callconv(.c) void,
    glPolygonMode: *const fn (GLenum, GLenum) callconv(.c) void,
    glPixelStorei: *const fn (GLenum, GLint) callconv(.c) void,
    glReadPixels: *const fn (GLint, GLint, GLsizei, GLsizei, GLenum, GLenum, ?*anyopaque) callconv(.c) void,
    glGetTexImage: *const fn (GLenum, GLint, GLenum, GLenum, ?*anyopaque) callconv(.c) void,
    glFinish: *const fn () callconv(.c) void,
    glFlush: *const fn () callconv(.c) void,

    glGenTextures: *const fn (GLsizei, *GLuint) callconv(.c) void,
    glDeleteTextures: *const fn (GLsizei, *const GLuint) callconv(.c) void,
    glBindTexture: *const fn (GLenum, GLuint) callconv(.c) void,
    glActiveTexture: *const fn (GLenum) callconv(.c) void,
    glTexParameteri: *const fn (GLenum, GLenum, GLint) callconv(.c) void,
    glTexImage2D: *const fn (GLenum, GLint, GLint, GLsizei, GLsizei, GLint, GLenum, GLenum, ?*const anyopaque) callconv(.c) void,
    glTexSubImage2D: *const fn (GLenum, GLint, GLint, GLint, GLsizei, GLsizei, GLenum, GLenum, ?*const anyopaque) callconv(.c) void,
    glCompressedTexImage2D: *const fn (GLenum, GLint, GLenum, GLsizei, GLsizei, GLint, GLsizei, ?*const anyopaque) callconv(.c) void,
    glCompressedTexSubImage2D: *const fn (GLenum, GLint, GLint, GLint, GLsizei, GLsizei, GLenum, GLsizei, ?*const anyopaque) callconv(.c) void,
    glTexImage3D: *const fn (GLenum, GLint, GLint, GLsizei, GLsizei, GLsizei, GLint, GLenum, GLenum, ?*const anyopaque) callconv(.c) void,
    glTexSubImage3D: *const fn (GLenum, GLint, GLint, GLint, GLint, GLsizei, GLsizei, GLsizei, GLenum, GLenum, ?*const anyopaque) callconv(.c) void,
    glCompressedTexImage3D: *const fn (GLenum, GLint, GLenum, GLsizei, GLsizei, GLsizei, GLint, GLsizei, ?*const anyopaque) callconv(.c) void,
    glCompressedTexSubImage3D: *const fn (GLenum, GLint, GLint, GLint, GLint, GLsizei, GLsizei, GLsizei, GLenum, GLsizei, ?*const anyopaque) callconv(.c) void,
    glTexImage1D: *const fn (GLenum, GLint, GLint, GLsizei, GLint, GLenum, GLenum, ?*const anyopaque) callconv(.c) void,
    glTexSubImage1D: *const fn (GLenum, GLint, GLint, GLsizei, GLenum, GLenum, ?*const anyopaque) callconv(.c) void,
    glGenerateMipmap: *const fn (GLenum) callconv(.c) void,

    glGenSamplers: *const fn (GLsizei, *GLuint) callconv(.c) void,
    glDeleteSamplers: *const fn (GLsizei, *const GLuint) callconv(.c) void,
    glBindSampler: *const fn (GLuint, GLuint) callconv(.c) void,
    glSamplerParameteri: *const fn (GLuint, GLenum, GLint) callconv(.c) void,
    glSamplerParameterf: *const fn (GLuint, GLenum, f32) callconv(.c) void,
    glSamplerParameterfv: *const fn (GLuint, GLenum, [*]const f32) callconv(.c) void,

    glGenBuffers: *const fn (GLsizei, *GLuint) callconv(.c) void,
    glDeleteBuffers: *const fn (GLsizei, *const GLuint) callconv(.c) void,
    glBindBuffer: *const fn (GLenum, GLuint) callconv(.c) void,
    glBufferData: *const fn (GLenum, GLsizeiptr, ?*const anyopaque, GLenum) callconv(.c) void,
    glBufferSubData: *const fn (GLenum, GLintptr, GLsizeiptr, ?*const anyopaque) callconv(.c) void,
    glBindBufferBase: *const fn (GLenum, GLuint, GLuint) callconv(.c) void,
    glBindBufferRange: *const fn (GLenum, GLuint, GLuint, GLintptr, GLsizeiptr) callconv(.c) void,

    glGenVertexArrays: *const fn (GLsizei, *GLuint) callconv(.c) void,
    glBindVertexArray: *const fn (GLuint) callconv(.c) void,
    glEnableVertexAttribArray: *const fn (GLuint) callconv(.c) void,
    glDisableVertexAttribArray: *const fn (GLuint) callconv(.c) void,
    glVertexAttribPointer: *const fn (GLuint, GLint, GLenum, u8, GLsizei, ?*const anyopaque) callconv(.c) void,
    glVertexAttribIPointer: *const fn (GLuint, GLint, GLenum, GLsizei, ?*const anyopaque) callconv(.c) void,
    glVertexAttribDivisor: *const fn (GLuint, GLuint) callconv(.c) void,

    glCreateShader: *const fn (GLenum) callconv(.c) GLuint,
    glShaderSource: *const fn (GLuint, GLsizei, *const [*:0]const u8, ?*const GLint) callconv(.c) void,
    glCompileShader: *const fn (GLuint) callconv(.c) void,
    glGetShaderiv: *const fn (GLuint, GLenum, *GLint) callconv(.c) void,
    glGetShaderInfoLog: *const fn (GLuint, GLsizei, ?*GLsizei, [*]u8) callconv(.c) void,
    glDeleteShader: *const fn (GLuint) callconv(.c) void,
    glCreateProgram: *const fn () callconv(.c) GLuint,
    glAttachShader: *const fn (GLuint, GLuint) callconv(.c) void,
    glLinkProgram: *const fn (GLuint) callconv(.c) void,
    glGetProgramiv: *const fn (GLuint, GLenum, *GLint) callconv(.c) void,
    glGetProgramInfoLog: *const fn (GLuint, GLsizei, ?*GLsizei, [*]u8) callconv(.c) void,
    glDeleteProgram: *const fn (GLuint) callconv(.c) void,
    glUseProgram: *const fn (GLuint) callconv(.c) void,

    glDrawArrays: *const fn (GLenum, GLint, GLsizei) callconv(.c) void,
    glDrawElements: *const fn (GLenum, GLsizei, GLenum, ?*const anyopaque) callconv(.c) void,
    glDrawElementsBaseVertex: *const fn (GLenum, GLsizei, GLenum, ?*const anyopaque, GLint) callconv(.c) void,
    glDrawArraysInstanced: *const fn (GLenum, GLint, GLsizei, GLsizei) callconv(.c) void,
    glDrawElementsInstanced: *const fn (GLenum, GLsizei, GLenum, ?*const anyopaque, GLsizei) callconv(.c) void,
    glDrawElementsInstancedBaseVertex: *const fn (GLenum, GLsizei, GLenum, ?*const anyopaque, GLsizei, GLint) callconv(.c) void,
    glDrawArraysIndirect: *const fn (GLenum, ?*const anyopaque) callconv(.c) void,
    glDrawElementsIndirect: *const fn (GLenum, GLenum, ?*const anyopaque) callconv(.c) void,

    glGenFramebuffers: *const fn (GLsizei, *GLuint) callconv(.c) void,
    glDeleteFramebuffers: *const fn (GLsizei, *const GLuint) callconv(.c) void,
    glBindFramebuffer: *const fn (GLenum, GLuint) callconv(.c) void,
    glFramebufferTexture2D: *const fn (GLenum, GLenum, GLenum, GLuint, GLint) callconv(.c) void,
    glFramebufferTextureLayer: *const fn (GLenum, GLenum, GLuint, GLint, GLint) callconv(.c) void,
    glCheckFramebufferStatus: *const fn (GLenum) callconv(.c) GLenum,
    glDrawBuffers: *const fn (GLsizei, [*]const GLenum) callconv(.c) void,
    glBlitFramebuffer: *const fn (GLint, GLint, GLint, GLint, GLint, GLint, GLint, GLint, c_uint, GLenum) callconv(.c) void,

    // Compute / SM5 memory (GL 4.3)
    glDispatchCompute: *const fn (GLuint, GLuint, GLuint) callconv(.c) void,
    glDispatchComputeIndirect: *const fn (GLintptr) callconv(.c) void,
    glMemoryBarrier: *const fn (c_uint) callconv(.c) void,
    glBindImageTexture: *const fn (GLuint, GLuint, GLint, u8, GLint, GLenum, GLenum) callconv(.c) void,
    glTexBufferRange: *const fn (GLenum, GLenum, GLuint, GLintptr, GLsizeiptr) callconv(.c) void,
};

const FnClipControl = *const fn (GLenum, GLenum) callconv(.c) void;
const FnCopyImageSubData = *const fn (GLuint, GLenum, GLint, GLint, GLint, GLint, GLuint, GLenum, GLint, GLint, GLint, GLint, GLsizei, GLsizei, GLsizei) callconv(.c) void;
const FnSwapIntervalEXT = *const fn (?*anyopaque, c_ulong, c_int) callconv(.c) void;
const FnClearTexImage = *const fn (GLuint, GLint, GLenum, GLenum, ?*const anyopaque) callconv(.c) void;

var gl: Gl = undefined;
var xlib: Xlib = undefined;
var glx: Glx = undefined;
var p_clip_control: ?FnClipControl = null;
var p_copy_image: ?FnCopyImageSubData = null;
var p_swap_interval: ?FnSwapIntervalEXT = null;
var p_clear_tex_image: ?FnClearTexImage = null;
var g_gl_display: ?*anyopaque = null;
var g_gl_ctx: ?*anyopaque = null;
var g_gl_dummy_win: c_ulong = 0;
var g_gl_window: c_ulong = 0;
var g_default_vao: GLuint = 0;
var g_copy_fbo_read: GLuint = 0;
var g_copy_fbo_draw: GLuint = 0;

// ---- Public D3D11 -> GL State & Resource Structs ---------------------------

pub const Buffer = struct {
    gl_id: GLuint = 0,
    size: u32 = 0,
    /// D3D11_BUFFER_DESC StructureByteStride / MiscFlags (0x20 raw, 0x40 structured).
    stride: u32 = 0,
    misc: u32 = 0,
    bind_flags: u32 = 0,
    usage: u32 = 0,
    cpu_access: u32 = 0,
    shadow: ?[]u8 = null,
    dirty: bool = false,
};

pub const Texture = struct {
    gl_id: GLuint = 0,
    target: GLenum = 0x0DE1, // GL_TEXTURE_2D
    width: u32 = 1,
    height: u32 = 1,
    depth: u32 = 1,
    mip_levels: u32 = 1,
    array_size: u32 = 1,
    dxgi_fmt: u32 = 28,
    bind_flags: u32 = 0,
    usage: u32 = 0,
    cpu_access: u32 = 0,
    is_depth: bool = false,
    is_compressed: bool = false,
    is_swapchain: bool = false,
    shadow: ?[]u8 = null,
    row_pitch: u32 = 0,
};

pub const View = struct {
    tex: ?*Texture = null,
    buf: ?*Buffer = null,
    dxgi_fmt: u32 = 0,
    first_mip: u32 = 0,
    num_mips: u32 = 1,
    first_slice: u32 = 0,
    num_slices: u32 = 1,
    /// Buffer views: byte range of the viewed elements.
    buf_off: u32 = 0,
    buf_size: u32 = 0,
    /// UAV: D3D11_UAV_DIMENSION (0 = not a UAV) and buffer flags (1 raw, 2 append, 4 counter).
    uav_dim: u32 = 0,
    uav_flags: u32 = 0,
    /// Typed buffer view as a GL buffer texture (created on first bind).
    gl_tbo: GLuint = 0,
    /// Append/consume counter (one uint GL buffer) and a pending initial count.
    counter: GLuint = 0,
    counter_set: ?u32 = null,
};

pub const Sampler = struct {
    gl_id: GLuint = 0,
};

pub const RtBlendDesc = struct {
    enable: bool = false,
    src_rgb: GLenum = 1,
    dst_rgb: GLenum = 0,
    op_rgb: GLenum = 0x8006,
    src_a: GLenum = 1,
    dst_a: GLenum = 0,
    op_a: GLenum = 0x8006,
    write_mask: u8 = 0xF,
};

pub const BlendState = struct {
    alpha_to_coverage: bool = false,
    independent: bool = false,
    rt: [8]RtBlendDesc = [_]RtBlendDesc{.{}} ** 8,
};

pub const DepthStencilState = struct {
    depth_enable: bool = true,
    depth_write: bool = true,
    depth_func: GLenum = 0x0201, // GL_LESS
    stencil_enable: bool = false,
    stencil_read_mask: u8 = 0xFF,
    stencil_write_mask: u8 = 0xFF,
    front_fail: GLenum = 0x1E00,
    front_zfail: GLenum = 0x1E00,
    front_pass: GLenum = 0x1E00,
    front_func: GLenum = 0x0207,
    back_fail: GLenum = 0x1E00,
    back_zfail: GLenum = 0x1E00,
    back_pass: GLenum = 0x1E00,
    back_func: GLenum = 0x0207,
};

pub const RasterizerState = struct {
    wireframe: bool = false,
    cull_mode: u32 = 3, // 1=NONE, 2=FRONT, 3=BACK
    front_ccw: bool = false,
    scissor_enable: bool = false,
    depth_clip: bool = true,
};

pub const InputElem = struct {
    location: u32 = 0,
    components: i32 = 4, // 1..4 or 0x80E1 (GL_BGRA)
    gl_type: GLenum = 0x1406, // GL_FLOAT
    normalized: bool = false,
    is_int: bool = false,
    slot: u32 = 0,
    offset: u32 = 0,
    step_rate: u32 = 0,
    is_instance: bool = false,
    sem_name: [32]u8 = .{0} ** 32,
    sem_len: u8 = 0,
    sem_index: u32 = 0,
};

pub const InputLayout = struct {
    count: usize = 0,
    elems: [32]InputElem = [_]InputElem{.{}} ** 32,
};

pub const MAX_SRV = shader.MAX_TEX;

pub const Shader = struct {
    is_pixel: bool = false,
    is_compute: bool = false,
    /// Compute: linked program (0 = not yet / failed) and its resource bindings.
    cs_linked: bool = false,
    cs_prog: GLuint = 0,
    cs_tex: []const shader.TexBinding = &.{},
    cs_buf: []const shader.BufBinding = &.{},
    cs_img: []const shader.ImgBinding = &.{},
    /// Unique per createShader: program cache key (heap addresses get reused).
    uid: u64 = 0,
    bytecode: []u8 = &.{},
    inputs: []shader.SigElem = &.{},
    outputs: []shader.SigElem = &.{},
};

pub const DrawKind = enum {
    arrays,
    indexed,
    arrays_instanced,
    indexed_instanced,
    arrays_indirect,
    indexed_indirect,
};

pub const Viewport = struct {
    x: f32 = 0,
    y: f32 = 0,
    w: f32 = 0,
    h: f32 = 0,
    min_depth: f32 = 0,
    max_depth: f32 = 1,
};

pub const ScissorRect = struct {
    left: i32 = 0,
    top: i32 = 0,
    right: i32 = 0,
    bottom: i32 = 0,
};

pub const DrawState = struct {
    topology: u32 = 4, // D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST
    input_layout: ?*InputLayout = null,
    vb: [16]?*Buffer = [_]?*Buffer{null} ** 16,
    vb_stride: [16]u32 = [_]u32{0} ** 16,
    vb_offset: [16]u32 = [_]u32{0} ** 16,
    ib: ?*Buffer = null,
    ib_format: u32 = 57, // DXGI_FORMAT_R16_UINT
    ib_offset: u32 = 0,

    vs: ?*Shader = null,
    ps: ?*Shader = null,
    vs_cb: [16]?*Buffer = [_]?*Buffer{null} ** 16,
    vs_cb_off: [16]u32 = [_]u32{0} ** 16,
    vs_cb_sz: [16]u32 = [_]u32{0} ** 16,
    ps_cb: [16]?*Buffer = [_]?*Buffer{null} ** 16,
    ps_cb_off: [16]u32 = [_]u32{0} ** 16,
    ps_cb_sz: [16]u32 = [_]u32{0} ** 16,

    vs_srv: [MAX_SRV]?*View = [_]?*View{null} ** MAX_SRV,
    ps_srv: [MAX_SRV]?*View = [_]?*View{null} ** MAX_SRV,
    vs_samp: [16]?*Sampler = [_]?*Sampler{null} ** 16,
    ps_samp: [16]?*Sampler = [_]?*Sampler{null} ** 16,

    /// A geometry shader is bound (GS is not translated: such draws are skipped).
    gs_active: bool = false,

    cs: ?*Shader = null,
    cs_cb: [16]?*Buffer = [_]?*Buffer{null} ** 16,
    cs_cb_off: [16]u32 = [_]u32{0} ** 16,
    cs_cb_sz: [16]u32 = [_]u32{0} ** 16,
    cs_srv: [MAX_SRV]?*View = [_]?*View{null} ** MAX_SRV,
    cs_samp: [16]?*Sampler = [_]?*Sampler{null} ** 16,
    cs_uav: [shader.MAX_UAV]?*View = [_]?*View{null} ** shader.MAX_UAV,

    rtv: [8]?*View = [_]?*View{null} ** 8,
    num_rtvs: u32 = 0,
    dsv: ?*View = null,

    blend: ?*BlendState = null,
    blend_factor: [4]f32 = .{ 1, 1, 1, 1 },
    sample_mask: u32 = 0xFFFFFFFF,
    depth_stencil: ?*DepthStencilState = null,
    stencil_ref: u32 = 0,
    rasterizer: ?*RasterizerState = null,

    num_viewports: u32 = 0,
    viewports: [8]Viewport = [_]Viewport{.{}} ** 8,
    num_scissors: u32 = 0,
    scissors: [8]ScissorRect = [_]ScissorRect{.{}} ** 8,
};

// ---- Format Mapping ---------------------------------------------------------

pub const GlTexFmt = struct {
    internal: GLint,
    format: GLenum,
    ty: GLenum,
    bpp: u32,
    compressed: bool,
    block_bytes: u32,
    is_depth: bool,
    is_stencil: bool,
    is_a8: bool,
};

pub fn dxgiToGlFormat(fmt: u32) GlTexFmt {
    return switch (fmt) {
        1, 2 => .{ .internal = 0x8814, .format = 0x1908, .ty = 0x1406, .bpp = 16, .compressed = false, .block_bytes = 0, .is_depth = false, .is_stencil = false, .is_a8 = false }, // RGBA32F
        9, 10 => .{ .internal = 0x881A, .format = 0x1908, .ty = 0x140B, .bpp = 8, .compressed = false, .block_bytes = 0, .is_depth = false, .is_stencil = false, .is_a8 = false }, // RGBA16F
        11 => .{ .internal = 0x805B, .format = 0x1908, .ty = 0x1403, .bpp = 8, .compressed = false, .block_bytes = 0, .is_depth = false, .is_stencil = false, .is_a8 = false }, // RGBA16
        15, 16 => .{ .internal = 0x8230, .format = 0x8227, .ty = 0x1406, .bpp = 8, .compressed = false, .block_bytes = 0, .is_depth = false, .is_stencil = false, .is_a8 = false }, // RG32F
        19, 20, 21, 22 => .{ .internal = 0x8CAD, .format = 0x84F9, .ty = 0x8DAD, .bpp = 8, .compressed = false, .block_bytes = 0, .is_depth = true, .is_stencil = true, .is_a8 = false }, // D32F_S8
        23, 24 => .{ .internal = 0x8059, .format = 0x1908, .ty = 0x8368, .bpp = 4, .compressed = false, .block_bytes = 0, .is_depth = false, .is_stencil = false, .is_a8 = false }, // RGB10_A2
        26 => .{ .internal = 0x8C3A, .format = 0x1907, .ty = 0x8C3B, .bpp = 4, .compressed = false, .block_bytes = 0, .is_depth = false, .is_stencil = false, .is_a8 = false }, // R11F_G11F_B10F
        27, 28, 30, 31, 32 => .{ .internal = 0x8058, .format = 0x1908, .ty = 0x1401, .bpp = 4, .compressed = false, .block_bytes = 0, .is_depth = false, .is_stencil = false, .is_a8 = false }, // RGBA8
        29 => .{ .internal = 0x8C43, .format = 0x1908, .ty = 0x1401, .bpp = 4, .compressed = false, .block_bytes = 0, .is_depth = false, .is_stencil = false, .is_a8 = false }, // SRGB8_ALPHA8
        33, 34 => .{ .internal = 0x822F, .format = 0x8227, .ty = 0x140B, .bpp = 4, .compressed = false, .block_bytes = 0, .is_depth = false, .is_stencil = false, .is_a8 = false }, // RG16F
        35 => .{ .internal = 0x822C, .format = 0x8227, .ty = 0x1403, .bpp = 4, .compressed = false, .block_bytes = 0, .is_depth = false, .is_stencil = false, .is_a8 = false }, // RG16
        39, 40 => .{ .internal = 0x8CAC, .format = 0x1902, .ty = 0x1406, .bpp = 4, .compressed = false, .block_bytes = 0, .is_depth = true, .is_stencil = false, .is_a8 = false }, // D32F
        41 => .{ .internal = 0x822E, .format = 0x1903, .ty = 0x1406, .bpp = 4, .compressed = false, .block_bytes = 0, .is_depth = false, .is_stencil = false, .is_a8 = false }, // R32F
        44, 45, 46, 47 => .{ .internal = 0x88F0, .format = 0x84F9, .ty = 0x84FA, .bpp = 4, .compressed = false, .block_bytes = 0, .is_depth = true, .is_stencil = true, .is_a8 = false }, // D24S8
        48, 49 => .{ .internal = 0x822B, .format = 0x8227, .ty = 0x1401, .bpp = 2, .compressed = false, .block_bytes = 0, .is_depth = false, .is_stencil = false, .is_a8 = false }, // RG8
        53, 54 => .{ .internal = 0x822D, .format = 0x1903, .ty = 0x140B, .bpp = 2, .compressed = false, .block_bytes = 0, .is_depth = false, .is_stencil = false, .is_a8 = false }, // R16F
        55 => .{ .internal = 0x81A5, .format = 0x1902, .ty = 0x1403, .bpp = 2, .compressed = false, .block_bytes = 0, .is_depth = true, .is_stencil = false, .is_a8 = false }, // D16
        56 => .{ .internal = 0x822A, .format = 0x1903, .ty = 0x1403, .bpp = 2, .compressed = false, .block_bytes = 0, .is_depth = false, .is_stencil = false, .is_a8 = false }, // R16
        60, 61 => .{ .internal = 0x8229, .format = 0x1903, .ty = 0x1401, .bpp = 1, .compressed = false, .block_bytes = 0, .is_depth = false, .is_stencil = false, .is_a8 = false }, // R8
        65 => .{ .internal = 0x8229, .format = 0x1903, .ty = 0x1401, .bpp = 1, .compressed = false, .block_bytes = 0, .is_depth = false, .is_stencil = false, .is_a8 = true }, // A8 -> R8 swizzled
        70, 71 => .{ .internal = 0x83F1, .format = 0x83F1, .ty = 0, .bpp = 0, .compressed = true, .block_bytes = 8, .is_depth = false, .is_stencil = false, .is_a8 = false }, // BC1
        72 => .{ .internal = 0x8C4D, .format = 0x8C4D, .ty = 0, .bpp = 0, .compressed = true, .block_bytes = 8, .is_depth = false, .is_stencil = false, .is_a8 = false }, // BC1_SRGB
        73, 74 => .{ .internal = 0x83F2, .format = 0x83F2, .ty = 0, .bpp = 0, .compressed = true, .block_bytes = 16, .is_depth = false, .is_stencil = false, .is_a8 = false }, // BC2
        75 => .{ .internal = 0x8C4E, .format = 0x8C4E, .ty = 0, .bpp = 0, .compressed = true, .block_bytes = 16, .is_depth = false, .is_stencil = false, .is_a8 = false }, // BC2_SRGB
        76, 77 => .{ .internal = 0x83F3, .format = 0x83F3, .ty = 0, .bpp = 0, .compressed = true, .block_bytes = 16, .is_depth = false, .is_stencil = false, .is_a8 = false }, // BC3
        78 => .{ .internal = 0x8C4F, .format = 0x8C4F, .ty = 0, .bpp = 0, .compressed = true, .block_bytes = 16, .is_depth = false, .is_stencil = false, .is_a8 = false }, // BC3_SRGB
        79, 80, 81 => .{ .internal = 0x8DBB, .format = 0x8DBB, .ty = 0, .bpp = 0, .compressed = true, .block_bytes = 8, .is_depth = false, .is_stencil = false, .is_a8 = false }, // BC4
        82, 83, 84 => .{ .internal = 0x8DBD, .format = 0x8DBD, .ty = 0, .bpp = 0, .compressed = true, .block_bytes = 16, .is_depth = false, .is_stencil = false, .is_a8 = false }, // BC5
        87, 88, 90 => .{ .internal = 0x8058, .format = 0x80E1, .ty = 0x1401, .bpp = 4, .compressed = false, .block_bytes = 0, .is_depth = false, .is_stencil = false, .is_a8 = false }, // BGRA8
        91, 93 => .{ .internal = 0x8C43, .format = 0x80E1, .ty = 0x1401, .bpp = 4, .compressed = false, .block_bytes = 0, .is_depth = false, .is_stencil = false, .is_a8 = false }, // BGRA8_SRGB
        94, 95 => .{ .internal = 0x8E8F, .format = 0x8E8F, .ty = 0, .bpp = 0, .compressed = true, .block_bytes = 16, .is_depth = false, .is_stencil = false, .is_a8 = false }, // BC6H_UF16
        96 => .{ .internal = 0x8E8E, .format = 0x8E8E, .ty = 0, .bpp = 0, .compressed = true, .block_bytes = 16, .is_depth = false, .is_stencil = false, .is_a8 = false }, // BC6H_SF16
        97, 98 => .{ .internal = 0x8E8C, .format = 0x8E8C, .ty = 0, .bpp = 0, .compressed = true, .block_bytes = 16, .is_depth = false, .is_stencil = false, .is_a8 = false }, // BC7
        99 => .{ .internal = 0x8E8D, .format = 0x8E8D, .ty = 0, .bpp = 0, .compressed = true, .block_bytes = 16, .is_depth = false, .is_stencil = false, .is_a8 = false }, // BC7_SRGB
        else => .{ .internal = 0x8058, .format = 0x1908, .ty = 0x1401, .bpp = 4, .compressed = false, .block_bytes = 0, .is_depth = false, .is_stencil = false, .is_a8 = false },
    };
}

pub const InputFmtInfo = struct {
    components: i32,
    gl_type: GLenum,
    normalized: bool,
    is_int: bool,
    byte_size: u32,
};

pub fn inputFormatToGl(fmt: u32) InputFmtInfo {
    return switch (fmt) {
        2 => .{ .components = 4, .gl_type = 0x1406, .normalized = false, .is_int = false, .byte_size = 16 },
        3 => .{ .components = 4, .gl_type = 0x1405, .normalized = false, .is_int = true, .byte_size = 16 },
        4 => .{ .components = 4, .gl_type = 0x1404, .normalized = false, .is_int = true, .byte_size = 16 },
        6 => .{ .components = 3, .gl_type = 0x1406, .normalized = false, .is_int = false, .byte_size = 12 },
        7 => .{ .components = 3, .gl_type = 0x1405, .normalized = false, .is_int = true, .byte_size = 12 },
        8 => .{ .components = 3, .gl_type = 0x1404, .normalized = false, .is_int = true, .byte_size = 12 },
        10 => .{ .components = 4, .gl_type = 0x140B, .normalized = false, .is_int = false, .byte_size = 8 },
        11 => .{ .components = 4, .gl_type = 0x1403, .normalized = true, .is_int = false, .byte_size = 8 },
        12 => .{ .components = 4, .gl_type = 0x1403, .normalized = false, .is_int = true, .byte_size = 8 },
        13 => .{ .components = 4, .gl_type = 0x1402, .normalized = true, .is_int = false, .byte_size = 8 },
        14 => .{ .components = 4, .gl_type = 0x1402, .normalized = false, .is_int = true, .byte_size = 8 },
        16 => .{ .components = 2, .gl_type = 0x1406, .normalized = false, .is_int = false, .byte_size = 8 },
        17 => .{ .components = 2, .gl_type = 0x1405, .normalized = false, .is_int = true, .byte_size = 8 },
        18 => .{ .components = 2, .gl_type = 0x1404, .normalized = false, .is_int = true, .byte_size = 8 },
        28 => .{ .components = 4, .gl_type = 0x1401, .normalized = true, .is_int = false, .byte_size = 4 },
        30 => .{ .components = 4, .gl_type = 0x1401, .normalized = false, .is_int = true, .byte_size = 4 },
        31 => .{ .components = 4, .gl_type = 0x1400, .normalized = true, .is_int = false, .byte_size = 4 },
        32 => .{ .components = 4, .gl_type = 0x1400, .normalized = false, .is_int = true, .byte_size = 4 },
        34 => .{ .components = 2, .gl_type = 0x140B, .normalized = false, .is_int = false, .byte_size = 4 },
        35 => .{ .components = 2, .gl_type = 0x1403, .normalized = true, .is_int = false, .byte_size = 4 },
        41 => .{ .components = 1, .gl_type = 0x1406, .normalized = false, .is_int = false, .byte_size = 4 },
        42 => .{ .components = 1, .gl_type = 0x1405, .normalized = false, .is_int = true, .byte_size = 4 },
        43 => .{ .components = 1, .gl_type = 0x1404, .normalized = false, .is_int = true, .byte_size = 4 },
        49 => .{ .components = 2, .gl_type = 0x1401, .normalized = true, .is_int = false, .byte_size = 2 },
        54 => .{ .components = 1, .gl_type = 0x140B, .normalized = false, .is_int = false, .byte_size = 2 },
        56 => .{ .components = 1, .gl_type = 0x1403, .normalized = true, .is_int = false, .byte_size = 2 },
        61 => .{ .components = 1, .gl_type = 0x1401, .normalized = true, .is_int = false, .byte_size = 1 },
        24 => .{ .components = 4, .gl_type = 0x8368, .normalized = true, .is_int = false, .byte_size = 4 }, // R10G10B10A2_UNORM
        29 => .{ .components = 4, .gl_type = 0x1401, .normalized = true, .is_int = false, .byte_size = 4 }, // R8G8B8A8_UNORM_SRGB
        36 => .{ .components = 2, .gl_type = 0x1403, .normalized = false, .is_int = true, .byte_size = 4 }, // R16G16_UINT
        37 => .{ .components = 2, .gl_type = 0x1402, .normalized = true, .is_int = false, .byte_size = 4 }, // R16G16_SNORM
        38 => .{ .components = 2, .gl_type = 0x1402, .normalized = false, .is_int = true, .byte_size = 4 }, // R16G16_SINT
        50 => .{ .components = 2, .gl_type = 0x1401, .normalized = false, .is_int = true, .byte_size = 2 }, // R8G8_UINT
        51 => .{ .components = 2, .gl_type = 0x1400, .normalized = true, .is_int = false, .byte_size = 2 }, // R8G8_SNORM
        52 => .{ .components = 2, .gl_type = 0x1400, .normalized = false, .is_int = true, .byte_size = 2 }, // R8G8_SINT
        57 => .{ .components = 1, .gl_type = 0x1403, .normalized = false, .is_int = true, .byte_size = 2 }, // R16_UINT
        58 => .{ .components = 1, .gl_type = 0x1402, .normalized = true, .is_int = false, .byte_size = 2 }, // R16_SNORM
        59 => .{ .components = 1, .gl_type = 0x1402, .normalized = false, .is_int = true, .byte_size = 2 }, // R16_SINT
        62 => .{ .components = 1, .gl_type = 0x1401, .normalized = false, .is_int = true, .byte_size = 1 }, // R8_UINT
        63 => .{ .components = 1, .gl_type = 0x1400, .normalized = true, .is_int = false, .byte_size = 1 }, // R8_SNORM
        64 => .{ .components = 1, .gl_type = 0x1400, .normalized = false, .is_int = true, .byte_size = 1 }, // R8_SINT
        87, 88 => .{ .components = 0x80E1, .gl_type = 0x1401, .normalized = true, .is_int = false, .byte_size = 4 }, // GL_BGRA (B8G8R8A8/X8)
        else => blk: {
            const S = struct { var seen: [128]bool = @splat(false); };
            if (fmt < 128 and !S.seen[fmt]) {
                S.seen[fmt] = true;
                std.debug.print("[WINS:D3D11] input layout: DXGI format {d} not mapped (treated as RGBA32F)\n", .{fmt});
            }
            break :blk .{ .components = 4, .gl_type = 0x1406, .normalized = false, .is_int = false, .byte_size = 16 };
        },
    };
}

// ---- Render Thread & Job Runner ---------------------------------------------

const JobFn = *const fn (?*anyopaque) void;
var g_job_fn: ?JobFn = null;
var g_job_ctx: ?*anyopaque = null;
var g_posted = std.atomic.Value(u32).init(0);
var g_done = std.atomic.Value(u32).init(0);
var g_submit = std.atomic.Value(u32).init(0);
var g_state = std.atomic.Value(u32).init(0); // 0=init, 1=ready, 2=failed
var g_started = false;
var g_init_hwnd: usize = 0;
var g_init_w: u32 = 1280;
var g_init_h: u32 = 720;

fn futexWait(word: *std.atomic.Value(u32), expect: u32) void {
    _ = linux.syscall4(.futex, @intFromPtr(word), 0, expect, 0);
}

fn futexWake(word: *std.atomic.Value(u32)) void {
    _ = linux.syscall3(.futex, @intFromPtr(word), 1, std.math.maxInt(i32));
}

pub fn run(func: JobFn, ctx: ?*anyopaque) void {
    if (g_state.load(.acquire) != 1) return;
    while (g_submit.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) futexWait(&g_submit, 1);
    g_job_fn = func;
    g_job_ctx = ctx;
    const ticket = g_posted.fetchAdd(1, .release) +% 1;
    futexWake(&g_posted);
    var spins: u32 = 0;
    while (true) {
        const done = g_done.load(.acquire);
        if (done == ticket) break;
        if (spins < 4000) {
            spins += 1;
            std.atomic.spinLoopHint();
            continue;
        }
        futexWait(&g_done, done);
    }
    g_submit.store(0, .release);
    futexWake(&g_submit);
}

pub fn isActive() bool {
    return g_state.load(.acquire) == 1;
}

fn loadTable(comptime T: type, table: *T, lib: ?*anyopaque, comptime what: []const u8) bool {
    inline for (std.meta.fields(T)) |f| {
        const sym = dlsym(lib, f.name ++ "") orelse {
            std.debug.print("[WINS:D3D11:GL] {s} missing symbol {s}\n", .{ what, f.name });
            return false;
        };
        @field(table, f.name) = @ptrCast(@alignCast(sym));
    }
    return true;
}

fn loadGl() bool {
    inline for (std.meta.fields(Gl)) |f| {
        const sym = glx.glXGetProcAddressARB(f.name ++ "") orelse {
            std.debug.print("[WINS:D3D11:GL] OpenGL missing {s}\n", .{f.name});
            return false;
        };
        @field(gl, f.name) = @ptrCast(@alignCast(sym));
    }
    if (glx.glXGetProcAddressARB("glClipControl")) |s| p_clip_control = @ptrCast(@alignCast(s));
    if (glx.glXGetProcAddressARB("glCopyImageSubData")) |s| p_copy_image = @ptrCast(@alignCast(s));
    if (glx.glXGetProcAddressARB("glXSwapIntervalEXT")) |s| p_swap_interval = @ptrCast(@alignCast(s));
    if (glx.glXGetProcAddressARB("glClearTexImage")) |s| p_clear_tex_image = @ptrCast(@alignCast(s));
    return true;
}

fn preferDiscreteGpu() void {
    if (getenv("WINS_GPU")) |v| {
        if (std.mem.eql(u8, std.mem.sliceTo(v, 0), "integrated")) return;
    }
    if (getenv("__NV_PRIME_RENDER_OFFLOAD") != null or getenv("__GLX_VENDOR_LIBRARY_NAME") != null or getenv("DRI_PRIME") != null) return;
    if (access("/dev/nvidiactl", 6) != 0) return;
    if (dlopen("libGLX_nvidia.so.0", 2) == null) return;
    _ = setenv("__NV_PRIME_RENDER_OFFLOAD", "1", 1);
    _ = setenv("__GLX_VENDOR_LIBRARY_NAME", "nvidia", 1);
    std.debug.print("[WINS:D3D11:GL] NVIDIA GPU detected -> PRIME render offload enabled\n", .{});
}

fn findFbConfigForWin(dpy: ?*anyopaque, win: c_ulong) ?*anyopaque {
    var xwa: XWindowAttributes = undefined;
    if (xlib.XGetWindowAttributes(dpy, win, &xwa) == 0) {
        std.debug.print("[WINS:D3D11:GL] XGetWindowAttributes failed\n", .{});
        return null;
    }
    const win_vid = xlib.XVisualIDFromVisual(xwa.visual);
    const screen = xlib.XDefaultScreen(dpy);

    var ncfg: c_int = 0;
    const cfgs = glx.glXGetFBConfigs(dpy, screen, &ncfg) orelse return null;
    var best_cfg: ?*anyopaque = null;
    var fallback_cfg: ?*anyopaque = null;
    var i: usize = 0;
    while (i < @as(usize, @intCast(@max(0, ncfg)))) : (i += 1) {
        const cfg = cfgs[i] orelse continue;
        var render_type: c_int = 0;
        var draw_type: c_int = 0;
        var dbl: c_int = 0;
        _ = glx.glXGetFBConfigAttrib(dpy, cfg, 0x8011, &render_type); // GLX_RENDER_TYPE
        _ = glx.glXGetFBConfigAttrib(dpy, cfg, 0x8010, &draw_type); // GLX_DRAWABLE_TYPE
        _ = glx.glXGetFBConfigAttrib(dpy, cfg, 5, &dbl); // GLX_DOUBLEBUFFER
        if ((render_type & 1) == 0 or (draw_type & 1) == 0 or dbl == 0) continue;
        const vi = glx.glXGetVisualFromFBConfig(dpy, cfg) orelse continue;
        defer _ = xlib.XFree(vi);
        if (vi.visualid == win_vid) {
            best_cfg = cfg;
            break;
        }
        if (fallback_cfg == null) fallback_cfg = cfg;
    }
    _ = xlib.XFree(@ptrCast(cfgs));
    return best_cfg orelse fallback_cfg;
}

fn createCoreContext(dpy: ?*anyopaque, chosen: ?*anyopaque, share: ?*anyopaque) ?*anyopaque {
    const FnCreateCtxAttribs = *const fn (?*anyopaque, ?*anyopaque, ?*anyopaque, c_int, [*]const c_int) callconv(.c) ?*anyopaque;
    const create_attribs: FnCreateCtxAttribs = @ptrCast(@alignCast(glx.glXGetProcAddressARB("glXCreateContextAttribsARB") orelse return null));
    const attrs45 = [_]c_int{ 0x2091, 4, 0x2092, 5, 0x9126, 1, 0 };
    const attrs42 = [_]c_int{ 0x2091, 4, 0x2092, 2, 0x9126, 1, 0 };
    const attrs33 = [_]c_int{ 0x2091, 3, 0x2092, 3, 0x9126, 1, 0 };
    return create_attribs(dpy, chosen, share, 1, &attrs45) orelse
        create_attribs(dpy, chosen, share, 1, &attrs42) orelse
        create_attribs(dpy, chosen, share, 1, &attrs33);
}

fn initContextState() void {
    if (p_clip_control) |cc| {
        cc(0x8CA2, 0x935F); // GL_UPPER_LEFT, GL_ZERO_TO_ONE
    } else {
        std.debug.print("[WINS:D3D11:GL] warning: glClipControl missing, Y/Z may need extension\n", .{});
    }
    gl.glGenVertexArrays(1, &g_default_vao);
    gl.glBindVertexArray(g_default_vao);
    gl.glGenFramebuffers(1, &g_copy_fbo_read);
    gl.glGenFramebuffers(1, &g_copy_fbo_draw);
    gl.glPixelStorei(0x0CF5, 1);
    gl.glPixelStorei(0x0D05, 1);
}

fn openGlxInitial() bool {
    preferDiscreteGpu();
    const lx = dlopen("libX11.so.6", 2) orelse return false;
    const lg = dlopen("libGL.so.1", 2) orelse return false;
    if (!loadTable(Xlib, &xlib, lx, "libX11") or !loadTable(Glx, &glx, lg, "libGL")) return false;

    const dpy = xlib.XOpenDisplay(null) orelse {
        std.debug.print("[WINS:D3D11:GL] XOpenDisplay failed on render thread\n", .{});
        return false;
    };
    _ = xlib.XSetErrorHandler(&xErrorHandler);
    const root = xlib.XDefaultRootWindow(dpy);
    const dummy = xlib.XCreateSimpleWindow(dpy, root, 0, 0, 1, 1, 0, 0, 0);
    if (dummy == 0) return false;
    _ = xlib.XSync(dpy, 0);

    const chosen = findFbConfigForWin(dpy, dummy) orelse return false;
    const ctx = createCoreContext(dpy, chosen, null) orelse {
        std.debug.print("[WINS:D3D11:GL] glXCreateContextAttribsARB failed\n", .{});
        return false;
    };
    if (glx.glXMakeCurrent(dpy, dummy, ctx) == 0) {
        std.debug.print("[WINS:D3D11:GL] glXMakeCurrent failed on dummy win=0x{x}\n", .{dummy});
        return false;
    }
    if (!loadGl()) return false;

    g_gl_display = dpy;
    g_gl_ctx = ctx;
    g_gl_dummy_win = dummy;
    initContextState();

    std.debug.print("[WINS:D3D11:GL] Core context initialized (early); renderer=\"{s}\" GL=\"{s}\"\n", .{
        gl.glGetString(0x1F01) orelse "?", gl.glGetString(0x1F02) orelse "?",
    });
    return true;
}

const BindSurfJob = struct { win: c_ulong, w: u32, h: u32, ok: bool = false };

fn bindSurfaceJob(raw: ?*anyopaque) void {
    const j: *BindSurfJob = @ptrCast(@alignCast(raw.?));
    const dpy = g_gl_display orelse return;
    g_init_w = @max(1, j.w);
    g_init_h = @max(1, j.h);
    if (glx.glXMakeCurrent(dpy, j.win, g_gl_ctx) == 0) {
        const chosen = findFbConfigForWin(dpy, j.win) orelse return;
        const shared_ctx = createCoreContext(dpy, chosen, g_gl_ctx) orelse return;
        if (glx.glXMakeCurrent(dpy, j.win, shared_ctx) == 0) return;
        g_gl_ctx = shared_ctx;
        initContextState();
    }
    g_gl_window = j.win;
    if (p_swap_interval) |si| si(dpy, j.win, 0);
    std.debug.print("[WINS:D3D11:GL] Core context ready {d}x{d} on X11 win=0x{x}; renderer=\"{s}\" GL=\"{s}\"\n", .{
        g_init_w, g_init_h, j.win, gl.glGetString(0x1F01) orelse "?", gl.glGetString(0x1F02) orelse "?",
    });
    j.ok = true;
}

fn renderThreadMain() void {
    const ok = openGlxInitial();
    g_state.store(if (ok) 1 else 2, .release);
    futexWake(&g_state);
    if (!ok) return;
    var served: u32 = 0;
    var idle_spins: u32 = 0;
    while (true) {
        const posted = g_posted.load(.acquire);
        if (posted == served and idle_spins < 8000) {
            idle_spins += 1;
            std.atomic.spinLoopHint();
            continue;
        }
        idle_spins = 0;
        if (posted == served) {
            var ts: linux.timespec = .{ .sec = 0, .nsec = 10_000_000 };
            _ = linux.syscall4(.futex, @intFromPtr(&g_posted), 0, posted, @intFromPtr(&ts));
            continue;
        }
        if (g_job_fn) |f| f(g_job_ctx);
        served +%= 1;
        g_done.store(served, .release);
        futexWake(&g_done);
    }
}

pub fn ensureStarted() bool {
    if (!g_started) {
        g_started = true;
        // Start X11/GL render thread immediately so D3D11 buffers/textures created before CreateSwapChain get real GL IDs.
        const t = std.Thread.spawn(.{}, renderThreadMain, .{}) catch {
            g_state.store(2, .release);
            return false;
        };
        t.detach();
    }
    while (g_state.load(.acquire) == 0) futexWait(&g_state, 0);
    return g_state.load(.acquire) == 1;
}

pub fn init(hwnd: usize, w: u32, h: u32) bool {
    if (!ensureStarted()) return false;
    g_init_hwnd = hwnd;
    // Create the X11 window on the main/UI side before binding GLX drawable
    const surf = gui.ensureGlSurfaceForHwnd(hwnd) orelse return false;
    var j: BindSurfJob = .{ .win = surf.window, .w = w, .h = h };
    run(&bindSurfaceJob, &j);
    return j.ok;
}

// ---- GL Caches (Program Pair & FBO) -----------------------------------------

const ProgKey = packed struct(u128) {
    vs: u64,
    ps: u64,
};

const LinkedProg = struct {
    prog: GLuint = 0,
    ps_tex_bindings: []const shader.TexBinding = &.{},
    vs_tex_bindings: []const shader.TexBinding = &.{},
    ps_buf_bindings: []const shader.BufBinding = &.{},
    vs_buf_bindings: []const shader.BufBinding = &.{},
};

var g_progs: std.AutoHashMapUnmanaged(ProgKey, LinkedProg) = .{};
var g_shader_uid = std.atomic.Value(u64).init(0);

const FboKey = struct {
    rtvs: [8]GLuint,
    rtv_mips: [8]u32,
    rtv_slices: [8]u32,
    num_rtvs: u32,
    dsv: GLuint,
    dsv_mip: u32,
    dsv_slice: u32,
};

const FboEntry = struct { key: FboKey, fbo: GLuint };
var g_fbos: std.ArrayListUnmanaged(FboEntry) = .empty;

fn compileGlShader(kind: GLenum, src: [:0]const u8, label: []const u8) GLuint {
    const sh = gl.glCreateShader(kind);
    const p: [*:0]const u8 = src.ptr;
    gl.glShaderSource(sh, 1, &p, null);
    gl.glCompileShader(sh);
    var ok: GLint = 0;
    gl.glGetShaderiv(sh, 0x8B81, &ok);
    if (ok == 0) {
        var log_buf: [2048]u8 = undefined;
        var n: GLsizei = 0;
        gl.glGetShaderInfoLog(sh, log_buf.len, &n, &log_buf);
        std.debug.print("[WINS:D3D11:GL] {s} compile FAIL:\n{s}\n--- GLSL ---\n{s}\n", .{ label, log_buf[0..@intCast(@max(0, n))], src });
        gl.glDeleteShader(sh);
        return 0;
    }
    return sh;
}

/// A failed translate/compile/link is cached too (prog = 0): retrying it on every
/// draw recompiled the same broken GLSL ~80k times and wrote a 600 MB log.
fn getOrLinkProgram(vs: *Shader, ps: ?*Shader) LinkedProg {
    const ps_uid: u64 = if (ps) |p| p.uid else 0;
    const key: ProgKey = .{ .vs = vs.uid, .ps = ps_uid };
    if (g_progs.get(key)) |hit| return hit;
    const res = linkProgram(vs, ps);
    if (res.prog == 0) {
        g_progs.put(alloc, key, res) catch {};
        dumpFailedBytecode(vs, ps);
    }
    return res;
}

/// WINS_D3D11_CAPTURE=<dir>: each failed program leaves its VS/PS DXBC there
/// (fail<N>_vs.dxbc / fail<N>_ps.dxbc) so the translator can be fixed offline.
fn dumpFailedBytecode(vs: *Shader, ps: ?*Shader) void {
    const dir = getenv("WINS_D3D11_CAPTURE") orelse return;
    const S = struct { var n: u32 = 0; };
    S.n += 1;
    if (S.n > 64) return;
    var buf: [1024]u8 = undefined;
    if (std.fmt.bufPrintZ(&buf, "{s}/fail{d:0>3}_vs.dxbc", .{ std.mem.span(dir), S.n })) |path| writeFileZ(path, vs.bytecode) else |_| {}
    if (ps) |p| {
        if (std.fmt.bufPrintZ(&buf, "{s}/fail{d:0>3}_ps.dxbc", .{ std.mem.span(dir), S.n })) |path| writeFileZ(path, p.bytecode) else |_| {}
    }
}

fn linkProgram(vs: *Shader, ps: ?*Shader) LinkedProg {
    const ps_uid: u64 = if (ps) |p| p.uid else 0;
    const key: ProgKey = .{ .vs = vs.uid, .ps = ps_uid };

    var tv = shader.translateWithVaryings(alloc, vs.bytecode, null) catch |e| {
        std.debug.print("[WINS:D3D11:GL] VS translate err={s} ({s})\n", .{ @errorName(e), shader.last_error });
        return .{};
    };
    defer tv.deinit(alloc);
    const gl_vs = compileGlShader(0x8B31, tv.glsl, "VS");
    if (gl_vs == 0) return .{};
    defer gl.glDeleteShader(gl_vs);

    var gl_ps: GLuint = 0;
    var ps_tex: []const shader.TexBinding = &.{};
    var ps_buf: []const shader.BufBinding = &.{};
    const trace_glsl = (getenv("WINS_D3D11_TRACE_DRAWS") != null);
    if (trace_glsl) {
        const S = struct { var n: u32 = 0; };
        S.n += 1;
        if (S.n == 1 or (S.n >= 18 and S.n <= 21)) {
            std.debug.print("=== TRACE_GLSL VS#{d} ===\n{s}\n", .{ S.n, tv.glsl });
        }
    }
    if (ps) |p| {
        var tp = shader.translateWithVaryings(alloc, p.bytecode, tv.outputs) catch |e| {
            std.debug.print("[WINS:D3D11:GL] PS translate err={s} ({s})\n", .{ @errorName(e), shader.last_error });
            return .{};
        };
        if (trace_glsl) {
            const S = struct { var n: u32 = 0; };
            S.n += 1;
            if (S.n == 1 or (S.n >= 18 and S.n <= 21)) {
                std.debug.print("=== TRACE_GLSL PS#{d} (tex={d}) ===\n{s}\n", .{ S.n, tp.tex_bindings.len, tp.glsl });
            }
        }
        gl_ps = compileGlShader(0x8B30, tp.glsl, "PS");
        ps_tex = alloc.dupe(shader.TexBinding, tp.tex_bindings) catch &.{};
        ps_buf = alloc.dupe(shader.BufBinding, tp.buf_bindings) catch &.{};
        tp.deinit(alloc);
        if (gl_ps == 0) return .{};
    } else {
        // Minimal passthrough FS for depth-only rendering
        gl_ps = compileGlShader(0x8B30, "#version 420 core\nvoid main(){}\n", "DummyPS");
        if (gl_ps == 0) return .{};
    }
    defer gl.glDeleteShader(gl_ps);

    const prog = gl.glCreateProgram();
    gl.glAttachShader(prog, gl_vs);
    gl.glAttachShader(prog, gl_ps);
    gl.glLinkProgram(prog);
    var ok: GLint = 0;
    gl.glGetProgramiv(prog, 0x8B82, &ok);
    if (ok == 0) {
        var log_buf: [2048]u8 = undefined;
        var n: GLsizei = 0;
        gl.glGetProgramInfoLog(prog, log_buf.len, &n, &log_buf);
        std.debug.print("[WINS:D3D11:GL] link FAIL:\n{s}\n", .{log_buf[0..@intCast(@max(0, n))]});
        gl.glDeleteProgram(prog);
        return .{};
    }

    const vs_tex = alloc.dupe(shader.TexBinding, tv.tex_bindings) catch &.{};
    const vs_buf = alloc.dupe(shader.BufBinding, tv.buf_bindings) catch &.{};
    const res: LinkedProg = .{ .prog = prog, .ps_tex_bindings = ps_tex, .vs_tex_bindings = vs_tex, .ps_buf_bindings = ps_buf, .vs_buf_bindings = vs_buf };
    dumpProgram(prog, vs, ps, tv.glsl);
    g_progs.put(alloc, key, res) catch {};
    return res;
}

extern fn fopen(path: [*:0]const u8, mode: [*:0]const u8) ?*anyopaque;
extern fn fwrite(ptr: [*]const u8, size: usize, n: usize, f: *anyopaque) usize;
extern fn fclose(f: *anyopaque) c_int;

fn writeFileZ(path: [:0]const u8, data: []const u8) void {
    const f = fopen(path.ptr, "wb") orelse return;
    _ = fwrite(data.ptr, 1, data.len, f);
    _ = fclose(f);
}

pub fn dumpFile(dir: []const u8, prog: GLuint, suffix: []const u8, data: []const u8) void {
    var path_buf: [1024]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "{s}/p{d:0>4}_{s}", .{ dir, prog, suffix }) catch return;
    const f = fopen(path.ptr, "wb") orelse return;
    _ = fwrite(data.ptr, 1, data.len, f);
    _ = fclose(f);
}

/// WINS_D3D11_DUMP_DIR=<dir>: write each newly linked program's DXBC and GLSL
/// (p<prog>_{vs,ps}.{dxbc,glsl}) for offline inspection. Off by default.
fn dumpProgram(prog: GLuint, vs: *Shader, ps: ?*Shader, vs_glsl: []const u8) void {
    const dir_z = getenv("WINS_D3D11_DUMP_DIR") orelse return;
    const dir = std.mem.span(dir_z);
    dumpFile(dir, prog, "vs.dxbc", vs.bytecode);
    dumpFile(dir, prog, "vs.glsl", vs_glsl);
    const p = ps orelse return;
    dumpFile(dir, prog, "ps.dxbc", p.bytecode);
    var tv = shader.translateWithVaryings(alloc, vs.bytecode, null) catch return;
    defer tv.deinit(alloc);
    var tp = shader.translateWithVaryings(alloc, p.bytecode, tv.outputs) catch return;
    defer tp.deinit(alloc);
    dumpFile(dir, prog, "ps.glsl", tp.glsl);
}

fn cbVec(cb: ?*Buffer, off_regs: u32, reg: u32) [4]f32 {
    const b = cb orelse return .{ -1, -1, -1, -1 };
    const sh = b.shadow orelse return .{ -9, -9, -9, -9 };
    const at = (@as(usize, off_regs) + reg) * 16;
    if (at + 16 > sh.len) return .{ -7, -7, -7, -7 };
    var v: [4]f32 = undefined;
    @memcpy(std.mem.asBytes(&v), sh[at..][0..16]);
    return v;
}

/// WINS_D3D11_TRACE_PROG=<gl program ids, comma separated>: for the first 4 draws
/// of each listed program (and every 500th after) print its textures, depth
/// state, vertex layout and first vertices, and the constant registers named by
/// WINS_D3D11_TRACE_REGS="v0:22,v1:6,p0:26" (stage, slot, register). With
/// WINS_D3D11_DUMP_DIR set, A8 atlases are also read back as PGM. Off by default.
fn traceProgConstants(s: *const DrawState, prog: GLuint, fw: u32, fh: u32) void {
    const C = struct { var init = false; var env: ?[*:0]const u8 = null; };
    if (!C.init) {
        C.init = true;
        C.env = getenv("WINS_D3D11_TRACE_PROG");
    }
    const want_z = C.env orelse return;
    var wit = std.mem.tokenizeScalar(u8, std.mem.span(want_z), ',');
    const slot_idx: usize = blk: {
        var i: usize = 0;
        while (wit.next()) |w| : (i += 1) {
            if (i >= 8) return;
            if ((std.fmt.parseInt(GLuint, w, 10) catch continue) == prog) break :blk i;
        }
        return;
    };
    const S = struct { var n: [8]u32 = .{0} ** 8; };
    S.n[slot_idx] += 1;
    const n = S.n[slot_idx];
    if (n > 4 and n % 500 != 0) return;
    for (0..3) |i| {
        const v = s.ps_srv[i] orelse continue;
        const t = v.tex orelse continue;
        std.debug.print("[WINS:TRACEPROG]   ps_srv{d}: gl={d} {d}x{d} mips={d} tex_fmt={d} view_fmt={d} usage={d}\n", .{ i, t.gl_id, t.width, t.height, t.mip_levels, t.dxgi_fmt, v.dxgi_fmt, t.usage });
        // A8 atlases: read mip 0 back (red channel holds alpha) as a PGM.
        if (i == 0 and t.dxgi_fmt == 65 and t.target == 0x0DE1 and (n == 1 or n == 500)) {
            if (getenv("WINS_D3D11_DUMP_DIR")) |dz| {
                const px = alloc.alloc(u8, @as(usize, t.width) * t.height) catch continue;
                defer alloc.free(px);
                gl.glBindTexture(0x0DE1, t.gl_id);
                gl.glGetTexImage(0x0DE1, 0, 0x1903, 0x1401, px.ptr);
                gl.glBindTexture(0x0DE1, 0);
                var nz: usize = 0;
                for (px) |b| nz += @intFromBool(b != 0);
                std.debug.print("[WINS:TRACEPROG]   atlas gl={d}: {d}/{d} nonzero texels\n", .{ t.gl_id, nz, px.len });
                var hdr_buf: [64]u8 = undefined;
                const hdr = std.fmt.bufPrint(&hdr_buf, "P5\n{d} {d}\n255\n", .{ t.width, t.height }) catch continue;
                var name_buf: [64]u8 = undefined;
                const name = std.fmt.bufPrint(&name_buf, "atlas{d}_n{d}.pgm", .{ t.gl_id, n }) catch continue;
                const all = alloc.alloc(u8, hdr.len + px.len) catch continue;
                defer alloc.free(all);
                @memcpy(all[0..hdr.len], hdr);
                @memcpy(all[hdr.len..], px);
                dumpFile(std.mem.span(dz), prog, name, all);
            }
        }
    }
    if (s.depth_stencil) |d| std.debug.print("[WINS:TRACEPROG]   depth en={} write={} func=0x{x}\n", .{ d.depth_enable, d.depth_write, d.depth_func });
    if (s.input_layout) |il| {
        for (il.elems[0..il.count]) |el| {
            std.debug.print("[WINS:TRACEPROG]   attr loc={d} slot={d} off={d} comps={d} gltype=0x{x} norm={} int={}\n", .{ el.location, el.slot, el.offset, el.components, el.gl_type, el.normalized, el.is_int });
        }
    }
    if (s.vb[0]) |vb| if (vb.shadow) |sh| {
        const stride = s.vb_stride[0];
        const base = @as(usize, s.vb_offset[0]);
        std.debug.print("[WINS:TRACEPROG]   vb0 stride={d} off={d} size={d}:", .{ stride, base, sh.len });
        var k: usize = 0;
        while (k < stride and base + k + 4 <= sh.len) : (k += 4) {
            var f: f32 = undefined;
            @memcpy(std.mem.asBytes(&f), sh[base + k ..][0..4]);
            std.debug.print(" {d:.3}", .{f});
        }
        std.debug.print("\n", .{});
        // Per-vertex summary for UI-layout buffers: pos.xy, color, uv0, uv1.
        if (stride == 60) {
            var nz: usize = 0;
            var printed: usize = 0;
            var vi: usize = 0;
            while (base + (vi + 1) * stride <= sh.len) : (vi += 1) {
                const at = base + vi * stride;
                var f: [15]f32 = undefined;
                @memcpy(std.mem.asBytes(&f), sh[at..][0..60]);
                const col = std.mem.readInt(u32, sh[at + 24 ..][0..4], .little);
                if (f[9] != 0 or f[10] != 0) {
                    nz += 1;
                    if (printed < 6) {
                        printed += 1;
                        std.debug.print("[WINS:TRACEPROG]     v{d}: pos=({d:.1},{d:.1},{d:.1}) col=0x{x:0>8} uv0=({d:.4},{d:.4}) uv1=({d:.4},{d:.4})\n", .{ vi, f[0], f[1], f[2], col, f[7], f[8], f[9], f[10] });
                    }
                }
            }
            std.debug.print("[WINS:TRACEPROG]     {d}/{d} vertices with nonzero uv1\n", .{ nz, vi });
        }
    } else std.debug.print("[WINS:TRACEPROG]   vb0 has no CPU shadow\n", .{});
    const vp = if (s.num_viewports > 0) s.viewports[0] else std.mem.zeroes(@TypeOf(s.viewports[0]));
    std.debug.print("[WINS:TRACEPROG] prog={d} n={d} f={d} fb={d}x{d} vp=({d:.1},{d:.1},{d:.1},{d:.1}) stencil={} ref={d}\n", .{
        prog, n, g_present_count, fw, fh, vp.x, vp.y, vp.w, vp.h,
        if (s.depth_stencil) |d| d.stencil_enable else false, s.stencil_ref,
    });
    const regs_z = getenv("WINS_D3D11_TRACE_REGS") orelse return;
    var it = std.mem.tokenizeScalar(u8, std.mem.span(regs_z), ',');
    while (it.next()) |spec| {
        if (spec.len < 4 or spec[2] != ':') continue;
        const slot = std.fmt.parseInt(u32, spec[1..2], 10) catch continue;
        const reg = std.fmt.parseInt(u32, spec[3..], 10) catch continue;
        const v = if (spec[0] == 'v')
            cbVec(s.vs_cb[slot], s.vs_cb_off[slot], reg)
        else
            cbVec(s.ps_cb[slot], s.ps_cb_off[slot], reg);
        std.debug.print("    {s} = ({e:.4}, {e:.4}, {e:.4}, {e:.4})\n", .{ spec, v[0], v[1], v[2], v[3] });
    }
}

fn attachTextureView(att: GLenum, v: *View) void {
    const tex = v.tex orelse return;
    if (tex.target == 0x8C1A or tex.target == 0x806F or tex.target == 0x8C18) { // 2D_ARRAY / 3D / 1D_ARRAY
        gl.glFramebufferTextureLayer(0x8D40, att, tex.gl_id, @intCast(v.first_mip), @intCast(v.first_slice));
    } else if (tex.target == 0x8513) { // CUBE_MAP
        const face: GLenum = 0x8515 + @as(GLenum, @intCast(v.first_slice % 6));
        gl.glFramebufferTexture2D(0x8D40, att, face, tex.gl_id, @intCast(v.first_mip));
    } else {
        gl.glFramebufferTexture2D(0x8D40, att, 0x0DE1, tex.gl_id, @intCast(v.first_mip));
    }
}

fn bindFramebufferForState(s: *const DrawState) struct { w: u32, h: u32 } {
    var key: FboKey = .{
        .rtvs = [_]GLuint{0} ** 8,
        .rtv_mips = [_]u32{0} ** 8,
        .rtv_slices = [_]u32{0} ** 8,
        .num_rtvs = @min(8, s.num_rtvs),
        .dsv = if (s.dsv) |d| (if (d.tex) |t| t.gl_id else 0) else 0,
        .dsv_mip = if (s.dsv) |d| d.first_mip else 0,
        .dsv_slice = if (s.dsv) |d| d.first_slice else 0,
    };
    var rt_w: u32 = g_init_w;
    var rt_h: u32 = g_init_h;
    var any = (key.dsv != 0);
    if (s.dsv) |d| {
        if (d.tex) |t| {
            rt_w = @max(1, t.width >> @intCast(@min(31, d.first_mip)));
            rt_h = @max(1, t.height >> @intCast(@min(31, d.first_mip)));
        }
    }
    for (0..key.num_rtvs) |i| {
        if (s.rtv[i]) |rv| {
            if (rv.tex) |t| {
                key.rtvs[i] = t.gl_id;
                key.rtv_mips[i] = rv.first_mip;
                key.rtv_slices[i] = rv.first_slice;
                any = true;
                rt_w = @max(1, t.width >> @intCast(@min(31, rv.first_mip)));
                rt_h = @max(1, t.height >> @intCast(@min(31, rv.first_mip)));
            }
        }
    }
    if (!any) {
        gl.glBindFramebuffer(0x8D40, 0);
        return .{ .w = g_init_w, .h = g_init_h };
    }
    for (g_fbos.items) |e| {
        if (std.meta.eql(e.key, key)) {
            gl.glBindFramebuffer(0x8D40, e.fbo);
            return .{ .w = rt_w, .h = rt_h };
        }
    }

    var fbo: GLuint = 0;
    gl.glGenFramebuffers(1, &fbo);
    gl.glBindFramebuffer(0x8D40, fbo);
    var bufs: [8]GLenum = undefined;
    var db_count: GLsizei = 0;
    for (0..key.num_rtvs) |i| {
        if (s.rtv[i]) |rv| {
            if (rv.tex != null) {
                attachTextureView(0x8CE0 + @as(GLenum, @intCast(i)), rv);
                bufs[i] = 0x8CE0 + @as(GLenum, @intCast(i));
            } else {
                bufs[i] = 0;
            }
        } else {
            bufs[i] = 0;
        }
        db_count += 1;
    }
    if (db_count == 0) {
        const none_buf: GLenum = 0;
        gl.glDrawBuffers(1, (&none_buf)[0..1].ptr);
    } else {
        gl.glDrawBuffers(db_count, &bufs);
    }
    if (s.dsv) |dv| {
        if (dv.tex) |dt| {
            const gf = dxgiToGlFormat(if (dv.dxgi_fmt != 0) dv.dxgi_fmt else dt.dxgi_fmt);
            const att: GLenum = if (gf.is_stencil) 0x821A else 0x8D00;
            attachTextureView(att, dv);
        }
    }
    const status = gl.glCheckFramebufferStatus(0x8D40);
    if (status != 0x8CD5) {
        const rtv0_fmt: u32 = if (s.rtv[0]) |rv| (if (rv.tex) |t| t.dxgi_fmt else 0) else 0;
        const rtv0_id: u32 = key.rtvs[0];
        const dsv_fmt: u32 = if (s.dsv) |dv| (if (dv.tex) |t| t.dxgi_fmt else 0) else 0;
        const dsv_id: u32 = key.dsv;
        std.debug.print("[WINS:D3D11:GL] FBO incomplete status=0x{x} {d}x{d} nrtv={d} rtv0=(id={d},fmt={d}) dsv=(id={d},fmt={d})\n", .{
            status, rt_w, rt_h, key.num_rtvs, rtv0_id, rtv0_fmt, dsv_id, dsv_fmt,
        });
    }
    g_fbos.append(alloc, .{ .key = key, .fbo = fbo }) catch {};
    return .{ .w = rt_w, .h = rt_h };
}

// ---- Operations dispatched to Render Thread ---------------------------------

const SwapBufJob = struct { tex: *Texture, w: u32, h: u32, fmt: u32 };

fn allocTextureStorage2D(t: *Texture) void {
    const gf = dxgiToGlFormat(t.dxgi_fmt);
    gl.glBindTexture(0x0DE1, t.gl_id);
    gl.glTexParameteri(0x0DE1, 0x813D, @intCast(t.mip_levels - 1)); // GL_TEXTURE_MAX_LEVEL
    gl.glTexParameteri(0x0DE1, 0x2801, 0x2601); // LINEAR
    gl.glTexParameteri(0x0DE1, 0x2800, 0x2601);
    if (gf.is_a8) {
        gl.glTexParameteri(0x0DE1, 0x8E42, 0); // SWIZZLE_R = ZERO
        gl.glTexParameteri(0x0DE1, 0x8E43, 0); // SWIZZLE_G = ZERO
        gl.glTexParameteri(0x0DE1, 0x8E44, 0); // SWIZZLE_B = ZERO
        gl.glTexParameteri(0x0DE1, 0x8E45, 0x1903); // SWIZZLE_A = RED
    }
    var mw = t.width;
    var mh = t.height;
    for (0..t.mip_levels) |m| {
        if (gf.compressed) {
            const bw = @max(1, (mw + 3) / 4);
            const bh = @max(1, (mh + 3) / 4);
            gl.glCompressedTexImage2D(0x0DE1, @intCast(m), @intCast(gf.internal), @intCast(mw), @intCast(mh), 0, @intCast(bw * bh * gf.block_bytes), null);
        } else {
            gl.glTexImage2D(0x0DE1, @intCast(m), gf.internal, @intCast(mw), @intCast(mh), 0, gf.format, gf.ty, null);
        }
        mw = @max(1, mw >> 1);
        mh = @max(1, mh >> 1);
    }
    gl.glBindTexture(0x0DE1, 0);
}

fn createSwapchainBackbufferJob(raw: ?*anyopaque) void {
    const j: *SwapBufJob = @ptrCast(@alignCast(raw.?));
    j.tex.width = @max(1, j.w);
    j.tex.height = @max(1, j.h);
    j.tex.mip_levels = 1;
    j.tex.dxgi_fmt = j.fmt;
    j.tex.is_swapchain = true;
    gl.glGenTextures(1, &j.tex.gl_id);
    allocTextureStorage2D(j.tex);
}

pub fn createSwapchainBackbuffer(tex: *Texture, w: u32, h: u32, fmt: u32) void {
    var j: SwapBufJob = .{ .tex = tex, .w = w, .h = h, .fmt = fmt };
    run(&createSwapchainBackbufferJob, &j);
}

fn resizeSwapchainJob(raw: ?*anyopaque) void {
    const j: *SwapBufJob = @ptrCast(@alignCast(raw.?));
    j.tex.width = @max(1, j.w);
    j.tex.height = @max(1, j.h);
    allocTextureStorage2D(j.tex);
}

pub fn resizeSwapchainBackbuffer(tex: *Texture, w: u32, h: u32) void {
    var j: SwapBufJob = .{ .tex = tex, .w = w, .h = h, .fmt = tex.dxgi_fmt };
    run(&resizeSwapchainJob, &j);
}

const BufCreateJob = struct { b: *Buffer, init_data: ?[*]const u8 };

fn glTargetForBuffer(bind_flags: u32) GLenum {
    if ((bind_flags & 4) != 0) return 0x8A11; // GL_UNIFORM_BUFFER
    if ((bind_flags & 2) != 0) return 0x8893; // GL_ELEMENT_ARRAY_BUFFER
    return 0x8892; // GL_ARRAY_BUFFER
}

fn createBufferJob(raw: ?*anyopaque) void {
    const j: *BufCreateJob = @ptrCast(@alignCast(raw.?));
    const b = j.b;
    const target = glTargetForBuffer(b.bind_flags);
    gl.glGenBuffers(1, &b.gl_id);
    gl.glBindBuffer(target, b.gl_id);
    const gl_usage: GLenum = if (b.usage == 2) 0x88E8 else 0x88E4; // DYNAMIC_DRAW vs STATIC_DRAW
    gl.glBufferData(target, @intCast(b.size), if (j.init_data) |p| @ptrCast(p) else null, gl_usage);
    gl.glBindBuffer(target, 0);
}

pub fn createBuffer(b: *Buffer, initial: ?[*]const u8) void {
    b.shadow = alloc.alloc(u8, @max(1, b.size)) catch null;
    if (b.shadow) |sh| {
        if (initial) |p| @memcpy(sh[0..b.size], p[0..b.size]) else @memset(sh, 0);
    }
    var j: BufCreateJob = .{ .b = b, .init_data = initial };
    run(&createBufferJob, &j);
}

const BufUploadJob = struct { b: *Buffer, off: u32, data: [*]const u8, len: u32 };

fn uploadBufferJob(raw: ?*anyopaque) void {
    const j: *BufUploadJob = @ptrCast(@alignCast(raw.?));
    const b = j.b;
    if (b.gl_id == 0) return;
    const target = glTargetForBuffer(b.bind_flags);
    gl.glBindBuffer(target, b.gl_id);
    gl.glBufferSubData(target, @intCast(j.off), @intCast(j.len), @ptrCast(j.data));
    gl.glBindBuffer(target, 0);
}

pub fn uploadBuffer(b: *Buffer, offset: u32, data: [*]const u8, len: u32) void {
    if (b.shadow) |sh| {
        const end = @min(sh.len, @as(usize, offset) + len);
        if (offset < end and @intFromPtr(data) != @intFromPtr(sh.ptr + offset)) {
            @memcpy(sh[offset..end], data[0 .. end - offset]);
        }
    }
    var j: BufUploadJob = .{ .b = b, .off = offset, .data = data, .len = len };
    run(&uploadBufferJob, &j);
}

fn destroyBufferJob(raw: ?*anyopaque) void {
    const b: *Buffer = @ptrCast(@alignCast(raw.?));
    if (b.gl_id != 0) {
        gl.glDeleteBuffers(1, &b.gl_id);
        b.gl_id = 0;
    }
}

pub fn destroyBuffer(b: *Buffer) void {
    if (b.shadow) |sh| {
        alloc.free(sh);
        b.shadow = null;
    }
    run(&destroyBufferJob, b);
}

const TexCreateJob = struct {
    t: *Texture,
    init_ptrs: ?[*]const ?*const anyopaque,
    init_pitches: ?[*]const u32,
    init_slice_pitches: ?[*]const u32 = null,
};

/// Copy a (possibly padded) row/slice-pitched 3D block into a tightly packed
/// buffer so GL can take it without UNPACK_* state. `row_bytes` is the tight
/// row size and `rows` the rows per slice (block rows for compressed formats).
fn packSlices(src: [*]const u8, row_pitch: u32, slice_pitch: u32, row_bytes: u32, rows: u32, depth: u32) ?[]u8 {
    const tmp = alloc.alloc(u8, @as(usize, row_bytes) * rows * depth) catch return null;
    const rp: usize = if (row_pitch == 0) row_bytes else row_pitch;
    const sp: usize = if (slice_pitch == 0) rp * rows else slice_pitch;
    for (0..depth) |z| for (0..rows) |y| {
        @memcpy(tmp[(z * rows + y) * row_bytes ..][0..row_bytes], src[z * sp + y * rp ..][0..row_bytes]);
    };
    return tmp;
}

fn upload3DLevel(level: u32, w: u32, h: u32, d: u32, gf: GlTexFmt, ptr: ?*const anyopaque, pitch: u32, slice_pitch: u32) void {
    const bw = if (gf.compressed) @max(1, (w + 3) / 4) else w;
    const rows = if (gf.compressed) @max(1, (h + 3) / 4) else h;
    const row_bytes = if (gf.compressed) bw * gf.block_bytes else w * @max(1, gf.bpp);
    var packbuf: ?[]u8 = null;
    defer if (packbuf) |pk| alloc.free(pk);
    var data: ?*const anyopaque = ptr;
    if (ptr) |p| {
        const tight_rp = pitch == 0 or pitch == row_bytes;
        const tight_sp = slice_pitch == 0 or slice_pitch == row_bytes * rows;
        if (!(tight_rp and tight_sp)) {
            packbuf = packSlices(@ptrCast(p), pitch, slice_pitch, row_bytes, rows, d);
            data = if (packbuf) |pk| pk.ptr else null;
        }
    }
    if (gf.compressed) {
        gl.glCompressedTexImage3D(0x806F, @intCast(level), @intCast(gf.internal), @intCast(w), @intCast(h), @intCast(d), 0, @intCast(row_bytes * rows * d), data);
    } else {
        gl.glTexImage3D(0x806F, @intCast(level), gf.internal, @intCast(w), @intCast(h), @intCast(d), 0, gf.format, gf.ty, data);
    }
}

fn uploadMipSlice2D(target: GLenum, level: u32, w: u32, h: u32, gf: GlTexFmt, ptr: ?*const anyopaque, pitch: u32) void {
    if (gf.compressed) {
        const bw = @max(1, (w + 3) / 4);
        const bh = @max(1, (h + 3) / 4);
        const sz = bw * bh * gf.block_bytes;
        if (ptr) |p| {
            // Check if row stride matches tight packing
            const row_bytes = bw * gf.block_bytes;
            if (pitch == 0 or pitch == row_bytes or bh == 1) {
                gl.glCompressedTexImage2D(target, @intCast(level), @intCast(gf.internal), @intCast(w), @intCast(h), 0, @intCast(sz), p);
            } else {
                const tmp = alloc.alloc(u8, sz) catch return;
                defer alloc.free(tmp);
                const src: [*]const u8 = @ptrCast(p);
                for (0..bh) |ry| {
                    @memcpy(tmp[ry * row_bytes ..][0..row_bytes], src[ry * pitch ..][0..row_bytes]);
                }
                gl.glCompressedTexImage2D(target, @intCast(level), @intCast(gf.internal), @intCast(w), @intCast(h), 0, @intCast(sz), tmp.ptr);
            }
        } else {
            gl.glCompressedTexImage2D(target, @intCast(level), @intCast(gf.internal), @intCast(w), @intCast(h), 0, @intCast(sz), null);
        }
    } else {
        if (ptr != null and pitch > w * gf.bpp and gf.bpp > 0) {
            gl.glPixelStorei(0x0CF2, @intCast(pitch / gf.bpp)); // GL_UNPACK_ROW_LENGTH
        }
        gl.glTexImage2D(target, @intCast(level), gf.internal, @intCast(w), @intCast(h), 0, gf.format, gf.ty, ptr);
        if (ptr != null and pitch > w * gf.bpp and gf.bpp > 0) {
            gl.glPixelStorei(0x0CF2, 0);
        }
    }
}

/// WINS_D3D11_DUMP_TEX=<w>x<h> (+ WINS_D3D11_DUMP_DIR): writes the first 16
/// initialised 2D textures of that size (or min<N>: either side >= N; cap 160), mip 0 read back as RGBA8 (GL
/// decompresses BC*), to tex<gl>_<fmt>.ppm with alpha as tex<gl>_a.pgm.
fn dumpTex2D(t: *const Texture) void {
    const C = struct { var init = false; var w: u32 = 0; var h: u32 = 0; var n: u32 = 0; var min: u32 = 0; };
    if (!C.init) {
        C.init = true;
        if (getenv("WINS_D3D11_DUMP_TEX")) |z| {
            const zs = std.mem.span(z);
            if (std.mem.startsWith(u8, zs, "min")) { // min<N>: every texture with width or height >= N
                C.min = std.fmt.parseInt(u32, zs[3..], 10) catch 0;
            }
            var it = std.mem.tokenizeScalar(u8, zs, 'x');
            C.w = std.fmt.parseInt(u32, it.next() orelse "0", 10) catch 0;
            C.h = std.fmt.parseInt(u32, it.next() orelse "0", 10) catch 0;
        }
    }
    const hit = if (C.min != 0) (t.width >= C.min or t.height >= C.min) else (C.w != 0 and t.width == C.w and t.height == C.h);
    if (!hit or C.n >= 160) return;
    const dir = getenv("WINS_D3D11_DUMP_DIR") orelse return;
    C.n += 1;
    const npx = @as(usize, t.width) * t.height;
    const px = alloc.alloc(u8, npx * 4) catch return;
    defer alloc.free(px);
    gl.glPixelStorei(0x0D05, 1); // PACK_ALIGNMENT
    gl.glGetTexImage(0x0DE1, 0, 0x1908, 0x1401, px.ptr);
    const rgb = alloc.alloc(u8, npx * 3 + 32) catch return;
    defer alloc.free(rgb);
    const al = alloc.alloc(u8, npx + 32) catch return;
    defer alloc.free(al);
    var ha: [32]u8 = undefined;
    const h1 = std.fmt.bufPrint(&ha, "P6\n{d} {d}\n255\n", .{ t.width, t.height }) catch return;
    @memcpy(rgb[0..h1.len], h1);
    var hb: [32]u8 = undefined;
    const h2 = std.fmt.bufPrint(&hb, "P5\n{d} {d}\n255\n", .{ t.width, t.height }) catch return;
    @memcpy(al[0..h2.len], h2);
    var nz: usize = 0;
    for (0..npx) |i| {
        rgb[h1.len + i * 3 ..][0..3].* = px[i * 4 ..][0..3].*;
        al[h2.len + i] = px[i * 4 + 3];
        nz += @intFromBool(px[i * 4 + 3] != 0);
    }
    var nb: [256]u8 = undefined;
    const n1 = std.fmt.bufPrintZ(&nb, "{s}/tex{d}_{d}.ppm", .{ std.mem.span(dir), t.gl_id, t.dxgi_fmt }) catch return;
    writeFileZ(n1, rgb[0 .. h1.len + npx * 3]);
    const n2 = std.fmt.bufPrintZ(&nb, "{s}/tex{d}_a.pgm", .{ std.mem.span(dir), t.gl_id }) catch return;
    writeFileZ(n2, al[0 .. h2.len + npx]);
    std.debug.print("[WINS:D3D11:GL] dumped tex gl={d} {d}x{d} fmt={d} alpha_nonzero={d}/{d}\n", .{ t.gl_id, t.width, t.height, t.dxgi_fmt, nz, npx });
}

fn createTexture2DJob(raw: ?*anyopaque) void {
    const j: *TexCreateJob = @ptrCast(@alignCast(raw.?));
    const t = j.t;
    const gf = dxgiToGlFormat(t.dxgi_fmt);
    t.is_depth = gf.is_depth;
    t.is_compressed = gf.compressed;
    t.target = switch (t.target) {
        // Always a 1D array: D3D binds a 1-slice Texture1D through Texture1DArray
        // SRVs too, and GL samplers are typed by target.
        0x0DE0, 0x8C18 => 0x8C18,
        0x806F => 0x806F, // TEXTURE_3D
        else => if (t.array_size >= 6 and (t.target == 0x8513)) 0x8513 else if (t.array_size > 1) 0x8C1A else 0x0DE1,
    };

    gl.glGenTextures(1, &t.gl_id);
    gl.glBindTexture(t.target, t.gl_id);
    gl.glTexParameteri(t.target, 0x813D, @intCast(@max(1, t.mip_levels) - 1));
    gl.glTexParameteri(t.target, 0x2801, if (t.mip_levels > 1) @as(GLint, 0x2703) else @as(GLint, 0x2601));
    gl.glTexParameteri(t.target, 0x2800, 0x2601);
    if (gf.is_a8) {
        gl.glTexParameteri(t.target, 0x8E42, 0);
        gl.glTexParameteri(t.target, 0x8E43, 0);
        gl.glTexParameteri(t.target, 0x8E44, 0);
        gl.glTexParameteri(t.target, 0x8E45, 0x1903);
    }

    if (t.target == 0x0DE0) { // TEXTURE_1D (D3D has no compressed 1D formats)
        var mw = t.width;
        for (0..t.mip_levels) |m| {
            const p = if (j.init_ptrs) |ps| ps[m] else null;
            gl.glTexImage1D(0x0DE0, @intCast(m), gf.internal, @intCast(mw), 0, gf.format, gf.ty, p);
            mw = @max(1, mw >> 1);
        }
    } else if (t.target == 0x8C18) { // TEXTURE_1D_ARRAY: GL stores it as w x layers
        var mw = t.width;
        for (0..t.mip_levels) |m| {
            gl.glTexImage2D(0x8C18, @intCast(m), gf.internal, @intCast(mw), @intCast(t.array_size), 0, gf.format, gf.ty, null);
            if (j.init_ptrs) |ps| {
                for (0..t.array_size) |sl| {
                    if (ps[sl * t.mip_levels + m]) |p| gl.glTexSubImage2D(0x8C18, @intCast(m), 0, @intCast(sl), @intCast(mw), 1, gf.format, gf.ty, p);
                }
            }
            mw = @max(1, mw >> 1);
        }
    } else if (t.target == 0x806F) { // TEXTURE_3D
        var mw = t.width;
        var mh = t.height;
        var md = t.depth;
        for (0..t.mip_levels) |m| {
            const p = if (j.init_ptrs) |ps| ps[m] else null;
            const pitch = if (j.init_pitches) |pits| pits[m] else 0;
            const spitch = if (j.init_slice_pitches) |sps| sps[m] else 0;
            upload3DLevel(@intCast(m), mw, mh, md, gf, p, pitch, spitch);
            mw = @max(1, mw >> 1);
            mh = @max(1, mh >> 1);
            md = @max(1, md >> 1);
        }
    } else if (t.target == 0x0DE1) {
        var mw = t.width;
        var mh = t.height;
        for (0..t.mip_levels) |m| {
            const p = if (j.init_ptrs) |ps| ps[m] else null;
            const pitch = if (j.init_pitches) |pits| pits[m] else 0;
            uploadMipSlice2D(0x0DE1, @intCast(m), mw, mh, gf, p, pitch);
            mw = @max(1, mw >> 1);
            mh = @max(1, mh >> 1);
        }
        if (j.init_ptrs != null) dumpTex2D(t);
    } else if (t.target == 0x8513) { // Cubemap
        for (0..6) |face| {
            var mw = t.width;
            var mh = t.height;
            for (0..t.mip_levels) |m| {
                const idx = face * t.mip_levels + m;
                const p = if (j.init_ptrs) |ps| ps[idx] else null;
                const pitch = if (j.init_pitches) |pits| pits[idx] else 0;
                uploadMipSlice2D(0x8515 + @as(GLenum, @intCast(face)), @intCast(m), mw, mh, gf, p, pitch);
                mw = @max(1, mw >> 1);
                mh = @max(1, mh >> 1);
            }
        }
    } else { // TEXTURE_2D_ARRAY
        var mw = t.width;
        var mh = t.height;
        for (0..t.mip_levels) |m| {
            gl.glTexImage3D(0x8C1A, @intCast(m), gf.internal, @intCast(mw), @intCast(mh), @intCast(t.array_size), 0, gf.format, gf.ty, null);
            if (j.init_ptrs) |ps| {
                for (0..t.array_size) |sl| {
                    const idx = sl * t.mip_levels + m;
                    if (ps[idx]) |p| {
                        const pitch = if (j.init_pitches) |pits| pits[idx] else 0;
                        if (pitch > mw * gf.bpp and gf.bpp > 0) gl.glPixelStorei(0x0CF2, @intCast(pitch / gf.bpp));
                        gl.glTexSubImage3D(0x8C1A, @intCast(m), 0, 0, @intCast(sl), @intCast(mw), @intCast(mh), 1, gf.format, gf.ty, p);
                        gl.glPixelStorei(0x0CF2, 0);
                    }
                }
            }
            mw = @max(1, mw >> 1);
            mh = @max(1, mh >> 1);
        }
    }
    gl.glBindTexture(t.target, 0);
}

pub fn createTexture2D(t: *Texture, init_ptrs: ?[*]const ?*const anyopaque, init_pitches: ?[*]const u32) void {
    createTexture(t, init_ptrs, init_pitches, null);
}

/// Create a 1D/2D/3D/cube texture; `t.target` picks the kind (TEXTURE_1D,
/// TEXTURE_3D, CUBE_MAP; anything else is 2D/2D-array by `array_size`).
pub fn createTexture(t: *Texture, init_ptrs: ?[*]const ?*const anyopaque, init_pitches: ?[*]const u32, init_slice_pitches: ?[*]const u32) void {
    t.width = @max(1, t.width);
    t.height = @max(1, t.height);
    t.depth = @max(1, t.depth);
    if (t.mip_levels == 0) {
        t.mip_levels = 1 + @max(std.math.log2_int(u32, t.width), std.math.log2_int(u32, t.height), std.math.log2_int(u32, t.depth));
    }
    // Allocate staging shadow buffer when CPU read/write is requested
    if (t.usage == 3 or (t.cpu_access & 0x30000) != 0) {
        const gf = dxgiToGlFormat(t.dxgi_fmt);
        const pitch = if (gf.compressed) @max(1, (t.width + 3) / 4) * gf.block_bytes else t.width * @max(1, gf.bpp);
        const rows = if (gf.compressed) @max(1, (t.height + 3) / 4) else t.height;
        t.row_pitch = pitch;
        t.shadow = alloc.alloc(u8, @max(1, pitch * rows * t.depth)) catch null;
        if (t.shadow) |sh| {
            @memset(sh, 0);
            if (init_ptrs) |ps| {
                if (ps[0]) |p| {
                    const src: [*]const u8 = @ptrCast(p);
                    const sp = if (init_pitches) |pits| pits[0] else pitch;
                    const copy_row = @min(pitch, sp);
                    const ssp: usize = if (init_slice_pitches) |sps| (if (sps[0] != 0) sps[0] else sp * rows) else sp * rows;
                    for (0..t.depth) |z| for (0..rows) |r| {
                        @memcpy(sh[(z * rows + r) * pitch ..][0..copy_row], src[z * ssp + r * sp ..][0..copy_row]);
                    };
                }
            }
        }
        if (t.usage == 3) return; // D3D11_USAGE_STAGING needs no GL texture
    }
    var j: TexCreateJob = .{ .t = t, .init_ptrs = init_ptrs, .init_pitches = init_pitches, .init_slice_pitches = init_slice_pitches };
    run(&createTexture2DJob, &j);
}

fn destroyTextureJob(raw: ?*anyopaque) void {
    const t: *Texture = @ptrCast(@alignCast(raw.?));
    if (t.gl_id != 0) {
        gl.glDeleteTextures(1, &t.gl_id);
        t.gl_id = 0;
    }
}

pub fn destroyTexture(t: *Texture) void {
    if (t.shadow) |sh| {
        alloc.free(sh);
        t.shadow = null;
    }
    run(&destroyTextureJob, t);
}

const TexUpdateJob = struct {
    t: *Texture,
    sub: u32,
    has_box: bool,
    bx: [6]u32,
    data: [*]const u8,
    row_pitch: u32,
    depth_pitch: u32 = 0,
};

fn updateSubresourceTextureJob(raw: ?*anyopaque) void {
    const j: *TexUpdateJob = @ptrCast(@alignCast(raw.?));
    const t = j.t;
    if (t.gl_id == 0) return;
    const mips = @max(1, t.mip_levels);
    const mip = j.sub % mips;
    const slice = j.sub / mips;
    const mw = @max(1, t.width >> @intCast(@min(31, mip)));
    const mh = @max(1, t.height >> @intCast(@min(31, mip)));
    const x0: u32 = if (j.has_box) j.bx[0] else 0;
    const y0: u32 = if (j.has_box) j.bx[1] else 0;
    const w: u32 = if (j.has_box) @max(1, j.bx[3] -| j.bx[0]) else mw;
    const h: u32 = if (j.has_box) @max(1, j.bx[4] -| j.bx[1]) else mh;
    const gf = dxgiToGlFormat(t.dxgi_fmt);

    if (t.target == 0x0DE0 or t.target == 0x8C18 or t.target == 0x806F) {
        updateSubresource1D3D(j, mip, slice, x0, y0, w, h, gf);
        return;
    }
    gl.glBindTexture(t.target, t.gl_id);
    const gl_t: GLenum = if (t.target == 0x8513) 0x8515 + @as(GLenum, @intCast(slice % 6)) else t.target;
    if (gf.compressed) {
        const bw = @max(1, (w + 3) / 4);
        const bh = @max(1, (h + 3) / 4);
        const row_bytes = bw * gf.block_bytes;
        const sz = bh * row_bytes;
        if (j.row_pitch == 0 or j.row_pitch == row_bytes or bh == 1) {
            gl.glCompressedTexSubImage2D(gl_t, @intCast(mip), @intCast(x0), @intCast(y0), @intCast(w), @intCast(h), @intCast(gf.internal), @intCast(sz), @ptrCast(j.data));
        } else {
            const tmp = alloc.alloc(u8, sz) catch return;
            defer alloc.free(tmp);
            for (0..bh) |ry| @memcpy(tmp[ry * row_bytes ..][0..row_bytes], j.data[ry * j.row_pitch ..][0..row_bytes]);
            gl.glCompressedTexSubImage2D(gl_t, @intCast(mip), @intCast(x0), @intCast(y0), @intCast(w), @intCast(h), @intCast(gf.internal), @intCast(sz), tmp.ptr);
        }
    } else {
        if (j.row_pitch > w * gf.bpp and gf.bpp > 0) gl.glPixelStorei(0x0CF2, @intCast(j.row_pitch / gf.bpp));
        if (t.target == 0x8C1A) {
            gl.glTexSubImage3D(0x8C1A, @intCast(mip), @intCast(x0), @intCast(y0), @intCast(slice), @intCast(w), @intCast(h), 1, gf.format, gf.ty, @ptrCast(j.data));
        } else {
            gl.glTexSubImage2D(gl_t, @intCast(mip), @intCast(x0), @intCast(y0), @intCast(w), @intCast(h), gf.format, gf.ty, @ptrCast(j.data));
        }
        gl.glPixelStorei(0x0CF2, 0);
    }
    gl.glBindTexture(t.target, 0);
}

fn updateSubresource1D3D(j: *TexUpdateJob, mip: u32, slice: u32, x0: u32, y0: u32, w: u32, h: u32, gf: GlTexFmt) void {
    const t = j.t;
    gl.glBindTexture(t.target, t.gl_id);
    defer gl.glBindTexture(t.target, 0);
    switch (t.target) {
        0x0DE0 => gl.glTexSubImage1D(0x0DE0, @intCast(mip), @intCast(x0), @intCast(w), gf.format, gf.ty, @ptrCast(j.data)),
        0x8C18 => gl.glTexSubImage2D(0x8C18, @intCast(mip), @intCast(x0), @intCast(slice), @intCast(w), 1, gf.format, gf.ty, @ptrCast(j.data)),
        else => { // TEXTURE_3D: the box's front/back pick the depth range
            const md = @max(1, t.depth >> @intCast(@min(31, mip)));
            const z0: u32 = if (j.has_box) j.bx[2] else 0;
            const d: u32 = if (j.has_box) @max(1, j.bx[5] -| j.bx[2]) else md;
            const bw = if (gf.compressed) @max(1, (w + 3) / 4) else w;
            const rows = if (gf.compressed) @max(1, (h + 3) / 4) else h;
            const row_bytes = if (gf.compressed) bw * gf.block_bytes else w * @max(1, gf.bpp);
            const packbuf = packSlices(j.data, j.row_pitch, j.depth_pitch, row_bytes, rows, d) orelse return;
            defer alloc.free(packbuf);
            if (gf.compressed) {
                gl.glCompressedTexSubImage3D(0x806F, @intCast(mip), @intCast(x0), @intCast(y0), @intCast(z0), @intCast(w), @intCast(h), @intCast(d), @intCast(gf.internal), @intCast(packbuf.len), packbuf.ptr);
            } else {
                gl.glTexSubImage3D(0x806F, @intCast(mip), @intCast(x0), @intCast(y0), @intCast(z0), @intCast(w), @intCast(h), @intCast(d), gf.format, gf.ty, packbuf.ptr);
            }
        },
    }
}

pub fn updateSubresourceTexture(t: *Texture, sub: u32, has_box: bool, bx: [6]u32, data: [*]const u8, row_pitch: u32, depth_pitch: u32) void {
    var j: TexUpdateJob = .{ .t = t, .sub = sub, .has_box = has_box, .bx = bx, .data = data, .row_pitch = row_pitch, .depth_pitch = depth_pitch };
    run(&updateSubresourceTextureJob, &j);
}

const SampJob = struct {
    s: *Sampler,
    filter: u32,
    addr_u: u32,
    addr_v: u32,
    addr_w: u32,
    mip_bias: f32,
    max_aniso: u32,
    cmp_func: u32,
    border: [4]f32,
    min_lod: f32,
    max_lod: f32,
};

fn texWrap(addr: u32) GLint {
    return switch (addr) {
        1 => 0x2901, // REPEAT (WRAP)
        2 => 0x8370, // MIRRORED_REPEAT
        3 => 0x812F, // CLAMP_TO_EDGE
        4 => 0x812D, // CLAMP_TO_BORDER
        5 => 0x8743, // MIRROR_CLAMP_TO_EDGE
        else => 0x812F,
    };
}

fn createSamplerJob(raw: ?*anyopaque) void {
    const j: *SampJob = @ptrCast(@alignCast(raw.?));
    const s = j.s;
    gl.glGenSamplers(1, &s.gl_id);
    const point_min = (j.filter & 0x10) == 0;
    const point_mag = (j.filter & 0x04) == 0;
    const point_mip = (j.filter & 0x01) == 0;
    const min_f: GLint = if (point_min) (if (point_mip) 0x2700 else 0x2702) else (if (point_mip) 0x2701 else 0x2703);
    const mag_f: GLint = if (point_mag) 0x2600 else 0x2601;
    gl.glSamplerParameteri(s.gl_id, 0x2801, min_f);
    gl.glSamplerParameteri(s.gl_id, 0x2800, mag_f);
    gl.glSamplerParameteri(s.gl_id, 0x2802, texWrap(j.addr_u));
    gl.glSamplerParameteri(s.gl_id, 0x2803, texWrap(j.addr_v));
    gl.glSamplerParameteri(s.gl_id, 0x8072, texWrap(j.addr_w));
    gl.glSamplerParameterf(s.gl_id, 0x8501, j.mip_bias);
    gl.glSamplerParameterf(s.gl_id, 0x813A, j.min_lod);
    gl.glSamplerParameterf(s.gl_id, 0x813B, j.max_lod);
    gl.glSamplerParameterfv(s.gl_id, 0x1004, &j.border);
    if ((j.filter & 0x80) != 0) { // COMPARISON bit
        gl.glSamplerParameteri(s.gl_id, 0x884C, 0x884E); // COMPARE_REF_TO_TEXTURE
        gl.glSamplerParameteri(s.gl_id, 0x884D, if (j.cmp_func >= 1 and j.cmp_func <= 8) @intCast(0x0200 + (j.cmp_func - 1)) else 0x0203);
    }
    if ((j.filter & 0x40) != 0 and j.max_aniso > 1) {
        gl.glSamplerParameterf(s.gl_id, 0x84FE, @floatFromInt(@min(16, j.max_aniso)));
    }
}

pub fn createSampler(s: *Sampler, filter: u32, addr_u: u32, addr_v: u32, addr_w: u32, mip_bias: f32, max_aniso: u32, cmp_func: u32, border: [4]f32, min_lod: f32, max_lod: f32) void {
    var j: SampJob = .{
        .s = s, .filter = filter, .addr_u = addr_u, .addr_v = addr_v, .addr_w = addr_w,
        .mip_bias = mip_bias, .max_aniso = max_aniso, .cmp_func = cmp_func,
        .border = border, .min_lod = min_lod, .max_lod = max_lod,
    };
    run(&createSamplerJob, &j);
}

fn destroySamplerJob(raw: ?*anyopaque) void {
    const s: *Sampler = @ptrCast(@alignCast(raw.?));
    if (s.gl_id != 0) {
        gl.glDeleteSamplers(1, &s.gl_id);
        s.gl_id = 0;
    }
}

pub fn destroySampler(s: *Sampler) void {
    run(&destroySamplerJob, s);
}

pub fn createShader(sh: *Shader, bytes: []const u8, is_pixel: bool) bool {
    sh.is_pixel = is_pixel;
    sh.uid = g_shader_uid.fetchAdd(1, .monotonic) + 1;
    sh.bytecode = alloc.dupe(u8, bytes) catch return false;
    {
        // Rare progress line: titles that stream thousands of shaders at boot.
        const S = struct { var n = std.atomic.Value(u32).init(0); };
        const n = S.n.fetchAdd(1, .monotonic) + 1;
        if (n % 1000 == 0) std.debug.print("[WINS:D3D11:GL] {d} shaders created (present #{d})\n", .{ n, g_present_count });
    }
    var tr = shader.translate(alloc, sh.bytecode) catch |e| {
        var h0: u32 = 0;
        var h1: u32 = 0;
        var h7: u32 = 0;
        if (bytes.len >= 32) {
            h0 = std.mem.readInt(u32, bytes[0..4], .little);
            h1 = std.mem.readInt(u32, bytes[24..28], .little);
            h7 = std.mem.readInt(u32, bytes[28..32], .little);
        }
        std.debug.print("[WINS:D3D11:GL] DXBC parse err={s} ({s}) ps={} len={d} h0=0x{x} sz={d} nch={d}\n", .{
            @errorName(e), shader.last_error, is_pixel, bytes.len, h0, h1, h7,
        });
        return false;
    };
    sh.inputs = alloc.dupe(shader.SigElem, tr.inputs) catch &.{};
    sh.outputs = alloc.dupe(shader.SigElem, tr.outputs) catch &.{};
    tr.deinit(alloc);
    return true;
}

pub fn destroyShader(sh: *Shader) void {
    if (sh.bytecode.len > 0) alloc.free(sh.bytecode);
    if (sh.inputs.len > 0) alloc.free(sh.inputs);
    if (sh.outputs.len > 0) alloc.free(sh.outputs);
    sh.bytecode = &.{};
    sh.inputs = &.{};
    sh.outputs = &.{};
}

// ---- Clear / Copy / GenerateMips --------------------------------------------

const ClearRtvJob = struct { rtv: *View, rgba: [4]f32 };

fn clearRtvJob(raw: ?*anyopaque) void {
    const j: *ClearRtvJob = @ptrCast(@alignCast(raw.?));
    var tmp: DrawState = .{};
    tmp.rtv[0] = j.rtv;
    tmp.num_rtvs = 1;
    _ = bindFramebufferForState(&tmp);
    gl.glColorMaski(0, 1, 1, 1, 1);
    gl.glDisable(0x0C11); // SCISSOR_TEST
    gl.glClearBufferfv(0x1800, 0, &j.rgba); // GL_COLOR
    if (getenv("WINS_D3D11_TRACE_DRAWS") != null and g_present_count < 6) {
        const t = j.rtv.tex;
        std.debug.print("[WINS:D3D11:GL] clearRtv frame={d} rtv_gl={d} sw={} {d}x{d} rgba=({d:.3},{d:.3},{d:.3},{d:.3})\n", .{
            g_present_count, if (t) |x| x.gl_id else 0, if (t) |x| x.is_swapchain else false,
            if (t) |x| x.width else 0, if (t) |x| x.height else 0, j.rgba[0], j.rgba[1], j.rgba[2], j.rgba[3],
        });
    }
}

pub fn clearRtv(rtv: *View, rgba: [4]f32) void {
    var j: ClearRtvJob = .{ .rtv = rtv, .rgba = rgba };
    run(&clearRtvJob, &j);
}

const ClearDsvJob = struct { dsv: *View, flags: u32, depth: f32, stencil: u8 };

fn clearDsvJob(raw: ?*anyopaque) void {
    const j: *ClearDsvJob = @ptrCast(@alignCast(raw.?));
    var tmp: DrawState = .{};
    tmp.dsv = j.dsv;
    _ = bindFramebufferForState(&tmp);
    gl.glDisable(0x0C11);
    const has_d = (j.flags & 1) != 0;
    const has_s = (j.flags & 2) != 0;
    if (has_d) gl.glDepthMask(1);
    if (has_s) gl.glStencilMask(0xFF);
    if (has_d and has_s) {
        gl.glClearBufferfi(0x84F9, 0, j.depth, @intCast(j.stencil));
    } else if (has_d) {
        gl.glClearBufferfv(0x1801, 0, (&j.depth)[0..1].ptr);
    } else if (has_s) {
        gl.glClearStencil(@intCast(j.stencil));
        gl.glClear(0x0400);
    }
}

pub fn clearDsv(dsv: *View, flags: u32, depth: f32, stencil: u8) void {
    var j: ClearDsvJob = .{ .dsv = dsv, .flags = flags, .depth = depth, .stencil = stencil };
    run(&clearDsvJob, &j);
}

const ClearUavJob = struct { uav: *View, vals: [4]u32, is_float: bool };

fn clearUavJob(raw: ?*anyopaque) void {
    const j: *ClearUavJob = @ptrCast(@alignCast(raw.?));
    const v = j.uav;
    const is_zero = (j.vals[0] == 0 and j.vals[1] == 0 and j.vals[2] == 0 and j.vals[3] == 0);
    if (v.buf) |b| {
        if (b.gl_id == 0 or b.size == 0) return;
        const off: usize = @min(v.buf_off, b.size);
        const len: usize = if (v.buf_size > 0) @min(v.buf_size, b.size - @as(u32, @intCast(off))) else (b.size - @as(u32, @intCast(off)));
        if (len == 0) return;
        if (b.shadow) |sh| {
            const slice = sh[off .. off + len];
            if (is_zero) {
                @memset(slice, 0);
            } else {
                var k: usize = 0;
                while (k + 4 <= slice.len) : (k += 4) {
                    std.mem.writeInt(u32, slice[k..][0..4], j.vals[0], .little);
                }
            }
            const target = glTargetForBuffer(b.bind_flags);
            gl.glBindBuffer(target, b.gl_id);
            gl.glBufferSubData(target, @intCast(off), @intCast(len), slice.ptr);
            gl.glBindBuffer(target, 0);
        }
    } else if (v.tex) |t| {
        if (t.gl_id == 0) return;
        if (p_clear_tex_image) |cti| {
            const gf = dxgiToGlFormat(t.dxgi_fmt);
            if (!gf.compressed) {
                if (is_zero) {
                    cti(t.gl_id, @intCast(v.first_mip), gf.format, gf.ty, null);
                } else {
                    const ty: GLenum = if (j.is_float) 0x1406 else gf.ty;
                    cti(t.gl_id, @intCast(v.first_mip), gf.format, ty, @ptrCast(&j.vals));
                }
            }
        }
    }
}

pub fn clearUav(uav: *View, vals: [4]u32, is_float: bool) void {
    var j: ClearUavJob = .{ .uav = uav, .vals = vals, .is_float = is_float };
    run(&clearUavJob, &j);
}

const CopyJob = struct {
    dst: *Texture,
    dst_sub: u32,
    dx: u32,
    dy: u32,
    dz: u32,
    src: *Texture,
    src_sub: u32,
    has_box: bool,
    bx: [6]u32,
};

fn readbackTextureToShadow(src: *Texture, mip: u32) void {
    const sh = src.shadow orelse return;
    if (src.gl_id == 0) return;
    const gf = dxgiToGlFormat(src.dxgi_fmt);
    if (gf.compressed or gf.is_depth) return;
    gl.glBindFramebuffer(0x8CA8, g_copy_fbo_read);
    gl.glFramebufferTexture2D(0x8CA8, 0x8CE0, 0x0DE1, src.gl_id, @intCast(mip));
    gl.glReadPixels(0, 0, @intCast(src.width), @intCast(src.height), gf.format, gf.ty, sh.ptr);
    gl.glBindFramebuffer(0x8CA8, 0);
}

/// Copy the (boxed) region of a staging texture's CPU shadow into subresource
/// (dmip, dslice) of a GPU texture at (dx, dy, dz). Runs on the GL thread.
/// Where a staging copy reads from the CPU shadow. `first` is the byte offset of
/// the region's first row (in block rows for compressed formats), `rows` how many
/// (block) rows to read, `row_bytes` the bytes per row actually copied, and
/// `w`/`h` the region size in texels.
pub const StagingRegion = struct { first: usize, rows: usize, row_bytes: usize, w: u32, h: u32 };

/// Compute the source region of a CPU-staging -> GPU copy. `elem_bytes` is the
/// bytes per texel (uncompressed) or per 4x4 block (compressed). Returns null when
/// the region is empty or would read outside the shadow.
pub fn stagingRegion(src_w: u32, src_h: u32, pitch: usize, shadow_len: usize, compressed: bool, elem_bytes: usize, has_box: bool, bx: [6]u32) ?StagingRegion {
    if (pitch == 0 or elem_bytes == 0) return null;
    const sx: u32 = if (has_box) @min(bx[0], src_w) else 0;
    const sy: u32 = if (has_box) @min(bx[1], src_h) else 0;
    const ex: u32 = if (has_box) @min(bx[3], src_w) else src_w;
    const ey: u32 = if (has_box) @min(bx[4], src_h) else src_h;
    if (ex <= sx or ey <= sy) return null;
    const w = ex - sx;
    const h = ey - sy;
    const r: StagingRegion = if (compressed) .{
        .first = @as(usize, sy / 4) * pitch + @as(usize, sx / 4) * elem_bytes,
        .rows = (h + 3) / 4,
        .row_bytes = @as(usize, (w + 3) / 4) * elem_bytes,
        .w = w,
        .h = h,
    } else .{
        .first = @as(usize, sy) * pitch + @as(usize, sx) * elem_bytes,
        .rows = h,
        .row_bytes = @as(usize, w) * elem_bytes,
        .w = w,
        .h = h,
    };
    if (!compressed and pitch % elem_bytes != 0) return null;
    if (r.first + (r.rows - 1) * pitch + r.row_bytes > shadow_len) return null;
    return r;
}

fn uploadFromStaging(j: *const CopyJob, shadow: []const u8, dmip: u32, dslice: u32) void {
    const src = j.src;
    const dst = j.dst;
    const gf = dxgiToGlFormat(dst.dxgi_fmt);
    if (gf.is_depth) return;
    if (gf.compressed and dst.target == 0x8C1A) return; // compressed array uploads: no observed caller
    const elem: usize = if (gf.compressed) gf.block_bytes else @max(1, gf.bpp);
    const pitch: usize = src.row_pitch;
    const r = stagingRegion(src.width, src.height, pitch, shadow.len, gf.compressed, elem, j.has_box, j.bx) orelse return;

    const face_target: GLenum = if (dst.target == 0x8513) 0x8515 + @as(GLenum, @intCast(dslice % 6)) else dst.target;
    gl.glBindTexture(dst.target, dst.gl_id);
    defer gl.glBindTexture(dst.target, 0);

    if (gf.compressed) {
        const tmp = alloc.alloc(u8, r.row_bytes * r.rows) catch return;
        defer alloc.free(tmp);
        for (0..r.rows) |i| @memcpy(tmp[i * r.row_bytes ..][0..r.row_bytes], shadow[r.first + i * pitch ..][0..r.row_bytes]);
        gl.glCompressedTexSubImage2D(face_target, @intCast(dmip), @intCast(j.dx), @intCast(j.dy), @intCast(r.w), @intCast(r.h), @intCast(gf.internal), @intCast(tmp.len), tmp.ptr);
        return;
    }

    gl.glPixelStorei(0x0CF2, @intCast(pitch / elem)); // GL_UNPACK_ROW_LENGTH
    defer gl.glPixelStorei(0x0CF2, 0);
    const ptr: *const anyopaque = @ptrCast(shadow[r.first..].ptr);
    if (dst.target == 0x8C1A) {
        gl.glTexSubImage3D(0x8C1A, @intCast(dmip), @intCast(j.dx), @intCast(j.dy), @intCast(dslice + j.dz), @intCast(r.w), @intCast(r.h), 1, gf.format, gf.ty, ptr);
    } else {
        gl.glTexSubImage2D(face_target, @intCast(dmip), @intCast(j.dx), @intCast(j.dy), @intCast(r.w), @intCast(r.h), gf.format, gf.ty, ptr);
    }
}

fn copyTexJob(raw: ?*anyopaque) void {
    const j: *CopyJob = @ptrCast(@alignCast(raw.?));
    const smips = @max(1, j.src.mip_levels);
    const dmips = @max(1, j.dst.mip_levels);
    const smip = j.src_sub % smips;
    const sslice = j.src_sub / smips;
    const dmip = j.dst_sub % dmips;
    const dslice = j.dst_sub / dmips;

    if (j.dst.usage == 3 and j.src.gl_id != 0 and j.dst.shadow != null) {
        // GPU -> CPU staging readback!
        j.dst.shadow = j.dst.shadow;
        if (j.dst.shadow) |sh| {
            const gf = dxgiToGlFormat(j.src.dxgi_fmt);
            if (!gf.compressed and !gf.is_depth) {
                gl.glBindFramebuffer(0x8CA8, g_copy_fbo_read);
                gl.glFramebufferTexture2D(0x8CA8, 0x8CE0, 0x0DE1, j.src.gl_id, @intCast(smip));
                gl.glReadPixels(0, 0, @intCast(j.src.width), @intCast(j.src.height), gf.format, gf.ty, sh.ptr);
                gl.glBindFramebuffer(0x8CA8, 0);
            }
        }
        return;
    }

    // CPU staging -> GPU upload. Unity fills a STAGING texture through Map and
    // then copies it into the DEFAULT texture (font atlases, runtime textures).
    // A staging texture has no GL object, only its CPU shadow (mip 0, slice 0).
    if (j.src.gl_id == 0 and j.dst.gl_id != 0) {
        if (j.src.shadow) |shadow| {
            if (j.src_sub == 0) uploadFromStaging(j, shadow, dmip, dslice);
        }
        return;
    }

    if (j.src.gl_id == 0 or j.dst.gl_id == 0) return;
    const sw = @max(1, j.src.width >> @intCast(@min(31, smip)));
    const sh = @max(1, j.src.height >> @intCast(@min(31, smip)));
    const sx: u32 = if (j.has_box) j.bx[0] else 0;
    const sy: u32 = if (j.has_box) j.bx[1] else 0;
    const sz: u32 = if (j.has_box) j.bx[2] else 0;
    const cw: u32 = if (j.has_box) @max(1, j.bx[3] -| j.bx[0]) else sw;
    const ch: u32 = if (j.has_box) @max(1, j.bx[4] -| j.bx[1]) else sh;

    if (p_copy_image) |ci| {
        ci(j.src.gl_id, j.src.target, @intCast(smip), @intCast(sx), @intCast(sy), @intCast(sslice + sz),
            j.dst.gl_id, j.dst.target, @intCast(dmip), @intCast(j.dx), @intCast(j.dy), @intCast(dslice + j.dz),
            @intCast(cw), @intCast(ch), 1);
    } else if (!j.src.is_depth and !j.dst.is_depth) {
        gl.glBindFramebuffer(0x8CA8, g_copy_fbo_read);
        gl.glFramebufferTexture2D(0x8CA8, 0x8CE0, 0x0DE1, j.src.gl_id, @intCast(smip));
        gl.glBindFramebuffer(0x8CA9, g_copy_fbo_draw);
        gl.glFramebufferTexture2D(0x8CA9, 0x8CE0, 0x0DE1, j.dst.gl_id, @intCast(dmip));
        gl.glBlitFramebuffer(@intCast(sx), @intCast(sy), @intCast(sx + cw), @intCast(sy + ch),
            @intCast(j.dx), @intCast(j.dy), @intCast(j.dx + cw), @intCast(j.dy + ch), 0x4000, 0x2600);
        gl.glBindFramebuffer(0x8CA8, 0);
        gl.glBindFramebuffer(0x8CA9, 0);
    }
}

pub fn copyResource(dst_tex: ?*Texture, dst_buf: ?*Buffer, src_tex: ?*Texture, src_buf: ?*Buffer) void {
    if (dst_buf != null and src_buf != null) {
        const db = dst_buf.?;
        const sb = src_buf.?;
        if (db.shadow != null and sb.shadow != null) {
            const n = @min(db.size, sb.size);
            @memcpy(db.shadow.?[0..n], sb.shadow.?[0..n]);
            uploadBuffer(db, 0, db.shadow.?.ptr, n);
        }
        return;
    }
    if (dst_tex != null and src_tex != null) {
        var j: CopyJob = .{
            .dst = dst_tex.?, .dst_sub = 0, .dx = 0, .dy = 0, .dz = 0,
            .src = src_tex.?, .src_sub = 0, .has_box = false, .bx = .{0} ** 6,
        };
        run(&copyTexJob, &j);
    }
}

pub fn copySubresourceRegion(dst_tex: ?*Texture, dst_sub: u32, dx: u32, dy: u32, dz: u32, src_tex: ?*Texture, src_sub: u32, has_box: bool, bx: [6]u32) void {
    if (dst_tex == null or src_tex == null) return;
    var j: CopyJob = .{
        .dst = dst_tex.?, .dst_sub = dst_sub, .dx = dx, .dy = dy, .dz = dz,
        .src = src_tex.?, .src_sub = src_sub, .has_box = has_box, .bx = bx,
    };
    run(&copyTexJob, &j);
}

pub fn resolveSubresource(dst_tex: *Texture, dst_sub: u32, src_tex: *Texture, src_sub: u32) void {
    copySubresourceRegion(dst_tex, dst_sub, 0, 0, 0, src_tex, src_sub, false, .{0} ** 6);
}

fn genMipsJob(raw: ?*anyopaque) void {
    const v: *View = @ptrCast(@alignCast(raw.?));
    const t = v.tex orelse return;
    if (t.gl_id == 0) return;
    gl.glBindTexture(t.target, t.gl_id);
    gl.glGenerateMipmap(t.target);
    gl.glBindTexture(t.target, 0);
}

pub fn generateMips(srv: *View) void {
    run(&genMipsJob, srv);
}

// ---- Draw Pipeline Execution ------------------------------------------------

const DrawJob = struct {
    s: *const DrawState,
    kind: DrawKind,
    count: u32,
    inst_count: u32,
    start_vertex: u32,
    start_index: u32,
    base_vertex: i32,
    start_instance: u32,
    indirect_buf: ?*Buffer = null,
    indirect_off: u32 = 0,
};

var g_active_attribs: u32 = 0;
var g_draw_count: u32 = 0;
var g_err_logged: u32 = 0;

fn setCap(cap: GLenum, on: bool) void {
    if (on) gl.glEnable(cap) else gl.glDisable(cap);
}

fn glPrimTopology(t: u32) GLenum {
    return switch (t) {
        1 => 0x0000, // POINTS
        2 => 0x0001, // LINES
        3 => 0x0003, // LINE_STRIP
        4 => 0x0004, // TRIANGLES
        5 => 0x0005, // TRIANGLE_STRIP
        else => 0x0004,
    };
}

/// WINS_D3D11_TRACE_FRAME=N: also trace every draw of present #N (with
/// WINS_D3D11_TRACE_DRAWS).
fn traceFrame() bool {
    const C = struct { var init = false; var n: ?u32 = null; };
    if (!C.init) {
        C.init = true;
        if (getenv("WINS_D3D11_TRACE_FRAME")) |z| C.n = std.fmt.parseInt(u32, std.mem.span(z), 10) catch null;
    }
    return if (C.n) |n| g_present_count == n else false;
}

fn bindTextureSlots(bindings: []const shader.TexBinding, srvs: *const [MAX_SRV]?*View, samps: *const [16]?*Sampler) void {
    for (bindings) |b| {
        const unit: GLuint = b.unit;
        gl.glActiveTexture(0x84C0 + unit);
        if (srvs[b.reg]) |rv| {
            if (rv.tex) |t| {
                gl.glBindTexture(t.target, t.gl_id);
            } else if (rv.buf != null and b.dim == .buf) {
                gl.glBindTexture(0x8C2A, bufferTexture(rv)); // GL_TEXTURE_BUFFER
            } else {
                gl.glBindTexture(0x0DE1, 0);
            }
        } else {
            gl.glBindTexture(0x0DE1, 0);
        }
        const sid: GLuint = if (samps[b.samp]) |smp| smp.gl_id else 0;
        gl.glBindSampler(unit, sid);
    }
}

// ---- SM5 memory: buffer textures, storage blocks, images, compute -----------

/// GL sized internal format for a typed buffer view (texture buffer / image
/// buffer); integer formats included, unlike the texture table.
fn bufferViewFormat(fmt: u32) GLenum {
    return switch (fmt) {
        2 => 0x8814, // RGBA32F
        3 => 0x8D70, // RGBA32UI
        4 => 0x8D82, // RGBA32I
        6 => 0x8815, // RGB32F
        7 => 0x8D71, // RGB32UI
        8 => 0x8D83, // RGB32I
        10 => 0x881A, // RGBA16F
        11 => 0x805B, // RGBA16
        12 => 0x8D76, // RGBA16UI
        14 => 0x8D88, // RGBA16I
        16 => 0x8230, // RG32F
        17 => 0x823C, // RG32UI
        18 => 0x823B, // RG32I
        28 => 0x8058, // RGBA8
        30 => 0x8D7C, // RGBA8UI
        32 => 0x8D8E, // RGBA8I
        34 => 0x822F, // RG16F
        36 => 0x823A, // RG16UI
        38 => 0x8239, // RG16I
        41 => 0x822E, // R32F
        42 => 0x8236, // R32UI
        43 => 0x8235, // R32I
        54 => 0x822D, // R16F
        57 => 0x8234, // R16UI
        59 => 0x8233, // R16I
        61 => 0x8229, // R8
        62 => 0x8232, // R8UI
        64 => 0x8231, // R8I
        else => 0x8236, // raw / unknown: R32UI words
    };
}

/// The GL buffer texture of a typed buffer view, created on first use.
fn bufferTexture(v: *View) GLuint {
    if (v.gl_tbo != 0) return v.gl_tbo;
    const b = v.buf orelse return 0;
    gl.glGenTextures(1, &v.gl_tbo);
    gl.glBindTexture(0x8C2A, v.gl_tbo);
    const size = if (v.buf_size > 0) @min(v.buf_size, b.size -| v.buf_off) else b.size -| v.buf_off;
    gl.glTexBufferRange(0x8C2A, bufferViewFormat(v.dxgi_fmt), b.gl_id, @intCast(v.buf_off), @intCast(@max(4, size)));
    return v.gl_tbo;
}

var g_ssbo_align: u32 = 0;
var g_zero_buf: GLuint = 0;

/// Bound to storage blocks whose t#/u# slot is empty: unbound SSBO access is
/// undefined in GL, D3D reads zeros.
fn zeroBuffer() GLuint {
    if (g_zero_buf == 0) {
        gl.glGenBuffers(1, &g_zero_buf);
        gl.glBindBuffer(0x90D2, g_zero_buf);
        const z = alloc.alloc(u8, 65536) catch return 0;
        defer alloc.free(z);
        @memset(z, 0);
        gl.glBufferData(0x90D2, 65536, z.ptr, 0x88E4);
        gl.glBindBuffer(0x90D2, 0);
    }
    return g_zero_buf;
}

fn counterBuffer(v: *View) GLuint {
    if (v.counter == 0) {
        gl.glGenBuffers(1, &v.counter);
        gl.glBindBuffer(0x90D2, v.counter);
        const zero: u32 = 0;
        gl.glBufferData(0x90D2, 4, &zero, 0x88E8);
        gl.glBindBuffer(0x90D2, 0);
    }
    if (v.counter_set) |n| {
        gl.glBindBuffer(0x90D2, v.counter);
        gl.glBufferSubData(0x90D2, 0, 4, &n);
        gl.glBindBuffer(0x90D2, 0);
        v.counter_set = null;
    }
    return v.counter;
}

fn bindSsbo(binding: GLuint, v: ?*View) void {
    const GL_SSBO: GLenum = 0x90D2;
    const view = v orelse return gl.glBindBufferBase(GL_SSBO, binding, zeroBuffer());
    const b = view.buf orelse return gl.glBindBufferBase(GL_SSBO, binding, zeroBuffer());
    if (g_ssbo_align == 0) {
        var al: GLint = 0;
        gl.glGetIntegerv(0x90DF, &al); // GL_SHADER_STORAGE_BUFFER_OFFSET_ALIGNMENT
        g_ssbo_align = @intCast(@max(1, al));
    }
    const size = if (view.buf_size > 0) @min(view.buf_size, b.size -| view.buf_off) else b.size -| view.buf_off;
    if (view.buf_off == 0 and size == b.size) {
        gl.glBindBufferBase(GL_SSBO, binding, b.gl_id);
    } else if (view.buf_off % g_ssbo_align == 0 and size > 0) {
        gl.glBindBufferRange(GL_SSBO, binding, b.gl_id, @intCast(view.buf_off), @intCast(size));
    } else {
        // Unaligned first element: the shader would index from the buffer start.
        const S = struct { var told = false; };
        if (!S.told) {
            S.told = true;
            std.debug.print("[WINS:D3D11:GL] buffer view offset {d} not {d}-aligned: bound from 0\n", .{ view.buf_off, g_ssbo_align });
        }
        gl.glBindBufferBase(GL_SSBO, binding, b.gl_id);
    }
}

fn bindBufSlots(bindings: []const shader.BufBinding, srvs: *const [MAX_SRV]?*View, uavs: ?*const [shader.MAX_UAV]?*View) void {
    for (bindings) |b| {
        switch (b.kind) {
            .srv => bindSsbo(b.binding, srvs[b.reg]),
            .uav => bindSsbo(b.binding, if (uavs) |u| u[b.reg] else null),
            .counter => {
                const v = if (uavs) |u| u[b.reg] else null;
                if (v) |view| {
                    gl.glBindBufferBase(0x90D2, b.binding, counterBuffer(view));
                } else gl.glBindBufferBase(0x90D2, b.binding, zeroBuffer());
            },
        }
    }
}

/// Image-compatible internal format for a texture bound as a typed UAV.
fn imageFormat(internal: GLint) GLenum {
    return switch (internal) {
        0x8C43 => 0x8058, // SRGB8_ALPHA8 -> RGBA8
        else => @intCast(internal),
    };
}

fn bindImageSlots(bindings: []const shader.ImgBinding, uavs: *const [shader.MAX_UAV]?*View) void {
    const GL_READ_WRITE: GLenum = 0x88BA;
    for (bindings) |ib| {
        const v = uavs[ib.reg] orelse {
            gl.glBindImageTexture(ib.unit, 0, 0, 0, 0, GL_READ_WRITE, 0x8058);
            continue;
        };
        if (v.tex) |t| {
            const fmt: GLenum = if (ib.atomic) 0x8236 else imageFormat(dxgiToGlFormat(t.dxgi_fmt).internal);
            // 2D array, 3D, 1D array, cube, cube array bind every layer.
            const layered: u8 = switch (t.target) { 0x8C1A, 0x806F, 0x8C18, 0x9009, 0x8513 => 1, else => 0 };
            gl.glBindImageTexture(ib.unit, t.gl_id, @intCast(v.first_mip), layered, 0, GL_READ_WRITE, fmt);
        } else if (v.buf != null) {
            const fmt: GLenum = if (ib.atomic) 0x8236 else bufferViewFormat(v.dxgi_fmt);
            gl.glBindImageTexture(ib.unit, bufferTexture(v), 0, 0, 0, GL_READ_WRITE, fmt);
        }
    }
}

pub fn createComputeShader(sh: *Shader, bytes: []const u8) bool {
    sh.is_compute = true;
    sh.uid = g_shader_uid.fetchAdd(1, .monotonic) + 1;
    sh.bytecode = alloc.dupe(u8, bytes) catch return false;
    return true;
}

/// Translate + compile + link a compute shader once (a failure is remembered).
fn linkCompute(sh: *Shader) void {
    if (sh.cs_linked) return;
    sh.cs_linked = true;
    var tr = shader.translate(alloc, sh.bytecode) catch |e| {
        std.debug.print("[WINS:D3D11:GL] CS translate err={s} ({s})\n", .{ @errorName(e), shader.last_error });
        return;
    };
    defer tr.deinit(alloc);
    const cs = compileGlShader(0x91B9, tr.glsl, "CS"); // GL_COMPUTE_SHADER
    if (cs == 0) return;
    defer gl.glDeleteShader(cs);
    const prog = gl.glCreateProgram();
    gl.glAttachShader(prog, cs);
    gl.glLinkProgram(prog);
    var ok: GLint = 0;
    gl.glGetProgramiv(prog, 0x8B82, &ok);
    if (ok == 0) {
        var log_buf: [2048]u8 = undefined;
        var n: GLsizei = 0;
        gl.glGetProgramInfoLog(prog, log_buf.len, &n, &log_buf);
        std.debug.print("[WINS:D3D11:GL] CS link FAIL:\n{s}\n", .{log_buf[0..@intCast(@max(0, n))]});
        gl.glDeleteProgram(prog);
        return;
    }
    sh.cs_prog = prog;
    sh.cs_tex = alloc.dupe(shader.TexBinding, tr.tex_bindings) catch &.{};
    sh.cs_buf = alloc.dupe(shader.BufBinding, tr.buf_bindings) catch &.{};
    sh.cs_img = alloc.dupe(shader.ImgBinding, tr.img_bindings) catch &.{};
    if (getenv("WINS_D3D11_DUMP_DIR")) |dz| dumpFile(std.mem.span(dz), prog, "cs.glsl", tr.glsl);
}

const DispatchJob = struct {
    s: *DrawState,
    x: u32 = 0,
    y: u32 = 0,
    z: u32 = 0,
    indirect_buf: ?*Buffer = null,
    indirect_off: u32 = 0,
};
pub var g_dispatch_count: u32 = 0;

fn dispatchJob(raw: ?*anyopaque) void {
    const j: *DispatchJob = @ptrCast(@alignCast(raw.?));
    const s = j.s;
    const cs = s.cs orelse return;
    linkCompute(cs);
    if (cs.cs_prog == 0) return;
    g_dispatch_count += 1;
    gl.glUseProgram(cs.cs_prog);
    for (0..16) |i| {
        const cb = s.cs_cb[i] orelse continue;
        const off = s.cs_cb_off[i] * 16;
        const sz = if (s.cs_cb_sz[i] > 0) @min(cb.size -| off, s.cs_cb_sz[i] * 16) else (cb.size -| off);
        if (off > 0 and sz > 0) {
            gl.glBindBufferRange(0x8A11, @intCast(i), cb.gl_id, @intCast(off), @intCast(sz));
        } else {
            gl.glBindBufferBase(0x8A11, @intCast(i), cb.gl_id);
        }
    }
    bindTextureSlots(cs.cs_tex, &s.cs_srv, &s.cs_samp);
    bindBufSlots(cs.cs_buf, &s.cs_srv, &s.cs_uav);
    bindImageSlots(cs.cs_img, &s.cs_uav);
    if (j.indirect_buf) |ib| {
        if (ib.gl_id == 0) return;
        gl.glBindBuffer(0x90EE, ib.gl_id); // GL_DISPATCH_INDIRECT_BUFFER
        gl.glDispatchComputeIndirect(@intCast(j.indirect_off));
        gl.glBindBuffer(0x90EE, 0);
    } else {
        gl.glDispatchCompute(j.x, j.y, j.z);
    }
    // D3D11 orders every Dispatch against what follows; GL needs explicit barriers.
    gl.glMemoryBarrier(0xFFFFFFFF);
    if (g_err_logged < 32) {
        const e = gl.glGetError();
        if (e != 0) {
            g_err_logged += 1;
            std.debug.print("[WINS:D3D11:GL] Dispatch({d},{d},{d}) glError 0x{x}\n", .{ j.x, j.y, j.z, e });
        }
    }
}

pub fn dispatch(s: *DrawState, x: u32, y: u32, z: u32) void {
    if (x == 0 or y == 0 or z == 0) return;
    var j: DispatchJob = .{ .s = s, .x = x, .y = y, .z = z };
    run(&dispatchJob, &j);
}

pub fn dispatchIndirect(s: *DrawState, buf: *Buffer, off: u32) void {
    var j: DispatchJob = .{ .s = s, .indirect_buf = buf, .indirect_off = off };
    run(&dispatchJob, &j);
}

fn drawJob(raw: ?*anyopaque) void {
    const j: *DrawJob = @ptrCast(@alignCast(raw.?));
    const s = j.s;
    const vs = s.vs orelse return;
    const lp = getOrLinkProgram(vs, s.ps);
    if (lp.prog == 0) return;

    const fb_dim = bindFramebufferForState(s);
    gl.glUseProgram(lp.prog);

    // Viewport (default to RT size if SetViewports wasn't called yet)
    if (s.num_viewports > 0) {
        const vp = s.viewports[0];
        gl.glViewport(@intFromFloat(vp.x), @intFromFloat(vp.y), @intFromFloat(@max(1.0, vp.w)), @intFromFloat(@max(1.0, vp.h)));
        gl.glDepthRange(@floatCast(vp.min_depth), @floatCast(vp.max_depth));
    } else {
        gl.glViewport(0, 0, @intCast(fb_dim.w), @intCast(fb_dim.h));
        gl.glDepthRange(0.0, 1.0);
    }

    // Rasterizer
    if (s.rasterizer) |rs| {
        gl.glPolygonMode(0x0408, if (rs.wireframe) 0x1B01 else 0x1B02);
        // Winding is set even with culling off: two-sided stencil (front vs back ops)
        // depends on it, and a stale value from the previous draw flips the faces.
        gl.glFrontFace(if (rs.front_ccw) 0x0901 else 0x0900); // GL_UPPER_LEFT keeps CW = D3D default!
        if (rs.cull_mode == 1) {
            gl.glDisable(0x0B44);
        } else {
            gl.glEnable(0x0B44);
            gl.glCullFace(if (rs.cull_mode == 2) 0x0404 else 0x0405);
        }
        if (rs.scissor_enable and s.num_scissors > 0) {
            const sc = s.scissors[0];
            gl.glEnable(0x0C11);
            gl.glScissor(sc.left, sc.top, @max(0, sc.right - sc.left), @max(0, sc.bottom - sc.top));
        } else {
            gl.glDisable(0x0C11);
        }
    } else {
        gl.glPolygonMode(0x0408, 0x1B02);
        gl.glEnable(0x0B44);
        gl.glCullFace(0x0405);
        gl.glFrontFace(0x0900);
        gl.glDisable(0x0C11);
    }

    // Depth-Stencil
    if (s.depth_stencil) |ds| {
        setCap(0x0B71, ds.depth_enable);
        gl.glDepthMask(if (ds.depth_write) 1 else 0);
        gl.glDepthFunc(ds.depth_func);
        setCap(0x0B90, ds.stencil_enable);
        if (ds.stencil_enable) {
            gl.glStencilMask(ds.stencil_write_mask);
            gl.glStencilFuncSeparate(0x0404, ds.front_func, @intCast(s.stencil_ref), ds.stencil_read_mask);
            gl.glStencilFuncSeparate(0x0405, ds.back_func, @intCast(s.stencil_ref), ds.stencil_read_mask);
            gl.glStencilOpSeparate(0x0404, ds.front_fail, ds.front_zfail, ds.front_pass);
            gl.glStencilOpSeparate(0x0405, ds.back_fail, ds.back_zfail, ds.back_pass);
        }
    } else {
        gl.glEnable(0x0B71);
        gl.glDepthMask(1);
        gl.glDepthFunc(0x0201); // LESS
        gl.glDisable(0x0B90);
    }

    // Blend
    if (s.blend) |bl| {
        gl.glBlendColor(s.blend_factor[0], s.blend_factor[1], s.blend_factor[2], s.blend_factor[3]);
        const nrt = @max(@as(u32, 1), @min(8, s.num_rtvs));
        for (0..nrt) |i| {
            const rt = bl.rt[if (bl.independent) i else 0];
            gl.glColorMaski(@intCast(i), if ((rt.write_mask & 1) != 0) 1 else 0, if ((rt.write_mask & 2) != 0) 1 else 0, if ((rt.write_mask & 4) != 0) 1 else 0, if ((rt.write_mask & 8) != 0) 1 else 0);
            if (rt.enable) {
                gl.glEnablei(0x0BE2, @intCast(i));
                gl.glBlendFuncSeparatei(@intCast(i), rt.src_rgb, rt.dst_rgb, rt.src_a, rt.dst_a);
                gl.glBlendEquationSeparatei(@intCast(i), rt.op_rgb, rt.op_a);
            } else {
                gl.glDisablei(0x0BE2, @intCast(i));
            }
        }
    } else {
        gl.glDisable(0x0BE2);
        for (0..@max(@as(u32, 1), @min(8, s.num_rtvs))) |i| gl.glColorMaski(@intCast(i), 1, 1, 1, 1);
    }

    // Constant Buffers (VS -> bindings 0..15, PS -> bindings 16..31)
    for (0..16) |i| {
        if (s.vs_cb[i]) |cb| {
            const off = s.vs_cb_off[i] * 16;
            const sz = if (s.vs_cb_sz[i] > 0) @min(cb.size -| off, s.vs_cb_sz[i] * 16) else (cb.size -| off);
            if (off > 0 and sz > 0) {
                gl.glBindBufferRange(0x8A11, @intCast(i), cb.gl_id, @intCast(off), @intCast(sz));
            } else {
                gl.glBindBufferBase(0x8A11, @intCast(i), cb.gl_id);
            }
        }
        if (s.ps_cb[i]) |cb| {
            const off = s.ps_cb_off[i] * 16;
            const sz = if (s.ps_cb_sz[i] > 0) @min(cb.size -| off, s.ps_cb_sz[i] * 16) else (cb.size -| off);
            if (off > 0 and sz > 0) {
                gl.glBindBufferRange(0x8A11, @intCast(16 + i), cb.gl_id, @intCast(off), @intCast(sz));
            } else {
                gl.glBindBufferBase(0x8A11, @intCast(16 + i), cb.gl_id);
            }
        }
    }

    // Textures & Samplers
    bindTextureSlots(lp.ps_tex_bindings, &s.ps_srv, &s.ps_samp);
    bindTextureSlots(lp.vs_tex_bindings, &s.vs_srv, &s.vs_samp);
    // Raw/structured SRVs (UAVs in VS/PS are not bound yet: OMSetRenderTargetsAndUAVs)
    bindBufSlots(lp.ps_buf_bindings, &s.ps_srv, null);
    bindBufSlots(lp.vs_buf_bindings, &s.vs_srv, null);

    // Input Layout + Vertex Buffers on Default VAO
    var new_mask: u32 = 0;
    if (s.input_layout) |il| {
        for (il.elems[0..il.count]) |el| {
            if (el.slot >= 16) continue;
            const vb = s.vb[el.slot] orelse continue;
            var loc: u32 = el.location;
            var is_int: bool = el.is_int;
            if (vs.inputs.len > 0 and el.sem_len > 0) {
                const sem = el.sem_name[0..el.sem_len];
                var found = false;
                for (vs.inputs) |se| {
                    if (se.index == el.sem_index and std.ascii.eqlIgnoreCase(se.name, sem)) {
                        loc = se.reg;
                        is_int = (se.comp_type == 1 or se.comp_type == 2) and el.is_int;
                        found = true;
                        break;
                    }
                }
                if (!found) continue;
            }
            if (loc >= 32) continue;
            new_mask |= @as(u32, 1) << @intCast(loc);
            gl.glBindBuffer(0x8892, vb.gl_id);
            gl.glEnableVertexAttribArray(loc);
            const inst_off: usize = if (el.is_instance) @as(usize, j.start_instance) * @as(usize, s.vb_stride[el.slot]) else 0;
            const ptr_off: usize = @as(usize, s.vb_offset[el.slot]) + @as(usize, el.offset) + inst_off;
            const stride: GLsizei = @intCast(s.vb_stride[el.slot]);
            if (is_int) {
                gl.glVertexAttribIPointer(loc, el.components, el.gl_type, stride, @ptrFromInt(ptr_off));
            } else {
                gl.glVertexAttribPointer(loc, el.components, el.gl_type, if (el.normalized) 1 else 0, stride, @ptrFromInt(ptr_off));
            }
            gl.glVertexAttribDivisor(loc, if (el.is_instance) @max(1, el.step_rate) else 0);
        }
    }
    var cleared = g_active_attribs & ~new_mask;
    while (cleared != 0) {
        const bit: u32 = @ctz(cleared);
        gl.glDisableVertexAttribArray(bit);
        cleared &= cleared - 1;
    }
    g_active_attribs = new_mask;

    // Index Buffer & Draw
    const mode = glPrimTopology(s.topology);
    if (j.kind == .arrays) {
        gl.glDrawArrays(mode, @intCast(j.start_vertex), @intCast(j.count));
    } else if (j.kind == .arrays_instanced) {
        gl.glDrawArraysInstanced(mode, @intCast(j.start_vertex), @intCast(j.count), @intCast(j.inst_count));
    } else if (j.kind == .arrays_indirect) {
        const ab = j.indirect_buf orelse return;
        if (ab.gl_id == 0) return;
        gl.glBindBuffer(0x8F3F, ab.gl_id); // GL_DRAW_INDIRECT_BUFFER
        gl.glDrawArraysIndirect(mode, @ptrFromInt(@as(usize, j.indirect_off)));
        gl.glBindBuffer(0x8F3F, 0);
    } else {
        const ib = s.ib orelse return;
        gl.glBindBuffer(0x8893, ib.gl_id);
        const is_u32 = (s.ib_format == 42); // DXGI_FORMAT_R32_UINT
        const idx_ty: GLenum = if (is_u32) 0x1405 else 0x1403;
        const idx_bytes: usize = if (is_u32) 4 else 2;
        const ib_ptr: ?*const anyopaque = @ptrFromInt(@as(usize, s.ib_offset) + @as(usize, j.start_index) * idx_bytes);
        if (j.kind == .indexed_indirect) {
            const ab = j.indirect_buf orelse return;
            if (ab.gl_id == 0) return;
            gl.glBindBuffer(0x8F3F, ab.gl_id); // GL_DRAW_INDIRECT_BUFFER
            gl.glDrawElementsIndirect(mode, idx_ty, @ptrFromInt(@as(usize, j.indirect_off)));
            gl.glBindBuffer(0x8F3F, 0);
        } else if (j.kind == .indexed) {
            if (j.base_vertex != 0) {
                gl.glDrawElementsBaseVertex(mode, @intCast(j.count), idx_ty, ib_ptr, j.base_vertex);
            } else {
                gl.glDrawElements(mode, @intCast(j.count), idx_ty, ib_ptr);
            }
        } else {
            if (j.base_vertex != 0) {
                gl.glDrawElementsInstancedBaseVertex(mode, @intCast(j.count), idx_ty, ib_ptr, @intCast(j.inst_count), j.base_vertex);
            } else {
                gl.glDrawElementsInstanced(mode, @intCast(j.count), idx_ty, ib_ptr, @intCast(j.inst_count));
            }
        }
    }
    traceProgConstants(s, lp.prog, fb_dim.w, fb_dim.h);
    if (g_err_logged < 8) {
        const err = gl.glGetError();
        if (err != 0) {
            g_err_logged += 1;
            std.debug.print("[WINS:D3D11:GL] draw glError=0x{x} draws={d}\n", .{ err, g_draw_count });
        }
    }
    if (getenv("WINS_D3D11_TRACE_DRAWS") != null and (g_draw_count <= 36 or (g_present_count >= 4 and g_present_count <= 5) or traceFrame())) {
        const rt0 = if (s.num_rtvs > 0 and s.rtv[0] != null and s.rtv[0].?.tex != null) s.rtv[0].?.tex.? else null;
        const ps0 = if (s.ps_srv[0] != null and s.ps_srv[0].?.tex != null) s.ps_srv[0].?.tex.? else null;
        var px: [4]u8 = .{ 0, 0, 0, 0 };
        if (rt0 != null and !rt0.?.is_depth) {
            gl.glReadPixels(@intCast(fb_dim.w / 2), @intCast(fb_dim.h / 2), 1, 1, 0x1908, 0x1401, &px);
        }
        const vb0 = s.vb[0];
        const cb_vs0 = s.vs_cb[0];
        const cb_ps0 = s.ps_cb[0];
        const bl_en = if (s.blend) |b| b.rt[0].enable else false;
        const bl_mask = if (s.blend) |b| b.rt[0].write_mask else 0xF;
        const rs_cull: u32 = if (s.rasterizer) |r| r.cull_mode else 3;
        const rs_sc: bool = if (s.rasterizer) |r| r.scissor_enable else false;
        const ds_en: bool = if (s.depth_stencil) |d| d.depth_enable else true;
        const ds_fn: u32 = if (s.depth_stencil) |d| d.depth_func else 0x0201;
        std.debug.print("[WINS:D3D11:GL] draw#{d} f={d} k={} cnt={d} si={d} bv={d} sv={d} rt0={d}(sw={}) dsv={} vp={d}x{d}(nvp={d}) il={} vb0={d}(st={d},off={d}) ib={} cb=({d},{d}) srv0={d} prog={d} bl=({}/0x{x}) ds=({}/0x{x}) rs=(cull={},sc={}) ctrPx=({d},{d},{d},{d})\n", .{
            g_draw_count, g_present_count, j.kind, j.count, j.start_index, j.base_vertex, j.start_vertex,
            if (rt0) |r| r.gl_id else 0, if (rt0) |r| r.is_swapchain else false, s.dsv != null,
            fb_dim.w, fb_dim.h, s.num_viewports, if (s.input_layout) |il| il.count else 0,
            if (vb0) |v| v.gl_id else 0, s.vb_stride[0], s.vb_offset[0], s.ib != null,
            if (cb_vs0) |c| c.size else 0, if (cb_ps0) |c| c.size else 0,
            if (ps0) |p| p.gl_id else 0, lp.prog,
            bl_en, bl_mask, ds_en, ds_fn, rs_cull, rs_sc, px[0], px[1], px[2], px[3],
        });
        if (traceFrame()) if (s.blend) |bl| {
            const r0 = bl.rt[0];
            std.debug.print("    blend rt0 en={} src=0x{x}/0x{x} dst=0x{x}/0x{x} op=0x{x}/0x{x} mask=0x{x} factor=({d:.2},{d:.2},{d:.2},{d:.2}) indep={} rtfmt={d}\n", .{
                r0.enable, r0.src_rgb, r0.src_a, r0.dst_rgb, r0.dst_a, r0.op_rgb, r0.op_a, r0.write_mask,
                s.blend_factor[0], s.blend_factor[1], s.blend_factor[2], s.blend_factor[3], bl.independent,
                if (rt0) |r| r.dxgi_fmt else 0,
            });
        };
        if (traceFrame() and s.dsv != null) {
            var grid: [15]u8 = undefined;
            for (0..3) |gy| for (0..5) |gx| {
                var sv: [4]u8 = .{ 0, 0, 0, 0 };
                gl.glReadPixels(@intCast(fb_dim.w * (2 * gx + 1) / 10), @intCast(fb_dim.h * (2 * gy + 1) / 6), 1, 1, 0x1901, 0x1401, &sv); // STENCIL_INDEX
                grid[gy * 5 + gx] = sv[0];
            };
            const dfmt: u32 = if (s.dsv.?.tex) |t| t.dxgi_fmt else 0;
            std.debug.print("    stencil grid={any} dsv_fmt={d} view_fmt={d} glErr=0x{x}\n", .{ grid, dfmt, s.dsv.?.dxgi_fmt, gl.glGetError() });
            // 48x27 map: stencil digit, or '#' where the colour RT is bright (>96).
            var y: usize = 0;
            while (y < 27) : (y += 1) {
                var line: [48]u8 = undefined;
                for (0..48) |x| {
                    const px_x: GLint = @intCast(fb_dim.w * (2 * x + 1) / 96);
                    const px_y: GLint = @intCast(fb_dim.h * (2 * y + 1) / 54);
                    var st: [4]u8 = .{ 0, 0, 0, 0 };
                    var col: [4]u8 = .{ 0, 0, 0, 0 };
                    gl.glReadPixels(px_x, px_y, 1, 1, 0x1901, 0x1401, &st);
                    gl.glReadPixels(px_x, px_y, 1, 1, 0x1908, 0x1401, &col);
                    const lum = (@as(u32, col[0]) + col[1] + col[2]) / 3;
                    line[x] = if (lum > 96) '#' else if (st[0] > 0) @as(u8, '0') + @min(st[0], 9) else '.';
                }
                std.debug.print("    |{s}|\n", .{line});
            }
        }
        if (traceFrame()) if (s.depth_stencil) |d| {
            std.debug.print("    ds depth={}/{} func=0x{x} stencil={} rmask=0x{x} wmask=0x{x} front(func=0x{x} pass=0x{x} fail=0x{x}) back(func=0x{x} pass=0x{x} fail=0x{x}) ref={d}\n", .{
                d.depth_enable, d.depth_write, d.depth_func, d.stencil_enable, d.stencil_read_mask, d.stencil_write_mask, d.front_func, d.front_pass, d.front_fail, d.back_func, d.back_pass, d.back_fail, s.stencil_ref,
            });
        };
        // Traced frame: first indices of an indexed draw and their vertex bytes.
        if (traceFrame() and j.kind == .indexed) blk: {
            const ib = s.ib orelse break :blk;
            const ish = ib.shadow orelse break :blk;
            const vb = s.vb[0] orelse break :blk;
            const vsh = vb.shadow orelse break :blk;
            const is32 = s.ib_format == 42;
            const ib_bytes: usize = if (is32) 4 else 2;
            var q: usize = 0;
            while (q < @min(@as(u32, if (getenv("WINS_D3D11_TRACE_ALLIDX") != null) 4096 else 6), j.count)) : (q += 1) {
                const at = @as(usize, s.ib_offset) + (@as(usize, j.start_index) + q) * ib_bytes;
                if (at + ib_bytes > ish.len) break;
                const idx: usize = if (is32) std.mem.readInt(u32, ish[at..][0..4], .little) else std.mem.readInt(u16, ish[at..][0..2], .little);
                const v_at = @as(usize, s.vb_offset[0]) + (idx + @as(usize, @bitCast(@as(isize, j.base_vertex)))) * s.vb_stride[0];
                if (v_at + 16 > vsh.len) break;
                std.debug.print("    idx[{d}]={d} v@{d}: {x}\n", .{ q, idx, v_at, vsh[v_at..][0..@min(16, s.vb_stride[0])] });
            }
        }
        if (g_draw_count == 20 or g_draw_count == 22 or g_draw_count == 25 or g_draw_count == 34) {
            if (s.num_viewports > 0) {
                const v0 = s.viewports[0];
                std.debug.print("  vp0=({d:.1},{d:.1},{d:.1},{d:.1}, z={d:.2}..{d:.2})\n", .{ v0.x, v0.y, v0.w, v0.h, v0.min_depth, v0.max_depth });
            }
            if (s.input_layout) |il| {
                for (il.elems[0..il.count], 0..) |el, ei| {
                    std.debug.print("  il[{d}] loc={d} comp={d} ty=0x{x} norm={} int={} slot={d} off={d}\n", .{
                        ei, el.location, el.components, el.gl_type, el.normalized, el.is_int, el.slot, el.offset,
                    });
                }
            }
            var idx0: i32 = 0;
            if (s.ib) |ib| {
                if (ib.shadow) |sh| {
                    const is_u32 = (s.ib_format == 42);
                    const ib_byte_off: usize = @as(usize, s.ib_offset) + @as(usize, j.start_index) * (if (is_u32) @as(usize, 4) else @as(usize, 2));
                    const avail = @min(@as(usize, 6), (sh.len -| ib_byte_off) / (if (is_u32) @as(usize, 4) else @as(usize, 2)));
                    std.debug.print("  ib@{d}(u32={}):", .{ ib_byte_off, is_u32 });
                    for (0..avail) |ii| {
                        const iv: u32 = if (is_u32) std.mem.readInt(u32, sh[ib_byte_off + ii * 4 ..][0..4], .little) else std.mem.readInt(u16, sh[ib_byte_off + ii * 2 ..][0..2], .little);
                        if (ii == 0) idx0 = @intCast(iv);
                        std.debug.print(" {d}", .{iv});
                    }
                    std.debug.print("\n", .{});
                }
            }
            if (vb0) |v| {
                if (v.shadow) |sh| {
                    const vbase_i: i64 = @as(i64, s.vb_offset[0]) + (@as(i64, j.base_vertex) + @as(i64, j.start_vertex) + @as(i64, idx0)) * @as(i64, s.vb_stride[0]);
                    const base: usize = if (vbase_i >= 0 and @as(usize, @intCast(vbase_i)) < sh.len) @intCast(vbase_i) else 0;
                    const avail = @min(@as(usize, 48), (sh.len - base) / 4);
                    std.debug.print("  vb0_f32@{d}:", .{base});
                    for (0..avail) |fi| {
                        const val: f32 = @bitCast(std.mem.readInt(u32, sh[base + fi * 4 ..][0..4], .little));
                        std.debug.print(" {d:.3}", .{val});
                    }
                    std.debug.print("\n", .{});
                }
            }
            for (0..3) |ci| {
                if (s.vs_cb[ci]) |c| {
                    if (c.shadow) |sh| {
                        const avail = @min(@as(usize, 48), sh.len / 4);
                        std.debug.print("  vscb{d}(gl={d},off={d}):", .{ ci, c.gl_id, s.vs_cb_off[ci] });
                        for (0..avail) |fi| {
                            const val: f32 = @bitCast(std.mem.readInt(u32, sh[fi * 4 ..][0..4], .little));
                            std.debug.print(" {d:.3}", .{val});
                        }
                        std.debug.print("\n", .{});
                    }
                }
            }
            for (0..2) |si| {
                if (s.ps_srv[si]) |sv| {
                    if (sv.tex) |t| {
                        std.debug.print("  ps_srv[{d}] gl={d} {d}x{d} fmt={d}\n", .{ si, t.gl_id, t.width, t.height, t.dxgi_fmt });
                    }
                }
            }
        }
    }
}

pub var g_skipped_stage_draws: u32 = 0;

pub fn draw(s: *const DrawState, kind: DrawKind, count: u32, inst_count: u32, start_vertex: u32, start_index: u32, base_vertex: i32, start_instance: u32) void {
    // Tessellation (patch-list topologies 33..64) and geometry shaders are not
    // translated: the VS output is not clip-space geometry then, so drawing it
    // as triangles only scribbles over the targets. Skip those draws.
    if (s.topology >= 33 or s.gs_active) {
        g_skipped_stage_draws += 1;
        if (g_skipped_stage_draws == 1 or g_skipped_stage_draws % 10000 == 0)
            std.debug.print("[WINS:D3D11:GL] {d} draws skipped (tessellation/GS not translated)\n", .{g_skipped_stage_draws});
        return;
    }
    g_draw_count += 1;
    var j: DrawJob = .{
        .s = s, .kind = kind, .count = count, .inst_count = inst_count,
        .start_vertex = start_vertex, .start_index = start_index,
        .base_vertex = base_vertex, .start_instance = start_instance,
    };
    run(&drawJob, &j);
}

pub fn drawIndirect(s: *const DrawState, indexed: bool, buf: *Buffer, off: u32) void {
    if (s.topology >= 33 or s.gs_active) {
        g_skipped_stage_draws += 1;
        return;
    }
    g_draw_count += 1;
    var j: DrawJob = .{
        .s = s,
        .kind = if (indexed) .indexed_indirect else .arrays_indirect,
        .count = 0,
        .inst_count = 0,
        .start_vertex = 0,
        .start_index = 0,
        .base_vertex = 0,
        .start_instance = 0,
        .indirect_buf = buf,
        .indirect_off = off,
    };
    run(&drawJob, &j);
}

// ---- Present & Frame Capture ------------------------------------------------

const PresentJob = struct { backbuffer: *Texture, hwnd: usize, sync_interval: u32 };
var g_present_count: u32 = 0;

fn maybeCaptureFrame(t: *Texture) void {
    const cap_env = getenv("WINS_D3D11_CAPTURE") orelse return;
    // WINS_D3D11_CAPTURE_EVERY=N: also capture every Nth present (long playtests
    // without the cost of WINS_D3D11_CAPTURE_ALL, which reads back every frame).
    const every: u32 = if (getenv("WINS_D3D11_CAPTURE_EVERY")) |e| (std.fmt.parseInt(u32, std.mem.sliceTo(e, 0), 10) catch 0) else 0;
    const periodic = every != 0 and g_present_count % every == 0;
    if (getenv("WINS_D3D11_CAPTURE_ALL") == null and !periodic and
        g_present_count != 5 and g_present_count != 20 and g_present_count != 40 and g_present_count != 80 and g_present_count != 150 and g_present_count != 240 and g_present_count != 400 and g_present_count != 600)
        return;
    const base = std.mem.sliceTo(cap_env, 0);
    const w = t.width;
    const h = t.height;
    const rgba = alloc.alloc(u8, w * h * 4) catch return;
    defer alloc.free(rgba);
    gl.glReadPixels(0, 0, @intCast(w), @intCast(h), 0x1908, 0x1401, rgba.ptr);

    var path_buf: [512]u8 = undefined;
    const path = if (std.mem.endsWith(u8, base, ".ppm"))
        base
    else
        (std.fmt.bufPrint(&path_buf, "{s}/frame_{d:04}.ppm", .{ base, g_present_count }) catch return);

    var dir_slice = path;
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |slash| dir_slice = path[0..slash];
    var dir_z: [512]u8 = undefined;
    if (dir_slice.len < dir_z.len) {
        @memcpy(dir_z[0..dir_slice.len], dir_slice);
        dir_z[dir_slice.len] = 0;
        _ = linux.mkdir(@ptrCast(&dir_z), 0o755);
    }

    var p_z: [512]u8 = undefined;
    if (path.len >= p_z.len) return;
    @memcpy(p_z[0..path.len], path);
    p_z[path.len] = 0;
    const fd = linux.open(@ptrCast(&p_z), .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (@as(isize, @bitCast(fd)) < 0) return;
    defer _ = linux.close(@intCast(fd));

    var hdr_buf: [64]u8 = undefined;
    const hdr = std.fmt.bufPrint(&hdr_buf, "P6\n{d} {d}\n255\n", .{ w, h }) catch return;
    _ = linux.write(@intCast(fd), hdr.ptr, hdr.len);
    const rgb = alloc.alloc(u8, w * h * 3) catch return;
    defer alloc.free(rgb);
    for (0..(w * h)) |p| {
        rgb[p * 3 + 0] = rgba[p * 4 + 0];
        rgb[p * 3 + 1] = rgba[p * 4 + 1];
        rgb[p * 3 + 2] = rgba[p * 4 + 2];
    }
    var written: usize = 0;
    while (written < rgb.len) {
        const n = linux.write(@intCast(fd), rgb.ptr + written, rgb.len - written);
        if (@as(isize, @bitCast(n)) <= 0) break;
        written += n;
    }
    std.debug.print("[WINS:D3D11:GL] captured {s} ({d}x{d}, draws={d})\n", .{ path, w, h, g_draw_count });
}

fn presentJob(raw: ?*anyopaque) void {
    const j: *PresentJob = @ptrCast(@alignCast(raw.?));
    const t = j.backbuffer;
    if (t.gl_id == 0 or g_gl_display == null or g_gl_window == 0) return;
    g_present_count += 1;

    gl.glBindFramebuffer(0x8CA8, g_copy_fbo_read);
    gl.glFramebufferTexture2D(0x8CA8, 0x8CE0, 0x0DE1, t.gl_id, 0);

    maybeCaptureFrame(t);

    const sz = gui.getWindowClientSize(j.hwnd);
    const dst_w = @max(1, sz.w);
    const dst_h = @max(1, sz.h);

    gl.glBindFramebuffer(0x8CA9, 0);
    // Flip Y cleanly because row 0 of D3D11 FBO texture is TOP whereas X11 default GL backbuffer row 0 is BOTTOM!
    gl.glBlitFramebuffer(0, 0, @intCast(t.width), @intCast(t.height), 0, @intCast(dst_h), @intCast(dst_w), 0, 0x4000, 0x2601);
    gl.glBindFramebuffer(0x8CA8, 0);

    if (g_lost_window.load(.acquire) == g_gl_window) return; // window destroyed: nothing to swap to
    if (p_swap_interval) |si| si(g_gl_display, g_gl_window, @intCast(@min(1, j.sync_interval)));
    glx.glXSwapBuffers(g_gl_display, g_gl_window);
}

pub fn present(backbuffer: *Texture, hwnd: usize, sync_interval: u32) void {
    var j: PresentJob = .{ .backbuffer = backbuffer, .hwnd = hwnd, .sync_interval = sync_interval };
    run(&presentJob, &j);
}

test "staging upload covers the whole A8 atlas when no box is given" {
    // Cuphead's 1024x1024 A8 font atlas: Map staging (pitch 1024), CopySubresourceRegion(box=null).
    const r = stagingRegion(1024, 1024, 1024, 1024 * 1024, false, 1, false, .{0} ** 6).?;
    try std.testing.expectEqual(@as(usize, 0), r.first);
    try std.testing.expectEqual(@as(usize, 1024), r.rows);
    try std.testing.expectEqual(@as(usize, 1024), r.row_bytes);
    try std.testing.expectEqual(@as(u32, 1024), r.w);
}

test "staging upload of a boxed RGBA8 region starts at the box corner" {
    // 64x32 RGBA8 staging, pitch 256 bytes; box x=[8,24) y=[4,10).
    const r = stagingRegion(64, 32, 256, 256 * 32, false, 4, true, .{ 8, 4, 0, 24, 10, 1 }).?;
    try std.testing.expectEqual(@as(usize, 4 * 256 + 8 * 4), r.first);
    try std.testing.expectEqual(@as(usize, 6), r.rows);
    try std.testing.expectEqual(@as(usize, 16 * 4), r.row_bytes);
    try std.testing.expectEqual(@as(u32, 16), r.w);
    try std.testing.expectEqual(@as(u32, 6), r.h);
}

test "staging upload of a compressed region counts 4x4 block rows" {
    // 128x128 BC3 (16-byte blocks): pitch 32 blocks * 16 = 512; box x=[16,48) y=[8,24).
    const r = stagingRegion(128, 128, 512, 512 * 32, true, 16, true, .{ 16, 8, 0, 48, 24, 1 }).?;
    try std.testing.expectEqual(@as(usize, 2 * 512 + 4 * 16), r.first);
    try std.testing.expectEqual(@as(usize, 4), r.rows);
    try std.testing.expectEqual(@as(usize, 8 * 16), r.row_bytes);
}

test "staging upload rejects empty boxes and regions past the shadow" {
    try std.testing.expect(stagingRegion(64, 64, 64, 64 * 64, false, 1, true, .{ 10, 0, 0, 10, 64, 1 }) == null);
    // Negative control: a shadow one byte short of the last row must be refused.
    try std.testing.expect(stagingRegion(64, 64, 64, 64 * 64 - 1, false, 1, false, .{0} ** 6) == null);
    try std.testing.expect(stagingRegion(64, 64, 0, 64 * 64, false, 1, false, .{0} ** 6) == null);
    // A box larger than the texture is clamped, not read out of bounds.
    const r = stagingRegion(64, 64, 64, 64 * 64, false, 1, true, .{ 32, 32, 0, 999, 999, 1 }).?;
    try std.testing.expectEqual(@as(u32, 32), r.w);
    try std.testing.expectEqual(@as(u32, 32), r.h);
}
