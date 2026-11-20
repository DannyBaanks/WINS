const std = @import("std");
const glb = @import("wins_d3d11_gl.zig");
const shader = @import("wins_d3d11_shader.zig");
const gui = @import("winrun_gui_support.zig");

const alloc = std.heap.page_allocator;
const W = std.builtin.CallingConvention.winapi;

const S_OK: i32 = 0;
const S_FALSE: i32 = 1;
const E_NOINTERFACE: i32 = @bitCast(@as(u32, 0x80004002));
const E_FAIL: i32 = @bitCast(@as(u32, 0x80004005));
const E_INVALIDARG: i32 = @bitCast(@as(u32, 0x80070057));
const E_NOTIMPL: i32 = @bitCast(@as(u32, 0x80004001));
const DXGI_ERROR_NOT_FOUND: i32 = @bitCast(@as(u32, 0x887A0002));
const DXGI_ERROR_MORE_DATA: i32 = @bitCast(@as(u32, 0x887A0003));
const D3D_FEATURE_LEVEL_11_0: u32 = 0xb000;

var g_trace_init = false;
var g_trace_on = false;
fn trace(comptime fmt: []const u8, args: anytype) void {
    if (!g_trace_init) {
        g_trace_init = true;
        g_trace_on = if (comptime @import("builtin").link_libc) std.c.getenv("WINS_TRACE") != null else false;
    }
    if (g_trace_on) std.debug.print("[WINS:D3D11] " ++ fmt ++ "\n", args);
}

/// WINS_D3D11_TRACE_FMT=<dxgi format>: log every create/update/map/copy that
/// touches a texture of that format (diagnostic; off by default).
fn traceFmtOn(fmt_id: u32) bool {
    const C = struct { var init = false; var want: ?u32 = null; };
    if (!C.init) {
        C.init = true;
        if (comptime @import("builtin").link_libc) {
            if (std.c.getenv("WINS_D3D11_TRACE_FMT")) |z| C.want = std.fmt.parseInt(u32, std.mem.span(z), 10) catch null;
        }
    }
    return C.want != null and C.want.? == fmt_id;
}

fn traceFmt(fmt_id: u32, comptime fmt: []const u8, args: anytype) void {
    if (!traceFmtOn(fmt_id)) return;
    std.debug.print("[WINS:TEXFMT] " ++ fmt ++ "\n", args);
}

fn nonzeroBytes(p: ?*const anyopaque, n: usize) usize {
    const b: [*]const u8 = @ptrCast(p orelse return 0);
    var c: usize = 0;
    for (b[0..n]) |x| c += @intFromBool(x != 0);
    return c;
}

// ---- Win64 COM Types --------------------------------------------------------

pub const GUID = extern struct {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [8]u8,
};

fn eqlGuid(a: *const GUID, b: *const GUID) bool {
    return a.data1 == b.data1 and a.data2 == b.data2 and a.data3 == b.data3 and std.mem.eql(u8, &a.data4, &b.data4);
}

const IID_IUnknown = GUID{ .data1 = 0x00000000, .data2 = 0x0000, .data3 = 0x0000, .data4 = .{ 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
const IID_IDXGIFactory = GUID{ .data1 = 0x7b7166ec, .data2 = 0x21c7, .data3 = 0x44ae, .data4 = .{ 0xb2, 0x1a, 0xc9, 0xae, 0x32, 0x1a, 0xe3, 0x69 } };
const IID_IDXGIFactory1 = GUID{ .data1 = 0x770aae78, .data2 = 0xf26f, .data3 = 0x4dba, .data4 = .{ 0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87 } };
const IID_IDXGIAdapter = GUID{ .data1 = 0x2411e7e1, .data2 = 0x12ac, .data3 = 0x4ccf, .data4 = .{ 0xbd, 0x14, 0x97, 0x98, 0xe8, 0x53, 0x4d, 0xc0 } };
const IID_IDXGIAdapter1 = GUID{ .data1 = 0x29038f61, .data2 = 0x3839, .data3 = 0x4626, .data4 = .{ 0x91, 0xfd, 0x08, 0x68, 0x79, 0x01, 0x1a, 0x05 } };
const IID_IDXGIOutput = GUID{ .data1 = 0xae02eedb, .data2 = 0xc735, .data3 = 0x4690, .data4 = .{ 0x8d, 0x52, 0x5a, 0x8d, 0xc2, 0x02, 0x13, 0xaa } };
const IID_IDXGIDevice = GUID{ .data1 = 0x54ec77fa, .data2 = 0x1377, .data3 = 0x44e6, .data4 = .{ 0x8c, 0x32, 0x88, 0xfd, 0x5f, 0x44, 0xc8, 0x4c } };
const IID_IDXGIDevice1 = GUID{ .data1 = 0x77db970f, .data2 = 0x6276, .data3 = 0x48ba, .data4 = .{ 0xba, 0x28, 0x07, 0x01, 0x43, 0xb4, 0x39, 0x2c } };
const IID_IDXGISwapChain = GUID{ .data1 = 0x310d36a0, .data2 = 0xd2e7, .data3 = 0x4c0a, .data4 = .{ 0xaa, 0x04, 0x6a, 0x9d, 0x23, 0xb8, 0x88, 0x6a } };
const IID_ID3D11Device = GUID{ .data1 = 0xdb6f6ddb, .data2 = 0xac77, .data3 = 0x4e88, .data4 = .{ 0x82, 0x53, 0x81, 0x9d, 0xf9, 0xbb, 0xf1, 0x40 } };
const IID_ID3D11DeviceContext = GUID{ .data1 = 0xc0bfa96c, .data2 = 0xe089, .data3 = 0x44fb, .data4 = .{ 0x8e, 0xaf, 0x26, 0xf8, 0x79, 0x61, 0x90, 0xda } };
const IID_ID3D11Texture2D = GUID{ .data1 = 0x6f15aaf2, .data2 = 0xd208, .data3 = 0x4e89, .data4 = .{ 0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c } };
const IID_ID3D11Texture1D = GUID{ .data1 = 0xf8fb5c27, .data2 = 0xc6b3, .data3 = 0x4f75, .data4 = .{ 0xa4, 0xc8, 0x43, 0x9a, 0xf2, 0xef, 0x56, 0x4c } };
const IID_ID3D11Texture3D = GUID{ .data1 = 0x037e866e, .data2 = 0xf56d, .data3 = 0x4357, .data4 = .{ 0xa8, 0xaf, 0x9d, 0xab, 0xbe, 0x6e, 0x25, 0x0e } };
const IID_ID3D11Buffer = GUID{ .data1 = 0x48570b85, .data2 = 0xd1ee, .data3 = 0x4fcd, .data4 = .{ 0xa2, 0x50, 0xeb, 0x35, 0x07, 0x22, 0xb0, 0x37 } };
const IID_ID3D11Resource = GUID{ .data1 = 0xdc8e63f3, .data2 = 0xd12b, .data3 = 0x4952, .data4 = .{ 0xb4, 0x7b, 0x5e, 0x45, 0x02, 0x6a, 0x86, 0x2d } };

const DXGI_RATIONAL = extern struct { Numerator: u32, Denominator: u32 };
const DXGI_SAMPLE_DESC = extern struct { Count: u32, Quality: u32 };
const DXGI_MODE_DESC = extern struct {
    Width: u32,
    Height: u32,
    RefreshRate: DXGI_RATIONAL,
    Format: u32,
    ScanlineOrdering: u32,
    Scaling: u32,
};

const DXGI_SWAP_CHAIN_DESC = extern struct {
    BufferDesc: DXGI_MODE_DESC,
    SampleDesc: DXGI_SAMPLE_DESC,
    BufferUsage: u32,
    BufferCount: u32,
    OutputWindow: usize,
    Windowed: i32,
    SwapEffect: u32,
    Flags: u32,
};

const DXGI_ADAPTER_DESC = extern struct {
    Description: [128]u16,
    VendorId: u32,
    DeviceId: u32,
    SubSysId: u32,
    Revision: u32,
    DedicatedVideoMemory: usize,
    DedicatedSystemMemory: usize,
    SharedSystemMemory: usize,
    AdapterLuid: u64,
};

const DXGI_ADAPTER_DESC1 = extern struct {
    Description: [128]u16,
    VendorId: u32,
    DeviceId: u32,
    SubSysId: u32,
    Revision: u32,
    DedicatedVideoMemory: usize,
    DedicatedSystemMemory: usize,
    SharedSystemMemory: usize,
    AdapterLuid: u64,
    Flags: u32,
};

const RECT = extern struct { left: i32, top: i32, right: i32, bottom: i32 };
const DXGI_OUTPUT_DESC = extern struct {
    DeviceName: [32]u16,
    DesktopCoordinates: RECT,
    AttachedToDesktop: i32,
    Rotation: u32,
    Monitor: usize,
};

const D3D11_BUFFER_DESC = extern struct {
    ByteWidth: u32,
    Usage: u32,
    BindFlags: u32,
    CPUAccessFlags: u32,
    MiscFlags: u32,
    StructureByteStride: u32,
};

const D3D11_TEXTURE2D_DESC = extern struct {
    Width: u32,
    Height: u32,
    MipLevels: u32,
    ArraySize: u32,
    Format: u32,
    SampleDesc: DXGI_SAMPLE_DESC,
    Usage: u32,
    BindFlags: u32,
    CPUAccessFlags: u32,
    MiscFlags: u32,
};

const D3D11_TEXTURE1D_DESC = extern struct {
    Width: u32,
    MipLevels: u32,
    ArraySize: u32,
    Format: u32,
    Usage: u32,
    BindFlags: u32,
    CPUAccessFlags: u32,
    MiscFlags: u32,
};

const D3D11_TEXTURE3D_DESC = extern struct {
    Width: u32,
    Height: u32,
    Depth: u32,
    MipLevels: u32,
    Format: u32,
    Usage: u32,
    BindFlags: u32,
    CPUAccessFlags: u32,
    MiscFlags: u32,
};

const D3D11_SUBRESOURCE_DATA = extern struct {
    pSysMem: ?*const anyopaque,
    SysMemPitch: u32,
    SysMemSlicePitch: u32,
};

const D3D11_MAPPED_SUBRESOURCE = extern struct {
    pData: ?*anyopaque,
    RowPitch: u32,
    DepthPitch: u32,
};

const D3D11_BOX = extern struct { left: u32, top: u32, front: u32, right: u32, bottom: u32, back: u32 };
const D3D11_VIEWPORT = extern struct { TopLeftX: f32, TopLeftY: f32, Width: f32, Height: f32, MinDepth: f32, MaxDepth: f32 };

const D3D11_INPUT_ELEMENT_DESC = extern struct {
    SemanticName: ?[*:0]const u8,
    SemanticIndex: u32,
    Format: u32,
    InputSlot: u32,
    AlignedByteOffset: u32,
    InputSlotClass: u32,
    InstanceDataStepRate: u32,
};

const D3D11_RENDER_TARGET_BLEND_DESC = extern struct {
    BlendEnable: i32,
    SrcBlend: u32,
    DestBlend: u32,
    BlendOp: u32,
    SrcBlendAlpha: u32,
    DestBlendAlpha: u32,
    BlendOpAlpha: u32,
    RenderTargetWriteMask: u8,
};

const D3D11_BLEND_DESC = extern struct {
    AlphaToCoverageEnable: i32,
    IndependentBlendEnable: i32,
    RenderTarget: [8]D3D11_RENDER_TARGET_BLEND_DESC,
};

const D3D11_DEPTH_STENCILOP_DESC = extern struct {
    StencilFailOp: u32,
    StencilDepthFailOp: u32,
    StencilPassOp: u32,
    StencilFunc: u32,
};

const D3D11_DEPTH_STENCIL_DESC = extern struct {
    DepthEnable: i32,
    DepthWriteMask: u32,
    DepthFunc: u32,
    StencilEnable: i32,
    StencilReadMask: u8,
    StencilWriteMask: u8,
    FrontFace: D3D11_DEPTH_STENCILOP_DESC,
    BackFace: D3D11_DEPTH_STENCILOP_DESC,
};

const D3D11_RASTERIZER_DESC = extern struct {
    FillMode: u32,
    CullMode: u32,
    FrontCounterClockwise: i32,
    DepthBias: i32,
    DepthBiasClamp: f32,
    SlopeScaledDepthBias: f32,
    DepthClipEnable: i32,
    ScissorEnable: i32,
    MultisampleEnable: i32,
    AntialiasedLineEnable: i32,
};

const D3D11_SAMPLER_DESC = extern struct {
    Filter: u32,
    AddressU: u32,
    AddressV: u32,
    AddressW: u32,
    MipLODBias: f32,
    MaxAnisotropy: u32,
    ComparisonFunc: u32,
    BorderColor: [4]f32,
    MinLOD: f32,
    MaxLOD: f32,
};

const D3D11_RENDER_TARGET_VIEW_DESC = extern struct {
    Format: u32,
    ViewDimension: u32,
    u0: u32,
    u1: u32,
    u2: u32,
};

const D3D11_DEPTH_STENCIL_VIEW_DESC = extern struct {
    Format: u32,
    ViewDimension: u32,
    Flags: u32,
    u0: u32,
    u1: u32,
    u2: u32,
};

const D3D11_SHADER_RESOURCE_VIEW_DESC = extern struct {
    Format: u32,
    ViewDimension: u32,
    u0: u32,
    u1: u32,
    u2: u32,
    u3: u32,
};

// ---- Generic COM Wrappers ---------------------------------------------------

const ComObj = extern struct {
    lpVtbl: [*]const ?*const anyopaque,
    ref_count: u32 = 1,
    kind: Kind = .device,
    payload: usize = 0,
    parent: ?*ComObj = null,
    view_res: ?*ComObj = null,
    view_desc: [6]u32 = .{ 0, 0, 0, 0, 0, 0 },
    desc2d: D3D11_TEXTURE2D_DESC = std.mem.zeroes(D3D11_TEXTURE2D_DESC),
    desc1d: D3D11_TEXTURE1D_DESC = std.mem.zeroes(D3D11_TEXTURE1D_DESC),
    desc3d: D3D11_TEXTURE3D_DESC = std.mem.zeroes(D3D11_TEXTURE3D_DESC),
    descbuf: D3D11_BUFFER_DESC = std.mem.zeroes(D3D11_BUFFER_DESC),
    swap_desc: DXGI_SWAP_CHAIN_DESC = std.mem.zeroes(DXGI_SWAP_CHAIN_DESC),
    /// Copy of the creation desc for state objects and queries (GetDesc).
    desc_blob: ?[*]u8 = null,
    desc_len: usize = 0,

    const Kind = enum(u32) {
        factory,
        adapter,
        output,
        swapchain,
        device,
        dxgi_device,
        context,
        buffer,
        texture2d,
        texture1d,
        texture3d,
        rtv,
        dsv,
        srv,
        uav,
        input_layout,
        vs,
        ps,
        blend,
        depth_stencil,
        rasterizer,
        sampler,
        query,
        deferred_ctx,
        cmdlist,
    };
};

fn newCom(vtable: [*]const ?*const anyopaque, kind: ComObj.Kind, payload: usize, parent: ?*ComObj) ?*ComObj {
    const o = alloc.create(ComObj) catch return null;
    o.* = .{ .lpVtbl = vtable, .ref_count = 1, .kind = kind, .payload = payload, .parent = parent };
    return o;
}

fn comAddRef(raw: ?*anyopaque) callconv(W) u32 {
    const o: *ComObj = @ptrCast(@alignCast(raw orelse return 0));
    return @atomicRmw(u32, &o.ref_count, .Add, 1, .acq_rel) + 1;
}

fn comRelease(raw: ?*anyopaque) callconv(W) u32 {
    const o: *ComObj = @ptrCast(@alignCast(raw orelse return 0));
    const prev = @atomicRmw(u32, &o.ref_count, .Sub, 1, .acq_rel);
    if (prev == 1) {
        if (o.desc_blob) |b| alloc.free(b[0..o.desc_len]);
        switch (o.kind) {
            .buffer => if (o.payload != 0) {
                const b: *glb.Buffer = @ptrFromInt(o.payload);
                glb.destroyBuffer(b);
                alloc.destroy(b);
            },
            .texture2d, .texture1d, .texture3d => if (o.payload != 0) {
                const t: *glb.Texture = @ptrFromInt(o.payload);
                glb.destroyTexture(t);
                alloc.destroy(t);
            },
            .deferred_ctx => if (o.payload != 0) {
                const r: *Recorder = @ptrFromInt(o.payload);
                r.reset();
                r.arena.deinit();
                alloc.destroy(r);
            },
            .cmdlist => if (o.payload != 0) destroyCmdList(@ptrFromInt(o.payload)),
            .rtv, .dsv, .srv, .uav => if (o.payload != 0) {
                const v: *glb.View = @ptrFromInt(o.payload);
                alloc.destroy(v);
            },
            .vs, .ps => if (o.payload != 0) {
                const s: *glb.Shader = @ptrFromInt(o.payload);
                glb.destroyShader(s);
                alloc.destroy(s);
            },
            .sampler => if (o.payload != 0) {
                const sm: *glb.Sampler = @ptrFromInt(o.payload);
                glb.destroySampler(sm);
                alloc.destroy(sm);
            },
            else => {},
        }
        alloc.destroy(o);
    }
    return prev -| 1;
}

fn comQiDefault(raw: ?*anyopaque, riid: *const GUID, ppv: *?*anyopaque) callconv(W) i32 {
    const o: *ComObj = @ptrCast(@alignCast(raw orelse return E_INVALIDARG));
    if (eqlGuid(riid, &IID_IUnknown)) {
        _ = comAddRef(raw);
        ppv.* = raw;
        return S_OK;
    }
    if (o.kind == .device and (eqlGuid(riid, &IID_IDXGIDevice) or eqlGuid(riid, &IID_IDXGIDevice1))) {
        const dxdev = newCom(&dxgi_device_vtbl, .dxgi_device, @intFromPtr(o), o) orelse return E_FAIL;
        ppv.* = dxdev;
        return S_OK;
    }
    if (o.kind == .device and eqlGuid(riid, &IID_ID3D11Device)) {
        _ = comAddRef(raw);
        ppv.* = raw;
        return S_OK;
    }
    if ((o.kind == .context or o.kind == .deferred_ctx) and eqlGuid(riid, &IID_ID3D11DeviceContext)) {
        _ = comAddRef(raw);
        ppv.* = raw;
        return S_OK;
    }
    if (o.kind == .factory and (eqlGuid(riid, &IID_IDXGIFactory) or eqlGuid(riid, &IID_IDXGIFactory1))) {
        _ = comAddRef(raw);
        ppv.* = raw;
        return S_OK;
    }
    if (o.kind == .adapter and (eqlGuid(riid, &IID_IDXGIAdapter) or eqlGuid(riid, &IID_IDXGIAdapter1))) {
        _ = comAddRef(raw);
        ppv.* = raw;
        return S_OK;
    }
    if (o.kind == .swapchain and eqlGuid(riid, &IID_IDXGISwapChain)) {
        _ = comAddRef(raw);
        ppv.* = raw;
        return S_OK;
    }
    if (o.kind == .texture2d and (eqlGuid(riid, &IID_ID3D11Texture2D) or eqlGuid(riid, &IID_ID3D11Resource))) {
        _ = comAddRef(raw);
        ppv.* = raw;
        return S_OK;
    }
    if ((o.kind == .texture1d and (eqlGuid(riid, &IID_ID3D11Texture1D) or eqlGuid(riid, &IID_ID3D11Resource))) or
        (o.kind == .texture3d and (eqlGuid(riid, &IID_ID3D11Texture3D) or eqlGuid(riid, &IID_ID3D11Resource))))
    {
        _ = comAddRef(raw);
        ppv.* = raw;
        return S_OK;
    }
    if (o.kind == .buffer and (eqlGuid(riid, &IID_ID3D11Buffer) or eqlGuid(riid, &IID_ID3D11Resource))) {
        _ = comAddRef(raw);
        ppv.* = raw;
        return S_OK;
    }
    ppv.* = null;
    return E_NOINTERFACE;
}

fn stubRetOk() callconv(W) i32 { return S_OK; }

/// Device creation methods WINS does not implement: fail with E_NOTIMPL and a
/// NULL object (reported once per method) instead of S_OK with no object.
fn notImplCreate(comptime name: []const u8, comptime out_index: usize) *const anyopaque {
    return @ptrCast(&struct {
        var told = std.atomic.Value(bool).init(false);
        fn f(a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) callconv(W) i32 {
            const args = [_]usize{ a1, a2, a3, a4, a5 };
            if (args[out_index] != 0) @as(*usize, @ptrFromInt(args[out_index])).* = 0;
            if (!told.swap(true, .monotonic)) std.debug.print("[WINS:D3D11] {s} is not implemented (E_NOTIMPL)\n", .{name});
            return E_NOTIMPL;
        }
    }.f);
}
fn stubVoid() callconv(W) void {}
fn stubRetZero() callconv(W) u32 { return 0; }
fn dxgiGetParent(raw: ?*anyopaque, riid: *const GUID, pp: *?*anyopaque) callconv(W) i32 {
    const o: *ComObj = @ptrCast(@alignCast(raw orelse return E_INVALIDARG));
    if (o.parent) |p| return comQiDefault(p, riid, pp);
    if (eqlGuid(riid, &IID_IDXGIFactory) or eqlGuid(riid, &IID_IDXGIFactory1)) {
        pp.* = getSingletonFactory();
        _ = comAddRef(pp.*);
        return S_OK;
    }
    pp.* = null;
    return E_NOINTERFACE;
}

// ---- Singletons -------------------------------------------------------------

var g_factory: ?*ComObj = null;
var g_adapter: ?*ComObj = null;
var g_output: ?*ComObj = null;
var g_context: ?*ComObj = null;
var g_device: ?*ComObj = null;
var g_draw_state: glb.DrawState = .{};

fn getSingletonFactory() *ComObj {
    if (g_factory) |f| return f;
    g_factory = newCom(&dxgi_factory_vtbl, .factory, 0, null).?;
    return g_factory.?;
}

fn getSingletonAdapter() *ComObj {
    if (g_adapter) |a| return a;
    g_adapter = newCom(&dxgi_adapter_vtbl, .adapter, 0, getSingletonFactory()).?;
    return g_adapter.?;
}

fn getSingletonOutput() *ComObj {
    if (g_output) |o| return o;
    g_output = newCom(&dxgi_output_vtbl, .output, 0, getSingletonAdapter()).?;
    return g_output.?;
}

// ---- DXGI Factory / Adapter / Output / Device / SwapChain ------------------

fn facEnumAdapters(_: ?*anyopaque, idx: u32, pp: *?*anyopaque) callconv(W) i32 {
    if (idx != 0) {
        pp.* = null;
        return DXGI_ERROR_NOT_FOUND;
    }
    const ad = getSingletonAdapter();
    _ = comAddRef(ad);
    pp.* = ad;
    return S_OK;
}

fn facCreateSwapChain(_: ?*anyopaque, pDev: ?*anyopaque, pDesc: *const DXGI_SWAP_CHAIN_DESC, ppSc: *?*anyopaque) callconv(W) i32 {
    _ = pDev;
    const w = if (pDesc.BufferDesc.Width > 0) pDesc.BufferDesc.Width else 1280;
    const h = if (pDesc.BufferDesc.Height > 0) pDesc.BufferDesc.Height else 720;
    const fmt = if (pDesc.BufferDesc.Format != 0) pDesc.BufferDesc.Format else 28;
    trace("CreateSwapChain hwnd=0x{x} {d}x{d} fmt={d}", .{ pDesc.OutputWindow, w, h, fmt });
    _ = glb.init(pDesc.OutputWindow, w, h);

    const bb_tex = alloc.create(glb.Texture) catch return E_FAIL;
    bb_tex.* = .{};
    glb.createSwapchainBackbuffer(bb_tex, w, h, fmt);

    const bb_obj = newCom(&tex2d_vtbl, .texture2d, @intFromPtr(bb_tex), g_device) orelse return E_FAIL;
    bb_obj.desc2d = .{
        .Width = w, .Height = h, .MipLevels = 1, .ArraySize = 1, .Format = fmt,
        .SampleDesc = .{ .Count = 1, .Quality = 0 }, .Usage = 0, .BindFlags = 0x28, .CPUAccessFlags = 0, .MiscFlags = 0,
    };

    const sc = newCom(&swapchain_vtbl, .swapchain, @intFromPtr(bb_obj), g_device) orelse return E_FAIL;
    sc.swap_desc = pDesc.*;
    sc.swap_desc.BufferDesc.Width = w;
    sc.swap_desc.BufferDesc.Height = h;
    sc.swap_desc.BufferDesc.Format = fmt;
    ppSc.* = sc;
    return S_OK;
}

fn facIsCurrent(_: ?*anyopaque) callconv(W) i32 { return 1; }

fn adEnumOutputs(_: ?*anyopaque, idx: u32, pp: *?*anyopaque) callconv(W) i32 {
    if (idx != 0) {
        pp.* = null;
        return DXGI_ERROR_NOT_FOUND;
    }
    const out = getSingletonOutput();
    _ = comAddRef(out);
    pp.* = out;
    return S_OK;
}

fn writeUtf16Ascii(dst: []u16, s: []const u8) void {
    @memset(dst, 0);
    for (s[0..@min(dst.len - 1, s.len)], 0..) |c, i| dst[i] = c;
}

fn adGetDesc(_: ?*anyopaque, pDesc: *DXGI_ADAPTER_DESC) callconv(W) i32 {
    pDesc.* = std.mem.zeroes(DXGI_ADAPTER_DESC);
    writeUtf16Ascii(&pDesc.Description, "WINS OpenGL Core Direct3D11 Adapter");
    pDesc.VendorId = 0x10DE;
    pDesc.DeviceId = 0x2684;
    pDesc.DedicatedVideoMemory = 2048 * 1024 * 1024;
    pDesc.SharedSystemMemory = 2048 * 1024 * 1024;
    pDesc.AdapterLuid = 0x1001;
    return S_OK;
}

fn adGetDesc1(_: ?*anyopaque, pDesc: *DXGI_ADAPTER_DESC1) callconv(W) i32 {
    pDesc.* = std.mem.zeroes(DXGI_ADAPTER_DESC1);
    writeUtf16Ascii(&pDesc.Description, "WINS OpenGL Core Direct3D11 Adapter");
    pDesc.VendorId = 0x10DE;
    pDesc.DeviceId = 0x2684;
    pDesc.DedicatedVideoMemory = 2048 * 1024 * 1024;
    pDesc.SharedSystemMemory = 2048 * 1024 * 1024;
    pDesc.AdapterLuid = 0x1001;
    pDesc.Flags = 0;
    return S_OK;
}

fn adCheckInterface(_: ?*anyopaque, _: *const GUID, pVer: ?*i64) callconv(W) i32 {
    if (pVer) |p| p.* = 0x0009001200000000;
    return S_OK;
}

fn outGetDesc(_: ?*anyopaque, pDesc: *DXGI_OUTPUT_DESC) callconv(W) i32 {
    pDesc.* = std.mem.zeroes(DXGI_OUTPUT_DESC);
    writeUtf16Ascii(&pDesc.DeviceName, "\\\\.\\DISPLAY1");
    pDesc.DesktopCoordinates = .{ .left = 0, .top = 0, .right = 1920, .bottom = 1080 };
    pDesc.AttachedToDesktop = 1;
    pDesc.Rotation = 1;
    return S_OK;
}

const g_modes = [_]DXGI_MODE_DESC{
    .{ .Width = 1280, .Height = 720, .RefreshRate = .{ .Numerator = 60, .Denominator = 1 }, .Format = 28, .ScanlineOrdering = 0, .Scaling = 0 },
    .{ .Width = 1920, .Height = 1080, .RefreshRate = .{ .Numerator = 60, .Denominator = 1 }, .Format = 28, .ScanlineOrdering = 0, .Scaling = 0 },
    .{ .Width = 800, .Height = 600, .RefreshRate = .{ .Numerator = 60, .Denominator = 1 }, .Format = 28, .ScanlineOrdering = 0, .Scaling = 0 },
};

fn outGetDisplayModeList(_: ?*anyopaque, fmt: u32, _: u32, pNum: *u32, pDesc: ?[*]DXGI_MODE_DESC) callconv(W) i32 {
    if (pDesc == null) {
        pNum.* = g_modes.len;
        return S_OK;
    }
    const n = @min(pNum.*, g_modes.len);
    for (0..n) |i| {
        pDesc.?[i] = g_modes[i];
        pDesc.?[i].Format = if (fmt != 0) fmt else 28;
    }
    pNum.* = @intCast(n);
    return S_OK;
}

fn outFindClosestMode(_: ?*anyopaque, match: *const DXGI_MODE_DESC, closest: *DXGI_MODE_DESC, _: ?*anyopaque) callconv(W) i32 {
    closest.* = match.*;
    if (closest.Width == 0) closest.Width = 1280;
    if (closest.Height == 0) closest.Height = 720;
    if (closest.RefreshRate.Numerator == 0) closest.RefreshRate = .{ .Numerator = 60, .Denominator = 1 };
    if (closest.Format == 0) closest.Format = 28;
    return S_OK;
}

fn dxgidevGetAdapter(_: ?*anyopaque, pp: *?*anyopaque) callconv(W) i32 {
    const ad = getSingletonAdapter();
    _ = comAddRef(ad);
    pp.* = ad;
    return S_OK;
}

fn scGetDevice(_: ?*anyopaque, riid: *const GUID, pp: *?*anyopaque) callconv(W) i32 {
    if (g_device) |d| return comQiDefault(d, riid, pp);
    pp.* = null;
    return E_NOINTERFACE;
}

var present_count: u32 = 0;

fn scPresent(raw: ?*anyopaque, sync: u32, _: u32) callconv(W) i32 {
    const sc: *ComObj = @ptrCast(@alignCast(raw orelse return E_INVALIDARG));
    const bb_obj: *ComObj = @ptrFromInt(sc.payload);
    const bb_tex: *glb.Texture = @ptrFromInt(bb_obj.payload);
    glb.present(bb_tex, sc.swap_desc.OutputWindow, sync);
    present_count += 1;
    @import("winrun_seh64.zig").maybeArmStep(present_count);
    return S_OK;
}

fn scGetBuffer(raw: ?*anyopaque, idx: u32, riid: *const GUID, pp: *?*anyopaque) callconv(W) i32 {
    if (idx != 0) {
        pp.* = null;
        return E_INVALIDARG;
    }
    const sc: *ComObj = @ptrCast(@alignCast(raw orelse return E_INVALIDARG));
    const bb_obj: *ComObj = @ptrFromInt(sc.payload);
    return comQiDefault(bb_obj, riid, pp);
}

fn scGetDesc(raw: ?*anyopaque, pDesc: *DXGI_SWAP_CHAIN_DESC) callconv(W) i32 {
    const sc: *ComObj = @ptrCast(@alignCast(raw orelse return E_INVALIDARG));
    pDesc.* = sc.swap_desc;
    return S_OK;
}

fn scResizeBuffers(raw: ?*anyopaque, _: u32, w: u32, h: u32, fmt: u32, _: u32) callconv(W) i32 {
    const sc: *ComObj = @ptrCast(@alignCast(raw orelse return E_INVALIDARG));
    const bb_obj: *ComObj = @ptrFromInt(sc.payload);
    const bb_tex: *glb.Texture = @ptrFromInt(bb_obj.payload);
    const nw = if (w > 0) w else @max(1, sc.swap_desc.BufferDesc.Width);
    const nh = if (h > 0) h else @max(1, sc.swap_desc.BufferDesc.Height);
    if (fmt != 0) bb_tex.dxgi_fmt = fmt;
    sc.swap_desc.BufferDesc.Width = nw;
    sc.swap_desc.BufferDesc.Height = nh;
    bb_obj.desc2d.Width = nw;
    bb_obj.desc2d.Height = nh;
    glb.resizeSwapchainBackbuffer(bb_tex, nw, nh);
    return S_OK;
}

// ---- ID3D11Device Implementation --------------------------------------------

fn devCreateBuffer(_: ?*anyopaque, desc: *const D3D11_BUFFER_DESC, init_data: ?*const D3D11_SUBRESOURCE_DATA, pp: ?*?*anyopaque) callconv(W) i32 {
    if (pp == null) return S_FALSE;
    const b = alloc.create(glb.Buffer) catch return E_FAIL;
    b.* = .{
        .size = @max(1, desc.ByteWidth),
        .bind_flags = desc.BindFlags,
        .usage = desc.Usage,
        .cpu_access = desc.CPUAccessFlags,
    };
    const p_mem: ?[*]const u8 = if (init_data) |id| (if (id.pSysMem) |m| @ptrCast(m) else null) else null;
    glb.createBuffer(b, p_mem);
    const o = newCom(&buf_vtbl, .buffer, @intFromPtr(b), g_device) orelse return E_FAIL;
    o.descbuf = desc.*;
    pp.?.* = o;
    return S_OK;
}

fn devCreateTexture2D(_: ?*anyopaque, desc: *const D3D11_TEXTURE2D_DESC, init_data: ?[*]const D3D11_SUBRESOURCE_DATA, pp: ?*?*anyopaque) callconv(W) i32 {
    if (pp == null) return S_FALSE;
    const t = alloc.create(glb.Texture) catch return E_FAIL;
    const is_cube = (desc.MiscFlags & 4) != 0;
    t.* = .{
        .width = desc.Width,
        .height = desc.Height,
        .mip_levels = desc.MipLevels,
        .array_size = desc.ArraySize,
        .dxgi_fmt = desc.Format,
        .bind_flags = desc.BindFlags,
        .usage = desc.Usage,
        .cpu_access = desc.CPUAccessFlags,
        .target = if (is_cube) 0x8513 else if (desc.ArraySize > 1) 0x8C1A else 0x0DE1,
    };
    var ptrs_buf: [64]?*const anyopaque = [_]?*const anyopaque{null} ** 64;
    var pitch_buf: [64]u32 = [_]u32{0} ** 64;
    var has_init = false;
    if (init_data) |subs| {
        const nmips = if (desc.MipLevels == 0) 1 else desc.MipLevels;
        const nsubs = @min(64, nmips * @max(1, desc.ArraySize));
        for (0..nsubs) |i| {
            ptrs_buf[i] = subs[i].pSysMem;
            pitch_buf[i] = subs[i].SysMemPitch;
        }
        has_init = true;
    }
    traceFmt(desc.Format, "create {d}x{d} mips={d} arr={d} usage={d} cpu=0x{x} bind=0x{x} misc=0x{x} init={} pitch0={d} nz0={d}", .{
        desc.Width, desc.Height, desc.MipLevels, desc.ArraySize, desc.Usage, desc.CPUAccessFlags, desc.BindFlags, desc.MiscFlags,
        has_init, pitch_buf[0], if (has_init and traceFmtOn(desc.Format)) nonzeroBytes(ptrs_buf[0], @as(usize, pitch_buf[0]) * desc.Height) else 0,
    });
    glb.createTexture2D(t, if (has_init) &ptrs_buf else null, if (has_init) &pitch_buf else null);
    const o = newCom(&tex2d_vtbl, .texture2d, @intFromPtr(t), g_device) orelse return E_FAIL;
    o.desc2d = desc.*;
    o.desc2d.MipLevels = t.mip_levels;
    pp.?.* = o;
    return S_OK;
}

fn collectInit(init_data: ?[*]const D3D11_SUBRESOURCE_DATA, nsubs_in: u32, ptrs: *[64]?*const anyopaque, pitches: *[64]u32, slices: *[64]u32) bool {
    const subs = init_data orelse return false;
    const nsubs = @min(64, nsubs_in);
    for (0..nsubs) |i| {
        ptrs[i] = subs[i].pSysMem;
        pitches[i] = subs[i].SysMemPitch;
        slices[i] = subs[i].SysMemSlicePitch;
    }
    return true;
}

fn devCreateTexture1D(_: ?*anyopaque, desc: *const D3D11_TEXTURE1D_DESC, init_data: ?[*]const D3D11_SUBRESOURCE_DATA, pp: ?*?*anyopaque) callconv(W) i32 {
    if (pp == null) return S_FALSE;
    const t = alloc.create(glb.Texture) catch return E_FAIL;
    t.* = .{
        .width = desc.Width,
        .height = 1,
        .mip_levels = desc.MipLevels,
        .array_size = @max(1, desc.ArraySize),
        .dxgi_fmt = desc.Format,
        .bind_flags = desc.BindFlags,
        .usage = desc.Usage,
        .cpu_access = desc.CPUAccessFlags,
        .target = if (desc.ArraySize > 1) 0x8C18 else 0x0DE0,
    };
    var ptrs: [64]?*const anyopaque = [_]?*const anyopaque{null} ** 64;
    var pitches: [64]u32 = [_]u32{0} ** 64;
    var slices: [64]u32 = [_]u32{0} ** 64;
    const nmips = if (desc.MipLevels == 0) 1 else desc.MipLevels;
    const has_init = collectInit(init_data, nmips * @max(1, desc.ArraySize), &ptrs, &pitches, &slices);
    traceFmt(desc.Format, "create1d {d} mips={d} arr={d} usage={d} bind=0x{x} init={}", .{ desc.Width, desc.MipLevels, desc.ArraySize, desc.Usage, desc.BindFlags, has_init });
    glb.createTexture(t, if (has_init) &ptrs else null, if (has_init) &pitches else null, null);
    const o = newCom(&tex1d_vtbl, .texture1d, @intFromPtr(t), g_device) orelse return E_FAIL;
    o.desc1d = desc.*;
    o.desc1d.MipLevels = t.mip_levels;
    pp.?.* = o;
    return S_OK;
}

fn devCreateTexture3D(_: ?*anyopaque, desc: *const D3D11_TEXTURE3D_DESC, init_data: ?[*]const D3D11_SUBRESOURCE_DATA, pp: ?*?*anyopaque) callconv(W) i32 {
    if (pp == null) return S_FALSE;
    const t = alloc.create(glb.Texture) catch return E_FAIL;
    t.* = .{
        .width = desc.Width,
        .height = desc.Height,
        .depth = desc.Depth,
        .mip_levels = desc.MipLevels,
        .array_size = 1,
        .dxgi_fmt = desc.Format,
        .bind_flags = desc.BindFlags,
        .usage = desc.Usage,
        .cpu_access = desc.CPUAccessFlags,
        .target = 0x806F,
    };
    var ptrs: [64]?*const anyopaque = [_]?*const anyopaque{null} ** 64;
    var pitches: [64]u32 = [_]u32{0} ** 64;
    var slices: [64]u32 = [_]u32{0} ** 64;
    const has_init = collectInit(init_data, if (desc.MipLevels == 0) 1 else desc.MipLevels, &ptrs, &pitches, &slices);
    traceFmt(desc.Format, "create3d {d}x{d}x{d} mips={d} usage={d} bind=0x{x} init={}", .{ desc.Width, desc.Height, desc.Depth, desc.MipLevels, desc.Usage, desc.BindFlags, has_init });
    glb.createTexture(t, if (has_init) &ptrs else null, if (has_init) &pitches else null, if (has_init) &slices else null);
    const o = newCom(&tex3d_vtbl, .texture3d, @intFromPtr(t), g_device) orelse return E_FAIL;
    o.desc3d = desc.*;
    o.desc3d.MipLevels = t.mip_levels;
    pp.?.* = o;
    return S_OK;
}

fn extractResTexture(res: ?*anyopaque) struct { tex: ?*glb.Texture, buf: ?*glb.Buffer } {
    const o: *ComObj = @ptrCast(@alignCast(res orelse return .{ .tex = null, .buf = null }));
    if (isTexKind(o.kind)) return .{ .tex = @ptrFromInt(o.payload), .buf = null };
    if (o.kind == .buffer) return .{ .tex = null, .buf = @ptrFromInt(o.payload) };
    return .{ .tex = null, .buf = null };
}

/// D3D stores a view desc canonicalised: union members the view dimension does
/// not use read back as 0, and an SRV's MipLevels = -1 ("all the rest") reads
/// back resolved. Titles parse GetDesc generically (DS3 takes desc+0xC as a mip
/// count even for a TEXTURE2D RTV), so stale caller bytes there are fatal.
fn normalizeViewDesc(kind: ComObj.Kind, vd: *[6]u32, tex: ?*glb.Texture) void {
    const dim = vd[1];
    // Index of the first union dword and how many the dimension uses.
    const first: usize = if (kind == .dsv) 3 else 2;
    const used: usize = switch (kind) {
        .rtv => switch (dim) { 1 => 2, 2, 4 => 1, 3, 5, 8 => 3, 7 => 2, else => 0 },
        .dsv => switch (dim) { 1, 3 => 1, 2, 4 => 3, 6 => 2, else => 0 },
        .srv => switch (dim) { 1, 2, 4, 7, 8, 9 => 2, 3, 5, 10 => 4, 11 => 3, else => 0 },
        else => 4,
    };
    for (first + used..6) |i| vd[i] = 0;
    if (kind == .srv and vd[3] == 0xFFFFFFFF) switch (dim) {
        2, 3, 4, 5, 8, 9, 10 => if (tex) |t| {
            vd[3] = @max(1, t.mip_levels) -| vd[2];
        },
        else => {},
    };
}

fn devCreateSRV(_: ?*anyopaque, res: ?*anyopaque, desc: ?*const D3D11_SHADER_RESOURCE_VIEW_DESC, pp: ?*?*anyopaque) callconv(W) i32 {
    if (pp == null) return S_FALSE;
    const r = extractResTexture(res);
    const v = alloc.create(glb.View) catch return E_FAIL;
    v.* = .{ .tex = r.tex, .buf = r.buf };
    var vd: [6]u32 = .{ if (r.tex) |t| t.dxgi_fmt else 28, 4, 0, if (r.tex) |t| t.mip_levels else 1, 0, 0 };
    if (desc) |d| {
        v.dxgi_fmt = d.Format;
        vd = .{ d.Format, d.ViewDimension, d.u0, d.u1, d.u2, d.u3 };
        if (d.ViewDimension == 4) { // TEXTURE2D
            v.first_mip = d.u0;
            v.num_mips = d.u1;
        }
    }
    const o = newCom(&view_vtbl, .srv, @intFromPtr(v), g_device) orelse return E_FAIL;
    if (res) |ro| {
        o.view_res = @ptrCast(@alignCast(ro));
        _ = comAddRef(ro);
    }
    normalizeViewDesc(.srv, &vd, r.tex);
    o.view_desc = vd;
    pp.?.* = o;
    return S_OK;
}

fn devCreateUAV(_: ?*anyopaque, res: ?*anyopaque, _: ?*const anyopaque, pp: ?*?*anyopaque) callconv(W) i32 {
    if (pp == null) return S_FALSE;
    const r = extractResTexture(res);
    const v = alloc.create(glb.View) catch return E_FAIL;
    v.* = .{ .tex = r.tex, .buf = r.buf };
    const o = newCom(&view_vtbl, .uav, @intFromPtr(v), g_device) orelse return E_FAIL;
    if (res) |ro| {
        o.view_res = @ptrCast(@alignCast(ro));
        _ = comAddRef(ro);
    }
    pp.?.* = o;
    return S_OK;
}

fn devCreateRTV(_: ?*anyopaque, res: ?*anyopaque, desc: ?*const D3D11_RENDER_TARGET_VIEW_DESC, pp: ?*?*anyopaque) callconv(W) i32 {
    if (pp == null) return S_FALSE;
    const r = extractResTexture(res);
    const v = alloc.create(glb.View) catch return E_FAIL;
    v.* = .{ .tex = r.tex, .buf = r.buf };
    var vd: [6]u32 = .{ if (r.tex) |t| t.dxgi_fmt else 28, 4, 0, 0, 0, 0 };
    if (desc) |d| {
        v.dxgi_fmt = d.Format;
        vd = .{ d.Format, d.ViewDimension, d.u0, d.u1, d.u2, 0 };
        switch (d.ViewDimension) {
            // TEXTURE1D, TEXTURE1DARRAY, TEXTURE2D, TEXTURE2DARRAY, TEXTURE3D (u1 = FirstWSlice)
            2, 3, 4, 5, 8 => {
                v.first_mip = d.u0;
                if (d.ViewDimension == 3 or d.ViewDimension == 5 or d.ViewDimension == 8) v.first_slice = d.u1;
            },
            else => {},
        }
    }
    const o = newCom(&view_vtbl, .rtv, @intFromPtr(v), g_device) orelse return E_FAIL;
    if (res) |ro| {
        o.view_res = @ptrCast(@alignCast(ro));
        _ = comAddRef(ro);
    }
    normalizeViewDesc(.rtv, &vd, r.tex);
    o.view_desc = vd;
    pp.?.* = o;
    return S_OK;
}

fn devCreateDSV(_: ?*anyopaque, res: ?*anyopaque, desc: ?*const D3D11_DEPTH_STENCIL_VIEW_DESC, pp: ?*?*anyopaque) callconv(W) i32 {
    if (pp == null) return S_FALSE;
    const r = extractResTexture(res);
    const v = alloc.create(glb.View) catch return E_FAIL;
    v.* = .{ .tex = r.tex, .buf = r.buf };
    var vd: [6]u32 = .{ if (r.tex) |t| t.dxgi_fmt else 45, 3, 0, 0, 0, 0 };
    if (desc) |d| {
        v.dxgi_fmt = d.Format;
        vd = .{ d.Format, d.ViewDimension, d.Flags, d.u0, d.u1, d.u2 };
        if (d.ViewDimension == 3 or d.ViewDimension == 4) { // TEXTURE2D / TEXTURE2DARRAY
            v.first_mip = d.u0;
            if (d.ViewDimension == 4) v.first_slice = d.u1;
        }
    }
    const o = newCom(&view_vtbl, .dsv, @intFromPtr(v), g_device) orelse return E_FAIL;
    if (res) |ro| {
        o.view_res = @ptrCast(@alignCast(ro));
        _ = comAddRef(ro);
    }
    normalizeViewDesc(.dsv, &vd, r.tex);
    o.view_desc = vd;
    pp.?.* = o;
    return S_OK;
}

fn devCreateInputLayout(_: ?*anyopaque, elems: [*]const D3D11_INPUT_ELEMENT_DESC, count: u32, bc: [*]const u8, bc_len: usize, pp: ?*?*anyopaque) callconv(W) i32 {
    if (pp == null) return S_FALSE;
    const sig = shader.parseInputSignature(alloc, bc[0..bc_len]) catch &[_]shader.SigElem{};
    defer if (sig.len > 0) alloc.free(sig);

    const il = alloc.create(glb.InputLayout) catch return E_FAIL;
    il.* = .{};
    var auto_off = [_]u32{0} ** 16;
    const n = @min(16, count);
    for (0..n) |i| {
        const e = elems[i];
        const info = glb.inputFormatToGl(e.Format);
        const slot = @min(15, e.InputSlot);
        const off = if (e.AlignedByteOffset == 0xFFFFFFFF) auto_off[slot] else e.AlignedByteOffset;
        auto_off[slot] = off + info.byte_size;

        var loc: u32 = @intCast(i);
        var matched = (sig.len == 0);
        if (e.SemanticName) |sname| {
            const sem = std.mem.sliceTo(sname, 0);
            for (sig) |se| {
                if (se.index == e.SemanticIndex and std.ascii.eqlIgnoreCase(se.name, sem)) {
                    loc = se.reg;
                    matched = true;
                    break;
                }
            }
        }
        if (!matched) continue;
        il.elems[il.count] = .{
            .location = loc,
            .components = info.components,
            .gl_type = info.gl_type,
            .normalized = info.normalized,
            .is_int = info.is_int,
            .slot = slot,
            .offset = off,
            .step_rate = e.InstanceDataStepRate,
            .is_instance = (e.InputSlotClass == 1),
        };
        il.count += 1;
    }
    pp.?.* = newCom(&child_vtbl, .input_layout, @intFromPtr(il), g_device);
    return S_OK;
}

fn devCreateVertexShader(_: ?*anyopaque, bc: [*]const u8, bc_len: usize, _: ?*anyopaque, pp: ?*?*anyopaque) callconv(W) i32 {
    if (pp == null) return S_FALSE;
    const sh = alloc.create(glb.Shader) catch return E_FAIL;
    sh.* = .{};
    _ = glb.createShader(sh, bc[0..bc_len], false);
    pp.?.* = newCom(&child_vtbl, .vs, @intFromPtr(sh), g_device);
    return S_OK;
}

fn devCreatePixelShader(_: ?*anyopaque, bc: [*]const u8, bc_len: usize, _: ?*anyopaque, pp: ?*?*anyopaque) callconv(W) i32 {
    if (pp == null) return S_FALSE;
    const sh = alloc.create(glb.Shader) catch return E_FAIL;
    sh.* = .{};
    _ = glb.createShader(sh, bc[0..bc_len], true);
    pp.?.* = newCom(&child_vtbl, .ps, @intFromPtr(sh), g_device);
    return S_OK;
}

fn devCreateDummyShader(_: ?*anyopaque, _: [*]const u8, _: usize, _: ?*anyopaque, pp: ?*?*anyopaque) callconv(W) i32 {
    if (pp == null) return S_FALSE;
    pp.?.* = newCom(&child_vtbl, .query, 0, g_device);
    return S_OK;
}

fn d3dBlendToGl(b: u32) glb.GLenum {
    return switch (b) {
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
        16 => 0x8003,
        17 => 0x8004,
        else => 1,
    };
}

fn d3dBlendOpToGl(op: u32) glb.GLenum {
    return switch (op) {
        2 => 0x800A,
        3 => 0x800B,
        4 => 0x8007,
        5 => 0x8008,
        else => 0x8006,
    };
}

fn d3dCmpToGl(f: u32) glb.GLenum {
    return if (f >= 1 and f <= 8) 0x0200 + (f - 1) else 0x0207;
}

fn d3dStencilOpToGl(op: u32) glb.GLenum {
    return switch (op) {
        2 => 0,
        3 => 0x1E01,
        4 => 0x1E02,
        5 => 0x1E03,
        6 => 0x150A,
        7 => 0x8507,
        8 => 0x8508,
        else => 0x1E00,
    };
}

/// newCom for objects whose GetDesc returns the creation desc verbatim.
fn newComWithDesc(vtable: [*]const ?*const anyopaque, kind: ComObj.Kind, payload: usize, desc: []const u8) ?*ComObj {
    const o = newCom(vtable, kind, payload, g_device) orelse return null;
    const b = alloc.alloc(u8, desc.len) catch return o;
    @memcpy(b, desc);
    o.desc_blob = b.ptr;
    o.desc_len = b.len;
    return o;
}

fn stateGetDesc(raw: ?*anyopaque, out: ?*anyopaque) callconv(W) void {
    const o: *ComObj = @ptrCast(@alignCast(raw orelse return));
    const dst: [*]u8 = @ptrCast(out orelse return);
    if (o.desc_blob) |b| @memcpy(dst[0..o.desc_len], b[0..o.desc_len]);
}

fn queryGetDataSize(raw: ?*anyopaque) callconv(W) u32 {
    const o: *ComObj = @ptrCast(@alignCast(raw orelse return 0));
    return switch (o.payload) { // D3D11_QUERY
        0, 7 => 4, // EVENT, OCCLUSION_PREDICATE (BOOL)
        1, 2 => 8, // OCCLUSION, TIMESTAMP
        3 => 16, // TIMESTAMP_DISJOINT
        4 => 88, // PIPELINE_STATISTICS
        5, 6 => 16, // SO_STATISTICS, SO_OVERFLOW_PREDICATE (approx.)
        else => 16,
    };
}

fn devCreateBlendState(_: ?*anyopaque, desc: *const D3D11_BLEND_DESC, pp: ?*?*anyopaque) callconv(W) i32 {
    if (pp == null) return S_FALSE;
    const bs = alloc.create(glb.BlendState) catch return E_FAIL;
    bs.* = .{
        .alpha_to_coverage = (desc.AlphaToCoverageEnable != 0),
        .independent = (desc.IndependentBlendEnable != 0),
    };
    for (0..8) |i| {
        const r = desc.RenderTarget[i];
        bs.rt[i] = .{
            .enable = (r.BlendEnable != 0),
            .src_rgb = d3dBlendToGl(r.SrcBlend),
            .dst_rgb = d3dBlendToGl(r.DestBlend),
            .op_rgb = d3dBlendOpToGl(r.BlendOp),
            .src_a = d3dBlendToGl(r.SrcBlendAlpha),
            .dst_a = d3dBlendToGl(r.DestBlendAlpha),
            .op_a = d3dBlendOpToGl(r.BlendOpAlpha),
            .write_mask = r.RenderTargetWriteMask,
        };
    }
    pp.?.* = newComWithDesc(&state_vtbl, .blend, @intFromPtr(bs), std.mem.asBytes(desc));
    return S_OK;
}

fn devCreateDepthStencilState(_: ?*anyopaque, desc: *const D3D11_DEPTH_STENCIL_DESC, pp: ?*?*anyopaque) callconv(W) i32 {
    if (pp == null) return S_FALSE;
    const ds = alloc.create(glb.DepthStencilState) catch return E_FAIL;
    ds.* = .{
        .depth_enable = (desc.DepthEnable != 0),
        .depth_write = (desc.DepthWriteMask != 0),
        .depth_func = d3dCmpToGl(desc.DepthFunc),
        .stencil_enable = (desc.StencilEnable != 0),
        .stencil_read_mask = desc.StencilReadMask,
        .stencil_write_mask = desc.StencilWriteMask,
        .front_fail = d3dStencilOpToGl(desc.FrontFace.StencilFailOp),
        .front_zfail = d3dStencilOpToGl(desc.FrontFace.StencilDepthFailOp),
        .front_pass = d3dStencilOpToGl(desc.FrontFace.StencilPassOp),
        .front_func = d3dCmpToGl(desc.FrontFace.StencilFunc),
        .back_fail = d3dStencilOpToGl(desc.BackFace.StencilFailOp),
        .back_zfail = d3dStencilOpToGl(desc.BackFace.StencilDepthFailOp),
        .back_pass = d3dStencilOpToGl(desc.BackFace.StencilPassOp),
        .back_func = d3dCmpToGl(desc.BackFace.StencilFunc),
    };
    pp.?.* = newComWithDesc(&state_vtbl, .depth_stencil, @intFromPtr(ds), std.mem.asBytes(desc));
    return S_OK;
}

fn devCreateRasterizerState(_: ?*anyopaque, desc: *const D3D11_RASTERIZER_DESC, pp: ?*?*anyopaque) callconv(W) i32 {
    if (pp == null) return S_FALSE;
    const rs = alloc.create(glb.RasterizerState) catch return E_FAIL;
    rs.* = .{
        .wireframe = (desc.FillMode == 2),
        .cull_mode = desc.CullMode,
        .front_ccw = (desc.FrontCounterClockwise != 0),
        .scissor_enable = (desc.ScissorEnable != 0),
        .depth_clip = (desc.DepthClipEnable != 0),
    };
    pp.?.* = newComWithDesc(&state_vtbl, .rasterizer, @intFromPtr(rs), std.mem.asBytes(desc));
    return S_OK;
}

fn devCreateSamplerState(_: ?*anyopaque, desc: *const D3D11_SAMPLER_DESC, pp: ?*?*anyopaque) callconv(W) i32 {
    if (pp == null) return S_FALSE;
    const sm = alloc.create(glb.Sampler) catch return E_FAIL;
    sm.* = .{};
    glb.createSampler(sm, desc.Filter, desc.AddressU, desc.AddressV, desc.AddressW, desc.MipLODBias, desc.MaxAnisotropy, desc.ComparisonFunc, desc.BorderColor, desc.MinLOD, desc.MaxLOD);
    pp.?.* = newComWithDesc(&state_vtbl, .sampler, @intFromPtr(sm), std.mem.asBytes(desc));
    return S_OK;
}

fn devCreateQuery(_: ?*anyopaque, desc: ?*const [2]u32, pp: ?*?*anyopaque) callconv(W) i32 {
    if (pp == null) return S_FALSE;
    const qt: usize = if (desc) |d| d[0] else 0;
    const qd: [2]u32 = if (desc) |d| d.* else .{ 0, 0 };
    pp.?.* = newComWithDesc(&query_vtbl, .query, qt, std.mem.asBytes(&qd));
    return S_OK;
}

fn devCheckFormatSupport(_: ?*anyopaque, fmt: u32, pSupport: *u32) callconv(W) i32 {
    const gf = glb.dxgiToGlFormat(fmt);
    var sup: u32 = 0x00000020 | 0x00000400 | 0x00001000 | 0x00002000 | 0x00004000; // TEXTURE2D | IA_VERTEX | SHADER_LOAD | SHADER_SAMPLE | MIP
    if (!gf.compressed and !gf.is_depth) sup |= 0x00000001 | 0x00000002 | 0x00008000 | 0x00020000 | 0x00080000; // BUFFER | IA_VERTEX | RENDER_TARGET | BLENDABLE | DISPLAY
    if (gf.is_depth) sup |= 0x00010000; // DEPTH_STENCIL
    pSupport.* = sup;
    return S_OK;
}

fn devCheckMultisample(_: ?*anyopaque, _: u32, sample_count: u32, pNum: *u32) callconv(W) i32 {
    pNum.* = if (sample_count == 1) 1 else 0;
    return S_OK;
}

fn devCheckFeatureSupport(_: ?*anyopaque, feature: u32, data: ?*anyopaque, size: u32) callconv(W) i32 {
    if (data == null) return E_INVALIDARG;
    const bytes: [*]u8 = @ptrCast(data.?);
    @memset(bytes[0..size], 0);
    if (feature == 0 and size >= 8) { // D3D11_FEATURE_THREADING
        const ints: [*]u32 = @ptrCast(@alignCast(data.?));
        ints[0] = 1; // DriverConcurrentCreates
        ints[1] = 0; // DriverCommandLists
    }
    return S_OK;
}

fn devGetFeatureLevel(_: ?*anyopaque) callconv(W) u32 { return D3D_FEATURE_LEVEL_11_0; }
fn devGetImmediateContext(_: ?*anyopaque, pp: *?*anyopaque) callconv(W) void {
    const c = g_context.?;
    _ = comAddRef(c);
    pp.* = c;
}

// ---- Resource GetDesc / Child GetDevice -------------------------------------

fn childGetDevice(_: ?*anyopaque, pp: *?*anyopaque) callconv(W) void {
    const d = g_device.?;
    _ = comAddRef(d);
    pp.* = d;
}

fn resGetType(raw: ?*anyopaque, pType: *u32) callconv(W) void {
    const o: *ComObj = @ptrCast(@alignCast(raw orelse return));
    pType.* = switch (o.kind) {
        .buffer => 1,
        .texture1d => 2,
        .texture3d => 4,
        else => 3,
    };
}

fn isTexKind(k: ComObj.Kind) bool {
    return k == .texture2d or k == .texture1d or k == .texture3d;
}

fn tex1dGetDesc(raw: ?*anyopaque, pDesc: *D3D11_TEXTURE1D_DESC) callconv(W) void {
    const o: *ComObj = @ptrCast(@alignCast(raw orelse return));
    pDesc.* = o.desc1d;
}

fn tex3dGetDesc(raw: ?*anyopaque, pDesc: *D3D11_TEXTURE3D_DESC) callconv(W) void {
    const o: *ComObj = @ptrCast(@alignCast(raw orelse return));
    pDesc.* = o.desc3d;
}

fn bufGetDesc(raw: ?*anyopaque, pDesc: *D3D11_BUFFER_DESC) callconv(W) void {
    const o: *ComObj = @ptrCast(@alignCast(raw orelse return));
    pDesc.* = o.descbuf;
}

fn tex2dGetDesc(raw: ?*anyopaque, pDesc: *D3D11_TEXTURE2D_DESC) callconv(W) void {
    const o: *ComObj = @ptrCast(@alignCast(raw orelse return));
    pDesc.* = o.desc2d;
}

fn viewGetResource(raw: ?*anyopaque, pp: *?*anyopaque) callconv(W) void {
    const o: *ComObj = @ptrCast(@alignCast(raw orelse {
        pp.* = null;
        return;
    }));
    if (o.view_res) |r| {
        _ = comAddRef(r);
        pp.* = r;
    } else {
        pp.* = null;
    }
}

fn viewGetDesc(raw: ?*anyopaque, pDesc: ?*anyopaque) callconv(W) void {
    const o: *ComObj = @ptrCast(@alignCast(raw orelse return));
    const dst: [*]u32 = @ptrCast(@alignCast(pDesc orelse return));
    const count: usize = if (o.kind == .rtv) 5 else 6;
    for (0..count) |i| dst[i] = o.view_desc[i];
}

// ---- ID3D11DeviceContext Implementation -------------------------------------

fn ctxVSSetCB(_: ?*anyopaque, start: u32, num: u32, pp: ?[*]const ?*anyopaque) callconv(W) void {
    for (0..num) |i| {
        const s = start + i;
        if (s >= 16) break;
        const raw = if (pp) |arr| arr[i] else null;
        g_draw_state.vs_cb[s] = if (raw) |r| @ptrFromInt(@as(*ComObj, @ptrCast(@alignCast(r))).payload) else null;
        g_draw_state.vs_cb_off[s] = 0;
        g_draw_state.vs_cb_sz[s] = 0;
    }
}

fn ctxPSSetCB(_: ?*anyopaque, start: u32, num: u32, pp: ?[*]const ?*anyopaque) callconv(W) void {
    for (0..num) |i| {
        const s = start + i;
        if (s >= 16) break;
        const raw = if (pp) |arr| arr[i] else null;
        g_draw_state.ps_cb[s] = if (raw) |r| @ptrFromInt(@as(*ComObj, @ptrCast(@alignCast(r))).payload) else null;
        g_draw_state.ps_cb_off[s] = 0;
        g_draw_state.ps_cb_sz[s] = 0;
    }
}

fn ctxPSSetSRV(_: ?*anyopaque, start: u32, num: u32, pp: ?[*]const ?*anyopaque) callconv(W) void {
    for (0..num) |i| {
        const s = start + i;
        if (s >= 16) break;
        const raw = if (pp) |arr| arr[i] else null;
        g_draw_state.ps_srv[s] = if (raw) |r| @ptrFromInt(@as(*ComObj, @ptrCast(@alignCast(r))).payload) else null;
    }
}

fn ctxVSSetSRV(_: ?*anyopaque, start: u32, num: u32, pp: ?[*]const ?*anyopaque) callconv(W) void {
    for (0..num) |i| {
        const s = start + i;
        if (s >= 16) break;
        const raw = if (pp) |arr| arr[i] else null;
        g_draw_state.vs_srv[s] = if (raw) |r| @ptrFromInt(@as(*ComObj, @ptrCast(@alignCast(r))).payload) else null;
    }
}

fn ctxPSSetSamplers(_: ?*anyopaque, start: u32, num: u32, pp: ?[*]const ?*anyopaque) callconv(W) void {
    for (0..num) |i| {
        const s = start + i;
        if (s >= 16) break;
        const raw = if (pp) |arr| arr[i] else null;
        g_draw_state.ps_samp[s] = if (raw) |r| @ptrFromInt(@as(*ComObj, @ptrCast(@alignCast(r))).payload) else null;
    }
}

fn ctxVSSetSamplers(_: ?*anyopaque, start: u32, num: u32, pp: ?[*]const ?*anyopaque) callconv(W) void {
    for (0..num) |i| {
        const s = start + i;
        if (s >= 16) break;
        const raw = if (pp) |arr| arr[i] else null;
        g_draw_state.vs_samp[s] = if (raw) |r| @ptrFromInt(@as(*ComObj, @ptrCast(@alignCast(r))).payload) else null;
    }
}

fn ctxPSSetShader(_: ?*anyopaque, sh: ?*anyopaque, _: ?*const anyopaque, _: u32) callconv(W) void {
    g_draw_state.ps = if (sh) |r| @ptrFromInt(@as(*ComObj, @ptrCast(@alignCast(r))).payload) else null;
}

fn ctxVSSetShader(_: ?*anyopaque, sh: ?*anyopaque, _: ?*const anyopaque, _: u32) callconv(W) void {
    g_draw_state.vs = if (sh) |r| @ptrFromInt(@as(*ComObj, @ptrCast(@alignCast(r))).payload) else null;
}

fn ctxIASetInputLayout(_: ?*anyopaque, il: ?*anyopaque) callconv(W) void {
    g_draw_state.input_layout = if (il) |r| @ptrFromInt(@as(*ComObj, @ptrCast(@alignCast(r))).payload) else null;
}

fn ctxIASetVertexBuffers(_: ?*anyopaque, start: u32, num: u32, pp: ?[*]const ?*anyopaque, strides: ?[*]const u32, offsets: ?[*]const u32) callconv(W) void {
    for (0..num) |i| {
        const s = start + i;
        if (s >= 16) break;
        const raw = if (pp) |arr| arr[i] else null;
        g_draw_state.vb[s] = if (raw) |r| @ptrFromInt(@as(*ComObj, @ptrCast(@alignCast(r))).payload) else null;
        g_draw_state.vb_stride[s] = if (strides) |st| st[i] else 0;
        g_draw_state.vb_offset[s] = if (offsets) |of| of[i] else 0;
    }
}

fn ctxIASetIndexBuffer(_: ?*anyopaque, ib: ?*anyopaque, fmt: u32, off: u32) callconv(W) void {
    g_draw_state.ib = if (ib) |r| @ptrFromInt(@as(*ComObj, @ptrCast(@alignCast(r))).payload) else null;
    g_draw_state.ib_format = fmt;
    g_draw_state.ib_offset = off;
}

fn ctxIASetTopology(_: ?*anyopaque, topo: u32) callconv(W) void {
    g_draw_state.topology = topo;
}

/// COM pointers behind the bound output-merger/rasterizer objects, for the
/// Get* methods (DrawState keeps only the GL-side payloads). Not referenced:
/// a getter AddRefs what it hands out, as D3D does.
const BoundCom = struct {
    rtv: [8]?*anyopaque = .{null} ** 8,
    num_rtvs: u32 = 0,
    dsv: ?*anyopaque = null,
    blend: ?*anyopaque = null,
    depth: ?*anyopaque = null,
    rs: ?*anyopaque = null,
};
var g_bound: BoundCom = .{};

/// What a deferred context's Get* methods report: the state recorded so far.
const Shadow = struct {
    com: BoundCom = .{},
    vps: [8]D3D11_VIEWPORT = std.mem.zeroes([8]D3D11_VIEWPORT),
    nvp: u32 = 0,
    sc: [8]RECT = std.mem.zeroes([8]RECT),
    nsc: u32 = 0,
    blend_factor: [4]f32 = .{ 1, 1, 1, 1 },
    sample_mask: u32 = 0xFFFFFFFF,
    stencil_ref: u32 = 0,
};

fn shadowOf(this: ?*anyopaque) ?*Shadow {
    const o: *ComObj = @ptrCast(@alignCast(this orelse return null));
    if (o.kind != .deferred_ctx) return null;
    return &recOf(this).shadow;
}

fn handOut(dst: ?*?*anyopaque, obj: ?*anyopaque) void {
    const d = dst orelse return;
    d.* = obj;
    if (obj) |o| _ = comAddRef(o);
}

/// Snapshot of the calling context's OM/RS state: the recorder's shadow for a
/// deferred context, the live draw state for the immediate one.
fn curShadow(this: ?*anyopaque) Shadow {
    if (shadowOf(this)) |sh| return sh.*;
    var out: Shadow = .{ .com = g_bound, .nvp = g_draw_state.num_viewports, .nsc = g_draw_state.num_scissors };
    for (0..g_draw_state.num_viewports) |i| {
        const v = g_draw_state.viewports[i];
        out.vps[i] = .{ .TopLeftX = v.x, .TopLeftY = v.y, .Width = v.w, .Height = v.h, .MinDepth = v.min_depth, .MaxDepth = v.max_depth };
    }
    for (0..g_draw_state.num_scissors) |i| {
        const r = g_draw_state.scissors[i];
        out.sc[i] = .{ .left = r.left, .top = r.top, .right = r.right, .bottom = r.bottom };
    }
    out.blend_factor = g_draw_state.blend_factor;
    out.sample_mask = g_draw_state.sample_mask;
    out.stencil_ref = g_draw_state.stencil_ref;
    return out;
}

fn getTrace(comptime name: []const u8, this: ?*anyopaque, ra: usize) void {
    const S = struct { var n = std.atomic.Value(u32).init(0); };
    if (S.n.fetchAdd(1, .monotonic) < 24 and std.c.getenv("WINS_D3D11_TRACE_GET") != null)
        std.debug.print("[WINS:D3D11] {s} deferred={} ret=0x{x}\n", .{ name, shadowOf(this) != null, ra });
}

fn ctxOMGetRenderTargets(this: ?*anyopaque, num: u32, ppRTV: ?[*]?*anyopaque, ppDSV: ?*?*anyopaque) callconv(W) void {
    getTrace("OMGetRenderTargets", this, @returnAddress());
    const st = curShadow(this);
    if (ppRTV) |arr| {
        for (0..@min(8, num)) |i| handOut(&arr[i], if (i < st.com.num_rtvs) st.com.rtv[i] else null);
    }
    handOut(ppDSV, st.com.dsv);
}

fn ctxOMGetBlendState(this: ?*anyopaque, ppBS: ?*?*anyopaque, factor: ?*[4]f32, mask: ?*u32) callconv(W) void {
    const st = curShadow(this);
    handOut(ppBS, st.com.blend);
    if (factor) |f| f.* = st.blend_factor;
    if (mask) |m| m.* = st.sample_mask;
}

fn ctxOMGetDepthStencilState(this: ?*anyopaque, ppDS: ?*?*anyopaque, ref: ?*u32) callconv(W) void {
    const st = curShadow(this);
    handOut(ppDS, st.com.depth);
    if (ref) |r| r.* = st.stencil_ref;
}

fn ctxRSGetState(this: ?*anyopaque, ppRS: ?*?*anyopaque) callconv(W) void {
    handOut(ppRS, curShadow(this).com.rs);
}

fn ctxRSGetViewports(this: ?*anyopaque, pNum: ?*u32, vps: ?[*]D3D11_VIEWPORT) callconv(W) void {
    getTrace("RSGetViewports", this, @returnAddress());
    const num = pNum orelse return;
    const st = curShadow(this);
    if (vps) |arr| {
        for (0..@min(8, num.*)) |i| arr[i] = if (i < st.nvp) st.vps[i] else std.mem.zeroes(D3D11_VIEWPORT);
    }
    num.* = st.nvp;
}

fn ctxRSGetScissorRects(this: ?*anyopaque, pNum: ?*u32, rects: ?[*]RECT) callconv(W) void {
    const num = pNum orelse return;
    const st = curShadow(this);
    if (rects) |arr| {
        for (0..@min(8, num.*)) |i| arr[i] = if (i < st.nsc) st.sc[i] else std.mem.zeroes(RECT);
    }
    num.* = st.nsc;
}

fn ctxOMSetRenderTargets(_: ?*anyopaque, num: u32, ppRTV: ?[*]const ?*anyopaque, pDSV: ?*anyopaque) callconv(W) void {
    const n = @min(8, num);
    g_draw_state.num_rtvs = n;
    g_bound.num_rtvs = n;
    g_bound.dsv = pDSV;
    for (0..8) |i| {
        g_bound.rtv[i] = if (i < n and ppRTV != null) ppRTV.?[i] else null;
        if (i < n and ppRTV != null) {
            const raw = ppRTV.?[i];
            g_draw_state.rtv[i] = if (raw) |r| @ptrFromInt(@as(*ComObj, @ptrCast(@alignCast(r))).payload) else null;
        } else {
            g_draw_state.rtv[i] = null;
        }
    }
    g_draw_state.dsv = if (pDSV) |r| @ptrFromInt(@as(*ComObj, @ptrCast(@alignCast(r))).payload) else null;
}

fn ctxOMSetBlendState(_: ?*anyopaque, bs: ?*anyopaque, factor: ?*const [4]f32, mask: u32) callconv(W) void {
    g_bound.blend = bs;
    g_draw_state.blend = if (bs) |r| @ptrFromInt(@as(*ComObj, @ptrCast(@alignCast(r))).payload) else null;
    if (factor) |f| g_draw_state.blend_factor = f.* else g_draw_state.blend_factor = .{ 1, 1, 1, 1 };
    g_draw_state.sample_mask = mask;
}

fn ctxOMSetDepthStencilState(_: ?*anyopaque, ds: ?*anyopaque, ref: u32) callconv(W) void {
    g_bound.depth = ds;
    g_draw_state.depth_stencil = if (ds) |r| @ptrFromInt(@as(*ComObj, @ptrCast(@alignCast(r))).payload) else null;
    g_draw_state.stencil_ref = ref;
}

fn ctxRSSetState(_: ?*anyopaque, rs: ?*anyopaque) callconv(W) void {
    g_bound.rs = rs;
    g_draw_state.rasterizer = if (rs) |r| @ptrFromInt(@as(*ComObj, @ptrCast(@alignCast(r))).payload) else null;
}

fn ctxRSSetViewports(_: ?*anyopaque, num: u32, vps: ?[*]const D3D11_VIEWPORT) callconv(W) void {
    const n = @min(8, num);
    g_draw_state.num_viewports = n;
    if (vps) |arr| {
        for (0..n) |i| {
            g_draw_state.viewports[i] = .{
                .x = arr[i].TopLeftX, .y = arr[i].TopLeftY, .w = arr[i].Width, .h = arr[i].Height,
                .min_depth = arr[i].MinDepth, .max_depth = arr[i].MaxDepth,
            };
        }
    }
}

fn ctxRSSetScissors(_: ?*anyopaque, num: u32, rects: ?[*]const RECT) callconv(W) void {
    const n = @min(8, num);
    g_draw_state.num_scissors = n;
    if (rects) |arr| {
        for (0..n) |i| {
            g_draw_state.scissors[i] = .{
                .left = arr[i].left, .top = arr[i].top, .right = arr[i].right, .bottom = arr[i].bottom,
            };
        }
    }
}

fn ctxDraw(_: ?*anyopaque, vcount: u32, vstart: u32) callconv(W) void {
    glb.draw(&g_draw_state, .arrays, vcount, 1, vstart, 0, 0, 0);
}

fn ctxDrawIndexed(_: ?*anyopaque, icount: u32, istart: u32, vbase: i32) callconv(W) void {
    glb.draw(&g_draw_state, .indexed, icount, 1, 0, istart, vbase, 0);
}

fn ctxDrawInstanced(_: ?*anyopaque, vcount: u32, inst_count: u32, vstart: u32, inst_start: u32) callconv(W) void {
    glb.draw(&g_draw_state, .arrays_instanced, vcount, inst_count, vstart, 0, 0, inst_start);
}

fn ctxDrawIndexedInstanced(_: ?*anyopaque, icount: u32, inst_count: u32, istart: u32, vbase: i32, inst_start: u32) callconv(W) void {
    glb.draw(&g_draw_state, .indexed_instanced, icount, inst_count, 0, istart, vbase, inst_start);
}

fn ctxMap(_: ?*anyopaque, res: ?*anyopaque, sub: u32, map_type: u32, _: u32, mapped: *D3D11_MAPPED_SUBRESOURCE) callconv(W) i32 {
    const o: *ComObj = @ptrCast(@alignCast(res orelse return E_INVALIDARG));
    if (o.kind == .buffer) {
        const b: *glb.Buffer = @ptrFromInt(o.payload);
        mapped.pData = if (b.shadow) |sh| sh.ptr else return E_FAIL;
        mapped.RowPitch = b.size;
        mapped.DepthPitch = b.size;
        return S_OK;
    } else if (isTexKind(o.kind)) {
        const t: *glb.Texture = @ptrFromInt(o.payload);
        traceFmt(t.dxgi_fmt, "map gl={d} sub={d} type={d} shadow={}", .{ t.gl_id, sub, map_type, t.shadow != null });
        if (t.shadow) |sh| {
            mapped.pData = sh.ptr;
            mapped.RowPitch = t.row_pitch;
            mapped.DepthPitch = @intCast(sh.len / @max(1, t.depth));
            return S_OK;
        }
    }
    return E_FAIL;
}

fn ctxUnmap(_: ?*anyopaque, res: ?*anyopaque, sub: u32) callconv(W) void {
    const o: *ComObj = @ptrCast(@alignCast(res orelse return));
    if (o.kind == .buffer) {
        const b: *glb.Buffer = @ptrFromInt(o.payload);
        if (b.shadow) |sh| glb.uploadBuffer(b, 0, sh.ptr, b.size);
    } else if (isTexKind(o.kind)) {
        const t: *glb.Texture = @ptrFromInt(o.payload);
        if (t.usage != 3 and t.shadow != null) {
            glb.updateSubresourceTexture(t, sub, false, .{0} ** 6, t.shadow.?.ptr, t.row_pitch, @intCast(t.shadow.?.len));
        }
    }
}

fn ctxUpdateSubresource(_: ?*anyopaque, res: ?*anyopaque, sub: u32, box: ?*const D3D11_BOX, data: ?*const anyopaque, row_pitch: u32, depth_pitch: u32) callconv(W) void {
    const dptr: [*]const u8 = @ptrCast(data orelse return);
    const o: *ComObj = @ptrCast(@alignCast(res orelse return));
    if (o.kind == .buffer) {
        const b: *glb.Buffer = @ptrFromInt(o.payload);
        if (box) |bx| {
            const len = @min(b.size -| bx.left, bx.right -| bx.left);
            if (len > 0) {
                if (b.shadow) |sh| {
                    if (@intFromPtr(dptr) != @intFromPtr(sh.ptr + bx.left)) @memcpy(sh[bx.left..][0..len], dptr[0..len]);
                }
                glb.uploadBuffer(b, bx.left, dptr, len);
            }
        } else {
            if (b.shadow) |sh| {
                const n = @min(sh.len, b.size);
                if (@intFromPtr(dptr) != @intFromPtr(sh.ptr)) @memcpy(sh[0..n], dptr[0..n]);
            }
            glb.uploadBuffer(b, 0, dptr, b.size);
        }
    } else if (isTexKind(o.kind)) {
        const t: *glb.Texture = @ptrFromInt(o.payload);
        const bx = if (box) |b| [6]u32{ b.left, b.top, b.front, b.right, b.bottom, b.back } else [_]u32{0} ** 6;
        traceFmt(t.dxgi_fmt, "update gl={d} sub={d} box={} [{d},{d})x[{d},{d}) pitch={d} nz={d}", .{
            t.gl_id, sub, box != null, bx[0], bx[3], bx[1], bx[4], row_pitch,
            if (traceFmtOn(t.dxgi_fmt)) nonzeroBytes(dptr, @as(usize, row_pitch) * (if (box != null) bx[4] -| bx[1] else t.height)) else 0,
        });
        if (t.dxgi_fmt == 41 and traceFmtOn(41) and row_pitch >= 4100) {
            const f: [*]align(1) const f32 = @ptrCast(dptr);
            traceFmt(41, "  r32f[0,1,256,512,1024] = {d:.4} {d:.4} {d:.4} {d:.4} {d:.4}", .{ f[0], f[1], f[256], f[512], f[1024] });
        }
        glb.updateSubresourceTexture(t, sub, box != null, bx, dptr, row_pitch, depth_pitch);
    }
}

fn ctxClearRTV(_: ?*anyopaque, rtv: ?*anyopaque, color: *const [4]f32) callconv(W) void {
    const o: *ComObj = @ptrCast(@alignCast(rtv orelse return));
    const v: *glb.View = @ptrFromInt(o.payload);
    glb.clearRtv(v, color.*);
}

fn ctxClearDSV(_: ?*anyopaque, dsv: ?*anyopaque, flags: u32, depth: f32, stencil: u8) callconv(W) void {
    const o: *ComObj = @ptrCast(@alignCast(dsv orelse return));
    const v: *glb.View = @ptrFromInt(o.payload);
    glb.clearDsv(v, flags, depth, stencil);
}

fn ctxCopyResource(_: ?*anyopaque, dst: ?*anyopaque, src: ?*anyopaque) callconv(W) void {
    const d = extractResTexture(dst);
    const s = extractResTexture(src);
    if (d.tex) |dt| traceFmt(dt.dxgi_fmt, "copyResource dst gl={d} <- src gl={d} fmt={d} usage={d}", .{ dt.gl_id, if (s.tex) |st| st.gl_id else 0, if (s.tex) |st| st.dxgi_fmt else 0, if (s.tex) |st| st.usage else 0 });
    glb.copyResource(d.tex, d.buf, s.tex, s.buf);
}

fn ctxCopySubresourceRegion(_: ?*anyopaque, dst: ?*anyopaque, dsub: u32, dx: u32, dy: u32, dz: u32, src: ?*anyopaque, ssub: u32, box: ?*const D3D11_BOX) callconv(W) void {
    const d = extractResTexture(dst);
    const s = extractResTexture(src);
    const bx = if (box) |b| [6]u32{ b.left, b.top, b.front, b.right, b.bottom, b.back } else [_]u32{0} ** 6;
    if (d.tex) |dt| traceFmt(dt.dxgi_fmt, "copyRegion dst gl={d} sub={d} at ({d},{d}) <- src gl={d} sub={d} fmt={d} usage={d} box={} {any}", .{ dt.gl_id, dsub, dx, dy, if (s.tex) |st| st.gl_id else 0, ssub, if (s.tex) |st| st.dxgi_fmt else 0, if (s.tex) |st| st.usage else 0, box != null, bx });
    glb.copySubresourceRegion(d.tex, dsub, dx, dy, dz, s.tex, ssub, box != null, bx);
}

fn ctxResolveSubresource(_: ?*anyopaque, dst: ?*anyopaque, dsub: u32, src: ?*anyopaque, ssub: u32, _: u32) callconv(W) void {
    const d = extractResTexture(dst);
    const s = extractResTexture(src);
    if (d.tex != null and s.tex != null) glb.resolveSubresource(d.tex.?, dsub, s.tex.?, ssub);
}

fn ctxGenerateMips(_: ?*anyopaque, srv: ?*anyopaque) callconv(W) void {
    const o: *ComObj = @ptrCast(@alignCast(srv orelse return));
    const v: *glb.View = @ptrFromInt(o.payload);
    glb.generateMips(v);
}

fn ctxGetData(_: ?*anyopaque, q: ?*anyopaque, data: ?*anyopaque, sz: u32, _: u32) callconv(W) i32 {
    if (data != null and sz > 0) {
        const qt = if (q) |r| @as(*ComObj, @ptrCast(@alignCast(r))).payload else 0;
        if (qt == 2 and sz >= 8) { // D3D11_QUERY_TIMESTAMP
            const ts: *u64 = @ptrCast(@alignCast(data.?));
            ts.* = 1000;
        } else if (sz >= 4) {
            @as(*u32, @ptrCast(@alignCast(data.?))).* = 1;
        }
    }
    return S_OK;
}

fn ctxClearState(_: ?*anyopaque) callconv(W) void {
    g_draw_state = .{};
    g_bound = .{};
}

fn ctxGetType(_: ?*anyopaque) callconv(W) u32 { return 0; } // IMMEDIATE

// ---- Static COM Vtables -----------------------------------------------------

const dxgi_factory_vtbl = [_]?*const anyopaque{
    @ptrCast(&comQiDefault), @ptrCast(&comAddRef), @ptrCast(&comRelease),
    @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&dxgiGetParent),
    @ptrCast(&facEnumAdapters), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&facCreateSwapChain), @ptrCast(&stubRetOk),
    @ptrCast(&facEnumAdapters), @ptrCast(&facIsCurrent),
};

const dxgi_adapter_vtbl = [_]?*const anyopaque{
    @ptrCast(&comQiDefault), @ptrCast(&comAddRef), @ptrCast(&comRelease),
    @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&dxgiGetParent),
    @ptrCast(&adEnumOutputs), @ptrCast(&adGetDesc), @ptrCast(&adCheckInterface), @ptrCast(&adGetDesc1),
};

const dxgi_output_vtbl = [_]?*const anyopaque{
    @ptrCast(&comQiDefault), @ptrCast(&comAddRef), @ptrCast(&comRelease),
    @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&dxgiGetParent),
    @ptrCast(&outGetDesc), @ptrCast(&outGetDisplayModeList), @ptrCast(&outFindClosestMode), @ptrCast(&stubRetOk),
    @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk),
    @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk),
};

const dxgi_device_vtbl = [_]?*const anyopaque{
    @ptrCast(&comQiDefault), @ptrCast(&comAddRef), @ptrCast(&comRelease),
    @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&dxgiGetParent),
    @ptrCast(&dxgidevGetAdapter), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk),
    @ptrCast(&stubRetOk), @ptrCast(&stubRetOk),
};

const swapchain_vtbl = [_]?*const anyopaque{
    @ptrCast(&comQiDefault), @ptrCast(&comAddRef), @ptrCast(&comRelease),
    @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&dxgiGetParent),
    @ptrCast(&scGetDevice), @ptrCast(&scPresent), @ptrCast(&scGetBuffer),
    @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&scGetDesc),
    @ptrCast(&scResizeBuffers), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk),
    @ptrCast(&stubRetOk), @ptrCast(&stubRetOk),
};

const child_vtbl = [_]?*const anyopaque{
    @ptrCast(&comQiDefault), @ptrCast(&comAddRef), @ptrCast(&comRelease),
    @ptrCast(&childGetDevice), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk),
};

/// ID3D11{Blend,DepthStencil,Rasterizer,Sampler}State: DeviceChild + GetDesc (7).
const state_vtbl = [_]?*const anyopaque{
    @ptrCast(&comQiDefault), @ptrCast(&comAddRef), @ptrCast(&comRelease),
    @ptrCast(&childGetDevice), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk),
    @ptrCast(&stateGetDesc),
};

/// ID3D11Query/Predicate: DeviceChild + GetDataSize (7) + GetDesc (8).
const query_vtbl = [_]?*const anyopaque{
    @ptrCast(&comQiDefault), @ptrCast(&comAddRef), @ptrCast(&comRelease),
    @ptrCast(&childGetDevice), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk),
    @ptrCast(&queryGetDataSize), @ptrCast(&stateGetDesc),
};

const buf_vtbl = [_]?*const anyopaque{
    @ptrCast(&comQiDefault), @ptrCast(&comAddRef), @ptrCast(&comRelease),
    @ptrCast(&childGetDevice), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk),
    @ptrCast(&resGetType), @ptrCast(&stubVoid), @ptrCast(&stubRetZero),
    @ptrCast(&bufGetDesc),
};

const tex2d_vtbl = [_]?*const anyopaque{
    @ptrCast(&comQiDefault), @ptrCast(&comAddRef), @ptrCast(&comRelease),
    @ptrCast(&childGetDevice), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk),
    @ptrCast(&resGetType), @ptrCast(&stubVoid), @ptrCast(&stubRetZero),
    @ptrCast(&tex2dGetDesc),
};

const tex1d_vtbl = [_]?*const anyopaque{
    @ptrCast(&comQiDefault), @ptrCast(&comAddRef), @ptrCast(&comRelease),
    @ptrCast(&childGetDevice), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk),
    @ptrCast(&resGetType), @ptrCast(&stubVoid), @ptrCast(&stubRetZero),
    @ptrCast(&tex1dGetDesc),
};

const tex3d_vtbl = [_]?*const anyopaque{
    @ptrCast(&comQiDefault), @ptrCast(&comAddRef), @ptrCast(&comRelease),
    @ptrCast(&childGetDevice), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk),
    @ptrCast(&resGetType), @ptrCast(&stubVoid), @ptrCast(&stubRetZero),
    @ptrCast(&tex3dGetDesc),
};

const view_vtbl = [_]?*const anyopaque{
    @ptrCast(&comQiDefault), @ptrCast(&comAddRef), @ptrCast(&comRelease),
    @ptrCast(&childGetDevice), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk),
    @ptrCast(&viewGetResource), @ptrCast(&viewGetDesc),
};

const device_vtbl = [_]?*const anyopaque{
    @ptrCast(&comQiDefault), @ptrCast(&comAddRef), @ptrCast(&comRelease), // 0..2
    @ptrCast(&devCreateBuffer), // 3
    @ptrCast(&devCreateTexture1D), // 4
    @ptrCast(&devCreateTexture2D), // 5
    @ptrCast(&devCreateTexture3D), // 6
    @ptrCast(&devCreateSRV), // 7
    @ptrCast(&devCreateUAV), // 8
    @ptrCast(&devCreateRTV), // 9
    @ptrCast(&devCreateDSV), // 10
    @ptrCast(&devCreateInputLayout), // 11
    @ptrCast(&devCreateVertexShader), // 12
    @ptrCast(&devCreateDummyShader), // 13 GS
    @ptrCast(&devCreateDummyShader), // 14 GS+SO
    @ptrCast(&devCreatePixelShader), // 15
    @ptrCast(&devCreateDummyShader), // 16 HS
    @ptrCast(&devCreateDummyShader), // 17 DS
    @ptrCast(&devCreateDummyShader), // 18 CS
    notImplCreate("CreateClassLinkage", 1), // 19
    @ptrCast(&devCreateBlendState), // 20
    @ptrCast(&devCreateDepthStencilState), // 21
    @ptrCast(&devCreateRasterizerState), // 22
    @ptrCast(&devCreateSamplerState), // 23
    @ptrCast(&devCreateQuery), // 24
    @ptrCast(&devCreateQuery), // 25 CreatePredicate
    notImplCreate("CreateCounter", 2), // 26
    @ptrCast(&devCreateDeferredContext), // 27
    notImplCreate("OpenSharedResource", 3), // 28
    @ptrCast(&devCheckFormatSupport), // 29
    @ptrCast(&devCheckMultisample), // 30
    @ptrCast(&stubVoid), // 31 CheckCounterInfo
    @ptrCast(&stubRetOk), // 32 CheckCounter
    @ptrCast(&devCheckFeatureSupport), // 33
    @ptrCast(&stubRetOk), // 34 GetPrivateData
    @ptrCast(&stubRetOk), // 35 SetPrivateData
    @ptrCast(&stubRetOk), // 36 SetPrivateDataInterface
    @ptrCast(&devGetFeatureLevel), // 37
    @ptrCast(&stubRetZero), // 38 GetCreationFlags
    @ptrCast(&stubRetOk), // 39 GetDeviceRemovedReason
    @ptrCast(&devGetImmediateContext), // 40
    @ptrCast(&stubRetOk), // 41 SetExceptionMode
    @ptrCast(&stubRetZero), // 42 GetExceptionMode
};

/// Unimplemented immediate-context method: does nothing, but names itself on
/// first use (a title drawing through Dispatch/Indirect would otherwise just
/// render black with no clue).
fn iStub(comptime slot: usize) *const anyopaque {
    return @ptrCast(&struct {
        var told = std.atomic.Value(bool).init(false);
        fn w() callconv(W) void {
            if (!told.swap(true, .monotonic)) std.debug.print("[WINS:D3D11] context slot {d} called but not implemented (no-op)\n", .{slot});
        }
    }.w);
}

const context_vtbl = [_]?*const anyopaque{
    @ptrCast(&comQiDefault), @ptrCast(&comAddRef), @ptrCast(&comRelease), // 0..2
    @ptrCast(&childGetDevice), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), // 3..6
    @ptrCast(&ctxVSSetCB), // 7
    @ptrCast(&ctxPSSetSRV), // 8
    @ptrCast(&ctxPSSetShader), // 9
    @ptrCast(&ctxPSSetSamplers), // 10
    @ptrCast(&ctxVSSetShader), // 11
    @ptrCast(&ctxDrawIndexed), // 12
    @ptrCast(&ctxDraw), // 13
    @ptrCast(&ctxMap), // 14
    @ptrCast(&ctxUnmap), // 15
    @ptrCast(&ctxPSSetCB), // 16
    @ptrCast(&ctxIASetInputLayout), // 17
    @ptrCast(&ctxIASetVertexBuffers), // 18
    @ptrCast(&ctxIASetIndexBuffer), // 19
    @ptrCast(&ctxDrawIndexedInstanced), // 20
    @ptrCast(&ctxDrawInstanced), // 21
    iStub(22), // 22 GSSetConstantBuffers
    iStub(23), // 23 GSSetShader
    @ptrCast(&ctxIASetTopology), // 24
    @ptrCast(&ctxVSSetSRV), // 25
    @ptrCast(&ctxVSSetSamplers), // 26
    iStub(27), // 27 Begin
    iStub(28), // 28 End
    @ptrCast(&ctxGetData), // 29
    iStub(30), // 30 SetPredication
    iStub(31), // 31 GSSetShaderResources
    iStub(32), // 32 GSSetSamplers
    @ptrCast(&ctxOMSetRenderTargets), // 33
    iStub(34), // 34 OMSetRenderTargetsAndUAVs
    @ptrCast(&ctxOMSetBlendState), // 35
    @ptrCast(&ctxOMSetDepthStencilState), // 36
    iStub(37), // 37 SOSetTargets
    iStub(38), // 38 DrawAuto
    iStub(39), // 39 DrawIndexedInstancedIndirect
    iStub(40), // 40 DrawInstancedIndirect
    iStub(41), // 41 Dispatch
    iStub(42), // 42 DispatchIndirect
    @ptrCast(&ctxRSSetState), // 43
    @ptrCast(&ctxRSSetViewports), // 44
    @ptrCast(&ctxRSSetScissors), // 45
    @ptrCast(&ctxCopySubresourceRegion), // 46
    @ptrCast(&ctxCopyResource), // 47
    @ptrCast(&ctxUpdateSubresource), // 48
    iStub(49), // 49 CopyStructureCount
    @ptrCast(&ctxClearRTV), // 50
    iStub(51), // 51 ClearUnorderedAccessViewUint
    iStub(52), // 52 ClearUnorderedAccessViewFloat
    @ptrCast(&ctxClearDSV), // 53
    @ptrCast(&ctxGenerateMips), // 54
    iStub(55), // 55 SetResourceMinLOD
    @ptrCast(&stubRetZero), // 56 GetResourceMinLOD
    @ptrCast(&ctxResolveSubresource), // 57
    @ptrCast(&ctxExecuteCommandList), // 58
    iStub(59), iStub(60), iStub(61), iStub(62), // 59..62 HS
    iStub(63), iStub(64), iStub(65), iStub(66), // 63..66 DS
    iStub(67), iStub(68), iStub(69), iStub(70), iStub(71), // 67..71 CS
} ++ getterStubs: {
    var g: [38]?*const anyopaque = undefined;
    for (&g, 72..) |*e, i| e.* = iStub(i);
    g[89 - 72] = @ptrCast(&ctxOMGetRenderTargets);
    g[91 - 72] = @ptrCast(&ctxOMGetBlendState);
    g[92 - 72] = @ptrCast(&ctxOMGetDepthStencilState);
    g[94 - 72] = @ptrCast(&ctxRSGetState);
    g[95 - 72] = @ptrCast(&ctxRSGetViewports);
    g[96 - 72] = @ptrCast(&ctxRSGetScissorRects);
    break :getterStubs g;
} ++ [_]?*const anyopaque{ // 72..109 Getters
    @ptrCast(&ctxClearState), // 110
    @ptrCast(&stubVoid), // 111 Flush
    @ptrCast(&ctxGetType), // 112
    @ptrCast(&stubRetZero), // 113 GetContextFlags
    @ptrCast(&ctxFinishCommandListImmediate), // 114 FinishCommandList
};

comptime {
    // ID3D11DeviceContext has 115 methods (d3d11.h); a short table makes the
    // last calls run whatever sits after it in .rodata.
    if (context_vtbl.len != 115) @compileError("ID3D11DeviceContext vtable must have 115 slots");
}

fn ctxFinishCommandListImmediate(_: ?*anyopaque, _: i32, pp: ?*?*anyopaque) callconv(W) i32 {
    if (pp) |p| p.* = null;
    return @bitCast(@as(u32, 0x887A0001)); // DXGI_ERROR_INVALID_CALL
}

// ---- Deferred contexts / command lists -------------------------------------
//
// A deferred context records calls; ExecuteCommandList replays them on the
// immediate context. Recording never touches g_draw_state (worker threads
// record while the main thread draws). Each command keeps a copy of its
// arguments (pointer arrays, colours, boxes and upload bytes are deep-copied
// into the recorder's arena) and holds a reference on every COM object it
// names until the command list is released, like the D3D11 runtime does.

const Cmd = struct {
    run: *const fn (*const anyopaque) void,
    args: *const anyopaque,
};

/// A deferred Map in flight. `base` (NO_OVERWRITE only) is the content the
/// mapping started from, so Unmap can upload just the bytes the app changed.
const MapRec = struct { res: usize, sub: u32, mem: []u8, base: ?[]const u8 = null };

const Recorder = struct {
    arena: std.heap.ArenaAllocator,
    cmds: std.ArrayList(Cmd) = .empty,
    refs: std.ArrayList(*anyopaque) = .empty,
    maps: std.ArrayList(MapRec) = .empty,
    shadow: Shadow = .{},

    fn a(r: *Recorder) std.mem.Allocator {
        return r.arena.allocator();
    }

    fn ref(r: *Recorder, obj: ?*anyopaque) ?*anyopaque {
        const o = obj orelse return null;
        r.refs.append(r.a(), o) catch return o;
        _ = comAddRef(o);
        return o;
    }

    fn dup(r: *Recorder, comptime T: type, src: ?[*]const T, n: usize) ?[*]const T {
        const s = src orelse return null;
        const d = r.a().alloc(T, @max(1, n)) catch return null;
        @memcpy(d[0..n], s[0..n]);
        return d.ptr;
    }

    fn dupRefs(r: *Recorder, src: ?[*]const ?*anyopaque, n: usize) ?[*]const ?*anyopaque {
        const d = r.dup(?*anyopaque, src, n) orelse return null;
        for (d[0..n]) |o| _ = r.ref(o);
        return d;
    }

    /// Drop everything recorded so far (refs released, arena reset).
    fn reset(r: *Recorder) void {
        for (r.refs.items) |o| _ = comRelease(o);
        _ = r.arena.reset(.free_all);
        r.cmds = .empty;
        r.refs = .empty;
        r.maps = .empty;
    }
};

/// A finished command list owns the arena the commands were recorded into.
const CmdList = struct {
    arena: std.heap.ArenaAllocator,
    cmds: []const Cmd,
    refs: []const *anyopaque,
};

fn recOf(raw: ?*anyopaque) *Recorder {
    const o: *ComObj = @ptrCast(@alignCast(raw.?));
    return @ptrFromInt(o.payload);
}

/// Record a call to immediate-context method `f` with `args` (args[0] is the
/// deferred context; replay substitutes the immediate one).
fn push(r: *Recorder, comptime f: anytype, args: std.meta.ArgsTuple(@TypeOf(f))) void {
    const T = @TypeOf(args);
    const p = r.a().create(T) catch return;
    p.* = args;
    const thunk = struct {
        fn run(raw: *const anyopaque) void {
            var t = @as(*const T, @ptrCast(@alignCast(raw))).*;
            t[0] = @ptrCast(g_context);
            const R = @typeInfo(@TypeOf(f)).@"fn".return_type.?;
            if (R == void) @call(.auto, f, t) else _ = @call(.auto, f, t);
        }
    };
    r.cmds.append(r.a(), .{ .run = &thunk.run, .args = p }) catch return;
}

/// Set{CB,SRV,Samplers}(start, num, pp): copy + reference the object array.
fn dSetArr(comptime f: anytype) *const anyopaque {
    return @ptrCast(&struct {
        fn w(raw: ?*anyopaque, start: u32, num: u32, pp: ?[*]const ?*anyopaque) callconv(W) void {
            const r = recOf(raw);
            push(r, f, .{ raw, start, num, r.dupRefs(pp, num) });
        }
    }.w);
}

fn dSetShader(comptime f: anytype) *const anyopaque {
    return @ptrCast(&struct {
        fn w(raw: ?*anyopaque, sh: ?*anyopaque, _: ?*const anyopaque, _: u32) callconv(W) void {
            const r = recOf(raw);
            push(r, f, .{ raw, r.ref(sh), null, 0 });
        }
    }.w);
}

/// Methods whose only object argument is the first one after `this`.
fn dObj1(comptime f: anytype) *const anyopaque {
    const P = @typeInfo(@TypeOf(f)).@"fn".params;
    return switch (P.len) {
        2 => @ptrCast(&struct {
            fn w(raw: ?*anyopaque, o: ?*anyopaque) callconv(W) void {
                const r = recOf(raw);
                push(r, f, .{ raw, r.ref(o) });
            }
        }.w),
        3 => @ptrCast(&struct {
            fn w(raw: ?*anyopaque, o: ?*anyopaque, x: P[2].type.?) callconv(W) void {
                const r = recOf(raw);
                push(r, f, .{ raw, r.ref(o), x });
            }
        }.w),
        4 => @ptrCast(&struct {
            fn w(raw: ?*anyopaque, o: ?*anyopaque, x: P[2].type.?, y: P[3].type.?) callconv(W) void {
                const r = recOf(raw);
                push(r, f, .{ raw, r.ref(o), x, y });
            }
        }.w),
        5 => @ptrCast(&struct {
            fn w(raw: ?*anyopaque, o: ?*anyopaque, x: P[2].type.?, y: P[3].type.?, z: P[4].type.?) callconv(W) void {
                const r = recOf(raw);
                push(r, f, .{ raw, r.ref(o), x, y, z });
            }
        }.w),
        else => @compileError("dObj1: unsupported arity"),
    };
}

/// Pure-value methods (draws, topology, ClearState).
fn dVal(comptime f: anytype) *const anyopaque {
    const P = @typeInfo(@TypeOf(f)).@"fn".params;
    return switch (P.len) {
        1 => @ptrCast(&struct {
            fn w(raw: ?*anyopaque) callconv(W) void {
                push(recOf(raw), f, .{raw});
            }
        }.w),
        2 => @ptrCast(&struct {
            fn w(raw: ?*anyopaque, x1: P[1].type.?) callconv(W) void {
                push(recOf(raw), f, .{ raw, x1 });
            }
        }.w),
        3 => @ptrCast(&struct {
            fn w(raw: ?*anyopaque, x1: P[1].type.?, x2: P[2].type.?) callconv(W) void {
                push(recOf(raw), f, .{ raw, x1, x2 });
            }
        }.w),
        4 => @ptrCast(&struct {
            fn w(raw: ?*anyopaque, x1: P[1].type.?, x2: P[2].type.?, x3: P[3].type.?) callconv(W) void {
                push(recOf(raw), f, .{ raw, x1, x2, x3 });
            }
        }.w),
        5 => @ptrCast(&struct {
            fn w(raw: ?*anyopaque, x1: P[1].type.?, x2: P[2].type.?, x3: P[3].type.?, x4: P[4].type.?) callconv(W) void {
                push(recOf(raw), f, .{ raw, x1, x2, x3, x4 });
            }
        }.w),
        6 => @ptrCast(&struct {
            fn w(raw: ?*anyopaque, x1: P[1].type.?, x2: P[2].type.?, x3: P[3].type.?, x4: P[4].type.?, x5: P[5].type.?) callconv(W) void {
                push(recOf(raw), f, .{ raw, x1, x2, x3, x4, x5 });
            }
        }.w),
        else => @compileError("dVal: unsupported arity"),
    };
}

fn dIASetVertexBuffers(raw: ?*anyopaque, start: u32, num: u32, pp: ?[*]const ?*anyopaque, strides: ?[*]const u32, offsets: ?[*]const u32) callconv(W) void {
    const r = recOf(raw);
    push(r, ctxIASetVertexBuffers, .{ raw, start, num, r.dupRefs(pp, num), r.dup(u32, strides, num), r.dup(u32, offsets, num) });
}

fn dOMSetRenderTargets(raw: ?*anyopaque, num: u32, pp: ?[*]const ?*anyopaque, dsv: ?*anyopaque) callconv(W) void {
    const r = recOf(raw);
    const n = @min(8, num);
    r.shadow.com.num_rtvs = n;
    r.shadow.com.dsv = dsv;
    for (0..8) |i| r.shadow.com.rtv[i] = if (i < n and pp != null) pp.?[i] else null;
    push(r, ctxOMSetRenderTargets, .{ raw, num, r.dupRefs(pp, num), r.ref(dsv) });
}

fn dOMSetBlendState(raw: ?*anyopaque, bs: ?*anyopaque, factor: ?*const [4]f32, mask: u32) callconv(W) void {
    const r = recOf(raw);
    r.shadow.com.blend = bs;
    r.shadow.blend_factor = if (factor) |f| f.* else .{ 1, 1, 1, 1 };
    r.shadow.sample_mask = mask;
    const fc: ?*const [4]f32 = if (r.dup([4]f32, if (factor) |f| @ptrCast(f) else null, 1)) |p| &p[0] else null;
    push(r, ctxOMSetBlendState, .{ raw, r.ref(bs), fc, mask });
}

fn dOMSetDepthStencilState(raw: ?*anyopaque, ds: ?*anyopaque, ref: u32) callconv(W) void {
    const r = recOf(raw);
    r.shadow.com.depth = ds;
    r.shadow.stencil_ref = ref;
    push(r, ctxOMSetDepthStencilState, .{ raw, r.ref(ds), ref });
}

fn dRSSetState(raw: ?*anyopaque, rs: ?*anyopaque) callconv(W) void {
    const r = recOf(raw);
    r.shadow.com.rs = rs;
    push(r, ctxRSSetState, .{ raw, r.ref(rs) });
}

fn dRSSetViewports(raw: ?*anyopaque, num: u32, vps: ?[*]const D3D11_VIEWPORT) callconv(W) void {
    const r = recOf(raw);
    r.shadow.nvp = @min(8, num);
    if (vps) |arr| for (0..r.shadow.nvp) |i| { r.shadow.vps[i] = arr[i]; };
    push(r, ctxRSSetViewports, .{ raw, num, r.dup(D3D11_VIEWPORT, vps, num) });
}

fn dRSSetScissors(raw: ?*anyopaque, num: u32, rects: ?[*]const RECT) callconv(W) void {
    const r = recOf(raw);
    r.shadow.nsc = @min(8, num);
    if (rects) |arr| for (0..r.shadow.nsc) |i| { r.shadow.sc[i] = arr[i]; };
    push(r, ctxRSSetScissors, .{ raw, num, r.dup(RECT, rects, num) });
}

fn dClearRTV(raw: ?*anyopaque, rtv: ?*anyopaque, color: *const [4]f32) callconv(W) void {
    const r = recOf(raw);
    const c = r.dup([4]f32, @ptrCast(color), 1) orelse return;
    push(r, ctxClearRTV, .{ raw, r.ref(rtv), &c[0] });
}

fn dCopySubresourceRegion(raw: ?*anyopaque, dst: ?*anyopaque, dsub: u32, dx: u32, dy: u32, dz: u32, src: ?*anyopaque, ssub: u32, box: ?*const D3D11_BOX) callconv(W) void {
    const r = recOf(raw);
    const b: ?*const D3D11_BOX = if (r.dup(D3D11_BOX, if (box) |p| @ptrCast(p) else null, 1)) |p| &p[0] else null;
    push(r, ctxCopySubresourceRegion, .{ raw, r.ref(dst), dsub, dx, dy, dz, r.ref(src), ssub, b });
}

fn dCopyResource(raw: ?*anyopaque, dst: ?*anyopaque, src: ?*anyopaque) callconv(W) void {
    const r = recOf(raw);
    push(r, ctxCopyResource, .{ raw, r.ref(dst), r.ref(src) });
}

fn dResolveSubresource(raw: ?*anyopaque, dst: ?*anyopaque, dsub: u32, src: ?*anyopaque, ssub: u32, fmt: u32) callconv(W) void {
    const r = recOf(raw);
    push(r, ctxResolveSubresource, .{ raw, r.ref(dst), dsub, r.ref(src), ssub, fmt });
}

/// Bytes UpdateSubresource reads from `data` for this resource/box.
fn updateSourceSize(o: *ComObj, sub: u32, box: ?*const D3D11_BOX, row_pitch: u32, depth_pitch: u32) usize {
    if (o.kind == .buffer) {
        if (box) |b| return b.right -| b.left;
        return o.descbuf.ByteWidth;
    }
    if (!isTexKind(o.kind)) return 0;
    const t: *glb.Texture = @ptrFromInt(o.payload);
    const gf = glb.dxgiToGlFormat(t.dxgi_fmt);
    const mip: u5 = @intCast(@min(31, sub % @max(1, t.mip_levels)));
    const w: u32 = if (box) |b| b.right -| b.left else @max(1, t.width >> mip);
    const h: u32 = if (box) |b| b.bottom -| b.top else @max(1, t.height >> mip);
    const d: u32 = if (box) |b| b.back -| b.front else @max(1, t.depth >> mip);
    if (w == 0 or h == 0 or d == 0) return 0;
    const rows: usize = if (gf.compressed) (h + 3) / 4 else h;
    const row_bytes: usize = if (gf.compressed) ((w + 3) / 4) * gf.block_bytes else w * @max(1, gf.bpp);
    const rp: usize = if (row_pitch != 0) row_pitch else row_bytes;
    const dp: usize = if (depth_pitch != 0) depth_pitch else rp * rows;
    return (d - 1) * dp + (rows - 1) * rp + row_bytes;
}

fn dUpdateSubresource(raw: ?*anyopaque, res: ?*anyopaque, sub: u32, box: ?*const D3D11_BOX, data: ?*const anyopaque, row_pitch: u32, depth_pitch: u32) callconv(W) void {
    const r = recOf(raw);
    const o: *ComObj = @ptrCast(@alignCast(res orelse return));
    const src: [*]const u8 = @ptrCast(data orelse return);
    const n = updateSourceSize(o, sub, box, row_pitch, depth_pitch);
    if (n == 0) return;
    const bytes = r.dup(u8, src, n) orelse return;
    const b: ?*const D3D11_BOX = if (r.dup(D3D11_BOX, if (box) |p| @ptrCast(p) else null, 1)) |p| &p[0] else null;
    push(r, ctxUpdateSubresource, .{ raw, r.ref(res), sub, b, @as(?*const anyopaque, @ptrCast(bytes)), row_pitch, depth_pitch });
}

/// Replay of a deferred Map/Unmap: write the recorded bytes through the
/// immediate context's own Map so shadows and GL objects stay in sync.
fn replayUpload(ctx: ?*anyopaque, res: ?*anyopaque, sub: u32, mem: [*]const u8, len: usize) callconv(W) void {
    var m: D3D11_MAPPED_SUBRESOURCE = undefined;
    if (ctxMap(ctx, res, sub, 4, 0, &m) != S_OK) return;
    if (m.pData) |dst| @memcpy(@as([*]u8, @ptrCast(dst))[0..len], mem[0..len]);
    ctxUnmap(ctx, res, sub);
}

/// Replay of a deferred NO_OVERWRITE Map of a buffer: only [off, off+len) was
/// written by the app, so only that range reaches the shadow and GL. Writing
/// the whole recorded copy back would clobber what other command lists put in
/// the same ring buffer meanwhile (Scaleform vertices in DS3).
fn replayUploadRange(_: ?*anyopaque, res: ?*anyopaque, mem: [*]const u8, off: usize, len: usize) callconv(W) void {
    const o: *ComObj = @ptrCast(@alignCast(res orelse return));
    if (o.kind != .buffer or len == 0) return;
    const b: *glb.Buffer = @ptrFromInt(o.payload);
    if (off >= b.size) return;
    glb.uploadBuffer(b, @intCast(off), mem + off, @intCast(@min(len, b.size - off)));
}

/// First and one-past-last differing byte of two equal-length slices.
fn diffRange(a: []const u8, b: []const u8) ?struct { lo: usize, hi: usize } {
    const n = @min(a.len, b.len);
    var lo: usize = 0;
    while (lo + 8 <= n and std.mem.readInt(u64, a[lo..][0..8], .little) == std.mem.readInt(u64, b[lo..][0..8], .little)) lo += 8;
    while (lo < n and a[lo] == b[lo]) lo += 1;
    if (lo == n) return null;
    var hi: usize = n;
    while (hi >= lo + 8 and std.mem.readInt(u64, a[hi - 8 ..][0..8], .little) == std.mem.readInt(u64, b[hi - 8 ..][0..8], .little)) hi -= 8;
    while (hi > lo and a[hi - 1] == b[hi - 1]) hi -= 1;
    return .{ .lo = lo, .hi = hi };
}

fn mapSize(o: *ComObj) ?struct { len: usize, row: u32 } {
    if (o.kind == .buffer) {
        const b: *glb.Buffer = @ptrFromInt(o.payload);
        return .{ .len = b.size, .row = b.size };
    }
    if (isTexKind(o.kind)) {
        const t: *glb.Texture = @ptrFromInt(o.payload);
        const sh = t.shadow orelse return null;
        return .{ .len = sh.len, .row = t.row_pitch };
    }
    return null;
}

/// Deferred contexts may only Map with WRITE_DISCARD (4) or WRITE_NO_OVERWRITE
/// (5). The app writes into recorder memory; Unmap records the upload. For
/// NO_OVERWRITE the buffer starts from the latest bytes this list wrote (or
/// the resource's current shadow) so untouched ranges survive the upload.
fn dMap(raw: ?*anyopaque, res: ?*anyopaque, sub: u32, map_type: u32, _: u32, mapped: *D3D11_MAPPED_SUBRESOURCE) callconv(W) i32 {
    const r = recOf(raw);
    const o: *ComObj = @ptrCast(@alignCast(res orelse return E_INVALIDARG));
    if (map_type != 4 and map_type != 5) return E_INVALIDARG;
    const sz = mapSize(o) orelse return E_INVALIDARG;
    const mem = r.a().alloc(u8, @max(1, sz.len)) catch return E_FAIL;
    var base: ?[]const u8 = null;
    if (map_type == 5) {
        var prev: ?[]const u8 = null;
        var i = r.maps.items.len;
        while (i > 0) : (i -= 1) {
            const mr = r.maps.items[i - 1];
            if (mr.res == @intFromPtr(res) and mr.sub == sub) {
                prev = mr.mem;
                break;
            }
        }
        if (prev == null) {
            if (o.kind == .buffer) {
                const b: *glb.Buffer = @ptrFromInt(o.payload);
                if (b.shadow) |sh| prev = sh;
            } else {
                const t: *glb.Texture = @ptrFromInt(o.payload);
                prev = t.shadow;
            }
        }
        if (prev) |p| @memcpy(mem[0..@min(mem.len, p.len)], p[0..@min(mem.len, p.len)]);
        if (o.kind == .buffer) base = r.a().dupe(u8, mem) catch null;
    }
    r.maps.append(r.a(), .{ .res = @intFromPtr(res), .sub = sub, .mem = mem, .base = base }) catch return E_FAIL;
    mapped.pData = mem.ptr;
    mapped.RowPitch = sz.row;
    mapped.DepthPitch = @intCast(sz.len);
    return S_OK;
}

fn dUnmap(raw: ?*anyopaque, res: ?*anyopaque, sub: u32) callconv(W) void {
    const r = recOf(raw);
    var i = r.maps.items.len;
    while (i > 0) : (i -= 1) {
        const mr = r.maps.items[i - 1];
        if (mr.res == @intFromPtr(res) and mr.sub == sub) {
            if (mr.base) |base| {
                // NO_OVERWRITE on a buffer: upload only what the app changed.
                const d = diffRange(base, mr.mem) orelse return;
                push(r, replayUploadRange, .{ raw, r.ref(res), mr.mem.ptr, d.lo, d.hi - d.lo });
                return;
            }
            push(r, replayUpload, .{ raw, r.ref(res), sub, mr.mem.ptr, mr.mem.len });
            return;
        }
    }
}

fn dExecuteCommandList(raw: ?*anyopaque, cl: ?*anyopaque, restore: i32) callconv(W) void {
    const r = recOf(raw);
    push(r, ctxExecuteCommandList, .{ raw, r.ref(cl), restore });
}

fn dGetType(_: ?*anyopaque) callconv(W) u32 {
    return 1; // D3D11_DEVICE_CONTEXT_DEFERRED
}

fn dFinishCommandList(raw: ?*anyopaque, restore: i32, pp: ?*?*anyopaque) callconv(W) i32 {
    const out = pp orelse return E_INVALIDARG;
    out.* = null;
    const r = recOf(raw);
    if (restore != 0) {
        const T = struct {
            var told = std.atomic.Value(bool).init(false);
        };
        if (!T.told.swap(true, .monotonic)) std.debug.print("[WINS:D3D11] FinishCommandList(RestoreDeferredContextState=TRUE): deferred state is not carried over\n", .{});
    }
    const cl = alloc.create(CmdList) catch return E_FAIL;
    // Hand the arena (and everything recorded into it) to the command list.
    cl.* = .{ .arena = r.arena, .cmds = r.cmds.items, .refs = r.refs.items };
    r.arena = std.heap.ArenaAllocator.init(alloc);
    r.cmds = .empty;
    r.refs = .empty;
    r.maps = .empty;
    r.shadow = .{};
    const o = newCom(&cmdlist_vtbl, .cmdlist, @intFromPtr(cl), g_device) orelse {
        destroyCmdList(cl);
        return E_FAIL;
    };
    out.* = o;
    return S_OK;
}

fn destroyCmdList(cl: *CmdList) void {
    for (cl.refs) |o| _ = comRelease(o);
    cl.arena.deinit();
    alloc.destroy(cl);
}

/// Replays a command list on the immediate context. D3D11 runs a command
/// list from the default state and afterwards either restores the immediate
/// context's previous state or leaves it cleared.
fn ctxExecuteCommandList(_: ?*anyopaque, cl_raw: ?*anyopaque, restore: i32) callconv(W) void {
    const o: *ComObj = @ptrCast(@alignCast(cl_raw orelse return));
    if (o.kind != .cmdlist) return;
    const cl: *CmdList = @ptrFromInt(o.payload);
    {
        // Rare progress line: shows whether a title renders through command lists.
        const S = struct {
            var n: u32 = 0;
            var cmds: u64 = 0;
        };
        S.n += 1;
        S.cmds += cl.cmds.len;
        if (S.n <= 4 or S.n % 1024 == 0) std.debug.print("[WINS:D3D11] ExecuteCommandList #{d}: {d} cmds (total {d})\n", .{ S.n, cl.cmds.len, S.cmds });
    }
    const saved = g_draw_state;
    const saved_com = g_bound;
    g_draw_state = .{};
    g_bound = .{};
    for (cl.cmds) |c| c.run(c.args);
    g_draw_state = if (restore != 0) saved else .{};
    g_bound = if (restore != 0) saved_com else .{};
}

fn cmdlistGetContextFlags(_: ?*anyopaque) callconv(W) u32 {
    return 0;
}

fn devCreateDeferredContext(_: ?*anyopaque, _: u32, pp: ?*?*anyopaque) callconv(W) i32 {
    const out = pp orelse return E_INVALIDARG;
    out.* = null;
    const r = alloc.create(Recorder) catch return E_FAIL;
    r.* = .{ .arena = std.heap.ArenaAllocator.init(alloc) };
    const o = newCom(&deferred_vtbl, .deferred_ctx, @intFromPtr(r), g_device) orelse {
        alloc.destroy(r);
        return E_FAIL;
    };
    out.* = o;
    return S_OK;
}

const cmdlist_vtbl = [_]?*const anyopaque{
    @ptrCast(&comQiDefault), @ptrCast(&comAddRef), @ptrCast(&comRelease),
    @ptrCast(&childGetDevice), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk),
    @ptrCast(&cmdlistGetContextFlags),
};

/// Unrecorded deferred-context slot: it still runs the immediate method right
/// away (out of order), but says so once per slot so missing recorders show.
fn dUnrecorded(comptime slot: usize) *const anyopaque {
    return @ptrCast(&struct {
        var told = std.atomic.Value(bool).init(false);
        fn w(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64) callconv(W) u64 {
            if (!told.swap(true, .monotonic)) std.debug.print("[WINS:D3D11] deferred context: slot {d} is not recorded (runs immediately)\n", .{slot});
            const F = *const fn (u64, u64, u64, u64, u64, u64, u64, u64) callconv(W) u64;
            const f: F = @ptrCast(context_vtbl[slot].?);
            return f(a0, a1, a2, a3, a4, a5, a6, a7);
        }
    }.w);
}

/// The immediate vtable with every state-touching slot swapped for a recorder.
const deferred_vtbl = blk: {
    var v = context_vtbl;
    // Default: every state slot (below the getters, 87..109) logs its first use.
    for (7..87) |i| v[i] = dUnrecorded(i);
    v[110] = dUnrecorded(110);
    v[111] = dUnrecorded(111);
    v[7] = dSetArr(ctxVSSetCB);
    v[8] = dSetArr(ctxPSSetSRV);
    v[9] = dSetShader(ctxPSSetShader);
    v[10] = dSetArr(ctxPSSetSamplers);
    v[11] = dSetShader(ctxVSSetShader);
    v[12] = dVal(ctxDrawIndexed);
    v[13] = dVal(ctxDraw);
    v[14] = @ptrCast(&dMap);
    v[15] = @ptrCast(&dUnmap);
    v[16] = dSetArr(ctxPSSetCB);
    v[17] = dObj1(ctxIASetInputLayout);
    v[18] = @ptrCast(&dIASetVertexBuffers);
    v[19] = dObj1(ctxIASetIndexBuffer);
    v[20] = dVal(ctxDrawIndexedInstanced);
    v[21] = dVal(ctxDrawInstanced);
    v[24] = dVal(ctxIASetTopology);
    v[25] = dSetArr(ctxVSSetSRV);
    v[26] = dSetArr(ctxVSSetSamplers);
    v[29] = @ptrCast(&stubRetOk); // GetData is invalid on a deferred context
    v[33] = @ptrCast(&dOMSetRenderTargets);
    v[35] = @ptrCast(&dOMSetBlendState);
    v[36] = @ptrCast(&dOMSetDepthStencilState);
    v[43] = @ptrCast(&dRSSetState);
    v[44] = @ptrCast(&dRSSetViewports);
    v[45] = @ptrCast(&dRSSetScissors);
    v[46] = @ptrCast(&dCopySubresourceRegion);
    v[47] = @ptrCast(&dCopyResource);
    v[48] = @ptrCast(&dUpdateSubresource);
    v[50] = @ptrCast(&dClearRTV);
    v[53] = dObj1(ctxClearDSV);
    v[54] = dObj1(ctxGenerateMips);
    v[57] = @ptrCast(&dResolveSubresource);
    v[58] = @ptrCast(&dExecuteCommandList);
    v[110] = dVal(ctxClearState);
    v[112] = @ptrCast(&dGetType);
    v[114] = @ptrCast(&dFinishCommandList);
    break :blk v;
};


// ---- DLL Export Entry Points ------------------------------------------------

fn ensureDeviceAndContext() void {
    _ = glb.ensureStarted();
    if (g_device == null) {
        g_device = newCom(&device_vtbl, .device, 0, null);
        g_context = newCom(&context_vtbl, .context, 0, g_device);
    }
}

pub fn createDXGIFactory(riid: *const GUID, ppFactory: *?*anyopaque) callconv(W) i32 {
    trace("CreateDXGIFactory", .{});
    const f = getSingletonFactory();
    return comQiDefault(f, riid, ppFactory);
}

pub fn createDXGIFactory1(riid: *const GUID, ppFactory: *?*anyopaque) callconv(W) i32 {
    trace("CreateDXGIFactory1", .{});
    const f = getSingletonFactory();
    return comQiDefault(f, riid, ppFactory);
}

pub fn d3d11CreateDevice(
    pAdapter: ?*anyopaque,
    driverType: u32,
    software: usize,
    flags: u32,
    pFeatureLevels: ?[*]const u32,
    featureLevels: u32,
    sdkVersion: u32,
    ppDevice: ?*?*anyopaque,
    pFeatureLevel: ?*u32,
    ppImmediateContext: ?*?*anyopaque,
) callconv(W) i32 {
    _ = pAdapter;
    _ = software;
    _ = flags;
    _ = pFeatureLevels;
    _ = featureLevels;
    _ = sdkVersion;
    trace("D3D11CreateDevice driverType={d}", .{driverType});
    ensureDeviceAndContext();
    if (pFeatureLevel) |fl| fl.* = D3D_FEATURE_LEVEL_11_0;
    if (ppDevice) |d| {
        _ = comAddRef(g_device);
        d.* = g_device;
    }
    if (ppImmediateContext) |c| {
        _ = comAddRef(g_context);
        c.* = g_context;
    }
    return S_OK;
}

pub fn d3d11CreateDeviceAndSwapChain(
    pAdapter: ?*anyopaque,
    driverType: u32,
    software: usize,
    flags: u32,
    pFeatureLevels: ?[*]const u32,
    featureLevels: u32,
    sdkVersion: u32,
    pSwapChainDesc: ?*const DXGI_SWAP_CHAIN_DESC,
    ppSwapChain: ?*?*anyopaque,
    ppDevice: ?*?*anyopaque,
    pFeatureLevel: ?*u32,
    ppImmediateContext: ?*?*anyopaque,
) callconv(W) i32 {
    const hr = d3d11CreateDevice(pAdapter, driverType, software, flags, pFeatureLevels, featureLevels, sdkVersion, ppDevice, pFeatureLevel, ppImmediateContext);
    if (hr != S_OK) return hr;
    if (pSwapChainDesc != null and ppSwapChain != null) {
        return facCreateSwapChain(getSingletonFactory(), g_device, pSwapChainDesc.?, ppSwapChain.?);
    }
    return S_OK;
}
