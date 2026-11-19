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
    descbuf: D3D11_BUFFER_DESC = std.mem.zeroes(D3D11_BUFFER_DESC),
    swap_desc: DXGI_SWAP_CHAIN_DESC = std.mem.zeroes(DXGI_SWAP_CHAIN_DESC),

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
        switch (o.kind) {
            .buffer => if (o.payload != 0) {
                const b: *glb.Buffer = @ptrFromInt(o.payload);
                glb.destroyBuffer(b);
                alloc.destroy(b);
            },
            .texture2d => if (o.payload != 0) {
                const t: *glb.Texture = @ptrFromInt(o.payload);
                glb.destroyTexture(t);
                alloc.destroy(t);
            },
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
    if (o.kind == .context and eqlGuid(riid, &IID_ID3D11DeviceContext)) {
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
    if (o.kind == .buffer and (eqlGuid(riid, &IID_ID3D11Buffer) or eqlGuid(riid, &IID_ID3D11Resource))) {
        _ = comAddRef(raw);
        ppv.* = raw;
        return S_OK;
    }
    ppv.* = null;
    return E_NOINTERFACE;
}

fn stubRetOk() callconv(W) i32 { return S_OK; }
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

fn scPresent(raw: ?*anyopaque, sync: u32, _: u32) callconv(W) i32 {
    const sc: *ComObj = @ptrCast(@alignCast(raw orelse return E_INVALIDARG));
    const bb_obj: *ComObj = @ptrFromInt(sc.payload);
    const bb_tex: *glb.Texture = @ptrFromInt(bb_obj.payload);
    glb.present(bb_tex, sc.swap_desc.OutputWindow, sync);
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

fn extractResTexture(res: ?*anyopaque) struct { tex: ?*glb.Texture, buf: ?*glb.Buffer } {
    const o: *ComObj = @ptrCast(@alignCast(res orelse return .{ .tex = null, .buf = null }));
    if (o.kind == .texture2d) return .{ .tex = @ptrFromInt(o.payload), .buf = null };
    if (o.kind == .buffer) return .{ .tex = null, .buf = @ptrFromInt(o.payload) };
    return .{ .tex = null, .buf = null };
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
        if (d.ViewDimension == 4 or d.ViewDimension == 5) { // TEXTURE2D / TEXTURE2DARRAY
            v.first_mip = d.u0;
            if (d.ViewDimension == 5) v.first_slice = d.u1;
        }
    }
    const o = newCom(&view_vtbl, .rtv, @intFromPtr(v), g_device) orelse return E_FAIL;
    if (res) |ro| {
        o.view_res = @ptrCast(@alignCast(ro));
        _ = comAddRef(ro);
    }
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
    pp.?.* = newCom(&child_vtbl, .blend, @intFromPtr(bs), g_device);
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
    pp.?.* = newCom(&child_vtbl, .depth_stencil, @intFromPtr(ds), g_device);
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
    pp.?.* = newCom(&child_vtbl, .rasterizer, @intFromPtr(rs), g_device);
    return S_OK;
}

fn devCreateSamplerState(_: ?*anyopaque, desc: *const D3D11_SAMPLER_DESC, pp: ?*?*anyopaque) callconv(W) i32 {
    if (pp == null) return S_FALSE;
    const sm = alloc.create(glb.Sampler) catch return E_FAIL;
    sm.* = .{};
    glb.createSampler(sm, desc.Filter, desc.AddressU, desc.AddressV, desc.AddressW, desc.MipLODBias, desc.MaxAnisotropy, desc.ComparisonFunc, desc.BorderColor, desc.MinLOD, desc.MaxLOD);
    pp.?.* = newCom(&child_vtbl, .sampler, @intFromPtr(sm), g_device);
    return S_OK;
}

fn devCreateQuery(_: ?*anyopaque, desc: ?*const [2]u32, pp: ?*?*anyopaque) callconv(W) i32 {
    if (pp == null) return S_FALSE;
    const qt: usize = if (desc) |d| d[0] else 0;
    pp.?.* = newCom(&child_vtbl, .query, qt, g_device);
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
    pType.* = if (o.kind == .buffer) 1 else 3;
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

fn ctxOMSetRenderTargets(_: ?*anyopaque, num: u32, ppRTV: ?[*]const ?*anyopaque, pDSV: ?*anyopaque) callconv(W) void {
    const n = @min(8, num);
    g_draw_state.num_rtvs = n;
    for (0..8) |i| {
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
    g_draw_state.blend = if (bs) |r| @ptrFromInt(@as(*ComObj, @ptrCast(@alignCast(r))).payload) else null;
    if (factor) |f| g_draw_state.blend_factor = f.* else g_draw_state.blend_factor = .{ 1, 1, 1, 1 };
    g_draw_state.sample_mask = mask;
}

fn ctxOMSetDepthStencilState(_: ?*anyopaque, ds: ?*anyopaque, ref: u32) callconv(W) void {
    g_draw_state.depth_stencil = if (ds) |r| @ptrFromInt(@as(*ComObj, @ptrCast(@alignCast(r))).payload) else null;
    g_draw_state.stencil_ref = ref;
}

fn ctxRSSetState(_: ?*anyopaque, rs: ?*anyopaque) callconv(W) void {
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
    } else if (o.kind == .texture2d) {
        const t: *glb.Texture = @ptrFromInt(o.payload);
        traceFmt(t.dxgi_fmt, "map gl={d} sub={d} type={d} shadow={}", .{ t.gl_id, sub, map_type, t.shadow != null });
        if (t.shadow) |sh| {
            mapped.pData = sh.ptr;
            mapped.RowPitch = t.row_pitch;
            mapped.DepthPitch = @intCast(sh.len);
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
    } else if (o.kind == .texture2d) {
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
    } else if (o.kind == .texture2d) {
        const t: *glb.Texture = @ptrFromInt(o.payload);
        const bx = if (box) |b| [6]u32{ b.left, b.top, b.front, b.right, b.bottom, b.back } else [_]u32{0} ** 6;
        traceFmt(t.dxgi_fmt, "update gl={d} sub={d} box={} [{d},{d})x[{d},{d}) pitch={d} nz={d}", .{
            t.gl_id, sub, box != null, bx[0], bx[3], bx[1], bx[4], row_pitch,
            if (traceFmtOn(t.dxgi_fmt)) nonzeroBytes(dptr, @as(usize, row_pitch) * (if (box != null) bx[4] -| bx[1] else t.height)) else 0,
        });
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

const view_vtbl = [_]?*const anyopaque{
    @ptrCast(&comQiDefault), @ptrCast(&comAddRef), @ptrCast(&comRelease),
    @ptrCast(&childGetDevice), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk), @ptrCast(&stubRetOk),
    @ptrCast(&viewGetResource), @ptrCast(&viewGetDesc),
};

const device_vtbl = [_]?*const anyopaque{
    @ptrCast(&comQiDefault), @ptrCast(&comAddRef), @ptrCast(&comRelease), // 0..2
    @ptrCast(&devCreateBuffer), // 3
    @ptrCast(&stubRetOk), // 4 CreateTexture1D
    @ptrCast(&devCreateTexture2D), // 5
    @ptrCast(&stubRetOk), // 6 CreateTexture3D
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
    @ptrCast(&stubRetOk), // 19 CreateClassLinkage
    @ptrCast(&devCreateBlendState), // 20
    @ptrCast(&devCreateDepthStencilState), // 21
    @ptrCast(&devCreateRasterizerState), // 22
    @ptrCast(&devCreateSamplerState), // 23
    @ptrCast(&devCreateQuery), // 24
    @ptrCast(&devCreateQuery), // 25 CreatePredicate
    @ptrCast(&stubRetOk), // 26 CreateCounter
    @ptrCast(&stubRetOk), // 27 CreateDeferredContext
    @ptrCast(&stubRetOk), // 28 OpenSharedResource
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
    @ptrCast(&stubVoid), // 22 GSSetConstantBuffers
    @ptrCast(&stubVoid), // 23 GSSetShader
    @ptrCast(&ctxIASetTopology), // 24
    @ptrCast(&ctxVSSetSRV), // 25
    @ptrCast(&ctxVSSetSamplers), // 26
    @ptrCast(&stubVoid), // 27 Begin
    @ptrCast(&stubVoid), // 28 End
    @ptrCast(&ctxGetData), // 29
    @ptrCast(&stubVoid), // 30 SetPredication
    @ptrCast(&stubVoid), // 31 GSSetShaderResources
    @ptrCast(&stubVoid), // 32 GSSetSamplers
    @ptrCast(&ctxOMSetRenderTargets), // 33
    @ptrCast(&stubVoid), // 34 OMSetRenderTargetsAndUAVs
    @ptrCast(&ctxOMSetBlendState), // 35
    @ptrCast(&ctxOMSetDepthStencilState), // 36
    @ptrCast(&stubVoid), // 37 SOSetTargets
    @ptrCast(&stubVoid), // 38 DrawAuto
    @ptrCast(&stubVoid), // 39 DrawIndexedInstancedIndirect
    @ptrCast(&stubVoid), // 40 DrawInstancedIndirect
    @ptrCast(&stubVoid), // 41 Dispatch
    @ptrCast(&stubVoid), // 42 DispatchIndirect
    @ptrCast(&ctxRSSetState), // 43
    @ptrCast(&ctxRSSetViewports), // 44
    @ptrCast(&ctxRSSetScissors), // 45
    @ptrCast(&ctxCopySubresourceRegion), // 46
    @ptrCast(&ctxCopyResource), // 47
    @ptrCast(&ctxUpdateSubresource), // 48
    @ptrCast(&stubVoid), // 49 CopyStructureCount
    @ptrCast(&ctxClearRTV), // 50
    @ptrCast(&ctxClearDSV), // 51
    @ptrCast(&stubVoid), // 52 ClearUAVUint
    @ptrCast(&stubVoid), // 53 ClearUAVFloat
    @ptrCast(&ctxResolveSubresource), // 54
    @ptrCast(&ctxGenerateMips), // 55
    @ptrCast(&stubVoid), // 56 SetResourceMinLOD
    @ptrCast(&stubRetZero), // 57 GetResourceMinLOD
    @ptrCast(&stubVoid), // 58 ExecuteCommandList
    @ptrCast(&stubVoid), @ptrCast(&stubVoid), @ptrCast(&stubVoid), @ptrCast(&stubVoid), // 59..62 HS
    @ptrCast(&stubVoid), @ptrCast(&stubVoid), @ptrCast(&stubVoid), @ptrCast(&stubVoid), // 63..66 DS
    @ptrCast(&stubVoid), @ptrCast(&stubVoid), @ptrCast(&stubVoid), @ptrCast(&stubVoid), @ptrCast(&stubVoid), // 67..71 CS
} ++ ([_]?*const anyopaque{@ptrCast(&stubVoid)} ** 35) ++ [_]?*const anyopaque{ // 72..106 Getters
    @ptrCast(&ctxClearState), // 107
    @ptrCast(&stubVoid), // 108 Flush
    @ptrCast(&ctxGetType), // 109
    @ptrCast(&stubRetZero), // 110 GetContextFlags
    @ptrCast(&stubRetOk), // 111 FinishCommandList
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
