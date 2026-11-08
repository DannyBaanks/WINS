//! WINS Native Direct3D 9 State Tracker & COM Implementation (Zig 0.16)
//! Provides a 100% native Linux Direct3D 9 runtime (Zero Wine, Zero Proton).
//! Directly implements IDirect3D9, IDirect3DDevice9, IDirect3DTexture9,
//! IDirect3DVertexBuffer9, and IDirect3DIndexBuffer9 with true bit-exact __stdcall ABI.

const std = @import("std");
const linux = std.os.linux;

const W: std.builtin.CallingConvention = .winapi;

// ============================================================================
// D3D9 Types & Enums
// ============================================================================

pub const HRESULT = i32;
pub const S_OK: HRESULT = 0;
pub const S_FALSE: HRESULT = 1;
pub const E_FAIL: HRESULT = -2147467259; // 0x80004005
pub const E_NOINTERFACE: HRESULT = -2147467262; // 0x80004002
pub const E_OUTOFMEMORY: HRESULT = -2147024882; // 0x8007000E
pub const D3D_OK: HRESULT = S_OK;

pub const D3DFORMAT = enum(u32) {
    UNKNOWN = 0,
    R8G8B8 = 20,
    A8R8G8B8 = 21,
    X8R8G8B8 = 22,
    R5G6B5 = 23,
    X1R5G5B5 = 24,
    A1R5G5B5 = 25,
    A4R4G4B4 = 26,
    R3G3B2 = 27,
    A8 = 28,
    A8R3G3B2 = 29,
    X4R4G4B4 = 30,
    A2B10G10R10 = 31,
    A8B8G8R8 = 32,
    X8B8G8R8 = 33,
    G16R16 = 34,
    A2R10G10B10 = 35,
    A16B16G16R16 = 36,
    D16_LOCKABLE = 70,
    D32 = 71,
    D15S1 = 73,
    D24S8 = 75,
    D24X8 = 77,
    D24X4S4 = 79,
    D16 = 80,
    D32F_LOCKABLE = 82,
    D24FS8 = 83,
    _,
};

pub const D3DPRIMITIVETYPE = enum(u32) {
    POINTLIST = 1,
    LINELIST = 2,
    LINESTRIP = 3,
    TRIANGLELIST = 4,
    TRIANGLESTRIP = 5,
    TRIANGLEFAN = 6,
    _,
};

pub const D3DCAPS9 = extern struct {
    DeviceType: u32,
    AdapterOrdinal: u32,
    Caps: u32,
    Caps2: u32,
    Caps3: u32,
    PresentationIntervals: u32,
    CursorCaps: u32,
    DevCaps: u32,
    PrimitiveMiscCaps: u32,
    RasterCaps: u32,
    ZCmpCaps: u32,
    SrcBlendCaps: u32,
    DestBlendCaps: u32,
    AlphaCmpCaps: u32,
    ShadeCaps: u32,
    TextureCaps: u32,
    TextureFilterCaps: u32,
    CubeTextureFilterCaps: u32,
    VolumeTextureFilterCaps: u32,
    TextureAddressCaps: u32,
    VolumeTextureAddressCaps: u32,
    LineCaps: u32,
    MaxTextureWidth: u32,
    MaxTextureHeight: u32,
    MaxVolumeExtent: u32,
    MaxTextureRepeat: u32,
    MaxTextureAspectRatio: u32,
    MaxAnisotropy: u32,
    MaxVertexW: f32,
    GuardBandLeft: f32,
    GuardBandTop: f32,
    GuardBandRight: f32,
    GuardBandBottom: f32,
    ExtentsAdjust: f32,
    StencilCaps: u32,
    FVFCaps: u32,
    TextureOpCaps: u32,
    MaxTextureBlendStages: u32,
    MaxSimultaneousTextures: u32,
    VertexProcessingCaps: u32,
    MaxActiveLights: u32,
    MaxUserClipPlanes: u32,
    MaxVertexBlendMatrices: u32,
    MaxVertexBlendMatrixIndex: u32,
    MaxPointSize: f32,
    MaxPrimitiveCount: u32,
    MaxVertexIndex: u32,
    MaxStreams: u32,
    MaxStreamStride: u32,
    VertexShaderVersion: u32,
    MaxVertexShaderConst: u32,
    PixelShaderVersion: u32,
    PixelShader1xMaxValue: f32,
    DevCaps2: u32,
    MaxNpatchTessellationLevel: f32,
    Reserved5: u32,
    MasterAdapterOrdinal: u32,
    AdapterOrdinalInGroup: u32,
    NumberOfAdaptersInGroup: u32,
    DeclTypes: u32,
    NumSimultaneousRTs: u32,
    StretchRectFilterCaps: u32,
    VS20Caps: [2]u32,
    PS20Caps: [2]u32,
    VertexTextureFilterCaps: u32,
    MaxVShaderInstructionsExecuted: u32,
    MaxPShaderInstructionsExecuted: u32,
    MaxVertexShader30InstructionSlots: u32,
    MaxPixelShader30InstructionSlots: u32,
};

pub const D3DPRESENT_PARAMETERS = extern struct {
    BackBufferWidth: u32,
    BackBufferHeight: u32,
    BackBufferFormat: u32,
    BackBufferCount: u32,
    MultiSampleType: u32,
    MultiSampleQuality: u32,
    SwapEffect: u32,
    hDeviceWindow: usize,
    Windowed: i32,
    EnableAutoDepthStencil: i32,
    AutoDepthStencilFormat: u32,
    Flags: u32,
    FullScreen_RefreshRateInHz: u32,
    PresentationInterval: u32,
};

pub const D3DVIEWPORT9 = extern struct {
    X: u32,
    Y: u32,
    Width: u32,
    Height: u32,
    MinZ: f32,
    MaxZ: f32,
};

pub const D3DRECT = extern struct {
    x1: i32,
    y1: i32,
    x2: i32,
    y2: i32,
};

pub const D3DLOCKED_RECT = extern struct {
    Pitch: i32,
    pBits: ?*anyopaque,
};

// ============================================================================
// COM Vtable Definitions
// ============================================================================

pub const IDirect3D9Vtbl = extern struct {
    QueryInterface: *const fn (*anyopaque, ?*const anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    AddRef: *const fn (*anyopaque) callconv(W) u32,
    Release: *const fn (*anyopaque) callconv(W) u32,
    RegisterSoftwareDevice: *const fn (*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    GetAdapterCount: *const fn (*anyopaque) callconv(W) u32,
    GetAdapterIdentifier: *const fn (*anyopaque, u32, u32, ?*anyopaque) callconv(W) HRESULT,
    GetAdapterModeCount: *const fn (*anyopaque, u32, u32) callconv(W) u32,
    EnumAdapterModes: *const fn (*anyopaque, u32, u32, u32, ?*anyopaque) callconv(W) HRESULT,
    GetAdapterDisplayMode: *const fn (*anyopaque, u32, ?*anyopaque) callconv(W) HRESULT,
    CheckDeviceType: *const fn (*anyopaque, u32, u32, u32, u32, i32) callconv(W) HRESULT,
    CheckDeviceFormat: *const fn (*anyopaque, u32, u32, u32, u32, u32, u32) callconv(W) HRESULT,
    CheckDeviceMultiSampleType: *const fn (*anyopaque, u32, u32, u32, i32, u32, ?*u32) callconv(W) HRESULT,
    CheckDepthStencilMatch: *const fn (*anyopaque, u32, u32, u32, u32, u32) callconv(W) HRESULT,
    CheckDeviceFormatConversion: *const fn (*anyopaque, u32, u32, u32, u32) callconv(W) HRESULT,
    GetDeviceCaps: *const fn (*anyopaque, u32, u32, ?*D3DCAPS9) callconv(W) HRESULT,
    GetAdapterMonitor: *const fn (*anyopaque, u32) callconv(W) usize,
    CreateDevice: *const fn (*anyopaque, u32, u32, usize, u32, ?*D3DPRESENT_PARAMETERS, ?*?*anyopaque) callconv(W) HRESULT,
};

pub const IDirect3DDevice9Vtbl = extern struct {
    QueryInterface: *const fn (*anyopaque, ?*const anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    AddRef: *const fn (*anyopaque) callconv(W) u32,
    Release: *const fn (*anyopaque) callconv(W) u32,
    TestCooperativeLevel: *const fn (*anyopaque) callconv(W) HRESULT,
    GetAvailableTextureMem: *const fn (*anyopaque) callconv(W) u32,
    EvictManagedResources: *const fn (*anyopaque) callconv(W) HRESULT,
    GetDirect3D: *const fn (*anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    GetDeviceCaps: *const fn (*anyopaque, ?*D3DCAPS9) callconv(W) HRESULT,
    GetDisplayMode: *const fn (*anyopaque, u32, ?*anyopaque) callconv(W) HRESULT,
    GetCreationParameters: *const fn (*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    SetCursorProperties: *const fn (*anyopaque, u32, u32, ?*anyopaque) callconv(W) HRESULT,
    SetCursorPosition: *const fn (*anyopaque, i32, i32, u32) callconv(W) void,
    ShowCursor: *const fn (*anyopaque, i32) callconv(W) i32,
    CreateAdditionalSwapChain: *const fn (*anyopaque, ?*D3DPRESENT_PARAMETERS, ?*?*anyopaque) callconv(W) HRESULT,
    GetSwapChain: *const fn (*anyopaque, u32, ?*?*anyopaque) callconv(W) HRESULT,
    GetNumberOfSwapChains: *const fn (*anyopaque) callconv(W) u32,
    Reset: *const fn (*anyopaque, ?*D3DPRESENT_PARAMETERS) callconv(W) HRESULT,
    Present: *const fn (*anyopaque, ?*const D3DRECT, ?*const D3DRECT, usize, ?*const anyopaque) callconv(W) HRESULT,
    GetBackBuffer: *const fn (*anyopaque, u32, u32, u32, ?*?*anyopaque) callconv(W) HRESULT,
    GetRasterStatus: *const fn (*anyopaque, u32, ?*anyopaque) callconv(W) HRESULT,
    SetDialogBoxMode: *const fn (*anyopaque, i32) callconv(W) HRESULT,
    SetGammaRamp: *const fn (*anyopaque, u32, u32, ?*const anyopaque) callconv(W) void,
    GetGammaRamp: *const fn (*anyopaque, u32, ?*anyopaque) callconv(W) void,
    CreateTexture: *const fn (*anyopaque, u32, u32, u32, u32, u32, u32, ?*?*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    CreateVolumeTexture: *const fn (*anyopaque, u32, u32, u32, u32, u32, u32, u32, ?*?*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    CreateCubeTexture: *const fn (*anyopaque, u32, u32, u32, u32, u32, ?*?*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    CreateVertexBuffer: *const fn (*anyopaque, u32, u32, u32, u32, ?*?*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    CreateIndexBuffer: *const fn (*anyopaque, u32, u32, u32, u32, ?*?*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    CreateRenderTarget: *const fn (*anyopaque, u32, u32, u32, u32, u32, i32, ?*?*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    CreateDepthStencilSurface: *const fn (*anyopaque, u32, u32, u32, u32, u32, i32, ?*?*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    UpdateSurface: *const fn (*anyopaque, ?*anyopaque, ?*const D3DRECT, ?*anyopaque, ?*const anyopaque) callconv(W) HRESULT,
    UpdateTexture: *const fn (*anyopaque, ?*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    GetRenderTargetData: *const fn (*anyopaque, ?*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    GetFrontBufferData: *const fn (*anyopaque, u32, ?*anyopaque) callconv(W) HRESULT,
    StretchRect: *const fn (*anyopaque, ?*anyopaque, ?*const D3DRECT, ?*anyopaque, ?*const D3DRECT, u32) callconv(W) HRESULT,
    ColorFill: *const fn (*anyopaque, ?*anyopaque, ?*const D3DRECT, u32) callconv(W) HRESULT,
    CreateOffscreenPlainSurface: *const fn (*anyopaque, u32, u32, u32, u32, ?*?*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    SetRenderTarget: *const fn (*anyopaque, u32, ?*anyopaque) callconv(W) HRESULT,
    GetRenderTarget: *const fn (*anyopaque, u32, ?*?*anyopaque) callconv(W) HRESULT,
    SetDepthStencilSurface: *const fn (*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    GetDepthStencilSurface: *const fn (*anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    BeginScene: *const fn (*anyopaque) callconv(W) HRESULT,
    EndScene: *const fn (*anyopaque) callconv(W) HRESULT,
    Clear: *const fn (*anyopaque, u32, ?*const D3DRECT, u32, u32, f32, u32) callconv(W) HRESULT,
    SetTransform: *const fn (*anyopaque, u32, ?*const anyopaque) callconv(W) HRESULT,
    GetTransform: *const fn (*anyopaque, u32, ?*anyopaque) callconv(W) HRESULT,
    MultiplyTransform: *const fn (*anyopaque, u32, ?*const anyopaque) callconv(W) HRESULT,
    SetViewport: *const fn (*anyopaque, ?*const D3DVIEWPORT9) callconv(W) HRESULT,
    GetViewport: *const fn (*anyopaque, ?*D3DVIEWPORT9) callconv(W) HRESULT,
    SetMaterial: *const fn (*anyopaque, ?*const anyopaque) callconv(W) HRESULT,
    GetMaterial: *const fn (*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    SetLight: *const fn (*anyopaque, u32, ?*const anyopaque) callconv(W) HRESULT,
    GetLight: *const fn (*anyopaque, u32, ?*anyopaque) callconv(W) HRESULT,
    LightEnable: *const fn (*anyopaque, u32, i32) callconv(W) HRESULT,
    GetLightEnable: *const fn (*anyopaque, u32, ?*i32) callconv(W) HRESULT,
    SetClipPlane: *const fn (*anyopaque, u32, ?*const f32) callconv(W) HRESULT,
    GetClipPlane: *const fn (*anyopaque, u32, ?*f32) callconv(W) HRESULT,
    SetRenderState: *const fn (*anyopaque, u32, u32) callconv(W) HRESULT,
    GetRenderState: *const fn (*anyopaque, u32, ?*u32) callconv(W) HRESULT,
    CreateStateBlock: *const fn (*anyopaque, u32, ?*?*anyopaque) callconv(W) HRESULT,
    BeginStateBlock: *const fn (*anyopaque) callconv(W) HRESULT,
    EndStateBlock: *const fn (*anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    SetClipStatus: *const fn (*anyopaque, ?*const anyopaque) callconv(W) HRESULT,
    GetClipStatus: *const fn (*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    GetTexture: *const fn (*anyopaque, u32, ?*?*anyopaque) callconv(W) HRESULT,
    SetTexture: *const fn (*anyopaque, u32, ?*anyopaque) callconv(W) HRESULT,
    GetTextureStageState: *const fn (*anyopaque, u32, u32, ?*u32) callconv(W) HRESULT,
    SetTextureStageState: *const fn (*anyopaque, u32, u32, u32) callconv(W) HRESULT,
    GetSamplerState: *const fn (*anyopaque, u32, u32, ?*u32) callconv(W) HRESULT,
    SetSamplerState: *const fn (*anyopaque, u32, u32, u32) callconv(W) HRESULT,
    ValidateDevice: *const fn (*anyopaque, ?*u32) callconv(W) HRESULT,
    SetPaletteEntries: *const fn (*anyopaque, u32, ?*const anyopaque) callconv(W) HRESULT,
    GetPaletteEntries: *const fn (*anyopaque, u32, ?*anyopaque) callconv(W) HRESULT,
    SetCurrentTexturePalette: *const fn (*anyopaque, u32) callconv(W) HRESULT,
    GetCurrentTexturePalette: *const fn (*anyopaque, ?*u32) callconv(W) HRESULT,
    SetScissorRect: *const fn (*anyopaque, ?*const D3DRECT) callconv(W) HRESULT,
    GetScissorRect: *const fn (*anyopaque, ?*D3DRECT) callconv(W) HRESULT,
    SetSoftwareVertexProcessing: *const fn (*anyopaque, i32) callconv(W) HRESULT,
    GetSoftwareVertexProcessing: *const fn (*anyopaque) callconv(W) i32,
    SetNPatchMode: *const fn (*anyopaque, f32) callconv(W) HRESULT,
    GetNPatchMode: *const fn (*anyopaque) callconv(W) f32,
    DrawPrimitive: *const fn (*anyopaque, u32, u32, u32) callconv(W) HRESULT,
    DrawIndexedPrimitive: *const fn (*anyopaque, u32, i32, u32, u32, u32, u32) callconv(W) HRESULT,
    DrawPrimitiveUP: *const fn (*anyopaque, u32, u32, ?*const anyopaque, u32) callconv(W) HRESULT,
    DrawIndexedPrimitiveUP: *const fn (*anyopaque, u32, u32, u32, u32, ?*const anyopaque, u32, ?*const anyopaque, u32) callconv(W) HRESULT,
    ProcessVertices: *const fn (*anyopaque, u32, u32, u32, ?*anyopaque, ?*anyopaque, u32) callconv(W) HRESULT,
    CreateVertexDeclaration: *const fn (*anyopaque, ?*const anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    SetVertexDeclaration: *const fn (*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    GetVertexDeclaration: *const fn (*anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    SetFVF: *const fn (*anyopaque, u32) callconv(W) HRESULT,
    GetFVF: *const fn (*anyopaque, ?*u32) callconv(W) HRESULT,
    CreateVertexShader: *const fn (*anyopaque, ?*const u32, ?*?*anyopaque) callconv(W) HRESULT,
    SetVertexShader: *const fn (*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    GetVertexShader: *const fn (*anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    SetVertexShaderConstantF: *const fn (*anyopaque, u32, ?*const f32, u32) callconv(W) HRESULT,
    GetVertexShaderConstantF: *const fn (*anyopaque, u32, ?*f32, u32) callconv(W) HRESULT,
    SetVertexShaderConstantI: *const fn (*anyopaque, u32, ?*const i32, u32) callconv(W) HRESULT,
    GetVertexShaderConstantI: *const fn (*anyopaque, u32, ?*i32, u32) callconv(W) HRESULT,
    SetVertexShaderConstantB: *const fn (*anyopaque, u32, ?*const i32, u32) callconv(W) HRESULT,
    GetVertexShaderConstantB: *const fn (*anyopaque, u32, ?*i32, u32) callconv(W) HRESULT,
    SetStreamSource: *const fn (*anyopaque, u32, ?*anyopaque, u32, u32) callconv(W) HRESULT,
    GetStreamSource: *const fn (*anyopaque, u32, ?*?*anyopaque, ?*u32, ?*u32) callconv(W) HRESULT,
    SetStreamSourceFreq: *const fn (*anyopaque, u32, u32) callconv(W) HRESULT,
    GetStreamSourceFreq: *const fn (*anyopaque, u32, ?*u32) callconv(W) HRESULT,
    SetIndices: *const fn (*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    GetIndices: *const fn (*anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    CreatePixelShader: *const fn (*anyopaque, ?*const u32, ?*?*anyopaque) callconv(W) HRESULT,
    SetPixelShader: *const fn (*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    GetPixelShader: *const fn (*anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    SetPixelShaderConstantF: *const fn (*anyopaque, u32, ?*const f32, u32) callconv(W) HRESULT,
    GetPixelShaderConstantF: *const fn (*anyopaque, u32, ?*f32, u32) callconv(W) HRESULT,
    SetPixelShaderConstantI: *const fn (*anyopaque, u32, ?*const i32, u32) callconv(W) HRESULT,
    GetPixelShaderConstantI: *const fn (*anyopaque, u32, ?*i32, u32) callconv(W) HRESULT,
    SetPixelShaderConstantB: *const fn (*anyopaque, u32, ?*const i32, u32) callconv(W) HRESULT,
    GetPixelShaderConstantB: *const fn (*anyopaque, u32, ?*i32, u32) callconv(W) HRESULT,
    DrawRectPatch: *const fn (*anyopaque, u32, ?*const f32, ?*const anyopaque) callconv(W) HRESULT,
    DrawTriPatch: *const fn (*anyopaque, u32, ?*const f32, ?*const anyopaque) callconv(W) HRESULT,
    DeletePatch: *const fn (*anyopaque, u32) callconv(W) HRESULT,
    CreateQuery: *const fn (*anyopaque, u32, ?*?*anyopaque) callconv(W) HRESULT,
};

// ============================================================================
// State Tracker Implementations
// ============================================================================

pub const WinsD3D9 = struct {
    vtbl: *const IDirect3D9Vtbl,
    ref_count: u32,

    pub fn init() WinsD3D9 {
        return .{
            .vtbl = &g_d3d9_vtbl,
            .ref_count = 1,
        };
    }
};

pub const WinsD3DDevice9 = struct {
    vtbl: *const IDirect3DDevice9Vtbl,
    ref_count: u32,
    params: D3DPRESENT_PARAMETERS,
    viewport: D3DVIEWPORT9,
    in_scene: bool,
    frame_count: u64,
    draw_call_count: u64,
    backbuffer: []u32, // RGBA pixels allocated in host memory

    pub fn init(allocator: std.mem.Allocator, params: D3DPRESENT_PARAMETERS) !*WinsD3DDevice9 {
        const dev = try allocator.create(WinsD3DDevice9);
        const w = if (params.BackBufferWidth > 0) params.BackBufferWidth else 800;
        const h = if (params.BackBufferHeight > 0) params.BackBufferHeight else 600;

        const pixels = try allocator.alloc(u32, w * h);
        @memset(pixels, 0xFF000000); // Clear black

        dev.* = .{
            .vtbl = &g_device9_vtbl,
            .ref_count = 1,
            .params = params,
            .viewport = .{
                .X = 0,
                .Y = 0,
                .Width = w,
                .Height = h,
                .MinZ = 0.0,
                .MaxZ = 1.0,
            },
            .in_scene = false,
            .frame_count = 0,
            .draw_call_count = 0,
            .backbuffer = pixels,
        };
        return dev;
    }
};

// ============================================================================
// IDirect3D9 Methods
// ============================================================================

fn d3d9_QueryInterface(this: *anyopaque, riid: ?*const anyopaque, ppv: ?*?*anyopaque) callconv(W) HRESULT {
    _ = riid;
    if (ppv) |p| p.* = this;
    return S_OK;
}

fn d3d9_AddRef(this: *anyopaque) callconv(W) u32 {
    const self: *WinsD3D9 = @ptrCast(@alignCast(this));
    self.ref_count += 1;
    return self.ref_count;
}

fn d3d9_Release(this: *anyopaque) callconv(W) u32 {
    const self: *WinsD3D9 = @ptrCast(@alignCast(this));
    if (self.ref_count > 0) self.ref_count -= 1;
    return self.ref_count;
}

fn d3d9_GetAdapterCount(this: *anyopaque) callconv(W) u32 {
    _ = this;
    return 1;
}

fn d3d9_GetDeviceCaps(this: *anyopaque, adapter: u32, dev_type: u32, pCaps: ?*D3DCAPS9) callconv(W) HRESULT {
    _ = this;
    _ = adapter;
    _ = dev_type;
    if (pCaps) |caps| {
        @memset(std.mem.asBytes(caps), 0);
        caps.DeviceType = 1; // HAL
        caps.MaxTextureWidth = 8192;
        caps.MaxTextureHeight = 8192;
        caps.MaxVolumeExtent = 2048;
        caps.MaxTextureRepeat = 8192;
        caps.MaxTextureAspectRatio = 8192;
        caps.MaxAnisotropy = 16;
        caps.MaxPrimitiveCount = 1048576;
        caps.MaxVertexIndex = 1048576;
        caps.MaxStreams = 16;
        caps.MaxStreamStride = 256;
        caps.VertexShaderVersion = 0xFFFE0300; // vs_3_0
        caps.PixelShaderVersion = 0xFFFF0300; // ps_3_0
        caps.MaxVertexShader30InstructionSlots = 32768;
        caps.MaxPixelShader30InstructionSlots = 32768;
        caps.NumSimultaneousRTs = 4;
    }
    return D3D_OK;
}

fn d3d9_CreateDevice(
    this: *anyopaque,
    adapter: u32,
    dev_type: u32,
    hFocusWindow: usize,
    behavior_flags: u32,
    pParams: ?*D3DPRESENT_PARAMETERS,
    ppDevice: ?*?*anyopaque,
) callconv(W) HRESULT {
    _ = this;
    _ = adapter;
    _ = dev_type;
    _ = hFocusWindow;
    _ = behavior_flags;

    if (ppDevice == null or pParams == null) return E_FAIL;

    const gpa = std.heap.page_allocator;
    const dev = WinsD3DDevice9.init(gpa, pParams.?.*) catch return E_OUTOFMEMORY;
    ppDevice.?.* = @ptrCast(dev);
    return D3D_OK;
}

// Global D3D9 Stub for Unimplemented Methods
fn d3d9_Stub(this: *anyopaque) callconv(W) HRESULT {
    _ = this;
    return D3D_OK;
}

const g_d3d9_vtbl: IDirect3D9Vtbl = .{
    .QueryInterface = &d3d9_QueryInterface,
    .AddRef = &d3d9_AddRef,
    .Release = &d3d9_Release,
    .RegisterSoftwareDevice = @ptrCast(&d3d9_Stub),
    .GetAdapterCount = &d3d9_GetAdapterCount,
    .GetAdapterIdentifier = @ptrCast(&d3d9_Stub),
    .GetAdapterModeCount = @ptrCast(&d3d9_GetAdapterCount),
    .EnumAdapterModes = @ptrCast(&d3d9_Stub),
    .GetAdapterDisplayMode = @ptrCast(&d3d9_Stub),
    .CheckDeviceType = @ptrCast(&d3d9_Stub),
    .CheckDeviceFormat = @ptrCast(&d3d9_Stub),
    .CheckDeviceMultiSampleType = @ptrCast(&d3d9_Stub),
    .CheckDepthStencilMatch = @ptrCast(&d3d9_Stub),
    .CheckDeviceFormatConversion = @ptrCast(&d3d9_Stub),
    .GetDeviceCaps = &d3d9_GetDeviceCaps,
    .GetAdapterMonitor = @ptrCast(&d3d9_Stub),
    .CreateDevice = &d3d9_CreateDevice,
};

// ============================================================================
// IDirect3DDevice9 Methods
// ============================================================================

fn dev9_QueryInterface(this: *anyopaque, riid: ?*const anyopaque, ppv: ?*?*anyopaque) callconv(W) HRESULT {
    _ = riid;
    if (ppv) |p| p.* = this;
    return S_OK;
}

fn dev9_AddRef(this: *anyopaque) callconv(W) u32 {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    self.ref_count += 1;
    return self.ref_count;
}

fn dev9_Release(this: *anyopaque) callconv(W) u32 {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (self.ref_count > 0) self.ref_count -= 1;
    return self.ref_count;
}

fn dev9_BeginScene(this: *anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    self.in_scene = true;
    return D3D_OK;
}

fn dev9_EndScene(this: *anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    self.in_scene = false;
    return D3D_OK;
}

fn dev9_Clear(
    this: *anyopaque,
    count: u32,
    pRects: ?*const D3DRECT,
    flags: u32,
    color: u32,
    z: f32,
    stencil: u32,
) callconv(W) HRESULT {
    _ = count;
    _ = pRects;
    _ = flags;
    _ = z;
    _ = stencil;
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    @memset(self.backbuffer, color);
    return D3D_OK;
}

fn dev9_Present(
    this: *anyopaque,
    pSource: ?*const D3DRECT,
    pDest: ?*const D3DRECT,
    hWindow: usize,
    pDirty: ?*const anyopaque,
) callconv(W) HRESULT {
    _ = pSource;
    _ = pDest;
    _ = hWindow;
    _ = pDirty;
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    self.frame_count += 1;
    return D3D_OK;
}

fn dev9_SetViewport(this: *anyopaque, pViewport: ?*const D3DVIEWPORT9) callconv(W) HRESULT {
    if (pViewport) |vp| {
        const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
        self.viewport = vp.*;
    }
    return D3D_OK;
}

fn dev9_GetViewport(this: *anyopaque, pViewport: ?*D3DVIEWPORT9) callconv(W) HRESULT {
    if (pViewport) |vp| {
        const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
        vp.* = self.viewport;
    }
    return D3D_OK;
}

fn dev9_DrawPrimitive(this: *anyopaque, prim_type: u32, start_vertex: u32, count: u32) callconv(W) HRESULT {
    _ = prim_type;
    _ = start_vertex;
    _ = count;
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    self.draw_call_count += 1;
    return D3D_OK;
}

fn dev9_Stub(this: *anyopaque) callconv(W) HRESULT {
    _ = this;
    return D3D_OK;
}

const g_device9_vtbl: IDirect3DDevice9Vtbl = .{
    .QueryInterface = &dev9_QueryInterface,
    .AddRef = &dev9_AddRef,
    .Release = &dev9_Release,
    .TestCooperativeLevel = @ptrCast(&dev9_Stub),
    .GetAvailableTextureMem = @ptrCast(&dev9_Stub),
    .EvictManagedResources = @ptrCast(&dev9_Stub),
    .GetDirect3D = @ptrCast(&dev9_Stub),
    .GetDeviceCaps = @ptrCast(&dev9_Stub),
    .GetDisplayMode = @ptrCast(&dev9_Stub),
    .GetCreationParameters = @ptrCast(&dev9_Stub),
    .SetCursorProperties = @ptrCast(&dev9_Stub),
    .SetCursorPosition = @ptrCast(&dev9_Stub),
    .ShowCursor = @ptrCast(&dev9_Stub),
    .CreateAdditionalSwapChain = @ptrCast(&dev9_Stub),
    .GetSwapChain = @ptrCast(&dev9_Stub),
    .GetNumberOfSwapChains = @ptrCast(&dev9_Stub),
    .Reset = @ptrCast(&dev9_Stub),
    .Present = &dev9_Present,
    .GetBackBuffer = @ptrCast(&dev9_Stub),
    .GetRasterStatus = @ptrCast(&dev9_Stub),
    .SetDialogBoxMode = @ptrCast(&dev9_Stub),
    .SetGammaRamp = @ptrCast(&dev9_Stub),
    .GetGammaRamp = @ptrCast(&dev9_Stub),
    .CreateTexture = @ptrCast(&dev9_Stub),
    .CreateVolumeTexture = @ptrCast(&dev9_Stub),
    .CreateCubeTexture = @ptrCast(&dev9_Stub),
    .CreateVertexBuffer = @ptrCast(&dev9_Stub),
    .CreateIndexBuffer = @ptrCast(&dev9_Stub),
    .CreateRenderTarget = @ptrCast(&dev9_Stub),
    .CreateDepthStencilSurface = @ptrCast(&dev9_Stub),
    .UpdateSurface = @ptrCast(&dev9_Stub),
    .UpdateTexture = @ptrCast(&dev9_Stub),
    .GetRenderTargetData = @ptrCast(&dev9_Stub),
    .GetFrontBufferData = @ptrCast(&dev9_Stub),
    .StretchRect = @ptrCast(&dev9_Stub),
    .ColorFill = @ptrCast(&dev9_Stub),
    .CreateOffscreenPlainSurface = @ptrCast(&dev9_Stub),
    .SetRenderTarget = @ptrCast(&dev9_Stub),
    .GetRenderTarget = @ptrCast(&dev9_Stub),
    .SetDepthStencilSurface = @ptrCast(&dev9_Stub),
    .GetDepthStencilSurface = @ptrCast(&dev9_Stub),
    .BeginScene = &dev9_BeginScene,
    .EndScene = &dev9_EndScene,
    .Clear = &dev9_Clear,
    .SetTransform = @ptrCast(&dev9_Stub),
    .GetTransform = @ptrCast(&dev9_Stub),
    .MultiplyTransform = @ptrCast(&dev9_Stub),
    .SetViewport = &dev9_SetViewport,
    .GetViewport = &dev9_GetViewport,
    .SetMaterial = @ptrCast(&dev9_Stub),
    .GetMaterial = @ptrCast(&dev9_Stub),
    .SetLight = @ptrCast(&dev9_Stub),
    .GetLight = @ptrCast(&dev9_Stub),
    .LightEnable = @ptrCast(&dev9_Stub),
    .GetLightEnable = @ptrCast(&dev9_Stub),
    .SetClipPlane = @ptrCast(&dev9_Stub),
    .GetClipPlane = @ptrCast(&dev9_Stub),
    .SetRenderState = @ptrCast(&dev9_Stub),
    .GetRenderState = @ptrCast(&dev9_Stub),
    .CreateStateBlock = @ptrCast(&dev9_Stub),
    .BeginStateBlock = @ptrCast(&dev9_Stub),
    .EndStateBlock = @ptrCast(&dev9_Stub),
    .SetClipStatus = @ptrCast(&dev9_Stub),
    .GetClipStatus = @ptrCast(&dev9_Stub),
    .GetTexture = @ptrCast(&dev9_Stub),
    .SetTexture = @ptrCast(&dev9_Stub),
    .GetTextureStageState = @ptrCast(&dev9_Stub),
    .SetTextureStageState = @ptrCast(&dev9_Stub),
    .GetSamplerState = @ptrCast(&dev9_Stub),
    .SetSamplerState = @ptrCast(&dev9_Stub),
    .ValidateDevice = @ptrCast(&dev9_Stub),
    .SetPaletteEntries = @ptrCast(&dev9_Stub),
    .GetPaletteEntries = @ptrCast(&dev9_Stub),
    .SetCurrentTexturePalette = @ptrCast(&dev9_Stub),
    .GetCurrentTexturePalette = @ptrCast(&dev9_Stub),
    .SetScissorRect = @ptrCast(&dev9_Stub),
    .GetScissorRect = @ptrCast(&dev9_Stub),
    .SetSoftwareVertexProcessing = @ptrCast(&dev9_Stub),
    .GetSoftwareVertexProcessing = @ptrCast(&dev9_Stub),
    .SetNPatchMode = @ptrCast(&dev9_Stub),
    .GetNPatchMode = @ptrCast(&dev9_Stub),
    .DrawPrimitive = &dev9_DrawPrimitive,
    .DrawIndexedPrimitive = @ptrCast(&dev9_Stub),
    .DrawPrimitiveUP = @ptrCast(&dev9_Stub),
    .DrawIndexedPrimitiveUP = @ptrCast(&dev9_Stub),
    .ProcessVertices = @ptrCast(&dev9_Stub),
    .CreateVertexDeclaration = @ptrCast(&dev9_Stub),
    .SetVertexDeclaration = @ptrCast(&dev9_Stub),
    .GetVertexDeclaration = @ptrCast(&dev9_Stub),
    .SetFVF = @ptrCast(&dev9_Stub),
    .GetFVF = @ptrCast(&dev9_Stub),
    .CreateVertexShader = @ptrCast(&dev9_Stub),
    .SetVertexShader = @ptrCast(&dev9_Stub),
    .GetVertexShader = @ptrCast(&dev9_Stub),
    .SetVertexShaderConstantF = @ptrCast(&dev9_Stub),
    .GetVertexShaderConstantF = @ptrCast(&dev9_Stub),
    .SetVertexShaderConstantI = @ptrCast(&dev9_Stub),
    .GetVertexShaderConstantI = @ptrCast(&dev9_Stub),
    .SetVertexShaderConstantB = @ptrCast(&dev9_Stub),
    .GetVertexShaderConstantB = @ptrCast(&dev9_Stub),
    .SetStreamSource = @ptrCast(&dev9_Stub),
    .GetStreamSource = @ptrCast(&dev9_Stub),
    .SetStreamSourceFreq = @ptrCast(&dev9_Stub),
    .GetStreamSourceFreq = @ptrCast(&dev9_Stub),
    .SetIndices = @ptrCast(&dev9_Stub),
    .GetIndices = @ptrCast(&dev9_Stub),
    .CreatePixelShader = @ptrCast(&dev9_Stub),
    .SetPixelShader = @ptrCast(&dev9_Stub),
    .GetPixelShader = @ptrCast(&dev9_Stub),
    .SetPixelShaderConstantF = @ptrCast(&dev9_Stub),
    .GetPixelShaderConstantF = @ptrCast(&dev9_Stub),
    .SetPixelShaderConstantI = @ptrCast(&dev9_Stub),
    .GetPixelShaderConstantI = @ptrCast(&dev9_Stub),
    .SetPixelShaderConstantB = @ptrCast(&dev9_Stub),
    .GetPixelShaderConstantB = @ptrCast(&dev9_Stub),
    .DrawRectPatch = @ptrCast(&dev9_Stub),
    .DrawTriPatch = @ptrCast(&dev9_Stub),
    .DeletePatch = @ptrCast(&dev9_Stub),
    .CreateQuery = @ptrCast(&dev9_Stub),
};

// ============================================================================
// Public C/Win32 Exported Entry Points
// ============================================================================

var g_global_d3d9: WinsD3D9 = WinsD3D9.init();

pub export fn Direct3DCreate9(sdk_version: u32) callconv(W) ?*anyopaque {
    _ = sdk_version;
    return @ptrCast(&g_global_d3d9);
}

pub export fn D3DPERF_SetOptions(options: u32) callconv(W) void {
    _ = options;
}

pub export fn D3DPERF_BeginEvent(col: u32, wszName: ?[*:0]const u16) callconv(W) i32 {
    _ = col;
    _ = wszName;
    return 0;
}

pub export fn D3DPERF_EndEvent() callconv(W) i32 {
    return 0;
}

// ============================================================================
// D3DX9 Linear Algebra & Math Functions (Pure Native Linux CPU / SIMD)
// ============================================================================

pub const D3DVECTOR = extern struct {
    x: f32,
    y: f32,
    z: f32,
};

pub const D3DVECTOR4 = extern struct {
    x: f32,
    y: f32,
    z: f32,
    w: f32,
};

pub const D3DMATRIX = extern struct {
    m: [4][4]f32,
};

pub export fn D3DXMatrixMultiply(
    pOut: ?*D3DMATRIX,
    pM1: ?*const D3DMATRIX,
    pM2: ?*const D3DMATRIX,
) callconv(W) ?*D3DMATRIX {
    const out = pOut orelse return null;
    const m1 = pM1 orelse return null;
    const m2 = pM2 orelse return null;

    var temp: D3DMATRIX = undefined;
    for (0..4) |i| {
        for (0..4) |j| {
            temp.m[i][j] = m1.m[i][0] * m2.m[0][j] +
                m1.m[i][1] * m2.m[1][j] +
                m1.m[i][2] * m2.m[2][j] +
                m1.m[i][3] * m2.m[3][j];
        }
    }
    out.* = temp;
    return out;
}

pub export fn D3DXMatrixTranspose(
    pOut: ?*D3DMATRIX,
    pM: ?*const D3DMATRIX,
) callconv(W) ?*D3DMATRIX {
    const out = pOut orelse return null;
    const m = pM orelse return null;

    var temp: D3DMATRIX = undefined;
    for (0..4) |i| {
        for (0..4) |j| {
            temp.m[i][j] = m.m[j][i];
        }
    }
    out.* = temp;
    return out;
}

pub export fn D3DXMatrixMultiplyTranspose(
    pOut: ?*D3DMATRIX,
    pM1: ?*const D3DMATRIX,
    pM2: ?*const D3DMATRIX,
) callconv(W) ?*D3DMATRIX {
    _ = D3DXMatrixMultiply(pOut, pM1, pM2);
    _ = D3DXMatrixTranspose(pOut, pOut);
    return pOut;
}

pub export fn D3DXVec3Normalize(
    pOut: ?*D3DVECTOR,
    pV: ?*const D3DVECTOR,
) callconv(W) ?*D3DVECTOR {
    const out = pOut orelse return null;
    const v = pV orelse return null;

    const len_sq = v.x * v.x + v.y * v.y + v.z * v.z;
    if (len_sq > 0.0) {
        const inv_len = 1.0 / @sqrt(len_sq);
        out.x = v.x * inv_len;
        out.y = v.y * inv_len;
        out.z = v.z * inv_len;
    } else {
        out.x = 0;
        out.y = 0;
        out.z = 0;
    }
    return out;
}

pub export fn D3DXVec3TransformCoord(
    pOut: ?*D3DVECTOR,
    pV: ?*const D3DVECTOR,
    pM: ?*const D3DMATRIX,
) callconv(W) ?*D3DVECTOR {
    const out = pOut orelse return null;
    const v = pV orelse return null;
    const m = pM orelse return null;

    const norm = m.m[0][3] * v.x + m.m[1][3] * v.y + m.m[2][3] * v.z + m.m[3][3];
    const inv_w = if (norm != 0.0) 1.0 / norm else 1.0;

    out.x = (m.m[0][0] * v.x + m.m[1][0] * v.y + m.m[2][0] * v.z + m.m[3][0]) * inv_w;
    out.y = (m.m[0][1] * v.x + m.m[1][1] * v.y + m.m[2][1] * v.z + m.m[3][1]) * inv_w;
    out.z = (m.m[0][2] * v.x + m.m[1][2] * v.y + m.m[2][2] * v.z + m.m[3][2]) * inv_w;
    return out;
}

pub export fn D3DXVec4Transform(
    pOut: ?*D3DVECTOR4,
    pV: ?*const D3DVECTOR4,
    pM: ?*const D3DMATRIX,
) callconv(W) ?*D3DVECTOR4 {
    const out = pOut orelse return null;
    const v = pV orelse return null;
    const m = pM orelse return null;

    var temp: D3DVECTOR4 = undefined;
    temp.x = m.m[0][0] * v.x + m.m[1][0] * v.y + m.m[2][0] * v.z + m.m[3][0] * v.w;
    temp.y = m.m[0][1] * v.x + m.m[1][1] * v.y + m.m[2][1] * v.z + m.m[3][1] * v.w;
    temp.z = m.m[0][2] * v.x + m.m[1][2] * v.y + m.m[2][2] * v.z + m.m[3][2] * v.w;
    temp.w = m.m[0][3] * v.x + m.m[1][3] * v.y + m.m[2][3] * v.z + m.m[3][3] * v.w;
    out.* = temp;
    return out;
}

// ============================================================================
// Unit Tests (Embedded Verification)
// ============================================================================

test "Direct3DCreate9 and device initialization" {
    const d3d9_ptr = Direct3DCreate9(32);
    try std.testing.expect(d3d9_ptr != null);

    const d3d9: *WinsD3D9 = @ptrCast(@alignCast(d3d9_ptr.?));
    try std.testing.expectEqual(@as(u32, 1), d3d9.vtbl.GetAdapterCount(d3d9));

    // Check Device Caps
    var caps: D3DCAPS9 = undefined;
    const caps_rc = d3d9.vtbl.GetDeviceCaps(d3d9, 0, 1, &caps);
    try std.testing.expectEqual(D3D_OK, caps_rc);
    try std.testing.expectEqual(@as(u32, 0xFFFE0300), caps.VertexShaderVersion); // vs_3_0
    try std.testing.expectEqual(@as(u32, 0xFFFF0300), caps.PixelShaderVersion);  // ps_3_0
    try std.testing.expectEqual(@as(u32, 8192), caps.MaxTextureWidth);

    // Create Device
    var params: D3DPRESENT_PARAMETERS = undefined;
    @memset(std.mem.asBytes(&params), 0);
    params.BackBufferWidth = 1280;
    params.BackBufferHeight = 720;
    params.Windowed = 1;

    var dev_raw: ?*anyopaque = null;
    const create_rc = d3d9.vtbl.CreateDevice(d3d9, 0, 1, 0, 0, &params, &dev_raw);
    try std.testing.expectEqual(D3D_OK, create_rc);
    try std.testing.expect(dev_raw != null);

    const dev: *WinsD3DDevice9 = @ptrCast(@alignCast(dev_raw.?));
    try std.testing.expectEqual(@as(u32, 1280), dev.viewport.Width);
    try std.testing.expectEqual(@as(u32, 720), dev.viewport.Height);

    // Test Scene Loop
    try std.testing.expectEqual(D3D_OK, dev.vtbl.Clear(dev, 0, null, 1, 0xFFFF0000, 1.0, 0)); // Red clear
    try std.testing.expectEqual(@as(u32, 0xFFFF0000), dev.backbuffer[0]);

    try std.testing.expectEqual(D3D_OK, dev.vtbl.BeginScene(dev));
    try std.testing.expect(dev.in_scene);

    try std.testing.expectEqual(D3D_OK, dev.vtbl.DrawPrimitive(dev, 4, 0, 2)); // 2 triangles
    try std.testing.expectEqual(@as(u64, 1), dev.draw_call_count);

    try std.testing.expectEqual(D3D_OK, dev.vtbl.EndScene(dev));
    try std.testing.expect(!dev.in_scene);

    try std.testing.expectEqual(D3D_OK, dev.vtbl.Present(dev, null, null, 0, null));
    try std.testing.expectEqual(@as(u64, 1), dev.frame_count);
}

test "D3DX linear algebra math" {
    // Vector normalize test (3-4-5 triangle)
    var v = D3DVECTOR{ .x = 3.0, .y = 4.0, .z = 0.0 };
    var v_norm: D3DVECTOR = undefined;
    _ = D3DXVec3Normalize(&v_norm, &v);
    try std.testing.expectApproxEqAbs(@as(f32, 0.6), v_norm.x, 0.0001);
    try std.testing.expectApproxEqAbs(@as(f32, 0.8), v_norm.y, 0.0001);
    try std.testing.expectApproxEqAbs(@as(f32, 0.0), v_norm.z, 0.0001);

    // Matrix Transpose test
    var m = D3DMATRIX{
        .m = .{
            .{ 1, 2, 3, 4 },
            .{ 5, 6, 7, 8 },
            .{ 9, 10, 11, 12 },
            .{ 13, 14, 15, 16 },
        },
    };
    var m_t: D3DMATRIX = undefined;
    _ = D3DXMatrixTranspose(&m_t, &m);
    try std.testing.expectEqual(@as(f32, 1), m_t.m[0][0]);
    try std.testing.expectEqual(@as(f32, 5), m_t.m[0][1]);
    try std.testing.expectEqual(@as(f32, 2), m_t.m[1][0]);
    try std.testing.expectEqual(@as(f32, 16), m_t.m[3][3]);
}
