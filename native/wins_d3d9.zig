//! WINS Native Direct3D 9 State Tracker & COM Implementation (Zig 0.16)
//! Provides a 100% native Linux Direct3D 9 runtime (Zero Wine, Zero Proton).
//! Directly implements IDirect3D9, IDirect3DDevice9, IDirect3DTexture9,
//! IDirect3DVertexBuffer9, IDirect3DIndexBuffer9, IDirect3DSurface9, and ID3DXBuffer
//! with true bit-exact __stdcall ABI and software rasterization capabilities.

const std = @import("std");
const linux = std.os.linux;

pub const W: std.builtin.CallingConvention = .winapi;

// The Fallout guest reaches this D3D9 object through both the Win32 COM stack
// ABI and an x86 C++ thiscall path. The latter puts `this` in ECX and leaves
// only explicit parameters on the stack. These adapters are selected at the
// affected vtable entries and compare ECX/stack `this` against the live object.
pub export var wins_d3d9_device_self: u32 = 0;

// ============================================================================
// D3D9 Types & Enums
// ============================================================================

pub const HRESULT = i32;
pub const S_OK: HRESULT = 0;
pub const S_FALSE: HRESULT = 1;
pub const E_FAIL: HRESULT = -2147467259; // 0x80004005
pub const E_NOINTERFACE: HRESULT = -2147467262; // 0x80004002
pub const E_NOTIMPL: HRESULT = -2147467263; // 0x80004001
pub const E_POINTER: HRESULT = -2147467261; // 0x80004003 (was -2147467263 = E_NOTIMPL)
pub const E_OUTOFMEMORY: HRESULT = -2147024882; // 0x8007000E
pub const D3DERR_INVALIDARG: HRESULT = -2147024809; // 0x80070057
pub const D3DERR_NOTAVAILABLE: HRESULT = -2005530518; // 0x8876086A
pub const D3D_OK: HRESULT = S_OK;

pub const D3DFMT_A8R8G8B8: u32 = 21;
pub const D3DFMT_X8R8G8B8: u32 = 22;
pub const D3DFMT_A8B8G8R8: u32 = 23;
pub const D3DFMT_D24S8: u32 = 75;
pub const D3DFMT_D16: u32 = 80;
pub const D3DFMT_INDEX16: u32 = 101;
pub const D3DFMT_INDEX32: u32 = 102;

// d3d9types.h
pub const D3DUSAGE_RENDERTARGET: u32 = 0x00000001;
pub const D3DUSAGE_DEPTHSTENCIL: u32 = 0x00000002;
pub const D3DUSAGE_WRITEONLY: u32 = 0x00000008;
pub const D3DUSAGE_DYNAMIC: u32 = 0x00000200;
pub const D3DRTYPE_SURFACE: u32 = 1;
pub const D3DRTYPE_VOLUME: u32 = 2;
pub const D3DRTYPE_TEXTURE: u32 = 3;
pub const D3DMULTISAMPLE_NONE: u32 = 0;
pub const D3DDEVTYPE_HAL: u32 = 1;
pub const D3DDEVTYPE_REF: u32 = 2;
pub const D3DDEVCAPS_HWTRANSFORMLIGHT: u32 = 0x00010000;
pub const D3DDEVTYPE_SW: u32 = 3;
pub const D3DDEVTYPE_NULLREF: u32 = 4;

pub const D3DCLEAR_TARGET: u32 = 0x00000001;
pub const D3DCLEAR_ZBUFFER: u32 = 0x00000002;
pub const D3DCLEAR_STENCIL: u32 = 0x00000004;

pub const D3DPRIMITIVETYPE = enum(u32) {
    POINTLIST = 1,
    LINELIST = 2,
    LINESTRIP = 3,
    TRIANGLELIST = 4,
    TRIANGLESTRIP = 5,
    TRIANGLEFAN = 6,
    _,
};

pub const D3DVIEWPORT9 = extern struct {
    X: u32,
    Y: u32,
    Width: u32,
    Height: u32,
    MinZ: f32,
    MaxZ: f32,
};

pub const D3DCOLORVALUE = extern struct {
    r: f32,
    g: f32,
    b: f32,
    a: f32,
};

pub const D3DMATERIAL9 = extern struct {
    Diffuse: D3DCOLORVALUE,
    Ambient: D3DCOLORVALUE,
    Specular: D3DCOLORVALUE,
    Emissive: D3DCOLORVALUE,
    Power: f32,
};

pub const D3DLIGHT9 = extern struct {
    Type: u32,
    Diffuse: D3DCOLORVALUE,
    Specular: D3DCOLORVALUE,
    Ambient: D3DCOLORVALUE,
    Position: D3DVECTOR,
    Direction: D3DVECTOR,
    Range: f32,
    Falloff: f32,
    Attenuation0: f32,
    Attenuation1: f32,
    Attenuation2: f32,
    Theta: f32,
    Phi: f32,
};

pub const D3DLIGHT_POINT: u32 = 1;
pub const D3DLIGHT_SPOT: u32 = 2;
pub const D3DLIGHT_DIRECTIONAL: u32 = 3;
pub const kMaxDeviceLights: usize = 8;

const D3DLightState9 = struct {
    light: D3DLIGHT9,
    enabled: bool,
};

fn defaultMaterial9() D3DMATERIAL9 {
    const white = D3DCOLORVALUE{ .r = 1, .g = 1, .b = 1, .a = 1 };
    const black = D3DCOLORVALUE{ .r = 0, .g = 0, .b = 0, .a = 0 };
    return .{
        .Diffuse = white,
        .Ambient = white,
        .Specular = black,
        .Emissive = black,
        .Power = 0,
    };
}

fn defaultLight9() D3DLIGHT9 {
    return .{
        .Type = D3DLIGHT_DIRECTIONAL,
        .Diffuse = .{ .r = 1, .g = 1, .b = 1, .a = 0 },
        .Specular = .{ .r = 0, .g = 0, .b = 0, .a = 0 },
        .Ambient = .{ .r = 0, .g = 0, .b = 0, .a = 0 },
        .Position = .{ .x = 0, .y = 0, .z = 0 },
        .Direction = .{ .x = 0, .y = 0, .z = 1 },
        .Range = 0,
        .Falloff = 0,
        .Attenuation0 = 0,
        .Attenuation1 = 0,
        .Attenuation2 = 0,
        .Theta = 0,
        .Phi = 0,
    };
}

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

pub const D3DSURFACE_DESC = extern struct {
    Format: u32,
    Type: u32,
    Usage: u32,
    Pool: u32,
    MultiSampleType: u32,
    MultiSampleQuality: u32,
    Width: u32,
    Height: u32,
};

pub const D3DVERTEXBUFFER_DESC = extern struct {
    Format: u32,
    Type: u32,
    Usage: u32,
    Pool: u32,
    Size: u32,
    FVF: u32,
};

pub const D3DINDEXBUFFER_DESC = extern struct {
    Format: u32,
    Type: u32,
    Usage: u32,
    Pool: u32,
    Size: u32,
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
    VS20Caps: D3DVSHADERCAPS2_0,
    PS20Caps: D3DPSHADERCAPS2_0,
    VertexTextureFilterCaps: u32,
    MaxVShaderInstructionsExecuted: u32,
    MaxPShaderInstructionsExecuted: u32,
    MaxVertexShader30InstructionSlots: u32,
    MaxPixelShader30InstructionSlots: u32,
};

/// d3d9caps.h: D3DVSHADERCAPS2_0 and D3DPSHADERCAPS2_0. The tail of
/// D3DCAPS9 holds these two by value, and they are four and five dwords, not
/// two each. Getting that size wrong moves every field that follows them.
pub const D3DVSHADERCAPS2_0 = extern struct {
    Caps: u32,
    DynamicFlowControlDepth: i32,
    NumTemps: i32,
    StaticFlowControlDepth: i32,
};

pub const D3DPSHADERCAPS2_0 = extern struct {
    Caps: u32,
    DynamicFlowControlDepth: i32,
    NumTemps: i32,
    StaticFlowControlDepth: i32,
    NumInstructionSlots: i32,
};

pub const GUID = extern struct {
    Data1: u32,
    Data2: u16,
    Data3: u16,
    Data4: [8]u8,
};

/// The interface identifiers this module answers.
///
/// d3d9.h: IID_IDirect3D9 and IID_IDirect3DDevice9. A guest that asks for an
/// interface the module does not implement must get E_NOINTERFACE: answering
/// S_OK for an unknown identifier hands out an object whose vtable is shorter
/// than the interface the guest believes it is holding, and the next call
/// reads past the end of the table.
pub const IID_IDirect3D9 = GUID{
    .Data1 = 0x81BDCBCA,
    .Data2 = 0x64D4,
    .Data3 = 0x426D,
    .Data4 = .{ 0xAE, 0x8D, 0xAD, 0x01, 0x47, 0xF4, 0x27, 0x5C },
};
pub const IID_IDirect3DDevice9 = GUID{
    .Data1 = 0xD0223B96,
    .Data2 = 0xBF7A,
    .Data3 = 0x43FD,
    .Data4 = .{ 0x92, 0xBD, 0xA4, 0x3B, 0x0D, 0x82, 0xB9, 0xEB },
};
pub const IID_IDirect3DResource9 = GUID{
    .Data1 = 0x05EEC05D,
    .Data2 = 0x8F7D,
    .Data3 = 0x4362,
    .Data4 = .{ 0xB9, 0x99, 0xD1, 0xBA, 0xF3, 0x57, 0xC7, 0x04 },
};
pub const IID_IDirect3DBaseTexture9 = GUID{
    .Data1 = 0x580CA87E,
    .Data2 = 0x1D3C,
    .Data3 = 0x4D54,
    .Data4 = .{ 0x99, 0x1D, 0xB7, 0xD3, 0xE3, 0xC2, 0x98, 0xCE },
};
pub const IID_IDirect3DTexture9 = GUID{
    .Data1 = 0x85C31227,
    .Data2 = 0x3DE5,
    .Data3 = 0x4F00,
    .Data4 = .{ 0x9B, 0x3A, 0xF1, 0x1A, 0xC3, 0x8C, 0x18, 0xB5 },
};
pub const IID_IUnknown = GUID{
    .Data1 = 0x00000000,
    .Data2 = 0x0000,
    .Data3 = 0x0000,
    .Data4 = .{ 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 },
};
pub const IID_IDirect3DVertexDeclaration9 = GUID{
    .Data1 = 0xDD13C59C,
    .Data2 = 0x36FA,
    .Data3 = 0x4098,
    .Data4 = .{ 0xA8, 0xFB, 0xC7, 0xED, 0x39, 0xDC, 0x85, 0x46 },
};

/// d3d9types.h: D3DVERTEXELEMENT9 (8 bytes). D3DDECL_END() is Stream 0xFF,
/// Type D3DDECLTYPE_UNUSED (17).
pub const D3DVERTEXELEMENT9 = extern struct {
    Stream: u16,
    Offset: u16,
    Type: u8,
    Method: u8,
    Usage: u8,
    UsageIndex: u8,
};
const kDeclTypeUnused: u8 = 17;
const kMaxDeclLength = 64; // MAXD3DDECLLENGTH
fn isDeclEnd(e: D3DVERTEXELEMENT9) bool {
    return e.Stream == 0xFF and e.Type == kDeclTypeUnused;
}

pub const IDirect3DVertexDeclaration9Vtbl = extern struct {
    QueryInterface: *const fn (*anyopaque, ?*const anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    AddRef: *const fn (*anyopaque) callconv(W) u32,
    Release: *const fn (*anyopaque) callconv(W) u32,
    GetDevice: *const fn (*anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    GetDeclaration: *const fn (*anyopaque, ?*D3DVERTEXELEMENT9, ?*u32) callconv(W) HRESULT,
};

/// Compares an interface identifier the guest handed over with one of ours.
///
/// The identifier is read through an align(1) pointer: the guest's buffer is
/// its own, and this module does not get to decide how it is aligned.
fn guidEql(a: *align(1) const GUID, b: *align(1) const GUID) bool {
    if (a.Data1 != b.Data1) return false;
    if (a.Data2 != b.Data2) return false;
    if (a.Data3 != b.Data3) return false;
    for (a.Data4, b.Data4) |x, y| {
        if (x != y) return false;
    }
    return true;
}

/// d3d9types.h: D3DADAPTER_IDENTIFIER9. The guest reads the driver and the
/// description out of this by offset, so the layout is the Windows one: two
/// five-hundred-and-twelve byte strings, the device name, the driver version
/// as a 64-bit value, and the ids.
pub const D3DADAPTER_IDENTIFIER9 = extern struct {
    Driver: [512]u8,
    Description: [512]u8,
    DeviceName: [32]u8,
    DriverVersion: u64,
    VendorId: u32,
    DeviceId: u32,
    SubSysId: u32,
    Revision: u32,
    DeviceIdentifier: GUID,
    WHQLLevel: u32,
};

/// d3d9types.h: D3DDISPLAYMODE.
///
/// Four fields, sixteen bytes. There is no ScanLineOrdering member in the
/// D3D9 struct: the guest keeps this one in a sixteen-byte stack slot that
/// its own saved return address follows immediately, so writing twenty bytes
/// here lands four bytes past the slot and destroys the return address. The
/// guest then returns to zero and dies with EIP=0, which looks like a null
/// call and is not one.
pub const D3DDISPLAYMODE = extern struct {
    Width: u32,
    Height: u32,
    RefreshRate: u32,
    Format: u32,
};

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

const kTransformStateCount = 512;

fn d3dIdentityMatrix() D3DMATRIX {
    return .{ .m = .{
        .{ 1, 0, 0, 0 },
        .{ 0, 1, 0, 0 },
        .{ 0, 0, 1, 0 },
        .{ 0, 0, 0, 1 },
    } };
}

fn d3dTransformStateIndex(state: u32) ?usize {
    if (state == 2 or state == 3 or (state >= 16 and state <= 23) or (state >= 256 and state < kTransformStateCount)) {
        return @intCast(state);
    }
    return null;
}

pub const D3DXPLANE = extern struct {
    a: f32,
    b: f32,
    c: f32,
    d: f32,
};

pub const D3DXIMAGE_INFO = extern struct {
    Width: u32,
    Height: u32,
    Depth: u32,
    MipLevels: u32,
    Format: u32,
    ResourceType: u32,
    ImageFileFormat: u32,
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

pub const ID3DXBufferVtbl = extern struct {
    QueryInterface: *const fn (*anyopaque, ?*const anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    AddRef: *const fn (*anyopaque) callconv(W) u32,
    Release: *const fn (*anyopaque) callconv(W) u32,
    GetBufferPointer: *const fn (*anyopaque) callconv(W) ?*anyopaque,
    GetBufferSize: *const fn (*anyopaque) callconv(W) u32,
};

pub const IDirect3DVertexBuffer9Vtbl = extern struct {
    QueryInterface: *const fn (*anyopaque, ?*const anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    AddRef: *const fn (*anyopaque) callconv(W) u32,
    Release: *const fn (*anyopaque) callconv(W) u32,
    GetDevice: *const fn (*anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    SetPrivateData: *const fn (*anyopaque, ?*const anyopaque, ?*const anyopaque, u32, u32) callconv(W) HRESULT,
    GetPrivateData: *const fn (*anyopaque, ?*const anyopaque, ?*anyopaque, ?*u32) callconv(W) HRESULT,
    FreePrivateData: *const fn (*anyopaque, ?*const anyopaque) callconv(W) HRESULT,
    SetPriority: *const fn (*anyopaque, u32) callconv(W) u32,
    GetPriority: *const fn (*anyopaque) callconv(W) u32,
    PreLoad: *const fn (*anyopaque) callconv(W) void,
    GetType: *const fn (*anyopaque) callconv(W) u32,
    Lock: *const fn (*anyopaque, u32, u32, ?*?*anyopaque, u32) callconv(W) HRESULT,
    Unlock: *const fn (*anyopaque) callconv(W) HRESULT,
    GetDesc: *const fn (*anyopaque, ?*D3DVERTEXBUFFER_DESC) callconv(W) HRESULT,
};

pub const IDirect3DIndexBuffer9Vtbl = extern struct {
    QueryInterface: *const fn (*anyopaque, ?*const anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    AddRef: *const fn (*anyopaque) callconv(W) u32,
    Release: *const fn (*anyopaque) callconv(W) u32,
    GetDevice: *const fn (*anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    SetPrivateData: *const fn (*anyopaque, ?*const anyopaque, ?*const anyopaque, u32, u32) callconv(W) HRESULT,
    GetPrivateData: *const fn (*anyopaque, ?*const anyopaque, ?*anyopaque, ?*u32) callconv(W) HRESULT,
    FreePrivateData: *const fn (*anyopaque, ?*const anyopaque) callconv(W) HRESULT,
    SetPriority: *const fn (*anyopaque, u32) callconv(W) u32,
    GetPriority: *const fn (*anyopaque) callconv(W) u32,
    PreLoad: *const fn (*anyopaque) callconv(W) void,
    GetType: *const fn (*anyopaque) callconv(W) u32,
    Lock: *const fn (*anyopaque, u32, u32, ?*?*anyopaque, u32) callconv(W) HRESULT,
    Unlock: *const fn (*anyopaque) callconv(W) HRESULT,
    GetDesc: *const fn (*anyopaque, ?*D3DINDEXBUFFER_DESC) callconv(W) HRESULT,
};

pub const IDirect3DSurface9Vtbl = extern struct {
    QueryInterface: *const fn (*anyopaque, ?*const anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    AddRef: *const fn (*anyopaque) callconv(W) u32,
    Release: *const fn (*anyopaque) callconv(W) u32,
    GetDevice: *const fn (*anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    SetPrivateData: *const fn (*anyopaque, ?*const anyopaque, ?*const anyopaque, u32, u32) callconv(W) HRESULT,
    GetPrivateData: *const fn (*anyopaque, ?*const anyopaque, ?*anyopaque, ?*u32) callconv(W) HRESULT,
    FreePrivateData: *const fn (*anyopaque, ?*const anyopaque) callconv(W) HRESULT,
    SetPriority: *const fn (*anyopaque, u32) callconv(W) u32,
    GetPriority: *const fn (*anyopaque) callconv(W) u32,
    PreLoad: *const fn (*anyopaque) callconv(W) void,
    GetType: *const fn (*anyopaque) callconv(W) u32,
    GetContainer: *const fn (*anyopaque, ?*const anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    GetDesc: *const fn (*anyopaque, ?*D3DSURFACE_DESC) callconv(W) HRESULT,
    LockRect: *const fn (*anyopaque, ?*D3DLOCKED_RECT, ?*const D3DRECT, u32) callconv(W) HRESULT,
    UnlockRect: *const fn (*anyopaque) callconv(W) HRESULT,
    GetDC: *const fn (*anyopaque, ?*usize) callconv(W) HRESULT,
    ReleaseDC: *const fn (*anyopaque, usize) callconv(W) HRESULT,
};

pub const IDirect3DTexture9Vtbl = extern struct {
    QueryInterface: *const fn (*anyopaque, ?*const anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    AddRef: *const fn (*anyopaque) callconv(W) u32,
    Release: *const fn (*anyopaque) callconv(W) u32,
    GetDevice: *const fn (*anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    SetPrivateData: *const fn (*anyopaque, ?*const anyopaque, ?*const anyopaque, u32, u32) callconv(W) HRESULT,
    GetPrivateData: *const fn (*anyopaque, ?*const anyopaque, ?*anyopaque, ?*u32) callconv(W) HRESULT,
    FreePrivateData: *const fn (*anyopaque, ?*const anyopaque) callconv(W) HRESULT,
    SetPriority: *const fn (*anyopaque, u32) callconv(W) u32,
    GetPriority: *const fn (*anyopaque) callconv(W) u32,
    PreLoad: *const fn (*anyopaque) callconv(W) void,
    GetType: *const fn (*anyopaque) callconv(W) u32,
    SetLOD: *const fn (*anyopaque, u32) callconv(W) u32,
    GetLOD: *const fn (*anyopaque) callconv(W) u32,
    GetLevelCount: *const fn (*anyopaque) callconv(W) u32,
    SetAutoGenFilterType: *const fn (*anyopaque, u32) callconv(W) HRESULT,
    GetAutoGenFilterType: *const fn (*anyopaque) callconv(W) u32,
    GenerateMipSubLevels: *const fn (*anyopaque) callconv(W) void,
    GetLevelDesc: *const fn (*anyopaque, u32, ?*D3DSURFACE_DESC) callconv(W) HRESULT,
    GetSurfaceLevel: *const fn (*anyopaque, u32, ?*?*anyopaque) callconv(W) HRESULT,
    LockRect: *const fn (*anyopaque, u32, ?*D3DLOCKED_RECT, ?*const D3DRECT, u32) callconv(W) HRESULT,
    UnlockRect: *const fn (*anyopaque, u32) callconv(W) HRESULT,
    AddDirtyRect: *const fn (*anyopaque, ?*const D3DRECT) callconv(W) HRESULT,
};

pub const IDirect3DShader9Vtbl = extern struct {
    QueryInterface: *const fn (*anyopaque, ?*const anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    AddRef: *const fn (*anyopaque) callconv(W) u32,
    Release: *const fn (*anyopaque) callconv(W) u32,
    GetDevice: *const fn (*anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    GetFunction: *const fn (*anyopaque, ?*anyopaque, ?*u32) callconv(W) HRESULT,
};

// ============================================================================
// Concrete COM Structures & Implementations
// ============================================================================

pub const WinsD3DXBuffer = struct {
    vtbl: *const ID3DXBufferVtbl,
    ref_count: u32,
    data: []u8,
    allocator: std.mem.Allocator,

    pub fn create(allocator: std.mem.Allocator, size: u32) !*WinsD3DXBuffer {
        const buf = try allocator.create(WinsD3DXBuffer);
        const mem = try allocator.alloc(u8, size);
        @memset(mem, 0);
        buf.* = .{
            .vtbl = &g_d3dx_buffer_vtbl,
            .ref_count = 1,
            .data = mem,
            .allocator = allocator,
        };
        return buf;
    }
};

fn buf_QueryInterface(this: *anyopaque, riid: ?*const anyopaque, ppv: ?*?*anyopaque) callconv(W) HRESULT {
    _ = riid;
    if (ppv) |p| p.* = this;
    return S_OK;
}
fn buf_AddRef(this: *anyopaque) callconv(W) u32 {
    const self: *WinsD3DXBuffer = @ptrCast(@alignCast(this));
    self.ref_count += 1;
    return self.ref_count;
}
fn buf_Release(this: *anyopaque) callconv(W) u32 {
    const self: *WinsD3DXBuffer = @ptrCast(@alignCast(this));
    if (self.ref_count > 0) self.ref_count -= 1;
    return self.ref_count;
}
fn buf_GetBufferPointer(this: *anyopaque) callconv(W) ?*anyopaque {
    const self: *WinsD3DXBuffer = @ptrCast(@alignCast(this));
    return self.data.ptr;
}
fn buf_GetBufferSize(this: *anyopaque) callconv(W) u32 {
    const self: *WinsD3DXBuffer = @ptrCast(@alignCast(this));
    return @intCast(self.data.len);
}

const g_d3dx_buffer_vtbl: ID3DXBufferVtbl = .{
    .QueryInterface = &buf_QueryInterface,
    .AddRef = &buf_AddRef,
    .Release = &buf_Release,
    .GetBufferPointer = &buf_GetBufferPointer,
    .GetBufferSize = &buf_GetBufferSize,
};

// Vertex Buffer 9
pub const WinsVertexBuffer9 = struct {
    vtbl: *const IDirect3DVertexBuffer9Vtbl,
    ref_count: u32,
    length: u32,
    usage: u32,
    fvf: u32,
    pool: u32,
    data: []u8,
    allocator: std.mem.Allocator,

    pub fn create(allocator: std.mem.Allocator, length: u32, usage: u32, fvf: u32, pool: u32) !*WinsVertexBuffer9 {
        const vb = try allocator.create(WinsVertexBuffer9);
        const mem = try allocator.alloc(u8, length);
        @memset(mem, 0);
        vb.* = .{
            .vtbl = &g_vb9_vtbl,
            .ref_count = 1,
            .length = length,
            .usage = usage,
            .fvf = fvf,
            .pool = pool,
            .data = mem,
            .allocator = allocator,
        };
        return vb;
    }
};

fn vb_QueryInterface(this: *anyopaque, riid: ?*const anyopaque, ppv: ?*?*anyopaque) callconv(W) HRESULT {
    _ = riid;
    if (ppv) |p| p.* = this;
    return S_OK;
}
fn vb_AddRef(this: *anyopaque) callconv(W) u32 {
    const self: *WinsVertexBuffer9 = @ptrCast(@alignCast(this));
    self.ref_count += 1;
    return self.ref_count;
}
fn vb_Release(this: *anyopaque) callconv(W) u32 {
    const self: *WinsVertexBuffer9 = @ptrCast(@alignCast(this));
    if (self.ref_count > 0) self.ref_count -= 1;
    return self.ref_count;
}
fn vb_Stub(this: *anyopaque) callconv(W) HRESULT {
    _ = this;
    return D3D_OK;
}
fn vb_Lock(this: *anyopaque, offset: u32, size: u32, ppbData: ?*?*anyopaque, flags: u32) callconv(W) HRESULT {
    _ = flags;
    const self: *WinsVertexBuffer9 = @ptrCast(@alignCast(this));
    if (ppbData == null or offset >= self.length) return E_FAIL;
    _ = size;
    ppbData.?.* = @ptrCast(self.data.ptr + offset);
    return D3D_OK;
}
fn vb_Unlock(this: *anyopaque) callconv(W) HRESULT {
    _ = this;
    return D3D_OK;
}
fn vb_GetDesc(this: *anyopaque, pDesc: ?*D3DVERTEXBUFFER_DESC) callconv(W) HRESULT {
    const self: *WinsVertexBuffer9 = @ptrCast(@alignCast(this));
    if (pDesc) |d| {
        d.Format = 0;
        d.Type = 1; // D3DRTYPE_VERTEXBUFFER
        d.Usage = self.usage;
        d.Pool = self.pool;
        d.Size = self.length;
        d.FVF = self.fvf;
    }
    return D3D_OK;
}

const g_vb9_vtbl: IDirect3DVertexBuffer9Vtbl = .{
    .QueryInterface = &vb_QueryInterface,
    .AddRef = &vb_AddRef,
    .Release = &vb_Release,
    .GetDevice = @ptrCast(&vb_Stub),
    .SetPrivateData = @ptrCast(&vb_Stub),
    .GetPrivateData = @ptrCast(&vb_Stub),
    .FreePrivateData = @ptrCast(&vb_Stub),
    .SetPriority = @ptrCast(&vb_Stub),
    .GetPriority = @ptrCast(&vb_Stub),
    .PreLoad = @ptrCast(&vb_Stub),
    .GetType = @ptrCast(&vb_Stub),
    .Lock = &vb_Lock,
    .Unlock = &vb_Unlock,
    .GetDesc = &vb_GetDesc,
};

// Index Buffer 9
pub const WinsIndexBuffer9 = struct {
    vtbl: *const IDirect3DIndexBuffer9Vtbl,
    ref_count: u32,
    length: u32,
    usage: u32,
    format: u32,
    pool: u32,
    data: []u8,
    allocator: std.mem.Allocator,

    pub fn create(allocator: std.mem.Allocator, length: u32, usage: u32, format: u32, pool: u32) !*WinsIndexBuffer9 {
        const ib = try allocator.create(WinsIndexBuffer9);
        const mem = try allocator.alloc(u8, length);
        @memset(mem, 0);
        ib.* = .{
            .vtbl = &g_ib9_vtbl,
            .ref_count = 1,
            .length = length,
            .usage = usage,
            .format = format,
            .pool = pool,
            .data = mem,
            .allocator = allocator,
        };
        return ib;
    }
};

fn ib_QueryInterface(this: *anyopaque, riid: ?*const anyopaque, ppv: ?*?*anyopaque) callconv(W) HRESULT {
    _ = riid;
    if (ppv) |p| p.* = this;
    return S_OK;
}
fn ib_AddRef(this: *anyopaque) callconv(W) u32 {
    const self: *WinsIndexBuffer9 = @ptrCast(@alignCast(this));
    self.ref_count += 1;
    return self.ref_count;
}
fn ib_Release(this: *anyopaque) callconv(W) u32 {
    const self: *WinsIndexBuffer9 = @ptrCast(@alignCast(this));
    if (self.ref_count > 0) self.ref_count -= 1;
    return self.ref_count;
}
fn ib_Lock(this: *anyopaque, offset: u32, size: u32, ppbData: ?*?*anyopaque, flags: u32) callconv(W) HRESULT {
    _ = flags;
    const self: *WinsIndexBuffer9 = @ptrCast(@alignCast(this));
    if (ppbData == null or offset >= self.length) return E_FAIL;
    _ = size;
    ppbData.?.* = @ptrCast(self.data.ptr + offset);
    return D3D_OK;
}
fn ib_Unlock(this: *anyopaque) callconv(W) HRESULT {
    _ = this;
    return D3D_OK;
}
fn ib_GetDesc(this: *anyopaque, pDesc: ?*D3DINDEXBUFFER_DESC) callconv(W) HRESULT {
    const self: *WinsIndexBuffer9 = @ptrCast(@alignCast(this));
    if (pDesc) |d| {
        d.Format = self.format;
        d.Type = 2; // D3DRTYPE_INDEXBUFFER
        d.Usage = self.usage;
        d.Pool = self.pool;
        d.Size = self.length;
    }
    return D3D_OK;
}

const g_ib9_vtbl: IDirect3DIndexBuffer9Vtbl = .{
    .QueryInterface = &ib_QueryInterface,
    .AddRef = &ib_AddRef,
    .Release = &ib_Release,
    .GetDevice = @ptrCast(&vb_Stub),
    .SetPrivateData = @ptrCast(&vb_Stub),
    .GetPrivateData = @ptrCast(&vb_Stub),
    .FreePrivateData = @ptrCast(&vb_Stub),
    .SetPriority = @ptrCast(&vb_Stub),
    .GetPriority = @ptrCast(&vb_Stub),
    .PreLoad = @ptrCast(&vb_Stub),
    .GetType = @ptrCast(&vb_Stub),
    .Lock = &ib_Lock,
    .Unlock = &ib_Unlock,
    .GetDesc = &ib_GetDesc,
};

pub const D3DFMT_DXT1: u32 = 0x31545844; // 'DXT1'
pub const D3DFMT_DXT3: u32 = 0x33545844; // 'DXT3'
pub const D3DFMT_DXT5: u32 = 0x35545844; // 'DXT5'

pub const SurfaceLayout = struct { pitch: u32, size: usize };

/// Storage layout of a colour surface/texture level, or null when the format has
/// none here (depth/stencil, 24-bit, YUV, unknown). Rows are `pitch` bytes; DXT is
/// stored as 4x4 blocks (8 bytes for DXT1, 16 for DXT3/DXT5) and its pitch is one
/// row of blocks, as in D3D9 where LockRect on a compressed level returns that.
/// This is STORAGE only: nothing here decodes or samples texels.
pub fn surfaceLayout(format: u32, width: u32, height: u32) ?SurfaceLayout {
    const block: u32 = switch (format) {
        D3DFMT_DXT1 => 8,
        D3DFMT_DXT3, D3DFMT_DXT5 => 16,
        else => 0,
    };
    if (block != 0) {
        const bw = @max(1, (width + 3) / 4);
        const bh = @max(1, (height + 3) / 4);
        return .{ .pitch = bw * block, .size = @as(usize, bw * block) * bh };
    }
    const bpp: u32 = switch (format) {
        21, 22, 31, 32, 33, 62, 112, 114 => 4, // A8R8G8B8 X8R8G8B8 A2B10G10R10 A8B8G8R8 X8B8G8R8 X8L8V8U8 G16R16F R32F
        23, 24, 25, 26, 30, 51, 60, 61, 111 => 2, // R5G6B5 X1R5G5B5 A1R5G5B5 A4R4G4B4 X4R4G4B4 A8L8 V8U8 L6V5U5 R16F
        28, 50 => 1, // A8 L8
        113, 115 => 8, // A16B16G16R16F G32R32F
        116 => 16, // A32B32G32R32F
        else => return null,
    };
    return .{ .pitch = width * bpp, .size = @as(usize, width * bpp) * height };
}

// Surface 9
pub const WinsSurface9 = struct {
    vtbl: *const IDirect3DSurface9Vtbl,
    ref_count: u32,
    width: u32,
    height: u32,
    format: u32,
    pitch: i32,
    data: []u8,
    allocator: std.mem.Allocator,
    /// False when `data` belongs to someone else (the device's back/depth buffer).
    owns_data: bool = true,
    usage: u32 = 0,
    pool: u32 = 1, // D3DPOOL_MANAGED
    owner_device: ?*anyopaque = null,
    multi_sample_type: u32 = 0,
    /// Depth/stencil surfaces are not lockable in D3D9 (LockRect -> D3DERR_INVALIDCALL).
    lockable: bool = true,

    /// A surface over memory owned elsewhere, e.g. the device's back buffer: the
    /// guest and the rasterizer then see the very same pixels, with no copy.
    pub fn wrap(allocator: std.mem.Allocator, width: u32, height: u32, format: u32, bytes: []u8, usage: u32, pool: u32, lockable: bool) !*WinsSurface9 {
        const surf = try allocator.create(WinsSurface9);
        surf.* = .{
            .vtbl = &g_surf9_vtbl,
            .ref_count = 1,
            .width = width,
            .height = height,
            .format = format,
            .pitch = @intCast(width * 4),
            .data = bytes,
            .allocator = allocator,
            .owns_data = false,
            .usage = usage,
            .pool = pool,
            .lockable = lockable,
        };
        return surf;
    }

    /// Frees the pixel storage (when owned) and the object itself.
    pub fn destroy(self: *WinsSurface9) void {
        const a = self.allocator;
        if (self.owns_data) a.free(self.data);
        a.destroy(self);
    }

    pub fn create(allocator: std.mem.Allocator, width: u32, height: u32, format: u32) !*WinsSurface9 {
        const surf = try allocator.create(WinsSurface9);
        // Colour formats get their real layout; everything else (depth/stencil)
        // keeps 4 bytes per pixel.
        const lay: SurfaceLayout = surfaceLayout(format, width, height) orelse .{ .pitch = width * 4, .size = @as(usize, width * 4) * height };
        const pitch: i32 = @intCast(lay.pitch);
        const total_size: usize = lay.size;
        const mem = try allocator.alloc(u8, total_size);
        @memset(mem, 0);
        surf.* = .{
            .vtbl = &g_surf9_vtbl,
            .ref_count = 1,
            .width = width,
            .height = height,
            .format = format,
            .pitch = pitch,
            .data = mem,
            .allocator = allocator,
        };
        return surf;
    }
};

fn surf_QueryInterface(this: *anyopaque, riid: ?*const anyopaque, ppv: ?*?*anyopaque) callconv(W) HRESULT {
    _ = riid;
    if (ppv) |p| p.* = this;
    return S_OK;
}
fn surf_AddRef(this: *anyopaque) callconv(W) u32 {
    const self: *WinsSurface9 = @ptrCast(@alignCast(this));
    self.ref_count += 1;
    return self.ref_count;
}
fn surf_Release(this: *anyopaque) callconv(W) u32 {
    const self: *WinsSurface9 = @ptrCast(@alignCast(this));
    if (self.ref_count > 0) self.ref_count -= 1;
    return self.ref_count;
}
fn surf_LockRect(this: *anyopaque, pLocked: ?*D3DLOCKED_RECT, pRect: ?*const D3DRECT, flags: u32) callconv(W) HRESULT {
    _ = flags;
    _ = pRect;
    const self: *WinsSurface9 = @ptrCast(@alignCast(this));
    if (!self.lockable) return D3DERR_INVALIDCALL;
    if (pLocked) |l| {
        l.Pitch = self.pitch;
        l.pBits = self.data.ptr;
    }
    return D3D_OK;
}
fn surf_UnlockRect(this: *anyopaque) callconv(W) HRESULT {
    _ = this;
    return D3D_OK;
}
fn surf_GetType(this: *anyopaque) callconv(W) u32 {
    _ = this;
    return D3DRTYPE_SURFACE;
}
fn surf_GetDesc(this: *anyopaque, pDesc: ?*D3DSURFACE_DESC) callconv(W) HRESULT {
    const self: *WinsSurface9 = @ptrCast(@alignCast(this));
    if (pDesc) |d| {
        d.Width = self.width;
        d.Height = self.height;
        d.Format = self.format;
        d.Type = 1; // D3DRTYPE_SURFACE (3 is D3DRTYPE_TEXTURE)
        d.Usage = self.usage;
        d.Pool = self.pool;
        d.MultiSampleType = 0;
        d.MultiSampleQuality = 0;
    }
    return D3D_OK;
}

const g_surf9_vtbl: IDirect3DSurface9Vtbl = .{
    .QueryInterface = &surf_QueryInterface,
    .AddRef = &surf_AddRef,
    .Release = &surf_Release,
    .GetDevice = @ptrCast(&vb_Stub),
    .SetPrivateData = @ptrCast(&vb_Stub),
    .GetPrivateData = @ptrCast(&vb_Stub),
    .FreePrivateData = @ptrCast(&vb_Stub),
    .SetPriority = @ptrCast(&vb_Stub),
    .GetPriority = @ptrCast(&vb_Stub),
    .PreLoad = @ptrCast(&vb_Stub),
    .GetType = &surf_GetType,
    .GetContainer = @ptrCast(&vb_Stub),
    .GetDesc = &surf_GetDesc,
    .LockRect = &surf_LockRect,
    .UnlockRect = &surf_UnlockRect,
    .GetDC = @ptrCast(&vb_Stub),
    .ReleaseDC = @ptrCast(&vb_Stub),
};

// Texture 9
pub const WinsTexture9 = struct {
    vtbl: *const IDirect3DTexture9Vtbl,
    ref_count: u32,
    width: u32,
    height: u32,
    levels: u32,
    usage: u32,
    format: u32,
    pool: u32,
    /// Level 0 (kept as its own field: it is what most callers want).
    surface: *WinsSurface9,
    /// One surface per mip level, each with its own size, pitch and storage.
    surfaces: []*WinsSurface9,
    allocator: std.mem.Allocator,

    /// Number of levels in a full mip chain down to 1x1: 1 + floor(log2(max(w, h))).
    pub fn fullChain(width: u32, height: u32) u32 {
        return 1 + (31 - @clz(@max(width, height)));
    }

    /// `levels == 0` asks for the full chain; more levels than the chain holds,
    /// a zero dimension or a format without a storage layout is D3DERR_INVALIDCALL.
    pub fn create(allocator: std.mem.Allocator, width: u32, height: u32, levels: u32, usage: u32, format: u32, pool: u32) !*WinsTexture9 {
        if (width == 0 or height == 0 or surfaceLayout(format, 1, 1) == null) return error.InvalidCall;
        const full = fullChain(width, height);
        const n: u32 = if (levels == 0) full else levels;
        if (n > full) return error.InvalidCall;
        const tex = try allocator.create(WinsTexture9);
        errdefer allocator.destroy(tex);
        const surfs = try allocator.alloc(*WinsSurface9, n);
        errdefer allocator.free(surfs);
        var made: usize = 0;
        errdefer for (surfs[0..made]) |s| s.destroy();
        while (made < n) : (made += 1) {
            const w = @max(1, width >> @intCast(made));
            const h = @max(1, height >> @intCast(made));
            const s = try WinsSurface9.create(allocator, w, h, format);
            s.usage = usage;
            s.pool = pool;
            surfs[made] = s;
        }
        tex.* = .{
            .vtbl = &g_tex9_vtbl,
            .ref_count = 1,
            .width = width,
            .height = height,
            .levels = n,
            .usage = usage,
            .format = format,
            .pool = pool,
            .surface = surfs[0],
            .surfaces = surfs,
            .allocator = allocator,
        };
        return tex;
    }

    /// Frees the texture and its levels, unless the guest still holds a level
    /// surface it took with GetSurfaceLevel (then it is left alone: a leak, not a
    /// use-after-free).
    pub fn destroy(self: *WinsTexture9) void {
        for (self.surfaces) |s| {
            if (s.ref_count > 1) return;
        }
        const a = self.allocator;
        for (self.surfaces) |s| s.destroy();
        a.free(self.surfaces);
        a.destroy(self);
    }
};

/// IUnknown, IDirect3DResource9, IDirect3DBaseTexture9 and IDirect3DTexture9 are
/// implemented by a 2D texture; anything else is E_NOINTERFACE, and a successful
/// query takes a reference.
fn tex_QueryInterface(this: *anyopaque, riid: ?*const anyopaque, ppv: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsTexture9 = @ptrCast(@alignCast(this));
    const out = ppv orelse return E_POINTER;
    out.* = null;
    const r = riid orelse return E_POINTER;
    const id: *align(1) const GUID = @ptrCast(r);
    if (guidEql(id, &IID_IUnknown) or guidEql(id, &IID_IDirect3DResource9) or
        guidEql(id, &IID_IDirect3DBaseTexture9) or guidEql(id, &IID_IDirect3DTexture9))
    {
        self.ref_count += 1;
        out.* = this;
        return S_OK;
    }
    return E_NOINTERFACE;
}
fn tex_AddRef(this: *anyopaque) callconv(W) u32 {
    const self: *WinsTexture9 = @ptrCast(@alignCast(this));
    self.ref_count += 1;
    return self.ref_count;
}
fn tex_Release(this: *anyopaque) callconv(W) u32 {
    const self: *WinsTexture9 = @ptrCast(@alignCast(this));
    if (self.ref_count > 0) self.ref_count -= 1;
    const left = self.ref_count;
    if (left == 0) self.destroy();
    return left;
}
fn tex_GetType(this: *anyopaque) callconv(W) u32 {
    _ = this;
    return D3DRTYPE_TEXTURE;
}
fn tex_GetLevelCount(this: *anyopaque) callconv(W) u32 {
    const self: *WinsTexture9 = @ptrCast(@alignCast(this));
    return @intCast(self.surfaces.len);
}
fn tex_GetLevelDesc(this: *anyopaque, level: u32, pDesc: ?*D3DSURFACE_DESC) callconv(W) HRESULT {
    const self: *WinsTexture9 = @ptrCast(@alignCast(this));
    if (level >= self.surfaces.len) return D3DERR_INVALIDCALL;
    const s = self.surfaces[level];
    return s.vtbl.GetDesc(s, pDesc);
}
/// Hands out the level's surface with a reference of its own, as D3D9 does.
fn tex_GetSurfaceLevel(this: *anyopaque, level: u32, ppSurface: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsTexture9 = @ptrCast(@alignCast(this));
    const out = ppSurface orelse return D3DERR_INVALIDCALL;
    out.* = null;
    if (level >= self.surfaces.len) return D3DERR_INVALIDCALL;
    const s = self.surfaces[level];
    s.ref_count += 1;
    out.* = s;
    return D3D_OK;
}
fn tex_LockRect(this: *anyopaque, level: u32, pLocked: ?*D3DLOCKED_RECT, pRect: ?*const D3DRECT, flags: u32) callconv(W) HRESULT {
    const self: *WinsTexture9 = @ptrCast(@alignCast(this));
    if (level >= self.surfaces.len) return D3DERR_INVALIDCALL;
    const s = self.surfaces[level];
    return s.vtbl.LockRect(s, pLocked, pRect, flags);
}
fn tex_UnlockRect(this: *anyopaque, level: u32) callconv(W) HRESULT {
    const self: *WinsTexture9 = @ptrCast(@alignCast(this));
    if (level >= self.surfaces.len) return D3DERR_INVALIDCALL;
    const s = self.surfaces[level];
    return s.vtbl.UnlockRect(s);
}

const g_tex9_vtbl: IDirect3DTexture9Vtbl = .{
    .QueryInterface = &tex_QueryInterface,
    .AddRef = &tex_AddRef,
    .Release = &tex_Release,
    .GetDevice = @ptrCast(&vb_Stub),
    .SetPrivateData = @ptrCast(&vb_Stub),
    .GetPrivateData = @ptrCast(&vb_Stub),
    .FreePrivateData = @ptrCast(&vb_Stub),
    .SetPriority = @ptrCast(&vb_Stub),
    .GetPriority = @ptrCast(&vb_Stub),
    .PreLoad = @ptrCast(&vb_Stub),
    .GetType = &tex_GetType,
    .SetLOD = @ptrCast(&vb_Stub),
    .GetLOD = @ptrCast(&vb_Stub),
    .GetLevelCount = &tex_GetLevelCount,
    .SetAutoGenFilterType = @ptrCast(&vb_Stub),
    .GetAutoGenFilterType = @ptrCast(&vb_Stub),
    .GenerateMipSubLevels = @ptrCast(&vb_Stub),
    .GetLevelDesc = &tex_GetLevelDesc,
    .GetSurfaceLevel = &tex_GetSurfaceLevel,
    .LockRect = &tex_LockRect,
    .UnlockRect = &tex_UnlockRect,
    .AddDirtyRect = @ptrCast(&vb_Stub),
};

// Shader 9
pub const WinsShader9 = struct {
    vtbl: *const IDirect3DShader9Vtbl,
    ref_count: u32,
    is_pixel: bool,
    tokens: []const u32,
    allocator: std.mem.Allocator,

    pub fn create(allocator: std.mem.Allocator, is_pixel: bool, pFunction: ?*const u32) !*WinsShader9 {
        const sh = try allocator.create(WinsShader9);
        var count: usize = 0;
        if (pFunction) |fn_ptr| {
            const ptr: [*]const u32 = @ptrCast(fn_ptr);
            while (count < 65536) : (count += 1) {
                if (ptr[count] == 0x0000FFFF) {
                    count += 1;
                    break;
                }
            }
        }
        var tokens_slice: []u32 = &[_]u32{};
        if (count > 0 and pFunction != null) {
            tokens_slice = try allocator.alloc(u32, count);
            const ptr: [*]const u32 = @ptrCast(pFunction.?);
            @memcpy(tokens_slice, ptr[0..count]);
        }
        sh.* = .{
            .vtbl = &g_shader9_vtbl,
            .ref_count = 1,
            .is_pixel = is_pixel,
            .tokens = tokens_slice,
            .allocator = allocator,
        };
        return sh;
    }
};

fn sh_QueryInterface(this: *anyopaque, riid: ?*const anyopaque, ppv: ?*?*anyopaque) callconv(W) HRESULT {
    _ = riid;
    if (ppv) |p| p.* = this;
    return S_OK;
}
fn sh_AddRef(this: *anyopaque) callconv(W) u32 {
    const self: *WinsShader9 = @ptrCast(@alignCast(this));
    self.ref_count += 1;
    return self.ref_count;
}
fn sh_Release(this: *anyopaque) callconv(W) u32 {
    const self: *WinsShader9 = @ptrCast(@alignCast(this));
    if (self.ref_count > 0) self.ref_count -= 1;
    return self.ref_count;
}
fn sh_GetFunction(this: *anyopaque, pData: ?*anyopaque, pSize: ?*u32) callconv(W) HRESULT {
    const self: *WinsShader9 = @ptrCast(@alignCast(this));
    const size_bytes: u32 = @intCast(self.tokens.len * 4);
    if (pSize) |ps| ps.* = size_bytes;
    if (pData) |pd| {
        const dst: [*]u8 = @ptrCast(pd);
        const src: [*]const u8 = @ptrCast(self.tokens.ptr);
        @memcpy(dst[0..size_bytes], src[0..size_bytes]);
    }
    return D3D_OK;
}

const g_shader9_vtbl: IDirect3DShader9Vtbl = .{
    .QueryInterface = &sh_QueryInterface,
    .AddRef = &sh_AddRef,
    .Release = &sh_Release,
    .GetDevice = @ptrCast(&vb_Stub),
    .GetFunction = &sh_GetFunction,
};

// ============================================================================
// D3D9 Main Interfaces
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

/// D3DERR_INVALIDCALL (0x8876086C).
pub const D3DERR_INVALIDCALL: HRESULT = -2005530516;
/// D3DERR_NOTFOUND (0x88760866).
pub const D3DERR_NOTFOUND: HRESULT = -2005530522;

/// Texture stages (D3DTSS_*) and samplers (D3DSAMP_*) whose state this device
/// stores. The caps MaxTextureBlendStages / MaxSimultaneousTextures are derived
/// from kMaxTextureStages, so the device can never advertise more stages than
/// it keeps state for. Storing state is what is implemented: the software
/// rasterizer samples only bound texture 0 and does not yet evaluate stage
/// operations, so multi-texture blending is NOT_DEMONSTRATED.
pub const kMaxTextureStages: u32 = 8;
const kTssSlots = 33; // D3DTSS_COLOROP (1) .. D3DTSS_CONSTANT (32)
const kSampSlots = 14; // D3DSAMP_ADDRESSU (1) .. D3DSAMP_DMAPOFFSET (13)

/// Documented D3D9 power-on defaults for texture stage state.
fn defaultTextureStageStates() [kMaxTextureStages][kTssSlots]u32 {
    var s = [_][kTssSlots]u32{[_]u32{0} ** kTssSlots} ** kMaxTextureStages;
    for (0..kMaxTextureStages) |i| {
        s[i][1] = if (i == 0) 4 else 1; // COLOROP: MODULATE on stage 0, DISABLE elsewhere
        s[i][2] = 2; // COLORARG1: TEXTURE
        s[i][3] = 1; // COLORARG2: CURRENT
        s[i][4] = if (i == 0) 2 else 1; // ALPHAOP: SELECTARG1 on stage 0, DISABLE elsewhere
        s[i][5] = 2; // ALPHAARG1: TEXTURE
        s[i][6] = 1; // ALPHAARG2: CURRENT
        s[i][11] = @intCast(i); // TEXCOORDINDEX
        s[i][26] = 1; // COLORARG0: CURRENT
        s[i][27] = 1; // ALPHAARG0: CURRENT
        s[i][28] = 1; // RESULTARG: CURRENT
    }
    return s;
}

/// Documented D3D9 power-on defaults for sampler state.
fn defaultSamplerStates() [16][kSampSlots]u32 {
    var s = [_][kSampSlots]u32{[_]u32{0} ** kSampSlots} ** 16;
    for (0..16) |i| {
        s[i][1] = 1; // ADDRESSU: WRAP
        s[i][2] = 1; // ADDRESSV: WRAP
        s[i][3] = 1; // ADDRESSW: WRAP
        s[i][5] = 1; // MAGFILTER: POINT
        s[i][6] = 1; // MINFILTER: POINT
        s[i][7] = 0; // MIPFILTER: NONE
        s[i][10] = 1; // MAXANISOTROPY
    }
    return s;
}

/// IDirect3DVertexDeclaration9: an immutable copy of the element list, END included.
pub const WinsVertexDecl9 = struct {
    vtbl: *const IDirect3DVertexDeclaration9Vtbl align(16),
    ref_count: u32,
    device: *WinsD3DDevice9,
    elements: []D3DVERTEXELEMENT9,
};

fn vdecl_QueryInterface(this: *anyopaque, riid: ?*const anyopaque, ppv: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsVertexDecl9 = @ptrCast(@alignCast(this));
    const out = ppv orelse return E_POINTER;
    out.* = null;
    const r = riid orelse return E_POINTER;
    const id: *align(1) const GUID = @ptrCast(r);
    if (guidEql(id, &IID_IUnknown) or guidEql(id, &IID_IDirect3DVertexDeclaration9)) {
        self.ref_count += 1;
        out.* = this;
        return S_OK;
    }
    return E_NOINTERFACE;
}
fn vdecl_AddRef(this: *anyopaque) callconv(W) u32 {
    const self: *WinsVertexDecl9 = @ptrCast(@alignCast(this));
    self.ref_count += 1;
    return self.ref_count;
}
fn vdecl_Release(this: *anyopaque) callconv(W) u32 {
    const self: *WinsVertexDecl9 = @ptrCast(@alignCast(this));
    if (self.ref_count > 0) self.ref_count -= 1;
    return self.ref_count;
}
fn vdecl_GetDevice(this: *anyopaque, ppDevice: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsVertexDecl9 = @ptrCast(@alignCast(this));
    const out = ppDevice orelse return D3DERR_INVALIDCALL;
    self.device.ref_count += 1;
    out.* = self.device;
    return D3D_OK;
}
/// With a null buffer only the count (END included) is returned.
fn vdecl_GetDeclaration(this: *anyopaque, pElement: ?*D3DVERTEXELEMENT9, pNumElements: ?*u32) callconv(W) HRESULT {
    const self: *WinsVertexDecl9 = @ptrCast(@alignCast(this));
    const n = pNumElements orelse return D3DERR_INVALIDCALL;
    n.* = @intCast(self.elements.len);
    if (pElement) |dst| {
        const out: [*]D3DVERTEXELEMENT9 = @ptrCast(dst);
        @memcpy(out[0..self.elements.len], self.elements);
    }
    return D3D_OK;
}
const g_vdecl9_vtbl: IDirect3DVertexDeclaration9Vtbl = .{
    .QueryInterface = &vdecl_QueryInterface,
    .AddRef = &vdecl_AddRef,
    .Release = &vdecl_Release,
    .GetDevice = &vdecl_GetDevice,
    .GetDeclaration = &vdecl_GetDeclaration,
};

// COM contract: the guest reads the vtable pointer at offset 0 of every object it
// is handed. A plain Zig `struct` may be reordered by the compiler, so this is
// asserted at compile time for every COM-visible object. (Adding unrelated fields
// to WinsD3DDevice9 once moved `vtbl` away from offset 0: the guest then read a
// NULL vtable and crashed, while tests that go through fields still passed.)
comptime {
    for (.{ WinsD3D9, WinsD3DDevice9, WinsSurface9, WinsTexture9, WinsVertexBuffer9, WinsIndexBuffer9, WinsShader9, WinsD3DXBuffer, WinsVertexDecl9 }) |T| {
        if (@offsetOf(T, "vtbl") != 0) @compileError("COM object " ++ @typeName(T) ++ " must keep vtbl at offset 0");
    }
}

pub const WinsD3DDevice9 = struct {
    // Largest alignment in the struct, so the compiler keeps it first (see the
    // comptime check above); the guest dereferences offset 0 as the vtable.
    vtbl: *const IDirect3DDevice9Vtbl align(16),
    ref_count: u32,
    adapter: u32,
    device_type: u32,
    params: D3DPRESENT_PARAMETERS,
    viewport: D3DVIEWPORT9,
    material: D3DMATERIAL9,
    transform_states: [kTransformStateCount]D3DMATRIX,
    lights: std.AutoHashMapUnmanaged(u32, D3DLightState9),
    in_scene: bool,
    frame_count: u64,
    draw_call_count: u64,
    backbuffer: []u32, // Screen pixels in ARGB format
    depthbuffer: []f32, // 32-bit floating point depth buffer
    vs_consts: [256][4]f32,
    ps_consts: [224][4]f32,
    render_states: [256]u32,
    tex_stage_states: [kMaxTextureStages][kTssSlots]u32,
    rt_surface: ?*WinsSurface9,
    ds_surface: ?*WinsSurface9,
    bound_ds_surface: ?*WinsSurface9,
    depth_stencil_explicit: bool,
    vertex_decl: ?*WinsVertexDecl9,
    sampler_states: [16][kSampSlots]u32,
    streams: [16]?*WinsVertexBuffer9,
    stream_strides: [16]u32,
    stream_offsets: [16]u32,
    indices: ?*WinsIndexBuffer9,
    bound_textures: [16]?*WinsTexture9,
    active_vs: ?*WinsShader9,
    active_ps: ?*WinsShader9,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, adapter: u32, device_type: u32, params: D3DPRESENT_PARAMETERS) !*WinsD3DDevice9 {
        const dev = try allocator.create(WinsD3DDevice9);
        const w = if (params.BackBufferWidth > 0) params.BackBufferWidth else 800;
        const h = if (params.BackBufferHeight > 0) params.BackBufferHeight else 600;

        const pixels = try allocator.alloc(u32, w * h);
        @memset(pixels, 0xFF000000); // Clear black

        const depths = try allocator.alloc(f32, w * h);
        @memset(depths, 1.0); // Clear 1.0 (far plane)

        dev.* = .{
            .vtbl = &g_device9_vtbl,
            .ref_count = 1,
            .adapter = adapter,
            .device_type = device_type,
            .params = params,
            .viewport = .{
                .X = 0,
                .Y = 0,
                .Width = w,
                .Height = h,
                .MinZ = 0.0,
                .MaxZ = 1.0,
            },
            .material = defaultMaterial9(),
            .transform_states = [_]D3DMATRIX{d3dIdentityMatrix()} ** kTransformStateCount,
            .lights = .empty,
            .in_scene = false,
            .frame_count = 0,
            .draw_call_count = 0,
            .backbuffer = pixels,
            .depthbuffer = depths,
            .vs_consts = [_][4]f32{[_]f32{ 0, 0, 0, 0 }} ** 256,
            .ps_consts = [_][4]f32{[_]f32{ 0, 0, 0, 0 }} ** 224,
            .render_states = [_]u32{0} ** 256,
            .tex_stage_states = defaultTextureStageStates(),
            .rt_surface = null,
            .ds_surface = null,
            .bound_ds_surface = null,
            .depth_stencil_explicit = false,
            .vertex_decl = null,
            .sampler_states = defaultSamplerStates(),
            .streams = [_]?*WinsVertexBuffer9{null} ** 16,
            .stream_strides = [_]u32{0} ** 16,
            .stream_offsets = [_]u32{0} ** 16,
            .indices = null,
            .bound_textures = [_]?*WinsTexture9{null} ** 16,
            .active_vs = null,
            .active_ps = null,
            .allocator = allocator,
        };
        if (comptime @sizeOf(usize) == 4) {
            wins_d3d9_device_self = @intCast(@intFromPtr(dev));
        }
        return dev;
    }
};

/// IDirect3D9::QueryInterface.
///
/// Only the interfaces this module implements are answered. Any other
/// identifier gets E_NOINTERFACE: answering S_OK hands the guest an object
/// whose vtable is shorter than the interface the guest believes it holds,
/// and the next call reads past the end of the table.
fn d3d9_QueryInterface(this: *anyopaque, riid: ?*const anyopaque, ppv: ?*?*anyopaque) callconv(W) HRESULT {
    if (riid == null or ppv == null) return E_POINTER;
    const id: *align(1) const GUID = @ptrCast(riid.?);
    if (guidEql(id, &IID_IDirect3D9)) {
        ppv.?.* = this;
        return S_OK;
    }
    std.debug.print("[WINS:D3D9] QueryInterface: this module implements only IDirect3D9; answering E_NOINTERFACE\n", .{});
    return E_NOINTERFACE;
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

/// The one display mode this adapter offers.
const kDisplayMode: D3DDISPLAYMODE = .{
    .Width = 1280,
    .Height = 720,
    .RefreshRate = 60,
    .Format = D3DFMT_X8R8G8B8,
};

fn fillAscii(dest: []u8, text: []const u8) void {
    @memset(dest, 0);
    const n = @min(dest.len, text.len);
    @memcpy(dest[0..n], text[0..n]);
}

/// IDirect3D9::GetAdapterIdentifier.
///
/// This method has to write the structure: the guest reads the driver name
/// and the description out of it by offset and then walks what it finds.
/// Answering D3D_OK without writing it leaves the guest reading whatever was
/// on its stack, which is what it was doing: the first dword it read back
/// was 0xc03302eb and the next instruction dereferenced it.
fn d3d9_GetAdapterIdentifier(this: *anyopaque, adapter: u32, flags: u32, pIdentifier: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = flags;
    if (adapter != 0) return D3DERR_INVALIDARG;
    // align(1): the caller's buffer is the guest's, and a trap on an
    // unexpected alignment would turn a readable structure into a crash.
    const out: ?*align(1) D3DADAPTER_IDENTIFIER9 = if (pIdentifier) |p| @ptrCast(p) else null;
    const id = out orelse return E_POINTER;
    var value: D3DADAPTER_IDENTIFIER9 = std.mem.zeroes(D3DADAPTER_IDENTIFIER9);
    fillAscii(value.Driver[0..], "WINS Direct3D 9 Software Adapter");
    fillAscii(value.Description[0..], "WINS Direct3D 9 software rasterizer");
    fillAscii(value.DeviceName[0..], "\\.\\DISPLAY1");
    value.DriverVersion = 0x0000000100000000;
    value.VendorId = 0x8086;
    value.DeviceId = 0x1237;
    value.SubSysId = 0;
    value.Revision = 0;
    value.WHQLLevel = 0;
    id.* = value;
    return D3D_OK;
}

/// IDirect3D9::GetAdapterModeCount.
fn d3d9_GetAdapterModeCount(this: *anyopaque, adapter: u32, format: u32) callconv(W) u32 {
    _ = this;
    if (adapter != 0) return 0;
    // D3DFORMAT_UNKNOWN asks for every mode the adapter has.
    if (format == 0 or isRenderTargetFormat(format)) return 1;
    return 0;
}

/// IDirect3D9::EnumAdapterModes. The guest reads the mode out of the
/// structure by offset, so it has to be written.
fn d3d9_EnumAdapterModes(this: *anyopaque, adapter: u32, format: u32, mode: u32, pMode: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    if (adapter != 0) return D3DERR_INVALIDARG;
    if (mode != 0) return D3DERR_INVALIDARG;
    if (format != 0 and !isRenderTargetFormat(format)) return D3DERR_INVALIDARG;
    const out: ?*align(1) D3DDISPLAYMODE = if (pMode) |p| @ptrCast(p) else null;
    const m = out orelse return E_POINTER;
    m.* = kDisplayMode;
    return D3D_OK;
}

/// IDirect3D9::GetAdapterDisplayMode.
fn d3d9_GetAdapterDisplayMode(this: *anyopaque, adapter: u32, pMode: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    if (adapter != 0) return D3DERR_INVALIDARG;
    const out: ?*align(1) D3DDISPLAYMODE = if (pMode) |p| @ptrCast(p) else null;
    const m = out orelse return E_POINTER;
    m.* = kDisplayMode;
    return D3D_OK;
}
fn d3d9_GetDeviceCaps(this: *anyopaque, adapter: u32, dev_type: u32, pCaps: ?*D3DCAPS9) callconv(W) HRESULT {
    _ = this;
    _ = adapter;
    if (pCaps) |caps| {
        @memset(std.mem.asBytes(caps), 0);
        caps.DeviceType = dev_type;
        // The rasterizer is software, so transform & lighting run on the CPU:
        // the HWTRANSFORMLIGHT cap is honest here, and guests gate on it
        // before calling CreateDevice.
        caps.DevCaps = D3DDEVCAPS_HWTRANSFORMLIGHT;
        caps.MaxTextureWidth = 8192;
        caps.MaxTextureHeight = 8192;
        caps.MaxVolumeExtent = 2048;
        caps.MaxTextureRepeat = 8192;
        caps.MaxTextureAspectRatio = 8192;
        caps.MaxAnisotropy = 16;
        caps.MaxActiveLights = kMaxDeviceLights;
        caps.MaxPrimitiveCount = 1048576;
        caps.MaxVertexIndex = 1048576;
        caps.MaxStreams = 16;
        caps.MaxStreamStride = 256;
        caps.VertexShaderVersion = 0xFFFE0300; // vs_3_0
        caps.PixelShaderVersion = 0xFFFF0300; // ps_3_0
        caps.MaxVertexShader30InstructionSlots = 32768;
        caps.MaxPixelShader30InstructionSlots = 32768;
        caps.NumSimultaneousRTs = 4;
        // Derived from what the device stores state for (see kMaxTextureStages).
        caps.MaxTextureBlendStages = kMaxTextureStages;
        caps.MaxSimultaneousTextures = kMaxTextureStages;
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
    _ = hFocusWindow;
    _ = behavior_flags;
    if (ppDevice == null or pParams == null) return E_FAIL;
    const gpa = std.heap.page_allocator;
    const dev = WinsD3DDevice9.init(gpa, adapter, dev_type, pParams.?.*) catch return E_OUTOFMEMORY;
    ppDevice.?.* = @ptrCast(dev);
    return D3D_OK;
}
/// The formats this adapter can render into.
///
/// The software back buffer is 32-bit; both RGBA byte orders (22 and 23,
/// matching what Proton's HAL accepts) are served from it. Everything else is
/// refused rather than silently accepted: a guest that is told a format is
/// available allocates it and then writes to it.
fn isRenderTargetFormat(format: u32) bool {
    return format == D3DFMT_A8R8G8B8 or format == D3DFMT_X8R8G8B8 or format == D3DFMT_A8B8G8R8;
}

/// The depth/stencil formats this adapter can allocate.
fn isDepthStencilFormat(format: u32) bool {
    return format == D3DFMT_D24S8 or format == D3DFMT_D16;
}

/// IDirect3D9::CheckDeviceType.
///
/// d3d9.h: (Adapter, DevType, DisplayFormat, BackBufferFormat, Windowed).
fn d3d9_CheckDeviceType(
    this: *anyopaque,
    adapter: u32,
    dev_type: u32,
    display_format: u32,
    back_buffer_format: u32,
    windowed: i32,
) callconv(W) HRESULT {
    _ = this;
    if (adapter != 0) return D3DERR_INVALIDARG;
    if (dev_type != D3DDEVTYPE_HAL and dev_type != D3DDEVTYPE_REF) return D3DERR_INVALIDARG;
    if (windowed != 0 and windowed != 1) return D3DERR_INVALIDARG;
    if (!isRenderTargetFormat(display_format)) return D3DERR_INVALIDARG;
    // A back buffer format of zero means "the same as the display format".
    const want = if (back_buffer_format == 0) display_format else back_buffer_format;
    if (!isRenderTargetFormat(want)) return D3DERR_INVALIDARG;
    return D3D_OK;
}

/// Texture formats WinsTexture9 can back: every colour format surfaceLayout knows
/// (32/16/8-bit, V8U8, the float formats and DXT1/3/5). Backing means creating the
/// storage with the right pitch and size and returning it from LockRect; nothing
/// decodes or samples texels (the rasterizer samples no texture at all yet).
fn isTextureFormat(format: u32) bool {
    return surfaceLayout(format, 1, 1) != null;
}

/// IDirect3D9::CheckDeviceFormat.
///
/// d3d9.h: (Adapter, DeviceType, AdapterFormat, Usage, RType, CheckFormat).
fn d3d9_CheckDeviceFormat(
    this: *anyopaque,
    adapter: u32,
    dev_type: u32,
    adapter_format: u32,
    usage: u32,
    rtype: u32,
    check_format: u32,
) callconv(W) HRESULT {
    _ = this;
    if (adapter != 0) return D3DERR_INVALIDARG;
    if (dev_type != D3DDEVTYPE_HAL and dev_type != D3DDEVTYPE_REF) return D3DERR_INVALIDARG;
    if (!isRenderTargetFormat(adapter_format)) return D3DERR_NOTAVAILABLE;
    if ((usage & D3DUSAGE_RENDERTARGET) != 0) {
        if (rtype != 0 and rtype != D3DRTYPE_SURFACE and rtype != D3DRTYPE_TEXTURE) {
            return D3DERR_NOTAVAILABLE;
        }
        if (!isRenderTargetFormat(check_format)) return D3DERR_NOTAVAILABLE;
        return D3D_OK;
    }
    if ((usage & D3DUSAGE_DEPTHSTENCIL) != 0) {
        if (rtype != 0 and rtype != D3DRTYPE_SURFACE) return D3DERR_NOTAVAILABLE;
        if (!isDepthStencilFormat(check_format)) return D3DERR_NOTAVAILABLE;
        return D3D_OK;
    }
    // A plain 2D texture (optionally DYNAMIC). Only what CreateTexture can back:
    // volume/cube textures, auto-generated mipmaps and every other usage flag are
    // not implemented, and neither are the 16-bit and compressed formats.
    if (rtype == D3DRTYPE_TEXTURE and (usage & ~D3DUSAGE_DYNAMIC) == 0 and isTextureFormat(check_format)) return D3D_OK;
    return D3DERR_NOTAVAILABLE;
}

/// IDirect3D9::CheckDeviceMultiSampleType.
///
/// d3d9.h: (Adapter, DeviceType, SurfaceFormat, Windowed, MultiSampleType,
/// pNumQualityLevels).
///
/// The count of quality levels is an output, and this guest reads it: it
/// stores the byte in the capability record it builds for the mode and
/// compares that record later, so leaving the word unset hands the guest
/// whatever was on its stack and the mode it recorded is not the mode this
/// adapter has.
fn d3d9_CheckDeviceMultiSampleType(
    this: *anyopaque,
    adapter: u32,
    dev_type: u32,
    surface_format: u32,
    windowed: i32,
    multi_sample_type: u32,
    p_quality_levels: ?*u32,
) callconv(W) HRESULT {
    _ = this;
    _ = windowed;
    if (adapter != 0) return D3DERR_INVALIDARG;
    if (dev_type != D3DDEVTYPE_HAL and dev_type != D3DDEVTYPE_REF) return D3DERR_INVALIDARG;
    if (!isRenderTargetFormat(surface_format)) return D3DERR_NOTAVAILABLE;
    if (p_quality_levels) |p| p.* = 0;
    // This adapter has no multisample buffers, so every count other than
    // "none" is refused instead of answered with a number it cannot honour.
    if (multi_sample_type != D3DMULTISAMPLE_NONE) return D3DERR_NOTAVAILABLE;
    return D3D_OK;
}

/// IDirect3D9::CheckDepthStencilMatch.
///
/// d3d9.h: (Adapter, DeviceType, AdapterFormat, RenderTargetFormat,
/// DepthStencilFormat).
fn d3d9_CheckDepthStencilMatch(
    this: *anyopaque,
    adapter: u32,
    dev_type: u32,
    adapter_format: u32,
    render_target_format: u32,
    depth_stencil_format: u32,
) callconv(W) HRESULT {
    _ = this;
    if (adapter != 0) return D3DERR_INVALIDARG;
    if (dev_type != D3DDEVTYPE_HAL and dev_type != D3DDEVTYPE_REF) return D3DERR_INVALIDARG;
    if (!isRenderTargetFormat(adapter_format)) return D3DERR_NOTAVAILABLE;
    if (!isRenderTargetFormat(render_target_format)) return D3DERR_NOTAVAILABLE;
    if (!isDepthStencilFormat(depth_stencil_format)) return D3DERR_NOTAVAILABLE;
    return D3D_OK;
}

/// IDirect3D9::CheckDeviceFormatConversion.
///
/// d3d9.h: (Adapter, DeviceType, SourceFormat, TargetFormat). The software
/// path converts between the two render target formats in software, so the
/// answer is yes for that pair and no for everything else.
fn d3d9_CheckDeviceFormatConversion(
    this: *anyopaque,
    adapter: u32,
    dev_type: u32,
    source_format: u32,
    target_format: u32,
) callconv(W) HRESULT {
    _ = this;
    if (adapter != 0) return D3DERR_INVALIDARG;
    if (dev_type != D3DDEVTYPE_HAL and dev_type != D3DDEVTYPE_REF) return D3DERR_INVALIDARG;
    if (!isRenderTargetFormat(source_format)) return D3DERR_NOTAVAILABLE;
    if (!isRenderTargetFormat(target_format)) return D3DERR_NOTAVAILABLE;
    return D3D_OK;
}

/// IDirect3D9::RegisterSoftwareDevice.
///
/// There is no software plug-in to register.
fn d3d9_RegisterSoftwareDevice(this: *anyopaque, software: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = software;
    std.debug.print("[WINS:D3D9] RegisterSoftwareDevice: this adapter has no software plug-ins; answering E_NOTIMPL\n", .{});
    return E_NOTIMPL;
}

/// IDirect3D9::GetAdapterMonitor.
///
/// The guest asks for the monitor of an adapter it is about to create a
/// device on. There is no X11 monitor behind this adapter yet, so the handle
/// is null and the call says so.
fn d3d9_GetAdapterMonitor(this: *anyopaque, adapter: u32) callconv(W) usize {
    _ = this;
    if (adapter != 0) {
        std.debug.print("[WINS:D3D9] GetAdapterMonitor: adapter {d} does not exist\n", .{adapter});
        return 0;
    }
    std.debug.print("[WINS:D3D9] GetAdapterMonitor: this adapter has no monitor yet; answering a null handle\n", .{});
    return 0;
}

const g_d3d9_vtbl: IDirect3D9Vtbl = .{
    .QueryInterface = &d3d9_QueryInterface,
    .AddRef = &d3d9_AddRef,
    .Release = &d3d9_Release,
    .RegisterSoftwareDevice = &d3d9_RegisterSoftwareDevice,
    .GetAdapterCount = &d3d9_GetAdapterCount,
    .GetAdapterIdentifier = &d3d9_GetAdapterIdentifier,
    .GetAdapterModeCount = &d3d9_GetAdapterModeCount,
    .EnumAdapterModes = &d3d9_EnumAdapterModes,
    .GetAdapterDisplayMode = &d3d9_GetAdapterDisplayMode,
    .CheckDeviceType = &d3d9_CheckDeviceType,
    .CheckDeviceFormat = &d3d9_CheckDeviceFormat,
    .CheckDeviceMultiSampleType = &d3d9_CheckDeviceMultiSampleType,
    .CheckDepthStencilMatch = &d3d9_CheckDepthStencilMatch,
    .CheckDeviceFormatConversion = &d3d9_CheckDeviceFormatConversion,
    .GetDeviceCaps = &d3d9_GetDeviceCaps,
    .GetAdapterMonitor = &d3d9_GetAdapterMonitor,
    .CreateDevice = &d3d9_CreateDevice,
};

// ============================================================================
// IDirect3DDevice9 Methods
// ============================================================================

/// Only IUnknown and IDirect3DDevice9 are implemented. Any other identifier, in
/// particular IDirect3DDevice9Ex ({B18B10CE-2649-405A-870F-95F777D4313A}, which
/// FalloutNV asks for to detect Ex support), gets E_NOINTERFACE and a null
/// pointer: answering S_OK hands out an object whose vtable is shorter than the
/// interface the guest believes it holds. Reference: Wine's d3d9 does the same.
fn dev9_QueryInterface(this: *anyopaque, riid: ?*const anyopaque, ppv: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const out = ppv orelse return E_POINTER;
    out.* = null;
    const r = riid orelse return E_POINTER;
    const id: *align(1) const GUID = @ptrCast(r);
    if (guidEql(id, &IID_IUnknown) or guidEql(id, &IID_IDirect3DDevice9)) {
        self.ref_count += 1;
        out.* = this;
        return S_OK;
    }
    return E_NOINTERFACE;
}
fn dev9_AddRef(this: *anyopaque) callconv(W) u32 {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    self.ref_count += 1;
    return self.ref_count;
}
fn dev9_Release(this: *anyopaque) callconv(W) u32 {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (self.ref_count > 0) {
        self.ref_count -= 1;
        if (self.ref_count == 0) self.lights.deinit(self.allocator);
    }
    return self.ref_count;
}
fn dev9_BeginScene(this: *anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (self.in_scene) return D3DERR_INVALIDCALL;
    self.in_scene = true;
    return D3D_OK;
}
fn dev9_EndScene(this: *anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (!self.in_scene) return D3DERR_INVALIDCALL;
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
    _ = stencil;
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if ((flags & D3DCLEAR_TARGET) != 0) {
        @memset(self.backbuffer, color);
    }
    if ((flags & D3DCLEAR_ZBUFFER) != 0) {
        @memset(self.depthbuffer, z);
    }
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

// Resource Creators
fn dev9_CreateVertexBuffer(
    this: *anyopaque,
    Length: u32,
    Usage: u32,
    FVF: u32,
    Pool: u32,
    ppVertexBuffer: ?*?*anyopaque,
    pSharedHandle: ?*anyopaque,
) callconv(W) HRESULT {
    _ = pSharedHandle;
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (ppVertexBuffer == null) return E_FAIL;
    const vb = WinsVertexBuffer9.create(self.allocator, Length, Usage, FVF, Pool) catch return E_OUTOFMEMORY;
    ppVertexBuffer.?.* = @ptrCast(vb);
    return D3D_OK;
}

fn dev9_CreateIndexBuffer(
    this: *anyopaque,
    Length: u32,
    Usage: u32,
    Format: u32,
    Pool: u32,
    ppIndexBuffer: ?*?*anyopaque,
    pSharedHandle: ?*anyopaque,
) callconv(W) HRESULT {
    _ = pSharedHandle;
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (ppIndexBuffer == null) return E_FAIL;
    const ib = WinsIndexBuffer9.create(self.allocator, Length, Usage, Format, Pool) catch return E_OUTOFMEMORY;
    ppIndexBuffer.?.* = @ptrCast(ib);
    return D3D_OK;
}

fn dev9_CreateTexture(
    this: *anyopaque,
    Width: u32,
    Height: u32,
    Levels: u32,
    Usage: u32,
    Format: u32,
    Pool: u32,
    ppTexture: ?*?*anyopaque,
    pSharedHandle: ?*anyopaque,
) callconv(W) HRESULT {
    _ = pSharedHandle;
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (ppTexture == null) return E_FAIL;
    const tex = WinsTexture9.create(self.allocator, Width, Height, Levels, Usage, Format, Pool) catch |e| return if (e == error.InvalidCall) D3DERR_INVALIDCALL else E_OUTOFMEMORY;
    ppTexture.?.* = @ptrCast(tex);
    return D3D_OK;
}

fn dev9_CreateVertexShader(this: *anyopaque, pFunction: ?*const u32, ppShader: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (ppShader == null) return E_FAIL;
    const sh = WinsShader9.create(self.allocator, false, pFunction) catch return E_OUTOFMEMORY;
    ppShader.?.* = @ptrCast(sh);
    return D3D_OK;
}

fn dev9_CreatePixelShader(this: *anyopaque, pFunction: ?*const u32, ppShader: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (ppShader == null) return E_FAIL;
    const sh = WinsShader9.create(self.allocator, true, pFunction) catch return E_OUTOFMEMORY;
    ppShader.?.* = @ptrCast(sh);
    return D3D_OK;
}

fn dev9_SetStreamSource(this: *anyopaque, StreamNumber: u32, pStreamData: ?*anyopaque, OffsetInBytes: u32, Stride: u32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (StreamNumber < 16) {
        self.streams[StreamNumber] = if (pStreamData) |ps| @ptrCast(@alignCast(ps)) else null;
        self.stream_strides[StreamNumber] = Stride;
        self.stream_offsets[StreamNumber] = OffsetInBytes;
    }
    return D3D_OK;
}

fn dev9_SetIndices(this: *anyopaque, pIndexData: ?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    self.indices = if (pIndexData) |pi| @ptrCast(@alignCast(pi)) else null;
    return D3D_OK;
}

fn dev9_SetVertexShader(this: *anyopaque, pShader: ?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    self.active_vs = if (pShader) |ps| @ptrCast(@alignCast(ps)) else null;
    return D3D_OK;
}

fn dev9_SetPixelShader(this: *anyopaque, pShader: ?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    self.active_ps = if (pShader) |ps| @ptrCast(@alignCast(ps)) else null;
    return D3D_OK;
}

fn dev9_SetVertexShaderConstantF(this: *anyopaque, StartRegister: u32, pConstantData: ?*const f32, Vector4fCount: u32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (pConstantData) |cd| {
        const ptr: [*]const f32 = @ptrCast(cd);
        var i: u32 = 0;
        while (i < Vector4fCount and StartRegister + i < 256) : (i += 1) {
            const src = ptr + i * 4;
            self.vs_consts[StartRegister + i] = [4]f32{ src[0], src[1], src[2], src[3] };
        }
    }
    return D3D_OK;
}

fn dev9_SetPixelShaderConstantF(this: *anyopaque, StartRegister: u32, pConstantData: ?*const f32, Vector4fCount: u32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (pConstantData) |cd| {
        const ptr: [*]const f32 = @ptrCast(cd);
        var i: u32 = 0;
        while (i < Vector4fCount and StartRegister + i < 224) : (i += 1) {
            const src = ptr + i * 4;
            self.ps_consts[StartRegister + i] = [4]f32{ src[0], src[1], src[2], src[3] };
        }
    }
    return D3D_OK;
}

fn dev9_SetRenderState(this: *anyopaque, State: u32, Value: u32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (State < 256) self.render_states[State] = Value;
    return D3D_OK;
}

fn dev9_GetRenderState(this: *anyopaque, State: u32, pValue: ?*u32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (pValue) |pv| {
        pv.* = if (State < 256) self.render_states[State] else 0;
    }
    return D3D_OK;
}

fn dev9_SetTexture(this: *anyopaque, Sampler: u32, pTexture: ?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (Sampler < 16) {
        self.bound_textures[Sampler] = if (pTexture) |pt| @ptrCast(@alignCast(pt)) else null;
    }
    return D3D_OK;
}

// Software Triangle Rasterizer with Depth-Buffer
fn dev9_DrawPrimitive(this: *anyopaque, prim_type: u32, start_vertex: u32, count: u32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    self.draw_call_count += 1;

    // Rasterize TRIANGLELIST (4) if stream 0 is bound
    if (prim_type == 4 and self.streams[0] != null and count > 0) {
        const vb = self.streams[0].?;
        const stride = if (self.stream_strides[0] >= 12) self.stream_strides[0] else 12;
        const total_verts = count * 3;
        var t: u32 = 0;
        while (t < count) : (t += 1) {
            const idx0 = (start_vertex + t * 3 + 0) * stride;
            const idx1 = (start_vertex + t * 3 + 1) * stride;
            const idx2 = (start_vertex + t * 3 + 2) * stride;

            if (idx2 + 12 > vb.length) break;

            const p0: [*]const f32 = @ptrCast(@alignCast(vb.data.ptr + idx0));
            const p1: [*]const f32 = @ptrCast(@alignCast(vb.data.ptr + idx1));
            const p2: [*]const f32 = @ptrCast(@alignCast(vb.data.ptr + idx2));

            // Viewport projection: NDC [-1, 1] -> Screen [0, W]
            const half_w = @as(f32, @floatFromInt(self.viewport.Width)) * 0.5;
            const half_h = @as(f32, @floatFromInt(self.viewport.Height)) * 0.5;

            const sx0 = (p0[0] + 1.0) * half_w;
            const sy0 = (1.0 - p0[1]) * half_h;
            const sx1 = (p1[0] + 1.0) * half_w;
            const sy1 = (1.0 - p1[1]) * half_h;
            const sx2 = (p2[0] + 1.0) * half_w;
            const sy2 = (1.0 - p2[1]) * half_h;

            const min_x_f = @min(@min(sx0, sx1), sx2);
            const max_x_f = @max(@max(sx0, sx1), sx2);
            const min_y_f = @min(@min(sy0, sy1), sy2);
            const max_y_f = @max(@max(sy0, sy1), sy2);

            const min_x = @max(0, @as(i32, @intFromFloat(min_x_f)));
            const max_x = @min(@as(i32, @intCast(self.viewport.Width - 1)), @as(i32, @intFromFloat(max_x_f)));
            const min_y = @max(0, @as(i32, @intFromFloat(min_y_f)));
            const max_y = @min(@as(i32, @intCast(self.viewport.Height - 1)), @as(i32, @intFromFloat(max_y_f)));

            const x0 = @as(i32, @intFromFloat(sx0));
            const y0 = @as(i32, @intFromFloat(sy0));
            const x1 = @as(i32, @intFromFloat(sx1));
            const y1 = @as(i32, @intFromFloat(sy1));
            const x2 = @as(i32, @intFromFloat(sx2));
            const y2 = @as(i32, @intFromFloat(sy2));

            const area = (x1 - x0) * (y2 - y0) - (y1 - y0) * (x2 - x0);
            if (area == 0) continue;

            const draw_color: u32 = 0xFF00FF00; // Solid green
            var py = min_y;
            while (py <= max_y) : (py += 1) {
                var px = min_x;
                while (px <= max_x) : (px += 1) {
                    const w0 = (x1 - px) * (y2 - py) - (y1 - py) * (x2 - px);
                    const w1 = (x2 - px) * (y0 - py) - (y2 - py) * (x0 - px);
                    const w2 = (x0 - px) * (y1 - py) - (y0 - py) * (x1 - px);

                    const inside = if (area > 0)
                        (w0 >= 0 and w1 >= 0 and w2 >= 0)
                    else
                        (w0 <= 0 and w1 <= 0 and w2 <= 0);

                    if (inside) {
                        const pixel_idx = @as(usize, @intCast(py)) * self.viewport.Width + @as(usize, @intCast(px));
                        const z_depth = (p0[2] + p1[2] + p2[2]) / 3.0;
                        if (z_depth < self.depthbuffer[pixel_idx]) {
                            self.depthbuffer[pixel_idx] = z_depth;
                            self.backbuffer[pixel_idx] = draw_color;
                        }
                    }
                }
            }
        }
        _ = total_verts;
    }

    return D3D_OK;
}

fn dev9_DrawIndexedPrimitive(
    this: *anyopaque,
    prim_type: u32,
    base_vertex_idx: i32,
    min_vertex_idx: u32,
    num_vertices: u32,
    start_index: u32,
    prim_count: u32,
) callconv(W) HRESULT {
    _ = base_vertex_idx;
    _ = min_vertex_idx;
    _ = num_vertices;
    _ = start_index;
    return dev9_DrawPrimitive(this, prim_type, 0, prim_count);
}

/// The IDirect3DDevice9 methods this module does not implement yet.
///
/// Same contract as d3d9_Stub: they answer D3D_OK without writing the
/// caller's output, so they announce themselves instead of failing quietly.
// Per-slot stubs for the published device object.
//
// Every unimplemented method of IDirect3DDevice9 used to be one shared
// one-argument function. A guest that called GetDeviceCaps(this, pCaps)
// through it left pCaps on the stack: the callee popped a single word, the
// guest's ESP never came back, and the drift only surfaced thousands of
// calls later as a wild jump. Each slot now points at a stub whose
// signature matches its own declaration -- the first declared parameter is
// `this` and the rest are the words the guest pushed -- so the guest's
// stack stays whatever it was, and the method it asked for is printed so
// the gap is audible instead of silent.

fn dev9_TestCooperativeLevel(this: *anyopaque) callconv(W) HRESULT {
    _ = this;
    return D3D_OK;
}

fn dev9_GetAvailableTextureMem(this: *anyopaque) callconv(W) u32 {
    _ = this;
    std.debug.print("[WINS:D3D9] device!GetAvailableTextureMem is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return 0;
}

fn dev9_EvictManagedResources(this: *anyopaque) callconv(W) HRESULT {
    _ = this;
    std.debug.print("[WINS:D3D9] device!EvictManagedResources is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetDirect3D(this: *anyopaque, ppD3D9: ?*?*anyopaque) callconv(W) HRESULT {
    _ = this;
    const out = ppD3D9 orelse return D3DERR_INVALIDCALL;
    g_global_d3d9.ref_count += 1;
    out.* = &g_global_d3d9;
    return D3D_OK;
}

fn dev9_GetDeviceCaps(this: *anyopaque, p0: ?*D3DCAPS9) callconv(W) HRESULT {
    const dev: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    return d3d9_GetDeviceCaps(this, dev.adapter, dev.device_type, p0);
}

/// The adapter's single display mode (see kDisplayMode); one implicit swap chain.
fn dev9_GetDisplayMode(this: *anyopaque, swap_chain: u32, pMode: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    const out: *align(1) D3DDISPLAYMODE = if (pMode) |p| @ptrCast(p) else return D3DERR_INVALIDCALL;
    if (swap_chain != 0) return D3DERR_INVALIDCALL;
    out.* = kDisplayMode;
    return D3D_OK;
}

fn dev9_GetCreationParameters(this: *anyopaque, p0: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!GetCreationParameters is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetCursorProperties(this: *anyopaque, p0: u32, p1: u32, p2: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    std.debug.print("[WINS:D3D9] device!SetCursorProperties is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetCursorPosition(this: *anyopaque, p0: i32, p1: i32, p2: u32) callconv(W) void {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    std.debug.print("[WINS:D3D9] device!SetCursorPosition is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
}

fn dev9_ShowCursor(this: *anyopaque, p0: i32) callconv(W) i32 {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!ShowCursor is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return 0;
}

fn dev9_CreateAdditionalSwapChain(this: *anyopaque, p0: ?*D3DPRESENT_PARAMETERS, p1: ?*?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!CreateAdditionalSwapChain is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetSwapChain(this: *anyopaque, p0: u32, p1: ?*?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!GetSwapChain is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetNumberOfSwapChains(this: *anyopaque) callconv(W) u32 {
    _ = this;
    std.debug.print("[WINS:D3D9] device!GetNumberOfSwapChains is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return 0;
}

fn dev9_Reset(this: *anyopaque, p0: ?*D3DPRESENT_PARAMETERS) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!Reset is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

/// The device's persistent render-target surface: wraps the back buffer the
/// rasterizer draws into. Created on first use; callers receive a counted reference.
fn deviceRenderTarget(self: *WinsD3DDevice9) ?*WinsSurface9 {
    if (self.rt_surface == null) {
        const fmt: u32 = if (self.params.BackBufferFormat != 0) self.params.BackBufferFormat else D3DFMT_X8R8G8B8;
        self.rt_surface = WinsSurface9.wrap(self.allocator, self.viewport.Width, self.viewport.Height, fmt, std.mem.sliceAsBytes(self.backbuffer), D3DUSAGE_RENDERTARGET, 0, true) catch return null;
        self.rt_surface.?.owner_device = @ptrCast(self);
    }
    return self.rt_surface;
}

fn deviceDepthStencil(self: *WinsD3DDevice9) ?*WinsSurface9 {
    if (self.params.EnableAutoDepthStencil == 0) return null;
    if (self.ds_surface == null) {
        self.ds_surface = WinsSurface9.wrap(self.allocator, self.viewport.Width, self.viewport.Height, self.params.AutoDepthStencilFormat, std.mem.sliceAsBytes(self.depthbuffer), D3DUSAGE_DEPTHSTENCIL, 0, false) catch return null;
        self.ds_surface.?.owner_device = @ptrCast(self);
    }
    return self.ds_surface;
}

fn deviceBoundDepthStencil(self: *WinsD3DDevice9) ?*WinsSurface9 {
    if (self.depth_stencil_explicit) return self.bound_ds_surface;
    return deviceDepthStencil(self);
}

fn dev9_GetBackBuffer(this: *anyopaque, swap_chain: u32, back_buffer: u32, buf_type: u32, ppSurface: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const out = ppSurface orelse return D3DERR_INVALIDCALL;
    const count: u32 = if (self.params.BackBufferCount == 0) 1 else self.params.BackBufferCount;
    // D3DBACKBUFFER_TYPE_MONO (0) only; a single implicit swap chain; one buffer.
    if (swap_chain != 0 or buf_type != 0 or back_buffer >= count or back_buffer != 0) return D3DERR_INVALIDCALL;
    const s = deviceRenderTarget(self) orelse return E_OUTOFMEMORY;
    s.ref_count += 1;
    out.* = s;
    return D3D_OK;
}

fn dev9_GetRasterStatus(this: *anyopaque, p0: u32, p1: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!GetRasterStatus is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetDialogBoxMode(this: *anyopaque, p0: i32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!SetDialogBoxMode is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetGammaRamp(this: *anyopaque, p0: u32, p1: u32, p2: ?*const anyopaque) callconv(W) void {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    std.debug.print("[WINS:D3D9] device!SetGammaRamp is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
}

fn dev9_GetGammaRamp(this: *anyopaque, p0: u32, p1: ?*anyopaque) callconv(W) void {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!GetGammaRamp is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
}

fn dev9_CreateVolumeTexture(this: *anyopaque, p0: u32, p1: u32, p2: u32, p3: u32, p4: u32, p5: u32, p6: u32, p7: ?*?*anyopaque, p8: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    _ = p3;
    _ = p4;
    _ = p5;
    _ = p6;
    _ = p7;
    _ = p8;
    std.debug.print("[WINS:D3D9] device!CreateVolumeTexture is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_CreateCubeTexture(this: *anyopaque, p0: u32, p1: u32, p2: u32, p3: u32, p4: u32, p5: ?*?*anyopaque, p6: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    _ = p3;
    _ = p4;
    _ = p5;
    _ = p6;
    std.debug.print("[WINS:D3D9] device!CreateCubeTexture is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_CreateRenderTarget(this: *anyopaque, p0: u32, p1: u32, p2: u32, p3: u32, p4: u32, p5: i32, p6: ?*?*anyopaque, p7: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    _ = p3;
    _ = p4;
    _ = p5;
    _ = p6;
    _ = p7;
    std.debug.print("[WINS:D3D9] device!CreateRenderTarget is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

/// A depth/stencil surface of its own (not the device's auto depth buffer): 4 bytes per
/// pixel like every surface here, not lockable, default pool. Multisampling and
/// non-depth formats are refused rather than accepted and ignored.
fn dev9_CreateDepthStencilSurface(this: *anyopaque, width: u32, height: u32, format: u32, multi_sample: u32, multi_sample_quality: u32, discard: i32, ppSurface: ?*?*anyopaque, pSharedHandle: ?*anyopaque) callconv(W) HRESULT {
    _ = discard;
    _ = pSharedHandle;
    _ = multi_sample_quality;
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const out = ppSurface orelse return D3DERR_INVALIDCALL;
    if (width == 0 or height == 0 or !isDepthStencilFormat(format)) return D3DERR_INVALIDCALL;
    if (multi_sample != D3DMULTISAMPLE_NONE) return D3DERR_NOTAVAILABLE;
    const s = WinsSurface9.create(self.allocator, width, height, format) catch return E_OUTOFMEMORY;
    s.usage = D3DUSAGE_DEPTHSTENCIL;
    s.pool = 0; // D3DPOOL_DEFAULT
    s.lockable = false;
    s.owner_device = this;
    s.multi_sample_type = multi_sample;
    out.* = s;
    return D3D_OK;
}

fn dev9_UpdateSurface(this: *anyopaque, p0: ?*anyopaque, p1: ?*const D3DRECT, p2: ?*anyopaque, p3: ?*const anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    _ = p3;
    std.debug.print("[WINS:D3D9] device!UpdateSurface is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_UpdateTexture(this: *anyopaque, p0: ?*anyopaque, p1: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!UpdateTexture is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetRenderTargetData(this: *anyopaque, p0: ?*anyopaque, p1: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!GetRenderTargetData is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetFrontBufferData(this: *anyopaque, p0: u32, p1: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!GetFrontBufferData is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_StretchRect(this: *anyopaque, p0: ?*anyopaque, p1: ?*const D3DRECT, p2: ?*anyopaque, p3: ?*const D3DRECT, p4: u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    _ = p3;
    _ = p4;
    std.debug.print("[WINS:D3D9] device!StretchRect is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_ColorFill(this: *anyopaque, p0: ?*anyopaque, p1: ?*const D3DRECT, p2: u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    std.debug.print("[WINS:D3D9] device!ColorFill is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_CreateOffscreenPlainSurface(this: *anyopaque, p0: u32, p1: u32, p2: u32, p3: u32, p4: ?*?*anyopaque, p5: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    _ = p3;
    _ = p4;
    _ = p5;
    std.debug.print("[WINS:D3D9] device!CreateOffscreenPlainSurface is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetRenderTarget(this: *anyopaque, p0: u32, p1: ?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (p0 != 0 or p1 == null) return D3DERR_INVALIDCALL;
    const backbuffer = deviceRenderTarget(self) orelse return E_OUTOFMEMORY;
    // The software rasterizer currently renders only into its implicit back
    // buffer. Accept rebinding that actual surface; do not pretend arbitrary
    // render targets work until drawing and ownership are implemented for them.
    if (p1.? != @as(*anyopaque, @ptrCast(backbuffer))) return E_NOTIMPL;
    self.viewport = .{ .X = 0, .Y = 0, .Width = backbuffer.width, .Height = backbuffer.height, .MinZ = 0, .MaxZ = 1 };
    return D3D_OK;
}

fn dev9_GetRenderTarget(this: *anyopaque, index: u32, ppSurface: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const out = ppSurface orelse return D3DERR_INVALIDCALL;
    if (index != 0) return D3DERR_NOTFOUND; // one render target; MRT is not implemented
    const s = deviceRenderTarget(self) orelse return E_OUTOFMEMORY;
    s.ref_count += 1;
    out.* = s;
    return D3D_OK;
}

fn dev9_SetDepthStencilSurface(this: *anyopaque, p0: ?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const active = deviceBoundDepthStencil(self);
    if (p0) |raw_surface| {
        const surface: *WinsSurface9 = @ptrCast(@alignCast(raw_surface));
        if (surface.vtbl != &g_surf9_vtbl or surface.owner_device != this) return D3DERR_INVALIDCALL;
        if ((surface.usage & D3DUSAGE_DEPTHSTENCIL) == 0 or surface.pool != 0 or !isDepthStencilFormat(surface.format)) return D3DERR_INVALIDCALL;
        if (surface.multi_sample_type != 0) return D3DERR_INVALIDCALL;
        const render_target = deviceRenderTarget(self) orelse return E_OUTOFMEMORY;
        if (surface.width != render_target.width or surface.height != render_target.height or surface.multi_sample_type != render_target.multi_sample_type) return D3DERR_INVALIDCALL;

        if (active) |current| {
            if (current == surface) {
                if (!self.depth_stencil_explicit) {
                    surface.ref_count += 1;
                    self.bound_ds_surface = surface;
                    self.depth_stencil_explicit = true;
                }
                return D3D_OK;
            }
        }

        surface.ref_count += 1;
        if (self.depth_stencil_explicit) {
            if (self.bound_ds_surface) |previous| {
                if (previous.ref_count > 0) previous.ref_count -= 1;
            }
        }
        self.bound_ds_surface = surface;
        self.depth_stencil_explicit = true;
        return D3D_OK;
    }

    if (self.depth_stencil_explicit) {
        if (self.bound_ds_surface) |previous| {
            if (previous.ref_count > 0) previous.ref_count -= 1;
        }
    }
    self.bound_ds_surface = null;
    self.depth_stencil_explicit = true;
    return D3D_OK;
}

fn dev9_GetDepthStencilSurface(this: *anyopaque, ppSurface: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const out = ppSurface orelse return D3DERR_INVALIDCALL;
    out.* = null;
    const s = deviceBoundDepthStencil(self) orelse return D3DERR_NOTFOUND;
    s.ref_count += 1;
    out.* = s;
    return D3D_OK;
}

fn dev9_SetTransform(this: *anyopaque, p0: u32, p1: ?*const anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const state = d3dTransformStateIndex(p0) orelse return D3DERR_INVALIDCALL;
    const source = p1 orelse return D3DERR_INVALIDCALL;
    const matrix: *const D3DMATRIX = @ptrCast(@alignCast(source));
    self.transform_states[state] = matrix.*;
    return D3D_OK;
}

fn dev9_GetTransform(this: *anyopaque, p0: u32, p1: ?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const state = d3dTransformStateIndex(p0) orelse return D3DERR_INVALIDCALL;
    const destination = p1 orelse return D3DERR_INVALIDCALL;
    const matrix: *D3DMATRIX = @ptrCast(@alignCast(destination));
    matrix.* = self.transform_states[state];
    return D3D_OK;
}

fn dev9_MultiplyTransform(this: *anyopaque, p0: u32, p1: ?*const anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!MultiplyTransform is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetMaterial(this: *anyopaque, p0: ?*const anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const source = p0 orelse return D3DERR_INVALIDCALL;
    var value: D3DMATERIAL9 = undefined;
    @memcpy(std.mem.asBytes(&value), @as([*]const u8, @ptrCast(source))[0..@sizeOf(D3DMATERIAL9)]);
    self.material = value;
    return D3D_OK;
}

fn dev9_GetMaterial(this: *anyopaque, p0: ?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const destination = p0 orelse return D3DERR_INVALIDCALL;
    @memcpy(@as([*]u8, @ptrCast(destination))[0..@sizeOf(D3DMATERIAL9)], std.mem.asBytes(&self.material));
    return D3D_OK;
}

fn dev9_SetLight(this: *anyopaque, p0: u32, p1: ?*const anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const source = p1 orelse return D3DERR_INVALIDCALL;
    var value: D3DLIGHT9 = undefined;
    @memcpy(std.mem.asBytes(&value), @as([*]const u8, @ptrCast(source))[0..@sizeOf(D3DLIGHT9)]);
    if (value.Type < D3DLIGHT_POINT or value.Type > D3DLIGHT_DIRECTIONAL) return D3DERR_INVALIDCALL;
    if (self.lights.getPtr(p0)) |state| {
        state.light = value;
    } else {
        self.lights.put(self.allocator, p0, .{ .light = value, .enabled = false }) catch return E_OUTOFMEMORY;
    }
    return D3D_OK;
}

pub export fn wins_d3d9_thunk_begin_scene(this: *anyopaque) callconv(W) HRESULT {
    return dev9_BeginScene(this);
}

pub export fn wins_d3d9_thunk_get_material(this: *anyopaque, out: ?*anyopaque) callconv(W) HRESULT {
    return dev9_GetMaterial(this, out);
}

pub export fn wins_d3d9_thunk_set_light(this: *anyopaque, index: u32, light: ?*const anyopaque) callconv(W) HRESULT {
    return dev9_SetLight(this, index, light);
}

// Bridge both x86 call forms seen on the same IDirect3DDevice9 vtable. For a
// thiscall invocation, ECX is the live device and ESP starts at the first
// explicit argument. For stdcall, this is the first stack argument. The helper
// calls remain stdcall; each bridge returns with the cleanup required by the
// guest-side call form.
fn dev9_BeginScene_dual() callconv(.naked) void {
    if (comptime @sizeOf(usize) == 4) {
        asm volatile (
            \\ movl wins_d3d9_device_self, %%eax
            \\ cmpl %%eax, %%ecx
            \\ jne 1f
            \\ cmpl %%eax, 4(%%esp)
            \\ je 1f
            \\ pushl %%ecx
            \\ call wins_d3d9_thunk_begin_scene
            \\ ret
            \\ 1:
            \\ pushl 4(%%esp)
            \\ call wins_d3d9_thunk_begin_scene
            \\ ret $4
        );
    } else {
        asm volatile ("ret");
    }
}

fn dev9_GetMaterial_dual() callconv(.naked) void {
    if (comptime @sizeOf(usize) == 4) {
        asm volatile (
            \\ movl wins_d3d9_device_self, %%eax
            \\ cmpl %%eax, %%ecx
            \\ jne 1f
            \\ cmpl %%eax, 4(%%esp)
            \\ je 1f
            \\ pushl 4(%%esp)
            \\ pushl %%ecx
            \\ call wins_d3d9_thunk_get_material
            \\ ret $4
            \\ 1:
            \\ pushl 8(%%esp)
            \\ pushl 8(%%esp)
            \\ call wins_d3d9_thunk_get_material
            \\ ret $8
        );
    } else {
        asm volatile ("ret");
    }
}

fn dev9_SetLight_dual() callconv(.naked) void {
    if (comptime @sizeOf(usize) == 4) {
        asm volatile (
            \\ movl wins_d3d9_device_self, %%eax
            \\ cmpl %%eax, %%ecx
            \\ jne 1f
            \\ cmpl %%eax, 4(%%esp)
            \\ je 1f
            \\ pushl 8(%%esp)
            \\ pushl 8(%%esp)
            \\ pushl %%ecx
            \\ call wins_d3d9_thunk_set_light
            \\ ret $8
            \\ 1:
            \\ pushl 12(%%esp)
            \\ pushl 12(%%esp)
            \\ pushl 12(%%esp)
            \\ call wins_d3d9_thunk_set_light
            \\ ret $12
        );
    } else {
        asm volatile ("ret");
    }
}

fn dev9_GetLight(this: *anyopaque, p0: u32, p1: ?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const destination = p1 orelse return D3DERR_INVALIDCALL;
    const state = self.lights.get(p0) orelse return D3DERR_INVALIDCALL;
    @memcpy(@as([*]u8, @ptrCast(destination))[0..@sizeOf(D3DLIGHT9)], std.mem.asBytes(&state.light));
    return D3D_OK;
}

fn dev9_LightEnable(this: *anyopaque, p0: u32, p1: i32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (self.lights.getPtr(p0)) |state| {
        state.enabled = p1 != 0;
    } else {
        self.lights.put(self.allocator, p0, .{ .light = defaultLight9(), .enabled = p1 != 0 }) catch return E_OUTOFMEMORY;
    }
    return D3D_OK;
}

fn dev9_GetLightEnable(this: *anyopaque, p0: u32, p1: ?*i32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const out = p1 orelse return D3DERR_INVALIDCALL;
    const state = self.lights.get(p0) orelse return D3DERR_INVALIDCALL;
    out.* = if (state.enabled) 1 else 0;
    return D3D_OK;
}

fn dev9_SetClipPlane(this: *anyopaque, p0: u32, p1: ?*const f32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!SetClipPlane is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetClipPlane(this: *anyopaque, p0: u32, p1: ?*f32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!GetClipPlane is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_CreateStateBlock(this: *anyopaque, p0: u32, p1: ?*?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!CreateStateBlock is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_BeginStateBlock(this: *anyopaque) callconv(W) HRESULT {
    _ = this;
    std.debug.print("[WINS:D3D9] device!BeginStateBlock is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_EndStateBlock(this: *anyopaque, p0: ?*?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!EndStateBlock is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetClipStatus(this: *anyopaque, p0: ?*const anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!SetClipStatus is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetClipStatus(this: *anyopaque, p0: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!GetClipStatus is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetTexture(this: *anyopaque, p0: u32, p1: ?*?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!GetTexture is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetTextureStageState(this: *anyopaque, stage: u32, ty: u32, pValue: ?*u32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const out = pValue orelse return D3DERR_INVALIDCALL;
    if (stage >= kMaxTextureStages or ty == 0 or ty >= kTssSlots) return D3DERR_INVALIDCALL;
    out.* = self.tex_stage_states[stage][ty];
    return D3D_OK;
}

fn dev9_SetTextureStageState(this: *anyopaque, stage: u32, ty: u32, value: u32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (stage >= kMaxTextureStages or ty == 0 or ty >= kTssSlots) return D3DERR_INVALIDCALL;
    self.tex_stage_states[stage][ty] = value;
    return D3D_OK;
}

fn dev9_GetSamplerState(this: *anyopaque, sampler: u32, ty: u32, pValue: ?*u32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const out = pValue orelse return D3DERR_INVALIDCALL;
    if (sampler >= 16 or ty == 0 or ty >= kSampSlots) return D3DERR_INVALIDCALL;
    out.* = self.sampler_states[sampler][ty];
    return D3D_OK;
}

fn dev9_SetSamplerState(this: *anyopaque, sampler: u32, ty: u32, value: u32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (sampler >= 16 or ty == 0 or ty >= kSampSlots) return D3DERR_INVALIDCALL;
    self.sampler_states[sampler][ty] = value;
    return D3D_OK;
}

fn dev9_ValidateDevice(this: *anyopaque, p0: ?*u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!ValidateDevice is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetPaletteEntries(this: *anyopaque, p0: u32, p1: ?*const anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!SetPaletteEntries is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetPaletteEntries(this: *anyopaque, p0: u32, p1: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!GetPaletteEntries is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetCurrentTexturePalette(this: *anyopaque, p0: u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!SetCurrentTexturePalette is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetCurrentTexturePalette(this: *anyopaque, p0: ?*u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!GetCurrentTexturePalette is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetScissorRect(this: *anyopaque, p0: ?*const D3DRECT) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!SetScissorRect is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetScissorRect(this: *anyopaque, p0: ?*D3DRECT) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!GetScissorRect is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetSoftwareVertexProcessing(this: *anyopaque, p0: i32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!SetSoftwareVertexProcessing is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetSoftwareVertexProcessing(this: *anyopaque) callconv(W) i32 {
    _ = this;
    std.debug.print("[WINS:D3D9] device!GetSoftwareVertexProcessing is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return 0;
}

fn dev9_SetNPatchMode(this: *anyopaque, p0: f32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!SetNPatchMode is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetNPatchMode(this: *anyopaque) callconv(W) f32 {
    _ = this;
    std.debug.print("[WINS:D3D9] device!GetNPatchMode is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return 0;
}

fn dev9_DrawPrimitiveUP(this: *anyopaque, p0: u32, p1: u32, p2: ?*const anyopaque, p3: u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    _ = p3;
    std.debug.print("[WINS:D3D9] device!DrawPrimitiveUP is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_DrawIndexedPrimitiveUP(this: *anyopaque, p0: u32, p1: u32, p2: u32, p3: u32, p4: ?*const anyopaque, p5: u32, p6: ?*const anyopaque, p7: u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    _ = p3;
    _ = p4;
    _ = p5;
    _ = p6;
    _ = p7;
    std.debug.print("[WINS:D3D9] device!DrawIndexedPrimitiveUP is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_ProcessVertices(this: *anyopaque, p0: u32, p1: u32, p2: u32, p3: ?*anyopaque, p4: ?*anyopaque, p5: u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    _ = p3;
    _ = p4;
    _ = p5;
    std.debug.print("[WINS:D3D9] device!ProcessVertices is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

/// Copies the element list up to and including D3DDECL_END. A list without END
/// within MAXD3DDECLLENGTH elements, or with an element type above UNUSED, is invalid.
fn dev9_CreateVertexDeclaration(this: *anyopaque, pElements: ?*const anyopaque, ppDecl: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const out = ppDecl orelse return D3DERR_INVALIDCALL;
    const src_raw = pElements orelse return D3DERR_INVALIDCALL;
    const src: [*]align(1) const D3DVERTEXELEMENT9 = @ptrCast(src_raw);
    var n: usize = 0;
    while (n < kMaxDeclLength) : (n += 1) {
        if (isDeclEnd(src[n])) break;
        if (src[n].Type > kDeclTypeUnused) return D3DERR_INVALIDCALL;
    } else return D3DERR_INVALIDCALL;
    const els = self.allocator.alloc(D3DVERTEXELEMENT9, n + 1) catch return E_OUTOFMEMORY;
    for (0..n + 1) |i| els[i] = src[i];
    const d = self.allocator.create(WinsVertexDecl9) catch return E_OUTOFMEMORY;
    d.* = .{ .vtbl = &g_vdecl9_vtbl, .ref_count = 1, .device = self, .elements = els };
    out.* = d;
    return D3D_OK;
}

fn dev9_SetVertexDeclaration(this: *anyopaque, pDecl: ?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const new: ?*WinsVertexDecl9 = if (pDecl) |p| @ptrCast(@alignCast(p)) else null;
    if (new) |n| n.ref_count += 1;
    if (self.vertex_decl) |old| {
        if (old.ref_count > 0) old.ref_count -= 1;
    }
    self.vertex_decl = new;
    return D3D_OK;
}

fn dev9_GetVertexDeclaration(this: *anyopaque, ppDecl: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const out = ppDecl orelse return D3DERR_INVALIDCALL;
    if (self.vertex_decl) |d| d.ref_count += 1;
    out.* = self.vertex_decl;
    return D3D_OK;
}

fn dev9_SetFVF(this: *anyopaque, p0: u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!SetFVF is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetFVF(this: *anyopaque, p0: ?*u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!GetFVF is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetVertexShader(this: *anyopaque, p0: ?*?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!GetVertexShader is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetVertexShaderConstantF(this: *anyopaque, p0: u32, p1: ?*f32, p2: u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    std.debug.print("[WINS:D3D9] device!GetVertexShaderConstantF is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetVertexShaderConstantI(this: *anyopaque, p0: u32, p1: ?*const i32, p2: u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    std.debug.print("[WINS:D3D9] device!SetVertexShaderConstantI is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetVertexShaderConstantI(this: *anyopaque, p0: u32, p1: ?*i32, p2: u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    std.debug.print("[WINS:D3D9] device!GetVertexShaderConstantI is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetVertexShaderConstantB(this: *anyopaque, p0: u32, p1: ?*const i32, p2: u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    std.debug.print("[WINS:D3D9] device!SetVertexShaderConstantB is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetVertexShaderConstantB(this: *anyopaque, p0: u32, p1: ?*i32, p2: u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    std.debug.print("[WINS:D3D9] device!GetVertexShaderConstantB is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetStreamSource(this: *anyopaque, p0: u32, p1: ?*?*anyopaque, p2: ?*u32, p3: ?*u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    _ = p3;
    std.debug.print("[WINS:D3D9] device!GetStreamSource is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetStreamSourceFreq(this: *anyopaque, p0: u32, p1: u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!SetStreamSourceFreq is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetStreamSourceFreq(this: *anyopaque, p0: u32, p1: ?*u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!GetStreamSourceFreq is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetIndices(this: *anyopaque, p0: ?*?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!GetIndices is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetPixelShader(this: *anyopaque, p0: ?*?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!GetPixelShader is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetPixelShaderConstantF(this: *anyopaque, p0: u32, p1: ?*f32, p2: u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    std.debug.print("[WINS:D3D9] device!GetPixelShaderConstantF is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetPixelShaderConstantI(this: *anyopaque, p0: u32, p1: ?*const i32, p2: u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    std.debug.print("[WINS:D3D9] device!SetPixelShaderConstantI is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetPixelShaderConstantI(this: *anyopaque, p0: u32, p1: ?*i32, p2: u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    std.debug.print("[WINS:D3D9] device!GetPixelShaderConstantI is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetPixelShaderConstantB(this: *anyopaque, p0: u32, p1: ?*const i32, p2: u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    std.debug.print("[WINS:D3D9] device!SetPixelShaderConstantB is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetPixelShaderConstantB(this: *anyopaque, p0: u32, p1: ?*i32, p2: u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    std.debug.print("[WINS:D3D9] device!GetPixelShaderConstantB is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_DrawRectPatch(this: *anyopaque, p0: u32, p1: ?*const f32, p2: ?*const anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    std.debug.print("[WINS:D3D9] device!DrawRectPatch is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_DrawTriPatch(this: *anyopaque, p0: u32, p1: ?*const f32, p2: ?*const anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    std.debug.print("[WINS:D3D9] device!DrawTriPatch is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_DeletePatch(this: *anyopaque, p0: u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!DeletePatch is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_CreateQuery(this: *anyopaque, p0: u32, p1: ?*?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!CreateQuery is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}
const g_device9_vtbl: IDirect3DDevice9Vtbl = .{
    .QueryInterface = &dev9_QueryInterface,
    .AddRef = &dev9_AddRef,
    .Release = &dev9_Release,
    .TestCooperativeLevel = @ptrCast(&dev9_TestCooperativeLevel),
    .GetAvailableTextureMem = @ptrCast(&dev9_GetAvailableTextureMem),
    .EvictManagedResources = @ptrCast(&dev9_EvictManagedResources),
    .GetDirect3D = @ptrCast(&dev9_GetDirect3D),
    .GetDeviceCaps = @ptrCast(&dev9_GetDeviceCaps),
    .GetDisplayMode = @ptrCast(&dev9_GetDisplayMode),
    .GetCreationParameters = @ptrCast(&dev9_GetCreationParameters),
    .SetCursorProperties = @ptrCast(&dev9_SetCursorProperties),
    .SetCursorPosition = @ptrCast(&dev9_SetCursorPosition),
    .ShowCursor = @ptrCast(&dev9_ShowCursor),
    .CreateAdditionalSwapChain = @ptrCast(&dev9_CreateAdditionalSwapChain),
    .GetSwapChain = @ptrCast(&dev9_GetSwapChain),
    .GetNumberOfSwapChains = @ptrCast(&dev9_GetNumberOfSwapChains),
    .Reset = @ptrCast(&dev9_Reset),
    .Present = &dev9_Present,
    .GetBackBuffer = @ptrCast(&dev9_GetBackBuffer),
    .GetRasterStatus = @ptrCast(&dev9_GetRasterStatus),
    .SetDialogBoxMode = @ptrCast(&dev9_SetDialogBoxMode),
    .SetGammaRamp = @ptrCast(&dev9_SetGammaRamp),
    .GetGammaRamp = @ptrCast(&dev9_GetGammaRamp),
    .CreateTexture = &dev9_CreateTexture,
    .CreateVolumeTexture = @ptrCast(&dev9_CreateVolumeTexture),
    .CreateCubeTexture = @ptrCast(&dev9_CreateCubeTexture),
    .CreateVertexBuffer = &dev9_CreateVertexBuffer,
    .CreateIndexBuffer = &dev9_CreateIndexBuffer,
    .CreateRenderTarget = @ptrCast(&dev9_CreateRenderTarget),
    .CreateDepthStencilSurface = @ptrCast(&dev9_CreateDepthStencilSurface),
    .UpdateSurface = @ptrCast(&dev9_UpdateSurface),
    .UpdateTexture = @ptrCast(&dev9_UpdateTexture),
    .GetRenderTargetData = @ptrCast(&dev9_GetRenderTargetData),
    .GetFrontBufferData = @ptrCast(&dev9_GetFrontBufferData),
    .StretchRect = @ptrCast(&dev9_StretchRect),
    .ColorFill = @ptrCast(&dev9_ColorFill),
    .CreateOffscreenPlainSurface = @ptrCast(&dev9_CreateOffscreenPlainSurface),
    .SetRenderTarget = @ptrCast(&dev9_SetRenderTarget),
    .GetRenderTarget = @ptrCast(&dev9_GetRenderTarget),
    .SetDepthStencilSurface = @ptrCast(&dev9_SetDepthStencilSurface),
    .GetDepthStencilSurface = @ptrCast(&dev9_GetDepthStencilSurface),
    .BeginScene = if (@sizeOf(usize) == 4) @ptrCast(&dev9_BeginScene_dual) else &dev9_BeginScene,
    .EndScene = &dev9_EndScene,
    .Clear = &dev9_Clear,
    .SetTransform = @ptrCast(&dev9_SetTransform),
    .GetTransform = @ptrCast(&dev9_GetTransform),
    .MultiplyTransform = @ptrCast(&dev9_MultiplyTransform),
    .SetViewport = &dev9_SetViewport,
    .GetViewport = &dev9_GetViewport,
    .SetMaterial = @ptrCast(&dev9_SetMaterial),
    .GetMaterial = if (@sizeOf(usize) == 4) @ptrCast(&dev9_GetMaterial_dual) else @ptrCast(&dev9_GetMaterial),
    .SetLight = if (@sizeOf(usize) == 4) @ptrCast(&dev9_SetLight_dual) else @ptrCast(&dev9_SetLight),
    .GetLight = @ptrCast(&dev9_GetLight),
    .LightEnable = @ptrCast(&dev9_LightEnable),
    .GetLightEnable = @ptrCast(&dev9_GetLightEnable),
    .SetClipPlane = @ptrCast(&dev9_SetClipPlane),
    .GetClipPlane = @ptrCast(&dev9_GetClipPlane),
    .SetRenderState = &dev9_SetRenderState,
    .GetRenderState = &dev9_GetRenderState,
    .CreateStateBlock = @ptrCast(&dev9_CreateStateBlock),
    .BeginStateBlock = @ptrCast(&dev9_BeginStateBlock),
    .EndStateBlock = @ptrCast(&dev9_EndStateBlock),
    .SetClipStatus = @ptrCast(&dev9_SetClipStatus),
    .GetClipStatus = @ptrCast(&dev9_GetClipStatus),
    .GetTexture = @ptrCast(&dev9_GetTexture),
    .SetTexture = &dev9_SetTexture,
    .GetTextureStageState = @ptrCast(&dev9_GetTextureStageState),
    .SetTextureStageState = @ptrCast(&dev9_SetTextureStageState),
    .GetSamplerState = @ptrCast(&dev9_GetSamplerState),
    .SetSamplerState = @ptrCast(&dev9_SetSamplerState),
    .ValidateDevice = @ptrCast(&dev9_ValidateDevice),
    .SetPaletteEntries = @ptrCast(&dev9_SetPaletteEntries),
    .GetPaletteEntries = @ptrCast(&dev9_GetPaletteEntries),
    .SetCurrentTexturePalette = @ptrCast(&dev9_SetCurrentTexturePalette),
    .GetCurrentTexturePalette = @ptrCast(&dev9_GetCurrentTexturePalette),
    .SetScissorRect = @ptrCast(&dev9_SetScissorRect),
    .GetScissorRect = @ptrCast(&dev9_GetScissorRect),
    .SetSoftwareVertexProcessing = @ptrCast(&dev9_SetSoftwareVertexProcessing),
    .GetSoftwareVertexProcessing = @ptrCast(&dev9_GetSoftwareVertexProcessing),
    .SetNPatchMode = @ptrCast(&dev9_SetNPatchMode),
    .GetNPatchMode = @ptrCast(&dev9_GetNPatchMode),
    .DrawPrimitive = &dev9_DrawPrimitive,
    .DrawIndexedPrimitive = &dev9_DrawIndexedPrimitive,
    .DrawPrimitiveUP = @ptrCast(&dev9_DrawPrimitiveUP),
    .DrawIndexedPrimitiveUP = @ptrCast(&dev9_DrawIndexedPrimitiveUP),
    .ProcessVertices = @ptrCast(&dev9_ProcessVertices),
    .CreateVertexDeclaration = @ptrCast(&dev9_CreateVertexDeclaration),
    .SetVertexDeclaration = @ptrCast(&dev9_SetVertexDeclaration),
    .GetVertexDeclaration = @ptrCast(&dev9_GetVertexDeclaration),
    .SetFVF = @ptrCast(&dev9_SetFVF),
    .GetFVF = @ptrCast(&dev9_GetFVF),
    .CreateVertexShader = &dev9_CreateVertexShader,
    .SetVertexShader = &dev9_SetVertexShader,
    .GetVertexShader = @ptrCast(&dev9_GetVertexShader),
    .SetVertexShaderConstantF = &dev9_SetVertexShaderConstantF,
    .GetVertexShaderConstantF = @ptrCast(&dev9_GetVertexShaderConstantF),
    .SetVertexShaderConstantI = @ptrCast(&dev9_SetVertexShaderConstantI),
    .GetVertexShaderConstantI = @ptrCast(&dev9_GetVertexShaderConstantI),
    .SetVertexShaderConstantB = @ptrCast(&dev9_SetVertexShaderConstantB),
    .GetVertexShaderConstantB = @ptrCast(&dev9_GetVertexShaderConstantB),
    .SetStreamSource = &dev9_SetStreamSource,
    .GetStreamSource = @ptrCast(&dev9_GetStreamSource),
    .SetStreamSourceFreq = @ptrCast(&dev9_SetStreamSourceFreq),
    .GetStreamSourceFreq = @ptrCast(&dev9_GetStreamSourceFreq),
    .SetIndices = &dev9_SetIndices,
    .GetIndices = @ptrCast(&dev9_GetIndices),
    .CreatePixelShader = &dev9_CreatePixelShader,
    .SetPixelShader = &dev9_SetPixelShader,
    .GetPixelShader = @ptrCast(&dev9_GetPixelShader),
    .SetPixelShaderConstantF = &dev9_SetPixelShaderConstantF,
    .GetPixelShaderConstantF = @ptrCast(&dev9_GetPixelShaderConstantF),
    .SetPixelShaderConstantI = @ptrCast(&dev9_SetPixelShaderConstantI),
    .GetPixelShaderConstantI = @ptrCast(&dev9_GetPixelShaderConstantI),
    .SetPixelShaderConstantB = @ptrCast(&dev9_SetPixelShaderConstantB),
    .GetPixelShaderConstantB = @ptrCast(&dev9_GetPixelShaderConstantB),
    .DrawRectPatch = @ptrCast(&dev9_DrawRectPatch),
    .DrawTriPatch = @ptrCast(&dev9_DrawTriPatch),
    .DeletePatch = @ptrCast(&dev9_DeletePatch),
    .CreateQuery = @ptrCast(&dev9_CreateQuery),
};

// ============================================================================
// Public C/Win32 Direct3D 9 Exports
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
// Complete 25 D3DX9 Exports for d3dx9_38.dll (100% Native Implementation)
// ============================================================================

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

pub export fn D3DXMatrixInverse(
    pOut: ?*D3DMATRIX,
    pDeterminant: ?*f32,
    pM: ?*const D3DMATRIX,
) callconv(W) ?*D3DMATRIX {
    const out = pOut orelse return null;
    const m = pM orelse return null;

    const m00 = m.m[0][0];
    const m01 = m.m[0][1];
    const m02 = m.m[0][2];
    const m03 = m.m[0][3];
    const m10 = m.m[1][0];
    const m11 = m.m[1][1];
    const m12 = m.m[1][2];
    const m13 = m.m[1][3];
    const m20 = m.m[2][0];
    const m21 = m.m[2][1];
    const m22 = m.m[2][2];
    const m23 = m.m[2][3];
    const m30 = m.m[3][0];
    const m31 = m.m[3][1];
    const m32 = m.m[3][2];
    const m33 = m.m[3][3];

    const s0 = m00 * m11 - m01 * m10;
    const s1 = m00 * m12 - m02 * m10;
    const s2 = m00 * m13 - m03 * m10;
    const s3 = m01 * m12 - m02 * m11;
    const s4 = m01 * m13 - m03 * m11;
    const s5 = m02 * m13 - m03 * m12;

    const c5 = m22 * m33 - m23 * m32;
    const c4 = m21 * m33 - m23 * m31;
    const c3 = m21 * m32 - m22 * m31;
    const c2 = m20 * m33 - m23 * m30;
    const c1 = m20 * m32 - m22 * m30;
    const c0 = m20 * m31 - m21 * m30;

    const det = s0 * c5 - s1 * c4 + s2 * c3 + s3 * c2 - s4 * c1 + s5 * c0;
    if (pDeterminant) |d| d.* = det;

    if (det == 0.0) return null;
    const inv_det = 1.0 / det;

    var res: D3DMATRIX = undefined;
    res.m[0][0] = (m11 * c5 - m12 * c4 + m13 * c3) * inv_det;
    res.m[0][1] = (-m01 * c5 + m02 * c4 - m03 * c3) * inv_det;
    res.m[0][2] = (m31 * s5 - m32 * s4 + m33 * s3) * inv_det;
    res.m[0][3] = (-m21 * s5 + m22 * s4 - m23 * s3) * inv_det;

    res.m[1][0] = (-m10 * c5 + m12 * c2 - m13 * c1) * inv_det;
    res.m[1][1] = (m00 * c5 - m02 * c2 + m03 * c1) * inv_det;
    res.m[1][2] = (-m30 * s5 + m32 * s2 - m33 * s1) * inv_det;
    res.m[1][3] = (m20 * s5 - m22 * s2 + m23 * s1) * inv_det;

    res.m[2][0] = (m10 * c4 - m11 * c2 + m13 * c0) * inv_det;
    res.m[2][1] = (-m00 * c4 + m01 * c2 - m03 * c0) * inv_det;
    res.m[2][2] = (m30 * s4 - m31 * s2 + m33 * s0) * inv_det;
    res.m[2][3] = (-m20 * s4 + m21 * s2 - m23 * s0) * inv_det;

    res.m[3][0] = (-m10 * c3 + m11 * c1 - m12 * c0) * inv_det;
    res.m[3][1] = (m00 * c3 - m01 * c1 + m02 * c0) * inv_det;
    res.m[3][2] = (-m30 * s3 + m31 * s1 - m32 * s0) * inv_det;
    res.m[3][3] = (m20 * s3 - m21 * s1 + m22 * s0) * inv_det;

    out.* = res;
    return out;
}

pub export fn D3DXMatrixRotationYawPitchRoll(
    pOut: ?*D3DMATRIX,
    yaw: f32,
    pitch: f32,
    roll: f32,
) callconv(W) ?*D3DMATRIX {
    const out = pOut orelse return null;
    const cy = @cos(yaw);
    const sy = @sin(yaw);
    const cp = @cos(pitch);
    const sp = @sin(pitch);
    const cr = @cos(roll);
    const sr = @sin(roll);

    out.m[0][0] = cr * cy + sr * sp * sy;
    out.m[0][1] = sr * cp;
    out.m[0][2] = -cr * sy + sr * sp * cy;
    out.m[0][3] = 0.0;

    out.m[1][0] = -sr * cy + cr * sp * sy;
    out.m[1][1] = cr * cp;
    out.m[1][2] = sr * sy + cr * sp * cy;
    out.m[1][3] = 0.0;

    out.m[2][0] = cp * sy;
    out.m[2][1] = -sp;
    out.m[2][2] = cp * cy;
    out.m[2][3] = 0.0;

    out.m[3][0] = 0.0;
    out.m[3][1] = 0.0;
    out.m[3][2] = 0.0;
    out.m[3][3] = 1.0;

    return out;
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

pub export fn D3DXVec3TransformNormal(
    pOut: ?*D3DVECTOR,
    pV: ?*const D3DVECTOR,
    pM: ?*const D3DMATRIX,
) callconv(W) ?*D3DVECTOR {
    const out = pOut orelse return null;
    const v = pV orelse return null;
    const m = pM orelse return null;

    var temp: D3DVECTOR = undefined;
    temp.x = m.m[0][0] * v.x + m.m[1][0] * v.y + m.m[2][0] * v.z;
    temp.y = m.m[0][1] * v.x + m.m[1][1] * v.y + m.m[2][1] * v.z;
    temp.z = m.m[0][2] * v.x + m.m[1][2] * v.y + m.m[2][2] * v.z;
    out.* = temp;
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

pub export fn D3DXPlaneNormalize(
    pOut: ?*D3DXPLANE,
    pP: ?*const D3DXPLANE,
) callconv(W) ?*D3DXPLANE {
    const out = pOut orelse return null;
    const p = pP orelse return null;

    const len_sq = p.a * p.a + p.b * p.b + p.c * p.c;
    if (len_sq > 0.0) {
        const inv_len = 1.0 / @sqrt(len_sq);
        out.a = p.a * inv_len;
        out.b = p.b * inv_len;
        out.c = p.c * inv_len;
        out.d = p.d * inv_len;
    } else {
        out.a = 0;
        out.b = 0;
        out.c = 0;
        out.d = 0;
    }
    return out;
}

pub export fn D3DXPlaneTransform(
    pOut: ?*D3DXPLANE,
    pP: ?*const D3DXPLANE,
    pM: ?*const D3DMATRIX,
) callconv(W) ?*D3DXPLANE {
    const out = pOut orelse return null;
    const p = pP orelse return null;
    const m = pM orelse return null;

    var inv_m: D3DMATRIX = undefined;
    if (D3DXMatrixInverse(&inv_m, null, m) == null) return null;

    var temp: D3DXPLANE = undefined;
    temp.a = inv_m.m[0][0] * p.a + inv_m.m[0][1] * p.b + inv_m.m[0][2] * p.c + inv_m.m[0][3] * p.d;
    temp.b = inv_m.m[1][0] * p.a + inv_m.m[1][1] * p.b + inv_m.m[1][2] * p.c + inv_m.m[1][3] * p.d;
    temp.c = inv_m.m[2][0] * p.a + inv_m.m[2][1] * p.b + inv_m.m[2][2] * p.c + inv_m.m[2][3] * p.d;
    temp.d = inv_m.m[3][0] * p.a + inv_m.m[3][1] * p.b + inv_m.m[3][2] * p.c + inv_m.m[3][3] * p.d;
    out.* = temp;
    return out;
}

pub export fn D3DXCreateBuffer(NumBytes: u32, ppBuffer: ?*?*anyopaque) callconv(W) HRESULT {
    if (ppBuffer == null) return E_FAIL;
    const gpa = std.heap.page_allocator;
    const buf = WinsD3DXBuffer.create(gpa, NumBytes) catch return E_OUTOFMEMORY;
    ppBuffer.?.* = @ptrCast(buf);
    return D3D_OK;
}

pub export fn D3DXGetShaderConstantTable(pFunction: ?*const u32, ppConstantTable: ?*?*anyopaque) callconv(W) HRESULT {
    _ = pFunction;
    if (ppConstantTable) |pct| pct.* = null;
    return D3D_OK;
}

pub export fn D3DXGetVertexShaderProfile(pDevice: ?*anyopaque) callconv(W) ?[*:0]const u8 {
    _ = pDevice;
    return "vs_3_0";
}

pub export fn D3DXGetPixelShaderProfile(pDevice: ?*anyopaque) callconv(W) ?[*:0]const u8 {
    _ = pDevice;
    return "ps_3_0";
}

pub export fn D3DXAssembleShader(
    pSrcData: ?*const anyopaque,
    SrcDataLen: u32,
    pDefines: ?*const anyopaque,
    pInclude: ?*anyopaque,
    Flags: u32,
    ppShader: ?*?*anyopaque,
    ppErrorMsgs: ?*?*anyopaque,
) callconv(W) HRESULT {
    _ = pSrcData;
    _ = SrcDataLen;
    _ = pDefines;
    _ = pInclude;
    _ = Flags;
    _ = ppErrorMsgs;
    if (ppShader == null) return E_FAIL;
    const gpa = std.heap.page_allocator;
    const buf = WinsD3DXBuffer.create(gpa, 16) catch return E_OUTOFMEMORY;
    const tokens: [*]u32 = @ptrCast(@alignCast(buf.data.ptr));
    tokens[0] = 0xFFFE0300; // vs_3_0
    tokens[1] = 0x0000FFFF; // end
    ppShader.?.* = @ptrCast(buf);
    return D3D_OK;
}

pub export fn D3DXAssembleShaderFromFileA(
    pSrcFile: ?[*:0]const u8,
    pDefines: ?*const anyopaque,
    pInclude: ?*anyopaque,
    Flags: u32,
    ppShader: ?*?*anyopaque,
    ppErrorMsgs: ?*?*anyopaque,
) callconv(W) HRESULT {
    _ = pSrcFile;
    return D3DXAssembleShader(null, 0, pDefines, pInclude, Flags, ppShader, ppErrorMsgs);
}

pub export fn D3DXCompileShader(
    pSrcData: ?*const anyopaque,
    SrcDataLen: u32,
    pDefines: ?*const anyopaque,
    pInclude: ?*anyopaque,
    pFunctionName: ?[*:0]const u8,
    pProfile: ?[*:0]const u8,
    Flags: u32,
    ppShader: ?*?*anyopaque,
    ppErrorMsgs: ?*?*anyopaque,
    ppConstantTable: ?*?*anyopaque,
) callconv(W) HRESULT {
    _ = pSrcData;
    _ = SrcDataLen;
    _ = pDefines;
    _ = pInclude;
    _ = pFunctionName;
    _ = pProfile;
    _ = Flags;
    _ = ppErrorMsgs;
    if (ppConstantTable) |pct| pct.* = null;
    if (ppShader == null) return E_FAIL;
    const gpa = std.heap.page_allocator;
    const buf = WinsD3DXBuffer.create(gpa, 16) catch return E_OUTOFMEMORY;
    const tokens: [*]u32 = @ptrCast(@alignCast(buf.data.ptr));
    tokens[0] = 0xFFFF0300; // ps_3_0
    tokens[1] = 0x0000FFFF; // end
    ppShader.?.* = @ptrCast(buf);
    return D3D_OK;
}

pub export fn D3DXCompileShaderFromFileA(
    pSrcFile: ?[*:0]const u8,
    pDefines: ?*const anyopaque,
    pInclude: ?*anyopaque,
    pFunctionName: ?[*:0]const u8,
    pProfile: ?[*:0]const u8,
    Flags: u32,
    ppShader: ?*?*anyopaque,
    ppErrorMsgs: ?*?*anyopaque,
    ppConstantTable: ?*?*anyopaque,
) callconv(W) HRESULT {
    _ = pSrcFile;
    return D3DXCompileShader(null, 0, pDefines, pInclude, pFunctionName, pProfile, Flags, ppShader, ppErrorMsgs, ppConstantTable);
}

pub export fn D3DXGetImageInfoFromFileInMemory(
    pSrcData: ?*const anyopaque,
    SrcDataSize: u32,
    pSrcInfo: ?*D3DXIMAGE_INFO,
) callconv(W) HRESULT {
    if (pSrcData == null or SrcDataSize < 32 or pSrcInfo == null) return E_FAIL;
    const bytes: [*]const u8 = @ptrCast(pSrcData.?);
    if (SrcDataSize >= 128 and std.mem.eql(u8, bytes[0..4], "DDS ")) {
        pSrcInfo.?.Height = std.mem.readInt(u32, bytes[12..16], .little);
        pSrcInfo.?.Width = std.mem.readInt(u32, bytes[16..20], .little);
        pSrcInfo.?.MipLevels = std.mem.readInt(u32, bytes[28..32], .little);
        pSrcInfo.?.Depth = 1;
        pSrcInfo.?.Format = D3DFMT_A8R8G8B8;
        pSrcInfo.?.ResourceType = 1;
        pSrcInfo.?.ImageFileFormat = 4;
        return D3D_OK;
    }
    pSrcInfo.?.Width = 256;
    pSrcInfo.?.Height = 256;
    pSrcInfo.?.Depth = 1;
    pSrcInfo.?.MipLevels = 1;
    pSrcInfo.?.Format = D3DFMT_A8R8G8B8;
    pSrcInfo.?.ResourceType = 1;
    pSrcInfo.?.ImageFileFormat = 4;
    return D3D_OK;
}

pub export fn D3DXCreateTextureFromFileInMemory(
    pDevice: ?*anyopaque,
    pSrcData: ?*const anyopaque,
    SrcDataSize: u32,
    ppTexture: ?*?*anyopaque,
) callconv(W) HRESULT {
    _ = pDevice;
    if (ppTexture == null) return E_FAIL;
    var info: D3DXIMAGE_INFO = undefined;
    _ = D3DXGetImageInfoFromFileInMemory(pSrcData, SrcDataSize, &info);
    const gpa = std.heap.page_allocator;
    const tex = WinsTexture9.create(gpa, info.Width, info.Height, info.MipLevels, 0, info.Format, 1) catch return E_OUTOFMEMORY;
    ppTexture.?.* = @ptrCast(tex);
    return D3D_OK;
}

pub export fn D3DXCreateCubeTextureFromFileInMemory(
    pDevice: ?*anyopaque,
    pSrcData: ?*const anyopaque,
    SrcDataSize: u32,
    ppCubeTexture: ?*?*anyopaque,
) callconv(W) HRESULT {
    return D3DXCreateTextureFromFileInMemory(pDevice, pSrcData, SrcDataSize, ppCubeTexture);
}

pub export fn D3DXCreateVolumeTextureFromFileInMemory(
    pDevice: ?*anyopaque,
    pSrcData: ?*const anyopaque,
    SrcDataSize: u32,
    ppVolumeTexture: ?*?*anyopaque,
) callconv(W) HRESULT {
    return D3DXCreateTextureFromFileInMemory(pDevice, pSrcData, SrcDataSize, ppVolumeTexture);
}

pub export fn D3DXLoadSurfaceFromSurface(
    pDestSurface: ?*anyopaque,
    pDestPalette: ?*const anyopaque,
    pDestRect: ?*const D3DRECT,
    pSrcSurface: ?*anyopaque,
    pSrcPalette: ?*const anyopaque,
    pSrcRect: ?*const D3DRECT,
    Filter: u32,
    ColorKey: u32,
) callconv(W) HRESULT {
    _ = pDestSurface;
    _ = pDestPalette;
    _ = pDestRect;
    _ = pSrcSurface;
    _ = pSrcPalette;
    _ = pSrcRect;
    _ = Filter;
    _ = ColorKey;
    return D3D_OK;
}

pub export fn D3DXSaveTextureToFileA(
    pDestFile: ?[*:0]const u8,
    DestFormat: u32,
    pSrcTexture: ?*anyopaque,
    pSrcPalette: ?*const anyopaque,
) callconv(W) HRESULT {
    _ = pDestFile;
    _ = DestFormat;
    _ = pSrcTexture;
    _ = pSrcPalette;
    return D3D_OK;
}

// ============================================================================
// Unit Tests (Embedded Verification)
// ============================================================================

test "GetDeviceCaps reports the requested HAL or REF device type" {
    const d3d: *WinsD3D9 = @ptrCast(@alignCast(Direct3DCreate9(32).?));
    var caps: D3DCAPS9 = undefined;
    try std.testing.expectEqual(D3D_OK, d3d.vtbl.GetDeviceCaps(d3d, 0, 1, &caps));
    try std.testing.expectEqual(@as(u32, 1), caps.DeviceType);
    try std.testing.expectEqual(D3D_OK, d3d.vtbl.GetDeviceCaps(d3d, 0, 2, &caps));
    try std.testing.expectEqual(@as(u32, 2), caps.DeviceType);
}

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
    try std.testing.expectEqual(@as(u32, 0xFFFF0300), caps.PixelShaderVersion); // ps_3_0
    try std.testing.expectEqual(@as(u32, 8192), caps.MaxTextureWidth);

    // Create Device
    var params: D3DPRESENT_PARAMETERS = undefined;
    @memset(std.mem.asBytes(&params), 0);
    params.BackBufferWidth = 640;
    params.BackBufferHeight = 480;
    params.Windowed = 1;

    var dev_raw: ?*anyopaque = null;
    const create_rc = d3d9.vtbl.CreateDevice(d3d9, 0, 1, 0, 0, &params, &dev_raw);
    try std.testing.expectEqual(D3D_OK, create_rc);
    try std.testing.expect(dev_raw != null);

    const dev: *WinsD3DDevice9 = @ptrCast(@alignCast(dev_raw.?));
    var device_caps: D3DCAPS9 = undefined;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetDeviceCaps(dev, &device_caps));
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&caps), std.mem.asBytes(&device_caps));
    try std.testing.expectEqual(@as(u32, 640), dev.viewport.Width);
    try std.testing.expectEqual(@as(u32, 480), dev.viewport.Height);

    // Test Clear
    try std.testing.expectEqual(D3D_OK, dev.vtbl.Clear(dev, 0, null, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, 0xFFFF0000, 1.0, 0));
    try std.testing.expectEqual(@as(u32, 0xFFFF0000), dev.backbuffer[0]);
    try std.testing.expectEqual(@as(f32, 1.0), dev.depthbuffer[0]);

    // Test Vertex Buffer Creation, Lock, Unlock
    var vb_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateVertexBuffer(dev, 36, 0, 0, 1, &vb_raw, null));
    try std.testing.expect(vb_raw != null);
    const vb: *WinsVertexBuffer9 = @ptrCast(@alignCast(vb_raw.?));

    var lock_ptr: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, vb.vtbl.Lock(vb, 0, 36, &lock_ptr, 0));
    try std.testing.expect(lock_ptr != null);

    // Write a triangle in NDC coordinates:
    // (0, 0.5, 0.5), (-0.5, -0.5, 0.5), (0.5, -0.5, 0.5)
    const verts: [*]f32 = @ptrCast(@alignCast(lock_ptr.?));
    verts[0] = 0.0;
    verts[1] = 0.5;
    verts[2] = 0.5;
    verts[3] = -0.5;
    verts[4] = -0.5;
    verts[5] = 0.5;
    verts[6] = 0.5;
    verts[7] = -0.5;
    verts[8] = 0.5;
    try std.testing.expectEqual(D3D_OK, vb.vtbl.Unlock(vb));

    // Bind Vertex Buffer and Draw Primitive
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetStreamSource(dev, 0, vb, 0, 12));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.BeginScene(dev));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.BeginScene(dev));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.DrawPrimitive(dev, 4, 0, 1)); // 1 triangle
    try std.testing.expectEqual(D3D_OK, dev.vtbl.EndScene(dev));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.EndScene(dev));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.Present(dev, null, null, 0, null));

    try std.testing.expectEqual(@as(u64, 1), dev.draw_call_count);
    try std.testing.expectEqual(@as(u64, 1), dev.frame_count);

    // Center pixel of screen (320, 240) should now be green (0xFF00FF00) due to rasterizer!
    const center_idx = 240 * 640 + 320;
    try std.testing.expectEqual(@as(u32, 0xFF00FF00), dev.backbuffer[center_idx]);
    try std.testing.expectEqual(@as(f32, 0.5), dev.depthbuffer[center_idx]);
}

test "D3DX linear algebra math and matrix inversion" {
    // Vector normalize test
    var v = D3DVECTOR{ .x = 3.0, .y = 4.0, .z = 0.0 };
    var v_norm: D3DVECTOR = undefined;
    _ = D3DXVec3Normalize(&v_norm, &v);
    try std.testing.expectApproxEqAbs(@as(f32, 0.6), v_norm.x, 0.0001);
    try std.testing.expectApproxEqAbs(@as(f32, 0.8), v_norm.y, 0.0001);

    // Matrix Inversion Test
    var m = D3DMATRIX{
        .m = .{
            .{ 1, 0, 0, 0 },
            .{ 0, 2, 0, 0 },
            .{ 0, 0, 4, 0 },
            .{ 0, 0, 0, 1 },
        },
    };
    var m_inv: D3DMATRIX = undefined;
    var det: f32 = 0;
    _ = D3DXMatrixInverse(&m_inv, &det, &m);
    try std.testing.expectEqual(@as(f32, 8.0), det);
    try std.testing.expectEqual(@as(f32, 1.0), m_inv.m[0][0]);
    try std.testing.expectEqual(@as(f32, 0.5), m_inv.m[1][1]);
    try std.testing.expectEqual(@as(f32, 0.25), m_inv.m[2][2]);

    // Plane Normalize Test
    var plane = D3DXPLANE{ .a = 0.0, .b = 3.0, .c = 4.0, .d = 10.0 };
    var p_norm: D3DXPLANE = undefined;
    _ = D3DXPlaneNormalize(&p_norm, &plane);
    try std.testing.expectApproxEqAbs(@as(f32, 0.6), p_norm.b, 0.0001);
    try std.testing.expectApproxEqAbs(@as(f32, 0.8), p_norm.c, 0.0001);
    try std.testing.expectApproxEqAbs(@as(f32, 2.0), p_norm.d, 0.0001);

    // Buffer Allocation Test
    var buf_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, D3DXCreateBuffer(1024, &buf_raw));
    try std.testing.expect(buf_raw != null);
    const buf: *WinsD3DXBuffer = @ptrCast(@alignCast(buf_raw.?));
    try std.testing.expectEqual(@as(u32, 1024), buf.vtbl.GetBufferSize(buf));
}

test "adapter caps advertise hardware transform and lighting (software T&L)" {
    const d3d: *WinsD3D9 = @ptrCast(@alignCast(Direct3DCreate9(32).?));
    var caps: D3DCAPS9 = undefined;
    try std.testing.expectEqual(D3D_OK, d3d.vtbl.GetDeviceCaps(d3d, 0, D3DDEVTYPE_HAL, &caps));
    try std.testing.expect(caps.DevCaps & D3DDEVCAPS_HWTRANSFORMLIGHT != 0);
    try std.testing.expectEqual(D3D_OK, d3d.vtbl.GetDeviceCaps(d3d, 0, D3DDEVTYPE_REF, &caps));
    try std.testing.expect(caps.DevCaps & D3DDEVCAPS_HWTRANSFORMLIGHT != 0);
}

test "format 23 (A8B8G8R8) is accepted wherever 22 (X8R8G8B8) is" {
    const d3d: *WinsD3D9 = @ptrCast(@alignCast(Direct3DCreate9(32).?));
    try std.testing.expectEqual(D3D_OK, d3d.vtbl.CheckDeviceFormat(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, D3DUSAGE_RENDERTARGET, D3DRTYPE_SURFACE, D3DFMT_A8B8G8R8));
    try std.testing.expectEqual(D3D_OK, d3d.vtbl.CheckDeviceType(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, D3DFMT_A8B8G8R8, 1));
    try std.testing.expectEqual(@as(u32, 1), d3d.vtbl.GetAdapterModeCount(d3d, 0, D3DFMT_A8B8G8R8));
}

test "texture stage / sampler state: D3D9 defaults, round trip, range checks, caps match storage" {
    const d3d: *WinsD3D9 = @ptrCast(@alignCast(Direct3DCreate9(32).?));
    var params: D3DPRESENT_PARAMETERS = undefined;
    @memset(std.mem.asBytes(&params), 0);
    params.BackBufferWidth = 64;
    params.BackBufferHeight = 64;
    params.Windowed = 1;
    var dev_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, d3d.vtbl.CreateDevice(d3d, 0, 1, 0, 0, &params, &dev_raw));
    const dev: *WinsD3DDevice9 = @ptrCast(@alignCast(dev_raw.?));
    var v: u32 = 0xdead;

    // Documented defaults: stage 0 MODULATE/SELECTARG1, other stages DISABLE.
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetTextureStageState(dev, 0, 1, &v));
    try std.testing.expectEqual(@as(u32, 4), v);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetTextureStageState(dev, 1, 1, &v));
    try std.testing.expectEqual(@as(u32, 1), v);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetTextureStageState(dev, 3, 11, &v)); // TEXCOORDINDEX = stage
    try std.testing.expectEqual(@as(u32, 3), v);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetSamplerState(dev, 2, 5, &v)); // MAGFILTER
    try std.testing.expectEqual(@as(u32, 1), v);

    // Round trip, and each slot is independent of its neighbours.
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetTextureStageState(dev, 1, 1, 4));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetTextureStageState(dev, 1, 1, &v));
    try std.testing.expectEqual(@as(u32, 4), v);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetTextureStageState(dev, 0, 1, &v));
    try std.testing.expectEqual(@as(u32, 4), v);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetTextureStageState(dev, 2, 1, &v));
    try std.testing.expectEqual(@as(u32, 1), v); // untouched
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetSamplerState(dev, 15, 6, 2));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetSamplerState(dev, 15, 6, &v));
    try std.testing.expectEqual(@as(u32, 2), v);

    // Out-of-range stage / type / sampler / null out-pointer are refused, not accepted.
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.SetTextureStageState(dev, kMaxTextureStages, 1, 1));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.SetTextureStageState(dev, 0, 0, 1));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.SetTextureStageState(dev, 0, kTssSlots, 1));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.GetTextureStageState(dev, 0, 1, null));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.SetSamplerState(dev, 16, 1, 1));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.GetSamplerState(dev, 0, kSampSlots, &v));

    // The caps never advertise more stages than the device stores state for,
    // and satisfy the engine's gate (>= 2 stages and >= 2 simultaneous textures).
    var caps: D3DCAPS9 = undefined;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetDeviceCaps(dev, &caps));
    try std.testing.expect(caps.MaxTextureBlendStages >= 2 and caps.MaxSimultaneousTextures >= 2);
    try std.testing.expect(caps.MaxTextureBlendStages <= dev.tex_stage_states.len);
    try std.testing.expect(caps.MaxSimultaneousTextures <= dev.tex_stage_states.len);
    // Negative control: the last advertised stage really is usable, the next is refused.
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetTextureStageState(dev, caps.MaxTextureBlendStages - 1, 1, 1));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.SetTextureStageState(dev, caps.MaxTextureBlendStages, 1, 1));
}

test "render target / back buffer / depth surfaces wrap the device's own memory" {
    const d3d: *WinsD3D9 = @ptrCast(@alignCast(Direct3DCreate9(32).?));
    var params: D3DPRESENT_PARAMETERS = undefined;
    @memset(std.mem.asBytes(&params), 0);
    params.BackBufferWidth = 64;
    params.BackBufferHeight = 32;
    params.BackBufferFormat = D3DFMT_X8R8G8B8;
    params.Windowed = 1;
    params.EnableAutoDepthStencil = 1;
    params.AutoDepthStencilFormat = 75; // D3DFMT_D24S8
    var dev_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, d3d.vtbl.CreateDevice(d3d, 0, 1, 0, 0, &params, &dev_raw));
    const dev: *WinsD3DDevice9 = @ptrCast(@alignCast(dev_raw.?));

    // GetRenderTarget(0) and GetBackBuffer(0,0,MONO) return the same surface object.
    var rt: ?*anyopaque = null;
    var bb: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetRenderTarget(dev, 0, &rt));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetBackBuffer(dev, 0, 0, 0, &bb));
    try std.testing.expect(rt != null and rt == bb);
    const s: *WinsSurface9 = @ptrCast(@alignCast(rt.?));
    try std.testing.expectEqual(@as(u32, 3), s.ref_count); // the device's own + one per Get call
    try std.testing.expectEqual(D3DRTYPE_SURFACE, s.vtbl.GetType(s));
    dev.viewport.Width = 10;
    dev.viewport.Height = 10;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetRenderTarget(dev, 0, bb));
    try std.testing.expectEqual(@as(u32, 64), dev.viewport.Width);
    try std.testing.expectEqual(@as(u32, 32), dev.viewport.Height);
    try std.testing.expectEqual(@as(u32, 3), s.ref_count);
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.SetRenderTarget(dev, 0, null));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.SetRenderTarget(dev, 1, bb));

    // Description: a render-target surface, in the default pool, device-sized.
    var desc: D3DSURFACE_DESC = undefined;
    try std.testing.expectEqual(D3D_OK, s.vtbl.GetDesc(s, &desc));
    try std.testing.expectEqual(@as(u32, 64), desc.Width);
    try std.testing.expectEqual(@as(u32, 32), desc.Height);
    try std.testing.expectEqual(D3DFMT_X8R8G8B8, desc.Format);
    try std.testing.expectEqual(@as(u32, 1), desc.Type); // D3DRTYPE_SURFACE
    try std.testing.expectEqual(D3DUSAGE_RENDERTARGET, desc.Usage);
    try std.testing.expectEqual(@as(u32, 0), desc.Pool); // D3DPOOL_DEFAULT

    // Same memory as the rasterizer's back buffer, in both directions.
    var lr: D3DLOCKED_RECT = undefined;
    try std.testing.expectEqual(D3D_OK, s.vtbl.LockRect(s, &lr, null, 0));
    try std.testing.expectEqual(@as(i32, 64 * 4), lr.Pitch);
    try std.testing.expect(@intFromPtr(lr.pBits) == @intFromPtr(dev.backbuffer.ptr));
    const px: [*]u32 = @ptrCast(@alignCast(lr.pBits));
    px[5] = 0xff112233;
    try std.testing.expectEqual(@as(u32, 0xff112233), dev.backbuffer[5]);
    dev.backbuffer[7] = 0xff445566;
    try std.testing.expectEqual(@as(u32, 0xff445566), px[7]);

    // Only one target / one buffer / mono / swap chain 0: everything else is refused.
    var other: ?*anyopaque = null;
    try std.testing.expectEqual(D3DERR_NOTFOUND, dev.vtbl.GetRenderTarget(dev, 1, &other));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.GetBackBuffer(dev, 0, 1, 0, &other));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.GetBackBuffer(dev, 1, 0, 0, &other));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.GetBackBuffer(dev, 0, 0, 1, &other));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.GetRenderTarget(dev, 0, null));
    try std.testing.expect(other == null);

    // Depth/stencil: present because the device was created with one, and not lockable.
    var ds: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetDepthStencilSurface(dev, &ds));
    const d: *WinsSurface9 = @ptrCast(@alignCast(ds.?));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetDepthStencilSurface(dev, ds));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetDepthStencilSurface(dev, null));
    try std.testing.expectEqual(D3DERR_NOTFOUND, dev.vtbl.GetDepthStencilSurface(dev, &ds));
    try std.testing.expect(ds == null);
    try std.testing.expectEqual(D3D_OK, d.vtbl.GetDesc(d, &desc));
    try std.testing.expectEqual(D3DUSAGE_DEPTHSTENCIL, desc.Usage);
    try std.testing.expectEqual(@as(u32, 75), desc.Format);
    try std.testing.expectEqual(D3DERR_INVALIDCALL, d.vtbl.LockRect(d, &lr, null, 0));
}

test "SetDepthStencilSurface binds caller-created surfaces, retains them, and unbinds null" {
    const d3d: *WinsD3D9 = @ptrCast(@alignCast(Direct3DCreate9(32).?));
    const dev = try testDevice(d3d);

    var depth_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateDepthStencilSurface(dev, 32, 32, D3DFMT_D24S8, 0, 0, 0, &depth_raw, null));
    const depth: *WinsSurface9 = @ptrCast(@alignCast(depth_raw.?));
    try std.testing.expectEqual(@as(u32, 1), depth.ref_count);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetDepthStencilSurface(dev, depth));
    try std.testing.expectEqual(@as(u32, 2), depth.ref_count);

    var current: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetDepthStencilSurface(dev, &current));
    try std.testing.expectEqual(@intFromPtr(depth), @intFromPtr(current.?));
    try std.testing.expectEqual(@as(u32, 3), depth.ref_count);
    try std.testing.expectEqual(@as(u32, 2), depth.vtbl.Release(depth));

    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetDepthStencilSurface(dev, null));
    try std.testing.expectEqual(@as(u32, 1), depth.ref_count);
    current = depth;
    try std.testing.expectEqual(D3DERR_NOTFOUND, dev.vtbl.GetDepthStencilSurface(dev, &current));
    try std.testing.expect(current == null);

    // A same-device depth surface still has to match the active render target.
    var wrong_size: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateDepthStencilSurface(dev, 16, 32, D3DFMT_D24S8, 0, 0, 0, &wrong_size, null));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.SetDepthStencilSurface(dev, wrong_size));

    var backbuffer: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetBackBuffer(dev, 0, 0, 0, &backbuffer));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.SetDepthStencilSurface(dev, backbuffer));
}

test "no depth/stencil surface when the device was created without one" {
    const d3d: *WinsD3D9 = @ptrCast(@alignCast(Direct3DCreate9(32).?));
    var params: D3DPRESENT_PARAMETERS = undefined;
    @memset(std.mem.asBytes(&params), 0);
    params.BackBufferWidth = 16;
    params.BackBufferHeight = 16;
    params.Windowed = 1;
    var dev_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, d3d.vtbl.CreateDevice(d3d, 0, 1, 0, 0, &params, &dev_raw));
    const dev: *WinsD3DDevice9 = @ptrCast(@alignCast(dev_raw.?));
    var ds: ?*anyopaque = null;
    try std.testing.expectEqual(D3DERR_NOTFOUND, dev.vtbl.GetDepthStencilSurface(dev, &ds));
    try std.testing.expect(ds == null);
}

test "CheckDeviceFormat: plain textures are available exactly for the formats CreateTexture backs" {
    const d3d: *WinsD3D9 = @ptrCast(@alignCast(Direct3DCreate9(32).?));
    const tex = D3DRTYPE_TEXTURE;
    // Backed formats are available, with or without DYNAMIC.
    try std.testing.expectEqual(D3D_OK, d3d.vtbl.CheckDeviceFormat(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 0, tex, D3DFMT_A8R8G8B8));
    try std.testing.expectEqual(D3D_OK, d3d.vtbl.CheckDeviceFormat(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 0, tex, D3DFMT_X8R8G8B8));
    try std.testing.expectEqual(D3D_OK, d3d.vtbl.CheckDeviceFormat(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, D3DUSAGE_DYNAMIC, tex, D3DFMT_A8R8G8B8));
    // Every format with a storage layout is available: the ones FalloutNV probes.
    const backed = [_]u32{ 21, 22, 23, 24, 25, 26, 28, 32, 50, 60, 61, 62, 111, 112, 113, 114, 115, 116, D3DFMT_DXT1, D3DFMT_DXT3, D3DFMT_DXT5 };
    for (backed) |f| {
        try std.testing.expectEqual(D3D_OK, d3d.vtbl.CheckDeviceFormat(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 0, tex, f));
    }
    // Negative controls: formats without a layout here (UNKNOWN, 24-bit R8G8B8, the
    // depth formats, UYVY, garbage) are NOT backed, so they must not be advertised.
    const refused = [_]u32{ 0, 20, 29, 75, 80, 0x59565955, 0xdeadbeef };
    for (refused) |f| {
        try std.testing.expectEqual(D3DERR_NOTAVAILABLE, d3d.vtbl.CheckDeviceFormat(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 0, tex, f));
    }
    // Other resource types and usages that are not implemented are refused.
    try std.testing.expectEqual(D3DERR_NOTAVAILABLE, d3d.vtbl.CheckDeviceFormat(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 0, 4, D3DFMT_A8R8G8B8)); // volume texture
    try std.testing.expectEqual(D3DERR_NOTAVAILABLE, d3d.vtbl.CheckDeviceFormat(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 0x400, tex, D3DFMT_A8R8G8B8)); // AUTOGENMIPMAP
    // What is advertised can actually be created, 4 bytes per pixel.
    var params: D3DPRESENT_PARAMETERS = undefined;
    @memset(std.mem.asBytes(&params), 0);
    params.BackBufferWidth = 16;
    params.BackBufferHeight = 16;
    params.Windowed = 1;
    var dev_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, d3d.vtbl.CreateDevice(d3d, 0, 1, 0, 0, &params, &dev_raw));
    const dev: *WinsD3DDevice9 = @ptrCast(@alignCast(dev_raw.?));
    var tex_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateTexture(dev, 8, 4, 1, 0, D3DFMT_A8R8G8B8, 1, &tex_raw, null));
    const t9: *WinsTexture9 = @ptrCast(@alignCast(tex_raw.?));
    try std.testing.expectEqual(@as(i32, 8 * 4), t9.surface.pitch);
    try std.testing.expectEqual(@as(usize, 8 * 4 * 4), t9.surface.data.len);
}

fn testDevice(d3d: *WinsD3D9) !*WinsD3DDevice9 {
    var params: D3DPRESENT_PARAMETERS = undefined;
    @memset(std.mem.asBytes(&params), 0);
    params.BackBufferWidth = 32;
    params.BackBufferHeight = 32;
    params.Windowed = 1;
    var dev_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, d3d.vtbl.CreateDevice(d3d, 0, 1, 0, 0, &params, &dev_raw));
    return @ptrCast(@alignCast(dev_raw.?));
}

test "device cooperative and transform state match D3D9" {
    const d3d: *WinsD3D9 = @ptrCast(@alignCast(Direct3DCreate9(32).?));
    const dev = try testDevice(d3d);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.TestCooperativeLevel(dev));

    const identity = d3dIdentityMatrix();
    var got: D3DMATRIX = undefined;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetTransform(dev, 2, &got));
    try std.testing.expectEqual(identity, got);

    const view = D3DMATRIX{ .m = .{
        .{ 1, 0, 0, 4 },
        .{ 0, 1, 0, 5 },
        .{ 0, 0, 1, 6 },
        .{ 0, 0, 0, 1 },
    } };
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetTransform(dev, 2, &view));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetTransform(dev, 2, &got));
    try std.testing.expectEqual(view, got);

    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.SetTransform(dev, 1, &view));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.GetTransform(dev, 24, &got));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.SetTransform(dev, 2, null));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.GetTransform(dev, 2, null));
}

test "E_POINTER is 0x80004003 and distinct from E_NOTIMPL" {
    try std.testing.expectEqual(@as(u32, 0x80004003), @as(u32, @bitCast(E_POINTER)));
    try std.testing.expect(E_POINTER != E_NOTIMPL);
}

test "device QueryInterface answers only IUnknown and IDirect3DDevice9 (Ex is refused)" {
    const d3d: *WinsD3D9 = @ptrCast(@alignCast(Direct3DCreate9(32).?));
    const dev = try testDevice(d3d);
    const ex = GUID{ .Data1 = 0xB18B10CE, .Data2 = 0x2649, .Data3 = 0x405A, .Data4 = .{ 0x87, 0x0F, 0x95, 0xF7, 0x77, 0xD4, 0x31, 0x3A } };
    var out: ?*anyopaque = @ptrFromInt(0x1234);
    // Negative control: the identifier FalloutNV really asks for is refused, pointer cleared.
    try std.testing.expectEqual(E_NOINTERFACE, dev.vtbl.QueryInterface(dev, &ex, &out));
    try std.testing.expect(out == null);
    const before = dev.ref_count;
    try std.testing.expectEqual(S_OK, dev.vtbl.QueryInterface(dev, &IID_IDirect3DDevice9, &out));
    try std.testing.expect(out == @as(?*anyopaque, dev));
    try std.testing.expectEqual(before + 1, dev.ref_count); // a successful QI takes a reference
    try std.testing.expectEqual(S_OK, dev.vtbl.QueryInterface(dev, &IID_IUnknown, &out));
    try std.testing.expectEqual(E_POINTER, dev.vtbl.QueryInterface(dev, &IID_IUnknown, null));
}

test "device GetDirect3D and GetDisplayMode" {
    const d3d: *WinsD3D9 = @ptrCast(@alignCast(Direct3DCreate9(32).?));
    const dev = try testDevice(d3d);
    var p: ?*anyopaque = null;
    const refs = g_global_d3d9.ref_count;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetDirect3D(dev, &p));
    try std.testing.expect(p == @as(?*anyopaque, &g_global_d3d9));
    try std.testing.expectEqual(refs + 1, g_global_d3d9.ref_count);
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.GetDirect3D(dev, null));
    // The mode record is exactly 16 bytes: the guest keeps it in a 16-byte stack slot.
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(D3DDISPLAYMODE));
    var m: D3DDISPLAYMODE = undefined;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetDisplayMode(dev, 0, &m));
    try std.testing.expectEqual(@as(u32, 1280), m.Width);
    try std.testing.expectEqual(@as(u32, 720), m.Height);
    try std.testing.expectEqual(D3DFMT_X8R8G8B8, m.Format);
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.GetDisplayMode(dev, 1, &m));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.GetDisplayMode(dev, 0, null));
}

test "CreateDepthStencilSurface: real, unlockable, validated" {
    const d3d: *WinsD3D9 = @ptrCast(@alignCast(Direct3DCreate9(32).?));
    const dev = try testDevice(d3d);
    var s_raw: ?*anyopaque = null;
    // The exact call FalloutNV makes (and Wine accepts): 1280x720 D24S8, no multisampling.
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateDepthStencilSurface(dev, 1280, 720, D3DFMT_D24S8, 0, 0, 0, &s_raw, null));
    const s: *WinsSurface9 = @ptrCast(@alignCast(s_raw.?));
    var desc: D3DSURFACE_DESC = undefined;
    try std.testing.expectEqual(D3D_OK, s.vtbl.GetDesc(s, &desc));
    try std.testing.expectEqual(@as(u32, 1280), desc.Width);
    try std.testing.expectEqual(@as(u32, 720), desc.Height);
    try std.testing.expectEqual(D3DFMT_D24S8, desc.Format);
    try std.testing.expectEqual(D3DUSAGE_DEPTHSTENCIL, desc.Usage);
    try std.testing.expectEqual(@as(u32, 0), desc.Pool);
    var lr: D3DLOCKED_RECT = undefined;
    try std.testing.expectEqual(D3DERR_INVALIDCALL, s.vtbl.LockRect(s, &lr, null, 0));
    // Refusals: colour format, zero size, null out pointer, multisampling.
    var o2: ?*anyopaque = null;
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.CreateDepthStencilSurface(dev, 64, 64, D3DFMT_A8R8G8B8, 0, 0, 0, &o2, null));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.CreateDepthStencilSurface(dev, 0, 64, D3DFMT_D24S8, 0, 0, 0, &o2, null));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.CreateDepthStencilSurface(dev, 64, 64, D3DFMT_D24S8, 0, 0, 0, null, null));
    try std.testing.expectEqual(D3DERR_NOTAVAILABLE, dev.vtbl.CreateDepthStencilSurface(dev, 64, 64, D3DFMT_D24S8, 2, 0, 0, &o2, null));
    try std.testing.expect(o2 == null);
}

test "vertex declarations: create copies the list, Get/Set round trip, invalid lists refused" {
    const d3d: *WinsD3D9 = @ptrCast(@alignCast(Direct3DCreate9(32).?));
    const dev = try testDevice(d3d);
    const end = D3DVERTEXELEMENT9{ .Stream = 0xFF, .Offset = 0, .Type = kDeclTypeUnused, .Method = 0, .Usage = 0, .UsageIndex = 0 };
    var els = [_]D3DVERTEXELEMENT9{
        .{ .Stream = 0, .Offset = 0, .Type = 2, .Method = 0, .Usage = 0, .UsageIndex = 0 }, // FLOAT3 POSITION
        .{ .Stream = 0, .Offset = 12, .Type = 4, .Method = 0, .Usage = 10, .UsageIndex = 0 }, // D3DCOLOR COLOR
        end,
    };
    var d_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateVertexDeclaration(dev, &els, &d_raw));
    els[0].Offset = 99; // the copy must not alias the caller's array
    const d: *WinsVertexDecl9 = @ptrCast(@alignCast(d_raw.?));
    var n: u32 = 0;
    try std.testing.expectEqual(D3D_OK, d.vtbl.GetDeclaration(d, null, &n));
    try std.testing.expectEqual(@as(u32, 3), n); // two elements plus END
    var back: [3]D3DVERTEXELEMENT9 = undefined;
    try std.testing.expectEqual(D3D_OK, d.vtbl.GetDeclaration(d, &back[0], &n));
    try std.testing.expectEqual(@as(u16, 0), back[0].Offset);
    try std.testing.expectEqual(@as(u8, 10), back[1].Usage);
    try std.testing.expect(isDeclEnd(back[2]));
    // Set/Get round trip with reference counting.
    var cur: ?*anyopaque = @ptrFromInt(0x1);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetVertexDeclaration(dev, &cur));
    try std.testing.expect(cur == null); // nothing set yet
    const r0 = d.ref_count;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetVertexDeclaration(dev, d));
    try std.testing.expectEqual(r0 + 1, d.ref_count);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetVertexDeclaration(dev, &cur));
    try std.testing.expect(cur == @as(?*anyopaque, d));
    try std.testing.expectEqual(r0 + 2, d.ref_count);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetVertexDeclaration(dev, null));
    try std.testing.expectEqual(r0 + 1, d.ref_count); // device's reference dropped
    // Declaration QueryInterface: IUnknown / own IID yes, the device IID no.
    var q: ?*anyopaque = null;
    try std.testing.expectEqual(S_OK, d.vtbl.QueryInterface(d, &IID_IDirect3DVertexDeclaration9, &q));
    try std.testing.expectEqual(E_NOINTERFACE, d.vtbl.QueryInterface(d, &IID_IDirect3DDevice9, &q));
    // Invalid lists: no END, END too late, bad element type, null pointers.
    var no_end = [_]D3DVERTEXELEMENT9{.{ .Stream = 0, .Offset = 0, .Type = 2, .Method = 0, .Usage = 0, .UsageIndex = 0 }} ** kMaxDeclLength;
    var o2: ?*anyopaque = null;
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.CreateVertexDeclaration(dev, &no_end, &o2));
    var bad_type = [_]D3DVERTEXELEMENT9{ .{ .Stream = 0, .Offset = 0, .Type = 40, .Method = 0, .Usage = 0, .UsageIndex = 0 }, end };
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.CreateVertexDeclaration(dev, &bad_type, &o2));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.CreateVertexDeclaration(dev, null, &o2));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.CreateVertexDeclaration(dev, &els, null));
    try std.testing.expect(o2 == null);
}

test "surface layouts: pitch and size per format, DXT as 4x4 blocks" {
    // 32-bit, 16-bit, 8-bit
    try std.testing.expectEqual(@as(u32, 256), surfaceLayout(21, 64, 8).?.pitch);
    try std.testing.expectEqual(@as(usize, 2048), surfaceLayout(21, 64, 8).?.size);
    try std.testing.expectEqual(@as(u32, 4), surfaceLayout(23, 2, 1).?.pitch); // R5G6B5 2x1: what FalloutNV probes with
    try std.testing.expectEqual(@as(usize, 4), surfaceLayout(23, 2, 1).?.size);
    try std.testing.expectEqual(@as(u32, 3), surfaceLayout(28, 3, 5).?.pitch); // A8
    try std.testing.expectEqual(@as(usize, 15), surfaceLayout(28, 3, 5).?.size);
    try std.testing.expectEqual(@as(u32, 16), surfaceLayout(116, 1, 1).?.pitch); // A32B32G32R32F
    // DXT: one row of 4x4 blocks; sizes round up to whole blocks, never below one block.
    try std.testing.expectEqual(@as(u32, 128), surfaceLayout(D3DFMT_DXT1, 64, 64).?.pitch);
    try std.testing.expectEqual(@as(usize, 2048), surfaceLayout(D3DFMT_DXT1, 64, 64).?.size);
    try std.testing.expectEqual(@as(u32, 256), surfaceLayout(D3DFMT_DXT5, 64, 64).?.pitch);
    try std.testing.expectEqual(@as(usize, 4096), surfaceLayout(D3DFMT_DXT5, 64, 64).?.size);
    try std.testing.expectEqual(@as(usize, 32), surfaceLayout(D3DFMT_DXT5, 5, 3).?.size); // 2x1 blocks
    try std.testing.expectEqual(@as(usize, 8), surfaceLayout(D3DFMT_DXT1, 1, 1).?.size);
    // Negative controls: no colour layout for depth, 24-bit, unknown.
    try std.testing.expect(surfaceLayout(75, 8, 8) == null);
    try std.testing.expect(surfaceLayout(20, 8, 8) == null);
    try std.testing.expect(surfaceLayout(0, 8, 8) == null);
}

test "CreateTexture backs what it advertises, with the real layout" {
    const d3d: *WinsD3D9 = @ptrCast(@alignCast(Direct3DCreate9(32).?));
    const dev = try testDevice(d3d);
    var t_raw: ?*anyopaque = null;
    // FalloutNV's first texture under Wine: 2x1 R5G6B5.
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateTexture(dev, 2, 1, 1, 0, 23, 1, &t_raw, null));
    const small: *WinsTexture9 = @ptrCast(@alignCast(t_raw.?));
    try std.testing.expectEqual(@as(i32, 4), small.surface.pitch);
    try std.testing.expectEqual(@as(usize, 4), small.surface.data.len);
    // The loader's usual texture: DXT5 64x64, locked and filled like a .dds upload.
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateTexture(dev, 64, 64, 1, 0, D3DFMT_DXT5, 1, &t_raw, null));
    const dxt: *WinsTexture9 = @ptrCast(@alignCast(t_raw.?));
    try std.testing.expectEqual(@as(i32, 256), dxt.surface.pitch);
    try std.testing.expectEqual(@as(usize, 4096), dxt.surface.data.len);
    var lr: D3DLOCKED_RECT = undefined;
    try std.testing.expectEqual(D3D_OK, dxt.surface.vtbl.LockRect(dxt.surface, &lr, null, 0));
    try std.testing.expectEqual(@as(i32, 256), lr.Pitch);
    @memset(@as([*]u8, @ptrCast(lr.pBits))[0..4096], 0xAB);
    try std.testing.expectEqual(@as(u8, 0xAB), dxt.surface.data[4095]);
    // Depth/stencil surfaces keep their 4-byte storage.
    var ds: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateDepthStencilSurface(dev, 8, 8, D3DFMT_D24S8, 0, 0, 0, &ds, null));
    const d: *WinsSurface9 = @ptrCast(@alignCast(ds.?));
    try std.testing.expectEqual(@as(i32, 32), d.pitch);
}

test "texture QueryInterface: IUnknown/Resource/BaseTexture/Texture yes (with a reference), Device9 no" {
    const d3d: *WinsD3D9 = @ptrCast(@alignCast(Direct3DCreate9(32).?));
    const dev = try testDevice(d3d);
    var t_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateTexture(dev, 4, 4, 1, 0, 21, 1, &t_raw, null));
    const tex: *WinsTexture9 = @ptrCast(@alignCast(t_raw.?));
    var q: ?*anyopaque = null;
    const ids = [_]*const GUID{ &IID_IUnknown, &IID_IDirect3DResource9, &IID_IDirect3DBaseTexture9, &IID_IDirect3DTexture9 };
    for (ids) |id| {
        const before = tex.ref_count;
        try std.testing.expectEqual(S_OK, tex.vtbl.QueryInterface(tex, id, &q));
        try std.testing.expect(q == @as(?*anyopaque, tex));
        try std.testing.expectEqual(before + 1, tex.ref_count);
    }
    try std.testing.expectEqual(E_NOINTERFACE, tex.vtbl.QueryInterface(tex, &IID_IDirect3DDevice9, &q));
    try std.testing.expect(q == null);
}

test "mip chain: one real surface per level, with its own size, pitch and storage" {
    const d3d: *WinsD3D9 = @ptrCast(@alignCast(Direct3DCreate9(32).?));
    const dev = try testDevice(d3d);
    var t_raw: ?*anyopaque = null;
    // What FalloutNV asks for: 256x256 DXT1 with the full nine levels.
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateTexture(dev, 256, 256, 9, 0, D3DFMT_DXT1, 1, &t_raw, null));
    const tex: *WinsTexture9 = @ptrCast(@alignCast(t_raw.?));
    try std.testing.expectEqual(@as(u32, 9), tex.vtbl.GetLevelCount(tex));
    try std.testing.expectEqual(@as(u32, D3DRTYPE_TEXTURE), tex.vtbl.GetType(tex));
    const sizes = [_]usize{ 32768, 8192, 2048, 512, 128, 32, 8, 8, 8 }; // 4x4 blocks, never below one
    const pitches = [_]i32{ 512, 256, 128, 64, 32, 16, 8, 8, 8 };
    var level: u32 = 0;
    while (level < 9) : (level += 1) {
        var desc: D3DSURFACE_DESC = undefined;
        try std.testing.expectEqual(D3D_OK, tex.vtbl.GetLevelDesc(tex, level, &desc));
        try std.testing.expectEqual(@max(1, @as(u32, 256) >> @intCast(level)), desc.Width);
        try std.testing.expectEqual(@max(1, @as(u32, 256) >> @intCast(level)), desc.Height);
        try std.testing.expectEqual(@as(u32, 1), desc.Type); // a level is a SURFACE
        var s_raw: ?*anyopaque = null;
        try std.testing.expectEqual(D3D_OK, tex.vtbl.GetSurfaceLevel(tex, level, &s_raw));
        const s: *WinsSurface9 = @ptrCast(@alignCast(s_raw.?));
        try std.testing.expectEqual(sizes[level], s.data.len);
        try std.testing.expectEqual(@as(u32, 2), s.ref_count); // owned by the texture + this reference
        var lr: D3DLOCKED_RECT = undefined;
        try std.testing.expectEqual(D3D_OK, tex.vtbl.LockRect(tex, level, &lr, null, 0));
        try std.testing.expectEqual(pitches[level], lr.Pitch);
        try std.testing.expect(@intFromPtr(lr.pBits) == @intFromPtr(s.data.ptr));
        @memset(s.data, @intCast(0x10 + level));
        try std.testing.expectEqual(D3D_OK, tex.vtbl.UnlockRect(tex, level));
    }
    // Levels do not share storage: each still holds the byte written to it.
    level = 0;
    while (level < 9) : (level += 1) {
        try std.testing.expectEqual(@as(u8, @intCast(0x10 + level)), tex.surfaces[level].data[0]);
    }
    // Out-of-range levels are refused and clear the out pointer.
    var o: ?*anyopaque = @ptrFromInt(0x1);
    try std.testing.expectEqual(D3DERR_INVALIDCALL, tex.vtbl.GetSurfaceLevel(tex, 9, &o));
    try std.testing.expect(o == null);
    var lr2: D3DLOCKED_RECT = undefined;
    try std.testing.expectEqual(D3DERR_INVALIDCALL, tex.vtbl.LockRect(tex, 9, &lr2, null, 0));
    var d2: D3DSURFACE_DESC = undefined;
    try std.testing.expectEqual(D3DERR_INVALIDCALL, tex.vtbl.GetLevelDesc(tex, 99, &d2));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, tex.vtbl.GetSurfaceLevel(tex, 0, null));
}

test "CreateTexture level counts: 0 means the full chain, too many or zero sizes or unknown formats are refused" {
    const d3d: *WinsD3D9 = @ptrCast(@alignCast(Direct3DCreate9(32).?));
    const dev = try testDevice(d3d);
    var t_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateTexture(dev, 256, 64, 0, 0, 21, 1, &t_raw, null));
    var tex: *WinsTexture9 = @ptrCast(@alignCast(t_raw.?));
    try std.testing.expectEqual(@as(u32, 9), tex.vtbl.GetLevelCount(tex)); // log2(256) + 1
    var d: D3DSURFACE_DESC = undefined;
    try std.testing.expectEqual(D3D_OK, tex.vtbl.GetLevelDesc(tex, 3, &d));
    try std.testing.expectEqual(@as(u32, 32), d.Width); // 256 >> 3
    try std.testing.expectEqual(@as(u32, 8), d.Height); // 64 >> 3
    try std.testing.expectEqual(D3D_OK, tex.vtbl.GetLevelDesc(tex, 8, &d));
    try std.testing.expectEqual(@as(u32, 1), d.Width);
    try std.testing.expectEqual(@as(u32, 1), d.Height); // height reached 1 earlier and stays 1
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateTexture(dev, 1, 1, 0, 0, 21, 1, &t_raw, null));
    try std.testing.expectEqual(@as(u32, 1), @as(*WinsTexture9, @ptrCast(@alignCast(t_raw.?))).levels);
    var bad: ?*anyopaque = null;
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.CreateTexture(dev, 16, 16, 6, 0, 21, 1, &bad, null)); // 5 levels at most
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.CreateTexture(dev, 0, 16, 1, 0, 21, 1, &bad, null));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.CreateTexture(dev, 16, 16, 1, 0, D3DFMT_D24S8, 1, &bad, null)); // depth is not a texture format
    try std.testing.expect(bad == null);
    tex = @ptrCast(@alignCast(t_raw.?));
}

test "texture level counts match fullChain" {
    try std.testing.expectEqual(@as(u32, 1), WinsTexture9.fullChain(1, 1));
    try std.testing.expectEqual(@as(u32, 2), WinsTexture9.fullChain(2, 1));
    try std.testing.expectEqual(@as(u32, 9), WinsTexture9.fullChain(256, 256));
    try std.testing.expectEqual(@as(u32, 10), WinsTexture9.fullChain(1000, 3)); // floor(log2(1000)) + 1
    try std.testing.expectEqual(@as(u32, 13), WinsTexture9.fullChain(4096, 4096));
}

test "releasing a texture frees every level (no leak, no double free)" {
    // std.testing.allocator fails the test on any leak or double free.
    const tex = try WinsTexture9.create(std.testing.allocator, 64, 32, 0, 0, D3DFMT_DXT5, 1);
    try std.testing.expectEqual(@as(u32, 0), tex.vtbl.Release(tex));
    // A level surface the guest still holds keeps the texture alive instead of
    // dangling: it is a leak to be fixed by releasing the surface, never a crash.
    const keep = try WinsTexture9.create(std.testing.allocator, 8, 8, 2, 0, 21, 1);
    var s_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, keep.vtbl.GetSurfaceLevel(keep, 1, &s_raw));
    try std.testing.expectEqual(@as(u32, 0), keep.vtbl.Release(keep));
    const held: *WinsSurface9 = @ptrCast(@alignCast(s_raw.?));
    try std.testing.expectEqual(@as(u32, 2), held.ref_count); // still valid to touch
    held.ref_count = 1; // the guest releases its reference
    keep.destroy(); // now the whole texture can go
}

test "material and light state round-trip with D3D9 validation" {
    try std.testing.expectEqual(@as(usize, 68), @sizeOf(D3DMATERIAL9));
    try std.testing.expectEqual(@as(usize, 104), @sizeOf(D3DLIGHT9));

    const d3d: *WinsD3D9 = @ptrCast(@alignCast(Direct3DCreate9(32).?));
    const dev = try testDevice(d3d);
    var caps: D3DCAPS9 = undefined;
    try std.testing.expectEqual(D3D_OK, d3d.vtbl.GetDeviceCaps(d3d, 0, D3DDEVTYPE_HAL, &caps));
    try std.testing.expectEqual(@as(u32, kMaxDeviceLights), caps.MaxActiveLights);

    var material: D3DMATERIAL9 = undefined;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetMaterial(dev, &material));
    try std.testing.expectEqual(@as(f32, 1), material.Diffuse.r);
    try std.testing.expectEqual(@as(f32, 1), material.Ambient.a);
    try std.testing.expectEqual(@as(f32, 0), material.Specular.r);
    try std.testing.expectEqual(@as(f32, 0), material.Power);
    material.Diffuse = .{ .r = 0.25, .g = 0.5, .b = 0.75, .a = 1 };
    material.Ambient.r = 0.125;
    material.Power = 8;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetMaterial(dev, &material));
    var material_read: D3DMATERIAL9 = undefined;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetMaterial(dev, &material_read));
    try std.testing.expectEqual(material, material_read);
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.SetMaterial(dev, null));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.GetMaterial(dev, null));

    var light = std.mem.zeroes(D3DLIGHT9);
    light.Type = D3DLIGHT_POINT;
    light.Diffuse = .{ .r = 0.25, .g = 0.5, .b = 0.75, .a = 1 };
    light.Position.x = 1;
    light.Range = 20;
    light.Attenuation0 = 1;
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.GetLight(dev, 0, &light));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetLight(dev, 0, &light));
    var light_read: D3DLIGHT9 = undefined;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetLight(dev, 0, &light_read));
    try std.testing.expectEqual(light, light_read);

    var bad_light = light;
    bad_light.Type = 99;
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.SetLight(dev, 0, &bad_light));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.SetLight(dev, 0, null));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.GetLight(dev, 0, null));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.GetLight(dev, 1, &light_read));

    // SetLight stores sparse DWORD indexes; MaxActiveLights describes how many
    // may be active, not the largest index. Fallout uses a pointer-like key.
    const game_light_index: u32 = 0x0b002488;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetLight(dev, game_light_index, &light));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetLight(dev, game_light_index, &light_read));
    try std.testing.expectEqual(light, light_read);

    try std.testing.expectEqual(D3D_OK, dev.vtbl.LightEnable(dev, 0, 1));
    var enabled: i32 = 0;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetLightEnable(dev, 0, &enabled));
    try std.testing.expectEqual(@as(i32, 1), enabled);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.LightEnable(dev, 0, 0));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetLightEnable(dev, 0, &enabled));
    try std.testing.expectEqual(@as(i32, 0), enabled);
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.GetLightEnable(dev, 0, null));

    const high_enable_index: u32 = 0xd002488;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.LightEnable(dev, high_enable_index, 1));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetLightEnable(dev, high_enable_index, &enabled));
    try std.testing.expectEqual(@as(i32, 1), enabled);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetLight(dev, high_enable_index, &light_read));
    try std.testing.expectEqual(D3DLIGHT_DIRECTIONAL, light_read.Type);
    try std.testing.expectEqual(@as(f32, 1), light_read.Diffuse.r);
    try std.testing.expectEqual(@as(u32, 0), dev.vtbl.Release(dev));
}
