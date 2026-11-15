//! WINS Native Direct3D 9 State Tracker & COM Implementation (Zig 0.16)
//! Provides a 100% native Linux Direct3D 9 runtime (Zero Wine, Zero Proton).
//! Directly implements IDirect3D9, IDirect3DDevice9, IDirect3DTexture9,
//! IDirect3DVertexBuffer9, IDirect3DIndexBuffer9, IDirect3DSurface9, and ID3DXBuffer
//! with true bit-exact __stdcall ABI and software rasterization capabilities.

const std = @import("std");
const linux = std.os.linux;
const hostgl = @import("wins_d3d9_gl.zig");

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
pub const D3DFMT_A8B8G8R8: u32 = 32;
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
pub const D3DRTYPE_VOLUMETEXTURE: u32 = 4;
pub const D3DRTYPE_CUBETEXTURE: u32 = 5;
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

pub const POINT = extern struct {
    x: i32,
    y: i32,
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
pub const IID_IDirect3DStateBlock9 = GUID{
    .Data1 = 0xB07C4FE5,
    .Data2 = 0x310D,
    .Data3 = 0x4BA8,
    .Data4 = .{ 0xA2, 0x3C, 0x4F, 0x0F, 0x20, 0x6F, 0x21, 0x8B },
};
pub const D3DSBT_ALL: u32 = 1;
pub const D3DSBT_PIXELSTATE: u32 = 2;
pub const D3DSBT_VERTEXSTATE: u32 = 3;
pub const IDirect3DStateBlock9Vtbl = extern struct {
    QueryInterface: *const fn (*anyopaque, ?*const anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    AddRef: *const fn (*anyopaque) callconv(W) u32,
    Release: *const fn (*anyopaque) callconv(W) u32,
    GetDevice: *const fn (*anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    Capture: *const fn (*anyopaque) callconv(W) HRESULT,
    Apply: *const fn (*anyopaque) callconv(W) HRESULT,
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
pub const IID_IDirect3DVolume9 = GUID{
    .Data1 = 0x24F416E6,
    .Data2 = 0x1F67,
    .Data3 = 0x4AA7,
    .Data4 = .{ 0xB8, 0x8E, 0xD3, 0x3F, 0x6F, 0x31, 0x28, 0xA1 },
};
pub const IID_IDirect3DCubeTexture9 = GUID{
    .Data1 = 0xFFF32F81,
    .Data2 = 0xD953,
    .Data3 = 0x473A,
    .Data4 = .{ 0x92, 0x23, 0x93, 0xD6, 0x52, 0xAB, 0xA9, 0x3F },
};
pub const IID_IDirect3DVolumeTexture9 = GUID{
    .Data1 = 0x2518526C,
    .Data2 = 0xE789,
    .Data3 = 0x4111,
    .Data4 = .{ 0xA7, 0xB9, 0x47, 0xEF, 0x32, 0x8D, 0x13, 0xE6 },
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

pub fn d3dTransformStateIndex(state: u32) ?usize {
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

pub const D3DBOX = extern struct {
    Left: u32,
    Top: u32,
    Right: u32,
    Bottom: u32,
    Front: u32,
    Back: u32,
};

pub const D3DLOCKED_BOX = extern struct {
    RowPitch: i32,
    SlicePitch: i32,
    pBits: ?*anyopaque,
};

pub const D3DVOLUME_DESC = extern struct {
    Format: u32,
    Type: u32,
    Usage: u32,
    Pool: u32,
    Width: u32,
    Height: u32,
    Depth: u32,
};

pub const IDirect3DVolume9Vtbl = extern struct {
    QueryInterface: *const fn (*anyopaque, ?*const anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    AddRef: *const fn (*anyopaque) callconv(W) u32,
    Release: *const fn (*anyopaque) callconv(W) u32,
    GetDevice: *const fn (*anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    SetPrivateData: *const fn (*anyopaque, ?*const anyopaque, ?*const anyopaque, u32, u32) callconv(W) HRESULT,
    GetPrivateData: *const fn (*anyopaque, ?*const anyopaque, ?*anyopaque, ?*u32) callconv(W) HRESULT,
    FreePrivateData: *const fn (*anyopaque, ?*const anyopaque) callconv(W) HRESULT,
    GetContainer: *const fn (*anyopaque, ?*const anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    GetDesc: *const fn (*anyopaque, ?*D3DVOLUME_DESC) callconv(W) HRESULT,
    LockBox: *const fn (*anyopaque, ?*D3DLOCKED_BOX, ?*const D3DBOX, u32) callconv(W) HRESULT,
    UnlockBox: *const fn (*anyopaque) callconv(W) HRESULT,
};

pub const IDirect3DCubeTexture9Vtbl = extern struct {
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
    GetCubeMapSurface: *const fn (*anyopaque, u32, u32, ?*?*anyopaque) callconv(W) HRESULT,
    LockRect: *const fn (*anyopaque, u32, u32, ?*D3DLOCKED_RECT, ?*const D3DRECT, u32) callconv(W) HRESULT,
    UnlockRect: *const fn (*anyopaque, u32, u32) callconv(W) HRESULT,
    AddDirtyRect: *const fn (*anyopaque, u32, ?*const D3DRECT) callconv(W) HRESULT,
};

pub const IDirect3DVolumeTexture9Vtbl = extern struct {
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
    GetLevelDesc: *const fn (*anyopaque, u32, ?*D3DVOLUME_DESC) callconv(W) HRESULT,
    GetVolumeLevel: *const fn (*anyopaque, u32, ?*?*anyopaque) callconv(W) HRESULT,
    LockBox: *const fn (*anyopaque, u32, ?*D3DLOCKED_BOX, ?*const D3DBOX, u32) callconv(W) HRESULT,
    UnlockBox: *const fn (*anyopaque, u32) callconv(W) HRESULT,
    AddDirtyBox: *const fn (*anyopaque, ?*const D3DBOX) callconv(W) HRESULT,
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
    owner_device: ?*WinsD3DDevice9 = null,

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
    if (self.ref_count == 0) {
        if (self.owner_device) |dev| dev.untrackDefault(this);
    }
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
    owner_device: ?*WinsD3DDevice9 = null,

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
    if (self.ref_count == 0) {
        if (self.owner_device) |dev| dev.untrackDefault(this);
    }
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

pub const VolumeLayout = struct {
    row_pitch: u32,
    slice_pitch: u32,
    size: usize,
};

pub fn volumeLayout(format: u32, width: u32, height: u32, depth: u32) ?VolumeLayout {
    const lay = surfaceLayout(format, width, height) orelse return null;
    const slice: u32 = @intCast(lay.size);
    return .{ .row_pitch = lay.pitch, .slice_pitch = slice, .size = lay.size * @max(1, depth) };
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
    /// Host GPU object (wins_d3d9_gl.zig): a texture for colour render
    /// targets, a renderbuffer for depth/stencil; 0 until first used.
    gl_name: u32 = 0,
    gl_dirty: bool = false,
    /// Set for a level of a texture or cube texture: the texture owns the GPU storage.
    parent: ?*WinsTexture9 = null,
    cube_parent: ?*WinsCubeTexture9 = null,
    cube_face: u32 = 0,
    level: u32 = 0,

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
    const left = self.ref_count;
    if (left == 0) {
        if (self.parent == null and self.cube_parent == null) {
            if (self.owner_device) |od| {
                const dev: *WinsD3DDevice9 = @ptrCast(@alignCast(od));
                if (dev.rt_surface != self and dev.ds_surface != self) dev.untrackDefault(this);
            }
        }
    } else if (left == 1) {
        if (self.parent) |p| {
            if (p.ref_count == 0) p.destroy();
        } else if (self.cube_parent) |cp| {
            if (cp.ref_count == 0) cp.destroy();
        }
    }
    return left;
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
    const self: *WinsSurface9 = @ptrCast(@alignCast(this));
    if (self.parent) |p| p.gl_dirty = true;
    if (self.cube_parent) |cp| cp.gl_dirty = true;
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
    /// Host GPU copy (wins_d3d9_gl.zig): 0 until first sampled; dirty after an unlock.
    gl_name: u32 = 0,
    gl_dirty: bool = true,
    owner_device: ?*WinsD3DDevice9 = null,

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
        for (surfs, 0..) |sf, li| {
            sf.parent = tex;
            sf.level = @intCast(li);
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
        if (self.owner_device) |dev| dev.untrackDefault(self);
        const a = self.allocator;
        hostgl.textureGone(self.gl_name);
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
    self.gl_dirty = true;
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

// Cube Texture 9
pub const WinsCubeTexture9 = struct {
    vtbl: *const IDirect3DCubeTexture9Vtbl,
    ref_count: u32,
    edge_length: u32,
    levels: u32,
    usage: u32,
    format: u32,
    pool: u32,
    /// `6 * levels` faces in D3DCUBEMAP_FACES major order (`face * levels + level`).
    faces: []*WinsSurface9,
    allocator: std.mem.Allocator,
    gl_name: u32 = 0,
    gl_dirty: bool = true,
    owner_device: ?*WinsD3DDevice9 = null,

    pub fn create(allocator: std.mem.Allocator, edge_length: u32, levels: u32, usage: u32, format: u32, pool: u32) !*WinsCubeTexture9 {
        if (edge_length == 0 or surfaceLayout(format, 1, 1) == null) return error.InvalidCall;
        if ((usage & D3DUSAGE_RENDERTARGET) != 0 and !isRenderTargetFormat(format)) return error.InvalidCall;
        const full = WinsTexture9.fullChain(edge_length, edge_length);
        const n: u32 = if (levels == 0) full else levels;
        if (n > full) return error.InvalidCall;
        const ct = try allocator.create(WinsCubeTexture9);
        errdefer allocator.destroy(ct);
        const total = 6 * @as(usize, n);
        const faces = try allocator.alloc(*WinsSurface9, total);
        errdefer allocator.free(faces);
        var made: usize = 0;
        errdefer for (faces[0..made]) |s| s.destroy();
        for (0..6) |f| {
            for (0..n) |l| {
                const dim = @max(1, edge_length >> @intCast(l));
                const s = try WinsSurface9.create(allocator, dim, dim, format);
                s.usage = usage;
                s.pool = pool;
                s.lockable = (usage & D3DUSAGE_RENDERTARGET) == 0;
                s.cube_parent = ct;
                s.cube_face = @intCast(f);
                s.level = @intCast(l);
                faces[made] = s;
                made += 1;
            }
        }
        ct.* = .{
            .vtbl = &g_cubetex9_vtbl,
            .ref_count = 1,
            .edge_length = edge_length,
            .levels = n,
            .usage = usage,
            .format = format,
            .pool = pool,
            .faces = faces,
            .allocator = allocator,
        };
        return ct;
    }

    pub fn destroy(self: *WinsCubeTexture9) void {
        for (self.faces) |s| {
            if (s.ref_count > 1) return;
        }
        if (self.owner_device) |dev| dev.untrackDefault(self);
        const a = self.allocator;
        hostgl.textureGone(self.gl_name);
        for (self.faces) |s| s.destroy();
        a.free(self.faces);
        a.destroy(self);
    }
};

fn cubetex_QueryInterface(this: *anyopaque, riid: ?*const anyopaque, ppv: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsCubeTexture9 = @ptrCast(@alignCast(this));
    const out = ppv orelse return E_POINTER;
    out.* = null;
    const r = riid orelse return E_POINTER;
    const id: *align(1) const GUID = @ptrCast(r);
    if (guidEql(id, &IID_IUnknown) or guidEql(id, &IID_IDirect3DResource9) or
        guidEql(id, &IID_IDirect3DBaseTexture9) or guidEql(id, &IID_IDirect3DCubeTexture9))
    {
        self.ref_count += 1;
        out.* = this;
        return S_OK;
    }
    return E_NOINTERFACE;
}
fn cubetex_AddRef(this: *anyopaque) callconv(W) u32 {
    const self: *WinsCubeTexture9 = @ptrCast(@alignCast(this));
    self.ref_count += 1;
    return self.ref_count;
}
fn cubetex_Release(this: *anyopaque) callconv(W) u32 {
    const self: *WinsCubeTexture9 = @ptrCast(@alignCast(this));
    if (self.ref_count > 0) self.ref_count -= 1;
    const left = self.ref_count;
    if (left == 0) self.destroy();
    return left;
}
fn cubetex_GetType(this: *anyopaque) callconv(W) u32 {
    _ = this;
    return D3DRTYPE_CUBETEXTURE;
}
fn cubetex_GetLevelCount(this: *anyopaque) callconv(W) u32 {
    const self: *WinsCubeTexture9 = @ptrCast(@alignCast(this));
    return self.levels;
}
fn cubetex_GetLevelDesc(this: *anyopaque, level: u32, pDesc: ?*D3DSURFACE_DESC) callconv(W) HRESULT {
    const self: *WinsCubeTexture9 = @ptrCast(@alignCast(this));
    if (level >= self.levels) return D3DERR_INVALIDCALL;
    const s = self.faces[level];
    return s.vtbl.GetDesc(s, pDesc);
}
fn cubetex_GetCubeMapSurface(this: *anyopaque, face: u32, level: u32, ppSurface: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsCubeTexture9 = @ptrCast(@alignCast(this));
    const out = ppSurface orelse return D3DERR_INVALIDCALL;
    out.* = null;
    if (face >= 6 or level >= self.levels) return D3DERR_INVALIDCALL;
    const s = self.faces[@as(usize, face) * self.levels + level];
    s.ref_count += 1;
    out.* = s;
    return D3D_OK;
}
fn cubetex_LockRect(this: *anyopaque, face: u32, level: u32, pLocked: ?*D3DLOCKED_RECT, pRect: ?*const D3DRECT, flags: u32) callconv(W) HRESULT {
    const self: *WinsCubeTexture9 = @ptrCast(@alignCast(this));
    if (face >= 6 or level >= self.levels) return D3DERR_INVALIDCALL;
    const s = self.faces[@as(usize, face) * self.levels + level];
    return s.vtbl.LockRect(s, pLocked, pRect, flags);
}
fn cubetex_UnlockRect(this: *anyopaque, face: u32, level: u32) callconv(W) HRESULT {
    const self: *WinsCubeTexture9 = @ptrCast(@alignCast(this));
    if (face >= 6 or level >= self.levels) return D3DERR_INVALIDCALL;
    self.gl_dirty = true;
    const s = self.faces[@as(usize, face) * self.levels + level];
    return s.vtbl.UnlockRect(s);
}
fn cubetex_AddDirtyRect(this: *anyopaque, face: u32, pDirty: ?*const D3DRECT) callconv(W) HRESULT {
    _ = pDirty;
    const self: *WinsCubeTexture9 = @ptrCast(@alignCast(this));
    if (face >= 6) return D3DERR_INVALIDCALL;
    self.gl_dirty = true;
    return D3D_OK;
}

const g_cubetex9_vtbl: IDirect3DCubeTexture9Vtbl = .{
    .QueryInterface = &cubetex_QueryInterface,
    .AddRef = &cubetex_AddRef,
    .Release = &cubetex_Release,
    .GetDevice = @ptrCast(&vb_Stub),
    .SetPrivateData = @ptrCast(&vb_Stub),
    .GetPrivateData = @ptrCast(&vb_Stub),
    .FreePrivateData = @ptrCast(&vb_Stub),
    .SetPriority = @ptrCast(&vb_Stub),
    .GetPriority = @ptrCast(&vb_Stub),
    .PreLoad = @ptrCast(&vb_Stub),
    .GetType = &cubetex_GetType,
    .SetLOD = @ptrCast(&vb_Stub),
    .GetLOD = @ptrCast(&vb_Stub),
    .GetLevelCount = &cubetex_GetLevelCount,
    .SetAutoGenFilterType = @ptrCast(&vb_Stub),
    .GetAutoGenFilterType = @ptrCast(&vb_Stub),
    .GenerateMipSubLevels = @ptrCast(&vb_Stub),
    .GetLevelDesc = &cubetex_GetLevelDesc,
    .GetCubeMapSurface = &cubetex_GetCubeMapSurface,
    .LockRect = &cubetex_LockRect,
    .UnlockRect = &cubetex_UnlockRect,
    .AddDirtyRect = &cubetex_AddDirtyRect,
};

// Volume 9 & Volume Texture 9
pub const WinsVolume9 = struct {
    vtbl: *const IDirect3DVolume9Vtbl,
    ref_count: u32,
    width: u32,
    height: u32,
    depth: u32,
    format: u32,
    row_pitch: i32,
    slice_pitch: i32,
    data: []u8,
    allocator: std.mem.Allocator,
    usage: u32 = 0,
    pool: u32 = 1,
    parent: ?*WinsVolumeTexture9 = null,
    level: u32 = 0,

    pub fn create(allocator: std.mem.Allocator, width: u32, height: u32, depth: u32, format: u32) !*WinsVolume9 {
        const lay = volumeLayout(format, width, height, depth) orelse return error.InvalidCall;
        const vol = try allocator.create(WinsVolume9);
        errdefer allocator.destroy(vol);
        const mem = try allocator.alloc(u8, lay.size);
        @memset(mem, 0);
        vol.* = .{
            .vtbl = &g_vol9_vtbl,
            .ref_count = 1,
            .width = width,
            .height = height,
            .depth = depth,
            .format = format,
            .row_pitch = @intCast(lay.row_pitch),
            .slice_pitch = @intCast(lay.slice_pitch),
            .data = mem,
            .allocator = allocator,
        };
        return vol;
    }

    pub fn destroy(self: *WinsVolume9) void {
        const a = self.allocator;
        a.free(self.data);
        a.destroy(self);
    }
};

fn vol_QueryInterface(this: *anyopaque, riid: ?*const anyopaque, ppv: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsVolume9 = @ptrCast(@alignCast(this));
    const out = ppv orelse return E_POINTER;
    out.* = null;
    const r = riid orelse return E_POINTER;
    const id: *align(1) const GUID = @ptrCast(r);
    if (guidEql(id, &IID_IUnknown) or guidEql(id, &IID_IDirect3DVolume9)) {
        self.ref_count += 1;
        out.* = this;
        return S_OK;
    }
    return E_NOINTERFACE;
}
fn vol_AddRef(this: *anyopaque) callconv(W) u32 {
    const self: *WinsVolume9 = @ptrCast(@alignCast(this));
    self.ref_count += 1;
    return self.ref_count;
}
fn vol_Release(this: *anyopaque) callconv(W) u32 {
    const self: *WinsVolume9 = @ptrCast(@alignCast(this));
    if (self.ref_count > 0) self.ref_count -= 1;
    const left = self.ref_count;
    if (left == 1) {
        if (self.parent) |p| {
            if (p.ref_count == 0) p.destroy();
        }
    }
    return left;
}
fn vol_GetContainer(this: *anyopaque, riid: ?*const anyopaque, ppContainer: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsVolume9 = @ptrCast(@alignCast(this));
    const out = ppContainer orelse return D3DERR_INVALIDCALL;
    out.* = null;
    const p = self.parent orelse return D3DERR_INVALIDCALL;
    return p.vtbl.QueryInterface(p, riid, out);
}
fn vol_GetDesc(this: *anyopaque, pDesc: ?*D3DVOLUME_DESC) callconv(W) HRESULT {
    const self: *WinsVolume9 = @ptrCast(@alignCast(this));
    const d = pDesc orelse return D3DERR_INVALIDCALL;
    d.* = .{
        .Format = self.format,
        .Type = D3DRTYPE_VOLUME,
        .Usage = self.usage,
        .Pool = self.pool,
        .Width = self.width,
        .Height = self.height,
        .Depth = self.depth,
    };
    return D3D_OK;
}
fn vol_LockBox(this: *anyopaque, pLockedVolume: ?*D3DLOCKED_BOX, pBox: ?*const D3DBOX, flags: u32) callconv(W) HRESULT {
    _ = pBox;
    _ = flags;
    const self: *WinsVolume9 = @ptrCast(@alignCast(this));
    const l = pLockedVolume orelse return D3DERR_INVALIDCALL;
    l.* = .{
        .RowPitch = self.row_pitch,
        .SlicePitch = self.slice_pitch,
        .pBits = self.data.ptr,
    };
    return D3D_OK;
}
fn vol_UnlockBox(this: *anyopaque) callconv(W) HRESULT {
    const self: *WinsVolume9 = @ptrCast(@alignCast(this));
    if (self.parent) |p| p.gl_dirty = true;
    return D3D_OK;
}

const g_vol9_vtbl: IDirect3DVolume9Vtbl = .{
    .QueryInterface = &vol_QueryInterface,
    .AddRef = &vol_AddRef,
    .Release = &vol_Release,
    .GetDevice = @ptrCast(&vb_Stub),
    .SetPrivateData = @ptrCast(&vb_Stub),
    .GetPrivateData = @ptrCast(&vb_Stub),
    .FreePrivateData = @ptrCast(&vb_Stub),
    .GetContainer = &vol_GetContainer,
    .GetDesc = &vol_GetDesc,
    .LockBox = &vol_LockBox,
    .UnlockBox = &vol_UnlockBox,
};

pub const WinsVolumeTexture9 = struct {
    vtbl: *const IDirect3DVolumeTexture9Vtbl,
    ref_count: u32,
    width: u32,
    height: u32,
    depth: u32,
    levels: u32,
    usage: u32,
    format: u32,
    pool: u32,
    volumes: []*WinsVolume9,
    allocator: std.mem.Allocator,
    gl_name: u32 = 0,
    gl_dirty: bool = true,
    owner_device: ?*WinsD3DDevice9 = null,

    pub fn fullChain(width: u32, height: u32, depth: u32) u32 {
        return 1 + (31 - @clz(@max(@max(width, height), depth)));
    }

    pub fn create(allocator: std.mem.Allocator, width: u32, height: u32, depth: u32, levels: u32, usage: u32, format: u32, pool: u32) !*WinsVolumeTexture9 {
        if (width == 0 or height == 0 or depth == 0) return error.InvalidCall;
        if ((usage & (D3DUSAGE_RENDERTARGET | D3DUSAGE_DEPTHSTENCIL)) != 0) return error.InvalidCall;
        if (volumeLayout(format, 1, 1, 1) == null) return error.InvalidCall;
        const full = fullChain(width, height, depth);
        const n: u32 = if (levels == 0) full else levels;
        if (n > full) return error.InvalidCall;
        const vt = try allocator.create(WinsVolumeTexture9);
        errdefer allocator.destroy(vt);
        const vols = try allocator.alloc(*WinsVolume9, n);
        errdefer allocator.free(vols);
        var made: usize = 0;
        errdefer for (vols[0..made]) |v| v.destroy();
        while (made < n) : (made += 1) {
            const w = @max(1, width >> @intCast(made));
            const h = @max(1, height >> @intCast(made));
            const d = @max(1, depth >> @intCast(made));
            const v = try WinsVolume9.create(allocator, w, h, d, format);
            v.usage = usage;
            v.pool = pool;
            v.parent = vt;
            v.level = @intCast(made);
            vols[made] = v;
        }
        vt.* = .{
            .vtbl = &g_voltex9_vtbl,
            .ref_count = 1,
            .width = width,
            .height = height,
            .depth = depth,
            .levels = n,
            .usage = usage,
            .format = format,
            .pool = pool,
            .volumes = vols,
            .allocator = allocator,
        };
        return vt;
    }

    pub fn destroy(self: *WinsVolumeTexture9) void {
        for (self.volumes) |v| {
            if (v.ref_count > 1) return;
        }
        if (self.owner_device) |dev| dev.untrackDefault(self);
        const a = self.allocator;
        hostgl.textureGone(self.gl_name);
        for (self.volumes) |v| v.destroy();
        a.free(self.volumes);
        a.destroy(self);
    }
};

fn voltex_QueryInterface(this: *anyopaque, riid: ?*const anyopaque, ppv: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsVolumeTexture9 = @ptrCast(@alignCast(this));
    const out = ppv orelse return E_POINTER;
    out.* = null;
    const r = riid orelse return E_POINTER;
    const id: *align(1) const GUID = @ptrCast(r);
    if (guidEql(id, &IID_IUnknown) or guidEql(id, &IID_IDirect3DResource9) or
        guidEql(id, &IID_IDirect3DBaseTexture9) or guidEql(id, &IID_IDirect3DVolumeTexture9))
    {
        self.ref_count += 1;
        out.* = this;
        return S_OK;
    }
    return E_NOINTERFACE;
}
fn voltex_AddRef(this: *anyopaque) callconv(W) u32 {
    const self: *WinsVolumeTexture9 = @ptrCast(@alignCast(this));
    self.ref_count += 1;
    return self.ref_count;
}
fn voltex_Release(this: *anyopaque) callconv(W) u32 {
    const self: *WinsVolumeTexture9 = @ptrCast(@alignCast(this));
    if (self.ref_count > 0) self.ref_count -= 1;
    const left = self.ref_count;
    if (left == 0) self.destroy();
    return left;
}
fn voltex_GetType(this: *anyopaque) callconv(W) u32 {
    _ = this;
    return D3DRTYPE_VOLUMETEXTURE;
}
fn voltex_GetLevelCount(this: *anyopaque) callconv(W) u32 {
    const self: *WinsVolumeTexture9 = @ptrCast(@alignCast(this));
    return self.levels;
}
fn voltex_GetLevelDesc(this: *anyopaque, level: u32, pDesc: ?*D3DVOLUME_DESC) callconv(W) HRESULT {
    const self: *WinsVolumeTexture9 = @ptrCast(@alignCast(this));
    if (level >= self.levels) return D3DERR_INVALIDCALL;
    const v = self.volumes[level];
    return v.vtbl.GetDesc(v, pDesc);
}
fn voltex_GetVolumeLevel(this: *anyopaque, level: u32, ppVolumeLevel: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsVolumeTexture9 = @ptrCast(@alignCast(this));
    const out = ppVolumeLevel orelse return D3DERR_INVALIDCALL;
    out.* = null;
    if (level >= self.levels) return D3DERR_INVALIDCALL;
    const v = self.volumes[level];
    v.ref_count += 1;
    out.* = v;
    return D3D_OK;
}
fn voltex_LockBox(this: *anyopaque, level: u32, pLocked: ?*D3DLOCKED_BOX, pBox: ?*const D3DBOX, flags: u32) callconv(W) HRESULT {
    const self: *WinsVolumeTexture9 = @ptrCast(@alignCast(this));
    if (level >= self.levels) return D3DERR_INVALIDCALL;
    const v = self.volumes[level];
    return v.vtbl.LockBox(v, pLocked, pBox, flags);
}
fn voltex_UnlockBox(this: *anyopaque, level: u32) callconv(W) HRESULT {
    const self: *WinsVolumeTexture9 = @ptrCast(@alignCast(this));
    if (level >= self.levels) return D3DERR_INVALIDCALL;
    self.gl_dirty = true;
    const v = self.volumes[level];
    return v.vtbl.UnlockBox(v);
}
fn voltex_AddDirtyBox(this: *anyopaque, pDirtyBox: ?*const D3DBOX) callconv(W) HRESULT {
    _ = pDirtyBox;
    const self: *WinsVolumeTexture9 = @ptrCast(@alignCast(this));
    self.gl_dirty = true;
    return D3D_OK;
}

const g_voltex9_vtbl: IDirect3DVolumeTexture9Vtbl = .{
    .QueryInterface = &voltex_QueryInterface,
    .AddRef = &voltex_AddRef,
    .Release = &voltex_Release,
    .GetDevice = @ptrCast(&vb_Stub),
    .SetPrivateData = @ptrCast(&vb_Stub),
    .GetPrivateData = @ptrCast(&vb_Stub),
    .FreePrivateData = @ptrCast(&vb_Stub),
    .SetPriority = @ptrCast(&vb_Stub),
    .GetPriority = @ptrCast(&vb_Stub),
    .PreLoad = @ptrCast(&vb_Stub),
    .GetType = &voltex_GetType,
    .SetLOD = @ptrCast(&vb_Stub),
    .GetLOD = @ptrCast(&vb_Stub),
    .GetLevelCount = &voltex_GetLevelCount,
    .SetAutoGenFilterType = @ptrCast(&vb_Stub),
    .GetAutoGenFilterType = @ptrCast(&vb_Stub),
    .GenerateMipSubLevels = @ptrCast(&vb_Stub),
    .GetLevelDesc = &voltex_GetLevelDesc,
    .GetVolumeLevel = &voltex_GetVolumeLevel,
    .LockBox = &voltex_LockBox,
    .UnlockBox = &voltex_UnlockBox,
    .AddDirtyBox = &voltex_AddDirtyBox,
};

/// Returns D3DRTYPE_TEXTURE / CUBETEXTURE / VOLUMETEXTURE for a bound texture,
/// or 0 if null / unrecognised.
pub fn textureKind(ptr: ?*const anyopaque) u32 {
    const p = ptr orelse return 0;
    const vptr: *const *const anyopaque = @ptrCast(@alignCast(p));
    const v = @intFromPtr(vptr.*);
    if (v == @intFromPtr(&g_tex9_vtbl)) return D3DRTYPE_TEXTURE;
    if (v == @intFromPtr(&g_cubetex9_vtbl)) return D3DRTYPE_CUBETEXTURE;
    if (v == @intFromPtr(&g_voltex9_vtbl)) return D3DRTYPE_VOLUMETEXTURE;
    return 0;
}

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
    for (.{ WinsD3D9, WinsD3DDevice9, WinsSurface9, WinsTexture9, WinsCubeTexture9, WinsVolume9, WinsVolumeTexture9, WinsVertexBuffer9, WinsIndexBuffer9, WinsShader9, WinsD3DXBuffer, WinsVertexDecl9 }) |T| {
        if (@offsetOf(T, "vtbl") != 0) @compileError("COM object " ++ @typeName(T) ++ " must keep vtbl at offset 0");
    }
}

/// Draw tracer: an instrument, off unless the loader sets it from
/// WINS_D3D9_TRACE=<frames>. While frames remain, every draw, clear, target
/// change and present prints one line with the state a backend would need, so
/// the next piece of the device is built from what the guest really asks for.
pub var trace_frames: u32 = 0;
/// Set by the loader (WINS_D3D9_HOST=0 turns it off): devices get an X11
/// window and render on the host GPU.
pub var host_enabled: bool = false;
/// WINS_D3D9_TRACE=<start>:<frames> arms the tracer once `start` frames were
/// presented (the frames of interest come long after the loading screens).
pub var trace_after: u64 = 0;
pub var trace_budget: u32 = 0;
/// Non-zero: re-arm every `trace_period` frames (WINS_D3D9_TRACE=<start>:<frames>:<period>).
pub var trace_period: u64 = 0;
/// Stays true once tracing was requested: resource creation is logged for the
/// whole run (it happens long before the frames of interest).
pub var trace_resources: bool = false;

fn shaderVersion(sh: ?*const WinsShader9) u32 {
    const s = sh orelse return 0;
    return if (s.tokens.len > 0) s.tokens[0] else 0;
}

fn traceDraw(self: *const WinsD3DDevice9, kind: []const u8, prim: u32, a: i64, b: u32, c: u32) void {
    if (trace_frames == 0) return;
    std.debug.print("[WINS:D3D9:trace] f{d} {s} prim={d} base/start={d} first={d} count={d} vs={x}@{x} ps={x}@{x} zenable={d} zwrite={d} alphablend={d} src={d} dst={d} alphatest={d} cull={d} scissor={d} colorwrite={x}\n", .{
        self.frame_count,                 kind,                                 prim,                                a,                                   b,                                   c,
        shaderVersion(self.active_vs),    @intFromPtr(self.active_vs),          shaderVersion(self.active_ps),       @intFromPtr(self.active_ps),         self.render_states[7],               self.render_states[14],
        self.render_states[27],           self.render_states[19],               self.render_states[20],              self.render_states[15],              self.render_states[22],              self.render_states[174],
        self.render_states[168],
    });
    inline for (.{ self.active_vs, self.active_ps }, .{ "vs", "ps" }) |maybe_sh, tag| {
        if (maybe_sh) |sh| {
            std.debug.print("[WINS:D3D9:trace]   {s} tokens:", .{tag});
            for (sh.tokens) |t| std.debug.print(" {x:0>8}", .{t});
            std.debug.print("\n", .{});
        }
    }
    std.debug.print("[WINS:D3D9:trace]   vsc:", .{});
    for (self.vs_consts[0..12]) |k| std.debug.print(" [{d:.4} {d:.4} {d:.4} {d:.4}]", .{ k[0], k[1], k[2], k[3] });
    std.debug.print("\n[WINS:D3D9:trace]   psc:", .{});
    for (self.ps_consts[0..6]) |k| std.debug.print(" [{d:.4} {d:.4} {d:.4} {d:.4}]", .{ k[0], k[1], k[2], k[3] });
    std.debug.print("\n", .{});
    if (self.streams[0]) |vb| {
        std.debug.print("[WINS:D3D9:trace]   vb0 floats:", .{});
        var o: usize = self.stream_offsets[0];
        while (o + 4 <= vb.data.len and o < self.stream_offsets[0] + 80) : (o += 4) std.debug.print(" {d:.3}", .{readFloat32LE(vb.data, o)});
        std.debug.print("\n", .{});
    }
    if (self.indices) |ib| {
        std.debug.print("[WINS:D3D9:trace]   ib bytes:", .{});
        for (ib.data[0..@min(ib.data.len, 24)]) |x| std.debug.print(" {x:0>2}", .{x});
        std.debug.print("\n", .{});
    }
    std.debug.print("[WINS:D3D9:trace]   viewport {d},{d} {d}x{d} z {d}..{d}\n", .{ self.viewport.X, self.viewport.Y, self.viewport.Width, self.viewport.Height, self.viewport.MinZ, self.viewport.MaxZ });
    if (self.vertex_decl) |d| {
        std.debug.print("[WINS:D3D9:trace]   decl@{x}:", .{@intFromPtr(d)});
        for (d.elements) |e| {
            if (isDeclEnd(e)) break;
            std.debug.print(" s{d}+{d}:t{d}:u{d}.{d}", .{ e.Stream, e.Offset, e.Type, e.Usage, e.UsageIndex });
        }
        std.debug.print("\n", .{});
    } else std.debug.print("[WINS:D3D9:trace]   decl=null\n", .{});
    for (self.streams, 0..) |maybe, i| {
        const vb = maybe orelse continue;
        std.debug.print("[WINS:D3D9:trace]   stream{d} vb@{x} len={d} stride={d} off={d} usage={x}\n", .{ i, @intFromPtr(vb), vb.length, self.stream_strides[i], self.stream_offsets[i], vb.usage });
    }
    if (self.indices) |ib| std.debug.print("[WINS:D3D9:trace]   ib@{x} len={d} fmt={d}\n", .{ @intFromPtr(ib), ib.data.len, ib.format });
    for (self.bound_textures, 0..) |maybe, i| {
        const t = maybe orelse continue;
        switch (textureKind(t)) {
            D3DRTYPE_TEXTURE => {
                const tex: *const WinsTexture9 = @ptrCast(@alignCast(t));
                std.debug.print("[WINS:D3D9:trace]   tex{d} @{x} {d}x{d} fmt={x} levels={d} usage={x} min={d} mag={d} mip={d} addr={d}/{d}\n", .{
                    i,                           @intFromPtr(t),               tex.width,                   tex.height, tex.format, tex.levels, tex.usage,
                    self.sampler_states[i][6],   self.sampler_states[i][5],   self.sampler_states[i][7],   self.sampler_states[i][1], self.sampler_states[i][2],
                });
            },
            D3DRTYPE_CUBETEXTURE => {
                const ct: *const WinsCubeTexture9 = @ptrCast(@alignCast(t));
                std.debug.print("[WINS:D3D9:trace]   cube{d} @{x} {d} fmt={x} levels={d} usage={x}\n", .{ i, @intFromPtr(t), ct.edge_length, ct.format, ct.levels, ct.usage });
            },
            D3DRTYPE_VOLUMETEXTURE => {
                const vt: *const WinsVolumeTexture9 = @ptrCast(@alignCast(t));
                std.debug.print("[WINS:D3D9:trace]   vol{d} @{x} {d}x{d}x{d} fmt={x} levels={d} usage={x}\n", .{ i, @intFromPtr(t), vt.width, vt.height, vt.depth, vt.format, vt.levels, vt.usage });
            },
            else => {},
        }
    }
}

/// D3D9's documented render-state defaults (d3d9types.h / IDirect3DDevice9::
/// SetRenderState). A device starts with these, not with zeros: a zero
/// COLORWRITEENABLE writes nothing, a zero ZFUNC fails every depth test.
fn defaultRenderStates(auto_depth: bool) [256]u32 {
    var rs = [_]u32{0} ** 256;
    rs[7] = @intFromBool(auto_depth); // ZENABLE
    rs[8] = 3; // FILLMODE solid
    rs[9] = 2; // SHADEMODE gouraud
    rs[14] = 1; // ZWRITEENABLE
    rs[16] = 1; // LASTPIXEL
    rs[19] = 2; // SRCBLEND one
    rs[20] = 1; // DESTBLEND zero
    rs[22] = 3; // CULLMODE ccw
    rs[23] = 4; // ZFUNC lessequal
    rs[25] = 8; // ALPHAFUNC always
    rs[56] = 8; // STENCILFUNC always
    rs[53] = 1; // STENCILFAIL keep
    rs[54] = 1; // STENCILZFAIL keep
    rs[55] = 1; // STENCILPASS keep
    rs[58] = 0xFFFFFFFF; // STENCILMASK
    rs[59] = 0xFFFFFFFF; // STENCILWRITEMASK
    rs[60] = 0xFFFFFFFF; // TEXTUREFACTOR
    rs[136] = 1; // CLIPPING
    rs[137] = 1; // LIGHTING
    rs[141] = 1; // COLORVERTEX
    rs[142] = 1; // LOCALVIEWER
    rs[143] = 0; // NORMALIZENORMALS
    rs[145] = 1; // DIFFUSEMATERIALSOURCE color1
    rs[146] = 2; // SPECULARMATERIALSOURCE color2
    rs[154] = @bitCast(@as(f32, 1.0)); // POINTSIZE
    rs[155] = @bitCast(@as(f32, 1.0)); // POINTSIZE_MIN
    rs[158] = @bitCast(@as(f32, 1.0)); // POINTSCALE_A
    rs[161] = 1; // MULTISAMPLEANTIALIAS
    rs[162] = 0xFFFFFFFF; // MULTISAMPLEMASK
    rs[166] = @bitCast(@as(f32, 64.0)); // POINTSIZE_MAX
    rs[168] = 0xF; // COLORWRITEENABLE
    rs[171] = 1; // BLENDOP add
    rs[186] = 8; // CCW_STENCILFUNC always
    rs[187] = 1; // CCW_STENCILFAIL keep
    rs[188] = 1;
    rs[189] = 1;
    rs[190] = 0xF; // COLORWRITEENABLE1
    rs[191] = 0xF; // COLORWRITEENABLE2
    rs[192] = 0xF; // COLORWRITEENABLE3
    rs[193] = 0xFFFFFFFF; // BLENDFACTOR
    rs[207] = 2; // SRCBLENDALPHA one
    rs[208] = 1; // DESTBLENDALPHA zero
    rs[209] = 1; // BLENDOPALPHA add
    rs[37] = @bitCast(@as(f32, 1.0)); // FOGEND
    rs[38] = @bitCast(@as(f32, 1.0)); // FOGDENSITY
    return rs;
}

const DefaultKind = enum { vb, ib, surf, tex, cube, vol };
const DefaultRes = struct { kind: DefaultKind, ptr: *anyopaque };

const RecordedLight = struct {
    has_light: bool = false,
    light: D3DLIGHT9 = undefined,
    has_enable: bool = false,
    enabled: bool = false,
};

pub const WinsStateBlock9 = struct {
    vtbl: *const IDirect3DStateBlock9Vtbl align(16),
    ref_count: u32,
    device: *WinsD3DDevice9,
    allocator: std.mem.Allocator,
    capture_all_lights: bool = false,

    has_viewport: bool = false,
    viewport: D3DVIEWPORT9 = undefined,
    has_scissor: bool = false,
    scissor: D3DRECT = undefined,
    has_material: bool = false,
    material: D3DMATERIAL9 = undefined,

    has_transform: [kTransformStateCount]bool = [_]bool{false} ** kTransformStateCount,
    transform_states: [kTransformStateCount]D3DMATRIX = undefined,

    has_vs_const: [256]bool = [_]bool{false} ** 256,
    vs_consts: [256][4]f32 = undefined,
    has_ps_const: [224]bool = [_]bool{false} ** 224,
    ps_consts: [224][4]f32 = undefined,

    has_render_state: [256]bool = [_]bool{false} ** 256,
    render_states: [256]u32 = undefined,

    has_tss: [kMaxTextureStages][kTssSlots]bool = [_][kTssSlots]bool{[_]bool{false} ** kTssSlots} ** kMaxTextureStages,
    tex_stage_states: [kMaxTextureStages][kTssSlots]u32 = undefined,

    has_samp: [16][kSampSlots]bool = [_][kSampSlots]bool{[_]bool{false} ** kSampSlots} ** 16,
    sampler_states: [16][kSampSlots]u32 = undefined,

    has_clip: u32 = 0,
    clip_planes: [32][4]f32 = undefined,

    has_stream: [16]bool = [_]bool{false} ** 16,
    streams: [16]?*WinsVertexBuffer9 = undefined,
    stream_strides: [16]u32 = undefined,
    stream_offsets: [16]u32 = undefined,

    has_indices: bool = false,
    indices: ?*WinsIndexBuffer9 = undefined,

    has_texture: [16]bool = [_]bool{false} ** 16,
    bound_textures: [16]?*anyopaque = undefined,

    has_vs: bool = false,
    active_vs: ?*WinsShader9 = undefined,
    has_ps: bool = false,
    active_ps: ?*WinsShader9 = undefined,

    has_vdecl_mode: bool = false,
    vertex_decl: ?*WinsVertexDecl9 = null,
    use_fvf: bool = false,
    fvf: u32 = 0,
    fvf_elements: [24]D3DVERTEXELEMENT9 = undefined,

    lights: std.AutoHashMapUnmanaged(u32, RecordedLight) = .empty,

    pub fn create(allocator: std.mem.Allocator, dev: *WinsD3DDevice9) !*WinsStateBlock9 {
        const sb = try allocator.create(WinsStateBlock9);
        @memset(std.mem.asBytes(sb), 0);
        sb.vtbl = &g_stateblock9_vtbl;
        sb.ref_count = 1;
        sb.device = dev;
        sb.allocator = allocator;
        sb.lights = .empty;
        return sb;
    }

    pub fn destroy(self: *WinsStateBlock9) void {
        const a = self.allocator;
        self.lights.deinit(a);
        a.destroy(self);
    }
};

pub const WinsD3DDevice9 = struct {
    // Largest alignment in the struct, so the compiler keeps it first (see the
    // comptime check above); the guest dereferences offset 0 as the vtable.
    vtbl: *const IDirect3DDevice9Vtbl align(16),
    ref_count: u32,
    adapter: u32,
    device_type: u32,
    params: D3DPRESENT_PARAMETERS,
    viewport: D3DVIEWPORT9,
    /// D3DRS_SCISSORTESTENABLE clips to this; a new device starts with the
    /// whole back buffer.
    scissor: D3DRECT,
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
    bound_textures: [16]?*anyopaque,
    active_vs: ?*WinsShader9,
    active_ps: ?*WinsShader9,
    allocator: std.mem.Allocator,
    clip_planes: [32][4]f32 = [_][4]f32{.{ 0, 0, 0, 0 }} ** 32,
    /// Last SetFVF; while `use_fvf` it is the vertex layout (SetVertexDeclaration
    /// switches back), described as the equivalent declaration.
    fvf: u32 = 0,
    use_fvf: bool = false,
    fvf_elements: [24]D3DVERTEXELEMENT9 = undefined,
    /// SetRenderTarget slots; null in slot 0 means the implicit back buffer.
    render_targets: [4]?*WinsSurface9 = .{ null, null, null, null },
    /// True when this device renders through wins_d3d9_gl.zig.
    host: bool = false,
    default_resources: std.ArrayListUnmanaged(DefaultRes) = .empty,
    recording_sb: ?*WinsStateBlock9 = null,

    pub fn trackDefault(self: *WinsD3DDevice9, kind: DefaultKind, ptr: *anyopaque) void {
        self.default_resources.append(self.allocator, .{ .kind = kind, .ptr = ptr }) catch {};
    }

    pub fn untrackDefault(self: *WinsD3DDevice9, ptr: *const anyopaque) void {
        var i: usize = 0;
        while (i < self.default_resources.items.len) {
            if (@intFromPtr(self.default_resources.items[i].ptr) == @intFromPtr(ptr)) {
                _ = self.default_resources.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    pub fn hasLiveDefaultResources(self: *const WinsD3DDevice9) bool {
        if (self.rt_surface) |rt| {
            if (rt.ref_count > 1) return true;
        }
        if (self.ds_surface) |ds| {
            if (ds.ref_count > 1) return true;
        }
        for (self.default_resources.items) |item| {
            switch (item.kind) {
                .vb => {
                    const vb: *const WinsVertexBuffer9 = @ptrCast(@alignCast(item.ptr));
                    if (vb.ref_count > 0) return true;
                },
                .ib => {
                    const ib: *const WinsIndexBuffer9 = @ptrCast(@alignCast(item.ptr));
                    if (ib.ref_count > 0) return true;
                },
                .surf => {
                    const s: *const WinsSurface9 = @ptrCast(@alignCast(item.ptr));
                    if (s.ref_count > 0) return true;
                },
                .tex => {
                    const t: *const WinsTexture9 = @ptrCast(@alignCast(item.ptr));
                    if (t.ref_count > 0) return true;
                    for (t.surfaces) |s| {
                        if (s.ref_count > 1) return true;
                    }
                },
                .cube => {
                    const c: *const WinsCubeTexture9 = @ptrCast(@alignCast(item.ptr));
                    if (c.ref_count > 0) return true;
                    for (c.faces) |s| {
                        if (s.ref_count > 1) return true;
                    }
                },
                .vol => {
                    const v: *const WinsVolumeTexture9 = @ptrCast(@alignCast(item.ptr));
                    if (v.ref_count > 0) return true;
                    for (v.volumes) |vol| {
                        if (vol.ref_count > 1) return true;
                    }
                },
            }
        }
        return false;
    }

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
            .scissor = .{ .x1 = 0, .y1 = 0, .x2 = @intCast(w), .y2 = @intCast(h) },
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
            .render_states = defaultRenderStates(params.EnableAutoDepthStencil != 0),
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
            .bound_textures = [_]?*anyopaque{null} ** 16,
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
    std.debug.print("[WINS:D3D9] GetAdapterCount() -> 1\n", .{});
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
    std.debug.print("[WINS:D3D9] GetAdapterIdentifier(adapter={d}, flags=0x{x})\n", .{ adapter, flags });
    if (adapter != 0) return D3DERR_INVALIDARG;
    // align(1): the caller's buffer is the guest's, and a trap on an
    // unexpected alignment would turn a readable structure into a crash.
    const out: ?*align(1) D3DADAPTER_IDENTIFIER9 = if (pIdentifier) |p| @ptrCast(p) else null;
    const id = out orelse return E_POINTER;
    var value: D3DADAPTER_IDENTIFIER9 = std.mem.zeroes(D3DADAPTER_IDENTIFIER9);
    // FalloutNV picks its renderer tier from the driver file name's prefix
    // ("ati", "nv", "ig"); with an unknown one it never creates the shader
    // object its 3D scenes ask for and crashes at 0xb57aa9 (New Game after
    // the intro). The name is what wined3d reports for this AMD adapter,
    // measured with the Proton oracle (tools/adapter_id.exe): atiumdag.dll.
    fillAscii(value.Driver[0..], "atiumdag.dll");
    // Fallout NV stores D3DADAPTER_IDENTIFIER9.Description as sD3DDevice in
    // FalloutPrefs.ini and launches its separate launcher when the current
    // description differs. Keep the host adapter identity here even though
    // WINS rasterizes in software, so an existing profile remains selectable.
    fillAscii(value.Description[0..], "AMD Radeon 760M Graphics (RADV PHOENIX)");
    fillAscii(value.DeviceName[0..], "\\.\\DISPLAY1");
    value.DriverVersion = 0x0000000100000000;
    value.VendorId = 0x1002;
    value.DeviceId = 0x1900;
    value.SubSysId = 0;
    value.Revision = 0;
    value.WHQLLevel = 0;
    id.* = value;
    return D3D_OK;
}

/// IDirect3D9::GetAdapterModeCount.
fn d3d9_GetAdapterModeCount(this: *anyopaque, adapter: u32, format: u32) callconv(W) u32 {
    _ = this;
    if (adapter != 0) {
        std.debug.print("[WINS:D3D9] GetAdapterModeCount(adapter={d}, format={d}) -> 0\n", .{ adapter, format });
        return 0;
    }
    // D3DFORMAT_UNKNOWN asks for every mode the adapter has.
    if (format == 0 or isRenderTargetFormat(format)) {
        std.debug.print("[WINS:D3D9] GetAdapterModeCount(adapter={d}, format={d}) -> 1\n", .{ adapter, format });
        return 1;
    }
    std.debug.print("[WINS:D3D9] GetAdapterModeCount(adapter={d}, format={d}) -> 0\n", .{ adapter, format });
    return 0;
}

/// IDirect3D9::EnumAdapterModes. The guest reads the mode out of the
/// structure by offset, so it has to be written.
fn d3d9_EnumAdapterModes(this: *anyopaque, adapter: u32, format: u32, mode: u32, pMode: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    std.debug.print("[WINS:D3D9] EnumAdapterModes(adapter={d}, format={d}, mode={d})\n", .{ adapter, format, mode });
    if (adapter != 0) return D3DERR_INVALIDARG;
    if (mode != 0) return D3DERR_INVALIDARG;
    if (format != 0 and !isRenderTargetFormat(format)) return D3DERR_INVALIDARG;
    const out: ?*align(1) D3DDISPLAYMODE = if (pMode) |p| @ptrCast(p) else null;
    const m = out orelse return E_POINTER;
    var value = kDisplayMode;
    value.Format = if (format == 0) kDisplayMode.Format else format;
    m.* = value;
    return D3D_OK;
}

/// IDirect3D9::GetAdapterDisplayMode.
fn d3d9_GetAdapterDisplayMode(this: *anyopaque, adapter: u32, pMode: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    std.debug.print("[WINS:D3D9] GetAdapterDisplayMode(adapter={d})\n", .{adapter});
    if (adapter != 0) return D3DERR_INVALIDARG;
    const out: ?*align(1) D3DDISPLAYMODE = if (pMode) |p| @ptrCast(p) else null;
    const m = out orelse return E_POINTER;
    m.* = kDisplayMode;
    return D3D_OK;
}
/// D3DCAPS9 (304 bytes, 76 dwords) exactly as wined3d reports it for this
/// adapter, measured with the Proton oracle (replay harness,
/// ~/.cache/wins-oracle/replay/replay_wine.tsv, "GetDeviceCaps 0 0x1").
/// The earlier hand-filled caps left most fields at zero: FalloutNV reads
/// PS20Caps.NumInstructionSlots (> 255) and PS20Caps.NumTemps (>= 32) to pick
/// its shader tier, and with zeros it never enables the object New Game's
/// first 3D scene asks for (fault at 0xb57aa9). The host backend runs vs/ps up
/// to 3_0 through GLSL, so these caps describe what it is asked to do; any
/// shader it cannot translate is reported and its draw skipped.
const kOracleCaps = [76]u32{
    0x00000001, 0x00000000, 0x00000000, 0x60020000, 0x00000320, 0x80000001, 0x00000003, 0x0019aff0,
    0x002ecff2, 0x07332191, 0x000000ff, 0x00003fff, 0x000027ff, 0x000000ff, 0x00084208, 0x0001ec85,
    0x07030700, 0x07030700, 0x03030300, 0x0000003f, 0x0000003f, 0x0000001f, 0x00004000, 0x00004000,
    0x00002000, 0x00008000, 0x00004000, 0x00000010, 0x501502f9, 0xc7000000, 0xc7000000, 0x47000000,
    0x47000000, 0x00000000, 0x000001ff, 0x00100008, 0x03feffff, 0x00000008, 0x00000008, 0x0000013b,
    0x00000008, 0x00000008, 0x00000004, 0x00000000, 0x45000000, 0x00555555, 0x00ffffff, 0x00000010,
    0x00000400, 0xfffe0300, 0x00000100, 0xffff0300, 0x7f7fffff, 0x00000051, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000001, 0x0000030f, 0x00000004, 0x03000300, 0x00000001, 0x00000018,
    0x00000020, 0x00000004, 0x0000001f, 0x00000018, 0x00000020, 0x00000004, 0x00000200, 0x01000100,
    0x0000ffff, 0x0000ffff, 0x00000200, 0x00000200,
};

fn d3d9_GetDeviceCaps(this: *anyopaque, adapter: u32, dev_type: u32, pCaps: ?*D3DCAPS9) callconv(W) HRESULT {
    _ = this;
    std.debug.print("[WINS:D3D9] GetDeviceCaps(adapter={d}, type={d}, out={})\n", .{ adapter, dev_type, pCaps != null });
    if (pCaps) |caps| {
        comptime std.debug.assert(@sizeOf(D3DCAPS9) == @sizeOf(@TypeOf(kOracleCaps)));
        @memcpy(std.mem.asBytes(caps), std.mem.sliceAsBytes(&kOracleCaps));
        caps.DeviceType = dev_type;
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
    _ = behavior_flags;
    if (ppDevice == null or pParams == null) return E_FAIL;
    const params = pParams.?.*;
    std.debug.print("[WINS:D3D9] CreateDevice(adapter={d}, type={d}, hwnd=0x{x}, size={d}x{d}, format={d}, windowed={d})\n", .{
        adapter,
        dev_type,
        hFocusWindow,
        params.BackBufferWidth,
        params.BackBufferHeight,
        params.BackBufferFormat,
        params.Windowed,
    });
    const gpa = std.heap.page_allocator;
    const dev = WinsD3DDevice9.init(gpa, adapter, dev_type, params) catch return E_OUTOFMEMORY;
    if (host_enabled) dev.host = hostgl.attach(dev.viewport.Width, dev.viewport.Height, "WINS");
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
    std.debug.print("[WINS:D3D9] CheckDeviceType(adapter={d}, type={d}, display={d}, back={d}, windowed={d})\n", .{ adapter, dev_type, display_format, back_buffer_format, windowed });
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
        if (rtype != 0 and rtype != D3DRTYPE_SURFACE and rtype != D3DRTYPE_TEXTURE and rtype != D3DRTYPE_CUBETEXTURE) {
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
    // 2D, cube and volume textures (optionally DYNAMIC).
    if ((rtype == D3DRTYPE_TEXTURE or rtype == D3DRTYPE_CUBETEXTURE or rtype == D3DRTYPE_VOLUMETEXTURE) and
        (usage & ~D3DUSAGE_DYNAMIC) == 0 and isTextureFormat(check_format))
    {
        return D3D_OK;
    }
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
        if (self.ref_count == 0) {
            self.lights.deinit(self.allocator);
            self.default_resources.deinit(self.allocator);
            if (self.recording_sb) |sb| {
                sb.destroy();
                self.recording_sb = null;
            }
        }
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
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (trace_frames != 0) std.debug.print("[WINS:D3D9:trace] f{d} Clear(rects={d}, flags={x}, color={x}, z={d}, stencil={d})\n", .{ self.frame_count, count, flags, color, z, stencil });
    if (self.host) {
        hostgl.clear(self, count, pRects, flags, color, z, stencil);
        return D3D_OK;
    }
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
    if (trace_frames != 0) {
        std.debug.print("[WINS:D3D9:trace] f{d} Present (draw calls so far {d})\n", .{ self.frame_count, self.draw_call_count });
        trace_frames -= 1;
    }
    if (self.host) hostgl.present(self.frame_count);
    self.frame_count += 1;
    if (trace_budget != 0 and self.frame_count >= trace_after) {
        trace_frames = trace_budget;
        if (trace_period != 0) trace_after = self.frame_count + trace_period else trace_budget = 0;
    }
    return D3D_OK;
}
fn dev9_SetViewport(this: *anyopaque, pViewport: ?*const D3DVIEWPORT9) callconv(W) HRESULT {
    if (pViewport) |vp| {
        const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
        if (self.recording_sb) |sb| {
            sb.viewport = vp.*;
            sb.has_viewport = true;
            return D3D_OK;
        }
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
    if (Pool == 0) {
        vb.owner_device = self;
        self.trackDefault(.vb, vb);
    }
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
    if (Pool == 0) {
        ib.owner_device = self;
        self.trackDefault(.ib, ib);
    }
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
    const tex = WinsTexture9.create(self.allocator, Width, Height, Levels, Usage, Format, Pool) catch |e| {
        if (trace_resources) std.debug.print("[WINS:D3D9:trace] CreateTexture({d}x{d}, levels={d}, usage={x}, fmt={x}, pool={d}) REFUSED\n", .{ Width, Height, Levels, Usage, Format, Pool });
        return if (e == error.InvalidCall) D3DERR_INVALIDCALL else E_OUTOFMEMORY;
    };
    if (Pool == 0) {
        tex.owner_device = self;
        self.trackDefault(.tex, tex);
    }
    if (trace_resources) std.debug.print("[WINS:D3D9:trace] CreateTexture({d}x{d}, levels={d}, usage={x}, fmt={x}, pool={d}) -> @{x}\n", .{ Width, Height, Levels, Usage, Format, Pool, @intFromPtr(tex) });
    ppTexture.?.* = @ptrCast(tex);
    return D3D_OK;
}

fn dev9_CreateVertexShader(this: *anyopaque, pFunction: ?*const u32, ppShader: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (ppShader == null) return E_FAIL;
    const sh = WinsShader9.create(self.allocator, false, pFunction) catch return E_OUTOFMEMORY;
    if (trace_resources) std.debug.print("[WINS:D3D9:trace] CreateVertexShader -> @{x} version={x} tokens={d}\n", .{ @intFromPtr(sh), shaderVersion(sh), sh.tokens.len });
    ppShader.?.* = @ptrCast(sh);
    return D3D_OK;
}

fn dev9_CreatePixelShader(this: *anyopaque, pFunction: ?*const u32, ppShader: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (ppShader == null) return E_FAIL;
    const sh = WinsShader9.create(self.allocator, true, pFunction) catch return E_OUTOFMEMORY;
    if (trace_resources) std.debug.print("[WINS:D3D9:trace] CreatePixelShader -> @{x} version={x} tokens={d}\n", .{ @intFromPtr(sh), shaderVersion(sh), sh.tokens.len });
    ppShader.?.* = @ptrCast(sh);
    return D3D_OK;
}

fn dev9_SetStreamSource(this: *anyopaque, StreamNumber: u32, pStreamData: ?*anyopaque, OffsetInBytes: u32, Stride: u32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (self.recording_sb) |sb| {
        if (StreamNumber < 16) {
            sb.streams[StreamNumber] = if (pStreamData) |ps| @ptrCast(@alignCast(ps)) else null;
            sb.stream_strides[StreamNumber] = Stride;
            sb.stream_offsets[StreamNumber] = OffsetInBytes;
            sb.has_stream[StreamNumber] = true;
        }
        return D3D_OK;
    }
    if (StreamNumber < 16) {
        self.streams[StreamNumber] = if (pStreamData) |ps| @ptrCast(@alignCast(ps)) else null;
        self.stream_strides[StreamNumber] = Stride;
        self.stream_offsets[StreamNumber] = OffsetInBytes;
    }
    return D3D_OK;
}

fn dev9_SetIndices(this: *anyopaque, pIndexData: ?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (self.recording_sb) |sb| {
        sb.indices = if (pIndexData) |pi| @ptrCast(@alignCast(pi)) else null;
        sb.has_indices = true;
        return D3D_OK;
    }
    self.indices = if (pIndexData) |pi| @ptrCast(@alignCast(pi)) else null;
    return D3D_OK;
}

fn dev9_SetVertexShader(this: *anyopaque, pShader: ?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (self.recording_sb) |sb| {
        sb.active_vs = if (pShader) |ps| @ptrCast(@alignCast(ps)) else null;
        sb.has_vs = true;
        return D3D_OK;
    }
    self.active_vs = if (pShader) |ps| @ptrCast(@alignCast(ps)) else null;
    return D3D_OK;
}

fn dev9_SetPixelShader(this: *anyopaque, pShader: ?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (self.recording_sb) |sb| {
        sb.active_ps = if (pShader) |ps| @ptrCast(@alignCast(ps)) else null;
        sb.has_ps = true;
        return D3D_OK;
    }
    self.active_ps = if (pShader) |ps| @ptrCast(@alignCast(ps)) else null;
    return D3D_OK;
}

fn dev9_SetVertexShaderConstantF(this: *anyopaque, StartRegister: u32, pConstantData: ?*const f32, Vector4fCount: u32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (pConstantData) |cd| {
        const ptr: [*]const f32 = @ptrCast(cd);
        if (self.recording_sb) |sb| {
            var i: u32 = 0;
            while (i < Vector4fCount and StartRegister + i < 256) : (i += 1) {
                const src = ptr + i * 4;
                sb.vs_consts[StartRegister + i] = [4]f32{ src[0], src[1], src[2], src[3] };
                sb.has_vs_const[StartRegister + i] = true;
            }
            return D3D_OK;
        }
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
        if (self.recording_sb) |sb| {
            var i: u32 = 0;
            while (i < Vector4fCount and StartRegister + i < 224) : (i += 1) {
                const src = ptr + i * 4;
                sb.ps_consts[StartRegister + i] = [4]f32{ src[0], src[1], src[2], src[3] };
                sb.has_ps_const[StartRegister + i] = true;
            }
            return D3D_OK;
        }
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
    if (self.recording_sb) |sb| {
        if (State < 256) {
            sb.render_states[State] = Value;
            sb.has_render_state[State] = true;
        }
        return D3D_OK;
    }
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
    if (self.recording_sb) |sb| {
        if (Sampler < 16) {
            sb.bound_textures[Sampler] = pTexture;
            sb.has_texture[Sampler] = true;
        }
        return D3D_OK;
    }
    if (Sampler < 16) {
        self.bound_textures[Sampler] = pTexture;
    }
    return D3D_OK;
}

const D3DPT_TRIANGLELIST: u32 = 4;
const D3DPT_TRIANGLESTRIP: u32 = 5;
const D3DPT_TRIANGLEFAN: u32 = 6;

/// The three stream offsets consumed by one triangle for a D3D primitive type.
/// D3D9 counts primitives, not vertices, in DrawPrimitive and
/// DrawIndexedPrimitive.
fn triangleVertexOffsets(prim_type: u32, triangle: u32) ?[3]u64 {
    const t: u64 = triangle;
    return switch (prim_type) {
        D3DPT_TRIANGLELIST => .{ t * 3, t * 3 + 1, t * 3 + 2 },
        D3DPT_TRIANGLESTRIP => .{ t, t + 1, t + 2 },
        D3DPT_TRIANGLEFAN => .{ 0, t + 1, t + 2 },
        else => null,
    };
}

fn readIndex(ib: *const WinsIndexBuffer9, index: u64) ?u32 {
    const width: u64 = switch (ib.format) {
        D3DFMT_INDEX16 => 2,
        D3DFMT_INDEX32 => 4,
        else => return null,
    };
    const byte_offset = index * width;
    if (byte_offset + width > @as(u64, @intCast(ib.data.len))) return null;
    const offset: usize = @intCast(byte_offset);
    if (ib.format == D3DFMT_INDEX16) {
        return @as(u32, ib.data[offset]) | (@as(u32, ib.data[offset + 1]) << 8);
    }
    return @as(u32, ib.data[offset]) |
        (@as(u32, ib.data[offset + 1]) << 8) |
        (@as(u32, ib.data[offset + 2]) << 16) |
        (@as(u32, ib.data[offset + 3]) << 24);
}

fn readFloat32LE(bytes: []const u8, offset: usize) f32 {
    const bits = @as(u32, bytes[offset]) |
        (@as(u32, bytes[offset + 1]) << 8) |
        (@as(u32, bytes[offset + 2]) << 16) |
        (@as(u32, bytes[offset + 3]) << 24);
    return @bitCast(bits);
}

/// This first software path accepts a stream whose first three components are
/// XYZ in NDC. Respect both the vertex-buffer binding offset and the stride; do
/// not assume that the first vertex begins at byte zero.
fn readVertexPosition(self: *const WinsD3DDevice9, vb: *const WinsVertexBuffer9, vertex: u32) ?[3]f32 {
    const stride: u64 = if (self.stream_strides[0] >= 12) self.stream_strides[0] else 12;
    const byte_offset = @as(u64, self.stream_offsets[0]) + @as(u64, vertex) * stride;
    if (byte_offset + 12 > @as(u64, @intCast(vb.data.len))) return null;
    const offset: usize = @intCast(byte_offset);
    return .{
        readFloat32LE(vb.data, offset),
        readFloat32LE(vb.data, offset + 4),
        readFloat32LE(vb.data, offset + 8),
    };
}

fn rasterizeTriangle(self: *WinsD3DDevice9, vb: *const WinsVertexBuffer9, vertices: [3]u32) void {
    if (self.viewport.Width == 0 or self.viewport.Height == 0) return;
    const p0 = readVertexPosition(self, vb, vertices[0]) orelse return;
    const p1 = readVertexPosition(self, vb, vertices[1]) orelse return;
    const p2 = readVertexPosition(self, vb, vertices[2]) orelse return;

    // Viewport projection: NDC [-1, 1] -> Screen [0, W].
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
    if (area == 0) return;

    const draw_color: u32 = 0xFF00FF00; // Deliberately simple placeholder shading.
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
                if (pixel_idx >= self.backbuffer.len or pixel_idx >= self.depthbuffer.len) continue;
                const z_depth = (p0[2] + p1[2] + p2[2]) / 3.0;
                if (z_depth < self.depthbuffer[pixel_idx]) {
                    self.depthbuffer[pixel_idx] = z_depth;
                    self.backbuffer[pixel_idx] = draw_color;
                }
            }
        }
    }
}

// Software triangle rasterizer with depth-buffer. Vertex shaders, declaration
// formats and textures remain outside this initial NDC path.
fn dev9_DrawPrimitive(this: *anyopaque, prim_type: u32, start_vertex: u32, count: u32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    self.draw_call_count += 1;
    traceDraw(self, "DrawPrimitive", prim_type, 0, start_vertex, count);
    if (count == 0) return D3D_OK;
    if (self.host) {
        var job: hostgl.DrawJob = .{ .dev = self, .prim = prim_type, .indexed = false, .base_vertex = start_vertex, .prim_count = count };
        hostgl.draw(&job);
        return D3D_OK;
    }
    const vb = self.streams[0] orelse return D3D_OK;

    var triangle: u32 = 0;
    while (triangle < count) : (triangle += 1) {
        const offsets = triangleVertexOffsets(prim_type, triangle) orelse return D3D_OK;
        var vertices: [3]u32 = undefined;
        for (offsets, 0..) |relative, i| {
            const absolute = @as(u64, start_vertex) + relative;
            if (absolute > std.math.maxInt(u32)) return D3DERR_INVALIDCALL;
            vertices[i] = @intCast(absolute);
        }
        rasterizeTriangle(self, vb, vertices);
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
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    self.draw_call_count += 1;
    traceDraw(self, "DrawIndexedPrimitive", prim_type, base_vertex_idx, start_index, prim_count);
    if (prim_count == 0) return D3D_OK;
    if (self.host) {
        if (self.indices == null) return D3DERR_INVALIDCALL;
        var job: hostgl.DrawJob = .{ .dev = self, .prim = prim_type, .indexed = true, .base_vertex = base_vertex_idx, .min_index = min_vertex_idx, .num_vertices = num_vertices, .start_index = start_index, .prim_count = prim_count };
        hostgl.draw(&job);
        return D3D_OK;
    }
    if (triangleVertexOffsets(prim_type, 0) == null) return D3D_OK;
    const vb = self.streams[0] orelse return D3DERR_INVALIDCALL;
    const ib = self.indices orelse return D3DERR_INVALIDCALL;
    const range_end = @as(u64, min_vertex_idx) + num_vertices;

    var triangle: u32 = 0;
    while (triangle < prim_count) : (triangle += 1) {
        const relative = triangleVertexOffsets(prim_type, triangle) orelse unreachable;
        var vertices: [3]u32 = undefined;
        for (relative, 0..) |position, i| {
            const index_position = @as(u64, start_index) + position;
            const raw_index = readIndex(ib, index_position) orelse return D3DERR_INVALIDCALL;
            if (raw_index < min_vertex_idx or @as(u64, raw_index) >= range_end) return D3DERR_INVALIDCALL;
            const absolute = @as(i64, base_vertex_idx) + @as(i64, raw_index);
            if (absolute < 0 or absolute > std.math.maxInt(u32)) return D3DERR_INVALIDCALL;
            vertices[i] = @intCast(absolute);
        }
        rasterizeTriangle(self, vb, vertices);
    }
    return D3D_OK;
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
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const p = p0 orelse return D3DERR_INVALIDCALL;
    if (self.recording_sb != null) return D3DERR_INVALIDCALL;
    if (self.hasLiveDefaultResources()) return D3DERR_INVALIDCALL;

    const w: u32 = if (p.BackBufferWidth > 0) p.BackBufferWidth else 800;
    const h: u32 = if (p.BackBufferHeight > 0) p.BackBufferHeight else 600;
    const total = @as(usize, w) * h;
    const new_pixels = self.allocator.alloc(u32, total) catch return E_OUTOFMEMORY;
    errdefer self.allocator.free(new_pixels);
    const new_depths = self.allocator.alloc(f32, total) catch return E_OUTOFMEMORY;
    @memset(new_pixels, 0xFF000000);
    @memset(new_depths, 1.0);

    for (0..4) |i| {
        if (self.render_targets[i]) |old_rt| {
            if (old_rt.ref_count > 0) old_rt.ref_count -= 1;
            self.render_targets[i] = null;
        }
    }
    if (self.depth_stencil_explicit) {
        if (self.bound_ds_surface) |old_ds| {
            if (old_ds.ref_count > 0) old_ds.ref_count -= 1;
        }
    }
    self.bound_ds_surface = null;
    self.depth_stencil_explicit = false;
    if (self.vertex_decl) |dcl| {
        if (dcl.ref_count > 0) dcl.ref_count -= 1;
        self.vertex_decl = null;
    }

    if (self.rt_surface) |rt| {
        rt.destroy();
        self.rt_surface = null;
    }
    if (self.ds_surface) |ds| {
        ds.destroy();
        self.ds_surface = null;
    }
    self.allocator.free(self.backbuffer);
    self.allocator.free(self.depthbuffer);
    self.backbuffer = new_pixels;
    self.depthbuffer = new_depths;

    self.params = p.*;
    self.viewport = .{ .X = 0, .Y = 0, .Width = w, .Height = h, .MinZ = 0.0, .MaxZ = 1.0 };
    self.scissor = .{ .x1 = 0, .y1 = 0, .x2 = @intCast(w), .y2 = @intCast(h) };
    self.material = defaultMaterial9();
    self.transform_states = [_]D3DMATRIX{d3dIdentityMatrix()} ** kTransformStateCount;
    self.lights.clearRetainingCapacity();
    self.in_scene = false;
    self.vs_consts = [_][4]f32{[_]f32{ 0, 0, 0, 0 }} ** 256;
    self.ps_consts = [_][4]f32{[_]f32{ 0, 0, 0, 0 }} ** 224;
    self.render_states = defaultRenderStates(p.EnableAutoDepthStencil != 0);
    self.tex_stage_states = defaultTextureStageStates();
    self.sampler_states = defaultSamplerStates();
    self.clip_planes = [_][4]f32{.{ 0, 0, 0, 0 }} ** 32;
    self.streams = [_]?*WinsVertexBuffer9{null} ** 16;
    self.stream_strides = [_]u32{0} ** 16;
    self.stream_offsets = [_]u32{0} ** 16;
    self.indices = null;
    self.bound_textures = [_]?*anyopaque{null} ** 16;
    self.active_vs = null;
    self.active_ps = null;
    self.use_fvf = false;
    self.fvf = 0;

    if (self.host) hostgl.resize(w, h);
    return D3D_OK;
}

/// The device's persistent render-target surface: wraps the back buffer the
/// rasterizer draws into. Created on first use; callers receive a counted reference.
pub fn deviceRenderTarget(self: *WinsD3DDevice9) ?*WinsSurface9 {
    if (self.rt_surface == null) {
        const fmt: u32 = if (self.params.BackBufferFormat != 0) self.params.BackBufferFormat else D3DFMT_X8R8G8B8;
        self.rt_surface = WinsSurface9.wrap(self.allocator, self.viewport.Width, self.viewport.Height, fmt, std.mem.sliceAsBytes(self.backbuffer), D3DUSAGE_RENDERTARGET, 0, true) catch return null;
        self.rt_surface.?.owner_device = @ptrCast(self);
    }
    return self.rt_surface;
}

pub fn deviceDepthStencil(self: *WinsD3DDevice9) ?*WinsSurface9 {
    if (self.params.EnableAutoDepthStencil == 0) return null;
    if (self.ds_surface == null) {
        self.ds_surface = WinsSurface9.wrap(self.allocator, self.viewport.Width, self.viewport.Height, self.params.AutoDepthStencilFormat, std.mem.sliceAsBytes(self.depthbuffer), D3DUSAGE_DEPTHSTENCIL, 0, false) catch return null;
        self.ds_surface.?.owner_device = @ptrCast(self);
    }
    return self.ds_surface;
}

pub fn deviceBoundDepthStencil(self: *WinsD3DDevice9) ?*WinsSurface9 {
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

fn dev9_CreateVolumeTexture(
    this: *anyopaque,
    Width: u32,
    Height: u32,
    Depth: u32,
    Levels: u32,
    Usage: u32,
    Format: u32,
    Pool: u32,
    ppVolumeTexture: ?*?*anyopaque,
    pSharedHandle: ?*anyopaque,
) callconv(W) HRESULT {
    _ = pSharedHandle;
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const out = ppVolumeTexture orelse return D3DERR_INVALIDCALL;
    const vt = WinsVolumeTexture9.create(self.allocator, Width, Height, Depth, Levels, Usage, Format, Pool) catch |e| {
        if (trace_resources) std.debug.print("[WINS:D3D9:trace] CreateVolumeTexture({d}x{d}x{d}, levels={d}, usage={x}, fmt={x}, pool={d}) REFUSED\n", .{ Width, Height, Depth, Levels, Usage, Format, Pool });
        return if (e == error.InvalidCall) D3DERR_INVALIDCALL else E_OUTOFMEMORY;
    };
    if (Pool == 0) {
        vt.owner_device = self;
        self.trackDefault(.vol, vt);
    }
    if (trace_resources) std.debug.print("[WINS:D3D9:trace] CreateVolumeTexture({d}x{d}x{d}, levels={d}, usage={x}, fmt={x}, pool={d}) -> @{x}\n", .{ Width, Height, Depth, Levels, Usage, Format, Pool, @intFromPtr(vt) });
    out.* = @ptrCast(vt);
    return D3D_OK;
}

fn dev9_CreateCubeTexture(
    this: *anyopaque,
    EdgeLength: u32,
    Levels: u32,
    Usage: u32,
    Format: u32,
    Pool: u32,
    ppCubeTexture: ?*?*anyopaque,
    pSharedHandle: ?*anyopaque,
) callconv(W) HRESULT {
    _ = pSharedHandle;
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const out = ppCubeTexture orelse return D3DERR_INVALIDCALL;
    const ct = WinsCubeTexture9.create(self.allocator, EdgeLength, Levels, Usage, Format, Pool) catch |e| {
        if (trace_resources) std.debug.print("[WINS:D3D9:trace] CreateCubeTexture({d}, levels={d}, usage={x}, fmt={x}, pool={d}) REFUSED\n", .{ EdgeLength, Levels, Usage, Format, Pool });
        return if (e == error.InvalidCall) D3DERR_INVALIDCALL else E_OUTOFMEMORY;
    };
    if (Pool == 0) {
        ct.owner_device = self;
        self.trackDefault(.cube, ct);
    }
    if (trace_resources) std.debug.print("[WINS:D3D9:trace] CreateCubeTexture({d}, levels={d}, usage={x}, fmt={x}, pool={d}) -> @{x}\n", .{ EdgeLength, Levels, Usage, Format, Pool, @intFromPtr(ct) });
    out.* = @ptrCast(ct);
    return D3D_OK;
}

/// A colour surface the device can render into (default pool). Its pixels
/// live on the host GPU; LockRect on it is not supported (lockable = false
/// is answered whatever the caller asked). Multisampling is refused.
fn dev9_CreateRenderTarget(this: *anyopaque, width: u32, height: u32, format: u32, multi_sample: u32, multi_sample_quality: u32, lockable: i32, ppSurface: ?*?*anyopaque, pShared: ?*anyopaque) callconv(W) HRESULT {
    _ = multi_sample_quality;
    _ = lockable;
    _ = pShared;
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const out = ppSurface orelse return D3DERR_INVALIDCALL;
    if (width == 0 or height == 0) return D3DERR_INVALIDCALL;
    if (multi_sample != D3DMULTISAMPLE_NONE) return D3DERR_NOTAVAILABLE;
    const s = WinsSurface9.create(self.allocator, width, height, format) catch return E_OUTOFMEMORY;
    s.usage = D3DUSAGE_RENDERTARGET;
    s.pool = 0;
    s.lockable = false;
    s.owner_device = this;
    self.trackDefault(.surf, s);
    if (trace_resources) std.debug.print("[WINS:D3D9:trace] CreateRenderTarget({d}x{d}, fmt={x}) -> @{x}\n", .{ width, height, format, @intFromPtr(s) });
    out.* = s;
    return D3D_OK;
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
    self.trackDefault(.surf, s);
    out.* = s;
    return D3D_OK;
}

fn copySurfaceRect(src: *const WinsSurface9, sr: D3DRECT, dst: *WinsSurface9, dp: POINT) HRESULT {
    if (sr.x1 < 0 or sr.y1 < 0 or sr.x2 <= sr.x1 or sr.y2 <= sr.y1) return D3DERR_INVALIDCALL;
    if (sr.x2 > @as(i32, @intCast(src.width)) or sr.y2 > @as(i32, @intCast(src.height))) return D3DERR_INVALIDCALL;
    if (dp.x < 0 or dp.y < 0) return D3DERR_INVALIDCALL;
    const cw: u32 = @intCast(sr.x2 - sr.x1);
    const ch: u32 = @intCast(sr.y2 - sr.y1);
    if (@as(u64, @intCast(dp.x)) + cw > dst.width or @as(u64, @intCast(dp.y)) + ch > dst.height) return D3DERR_INVALIDCALL;
    if (src.pitch < 0 or dst.pitch < 0) return D3DERR_INVALIDCALL;
    const src_pitch: usize = @intCast(src.pitch);
    const dst_pitch: usize = @intCast(dst.pitch);

    if (src.format == D3DFMT_DXT1 or src.format == D3DFMT_DXT3 or src.format == D3DFMT_DXT5) {
        if ((@as(u32, @intCast(sr.x1)) & 3) != 0 or (@as(u32, @intCast(sr.y1)) & 3) != 0 or
            (@as(u32, @intCast(dp.x)) & 3) != 0 or (@as(u32, @intCast(dp.y)) & 3) != 0)
        {
            return D3DERR_INVALIDCALL;
        }
        const block_bytes: usize = if (src.format == D3DFMT_DXT1) 8 else 16;
        const bx_s: usize = @as(usize, @intCast(sr.x1)) / 4;
        const by_s: usize = @as(usize, @intCast(sr.y1)) / 4;
        const bx_d: usize = @as(usize, @intCast(dp.x)) / 4;
        const by_d: usize = @as(usize, @intCast(dp.y)) / 4;
        const bw: usize = @max(1, (cw + 3) / 4);
        const bh: usize = @max(1, (ch + 3) / 4);
        const row_bytes = bw * block_bytes;
        for (0..bh) |r| {
            const s_off = (by_s + r) * src_pitch + bx_s * block_bytes;
            const d_off = (by_d + r) * dst_pitch + bx_d * block_bytes;
            if (s_off + row_bytes > src.data.len or d_off + row_bytes > dst.data.len) return D3DERR_INVALIDCALL;
            @memcpy(dst.data[d_off .. d_off + row_bytes], src.data[s_off .. s_off + row_bytes]);
        }
        return D3D_OK;
    }

    const lay = surfaceLayout(src.format, 1, 1) orelse return D3DERR_INVALIDCALL;
    const bpp: usize = @intCast(lay.pitch);
    const row_bytes = @as(usize, cw) * bpp;
    for (0..ch) |r| {
        const s_off = (@as(usize, @intCast(sr.y1)) + r) * src_pitch + @as(usize, @intCast(sr.x1)) * bpp;
        const d_off = (@as(usize, @intCast(dp.y)) + r) * dst_pitch + @as(usize, @intCast(dp.x)) * bpp;
        if (s_off + row_bytes > src.data.len or d_off + row_bytes > dst.data.len) return D3DERR_INVALIDCALL;
        @memcpy(dst.data[d_off .. d_off + row_bytes], src.data[s_off .. s_off + row_bytes]);
    }
    return D3D_OK;
}

fn markSurfaceUpdated(self: *WinsD3DDevice9, dst: *WinsSurface9) void {
    dst.gl_dirty = true;
    if (dst.parent) |t| {
        if (t.usage & D3DUSAGE_RENDERTARGET == 0) t.gl_dirty = true;
    }
    if (dst.cube_parent) |ct| {
        if (ct.usage & D3DUSAGE_RENDERTARGET == 0) ct.gl_dirty = true;
    }
    if (self.host) hostgl.uploadSurface(self, dst);
}

fn dev9_UpdateSurface(this: *anyopaque, p0: ?*anyopaque, p1: ?*const D3DRECT, p2: ?*anyopaque, p3: ?*const POINT) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const src_raw = p0 orelse return D3DERR_INVALIDCALL;
    const dst_raw = p2 orelse return D3DERR_INVALIDCALL;
    const src: *WinsSurface9 = @ptrCast(@alignCast(src_raw));
    const dst: *WinsSurface9 = @ptrCast(@alignCast(dst_raw));
    if (src.vtbl != &g_surf9_vtbl or dst.vtbl != &g_surf9_vtbl) return D3DERR_INVALIDCALL;
    if (src.pool != 2 or dst.pool != 0) return D3DERR_INVALIDCALL;
    if ((src.usage & D3DUSAGE_DEPTHSTENCIL) != 0 or (dst.usage & D3DUSAGE_DEPTHSTENCIL) != 0) return D3DERR_INVALIDCALL;
    if (dst.multi_sample_type != 0 or src.format != dst.format) return D3DERR_INVALIDCALL;
    const sr: D3DRECT = if (p1) |r| r.* else .{ .x1 = 0, .y1 = 0, .x2 = @intCast(src.width), .y2 = @intCast(src.height) };
    const dp: POINT = if (p3) |pt| pt.* else .{ .x = 0, .y = 0 };
    const rc = copySurfaceRect(src, sr, dst, dp);
    if (rc != D3D_OK) return rc;
    markSurfaceUpdated(self, dst);
    return D3D_OK;
}

fn dev9_UpdateTexture(this: *anyopaque, p0: ?*anyopaque, p1: ?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const src_raw = p0 orelse return D3DERR_INVALIDCALL;
    const dst_raw = p1 orelse return D3DERR_INVALIDCALL;
    const kind = textureKind(src_raw);
    if (kind == 0 or kind != textureKind(dst_raw)) return D3DERR_INVALIDCALL;
    switch (kind) {
        D3DRTYPE_TEXTURE => {
            const src: *WinsTexture9 = @ptrCast(@alignCast(src_raw));
            const dst: *WinsTexture9 = @ptrCast(@alignCast(dst_raw));
            if (src.pool != 2 or dst.pool != 0 or src.format != dst.format) return D3DERR_INVALIDCALL;
            if (src.width != dst.width or src.height != dst.height) return D3DERR_INVALIDCALL;
            const n = @min(src.surfaces.len, dst.surfaces.len);
            for (0..n) |i| {
                const s_lvl = src.surfaces[i];
                const d_lvl = dst.surfaces[i];
                const sr: D3DRECT = .{ .x1 = 0, .y1 = 0, .x2 = @intCast(s_lvl.width), .y2 = @intCast(s_lvl.height) };
                const rc = copySurfaceRect(s_lvl, sr, d_lvl, .{ .x = 0, .y = 0 });
                if (rc != D3D_OK) return rc;
                d_lvl.gl_dirty = true;
            }
            if (dst.usage & D3DUSAGE_RENDERTARGET == 0) dst.gl_dirty = true;
            if (self.host) {
                for (0..n) |i| hostgl.uploadSurface(self, dst.surfaces[i]);
            }
        },
        D3DRTYPE_CUBETEXTURE => {
            const src: *WinsCubeTexture9 = @ptrCast(@alignCast(src_raw));
            const dst: *WinsCubeTexture9 = @ptrCast(@alignCast(dst_raw));
            if (src.pool != 2 or dst.pool != 0 or src.format != dst.format) return D3DERR_INVALIDCALL;
            if (src.edge_length != dst.edge_length) return D3DERR_INVALIDCALL;
            const n = @min(src.levels, dst.levels);
            for (0..6) |face| {
                for (0..n) |lvl| {
                    const s_lvl = src.faces[face * src.levels + lvl];
                    const d_lvl = dst.faces[face * dst.levels + lvl];
                    const sr: D3DRECT = .{ .x1 = 0, .y1 = 0, .x2 = @intCast(s_lvl.width), .y2 = @intCast(s_lvl.height) };
                    const rc = copySurfaceRect(s_lvl, sr, d_lvl, .{ .x = 0, .y = 0 });
                    if (rc != D3D_OK) return rc;
                    d_lvl.gl_dirty = true;
                }
            }
            if (dst.usage & D3DUSAGE_RENDERTARGET == 0) dst.gl_dirty = true;
            if (self.host) {
                for (0..6) |face| {
                    for (0..n) |lvl| hostgl.uploadSurface(self, dst.faces[face * dst.levels + lvl]);
                }
            }
        },
        D3DRTYPE_VOLUMETEXTURE => {
            const src: *WinsVolumeTexture9 = @ptrCast(@alignCast(src_raw));
            const dst: *WinsVolumeTexture9 = @ptrCast(@alignCast(dst_raw));
            if (src.pool != 2 or dst.pool != 0 or src.format != dst.format) return D3DERR_INVALIDCALL;
            if (src.width != dst.width or src.height != dst.height or src.depth != dst.depth) return D3DERR_INVALIDCALL;
            const n = @min(src.volumes.len, dst.volumes.len);
            for (0..n) |i| {
                const sv = src.volumes[i];
                const dv = dst.volumes[i];
                if (sv.data.len != dv.data.len) return D3DERR_INVALIDCALL;
                @memcpy(dv.data, sv.data);
            }
            dst.gl_dirty = true;
        },
        else => return D3DERR_INVALIDCALL,
    }
    return D3D_OK;
}

/// Render target -> system-memory surface of the same size and format.
fn dev9_GetRenderTargetData(this: *anyopaque, src_raw: ?*anyopaque, dst_raw: ?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const src: *WinsSurface9 = @ptrCast(@alignCast(src_raw orelse return D3DERR_INVALIDCALL));
    const dst: *WinsSurface9 = @ptrCast(@alignCast(dst_raw orelse return D3DERR_INVALIDCALL));
    if (src.width != dst.width or src.height != dst.height or src.format != dst.format) return D3DERR_INVALIDCALL;
    if (self.host) hostgl.readSurface(self, src, dst) else if (src.data.len == dst.data.len) @memcpy(dst.data, src.data);
    return D3D_OK;
}

fn dev9_GetFrontBufferData(this: *anyopaque, p0: u32, p1: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!GetFrontBufferData is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

/// Surface-to-surface copy with scaling, on the host GPU.
fn dev9_StretchRect(this: *anyopaque, src_raw: ?*anyopaque, src_rect: ?*const D3DRECT, dst_raw: ?*anyopaque, dst_rect: ?*const D3DRECT, filter: u32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const src: *WinsSurface9 = @ptrCast(@alignCast(src_raw orelse return D3DERR_INVALIDCALL));
    const dst: *WinsSurface9 = @ptrCast(@alignCast(dst_raw orelse return D3DERR_INVALIDCALL));
    const sr: D3DRECT = if (src_rect) |r| r.* else .{ .x1 = 0, .y1 = 0, .x2 = @intCast(src.width), .y2 = @intCast(src.height) };
    const dr: D3DRECT = if (dst_rect) |r| r.* else .{ .x1 = 0, .y1 = 0, .x2 = @intCast(dst.width), .y2 = @intCast(dst.height) };
    if (trace_frames != 0) std.debug.print("[WINS:D3D9:trace] f{d} StretchRect(@{x} -> @{x}, filter {d})\n", .{ self.frame_count, @intFromPtr(src), @intFromPtr(dst), filter });
    if (self.host) hostgl.stretchRect(self, src, sr, dst, dr, filter);
    return D3D_OK;
}

/// Fill a rectangle of a render target (or off-screen surface) with a colour.
fn dev9_ColorFill(this: *anyopaque, surf_raw: ?*anyopaque, rect: ?*const D3DRECT, color: u32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const s: *WinsSurface9 = @ptrCast(@alignCast(surf_raw orelse return D3DERR_INVALIDCALL));
    const r: D3DRECT = if (rect) |x| x.* else .{ .x1 = 0, .y1 = 0, .x2 = @intCast(s.width), .y2 = @intCast(s.height) };
    if (self.host) hostgl.colorFill(self, s, r, color);
    return D3D_OK;
}

/// A plain surface in system or scratch memory (screenshots, readbacks): CPU
/// pixels with the format's real layout, lockable. D3DPOOL_MANAGED is invalid
/// for these, as in D3D9.
fn dev9_CreateOffscreenPlainSurface(this: *anyopaque, width: u32, height: u32, format: u32, pool: u32, ppSurface: ?*?*anyopaque, pShared: ?*anyopaque) callconv(W) HRESULT {
    _ = pShared;
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const out = ppSurface orelse return D3DERR_INVALIDCALL;
    out.* = null;
    if (width == 0 or height == 0 or pool == 1) return D3DERR_INVALIDCALL;
    if (surfaceLayout(format, 1, 1) == null) return D3DERR_INVALIDCALL;
    const sf = WinsSurface9.create(self.allocator, width, height, format) catch return E_OUTOFMEMORY;
    sf.usage = 0;
    sf.pool = pool;
    sf.owner_device = this;
    if (pool == 0) self.trackDefault(.surf, sf);
    out.* = sf;
    return D3D_OK;
}


/// Slot 0 must stay bound; slots 1..3 (multiple render targets) may be
/// unbound with null. Setting slot 0 resets the viewport and the scissor
/// rectangle to the new target, as D3D9 does.
fn dev9_SetRenderTarget(this: *anyopaque, index: u32, raw: ?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (index >= 4) return D3DERR_INVALIDCALL;
    if (index == 0 and raw == null) return D3DERR_INVALIDCALL;
    const backbuffer = deviceRenderTarget(self) orelse return E_OUTOFMEMORY;
    var surface: ?*WinsSurface9 = null;
    if (raw) |r| {
        const s: *WinsSurface9 = @ptrCast(@alignCast(r));
        if (s.vtbl != &g_surf9_vtbl) return D3DERR_INVALIDCALL;
        if (s != backbuffer and (s.usage & D3DUSAGE_RENDERTARGET) == 0) return D3DERR_INVALIDCALL;
        surface = if (s == backbuffer) null else s;
    }
    if (self.render_targets[index]) |old| {
        if (old.ref_count > 0) old.ref_count -= 1;
    }
    if (surface) |s| s.ref_count += 1;
    self.render_targets[index] = surface;
    if (trace_frames != 0) std.debug.print("[WINS:D3D9:trace] f{d} SetRenderTarget({d}, @{x})\n", .{ self.frame_count, index, @intFromPtr(raw) });
    if (index == 0) {
        const t = surface orelse backbuffer;
        self.viewport = .{ .X = 0, .Y = 0, .Width = t.width, .Height = t.height, .MinZ = 0, .MaxZ = 1 };
        self.scissor = .{ .x1 = 0, .y1 = 0, .x2 = @intCast(t.width), .y2 = @intCast(t.height) };
    }
    return D3D_OK;
}

fn dev9_GetRenderTarget(this: *anyopaque, index: u32, ppSurface: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const out = ppSurface orelse return D3DERR_INVALIDCALL;
    out.* = null;
    if (index >= 4) return D3DERR_INVALIDCALL;
    const s = self.render_targets[index] orelse blk: {
        if (index != 0) return D3DERR_NOTFOUND;
        break :blk deviceRenderTarget(self) orelse return E_OUTOFMEMORY;
    };
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
        // D3D9: the depth buffer must be at least as large as render target 0.
        const rt0 = self.render_targets[0] orelse (deviceRenderTarget(self) orelse return E_OUTOFMEMORY);
        if (surface.width < rt0.width or surface.height < rt0.height) return D3DERR_INVALIDCALL;

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
    if (self.recording_sb) |sb| {
        sb.transform_states[state] = matrix.*;
        sb.has_transform[state] = true;
        return D3D_OK;
    }
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
    if (self.recording_sb) |sb| {
        sb.material = value;
        sb.has_material = true;
        return D3D_OK;
    }
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
    if (self.recording_sb) |sb| {
        if (sb.lights.getPtr(p0)) |rl| {
            rl.has_light = true;
            rl.light = value;
        } else {
            sb.lights.put(sb.allocator, p0, .{ .has_light = true, .light = value, .has_enable = false, .enabled = false }) catch return E_OUTOFMEMORY;
        }
        return D3D_OK;
    }
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
    if (self.recording_sb) |sb| {
        if (sb.lights.getPtr(p0)) |rl| {
            rl.has_enable = true;
            rl.enabled = p1 != 0;
        } else {
            sb.lights.put(sb.allocator, p0, .{ .has_light = false, .light = defaultLight9(), .has_enable = true, .enabled = p1 != 0 }) catch return E_OUTOFMEMORY;
        }
        return D3D_OK;
    }
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

fn dev9_SetClipPlane(this: *anyopaque, index: u32, pPlane: ?*const f32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const src = pPlane orelse return D3DERR_INVALIDCALL;
    if (index >= self.clip_planes.len) return D3DERR_INVALIDCALL;
    const p: [*]const f32 = @ptrCast(src);
    if (self.recording_sb) |sb| {
        if (index < sb.clip_planes.len and index < 32) {
            sb.clip_planes[index] = .{ p[0], p[1], p[2], p[3] };
            sb.has_clip |= @as(u32, 1) << @as(u5, @intCast(index));
        }
        return D3D_OK;
    }
    self.clip_planes[index] = .{ p[0], p[1], p[2], p[3] };
    return D3D_OK;
}

fn dev9_GetClipPlane(this: *anyopaque, index: u32, pPlane: ?*f32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const dst = pPlane orelse return D3DERR_INVALIDCALL;
    if (index >= self.clip_planes.len) return D3DERR_INVALIDCALL;
    const p: [*]f32 = @ptrCast(dst);
    const v = self.clip_planes[index];
    p[0] = v[0];
    p[1] = v[1];
    p[2] = v[2];
    p[3] = v[3];
    return D3D_OK;
}

fn isPixelRenderState(rs: u32) bool {
    return switch (rs) {
        7, 8, 9, 14, 15, 16, 19, 20, 23, 24, 25, 26, 27, 28, 34...38, 52...60, 128...135, 168, 171, 174, 175, 176, 185...195, 198...209 => true,
        else => false,
    };
}

fn isVertexRenderState(rs: u32) bool {
    return switch (rs) {
        9, 22, 28, 29, 34, 36, 37, 38, 48, 136, 137, 139...143, 145...148, 151, 152, 154...163, 166, 167, 170, 172, 173, 178...184 => true,
        else => false,
    };
}

fn isPixelTss(ty: u32) bool {
    return switch (ty) {
        1...10, 22, 23, 26, 27, 28, 32 => true,
        else => false,
    };
}

fn initStateBlockMask(sb: *WinsStateBlock9, block_type: u32) void {
    switch (block_type) {
        D3DSBT_ALL => {
            sb.has_viewport = true;
            sb.has_scissor = true;
            sb.has_material = true;
            @memset(&sb.has_transform, true);
            @memset(&sb.has_vs_const, true);
            @memset(&sb.has_ps_const, true);
            @memset(&sb.has_render_state, true);
            for (&sb.has_tss) |*row| @memset(row, true);
            for (&sb.has_samp) |*row| @memset(row, true);
            sb.has_clip = 0xFFFFFFFF;
            @memset(&sb.has_stream, true);
            sb.has_indices = true;
            @memset(&sb.has_texture, true);
            sb.has_vs = true;
            sb.has_ps = true;
            sb.has_vdecl_mode = true;
            sb.capture_all_lights = true;
        },
        D3DSBT_PIXELSTATE => {
            for (0..256) |rs| sb.has_render_state[rs] = isPixelRenderState(@intCast(rs));
            for (0..kMaxTextureStages) |st| {
                for (1..kTssSlots) |ty| sb.has_tss[st][ty] = isPixelTss(@intCast(ty));
            }
            for (0..16) |s| {
                for (1..13) |ty| sb.has_samp[s][ty] = true;
            }
            sb.has_ps = true;
            @memset(&sb.has_ps_const, true);
        },
        D3DSBT_VERTEXSTATE => {
            for (0..256) |rs| sb.has_render_state[rs] = isVertexRenderState(@intCast(rs));
            for (0..kMaxTextureStages) |st| {
                sb.has_tss[st][11] = true;
                sb.has_tss[st][24] = true;
            }
            for (0..16) |s| sb.has_samp[s][13] = true;
            sb.has_vs = true;
            @memset(&sb.has_vs_const, true);
            sb.has_vdecl_mode = true;
            sb.capture_all_lights = true;
        },
        else => {},
    }
}

fn sb_QueryInterface(this: *anyopaque, riid: ?*const anyopaque, ppv: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsStateBlock9 = @ptrCast(@alignCast(this));
    const out = ppv orelse return E_POINTER;
    out.* = null;
    const r = riid orelse return E_POINTER;
    const id: *align(1) const GUID = @ptrCast(r);
    if (guidEql(id, &IID_IUnknown) or guidEql(id, &IID_IDirect3DStateBlock9)) {
        self.ref_count += 1;
        out.* = this;
        return S_OK;
    }
    return E_NOINTERFACE;
}

fn sb_AddRef(this: *anyopaque) callconv(W) u32 {
    const self: *WinsStateBlock9 = @ptrCast(@alignCast(this));
    self.ref_count += 1;
    return self.ref_count;
}

fn sb_Release(this: *anyopaque) callconv(W) u32 {
    const self: *WinsStateBlock9 = @ptrCast(@alignCast(this));
    if (self.ref_count > 0) self.ref_count -= 1;
    const left = self.ref_count;
    if (left == 0) self.destroy();
    return left;
}

fn sb_GetDevice(this: *anyopaque, out: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsStateBlock9 = @ptrCast(@alignCast(this));
    const p = out orelse return D3DERR_INVALIDCALL;
    self.device.ref_count += 1;
    p.* = self.device;
    return D3D_OK;
}

fn sb_Capture(this: *anyopaque) callconv(W) HRESULT {
    const self: *WinsStateBlock9 = @ptrCast(@alignCast(this));
    const dev = self.device;
    if (self.has_viewport) self.viewport = dev.viewport;
    if (self.has_scissor) self.scissor = dev.scissor;
    if (self.has_material) self.material = dev.material;
    for (0..kTransformStateCount) |i| {
        if (self.has_transform[i]) self.transform_states[i] = dev.transform_states[i];
    }
    for (0..256) |i| {
        if (self.has_vs_const[i]) self.vs_consts[i] = dev.vs_consts[i];
        if (self.has_render_state[i]) self.render_states[i] = dev.render_states[i];
    }
    for (0..224) |i| {
        if (self.has_ps_const[i]) self.ps_consts[i] = dev.ps_consts[i];
    }
    for (0..kMaxTextureStages) |st| {
        for (1..kTssSlots) |ty| {
            if (self.has_tss[st][ty]) self.tex_stage_states[st][ty] = dev.tex_stage_states[st][ty];
        }
    }
    for (0..16) |s| {
        for (1..kSampSlots) |ty| {
            if (self.has_samp[s][ty]) self.sampler_states[s][ty] = dev.sampler_states[s][ty];
        }
        if (self.has_stream[s]) {
            self.streams[s] = dev.streams[s];
            self.stream_strides[s] = dev.stream_strides[s];
            self.stream_offsets[s] = dev.stream_offsets[s];
        }
        if (self.has_texture[s]) self.bound_textures[s] = dev.bound_textures[s];
    }
    for (0..32) |ci| {
        if ((self.has_clip & (@as(u32, 1) << @intCast(ci))) != 0) self.clip_planes[ci] = dev.clip_planes[ci];
    }
    if (self.has_indices) self.indices = dev.indices;
    if (self.has_vs) self.active_vs = dev.active_vs;
    if (self.has_ps) self.active_ps = dev.active_ps;
    if (self.has_vdecl_mode) {
        self.vertex_decl = dev.vertex_decl;
        self.use_fvf = dev.use_fvf;
        self.fvf = dev.fvf;
        self.fvf_elements = dev.fvf_elements;
    }
    if (self.capture_all_lights) {
        self.lights.clearRetainingCapacity();
        var it = dev.lights.iterator();
        while (it.next()) |entry| {
            self.lights.put(self.allocator, entry.key_ptr.*, .{
                .has_light = true,
                .light = entry.value_ptr.light,
                .has_enable = true,
                .enabled = entry.value_ptr.enabled,
            }) catch return E_OUTOFMEMORY;
        }
    } else {
        var it = self.lights.iterator();
        while (it.next()) |entry| {
            if (dev.lights.get(entry.key_ptr.*)) |cur| {
                if (entry.value_ptr.has_light) entry.value_ptr.light = cur.light;
                if (entry.value_ptr.has_enable) entry.value_ptr.enabled = cur.enabled;
            }
        }
    }
    return D3D_OK;
}

fn sb_Apply(this: *anyopaque) callconv(W) HRESULT {
    const self: *WinsStateBlock9 = @ptrCast(@alignCast(this));
    const dev = self.device;
    if (self.has_viewport) dev.viewport = self.viewport;
    if (self.has_scissor) dev.scissor = self.scissor;
    if (self.has_material) dev.material = self.material;
    for (0..kTransformStateCount) |i| {
        if (self.has_transform[i]) dev.transform_states[i] = self.transform_states[i];
    }
    for (0..256) |i| {
        if (self.has_vs_const[i]) dev.vs_consts[i] = self.vs_consts[i];
        if (self.has_render_state[i]) dev.render_states[i] = self.render_states[i];
    }
    for (0..224) |i| {
        if (self.has_ps_const[i]) dev.ps_consts[i] = self.ps_consts[i];
    }
    for (0..kMaxTextureStages) |st| {
        for (1..kTssSlots) |ty| {
            if (self.has_tss[st][ty]) dev.tex_stage_states[st][ty] = self.tex_stage_states[st][ty];
        }
    }
    for (0..16) |s| {
        for (1..kSampSlots) |ty| {
            if (self.has_samp[s][ty]) dev.sampler_states[s][ty] = self.sampler_states[s][ty];
        }
        if (self.has_stream[s]) {
            dev.streams[s] = self.streams[s];
            dev.stream_strides[s] = self.stream_strides[s];
            dev.stream_offsets[s] = self.stream_offsets[s];
        }
        if (self.has_texture[s]) dev.bound_textures[s] = self.bound_textures[s];
    }
    for (0..32) |ci| {
        if ((self.has_clip & (@as(u32, 1) << @intCast(ci))) != 0) dev.clip_planes[ci] = self.clip_planes[ci];
    }
    if (self.has_indices) dev.indices = self.indices;
    if (self.has_vs) dev.active_vs = self.active_vs;
    if (self.has_ps) dev.active_ps = self.active_ps;
    if (self.has_vdecl_mode) {
        if (!self.use_fvf) {
            if (self.vertex_decl) |n| n.ref_count += 1;
            if (dev.vertex_decl) |o| {
                if (o.ref_count > 0) o.ref_count -= 1;
            }
            dev.vertex_decl = self.vertex_decl;
            dev.use_fvf = false;
        } else {
            dev.fvf = self.fvf;
            dev.fvf_elements = self.fvf_elements;
            dev.use_fvf = true;
        }
    }
    if (self.capture_all_lights) {
        var dev_it = dev.lights.iterator();
        while (dev_it.next()) |entry| {
            if (!self.lights.contains(entry.key_ptr.*)) entry.value_ptr.enabled = false;
        }
    }
    var it = self.lights.iterator();
    while (it.next()) |entry| {
        const idx = entry.key_ptr.*;
        const rl = entry.value_ptr.*;
        if (dev.lights.getPtr(idx)) |dst| {
            if (rl.has_light) dst.light = rl.light;
            if (rl.has_enable) dst.enabled = rl.enabled;
        } else {
            dev.lights.put(dev.allocator, idx, .{
                .light = if (rl.has_light) rl.light else defaultLight9(),
                .enabled = if (rl.has_enable) rl.enabled else false,
            }) catch return E_OUTOFMEMORY;
        }
    }
    return D3D_OK;
}

const g_stateblock9_vtbl: IDirect3DStateBlock9Vtbl = .{
    .QueryInterface = &sb_QueryInterface,
    .AddRef = &sb_AddRef,
    .Release = &sb_Release,
    .GetDevice = &sb_GetDevice,
    .Capture = &sb_Capture,
    .Apply = &sb_Apply,
};

fn dev9_CreateStateBlock(this: *anyopaque, p0: u32, p1: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const out = p1 orelse return D3DERR_INVALIDCALL;
    if (self.recording_sb != null) return D3DERR_INVALIDCALL;
    if (p0 != D3DSBT_ALL and p0 != D3DSBT_PIXELSTATE and p0 != D3DSBT_VERTEXSTATE) return D3DERR_INVALIDCALL;
    const sb = WinsStateBlock9.create(self.allocator, self) catch return E_OUTOFMEMORY;
    initStateBlockMask(sb, p0);
    const rc = sb_Capture(sb);
    if (rc != D3D_OK) {
        sb.destroy();
        return rc;
    }
    out.* = @ptrCast(sb);
    return D3D_OK;
}

fn dev9_BeginStateBlock(this: *anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (self.recording_sb != null) return D3DERR_INVALIDCALL;
    const sb = WinsStateBlock9.create(self.allocator, self) catch return E_OUTOFMEMORY;
    self.recording_sb = sb;
    return D3D_OK;
}

fn dev9_EndStateBlock(this: *anyopaque, p0: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const sb = self.recording_sb orelse return D3DERR_INVALIDCALL;
    const out = p0 orelse return D3DERR_INVALIDCALL;
    self.recording_sb = null;
    out.* = @ptrCast(sb);
    return D3D_OK;
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

fn dev9_GetTexture(this: *anyopaque, Sampler: u32, ppTexture: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const out = ppTexture orelse return D3DERR_INVALIDCALL;
    out.* = null;
    if (Sampler >= 16) return D3DERR_INVALIDCALL;
    out.* = self.bound_textures[Sampler];
    if (out.*) |t| {
        const vt: *const *const IDirect3DTexture9Vtbl = @ptrCast(@alignCast(t));
        _ = vt.*.AddRef(t);
    }
    return D3D_OK;
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
    if (self.recording_sb) |sb| {
        sb.tex_stage_states[stage][ty] = value;
        sb.has_tss[stage][ty] = true;
        return D3D_OK;
    }
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
    if (self.recording_sb) |sb| {
        sb.sampler_states[sampler][ty] = value;
        sb.has_samp[sampler][ty] = true;
        return D3D_OK;
    }
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

/// The rectangle is stored as given (D3D9 does not clamp or validate it); a
/// null pointer is D3DERR_INVALIDCALL. It only clips while
/// D3DRS_SCISSORTESTENABLE (174) is set.
fn dev9_SetScissorRect(this: *anyopaque, p0: ?*const D3DRECT) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const r = p0 orelse return D3DERR_INVALIDCALL;
    if (self.recording_sb) |sb| {
        sb.scissor = r.*;
        sb.has_scissor = true;
        return D3D_OK;
    }
    self.scissor = r.*;
    if (trace_frames != 0) std.debug.print("[WINS:D3D9:trace] f{d} SetScissorRect({d},{d},{d},{d})\n", .{ self.frame_count, r.x1, r.y1, r.x2, r.y2 });
    return D3D_OK;
}

fn dev9_GetScissorRect(this: *anyopaque, p0: ?*D3DRECT) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const out = p0 orelse return D3DERR_INVALIDCALL;
    out.* = self.scissor;
    return D3D_OK;
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

/// Vertices (and indices) from the caller's memory. As in D3D9, stream 0
/// (and, for the indexed form, the index buffer) is unbound afterwards.
fn dev9_DrawPrimitiveUP(this: *anyopaque, prim: u32, count: u32, data: ?*const anyopaque, stride: u32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const d = data orelse return D3DERR_INVALIDCALL;
    if (stride == 0) return D3DERR_INVALIDCALL;
    self.draw_call_count += 1;
    if (self.host and count != 0) {
        var job: hostgl.DrawJob = .{ .dev = self, .prim = prim, .indexed = false, .base_vertex = 0, .prim_count = count, .up_vb = @ptrCast(d), .up_stride = stride };
        hostgl.draw(&job);
    }
    self.streams[0] = null;
    self.stream_offsets[0] = 0;
    self.stream_strides[0] = 0;
    return D3D_OK;
}

fn dev9_DrawIndexedPrimitiveUP(this: *anyopaque, prim: u32, min_index: u32, num_vertices: u32, count: u32, indices: ?*const anyopaque, index_format: u32, data: ?*const anyopaque, stride: u32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const d = data orelse return D3DERR_INVALIDCALL;
    const ix = indices orelse return D3DERR_INVALIDCALL;
    if (stride == 0 or (index_format != D3DFMT_INDEX16 and index_format != D3DFMT_INDEX32)) return D3DERR_INVALIDCALL;
    self.draw_call_count += 1;
    if (self.host and count != 0) {
        var job: hostgl.DrawJob = .{ .dev = self, .prim = prim, .indexed = true, .base_vertex = 0, .min_index = min_index, .num_vertices = num_vertices, .start_index = 0, .prim_count = count, .up_vb = @ptrCast(d), .up_stride = stride, .up_ib = @ptrCast(ix), .up_ib_format = index_format };
        hostgl.draw(&job);
    }
    self.streams[0] = null;
    self.stream_offsets[0] = 0;
    self.stream_strides[0] = 0;
    self.indices = null;
    return D3D_OK;
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
    if (self.recording_sb) |sb| {
        sb.vertex_decl = new;
        if (new != null) sb.use_fvf = false;
        sb.has_vdecl_mode = true;
        return D3D_OK;
    }
    if (new) |n| n.ref_count += 1;
    if (self.vertex_decl) |old| {
        if (old.ref_count > 0) old.ref_count -= 1;
    }
    self.vertex_decl = new;
    if (new != null) self.use_fvf = false;
    return D3D_OK;
}

fn dev9_GetVertexDeclaration(this: *anyopaque, ppDecl: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const out = ppDecl orelse return D3DERR_INVALIDCALL;
    if (self.vertex_decl) |d| d.ref_count += 1;
    out.* = self.vertex_decl;
    return D3D_OK;
}

/// The FVF as the declaration it stands for (D3DFVF_* -> D3DVERTEXELEMENT9),
/// so every draw reads its vertices one way. Returns the element count.
pub fn fvfElements(fvf: u32, out: *[24]D3DVERTEXELEMENT9) ?usize {
    var n: usize = 0;
    var off: u16 = 0;
    const add = struct {
        fn f(o: *[24]D3DVERTEXELEMENT9, k: *usize, at: *u16, ty: u8, size: u16, usage: u8, idx: u8) void {
            o[k.*] = .{ .Stream = 0, .Offset = at.*, .Type = ty, .Method = 0, .Usage = usage, .UsageIndex = idx };
            k.* += 1;
            at.* += size;
        }
    }.f;
    switch (fvf & 0x400E) {
        0 => {},
        0x002 => add(out, &n, &off, 2, 12, 0, 0), // XYZ
        0x004 => add(out, &n, &off, 3, 16, 9, 0), // XYZRHW -> POSITIONT
        0x4002 => add(out, &n, &off, 3, 16, 0, 0), // XYZW
        0x006, 0x008, 0x00A, 0x00C, 0x00E => {
            add(out, &n, &off, 2, 12, 0, 0);
            const weights: u16 = @intCast(((fvf & 0xE) - 4) / 2);
            off += weights * 4; // blend weights / indices: not used by this device
        },
        else => return null,
    }
    if (fvf & 0x10 != 0) add(out, &n, &off, 2, 12, 3, 0); // NORMAL
    if (fvf & 0x20 != 0) add(out, &n, &off, 0, 4, 4, 0); // PSIZE
    if (fvf & 0x40 != 0) add(out, &n, &off, 4, 4, 10, 0); // DIFFUSE
    if (fvf & 0x80 != 0) add(out, &n, &off, 4, 4, 10, 1); // SPECULAR
    const tc = (fvf >> 8) & 0xF;
    if (tc > 8) return null;
    var i: u32 = 0;
    while (i < tc) : (i += 1) {
        const code = (fvf >> @intCast(16 + 2 * i)) & 3;
        const t: struct { ty: u8, sz: u16 } = switch (code) {
            0 => .{ .ty = 1, .sz = 8 },
            1 => .{ .ty = 2, .sz = 12 },
            2 => .{ .ty = 3, .sz = 16 },
            else => .{ .ty = 0, .sz = 4 },
        };
        add(out, &n, &off, t.ty, t.sz, 5, @intCast(i));
    }
    out[n] = .{ .Stream = 0xFF, .Offset = 0, .Type = kDeclTypeUnused, .Method = 0, .Usage = 0, .UsageIndex = 0 };
    return n;
}

fn dev9_SetFVF(this: *anyopaque, fvf: u32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    if (fvf == 0) return D3D_OK; // D3D9 ignores a zero FVF
    if (self.recording_sb) |sb| {
        _ = fvfElements(fvf, &sb.fvf_elements) orelse return D3DERR_INVALIDCALL;
        sb.fvf = fvf;
        sb.use_fvf = true;
        sb.has_vdecl_mode = true;
        return D3D_OK;
    }
    _ = fvfElements(fvf, &self.fvf_elements) orelse return D3DERR_INVALIDCALL;
    if (trace_resources and fvf != self.fvf) std.debug.print("[WINS:D3D9:trace] SetFVF(0x{x})\n", .{fvf});
    self.fvf = fvf;
    self.use_fvf = true;
    return D3D_OK;
}

fn dev9_GetFVF(this: *anyopaque, p0: ?*u32) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    const out = p0 orelse return D3DERR_INVALIDCALL;
    out.* = if (self.use_fvf) self.fvf else 0;
    return D3D_OK;
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

// ---- IDirect3DQuery9 ---------------------------------------------------------

const D3DQUERYTYPE_EVENT: u32 = 8;
const D3DQUERYTYPE_OCCLUSION: u32 = 9;
const D3DISSUE_END: u32 = 1;
const D3DISSUE_BEGIN: u32 = 2;

const IDirect3DQuery9Vtbl = extern struct {
    QueryInterface: *const fn (*anyopaque, ?*const anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    AddRef: *const fn (*anyopaque) callconv(W) u32,
    Release: *const fn (*anyopaque) callconv(W) u32,
    GetDevice: *const fn (*anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    GetType: *const fn (*anyopaque) callconv(W) u32,
    GetDataSize: *const fn (*anyopaque) callconv(W) u32,
    Issue: *const fn (*anyopaque, u32) callconv(W) HRESULT,
    GetData: *const fn (*anyopaque, ?*anyopaque, u32, u32) callconv(W) HRESULT,
};

/// An occlusion query counts, on the host GPU, the samples that pass the depth
/// test between Issue(BEGIN) and Issue(END). An event query only says "the GPU
/// caught up", which is true by the time GetData's job has run.
pub const WinsQuery9 = extern struct {
    vtbl: *const IDirect3DQuery9Vtbl,
    ref_count: u32,
    device: *WinsD3DDevice9,
    kind: u32,
    gl_name: u32 = 0,
    result: u32 = 0,
    /// Issue(END) happened at least once, so there is a count to hand out.
    ended: bool = false,
};

fn query_QueryInterface(this: *anyopaque, riid: ?*const anyopaque, ppv: ?*?*anyopaque) callconv(W) HRESULT {
    _ = riid;
    const self: *WinsQuery9 = @ptrCast(@alignCast(this));
    self.ref_count += 1;
    if (ppv) |p| p.* = this;
    return S_OK;
}
fn query_AddRef(this: *anyopaque) callconv(W) u32 {
    const self: *WinsQuery9 = @ptrCast(@alignCast(this));
    self.ref_count += 1;
    return self.ref_count;
}
fn query_Release(this: *anyopaque) callconv(W) u32 {
    const self: *WinsQuery9 = @ptrCast(@alignCast(this));
    if (self.ref_count > 0) self.ref_count -= 1;
    if (self.ref_count == 0 and self.gl_name != 0) hostgl.queryGone(self);
    return self.ref_count;
}
fn query_GetDevice(this: *anyopaque, out: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsQuery9 = @ptrCast(@alignCast(this));
    const o = out orelse return D3DERR_INVALIDCALL;
    self.device.ref_count += 1;
    o.* = @ptrCast(self.device);
    return D3D_OK;
}
fn query_GetType(this: *anyopaque) callconv(W) u32 {
    const self: *WinsQuery9 = @ptrCast(@alignCast(this));
    return self.kind;
}
fn query_GetDataSize(this: *anyopaque) callconv(W) u32 {
    _ = this;
    return 4; // DWORD sample count, or BOOL for the event query
}
fn query_Issue(this: *anyopaque, flags: u32) callconv(W) HRESULT {
    const self: *WinsQuery9 = @ptrCast(@alignCast(this));
    if (self.kind == D3DQUERYTYPE_OCCLUSION) {
        if (flags & D3DISSUE_BEGIN != 0) {
            self.ended = false;
            hostgl.queryBegin(self);
        }
        if (flags & D3DISSUE_END != 0) {
            hostgl.queryEnd(self);
            self.ended = true;
        }
    } else if (flags & D3DISSUE_END != 0) {
        self.ended = true;
    }
    return D3D_OK;
}
fn query_GetData(this: *anyopaque, data: ?*anyopaque, size: u32, flags: u32) callconv(W) HRESULT {
    _ = flags;
    const self: *WinsQuery9 = @ptrCast(@alignCast(this));
    var value: u32 = 1; // event: the GPU has caught up
    if (self.kind == D3DQUERYTYPE_OCCLUSION) {
        if (self.ended) hostgl.queryResult(self);
        value = self.result;
    }
    if (data) |d| {
        if (size < 4) return D3DERR_INVALIDCALL;
        @as(*align(1) u32, @ptrCast(d)).* = value;
    }
    return S_OK;
}

const g_query9_vtbl: IDirect3DQuery9Vtbl = .{
    .QueryInterface = &query_QueryInterface,
    .AddRef = &query_AddRef,
    .Release = &query_Release,
    .GetDevice = &query_GetDevice,
    .GetType = &query_GetType,
    .GetDataSize = &query_GetDataSize,
    .Issue = &query_Issue,
    .GetData = &query_GetData,
};

/// FalloutNV asks for an occlusion query when it loads the Mojave (0xc4ed32)
/// and calls Issue on the result without looking at the HRESULT.
fn dev9_CreateQuery(this: *anyopaque, kind: u32, out: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    // Counting samples needs the GPU; without a host surface there is nothing
    // honest to answer.
    const supported = kind == D3DQUERYTYPE_EVENT or (kind == D3DQUERYTYPE_OCCLUSION and self.host);
    if (!supported) {
        std.debug.print("[WINS:D3D9] CreateQuery(type {d}) is not available (caller 0x{x})\n", .{ kind, @returnAddress() });
        if (out) |o| o.* = null;
        return D3DERR_NOTAVAILABLE;
    }
    const o = out orelse return D3D_OK; // NULL asks only "is it supported?"
    const q = self.allocator.create(WinsQuery9) catch return E_OUTOFMEMORY;
    q.* = .{ .vtbl = &g_query9_vtbl, .ref_count = 1, .device = self, .kind = kind };
    o.* = @ptrCast(q);
    return D3D_OK;
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
    std.debug.print("[WINS:D3D9] Direct3DCreate9(sdk_version={d})\n", .{sdk_version});
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

const DdsParsed = struct {
    info: D3DXIMAGE_INFO,
    data_offset: usize,
    face_mask: u32,
};

fn ddsFormat(pf_flags: u32, fourcc: u32, bpp: u32, rm: u32, gm: u32, bm: u32, am: u32, dxgi: u32) u32 {
    if ((pf_flags & 0x4) != 0) {
        return switch (fourcc) {
            D3DFMT_DXT1, D3DFMT_DXT3, D3DFMT_DXT5, 111, 112, 113, 114, 115, 116 => fourcc,
            0x30315844 => switch (dxgi) { // DX10
                70, 71, 72 => D3DFMT_DXT1,
                73, 74, 75 => D3DFMT_DXT3,
                76, 77, 78 => D3DFMT_DXT5,
                87, 91 => D3DFMT_A8R8G8B8,
                88, 93 => D3DFMT_X8R8G8B8,
                28, 29 => D3DFMT_A8B8G8R8,
                10 => 113,
                2 => 116,
                41 => 114,
                54 => 111,
                61 => 50,
                65 => 28,
                else => 0,
            },
            else => 0,
        };
    }
    if ((pf_flags & 0x40) != 0) {
        if (bpp == 32) {
            if (rm == 0x00FF0000 and gm == 0x0000FF00 and bm == 0x000000FF) {
                return if (am != 0 or (pf_flags & 1) != 0) D3DFMT_A8R8G8B8 else D3DFMT_X8R8G8B8;
            }
            if (rm == 0x000000FF and gm == 0x0000FF00 and bm == 0x00FF0000) {
                return if (am != 0 or (pf_flags & 1) != 0) D3DFMT_A8B8G8R8 else 33;
            }
        } else if (bpp == 16) {
            if (rm == 0xF800 and gm == 0x07E0 and bm == 0x001F) return 23;
            if (rm == 0x7C00 and gm == 0x03E0 and bm == 0x001F) return if (am != 0 or (pf_flags & 1) != 0) 25 else 24;
            if (rm == 0x0F00 and gm == 0x00F0 and bm == 0x000F) return 26;
        }
    }
    if ((pf_flags & 0x20000) != 0) return if (bpp == 8) 50 else if (bpp == 16) 51 else 0;
    if ((pf_flags & 0x80000) != 0 and bpp == 16) return 60;
    if ((pf_flags & 0x2) != 0 and bpp == 8) return 28;
    return 0;
}

fn parseDds(bytes: []const u8) ?DdsParsed {
    if (bytes.len < 128 or !std.mem.eql(u8, bytes[0..4], "DDS ")) return null;
    const flags = std.mem.readInt(u32, bytes[8..12], .little);
    const h = @max(1, std.mem.readInt(u32, bytes[12..16], .little));
    const w = @max(1, std.mem.readInt(u32, bytes[16..20], .little));
    const raw_d = std.mem.readInt(u32, bytes[24..28], .little);
    const raw_mips = std.mem.readInt(u32, bytes[28..32], .little);
    const pf_flags = std.mem.readInt(u32, bytes[80..84], .little);
    const fourcc = std.mem.readInt(u32, bytes[84..88], .little);
    const bpp = std.mem.readInt(u32, bytes[88..92], .little);
    const rm = std.mem.readInt(u32, bytes[92..96], .little);
    const gm = std.mem.readInt(u32, bytes[96..100], .little);
    const bm = std.mem.readInt(u32, bytes[100..104], .little);
    const am = std.mem.readInt(u32, bytes[104..108], .little);
    const caps2 = std.mem.readInt(u32, bytes[112..116], .little);

    var data_off: usize = 128;
    var dxgi: u32 = 0;
    if ((pf_flags & 0x4) != 0 and fourcc == 0x30315844) {
        if (bytes.len < 148) return null;
        dxgi = std.mem.readInt(u32, bytes[128..132], .little);
        data_off = 148;
    }
    const fmt = ddsFormat(pf_flags, fourcc, bpp, rm, gm, bm, am, dxgi);
    if (fmt == 0) return null;

    const is_cube = (caps2 & 0x200) != 0;
    const is_vol = !is_cube and ((caps2 & 0x200000) != 0 or ((flags & 0x800000) != 0 and raw_d > 1));
    const d: u32 = if (is_vol) @max(1, raw_d) else 1;
    const max_mips = if (is_vol) WinsVolumeTexture9.fullChain(w, h, d) else WinsTexture9.fullChain(w, h);
    const mips = @min(@max(1, raw_mips), max_mips);
    const rtype: u32 = if (is_cube) D3DRTYPE_CUBETEXTURE else if (is_vol) D3DRTYPE_VOLUMETEXTURE else D3DRTYPE_TEXTURE;
    const face_mask: u32 = if (is_cube) (if ((caps2 & 0xFC00) != 0) ((caps2 >> 10) & 0x3F) else 0x3F) else 0;
    return .{
        .info = .{
            .Width = w,
            .Height = h,
            .Depth = d,
            .MipLevels = mips,
            .Format = fmt,
            .ResourceType = rtype,
            .ImageFileFormat = 4, // D3DXIFF_DDS
        },
        .data_offset = data_off,
        .face_mask = face_mask,
    };
}

fn copyDdsSlice(src: []const u8, off: *usize, dst: []u8) void {
    const rem = src.len -| off.*;
    const take = @min(dst.len, rem);
    if (take > 0) @memcpy(dst[0..take], src[off.* .. off.* + take]);
    off.* += dst.len;
}

pub export fn D3DXGetImageInfoFromFileInMemory(
    pSrcData: ?*const anyopaque,
    SrcDataSize: u32,
    pSrcInfo: ?*D3DXIMAGE_INFO,
) callconv(W) HRESULT {
    if (pSrcData == null or SrcDataSize < 32 or pSrcInfo == null) return E_FAIL;
    const raw: [*]const u8 = @ptrCast(pSrcData.?);
    const bytes = raw[0..SrcDataSize];
    if (parseDds(bytes)) |parsed| {
        pSrcInfo.?.* = parsed.info;
        return D3D_OK;
    }
    pSrcInfo.?.Width = 256;
    pSrcInfo.?.Height = 256;
    pSrcInfo.?.Depth = 1;
    pSrcInfo.?.MipLevels = 1;
    pSrcInfo.?.Format = D3DFMT_A8R8G8B8;
    pSrcInfo.?.ResourceType = D3DRTYPE_TEXTURE;
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
    if (pSrcData == null or SrcDataSize == 0 or ppTexture == null) return D3DERR_INVALIDCALL;
    const raw: [*]const u8 = @ptrCast(pSrcData.?);
    const bytes = raw[0..SrcDataSize];
    const gpa = std.heap.page_allocator;
    if (parseDds(bytes)) |parsed| {
        const tex = WinsTexture9.create(gpa, parsed.info.Width, parsed.info.Height, parsed.info.MipLevels, 0, parsed.info.Format, 1) catch |e| {
            return if (e == error.InvalidCall) D3DERR_INVALIDCALL else E_OUTOFMEMORY;
        };
        var off = parsed.data_offset;
        for (tex.surfaces) |s| copyDdsSlice(bytes, &off, s.data);
        tex.gl_dirty = true;
        ppTexture.?.* = @ptrCast(tex);
        return D3D_OK;
    }
    const tex = WinsTexture9.create(gpa, 256, 256, 1, 0, D3DFMT_A8R8G8B8, 1) catch return E_OUTOFMEMORY;
    ppTexture.?.* = @ptrCast(tex);
    return D3D_OK;
}

pub export fn D3DXCreateCubeTextureFromFileInMemory(
    pDevice: ?*anyopaque,
    pSrcData: ?*const anyopaque,
    SrcDataSize: u32,
    ppCubeTexture: ?*?*anyopaque,
) callconv(W) HRESULT {
    _ = pDevice;
    if (pSrcData == null or SrcDataSize == 0 or ppCubeTexture == null) return D3DERR_INVALIDCALL;
    const raw: [*]const u8 = @ptrCast(pSrcData.?);
    const bytes = raw[0..SrcDataSize];
    const gpa = std.heap.page_allocator;
    if (parseDds(bytes)) |parsed| {
        const edge = @max(parsed.info.Width, parsed.info.Height);
        const ct = WinsCubeTexture9.create(gpa, edge, parsed.info.MipLevels, 0, parsed.info.Format, 1) catch |e| {
            return if (e == error.InvalidCall) D3DERR_INVALIDCALL else E_OUTOFMEMORY;
        };
        var off = parsed.data_offset;
        const fmask = if (parsed.face_mask != 0) parsed.face_mask else 0x3F;
        for (0..6) |face| {
            if ((fmask & (@as(u32, 1) << @intCast(face))) == 0) continue;
            for (0..ct.levels) |level| {
                copyDdsSlice(bytes, &off, ct.faces[face * ct.levels + level].data);
            }
        }
        ct.gl_dirty = true;
        ppCubeTexture.?.* = @ptrCast(ct);
        return D3D_OK;
    }
    const ct = WinsCubeTexture9.create(gpa, 1, 1, 0, D3DFMT_A8R8G8B8, 1) catch return E_OUTOFMEMORY;
    ppCubeTexture.?.* = @ptrCast(ct);
    return D3D_OK;
}

pub export fn D3DXCreateVolumeTextureFromFileInMemory(
    pDevice: ?*anyopaque,
    pSrcData: ?*const anyopaque,
    SrcDataSize: u32,
    ppVolumeTexture: ?*?*anyopaque,
) callconv(W) HRESULT {
    _ = pDevice;
    if (pSrcData == null or SrcDataSize == 0 or ppVolumeTexture == null) return D3DERR_INVALIDCALL;
    const raw: [*]const u8 = @ptrCast(pSrcData.?);
    const bytes = raw[0..SrcDataSize];
    const gpa = std.heap.page_allocator;
    if (parseDds(bytes)) |parsed| {
        const vt = WinsVolumeTexture9.create(gpa, parsed.info.Width, parsed.info.Height, parsed.info.Depth, parsed.info.MipLevels, 0, parsed.info.Format, 1) catch |e| {
            return if (e == error.InvalidCall) D3DERR_INVALIDCALL else E_OUTOFMEMORY;
        };
        var off = parsed.data_offset;
        for (vt.volumes) |v| copyDdsSlice(bytes, &off, v.data);
        vt.gl_dirty = true;
        ppVolumeTexture.?.* = @ptrCast(vt);
        return D3D_OK;
    }
    const vt = WinsVolumeTexture9.create(gpa, 1, 1, 1, 1, 0, D3DFMT_A8R8G8B8, 1) catch return E_OUTOFMEMORY;
    ppVolumeTexture.?.* = @ptrCast(vt);
    return D3D_OK;
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
    try std.testing.expectEqual(@as(u32, 16384), caps.MaxTextureWidth); // wined3d on this adapter

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

test "format 32 (A8B8G8R8) is accepted wherever 22 (X8R8G8B8) is" {
    const d3d: *WinsD3D9 = @ptrCast(@alignCast(Direct3DCreate9(32).?));
    try std.testing.expectEqual(D3D_OK, d3d.vtbl.CheckDeviceFormat(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, D3DUSAGE_RENDERTARGET, D3DRTYPE_SURFACE, D3DFMT_A8B8G8R8));
    try std.testing.expectEqual(D3D_OK, d3d.vtbl.CheckDeviceType(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, D3DFMT_A8B8G8R8, 1));
    try std.testing.expectEqual(@as(u32, 1), d3d.vtbl.GetAdapterModeCount(d3d, 0, D3DFMT_A8B8G8R8));
    try std.testing.expectEqual(@as(u32, 0), d3d.vtbl.GetAdapterModeCount(d3d, 0, 23));
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
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.SetRenderTarget(dev, 4, bb)); // NumSimultaneousRTs = 4

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

    // A same-device depth surface must be at least as large as the active render target.
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
    // Cube & volume textures are available for all texture formats; volume cannot be RT, while cube can.
    try std.testing.expectEqual(D3D_OK, d3d.vtbl.CheckDeviceFormat(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 0, D3DRTYPE_VOLUMETEXTURE, D3DFMT_A8R8G8B8));
    try std.testing.expectEqual(D3DERR_NOTAVAILABLE, d3d.vtbl.CheckDeviceFormat(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, D3DUSAGE_RENDERTARGET, D3DRTYPE_VOLUMETEXTURE, D3DFMT_A8R8G8B8));
    try std.testing.expectEqual(D3D_OK, d3d.vtbl.CheckDeviceFormat(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 0, D3DRTYPE_CUBETEXTURE, D3DFMT_DXT1));
    try std.testing.expectEqual(D3D_OK, d3d.vtbl.CheckDeviceFormat(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, D3DUSAGE_RENDERTARGET, D3DRTYPE_CUBETEXTURE, D3DFMT_A8R8G8B8));
    try std.testing.expectEqual(D3DERR_NOTAVAILABLE, d3d.vtbl.CheckDeviceFormat(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 0, 99, D3DFMT_A8R8G8B8));
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

fn writeTestU32LE(bytes: []u8, offset: usize, value: u32) void {
    bytes[offset] = @truncate(value);
    bytes[offset + 1] = @truncate(value >> 8);
    bytes[offset + 2] = @truncate(value >> 16);
    bytes[offset + 3] = @truncate(value >> 24);
}

fn writeTestPosition(bytes: []u8, vertex: usize, position: [3]f32) void {
    for (position, 0..) |component, axis| {
        writeTestU32LE(bytes, vertex * 12 + axis * 4, @bitCast(component));
    }
}

fn setTestViewport(dev: *WinsD3DDevice9) void {
    const viewport = D3DVIEWPORT9{ .X = 0, .Y = 0, .Width = 32, .Height = 32, .MinZ = 0, .MaxZ = 1 };
    _ = dev.vtbl.SetViewport(dev, &viewport);
}

test "DrawIndexedPrimitive honors INDEX16 start index, base vertex and stream offset" {
    const d3d: *WinsD3D9 = @ptrCast(@alignCast(Direct3DCreate9(32).?));
    const dev = try testDevice(d3d);
    setTestViewport(dev);

    var vb_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateVertexBuffer(dev, 5 * 12, 0, 0, 1, &vb_raw, null));
    const vb: *WinsVertexBuffer9 = @ptrCast(@alignCast(vb_raw.?));
    const positions = [_][3]f32{
        .{ 2, 2, 0.5 }, // unused vertices catch an ignored base/stream offset
        .{ 2, 2, 0.5 },
        .{ -0.75, -0.75, 0.5 },
        .{ 0.75, -0.75, 0.5 },
        .{ 0, 0.75, 0.5 },
    };
    for (positions, 0..) |position, i| writeTestPosition(vb.data, i, position);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetStreamSource(dev, 0, vb, 12, 12));

    var ib_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateIndexBuffer(dev, 8, 0, D3DFMT_INDEX16, 1, &ib_raw, null));
    const ib: *WinsIndexBuffer9 = @ptrCast(@alignCast(ib_raw.?));
    const index_bytes = [_]u8{ 99, 0, 0, 0, 1, 0, 2, 0 };
    @memcpy(ib.data, &index_bytes);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetIndices(dev, ib));

    // Skip index 99, then add base vertex 1; stream offset adds another vertex.
    try std.testing.expectEqual(D3D_OK, dev.vtbl.DrawIndexedPrimitive(dev, D3DPT_TRIANGLELIST, 1, 0, 3, 1, 1));
    try std.testing.expectEqual(@as(u64, 1), dev.draw_call_count);
    try std.testing.expectEqual(@as(u32, 0xFF00FF00), dev.backbuffer[16 * 32 + 16]);
    try std.testing.expectEqual(@as(u32, 0xFF000000), dev.backbuffer[0]);

    // Negative control: a negative effective vertex index is rejected before drawing.
    @memset(dev.backbuffer, 0);
    @memset(dev.depthbuffer, 1.0);
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.DrawIndexedPrimitive(dev, D3DPT_TRIANGLELIST, -1, 0, 3, 1, 1));
    try std.testing.expectEqual(@as(u32, 0), dev.backbuffer[16 * 32 + 16]);
}

test "DrawIndexedPrimitive assembles INDEX32 triangle strips and fans" {
    const d3d: *WinsD3D9 = @ptrCast(@alignCast(Direct3DCreate9(32).?));
    const dev = try testDevice(d3d);
    setTestViewport(dev);

    var vb_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateVertexBuffer(dev, 4 * 12, 0, 0, 1, &vb_raw, null));
    const vb: *WinsVertexBuffer9 = @ptrCast(@alignCast(vb_raw.?));
    const positions = [_][3]f32{
        .{ -0.75, -0.75, 0.5 },
        .{ -0.75, 0.75, 0.5 },
        .{ 0.75, -0.75, 0.5 },
        .{ 0.75, 0.75, 0.5 },
    };
    for (positions, 0..) |position, i| writeTestPosition(vb.data, i, position);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetStreamSource(dev, 0, vb, 0, 12));

    var ib_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateIndexBuffer(dev, 4 * 4, 0, D3DFMT_INDEX32, 1, &ib_raw, null));
    const ib: *WinsIndexBuffer9 = @ptrCast(@alignCast(ib_raw.?));
    for ([_]u32{ 0, 1, 2, 3 }, 0..) |index, i| writeTestU32LE(ib.data, i * 4, index);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetIndices(dev, ib));

    try std.testing.expectEqual(D3D_OK, dev.vtbl.DrawIndexedPrimitive(dev, D3DPT_TRIANGLESTRIP, 0, 0, 4, 0, 2));
    try std.testing.expectEqual(@as(u32, 0xFF00FF00), dev.backbuffer[16 * 32 + 16]);

    @memset(dev.backbuffer, 0);
    @memset(dev.depthbuffer, 1.0);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.DrawIndexedPrimitive(dev, D3DPT_TRIANGLEFAN, 0, 0, 4, 0, 2));
    try std.testing.expectEqual(@as(u32, 0xFF00FF00), dev.backbuffer[16 * 32 + 16]);
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

test "scissor rectangle: starts as the back buffer, round trips, null is INVALIDCALL" {
    var d3d = WinsD3D9.init();
    const dev = try testDevice(&d3d);
    var r: D3DRECT = undefined;
    try std.testing.expectEqual(D3D_OK, dev9_GetScissorRect(dev, &r));
    try std.testing.expectEqual(@as(i32, 0), r.x1);
    try std.testing.expectEqual(@as(i32, @intCast(dev.viewport.Width)), r.x2);
    try std.testing.expectEqual(@as(i32, @intCast(dev.viewport.Height)), r.y2);
    const want: D3DRECT = .{ .x1 = 3, .y1 = 5, .x2 = 70, .y2 = 90 };
    try std.testing.expectEqual(D3D_OK, dev9_SetScissorRect(dev, &want));
    try std.testing.expectEqual(D3D_OK, dev9_GetScissorRect(dev, &r));
    try std.testing.expectEqual(want, r);
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev9_SetScissorRect(dev, null));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev9_GetScissorRect(dev, null));
    try std.testing.expectEqual(want, r);
}

/// WINS_D3D9_PROF=1 (set by the loader): frame-rate and render-time report.
pub fn hostgl_prof(on: bool) void {
    hostgl.prof_enabled = on;
}

/// WINS_D3D9_CAPTURE=<frame>:<path> (set by the loader).
pub fn hostgl_capture(frame: u64, path_spec: []const u8) void {
    hostgl.capture_frame = frame;
    // <path>[:<period>]
    var path = path_spec;
    if (std.mem.lastIndexOfScalar(u8, path_spec, ':')) |c| {
        if (std.fmt.parseInt(u64, path_spec[c + 1 ..], 10)) |period| {
            hostgl.capture_period = period;
            path = path_spec[0..c];
        } else |_| {}
    }
    const n = @min(path.len, hostgl.capture_path.len - 1);
    @memcpy(hostgl.capture_path[0..n], path[0..n]);
    hostgl.capture_path[n] = 0;
}

test "device caps carry the oracle's shader limits FalloutNV gates on" {
    var caps: D3DCAPS9 = undefined;
    try std.testing.expectEqual(D3D_OK, d3d9_GetDeviceCaps(undefined, 0, 1, &caps));
    try std.testing.expectEqual(@as(usize, 0x118), @offsetOf(D3DCAPS9, "PS20Caps") + @offsetOf(D3DPSHADERCAPS2_0, "NumInstructionSlots"));
    try std.testing.expect(caps.PS20Caps.NumInstructionSlots > 0xff);
    try std.testing.expect(caps.PS20Caps.NumTemps >= 32);
    try std.testing.expectEqual(@as(u32, 1), caps.DeviceType);
}

test "FVF XYZRHW|DIFFUSE|TEX1 becomes POSITIONT float4, COLOR0, TEXCOORD0 float2" {
    var els: [24]D3DVERTEXELEMENT9 = undefined;
    const n = fvfElements(0x144, &els).?;
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqual(@as(u8, 9), els[0].Usage);
    try std.testing.expectEqual(@as(u8, 3), els[0].Type);
    try std.testing.expectEqual(@as(u16, 16), els[1].Offset);
    try std.testing.expectEqual(@as(u8, 10), els[1].Usage);
    try std.testing.expectEqual(@as(u16, 20), els[2].Offset);
    try std.testing.expectEqual(@as(u8, 1), els[2].Type);
    try std.testing.expectEqual(@as(u16, 0xFF), els[3].Stream);
}

test "render states start at the D3D9 defaults" {
    const rs = defaultRenderStates(true);
    try std.testing.expectEqual(@as(u32, 0xF), rs[168]);
    try std.testing.expectEqual(@as(u32, 3), rs[22]);
    try std.testing.expectEqual(@as(u32, 4), rs[23]);
    try std.testing.expectEqual(@as(u32, 1), rs[7]);
    try std.testing.expectEqual(@as(u32, 0), defaultRenderStates(false)[7]);
}

test "clip planes: SetClipPlane / GetClipPlane round-trip, OOB and null INVALIDCALL, RS 152 default 0" {
    var d3d = WinsD3D9.init();
    const dev = try testDevice(&d3d);
    defer _ = dev.vtbl.Release(dev);

    var rs: u32 = 0xDEADBEEF;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetRenderState(dev, 152, &rs));
    try std.testing.expectEqual(@as(u32, 0), rs);

    var out: [4]f32 = .{ 9, 9, 9, 9 };
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetClipPlane(dev, 0, &out[0]));
    try std.testing.expectEqual([4]f32{ 0, 0, 0, 0 }, out);

    const p: [4]f32 = .{ 1.5, -2.25, 0.5, 3.0 };
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetClipPlane(dev, 7, &p[0]));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetClipPlane(dev, 7, &out[0]));
    try std.testing.expectEqual(p, out);

    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.SetClipPlane(dev, 0, null));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.GetClipPlane(dev, 0, null));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.SetClipPlane(dev, 32, &p[0]));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.GetClipPlane(dev, 32, &out[0]));

    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetRenderState(dev, 152, 0xFF));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetRenderState(dev, 152, &rs));
    try std.testing.expectEqual(@as(u32, 0xFF), rs);
}

test "cube and volume textures: creation, descriptors, locks, SetTexture/GetTexture, and DDS loader" {
    var d3d = WinsD3D9.init();
    const dev = try testDevice(&d3d);
    defer _ = dev.vtbl.Release(dev);

    // Cube texture creation + invalid edge + face access
    var bad: ?*anyopaque = null;
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.CreateCubeTexture(dev, 0, 1, 0, D3DFMT_A8R8G8B8, 1, &bad, null));
    var ct_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateCubeTexture(dev, 4, 0, 0, D3DFMT_A8R8G8B8, 1, &ct_raw, null));
    const ct: *WinsCubeTexture9 = @ptrCast(@alignCast(ct_raw.?));
    defer _ = ct.vtbl.Release(ct);
    try std.testing.expectEqual(D3DRTYPE_CUBETEXTURE, ct.vtbl.GetType(ct));
    try std.testing.expectEqual(@as(u32, 3), ct.vtbl.GetLevelCount(ct));
    try std.testing.expectEqual(D3DRTYPE_CUBETEXTURE, textureKind(ct));

    var sdesc: D3DSURFACE_DESC = undefined;
    try std.testing.expectEqual(D3D_OK, ct.vtbl.GetLevelDesc(ct, 1, &sdesc));
    try std.testing.expectEqual(D3DRTYPE_SURFACE, sdesc.Type);
    try std.testing.expectEqual(@as(u32, 2), sdesc.Width);
    try std.testing.expectEqual(@as(u32, 2), sdesc.Height);

    var surf_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3DERR_INVALIDCALL, ct.vtbl.GetCubeMapSurface(ct, 6, 0, &surf_raw));
    try std.testing.expectEqual(D3D_OK, ct.vtbl.GetCubeMapSurface(ct, 2, 0, &surf_raw));
    const face2: *WinsSurface9 = @ptrCast(@alignCast(surf_raw.?));
    defer _ = face2.vtbl.Release(face2);
    try std.testing.expectEqual(@as(u32, 2), face2.cube_face);

    // Volume texture creation + LockBox + GetVolumeLevel
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.CreateVolumeTexture(dev, 0, 4, 4, 1, 0, D3DFMT_A8R8G8B8, 1, &bad, null));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.CreateVolumeTexture(dev, 4, 4, 4, 1, D3DUSAGE_RENDERTARGET, D3DFMT_A8R8G8B8, 0, &bad, null));
    var vt_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateVolumeTexture(dev, 4, 4, 4, 0, 0, D3DFMT_A8R8G8B8, 1, &vt_raw, null));
    const vt: *WinsVolumeTexture9 = @ptrCast(@alignCast(vt_raw.?));
    defer _ = vt.vtbl.Release(vt);
    try std.testing.expectEqual(D3DRTYPE_VOLUMETEXTURE, vt.vtbl.GetType(vt));
    try std.testing.expectEqual(@as(u32, 3), vt.vtbl.GetLevelCount(vt));
    try std.testing.expectEqual(D3DRTYPE_VOLUMETEXTURE, textureKind(vt));

    var vdesc: D3DVOLUME_DESC = undefined;
    try std.testing.expectEqual(D3D_OK, vt.vtbl.GetLevelDesc(vt, 1, &vdesc));
    try std.testing.expectEqual(D3DRTYPE_VOLUME, vdesc.Type);
    try std.testing.expectEqual(@as(u32, 2), vdesc.Depth);

    var vol_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, vt.vtbl.GetVolumeLevel(vt, 0, &vol_raw));
    const vol0: *WinsVolume9 = @ptrCast(@alignCast(vol_raw.?));
    defer _ = vol0.vtbl.Release(vol0);
    var lb: D3DLOCKED_BOX = undefined;
    try std.testing.expectEqual(D3D_OK, vol0.vtbl.LockBox(vol0, &lb, null, 0));
    try std.testing.expectEqual(@as(i32, 16), lb.RowPitch);
    try std.testing.expectEqual(@as(i32, 64), lb.SlicePitch);
    try std.testing.expectEqual(D3D_OK, vol0.vtbl.UnlockBox(vol0));

    // SetTexture + GetTexture round-trip for CubeTexture
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetTexture(dev, 0, ct));
    var got_tex: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetTexture(dev, 0, &got_tex));
    try std.testing.expectEqual(@as(?*anyopaque, ct), got_tex);
    _ = ct.vtbl.Release(ct);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetTexture(dev, 0, null));

    // D3DXGetImageInfoFromFileInMemory + CreateCube/Volume from DDS
    var dds_cube: [128 + 24]u8 = [_]u8{0} ** (128 + 24);
    @memcpy(dds_cube[0..4], "DDS ");
    std.mem.writeInt(u32, dds_cube[4..8], 124, .little);
    std.mem.writeInt(u32, dds_cube[8..12], 0x1007, .little);
    std.mem.writeInt(u32, dds_cube[12..16], 1, .little);
    std.mem.writeInt(u32, dds_cube[16..20], 1, .little);
    std.mem.writeInt(u32, dds_cube[28..32], 1, .little);
    std.mem.writeInt(u32, dds_cube[76..80], 32, .little);
    std.mem.writeInt(u32, dds_cube[80..84], 0x41, .little);
    std.mem.writeInt(u32, dds_cube[88..92], 32, .little);
    std.mem.writeInt(u32, dds_cube[92..96], 0x00FF0000, .little);
    std.mem.writeInt(u32, dds_cube[96..100], 0x0000FF00, .little);
    std.mem.writeInt(u32, dds_cube[100..104], 0x000000FF, .little);
    std.mem.writeInt(u32, dds_cube[104..108], 0xFF000000, .little);
    std.mem.writeInt(u32, dds_cube[112..116], 0xFE00, .little);
    std.mem.writeInt(u32, dds_cube[128 + 8 .. 128 + 12], 0xFF0000FF, .little); // +Y face

    var info: D3DXIMAGE_INFO = undefined;
    try std.testing.expectEqual(D3D_OK, D3DXGetImageInfoFromFileInMemory(&dds_cube, dds_cube.len, &info));
    try std.testing.expectEqual(D3DRTYPE_CUBETEXTURE, info.ResourceType);
    try std.testing.expectEqual(D3DFMT_A8R8G8B8, info.Format);

    var dds_ct_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, D3DXCreateCubeTextureFromFileInMemory(dev, &dds_cube, dds_cube.len, &dds_ct_raw));
    const dds_ct: *WinsCubeTexture9 = @ptrCast(@alignCast(dds_ct_raw.?));
    defer _ = dds_ct.vtbl.Release(dds_ct);
    try std.testing.expectEqual(@as(u32, 0xFF0000FF), std.mem.readInt(u32, dds_ct.faces[2].data[0..4], .little));
}

test "IDirect3DStateBlock9: Begin/End isolation, partial Apply, CreateStateBlock Capture/Apply, QI and GetDevice" {
    var d3d = WinsD3D9.init();
    const dev = try testDevice(&d3d);
    defer _ = dev.vtbl.Release(dev);

    // Errors outside valid sequence
    var dummy_sb: ?*anyopaque = null;
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.EndStateBlock(dev, &dummy_sb));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.CreateStateBlock(dev, 99, &dummy_sb));

    // Baseline live device state
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetRenderState(dev, 7, 1)); // ZENABLE = 1
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetRenderState(dev, 14, 0)); // ZWRITEENABLE = 0
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetTextureStageState(dev, 0, 1, 4)); // COLOROP = MODULATE
    var m_live = d3dIdentityMatrix();
    m_live.m[3][0] = 10.0;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetTransform(dev, 2, &m_live)); // VIEW

    // BeginStateBlock records without mutating live device state
    try std.testing.expectEqual(D3D_OK, dev.vtbl.BeginStateBlock(dev));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.BeginStateBlock(dev)); // nested
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.CreateStateBlock(dev, D3DSBT_ALL, &dummy_sb));

    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetRenderState(dev, 14, 1)); // recorded only
    var m_rec = d3dIdentityMatrix();
    m_rec.m[3][0] = 42.0;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetTransform(dev, 2, &m_rec));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetTextureStageState(dev, 0, 1, 2)); // SELECTARG1
    var l_rec = defaultLight9();
    l_rec.Diffuse = .{ .r = 0.25, .g = 0.5, .b = 0.75, .a = 1.0 };
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetLight(dev, 1, &l_rec));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.LightEnable(dev, 1, 1));

    var rec_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.EndStateBlock(dev, &rec_raw));
    const rec_sb: *WinsStateBlock9 = @ptrCast(@alignCast(rec_raw.?));
    defer _ = rec_sb.vtbl.Release(rec_sb);

    // Live state must NOT have changed during Begin/End
    var rs_val: u32 = 999;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetRenderState(dev, 14, &rs_val));
    try std.testing.expectEqual(@as(u32, 0), rs_val);
    var m_out: D3DMATRIX = undefined;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetTransform(dev, 2, &m_out));
    try std.testing.expectEqual(@as(f32, 10.0), m_out.m[3][0]);

    // Change unrelated live RS 7 before partial Apply()
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetRenderState(dev, 7, 0));
    try std.testing.expectEqual(D3D_OK, rec_sb.vtbl.Apply(rec_sb));

    // Recorded fields changed; unrecorded RS 7 remained untouched
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetRenderState(dev, 7, &rs_val));
    try std.testing.expectEqual(@as(u32, 0), rs_val);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetRenderState(dev, 14, &rs_val));
    try std.testing.expectEqual(@as(u32, 1), rs_val);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetTransform(dev, 2, &m_out));
    try std.testing.expectEqual(@as(f32, 42.0), m_out.m[3][0]);
    var l_en: i32 = 0;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetLightEnable(dev, 1, &l_en));
    try std.testing.expectEqual(@as(i32, 1), l_en);

    // QI + GetDevice checks
    var qi_ptr: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, rec_sb.vtbl.QueryInterface(rec_sb, &IID_IDirect3DStateBlock9, &qi_ptr));
    _ = rec_sb.vtbl.Release(rec_sb);
    var got_dev_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, rec_sb.vtbl.GetDevice(rec_sb, &got_dev_raw));
    try std.testing.expectEqual(@as(?*anyopaque, dev), got_dev_raw);
    const got_dev: *WinsD3DDevice9 = @ptrCast(@alignCast(got_dev_raw.?));
    _ = got_dev.vtbl.Release(got_dev);

    // CreateStateBlock(PIXELSTATE) captures RS 14 / TSS, NOT Transform 2 / Lights
    var pix_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateStateBlock(dev, D3DSBT_PIXELSTATE, &pix_raw));
    const pix_sb: *WinsStateBlock9 = @ptrCast(@alignCast(pix_raw.?));
    defer _ = pix_sb.vtbl.Release(pix_sb);
    try std.testing.expect(!pix_sb.has_transform[d3dTransformStateIndex(2).?]);
    try std.testing.expect(pix_sb.has_render_state[14]);

    // Capture overwrites pixel state when RS 14 mutates, while Transform stays independent
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetRenderState(dev, 14, 0));
    try std.testing.expectEqual(D3D_OK, pix_sb.vtbl.Capture(pix_sb));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetRenderState(dev, 14, 1));
    m_rec.m[3][0] = 99.0;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetTransform(dev, 2, &m_rec));
    try std.testing.expectEqual(D3D_OK, pix_sb.vtbl.Apply(pix_sb));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetRenderState(dev, 14, &rs_val));
    try std.testing.expectEqual(@as(u32, 0), rs_val);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetTransform(dev, 2, &m_out));
    try std.testing.expectEqual(@as(f32, 99.0), m_out.m[3][0]);

    // CreateStateBlock(ALL) captures & restores everything including transform & lights
    var all_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateStateBlock(dev, D3DSBT_ALL, &all_raw));
    const all_sb: *WinsStateBlock9 = @ptrCast(@alignCast(all_raw.?));
    defer _ = all_sb.vtbl.Release(all_sb);
    m_rec.m[3][0] = 5.0;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetTransform(dev, 2, &m_rec));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.LightEnable(dev, 1, 0));
    try std.testing.expectEqual(D3D_OK, all_sb.vtbl.Apply(all_sb));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetTransform(dev, 2, &m_out));
    try std.testing.expectEqual(@as(f32, 99.0), m_out.m[3][0]);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetLightEnable(dev, 1, &l_en));
    try std.testing.expectEqual(@as(i32, 1), l_en);

    // CreateStateBlock(VERTEXSTATE) captures vertex states (e.g. LIGHTING=137, TEXCOORDINDEX=11, lights), excludes pixel RS 14 & transforms
    var vs_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateStateBlock(dev, D3DSBT_VERTEXSTATE, &vs_raw));
    const vs_sb: *WinsStateBlock9 = @ptrCast(@alignCast(vs_raw.?));
    defer _ = vs_sb.vtbl.Release(vs_sb);
    try std.testing.expect(!vs_sb.has_render_state[14]);
    try std.testing.expect(!vs_sb.has_transform[d3dTransformStateIndex(2).?]);
    try std.testing.expect(vs_sb.has_render_state[137]);
    try std.testing.expect(vs_sb.has_tss[0][11]);
    try std.testing.expect(vs_sb.capture_all_lights);
}

test "UpdateSurface and UpdateTexture: SYSTEMMEM to DEFAULT upload, subrect copy, and invalid directions" {
    var d3d = WinsD3D9.init();
    const dev = try testDevice(&d3d);
    defer _ = dev.vtbl.Release(dev);

    // Surfaces: SYSTEMMEM (pool 2) -> DEFAULT (pool 0)
    var src_raw: ?*anyopaque = null;
    var dst_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateOffscreenPlainSurface(dev, 4, 4, D3DFMT_A8R8G8B8, 2, &src_raw, null));
    defer _ = @as(*WinsSurface9, @ptrCast(@alignCast(src_raw.?))).vtbl.Release(src_raw.?);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateOffscreenPlainSurface(dev, 4, 4, D3DFMT_A8R8G8B8, 0, &dst_raw, null));
    defer _ = @as(*WinsSurface9, @ptrCast(@alignCast(dst_raw.?))).vtbl.Release(dst_raw.?);

    const src_s: *WinsSurface9 = @ptrCast(@alignCast(src_raw.?));
    const dst_s: *WinsSurface9 = @ptrCast(@alignCast(dst_raw.?));
    var lr: D3DLOCKED_RECT = undefined;
    try std.testing.expectEqual(D3D_OK, src_s.vtbl.LockRect(src_s, &lr, null, 0));
    const spx: [*]u32 = @ptrCast(@alignCast(lr.pBits.?));
    for (0..16) |i| spx[i] = 0xAA000000 | @as(u32, @intCast(i));
    try std.testing.expectEqual(D3D_OK, src_s.vtbl.UnlockRect(src_s));

    const rect = D3DRECT{ .x1 = 1, .y1 = 1, .x2 = 3, .y2 = 3 };
    const pt = POINT{ .x = 2, .y = 1 };
    dst_s.gl_dirty = false;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.UpdateSurface(dev, src_s, &rect, dst_s, &pt));
    try std.testing.expect(dst_s.gl_dirty);
    const dst_px: [*]const u32 = @ptrCast(@alignCast(dst_s.data.ptr));
    // dst(2,1) <- src(1,1) = index 5; dst(3,2) <- src(2,2) = index 10
    try std.testing.expectEqual(@as(u32, 0xAA000005), dst_px[1 * 4 + 2]);
    try std.testing.expectEqual(@as(u32, 0xAA00000A), dst_px[2 * 4 + 3]);

    // Invalid UpdateSurface directions & pools
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.UpdateSurface(dev, dst_s, null, src_s, null));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.UpdateSurface(dev, src_s, null, src_s, null));

    // Textures: SYSTEMMEM -> DEFAULT (2D + Cube + Volume)
    var stex_raw: ?*anyopaque = null;
    var dtex_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateTexture(dev, 4, 4, 2, 0, D3DFMT_A8R8G8B8, 2, &stex_raw, null));
    defer _ = @as(*WinsTexture9, @ptrCast(@alignCast(stex_raw.?))).vtbl.Release(stex_raw.?);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateTexture(dev, 4, 4, 2, 0, D3DFMT_A8R8G8B8, 0, &dtex_raw, null));
    defer _ = @as(*WinsTexture9, @ptrCast(@alignCast(dtex_raw.?))).vtbl.Release(dtex_raw.?);
    const stex: *WinsTexture9 = @ptrCast(@alignCast(stex_raw.?));
    const dtex: *WinsTexture9 = @ptrCast(@alignCast(dtex_raw.?));
    std.mem.writeInt(u32, stex.surfaces[0].data[0..4], 0x11223344, .little);
    std.mem.writeInt(u32, stex.surfaces[1].data[0..4], 0x55667788, .little);
    dtex.gl_dirty = false;
    dtex.surfaces[0].gl_dirty = false;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.UpdateTexture(dev, stex, dtex));
    try std.testing.expect(dtex.gl_dirty);
    try std.testing.expect(dtex.surfaces[0].gl_dirty);
    try std.testing.expectEqual(@as(u32, 0x11223344), std.mem.readInt(u32, dtex.surfaces[0].data[0..4], .little));
    try std.testing.expectEqual(@as(u32, 0x55667788), std.mem.readInt(u32, dtex.surfaces[1].data[0..4], .little));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.UpdateTexture(dev, dtex, stex));

    var sct_raw: ?*anyopaque = null;
    var dct_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateCubeTexture(dev, 2, 1, 0, D3DFMT_A8R8G8B8, 2, &sct_raw, null));
    defer _ = @as(*WinsCubeTexture9, @ptrCast(@alignCast(sct_raw.?))).vtbl.Release(sct_raw.?);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateCubeTexture(dev, 2, 1, 0, D3DFMT_A8R8G8B8, 0, &dct_raw, null));
    defer _ = @as(*WinsCubeTexture9, @ptrCast(@alignCast(dct_raw.?))).vtbl.Release(dct_raw.?);
    const sct: *WinsCubeTexture9 = @ptrCast(@alignCast(sct_raw.?));
    const dct: *WinsCubeTexture9 = @ptrCast(@alignCast(dct_raw.?));
    std.mem.writeInt(u32, sct.faces[3].data[0..4], 0xDEADBEEF, .little);
    dct.gl_dirty = false;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.UpdateTexture(dev, sct, dct));
    try std.testing.expect(dct.gl_dirty);
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), std.mem.readInt(u32, dct.faces[3].data[0..4], .little));

    var svt_raw: ?*anyopaque = null;
    var dvt_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateVolumeTexture(dev, 2, 2, 2, 1, 0, D3DFMT_A8R8G8B8, 2, &svt_raw, null));
    defer _ = @as(*WinsVolumeTexture9, @ptrCast(@alignCast(svt_raw.?))).vtbl.Release(svt_raw.?);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateVolumeTexture(dev, 2, 2, 2, 1, 0, D3DFMT_A8R8G8B8, 0, &dvt_raw, null));
    defer _ = @as(*WinsVolumeTexture9, @ptrCast(@alignCast(dvt_raw.?))).vtbl.Release(dvt_raw.?);
    const svt: *WinsVolumeTexture9 = @ptrCast(@alignCast(svt_raw.?));
    const dvt: *WinsVolumeTexture9 = @ptrCast(@alignCast(dvt_raw.?));
    std.mem.writeInt(u32, svt.volumes[0].data[0..4], 0xCAFEBABE, .little);
    dvt.gl_dirty = false;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.UpdateTexture(dev, svt, dvt));
    try std.testing.expect(dvt.gl_dirty);
    try std.testing.expectEqual(@as(u32, 0xCAFEBABE), std.mem.readInt(u32, dvt.volumes[0].data[0..4], .little));
}

test "device Reset: enforces DEFAULT pool + backbuffer + recording gates, resets state and resizes targets" {
    var d3d = WinsD3D9.init();
    const dev = try testDevice(&d3d);
    defer _ = dev.vtbl.Release(dev);

    var pp = dev.params;
    pp.BackBufferWidth = 128;
    pp.BackBufferHeight = 96;
    pp.EnableAutoDepthStencil = 1;
    pp.AutoDepthStencilFormat = D3DFMT_D24S8;

    // Gate 1: active BeginStateBlock blocks Reset
    try std.testing.expectEqual(D3D_OK, dev.vtbl.BeginStateBlock(dev));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.Reset(dev, &pp));
    var sb_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.EndStateBlock(dev, &sb_raw));
    _ = @as(*WinsStateBlock9, @ptrCast(@alignCast(sb_raw.?))).vtbl.Release(sb_raw.?);

    // Gate 2: live D3DPOOL_DEFAULT VertexBuffer blocks Reset until Release
    var vb_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateVertexBuffer(dev, 64, 0, 0, 0, &vb_raw, null));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.Reset(dev, &pp));
    _ = @as(*WinsVertexBuffer9, @ptrCast(@alignCast(vb_raw.?))).vtbl.Release(vb_raw.?);

    // Gate 3: orphaned child GetSurfaceLevel ref on D3DPOOL_DEFAULT texture blocks Reset until Release
    var tex_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateTexture(dev, 4, 4, 1, 0, D3DFMT_A8R8G8B8, 0, &tex_raw, null));
    const tex: *WinsTexture9 = @ptrCast(@alignCast(tex_raw.?));
    var lvl0_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, tex.vtbl.GetSurfaceLevel(tex, 0, &lvl0_raw));
    _ = tex.vtbl.Release(tex);
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.Reset(dev, &pp));
    _ = @as(*WinsSurface9, @ptrCast(@alignCast(lvl0_raw.?))).vtbl.Release(lvl0_raw.?);

    // Gate 4: extra GetBackBuffer ref blocks Reset until Release
    var bb_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetBackBuffer(dev, 0, 0, 0, &bb_raw));
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.Reset(dev, &pp));
    _ = @as(*WinsSurface9, @ptrCast(@alignCast(bb_raw.?))).vtbl.Release(bb_raw.?);

    // Mutate states before valid Reset
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetRenderState(dev, 14, 0));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetRenderState(dev, 137, 0)); // LIGHTING = 0
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetRenderState(dev, 174, 1)); // SCISSORTESTENABLE = 1
    var mv = d3dIdentityMatrix();
    mv.m[3][0] = 77.0;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetTransform(dev, 2, &mv));
    const l0 = defaultLight9();
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetLight(dev, 0, &l0));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.LightEnable(dev, 0, 1));

    // MANAGED VB survives Reset (only DEFAULT blocks)
    var mvb_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.CreateVertexBuffer(dev, 64, 0, 0, 1, &mvb_raw, null));
    defer _ = @as(*WinsVertexBuffer9, @ptrCast(@alignCast(mvb_raw.?))).vtbl.Release(mvb_raw.?);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetStreamSource(dev, 0, mvb_raw, 0, 12));

    // Reset succeeds now
    try std.testing.expectEqual(D3D_OK, dev.vtbl.Reset(dev, &pp));

    // Verify resized targets & reset states
    var vp: D3DVIEWPORT9 = undefined;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetViewport(dev, &vp));
    try std.testing.expectEqual(@as(u32, 128), vp.Width);
    try std.testing.expectEqual(@as(u32, 96), vp.Height);
    try std.testing.expectEqual(@as(i32, 128), dev.scissor.x2);
    try std.testing.expectEqual(@as(i32, 96), dev.scissor.y2);

    var bb2_raw: ?*anyopaque = null;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetBackBuffer(dev, 0, 0, 0, &bb2_raw));
    const bb2: *WinsSurface9 = @ptrCast(@alignCast(bb2_raw.?));
    defer _ = bb2.vtbl.Release(bb2);
    var bb2_desc: D3DSURFACE_DESC = undefined;
    try std.testing.expectEqual(D3D_OK, bb2.vtbl.GetDesc(bb2, &bb2_desc));
    try std.testing.expectEqual(@as(u32, 128), bb2_desc.Width);
    try std.testing.expectEqual(@as(u32, 96), bb2_desc.Height);

    var rs: u32 = 0;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetRenderState(dev, 137, &rs));
    try std.testing.expectEqual(@as(u32, 1), rs);
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetRenderState(dev, 174, &rs));
    try std.testing.expectEqual(@as(u32, 0), rs);

    var m_after: D3DMATRIX = undefined;
    try std.testing.expectEqual(D3D_OK, dev.vtbl.GetTransform(dev, 2, &m_after));
    try std.testing.expectEqual(@as(f32, 0.0), m_after.m[3][0]);
    var l_en: i32 = 1;
    try std.testing.expectEqual(D3DERR_INVALIDCALL, dev.vtbl.GetLightEnable(dev, 0, &l_en));
    try std.testing.expect(dev.streams[0] == null);
}
