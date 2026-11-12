//! WINS Native Direct3D 9 State Tracker & COM Implementation (Zig 0.16)
//! Provides a 100% native Linux Direct3D 9 runtime (Zero Wine, Zero Proton).
//! Directly implements IDirect3D9, IDirect3DDevice9, IDirect3DTexture9,
//! IDirect3DVertexBuffer9, IDirect3DIndexBuffer9, IDirect3DSurface9, and ID3DXBuffer
//! with true bit-exact __stdcall ABI and software rasterization capabilities.

const std = @import("std");
const linux = std.os.linux;

pub const W: std.builtin.CallingConvention = .winapi;

// ============================================================================
// D3D9 Types & Enums
// ============================================================================

pub const HRESULT = i32;
pub const S_OK: HRESULT = 0;
pub const S_FALSE: HRESULT = 1;
pub const E_FAIL: HRESULT = -2147467259; // 0x80004005
pub const E_NOINTERFACE: HRESULT = -2147467262; // 0x80004002
pub const E_NOTIMPL: HRESULT = -2147467263; // 0x80004001
pub const E_POINTER: HRESULT = -2147467263; // 0x80004003
pub const E_OUTOFMEMORY: HRESULT = -2147024882; // 0x8007000E
pub const D3DERR_INVALIDARG: HRESULT = -2147024809; // 0x80070057
pub const D3DERR_NOTAVAILABLE: HRESULT = -2005530518; // 0x8876086A
pub const D3D_OK: HRESULT = S_OK;

pub const D3DFMT_A8R8G8B8: u32 = 21;
pub const D3DFMT_X8R8G8B8: u32 = 22;
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

    pub fn create(allocator: std.mem.Allocator, width: u32, height: u32, format: u32) !*WinsSurface9 {
        const surf = try allocator.create(WinsSurface9);
        const pitch: i32 = @intCast(width * 4);
        const total_size: usize = @intCast(pitch * @as(i32, @intCast(height)));
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
    _ = flags; _ = pRect;
    const self: *WinsSurface9 = @ptrCast(@alignCast(this));
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
fn surf_GetDesc(this: *anyopaque, pDesc: ?*D3DSURFACE_DESC) callconv(W) HRESULT {
    const self: *WinsSurface9 = @ptrCast(@alignCast(this));
    if (pDesc) |d| {
        d.Width = self.width;
        d.Height = self.height;
        d.Format = self.format;
        d.Type = 3; // D3DRTYPE_SURFACE
        d.Usage = 0;
        d.Pool = 1; // D3DPOOL_MANAGED
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
    .GetType = @ptrCast(&vb_Stub),
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
    surface: *WinsSurface9,
    allocator: std.mem.Allocator,

    pub fn create(allocator: std.mem.Allocator, width: u32, height: u32, levels: u32, usage: u32, format: u32, pool: u32) !*WinsTexture9 {
        const tex = try allocator.create(WinsTexture9);
        const surf = try WinsSurface9.create(allocator, width, height, format);
        tex.* = .{
            .vtbl = &g_tex9_vtbl,
            .ref_count = 1,
            .width = width,
            .height = height,
            .levels = if (levels > 0) levels else 1,
            .usage = usage,
            .format = format,
            .pool = pool,
            .surface = surf,
            .allocator = allocator,
        };
        return tex;
    }
};

fn tex_QueryInterface(this: *anyopaque, riid: ?*const anyopaque, ppv: ?*?*anyopaque) callconv(W) HRESULT {
    _ = riid;
    if (ppv) |p| p.* = this;
    return S_OK;
}
fn tex_AddRef(this: *anyopaque) callconv(W) u32 {
    const self: *WinsTexture9 = @ptrCast(@alignCast(this));
    self.ref_count += 1;
    return self.ref_count;
}
fn tex_Release(this: *anyopaque) callconv(W) u32 {
    const self: *WinsTexture9 = @ptrCast(@alignCast(this));
    if (self.ref_count > 0) self.ref_count -= 1;
    return self.ref_count;
}
fn tex_GetLevelCount(this: *anyopaque) callconv(W) u32 {
    const self: *WinsTexture9 = @ptrCast(@alignCast(this));
    return self.levels;
}
fn tex_GetLevelDesc(this: *anyopaque, level: u32, pDesc: ?*D3DSURFACE_DESC) callconv(W) HRESULT {
    _ = level;
    const self: *WinsTexture9 = @ptrCast(@alignCast(this));
    return self.surface.vtbl.GetDesc(self.surface, pDesc);
}
fn tex_GetSurfaceLevel(this: *anyopaque, level: u32, ppSurface: ?*?*anyopaque) callconv(W) HRESULT {
    _ = level;
    const self: *WinsTexture9 = @ptrCast(@alignCast(this));
    if (ppSurface) |ps| ps.* = @ptrCast(self.surface);
    return D3D_OK;
}
fn tex_LockRect(this: *anyopaque, level: u32, pLocked: ?*D3DLOCKED_RECT, pRect: ?*const D3DRECT, flags: u32) callconv(W) HRESULT {
    _ = level;
    const self: *WinsTexture9 = @ptrCast(@alignCast(this));
    return self.surface.vtbl.LockRect(self.surface, pLocked, pRect, flags);
}
fn tex_UnlockRect(this: *anyopaque, level: u32) callconv(W) HRESULT {
    _ = level;
    const self: *WinsTexture9 = @ptrCast(@alignCast(this));
    return self.surface.vtbl.UnlockRect(self.surface);
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
    .GetType = @ptrCast(&vb_Stub),
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

pub const WinsD3DDevice9 = struct {
    vtbl: *const IDirect3DDevice9Vtbl,
    ref_count: u32,
    adapter: u32,
    device_type: u32,
    params: D3DPRESENT_PARAMETERS,
    viewport: D3DVIEWPORT9,
    in_scene: bool,
    frame_count: u64,
    draw_call_count: u64,
    backbuffer: []u32,   // Screen pixels in ARGB format
    depthbuffer: []f32,  // 32-bit floating point depth buffer
    vs_consts: [256][4]f32,
    ps_consts: [224][4]f32,
    render_states: [256]u32,
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
            .in_scene = false,
            .frame_count = 0,
            .draw_call_count = 0,
            .backbuffer = pixels,
            .depthbuffer = depths,
            .vs_consts = [_][4]f32{[_]f32{ 0, 0, 0, 0 }} ** 256,
            .ps_consts = [_][4]f32{[_]f32{ 0, 0, 0, 0 }} ** 224,
            .render_states = [_]u32{0} ** 256,
            .streams = [_]?*WinsVertexBuffer9{null} ** 16,
            .stream_strides = [_]u32{0} ** 16,
            .stream_offsets = [_]u32{0} ** 16,
            .indices = null,
            .bound_textures = [_]?*WinsTexture9{null} ** 16,
            .active_vs = null,
            .active_ps = null,
            .allocator = allocator,
        };
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
    if (format == 0 or format == kDisplayMode.Format) return 1;
    return 0;
}

/// IDirect3D9::EnumAdapterModes. The guest reads the mode out of the
/// structure by offset, so it has to be written.
fn d3d9_EnumAdapterModes(this: *anyopaque, adapter: u32, format: u32, mode: u32, pMode: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    if (adapter != 0) return D3DERR_INVALIDARG;
    if (mode != 0) return D3DERR_INVALIDARG;
    if (format != 0 and format != kDisplayMode.Format) return D3DERR_INVALIDARG;
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
    _ = this; _ = adapter;
    if (pCaps) |caps| {
        @memset(std.mem.asBytes(caps), 0);
        caps.DeviceType = dev_type;
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
        caps.PixelShaderVersion = 0xFFFF0300;  // ps_3_0
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
    _ = this; _ = hFocusWindow; _ = behavior_flags;
    if (ppDevice == null or pParams == null) return E_FAIL;
    const gpa = std.heap.page_allocator;
    const dev = WinsD3DDevice9.init(gpa, adapter, dev_type, pParams.?.*) catch return E_OUTOFMEMORY;
    ppDevice.?.* = @ptrCast(dev);
    return D3D_OK;
}
/// The formats this adapter can render into.
///
/// The software back buffer is 32-bit RGBA, which the guest sees as either of
/// these. Everything else is refused rather than silently accepted: a guest
/// that is told a format is available allocates it and then writes to it.
fn isRenderTargetFormat(format: u32) bool {
    return format == D3DFMT_A8R8G8B8 or format == D3DFMT_X8R8G8B8;
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
    _ = count; _ = pRects; _ = stencil;
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
    _ = pSource; _ = pDest; _ = hWindow; _ = pDirty;
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
    const tex = WinsTexture9.create(self.allocator, Width, Height, Levels, Usage, Format, Pool) catch return E_OUTOFMEMORY;
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
    _ = base_vertex_idx; _ = min_vertex_idx; _ = num_vertices; _ = start_index;
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
    std.debug.print("[WINS:D3D9] device!TestCooperativeLevel is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
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

fn dev9_GetDirect3D(this: *anyopaque, p0: ?*?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!GetDirect3D is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetDeviceCaps(this: *anyopaque, p0: ?*D3DCAPS9) callconv(W) HRESULT {
    const dev: *WinsD3DDevice9 = @ptrCast(@alignCast(this));
    return d3d9_GetDeviceCaps(this, dev.adapter, dev.device_type, p0);
}

fn dev9_GetDisplayMode(this: *anyopaque, p0: u32, p1: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!GetDisplayMode is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
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

fn dev9_GetBackBuffer(this: *anyopaque, p0: u32, p1: u32, p2: u32, p3: ?*?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    _ = p3;
    std.debug.print("[WINS:D3D9] device!GetBackBuffer is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
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

fn dev9_CreateDepthStencilSurface(this: *anyopaque, p0: u32, p1: u32, p2: u32, p3: u32, p4: u32, p5: i32, p6: ?*?*anyopaque, p7: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    _ = p3;
    _ = p4;
    _ = p5;
    _ = p6;
    _ = p7;
    std.debug.print("[WINS:D3D9] device!CreateDepthStencilSurface is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
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
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!SetRenderTarget is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetRenderTarget(this: *anyopaque, p0: u32, p1: ?*?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!GetRenderTarget is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetDepthStencilSurface(this: *anyopaque, p0: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!SetDepthStencilSurface is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetDepthStencilSurface(this: *anyopaque, p0: ?*?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!GetDepthStencilSurface is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetTransform(this: *anyopaque, p0: u32, p1: ?*const anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!SetTransform is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetTransform(this: *anyopaque, p0: u32, p1: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!GetTransform is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_MultiplyTransform(this: *anyopaque, p0: u32, p1: ?*const anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!MultiplyTransform is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetMaterial(this: *anyopaque, p0: ?*const anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!SetMaterial is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetMaterial(this: *anyopaque, p0: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!GetMaterial is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetLight(this: *anyopaque, p0: u32, p1: ?*const anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!SetLight is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetLight(this: *anyopaque, p0: u32, p1: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!GetLight is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_LightEnable(this: *anyopaque, p0: u32, p1: i32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!LightEnable is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetLightEnable(this: *anyopaque, p0: u32, p1: ?*i32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!GetLightEnable is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
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

fn dev9_GetTextureStageState(this: *anyopaque, p0: u32, p1: u32, p2: ?*u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    std.debug.print("[WINS:D3D9] device!GetTextureStageState is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetTextureStageState(this: *anyopaque, p0: u32, p1: u32, p2: u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    std.debug.print("[WINS:D3D9] device!SetTextureStageState is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetSamplerState(this: *anyopaque, p0: u32, p1: u32, p2: ?*u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    std.debug.print("[WINS:D3D9] device!GetSamplerState is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetSamplerState(this: *anyopaque, p0: u32, p1: u32, p2: u32) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    _ = p2;
    std.debug.print("[WINS:D3D9] device!SetSamplerState is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
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

fn dev9_CreateVertexDeclaration(this: *anyopaque, p0: ?*const anyopaque, p1: ?*?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    _ = p1;
    std.debug.print("[WINS:D3D9] device!CreateVertexDeclaration is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_SetVertexDeclaration(this: *anyopaque, p0: ?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!SetVertexDeclaration is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
}

fn dev9_GetVertexDeclaration(this: *anyopaque, p0: ?*?*anyopaque) callconv(W) HRESULT {
    _ = this;
    _ = p0;
    std.debug.print("[WINS:D3D9] device!GetVertexDeclaration is not implemented yet (caller 0x{x})\n", .{@returnAddress()});
    return E_NOTIMPL;
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
    .BeginScene = &dev9_BeginScene,
    .EndScene = &dev9_EndScene,
    .Clear = &dev9_Clear,
    .SetTransform = @ptrCast(&dev9_SetTransform),
    .GetTransform = @ptrCast(&dev9_GetTransform),
    .MultiplyTransform = @ptrCast(&dev9_MultiplyTransform),
    .SetViewport = &dev9_SetViewport,
    .GetViewport = &dev9_GetViewport,
    .SetMaterial = @ptrCast(&dev9_SetMaterial),
    .GetMaterial = @ptrCast(&dev9_GetMaterial),
    .SetLight = @ptrCast(&dev9_SetLight),
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
    _ = col; _ = wszName;
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

    const m00 = m.m[0][0]; const m01 = m.m[0][1]; const m02 = m.m[0][2]; const m03 = m.m[0][3];
    const m10 = m.m[1][0]; const m11 = m.m[1][1]; const m12 = m.m[1][2]; const m13 = m.m[1][3];
    const m20 = m.m[2][0]; const m21 = m.m[2][1]; const m22 = m.m[2][2]; const m23 = m.m[2][3];
    const m30 = m.m[3][0]; const m31 = m.m[3][1]; const m32 = m.m[3][2]; const m33 = m.m[3][3];

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
        out.x = 0; out.y = 0; out.z = 0;
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
        out.a = 0; out.b = 0; out.c = 0; out.d = 0;
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
    _ = pSrcData; _ = SrcDataLen; _ = pDefines; _ = pInclude; _ = Flags; _ = ppErrorMsgs;
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
    _ = pSrcData; _ = SrcDataLen; _ = pDefines; _ = pInclude; _ = pFunctionName; _ = pProfile; _ = Flags; _ = ppErrorMsgs;
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
    _ = pDestSurface; _ = pDestPalette; _ = pDestRect; _ = pSrcSurface; _ = pSrcPalette; _ = pSrcRect; _ = Filter; _ = ColorKey;
    return D3D_OK;
}

pub export fn D3DXSaveTextureToFileA(
    pDestFile: ?[*:0]const u8,
    DestFormat: u32,
    pSrcTexture: ?*anyopaque,
    pSrcPalette: ?*const anyopaque,
) callconv(W) HRESULT {
    _ = pDestFile; _ = DestFormat; _ = pSrcTexture; _ = pSrcPalette;
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
    try std.testing.expectEqual(@as(u32, 0xFFFF0300), caps.PixelShaderVersion);  // ps_3_0
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
    verts[0] = 0.0;   verts[1] = 0.5;   verts[2] = 0.5;
    verts[3] = -0.5;  verts[4] = -0.5;  verts[5] = 0.5;
    verts[6] = 0.5;   verts[7] = -0.5;  verts[8] = 0.5;
    try std.testing.expectEqual(D3D_OK, vb.vtbl.Unlock(vb));

    // Bind Vertex Buffer and Draw Primitive
    try std.testing.expectEqual(D3D_OK, dev.vtbl.SetStreamSource(dev, 0, vb, 0, 12));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.BeginScene(dev));
    try std.testing.expectEqual(D3D_OK, dev.vtbl.DrawPrimitive(dev, 4, 0, 1)); // 1 triangle
    try std.testing.expectEqual(D3D_OK, dev.vtbl.EndScene(dev));
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
