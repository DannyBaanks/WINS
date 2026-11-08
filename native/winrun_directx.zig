//! WINS Direct3D, DXGI, Shader Compiler, XInput & Multimedia Shim Module (Zig 0.16)
//! Provides standard Win64 ABI shims for DirectX 11/12, DXGI, HLSL Shader Compiler (d3dcompiler_47),
//! XInput, HID, WINMM, IMM32, VERSION, SETUPAPI, and UnityPlayer engine entry point.

const std = @import("std");
const linux = std.os.linux;
const W: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

// ============================================================================
// Direct3D 11 & DXGI Shims
// ============================================================================

/// HRESULT WINAPI D3D11CreateDevice(...)
pub fn d3d11CreateDevice(
    pAdapter: ?*anyopaque,
    DriverType: u32,
    Software: ?*anyopaque,
    Flags: u32,
    pFeatureLevels: ?*const u32,
    FeatureLevels: u32,
    SDKVersion: u32,
    ppDevice: ?*?*anyopaque,
    pFeatureLevel: ?*u32,
    ppImmediateContext: ?*?*anyopaque,
) callconv(W) i32 {
    _ = pAdapter;
    _ = DriverType;
    _ = Software;
    _ = Flags;
    _ = pFeatureLevels;
    _ = FeatureLevels;
    _ = SDKVersion;
    if (pFeatureLevel) |pfl| pfl.* = 0xb000; // D3D_FEATURE_LEVEL_11_0
    if (ppDevice) |pd| pd.* = null;
    if (ppImmediateContext) |pic| pic.* = null;
    return 0; // S_OK
}

/// HRESULT WINAPI D3D11CreateDeviceAndSwapChain(...)
pub fn d3d11CreateDeviceAndSwapChain(
    pAdapter: ?*anyopaque,
    DriverType: u32,
    Software: ?*anyopaque,
    Flags: u32,
    pFeatureLevels: ?*const u32,
    FeatureLevels: u32,
    SDKVersion: u32,
    pSwapChainDesc: ?*const anyopaque,
    ppSwapChain: ?*?*anyopaque,
    ppDevice: ?*?*anyopaque,
    pFeatureLevel: ?*u32,
    ppImmediateContext: ?*?*anyopaque,
) callconv(W) i32 {
    _ = pAdapter;
    _ = DriverType;
    _ = Software;
    _ = Flags;
    _ = pFeatureLevels;
    _ = FeatureLevels;
    _ = SDKVersion;
    _ = pSwapChainDesc;
    if (ppSwapChain) |psc| psc.* = null;
    if (ppDevice) |pd| pd.* = null;
    if (pFeatureLevel) |pfl| pfl.* = 0xb000; // D3D_FEATURE_LEVEL_11_0
    if (ppImmediateContext) |pic| pic.* = null;
    return 0; // S_OK
}

/// HRESULT WINAPI CreateDXGIFactory(REFIID riid, void **ppFactory)
pub fn createDXGIFactory(riid: ?*const anyopaque, ppFactory: ?*?*anyopaque) callconv(W) i32 {
    _ = riid;
    if (ppFactory) |pf| pf.* = null;
    return 0;
}

/// HRESULT WINAPI CreateDXGIFactory1(REFIID riid, void **ppFactory)
pub fn createDXGIFactory1(riid: ?*const anyopaque, ppFactory: ?*?*anyopaque) callconv(W) i32 {
    _ = riid;
    if (ppFactory) |pf| pf.* = null;
    return 0;
}

/// HRESULT WINAPI CreateDXGIFactory2(UINT Flags, REFIID riid, void **ppFactory)
pub fn createDXGIFactory2(Flags: u32, riid: ?*const anyopaque, ppFactory: ?*?*anyopaque) callconv(W) i32 {
    _ = Flags;
    _ = riid;
    if (ppFactory) |pf| pf.* = null;
    return 0;
}

// ============================================================================
// D3DCompiler / HLSL Shaders
// ============================================================================

/// HRESULT WINAPI D3DCompile(...)
pub fn d3dCompile(
    pSrcData: ?*const anyopaque,
    SrcDataSize: usize,
    pSourceName: ?[*:0]const u8,
    pDefines: ?*const anyopaque,
    pInclude: ?*anyopaque,
    pEntrypoint: ?[*:0]const u8,
    pTarget: ?[*:0]const u8,
    Flags1: u32,
    Flags2: u32,
    ppCode: ?*?*anyopaque,
    ppErrorMsgs: ?*?*anyopaque,
) callconv(W) i32 {
    _ = pSrcData;
    _ = SrcDataSize;
    _ = pSourceName;
    _ = pDefines;
    _ = pInclude;
    _ = pEntrypoint;
    _ = pTarget;
    _ = Flags1;
    _ = Flags2;
    if (ppCode) |pc| pc.* = null;
    if (ppErrorMsgs) |pe| pe.* = null;
    return 0;
}

pub fn d3dCreateBlob(Size: usize, ppBlob: ?*?*anyopaque) callconv(W) i32 {
    _ = Size;
    if (ppBlob) |pb| pb.* = null;
    return 0;
}

pub fn d3dDisassemble(pSrcData: ?*const anyopaque, SrcDataSize: usize, Flags: u32, szComments: ?[*:0]const u8, ppDisassembly: ?*?*anyopaque) callconv(W) i32 {
    _ = pSrcData;
    _ = SrcDataSize;
    _ = Flags;
    _ = szComments;
    if (ppDisassembly) |pd| pd.* = null;
    return 0;
}

pub fn d3dReflect(pSrcData: ?*const anyopaque, SrcDataSize: usize, pInterface: ?*const anyopaque, ppReflector: ?*?*anyopaque) callconv(W) i32 {
    _ = pSrcData;
    _ = SrcDataSize;
    _ = pInterface;
    if (ppReflector) |pr| pr.* = null;
    return 0;
}

// ============================================================================
// XInput
// ============================================================================

pub const XINPUT_GAMEPAD = extern struct {
    wButtons: u16,
    bLeftTrigger: u8,
    bRightTrigger: u8,
    sThumbLX: i16,
    sThumbLY: i16,
    sThumbRX: i16,
    sThumbRY: i16,
};

pub const XINPUT_STATE = extern struct {
    dwPacketNumber: u32,
    Gamepad: XINPUT_GAMEPAD,
};

pub fn xinputGetState(dwUserIndex: u32, pState: ?*XINPUT_STATE) callconv(W) u32 {
    _ = dwUserIndex;
    if (pState) |ps| {
        ps.dwPacketNumber = 1;
        ps.Gamepad = std.mem.zeroes(XINPUT_GAMEPAD);
    }
    return 0; // ERROR_SUCCESS
}

pub fn xinputSetState(dwUserIndex: u32, pVibration: ?*const anyopaque) callconv(W) u32 {
    _ = dwUserIndex;
    _ = pVibration;
    return 0;
}

pub fn xinputGetCapabilities(dwUserIndex: u32, dwFlags: u32, pCapabilities: ?*anyopaque) callconv(W) u32 {
    _ = dwUserIndex;
    _ = dwFlags;
    _ = pCapabilities;
    return 0;
}

pub fn xinputEnable(enable: u32) callconv(W) void {
    _ = enable;
}

// ============================================================================
// OpenGL32
// ============================================================================

pub fn wglGetProcAddress(name: ?[*:0]const u8) callconv(W) ?*anyopaque {
    _ = name;
    return null;
}

pub fn wglGetCurrentDC() callconv(W) ?*anyopaque {
    return @ptrFromInt(0x1000);
}

pub fn wglGetCurrentContext() callconv(W) ?*anyopaque {
    return @ptrFromInt(0x2000);
}

pub fn wglDeleteContext(hglrc: ?*anyopaque) callconv(W) u32 {
    _ = hglrc;
    return 1;
}

pub fn wglCreateContext(hdc: ?*anyopaque) callconv(W) ?*anyopaque {
    _ = hdc;
    return @ptrFromInt(0x2000);
}

pub fn wglMakeCurrent(hdc: ?*anyopaque, hglrc: ?*anyopaque) callconv(W) u32 {
    _ = hdc;
    _ = hglrc;
    return 1;
}

// ============================================================================
// HID (Human Interface Device)
// ============================================================================

pub fn hidD_GetManufacturerString(HidDeviceObject: ?*anyopaque, Buffer: ?*anyopaque, BufferLength: u32) callconv(W) u8 {
    _ = HidDeviceObject;
    _ = Buffer;
    _ = BufferLength;
    return 1;
}

pub fn hidD_GetSerialNumberString(HidDeviceObject: ?*anyopaque, Buffer: ?*anyopaque, BufferLength: u32) callconv(W) u8 {
    _ = HidDeviceObject;
    _ = Buffer;
    _ = BufferLength;
    return 1;
}

pub fn hidD_GetIndexedString(HidDeviceObject: ?*anyopaque, StringIndex: u32, Buffer: ?*anyopaque, BufferLength: u32) callconv(W) u8 {
    _ = HidDeviceObject;
    _ = StringIndex;
    _ = Buffer;
    _ = BufferLength;
    return 1;
}

pub fn hidD_GetAttributes(HidDeviceObject: ?*anyopaque, Attributes: ?*anyopaque) callconv(W) u8 {
    _ = HidDeviceObject;
    _ = Attributes;
    return 1;
}

pub fn hidD_GetProductString(HidDeviceObject: ?*anyopaque, Buffer: ?*anyopaque, BufferLength: u32) callconv(W) u8 {
    _ = HidDeviceObject;
    _ = Buffer;
    _ = BufferLength;
    return 1;
}

pub fn hidD_GetPreparsedData(HidDeviceObject: ?*anyopaque, PreparsedData: ?*?*anyopaque) callconv(W) u8 {
    _ = HidDeviceObject;
    if (PreparsedData) |pd| pd.* = @ptrFromInt(0x3000);
    return 1;
}

pub fn hidD_FreePreparsedData(PreparsedData: ?*anyopaque) callconv(W) u8 {
    _ = PreparsedData;
    return 1;
}

pub fn hidD_GetHidGuid(HidGuid: ?*anyopaque) callconv(W) void {
    _ = HidGuid;
}

pub fn hidP_GetCaps(PreparsedData: ?*anyopaque, Capabilities: ?*anyopaque) callconv(W) i32 {
    _ = PreparsedData;
    _ = Capabilities;
    return 0x00110000; // HIDP_STATUS_SUCCESS
}

pub fn hidP_GetButtonCaps(ReportType: u32, ButtonCaps: ?*anyopaque, ButtonCapsLength: ?*u16, PreparsedData: ?*anyopaque) callconv(W) i32 {
    _ = ReportType;
    _ = ButtonCaps;
    if (ButtonCapsLength) |bcl| bcl.* = 0;
    _ = PreparsedData;
    return 0x00110000;
}

pub fn hidP_GetValueCaps(ReportType: u32, ValueCaps: ?*anyopaque, ValueCapsLength: ?*u16, PreparsedData: ?*anyopaque) callconv(W) i32 {
    _ = ReportType;
    _ = ValueCaps;
    if (ValueCapsLength) |vcl| vcl.* = 0;
    _ = PreparsedData;
    return 0x00110000;
}

pub fn hidP_MaxDataListLength(ReportType: u32, PreparsedData: ?*anyopaque) callconv(W) u32 {
    _ = ReportType;
    _ = PreparsedData;
    return 0;
}

pub fn hidP_GetData(ReportType: u32, DataList: ?*anyopaque, DataLength: ?*u32, PreparsedData: ?*anyopaque, Report: ?*anyopaque, ReportLength: u32) callconv(W) i32 {
    _ = ReportType;
    _ = DataList;
    if (DataLength) |dl| dl.* = 0;
    _ = PreparsedData;
    _ = Report;
    _ = ReportLength;
    return 0x00110000;
}

pub fn hidP_InitializeReportForID(ReportType: u32, ReportID: u8, PreparsedData: ?*anyopaque, Report: ?*anyopaque, ReportLength: u32) callconv(W) i32 {
    _ = ReportType;
    _ = ReportID;
    _ = PreparsedData;
    _ = Report;
    _ = ReportLength;
    return 0x00110000;
}

pub fn hidP_SetUsageValue(ReportType: u32, UsagePage: u16, LinkCollection: u16, Usage: u16, UsageValue: u32, PreparsedData: ?*anyopaque, Report: ?*anyopaque, ReportLength: u32) callconv(W) i32 {
    _ = ReportType;
    _ = UsagePage;
    _ = LinkCollection;
    _ = Usage;
    _ = UsageValue;
    _ = PreparsedData;
    _ = Report;
    _ = ReportLength;
    return 0x00110000;
}

pub fn hidP_SetUsageValueArray(ReportType: u32, UsagePage: u16, LinkCollection: u16, Usage: u16, UsageValueStream: ?*anyopaque, UsageValueStreamLength: u16, PreparsedData: ?*anyopaque, Report: ?*anyopaque, ReportLength: u32) callconv(W) i32 {
    _ = ReportType;
    _ = UsagePage;
    _ = LinkCollection;
    _ = Usage;
    _ = UsageValueStream;
    _ = UsageValueStreamLength;
    _ = PreparsedData;
    _ = Report;
    _ = ReportLength;
    return 0x00110000;
}

// ============================================================================
// WINMM (Multimedia & Audio)
// ============================================================================

pub fn timeGetTime() callconv(W) u32 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    const ms = (@as(u64, @intCast(ts.sec)) * 1000) + (@as(u64, @intCast(ts.nsec)) / 1_000_000);
    return @truncate(ms);
}

pub fn timeBeginPeriod(uPeriod: u32) callconv(W) u32 {
    _ = uPeriod;
    return 0; // TIMERR_NOERROR
}

pub fn timeEndPeriod(uPeriod: u32) callconv(W) u32 {
    _ = uPeriod;
    return 0; // TIMERR_NOERROR
}

pub fn waveOutGetNumDevs() callconv(W) u32 {
    return 1;
}

pub fn waveInGetNumDevs() callconv(W) u32 {
    return 1;
}

pub fn waveOutGetDevCapsA(uDeviceID: usize, pwoc: ?*anyopaque, cbwoc: u32) callconv(W) u32 {
    _ = uDeviceID;
    _ = pwoc;
    _ = cbwoc;
    return 0; // MMSYSERR_NOERROR
}

pub fn waveOutGetDevCapsW(uDeviceID: usize, pwoc: ?*anyopaque, cbwoc: u32) callconv(W) u32 {
    _ = uDeviceID;
    _ = pwoc;
    _ = cbwoc;
    return 0;
}

pub fn waveInGetDevCapsA(uDeviceID: usize, pwic: ?*anyopaque, cbwic: u32) callconv(W) u32 {
    _ = uDeviceID;
    _ = pwic;
    _ = cbwic;
    return 0;
}

pub fn waveInGetDevCapsW(uDeviceID: usize, pwic: ?*anyopaque, cbwic: u32) callconv(W) u32 {
    _ = uDeviceID;
    _ = pwic;
    _ = cbwic;
    return 0;
}

pub fn waveOutOpen(phwo: ?*?*anyopaque, uDeviceID: u32, pwfx: ?*const anyopaque, dwCallback: usize, dwInstance: usize, fdwOpen: u32) callconv(W) u32 {
    _ = uDeviceID;
    _ = pwfx;
    _ = dwCallback;
    _ = dwInstance;
    _ = fdwOpen;
    if (phwo) |ph| ph.* = @ptrFromInt(0x4000);
    return 0;
}

pub fn waveOutClose(hwo: ?*anyopaque) callconv(W) u32 {
    _ = hwo;
    return 0;
}

pub fn waveOutPrepareHeader(hwo: ?*anyopaque, pwh: ?*anyopaque, cbwh: u32) callconv(W) u32 {
    _ = hwo;
    _ = pwh;
    _ = cbwh;
    return 0;
}

pub fn waveOutUnprepareHeader(hwo: ?*anyopaque, pwh: ?*anyopaque, cbwh: u32) callconv(W) u32 {
    _ = hwo;
    _ = pwh;
    _ = cbwh;
    return 0;
}

pub fn waveOutWrite(hwo: ?*anyopaque, pwh: ?*anyopaque, cbwh: u32) callconv(W) u32 {
    _ = hwo;
    _ = pwh;
    _ = cbwh;
    return 0;
}

pub fn waveOutReset(hwo: ?*anyopaque) callconv(W) u32 {
    _ = hwo;
    return 0;
}

pub fn waveOutGetPosition(hwo: ?*anyopaque, pmmt: ?*anyopaque, cbmmt: u32) callconv(W) u32 {
    _ = hwo;
    _ = pmmt;
    _ = cbmmt;
    return 0;
}

pub fn waveInOpen(phwi: ?*?*anyopaque, uDeviceID: u32, pwfx: ?*const anyopaque, dwCallback: usize, dwInstance: usize, fdwOpen: u32) callconv(W) u32 {
    _ = uDeviceID;
    _ = pwfx;
    _ = dwCallback;
    _ = dwInstance;
    _ = fdwOpen;
    if (phwi) |ph| ph.* = @ptrFromInt(0x5000);
    return 0;
}

pub fn waveInClose(hwi: ?*anyopaque) callconv(W) u32 {
    _ = hwi;
    return 0;
}

pub fn waveInPrepareHeader(hwi: ?*anyopaque, pwh: ?*anyopaque, cbwh: u32) callconv(W) u32 {
    _ = hwi;
    _ = pwh;
    _ = cbwh;
    return 0;
}

pub fn waveInUnprepareHeader(hwi: ?*anyopaque, pwh: ?*anyopaque, cbwh: u32) callconv(W) u32 {
    _ = hwi;
    _ = pwh;
    _ = cbwh;
    return 0;
}

pub fn waveInAddBuffer(hwi: ?*anyopaque, pwh: ?*anyopaque, cbwh: u32) callconv(W) u32 {
    _ = hwi;
    _ = pwh;
    _ = cbwh;
    return 0;
}

pub fn waveInStart(hwi: ?*anyopaque) callconv(W) u32 {
    _ = hwi;
    return 0;
}

pub fn waveInReset(hwi: ?*anyopaque) callconv(W) u32 {
    _ = hwi;
    return 0;
}

// ============================================================================
// IMM32 (Input Method Manager)
// ============================================================================

pub fn immGetContext(hWnd: ?*anyopaque) callconv(W) ?*anyopaque {
    _ = hWnd;
    return @ptrFromInt(0x6000);
}

pub fn immReleaseContext(hWnd: ?*anyopaque, hIMC: ?*anyopaque) callconv(W) u32 {
    _ = hWnd;
    _ = hIMC;
    return 1;
}

pub fn immAssociateContext(hWnd: ?*anyopaque, hIMC: ?*anyopaque) callconv(W) ?*anyopaque {
    _ = hWnd;
    _ = hIMC;
    return null;
}

pub fn immAssociateContextEx(hWnd: ?*anyopaque, hIMC: ?*anyopaque, dwFlags: u32) callconv(W) u32 {
    _ = hWnd;
    _ = hIMC;
    _ = dwFlags;
    return 1;
}

pub fn immGetCompositionStringW(hIMC: ?*anyopaque, dwIndex: u32, lpBuf: ?*anyopaque, dwBufLen: u32) callconv(W) i32 {
    _ = hIMC;
    _ = dwIndex;
    _ = lpBuf;
    _ = dwBufLen;
    return 0;
}

pub fn immSetCompositionStringW(hIMC: ?*anyopaque, dwIndex: u32, lpComp: ?*const anyopaque, dwCompLen: u32, lpRead: ?*const anyopaque, dwReadLen: u32) callconv(W) u32 {
    _ = hIMC;
    _ = dwIndex;
    _ = lpComp;
    _ = dwCompLen;
    _ = lpRead;
    _ = dwReadLen;
    return 1;
}

pub fn immGetConversionStatus(hIMC: ?*anyopaque, lpfdwConversion: ?*u32, lpfdwSentence: ?*u32) callconv(W) u32 {
    _ = hIMC;
    if (lpfdwConversion) |c| c.* = 0;
    if (lpfdwSentence) |s| s.* = 0;
    return 1;
}

pub fn immSetOpenStatus(hIMC: ?*anyopaque, fOpen: u32) callconv(W) u32 {
    _ = hIMC;
    _ = fOpen;
    return 1;
}

// ============================================================================
// VERSION (File Version Information)
// ============================================================================

pub fn getFileVersionInfoSizeA(lptstrFilename: ?[*:0]const u8, lpdwHandle: ?*u32) callconv(W) u32 {
    _ = lptstrFilename;
    if (lpdwHandle) |h| h.* = 0;
    return 512;
}

pub fn getFileVersionInfoSizeW(lptstrFilename: ?[*:0]const u16, lpdwHandle: ?*u32) callconv(W) u32 {
    _ = lptstrFilename;
    if (lpdwHandle) |h| h.* = 0;
    return 512;
}

pub fn getFileVersionInfoA(lptstrFilename: ?[*:0]const u8, dwHandle: u32, dwLen: u32, lpData: ?*anyopaque) callconv(W) u32 {
    _ = lptstrFilename;
    _ = dwHandle;
    if (lpData) |p| @memset(@as([*]u8, @ptrCast(p))[0..@min(dwLen, 512)], 0);
    return 1;
}

pub fn getFileVersionInfoW(lptstrFilename: ?[*:0]const u16, dwHandle: u32, dwLen: u32, lpData: ?*anyopaque) callconv(W) u32 {
    _ = lptstrFilename;
    _ = dwHandle;
    if (lpData) |p| @memset(@as([*]u8, @ptrCast(p))[0..@min(dwLen, 512)], 0);
    return 1;
}

pub fn verQueryValueA(pBlock: ?*const anyopaque, lpSubBlock: ?[*:0]const u8, lplpBuffer: ?*?*anyopaque, puLen: ?*u32) callconv(W) u32 {
    _ = pBlock;
    _ = lpSubBlock;
    if (lplpBuffer) |b| b.* = null;
    if (puLen) |l| l.* = 0;
    return 1;
}

pub fn verQueryValueW(pBlock: ?*const anyopaque, lpSubBlock: ?[*:0]const u16, lplpBuffer: ?*?*anyopaque, puLen: ?*u32) callconv(W) u32 {
    _ = pBlock;
    _ = lpSubBlock;
    if (lplpBuffer) |b| b.* = null;
    if (puLen) |l| l.* = 0;
    return 1;
}

// ============================================================================
// SETUPAPI (Device Interface Enumeration)
// ============================================================================

pub fn setupDiGetClassDevsA(ClassGuid: ?*const anyopaque, Enumerator: ?[*:0]const u8, hwndParent: ?*anyopaque, Flags: u32) callconv(W) ?*anyopaque {
    _ = ClassGuid;
    _ = Enumerator;
    _ = hwndParent;
    _ = Flags;
    return @ptrFromInt(0x7000);
}

pub fn setupDiGetClassDevsW(ClassGuid: ?*const anyopaque, Enumerator: ?[*:0]const u16, hwndParent: ?*anyopaque, Flags: u32) callconv(W) ?*anyopaque {
    _ = ClassGuid;
    _ = Enumerator;
    _ = hwndParent;
    _ = Flags;
    return @ptrFromInt(0x7000);
}

pub fn setupDiEnumDeviceInterfaces(DeviceInfoSet: ?*anyopaque, DeviceInfoData: ?*anyopaque, InterfaceClassGuid: ?*const anyopaque, MemberIndex: u32, DeviceInterfaceData: ?*anyopaque) callconv(W) u32 {
    _ = DeviceInfoSet;
    _ = DeviceInfoData;
    _ = InterfaceClassGuid;
    _ = MemberIndex;
    _ = DeviceInterfaceData;
    return 0; // FALSE (no more devices)
}

pub fn setupDiGetDeviceInterfaceDetailW(DeviceInfoSet: ?*anyopaque, DeviceInterfaceData: ?*anyopaque, DeviceInterfaceDetailData: ?*anyopaque, DeviceInterfaceDetailDataSize: u32, RequiredSize: ?*u32, DeviceInfoData: ?*anyopaque) callconv(W) u32 {
    _ = DeviceInfoSet;
    _ = DeviceInterfaceData;
    _ = DeviceInterfaceDetailData;
    _ = DeviceInterfaceDetailDataSize;
    if (RequiredSize) |rs| rs.* = 0;
    _ = DeviceInfoData;
    return 0;
}

pub fn setupDiDestroyDeviceInfoList(DeviceInfoSet: ?*anyopaque) callconv(W) u32 {
    _ = DeviceInfoSet;
    return 1;
}

// ============================================================================
// Unity Engine Main Entry
// ============================================================================

/// int WINAPI UnityMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nShowCmd)
pub fn unityMain(
    hInstance: ?*anyopaque,
    hPrevInstance: ?*anyopaque,
    lpCmdLine: ?[*:0]const u16,
    nShowCmd: i32,
) callconv(W) i32 {
    _ = hInstance;
    _ = hPrevInstance;
    _ = lpCmdLine;
    _ = nShowCmd;
    return 0; // Engine exit success
}

// ============================================================================
// Dispatch Lookup Table
// ============================================================================

pub fn lookupDirectX(sym: []const u8) ?*const anyopaque {
    const table = [_]struct { name: []const u8, func: *const anyopaque }{
        .{ .name = "D3D11CreateDevice", .func = @ptrCast(&d3d11CreateDevice) },
        .{ .name = "D3D11CreateDeviceAndSwapChain", .func = @ptrCast(&d3d11CreateDeviceAndSwapChain) },
        .{ .name = "CreateDXGIFactory", .func = @ptrCast(&createDXGIFactory) },
        .{ .name = "CreateDXGIFactory1", .func = @ptrCast(&createDXGIFactory1) },
        .{ .name = "CreateDXGIFactory2", .func = @ptrCast(&createDXGIFactory2) },
        .{ .name = "D3DCompile", .func = @ptrCast(&d3dCompile) },
        .{ .name = "D3DCreateBlob", .func = @ptrCast(&d3dCreateBlob) },
        .{ .name = "D3DDisassemble", .func = @ptrCast(&d3dDisassemble) },
        .{ .name = "D3DReflect", .func = @ptrCast(&d3dReflect) },
        .{ .name = "XInputGetState", .func = @ptrCast(&xinputGetState) },
        .{ .name = "XInputSetState", .func = @ptrCast(&xinputSetState) },
        .{ .name = "XInputGetCapabilities", .func = @ptrCast(&xinputGetCapabilities) },
        .{ .name = "XInputEnable", .func = @ptrCast(&xinputEnable) },
        .{ .name = "wglGetProcAddress", .func = @ptrCast(&wglGetProcAddress) },
        .{ .name = "wglGetCurrentDC", .func = @ptrCast(&wglGetCurrentDC) },
        .{ .name = "wglGetCurrentContext", .func = @ptrCast(&wglGetCurrentContext) },
        .{ .name = "wglDeleteContext", .func = @ptrCast(&wglDeleteContext) },
        .{ .name = "wglCreateContext", .func = @ptrCast(&wglCreateContext) },
        .{ .name = "wglMakeCurrent", .func = @ptrCast(&wglMakeCurrent) },
        .{ .name = "HidD_GetManufacturerString", .func = @ptrCast(&hidD_GetManufacturerString) },
        .{ .name = "HidD_GetSerialNumberString", .func = @ptrCast(&hidD_GetSerialNumberString) },
        .{ .name = "HidD_GetIndexedString", .func = @ptrCast(&hidD_GetIndexedString) },
        .{ .name = "HidD_GetAttributes", .func = @ptrCast(&hidD_GetAttributes) },
        .{ .name = "HidD_GetProductString", .func = @ptrCast(&hidD_GetProductString) },
        .{ .name = "HidD_GetPreparsedData", .func = @ptrCast(&hidD_GetPreparsedData) },
        .{ .name = "HidD_FreePreparsedData", .func = @ptrCast(&hidD_FreePreparsedData) },
        .{ .name = "HidD_GetHidGuid", .func = @ptrCast(&hidD_GetHidGuid) },
        .{ .name = "HidP_GetCaps", .func = @ptrCast(&hidP_GetCaps) },
        .{ .name = "HidP_GetButtonCaps", .func = @ptrCast(&hidP_GetButtonCaps) },
        .{ .name = "HidP_GetValueCaps", .func = @ptrCast(&hidP_GetValueCaps) },
        .{ .name = "HidP_MaxDataListLength", .func = @ptrCast(&hidP_MaxDataListLength) },
        .{ .name = "HidP_GetData", .func = @ptrCast(&hidP_GetData) },
        .{ .name = "HidP_InitializeReportForID", .func = @ptrCast(&hidP_InitializeReportForID) },
        .{ .name = "HidP_SetUsageValue", .func = @ptrCast(&hidP_SetUsageValue) },
        .{ .name = "HidP_SetUsageValueArray", .func = @ptrCast(&hidP_SetUsageValueArray) },
        .{ .name = "timeGetTime", .func = @ptrCast(&timeGetTime) },
        .{ .name = "timeBeginPeriod", .func = @ptrCast(&timeBeginPeriod) },
        .{ .name = "timeEndPeriod", .func = @ptrCast(&timeEndPeriod) },
        .{ .name = "waveOutGetNumDevs", .func = @ptrCast(&waveOutGetNumDevs) },
        .{ .name = "waveInGetNumDevs", .func = @ptrCast(&waveInGetNumDevs) },
        .{ .name = "waveOutGetDevCapsA", .func = @ptrCast(&waveOutGetDevCapsA) },
        .{ .name = "waveOutGetDevCapsW", .func = @ptrCast(&waveOutGetDevCapsW) },
        .{ .name = "waveInGetDevCapsA", .func = @ptrCast(&waveInGetDevCapsA) },
        .{ .name = "waveInGetDevCapsW", .func = @ptrCast(&waveInGetDevCapsW) },
        .{ .name = "waveOutOpen", .func = @ptrCast(&waveOutOpen) },
        .{ .name = "waveOutClose", .func = @ptrCast(&waveOutClose) },
        .{ .name = "waveOutPrepareHeader", .func = @ptrCast(&waveOutPrepareHeader) },
        .{ .name = "waveOutUnprepareHeader", .func = @ptrCast(&waveOutUnprepareHeader) },
        .{ .name = "waveOutWrite", .func = @ptrCast(&waveOutWrite) },
        .{ .name = "waveOutReset", .func = @ptrCast(&waveOutReset) },
        .{ .name = "waveOutGetPosition", .func = @ptrCast(&waveOutGetPosition) },
        .{ .name = "waveInOpen", .func = @ptrCast(&waveInOpen) },
        .{ .name = "waveInClose", .func = @ptrCast(&waveInClose) },
        .{ .name = "waveInPrepareHeader", .func = @ptrCast(&waveInPrepareHeader) },
        .{ .name = "waveInUnprepareHeader", .func = @ptrCast(&waveInUnprepareHeader) },
        .{ .name = "waveInAddBuffer", .func = @ptrCast(&waveInAddBuffer) },
        .{ .name = "waveInStart", .func = @ptrCast(&waveInStart) },
        .{ .name = "waveInReset", .func = @ptrCast(&waveInReset) },
        .{ .name = "ImmGetContext", .func = @ptrCast(&immGetContext) },
        .{ .name = "ImmReleaseContext", .func = @ptrCast(&immReleaseContext) },
        .{ .name = "ImmAssociateContext", .func = @ptrCast(&immAssociateContext) },
        .{ .name = "ImmAssociateContextEx", .func = @ptrCast(&immAssociateContextEx) },
        .{ .name = "ImmGetCompositionStringW", .func = @ptrCast(&immGetCompositionStringW) },
        .{ .name = "ImmSetCompositionStringW", .func = @ptrCast(&immSetCompositionStringW) },
        .{ .name = "ImmGetConversionStatus", .func = @ptrCast(&immGetConversionStatus) },
        .{ .name = "ImmSetOpenStatus", .func = @ptrCast(&immSetOpenStatus) },
        .{ .name = "GetFileVersionInfoSizeA", .func = @ptrCast(&getFileVersionInfoSizeA) },
        .{ .name = "GetFileVersionInfoSizeW", .func = @ptrCast(&getFileVersionInfoSizeW) },
        .{ .name = "GetFileVersionInfoA", .func = @ptrCast(&getFileVersionInfoA) },
        .{ .name = "GetFileVersionInfoW", .func = @ptrCast(&getFileVersionInfoW) },
        .{ .name = "VerQueryValueA", .func = @ptrCast(&verQueryValueA) },
        .{ .name = "VerQueryValueW", .func = @ptrCast(&verQueryValueW) },
        .{ .name = "SetupDiGetClassDevsA", .func = @ptrCast(&setupDiGetClassDevsA) },
        .{ .name = "SetupDiGetClassDevsW", .func = @ptrCast(&setupDiGetClassDevsW) },
        .{ .name = "SetupDiEnumDeviceInterfaces", .func = @ptrCast(&setupDiEnumDeviceInterfaces) },
        .{ .name = "SetupDiGetDeviceInterfaceDetailW", .func = @ptrCast(&setupDiGetDeviceInterfaceDetailW) },
        .{ .name = "SetupDiDestroyDeviceInfoList", .func = @ptrCast(&setupDiDestroyDeviceInfoList) },
        .{ .name = "UnityMain", .func = @ptrCast(&unityMain) },
    };

    for (table) |entry| {
        if (std.mem.eql(u8, sym, entry.name)) return entry.func;
    }
    return null;
}
