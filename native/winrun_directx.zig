//! WINS Direct3D, DXGI, Shader Compiler, XInput & Multimedia Shim Module (Zig 0.16)
//! Provides standard Win64 ABI shims for DirectX 11/12, DXGI, HLSL Shader Compiler (d3dcompiler_47),
//! XInput, HID, WINMM, IMM32, VERSION, SETUPAPI, and UnityPlayer engine entry point.

const std = @import("std");
const linux = std.os.linux;
const d3d11 = @import("wins_d3d11.zig");
const W: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

// ============================================================================
// Direct3D 11 & DXGI (backed by OpenGL 4.2+ Core in wins_d3d11.zig)
// ============================================================================

/// HRESULT WINAPI D3D11CreateDevice(...)
pub fn d3d11CreateDevice(
    pAdapter: ?*anyopaque,
    DriverType: u32,
    Software: ?*anyopaque,
    Flags: u32,
    pFeatureLevels: ?[*]const u32,
    FeatureLevels: u32,
    SDKVersion: u32,
    ppDevice: ?*?*anyopaque,
    pFeatureLevel: ?*u32,
    ppImmediateContext: ?*?*anyopaque,
) callconv(W) i32 {
    return d3d11.d3d11CreateDevice(
        pAdapter,
        DriverType,
        @intFromPtr(Software),
        Flags,
        pFeatureLevels,
        FeatureLevels,
        SDKVersion,
        ppDevice,
        pFeatureLevel,
        ppImmediateContext,
    );
}

/// HRESULT WINAPI D3D11CreateDeviceAndSwapChain(...)
pub fn d3d11CreateDeviceAndSwapChain(
    pAdapter: ?*anyopaque,
    DriverType: u32,
    Software: ?*anyopaque,
    Flags: u32,
    pFeatureLevels: ?[*]const u32,
    FeatureLevels: u32,
    SDKVersion: u32,
    pSwapChainDesc: ?*const anyopaque,
    ppSwapChain: ?*?*anyopaque,
    ppDevice: ?*?*anyopaque,
    pFeatureLevel: ?*u32,
    ppImmediateContext: ?*?*anyopaque,
) callconv(W) i32 {
    return d3d11.d3d11CreateDeviceAndSwapChain(
        pAdapter,
        DriverType,
        @intFromPtr(Software),
        Flags,
        pFeatureLevels,
        FeatureLevels,
        SDKVersion,
        @ptrCast(@alignCast(pSwapChainDesc)),
        ppSwapChain,
        ppDevice,
        pFeatureLevel,
        ppImmediateContext,
    );
}

/// HRESULT WINAPI CreateDXGIFactory(REFIID riid, void **ppFactory)
pub fn createDXGIFactory(riid: *const anyopaque, ppFactory: *?*anyopaque) callconv(W) i32 {
    return d3d11.createDXGIFactory(@ptrCast(@alignCast(riid)), ppFactory);
}

/// HRESULT WINAPI CreateDXGIFactory1(REFIID riid, void **ppFactory)
pub fn createDXGIFactory1(riid: *const anyopaque, ppFactory: *?*anyopaque) callconv(W) i32 {
    return d3d11.createDXGIFactory1(@ptrCast(@alignCast(riid)), ppFactory);
}

/// HRESULT WINAPI CreateDXGIFactory2(UINT Flags, REFIID riid, void **ppFactory)
pub fn createDXGIFactory2(Flags: u32, riid: *const anyopaque, ppFactory: *?*anyopaque) callconv(W) i32 {
    _ = Flags;
    return d3d11.createDXGIFactory1(@ptrCast(@alignCast(riid)), ppFactory);
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
// XInput — real Win64 path. wins_xinput.zig drives Linux evdev/joystick
// through the SDL2 GameController bridge (dlopen). When no pad is attached it
// returns ERROR_DEVICE_NOT_CONNECTED (1167) honestly, which is valid Windows
// behaviour and lets games (Rewired) finish XInput initialisation and fall
// back to keyboard/RawInput.
// ============================================================================

const xinput = @import("wins_xinput.zig");

pub const XINPUT_GAMEPAD = xinput.XINPUT_GAMEPAD;
pub const XINPUT_STATE = xinput.XINPUT_STATE;
pub const XINPUT_VIBRATION = xinput.XINPUT_VIBRATION;
pub const XINPUT_CAPABILITIES = xinput.XINPUT_CAPABILITIES;

fn xiTrace(comptime name: []const u8, dwUserIndex: u32, ret: u32) void {
    if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:XInput] {s}({d}) -> {d}\n", .{ name, dwUserIndex, ret });
}

pub fn xinputGetState(dwUserIndex: u32, pState: ?*XINPUT_STATE) callconv(W) u32 {
    const r = xinput.XInputGetState(dwUserIndex, pState);
    xiTrace("XInputGetState", dwUserIndex, r);
    return r;
}

pub fn xinputGetStateEx(dwUserIndex: u32, pState: ?*XINPUT_STATE) callconv(W) u32 {
    const r = xinput.XInputGetStateEx(dwUserIndex, pState);
    xiTrace("XInputGetStateEx", dwUserIndex, r);
    return r;
}

pub fn xinputSetState(dwUserIndex: u32, pVibration: ?*const XINPUT_VIBRATION) callconv(W) u32 {
    const r = xinput.XInputSetState(dwUserIndex, pVibration);
    xiTrace("XInputSetState", dwUserIndex, r);
    return r;
}

pub fn xinputGetCapabilities(dwUserIndex: u32, dwFlags: u32, pCapabilities: ?*XINPUT_CAPABILITIES) callconv(W) u32 {
    const r = xinput.XInputGetCapabilities(dwUserIndex, dwFlags, pCapabilities);
    if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:XInput] XInputGetCapabilities({d}, flags={d}) -> {d} caps.Type={d} SubType={d}\n", .{ dwUserIndex, dwFlags, r, if (pCapabilities) |c| c.Type else 0, if (pCapabilities) |c| c.SubType else 0 });
    return r;
}

pub fn xinputEnable(enable: u32) callconv(W) void {
    if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:XInput] XInputEnable({d})\n", .{enable});
    xinput.XInputEnable(if (enable != 0) 1 else 0);
}

pub fn xinputGetDSoundAudioDeviceGuids(dwUserIndex: u32, pRenderGuid: ?*[16]u8, pCaptureGuid: ?*[16]u8) callconv(W) u32 {
    return xinput.XInputGetDSoundAudioDeviceGuids(dwUserIndex, pRenderGuid, pCaptureGuid);
}

pub fn xinputGetBatteryInformation(dwUserIndex: u32, devType: u8, pBatteryInfo: ?*xinput.XINPUT_BATTERY_INFORMATION) callconv(W) u32 {
    return xinput.XInputGetBatteryInformation(dwUserIndex, devType, pBatteryInfo);
}

pub fn xinputGetKeystroke(dwUserIndex: u32, dwReserved: u32, pKeystroke: ?*xinput.XINPUT_KEYSTROKE) callconv(W) u32 {
    return xinput.XInputGetKeystroke(dwUserIndex, dwReserved, pKeystroke);
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

pub fn hidD_GetHidGuid(HidGuid: ?*GUID) callconv(W) void {
    if (HidGuid) |g| {
        // GUID_DEVINTERFACE_HID = {4D1E55B2-F16F-11CF-88CB-001111000030}
        g.* = .{
            .Data1 = 0x4d1e55b2,
            .Data2 = 0xf16f,
            .Data3 = 0x11cf,
            .Data4 = .{ 0x88, 0xcb, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30 },
        };
    }
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

pub fn timeGetDevCaps(ptc: ?[*]u32, cbtc: u32) callconv(W) u32 {
    if (ptc == null or cbtc < 8) return 96; // MMSYSERR_INVALPARAM / TIMERR_STRUCT
    ptc.?[0] = 1; // wPeriodMin = 1 ms
    ptc.?[1] = 1_000_000; // wPeriodMax = 1,000,000 ms
    return 0; // TIMERR_NOERROR
}

var next_timer_id: std.atomic.Value(u32) = std.atomic.Value(u32).init(1);

pub fn timeSetEvent(uDelay: u32, uResolution: u32, fptc: usize, dwUser: usize, fuEvent: u32) callconv(W) u32 {
    _ = uResolution;
    // TIME_CALLBACK_EVENT_SET = 0x0010, TIME_CALLBACK_EVENT_PULSE = 0x0020, TIME_PERIODIC = 1
    // Return non-zero timer ID; for Mono's timer thread, if TIME_CALLBACK_FUNCTION (0) spawns once/periodic:
    const id = next_timer_id.fetchAdd(1, .monotonic);
    if (fptc == 0) return id;
    if ((fuEvent & 0x0030) == 0) {
        // Defer thread spawn if delay > 0 via detached pthread/zig thread
        const Ctx = struct {
            delay_ms: u32,
            cb: *const fn (u32, u32, usize, usize, usize) callconv(W) void,
            id: u32,
            user: usize,
            periodic: bool,
        };
        const t = std.Thread.spawn(.{}, struct {
            fn run(ctx: Ctx) void {
                while (true) {
                    var ts: linux.timespec = .{
                        .sec = @intCast(ctx.delay_ms / 1000),
                        .nsec = @intCast(@as(u64, ctx.delay_ms % 1000) * 1_000_000),
                    };
                    _ = linux.nanosleep(&ts, null);
                    ctx.cb(ctx.id, 0, ctx.user, 0, 0);
                    if (!ctx.periodic) break;
                }
            }
        }.run, .{Ctx{
            .delay_ms = if (uDelay == 0) 1 else uDelay,
            .cb = @ptrFromInt(fptc),
            .id = id,
            .user = dwUser,
            .periodic = (fuEvent & 1) != 0,
        }}) catch return id;
        t.detach();
    }
    return id;
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
// SETUPAPI (Device Information & Interface Enumeration, Win64 x86_64 ABI)
// ============================================================================

pub var set_last_error_fn: ?*const fn (u32) callconv(W) void = null;

fn setLastError(code: u32) void {
    if (set_last_error_fn) |f| f(code);
}

const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_INVALID_DATA: u32 = 13;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const ERROR_INVALID_USER_BUFFER: u32 = 1784;
const INVALID_HANDLE_ADDR: usize = std.math.maxInt(usize);

pub const GUID = extern struct {
    Data1: u32,
    Data2: u16,
    Data3: u16,
    Data4: [8]u8,
};

pub const SP_DEVINFO_DATA = extern struct {
    cbSize: u32,
    ClassGuid: GUID,
    DevInst: u32,
    Reserved: usize,
};

pub const SP_DEVICE_INTERFACE_DATA = extern struct {
    cbSize: u32,
    InterfaceClassGuid: GUID,
    Flags: u32,
    Reserved: usize,
};

pub const SP_DEVICE_INTERFACE_DETAIL_DATA_A = extern struct {
    cbSize: u32,
    DevicePath: [1]u8,
};

pub const SP_DEVICE_INTERFACE_DETAIL_DATA_W = extern struct {
    cbSize: u32,
    DevicePath: [1]u16,
};

comptime {
    if (@sizeOf(GUID) != 16) @compileError("GUID must be 16 bytes");
    if (@sizeOf(SP_DEVINFO_DATA) != 32) @compileError("Win64 SP_DEVINFO_DATA must be 32 bytes");
    if (@offsetOf(SP_DEVINFO_DATA, "ClassGuid") != 4) @compileError("SP_DEVINFO_DATA.ClassGuid offset");
    if (@offsetOf(SP_DEVINFO_DATA, "DevInst") != 20) @compileError("SP_DEVINFO_DATA.DevInst offset");
    if (@offsetOf(SP_DEVINFO_DATA, "Reserved") != 24) @compileError("SP_DEVINFO_DATA.Reserved offset");
    if (@sizeOf(SP_DEVICE_INTERFACE_DATA) != 32) @compileError("Win64 SP_DEVICE_INTERFACE_DATA must be 32 bytes");
    if (@offsetOf(SP_DEVICE_INTERFACE_DATA, "Reserved") != 24) @compileError("SP_DEVICE_INTERFACE_DATA.Reserved offset");
    if (@sizeOf(SP_DEVICE_INTERFACE_DETAIL_DATA_A) != 8) @compileError("Win64 SP_DEVICE_INTERFACE_DETAIL_DATA_A must be 8 bytes");
    if (@offsetOf(SP_DEVICE_INTERFACE_DETAIL_DATA_A, "DevicePath") != 4) @compileError("SP_DEVICE_INTERFACE_DETAIL_DATA_A.DevicePath offset");
    if (@sizeOf(SP_DEVICE_INTERFACE_DETAIL_DATA_W) != 8) @compileError("Win64 SP_DEVICE_INTERFACE_DETAIL_DATA_W must be 8 bytes");
    if (@offsetOf(SP_DEVICE_INTERFACE_DETAIL_DATA_W, "DevicePath") != 4) @compileError("SP_DEVICE_INTERFACE_DETAIL_DATA_W.DevicePath offset");
}

fn validDevInfoSet(h: ?*anyopaque) bool {
    const p = h orelse return false;
    return @intFromPtr(p) != INVALID_HANDLE_ADDR;
}

pub fn setupDiGetClassDevsA(ClassGuid: ?*const GUID, Enumerator: ?[*:0]const u8, hwndParent: ?*anyopaque, Flags: u32) callconv(W) ?*anyopaque {
    _ = ClassGuid;
    _ = Enumerator;
    _ = hwndParent;
    _ = Flags;
    return @ptrFromInt(0x7000);
}

pub fn setupDiGetClassDevsW(ClassGuid: ?*const GUID, Enumerator: ?[*:0]const u16, hwndParent: ?*anyopaque, Flags: u32) callconv(W) ?*anyopaque {
    _ = ClassGuid;
    _ = Enumerator;
    _ = hwndParent;
    _ = Flags;
    return @ptrFromInt(0x7000);
}

pub fn setupDiEnumDeviceInfo(DeviceInfoSet: ?*anyopaque, MemberIndex: u32, DeviceInfoData: ?*SP_DEVINFO_DATA) callconv(W) u32 {
    _ = MemberIndex;
    if (!validDevInfoSet(DeviceInfoSet)) {
        setLastError(ERROR_INVALID_HANDLE);
        return 0;
    }
    const did = DeviceInfoData orelse {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if (did.cbSize != @sizeOf(SP_DEVINFO_DATA)) {
        setLastError(ERROR_INVALID_USER_BUFFER);
        return 0;
    }
    setLastError(ERROR_NO_MORE_ITEMS);
    return 0; // FALSE (no raw SetupAPI devnodes; gamepads use XInput/RawInput)
}

pub fn setupDiGetDeviceRegistryPropertyA(
    DeviceInfoSet: ?*anyopaque,
    DeviceInfoData: ?*const SP_DEVINFO_DATA,
    Property: u32,
    PropertyRegDataType: ?*u32,
    PropertyBuffer: ?[*]u8,
    PropertyBufferSize: u32,
    RequiredSize: ?*u32,
) callconv(W) u32 {
    _ = Property;
    _ = PropertyBuffer;
    _ = PropertyBufferSize;
    if (PropertyRegDataType) |t| t.* = 0;
    if (RequiredSize) |rs| rs.* = 0;
    if (!validDevInfoSet(DeviceInfoSet)) {
        setLastError(ERROR_INVALID_HANDLE);
        return 0;
    }
    const did = DeviceInfoData orelse {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if (did.cbSize != @sizeOf(SP_DEVINFO_DATA)) {
        setLastError(ERROR_INVALID_USER_BUFFER);
        return 0;
    }
    setLastError(ERROR_INVALID_DATA);
    return 0;
}

pub fn setupDiGetDeviceRegistryPropertyW(
    DeviceInfoSet: ?*anyopaque,
    DeviceInfoData: ?*const SP_DEVINFO_DATA,
    Property: u32,
    PropertyRegDataType: ?*u32,
    PropertyBuffer: ?[*]u8,
    PropertyBufferSize: u32,
    RequiredSize: ?*u32,
) callconv(W) u32 {
    _ = Property;
    _ = PropertyBuffer;
    _ = PropertyBufferSize;
    if (PropertyRegDataType) |t| t.* = 0;
    if (RequiredSize) |rs| rs.* = 0;
    if (!validDevInfoSet(DeviceInfoSet)) {
        setLastError(ERROR_INVALID_HANDLE);
        return 0;
    }
    const did = DeviceInfoData orelse {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if (did.cbSize != @sizeOf(SP_DEVINFO_DATA)) {
        setLastError(ERROR_INVALID_USER_BUFFER);
        return 0;
    }
    setLastError(ERROR_INVALID_DATA);
    return 0;
}

pub fn setupDiEnumDeviceInterfaces(
    DeviceInfoSet: ?*anyopaque,
    DeviceInfoData: ?*const SP_DEVINFO_DATA,
    InterfaceClassGuid: ?*const GUID,
    MemberIndex: u32,
    DeviceInterfaceData: ?*SP_DEVICE_INTERFACE_DATA,
) callconv(W) u32 {
    _ = InterfaceClassGuid;
    _ = MemberIndex;
    if (!validDevInfoSet(DeviceInfoSet)) {
        setLastError(ERROR_INVALID_HANDLE);
        return 0;
    }
    if (DeviceInfoData) |did| {
        if (did.cbSize != @sizeOf(SP_DEVINFO_DATA)) {
            setLastError(ERROR_INVALID_USER_BUFFER);
            return 0;
        }
    }
    const ifd = DeviceInterfaceData orelse {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if (ifd.cbSize != @sizeOf(SP_DEVICE_INTERFACE_DATA)) {
        setLastError(ERROR_INVALID_USER_BUFFER);
        return 0;
    }
    setLastError(ERROR_NO_MORE_ITEMS);
    return 0; // FALSE (no more devices)
}

pub fn setupDiGetDeviceInterfaceDetailA(
    DeviceInfoSet: ?*anyopaque,
    DeviceInterfaceData: ?*const SP_DEVICE_INTERFACE_DATA,
    DeviceInterfaceDetailData: ?*SP_DEVICE_INTERFACE_DETAIL_DATA_A,
    DeviceInterfaceDetailDataSize: u32,
    RequiredSize: ?*u32,
    DeviceInfoData: ?*SP_DEVINFO_DATA,
) callconv(W) u32 {
    if (RequiredSize) |rs| rs.* = 0;
    if (!validDevInfoSet(DeviceInfoSet)) {
        setLastError(ERROR_INVALID_HANDLE);
        return 0;
    }
    const ifd = DeviceInterfaceData orelse {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if (ifd.cbSize != @sizeOf(SP_DEVICE_INTERFACE_DATA)) {
        setLastError(ERROR_INVALID_USER_BUFFER);
        return 0;
    }
    if (DeviceInterfaceDetailData) |dd| {
        if (DeviceInterfaceDetailDataSize < @sizeOf(SP_DEVICE_INTERFACE_DETAIL_DATA_A) or
            dd.cbSize != @sizeOf(SP_DEVICE_INTERFACE_DETAIL_DATA_A))
        {
            setLastError(ERROR_INVALID_USER_BUFFER);
            return 0;
        }
    }
    if (DeviceInfoData) |did| {
        if (did.cbSize != @sizeOf(SP_DEVINFO_DATA)) {
            setLastError(ERROR_INVALID_USER_BUFFER);
            return 0;
        }
    }
    setLastError(ERROR_NO_MORE_ITEMS);
    return 0;
}

pub fn setupDiGetDeviceInterfaceDetailW(
    DeviceInfoSet: ?*anyopaque,
    DeviceInterfaceData: ?*const SP_DEVICE_INTERFACE_DATA,
    DeviceInterfaceDetailData: ?*SP_DEVICE_INTERFACE_DETAIL_DATA_W,
    DeviceInterfaceDetailDataSize: u32,
    RequiredSize: ?*u32,
    DeviceInfoData: ?*SP_DEVINFO_DATA,
) callconv(W) u32 {
    if (RequiredSize) |rs| rs.* = 0;
    if (!validDevInfoSet(DeviceInfoSet)) {
        setLastError(ERROR_INVALID_HANDLE);
        return 0;
    }
    const ifd = DeviceInterfaceData orelse {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if (ifd.cbSize != @sizeOf(SP_DEVICE_INTERFACE_DATA)) {
        setLastError(ERROR_INVALID_USER_BUFFER);
        return 0;
    }
    if (DeviceInterfaceDetailData) |dd| {
        if (DeviceInterfaceDetailDataSize < @sizeOf(SP_DEVICE_INTERFACE_DETAIL_DATA_W) or
            dd.cbSize != @sizeOf(SP_DEVICE_INTERFACE_DETAIL_DATA_W))
        {
            setLastError(ERROR_INVALID_USER_BUFFER);
            return 0;
        }
    }
    if (DeviceInfoData) |did| {
        if (did.cbSize != @sizeOf(SP_DEVINFO_DATA)) {
            setLastError(ERROR_INVALID_USER_BUFFER);
            return 0;
        }
    }
    setLastError(ERROR_NO_MORE_ITEMS);
    return 0;
}

pub fn setupDiDestroyDeviceInfoList(DeviceInfoSet: ?*anyopaque) callconv(W) u32 {
    if (!validDevInfoSet(DeviceInfoSet)) {
        setLastError(ERROR_INVALID_HANDLE);
        return 0;
    }
    return 1;
}

// ============================================================================
// RawInput & Key State (user32.dll, Win64 x86_64 ABI)
// ============================================================================

pub const RIM_TYPEMOUSE: u32 = 0;
pub const RIM_TYPEKEYBOARD: u32 = 1;
pub const RIM_TYPEHID: u32 = 2;

pub const RID_INPUT: u32 = 0x10000003;
pub const RID_HEADER: u32 = 0x10000005;

pub const RIDI_PREPARSEDDATA: u32 = 0x20000005;
pub const RIDI_DEVICENAME: u32 = 0x20000007;
pub const RIDI_DEVICEINFO: u32 = 0x2000000b;

pub const RIDEV_REMOVE: u32 = 0x00000001;
pub const RI_KEY_MAKE: u16 = 0x0000;
pub const RI_KEY_BREAK: u16 = 0x0001;
pub const RI_KEY_E0: u16 = 0x0002;
pub const RI_KEY_E1: u16 = 0x0004;

pub const RI_MOUSE_LEFT_BUTTON_DOWN: u16 = 0x0001;
pub const RI_MOUSE_LEFT_BUTTON_UP: u16 = 0x0002;
pub const RI_MOUSE_RIGHT_BUTTON_DOWN: u16 = 0x0004;
pub const RI_MOUSE_RIGHT_BUTTON_UP: u16 = 0x0008;
pub const RI_MOUSE_MIDDLE_BUTTON_DOWN: u16 = 0x0010;
pub const RI_MOUSE_MIDDLE_BUTTON_UP: u16 = 0x0020;

pub const RAWINPUTDEVICE = extern struct {
    usUsagePage: u16,
    usUsage: u16,
    dwFlags: u32,
    hwndTarget: usize,
};

pub const RAWINPUTDEVICELIST = extern struct {
    hDevice: usize,
    dwType: u32,
};

pub const RAWINPUTHEADER = extern struct {
    dwType: u32,
    dwSize: u32,
    hDevice: usize,
    wParam: usize,
};

pub const RAWMOUSE = extern struct {
    usFlags: u16,
    _pad0: u16 = 0,
    usButtonFlags: u16,
    usButtonData: u16,
    ulRawButtons: u32,
    lLastX: i32,
    lLastY: i32,
    ulExtraInformation: u32,
};

pub const RAWKEYBOARD = extern struct {
    MakeCode: u16,
    Flags: u16,
    Reserved: u16,
    VKey: u16,
    Message: u32,
    ExtraInformation: u32,
};

pub const RAWHID = extern struct {
    dwSizeHid: u32,
    dwCount: u32,
    bRawData: [1]u8,
};

pub const RAWINPUT = extern struct {
    header: RAWINPUTHEADER,
    data: extern union {
        mouse: RAWMOUSE,
        keyboard: RAWKEYBOARD,
        hid: RAWHID,
    },
};

pub const RID_DEVICE_INFO_MOUSE = extern struct {
    dwId: u32,
    dwNumberOfButtons: u32,
    dwSampleRate: u32,
    fHasHorizontalWheel: i32,
};

pub const RID_DEVICE_INFO_KEYBOARD = extern struct {
    dwType: u32,
    dwSubType: u32,
    dwKeyboardMode: u32,
    dwNumberOfFunctionKeys: u32,
    dwNumberOfIndicators: u32,
    dwNumberOfKeysTotal: u32,
};

pub const RID_DEVICE_INFO_HID = extern struct {
    dwVendorId: u32,
    dwProductId: u32,
    dwVersionNumber: u32,
    usUsagePage: u16,
    usUsage: u16,
};

pub const RID_DEVICE_INFO = extern struct {
    cbSize: u32,
    dwType: u32,
    info: extern union {
        mouse: RID_DEVICE_INFO_MOUSE,
        keyboard: RID_DEVICE_INFO_KEYBOARD,
        hid: RID_DEVICE_INFO_HID,
    },
};

comptime {
    if (@sizeOf(RAWINPUTDEVICE) != 16) @compileError("Win64 RAWINPUTDEVICE must be 16 bytes");
    if (@offsetOf(RAWINPUTDEVICE, "hwndTarget") != 8) @compileError("RAWINPUTDEVICE.hwndTarget offset");
    if (@sizeOf(RAWINPUTDEVICELIST) != 16) @compileError("Win64 RAWINPUTDEVICELIST must be 16 bytes");
    if (@offsetOf(RAWINPUTDEVICELIST, "dwType") != 8) @compileError("RAWINPUTDEVICELIST.dwType offset");
    if (@sizeOf(RAWINPUTHEADER) != 24) @compileError("Win64 RAWINPUTHEADER must be 24 bytes");
    if (@offsetOf(RAWINPUTHEADER, "hDevice") != 8) @compileError("RAWINPUTHEADER.hDevice offset");
    if (@offsetOf(RAWINPUTHEADER, "wParam") != 16) @compileError("RAWINPUTHEADER.wParam offset");
    if (@sizeOf(RAWMOUSE) != 24) @compileError("RAWMOUSE must be 24 bytes");
    if (@sizeOf(RAWKEYBOARD) != 16) @compileError("RAWKEYBOARD must be 16 bytes");
    if (@sizeOf(RAWHID) != 12) @compileError("RAWHID must be 12 bytes");
    if (@sizeOf(RAWINPUT) != 48) @compileError("Win64 RAWINPUT must be 48 bytes");
    if (@offsetOf(RAWINPUT, "data") != 24) @compileError("RAWINPUT.data offset");
    if (@sizeOf(RID_DEVICE_INFO) != 32) @compileError("Win64 RID_DEVICE_INFO must be 32 bytes");
}

const RAW_KBD_HANDLE: usize = 0x10001;
const RAW_MOUSE_HANDLE: usize = 0x10002;
const RAW_KBD_DEV_NAME = "\\\\?\\HID#WINS_KBD#1&0000#{884b96c3-56ef-11d1-bc8c-00a0c91405dd}";
const RAW_MOUSE_DEV_NAME = "\\\\?\\HID#WINS_MOUSE#1&0000#{378de44c-56ef-11d1-bc8c-00a0c91405dd}";
const RAW_KBD_PACKET_SIZE: u32 = @sizeOf(RAWINPUTHEADER) + @sizeOf(RAWKEYBOARD); // 40 bytes
const RAW_MOUSE_PACKET_SIZE: u32 = @sizeOf(RAWINPUTHEADER) + @sizeOf(RAWMOUSE); // 48 bytes
const RAW_INVALID_SIZE: u32 = std.math.maxInt(u32); // (UINT)-1

const RawInputSlot = struct {
    handle: usize = 0,
    input: RAWINPUT = std.mem.zeroes(RAWINPUT),
};

var g_raw_lock = std.atomic.Value(u32).init(0);
var g_raw_devs: [16]RAWINPUTDEVICE = [_]RAWINPUTDEVICE{std.mem.zeroes(RAWINPUTDEVICE)} ** 16;
var g_raw_dev_count: usize = 0;
var g_raw_ring: [256]RawInputSlot = [_]RawInputSlot{.{}} ** 256;
var g_raw_write_idx: usize = 0;
var g_raw_next_seq: usize = 1;

var g_vk_down: [256]std.atomic.Value(bool) = [_]std.atomic.Value(bool){std.atomic.Value(bool).init(false)} ** 256;
var g_vk_pressed_since: [256]std.atomic.Value(bool) = [_]std.atomic.Value(bool){std.atomic.Value(bool).init(false)} ** 256;
var g_vk_toggled: [256]std.atomic.Value(bool) = [_]std.atomic.Value(bool){std.atomic.Value(bool).init(false)} ** 256;

fn rawLock() void {
    while (g_raw_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
}

fn rawUnlock() void {
    g_raw_lock.store(0, .release);
}

/// Update the Win32 virtual-key state table (shared by `GetAsyncKeyState` / `GetKeyState`).
pub fn feedKeyState(vk: u16, down: bool) void {
    if (vk >= 256) return;
    const idx: usize = vk;
    const was = g_vk_down[idx].swap(down, .monotonic);
    if (down and !was) {
        g_vk_pressed_since[idx].store(true, .monotonic);
        const prev_tog = g_vk_toggled[idx].load(.monotonic);
        g_vk_toggled[idx].store(!prev_tog, .monotonic);
    }
    const generic: usize = switch (vk) {
        0xA0, 0xA1 => 0x10, // VK_LSHIFT/VK_RSHIFT -> VK_SHIFT
        0xA2, 0xA3 => 0x11, // VK_LCONTROL/VK_RCONTROL -> VK_CONTROL
        0xA4, 0xA5 => 0x12, // VK_LMENU/VK_RMENU -> VK_MENU
        else => 0,
    };
    if (generic != 0) {
        const other: usize = idx ^ 1;
        const g_down = down or g_vk_down[other].load(.monotonic);
        const g_was = g_vk_down[generic].swap(g_down, .monotonic);
        if (g_down and !g_was) {
            g_vk_pressed_since[generic].store(true, .monotonic);
            const prev_tog = g_vk_toggled[generic].load(.monotonic);
            g_vk_toggled[generic].store(!prev_tog, .monotonic);
        }
    }
}

/// Enqueue a RawInput keyboard event and update key state; returns an `HRAWINPUT` handle
/// suitable for `WM_INPUT` (`lParam`) and `GetRawInputData`.
pub fn pushRawKeyEvent(vk: u16, make_code: u16, extended: bool, down: bool) usize {
    feedKeyState(vk, down);
    var flags: u16 = if (down) RI_KEY_MAKE else RI_KEY_BREAK;
    if (extended) flags |= RI_KEY_E0;

    var pkt: RAWINPUT = std.mem.zeroes(RAWINPUT);
    pkt.header = .{
        .dwType = RIM_TYPEKEYBOARD,
        .dwSize = RAW_KBD_PACKET_SIZE,
        .hDevice = RAW_KBD_HANDLE,
        .wParam = 0, // RIM_INPUT
    };
    pkt.data.keyboard = .{
        .MakeCode = make_code,
        .Flags = flags,
        .Reserved = 0,
        .VKey = vk,
        .Message = if (down) 0x0100 else 0x0101,
        .ExtraInformation = 0,
    };

    rawLock();
    defer rawUnlock();
    const handle = 0x20000 + g_raw_next_seq;
    g_raw_next_seq +%= 1;
    if (g_raw_next_seq == 0) g_raw_next_seq = 1;
    g_raw_ring[g_raw_write_idx] = .{ .handle = handle, .input = pkt };
    g_raw_write_idx = (g_raw_write_idx + 1) % g_raw_ring.len;
    return handle;
}

/// Enqueue a RawInput mouse event and update mouse button virtual keys; returns an `HRAWINPUT` handle.
pub fn pushRawMouseEvent(dx: i32, dy: i32, button_flags: u16, button_data: u16) usize {
    if (button_flags & RI_MOUSE_LEFT_BUTTON_DOWN != 0) feedKeyState(0x01, true);
    if (button_flags & RI_MOUSE_LEFT_BUTTON_UP != 0) feedKeyState(0x01, false);
    if (button_flags & RI_MOUSE_RIGHT_BUTTON_DOWN != 0) feedKeyState(0x02, true);
    if (button_flags & RI_MOUSE_RIGHT_BUTTON_UP != 0) feedKeyState(0x02, false);
    if (button_flags & RI_MOUSE_MIDDLE_BUTTON_DOWN != 0) feedKeyState(0x04, true);
    if (button_flags & RI_MOUSE_MIDDLE_BUTTON_UP != 0) feedKeyState(0x04, false);

    var pkt: RAWINPUT = std.mem.zeroes(RAWINPUT);
    pkt.header = .{
        .dwType = RIM_TYPEMOUSE,
        .dwSize = RAW_MOUSE_PACKET_SIZE,
        .hDevice = RAW_MOUSE_HANDLE,
        .wParam = 0,
    };
    pkt.data.mouse = .{
        .usFlags = 0, // MOUSE_MOVE_RELATIVE
        ._pad0 = 0,
        .usButtonFlags = button_flags,
        .usButtonData = button_data,
        .ulRawButtons = 0,
        .lLastX = dx,
        .lLastY = dy,
        .ulExtraInformation = 0,
    };

    rawLock();
    defer rawUnlock();
    const handle = 0x20000 + g_raw_next_seq;
    g_raw_next_seq +%= 1;
    if (g_raw_next_seq == 0) g_raw_next_seq = 1;
    g_raw_ring[g_raw_write_idx] = .{ .handle = handle, .input = pkt };
    g_raw_write_idx = (g_raw_write_idx + 1) % g_raw_ring.len;
    return handle;
}

/// Returns the registered `hwndTarget` (if any) for a HID usage page/usage pair (e.g. (1, 6) keyboard, (1, 2) mouse).
pub fn getRegisteredRawInputTarget(usage_page: u16, usage: u16) ?usize {
    rawLock();
    defer rawUnlock();
    for (g_raw_devs[0..g_raw_dev_count]) |d| {
        if (d.usUsagePage == usage_page and d.usUsage == usage) return d.hwndTarget;
    }
    return null;
}

pub fn resetRawInputStateForTest() void {
    rawLock();
    g_raw_dev_count = 0;
    g_raw_write_idx = 0;
    g_raw_next_seq = 1;
    @memset(&g_raw_devs, std.mem.zeroes(RAWINPUTDEVICE));
    @memset(&g_raw_ring, RawInputSlot{});
    rawUnlock();
    for (&g_vk_down) |*v| v.store(false, .monotonic);
    for (&g_vk_pressed_since) |*v| v.store(false, .monotonic);
    for (&g_vk_toggled) |*v| v.store(false, .monotonic);
}

pub fn rawGetAsyncKeyState(vKey: i32) callconv(W) i16 {
    if (vKey < 0 or vKey >= 256) return 0;
    const idx: usize = @intCast(vKey);
    var res: u16 = if (g_vk_down[idx].load(.monotonic)) 0x8000 else 0;
    if (g_vk_pressed_since[idx].swap(false, .monotonic)) res |= 0x0001;
    return @bitCast(res);
}

pub fn rawGetKeyState(nVirtKey: i32) callconv(W) i16 {
    if (nVirtKey < 0 or nVirtKey >= 256) return 0;
    const idx: usize = @intCast(nVirtKey);
    var res: u16 = if (g_vk_down[idx].load(.monotonic)) 0x8000 else 0;
    if (g_vk_toggled[idx].load(.monotonic)) res |= 0x0001;
    return @bitCast(res);
}

pub fn registerRawInputDevices(pRawInputDevices: ?[*]const RAWINPUTDEVICE, uiNumDevices: u32, cbSize: u32) callconv(W) i32 {
    if (cbSize != @sizeOf(RAWINPUTDEVICE) or uiNumDevices == 0) {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    const devs = pRawInputDevices orelse {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    };
    rawLock();
    defer rawUnlock();
    for (devs[0..uiNumDevices]) |dev| {
        if ((dev.dwFlags & RIDEV_REMOVE) != 0) {
            if (dev.hwndTarget != 0) {
                setLastError(ERROR_INVALID_PARAMETER);
                return 0;
            }
            var i: usize = 0;
            while (i < g_raw_dev_count) : (i += 1) {
                if (g_raw_devs[i].usUsagePage == dev.usUsagePage and g_raw_devs[i].usUsage == dev.usUsage) {
                    g_raw_dev_count -= 1;
                    g_raw_devs[i] = g_raw_devs[g_raw_dev_count];
                    break;
                }
            }
            continue;
        }
        var found = false;
        for (g_raw_devs[0..g_raw_dev_count]) |*slot| {
            if (slot.usUsagePage == dev.usUsagePage and slot.usUsage == dev.usUsage) {
                slot.* = dev;
                found = true;
                break;
            }
        }
        if (!found and g_raw_dev_count < g_raw_devs.len) {
            g_raw_devs[g_raw_dev_count] = dev;
            g_raw_dev_count += 1;
        }
    }
    return 1;
}

pub fn getRegisteredRawInputDevices(pRawInputDevices: ?[*]RAWINPUTDEVICE, puiNumDevices: ?*u32, cbSize: u32) callconv(W) u32 {
    if (cbSize != @sizeOf(RAWINPUTDEVICE)) {
        setLastError(ERROR_INVALID_PARAMETER);
        return RAW_INVALID_SIZE;
    }
    const pnum = puiNumDevices orelse {
        setLastError(ERROR_INVALID_PARAMETER);
        return RAW_INVALID_SIZE;
    };
    rawLock();
    defer rawUnlock();
    const count: u32 = @intCast(g_raw_dev_count);
    if (pRawInputDevices == null) {
        pnum.* = count;
        return 0;
    }
    const cap = pnum.*;
    pnum.* = count;
    if (cap < count) {
        setLastError(ERROR_INSUFFICIENT_BUFFER);
        return RAW_INVALID_SIZE;
    }
    for (0..g_raw_dev_count) |i| {
        pRawInputDevices.?[i] = g_raw_devs[i];
    }
    return count;
}

pub fn getRawInputDeviceList(pRawInputDeviceList: ?[*]RAWINPUTDEVICELIST, puiNumDevices: ?*u32, cbSize: u32) callconv(W) u32 {
    if (cbSize != @sizeOf(RAWINPUTDEVICELIST)) {
        setLastError(ERROR_INVALID_PARAMETER);
        return RAW_INVALID_SIZE;
    }
    const pnum = puiNumDevices orelse {
        setLastError(ERROR_INVALID_PARAMETER);
        return RAW_INVALID_SIZE;
    };
    const count: u32 = 2;
    if (pRawInputDeviceList == null) {
        pnum.* = count;
        return 0;
    }
    const cap = pnum.*;
    pnum.* = count;
    if (cap < count) {
        setLastError(ERROR_INSUFFICIENT_BUFFER);
        return RAW_INVALID_SIZE;
    }
    pRawInputDeviceList.?[0] = .{ .hDevice = RAW_KBD_HANDLE, .dwType = RIM_TYPEKEYBOARD };
    pRawInputDeviceList.?[1] = .{ .hDevice = RAW_MOUSE_HANDLE, .dwType = RIM_TYPEMOUSE };
    return count;
}

fn fillDeviceInfo(hDevice: usize, out: *RID_DEVICE_INFO) bool {
    out.* = std.mem.zeroes(RID_DEVICE_INFO);
    out.cbSize = @sizeOf(RID_DEVICE_INFO);
    if (hDevice == RAW_KBD_HANDLE) {
        out.dwType = RIM_TYPEKEYBOARD;
        out.info.keyboard = .{
            .dwType = 4, // enhanced 101/102-key
            .dwSubType = 0,
            .dwKeyboardMode = 1,
            .dwNumberOfFunctionKeys = 12,
            .dwNumberOfIndicators = 3,
            .dwNumberOfKeysTotal = 104,
        };
        return true;
    }
    if (hDevice == RAW_MOUSE_HANDLE) {
        out.dwType = RIM_TYPEMOUSE;
        out.info.mouse = .{
            .dwId = 256,
            .dwNumberOfButtons = 5,
            .dwSampleRate = 0,
            .fHasHorizontalWheel = 1,
        };
        return true;
    }
    return false;
}

pub fn getRawInputDeviceInfoA(hDevice: usize, uiCommand: u32, pData: ?*anyopaque, pcbSize: ?*u32) callconv(W) u32 {
    const psize = pcbSize orelse {
        setLastError(ERROR_INVALID_PARAMETER);
        return RAW_INVALID_SIZE;
    };
    if (hDevice != RAW_KBD_HANDLE and hDevice != RAW_MOUSE_HANDLE) {
        setLastError(ERROR_INVALID_HANDLE);
        return RAW_INVALID_SIZE;
    }
    switch (uiCommand) {
        RIDI_DEVICENAME => {
            const name = if (hDevice == RAW_KBD_HANDLE) RAW_KBD_DEV_NAME else RAW_MOUSE_DEV_NAME;
            const needed: u32 = @intCast(name.len + 1); // chars including NUL
            if (pData == null) {
                psize.* = needed;
                return 0;
            }
            const cap = psize.*;
            psize.* = needed;
            if (cap < needed) {
                setLastError(ERROR_INSUFFICIENT_BUFFER);
                return RAW_INVALID_SIZE;
            }
            const dst: [*]u8 = @ptrCast(pData.?);
            @memcpy(dst[0..name.len], name);
            dst[name.len] = 0;
            return needed;
        },
        RIDI_DEVICEINFO => {
            const needed: u32 = @sizeOf(RID_DEVICE_INFO);
            if (pData == null) {
                psize.* = needed;
                return 0;
            }
            const cap = psize.*;
            psize.* = needed;
            if (cap < needed) {
                setLastError(ERROR_INSUFFICIENT_BUFFER);
                return RAW_INVALID_SIZE;
            }
            const out: *RID_DEVICE_INFO = @ptrCast(@alignCast(pData.?));
            _ = fillDeviceInfo(hDevice, out);
            return needed;
        },
        RIDI_PREPARSEDDATA => {
            psize.* = 0;
            return 0;
        },
        else => {
            setLastError(ERROR_INVALID_PARAMETER);
            return RAW_INVALID_SIZE;
        },
    }
}

pub fn getRawInputDeviceInfoW(hDevice: usize, uiCommand: u32, pData: ?*anyopaque, pcbSize: ?*u32) callconv(W) u32 {
    const psize = pcbSize orelse {
        setLastError(ERROR_INVALID_PARAMETER);
        return RAW_INVALID_SIZE;
    };
    if (hDevice != RAW_KBD_HANDLE and hDevice != RAW_MOUSE_HANDLE) {
        setLastError(ERROR_INVALID_HANDLE);
        return RAW_INVALID_SIZE;
    }
    if (uiCommand == RIDI_DEVICENAME) {
        const name = if (hDevice == RAW_KBD_HANDLE) RAW_KBD_DEV_NAME else RAW_MOUSE_DEV_NAME;
        const needed: u32 = @intCast(name.len + 1); // WCHAR count including NUL
        if (pData == null) {
            psize.* = needed;
            return 0;
        }
        const cap = psize.*;
        psize.* = needed;
        if (cap < needed) {
            setLastError(ERROR_INSUFFICIENT_BUFFER);
            return RAW_INVALID_SIZE;
        }
        const dst: [*]u16 = @ptrCast(@alignCast(pData.?));
        for (name, 0..) |ch, idx| dst[idx] = ch;
        dst[name.len] = 0;
        return needed;
    }
    return getRawInputDeviceInfoA(hDevice, uiCommand, pData, pcbSize);
}

pub fn getRawInputData(hRawInput: usize, uiCommand: u32, pData: ?*anyopaque, pcbSize: ?*u32, cbSizeHeader: u32) callconv(W) u32 {
    if (cbSizeHeader != @sizeOf(RAWINPUTHEADER)) {
        setLastError(ERROR_INVALID_PARAMETER);
        return RAW_INVALID_SIZE;
    }
    const psize = pcbSize orelse {
        setLastError(ERROR_INVALID_PARAMETER);
        return RAW_INVALID_SIZE;
    };
    if (uiCommand != RID_INPUT and uiCommand != RID_HEADER) {
        setLastError(ERROR_INVALID_PARAMETER);
        return RAW_INVALID_SIZE;
    }
    if (hRawInput == 0) {
        setLastError(ERROR_INVALID_HANDLE);
        return RAW_INVALID_SIZE;
    }

    var found: ?RAWINPUT = null;
    rawLock();
    for (g_raw_ring) |slot| {
        if (slot.handle == hRawInput) {
            found = slot.input;
            break;
        }
    }
    rawUnlock();

    const pkt = found orelse {
        setLastError(ERROR_INVALID_HANDLE);
        return RAW_INVALID_SIZE;
    };

    const needed: u32 = if (uiCommand == RID_HEADER) @sizeOf(RAWINPUTHEADER) else pkt.header.dwSize;
    if (pData == null) {
        psize.* = needed;
        return 0;
    }
    const cap = psize.*;
    psize.* = needed;
    if (cap < needed) {
        setLastError(ERROR_INSUFFICIENT_BUFFER);
        return RAW_INVALID_SIZE;
    }
    const src = std.mem.asBytes(&pkt);
    const dst: [*]u8 = @ptrCast(pData.?);
    @memcpy(dst[0..needed], src[0..needed]);
    return needed;
}

pub fn defRawInputProc(paRawInput: ?*const anyopaque, nInput: i32, cbSizeHeader: u32) callconv(W) isize {
    _ = paRawInput;
    if (nInput < 0 or cbSizeHeader != @sizeOf(RAWINPUTHEADER)) {
        setLastError(ERROR_INVALID_PARAMETER);
        return -1;
    }
    return 0;
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
// Dispatch Lookup Tables
// ============================================================================

pub fn lookupRawInput(sym: []const u8) ?*const anyopaque {
    const table = [_]struct { name: []const u8, func: *const anyopaque }{
        .{ .name = "RegisterRawInputDevices", .func = @ptrCast(&registerRawInputDevices) },
        .{ .name = "GetRegisteredRawInputDevices", .func = @ptrCast(&getRegisteredRawInputDevices) },
        .{ .name = "GetRawInputData", .func = @ptrCast(&getRawInputData) },
        .{ .name = "GetRawInputDeviceList", .func = @ptrCast(&getRawInputDeviceList) },
        .{ .name = "GetRawInputDeviceInfoA", .func = @ptrCast(&getRawInputDeviceInfoA) },
        .{ .name = "GetRawInputDeviceInfoW", .func = @ptrCast(&getRawInputDeviceInfoW) },
        .{ .name = "DefRawInputProc", .func = @ptrCast(&defRawInputProc) },
    };
    for (table) |entry| {
        if (std.mem.eql(u8, sym, entry.name)) return entry.func;
    }
    return null;
}

pub fn lookupUser32Input(sym: []const u8) ?*const anyopaque {
    if (lookupRawInput(sym)) |f| return f;
    if (std.mem.eql(u8, sym, "GetAsyncKeyState")) return @ptrCast(&rawGetAsyncKeyState);
    if (std.mem.eql(u8, sym, "GetKeyState")) return @ptrCast(&rawGetKeyState);
    return null;
}

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
        .{ .name = "XInputGetStateEx", .func = @ptrCast(&xinputGetStateEx) },
        .{ .name = "XInputSetState", .func = @ptrCast(&xinputSetState) },
        .{ .name = "XInputGetCapabilities", .func = @ptrCast(&xinputGetCapabilities) },
        .{ .name = "XInputEnable", .func = @ptrCast(&xinputEnable) },
        .{ .name = "XInputGetDSoundAudioDeviceGuids", .func = @ptrCast(&xinputGetDSoundAudioDeviceGuids) },
        .{ .name = "XInputGetBatteryInformation", .func = @ptrCast(&xinputGetBatteryInformation) },
        .{ .name = "XInputGetKeystroke", .func = @ptrCast(&xinputGetKeystroke) },
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
        .{ .name = "timeGetDevCaps", .func = @ptrCast(&timeGetDevCaps) },
        .{ .name = "timeSetEvent", .func = @ptrCast(&timeSetEvent) },
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
        .{ .name = "SetupDiEnumDeviceInfo", .func = @ptrCast(&setupDiEnumDeviceInfo) },
        .{ .name = "SetupDiGetDeviceRegistryPropertyA", .func = @ptrCast(&setupDiGetDeviceRegistryPropertyA) },
        .{ .name = "SetupDiGetDeviceRegistryPropertyW", .func = @ptrCast(&setupDiGetDeviceRegistryPropertyW) },
        .{ .name = "SetupDiEnumDeviceInterfaces", .func = @ptrCast(&setupDiEnumDeviceInterfaces) },
        .{ .name = "SetupDiGetDeviceInterfaceDetailA", .func = @ptrCast(&setupDiGetDeviceInterfaceDetailA) },
        .{ .name = "SetupDiGetDeviceInterfaceDetailW", .func = @ptrCast(&setupDiGetDeviceInterfaceDetailW) },
        .{ .name = "SetupDiDestroyDeviceInfoList", .func = @ptrCast(&setupDiDestroyDeviceInfoList) },
        .{ .name = "UnityMain", .func = @ptrCast(&unityMain) },
    };

    for (table) |entry| {
        if (std.mem.eql(u8, sym, entry.name)) return entry.func;
    }
    return null;
}

// ============================================================================
// Unit Tests (Win64 Struct Layouts, SetupAPI, RawInput, Key State)
// ============================================================================

var g_test_last_err: u32 = 0;
fn testSetLastError(code: u32) callconv(W) void {
    g_test_last_err = code;
}

test "Win64 SetupAPI and RawInput struct sizes and offsets match x86_64 Windows ABI" {
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(GUID));
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(SP_DEVINFO_DATA));
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(SP_DEVICE_INTERFACE_DATA));
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(SP_DEVICE_INTERFACE_DETAIL_DATA_A));
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(SP_DEVICE_INTERFACE_DETAIL_DATA_W));
    try std.testing.expectEqual(@as(usize, 4), @offsetOf(SP_DEVICE_INTERFACE_DETAIL_DATA_W, "DevicePath"));

    try std.testing.expectEqual(@as(usize, 16), @sizeOf(RAWINPUTDEVICE));
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(RAWINPUTDEVICELIST));
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(RAWINPUTHEADER));
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(RAWMOUSE));
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(RAWKEYBOARD));
    try std.testing.expectEqual(@as(usize, 12), @sizeOf(RAWHID));
    try std.testing.expectEqual(@as(usize, 48), @sizeOf(RAWINPUT));
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(RID_DEVICE_INFO));
}

test "SetupAPI enumeration, property queries, cbSize checks, and HID GUID" {
    set_last_error_fn = &testSetLastError;
    defer set_last_error_fn = null;

    var hid_guid: GUID = std.mem.zeroes(GUID);
    hidD_GetHidGuid(&hid_guid);
    try std.testing.expectEqual(@as(u32, 0x4d1e55b2), hid_guid.Data1);

    const h = setupDiGetClassDevsA(&hid_guid, null, null, 0x12);
    try std.testing.expect(h != null);

    var did: SP_DEVINFO_DATA = std.mem.zeroes(SP_DEVINFO_DATA);
    did.cbSize = 28; // wrong Win32 size
    g_test_last_err = 0;
    try std.testing.expectEqual(@as(u32, 0), setupDiEnumDeviceInfo(h, 0, &did));
    try std.testing.expectEqual(ERROR_INVALID_USER_BUFFER, g_test_last_err);

    did.cbSize = @sizeOf(SP_DEVINFO_DATA); // 32 bytes Win64
    g_test_last_err = 0;
    try std.testing.expectEqual(@as(u32, 0), setupDiEnumDeviceInfo(h, 0, &did));
    try std.testing.expectEqual(ERROR_NO_MORE_ITEMS, g_test_last_err);

    var prop_type: u32 = 99;
    var req_sz: u32 = 99;
    try std.testing.expectEqual(@as(u32, 0), setupDiGetDeviceRegistryPropertyA(h, &did, 0, &prop_type, null, 0, &req_sz));
    try std.testing.expectEqual(@as(u32, 0), req_sz);
    try std.testing.expectEqual(ERROR_INVALID_DATA, g_test_last_err);
    try std.testing.expectEqual(@as(u32, 0), setupDiGetDeviceRegistryPropertyW(h, &did, 0, &prop_type, null, 0, &req_sz));

    var ifd: SP_DEVICE_INTERFACE_DATA = std.mem.zeroes(SP_DEVICE_INTERFACE_DATA);
    ifd.cbSize = @sizeOf(SP_DEVICE_INTERFACE_DATA);
    try std.testing.expectEqual(@as(u32, 0), setupDiEnumDeviceInterfaces(h, null, &hid_guid, 0, &ifd));
    try std.testing.expectEqual(ERROR_NO_MORE_ITEMS, g_test_last_err);

    var detail_a: SP_DEVICE_INTERFACE_DETAIL_DATA_A = .{ .cbSize = @sizeOf(SP_DEVICE_INTERFACE_DETAIL_DATA_A), .DevicePath = .{0} };
    try std.testing.expectEqual(@as(u32, 0), setupDiGetDeviceInterfaceDetailA(h, &ifd, &detail_a, @sizeOf(SP_DEVICE_INTERFACE_DETAIL_DATA_A), &req_sz, &did));
    try std.testing.expectEqual(@as(u32, 0), setupDiGetDeviceInterfaceDetailW(h, &ifd, null, 0, &req_sz, &did));

    try std.testing.expectEqual(@as(u32, 1), setupDiDestroyDeviceInfoList(h));
    try std.testing.expectEqual(@as(u32, 0), setupDiDestroyDeviceInfoList(null));
    try std.testing.expect(lookupDirectX("SetupDiEnumDeviceInfo") != null);
    // All xinput1_3/1_4/9_1_0 named exports (incl. ordinal 100 = XInputGetStateEx)
    // must resolve to the real wins_xinput.zig implementation, not stubs.
    for ([_][]const u8{ "XInputGetState", "XInputGetStateEx", "XInputSetState", "XInputGetCapabilities", "XInputEnable", "XInputGetDSoundAudioDeviceGuids", "XInputGetBatteryInformation", "XInputGetKeystroke" }) |nm| {
        try std.testing.expect(lookupDirectX(nm) != null);
    }
    try std.testing.expectEqual(@intFromPtr(&xinputGetState), @intFromPtr(lookupDirectX("XInputGetState").?));
    // Real implementation behaviour: no pad attached -> ERROR_DEVICE_NOT_CONNECTED (1167),
    // which is valid Windows behaviour and must let Rewired finish XInput init.
    var st: XINPUT_STATE = undefined;
    try std.testing.expectEqual(@as(u32, 1167), xinputGetState(0, &st));
    var caps: XINPUT_CAPABILITIES = undefined;
    try std.testing.expectEqual(@as(u32, 1167), xinputGetCapabilities(0, 1, &caps));
    try std.testing.expect(lookupDirectX("SetupDiGetDeviceRegistryPropertyA") != null);
    try std.testing.expect(lookupDirectX("SetupDiGetDeviceRegistryPropertyW") != null);
    try std.testing.expect(lookupDirectX("SetupDiGetDeviceInterfaceDetailA") != null);
}

test "RawInput device registration, enumeration, info, and pushed keyboard/mouse data" {
    set_last_error_fn = &testSetLastError;
    defer set_last_error_fn = null;
    resetRawInputStateForTest();
    defer resetRawInputStateForTest();

    // Reject wrong cbSize (e.g. Win32 12-byte RAWINPUTDEVICE)
    const bad_reg = RAWINPUTDEVICE{ .usUsagePage = 1, .usUsage = 6, .dwFlags = 0, .hwndTarget = 0x1234 };
    try std.testing.expectEqual(@as(i32, 0), registerRawInputDevices(@ptrCast(&bad_reg), 1, 12));
    try std.testing.expectEqual(ERROR_INVALID_PARAMETER, g_test_last_err);

    const regs = [_]RAWINPUTDEVICE{
        .{ .usUsagePage = 1, .usUsage = 6, .dwFlags = 0, .hwndTarget = 0x1234 },
        .{ .usUsagePage = 1, .usUsage = 2, .dwFlags = 0, .hwndTarget = 0x1234 },
    };
    try std.testing.expectEqual(@as(i32, 1), registerRawInputDevices(&regs, 2, @sizeOf(RAWINPUTDEVICE)));
    try std.testing.expectEqual(@as(?usize, 0x1234), getRegisteredRawInputTarget(1, 6));

    var n_reg: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), getRegisteredRawInputDevices(null, &n_reg, @sizeOf(RAWINPUTDEVICE)));
    try std.testing.expectEqual(@as(u32, 2), n_reg);
    var out_reg: [2]RAWINPUTDEVICE = undefined;
    try std.testing.expectEqual(@as(u32, 2), getRegisteredRawInputDevices(&out_reg, &n_reg, @sizeOf(RAWINPUTDEVICE)));
    try std.testing.expectEqual(@as(u16, 6), out_reg[0].usUsage);

    // Enumerate virtual keyboard + mouse
    var n_dev: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), getRawInputDeviceList(null, &n_dev, @sizeOf(RAWINPUTDEVICELIST)));
    try std.testing.expectEqual(@as(u32, 2), n_dev);
    var devs: [2]RAWINPUTDEVICELIST = undefined;
    try std.testing.expectEqual(@as(u32, 2), getRawInputDeviceList(&devs, &n_dev, @sizeOf(RAWINPUTDEVICELIST)));
    try std.testing.expectEqual(RIM_TYPEKEYBOARD, devs[0].dwType);
    try std.testing.expectEqual(RIM_TYPEMOUSE, devs[1].dwType);

    // Query RIDI_DEVICEINFO and RIDI_DEVICENAME (A & W)
    var dinfo: RID_DEVICE_INFO = std.mem.zeroes(RID_DEVICE_INFO);
    var sz: u32 = @sizeOf(RID_DEVICE_INFO);
    try std.testing.expectEqual(@as(u32, 32), getRawInputDeviceInfoW(devs[0].hDevice, RIDI_DEVICEINFO, &dinfo, &sz));
    try std.testing.expectEqual(RIM_TYPEKEYBOARD, dinfo.dwType);
    try std.testing.expectEqual(@as(u32, 104), dinfo.info.keyboard.dwNumberOfKeysTotal);

    var wname: [128]u16 = [_]u16{0} ** 128;
    var wn_len: u32 = wname.len;
    const copied_w = getRawInputDeviceInfoW(devs[0].hDevice, RIDI_DEVICENAME, &wname, &wn_len);
    try std.testing.expect(copied_w > 10 and copied_w == wn_len);
    var aname: [128]u8 = [_]u8{0} ** 128;
    var an_len: u32 = aname.len;
    const copied_a = getRawInputDeviceInfoA(devs[1].hDevice, RIDI_DEVICENAME, &aname, &an_len);
    try std.testing.expect(copied_a > 10 and copied_a == an_len);

    // Push raw key down/up -> GetRawInputData + GetAsyncKeyState + GetKeyState
    const h_down = pushRawKeyEvent('Z', 0x2C, false, true);
    try std.testing.expect(rawGetAsyncKeyState('Z') < 0);
    try std.testing.expect(rawGetKeyState('Z') < 0);

    var raw_sz: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), getRawInputData(h_down, RID_INPUT, null, &raw_sz, @sizeOf(RAWINPUTHEADER)));
    try std.testing.expectEqual(@as(u32, 40), raw_sz);
    var raw_pkt: RAWINPUT = std.mem.zeroes(RAWINPUT);
    try std.testing.expectEqual(@as(u32, 40), getRawInputData(h_down, RID_INPUT, &raw_pkt, &raw_sz, @sizeOf(RAWINPUTHEADER)));
    try std.testing.expectEqual(RIM_TYPEKEYBOARD, raw_pkt.header.dwType);
    try std.testing.expectEqual(@as(u16, 'Z'), raw_pkt.data.keyboard.VKey);
    try std.testing.expectEqual(@as(u16, 0x2C), raw_pkt.data.keyboard.MakeCode);
    try std.testing.expectEqual(RI_KEY_MAKE, raw_pkt.data.keyboard.Flags);

    // Fast-tap latching on release
    _ = pushRawKeyEvent('X', 0x2D, false, true);
    _ = pushRawKeyEvent('X', 0x2D, false, false);
    try std.testing.expectEqual(@as(i16, 1), rawGetAsyncKeyState('X'));
    try std.testing.expectEqual(@as(i16, 0), rawGetAsyncKeyState('X'));

    // Mouse raw event
    const h_mouse = pushRawMouseEvent(12, -5, RI_MOUSE_LEFT_BUTTON_DOWN, 0);
    try std.testing.expect(rawGetAsyncKeyState(0x01) < 0);
    var m_sz: u32 = @sizeOf(RAWINPUT);
    var m_pkt: RAWINPUT = std.mem.zeroes(RAWINPUT);
    try std.testing.expectEqual(@as(u32, 48), getRawInputData(h_mouse, RID_INPUT, &m_pkt, &m_sz, @sizeOf(RAWINPUTHEADER)));
    try std.testing.expectEqual(@as(i32, 12), m_pkt.data.mouse.lLastX);
    try std.testing.expectEqual(@as(i32, -5), m_pkt.data.mouse.lLastY);
    try std.testing.expectEqual(@as(isize, 0), defRawInputProc(&m_pkt, 1, @sizeOf(RAWINPUTHEADER)));

    // Lookup helpers
    try std.testing.expect(lookupRawInput("RegisterRawInputDevices") != null);
    try std.testing.expect(lookupRawInput("GetRegisteredRawInputDevices") != null);
    try std.testing.expect(lookupRawInput("GetRawInputData") != null);
    try std.testing.expect(lookupRawInput("GetRawInputDeviceList") != null);
    try std.testing.expect(lookupRawInput("GetRawInputDeviceInfoA") != null);
    try std.testing.expect(lookupRawInput("GetRawInputDeviceInfoW") != null);
    try std.testing.expect(lookupRawInput("DefRawInputProc") != null);
    try std.testing.expect(lookupUser32Input("GetAsyncKeyState") != null);
    try std.testing.expect(lookupUser32Input("GetKeyState") != null);
}
