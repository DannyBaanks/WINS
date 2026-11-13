//! WINS native DirectShow filter graph (quartz.dll's CLSID_FilterGraph) for
//! MPEG audio streams.
//!
//! Why this file exists: FalloutNV plays its music through DirectShow with
//! its OWN source filter (Proton +quartz trace, 2026-11-13):
//! CoCreateInstance(CLSID_FilterGraph, IID_IFilterGraph) -> AddFilter(own
//! filter, NULL) -> Render(own output pin, MEDIATYPE_Stream /
//! MEDIASUBTYPE_MPEG1Audio, pulled through IAsyncReader) -> QueryInterface
//! IMediaControl / IMediaEvent / IMediaPosition / IBasicAudio -> put_Volume
//! fades, Pause, Run, then GetEvent(0) and duration/position polls every
//! frame. With no graph the game dereferences NULL (EIP 0x83101e).
//!
//! What is implemented here: the graph object and the interfaces that
//! client uses (IFilterGraph/IGraphBuilder, IMediaControl, IMediaEventEx,
//! IMediaEventSink, IMediaPosition, IMediaSeeking, IBasicAudio, IMediaFilter),
//! a system reference clock, and one renderer filter whose input pin accepts
//! a pull-mode MPEG audio stream: it connects to the caller's output pin,
//! reads the whole stream through the caller's IAsyncReader, walks its MPEG
//! frames, and answers duration, position, state and EC_COMPLETE from that
//! stream and a monotonic clock. Semantics are pinned against Proton by
//! native/testdata/dshow_probe.c.
//!
//! What is NOT implemented, deliberately and visibly: no PCM reaches an
//! output device, so playback is silent (the MP3 is parsed, not decoded);
//! one rendered stream per graph; no RenderFile/AddSourceFilter (no file
//! source filter here); IReferenceClock::AdviseTime/AdvisePeriodic answer
//! E_NOTIMPL; EC_COMPLETE is raised when a caller next asks the graph for
//! position or events, so an event handle from GetEventHandle is only
//! signaled by those calls; window notification (SetNotifyWindow) is stored
//! but no message is ever posted; IDispatch is not implemented.

const std = @import("std");
const linux = std.os.linux;
const threads_mod = @import("winrun_threads.zig");

pub const W: std.builtin.CallingConvention = .winapi;
pub const HRESULT = i32;

fn hr32(x: u32) HRESULT {
    return @bitCast(x);
}
pub const S_OK: HRESULT = 0;
pub const S_FALSE: HRESULT = 1;
pub const E_NOTIMPL: HRESULT = hr32(0x80004001);
pub const E_NOINTERFACE: HRESULT = hr32(0x80004002);
pub const E_POINTER: HRESULT = hr32(0x80004003);
pub const E_ABORT: HRESULT = hr32(0x80004004);
pub const E_FAIL: HRESULT = hr32(0x80004005);
pub const E_UNEXPECTED: HRESULT = hr32(0x8000FFFF);
pub const E_OUTOFMEMORY: HRESULT = hr32(0x8007000E);
pub const E_INVALIDARG: HRESULT = hr32(0x80070057);
pub const CLASS_E_NOAGGREGATION: HRESULT = hr32(0x80040110);
pub const VFW_E_ALREADY_CONNECTED: HRESULT = hr32(0x80040204);
pub const VFW_E_INVALID_DIRECTION: HRESULT = hr32(0x80040208);
pub const VFW_E_NOT_CONNECTED: HRESULT = hr32(0x80040209);
pub const VFW_E_NOT_FOUND: HRESULT = hr32(0x80040216);
pub const VFW_E_CANNOT_RENDER: HRESULT = hr32(0x80040218);
pub const VFW_E_TYPE_NOT_ACCEPTED: HRESULT = hr32(0x8004022A);

pub const EC_COMPLETE: i32 = 0x01;
pub const EC_CLOCK_CHANGED: i32 = 0x0D;

pub const Guid = extern struct {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [8]u8,

    pub fn eql(a: *const Guid, b: *const Guid) bool {
        return a.data1 == b.data1 and a.data2 == b.data2 and a.data3 == b.data3 and
            std.mem.eql(u8, &a.data4, &b.data4);
    }
};
fn qg(d1: u32, d2: u16, d3: u16, d4: [8]u8) Guid {
    return .{ .data1 = d1, .data2 = d2, .data3 = d3, .data4 = d4 };
}
const B03A = [8]u8{ 0xb0, 0x3a, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70 };
const COM_BASE = [8]u8{ 0xc0, 0, 0, 0, 0, 0, 0, 0x46 };
pub const CLSID_FilterGraph = qg(0xe436ebb3, 0x524f, 0x11ce, .{ 0x9f, 0x53, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70 });
pub const CLSID_FilterGraphNoThread = qg(0xe436ebb8, 0x524f, 0x11ce, .{ 0x9f, 0x53, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70 });
const CLSID_WinsMpegRenderer = qg(0x57494e53, 0x6d70, 0x3372, .{ 0x72, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x00, 0x01 });
const IID_IUnknown = qg(0, 0, 0, COM_BASE);
const IID_IPersist = qg(0x0000010c, 0, 0, COM_BASE);
const IID_IFilterGraph = qg(0x56a8689f, 0x0ad4, 0x11ce, B03A);
const IID_IGraphBuilder = qg(0x56a868a9, 0x0ad4, 0x11ce, B03A);
const IID_IMediaEventSink = qg(0x56a868a2, 0x0ad4, 0x11ce, B03A);
const IID_IMediaControl = qg(0x56a868b1, 0x0ad4, 0x11ce, B03A);
const IID_IMediaPosition = qg(0x56a868b2, 0x0ad4, 0x11ce, B03A);
const IID_IBasicAudio = qg(0x56a868b3, 0x0ad4, 0x11ce, B03A);
const IID_IMediaEvent = qg(0x56a868b6, 0x0ad4, 0x11ce, B03A);
const IID_IMediaEventEx = qg(0x56a868c0, 0x0ad4, 0x11ce, B03A);
const IID_IMediaFilter = qg(0x56a86899, 0x0ad4, 0x11ce, B03A);
const IID_IBaseFilter = qg(0x56a86895, 0x0ad4, 0x11ce, B03A);
const IID_IPin = qg(0x56a86891, 0x0ad4, 0x11ce, B03A);
const IID_IEnumPins = qg(0x56a86892, 0x0ad4, 0x11ce, B03A);
const IID_IEnumFilters = qg(0x56a86893, 0x0ad4, 0x11ce, B03A);
const IID_IReferenceClock = qg(0x56a86897, 0x0ad4, 0x11ce, B03A);
const IID_IAsyncReader = qg(0x56a868aa, 0x0ad4, 0x11ce, B03A);
const IID_IEnumMediaTypes = qg(0x89c31040, 0x846b, 0x11ce, .{ 0x97, 0xd3, 0x00, 0xaa, 0x00, 0x55, 0x59, 0x5a });
const IID_IMediaSeeking = qg(0x36b73880, 0xc2c8, 0x11cf, .{ 0x8b, 0x46, 0x00, 0x80, 0x5f, 0x6c, 0xef, 0x60 });
const MEDIATYPE_Stream = qg(0xe436eb83, 0x524f, 0x11ce, .{ 0x9f, 0x53, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70 });
const MEDIASUBTYPE_MPEG1Audio = qg(0xe436eb87, 0x524f, 0x11ce, .{ 0x9f, 0x53, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70 });
const GUID_NULL = qg(0, 0, 0, .{ 0, 0, 0, 0, 0, 0, 0, 0 });
const TIME_FORMAT_MEDIA_TIME = qg(0x7b785574, 0x8c82, 0x11cf, .{ 0xbc, 0x0c, 0x00, 0xaa, 0x00, 0xac, 0x74, 0xf6 });

pub const AM_MEDIA_TYPE = extern struct {
    majortype: Guid,
    subtype: Guid,
    bFixedSizeSamples: i32,
    bTemporalCompression: i32,
    lSampleSize: u32,
    formattype: Guid,
    pUnk: ?*anyopaque,
    cbFormat: u32,
    pbFormat: ?[*]u8,
};
const PIN_INFO = extern struct { pFilter: ?*anyopaque, dir: u32, achName: [128]u16 };
const FILTER_INFO = extern struct { achName: [128]u16, pGraph: ?*anyopaque };
const PINDIR_INPUT: u32 = 0;
const PINDIR_OUTPUT: u32 = 1;

// ---------------------------------------------------------------------------
// Guest COM interfaces this file CALLS (the caller's filter and pin).
// ---------------------------------------------------------------------------
const Self = *anyopaque;
const UnkVtbl = extern struct {
    QueryInterface: *const fn (Self, *const Guid, *?*anyopaque) callconv(W) HRESULT,
    AddRef: *const fn (Self) callconv(W) u32,
    Release: *const fn (Self) callconv(W) u32,
};
const BaseFilterVtbl = extern struct {
    unk: UnkVtbl,
    GetClassID: *const fn (Self, *Guid) callconv(W) HRESULT,
    Stop: *const fn (Self) callconv(W) HRESULT,
    Pause: *const fn (Self) callconv(W) HRESULT,
    Run: *const fn (Self, i64) callconv(W) HRESULT,
    GetState: *const fn (Self, u32, *u32) callconv(W) HRESULT,
    SetSyncSource: *const fn (Self, ?*anyopaque) callconv(W) HRESULT,
    GetSyncSource: *const fn (Self, *?*anyopaque) callconv(W) HRESULT,
    EnumPins: *const fn (Self, *?*anyopaque) callconv(W) HRESULT,
    FindPin: *const fn (Self, ?[*:0]const u16, *?*anyopaque) callconv(W) HRESULT,
    QueryFilterInfo: *const fn (Self, *FILTER_INFO) callconv(W) HRESULT,
    JoinFilterGraph: *const fn (Self, ?*anyopaque, ?[*:0]const u16) callconv(W) HRESULT,
    QueryVendorInfo: *const fn (Self, *?[*:0]u16) callconv(W) HRESULT,
};
const PinVtbl = extern struct {
    unk: UnkVtbl,
    Connect: *const fn (Self, ?*anyopaque, ?*const AM_MEDIA_TYPE) callconv(W) HRESULT,
    ReceiveConnection: *const fn (Self, ?*anyopaque, ?*const AM_MEDIA_TYPE) callconv(W) HRESULT,
    Disconnect: *const fn (Self) callconv(W) HRESULT,
    ConnectedTo: *const fn (Self, *?*anyopaque) callconv(W) HRESULT,
    ConnectionMediaType: *const fn (Self, *AM_MEDIA_TYPE) callconv(W) HRESULT,
    QueryPinInfo: *const fn (Self, *PIN_INFO) callconv(W) HRESULT,
    QueryDirection: *const fn (Self, *u32) callconv(W) HRESULT,
    QueryId: *const fn (Self, *?[*:0]u16) callconv(W) HRESULT,
    QueryAccept: *const fn (Self, ?*const AM_MEDIA_TYPE) callconv(W) HRESULT,
    EnumMediaTypes: *const fn (Self, *?*anyopaque) callconv(W) HRESULT,
    QueryInternalConnections: *const fn (Self, ?[*]?*anyopaque, *u32) callconv(W) HRESULT,
    EndOfStream: *const fn (Self) callconv(W) HRESULT,
    BeginFlush: *const fn (Self) callconv(W) HRESULT,
    EndFlush: *const fn (Self) callconv(W) HRESULT,
    NewSegment: *const fn (Self, i64, i64, f64) callconv(W) HRESULT,
};
const AsyncReaderVtbl = extern struct {
    unk: UnkVtbl,
    RequestAllocator: *const fn (Self, ?*anyopaque, ?*anyopaque, *?*anyopaque) callconv(W) HRESULT,
    Request: *const fn (Self, ?*anyopaque, usize) callconv(W) HRESULT,
    WaitForNext: *const fn (Self, u32, *?*anyopaque, *usize) callconv(W) HRESULT,
    SyncReadAligned: *const fn (Self, ?*anyopaque) callconv(W) HRESULT,
    SyncRead: *const fn (Self, i64, i32, [*]u8) callconv(W) HRESULT,
    Length: *const fn (Self, *i64, *i64) callconv(W) HRESULT,
    BeginFlush: *const fn (Self) callconv(W) HRESULT,
    EndFlush: *const fn (Self) callconv(W) HRESULT,
};
fn vt(comptime V: type, p: *anyopaque) *const V {
    return @as(*const *const V, @ptrCast(@alignCast(p))).*;
}
fn comRelease(p: ?*anyopaque) void {
    if (p) |q| _ = vt(UnkVtbl, q).Release(q);
}
fn comAddRef(p: *anyopaque) void {
    _ = vt(UnkVtbl, p).AddRef(p);
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
const Iface = extern struct { vtbl: *const anyopaque };

const SpinLock = struct {
    v: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    fn lock(s: *SpinLock) void {
        while (s.v.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }
    fn unlock(s: *SpinLock) void {
        s.v.store(0, .release);
    }
};

/// Monotonic time in REFERENCE_TIME units (100 ns).
fn now100ns() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
    return @as(i64, @intCast(ts.sec)) * 10_000_000 + @divTrunc(@as(i64, @intCast(ts.nsec)), 100);
}
fn sleepMs(ms: u32) void {
    const req = linux.timespec{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * 1_000_000) };
    var rem: linux.timespec = undefined;
    _ = linux.nanosleep(&req, &rem);
}
fn acceptable(mt: *const AM_MEDIA_TYPE) bool {
    return mt.majortype.eql(&MEDIATYPE_Stream) and
        (mt.subtype.eql(&MEDIASUBTYPE_MPEG1Audio) or mt.subtype.eql(&GUID_NULL));
}
fn copyName(dst: []u16, s: []const u8) void {
    const n = @min(dst.len - 1, s.len);
    for (0..n) |i| dst[i] = s[i];
    dst[n] = 0;
}

// ---------------------------------------------------------------------------
// MPEG audio frame walk (headers only; nothing is decoded here)
// ---------------------------------------------------------------------------
pub const MpegInfo = struct {
    frames: u32,
    sample_rate: u32,
    channels: u32,
    samples_per_frame: u32,
    first_frame: usize,
    duration: i64, // 100 ns
};

const Hdr = struct { len: usize, sr: u32, spf: u32, ver: u2, layer: u2, chans: u32 };

const br_tab = [5][16]u16{
    .{ 0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0 }, // V1 L1
    .{ 0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0 }, // V1 L2
    .{ 0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0 }, // V1 L3
    .{ 0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0 }, // V2 L1
    .{ 0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0 }, // V2 L2/L3
};
const sr_tab = [3][3]u32{ .{ 44100, 48000, 32000 }, .{ 22050, 24000, 16000 }, .{ 11025, 12000, 8000 } };

fn parseHdr(b: []const u8) ?Hdr {
    if (b.len < 4) return null;
    if (b[0] != 0xFF or (b[1] & 0xE0) != 0xE0) return null;
    const ver: u2 = @truncate(b[1] >> 3); // 3 = MPEG1, 2 = MPEG2, 0 = MPEG2.5
    const layer: u2 = @truncate(b[1] >> 1); // 3 = L1, 2 = L2, 1 = L3
    if (ver == 1 or layer == 0) return null;
    const bri: u4 = @truncate(b[2] >> 4);
    const sri: u2 = @truncate(b[2] >> 2);
    if (bri == 0 or bri == 15 or sri == 3) return null; // free format unsupported
    const pad: u32 = (b[2] >> 1) & 1;
    const v1 = ver == 3;
    const tab: usize = if (v1) switch (layer) {
        3 => 0,
        2 => 1,
        else => 2,
    } else if (layer == 3) 3 else 4;
    const kbps: u32 = br_tab[tab][bri];
    const sr = sr_tab[if (v1) 0 else if (ver == 2) 1 else 2][sri];
    const bps = kbps * 1000;
    var len: usize = undefined;
    var spf: u32 = undefined;
    switch (layer) {
        3 => {
            len = (12 * bps / sr + pad) * 4;
            spf = 384;
        },
        2 => {
            len = 144 * bps / sr + pad;
            spf = 1152;
        },
        else => {
            len = (if (v1) 144 * bps / sr else 72 * bps / sr) + pad;
            spf = if (v1) 1152 else 576;
        },
    }
    if (len < 4) return null;
    const chans: u32 = if ((b[3] >> 6) == 3) 1 else 2;
    return .{ .len = len, .sr = sr, .spf = spf, .ver = ver, .layer = layer, .chans = chans };
}

/// Walk the MPEG audio frames of `data`: skip an ID3v2 tag, find the first
/// header confirmed by the next one, count frames of the same stream until
/// the data ends (an ID3v1 "TAG" or junk ends it too). A Xing/Info frame is
/// metadata, not audio: its frame count wins when present, and the frame
/// itself is never counted.
pub fn mpegScan(data: []const u8) ?MpegInfo {
    var off: usize = 0;
    if (data.len >= 10 and std.mem.eql(u8, data[0..3], "ID3")) {
        const sz = (@as(usize, data[6] & 0x7f) << 21) | (@as(usize, data[7] & 0x7f) << 14) |
            (@as(usize, data[8] & 0x7f) << 7) | @as(usize, data[9] & 0x7f);
        off = 10 + sz + (if (data[5] & 0x10 != 0) @as(usize, 10) else 0);
    }
    // First header whose successor is also a header of the same stream.
    var first: ?Hdr = null;
    while (off + 4 <= data.len) : (off += 1) {
        const h = parseHdr(data[off..]) orelse continue;
        if (off + h.len + 4 <= data.len) {
            const n = parseHdr(data[off + h.len ..]) orelse continue;
            if (n.sr != h.sr or n.layer != h.layer or n.ver != h.ver) continue;
        } else if (off + h.len != data.len) continue;
        first = h;
        break;
    }
    const h0 = first orelse return null;
    const start = off;
    var frames: u32 = 0;
    var xing_frames: ?u32 = null;
    // Xing/Info lives after the side info of the first frame.
    {
        const side: usize = if (h0.ver == 3) (if (h0.chans == 1) 17 else 32) else (if (h0.chans == 1) 9 else 17);
        const x = start + 4 + side;
        if (h0.layer == 1 and x + 12 <= data.len and
            (std.mem.eql(u8, data[x .. x + 4], "Xing") or std.mem.eql(u8, data[x .. x + 4], "Info")))
        {
            const flags = std.mem.readInt(u32, data[x + 4 ..][0..4], .big);
            if (flags & 1 != 0) xing_frames = std.mem.readInt(u32, data[x + 8 ..][0..4], .big);
            off = start + h0.len; // the Xing frame is not audio
        }
    }
    while (off + 4 <= data.len) {
        if (std.mem.eql(u8, data[off .. off + 3], "TAG")) break;
        const h = parseHdr(data[off..]) orelse break;
        if (h.sr != h0.sr or h.layer != h0.layer or h.ver != h0.ver) break;
        if (off + h.len > data.len) break; // truncated last frame
        frames += 1;
        off += h.len;
    }
    if (xing_frames) |xf| frames = xf;
    if (frames == 0) return null;
    const dur: i64 = @intCast(@as(u64, frames) * h0.spf * 10_000_000 / h0.sr);
    return .{
        .frames = frames,
        .sample_rate = h0.sr,
        .channels = h0.chans,
        .samples_per_frame = h0.spf,
        .first_frame = start,
        .duration = dur,
    };
}

// ---------------------------------------------------------------------------
// Generic enumerator (IEnumPins / IEnumFilters / IEnumMediaTypes shape)
// ---------------------------------------------------------------------------
const MAX_ENUM = 10;
const ObjEnum = struct {
    unk: Iface,
    refs: std.atomic.Value(u32),
    iid: *const Guid,
    items: [MAX_ENUM]?*anyopaque,
    count: usize,
    pos: usize,
};
fn enumFrom(p: *anyopaque) *ObjEnum {
    const i: *Iface = @ptrCast(@alignCast(p));
    return @fieldParentPtr("unk", i);
}
fn enumNew(iid: *const Guid, items: []const *anyopaque, pos: usize) ?*ObjEnum {
    const e = std.heap.page_allocator.create(ObjEnum) catch return null;
    e.* = .{ .unk = .{ .vtbl = &enum_vtbl }, .refs = std.atomic.Value(u32).init(1), .iid = iid, .items = [_]?*anyopaque{null} ** MAX_ENUM, .count = items.len, .pos = pos };
    for (items, 0..) |it, i| {
        comAddRef(it);
        e.items[i] = it;
    }
    return e;
}
fn enumQI(p: Self, iid: ?*const Guid, out: ?*?*anyopaque) callconv(W) HRESULT {
    const o = out orelse return E_POINTER;
    const e = enumFrom(p);
    const g = iid orelse return E_POINTER;
    if (g.eql(&IID_IUnknown) or g.eql(e.iid)) {
        _ = e.refs.fetchAdd(1, .monotonic);
        o.* = p;
        return S_OK;
    }
    o.* = null;
    return E_NOINTERFACE;
}
fn enumAddRef(p: Self) callconv(W) u32 {
    return enumFrom(p).refs.fetchAdd(1, .monotonic) + 1;
}
fn enumRelease(p: Self) callconv(W) u32 {
    const e = enumFrom(p);
    const r = e.refs.fetchSub(1, .acq_rel) - 1;
    if (r == 0) {
        for (e.items[0..e.count]) |it| comRelease(it);
        std.heap.page_allocator.destroy(e);
    }
    return r;
}
fn enumNext(p: Self, n: u32, out: ?[*]?*anyopaque, fetched: ?*u32) callconv(W) HRESULT {
    const e = enumFrom(p);
    if (n > 1 and fetched == null) return E_POINTER;
    var k: u32 = 0;
    while (k < n and e.pos < e.count) : (k += 1) {
        const it = e.items[e.pos].?;
        comAddRef(it);
        out.?[k] = it;
        e.pos += 1;
    }
    if (fetched) |f| f.* = k;
    return if (k == n) S_OK else S_FALSE;
}
fn enumSkip(p: Self, n: u32) callconv(W) HRESULT {
    const e = enumFrom(p);
    e.pos = @min(e.count, e.pos + n);
    return if (e.pos < e.count or n == 0) S_OK else S_FALSE;
}
fn enumReset(p: Self) callconv(W) HRESULT {
    enumFrom(p).pos = 0;
    return S_OK;
}
fn enumClone(p: Self, out: ?*?*anyopaque) callconv(W) HRESULT {
    const o = out orelse return E_POINTER;
    const e = enumFrom(p);
    var tmp: [MAX_ENUM]*anyopaque = undefined;
    for (0..e.count) |i| tmp[i] = e.items[i].?;
    const c = enumNew(e.iid, tmp[0..e.count], e.pos) orelse return E_OUTOFMEMORY;
    o.* = &c.unk;
    return S_OK;
}
const enum_vtbl = [_]*const anyopaque{ &enumQI, &enumAddRef, &enumRelease, &enumNext, &enumSkip, &enumReset, &enumClone };

// ---------------------------------------------------------------------------
// System reference clock (IReferenceClock)
// ---------------------------------------------------------------------------
const Clock = struct { unk: Iface, refs: std.atomic.Value(u32) };
fn clockFrom(p: *anyopaque) *Clock {
    const i: *Iface = @ptrCast(@alignCast(p));
    return @fieldParentPtr("unk", i);
}
fn clockQI(p: Self, iid: ?*const Guid, out: ?*?*anyopaque) callconv(W) HRESULT {
    const o = out orelse return E_POINTER;
    const g = iid orelse return E_POINTER;
    if (g.eql(&IID_IUnknown) or g.eql(&IID_IReferenceClock)) {
        _ = clockFrom(p).refs.fetchAdd(1, .monotonic);
        o.* = p;
        return S_OK;
    }
    o.* = null;
    return E_NOINTERFACE;
}
fn clockAddRef(p: Self) callconv(W) u32 {
    return clockFrom(p).refs.fetchAdd(1, .monotonic) + 1;
}
fn clockRelease(p: Self) callconv(W) u32 {
    const c = clockFrom(p);
    const r = c.refs.fetchSub(1, .acq_rel) - 1;
    if (r == 0) std.heap.page_allocator.destroy(c);
    return r;
}
fn clockGetTime(p: Self, t: ?*i64) callconv(W) HRESULT {
    _ = p;
    const o = t orelse return E_POINTER;
    o.* = now100ns();
    return S_OK;
}
fn clockAdviseTime(p: Self, base: i64, stream: i64, ev: usize, cookie: ?*usize) callconv(W) HRESULT {
    _ = p; _ = base; _ = stream; _ = ev; _ = cookie;
    std.debug.print("[WINS:DShow] IReferenceClock::AdviseTime -> E_NOTIMPL (no clock advise thread yet)\n", .{});
    return E_NOTIMPL;
}
fn clockAdvisePeriodic(p: Self, start: i64, period: i64, sem: usize, cookie: ?*usize) callconv(W) HRESULT {
    _ = p; _ = start; _ = period; _ = sem; _ = cookie;
    std.debug.print("[WINS:DShow] IReferenceClock::AdvisePeriodic -> E_NOTIMPL (no clock advise thread yet)\n", .{});
    return E_NOTIMPL;
}
fn clockUnadvise(p: Self, cookie: usize) callconv(W) HRESULT {
    _ = p; _ = cookie;
    return S_FALSE;
}
const clock_vtbl = [_]*const anyopaque{ &clockQI, &clockAddRef, &clockRelease, &clockGetTime, &clockAdviseTime, &clockAdvisePeriodic, &clockUnadvise };
fn clockNew() ?*Clock {
    const c = std.heap.page_allocator.create(Clock) catch return null;
    c.* = .{ .unk = .{ .vtbl = &clock_vtbl }, .refs = std.atomic.Value(u32).init(1) };
    return c;
}

// ---------------------------------------------------------------------------
// Renderer filter: one input pin that pulls an MPEG audio stream
// ---------------------------------------------------------------------------
pub const Renderer = struct {
    filt: Iface, // IBaseFilter
    pin: Iface, // IPin (input)
    refs: std.atomic.Value(u32),
    graph: ?*Graph, // weak
    clock: ?*anyopaque,
    state: u32 = 0,
    peer: ?*anyopaque = null, // caller's output pin (AddRef'd)
    reader: ?*anyopaque = null, // caller's IAsyncReader (AddRef'd)
    mt: AM_MEDIA_TYPE = undefined,
    data: []u8 = &[_]u8{},
    info: ?MpegInfo = null,
};
fn rendFromFilt(p: *anyopaque) *Renderer {
    const i: *Iface = @ptrCast(@alignCast(p));
    return @fieldParentPtr("filt", i);
}
fn rendFromPin(p: *anyopaque) *Renderer {
    const i: *Iface = @ptrCast(@alignCast(p));
    return @fieldParentPtr("pin", i);
}
fn rendAddRefR(r: *Renderer) u32 {
    return r.refs.fetchAdd(1, .monotonic) + 1;
}
fn rendDropConnection(r: *Renderer) void {
    comRelease(r.reader);
    r.reader = null;
    comRelease(r.peer);
    r.peer = null;
}
fn rendReleaseR(r: *Renderer) u32 {
    const left = r.refs.fetchSub(1, .acq_rel) - 1;
    if (left == 0) {
        rendDropConnection(r);
        comRelease(r.clock);
        if (r.data.len != 0) std.heap.page_allocator.free(r.data);
        std.heap.page_allocator.destroy(r);
    }
    return left;
}

// IBaseFilter of the renderer
fn rfQI(p: Self, iid: ?*const Guid, out: ?*?*anyopaque) callconv(W) HRESULT {
    const o = out orelse return E_POINTER;
    const g = iid orelse return E_POINTER;
    const r = rendFromFilt(p);
    if (g.eql(&IID_IUnknown) or g.eql(&IID_IPersist) or g.eql(&IID_IMediaFilter) or g.eql(&IID_IBaseFilter)) {
        _ = rendAddRefR(r);
        o.* = p;
        return S_OK;
    }
    o.* = null;
    return E_NOINTERFACE;
}
fn rfAddRef(p: Self) callconv(W) u32 {
    return rendAddRefR(rendFromFilt(p));
}
fn rfRelease(p: Self) callconv(W) u32 {
    return rendReleaseR(rendFromFilt(p));
}
fn rfGetClassID(p: Self, c: ?*Guid) callconv(W) HRESULT {
    _ = p;
    (c orelse return E_POINTER).* = CLSID_WinsMpegRenderer;
    return S_OK;
}
fn rfStop(p: Self) callconv(W) HRESULT {
    rendFromFilt(p).state = 0;
    return S_OK;
}
fn rfPause(p: Self) callconv(W) HRESULT {
    rendFromFilt(p).state = 1;
    return S_OK;
}
fn rfRun(p: Self, t: i64) callconv(W) HRESULT {
    _ = t;
    rendFromFilt(p).state = 2;
    return S_OK;
}
fn rfGetState(p: Self, ms: u32, s: ?*u32) callconv(W) HRESULT {
    _ = ms;
    (s orelse return E_POINTER).* = rendFromFilt(p).state;
    return S_OK;
}
fn rfSetSyncSource(p: Self, c: ?*anyopaque) callconv(W) HRESULT {
    const r = rendFromFilt(p);
    if (c) |q| comAddRef(q);
    comRelease(r.clock);
    r.clock = c;
    return S_OK;
}
fn rfGetSyncSource(p: Self, c: ?*?*anyopaque) callconv(W) HRESULT {
    const r = rendFromFilt(p);
    const o = c orelse return E_POINTER;
    o.* = r.clock;
    if (r.clock) |q| comAddRef(q);
    return S_OK;
}
fn rfEnumPins(p: Self, out: ?*?*anyopaque) callconv(W) HRESULT {
    const o = out orelse return E_POINTER;
    const r = rendFromFilt(p);
    const items = [_]*anyopaque{&r.pin};
    const e = enumNew(&IID_IEnumPins, &items, 0) orelse return E_OUTOFMEMORY;
    o.* = &e.unk;
    return S_OK;
}
fn rfFindPin(p: Self, id: ?[*:0]const u16, out: ?*?*anyopaque) callconv(W) HRESULT {
    const o = out orelse return E_POINTER;
    const r = rendFromFilt(p);
    if (id) |s| if (s[0] == 'I' and s[1] == 'n') {
        _ = rendAddRefR(r);
        o.* = &r.pin;
        return S_OK;
    };
    o.* = null;
    return VFW_E_NOT_FOUND;
}
fn rfQueryFilterInfo(p: Self, fi: ?*FILTER_INFO) callconv(W) HRESULT {
    const r = rendFromFilt(p);
    const f = fi orelse return E_POINTER;
    copyName(&f.achName, "WINS MPEG audio renderer");
    f.pGraph = null;
    if (r.graph) |g| {
        f.pGraph = &g.gb;
        _ = graphAddRef(g);
    }
    return S_OK;
}
fn rfJoinFilterGraph(p: Self, g: ?*anyopaque, name: ?[*:0]const u16) callconv(W) HRESULT {
    _ = name;
    rendFromFilt(p).graph = if (g) |q| graphFrom("gb", q) else null;
    return S_OK;
}
fn rfQueryVendorInfo(p: Self, v: ?*?[*:0]u16) callconv(W) HRESULT {
    _ = p;
    if (v) |o| o.* = null;
    return E_NOTIMPL;
}
const rend_filter_vtbl = [_]*const anyopaque{ &rfQI, &rfAddRef, &rfRelease, &rfGetClassID, &rfStop, &rfPause, &rfRun, &rfGetState, &rfSetSyncSource, &rfGetSyncSource, &rfEnumPins, &rfFindPin, &rfQueryFilterInfo, &rfJoinFilterGraph, &rfQueryVendorInfo };

// IPin (input) of the renderer
fn rpQI(p: Self, iid: ?*const Guid, out: ?*?*anyopaque) callconv(W) HRESULT {
    const o = out orelse return E_POINTER;
    const g = iid orelse return E_POINTER;
    if (g.eql(&IID_IUnknown) or g.eql(&IID_IPin)) {
        _ = rendAddRefR(rendFromPin(p));
        o.* = p;
        return S_OK;
    }
    o.* = null;
    return E_NOINTERFACE;
}
fn rpAddRef(p: Self) callconv(W) u32 {
    return rendAddRefR(rendFromPin(p));
}
fn rpRelease(p: Self) callconv(W) u32 {
    return rendReleaseR(rendFromPin(p));
}
fn rpConnect(p: Self, rx: ?*anyopaque, mt: ?*const AM_MEDIA_TYPE) callconv(W) HRESULT {
    _ = p; _ = rx; _ = mt;
    return E_UNEXPECTED; // an input pin is connected TO, it never connects
}

const MAX_STREAM: i64 = 64 * 1024 * 1024;

/// The upstream pin offers a pull-mode stream: take its IAsyncReader, read
/// the whole stream, and accept it only if MPEG audio frames are found.
fn rpReceiveConnection(p: Self, peer: ?*anyopaque, mt: ?*const AM_MEDIA_TYPE) callconv(W) HRESULT {
    const r = rendFromPin(p);
    const up = peer orelse return E_POINTER;
    const m = mt orelse return E_POINTER;
    if (r.peer != null) return VFW_E_ALREADY_CONNECTED;
    if (!acceptable(m)) return VFW_E_TYPE_NOT_ACCEPTED;
    var reader_p: ?*anyopaque = null;
    if (vt(UnkVtbl, up).QueryInterface(up, &IID_IAsyncReader, &reader_p) != S_OK or reader_p == null) {
        std.debug.print("[WINS:DShow] ReceiveConnection: upstream pin has no IAsyncReader (push mode not supported)\n", .{});
        return E_NOINTERFACE;
    }
    const reader = reader_p.?;
    var total: i64 = 0;
    var avail: i64 = 0;
    const lhr = vt(AsyncReaderVtbl, reader).Length(reader, &total, &avail);
    if (lhr < 0 or total <= 0 or total > MAX_STREAM) {
        std.debug.print("[WINS:DShow] ReceiveConnection: IAsyncReader::Length hr=0x{x} total={}\n", .{ @as(u32, @bitCast(lhr)), total });
        comRelease(reader);
        return VFW_E_TYPE_NOT_ACCEPTED;
    }
    const buf = std.heap.page_allocator.alloc(u8, @intCast(total)) catch {
        comRelease(reader);
        return E_OUTOFMEMORY;
    };
    var pos: i64 = 0;
    while (pos < total) {
        const chunk: i32 = @intCast(@min(total - pos, 65536));
        const rhr = vt(AsyncReaderVtbl, reader).SyncRead(reader, pos, chunk, buf.ptr + @as(usize, @intCast(pos)));
        if (rhr < 0) break;
        pos += chunk;
        if (rhr == S_FALSE) break; // end of stream
    }
    const got: usize = @intCast(@min(pos, total));
    const info = mpegScan(buf[0..got]) orelse {
        std.debug.print("[WINS:DShow] ReceiveConnection: {} bytes read, no MPEG audio frames -> refused\n", .{got});
        std.heap.page_allocator.free(buf);
        comRelease(reader);
        return VFW_E_TYPE_NOT_ACCEPTED;
    };
    comAddRef(up);
    r.peer = up;
    r.reader = reader;
    r.mt = m.*;
    r.mt.pUnk = null;
    r.mt.cbFormat = 0;
    r.mt.pbFormat = null;
    if (r.data.len != 0) std.heap.page_allocator.free(r.data);
    r.data = buf;
    r.info = info;
    std.debug.print("[WINS:DShow] connected: {} bytes, {} frames, {} Hz, {} ch, duration {} ms (playback is silent: no PCM output yet)\n", .{ got, info.frames, info.sample_rate, info.channels, @divTrunc(info.duration, 10_000) });
    return S_OK;
}
fn rpDisconnect(p: Self) callconv(W) HRESULT {
    const r = rendFromPin(p);
    if (r.peer == null) return S_FALSE;
    rendDropConnection(r);
    return S_OK;
}
fn rpConnectedTo(p: Self, out: ?*?*anyopaque) callconv(W) HRESULT {
    const o = out orelse return E_POINTER;
    const r = rendFromPin(p);
    o.* = r.peer;
    const peer = r.peer orelse return VFW_E_NOT_CONNECTED;
    comAddRef(peer);
    return S_OK;
}
fn rpConnectionMediaType(p: Self, out: ?*AM_MEDIA_TYPE) callconv(W) HRESULT {
    const o = out orelse return E_POINTER;
    const r = rendFromPin(p);
    if (r.peer == null) {
        @memset(@as([*]u8, @ptrCast(o))[0..@sizeOf(AM_MEDIA_TYPE)], 0);
        return VFW_E_NOT_CONNECTED;
    }
    o.* = r.mt;
    return S_OK;
}
fn rpQueryPinInfo(p: Self, out: ?*PIN_INFO) callconv(W) HRESULT {
    const o = out orelse return E_POINTER;
    const r = rendFromPin(p);
    _ = rendAddRefR(r);
    o.pFilter = &r.filt;
    o.dir = PINDIR_INPUT;
    copyName(&o.achName, "Input");
    return S_OK;
}
fn rpQueryDirection(p: Self, d: ?*u32) callconv(W) HRESULT {
    _ = p;
    (d orelse return E_POINTER).* = PINDIR_INPUT;
    return S_OK;
}
fn rpQueryId(p: Self, id: ?*?[*:0]u16) callconv(W) HRESULT {
    _ = p;
    if (id) |o| o.* = null;
    return E_NOTIMPL; // needs CoTaskMemAlloc ownership; nothing has asked yet
}
fn rpQueryAccept(p: Self, mt: ?*const AM_MEDIA_TYPE) callconv(W) HRESULT {
    _ = p;
    const m = mt orelse return E_POINTER;
    return if (acceptable(m)) S_OK else S_FALSE;
}
fn rpEnumMediaTypes(p: Self, out: ?*?*anyopaque) callconv(W) HRESULT {
    _ = p;
    const o = out orelse return E_POINTER;
    // No preferred types: the upstream pin offers its own (CBasePin::AgreeMediaType).
    const e = enumNew(&IID_IEnumMediaTypes, &[_]*anyopaque{}, 0) orelse return E_OUTOFMEMORY;
    o.* = &e.unk;
    return S_OK;
}
fn rpQueryInternalConnections(p: Self, a: ?[*]?*anyopaque, n: ?*u32) callconv(W) HRESULT {
    _ = p; _ = a; _ = n;
    return E_NOTIMPL;
}
fn rpNoop(p: Self) callconv(W) HRESULT {
    _ = p;
    return S_OK;
}
fn rpNewSegment(p: Self, a: i64, b: i64, rate: f64) callconv(W) HRESULT {
    _ = p; _ = a; _ = b; _ = rate;
    return S_OK;
}
const rend_pin_vtbl = [_]*const anyopaque{ &rpQI, &rpAddRef, &rpRelease, &rpConnect, &rpReceiveConnection, &rpDisconnect, &rpConnectedTo, &rpConnectionMediaType, &rpQueryPinInfo, &rpQueryDirection, &rpQueryId, &rpQueryAccept, &rpEnumMediaTypes, &rpQueryInternalConnections, &rpNoop, &rpNoop, &rpNoop, &rpNewSegment };

fn rendNew(g: *Graph) ?*Renderer {
    const r = std.heap.page_allocator.create(Renderer) catch return null;
    r.* = .{ .filt = .{ .vtbl = &rend_filter_vtbl }, .pin = .{ .vtbl = &rend_pin_vtbl }, .refs = std.atomic.Value(u32).init(1), .graph = g, .clock = null };
    return r;
}

// ---------------------------------------------------------------------------
// The filter graph
// ---------------------------------------------------------------------------
const MAX_FILTERS = 8;
const MAX_EVENTS = 64;
const Event = struct { code: i32, p1: usize, p2: usize };

pub const Graph = struct {
    gb: Iface, // IUnknown / IFilterGraph / IGraphBuilder
    mc: Iface, // IMediaControl
    ev: Iface, // IMediaEvent / IMediaEventEx
    pos: Iface, // IMediaPosition
    seek: Iface, // IMediaSeeking
    audio: Iface, // IBasicAudio
    mf: Iface, // IMediaFilter / IPersist
    sink: Iface, // IMediaEventSink
    refs: std.atomic.Value(u32),
    lock: SpinLock = .{},
    filters: [MAX_FILTERS]?*anyopaque = [_]?*anyopaque{null} ** MAX_FILTERS, // caller filters, AddRef'd
    nfilters: usize = 0,
    rend: ?*Renderer = null,
    clock: ?*anyopaque = null,
    clock_given: bool = false,
    state: u32 = 0, // 0 stopped, 1 paused, 2 running
    base: i64 = 0, // stream position when the clock was last (re)started, 100 ns
    run_start: i64 = 0,
    stop_pos: ?i64 = null, // null = end of stream
    rate: f64 = 1.0,
    completed: bool = false,
    volume: i32 = 0,
    balance: i32 = 0,
    events: [MAX_EVENTS]Event = undefined,
    ev_head: usize = 0,
    ev_len: usize = 0,
    ev_handle: usize = 0,
    notify_flags: i32 = 0,
};

fn graphFrom(comptime field: []const u8, p: *anyopaque) *Graph {
    const i: *Iface = @ptrCast(@alignCast(p));
    return @fieldParentPtr(field, i);
}
fn graphAddRef(g: *Graph) u32 {
    return g.refs.fetchAdd(1, .monotonic) + 1;
}
fn graphRelease(g: *Graph) u32 {
    const left = g.refs.fetchSub(1, .acq_rel) - 1;
    if (left == 0) graphDestroy(g);
    return left;
}
fn graphQI(g: *Graph, iid: ?*const Guid, out: ?*?*anyopaque) HRESULT {
    const o = out orelse return E_POINTER;
    const id = iid orelse return E_POINTER;
    const iface: ?*Iface =
        if (id.eql(&IID_IUnknown) or id.eql(&IID_IFilterGraph) or id.eql(&IID_IGraphBuilder)) &g.gb
        else if (id.eql(&IID_IMediaControl)) &g.mc
        else if (id.eql(&IID_IMediaEvent) or id.eql(&IID_IMediaEventEx)) &g.ev
        else if (id.eql(&IID_IMediaPosition)) &g.pos
        else if (id.eql(&IID_IMediaSeeking)) &g.seek
        else if (id.eql(&IID_IBasicAudio)) &g.audio
        else if (id.eql(&IID_IMediaFilter) or id.eql(&IID_IPersist)) &g.mf
        else if (id.eql(&IID_IMediaEventSink)) &g.sink
        else null;
    if (iface) |i| {
        _ = graphAddRef(g);
        o.* = i;
        return S_OK;
    }
    o.* = null;
    return E_NOINTERFACE;
}
fn Unk(comptime field: []const u8) type {
    return struct {
        fn qi(p: Self, iid: ?*const Guid, out: ?*?*anyopaque) callconv(W) HRESULT {
            return graphQI(graphFrom(field, p), iid, out);
        }
        fn addRef(p: Self) callconv(W) u32 {
            return graphAddRef(graphFrom(field, p));
        }
        fn release(p: Self) callconv(W) u32 {
            return graphRelease(graphFrom(field, p));
        }
    };
}

// --- events ---
fn pushEventLocked(g: *Graph, code: i32, p1: usize, p2: usize) void {
    if (g.ev_len == MAX_EVENTS) return; // full: the oldest are kept, as a bounded queue must
    g.events[(g.ev_head + g.ev_len) % MAX_EVENTS] = .{ .code = code, .p1 = p1, .p2 = p2 };
    g.ev_len += 1;
    if (g.ev_handle != 0) _ = threads_mod.setEvent(g.ev_handle);
}
fn popEventLocked(g: *Graph) ?Event {
    if (g.ev_len == 0) return null;
    const e = g.events[g.ev_head];
    g.ev_head = (g.ev_head + 1) % MAX_EVENTS;
    g.ev_len -= 1;
    if (g.ev_len == 0 and g.ev_handle != 0) _ = threads_mod.resetEvent(g.ev_handle);
    return e;
}

// --- clock / position ---
fn durationOf(g: *Graph) i64 {
    if (g.rend) |r| if (r.info) |i| return i.duration;
    return 0;
}
fn stopOf(g: *Graph) i64 {
    return g.stop_pos orelse durationOf(g);
}
/// Current stream position; raises EC_COMPLETE once when a running stream
/// reaches its stop position. Caller holds the lock.
fn positionLocked(g: *Graph) i64 {
    if (g.state != 2) return g.base;
    const elapsed: f64 = @floatFromInt(now100ns() - g.run_start);
    var p = g.base + @as(i64, @intFromFloat(elapsed * g.rate));
    const stop = stopOf(g);
    if (p >= stop) {
        p = stop;
        if (!g.completed and g.rend != null) {
            g.completed = true;
            pushEventLocked(g, EC_COMPLETE, 0, 0);
            std.debug.print("[WINS:DShow] EC_COMPLETE at {} ms\n", .{@divTrunc(stop, 10_000)});
        }
    }
    return p;
}
fn setPositionLocked(g: *Graph, p: i64) void {
    g.base = std.math.clamp(p, 0, durationOf(g));
    g.run_start = now100ns();
    g.completed = false;
}

// --- state changes, the caller's filters included ---
fn snapshotFilters(g: *Graph, out: *[MAX_FILTERS + 1]*anyopaque) usize {
    g.lock.lock();
    defer g.lock.unlock();
    var n: usize = 0;
    for (g.filters[0..g.nfilters]) |f| {
        out[n] = f.?;
        comAddRef(out[n]);
        n += 1;
    }
    if (g.rend) |r| {
        out[n] = &r.filt;
        comAddRef(out[n]);
        n += 1;
    }
    return n;
}
fn forEachFilter(g: *Graph, comptime op: enum { stop, pause, run, clock }, t: i64) void {
    var fs: [MAX_FILTERS + 1]*anyopaque = undefined;
    const n = snapshotFilters(g, &fs);
    for (fs[0..n]) |f| {
        const v = vt(BaseFilterVtbl, f);
        _ = switch (op) {
            .stop => v.Stop(f),
            .pause => v.Pause(f),
            .run => v.Run(f, t),
            .clock => v.SetSyncSource(f, g.clock),
        };
        comRelease(f);
    }
}
fn doPause(g: *Graph) HRESULT {
    var first_clock = false;
    g.lock.lock();
    if (g.state == 0 and !g.clock_given and g.clock == null) {
        if (clockNew()) |c| g.clock = &c.unk;
        first_clock = true;
    }
    if (g.state == 2) g.base = positionLocked(g);
    g.lock.unlock();
    if (first_clock) {
        forEachFilter(g, .clock, 0);
        g.lock.lock();
        pushEventLocked(g, EC_CLOCK_CHANGED, 0, 0);
        g.lock.unlock();
    }
    forEachFilter(g, .pause, 0);
    g.lock.lock();
    g.state = 1;
    g.lock.unlock();
    return S_OK;
}
fn doRun(g: *Graph) HRESULT {
    if (g.state == 2) return S_OK;
    if (g.state == 0) _ = doPause(g);
    const t0 = now100ns();
    forEachFilter(g, .run, t0);
    g.lock.lock();
    g.run_start = t0;
    g.state = 2;
    g.lock.unlock();
    std.debug.print("[WINS:DShow] Run at {} ms\n", .{@divTrunc(g.base, 10_000)});
    return S_OK;
}
fn doStop(g: *Graph) HRESULT {
    g.lock.lock();
    if (g.state == 2) g.base = positionLocked(g);
    g.lock.unlock();
    forEachFilter(g, .stop, 0);
    g.lock.lock();
    g.state = 0;
    g.lock.unlock();
    return S_OK;
}

fn graphDestroy(g: *Graph) void {
    if (g.state != 0) _ = doStop(g);
    if (g.rend) |r| {
        if (r.peer) |up| _ = vt(PinVtbl, up).Disconnect(up);
        rendDropConnection(r);
        r.graph = null;
        _ = rendReleaseR(r);
        g.rend = null;
    }
    for (g.filters[0..g.nfilters]) |f| {
        _ = vt(BaseFilterVtbl, f.?).JoinFilterGraph(f.?, null, null);
        comRelease(f);
    }
    g.nfilters = 0;
    comRelease(g.clock);
    if (g.ev_handle != 0) _ = threads_mod.closeHandle(g.ev_handle);
    std.debug.print("[WINS:DShow] graph released\n", .{});
    std.heap.page_allocator.destroy(g);
}

// --- IFilterGraph / IGraphBuilder ---
const UGb = Unk("gb");
fn gbAddFilter(p: Self, filter: ?*anyopaque, name: ?[*:0]const u16) callconv(W) HRESULT {
    const g = graphFrom("gb", p);
    const f = filter orelse return E_POINTER;
    g.lock.lock();
    if (g.nfilters == MAX_FILTERS) {
        g.lock.unlock();
        return E_OUTOFMEMORY;
    }
    comAddRef(f);
    g.filters[g.nfilters] = f;
    g.nfilters += 1;
    const index = g.nfilters;
    g.lock.unlock();
    var gen: [16:0]u16 = undefined;
    const nm: [*:0]const u16 = if (name) |n| (if (n[0] != 0) n else blk: {
        copyName(&gen, "0001");
        gen[3] = @intCast('0' + index % 10);
        break :blk &gen;
    }) else blk: {
        copyName(&gen, "0001");
        gen[3] = @intCast('0' + index % 10);
        break :blk &gen;
    };
    const jhr = vt(BaseFilterVtbl, f).JoinFilterGraph(f, &g.gb, nm);
    if (jhr < 0) {
        g.lock.lock();
        g.nfilters -= 1;
        g.filters[g.nfilters] = null;
        g.lock.unlock();
        comRelease(f);
        return jhr;
    }
    std.debug.print("[WINS:DShow] AddFilter -> S_OK\n", .{});
    return S_OK;
}
fn gbRemoveFilter(p: Self, filter: ?*anyopaque) callconv(W) HRESULT {
    const g = graphFrom("gb", p);
    const f = filter orelse return E_POINTER;
    g.lock.lock();
    var found: ?usize = null;
    for (g.filters[0..g.nfilters], 0..) |x, i| {
        if (x == f) found = i;
    }
    const idx = found orelse {
        g.lock.unlock();
        return VFW_E_NOT_FOUND;
    };
    for (idx..g.nfilters - 1) |i| g.filters[i] = g.filters[i + 1];
    g.nfilters -= 1;
    g.filters[g.nfilters] = null;
    const rend = g.rend;
    g.lock.unlock();
    // Disconnect whatever of ours is attached to this filter's pins.
    if (rend) |r| if (r.peer) |up| {
        var pi: PIN_INFO = undefined;
        if (vt(PinVtbl, up).QueryPinInfo(up, &pi) == S_OK) {
            const owner = pi.pFilter;
            comRelease(owner);
            if (owner == f) {
                _ = vt(PinVtbl, up).Disconnect(up);
                rendDropConnection(r);
            }
        }
    };
    _ = vt(BaseFilterVtbl, f).JoinFilterGraph(f, null, null);
    comRelease(f);
    return S_OK;
}
fn gbEnumFilters(p: Self, out: ?*?*anyopaque) callconv(W) HRESULT {
    const g = graphFrom("gb", p);
    const o = out orelse return E_POINTER;
    var fs: [MAX_FILTERS + 1]*anyopaque = undefined;
    const n = snapshotFilters(g, &fs);
    const e = enumNew(&IID_IEnumFilters, fs[0..n], 0);
    for (fs[0..n]) |f| comRelease(f);
    o.* = if (e) |x| &x.unk else null;
    return if (e != null) S_OK else E_OUTOFMEMORY;
}
fn gbFindFilterByName(p: Self, name: ?[*:0]const u16, out: ?*?*anyopaque) callconv(W) HRESULT {
    _ = p; _ = name;
    if (out) |o| o.* = null;
    return VFW_E_NOT_FOUND; // names are passed to the filters, not kept here
}
fn connectPins(g: *Graph, out_pin: *anyopaque, in_pin: *anyopaque, mt: ?*const AM_MEDIA_TYPE) HRESULT {
    _ = g;
    return vt(PinVtbl, out_pin).Connect(out_pin, in_pin, mt);
}
fn gbConnectDirect(p: Self, a: ?*anyopaque, b: ?*anyopaque, mt: ?*const AM_MEDIA_TYPE) callconv(W) HRESULT {
    return connectPins(graphFrom("gb", p), a orelse return E_POINTER, b orelse return E_POINTER, mt);
}
fn gbReconnect(p: Self, pin: ?*anyopaque) callconv(W) HRESULT {
    _ = p; _ = pin;
    return E_NOTIMPL;
}
fn gbDisconnect(p: Self, pin: ?*anyopaque) callconv(W) HRESULT {
    _ = p;
    const q = pin orelse return E_POINTER;
    return vt(PinVtbl, q).Disconnect(q);
}
fn gbSetDefaultSyncSource(p: Self) callconv(W) HRESULT {
    const g = graphFrom("gb", p);
    g.lock.lock();
    if (g.clock == null) {
        if (clockNew()) |c| g.clock = &c.unk;
    }
    g.clock_given = false;
    g.lock.unlock();
    forEachFilter(g, .clock, 0);
    return S_OK;
}
fn gbConnect(p: Self, a: ?*anyopaque, b: ?*anyopaque) callconv(W) HRESULT {
    return connectPins(graphFrom("gb", p), a orelse return E_POINTER, b orelse return E_POINTER, null);
}
fn gbRender(p: Self, pin: ?*anyopaque) callconv(W) HRESULT {
    const g = graphFrom("gb", p);
    const out_pin = pin orelse return E_POINTER;
    const pv = vt(PinVtbl, out_pin);
    var dir: u32 = 0;
    if (pv.QueryDirection(out_pin, &dir) != S_OK or dir != PINDIR_OUTPUT) return VFW_E_INVALID_DIRECTION;
    var peer: ?*anyopaque = null;
    if (pv.ConnectedTo(out_pin, &peer) == S_OK) {
        comRelease(peer);
        return VFW_E_CANNOT_RENDER; // already connected (Proton answers the same)
    }
    if (g.rend != null) {
        std.debug.print("[WINS:DShow] Render: a second stream in one graph is not supported\n", .{});
        return VFW_E_CANNOT_RENDER;
    }
    const r = rendNew(g) orelse return E_OUTOFMEMORY;
    g.rend = r;
    const chr = pv.Connect(out_pin, &r.pin, null);
    if (chr != S_OK) {
        std.debug.print("[WINS:DShow] Render: Connect -> 0x{x}, nothing rendered\n", .{@as(u32, @bitCast(chr))});
        g.rend = null;
        r.graph = null;
        _ = rendReleaseR(r);
        return VFW_E_CANNOT_RENDER;
    }
    if (g.clock) |c| _ = vt(BaseFilterVtbl, &r.filt).SetSyncSource(&r.filt, c);
    std.debug.print("[WINS:DShow] Render -> S_OK\n", .{});
    return S_OK;
}
fn gbRenderFile(p: Self, file: ?[*:0]const u16, list: ?[*:0]const u16) callconv(W) HRESULT {
    _ = p; _ = file; _ = list;
    std.debug.print("[WINS:DShow] RenderFile -> E_NOTIMPL (no file source filter)\n", .{});
    return E_NOTIMPL;
}
fn gbAddSourceFilter(p: Self, file: ?[*:0]const u16, name: ?[*:0]const u16, out: ?*?*anyopaque) callconv(W) HRESULT {
    _ = p; _ = file; _ = name;
    if (out) |o| o.* = null;
    std.debug.print("[WINS:DShow] AddSourceFilter -> E_NOTIMPL (no file source filter)\n", .{});
    return E_NOTIMPL;
}
fn gbSetLogFile(p: Self, h: usize) callconv(W) HRESULT {
    _ = p; _ = h;
    return S_OK;
}
fn gbAbort(p: Self) callconv(W) HRESULT {
    _ = p;
    return S_OK;
}
fn gbShouldOperationContinue(p: Self) callconv(W) HRESULT {
    _ = p;
    return S_OK;
}
const gb_vtbl = [_]*const anyopaque{ &UGb.qi, &UGb.addRef, &UGb.release, &gbAddFilter, &gbRemoveFilter, &gbEnumFilters, &gbFindFilterByName, &gbConnectDirect, &gbReconnect, &gbDisconnect, &gbSetDefaultSyncSource, &gbConnect, &gbRender, &gbRenderFile, &gbAddSourceFilter, &gbSetLogFile, &gbAbort, &gbShouldOperationContinue };

// --- IDispatch (not implemented; shared by the dual interfaces) ---
fn dispGetTypeInfoCount(p: Self, n: ?*u32) callconv(W) HRESULT {
    _ = p;
    (n orelse return E_POINTER).* = 0;
    return S_OK;
}
fn dispGetTypeInfo(p: Self, i: u32, l: u32, out: ?*?*anyopaque) callconv(W) HRESULT {
    _ = p; _ = i; _ = l;
    if (out) |o| o.* = null;
    return E_NOTIMPL;
}
fn dispGetIDsOfNames(p: Self, riid: ?*const Guid, names: ?*anyopaque, n: u32, lcid: u32, ids: ?*anyopaque) callconv(W) HRESULT {
    _ = p; _ = riid; _ = names; _ = n; _ = lcid; _ = ids;
    return E_NOTIMPL;
}
fn dispInvoke(p: Self, id: i32, riid: ?*const Guid, lcid: u32, flags: u16, params: ?*anyopaque, res: ?*anyopaque, exc: ?*anyopaque, arg: ?*u32) callconv(W) HRESULT {
    _ = p; _ = id; _ = riid; _ = lcid; _ = flags; _ = params; _ = res; _ = exc; _ = arg;
    return E_NOTIMPL;
}

// --- IMediaControl ---
const UMc = Unk("mc");
fn mcRun(p: Self) callconv(W) HRESULT {
    return doRun(graphFrom("mc", p));
}
fn mcPause(p: Self) callconv(W) HRESULT {
    return doPause(graphFrom("mc", p));
}
fn mcStop(p: Self) callconv(W) HRESULT {
    return doStop(graphFrom("mc", p));
}
fn mcGetState(p: Self, ms: i32, out: ?*i32) callconv(W) HRESULT {
    _ = ms;
    (out orelse return E_POINTER).* = @intCast(graphFrom("mc", p).state);
    return S_OK;
}
fn mcRenderFile(p: Self, name: ?*anyopaque) callconv(W) HRESULT {
    _ = p; _ = name;
    std.debug.print("[WINS:DShow] IMediaControl::RenderFile -> E_NOTIMPL\n", .{});
    return E_NOTIMPL;
}
fn mcAddSourceFilter(p: Self, name: ?*anyopaque, out: ?*?*anyopaque) callconv(W) HRESULT {
    _ = p; _ = name;
    if (out) |o| o.* = null;
    return E_NOTIMPL;
}
fn mcGetCollection(p: Self, out: ?*?*anyopaque) callconv(W) HRESULT {
    _ = p;
    if (out) |o| o.* = null;
    return E_NOTIMPL;
}
const mc_vtbl = [_]*const anyopaque{ &UMc.qi, &UMc.addRef, &UMc.release, &dispGetTypeInfoCount, &dispGetTypeInfo, &dispGetIDsOfNames, &dispInvoke, &mcRun, &mcPause, &mcStop, &mcGetState, &mcRenderFile, &mcAddSourceFilter, &mcGetCollection, &mcGetCollection, &mcStop };

// --- IMediaEventEx ---
const UEv = Unk("ev");
fn evGetEventHandle(p: Self, out: ?*usize) callconv(W) HRESULT {
    const g = graphFrom("ev", p);
    const o = out orelse return E_POINTER;
    g.lock.lock();
    defer g.lock.unlock();
    if (g.ev_handle == 0) {
        g.ev_handle = threads_mod.createEvent(true, g.ev_len != 0, null);
    }
    o.* = g.ev_handle;
    return S_OK;
}
fn evGetEvent(p: Self, code: ?*i32, p1: ?*usize, p2: ?*usize, timeout: i32) callconv(W) HRESULT {
    const g = graphFrom("ev", p);
    const c = code orelse return E_POINTER;
    const a = p1 orelse return E_POINTER;
    const b = p2 orelse return E_POINTER;
    const deadline: ?i64 = if (timeout < 0) null else now100ns() + @as(i64, timeout) * 10_000;
    while (true) {
        g.lock.lock();
        _ = positionLocked(g); // raises EC_COMPLETE when due
        const e = popEventLocked(g);
        g.lock.unlock();
        if (e) |ev| {
            c.* = ev.code;
            a.* = ev.p1;
            b.* = ev.p2;
            return S_OK;
        }
        if (deadline) |d| if (now100ns() >= d) {
            c.* = 0;
            a.* = 0;
            b.* = 0;
            return E_ABORT;
        };
        sleepMs(5);
    }
}
fn evWaitForCompletion(p: Self, timeout: i32, code: ?*i32) callconv(W) HRESULT {
    const g = graphFrom("ev", p);
    const deadline: ?i64 = if (timeout < 0) null else now100ns() + @as(i64, timeout) * 10_000;
    while (true) {
        g.lock.lock();
        _ = positionLocked(g);
        const done = g.completed;
        g.lock.unlock();
        if (done) {
            if (code) |o| o.* = EC_COMPLETE;
            return S_OK;
        }
        if (g.state != 2) return VFW_E_WRONG_STATE;
        if (deadline) |d| if (now100ns() >= d) {
            if (code) |o| o.* = 0;
            return E_ABORT;
        };
        sleepMs(5);
    }
}
const VFW_E_WRONG_STATE: HRESULT = hr32(0x80040227);
fn evCodeOnly(p: Self, code: i32) callconv(W) HRESULT {
    _ = p; _ = code;
    return S_OK;
}
fn evFreeEventParams(p: Self, code: i32, a: usize, b: usize) callconv(W) HRESULT {
    _ = p; _ = code; _ = a; _ = b;
    return S_OK; // no event carries an allocated parameter here
}
fn evSetNotifyWindow(p: Self, hwnd: usize, msg: i32, inst: usize) callconv(W) HRESULT {
    _ = p; _ = hwnd; _ = msg; _ = inst;
    std.debug.print("[WINS:DShow] SetNotifyWindow stored; no window message is ever posted\n", .{});
    return S_OK;
}
fn evSetNotifyFlags(p: Self, f: i32) callconv(W) HRESULT {
    if (f != 0 and f != 1) return E_INVALIDARG;
    graphFrom("ev", p).notify_flags = f;
    return S_OK;
}
fn evGetNotifyFlags(p: Self, f: ?*i32) callconv(W) HRESULT {
    (f orelse return E_POINTER).* = graphFrom("ev", p).notify_flags;
    return S_OK;
}
const ev_vtbl = [_]*const anyopaque{ &UEv.qi, &UEv.addRef, &UEv.release, &dispGetTypeInfoCount, &dispGetTypeInfo, &dispGetIDsOfNames, &dispInvoke, &evGetEventHandle, &evGetEvent, &evWaitForCompletion, &evCodeOnly, &evCodeOnly, &evFreeEventParams, &evSetNotifyWindow, &evSetNotifyFlags, &evGetNotifyFlags };

// --- IMediaEventSink ---
const USink = Unk("sink");
fn sinkNotify(p: Self, code: i32, a: usize, b: usize) callconv(W) HRESULT {
    const g = graphFrom("sink", p);
    g.lock.lock();
    pushEventLocked(g, code, a, b);
    g.lock.unlock();
    return S_OK;
}
const sink_vtbl = [_]*const anyopaque{ &USink.qi, &USink.addRef, &USink.release, &sinkNotify };

// --- IMediaSeeking (100 ns units) ---
const USeek = Unk("seek");
const AM_SEEKING_CAPS: u32 = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x100; // absolute, fwd, back, cur, stop, duration
fn skGetCapabilities(p: Self, c: ?*u32) callconv(W) HRESULT {
    _ = p;
    (c orelse return E_POINTER).* = AM_SEEKING_CAPS;
    return S_OK;
}
fn skCheckCapabilities(p: Self, c: ?*u32) callconv(W) HRESULT {
    _ = p;
    const q = c orelse return E_POINTER;
    const want = q.*;
    q.* = want & AM_SEEKING_CAPS;
    if (q.* == want) return S_OK;
    return if (q.* != 0) S_FALSE else E_FAIL;
}
fn skIsFormatSupported(p: Self, f: ?*const Guid) callconv(W) HRESULT {
    _ = p;
    const g = f orelse return E_POINTER;
    return if (g.eql(&TIME_FORMAT_MEDIA_TIME)) S_OK else S_FALSE;
}
fn skFormatOut(p: Self, f: ?*Guid) callconv(W) HRESULT {
    _ = p;
    (f orelse return E_POINTER).* = TIME_FORMAT_MEDIA_TIME;
    return S_OK;
}
fn skSetTimeFormat(p: Self, f: ?*const Guid) callconv(W) HRESULT {
    _ = p;
    const g = f orelse return E_POINTER;
    return if (g.eql(&TIME_FORMAT_MEDIA_TIME)) S_OK else E_INVALIDARG;
}
fn skGetDuration(p: Self, d: ?*i64) callconv(W) HRESULT {
    const g = graphFrom("seek", p);
    (d orelse return E_POINTER).* = durationOf(g);
    return S_OK;
}
fn skGetStopPosition(p: Self, d: ?*i64) callconv(W) HRESULT {
    const g = graphFrom("seek", p);
    (d orelse return E_POINTER).* = stopOf(g);
    return S_OK;
}
fn skGetCurrentPosition(p: Self, d: ?*i64) callconv(W) HRESULT {
    const g = graphFrom("seek", p);
    const o = d orelse return E_POINTER;
    g.lock.lock();
    o.* = positionLocked(g);
    g.lock.unlock();
    return S_OK;
}
fn skConvertTimeFormat(p: Self, target: ?*i64, tf: ?*const Guid, src: i64, sf: ?*const Guid) callconv(W) HRESULT {
    _ = p;
    const o = target orelse return E_POINTER;
    const tok = if (tf) |g| g.eql(&TIME_FORMAT_MEDIA_TIME) else true;
    const sok = if (sf) |g| g.eql(&TIME_FORMAT_MEDIA_TIME) else true;
    if (!tok or !sok) return E_INVALIDARG;
    o.* = src;
    return S_OK;
}
fn skSetPositions(p: Self, cur: ?*i64, cur_flags: u32, stop: ?*i64, stop_flags: u32) callconv(W) HRESULT {
    const g = graphFrom("seek", p);
    g.lock.lock();
    defer g.lock.unlock();
    const now_pos = positionLocked(g);
    switch (cur_flags & 3) {
        0 => {},
        1 => if (cur) |c| setPositionLocked(g, c.*) else return E_POINTER,
        2, 3 => if (cur) |c| setPositionLocked(g, now_pos + c.*) else return E_POINTER,
        else => unreachable,
    }
    switch (stop_flags & 3) {
        0 => {},
        1 => if (stop) |s| {
            g.stop_pos = std.math.clamp(s.*, 0, durationOf(g));
        } else return E_POINTER,
        2, 3 => if (stop) |s| {
            g.stop_pos = std.math.clamp(stopOf(g) + s.*, 0, durationOf(g));
        } else return E_POINTER,
        else => unreachable,
    }
    return S_OK;
}
fn skGetPositions(p: Self, cur: ?*i64, stop: ?*i64) callconv(W) HRESULT {
    const g = graphFrom("seek", p);
    g.lock.lock();
    defer g.lock.unlock();
    if (cur) |c| c.* = positionLocked(g);
    if (stop) |s| s.* = stopOf(g);
    return S_OK;
}
fn skGetAvailable(p: Self, a: ?*i64, b: ?*i64) callconv(W) HRESULT {
    const g = graphFrom("seek", p);
    if (a) |x| x.* = 0;
    if (b) |x| x.* = durationOf(g);
    return S_OK;
}
fn setRate(g: *Graph, r: f64) HRESULT {
    if (!(r > 0)) return E_INVALIDARG;
    g.lock.lock();
    defer g.lock.unlock();
    g.base = positionLocked(g);
    g.run_start = now100ns();
    g.rate = r;
    return S_OK;
}
fn skSetRate(p: Self, r: f64) callconv(W) HRESULT {
    return setRate(graphFrom("seek", p), r);
}
fn skGetRate(p: Self, r: ?*f64) callconv(W) HRESULT {
    (r orelse return E_POINTER).* = graphFrom("seek", p).rate;
    return S_OK;
}
fn skGetPreroll(p: Self, r: ?*i64) callconv(W) HRESULT {
    _ = p;
    (r orelse return E_POINTER).* = 0;
    return S_OK;
}
const seek_vtbl = [_]*const anyopaque{ &USeek.qi, &USeek.addRef, &USeek.release, &skGetCapabilities, &skCheckCapabilities, &skIsFormatSupported, &skFormatOut, &skFormatOut, &skIsFormatSupported, &skSetTimeFormat, &skGetDuration, &skGetStopPosition, &skGetCurrentPosition, &skConvertTimeFormat, &skSetPositions, &skGetPositions, &skGetAvailable, &skSetRate, &skGetRate, &skGetPreroll };

// --- IMediaPosition (REFTIME = seconds as double) ---
const UPos = Unk("pos");
fn secs(t: i64) f64 {
    return @as(f64, @floatFromInt(t)) / 10_000_000.0;
}
fn ticks(s: f64) i64 {
    return @intFromFloat(s * 10_000_000.0);
}
fn mpGetDuration(p: Self, out: ?*f64) callconv(W) HRESULT {
    (out orelse return E_POINTER).* = secs(durationOf(graphFrom("pos", p)));
    return S_OK;
}
fn mpPutCurrentPosition(p: Self, s: f64) callconv(W) HRESULT {
    const g = graphFrom("pos", p);
    g.lock.lock();
    setPositionLocked(g, ticks(s));
    g.lock.unlock();
    return S_OK;
}
fn mpGetCurrentPosition(p: Self, out: ?*f64) callconv(W) HRESULT {
    const g = graphFrom("pos", p);
    const o = out orelse return E_POINTER;
    g.lock.lock();
    o.* = secs(positionLocked(g));
    g.lock.unlock();
    return S_OK;
}
fn mpGetStopTime(p: Self, out: ?*f64) callconv(W) HRESULT {
    (out orelse return E_POINTER).* = secs(stopOf(graphFrom("pos", p)));
    return S_OK;
}
fn mpPutStopTime(p: Self, s: f64) callconv(W) HRESULT {
    const g = graphFrom("pos", p);
    g.stop_pos = std.math.clamp(ticks(s), 0, durationOf(g));
    return S_OK;
}
fn mpGetPreroll(p: Self, out: ?*f64) callconv(W) HRESULT {
    _ = p;
    (out orelse return E_POINTER).* = 0;
    return S_OK;
}
fn mpPutPreroll(p: Self, s: f64) callconv(W) HRESULT {
    _ = p; _ = s;
    return S_OK;
}
fn mpPutRate(p: Self, r: f64) callconv(W) HRESULT {
    return setRate(graphFrom("pos", p), r);
}
fn mpGetRate(p: Self, r: ?*f64) callconv(W) HRESULT {
    (r orelse return E_POINTER).* = graphFrom("pos", p).rate;
    return S_OK;
}
fn mpCanSeek(p: Self, out: ?*i32) callconv(W) HRESULT {
    _ = p;
    (out orelse return E_POINTER).* = -1; // OATRUE
    return S_OK;
}
const pos_vtbl = [_]*const anyopaque{ &UPos.qi, &UPos.addRef, &UPos.release, &dispGetTypeInfoCount, &dispGetTypeInfo, &dispGetIDsOfNames, &dispInvoke, &mpGetDuration, &mpPutCurrentPosition, &mpGetCurrentPosition, &mpGetStopTime, &mpPutStopTime, &mpGetPreroll, &mpPutPreroll, &mpPutRate, &mpGetRate, &mpCanSeek, &mpCanSeek };

// --- IBasicAudio ---
const UAu = Unk("audio");
fn baPutVolume(p: Self, v: i32) callconv(W) HRESULT {
    if (v > 0 or v < -10000) return E_INVALIDARG;
    graphFrom("audio", p).volume = v;
    return S_OK;
}
fn baGetVolume(p: Self, v: ?*i32) callconv(W) HRESULT {
    (v orelse return E_POINTER).* = graphFrom("audio", p).volume;
    return S_OK;
}
fn baPutBalance(p: Self, v: i32) callconv(W) HRESULT {
    if (v > 10000 or v < -10000) return E_INVALIDARG;
    graphFrom("audio", p).balance = v;
    return S_OK;
}
fn baGetBalance(p: Self, v: ?*i32) callconv(W) HRESULT {
    (v orelse return E_POINTER).* = graphFrom("audio", p).balance;
    return S_OK;
}
const audio_vtbl = [_]*const anyopaque{ &UAu.qi, &UAu.addRef, &UAu.release, &dispGetTypeInfoCount, &dispGetTypeInfo, &dispGetIDsOfNames, &dispInvoke, &baPutVolume, &baGetVolume, &baPutBalance, &baGetBalance };

// --- IMediaFilter on the graph ---
const UMf = Unk("mf");
fn mfGetClassID(p: Self, c: ?*Guid) callconv(W) HRESULT {
    _ = p;
    (c orelse return E_POINTER).* = CLSID_FilterGraph;
    return S_OK;
}
fn mfStop(p: Self) callconv(W) HRESULT {
    return doStop(graphFrom("mf", p));
}
fn mfPause(p: Self) callconv(W) HRESULT {
    return doPause(graphFrom("mf", p));
}
fn mfRun(p: Self, t: i64) callconv(W) HRESULT {
    _ = t;
    return doRun(graphFrom("mf", p));
}
fn mfGetState(p: Self, ms: u32, s: ?*u32) callconv(W) HRESULT {
    _ = ms;
    (s orelse return E_POINTER).* = graphFrom("mf", p).state;
    return S_OK;
}
fn mfSetSyncSource(p: Self, c: ?*anyopaque) callconv(W) HRESULT {
    const g = graphFrom("mf", p);
    if (c) |q| comAddRef(q);
    g.lock.lock();
    const old = g.clock;
    g.clock = c;
    g.clock_given = true;
    g.lock.unlock();
    comRelease(old);
    forEachFilter(g, .clock, 0);
    return S_OK;
}
fn mfGetSyncSource(p: Self, c: ?*?*anyopaque) callconv(W) HRESULT {
    const g = graphFrom("mf", p);
    const o = c orelse return E_POINTER;
    o.* = g.clock;
    if (g.clock) |q| comAddRef(q);
    return S_OK;
}
const mf_vtbl = [_]*const anyopaque{ &UMf.qi, &UMf.addRef, &UMf.release, &mfGetClassID, &mfStop, &mfPause, &mfRun, &mfGetState, &mfSetSyncSource, &mfGetSyncSource };

comptime {
    // Method counts per interface, from the SDK headers (strmif.h / control.h).
    std.debug.assert(gb_vtbl.len == 18);
    std.debug.assert(mc_vtbl.len == 16);
    std.debug.assert(ev_vtbl.len == 16);
    std.debug.assert(pos_vtbl.len == 18);
    std.debug.assert(seek_vtbl.len == 20);
    std.debug.assert(audio_vtbl.len == 11);
    std.debug.assert(mf_vtbl.len == 10);
    std.debug.assert(sink_vtbl.len == 4);
    std.debug.assert(rend_filter_vtbl.len == 15);
    std.debug.assert(rend_pin_vtbl.len == 18);
    std.debug.assert(enum_vtbl.len == 7);
    std.debug.assert(clock_vtbl.len == 7);
    std.debug.assert(@offsetOf(Iface, "vtbl") == 0);
}

// ---------------------------------------------------------------------------
// Entry point for CoCreateInstance
// ---------------------------------------------------------------------------
pub fn isFilterGraph(clsid: ?*const anyopaque) bool {
    const c: *const Guid = @ptrCast(@alignCast(clsid orelse return false));
    return c.eql(&CLSID_FilterGraph) or c.eql(&CLSID_FilterGraphNoThread);
}

pub fn createFilterGraph(outer: ?*anyopaque, riid: ?*const anyopaque, ppv: ?*?*anyopaque) HRESULT {
    const o = ppv orelse return E_POINTER;
    o.* = null;
    if (outer != null) return CLASS_E_NOAGGREGATION;
    const g = std.heap.page_allocator.create(Graph) catch return E_OUTOFMEMORY;
    g.* = .{
        .gb = .{ .vtbl = &gb_vtbl },
        .mc = .{ .vtbl = &mc_vtbl },
        .ev = .{ .vtbl = &ev_vtbl },
        .pos = .{ .vtbl = &pos_vtbl },
        .seek = .{ .vtbl = &seek_vtbl },
        .audio = .{ .vtbl = &audio_vtbl },
        .mf = .{ .vtbl = &mf_vtbl },
        .sink = .{ .vtbl = &sink_vtbl },
        .refs = std.atomic.Value(u32).init(1),
    };
    const hr = graphQI(g, @ptrCast(@alignCast(riid)), o);
    _ = graphRelease(g); // the QI reference is the caller's; on failure this frees the graph
    return hr;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
test "mpegScan: ID3v2 skip, MPEG-1 Layer III 48 kHz 256 kbps frame walk" {
    // Synthesize: ID3v2 tag (size 20) + 5 frames of 0xFFFB D4 00 (768 bytes each).
    var buf: [10 + 20 + 5 * 768 + 128]u8 = undefined;
    @memset(&buf, 0);
    @memcpy(buf[0..3], "ID3");
    buf[3] = 3;
    buf[9] = 20;
    var off: usize = 30;
    for (0..5) |_| {
        buf[off] = 0xFF;
        buf[off + 1] = 0xFB;
        buf[off + 2] = 0xD4;
        buf[off + 3] = 0x00;
        off += 768;
    }
    @memcpy(buf[off .. off + 3], "TAG"); // ID3v1 ends the stream
    const info = mpegScan(&buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 5), info.frames);
    try std.testing.expectEqual(@as(u32, 48000), info.sample_rate);
    try std.testing.expectEqual(@as(u32, 1152), info.samples_per_frame);
    try std.testing.expectEqual(@as(usize, 30), info.first_frame);
    try std.testing.expectEqual(@as(i64, 5 * 1152 * 10_000_000 / 48000), info.duration); // 120 ms
    // Negative control: no frames at all.
    try std.testing.expect(mpegScan(buf[0..30]) == null);
}

test "createFilterGraph: refuses aggregation and unknown interfaces, QI table is closed" {
    var out: ?*anyopaque = null;
    try std.testing.expectEqual(CLASS_E_NOAGGREGATION, createFilterGraph(@ptrFromInt(0x1000), &IID_IFilterGraph, &out));
    try std.testing.expectEqual(E_NOINTERFACE, createFilterGraph(null, &IID_IPin, &out));
    try std.testing.expect(out == null);
    try std.testing.expectEqual(S_OK, createFilterGraph(null, &IID_IFilterGraph, &out));
    const g = graphFrom("gb", out.?);
    var mc: ?*anyopaque = null;
    try std.testing.expectEqual(S_OK, graphQI(g, &IID_IMediaControl, &mc));
    try std.testing.expectEqual(@as(u32, 2), g.refs.load(.monotonic));
    var st: i32 = -1;
    try std.testing.expectEqual(S_OK, mcGetState(mc.?, 0, &st));
    try std.testing.expectEqual(@as(i32, 0), st);
    try std.testing.expectEqual(E_INVALIDARG, baPutVolume(&g.audio, 1));
    try std.testing.expectEqual(S_OK, baPutVolume(&g.audio, -2602));
    var code: i32 = 0;
    var a: usize = 0;
    var b: usize = 0;
    try std.testing.expectEqual(E_ABORT, evGetEvent(&g.ev, &code, &a, &b, 0));
    _ = UMc.release(mc.?);
    try std.testing.expectEqual(@as(u32, 0), UGb.release(out.?));
}
