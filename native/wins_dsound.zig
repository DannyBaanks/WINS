//! WINS native DirectSound (dsound.dll) — COM objects over memory-backed buffers.
//!
//! Why this file exists: the real Steam build of FalloutNV.exe imports
//! `DSOUND.dll!ordinal 11`, and that ordinal is `DirectSoundCreate8` (measured
//! against the export table of Proton's i386 dsound.dll, whose ordinal base is
//! 1: 1 DirectSoundCreate, 6 DirectSoundCaptureCreate, 10
//! DirectSoundFullDuplexCreate, 11 DirectSoundCreate8, 12
//! DirectSoundCaptureCreate8). With the slot unresolved the loader refuses to
//! run the image at all, so the import has to resolve to a real implementation.
//!
//! What is implemented here: the object graph a DirectSound app talks to.
//! `DirectSoundCreate8` returns an IDirectSound8 whose vtable carries the full
//! method set, and `CreateSoundBuffer` returns an IDirectSoundBuffer8 backed by
//! real memory, with Lock/Unlock honouring the DSBLOCK flags and wrap-around,
//! and a play cursor advanced by a monotonic clock at the buffer's own byte
//! rate. Volume, pan, frequency, format, status and caps answer with the values
//! that were set, not with fabricated success.
//!
//! What is NOT implemented, deliberately and visibly: no PCM ever reaches an
//! output device, so playback is silent; capture devices report DSERR_NODRIVER
//! because this machine has no capture path wired; the 3D listener/buffer
//! interfaces and the notify interface are REFUSED through QueryInterface with
//! E_NOINTERFACE instead of handing back an object whose vtable would not match
//! what the caller is about to call. QueryInterface therefore matches the exact
//! IIDs of the interfaces this file actually implements, not a GUID prefix.
//! The next step after a boot is a mixer that writes these same buffers to
//! ALSA, and this note goes away then.

const std = @import("std");
const linux = std.os.linux;

pub const W: std.builtin.CallingConvention = .winapi;

pub const HRESULT = i32;
pub const S_OK: HRESULT = 0;
pub const S_FALSE: HRESULT = 1;
pub const E_NOINTERFACE: HRESULT = -2147467262; // 0x80004002
pub const E_INVALIDARG: HRESULT = -2147024809; // 0x80070057
pub const E_OUTOFMEMORY: HRESULT = -2147024882; // 0x8007000E
pub const E_NOTIMPL: HRESULT = -2147467263; // 0x80004001
pub const DSERR_NODRIVER: HRESULT = -2004287368; // 0x88780078
pub const DSERR_INVALIDCALL: HRESULT = -2004287328; // 0x887800A0
pub const DSERR_UNSUPPORTED: HRESULT = -2004287314; // 0x887800AE

// DSBCAPS
pub const DSBCAPS_PRIMARYBUFFER: u32 = 0x00000001;
pub const DSBCAPS_CTRL3D: u32 = 0x00000010;
pub const DSBCAPS_CTRLFREQUENCY: u32 = 0x00000020;
pub const DSBCAPS_CTRLPAN: u32 = 0x00000040;
pub const DSBCAPS_CTRLVOLUME: u32 = 0x00000080;
pub const DSBCAPS_CTRLPOSITIONNOTIFY: u32 = 0x00000100;
pub const DSBCAPS_GLOBALFOCUS: u32 = 0x00008000;
pub const DSBCAPS_GETCURRENTPOSITION2: u32 = 0x00010000;

// DSBPLAY / DSBLOCK / DSBSTATUS
pub const DSBPLAY_LOOPING: u32 = 0x00000001;
pub const DSBLOCK_FROMWRITECURSOR: u32 = 0x00000001;
pub const DSBLOCK_ENTIREBUFFER: u32 = 0x00000002;
pub const DSBSTATUS_PLAYING: u32 = 0x00000001;
pub const DSBSTATUS_BUFFERLOST: u32 = 0x00000002;
pub const DSBSTATUS_LOOPING: u32 = 0x00000004;

// DSCAPS flags
pub const DSCAPS_PRIMARYMONO: u32 = 0x00000001;
pub const DSCAPS_PRIMARYSTEREO: u32 = 0x00000002;
pub const DSCAPS_PRIMARY16BIT: u32 = 0x00000008;
pub const DSCAPS_SECONDARYMONO: u32 = 0x00000100;
pub const DSCAPS_SECONDARYSTEREO: u32 = 0x00000200;
pub const DSCAPS_SECONDARY16BIT: u32 = 0x00000800;

pub const Guid = extern struct {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [8]u8,

    fn eql(self: *const Guid, other: *const Guid) bool {
        return self.data1 == other.data1 and self.data2 == other.data2 and
            self.data3 == other.data3 and std.mem.eql(u8, &self.data4, &other.data4);
    }
};

// The interfaces this file actually implements. Anything else is refused.
const IID_IUnknown = Guid{ .data1 = 0x00000000, .data2 = 0x0000, .data3 = 0x0000, .data4 = .{ 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
const IID_IDirectSound = Guid{ .data1 = 0x279AFA83, .data2 = 0x4981, .data3 = 0x11CE, .data4 = .{ 0xA5, 0x21, 0x00, 0x20, 0xAF, 0x0B, 0xE5, 0x60 } };
const IID_IDirectSound8 = Guid{ .data1 = 0xC50A7E93, .data2 = 0xF395, .data3 = 0x4834, .data4 = .{ 0x9E, 0xF6, 0x7F, 0xA9, 0x9D, 0xE5, 0x09, 0x66 } };
const IID_IDirectSoundBuffer = Guid{ .data1 = 0x279AFA85, .data2 = 0x4981, .data3 = 0x11CE, .data4 = .{ 0xA5, 0x21, 0x00, 0x20, 0xAF, 0x0B, 0xE5, 0x60 } };
const IID_IDirectSoundBuffer8 = Guid{ .data1 = 0x6825A449, .data2 = 0x7524, .data3 = 0x4D82, .data4 = .{ 0x92, 0x00, 0x61, 0x43, 0x4A, 0x00, 0x2F, 0xA0 } };

fn accepts(self_iid: *const Guid, iid: ?*const Guid) bool {
    const g = iid orelse return false;
    return g.eql(self_iid) or g.eql(&IID_IUnknown);
}

pub const WAVEFORMATEX = extern struct {
    wFormatTag: u16 = 1, // WAVE_FORMAT_PCM
    nChannels: u16 = 2,
    nSamplesPerSec: u32 = 44100,
    nAvgBytesPerSec: u32 = 44100 * 4,
    nBlockAlign: u16 = 4,
    wBitsPerSample: u16 = 16,
    cbSize: u16 = 0,
};

pub const DSBUFFERDESC = extern struct {
    dwSize: u32,
    dwFlags: u32,
    dwBufferBytes: u32,
    dwReserved: u32,
    lpwfxFormat: ?*WAVEFORMATEX,
    guid3DAlgorithm: Guid = .{ .data1 = 0, .data2 = 0, .data3 = 0, .data4 = [_]u8{0} ** 8 },
};

pub const DSCBCAPS = extern struct {
    dwSize: u32,
    dwFlags: u32,
    dwBufferBytes: u32,
    dwReserved: u32,
};

pub const DSCAPS = extern struct {
    dwSize: u32,
    dwFlags: u32,
    dwMinSecondarySampleRate: u32,
    dwMaxSecondarySampleRate: u32,
    dwPrimaryBuffers: u32,
    dwMaxHwMixingAllBuffers: u32,
    dwMaxHwMixingStaticBuffers: u32,
    dwMaxHwMixingStreamingBuffers: u32,
    dwFreeHwMixingAllBuffers: u32,
    dwFreeHwMixingStaticBuffers: u32,
    dwFreeHwMixingStreamingBuffers: u32,
    dwMaxHw3DAllBuffers: u32,
    dwMaxHw3DStaticBuffers: u32,
    dwMaxHw3DStreamingBuffers: u32,
    dwFreeHw3DAllBuffers: u32,
    dwFreeHw3DStaticBuffers: u32,
    dwFreeHw3DStreamingBuffers: u32,
    dwTotalHwMemBytes: u32,
    dwFreeHwMemBytes: u32,
    dwMaxContigFreeHwMemBytes: u32,
    dwUnlockTransferRateHwBuffers: u32,
    dwPlayCpuOverheadSwBuffers: u32,
    dwReserved1: u32,
    dwReserved2: u32,
};

// ---------------------------------------------------------------------------
// Sound buffer object (IDirectSoundBuffer8)
// ---------------------------------------------------------------------------

pub const Buffer = extern struct {
    vtbl: *const BufferVtbl,
    refs: u32,
    buf_ptr: ?[*]u8,
    buf_len: u32,
    wfx: WAVEFORMATEX,
    flags: u32,
    volume: i32,
    pan: i32,
    frequency: u32,
    playing: bool,
    looping: bool,
    start_ms: i64,
    start_cursor: u32,
    primary: bool,
};

pub const BufferVtbl = extern struct {
    QueryInterface: *const fn (*anyopaque, ?*const Guid, ?*?*anyopaque) callconv(W) HRESULT,
    AddRef: *const fn (*anyopaque) callconv(W) u32,
    Release: *const fn (*anyopaque) callconv(W) u32,
    GetCaps: *const fn (*anyopaque, ?*DSCBCAPS) callconv(W) HRESULT,
    GetCurrentPosition: *const fn (*anyopaque, ?*u32, ?*u32) callconv(W) HRESULT,
    GetFormat: *const fn (*anyopaque, ?*WAVEFORMATEX, u32, ?*u32) callconv(W) HRESULT,
    GetVolume: *const fn (*anyopaque, ?*i32) callconv(W) HRESULT,
    GetPan: *const fn (*anyopaque, ?*i32) callconv(W) HRESULT,
    GetFrequency: *const fn (*anyopaque, ?*u32) callconv(W) HRESULT,
    GetStatus: *const fn (*anyopaque, ?*u32) callconv(W) HRESULT,
    Initialize: *const fn (*anyopaque, ?*anyopaque, ?*DSBUFFERDESC) callconv(W) HRESULT,
    Lock: *const fn (*anyopaque, u32, u32, ?*?*anyopaque, ?*u32, ?*?*anyopaque, ?*u32, u32) callconv(W) HRESULT,
    Play: *const fn (*anyopaque, u32, u32, u32) callconv(W) HRESULT,
    SetCurrentPosition: *const fn (*anyopaque, u32) callconv(W) HRESULT,
    SetFormat: *const fn (*anyopaque, ?*WAVEFORMATEX) callconv(W) HRESULT,
    SetVolume: *const fn (*anyopaque, i32) callconv(W) HRESULT,
    SetPan: *const fn (*anyopaque, i32) callconv(W) HRESULT,
    SetFrequency: *const fn (*anyopaque, u32) callconv(W) HRESULT,
    Stop: *const fn (*anyopaque) callconv(W) HRESULT,
    Unlock: *const fn (*anyopaque, ?*anyopaque, u32, ?*anyopaque, u32) callconv(W) HRESULT,
    Restore: *const fn (*anyopaque) callconv(W) HRESULT,
    // IDirectSoundBuffer8
    SetFX: *const fn (*anyopaque, u32, ?*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    AcquireResources: *const fn (*anyopaque, u32, u32, u32, ?*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    GetObjectInPath: *const fn (*anyopaque, ?*const Guid, u32, u32, ?*const Guid, u32, ?*?*anyopaque) callconv(W) HRESULT,
};

fn bufBytes(self: *Buffer) u32 {
    return self.buf_len;
}

/// Monotonic milliseconds from the same syscall the rest of the loader uses
/// (std.time.milliTimestamp is gone in Zig 0.16).
fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
    return @as(i64, @intCast(ts.sec)) * 1000 + @divTrunc(@as(i64, @intCast(ts.nsec)), 1_000_000);
}

fn bufRate(self: *Buffer) u32 {
    return if (self.wfx.nAvgBytesPerSec != 0) self.wfx.nAvgBytesPerSec else 44100 * 4;
}

fn bufCursor(self: *Buffer) u32 {
    const rate = bufRate(self);
    const len = bufBytes(self);
    if (len == 0) return 0;
    if (!self.playing) return self.start_cursor % len;
    const elapsed: i64 = nowMs() - self.start_ms;
    if (elapsed <= 0) return self.start_cursor % len;
    const advanced: u64 = @as(u64, @intCast(elapsed)) * @as(u64, rate) / 1000;
    var pos: u64 = @as(u64, self.start_cursor) + advanced;
    if (self.looping) {
        pos %= len;
    } else if (pos >= len) {
        self.playing = false;
        return len - 1;
    }
    return @intCast(pos);
}

fn bufQueryInterface(p: *anyopaque, iid: ?*const Guid, out: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *Buffer = @ptrCast(@alignCast(p));
    const o = out orelse return E_INVALIDARG;
    if (accepts(&IID_IDirectSoundBuffer8, iid) or accepts(&IID_IDirectSoundBuffer, iid)) {
        self.refs += 1;
        o.* = p;
        return S_OK;
    }
    o.* = null;
    return E_NOINTERFACE;
}

fn bufAddRef(p: *anyopaque) callconv(W) u32 {
    const self: *Buffer = @ptrCast(@alignCast(p));
    self.refs += 1;
    return self.refs;
}

fn poolIndexOf(self: *Buffer) ?usize {
    const base = @intFromPtr(&pool[0]);
    const addr = @intFromPtr(self);
    if (addr < base) return null;
    const idx = (addr - base) / @sizeOf(Buffer);
    if (idx >= POOL_MAX) return null;
    return idx;
}

fn bufRelease(p: *anyopaque) callconv(W) u32 {
    const self: *Buffer = @ptrCast(@alignCast(p));
    if (self.refs > 0) self.refs -= 1;
    if (self.refs != 0) return self.refs;
    if (self.buf_ptr) |ptr| {
        if (self.buf_len != 0) std.heap.page_allocator.free(ptr[0..self.buf_len]);
    }
    self.buf_ptr = null;
    self.buf_len = 0;
    self.playing = false;
    self.looping = false;
    if (poolIndexOf(self)) |idx| pool_used[idx] = false;
    return 0;
}

fn bufGetCaps(p: *anyopaque, caps: ?*DSCBCAPS) callconv(W) HRESULT {
    const self: *Buffer = @ptrCast(@alignCast(p));
    const c = caps orelse return E_INVALIDARG;
    if (c.dwSize < @sizeOf(DSCBCAPS)) return E_INVALIDARG;
    c.dwFlags = self.flags;
    c.dwBufferBytes = bufBytes(self);
    c.dwReserved = 0;
    return S_OK;
}

fn bufGetCurrentPosition(p: *anyopaque, play: ?*u32, write: ?*u32) callconv(W) HRESULT {
    const self: *Buffer = @ptrCast(@alignCast(p));
    const cur = bufCursor(self);
    if (play) |q| q.* = cur;
    if (write) |q| q.* = cur;
    return S_OK;
}

fn bufGetFormat(p: *anyopaque, wfx: ?*WAVEFORMATEX, size: u32, written: ?*u32) callconv(W) HRESULT {
    const self: *Buffer = @ptrCast(@alignCast(p));
    const dest = wfx orelse return E_INVALIDARG;
    if (size < @sizeOf(WAVEFORMATEX)) return E_INVALIDARG;
    dest.* = self.wfx;
    if (written) |q| q.* = @sizeOf(WAVEFORMATEX);
    return S_OK;
}

fn bufGetVolume(p: *anyopaque, v: ?*i32) callconv(W) HRESULT {
    const self: *Buffer = @ptrCast(@alignCast(p));
    const q = v orelse return E_INVALIDARG;
    q.* = self.volume;
    return S_OK;
}

fn bufGetPan(p: *anyopaque, v: ?*i32) callconv(W) HRESULT {
    const self: *Buffer = @ptrCast(@alignCast(p));
    const q = v orelse return E_INVALIDARG;
    q.* = self.pan;
    return S_OK;
}

fn bufGetFrequency(p: *anyopaque, v: ?*u32) callconv(W) HRESULT {
    const self: *Buffer = @ptrCast(@alignCast(p));
    const q = v orelse return E_INVALIDARG;
    q.* = if (self.frequency != 0) self.frequency else self.wfx.nSamplesPerSec;
    return S_OK;
}

fn bufGetStatus(p: *anyopaque, status: ?*u32) callconv(W) HRESULT {
    const self: *Buffer = @ptrCast(@alignCast(p));
    const q = status orelse return E_INVALIDARG;
    var s: u32 = 0;
    if (self.playing) s |= DSBSTATUS_PLAYING;
    if (self.playing and self.looping) s |= DSBSTATUS_LOOPING;
    q.* = s;
    return S_OK;
}

fn bufInitialize(p: *anyopaque, ds: ?*anyopaque, desc: ?*DSBUFFERDESC) callconv(W) HRESULT {
    _ = ds;
    const self: *Buffer = @ptrCast(@alignCast(p));
    const d = desc orelse return E_INVALIDARG;
    if (self.buf_len != 0) return DSERR_INVALIDCALL;
    return bufAlloc(self, d);
}

fn bufLock(
    p: *anyopaque,
    offset: u32,
    bytes: u32,
    ptr1: ?*?*anyopaque,
    len1: ?*u32,
    ptr2: ?*?*anyopaque,
    len2: ?*u32,
    flags: u32,
) callconv(W) HRESULT {
    const self: *Buffer = @ptrCast(@alignCast(p));
    const total = bufBytes(self);
    if (total == 0) return DSERR_UNSUPPORTED;
    const ptr = self.buf_ptr orelse return DSERR_UNSUPPORTED;
    const a = ptr1 orelse return E_INVALIDARG;
    const b = len1 orelse return E_INVALIDARG;

    var start = offset;
    if ((flags & DSBLOCK_FROMWRITECURSOR) != 0) start = bufCursor(self);
    var count = bytes;
    if ((flags & DSBLOCK_ENTIREBUFFER) != 0) {
        start = 0;
        count = total;
    }
    if (count == 0) count = total;
    if (start >= total) start %= total;
    if (count > total) count = total;

    const first: u32 = @min(count, total - start);
    a.* = @ptrCast(ptr + start);
    b.* = first;
    if (ptr2) |c| {
        if (len2) |d| {
            if (first < count) {
                c.* = @ptrCast(ptr);
                d.* = count - first;
            } else {
                c.* = null;
                d.* = 0;
            }
        }
    }
    return S_OK;
}

fn bufPlay(p: *anyopaque, reserved1: u32, priority: u32, flags: u32) callconv(W) HRESULT {
    _ = reserved1;
    _ = priority;
    const self: *Buffer = @ptrCast(@alignCast(p));
    if (self.buf_len == 0) return DSERR_UNSUPPORTED;
    if (!self.playing) {
        self.start_cursor = bufCursor(self);
        self.start_ms = nowMs();
        self.playing = true;
    }
    self.looping = (flags & DSBPLAY_LOOPING) != 0;
    return S_OK;
}

fn bufSetCurrentPosition(p: *anyopaque, pos: u32) callconv(W) HRESULT {
    const self: *Buffer = @ptrCast(@alignCast(p));
    const total = bufBytes(self);
    if (total == 0) return DSERR_UNSUPPORTED;
    self.start_cursor = pos % total;
    self.start_ms = nowMs();
    return S_OK;
}

fn bufSetFormat(p: *anyopaque, wfx: ?*WAVEFORMATEX) callconv(W) HRESULT {
    const self: *Buffer = @ptrCast(@alignCast(p));
    const src = wfx orelse return E_INVALIDARG;
    if (!self.primary) return DSERR_INVALIDCALL; // only the primary buffer may change format
    if (src.nChannels == 0 or src.nSamplesPerSec == 0) return E_INVALIDARG;
    self.wfx = src.*;
    return S_OK;
}

fn bufSetVolume(p: *anyopaque, v: i32) callconv(W) HRESULT {
    const self: *Buffer = @ptrCast(@alignCast(p));
    if (v > 0 or v < -10000) return E_INVALIDARG;
    self.volume = v;
    return S_OK;
}

fn bufSetPan(p: *anyopaque, v: i32) callconv(W) HRESULT {
    const self: *Buffer = @ptrCast(@alignCast(p));
    if (v > 10000 or v < -10000) return E_INVALIDARG;
    self.pan = v;
    return S_OK;
}

fn bufSetFrequency(p: *anyopaque, v: u32) callconv(W) HRESULT {
    const self: *Buffer = @ptrCast(@alignCast(p));
    if (v == 0) return E_INVALIDARG;
    self.frequency = v;
    return S_OK;
}

fn bufStop(p: *anyopaque) callconv(W) HRESULT {
    const self: *Buffer = @ptrCast(@alignCast(p));
    self.playing = false;
    self.looping = false;
    return S_OK;
}

fn bufUnlock(p: *anyopaque, ptr1: ?*anyopaque, len1: u32, ptr2: ?*anyopaque, len2: u32) callconv(W) HRESULT {
    _ = p;
    // Memory-backed buffers need no copy-back, but a mismatched pair is a real
    // error the caller would rely on being reported.
    if (len1 != 0 and ptr1 == null) return E_INVALIDARG;
    if (len2 != 0 and ptr2 == null) return E_INVALIDARG;
    return S_OK;
}

fn bufRestore(p: *anyopaque) callconv(W) HRESULT {
    _ = p;
    return S_OK;
}

fn bufSetFX(p: *anyopaque, count: u32, descs: ?*anyopaque, results: ?*anyopaque) callconv(W) HRESULT {
    _ = p;
    _ = count;
    _ = descs;
    _ = results;
    return E_NOTIMPL;
}

fn bufAcquireResources(p: *anyopaque, flags: u32, count: u32, index: u32, found: ?*anyopaque, aff: ?*anyopaque) callconv(W) HRESULT {
    _ = p;
    _ = flags;
    _ = count;
    _ = index;
    _ = found;
    _ = aff;
    return E_NOTIMPL;
}

fn bufGetObjectInPath(p: *anyopaque, rguid: ?*const Guid, index: u32, path: u32, iid: ?*const Guid, size: u32, obj: ?*?*anyopaque) callconv(W) HRESULT {
    _ = p;
    _ = rguid;
    _ = index;
    _ = path;
    _ = iid;
    _ = size;
    if (obj) |o| o.* = null;
    return E_NOTIMPL;
}

const buffer_vtbl = BufferVtbl{
    .QueryInterface = bufQueryInterface,
    .AddRef = bufAddRef,
    .Release = bufRelease,
    .GetCaps = bufGetCaps,
    .GetCurrentPosition = bufGetCurrentPosition,
    .GetFormat = bufGetFormat,
    .GetVolume = bufGetVolume,
    .GetPan = bufGetPan,
    .GetFrequency = bufGetFrequency,
    .GetStatus = bufGetStatus,
    .Initialize = bufInitialize,
    .Lock = bufLock,
    .Play = bufPlay,
    .SetCurrentPosition = bufSetCurrentPosition,
    .SetFormat = bufSetFormat,
    .SetVolume = bufSetVolume,
    .SetPan = bufSetPan,
    .SetFrequency = bufSetFrequency,
    .Stop = bufStop,
    .Unlock = bufUnlock,
    .Restore = bufRestore,
    .SetFX = bufSetFX,
    .AcquireResources = bufAcquireResources,
    .GetObjectInPath = bufGetObjectInPath,
};

// A fixed pool: DirectSound apps create a bounded number of buffers, and a pool
// keeps every object at a stable address for the life of the process.
const POOL_MAX = 256;
var pool: [POOL_MAX]Buffer = undefined;
var pool_used: [POOL_MAX]bool = [_]bool{false} ** POOL_MAX;

fn poolTake() ?*Buffer {
    for (&pool, 0..) |*slot, i| {
        if (!pool_used[i]) {
            pool_used[i] = true;
            slot.* = std.mem.zeroes(Buffer);
            slot.vtbl = &buffer_vtbl;
            slot.refs = 1;
            return slot;
        }
    }
    return null;
}

fn bufAlloc(self: *Buffer, desc: *DSBUFFERDESC) HRESULT {
    self.flags = desc.dwFlags;
    self.primary = (desc.dwFlags & DSBCAPS_PRIMARYBUFFER) != 0;
    if (desc.lpwfxFormat) |fmt| self.wfx = fmt.*;
    const wanted: usize = if (self.primary)
        // The primary buffer mixes the whole device: give it a real ring that a
        // future mixer can point at, sized from its format (100 ms).
        @max(@as(usize, bufRate(self)) / 10, 4096)
    else if (desc.dwBufferBytes != 0)
        desc.dwBufferBytes
    else
        65536;
    const mem = std.heap.page_allocator.alloc(u8, wanted) catch return E_OUTOFMEMORY;
    self.buf_ptr = mem.ptr;
    self.buf_len = @intCast(mem.len);
    @memset(mem, 0);
    return S_OK;
}

// ---------------------------------------------------------------------------
// Device object (IDirectSound8)
// ---------------------------------------------------------------------------

pub const Device = extern struct {
    vtbl: *const DeviceVtbl,
    refs: u32,
    cooperative: u32,
    hwnd: usize,
    speaker_config: u32, // 0 = DSSPEAKER_CONFIG with stereo
};

pub const DeviceVtbl = extern struct {
    QueryInterface: *const fn (*anyopaque, ?*const Guid, ?*?*anyopaque) callconv(W) HRESULT,
    AddRef: *const fn (*anyopaque) callconv(W) u32,
    Release: *const fn (*anyopaque) callconv(W) u32,
    CreateSoundBuffer: *const fn (*anyopaque, ?*DSBUFFERDESC, ?*?*anyopaque, ?*anyopaque) callconv(W) HRESULT,
    GetCaps: *const fn (*anyopaque, ?*DSCAPS) callconv(W) HRESULT,
    DuplicateSoundBuffer: *const fn (*anyopaque, ?*anyopaque, ?*?*anyopaque) callconv(W) HRESULT,
    SetCooperativeLevel: *const fn (*anyopaque, usize, u32) callconv(W) HRESULT,
    Compact: *const fn (*anyopaque) callconv(W) HRESULT,
    GetSpeakerConfig: *const fn (*anyopaque, ?*u32) callconv(W) HRESULT,
    SetSpeakerConfig: *const fn (*anyopaque, u32) callconv(W) HRESULT,
    Initialize: *const fn (*anyopaque, ?*const Guid) callconv(W) HRESULT,
    VerifyCertification: *const fn (*anyopaque, ?*u32) callconv(W) HRESULT,
};

fn devQueryInterface(p: *anyopaque, iid: ?*const Guid, out: ?*?*anyopaque) callconv(W) HRESULT {
    const self: *Device = @ptrCast(@alignCast(p));
    const o = out orelse return E_INVALIDARG;
    if (accepts(&IID_IDirectSound8, iid) or accepts(&IID_IDirectSound, iid)) {
        self.refs += 1;
        o.* = p;
        return S_OK;
    }
    o.* = null;
    return E_NOINTERFACE;
}

fn devAddRef(p: *anyopaque) callconv(W) u32 {
    const self: *Device = @ptrCast(@alignCast(p));
    self.refs += 1;
    return self.refs;
}

fn devRelease(p: *anyopaque) callconv(W) u32 {
    const self: *Device = @ptrCast(@alignCast(p));
    if (self.refs > 0) self.refs -= 1;
    return self.refs;
}

fn devCreateSoundBuffer(p: *anyopaque, desc: ?*DSBUFFERDESC, out: ?*?*anyopaque, outer: ?*anyopaque) callconv(W) HRESULT {
    _ = p;
    if (outer != null) return DSERR_INVALIDCALL;
    const d = desc orelse return E_INVALIDARG;
    const o = out orelse return E_INVALIDARG;
    if (d.dwSize < 36) return E_INVALIDARG;
    if ((d.dwFlags & DSBCAPS_PRIMARYBUFFER) == 0 and d.lpwfxFormat == null) return E_INVALIDARG;
    const slot = poolTake() orelse return E_OUTOFMEMORY;
    const hr = bufAlloc(slot, d);
    if (hr != S_OK) {
        if (poolIndexOf(slot)) |idx| pool_used[idx] = false;
        return hr;
    }
    o.* = @ptrCast(slot);
    return S_OK;
}

fn devGetCaps(p: *anyopaque, caps: ?*DSCAPS) callconv(W) HRESULT {
    _ = p;
    const c = caps orelse return E_INVALIDARG;
    const declared: usize = @min(@as(usize, c.dwSize), @sizeOf(DSCAPS));
    if (declared < 8) return E_INVALIDARG;
    const raw: [*]u8 = @ptrCast(c);
    @memset(raw[8..declared], 0);
    c.dwFlags = DSCAPS_PRIMARYSTEREO | DSCAPS_PRIMARY16BIT | DSCAPS_SECONDARYSTEREO | DSCAPS_SECONDARY16BIT;
    c.dwMinSecondarySampleRate = 8000;
    c.dwMaxSecondarySampleRate = 192000;
    c.dwPrimaryBuffers = 1;
    c.dwMaxHwMixingAllBuffers = 32;
    c.dwMaxHwMixingStaticBuffers = 32;
    c.dwMaxHwMixingStreamingBuffers = 32;
    c.dwFreeHwMixingAllBuffers = 32;
    c.dwFreeHwMixingStaticBuffers = 32;
    c.dwFreeHwMixingStreamingBuffers = 32;
    return S_OK;
}

fn devDuplicateSoundBuffer(p: *anyopaque, src: ?*anyopaque, out: ?*?*anyopaque) callconv(W) HRESULT {
    _ = p;
    if (src == null or out == null) return E_INVALIDARG;
    return E_NOTIMPL;
}

fn devSetCooperativeLevel(p: *anyopaque, hwnd: usize, level: u32) callconv(W) HRESULT {
    const self: *Device = @ptrCast(@alignCast(p));
    self.hwnd = hwnd;
    self.cooperative = level;
    return S_OK;
}

fn devCompact(p: *anyopaque) callconv(W) HRESULT {
    _ = p;
    return S_OK;
}

fn devGetSpeakerConfig(p: *anyopaque, cfg: ?*u32) callconv(W) HRESULT {
    const self: *Device = @ptrCast(@alignCast(p));
    const q = cfg orelse return E_INVALIDARG;
    q.* = self.speaker_config;
    return S_OK;
}

fn devSetSpeakerConfig(p: *anyopaque, cfg: u32) callconv(W) HRESULT {
    const self: *Device = @ptrCast(@alignCast(p));
    self.speaker_config = cfg;
    return S_OK;
}

fn devInitialize(p: *anyopaque, guid: ?*const Guid) callconv(W) HRESULT {
    _ = p;
    _ = guid;
    return E_NOTIMPL;
}

fn devVerifyCertification(p: *anyopaque, cert: ?*u32) callconv(W) HRESULT {
    _ = p;
    const q = cert orelse return E_INVALIDARG;
    q.* = 1; // DS_CERTIFIED
    return S_OK;
}

const device_vtbl = DeviceVtbl{
    .QueryInterface = devQueryInterface,
    .AddRef = devAddRef,
    .Release = devRelease,
    .CreateSoundBuffer = devCreateSoundBuffer,
    .GetCaps = devGetCaps,
    .DuplicateSoundBuffer = devDuplicateSoundBuffer,
    .SetCooperativeLevel = devSetCooperativeLevel,
    .Compact = devCompact,
    .GetSpeakerConfig = devGetSpeakerConfig,
    .SetSpeakerConfig = devSetSpeakerConfig,
    .Initialize = devInitialize,
    .VerifyCertification = devVerifyCertification,
};

var device: Device = .{
    .vtbl = &device_vtbl,
    .refs = 1,
    .cooperative = 0,
    .hwnd = 0,
    .speaker_config = 0,
};

fn makeDevice(out: ?*?*anyopaque, outer: ?*anyopaque) HRESULT {
    if (outer != null) return DSERR_INVALIDCALL;
    const o = out orelse return E_INVALIDARG;
    device.refs += 1;
    o.* = @ptrCast(&device);
    return S_OK;
}

// ---------------------------------------------------------------------------
// Exported entry points (stdcall, as dsound.dll exports them)
// ---------------------------------------------------------------------------

fn DirectSoundCreate(guid: ?*const Guid, out: ?*?*anyopaque, outer: ?*anyopaque) callconv(W) HRESULT {
    _ = guid;
    return makeDevice(out, outer);
}

fn DirectSoundCreate8(guid: ?*const Guid, out: ?*?*anyopaque, outer: ?*anyopaque) callconv(W) HRESULT {
    _ = guid;
    return makeDevice(out, outer);
}

fn DirectSoundCaptureCreate(guid: ?*const Guid, out: ?*?*anyopaque, outer: ?*anyopaque) callconv(W) HRESULT {
    _ = guid;
    _ = outer;
    if (out) |o| o.* = null;
    return DSERR_NODRIVER;
}

fn DirectSoundCaptureCreate8(guid: ?*const Guid, out: ?*?*anyopaque, outer: ?*anyopaque) callconv(W) HRESULT {
    return DirectSoundCaptureCreate(guid, out, outer);
}

fn DirectSoundFullDuplexCreate(
    capture: ?*const Guid,
    render: ?*const Guid,
    caps: ?*anyopaque,
    effect: ?*anyopaque,
    hwnd: usize,
    level: u32,
    ds_out: ?*?*anyopaque,
    cap_out: ?*?*anyopaque,
    outer: ?*anyopaque,
) callconv(W) HRESULT {
    _ = capture;
    _ = render;
    _ = caps;
    _ = effect;
    _ = hwnd;
    _ = level;
    _ = outer;
    if (ds_out) |o| o.* = null;
    if (cap_out) |o| o.* = null;
    return DSERR_NODRIVER;
}

// DSENUMCALLBACKA: BOOL (CALLBACK *)(LPGUID, LPCSTR description, LPCSTR module, LPVOID ctx)
// DSENUMCALLBACKW: the same with LPCWSTR. Four parameters, not three.
const EnumerateProc = *const fn (?*const Guid, ?[*:0]const u8, ?[*:0]const u8, ?*anyopaque) callconv(W) i32;
const EnumerateProcW = *const fn (?*const Guid, ?[*:0]const u16, ?[*:0]const u16, ?*anyopaque) callconv(W) i32;

const wide_device_name: [16:0]u16 = .{
    'W', 'I', 'N', 'S', ' ', 'D', 'i', 'r', 'e', 'c', 't', 'S', 'o', 'u', 'n', 'd',
};

fn DirectSoundEnumerateA(cb: ?EnumerateProc, ctx: ?*anyopaque) callconv(W) HRESULT {
    const f = cb orelse return E_INVALIDARG;
    // One device, no GUID (the default device), then the terminating null entry.
    _ = f(null, "WINS DirectSound", null, ctx);
    _ = f(null, null, null, ctx);
    return S_OK;
}

fn DirectSoundEnumerateW(cb: ?EnumerateProcW, ctx: ?*anyopaque) callconv(W) HRESULT {
    const f = cb orelse return E_INVALIDARG;
    _ = f(null, &wide_device_name, null, ctx);
    _ = f(null, null, null, ctx);
    return S_OK;
}

fn DirectSoundCaptureEnumerateA(cb: ?EnumerateProc, ctx: ?*anyopaque) callconv(W) HRESULT {
    _ = cb;
    _ = ctx;
    return S_OK; // no capture device: an empty enumeration is the honest answer
}

fn DirectSoundCaptureEnumerateW(cb: ?EnumerateProcW, ctx: ?*anyopaque) callconv(W) HRESULT {
    _ = cb;
    _ = ctx;
    return S_OK;
}

fn GetDeviceID(guid_src: ?*const Guid, guid_out: ?*Guid) callconv(W) HRESULT {
    _ = guid_src;
    const o = guid_out orelse return E_INVALIDARG;
    o.* = .{ .data1 = 0, .data2 = 0, .data3 = 0, .data4 = [_]u8{0} ** 8 };
    return DSERR_NODRIVER;
}

fn DllCanUnloadNow() callconv(W) HRESULT {
    return S_FALSE;
}

fn DllRegisterServer() callconv(W) HRESULT {
    return S_OK;
}

fn DllUnregisterServer() callconv(W) HRESULT {
    return S_OK;
}

fn DllGetClassObject(rclsid: ?*const Guid, riid: ?*const Guid, out: ?*?*anyopaque) callconv(W) HRESULT {
    _ = rclsid;
    _ = riid;
    if (out) |o| o.* = null;
    return E_NOTIMPL;
}

/// Resolve a dsound export by name. Mirrors the other shim modules: the loader
/// asks, this answers with the address or null, and nothing is fabricated.
pub fn lookupDsound(name: []const u8) ?usize {
    const table = .{
        .{ "DirectSoundCreate", &DirectSoundCreate },
        .{ "DirectSoundCreate8", &DirectSoundCreate8 },
        .{ "DirectSoundCaptureCreate", &DirectSoundCaptureCreate },
        .{ "DirectSoundCaptureCreate8", &DirectSoundCaptureCreate8 },
        .{ "DirectSoundFullDuplexCreate", &DirectSoundFullDuplexCreate },
        .{ "DirectSoundEnumerateA", &DirectSoundEnumerateA },
        .{ "DirectSoundEnumerateW", &DirectSoundEnumerateW },
        .{ "DirectSoundCaptureEnumerateA", &DirectSoundCaptureEnumerateA },
        .{ "DirectSoundCaptureEnumerateW", &DirectSoundCaptureEnumerateW },
        .{ "GetDeviceID", &GetDeviceID },
        .{ "DllCanUnloadNow", &DllCanUnloadNow },
        .{ "DllGetClassObject", &DllGetClassObject },
        .{ "DllRegisterServer", &DllRegisterServer },
        .{ "DllUnregisterServer", &DllUnregisterServer },
    };
    inline for (table) |entry| {
        if (std.mem.eql(u8, name, entry[0])) return @intFromPtr(entry[1]);
    }
    return null;
}
