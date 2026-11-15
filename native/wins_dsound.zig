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
// {6825A449-7524-4D82-920F-50E36AB3AB1E} (dsound.h). The tail used to be
// mistyped, so a correct QueryInterface for IDirectSoundBuffer8 was refused
// and FalloutNV dereferenced the NULL it got back (0xaecc16).
const IID_IDirectSoundBuffer8 = Guid{ .data1 = 0x6825A449, .data2 = 0x7524, .data3 = 0x4D82, .data4 = .{ 0x92, 0x0F, 0x50, 0xE3, 0x6A, 0xB3, 0xAB, 0x1E } };

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
    /// IDirectSound3DListener (primary buffers) / IDirectSound3DBuffer
    /// (secondary buffers created with DSBCAPS_CTRL3D): a second interface
    /// of the same object, sharing its reference count.
    i3d: Sub3D,
};

/// The 3D interface of a buffer. Parameters are stored and answered as set;
/// positional mixing is not done (there is no mixer output yet).
pub const Sub3D = extern struct {
    vtbl: ?*const anyopaque,
    owner: ?*Buffer,
    // DS3DLISTENER / DS3DBUFFER without dwSize, as 32-bit words.
    words: [15]u32,
};

const IID_IDirectSound3DListener = Guid{ .data1 = 0x279AFA84, .data2 = 0x4981, .data3 = 0x11CE, .data4 = .{ 0xA5, 0x21, 0x00, 0x20, 0xAF, 0x0B, 0xE5, 0x60 } };
const IID_IDirectSound3DBuffer = Guid{ .data1 = 0x279AFA86, .data2 = 0x4981, .data3 = 0x11CE, .data4 = .{ 0xA5, 0x21, 0x00, 0x20, 0xAF, 0x0B, 0xE5, 0x60 } };

fn subOf(p: *anyopaque) *Sub3D {
    return @ptrCast(@alignCast(p));
}
fn s3QueryInterface(p: *anyopaque, iid: ?*const Guid, out: ?*?*anyopaque) callconv(W) HRESULT {
    return bufQueryInterface(subOf(p).owner.?, iid, out);
}
fn s3AddRef(p: *anyopaque) callconv(W) u32 {
    return bufAddRef(subOf(p).owner.?);
}
fn s3Release(p: *anyopaque) callconv(W) u32 {
    return bufRelease(subOf(p).owner.?);
}
fn putVec(dst: ?*[3]f32, src: []const u32) HRESULT {
    const d = dst orelse return E_INVALIDARG;
    for (0..3) |i| d[i] = @bitCast(src[i]);
    return S_OK;
}
fn putF(dst: ?*f32, w: u32) HRESULT {
    (dst orelse return E_INVALIDARG).* = @bitCast(w);
    return S_OK;
}
fn setVec(sub: *Sub3D, at: usize, x: f32, y: f32, z: f32) HRESULT {
    sub.words[at] = @bitCast(x);
    sub.words[at + 1] = @bitCast(y);
    sub.words[at + 2] = @bitCast(z);
    return S_OK;
}
fn getAll(sub: *Sub3D, out: ?[*]u32) HRESULT {
    const o = out orelse return E_INVALIDARG;
    if (o[0] < 64) return E_INVALIDARG;
    @memcpy(o[1..16], &sub.words);
    return S_OK;
}
fn setAll(sub: *Sub3D, in: ?[*]const u32) HRESULT {
    const i = in orelse return E_INVALIDARG;
    if (i[0] < 64) return E_INVALIDARG;
    @memcpy(&sub.words, i[1..16]);
    return S_OK;
}

// Listener layout (words): position 0..2, velocity 3..5, front 6..8, top 9..11,
// distance factor 12, rolloff 13, doppler 14.
fn lGetAll(p: *anyopaque, o: ?[*]u32) callconv(W) HRESULT {
    return getAll(subOf(p), o);
}
fn lGetDistance(p: *anyopaque, o: ?*f32) callconv(W) HRESULT {
    return putF(o, subOf(p).words[12]);
}
fn lGetDoppler(p: *anyopaque, o: ?*f32) callconv(W) HRESULT {
    return putF(o, subOf(p).words[14]);
}
fn lGetOrientation(p: *anyopaque, front: ?*[3]f32, top: ?*[3]f32) callconv(W) HRESULT {
    const s = subOf(p);
    const r = putVec(front, s.words[6..9]);
    if (r != S_OK) return r;
    return putVec(top, s.words[9..12]);
}
fn lGetPosition(p: *anyopaque, o: ?*[3]f32) callconv(W) HRESULT {
    return putVec(o, subOf(p).words[0..3]);
}
fn lGetRolloff(p: *anyopaque, o: ?*f32) callconv(W) HRESULT {
    return putF(o, subOf(p).words[13]);
}
fn lGetVelocity(p: *anyopaque, o: ?*[3]f32) callconv(W) HRESULT {
    return putVec(o, subOf(p).words[3..6]);
}
fn lSetAll(p: *anyopaque, i: ?[*]const u32, apply: u32) callconv(W) HRESULT {
    _ = apply;
    return setAll(subOf(p), i);
}
fn lSetDistance(p: *anyopaque, v: f32, apply: u32) callconv(W) HRESULT {
    _ = apply;
    subOf(p).words[12] = @bitCast(v);
    return S_OK;
}
fn lSetDoppler(p: *anyopaque, v: f32, apply: u32) callconv(W) HRESULT {
    _ = apply;
    subOf(p).words[14] = @bitCast(v);
    return S_OK;
}
fn lSetOrientation(p: *anyopaque, fx: f32, fy: f32, fz: f32, tx: f32, ty: f32, tz: f32, apply: u32) callconv(W) HRESULT {
    _ = apply;
    _ = setVec(subOf(p), 6, fx, fy, fz);
    return setVec(subOf(p), 9, tx, ty, tz);
}
fn lSetPosition(p: *anyopaque, x: f32, y: f32, z: f32, apply: u32) callconv(W) HRESULT {
    _ = apply;
    return setVec(subOf(p), 0, x, y, z);
}
fn lSetRolloff(p: *anyopaque, v: f32, apply: u32) callconv(W) HRESULT {
    _ = apply;
    subOf(p).words[13] = @bitCast(v);
    return S_OK;
}
fn lSetVelocity(p: *anyopaque, x: f32, y: f32, z: f32, apply: u32) callconv(W) HRESULT {
    _ = apply;
    return setVec(subOf(p), 3, x, y, z);
}
fn s3Commit(p: *anyopaque) callconv(W) HRESULT {
    _ = p;
    return S_OK;
}
const listener_vtbl = [_]*const anyopaque{
    @ptrCast(&s3QueryInterface), @ptrCast(&s3AddRef),       @ptrCast(&s3Release),
    @ptrCast(&lGetAll),          @ptrCast(&lGetDistance),   @ptrCast(&lGetDoppler),
    @ptrCast(&lGetOrientation),  @ptrCast(&lGetPosition),   @ptrCast(&lGetRolloff),
    @ptrCast(&lGetVelocity),     @ptrCast(&lSetAll),        @ptrCast(&lSetDistance),
    @ptrCast(&lSetDoppler),      @ptrCast(&lSetOrientation), @ptrCast(&lSetPosition),
    @ptrCast(&lSetRolloff),      @ptrCast(&lSetVelocity),   @ptrCast(&s3Commit),
};

// 3D buffer layout (words): position 0..2, velocity 3..5, inside cone 6,
// outside cone 7, cone orientation 8..10, cone outside volume 11, min
// distance 12, max distance 13, mode 14.
fn bGetAll(p: *anyopaque, o: ?[*]u32) callconv(W) HRESULT {
    return getAll(subOf(p), o);
}
fn bGetConeAngles(p: *anyopaque, inside: ?*u32, outside: ?*u32) callconv(W) HRESULT {
    const s = subOf(p);
    if (inside) |x| x.* = s.words[6];
    if (outside) |x| x.* = s.words[7];
    return S_OK;
}
fn bGetConeOrientation(p: *anyopaque, o: ?*[3]f32) callconv(W) HRESULT {
    return putVec(o, subOf(p).words[8..11]);
}
fn bGetConeOutsideVolume(p: *anyopaque, o: ?*i32) callconv(W) HRESULT {
    (o orelse return E_INVALIDARG).* = @bitCast(subOf(p).words[11]);
    return S_OK;
}
fn bGetMaxDistance(p: *anyopaque, o: ?*f32) callconv(W) HRESULT {
    return putF(o, subOf(p).words[13]);
}
fn bGetMinDistance(p: *anyopaque, o: ?*f32) callconv(W) HRESULT {
    return putF(o, subOf(p).words[12]);
}
fn bGetMode(p: *anyopaque, o: ?*u32) callconv(W) HRESULT {
    (o orelse return E_INVALIDARG).* = subOf(p).words[14];
    return S_OK;
}
fn bGetPosition(p: *anyopaque, o: ?*[3]f32) callconv(W) HRESULT {
    return putVec(o, subOf(p).words[0..3]);
}
fn bGetVelocity(p: *anyopaque, o: ?*[3]f32) callconv(W) HRESULT {
    return putVec(o, subOf(p).words[3..6]);
}
fn bSetAll(p: *anyopaque, i: ?[*]const u32, apply: u32) callconv(W) HRESULT {
    _ = apply;
    return setAll(subOf(p), i);
}
fn bSetConeAngles(p: *anyopaque, inside: u32, outside: u32, apply: u32) callconv(W) HRESULT {
    _ = apply;
    subOf(p).words[6] = inside;
    subOf(p).words[7] = outside;
    return S_OK;
}
fn bSetConeOrientation(p: *anyopaque, x: f32, y: f32, z: f32, apply: u32) callconv(W) HRESULT {
    _ = apply;
    return setVec(subOf(p), 8, x, y, z);
}
fn bSetConeOutsideVolume(p: *anyopaque, v: i32, apply: u32) callconv(W) HRESULT {
    _ = apply;
    subOf(p).words[11] = @bitCast(v);
    return S_OK;
}
fn bSetMaxDistance(p: *anyopaque, v: f32, apply: u32) callconv(W) HRESULT {
    _ = apply;
    subOf(p).words[13] = @bitCast(v);
    return S_OK;
}
fn bSetMinDistance(p: *anyopaque, v: f32, apply: u32) callconv(W) HRESULT {
    _ = apply;
    subOf(p).words[12] = @bitCast(v);
    return S_OK;
}
fn bSetMode(p: *anyopaque, v: u32, apply: u32) callconv(W) HRESULT {
    _ = apply;
    subOf(p).words[14] = v;
    return S_OK;
}
fn bSetPosition(p: *anyopaque, x: f32, y: f32, z: f32, apply: u32) callconv(W) HRESULT {
    _ = apply;
    return setVec(subOf(p), 0, x, y, z);
}
fn bSetVelocity(p: *anyopaque, x: f32, y: f32, z: f32, apply: u32) callconv(W) HRESULT {
    _ = apply;
    return setVec(subOf(p), 3, x, y, z);
}
const buffer3d_vtbl = [_]*const anyopaque{
    @ptrCast(&s3QueryInterface),     @ptrCast(&s3AddRef),             @ptrCast(&s3Release),
    @ptrCast(&bGetAll),              @ptrCast(&bGetConeAngles),       @ptrCast(&bGetConeOrientation),
    @ptrCast(&bGetConeOutsideVolume), @ptrCast(&bGetMaxDistance),     @ptrCast(&bGetMinDistance),
    @ptrCast(&bGetMode),             @ptrCast(&bGetPosition),         @ptrCast(&bGetVelocity),
    @ptrCast(&bSetAll),              @ptrCast(&bSetConeAngles),       @ptrCast(&bSetConeOrientation),
    @ptrCast(&bSetConeOutsideVolume), @ptrCast(&bSetMaxDistance),     @ptrCast(&bSetMinDistance),
    @ptrCast(&bSetMode),             @ptrCast(&bSetPosition),         @ptrCast(&bSetVelocity),
};

/// DirectSound's defaults for a new listener / 3D buffer.
fn init3D(b: *Buffer) void {
    b.i3d = .{ .vtbl = null, .owner = b, .words = [_]u32{0} ** 15 };
    if (b.flags & DSBCAPS_CTRL3D == 0) return;
    if (b.primary) {
        b.i3d.vtbl = @ptrCast(&listener_vtbl);
        b.i3d.words[8] = @bitCast(@as(f32, 1.0)); // front (0,0,1) at 6..8
        b.i3d.words[10] = @bitCast(@as(f32, 1.0)); // top (0,1,0) at 9..11
        b.i3d.words[12] = @bitCast(@as(f32, 1.0)); // DS3D_DEFAULTDISTANCEFACTOR
        b.i3d.words[13] = @bitCast(@as(f32, 1.0)); // rolloff
        b.i3d.words[14] = @bitCast(@as(f32, 1.0)); // doppler
    } else {
        b.i3d.vtbl = @ptrCast(&buffer3d_vtbl);
        b.i3d.words[6] = 360; // DS3D_DEFAULTCONEANGLE
        b.i3d.words[7] = 360;
        b.i3d.words[10] = @bitCast(@as(f32, 1.0)); // cone orientation (0,0,1)
        b.i3d.words[12] = @bitCast(@as(f32, 1.0)); // DS3D_DEFAULTMINDISTANCE
        b.i3d.words[13] = @bitCast(@as(f32, 1000000000.0)); // DS3D_DEFAULTMAXDISTANCE
    }
}

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
    traceFirst(0, "bufQueryInterface", @returnAddress());
    const self: *Buffer = @ptrCast(@alignCast(p));
    const o = out orelse return E_INVALIDARG;
    if (accepts(&IID_IDirectSoundBuffer8, iid) or accepts(&IID_IDirectSoundBuffer, iid)) {
        self.refs += 1;
        o.* = p;
        return S_OK;
    }
    if (iid) |g| {
        const want_listener = g.eql(&IID_IDirectSound3DListener);
        const want_3d = g.eql(&IID_IDirectSound3DBuffer);
        if (self.i3d.vtbl != null and ((want_listener and self.primary) or (want_3d and !self.primary))) {
            self.refs += 1;
            o.* = @ptrCast(&self.i3d);
            return S_OK;
        }
    }
    o.* = null;
    if (iid) |g| logRefused("buffer", g);
    return E_NOINTERFACE;
}

var refused_logged: u32 = 0;
fn logRefused(what: []const u8, g: *const Guid) void {
    if (refused_logged >= 8) return;
    refused_logged += 1;
    std.debug.print("[WINS:DSound] {s} QueryInterface({x:0>8}-{x:0>4}-{x:0>4}-...) refused (E_NOINTERFACE)\n", .{ what, g.data1, g.data2, g.data3 });
}

var created_logged: u32 = 0;

fn bufAddRef(p: *anyopaque) callconv(W) u32 {
    traceFirst(1, "bufAddRef", @returnAddress());
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
    traceFirst(2, "bufRelease", @returnAddress());
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
    traceFirst(3, "bufGetCaps", @returnAddress());
    const self: *Buffer = @ptrCast(@alignCast(p));
    const c = caps orelse return E_INVALIDARG;
    if (c.dwSize < @sizeOf(DSCBCAPS)) return E_INVALIDARG;
    c.dwFlags = self.flags;
    c.dwBufferBytes = bufBytes(self);
    c.dwReserved = 0;
    return S_OK;
}

fn bufGetCurrentPosition(p: *anyopaque, play: ?*u32, write: ?*u32) callconv(W) HRESULT {
    traceFirst(4, "bufGetCurrentPosition", @returnAddress());
    const self: *Buffer = @ptrCast(@alignCast(p));
    const cur = bufCursor(self);
    if (play) |q| q.* = cur;
    if (write) |q| q.* = cur;
    return S_OK;
}

fn bufGetFormat(p: *anyopaque, wfx: ?*WAVEFORMATEX, size: u32, written: ?*u32) callconv(W) HRESULT {
    traceFirst(5, "bufGetFormat", @returnAddress());
    const self: *Buffer = @ptrCast(@alignCast(p));
    const dest = wfx orelse return E_INVALIDARG;
    if (size < @sizeOf(WAVEFORMATEX)) return E_INVALIDARG;
    dest.* = self.wfx;
    if (written) |q| q.* = @sizeOf(WAVEFORMATEX);
    return S_OK;
}

fn bufGetVolume(p: *anyopaque, v: ?*i32) callconv(W) HRESULT {
    traceFirst(6, "bufGetVolume", @returnAddress());
    const self: *Buffer = @ptrCast(@alignCast(p));
    const q = v orelse return E_INVALIDARG;
    q.* = self.volume;
    return S_OK;
}

fn bufGetPan(p: *anyopaque, v: ?*i32) callconv(W) HRESULT {
    traceFirst(7, "bufGetPan", @returnAddress());
    const self: *Buffer = @ptrCast(@alignCast(p));
    const q = v orelse return E_INVALIDARG;
    q.* = self.pan;
    return S_OK;
}

fn bufGetFrequency(p: *anyopaque, v: ?*u32) callconv(W) HRESULT {
    traceFirst(8, "bufGetFrequency", @returnAddress());
    const self: *Buffer = @ptrCast(@alignCast(p));
    const q = v orelse return E_INVALIDARG;
    q.* = if (self.frequency != 0) self.frequency else self.wfx.nSamplesPerSec;
    return S_OK;
}

fn bufGetStatus(p: *anyopaque, status: ?*u32) callconv(W) HRESULT {
    traceFirst(9, "bufGetStatus", @returnAddress());
    const self: *Buffer = @ptrCast(@alignCast(p));
    const q = status orelse return E_INVALIDARG;
    // The play cursor runs on the clock; a one-shot buffer that reached its
    // end has stopped even if nobody asked for the position since.
    _ = bufCursor(self);
    var s: u32 = 0;
    if (self.playing) s |= DSBSTATUS_PLAYING;
    if (self.playing and self.looping) s |= DSBSTATUS_LOOPING;
    q.* = s;
    return S_OK;
}

fn bufInitialize(p: *anyopaque, ds: ?*anyopaque, desc: ?*DSBUFFERDESC) callconv(W) HRESULT {
    traceFirst(10, "bufInitialize", @returnAddress());
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
    traceFirst(11, "bufPlay", @returnAddress());
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
    traceFirst(12, "bufSetCurrentPosition", @returnAddress());
    const self: *Buffer = @ptrCast(@alignCast(p));
    const total = bufBytes(self);
    if (total == 0) return DSERR_UNSUPPORTED;
    self.start_cursor = pos % total;
    self.start_ms = nowMs();
    return S_OK;
}

fn bufSetFormat(p: *anyopaque, wfx: ?*WAVEFORMATEX) callconv(W) HRESULT {
    traceFirst(13, "bufSetFormat", @returnAddress());
    const self: *Buffer = @ptrCast(@alignCast(p));
    const src = wfx orelse return E_INVALIDARG;
    if (!self.primary) return DSERR_INVALIDCALL; // only the primary buffer may change format
    if (src.nChannels == 0 or src.nSamplesPerSec == 0) return E_INVALIDARG;
    self.wfx = src.*;
    return S_OK;
}

fn bufSetVolume(p: *anyopaque, v: i32) callconv(W) HRESULT {
    traceFirst(14, "bufSetVolume", @returnAddress());
    const self: *Buffer = @ptrCast(@alignCast(p));
    if (v > 0 or v < -10000) return E_INVALIDARG;
    self.volume = v;
    return S_OK;
}

fn bufSetPan(p: *anyopaque, v: i32) callconv(W) HRESULT {
    traceFirst(15, "bufSetPan", @returnAddress());
    const self: *Buffer = @ptrCast(@alignCast(p));
    if (v > 10000 or v < -10000) return E_INVALIDARG;
    self.pan = v;
    return S_OK;
}

fn bufSetFrequency(p: *anyopaque, v: u32) callconv(W) HRESULT {
    traceFirst(16, "bufSetFrequency", @returnAddress());
    const self: *Buffer = @ptrCast(@alignCast(p));
    if (v == 0) return E_INVALIDARG;
    self.frequency = v;
    return S_OK;
}

fn bufStop(p: *anyopaque) callconv(W) HRESULT {
    traceFirst(17, "bufStop", @returnAddress());
    const self: *Buffer = @ptrCast(@alignCast(p));
    self.playing = false;
    self.looping = false;
    return S_OK;
}

fn bufUnlock(p: *anyopaque, ptr1: ?*anyopaque, len1: u32, ptr2: ?*anyopaque, len2: u32) callconv(W) HRESULT {
    traceFirst(18, "bufUnlock", @returnAddress());
    _ = p;
    // Memory-backed buffers need no copy-back, but a mismatched pair is a real
    // error the caller would rely on being reported.
    if (len1 != 0 and ptr1 == null) return E_INVALIDARG;
    if (len2 != 0 and ptr2 == null) return E_INVALIDARG;
    return S_OK;
}

fn bufRestore(p: *anyopaque) callconv(W) HRESULT {
    traceFirst(19, "bufRestore", @returnAddress());
    _ = p;
    return S_OK;
}

fn bufSetFX(p: *anyopaque, count: u32, descs: ?*anyopaque, results: ?*anyopaque) callconv(W) HRESULT {
    traceFirst(20, "bufSetFX", @returnAddress());
    _ = p;
    _ = count;
    _ = descs;
    _ = results;
    return E_NOTIMPL;
}

fn bufAcquireResources(p: *anyopaque, flags: u32, count: u32, index: u32, found: ?*anyopaque, aff: ?*anyopaque) callconv(W) HRESULT {
    traceFirst(21, "bufAcquireResources", @returnAddress());
    _ = p;
    _ = flags;
    _ = count;
    _ = index;
    _ = found;
    _ = aff;
    return E_NOTIMPL;
}

fn bufGetObjectInPath(p: *anyopaque, rguid: ?*const Guid, index: u32, path: u32, iid: ?*const Guid, size: u32, obj: ?*?*anyopaque) callconv(W) HRESULT {
    traceFirst(22, "bufGetObjectInPath", @returnAddress());
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
    traceFirst(23, "devQueryInterface", @returnAddress());
    const self: *Device = @ptrCast(@alignCast(p));
    const o = out orelse return E_INVALIDARG;
    if (accepts(&IID_IDirectSound8, iid) or accepts(&IID_IDirectSound, iid)) {
        self.refs += 1;
        o.* = p;
        return S_OK;
    }
    o.* = null;
    if (iid) |g| logRefused("device", g);
    return E_NOINTERFACE;
}

fn devAddRef(p: *anyopaque) callconv(W) u32 {
    traceFirst(24, "devAddRef", @returnAddress());
    const self: *Device = @ptrCast(@alignCast(p));
    self.refs += 1;
    return self.refs;
}

fn devRelease(p: *anyopaque) callconv(W) u32 {
    traceFirst(25, "devRelease", @returnAddress());
    const self: *Device = @ptrCast(@alignCast(p));
    if (self.refs > 0) self.refs -= 1;
    return self.refs;
}

fn devCreateSoundBuffer(p: *anyopaque, desc: ?*DSBUFFERDESC, out: ?*?*anyopaque, outer: ?*anyopaque) callconv(W) HRESULT {
    traceFirst(26, "devCreateSoundBuffer", @returnAddress());
    _ = p;
    if (outer != null) return DSERR_INVALIDCALL;
    const d = desc orelse return E_INVALIDARG;
    const o = out orelse return E_INVALIDARG;
    if (d.dwSize < 36) return E_INVALIDARG;
    if ((d.dwFlags & DSBCAPS_PRIMARYBUFFER) == 0 and d.lpwfxFormat == null) return E_INVALIDARG;
    const slot = poolTake() orelse {
        std.debug.print("[WINS:DSound] CreateSoundBuffer: all {d} buffers are in use; refused\n", .{POOL_MAX});
        return E_OUTOFMEMORY;
    };
    if (created_logged < 12) {
        created_logged += 1;
        const f = d.lpwfxFormat;
        std.debug.print("[WINS:DSound] CreateSoundBuffer(flags 0x{x}, {d} bytes, {d} Hz {d} ch {d} bit)\n", .{ d.dwFlags, d.dwBufferBytes, if (f) |x| x.nSamplesPerSec else 0, if (f) |x| x.nChannels else 0, if (f) |x| x.wBitsPerSample else 0 });
    }
    const hr = bufAlloc(slot, d);
    init3D(slot);
    if (hr != S_OK) {
        if (poolIndexOf(slot)) |idx| pool_used[idx] = false;
        return hr;
    }
    o.* = @ptrCast(slot);
    return S_OK;
}

fn devGetCaps(p: *anyopaque, caps: ?*DSCAPS) callconv(W) HRESULT {
    traceFirst(27, "devGetCaps", @returnAddress());
    _ = p;
    const c = caps orelse return E_INVALIDARG;
    const declared: usize = @min(@as(usize, c.dwSize), @sizeOf(DSCAPS));
    if (declared < 8) return E_INVALIDARG;
    const raw: [*]u8 = @ptrCast(c);
    @memset(raw[8..declared], 0);
    // What Proton's dsound answers on this machine (oracle probe dscaps.exe,
    // 2026-11-14): software mixing only, no hardware 3D voices.
    c.dwFlags = 0xF5F;
    c.dwMinSecondarySampleRate = 100;
    c.dwMaxSecondarySampleRate = 200000;
    c.dwPrimaryBuffers = 1;
    c.dwMaxHwMixingAllBuffers = 1;
    c.dwMaxHwMixingStaticBuffers = 1;
    c.dwMaxHwMixingStreamingBuffers = 1;
    return S_OK;
}

fn devDuplicateSoundBuffer(p: *anyopaque, src: ?*anyopaque, out: ?*?*anyopaque) callconv(W) HRESULT {
    traceFirst(28, "devDuplicateSoundBuffer", @returnAddress());
    _ = p;
    if (src == null or out == null) return E_INVALIDARG;
    return E_NOTIMPL;
}

fn devSetCooperativeLevel(p: *anyopaque, hwnd: usize, level: u32) callconv(W) HRESULT {
    traceFirst(29, "devSetCooperativeLevel", @returnAddress());
    const self: *Device = @ptrCast(@alignCast(p));
    self.hwnd = hwnd;
    self.cooperative = level;
    return S_OK;
}

fn devCompact(p: *anyopaque) callconv(W) HRESULT {
    traceFirst(30, "devCompact", @returnAddress());
    _ = p;
    return S_OK;
}

fn devGetSpeakerConfig(p: *anyopaque, cfg: ?*u32) callconv(W) HRESULT {
    traceFirst(31, "devGetSpeakerConfig", @returnAddress());
    const self: *Device = @ptrCast(@alignCast(p));
    const q = cfg orelse return E_INVALIDARG;
    q.* = self.speaker_config;
    return S_OK;
}

fn devSetSpeakerConfig(p: *anyopaque, cfg: u32) callconv(W) HRESULT {
    traceFirst(32, "devSetSpeakerConfig", @returnAddress());
    const self: *Device = @ptrCast(@alignCast(p));
    self.speaker_config = cfg;
    return S_OK;
}

fn devInitialize(p: *anyopaque, guid: ?*const Guid) callconv(W) HRESULT {
    traceFirst(33, "devInitialize", @returnAddress());
    _ = p;
    _ = guid;
    return E_NOTIMPL;
}

fn devVerifyCertification(p: *anyopaque, cert: ?*u32) callconv(W) HRESULT {
    traceFirst(34, "devVerifyCertification", @returnAddress());
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
    traceFirst(35, "DirectSoundCreate", @returnAddress());
    _ = guid;
    return makeDevice(out, outer);
}

fn DirectSoundCreate8(guid: ?*const Guid, out: ?*?*anyopaque, outer: ?*anyopaque) callconv(W) HRESULT {
    traceFirst(36, "DirectSoundCreate8", @returnAddress());
    _ = guid;
    return makeDevice(out, outer);
}

fn DirectSoundCaptureCreate(guid: ?*const Guid, out: ?*?*anyopaque, outer: ?*anyopaque) callconv(W) HRESULT {
    traceFirst(37, "DirectSoundCaptureCreate", @returnAddress());
    _ = guid;
    _ = outer;
    if (out) |o| o.* = null;
    return DSERR_NODRIVER;
}

fn DirectSoundCaptureCreate8(guid: ?*const Guid, out: ?*?*anyopaque, outer: ?*anyopaque) callconv(W) HRESULT {
    traceFirst(38, "DirectSoundCaptureCreate8", @returnAddress());
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
    traceFirst(39, "DirectSoundEnumerateA", @returnAddress());
    const f = cb orelse return E_INVALIDARG;
    // One device, no GUID (the default device), then the terminating null entry.
    _ = f(null, "WINS DirectSound", null, ctx);
    _ = f(null, null, null, ctx);
    return S_OK;
}

fn DirectSoundEnumerateW(cb: ?EnumerateProcW, ctx: ?*anyopaque) callconv(W) HRESULT {
    traceFirst(40, "DirectSoundEnumerateW", @returnAddress());
    const f = cb orelse return E_INVALIDARG;
    _ = f(null, &wide_device_name, null, ctx);
    _ = f(null, null, null, ctx);
    return S_OK;
}

fn DirectSoundCaptureEnumerateA(cb: ?EnumerateProc, ctx: ?*anyopaque) callconv(W) HRESULT {
    traceFirst(41, "DirectSoundCaptureEnumerateA", @returnAddress());
    _ = cb;
    _ = ctx;
    return S_OK; // no capture device: an empty enumeration is the honest answer
}

fn DirectSoundCaptureEnumerateW(cb: ?EnumerateProcW, ctx: ?*anyopaque) callconv(W) HRESULT {
    traceFirst(42, "DirectSoundCaptureEnumerateW", @returnAddress());
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

var traced: [64]bool = [_]bool{false} ** 64;
/// Instrument: the first call of each DirectSound entry point, with its caller.
fn traceFirst(slot: usize, comptime name: []const u8, caller: usize) void {
    if (slot >= traced.len or traced[slot]) return;
    traced[slot] = true;
    std.debug.print("[WINS:DSound] first call: {s} (caller 0x{x})\n", .{ name, caller });
}
