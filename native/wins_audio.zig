//! Native audio for WINS: MPEG decode through the real i386 libmpg123 and PCM
//! output through the real i386 libpulse-simple (PulseAudio or PipeWire's
//! pulse server on the host).
//!
//! These are bridges, not reimplementations, for the same reason as
//! winrun_vorbis.zig: the libraries are cdecl and the loader is a Linux i386
//! process, so calling them needs no translation. They are loaded at run time
//! with dlopen so the loader still starts on a machine without them.
//!
//! When a library or the sound server is missing the answer is an error that
//! says so (and the caller logs it), never a decoder that hands back silence:
//! a mute stream that claims success is the failure mode this project rejects.
//!
//! Overrides: WINS_LIBMPG123, WINS_LIBPULSE_SIMPLE (library paths);
//! WINS_AUDIO=0 disables output (decode still works) for headless runs.

const std = @import("std");
const builtin = @import("builtin");

extern fn dlopen(path: [*:0]const u8, flags: c_int) ?*anyopaque;
extern fn dlsym(handle: ?*anyopaque, sym: [*:0]const u8) ?*anyopaque;
extern fn getenv(name: [*:0]const u8) ?[*:0]const u8;
const RTLD_NOW: c_int = 2;

fn openLib(env: [*:0]const u8, candidates: []const [*:0]const u8) ?*anyopaque {
    if (getenv(env)) |p| return dlopen(p, RTLD_NOW);
    for (candidates) |c| if (dlopen(c, RTLD_NOW)) |h| return h;
    return null;
}
fn sym(comptime T: type, h: *anyopaque, name: [*:0]const u8) ?T {
    return @ptrCast(@alignCast(dlsym(h, name) orelse return null));
}

pub const Error = error{ LibraryMissing, SymbolMissing, DecoderFailed, NoAudio, OutOfMemory, ServerUnavailable };

// ---------------------------------------------------------------------------
// libmpg123
// ---------------------------------------------------------------------------
const Mh = opaque {};
const Mpg = struct {
    init: *const fn () callconv(.c) c_int,
    new: *const fn (?[*:0]const u8, ?*c_int) callconv(.c) ?*Mh,
    delete: *const fn (*Mh) callconv(.c) void,
    param: *const fn (*Mh, c_int, c_long, f64) callconv(.c) c_int,
    format_none: *const fn (*Mh) callconv(.c) c_int,
    format: *const fn (*Mh, c_long, c_int, c_int) callconv(.c) c_int,
    open_feed: *const fn (*Mh) callconv(.c) c_int,
    feed: *const fn (*Mh, [*]const u8, usize) callconv(.c) c_int,
    read: *const fn (*Mh, [*]u8, usize, *usize) callconv(.c) c_int,
    getformat: *const fn (*Mh, *c_long, *c_int, *c_int) callconv(.c) c_int,
    plain_strerror: *const fn (c_int) callconv(.c) [*:0]const u8,
};
var mpg_once = std.atomic.Value(u8).init(0); // 0 untried, 1 ok, 2 failed
var mpg: Mpg = undefined;
var mpg_lock: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

fn loadMpg() Error!*const Mpg {
    while (mpg_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    defer mpg_lock.store(0, .release);
    switch (mpg_once.load(.acquire)) {
        1 => return &mpg,
        2 => return Error.LibraryMissing,
        else => {},
    }
    const mpg_candidates: []const [*:0]const u8 = if (builtin.cpu.arch == .x86_64)
        &.{ "libmpg123.so.0", "/usr/lib/x86_64-linux-gnu/libmpg123.so.0", "/usr/lib64/libmpg123.so.0" }
    else
        &.{ "libmpg123.so.0", "/usr/lib/i386-linux-gnu/libmpg123.so.0" };
    const h = openLib("WINS_LIBMPG123", mpg_candidates) orelse {
        mpg_once.store(2, .release);
        return Error.LibraryMissing;
    };
    mpg = .{
        .init = sym(@TypeOf(mpg.init), h, "mpg123_init") orelse return Error.SymbolMissing,
        .new = sym(@TypeOf(mpg.new), h, "mpg123_new") orelse return Error.SymbolMissing,
        .delete = sym(@TypeOf(mpg.delete), h, "mpg123_delete") orelse return Error.SymbolMissing,
        .param = sym(@TypeOf(mpg.param), h, "mpg123_param") orelse return Error.SymbolMissing,
        .format_none = sym(@TypeOf(mpg.format_none), h, "mpg123_format_none") orelse return Error.SymbolMissing,
        .format = sym(@TypeOf(mpg.format), h, "mpg123_format") orelse return Error.SymbolMissing,
        .open_feed = sym(@TypeOf(mpg.open_feed), h, "mpg123_open_feed") orelse return Error.SymbolMissing,
        .feed = sym(@TypeOf(mpg.feed), h, "mpg123_feed") orelse return Error.SymbolMissing,
        .read = sym(@TypeOf(mpg.read), h, "mpg123_read") orelse return Error.SymbolMissing,
        .getformat = sym(@TypeOf(mpg.getformat), h, "mpg123_getformat") orelse return Error.SymbolMissing,
        .plain_strerror = sym(@TypeOf(mpg.plain_strerror), h, "mpg123_plain_strerror") orelse return Error.SymbolMissing,
    };
    _ = mpg.init();
    mpg_once.store(1, .release);
    return &mpg;
}

const MPG123_OK: c_int = 0;
const MPG123_NEED_MORE: c_int = -10;
const MPG123_NEW_FORMAT: c_int = -11;
const MPG123_DONE: c_int = -12;
const MPG123_ADD_FLAGS: c_int = 2;
const MPG123_QUIET: c_long = 0x20;
const MPG123_ENC_SIGNED_16: c_int = 0xD0;
const MPG123_MONO: c_int = 1;
const MPG123_STEREO: c_int = 2;

pub const Pcm = struct {
    samples: []i16, // interleaved
    rate: u32,
    channels: u32,

    pub fn frames(self: Pcm) usize {
        return self.samples.len / self.channels;
    }
    pub fn deinit(self: Pcm) void {
        std.heap.page_allocator.free(self.samples);
    }
};

/// Decode a whole MPEG audio stream (ID3 tags and all) to interleaved s16.
pub fn decodeMpeg(data: []const u8) Error!Pcm {
    const m = try loadMpg();
    var err: c_int = 0;
    const h = m.new(null, &err) orelse return Error.DecoderFailed;
    defer m.delete(h);
    _ = m.param(h, MPG123_ADD_FLAGS, MPG123_QUIET, 0);
    _ = m.format_none(h);
    for ([_]c_long{ 8000, 11025, 12000, 16000, 22050, 24000, 32000, 44100, 48000 }) |r| {
        _ = m.format(h, r, MPG123_MONO | MPG123_STEREO, MPG123_ENC_SIGNED_16);
    }
    if (m.open_feed(h) != MPG123_OK) return Error.DecoderFailed;
    if (m.feed(h, data.ptr, data.len) != MPG123_OK) return Error.DecoderFailed;

    const alloc = std.heap.page_allocator;
    // Upper bound: every 4 input bytes rarely yield more than 64 output bytes;
    // grow if needed.
    var cap: usize = @max(1 << 16, data.len * 12);
    var buf = alloc.alloc(u8, cap) catch return Error.OutOfMemory;
    errdefer alloc.free(buf);
    var len: usize = 0;
    var rate: c_long = 0;
    var chans: c_int = 0;
    var enc: c_int = 0;
    while (true) {
        if (cap - len < 1 << 15) {
            const ncap = cap * 2;
            buf = alloc.realloc(buf, ncap) catch return Error.OutOfMemory;
            cap = ncap;
        }
        var done: usize = 0;
        const rc = m.read(h, buf.ptr + len, cap - len, &done);
        len += done;
        if (rc == MPG123_NEW_FORMAT) {
            _ = m.getformat(h, &rate, &chans, &enc);
            continue;
        }
        if (rc == MPG123_OK) continue;
        if (rc == MPG123_NEED_MORE or rc == MPG123_DONE) break; // all input consumed
        std.debug.print("[WINS:audio] mpg123_read: {s}\n", .{m.plain_strerror(rc)});
        break;
    }
    if (rate == 0) _ = m.getformat(h, &rate, &chans, &enc);
    if (len < 4 or rate <= 0 or chans <= 0 or enc != MPG123_ENC_SIGNED_16) {
        alloc.free(buf);
        return Error.NoAudio;
    }
    const nsamp = len / 2;
    const out = alloc.alloc(i16, nsamp) catch return Error.OutOfMemory;
    @memcpy(std.mem.sliceAsBytes(out), buf[0 .. nsamp * 2]);
    alloc.free(buf);
    return .{ .samples = out, .rate = @intCast(rate), .channels = @intCast(chans) };
}

// ---------------------------------------------------------------------------
// libpulse-simple
// ---------------------------------------------------------------------------
const PaSimple = opaque {};
const PaSampleSpec = extern struct { format: c_int, rate: u32, channels: u8 };
const PaBufferAttr = extern struct { maxlength: u32, tlength: u32, prebuf: u32, minreq: u32, fragsize: u32 };
const Pa = struct {
    new: *const fn (?[*:0]const u8, [*:0]const u8, c_int, ?[*:0]const u8, [*:0]const u8, *const PaSampleSpec, ?*const anyopaque, ?*const PaBufferAttr, ?*c_int) callconv(.c) ?*PaSimple,
    write: *const fn (*PaSimple, [*]const u8, usize, ?*c_int) callconv(.c) c_int,
    flush: *const fn (*PaSimple, ?*c_int) callconv(.c) c_int,
    free: *const fn (*PaSimple) callconv(.c) void,
    strerror: ?*const fn (c_int) callconv(.c) [*:0]const u8,
};
var pa_once = std.atomic.Value(u8).init(0);
var pa: Pa = undefined;
var pa_lock: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

fn loadPa() Error!*const Pa {
    while (pa_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    defer pa_lock.store(0, .release);
    switch (pa_once.load(.acquire)) {
        1 => return &pa,
        2 => return Error.LibraryMissing,
        else => {},
    }
    const pa_candidates: []const [*:0]const u8 = if (builtin.cpu.arch == .x86_64)
        &.{ "libpulse-simple.so.0", "/usr/lib/x86_64-linux-gnu/libpulse-simple.so.0", "/usr/lib64/libpulse-simple.so.0" }
    else
        &.{ "libpulse-simple.so.0", "/usr/lib/i386-linux-gnu/libpulse-simple.so.0" };
    const h = openLib("WINS_LIBPULSE_SIMPLE", pa_candidates) orelse {
        pa_once.store(2, .release);
        return Error.LibraryMissing;
    };
    const core = dlopen("libpulse.so.0", RTLD_NOW) orelse
        if (builtin.cpu.arch == .x86_64) dlopen("/usr/lib/x86_64-linux-gnu/libpulse.so.0", RTLD_NOW) else dlopen("/usr/lib/i386-linux-gnu/libpulse.so.0", RTLD_NOW);
    pa = .{
        .new = sym(@TypeOf(pa.new), h, "pa_simple_new") orelse return Error.SymbolMissing,
        .write = sym(@TypeOf(pa.write), h, "pa_simple_write") orelse return Error.SymbolMissing,
        .flush = sym(@TypeOf(pa.flush), h, "pa_simple_flush") orelse return Error.SymbolMissing,
        .free = sym(@TypeOf(pa.free), h, "pa_simple_free") orelse return Error.SymbolMissing,
        .strerror = if (core) |c| sym(*const fn (c_int) callconv(.c) [*:0]const u8, c, "pa_strerror") else null,
    };
    pa_once.store(1, .release);
    return &pa;
}

pub fn outputEnabled() bool {
    if (getenv("WINS_AUDIO")) |v| return !(v[0] == '0' and v[1] == 0);
    return true;
}

/// One playback stream on the host sound server. write() blocks while the
/// server's buffer is full, which paces the caller at real time.
pub const Output = struct {
    s: *PaSimple,
    p: *const Pa,
    rate: u32,
    channels: u32,

    pub fn open(rate: u32, channels: u32, stream_name: [*:0]const u8) Error!Output {
        if (rate == 0 or channels == 0 or channels > 255) return Error.NoAudio;
        const p = try loadPa();
        const spec = PaSampleSpec{ .format = 3, .rate = rate, .channels = @intCast(channels) }; // PA_SAMPLE_S16LE
        const bytes_per_sec: u64 = @as(u64, rate) * channels * 2;
        const tlen: u32 = @intCast(@min(@as(u64, 0xFFFFFFFF), @max(@as(u64, 1), bytes_per_sec * 60 / 1000)));
        // ~60 ms target buffer so pause, seek and volume answer quickly.
        const attr = PaBufferAttr{ .maxlength = 0xFFFFFFFF, .tlength = tlen, .prebuf = 0xFFFFFFFF, .minreq = 0xFFFFFFFF, .fragsize = 0xFFFFFFFF };
        var err: c_int = 0;
        const s = p.new(null, "WINS", 1, null, stream_name, &spec, null, &attr, &err) orelse {
            const why: [*:0]const u8 = if (p.strerror) |f| f(err) else "unknown";
            std.debug.print("[WINS:audio] pa_simple_new failed: {s}\n", .{why});
            return Error.ServerUnavailable;
        };
        return .{ .s = s, .p = p, .rate = rate, .channels = channels };
    }
    pub fn write(self: Output, samples: []const i16) bool {
        var err: c_int = 0;
        return self.p.write(self.s, @ptrCast(samples.ptr), samples.len * 2, &err) >= 0;
    }
    pub fn flush(self: Output) void {
        var err: c_int = 0;
        _ = self.p.flush(self.s, &err);
    }
    pub fn close(self: Output) void {
        self.p.free(self.s);
    }
};

/// DirectSound/DirectShow volume (hundredths of a dB, 0 = full, -10000 =
/// silence) and balance to linear left/right gains.
pub fn gains(volume: i32, balance: i32) [2]f32 {
    const v: f32 = if (volume <= -10000) 0 else std.math.pow(f32, 10, @as(f32, @floatFromInt(volume)) / 2000);
    var l = v;
    var r = v;
    if (balance > 0) l *= std.math.pow(f32, 10, -@as(f32, @floatFromInt(balance)) / 2000);
    if (balance < 0) r *= std.math.pow(f32, 10, @as(f32, @floatFromInt(balance)) / 2000);
    return .{ l, r };
}

test "gains: 0 dB is unity, -6000 is about 0.001, balance attenuates one side" {
    const g0 = gains(0, 0);
    try std.testing.expectApproxEqAbs(@as(f32, 1), g0[0], 1e-6);
    const g6 = gains(-6000, 0);
    try std.testing.expectApproxEqAbs(@as(f32, 0.001), g6[0], 1e-6);
    try std.testing.expectEqual(@as(f32, 0), gains(-10000, 0)[1]);
    const gb = gains(0, 2000);
    try std.testing.expectApproxEqAbs(@as(f32, 0.1), gb[0], 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 1), gb[1], 1e-6);
}
