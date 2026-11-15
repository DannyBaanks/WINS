//! binkw32: Bink 1 video playback for the guest.
//!
//! The container is read here (it is a header, a frame index and per-frame
//! audio/video packets); the packets are decoded by the host's libavcodec
//! (decoders "binkvideo" and "binkaudio_dct"/"binkaudio_rdft"), opened with
//! dlopen like the other host bridges.
//!
//! Threads: every libavcodec call runs on native threads owned by this module
//! (a video thread decoding ahead into a small ring of BGRx frames, an audio
//! thread feeding the host sound server). The guest's calls only copy pixels
//! and move counters, so no host library ever runs on a guest stack.
//!
//! The guest-visible handle is a BINK structure whose first fields are the
//! documented ones (Width, Height, Frames, FrameNum, LastFrameNum, FrameRate,
//! FrameRateDiv, ...); FalloutNV reads Width/Height/Frames.

const std = @import("std");
const linux = std.os.linux;
const audio = @import("wins_audio.zig");

extern fn dlopen(path: [*:0]const u8, flags: c_int) ?*anyopaque;
extern fn dlsym(handle: ?*anyopaque, name: [*:0]const u8) ?*anyopaque;

// ---- libavcodec / libavutil ------------------------------------------------------

const Av = struct {
    avcodec_find_decoder_by_name: *const fn ([*:0]const u8) callconv(.c) ?*const anyopaque,
    avcodec_alloc_context3: *const fn (?*const anyopaque) callconv(.c) ?*anyopaque,
    avcodec_parameters_alloc: *const fn () callconv(.c) ?[*]u8,
    avcodec_parameters_to_context: *const fn (?*anyopaque, [*]const u8) callconv(.c) c_int,
    avcodec_open2: *const fn (?*anyopaque, ?*const anyopaque, ?*anyopaque) callconv(.c) c_int,
    avcodec_send_packet: *const fn (?*anyopaque, ?*anyopaque) callconv(.c) c_int,
    avcodec_receive_frame: *const fn (?*anyopaque, ?*anyopaque) callconv(.c) c_int,
    avcodec_free_context: *const fn (*?*anyopaque) callconv(.c) void,
    av_packet_alloc: *const fn () callconv(.c) ?*anyopaque,
    av_packet_from_data: *const fn (?*anyopaque, [*]u8, c_int) callconv(.c) c_int,
    av_packet_unref: *const fn (?*anyopaque) callconv(.c) void,
    av_packet_free: *const fn (*?*anyopaque) callconv(.c) void,
    av_frame_alloc: *const fn () callconv(.c) ?*anyopaque,
    av_frame_free: *const fn (*?*anyopaque) callconv(.c) void,
    av_malloc: *const fn (usize) callconv(.c) ?[*]u8,
    av_opt_set: *const fn (?*anyopaque, [*:0]const u8, [*:0]const u8, c_int) callconv(.c) c_int,
    av_opt_set_int: *const fn (?*anyopaque, [*:0]const u8, i64, c_int) callconv(.c) c_int,
};

var av: Av = undefined;
var av_state = std.atomic.Value(u8).init(0); // 0 unknown, 1 ready, 2 missing

fn loadAv() bool {
    switch (av_state.load(.acquire)) {
        1 => return true,
        2 => return false,
        else => {},
    }
    const codec = dlopen("libavcodec.so.60", 2);
    const util = dlopen("libavutil.so.58", 2);
    if (codec == null or util == null) {
        std.debug.print("[WINS:Bink] i386 libavcodec.so.60 / libavutil.so.58 not available; videos are skipped\n", .{});
        av_state.store(2, .release);
        return false;
    }
    inline for (std.meta.fields(Av)) |f| {
        const s = dlsym(codec, f.name ++ "") orelse dlsym(util, f.name ++ "") orelse {
            std.debug.print("[WINS:Bink] host libavcodec has no " ++ f.name ++ "; videos are skipped\n", .{});
            av_state.store(2, .release);
            return false;
        };
        @field(av, f.name) = @ptrCast(@alignCast(s));
    }
    av_state.store(1, .release);
    return true;
}

// AVCodecParameters (libavcodec 60, i386): fields this module sets.
const PAR_CODEC_TYPE = 0;
const PAR_CODEC_ID = 4;
const PAR_CODEC_TAG = 8;
const PAR_EXTRADATA = 12;
const PAR_EXTRADATA_SIZE = 16;
const PAR_WIDTH = 48;
const PAR_HEIGHT = 52;
// AVCodec: name, long_name, type, id.
const CODEC_ID = 12;
// AVFrame: data[8], linesize[8], extended_data, width, height, nb_samples, format.
const FRAME_LINESIZE = 32;
const FRAME_WIDTH = 68;
const FRAME_HEIGHT = 72;
const FRAME_NB_SAMPLES = 76;
const FRAME_FORMAT = 80;

fn putU32(p: [*]u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, p[off..][0..4], v, .little);
}
fn getI32(p: *anyopaque, off: usize) i32 {
    const b: [*]const u8 = @ptrCast(p);
    return std.mem.readInt(i32, b[off..][0..4], .little);
}
fn getPtr(p: *anyopaque, off: usize) ?[*]const u8 {
    const b: [*]const u8 = @ptrCast(p);
    return @ptrFromInt(std.mem.readInt(usize, b[off..][0..@sizeOf(usize)], .little));
}

/// Open a decoder; `extra` is copied (with libavcodec's padding).
fn openDecoder(name: [*:0]const u8, media_type: u32, tag: u32, extra: []const u8, w: u32, h: u32) ?*anyopaque {
    const codec = av.avcodec_find_decoder_by_name(name) orelse return null;
    const ctx = av.avcodec_alloc_context3(codec) orelse return null;
    const par = av.avcodec_parameters_alloc() orelse return null;
    const cb: [*]const u8 = @ptrCast(codec);
    putU32(par, PAR_CODEC_TYPE, media_type);
    putU32(par, PAR_CODEC_ID, std.mem.readInt(u32, cb[CODEC_ID..][0..4], .little));
    putU32(par, PAR_CODEC_TAG, tag);
    const ed = av.av_malloc(extra.len + 64) orelse return null;
    @memcpy(ed[0..extra.len], extra);
    @memset(ed[extra.len .. extra.len + 64], 0);
    putU32(par, PAR_EXTRADATA, @intCast(@intFromPtr(ed)));
    putU32(par, PAR_EXTRADATA_SIZE, @intCast(extra.len));
    putU32(par, PAR_WIDTH, w);
    putU32(par, PAR_HEIGHT, h);
    var c: ?*anyopaque = ctx;
    if (av.avcodec_parameters_to_context(ctx, par) < 0) {
        av.avcodec_free_context(&c);
        return null;
    }
    return ctx;
}

fn sendPacket(ctx: ?*anyopaque, pkt: ?*anyopaque, bytes: []const u8) bool {
    if (bytes.len == 0) return false;
    const buf = av.av_malloc(bytes.len + 64) orelse return false;
    @memcpy(buf[0..bytes.len], bytes);
    @memset(buf[bytes.len .. bytes.len + 64], 0);
    if (av.av_packet_from_data(pkt, buf, @intCast(bytes.len)) < 0) return false;
    const rc = av.avcodec_send_packet(ctx, pkt);
    av.av_packet_unref(pkt);
    return rc >= 0;
}

// ---- container -----------------------------------------------------------------

pub const Header = struct {
    tag: u32,
    file_size: u64,
    frames: u32,
    width: u32,
    height: u32,
    fps_num: u32,
    fps_den: u32,
    video_flags: u32,
    audio_tracks: u32,
    audio_rate: u16 = 0,
    audio_flags: u16 = 0,
    index_offset: u64,
};

pub fn parseHeader(b: []const u8) ?Header {
    if (b.len < 44) return null;
    const rd = struct {
        fn u(x: []const u8, o: usize) u32 {
            return std.mem.readInt(u32, x[o..][0..4], .little);
        }
    }.u;
    const tag = rd(b, 0);
    if ((tag & 0xFFFFFF) != 0x4B4942) return null; // "BIK"
    const rev: u8 = @intCast(tag >> 24);
    if (rev < 'b' or rev > 'k') return null;
    var h: Header = .{
        .tag = tag,
        .file_size = @as(u64, rd(b, 4)) + 8,
        .frames = rd(b, 8),
        .width = rd(b, 20),
        .height = rd(b, 24),
        .fps_num = rd(b, 28),
        .fps_den = rd(b, 32),
        .video_flags = rd(b, 36),
        .audio_tracks = rd(b, 40),
        .index_offset = 0,
    };
    if (h.frames == 0 or h.width == 0 or h.height == 0 or h.width > 8192 or h.height > 8192 or h.fps_den == 0 or h.audio_tracks > 256) return null;
    var off: usize = 44;
    if (rev == 'k') off += 4;
    if (h.audio_tracks > 0) {
        off += 4 * h.audio_tracks; // max decoded sizes
        if (b.len < off + 4) return null;
        h.audio_rate = std.mem.readInt(u16, b[off..][0..2], .little);
        h.audio_flags = std.mem.readInt(u16, b[off + 2 ..][0..2], .little);
        off += 4 * h.audio_tracks; // rate + flags per track
        off += 4 * h.audio_tracks; // track ids
    }
    h.index_offset = off;
    return h;
}

// ---- the guest handle ----------------------------------------------------------

const RING = 4;

pub const Bink = extern struct {
    // Documented BINK prefix (binkw32 1.x).
    Width: u32,
    Height: u32,
    Frames: u32,
    FrameNum: u32,
    LastFrameNum: u32,
    FrameRate: u32,
    FrameRateDiv: u32,
    ReadError: u32,
    OpenFlags: u32,
    BinkType: u32,
    Size: u32,
    FrameSize: u32,
    SndSize: u32,
    reserved: [115]u32,
    // Private.
    state: *State,
};

const State = struct {
    fd: i32,
    hdr: Header,
    index: []u32, // frame start offsets (keyframe bit cleared), frames + 1 entries
    pixels: [RING][]u32, // BGRx frames
    decoded: std.atomic.Value(u32) = .init(0), // frames finished (1-based count)
    consumed: std.atomic.Value(u32) = .init(0), // frames the guest has moved past
    stop: std.atomic.Value(bool) = .init(false),
    paused: std.atomic.Value(bool) = .init(false),
    failed: std.atomic.Value(bool) = .init(false),
    start_ns: u64 = 0,
    paused_ns: u64 = 0,
    pause_began: u64 = 0,
    video: ?std.Thread = null,
    sound: ?std.Thread = null,
};

fn nowNs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

fn futexWait(word: *std.atomic.Value(u32), expect: u32) void {
    var ts: linux.timespec = .{ .sec = 0, .nsec = 50_000_000 };
    _ = linux.syscall4(.futex, @intFromPtr(word), 0, expect, @intFromPtr(&ts));
}
fn futexWake(word: *std.atomic.Value(u32)) void {
    _ = linux.syscall3(.futex, @intFromPtr(word), 1, std.math.maxInt(i32));
}

fn readAt(fd: i32, buf: []u8, off: u64) bool {
    var done: usize = 0;
    while (done < buf.len) {
        const n = linux.pread(fd, buf.ptr + done, buf.len - done, @intCast(off + done));
        if (linux.errno(n) != .SUCCESS or n == 0) return false;
        done += n;
    }
    return true;
}

/// The video part of frame `i`: after one length-prefixed block per audio track.
fn videoPart(st: *State, frame: []u8) []u8 {
    var off: usize = 0;
    var t: u32 = 0;
    while (t < st.hdr.audio_tracks) : (t += 1) {
        if (off + 4 > frame.len) return frame[frame.len..];
        const n = std.mem.readInt(u32, frame[off..][0..4], .little);
        off += 4 + n;
    }
    return if (off <= frame.len) frame[off..] else frame[frame.len..];
}

fn clamp8(v: i32) u32 {
    return @intCast(std.math.clamp(v, 0, 255));
}

/// YUV 4:2:0 (full range, as Bink stores it) -> BGRx.
fn convert(st: *State, frm: *anyopaque, out: []u32) void {
    const w = st.hdr.width;
    const h = st.hdr.height;
    const y_p = getPtr(frm, 0) orelse return;
    const u_p = getPtr(frm, 4) orelse return;
    const v_p = getPtr(frm, 8) orelse return;
    const ys: usize = @intCast(getI32(frm, FRAME_LINESIZE));
    const us: usize = @intCast(getI32(frm, FRAME_LINESIZE + 4));
    const vs: usize = @intCast(getI32(frm, FRAME_LINESIZE + 8));
    var row: usize = 0;
    while (row < h) : (row += 1) {
        var x: usize = 0;
        while (x < w) : (x += 1) {
            const Y: i32 = y_p[row * ys + x];
            const U: i32 = @as(i32, u_p[(row / 2) * us + x / 2]) - 128;
            const V: i32 = @as(i32, v_p[(row / 2) * vs + x / 2]) - 128;
            const r = clamp8(Y + ((91881 * V) >> 16));
            const g = clamp8(Y - ((22554 * U + 46802 * V) >> 16));
            const b = clamp8(Y + ((116130 * U) >> 16));
            out[row * w + x] = 0xFF000000 | (r << 16) | (g << 8) | b;
        }
    }
}

fn videoMain(st: *State) void {
    const ctx = openDecoder("binkvideo", 0, st.hdr.tag, std.mem.asBytes(&st.hdr.video_flags), st.hdr.width, st.hdr.height) orelse {
        std.debug.print("[WINS:Bink] the host has no usable binkvideo decoder\n", .{});
        st.failed.store(true, .release);
        futexWake(&st.decoded);
        return;
    };
    var c: ?*anyopaque = ctx;
    if (av.avcodec_open2(ctx, null, null) < 0) {
        std.debug.print("[WINS:Bink] binkvideo refused the stream (tag 0x{x}, {d}x{d})\n", .{ st.hdr.tag, st.hdr.width, st.hdr.height });
        st.failed.store(true, .release);
        futexWake(&st.decoded);
        return;
    }
    var pkt = av.av_packet_alloc();
    var frm = av.av_frame_alloc();
    defer {
        av.av_packet_free(&pkt);
        av.av_frame_free(&frm);
        av.avcodec_free_context(&c);
    }
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.heap.page_allocator);
    var i: u32 = 0;
    while (i < st.hdr.frames and !st.stop.load(.acquire)) : (i += 1) {
        // Stay at most RING-1 frames ahead of what the guest shows.
        while (i >= st.consumed.load(.acquire) + RING - 1 and !st.stop.load(.acquire)) futexWait(&st.consumed, st.consumed.load(.acquire));
        const a = st.index[i];
        const b = st.index[i + 1];
        if (b <= a or b - a > 64 << 20) break;
        buf.resize(std.heap.page_allocator, b - a) catch break;
        if (!readAt(st.fd, buf.items, a)) break;
        const vpart = videoPart(st, buf.items);
        if (!sendPacket(ctx, pkt, vpart)) {
            std.debug.print("[WINS:Bink] frame {d}: the decoder rejected the packet\n", .{i});
            break;
        }
        if (av.avcodec_receive_frame(ctx, frm) < 0) break;
        if (i == 0) std.debug.print("[WINS:Bink] first frame decoded: {d}x{d}, pixel format {d}\n", .{ getI32(frm.?, FRAME_WIDTH), getI32(frm.?, FRAME_HEIGHT), getI32(frm.?, FRAME_FORMAT) });
        convert(st, frm.?, st.pixels[i % RING]);
        st.decoded.store(i + 1, .release);
        futexWake(&st.decoded);
    }
    if (i < st.hdr.frames and !st.stop.load(.acquire)) {
        std.debug.print("[WINS:Bink] decoding stopped at frame {d} of {d}\n", .{ i, st.hdr.frames });
        st.failed.store(true, .release);
        futexWake(&st.decoded);
    }
}

fn soundMain(st: *State) void {
    const dct = st.hdr.audio_flags & 0x1000 != 0;
    const stereo = st.hdr.audio_flags & 0x2000 != 0;
    const channels: u32 = if (stereo) 2 else 1;
    const ctx = openDecoder(if (dct) "binkaudio_dct" else "binkaudio_rdft", 1, 0, std.mem.asBytes(&st.hdr.tag), 0, 0) orelse {
        std.debug.print("[WINS:Bink] the host has no usable Bink audio decoder; the video plays silent\n", .{});
        return;
    };
    var c: ?*anyopaque = ctx;
    defer av.avcodec_free_context(&c);
    _ = av.av_opt_set(ctx, "ch_layout", if (stereo) "stereo" else "mono", 0);
    _ = av.av_opt_set_int(ctx, "ar", st.hdr.audio_rate, 0);
    if (av.avcodec_open2(ctx, null, null) < 0) {
        std.debug.print("[WINS:Bink] the audio decoder refused the track; the video plays silent\n", .{});
        return;
    }
    if (!audio.outputEnabled()) return;
    const out = audio.Output.open(st.hdr.audio_rate, channels, "Bink video") catch {
        std.debug.print("[WINS:Bink] no host sound server; the video plays silent\n", .{});
        return;
    };
    defer out.close();
    std.debug.print("[WINS:Bink] audio: {d} Hz, {d} channel(s), {s}, playing through the host sound server\n", .{ st.hdr.audio_rate, channels, if (dct) "DCT" else "RDFT" });
    var pkt = av.av_packet_alloc();
    var frm = av.av_frame_alloc();
    defer {
        av.av_packet_free(&pkt);
        av.av_frame_free(&frm);
    }
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.heap.page_allocator);
    var pcm: std.ArrayList(i16) = .empty;
    defer pcm.deinit(std.heap.page_allocator);
    var i: u32 = 0;
    while (i < st.hdr.frames and !st.stop.load(.acquire)) : (i += 1) {
        while (st.paused.load(.acquire) and !st.stop.load(.acquire)) sleepMs(10);
        const a = st.index[i];
        const b = st.index[i + 1];
        if (b <= a or b - a > 64 << 20) break;
        buf.resize(std.heap.page_allocator, b - a) catch break;
        if (!readAt(st.fd, buf.items, a)) break;
        if (buf.items.len < 4) continue;
        const n = std.mem.readInt(u32, buf.items[0..4], .little);
        if (n < 4 or 4 + n > buf.items.len) continue; // no audio in this frame (track 0)
        if (!sendPacket(ctx, pkt, buf.items[4 .. 4 + n])) continue;
        while (av.avcodec_receive_frame(ctx, frm) >= 0) {
            const ns: usize = @intCast(getI32(frm.?, FRAME_NB_SAMPLES));
            const fmt = getI32(frm.?, FRAME_FORMAT);
            if (fmt != 8) { // AV_SAMPLE_FMT_FLTP
                std.debug.print("[WINS:Bink] audio sample format {d} is not handled; the video plays silent\n", .{fmt});
                return;
            }
            pcm.resize(std.heap.page_allocator, ns * channels) catch return;
            var ch: usize = 0;
            while (ch < channels) : (ch += 1) {
                const plane: [*]const f32 = @ptrCast(@alignCast(getPtr(frm.?, ch * 4) orelse return));
                for (0..ns) |s| pcm.items[s * channels + ch] = @intFromFloat(std.math.clamp(plane[s], -1.0, 1.0) * 32767.0);
            }
            if (!out.write(pcm.items)) return;
        }
    }
}

// ---- binkw32 entry points (called from winrun32's stdcall thunks) --------------

pub fn open(path: [:0]const u8, flags: u32) ?*Bink {
    const fd_raw = linux.open(path.ptr, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(fd_raw) != .SUCCESS) {
        std.debug.print("[WINS:Bink] cannot open {s}\n", .{path});
        return null;
    }
    const fd: i32 = @intCast(fd_raw);
    var head: [512]u8 = undefined;
    if (!readAt(fd, &head, 0)) {
        _ = linux.close(fd);
        return null;
    }
    const hdr = parseHeader(&head) orelse {
        std.debug.print("[WINS:Bink] {s} is not a Bink 1 file this player understands\n", .{path});
        _ = linux.close(fd);
        return null;
    };
    if (!loadAv()) {
        _ = linux.close(fd);
        return null;
    }
    const a = std.heap.page_allocator;
    const raw_index = a.alloc(u32, hdr.frames) catch return null;
    defer a.free(raw_index);
    if (!readAt(fd, std.mem.sliceAsBytes(raw_index), hdr.index_offset)) {
        _ = linux.close(fd);
        return null;
    }
    const index = a.alloc(u32, hdr.frames + 1) catch return null;
    for (raw_index, 0..) |v, i| index[i] = v & ~@as(u32, 1);
    index[hdr.frames] = @intCast(@min(hdr.file_size, std.math.maxInt(u32)));
    const st = a.create(State) catch return null;
    st.* = .{ .fd = fd, .hdr = hdr, .index = index, .pixels = undefined };
    for (&st.pixels) |*p| {
        p.* = a.alloc(u32, @as(usize, hdr.width) * hdr.height) catch return null;
        @memset(p.*, 0xFF000000);
    }
    const b = a.create(Bink) catch return null;
    @memset(std.mem.asBytes(b), 0);
    b.Width = hdr.width;
    b.Height = hdr.height;
    b.Frames = hdr.frames;
    b.FrameNum = 1;
    b.FrameRate = hdr.fps_num;
    b.FrameRateDiv = hdr.fps_den;
    b.OpenFlags = flags;
    b.Size = @intCast(@min(hdr.file_size, std.math.maxInt(u32)));
    b.state = st;
    st.start_ns = nowNs();
    st.video = std.Thread.spawn(.{}, videoMain, .{st}) catch null;
    if (hdr.audio_tracks > 0) st.sound = std.Thread.spawn(.{}, soundMain, .{st}) catch null;
    std.debug.print("[WINS:Bink] {s}: {d}x{d}, {d} frames at {d}/{d} fps, {d} audio track(s) ({d} Hz, flags 0x{x})\n", .{ path, hdr.width, hdr.height, hdr.frames, hdr.fps_num, hdr.fps_den, hdr.audio_tracks, hdr.audio_rate, hdr.audio_flags });
    return b;
}

pub fn close(b: *Bink) void {
    const st = b.state;
    st.stop.store(true, .release);
    futexWake(&st.consumed);
    if (st.video) |t| t.join();
    if (st.sound) |t| t.join();
    _ = linux.close(st.fd);
    const a = std.heap.page_allocator;
    for (st.pixels) |p| a.free(p);
    a.free(st.index);
    a.destroy(st);
    a.destroy(b);
}

/// Wait until the current frame is decoded (or decoding gave up).
pub fn doFrame(b: *Bink) i32 {
    const st = b.state;
    const want = b.FrameNum;
    while (st.decoded.load(.acquire) < want and !st.failed.load(.acquire)) futexWait(&st.decoded, st.decoded.load(.acquire));
    return 0;
}

pub fn nextFrame(b: *Bink) void {
    const st = b.state;
    b.LastFrameNum = b.FrameNum;
    if (b.FrameNum < b.Frames) b.FrameNum += 1;
    st.consumed.store(b.FrameNum - 1, .release);
    futexWake(&st.consumed);
}

/// Nonzero while it is too early to show the next frame.
pub fn wait(b: *Bink) i32 {
    const st = b.state;
    if (st.paused.load(.acquire)) return 1;
    const elapsed = nowNs() - st.start_ns - st.paused_ns;
    const due: u64 = @intCast(@as(u128, b.FrameNum - 1) * st.hdr.fps_den * 1_000_000_000 / st.hdr.fps_num);
    return @intFromBool(elapsed < due);
}

pub fn pause(b: *Bink, on: bool) i32 {
    const st = b.state;
    const was = st.paused.swap(on, .acq_rel);
    if (on and !was) st.pause_began = nowNs();
    if (!on and was) st.paused_ns += nowNs() - st.pause_began;
    return @intFromBool(on);
}

/// Copy the (srcx, srcy, srcw, srch) part of the current frame to `dest` at
/// (destx, desty). Surface types 3 (32-bit BGRx) and 5/6 (32-bit with alpha)
/// share one layout here; anything else is reported once and copied as 32-bit.
pub fn copyToBufferRect(b: *Bink, dest: usize, pitch: u32, dest_height: u32, dx: u32, dy: u32, sx: u32, sy: u32, sw: u32, sh: u32, flags: u32) i32 {
    const st = b.state;
    const surface = flags & 0xF;
    if (surface != 3 and surface != 5 and surface != 6 and !warned_surface) {
        warned_surface = true;
        std.debug.print("[WINS:Bink] CopyToBufferRect surface type {d} is copied as 32-bit BGRx\n", .{surface});
    }
    if (dest == 0) return 1;
    const frame = st.pixels[(b.FrameNum - 1) % RING];
    const w = st.hdr.width;
    const h = st.hdr.height;
    if (sx >= w or sy >= h) return 0;
    const cw = @min(sw, w - sx);
    const ch = @min(sh, h - sy);
    var row: u32 = 0;
    while (row < ch) : (row += 1) {
        if (dy + row >= dest_height) break;
        const dst: [*]u32 = @ptrFromInt(dest + (dy + row) * @as(usize, pitch) + dx * 4);
        const src = frame[(sy + row) * w + sx ..][0..cw];
        @memcpy(dst[0..cw], src);
    }
    return 0;
}
var warned_surface = false;

test "Bink 1 header: dimensions, rate, audio track and index offset" {
    const hdr = [_]u8{
        0x42, 0x49, 0x4b, 0x69, 0x54, 0xf5, 0x0e, 0x15, 0xf4, 0x21, 0x00, 0x00, 0x48, 0xd9, 0x02, 0x00,
        0xf4, 0x21, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0xd0, 0x02, 0x00, 0x00, 0x80, 0x96, 0x98, 0x00,
        0x15, 0x16, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x02, 0x00,
        0x80, 0xbb, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x88, 0x00, 0x00, 0x64, 0xcb, 0x00, 0x00,
    };
    const h = parseHeader(&hdr).?;
    try std.testing.expectEqual(@as(u32, 1280), h.width);
    try std.testing.expectEqual(@as(u32, 720), h.height);
    try std.testing.expectEqual(@as(u32, 8692), h.frames);
    try std.testing.expectEqual(@as(u32, 10000000), h.fps_num);
    try std.testing.expectEqual(@as(u32, 333333), h.fps_den);
    try std.testing.expectEqual(@as(u32, 1), h.audio_tracks);
    try std.testing.expectEqual(@as(u16, 48000), h.audio_rate);
    try std.testing.expectEqual(@as(u16, 0x7000), h.audio_flags);
    try std.testing.expectEqual(@as(u64, 0x38), h.index_offset);
    try std.testing.expect(parseHeader(hdr[0..20]) == null);
    var bad = hdr;
    bad[0] = 'X';
    try std.testing.expect(parseHeader(&bad) == null);
}

fn sleepMs(ms: u32) void {
    var ts: linux.timespec = .{ .sec = 0, .nsec = @as(isize, @intCast(ms)) * 1_000_000 };
    _ = linux.nanosleep(&ts, null);
}
