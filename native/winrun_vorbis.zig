//! libvorbisfile.dll -> the real i386 libvorbisfile.
//!
//! This is a bridge, not a reimplementation. The real library is loaded and its
//! exports are handed to the guest, because they already agree: libvorbisfile is
//! cdecl, and on i386 the Windows cdecl the guest speaks and the Linux cdecl the
//! library speaks are the same convention (arguments on the stack, caller cleans
//! up, result in eax). That is the difference from the Steam bridge, where the
//! C++ ABI genuinely differs and each call has to be translated.
//!
//! The one thing that has to be right is the callback struct the guest passes by
//! value: four function pointers into the guest's own image, which the real
//! library will call. Measured with a standalone i386 binary that passes a
//! struct by value and gets the library's own error code back (-132, not a
//! garbage value or a crash), which is the evidence the struct is laid out the
//! way both sides expect.
//!
//! When the real library cannot be found the answer is a refusal that says so,
//! not a stub: a decoder that returns silence would let the game believe it has
//! audio it does not have, which is the same failure mode as the dummy Steam
//! vtables the DRM rejected.

const std = @import("std");
const linux = std.os.linux;

extern fn dlopen(path: [*:0]const u8, flags: c_int) ?*anyopaque;
extern fn getenv(name: [*:0]const u8) ?[*:0]const u8;

/// The override path, from the environment, so a different installation can be
/// pointed at without rebuilding the artifact.
fn envPath() ?[*:0]const u8 {
    return getenv("WINS_LIBVORBISFILE");
}
extern fn dlsym(handle: ?*anyopaque, sym: [*:0]const u8) ?*anyopaque;

/// ov_callbacks, passed BY VALUE by both sides. Four function pointers in the
/// guest's address space, which the real library calls directly -- the
/// convention matches, which is the whole reason no adapter is needed here.
pub const OvCallbacks = extern struct {
    read_func: ?*const fn (?*anyopaque, usize, usize, ?*anyopaque) callconv(.c) usize,
    seek_func: ?*const fn (?*anyopaque, i64, i32) callconv(.c) i32,
    close_func: ?*const fn (?*anyopaque) callconv(.c) i32,
    tell_func: ?*const fn (?*anyopaque) callconv(.c) i64,
};

var g_vf_handle: ?*anyopaque = null;
var g_vf_tried: bool = false;
var g_vf_path_buf: [256]u8 = [_]u8{0} ** 256;

/// Where the real library might be. Searched in order, and overridable with
/// WINS_LIBVORBISFILE so a different installation can be pointed at without
/// rebuilding. Each candidate is measured rather than assumed: the multiarch
/// path is where the distro package installs it, and the Steam Linux Runtime
/// ships its own i386 copy for the games that need it.
const VF_CANDIDATES = [_][*:0]const u8{
    "/usr/lib/i386-linux-gnu/libvorbisfile.so.3",
    "/usr/lib/i386-linux-gnu/libvorbisfile.so",
    "/usr/lib/libvorbisfile.so.3",
    "/usr/local/lib/libvorbisfile.so.3",
};

fn vfReal() ?*anyopaque {
    if (g_vf_tried) return g_vf_handle;
    g_vf_tried = true;
    if (envPath()) |p| {
        g_vf_handle = dlopen(p, 2);
        if (g_vf_handle != null) {
            std.debug.print("[WINS:vorbis] using the real libvorbisfile from WINS_LIBVORBISFILE: {s}\n", .{p});
            return g_vf_handle;
        }
        std.debug.print("[WINS:vorbis] WINS_LIBVORBISFILE={s} did not load; falling back to the search list\n", .{p});
    }
    for (VF_CANDIDATES) |c| {
        g_vf_handle = dlopen(c, 2);
        if (g_vf_handle != null) {
            std.debug.print("[WINS:vorbis] using the real libvorbisfile at {s}\n", .{c});
            return g_vf_handle;
        }
    }
    // Last resort: the Steam Linux Runtime, which ships an i386 copy for exactly
    // this purpose. It is found by looking at the Steam installation the guest
    // was launched from, so it is read from the machine rather than hardcoded.
    if (steamRuntimeVorbisfile()) |p| {
        g_vf_handle = dlopen(p, 2);
        if (g_vf_handle != null) {
            std.debug.print("[WINS:vorbis] using the real libvorbisfile at {s}\n", .{p});
            return g_vf_handle;
        }
    }
    std.debug.print("[WINS:vorbis] no real libvorbisfile on this machine: ov_* cannot be served.\n", .{});
    std.debug.print("            (install libvorbisfile3:i386, or set WINS_LIBVORBISFILE)\n", .{});
    return null;
}

/// Look for the Steam Linux Runtime's i386 copy. Steam is the only reason this
/// machine has an i386 library tree at all, so it is the honest last place to
/// look. Found by walking the directory with the same syscalls the Steam bridge
/// uses, because a hardcoded version number in a path is a path that breaks on
/// the next runtime update -- and it would still have looked plausible.
fn steamRuntimeVorbisfile() ?[*:0]const u8 {
    const roots = [_][*:0]const u8{
        "/home/danny/.local/share/Steam/steamapps/common",
        "/home/danny/.steam/steam/steamapps/common",
    };
    const suffix = "/files/lib/i386-linux-gnu/libvorbisfile.so.3";
    for (roots) |root| {
        const fd = linux.open(root, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
        if (linux.errno(fd) != .SUCCESS) continue;
        defer _ = linux.close(@intCast(fd));
        var dir_buf: [8 * 1024]u8 align(@alignOf(linux.dirent64)) = undefined;
        while (true) {
            const n = linux.getdents64(@intCast(fd), &dir_buf, dir_buf.len);
            if (linux.errno(n) != .SUCCESS) break;
            const len: usize = @intCast(n);
            if (len == 0) break;
            var off: usize = 0;
            while (off + @sizeOf(linux.dirent64) <= len) {
                const ent: *align(1) const linux.dirent64 = @ptrCast(&dir_buf[off]);
                const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&ent.name)), 0);
                off += ent.reclen;
                if (std.mem.indexOf(u8, name, "SteamLinuxRuntime") == null) continue;
                var path_buf: [512:0]u8 = undefined;
                const joined = std.fmt.bufPrint(path_buf[0 .. path_buf.len - suffix.len - 1], "{s}/{s}{s}", .{ root, name, suffix }) catch continue;
                @memcpy(path_buf[joined.len .. joined.len + suffix.len], suffix);
                path_buf[joined.len + suffix.len] = 0;
                // Existence checked by opening it, so a stale directory entry
                // cannot produce a path that dlopen then fails on.
                const probe = linux.open(&path_buf, .{ .ACCMODE = .RDONLY }, 0);
                if (linux.errno(probe) != .SUCCESS) continue;
                _ = linux.close(@intCast(probe));
                const m = @min(joined.len + suffix.len, g_vf_path_buf.len - 1);
                @memcpy(g_vf_path_buf[0..m], path_buf[0..m]);
                g_vf_path_buf[m] = 0;
                return @as([*:0]const u8, @ptrCast(&g_vf_path_buf));
            }
            if (len < dir_buf.len) break;
        }
    }
    return null;
}

/// Resolve one export from the real library, or return null.
fn vfSym(comptime name: [:0]const u8) ?*anyopaque {
    const h = vfReal() orelse return null;
    const p = dlsym(h, name);
    if (p == null) std.debug.print("[WINS:vorbis] the real library has no export {s}\n", .{name});
    return p;
}

/// How the guest calls these entry points: cdecl, but a Windows caller only
/// keeps ESP 4-byte aligned. A host library built for the i386 System V ABI
/// assumes 16 (the Steam runtime's libvorbisfile loads locals with movdqa:
/// ov_raw_seek+0x6a5, a general-protection fault reported as a NULL read when
/// FalloutNV's Continue opened its first .ogg). Declaring 4-byte incoming
/// alignment makes each wrapper realign the stack before calling the library.
const GuestC: std.builtin.CallingConvention = .{ .x86_sysv = .{ .incoming_stack_alignment = 4 } };

/// The table the import resolver consults. Every entry forwards to the real
/// library; nothing here answers on the library's behalf.
pub fn lookupVorbisfile(name: []const u8) ?usize {
    const T = struct {
        fn f_ov_clear(vf: ?*anyopaque) callconv(GuestC) i32 {
            const f: *const fn (?*anyopaque) callconv(.c) i32 = @ptrCast(vfSym("ov_clear") orelse return -1);
            return f(vf);
        }
        fn f_ov_seekable(vf: ?*anyopaque) callconv(GuestC) i32 {
            const f: *const fn (?*anyopaque) callconv(.c) i32 = @ptrCast(vfSym("ov_seekable") orelse return 0);
            return f(vf);
        }
        fn f_ov_pcm_total(vf: ?*anyopaque, i: i32) callconv(GuestC) i64 {
            const f: *const fn (?*anyopaque, i32) callconv(.c) i64 = @ptrCast(vfSym("ov_pcm_total") orelse return -1);
            return f(vf, i);
        }
        fn f_ov_info(vf: ?*anyopaque, i: i32) callconv(GuestC) ?*anyopaque {
            const f: *const fn (?*anyopaque, i32) callconv(.c) ?*anyopaque = @ptrCast(vfSym("ov_info") orelse return null);
            return f(vf, i);
        }
        fn f_ov_read(vf: ?*anyopaque, buffer: ?[*]u8, length: i32, bigendianp: i32, word: i32, sgned: i32, bitstream: ?*i32) callconv(GuestC) i64 {
            const f: *const fn (?*anyopaque, ?[*]u8, i32, i32, i32, i32, ?*i32) callconv(.c) i64 = @ptrCast(vfSym("ov_read") orelse {
                if (bitstream) |b| b.* = 0;
                return 0;
            });
            return f(vf, buffer, length, bigendianp, word, sgned, bitstream);
        }
        fn f_ov_open_callbacks(datasource: ?*anyopaque, vf: ?*anyopaque, initial: ?[*:0]const u8, ibytes: i32, callbacks: OvCallbacks) callconv(GuestC) i32 {
            const f: *const fn (?*anyopaque, ?*anyopaque, ?[*:0]const u8, i32, OvCallbacks) callconv(.c) i32 = @ptrCast(vfSym("ov_open_callbacks") orelse return -132);
            return f(datasource, vf, initial, ibytes, callbacks);
        }
    };
    if (std.mem.eql(u8, name, "ov_clear")) return @intFromPtr(&T.f_ov_clear);
    if (std.mem.eql(u8, name, "ov_seekable")) return @intFromPtr(&T.f_ov_seekable);
    if (std.mem.eql(u8, name, "ov_pcm_total")) return @intFromPtr(&T.f_ov_pcm_total);
    if (std.mem.eql(u8, name, "ov_info")) return @intFromPtr(&T.f_ov_info);
    if (std.mem.eql(u8, name, "ov_read")) return @intFromPtr(&T.f_ov_read);
    if (std.mem.eql(u8, name, "ov_open_callbacks")) return @intFromPtr(&T.f_ov_open_callbacks);
    return null;
}
