//! Probe PE (x86_64-windows-gnu) used ONLY as a behavioural oracle under Wine.
//! It calls the system MultiByteToWideChar / WideCharToMultiByte (CP_UTF8) with the
//! cases it reads from stdin and writes back what the system returned.
//! Wine reimplements Windows: its answers are evidence, not ground truth.
//!
//! request : u8 mode(0=mb2wc,1=wc2mb) u32 flags i32 len i32 size u8 dst_null u32 nbytes bytes[nbytes]
//! response: i32 ret  u32 last_error  u32 nout  bytes[nout]
//! Build: zig build-exe native/testdata/wine_text_probe.zig -target x86_64-windows-gnu -O ReleaseSmall -fentry=wWinMainCRTStartup --subsystem console
const std = @import("std");
const W: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

extern "kernel32" fn GetStdHandle(n: u32) callconv(W) usize;
extern "kernel32" fn ReadFile(h: usize, b: [*]u8, n: u32, r: *u32, o: ?*anyopaque) callconv(W) i32;
extern "kernel32" fn WriteFile(h: usize, b: [*]const u8, n: u32, w: *u32, o: ?*anyopaque) callconv(W) i32;
extern "kernel32" fn ExitProcess(c: u32) callconv(W) noreturn;
extern "kernel32" fn GetLastError() callconv(W) u32;
extern "kernel32" fn SetLastError(e: u32) callconv(W) void;
extern "kernel32" fn MultiByteToWideChar(cp: u32, fl: u32, s: ?[*]const u8, cb: i32, d: ?[*]u16, cch: i32) callconv(W) i32;
extern "kernel32" fn WideCharToMultiByte(cp: u32, fl: u32, s: ?[*]const u16, cch: i32, d: ?[*]u8, cb: i32, def: ?[*]const u8, used: ?*i32) callconv(W) i32;

const CP_UTF8: u32 = 65001;
const STD_INPUT_HANDLE: u32 = @bitCast(@as(i32, -10));
const STD_OUTPUT_HANDLE: u32 = @bitCast(@as(i32, -11));

var in_storage: [1 << 20]u8 = undefined;
var dst_u16: [1 << 19]u16 = undefined;
var dst_u8: [1 << 20]u8 = undefined;

fn readExact(h: usize, buf: []u8) bool {
    var done: usize = 0;
    while (done < buf.len) {
        var got: u32 = 0;
        const want: u32 = @intCast(buf.len - done);
        if (ReadFile(h, buf.ptr + done, want, &got, null) == 0 or got == 0) return false;
        done += got;
    }
    return true;
}

fn writeAll(h: usize, buf: []const u8) bool {
    var done: usize = 0;
    while (done < buf.len) {
        var wrote: u32 = 0;
        const want: u32 = @intCast(buf.len - done);
        if (WriteFile(h, buf.ptr + done, want, &wrote, null) == 0 or wrote == 0) return false;
        done += wrote;
    }
    return true;
}

pub const panic = std.debug.no_panic;

pub export fn wWinMainCRTStartup() callconv(W) noreturn {
    const hin = GetStdHandle(STD_INPUT_HANDLE);
    const hout = GetStdHandle(STD_OUTPUT_HANDLE);

    while (true) {
        var hdr: [18]u8 = undefined;
        if (!readExact(hin, &hdr)) break;

        const mode = hdr[0];
        const flags = std.mem.readInt(u32, hdr[1..5], .little);
        const len = std.mem.readInt(i32, hdr[5..9], .little);
        const size = std.mem.readInt(i32, hdr[9..13], .little);
        const dst_null = hdr[13] != 0;
        const nbytes = std.mem.readInt(u32, hdr[14..18], .little);

        if (nbytes > in_storage.len) ExitProcess(2);
        if (nbytes > 0 and !readExact(hin, in_storage[0..nbytes])) break;

        SetLastError(0);
        var ret: i32 = 0;
        var nout: u32 = 0;
        var out_bytes: []const u8 = &.{};

        if (mode == 0) {
            const src = if (nbytes > 0) in_storage[0..nbytes].ptr else null;
            const d = if (dst_null) null else dst_u16[0..@min(dst_u16.len, @as(usize, @intCast(@max(size, 0))))].ptr;
            ret = MultiByteToWideChar(CP_UTF8, flags, src, len, d, size);
            if (ret > 0 and !dst_null) {
                nout = @intCast(@as(usize, @intCast(ret)) * 2);
                out_bytes = std.mem.sliceAsBytes(dst_u16[0..@intCast(ret)]);
            }
        } else if (mode == 1) {
            const src: ?[*]const u16 = if (nbytes >= 2) @ptrCast(@alignCast(in_storage[0..nbytes].ptr)) else null;
            const d = if (dst_null) null else dst_u8[0..@min(dst_u8.len, @as(usize, @intCast(@max(size, 0))))].ptr;
            ret = WideCharToMultiByte(CP_UTF8, flags, src, len, d, size, null, null);
            if (ret > 0 and !dst_null) {
                nout = @intCast(ret);
                out_bytes = dst_u8[0..@intCast(ret)];
            }
        } else {
            ExitProcess(3);
        }

        const err = GetLastError();
        var resp_hdr: [12]u8 = undefined;
        std.mem.writeInt(i32, resp_hdr[0..4], ret, .little);
        std.mem.writeInt(u32, resp_hdr[4..8], err, .little);
        std.mem.writeInt(u32, resp_hdr[8..12], nout, .little);

        if (!writeAll(hout, &resp_hdr)) break;
        if (nout > 0 and !writeAll(hout, out_bytes[0..nout])) break;
    }

    ExitProcess(0);
}
