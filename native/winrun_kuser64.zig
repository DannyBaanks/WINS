//! KUSER_SHARED_DATA for winload64: the read-only page Windows maps at
//! 0x7FFE0000 in every process. Code reads the clocks there directly instead of
//! calling the kernel (Arxan-protected code in Dark Souls III does; so do MSVC
//! runtimes' GetTickCount fast paths).
//!
//! One memfd page is mapped twice: read-only at 0x7FFE0000 for the guest (as on
//! Windows, a guest write faults) and read-write at a kernel-chosen address for
//! the updater thread, which refreshes the clocks every millisecond with the
//! KSYSTEM_TIME protocol (High2Time, LowPart, High1Time; readers retry until
//! High1Time == High2Time). Values describe this machine as WINS reports it
//! elsewhere: Windows 10 build 19045, x86-64, no kernel debugger.
const std = @import("std");
const linux = std.os.linux;

pub const address: usize = 0x7FFE_0000;
const page = 4096;

// x64 KUSER_SHARED_DATA offsets (Windows 10).
const off_tick_multiplier = 0x004;
const off_interrupt_time = 0x008;
const off_system_time = 0x014;
const off_time_zone_bias = 0x020;
const off_image_number_low = 0x02C;
const off_image_number_high = 0x02E;
const off_nt_system_root = 0x030;
const off_nt_build_number = 0x260;
const off_nt_product_type = 0x264;
const off_product_type_is_valid = 0x268;
const off_nt_major = 0x26C;
const off_nt_minor = 0x270;
const off_processor_features = 0x274;
const off_kd_debugger_enabled = 0x2D4;
const off_number_of_physical_pages = 0x2E8;
const off_qpc_frequency = 0x300;
const off_tick_count = 0x320;
const off_active_processor_count = 0x3C0;

var rw: ?[*]u8 = null;
var started = std.atomic.Value(bool).init(false);

/// 100 ns units between 1601-01-01 and 1970-01-01.
const epoch_1601: u64 = 116_444_736_000_000_000;

fn now100ns(clock: linux.clockid_t) u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(clock, &ts);
    return @as(u64, @intCast(ts.sec)) * 10_000_000 + @as(u64, @intCast(ts.nsec)) / 100;
}

fn writeKSystemTime(p: [*]u8, off: usize, v: u64) void {
    const hi: u32 = @truncate(v >> 32);
    const lo: u32 = @truncate(v);
    @as(*volatile u32, @ptrCast(@alignCast(p + off + 8))).* = hi; // High2Time
    @as(*volatile u32, @ptrCast(@alignCast(p + off + 0))).* = lo; // LowPart
    @as(*volatile u32, @ptrCast(@alignCast(p + off + 4))).* = hi; // High1Time
}

fn refresh(p: [*]u8) void {
    const boot = now100ns(.BOOTTIME);
    writeKSystemTime(p, off_interrupt_time, boot);
    writeKSystemTime(p, off_system_time, now100ns(.REALTIME) + epoch_1601);
    // TickCount in ms is derived by readers as (TickCountQuad * multiplier) >> 24
    // with multiplier 0x0FA00000 (= 1000/16 * 2^24 / 62.5): store 15.625 ms ticks.
    const ticks = boot / 156_250;
    writeKSystemTime(p, off_tick_count, ticks);
}

fn put16(p: [*]u8, off: usize, v: u16) void {
    std.mem.writeInt(u16, p[off..][0..2], v, .little);
}
fn put32(p: [*]u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, p[off..][0..4], v, .little);
}
fn put64(p: [*]u8, off: usize, v: u64) void {
    std.mem.writeInt(u64, p[off..][0..8], v, .little);
}

fn fill(p: [*]u8) void {
    @memset(p[0..page], 0);
    put32(p, off_tick_multiplier, 0x0FA0_0000);
    writeKSystemTime(p, off_time_zone_bias, 0);
    put16(p, off_image_number_low, 0x8664);
    put16(p, off_image_number_high, 0x8664);
    for ("C:\\Windows", 0..) |c, k| put16(p, off_nt_system_root + 2 * k, c);
    put32(p, off_nt_build_number, 19045);
    put32(p, off_nt_product_type, 1); // NtProductWinNt
    p[off_product_type_is_valid] = 1;
    put32(p, off_nt_major, 10);
    put32(p, off_nt_minor, 0);
    // PF_* flags this CPU class has (same answers as IsProcessorFeaturePresent).
    for ([_]usize{ 2, 3, 6, 8, 9, 10, 12, 13, 17, 20 }) |f| p[off_processor_features + f] = 1;
    p[off_kd_debugger_enabled] = 0;
    var set: [16]u64 = @splat(0);
    const got = linux.syscall3(.sched_getaffinity, 0, @sizeOf(@TypeOf(set)), @intFromPtr(&set));
    var cpus: u32 = 0;
    if (linux.errno(got) == .SUCCESS) for (set) |w| {
        cpus += @popCount(w);
    };
    if (cpus == 0) cpus = 1;
    put32(p, off_active_processor_count, cpus);
    put32(p, off_number_of_physical_pages, 0x400000); // 16 GiB in 4 KiB pages (nominal)
    put64(p, off_qpc_frequency, 10_000_000);
    refresh(p);
}

extern "c" fn pthread_create(t: *usize, attr: ?*const anyopaque, start: *const fn (?*anyopaque) callconv(.c) ?*anyopaque, arg: ?*anyopaque) c_int;
extern "c" fn pthread_detach(t: usize) c_int;

fn updater(_: ?*anyopaque) callconv(.c) ?*anyopaque {
    const p = rw.?;
    const req = linux.timespec{ .sec = 0, .nsec = 1_000_000 };
    while (true) {
        refresh(p);
        _ = linux.nanosleep(&req, null);
    }
}

/// Maps the page and starts the updater. Returns false (and maps nothing) if
/// 0x7FFE0000 is already taken, which the caller reports.
pub fn install() bool {
    if (started.swap(true, .acq_rel)) return true;
    const fd_rc = linux.memfd_create("wins-kuser", 0);
    if (linux.errno(fd_rc) != .SUCCESS) return false;
    const fd: i32 = @bitCast(@as(u32, @truncate(fd_rc)));
    defer _ = linux.close(fd);
    if (linux.errno(linux.ftruncate(fd, page)) != .SUCCESS) return false;
    const w = linux.mmap(null, page, .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED }, fd, 0);
    if (linux.errno(w) != .SUCCESS) return false;
    const ro = linux.mmap(@ptrFromInt(address), page, .{ .READ = true }, .{ .TYPE = .SHARED, .FIXED_NOREPLACE = true }, fd, 0);
    if (linux.errno(ro) != .SUCCESS or ro != address) {
        _ = linux.munmap(@ptrFromInt(w), page);
        return false;
    }
    rw = @ptrFromInt(w);
    fill(rw.?);
    var t: usize = 0;
    if (pthread_create(&t, null, &updater, null) != 0) return false;
    _ = pthread_detach(t);
    return true;
}

test "KSYSTEM_TIME words agree and clocks move" {
    var buf: [page]u8 align(4096) = undefined;
    fill(&buf);
    const lo = std.mem.readInt(u32, buf[off_interrupt_time..][0..4], .little);
    const h1 = std.mem.readInt(u32, buf[off_interrupt_time + 4 ..][0..4], .little);
    const h2 = std.mem.readInt(u32, buf[off_interrupt_time + 8 ..][0..4], .little);
    try std.testing.expectEqual(h1, h2);
    const t0 = (@as(u64, h1) << 32) | lo;
    const sys_hi = std.mem.readInt(u32, buf[off_system_time + 4 ..][0..4], .little);
    try std.testing.expect(sys_hi > 0x01D0_0000); // after year 2015 in FILETIME
    try std.testing.expectEqual(@as(u32, 10), std.mem.readInt(u32, buf[off_nt_major..][0..4], .little));
    try std.testing.expectEqual(@as(u8, 0), buf[off_kd_debugger_enabled]);
    const req = linux.timespec{ .sec = 0, .nsec = 2_000_000 };
    _ = linux.nanosleep(&req, null);
    refresh(&buf);
    const t1 = (@as(u64, std.mem.readInt(u32, buf[off_interrupt_time + 4 ..][0..4], .little)) << 32) | std.mem.readInt(u32, buf[off_interrupt_time..][0..4], .little);
    try std.testing.expect(t1 > t0);
}

test "install maps the page read-only at 0x7FFE0000" {
    try std.testing.expect(install());
    const p: [*]const volatile u8 = @ptrFromInt(address);
    try std.testing.expectEqual(@as(u8, 10), p[off_nt_major]);
}
