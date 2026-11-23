const std = @import("std");
const trace = @import("../runtime/trace.zig");
const c_stat = @cImport({
    @cInclude("sys/stat.h");
    @cInclude("dirent.h");
    @cInclude("fcntl.h");
    @cInclude("unistd.h");
});

// Exact Darwin x86_64 struct stat (64-bit inode, 144 bytes)
pub const DarwinTimespec = extern struct {
    tv_sec: i64,
    tv_nsec: i64,
};

pub const DarwinStat64 = extern struct {
    st_dev: i32,
    st_mode: u16,
    st_nlink: u16,
    st_ino: u64,
    st_uid: u32,
    st_gid: u32,
    st_rdev: i32,
    st_atimespec: DarwinTimespec,
    st_mtimespec: DarwinTimespec,
    st_ctimespec: DarwinTimespec,
    st_birthtimespec: DarwinTimespec,
    st_size: i64,
    st_blocks: i64,
    st_blksize: i32,
    st_flags: u32,
    st_gen: u32,
    st_lspare: i32,
    st_qspare: [2]i64,
};

comptime {
    std.debug.assert(@sizeOf(DarwinStat64) == 144);
}

fn translateLinuxStatToDarwin(lx: *const c_stat.struct_stat, out: *DarwinStat64) void {
    out.* = .{
        .st_dev = @truncate(@as(i64, @intCast(lx.st_dev))),
        .st_mode = @truncate(lx.st_mode),
        .st_nlink = @truncate(lx.st_nlink),
        .st_ino = lx.st_ino,
        .st_uid = lx.st_uid,
        .st_gid = lx.st_gid,
        .st_rdev = @truncate(@as(i64, @intCast(lx.st_rdev))),
        .st_atimespec = .{ .tv_sec = lx.st_atim.tv_sec, .tv_nsec = lx.st_atim.tv_nsec },
        .st_mtimespec = .{ .tv_sec = lx.st_mtim.tv_sec, .tv_nsec = lx.st_mtim.tv_nsec },
        .st_ctimespec = .{ .tv_sec = lx.st_ctim.tv_sec, .tv_nsec = lx.st_ctim.tv_nsec },
        .st_birthtimespec = .{ .tv_sec = lx.st_ctim.tv_sec, .tv_nsec = lx.st_ctim.tv_nsec },
        .st_size = lx.st_size,
        .st_blocks = lx.st_blocks,
        .st_blksize = @truncate(lx.st_blksize),
        .st_flags = 0,
        .st_gen = 0,
        .st_lspare = 0,
        .st_qspare = .{ 0, 0 },
    };
}

pub fn shim_stat(path: [*:0]const u8, buf: *DarwinStat64) callconv(.c) c_int {
    if (trace.active_tracer) |t| t.recordExternalCall("_stat");
    var lx: c_stat.struct_stat = undefined;
    const rc = c_stat.stat(path, &lx);
    if (rc != 0) return -1;
    translateLinuxStatToDarwin(&lx, buf);
    return 0;
}

pub fn shim_lstat(path: [*:0]const u8, buf: *DarwinStat64) callconv(.c) c_int {
    if (trace.active_tracer) |t| t.recordExternalCall("_lstat");
    var lx: c_stat.struct_stat = undefined;
    const rc = c_stat.lstat(path, &lx);
    if (rc != 0) return -1;
    translateLinuxStatToDarwin(&lx, buf);
    return 0;
}

pub fn shim_fstat(fd: c_int, buf: *DarwinStat64) callconv(.c) c_int {
    if (trace.active_tracer) |t| t.recordExternalCall("_fstat");
    var lx: c_stat.struct_stat = undefined;
    const rc = c_stat.fstat(fd, &lx);
    if (rc != 0) return -1;
    translateLinuxStatToDarwin(&lx, buf);
    return 0;
}

// Darwin x86_64 64-bit struct dirent
pub const DarwinDirent64 = extern struct {
    d_ino: u64,
    d_seekoff: u64,
    d_reclen: u16,
    d_namlen: u16,
    d_type: u8,
    d_name: [1024]u8,
};

threadlocal var tls_darwin_dirent: DarwinDirent64 = undefined;

pub fn shim_opendir(name: [*:0]const u8) callconv(.c) ?*c_stat.DIR {
    if (trace.active_tracer) |t| t.recordExternalCall("_opendir$INODE64");
    return c_stat.opendir(name);
}

pub fn shim_readdir(dirp: ?*c_stat.DIR) callconv(.c) ?*DarwinDirent64 {
    if (trace.active_tracer) |t| t.recordExternalCall("_readdir$INODE64");
    const d = dirp orelse return null;
    const lx = c_stat.readdir(d) orelse return null;
    const name_ptr: [*:0]const u8 = @ptrCast(&lx.*.d_name);
    const name_slice = std.mem.span(name_ptr);
    const copy_len = @min(name_slice.len, tls_darwin_dirent.d_name.len - 1);

    tls_darwin_dirent.d_ino = lx.*.d_ino;
    tls_darwin_dirent.d_seekoff = @bitCast(lx.*.d_off);
    tls_darwin_dirent.d_reclen = @sizeOf(DarwinDirent64);
    tls_darwin_dirent.d_namlen = @intCast(copy_len);
    tls_darwin_dirent.d_type = lx.*.d_type;
    @memcpy(tls_darwin_dirent.d_name[0..copy_len], name_slice[0..copy_len]);
    tls_darwin_dirent.d_name[copy_len] = 0;
    return &tls_darwin_dirent;
}

pub fn shim_closedir(dirp: ?*c_stat.DIR) callconv(.c) c_int {
    if (trace.active_tracer) |t| t.recordExternalCall("_closedir");
    const d = dirp orelse return -1;
    return c_stat.closedir(d);
}

pub fn shim_fdopendir(fd: c_int) callconv(.c) ?*c_stat.DIR {
    if (trace.active_tracer) |t| t.recordExternalCall("_fdopendir$INODE64");
    return c_stat.fdopendir(fd);
}

fn mapDarwinAtFd(dirfd: c_int) c_int {
    // Darwin AT_FDCWD == -2, Linux AT_FDCWD == -100
    return if (dirfd == -2) -100 else dirfd;
}

pub fn shim_fstatat(dirfd: c_int, path: [*:0]const u8, buf: *DarwinStat64, darwin_flag: c_int) callconv(.c) c_int {
    if (trace.active_tracer) |t| t.recordExternalCall("_fstatat$INODE64");
    var lx_flag: c_int = 0;
    if ((darwin_flag & 0x0020) != 0) lx_flag |= 0x0100; // AT_SYMLINK_NOFOLLOW
    var lx: c_stat.struct_stat = undefined;
    const rc = c_stat.fstatat(mapDarwinAtFd(dirfd), path, &lx, lx_flag);
    if (rc != 0) return -1;
    translateLinuxStatToDarwin(&lx, buf);
    return 0;
}

pub fn shim_readlinkat(dirfd: c_int, path: [*:0]const u8, buf: [*]u8, bufsiz: usize) callconv(.c) isize {
    if (trace.active_tracer) |t| t.recordExternalCall("_readlinkat");
    return c_stat.readlinkat(mapDarwinAtFd(dirfd), path, buf, bufsiz);
}
