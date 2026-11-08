//! winrun: minimal Linux-native loader for 64-bit Windows console PEs (step 1 of the
//! Wine-free path). It maps the image, applies base relocations, binds the import
//! table to a tiny kernel32 implementation, and calls the entry point.
//!
//! THIS EXECUTES THE PE'S MACHINE CODE IN THIS PROCESS. Therefore:
//!  * run ONLY inside the WINS cleanroom (bubblewrap, no network, read-only fs);
//!  * the caller must pass the exact SHA-256 of the image (`--sha256`); any other
//!    file is refused, so nothing runs by accident;
//!  * every import must be implemented *before* the first instruction runs, else
//!    the loader lists the unresolved ones and exits without executing anything.
//!
//! Scope of v0 (everything else is refused, not guessed): PE32+ x86-64, console
//! subsystem, DIR64 relocations, imports by name from kernel32 only
//! (GetStdHandle, WriteFile, ReadFile, GetLastError, SetLastError, ExitProcess),
//! no TLS, no exception handlers (unwind data without handlers is tolerated but
//! never registered), no TEB/PEB (code touching GS will fault), no DLLs, no delay
//! imports, no CLR, no writable+executable sections. Windows exit codes are
//! truncated to 8 bits by Linux.
//! Position: images are always mapped at a kernel-chosen address, never at ImageBase,
//! so relocation bugs cannot hide.
//!
//!   usage: winrun --sha256 HEX [--check] IMAGE.exe
//!   exit codes of the loader itself: 2 usage, 3 refused (hash/scope), 4 unresolved
//!   imports, 5 malformed image, 6 mapping failed. After the entry point runs, the
//!   exit code is the PE's.
const std = @import("std");
const linux = std.os.linux;

const W: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

/// Deliberate defects for the negative controls (winrun_bad_*.zig).
pub const Bug = enum { none, skip_relocs, exit_off_by_one, short_write_count };

const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_INVALID_PARAMETER: u32 = 87;
const HANDLE_STDIN: usize = 0x1000;
const HANDLE_STDOUT: usize = 0x1001;
const HANDLE_STDERR: usize = 0x1002;
const INVALID_HANDLE_VALUE: usize = std.math.maxInt(usize);

const Exit = enum(u8) { usage = 2, refused = 3, unresolved = 4, bad_image = 5, map_failed = 6 };

fn die(code: Exit, comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("winrun: " ++ fmt ++ "\n", args);
    std.process.exit(@intFromEnum(code));
}

fn rd(comptime T: type, b: []const u8, p: usize) ?T {
    if (p > b.len or @sizeOf(T) > b.len - p) return null;
    return std.mem.readInt(T, b[p..][0..@sizeOf(T)], .little);
}

fn need(comptime T: type, b: []const u8, p: usize, what: []const u8) T {
    return rd(T, b, p) orelse die(.bad_image, "truncated: {s} at 0x{x}", .{ what, p });
}

/// NUL-terminated ASCII string at `p`, bounded by the image.
fn cstr(b: []const u8, p: usize, what: []const u8) []const u8 {
    if (p >= b.len) die(.bad_image, "{s} out of image (0x{x})", .{ what, p });
    const end = std.mem.indexOfScalarPos(u8, b, p, 0) orelse die(.bad_image, "{s} not terminated", .{what});
    if (end - p > 255) die(.bad_image, "{s} too long", .{what});
    return b[p..end];
}

const SCN_EXEC: u32 = 0x20000000;
const SCN_READ: u32 = 0x40000000;
const SCN_WRITE: u32 = 0x80000000;
const SCN_CODE: u32 = 0x00000020;

const Section = struct { name: [8]u8, va: u32, vsize: u32, raw_ptr: u32, raw_size: u32, chars: u32 };

pub fn Impl(comptime bug: Bug) type {
    return struct {
        threadlocal var last_error: u32 = 0;

        fn GetLastError() callconv(W) u32 {
            return last_error;
        }
        fn SetLastError(v: u32) callconv(W) void {
            last_error = v;
        }
        fn GetStdHandle(n: u32) callconv(W) usize {
            return switch (n) {
                0xFFFFFFF6 => HANDLE_STDIN, // STD_INPUT_HANDLE  (-10)
                0xFFFFFFF5 => HANDLE_STDOUT, // STD_OUTPUT_HANDLE (-11)
                0xFFFFFFF4 => HANDLE_STDERR, // STD_ERROR_HANDLE  (-12)
                else => blk: {
                    last_error = ERROR_INVALID_HANDLE;
                    break :blk INVALID_HANDLE_VALUE;
                },
            };
        }
        fn WriteFile(h: usize, buf: ?[*]const u8, n: u32, written: ?*u32, overlapped: ?*anyopaque) callconv(W) i32 {
            if (overlapped != null or (h != HANDLE_STDOUT and h != HANDLE_STDERR) or (buf == null and n != 0)) {
                last_error = if (overlapped != null) ERROR_INVALID_PARAMETER else ERROR_INVALID_HANDLE;
                if (written) |w| w.* = 0;
                return 0;
            }
            const fd: i32 = if (h == HANDLE_STDOUT) 1 else 2;
            var done: usize = 0;
            while (done < n) {
                const rc = linux.write(fd, buf.? + done, n - done);
                if (linux.errno(rc) != .SUCCESS) break;
                if (rc == 0) break;
                done += rc;
            }
            if (written) |w| w.* = if (bug == .short_write_count and done > 1) @intCast(done - 1) else @intCast(done);
            if (done != n) last_error = ERROR_INVALID_HANDLE;
            return if (done == n) 1 else 0;
        }
        fn ReadFile(h: usize, buf: ?[*]u8, n: u32, read: ?*u32, overlapped: ?*anyopaque) callconv(W) i32 {
            if (overlapped != null or h != HANDLE_STDIN or (buf == null and n != 0)) {
                last_error = if (overlapped != null) ERROR_INVALID_PARAMETER else ERROR_INVALID_HANDLE;
                if (read) |r| r.* = 0;
                return 0;
            }
            const rc = linux.read(0, buf.?, n);
            if (linux.errno(rc) != .SUCCESS) {
                if (read) |r| r.* = 0;
                last_error = ERROR_INVALID_HANDLE;
                return 0;
            }
            if (read) |r| r.* = @intCast(rc);
            return 1;
        }
        fn exitWith(code: u32) noreturn {
            const c: u32 = if (bug == .exit_off_by_one) code +% 1 else code;
            linux.exit_group(@bitCast(c));
        }
        fn ExitProcess(code: u32) callconv(W) noreturn {
            exitWith(code);
        }

        const Export = struct { name: []const u8, addr: usize };
        fn exports() [6]Export {
            return .{
                .{ .name = "GetLastError", .addr = @intFromPtr(&GetLastError) },
                .{ .name = "SetLastError", .addr = @intFromPtr(&SetLastError) },
                .{ .name = "GetStdHandle", .addr = @intFromPtr(&GetStdHandle) },
                .{ .name = "WriteFile", .addr = @intFromPtr(&WriteFile) },
                .{ .name = "ReadFile", .addr = @intFromPtr(&ReadFile) },
                .{ .name = "ExitProcess", .addr = @intFromPtr(&ExitProcess) },
            };
        }

        fn lookup(lib: []const u8, name: []const u8) ?usize {
            if (!std.ascii.eqlIgnoreCase(lib, "kernel32.dll")) return null;
            for (exports()) |e| if (std.mem.eql(u8, name, e.name)) return e.addr;
            return null;
        }

        pub fn main(init: std.process.Init) !void {
            const a = init.arena.allocator();
            const io = init.io;
            const args = try init.minimal.args.toSlice(a);

            var want_hash: ?[]const u8 = null;
            var check_only = false;
            var path: ?[]const u8 = null;
            var i: usize = 1;
            while (i < args.len) : (i += 1) {
                if (std.mem.eql(u8, args[i], "--sha256") and i + 1 < args.len) {
                    i += 1;
                    want_hash = args[i];
                } else if (std.mem.eql(u8, args[i], "--check")) {
                    check_only = true;
                } else if (path == null and !std.mem.startsWith(u8, args[i], "--")) {
                    path = args[i];
                } else die(.usage, "usage: winrun --sha256 HEX [--check] IMAGE.exe", .{});
            }
            if (want_hash == null or path == null) die(.usage, "usage: winrun --sha256 HEX [--check] IMAGE.exe", .{});
            // An accidental-use guard, not a sandbox attestation: the caller
            // controls its environment. The wrapper supplies it inside bwrap.
            if (!check_only and !std.mem.eql(u8, init.environ_map.get("WINS_WINRUN_BOX") orelse "", "1"))
                die(.usage, "execution requires the boxed launcher; use winrun_box.py", .{});

            const file = std.Io.Dir.cwd().readFileAlloc(io, path.?, a, .limited(64 * 1024 * 1024)) catch |e|
                die(.usage, "cannot read {s}: {s}", .{ path.?, @errorName(e) });

            // 1. Identity gate: only the exact image the caller vouched for.
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(file, &digest, .{});
            const got_hash = std.fmt.bytesToHex(digest, .lower);
            if (want_hash.?.len != 64 or !std.ascii.eqlIgnoreCase(want_hash.?, &got_hash))
                die(.refused, "sha256 mismatch: image is {s}", .{&got_hash});

            // 2. Headers and scope.
            if (file.len < 64 or !std.mem.eql(u8, file[0..2], "MZ")) die(.bad_image, "not an MZ file", .{});
            const pe: usize = need(u32, file, 0x3c, "e_lfanew");
            if (rd(u32, file, pe) != 0x00004550) die(.bad_image, "no PE signature", .{});
            const machine = need(u16, file, pe + 4, "machine");
            const nsec = need(u16, file, pe + 6, "section count");
            const opt_size = need(u16, file, pe + 20, "optional header size");
            const fchars = need(u16, file, pe + 22, "characteristics");
            const opt = pe + 24;
            if (machine != 0x8664) die(.refused, "machine 0x{x} is not x86-64", .{machine});
            if (need(u16, file, opt, "magic") != 0x20b) die(.refused, "not PE32+", .{});
            if (opt_size < 112 + 16 * 8) die(.bad_image, "optional header too small ({d})", .{opt_size});
            if (fchars & 0x2000 != 0) die(.refused, "image is a DLL", .{});
            if (fchars & 0x0001 != 0) die(.refused, "relocations stripped; winrun never maps at ImageBase", .{});
            const entry_rva = need(u32, file, opt + 16, "entry point");
            const image_base = need(u64, file, opt + 24, "ImageBase");
            const sect_align = need(u32, file, opt + 32, "SectionAlignment");
            const size_of_image = need(u32, file, opt + 56, "SizeOfImage");
            const size_of_headers = need(u32, file, opt + 60, "SizeOfHeaders");
            const subsystem = need(u16, file, opt + 68, "subsystem");
            const ndirs = need(u32, file, opt + 108, "NumberOfRvaAndSizes");
            if (subsystem != 3) die(.refused, "subsystem {d} is not console (3)", .{subsystem});
            if (sect_align < 4096 or sect_align % 4096 != 0) die(.refused, "SectionAlignment 0x{x} below page size", .{sect_align});
            if (size_of_image == 0 or size_of_image > 256 * 1024 * 1024) die(.bad_image, "SizeOfImage 0x{x}", .{size_of_image});
            if (size_of_headers > file.len or size_of_headers > size_of_image) die(.bad_image, "SizeOfHeaders 0x{x}", .{size_of_headers});
            if (ndirs < 16) die(.refused, "only {d} data directories", .{ndirs});

            const Dir = struct { rva: u32, size: u32 };
            var dirs: [16]Dir = undefined;
            for (&dirs, 0..) |*d, k| d.* = .{ .rva = need(u32, file, opt + 112 + k * 8, "dir"), .size = need(u32, file, opt + 116 + k * 8, "dir") };
            if (dirs[9].size != 0) die(.refused, "TLS directory present (unsupported)", .{});
            if (dirs[13].size != 0) die(.refused, "delay-import directory present (unsupported)", .{});
            if (dirs[14].size != 0) die(.refused, "CLR header present (managed code unsupported)", .{});
            if (dirs[11].size != 0) die(.refused, "bound-import directory present (unsupported)", .{});

            // 3. Sections.
            const sec_off = opt + opt_size;
            if (nsec == 0 or nsec > 96) die(.bad_image, "{d} sections", .{nsec});
            const secs = try a.alloc(Section, nsec);
            for (secs, 0..) |*s, k| {
                const o = sec_off + k * 40;
                if (o + 40 > file.len) die(.bad_image, "section table truncated", .{});
                s.* = .{
                    .name = file[o..][0..8].*,
                    .vsize = need(u32, file, o + 8, "vsize"),
                    .va = need(u32, file, o + 12, "va"),
                    .raw_size = need(u32, file, o + 16, "raw size"),
                    .raw_ptr = need(u32, file, o + 20, "raw ptr"),
                    .chars = need(u32, file, o + 36, "section characteristics"),
                };
                const nm = std.mem.sliceTo(&s.name, 0);
                if (s.chars & SCN_EXEC != 0 and s.chars & SCN_WRITE != 0) die(.refused, "section {s} is writable and executable", .{nm});
                if (s.va % 4096 != 0 or s.va < size_of_headers) die(.bad_image, "section {s} at 0x{x} misplaced", .{ nm, s.va });
                const span = @max(s.vsize, s.raw_size);
                if (@as(u64, s.va) + span > size_of_image) die(.bad_image, "section {s} beyond SizeOfImage", .{nm});
                if (s.raw_size != 0 and @as(u64, s.raw_ptr) + s.raw_size > file.len) die(.bad_image, "section {s} raw data beyond file", .{nm});
                if (k > 0 and s.va < secs[k - 1].va + std.mem.alignForward(u32, @max(@max(secs[k - 1].vsize, secs[k - 1].raw_size), 1), 4096)) die(.bad_image, "section {s} overlaps", .{nm});
            }

            // 4. Map read-write at a kernel-chosen address (never ImageBase).
            const map_len = std.mem.alignForward(usize, size_of_image, 4096);
            const mrc = linux.mmap(null, map_len, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
            if (linux.errno(mrc) != .SUCCESS) die(.map_failed, "mmap of 0x{x} bytes failed", .{map_len});
            const base: usize = mrc;
            if (base == image_base) die(.map_failed, "kernel chose ImageBase itself; refusing to hide relocation bugs", .{});
            const img: []u8 = @as([*]u8, @ptrFromInt(base))[0..map_len];
            @memcpy(img[0..size_of_headers], file[0..size_of_headers]);
            for (secs) |s| {
                const n = if (s.vsize != 0) @min(s.raw_size, s.vsize) else s.raw_size;
                if (n != 0) @memcpy(img[s.va..][0..n], file[s.raw_ptr..][0..n]);
            }

            // 5. Base relocations.
            const delta: u64 = @as(u64, base) -% image_base;
            var n_relocs: usize = 0;
            if (dirs[5].size != 0) {
                if (@as(u64, dirs[5].rva) + dirs[5].size > size_of_image) die(.bad_image, "reloc directory beyond image", .{});
                var p: usize = dirs[5].rva;
                const end: usize = p + dirs[5].size;
                while (p + 8 <= end) {
                    const page = need(u32, img, p, "reloc page");
                    const bsize = need(u32, img, p + 4, "reloc block size");
                    if (bsize < 8 or bsize % 2 != 0 or p + bsize > end) die(.bad_image, "reloc block size {d}", .{bsize});
                    var q = p + 8;
                    while (q < p + bsize) : (q += 2) {
                        const e = need(u16, img, q, "reloc entry");
                        const kind = e >> 12;
                        const tgt = @as(u64, page) + (e & 0xfff);
                        switch (kind) {
                            0 => {}, // IMAGE_REL_BASED_ABSOLUTE: padding
                            10 => { // IMAGE_REL_BASED_DIR64
                                if (tgt + 8 > size_of_image) die(.bad_image, "DIR64 target 0x{x} beyond image", .{tgt});
                                if (bug != .skip_relocs) {
                                    const t: usize = @intCast(tgt);
                                    const v = std.mem.readInt(u64, img[t..][0..8], .little);
                                    std.mem.writeInt(u64, img[t..][0..8], v +% delta, .little);
                                }
                                n_relocs += 1;
                            },
                            else => die(.refused, "relocation type {d} unsupported", .{kind}),
                        }
                    }
                    p += bsize;
                }
                if (p != end) die(.bad_image, "truncated relocation block", .{});
            } else die(.refused, "no relocation directory; winrun never maps at ImageBase", .{});

            // 6. Exception data: tolerate unwind info, refuse handlers (nothing would dispatch them).
            if (dirs[3].size != 0) {
                if (@as(u64, dirs[3].rva) + dirs[3].size > size_of_image or dirs[3].size % 12 != 0) die(.bad_image, "exception directory malformed", .{});
                var p: usize = dirs[3].rva;
                while (p < dirs[3].rva + dirs[3].size) : (p += 12) {
                    var ui = need(u32, img, p + 8, "unwind info rva");
                    var depth: usize = 0;
                    while (true) : (depth += 1) {
                        if (depth > 32) die(.bad_image, "unwind chain too deep", .{});
                        const hdr = need(u8, img, ui, "unwind info");
                        const flags = hdr >> 3;
                        if (flags & 0x3 != 0) die(.refused, "function at RVA 0x{x} has an exception handler (SEH unsupported)", .{need(u32, img, p, "begin")});
                        if (flags & 0x4 == 0) break; // not chained
                        const codes = need(u8, img, ui + 2, "unwind code count");
                        const chained = ui + 4 + std.mem.alignForward(usize, codes, 2) * 2;
                        ui = need(u32, img, chained + 8, "chained unwind info");
                    }
                }
            }

            // 7. Imports: resolve everything first; execute nothing if anything is missing.
            var n_imports: usize = 0;
            var missing: std.ArrayList(u8) = .empty;
            if (dirs[1].size != 0) {
                if (@as(u64, dirs[1].rva) + dirs[1].size > size_of_image) die(.bad_image, "import directory beyond image", .{});
                var d: usize = dirs[1].rva;
                const end: usize = d + dirs[1].size;
                while (true) : (d += 20) {
                    if (d > end or end - d < 20) die(.bad_image, "truncated import directory", .{});
                    const oft = need(u32, img, d, "import OFT");
                    const name_rva = need(u32, img, d + 12, "import name");
                    const ft = need(u32, img, d + 16, "import FT");
                    if (oft == 0 and name_rva == 0 and ft == 0) break;
                    const lib = cstr(img, name_rva, "library name");
                    var lt: usize = if (oft != 0) oft else ft;
                    var at: usize = ft;
                    while (true) : ({
                        lt += 8;
                        at += 8;
                    }) {
                        const thunk = need(u64, img, lt, "lookup thunk");
                        if (thunk == 0) break;
                        if (at + 8 > size_of_image) die(.bad_image, "IAT beyond image", .{});
                        if (thunk >> 63 != 0) {
                            try missing.print(a, "  {s}!#{d} (by ordinal)\n", .{ lib, thunk & 0xffff });
                            continue;
                        }
                        const sym = cstr(img, @intCast((thunk & 0x7fffffff) + 2), "import name");
                        if (lookup(lib, sym)) |addr| {
                            std.mem.writeInt(u64, img[at..][0..8], addr, .little);
                            n_imports += 1;
                        } else try missing.print(a, "  {s}!{s}\n", .{ lib, sym });
                    }
                }
            }
            if (missing.items.len != 0) die(.unresolved, "unresolved imports, nothing executed:\n{s}", .{missing.items});

            // 8. Entry point must lie in an executable section.
            var entry_ok = false;
            for (secs) |s| {
                if (s.chars & SCN_EXEC != 0 and entry_rva >= s.va and entry_rva < s.va + @max(s.vsize, s.raw_size)) entry_ok = true;
            }
            if (!entry_ok) die(.bad_image, "entry point 0x{x} not in an executable section", .{entry_rva});

            if (check_only) {
                std.debug.print("winrun: READY sha256={s} relocs={d} imports={d} base=0x{x} (not executed: --check)\n", .{ &got_hash, n_relocs, n_imports, base });
                std.process.exit(0);
            }

            // 9. Final protections: headers R, sections per characteristics (never W+X).
            protect(img.ptr, std.mem.alignForward(usize, size_of_headers, 4096), .{ .READ = true });
            for (secs) |s| {
                const len = std.mem.alignForward(usize, @max(s.vsize, s.raw_size), 4096);
                if (len == 0) continue;
                protect(img.ptr + s.va, len, .{
                    .READ = s.chars & SCN_READ != 0 or s.chars & SCN_EXEC != 0,
                    .WRITE = s.chars & SCN_WRITE != 0,
                    .EXEC = s.chars & SCN_EXEC != 0,
                });
            }

            // 10. Run. Returning from the entry point ends the process with its return value.
            const entry: *const fn () callconv(W) u32 = @ptrFromInt(base + entry_rva);
            const rc = entry();
            exitWith(rc);
        }

        fn protect(p: [*]u8, len: usize, prot: linux.PROT) void {
            const rc = linux.mprotect(p, len, prot);
            if (linux.errno(rc) != .SUCCESS) die(.map_failed, "mprotect failed", .{});
        }
    };
}
