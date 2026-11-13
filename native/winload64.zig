//! winload64: Linux-native loader for 64-bit Windows DLL graphs (no Wine).
//!
//! Loads a root PE32+ DLL and every DLL it imports that is present in --dll-dir,
//! binds imports across those images (by name, by ordinal, export forwarders) and
//! against the WINS shim table (winrun's kernel32/msvcrt/extra DLLs, api-set CRT),
//! gives each image its own implicit-TLS slot, sets up a GS-based TEB/PEB, runs TLS
//! callbacks and DllMain(PROCESS_ATTACH) dependencies-first, then calls the exports
//! named with --call and prints their results.
//!
//! THIS EXECUTES THE DLLS' MACHINE CODE IN THIS PROCESS. Therefore:
//!  * run ONLY inside the WINS cleanroom (winload64_box.py: bubblewrap, no network);
//!  * EVERY image must be pinned by SHA-256 (--pin NAME=HEX); an unpinned or
//!    mismatching file is refused before anything is mapped;
//!  * every import must resolve before the first instruction runs, otherwise the
//!    loader lists what is missing and exits without executing anything.
//!
//! Scope (everything else is refused, not guessed): PE32+ x86-64 DLLs, DIR64
//! relocations, images never mapped at ImageBase, no W+X sections, no CLR, no bound
//! imports. Delay imports are bound eagerly; a delay import with no implementation
//! is bound to a trap that reports it and exits only if it is actually called.
//! `.pdata` is validated and recorded but SEH dispatch is NOT implemented: a raised
//! exception still ends the process.
//!
//!   usage: winload64 --pin ROOT.dll=HEX [--pin DEP.dll=HEX ...] [--dll-dir DIR] [--check]
//!                    ROOT.dll [--call [DLL!]EXPORT [--arg N ...] [--ret u32|i32|u64|str]] ...
//!   exit codes: 2 usage, 3 refused, 4 unresolved imports, 5 malformed image,
//!               6 mapping failed, 7 DllMain/TLS init failed.
const std = @import("std");
const linux = std.os.linux;
const winrun = @import("winrun_impl.zig").Impl(.none);

const W: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

/// Deliberate defects for negative controls (winload64_bad_*.zig set `winload64_bug`
/// in their root file). The real loader has none.
pub const Bug = enum { none, shared_tls_index };
const bug: Bug = if (@hasDecl(@import("root"), "winload64_bug")) @import("root").winload64_bug else .none;

const Exit = enum(u8) { usage = 2, refused = 3, unresolved = 4, bad_image = 5, map_failed = 6, init_failed = 7 };

fn die(code: Exit, comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("winload64: " ++ fmt ++ "\n", args);
    std.process.exit(@intFromEnum(code));
}

fn rd(comptime T: type, b: []const u8, p: usize) ?T {
    if (p > b.len or @sizeOf(T) > b.len - p) return null;
    return std.mem.readInt(T, b[p..][0..@sizeOf(T)], .little);
}

fn need(comptime T: type, b: []const u8, p: usize, what: []const u8) T {
    return rd(T, b, p) orelse die(.bad_image, "truncated: {s} at 0x{x}", .{ what, p });
}

fn cstr(b: []const u8, p: usize, what: []const u8) []const u8 {
    if (p >= b.len) die(.bad_image, "{s} out of image (0x{x})", .{ what, p });
    const end = std.mem.indexOfScalarPos(u8, b, p, 0) orelse die(.bad_image, "{s} not terminated", .{what});
    if (end - p > 512) die(.bad_image, "{s} too long", .{what});
    return b[p..end];
}

const SCN_EXEC: u32 = 0x20000000;
const SCN_READ: u32 = 0x40000000;
const SCN_WRITE: u32 = 0x80000000;

const Section = struct { va: u32, vsize: u32, raw_ptr: u32, raw_size: u32, chars: u32 };
const Dir = struct { rva: u32, size: u32 };

const Image = struct {
    name: []const u8, // lower-case basename, e.g. "fixture_a.dll"
    base: usize,
    img: []u8,
    size_of_image: u32,
    size_of_headers: u32,
    entry_rva: u32,
    secs: []Section,
    dirs: [16]Dir,
    deps: std.ArrayList(usize) = .empty, // indices into Loader.images
    tls_index: ?u32 = null,
    tls_template_rva: u32 = 0,
    tls_template_len: usize = 0,
    tls_zero_fill: usize = 0,
    tls_cb_rvas: std.ArrayList(u32) = .empty,
    pdata_entries: usize = 0,
    state: enum { mapped, binding, bound, initialized } = .mapped,
};

/// Delay imports that resolve to nothing are bound to one of these traps; the
/// trap reports which import was called and exits (Windows would raise there).
const max_traps = 64;
var trap_names: [max_traps][]const u8 = undefined;
var n_traps: usize = 0;
fn trapCall(comptime k: usize) *const fn () callconv(W) noreturn {
    return &struct {
        fn f() callconv(W) noreturn {
            die(.unresolved, "called unimplemented delay import {s}", .{trap_names[k]});
        }
    }.f;
}
const trap_table = blk: {
    var t: [max_traps]*const fn () callconv(W) noreturn = undefined;
    for (0..max_traps) |k| t[k] = trapCall(k);
    break :blk t;
};

const Loader = struct {
    a: std.mem.Allocator,
    io: std.Io,
    dll_dir: ?[]const u8,
    pins: std.StringHashMapUnmanaged([]const u8) = .empty, // lower-case name -> hex
    images: std.ArrayList(Image) = .empty,
    missing: std.ArrayList(u8) = .empty,
    n_tls: u32 = 0,
    n_imports: usize = 0,

    fn lower(self: *Loader, s: []const u8) []const u8 {
        const out = self.a.alloc(u8, s.len) catch die(.map_failed, "out of memory", .{});
        return std.ascii.lowerString(out, s);
    }

    fn find(self: *Loader, name: []const u8) ?usize {
        for (self.images.items, 0..) |im, k| if (std.ascii.eqlIgnoreCase(im.name, name)) return k;
        return null;
    }

    /// A DLL is loaded as an image when it is pinned (or present in --dll-dir and
    /// pinned); otherwise its imports go to the shim table.
    fn isImage(self: *Loader, name: []const u8) bool {
        return self.pins.get(self.lower(name)) != null;
    }

    fn readPinned(self: *Loader, path: []const u8, name: []const u8) []u8 {
        const want = self.pins.get(name) orelse die(.refused, "{s} is not pinned (--pin {s}=SHA256)", .{ name, name });
        const file = std.Io.Dir.cwd().readFileAlloc(self.io, path, self.a, .limited(1024 * 1024 * 1024)) catch |e|
            die(.usage, "cannot read {s}: {s}", .{ path, @errorName(e) });
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(file, &digest, .{});
        const got = std.fmt.bytesToHex(digest, .lower);
        if (want.len != 64 or !std.ascii.eqlIgnoreCase(want, &got))
            die(.refused, "sha256 mismatch for {s}: file is {s}", .{ name, &got });
        return file;
    }

    /// Map one image (headers, sections, relocations, TLS, .pdata). Imports later.
    fn map(self: *Loader, path: []const u8) usize {
        const name = self.lower(std.fs.path.basename(path));
        if (self.find(name)) |k| return k;
        const file = self.readPinned(path, name);

        if (file.len < 64 or !std.mem.eql(u8, file[0..2], "MZ")) die(.bad_image, "{s}: not an MZ file", .{name});
        const pe: usize = need(u32, file, 0x3c, "e_lfanew");
        if (rd(u32, file, pe) != 0x00004550) die(.bad_image, "{s}: no PE signature", .{name});
        const machine = need(u16, file, pe + 4, "machine");
        const nsec = need(u16, file, pe + 6, "section count");
        const opt_size = need(u16, file, pe + 20, "optional header size");
        const fchars = need(u16, file, pe + 22, "characteristics");
        const opt = pe + 24;
        if (machine != 0x8664) die(.refused, "{s}: machine 0x{x} is not x86-64", .{ name, machine });
        if (need(u16, file, opt, "magic") != 0x20b) die(.refused, "{s}: not PE32+", .{name});
        if (opt_size < 112 + 16 * 8) die(.bad_image, "{s}: optional header too small", .{name});
        if (fchars & 0x2000 == 0) die(.refused, "{s}: not a DLL", .{name});
        if (fchars & 0x0001 != 0) die(.refused, "{s}: relocations stripped", .{name});
        const entry_rva = need(u32, file, opt + 16, "entry point");
        const image_base = need(u64, file, opt + 24, "ImageBase");
        const sect_align = need(u32, file, opt + 32, "SectionAlignment");
        const size_of_image = need(u32, file, opt + 56, "SizeOfImage");
        const size_of_headers = need(u32, file, opt + 60, "SizeOfHeaders");
        const ndirs = need(u32, file, opt + 108, "NumberOfRvaAndSizes");
        if (sect_align < 4096 or sect_align % 4096 != 0) die(.refused, "{s}: SectionAlignment 0x{x}", .{ name, sect_align });
        if (size_of_image == 0 or size_of_image > 1024 * 1024 * 1024) die(.bad_image, "{s}: SizeOfImage 0x{x}", .{ name, size_of_image });
        if (size_of_headers > file.len or size_of_headers > size_of_image) die(.bad_image, "{s}: SizeOfHeaders", .{name});
        if (ndirs < 16) die(.refused, "{s}: only {d} data directories", .{ name, ndirs });

        var dirs: [16]Dir = undefined;
        for (&dirs, 0..) |*d, k| d.* = .{ .rva = need(u32, file, opt + 112 + k * 8, "dir"), .size = need(u32, file, opt + 116 + k * 8, "dir") };
        for ([_]usize{ 1, 3, 5, 9, 13 }) |k| if (dirs[k].size != 0 and @as(u64, dirs[k].rva) + dirs[k].size > size_of_image)
            die(.bad_image, "{s}: data directory {d} beyond image", .{ name, k });
        if (dirs[14].size != 0) die(.refused, "{s}: CLR header (managed code unsupported)", .{name});
        if (dirs[11].size != 0) die(.refused, "{s}: bound-import directory (unsupported)", .{name});

        const sec_off = opt + opt_size;
        if (nsec == 0 or nsec > 96) die(.bad_image, "{s}: {d} sections", .{ name, nsec });
        const secs = self.a.alloc(Section, nsec) catch die(.map_failed, "out of memory", .{});
        for (secs, 0..) |*s, k| {
            const o = sec_off + k * 40;
            if (o + 40 > file.len) die(.bad_image, "{s}: section table truncated", .{name});
            s.* = .{
                .vsize = need(u32, file, o + 8, "vsize"),
                .va = need(u32, file, o + 12, "va"),
                .raw_size = need(u32, file, o + 16, "raw size"),
                .raw_ptr = need(u32, file, o + 20, "raw ptr"),
                .chars = need(u32, file, o + 36, "section characteristics"),
            };
            if (s.chars & SCN_EXEC != 0 and s.chars & SCN_WRITE != 0) die(.refused, "{s}: a section is writable and executable", .{name});
            if (s.va % 4096 != 0 or s.va < size_of_headers) die(.bad_image, "{s}: section at 0x{x} misplaced", .{ name, s.va });
            if (@as(u64, s.va) + @max(s.vsize, s.raw_size) > size_of_image) die(.bad_image, "{s}: section beyond SizeOfImage", .{name});
            if (s.raw_size != 0 and @as(u64, s.raw_ptr) + s.raw_size > file.len) die(.bad_image, "{s}: section data beyond file", .{name});
        }

        const map_len = std.mem.alignForward(usize, size_of_image, 4096);
        const mrc = linux.mmap(null, map_len, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
        if (linux.errno(mrc) != .SUCCESS) die(.map_failed, "{s}: mmap of 0x{x} bytes failed", .{ name, map_len });
        const base: usize = mrc;
        if (base == image_base) die(.map_failed, "{s}: kernel chose ImageBase; refusing to hide relocation bugs", .{name});
        const img: []u8 = @as([*]u8, @ptrFromInt(base))[0..map_len];
        @memcpy(img[0..size_of_headers], file[0..size_of_headers]);
        for (secs) |s| {
            const n = if (s.vsize != 0) @min(s.raw_size, s.vsize) else s.raw_size;
            if (n != 0) @memcpy(img[s.va..][0..n], file[s.raw_ptr..][0..n]);
        }

        var im: Image = .{ .name = name, .base = base, .img = img, .size_of_image = size_of_image, .size_of_headers = size_of_headers, .entry_rva = entry_rva, .secs = secs, .dirs = dirs };

        // TLS directory (VAs are still relative to ImageBase here: read before relocating).
        if (dirs[9].size != 0) {
            if (dirs[9].size < 40) die(.bad_image, "{s}: TLS directory too small", .{name});
            const td = dirs[9].rva;
            const start_va = need(u64, img, td + 0, "TLS.Start");
            const end_va = need(u64, img, td + 8, "TLS.End");
            const index_va = need(u64, img, td + 16, "TLS.AddressOfIndex");
            const cb_va = need(u64, img, td + 24, "TLS.AddressOfCallBacks");
            const zfill = need(u32, img, td + 32, "TLS.SizeOfZeroFill");
            if (start_va > end_va or end_va - start_va > 16 * 1024 * 1024 or zfill > 16 * 1024 * 1024) die(.refused, "{s}: TLS template size", .{name});
            if (start_va != 0) {
                const srva = start_va -% image_base;
                if (srva + (end_va - start_va) > size_of_image) die(.refused, "{s}: TLS template out of image", .{name});
                im.tls_template_rva = @intCast(srva);
                im.tls_template_len = @intCast(end_va - start_va);
            }
            im.tls_zero_fill = zfill;
            const irva = index_va -% image_base;
            if (irva + 4 > size_of_image) die(.refused, "{s}: TLS index out of image", .{name});
            const slot: u32 = if (bug == .shared_tls_index) 0 else self.n_tls;
            im.tls_index = slot;
            std.mem.writeInt(u32, img[@intCast(irva)..][0..4], slot, .little);
            self.n_tls += 1;
            if (cb_va != 0) {
                var crva = cb_va -% image_base;
                while (true) : (crva += 8) {
                    if (crva + 8 > size_of_image) die(.refused, "{s}: TLS callback table truncated", .{name});
                    const fva = need(u64, img, @intCast(crva), "TLS callback");
                    if (fva == 0) break;
                    const frva = fva -% image_base;
                    if (!inExec(secs, frva)) die(.refused, "{s}: TLS callback 0x{x} not in executable section", .{ name, fva });
                    im.tls_cb_rvas.append(self.a, @intCast(frva)) catch die(.map_failed, "out of memory", .{});
                }
            }
        }

        // Relocations: DIR64 only (plus ABSOLUTE padding).
        const delta: u64 = @as(u64, base) -% image_base;
        if (dirs[5].size == 0) die(.refused, "{s}: no relocation directory", .{name});
        var p: usize = dirs[5].rva;
        const rend: usize = p + dirs[5].size;
        while (p + 8 <= rend) {
            const page = need(u32, img, p, "reloc page");
            const bsize = need(u32, img, p + 4, "reloc block size");
            if (bsize < 8 or bsize % 2 != 0 or p + bsize > rend) die(.bad_image, "{s}: reloc block size {d}", .{ name, bsize });
            var q = p + 8;
            while (q < p + bsize) : (q += 2) {
                const e = need(u16, img, q, "reloc entry");
                const tgt = @as(u64, page) + (e & 0xfff);
                switch (e >> 12) {
                    0 => {},
                    10 => {
                        if (tgt + 8 > size_of_image) die(.bad_image, "{s}: DIR64 target beyond image", .{name});
                        const t: usize = @intCast(tgt);
                        std.mem.writeInt(u64, img[t..][0..8], std.mem.readInt(u64, img[t..][0..8], .little) +% delta, .little);
                    },
                    else => |k| die(.refused, "{s}: relocation type {d} unsupported", .{ name, k }),
                }
            }
            p += bsize;
        }
        if (p != rend) die(.bad_image, "{s}: truncated relocation block", .{name});

        // .pdata: validate bounds (RUNTIME_FUNCTION = 12 bytes); recorded, not dispatched.
        if (dirs[3].size != 0) {
            if (dirs[3].size % 12 != 0) die(.bad_image, "{s}: exception directory size", .{name});
            im.pdata_entries = dirs[3].size / 12;
        }

        self.images.append(self.a, im) catch die(.map_failed, "out of memory", .{});
        const idx = self.images.items.len - 1;
        // Map dependencies that are images (pinned) before binding anything.
        self.forEachImportLib(idx, struct {
            fn f(ld: *Loader, me: usize, lib: []const u8) void {
                if (!ld.isImage(lib)) return;
                const dir = ld.dll_dir orelse die(.usage, "{s} needs {s}: pass --dll-dir", .{ ld.images.items[me].name, lib });
                const dp = std.fs.path.join(ld.a, &.{ dir, lib }) catch die(.map_failed, "out of memory", .{});
                const k = ld.map(dp);
                ld.images.items[me].deps.append(ld.a, k) catch die(.map_failed, "out of memory", .{});
            }
        }.f);
        return idx;
    }

    fn forEachImportLib(self: *Loader, idx: usize, comptime f: fn (*Loader, usize, []const u8) void) void {
        for ([_]usize{ 1, 13 }) |dk| {
            const im = &self.images.items[idx];
            const d = im.dirs[dk];
            if (d.size == 0) continue;
            const stride: usize = if (dk == 1) 20 else 32;
            const name_off: usize = if (dk == 1) 12 else 4;
            var p: usize = d.rva;
            while (p + stride <= d.rva + d.size) : (p += stride) {
                const nrva = need(u32, im.img, p + name_off, "import name");
                if (nrva == 0) break;
                f(self, idx, cstr(im.img, nrva, "library name"));
            }
        }
    }

    fn exportByName(self: *Loader, k: usize, sym: []const u8, depth: u8) ?usize {
        const im = self.images.items[k];
        const d = im.dirs[0];
        if (d.size == 0) return null;
        const nnames = need(u32, im.img, d.rva + 24, "export names");
        const afun = need(u32, im.img, d.rva + 28, "export functions");
        const anames = need(u32, im.img, d.rva + 32, "export name ptrs");
        const aords = need(u32, im.img, d.rva + 36, "export ordinals");
        var i: usize = 0;
        while (i < nnames) : (i += 1) {
            const n = cstr(im.img, need(u32, im.img, anames + i * 4, "export name rva"), "export name");
            if (!std.mem.eql(u8, n, sym)) continue;
            const ord = need(u16, im.img, aords + i * 2, "export ordinal");
            return self.exportRva(k, need(u32, im.img, afun + @as(usize, ord) * 4, "export rva"), depth);
        }
        return null;
    }

    fn exportByOrdinal(self: *Loader, k: usize, ordinal: u16, depth: u8) ?usize {
        const im = self.images.items[k];
        const d = im.dirs[0];
        if (d.size == 0) return null;
        const obase = need(u32, im.img, d.rva + 16, "export ordinal base");
        const nfun = need(u32, im.img, d.rva + 20, "export count");
        const afun = need(u32, im.img, d.rva + 28, "export functions");
        if (ordinal < obase or ordinal - obase >= nfun) return null;
        return self.exportRva(k, need(u32, im.img, afun + (ordinal - obase) * 4, "export rva"), depth);
    }

    /// An export RVA inside the export directory is a forwarder "DLL.Func" / "DLL.#N".
    fn exportRva(self: *Loader, k: usize, rva: u32, depth: u8) ?usize {
        if (rva == 0) return null;
        const im = self.images.items[k];
        const d = im.dirs[0];
        if (rva >= d.rva and rva < d.rva + d.size) {
            if (depth > 8) die(.bad_image, "{s}: export forwarder chain too deep", .{im.name});
            const fwd = cstr(im.img, rva, "forwarder");
            const dot = std.mem.lastIndexOfScalar(u8, fwd, '.') orelse die(.bad_image, "{s}: bad forwarder {s}", .{ im.name, fwd });
            const lib = std.fmt.allocPrint(self.a, "{s}.dll", .{fwd[0..dot]}) catch die(.map_failed, "out of memory", .{});
            return self.resolve(lib, fwd[dot + 1 ..], depth + 1);
        }
        return im.base + rva;
    }

    /// Resolve LIB!SYM ("#N" = ordinal) against loaded images, then the shim table.
    fn resolve(self: *Loader, lib: []const u8, sym: []const u8, depth: u8) ?usize {
        if (self.find(lib)) |k| {
            if (sym.len > 1 and sym[0] == '#') {
                const ord = std.fmt.parseInt(u16, sym[1..], 10) catch return null;
                return self.exportByOrdinal(k, ord, depth);
            }
            return self.exportByName(k, sym, depth);
        }
        if (self.dll_dir) |dir| {   // a real DLL file that is not pinned is refused, not shimmed
            const dp = std.fs.path.join(self.a, &.{ dir, lib }) catch return null;
            if (std.Io.Dir.cwd().access(self.io, dp, .{})) |_| {
                die(.refused, "{s} is in --dll-dir but not pinned (--pin {s}=SHA256); nothing executed", .{ lib, lib });
            } else |_| {}
        }
        const shim_lib = shimLibrary(lib);
        if (sym.len > 1 and sym[0] == '#') {
            const ord = std.fmt.parseInt(u16, sym[1..], 10) catch return null;
            const nm = @import("winrun_ordinals.zig").getOrdinalName(lib, ord) orelse return null;
            return winrun.lookup(shim_lib, nm);
        }
        return winrun.lookup(shim_lib, sym);
    }

    fn bind(self: *Loader, idx: usize) void {
        if (self.images.items[idx].state != .mapped) return;
        self.images.items[idx].state = .binding;
        for (self.images.items[idx].deps.items) |dep| self.bind(dep);
        const im = self.images.items[idx];
        for ([_]usize{ 1, 13 }) |dk| {
            const d = im.dirs[dk];
            if (d.size == 0) continue;
            const delay = dk == 13;
            const stride: usize = if (delay) 32 else 20;
            var p: usize = d.rva;
            while (p + stride <= d.rva + d.size) : (p += stride) {
                const name_rva = need(u32, im.img, p + (if (delay) @as(usize, 4) else 12), "import name");
                if (name_rva == 0) break;
                const lib = cstr(im.img, name_rva, "library name");
                const iat: usize = need(u32, im.img, p + (if (delay) @as(usize, 12) else 16), "IAT");
                const int_: usize = if (delay) need(u32, im.img, p + 16, "delay INT") else blk: {
                    const oft = need(u32, im.img, p, "OFT");
                    break :blk if (oft != 0) oft else iat;
                };
                if (delay) {
                    const attrs = need(u32, im.img, p, "delay attributes");
                    if (attrs & 1 == 0) die(.refused, "{s}: VA-based (v1) delay import descriptor unsupported", .{im.name});
                }
                var lt = int_;
                var at = iat;
                while (true) : ({
                    lt += 8;
                    at += 8;
                }) {
                    const thunk = need(u64, im.img, lt, "lookup thunk");
                    if (thunk == 0) break;
                    if (at + 8 > im.size_of_image) die(.bad_image, "{s}: IAT beyond image", .{im.name});
                    var symbuf: [16]u8 = undefined;
                    const sym = if (thunk >> 63 != 0)
                        std.fmt.bufPrint(&symbuf, "#{d}", .{thunk & 0xffff}) catch unreachable
                    else
                        cstr(im.img, @intCast((thunk & 0x7fffffff) + 2), "import name");
                    if (self.resolve(lib, sym, 0)) |addr| {
                        std.mem.writeInt(u64, im.img[at..][0..8], addr, .little);
                        self.n_imports += 1;
                    } else if (delay and n_traps < max_traps) {
                        trap_names[n_traps] = std.fmt.allocPrint(self.a, "{s}!{s} (from {s})", .{ lib, sym, im.name }) catch "?";
                        std.mem.writeInt(u64, im.img[at..][0..8], @intFromPtr(trap_table[n_traps]), .little);
                        n_traps += 1;
                    } else {
                        self.missing.print(self.a, "  {s}: {s}!{s}{s}\n", .{ im.name, lib, sym, if (delay) " (delay)" else "" }) catch {};
                    }
                }
            }
        }
        self.images.items[idx].state = .bound;
    }

    fn protectAll(self: *Loader) void {
        for (self.images.items) |im| {
            protect(im.img.ptr, std.mem.alignForward(usize, im.size_of_headers, 4096), .{ .READ = true });
            for (im.secs) |s| {
                const len = std.mem.alignForward(usize, @max(s.vsize, s.raw_size), 4096);
                if (len == 0) continue;
                protect(im.img.ptr + s.va, len, .{
                    .READ = s.chars & SCN_READ != 0 or s.chars & SCN_EXEC != 0,
                    .WRITE = s.chars & SCN_WRITE != 0,
                    .EXEC = s.chars & SCN_EXEC != 0,
                });
            }
        }
    }

    /// TLS callbacks + DllMain(PROCESS_ATTACH), dependencies first.
    fn initialize(self: *Loader, idx: usize) void {
        if (self.images.items[idx].state == .initialized) return;
        self.images.items[idx].state = .initialized;
        for (self.images.items[idx].deps.items) |dep| self.initialize(dep);
        const im = self.images.items[idx];
        const TlsCallback = *const fn (usize, u32, usize) callconv(W) void;
        for (im.tls_cb_rvas.items) |cb| (@as(TlsCallback, @ptrFromInt(im.base + cb)))(im.base, 1, 0);
        if (im.entry_rva != 0) {
            if (!inExec(im.secs, im.entry_rva)) die(.bad_image, "{s}: entry point not executable", .{im.name});
            const DllMain = *const fn (usize, u32, usize) callconv(W) i32;
            const ok = (@as(DllMain, @ptrFromInt(im.base + im.entry_rva)))(im.base, 1, 0);
            if (ok == 0) die(.init_failed, "{s}: DllMain(PROCESS_ATTACH) returned FALSE", .{im.name});
        }
    }
};

fn callTarget(ld: *Loader, root_idx: usize, spec: []const u8) ?usize {
    if (std.mem.indexOfScalar(u8, spec, '!')) |bang| {
        const k = ld.find(spec[0..bang]) orelse return null;
        return ld.exportByName(k, spec[bang + 1 ..], 0);
    }
    return ld.exportByName(root_idx, spec, 0);
}

fn inExec(secs: []const Section, rva: u64) bool {
    for (secs) |s| if (s.chars & SCN_EXEC != 0 and rva >= s.va and rva < s.va + @max(s.vsize, s.raw_size)) return true;
    return false;
}

fn protect(p: [*]u8, len: usize, prot: linux.PROT) void {
    if (linux.errno(linux.mprotect(p, len, prot)) != .SUCCESS) die(.map_failed, "mprotect failed", .{});
}

/// api-set and redistributable CRT names map onto the shim table's CRT.
fn shimLibrary(lib: []const u8) []const u8 {
    if (std.ascii.startsWithIgnoreCase(lib, "api-ms-win-crt-") or
        std.ascii.eqlIgnoreCase(lib, "vcruntime140.dll") or
        std.ascii.eqlIgnoreCase(lib, "vcruntime140_1.dll") or
        std.ascii.eqlIgnoreCase(lib, "msvcp140.dll")) return "ucrtbase.dll";
    if (std.ascii.startsWithIgnoreCase(lib, "api-ms-win-core-")) return "kernel32.dll";
    return lib;
}

const Call = struct { name: []const u8, args: std.ArrayList(u64) = .empty, ret: enum { u32, i32, u64, str } = .u64 };

const usage = "usage: winload64 --pin ROOT.dll=HEX [--pin DEP.dll=HEX ...] [--dll-dir DIR] [--check] ROOT.dll [--call EXPORT [--arg N ...] [--ret u32|i32|u64|str]] ...";

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    var ld: Loader = .{ .a = a, .io = init.io, .dll_dir = null };
    var root: ?[]const u8 = null;
    var check_only = false;
    var calls: std.ArrayList(Call) = .empty;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        const more = i + 1 < args.len;
        if (std.mem.eql(u8, arg, "--pin") and more) {
            i += 1;
            const eq = std.mem.indexOfScalar(u8, args[i], '=') orelse die(.usage, "--pin wants NAME=SHA256", .{});
            try ld.pins.put(a, ld.lower(std.fs.path.basename(args[i][0..eq])), args[i][eq + 1 ..]);
        } else if (std.mem.eql(u8, arg, "--dll-dir") and more) {
            i += 1;
            ld.dll_dir = args[i];
        } else if (std.mem.eql(u8, arg, "--check")) {
            check_only = true;
        } else if (std.mem.eql(u8, arg, "--call") and more) {
            i += 1;
            try calls.append(a, .{ .name = args[i] });
        } else if (std.mem.eql(u8, arg, "--arg") and more and calls.items.len > 0) {
            i += 1;
            const v = std.fmt.parseInt(i64, args[i], 0) catch die(.usage, "bad --arg {s}", .{args[i]});
            try calls.items[calls.items.len - 1].args.append(a, @bitCast(v));
        } else if (std.mem.eql(u8, arg, "--ret") and more and calls.items.len > 0) {
            i += 1;
            calls.items[calls.items.len - 1].ret = std.meta.stringToEnum(@TypeOf(calls.items[0].ret), args[i]) orelse die(.usage, "bad --ret {s}", .{args[i]});
        } else if (root == null and !std.mem.startsWith(u8, arg, "--")) {
            root = arg;
        } else die(.usage, usage, .{});
    }
    if (root == null) die(.usage, usage, .{});
    if (!check_only and !std.mem.eql(u8, init.environ_map.get("WINS_WINRUN_BOX") orelse "", "1"))
        die(.usage, "execution requires the boxed launcher; use winload64_box.py", .{});

    const root_idx = ld.map(root.?);
    ld.bind(root_idx);
    if (ld.missing.items.len != 0) die(.unresolved, "unresolved imports, nothing executed:\n{s}", .{ld.missing.items});
    // --call EXPORT targets the root; --call DLL!EXPORT any loaded image.
    for (calls.items) |c| if (callTarget(&ld, root_idx, c.name) == null) die(.unresolved, "no export {s}", .{c.name});

    var pdata: usize = 0;
    for (ld.images.items) |im| pdata += im.pdata_entries;
    std.debug.print("winload64: READY images={d} imports={d} tls_slots={d} delay_traps={d} pdata={d}\n", .{ ld.images.items.len, ld.n_imports, ld.n_tls, n_traps, pdata });
    for (ld.images.items) |im| std.debug.print("  {s} base=0x{x} tls={?d} tls_callbacks={d} entry=0x{x}\n", .{ im.name, im.base, im.tls_index, im.tls_cb_rvas.items.len, im.entry_rva });
    if (check_only) std.process.exit(0);

    ld.protectAll();

    // GS-based TEB/PEB (same layout winrun uses), one implicit-TLS block per image.
    const teb = try a.alignedAlloc(u8, .fromByteUnits(4096), 4096);
    const peb = try a.alignedAlloc(u8, .fromByteUnits(4096), 4096);
    const params = try a.alignedAlloc(u8, .fromByteUnits(4096), 4096);
    const tls_array = try a.alloc(usize, @max(ld.n_tls, 1) + 64);
    @memset(teb, 0);
    @memset(peb, 0);
    @memset(params, 0);
    @memset(tls_array, 0);
    for (ld.images.items) |im| if (im.tls_index) |k| {
        const block = try a.alloc(u8, @max(im.tls_template_len + im.tls_zero_fill, 16));
        @memset(block, 0);
        if (im.tls_template_len > 0) @memcpy(block[0..im.tls_template_len], im.img[im.tls_template_rva..][0..im.tls_template_len]);
        tls_array[k] = @intFromPtr(block.ptr);
    };
    var stack_probe: u8 = 0;
    const sp = @intFromPtr(&stack_probe);
    std.mem.writeInt(usize, teb[0x08..][0..8], std.mem.alignForward(usize, sp, 4096) + 4096, .little); // StackBase (approx.)
    std.mem.writeInt(usize, teb[0x10..][0..8], sp - 8 * 1024 * 1024 + 4096, .little); // StackLimit (8 MiB stack)
    std.mem.writeInt(usize, teb[0x30..][0..8], @intFromPtr(teb.ptr), .little); // NtCurrentTeb()
    std.mem.writeInt(usize, teb[0x40..][0..8], @as(usize, @intCast(linux.getpid())), .little); // ClientId.UniqueProcess
    std.mem.writeInt(usize, teb[0x58..][0..8], @intFromPtr(tls_array.ptr), .little); // ThreadLocalStoragePointer
    std.mem.writeInt(usize, teb[0x60..][0..8], @intFromPtr(peb.ptr), .little); // ProcessEnvironmentBlock
    std.mem.writeInt(usize, peb[0x10..][0..8], ld.images.items[root_idx].base, .little); // ImageBaseAddress
    std.mem.writeInt(usize, peb[0x18..][0..8], 0x10000, .little); // ProcessHeap (opaque)
    std.mem.writeInt(usize, peb[0x20..][0..8], @intFromPtr(params.ptr), .little); // ProcessParameters
    if (linux.errno(linux.syscall2(.arch_prctl, 0x1001, @intFromPtr(teb.ptr))) != .SUCCESS) die(.map_failed, "arch_prctl(ARCH_SET_GS) failed", .{});

    ld.initialize(root_idx);

    var out: [256]u8 = undefined;
    for (calls.items) |c| {
        const addr = callTarget(&ld, root_idx, c.name).?;
        var av = [4]u64{ 0, 0, 0, 0 };
        if (c.args.items.len > 4) die(.usage, "--call {s}: at most 4 integer args", .{c.name});
        for (c.args.items, 0..) |v, k| av[k] = v;
        const F = *const fn (u64, u64, u64, u64) callconv(W) u64;
        const r = (@as(F, @ptrFromInt(addr)))(av[0], av[1], av[2], av[3]);
        const s = switch (c.ret) {
            .u32 => try std.fmt.bufPrint(&out, "{d}", .{@as(u32, @truncate(r))}),
            .i32 => try std.fmt.bufPrint(&out, "{d}", .{@as(i32, @bitCast(@as(u32, @truncate(r))))}),
            .u64 => try std.fmt.bufPrint(&out, "0x{x}", .{r}),
            .str => if (r == 0) "(null)" else std.mem.span(@as([*:0]const u8, @ptrFromInt(r))),
        };
        std.debug.print("call {s} = {s}\n", .{ c.name, s });
    }
    std.process.exit(0);
}
