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
//!               6 mapping failed, 7 DllMain/TLS init failed,
//!               8 a trapped (unimplemented) import was called (--trap-unresolved),
//!               9 the loaded code crashed (crash report on stderr).
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

/// Delay imports that resolve to nothing (and, with --trap-unresolved, ANY unresolved
/// import) are bound to one of these traps; the trap reports which import was called
/// and exits 8. --trap-unresolved is a diagnostic instrument to find which missing
/// functions a DLL really calls; it never makes a run count as supported.
const max_traps = 1024;
var trap_names: [max_traps][]const u8 = undefined;
var n_traps: usize = 0;
fn trapCall(comptime k: usize) *const fn () callconv(W) noreturn {
    return &struct {
        fn f() callconv(W) noreturn {
            std.debug.print("winload64: TRAP called unimplemented import {s}\n", .{trap_names[k]});
            std.process.exit(8);
        }
    }.f;
}
const trap_table = blk: {
    @setEvalBranchQuota(20 * max_traps);
    var t: [max_traps]*const fn () callconv(W) noreturn = undefined;
    for (0..max_traps) |k| t[k] = trapCall(k);
    break :blk t;
};

var trap_all = false;

// ---------------------------------------------------------------- module registry
// GetModuleHandle*/LoadLibrary*/GetProcAddress over (a) the images winload64 mapped
// and (b) the system DLLs WINS emulates (pseudo-handles; never dereferenced by us).
// They take precedence over winrun's single-image stubs (GetProcAddress there is a
// stub that returns 0, GetModuleHandle only answers NULL).
var g_ld: ?*Loader = null;

const system_dlls = [_][]const u8{
    "kernel32.dll", "kernelbase.dll", "ntdll.dll",    "user32.dll",   "gdi32.dll",    "advapi32.dll",
    "ws2_32.dll",   "wsock32.dll",    "crypt32.dll",  "bcrypt.dll",   "ncrypt.dll",   "ole32.dll",
    "oleaut32.dll", "shell32.dll",    "shlwapi.dll",  "iphlpapi.dll", "winhttp.dll",  "dbghelp.dll",
    "winmm.dll",    "powrprof.dll",   "propsys.dll",  "ucrtbase.dll", "msvcrt.dll",   "version.dll",
    "secur32.dll",  "dnsapi.dll",     "wintrust.dll", "userenv.dll",  "comctl32.dll", "imm32.dll",
};
/// Pseudo-handle for system DLL k: high, page-aligned, distinct, never a real mapping.
fn sysHandle(k: usize) usize {
    return 0x7FFE_0000_0000 + (k << 20);
}

const ERROR_MOD_NOT_FOUND: u32 = 126;
const ERROR_PROC_NOT_FOUND: u32 = 127;

fn setLastError(code: u32) void {
    const f = winrun.lookup("kernel32.dll", "SetLastError") orelse return;
    (@as(*const fn (u32) callconv(W) void, @ptrFromInt(f)))(code);
}

/// "C:\x\KERNEL32" -> "kernel32.dll"; api-sets fold onto their host DLL.
fn moduleKey(buf: []u8, raw: []const u8) []const u8 {
    var name = raw;
    if (std.mem.lastIndexOfAny(u8, name, "\\/")) |i| name = name[i + 1 ..];
    const n = @min(name.len, buf.len - 4);
    _ = std.ascii.lowerString(buf[0..n], name[0..n]);
    var out = buf[0..n];
    if (std.mem.indexOfScalar(u8, out, '.') == null) {
        @memcpy(buf[n..][0..4], ".dll");
        out = buf[0 .. n + 4];
    }
    if (std.mem.startsWith(u8, out, "api-ms-win-crt-")) return "ucrtbase.dll";
    if (std.mem.startsWith(u8, out, "api-ms-win-") or std.mem.startsWith(u8, out, "ext-ms-win-")) return "kernel32.dll";
    return out;
}

fn handleFor(key: []const u8) usize {
    const ld = g_ld orelse return 0;
    if (ld.find(key)) |k| return ld.images.items[k].base;
    for (system_dlls, 0..) |d, k| if (std.mem.eql(u8, d, key)) return sysHandle(k);
    return 0;
}

fn utf16Key(buf: []u8, w: [*:0]const u16) []const u8 {
    var tmp: [260]u8 = undefined;
    var n: usize = 0;
    while (w[n] != 0 and n < tmp.len) : (n += 1) tmp[n] = if (w[n] < 0x80) @intCast(w[n]) else '?';
    return moduleKey(buf, tmp[0..n]);
}

fn rootBase() usize {
    const ld = g_ld orelse return 0;
    return ld.images.items[0].base;
}

fn moduleByName(key: []const u8, what: []const u8) usize {
    const h = handleFor(key);
    if (h == 0) {
        std.debug.print("winload64: {s}({s}) -> not loaded/emulated (ERROR_MOD_NOT_FOUND)\n", .{ what, key });
        setLastError(ERROR_MOD_NOT_FOUND);
    }
    return h;
}

fn GetModuleHandleW(name: ?[*:0]const u16) callconv(W) usize {
    var b: [272]u8 = undefined;
    return if (name) |n| moduleByName(utf16Key(&b, n), "GetModuleHandleW") else rootBase();
}
fn GetModuleHandleA(name: ?[*:0]const u8) callconv(W) usize {
    var b: [272]u8 = undefined;
    return if (name) |n| moduleByName(moduleKey(&b, std.mem.span(n)), "GetModuleHandleA") else rootBase();
}
fn GetModuleHandleExW(flags: u32, name: ?*const anyopaque, out: ?*usize) callconv(W) i32 {
    const FROM_ADDRESS: u32 = 0x4;
    var h: usize = 0;
    if (flags & FROM_ADDRESS != 0) {
        const addr = @intFromPtr(name);
        if (g_ld) |ld| for (ld.images.items) |im| {
            if (addr >= im.base and addr < im.base + im.img.len) h = im.base;
        };
        if (h == 0) setLastError(ERROR_MOD_NOT_FOUND);
    } else h = GetModuleHandleW(@ptrCast(@alignCast(name)));
    if (out) |o| o.* = h;
    return @intFromBool(h != 0);
}
fn GetModuleHandleExA(flags: u32, name: ?*const anyopaque, out: ?*usize) callconv(W) i32 {
    const FROM_ADDRESS: u32 = 0x4;
    if (flags & FROM_ADDRESS != 0) return GetModuleHandleExW(flags, name, out);
    const h = GetModuleHandleA(@ptrCast(name));
    if (out) |o| o.* = h;
    return @intFromBool(h != 0);
}
/// CreateEventExW(attrs, name, flags, access): flags 1 = manual reset, 2 = initial set.
fn CreateEventExW(attrs: ?*anyopaque, name: ?[*:0]const u16, flags: u32, access: u32) callconv(W) usize {
    _ = access;
    const f = winrun.lookup("kernel32.dll", "CreateEventW") orelse return 0;
    const CreateEventW = *const fn (?*anyopaque, i32, i32, ?[*:0]const u16) callconv(W) usize;
    return (@as(CreateEventW, @ptrFromInt(f)))(attrs, @intFromBool(flags & 1 != 0), @intFromBool(flags & 2 != 0), name);
}
fn LoadLibraryW(name: ?[*:0]const u16) callconv(W) usize {
    var b: [272]u8 = undefined;
    return if (name) |n| moduleByName(utf16Key(&b, n), "LoadLibraryW") else 0;
}
fn LoadLibraryA(name: ?[*:0]const u8) callconv(W) usize {
    var b: [272]u8 = undefined;
    return if (name) |n| moduleByName(moduleKey(&b, std.mem.span(n)), "LoadLibraryA") else 0;
}
fn LoadLibraryExW(name: ?[*:0]const u16, file: usize, flags: u32) callconv(W) usize {
    _ = file;
    _ = flags;
    return LoadLibraryW(name);
}
fn LoadLibraryExA(name: ?[*:0]const u8, file: usize, flags: u32) callconv(W) usize {
    _ = file;
    _ = flags;
    return LoadLibraryA(name);
}
fn FreeLibrary(h: usize) callconv(W) i32 {
    _ = h;
    return 1; // images stay mapped for the process lifetime
}
fn GetProcAddress(h: usize, name: ?[*:0]const u8) callconv(W) usize {
    const ld = g_ld orelse return 0;
    var symbuf: [16]u8 = undefined;
    const sym: []const u8 = if (@intFromPtr(name) < 0x10000)
        std.fmt.bufPrint(&symbuf, "#{d}", .{@intFromPtr(name)}) catch unreachable
    else
        std.mem.span(name.?);
    var lib: ?[]const u8 = null;
    for (ld.images.items) |im| if (im.base == h) {
        lib = im.name;
    };
    if (lib == null) for (system_dlls, 0..) |d, k| if (sysHandle(k) == h) {
        lib = d;
    };
    const l = lib orelse {
        setLastError(ERROR_MOD_NOT_FOUND);
        return 0;
    };
    const addr = ld.resolve(l, sym, 0) orelse {
        std.debug.print("winload64: GetProcAddress({s}, {s}) -> not implemented (ERROR_PROC_NOT_FOUND)\n", .{ l, sym });
        setLastError(ERROR_PROC_NOT_FOUND);
        return 0;
    };
    return addr;
}

// ---------------------------------------------------------------- virtual memory
// Windows semantics over mmap: regions reserved at 64 KiB granularity (MEM_RESERVE =
// PROT_NONE + NORESERVE), pages committed/decommitted inside a region with their own
// protection, MEM_RELEASE only at a region base, VirtualQuery/VirtualProtect answer
// from the same bookkeeping. Chromium's PartitionAlloc relies on all of it.
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_DECOMMIT: u32 = 0x4000;
const MEM_RELEASE: u32 = 0x8000;
const MEM_FREE: u32 = 0x10000;
const MEM_PRIVATE: u32 = 0x20000;
const MEM_IMAGE: u32 = 0x1000000;
const ERROR_INVALID_ADDRESS: u32 = 487;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
const GRAN: usize = 64 * 1024;
const PAGE: usize = 4096;

const Region = struct {
    base: usize,
    size: usize,
    alloc_protect: u32,
    pages: []u8, // per page: 0 = reserved, else the Windows PAGE_* protection (committed)
};
var regions: std.ArrayList(Region) = .empty;
var vm_lock: std.atomic.Mutex = .unlocked;
fn vmLock() void {
    while (!vm_lock.tryLock()) std.atomic.spinLoopHint();
}

fn vmAlloc() std.mem.Allocator {
    return std.heap.page_allocator;
}

fn linuxProt(p: u32) linux.PROT {
    return switch (p & 0xff) {
        0x01 => .{}, // PAGE_NOACCESS
        0x02 => .{ .READ = true },
        0x04, 0x08 => .{ .READ = true, .WRITE = true },
        0x10, 0x20 => .{ .READ = true, .EXEC = true },
        0x40, 0x80 => .{ .READ = true, .WRITE = true, .EXEC = true },
        else => .{ .READ = true, .WRITE = true },
    };
}

fn regionOf(addr: usize) ?*Region {
    for (regions.items) |*r| if (addr >= r.base and addr < r.base + r.size) return r;
    return null;
}

fn reserve(at: usize, size: usize, prot: u32) ?*Region {
    const len = std.mem.alignForward(usize, size, PAGE);
    var base: usize = 0;
    const flags: linux.MAP = .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .NORESERVE = true, .FIXED_NOREPLACE = at != 0 };
    if (at != 0) {
        if (at % GRAN != 0) return null;
        const rc = linux.mmap(@ptrFromInt(at), len, .{}, flags, -1, 0);
        if (linux.errno(rc) != .SUCCESS or rc != at) return null;
        base = rc;
    } else {
        // Over-reserve and trim so the region starts on the 64 KiB allocation granularity.
        const rc = linux.mmap(null, len + GRAN, .{}, flags, -1, 0);
        if (linux.errno(rc) != .SUCCESS) return null;
        base = std.mem.alignForward(usize, rc, GRAN);
        if (base > rc) _ = linux.munmap(@ptrFromInt(rc), base - rc);
        const tail = rc + len + GRAN - (base + len);
        if (tail > 0) _ = linux.munmap(@ptrFromInt(base + len), tail);
    }
    const pages = vmAlloc().alloc(u8, len / PAGE) catch {
        _ = linux.munmap(@ptrFromInt(base), len);
        return null;
    };
    @memset(pages, 0);
    regions.append(vmAlloc(), .{ .base = base, .size = len, .alloc_protect = prot, .pages = pages }) catch return null;
    return &regions.items[regions.items.len - 1];
}

fn VirtualAlloc(addr: ?*anyopaque, size: usize, kind: u32, prot: u32) callconv(W) ?*anyopaque {
    vmLock();
    defer vm_lock.unlock();
    if (size == 0 or kind & (MEM_COMMIT | MEM_RESERVE) == 0) {
        setLastError(ERROR_INVALID_PARAMETER);
        return null;
    }
    const want = @intFromPtr(addr);
    var r: *Region = undefined;
    var start: usize = undefined;
    if (want != 0 and regionOf(want) != null and kind & MEM_RESERVE == 0) {
        r = regionOf(want).?; // commit inside an existing reservation
        start = want & ~(PAGE - 1);
    } else if (kind & MEM_RESERVE != 0 or want == 0) {
        r = reserve(if (want != 0) want & ~(GRAN - 1) else 0, size + (want & (GRAN - 1)), prot) orelse {
            setLastError(if (want != 0) ERROR_INVALID_ADDRESS else ERROR_NOT_ENOUGH_MEMORY);
            return null;
        };
        start = if (want != 0) want & ~(PAGE - 1) else r.base;
        if (kind & MEM_COMMIT == 0) return @ptrFromInt(r.base);
    } else {
        setLastError(ERROR_INVALID_ADDRESS);
        return null;
    }
    const end = std.mem.alignForward(usize, (if (want != 0) want else r.base) + size, PAGE);
    if (end > r.base + r.size) {
        setLastError(ERROR_INVALID_ADDRESS);
        return null;
    }
    if (linux.errno(linux.mprotect(@ptrFromInt(start), end - start, linuxProt(prot))) != .SUCCESS) {
        setLastError(ERROR_NOT_ENOUGH_MEMORY);
        return null;
    }
    var pg = (start - r.base) / PAGE;
    while (pg < (end - r.base) / PAGE) : (pg += 1) r.pages[pg] = @truncate(if (prot & 0xff == 0) 4 else prot);
    return @ptrFromInt(if (want != 0) start else r.base);
}

fn VirtualFree(addr: ?*anyopaque, size: usize, kind: u32) callconv(W) i32 {
    vmLock();
    defer vm_lock.unlock();
    const a = @intFromPtr(addr);
    const r = regionOf(a) orelse {
        setLastError(ERROR_INVALID_ADDRESS);
        return 0;
    };
    if (kind & MEM_RELEASE != 0) {
        if (size != 0 or a != r.base) {
            setLastError(ERROR_INVALID_PARAMETER);
            return 0;
        }
        _ = linux.munmap(@ptrFromInt(r.base), r.size);
        vmAlloc().free(r.pages);
        _ = regions.swapRemove(@divExact(@intFromPtr(r) - @intFromPtr(regions.items.ptr), @sizeOf(Region)));
        return 1;
    }
    if (kind & MEM_DECOMMIT != 0) {
        const start = a & ~(PAGE - 1);
        const end = if (size == 0) r.base + r.size else std.mem.alignForward(usize, a + size, PAGE);
        if (end > r.base + r.size) {
            setLastError(ERROR_INVALID_PARAMETER);
            return 0;
        }
        // Drop the contents (next commit reads zeroes) and make the pages inaccessible.
        _ = linux.madvise(@ptrFromInt(start), end - start, linux.MADV.DONTNEED);
        _ = linux.mprotect(@ptrFromInt(start), end - start, .{});
        @memset(r.pages[(start - r.base) / PAGE .. (end - r.base) / PAGE], 0);
        return 1;
    }
    setLastError(ERROR_INVALID_PARAMETER);
    return 0;
}

fn VirtualProtect(addr: ?*anyopaque, size: usize, prot: u32, old: ?*u32) callconv(W) i32 {
    vmLock();
    defer vm_lock.unlock();
    const a = @intFromPtr(addr);
    const start = a & ~(PAGE - 1);
    const end = std.mem.alignForward(usize, a + @max(size, 1), PAGE);
    if (regionOf(a)) |r| {
        if (end > r.base + r.size) {
            setLastError(ERROR_INVALID_ADDRESS);
            return 0;
        }
        const first = r.pages[(start - r.base) / PAGE];
        if (first == 0) {
            setLastError(ERROR_INVALID_ADDRESS); // reserved, not committed
            return 0;
        }
        if (old) |o| o.* = first;
        if (linux.errno(linux.mprotect(@ptrFromInt(start), end - start, linuxProt(prot))) != .SUCCESS) return 0;
        @memset(r.pages[(start - r.base) / PAGE .. (end - r.base) / PAGE], @truncate(prot));
        return 1;
    }
    // Outside our regions (image sections, stacks): honour it, report RW as the old value.
    if (old) |o| o.* = 0x04;
    return @intFromBool(linux.errno(linux.mprotect(@ptrFromInt(start), end - start, linuxProt(prot))) == .SUCCESS);
}

/// MEMORY_BASIC_INFORMATION (x64, 48 bytes).
const MBI = extern struct { BaseAddress: usize, AllocationBase: usize, AllocationProtect: u32, PartitionId: u16, _p: u16 = 0, RegionSize: usize, State: u32, Protect: u32, Type: u32, _q: u32 = 0 };

fn VirtualQuery(addr: ?*const anyopaque, out: ?*MBI, len: usize) callconv(W) usize {
    if (out == null or len < @sizeOf(MBI)) {
        setLastError(24); // ERROR_BAD_LENGTH
        return 0;
    }
    vmLock();
    defer vm_lock.unlock();
    const a = @intFromPtr(addr) & ~(PAGE - 1);
    var m: MBI = .{ .BaseAddress = a, .AllocationBase = 0, .AllocationProtect = 0, .PartitionId = 0, .RegionSize = PAGE, .State = MEM_FREE, .Protect = 0x01, .Type = 0 };
    if (regionOf(a)) |r| {
        var pg = (a - r.base) / PAGE;
        const st = r.pages[pg];
        const first = pg;
        while (pg < r.pages.len and r.pages[pg] == st) pg += 1; // run of identical pages
        m = .{ .BaseAddress = a, .AllocationBase = r.base, .AllocationProtect = r.alloc_protect, .PartitionId = 0, .RegionSize = (pg - first) * PAGE, .State = if (st == 0) MEM_RESERVE else MEM_COMMIT, .Protect = if (st == 0) 0 else st, .Type = MEM_PRIVATE };
    } else if (g_ld) |ld| {
        for (ld.images.items) |im| if (a >= im.base and a < im.base + im.img.len) {
            m = .{ .BaseAddress = a, .AllocationBase = im.base, .AllocationProtect = 0x80, .PartitionId = 0, .RegionSize = im.base + im.img.len - a, .State = MEM_COMMIT, .Protect = 0x20, .Type = MEM_IMAGE };
        };
        if (m.State == MEM_FREE and a != 0) {
            // Not ours: committed RW private memory if mapped (stack, heap), else free.
            const probe = linux.madvise(@ptrFromInt(a), PAGE, linux.MADV.NORMAL);
            if (linux.errno(probe) == .SUCCESS) m = .{ .BaseAddress = a, .AllocationBase = a, .AllocationProtect = 0x04, .PartitionId = 0, .RegionSize = PAGE, .State = MEM_COMMIT, .Protect = 0x04, .Type = MEM_PRIVATE };
        }
    }
    out.?.* = m;
    return @sizeOf(MBI);
}

fn VirtualLock(addr: ?*anyopaque, size: usize) callconv(W) i32 {
    _ = addr;
    _ = size;
    return 1; // advisory: pages stay resident enough for a cleanroom process
}
fn VirtualUnlock(addr: ?*anyopaque, size: usize) callconv(W) i32 {
    _ = addr;
    _ = size;
    return 1;
}

fn registryOverride(lib: []const u8, sym: []const u8) ?usize {
    var b: [272]u8 = undefined;
    if (@import("winload64_sync.zig").lookup(moduleKey(&b, lib), sym)) |a| return a;
    if (std.mem.eql(u8, moduleKey(&b, lib), "ucrtbase.dll") or std.ascii.startsWithIgnoreCase(lib, "vcruntime140"))
        if (@import("winload64_ucrt.zig").lookup(sym)) |a| return a;
    if (!std.mem.eql(u8, moduleKey(&b, lib), "kernel32.dll") and !std.ascii.eqlIgnoreCase(lib, "kernelbase.dll")) return null;
    const table = .{
        .{ "GetModuleHandleW", &GetModuleHandleW },   .{ "GetModuleHandleA", &GetModuleHandleA },
        .{ "GetModuleHandleExW", &GetModuleHandleExW }, .{ "LoadLibraryW", &LoadLibraryW },
        .{ "GetModuleHandleExA", &GetModuleHandleExA }, .{ "CreateEventExW", &CreateEventExW },
        .{ "LoadLibraryA", &LoadLibraryA },           .{ "LoadLibraryExW", &LoadLibraryExW },
        .{ "LoadLibraryExA", &LoadLibraryExA },       .{ "FreeLibrary", &FreeLibrary },
        .{ "GetProcAddress", &GetProcAddress },       .{ "VirtualAlloc", &VirtualAlloc },
        .{ "VirtualFree", &VirtualFree },             .{ "VirtualProtect", &VirtualProtect },
        .{ "VirtualQuery", &VirtualQuery },           .{ "VirtualLock", &VirtualLock },
        .{ "VirtualUnlock", &VirtualUnlock },
    };
    inline for (table) |e| if (std.mem.eql(u8, sym, e[0])) return @intFromPtr(e[1]);
    return null;
}

// ---------------------------------------------------------------- crash report
// A fault inside a loaded image (e.g. MSVC __fastfail = `int 0x29`) is reported as
// signal, RIP and fault address mapped to IMAGE+RVA, the general registers, and the
// stack words that point into executable sections (candidate return addresses).
// Exit 9. Instrument only: a crash report never makes a run count as supported.
var crash_images: []const Image = &.{};

fn where(buf: []u8, addr: u64) []const u8 {
    for (crash_images) |im| if (addr >= im.base and addr < im.base + im.img.len)
        return std.fmt.bufPrint(buf, "{s}+0x{x}", .{ im.name, addr - im.base }) catch "?";
    return std.fmt.bufPrint(buf, "0x{x}", .{addr}) catch "?";
}

fn onCrash(sig: linux.SIG, info: *const linux.siginfo_t, ctx: ?*anyopaque) callconv(.c) void {
    _ = info;
    const g: [*]const u64 = @ptrFromInt(@intFromPtr(ctx.?) + 40); // ucontext.uc_mcontext.gregs
    const rip = g[16];
    const rsp = g[15];
    var b1: [128]u8 = undefined;
    var b2: [128]u8 = undefined;
    std.debug.print("winload64: CRASH signal {d} at {s} (trapno={d} err=0x{x} cr2={s})\n", .{ @intFromEnum(sig), where(&b1, rip), g[20], g[19], where(&b2, g[22]) });
    std.debug.print("  rax=0x{x} rbx=0x{x} rcx=0x{x} rdx=0x{x}\n  rsi=0x{x} rdi=0x{x} rbp=0x{x} rsp=0x{x}\n  r8=0x{x} r9=0x{x} r10=0x{x} r11=0x{x}\n", .{ g[13], g[11], g[14], g[12], g[9], g[8], g[10], rsp, g[0], g[1], g[2], g[3] });
    std.debug.print("  stack words pointing into executable sections (candidate return addresses):\n", .{});
    var n: usize = 0;
    var k: usize = 0;
    var mapped_page: usize = 0;
    while (k < 1024 and n < 24) : (k += 1) {
        const at = rsp + k * 8;
        const page = at & ~@as(usize, 4095);
        if (page != mapped_page) { // stop at the end of the mapped stack
            if (linux.errno(linux.madvise(@ptrFromInt(page), 4096, linux.MADV.NORMAL)) != .SUCCESS) break;
            mapped_page = page;
        }
        const v = @as(*const u64, @ptrFromInt(at)).*;
        for (crash_images) |im| if (v >= im.base and v < im.base + im.img.len and inExec(im.secs, v - im.base)) {
            std.debug.print("    [rsp+0x{x}] {s}\n", .{ k * 8, where(&b1, v) });
            n += 1;
        };
    }
    std.process.exit(9);
}

fn installCrashReport(images: []const Image) void {
    crash_images = images;
    var act: linux.Sigaction = .{ .handler = .{ .sigaction = &onCrash }, .mask = std.mem.zeroes(linux.sigset_t), .flags = linux.SA.SIGINFO | linux.SA.ONSTACK };
    for ([_]linux.SIG{ .SEGV, .BUS, .ILL, .FPE, .TRAP }) |s| _ = linux.sigaction(s, &act, null);
}

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
        if (registryOverride(lib, sym)) |addr| return addr;
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
                    } else if ((delay or trap_all) and n_traps < max_traps) {
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

/// outstr: the export takes `const char** out` first and returns the length;
/// winload64 passes a cell, then prints `length` bytes from *out.
const Call = struct { name: []const u8, args: std.ArrayList(u64) = .empty, ret: enum { u32, i32, u64, str, outstr } = .u64 };

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
        } else if (std.mem.eql(u8, arg, "--trap-unresolved")) {
            trap_all = true;
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

    g_ld = &ld;
    if (winrun.lookup("kernel32.dll", "SetLastError")) |f| @import("winload64_sync.zig").set_last_error = @ptrFromInt(f);
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

    installCrashReport(ld.images.items);
    ld.initialize(root_idx);

    var out: [256]u8 = undefined;
    for (calls.items) |c| {
        const addr = callTarget(&ld, root_idx, c.name).?;
        var av = [4]u64{ 0, 0, 0, 0 };
        var out_cell: u64 = 0;
        const shift: usize = if (c.ret == .outstr) 1 else 0;
        if (c.args.items.len + shift > 4) die(.usage, "--call {s}: at most 4 integer args", .{c.name});
        if (shift == 1) av[0] = @intFromPtr(&out_cell);
        for (c.args.items, 0..) |v, k| av[k + shift] = v;
        const F = *const fn (u64, u64, u64, u64) callconv(W) u64;
        const r = (@as(F, @ptrFromInt(addr)))(av[0], av[1], av[2], av[3]);
        const s = switch (c.ret) {
            .u32 => try std.fmt.bufPrint(&out, "{d}", .{@as(u32, @truncate(r))}),
            .i32 => try std.fmt.bufPrint(&out, "{d}", .{@as(i32, @bitCast(@as(u32, @truncate(r))))}),
            .u64 => try std.fmt.bufPrint(&out, "0x{x}", .{r}),
            .str => if (r == 0) "(null)" else std.mem.span(@as([*:0]const u8, @ptrFromInt(r))),
            .outstr => if (out_cell == 0) "(null)" else @as([*]const u8, @ptrFromInt(out_cell))[0..@min(@as(usize, @truncate(r)), 4096)],
        };
        std.debug.print("call {s} = {s}\n", .{ c.name, s });
    }
    std.process.exit(0);
}
