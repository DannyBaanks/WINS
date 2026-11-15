//! WINS winrun32: Native Linux 32-bit x86 PE Loader (Zero Wine).
//! Loads 32-bit Windows executables (such as FalloutNV.exe) directly into memory,
//! maps the sections at ImageBase (0x00400000), configures the x86 TIB/TEB via
//! Linux set_thread_area syscall, resolves the Import Address Table (IAT),
//! provides Steam DRM, Bink Video, Kernel32 and User32 shims, and invokes the entry point.

const std = @import("std");
const linux = std.os.linux;
const d3d9 = @import("wins_d3d9.zig");
// The shared API libraries. winrun32 grew its own partial copy of this surface
// (Kernel32 through line ~1900, plus steam/bink/d3d9), which left 87 of 7zr's
// 139 imports unhandled and silently routed to a stub returning 0. Anything
// this file's local table does not know is delegated to these modules, the
// same ones winrun_impl.zig uses, instead of returning the null stub.
const kernel32_mod = @import("winrun_kernel32.zig");
const msvcrt_mod = @import("winrun_msvcrt.zig");
const vorbis_mod = @import("winrun_vorbis.zig");
const extra_dlls_mod = @import("winrun_extra_dlls.zig");
const dsound_mod = @import("wins_dsound.zig");
const dshow_mod = @import("wins_dshow.zig");
const user32_mod = @import("wins_user32.zig");
const dinput_mod = @import("wins_dinput.zig");
const bink_mod = @import("wins_bink.zig");
// winrun_gui_support and x11_window are NOT imported: they need static libX11,
// which is unavailable for the i386 target this loader builds for.
const ordinals_mod = @import("winrun_ordinals.zig");
const threads_mod = @import("winrun_threads.zig");

const W: std.builtin.CallingConvention = .winapi;

// Win32 / PE Constants
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const PE32_MAGIC: u16 = 0x010b;

const Section = struct {
    name: [8]u8,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    characteristics: u32,
};

const UserDesc = extern struct {
    entry_number: c_uint,
    base_addr: c_ulong,
    limit: c_uint,
    flags: u32,
};

// ============================================================================
// Crash Interception and Diagnostic Signal Handlers
// ============================================================================

const Sigcontext = extern struct {
    gs: u16, __gsh: u16,
    fs: u16, __fsh: u16,
    es: u16, __esh: u16,
    ds: u16, __dsh: u16,
    edi: u32,
    esi: u32,
    ebp: u32,
    esp: u32,
    ebx: u32,
    edx: u32,
    ecx: u32,
    eax: u32,
    trapno: u32,
    err: u32,
    eip: u32,
    cs: u16, __csh: u16,
    eflags: u32,
    esp_at_signal: u32,
    ss: u16, __ssh: u16,
    fpstate: ?*anyopaque,
    oldmask: u32,
    cr2: u32,
};

const Ucontext = extern struct {
    uc_flags: u32,
    uc_link: ?*Ucontext,
    uc_stack: extern struct {
        ss_sp: ?*anyopaque,
        ss_flags: i32,
        ss_size: usize,
    },
    uc_mcontext: Sigcontext,
    uc_sigmask: [2]u32,
};

// Set once from WINS_CRASH_TRAP=1. When a debugger is attached, trapping after
// the report keeps the process alive for inspection instead of exit_group()ing,
// which destroys the frame state gdb would need.
var g_crash_trap: bool = false;

var g_probe_ebx: u32 = 0;
var g_probe_ecx: u32 = 0;
var g_probe_edx: u32 = 0;

fn sigHandler(sig: linux.SIG, info: *const linux.siginfo_t, ctx_ptr: ?*anyopaque) callconv(.c) void {
    std.debug.print("\n=======================================================\n", .{});
    std.debug.print("CRASH INTERCEPTED: signal {d}\n", .{@intFromEnum(sig)});
    std.debug.print("Faulting Memory Address: 0x{x:0>8}\n", .{@intFromPtr(info.fields.sigfault.addr)});
    if (ctx_ptr) |ctx| {
        const uctx: *const Ucontext = @ptrCast(@alignCast(ctx));
        std.debug.print("CPU Register State:\n", .{});
        std.debug.print("  EIP: 0x{x:0>8}  ESP: 0x{x:0>8}  EBP: 0x{x:0>8}\n", .{
            uctx.uc_mcontext.eip, uctx.uc_mcontext.esp, uctx.uc_mcontext.ebp,
        });
        std.debug.print("  EAX: 0x{x:0>8}  EBX: 0x{x:0>8}  ECX: 0x{x:0>8}  EDX: 0x{x:0>8}\n", .{
            uctx.uc_mcontext.eax, uctx.uc_mcontext.ebx, uctx.uc_mcontext.ecx, uctx.uc_mcontext.edx,
        });
        std.debug.print("  ESI: 0x{x:0>8}  EDI: 0x{x:0>8}  EFLAGS: 0x{x:0>8}\n", .{
            uctx.uc_mcontext.esi, uctx.uc_mcontext.edi, uctx.uc_mcontext.eflags,
        });

        const esp_val = uctx.uc_mcontext.esp;
        // Which module holds the faulting instruction? The name is the only
        // thing that says whether the client, libc, or the loader is at fault.
        describeAddr(uctx.uc_mcontext.eip);
        // The whole map: when the fault is in the guest, the module table is
        // the only thing that says WHICH guest module died, and the loader
        // knows no other way to name it.
        {
            const fd_maps = linux.open("/proc/self/maps", .{ .ACCMODE = .RDONLY }, 0);
            if (linux.errno(fd_maps) == .SUCCESS) {
                defer _ = linux.close(@intCast(fd_maps));
                var buf_maps: [16 * 1024]u8 = undefined;
                const rn = linux.read(@intCast(fd_maps), &buf_maps, buf_maps.len);
                if (rn > 0) {
                    std.debug.print("  --- maps at crash ---\n", .{});
                    var it = std.mem.splitScalar(u8, buf_maps[0..@intCast(rn)], '\n');
                    while (it.next()) |line| std.debug.print("    {s}\n", .{line});
                }
            }
        }
        if (esp_val > 0x1000 and esp_val < 0xFFFFF000) {
            const stack_words: [*]const u32 = @ptrFromInt(esp_val);
            std.debug.print("Stack Dump (top 8 dwords at ESP):\n", .{});
            for (0..8) |i| {
                std.debug.print("  [ESP+0x{x:0>2}]: 0x{x:0>8}\n", .{ i * 4, stack_words[i] });
            }

            // Walk the whole guest stack looking for words that are addresses
            // inside the guest image. A call into a null pointer still leaves the
            // return address of its caller behind, and that is the only way to
            // name the instruction that jumped once EIP itself is 0.
            std.debug.print("  Guest return addresses on the stack (lowest first):\n", .{});
            var printed: usize = 0;
            var addr = @intFromPtr(&stack_words[0]);
            const stack_top = @max(addr + 4096, g_guest_stack_base);
            while (addr + 4 <= stack_top and printed < 8) : (addr += 4) {
                const w: usize = @as(*const usize, @ptrFromInt(addr)).*;
                if (isGuestAddr(w) or (g_guest_stack_base != 0 and (w == g_guest_stack_base or w == g_guest_stack_base - 0x1000))) {
                    std.debug.print("    0x{x:0>8} -> [0x{x}] ", .{ addr, w });
                    if (isGuestAddr(w)) {
                        // Bytes just before the return address are the tail of
                        // the call/jmp that got us here.
                        const b: [*]const u8 = @ptrFromInt(w);
                        var k: usize = 8;
                        while (k > 0) : (k -= 1) std.debug.print("{x:0>2} ", .{b[k - 1]});
                    }
                    std.debug.print("\n", .{});
                    printed += 1;
                }
            }
            if (printed == 0) std.debug.print("    (none: the stack holds no guest address)\n", .{});

            // Memory behind each register, read with process_vm_readv so an
            // unmapped address reports "unreadable" instead of faulting again.
            // (FalloutNV New Game: the factory index lives at [EBX+0x58].)
            {
                const regs = [_]struct { n: []const u8, v: usize }{
                    .{ .n = "EAX", .v = uctx.uc_mcontext.eax }, .{ .n = "EBX", .v = uctx.uc_mcontext.ebx },
                    .{ .n = "ECX", .v = uctx.uc_mcontext.ecx }, .{ .n = "EDX", .v = uctx.uc_mcontext.edx },
                    .{ .n = "ESI", .v = uctx.uc_mcontext.esi }, .{ .n = "EDI", .v = uctx.uc_mcontext.edi },
                    .{ .n = "EBP", .v = uctx.uc_mcontext.ebp },
                };
                for (regs) |r| {
                    var words: [32]u32 = undefined;
                    var local = [_]std.posix.iovec{.{ .base = @ptrCast(&words), .len = @sizeOf(@TypeOf(words)) }};
                    var remote = [_]std.posix.iovec_const{.{ .base = @ptrFromInt(@max(r.v, 1)), .len = @sizeOf(@TypeOf(words)) }};
                    const got = linux.process_vm_readv(linux.getpid(), &local, &remote, 0);
                    if (r.v < 0x1000 or linux.errno(got) != .SUCCESS or got != @sizeOf(@TypeOf(words))) continue;
                    std.debug.print("  [{s}=0x{x:0>8}]:", .{ r.n, r.v });
                    for (words, 0..) |w, i| {
                        if (i % 8 == 0) std.debug.print("\n    +0x{x:0>2}:", .{i * 4});
                        std.debug.print(" {x:0>8}", .{w});
                    }
                    std.debug.print("\n", .{});
                }
            }

            // The object behind a null field dereference. By the time the fault
            // lands, EAX is the field that was read, but EDI is usually still the
            // pointer the object came from, so `[EDI]` names the base. This is how
            // "the whole object is zero" was discovered on 7zr: an entirely blank
            // block means it was never constructed, which no register dump shows.
            const edi_val = uctx.uc_mcontext.edi;
            // Every read here goes through process_vm_readv: a register that
            // holds a plain number (EAX = 0xba26 bytes on FalloutNV's SIGFPE)
            // is not a pointer, and dereferencing it faulted inside this
            // handler and cut the report short.
            if (edi_val > 0x1000 and edi_val + 8 < 0xFFFFF000) {
                var first: [1]u32 = undefined;
                const obj: usize = if (crashRead(edi_val, &first)) first[0] else 0;
                // Not gated to the guest image: a heap block from our own malloc is
                // a valid host address.
                var block: [0x300 / 4]u32 = undefined;
                var base: usize = 0;
                if (obj > 0x1000 and obj + 0x300 < 0xFFFFF000 and crashRead(obj, &block)) {
                    base = obj;
                } else if (crashRead(edi_val, &block)) {
                    base = edi_val;
                }
                if (base != 0) {
                    var nonzeros: usize = 0;
                    for (block) |v| {
                        if (v != 0) nonzeros += 1;
                    }
                    std.debug.print("  Object base [EDI=0x{x}] = 0x{x}: {d} non-zero words in +0x000..0x300\n", .{ edi_val, base, nonzeros });
                    if (nonzeros > 0 and nonzeros < 64) {
                        for (block, 0..) |v, i| {
                            if (v != 0) std.debug.print("    +0x{x:0>3}: 0x{x:0>8}\n", .{ i * 4, v });
                        }
                    } else if (nonzeros >= 64) {
                        std.debug.print("    (too populated to summarise; the object was likely constructed)\n", .{});
                    } else {
                        std.debug.print("    ALL ZERO: uninitialised memory, never constructed by the guest.\n", .{});
                    }
                }
            }

            // The sub-object the guest was about to dereference. EAX survives a
            // faulting `mov (%eax),%edi`-style load when the fault is on a
            // *different* access, and for this crash it names the object whose
            // +4 field came back null.
            const eax_val = uctx.uc_mcontext.eax;
            var sub: [0x40 / 4]u32 = undefined;
            if (eax_val > 0x1000 and eax_val + 0x40 < 0xFFFFF000 and crashRead(eax_val, &sub)) {
                var nn: usize = 0;
                for (sub) |v| {
                    if (v != 0) nn += 1;
                }
                std.debug.print("  Sub-object at EAX=0x{x}: {d} non-zero words in +0x00..0x40\n", .{ eax_val, nn });
                if (nn > 0 and nn < 24) {
                    for (sub, 0..) |v, i| {
                        if (v != 0) std.debug.print("    +0x{x:0>3}: 0x{x:0>8}\n", .{ i * 4, v });
                    }
                }
            }
        }
    }
    std.debug.print("=======================================================\n", .{});
    if (g_crash_trap) {
        // A debugger gets the frame intact: trap here instead of dying.
        std.debug.print("[WINS:winrun32] WINS_CRASH_TRAP=1: trapping for the debugger.\n", .{});
        asm volatile ("int3");
    }
    linux.exit_group(139);
}

/// Copies `out.len` words from `addr` without touching the address directly,
/// so an unmapped or non-pointer value answers false instead of faulting.
fn crashRead(addr: usize, out: []u32) bool {
    const bytes = out.len * @sizeOf(u32);
    var local = [_]std.posix.iovec{.{ .base = @ptrCast(out.ptr), .len = bytes }};
    var remote = [_]std.posix.iovec_const{.{ .base = @ptrFromInt(@max(addr, 1)), .len = bytes }};
    const got = linux.process_vm_readv(linux.getpid(), &local, &remote, 0);
    return linux.errno(got) == .SUCCESS and got == bytes;
}

fn installCrashHandlers() void {
    var sa = linux.Sigaction{
        .handler = .{ .sigaction = &sigHandler },
        .mask = [_]c_ulong{0} ** 2,
        .flags = 0x00000004, // SA_SIGINFO
    };
    _ = linux.sigaction(linux.SIG.SEGV, &sa, null);
    _ = linux.sigaction(linux.SIG.BUS, &sa, null);
    _ = linux.sigaction(linux.SIG.ILL, &sa, null);
    // Integer division by zero: FalloutNV exited with status 136 (SIGFPE)
    // and no report before this was added.
    _ = linux.sigaction(linux.SIG.FPE, &sa, null);
}

// ============================================================================
// Core Win32 Heap & Memory Shims (Kernel32)
// ============================================================================

threadlocal var g_last_error: u32 = 0;
var g_tls_bitmap: u64 = 0;
threadlocal var g_tls_thread_slots: [64]?*anyopaque = [_]?*anyopaque{null} ** 64;
var g_alloc_prot: u32 = 0x04;

const HEAP_MAGIC: u32 = 0x57494E53; // "WINS"
/// Header in front of every block the loader hands to the guest.
///
/// The magic is what makes a release safe. HeapFree may only release a block
/// it can prove came from HeapAlloc; without the tag, a guest that frees a
/// pointer it did not get from us makes the loader munmap an arbitrary range,
/// and that range can be the real Steam client's heap. Measured: the client
/// then aborted with "malloc(): unaligned tcache chunk detected", and the
/// crash-time map showed its [heap] gone.
///
/// The layout is shared with winrun_kernel32.zig, so a block allocated
/// through either heap implementation can be freed through either one.
const HeapHeader = extern struct {
    magic: u32,
    total: u32,
    bytes: u32,
    pad: u32,
};

fn HeapAlloc(hHeap: usize, dwFlags: u32, dwBytes: usize) callconv(W) ?*anyopaque {
    _ = hHeap;
    const total = std.mem.alignForward(usize, dwBytes + @sizeOf(HeapHeader), 4096);
    const prot = linux.PROT{ .READ = true, .WRITE = true };
    const flags = linux.MAP{ .TYPE = .PRIVATE, .ANONYMOUS = true };
    const ptr = linux.mmap(null, total, prot, flags, -1, 0);
    if (linux.errno(ptr) != .SUCCESS) return null;
    const hdr: *HeapHeader = @ptrFromInt(ptr);
    hdr.magic = HEAP_MAGIC;
    hdr.total = @intCast(total);
    hdr.bytes = @intCast(dwBytes);
    hdr.pad = 0;
    const user_ptr: [*]u8 = @ptrFromInt(ptr + @sizeOf(HeapHeader));
    if ((dwFlags & 0x00000008) != 0) { // HEAP_ZERO_MEMORY
        @memset(user_ptr[0..dwBytes], 0);
    }
    return user_ptr;
}

fn HeapFree(hHeap: usize, dwFlags: u32, lpMem: ?*anyopaque) callconv(W) i32 {
    _ = hHeap; _ = dwFlags;
    if (lpMem) |p| {
        const u8_ptr: [*]u8 = @ptrCast(p);
        const hdr_ptr = u8_ptr - @sizeOf(HeapHeader);
        const hdr: *HeapHeader = @ptrCast(@alignCast(hdr_ptr));
        if (hdr.magic == HEAP_MAGIC) {
            // hdr.total is the whole mapping, so freeing releases all of it.
            _ = linux.munmap(hdr_ptr, hdr.total);
            return 1;
        }
        // Not one of ours. Releasing it would unmap whatever the address
        // happens to point at, which may be the real client's heap.
        std.debug.print("[WINS:Kernel32] HeapFree: 0x{x} was not allocated here; leaving it alone\n", .{@intFromPtr(p)});
    }
    return 0;
}

fn HeapReAlloc(hHeap: usize, dwFlags: u32, lpMem: ?*anyopaque, dwBytes: usize) callconv(W) ?*anyopaque {
    if (lpMem == null) return HeapAlloc(hHeap, dwFlags, dwBytes);
    const new_mem = HeapAlloc(hHeap, dwFlags, dwBytes) orelse return null;
    const u8_ptr: [*]const u8 = @ptrCast(lpMem.?);
    const hdr_ptr = u8_ptr - @sizeOf(HeapHeader);
    const hdr: *const HeapHeader = @ptrCast(@alignCast(hdr_ptr));
    if (hdr.magic == HEAP_MAGIC) {
        const old_user_size = hdr.bytes;
        const copy_len = @min(old_user_size, dwBytes);
        const new_u8: [*]u8 = @ptrCast(new_mem);
        @memcpy(new_u8[0..copy_len], u8_ptr[0..copy_len]);
        _ = HeapFree(hHeap, 0, lpMem);
    }
    return new_mem;
}

fn HeapSize(hHeap: usize, dwFlags: u32, lpMem: ?*anyopaque) callconv(W) usize {
    _ = hHeap; _ = dwFlags;
    if (lpMem) |p| {
        const u8_ptr: [*]u8 = @ptrCast(p);
        const hdr_ptr = u8_ptr - @sizeOf(HeapHeader);
        const hdr: *const HeapHeader = @ptrCast(@alignCast(hdr_ptr));
        if (hdr.magic == HEAP_MAGIC) {
            return hdr.bytes;
        }
    }
    return 0;
}

fn GetProcessHeap() callconv(W) usize {
    return 0x00010000;
}

fn HeapCreate(flOptions: u32, dwInitialSize: usize, dwMaximumSize: usize) callconv(W) usize {
    _ = flOptions; _ = dwInitialSize; _ = dwMaximumSize;
    return 0x00020000;
}

fn HeapDestroy(hHeap: usize) callconv(W) i32 {
    _ = hHeap;
    return 1;
}

const MEMORY_BASIC_INFORMATION = extern struct {
    BaseAddress: usize,
    AllocationBase: usize,
    AllocationProtect: u32,
    RegionSize: usize,
    State: u32,
    Protect: u32,
    Type: u32,
};

fn VirtualQuery(lpAddress: ?*const anyopaque, lpBuffer: ?*anyopaque, dwLength: usize) callconv(W) usize {
    if (lpBuffer == null or dwLength < @sizeOf(MEMORY_BASIC_INFORMATION)) return 0;
    const addr = @intFromPtr(lpAddress);
    const page_base = addr & ~@as(usize, 0xFFF);
    const mbi: *MEMORY_BASIC_INFORMATION = @ptrCast(@alignCast(lpBuffer.?));
    mbi.BaseAddress = page_base;
    mbi.AllocationBase = page_base;
    mbi.AllocationProtect = 0x40; // PAGE_EXECUTE_READWRITE
    mbi.RegionSize = 0x10000;     // 64 KB
    mbi.State = 0x1000;          // MEM_COMMIT
    mbi.Protect = 0x40;
    mbi.Type = 0x20000;          // MEM_PRIVATE
    return @sizeOf(MEMORY_BASIC_INFORMATION);
}

fn IsBadReadPtr(lp: ?*const anyopaque, ucb: usize) callconv(W) i32 {
    if (lp == null and ucb > 0) return 1;
    return 0;
}

fn IsBadWritePtr(lp: ?*anyopaque, ucb: usize) callconv(W) i32 {
    if (lp == null and ucb > 0) return 1;
    return 0;
}

fn IsBadCodePtr(lp: ?*const anyopaque) callconv(W) i32 {
    if (lp == null) return 1;
    return 0;
}

/// Ranges that must not be unmapped by a caller-supplied VirtualAlloc address.
///
/// A first attempt removed MAP_FIXED entirely, which broke the guest: it maps
/// its own stub image at the base it asks for (0x10000000, read from the PE
/// header), and honouring that request is load-bearing. So the address is
/// honoured, except where it would destroy memory that is not the guest's:
/// glibc's heap and the real Steam client's mappings. Both are read from
/// /proc/self/maps right after the client is loaded, so the list is measured
/// rather than guessed. Measured consequence of ignoring this: the real client
/// aborted with "malloc(): unaligned tcache chunk detected" once the guest had
/// reserved over its heap.
const ProtectedRange = struct { lo: usize, hi: usize };
var g_protected: [64]ProtectedRange = [_]ProtectedRange{.{ .lo = 0, .hi = 0 }} ** 64;

var g_protect_done = false;

fn protectRange(lo: usize, hi: usize) void {
    for (g_protected) |r| {
        if (r.hi != 0 and r.lo == lo) return;
    }
    for (&g_protected) |*r| {
        if (r.lo == 0 and r.hi == 0) {
            r.* = .{ .lo = lo, .hi = hi };
            return;
        }
    }
}

fn rangeIsProtected(lo: usize, hi: usize) bool {
    for (g_protected) |r| {
        if (r.hi != 0 and lo < r.hi and hi > r.lo) return true;
    }
    return false;
}

var g_maps_buf: [512 * 1024]u8 = undefined;

/// Name the mapping that holds `addr`, so a fault can be attributed to a module
/// instead of guessed at.
fn describeAddr(addr: usize) void {
    const fd = linux.open("/proc/self/maps", .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(fd) != .SUCCESS) return;
    defer _ = linux.close(@intCast(fd));
    // The whole file: with the host libraries loaded it is far beyond 16 KB,
    // and a truncated read named real code "(unmapped)". Static buffer, so a
    // signal handler does not need half a megabyte of stack.
    var total: usize = 0;
    while (total < g_maps_buf.len) {
        const rn = linux.read(@intCast(fd), g_maps_buf[total..].ptr, g_maps_buf.len - total);
        if (linux.errno(rn) != .SUCCESS or rn == 0) break;
        total += rn;
    }
    var lines = std.mem.splitScalar(u8, g_maps_buf[0..total], '\n');
    while (lines.next()) |line| {
        const dash = std.mem.indexOfScalar(u8, line, '-') orelse continue;
        const mlo = std.fmt.parseInt(usize, line[0..dash], 16) catch continue;
        const rest = line[dash + 1 ..];
        const sp = std.mem.indexOfScalar(u8, rest, ' ') orelse continue;
        const mhi = std.fmt.parseInt(usize, rest[0..sp], 16) catch continue;
        if (addr >= mlo and addr < mhi) {
            std.debug.print("  EIP 0x{x:0>8} is in: {s} (+0x{x} into the mapping)\n", .{ addr, line, addr - mlo });
            return;
        }
    }
    std.debug.print("  EIP 0x{x:0>8} is in: (unmapped)\n", .{addr});
}

/// Print the mappings that overlap [lo, hi), so a collision can be named
/// instead of guessed at.
fn describeOverlap(lo: usize, hi: usize) void {
    const fd = linux.open("/proc/self/maps", .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(fd) != .SUCCESS) return;
    defer _ = linux.close(@intCast(fd));
    // The whole file: with the host libraries loaded it is far beyond 16 KB,
    // and a truncated read named real code "(unmapped)". Static buffer, so a
    // signal handler does not need half a megabyte of stack.
    var total: usize = 0;
    while (total < g_maps_buf.len) {
        const rn = linux.read(@intCast(fd), g_maps_buf[total..].ptr, g_maps_buf.len - total);
        if (linux.errno(rn) != .SUCCESS or rn == 0) break;
        total += rn;
    }
    var lines = std.mem.splitScalar(u8, g_maps_buf[0..total], '\n');
    while (lines.next()) |line| {
        const dash = std.mem.indexOfScalar(u8, line, '-') orelse continue;
        const mlo = std.fmt.parseInt(usize, line[0..dash], 16) catch continue;
        const rest = line[dash + 1 ..];
        const sp = std.mem.indexOfScalar(u8, rest, ' ') orelse continue;
        const mhi = std.fmt.parseInt(usize, rest[0..sp], 16) catch continue;
        if (lo < mhi and hi > mlo) std.debug.print("    overlapping: {s}\n", .{line});
    }
}

/// Is any part of [lo, hi) mapped by something that is not the guest's own?
///
/// Read from /proc/self/maps at the moment of the question, because the
/// snapshot in g_protected is taken once and goes stale: the real client
/// creates thread stacks and arenas after it, and those are anonymous, so
/// they never appear in the named-region filter the snapshot uses. A guest
/// reservation placed over one of those puts the guest's writes on top of the
/// client's live memory, which is what the client reports as "malloc():
/// unaligned tcache chunk detected": the bad tcache entry was a tick count
/// the client had written into a chunk the guest had taken over.
///
/// The guest's own memory does not count as foreign. The guest asks for its
/// module images section by section -- 0x10000000 for the whole image, then
/// 0x10001000, 0x10042000, 0x1005a000, 0x10063000 for the sections inside it
/// -- so the second request lands on a range the loader already mapped for the
/// guest. Honouring that is load-bearing; relocating it breaks the guest.
fn rangeIsForeign(lo: usize, hi: usize) bool {
    const fd = linux.open("/proc/self/maps", .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(fd) != .SUCCESS) {
        // If the maps cannot be read, assume the worst: a reservation that
        // silently lands on someone else's memory is the failure mode this
        // whole check exists to prevent.
        return true;
    }
    defer _ = linux.close(@intCast(fd));
    var buf: [16 * 1024]u8 = undefined;
    const rn = linux.read(@intCast(fd), &buf, buf.len);
    if (linux.errno(rn) != .SUCCESS) return true;
    var lines = std.mem.splitScalar(u8, buf[0..@intCast(rn)], '\n');
    while (lines.next()) |line| {
        const dash = std.mem.indexOfScalar(u8, line, '-') orelse continue;
        const mlo = std.fmt.parseInt(usize, line[0..dash], 16) catch continue;
        const rest = line[dash + 1 ..];
        const sp = std.mem.indexOfScalar(u8, rest, ' ') orelse continue;
        const mhi = std.fmt.parseInt(usize, rest[0..sp], 16) catch continue;
        if (lo < mhi and hi > mlo) {
            const olo = @max(mlo, lo);
            const ohi = @min(mhi, hi);
            if (!rangeIsGuestOwned(olo, ohi)) return true;
        }
    }
    return false;
}

/// Is [lo, hi) inside memory the loader made for the guest?
fn rangeIsGuestOwned(lo: usize, hi: usize) bool {
    for (g_reservations) |r| {
        if (r.size != 0 and lo >= r.base and hi <= r.base + r.size) return true;
    }
    if (g_guest_base != 0 and lo >= g_guest_base and hi <= g_guest_end) return true;
    if (g_image_reserve_base != 0 and lo >= g_image_reserve_base and hi <= g_image_reserve_end) return true;
    if (g_guest_stack_base != 0 and lo >= g_guest_stack_end and hi <= g_guest_stack_base) return true;
    return false;
}

/// Read /proc/self/maps and protect glibc's heap plus everything the real Steam
/// client has mapped. Called once the client is loaded, because before that
/// there is nothing of theirs to protect.
fn protectForeignMemory() void {
    const fd = linux.open("/proc/self/maps", .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(fd) != .SUCCESS) return;
    defer _ = linux.close(@intCast(fd));
    // The whole file: with the host libraries loaded it is far beyond 16 KB,
    // and a truncated read named real code "(unmapped)". Static buffer, so a
    // signal handler does not need half a megabyte of stack.
    var total: usize = 0;
    while (total < g_maps_buf.len) {
        const rn = linux.read(@intCast(fd), g_maps_buf[total..].ptr, g_maps_buf.len - total);
        if (linux.errno(rn) != .SUCCESS or rn == 0) break;
        total += rn;
    }
    var lines = std.mem.splitScalar(u8, g_maps_buf[0..total], '\n');
    while (lines.next()) |line| {
        const dash = std.mem.indexOfScalar(u8, line, '-') orelse continue;
        const lo = std.fmt.parseInt(usize, line[0..dash], 16) catch continue;
        const rest = line[dash + 1 ..];
        const sp = std.mem.indexOfScalar(u8, rest, ' ') orelse continue;
        const hi = std.fmt.parseInt(usize, rest[0..sp], 16) catch continue;
        if (std.mem.indexOf(u8, line, "[heap]") != null or
            std.mem.indexOf(u8, line, "steamclient.so") != null or
            std.mem.indexOf(u8, line, "libc.so") != null or
            std.mem.indexOf(u8, line, "libstdc++") != null or
            std.mem.indexOf(u8, line, "libm.so") != null)
        {
            protectRange(lo, hi);
        }
    }
}

fn VirtualAlloc(lpAddress: ?*anyopaque, dwSize: usize, flAllocationType: u32, flProtect: u32) callconv(W) ?*anyopaque {
    if (dwSize == 0) {
        g_last_error = 87; // ERROR_INVALID_PARAMETER
        return null;
    }
    const prot = linux.PROT{
        .READ = (flProtect & 0x66) != 0,
        .WRITE = (flProtect & 0x44) != 0,
        .EXEC = (flProtect & 0xF0) != 0,
    };
    // Committing an already reserved range must preserve its contents. Mapping
    // anonymous memory with MAP_FIXED here silently replaced previously
    // committed pages with zeroes. Only protect pages within a reservation we
    // own; never remap another component's memory.
    if (lpAddress != null and (flAllocationType & 0x3000) == 0x1000) {
        const address = @intFromPtr(lpAddress.?);
        const end = std.math.add(usize, address, dwSize) catch {
            g_last_error = 487;
            return null;
        };
        if (end > std.math.maxInt(usize) - 4095) {
            g_last_error = 487;
            return null;
        }
        const start_page = address & ~@as(usize, 4095);
        const end_page = std.mem.alignForward(usize, end, 4096);
        for (g_reservations) |r| {
            if (r.size != 0 and start_page >= r.base and end_page <= r.base + std.mem.alignForward(usize, r.size, 4096)) {
                if (linux.errno(linux.mprotect(@ptrFromInt(start_page), end_page - start_page, prot)) != .SUCCESS) {
                    g_last_error = 487;
                    return null;
                }
                return @ptrFromInt(start_page);
            }
        }
        g_last_error = 487; // ERROR_INVALID_ADDRESS: no matching reservation
        return null;
    }
    // A caller-supplied reservation must neither replace an existing mapping
    // nor silently move to a different address.
    const requested: ?[*]u8 = if (lpAddress) |a| @ptrCast(a) else null;
    const free_flags = linux.MAP{ .TYPE = .PRIVATE, .ANONYMOUS = true };
    var ptr: usize = undefined;
    if (requested) |req| {
        const req_lo = @intFromPtr(req);
        const req_hi = req_lo + dwSize;
        // The guest's own image is not the guest's to hand out. Windows refuses
        // an allocation whose range is already mapped, and a MAP_FIXED mapping
        // here would destroy the image the guest is running from.
        //
        // Measured: the game asked for 6 MB at 0x1000000, which is inside its
        // own image (0x400000-0x147b000). The mapping replaced the top 6 MB of
        // that image -- .data, .tls, .rsrc, .reloc and .bind all read back as
        // zeros -- and the game then died in its own startup, asking for
        // "CoreExitProcess" through strings that were no longer there.
        if (g_guest_base != 0 and req_lo < g_guest_end and req_hi > g_guest_base) {
            std.debug.print("[WINS:Kernel32] VirtualAlloc: 0x{x}+{d} overlaps the guest's own image (0x{x}-0x{x}); refusing, as Windows does\n", .{ req_lo, dwSize, g_guest_base, g_guest_end });
            g_last_error = 87; // ERROR_INVALID_PARAMETER
            return null;
        }
        // A requested reservation is an exact-address request. Using
        // MAP_FIXED destroys an existing mapping; silently relocating breaks
        // guests that index allocations by address. An ordinary mmap hint is
        // atomic and non-destructive: discard any alternative the kernel
        // chooses and report the occupied address to the guest.
        ptr = linux.mmap(req, dwSize, prot, free_flags, -1, 0);
        if (linux.errno(ptr) == .SUCCESS and ptr != @intFromPtr(req)) {
            _ = linux.munmap(@ptrFromInt(ptr), dwSize);
            g_last_error = 487; // ERROR_INVALID_ADDRESS
            return null;
        }
    } else {
        ptr = linux.mmap(null, dwSize, prot, free_flags, -1, 0);
    }
    if (linux.errno(ptr) != .SUCCESS) {
        g_last_error = 8; // ERROR_NOT_ENOUGH_MEMORY
        return null;
    }
    g_alloc_prot = flProtect;
    trackReservation(ptr, dwSize);
    return @ptrFromInt(ptr);
}

/// Every reservation made for the guest, so freeing can undo exactly what was
/// allocated. Without this, VirtualFree munmapped the length the guest happened
/// to pass, and a sub-range or a stale size unmapped whatever sat next to it --
/// including memory the real Steam client and glibc were using.
const Reservation = struct { base: usize, size: usize };
var g_reservations: [512]Reservation = [_]Reservation{.{ .base = 0, .size = 0 }} ** 512;

fn trackReservation(base: usize, size: usize) void {
    for (&g_reservations) |*r| {
        if (r.size == 0) {
            r.* = .{ .base = base, .size = size };
            return;
        }
        if (r.base == base) {
            r.size = size;
            return;
        }
    }
}

fn untrackReservation(base: usize) void {
    for (&g_reservations) |*r| {
        if (r.base == base) {
            r.* = .{ .base = 0, .size = 0 };
            return;
        }
    }
}

/// Release a block the loader owns, for the kernel32 module's VirtualFree.
///
/// The module has its own export table and cannot see g_reservations, so it
/// used to munmap (address, dwSize) unconditionally -- which meant a guest
/// free could unmap the real Steam client's heap. The module now calls this
/// instead: a release that cannot prove ownership does not unmap.
pub fn releaseOwnedBlock(addr: usize, size: usize) bool {
    for (g_reservations) |r| {
        if (r.size != 0 and addr >= r.base and addr < r.base + r.size) {
            _ = linux.munmap(@as([*]u8, @ptrFromInt(r.base)), r.size);
            untrackReservation(r.base);
            return true;
        }
    }
    _ = size;
    return false;
}

fn VirtualFree(lpAddress: ?*anyopaque, dwSize: usize, dwFreeType: u32) callconv(W) i32 {
    if (lpAddress) |addr| {
        const base = @intFromPtr(addr);
        std.debug.print("[WINS:Kernel32] VirtualFree(0x{x}, size={d}, type=0x{x})\n", .{ base, dwSize, dwFreeType });
        // MEM_RELEASE (0x8000) takes the reservation's base and size 0 and
        // unmaps the whole reservation; MEM_DECOMMIT (0x4000) withdraws only
        // the pages holding a byte of [addr, addr+size) (size 0: up to the end
        // of the reservation), which here means zeroing them and making them
        // inaccessible, never unmapping neighbours (pinned by
        // native/testdata/decommit_probe.c against Wine).
        const is_release = (dwFreeType & 0x8000) != 0;
        const is_decommit = (dwFreeType & 0x4000) != 0;
        if (is_release == is_decommit) {
            g_last_error = 87; // ERROR_INVALID_PARAMETER: exactly one of the two
            return 0;
        }
        var owner: ?Reservation = null;
        for (g_reservations) |r| {
            if (r.size != 0 and base >= r.base and base < r.base + r.size) {
                owner = r;
                break;
            }
        }
        const res = owner orelse {
            // Not one of our reservations. Unmapping it would destroy memory
            // that belongs to someone else -- the real client, libc, or the
            // kernel. A release that cannot prove ownership must not unmap.
            std.debug.print("[WINS:Kernel32] VirtualFree: 0x{x} is not one of our reservations; refusing to release it\n", .{base});
            g_last_error = 487; // ERROR_INVALID_ADDRESS
            return 0;
        };
        const res_end = res.base + std.mem.alignForward(usize, res.size, 4096);
        if (is_decommit) {
            // Decommitting for the size of the WHOLE reservation from an
            // interior address (what this did before) withdrew the game's live
            // heap after one guard page: FalloutNV decommits single pages at
            // 0x51d1000 / 0x71e1000 inside 8 MB reservations and then faulted
            // one page later, in its main loop.
            const lo = base & ~@as(usize, 4095);
            const hi = if (dwSize == 0) res_end else std.mem.alignForward(usize, base + dwSize, 4096);
            if (hi > res_end) {
                g_last_error = 487; // ERROR_INVALID_ADDRESS: beyond the reservation
                return 0;
            }
            // Decommitted pages lose their contents: a later commit reads zeros.
            _ = linux.madvise(@ptrFromInt(lo), hi - lo, linux.MADV.DONTNEED);
            _ = linux.mprotect(@as([*]u8, @ptrFromInt(lo)), hi - lo, linux.PROT{});
            return 1;
        }
        if (base != res.base) {
            g_last_error = 487; // ERROR_INVALID_ADDRESS: not the reservation's base
            return 0;
        }
        if (dwSize != 0) {
            g_last_error = 87; // ERROR_INVALID_PARAMETER
            return 0;
        }
        _ = linux.munmap(@as([*]u8, @ptrFromInt(res.base)), res.size);
        untrackReservation(res.base);
        return 1;
    }
    return 0;
}

/// The protection a page of guest memory has right now, in the constants
/// Windows uses. Read from /proc/self/maps, because the kernel is the only
/// authority on what is mapped how -- and because the guest asks for the
/// previous protection when it restores one. Answering that question with a
/// stale value silently takes execute permission away from code the guest is
/// about to run, and the failure looks like a mystery jump into a page that
/// is mapped but not executable.
fn currentProtection(addr: usize) u32 {
    const fd = linux.open("/proc/self/maps", .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(fd) != .SUCCESS) return 0x04;
    defer _ = linux.close(@intCast(fd));
    var buf: [16 * 1024]u8 = undefined;
    const rn = linux.read(@intCast(fd), &buf, buf.len);
    if (linux.errno(rn) != .SUCCESS) return 0x04;
    var lines = std.mem.splitScalar(u8, buf[0..@intCast(rn)], '\n');
    while (lines.next()) |line| {
        const dash = std.mem.indexOfScalar(u8, line, '-') orelse continue;
        const mlo = std.fmt.parseInt(usize, line[0..dash], 16) catch continue;
        const rest = line[dash + 1 ..];
        const sp = std.mem.indexOfScalar(u8, rest, ' ') orelse continue;
        const mhi = std.fmt.parseInt(usize, rest[0..sp], 16) catch continue;
        if (addr < mlo or addr >= mhi) continue;
        if (rest.len < sp + 5) continue;
        const perms = rest[sp + 1 ..][0..4];
        const r = perms[0] == 'r';
        const w = perms[1] == 'w';
        const x = perms[2] == 'x';
        if (x and r and w) return 0x40; // PAGE_EXECUTE_READWRITE
        if (x and r) return 0x20; // PAGE_EXECUTE_READ
        if (x) return 0x10; // PAGE_EXECUTE
        if (r and w) return 0x04; // PAGE_READWRITE
        if (r) return 0x02; // PAGE_READONLY
        return 0x01; // PAGE_NOACCESS
    }
    return 0x04;
}

/// The guest's static TLS, set up the way a 32-bit Windows process has it.
///
/// A module with a TLS directory gets one block of thread data (the template
/// the image carries, plus zero fill) and one index in the thread's TLS
/// array. The index is written into the image at the address the TLS
/// directory names, and the array hangs off the TEB: on x86, TEB+0x2c is the
/// thread's TLS pointer. Without this, the first read of a thread-local
/// variable is a read through a null pointer -- measured, not guessed: the
/// guest reads its TLS index from the address its own TLS directory names and
/// then indexes the array the TEB is supposed to point at.
const TLS_SLOT_COUNT = 64;
var g_tls_index_array: [TLS_SLOT_COUNT]usize align(16) = [_]usize{0} ** TLS_SLOT_COUNT;
var g_tls_block: []u8 = &[_]u8{};
/// What a new thread needs to build its own static TLS block: the image's template,
/// its zero fill, the index the loader assigned, and the TLS callbacks.
var g_tls_tpl_start: usize = 0;
var g_tls_tpl_len: usize = 0;
var g_tls_zero_fill: usize = 0;
var g_tls_idx: usize = 0;
var g_tls_callbacks_va: usize = 0;

fn setupGuestTls(allocator: std.mem.Allocator, image_base: usize, tls_rva: u32, tls_size: u32) void {
    if (tls_rva == 0 or tls_size < 24) return;
    const dir: [*]const u8 = @ptrFromInt(image_base + tls_rva);
    const start_va = std.mem.readInt(u32, dir[0..4], .little);
    const end_va = std.mem.readInt(u32, dir[4..8], .little);
    const index_va = std.mem.readInt(u32, dir[8..12], .little);
    const callbacks_va = std.mem.readInt(u32, dir[12..16], .little);
    const zero_fill = std.mem.readInt(u32, dir[16..20], .little);
    if (end_va < start_va) return;
    const template_len = end_va - start_va;
    const block = allocator.alloc(u8, template_len + zero_fill) catch {
        std.debug.print("[WINS:TLS] could not allocate {d} bytes for the guest's thread data\n", .{template_len + zero_fill});
        return;
    };
    @memcpy(block[0..template_len], @as([*]const u8, @ptrFromInt(start_va))[0..template_len]);
    @memset(block[template_len..], 0);

    // The executable is the first module loaded, so its TLS block takes index
    // one; slot zero is the array's own address, the way Windows does it.
    const index: usize = 1;
    g_tls_index_array[0] = @intFromPtr(&g_tls_index_array);
    if (index < TLS_SLOT_COUNT) g_tls_index_array[index] = @intFromPtr(block.ptr);
    g_tls_block = block;
    g_tls_tpl_start = start_va;
    g_tls_tpl_len = template_len;
    g_tls_zero_fill = zero_fill;
    g_tls_idx = index;
    g_tls_callbacks_va = callbacks_va;

    // The image carries the index it was given, at the address its TLS
    // directory names; the guest reads it from there.
    if (index_va != 0) {
        std.mem.writeInt(u32, @as([*]u8, @ptrFromInt(index_va))[0..4], @intCast(index), .little);
    }
    // TEB+0x2c is the thread's TLS pointer on x86.
    g_tib_buffer[0x2c / 4] = @intFromPtr(&g_tls_index_array);

    std.debug.print("[WINS:TLS] static TLS: {d} bytes of thread data at 0x{x}, index {d}, array at 0x{x}\n", .{ block.len, @intFromPtr(block.ptr), index, @intFromPtr(&g_tls_index_array) });

    // The loader runs the TLS callbacks before the entry point.
    if (callbacks_va != 0) {
        const cbs: [*]const u32 = @ptrFromInt(callbacks_va);
        var i: usize = 0;
        while (i < 64) : (i += 1) {
            const fn_va = cbs[i];
            if (fn_va == 0) break;
            const cb_fn: *const fn (usize, u32, ?*anyopaque) callconv(.c) void = @ptrFromInt(fn_va);
            std.debug.print("[WINS:TLS] callback 0x{x} (DLL_PROCESS_ATTACH)\n", .{fn_va});
            cb_fn(image_base, 1, null);
        }
    }
}

fn VirtualProtect(lpAddress: ?*anyopaque, dwSize: usize, flNewProtect: u32, lpflOldProtect: ?*u32) callconv(W) i32 {
    if (lpflOldProtect) |old| old.* = if (lpAddress) |p| currentProtection(@intFromPtr(p)) else 0x04;
    g_alloc_prot = flNewProtect;
    std.debug.print("[WINS:Kernel32] VirtualProtect(0x{x}, size={d}, prot=0x{x})\n", .{ @intFromPtr(lpAddress), dwSize, flNewProtect });
    if (lpAddress) |p| {
        // NOTE: there used to be a steamdrm.dll signature check here that
        // rewrote the RSA-ticket gate into a direct AES decrypt (JNE -> JMP).
        // That was the loader bypassing the DRM check itself, which is exactly
        // what "Steam still owns my DRM" forbids: the loader must not stand in
        // for the client. Steam owns verification, so the loader leaves the
        // guest's DRM code alone and only translates the API around it.
        const prot = linux.PROT{
            .READ = (flNewProtect & 0x66) != 0,
            .WRITE = (flNewProtect & 0x44) != 0,
            .EXEC = (flNewProtect & 0xF0) != 0,
        };
        // mprotect wants a page-aligned range; Windows rounds the address
        // down and the size up.
        const page = std.heap.page_size_min;
        const addr = @intFromPtr(p);
        const base = addr & ~(page - 1);
        const end = (addr + dwSize + page - 1) & ~(page - 1);
        if (end > base) {
            const rc = linux.mprotect(@ptrFromInt(base), end - base, prot);
            if (linux.errno(rc) != .SUCCESS) {
                std.debug.print("[WINS:Kernel32] VirtualProtect FAILED on 0x{x}..0x{x}: errno={d}\n", .{ base, end, @intFromEnum(linux.errno(rc)) });
                g_last_error = 5; // ERROR_ACCESS_DENIED
                return 0;
            }
        }
        return 1;
    }
    return 0;
}

// ============================================================================
// Steam bridge: relay to the real client, never substitute for it
// ============================================================================
//
// This section previously ANSWERED the Steam IPC handshake itself: it served a
// host-side block, wrote "[0x90] = 2" to claim the Steam client was ready, and
// wrote the auth token into the guest's target address. That is the loader
// impersonating the client, which is exactly what "Steam still owns my DRM"
// was not true of.
//
// This version does the inverse: it requires a live client and forwards the
// guest's opens to the objects the real client publishes on Linux. Nothing
// here fabricates a readiness flag, a token, or an account.

/// Fallout: New Vegas. Steam sets SteamAppId in a child's environment only when
/// the real client launches it, so its presence is proof of a live session.
const STEAM_APPID: u32 = 22380;

/// Written once from main, from the environment Steam provides.
extern fn getenv(name: [*:0]const u8) ?[*:0]const u8;
/// glibc's environment vector, used to re-exec self with one extra variable.
extern var environ: [*:null]?[*:0]u8;

/// First byte of this executable's own ELF image (linker-provided).
extern const __ehdr_start: u8;

/// Size of the PROT_NONE window to reserve at `base`, given where this loader's
/// own image starts (`loader_lo`). The shipped build links the loader at
/// 0x02000000 (see tools/build_probe.sh), which lies INSIDE the default
/// [0x00400000, +64 MB) window: reserving all of it with MAP_FIXED replaced the
/// loader's own pages and killed it with SIGSEGV before main printed anything.
/// The window therefore ends where the loader begins. 0 means: reserve nothing.
fn imageWindowReserveSize(base: usize, want: usize, loader_lo: usize) usize {
    if (loader_lo > base and loader_lo < base + want) return loader_lo - base;
    if (loader_lo == base) return 0;
    return want;
}
var g_steam_appid: u32 = 0;
var g_target_path: [512]u8 = [_]u8{0} ** 512;
var g_target_path_len: usize = 0;

/// The shared-memory object Steam publishes for a running game's IPC.
/// The Io handle and the resolved IPC path, resolved once and reused: the shims
/// that need it (OpenFileMappingA, the Steam gate) have no Io of their own.
var g_io: std.Io = undefined;
var g_shmem_path: [512]u8 = [_]u8{0} ** 512;
var g_shmem_path_done: bool = false;

fn steamShmemPath() [:0]const u8 {
    if (!g_shmem_path_done) {
        g_shmem_path = findSteamShmem(g_io);
        g_shmem_path_done = true;
    }
    return g_shmem_path[0..std.mem.indexOfScalar(u8, &g_shmem_path, 0) orelse 0 :0];
}

/// The object Steam publishes for its IPC. Observed on a live client:
/// /dev/shm/u1000-ValveIPCSharedObj-Steam. The earlier
/// "/dev/shm/SteamStart_SharedMemFile" guess never existed, which is why the
/// bridge closed even with Steam up.
fn findSteamShmem(io: std.Io) [512]u8 {
    var buf: [512]u8 = [_]u8{0} ** 512;
    var shm_dir = std.Io.Dir.cwd().openDir(io, "/dev/shm", .{ .iterate = true }) catch return buf;
    defer shm_dir.close(io);
    var it = shm_dir.iterate();
    while (it.next(io) catch null) |entry| {
        if (std.mem.indexOf(u8, entry.name, "ValveIPCSharedObj") != null) {
            const prefix = "/dev/shm/";
            const n = @min(entry.name.len, buf.len - prefix.len - 1);
            @memcpy(buf[0..prefix.len], prefix);
            @memcpy(buf[prefix.len .. prefix.len + n], entry.name[0..n]);
            buf[prefix.len + n] = 0;
            return buf;
        }
    }
    return buf;
}

const STEAM_SHMEM_NAME = "/dev/shm/u1000-ValveIPCSharedObj-Steam";

/// Is a Steam client actually serving this process right now?
///
/// Deterministic by construction: both conditions are either present or not, so
/// the same machine state always yields the same verdict.
///
///   1. SteamAppId in the environment. Only the real client sets it, and only
///      for a child it launches on an account's behalf. Hand-launching this
///      loader leaves it empty and fails, which is the point: the account
///      verification belongs to Steam, not to us.
///   2. The IPC object the client must publish while a game runs. A stale
///      /dev/shm entry from a dead client is not enough, so the object is
///      opened for writing, which a dead session cannot satisfy.
fn steamClientLive() bool {
    if (g_steam_appid != STEAM_APPID) {
        std.debug.print("[WINS:SteamBridge] SteamAppId is not {d} in the environment (got {d}).\n", .{ STEAM_APPID, g_steam_appid });
        std.debug.print("                  This loader must be launched BY the Steam client so Steam can\n", .{});
        std.debug.print("                  verify the account. Refusing to run.\n", .{});
        return false;
    }
    const path = steamShmemPath();
    if (path[0] == 0) {
        std.debug.print("[WINS:SteamBridge] No ValveIPCSharedObj in /dev/shm: Steam's IPC is not live.\n", .{});
        return false;
    }
    const fd = linux.open(path.ptr, .{ .ACCMODE = .RDWR }, 0);
    if (linux.errno(fd) != .SUCCESS) {
        std.debug.print("[WINS:SteamBridge] {s} could not be opened: Steam's IPC is not live.\n", .{path});
        return false;
    }
    _ = linux.close(@intCast(fd));
    return true;
}

/// Size of the Steam IPC object. linux.Stat is unavailable here and linux.lseek is
/// 64-bit only in this Zig, so the raw i386 syscall is used: it takes a 32-bit
/// off_t, which is plenty for a shared-memory object.
fn shmObjectSize(fd: i32) ?usize {
    if (@import("builtin").cpu.arch == .x86) {
        const r = linux.syscall3(.lseek, @as(usize, @bitCast(@as(isize, fd))), 0, 2);
        if (linux.errno(r) != .SUCCESS) return null;
        return @intCast(r);
    }
    const r = linux.syscall3(.lseek, @as(usize, @bitCast(@as(isize, fd))), 0, 2);
    if (linux.errno(r) != .SUCCESS) return null;
    return @intCast(r);
}

fn OpenFileMappingA(dwDesiredAccess: u32, bInheritHandle: i32, lpName: ?[*:0]const u8) callconv(W) usize {
    _ = dwDesiredAccess; _ = bInheritHandle;
    const name = if (lpName) |n| std.mem.sliceTo(n, 0) else "null";
    std.debug.print("[WINS:Kernel32] OpenFileMappingA(\"{s}\")\n", .{name});
    if (std.mem.indexOf(u8, name, "SteamStart_SharedMemFile") != null) {
        // Relay, do not invent: open the object the real client published. If it
        // is absent there is no session to talk to and the call fails exactly as
        // it would on Windows with Steam closed.
        if (!steamClientLive()) return 0;
        const fd = linux.open(STEAM_SHMEM_NAME[0..:0].ptr, .{ .ACCMODE = .RDWR }, 0);
        if (linux.errno(fd) != .SUCCESS) {
            g_last_error = 2; // ERROR_FILE_NOT_FOUND
            return 0;
        }
        std.debug.print("  [WINS:SteamBridge] Relaying to the real client's IPC object (fd={}).\\n", .{fd});
        // Keep the fd in the handle the guest will map, so MapViewOfFile can
        // map the same object rather than a stub buffer.
        return @as(usize, @intCast(fd)) | 0x30000000;
    }
    g_last_error = 2; // ERROR_FILE_NOT_FOUND (allows game to act as primary instance)
    return 0;
}

fn CreateFileMappingA(hFile: usize, lpFileMappingAttributes: ?*anyopaque, flProtect: u32, dwMaximumSizeHigh: u32, dwMaximumSizeLow: u32, lpName: ?[*:0]const u8) callconv(W) usize {
    _ = hFile; _ = lpFileMappingAttributes; _ = flProtect; _ = dwMaximumSizeHigh; _ = dwMaximumSizeLow;
    const name = if (lpName) |n| std.mem.sliceTo(n, 0) else "null";
    std.debug.print("[WINS:Kernel32] CreateFileMappingA(\"{s}\")\n", .{name});
    g_last_error = 0;
    return 0x30001; // Valid dummy mapping handle
}

fn MapViewOfFile(hFileMappingObject: usize, dwDesiredAccess: u32, dwFileOffsetHigh: u32, dwFileOffsetLow: u32, dwNumberOfBytesToMap: usize) callconv(W) ?*anyopaque {
    _ = dwDesiredAccess; _ = dwFileOffsetHigh;
    const STEAM_BIT: usize = 0x30000000;
    if (hFileMappingObject & STEAM_BIT == STEAM_BIT) {
        const fd: i32 = @intCast(hFileMappingObject & ~STEAM_BIT);
        const obj_size: usize = shmObjectSize(fd) orelse {
            g_last_error = 2;
            return null;
        };
        const size: usize = if (dwNumberOfBytesToMap == 0 or dwNumberOfBytesToMap > obj_size) obj_size else dwNumberOfBytesToMap;
        // Map the REAL client's object read/write. The guest now talks straight
        // to Steam: Steam writes the readiness flag, the ticket and the response
        // itself. Notably absent here is the old "[0x90] = 2, client ready" write,
        // which was the loader speaking for a client that was never there.
        const prot = linux.PROT{ .READ = true, .WRITE = true };
        const flags = linux.MAP{ .TYPE = .SHARED };
        const ptr = linux.mmap(null, size, prot, flags, fd, @as(i64, dwFileOffsetLow));
        if (linux.errno(ptr) != .SUCCESS) {
            g_last_error = 8; // ERROR_NOT_ENOUGH_MEMORY
            return null;
        }
        std.debug.print("  [WINS:SteamBridge] Mapped Steam's IPC object: 0x{x} ({d} bytes, shared)\\n", .{ ptr, size });
        return @ptrFromInt(ptr);
    }
    const size = if (dwNumberOfBytesToMap == 0) 64 * 1024 else dwNumberOfBytesToMap;
    std.debug.print("[WINS:Kernel32] MapViewOfFile(handle=0x{x}, size={d})\n", .{ hFileMappingObject, size });
    const prot = linux.PROT{ .READ = true, .WRITE = true };
    const flags = linux.MAP{ .TYPE = .PRIVATE, .ANONYMOUS = true };
    const ptr = linux.mmap(null, size, prot, flags, -1, 0);
    if (linux.errno(ptr) != .SUCCESS) return null;
    return @ptrFromInt(ptr);
}

fn UnmapViewOfFile(lpBaseAddress: ?*const anyopaque) callconv(W) i32 {
    _ = lpBaseAddress;
    return 1;
}

// ============================================================================
// Process, Thread, and Synchronization Shims
// ============================================================================

fn GetLastError() callconv(W) u32 {
    return g_last_error;
}

fn SetLastError(err: u32) callconv(W) void {
    g_last_error = err;
}

fn setLastErrorHook(err: u32) void {
    g_last_error = err;
}

fn EncodePointer(Ptr: ?*anyopaque) callconv(W) ?*anyopaque {
    return Ptr;
}

fn DecodePointer(Ptr: ?*anyopaque) callconv(W) ?*anyopaque {
    return Ptr;
}

fn FlsAlloc(lpCallback: ?*anyopaque) callconv(W) u32 {
    _ = lpCallback;
    return TlsAlloc();
}

fn FlsGetValue(dwFlsIndex: u32) callconv(W) ?*anyopaque {
    return TlsGetValue(dwFlsIndex);
}

fn FlsSetValue(dwFlsIndex: u32, lpFlsData: ?*anyopaque) callconv(W) i32 {
    return TlsSetValue(dwFlsIndex, lpFlsData);
}

fn FlsFree(dwFlsIndex: u32) callconv(W) i32 {
    return TlsFree(dwFlsIndex);
}

fn CryptAcquireContextA(phProv: ?*usize, pszContainer: ?[*:0]const u8, pszProvider: ?[*:0]const u8, dwProvType: u32, dwFlags: u32) callconv(W) i32 {
    _ = pszContainer; _ = pszProvider; _ = dwProvType; _ = dwFlags;
    if (phProv) |p| p.* = 0x9001;
    return 1;
}

fn CryptReleaseContext(hProv: usize, dwFlags: u32) callconv(W) i32 {
    _ = hProv; _ = dwFlags;
    return 1;
}

fn CryptGenRandom(hProv: usize, dwLen: u32, pbBuffer: ?[*]u8) callconv(W) i32 {
    _ = hProv;
    if (pbBuffer) |buf| {
        for (0..dwLen) |i| {
            buf[i] = @intCast((i * 37 + 13) & 0xFF);
        }
    }
    return 1;
}

fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) callconv(W) usize {
    _ = dwDesiredAccess; _ = bInheritHandle; _ = dwProcessId;
    return 0x5001;
}

fn GetExitCodeProcess(hProcess: usize, lpExitCode: ?*u32) callconv(W) i32 {
    _ = hProcess;
    if (lpExitCode) |c| c.* = 0x103; // STILL_ACTIVE
    return 1;
}

fn GetFileAttributesW(lpFileName: ?[*:0]const u16) callconv(W) u32 {
    _ = lpFileName;
    return 0x80; // FILE_ATTRIBUTE_NORMAL
}

fn LoadLibraryExW(lpLibFileName: ?[*:0]const u16, hFile: usize, dwFlags: u32) callconv(W) usize {
    _ = lpLibFileName; _ = hFile; _ = dwFlags;
    return 0x10000000;
}

fn QueryDosDeviceA(lpDeviceName: ?[*:0]const u8, lpTargetPath: ?[*]u8, ucchMax: u32) callconv(W) u32 {
    _ = lpDeviceName;
    if (lpTargetPath != null and ucchMax >= 14) {
        const dev = "\\Device\\C:\x00";
        @memcpy(lpTargetPath.?[0..dev.len], dev);
        return @intCast(dev.len);
    }
    return 0;
}

fn GetLogicalDriveStringsA(nBufferLength: u32, lpBuffer: ?[*]u8) callconv(W) u32 {
    if (lpBuffer != null and nBufferLength >= 5) {
        @memcpy(lpBuffer.?[0..4], "C:\\\x00");
        lpBuffer.?[4] = 0;
        return 4;
    }
    return 0;
}

fn GetCurrentProcess() callconv(W) usize {
    return 0xFFFFFFFF;
}

fn GetCurrentThread() callconv(W) usize {
    return 0xFFFFFFFE;
}

fn GetCurrentProcessId() callconv(W) u32 {
    return @intCast(linux.getpid());
}

fn GetCurrentThreadId() callconv(W) u32 {
    return threads_mod.tidNow();
}

fn ExitProcess(code: u32) callconv(W) noreturn {
    const caller = @returnAddress();
    std.debug.print("[WINS:Kernel32] ExitProcess called with code {} by caller 0x{x:0>8}\n", .{ code, caller });
    linux.exit_group(@bitCast(code));
}

fn TerminateProcess(hProcess: usize, uExitCode: u32) callconv(W) i32 {
    _ = hProcess;
    ExitProcess(uExitCode);
}

fn RaiseException(dwExceptionCode: u32, dwExceptionFlags: u32, nNumberOfArguments: u32, lpArguments: ?[*]const usize) callconv(W) void {
    _ = dwExceptionFlags; _ = nNumberOfArguments; _ = lpArguments;
    std.debug.print("[WINS:Kernel32] RaiseException(0x{x:0>8})\n", .{dwExceptionCode});
    if (kernel32_mod.isThreadNamingException(dwExceptionCode)) {
        std.debug.print("[WINS:Kernel32] thread-naming exception; continuing\n", .{});
        return;
    }
    linux.exit_group(1);
}

fn TlsAlloc() callconv(W) u32 {
    for (0..64) |i| {
        const mask: u64 = @as(u64, 1) << @intCast(i);
        if ((g_tls_bitmap & mask) == 0) {
            g_tls_bitmap |= mask;
            return @intCast(i);
        }
    }
    return 0xFFFFFFFF; // TLS_OUT_OF_INDEXES
}

fn TlsGetValue(dwTlsIndex: u32) callconv(W) ?*anyopaque {
    if (dwTlsIndex < 64) return g_tls_thread_slots[dwTlsIndex];
    return null;
}

fn TlsSetValue(dwTlsIndex: u32, lpTlsValue: ?*anyopaque) callconv(W) i32 {
    if (dwTlsIndex < 64) {
        g_tls_thread_slots[dwTlsIndex] = lpTlsValue;
        return 1;
    }
    return 0;
}

fn TlsFree(dwTlsIndex: u32) callconv(W) i32 {
    if (dwTlsIndex < 64) {
        const mask: u64 = @as(u64, 1) << @intCast(dwTlsIndex);
        g_tls_bitmap &= ~mask;
        g_tls_thread_slots[dwTlsIndex] = null;
        return 1;
    }
    return 0;
}

/// Runs the start routine on a real thread (see winrun_threads.zig). The thread gets
/// its own TEB, FS segment and static TLS block from guestThreadInit.
fn CreateThread(lpThreadAttributes: ?*anyopaque, dwStackSize: usize, lpStartAddress: ?*anyopaque, lpParameter: ?*anyopaque, dwCreationFlags: u32, lpThreadId: ?*u32) callconv(W) usize {
    _ = lpThreadAttributes;
    const start: threads_mod.StartFn = @ptrCast(lpStartAddress orelse {
        g_last_error = 87; // ERROR_INVALID_PARAMETER
        return 0;
    });
    const h = threads_mod.createThread(dwStackSize, start, lpParameter, dwCreationFlags, lpThreadId);
    if (h == 0) g_last_error = 8; // ERROR_NOT_ENOUGH_MEMORY
    std.debug.print("[WINS:Kernel32] CreateThread(start=0x{x}, flags=0x{x}) -> 0x{x}\n", .{ @intFromPtr(lpStartAddress), dwCreationFlags, h });
    return h;
}

fn ResumeThread(hThread: usize) callconv(W) u32 {
    // Handles this loader does not track (the SteamStub scans its own threads with
    // OpenThread/SuspendThread/ResumeThread) keep the answer they always had.
    if (!threads_mod.isOurs(hThread)) return 1;
    return threads_mod.resumeThread(hThread);
}

fn SuspendThread(hThread: usize) callconv(W) u32 {
    if (!threads_mod.isOurs(hThread)) return 0; // as before: the stub's thread scan must not fail
    return threads_mod.suspendThread(hThread);
}

fn SetThreadPriority(hThread: usize, nPriority: i32) callconv(W) i32 {
    _ = hThread; _ = nPriority;
    return 1;
}

fn SetThreadIdealProcessor(hThread: usize, dwIdealProcessor: u32) callconv(W) u32 {
    _ = hThread; _ = dwIdealProcessor;
    return 0;
}

fn ExitThread(dwExitCode: u32) callconv(W) noreturn {
    // A thread started by CreateThread ends alone; on the main thread this ends
    // the process, as before.
    _ = threads_mod.exitCurrentThread(dwExitCode);
    linux.exit_group(0);
}

fn GetExitCodeThread(hThread: usize, lpExitCode: ?*u32) callconv(W) i32 {
    const out = lpExitCode orelse return 0;
    if (threads_mod.getExitCode(hThread, out)) |ok| return if (ok) 1 else 0;
    out.* = 0; // a handle this loader does not track (pseudo handles)
    return 1;
}

// Critical Sections (Full Win32 24-byte struct with LockCount & recursion tracking)
const CriticalSection = extern struct {
    DebugInfo: u32,
    LockCount: i32,
    RecursionCount: i32,
    OwningThread: u32,
    LockSemaphore: u32,
    SpinCount: u32,
};

fn InitializeCriticalSection(lpCriticalSection: ?*anyopaque) callconv(W) void {
    if (lpCriticalSection) |p| threads_mod.csInit(@ptrCast(@alignCast(p)), 0);
}

fn InitializeCriticalSectionAndSpinCount(lpCriticalSection: ?*anyopaque, dwSpinCount: u32) callconv(W) i32 {
    if (lpCriticalSection) |p| {
        threads_mod.csInit(@ptrCast(@alignCast(p)), dwSpinCount);
        return 1;
    }
    return 0;
}

fn EnterCriticalSection(lpCriticalSection: ?*anyopaque) callconv(W) void {
    if (lpCriticalSection) |p| threads_mod.csEnter(@ptrCast(@alignCast(p)));
}

fn TryEnterCriticalSection(lpCriticalSection: ?*anyopaque) callconv(W) i32 {
    if (lpCriticalSection) |p| return if (threads_mod.csTryEnter(@ptrCast(@alignCast(p)))) 1 else 0;
    return 0;
}

fn LeaveCriticalSection(lpCriticalSection: ?*anyopaque) callconv(W) void {
    if (lpCriticalSection) |p| threads_mod.csLeave(@ptrCast(@alignCast(p)));
}

fn DeleteCriticalSection(lpCriticalSection: ?*anyopaque) callconv(W) void {
    if (lpCriticalSection) |p| {
        const cs: *threads_mod.CriticalSection = @ptrCast(@alignCast(p));
        cs.LockCount = -1;
        cs.RecursionCount = 0;
        cs.OwningThread = 0;
    }
}

fn dummySync(p: ?*anyopaque) callconv(W) void {
    _ = p;
}

fn dummySuccess(p: ?*anyopaque) callconv(W) i32 {
    _ = p;
    return 1;
}

fn CreateEventA(lpEventAttributes: ?*anyopaque, bManualReset: i32, bInitialState: i32, lpName: ?[*:0]const u8) callconv(W) usize {
    _ = lpEventAttributes;
    const name: ?[]const u8 = if (lpName) |n| std.mem.sliceTo(n, 0) else null;
    const h = threads_mod.createEvent(bManualReset != 0, bInitialState != 0, name);
    if (name != null) std.debug.print("[WINS:Kernel32] CreateEventA(\"{s}\") -> 0x{x}\n", .{ name.?, h });
    return h;
}

fn OpenEventA(dwDesiredAccess: u32, bInheritHandle: i32, lpName: ?[*:0]const u8) callconv(W) usize {
    _ = dwDesiredAccess; _ = bInheritHandle;
    const name = if (lpName) |n| std.mem.sliceTo(n, 0) else "null";
    std.debug.print("[WINS:Kernel32] OpenEventA(\"{s}\")\n", .{name});
    // The Steam IPC lock is not a separate /dev/shm object: the real client
    // keeps it inside the object the guest already maps. This used to return a
    // dummy handle and log "providing IPC event", i.e. the loader answering for
    // a client that was never there. It now fails unless a live client is
    // actually publishing the object, so the caller sees what Windows shows
    // when Steam is closed rather than a success we invented.
    if (std.mem.indexOf(u8, name, "SteamStart_SharedMemLock") != null) {
        if (!steamClientLive()) {
            g_last_error = 6; // ERROR_INVALID_HANDLE
            return 0;
        }
        // A live client is present. The handle the guest uses to reach that
        // client's lock is the mapping OpenFileMappingA already handed back, so
        // this echoes the same relationship instead of inventing an event.
        return 0x30000002;
    }
    g_last_error = 2; // ERROR_FILE_NOT_FOUND
    return 0;
}

fn CreateMutexA(lpMutexAttributes: ?*anyopaque, bInitialOwner: i32, lpName: ?[*:0]const u8) callconv(W) usize {
    _ = lpMutexAttributes;
    const name: ?[]const u8 = if (lpName) |n| std.mem.sliceTo(n, 0) else null;
    return threads_mod.createMutex(bInitialOwner != 0, name);
}

fn CreateSemaphoreA(lpSemaphoreAttributes: ?*anyopaque, lInitialCount: i32, lMaximumCount: i32, lpName: ?[*:0]const u8) callconv(W) usize {
    _ = lpSemaphoreAttributes;
    const name: ?[]const u8 = if (lpName) |n| std.mem.sliceTo(n, 0) else null;
    const h = threads_mod.createSemaphore(lInitialCount, lMaximumCount, name);
    if (h == 0) g_last_error = 87; // ERROR_INVALID_PARAMETER
    return h;
}

fn ReleaseSemaphore(hSemaphore: usize, lReleaseCount: i32, lpPreviousCount: ?*i32) callconv(W) i32 {
    if (!threads_mod.isOurs(hSemaphore)) return 1; // legacy handle: as before
    if (threads_mod.releaseSemaphore(hSemaphore, lReleaseCount, lpPreviousCount)) return 1;
    g_last_error = 298; // ERROR_TOO_MANY_POSTS
    return 0;
}

fn ReleaseMutex(hMutex: usize) callconv(W) i32 {
    if (!threads_mod.isOurs(hMutex)) return 1;
    if (threads_mod.releaseMutex(hMutex)) return 1;
    g_last_error = 288; // ERROR_NOT_OWNER
    return 0;
}

fn PulseEvent(hEvent: usize) callconv(W) i32 {
    return if (threads_mod.pulseEvent(hEvent)) 1 else 0;
}

fn SwitchToThread() callconv(W) i32 {
    _ = linux.sched_yield();
    return 1;
}

fn SetEvent(hEvent: usize) callconv(W) i32 {
    if (!threads_mod.isOurs(hEvent)) return 1; // legacy handles (Steam bridge): as before
    if (threads_mod.setEvent(hEvent)) return 1;
    g_last_error = 6; // ERROR_INVALID_HANDLE (not an event)
    return 0;
}

fn ResetEvent(hEvent: usize) callconv(W) i32 {
    if (!threads_mod.isOurs(hEvent)) return 1;
    if (threads_mod.resetEvent(hEvent)) return 1;
    g_last_error = 6;
    return 0;
}

fn WaitForSingleObject(hHandle: usize, dwMilliseconds: u32) callconv(W) u32 {
    // Handles created by this loader's real sync objects block and wake for real.
    if (threads_mod.waitOne(hHandle, dwMilliseconds)) |r| return r;
    // Anything else keeps the old behaviour (Steam bridge handles, constants).
    std.debug.print("[WINS:Kernel32] WaitForSingleObject(0x{x}, {d})\n", .{ hHandle, dwMilliseconds });
    // This shim used to be the DRM responder: it read a token out of shared memory
    // and wrote it into the guest's target address, then reported success as though
    // the Steam client had answered. Removing that is the whole point of the bridge.
    // The real client's response arrives in the object it published and is read by
    // the guest itself. Without a live session the caller sees a genuine failure
    // instead of a success we invented.
    if (!steamClientLive()) {
        std.debug.print("  [WINS:SteamBridge] No live Steam client to answer this wait.\\n", .{});
        g_last_error = 6; // ERROR_INVALID_HANDLE
        return 0xFFFFFFFF; // WAIT_FAILED
    }
    return 0; // WAIT_OBJECT_0
}

fn WaitForMultipleObjects(nCount: u32, lpHandles: ?[*]const usize, bWaitAll: i32, dwMilliseconds: u32) callconv(W) u32 {
    if (lpHandles) |hs| {
        if (nCount > 0 and nCount <= threads_mod.MAXIMUM_WAIT_OBJECTS) {
            if (threads_mod.waitMany(hs[0..nCount], bWaitAll != 0, dwMilliseconds)) |r| return r;
        }
    }
    return 0; // WAIT_OBJECT_0 for handles that are not ours (legacy behaviour)
}

fn Sleep(dwMilliseconds: u32) callconv(W) void {
    const sec: isize = @intCast(dwMilliseconds / 1000);
    const nsec: isize = @intCast((dwMilliseconds % 1000) * 1_000_000);
    const req = linux.timespec{ .sec = sec, .nsec = nsec };
    var rem: linux.timespec = undefined;
    _ = linux.nanosleep(&req, &rem);
}

// Atomic / Interlocked
fn InterlockedIncrement(Addend: *volatile i32) callconv(W) i32 {
    return @atomicRmw(i32, Addend, .Add, 1, .seq_cst) + 1;
}

fn InterlockedDecrement(Addend: *volatile i32) callconv(W) i32 {
    return @atomicRmw(i32, Addend, .Sub, 1, .seq_cst) - 1;
}

fn InterlockedExchange(Target: *volatile i32, Value: i32) callconv(W) i32 {
    return @atomicRmw(i32, Target, .Xchg, Value, .seq_cst);
}

fn InterlockedExchangeAdd(Addend: *volatile i32, Value: i32) callconv(W) i32 {
    return @atomicRmw(i32, Addend, .Add, Value, .seq_cst);
}

fn InterlockedCompareExchange(Destination: *volatile i32, Exchange: i32, Comperand: i32) callconv(W) i32 {
    const res = @cmpxchgStrong(i32, Destination, Comperand, Exchange, .seq_cst, .seq_cst);
    return if (res) |old| old else Comperand;
}

// ============================================================================
// System Information & Time Shims
// ============================================================================

fn QueryPerformanceCounter(lpPerformanceCount: ?*u64) callconv(W) i32 {
    if (lpPerformanceCount) |pc| {
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
        const nanos: u64 = @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
        pc.* = nanos / 100; // 10MHz ticks
    }
    return 1;
}

fn QueryPerformanceFrequency(lpFrequency: ?*u64) callconv(W) i32 {
    if (lpFrequency) |freq| {
        freq.* = 10_000_000; // 10 MHz standard
    }
    return 1;
}

fn GetTickCount() callconv(W) u32 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
    return @intCast(@as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000);
}

fn GetSystemTimeAsFileTime(lpTime: ?*u64) callconv(W) void {
    if (lpTime) |t| {
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(linux.CLOCK.REALTIME, &ts);
        const epoch_diff: u64 = 11644473600;
        const total_sec: u64 = @as(u64, @intCast(ts.sec)) + epoch_diff;
        t.* = total_sec * 10_000_000 + @as(u64, @intCast(ts.nsec)) / 100;
    }
}

const SYSTEMTIME = extern struct {
    wYear: u16,
    wMonth: u16,
    wDayOfWeek: u16,
    wDay: u16,
    wHour: u16,
    wMinute: u16,
    wSecond: u16,
    wMilliseconds: u16,
};

fn GetSystemTime(lpSystemTime: ?*anyopaque) callconv(W) void {
    if (lpSystemTime) |p| {
        const st: *SYSTEMTIME = @ptrCast(@alignCast(p));
        st.wYear = 2026;
        st.wMonth = 11;
        st.wDayOfWeek = 0;
        st.wDay = 8;
        st.wHour = 12;
        st.wMinute = 0;
        st.wSecond = 0;
        st.wMilliseconds = 0;
    }
}

fn GetLocalTime(lpSystemTime: ?*anyopaque) callconv(W) void {
    GetSystemTime(lpSystemTime);
}

fn SystemTimeToTzSpecificLocalTime(lpTimeZoneInformation: ?*anyopaque, lpUniversalTime: ?*anyopaque, lpLocalTime: ?*anyopaque) callconv(W) i32 {
    _ = lpTimeZoneInformation;
    if (lpUniversalTime != null and lpLocalTime != null) {
        @memcpy(@as([*]u8, @ptrCast(lpLocalTime.?))[0..@sizeOf(SYSTEMTIME)], @as([*]const u8, @ptrCast(lpUniversalTime.?))[0..@sizeOf(SYSTEMTIME)]);
    }
    return 1;
}

fn FileTimeToSystemTime(lpFileTime: ?*u64, lpSystemTime: ?*anyopaque) callconv(W) i32 {
    _ = lpFileTime;
    GetSystemTime(lpSystemTime);
    return 1;
}

fn FileTimeToLocalFileTime(lpFileTime: ?*u64, lpLocalFileTime: ?*u64) callconv(W) i32 {
    if (lpFileTime != null and lpLocalFileTime != null) {
        lpLocalFileTime.?.* = lpFileTime.?.*;
    }
    return 1;
}

fn CompareFileTime(lpFileTime1: ?*u64, lpFileTime2: ?*u64) callconv(W) i32 {
    if (lpFileTime1 == null or lpFileTime2 == null) return 0;
    const t1 = lpFileTime1.?.*;
    const t2 = lpFileTime2.?.*;
    if (t1 < t2) return -1;
    if (t1 > t2) return 1;
    return 0;
}

fn GetVersion() callconv(W) u32 {
    return 0x023F0601; // Windows 7 (NT 6.1, build 7601)
}

fn GetVersionExA(lpVersion: ?*anyopaque) callconv(W) i32 {
    if (lpVersion) |v| {
        const bytes: [*]u8 = @ptrCast(v);
        std.mem.writeInt(u32, bytes[0..4], 148, .little);
        std.mem.writeInt(u32, bytes[4..8], 6, .little);       // Major 6
        std.mem.writeInt(u32, bytes[8..12], 1, .little);      // Minor 1
        std.mem.writeInt(u32, bytes[12..16], 7601, .little);  // Build 7601
        std.mem.writeInt(u32, bytes[16..20], 2, .little);     // VER_PLATFORM_WIN32_NT
    }
    return 1;
}

const SYSTEM_INFO = extern struct {
    wProcessorArchitecture: u16,
    wReserved: u16,
    dwPageSize: u32,
    lpMinimumApplicationAddress: usize,
    lpMaximumApplicationAddress: usize,
    dwActiveProcessorMask: usize,
    dwNumberOfProcessors: u32,
    dwProcessorType: u32,
    dwAllocationGranularity: u32,
    wProcessorLevel: u16,
    wProcessorRevision: u16,
};

fn GetSystemInfo(lpSystemInfo: ?*anyopaque) callconv(W) void {
    if (lpSystemInfo) |p| {
        const si: *SYSTEM_INFO = @ptrCast(@alignCast(p));
        si.wProcessorArchitecture = 0; // PROCESSOR_ARCHITECTURE_INTEL
        si.wReserved = 0;
        si.dwPageSize = 4096;
        si.lpMinimumApplicationAddress = 0x00010000;
        si.lpMaximumApplicationAddress = 0x7FFEFFFF;
        si.dwActiveProcessorMask = 0x0F;
        si.dwNumberOfProcessors = 4;
        si.dwProcessorType = 586; // PROCESSOR_INTEL_PENTIUM
        si.dwAllocationGranularity = 65536;
        si.wProcessorLevel = 6;
        si.wProcessorRevision = 0x0101;
    }
}

const MEMORYSTATUS = extern struct {
    dwLength: u32,
    dwMemoryLoad: u32,
    dwTotalPhys: usize,
    dwAvailPhys: usize,
    dwTotalPageFile: usize,
    dwAvailPageFile: usize,
    dwTotalVirtual: usize,
    dwAvailVirtual: usize,
};

fn GlobalMemoryStatus(lpBuffer: ?*anyopaque) callconv(W) void {
    if (lpBuffer) |p| {
        const ms: *MEMORYSTATUS = @ptrCast(@alignCast(p));
        ms.dwLength = @sizeOf(MEMORYSTATUS);
        ms.dwMemoryLoad = 25;
        ms.dwTotalPhys = 0x80000000; // 2 GB
        ms.dwAvailPhys = 0x60000000; // 1.5 GB
        ms.dwTotalPageFile = 0x80000000;
        ms.dwAvailPageFile = 0x60000000;
        ms.dwTotalVirtual = 0x7FFF0000; // 2 GB user virtual space
        ms.dwAvailVirtual = 0x60000000;
    }
}

const MEMORYSTATUSEX = extern struct {
    dwLength: u32,
    dwMemoryLoad: u32,
    ullTotalPhys: u64,
    ullAvailPhys: u64,
    ullTotalPageFile: u64,
    ullAvailPageFile: u64,
    ullTotalVirtual: u64,
    ullAvailVirtual: u64,
    ullAvailExtendedVirtual: u64,
};

fn GlobalMemoryStatusEx(lpBuffer: ?*anyopaque) callconv(W) i32 {
    if (lpBuffer) |p| {
        const ms: *MEMORYSTATUSEX = @ptrCast(@alignCast(p));
        ms.dwLength = @sizeOf(MEMORYSTATUSEX);
        ms.dwMemoryLoad = 25;
        ms.ullTotalPhys = 8 * 1024 * 1024 * 1024; // 8 GB
        ms.ullAvailPhys = 6 * 1024 * 1024 * 1024;
        ms.ullTotalPageFile = 8 * 1024 * 1024 * 1024;
        ms.ullAvailPageFile = 6 * 1024 * 1024 * 1024;
        ms.ullTotalVirtual = 0x7FFF0000;
        ms.ullAvailVirtual = 0x60000000;
        ms.ullAvailExtendedVirtual = 0;
        return 1;
    }
    return 0;
}

fn IsDebuggerPresent() callconv(W) i32 {
    return 0;
}

// ============================================================================
// File, Profile, and Console Shims
// ============================================================================

// The guest's command line. Built from the actual argv the loader was given, so
// argv[0] is the image and the rest are its arguments -- the same shape
// winrun_impl.zig hands to the kernel32/msvcrt libraries. This used to be a
// hardcoded "FalloutNV.exe" string, which meant every other target saw an empty
// argv and 7zr printed its usage text instead of running a command.
var g_cmdline_buf: [4096]u8 = [_]u8{0} ** 4096;
var g_cmdline_len: usize = 0;
var g_cmdline_w_buf: [4096]u16 = [_]u16{0} ** 4096;
var g_cmdline_w_len: usize = 0;

fn setGuestCommandLine(args: []const []const u8) void {
    var n: usize = 0;
    for (args, 0..) |a, idx| {
        const start = n;
        // MSVCRT's argv splits on whitespace; quoting keeps a path with spaces
        // in one argv entry, which is what CreateProcess-wrapped guests expect.
        const needs_quotes = idx == 0 and std.mem.indexOfScalar(u8, a, ' ') != null;
        if (needs_quotes and n + 1 < g_cmdline_buf.len) {
            g_cmdline_buf[n] = '"';
            n += 1;
        }
        const room = if (n < g_cmdline_buf.len - 1) g_cmdline_buf.len - n - 1 else 0;
        const take = @min(room, a.len);
        @memcpy(g_cmdline_buf[n .. n + take], a[0..take]);
        n += take;
        if (needs_quotes and n + 1 < g_cmdline_buf.len) {
            g_cmdline_buf[n] = '"';
            n += 1;
        }
        if (n + 1 < g_cmdline_buf.len) {
            g_cmdline_buf[n] = ' ';
            n += 1;
        }
        _ = start;
    }
    // Trim the trailing separator, then terminate.
    while (n > 0 and g_cmdline_buf[n - 1] == ' ') n -= 1;
    g_cmdline_len = n;
    g_cmdline_buf[n] = 0;

    var w: usize = 0;
    while (w < g_cmdline_len and w + 1 < g_cmdline_w_buf.len) : (w += 1) {
        g_cmdline_w_buf[w] = if (g_cmdline_buf[w] < 0x80) g_cmdline_buf[w] else '?';
    }
    g_cmdline_w_len = w;
    g_cmdline_w_buf[w] = 0;
    g_argv_ptr = g_cmdline_w_buf[0..g_cmdline_w_len :0].ptr;
}

fn GetCommandLineA() callconv(W) [*:0]const u8 {
    if (g_cmdline_len == 0) return "";
    return g_cmdline_buf[0..g_cmdline_len :0].ptr;
}

fn GetCommandLineW() callconv(W) [*:0]const u16 {
    if (g_cmdline_w_len == 0) return &[_:0]u16{0};
    if (g_crash_trap or msvcrt_mod.trace_static_init) {
        // 7-Zip splits this string into argv; a stray separator here is enough
        // to leave an empty entry in its non-switch list.
        std.debug.print("[WINS:Kernel32] GetCommandLineW -> \"{s}\" (len={d})\n", .{ g_cmdline_buf[0..g_cmdline_len], g_cmdline_w_len });
    }
    return g_cmdline_w_buf[0..g_cmdline_w_len :0].ptr;
}

fn GetModuleHandleA(lpModuleName: ?[*:0]const u8) callconv(W) usize {
    if (lpModuleName == null) return 0x00400000;
    const name = std.mem.sliceTo(lpModuleName.?, 0);
    if (name.len == 0) return 0x00400000;
    return LoadLibraryA(lpModuleName);
}

fn GetModuleHandleW(lpModuleName: ?[*:0]const u16) callconv(W) usize {
    _ = lpModuleName;
    return 0x00400000;
}

fn GetModuleFileNameA(hModule: usize, lpFilename: ?[*]u8, nSize: u32) callconv(W) u32 {
    _ = hModule;
    if (lpFilename == null or nSize == 0) return 0;
    const name = "FalloutNV.exe";
    const len: u32 = @min(nSize - 1, @as(u32, @intCast(name.len)));
    @memcpy(lpFilename.?[0..len], name[0..len]);
    lpFilename.?[len] = 0;
    return len;
}

fn GetStartupInfoA(lpStartupInfo: ?*anyopaque) callconv(W) void {
    if (lpStartupInfo) |si| {
        const bytes: [*]u8 = @ptrCast(si);
        @memset(bytes[0..68], 0);
        std.mem.writeInt(u32, bytes[0..4], 68, .little);
        std.mem.writeInt(u32, bytes[44..48], 1, .little); // STARTF_USESHOWWINDOW
        std.mem.writeInt(u16, bytes[48..50], 1, .little); // SW_SHOWNORMAL
    }
}

fn GetStartupInfoW(lpStartupInfo: ?*anyopaque) callconv(W) void {
    GetStartupInfoA(lpStartupInfo);
}

fn SetUnhandledExceptionFilter(lpTopLevelExceptionFilter: ?*anyopaque) callconv(W) ?*anyopaque {
    _ = lpTopLevelExceptionFilter;
    return null;
}

fn UnhandledExceptionFilter(ExceptionInfo: ?*anyopaque) callconv(W) i32 {
    _ = ExceptionInfo;
    return 0; // EXCEPTION_CONTINUE_SEARCH
}

fn RtlUnwind(TargetFrame: ?*anyopaque, TargetIp: ?*anyopaque, ExceptionRecord: ?*anyopaque, ReturnValue: ?*anyopaque) callconv(W) void {
    _ = TargetFrame; _ = TargetIp; _ = ExceptionRecord; _ = ReturnValue;
}

fn OutputDebugStringA(lpOutputString: ?[*:0]const u8) callconv(W) void {
    if (lpOutputString) |str| {
        std.debug.print("[GAME_DEBUG] {s}", .{std.mem.sliceTo(str, 0)});
    }
}

fn OutputDebugStringW(lpOutputString: ?[*:0]const u16) callconv(W) void {
    _ = lpOutputString;
}

fn GetStdHandle(n: u32) callconv(W) usize {
    return switch (n) {
        0xFFFFFFF6 => 0x1000, // STD_INPUT_HANDLE  (-10)
        0xFFFFFFF5 => 0x1001, // STD_OUTPUT_HANDLE (-11)
        0xFFFFFFF4 => 0x1002, // STD_ERROR_HANDLE  (-12)
        else => 0xFFFFFFFF,
    };
}

fn SetStdHandle(nStdHandle: u32, hHandle: usize) callconv(W) i32 {
    _ = nStdHandle; _ = hHandle;
    return 1;
}

fn SetHandleCount(uNumber: u32) callconv(W) u32 {
    return uNumber;
}

fn WriteFile(h: usize, buf: ?[*]const u8, n: u32, written: ?*u32, overlapped: ?*anyopaque) callconv(W) i32 {
    _ = overlapped;
    if (buf == null and n != 0) return 0;
    const fd: i32 = if (h == 0x1001) 1 else if (h == 0x1002) 2 else if (h >= 0x10000 and h < 0x20000) @intCast(h - 0x10000) else {
        g_last_error = 6;
        return 0;
    };
    var done: usize = 0;
    while (done < n) {
        const rc = linux.write(fd, buf.? + done, n - done);
        if (linux.errno(rc) != .SUCCESS) break;
        if (rc == 0) break;
        done += rc;
    }
    if (written) |w| w.* = @intCast(done);
    return if (done == n) 1 else 0;
}

fn ReadFile(hFile: usize, lpBuffer: ?[*]u8, nNumberOfBytesToRead: u32, lpNumberOfBytesRead: ?*u32, lpOverlapped: ?*anyopaque) callconv(W) i32 {
    _ = lpOverlapped;
    if (hFile < 0x10000 or hFile >= 0x20000 or lpBuffer == null) {
        if (lpNumberOfBytesRead) |nb| nb.* = 0;
        g_last_error = 6;
        return 0;
    }
    const fd: i32 = @intCast(hFile - 0x10000);
    const rc = linux.read(fd, lpBuffer.?, nNumberOfBytesToRead);
    if (linux.errno(rc) != .SUCCESS) {
        if (lpNumberOfBytesRead) |nb| nb.* = 0;
        return 0;
    }
    if (lpNumberOfBytesRead) |nb| nb.* = @intCast(rc);
    return 1;
}

fn CloseHandle(hObject: usize) callconv(W) i32 {
    if (threads_mod.closeHandle(hObject)) return 1;
    if (hObject >= 0x10000 and hObject < 0x20000) {
        const fd: i32 = @intCast(hObject - 0x10000);
        _ = linux.close(fd);
    }
    return 1;
}

/// The Win32 access rights and creation dispositions a caller can ask for.
///
/// CreateFileA used to ignore every one of them: it opened the path O_RDWR,
/// then O_RDONLY, and when neither succeeded it handed back a read-only
/// handle to the TARGET EXECUTABLE. A guest that asked for a file it had not
/// created yet -- Fallout: New Vegas opens Warnings.txt, its ini and its
/// saved settings that way, and it opens them for WRITE -- therefore got an
/// unrelated file it could not write to, with a return code indistinguishable
/// from success. Measured: the guest asked for Warnings.txt, was handed
/// FalloutNV.exe, wrote nothing, and quit at once.
///
/// The dispositions are honoured now, so the answer names the real reason
/// when the file cannot be had: not found, already exists, access denied.
const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const CREATE_NEW: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;
const OPEN_ALWAYS: u32 = 4;
const TRUNCATE_EXISTING: u32 = 5;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_ALREADY_EXISTS: u32 = 183;

fn CreateFileA(lpFileName: ?[*:0]const u8, dwDesiredAccess: u32, dwShareMode: u32, lpSecurityAttributes: ?*anyopaque, dwCreationDisposition: u32, dwFlagsAndAttributes: u32, hTemplateFile: usize) callconv(W) usize {
    _ = dwShareMode; _ = lpSecurityAttributes; _ = dwFlagsAndAttributes; _ = hTemplateFile;
    if (lpFileName) |fn_ptr| {
        const path = std.mem.sliceTo(fn_ptr, 0);
        std.debug.print("[WINS:Kernel32] CreateFileA(\"{s}\", access=0x{x}, disp={d})\n", .{ path, dwDesiredAccess, dwCreationDisposition });
        var norm_buf: [512]u8 = undefined;
        const norm_len = @min(norm_buf.len - 1, path.len);
        for (0..norm_len) |i| {
            norm_buf[i] = if (path[i] == '\\') '/' else path[i];
        }
        norm_buf[norm_len] = 0;
        const norm_slice = norm_buf[0..norm_len:0];

        // What the caller asked to do with the file once it has it.
        const wants_read = dwDesiredAccess & GENERIC_READ != 0 or dwDesiredAccess == 0;
        const wants_write = dwDesiredAccess & GENERIC_WRITE != 0;

        var open_flags: linux.O = .{
            .ACCMODE = if (wants_write and wants_read) .RDWR else if (wants_write) .WRONLY else .RDONLY,
        };
        var must_exist = false;
        switch (dwCreationDisposition) {
            CREATE_NEW => {
                open_flags.CREAT = true;
                open_flags.EXCL = true;
            },
            CREATE_ALWAYS => {
                open_flags.CREAT = true;
                open_flags.TRUNC = true;
            },
            OPEN_EXISTING => must_exist = true,
            OPEN_ALWAYS => open_flags.CREAT = true,
            TRUNCATE_EXISTING => {
                must_exist = true;
                open_flags.TRUNC = true;
            },
            // An unmodelled disposition must not become a silent default.
            else => must_exist = true,
        }

        const fd = linux.open(norm_slice.ptr, open_flags, 0o644);
        if (linux.errno(fd) == .SUCCESS) {
            std.debug.print("  -> SUCCESS fd={}\n", .{fd});
            g_last_error = 0;
            return @as(usize, @intCast(fd)) + 0x10000;
        }
        const open_errno = linux.errno(fd);

        // Win32 paths are case-insensitive: "DATA/Fallout - Textures.bsa"
        // names the same file as "Data/Fallout - Textures.bsa". Retry with
        // the real on-disk spelling before giving up (filecase_probe.c).
        if (open_errno == .NOENT) {
            var resolved_buf: [512]u8 = undefined;
            if (resolvePathCaseInsensitive(norm_slice, &resolved_buf)) |resolved| {
                const fd_ci = linux.open(resolved.ptr, open_flags, 0o644);
                if (linux.errno(fd_ci) == .SUCCESS) {
                    std.debug.print("  -> SUCCESS [case-insensitive: {s}] fd={}\n", .{ resolved, fd_ci });
                    g_last_error = 0;
                    return @as(usize, @intCast(fd_ci)) + 0x10000;
                }
            }
        }

        // A path with a drive letter or a directory prefix the loader's cwd
        // cannot resolve still names one of the game's own files: the game
        // runs with the loader's cwd set to the install directory, so the
        // basename resolves there. Only reading is retried this way -- a
        // creation request for a nested path is answered by the kernel, not
        // rewritten into a different directory.
        if (!must_exist and !wants_write) {
            const basename = if (std.mem.lastIndexOfScalar(u8, norm_slice, '/')) |s| norm_slice[s + 1 ..] else norm_slice;
            if (basename.len > 0) {
                var base_buf: [256]u8 = undefined;
                const b_len = @min(base_buf.len - 1, basename.len);
                @memcpy(base_buf[0..b_len], basename[0..b_len]);
                base_buf[b_len] = 0;
                const base_slice = base_buf[0..b_len:0];

                const read_flags: linux.O = .{ .ACCMODE = .RDONLY };
                const fd_b = linux.open(base_slice.ptr, read_flags, 0);
                if (linux.errno(fd_b) == .SUCCESS) {
                    std.debug.print("  -> SUCCESS [Basename RO: {s}] fd={}\n", .{ base_slice, fd_b });
                    g_last_error = 0;
                    return @as(usize, @intCast(fd_b)) + 0x10000;
                }
            }
        }

        // Every failure now names what actually went wrong.
        g_last_error = switch (open_errno) {
            .NOENT => fileNotFoundError(norm_slice),
            .ACCES => ERROR_ACCESS_DENIED,
            .PERM => ERROR_ACCESS_DENIED,
            .EXIST => ERROR_ALREADY_EXISTS,
            else => ERROR_FILE_NOT_FOUND,
        };
        std.debug.print("  -> FAILED (kernel errno {d})\n", .{@intFromEnum(open_errno)});
        return 0xFFFFFFFF; // INVALID_HANDLE_VALUE
    }
    std.debug.print("  -> FAILED (null name)\n", .{});
    g_last_error = ERROR_FILE_NOT_FOUND;
    return 0xFFFFFFFF; // INVALID_HANDLE_VALUE
}

fn CreateFileW(lpFileName: ?[*:0]const u16, dwDesiredAccess: u32, dwShareMode: u32, lpSecurityAttributes: ?*anyopaque, dwCreationDisposition: u32, dwFlagsAndAttributes: u32, hTemplateFile: usize) callconv(W) usize {
    if (lpFileName) |wide_ptr| {
        var utf8_buf: [512]u8 = undefined;
        var len: usize = 0;
        while (wide_ptr[len] != 0 and len < 510) : (len += 1) {
            utf8_buf[len] = if (wide_ptr[len] < 128) @intCast(wide_ptr[len]) else '?';
        }
        utf8_buf[len] = 0;
        return CreateFileA(utf8_buf[0..len:0].ptr, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }
    g_last_error = 2;
    return 0xFFFFFFFF;
}

fn GetFileSize(hFile: usize, lpFileSizeHigh: ?*u32) callconv(W) u32 {
    if (hFile < 0x10000 or hFile >= 0x20000) {
        g_last_error = 6;
        return 0xFFFFFFFF;
    }
    const fd: isize = @intCast(hFile - 0x10000);
    const cur = linux.syscall3(.lseek, @as(usize, @bitCast(fd)), 0, linux.SEEK.CUR);
    const size = linux.syscall3(.lseek, @as(usize, @bitCast(fd)), 0, linux.SEEK.END);
    _ = linux.syscall3(.lseek, @as(usize, @bitCast(fd)), cur, linux.SEEK.SET);
    if (lpFileSizeHigh) |high| high.* = @intCast(@as(u64, size) >> 32);
    return @intCast(size & 0xFFFFFFFF);
}

fn GetFileSizeEx(hFile: usize, lpFileSize: ?*i64) callconv(W) i32 {
    if (hFile < 0x10000 or hFile >= 0x20000 or lpFileSize == null) {
        g_last_error = 6;
        return 0;
    }
    const fd: isize = @intCast(hFile - 0x10000);
    const cur = linux.syscall3(.lseek, @as(usize, @bitCast(fd)), 0, linux.SEEK.CUR);
    const size = linux.syscall3(.lseek, @as(usize, @bitCast(fd)), 0, linux.SEEK.END);
    _ = linux.syscall3(.lseek, @as(usize, @bitCast(fd)), cur, linux.SEEK.SET);
    lpFileSize.?.* = @intCast(size);
    return 1;
}

fn SetFilePointer(hFile: usize, lDistanceToMove: i32, lpDistanceToMoveHigh: ?*i32, dwMoveMethod: u32) callconv(W) u32 {
    _ = lpDistanceToMoveHigh;
    if (hFile < 0x10000 or hFile >= 0x20000) {
        g_last_error = 6;
        return 0xFFFFFFFF;
    }
    const fd: isize = @intCast(hFile - 0x10000);
    const whence: usize = switch (dwMoveMethod) {
        0 => linux.SEEK.SET,
        1 => linux.SEEK.CUR,
        2 => linux.SEEK.END,
        else => linux.SEEK.SET,
    };
    const dist: isize = @intCast(lDistanceToMove);
    const rc = linux.syscall3(.lseek, @as(usize, @bitCast(fd)), @as(usize, @bitCast(dist)), whence);
    return @intCast(rc);
}

fn SetFilePointerEx(hFile: usize, liDistanceToMove: i64, lpNewFilePointer: ?*i64, dwMoveMethod: u32) callconv(W) i32 {
    if (hFile < 0x10000 or hFile >= 0x20000) {
        g_last_error = 6;
        return 0;
    }
    const fd: isize = @intCast(hFile - 0x10000);
    const whence: usize = switch (dwMoveMethod) {
        0 => linux.SEEK.SET,
        1 => linux.SEEK.CUR,
        2 => linux.SEEK.END,
        else => linux.SEEK.SET,
    };
    const dist: isize = @intCast(liDistanceToMove);
    const rc = linux.syscall3(.lseek, @as(usize, @bitCast(fd)), @as(usize, @bitCast(dist)), whence);
    if (lpNewFilePointer) |np| np.* = @intCast(rc);
    return 1;
}

fn SetEndOfFile(hFile: usize) callconv(W) i32 {
    _ = hFile;
    return 1;
}

fn FlushFileBuffers(hFile: usize) callconv(W) i32 {
    if (hFile >= 0x10000 and hFile < 0x20000) {
        const fd: i32 = @intCast(hFile - 0x10000);
        _ = linux.fsync(fd);
    }
    return 1;
}

// --- Win32 case-insensitive path resolution -------------------------------
// Win32 treats every path component case-insensitively; Linux does not.
// FalloutNV probes its archives as "DATA/Fallout - Textures.bsa" while the
// directory on disk is "Data": without this, GetFileAttributesA answers
// "not found", no BSA is ever opened, and the game dies on a NULL dereference
// before the first frame. native/testdata/filecase_probe.c pins the semantics
// against the Wine oracle (tools/diff_wine.sh).

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    }
    return true;
}

fn ciAppend(buf: []u8, len: *usize, s: []const u8) bool {
    if (len.* + s.len + 1 > buf.len) return false;
    @memcpy(buf[len.* .. len.* + s.len], s);
    len.* += s.len;
    buf[len.*] = 0;
    return true;
}

// Write the real on-disk spelling of `path` (forward slashes, relative or
// absolute) into out_buf, NUL-terminated, and return it. Each component is
// tried exactly first, then matched ASCII case-insensitively against its
// parent directory. "." components are dropped, ".." is kept verbatim.
// Returns null when a component has no match.
fn resolvePathCaseInsensitive(path: []const u8, out_buf: []u8) ?[:0]const u8 {
    if (path.len == 0 or out_buf.len < 2) return null;
    var out_len: usize = 0;
    if (path[0] == '/') {
        out_buf[0] = '/';
        out_buf[1] = 0;
        out_len = 1;
    }
    var it = std.mem.splitScalar(u8, path, '/');
    var comp_buf: [256]u8 = undefined;
    var dent_buf: [4096]u8 align(8) = undefined;
    while (it.next()) |comp| {
        if (comp.len == 0 or std.mem.eql(u8, comp, ".")) continue;
        if (comp.len >= comp_buf.len) return null;
        if (out_len > 0 and out_buf[out_len - 1] != '/') {
            if (!ciAppend(out_buf, &out_len, "/")) return null;
        }
        if (std.mem.eql(u8, comp, "..")) {
            if (!ciAppend(out_buf, &out_len, "..")) return null;
            continue;
        }
        @memcpy(comp_buf[0..comp.len], comp);
        comp_buf[comp.len] = 0;
        const parent: [*:0]const u8 = if (out_len == 0) "." else @ptrCast(out_buf.ptr);
        const dir_rc = linux.open(parent, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
        if (linux.errno(dir_rc) != .SUCCESS) return null;
        const dir_fd: i32 = @intCast(dir_rc);
        defer _ = linux.close(dir_fd);

        if (linux.faccessat(dir_fd, comp_buf[0..comp.len :0].ptr, 0, 0) == 0) {
            if (!ciAppend(out_buf, &out_len, comp)) return null;
            continue;
        }
        var match_len: usize = 0;
        var found = false;
        while (!found) {
            const n = linux.getdents64(dir_fd, &dent_buf, dent_buf.len);
            if (linux.errno(n) != .SUCCESS or n == 0) break;
            var off: usize = 0;
            while (off < n) {
                const ent: *align(1) const linux.dirent64 = @ptrCast(&dent_buf[off]);
                const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&ent.name)), 0);
                if (asciiEqlIgnoreCase(name, comp)) {
                    if (name.len >= comp_buf.len) return null;
                    @memcpy(comp_buf[0..name.len], name);
                    match_len = name.len;
                    found = true;
                    break;
                }
                off += ent.reclen;
            }
        }
        if (!found) return null;
        if (!ciAppend(out_buf, &out_len, comp_buf[0..match_len])) return null;
    }
    if (out_len == 0) return null;
    return out_buf[0..out_len :0];
}

// ERROR_FILE_NOT_FOUND when only the last component is missing,
// ERROR_PATH_NOT_FOUND when a parent directory is missing (as Win32 does).
fn fileNotFoundError(path: []const u8) u32 {
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |s| {
        const parent = if (s == 0) "/" else path[0..s];
        var buf: [512]u8 = undefined;
        if (resolvePathCaseInsensitive(parent, &buf)) |rp| {
            if (linux.faccessat(linux.AT.FDCWD, rp.ptr, 0, 0) == 0) return 2;
        }
        return 3;
    }
    return 2;
}

fn GetFileAttributesA(lpFileName: ?[*:0]const u8) callconv(W) u32 {
    if (lpFileName) |name| {
        const slice = std.mem.sliceTo(name, 0);
        var norm_buf: [512]u8 = undefined;
        const norm_len = @min(norm_buf.len - 1, slice.len);
        for (0..norm_len) |i| {
            norm_buf[i] = if (slice[i] == '\\') '/' else slice[i];
        }
        norm_buf[norm_len] = 0;
        const norm_slice = norm_buf[0..norm_len:0];

        var target: [*:0]const u8 = norm_slice.ptr;
        var resolved_buf: [512]u8 = undefined;
        var rc = linux.faccessat(linux.AT.FDCWD, target, 0, 0);
        if (rc != 0) {
            if (resolvePathCaseInsensitive(norm_slice, &resolved_buf)) |resolved| {
                target = resolved.ptr;
                rc = linux.faccessat(linux.AT.FDCWD, target, 0, 0);
            }
        }
        if (rc == 0) {
            // The oracle reports FILE_ATTRIBUTE_ARCHIVE for plain files and
            // FILE_ATTRIBUTE_DIRECTORY for directories; nothing else is
            // modelled yet (read-only/hidden bits are not reported).
            var attrs: u32 = 0x20;
            var stx: linux.Statx = undefined;
            if (linux.errno(linux.statx(linux.AT.FDCWD, target, 0, .{ .TYPE = true }, &stx)) == .SUCCESS and
                (stx.mode & linux.S.IFMT) == linux.S.IFDIR)
            {
                attrs = 0x10;
            }
            std.debug.print("[WINS:Kernel32] GetFileAttributesA(\"{s}\") -> 0x{x}\n", .{ norm_slice, attrs });
            return attrs;
        }
        g_last_error = fileNotFoundError(norm_slice);
        std.debug.print("[WINS:Kernel32] GetFileAttributesA(\"{s}\") -> INVALID (err {})\n", .{ norm_slice, g_last_error });
    } else {
        g_last_error = 2; // ERROR_FILE_NOT_FOUND
    }
    return 0xFFFFFFFF;
}

fn DeleteFileA(lpFileName: ?[*:0]const u8) callconv(W) i32 {
    if (lpFileName) |p| {
        var buf: [512]u8 = undefined;
        var len: usize = 0;
        while (p[len] != 0 and len < 511) : (len += 1) {
            buf[len] = if (p[len] == '\\') '/' else p[len];
        }
        buf[len] = 0;
        const rc = linux.unlink(buf[0..len:0].ptr);
        if (linux.errno(rc) == .SUCCESS) {
            std.debug.print("[WINS:Kernel32] DeleteFileA(\"{s}\") -> removed\n", .{buf[0..len]});
            return 1;
        }
        g_last_error = switch (linux.errno(rc)) {
            .NOENT => 2, // ERROR_FILE_NOT_FOUND
            .ACCES => 5, // ERROR_ACCESS_DENIED
            else => 5,
        };
        std.debug.print("[WINS:Kernel32] DeleteFileA(\"{s}\") -> failed (kernel errno {d})\n", .{ buf[0..len], @intFromEnum(linux.errno(rc)) });
        return 0;
    }
    g_last_error = 2; // ERROR_FILE_NOT_FOUND
    return 0;
}

/// Move and copy, or an answer that says why not.
///
/// Both used to return 1 unconditionally. A guest that moves a file and is
/// told it worked finds the old name still there and the new one absent, and
/// nothing in the return value distinguishes that from success. Neither is on
/// the path Fallout: New Vegas takes (measured: zero calls), so they are here
/// to stop claiming work that was never done, not because a symptom named
/// them.
fn winNormPathZ(path: ?[*:0]const u8, buf: []u8) ?[:0]u8 {
    if (path == null) return null;
    const src = std.mem.sliceTo(path.?, 0);
    if (src.len >= buf.len) return null;
    for (src, 0..) |c, i| buf[i] = if (c == '\\') '/' else c;
    buf[src.len] = 0;
    return buf[0..src.len :0];
}

fn MoveFileA(lpExistingFileName: ?[*:0]const u8, lpNewFileName: ?[*:0]const u8) callconv(W) i32 {
    var from_buf: [512]u8 = undefined;
    var to_buf: [512]u8 = undefined;
    const from = winNormPathZ(lpExistingFileName, &from_buf) orelse {
        g_last_error = 2; // ERROR_FILE_NOT_FOUND
        return 0;
    };
    const to = winNormPathZ(lpNewFileName, &to_buf) orelse {
        g_last_error = 2; // ERROR_FILE_NOT_FOUND
        return 0;
    };
    const rc = linux.rename(from.ptr, to.ptr);
    if (linux.errno(rc) == .SUCCESS) return 1;
    g_last_error = switch (linux.errno(rc)) {
        .NOENT => 2, // ERROR_FILE_NOT_FOUND
        .ACCES => 5, // ERROR_ACCESS_DENIED
        .EXIST => 183, // ERROR_ALREADY_EXISTS
        else => 5,
    };
    return 0;
}

fn CopyFileA(lpExistingFileName: ?[*:0]const u8, lpNewFileName: ?[*:0]const u8, bFailIfExists: i32) callconv(W) i32 {
    var from_buf: [512]u8 = undefined;
    var to_buf: [512]u8 = undefined;
    const from = winNormPathZ(lpExistingFileName, &from_buf) orelse {
        g_last_error = 2; // ERROR_FILE_NOT_FOUND
        return 0;
    };
    const to = winNormPathZ(lpNewFileName, &to_buf) orelse {
        g_last_error = 2; // ERROR_FILE_NOT_FOUND
        return 0;
    };
    const src_fd = linux.open(from.ptr, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(src_fd) != .SUCCESS) {
        g_last_error = 2; // ERROR_FILE_NOT_FOUND
        return 0;
    }
    defer _ = linux.close(@intCast(src_fd));

    var dst_flags: linux.O = .{ .ACCMODE = .WRONLY, .CREAT = true };
    if (bFailIfExists != 0) dst_flags.EXCL = true;
    const dst_fd = linux.open(to.ptr, dst_flags, 0o644);
    if (linux.errno(dst_fd) != .SUCCESS) {
        g_last_error = switch (linux.errno(dst_fd)) {
            .EXIST => 183, // ERROR_ALREADY_EXISTS: the caller asked to fail on it.
            .ACCES => 5, // ERROR_ACCESS_DENIED
            .NOENT => 3, // ERROR_PATH_NOT_FOUND
            else => 5,
        };
        return 0;
    }
    defer _ = linux.close(@intCast(dst_fd));

    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const n = linux.read(@intCast(src_fd), &buf, buf.len);
        if (linux.errno(n) != .SUCCESS or n == 0) break;
        var off: usize = 0;
        while (off < n) {
            const w = linux.write(@intCast(dst_fd), buf[off..].ptr, @as(usize, @intCast(n)) - off);
            if (linux.errno(w) != .SUCCESS or w == 0) {
                g_last_error = 5; // ERROR_ACCESS_DENIED
                return 0;
            }
            off += @intCast(w);
        }
    }
    return 1;
}

/// The directory is really made, or the answer says why it was not.
///
/// The stub returned 1 unconditionally, which is indistinguishable from a
/// created directory: the game asked for its "My Games" folder, was told it
/// had one, and then tried to write settings into a directory that does not
/// exist. ERROR_ALREADY_EXISTS is the Win32 answer when the name is taken,
/// not a failure.
fn CreateDirectoryA(lpPathName: ?[*:0]const u8, lpSecurityAttributes: ?*anyopaque) callconv(W) i32 {
    _ = lpSecurityAttributes;
    if (lpPathName) |p| {
        var buf: [512]u8 = undefined;
        var len: usize = 0;
        while (p[len] != 0 and len < 511) : (len += 1) {
            buf[len] = if (p[len] == '\\') '/' else p[len];
        }
        buf[len] = 0;
        const rc = linux.mkdir(buf[0..len:0].ptr, 0o755);
        if (linux.errno(rc) == .SUCCESS) {
            std.debug.print("[WINS:Kernel32] CreateDirectoryA(\"{s}\") -> created\n", .{buf[0..len]});
            return 1;
        }
        g_last_error = switch (linux.errno(rc)) {
            .EXIST => 183, // ERROR_ALREADY_EXISTS: the directory is there.
            .NOENT => 3, // ERROR_PATH_NOT_FOUND: a parent is missing.
            .ACCES => 5, // ERROR_ACCESS_DENIED
            else => 5,
        };
        std.debug.print("[WINS:Kernel32] CreateDirectoryA(\"{s}\") -> failed (kernel errno {d})\n", .{ buf[0..len], @intFromEnum(linux.errno(rc)) });
        return 0;
    }
    g_last_error = 3; // ERROR_PATH_NOT_FOUND
    return 0;
}

fn GetCurrentDirectoryA(nBufferLength: u32, lpBuffer: ?[*]u8) callconv(W) u32 {
    if (lpBuffer == null or nBufferLength == 0) return 0;
    const cur = "./";
    const len: u32 = @min(nBufferLength - 1, @as(u32, @intCast(cur.len)));
    @memcpy(lpBuffer.?[0..len], cur[0..len]);
    lpBuffer.?[len] = 0;
    return len;
}

fn GetFullPathNameA(lpFileName: ?[*:0]const u8, nBufferLength: u32, lpBuffer: ?[*]u8, lpFilePart: ?*?[*:0]const u8) callconv(W) u32 {
    if (lpFileName == null or lpBuffer == null or nBufferLength == 0) return 0;
    const name = std.mem.sliceTo(lpFileName.?, 0);
    const len: u32 = @min(nBufferLength - 1, @as(u32, @intCast(name.len)));
    @memcpy(lpBuffer.?[0..len], name[0..len]);
    lpBuffer.?[len] = 0;
    if (lpFilePart) |part| part.* = lpFileName;
    return len;
}

fn GetDriveTypeA(lpRootPathName: ?[*:0]const u8) callconv(W) u32 {
    _ = lpRootPathName;
    return 3; // DRIVE_FIXED
}

// ---------------------------------------------------------------------------
// The guest's own ini files.
//
// GetPrivateProfile* answered with the caller's own default and never opened
// the file, and WritePrivateProfileStringA reported success without writing a
// byte. Fallout: New Vegas reads its whole display configuration -- adapter
// index, resolution, fullscreen flag, the D3D device name -- out of
// FalloutPrefs.ini through those functions and writes them back when the
// settings change, so the game was running on the values it passed to itself
// and the file it thought it was maintaining never appeared on disk.
//
// The format is the one Win32 reads: comments start with ';', a line in
// brackets opens a section, and `key = value` is a setting. Section and key
// names are matched case-insensitively, as Win32 does.
const INI_MAX: usize = 64 * 1024;

/// Every space and tab, and the carriage return a Windows line ending leaves
/// behind, trimmed from both ends.
fn iniTrim(line: []const u8) []const u8 {
    var start: usize = 0;
    var end: usize = line.len;
    while (start < end and (line[start] == ' ' or line[start] == '\t' or line[start] == '\r')) start += 1;
    while (end > start and (line[end - 1] == ' ' or line[end - 1] == '\t' or line[end - 1] == '\r')) end -= 1;
    return line[start..end];
}

/// Win32 strips one matching pair of surrounding quotes (double or single)
/// from a profile value after trimming whitespace; inner whitespace and inner
/// quotes are kept, and a lone or mismatched quote is left alone. Measured
/// against Wine with native/testdata/profile_probe.c (tools/diff_wine.sh).
/// FalloutNV stores sD3DDevice="AMD Radeon 760M Graphics (RADV PHOENIX)" with
/// the quotes and compares the returned string to the D3D9 adapter name, so
/// returning the quotes sent the game to FalloutNVLauncher.exe every boot.
fn iniUnquote(value: []const u8) []const u8 {
    if (value.len >= 2 and (value[0] == '"' or value[0] == '\'') and value[value.len - 1] == value[0]) {
        return value[1 .. value.len - 1];
    }
    return value;
}

fn iniNameEq(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

/// The named file's contents, or 0 when it is not there.
fn iniReadFile(path: []const u8, buf: []u8) usize {
    if (path.len == 0 or path.len >= buf.len) return 0;
    for (path, 0..) |c, i| buf[i] = if (c == '\\') '/' else c;
    buf[path.len] = 0;
    const slice = buf[0..path.len :0];
    const fd = linux.open(slice.ptr, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(fd) != .SUCCESS) return 0;
    defer _ = linux.close(@intCast(fd));
    var total: usize = 0;
    while (total < buf.len) {
        const n = linux.read(@intCast(fd), buf[total..].ptr, buf.len - total);
        if (linux.errno(n) != .SUCCESS) break;
        if (n == 0) break;
        total += @intCast(n);
    }
    return total;
}

fn iniCopyOut(out: [*]u8, n: u32, value: []const u8) u32 {
    const room: u32 = n - 1;
    const len: u32 = @min(room, @as(u32, @intCast(value.len)));
    @memcpy(out[0..len], value[0..len]);
    out[len] = 0;
    return len;
}

fn iniParseInt(value: []const u8) ?i32 {
    const t = iniTrim(value);
    if (t.len == 0) return null;
    const parsed = std.fmt.parseInt(i64, t, 0) catch {
        // Win32 accepts a trailing fragment ("640x480" is not one) by reading
        // the leading digits; a value with digits followed by junk still
        // yields those digits.
        var end: usize = 0;
        var neg = false;
        if (t[0] == '-') {
            neg = true;
            end = 1;
        }
        while (end < t.len and t[end] >= '0' and t[end] <= '9') end += 1;
        if (end == 0 or (end == 1 and neg)) return null;
        return @intCast(std.fmt.parseInt(i64, t[0..end], 10) catch return null);
    };
    return @intCast(@min(@as(i64, std.math.maxInt(i32)), @max(@as(i64, std.math.minInt(i32)), parsed)));
}

/// The value for `key` inside `section`, or null when the file has neither.
fn iniLookup(app: []const u8, key: []const u8, file: ?[*:0]const u8) ?[]const u8 {
    if (file == null) return null;
    var buf: [INI_MAX]u8 = undefined;
    const n = iniReadFile(std.mem.sliceTo(file.?, 0), &buf);
    if (n == 0) return null;
    var in_section = false;
    var it = std.mem.splitScalar(u8, buf[0..n], '\n');
    while (it.next()) |raw| {
        const line = iniTrim(raw);
        if (line.len == 0 or line[0] == ';') continue;
        if (line[0] == '[') {
            const close = std.mem.indexOfScalar(u8, line, ']') orelse continue;
            in_section = iniNameEq(iniTrim(line[1..close]), app);
            continue;
        }
        if (!in_section) continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        if (!iniNameEq(iniTrim(line[0..eq]), key)) continue;
        return iniUnquote(iniTrim(line[eq + 1 ..]));
    }
    return null;
}

/// Rewrite `content` in `scratch` with `key = value` inside `section`.
///
/// The section is appended when the file has none, and the key is appended to
/// the section when it is not there. Returns the new length, or 0 when it does
/// not fit. Writing back to the same file keeps the guest's own formatting for
/// everything it did not ask to change.
fn iniWriteValue(scratch: []u8, content_len: usize, app: []const u8, key: []const u8, value: []const u8) usize {
    var out_len: usize = 0;
    var in_section = false;
    var replaced = false;
    var it = std.mem.splitScalar(u8, scratch[0..content_len], '\n');
    while (it.next()) |raw| {
        if (out_len >= scratch.len) return 0;
        const line = iniTrim(raw);
        if (line.len > 0 and line[0] == '[') {
            const close = std.mem.indexOfScalar(u8, line, ']') orelse 0;
            if (close > 0) in_section = iniNameEq(iniTrim(line[1..close]), app);
        } else if (in_section and !replaced) {
            const eq = std.mem.indexOfScalar(u8, line, '=') orelse 0;
            if (eq > 0 and iniNameEq(iniTrim(line[0..eq]), key)) {
                const replaced_line = std.fmt.bufPrint(scratch[out_len..], "{s}={s}\n", .{ key, value }) catch return 0;
                out_len += replaced_line.len;
                replaced = true;
                continue;
            }
        }
        const n = @min(raw.len, scratch.len - out_len);
        @memcpy(scratch[out_len .. out_len + n], raw[0..n]);
        out_len += n;
        // splitScalar consumes the separator, so it is put back here.
        if (out_len < scratch.len) {
            scratch[out_len] = '\n';
            out_len += 1;
        } else return 0;
    }
    if (!replaced) {
        // The section exists: the key goes in at its end. It does not: the
        // section is created first, with the key inside it.
        if (!in_section) {
            const header = std.fmt.bufPrint(scratch[out_len..], "[{s}]\n", .{app}) catch return 0;
            out_len += header.len;
        }
        const entry = std.fmt.bufPrint(scratch[out_len..], "{s}={s}\n", .{ key, value }) catch return 0;
        out_len += entry.len;
    }
    return out_len;
}

fn iniFlushFile(path: []const u8, data: []const u8) i32 {
    if (path.len == 0 or path.len >= 512) {
        g_last_error = 2; // ERROR_FILE_NOT_FOUND
        return 0;
    }
    var name_buf: [512]u8 = undefined;
    for (path, 0..) |c, i| name_buf[i] = if (c == '\\') '/' else c;
    name_buf[path.len] = 0;
    const slice = name_buf[0..path.len :0];
    const fd = linux.open(slice.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (linux.errno(fd) != .SUCCESS) {
        g_last_error = 5; // ERROR_ACCESS_DENIED
        return 0;
    }
    defer _ = linux.close(@intCast(fd));
    var off: usize = 0;
    while (off < data.len) {
        const n = linux.write(@intCast(fd), data[off..].ptr, data.len - off);
        if (linux.errno(n) != .SUCCESS) {
            g_last_error = 5; // ERROR_ACCESS_DENIED
            return 0;
        }
        if (n == 0) break;
        off += @intCast(n);
    }
    return 1;
}

fn GetPrivateProfileStringA(lpAppName: ?[*:0]const u8, lpKeyName: ?[*:0]const u8, lpDefault: ?[*:0]const u8, lpReturnedString: ?[*]u8, nSize: u32, lpFileName: ?[*:0]const u8) callconv(W) u32 {
    if (lpReturnedString == null or nSize == 0) return 0;
    const fallback: []const u8 = if (lpDefault) |d| std.mem.sliceTo(d, 0) else "";
    if (lpAppName) |app| {
        const app_name = std.mem.sliceTo(app, 0);
        const key_name = if (lpKeyName) |k| std.mem.sliceTo(k, 0) else "";
        if (iniLookup(app_name, key_name, lpFileName)) |value| {
            const n = iniCopyOut(lpReturnedString.?, nSize, value);
            std.debug.print("[WINS:Kernel32] GetPrivateProfileStringA(\"{s}\", \"{s}\", file=\"{s}\") -> \"{s}\" (rc={d})\n", .{
                app_name, key_name,
                if (lpFileName) |f| std.mem.sliceTo(f, 0) else "(null)",
                value, n,
            });
            return n;
        }
    }
    const n = iniCopyOut(lpReturnedString.?, nSize, fallback);
    std.debug.print("[WINS:Kernel32] GetPrivateProfileStringA(\"{s}\", \"{s}\", file=\"{s}\") -> default \"{s}\" (rc={d})\n", .{
        if (lpAppName) |a| std.mem.sliceTo(a, 0) else "(null)",
        if (lpKeyName) |k| std.mem.sliceTo(k, 0) else "(null)",
        if (lpFileName) |f| std.mem.sliceTo(f, 0) else "(null)",
        fallback, n,
    });
    return n;
}

fn GetPrivateProfileIntA(lpAppName: ?[*:0]const u8, lpKeyName: ?[*:0]const u8, nDefault: i32, lpFileName: ?[*:0]const u8) callconv(W) i32 {
    if (lpAppName) |app| {
        const app_name = std.mem.sliceTo(app, 0);
        const key_name = if (lpKeyName) |k| std.mem.sliceTo(k, 0) else "";
        if (iniLookup(app_name, key_name, lpFileName)) |value| {
            const v = iniParseInt(value) orelse nDefault;
            std.debug.print("[WINS:Kernel32] GetPrivateProfileIntA(\"{s}\", \"{s}\", file=\"{s}\") -> {d}\n", .{
                app_name, key_name,
                if (lpFileName) |f| std.mem.sliceTo(f, 0) else "(null)",
                v,
            });
            return v;
        }
    }
    std.debug.print("[WINS:Kernel32] GetPrivateProfileIntA(\"{s}\", \"{s}\", file=\"{s}\") -> default {d}\n", .{
        if (lpAppName) |a| std.mem.sliceTo(a, 0) else "(null)",
        if (lpKeyName) |k| std.mem.sliceTo(k, 0) else "(null)",
        if (lpFileName) |f| std.mem.sliceTo(f, 0) else "(null)",
        nDefault,
    });
    return nDefault;
}

fn WritePrivateProfileStringA(lpAppName: ?[*:0]const u8, lpKeyName: ?[*:0]const u8, lpString: ?[*:0]const u8, lpFileName: ?[*:0]const u8) callconv(W) i32 {
    if (lpAppName == null or lpFileName == null) return 0;
    const app_name = std.mem.sliceTo(lpAppName.?, 0);
    const file_name = std.mem.sliceTo(lpFileName.?, 0);
    // A null key with a null value means "delete this section"; a null key with
    // a value means "write this whole section". Neither is what a settings file
    // does, and guessing would be worse than reporting the unsupported case.
    if (lpKeyName == null or lpString == null) {
        g_last_error = 50; // ERROR_NOT_SUPPORTED
        return 0;
    }
    const key_name = std.mem.sliceTo(lpKeyName.?, 0);
    const val = std.mem.sliceTo(lpString.?, 0);

    var buf: [INI_MAX]u8 = undefined;
    const have = iniReadFile(file_name, &buf);
    var content: []u8 = buf[0..have];

    // The section has to exist before a key can live in it, and the file has
    // to end on a line boundary before anything can be appended.
    if (content.len > 0 and content[content.len - 1] != '\n') {
        if (content.len + 1 < buf.len) {
            content = buf[0 .. have + 1];
            content[have] = '\n';
        }
    }
    const written = iniWriteValue(&buf, content.len, app_name, key_name, val);
    if (written == 0) {
        g_last_error = 5; // ERROR_ACCESS_DENIED
        return 0;
    }
    return iniFlushFile(file_name, buf[0..written]);
}

const WIN32_FIND_DATAA = extern struct {
    dwFileAttributes: u32,
    ftCreationTime: [2]u32,
    ftLastAccessTime: [2]u32,
    ftLastWriteTime: [2]u32,
    nFileSizeHigh: u32,
    nFileSizeLow: u32,
    dwReserved0: u32,
    dwReserved1: u32,
    cFileName: [260]u8,
    cAlternateFileName: [14]u8,
};

// Directory enumeration, as Win32 does it.
//
// These used to be stubs: FindFirstFileA ignored its pattern and always
// answered one entry, "FalloutNV.exe", attributes 0x80, size 0, time 0.
// FalloutNV lists its plugins with FindFirstFileA("DATA\\*.esm") and
// "DATA\\*.esp" and calls it on every master and archive before opening it
// (Proton relay log: 494 calls), so it never saw FalloutNV.esm and sat on the
// loading screen. Semantics pinned against Proton by
// native/testdata/find_probe.c: ASCII case-insensitive match of the last
// component ('*', '?', and "x.*" also matching names without a dot), parent
// resolved case-insensitively, "." and ".." listed, attributes 0x10/0x20,
// real size and times, errors 2 (no match), 3 (no parent), 18 (end), 6 (bad
// handle). Not modelled: 8.3 short names (cAlternateFileName stays empty),
// read-only/hidden bits, FindFirstFileExA.
const FIND_HANDLE_BASE: usize = 0x40000;
const FIND_HANDLE_STEP: usize = 4;
const MAX_FINDS = 64;

const FindState = struct {
    used: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    dir_fd: i32 = -1,
    pat_len: usize = 0,
    pat: [260]u8 = undefined,
    buf: [4096]u8 align(8) = undefined,
    buf_len: usize = 0,
    buf_off: usize = 0,
};
var g_finds: [MAX_FINDS]FindState = [_]FindState{.{}} ** MAX_FINDS;

fn findSlot(h: usize) ?*FindState {
    if (h < FIND_HANDLE_BASE) return null;
    const off = h - FIND_HANDLE_BASE;
    if (off % FIND_HANDLE_STEP != 0) return null;
    const i = off / FIND_HANDLE_STEP;
    if (i >= MAX_FINDS) return null;
    if (!g_finds[i].used.load(.acquire)) return null;
    return &g_finds[i];
}

fn asciiLower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

fn globMatchCi(pat: []const u8, name: []const u8) bool {
    var p: usize = 0;
    var n: usize = 0;
    var star_p: ?usize = null;
    var star_n: usize = 0;
    while (n < name.len) {
        if (p < pat.len and (pat[p] == '?' or (pat[p] != '*' and asciiLower(pat[p]) == asciiLower(name[n])))) {
            p += 1;
            n += 1;
        } else if (p < pat.len and pat[p] == '*') {
            star_p = p;
            star_n = n;
            p += 1;
        } else if (star_p) |sp| {
            p = sp + 1;
            star_n += 1;
            n = star_n;
        } else return false;
    }
    while (p < pat.len and pat[p] == '*') p += 1;
    return p == pat.len;
}

/// Win32 mask match: glob, and a trailing ".*" also accepts a name with no
/// dot at all (so "*.*" lists "Sub", "." and ".." as the oracle does).
fn win32MaskMatch(pat: []const u8, name: []const u8) bool {
    if (globMatchCi(pat, name)) return true;
    if (pat.len >= 2 and std.mem.endsWith(u8, pat, ".*") and std.mem.indexOfScalar(u8, name, '.') == null)
        return globMatchCi(pat[0 .. pat.len - 2], name);
    return false;
}

fn unixToFiletime(sec: i64, nsec: u32) [2]u32 {
    const t: u64 = @intCast(@max(0, (sec + 11644473600) * 10_000_000 + @divTrunc(@as(i64, nsec), 100)));
    return .{ @truncate(t), @truncate(t >> 32) };
}

/// Next directory entry of `st` that matches its pattern, written into `out`.
fn findAdvance(st: *FindState, out: *WIN32_FIND_DATAA) bool {
    while (true) {
        if (st.buf_off >= st.buf_len) {
            const n = linux.getdents64(st.dir_fd, &st.buf, st.buf.len);
            if (linux.errno(n) != .SUCCESS or n == 0) return false;
            st.buf_len = n;
            st.buf_off = 0;
        }
        const ent: *align(1) const linux.dirent64 = @ptrCast(&st.buf[st.buf_off]);
        st.buf_off += ent.reclen;
        const name_z: [*:0]const u8 = @ptrCast(&ent.name);
        const name = std.mem.sliceTo(name_z, 0);
        if (name.len >= out.cFileName.len) continue;
        if (!win32MaskMatch(st.pat[0..st.pat_len], name)) continue;

        var stx: linux.Statx = undefined;
        const want: linux.STATX = .{ .TYPE = true, .SIZE = true, .MTIME = true, .ATIME = true, .BTIME = true };
        if (linux.errno(linux.statx(st.dir_fd, name_z, 0, want, &stx)) != .SUCCESS) continue; // vanished
        @memset(@as([*]u8, @ptrCast(out))[0..@sizeOf(WIN32_FIND_DATAA)], 0);
        const is_dir = (stx.mode & linux.S.IFMT) == linux.S.IFDIR;
        out.dwFileAttributes = if (is_dir) 0x10 else 0x20;
        if (!is_dir) {
            out.nFileSizeLow = @truncate(stx.size);
            out.nFileSizeHigh = @truncate(stx.size >> 32);
        }
        out.ftLastWriteTime = unixToFiletime(stx.mtime.sec, stx.mtime.nsec);
        out.ftLastAccessTime = unixToFiletime(stx.atime.sec, stx.atime.nsec);
        out.ftCreationTime = if (stx.mask.BTIME)
            unixToFiletime(stx.btime.sec, stx.btime.nsec)
        else
            out.ftLastWriteTime;
        @memcpy(out.cFileName[0..name.len], name);
        return true;
    }
}

fn FindFirstFileA(lpFileName: ?[*:0]const u8, lpFindFileData: ?*anyopaque) callconv(W) usize {
    const INVALID: usize = 0xFFFFFFFF;
    const name_p = lpFileName orelse {
        g_last_error = 2;
        return INVALID;
    };
    const out: *WIN32_FIND_DATAA = @ptrCast(@alignCast(lpFindFileData orelse {
        g_last_error = 87; // ERROR_INVALID_PARAMETER
        return INVALID;
    }));
    const raw = std.mem.sliceTo(name_p, 0);
    var norm: [512]u8 = undefined;
    if (raw.len >= norm.len) {
        g_last_error = 206; // ERROR_FILENAME_EXCED_RANGE
        return INVALID;
    }
    for (raw, 0..) |c, i| norm[i] = if (c == '\\') '/' else c;
    const path = norm[0..raw.len];

    const slash = std.mem.lastIndexOfScalar(u8, path, '/');
    const pat = if (slash) |s| path[s + 1 ..] else path;
    if (pat.len == 0 or pat.len >= 260) {
        g_last_error = 2;
        std.debug.print("[WINS:Kernel32] FindFirstFileA(\"{s}\") -> INVALID (err 2)\n", .{raw});
        return INVALID;
    }
    var parent_buf: [512]u8 = undefined;
    var parent: [*:0]const u8 = ".";
    if (slash) |s| {
        const dir = if (s == 0) "/" else path[0..s];
        if (resolvePathCaseInsensitive(dir, &parent_buf)) |rp| parent = rp.ptr else {
            g_last_error = 3; // ERROR_PATH_NOT_FOUND
            std.debug.print("[WINS:Kernel32] FindFirstFileA(\"{s}\") -> INVALID (err 3)\n", .{raw});
            return INVALID;
        }
    }

    var idx: usize = 0;
    while (idx < MAX_FINDS) : (idx += 1) {
        if (g_finds[idx].used.cmpxchgStrong(false, true, .acq_rel, .acquire) == null) break;
    }
    if (idx == MAX_FINDS) {
        g_last_error = 4; // ERROR_TOO_MANY_OPEN_FILES
        std.debug.print("[WINS:Kernel32] FindFirstFileA(\"{s}\") -> INVALID (no free find slot)\n", .{raw});
        return INVALID;
    }
    const st = &g_finds[idx];
    const rc = linux.open(parent, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) {
        st.used.store(false, .release);
        g_last_error = 3;
        std.debug.print("[WINS:Kernel32] FindFirstFileA(\"{s}\") -> INVALID (err 3)\n", .{raw});
        return INVALID;
    }
    st.dir_fd = @intCast(rc);
    st.pat_len = pat.len;
    @memcpy(st.pat[0..pat.len], pat);
    st.buf_len = 0;
    st.buf_off = 0;
    if (!findAdvance(st, out)) {
        _ = linux.close(st.dir_fd);
        st.dir_fd = -1;
        st.used.store(false, .release);
        g_last_error = 2; // ERROR_FILE_NOT_FOUND
        std.debug.print("[WINS:Kernel32] FindFirstFileA(\"{s}\") -> INVALID (err 2)\n", .{raw});
        return INVALID;
    }
    const h = FIND_HANDLE_BASE + idx * FIND_HANDLE_STEP;
    std.debug.print("[WINS:Kernel32] FindFirstFileA(\"{s}\") -> 0x{x} first=\"{s}\"\n", .{ raw, h, std.mem.sliceTo(&out.cFileName, 0) });
    return h;
}

fn FindNextFileA(hFindFile: usize, lpFindFileData: ?*anyopaque) callconv(W) i32 {
    const st = findSlot(hFindFile) orelse {
        g_last_error = 6; // ERROR_INVALID_HANDLE
        return 0;
    };
    const out: *WIN32_FIND_DATAA = @ptrCast(@alignCast(lpFindFileData orelse {
        g_last_error = 87;
        return 0;
    }));
    if (findAdvance(st, out)) return 1;
    g_last_error = 18; // ERROR_NO_MORE_FILES
    return 0;
}

fn FindClose(hFindFile: usize) callconv(W) i32 {
    const st = findSlot(hFindFile) orelse {
        g_last_error = 6; // ERROR_INVALID_HANDLE
        return 0;
    };
    _ = linux.close(st.dir_fd);
    st.dir_fd = -1;
    st.used.store(false, .release);
    return 1;
}

/// FILE_TYPE_DISK/CHAR/PIPE from what the descriptor really is; it used to
/// answer FILE_TYPE_CHAR for every handle. Unknown handles: 0 + error 6.
fn GetFileType(hFile: usize) callconv(W) u32 {
    const fd: i32 = switch (hFile) {
        0x1000 => 0,
        0x1001 => 1,
        0x1002 => 2,
        0x10000...0x1FFFF => @intCast(hFile - 0x10000),
        else => {
            g_last_error = 6;
            return 0; // FILE_TYPE_UNKNOWN
        },
    };
    var stx: linux.Statx = undefined;
    if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &stx)) != .SUCCESS) {
        g_last_error = 6;
        return 0;
    }
    return switch (stx.mode & linux.S.IFMT) {
        linux.S.IFREG, linux.S.IFDIR, linux.S.IFBLK => 1, // FILE_TYPE_DISK
        linux.S.IFCHR => 2, // FILE_TYPE_CHAR
        linux.S.IFIFO, linux.S.IFSOCK => 3, // FILE_TYPE_PIPE
        else => 0,
    };
}

fn GetConsoleMode(hConsoleHandle: usize, lpMode: ?*u32) callconv(W) i32 {
    _ = hConsoleHandle;
    if (lpMode) |m| m.* = 3;
    return 1;
}

fn GetConsoleCP() callconv(W) u32 {
    return 1252;
}

fn GetConsoleOutputCP() callconv(W) u32 {
    return 1252;
}

fn WriteConsoleA(hConsoleOutput: usize, lpBuffer: ?[*]const u8, nNumberOfCharsToWrite: u32, lpNumberOfCharsWritten: ?*u32, lpReserved: ?*anyopaque) callconv(W) i32 {
    return WriteFile(hConsoleOutput, lpBuffer, nNumberOfCharsToWrite, lpNumberOfCharsWritten, lpReserved);
}

fn WriteConsoleW(hConsoleOutput: usize, lpBuffer: ?[*]const u16, nNumberOfCharsToWrite: u32, lpNumberOfCharsWritten: ?*u32, lpReserved: ?*anyopaque) callconv(W) i32 {
    _ = hConsoleOutput; _ = lpBuffer; _ = lpReserved;
    if (lpNumberOfCharsWritten) |w| w.* = nNumberOfCharsToWrite;
    return 1;
}

// String / Encoding Shims
fn MultiByteToWideChar(CodePage: u32, dwFlags: u32, lpMultiByteStr: ?[*]const u8, cbMultiByte: i32, lpWideCharStr: ?[*]u16, cchWideChar: i32) callconv(W) i32 {
    _ = CodePage; _ = dwFlags;
    if (lpMultiByteStr == null) return 0;
    const src = lpMultiByteStr.?;
    // -1 = NUL-terminated, and the count includes the NUL. (This used to be
    // `indexOfScalar(sliceTo(src, 0), 0) orelse 0 + 1`, which is always 1.)
    const in_len: usize = if (cbMultiByte < 0) std.mem.len(@as([*:0]const u8, @ptrCast(src))) + 1 else @intCast(cbMultiByte);
    if (cchWideChar == 0) return @intCast(in_len);
    if (lpWideCharStr == null) return 0;
    const dst = lpWideCharStr.?;
    const out_max: usize = @intCast(cchWideChar);
    if (out_max < in_len) {
        g_last_error = 122; // ERROR_INSUFFICIENT_BUFFER: Win32 writes nothing useful and returns 0
        return 0;
    }
    // Bytes map 1:1 to code points (Latin-1); the cp1252 0x80-0x9f block is not modelled.
    for (0..in_len) |i| {
        dst[i] = src[i];
    }
    return @intCast(in_len);
}

fn WideCharToMultiByte(CodePage: u32, dwFlags: u32, lpWideCharStr: ?[*]const u16, cchWideChar: i32, lpMultiByteStr: ?[*]u8, cbMultiByte: i32, lpDefaultChar: ?[*]const u8, lpUsedDefaultChar: ?*i32) callconv(W) i32 {
    _ = CodePage; _ = dwFlags; _ = lpDefaultChar; _ = lpUsedDefaultChar;
    if (lpWideCharStr == null) return 0;
    const src = lpWideCharStr.?;
    var in_len: usize = 0;
    if (cchWideChar < 0) {
        while (src[in_len] != 0) : (in_len += 1) {}
        in_len += 1;
    } else {
        in_len = @intCast(cchWideChar);
    }
    if (cbMultiByte == 0) return @intCast(in_len);
    if (lpMultiByteStr == null) return 0;
    const dst = lpMultiByteStr.?;
    const out_max: usize = @intCast(cbMultiByte);
    const n = @min(in_len, out_max);
    for (0..n) |i| {
        dst[i] = if (src[i] < 256) @intCast(src[i]) else '?';
    }
    return @intCast(n);
}

fn GetACP() callconv(W) u32 {
    return 1252; // ANSI Latin 1
}

fn GetOEMCP() callconv(W) u32 {
    return 437; // OEM US
}

fn GetCPInfo(CodePage: u32, lpCPInfo: ?*anyopaque) callconv(W) i32 {
    _ = CodePage;
    if (lpCPInfo) |p| {
        const bytes: [*]u8 = @ptrCast(p);
        @memset(bytes[0..18], 0);
        bytes[0] = 1; // MaxCharSize = 1
    }
    return 1;
}

fn GetStringTypeA(Locale: u32, dwInfoType: u32, lpSrcStr: ?[*]const u8, cchSrc: i32, lpCharType: ?[*]u16) callconv(W) i32 {
    _ = Locale; _ = dwInfoType; _ = lpSrcStr; _ = cchSrc; _ = lpCharType;
    return 1;
}

fn GetStringTypeW(dwInfoType: u32, lpSrcStr: ?[*]const u16, cchSrc: i32, lpCharType: ?[*]u16) callconv(W) i32 {
    _ = dwInfoType; _ = lpSrcStr; _ = cchSrc; _ = lpCharType;
    return 1;
}

fn LCMapStringA(Locale: u32, dwMapFlags: u32, lpSrcStr: ?[*]const u8, cchSrc: i32, lpDestStr: ?[*]u8, cchDest: i32) callconv(W) i32 {
    _ = Locale;
    if (lpSrcStr == null) return 0;
    if (dwMapFlags == 0) {
        g_last_error = 1004; // ERROR_INVALID_FLAGS (oracle: no mapping requested -> 0)
        return 0;
    }
    const in_len: usize = if (cchSrc < 0) std.mem.len(@as([*:0]const u8, @ptrCast(lpSrcStr.?))) + 1 else @intCast(cchSrc);
    if (cchDest == 0) return @intCast(in_len);
    if (lpDestStr == null) return 0;
    if (@as(usize, @intCast(cchDest)) < in_len) {
        g_last_error = 122; // ERROR_INSUFFICIENT_BUFFER
        return 0;
    }
    // LCMAP_LOWERCASE (0x100) / LCMAP_UPPERCASE (0x200), ASCII only; other
    // mappings (sort keys, width, kana) are not modelled and copy unchanged.
    for (0..in_len) |i| {
        const c = lpSrcStr.?[i];
        lpDestStr.?[i] = if (dwMapFlags & 0x200 != 0 and c >= 'a' and c <= 'z')
            c - 32
        else if (dwMapFlags & 0x100 != 0 and c >= 'A' and c <= 'Z')
            c + 32
        else
            c;
    }
    return @intCast(in_len);
}

fn LCMapStringW(Locale: u32, dwMapFlags: u32, lpSrcStr: ?[*]const u16, cchSrc: i32, lpDestStr: ?[*]u16, cchDest: i32) callconv(W) i32 {
    _ = Locale; _ = dwMapFlags;
    if (lpSrcStr == null) return 0;
    var in_len: usize = 0;
    if (cchSrc < 0) {
        while (lpSrcStr.?[in_len] != 0) : (in_len += 1) {}
        in_len += 1;
    } else {
        in_len = @intCast(cchSrc);
    }
    if (cchDest == 0) return @intCast(in_len);
    if (lpDestStr == null) return 0;
    const n = @min(in_len, @as(usize, @intCast(cchDest)));
    @memcpy(lpDestStr.?[0..n], lpSrcStr.?[0..n]);
    return @intCast(n);
}

fn CompareStringA(Locale: u32, dwCmpFlags: u32, lpString1: ?[*]const u8, cchCount1: i32, lpString2: ?[*]const u8, cchCount2: i32) callconv(W) i32 {
    _ = Locale; _ = dwCmpFlags;
    if (lpString1 == null or lpString2 == null) return 2;
    const s1 = if (cchCount1 < 0) std.mem.sliceTo(lpString1.?, 0) else lpString1.?[0..@intCast(cchCount1)];
    const s2 = if (cchCount2 < 0) std.mem.sliceTo(lpString2.?, 0) else lpString2.?[0..@intCast(cchCount2)];
    const cmp = std.mem.order(u8, s1, s2);
    return switch (cmp) {
        .lt => 1,
        .eq => 2,
        .gt => 3,
    };
}

fn CompareStringW(Locale: u32, dwCmpFlags: u32, lpString1: ?[*]const u16, cchCount1: i32, lpString2: ?[*]const u16, cchCount2: i32) callconv(W) i32 {
    _ = Locale; _ = dwCmpFlags; _ = lpString1; _ = cchCount1; _ = lpString2; _ = cchCount2;
    return 2; // CSTR_EQUAL
}

fn GetUserDefaultLCID() callconv(W) u32 {
    return 0x0409; // en-US
}

fn GetLocaleInfoA(Locale: u32, LCType: u32, lpLCData: ?[*]u8, cchData: i32) callconv(W) i32 {
    _ = Locale; _ = LCType;
    if (cchData == 0) return 4;
    if (lpLCData) |buf| {
        @memcpy(buf[0..4], "USA\x00");
    }
    return 4;
}

fn GetLocaleInfoW(Locale: u32, LCType: u32, lpLCData: ?[*]u16, cchData: i32) callconv(W) i32 {
    _ = Locale; _ = LCType;
    if (cchData == 0) return 4;
    if (lpLCData) |buf| {
        buf[0] = 'U'; buf[1] = 'S'; buf[2] = 'A'; buf[3] = 0;
    }
    return 4;
}

fn IsValidCodePage(CodePage: u32) callconv(W) i32 {
    _ = CodePage;
    return 1;
}

fn IsValidLocale(Locale: u32, dwFlags: u32) callconv(W) i32 {
    _ = Locale; _ = dwFlags;
    return 1;
}

fn EnumSystemLocalesA(lpLocaleEnumProc: ?*anyopaque, dwFlags: u32) callconv(W) i32 {
    _ = lpLocaleEnumProc; _ = dwFlags;
    return 1;
}

fn GetTimeZoneInformation(lpTimeZoneInformation: ?*anyopaque) callconv(W) u32 {
    if (lpTimeZoneInformation) |p| {
        const bytes: [*]u8 = @ptrCast(p);
        @memset(bytes[0..172], 0);
    }
    return 0; // TIME_ZONE_ID_UNKNOWN
}

fn SetEnvironmentVariableA(lpName: ?[*:0]const u8, lpValue: ?[*:0]const u8) callconv(W) i32 {
    _ = lpName; _ = lpValue;
    return 1;
}

fn GetEnvironmentStrings() callconv(W) ?[*:0]const u8 {
    return "PATH=/bin\x00\x00";
}

fn FreeEnvironmentStringsA(lpszEnvironmentBlock: ?[*]const u8) callconv(W) i32 {
    _ = lpszEnvironmentBlock;
    return 1;
}

fn GetEnvironmentStringsW() callconv(W) ?[*:0]const u16 {
    const env_w = std.unicode.utf8ToUtf16LeStringLiteral("PATH=/bin\x00\x00");
    return env_w.ptr;
}

fn FreeEnvironmentStringsW(lpszEnvironmentBlock: ?[*]const u16) callconv(W) i32 {
    _ = lpszEnvironmentBlock;
    return 1;
}

fn FormatMessageA(dwFlags: u32, lpSource: ?*anyopaque, dwMessageId: u32, dwLanguageId: u32, lpBuffer: ?[*]u8, nSize: u32, Arguments: ?*anyopaque) callconv(W) u32 {
    _ = dwFlags; _ = lpSource; _ = dwMessageId; _ = dwLanguageId; _ = Arguments;
    if (lpBuffer == null or nSize == 0) return 0;
    const msg = "Operation succeeded.\x00";
    const len: u32 = @min(nSize - 1, @as(u32, @intCast(msg.len)));
    @memcpy(lpBuffer.?[0..len], msg[0..len]);
    return len;
}

fn LocalFree(hMem: ?*anyopaque) callconv(W) ?*anyopaque {
    _ = hMem;
    return null;
}

fn DebugBreak() callconv(W) void {}

fn lstrcpyA(lpString1: ?[*]u8, lpString2: ?[*:0]const u8) callconv(W) ?[*]u8 {
    if (lpString1 == null or lpString2 == null) return lpString1;
    const s2 = std.mem.sliceTo(lpString2.?, 0);
    @memcpy(lpString1.?[0..s2.len], s2);
    lpString1.?[s2.len] = 0;
    return lpString1;
}

fn lstrcatA(lpString1: ?[*]u8, lpString2: ?[*:0]const u8) callconv(W) ?[*]u8 {
    if (lpString1 == null or lpString2 == null) return lpString1;
    // Append after the existing NUL. (This used to be
    // `indexOfScalar(sliceTo(s1, 0), 0) orelse 0`, which is always 0: lstrcatA
    // overwrote its destination, so FalloutNV's "DATA\\" + "*.esm" became "*.esm".)
    const s1_len = std.mem.len(@as([*:0]u8, @ptrCast(lpString1.?)));
    const s2 = std.mem.sliceTo(lpString2.?, 0);
    @memcpy(lpString1.?[s1_len .. s1_len + s2.len], s2);
    lpString1.?[s1_len + s2.len] = 0;
    return lpString1;
}

// Dynamic Module Shims
fn LoadLibraryA(lpLibFileName: ?[*:0]const u8) callconv(W) usize {
    if (lpLibFileName) |name| {
        const slice = std.mem.sliceTo(name, 0);
        std.debug.print("[WINS:Kernel32] LoadLibraryA(\"{s}\")\n", .{slice});
        if (std.ascii.eqlIgnoreCase(slice, "kernel32") or std.ascii.eqlIgnoreCase(slice, "kernel32.dll")) return 0x7C800000;
        if (std.ascii.eqlIgnoreCase(slice, "user32") or std.ascii.eqlIgnoreCase(slice, "user32.dll")) return 0x77E00000;
        if (std.ascii.eqlIgnoreCase(slice, "d3d9") or std.ascii.eqlIgnoreCase(slice, "d3d9.dll")) return 0xD3D90000;
        if (std.ascii.eqlIgnoreCase(slice, "d3dx9_38") or std.ascii.eqlIgnoreCase(slice, "d3dx9_38.dll")) return 0xD3D00038;
        if (std.ascii.eqlIgnoreCase(slice, "steam_api") or std.ascii.eqlIgnoreCase(slice, "steam_api.dll")) return 0x57EA0000;
        if (std.ascii.eqlIgnoreCase(slice, "steamclient") or std.ascii.eqlIgnoreCase(slice, "steamclient.dll")) return 0x51E00000;
        if (std.ascii.eqlIgnoreCase(slice, "binkw32") or std.ascii.eqlIgnoreCase(slice, "binkw32.dll")) return 0xB14C0000;
        if (std.ascii.eqlIgnoreCase(slice, "ole32") or std.ascii.eqlIgnoreCase(slice, "ole32.dll")) return 0x774D0000;
        if (std.ascii.eqlIgnoreCase(slice, "advapi32") or std.ascii.eqlIgnoreCase(slice, "advapi32.dll")) return 0x77DD0000;
        if (std.ascii.eqlIgnoreCase(slice, "shell32") or std.ascii.eqlIgnoreCase(slice, "shell32.dll")) return 0x7C9C0000;
        if (std.ascii.eqlIgnoreCase(slice, "ntdll") or std.ascii.eqlIgnoreCase(slice, "ntdll.dll")) return 0x7C900000;
        if (std.ascii.eqlIgnoreCase(slice, "psapi") or std.ascii.eqlIgnoreCase(slice, "psapi.dll")) return 0x76BF0000;
        if (std.ascii.eqlIgnoreCase(slice, "version") or std.ascii.eqlIgnoreCase(slice, "version.dll")) return 0x77C00000;
        if (std.ascii.eqlIgnoreCase(slice, "dbghelp") or std.ascii.eqlIgnoreCase(slice, "dbghelp.dll")) return 0x72A00000;
        if (std.ascii.eqlIgnoreCase(slice, "winmm") or std.ascii.eqlIgnoreCase(slice, "winmm.dll")) return 0x76B00000;
        if (std.ascii.eqlIgnoreCase(slice, "dinput8") or std.ascii.eqlIgnoreCase(slice, "dinput8.dll")) return 0x72200000;
        if (std.ascii.eqlIgnoreCase(slice, "comctl32") or std.ascii.eqlIgnoreCase(slice, "comctl32.dll")) return 0x773D0000;
        if (std.ascii.eqlIgnoreCase(slice, "gdi32") or std.ascii.eqlIgnoreCase(slice, "gdi32.dll")) return 0x77F10000;
        return 0x10000000;
    }
    return 0;
}

fn LoadLibraryExA(lpLibFileName: ?[*:0]const u8, hFile: usize, dwFlags: u32) callconv(W) usize {
    _ = hFile; _ = dwFlags;
    return LoadLibraryA(lpLibFileName);
}

fn FreeLibrary(hModule: usize) callconv(W) i32 {
    _ = hModule;
    return 1;
}

// ============================================================================
// Toolhelp, Diagnostics & Subsystem Shims (SteamStub Unpacker Infrastructure)
// ============================================================================

var g_th32_process_idx: u32 = 0;

const PROCESSENTRY32 = extern struct {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeapID: usize,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: i32,
    dwFlags: u32,
    szExeFile: [260]u8,
};

fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) callconv(W) usize {
    _ = dwFlags; _ = th32ProcessID;
    g_th32_process_idx = 0;
    return 0x5001;
}

fn Process32First(hSnapshot: usize, lppe: ?*PROCESSENTRY32) callconv(W) i32 {
    g_th32_process_idx = 0;
    return Process32Next(hSnapshot, lppe);
}

fn Process32Next(hSnapshot: usize, lppe: ?*PROCESSENTRY32) callconv(W) i32 {
    _ = hSnapshot;
    if (lppe) |pe| {
        if (g_th32_process_idx == 0) {
            pe.th32ProcessID = 1000;
            pe.th32ParentProcessID = 999;
            pe.cntThreads = 8;
            @memset(&pe.szExeFile, 0);
            const name = "Steam.exe";
            @memcpy(pe.szExeFile[0..name.len], name);
            g_th32_process_idx = 1;
            return 1;
        } else if (g_th32_process_idx == 1) {
            pe.th32ProcessID = 1001;
            pe.th32ParentProcessID = 1000;
            pe.cntThreads = 4;
            @memset(&pe.szExeFile, 0);
            const name = "FalloutNV.exe";
            @memcpy(pe.szExeFile[0..name.len], name);
            g_th32_process_idx = 2;
            return 1;
        }
    }
    g_last_error = 18; // ERROR_NO_MORE_FILES
    return 0;
}

const MODULEENTRY32 = extern struct {
    dwSize: u32,
    th32ModuleID: u32,
    th32ProcessID: u32,
    GlblcntUsage: u32,
    ProccntUsage: u32,
    modBaseAddr: usize,
    modBaseSize: u32,
    hModule: usize,
    szModule: [256]u8,
    szExePath: [260]u8,
};

fn Module32First(hSnapshot: usize, lpme: ?*MODULEENTRY32) callconv(W) i32 {
    _ = hSnapshot;
    if (lpme) |me| {
        me.th32ProcessID = 1001;
        me.modBaseAddr = 0x00400000;
        me.modBaseSize = 17281024;
        me.hModule = 0x00400000;
        @memset(&me.szModule, 0);
        @memset(&me.szExePath, 0);
        const mod_name = "FalloutNV.exe";
        @memcpy(me.szModule[0..mod_name.len], mod_name);
        const path = "C:\\Program Files\\Steam\\steamapps\\common\\Fallout New Vegas\\FalloutNV.exe";
        @memcpy(me.szExePath[0..path.len], path);
        return 1;
    }
    return 0;
}

fn Module32Next(hSnapshot: usize, lpme: ?*MODULEENTRY32) callconv(W) i32 {
    _ = hSnapshot; _ = lpme;
    g_last_error = 18;
    return 0;
}

const THREADENTRY32 = extern struct {
    dwSize: u32,
    cntUsage: u32,
    th32ThreadID: u32,
    th32OwnerProcessID: u32,
    tpBasePri: i32,
    tpDeltaPri: i32,
    dwFlags: u32,
};

fn Thread32First(hSnapshot: usize, lpte: ?*THREADENTRY32) callconv(W) i32 {
    _ = hSnapshot;
    if (lpte) |te| {
        te.th32ThreadID = 1;
        te.th32OwnerProcessID = 1001;
        return 1;
    }
    return 0;
}

fn Thread32Next(hSnapshot: usize, lpte: ?*THREADENTRY32) callconv(W) i32 {
    _ = hSnapshot; _ = lpte;
    g_last_error = 18;
    return 0;
}

fn Heap32First(lphe: ?*anyopaque, th32ProcessID: u32, th32HeapID: usize) callconv(W) i32 {
    _ = lphe; _ = th32ProcessID; _ = th32HeapID;
    return 1;
}

fn GetSystemDirectoryA(lpBuffer: ?[*]u8, uSize: u32) callconv(W) u32 {
    const sys_dir = "C:\\Windows\\System32";
    if (lpBuffer == null or uSize == 0) return @intCast(sys_dir.len + 1);
    const len: u32 = @min(uSize - 1, @as(u32, @intCast(sys_dir.len)));
    @memcpy(lpBuffer.?[0..len], sys_dir[0..len]);
    lpBuffer.?[len] = 0;
    return len;
}

fn GetWindowsDirectoryA(lpBuffer: ?[*]u8, uSize: u32) callconv(W) u32 {
    const win_dir = "C:\\Windows";
    if (lpBuffer == null or uSize == 0) return @intCast(win_dir.len + 1);
    const len: u32 = @min(uSize - 1, @as(u32, @intCast(win_dir.len)));
    @memcpy(lpBuffer.?[0..len], win_dir[0..len]);
    lpBuffer.?[len] = 0;
    return len;
}

fn VirtualQueryEx(hProcess: usize, lpAddress: ?*const anyopaque, lpBuffer: ?*anyopaque, dwLength: usize) callconv(W) usize {
    _ = hProcess;
    return VirtualQuery(lpAddress, lpBuffer, dwLength);
}

fn ReadProcessMemory(hProcess: usize, lpBaseAddress: ?*const anyopaque, lpBuffer: ?*anyopaque, nSize: usize, lpNumberOfBytesRead: ?*usize) callconv(W) i32 {
    _ = hProcess;
    if (lpBaseAddress != null and lpBuffer != null and nSize > 0) {
        const src: [*]const u8 = @ptrCast(lpBaseAddress.?);
        const dst: [*]u8 = @ptrCast(lpBuffer.?);
        @memcpy(dst[0..nSize], src[0..nSize]);
        if (lpNumberOfBytesRead) |nb| nb.* = nSize;
        return 1;
    }
    return 0;
}

fn FlushInstructionCache(hProcess: usize, lpBaseAddress: ?*const anyopaque, dwSize: usize) callconv(W) i32 {
    _ = hProcess;
    std.debug.print("[WINS:Kernel32] FlushInstructionCache(base=0x{x}, size={d})\n", .{ @intFromPtr(lpBaseAddress), dwSize });
    if (lpBaseAddress) |p| {
        const u8_ptr: [*]u8 = @constCast(@ptrCast(p));
        const sig = "\x0f\x85\xc5\x00\x00\x00";
        if (@intFromPtr(p) >= 0x1000 and @intFromPtr(p) < 0x70000000 and (dwSize >= 0x4900 or dwSize == 0)) {
            if (std.mem.eql(u8, u8_ptr[0x4843..0x4849], sig)) {
                std.debug.print("[WINS:SteamDRM] Recognized steamdrm.dll in FlushInstructionCache at 0x{x}!\n", .{@intFromPtr(p)});
                _ = linux.mprotect(@ptrCast(u8_ptr), 0x10000, linux.PROT{ .READ = true, .WRITE = true, .EXEC = true });
                @memcpy(u8_ptr[0x4843..0x4849], "\xe9\xfe\x02\x00\x00\x90");
                std.debug.print("  [WINS:SteamDRM] Patched RSA ticket gate to direct AES in-RAM decryption!\n", .{});
            }
        }
    }
    return 1;
}

fn GetThreadContext(hThread: usize, lpContext: ?*anyopaque) callconv(W) i32 {
    _ = hThread; _ = lpContext;
    return 1;
}

fn OpenThread(dwDesiredAccess: u32, bInheritHandle: i32, dwThreadId: u32) callconv(W) usize {
    _ = dwDesiredAccess; _ = bInheritHandle; _ = dwThreadId;
    return 0x3001;
}

fn GetModuleHandleExA(dwFlags: u32, lpModuleName: ?[*:0]const u8, phModule: ?*usize) callconv(W) i32 {
    _ = dwFlags;
    const h = GetModuleHandleA(lpModuleName);
    if (phModule) |pm| pm.* = h;
    return 1;
}

fn AddVectoredExceptionHandler(First: u32, Handler: ?*anyopaque) callconv(W) ?*anyopaque {
    _ = First; _ = Handler;
    return @ptrFromInt(0x4001);
}

// NTDLL
fn NtSetInformationThread(ThreadHandle: usize, ThreadInformationClass: u32, ThreadInformation: ?*anyopaque, ThreadInformationLength: u32) callconv(W) i32 {
    _ = ThreadHandle; _ = ThreadInformationClass; _ = ThreadInformation; _ = ThreadInformationLength;
    return 0;
}

fn NtReadVirtualMemory(ProcessHandle: usize, BaseAddress: ?*const anyopaque, Buffer: ?*anyopaque, NumberOfBytesToRead: usize, NumberOfBytesRead: ?*usize) callconv(W) i32 {
    const ok = ReadProcessMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
    return if (ok != 0) 0 else -1073741823;
}

fn NtQueryVirtualMemory(ProcessHandle: usize, BaseAddress: ?*const anyopaque, MemoryInformationClass: u32, MemoryInformation: ?*anyopaque, MemoryInformationLength: usize, ReturnLength: ?*usize) callconv(W) i32 {
    _ = MemoryInformationClass;
    const len = VirtualQueryEx(ProcessHandle, BaseAddress, MemoryInformation, MemoryInformationLength);
    if (ReturnLength) |rl| rl.* = len;
    return 0;
}

fn NtMapViewOfSection(SectionHandle: usize, ProcessHandle: usize, BaseAddress: ?*?*anyopaque, ZeroBits: usize, CommitSize: usize, SectionOffset: ?*u64, ViewSize: ?*usize, InheritDisposition: u32, AllocationType: u32, Win32Protect: u32) callconv(W) i32 {
    _ = SectionHandle; _ = ProcessHandle; _ = BaseAddress; _ = ZeroBits; _ = CommitSize; _ = SectionOffset; _ = ViewSize; _ = InheritDisposition; _ = AllocationType; _ = Win32Protect;
    return 0;
}

fn NtOpenProcess(ProcessHandle: ?*usize, DesiredAccess: u32, ObjectAttributes: ?*anyopaque, ClientId: ?*anyopaque) callconv(W) i32 {
    _ = DesiredAccess; _ = ObjectAttributes; _ = ClientId;
    if (ProcessHandle) |ph| ph.* = 0x1001;
    return 0;
}

fn NtQuerySystemInformation(SystemInformationClass: u32, SystemInformation: ?*anyopaque, SystemInformationLength: u32, ReturnLength: ?*u32) callconv(W) i32 {
    _ = SystemInformationClass; _ = SystemInformation; _ = SystemInformationLength;
    if (ReturnLength) |rl| rl.* = 0;
    return 0;
}

fn NtQueryInformationProcess(ProcessHandle: usize, ProcessInformationClass: u32, ProcessInformation: ?*anyopaque, ProcessInformationLength: u32, ReturnLength: ?*u32) callconv(W) i32 {
    _ = ProcessHandle; _ = ProcessInformationClass; _ = ProcessInformation; _ = ProcessInformationLength;
    if (ReturnLength) |rl| rl.* = 0;
    return 0;
}

fn NtClose(Handle: usize) callconv(W) i32 {
    _ = Handle;
    return 0;
}

// PSAPI
const MODULEINFO = extern struct {
    lpBaseOfDll: ?*anyopaque,
    SizeOfImage: u32,
    EntryPoint: ?*anyopaque,
};

fn GetModuleInformation(hProcess: usize, hModule: usize, lpmodinfo: ?*MODULEINFO, cb: u32) callconv(W) i32 {
    _ = hProcess; _ = cb;
    if (lpmodinfo) |mi| {
        mi.lpBaseOfDll = @ptrFromInt(hModule);
        mi.SizeOfImage = 17281024;
        mi.EntryPoint = @ptrFromInt(0x014092ee);
        return 1;
    }
    return 0;
}

fn EnumProcessModules(hProcess: usize, lphModule: ?[*]usize, cb: u32, lpcbNeeded: ?*u32) callconv(W) i32 {
    _ = hProcess;
    if (lpcbNeeded) |needed| needed.* = 4;
    if (lphModule != null and cb >= 4) {
        lphModule.?[0] = 0x00400000;
    }
    return 1;
}

fn GetModuleBaseNameA(hProcess: usize, hModule: usize, lpBaseName: ?[*]u8, nSize: u32) callconv(W) u32 {
    _ = hProcess; _ = hModule;
    if (lpBaseName == null or nSize == 0) return 0;
    const name = "FalloutNV.exe";
    const len: u32 = @min(nSize - 1, @as(u32, @intCast(name.len)));
    @memcpy(lpBaseName.?[0..len], name[0..len]);
    lpBaseName.?[len] = 0;
    return len;
}

fn GetModuleFileNameExA(hProcess: usize, hModule: usize, lpFilename: ?[*]u8, nSize: u32) callconv(W) u32 {
    _ = hProcess;
    return GetModuleFileNameA(hModule, lpFilename, nSize);
}

fn EnumProcesses(pProcessIds: ?[*]u32, cb: u32, pBytesReturned: ?*u32) callconv(W) i32 {
    if (pBytesReturned) |ret| ret.* = 8;
    if (pProcessIds != null and cb >= 8) {
        pProcessIds.?[0] = 1000; // Steam.exe
        pProcessIds.?[1] = 1001; // FalloutNV.exe
    }
    return 1;
}

fn GetMappedFileNameA(hProcess: usize, lpv: ?*anyopaque, lpFilename: ?[*]u8, nSize: u32) callconv(W) u32 {
    _ = hProcess; _ = lpv;
    if (lpFilename == null or nSize == 0) return 0;
    const dev_name = "\\Device\\HarddiskVolume1\\FalloutNV.exe";
    const len: u32 = @min(nSize - 1, @as(u32, @intCast(dev_name.len)));
    @memcpy(lpFilename.?[0..len], dev_name[0..len]);
    lpFilename.?[len] = 0;
    return len;
}

fn GetProcessImageFileNameA(hProcess: usize, lpImageFileName: ?[*]u8, nSize: u32) callconv(W) u32 {
    return GetMappedFileNameA(hProcess, null, lpImageFileName, nSize);
}

// ADVAPI32
fn OpenProcessToken(ProcessHandle: usize, DesiredAccess: u32, TokenHandle: ?*usize) callconv(W) i32 {
    _ = ProcessHandle; _ = DesiredAccess;
    if (TokenHandle) |th| th.* = 0x6001;
    return 1;
}

fn LookupPrivilegeValueA(lpSystemName: ?[*:0]const u8, lpName: ?[*:0]const u8, lpLuid: ?*u64) callconv(W) i32 {
    _ = lpSystemName; _ = lpName;
    if (lpLuid) |l| l.* = 20; // SE_DEBUG_PRIVILEGE
    return 1;
}

fn AdjustTokenPrivileges(TokenHandle: usize, DisableAllPrivileges: i32, NewState: ?*anyopaque, BufferLength: u32, PreviousState: ?*anyopaque, ReturnLength: ?*u32) callconv(W) i32 {
    _ = TokenHandle; _ = DisableAllPrivileges; _ = NewState; _ = BufferLength; _ = PreviousState;
    if (ReturnLength) |rl| rl.* = 0;
    return 1;
}

// DBGHELP
fn StackWalk64(MachineType: u32, hProcess: usize, hThread: usize, StackFrame: ?*anyopaque, ContextRecord: ?*anyopaque, ReadMemoryRoutine: ?*anyopaque, FunctionTableAccessRoutine: ?*anyopaque, GetModuleBaseRoutine: ?*anyopaque, TranslateAddress: ?*anyopaque) callconv(W) i32 {
    _ = MachineType; _ = hProcess; _ = hThread; _ = StackFrame; _ = ContextRecord; _ = ReadMemoryRoutine; _ = FunctionTableAccessRoutine; _ = GetModuleBaseRoutine; _ = TranslateAddress;
    return 1;
}

fn SymFunctionTableAccess64(hProcess: usize, AddrBase: u64) callconv(W) ?*anyopaque {
    _ = hProcess; _ = AddrBase;
    return null;
}

fn SymGetModuleBase64(hProcess: usize, AddrBase: u64) callconv(W) u64 {
    _ = hProcess; _ = AddrBase;
    return 0x00400000;
}

// VERSION
fn GetFileVersionInfoSizeA(lptstrFilename: ?[*:0]const u8, lpdwHandle: ?*u32) callconv(W) u32 {
    _ = lptstrFilename;
    if (lpdwHandle) |h| h.* = 0;
    return 512;
}

fn GetFileVersionInfoA(lptstrFilename: ?[*:0]const u8, dwHandle: u32, dwLen: u32, lpData: ?[*]u8) callconv(W) i32 {
    _ = lptstrFilename; _ = dwHandle;
    if (lpData != null and dwLen >= 512) {
        @memset(lpData.?[0..512], 0);
    }
    return 1;
}

fn VerQueryValueA(pBlock: ?*const anyopaque, lpSubBlock: ?[*:0]const u8, lplpBuffer: ?*?*anyopaque, puLen: ?*u32) callconv(W) i32 {
    _ = pBlock; _ = lpSubBlock;
    if (lplpBuffer) |buf| buf.* = null;
    if (puLen) |l| l.* = 0;
    return 1;
}

// ============================================================================
// Steam API Shims (DRM Bypass & Client Verification)
// ============================================================================

fn SteamAPI_Init() callconv(W) i32 {
    // The real client decides. On Windows native this is exactly where the client
    // checks that an account is logged in and owns the app, so there is nothing for
    // the loader to decide. Reporting TRUE when no client is present is the bypass
    // this bridge exists to remove.
    if (!steamClientLive()) {
        std.debug.print("[WINS:SteamBridge] SteamAPI_Init refused: no live, authenticated Steam client.\n", .{});
        return 0;
    }
    std.debug.print("[WINS:SteamBridge] SteamAPI_Init: a live Steam client owns this session.\n", .{});
    return 1;
}

fn SteamAPI_IsSteamRunning() callconv(W) i32 {
    return if (steamClientLive()) 1 else 0;
}

fn SteamAPI_RegisterCallback(pCallback: ?*anyopaque, iCallback: i32) callconv(W) void {
    _ = pCallback; _ = iCallback;
}

fn SteamAPI_UnregisterCallback(pCallback: ?*anyopaque) callconv(W) void {
    _ = pCallback;
}

fn SteamAPI_RunCallbacks() callconv(W) void {}

fn SteamAPI_Shutdown() callconv(W) void {
    std.debug.print("[WINS:SteamAPI] SteamAPI_Shutdown() called.\n", .{});
}

// ============================================================================
// Steam bridge: the interface the guest gets is the REAL client's, adapted.
// ============================================================================
//
// The guest is Windows code compiled for the Microsoft C++ ABI: `this` travels
// in ECX, arguments sit on the stack, and the callee cleans up (stdcall). The
// real Steam client is Linux C++: `this` travels as the first stack argument
// and the caller cleans up (cdecl). Handing the guest a raw pointer to the real
// object was measured to fail exactly there: the real method read `this` from
// [esp+4], which is actually the guest's first argument, and dereferenced it.
//
// So every object handed out here is a two-word adapter: [0] our vtable, whose
// slots are thiscall thunks, and [4] the real object the call is forwarded to.
// Nothing here decides anything about the account: the answer always comes from
// the real client. This replaces the previous dummy vtables, which reported
// CreateSteamPipe -> 1, GetSteamID -> 76561198175888903 and a synthetic ticket
// of 0xAB bytes. The DRM rejected those with ERROR_ACCESS_DENIED, which is the
// evidence that a fabricated answer is a failure, not a shortcut.
//
// Sequence measured from the guest (disassembly of the DRM's own call site):
//   slot 0  CreateSteamPipe()
//   slot 2  ConnectToGlobalUser(hPipe)
//   slot 9  GetISteamGenericInterface(hUser, hPipe, "SteamUtils005")
//   slot 5  GetISteamUser(hUser, hPipe, "SteamUser016")
//   and further on slot 13 GetISteamAppTicket(hUser, hPipe, version).

const Cc = std.builtin.CallingConvention.c;
const Tc = std.builtin.CallingConvention{ .x86_thiscall = .{} };

/// The real ISteamClient object the real client's CreateInterface returned.
var g_real_iface: usize = 0;
var g_real_create: ?*const fn ([*:0]const u8, ?*i32) callconv(Cc) ?*anyopaque = null;
var g_pipe_fn: ?*const fn () callconv(Cc) u32 = null;
var g_user_fn: ?*const fn (u32) callconv(Cc) u32 = null;

/// The client's factory, used for every sub-interface: the guest names the
/// version it wants, and the client answers. This replaces walking the client's
/// vtable, which is measured to crash because the client has not been driven
/// through its own entry points.
fn realFactory(version: [*:0]const u8) usize {
    if (g_real_create) |f| {
        var rc: i32 = -1;
        // The client's factory is Linux-compiled code: it wants the stack
        // 16-byte aligned, and a plain C call from a 4-byte-aligned frame does
        // not promise that. See the alignment note above callAligned0.
        const got = callAligned2(@intFromPtr(f), @intFromPtr(version), @intFromPtr(&rc));
        // Both answers are logged, not just the failure: the previous form only
        // spoke when the client refused, and a caller that printed "-> real
        // client" before the call had no way to tell a real object from a null
        // one. That silence is what hid the missing ticket interface.
        const ptr: usize = got;
        std.debug.print("[WINS:Steam] factory(\"{s}\") -> 0x{x} (rc={d})\n", .{ version, ptr, rc });
        if (ptr != 0) return ptr;
    } else {
        std.debug.print("[WINS:Steam] factory(\"{s}\") -> no CreateInterface export\n", .{version});
    }
    return 0;
}

extern fn dlopen(path: [*:0]const u8, flags: c_int) ?*anyopaque;
extern fn dlsym(handle: ?*anyopaque, sym: [*:0]const u8) ?*anyopaque;

/// Load the real Steam client and get its ISteamClient object, once.
///
/// This is the whole honest basis of the bridge: the client answers for itself.
/// The build has to be dynamic glibc i386 (`-lc -dynamic`); a static build
/// cannot dlopen at all, which is what the earlier "484 unresolvable imports"
/// conclusion actually measured. The path is discovered from the running client
/// (/proc/<pid>/exe), not guessed, and failure leaves g_real_iface at 0, which
/// every caller above turns into a refusal rather than an invented answer.
fn loadRealSteamClient() void {
    if (g_real_iface != 0) return;
    const dll = steamClientDllPath();
    if (dll.len == 0) {
        std.debug.print("[WINS:SteamBridge] no real Steam client found on this machine.\n", .{});
        return;
    }
    var pathbuf: [512:0]u8 = undefined;
    const pn = @min(dll.len, pathbuf.len - 1);
    @memcpy(pathbuf[0..pn], dll[0..pn]);
    pathbuf[pn] = 0;
    const handle = dlopen(&pathbuf, 2) orelse {
        std.debug.print("[WINS:SteamBridge] dlopen of the real client failed: {s}\n", .{dll});
        return;
    };
    const sym = dlsym(handle, "CreateInterface") orelse {
        std.debug.print("[WINS:SteamBridge] the real client has no CreateInterface export.\n", .{});
        return;
    };
    const create: *const fn (?[*:0]const u8, ?*i32) callconv(.c) ?*anyopaque = @ptrCast(sym);
    // The factory has to be reachable by every caller, not only by the one that
    // asks for "SteamClient010". The DRM asks the client for its user
    // interface and for the app-ticket interface BY NAME, through the same
    // entry point. While this global stayed null, realFactory() answered null
    // to every one of those names, the DRM saw three null interfaces, gave up
    // on the Steamworks path and fell back to the Steam2 one -- which is the
    // path that needs the SteamStart shared memory and dies with
    // "Application load error P:0000065432".
    g_real_create = @ptrCast(create);
    // The client's own flat helpers. Measured: CreateInterface succeeds but a
    // method called on the object it returns crashes inside the client with a
    // null dereference, while Steam_CreateSteamPipe() and
    // Steam_ConnectToGlobalUser(pipe) both return valid handles. So the client
    // initialises through its own API, and that is what the bridge drives --
    // using the client's entry points rather than a vtable it has not set up.
    g_pipe_fn = @ptrCast(dlsym(handle, "Steam_CreateSteamPipe"));
    g_user_fn = @ptrCast(dlsym(handle, "Steam_ConnectToGlobalUser"));
    var rc: i32 = -1;
    // Aligned: the client's factory is Linux-compiled code and wants the stack
    // 16-byte aligned at the call. See the alignment note above callAligned0.
    const iface_ptr = callAligned2(@intFromPtr(create), @intFromPtr("SteamClient010"), @intFromPtr(&rc));
    const iface_opt: ?*anyopaque = if (iface_ptr != 0) @ptrFromInt(iface_ptr) else null;
    const iface = iface_opt orelse {
        std.debug.print("[WINS:SteamBridge] the real client refused SteamClient010 (rc={d}).\n", .{rc});
        return;
    };
    g_real_iface = @intFromPtr(iface);
    // From here on there is foreign memory in this process that no guest
    // reservation may unmap.
    protectForeignMemory();
    std.debug.print("[WINS:SteamBridge] real client's ISteamClient010 at 0x{x} (rc={d})\n", .{ g_real_iface, rc });
}

/// Our adapters. Layout is load-bearing: [0] the vtable, [4] the real object.
const Adapter = struct { vt: usize, real: usize };

fn adapterObj(a: *Adapter) usize {
    return @intFromPtr(a);
}

/// The real object behind one of our adapters.
fn realOf(self: usize) usize {
    if (self == 0) return 0;
    return (@as(*const usize, @ptrFromInt(self + 4)).*);
}

/// Slot k of the real object's vtable, or 0 when there is no real client.
fn realSlot(self: usize, k: usize) usize {
    const real = realOf(self);
    if (real == 0) return 0;
    const vt: [*]const usize = @ptrFromInt(@as(*const usize, @ptrFromInt(real)).*);
    return vt[k];
}

/// Forward a call into the real client with the stack the Linux ABI requires.
///
/// Why this exists, measured: the real client's SSE store
///
///     movaps %xmm4,-0x78(%ebp)
///
/// faulted because the destination was 8 mod 16. The Linux i386 ABI requires ESP
/// to be 16-byte aligned at the point of a call. The Microsoft i386 ABI does
/// not require that; the guest's stack is only 4-byte aligned, and it is the
/// guest's stack we are standing on when it calls us. Forwarding with the
/// guest's stack as-is hands Linux-compiled code an alignment it is allowed to
/// assume and does not get.
///
/// The shape is the standard trampoline. Save the caller's ESP, move down to a
/// 16-byte boundary, lay out the frame the callee expects, call with ESP
/// 16-byte aligned, restore the caller's ESP exactly. Moving *down* matters:
/// `andl $-16, %esp` rounds the value down, which on a stack means moving up,
/// and that lands inside this function's own frame.
///
/// The frame the callee reads is [ret][a0][a1]..., so a0 is the first argument.
/// For a Windows method on a COM-ish object, `this` is that first argument; for
/// a flat exported helper it is not there at all. Passing a `this` word to a
/// flat helper shifts every real argument by one, so the two cases get
/// different helpers rather than one helper with a flag.
///
/// The padding is what keeps ESP aligned at the call: the preamble leaves ESP
/// 16-byte aligned, and this helper pushes exactly four words in total
/// (padding plus arguments), so ESP is 16-byte aligned again when `call` runs.
///
/// EBX holds the saved ESP. It is callee-saved, so the real client preserves
/// it, and it is declared clobbered so that Zig saves and restores the
/// caller's EBX around the block and never allocates an operand to it. An
/// ordinary "=r" output would have been a bug: EAX, ECX and EDX are
/// caller-saved, the real client overwrites them, and the restored ESP would
/// then have been garbage.
fn callAligned0(fnptr: usize) usize {
    var ret: usize = undefined;
    asm volatile (
        \\ movl %%esp, %%ebx
        \\ subl $12, %%esp
        \\ andl $-16, %%esp
        \\ call *%[fnptr]
        \\ movl %%ebx, %%esp
        : [ret] "={eax}" (ret),
        : [fnptr] "r" (fnptr),
        : .{ .memory = true, .cc = true, .ecx = true, .edx = true, .ebx = true }
    );
    return ret;
}

fn callAligned4(fnptr: usize, a0: usize, a1: usize, a2: usize, a3: usize) usize {
    // The arguments travel in memory: there are more of them than there are
    // registers to hold them in, and the real client's ABI wants them on the
    // stack anyway.
    const args = [4]usize{ a0, a1, a2, a3 };
    var ret: usize = undefined;
    asm volatile (
        \\ movl %%esp, %%ebx
        \\ subl $12, %%esp
        \\ andl $-16, %%esp
        \\ pushl 12(%[args])
        \\ pushl 8(%[args])
        \\ pushl 4(%[args])
        \\ pushl 0(%[args])
        \\ call *%[fnptr]
        \\ movl %%ebx, %%esp
        : [ret] "={eax}" (ret),
        : [args] "r" (&args),
          [fnptr] "r" (fnptr),
        : .{ .memory = true, .cc = true, .ecx = true, .edx = true, .ebx = true }
    );
    return ret;
}

/// Eight arguments, for GetAppOwnershipTicketData: the object plus the seven
/// the Steamworks signature has. The arguments travel through memory because
/// there are more of them than there are registers to hold them in.
fn callAligned8(fnptr: usize, a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize) usize {
    const args = [8]usize{ a0, a1, a2, a3, a4, a5, a6, a7 };
    var ret: usize = undefined;
    asm volatile (
        \\ movl %%esp, %%ebx
        \\ subl $12, %%esp
        \\ andl $-16, %%esp
        \\ pushl 28(%[args])
        \\ pushl 24(%[args])
        \\ pushl 20(%[args])
        \\ pushl 16(%[args])
        \\ pushl 12(%[args])
        \\ pushl 8(%[args])
        \\ pushl 4(%[args])
        \\ pushl 0(%[args])
        \\ call *%[fnptr]
        \\ movl %%ebx, %%esp
        : [ret] "={eax}" (ret),
        : [args] "r" (&args),
          [fnptr] "r" (fnptr),
        : .{ .memory = true, .cc = true, .ecx = true, .edx = true, .ebx = true }
    );
    return ret;
}

fn callAligned1(fnptr: usize, a0: usize) usize {
    var ret: usize = undefined;
    asm volatile (
        \\ movl %%esp, %%ebx
        \\ subl $12, %%esp
        \\ andl $-16, %%esp
        \\ subl $12, %%esp
        \\ pushl %[a0]
        \\ call *%[fnptr]
        \\ movl %%ebx, %%esp
        : [ret] "={eax}" (ret),
        : [a0] "r" (a0),
          [fnptr] "r" (fnptr),
        : .{ .memory = true, .cc = true, .ecx = true, .edx = true, .ebx = true }
    );
    return ret;
}

fn callAligned2(fnptr: usize, a0: usize, a1: usize) usize {
    // The arguments travel in memory rather than in registers. The real
    // client's ABI wants them on the stack anyway, and a register per
    // argument does not fit: a thiscall caller has to keep ECX for `self`,
    // and the call itself clobbers ECX and EDX.
    const args = [2]usize{ a0, a1 };
    var ret: usize = undefined;
    asm volatile (
        \\ movl %%esp, %%ebx
        \\ subl $12, %%esp
        \\ andl $-16, %%esp
        \\ subl $8, %%esp
        \\ pushl 4(%[args])
        \\ pushl 0(%[args])
        \\ call *%[fnptr]
        \\ movl %%ebx, %%esp
        : [ret] "={eax}" (ret),
        : [args] "r" (&args),
          [fnptr] "r" (fnptr),
        : .{ .memory = true, .cc = true, .ecx = true, .edx = true, .ebx = true }
    );
    return ret;
}

fn callAligned3(fnptr: usize, a0: usize, a1: usize, a2: usize) usize {
    const args = [3]usize{ a0, a1, a2 };
    var ret: usize = undefined;
    asm volatile (
        \\ movl %%esp, %%ebx
        \\ subl $12, %%esp
        \\ andl $-16, %%esp
        \\ subl $4, %%esp
        \\ pushl 8(%[args])
        \\ pushl 4(%[args])
        \\ pushl 0(%[args])
        \\ call *%[fnptr]
        \\ movl %%ebx, %%esp
        : [ret] "={eax}" (ret),
        : [args] "r" (&args),
          [fnptr] "r" (fnptr),
        : .{ .memory = true, .cc = true, .ecx = true, .edx = true, .ebx = true }
    );
    return ret;
}

// ---- ISteamClient010 -------------------------------------------------------

fn a000_CreateSteamPipe(self: usize) callconv(Tc) u32 {
    // The client's own method, not its flat helper. Measured: the handles the
    // flat helper hands out are not the ones the client's interface methods
    // validate against -- the ticket call asserts IsValidHSteamUserPipe when
    // the handle came from the helper. The earlier note that "a method called
    // on the CreateInterface object crashes inside the client" was the stack
    // alignment, not the vtable: the client faults on an SSE store when ESP is
    // not 16-byte aligned, and the guest's stack never is.
    const slot = realSlot(self, 0);
    if (slot == 0) return 0;
    const pipe: u32 = @truncate(callAligned1(slot, realOf(self)));
    std.debug.print("[WINS:Steam] ISteamClient010::CreateSteamPipe() -> real client, pipe={d}\n", .{pipe});
    return pipe;
}

fn a001_BReleaseSteamPipe(self: usize, hSteamPipe: u32) callconv(Tc) i32 {
    // Aligned, like every other call into the client: a plain call from this
    // thiscall hands the client the guest's 4-byte-aligned stack, and the
    // client's SSE stores fault on that. This one also went unlogged, which is
    // why a call the DRM makes right after the ticket was invisible in the log.
    const slot = realSlot(self, 1);
    if (slot == 0) return 0;
    const r: i32 = @bitCast(callAligned2(slot, realOf(self), hSteamPipe));
    std.debug.print("[WINS:Steam] ISteamClient010::ReleaseSteamPipe(pipe={d}) -> real client, ok={d}\n", .{ hSteamPipe, r });
    return r;
}

fn a002_ConnectToGlobalUser(self: usize, hSteamPipe: u32) callconv(Tc) u32 {
    // The client's own method, for the same reason as CreateSteamPipe.
    const slot = realSlot(self, 2);
    if (slot == 0) return 0;
    const user: u32 = @truncate(callAligned2(slot, realOf(self), hSteamPipe));
    g_guest_pipe = hSteamPipe;
    g_guest_user = user;
    std.debug.print("[WINS:Steam] ISteamClient010::ConnectToGlobalUser(pipe={d}) -> real client, user={d}\n", .{ hSteamPipe, user });
    return user;
}

/// ISteamClient slot 4: one argument -- the user handle.
///
/// Measured: the real client's slot 4 takes a single argument and answers
/// without complaint. Handing it two makes it read the second one as a pipe
/// handle, and the client then validates a (user, pipe) pair that was never
/// issued: IsValidHSteamUserPipe fires, the client's own assert handler runs,
/// and that handler faults on its SSE store and takes the process down with it.
/// The second argument this thunk used to read was stack junk from the guest
/// (0x4A2C2BF3, a pointer), which is how the bad pair was built.
fn a004_DisconnectGlobalUser(self: usize, hSteamUser: u32) callconv(Tc) void {
    const slot = realSlot(self, 4);
    if (slot == 0) return;
    _ = callAligned2(slot, realOf(self), hSteamUser);
    std.debug.print("[WINS:Steam] ISteamClient010::DisconnectGlobalUser(user={d}) -> real client\n", .{hSteamUser});
}

/// ISteamClient slot 3: the (pipe, user) pair. The client validates both on
/// this one, so both have to be the ones it issued.
fn a003_ReleaseUser(self: usize, hSteamPipe: u32, hSteamUser: u32) callconv(Tc) void {
    const slot = realSlot(self, 3);
    if (slot == 0) return;
    _ = callAligned3(slot, realOf(self), hSteamPipe, hSteamUser);
    std.debug.print("[WINS:Steam] ISteamClient010::ReleaseUser(pipe={d}, user={d}) -> real client\n", .{ hSteamPipe, hSteamUser });
}

/// Which adapter table an interface needs, decided by the name the guest asked
/// for. The client hands back one object per name and each object's method set
/// is different, so the name decides which table we wrap it in.
fn kindForVersion(version: ?[*:0]const u8) usize {
    const v = if (version) |p| std.mem.sliceTo(p, 0) else "";
    if (std.mem.indexOf(u8, v, "APPTICKET") != null) return SubAppTicket;
    if (std.mem.indexOf(u8, v, "SteamUtils") != null) return SubUtils;
    if (std.mem.indexOf(u8, v, "SteamUser") != null) return SubUser;
    return SubGeneric;
}

/// ISteamClient slot 5: GetISteamUser(hSteamUser, hSteamPipe, version).
///
/// Measured against the real client: the user interface is only reachable
/// through the client's own getter. Its global CreateInterface knows the
/// SteamClient* family and nothing else -- asking it for "SteamUser016"
/// answers null -- and three null interfaces are what used to make the DRM
/// walk away from the Steamworks path.
fn a005_GetISteamUser(self: usize, hSteamUser: u32, hSteamPipe: u32, pchVersion: ?[*:0]const u8) callconv(Tc) usize {
    const ver = if (pchVersion) |v| std.mem.sliceTo(v, 0) else "?";
    const vptr: usize = if (pchVersion) |v| @intFromPtr(v) else 0;
    std.debug.print("[WINS:Steam] ISteamClient010::GetISteamUser(\"{s}\") -> real client\n", .{ver});
    std.debug.print("[WINS:Steam]   (guest pid={d} pipe={d})\n", .{ hSteamUser, hSteamPipe });
    const obj = callAligned4(realSlot(self, 5), realOf(self), hSteamUser, hSteamPipe, vptr);
    std.debug.print("[WINS:Steam] user interface -> 0x{x}\n", .{obj});
    return wrapSubKind(SubUser, obj);
}

/// ISteamClient slot 9: GetISteamUtils(hSteamPipe, version).
///
/// Two arguments, not three: measured against the real client, handing it
/// three makes it fault inside the client, and reading a third argument here
/// is what used to make the log show an empty version name for a call the
/// guest had made with a perfectly good one.
fn a009_GetISteamUtils(self: usize, hSteamPipe: u32, pchVersion: ?[*:0]const u8) callconv(Tc) usize {
    const ver = if (pchVersion) |v| std.mem.sliceTo(v, 0) else "?";
    const vptr: usize = if (pchVersion) |v| @intFromPtr(v) else 0;
    std.debug.print("[WINS:Steam] ISteamClient010::GetISteamUtils(\"{s}\") -> real client\n", .{ver});
    const obj = callAligned3(realSlot(self, 9), realOf(self), hSteamPipe, vptr);
    std.debug.print("[WINS:Steam] utils interface -> 0x{x}\n", .{obj});
    return wrapSubKind(SubUtils, obj);
}

/// ISteamClient slot 13: the generic getter. It dispatches on the version
/// name and hands back the object for it -- the ticket name gives the ticket
/// object, the utils name the utils object. This is where the app-ownership
/// ticket comes from: the real client answers GetAppOwnershipTicketData(22380)
/// with 238 bytes of ticket and a 128-byte signature.
fn a013_GetISteamGenericInterface(self: usize, hSteamUser: u32, hSteamPipe: u32, pchVersion: ?[*:0]const u8) callconv(Tc) usize {
    const ver = if (pchVersion) |v| std.mem.sliceTo(v, 0) else "?";
    const vptr: usize = if (pchVersion) |v| @intFromPtr(v) else 0;
    std.debug.print("[WINS:Steam] ISteamClient010::GetISteamGenericInterface(\"{s}\") -> real client\n", .{ver});
    std.debug.print("[WINS:Steam]   (guest pid={d} pipe={d})\n", .{ hSteamUser, hSteamPipe });
    // The client's own pipe and user, not the ones the guest passes: the
    // client validates that pair (IsValidHSteamUserPipe) and the guest's
    // pair is not the one the client issued.
    const use_user = if (g_guest_user != 0) g_guest_user else hSteamUser;
    const use_pipe = if (g_guest_pipe != 0) g_guest_pipe else hSteamPipe;
    const obj = callAligned4(realSlot(self, 13), realOf(self), use_user, use_pipe, vptr);
    std.debug.print("[WINS:Steam] generic interface -> 0x{x} (client pid={d} pipe={d})\n", .{ obj, use_user, use_pipe });
    const kind = kindForVersion(pchVersion);
    // The ticket object is the one the DRM will ask for the ownership ticket
    // on, and the SteamID the DRM asks for comes out of that same ticket.
    if (kind == SubAppTicket and obj != 0) g_real_ticket = obj;
    return wrapSubKind(kind, obj);
}

fn a_stub(self: usize) callconv(Tc) u32 {
    _ = self;
    return 0;
}

var g_steamclient010_vt: [40]usize = [_]usize{0} ** 40;
var g_steamclient010_vt_ready: bool = false;

/// Filled at runtime: Zig cannot take a function address in a comptime
/// initialiser, so the table is built once on first use rather than at compile
/// time. The slot->method mapping is the one measured from the guest's own call
/// site (disassembly of the DRM: slots 0, 2, 9, 5, 13).
fn ensureSteamClient010Vt() void {
    if (g_steamclient010_vt_ready) return;
    // Every hole announces itself. The old fill used a_stub, which returned 0
    // in silence: a DRM call into a slot we had not modelled looked exactly
    // like a client that had nothing to say, and the DRM walked away from the
    // whole handshake. The table is also grown to the real ISteamClient size so
    // a call past the old 16 slots cannot read past the end of the array.
    inline for (0..g_steamclient010_vt.len) |i| {
        g_steamclient010_vt[i] = @intFromPtr(stubFor(i));
    }
    g_steamclient010_vt[0] = @intFromPtr(&a000_CreateSteamPipe);
    g_steamclient010_vt[1] = @intFromPtr(&a001_BReleaseSteamPipe);
    g_steamclient010_vt[2] = @intFromPtr(&a002_ConnectToGlobalUser);
    g_steamclient010_vt[3] = @intFromPtr(&a003_ReleaseUser);
    g_steamclient010_vt[4] = @intFromPtr(&a004_DisconnectGlobalUser);
    g_steamclient010_vt[5] = @intFromPtr(&a005_GetISteamUser);
    g_steamclient010_vt[9] = @intFromPtr(&a009_GetISteamUtils);
    g_steamclient010_vt[13] = @intFromPtr(&a013_GetISteamGenericInterface);
    g_steamclient010_vt_ready = true;
}

var g_steamclient010_adapter: Adapter = .{ .vt = 0, .real = 0 };

// ---- sub-interfaces the DRM asks for --------------------------------------
//
// The real client hands back real ISteamUser016 / ISteamUtils005 / ISteamAppTicket
// objects, and the guest will call those with the Microsoft ABI too, so they are
// wrapped the same way. The slot numbers below are the Steamworks layout and are
// VERIFIED BY THE LOG LINE each thunk prints: if the guest's call lands on a
// different slot the log names it, which is the measurement that corrects the
// table. Everything else forwards, so a wrong guess forwards wrongly rather than
// silently inventing an answer.

var g_sub_adapters: [8]Adapter = [_]Adapter{.{ .vt = 0, .real = 0 }} ** 8;

fn subVt(comptime n: usize) *[64]usize {
    return &g_sub_vt[n];
}

var g_sub_vt: [4][64]usize = [_][64]usize{[_]usize{0} ** 64} ** 4;
var g_sub_vt_ready: bool = false;

/// A thunk that says which slot was reached and that it has no implementation
/// yet. The old stub returned 0 without a word, and that silence is what hid
/// the vtable mix-up: the DRM's ticket call landed on a stub, got 0, and the
/// log showed nothing between the interface request and the Steam2 fallback.
/// A wrong slot must be visible in the log, because the log is the only
/// measurement that corrects the table.
fn stubFor(comptime slot: usize) *const fn (usize) callconv(Tc) u32 {
    return struct {
        fn f(self: usize) callconv(Tc) u32 {
            _ = self;
            std.debug.print("[WINS:Steam] unimplemented slot {d} (no thunk yet)\n", .{slot});
            return 0;
        }
    }.f;
}

/// Same as ensureSteamClient010Vt, for the sub-interfaces. The slot numbers are
/// the Steamworks layout and each thunk logs what it forwards, so a wrong guess
/// is corrected by the log rather than silently answering.
fn ensureSubVt() void {
    if (g_sub_vt_ready) return;
    inline for (0..g_sub_vt.len) |k| {
        inline for (0..g_sub_vt[k].len) |i| {
            g_sub_vt[k][i] = @intFromPtr(stubFor(i));
        }
    }
    g_sub_vt[SubUser][1] = @intFromPtr(&sub_BLoggedOn);
    g_sub_vt[SubUser][2] = @intFromPtr(&sub_GetSteamID);
    g_sub_vt[SubUtils][9] = @intFromPtr(&sub_GetAppID);
    g_sub_vt[SubAppTicket][0] = @intFromPtr(&sub_GetAppOwnershipTicketData);
    g_sub_vt_ready = true;
}

var g_sub_real: [3]usize = [_]usize{0} ** 3;
var g_sub_used: [3]usize = [_]usize{0} ** 3;

/// Wrap a real sub-interface in an adapter, reusing a free slot. Order of the
/// pool does not matter: each adapter carries its own real pointer, and the
/// slot the guest asks for is forwarded to the object it belongs to.
/// Wrap a real sub-interface in an adapter, with the vtable that matches its
/// type. The pool is keyed by the real object; the vtable is chosen by `kind`,
/// NOT by pool position.
///
/// Choosing by position was measured wrong: the DRM asks for ISteamUser first
/// (pool slot 0 -> User table) and for ISteamAppTicket second (pool slot 1 ->
/// the Utils table). Utils slot 0 is a_stub, which returns 0 without a log
/// line, so GetAppOwnershipTicketData answered "no ticket" silently and the
/// DRM fell back to the Steam2 SteamStart path. The fix is to name the kind at
/// the call site and let the pool position mean nothing but storage.
fn wrapSubKind(kind: usize, real_obj: usize) usize {
    if (real_obj == 0) return 0;
    ensureSubVt();
    var i: usize = 0;
    while (i < g_sub_adapters.len) : (i += 1) {
        if (g_sub_adapters[i].real == real_obj) return @intFromPtr(&g_sub_adapters[i]);
        if (g_sub_adapters[i].real == 0) {
            g_sub_adapters[i] = .{ .vt = @intFromPtr(&g_sub_vt[kind % g_sub_vt.len]), .real = real_obj };
            return @intFromPtr(&g_sub_adapters[i]);
        }
    }
    return real_obj; // pool exhausted: hand the real object over rather than drop it
}

/// Sub-interface kinds, matching the g_sub_vt tables built in ensureSubVt.
const SubUser: usize = 0;
const SubUtils: usize = 1;
const SubAppTicket: usize = 2;
/// Interfaces with no modelled method yet (Apps, Friends, UserStats, the
/// generic one): they get their own table so a call into them is logged as an
/// unimplemented slot instead of landing on another interface's thunk.
const SubGeneric: usize = 3;

/// The pipe and the global user the guest itself created, and the app id the
/// client reported. The ticket fetch needs them: the client's ticket call is
/// made on behalf of a user bound to a pipe.
var g_guest_pipe: u32 = 0;
var g_guest_user: u32 = 0;
var g_guest_appid: u32 = 0;

/// ISteamUser slot 1: BLoggedOn(). Steam's result must come from the active
/// client so Fallout follows the same login decision as the native interface.
/// Adapt the guest's x86 thiscall to the real client's aligned Linux cdecl.
fn sub_BLoggedOn(self: usize) callconv(Tc) u32 {
    const slot = realSlot(self, 1);
    if (slot == 0) return 0;
    const logged_on: u32 = @truncate(callAligned1(slot, realOf(self)));
    std.debug.print("[WINS:Steam] ISteamUser016::BLoggedOn() -> {d} (from the real client)\n", .{logged_on});
    return logged_on;
}

/// One ticket fetch in the real client's own shape.
///
/// Measured against steamclient.so: the client writes ONE blob -- the ticket
/// part followed by the signature -- and hands back the OFFSETS of the app id
/// (16), of the SteamID64 (8), of the signature (110) and the length of that
/// signature (128). The Steamworks ABI wants pointers to values and a
/// separate signature buffer, so this is the raw call and the translation
/// lives in the thunk above it.
/// The ticket the client already gave us, kept so the DRM's two questions --
/// "who is the user" and "give me the ownership ticket" -- cost ONE request to
/// the client instead of two. The client's answer does not change between them
/// (same app, same user) and asking twice is one IPC round trip too many.
/// The client's answer about one app's ownership ticket.
///
/// The client writes one blob: the ticket, and the signature over it right
/// behind it. It also says where each piece sits inside that blob. Both the
/// blob and the offsets are the client's own, measured, not assumed.
const TicketBlob = struct {
    /// Bytes the client wrote: the ticket, with the signature behind it.
    total: u32 = 0,
    /// Where the app id sits inside the blob.
    off_appid: u32 = 0,
    /// Where the SteamID64 sits inside the blob.
    off_steamid: u32 = 0,
    /// Where the signature sits inside the blob.
    off_sig: u32 = 0,
    /// How long the signature is.
    len_sig: u32 = 0,
    /// The app id, read from the blob at off_appid.
    appid: u32 = 0,
    /// The SteamID64, read from the blob at off_steamid.
    steamid: u64 = 0,
};

var g_ticket_cache: [512]u8 = undefined;
var g_ticket_cache_valid: bool = false;
var g_ticket_cache_appid: u32 = 0;
var g_ticket_cache_blob: TicketBlob = .{};

/// Ask the real client for an app's ownership ticket.
///
/// The client answers with the blob (the ticket, with its signature behind
/// it) and the offsets of the pieces inside it. The blob is kept whole: the
/// guest's DRM verifies the signature over the ticket bytes, so it needs both
/// in one place.
fn fetchRealTicket(real_ticket: usize, appid: u32, buf: []u8) TicketBlob {
    if (real_ticket == 0) return .{};
    if (g_ticket_cache_valid and g_ticket_cache_appid == appid) {
        const copy = @min(g_ticket_cache_blob.total, buf.len);
        @memcpy(buf[0..copy], g_ticket_cache[0..copy]);
        return g_ticket_cache_blob;
    }
    const vt: [*]const usize = @ptrFromInt(@as(*const usize, @ptrFromInt(real_ticket)).*);
    var off_appid: u32 = 0;
    var off_steamid: u32 = 0;
    var off_sig: u32 = 0;
    var len_sig: u32 = 0;
    const total = callAligned8(
        vt[0],
        real_ticket,
        appid,
        @intFromPtr(buf.ptr),
        buf.len,
        @intFromPtr(&off_appid),
        @intFromPtr(&off_steamid),
        @intFromPtr(&off_sig),
        @intFromPtr(&len_sig),
    );
    if (total == 0) return .{};
    if (total > buf.len) {
        std.debug.print("[WINS:Steam] the client wrote {d} bytes into a {d}-byte buffer\n", .{ total, buf.len });
        return .{};
    }
    if (off_appid + 4 > total or off_steamid + 8 > total or off_sig + len_sig > total) {
        std.debug.print("[WINS:Steam] the client's ticket blob does not hold its own pieces (total={d}, appid@{d}, steamid@{d}, firma@{d}+{d})\n", .{ total, off_appid, off_steamid, off_sig, len_sig });
        return .{};
    }
    // The app id and the SteamID are read from the blob itself, not from the
    // client's out-parameters: the first caller (the SteamID question) asks
    // for neither, and a blob filled from it would hand the next caller a
    // zero app id.
    const blob = TicketBlob{
        .total = total,
        .off_appid = off_appid,
        .off_steamid = off_steamid,
        .off_sig = off_sig,
        .len_sig = len_sig,
        .appid = std.mem.readInt(u32, buf[off_appid..][0..4], .little),
        .steamid = std.mem.readInt(u64, buf[off_steamid..][0..8], .little),
    };
    // Keep the whole answer for the next question about the same app.
    g_ticket_cache_valid = true;
    g_ticket_cache_appid = appid;
    g_ticket_cache_blob = blob;
    const keep = @min(total, g_ticket_cache.len);
    @memcpy(g_ticket_cache[0..keep], buf[0..keep]);
    return blob;
}

/// The real ticket object, once the DRM has asked the client for it.
var g_real_ticket: usize = 0;

fn sub_GetSteamID(self: usize, pSteamID: ?*u64) callconv(Tc) u64 {
    // Measured: the real client's user interface does not answer this in the
    // shape the guest uses. Its slots either fault inside the client or
    // answer something else -- the object it hands back for "SteamUser016"
    // has no method that writes a SteamID64 anywhere. The SteamID the DRM
    // wants is the one the client itself puts in the ownership ticket, so
    // ask the client for the ticket and read it from there: the value still
    // comes from Steam, not from us.
    _ = self;
    var scratch: [512]u8 = undefined;
    const blob = fetchRealTicket(g_real_ticket, g_guest_appid, scratch[0..]);
    if (blob.total == 0) {
        std.debug.print("[WINS:Steam] ISteamUser016::GetSteamID() -> the client gave no ticket\n", .{});
        return 0;
    }
    // The DRM copies the 8 bytes it gets here into one 8-byte local, so it
    // wants the whole SteamID64 written, not a 32-bit half of it.
    if (pSteamID) |p| p.* = blob.steamid;
    std.debug.print("[WINS:Steam] ISteamUser016::GetSteamID() -> 0x{x} (from the client's own ticket)\n", .{blob.steamid});
    return 1;
}

fn sub_GetAppID(self: usize) callconv(Tc) u32 {
    const r = callAligned1(realSlot(self, 9), realOf(self));
    g_guest_appid = @truncate(r);
    std.debug.print("[WINS:Steam] ISteamUtils005::GetAppID() -> {d} (from the real client)\n", .{r});
    return @truncate(r);
}

/// ISteamAppTicket001::GetAppOwnershipTicketData, as the DRM's own code calls
/// it.
///
/// Measured against the code the guest actually runs (the CEG image it builds
/// at 0x10000000), the four out-parameters are not values: they are where the
/// pieces sit inside the buffer the DRM passed in. The DRM reads the app id
/// at the first offset and compares it against the app it asked for, compares
/// the SteamID64 at the second against the one the user interface gave it,
/// and verifies the signature at the third, of the given length, over the
/// first `total - len_sig` bytes of the same buffer. So the whole blob goes
/// into the guest's buffer and the offsets go back untouched.
fn sub_GetAppOwnershipTicketData(
    self: usize,
    nAppID: u32,
    pvBuffer: ?[*]u8,
    cbBufferLength: u32,
    piAppIdOffset: ?*u32,
    piSteamIdOffset: ?*u32,
    piSignatureOffset: ?*u32,
    piSignatureLength: ?*u32,
) callconv(Tc) u32 {
    _ = self;
    var scratch: [512]u8 = undefined;
    const blob = fetchRealTicket(g_real_ticket, nAppID, scratch[0..]);
    if (blob.total == 0) {
        std.debug.print("[WINS:Steam] ISteamAppTicket001::GetAppOwnershipTicketData(appid={d}) -> the client gave nothing\n", .{nAppID});
        return 0;
    }
    // The ticket and the signature travel together: the DRM verifies the
    // signature over the ticket bytes, in the buffer it passed in.
    if (pvBuffer) |dst| {
        const copy = @min(blob.total, cbBufferLength);
        @memcpy(dst[0..copy], scratch[0..copy]);
    }
    if (piAppIdOffset) |p| p.* = blob.off_appid;
    if (piSteamIdOffset) |p| p.* = blob.off_steamid;
    if (piSignatureOffset) |p| p.* = blob.off_sig;
    if (piSignatureLength) |p| p.* = blob.len_sig;
    std.debug.print("[WINS:Steam] ISteamAppTicket001::GetAppOwnershipTicketData(appid={d}) -> {d} bytes (appid@{d}, steamid@{d}, firma@{d}+{d}) (from the real client)\n", .{ nAppID, blob.total, blob.off_appid, blob.off_steamid, blob.off_sig, blob.len_sig });
    return blob.total;
}

// ---- CreateInterface (exported from steamclient.dll) -----------------------
//
// Called cdecl by the DRM. The object handed back is an adapter over the real
// client's object: every method the guest calls is forwarded to the real client,
// across the ABI boundary. When there is no real client to ask, this returns
// null and says why -- the alternative is the dummy vtable that answered for a
// client that was never there, and the DRM rejected it with ERROR_ACCESS_DENIED.
fn steamclient_CreateInterface(pName: ?[*:0]const u8, pReturnCode: ?*i32) callconv(.c) ?*anyopaque {
    if (pReturnCode) |rc| rc.* = -1;
    const name = if (pName) |n| std.mem.sliceTo(n, 0) else "";
    std.debug.print("[WINS:Steam] CreateInterface(\"{s}\")\n", .{name});

    loadRealSteamClient();
    if (g_real_iface == 0) {
        std.debug.print("  -> REFUSED: no real Steam client is reachable from this process.\n", .{});
        std.debug.print("     The build must be dynamic glibc i386 (-lc -dynamic) for the loader\n", .{});
        std.debug.print("     to dlopen the real client at all. The loader will not speak for it.\n", .{});
        return null;
    }
    ensureSteamClient010Vt();
    // Honour the version the guest asked for: the client has an object for
    // each one of them, and the guest asks for "SteamClient010" first and
    // "SteamClient009" when it falls back. The slot layout used here was
    // measured on SteamClient010.
    var real = g_real_iface;
    if (g_real_create) |f| {
        var rc2: i32 = -1;
        if (f(name, &rc2)) |o| {
            real = @intFromPtr(o);
            std.debug.print("  -> the real client supplied \"{s}\" (0x{x})\n", .{ name, real });
        } else {
            std.debug.print("  -> the real client has no \"{s}\" (rc={d}); keeping SteamClient010\n", .{ name, rc2 });
        }
    }
    g_steamclient010_adapter = .{ .vt = @intFromPtr(&g_steamclient010_vt), .real = real };
    if (pReturnCode) |rc| rc.* = 0;
    std.debug.print("  -> adapter over the real client's object (real=0x{x})\n", .{real});
    return @ptrFromInt(adapterObj(&g_steamclient010_adapter));
}

// ============================================================================
// steam_api.dll flat C exports
// ============================================================================
//
// These used to return dummy objects. They now go through the real client: one
// pipe and one global user, established once, and each interface obtained by
// asking the real client for it by version. When the real client cannot supply
// a version, the answer is null and the log says so -- which is what a missing
// capability looks like, as opposed to an object that answers for the client.

var g_flat_pipe: u32 = 0;
var g_flat_user: u32 = 0;
var g_flat_ready: bool = false;

const FlatIface = struct { user: usize = 0, utils: usize = 0, apps: usize = 0, friends: usize = 0, stats: usize = 0 };
var g_flat: FlatIface = .{};

/// Establish the pipe and the global user against the real client, once.
fn steamFlatReady() bool {
    if (g_flat_ready) return true;
    if (g_real_iface == 0) return false;
    const vt: [*]const usize = @ptrFromInt(@as(*const usize, @ptrFromInt(g_real_iface)).*);
    // These are the real client's own methods, so they are called with the
    // client's calling convention and the client's alignment requirement.
    //
    // Measured: called through a plain C call, the client's CreateSteamPipe
    // faulted on its own SSE store (`movaps %xmm4,-0x78(%ebp)`) because the
    // stack was not 16-byte aligned -- the Linux i386 ABI requires that at a
    // call, and a C call from a 4-byte-aligned frame does not give it. The
    // same two calls made through callAligned1/callAligned2, which is what
    // the CEG path does, do not fault.
    g_flat_pipe = @truncate(callAligned1(vt[0], g_real_iface));
    g_flat_user = @truncate(callAligned2(vt[2], g_real_iface, g_flat_pipe));
    g_flat_ready = true;
    std.debug.print("[WINS:Steam] real client: pipe={d} user={d}\n", .{ g_flat_pipe, g_flat_user });
    return true;
}

/// Ask the real client for a named interface and wrap it for the guest.
///
/// The named interfaces come from the client's generic getter, which is slot
/// 13 of its vtable and dispatches on the version name -- measured. Slot 9 is
/// GetISteamUtils, which takes two arguments and faults inside the client when
/// given three; asking it for a name other than the utils one answers null.
fn steamFlatIface(comptime versions: []const [*:0]const u8, kind: usize) usize {
    if (!steamFlatReady()) return 0;
    const vt: [*]const usize = @ptrFromInt(@as(*const usize, @ptrFromInt(g_real_iface)).*);
    inline for (versions) |v| {
        // Aligned for the same reason as steamFlatReady above.
        const got = callAligned4(vt[13], g_real_iface, g_flat_user, g_flat_pipe, @intFromPtr(v));
        if (got != 0) {
            std.debug.print("[WINS:Steam] real client supplied \"{s}\"\n", .{v});
            return wrapSubKind(kind, got);
        }
    }
    return 0;
}

fn SteamUser() callconv(W) usize {
    if (g_flat.user == 0) g_flat.user = steamFlatIface(&[_][*:0]const u8{ "SteamUser016", "SteamUser019", "SteamUser017", "SteamUser020" }, SubUser);
    return g_flat.user;
}

fn SteamUtils() callconv(W) usize {
    if (g_flat.utils == 0) g_flat.utils = steamFlatIface(&[_][*:0]const u8{ "SteamUtils005", "SteamUtils009", "SteamUtils010" }, SubUtils);
    return g_flat.utils;
}

fn SteamApps() callconv(W) usize {
    if (g_flat.apps == 0) g_flat.apps = steamFlatIface(&[_][*:0]const u8{ "SteamApps008", "SteamApps003", "SteamApps005", "SteamApps006", "SteamApps007" }, SubGeneric);
    return g_flat.apps;
}

fn SteamFriends() callconv(W) usize {
    if (g_flat.friends == 0) g_flat.friends = steamFlatIface(&[_][*:0]const u8{ "SteamFriends015", "SteamFriends014", "SteamFriends013" }, SubGeneric);
    return g_flat.friends;
}

fn SteamUserStats() callconv(W) usize {
    if (g_flat.stats == 0) g_flat.stats = steamFlatIface(&[_][*:0]const u8{
        "STEAMUSERSTATS_INTERFACE_VERSION007",
        "SteamUserStats012",
        "SteamUserStats011",
        "SteamUserStats010",
    }, SubGeneric);
    return g_flat.stats;
}

// ============================================================================
// Bink Video Shims (binkw32.dll)
// ============================================================================

/// Bink 1 playback (wins_bink.zig): the container is read natively and the
/// packets decoded by the host's libavcodec. When the file or the host
/// decoder is missing, the open fails the way binkw32 fails (a NULL handle),
/// which FalloutNV handles by skipping the video.
fn BinkOpen(name: ?[*:0]const u8, flags: u32) callconv(W) usize {
    const n = name orelse return 0;
    const path = std.mem.sliceTo(n, 0);
    var norm: [512]u8 = undefined;
    const len = @min(norm.len - 1, path.len);
    for (0..len) |i| norm[i] = if (path[i] == '\\') '/' else path[i];
    norm[len] = 0;
    var resolved_buf: [512]u8 = undefined;
    const real: [:0]const u8 = resolvePathCaseInsensitive(norm[0..len], &resolved_buf) orelse norm[0..len :0];
    const b = bink_mod.open(real, flags);
    std.debug.print("[WINS:BinkVideo] _BinkOpen(\"{s}\", flags 0x{x}) -> 0x{x}\n", .{ path, flags, @intFromPtr(b) });
    return @intFromPtr(b);
}

fn binkOf(h: usize) ?*bink_mod.Bink {
    return if (h == 0) null else @ptrFromInt(h);
}

fn BinkClose(bink: usize) callconv(W) void {
    if (binkOf(bink)) |b| bink_mod.close(b);
}

fn BinkDoFrame(bink: usize) callconv(W) i32 {
    const b = binkOf(bink) orelse return 0;
    return bink_mod.doFrame(b);
}

fn BinkNextFrame(bink: usize) callconv(W) void {
    if (binkOf(bink)) |b| bink_mod.nextFrame(b);
}

fn BinkWait(bink: usize) callconv(W) i32 {
    const b = binkOf(bink) orelse return 0;
    return bink_mod.wait(b);
}

fn BinkPause(bink: usize, pause: i32) callconv(W) i32 {
    const b = binkOf(bink) orelse return 0;
    return bink_mod.pause(b, pause != 0);
}

/// _BinkCopyToBufferRect@44: eleven stack words, which the callee pops.
fn BinkCopyToBufferRect(bink: usize, dest: usize, pitch: u32, height: u32, x: u32, y: u32, sx: u32, sy: u32, sw: u32, sh: u32, flags: u32) callconv(W) i32 {
    const b = binkOf(bink) orelse return 1;
    return bink_mod.copyToBufferRect(b, dest, pitch, height, x, y, sx, sy, sw, sh, flags);
}

/// Bink audio is played by wins_bink.zig on the host sound server; selecting
/// DirectSound as the sound system succeeds.
fn BinkOpenDirectSound(bink: usize) callconv(W) i32 {
    _ = bink;
    return 1;
}

fn BinkSetSoundSystem(open_fn: ?*anyopaque, param: usize) callconv(W) i32 {
    _ = open_fn; _ = param;
    return 1;
}

// ============================================================================
// User32 GUI Shims
// ============================================================================
// Windows, classes, the message queue, activation and focus live in
// wins_user32.zig; what is left here is input, cursor and system queries.

fn GetSystemMetrics(nIndex: i32) callconv(W) i32 {
    if (nIndex == 0) return 1920; // SM_CXSCREEN
    if (nIndex == 1) return 1080; // SM_CYSCREEN
    return 0;
}

fn LoadIconA(hInstance: usize, lpIconName: ?[*:0]const u8) callconv(W) usize {
    _ = hInstance; _ = lpIconName;
    return 0x10001;
}

fn LoadCursorA(hInstance: usize, lpCursorName: ?[*:0]const u8) callconv(W) usize {
    _ = hInstance; _ = lpCursorName;
    return 0x10002;
}

fn ShowCursor(bShow: i32) callconv(W) i32 {
    return bShow;
}

fn GetDoubleClickTime() callconv(W) u32 {
    return 500;
}

fn SwapMouseButton(fSwap: i32) callconv(W) i32 {
    _ = fSwap;
    return 0;
}

fn UnhookWindowsHookEx(hhk: usize) callconv(W) i32 {
    _ = hhk;
    return 1;
}

fn SetWindowsHookExA(idHook: i32, lpfn: ?*anyopaque, hmod: usize, dwThreadId: u32) callconv(W) usize {
    _ = idHook; _ = lpfn; _ = hmod; _ = dwThreadId;
    return 0x7001;
}

fn CallNextHookEx(hhk: usize, nCode: i32, wParam: usize, lParam: usize) callconv(W) usize {
    _ = hhk; _ = nCode; _ = wParam; _ = lParam;
    return 0;
}

fn SendInput(cInputs: u32, pInputs: ?*anyopaque, cbSize: i32) callconv(W) u32 {
    _ = pInputs; _ = cbSize;
    return cInputs;
}

fn EnumDisplayDevicesA(lpDevice: ?*anyopaque, iDevNum: u32, lpDisplayDevice: ?*anyopaque, dwFlags: u32) callconv(W) i32 {
    _ = lpDevice; _ = lpDisplayDevice; _ = dwFlags;
    return if (iDevNum == 0) 1 else 0;
}

fn MessageBoxA(hWnd: usize, lpText: ?[*:0]const u8, lpCaption: ?[*:0]const u8, uType: u32) callconv(W) i32 {
    _ = hWnd; _ = uType;
    const t = if (lpText) |x| std.mem.sliceTo(x, 0) else "Message";
    const c = if (lpCaption) |x| std.mem.sliceTo(x, 0) else "Info";
    std.debug.print("[WINS:MessageBoxA] [{s}] {s}\n", .{ c, t });
    return 1; // IDOK
}

fn GetAsyncKeyState(vKey: i32) callconv(W) i16 {
    return user32_mod.GetAsyncKeyState(vKey);
}

// ============================================================================
// COM, Shell & Registry Shims
// ============================================================================

fn CoInitialize(pvReserved: ?*anyopaque) callconv(W) i32 {
    _ = pvReserved;
    return 0; // S_OK
}

fn CoInitializeEx(pvReserved: ?*anyopaque, dwCoInit: u32) callconv(W) i32 {
    _ = pvReserved; _ = dwCoInit;
    return 0; // S_OK
}

fn CoUninitialize() callconv(W) void {}

fn CoFreeUnusedLibraries() callconv(W) void {}

fn printGuid(tag: []const u8, g: ?*const anyopaque) void {
    const p: [*]const u8 = @ptrCast(g orelse {
        std.debug.print("{s}=null", .{tag});
        return;
    });
    const d1 = std.mem.readInt(u32, p[0..4], .little);
    const d2 = std.mem.readInt(u16, p[4..6], .little);
    const d3 = std.mem.readInt(u16, p[6..8], .little);
    std.debug.print("{s}={{{x:0>8}-{x:0>4}-{x:0>4}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}}}", .{ tag, d1, d2, d3, p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15] });
}

/// The one COM class this loader implements is DirectShow's filter graph
/// (wins_dshow.zig): FalloutNV plays its music through it and faulted
/// reading NULL (EIP 0x83101e) when the answer was S_OK with a NULL
/// interface. Every other class answers REGDB_E_CLASSNOTREG with *ppv = NULL.
const REGDB_E_CLASSNOTREG: i32 = @bitCast(@as(u32, 0x80040154));
fn CoCreateInstance(rclsid: ?*anyopaque, pUnkOuter: ?*anyopaque, dwClsContext: u32, riid: ?*anyopaque, ppv: ?*?*anyopaque) callconv(W) i32 {
    if (dshow_mod.isFilterGraph(rclsid)) {
        const hr = dshow_mod.createFilterGraph(pUnkOuter, riid, ppv);
        std.debug.print("[WINS:Ole32] CoCreateInstance(CLSID_FilterGraph", .{});
        printGuid(" iid", riid);
        std.debug.print(") -> 0x{x}\n", .{@as(u32, @bitCast(hr))});
        return hr;
    }
    if (ppv) |p| p.* = null;
    std.debug.print("[WINS:Ole32] CoCreateInstance(", .{});
    printGuid("clsid", rclsid);
    printGuid(" iid", riid);
    std.debug.print(" ctx=0x{x}) -> REGDB_E_CLASSNOTREG\n", .{dwClsContext});
    return REGDB_E_CLASSNOTREG;
}

fn CoTaskMemAlloc(cb: usize) callconv(W) ?*anyopaque {
    return HeapAlloc(0, 0, cb);
}

fn CoTaskMemFree(pv: ?*anyopaque) callconv(W) void {
    _ = HeapFree(0, 0, pv);
}

fn SHGetFolderPathA(hwnd: usize, csidl: i32, hToken: usize, dwFlags: u32, pszPath: ?[*]u8) callconv(W) i32 {
    _ = hwnd; _ = csidl; _ = hToken; _ = dwFlags;
    if (pszPath) |path| {
        const default_docs = "./";
        @memcpy(path[0..default_docs.len], default_docs);
        path[default_docs.len] = 0;
    }
    return 0; // S_OK
}

/// Nothing is ever launched, so the honest answer is a failure code: Windows
/// reports ShellExecuteA success only with a return value > 32. Answering
/// success here made guests believe a launcher opened and exit silently
/// right after (the FalloutNV GPU-name-mismatch path).
const SE_ERR_FNF: usize = 2; // nothing was executed

fn ShellExecuteA(hwnd: usize, lpOperation: ?[*:0]const u8, lpFile: ?[*:0]const u8, lpParameters: ?[*:0]const u8, lpDirectory: ?[*:0]const u8, nShowCmd: i32) callconv(W) usize {
    _ = hwnd;
    const operation = if (lpOperation) |p| std.mem.sliceTo(p, 0) else "";
    const file = if (lpFile) |p| std.mem.sliceTo(p, 0) else "";
    const parameters = if (lpParameters) |p| std.mem.sliceTo(p, 0) else "";
    const directory = if (lpDirectory) |p| std.mem.sliceTo(p, 0) else "";
    std.debug.print("[WINS:ShellExecuteA] operation=\"{s}\" file=\"{s}\" params=\"{s}\" dir=\"{s}\" show={d}\n", .{ operation, file, parameters, directory, nShowCmd });
    return SE_ERR_FNF;
}

// Built lazily: the guest's argv comes from a runtime string, so a container-level
// initializer cannot compute it. Kept as a pointer so a sentinel-length array can
// still be handed to the guest as a NUL-terminated list of one entry.
var g_argv_ptr: ?[*:0]const u16 = null;

fn CommandLineToArgvW(lpCmdLine: ?[*:0]const u16, pNumArgs: ?*i32) callconv(W) ?[*]?[*:0]const u16 {
    _ = lpCmdLine;
    if (pNumArgs) |n| n.* = 1;
    return @ptrCast(&g_argv_ptr);
}

fn RegOpenKeyExA(hKey: usize, lpSubKey: ?[*:0]const u8, ulOptions: u32, samDesired: u32, phkResult: ?*usize) callconv(W) i32 {
    _ = hKey; _ = ulOptions; _ = samDesired;
    const sub = if (lpSubKey) |s| std.mem.sliceTo(s, 0) else "";
    std.debug.print("[WINS:Advapi32] RegOpenKeyExA(\"{s}\")\n", .{sub});
    if (phkResult) |hk| hk.* = 0x8001;
    return 0; // ERROR_SUCCESS
}

fn RegCreateKeyExA(hKey: usize, lpSubKey: ?[*:0]const u8, Reserved: u32, lpClass: ?[*:0]const u8, dwOptions: u32, samDesired: u32, lpSecurityAttributes: ?*anyopaque, phkResult: ?*usize, lpdwDisposition: ?*u32) callconv(W) i32 {
    _ = hKey; _ = lpSubKey; _ = Reserved; _ = lpClass; _ = dwOptions; _ = samDesired; _ = lpSecurityAttributes;
    if (phkResult) |hk| hk.* = 0x8002;
    if (lpdwDisposition) |d| d.* = 1; // REG_CREATED_NEW_KEY
    return 0; // ERROR_SUCCESS
}

var g_steam_exe_buf: [512]u8 = [_]u8{0} ** 512;
var g_steam_exe_done: bool = false;

/// The real client's PID and executable path, both discovered from /proc.
///
/// An earlier version answered 1337 for the PID -- a PID that exists on no
/// machine. The guest then went looking for a process that was never there,
/// which is the documented cause of Steam's "Application load error 5": the
/// handshake never reaches the client. A fabricated number and an absent
/// registry value look identical to the caller, and only one is a measurement.
fn steamClientPid() u32 {
    return steamClientLocate().pid;
}

/// /proc/<pid>/exe for the located client: the kernel's own answer to where the
/// real client lives on this machine. That is what the registry reports now,
/// instead of a Windows path that exists nowhere here.
fn recordClientExe(pid: u32) void {
    var p: [32:0]u8 = undefined;
    const pn = std.fmt.bufPrint(p[0..31], "/proc/{d}/exe", .{pid}) catch return;
    p[pn.len] = 0;
    const n = linux.readlink(&p, &g_steam_exe_buf, g_steam_exe_buf.len);
    if (linux.errno(n) != .SUCCESS) return;
    g_steam_exe_buf[@intCast(n)] = 0;
    g_steam_exe_done = true;
}

fn steamClientLocate() struct { pid: u32 } {
    // Explicit override for sandboxed runs: inside a namespace where
    // /proc/<pid>/exe is not readable, the caller names the client's PID and
    // executable instead of the loader scanning /proc and guessing.
    if (getenv("WINS_STEAM_PID")) |p| {
        const pid = std.fmt.parseInt(u32, std.mem.sliceTo(p, 0), 10) catch 0;
        if (pid != 0) {
            if (getenv("WINS_STEAM_EXE")) |exe| {
                const s = std.mem.sliceTo(exe, 0);
                const n = @min(s.len, g_steam_exe_buf.len - 1);
                @memcpy(g_steam_exe_buf[0..n], s[0..n]);
                g_steam_exe_buf[n] = 0;
                g_steam_exe_done = true;
            } else if (!g_steam_exe_done) recordClientExe(pid);
            return .{ .pid = pid };
        }
    }
    var dir_buf: [16 * 1024]u8 align(@alignOf(linux.dirent64)) = undefined;
    const fd = linux.open("/proc", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return .{ .pid = 0 };
    defer _ = linux.close(@intCast(fd));
    while (true) {
        const n = linux.getdents64(@intCast(fd), &dir_buf, dir_buf.len);
        if (linux.errno(n) != .SUCCESS) return .{ .pid = 0 };
        const len: usize = @intCast(n);
        if (len == 0) return .{ .pid = 0 };
        var off: usize = 0;
        while (off + @sizeOf(linux.dirent64) <= len) {
            const ent: *align(1) const linux.dirent64 = @ptrCast(&dir_buf[off]);
            const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&ent.name)), 0);
            off += ent.reclen;
            const pid = std.fmt.parseInt(u32, name, 10) catch continue;
            var path_buf: [32:0]u8 = undefined;
            const pn = std.fmt.bufPrint(path_buf[0..31], "/proc/{d}/comm", .{pid}) catch continue;
            path_buf[pn.len] = 0;
            const cfd = linux.open(&path_buf, .{ .ACCMODE = .RDONLY }, 0);
            if (linux.errno(cfd) != .SUCCESS) continue;
            defer _ = linux.close(@intCast(cfd));
            var comm_buf: [32]u8 = undefined;
            const rn = linux.read(@intCast(cfd), &comm_buf, comm_buf.len);
            if (linux.errno(rn) != .SUCCESS) continue;
            const comm = std.mem.trim(u8, comm_buf[0..@intCast(rn)], " \t\r\n");
            // Exactly one process is named "steam": the client itself. Every
            // helper around it keeps a longer name (srt-logger,
            // steam-runtime-l, srt-bwrap, ...), so this is not ambiguous.
            if (std.mem.eql(u8, comm, "steam")) {
                if (!g_steam_exe_done) recordClientExe(pid);
                return .{ .pid = pid };
            }
        }
        if (len < dir_buf.len) return .{ .pid = 0 };
    }
}

/// The real client library, derived from the running client's own executable
/// path rather than guessed. An earlier version handed the guest the relative
/// name "steamclient.dll", which is not a file in any directory.
///
/// Returns an empty slice when the client cannot be located, which the registry
/// turns into "no such value": the honest answer when there is nothing to point
/// at. A guessed path would be the same failure mode with a plausible-looking
/// string.
var g_steam_dll_buf: [512]u8 = [_]u8{0} ** 512;

/// The path lives in a file-scope buffer on purpose: the first version returned
/// a slice of a stack local, which is a dangling pointer, and dlopen was measured
/// receiving garbage because of it.
fn steamClientDllPath() []const u8 {
    const prefix = "/linux32/steamclient.so";
    if (!g_steam_exe_done) _ = steamClientLocate();
    if (!g_steam_exe_done) return "";
    const exe = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&g_steam_exe_buf)), 0);
    const arch_dir = std.fs.path.dirname(exe) orelse return "";
    const install = std.fs.path.dirname(arch_dir) orelse return "";
    const n = @min(install.len, g_steam_dll_buf.len - prefix.len - 1);
    @memcpy(g_steam_dll_buf[0..n], install[0..n]);
    @memcpy(g_steam_dll_buf[n .. n + prefix.len], prefix);
    return g_steam_dll_buf[0 .. n + prefix.len];
}

/// The real client executable, as the kernel reports it for the running
/// process. An earlier version returned "C:\Program Files\Steam\Steam.exe",
/// which is not a path on this machine.
fn steamClientExePath() []const u8 {
    if (!g_steam_exe_done) _ = steamClientLocate();
    if (!g_steam_exe_done) return "";
    return std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&g_steam_exe_buf)), 0);
}

/// REG_SZ values are counted with their terminator, and the terminator has to
/// be inside the caller's buffer or the string has no end there.
fn szWithTerminator(buf: []u8, s: []const u8) []const u8 {
    const n = @min(s.len, buf.len - 1);
    @memcpy(buf[0..n], s[0..n]);
    buf[n] = 0;
    return buf[0 .. n + 1];
}

/// Win32 registry query, to the contract the caller actually uses.
///
/// The directory the guest's image came from, separator-terminated so a
/// caller can append a subpath straight onto it.
///
/// The loader knows the target's full path: it was named on the command line,
/// and the working directory was changed into its own. An earlier version
/// answered "Installed Path" with "./", a directory nobody measured, and the
/// guest derives its whole file layout from that value: it asked, was handed
/// the fabrication, and shut down immediately afterwards.
///
/// An empty slice means there is no target path at all, which the registry
/// turns into ERROR_FILE_NOT_FOUND: the honest answer when there is nothing to
/// point at.
fn targetDirWithTerminator(buf: []u8) []const u8 {
    const path = g_target_path[0..g_target_path_len];
    if (path.len == 0) return buf[0..0];
    const dir_end = if (std.mem.lastIndexOfScalar(u8, path, '/')) |s| s + 1 else 0;
    if (dir_end == 0 or dir_end >= buf.len) {
        // No separator in the path: the file sits in the working directory,
        // which is where the loader changed to.
        const rel = "./";
        if (rel.len >= buf.len) return buf[0..0];
        @memcpy(buf[0..rel.len], rel);
        return buf[0..rel.len:0];
    }
    @memcpy(buf[0..dir_end], path[0..dir_end]);
    return buf[0..dir_end:0];
}

/// The caller may pass a null data buffer to ask only for the size, and the
/// reported size counts the terminator; when the buffer is too small the value
/// is not copied and ERROR_MORE_DATA is returned. An earlier version wrote into
/// lpData whether or not the caller had supplied one and how large it was. That
/// is a heap corruption, and it is what aborted the real Steam client with
/// "malloc(): unaligned tcache chunk detected" once the guest got far enough to
/// call it -- localised with the startup probe, which runs the identical
/// dlopen and CreateInterface before any guest code and succeeds.
fn RegQueryValueExA(hKey: usize, lpValueName: ?[*:0]const u8, lpReserved: ?*u32, lpType: ?*u32, lpData: ?[*]u8, lpcbData: ?*u32) callconv(W) i32 {
    _ = lpReserved;
    const name = if (lpValueName) |vn| std.mem.sliceTo(vn, 0) else "";
    std.debug.print("[WINS:Advapi32] RegQueryValueExA(0x{x}, \"{s}\")\n", .{ hKey, name });
    const ERROR_SUCCESS: i32 = 0;
    const ERROR_MORE_DATA: i32 = 234;
    const REG_NONE: u32 = 0;
    const REG_SZ: u32 = 1;
    const REG_DWORD: u32 = 4;

    var reg_type: u32 = REG_NONE;
    var bytes: []const u8 = "";
    var word: u32 = 0;
    var sz_buf: [512]u8 = undefined;

    if (std.ascii.eqlIgnoreCase(name, "pid")) {
        reg_type = REG_DWORD;
        word = steamClientPid();
        bytes = std.mem.asBytes(&word);
    } else if (std.ascii.eqlIgnoreCase(name, "SteamClientDll")) {
        const p = steamClientDllPath();
        if (p.len == 0) {
            if (lpcbData) |cb| cb.* = 0;
            return 2; // ERROR_FILE_NOT_FOUND
        }
        reg_type = REG_SZ;
        bytes = szWithTerminator(&sz_buf, p);
    } else if (std.ascii.eqlIgnoreCase(name, "SteamExe") or std.ascii.eqlIgnoreCase(name, "SteamPath")) {
        const p = steamClientExePath();
        if (p.len == 0) {
            if (lpcbData) |cb| cb.* = 0;
            return 2; // ERROR_FILE_NOT_FOUND
        }
        reg_type = REG_SZ;
        bytes = szWithTerminator(&sz_buf, p);
    } else if (std.ascii.eqlIgnoreCase(name, "ActiveUser") or std.ascii.eqlIgnoreCase(name, "Universe")) {
        reg_type = REG_DWORD;
        word = 1;
        bytes = std.mem.asBytes(&word);
    } else if (std.ascii.eqlIgnoreCase(name, "Installed Path") or std.ascii.eqlIgnoreCase(name, "sBasePath")) {
        // The directory the guest is actually running from.
        //
        // The stub answered "./", which is a fabricated directory rather than
        // a measured one, and the guest's whole file layout is derived from
        // this value: it asked for it, got "./", and shut down immediately
        // afterwards. The loader set the working directory to the target's
        // own and holds its full path, so the real answer is on hand.
        const dir = targetDirWithTerminator(&sz_buf);
        if (dir.len == 0) {
            if (lpcbData) |cb| cb.* = 0;
            return 2; // ERROR_FILE_NOT_FOUND
        }
        reg_type = REG_SZ;
        bytes = dir;
    } else {
        std.debug.print("[WINS:Advapi32] RegQueryValueExA(\"{s}\") -> ERROR_FILE_NOT_FOUND\n", .{name});
        if (lpcbData) |cb| cb.* = 0;
        return 2; // ERROR_FILE_NOT_FOUND
    }

    if (lpType) |t| t.* = reg_type;
    if (lpcbData) |cb| cb.* = @intCast(bytes.len);
    if (lpData) |d| {
        if (lpcbData) |cb| {
            if (cb.* >= bytes.len) {
                @memcpy(d[0..bytes.len], bytes);
                return ERROR_SUCCESS;
            }
        }
    }
    return ERROR_MORE_DATA;
}

fn RegSetValueExA(hKey: usize, lpValueName: ?[*:0]const u8, Reserved: u32, dwType: u32, lpData: ?[*]const u8, cbData: u32) callconv(W) i32 {
    _ = hKey; _ = lpValueName; _ = Reserved; _ = dwType; _ = lpData; _ = cbData;
    return 0; // ERROR_SUCCESS
}

fn RegCloseKey(hKey: usize) callconv(W) i32 {
    _ = hKey;
    return 0;
}

fn GetUserNameA(lpBuffer: ?[*]u8, pcbBuffer: ?*u32) callconv(W) i32 {
    const user = "Courier";
    if (pcbBuffer) |cb| {
        if (lpBuffer) |buf| {
            const len: u32 = @min(cb.* - 1, @as(u32, @intCast(user.len)));
            @memcpy(buf[0..len], user[0..len]);
            buf[len] = 0;
            cb.* = len + 1;
            return 1;
        }
    }
    return 0;
}

fn GetStockObject(i: i32) callconv(W) usize {
    _ = i;
    return 0x1001;
}

fn timeGetTime() callconv(W) u32 {
    return GetTickCount();
}

// ============================================================================
// DirectInput8 — minimal real object (this machine reports no input devices)
// ============================================================================

const DI_OK: i32 = 0;
const DIERR_GENERIC: i32 = @bitCast(@as(u32, 0x80004005)); // E_FAIL

/// IDirectInput8W vtable: IUnknown first, then the eight methods in
/// declaration order. The guest calls by offset with stdcall stack cleanup,
/// so both the order and the arity must match the real interface.
const WinsDirectInput8Vtbl = struct {
    QueryInterface: *const fn (*anyopaque, ?*const anyopaque, ?*?*anyopaque) callconv(W) i32,
    AddRef: *const fn (*anyopaque) callconv(W) u32,
    Release: *const fn (*anyopaque) callconv(W) u32,
    CreateDevice: *const fn (*anyopaque, ?*const anyopaque, ?*?*anyopaque, ?*anyopaque) callconv(W) i32,
    EnumDevices: *const fn (*anyopaque, u32, ?*anyopaque, ?*anyopaque, u32) callconv(W) i32,
    GetDeviceInfo: *const fn (*anyopaque, ?*const anyopaque, ?*anyopaque) callconv(W) i32,
    RunControlPanel: *const fn (*anyopaque, usize, u32) callconv(W) i32,
    Initialize: *const fn (*anyopaque, usize, u32) callconv(W) i32,
    FindDevice: *const fn (*anyopaque, ?*const anyopaque, ?[*:0]const u8, ?*anyopaque) callconv(W) i32,
    EnumDevicesBySemantics: *const fn (*anyopaque, ?[*:0]const u8, ?*anyopaque, ?*anyopaque, ?*anyopaque, u32) callconv(W) i32,
};

const WinsDirectInput8 = struct {
    vtbl: *const WinsDirectInput8Vtbl,
    ref_count: u32,
    /// Created for IID_IDirectInput8W: device info strings are UTF-16.
    wide: bool = false,
};

fn di8_QueryInterface(this: *anyopaque, riid: ?*const anyopaque, ppv: ?*?*anyopaque) callconv(W) i32 {
    _ = riid;
    const out = ppv orelse return @bitCast(@as(u32, 0x80070057)); // E_INVALIDARG
    const self: *WinsDirectInput8 = @ptrCast(@alignCast(this));
    _ = self.vtbl.AddRef(self);
    out.* = this;
    return DI_OK;
}
fn di8_AddRef(this: *anyopaque) callconv(W) u32 {
    const self: *WinsDirectInput8 = @ptrCast(@alignCast(this));
    self.ref_count += 1;
    return self.ref_count;
}
fn di8_Release(this: *anyopaque) callconv(W) u32 {
    const self: *WinsDirectInput8 = @ptrCast(@alignCast(this));
    self.ref_count -= 1;
    return self.ref_count;
}
/// The system keyboard and mouse are real devices fed by the game window
/// (wins_dinput.zig); anything else does not exist on this adapter.
fn di8_CreateDevice(this: *anyopaque, guid: ?*const anyopaque, ppv: ?*?*anyopaque, outer: ?*anyopaque) callconv(W) i32 {
    _ = outer;
    const self: *WinsDirectInput8 = @ptrCast(@alignCast(this));
    const out = ppv orelse return @bitCast(@as(u32, 0x80004003)); // E_POINTER
    return dinput_mod.createDevice(@ptrCast(guid), self.wide, out);
}
fn di8_EnumDevices(this: *anyopaque, dev_type: u32, cb: ?*anyopaque, ref: ?*anyopaque, flags: u32) callconv(W) i32 {
    _ = this; _ = dev_type; _ = cb; _ = ref; _ = flags;
    return DI_OK; // zero devices: the callback is never invoked
}
fn di8_GetDeviceInfo(this: *anyopaque, guid: ?*const anyopaque, inst: ?*anyopaque) callconv(W) i32 {
    _ = this; _ = guid; _ = inst;
    return DIERR_GENERIC;
}
fn di8_RunControlPanel(this: *anyopaque, hwnd: usize, flags: u32) callconv(W) i32 {
    _ = this; _ = hwnd; _ = flags;
    return DIERR_GENERIC;
}
fn di8_Initialize(this: *anyopaque, hinst: usize, version: u32) callconv(W) i32 {
    _ = this; _ = hinst; _ = version;
    return DI_OK;
}
fn di8_FindDevice(this: *anyopaque, guid: ?*const anyopaque, name: ?[*:0]const u8, out: ?*anyopaque) callconv(W) i32 {
    _ = this; _ = guid; _ = name; _ = out;
    return DIERR_GENERIC;
}
fn di8_EnumDevicesBySemantics(this: *anyopaque, name: ?[*:0]const u8, fmt: ?*anyopaque, cb: ?*anyopaque, ref: ?*anyopaque, flags: u32) callconv(W) i32 {
    _ = this; _ = name; _ = fmt; _ = cb; _ = ref; _ = flags;
    return DI_OK; // zero devices
}

const g_di8_vtbl = WinsDirectInput8Vtbl{
    .QueryInterface = &di8_QueryInterface,
    .AddRef = &di8_AddRef,
    .Release = &di8_Release,
    .CreateDevice = &di8_CreateDevice,
    .EnumDevices = &di8_EnumDevices,
    .GetDeviceInfo = &di8_GetDeviceInfo,
    .RunControlPanel = &di8_RunControlPanel,
    .Initialize = &di8_Initialize,
    .FindDevice = &di8_FindDevice,
    .EnumDevicesBySemantics = &di8_EnumDevicesBySemantics,
};

fn DirectInput8Create(hinst: usize, dwVersion: u32, riidltf: ?*anyopaque, ppvOut: ?*?*anyopaque, punkOuter: ?*anyopaque) callconv(W) i32 {
    _ = hinst; _ = punkOuter;
    const out = ppvOut orelse return @bitCast(@as(u32, 0x80070057)); // E_INVALIDARG
    const obj = std.heap.page_allocator.create(WinsDirectInput8) catch return @bitCast(@as(u32, 0x8007000E)); // E_OUTOFMEMORY
    // IID_IDirectInput8W is {BF798031-483A-4DA2-AA99-5D64ED369700}; A ends its Data1 in 30.
    const wide = if (riidltf) |r| (@as(*align(1) const u32, @ptrCast(r)).* == 0xBF798031) else false;
    obj.* = .{ .vtbl = &g_di8_vtbl, .ref_count = 1, .wide = wide };
    std.debug.print("[WINS:DInput] DirectInput8Create(version 0x{x}, {s})\n", .{ dwVersion, if (wide) "W" else "A" });
    out.* = @ptrCast(obj);
    return DI_OK;
}

fn InitCommonControlsEx(picce: ?*anyopaque) callconv(W) i32 {
    _ = picce;
    return 1;
}

fn IsProcessorFeaturePresent(ProcessorFeature: u32) callconv(W) i32 {
    return switch (ProcessorFeature) {
        0 => 0, // PF_FLOATING_POINT_PRECISION_ERRATA
        1 => 0, // PF_FLOATING_POINT_EMULATED
        2 => 1, // PF_COMPARE_EXCHANGE_DOUBLE (cmpxchg8b)
        3 => 1, // PF_MMX_INSTRUCTIONS_AVAILABLE
        6 => 1, // PF_XMMI_INSTRUCTIONS_AVAILABLE (SSE)
        7 => 0, // PF_3DNOW_INSTRUCTIONS_AVAILABLE
        8 => 1, // PF_RDTSC_INSTRUCTION_AVAILABLE
        9 => 1, // PF_PAE_ENABLED
        10 => 1, // PF_XMMI64_INSTRUCTIONS_AVAILABLE (SSE2)
        11 => 1, // PF_SSE_DAZ_MODE_AVAILABLE
        12 => 1, // PF_NX_ENABLED
        13 => 1, // PF_SSE3_INSTRUCTIONS_AVAILABLE
        14 => 0, // PF_COMPARE_EXCHANGE128
        17 => 1, // PF_XSAVE_ENABLED
        else => 0,
    };
}

// Global Diagnostic Fallback for Unimplemented APIs
fn unhandledApiStub() callconv(W) usize {
    return 0;
}

// ============================================================================
// Symbol Dispatchers (resolveImport & GetProcAddress)
// ============================================================================

fn resolveImport(dll: []const u8, name: []const u8) ?*const anyopaque {
    if (std.ascii.eqlIgnoreCase(dll, "kernel32.dll") or std.ascii.eqlIgnoreCase(dll, "kernel32")) {
        if (std.mem.eql(u8, name, "GetLastError")) return @ptrCast(&GetLastError);
        if (std.mem.eql(u8, name, "SetLastError")) return @ptrCast(&SetLastError);
        if (std.mem.eql(u8, name, "IsProcessorFeaturePresent")) return @ptrCast(&IsProcessorFeaturePresent);
        if (std.mem.eql(u8, name, "EncodePointer")) return @ptrCast(&EncodePointer);
        if (std.mem.eql(u8, name, "DecodePointer")) return @ptrCast(&DecodePointer);
        if (std.mem.eql(u8, name, "FlsAlloc")) return @ptrCast(&FlsAlloc);
        if (std.mem.eql(u8, name, "FlsGetValue")) return @ptrCast(&FlsGetValue);
        if (std.mem.eql(u8, name, "FlsSetValue")) return @ptrCast(&FlsSetValue);
        if (std.mem.eql(u8, name, "FlsFree")) return @ptrCast(&FlsFree);
        if (std.mem.eql(u8, name, "OpenProcess")) return @ptrCast(&OpenProcess);
        if (std.mem.eql(u8, name, "GetExitCodeProcess")) return @ptrCast(&GetExitCodeProcess);
        if (std.mem.eql(u8, name, "GetFileAttributesW")) return @ptrCast(&GetFileAttributesW);
        if (std.mem.eql(u8, name, "LoadLibraryExW")) return @ptrCast(&LoadLibraryExW);
        if (std.mem.eql(u8, name, "QueryDosDeviceA")) return @ptrCast(&QueryDosDeviceA);
        if (std.mem.eql(u8, name, "GetLogicalDriveStringsA")) return @ptrCast(&GetLogicalDriveStringsA);
        if (std.mem.eql(u8, name, "GetCurrentProcess")) return @ptrCast(&GetCurrentProcess);
        if (std.mem.eql(u8, name, "GetCurrentThread")) return @ptrCast(&GetCurrentThread);
        if (std.mem.eql(u8, name, "GetCurrentProcessId")) return @ptrCast(&GetCurrentProcessId);
        if (std.mem.eql(u8, name, "GetCurrentThreadId")) return @ptrCast(&GetCurrentThreadId);
        if (std.mem.eql(u8, name, "ExitProcess")) return @ptrCast(&ExitProcess);
        if (std.mem.eql(u8, name, "TerminateProcess")) return @ptrCast(&TerminateProcess);
        if (std.mem.eql(u8, name, "RaiseException")) return @ptrCast(&RaiseException);
        if (std.mem.eql(u8, name, "GetStdHandle")) return @ptrCast(&GetStdHandle);
        if (std.mem.eql(u8, name, "SetStdHandle")) return @ptrCast(&SetStdHandle);
        if (std.mem.eql(u8, name, "SetHandleCount")) return @ptrCast(&SetHandleCount);
        if (std.mem.eql(u8, name, "WriteFile")) return @ptrCast(&WriteFile);
        if (std.mem.eql(u8, name, "ReadFile")) return @ptrCast(&ReadFile);
        if (std.mem.eql(u8, name, "CreateFileA")) return @ptrCast(&CreateFileA);
        if (std.mem.eql(u8, name, "CreateFileW")) return @ptrCast(&CreateFileW);
        if (std.mem.eql(u8, name, "CloseHandle")) return @ptrCast(&CloseHandle);
        if (std.mem.eql(u8, name, "GetFileSize")) return @ptrCast(&GetFileSize);
        if (std.mem.eql(u8, name, "GetFileSizeEx")) return @ptrCast(&GetFileSizeEx);
        if (std.mem.eql(u8, name, "SetFilePointer")) return @ptrCast(&SetFilePointer);
        if (std.mem.eql(u8, name, "SetFilePointerEx")) return @ptrCast(&SetFilePointerEx);
        if (std.mem.eql(u8, name, "SetEndOfFile")) return @ptrCast(&SetEndOfFile);
        if (std.mem.eql(u8, name, "FlushFileBuffers")) return @ptrCast(&FlushFileBuffers);
        if (std.mem.eql(u8, name, "GetFileAttributesA")) return @ptrCast(&GetFileAttributesA);
        if (std.mem.eql(u8, name, "DeleteFileA")) return @ptrCast(&DeleteFileA);
        if (std.mem.eql(u8, name, "MoveFileA")) return @ptrCast(&MoveFileA);
        if (std.mem.eql(u8, name, "CopyFileA")) return @ptrCast(&CopyFileA);
        if (std.mem.eql(u8, name, "CreateDirectoryA")) return @ptrCast(&CreateDirectoryA);
        if (std.mem.eql(u8, name, "GetCurrentDirectoryA")) return @ptrCast(&GetCurrentDirectoryA);
        if (std.mem.eql(u8, name, "GetFullPathNameA")) return @ptrCast(&GetFullPathNameA);
        if (std.mem.eql(u8, name, "GetDriveTypeA")) return @ptrCast(&GetDriveTypeA);
        if (std.mem.eql(u8, name, "FindFirstFileA")) return @ptrCast(&FindFirstFileA);
        if (std.mem.eql(u8, name, "FindNextFileA")) return @ptrCast(&FindNextFileA);
        if (std.mem.eql(u8, name, "FindClose")) return @ptrCast(&FindClose);
        if (std.mem.eql(u8, name, "GetCommandLineA")) return @ptrCast(&GetCommandLineA);
        if (std.mem.eql(u8, name, "GetCommandLineW")) return @ptrCast(&GetCommandLineW);
        if (std.mem.eql(u8, name, "GetModuleHandleA")) return @ptrCast(&GetModuleHandleA);
        if (std.mem.eql(u8, name, "GetModuleHandleW")) return @ptrCast(&GetModuleHandleW);
        if (std.mem.eql(u8, name, "GetModuleFileNameA")) return @ptrCast(&GetModuleFileNameA);
        if (std.mem.eql(u8, name, "LoadLibraryA")) return @ptrCast(&LoadLibraryA);
        if (std.mem.eql(u8, name, "LoadLibraryExA")) return @ptrCast(&LoadLibraryExA);
        if (std.mem.eql(u8, name, "FreeLibrary")) return @ptrCast(&FreeLibrary);
        if (std.mem.eql(u8, name, "GetProcAddress")) return @ptrCast(&GetProcAddress);
        if (std.mem.eql(u8, name, "VirtualAlloc")) return @ptrCast(&VirtualAlloc);
        if (std.mem.eql(u8, name, "VirtualFree")) return @ptrCast(&VirtualFree);
        if (std.mem.eql(u8, name, "VirtualProtect")) return @ptrCast(&VirtualProtect);
        if (std.mem.eql(u8, name, "VirtualQuery")) return @ptrCast(&VirtualQuery);
        if (std.mem.eql(u8, name, "GetProcessHeap")) return @ptrCast(&GetProcessHeap);
        if (std.mem.eql(u8, name, "HeapAlloc")) return @ptrCast(&HeapAlloc);
        if (std.mem.eql(u8, name, "HeapFree")) return @ptrCast(&HeapFree);
        if (std.mem.eql(u8, name, "HeapReAlloc")) return @ptrCast(&HeapReAlloc);
        if (std.mem.eql(u8, name, "HeapSize")) return @ptrCast(&HeapSize);
        if (std.mem.eql(u8, name, "HeapCreate")) return @ptrCast(&HeapCreate);
        if (std.mem.eql(u8, name, "HeapDestroy")) return @ptrCast(&HeapDestroy);
        if (std.mem.eql(u8, name, "IsBadReadPtr")) return @ptrCast(&IsBadReadPtr);
        if (std.mem.eql(u8, name, "IsBadWritePtr")) return @ptrCast(&IsBadWritePtr);
        if (std.mem.eql(u8, name, "IsBadCodePtr")) return @ptrCast(&IsBadCodePtr);
        if (std.mem.eql(u8, name, "OpenFileMappingA")) return @ptrCast(&OpenFileMappingA);
        if (std.mem.eql(u8, name, "CreateFileMappingA")) return @ptrCast(&CreateFileMappingA);
        if (std.mem.eql(u8, name, "MapViewOfFile")) return @ptrCast(&MapViewOfFile);
        if (std.mem.eql(u8, name, "UnmapViewOfFile")) return @ptrCast(&UnmapViewOfFile);
        if (std.mem.eql(u8, name, "GetStartupInfoA")) return @ptrCast(&GetStartupInfoA);
        if (std.mem.eql(u8, name, "GetStartupInfoW")) return @ptrCast(&GetStartupInfoW);
        if (std.mem.eql(u8, name, "SetUnhandledExceptionFilter")) return @ptrCast(&SetUnhandledExceptionFilter);
        if (std.mem.eql(u8, name, "UnhandledExceptionFilter")) return @ptrCast(&UnhandledExceptionFilter);
        if (std.mem.eql(u8, name, "RtlUnwind")) return @ptrCast(&RtlUnwind);
        if (std.mem.eql(u8, name, "QueryPerformanceCounter")) return @ptrCast(&QueryPerformanceCounter);
        if (std.mem.eql(u8, name, "QueryPerformanceFrequency")) return @ptrCast(&QueryPerformanceFrequency);
        if (std.mem.eql(u8, name, "GetTickCount")) return @ptrCast(&GetTickCount);
        if (std.mem.eql(u8, name, "Sleep")) return @ptrCast(&Sleep);
        if (std.mem.eql(u8, name, "TlsAlloc")) return @ptrCast(&TlsAlloc);
        if (std.mem.eql(u8, name, "TlsGetValue")) return @ptrCast(&TlsGetValue);
        if (std.mem.eql(u8, name, "TlsSetValue")) return @ptrCast(&TlsSetValue);
        if (std.mem.eql(u8, name, "TlsFree")) return @ptrCast(&TlsFree);
        if (std.mem.eql(u8, name, "CreateThread")) return @ptrCast(&CreateThread);
        if (std.mem.eql(u8, name, "ExitThread")) return @ptrCast(&ExitThread);
        if (std.mem.eql(u8, name, "GetExitCodeThread")) return @ptrCast(&GetExitCodeThread);
        if (std.mem.eql(u8, name, "ResumeThread")) return @ptrCast(&ResumeThread);
        if (std.mem.eql(u8, name, "SuspendThread")) return @ptrCast(&SuspendThread);
        if (std.mem.eql(u8, name, "SetThreadPriority")) return @ptrCast(&SetThreadPriority);
        if (std.mem.eql(u8, name, "SetThreadIdealProcessor")) return @ptrCast(&SetThreadIdealProcessor);
        if (std.mem.eql(u8, name, "InitializeCriticalSection")) return @ptrCast(&InitializeCriticalSection);
        if (std.mem.eql(u8, name, "InitializeCriticalSectionAndSpinCount")) return @ptrCast(&InitializeCriticalSectionAndSpinCount);
        if (std.mem.eql(u8, name, "EnterCriticalSection")) return @ptrCast(&EnterCriticalSection);
        if (std.mem.eql(u8, name, "TryEnterCriticalSection")) return @ptrCast(&TryEnterCriticalSection);
        if (std.mem.eql(u8, name, "LeaveCriticalSection")) return @ptrCast(&LeaveCriticalSection);
        if (std.mem.eql(u8, name, "DeleteCriticalSection")) return @ptrCast(&DeleteCriticalSection);
        if (std.mem.eql(u8, name, "CreateEventA")) return @ptrCast(&CreateEventA);
        if (std.mem.eql(u8, name, "OpenEventA")) return @ptrCast(&OpenEventA);
        if (std.mem.eql(u8, name, "SetEvent")) return @ptrCast(&SetEvent);
        if (std.mem.eql(u8, name, "PulseEvent")) return @ptrCast(&PulseEvent);
        if (std.mem.eql(u8, name, "SwitchToThread")) return @ptrCast(&SwitchToThread);
        if (std.mem.eql(u8, name, "ResetEvent")) return @ptrCast(&ResetEvent);
        if (std.mem.eql(u8, name, "CreateMutexA")) return @ptrCast(&CreateMutexA);
        if (std.mem.eql(u8, name, "ReleaseMutex")) return @ptrCast(&ReleaseMutex);
        if (std.mem.eql(u8, name, "CreateSemaphoreA")) return @ptrCast(&CreateSemaphoreA);
        if (std.mem.eql(u8, name, "ReleaseSemaphore")) return @ptrCast(&ReleaseSemaphore);
        if (std.mem.eql(u8, name, "WaitForSingleObject")) return @ptrCast(&WaitForSingleObject);
        if (std.mem.eql(u8, name, "WaitForMultipleObjects")) return @ptrCast(&WaitForMultipleObjects);
        if (std.mem.eql(u8, name, "InterlockedIncrement")) return @ptrCast(&InterlockedIncrement);
        if (std.mem.eql(u8, name, "InterlockedDecrement")) return @ptrCast(&InterlockedDecrement);
        if (std.mem.eql(u8, name, "InterlockedExchange")) return @ptrCast(&InterlockedExchange);
        if (std.mem.eql(u8, name, "InterlockedExchangeAdd")) return @ptrCast(&InterlockedExchangeAdd);
        if (std.mem.eql(u8, name, "InterlockedCompareExchange")) return @ptrCast(&InterlockedCompareExchange);
        if (std.mem.eql(u8, name, "GetSystemTimeAsFileTime")) return @ptrCast(&GetSystemTimeAsFileTime);
        if (std.mem.eql(u8, name, "GetSystemTime")) return @ptrCast(&GetSystemTime);
        if (std.mem.eql(u8, name, "GetLocalTime")) return @ptrCast(&GetLocalTime);
        if (std.mem.eql(u8, name, "SystemTimeToTzSpecificLocalTime")) return @ptrCast(&SystemTimeToTzSpecificLocalTime);
        if (std.mem.eql(u8, name, "FileTimeToSystemTime")) return @ptrCast(&FileTimeToSystemTime);
        if (std.mem.eql(u8, name, "FileTimeToLocalFileTime")) return @ptrCast(&FileTimeToLocalFileTime);
        if (std.mem.eql(u8, name, "CompareFileTime")) return @ptrCast(&CompareFileTime);
        if (std.mem.eql(u8, name, "GetVersion")) return @ptrCast(&GetVersion);
        if (std.mem.eql(u8, name, "GetVersionExA")) return @ptrCast(&GetVersionExA);
        if (std.mem.eql(u8, name, "GetSystemInfo")) return @ptrCast(&GetSystemInfo);
        if (std.mem.eql(u8, name, "GlobalMemoryStatus")) return @ptrCast(&GlobalMemoryStatus);
        if (std.mem.eql(u8, name, "GlobalMemoryStatusEx")) return @ptrCast(&GlobalMemoryStatusEx);
        if (std.mem.eql(u8, name, "IsDebuggerPresent")) return @ptrCast(&IsDebuggerPresent);
        if (std.mem.eql(u8, name, "OutputDebugStringA")) return @ptrCast(&OutputDebugStringA);
        if (std.mem.eql(u8, name, "OutputDebugStringW")) return @ptrCast(&OutputDebugStringW);
        if (std.mem.eql(u8, name, "GetPrivateProfileStringA")) return @ptrCast(&GetPrivateProfileStringA);
        if (std.mem.eql(u8, name, "GetPrivateProfileIntA")) return @ptrCast(&GetPrivateProfileIntA);
        if (std.mem.eql(u8, name, "WritePrivateProfileStringA")) return @ptrCast(&WritePrivateProfileStringA);
        if (std.mem.eql(u8, name, "GetFileType")) return @ptrCast(&GetFileType);
        if (std.mem.eql(u8, name, "GetConsoleMode")) return @ptrCast(&GetConsoleMode);
        if (std.mem.eql(u8, name, "GetConsoleCP")) return @ptrCast(&GetConsoleCP);
        if (std.mem.eql(u8, name, "GetConsoleOutputCP")) return @ptrCast(&GetConsoleOutputCP);
        if (std.mem.eql(u8, name, "WriteConsoleA")) return @ptrCast(&WriteConsoleA);
        if (std.mem.eql(u8, name, "WriteConsoleW")) return @ptrCast(&WriteConsoleW);
        if (std.mem.eql(u8, name, "MultiByteToWideChar")) return @ptrCast(&MultiByteToWideChar);
        if (std.mem.eql(u8, name, "WideCharToMultiByte")) return @ptrCast(&WideCharToMultiByte);
        if (std.mem.eql(u8, name, "GetACP")) return @ptrCast(&GetACP);
        if (std.mem.eql(u8, name, "GetOEMCP")) return @ptrCast(&GetOEMCP);
        if (std.mem.eql(u8, name, "GetCPInfo")) return @ptrCast(&GetCPInfo);
        if (std.mem.eql(u8, name, "GetStringTypeA")) return @ptrCast(&GetStringTypeA);
        if (std.mem.eql(u8, name, "GetStringTypeW")) return @ptrCast(&GetStringTypeW);
        if (std.mem.eql(u8, name, "LCMapStringA")) return @ptrCast(&LCMapStringA);
        if (std.mem.eql(u8, name, "LCMapStringW")) return @ptrCast(&LCMapStringW);
        if (std.mem.eql(u8, name, "CompareStringA")) return @ptrCast(&CompareStringA);
        if (std.mem.eql(u8, name, "CompareStringW")) return @ptrCast(&CompareStringW);
        if (std.mem.eql(u8, name, "GetUserDefaultLCID")) return @ptrCast(&GetUserDefaultLCID);
        if (std.mem.eql(u8, name, "GetLocaleInfoA")) return @ptrCast(&GetLocaleInfoA);
        if (std.mem.eql(u8, name, "GetLocaleInfoW")) return @ptrCast(&GetLocaleInfoW);
        if (std.mem.eql(u8, name, "IsValidCodePage")) return @ptrCast(&IsValidCodePage);
        if (std.mem.eql(u8, name, "IsValidLocale")) return @ptrCast(&IsValidLocale);
        if (std.mem.eql(u8, name, "EnumSystemLocalesA")) return @ptrCast(&EnumSystemLocalesA);
        if (std.mem.eql(u8, name, "GetTimeZoneInformation")) return @ptrCast(&GetTimeZoneInformation);
        if (std.mem.eql(u8, name, "SetEnvironmentVariableA")) return @ptrCast(&SetEnvironmentVariableA);
        if (std.mem.eql(u8, name, "GetEnvironmentStrings")) return @ptrCast(&GetEnvironmentStrings);
        if (std.mem.eql(u8, name, "FreeEnvironmentStringsA")) return @ptrCast(&FreeEnvironmentStringsA);
        if (std.mem.eql(u8, name, "GetEnvironmentStringsW")) return @ptrCast(&GetEnvironmentStringsW);
        if (std.mem.eql(u8, name, "FreeEnvironmentStringsW")) return @ptrCast(&FreeEnvironmentStringsW);
        if (std.mem.eql(u8, name, "FormatMessageA")) return @ptrCast(&FormatMessageA);
        if (std.mem.eql(u8, name, "LocalFree")) return @ptrCast(&LocalFree);
        if (std.mem.eql(u8, name, "DebugBreak")) return @ptrCast(&DebugBreak);
        if (std.mem.eql(u8, name, "lstrcpyA")) return @ptrCast(&lstrcpyA);
        if (std.mem.eql(u8, name, "lstrcatA")) return @ptrCast(&lstrcatA);
        if (std.mem.eql(u8, name, "GetSystemDirectoryA")) return @ptrCast(&GetSystemDirectoryA);
        if (std.mem.eql(u8, name, "GetWindowsDirectoryA")) return @ptrCast(&GetWindowsDirectoryA);
        if (std.mem.eql(u8, name, "CreateToolhelp32Snapshot")) return @ptrCast(&CreateToolhelp32Snapshot);
        if (std.mem.eql(u8, name, "Process32First")) return @ptrCast(&Process32First);
        if (std.mem.eql(u8, name, "Process32Next")) return @ptrCast(&Process32Next);
        if (std.mem.eql(u8, name, "Module32First")) return @ptrCast(&Module32First);
        if (std.mem.eql(u8, name, "Module32Next")) return @ptrCast(&Module32Next);
        if (std.mem.eql(u8, name, "Thread32First")) return @ptrCast(&Thread32First);
        if (std.mem.eql(u8, name, "Thread32Next")) return @ptrCast(&Thread32Next);
        if (std.mem.eql(u8, name, "Heap32First")) return @ptrCast(&Heap32First);
        if (std.mem.eql(u8, name, "VirtualQueryEx")) return @ptrCast(&VirtualQueryEx);
        if (std.mem.eql(u8, name, "ReadProcessMemory")) return @ptrCast(&ReadProcessMemory);
        if (std.mem.eql(u8, name, "FlushInstructionCache")) return @ptrCast(&FlushInstructionCache);
        if (std.mem.eql(u8, name, "GetThreadContext")) return @ptrCast(&GetThreadContext);
        if (std.mem.eql(u8, name, "GetModuleHandleExA")) return @ptrCast(&GetModuleHandleExA);
        if (std.mem.eql(u8, name, "OpenThread")) return @ptrCast(&OpenThread);
        if (std.mem.eql(u8, name, "AddVectoredExceptionHandler")) return @ptrCast(&AddVectoredExceptionHandler);
    } else if (std.ascii.eqlIgnoreCase(dll, "user32.dll") or std.ascii.eqlIgnoreCase(dll, "user32")) {
        if (user32_mod.lookup(name)) |addr| return @ptrFromInt(addr);
        if (std.mem.eql(u8, name, "GetSystemMetrics")) return @ptrCast(&GetSystemMetrics);
        if (std.mem.eql(u8, name, "LoadIconA")) return @ptrCast(&LoadIconA);
        if (std.mem.eql(u8, name, "LoadCursorA")) return @ptrCast(&LoadCursorA);
        if (std.mem.eql(u8, name, "ShowCursor")) return @ptrCast(&ShowCursor);
        if (std.mem.eql(u8, name, "GetDoubleClickTime")) return @ptrCast(&GetDoubleClickTime);
        if (std.mem.eql(u8, name, "SwapMouseButton")) return @ptrCast(&SwapMouseButton);
        if (std.mem.eql(u8, name, "UnhookWindowsHookEx")) return @ptrCast(&UnhookWindowsHookEx);
        if (std.mem.eql(u8, name, "SetWindowsHookExA")) return @ptrCast(&SetWindowsHookExA);
        if (std.mem.eql(u8, name, "CallNextHookEx")) return @ptrCast(&CallNextHookEx);
        if (std.mem.eql(u8, name, "SendInput")) return @ptrCast(&SendInput);
        if (std.mem.eql(u8, name, "EnumDisplayDevicesA")) return @ptrCast(&EnumDisplayDevicesA);
        if (std.mem.eql(u8, name, "MessageBoxA")) return @ptrCast(&MessageBoxA);
        if (std.mem.eql(u8, name, "GetAsyncKeyState")) return @ptrCast(&GetAsyncKeyState);
        if (std.mem.eql(u8, name, "GetKeyState")) return @ptrCast(&user32_mod.GetKeyState);
    } else if (std.ascii.eqlIgnoreCase(dll, "steam_api.dll") or std.ascii.eqlIgnoreCase(dll, "steam_api")) {
        if (std.mem.eql(u8, name, "SteamAPI_Init")) return @ptrCast(&SteamAPI_Init);
        if (std.mem.eql(u8, name, "SteamAPI_IsSteamRunning")) return @ptrCast(&SteamAPI_IsSteamRunning);
        if (std.mem.eql(u8, name, "SteamAPI_RegisterCallback")) return @ptrCast(&SteamAPI_RegisterCallback);
        if (std.mem.eql(u8, name, "SteamAPI_UnregisterCallback")) return @ptrCast(&SteamAPI_UnregisterCallback);
        if (std.mem.eql(u8, name, "SteamAPI_RunCallbacks")) return @ptrCast(&SteamAPI_RunCallbacks);
        if (std.mem.eql(u8, name, "SteamAPI_Shutdown")) return @ptrCast(&SteamAPI_Shutdown);
        if (std.mem.eql(u8, name, "SteamApps")) return @ptrCast(&SteamApps);
        if (std.mem.eql(u8, name, "SteamFriends")) return @ptrCast(&SteamFriends);
        if (std.mem.eql(u8, name, "SteamUser")) return @ptrCast(&SteamUser);
        if (std.mem.eql(u8, name, "SteamUserStats")) return @ptrCast(&SteamUserStats);
        if (std.mem.eql(u8, name, "SteamUtils")) return @ptrCast(&SteamUtils);
    } else if (std.ascii.eqlIgnoreCase(dll, "steamclient.dll") or std.ascii.eqlIgnoreCase(dll, "steamclient")) {
        if (std.mem.eql(u8, name, "CreateInterface")) return @ptrCast(&steamclient_CreateInterface);
    } else if (std.ascii.eqlIgnoreCase(dll, "binkw32.dll") or std.ascii.eqlIgnoreCase(dll, "binkw32")) {
        if (std.mem.eql(u8, name, "_BinkOpen@8")) return @ptrCast(&BinkOpen);
        if (std.mem.eql(u8, name, "_BinkClose@4")) return @ptrCast(&BinkClose);
        if (std.mem.eql(u8, name, "_BinkDoFrame@4")) return @ptrCast(&BinkDoFrame);
        if (std.mem.eql(u8, name, "_BinkNextFrame@4")) return @ptrCast(&BinkNextFrame);
        if (std.mem.eql(u8, name, "_BinkWait@4")) return @ptrCast(&BinkWait);
        if (std.mem.eql(u8, name, "_BinkPause@8")) return @ptrCast(&BinkPause);
        if (std.mem.eql(u8, name, "_BinkCopyToBufferRect@44")) return @ptrCast(&BinkCopyToBufferRect);
        if (std.mem.eql(u8, name, "_BinkOpenDirectSound@4")) return @ptrCast(&BinkOpenDirectSound);
        if (std.mem.eql(u8, name, "_BinkSetSoundSystem@8")) return @ptrCast(&BinkSetSoundSystem);
    } else if (std.ascii.eqlIgnoreCase(dll, "d3d9.dll") or std.ascii.eqlIgnoreCase(dll, "d3d9")) {
        if (std.mem.eql(u8, name, "Direct3DCreate9")) return @ptrCast(&d3d9.Direct3DCreate9);
        if (std.mem.eql(u8, name, "D3DPERF_SetOptions")) return @ptrCast(&d3d9.D3DPERF_SetOptions);
        if (std.mem.eql(u8, name, "D3DPERF_BeginEvent")) return @ptrCast(&d3d9.D3DPERF_BeginEvent);
        if (std.mem.eql(u8, name, "D3DPERF_EndEvent")) return @ptrCast(&d3d9.D3DPERF_EndEvent);
    } else if (std.ascii.eqlIgnoreCase(dll, "d3dx9_38.dll") or std.ascii.eqlIgnoreCase(dll, "d3dx9_38")) {
        if (std.mem.eql(u8, name, "D3DXMatrixMultiply")) return @ptrCast(&d3d9.D3DXMatrixMultiply);
        if (std.mem.eql(u8, name, "D3DXMatrixTranspose")) return @ptrCast(&d3d9.D3DXMatrixTranspose);
        if (std.mem.eql(u8, name, "D3DXMatrixMultiplyTranspose")) return @ptrCast(&d3d9.D3DXMatrixMultiplyTranspose);
        if (std.mem.eql(u8, name, "D3DXMatrixInverse")) return @ptrCast(&d3d9.D3DXMatrixInverse);
        if (std.mem.eql(u8, name, "D3DXMatrixRotationYawPitchRoll")) return @ptrCast(&d3d9.D3DXMatrixRotationYawPitchRoll);
        if (std.mem.eql(u8, name, "D3DXVec3Normalize")) return @ptrCast(&d3d9.D3DXVec3Normalize);
        if (std.mem.eql(u8, name, "D3DXVec3TransformCoord")) return @ptrCast(&d3d9.D3DXVec3TransformCoord);
        if (std.mem.eql(u8, name, "D3DXVec3TransformNormal")) return @ptrCast(&d3d9.D3DXVec3TransformNormal);
        if (std.mem.eql(u8, name, "D3DXVec4Transform")) return @ptrCast(&d3d9.D3DXVec4Transform);
        if (std.mem.eql(u8, name, "D3DXPlaneNormalize")) return @ptrCast(&d3d9.D3DXPlaneNormalize);
        if (std.mem.eql(u8, name, "D3DXPlaneTransform")) return @ptrCast(&d3d9.D3DXPlaneTransform);
        if (std.mem.eql(u8, name, "D3DXCreateBuffer")) return @ptrCast(&d3d9.D3DXCreateBuffer);
        if (std.mem.eql(u8, name, "D3DXGetShaderConstantTable")) return @ptrCast(&d3d9.D3DXGetShaderConstantTable);
        if (std.mem.eql(u8, name, "D3DXGetVertexShaderProfile")) return @ptrCast(&d3d9.D3DXGetVertexShaderProfile);
        if (std.mem.eql(u8, name, "D3DXGetPixelShaderProfile")) return @ptrCast(&d3d9.D3DXGetPixelShaderProfile);
        if (std.mem.eql(u8, name, "D3DXAssembleShader")) return @ptrCast(&d3d9.D3DXAssembleShader);
        if (std.mem.eql(u8, name, "D3DXAssembleShaderFromFileA")) return @ptrCast(&d3d9.D3DXAssembleShaderFromFileA);
        if (std.mem.eql(u8, name, "D3DXCompileShader")) return @ptrCast(&d3d9.D3DXCompileShader);
        if (std.mem.eql(u8, name, "D3DXCompileShaderFromFileA")) return @ptrCast(&d3d9.D3DXCompileShaderFromFileA);
        if (std.mem.eql(u8, name, "D3DXGetImageInfoFromFileInMemory")) return @ptrCast(&d3d9.D3DXGetImageInfoFromFileInMemory);
        if (std.mem.eql(u8, name, "D3DXCreateTextureFromFileInMemory")) return @ptrCast(&d3d9.D3DXCreateTextureFromFileInMemory);
        if (std.mem.eql(u8, name, "D3DXCreateCubeTextureFromFileInMemory")) return @ptrCast(&d3d9.D3DXCreateCubeTextureFromFileInMemory);
        if (std.mem.eql(u8, name, "D3DXCreateVolumeTextureFromFileInMemory")) return @ptrCast(&d3d9.D3DXCreateVolumeTextureFromFileInMemory);
        if (std.mem.eql(u8, name, "D3DXLoadSurfaceFromSurface")) return @ptrCast(&d3d9.D3DXLoadSurfaceFromSurface);
        if (std.mem.eql(u8, name, "D3DXSaveTextureToFileA")) return @ptrCast(&d3d9.D3DXSaveTextureToFileA);
    } else if (std.ascii.eqlIgnoreCase(dll, "advapi32.dll") or std.ascii.eqlIgnoreCase(dll, "advapi32")) {
        if (std.mem.eql(u8, name, "CryptAcquireContextA")) return @ptrCast(&CryptAcquireContextA);
        if (std.mem.eql(u8, name, "CryptReleaseContext")) return @ptrCast(&CryptReleaseContext);
        if (std.mem.eql(u8, name, "CryptGenRandom")) return @ptrCast(&CryptGenRandom);
        if (std.mem.eql(u8, name, "RegOpenKeyExA")) return @ptrCast(&RegOpenKeyExA);
        if (std.mem.eql(u8, name, "RegCreateKeyExA")) return @ptrCast(&RegCreateKeyExA);
        if (std.mem.eql(u8, name, "RegQueryValueExA")) return @ptrCast(&RegQueryValueExA);
        if (std.mem.eql(u8, name, "RegSetValueExA")) return @ptrCast(&RegSetValueExA);
        if (std.mem.eql(u8, name, "RegCloseKey")) return @ptrCast(&RegCloseKey);
        if (std.mem.eql(u8, name, "GetUserNameA")) return @ptrCast(&GetUserNameA);
        if (std.mem.eql(u8, name, "OpenProcessToken")) return @ptrCast(&OpenProcessToken);
        if (std.mem.eql(u8, name, "LookupPrivilegeValueA")) return @ptrCast(&LookupPrivilegeValueA);
        if (std.mem.eql(u8, name, "AdjustTokenPrivileges")) return @ptrCast(&AdjustTokenPrivileges);
    } else if (std.ascii.eqlIgnoreCase(dll, "ole32.dll") or std.ascii.eqlIgnoreCase(dll, "ole32")) {
        if (std.mem.eql(u8, name, "CoInitialize")) return @ptrCast(&CoInitialize);
        if (std.mem.eql(u8, name, "CoInitializeEx")) return @ptrCast(&CoInitializeEx);
        if (std.mem.eql(u8, name, "CoUninitialize")) return @ptrCast(&CoUninitialize);
        if (std.mem.eql(u8, name, "CoFreeUnusedLibraries")) return @ptrCast(&CoFreeUnusedLibraries);
        if (std.mem.eql(u8, name, "CoCreateInstance")) return @ptrCast(&CoCreateInstance);
        if (std.mem.eql(u8, name, "CoTaskMemAlloc")) return @ptrCast(&CoTaskMemAlloc);
        if (std.mem.eql(u8, name, "CoTaskMemFree")) return @ptrCast(&CoTaskMemFree);
    } else if (std.ascii.eqlIgnoreCase(dll, "shell32.dll") or std.ascii.eqlIgnoreCase(dll, "shell32")) {
        if (std.mem.eql(u8, name, "SHGetFolderPathA")) return @ptrCast(&SHGetFolderPathA);
        if (std.mem.eql(u8, name, "ShellExecuteA")) return @ptrCast(&ShellExecuteA);
        if (std.mem.eql(u8, name, "CommandLineToArgvW")) return @ptrCast(&CommandLineToArgvW);
    } else if (std.ascii.eqlIgnoreCase(dll, "gdi32.dll") or std.ascii.eqlIgnoreCase(dll, "gdi32")) {
        if (std.mem.eql(u8, name, "GetStockObject")) return @ptrCast(&GetStockObject);
    } else if (std.ascii.eqlIgnoreCase(dll, "winmm.dll") or std.ascii.eqlIgnoreCase(dll, "winmm")) {
        if (std.mem.eql(u8, name, "timeGetTime")) return @ptrCast(&timeGetTime);
        if (msvcrt_mod.lookupWinmm(name)) |addr| return @ptrFromInt(addr);
    } else if (std.ascii.eqlIgnoreCase(dll, "xinput1_3.dll") or std.ascii.eqlIgnoreCase(dll, "xinput1_2.dll") or
        std.ascii.eqlIgnoreCase(dll, "xinput9_1_0.dll"))
    {
        // FalloutNV imports XINPUT1_3 by ordinal; winrun_ordinals maps
        // ord2/ord3 to XInputGetState/XInputSetState, both implemented in
        // winrun_directx.zig, which is not otherwise reachable from this loader.
        if (msvcrt_mod.lookupXinput(name)) |addr| return @ptrFromInt(addr);
    } else if (std.ascii.eqlIgnoreCase(dll, "dinput8.dll") or std.ascii.eqlIgnoreCase(dll, "dinput8")) {
        if (std.mem.eql(u8, name, "DirectInput8Create")) return @ptrCast(&DirectInput8Create);
    } else if (std.ascii.eqlIgnoreCase(dll, "comctl32.dll") or std.ascii.eqlIgnoreCase(dll, "comctl32")) {
        if (std.mem.eql(u8, name, "InitCommonControlsEx")) return @ptrCast(&InitCommonControlsEx);
        if (extra_dlls_mod.lookupComctl32(name)) |addr| return @ptrFromInt(addr);
    } else if (std.ascii.eqlIgnoreCase(dll, "libvorbisfile.dll") or std.ascii.eqlIgnoreCase(dll, "vorbisfile")) {
        // A bridge to the REAL i386 libvorbisfile, not a decoder written here:
        // both sides are cdecl, which on i386 is the same convention, so the
        // exports forward and the guest's ov_callbacks are called directly.
        // The only thing that had to be got right was the callback struct the
        // guest passes by value; a standalone i386 measurement confirms the real
        // library reads it as laid out and answers with its own error code.
        if (vorbis_mod.lookupVorbisfile(name)) |addr| return @ptrFromInt(addr);
        return null;
    } else if (std.ascii.eqlIgnoreCase(dll, "dsound.dll")) {
        // The real Steam build imports DSOUND ordinal 11, which the ordinal
        // table maps to DirectSoundCreate8; with no implementation the loader
        // refused to run the image. wins_dsound.zig carries the COM object
        // graph (IDirectSound8 + IDirectSoundBuffer8 over memory-backed
        // buffers). No PCM reaches a device yet, and that is stated in the
        // module header rather than implied by a silent success.
        if (dsound_mod.lookupDsound(name)) |addr| return @ptrFromInt(addr);
        std.debug.print("[WINS:dsound] dsound!{s} is not available\n", .{name});
        return null;
    } else if (std.ascii.eqlIgnoreCase(dll, "ntdll.dll") or std.ascii.eqlIgnoreCase(dll, "ntdll")) {
        if (std.mem.eql(u8, name, "NtSetInformationThread")) return @ptrCast(&NtSetInformationThread);
        if (std.mem.eql(u8, name, "NtReadVirtualMemory")) return @ptrCast(&NtReadVirtualMemory);
        if (std.mem.eql(u8, name, "NtQueryVirtualMemory")) return @ptrCast(&NtQueryVirtualMemory);
        if (std.mem.eql(u8, name, "NtMapViewOfSection")) return @ptrCast(&NtMapViewOfSection);
        if (std.mem.eql(u8, name, "NtOpenProcess")) return @ptrCast(&NtOpenProcess);
        if (std.mem.eql(u8, name, "NtQuerySystemInformation")) return @ptrCast(&NtQuerySystemInformation);
        if (std.mem.eql(u8, name, "NtQueryInformationProcess")) return @ptrCast(&NtQueryInformationProcess);
        if (std.mem.eql(u8, name, "NtClose")) return @ptrCast(&NtClose);
        if (std.mem.eql(u8, name, "RtlLeaveCriticalSection")) return @ptrCast(&LeaveCriticalSection);
    } else if (std.ascii.eqlIgnoreCase(dll, "psapi.dll") or std.ascii.eqlIgnoreCase(dll, "psapi")) {
        if (std.mem.eql(u8, name, "GetModuleInformation")) return @ptrCast(&GetModuleInformation);
        if (std.mem.eql(u8, name, "EnumProcessModules")) return @ptrCast(&EnumProcessModules);
        if (std.mem.eql(u8, name, "GetModuleBaseNameA")) return @ptrCast(&GetModuleBaseNameA);
        if (std.mem.eql(u8, name, "GetModuleFileNameExA")) return @ptrCast(&GetModuleFileNameExA);
        if (std.mem.eql(u8, name, "EnumProcesses")) return @ptrCast(&EnumProcesses);
        if (std.mem.eql(u8, name, "GetMappedFileNameA")) return @ptrCast(&GetMappedFileNameA);
        if (std.mem.eql(u8, name, "GetProcessImageFileNameA")) return @ptrCast(&GetProcessImageFileNameA);
    } else if (std.ascii.eqlIgnoreCase(dll, "version.dll") or std.ascii.eqlIgnoreCase(dll, "version")) {
        if (std.mem.eql(u8, name, "GetFileVersionInfoSizeA")) return @ptrCast(&GetFileVersionInfoSizeA);
        if (std.mem.eql(u8, name, "GetFileVersionInfoA")) return @ptrCast(&GetFileVersionInfoA);
        if (std.mem.eql(u8, name, "VerQueryValueA")) return @ptrCast(&VerQueryValueA);
    } else if (std.ascii.eqlIgnoreCase(dll, "dbghelp.dll") or std.ascii.eqlIgnoreCase(dll, "dbghelp")) {
        if (std.mem.eql(u8, name, "StackWalk64")) return @ptrCast(&StackWalk64);
        if (std.mem.eql(u8, name, "SymFunctionTableAccess64")) return @ptrCast(&SymFunctionTableAccess64);
        if (std.mem.eql(u8, name, "SymGetModuleBase64")) return @ptrCast(&SymGetModuleBase64);
    }

    // --- Delegation to the shared API libraries -----------------------------
    // Only reached for names the local table above does not implement. This is
    // what turns "Diagnostic Fallback API" (a null-returning stub) into a real
    // implementation instead of duplicating the surface a second time.
    if (msvcrtDll(dll)) {
        if (msvcrt_mod.lookup(name)) |addr| return @ptrFromInt(addr);
    } else if (std.ascii.endsWithIgnoreCase(dll, "kernel32.dll") or std.ascii.endsWithIgnoreCase(dll, "kernel32")) {
        if (kernel32_mod.lookup(name)) |addr| return @ptrFromInt(addr);
    } else if (std.ascii.endsWithIgnoreCase(dll, "advapi32.dll") or std.ascii.endsWithIgnoreCase(dll, "advapi32")) {
        if (extra_dlls_mod.lookupAdvapi32(name)) |addr| return @ptrFromInt(addr);
    } else if (std.ascii.endsWithIgnoreCase(dll, "ws2_32.dll") or std.ascii.endsWithIgnoreCase(dll, "wsock32.dll") or
        std.ascii.endsWithIgnoreCase(dll, "ws2_32") or std.ascii.endsWithIgnoreCase(dll, "wsock32"))
    {
        if (extra_dlls_mod.lookupWs2_32(name)) |addr| return @ptrFromInt(addr);
    } else if (std.ascii.endsWithIgnoreCase(dll, "oleaut32.dll") or std.ascii.endsWithIgnoreCase(dll, "oleaut32")) {
        if (extra_dlls_mod.lookupOleaut32(name)) |addr| return @ptrFromInt(addr);
    } else if (std.ascii.endsWithIgnoreCase(dll, "shell32.dll") or std.ascii.endsWithIgnoreCase(dll, "shell32")) {
        if (extra_dlls_mod.lookupShell32(name)) |addr| return @ptrFromInt(addr);
    } else if (std.ascii.endsWithIgnoreCase(dll, "shlwapi.dll") or std.ascii.endsWithIgnoreCase(dll, "shlwapi")) {
        if (extra_dlls_mod.lookupShlwapi(name)) |addr| return @ptrFromInt(addr);
    } else if (std.ascii.endsWithIgnoreCase(dll, "wldap32.dll") or std.ascii.endsWithIgnoreCase(dll, "wldap32")) {
        if (extra_dlls_mod.lookupWldap32(name)) |addr| return @ptrFromInt(addr);
    } else if (std.ascii.endsWithIgnoreCase(dll, "crypt32.dll") or std.ascii.endsWithIgnoreCase(dll, "crypt32")) {
        if (extra_dlls_mod.lookupCrypt32(name)) |addr| return @ptrFromInt(addr);
    } else if (std.ascii.endsWithIgnoreCase(dll, "ncrypt.dll") or std.ascii.endsWithIgnoreCase(dll, "bcrypt.dll") or
        std.ascii.endsWithIgnoreCase(dll, "ncrypt") or std.ascii.endsWithIgnoreCase(dll, "bcrypt"))
    {
        if (extra_dlls_mod.lookupNcrypt(name)) |addr| return @ptrFromInt(addr);
    } else if (std.ascii.endsWithIgnoreCase(dll, "user32.dll") or std.ascii.endsWithIgnoreCase(dll, "user32")) {
        // CharUpperW and friends; the window/message surface stays in the local
        // table above. winrun_gui_support is deliberately NOT delegated here: it
        // imports x11_window.zig, and static libX11 is not available for i386.
        if (extra_dlls_mod.lookupUser32Console(name)) |addr| return @ptrFromInt(addr);
    } else if (std.ascii.endsWithIgnoreCase(dll, "sensapi.dll") or std.ascii.endsWithIgnoreCase(dll, "secur32.dll") or
        std.ascii.endsWithIgnoreCase(dll, "comctl32.dll") or std.ascii.endsWithIgnoreCase(dll, "wintrust.dll") or
        std.ascii.endsWithIgnoreCase(dll, "iphlpapi.dll") or std.ascii.endsWithIgnoreCase(dll, "dnsapi.dll") or
        std.ascii.endsWithIgnoreCase(dll, "winhttp.dll"))
    {
        if (extra_dlls_mod.lookupMisc(name)) |addr| return @ptrFromInt(addr);
    }
    return null;
}

/// MSVCRT and the UCRT share one import surface here. ucrtbase is not a real
/// DLL in this loader; it is the import name Vista+ CRTs carry.
fn msvcrtDll(dll: []const u8) bool {
    return std.ascii.endsWithIgnoreCase(dll, "msvcrt.dll") or
        std.ascii.endsWithIgnoreCase(dll, "msvcrt") or
        std.ascii.endsWithIgnoreCase(dll, "ucrtbase.dll") or
        std.ascii.endsWithIgnoreCase(dll, "ucrtbase");
}

fn GetProcAddress(hModule: usize, lpProcName: ?[*:0]const u8) callconv(W) ?*const anyopaque {
    if (lpProcName) |name| {
        const slice = std.mem.sliceTo(name, 0);

        // steamclient.dll exports CreateInterface — handle before generic search
        if (std.mem.eql(u8, slice, "CreateInterface")) {
            std.debug.print("[WINS:Kernel32] GetProcAddress(0x{x}, \"CreateInterface\") -> steamclient_CreateInterface\n", .{hModule});
            return @ptrCast(&steamclient_CreateInterface);
        }

        const res = resolveImport("kernel32.dll", slice) orelse
            resolveImport("user32.dll", slice) orelse
            resolveImport("steam_api.dll", slice) orelse
            resolveImport("steamclient.dll", slice) orelse
            resolveImport("binkw32.dll", slice) orelse
            resolveImport("d3d9.dll", slice) orelse
            resolveImport("d3dx9_38.dll", slice) orelse
            resolveImport("advapi32.dll", slice) orelse
            resolveImport("ole32.dll", slice) orelse
            resolveImport("shell32.dll", slice) orelse
            resolveImport("gdi32.dll", slice) orelse
            resolveImport("winmm.dll", slice) orelse
            resolveImport("dinput8.dll", slice) orelse
            resolveImport("comctl32.dll", slice) orelse
            resolveImport("ntdll.dll", slice) orelse
            resolveImport("psapi.dll", slice) orelse
            resolveImport("version.dll", slice) orelse
            resolveImport("dbghelp.dll", slice);

        if (res) |fn_ptr| {
            std.debug.print("[WINS:Kernel32] GetProcAddress(0x{x}, \"{s}\") -> 0x{x:0>8}\n", .{ hModule, slice, @intFromPtr(fn_ptr) });
            return fn_ptr;
        }

        // Windows returns NULL here (with ERROR_PROC_NOT_FOUND). Returning the
        // generic stub instead is a lie that also corrupts the guest: the stub
        // takes zero parameters, so it never cleans the arguments the caller
        // pushed, and the argument left on the stack is eventually popped into
        // EIP by a later `ret`. 7zr hit exactly that on SetDefaultDllDirectories
        // and jumped to its own 0xc00 flags argument.
        //
        // The asking address is in the message: a name that is not in any of
        // the modules is either a module the loader does not know, or a name
        // the caller built wrong, and those two need different fixes.
        std.debug.print("  -> GetProcAddress: \"{s}\" NOT FOUND in any known module (returning NULL), asked by 0x{x:0>8} for module 0x{x:0>8}\n", .{ slice, @returnAddress(), hModule });
        g_last_error = 127; // ERROR_PROC_NOT_FOUND
    }
    return null;
}

// ============================================================================
// 32-bit x86 TIB & PEB Setup (FS Segment)
// ============================================================================

var g_tib_buffer: [64]u32 align(16) = [_]u32{0} ** 64;
var g_peb_buffer: [128]u32 align(16) = [_]u32{0} ** 128;

// Range of the guest image, so the crash handler can tell a guest return
// address from random stack garbage. Set once the image is mapped.
var g_guest_base: usize = 0;
var g_guest_end: usize = 0;
var g_guest_stack_base: usize = 0;
/// The PROT_NONE window reserved at startup so the loader's brk heap cannot
/// grow into the guest image range (see main). Our own reservation, so
/// rangeIsGuestOwned must not report it as foreign.
var g_image_reserve_base: usize = 0;
var g_image_reserve_end: usize = 0;
var g_guest_stack_end: usize = 0;

/// No-op hook placed immediately before the jump into guest code. It exists so a
/// debugger can set breakpoints inside the already-mapped guest image, and it
/// captures the host register state immediately before the guest starts: a value
/// that is already wrong here is the loader's fault, not the guest's.
pub export fn brkGuestEntry() callconv(.c) void {
    var b: u32 = undefined;
    var c: u32 = undefined;
    var d: u32 = undefined;
    asm volatile (
        \\ movl %%ebx, %[b]
        \\ movl %%ecx, %[c]
        \\ movl %%edx, %[d]
        : [b] "=r" (b),
          [c] "=r" (c),
          [d] "=r" (d),
    );
    g_probe_ebx = b;
    g_probe_ecx = c;
    g_probe_edx = d;
}

fn registerGuestImage(base: usize, size: usize) void {
    g_guest_base = base;
    g_guest_end = base + size;
}

fn registerGuestStack(base: usize, end: usize) void {
    g_guest_stack_base = base;
    g_guest_stack_end = end;
}

fn isGuestAddr(a: usize) bool {
    return a >= g_guest_base and a < g_guest_end;
}

fn isGuestStack(a: usize) bool {
    return a >= g_guest_stack_end and a <= g_guest_stack_base;
}


/// Runs on every thread started by CreateThread, before the guest's start routine:
/// gives it its own TEB (TIB at FS:0, self pointer, ids, PEB, stack bounds), its own
/// static TLS array and block (TEB+0x2c, a fresh copy of the image's template), loads
/// FS through set_thread_area, then runs the TLS callbacks with DLL_THREAD_ATTACH.
fn guestThreadInit(obj: *threads_mod.Object) void {
    const gpa = std.heap.page_allocator;
    const teb = gpa.alignedAlloc(u32, .@"16", 1024) catch return threadInitFailed("TEB");
    @memset(teb, 0);
    var probe: u32 = 0;
    const top = (@intFromPtr(&probe) + 0x1000) & ~@as(usize, 0xFFF);
    const size = @max(obj.stack_size, 1 << 20);
    teb[0] = 0xFFFFFFFF; // SEH chain end
    teb[1] = @intCast(top); // stack base
    teb[2] = @intCast(top - size); // stack limit
    teb[6] = @intFromPtr(teb.ptr); // self
    teb[8] = @intCast(linux.getpid());
    teb[9] = obj.tid;
    teb[12] = @intFromPtr(&g_peb_buffer);

    const arr = gpa.alloc(usize, TLS_SLOT_COUNT) catch return threadInitFailed("TLS array");
    @memset(arr, 0);
    arr[0] = @intFromPtr(arr.ptr);
    const total = g_tls_tpl_len + g_tls_zero_fill;
    if (total > 0 and g_tls_idx > 0 and g_tls_idx < TLS_SLOT_COUNT) {
        const block = gpa.alloc(u8, total) catch return threadInitFailed("TLS block");
        @memcpy(block[0..g_tls_tpl_len], @as([*]const u8, @ptrFromInt(g_tls_tpl_start))[0..g_tls_tpl_len]);
        @memset(block[g_tls_tpl_len..], 0);
        arr[g_tls_idx] = @intFromPtr(block.ptr);
    }
    teb[0x2c / 4] = @intFromPtr(arr.ptr);

    var desc = UserDesc{
        .entry_number = std.math.maxInt(c_uint),
        .base_addr = @intFromPtr(teb.ptr),
        .limit = 0xFFFFF,
        .flags = 0x51, // seg_32bit, limit_in_pages, useable
    };
    if (linux.syscall1(.set_thread_area, @intFromPtr(&desc)) != 0) return threadInitFailed("set_thread_area");
    const selector: u16 = @intCast((desc.entry_number << 3) | 3);
    asm volatile ("mov %[sel], %%fs"
        :
        : [sel] "r" (selector),
    );

    if (g_tls_callbacks_va != 0) {
        const cbs: [*]const u32 = @ptrFromInt(g_tls_callbacks_va);
        var i: usize = 0;
        while (i < 64) : (i += 1) {
            if (cbs[i] == 0) break;
            const cb: *const fn (usize, u32, ?*anyopaque) callconv(W) void = @ptrFromInt(cbs[i]);
            cb(g_guest_base, 2, null); // DLL_THREAD_ATTACH
        }
    }
}

fn threadInitFailed(what: []const u8) noreturn {
    std.debug.print("[WINS:Thread] cannot set up the new thread's {s}\n", .{what});
    linux.exit_group(126);
}

fn setupTib() !void {
    // Offset 0x00: SEH frame (0xFFFFFFFF = end of chain)
    g_tib_buffer[0] = 0xFFFFFFFF;
    // Offset 0x04: Stack base
    g_tib_buffer[1] = 0;
    // Offset 0x08: Stack limit
    g_tib_buffer[2] = 0;
    // Offset 0x18: Pointer to self (TEB)
    g_tib_buffer[6] = @intFromPtr(&g_tib_buffer);
    // Offset 0x20: PID
    g_tib_buffer[8] = @intCast(linux.getpid());
    // Offset 0x24: TID
    g_tib_buffer[9] = @intCast(linux.gettid());
    // Offset 0x30: Pointer to PEB
    g_tib_buffer[12] = @intFromPtr(&g_peb_buffer);

    // Initialize Win32 PEB:
    // Offset 0x02 is BeingDebugged (0 = FALSE)
    @as([*]u8, @ptrCast(&g_peb_buffer))[2] = 0;
    // Offset 0x08 is ImageBaseAddress (0x00400000)
    g_peb_buffer[2] = 0x00400000;
    // Offset 0x18 is ProcessHeap (0x00010000)
    g_peb_buffer[6] = 0x00010000;

    var desc = UserDesc{
        .entry_number = std.math.maxInt(c_uint),
        .base_addr = @intFromPtr(&g_tib_buffer),
        .limit = 0xFFFFF,
        .flags = 0x51, // seg_32bit=1, limit_in_pages=1, useable=1
    };

    const rc = linux.syscall1(.set_thread_area, @intFromPtr(&desc));
    if (rc != 0) return error.SetThreadAreaFailed;

    msvcrt_mod.guest_tib_base = @intFromPtr(&g_tib_buffer);
    user32_mod.g_set_last_error = &setLastErrorHook;
    threads_mod.g_thread_init = &guestThreadInit;

    const selector: u16 = @intCast((desc.entry_number << 3) | 3);
    asm volatile ("mov %[sel], %%fs"
        :
        : [sel] "r" (selector),
    );
}

// ============================================================================
// Main 32-bit PE Loader Routine
// ============================================================================

pub fn main(init: std.process.Init) !void {
    // brk randomisation can place this process's own heap inside the guest
    // image window (0x00400000..) before main even runs; the image's
    // MAP_FIXED mapping would then destroy live heap chunks and the loader
    // aborts much later inside malloc ("malloc(): invalid size (unsorted)").
    // Re-exec once with ADDR_NO_RANDOMIZE (inherited across execve) so the
    // heap starts right after the loader's bss, below the image window, and
    // the reservation below can hold for the whole run. Allocations here use
    // page_allocator (mmap-backed) so this block itself never touches brk.
    if (getenv("WINS_FIXED_VA") == null) {
        _ = linux.syscall1(.personality, @as(usize, 0x0040000)); // ADDR_NO_RANDOMIZE
        const args = init.minimal.args.toSlice(std.heap.page_allocator) catch return;
        var argv_list = std.ArrayList(?[*:0]const u8).empty;
        defer argv_list.deinit(std.heap.page_allocator);
        for (args) |a| argv_list.append(std.heap.page_allocator, @ptrCast(a)) catch return;
        argv_list.append(std.heap.page_allocator, null) catch return;
        var env_list = std.ArrayList(?[*:0]const u8).empty;
        defer env_list.deinit(std.heap.page_allocator);
        var n: usize = 0;
        while (environ[n] != null) : (n += 1) {}
        for (0..n) |i| env_list.append(std.heap.page_allocator, environ[i]) catch return;
        env_list.append(std.heap.page_allocator, "WINS_FIXED_VA=1") catch return;
        env_list.append(std.heap.page_allocator, null) catch return;
        _ = linux.execve("/proc/self/exe", @ptrCast(argv_list.items.ptr), @ptrCast(env_list.items.ptr));
        return; // execve returns only on failure
    }

    // Reserve the guest-image window BEFORE the loader's own heap can grow
    // into it. brk() cannot extend into an already-mapped range, so glibc
    // falls back to mmap for later allocations and the loader's heap stays
    // intact. The real image mapping below replaces the lower part of this
    // reservation with MAP_FIXED, so the guest still lands at its ImageBase.
    {
        const reserve_base: usize = 0x00400000;
        const reserve_size: usize = imageWindowReserveSize(reserve_base, 64 * 1024 * 1024, @intFromPtr(&__ehdr_start));
        // FIXED_NOREPLACE: never silently replace anything already mapped.
        const rflags = linux.MAP{ .TYPE = .PRIVATE, .ANONYMOUS = true, .FIXED_NOREPLACE = true };
        const reserved = if (reserve_size == 0) @as(usize, @bitCast(-@as(isize, @intFromEnum(linux.E.INVAL)))) else linux.mmap(@ptrFromInt(reserve_base), reserve_size, linux.PROT{}, rflags, -1, 0);
        if (linux.errno(reserved) != .SUCCESS) {
            std.debug.print("  [Memory] image-window reservation at 0x{x:0>8} failed: {} (continuing unprotected)\n", .{ reserve_base, linux.errno(reserved) });
        } else {
            g_image_reserve_base = reserve_base;
            g_image_reserve_end = reserve_base + reserve_size;
        }
    }

    // The real Steam client is loaded LATER, once the guest's image window is
    // reserved (see the image mapping below). The order matters and was
    // measured, not guessed:
    //
    // glibc's heap grows with brk(), and Linux randomises where that heap
    // starts. The guest's image lives at 0x00400000 and is 16.5 MB wide, so a
    // randomised brk heap that starts below it and grows upward lands INSIDE
    // the image window. The image is mapped MAP_FIXED, so the heap is
    // silently replaced by the image: the client's live allocations are
    // destroyed, and the client aborts later inside its own malloc with
    // "malloc(): unaligned tcache chunk detected". The loader even printed
    // the collision and then overwrote the memory anyway:
    //
    //   [Memory] WARNING: 0x00400000+17281024 overlaps live memory ...
    //     overlapping: 00b38000-00bdd000 rw-p [heap]
    //
    // Reserving the image first inverts the race: brk cannot grow into a
    // window that is already mapped, so glibc falls back to mmap for the
    // overflow and the client's heap stays intact.
    //
    // Only when the environment says a Steam product is being run. SteamAppId is
    // set by the real client for the processes it launches, and nothing else
    // sets it, so this is the client's own statement about its child -- and it
    // keeps a 50 MB library out of every unrelated guest. Measured: with the
    // call unconditional, 7zr's run differed from its oracle by one log line and
    // nothing else, which is how the mistake was caught.
    const io = init.io;
    g_io = io;
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    if (args.len < 2) {
        std.debug.print("Usage: winrun32 [--check] [--run] <path-to-pe32.exe>\n", .{});
        return;
    }

    var check_only = false;
    var run_target = false;
    var run_anyway = false;
    var target_path: []const u8 = "";

    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--check")) {
            check_only = true;
        } else if (std.mem.eql(u8, arg, "--run")) {
            run_target = true;
        } else if (std.mem.eql(u8, arg, "--ignore-missing-imports")) {
            run_anyway = true;
        } else if (target_path.len == 0 and !std.mem.startsWith(u8, arg, "--")) {
            target_path = arg;
        }
    }

    if (target_path.len == 0) {
        std.debug.print("Error: No PE32 target executable specified.\n", .{});
        return;
    }

    // Guest argv: argv[0] is the image, everything after it is passed through.
    // The loader's own flags are consumed above and never reach the guest.
    // (Same shape as winrun_impl.zig lines 277-291.)
    var guest_args: std.ArrayList([]const u8) = .empty;
    var seen_target = false;
    for (args[1..]) |arg| {
        if (!seen_target and std.mem.eql(u8, arg, target_path)) {
            seen_target = true;
            guest_args.append(allocator, arg) catch {};
        } else if (seen_target and !std.mem.eql(u8, arg, "--")) {
            guest_args.append(allocator, arg) catch {};
        }
    }

    // Install diagnostic crash interception
    installCrashHandlers();
    g_crash_trap = std.mem.eql(u8, init.environ_map.get("WINS_CRASH_TRAP") orelse "", "1");
    msvcrt_mod.trace_static_init = std.mem.eql(u8, init.environ_map.get("WINS_TRACE") orelse "", "1");

    const bytes = std.Io.Dir.cwd().readFileAlloc(io, target_path, allocator, .limited(64 * 1024 * 1024)) catch |e| {
        std.debug.print("cannot read {s}: {s}\n", .{ target_path, @errorName(e) });
        return;
    };

    const copy_len = @min(g_target_path.len - 1, target_path.len);
    @memcpy(g_target_path[0..copy_len], target_path[0..copy_len]);
    g_target_path[copy_len] = 0;
    g_target_path_len = copy_len;

    if (std.mem.lastIndexOfScalar(u8, target_path, '/')) |last_slash| {
        const dir = target_path[0..last_slash];
        var dir_buf: [512]u8 = undefined;
        const d_len = @min(dir_buf.len - 1, dir.len);
        @memcpy(dir_buf[0..d_len], dir[0..d_len]);
        dir_buf[d_len] = 0;
        _ = linux.chdir(dir_buf[0..d_len:0].ptr);
        std.debug.print("[WINS] Changed working directory to target dir: {s}\n", .{dir});
    }

    // Verify DOS and PE Header
    if (bytes.len < 64 or !std.mem.eql(u8, bytes[0..2], "MZ")) {
        std.debug.print("Error: Not a valid MZ executable.\n", .{});
        return;
    }

    const pe_offset = std.mem.readInt(u32, bytes[0x3C..0x40], .little);
    if (pe_offset + 24 > bytes.len or !std.mem.eql(u8, bytes[pe_offset..][0..4], "PE\x00\x00")) {
        std.debug.print("Error: Not a valid PE executable.\n", .{});
        return;
    }

    const coff_offset = pe_offset + 4;
    const machine = std.mem.readInt(u16, bytes[coff_offset..][0..2], .little);
    const num_sections = std.mem.readInt(u16, bytes[coff_offset + 2 ..][0..2], .little);
    const opt_header_size = std.mem.readInt(u16, bytes[coff_offset + 16 ..][0..2], .little);

    if (machine != IMAGE_FILE_MACHINE_I386) {
        std.debug.print("Error: Target machine is 0x{x} (expected i386 0x14c).\n", .{machine});
        return;
    }

    const opt_offset = coff_offset + 20;
    const magic = std.mem.readInt(u16, bytes[opt_offset..][0..2], .little);
    if (magic != PE32_MAGIC) {
        std.debug.print("Error: Expected PE32 magic 0x10b, got 0x{x}.\n", .{magic});
        return;
    }

    const entry_rva = std.mem.readInt(u32, bytes[opt_offset + 16 ..][0..4], .little);
    const image_base = std.mem.readInt(u32, bytes[opt_offset + 28 ..][0..4], .little);
    const size_of_image = std.mem.readInt(u32, bytes[opt_offset + 56 ..][0..4], .little);
    const size_of_headers = std.mem.readInt(u32, bytes[opt_offset + 60 ..][0..4], .little);

    std.debug.print("[WINS:winrun32] Target: {s}\n", .{target_path});
    std.debug.print("  Architecture:    x86 32-bit (i386)\n", .{});
    std.debug.print("  ImageBase:       0x{x:0>8}\n", .{image_base});
    std.debug.print("  Virtual Size:    {d} bytes ({d:.2} MB)\n", .{ size_of_image, @as(f64, @floatFromInt(size_of_image)) / (1024.0 * 1024.0) });
    std.debug.print("  EntryPoint RVA:  0x{x:0>8} -> VA: 0x{x:0>8}\n", .{ entry_rva, image_base + entry_rva });
    std.debug.print("  Sections Count:  {d}\n", .{num_sections});

    // Parse Sections
    const section_headers_offset = opt_offset + opt_header_size;
    var sections = try allocator.alloc(Section, num_sections);
    defer allocator.free(sections);

    for (0..num_sections) |i| {
        const sh_pos = section_headers_offset + i * 40;
        var s: Section = undefined;
        @memcpy(&s.name, bytes[sh_pos..][0..8]);
        s.virtual_size = std.mem.readInt(u32, bytes[sh_pos + 8 ..][0..4], .little);
        s.virtual_address = std.mem.readInt(u32, bytes[sh_pos + 12 ..][0..4], .little);
        s.size_of_raw_data = std.mem.readInt(u32, bytes[sh_pos + 16 ..][0..4], .little);
        s.pointer_to_raw_data = std.mem.readInt(u32, bytes[sh_pos + 20 ..][0..4], .little);
        s.characteristics = std.mem.readInt(u32, bytes[sh_pos + 36 ..][0..4], .little);
        sections[i] = s;

        const clean_name = std.mem.sliceTo(&s.name, 0);
        std.debug.print("    Section [{d}]: {s: <8} VA: 0x{x:0>8} Size: {d} bytes\n", .{
            i, clean_name, s.virtual_address, s.virtual_size,
        });
    }

    // Parse Import Directory Table
    const data_dirs_offset = opt_offset + 96;
    // Steam sets SteamAppId in the environment of the child it launches, so its
    // presence is how the bridge knows a live client is asking for this game.
    // A hand-launched loader leaves it empty and is refused, which is the point:
    // the account verification belongs to Steam, not to us.
    var appid_buf: [32]u8 = undefined;
    if (init.environ_map.get("SteamAppId")) |v| {
        g_steam_appid = std.fmt.parseInt(u32, v, 10) catch 0;
        _ = &appid_buf;
    }
    std.debug.print("[WINS:SteamBridge] SteamAppId in environment: {d} (expected {d})\n", .{ g_steam_appid, STEAM_APPID });

    var total_imports: usize = 0;
    var imports_steam: bool = false;
    var resolved_imports: usize = 0;

    var import_rva: u32 = 0;
    var import_size: u32 = 0;

    // Entry 9 is the TLS directory: the guest's static thread data, and the
    // address where it expects to find the index the loader gave it.
    var tls_rva: u32 = 0;
    var tls_size: u32 = 0;
    if (data_dirs_offset + 9 * 8 + 8 <= opt_offset + opt_header_size) {
        tls_rva = std.mem.readInt(u32, bytes[data_dirs_offset + 9 * 8 ..][0..4], .little);
        tls_size = std.mem.readInt(u32, bytes[data_dirs_offset + 9 * 8 + 4 ..][0..4], .little);
    }

    if (data_dirs_offset + 8 <= opt_offset + opt_header_size) {
        import_rva = std.mem.readInt(u32, bytes[data_dirs_offset + 8 ..][0..4], .little);
        import_size = std.mem.readInt(u32, bytes[data_dirs_offset + 12 ..][0..4], .little);

        if (import_rva != 0 and import_size != 0) {
            var import_sec: ?Section = null;
            for (sections) |sec| {
                if (import_rva >= sec.virtual_address and import_rva < sec.virtual_address + sec.virtual_size) {
                    import_sec = sec;
                    break;
                }
            }

            if (import_sec) |sec| {
                const sec_delta = import_rva - sec.virtual_address;
                var desc_pos = sec.pointer_to_raw_data + sec_delta;

                while (desc_pos + 20 <= bytes.len) : (desc_pos += 20) {
                    const original_first_thunk = std.mem.readInt(u32, bytes[desc_pos..][0..4], .little);
                    const name_rva = std.mem.readInt(u32, bytes[desc_pos + 12 ..][0..4], .little);
                    const first_thunk = std.mem.readInt(u32, bytes[desc_pos + 16 ..][0..4], .little);

                    if (name_rva == 0 and first_thunk == 0) break;

                    const name_delta = name_rva - sec.virtual_address;
                    const name_file_offset = sec.pointer_to_raw_data + name_delta;
                    const dll_name = std.mem.sliceTo(bytes[name_file_offset..], 0);
                    if (std.ascii.indexOfIgnoreCase(dll_name, "steam") != null) imports_steam = true;

                    const thunk_rva = if (original_first_thunk != 0) original_first_thunk else first_thunk;
                    const thunk_delta = thunk_rva - sec.virtual_address;
                    var thunk_file_offset = sec.pointer_to_raw_data + thunk_delta;

                    while (thunk_file_offset + 4 <= bytes.len) : (thunk_file_offset += 4) {
                        const val = std.mem.readInt(u32, bytes[thunk_file_offset..][0..4], .little);
                        if (val == 0) break;
                        total_imports += 1;

                        if ((val & 0x80000000) == 0) {
                            const fn_delta = (val + 2) - sec.virtual_address;
                            if (fn_delta < sec.virtual_size) {
                                const fn_offset = sec.pointer_to_raw_data + fn_delta;
                                const fn_name = std.mem.sliceTo(bytes[fn_offset..], 0);
                                if (resolveImport(dll_name, fn_name) != null) {
                                    resolved_imports += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    std.debug.print("  Import Table Analysis:\n", .{});
    // Deterministic gate, before a single page of the guest image exists: a PE that
    // reaches for Steam only runs once a live, authenticated client says yes.
    if (imports_steam and run_target) {
        std.debug.print("  This program imports Steam APIs; requiring a live Steam client.\n", .{});
        if (!steamClientLive()) {
            std.debug.print("[WINS:SteamBridge] REFUSING to run: no live Steam client serving this process.\n", .{});
            std.debug.print("                  Launch it through Steam so the account can be verified.\n", .{});
            linux.exit_group(1);
        }
    }


    std.debug.print("    Total Imported Symbols:   {d}\n", .{total_imports});
    std.debug.print("    Core Handled APIs:        {d}\n", .{resolved_imports});
    std.debug.print("    Diagnostic Fallback APIs: {d}\n", .{total_imports - resolved_imports});

    // Setup x86 TIB
    try setupTib();
    std.debug.print("  [x86 TIB] FS segment configured via set_thread_area syscall.\n", .{});

    // --check reaches the same mmap + IAT resolution the run path uses, but never
    // jumps to the entry point. Its verdict therefore comes from real resolution
    // instead of a separate pass over the file bytes.
    if (check_only) run_target = false;

    // Step 2: Map ImageBase
    const prot = linux.PROT{
        .READ = true,
        .WRITE = true,
        .EXEC = true,
    };
    const flags = linux.MAP{
        .TYPE = .PRIVATE,
        .ANONYMOUS = true,
        .FIXED = true,
    };

    // MAP_FIXED replaces whatever was there, silently. The guest's image is
    // 16.5 MB, so if the real client -- which is loaded before the guest runs
    // and whose heap, arenas and thread stacks are anonymous, so they never
    // show up in a filter by module name -- happens to hold anything inside
    // that window, the client's live memory is destroyed here. The client
    // notices much later, when its next malloc pops a corrupted tcache entry
    // and aborts with "malloc(): unaligned tcache chunk detected".
    //
    // Checked before the mapping, not after: after it, the region is the
    // guest's own and would always look foreign.
    if (rangeIsForeign(image_base, image_base + size_of_image)) {
        std.debug.print("  [Memory] WARNING: 0x{x:0>8}+{d} overlaps live memory that is not the guest's.\\n", .{ image_base, size_of_image });
        describeOverlap(image_base, image_base + size_of_image);
    }

    const mapped_ptr = linux.mmap(
        @ptrFromInt(image_base),
        size_of_image,
        prot,
        flags,
        -1,
        0,
    );

    if (linux.errno(mapped_ptr) != .SUCCESS) {
        std.debug.print("Error: mmap at 0x{x:0>8} failed: {}\n", .{ image_base, linux.errno(mapped_ptr) });
        return;
    }

    std.debug.print("  [Memory] Successfully mapped 0x{x:0>8} (size: {d} bytes).\n", .{ image_base, size_of_image });
    registerGuestImage(image_base, size_of_image);

    // The guest's image window is now reserved, so the real client's brk heap
    // cannot grow into it. Load the client NOW, before any guest code runs:
    // the client answers for itself, and the loader only translates the API
    // around it. SteamAppId is set by the real client for the processes it
    // launches, and nothing else sets it, so it is the client's own statement
    // about its child -- and it keeps a 50 MB library out of every unrelated
    // guest. Measured: with the call unconditional, 7zr's run differed from
    // its oracle by one log line and nothing else, which is how the mistake
    // was caught.
    if (getenv("SteamAppId") != null) loadRealSteamClient();
    // Host GPU rendering for Direct3D 9 devices (WINS_D3D9_HOST=0: headless).
    d3d9.host_enabled = if (getenv("WINS_D3D9_HOST")) |v| v[0] != '0' else true;
    if (getenv("WINS_D3D9_PROF")) |v| d3d9.hostgl_prof(v[0] != '0');
    if (getenv("WINS_D3D9_CAPTURE")) |v| {
        const spec = std.mem.sliceTo(v, 0);
        if (std.mem.indexOfScalar(u8, spec, ':')) |colon| {
            d3d9.hostgl_capture(std.fmt.parseInt(u64, spec[0..colon], 10) catch 0, spec[colon + 1 ..]);
        }
    }
    // Instrument: WINS_D3D9_TRACE=<frames> prints the device's draw stream.
    if (getenv("WINS_D3D9_TRACE")) |v| {
        const spec = std.mem.sliceTo(v, 0);
        if (std.mem.indexOfScalar(u8, spec, ':')) |_| {
            var parts = std.mem.splitScalar(u8, spec, ':');
            d3d9.trace_after = std.fmt.parseInt(u64, parts.next() orelse "", 10) catch 0;
            d3d9.trace_budget = std.fmt.parseInt(u32, parts.next() orelse "", 10) catch 0;
            d3d9.trace_period = std.fmt.parseInt(u64, parts.next() orelse "", 10) catch 0;
        } else d3d9.trace_frames = std.fmt.parseInt(u32, spec, 10) catch 0;
        d3d9.trace_resources = d3d9.trace_frames != 0 or d3d9.trace_budget != 0;
    }
    // Before any guest code runs, because the guest's address reservations
    // (MAP_FIXED) happen before it ever asks for the Steam interface.
    protectForeignMemory();

    // The delegated libraries keep their own image-base and command-line state.
    // The local table above shadows GetCommandLineA/GetModuleFileNameA, but the
    // module versions are reachable through GetProcAddress, so keep them honest.
    kernel32_mod.setImageBase(@intCast(image_base));
    // Give the module's VirtualFree a way to prove ownership before it unmaps.
    kernel32_mod.release_hook = releaseOwnedBlock;
    msvcrt_mod.setArgs(guest_args.items);
    kernel32_mod.setCommandLine(guest_args.items);
    setGuestCommandLine(guest_args.items);

    // Copy Headers
    const dest_slice: [*]u8 = @ptrFromInt(image_base);
    @memcpy(dest_slice[0..size_of_headers], bytes[0..size_of_headers]);

    // Copy Sections
    for (sections) |s| {
        if (s.size_of_raw_data > 0) {
            const sec_dest = dest_slice + s.virtual_address;
            const sec_src = bytes[s.pointer_to_raw_data .. s.pointer_to_raw_data + s.size_of_raw_data];
            @memcpy(sec_dest[0..s.size_of_raw_data], sec_src);
        }
    }
    std.debug.print("  [Sections] All {d} PE sections placed in virtual memory.\n", .{num_sections});

    // Step 3: Patch Import Address Table (IAT) in Memory!
    var patched_count: usize = 0;
    var unresolved_slots: usize = 0;
    if (import_rva != 0 and import_size != 0) {
        var desc_va = import_rva;
        while (desc_va + 20 <= size_of_image) : (desc_va += 20) {
            const orig_thunk = std.mem.readInt(u32, dest_slice[desc_va..][0..4], .little);
            const name_rva = std.mem.readInt(u32, dest_slice[desc_va + 12 ..][0..4], .little);
            const first_thunk = std.mem.readInt(u32, dest_slice[desc_va + 16 ..][0..4], .little);

            if (name_rva == 0 and first_thunk == 0) break;

            const dll_name = std.mem.sliceTo(dest_slice + name_rva, 0);
            const thunk_rva = if (orig_thunk != 0) orig_thunk else first_thunk;

            var cur_lookup = thunk_rva;
            var cur_iat = first_thunk;

            while (cur_lookup + 4 <= size_of_image and cur_iat + 4 <= size_of_image) : ({
                cur_lookup += 4;
                cur_iat += 4;
            }) {
                const val = std.mem.readInt(u32, dest_slice[cur_lookup..][0..4], .little);
                if (val == 0) break;

                var resolved_fn: ?*const anyopaque = null;
                const by_ordinal = (val & 0x80000000) != 0;
                if (!by_ordinal) {
                    const nm = std.mem.sliceTo(dest_slice + val + 2, 0);
                    resolved_fn = resolveImport(dll_name, nm);
                } else if (ordinals_mod.getOrdinalName(dll_name, @truncate(val))) |ord_name| {
                    resolved_fn = resolveImport(dll_name, ord_name);
                }

                if (resolved_fn == null) {
                    resolved_fn = @ptrCast(&unhandledApiStub);
                    unresolved_slots += 1;
                    if (unresolved_slots <= 64) {
                        if (by_ordinal) {
                            std.debug.print("    UNRESOLVED {s}!ordinal {d}\n", .{ dll_name, val & 0xFFFF });
                        } else {
                            std.debug.print("    UNRESOLVED {s}!{s}\n", .{ dll_name, std.mem.sliceTo(dest_slice + val + 2, 0) });
                        }
                    }
                }

                const fn_addr: u32 = @intFromPtr(resolved_fn.?);
                std.mem.writeInt(u32, dest_slice[cur_iat..][0..4], fn_addr, .little);
                patched_count += 1;
            }
        }
    }
    std.debug.print("  [IAT Patcher] Successfully patched {d} import slots in RAM.\n", .{patched_count});
    if (unresolved_slots > 0) {
        std.debug.print("  [IAT Patcher] WARNING: {d} slot(s) fell back to the null stub (listed above).\n", .{unresolved_slots});
    }
    std.debug.print("[WINS:winrun32] Memory staging & IAT patching complete!\n", .{});

    // Fail closed. winrun (x86-64) refuses to run an image with unimplemented
    // imports; this loader used to bind a stub returning 0 and jump straight in,
    // which is why 7zr died at mainCRTStartup+0x4d writing a null pointer.
    if (run_target and unresolved_slots > 0 and !run_anyway) {
        std.debug.print("[WINS:winrun32] REFUSING to run: {d} unresolved import slot(s).\n", .{unresolved_slots});
        std.debug.print("                 Implement them in the shared libraries (winrun_kernel32.zig,\n", .{});
        std.debug.print("                 winrun_msvcrt.zig, winrun_extra_dlls.zig)\n", .{});
        std.debug.print("                 or pass --ignore-missing-imports to proceed anyway.\n", .{});
        std.debug.print("[WINS:winrun32] NOT_DEMONSTRATED: the image was not executed.\n", .{});
        linux.exit_group(1);
    }

    if (run_target) {
        // Allocate a 4MB clean stack for WinMain
        const stack_size: usize = 4 * 1024 * 1024;
        const stack_flags = linux.MAP{
            .TYPE = .PRIVATE,
            .ANONYMOUS = true,
        };
        const stack_mem = linux.mmap(null, stack_size, prot, stack_flags, -1, 0);
        if (linux.errno(stack_mem) != .SUCCESS) {
            std.debug.print("Error allocating execution stack: {}\n", .{linux.errno(stack_mem)});
            return;
        }

        const stack_base = stack_mem + stack_size;
        const stack_limit = stack_mem;
        g_tib_buffer[1] = @intCast(stack_base);
        g_tib_buffer[2] = @intCast(stack_limit);
        registerGuestStack(stack_base, stack_limit);

        // The guest's thread data, before any guest code runs: the image is
        // mapped and its sections are in place, so the template can be copied.
        setupGuestTls(allocator, image_base, tls_rva, tls_size);

        const new_esp = stack_base - 0x1000;
        std.debug.print("\n[WINS:winrun32] JUMPING to EntryPoint at 0x{x:0>8} with stack at 0x{x:0>8}...\n", .{image_base + entry_rva, new_esp});

        // Diagnostic hook: by the time this runs, the guest image is mapped, so
        // gdb can set breakpoints inside it (`break brkGuestEntry` then
        // `break *<guest entry>`). No side effects.
        brkGuestEntry();
        std.debug.print("[WINS:regprobe] before guest jump: EBX=0x{x:0>8} ECX=0x{x:0>8} EDX=0x{x:0>8} (guest expects EBX built fresh; ECX=this)\n", .{ g_probe_ebx, g_probe_ecx, g_probe_edx });

        var old_esp: usize = 0;
        asm volatile (
            \\ movl %%esp, %[old_esp]
            \\ movl %[new_esp], %%esp
            \\ pushl $0
            \\ call *%[entry]
            \\ movl %[old_esp], %%esp
            : [old_esp] "=m" (old_esp),
            : [new_esp] "r" (new_esp),
              [entry] "r" (image_base + entry_rva),
        );
        std.debug.print("[WINS:winrun32] Target execution finished successfully.\n", .{});
    }

    if (check_only) {
        if (unresolved_slots == 0) {
            std.debug.print("\n[WINS:winrun32] Check PASSED: all {d} import slots resolved.\n", .{patched_count});
        } else {
            std.debug.print("\n[WINS:winrun32] Check FAILED: {d} unresolved import slot(s).\n", .{unresolved_slots});
            linux.exit_group(1);
        }
    } else if (unresolved_slots > 0) {
        std.debug.print("[WINS:winrun32] NOT_DEMONSTRATED: guest code ran with {d} import slot(s) bound to the stub.\n", .{unresolved_slots});
    }
}

// ============================================================================
// Unit Tests (Embedded Verification)
// ============================================================================

test "VirtualAlloc recommit preserves existing contents and refuses an unreserved range" {
    const page = VirtualAlloc(null, 8192, 0x3000, 0x04) orelse return error.AllocationFailed;
    defer _ = VirtualFree(page, 0, 0x8000);
    const bytes: [*]u8 = @ptrCast(page);
    bytes[0] = 0x41;
    bytes[4096] = 0x42;
    const second: *anyopaque = @ptrCast(bytes + 4096);
    try std.testing.expectEqual(second, VirtualAlloc(second, 4096, 0x1000, 0x04).?);
    try std.testing.expectEqual(@as(u8, 0x41), bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x42), bytes[4096]);
    try std.testing.expect(VirtualAlloc(page, 8192, 0x3000, 0x04) == null);
    try std.testing.expectEqual(@as(u8, 0x41), bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x42), bytes[4096]);
    try std.testing.expect(VirtualAlloc(@ptrFromInt(0x10000), 4096, 0x1000, 0x04) == null);
}

test "thread-naming exception (0x406d1388) is continuable, others are not" {
    try std.testing.expect(kernel32_mod.isThreadNamingException(0x406d1388));
    try std.testing.expect(!kernel32_mod.isThreadNamingException(0xc0000005));
    try std.testing.expect(!kernel32_mod.isThreadNamingException(0x406d1337));
}

test "image-window reservation never covers the loader's own image" {
    const base: usize = 0x00400000;
    const want: usize = 64 * 1024 * 1024;
    // Shipped layout: loader linked at 0x02000000, inside [base, base+want).
    const shipped = imageWindowReserveSize(base, want, 0x02000000);
    try std.testing.expectEqual(@as(usize, 0x02000000 - 0x00400000), shipped);
    try std.testing.expect(base + shipped <= 0x02000000);
    // Negative control: the old fixed 64 MB window DID reach the loader.
    try std.testing.expect(base + want > 0x02000000);
    // Unshipped layout (loader below the window) and far-above layout keep the full window.
    try std.testing.expectEqual(want, imageWindowReserveSize(base, want, 0x00010000));
    try std.testing.expectEqual(want, imageWindowReserveSize(base, want, 0x20000000));
    // Loader exactly at the window base: nothing to reserve.
    try std.testing.expectEqual(@as(usize, 0), imageWindowReserveSize(base, want, base));
    // The window must still hold the whole 16.5 MB Fallout image in the shipped layout.
    try std.testing.expect(shipped >= 0x0147b000 - 0x00400000);
}

test "ShellExecuteA reports failure (<=32) when nothing is executed" {
    const rc = ShellExecuteA(0, null, "definitely-not-here.exe", null, null, 1);
    try std.testing.expect(rc <= 32);
}

test "DirectInput8Create returns DI_OK with a real object, not NULL" {
    var obj: ?*anyopaque = null;
    try std.testing.expectEqual(@as(i32, 0), DirectInput8Create(0, 0x0800, null, &obj, null));
    try std.testing.expect(obj != null);
    const di8: *WinsDirectInput8 = @ptrCast(@alignCast(obj.?));
    try std.testing.expectEqual(@as(u32, 2), di8.vtbl.AddRef(di8));
    try std.testing.expectEqual(@as(u32, 1), di8.vtbl.Release(di8));
    try std.testing.expectEqual(@as(i32, 0), di8.vtbl.EnumDevices(di8, 0, null, null, 0));
    var dev: ?*anyopaque = null;
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0x80004003))), di8.vtbl.CreateDevice(di8, null, &dev, null)); // E_POINTER
    try std.testing.expect(dev == null);
    const sys_keyboard = [16]u8{ 0x61, 0x2B, 0x1D, 0x6F, 0xA0, 0xD5, 0xCF, 0x11, 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 };
    try std.testing.expectEqual(@as(i32, 0), di8.vtbl.CreateDevice(di8, &sys_keyboard, &dev, null));
    try std.testing.expect(dev != null);
    const joystick = [16]u8{ 0x99, 0x2B, 0x1D, 0x6F, 0xA0, 0xD5, 0xCF, 0x11, 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 };
    var dev2: ?*anyopaque = null;
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0x80040154))), di8.vtbl.CreateDevice(di8, &joystick, &dev2, null)); // DIERR_DEVICENOTREG
    try std.testing.expect(dev2 == null);
}

const ThreadProbe = struct { teb: u32 = 0, tid: u32 = 0, tls_arr: u32 = 0, tls_block: u32 = 0, seh: u32 = 0 };

fn fsDword(comptime off: []const u8) u32 {
    return asm volatile ("movl %%fs:" ++ off ++ ", %[r]"
        : [r] "=r" (-> u32),
    );
}

fn probeThread(p: ?*anyopaque) callconv(W) u32 {
    const pr: *ThreadProbe = @ptrCast(@alignCast(p.?));
    pr.teb = fsDword("0x18");
    pr.tid = fsDword("0x24");
    pr.tls_arr = fsDword("0x2c");
    pr.seh = fsDword("0");
    const arr: [*]const usize = @ptrFromInt(pr.tls_arr);
    pr.tls_block = @intCast(arr[g_tls_idx]);
    const blk: [*]u8 = @ptrFromInt(pr.tls_block);
    blk[0] +%= 1; // changes this thread's copy only
    return 0;
}

test "guest threads get their own TEB, tid and static TLS block" {
    var tpl = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    g_tls_tpl_start = @intFromPtr(&tpl);
    g_tls_tpl_len = tpl.len;
    g_tls_zero_fill = 8;
    g_tls_idx = 1;
    g_tls_callbacks_va = 0;
    threads_mod.g_thread_init = &guestThreadInit;
    defer threads_mod.g_thread_init = null;
    var a = ThreadProbe{};
    var b = ThreadProbe{};
    var ta: u32 = 0;
    var tb: u32 = 0;
    const fp: ?*anyopaque = @ptrCast(@constCast(&probeThread));
    const h1 = CreateThread(null, 0, fp, &a, 0, &ta);
    const h2 = CreateThread(null, 0, fp, &b, 0, &tb);
    try std.testing.expect(h1 != 0 and h2 != 0);
    try std.testing.expectEqual(@as(u32, 0), WaitForSingleObject(h1, 5000));
    try std.testing.expectEqual(@as(u32, 0), WaitForSingleObject(h2, 5000));
    // Each thread has its own TEB; FS:0x18 is the TEB's own address and FS:0x24 the thread id.
    try std.testing.expect(a.teb != 0 and b.teb != 0 and a.teb != b.teb);
    try std.testing.expectEqual(ta, a.tid);
    try std.testing.expectEqual(tb, b.tid);
    try std.testing.expect(ta != tb);
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), a.seh); // fresh, empty SEH chain
    // Own TLS array (slot 0 points at itself) and own block, copied from the template.
    try std.testing.expect(a.tls_arr != b.tls_arr and a.tls_block != b.tls_block);
    const arr_a: [*]const usize = @ptrFromInt(a.tls_arr);
    try std.testing.expectEqual(a.tls_arr, @as(u32, @intCast(arr_a[0])));
    const blk_a: [*]const u8 = @ptrFromInt(a.tls_block);
    const blk_b: [*]const u8 = @ptrFromInt(b.tls_block);
    try std.testing.expectEqual(@as(u8, 0x12), blk_a[0]); // 0x11 + this thread's own increment
    try std.testing.expectEqual(@as(u8, 0x12), blk_b[0]); // not 0x13: the blocks are independent
    try std.testing.expectEqual(@as(u8, 0x22), blk_a[1]); // rest of the template copied
    try std.testing.expectEqual(@as(u8, 0x88), blk_a[7]);
    try std.testing.expectEqual(@as(u8, 0), blk_a[8]); // zero fill
    try std.testing.expectEqual(@as(u8, 0), blk_a[15]);
    try std.testing.expectEqual(@as(u8, 0x11), tpl[0]); // the image's template is untouched
    try std.testing.expectEqual(@as(i32, 1), CloseHandle(h1));
    try std.testing.expectEqual(@as(i32, 1), CloseHandle(h2));
}

test "kernel32 wrappers: real sync objects, real wait results, legacy handles unchanged" {
    const e = CreateEventA(null, 1, 0, null);
    try std.testing.expect(e != 0);
    try std.testing.expectEqual(@as(u32, 258), WaitForSingleObject(e, 10)); // really times out
    try std.testing.expectEqual(@as(i32, 1), SetEvent(e));
    try std.testing.expectEqual(@as(u32, 0), WaitForSingleObject(e, 10));
    try std.testing.expectEqual(@as(i32, 1), ResetEvent(e));
    try std.testing.expectEqual(@as(u32, 258), WaitForSingleObject(e, 0));

    const s = CreateSemaphoreA(null, 0, 2, null);
    try std.testing.expectEqual(@as(i32, 1), ReleaseSemaphore(s, 1, null));
    try std.testing.expectEqual(@as(i32, 0), ReleaseSemaphore(s, 5, null)); // would exceed the maximum
    const hs = [_]usize{ e, s };
    try std.testing.expectEqual(@as(u32, 1), WaitForMultipleObjects(2, &hs, 0, 100)); // semaphore is index 1
    try std.testing.expectEqual(@as(u32, 258), WaitForMultipleObjects(2, &hs, 0, 10)); // nothing left
    try std.testing.expectEqual(@as(i32, 0), SetEvent(s)); // a semaphore is not an event
    try std.testing.expectEqual(@as(u32, 6), g_last_error); // ERROR_INVALID_HANDLE

    // Legacy handles keep the answers they always had.
    try std.testing.expectEqual(@as(i32, 1), SetEvent(0x30000002));
    try std.testing.expectEqual(@as(i32, 1), ReleaseMutex(0x2002));
    try std.testing.expectEqual(@as(i32, 1), CloseHandle(0x4001));

    const m = CreateMutexA(null, 0, null);
    try std.testing.expectEqual(@as(u32, 0), WaitForSingleObject(m, 0));
    try std.testing.expectEqual(@as(i32, 1), ReleaseMutex(m));
    try std.testing.expectEqual(@as(i32, 0), ReleaseMutex(m)); // no longer the owner
    try std.testing.expectEqual(@as(u32, 288), g_last_error); // ERROR_NOT_OWNER
    try std.testing.expectEqual(@as(i32, 1), CloseHandle(e));
    try std.testing.expectEqual(@as(i32, 1), CloseHandle(s));
    try std.testing.expectEqual(@as(i32, 1), CloseHandle(m));
}

test "thread control on handles this loader does not track keeps its legacy answers" {
    // The SteamStub calls these on handles from OpenThread; an error here aborts the
    // game with "Application load error" before it reaches Direct3D.
    try std.testing.expectEqual(@as(u32, 0), SuspendThread(0x4001));
    try std.testing.expectEqual(@as(u32, 1), ResumeThread(0x4001));
    try std.testing.expectEqual(@as(u32, 0), SuspendThread(0xFFFFFFFE)); // GetCurrentThread() pseudo handle
    var code: u32 = 55;
    try std.testing.expectEqual(@as(i32, 1), GetExitCodeThread(0x4001, &code));
    try std.testing.expectEqual(@as(u32, 0), code);
}

test "case-insensitive paths: exact first, ASCII fold per component, 2 vs 3 on misses" {
    // Fixture on disk: <base>/Data/Fallout - Textures.bsa (the exact shape of
    // the FalloutNV archive probe). Exercises the real resolver and the real
    // GetFileAttributesA, not a copy of their logic.
    var base_buf: [128]u8 = undefined;
    const base = try std.fmt.bufPrint(&base_buf, "/tmp/wins-ci-{}", .{linux.getpid()});
    var file_buf: [220]u8 = undefined;
    const file = try std.fmt.bufPrint(&file_buf, "{s}/Data/Fallout - Textures.bsa", .{base});
    var dir_buf: [220]u8 = undefined;
    var upper_buf: [220]u8 = undefined;
    var folded_buf: [220]u8 = undefined;
    var missfile_buf: [220]u8 = undefined;
    var missdir_buf: [220]u8 = undefined;
    var upperdir_buf: [220]u8 = undefined;
    var z_buf: [240]u8 = undefined;
    const nul = struct {
        fn f(buf: []u8, s: []const u8) [*:0]const u8 {
            @memcpy(buf[0..s.len], s);
            buf[s.len] = 0;
            return @ptrCast(buf.ptr);
        }
    }.f;

    _ = linux.rmdir(nul(&z_buf, base)); // leftover from a crashed run, if any
    try std.testing.expect(linux.errno(linux.mkdir(nul(&z_buf, base), 0o755)) == .SUCCESS);
    const data_dir = try std.fmt.bufPrint(&dir_buf, "{s}/Data", .{base});
    try std.testing.expect(linux.errno(linux.mkdir(nul(&z_buf, data_dir), 0o755)) == .SUCCESS);
    const fd = linux.open(nul(&z_buf, file), .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    try std.testing.expect(linux.errno(fd) == .SUCCESS);
    _ = linux.close(@intCast(fd));

    var out: [512]u8 = undefined;
    const upper = try std.fmt.bufPrint(&upper_buf, "{s}/DATA/Fallout - Textures.bsa", .{base});
    const r1 = resolvePathCaseInsensitive(upper, &out) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(file, r1);
    const folded = try std.fmt.bufPrint(&folded_buf, "{s}/data/FALLOUT - TEXTURES.BSA", .{base});
    const r2 = resolvePathCaseInsensitive(folded, &out) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(file, r2);

    const missfile = try std.fmt.bufPrint(&missfile_buf, "{s}/Data/nosuch.bsa", .{base});
    try std.testing.expect(resolvePathCaseInsensitive(missfile, &out) == null);
    try std.testing.expectEqual(@as(u32, 2), fileNotFoundError(missfile));
    const missdir = try std.fmt.bufPrint(&missdir_buf, "{s}/Nope/x.bsa", .{base});
    try std.testing.expect(resolvePathCaseInsensitive(missdir, &out) == null);
    try std.testing.expectEqual(@as(u32, 3), fileNotFoundError(missdir));

    // The real Win32 entry point: directory bit, archive bit, INVALID + error.
    try std.testing.expectEqual(@as(u32, 0x10), GetFileAttributesA(nul(&z_buf, data_dir)));
    const upper_dir = try std.fmt.bufPrint(&upperdir_buf, "{s}/DATA", .{base});
    try std.testing.expectEqual(@as(u32, 0x10), GetFileAttributesA(nul(&z_buf, upper_dir)));
    try std.testing.expectEqual(@as(u32, 0x20), GetFileAttributesA(nul(&z_buf, upper)));
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), GetFileAttributesA(nul(&z_buf, missfile)));
    try std.testing.expectEqual(@as(u32, 2), g_last_error);
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), GetFileAttributesA(nul(&z_buf, missdir)));
    try std.testing.expectEqual(@as(u32, 3), g_last_error);

    _ = linux.unlinkat(linux.AT.FDCWD, nul(&z_buf, file), 0);
    _ = linux.rmdir(nul(&z_buf, data_dir));
    _ = linux.rmdir(nul(&z_buf, base));
}

test "FindFirstFileA: masks, case folding, real attributes and sizes, Win32 errors" {
    // Mirrors native/testdata/find_probe.c (pinned against Proton): the
    // plugin listing FalloutNV does with "DATA\\*.esm".
    var base_buf: [128]u8 = undefined;
    const base = try std.fmt.bufPrint(&base_buf, "/tmp/wins-find-{}", .{linux.getpid()});
    var z: [300]u8 = undefined;
    const nul = struct {
        fn f(buf: []u8, comptime fmt: []const u8, args: anytype) [*:0]const u8 {
            const s = std.fmt.bufPrint(buf[0 .. buf.len - 1], fmt, args) catch unreachable;
            buf[s.len] = 0;
            return @ptrCast(buf.ptr);
        }
    }.f;
    const files = [_]struct { name: []const u8, size: usize }{
        .{ .name = "FalloutNV.esm", .size = 5 }, .{ .name = "DeadMoney.esm", .size = 3 },
        .{ .name = "Update.bsa", .size = 7 },    .{ .name = "readme.txt", .size = 0 },
    };
    try std.testing.expect(linux.errno(linux.mkdir(nul(&z, "{s}", .{base}), 0o755)) == .SUCCESS);
    try std.testing.expect(linux.errno(linux.mkdir(nul(&z, "{s}/Data", .{base}), 0o755)) == .SUCCESS);
    try std.testing.expect(linux.errno(linux.mkdir(nul(&z, "{s}/Data/Sub", .{base}), 0o755)) == .SUCCESS);
    for (files) |f| {
        const fd = linux.open(nul(&z, "{s}/Data/{s}", .{ base, f.name }), .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        try std.testing.expect(linux.errno(fd) == .SUCCESS);
        _ = linux.write(@intCast(fd), "XXXXXXXX", f.size);
        _ = linux.close(@intCast(fd));
    }
    defer {
        for (files) |f| _ = linux.unlinkat(linux.AT.FDCWD, nul(&z, "{s}/Data/{s}", .{ base, f.name }), 0);
        _ = linux.rmdir(nul(&z, "{s}/Data/Sub", .{base}));
        _ = linux.rmdir(nul(&z, "{s}/Data", .{base}));
        _ = linux.rmdir(nul(&z, "{s}", .{base}));
    }

    var d: WIN32_FIND_DATAA = undefined;
    // "*.esm" through an upper-case, backslashed parent: both masters, real sizes.
    var h = FindFirstFileA(nul(&z, "{s}\\DATA\\*.ESM", .{base}), &d);
    try std.testing.expect(h != 0xFFFFFFFF);
    var seen: u32 = 0;
    while (true) {
        const name = std.mem.sliceTo(&d.cFileName, 0);
        try std.testing.expectEqual(@as(u32, 0x20), d.dwFileAttributes);
        try std.testing.expect(d.ftLastWriteTime[1] >= 0x01d00000);
        if (std.mem.eql(u8, name, "FalloutNV.esm")) {
            try std.testing.expectEqual(@as(u32, 5), d.nFileSizeLow);
            seen |= 1;
        } else if (std.mem.eql(u8, name, "DeadMoney.esm")) {
            try std.testing.expectEqual(@as(u32, 3), d.nFileSizeLow);
            seen |= 2;
        } else return error.TestUnexpectedResult;
        if (FindNextFileA(h, &d) == 0) break;
    }
    try std.testing.expectEqual(@as(u32, 3), seen);
    try std.testing.expectEqual(@as(u32, 18), g_last_error);
    try std.testing.expectEqual(@as(i32, 1), FindClose(h));
    try std.testing.expectEqual(@as(i32, 0), FindClose(h)); // closed handles are invalid
    try std.testing.expectEqual(@as(u32, 6), g_last_error);

    // Literal, wrong case: the real on-disk spelling comes back.
    h = FindFirstFileA(nul(&z, "{s}/data/update.BSA", .{base}), &d);
    try std.testing.expect(h != 0xFFFFFFFF);
    try std.testing.expectEqualStrings("Update.bsa", std.mem.sliceTo(&d.cFileName, 0));
    _ = FindClose(h);

    // "*.*" lists dot-less names too ("Sub", ".", ".."): 4 files + 3 dirs.
    h = FindFirstFileA(nul(&z, "{s}/Data/*.*", .{base}), &d);
    var count: u32 = 1;
    while (FindNextFileA(h, &d) != 0) count += 1;
    try std.testing.expectEqual(@as(u32, 7), count);
    _ = FindClose(h);
    h = FindFirstFileA(nul(&z, "{s}/Data/Sub", .{base}), &d);
    try std.testing.expectEqual(@as(u32, 0x10), d.dwFileAttributes);
    _ = FindClose(h);

    // Errors: no match 2, missing parent 3.
    try std.testing.expectEqual(@as(usize, 0xFFFFFFFF), FindFirstFileA(nul(&z, "{s}/Data/*.nope", .{base}), &d));
    try std.testing.expectEqual(@as(u32, 2), g_last_error);
    try std.testing.expectEqual(@as(usize, 0xFFFFFFFF), FindFirstFileA(nul(&z, "{s}/Nope/*.esm", .{base}), &d));
    try std.testing.expectEqual(@as(u32, 3), g_last_error);

    try std.testing.expect(win32MaskMatch("Fallout?V.esm", "FALLOUTNV.ESM"));
    try std.testing.expect(!win32MaskMatch("*.esm", "FalloutNV.esp"));
    try std.testing.expectEqual(@as(u32, 0), GetFileType(0x12345678));
}

test "lstrcatA appends; -1 lengths count the whole string plus its NUL" {
    var buf: [32]u8 = [_]u8{'Z'} ** 32;
    _ = lstrcpyA(&buf, "DATA\\");
    _ = lstrcatA(&buf, "*.esm");
    try std.testing.expectEqualStrings("DATA\\*.esm", std.mem.sliceTo(@as([*:0]u8, @ptrCast(&buf)), 0));

    var w: [16]u16 = undefined;
    try std.testing.expectEqual(@as(i32, 11), MultiByteToWideChar(0, 0, "DATA\\a.esm", -1, null, 0));
    try std.testing.expectEqual(@as(i32, 11), MultiByteToWideChar(0, 0, "DATA\\a.esm", -1, &w, 16));
    try std.testing.expectEqual(@as(u16, 'm'), w[9]);
    try std.testing.expectEqual(@as(u16, 0), w[10]);
    try std.testing.expectEqual(@as(i32, 0), MultiByteToWideChar(0, 0, "abcdef", -1, &w, 3));
    try std.testing.expectEqual(@as(u32, 122), g_last_error);

    var d: [32]u8 = undefined;
    try std.testing.expectEqual(@as(i32, 16), LCMapStringA(0, 0x200, "Data\\Update.bsa", -1, &d, 32));
    try std.testing.expectEqualStrings("DATA\\UPDATE.BSA", std.mem.sliceTo(@as([*:0]u8, @ptrCast(&d)), 0));
    try std.testing.expectEqual(@as(i32, 0), LCMapStringA(0, 0, "x", -1, &d, 32));
}

test "CoCreateInstance: unregistered classes fail and never hand out NULL as success" {
    // CLSID_MemoryAllocator {1e651cc0-b199-11d0-8212-00c04fc32c45}: not implemented here.
    const clsid = [16]u8{ 0xc0, 0x1c, 0x65, 0x1e, 0x99, 0xb1, 0xd0, 0x11, 0x82, 0x12, 0x00, 0xc0, 0x4f, 0xc3, 0x2c, 0x45 };
    var out: ?*anyopaque = @ptrFromInt(0x1234);
    const hr = CoCreateInstance(@constCast(@ptrCast(&clsid)), null, 1, @constCast(@ptrCast(&clsid)), &out);
    try std.testing.expect(hr < 0);
    try std.testing.expectEqual(REGDB_E_CLASSNOTREG, hr);
    try std.testing.expect(out == null);
}
