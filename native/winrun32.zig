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
const extra_dlls_mod = @import("winrun_extra_dlls.zig");
// winrun_gui_support and x11_window are NOT imported: they need static libX11,
// which is unavailable for the i386 target this loader builds for.
const ordinals_mod = @import("winrun_ordinals.zig");

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
    _ = sig;
    std.debug.print("\n=======================================================\n", .{});
    std.debug.print("CRASH INTERCEPTED: Segmentation Fault (SIGSEGV)!\n", .{});
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

            // The object behind a null field dereference. By the time the fault
            // lands, EAX is the field that was read, but EDI is usually still the
            // pointer the object came from, so `[EDI]` names the base. This is how
            // "the whole object is zero" was discovered on 7zr: an entirely blank
            // block means it was never constructed, which no register dump shows.
            const edi_val = uctx.uc_mcontext.edi;
            if (edi_val > 0x1000 and edi_val + 8 < 0xFFFFF000) {
                const obj: usize = @as(*const usize, @ptrFromInt(edi_val)).*;
                // Not gated to the guest image: a heap block from our own malloc is
                // a valid host address, and the guest reading obj+0x2b0 without
                // faulting proves those pages are mapped.
                const base = if (obj > 0x1000 and obj + 0x300 < 0xFFFFF000) obj else edi_val;
                if (base > 0x1000) {
                    var nonzeros: usize = 0;
                    var o: usize = 0;
                    while (o < 0x300) : (o += 4) {
                        if (@as(*const u32, @ptrFromInt(base + o)).* != 0) nonzeros += 1;
                    }
                    std.debug.print("  Object base [EDI=0x{x}] = 0x{x}: {d} non-zero words in +0x000..0x300\n", .{ edi_val, base, nonzeros });
                    if (nonzeros > 0 and nonzeros < 64) {
                        o = 0;
                        while (o < 0x300) : (o += 4) {
                            const v: u32 = @as(*const u32, @ptrFromInt(base + o)).*;
                            if (v != 0) std.debug.print("    +0x{x:0>3}: 0x{x:0>8}\n", .{ o, v });
                        }
                    } else if (nonzeros >= 64) {
                        std.debug.print("    (too populated to summarise; the object was likely constructed)\n", .{});
                    } else {
                        std.debug.print("    ALL ZERO: uninitialised memory, never constructed by the guest.\n", .{});
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

fn installCrashHandlers() void {
    var sa = linux.Sigaction{
        .handler = .{ .sigaction = &sigHandler },
        .mask = [_]c_ulong{0} ** 2,
        .flags = 0x00000004, // SA_SIGINFO
    };
    _ = linux.sigaction(linux.SIG.SEGV, &sa, null);
    _ = linux.sigaction(linux.SIG.BUS, &sa, null);
    _ = linux.sigaction(linux.SIG.ILL, &sa, null);
}

// ============================================================================
// Core Win32 Heap & Memory Shims (Kernel32)
// ============================================================================

threadlocal var g_last_error: u32 = 0;
var g_tls_bitmap: u64 = 0;
threadlocal var g_tls_thread_slots: [64]?*anyopaque = [_]?*anyopaque{null} ** 64;
var g_alloc_prot: u32 = 0x04;

const HEAP_MAGIC: u32 = 0x57494E53; // "WINS"
const HeapHeader = extern struct {
    magic: u32,
    size: u32,
};

fn HeapAlloc(hHeap: usize, dwFlags: u32, dwBytes: usize) callconv(W) ?*anyopaque {
    _ = hHeap;
    const total = dwBytes + @sizeOf(HeapHeader);
    const prot = linux.PROT{ .READ = true, .WRITE = true };
    const flags = linux.MAP{ .TYPE = .PRIVATE, .ANONYMOUS = true };
    const ptr = linux.mmap(null, total, prot, flags, -1, 0);
    if (linux.errno(ptr) != .SUCCESS) return null;
    const hdr: *HeapHeader = @ptrFromInt(ptr);
    hdr.magic = HEAP_MAGIC;
    hdr.size = @intCast(total);
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
            _ = linux.munmap(hdr_ptr, hdr.size);
            return 1;
        }
    }
    return 1;
}

fn HeapReAlloc(hHeap: usize, dwFlags: u32, lpMem: ?*anyopaque, dwBytes: usize) callconv(W) ?*anyopaque {
    if (lpMem == null) return HeapAlloc(hHeap, dwFlags, dwBytes);
    const new_mem = HeapAlloc(hHeap, dwFlags, dwBytes) orelse return null;
    const u8_ptr: [*]const u8 = @ptrCast(lpMem.?);
    const hdr_ptr = u8_ptr - @sizeOf(HeapHeader);
    const hdr: *const HeapHeader = @ptrCast(@alignCast(hdr_ptr));
    if (hdr.magic == HEAP_MAGIC) {
        const old_user_size = hdr.size - @sizeOf(HeapHeader);
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
            return hdr.size - @sizeOf(HeapHeader);
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

fn VirtualAlloc(lpAddress: ?*anyopaque, dwSize: usize, flAllocationType: u32, flProtect: u32) callconv(W) ?*anyopaque {
    _ = flAllocationType;
    if (dwSize == 0) {
        g_last_error = 87; // ERROR_INVALID_PARAMETER
        return null;
    }
    const prot = linux.PROT{
        .READ = (flProtect & 0x66) != 0,
        .WRITE = (flProtect & 0x44) != 0,
        .EXEC = (flProtect & 0xF0) != 0,
    };
    const flags = linux.MAP{ .TYPE = .PRIVATE, .ANONYMOUS = true, .FIXED = (lpAddress != null) };
    const addr: ?[*]u8 = if (lpAddress) |a| @ptrCast(a) else null;
    const ptr = linux.mmap(addr, dwSize, prot, flags, -1, 0);
    if (linux.errno(ptr) != .SUCCESS) {
        g_last_error = 8; // ERROR_NOT_ENOUGH_MEMORY
        return null;
    }
    g_alloc_prot = flProtect;
    return @ptrFromInt(ptr);
}

fn VirtualFree(lpAddress: ?*anyopaque, dwSize: usize, dwFreeType: u32) callconv(W) i32 {
    _ = dwFreeType;
    if (lpAddress) |addr| {
        const u8_ptr: [*]const u8 = @ptrCast(addr);
        _ = linux.munmap(u8_ptr, if (dwSize == 0) 4096 else dwSize);
        return 1;
    }
    return 0;
}

fn VirtualProtect(lpAddress: ?*anyopaque, dwSize: usize, flNewProtect: u32, lpflOldProtect: ?*u32) callconv(W) i32 {
    if (lpflOldProtect) |old| old.* = g_alloc_prot;
    g_alloc_prot = flNewProtect;
    std.debug.print("[WINS:Kernel32] VirtualProtect(0x{x}, size={d}, prot=0x{x})\n", .{ @intFromPtr(lpAddress), dwSize, flNewProtect });
    if (lpAddress) |p| {
        const u8_ptr: [*]u8 = @constCast(@ptrCast(p));
        // Check if steamdrm.dll has been unpacked
        const sig = "\x0f\x85\xc5\x00\x00\x00";
        if (@intFromPtr(p) >= 0x1000 and @intFromPtr(p) < 0x70000000 and dwSize >= 0x4900) {
            if (std.mem.eql(u8, u8_ptr[0x4843..0x4849], sig)) {
                std.debug.print("[WINS:SteamDRM] Recognized steamdrm.dll in VirtualProtect at 0x{x}!\n", .{@intFromPtr(p)});
                _ = linux.mprotect(@ptrCast(u8_ptr), 0x10000, linux.PROT{ .READ = true, .WRITE = true, .EXEC = true });
                @memcpy(u8_ptr[0x4843..0x4849], "\xe9\xfe\x02\x00\x00\x90");
                std.debug.print("  [WINS:SteamDRM] Patched RSA ticket gate to direct AES in-RAM decryption!\n", .{});
            }
        }
        const prot = linux.PROT{
            .READ = (flNewProtect & 0x66) != 0,
            .WRITE = (flNewProtect & 0x44) != 0,
            .EXEC = (flNewProtect & 0xF0) != 0,
        };
        _ = linux.mprotect(u8_ptr, dwSize, prot);
        return 1;
    }
    return 0;
}

// ============================================================================
// File Mapping APIs & SteamStub IPC Simulation
// ============================================================================

var g_steam_shmem: [4096]u8 align(4096) = [_]u8{0} ** 4096;
var g_target_path: [512]u8 = [_]u8{0} ** 512;
var g_target_path_len: usize = 0;

fn OpenFileMappingA(dwDesiredAccess: u32, bInheritHandle: i32, lpName: ?[*:0]const u8) callconv(W) usize {
    _ = dwDesiredAccess; _ = bInheritHandle;
    const name = if (lpName) |n| std.mem.sliceTo(n, 0) else "null";
    std.debug.print("[WINS:Kernel32] OpenFileMappingA(\"{s}\")\n", .{name});
    if (std.mem.indexOf(u8, name, "SteamStart_SharedMemFile") != null) {
        std.debug.print("  [WINS:SteamDRM] Recognized SteamStart_SharedMemFile! Providing IPC mapping.\n", .{});
        return 0x30002;
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
    _ = dwDesiredAccess; _ = dwFileOffsetHigh; _ = dwFileOffsetLow;
    if (hFileMappingObject == 0x30002) {
        std.debug.print("[WINS:SteamDRM] MapViewOfFile(SteamStart_SharedMemFile) -> Initializing Steam IPC protocol block!\n", .{});
        // [buffer + 0x90] = 2 means "Steam client ready"
        // Leave [0x94] = 0 so DRM can write its own auth request (1 = pending)
        std.mem.writeInt(u32, g_steam_shmem[0x90..0x94], 2, .little);
        // [0x94] stays 0 — DRM writes 1 here to request validation
        std.mem.writeInt(u32, g_steam_shmem[0x94..0x98], 0, .little);
        return &g_steam_shmem;
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
    return @intCast(linux.gettid());
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

fn RaiseException(dwExceptionCode: u32, dwExceptionFlags: u32, nNumberOfArguments: u32, lpArguments: ?[*]const usize) callconv(W) noreturn {
    _ = dwExceptionFlags; _ = nNumberOfArguments; _ = lpArguments;
    std.debug.print("[WINS:Kernel32] RaiseException(0x{x:0>8})\n", .{dwExceptionCode});
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

fn CreateThread(lpThreadAttributes: ?*anyopaque, dwStackSize: usize, lpStartAddress: ?*anyopaque, lpParameter: ?*anyopaque, dwCreationFlags: u32, lpThreadId: ?*u32) callconv(W) usize {
    _ = lpThreadAttributes; _ = dwStackSize; _ = lpStartAddress; _ = lpParameter; _ = dwCreationFlags;
    if (lpThreadId) |tid| tid.* = 2;
    return 0x4001; // Valid thread handle
}

fn ResumeThread(hThread: usize) callconv(W) u32 {
    _ = hThread;
    return 1;
}

fn SuspendThread(hThread: usize) callconv(W) u32 {
    _ = hThread;
    return 0;
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
    _ = dwExitCode;
    linux.exit_group(0);
}

fn GetExitCodeThread(hThread: usize, lpExitCode: ?*u32) callconv(W) i32 {
    _ = hThread;
    if (lpExitCode) |code| code.* = 0;
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
    if (lpCriticalSection) |p| {
        const cs: *CriticalSection = @ptrCast(@alignCast(p));
        cs.DebugInfo = 0;
        cs.LockCount = -1;
        cs.RecursionCount = 0;
        cs.OwningThread = 0;
        cs.LockSemaphore = 0;
        cs.SpinCount = 0;
    }
}

fn InitializeCriticalSectionAndSpinCount(lpCriticalSection: ?*anyopaque, dwSpinCount: u32) callconv(W) i32 {
    if (lpCriticalSection) |p| {
        const cs: *CriticalSection = @ptrCast(@alignCast(p));
        cs.DebugInfo = 0;
        cs.LockCount = -1;
        cs.RecursionCount = 0;
        cs.OwningThread = 0;
        cs.LockSemaphore = 0;
        cs.SpinCount = dwSpinCount;
        return 1;
    }
    return 0;
}

fn EnterCriticalSection(lpCriticalSection: ?*anyopaque) callconv(W) void {
    if (lpCriticalSection) |p| {
        const cs: *CriticalSection = @ptrCast(@alignCast(p));
        const tid: u32 = 1;
        if (cs.LockCount >= 0 and cs.OwningThread == tid) {
            cs.RecursionCount += 1;
            cs.LockCount += 1;
        } else {
            cs.LockCount += 1;
            cs.OwningThread = tid;
            cs.RecursionCount = 1;
        }
    }
}

fn TryEnterCriticalSection(lpCriticalSection: ?*anyopaque) callconv(W) i32 {
    if (lpCriticalSection) |p| {
        const cs: *CriticalSection = @ptrCast(@alignCast(p));
        const tid: u32 = 1;
        if (cs.LockCount == -1 or cs.OwningThread == tid) {
            EnterCriticalSection(lpCriticalSection);
            return 1;
        }
    }
    return 0;
}

fn LeaveCriticalSection(lpCriticalSection: ?*anyopaque) callconv(W) void {
    if (lpCriticalSection) |p| {
        const cs: *CriticalSection = @ptrCast(@alignCast(p));
        if (cs.RecursionCount > 1) {
            cs.RecursionCount -= 1;
            cs.LockCount -= 1;
        } else {
            cs.OwningThread = 0;
            cs.RecursionCount = 0;
            cs.LockCount = -1;
        }
    }
}

fn DeleteCriticalSection(lpCriticalSection: ?*anyopaque) callconv(W) void {
    if (lpCriticalSection) |p| {
        const cs: *CriticalSection = @ptrCast(@alignCast(p));
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
    _ = lpEventAttributes; _ = bManualReset; _ = bInitialState;
    const name = if (lpName) |n| std.mem.sliceTo(n, 0) else "null";
    std.debug.print("[WINS:Kernel32] CreateEventA(\"{s}\")\n", .{name});
    return 0x2001;
}

fn OpenEventA(dwDesiredAccess: u32, bInheritHandle: i32, lpName: ?[*:0]const u8) callconv(W) usize {
    _ = dwDesiredAccess; _ = bInheritHandle;
    const name = if (lpName) |n| std.mem.sliceTo(n, 0) else "null";
    std.debug.print("[WINS:Kernel32] OpenEventA(\"{s}\")\n", .{name});
    if (std.mem.indexOf(u8, name, "SteamStart_SharedMemLock") != null) {
        std.debug.print("  [WINS:SteamDRM] Recognized SteamStart_SharedMemLock! Providing IPC event.\n", .{});
        return 0x2001;
    }
    return 0x2001;
}

fn CreateMutexA(lpMutexAttributes: ?*anyopaque, bInitialOwner: i32, lpName: ?[*:0]const u8) callconv(W) usize {
    _ = lpMutexAttributes; _ = bInitialOwner; _ = lpName;
    return 0x2002;
}

fn CreateSemaphoreA(lpSemaphoreAttributes: ?*anyopaque, lInitialCount: i32, lMaximumCount: i32, lpName: ?[*:0]const u8) callconv(W) usize {
    _ = lpSemaphoreAttributes; _ = lInitialCount; _ = lMaximumCount; _ = lpName;
    return 0x2003;
}

fn SetEvent(hEvent: usize) callconv(W) i32 {
    std.debug.print("[WINS:Kernel32] SetEvent(0x{x})\n", .{hEvent});
    return 1;
}

fn ResetEvent(hEvent: usize) callconv(W) i32 {
    std.debug.print("[WINS:Kernel32] ResetEvent(0x{x})\n", .{hEvent});
    return 1;
}

fn WaitForSingleObject(hHandle: usize, dwMilliseconds: u32) callconv(W) u32 {
    std.debug.print("[WINS:Kernel32] WaitForSingleObject(0x{x}, {d})\n", .{ hHandle, dwMilliseconds });
    std.debug.print("  g_steam_shmem dump: ", .{});
    for (0..64) |i| {
        const val = std.mem.readInt(u32, g_steam_shmem[i * 4 ..][0..4], .little);
        if (val != 0) {
            std.debug.print("[0x{x}]=0x{x:0>8} ", .{ i * 4, val });
        }
    }
    std.debug.print("\n", .{});

    // Check if SteamStub wrote an auth request to g_steam_shmem!
    const req_status = std.mem.readInt(u32, g_steam_shmem[0x94..][0..4], .little);
    std.debug.print("  [SteamDRM] shmem[0x94]={d} (1=pending_auth 0=idle 2=done)\n", .{req_status});
    // steamdrm.dll writes 2 as the "auth request pending" signal (not 1)
    if (req_status != 0) {
        const pid = std.mem.readInt(u32, g_steam_shmem[0x98..][0..4], .little);
        const event_h = std.mem.readInt(u32, g_steam_shmem[0x9c..][0..4], .little);
        const token = std.mem.readInt(u32, g_steam_shmem[0xa4..][0..4], .little);
        const target_addr = std.mem.readInt(u32, g_steam_shmem[0xac..][0..4], .little);

        std.debug.print("[WINS:SteamDRM] Intercepted SteamStub Auth Handshake:\n", .{});
        std.debug.print("  Target Process PID: {}\n", .{pid});
        std.debug.print("  Event Handle:       0x{x}\n", .{event_h});
        std.debug.print("  Validation Token:   0x{x:0>8}\n", .{token});
        std.debug.print("  Target Pointer:     0x{x:0>8}\n", .{target_addr});

        if (target_addr != 0) {
            // The target is a stack address in the guest process — ensure it's writable.
            // mprotect the page containing it RWX before writing.
            const page_addr = target_addr & ~@as(u32, 0xFFF);
            const page_ptr: [*]u8 = @ptrFromInt(page_addr);
            _ = linux.mprotect(page_ptr, 4096, linux.PROT{ .READ = true, .WRITE = true, .EXEC = true });
            const target_ptr: *u32 = @ptrFromInt(target_addr);
            target_ptr.* = token;
            std.debug.print("  [WINS:SteamDRM] Injected token 0x{x:0>8} @ 0x{x:0>8} -> SteamStub unlocked!\n", .{ token, target_addr });
        }

        // Mark request as processed by Steam client
        std.mem.writeInt(u32, g_steam_shmem[0x94..][0..4], 2, .little);    }
    return 0; // WAIT_OBJECT_0
}

fn WaitForMultipleObjects(nCount: u32, lpHandles: ?[*]const usize, bWaitAll: i32, dwMilliseconds: u32) callconv(W) u32 {
    _ = nCount; _ = lpHandles; _ = bWaitAll; _ = dwMilliseconds;
    return 0; // WAIT_OBJECT_0
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
    if (hObject >= 0x10000 and hObject < 0x20000) {
        const fd: i32 = @intCast(hObject - 0x10000);
        _ = linux.close(fd);
    }
    return 1;
}

fn CreateFileA(lpFileName: ?[*:0]const u8, dwDesiredAccess: u32, dwShareMode: u32, lpSecurityAttributes: ?*anyopaque, dwCreationDisposition: u32, dwFlagsAndAttributes: u32, hTemplateFile: usize) callconv(W) usize {
    _ = dwDesiredAccess; _ = dwShareMode; _ = lpSecurityAttributes; _ = dwCreationDisposition; _ = dwFlagsAndAttributes; _ = hTemplateFile;
    if (lpFileName) |fn_ptr| {
        const path = std.mem.sliceTo(fn_ptr, 0);
        std.debug.print("[WINS:Kernel32] CreateFileA(\"{s}\")\n", .{path});
        var norm_buf: [512]u8 = undefined;
        const norm_len = @min(norm_buf.len - 1, path.len);
        for (0..norm_len) |i| {
            norm_buf[i] = if (path[i] == '\\') '/' else path[i];
        }
        norm_buf[norm_len] = 0;
        const norm_slice = norm_buf[0..norm_len:0];

        // 1. Try opening normalized path directly
        const fd = linux.open(norm_slice.ptr, .{ .ACCMODE = .RDWR }, 0);
        if (linux.errno(fd) == .SUCCESS) {
            std.debug.print("  -> SUCCESS fd={}\n", .{fd});
            return @as(usize, @intCast(fd)) + 0x10000;
        }
        const fd_ro = linux.open(norm_slice.ptr, .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(fd_ro) == .SUCCESS) {
            std.debug.print("  -> SUCCESS [RO] fd={}\n", .{fd_ro});
            return @as(usize, @intCast(fd_ro)) + 0x10000;
        }

        // 2. Try basename in current working directory
        const basename = if (std.mem.lastIndexOfScalar(u8, norm_slice, '/')) |s| norm_slice[s + 1 ..] else norm_slice;
        if (basename.len > 0) {
            var base_buf: [256]u8 = undefined;
            const b_len = @min(base_buf.len - 1, basename.len);
            @memcpy(base_buf[0..b_len], basename[0..b_len]);
            base_buf[b_len] = 0;
            const base_slice = base_buf[0..b_len:0];

            const fd_b = linux.open(base_slice.ptr, .{ .ACCMODE = .RDONLY }, 0);
            if (linux.errno(fd_b) == .SUCCESS) {
                std.debug.print("  -> SUCCESS [Basename RO: {s}] fd={}\n", .{ base_slice, fd_b });
                return @as(usize, @intCast(fd_b)) + 0x10000;
            }
        }

        // 3. Fallback to target executable if requested
        if (g_target_path_len > 0) {
            const fd_t = linux.open(g_target_path[0..g_target_path_len:0].ptr, .{ .ACCMODE = .RDONLY }, 0);
            if (linux.errno(fd_t) == .SUCCESS) {
                std.debug.print("  -> SUCCESS [Target Executable RO] fd={}\n", .{fd_t});
                return @as(usize, @intCast(fd_t)) + 0x10000;
            }
        }
    }
    std.debug.print("  -> FAILED (not found)\n", .{});
    g_last_error = 2; // ERROR_FILE_NOT_FOUND
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

        const rc = linux.faccessat(linux.AT.FDCWD, norm_slice.ptr, 0, 0);
        std.debug.print("[WINS:Kernel32] GetFileAttributesA(\"{s}\") -> rc={}\n", .{ norm_slice, rc });
        if (rc == 0) return 0x80; // FILE_ATTRIBUTE_NORMAL
    }
    g_last_error = 2; // ERROR_FILE_NOT_FOUND
    return 0xFFFFFFFF;
}

fn DeleteFileA(lpFileName: ?[*:0]const u8) callconv(W) i32 {
    _ = lpFileName;
    return 1;
}

fn MoveFileA(lpExistingFileName: ?[*:0]const u8, lpNewFileName: ?[*:0]const u8) callconv(W) i32 {
    _ = lpExistingFileName; _ = lpNewFileName;
    return 1;
}

fn CopyFileA(lpExistingFileName: ?[*:0]const u8, lpNewFileName: ?[*:0]const u8, bFailIfExists: i32) callconv(W) i32 {
    _ = lpExistingFileName; _ = lpNewFileName; _ = bFailIfExists;
    return 1;
}

fn CreateDirectoryA(lpPathName: ?[*:0]const u8, lpSecurityAttributes: ?*anyopaque) callconv(W) i32 {
    _ = lpPathName; _ = lpSecurityAttributes;
    return 1;
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

fn GetPrivateProfileStringA(lpAppName: ?[*:0]const u8, lpKeyName: ?[*:0]const u8, lpDefault: ?[*:0]const u8, lpReturnedString: ?[*]u8, nSize: u32, lpFileName: ?[*:0]const u8) callconv(W) u32 {
    _ = lpAppName; _ = lpKeyName; _ = lpFileName;
    if (lpReturnedString == null or nSize == 0) return 0;
    if (lpDefault) |def| {
        const slice = std.mem.sliceTo(def, 0);
        const len: u32 = @min(nSize - 1, @as(u32, @intCast(slice.len)));
        @memcpy(lpReturnedString.?[0..len], slice[0..len]);
        lpReturnedString.?[len] = 0;
        return len;
    }
    lpReturnedString.?[0] = 0;
    return 0;
}

fn GetPrivateProfileIntA(lpAppName: ?[*:0]const u8, lpKeyName: ?[*:0]const u8, nDefault: i32, lpFileName: ?[*:0]const u8) callconv(W) i32 {
    _ = lpAppName; _ = lpKeyName; _ = lpFileName;
    return nDefault;
}

fn WritePrivateProfileStringA(lpAppName: ?[*:0]const u8, lpKeyName: ?[*:0]const u8, lpString: ?[*:0]const u8, lpFileName: ?[*:0]const u8) callconv(W) i32 {
    _ = lpAppName; _ = lpKeyName; _ = lpString; _ = lpFileName;
    return 1;
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

fn FindFirstFileA(lpFileName: ?[*:0]const u8, lpFindFileData: ?*anyopaque) callconv(W) usize {
    _ = lpFileName;
    if (lpFindFileData) |p| {
        const fd: *WIN32_FIND_DATAA = @ptrCast(@alignCast(p));
        @memset(@as([*]u8, @ptrCast(fd))[0..@sizeOf(WIN32_FIND_DATAA)], 0);
        fd.dwFileAttributes = 0x80; // FILE_ATTRIBUTE_NORMAL
        @memcpy(fd.cFileName[0..13], "FalloutNV.exe");
        return 0x5001; // Valid find handle
    }
    g_last_error = 2;
    return 0xFFFFFFFF;
}

fn FindNextFileA(hFindFile: usize, lpFindFileData: ?*anyopaque) callconv(W) i32 {
    _ = hFindFile; _ = lpFindFileData;
    g_last_error = 18; // ERROR_NO_MORE_FILES
    return 0;
}

fn FindClose(hFindFile: usize) callconv(W) i32 {
    _ = hFindFile;
    return 1;
}

fn GetFileType(hFile: usize) callconv(W) u32 {
    _ = hFile;
    return 2; // FILE_TYPE_CHAR (console)
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
    const in_len: usize = if (cbMultiByte < 0) std.mem.indexOfScalar(u8, std.mem.sliceTo(src, 0), 0) orelse 0 + 1 else @intCast(cbMultiByte);
    if (cchWideChar == 0) return @intCast(in_len);
    if (lpWideCharStr == null) return 0;
    const dst = lpWideCharStr.?;
    const out_max: usize = @intCast(cchWideChar);
    const n = @min(in_len, out_max);
    for (0..n) |i| {
        dst[i] = src[i];
    }
    return @intCast(n);
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
    _ = Locale; _ = dwMapFlags;
    if (lpSrcStr == null) return 0;
    const in_len: usize = if (cchSrc < 0) std.mem.indexOfScalar(u8, std.mem.sliceTo(lpSrcStr.?, 0), 0) orelse 0 + 1 else @intCast(cchSrc);
    if (cchDest == 0) return @intCast(in_len);
    if (lpDestStr == null) return 0;
    const n = @min(in_len, @as(usize, @intCast(cchDest)));
    @memcpy(lpDestStr.?[0..n], lpSrcStr.?[0..n]);
    return @intCast(n);
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
    const s1_len = std.mem.indexOfScalar(u8, std.mem.sliceTo(lpString1.?, 0), 0) orelse 0;
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
    std.debug.print("[WINS:SteamAPI] SteamAPI_Init() called -> Bypass ACTIVE, returning TRUE (1)!\n", .{});
    return 1;
}

fn SteamAPI_IsSteamRunning() callconv(W) i32 {
    return 1;
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

var g_steam_dummy_vtable: [16]*const anyopaque = [_]*const anyopaque{@ptrCast(&unhandledApiStub)} ** 16;
var g_steam_dummy_obj: [1]*anyopaque = [_]*anyopaque{@ptrCast(&g_steam_dummy_vtable)};

// ============================================================================
// Steamworks COM Interface Vtables (ISteamClient010 / steamdrm.dll gate)
// ============================================================================
//
// steamdrm.dll calls:
//   GetProcAddress(hSteamClient, "CreateInterface")
//   CreateInterface("SteamClient010", null)
//   -> vtable->CreateSteamPipe()          slot 0
//   -> vtable->ConnectToGlobalUser(pipe)  slot 2
//   -> vtable->GetISteamUser(...)         slot 5  -> ISteamUser016
//   -> vtable->GetISteamGenericInterface("SteamUtils005") slot 9 -> ISteamUtils005
//   -> vtable->GetISteamAppTicket(...)    slot 13 -> ISteamAppTicket001
//   ISteamUtils005::GetAppID()            slot 9  -> 22380
//   ISteamUser016::GetSteamID(pID)        slot 2  -> 76561198175888903
//   ISteamAppTicket001::GetAppOwnershipTicketData() slot 0 -> >0

// ---- ISteamUtils005 (slot 9 = GetAppID) ------------------------------------
// All vtable methods use __thiscall: ECX = this, args on stack
fn steamutils005_stub() callconv(.{ .x86_thiscall = .{} }) u32 { return 0; }
fn steamutils005_GetAppID(_self: usize) callconv(.{ .x86_thiscall = .{} }) u32 {
    _ = _self;
    std.debug.print("[WINS:Steam] ISteamUtils005::GetAppID() -> 22380\n", .{});
    return 22380;
}

var g_steamutils005_vtable: [16]*const anyopaque = blk: {
    var v = [_]*const anyopaque{@ptrCast(&steamutils005_stub)} ** 16;
    v[9] = @ptrCast(&steamutils005_GetAppID);
    break :blk v;
};
var g_steamutils005_obj: [1]*anyopaque = [_]*anyopaque{@ptrCast(&g_steamutils005_vtable)};

// ---- ISteamUser016 (slot 2 = GetSteamID writes u64) ------------------------
fn steamuser016_stub() callconv(.{ .x86_thiscall = .{} }) u32 { return 0; }
fn steamuser016_GetSteamID(_self: usize, pSteamID: ?*u64) callconv(.{ .x86_thiscall = .{} }) void {
    _ = _self;
    if (pSteamID) |p| p.* = 76561198175888903;
    std.debug.print("[WINS:Steam] ISteamUser016::GetSteamID() -> 76561198175888903\n", .{});
}

var g_steamuser016_vtable: [16]*const anyopaque = blk: {
    var v = [_]*const anyopaque{@ptrCast(&steamuser016_stub)} ** 16;
    v[2] = @ptrCast(&steamuser016_GetSteamID);
    break :blk v;
};
var g_steamuser016_obj: [1]*anyopaque = [_]*anyopaque{@ptrCast(&g_steamuser016_vtable)};

// ---- ISteamAppTicket001 (slot 0 = GetAppOwnershipTicketData) ----------------
// Signature (thiscall): uint GetAppOwnershipTicketData(AppId_t nAppID,
//   void *pvBuffer, uint cbBufferLength,
//   uint *piAppId, uint *piSteamId, uint *piSignature, uint *pcbSignature)
var g_ticket_buf: [256]u8 = [_]u8{0xAB} ** 256;
fn steamappticket001_GetAppOwnershipTicketData(
    _self: usize,
    _nAppID: u32,
    pvBuffer: ?[*]u8,
    cbBufferLength: u32,
    piAppId: ?*u32,
    piSteamId: ?*u32,
    piSignature: ?*u32,
    pcbSignature: ?*u32,
) callconv(.{ .x86_thiscall = .{} }) u32 {
    _ = _self; _ = _nAppID;
    std.debug.print("[WINS:Steam] ISteamAppTicket001::GetAppOwnershipTicketData() -> synthetic ticket\n", .{});
    const copy_len = @min(cbBufferLength, 128);
    if (pvBuffer) |buf| @memcpy(buf[0..copy_len], g_ticket_buf[0..copy_len]);
    if (piAppId) |p| p.* = 22380;
    if (piSteamId) |p| p.* = @truncate(76561198175888903 & 0xFFFFFFFF);
    if (piSignature) |p| p.* = copy_len; // offset where "signature" starts
    if (pcbSignature) |p| p.* = 16;    // 16-byte dummy sig length
    return copy_len;
}
fn steamappticket001_stub() callconv(.{ .x86_thiscall = .{} }) u32 { return 0; }

var g_steamappticket001_vtable: [4]*const anyopaque = blk: {
    var v = [_]*const anyopaque{@ptrCast(&steamappticket001_stub)} ** 4;
    v[0] = @ptrCast(&steamappticket001_GetAppOwnershipTicketData);
    break :blk v;
};
var g_steamappticket001_obj: [1]*anyopaque = [_]*anyopaque{@ptrCast(&g_steamappticket001_vtable)};

// ---- ISteamClient010 (slots 0,1,2,4,5,9,13) --------------------------------
fn steamclient010_CreateSteamPipe(_self: usize) callconv(.{ .x86_thiscall = .{} }) u32 {
    _ = _self;
    std.debug.print("[WINS:Steam] ISteamClient010::CreateSteamPipe() -> 1\n", .{});
    return 1;
}
fn steamclient010_BReleaseSteamPipe(_self: usize, hSteamPipe: u32) callconv(.{ .x86_thiscall = .{} }) i32 {
    _ = _self; _ = hSteamPipe;
    return 1;
}
fn steamclient010_ConnectToGlobalUser(_self: usize, hSteamPipe: u32) callconv(.{ .x86_thiscall = .{} }) u32 {
    _ = _self; _ = hSteamPipe;
    std.debug.print("[WINS:Steam] ISteamClient010::ConnectToGlobalUser() -> 1\n", .{});
    return 1;
}
fn steamclient010_ReleaseUser(_self: usize, hSteamPipe: u32, hUser: u32) callconv(.{ .x86_thiscall = .{} }) void {
    _ = _self; _ = hSteamPipe; _ = hUser;
}
fn steamclient010_GetISteamUser(
    _self: usize, hSteamUser: u32, hSteamPipe: u32, pchVersion: ?[*:0]const u8,
) callconv(.{ .x86_thiscall = .{} }) ?*anyopaque {
    _ = _self; _ = hSteamUser; _ = hSteamPipe;
    const ver = if (pchVersion) |v| std.mem.sliceTo(v, 0) else "?";
    std.debug.print("[WINS:Steam] ISteamClient010::GetISteamUser(\"{s}\") -> &ISteamUser016\n", .{ver});
    return &g_steamuser016_obj;
}
fn steamclient010_GetISteamGenericInterface(
    _self: usize, hSteamUser: u32, hSteamPipe: u32, pchVersion: ?[*:0]const u8,
) callconv(.{ .x86_thiscall = .{} }) ?*anyopaque {
    _ = _self; _ = hSteamUser; _ = hSteamPipe;
    const ver = if (pchVersion) |v| std.mem.sliceTo(v, 0) else "?";
    std.debug.print("[WINS:Steam] ISteamClient010::GetISteamGenericInterface(\"{s}\")\n", .{ver});
    if (std.mem.startsWith(u8, ver, "SteamUtils")) return &g_steamutils005_obj;
    return &g_steam_dummy_obj;
}
fn steamclient010_GetISteamAppTicket(
    _self: usize, hSteamUser: u32, hSteamPipe: u32, pchVersion: ?[*:0]const u8,
) callconv(.{ .x86_thiscall = .{} }) ?*anyopaque {
    _ = _self; _ = hSteamUser; _ = hSteamPipe;
    const ver = if (pchVersion) |v| std.mem.sliceTo(v, 0) else "?";
    std.debug.print("[WINS:Steam] ISteamClient010::GetISteamAppTicket(\"{s}\") -> &ISteamAppTicket001\n", .{ver});
    return &g_steamappticket001_obj;
}
fn steamclient010_stub() callconv(.{ .x86_thiscall = .{} }) u32 { return 0; }

var g_steamclient010_vtable: [16]*const anyopaque = blk: {
    var v = [_]*const anyopaque{@ptrCast(&steamclient010_stub)} ** 16;
    v[0]  = @ptrCast(&steamclient010_CreateSteamPipe);
    v[1]  = @ptrCast(&steamclient010_BReleaseSteamPipe);
    v[2]  = @ptrCast(&steamclient010_ConnectToGlobalUser);
    v[4]  = @ptrCast(&steamclient010_ReleaseUser);
    v[5]  = @ptrCast(&steamclient010_GetISteamUser);
    v[9]  = @ptrCast(&steamclient010_GetISteamGenericInterface);
    v[13] = @ptrCast(&steamclient010_GetISteamAppTicket);
    break :blk v;
};
var g_steamclient010_obj: [1]*anyopaque = [_]*anyopaque{@ptrCast(&g_steamclient010_vtable)};

// ---- CreateInterface (exported from steamclient.dll) -----------------------
// Called with cdecl from steamdrm.dll: CreateInterface(pName, pReturnCode)
fn steamclient_CreateInterface(pName: ?[*:0]const u8, pReturnCode: ?*i32) callconv(.c) ?*anyopaque {
    if (pReturnCode) |rc| rc.* = 0;
    const name = if (pName) |n| std.mem.sliceTo(n, 0) else "";
    std.debug.print("[WINS:Steam] CreateInterface(\"{s}\")\n", .{name});
    if (std.mem.startsWith(u8, name, "SteamClient")) return &g_steamclient010_obj;
    if (std.mem.startsWith(u8, name, "SteamUtils"))  return &g_steamutils005_obj;
    if (std.mem.startsWith(u8, name, "SteamUser"))   return &g_steamuser016_obj;
    if (std.mem.startsWith(u8, name, "STEAMAPPTICKET")) return &g_steamappticket001_obj;
    std.debug.print("  -> UNHANDLED interface \"{s}\", returning dummy\n", .{name});
    return &g_steam_dummy_obj;
}

// ============================================================================
// steam_api.dll flat C exports
// ============================================================================

fn SteamApps() callconv(W) ?*anyopaque {
    return &g_steam_dummy_obj;
}

fn SteamFriends() callconv(W) ?*anyopaque {
    return &g_steam_dummy_obj;
}

fn SteamUser() callconv(W) ?*anyopaque {
    return &g_steamuser016_obj;
}

fn SteamUserStats() callconv(W) ?*anyopaque {
    return &g_steam_dummy_obj;
}

fn SteamUtils() callconv(W) ?*anyopaque {
    return &g_steamutils005_obj;
}

// ============================================================================
// Bink Video Shims (binkw32.dll)
// ============================================================================

fn BinkOpen(name: ?[*:0]const u8, flags: u32) callconv(W) usize {
    _ = flags;
    if (name) |n| {
        std.debug.print("[WINS:BinkVideo] _BinkOpen(\"{s}\") -> Video bypassed to menu.\n", .{std.mem.sliceTo(n, 0)});
    }
    return 0xB14C0001; // Valid dummy Bink handle
}

fn BinkClose(bink: usize) callconv(W) void {
    _ = bink;
}

fn BinkDoFrame(bink: usize) callconv(W) i32 {
    _ = bink;
    return 0; // Completed
}

fn BinkNextFrame(bink: usize) callconv(W) void {
    _ = bink;
}

fn BinkWait(bink: usize) callconv(W) i32 {
    _ = bink;
    return 0; // No wait
}

fn BinkPause(bink: usize, pause: i32) callconv(W) i32 {
    _ = bink; _ = pause;
    return 0;
}

fn BinkCopyToBufferRect() callconv(W) i32 {
    return 0;
}

fn BinkOpenDirectSound(bink: usize) callconv(W) i32 {
    _ = bink;
    return 0;
}

fn BinkSetSoundSystem(open_fn: ?*anyopaque, param: usize) callconv(W) i32 {
    _ = open_fn; _ = param;
    return 0;
}

// ============================================================================
// User32 GUI Shims
// ============================================================================

fn GetSystemMetrics(nIndex: i32) callconv(W) i32 {
    if (nIndex == 0) return 1920; // SM_CXSCREEN
    if (nIndex == 1) return 1080; // SM_CYSCREEN
    return 0;
}

fn GetDesktopWindow() callconv(W) usize {
    return 0x10001;
}

fn GetActiveWindow() callconv(W) usize {
    return 0x10002;
}

fn GetForegroundWindow() callconv(W) usize {
    return 0x10002;
}

fn FindWindowA(lpClass: ?[*:0]const u8, lpWindow: ?[*:0]const u8) callconv(W) usize {
    _ = lpClass; _ = lpWindow;
    return 0;
}

fn CreateWindowExA(
    dwExStyle: u32,
    lpClassName: ?[*:0]const u8,
    lpWindowName: ?[*:0]const u8,
    dwStyle: u32,
    x: i32,
    y: i32,
    nWidth: i32,
    nHeight: i32,
    hWndParent: usize,
    hMenu: usize,
    hInstance: usize,
    lpParam: ?*anyopaque,
) callconv(W) usize {
    _ = dwExStyle; _ = dwStyle; _ = x; _ = y; _ = hWndParent; _ = hMenu; _ = hInstance; _ = lpParam;
    const win_title = if (lpWindowName) |w| std.mem.sliceTo(w, 0) else "Game";
    std.debug.print("[WINS:User32] CreateWindowExA(\"{s}\", size: {}x{}) -> HWND 0x20001 created!\n", .{
        win_title, nWidth, nHeight,
    });
    _ = lpClassName;
    return 0x20001; // Valid HWND handle
}

fn DefWindowProcA(hWnd: usize, Msg: u32, wParam: usize, lParam: usize) callconv(W) usize {
    _ = hWnd; _ = Msg; _ = wParam; _ = lParam;
    return 0;
}

fn RegisterClassA(lpWndClass: ?*anyopaque) callconv(W) u16 {
    _ = lpWndClass;
    return 0xC001;
}

fn ShowWindow(hWnd: usize, nCmdShow: i32) callconv(W) i32 {
    _ = hWnd; _ = nCmdShow;
    return 1;
}

fn UpdateWindow(hWnd: usize) callconv(W) i32 {
    _ = hWnd;
    return 1;
}

fn SetFocus(hWnd: usize) callconv(W) usize {
    return hWnd;
}

fn SetForegroundWindow(hWnd: usize) callconv(W) i32 {
    _ = hWnd;
    return 1;
}

fn GetClientRect(hWnd: usize, lpRect: ?*d3d9.D3DRECT) callconv(W) i32 {
    _ = hWnd;
    if (lpRect) |r| {
        r.x1 = 0; r.y1 = 0; r.x2 = 1280; r.y2 = 720;
    }
    return 1;
}

fn GetWindowRect(hWnd: usize, lpRect: ?*d3d9.D3DRECT) callconv(W) i32 {
    return GetClientRect(hWnd, lpRect);
}

fn AdjustWindowRect(lpRect: ?*anyopaque, dwStyle: u32, bMenu: i32) callconv(W) i32 {
    _ = lpRect; _ = dwStyle; _ = bMenu;
    return 1;
}

fn AdjustWindowRectEx(lpRect: ?*anyopaque, dwStyle: u32, bMenu: i32, dwEx: u32) callconv(W) i32 {
    _ = lpRect; _ = dwStyle; _ = bMenu; _ = dwEx;
    return 1;
}

fn PeekMessageA(lpMsg: ?*anyopaque, hWnd: usize, wMin: u32, wMax: u32, wRemove: u32) callconv(W) i32 {
    _ = lpMsg; _ = hWnd; _ = wMin; _ = wMax; _ = wRemove;
    return 0; // No messages waiting
}

fn GetMessageA(lpMsg: ?*anyopaque, hWnd: usize, wMin: u32, wMax: u32) callconv(W) i32 {
    _ = lpMsg; _ = hWnd; _ = wMin; _ = wMax;
    return 0;
}

fn TranslateMessage(lpMsg: ?*anyopaque) callconv(W) i32 {
    _ = lpMsg;
    return 0;
}

fn DispatchMessageA(lpMsg: ?*anyopaque) callconv(W) usize {
    _ = lpMsg;
    return 0;
}

fn SendMessageA(hWnd: usize, Msg: u32, wParam: usize, lParam: usize) callconv(W) usize {
    _ = hWnd; _ = Msg; _ = wParam; _ = lParam;
    return 0;
}

fn DestroyWindow(hWnd: usize) callconv(W) i32 {
    _ = hWnd;
    return 1;
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

fn SetWindowPos(hWnd: usize, hWndInsertAfter: usize, X: i32, Y: i32, cx: i32, cy: i32, uFlags: u32) callconv(W) i32 {
    _ = hWnd; _ = hWndInsertAfter; _ = X; _ = Y; _ = cx; _ = cy; _ = uFlags;
    return 1;
}

fn GetWindow(hWnd: usize, uCmd: u32) callconv(W) usize {
    _ = hWnd; _ = uCmd;
    return 0;
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

fn GetWindowTextA(hWnd: usize, lpString: ?[*]u8, nMaxCount: i32) callconv(W) i32 {
    _ = hWnd;
    if (lpString == null or nMaxCount <= 0) return 0;
    const txt = "Fallout: New Vegas";
    const len: usize = @min(@as(usize, @intCast(nMaxCount - 1)), txt.len);
    @memcpy(lpString.?[0..len], txt[0..len]);
    lpString.?[len] = 0;
    return @intCast(len);
}

fn SetWindowTextA(hWnd: usize, lpString: ?[*:0]const u8) callconv(W) i32 {
    _ = hWnd; _ = lpString;
    return 1;
}

fn GetClassNameA(hWnd: usize, lpClassName: ?[*]u8, nMaxCount: i32) callconv(W) i32 {
    _ = hWnd;
    if (lpClassName == null or nMaxCount <= 0) return 0;
    const cls = "BethesdaWindowClass";
    const len: usize = @min(@as(usize, @intCast(nMaxCount - 1)), cls.len);
    @memcpy(lpClassName.?[0..len], cls[0..len]);
    lpClassName.?[len] = 0;
    return @intCast(len);
}

fn SendInput(cInputs: u32, pInputs: ?*anyopaque, cbSize: i32) callconv(W) u32 {
    _ = pInputs; _ = cbSize;
    return cInputs;
}

fn EnumChildWindows(hWndParent: usize, lpEnumFunc: ?*anyopaque, lParam: usize) callconv(W) i32 {
    _ = hWndParent; _ = lpEnumFunc; _ = lParam;
    return 1;
}

fn GetWindowLongA(hWnd: usize, nIndex: i32) callconv(W) usize {
    _ = hWnd; _ = nIndex;
    return 0;
}

fn GetClassLongA(hWnd: usize, nIndex: i32) callconv(W) usize {
    _ = hWnd; _ = nIndex;
    return 0;
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
    _ = vKey;
    return 0;
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

fn CoCreateInstance(rclsid: ?*anyopaque, pUnkOuter: ?*anyopaque, dwClsContext: u32, riid: ?*anyopaque, ppv: ?*?*anyopaque) callconv(W) i32 {
    _ = rclsid; _ = pUnkOuter; _ = dwClsContext; _ = riid;
    if (ppv) |p| p.* = null;
    return 0; // S_OK
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

fn ShellExecuteA(hwnd: usize, lpOperation: ?[*:0]const u8, lpFile: ?[*:0]const u8, lpParameters: ?[*:0]const u8, lpDirectory: ?[*:0]const u8, nShowCmd: i32) callconv(W) usize {
    _ = hwnd; _ = lpOperation; _ = lpFile; _ = lpParameters; _ = lpDirectory; _ = nShowCmd;
    return 42; // Success
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

fn RegQueryValueExA(hKey: usize, lpValueName: ?[*:0]const u8, lpReserved: ?*u32, lpType: ?*u32, lpData: ?[*]u8, lpcbData: ?*u32) callconv(W) i32 {
    _ = hKey; _ = lpReserved;
    const name = if (lpValueName) |vn| std.mem.sliceTo(vn, 0) else "";
    std.debug.print("[WINS:Advapi32] RegQueryValueExA(\"{s}\")\n", .{name});

    if (std.ascii.eqlIgnoreCase(name, "pid")) {
        if (lpType) |t| t.* = 4; // REG_DWORD
        if (lpData) |d| std.mem.writeInt(u32, d[0..4], 1337, .little);
        if (lpcbData) |cb| cb.* = 4;
        return 0;
    }
    if (std.ascii.eqlIgnoreCase(name, "SteamClientDll")) {
        const val = "steamclient.dll\x00";
        if (lpType) |t| t.* = 1; // REG_SZ
        if (lpcbData) |cb| {
            if (lpData) |d| @memcpy(d[0..val.len], val);
            cb.* = @intCast(val.len);
        }
        return 0;
    }
    if (std.ascii.eqlIgnoreCase(name, "SteamExe") or std.ascii.eqlIgnoreCase(name, "SteamPath")) {
        const val = "C:\\Program Files\\Steam\\Steam.exe\x00";
        if (lpType) |t| t.* = 1; // REG_SZ
        if (lpcbData) |cb| {
            if (lpData) |d| @memcpy(d[0..val.len], val);
            cb.* = @intCast(val.len);
        }
        return 0;
    }
    if (std.ascii.eqlIgnoreCase(name, "ActiveUser") or std.ascii.eqlIgnoreCase(name, "Universe")) {
        if (lpType) |t| t.* = 4; // REG_DWORD
        if (lpData) |d| std.mem.writeInt(u32, d[0..4], 1, .little);
        if (lpcbData) |cb| cb.* = 4;
        return 0;
    }
    if (std.ascii.eqlIgnoreCase(name, "Installed Path")) {
        const val = "./\x00";
        if (lpType) |t| t.* = 1; // REG_SZ
        if (lpcbData) |cb| {
            if (lpData) |d| @memcpy(d[0..val.len], val);
            cb.* = @intCast(val.len);
        }
        return 0;
    }

    if (lpcbData) |cb| cb.* = 0;
    return 2; // ERROR_FILE_NOT_FOUND
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

fn DirectInput8Create(hinst: usize, dwVersion: u32, riidltf: ?*anyopaque, ppvOut: ?*?*anyopaque, punkOuter: ?*anyopaque) callconv(W) i32 {
    _ = hinst; _ = dwVersion; _ = riidltf; _ = punkOuter;
    if (ppvOut) |p| p.* = null;
    return 0; // DI_OK
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
        if (std.mem.eql(u8, name, "SetEvent")) return @ptrCast(&dummySuccess);
        if (std.mem.eql(u8, name, "ResetEvent")) return @ptrCast(&dummySuccess);
        if (std.mem.eql(u8, name, "CreateMutexA")) return @ptrCast(&CreateMutexA);
        if (std.mem.eql(u8, name, "ReleaseMutex")) return @ptrCast(&dummySuccess);
        if (std.mem.eql(u8, name, "CreateSemaphoreA")) return @ptrCast(&CreateSemaphoreA);
        if (std.mem.eql(u8, name, "ReleaseSemaphore")) return @ptrCast(&dummySuccess);
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
        if (std.mem.eql(u8, name, "GetSystemMetrics")) return @ptrCast(&GetSystemMetrics);
        if (std.mem.eql(u8, name, "GetDesktopWindow")) return @ptrCast(&GetDesktopWindow);
        if (std.mem.eql(u8, name, "GetActiveWindow")) return @ptrCast(&GetActiveWindow);
        if (std.mem.eql(u8, name, "GetForegroundWindow")) return @ptrCast(&GetForegroundWindow);
        if (std.mem.eql(u8, name, "FindWindowA")) return @ptrCast(&FindWindowA);
        if (std.mem.eql(u8, name, "CreateWindowExA")) return @ptrCast(&CreateWindowExA);
        if (std.mem.eql(u8, name, "DefWindowProcA")) return @ptrCast(&DefWindowProcA);
        if (std.mem.eql(u8, name, "RegisterClassA")) return @ptrCast(&RegisterClassA);
        if (std.mem.eql(u8, name, "ShowWindow")) return @ptrCast(&ShowWindow);
        if (std.mem.eql(u8, name, "UpdateWindow")) return @ptrCast(&UpdateWindow);
        if (std.mem.eql(u8, name, "SetFocus")) return @ptrCast(&SetFocus);
        if (std.mem.eql(u8, name, "SetForegroundWindow")) return @ptrCast(&SetForegroundWindow);
        if (std.mem.eql(u8, name, "GetClientRect")) return @ptrCast(&GetClientRect);
        if (std.mem.eql(u8, name, "GetWindowRect")) return @ptrCast(&GetWindowRect);
        if (std.mem.eql(u8, name, "AdjustWindowRect")) return @ptrCast(&AdjustWindowRect);
        if (std.mem.eql(u8, name, "AdjustWindowRectEx")) return @ptrCast(&AdjustWindowRectEx);
        if (std.mem.eql(u8, name, "PeekMessageA")) return @ptrCast(&PeekMessageA);
        if (std.mem.eql(u8, name, "GetMessageA")) return @ptrCast(&GetMessageA);
        if (std.mem.eql(u8, name, "TranslateMessage")) return @ptrCast(&TranslateMessage);
        if (std.mem.eql(u8, name, "DispatchMessageA")) return @ptrCast(&DispatchMessageA);
        if (std.mem.eql(u8, name, "SendMessageA")) return @ptrCast(&SendMessageA);
        if (std.mem.eql(u8, name, "DestroyWindow")) return @ptrCast(&DestroyWindow);
        if (std.mem.eql(u8, name, "LoadIconA")) return @ptrCast(&LoadIconA);
        if (std.mem.eql(u8, name, "LoadCursorA")) return @ptrCast(&LoadCursorA);
        if (std.mem.eql(u8, name, "ShowCursor")) return @ptrCast(&ShowCursor);
        if (std.mem.eql(u8, name, "SetWindowPos")) return @ptrCast(&SetWindowPos);
        if (std.mem.eql(u8, name, "GetWindow")) return @ptrCast(&GetWindow);
        if (std.mem.eql(u8, name, "GetDoubleClickTime")) return @ptrCast(&GetDoubleClickTime);
        if (std.mem.eql(u8, name, "SwapMouseButton")) return @ptrCast(&SwapMouseButton);
        if (std.mem.eql(u8, name, "UnhookWindowsHookEx")) return @ptrCast(&UnhookWindowsHookEx);
        if (std.mem.eql(u8, name, "SetWindowsHookExA")) return @ptrCast(&SetWindowsHookExA);
        if (std.mem.eql(u8, name, "CallNextHookEx")) return @ptrCast(&CallNextHookEx);
        if (std.mem.eql(u8, name, "GetWindowTextA")) return @ptrCast(&GetWindowTextA);
        if (std.mem.eql(u8, name, "SetWindowTextA")) return @ptrCast(&SetWindowTextA);
        if (std.mem.eql(u8, name, "GetClassNameA")) return @ptrCast(&GetClassNameA);
        if (std.mem.eql(u8, name, "SendInput")) return @ptrCast(&SendInput);
        if (std.mem.eql(u8, name, "EnumChildWindows")) return @ptrCast(&EnumChildWindows);
        if (std.mem.eql(u8, name, "GetWindowLongA")) return @ptrCast(&GetWindowLongA);
        if (std.mem.eql(u8, name, "GetClassLongA")) return @ptrCast(&GetClassLongA);
        if (std.mem.eql(u8, name, "EnumDisplayDevicesA")) return @ptrCast(&EnumDisplayDevicesA);
        if (std.mem.eql(u8, name, "MessageBoxA")) return @ptrCast(&MessageBoxA);
        if (std.mem.eql(u8, name, "GetAsyncKeyState")) return @ptrCast(&GetAsyncKeyState);
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
    } else if (std.ascii.eqlIgnoreCase(dll, "dinput8.dll") or std.ascii.eqlIgnoreCase(dll, "dinput8")) {
        if (std.mem.eql(u8, name, "DirectInput8Create")) return @ptrCast(&DirectInput8Create);
    } else if (std.ascii.eqlIgnoreCase(dll, "comctl32.dll") or std.ascii.eqlIgnoreCase(dll, "comctl32")) {
        if (std.mem.eql(u8, name, "InitCommonControlsEx")) return @ptrCast(&InitCommonControlsEx);
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
        std.debug.print("  -> GetProcAddress: \"{s}\" NOT FOUND (returning NULL)\n", .{slice});
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
    const io = init.io;
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
    var total_imports: usize = 0;
    var resolved_imports: usize = 0;

    var import_rva: u32 = 0;
    var import_size: u32 = 0;

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

    // The delegated libraries keep their own image-base and command-line state.
    // The local table above shadows GetCommandLineA/GetModuleFileNameA, but the
    // module versions are reachable through GetProcAddress, so keep them honest.
    kernel32_mod.setImageBase(@intCast(image_base));
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

        const new_esp = stack_base - 0x1000;
        std.debug.print("\n[WINS:winrun32] JUMPING to EntryPoint at 0x{x:0>8} with stack at 0x{x:0>8}...\n", .{image_base + entry_rva, new_esp});

        // Diagnostic hook: by the time this runs, the guest image is mapped, so
        // gdb can set breakpoints inside it (`break brkGuestEntry` then
        // `break *<guest entry>`). No side effects.
        brkGuestEntry();
        std.debug.print("[probe] before guest jump: EBX=0x{x:0>8} ECX=0x{x:0>8} EDX=0x{x:0>8} (guest expects EBX built fresh; ECX=this)\n", .{ g_probe_ebx, g_probe_ecx, g_probe_edx });

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
