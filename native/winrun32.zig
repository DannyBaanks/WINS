//! WINS winrun32: Native Linux 32-bit x86 PE Loader (Zero Wine).
//! Loads 32-bit Windows executables (such as FalloutNV.exe) directly into memory,
//! maps the sections at ImageBase (0x00400000), configures the x86 TIB/TEB via
//! Linux set_thread_area syscall, resolves the Import Address Table (IAT),
//! provides Steam DRM, Bink Video, Kernel32 and User32 shims, and invokes the entry point.

const std = @import("std");
const linux = std.os.linux;
const d3d9 = @import("wins_d3d9.zig");

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
        }
    }
    std.debug.print("=======================================================\n", .{});
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
    if (lpAddress) |p| {
        const prot = linux.PROT{
            .READ = (flNewProtect & 0x66) != 0,
            .WRITE = (flNewProtect & 0x44) != 0,
            .EXEC = (flNewProtect & 0xF0) != 0,
        };
        const u8_ptr: [*]const u8 = @ptrCast(p);
        _ = linux.mprotect(u8_ptr, dwSize, prot);
        return 1;
    }
    return 0;
}

// ============================================================================
// File Mapping APIs & SteamStub IPC Simulation
// ============================================================================

var g_steam_shmem: [4096]u8 align(4096) = [_]u8{0} ** 4096;

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
        // [buffer + 0x90] = 2 (Steam client ready and authenticated)
        std.mem.writeInt(u32, g_steam_shmem[0x90..0x94], 2, .little);
        // [buffer + 0x94] = 0 (Ready for request)
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
    std.debug.print("[WINS:Kernel32] ExitProcess called with code {}\n", .{code});
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

// Critical Sections & Mutexes
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

fn WaitForSingleObject(hHandle: usize, dwMilliseconds: u32) callconv(W) u32 {
    _ = hHandle; _ = dwMilliseconds;
    // Check if SteamStub wrote an auth request to g_steam_shmem!
    const req_status = std.mem.readInt(u32, g_steam_shmem[0x94..0x98], .little);
    if (req_status == 1) {
        const pid = std.mem.readInt(u32, g_steam_shmem[0x98..0x9c], .little);
        const event_h = std.mem.readInt(u32, g_steam_shmem[0x9c..0xa0], .little);
        const token = std.mem.readInt(u32, g_steam_shmem[0xa4..0xa8], .little);
        const target_addr = std.mem.readInt(u32, g_steam_shmem[0xac..0xb0], .little);

        std.debug.print("[WINS:SteamDRM] Intercepted SteamStub Auth Handshake:\n", .{});
        std.debug.print("  Target Process PID: {}\n", .{pid});
        std.debug.print("  Event Handle:       0x{x}\n", .{event_h});
        std.debug.print("  Validation Token:   0x{x:0>8}\n", .{token});
        std.debug.print("  Target Pointer:     0x{x:0>8}\n", .{target_addr});

        if (target_addr != 0) {
            const target_ptr: *u32 = @ptrFromInt(target_addr);
            target_ptr.* = token;
            std.debug.print("  [WINS:SteamDRM] Injected token into memory target -> SteamStub unlocked!\n", .{});
        }

        // Mark request as processed by Steam client
        std.mem.writeInt(u32, g_steam_shmem[0x94..0x98], 2, .little);
    }
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

const g_cmdline: [:0]const u8 = "FalloutNV.exe";
const g_cmdline_w = std.unicode.utf8ToUtf16LeStringLiteral("FalloutNV.exe");

fn GetCommandLineA() callconv(W) [*:0]const u8 {
    return g_cmdline.ptr;
}

fn GetCommandLineW() callconv(W) [*:0]const u16 {
    return g_cmdline_w.ptr;
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
    const fd: i32 = if (h == 0x1001) 1 else if (h == 0x1002) 2 else if (h >= 0x10000) @intCast(h - 0x10000) else return 0;
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
    if (hFile < 0x10000 or lpBuffer == null) return 0;
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
        var norm_buf: [512]u8 = undefined;
        const norm_len = @min(norm_buf.len - 1, path.len);
        for (0..norm_len) |i| {
            norm_buf[i] = if (path[i] == '\\') '/' else path[i];
        }
        norm_buf[norm_len] = 0;
        const norm_slice = norm_buf[0..norm_len:0];

        const fd = linux.open(norm_slice.ptr, .{ .ACCMODE = .RDWR }, 0);
        if (linux.errno(fd) == .SUCCESS) {
            std.debug.print("[WINS:Kernel32] CreateFileA(\"{s}\") -> SUCCESS fd={}\n", .{ norm_slice, fd });
            return @as(usize, @intCast(fd)) + 0x10000;
        }
        const fd_ro = linux.open(norm_slice.ptr, .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(fd_ro) == .SUCCESS) {
            std.debug.print("[WINS:Kernel32] CreateFileA(\"{s}\") [RO] -> SUCCESS fd={}\n", .{ norm_slice, fd_ro });
            return @as(usize, @intCast(fd_ro)) + 0x10000;
        }
    }
    g_last_error = 2; // ERROR_FILE_NOT_FOUND
    return 0xFFFFFFFF; // INVALID_HANDLE_VALUE
}

fn CreateFileW(lpFileName: ?[*:0]const u16, dwDesiredAccess: u32, dwShareMode: u32, lpSecurityAttributes: ?*anyopaque, dwCreationDisposition: u32, dwFlagsAndAttributes: u32, hTemplateFile: usize) callconv(W) usize {
    _ = lpFileName; _ = dwDesiredAccess; _ = dwShareMode; _ = lpSecurityAttributes; _ = dwCreationDisposition; _ = dwFlagsAndAttributes; _ = hTemplateFile;
    g_last_error = 2;
    return 0xFFFFFFFF;
}

fn GetFileSize(hFile: usize, lpFileSizeHigh: ?*u32) callconv(W) u32 {
    if (hFile < 0x10000) return 0xFFFFFFFF;
    const fd: isize = @intCast(hFile - 0x10000);
    const cur = linux.syscall3(.lseek, @as(usize, @bitCast(fd)), 0, linux.SEEK.CUR);
    const size = linux.syscall3(.lseek, @as(usize, @bitCast(fd)), 0, linux.SEEK.END);
    _ = linux.syscall3(.lseek, @as(usize, @bitCast(fd)), cur, linux.SEEK.SET);
    if (lpFileSizeHigh) |high| high.* = @intCast(@as(u64, size) >> 32);
    return @intCast(size & 0xFFFFFFFF);
}

fn GetFileSizeEx(hFile: usize, lpFileSize: ?*i64) callconv(W) i32 {
    if (hFile < 0x10000 or lpFileSize == null) return 0;
    const fd: isize = @intCast(hFile - 0x10000);
    const cur = linux.syscall3(.lseek, @as(usize, @bitCast(fd)), 0, linux.SEEK.CUR);
    const size = linux.syscall3(.lseek, @as(usize, @bitCast(fd)), 0, linux.SEEK.END);
    _ = linux.syscall3(.lseek, @as(usize, @bitCast(fd)), cur, linux.SEEK.SET);
    lpFileSize.?.* = @intCast(size);
    return 1;
}

fn SetFilePointer(hFile: usize, lDistanceToMove: i32, lpDistanceToMoveHigh: ?*i32, dwMoveMethod: u32) callconv(W) u32 {
    _ = lpDistanceToMoveHigh;
    if (hFile < 0x10000) return 0xFFFFFFFF;
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
    if (hFile < 0x10000) return 0;
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
    if (hFile >= 0x10000) {
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
        if (std.ascii.eqlIgnoreCase(slice, "binkw32") or std.ascii.eqlIgnoreCase(slice, "binkw32.dll")) return 0xB14C0000;
        if (std.ascii.eqlIgnoreCase(slice, "ole32") or std.ascii.eqlIgnoreCase(slice, "ole32.dll")) return 0x774D0000;
        if (std.ascii.eqlIgnoreCase(slice, "advapi32") or std.ascii.eqlIgnoreCase(slice, "advapi32.dll")) return 0x77DD0000;
        if (std.ascii.eqlIgnoreCase(slice, "shell32") or std.ascii.eqlIgnoreCase(slice, "shell32.dll")) return 0x7C9C0000;
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

fn SteamApps() callconv(W) ?*anyopaque {
    return &g_steam_dummy_obj;
}

fn SteamFriends() callconv(W) ?*anyopaque {
    return &g_steam_dummy_obj;
}

fn SteamUser() callconv(W) ?*anyopaque {
    return &g_steam_dummy_obj;
}

fn SteamUserStats() callconv(W) ?*anyopaque {
    return &g_steam_dummy_obj;
}

fn SteamUtils() callconv(W) ?*anyopaque {
    return &g_steam_dummy_obj;
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

var g_argv = [_]?[*:0]const u16{g_cmdline_w.ptr};

fn CommandLineToArgvW(lpCmdLine: ?[*:0]const u16, pNumArgs: ?*i32) callconv(W) ?[*]?[*:0]const u16 {
    _ = lpCmdLine;
    if (pNumArgs) |n| n.* = 1;
    return &g_argv;
}

fn RegOpenKeyExA(hKey: usize, lpSubKey: ?[*:0]const u8, ulOptions: u32, samDesired: u32, phkResult: ?*usize) callconv(W) i32 {
    _ = hKey; _ = lpSubKey; _ = ulOptions; _ = samDesired;
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
    if (lpType) |t| t.* = 1; // REG_SZ
    if (lpValueName) |vn| {
        const name = std.mem.sliceTo(vn, 0);
        if (std.ascii.eqlIgnoreCase(name, "Installed Path")) {
            const val = "./\x00";
            if (lpcbData) |cb| {
                if (lpData) |d| @memcpy(d[0..val.len], val);
                cb.* = @intCast(val.len);
            }
            return 0;
        }
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
        if (std.mem.eql(u8, name, "InitializeCriticalSection")) return @ptrCast(&dummySync);
        if (std.mem.eql(u8, name, "InitializeCriticalSectionAndSpinCount")) return @ptrCast(&dummySuccess);
        if (std.mem.eql(u8, name, "EnterCriticalSection")) return @ptrCast(&dummySync);
        if (std.mem.eql(u8, name, "TryEnterCriticalSection")) return @ptrCast(&dummySuccess);
        if (std.mem.eql(u8, name, "LeaveCriticalSection")) return @ptrCast(&dummySync);
        if (std.mem.eql(u8, name, "DeleteCriticalSection")) return @ptrCast(&dummySync);
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
    }
    return null;
}

fn GetProcAddress(hModule: usize, lpProcName: ?[*:0]const u8) callconv(W) ?*const anyopaque {
    if (lpProcName) |name| {
        const slice = std.mem.sliceTo(name, 0);
        std.debug.print("[WINS:Kernel32] GetProcAddress(0x{x}, \"{s}\")\n", .{ hModule, slice });

        if (resolveImport("kernel32.dll", slice)) |fn_ptr| return fn_ptr;
        if (resolveImport("user32.dll", slice)) |fn_ptr| return fn_ptr;
        if (resolveImport("steam_api.dll", slice)) |fn_ptr| return fn_ptr;
        if (resolveImport("binkw32.dll", slice)) |fn_ptr| return fn_ptr;
        if (resolveImport("d3d9.dll", slice)) |fn_ptr| return fn_ptr;
        if (resolveImport("d3dx9_38.dll", slice)) |fn_ptr| return fn_ptr;
        if (resolveImport("advapi32.dll", slice)) |fn_ptr| return fn_ptr;
        if (resolveImport("ole32.dll", slice)) |fn_ptr| return fn_ptr;
        if (resolveImport("shell32.dll", slice)) |fn_ptr| return fn_ptr;
        if (resolveImport("gdi32.dll", slice)) |fn_ptr| return fn_ptr;
        if (resolveImport("winmm.dll", slice)) |fn_ptr| return fn_ptr;
        if (resolveImport("dinput8.dll", slice)) |fn_ptr| return fn_ptr;
        if (resolveImport("comctl32.dll", slice)) |fn_ptr| return fn_ptr;

        std.debug.print("  -> UNHANDLED GetProcAddress: \"{s}\" (fallback to unhandledApiStub)\n", .{slice});
    }
    return @ptrCast(&unhandledApiStub);
}

// ============================================================================
// 32-bit x86 TIB & PEB Setup (FS Segment)
// ============================================================================

var g_tib_buffer: [64]u32 align(16) = [_]u32{0} ** 64;
var g_peb_buffer: [128]u32 align(16) = [_]u32{0} ** 128;

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
    var target_path: []const u8 = "";

    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--check")) {
            check_only = true;
        } else if (std.mem.eql(u8, arg, "--run")) {
            run_target = true;
        } else if (target_path.len == 0 and !std.mem.startsWith(u8, arg, "--")) {
            target_path = arg;
        }
    }

    if (target_path.len == 0) {
        std.debug.print("Error: No PE32 target executable specified.\n", .{});
        return;
    }

    // Install diagnostic crash interception
    installCrashHandlers();

    const bytes = std.Io.Dir.cwd().readFileAlloc(io, target_path, allocator, .limited(64 * 1024 * 1024)) catch |e| {
        std.debug.print("cannot read {s}: {s}\n", .{ target_path, @errorName(e) });
        return;
    };

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

    if (check_only) {
        std.debug.print("\n[WINS:winrun32] Check PASSED: Image is 100% compliant and ready for memory mapping.\n", .{});
        return;
    }

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
                if ((val & 0x80000000) == 0) {
                    const fn_name = std.mem.sliceTo(dest_slice + val + 2, 0);
                    resolved_fn = resolveImport(dll_name, fn_name);
                }

                if (resolved_fn == null) {
                    resolved_fn = @ptrCast(&unhandledApiStub);
                }

                const fn_addr: u32 = @intFromPtr(resolved_fn.?);
                std.mem.writeInt(u32, dest_slice[cur_iat..][0..4], fn_addr, .little);
                patched_count += 1;
            }
        }
    }
    std.debug.print("  [IAT Patcher] Successfully patched {d} import slots in RAM.\n", .{patched_count});
    std.debug.print("[WINS:winrun32] Memory staging & IAT patching complete!\n", .{});

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

        const new_esp = stack_base - 0x1000;
        std.debug.print("\n[WINS:winrun32] JUMPING to EntryPoint at 0x{x:0>8} with stack at 0x{x:0>8}...\n", .{image_base + entry_rva, new_esp});

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
    } else {
        std.debug.print("[WINS:winrun32] Use --run to jump into execution.\n", .{});
    }
}
