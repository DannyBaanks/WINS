//! Minimal Microsoft x86-64 table-driven SEH / C++ EH unwind runtime (.pdata).
//! Enables guest binaries with statically linked MSVC VCRUNTIME C++ exceptions
//! (such as notepad++.exe) to unwind frames via their own __CxxFrameHandler3/4
//! and _GSHandlerCheck routines instead of aborting on RaiseException.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

fn hasTraceEnv() bool {
    if (comptime builtin.link_libc) {
        return std.c.getenv("WINS_TRACE") != null;
    }
    return false;
}

pub const W: std.builtin.CallingConvention = .winapi;

const UNW_FLAG_EHANDLER: u8 = 0x1;
const UNW_FLAG_UHANDLER: u8 = 0x2;
const UNW_FLAG_CHAININFO: u8 = 0x4;

const EXCEPTION_NONCONTINUABLE: u32 = 0x1;
const EXCEPTION_UNWINDING: u32 = 0x2;
const EXCEPTION_TARGET_UNWIND: u32 = 0x20;
const EXCEPTION_UNWIND: u32 = EXCEPTION_UNWINDING | 0x4 | 0x20 | 0x40;

const ExceptionContinueExecution: i32 = 0;
const ExceptionContinueSearch: i32 = 1;

const RUNTIME_FUNCTION = extern struct {
    BeginAddress: u32,
    EndAddress: u32,
    UnwindData: u32,
};

const EXCEPTION_RECORD = extern struct {
    ExceptionCode: u32,
    ExceptionFlags: u32,
    ExceptionRecord: ?*EXCEPTION_RECORD,
    ExceptionAddress: usize,
    NumberParameters: u32,
    _pad: u32 = 0,
    ExceptionInformation: [15]usize,
};

const DISPATCHER_CONTEXT = extern struct {
    ControlPc: u64,
    ImageBase: u64,
    FunctionEntry: ?*const RUNTIME_FUNCTION,
    EstablisherFrame: u64,
    TargetIp: u64,
    ContextRecord: [*]u8,
    LanguageHandler: ?*const anyopaque,
    HandlerData: ?*const anyopaque,
    HistoryTable: ?*anyopaque,
    ScopeIndex: u32,
    _pad: u32 = 0,
};

const LanguageHandlerFn = *const fn (*EXCEPTION_RECORD, u64, [*]u8, *DISPATCHER_CONTEXT) callconv(W) i32;

// Windows x64 CONTEXT register byte offsets inside [1232]u8 align(16).
const CTX_SIZE: usize = 1232;
const CTX_FLAGS: usize = 0x30;
const CTX_EFLAGS: usize = 0x44;
const CTX_REGS: usize = 0x78; // 16 x u64: Rax..R15 (RSP=4, RBP=5)
const CTX_RIP: usize = 0xf8;
const CTX_XMM0: usize = 0x1a0; // 16 x [16]u8

const MAX_MODULES: usize = 64;
const MAX_DYN_TABLES: usize = 256;
const MAX_VEHS: usize = 32;

const ModuleTable = struct {
    in_use: bool = false,
    base: usize = 0,
    image_len: usize = 0,
    pdata_rva: u32 = 0,
    pdata_size: u32 = 0,
};

const JitCallbackFn = *const fn (usize, ?*anyopaque) callconv(W) ?*const RUNTIME_FUNCTION;

const DynTable = struct {
    in_use: bool = false,
    id: usize = 0,
    base: usize = 0,
    len: usize = 0,
    entries: ?[*]const RUNTIME_FUNCTION = null,
    count: usize = 0,
    callback: ?JitCallbackFn = null,
    ctx: ?*anyopaque = null,
};

const EXCEPTION_POINTERS = extern struct {
    ExceptionRecord: *EXCEPTION_RECORD,
    ContextRecord: [*]u8,
};
pub const VehFn = *const fn (*EXCEPTION_POINTERS) callconv(W) i32;

var g_modules: [MAX_MODULES]ModuleTable = [_]ModuleTable{.{}} ** MAX_MODULES;
var g_dyn_tables: [MAX_DYN_TABLES]DynTable = [_]DynTable{.{}} ** MAX_DYN_TABLES;
var g_vehs: [MAX_VEHS]?VehFn = [_]?VehFn{null} ** MAX_VEHS;
var g_seh_lock: std.atomic.Mutex = .unlocked;
threadlocal var g_active_exc_ctx: ?*const [CTX_SIZE]u8 = null;

fn lockSeh() void {
    while (!g_seh_lock.tryLock()) std.atomic.spinLoopHint();
}

pub fn setExceptionTable(base: usize, image_len: usize, pdata_rva: u32, pdata_size: u32) void {
    lockSeh();
    defer g_seh_lock.unlock();
    g_modules = [_]ModuleTable{.{}} ** MAX_MODULES;
    if (base != 0) {
        g_modules[0] = .{
            .in_use = true,
            .base = base,
            .image_len = image_len,
            .pdata_rva = pdata_rva,
            .pdata_size = pdata_size,
        };
    }
}

pub fn addExceptionTable(base: usize, image_len: usize, pdata_rva: u32, pdata_size: u32) void {
    if (base == 0) return;
    lockSeh();
    defer g_seh_lock.unlock();
    for (&g_modules) |*m| {
        if (m.in_use and m.base == base) {
            m.* = .{ .in_use = true, .base = base, .image_len = image_len, .pdata_rva = pdata_rva, .pdata_size = pdata_size };
            return;
        }
    }
    for (&g_modules) |*m| {
        if (!m.in_use) {
            m.* = .{ .in_use = true, .base = base, .image_len = image_len, .pdata_rva = pdata_rva, .pdata_size = pdata_size };
            return;
        }
    }
}

pub fn addFunctionTable(entries: ?[*]const RUNTIME_FUNCTION, count: u32, base: usize) u8 {
    if (entries == null or count == 0) return 0;
    lockSeh();
    defer g_seh_lock.unlock();
    for (&g_dyn_tables) |*d| {
        if (!d.in_use) {
            d.* = .{
                .in_use = true,
                .id = @intFromPtr(entries.?),
                .base = base,
                .len = 0x10000000,
                .entries = entries,
                .count = count,
            };
            return 1;
        }
    }
    return 0;
}

pub fn installFunctionTableCallback(table_id: usize, base: usize, len: u32, callback: ?*const anyopaque, ctx: ?*anyopaque) u8 {
    if (callback == null or len == 0) return 0;
    lockSeh();
    defer g_seh_lock.unlock();
    for (&g_dyn_tables) |*d| {
        if (!d.in_use) {
            d.* = .{
                .in_use = true,
                .id = table_id,
                .base = base,
                .len = len,
                .callback = @ptrCast(@alignCast(callback.?)),
                .ctx = ctx,
            };
            return 1;
        }
    }
    return 0;
}

pub fn deleteFunctionTable(ptr_or_id: ?*anyopaque) u8 {
    const target = @intFromPtr(ptr_or_id orelse return 0);
    lockSeh();
    defer g_seh_lock.unlock();
    for (&g_dyn_tables) |*d| {
        if (d.in_use and (d.id == target or d.id == (target | 3) or @intFromPtr(d.entries) == target)) {
            d.* = .{};
            return 1;
        }
    }
    return 0;
}

pub fn addVectoredExceptionHandler(first: u32, handler: ?*const anyopaque) ?*anyopaque {
    const h: VehFn = @ptrCast(@alignCast(handler orelse return null));
    lockSeh();
    defer g_seh_lock.unlock();
    if (first != 0) {
        var idx: usize = MAX_VEHS - 1;
        while (idx > 0) : (idx -= 1) g_vehs[idx] = g_vehs[idx - 1];
        g_vehs[0] = h;
        return @constCast(handler);
    }
    for (&g_vehs) |*slot| {
        if (slot.* == null) {
            slot.* = h;
            return @constCast(handler);
        }
    }
    return null;
}

pub fn removeVectoredExceptionHandler(handle: ?*anyopaque) u32 {
    const target: usize = @intFromPtr(handle orelse return 0);
    lockSeh();
    defer g_seh_lock.unlock();
    for (&g_vehs) |*slot| {
        if (slot.*) |h| {
            if (@intFromPtr(h) == target) {
                slot.* = null;
                return 1;
            }
        }
    }
    return 0;
}

fn findModuleForPc(pc: usize) ?ModuleTable {
    for (g_modules) |m| {
        if (m.in_use and pc >= m.base and pc < m.base + m.image_len) return m;
    }
    return null;
}

fn readCtxReg(ctx: [*]const u8, reg: usize) u64 {
    return std.mem.readInt(u64, ctx[CTX_REGS + reg * 8 ..][0..8], .little);
}

fn writeCtxReg(ctx: [*]u8, reg: usize, val: u64) void {
    std.mem.writeInt(u64, ctx[CTX_REGS + reg * 8 ..][0..8], val, .little);
}

fn readCtxRip(ctx: [*]const u8) u64 {
    return std.mem.readInt(u64, ctx[CTX_RIP..][0..8], .little);
}

fn writeCtxRip(ctx: [*]u8, val: u64) void {
    std.mem.writeInt(u64, ctx[CTX_RIP..][0..8], val, .little);
}

fn readU64(addr: u64) u64 {
    return @as(*const u64, @ptrFromInt(@as(usize, @intCast(addr)))).*;
}

fn inModuleOrJit(base: usize, rva: u32, len: usize) bool {
    if (findModuleForPc(base)) |m| {
        return @as(u64, rva) + len <= m.image_len;
    }
    return rva != 0;
}

pub fn lookupFunctionEntry(pc: usize, base_out: ?*usize, hist: ?*anyopaque) callconv(W) ?*const RUNTIME_FUNCTION {
    _ = hist;
    if (findModuleForPc(pc)) |m| {
        if (base_out) |b| b.* = m.base;
        if (m.pdata_rva == 0 or m.pdata_size < @sizeOf(RUNTIME_FUNCTION)) return null;
        const rva: u32 = @intCast(pc - m.base);
        const count: usize = m.pdata_size / @sizeOf(RUNTIME_FUNCTION);
        const entries: [*]const RUNTIME_FUNCTION = @ptrFromInt(m.base + m.pdata_rva);
        var lo: usize = 0;
        var hi: usize = count;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            const rf = &entries[mid];
            if (rva < rf.BeginAddress) {
                hi = mid;
            } else if (rva >= rf.EndAddress) {
                lo = mid + 1;
            } else {
                return rf;
            }
        }
        return null;
    }
    for (g_dyn_tables) |d| {
        if (!d.in_use) continue;
        if (pc >= d.base and pc < d.base + d.len) {
            if (base_out) |b| b.* = d.base;
            if (d.callback) |cb| return cb(pc, d.ctx);
            if (d.entries) |ents| {
                const rva: u32 = @intCast(pc - d.base);
                for (0..d.count) |idx| {
                    const rf = &ents[idx];
                    if (rva >= rf.BeginAddress and rva < rf.EndAddress) return rf;
                }
            }
            return null;
        }
    }
    if (base_out) |b| b.* = 0;
    return null;
}

pub fn virtualUnwind(
    handler_type: u32,
    base: usize,
    pc: usize,
    entry_opt: ?*const RUNTIME_FUNCTION,
    ctx: [*]u8,
    handler_data: ?*?*const anyopaque,
    establisher_frame: ?*u64,
    context_pointers: ?*anyopaque,
) callconv(W) usize {
    _ = context_pointers;
    if (handler_data) |hd| hd.* = null;
    const entry = entry_opt orelse {
        const rsp = readCtxReg(ctx, 4);
        if (establisher_frame) |ef| ef.* = rsp;
        writeCtxRip(ctx, readU64(rsp));
        writeCtxReg(ctx, 4, rsp + 8);
        return 0;
    };

    var cur_entry: *const RUNTIME_FUNCTION = entry;
    var cur_pc = pc;
    var first_frame_set = false;
    var frame_base: u64 = readCtxReg(ctx, 4);
    var handler_ret: usize = 0;

    var depth: usize = 0;
    while (depth < 16) : (depth += 1) {
        const u_rva = cur_entry.UnwindData & ~@as(u32, 1);
        if (!inModuleOrJit(base, u_rva, 4)) break;
        const uptr: [*]const u8 = @ptrFromInt(base + u_rva);
        const ver_flags = uptr[0];
        const version = ver_flags & 0x7;
        const flags = ver_flags >> 3;
        const prolog_size = uptr[1];
        const code_count = uptr[2];
        const fr_byte = uptr[3];
        const frame_reg: usize = fr_byte & 0xf;
        const frame_offset: u64 = @as(u64, fr_byte >> 4) * 16;

        if (!first_frame_set) {
            frame_base = if (frame_reg == 0) readCtxReg(ctx, 4) else readCtxReg(ctx, frame_reg) -% frame_offset;
            if (establisher_frame) |ef| ef.* = frame_base;
            first_frame_set = true;
        }

        const prolog_off: u64 = if (cur_pc >= base + cur_entry.BeginAddress) cur_pc - (base + cur_entry.BeginAddress) else 0;
        const codes: [*]const u16 = @ptrCast(@alignCast(uptr + 4));
        const save_base: u64 = if (frame_reg == 0) readCtxReg(ctx, 4) else readCtxReg(ctx, frame_reg) -% frame_offset;

        var idx: usize = 0;
        while (idx < code_count) {
            const slot = codes[idx];
            const code_off: u8 = @truncate(slot & 0xff);
            const op: u8 = @truncate((slot >> 8) & 0xf);
            const info: u8 = @truncate((slot >> 12) & 0xf);

            const step: usize = switch (op) {
                0, 2, 3, 6, 10 => 1,
                1 => if (info == 0) 2 else 3,
                4, 8 => 2,
                5, 7, 9 => 3,
                else => 1,
            };
            const apply = (prolog_off >= prolog_size) or (prolog_off >= code_off);
            if (apply) {
                switch (op) {
                    0 => { // UWOP_PUSH_NONVOL
                        const rsp = readCtxReg(ctx, 4);
                        writeCtxReg(ctx, info, readU64(rsp));
                        writeCtxReg(ctx, 4, rsp + 8);
                    },
                    1 => { // UWOP_ALLOC_LARGE
                        const sz: u64 = if (info == 0)
                            @as(u64, codes[idx + 1]) * 8
                        else
                            @as(u64, codes[idx + 1]) | (@as(u64, codes[idx + 2]) << 16);
                        writeCtxReg(ctx, 4, readCtxReg(ctx, 4) + sz);
                    },
                    2 => { // UWOP_ALLOC_SMALL
                        const sz: u64 = @as(u64, info) * 8 + 8;
                        writeCtxReg(ctx, 4, readCtxReg(ctx, 4) + sz);
                    },
                    3 => { // UWOP_SET_FPREG
                        if (frame_reg != 0) {
                            writeCtxReg(ctx, 4, readCtxReg(ctx, frame_reg) -% frame_offset);
                        }
                    },
                    4 => { // UWOP_SAVE_NONVOL
                        const off: u64 = @as(u64, codes[idx + 1]) * 8;
                        writeCtxReg(ctx, info, readU64(save_base + off));
                    },
                    5 => { // UWOP_SAVE_NONVOL_FAR
                        const off: u64 = @as(u64, codes[idx + 1]) | (@as(u64, codes[idx + 2]) << 16);
                        writeCtxReg(ctx, info, readU64(save_base + off));
                    },
                    6, 7 => {}, // UWOP_EPILOG / UWOP_SPARE_CODE
                    8 => { // UWOP_SAVE_XMM128
                        const off: u64 = @as(u64, codes[idx + 1]) * 16;
                        const src: *const [16]u8 = @ptrFromInt(@as(usize, @intCast(save_base + off)));
                        @memcpy(ctx[CTX_XMM0 + @as(usize, info) * 16 ..][0..16], src);
                    },
                    9 => { // UWOP_SAVE_XMM128_FAR
                        const off: u64 = @as(u64, codes[idx + 1]) | (@as(u64, codes[idx + 2]) << 16);
                        const src: *const [16]u8 = @ptrFromInt(@as(usize, @intCast(save_base + off)));
                        @memcpy(ctx[CTX_XMM0 + @as(usize, info) * 16 ..][0..16], src);
                    },
                    10 => { // UWOP_PUSH_MACHFRAME
                        var rsp = readCtxReg(ctx, 4);
                        if (info == 1) rsp += 8;
                        writeCtxRip(ctx, readU64(rsp));
                        writeCtxReg(ctx, 4, readU64(rsp + 24));
                        return handler_ret;
                    },
                    else => {},
                }
            }
            _ = version;
            idx += step;
        }

        const aligned_codes = (code_count + 1) & ~@as(usize, 1);
        const tail_ptr = uptr + 4 + aligned_codes * 2;
        if ((flags & UNW_FLAG_CHAININFO) != 0) {
            cur_entry = @ptrCast(@alignCast(tail_ptr));
            cur_pc = base + cur_entry.BeginAddress + 255; // execute full chained frame
            continue;
        }
        if ((flags & @as(u8, @truncate(handler_type))) != 0) {
            const h_rva = std.mem.readInt(u32, tail_ptr[0..4], .little);
            if (h_rva != 0 and inModuleOrJit(base, h_rva, 1)) {
                handler_ret = base + h_rva;
                if (handler_data) |hd| hd.* = @ptrCast(tail_ptr + 4);
            }
        }
        break;
    }

    const rsp = readCtxReg(ctx, 4);
    writeCtxRip(ctx, readU64(rsp));
    writeCtxReg(ctx, 4, rsp + 8);
    return handler_ret;
}

pub fn captureContextNaked() callconv(.naked) void {
    asm volatile (
        \\ movq %%rax, 0x78(%%rcx)
        \\ movq %%rcx, 0x80(%%rcx)
        \\ movq %%rdx, 0x88(%%rcx)
        \\ movq %%rbx, 0x90(%%rcx)
        \\ leaq 8(%%rsp), %%rax
        \\ movq %%rax, 0x98(%%rcx)
        \\ movq %%rbp, 0xa0(%%rcx)
        \\ movq %%rsi, 0xa8(%%rcx)
        \\ movq %%rdi, 0xb0(%%rcx)
        \\ movq %%r8,  0xb8(%%rcx)
        \\ movq %%r9,  0xc0(%%rcx)
        \\ movq %%r10, 0xc8(%%rcx)
        \\ movq %%r11, 0xd0(%%rcx)
        \\ movq %%r12, 0xd8(%%rcx)
        \\ movq %%r13, 0xe0(%%rcx)
        \\ movq %%r14, 0xe8(%%rcx)
        \\ movq %%r15, 0xf0(%%rcx)
        \\ movq (%%rsp), %%rax
        \\ movq %%rax, 0xf8(%%rcx)
        \\ pushfq
        \\ popq %%rax
        \\ movl %%eax, 0x44(%%rcx)
        \\ movdqu %%xmm6,  0x200(%%rcx)
        \\ movdqu %%xmm7,  0x210(%%rcx)
        \\ movdqu %%xmm8,  0x220(%%rcx)
        \\ movdqu %%xmm9,  0x230(%%rcx)
        \\ movdqu %%xmm10, 0x240(%%rcx)
        \\ movdqu %%xmm11, 0x250(%%rcx)
        \\ movdqu %%xmm12, 0x260(%%rcx)
        \\ movdqu %%xmm13, 0x270(%%rcx)
        \\ movdqu %%xmm14, 0x280(%%rcx)
        \\ movdqu %%xmm15, 0x290(%%rcx)
        \\ movl $0x10000F, 0x30(%%rcx)
        \\ ret
    );
}

pub fn restoreContextNaked() callconv(.naked) noreturn {
    asm volatile (
        \\ movdqu 0x200(%%rcx), %%xmm6
        \\ movdqu 0x210(%%rcx), %%xmm7
        \\ movdqu 0x220(%%rcx), %%xmm8
        \\ movdqu 0x230(%%rcx), %%xmm9
        \\ movdqu 0x240(%%rcx), %%xmm10
        \\ movdqu 0x250(%%rcx), %%xmm11
        \\ movdqu 0x260(%%rcx), %%xmm12
        \\ movdqu 0x270(%%rcx), %%xmm13
        \\ movdqu 0x280(%%rcx), %%xmm14
        \\ movdqu 0x290(%%rcx), %%xmm15
        \\ movq 0x78(%%rcx), %%rax
        \\ movq 0x88(%%rcx), %%rdx
        \\ movq 0x90(%%rcx), %%rbx
        \\ movq 0xa0(%%rcx), %%rbp
        \\ movq 0xa8(%%rcx), %%rsi
        \\ movq 0xb0(%%rcx), %%rdi
        \\ movq 0xb8(%%rcx), %%r8
        \\ movq 0xc0(%%rcx), %%r9
        \\ movq 0xd0(%%rcx), %%r11
        \\ movq 0xd8(%%rcx), %%r12
        \\ movq 0xe0(%%rcx), %%r13
        \\ movq 0xe8(%%rcx), %%r14
        \\ movq 0xf0(%%rcx), %%r15
        \\ movl 0x44(%%rcx), %%r10d
        \\ pushq %%r10
        \\ popfq
        \\ movq 0x98(%%rcx), %%rsp
        \\ movq 0xf8(%%rcx), %%r10
        \\ movq 0x80(%%rcx), %%rcx
        \\ jmpq *%%r10
    );
}

pub inline fn callCaptureContext(ctx: [*]u8) void {
    asm volatile ("call %[target:P]"
        :
        : [target] "s" (&captureContextNaked),
          [ctx] "{rcx}" (ctx),
        : .{ .rax = true, .memory = true }
    );
}

pub inline fn callRestoreContext(ctx: [*]u8) noreturn {
    asm volatile ("jmp %[target:P]"
        :
        : [target] "s" (&restoreContextNaked),
          [ctx] "{rcx}" (ctx),
        : .{ .memory = true }
    );
    unreachable;
}

fn rvaForAddr(addr: usize) usize {
    if (findModuleForPc(addr)) |m| return addr - m.base;
    return 0;
}

pub fn unwindEx(
    target_frame: u64,
    target_ip: u64,
    record_opt: ?*EXCEPTION_RECORD,
    return_val: u64,
    ctx_opt: ?[*]u8,
    hist: ?*anyopaque,
) callconv(W) void {
    var local_ctx: [CTX_SIZE]u8 align(16) = [_]u8{0} ** CTX_SIZE;
    const ctx: [*]u8 = ctx_opt orelse &local_ctx;
    if (g_active_exc_ctx) |saved| {
        @memcpy(ctx[0..CTX_SIZE], saved);
    } else {
        callCaptureContext(ctx);
    }

    var local_rec: EXCEPTION_RECORD = .{
        .ExceptionCode = 0xC0000027, // STATUS_UNWIND
        .ExceptionFlags = EXCEPTION_UNWINDING,
        .ExceptionRecord = null,
        .ExceptionAddress = @intCast(readCtxRip(ctx)),
        .NumberParameters = 0,
        .ExceptionInformation = [_]usize{0} ** 15,
    };
    const rec: *EXCEPTION_RECORD = record_opt orelse &local_rec;
    rec.ExceptionFlags |= EXCEPTION_UNWINDING;

    var frames: usize = 0;
    const trace = hasTraceEnv();
    if (trace) {
        std.debug.print("[WINS:SEH64] unwindEx target_frame=0x{x} target_ip=0x{x} (rva=0x{x}) ret=0x{x} start_rip=0x{x} rsp=0x{x}\n", .{
            target_frame,
            target_ip,
            rvaForAddr(@intCast(target_ip)),
            return_val,
            readCtxRip(ctx),
            readCtxReg(ctx, 4),
        });
    }
    while (frames < 128) : (frames += 1) {
        const pc: usize = @intCast(readCtxRip(ctx));
        var base: usize = 0;
        const entry = lookupFunctionEntry(pc, &base, hist);
        if (entry == null and findModuleForPc(pc) == null) {
            if (trace) std.debug.print("[WINS:SEH64]   unwind stop pc=0x{x} out of range\n", .{pc});
            break;
        }
        var hdata: ?*const anyopaque = null;
        var estab: u64 = 0;

        // Peek current establisher & handler before mutating ctx to caller.
        var next_ctx: [CTX_SIZE]u8 align(16) = undefined;
        @memcpy(&next_ctx, ctx[0..CTX_SIZE]);
        const handler_addr = virtualUnwind(UNW_FLAG_UHANDLER, base, pc, entry, &next_ctx, &hdata, &estab, null);

        const is_target = (target_frame != 0 and estab == target_frame);
        if (is_target) rec.ExceptionFlags |= EXCEPTION_TARGET_UNWIND;

        if (trace) {
            std.debug.print("[WINS:SEH64]   unwind[{d}] rva=0x{x} estab=0x{x} rsp=0x{x} handler=0x{x} target={}\n", .{
                frames,
                if (base != 0 and pc >= base) pc - base else pc,
                estab,
                readCtxReg(ctx, 4),
                if (base != 0 and handler_addr >= base) handler_addr - base else handler_addr,
                is_target,
            });
        }

        if (handler_addr != 0) {
            var disp = DISPATCHER_CONTEXT{
                .ControlPc = pc,
                .ImageBase = base,
                .FunctionEntry = entry,
                .EstablisherFrame = estab,
                .TargetIp = target_ip,
                .ContextRecord = ctx,
                .LanguageHandler = @ptrFromInt(handler_addr),
                .HandlerData = hdata,
                .HistoryTable = hist,
                .ScopeIndex = 0,
            };
            const handler: LanguageHandlerFn = @ptrFromInt(handler_addr);
            const action = handler(rec, estab, ctx, &disp);
            if (trace) {
                std.debug.print("[WINS:SEH64]   -> handler action={d}\n", .{action});
            }
            if (is_target and action == ExceptionContinueExecution) break;
        }

        if (is_target) break;
        @memcpy(ctx[0..CTX_SIZE], &next_ctx);
        if (readCtxRip(ctx) == 0) break;
    }

    var final_ip: u64 = target_ip;
    if (rec.ExceptionCode == 0x80000029 and rec.NumberParameters >= 1 and rec.ExceptionInformation[0] != 0) {
        const ConsolidateFn = *const fn (*EXCEPTION_RECORD) callconv(W) u64;
        const cb: ConsolidateFn = @ptrFromInt(rec.ExceptionInformation[0]);
        if (trace) {
            std.debug.print("[WINS:SEH64] STATUS_UNWIND_CONSOLIDATE cb=0x{x} (rva=0x{x})\n", .{
                rec.ExceptionInformation[0],
                rvaForAddr(rec.ExceptionInformation[0]),
            });
        }
        final_ip = cb(rec);
    }

    if (trace) {
        std.debug.print("[WINS:SEH64] restore rip=0x{x} (rva=0x{x}) rsp=0x{x} rbp=0x{x} rbx=0x{x}\n", .{
            final_ip,
            rvaForAddr(@intCast(final_ip)),
            readCtxReg(ctx, 4),
            readCtxReg(ctx, 5),
            readCtxReg(ctx, 3),
        });
    }
    writeCtxRip(ctx, final_ip);
    writeCtxReg(ctx, 0, return_val); // RAX = return_val
    callRestoreContext(ctx);
}

pub fn raiseExceptionEntry() callconv(.naked) void {
    // Entry: %rcx=code, %rdx=flags, %r8=nargs, %r9=args, (%rsp)=return addr.
    // %rsp is 8 mod 16. Subtract 1288 -> 0 mod 16.
    // Layout: [0..32]=shadow, [32..40]=arg5 (&ctx), [48..1280]=CONTEXT (16-aligned).
    asm volatile (
        \\ subq $1288, %%rsp
        \\ movq %%rax, 0x78+48(%%rsp)
        \\ movq %%rcx, 0x80+48(%%rsp)
        \\ movq %%rdx, 0x88+48(%%rsp)
        \\ movq %%rbx, 0x90+48(%%rsp)
        \\ leaq 1296(%%rsp), %%rax
        \\ movq %%rax, 0x98+48(%%rsp)
        \\ movq %%rbp, 0xa0+48(%%rsp)
        \\ movq %%rsi, 0xa8+48(%%rsp)
        \\ movq %%rdi, 0xb0+48(%%rsp)
        \\ movq %%r8,  0xb8+48(%%rsp)
        \\ movq %%r9,  0xc0+48(%%rsp)
        \\ movq %%r10, 0xc8+48(%%rsp)
        \\ movq %%r11, 0xd0+48(%%rsp)
        \\ movq %%r12, 0xd8+48(%%rsp)
        \\ movq %%r13, 0xe0+48(%%rsp)
        \\ movq %%r14, 0xe8+48(%%rsp)
        \\ movq %%r15, 0xf0+48(%%rsp)
        \\ movq 1288(%%rsp), %%rax
        \\ movq %%rax, 0xf8+48(%%rsp)
        \\ pushfq
        \\ popq %%rax
        \\ movl %%eax, 0x44+48(%%rsp)
        \\ movdqu %%xmm6,  0x200+48(%%rsp)
        \\ movdqu %%xmm7,  0x210+48(%%rsp)
        \\ movdqu %%xmm8,  0x220+48(%%rsp)
        \\ movdqu %%xmm9,  0x230+48(%%rsp)
        \\ movdqu %%xmm10, 0x240+48(%%rsp)
        \\ movdqu %%xmm11, 0x250+48(%%rsp)
        \\ movdqu %%xmm12, 0x260+48(%%rsp)
        \\ movdqu %%xmm13, 0x270+48(%%rsp)
        \\ movdqu %%xmm14, 0x280+48(%%rsp)
        \\ movdqu %%xmm15, 0x290+48(%%rsp)
        \\ movl $0x10000F, 0x30+48(%%rsp)
        \\ leaq 48(%%rsp), %%rax
        \\ movq %%rax, 32(%%rsp)
        \\ call %[dispatch:P]
        \\ addq $1288, %%rsp
        \\ ret
        :
        : [dispatch] "s" (&raiseExceptionDispatch),
    );
}

fn raiseExceptionDispatch(code: u32, flags: u32, nargs: u32, args: ?[*]const usize, orig_ctx: [*]u8) callconv(W) void {
    if (code == 0x406d1388) return; // MS_VC_EXCEPTION thread naming

    var rec: EXCEPTION_RECORD = .{
        .ExceptionCode = code,
        .ExceptionFlags = flags & EXCEPTION_NONCONTINUABLE,
        .ExceptionRecord = null,
        .ExceptionAddress = @intCast(readCtxRip(orig_ctx)),
        .NumberParameters = @min(nargs, 15),
        .ExceptionInformation = [_]usize{0} ** 15,
    };
    if (args) |a| {
        for (0..rec.NumberParameters) |i| rec.ExceptionInformation[i] = a[i];
    }

    var ctx: [CTX_SIZE]u8 align(16) = undefined;
    @memcpy(&ctx, orig_ctx[0..CTX_SIZE]);
    const prev_exc_ctx = g_active_exc_ctx;
    g_active_exc_ctx = @ptrCast(@alignCast(orig_ctx));
    defer g_active_exc_ctx = prev_exc_ctx;

    var frames: usize = 0;
    const trace = hasTraceEnv();
    if (trace) {
        std.debug.print("[WINS:SEH64] RaiseException code=0x{x:0>8} flags=0x{x} rva=0x{x} rsp=0x{x} rbx=0x{x}\n", .{
            code,
            flags,
            rvaForAddr(rec.ExceptionAddress),
            readCtxReg(&ctx, 4),
            readCtxReg(&ctx, 3),
        });
    }
    var exc_ptrs = EXCEPTION_POINTERS{ .ExceptionRecord = &rec, .ContextRecord = orig_ctx };
    for (g_vehs) |maybe_veh| {
        if (maybe_veh) |veh| {
            if (veh(&exc_ptrs) == -1) callRestoreContext(orig_ctx);
        }
    }
    while (frames < 128) : (frames += 1) {
        const pc: usize = @intCast(readCtxRip(&ctx));
        var base: usize = 0;
        const entry = lookupFunctionEntry(pc, &base, null);
        if (entry == null and findModuleForPc(pc) == null) {
            if (trace) std.debug.print("[WINS:SEH64]   dispatch stop pc=0x{x} out of range\n", .{pc});
            break;
        }
        var hdata: ?*const anyopaque = null;
        var estab: u64 = 0;

        var next_ctx: [CTX_SIZE]u8 align(16) = undefined;
        @memcpy(&next_ctx, &ctx);
        const handler_addr = virtualUnwind(UNW_FLAG_EHANDLER, base, pc, entry, &next_ctx, &hdata, &estab, null);
        if (trace) {
            std.debug.print("[WINS:SEH64]   frame[{d}] rva=0x{x} estab=0x{x} rsp=0x{x} handler=0x{x}\n", .{
                frames,
                if (base != 0 and pc >= base) pc - base else pc,
                estab,
                readCtxReg(&ctx, 4),
                if (base != 0 and handler_addr >= base) handler_addr - base else handler_addr,
            });
        }
        if (handler_addr != 0) {
            var disp = DISPATCHER_CONTEXT{
                .ControlPc = pc,
                .ImageBase = base,
                .FunctionEntry = entry,
                .EstablisherFrame = estab,
                .TargetIp = 0,
                .ContextRecord = &ctx,
                .LanguageHandler = @ptrFromInt(handler_addr),
                .HandlerData = hdata,
                .HistoryTable = null,
                .ScopeIndex = 0,
            };
            const handler: LanguageHandlerFn = @ptrFromInt(handler_addr);
            const action = handler(&rec, estab, &ctx, &disp);
            if (trace) {
                std.debug.print("[WINS:SEH64]   -> action={d}\n", .{action});
            }
            if (action == ExceptionContinueExecution) {
                callRestoreContext(orig_ctx);
            }
        }
        @memcpy(&ctx, &next_ctx);
        if (readCtxRip(&ctx) == 0) break;
    }

    if (hasTraceEnv()) {
        const ra = rec.ExceptionAddress;
        std.debug.print("[WINS:SEH64] unhandled exception code=0x{x:0>8} rva=0x{x}\n", .{ code, rvaForAddr(ra) });
    }
    linux.exit_group(@bitCast(code));
}

/// Dispatch hardware faults (SIGSEGV / SIGFPE / SIGILL) from Linux sigaction
/// to Windows Vectored Exception Handlers (used heavily by Mono JIT) and SEH.
/// gregs follows Linux x86-64 mcontext_t gregset_t order (R8=0 .. EFLAGS=17).
pub fn dispatchHardwareException(code: u32, fault_addr: usize, gregs: [*]u64) bool {
    var win_ctx: [CTX_SIZE]u8 align(16) = [_]u8{0} ** CTX_SIZE;
    std.mem.writeInt(u32, win_ctx[CTX_FLAGS..][0..4], 0x10000F, .little);
    std.mem.writeInt(u32, win_ctx[CTX_EFLAGS..][0..4], @truncate(gregs[17]), .little);
    // Win64 register indices in CONTEXT: 0=Rax 1=Rcx 2=Rdx 3=Rbx 4=Rsp 5=Rbp 6=Rsi 7=Rdi 8..15=R8..R15
    const map_from_greg = [16]usize{ 13, 14, 12, 11, 15, 10, 9, 8, 0, 1, 2, 3, 4, 5, 6, 7 };
    for (0..16) |wreg| writeCtxReg(&win_ctx, wreg, gregs[map_from_greg[wreg]]);
    writeCtxRip(&win_ctx, gregs[16]);

    var rec: EXCEPTION_RECORD = .{
        .ExceptionCode = code,
        .ExceptionFlags = 0,
        .ExceptionRecord = null,
        .ExceptionAddress = @intCast(gregs[16]),
        .NumberParameters = if (code == 0xC0000005) 2 else 0,
        .ExceptionInformation = [_]usize{0} ** 15,
    };
    if (code == 0xC0000005) {
        rec.ExceptionInformation[0] = 0;
        rec.ExceptionInformation[1] = fault_addr;
    }

    var exc_ptrs = EXCEPTION_POINTERS{ .ExceptionRecord = &rec, .ContextRecord = &win_ctx };
    for (g_vehs) |maybe_veh| {
        if (maybe_veh) |veh| {
            const verdict = veh(&exc_ptrs);
            if (verdict == -1) { // EXCEPTION_CONTINUE_EXECUTION
                for (0..16) |wreg| gregs[map_from_greg[wreg]] = readCtxReg(&win_ctx, wreg);
                gregs[16] = readCtxRip(&win_ctx);
                gregs[17] = (gregs[17] & ~@as(u64, 0xFFFFFFFF)) | std.mem.readInt(u32, win_ctx[CTX_EFLAGS..][0..4], .little);
                return true;
            }
        }
    }
    return false;
}

test "lookupFunctionEntry binary searches RUNTIME_FUNCTION table" {
    const FakeImage = extern struct {
        pad: [64]u8 = [_]u8{0} ** 64,
        rf: [3]RUNTIME_FUNCTION = .{
            .{ .BeginAddress = 0x1000, .EndAddress = 0x1050, .UnwindData = 0x2000 },
            .{ .BeginAddress = 0x1100, .EndAddress = 0x1200, .UnwindData = 0x2010 },
            .{ .BeginAddress = 0x1300, .EndAddress = 0x1380, .UnwindData = 0x2020 },
        },
    };
    const img = FakeImage{};
    const base = @intFromPtr(&img);
    setExceptionTable(base, 0x3000, 64, @sizeOf(@TypeOf(img.rf)));
    defer setExceptionTable(0, 0, 0, 0);

    var out_base: usize = 0;
    const hit = lookupFunctionEntry(base + 0x1150, &out_base, null);
    try std.testing.expect(hit != null);
    try std.testing.expectEqual(base, out_base);
    try std.testing.expectEqual(@as(u32, 0x1100), hit.?.BeginAddress);
    try std.testing.expectEqual(@as(u32, 0x2010), hit.?.UnwindData);

    const miss = lookupFunctionEntry(base + 0x1080, &out_base, null);
    try std.testing.expect(miss == null);
}
