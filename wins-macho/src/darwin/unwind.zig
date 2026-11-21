//! Mach-O x86_64 Compact Unwind (`__TEXT,__unwind_info`) & Itanium Level-1 Unwinder
//!
//! Implements real two-phase Itanium C++ ABI stack unwinding for x86_64 Mach-O
//! binaries running natively on Linux under WINS-MachO:
//! - Image unwind table registry (`__TEXT,__unwind_info` / `__TEXT,__eh_frame`)
//! - Apple two-level compact unwind lookup (regular & compressed 2nd-level pages,
//!   LSDA binary search, personality GOT dereference)
//! - Exact x86_64 compact frame stepping (`MODE_RBP_FRAME`, `MODE_STACK_IMMD`,
//!   `MODE_STACK_IND` with Lehmer register-permutation decoding)
//! - Naked x86_64 register capture (`_Unwind_RaiseException`, `_Unwind_Resume`)
//!   and atomic landing-pad context transfer (`unwindJumpTo`)

const std = @import("std");
const trace = @import("../runtime/trace.zig");

// ============================================================================
// Itanium Level-1 Unwind ABI Constants & Types
// ============================================================================

pub const URC_NO_REASON: c_int = 0;
pub const URC_FOREIGN_EXCEPTION_CAUGHT: c_int = 1;
pub const URC_FATAL_PHASE2_ERROR: c_int = 2;
pub const URC_FATAL_PHASE1_ERROR: c_int = 3;
pub const URC_NORMAL_STOP: c_int = 4;
pub const URC_END_OF_STACK: c_int = 5;
pub const URC_HANDLER_FOUND: c_int = 6;
pub const URC_INSTALL_CONTEXT: c_int = 7;
pub const URC_CONTINUE_UNWIND: c_int = 8;

pub const UA_SEARCH_PHASE: c_int = 1;
pub const UA_CLEANUP_PHASE: c_int = 2;
pub const UA_HANDLER_FRAME: c_int = 4;
pub const UA_FORCE_UNWIND: c_int = 8;

pub const UnwindException = extern struct {
    exception_class: u64,
    exception_cleanup: ?*const fn (c_int, *UnwindException) callconv(.c) void,
    private_1: usize,
    private_2: usize,
};

comptime {
    std.debug.assert(@sizeOf(UnwindException) == 32);
}

/// x86_64 register file ordered identically to DWARF/libunwind register numbers 0..16:
/// 0=rax, 1=rdx, 2=rcx, 3=rbx, 4=rsi, 5=rdi, 6=rbp, 7=rsp,
/// 8..15=r8..r15, 16=rip
pub const UnwindRegs = extern struct {
    r: [17]u64 = .{0} ** 17,

    pub const RAX: usize = 0;
    pub const RDX: usize = 1;
    pub const RCX: usize = 2;
    pub const RBX: usize = 3;
    pub const RSI: usize = 4;
    pub const RDI: usize = 5;
    pub const RBP: usize = 6;
    pub const RSP: usize = 7;
    pub const R8: usize = 8;
    pub const R9: usize = 9;
    pub const R10: usize = 10;
    pub const R11: usize = 11;
    pub const R12: usize = 12;
    pub const R13: usize = 13;
    pub const R14: usize = 14;
    pub const R15: usize = 15;
    pub const RIP: usize = 16;
};

comptime {
    std.debug.assert(@sizeOf(UnwindRegs) == 136);
}

pub const FrameInfo = struct {
    dso_base: usize = 0,
    start_ip: usize = 0,
    end_ip: usize = 0,
    lsda: usize = 0,
    personality: usize = 0,
    encoding: u32 = 0,
};

pub const UnwindCursor = struct {
    regs: UnwindRegs,
    frame: FrameInfo = .{},
};

pub const PersonalityFn = *const fn (
    version: c_int,
    actions: c_int,
    exception_class: u64,
    exception_object: *UnwindException,
    context: *UnwindCursor,
) callconv(.c) c_int;

// ============================================================================
// Apple Mach-O Compact Unwind Constants (mach-o/compact_unwind_encoding.h)
// ============================================================================

const UNWIND_SECTION_VERSION: u32 = 1;
const UNWIND_SECOND_LEVEL_REGULAR: u32 = 2;
const UNWIND_SECOND_LEVEL_COMPRESSED: u32 = 3;

const UNWIND_HAS_LSDA: u32 = 0x40000000;
const UNWIND_PERSONALITY_MASK: u32 = 0x30000000;
const UNWIND_PERSONALITY_SHIFT: u5 = 28;

const UNWIND_X86_64_MODE_MASK: u32 = 0x0F000000;
const UNWIND_X86_64_MODE_RBP_FRAME: u32 = 0x01000000;
const UNWIND_X86_64_MODE_STACK_IMMD: u32 = 0x02000000;
const UNWIND_X86_64_MODE_STACK_IND: u32 = 0x03000000;
const UNWIND_X86_64_MODE_DWARF: u32 = 0x04000000;

const UNWIND_X86_64_REG_NONE: u32 = 0;
const UNWIND_X86_64_REG_RBX: u32 = 1;
const UNWIND_X86_64_REG_R12: u32 = 2;
const UNWIND_X86_64_REG_R13: u32 = 3;
const UNWIND_X86_64_REG_R14: u32 = 4;
const UNWIND_X86_64_REG_R15: u32 = 5;
const UNWIND_X86_64_REG_RBP: u32 = 6;

const UnwindSectionHeader = extern struct {
    version: u32,
    common_encodings_offset: u32,
    common_encodings_count: u32,
    personality_offset: u32,
    personality_count: u32,
    index_offset: u32,
    index_count: u32,
};

const TopLevelIndexEntry = extern struct {
    function_offset: u32,
    second_level_offset: u32,
    lsda_index_offset: u32,
};

const LsdaIndexEntry = extern struct {
    function_offset: u32,
    lsda_offset: u32,
};

const RegularPageHeader = extern struct {
    kind: u32,
    entry_page_offset: u16,
    entry_count: u16,
};

const RegularEntry = extern struct {
    function_offset: u32,
    encoding: u32,
};

const CompressedPageHeader = extern struct {
    kind: u32,
    entry_page_offset: u16,
    entry_count: u16,
    encodings_page_offset: u16,
    encodings_count: u16,
};

// ============================================================================
// Registered Mach-O Unwind Sections
// ============================================================================

pub const ImageUnwindEntry = struct {
    dso_base: usize = 0,
    text_start: usize = 0,
    text_end: usize = 0,
    unwind_info_addr: usize = 0,
    unwind_info_size: usize = 0,
    eh_frame_addr: usize = 0,
    eh_frame_size: usize = 0,
};

const MAX_IMAGES = 128;
var g_images: [MAX_IMAGES]ImageUnwindEntry = .{ImageUnwindEntry{}} ** MAX_IMAGES;
var g_image_count: usize = 0;
var g_images_lock: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

fn lockImages() void {
    while (g_images_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
        std.atomic.spinLoopHint();
    }
}

fn unlockImages() void {
    g_images_lock.store(0, .release);
}

pub fn clearImages() void {
    lockImages();
    defer unlockImages();
    g_image_count = 0;
}

pub fn registerImage(entry: ImageUnwindEntry) void {
    if (entry.unwind_info_addr == 0 and entry.eh_frame_addr == 0) return;
    lockImages();
    defer unlockImages();
    if (g_image_count < MAX_IMAGES) {
        g_images[g_image_count] = entry;
        g_image_count += 1;
    }
}

inline fn readMem(comptime T: type, addr: usize) T {
    const p: *align(1) const T = @ptrFromInt(addr);
    return p.*;
}

pub fn lookupCompactUnwind(entry: ImageUnwindEntry, pc: usize) ?FrameInfo {
    if (entry.unwind_info_addr == 0 or entry.unwind_info_size < @sizeOf(UnwindSectionHeader)) return null;
    if (pc < entry.dso_base) return null;

    const sect = entry.unwind_info_addr;
    const hdr = readMem(UnwindSectionHeader, sect);
    if (hdr.version != UNWIND_SECTION_VERSION or hdr.index_count < 2) return null;

    const target_offset: u64 = pc - entry.dso_base;
    if (target_offset > std.math.maxInt(u32)) return null;
    const target_off32: u32 = @intCast(target_offset);

    const top_base = sect + hdr.index_offset;
    const first_entry = readMem(TopLevelIndexEntry, top_base);
    const sentinel_entry = readMem(TopLevelIndexEntry, top_base + (@as(usize, hdr.index_count - 1) * @sizeOf(TopLevelIndexEntry)));
    if (target_off32 < first_entry.function_offset or target_off32 >= sentinel_entry.function_offset) return null;

    // Binary search top-level index (last entry is sentinel with second_level_offset == 0)
    var low: u32 = 0;
    var high: u32 = hdr.index_count - 1;
    const last_top: u32 = hdr.index_count - 2;
    while (low < high) {
        const mid = low + (high - low) / 2;
        const mid_off = readMem(TopLevelIndexEntry, top_base + @as(usize, mid) * @sizeOf(TopLevelIndexEntry)).function_offset;
        if (mid_off <= target_off32) {
            if (mid == last_top) {
                low = mid;
                break;
            }
            const next_off = readMem(TopLevelIndexEntry, top_base + @as(usize, mid + 1) * @sizeOf(TopLevelIndexEntry)).function_offset;
            if (next_off > target_off32) {
                low = mid;
                break;
            }
            low = mid + 1;
        } else {
            high = mid;
        }
    }

    const top = readMem(TopLevelIndexEntry, top_base + @as(usize, low) * @sizeOf(TopLevelIndexEntry));
    const top_next = readMem(TopLevelIndexEntry, top_base + @as(usize, low + 1) * @sizeOf(TopLevelIndexEntry));
    if (top.second_level_offset == 0) return null;

    const second_addr = sect + top.second_level_offset;
    const page_kind = readMem(u32, second_addr);

    var encoding: u32 = 0;
    var func_start: usize = 0;
    var func_end: usize = 0;

    if (page_kind == UNWIND_SECOND_LEVEL_REGULAR) {
        const ph = readMem(RegularPageHeader, second_addr);
        if (ph.entry_count == 0) return null;
        const arr_base = second_addr + ph.entry_page_offset;
        var l: u32 = 0;
        var h: u32 = ph.entry_count;
        const last_i: u32 = ph.entry_count - 1;
        while (l < h) {
            const m = l + (h - l) / 2;
            const m_ent = readMem(RegularEntry, arr_base + @as(usize, m) * @sizeOf(RegularEntry));
            if (m_ent.function_offset <= target_off32) {
                if (m == last_i) {
                    l = m;
                    func_end = entry.dso_base + top_next.function_offset;
                    break;
                }
                const n_ent = readMem(RegularEntry, arr_base + @as(usize, m + 1) * @sizeOf(RegularEntry));
                if (n_ent.function_offset > target_off32) {
                    l = m;
                    func_end = entry.dso_base + n_ent.function_offset;
                    break;
                }
                l = m + 1;
            } else {
                h = m;
            }
        }
        const chosen = readMem(RegularEntry, arr_base + @as(usize, l) * @sizeOf(RegularEntry));
        encoding = chosen.encoding;
        func_start = entry.dso_base + chosen.function_offset;
        if (func_end == 0) func_end = entry.dso_base + top_next.function_offset;
    } else if (page_kind == UNWIND_SECOND_LEVEL_COMPRESSED) {
        const ph = readMem(CompressedPageHeader, second_addr);
        if (ph.entry_count == 0) return null;
        const arr_base = second_addr + ph.entry_page_offset;
        const page_target: u32 = target_off32 - top.function_offset;

        var l: u32 = 0;
        var h: u32 = ph.entry_count;
        const last_i: u32 = ph.entry_count - 1;
        while (l < h) {
            const m = l + (h - l) / 2;
            const m_word = readMem(u32, arr_base + @as(usize, m) * 4);
            const m_off = m_word & 0x00FFFFFF;
            if (m_off <= page_target) {
                if (m == last_i) {
                    l = m;
                    break;
                }
                const n_word = readMem(u32, arr_base + @as(usize, m + 1) * 4);
                const n_off = n_word & 0x00FFFFFF;
                if (n_off > page_target) {
                    l = m;
                    break;
                }
                l = m + 1;
            } else {
                h = m;
            }
        }
        const chosen_word = readMem(u32, arr_base + @as(usize, l) * 4);
        const chosen_off = chosen_word & 0x00FFFFFF;
        const enc_idx: u32 = (chosen_word >> 24) & 0xFF;

        func_start = entry.dso_base + top.function_offset + chosen_off;
        if (l < last_i) {
            const next_word = readMem(u32, arr_base + @as(usize, l + 1) * 4);
            func_end = entry.dso_base + top.function_offset + (next_word & 0x00FFFFFF);
        } else {
            func_end = entry.dso_base + top_next.function_offset;
        }

        if (enc_idx < hdr.common_encodings_count) {
            encoding = readMem(u32, sect + hdr.common_encodings_offset + @as(usize, enc_idx) * 4);
        } else {
            const page_enc_idx = enc_idx - hdr.common_encodings_count;
            if (page_enc_idx >= ph.encodings_count) return null;
            encoding = readMem(u32, second_addr + ph.encodings_page_offset + @as(usize, page_enc_idx) * 4);
        }
    } else {
        return null;
    }

    if (pc < func_start or pc > func_end) return null;

    var lsda: usize = 0;
    if ((encoding & UNWIND_HAS_LSDA) != 0) {
        const lsda_start = sect + top.lsda_index_offset;
        const lsda_end = sect + top_next.lsda_index_offset;
        const lsda_count: u32 = if (lsda_end > lsda_start)
            @intCast((lsda_end - lsda_start) / @sizeOf(LsdaIndexEntry))
        else
            0;
        const func_start_off: u32 = @intCast(func_start - entry.dso_base);
        var l: u32 = 0;
        var h: u32 = lsda_count;
        while (l < h) {
            const m = l + (h - l) / 2;
            const le = readMem(LsdaIndexEntry, lsda_start + @as(usize, m) * @sizeOf(LsdaIndexEntry));
            if (le.function_offset == func_start_off) {
                lsda = entry.dso_base + le.lsda_offset;
                break;
            } else if (le.function_offset < func_start_off) {
                l = m + 1;
            } else {
                h = m;
            }
        }
    }

    var personality: usize = 0;
    const pers_idx = (encoding & UNWIND_PERSONALITY_MASK) >> UNWIND_PERSONALITY_SHIFT;
    if (pers_idx != 0 and pers_idx <= hdr.personality_count) {
        const pers_delta_raw = readMem(u32, sect + hdr.personality_offset + @as(usize, pers_idx - 1) * 4);
        const pers_delta: i32 = @bitCast(pers_delta_raw);
        const got_slot: usize = @intCast(@as(isize, @intCast(entry.dso_base)) + @as(isize, pers_delta));
        personality = readMem(usize, got_slot);
    }

    return FrameInfo{
        .dso_base = entry.dso_base,
        .start_ip = func_start,
        .end_ip = func_end,
        .lsda = lsda,
        .personality = personality,
        .encoding = encoding,
    };
}

pub fn findFrameInfo(pc: usize) ?FrameInfo {
    lockImages();
    const count = g_image_count;
    var snapshot: [MAX_IMAGES]ImageUnwindEntry = undefined;
    for (0..count) |i| snapshot[i] = g_images[i];
    unlockImages();

    for (snapshot[0..count]) |img| {
        if (pc >= img.text_start and pc < img.text_end) {
            if (lookupCompactUnwind(img, pc)) |info| return info;
        }
    }
    return null;
}

// ============================================================================
// Compact Unwind x86_64 Frame Stepping (matches LLVM CompactUnwinder_x86_64)
// ============================================================================

pub fn stepCompactX86_64(encoding: u32, func_start: usize, regs: *UnwindRegs) bool {
    const mode = encoding & UNWIND_X86_64_MODE_MASK;
    switch (mode) {
        UNWIND_X86_64_MODE_RBP_FRAME => {
            const saved_regs_offset: u64 = (encoding & 0x00FF0000) >> 16;
            var saved_locs: u32 = encoding & 0x00007FFF;
            var saved_ptr: usize = @intCast(regs.r[UnwindRegs.RBP] - 8 * saved_regs_offset);

            var i: usize = 0;
            while (i < 5) : (i += 1) {
                switch (saved_locs & 0x7) {
                    UNWIND_X86_64_REG_NONE => {},
                    UNWIND_X86_64_REG_RBX => regs.r[UnwindRegs.RBX] = readMem(u64, saved_ptr),
                    UNWIND_X86_64_REG_R12 => regs.r[UnwindRegs.R12] = readMem(u64, saved_ptr),
                    UNWIND_X86_64_REG_R13 => regs.r[UnwindRegs.R13] = readMem(u64, saved_ptr),
                    UNWIND_X86_64_REG_R14 => regs.r[UnwindRegs.R14] = readMem(u64, saved_ptr),
                    UNWIND_X86_64_REG_R15 => regs.r[UnwindRegs.R15] = readMem(u64, saved_ptr),
                    else => return false,
                }
                saved_ptr += 8;
                saved_locs >>= 3;
            }
            const rbp: usize = @intCast(regs.r[UnwindRegs.RBP]);
            regs.r[UnwindRegs.RBP] = readMem(u64, rbp);
            regs.r[UnwindRegs.RIP] = readMem(u64, rbp + 8);
            regs.r[UnwindRegs.RSP] = @intCast(rbp + 16);
            return true;
        },
        UNWIND_X86_64_MODE_STACK_IMMD, UNWIND_X86_64_MODE_STACK_IND => {
            const stack_size_encoded: u64 = (encoding & 0x00FF0000) >> 16;
            const stack_adjust: u64 = (encoding & 0x0000E000) >> 13;
            const reg_count: u32 = (encoding & 0x00001C00) >> 10;
            var permutation: u32 = encoding & 0x000003FF;
            if (reg_count > 6) return false;

            var stack_size: u64 = stack_size_encoded * 8;
            if (mode == UNWIND_X86_64_MODE_STACK_IND) {
                const subq_imm: u64 = readMem(u32, func_start + @as(usize, @intCast(stack_size_encoded)));
                stack_size = subq_imm + 8 * stack_adjust;
            }

            var permunreg: [6]u32 = .{0} ** 6;
            switch (reg_count) {
                6 => {
                    permunreg[0] = permutation / 120;
                    permutation -= permunreg[0] * 120;
                    permunreg[1] = permutation / 24;
                    permutation -= permunreg[1] * 24;
                    permunreg[2] = permutation / 6;
                    permutation -= permunreg[2] * 6;
                    permunreg[3] = permutation / 2;
                    permutation -= permunreg[3] * 2;
                    permunreg[4] = permutation;
                    permunreg[5] = 0;
                },
                5 => {
                    permunreg[0] = permutation / 120;
                    permutation -= permunreg[0] * 120;
                    permunreg[1] = permutation / 24;
                    permutation -= permunreg[1] * 24;
                    permunreg[2] = permutation / 6;
                    permutation -= permunreg[2] * 6;
                    permunreg[3] = permutation / 2;
                    permutation -= permunreg[3] * 2;
                    permunreg[4] = permutation;
                },
                4 => {
                    permunreg[0] = permutation / 60;
                    permutation -= permunreg[0] * 60;
                    permunreg[1] = permutation / 12;
                    permutation -= permunreg[1] * 12;
                    permunreg[2] = permutation / 3;
                    permutation -= permunreg[2] * 3;
                    permunreg[3] = permutation;
                },
                3 => {
                    permunreg[0] = permutation / 20;
                    permutation -= permunreg[0] * 20;
                    permunreg[1] = permutation / 4;
                    permutation -= permunreg[1] * 4;
                    permunreg[2] = permutation;
                },
                2 => {
                    permunreg[0] = permutation / 5;
                    permutation -= permunreg[0] * 5;
                    permunreg[1] = permutation;
                },
                1 => {
                    permunreg[0] = permutation;
                },
                0 => {},
                else => return false,
            }

            var regs_saved: [6]u32 = .{0} ** 6;
            var used: [7]bool = .{false} ** 7;
            var i: usize = 0;
            while (i < reg_count) : (i += 1) {
                var renum: u32 = 0;
                var u: u32 = 1;
                while (u < 7) : (u += 1) {
                    if (!used[u]) {
                        if (renum == permunreg[i]) {
                            regs_saved[i] = u;
                            used[u] = true;
                            break;
                        }
                        renum += 1;
                    }
                }
            }

            var saved_ptr: usize = @intCast(regs.r[UnwindRegs.RSP] + stack_size - 8 - 8 * @as(u64, reg_count));
            i = 0;
            while (i < reg_count) : (i += 1) {
                switch (regs_saved[i]) {
                    UNWIND_X86_64_REG_RBX => regs.r[UnwindRegs.RBX] = readMem(u64, saved_ptr),
                    UNWIND_X86_64_REG_R12 => regs.r[UnwindRegs.R12] = readMem(u64, saved_ptr),
                    UNWIND_X86_64_REG_R13 => regs.r[UnwindRegs.R13] = readMem(u64, saved_ptr),
                    UNWIND_X86_64_REG_R14 => regs.r[UnwindRegs.R14] = readMem(u64, saved_ptr),
                    UNWIND_X86_64_REG_R15 => regs.r[UnwindRegs.R15] = readMem(u64, saved_ptr),
                    UNWIND_X86_64_REG_RBP => regs.r[UnwindRegs.RBP] = readMem(u64, saved_ptr),
                    else => return false,
                }
                saved_ptr += 8;
            }
            regs.r[UnwindRegs.RIP] = readMem(u64, saved_ptr);
            regs.r[UnwindRegs.RSP] = @intCast(saved_ptr + 8);
            return true;
        },
        UNWIND_X86_64_MODE_DWARF => {
            std.debug.print("WINS-UNWIND: DWARF FDE compact encoding 0x{x} at func=0x{x} not yet supported\n", .{ encoding, func_start });
            return false;
        },
        else => return false,
    }
}

// ============================================================================
// Two-Phase Itanium Unwind Engine
// ============================================================================

fn unwindPhase1(initial_regs: *const UnwindRegs, exc: *UnwindException) c_int {
    var cursor = UnwindCursor{ .regs = initial_regs.* };
    var depth: usize = 0;
    while (depth < 1024) : (depth += 1) {
        const rip: usize = @intCast(cursor.regs.r[UnwindRegs.RIP]);
        if (rip == 0) return URC_END_OF_STACK;
        const info = findFrameInfo(rip - 1) orelse return URC_END_OF_STACK;
        cursor.frame = info;

        if (info.personality != 0) {
            const pers: PersonalityFn = @ptrFromInt(info.personality);
            const rc = pers(1, UA_SEARCH_PHASE, exc.exception_class, exc, &cursor);
            switch (rc) {
                URC_HANDLER_FOUND => {
                    exc.private_2 = @intCast(cursor.regs.r[UnwindRegs.RSP]);
                    return URC_NO_REASON;
                },
                URC_CONTINUE_UNWIND => {},
                else => return URC_FATAL_PHASE1_ERROR,
            }
        }

        if (!stepCompactX86_64(info.encoding, info.start_ip, &cursor.regs)) {
            return URC_END_OF_STACK;
        }
    }
    return URC_END_OF_STACK;
}

fn unwindPhase2(initial_regs: *const UnwindRegs, exc: *UnwindException) c_int {
    var cursor = UnwindCursor{ .regs = initial_regs.* };
    var depth: usize = 0;
    while (depth < 1024) : (depth += 1) {
        const rip: usize = @intCast(cursor.regs.r[UnwindRegs.RIP]);
        if (rip == 0) return URC_END_OF_STACK;
        const info = findFrameInfo(rip - 1) orelse return URC_END_OF_STACK;
        cursor.frame = info;

        if (info.personality != 0) {
            const pers: PersonalityFn = @ptrFromInt(info.personality);
            const sp: usize = @intCast(cursor.regs.r[UnwindRegs.RSP]);
            const action: c_int = if (sp == exc.private_2)
                (UA_CLEANUP_PHASE | UA_HANDLER_FRAME)
            else
                UA_CLEANUP_PHASE;
            const rc = pers(1, action, exc.exception_class, exc, &cursor);
            switch (rc) {
                URC_CONTINUE_UNWIND => {
                    if (sp == exc.private_2) return URC_FATAL_PHASE2_ERROR;
                },
                URC_INSTALL_CONTEXT => {
                    jumpToRegs(&cursor.regs);
                },
                else => return URC_FATAL_PHASE2_ERROR,
            }
        }

        if (!stepCompactX86_64(info.encoding, info.start_ip, &cursor.regs)) {
            return URC_FATAL_PHASE2_ERROR;
        }
    }
    return URC_FATAL_PHASE2_ERROR;
}

pub fn unwindRaiseFromRegs(exc: *UnwindException, initial_regs: *const UnwindRegs) callconv(.c) c_int {
    if (trace.active_tracer) |t| t.recordExternalCall("__Unwind_RaiseException");
    exc.private_1 = 0;
    exc.private_2 = 0;
    const p1 = unwindPhase1(initial_regs, exc);
    if (p1 != URC_NO_REASON) return p1;
    return unwindPhase2(initial_regs, exc);
}

pub fn unwindResumeFromRegs(exc: *UnwindException, initial_regs: *const UnwindRegs) callconv(.c) noreturn {
    if (trace.active_tracer) |t| t.recordExternalCall("__Unwind_Resume");
    _ = unwindPhase2(initial_regs, exc);
    std.debug.print("WINS-UNWIND: _Unwind_Resume phase 2 failed\n", .{});
    std.c.abort();
}

// ============================================================================
// x86_64 Naked Context Transfer & Register Capture Trampolines
// ============================================================================

/// Restores all x86_64 GPRs + RSP from `regs` (passed in %rdi) and jumps to `regs.rip`.
fn unwindJumpToNaked() callconv(.naked) void {
    asm volatile (
        \\movq 128(%%rdi), %%r11
        \\movq 0(%%rdi), %%rax
        \\movq 8(%%rdi), %%rdx
        \\movq 16(%%rdi), %%rcx
        \\movq 24(%%rdi), %%rbx
        \\movq 32(%%rdi), %%rsi
        \\movq 48(%%rdi), %%rbp
        \\movq 56(%%rdi), %%rsp
        \\movq 64(%%rdi), %%r8
        \\movq 72(%%rdi), %%r9
        \\movq 80(%%rdi), %%r10
        \\movq 96(%%rdi), %%r12
        \\movq 104(%%rdi), %%r13
        \\movq 112(%%rdi), %%r14
        \\movq 120(%%rdi), %%r15
        \\movq 40(%%rdi), %%rdi
        \\jmpq *%%r11
    );
}

pub fn jumpToRegs(regs: *const UnwindRegs) noreturn {
    const f: *const fn (*const UnwindRegs) callconv(.c) noreturn = @ptrCast(&unwindJumpToNaked);
    f(regs);
}

pub fn shim_unwind_raise_exception() callconv(.naked) void {
    // Entry: rdi = *UnwindException, 0(%rsp) = return addr, %rsp+8 = caller RSP, %rsp%16 == 8
    asm volatile (
        \\subq $152, %%rsp
        \\movq %%rax, 0(%%rsp)
        \\movq %%rdx, 8(%%rsp)
        \\movq %%rcx, 16(%%rsp)
        \\movq %%rbx, 24(%%rsp)
        \\movq %%rsi, 32(%%rsp)
        \\movq %%rdi, 40(%%rsp)
        \\movq %%rbp, 48(%%rsp)
        \\leaq 160(%%rsp), %%r11
        \\movq %%r11, 56(%%rsp)
        \\movq %%r8, 64(%%rsp)
        \\movq %%r9, 72(%%rsp)
        \\movq %%r10, 80(%%rsp)
        \\movq %%r11, 88(%%rsp)
        \\movq %%r12, 96(%%rsp)
        \\movq %%r13, 104(%%rsp)
        \\movq %%r14, 112(%%rsp)
        \\movq %%r15, 120(%%rsp)
        \\movq 152(%%rsp), %%r11
        \\movq %%r11, 128(%%rsp)
        \\movq %%rsp, %%rsi
        \\call %[impl:P]
        \\movq 24(%%rsp), %%rbx
        \\movq 48(%%rsp), %%rbp
        \\movq 96(%%rsp), %%r12
        \\movq 104(%%rsp), %%r13
        \\movq 112(%%rsp), %%r14
        \\movq 120(%%rsp), %%r15
        \\addq $152, %%rsp
        \\retq
        :
        : [impl] "X" (&unwindRaiseFromRegs),
    );
}

pub fn shim_unwind_resume() callconv(.naked) void {
    // Entry: rdi = *UnwindException
    asm volatile (
        \\subq $152, %%rsp
        \\movq %%rax, 0(%%rsp)
        \\movq %%rdx, 8(%%rsp)
        \\movq %%rcx, 16(%%rsp)
        \\movq %%rbx, 24(%%rsp)
        \\movq %%rsi, 32(%%rsp)
        \\movq %%rdi, 40(%%rsp)
        \\movq %%rbp, 48(%%rsp)
        \\leaq 160(%%rsp), %%r11
        \\movq %%r11, 56(%%rsp)
        \\movq %%r8, 64(%%rsp)
        \\movq %%r9, 72(%%rsp)
        \\movq %%r10, 80(%%rsp)
        \\movq %%r11, 88(%%rsp)
        \\movq %%r12, 96(%%rsp)
        \\movq %%r13, 104(%%rsp)
        \\movq %%r14, 112(%%rsp)
        \\movq %%r15, 120(%%rsp)
        \\movq 152(%%rsp), %%r11
        \\movq %%r11, 128(%%rsp)
        \\movq %%rsp, %%rsi
        \\call %[impl:P]
        \\ud2
        :
        : [impl] "X" (&unwindResumeFromRegs),
    );
}

// ============================================================================
// Itanium Level-1 Context Accessors
// ============================================================================

pub fn shim_unwind_get_ip(ctx: ?*UnwindCursor) callconv(.c) usize {
    const c = ctx orelse return 0;
    return @intCast(c.regs.r[UnwindRegs.RIP]);
}

pub fn shim_unwind_set_ip(ctx: ?*UnwindCursor, val: usize) callconv(.c) void {
    const c = ctx orelse return;
    c.regs.r[UnwindRegs.RIP] = @intCast(val);
}

pub fn shim_unwind_get_gr(ctx: ?*UnwindCursor, index: c_int) callconv(.c) usize {
    const c = ctx orelse return 0;
    if (index < 0 or index >= 17) return 0;
    return @intCast(c.regs.r[@intCast(index)]);
}

pub fn shim_unwind_set_gr(ctx: ?*UnwindCursor, index: c_int, val: usize) callconv(.c) void {
    const c = ctx orelse return;
    if (index < 0 or index >= 17) return;
    c.regs.r[@intCast(index)] = @intCast(val);
}

pub fn shim_unwind_get_lsda(ctx: ?*UnwindCursor) callconv(.c) ?*const anyopaque {
    const c = ctx orelse return null;
    if (c.frame.lsda == 0) return null;
    return @ptrFromInt(c.frame.lsda);
}

pub fn shim_unwind_get_region_start(ctx: ?*UnwindCursor) callconv(.c) usize {
    const c = ctx orelse return 0;
    return c.frame.start_ip;
}

pub fn shim_unwind_get_data_rel_base(ctx: ?*UnwindCursor) callconv(.c) usize {
    const c = ctx orelse return 0;
    return c.frame.dso_base;
}

pub fn shim_unwind_get_text_rel_base(ctx: ?*UnwindCursor) callconv(.c) usize {
    const c = ctx orelse return 0;
    return c.frame.dso_base;
}

pub fn shim_unwind_delete_exception(exc: ?*UnwindException) callconv(.c) void {
    const e = exc orelse return;
    if (e.exception_cleanup) |cleanup| {
        cleanup(URC_FOREIGN_EXCEPTION_CAUGHT, e);
    }
}
