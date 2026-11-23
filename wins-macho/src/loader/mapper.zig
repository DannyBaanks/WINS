const std = @import("std");
const parser = @import("../macho/parser.zig");
const types = @import("../macho/types.zig");
const image = @import("image.zig");

const PAGE_SIZE: usize = 4096;

pub const MapError = error{
    NoMappableSegments,
    MmapFailed,
    MprotectFailed,
    IntegerOverflow,
    OutOfMemory,
};

fn alignDown(val: u64, align_to: u64) u64 {
    return val & ~(align_to - 1);
}

fn alignUp(val: u64, align_to: u64) u64 {
    return (val + align_to - 1) & ~(align_to - 1);
}

pub fn machProtToLinux(prot: i32) std.c.PROT {
    return .{
        .READ = (prot & types.VM_PROT_READ) != 0,
        .WRITE = (prot & types.VM_PROT_WRITE) != 0,
        .EXEC = (prot & types.VM_PROT_EXECUTE) != 0,
    };
}

pub fn mapImage(allocator: std.mem.Allocator, path: []const u8, parsed: parser.ParsedMachO) MapError!image.MappedImage {
    var min_vm: u64 = std.math.maxInt(u64);
    var max_vm: u64 = 0;
    var found_any = false;

    for (parsed.segments) |seg| {
        if (std.mem.eql(u8, seg.name, "__PAGEZERO") and seg.cmd.filesize == 0 and seg.cmd.initprot == 0) {
            continue;
        }
        if (seg.cmd.vmsize == 0) continue;
        found_any = true;
        const seg_start = alignDown(seg.cmd.vmaddr, PAGE_SIZE);
        const seg_end = alignUp(seg.cmd.vmaddr + seg.cmd.vmsize, PAGE_SIZE);
        if (seg_start < min_vm) min_vm = seg_start;
        if (seg_end > max_vm) max_vm = seg_end;
    }

    if (!found_any or max_vm <= min_vm) return error.NoMappableSegments;
    const total_size_u64 = max_vm - min_vm;
    const total_size: usize = std.math.cast(usize, total_size_u64) orelse return error.IntegerOverflow;

    const map_flags = std.c.MAP{ .TYPE = .PRIVATE, .ANONYMOUS = true };
    const raw_ptr = std.c.mmap(null, total_size, .{}, map_flags, -1, 0);
    if (raw_ptr == std.c.MAP_FAILED) return error.MmapFailed;
    const base_ptr: [*]align(4096) u8 = @ptrCast(@alignCast(raw_ptr));
    errdefer _ = std.c.munmap(base_ptr, total_size);

    const actual_base: usize = @intFromPtr(base_ptr);
    const slide: i64 = @as(i64, @intCast(actual_base)) - @as(i64, @bitCast(min_vm));

    var mappings = try allocator.alloc(image.SegmentMapping, parsed.segments.len);
    errdefer allocator.free(mappings);

    for (parsed.segments, 0..) |seg, i| {
        const is_pagezero = std.mem.eql(u8, seg.name, "__PAGEZERO") and seg.cmd.filesize == 0 and seg.cmd.initprot == 0;
        if (is_pagezero or seg.cmd.vmsize == 0) {
            mappings[i] = .{
                .name = seg.name,
                .requested_vmaddr = seg.cmd.vmaddr,
                .actual_address = 0,
                .slide = 0,
                .fileoff = seg.cmd.fileoff,
                .filesize = seg.cmd.filesize,
                .vmsize = seg.cmd.vmsize,
                .initprot = seg.cmd.initprot,
                .maxprot = seg.cmd.maxprot,
                .skipped_pagezero = is_pagezero,
                .final_prot_applied = true,
            };
            continue;
        }

        const rel_start: usize = @intCast(alignDown(seg.cmd.vmaddr, PAGE_SIZE) - min_vm);
        const rel_end: usize = @intCast(alignUp(seg.cmd.vmaddr + seg.cmd.vmsize, PAGE_SIZE) - min_vm);
        const prot_len = rel_end - rel_start;

        // Temporarily PROT_READ | PROT_WRITE to copy segment bytes, zero-fill, and apply dyld fixups
        const seg_page_ptr: *align(4096) anyopaque = @ptrCast(@alignCast(base_ptr + rel_start));
        if (std.c.mprotect(seg_page_ptr, prot_len, .{ .READ = true, .WRITE = true }) != 0) {
            return error.MprotectFailed;
        }

        const exact_offset: usize = @intCast(seg.cmd.vmaddr - min_vm);
        const dest = base_ptr + exact_offset;
        if (seg.cmd.filesize > 0) {
            const fstart: usize = @intCast(seg.cmd.fileoff);
            const fend: usize = fstart + @as(usize, @intCast(seg.cmd.filesize));
            @memcpy(dest[0..@intCast(seg.cmd.filesize)], parsed.raw[fstart..fend]);
        }
        if (seg.cmd.vmsize > seg.cmd.filesize) {
            const zstart: usize = @intCast(seg.cmd.filesize);
            const zlen: usize = @intCast(seg.cmd.vmsize - seg.cmd.filesize);
            @memset(dest[zstart .. zstart + zlen], 0);
        }

        mappings[i] = .{
            .name = seg.name,
            .requested_vmaddr = seg.cmd.vmaddr,
            .actual_address = actual_base + exact_offset,
            .slide = slide,
            .fileoff = seg.cmd.fileoff,
            .filesize = seg.cmd.filesize,
            .vmsize = seg.cmd.vmsize,
            .initprot = seg.cmd.initprot,
            .maxprot = seg.cmd.maxprot,
            .skipped_pagezero = false,
            .final_prot_applied = false,
        };
    }

    var entry_addr: ?usize = null;
    if (parsed.main_entry) |ep| {
        entry_addr = actual_base + @as(usize, @intCast(ep.entryoff));
    }

    return .{
        .allocator = allocator,
        .path = path,
        .parsed = parsed,
        .base_ptr = base_ptr,
        .total_vm_size = total_size,
        .preferred_base_vmaddr = min_vm,
        .actual_base = actual_base,
        .slide = slide,
        .mappings = mappings,
        .entry_address = entry_addr,
    };
}

pub fn finalizeProtections(img: *image.MappedImage) MapError!void {
    for (img.parsed.segments, 0..) |seg, i| {
        if (img.mappings[i].skipped_pagezero or seg.cmd.vmsize == 0) continue;
        const rel_start: usize = @intCast(alignDown(seg.cmd.vmaddr, PAGE_SIZE) - img.preferred_base_vmaddr);
        const rel_end: usize = @intCast(alignUp(seg.cmd.vmaddr + seg.cmd.vmsize, PAGE_SIZE) - img.preferred_base_vmaddr);
        const prot_len = rel_end - rel_start;
        const linux_prot = machProtToLinux(seg.cmd.initprot);
        const seg_page_ptr: *align(4096) anyopaque = @ptrCast(@alignCast(img.base_ptr + rel_start));
        if (std.c.mprotect(seg_page_ptr, prot_len, linux_prot) != 0) {
            return error.MprotectFailed;
        }
        img.mappings[i].final_prot_applied = true;
    }
}
