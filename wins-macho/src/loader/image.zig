const std = @import("std");
const parser = @import("../macho/parser.zig");
const types = @import("../macho/types.zig");

pub const SegmentMapping = struct {
    name: []const u8,
    requested_vmaddr: u64,
    actual_address: usize,
    slide: i64,
    fileoff: u64,
    filesize: u64,
    vmsize: u64,
    initprot: i32,
    maxprot: i32,
    skipped_pagezero: bool,
    final_prot_applied: bool,
};

pub const MappedImage = struct {
    allocator: std.mem.Allocator,
    path: []const u8,
    parsed: parser.ParsedMachO,
    base_ptr: [*]align(4096) u8,
    total_vm_size: usize,
    preferred_base_vmaddr: u64,
    actual_base: usize,
    slide: i64,
    mappings: []SegmentMapping,
    entry_address: ?usize,

    pub fn deinit(self: *MappedImage) void {
        _ = std.c.munmap(self.base_ptr, self.total_vm_size);
        self.allocator.free(self.mappings);
        self.parsed.deinit();
    }

    pub fn vmToActual(self: *const MappedImage, vmaddr: u64) usize {
        const signed_vm: i64 = @bitCast(vmaddr);
        return @intCast(signed_vm + self.slide);
    }

    pub fn segOffsetToActual(self: *const MappedImage, seg_index: usize, seg_offset: u64) ?usize {
        if (seg_index >= self.parsed.segments.len) return null;
        const seg = self.parsed.segments[seg_index].cmd;
        if (seg_offset >= seg.vmsize) return null;
        return self.vmToActual(seg.vmaddr + seg_offset);
    }
};
