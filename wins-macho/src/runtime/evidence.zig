const std = @import("std");
const trace = @import("trace.zig");
const image = @import("../loader/image.zig");
const resolver = @import("../dyld/resolver.zig");

fn writeFile(dir: []const u8, name: []const u8, content: []const u8) void {
    var path_buf: [512]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/{s}\x00", .{ dir, name }) catch return;
    const fd = std.c.open(@ptrCast(path.ptr), .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, @as(std.c.mode_t, 0o644));
    if (fd < 0) return;
    defer _ = std.c.close(fd);
    var off: usize = 0;
    while (off < content.len) {
        const n = std.os.linux.write(fd, content.ptr + off, content.len - off);
        const sn: isize = @bitCast(n);
        if (sn <= 0) break;
        off += @intCast(sn);
    }
}

pub fn ensureDir(path: []const u8) void {
    var buf: [512]u8 = undefined;
    const z = std.fmt.bufPrint(&buf, "{s}\x00", .{path}) catch return;
    _ = std.os.linux.mkdir(@ptrCast(z.ptr), 0o755);
}

pub fn writeRunEvidence(
    allocator: std.mem.Allocator,
    evidence_dir: []const u8,
    target_path: []const u8,
    raw_bytes: []const u8,
    dyld: *const resolver.DyldContext,
    tracer: *const trace.Tracer,
    exit_code: ?c_int,
    seccomp_active: bool,
) void {
    ensureDir("evidence");
    ensureDir(evidence_dir);

    // 1. host.json
    {
        var uts: std.os.linux.utsname = undefined;
        _ = std.os.linux.uname(&uts);
        const sysname = std.mem.sliceTo(&uts.sysname, 0);
        const machine = std.mem.sliceTo(&uts.machine, 0);
        const release = std.mem.sliceTo(&uts.release, 0);
        const host_json = std.fmt.allocPrint(allocator,
            "{{\n  \"sysname\": \"{s}\",\n  \"machine\": \"{s}\",\n  \"release\": \"{s}\",\n  \"seccomp_darwin_trap_active\": {}\n}}\n",
            .{ sysname, machine, release, seccomp_active },
        ) catch return;
        defer allocator.free(host_json);
        writeFile(evidence_dir, "host.json", host_json);
    }

    // 2. target.json (SHA-256)
    {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(raw_bytes, &digest, .{});
        const hex = std.fmt.bytesToHex(digest, .lower);
        const target_json = std.fmt.allocPrint(allocator,
            "{{\n  \"path_local\": \"{s}\",\n  \"sha256\": \"{s}\",\n  \"size\": {d},\n  \"arch\": \"x86_64\"\n}}\n",
            .{ target_path, hex, raw_bytes.len },
        ) catch return;
        defer allocator.free(target_json);
        writeFile(evidence_dir, "target.json", target_json);
    }

    // 3. macho.json + mappings.json
    if (dyld.images.items.len > 0) {
        const main_img = &dyld.images.items[0];
        const entryoff = if (main_img.parsed.main_entry) |ep| ep.entryoff else 0;
        const macho_json = std.fmt.allocPrint(allocator,
            "{{\n  \"filetype\": {d},\n  \"ncmds\": {d},\n  \"sizeofcmds\": {d},\n  \"flags\": \"0x{x}\",\n  \"entryoff\": \"0x{x}\",\n  \"entry_address\": \"0x{x}\",\n  \"image_base\": \"0x{x}\",\n  \"slide\": {d}\n}}\n",
            .{
                main_img.parsed.header.filetype,
                main_img.parsed.header.ncmds,
                main_img.parsed.header.sizeofcmds,
                main_img.parsed.header.flags,
                entryoff,
                main_img.entry_address orelse 0,
                main_img.actual_base,
                main_img.slide,
            },
        ) catch return;
        defer allocator.free(macho_json);
        writeFile(evidence_dir, "macho.json", macho_json);

        var map_buf: std.ArrayList(u8) = .empty;
        defer map_buf.deinit(allocator);
        map_buf.appendSlice(allocator, "[\n") catch return;
        for (main_img.mappings, 0..) |m, i| {
            const line = std.fmt.allocPrint(allocator,
                "  {{\"segment\": \"{s}\", \"requested_vmaddr\": \"0x{x}\", \"actual_address\": \"0x{x}\", \"slide\": {d}, \"fileoff\": {d}, \"filesize\": {d}, \"vmsize\": {d}, \"initprot\": {d}, \"skipped_pagezero\": {}, \"final_prot_applied\": {}}}{s}\n",
                .{
                    m.name,
                    m.requested_vmaddr,
                    m.actual_address,
                    m.slide,
                    m.fileoff,
                    m.filesize,
                    m.vmsize,
                    m.initprot,
                    m.skipped_pagezero,
                    m.final_prot_applied,
                    if (i + 1 < main_img.mappings.len) "," else "",
                },
            ) catch continue;
            defer allocator.free(line);
            map_buf.appendSlice(allocator, line) catch {};
        }
        map_buf.appendSlice(allocator, "]\n") catch return;
        writeFile(evidence_dir, "mappings.json", map_buf.items);
    }

    // 4. dependencies.json
    {
        var dep_buf: std.ArrayList(u8) = .empty;
        defer dep_buf.deinit(allocator);
        dep_buf.appendSlice(allocator, "[\n") catch return;
        for (dyld.deps.items, 0..) |d, i| {
            const line = std.fmt.allocPrint(allocator,
                "  {{\"requested\": \"{s}\", \"resolved\": \"{s}\", \"kind\": \"{s}\"}}{s}\n",
                .{ d.requested_name, d.resolved_path, @tagName(d.kind), if (i + 1 < dyld.deps.items.len) "," else "" },
            ) catch continue;
            defer allocator.free(line);
            dep_buf.appendSlice(allocator, line) catch {};
        }
        dep_buf.appendSlice(allocator, "]\n") catch return;
        writeFile(evidence_dir, "dependencies.json", dep_buf.items);
    }

    // 5. symbols.json
    {
        var sym_buf: std.ArrayList(u8) = .empty;
        defer sym_buf.deinit(allocator);
        sym_buf.appendSlice(allocator, "[\n") catch return;
        for (dyld.resolved_symbols.items, 0..) |s, i| {
            const line = std.fmt.allocPrint(allocator,
                "  {{\"symbol\": \"{s}\", \"requested_by\": \"{s}\", \"provider\": \"{s}\", \"status\": \"{s}\", \"linux_equiv\": \"{s}\", \"address\": \"0x{x}\"}}{s}\n",
                .{
                    s.symbol,
                    s.requested_by,
                    s.provider,
                    @tagName(s.status),
                    s.linux_equiv,
                    s.address,
                    if (i + 1 < dyld.resolved_symbols.items.len) "," else "",
                },
            ) catch continue;
            defer allocator.free(line);
            sym_buf.appendSlice(allocator, line) catch {};
        }
        sym_buf.appendSlice(allocator, "]\n") catch return;
        writeFile(evidence_dir, "symbols.json", sym_buf.items);
    }

    // 6. trace.jsonl
    {
        var tr_buf: std.ArrayList(u8) = .empty;
        defer tr_buf.deinit(allocator);
        for (tracer.events.items) |ev| {
            const line = std.fmt.allocPrint(allocator,
                "{{\"ts_ns\": {d}, \"rel_us\": {d}, \"event\": \"{s}\", \"detail\": \"{s}\"}}\n",
                .{ ev.ts_ns, ev.rel_us, @tagName(ev.kind), ev.detail },
            ) catch continue;
            defer allocator.free(line);
            tr_buf.appendSlice(allocator, line) catch {};
        }
        writeFile(evidence_dir, "trace.jsonl", tr_buf.items);
    }

    // 7. verdict.md
    {
        const verdict = std.fmt.allocPrint(allocator,
            "# WINS-MachO Run Verdict\n\n- Target: `{s}`\n- Exit code: `{?d}`\n- Events recorded: `{d}`\n- Resolved symbols: `{d}`\n- Dependencies: `{d}`\n",
            .{ target_path, exit_code, tracer.events.items.len, dyld.resolved_symbols.items.len, dyld.deps.items.len },
        ) catch return;
        defer allocator.free(verdict);
        writeFile(evidence_dir, "verdict.md", verdict);
    }
}
