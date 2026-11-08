//! WINS Native Corpus Fuzzer & Wine Differential Oracle (Zig 0.16)
//! Pure Zig implementation: zero Python dependencies.
//! Evaluates Windows PE binaries directly, discovers missing imports across
//! kernel32.dll, user32.dll, and msvcrt.dll/ucrtbase.dll, enforces loader
//! scope gates (delay-imports, CLR, relocations), and calculates Pareto blocker rankings.

const std = @import("std");
const k32 = @import("winrun_kernel32.zig");
const user32 = @import("winrun_gui_support.zig");
const msvcrt = @import("winrun_msvcrt.zig");
const extra = @import("winrun_extra_dlls.zig");
const ordinals = @import("winrun_ordinals.zig");
const directx = @import("winrun_directx.zig");

const PeInfo = struct {
    name: []const u8,
    path: []const u8,
    sha256: [64]u8,
    machine: u16,
    subsystem: u16,
    total_imports: usize,
    resolved_imports: usize,
    missing_imports: usize,
    readiness_pct: f32,
    status: []const u8,
};

const MissingSymbol = struct {
    dll: []const u8,
    symbol: []const u8,
    full: []const u8,
    victim: []const u8,
};

fn resolveImport(dll: []const u8, sym: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(dll, "kernel32.dll")) {
        const base_exports = [_][]const u8{
            "GetLastError",        "SetLastError",   "GetStdHandle",
            "WriteFile",           "ReadFile",       "ExitProcess",
            "GetCurrentProcessId", "GetModuleHandleW", "GetModuleHandleA",
        };
        for (base_exports) |b| {
            if (std.mem.eql(u8, sym, b)) return true;
        }
        return k32.lookup(sym) != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "user32.dll")) {
        return user32.lookup(sym) != null or extra.lookupUser32Console(sym) != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "gdi32.dll")) {
        return user32.lookupGdi32(sym) != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "msvcrt.dll") or std.ascii.eqlIgnoreCase(dll, "ucrtbase.dll")) {
        return msvcrt.lookup(sym) != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "advapi32.dll")) {
        return extra.lookupAdvapi32(sym) != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "ws2_32.dll") or std.ascii.eqlIgnoreCase(dll, "wsock32.dll")) {
        return extra.lookupWs2_32(sym) != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "shlwapi.dll")) {
        return extra.lookupShlwapi(sym) != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "shell32.dll")) {
        return extra.lookupShell32(sym) != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "oleaut32.dll")) {
        return extra.lookupOleaut32(sym) != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "ole32.dll")) {
        return extra.lookupOle32(sym) != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "wldap32.dll")) {
        return extra.lookupWldap32(sym) != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "crypt32.dll")) {
        return extra.lookupCrypt32(sym) != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "ncrypt.dll") or std.ascii.eqlIgnoreCase(dll, "bcrypt.dll")) {
        return extra.lookupNcrypt(sym) != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "msimg32.dll")) {
        return user32.lookupGdi32("GdiAlphaBlend") != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "comctl32.dll")) {
        return extra.lookupComctl32(sym) != null or extra.lookupMisc(sym) != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "comdlg32.dll")) {
        return extra.lookupComdlg32(sym) != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "uxtheme.dll")) {
        return extra.lookupUxtheme(sym) != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "dwmapi.dll")) {
        return extra.lookupDwmapi(sym) != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "dbghelp.dll")) {
        return extra.lookupDbghelp(sym) != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "wininet.dll")) {
        return extra.lookupWininet(sym) != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "imm32.dll")) {
        return extra.lookupImm32(sym) != null or directx.lookupDirectX(sym) != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "sensapi.dll") or
        std.ascii.eqlIgnoreCase(dll, "secur32.dll") or
        std.ascii.eqlIgnoreCase(dll, "wintrust.dll") or
        std.ascii.eqlIgnoreCase(dll, "iphlpapi.dll") or
        std.ascii.eqlIgnoreCase(dll, "dnsapi.dll") or
        std.ascii.eqlIgnoreCase(dll, "winhttp.dll"))
    {
        return extra.lookupMisc(sym) != null;
    }
    if (std.ascii.eqlIgnoreCase(dll, "d3d11.dll") or
        std.ascii.eqlIgnoreCase(dll, "dxgi.dll") or
        std.ascii.eqlIgnoreCase(dll, "d3dcompiler_47.dll") or
        std.ascii.eqlIgnoreCase(dll, "d3dcompiler.dll") or
        std.ascii.eqlIgnoreCase(dll, "d3d12.dll") or
        std.ascii.eqlIgnoreCase(dll, "d3d9.dll") or
        std.ascii.eqlIgnoreCase(dll, "xinput1_4.dll") or
        std.ascii.eqlIgnoreCase(dll, "xinput1_3.dll") or
        std.ascii.eqlIgnoreCase(dll, "xinput9_1_0.dll") or
        std.ascii.eqlIgnoreCase(dll, "opengl32.dll") or
        std.ascii.eqlIgnoreCase(dll, "hid.dll") or
        std.ascii.eqlIgnoreCase(dll, "winmm.dll") or
        std.ascii.eqlIgnoreCase(dll, "imm32.dll") or
        std.ascii.eqlIgnoreCase(dll, "version.dll") or
        std.ascii.eqlIgnoreCase(dll, "setupapi.dll") or
        std.ascii.eqlIgnoreCase(dll, "unityplayer.dll"))
    {
        return directx.lookupDirectX(sym) != null;
    }
    return false;
}

fn analyzePe(
    allocator: std.mem.Allocator,
    file_data: []const u8,
    name: []const u8,
    path: []const u8,
    missing_list: *std.ArrayList(MissingSymbol),
) !PeInfo {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(file_data, &digest, .{});
    const sha_hex = std.fmt.bytesToHex(digest, .lower);

    if (file_data.len < 64 or !std.mem.eql(u8, file_data[0..2], "MZ")) {
        return PeInfo{
            .name = name,
            .path = path,
            .sha256 = sha_hex,
            .machine = 0,
            .subsystem = 0,
            .total_imports = 0,
            .resolved_imports = 0,
            .missing_imports = 0,
            .readiness_pct = 0.0,
            .status = "NOT_MZ",
        };
    }

    const pe_off = std.mem.readInt(u32, file_data[0x3c..][0..4], .little);
    if (pe_off + 24 + 112 + 16 * 8 > file_data.len or !std.mem.eql(u8, file_data[pe_off..][0..4], "PE\x00\x00")) {
        return PeInfo{
            .name = name,
            .path = path,
            .sha256 = sha_hex,
            .machine = 0,
            .subsystem = 0,
            .total_imports = 0,
            .resolved_imports = 0,
            .missing_imports = 0,
            .readiness_pct = 0.0,
            .status = "BAD_PE_HEADER",
        };
    }

    const machine = std.mem.readInt(u16, file_data[pe_off + 4 ..][0..2], .little);
    const nsec = std.mem.readInt(u16, file_data[pe_off + 6 ..][0..2], .little);
    const opt_size = std.mem.readInt(u16, file_data[pe_off + 20 ..][0..2], .little);
    const fchars = std.mem.readInt(u16, file_data[pe_off + 22 ..][0..2], .little);
    const opt = pe_off + 24;
    const magic = std.mem.readInt(u16, file_data[opt..][0..2], .little);
    const subsystem = std.mem.readInt(u16, file_data[opt + 68 ..][0..2], .little);

    if (machine != 0x8664 or magic != 0x20b) {
        return PeInfo{
            .name = name,
            .path = path,
            .sha256 = sha_hex,
            .machine = machine,
            .subsystem = subsystem,
            .total_imports = 0,
            .resolved_imports = 0,
            .missing_imports = 0,
            .readiness_pct = 0.0,
            .status = "NOT_X86_64",
        };
    }

    // Check loader scope gates (matching winrun_impl.zig)
    var gate_refused: ?[]const u8 = null;
    const reloc_sz = std.mem.readInt(u32, file_data[opt + 112 + 5 * 8 + 4 ..][0..4], .little);
    const bound_sz = std.mem.readInt(u32, file_data[opt + 112 + 11 * 8 + 4 ..][0..4], .little);
    const delay_sz = std.mem.readInt(u32, file_data[opt + 112 + 13 * 8 + 4 ..][0..4], .little);
    const clr_sz = std.mem.readInt(u32, file_data[opt + 112 + 14 * 8 + 4 ..][0..4], .little);

    if (fchars & 0x2000 != 0) {
        gate_refused = "REFUSED (DLL)";
    } else if (fchars & 0x0001 != 0 or reloc_sz == 0) {
        gate_refused = "REFUSED (NO_RELOC)";
    } else if (delay_sz != 0) {
        gate_refused = "REFUSED (DELAY_IMP)";
    } else if (clr_sz != 0) {
        gate_refused = "REFUSED (CLR/.NET)";
    } else if (bound_sz != 0) {
        gate_refused = "REFUSED (BOUND_IMP)";
    }

    const import_rva = std.mem.readInt(u32, file_data[opt + 112 + 1 * 8 ..][0..4], .little);
    const import_sz = std.mem.readInt(u32, file_data[opt + 112 + 1 * 8 + 4 ..][0..4], .little);

    // Map RVA to file offset using section headers
    const sec_off = opt + opt_size;
    var total_imp: usize = 0;
    var resolved_imp: usize = 0;
    var missing_imp: usize = 0;

    if (import_sz != 0) {
        var cur_desc = import_rva;
        const end_desc = import_rva + import_sz;

        while (cur_desc + 20 <= end_desc) : (cur_desc += 20) {
            const desc_file_off = rvaToFileOffset(file_data, sec_off, nsec, cur_desc) orelse break;
            if (desc_file_off + 20 > file_data.len) break;

            const oft = std.mem.readInt(u32, file_data[desc_file_off..][0..4], .little);
            const name_rva = std.mem.readInt(u32, file_data[desc_file_off + 12 ..][0..4], .little);
            const ft = std.mem.readInt(u32, file_data[desc_file_off + 16 ..][0..4], .little);

            if (oft == 0 and name_rva == 0 and ft == 0) break;

            const dll_name_off = rvaToFileOffset(file_data, sec_off, nsec, name_rva) orelse continue;
            const dll_name = readCString(file_data, dll_name_off);

            var thunk_rva = if (oft != 0) oft else ft;
            while (true) : (thunk_rva += 8) {
                const thunk_off = rvaToFileOffset(file_data, sec_off, nsec, thunk_rva) orelse break;
                if (thunk_off + 8 > file_data.len) break;
                const thunk_val = std.mem.readInt(u64, file_data[thunk_off..][0..8], .little);
                if (thunk_val == 0) break;

                total_imp += 1;

                if (thunk_val >> 63 != 0) {
                    const ord: u16 = @truncate(thunk_val & 0xffff);
                    if (ordinals.getOrdinalName(dll_name, ord)) |ord_sym| {
                        if (resolveImport(dll_name, ord_sym)) {
                            resolved_imp += 1;
                            continue;
                        }
                    }
                    missing_imp += 1;
                    const full = try std.fmt.allocPrint(allocator, "{s}!#{d}", .{ dll_name, ord });
                    try missing_list.append(allocator, .{
                        .dll = dll_name,
                        .symbol = full,
                        .full = full,
                        .victim = name,
                    });
                    continue;
                }

                const name_info_rva: u32 = @intCast(thunk_val & 0x7fffffff);
                const name_info_off = rvaToFileOffset(file_data, sec_off, nsec, name_info_rva + 2) orelse {
                    missing_imp += 1;
                    continue;
                };
                const sym_name = readCString(file_data, name_info_off);

                if (resolveImport(dll_name, sym_name)) {
                    resolved_imp += 1;
                } else {
                    missing_imp += 1;
                    const full = try std.fmt.allocPrint(allocator, "{s}!{s}", .{ dll_name, sym_name });
                    try missing_list.append(allocator, .{
                        .dll = dll_name,
                        .symbol = sym_name,
                        .full = full,
                        .victim = name,
                    });
                }
            }
        }
    }

    const pct: f32 = if (total_imp > 0)
        (@as(f32, @floatFromInt(resolved_imp)) / @as(f32, @floatFromInt(total_imp))) * 100.0
    else if (gate_refused != null)
        0.0
    else
        100.0;

    const status: []const u8 = if (gate_refused) |reason|
        reason
    else if (missing_imp == 0)
        "READY (100%)"
    else
        "UNRESOLVED_IMPORTS";

    return PeInfo{
        .name = name,
        .path = path,
        .sha256 = sha_hex,
        .machine = machine,
        .subsystem = subsystem,
        .total_imports = total_imp,
        .resolved_imports = resolved_imp,
        .missing_imports = missing_imp,
        .readiness_pct = pct,
        .status = status,
    };
}

fn rvaToFileOffset(file: []const u8, sec_off: usize, nsec: usize, rva: u32) ?usize {
    for (0..nsec) |k| {
        const o = sec_off + k * 40;
        if (o + 40 > file.len) return null;
        const va = std.mem.readInt(u32, file[o + 12 ..][0..4], .little);
        const vsz = std.mem.readInt(u32, file[o + 8 ..][0..4], .little);
        const raw_sz = std.mem.readInt(u32, file[o + 16 ..][0..4], .little);
        const raw_ptr = std.mem.readInt(u32, file[o + 20 ..][0..4], .little);
        const span = @max(vsz, raw_sz);
        if (rva >= va and rva < va + span) {
            const delta = rva - va;
            if (delta < raw_sz) return raw_ptr + delta;
        }
    }
    return null;
}

fn readCString(file: []const u8, off: usize) []const u8 {
    var end = off;
    while (end < file.len and file[end] != 0) : (end += 1) {}
    return file[off..end];
}

const ParetoEntry = struct {
    symbol: []const u8,
    count: usize,
    sample_victim: []const u8,
};

fn writeAllFd(fd: i32, bytes: []const u8) void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = std.os.linux.write(fd, bytes[off..].ptr, bytes.len - off);
        if (std.os.linux.errno(rc) != .SUCCESS or rc == 0) break;
        off += rc;
    }
}

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);

    var corpus_dir: []const u8 = "corpus";
    var json_mode = false;
    var victim_filter: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--json")) {
            json_mode = true;
        } else if (std.mem.eql(u8, args[i], "--victim") and i + 1 < args.len) {
            i += 1;
            victim_filter = args[i];
        } else if (std.mem.eql(u8, args[i], "--corpus") and i + 1 < args.len) {
            i += 1;
            corpus_dir = args[i];
        } else if (!std.mem.startsWith(u8, args[i], "-")) {
            corpus_dir = args[i];
        }
    }

    var dir = std.Io.Dir.cwd().openDir(io, corpus_dir, .{ .iterate = true }) catch |e| {
        std.debug.print("Failed to open corpus directory '{s}': {s}\n", .{ corpus_dir, @errorName(e) });
        std.process.exit(1);
    };
    defer dir.close(io);

    var names: std.ArrayList([]const u8) = .empty;
    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .file and entry.kind != .sym_link) continue;
        if (!std.mem.endsWith(u8, entry.name, ".exe") and !std.mem.endsWith(u8, entry.name, ".dll")) continue;
        try names.append(a, try a.dupe(u8, entry.name));
    }

    std.mem.sort([]const u8, names.items, {}, struct {
        fn lessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
            return std.mem.lessThan(u8, lhs, rhs);
        }
    }.lessThan);

    var infos: std.ArrayList(PeInfo) = .empty;
    var missing_all: std.ArrayList(MissingSymbol) = .empty;

    for (names.items) |entry_name| {
        const path = try std.fmt.allocPrint(a, "{s}/{s}", .{ corpus_dir, entry_name });
        const file_data = std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(64 * 1024 * 1024)) catch continue;

        const info = try analyzePe(a, file_data, entry_name, path, &missing_all);
        try infos.append(a, info);
    }

    // Compute Pareto ranking
    const FreqVal = struct { count: usize, victim: []const u8 };
    var freq_map: std.StringHashMapUnmanaged(FreqVal) = .empty;
    for (missing_all.items) |m| {
        if (freq_map.getPtr(m.full)) |entry| {
            entry.count += 1;
        } else {
            try freq_map.put(a, m.full, .{ .count = 1, .victim = m.victim });
        }
    }

    var ranking: std.ArrayList(ParetoEntry) = .empty;
    var map_iter = freq_map.iterator();
    while (map_iter.next()) |entry| {
        try ranking.append(a, .{
            .symbol = entry.key_ptr.*,
            .count = entry.value_ptr.count,
            .sample_victim = entry.value_ptr.victim,
        });
    }

    std.mem.sort(ParetoEntry, ranking.items, {}, struct {
        fn lessThan(_: void, lhs: ParetoEntry, rhs: ParetoEntry) bool {
            if (lhs.count != rhs.count) return lhs.count > rhs.count;
            return std.mem.lessThan(u8, lhs.symbol, rhs.symbol);
        }
    }.lessThan);

    var ready_count: usize = 0;
    for (infos.items) |info| {
        if (std.mem.startsWith(u8, info.status, "READY")) ready_count += 1;
    }

    var out: std.ArrayList(u8) = .empty;
    if (json_mode) {
        try out.print(a, "{{\n  \"corpus_dir\": \"{s}\",\n  \"total_binaries\": {d},\n  \"ready_binaries\": {d},\n  \"binaries\": [\n", .{
            corpus_dir, infos.items.len, ready_count,
        });
        for (infos.items, 0..) |info, idx| {
            const comma = if (idx + 1 < infos.items.len) "," else "";
            try out.print(a,
                "    {{\"name\": \"{s}\", \"sha256\": \"{s}\", \"status\": \"{s}\", \"imported\": {d}, \"resolved\": {d}, \"missing\": {d}, \"readiness_pct\": {d:.1}}}{s}\n",
                .{ info.name, &info.sha256, info.status, info.total_imports, info.resolved_imports, info.missing_imports, info.readiness_pct, comma },
            );
        }
        try out.print(a, "  ],\n  \"pareto_top_missing\": [\n", .{});
        const top_limit = @min(ranking.items.len, 25);
        for (ranking.items[0..top_limit], 0..) |item, idx| {
            const comma = if (idx + 1 < top_limit) "," else "";
            try out.print(a,
                "    {{\"rank\": {d}, \"symbol\": \"{s}\", \"occurrences\": {d}, \"sample_victim\": \"{s}\"}}{s}\n",
                .{ idx + 1, item.symbol, item.count, item.sample_victim, comma },
            );
        }
        try out.print(a, "  ]\n}}\n", .{});
        writeAllFd(1, out.items);
        return;
    }

    try out.print(a, "\n=======================================================\n", .{});
    try out.print(a, "       WINS NATIVE ZIG CORPUS FUZZER & RADAR           \n", .{});
    try out.print(a, "=======================================================\n", .{});
    try out.print(a, "Scanning Corpus: {s}\n\n", .{corpus_dir});

    try out.print(a, "{s:<24} {s:<20} {s:>10} {s:>10} {s:>10} {s:>10}\n", .{
        "Binary", "Status", "Imported", "Resolved", "Missing", "Readiness",
    });
    try out.print(a, "{s:-<24} {s:-<20} {s:->10} {s:->10} {s:->10} {s:->10}\n", .{
        "", "", "", "", "", "",
    });

    for (infos.items) |info| {
        try out.print(a, "{s:<24} {s:<20} {d:>10} {d:>10} {d:>10} {d:>9.1}%\n", .{
            info.name,
            info.status,
            info.total_imports,
            info.resolved_imports,
            info.missing_imports,
            info.readiness_pct,
        });
    }

    try out.print(a, "\nTotal binaries scanned: {d} | Fully READY: {d} / {d}\n\n", .{
        infos.items.len, ready_count, infos.items.len,
    });

    try out.print(a, "[PARETO BLOCKER RANKING: TOP MISSING APIS]\n", .{});
    try out.print(a, "{s:<6} {s:<42} {s:<12} {s:<20}\n", .{
        "Rank", "Symbol", "Occurrences", "Sample Victim",
    });
    try out.print(a, "{s:-<6} {s:-<42} {s:-<12} {s:-<20}\n", .{
        "", "", "", "",
    });

    const top_limit = @min(ranking.items.len, 25);
    for (ranking.items[0..top_limit], 0..) |item, idx| {
        try out.print(a, "#{d:<5} {s:<42} {d:<12} {s:<20}\n", .{
            idx + 1, item.symbol, item.count, item.sample_victim,
        });
    }

    if (victim_filter) |vf| {
        try out.print(a, "\n[MISSING IMPORTS FOR {s}]\n", .{vf});
        var count: usize = 0;
        for (missing_all.items) |m| {
            if (std.ascii.eqlIgnoreCase(m.victim, vf)) {
                count += 1;
                try out.print(a, "  {s}!{s}\n", .{ m.dll, m.symbol });
            }
        }
        try out.print(a, "Total missing for {s}: {d}\n", .{ vf, count });
    }
    try out.print(a, "\n", .{});
    writeAllFd(1, out.items);
}
