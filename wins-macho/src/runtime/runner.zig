const std = @import("std");
const parser = @import("../macho/parser.zig");
const mapper = @import("../loader/mapper.zig");
const entry = @import("../loader/entry.zig");
const resolver = @import("../dyld/resolver.zig");
const trace = @import("trace.zig");
const signals = @import("signals.zig");
const evidence = @import("evidence.zig");
const shims = @import("../darwin/shims.zig");

pub const RunOptions = struct {
    target_path: []const u8,
    target_args: []const []const u8,
    run_id: []const u8,
    inspect_only: bool = false,
    write_evidence: bool = true,
    lib_dirs: []const []const u8 = &.{},
};

fn readWholeFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const c_path = try allocator.dupeZ(u8, path);
    defer allocator.free(c_path);
    const fd = std.c.open(c_path.ptr, .{ .ACCMODE = .RDONLY }, @as(std.c.mode_t, 0));
    if (fd < 0) return error.FileNotFound;
    defer _ = std.c.close(fd);

    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    var tmp: [16384]u8 = undefined;
    while (true) {
        const n = std.os.linux.read(fd, &tmp, tmp.len);
        const sn: isize = @bitCast(n);
        if (sn < 0) return error.ReadFailed;
        if (sn == 0) break;
        try buf.appendSlice(allocator, tmp[0..@intCast(sn)]);
    }
    return buf.toOwnedSlice(allocator);
}

pub fn runTarget(allocator: std.mem.Allocator, io: std.Io, opts: RunOptions) !c_int {
    var tracer = trace.Tracer.init(allocator);
    defer tracer.deinit();
    trace.active_tracer = &tracer;
    defer trace.active_tracer = null;

    const evidence_dir = try std.fmt.allocPrint(allocator, "evidence/{s}", .{opts.run_id});
    defer allocator.free(evidence_dir);
    if (opts.write_evidence) {
        evidence.ensureDir("evidence");
        evidence.ensureDir(evidence_dir);
        signals.active_evidence_dir = evidence_dir;
    } else {
        signals.active_evidence_dir = null;
    }
    signals.active_target_path = opts.target_path;
    shims.active_executable_path = opts.target_path;
    defer {
        signals.active_evidence_dir = null;
        signals.active_target_path = null;
        shims.active_executable_path = null;
    }

    tracer.record(.START, "target={s} run_id={s}", .{ opts.target_path, opts.run_id });

    const raw = try readWholeFile(allocator, opts.target_path);
    defer allocator.free(raw);

    const parsed = if (opts.inspect_only)
        try parser.parseInspect(allocator, raw)
    else
        try parser.parse(allocator, raw);
    const mapped = try mapper.mapImage(allocator, opts.target_path, parsed);
    tracer.record(.IMAGE_MAPPED, "base=0x{x} slide={d} segs={d}", .{ mapped.actual_base, mapped.slide, mapped.mappings.len });

    const entry_addr = mapped.entry_address orelse return error.MissingEntryPoint;
    const entryoff = mapped.parsed.main_entry.?.entryoff;
    tracer.record(.ENTRYPOINT_RESOLVED, "entryoff=0x{x} entry_address=0x{x}", .{ entryoff, entry_addr });

    var dyld = resolver.DyldContext.init(allocator, io, opts.target_path);
    dyld.lib_dirs = opts.lib_dirs;
    defer dyld.deinit();

    try dyld.loadGraph(mapped);
    tracer.record(.DYLIB_GRAPH_READY, "images={d} deps={d}", .{ dyld.images.items.len, dyld.deps.items.len });

    dyld.applyFixupsAndBind() catch |err| {
        if (opts.write_evidence) {
            evidence.writeRunEvidence(allocator, evidence_dir, opts.target_path, raw, &dyld, &tracer, null, false);
        }
        return err;
    };
    tracer.record(.FIXUPS_APPLIED, "images={d}", .{dyld.images.items.len});
    tracer.record(.IMPORTS_RESOLVED, "symbols={d}", .{dyld.resolved_symbols.items.len});

    if (opts.inspect_only) {
        if (opts.write_evidence) {
            evidence.writeRunEvidence(allocator, evidence_dir, opts.target_path, raw, &dyld, &tracer, 0, false);
        }
        return 0;
    }

    signals.installSignalHandlers();
    const seccomp_ok = signals.installDarwinSyscallTrap();

    // Build C-compatible argv/envp/apple arrays
    const total_argc = 1 + opts.target_args.len;
    var c_argv = try allocator.alloc([*c]const u8, total_argc + 1);
    defer allocator.free(c_argv);
    const c_prog = try allocator.dupeZ(u8, opts.target_path);
    defer allocator.free(c_prog);
    c_argv[0] = c_prog.ptr;
    var owned_c_args = try allocator.alloc([:0]u8, opts.target_args.len);
    defer {
        for (owned_c_args) |a| allocator.free(a);
        allocator.free(owned_c_args);
    }
    for (opts.target_args, 0..) |arg, i| {
        owned_c_args[i] = try allocator.dupeZ(u8, arg);
        c_argv[1 + i] = owned_c_args[i].ptr;
    }
    c_argv[total_argc] = null;

    var apple_arr = [_][*c]const u8{ c_prog.ptr, null };
    const env_struct = struct {
        extern "c" var environ: [*c]const [*c]const u8;
    };
    const c_envp: [*c]const [*c]const u8 = env_struct.environ;

    const ctx = entry.EntryContext{
        .image_base = dyld.images.items[0].actual_base,
        .slide = dyld.images.items[0].slide,
        .entryoff = entryoff,
        .entry_address = entry_addr,
        .argc = @intCast(total_argc),
        .argv = c_argv.ptr,
        .envp = c_envp,
        .apple = &apple_arr,
    };

    tracer.record(.TRANSFER_CONTROL, "rip=0x{x} seccomp_trap={}", .{ entry_addr, seccomp_ok });
    const rc = entry.transferControl(ctx);
    shims.runMachoAtexitHandlers();
    tracer.record(.EXIT, "return_code={d}", .{rc});

    if (opts.write_evidence) {
        evidence.writeRunEvidence(allocator, evidence_dir, opts.target_path, raw, &dyld, &tracer, rc, seccomp_ok);
    }
    return rc;
}
