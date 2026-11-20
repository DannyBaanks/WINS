const std = @import("std");
const parser = @import("../macho/parser.zig");
const types = @import("../macho/types.zig");
const exports = @import("../macho/exports.zig");
const fixups = @import("../macho/fixups.zig");
const image = @import("../loader/image.zig");
const mapper = @import("../loader/mapper.zig");
const shims = @import("../darwin/shims.zig");
const objc = @import("../darwin/objc.zig");
const rpath = @import("rpath.zig");

pub const DepKind = enum {
    LOCAL_MACHO,
    DARWIN_SHIM,
    LINUX_NATIVE_LIB,
    WEAK_MISSING,
};

pub const LoadedDep = struct {
    requested_name: []const u8,
    resolved_path: []const u8,
    kind: DepKind,
    image_index: ?usize,
};

pub const ResolvedSymbolRecord = struct {
    symbol: []const u8,
    requested_by: []const u8,
    provider: []const u8,
    status: shims.ShimStatus,
    linux_equiv: []const u8,
    address: usize,
    site_addr: usize,
};

pub const UnresolvedReport = struct {
    image: []const u8,
    symbol: []const u8,
    requested_by: []const u8,
    resolution_path: []const u8,
};

pub const DyldContext = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    executable_path: []const u8,
    lib_dirs: []const []const u8 = &.{},
    images: std.ArrayList(image.MappedImage),
    owned_raw_buffers: std.ArrayList([]u8),
    owned_paths: std.ArrayList([]const u8),
    deps: std.ArrayList(LoadedDep),
    // Per image index -> slice of DepRef (matching parsed.dylibs ordinals 1..N)
    ordinal_maps: std.ArrayList([]DepRef),
    resolved_symbols: std.ArrayList(ResolvedSymbolRecord),
    unresolved: ?UnresolvedReport = null,

    pub const DepRef = struct {
        kind: DepKind,
        image_index: ?usize,
        name: []const u8,
    };

    pub fn init(allocator: std.mem.Allocator, io: std.Io, executable_path: []const u8) DyldContext {
        return .{
            .allocator = allocator,
            .io = io,
            .executable_path = executable_path,
            .images = .empty,
            .owned_raw_buffers = .empty,
            .owned_paths = .empty,
            .deps = .empty,
            .ordinal_maps = .empty,
            .resolved_symbols = .empty,
        };
    }

    pub fn deinit(self: *DyldContext) void {
        for (self.images.items) |*img| img.deinit();
        self.images.deinit(self.allocator);
        for (self.owned_raw_buffers.items) |buf| self.allocator.free(buf);
        self.owned_raw_buffers.deinit(self.allocator);
        for (self.owned_paths.items) |p| self.allocator.free(p);
        self.owned_paths.deinit(self.allocator);
        self.deps.deinit(self.allocator);
        for (self.ordinal_maps.items) |m| self.allocator.free(m);
        self.ordinal_maps.deinit(self.allocator);
        self.resolved_symbols.deinit(self.allocator);
    }

    fn readFileAlloc(self: *DyldContext, path: []const u8) ![]u8 {
        const c_path = try self.allocator.dupeZ(u8, path);
        defer self.allocator.free(c_path);
        const fd = std.c.open(c_path.ptr, .{ .ACCMODE = .RDONLY }, @as(std.c.mode_t, 0));
        if (fd < 0) return error.FileNotFound;
        defer _ = std.c.close(fd);

        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(self.allocator);
        var tmp: [8192]u8 = undefined;
        while (true) {
            const n = std.os.linux.read(fd, &tmp, tmp.len);
            const signed_n: isize = @bitCast(n);
            if (signed_n < 0) return error.ReadFailed;
            if (signed_n == 0) break;
            try buf.appendSlice(self.allocator, tmp[0..@intCast(signed_n)]);
        }
        return buf.toOwnedSlice(self.allocator);
    }

    pub fn loadGraph(self: *DyldContext, main_img: image.MappedImage) !void {
        try self.images.append(self.allocator, main_img);
        try self.ordinal_maps.append(self.allocator, &.{});

        var idx: usize = 0;
        while (idx < self.images.items.len) : (idx += 1) {
            const dylibs = self.images.items[idx].parsed.dylibs;
            const img_path = self.images.items[idx].path;
            const img_rpaths = self.images.items[idx].parsed.rpaths;

            var ord_map = try self.allocator.alloc(DepRef, dylibs.len);
            errdefer self.allocator.free(ord_map);

            for (dylibs, 0..) |d, di| {
                if (shims.nativeLinuxLibraryForDylib(d.name)) |so_name| {
                    ord_map[di] = .{ .kind = .LINUX_NATIVE_LIB, .image_index = null, .name = d.name };
                    try self.deps.append(self.allocator, .{
                        .requested_name = d.name,
                        .resolved_path = std.mem.span(so_name),
                        .kind = .LINUX_NATIVE_LIB,
                        .image_index = null,
                    });
                    continue;
                }
                if (shims.isDarwinSystemDylib(d.name)) {
                    ord_map[di] = .{ .kind = .DARWIN_SHIM, .image_index = null, .name = d.name };
                    try self.deps.append(self.allocator, .{
                        .requested_name = d.name,
                        .resolved_path = "darwin-shim://libSystem.B.dylib",
                        .kind = .DARWIN_SHIM,
                        .image_index = null,
                    });
                    continue;
                }

                // Combine image rpaths and executable rpaths
                var all_rpaths: std.ArrayList([]const u8) = .empty;
                defer all_rpaths.deinit(self.allocator);
                try all_rpaths.appendSlice(self.allocator, img_rpaths);
                if (idx != 0) {
                    try all_rpaths.appendSlice(self.allocator, self.images.items[0].parsed.rpaths);
                }

                var resolved_opt = try rpath.expandLoadPath(
                    self.allocator,
                    d.name,
                    self.executable_path,
                    img_path,
                    all_rpaths.items,
                );
                if (resolved_opt == null and self.lib_dirs.len > 0) {
                    const base = std.fs.path.basename(d.name);
                    for (self.lib_dirs) |ldir| {
                        const cand = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ ldir, base });
                        const c_cand = try self.allocator.dupeZ(u8, cand);
                        defer self.allocator.free(c_cand);
                        if (std.c.access(c_cand.ptr, 0) == 0) {
                            resolved_opt = cand;
                            break;
                        }
                        self.allocator.free(cand);
                    }
                }

                if (resolved_opt) |resolved_path| {
                    try self.owned_paths.append(self.allocator, resolved_path);
                    // Check if already loaded
                    var existing_idx: ?usize = null;
                    for (self.images.items, 0..) |loaded, li| {
                        if (std.mem.eql(u8, loaded.path, resolved_path)) {
                            existing_idx = li;
                            break;
                        }
                    }
                    if (existing_idx) |ei| {
                        ord_map[di] = .{ .kind = .LOCAL_MACHO, .image_index = ei, .name = resolved_path };
                    } else {
                        const raw = try self.readFileAlloc(resolved_path);
                        try self.owned_raw_buffers.append(self.allocator, raw);
                        const parsed_dep = try parser.parse(self.allocator, raw);
                        const mapped_dep = try mapper.mapImage(self.allocator, resolved_path, parsed_dep);
                        const new_idx = self.images.items.len;
                        try self.images.append(self.allocator, mapped_dep);
                        try self.ordinal_maps.append(self.allocator, &.{});
                        ord_map[di] = .{ .kind = .LOCAL_MACHO, .image_index = new_idx, .name = resolved_path };
                        try self.deps.append(self.allocator, .{
                            .requested_name = d.name,
                            .resolved_path = resolved_path,
                            .kind = .LOCAL_MACHO,
                            .image_index = new_idx,
                        });
                    }
                } else if (d.weak) {
                    ord_map[di] = .{ .kind = .WEAK_MISSING, .image_index = null, .name = d.name };
                    try self.deps.append(self.allocator, .{
                        .requested_name = d.name,
                        .resolved_path = "(weak missing)",
                        .kind = .WEAK_MISSING,
                        .image_index = null,
                    });
                } else {
                    std.debug.print("MISSING_DYLIB: {s} requested by {s}\n", .{ d.name, img_path });
                    return error.MissingDylib;
                }
            }

            self.ordinal_maps.items[idx] = ord_map;
        }
    }

    fn lookupInImageExports(self: *const DyldContext, img_idx: usize, symbol: []const u8, depth: usize) ?usize {
        if (depth >= 16) return null;
        const img = &self.images.items[img_idx];
        const trie_slice: ?[]const u8 = if (img.parsed.exports_trie) |et|
            img.parsed.sliceRange(et.dataoff, et.datasize) catch null
        else if (img.parsed.dyld_info) |di|
            (if (di.export_size > 0) img.parsed.sliceRange(di.export_off, di.export_size) catch null else null)
        else
            null;

        if (trie_slice) |trie| {
            if (exports.lookupExport(trie, symbol)) |exp| {
                if ((exp.flags & exports.EXPORT_SYMBOL_FLAGS_REEXPORT) != 0) {
                    const ord = exp.other;
                    const ord_map = self.ordinal_maps.items[img_idx];
                    if (ord > 0 and ord - 1 < ord_map.len) {
                        const dep = ord_map[@intCast(ord - 1)];
                        const target_sym = exp.import_name orelse symbol;
                        switch (dep.kind) {
                            .LOCAL_MACHO => return self.lookupInImageExports(dep.image_index.?, target_sym, depth + 1),
                            .DARWIN_SHIM => if (shims.lookup(target_sym)) |sh| return sh.address,
                            .LINUX_NATIVE_LIB => return shims.lookupNativeLibrarySymbol(dep.name, target_sym),
                            .WEAK_MISSING => return null,
                        }
                    }
                    return null;
                }
                if ((exp.flags & exports.EXPORT_SYMBOL_FLAGS_KIND_MASK) == exports.EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE) {
                    return @intCast(exp.address_offset);
                }
                return img.actual_base + @as(usize, @intCast(exp.address_offset));
            }
        }
        return null;
    }

    fn initializeMachoTlv(img: *const image.MappedImage) void {
        var init_data: ?[*]const u8 = null;
        var init_size: usize = 0;
        var bss_size: usize = 0;
        var vars_addr: usize = 0;
        var vars_size: usize = 0;

        for (img.parsed.segments) |seg| {
            for (seg.sections) |sec| {
                const sname = sec.name();
                if (std.mem.eql(u8, sname, "__thread_data")) {
                    init_data = @ptrFromInt(img.vmToActual(sec.addr));
                    init_size = @intCast(sec.size);
                } else if (std.mem.eql(u8, sname, "__thread_bss")) {
                    bss_size = @intCast(sec.size);
                } else if (std.mem.eql(u8, sname, "__thread_vars")) {
                    vars_addr = img.vmToActual(sec.addr);
                    vars_size = @intCast(sec.size);
                }
            }
        }
        if (vars_addr == 0 or vars_size < @sizeOf(shims.TlvDescriptor)) return;
        const tpl_key = shims.registerTlvImage(init_data, init_size, init_size + bss_size);
        const count = vars_size / @sizeOf(shims.TlvDescriptor);
        const descs: [*]shims.TlvDescriptor = @ptrFromInt(vars_addr);
        for (0..count) |i| {
            descs[i].thunk = &shims.shim_tlv_get_addr;
            descs[i].key = tpl_key;
        }
    }

    fn registerMachoObjcClasses(img: *const image.MappedImage) void {
        for (img.parsed.segments) |seg| {
            for (seg.sections) |sec| {
                if (std.mem.eql(u8, sec.name(), "__objc_classlist") and sec.size >= @sizeOf(usize)) {
                    const base = img.vmToActual(sec.addr);
                    const count: usize = @intCast(sec.size / @sizeOf(usize));
                    const list: [*]const usize = @ptrFromInt(base);
                    for (0..count) |i| {
                        const cls_addr = list[i];
                        if (cls_addr != 0 and (cls_addr & 0x7) == 0) {
                            objc.registerClass(@ptrFromInt(cls_addr));
                        }
                    }
                }
            }
        }
    }

    pub fn runInitializers(
        self: *const DyldContext,
        argc: c_int,
        argv: [*c]const [*c]const u8,
        envp: [*c]const [*c]const u8,
        apple: [*c]const [*c]const u8,
    ) void {
        const InitFn = *const fn (c_int, [*c]const [*c]const u8, [*c]const [*c]const u8, [*c]const [*c]const u8, ?*const anyopaque) callconv(.c) void;
        // Run dylib initializers first, then main executable (reverse load order)
        var idx: usize = self.images.items.len;
        while (idx > 0) {
            idx -= 1;
            const img = &self.images.items[idx];
            for (img.parsed.segments) |seg| {
                for (seg.sections) |sec| {
                    const sname = sec.name();
                    if (std.mem.eql(u8, sname, "__mod_init_func") and sec.size >= @sizeOf(usize)) {
                        const base = img.vmToActual(sec.addr);
                        const count: usize = @intCast(sec.size / @sizeOf(usize));
                        const ptrs: [*]const usize = @ptrFromInt(base);
                        for (0..count) |i| {
                            if (ptrs[i] != 0) {
                                const f: InitFn = @ptrFromInt(ptrs[i]);
                                f(argc, argv, envp, apple, null);
                            }
                        }
                    } else if (std.mem.eql(u8, sname, "__init_offsets") and sec.size >= @sizeOf(u32)) {
                        const base = img.vmToActual(sec.addr);
                        const count: usize = @intCast(sec.size / @sizeOf(u32));
                        const offs: [*]const u32 = @ptrFromInt(base);
                        for (0..count) |i| {
                            if (offs[i] != 0) {
                                const f: InitFn = @ptrFromInt(img.actual_base + @as(usize, offs[i]));
                                f(argc, argv, envp, apple, null);
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn applyFixupsAndBind(self: *DyldContext) !void {
        for (self.images.items, 0..) |*img, img_idx| {
            // 1. LC_DYLD_INFO_ONLY rebases & binds
            if (img.parsed.dyld_info) |di| {
                if (di.rebase_size > 0) {
                    const rb_blob = try img.parsed.sliceRange(di.rebase_off, di.rebase_size);
                    const sites = try fixups.parseRebaseOpcodes(self.allocator, rb_blob);
                    defer self.allocator.free(sites);
                    for (sites) |site| {
                        const addr = img.segOffsetToActual(site.seg_index, site.seg_offset) orelse return error.OutOfBounds;
                        if (site.rebase_type == types.REBASE_TYPE_POINTER) {
                            const ptr: *u64 = @ptrFromInt(addr);
                            const signed_val: i64 = @bitCast(ptr.*);
                            ptr.* = @bitCast(signed_val + img.slide);
                        }
                    }
                }

                const bind_streams = [_]struct { off: u32, size: u32, weak: bool }{
                    .{ .off = di.bind_off, .size = di.bind_size, .weak = false },
                    .{ .off = di.lazy_bind_off, .size = di.lazy_bind_size, .weak = false },
                    .{ .off = di.weak_bind_off, .size = di.weak_bind_size, .weak = true },
                };

                for (bind_streams) |bs| {
                    if (bs.size == 0) continue;
                    const blob = try img.parsed.sliceRange(bs.off, bs.size);
                    const sites = try fixups.parseBindOpcodes(self.allocator, blob, bs.weak);
                    defer self.allocator.free(sites);
                    for (sites) |site| {
                        try self.bindOneSite(img_idx, img, site);
                    }
                }
            }

            // 2. LC_DYLD_CHAINED_FIXUPS (modern macOS 12+/13+ binaries)
            if (img.parsed.chained_fixups) |cf| {
                try self.applyChainedFixups(img_idx, img, cf);
            }
        }

        // Initialize Mach-O TLS (__thread_vars) while __DATA is writable, then
        // restore final segment protections (never leave segments globally RWX)
        // and register any Objective-C classes defined inside the loaded Mach-O images.
        for (self.images.items) |*img| {
            initializeMachoTlv(img);
            try mapper.finalizeProtections(img);
            registerMachoObjcClasses(img);
        }
    }

    fn applyChainedFixups(
        self: *DyldContext,
        img_idx: usize,
        img: *const image.MappedImage,
        cf: types.LinkeditDataCommand,
    ) !void {
        const blob = try img.parsed.sliceRange(cf.dataoff, cf.datasize);
        const imports = try fixups.parseChainedImports(self.allocator, blob);
        defer self.allocator.free(imports);
        const seg_infos = try fixups.parseChainedSegments(self.allocator, blob);
        defer {
            for (seg_infos) |si| self.allocator.free(si.page_starts);
            self.allocator.free(seg_infos);
        }

        for (seg_infos) |si| {
            if (si.pointer_format != types.DYLD_CHAINED_PTR_64 and si.pointer_format != types.DYLD_CHAINED_PTR_64_OFFSET) {
                return error.UnsupportedFixupFormat;
            }
            for (si.page_starts, 0..) |page_start, page_idx| {
                if (page_start == fixups.DYLD_CHAINED_PTR_START_NONE) continue;
                var cursor_addr: usize = img.actual_base + @as(usize, @intCast(si.segment_offset)) +
                    page_idx * @as(usize, si.page_size) + @as(usize, page_start);

                while (true) {
                    const slot: *u64 = @ptrFromInt(cursor_addr);
                    const raw = slot.*;
                    const is_bind = ((raw >> 63) & 1) != 0;
                    const next_stride: usize = @intCast((raw >> 51) & 0xFFF);

                    if (is_bind) {
                        const ord: usize = @intCast(raw & 0xFFFFFF);
                        const inline_addend: i64 = @intCast((raw >> 24) & 0xFF);
                        if (ord >= imports.len) return error.OutOfBounds;
                        const imp = imports[ord];
                        const res = try self.resolveSymbol(
                            img_idx,
                            img,
                            imp.dylib_ordinal,
                            imp.symbol,
                            imp.weak_import,
                        );
                        const final_val: usize = if (res.addr == 0) 0 else @intCast(@as(i64, @intCast(res.addr)) + imp.addend + inline_addend);
                        slot.* = @intCast(final_val);
                        try self.resolved_symbols.append(self.allocator, .{
                            .symbol = imp.symbol,
                            .requested_by = img.path,
                            .provider = res.provider,
                            .status = res.status,
                            .linux_equiv = res.linux_equiv,
                            .address = final_val,
                            .site_addr = cursor_addr,
                        });
                    } else {
                        const target: u64 = raw & 0xFFFFFFFFF;
                        const high8: u64 = ((raw >> 36) & 0xFF) << 56;
                        if (si.pointer_format == types.DYLD_CHAINED_PTR_64_OFFSET) {
                            slot.* = (@as(u64, img.actual_base) + target) | high8;
                        } else {
                            slot.* = @as(u64, @bitCast(@as(i64, @bitCast(target)) + img.slide)) | high8;
                        }
                    }

                    if (next_stride == 0) break;
                    cursor_addr += next_stride * 4;
                }
            }
        }
    }

    const Resolution = struct {
        addr: usize,
        provider: []const u8,
        status: shims.ShimStatus,
        linux_equiv: []const u8,
    };

    fn resolveSymbol(
        self: *DyldContext,
        img_idx: usize,
        img: *const image.MappedImage,
        dylib_ordinal: i32,
        symbol: []const u8,
        is_weak: bool,
    ) !Resolution {
        const ord_map = self.ordinal_maps.items[img_idx];
        var resolved_addr: ?usize = null;
        var provider_name: []const u8 = "unknown";
        var status: shims.ShimStatus = .UNKNOWN;
        var linux_equiv: []const u8 = "-";

        if (dylib_ordinal == types.BIND_SPECIAL_DYLIB_SELF) {
            resolved_addr = self.lookupInImageExports(img_idx, symbol, 0);
            provider_name = img.path;
            status = .NATIVE_MAPPING;
            linux_equiv = "macho:self";
        } else if (dylib_ordinal == types.BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE) {
            resolved_addr = self.lookupInImageExports(0, symbol, 0);
            provider_name = self.images.items[0].path;
            status = .NATIVE_MAPPING;
            linux_equiv = "macho:main";
        } else if (dylib_ordinal == types.BIND_SPECIAL_DYLIB_FLAT_LOOKUP or dylib_ordinal == types.BIND_SPECIAL_DYLIB_WEAK_LOOKUP) {
            provider_name = "flat_namespace";
            if (shims.lookup(symbol)) |sh| {
                resolved_addr = sh.address;
                status = sh.status;
                linux_equiv = sh.linux_equiv;
            } else {
                for (self.images.items, 0..) |*loaded, li| {
                    if (self.lookupInImageExports(li, symbol, 0)) |addr| {
                        resolved_addr = addr;
                        provider_name = loaded.path;
                        status = .NATIVE_MAPPING;
                        linux_equiv = "macho:flat_lookup";
                        break;
                    }
                }
            }
        } else if (dylib_ordinal > 0 and @as(usize, @intCast(dylib_ordinal - 1)) < ord_map.len) {
            const dep = ord_map[@intCast(dylib_ordinal - 1)];
            provider_name = dep.name;
            switch (dep.kind) {
                .DARWIN_SHIM => {
                    if (shims.lookup(symbol)) |sh| {
                        resolved_addr = sh.address;
                        status = sh.status;
                        linux_equiv = sh.linux_equiv;
                    }
                },
                .LINUX_NATIVE_LIB => {
                    if (shims.lookupNativeLibrarySymbol(dep.name, symbol)) |addr| {
                        resolved_addr = addr;
                        status = .NATIVE_MAPPING;
                        linux_equiv = std.mem.span(shims.nativeLinuxLibraryForDylib(dep.name).?);
                    }
                },
                .LOCAL_MACHO => {
                    resolved_addr = self.lookupInImageExports(dep.image_index.?, symbol, 0);
                    status = .NATIVE_MAPPING;
                    linux_equiv = "macho:export_trie";
                },
                .WEAK_MISSING => {
                    if (is_weak) {
                        resolved_addr = 0;
                        status = .STUB_FOR_PROBE_ONLY;
                        linux_equiv = "weak:null";
                    }
                },
            }
        }

        if (resolved_addr == null) {
            if (is_weak) {
                resolved_addr = 0;
            } else {
                self.unresolved = .{
                    .image = provider_name,
                    .symbol = symbol,
                    .requested_by = img.path,
                    .resolution_path = provider_name,
                };
                std.debug.print(
                    "UNRESOLVED_SYMBOL\nimage={s}\nsymbol={s}\nrequested_by={s}\nresolution_path={s}\n",
                    .{ provider_name, symbol, img.path, provider_name },
                );
                return error.UnresolvedSymbol;
            }
        }

        return .{
            .addr = resolved_addr.?,
            .provider = provider_name,
            .status = status,
            .linux_equiv = linux_equiv,
        };
    }

    fn bindOneSite(self: *DyldContext, img_idx: usize, img: *const image.MappedImage, site: fixups.BindSite) !void {
        const slot_addr = img.segOffsetToActual(site.seg_index, site.seg_offset) orelse return error.OutOfBounds;
        const res = try self.resolveSymbol(img_idx, img, site.dylib_ordinal, site.symbol, site.is_weak);
        const final_val: usize = if (res.addr == 0) 0 else @intCast(@as(i64, @intCast(res.addr)) + site.addend);
        const ptr: *u64 = @ptrFromInt(slot_addr);
        ptr.* = @intCast(final_val);

        try self.resolved_symbols.append(self.allocator, .{
            .symbol = site.symbol,
            .requested_by = img.path,
            .provider = res.provider,
            .status = res.status,
            .linux_equiv = res.linux_equiv,
            .address = final_val,
            .site_addr = slot_addr,
        });
    }
};
