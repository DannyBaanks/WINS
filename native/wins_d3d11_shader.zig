//! Direct3D 10/11 DXBC (SM4/SM5) bytecode -> GLSL 4.20 Core translator.
//!
//! Decodes DXBC container chunks (`ISGN`, `OSGN`/`OSG5`, `SHDR`/`SHEX`) and emits
//! self-contained GLSL 420 core shaders with:
//!   * `layout(std140, binding = B) uniform CB_X { vec4 cbX[SIZE]; };`
//!   * `layout(binding = T) uniform sampler2D/samplerCube/sampler3D texT;`
//!   * `layout(location = R) in/out vec4 vR/oR;` matched across VS -> PS
//!   * 32-bit typeless temp registers (`vec4 r[N]`) with `intBitsToFloat` /
//!     `floatBitsToInt` / `uintBitsToFloat` / `floatBitsToUint` casts for integer ops.

const std = @import("std");

pub const Error = error{ Malformed, Unsupported, OutOfMemory };

pub const Stage = enum { vertex, pixel, other };

pub const TexDim = enum(u8) {
    none = 0,
    buf = 1,
    tex1d = 2,
    tex2d = 3,
    tex2dms = 4,
    tex3d = 5,
    cube = 6,
    tex1d_array = 7,
    tex2d_array = 8,
    cube_array = 10,
};

pub const SigElem = struct {
    name: []const u8,
    index: u32,
    sysval: u32,
    comp_type: u32,
    reg: u32,
    mask: u8,
};

pub const TexBinding = struct {
    reg: u8,
    dim: TexDim,
};

pub const Translated = struct {
    glsl: [:0]u8,
    stage: Stage,
    inputs: []SigElem,
    outputs: []SigElem,
    cb_mask: u16,
    tex_bindings: []TexBinding,

    pub fn deinit(self: *Translated, a: std.mem.Allocator) void {
        a.free(self.glsl);
        a.free(self.inputs);
        a.free(self.outputs);
        a.free(self.tex_bindings);
    }
};

pub var last_error: []const u8 = "";
/// Opcodes already reported as unhandled (bit per opcode; the last word also
/// absorbs any opcode >= 192).
var unhandled_seen: [4]u64 = .{ 0, 0, 0, 0 };

fn setErr(msg: []const u8) Error {
    last_error = msg;
    return error.Unsupported;
}

fn readU32(b: []const u8, off: usize) !u32 {
    if (off + 4 > b.len) return error.Malformed;
    return std.mem.readInt(u32, b[off..][0..4], .little);
}

fn parseSigChunk(a: std.mem.Allocator, chunk: []const u8, is_osg5: bool) ![]SigElem {
    if (chunk.len < 8) return error.Malformed;
    const count = try readU32(chunk, 0);
    const elem_sz: usize = if (is_osg5) 32 else 24;
    if (8 + @as(usize, count) * elem_sz > chunk.len) return error.Malformed;
    var list = try a.alloc(SigElem, count);
    for (0..count) |i| {
        const base = 8 + i * elem_sz;
        const off_adj: usize = if (is_osg5) 4 else 0;
        const name_off = try readU32(chunk, base + off_adj);
        const sem_idx = try readU32(chunk, base + off_adj + 4);
        const sysval = try readU32(chunk, base + off_adj + 8);
        const comp_ty = try readU32(chunk, base + off_adj + 12);
        const reg = try readU32(chunk, base + off_adj + 16);
        const mask_byte = chunk[base + off_adj + 20];
        const nm: []const u8 = if (name_off < chunk.len) std.mem.sliceTo(chunk[name_off..], 0) else "TEXCOORD";
        list[i] = .{
            .name = nm,
            .index = sem_idx,
            .sysval = sysval,
            .comp_type = comp_ty,
            .reg = reg,
            .mask = mask_byte & 0xF,
        };
    }
    return list;
}

const IndexVal = struct {
    kind: enum { imm, expr },
    imm: u32 = 0,
    expr: []const u8 = "",
};

const NumType = enum { f, i, u };

const Operand = struct {
    op_type: u8,
    num_comps: u8,
    sel_mode: u8,
    mask: u8, // 4-bit write mask (when sel_mode == 0)
    swz: [4]u8, // 0..3 for x,y,z,w
    indices: [3]IndexVal,
    index_dim: u8,
    imm_u32: [4]u32,
    neg: bool,
    abs: bool,
    sat: bool = false,
};

fn decodeOperand(a: std.mem.Allocator, toks: []const u32, pos: *usize) !Operand {
    if (pos.* >= toks.len) return error.Malformed;
    const tok = toks[pos.*];
    pos.* += 1;

    var op: Operand = .{
        .op_type = @intCast((tok >> 12) & 0xFF),
        .num_comps = @intCast(tok & 3),
        .sel_mode = @intCast((tok >> 2) & 3),
        .mask = 0xF,
        .swz = .{ 0, 1, 2, 3 },
        .indices = [_]IndexVal{.{ .kind = .imm, .imm = 0 }} ** 3,
        .index_dim = @intCast((tok >> 20) & 3),
        .imm_u32 = .{ 0, 0, 0, 0 },
        .neg = false,
        .abs = false,
    };

    if (op.num_comps == 2) {
        switch (op.sel_mode) {
            0 => op.mask = @intCast((tok >> 4) & 0xF),
            1 => {
                op.swz[0] = @intCast((tok >> 4) & 3);
                op.swz[1] = @intCast((tok >> 6) & 3);
                op.swz[2] = @intCast((tok >> 8) & 3);
                op.swz[3] = @intCast((tok >> 10) & 3);
            },
            2 => {
                const s: u8 = @intCast((tok >> 4) & 3);
                op.swz = .{ s, s, s, s };
            },
            else => {},
        }
    } else if (op.num_comps == 1) {
        op.mask = 1;
        op.swz = .{ 0, 0, 0, 0 };
    }

    var ext = (tok >> 31) != 0;
    while (ext) {
        if (pos.* >= toks.len) return error.Malformed;
        const etok = toks[pos.*];
        pos.* += 1;
        const etype = etok & 0x3F;
        if (etype == 1) { // D3D10_SB_EXTENDED_OPERAND_MODIFIER
            const m = (etok >> 6) & 0xFF;
            if (m == 1) op.neg = true else if (m == 2) op.abs = true else if (m == 3) {
                op.abs = true;
                op.neg = true;
            }
        }
        ext = (etok >> 31) != 0;
    }

    if (op.op_type == 4) { // Immediate32
        const cnt: usize = if (op.num_comps == 2) 4 else if (op.num_comps == 1) 1 else 0;
        for (0..cnt) |i| {
            if (pos.* >= toks.len) return error.Malformed;
            op.imm_u32[i] = toks[pos.*];
            pos.* += 1;
        }
    } else if (op.op_type == 5) { // Immediate64
        const cnt: usize = if (op.num_comps == 2) 4 else 2;
        for (0..cnt) |_| {
            if (pos.* >= toks.len) return error.Malformed;
            pos.* += 1;
        }
    }

    for (0..op.index_dim) |d| {
        const rep = (tok >> @intCast(22 + d * 3)) & 7;
        switch (rep) {
            0 => {
                if (pos.* >= toks.len) return error.Malformed;
                op.indices[d] = .{ .kind = .imm, .imm = toks[pos.*] };
                pos.* += 1;
            },
            1 => {
                if (pos.* + 2 > toks.len) return error.Malformed;
                op.indices[d] = .{ .kind = .imm, .imm = toks[pos.*] };
                pos.* += 2;
            },
            2 => {
                const sub = try decodeOperand(a, toks, pos);
                const sub_expr = try formatSrcScalarInt(a, &sub);
                op.indices[d] = .{ .kind = .expr, .expr = sub_expr };
            },
            3 => {
                if (pos.* >= toks.len) return error.Malformed;
                const offset = toks[pos.*];
                pos.* += 1;
                const sub = try decodeOperand(a, toks, pos);
                const sub_expr = try formatSrcScalarInt(a, &sub);
                const comb = try std.fmt.allocPrint(a, "({s} + {d})", .{ sub_expr, offset });
                op.indices[d] = .{ .kind = .expr, .expr = comb };
            },
            else => return setErr("64-bit relative index"),
        }
    }

    return op;
}

fn swzChar(c: u8) u8 {
    return switch (c) {
        0 => 'x',
        1 => 'y',
        2 => 'z',
        else => 'w',
    };
}

fn maskStr(mask: u8, buf: *[5]u8) []const u8 {
    var n: usize = 0;
    inline for (0..4) |c| {
        if ((mask & (@as(u8, 1) << @intCast(c))) != 0) {
            buf[n] = swzChar(@intCast(c));
            n += 1;
        }
    }
    if (n == 0) {
        buf[0] = 'x';
        return buf[0..1];
    }
    return buf[0..n];
}

fn maskCount(mask: u8) usize {
    var n: usize = 0;
    inline for (0..4) |c| {
        if ((mask & (@as(u8, 1) << @intCast(c))) != 0) n += 1;
    }
    return if (n == 0) 1 else n;
}

fn swzForMask(swz: [4]u8, mask: u8, buf: *[5]u8) []const u8 {
    var n: usize = 0;
    inline for (0..4) |c| {
        if ((mask & (@as(u8, 1) << @intCast(c))) != 0) {
            buf[n] = swzChar(swz[c]);
            n += 1;
        }
    }
    if (n == 0) {
        buf[0] = swzChar(swz[0]);
        return buf[0..1];
    }
    return buf[0..n];
}

fn formatIndex(a: std.mem.Allocator, iv: IndexVal) ![]const u8 {
    if (iv.kind == .imm) return std.fmt.allocPrint(a, "{d}", .{iv.imm});
    return iv.expr;
}

fn formatBaseVar(a: std.mem.Allocator, op: *const Operand, stage: Stage) ![]const u8 {
    return switch (op.op_type) {
        0 => std.fmt.allocPrint(a, "r[{s}]", .{try formatIndex(a, op.indices[0])}),
        1 => std.fmt.allocPrint(a, "vi{s}", .{try formatIndex(a, op.indices[0])}),
        2 => std.fmt.allocPrint(a, "vo{s}", .{try formatIndex(a, op.indices[0])}),
        3 => std.fmt.allocPrint(a, "x{d}[{s}]", .{ op.indices[0].imm, try formatIndex(a, op.indices[1]) }),
        8 => blk: {
            const prefix = if (stage == .pixel) "pcb" else "vcb";
            break :blk std.fmt.allocPrint(a, "{s}{d}[{s}]", .{ prefix, op.indices[0].imm, try formatIndex(a, op.indices[1]) });
        },
        9 => blk: {
            const prefix = if (stage == .pixel) "picb" else "vicb";
            break :blk std.fmt.allocPrint(a, "{s}[{s}]", .{ prefix, try formatIndex(a, op.indices[0]) });
        },
        11 => try a.dupe(u8, "vec4(uintBitsToFloat(uint(gl_PrimitiveID)), 0.0, 0.0, 0.0)"),
        12 => try a.dupe(u8, "oDepth"),
        13 => try a.dupe(u8, "dummyNull"),
        35 => try a.dupe(u8, "vec4(uintBitsToFloat(uint(gl_SampleMaskIn[0])), 0.0, 0.0, 0.0)"),
        else => try std.fmt.allocPrint(a, "vec4(0.0) /*op_type={d}*/", .{op.op_type}),
    };
}

fn formatSrcScalarInt(a: std.mem.Allocator, op: *const Operand) ![]const u8 {
    if (op.op_type == 4) {
        const idx = op.swz[0];
        const v: i32 = @bitCast(op.imm_u32[idx]);
        return std.fmt.allocPrint(a, "{d}", .{v});
    }
    const base = try formatBaseVar(a, op, .vertex);
    return std.fmt.allocPrint(a, "floatBitsToInt({s}.{c})", .{ base, swzChar(op.swz[0]) });
}

fn formatFloatBits(a: std.mem.Allocator, bits: u32, ty: NumType) ![]const u8 {
    return switch (ty) {
        .f => blk: {
            const f: f32 = @bitCast(bits);
            if (!std.math.isFinite(f)) {
                break :blk std.fmt.allocPrint(a, "uintBitsToFloat(0x{x}u)", .{bits});
            }
            var buf: [64]u8 = undefined;
            const s = try std.fmt.bufPrint(&buf, "{d:.8}", .{f});
            if (std.mem.indexOfScalar(u8, s, '.') == null and std.mem.indexOfScalar(u8, s, 'e') == null and std.mem.indexOfScalar(u8, s, 'E') == null) {
                break :blk std.fmt.allocPrint(a, "{s}.0", .{s});
            }
            break :blk a.dupe(u8, s);
        },
        .i => blk: {
            const v: i32 = @bitCast(bits);
            break :blk std.fmt.allocPrint(a, "{d}", .{v});
        },
        .u => std.fmt.allocPrint(a, "{d}u", .{bits}),
    };
}

fn formatSrc(a: std.mem.Allocator, op: *const Operand, mask: u8, ty: NumType, stage: Stage) ![]const u8 {
    const cnt = maskCount(mask);
    var expr: []const u8 = undefined;
    if (op.op_type == 4) {
        if (cnt == 1) {
            const c = @min(@ctz(mask), 3);
            const idx = if (op.num_comps == 1) 0 else op.swz[c];
            expr = try formatFloatBits(a, op.imm_u32[idx], ty);
        } else {
            var parts: std.ArrayList(u8) = .empty;
            const ctor = switch (ty) {
                .f => switch (cnt) { 2 => "vec2(", 3 => "vec3(", else => "vec4(" },
                .i => switch (cnt) { 2 => "ivec2(", 3 => "ivec3(", else => "ivec4(" },
                .u => switch (cnt) { 2 => "uvec2(", 3 => "uvec3(", else => "uvec4(" },
            };
            try parts.appendSlice(a, ctor);
            var first = true;
            inline for (0..4) |c| {
                if ((mask & (@as(u8, 1) << @intCast(c))) != 0) {
                    if (!first) try parts.appendSlice(a, ", ");
                    first = false;
                    const idx = if (op.num_comps == 1) 0 else op.swz[c];
                    try parts.appendSlice(a, try formatFloatBits(a, op.imm_u32[idx], ty));
                }
            }
            try parts.append(a, ')');
            expr = parts.items;
        }
    } else {
        const base = try formatBaseVar(a, op, stage);
        var sbuf: [5]u8 = undefined;
        const sw = swzForMask(op.swz, mask, &sbuf);
        const raw = try std.fmt.allocPrint(a, "{s}.{s}", .{ base, sw });
        expr = switch (ty) {
            .f => raw,
            .i => try std.fmt.allocPrint(a, "floatBitsToInt({s})", .{raw}),
            .u => try std.fmt.allocPrint(a, "floatBitsToUint({s})", .{raw}),
        };
    }
    if (op.abs) expr = try std.fmt.allocPrint(a, "abs({s})", .{expr});
    if (op.neg) expr = try std.fmt.allocPrint(a, "(-{s})", .{expr});
    return expr;
}

fn appendFmt(list: *std.ArrayList(u8), a: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    try list.appendSlice(a, try std.fmt.allocPrint(a, fmt, args));
}

fn assignDst(a: std.mem.Allocator, out: *std.ArrayList(u8), dst: *const Operand, rhs_in: []const u8, ty: NumType, stage: Stage) !void {
    if (dst.op_type == 13) return; // null register
    const mask = dst.mask;
    var rhs = rhs_in;
    if (dst.sat and ty == .f) {
        rhs = try std.fmt.allocPrint(a, "clamp({s}, 0.0, 1.0)", .{rhs});
    }
    rhs = switch (ty) {
        .f => rhs,
        .i => try std.fmt.allocPrint(a, "intBitsToFloat({s})", .{rhs}),
        .u => try std.fmt.allocPrint(a, "uintBitsToFloat({s})", .{rhs}),
    };
    if (dst.op_type == 12) { // oDepth
        try appendFmt(out, a, "    gl_FragDepth = {s};\n", .{rhs});
        return;
    }
    const base = try formatBaseVar(a, dst, stage);
    var mbuf: [5]u8 = undefined;
    const ms = maskStr(mask, &mbuf);
    try appendFmt(out, a, "    {s}.{s} = {s};\n", .{ base, ms, rhs });
}

fn typePrefix(cnt: usize, ty: NumType) []const u8 {
    return switch (ty) {
        .f => switch (cnt) { 1 => "float", 2 => "vec2", 3 => "vec3", else => "vec4" },
        .i => switch (cnt) { 1 => "int", 2 => "ivec2", 3 => "ivec3", else => "ivec4" },
        .u => switch (cnt) { 1 => "uint", 2 => "uvec2", 3 => "uvec3", else => "uvec4" },
    };
}

const SbOp = enum(u16) {
    add = 0,
    @"and" = 1,
    @"break" = 2,
    breakc = 3,
    call = 4,
    callc = 5,
    case = 6,
    @"continue" = 7,
    continuec = 8,
    cut = 9,
    default = 10,
    deriv_rtx = 11,
    deriv_rty = 12,
    discard = 13,
    div = 14,
    dp2 = 15,
    dp3 = 16,
    dp4 = 17,
    @"else" = 18,
    emit = 19,
    emitthencut = 20,
    endif = 21,
    endloop = 22,
    endswitch = 23,
    eq = 24,
    exp = 25,
    frc = 26,
    ftoi = 27,
    ftou = 28,
    ge = 29,
    iadd = 30,
    @"if" = 31,
    ieq = 32,
    ige = 33,
    ilt = 34,
    imad = 35,
    imax = 36,
    imin = 37,
    imul = 38,
    ine = 39,
    ineg = 40,
    ishl = 41,
    ishr = 42,
    itof = 43,
    label = 44,
    ld = 45,
    ld_ms = 46,
    log = 47,
    loop = 48,
    lt = 49,
    mad = 50,
    min = 51,
    max = 52,
    customdata = 53,
    mov = 54,
    movc = 55,
    mul = 56,
    ne = 57,
    nop = 58,
    not = 59,
    @"or" = 60,
    resinfo = 61,
    ret = 62,
    retc = 63,
    round_ne = 64,
    round_ni = 65,
    round_pi = 66,
    round_z = 67,
    rsq = 68,
    sample = 69,
    sample_c = 70,
    sample_c_lz = 71,
    sample_l = 72,
    sample_d = 73,
    sample_b = 74,
    sqrt = 75,
    @"switch" = 76,
    sincos = 77,
    udiv = 78,
    uge = 79,
    ult = 80,
    umad = 81,
    umax = 82,
    umin = 83,
    umul = 84,
    ushr = 85,
    utof = 86,
    xor = 87,
    dcl_resource = 88,
    dcl_constant_buffer = 89,
    dcl_sampler = 90,
    dcl_index_range = 91,
    dcl_gs_out_prim = 92,
    dcl_gs_in_prim = 93,
    dcl_max_out_vtx = 94,
    dcl_input = 95,
    dcl_input_sgv = 96,
    dcl_input_siv = 97,
    dcl_input_ps = 98,
    dcl_input_ps_sgv = 99,
    dcl_input_ps_siv = 100,
    dcl_output = 101,
    dcl_output_sgv = 102,
    dcl_output_siv = 103,
    dcl_temps = 104,
    dcl_indexable_temp = 105,
    dcl_global_flags = 106,
    deriv_rtx_coarse = 122,
    deriv_rtx_fine = 123,
    deriv_rty_coarse = 124,
    deriv_rty_fine = 125,
    rcp = 129,
    _,
};

pub fn parseInputSignature(gpa: std.mem.Allocator, dxbc: []const u8) ![]SigElem {
    if (dxbc.len < 32 or !std.mem.eql(u8, dxbc[0..4], "DXBC")) return error.Malformed;
    const nchunks = try readU32(dxbc, 28);
    if (nchunks == 0 or nchunks > 32 or 32 + @as(usize, nchunks) * 4 > dxbc.len) return error.Malformed;
    for (0..nchunks) |i| {
        const off = try readU32(dxbc, 32 + i * 4);
        if (off + 8 > dxbc.len) return error.Malformed;
        const tag = dxbc[off..][0..4];
        const csz = try readU32(dxbc, off + 4);
        if (off + 8 + csz > dxbc.len) return error.Malformed;
        if (std.mem.eql(u8, tag, "ISGN") or std.mem.eql(u8, tag, "ISG1")) {
            return parseSigChunk(gpa, dxbc[off + 8 ..][0..csz], false);
        }
    }
    return gpa.alloc(SigElem, 0);
}

pub fn translate(gpa: std.mem.Allocator, dxbc: []const u8) !Translated {
    return translateWithVaryings(gpa, dxbc, null);
}

pub fn translateWithVaryings(gpa: std.mem.Allocator, dxbc: []const u8, vs_outputs: ?[]const SigElem) !Translated {
    last_error = "";
    if (dxbc.len < 32 or !std.mem.eql(u8, dxbc[0..4], "DXBC")) return error.Malformed;
    const nchunks = try readU32(dxbc, 28);
    if (nchunks == 0 or nchunks > 32 or 32 + @as(usize, nchunks) * 4 > dxbc.len) return error.Malformed;

    var isgn_chunk: ?[]const u8 = null;
    var osgn_chunk: ?[]const u8 = null;
    var osg5 = false;
    var shdr_chunk: ?[]const u8 = null;

    for (0..nchunks) |i| {
        const off = try readU32(dxbc, 32 + i * 4);
        if (off + 8 > dxbc.len) return error.Malformed;
        const tag = dxbc[off..][0..4];
        const csz = try readU32(dxbc, off + 4);
        if (off + 8 + csz > dxbc.len) return error.Malformed;
        const payload = dxbc[off + 8 ..][0..csz];
        if (std.mem.eql(u8, tag, "ISGN") or std.mem.eql(u8, tag, "ISG1")) isgn_chunk = payload;
        if (std.mem.eql(u8, tag, "OSGN") or std.mem.eql(u8, tag, "OSG1")) { osgn_chunk = payload; osg5 = false; }
        if (std.mem.eql(u8, tag, "OSG5")) { osgn_chunk = payload; osg5 = true; }
        if (std.mem.eql(u8, tag, "SHDR") or std.mem.eql(u8, tag, "SHEX")) shdr_chunk = payload;
    }

    const sc = shdr_chunk orelse return setErr("missing SHDR/SHEX chunk");
    if (sc.len < 8) return error.Malformed;
    const n_toks = try readU32(sc, 4);
    if (@as(usize, n_toks) * 4 > sc.len) return error.Malformed;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const toks = try a.alloc(u32, n_toks);
    for (0..n_toks) |i| toks[i] = std.mem.readInt(u32, sc[i * 4 ..][0..4], .little);

    const ptype_raw = (toks[0] >> 16) & 0xFFFF;
    const stage: Stage = switch (ptype_raw) {
        0 => .pixel,
        1 => .vertex,
        else => .other,
    };
    if (stage == .other) return setErr("unsupported shader stage");

    const inputs = if (isgn_chunk) |c| try parseSigChunk(gpa, c, false) else try gpa.alloc(SigElem, 0);
    errdefer gpa.free(inputs);
    const outputs = if (osgn_chunk) |c| try parseSigChunk(gpa, c, osg5) else try gpa.alloc(SigElem, 0);
    errdefer gpa.free(outputs);

    var n_temps: u32 = 0;
    var cb_sizes = [_]u32{0} ** 16;
    var cb_mask: u16 = 0;
    var tex_dims = [_]TexDim{.none} ** 16;
    var idx_temp_sizes = [_]u32{0} ** 8;
    var icb_vals: ?[]const u32 = null;
    var sv_pos_out_reg: ?u32 = null;
    var sv_pos_in_reg: ?u32 = null;

    if (stage == .vertex) {
        for (outputs) |o| {
            if (o.sysval == 1 or std.ascii.eqlIgnoreCase(o.name, "SV_Position")) sv_pos_out_reg = o.reg;
        }
    } else {
        for (inputs) |in_e| {
            if (in_e.sysval == 1 or std.ascii.eqlIgnoreCase(in_e.name, "SV_Position")) sv_pos_in_reg = in_e.reg;
        }
    }

    var body: std.ArrayList(u8) = .empty;

    var k: usize = 2;
    while (k < toks.len) {
        const itok = toks[k];
        const op: SbOp = @enumFromInt(@as(u16, @intCast(itok & 0x7FF)));
        if (op == .customdata) {
            if (k + 1 >= toks.len) break;
            const clen = toks[k + 1];
            const class = (itok >> 11) & 0x1FFFFF;
            if (class == 3 and clen > 2 and k + clen <= toks.len) {
                icb_vals = toks[k + 2 .. k + clen];
            } else if (std.c.getenv("WINS_TRACE") != null and class != 0) {
                std.debug.print("[WINS:DXBC] customdata class={d} len={d}\n", .{ class, clen });
            }
            k += @max(@as(usize, 2), clen);
            continue;
        }
        const ilen = (itok >> 24) & 0x7F;
        if (ilen == 0 or k + ilen > toks.len) break;
        const next_k = k + ilen;
        defer k = next_k;

        const sat = (itok & 0x2000) != 0;
        const bool_nz = ((itok >> 18) & 1) != 0;

        var p = k + 1;
        var has_ext = (itok >> 31) != 0;
        while (has_ext and p < next_k) {
            has_ext = (toks[p] >> 31) != 0;
            p += 1;
        }

        switch (op) {
            .dcl_global_flags, .dcl_sampler, .dcl_index_range, .dcl_gs_out_prim, .dcl_gs_in_prim, .dcl_max_out_vtx,
            .dcl_input, .dcl_input_sgv, .dcl_input_siv, .dcl_input_ps, .dcl_input_ps_sgv, .dcl_input_ps_siv,
            .dcl_output, .dcl_output_sgv, .dcl_output_siv => continue,
            .dcl_temps => {
                if (p < next_k) n_temps = @max(n_temps, toks[p]);
                continue;
            },
            .dcl_constant_buffer => {
                const cop = try decodeOperand(a, toks, &p);
                if (cop.indices[0].imm < 16) {
                    cb_mask |= @as(u16, 1) << @intCast(cop.indices[0].imm);
                    cb_sizes[cop.indices[0].imm] = @max(cb_sizes[cop.indices[0].imm], cop.indices[1].imm);
                }
                continue;
            },
            .dcl_resource => {
                const dim_raw: u8 = @intCast((itok >> 11) & 0x1F);
                const rop = try decodeOperand(a, toks, &p);
                if (rop.indices[0].imm < 16) {
                    tex_dims[rop.indices[0].imm] = @enumFromInt(dim_raw);
                }
                continue;
            },
            .dcl_indexable_temp => {
                if (p + 1 < next_k) {
                    const reg = toks[p];
                    const sz = toks[p + 1];
                    if (reg < 8) idx_temp_sizes[reg] = @max(idx_temp_sizes[reg], sz);
                }
                continue;
            },
            .nop => continue,
            .ret => {
                if (stage == .vertex) {
                    if (sv_pos_out_reg) |r| {
                        try appendFmt(&body, a, "    gl_Position = vo{d};\n", .{r});
                    }
                }
                try body.appendSlice(a, "    return;\n");
            },
            .retc => {
                const c0 = try decodeOperand(a, toks, &p);
                const ce = try formatSrc(a, &c0, 1, .u, stage);
                const cmp = if (bool_nz) "!= 0u" else "== 0u";
                if (stage == .vertex and sv_pos_out_reg != null) {
                    try appendFmt(&body, a, "    if ({s} {s}) {{ gl_Position = vo{d}; return; }}\n", .{ ce, cmp, sv_pos_out_reg.? });
                } else {
                    try appendFmt(&body, a, "    if ({s} {s}) return;\n", .{ ce, cmp });
                }
            },
            .mov => {
                var dst = try decodeOperand(a, toks, &p); dst.sat = sat;
                const s0 = try decodeOperand(a, toks, &p);
                const rhs = try formatSrc(a, &s0, dst.mask, .f, stage);
                try assignDst(a, &body, &dst, rhs, .f, stage);
            },
            .movc => {
                var dst = try decodeOperand(a, toks, &p); dst.sat = sat;
                const c0 = try decodeOperand(a, toks, &p);
                const s1 = try decodeOperand(a, toks, &p);
                const s2 = try decodeOperand(a, toks, &p);
                inline for (0..4) |c| {
                    const bit: u8 = @as(u8, 1) << @intCast(c);
                    if ((dst.mask & bit) != 0) {
                        var sub_dst = dst; sub_dst.mask = bit;
                        const ce = try formatSrc(a, &c0, bit, .u, stage);
                        const e1 = try formatSrc(a, &s1, bit, .f, stage);
                        const e2 = try formatSrc(a, &s2, bit, .f, stage);
                        const rhs = try std.fmt.allocPrint(a, "(({s} != 0u) ? {s} : {s})", .{ ce, e1, e2 });
                        try assignDst(a, &body, &sub_dst, rhs, .f, stage);
                    }
                }
            },
            .add, .mul, .div, .min, .max, .rsq, .rcp => {
                var dst = try decodeOperand(a, toks, &p); dst.sat = sat;
                const s0 = try decodeOperand(a, toks, &p);
                const a0 = try formatSrc(a, &s0, dst.mask, .f, stage);
                if (op == .rsq) {
                    try assignDst(a, &body, &dst, try std.fmt.allocPrint(a, "inversesqrt({s})", .{a0}), .f, stage);
                } else if (op == .rcp) {
                    try assignDst(a, &body, &dst, try std.fmt.allocPrint(a, "(1.0 / {s})", .{a0}), .f, stage);
                } else {
                    const s1 = try decodeOperand(a, toks, &p);
                    const a1 = try formatSrc(a, &s1, dst.mask, .f, stage);
                    const rhs = switch (op) {
                        .add => try std.fmt.allocPrint(a, "({s} + {s})", .{ a0, a1 }),
                        .mul => try std.fmt.allocPrint(a, "({s} * {s})", .{ a0, a1 }),
                        .div => try std.fmt.allocPrint(a, "({s} / {s})", .{ a0, a1 }),
                        .min => try std.fmt.allocPrint(a, "min({s}, {s})", .{ a0, a1 }),
                        .max => try std.fmt.allocPrint(a, "max({s}, {s})", .{ a0, a1 }),
                        else => unreachable,
                    };
                    try assignDst(a, &body, &dst, rhs, .f, stage);
                }
            },
            .mad => {
                var dst = try decodeOperand(a, toks, &p); dst.sat = sat;
                const s0 = try decodeOperand(a, toks, &p);
                const s1 = try decodeOperand(a, toks, &p);
                const s2 = try decodeOperand(a, toks, &p);
                const a0 = try formatSrc(a, &s0, dst.mask, .f, stage);
                const a1 = try formatSrc(a, &s1, dst.mask, .f, stage);
                const a2 = try formatSrc(a, &s2, dst.mask, .f, stage);
                try assignDst(a, &body, &dst, try std.fmt.allocPrint(a, "({s} * {s} + {s})", .{ a0, a1, a2 }), .f, stage);
            },
            .dp2, .dp3, .dp4 => {
                var dst = try decodeOperand(a, toks, &p); dst.sat = sat;
                const s0 = try decodeOperand(a, toks, &p);
                const s1 = try decodeOperand(a, toks, &p);
                const dmask: u8 = if (op == .dp2) 0x3 else if (op == .dp3) 0x7 else 0xF;
                const a0 = try formatSrc(a, &s0, dmask, .f, stage);
                const a1 = try formatSrc(a, &s1, dmask, .f, stage);
                const cnt = maskCount(dst.mask);
                const dot_e = try std.fmt.allocPrint(a, "dot({s}, {s})", .{ a0, a1 });
                const rhs = if (cnt == 1) dot_e else try std.fmt.allocPrint(a, "{s}({s})", .{ typePrefix(cnt, .f), dot_e });
                try assignDst(a, &body, &dst, rhs, .f, stage);
            },
            .exp, .frc, .log, .round_ni, .round_pi, .round_ne, .round_z, .sqrt,
            .deriv_rtx, .deriv_rtx_coarse, .deriv_rtx_fine,
            .deriv_rty, .deriv_rty_coarse, .deriv_rty_fine => {
                var dst = try decodeOperand(a, toks, &p); dst.sat = sat;
                const s0 = try decodeOperand(a, toks, &p);
                const a0 = try formatSrc(a, &s0, dst.mask, .f, stage);
                const fn_name = switch (op) {
                    .exp => "exp2",
                    .frc => "fract",
                    .log => "log2",
                    .round_ni => "floor",
                    .round_pi => "ceil",
                    .round_ne => "roundEven",
                    .round_z => "trunc",
                    .sqrt => "sqrt",
                    .deriv_rtx, .deriv_rtx_coarse, .deriv_rtx_fine => "dFdx",
                    .deriv_rty, .deriv_rty_coarse, .deriv_rty_fine => "dFdy",
                    else => unreachable,
                };
                try assignDst(a, &body, &dst, try std.fmt.allocPrint(a, "{s}({s})", .{ fn_name, a0 }), .f, stage);
            },
            .sincos => {
                var dsin = try decodeOperand(a, toks, &p); dsin.sat = sat;
                var dcos = try decodeOperand(a, toks, &p); dcos.sat = sat;
                const s0 = try decodeOperand(a, toks, &p);
                const m = if (dsin.op_type != 13) dsin.mask else dcos.mask;
                const a0 = try formatSrc(a, &s0, m, .f, stage);
                if (dsin.op_type != 13) try assignDst(a, &body, &dsin, try std.fmt.allocPrint(a, "sin({s})", .{a0}), .f, stage);
                if (dcos.op_type != 13) try assignDst(a, &body, &dcos, try std.fmt.allocPrint(a, "cos({s})", .{a0}), .f, stage);
            },
            .eq, .ge, .lt, .ne => {
                const dst = try decodeOperand(a, toks, &p);
                const s0 = try decodeOperand(a, toks, &p);
                const s1 = try decodeOperand(a, toks, &p);
                const cmp_op = switch (op) { .eq => "==", .ge => ">=", .lt => "<", else => "!=" };
                inline for (0..4) |c| {
                    const bit: u8 = @as(u8, 1) << @intCast(c);
                    if ((dst.mask & bit) != 0) {
                        var sd = dst; sd.mask = bit;
                        const e0 = try formatSrc(a, &s0, bit, .f, stage);
                        const e1 = try formatSrc(a, &s1, bit, .f, stage);
                        try assignDst(a, &body, &sd, try std.fmt.allocPrint(a, "(({s} {s} {s}) ? 0xFFFFFFFFu : 0u)", .{ e0, cmp_op, e1 }), .u, stage);
                    }
                }
            },
            .ieq, .ige, .ilt, .ine, .ult, .uge => {
                const dst = try decodeOperand(a, toks, &p);
                const s0 = try decodeOperand(a, toks, &p);
                const s1 = try decodeOperand(a, toks, &p);
                const ty: NumType = if (op == .ult or op == .uge) .u else .i;
                const cmp_op = switch (op) { .ieq => "==", .ige, .uge => ">=", .ilt, .ult => "<", else => "!=" };
                inline for (0..4) |c| {
                    const bit: u8 = @as(u8, 1) << @intCast(c);
                    if ((dst.mask & bit) != 0) {
                        var sd = dst; sd.mask = bit;
                        const e0 = try formatSrc(a, &s0, bit, ty, stage);
                        const e1 = try formatSrc(a, &s1, bit, ty, stage);
                        try assignDst(a, &body, &sd, try std.fmt.allocPrint(a, "(({s} {s} {s}) ? 0xFFFFFFFFu : 0u)", .{ e0, cmp_op, e1 }), .u, stage);
                    }
                }
            },
            .@"and", .@"or", .xor, .iadd, .imad, .imin, .imax, .umin, .umax, .umad, .ishl, .ishr, .ushr, .itof, .utof, .ftoi, .ftou, .not, .ineg => {
                var dst = try decodeOperand(a, toks, &p);
                const cnt = maskCount(dst.mask);
                if (op == .itof) {
                    const s0 = try decodeOperand(a, toks, &p);
                    const a0 = try formatSrc(a, &s0, dst.mask, .i, stage);
                    try assignDst(a, &body, &dst, try std.fmt.allocPrint(a, "{s}({s})", .{ typePrefix(cnt, .f), a0 }), .f, stage);
                } else if (op == .utof) {
                    const s0 = try decodeOperand(a, toks, &p);
                    const a0 = try formatSrc(a, &s0, dst.mask, .u, stage);
                    try assignDst(a, &body, &dst, try std.fmt.allocPrint(a, "{s}({s})", .{ typePrefix(cnt, .f), a0 }), .f, stage);
                } else if (op == .ftoi) {
                    const s0 = try decodeOperand(a, toks, &p);
                    const a0 = try formatSrc(a, &s0, dst.mask, .f, stage);
                    try assignDst(a, &body, &dst, try std.fmt.allocPrint(a, "{s}({s})", .{ typePrefix(cnt, .i), a0 }), .i, stage);
                } else if (op == .ftou) {
                    const s0 = try decodeOperand(a, toks, &p);
                    const a0 = try formatSrc(a, &s0, dst.mask, .f, stage);
                    try assignDst(a, &body, &dst, try std.fmt.allocPrint(a, "{s}({s})", .{ typePrefix(cnt, .u), a0 }), .u, stage);
                } else if (op == .not) {
                    const s0 = try decodeOperand(a, toks, &p);
                    const a0 = try formatSrc(a, &s0, dst.mask, .u, stage);
                    try assignDst(a, &body, &dst, try std.fmt.allocPrint(a, "(~{s})", .{a0}), .u, stage);
                } else if (op == .ineg) {
                    const s0 = try decodeOperand(a, toks, &p);
                    const a0 = try formatSrc(a, &s0, dst.mask, .i, stage);
                    try assignDst(a, &body, &dst, try std.fmt.allocPrint(a, "(-{s})", .{a0}), .i, stage);
                } else if (op == .imad or op == .umad) {
                    const ty: NumType = if (op == .umad) .u else .i;
                    const s0 = try decodeOperand(a, toks, &p);
                    const s1 = try decodeOperand(a, toks, &p);
                    const s2 = try decodeOperand(a, toks, &p);
                    const a0 = try formatSrc(a, &s0, dst.mask, ty, stage);
                    const a1 = try formatSrc(a, &s1, dst.mask, ty, stage);
                    const a2 = try formatSrc(a, &s2, dst.mask, ty, stage);
                    try assignDst(a, &body, &dst, try std.fmt.allocPrint(a, "({s} * {s} + {s})", .{ a0, a1, a2 }), ty, stage);
                } else {
                    const ty: NumType = if (op == .@"and" or op == .@"or" or op == .xor or op == .ushr or op == .umin or op == .umax) .u else .i;
                    const s0 = try decodeOperand(a, toks, &p);
                    const s1 = try decodeOperand(a, toks, &p);
                    const a0 = try formatSrc(a, &s0, dst.mask, ty, stage);
                    const a1 = try formatSrc(a, &s1, dst.mask, ty, stage);
                    const rhs = switch (op) {
                        .@"and" => try std.fmt.allocPrint(a, "({s} & {s})", .{ a0, a1 }),
                        .@"or" => try std.fmt.allocPrint(a, "({s} | {s})", .{ a0, a1 }),
                        .xor => try std.fmt.allocPrint(a, "({s} ^ {s})", .{ a0, a1 }),
                        .iadd => try std.fmt.allocPrint(a, "({s} + {s})", .{ a0, a1 }),
                        .imax, .umax => try std.fmt.allocPrint(a, "max({s}, {s})", .{ a0, a1 }),
                        .imin, .umin => try std.fmt.allocPrint(a, "min({s}, {s})", .{ a0, a1 }),
                        .ishl => try std.fmt.allocPrint(a, "({s} << ({s} & 31))", .{ a0, a1 }),
                        .ishr, .ushr => try std.fmt.allocPrint(a, "({s} >> ({s} & 31))", .{ a0, a1 }),
                        else => unreachable,
                    };
                    try assignDst(a, &body, &dst, rhs, ty, stage);
                }
            },
            .imul, .umul => {
                var dhi = try decodeOperand(a, toks, &p);
                var dlo = try decodeOperand(a, toks, &p);
                const ty: NumType = if (op == .umul) .u else .i;
                const s0 = try decodeOperand(a, toks, &p);
                const s1 = try decodeOperand(a, toks, &p);
                const m = if (dlo.op_type != 13) dlo.mask else dhi.mask;
                const a0 = try formatSrc(a, &s0, m, ty, stage);
                const a1 = try formatSrc(a, &s1, m, ty, stage);
                if (dlo.op_type != 13) try assignDst(a, &body, &dlo, try std.fmt.allocPrint(a, "({s} * {s})", .{ a0, a1 }), ty, stage);
                if (dhi.op_type != 13) try assignDst(a, &body, &dhi, try std.fmt.allocPrint(a, "({s} ^ {s})", .{ a0, a1 }), ty, stage);
            },
            .udiv => {
                var dq = try decodeOperand(a, toks, &p);
                var dr = try decodeOperand(a, toks, &p);
                const s0 = try decodeOperand(a, toks, &p);
                const s1 = try decodeOperand(a, toks, &p);
                const m = if (dq.op_type != 13) dq.mask else dr.mask;
                const a0 = try formatSrc(a, &s0, m, .u, stage);
                const a1 = try formatSrc(a, &s1, m, .u, stage);
                if (dq.op_type != 13) try assignDst(a, &body, &dq, try std.fmt.allocPrint(a, "({s} / {s})", .{ a0, a1 }), .u, stage);
                if (dr.op_type != 13) try assignDst(a, &body, &dr, try std.fmt.allocPrint(a, "({s} % {s})", .{ a0, a1 }), .u, stage);
            },
            .sample, .sample_c, .sample_c_lz, .sample_l, .sample_d, .sample_b, .ld => {
                var dst = try decodeOperand(a, toks, &p); dst.sat = sat;
                const coord = try decodeOperand(a, toks, &p);
                const res = try decodeOperand(a, toks, &p);
                const reg: u8 = @intCast(@min(15, res.indices[0].imm));
                const tdim = tex_dims[reg];
                const cmask: u8 = switch (tdim) {
                    .tex1d => 1,
                    .tex3d, .cube => 7,
                    else => 3,
                };
                if (op != .ld) _ = try decodeOperand(a, toks, &p);
                var extra_e: []const u8 = "";
                if (op == .sample_l) {
                    const lod = try decodeOperand(a, toks, &p);
                    extra_e = try formatSrc(a, &lod, 1, .f, stage);
                } else if (op == .sample_c or op == .sample_c_lz) {
                    _ = try decodeOperand(a, toks, &p);
                } else if (op == .sample_d) {
                    _ = try decodeOperand(a, toks, &p);
                    _ = try decodeOperand(a, toks, &p);
                } else if (op == .sample_b) {
                    const bias = try decodeOperand(a, toks, &p);
                    extra_e = try formatSrc(a, &bias, 1, .f, stage);
                }
                const cname = if (stage == .pixel) "ptex" else "vtex";
                const call_expr = if (op == .ld) blk: {
                    const cexpr = try formatSrc(a, &coord, 3, .i, stage);
                    const lod_e = try formatSrc(a, &coord, 8, .i, stage);
                    break :blk try std.fmt.allocPrint(a, "texelFetch({s}{d}, {s}, {s})", .{ cname, reg, cexpr, lod_e });
                } else if (op == .sample_l) blk: {
                    const cexpr = try formatSrc(a, &coord, cmask, .f, stage);
                    break :blk try std.fmt.allocPrint(a, "textureLod({s}{d}, {s}, {s})", .{ cname, reg, cexpr, extra_e });
                } else if (op == .sample_b) blk: {
                    const cexpr = try formatSrc(a, &coord, cmask, .f, stage);
                    break :blk try std.fmt.allocPrint(a, "texture({s}{d}, {s}, {s})", .{ cname, reg, cexpr, extra_e });
                } else blk: {
                    const cexpr = try formatSrc(a, &coord, cmask, .f, stage);
                    break :blk try std.fmt.allocPrint(a, "texture({s}{d}, {s})", .{ cname, reg, cexpr });
                };
                var swbuf: [5]u8 = undefined;
                const sw = swzForMask(res.swz, dst.mask, &swbuf);
                try assignDst(a, &body, &dst, try std.fmt.allocPrint(a, "{s}.{s}", .{ call_expr, sw }), .f, stage);
            },
            .discard => {
                const c0 = try decodeOperand(a, toks, &p);
                const ce = try formatSrc(a, &c0, 1, .u, stage);
                const cmp = if (bool_nz) "!= 0u" else "== 0u";
                try appendFmt(&body, a, "    if ({s} {s}) discard;\n", .{ ce, cmp });
            },
            .@"if" => {
                const c0 = try decodeOperand(a, toks, &p);
                const ce = try formatSrc(a, &c0, 1, .u, stage);
                const cmp = if (bool_nz) "!= 0u" else "== 0u";
                try appendFmt(&body, a, "    if ({s} {s}) {{\n", .{ ce, cmp });
            },
            .@"else" => try body.appendSlice(a, "    } else {\n"),
            .endif => try body.appendSlice(a, "    }\n"),
            .loop => try body.appendSlice(a, "    while (true) {\n"),
            .endloop => try body.appendSlice(a, "    }\n"),
            .@"break" => try body.appendSlice(a, "    break;\n"),
            .breakc => {
                const c0 = try decodeOperand(a, toks, &p);
                const ce = try formatSrc(a, &c0, 1, .u, stage);
                const cmp = if (bool_nz) "!= 0u" else "== 0u";
                try appendFmt(&body, a, "    if ({s} {s}) break;\n", .{ ce, cmp });
            },
            .@"continue" => try body.appendSlice(a, "    continue;\n"),
            .continuec => {
                const c0 = try decodeOperand(a, toks, &p);
                const ce = try formatSrc(a, &c0, 1, .u, stage);
                const cmp = if (bool_nz) "!= 0u" else "== 0u";
                try appendFmt(&body, a, "    if ({s} {s}) continue;\n", .{ ce, cmp });
            },
            .@"switch" => {
                const s0 = try decodeOperand(a, toks, &p);
                const se = try formatSrc(a, &s0, 1, .i, stage);
                try appendFmt(&body, a, "    switch ({s}) {{\n", .{se});
            },
            .case => {
                const c0 = try decodeOperand(a, toks, &p);
                const ce = try formatSrc(a, &c0, 1, .i, stage);
                try appendFmt(&body, a, "    case {s}:\n", .{ce});
            },
            .default => try body.appendSlice(a, "    default:\n"),
            .endswitch => try body.appendSlice(a, "    }\n"),
            else => {
                // An unhandled opcode is silently dropped from the GLSL, so the
                // draw renders wrong with no error: report each one once.
                const code: u16 = @intFromEnum(op);
                const bit = @as(u64, 1) << @intCast(code & 63);
                const slot = &unhandled_seen[@min(code >> 6, unhandled_seen.len - 1)];
                if (slot.* & bit == 0 or std.c.getenv("WINS_TRACE") != null) {
                    slot.* |= bit;
                    std.debug.print("[WINS:DXBC] unhandled opcode {d} ({s} shader)\n", .{ code, @tagName(stage) });
                }
            },
        }
    }
    var hdr: std.ArrayList(u8) = .empty;
    try hdr.appendSlice(a, "#version 420 core\n");
    const prefix = if (stage == .pixel) "p" else "v";
    const cb_base: u32 = if (stage == .pixel) 16 else 0;
    for (0..16) |i| {
        if ((cb_mask & (@as(u16, 1) << @intCast(i))) != 0) {
            const sz = @max(@as(u32, 1), @min(@as(u32, 4096), cb_sizes[i]));
            try appendFmt(&hdr, a, "layout(std140, binding = {d}) uniform {s}cb{d}Block {{ vec4 {s}cb{d}[{d}]; }};\n", .{
                cb_base + i, prefix, i, prefix, i, sz,
            });
        }
    }

    if (icb_vals) |vals| {
        const n4 = vals.len / 4;
        if (n4 > 0) {
            try appendFmt(&hdr, a, "const vec4 {s}icb[{d}] = vec4[](", .{ prefix, n4 });
            for (0..n4) |i| {
                if (i > 0) try hdr.appendSlice(a, ", ");
                try appendFmt(&hdr, a, "vec4({s}, {s}, {s}, {s})", .{
                    try formatFloatBits(a, vals[i * 4], .f),
                    try formatFloatBits(a, vals[i * 4 + 1], .f),
                    try formatFloatBits(a, vals[i * 4 + 2], .f),
                    try formatFloatBits(a, vals[i * 4 + 3], .f),
                });
            }
            try hdr.appendSlice(a, ");\n");
        }
    }

    var tlist: std.ArrayList(TexBinding) = .empty;
    const tex_base: u32 = if (stage == .pixel) 0 else 16;
    for (0..16) |i| {
        if (tex_dims[i] != .none) {
            const stype = switch (tex_dims[i]) {
                .cube => "samplerCube",
                .tex3d => "sampler3D",
                .tex1d => "sampler1D",
                .tex2d_array => "sampler2DArray",
                else => "sampler2D",
            };
            try appendFmt(&hdr, a, "layout(binding = {d}) uniform {s} {s}tex{d};\n", .{
                tex_base + i, stype, prefix, i,
            });
            try tlist.append(gpa, .{ .reg = @intCast(i), .dim = tex_dims[i] });
        }
    }

    // A DXBC signature may pack several elements into one register (TEXCOORD0.xy +
    // TEXCOORD1.zw in o3); GLSL gets exactly one vec4 per register.
    var in_seen: u64 = 0;
    var out_seen: u64 = 0;
    if (stage == .vertex) {
        for (inputs) |in_e| {
            if (!firstUseOfReg(&in_seen, in_e.reg)) continue;
            try appendFmt(&hdr, a, "layout(location = {d}) in vec4 vi{d};\n", .{ in_e.reg, in_e.reg });
        }
        for (outputs) |out_e| {
            if (!firstUseOfReg(&out_seen, out_e.reg)) continue;
            try appendFmt(&hdr, a, "layout(location = {d}) out vec4 vo{d};\n", .{ out_e.reg, out_e.reg });
        }
    } else {
        for (inputs) |in_e| {
            if (!firstUseOfReg(&in_seen, in_e.reg)) continue;
            if (sv_pos_in_reg != null and sv_pos_in_reg.? == in_e.reg) {
                try appendFmt(&hdr, a, "vec4 vi{d};\n", .{in_e.reg});
            } else {
                var loc: u32 = in_e.reg;
                if (vs_outputs) |vouts| {
                    for (vouts) |vo| {
                        if (vo.index == in_e.index and std.ascii.eqlIgnoreCase(vo.name, in_e.name)) {
                            loc = vo.reg;
                            break;
                        }
                    }
                }
                try appendFmt(&hdr, a, "layout(location = {d}) in vec4 vi{d};\n", .{ loc, in_e.reg });
            }
        }
        for (outputs) |out_e| {
            if (!firstUseOfReg(&out_seen, out_e.reg)) continue;
            try appendFmt(&hdr, a, "layout(location = {d}) out vec4 vo{d};\n", .{ out_e.reg, out_e.reg });
        }
    }

    try hdr.appendSlice(a, "void main() {\n");
    if (n_temps > 0) {
        try appendFmt(&hdr, a, "    vec4 r[{d}];\n", .{n_temps});
    }
    for (0..8) |i| {
        if (idx_temp_sizes[i] > 0) {
            try appendFmt(&hdr, a, "    vec4 x{d}[{d}];\n", .{ i, idx_temp_sizes[i] });
        }
    }
    if (stage == .pixel) {
        if (sv_pos_in_reg) |r| {
            try appendFmt(&hdr, a, "    vi{d} = gl_FragCoord;\n", .{r});
        }
    }
    try hdr.appendSlice(a, "    vec4 dummyNull;\n    float oDepth;\n");
    try hdr.appendSlice(a, body.items);
    try hdr.appendSlice(a, "}\n");

    const glsl_z = try gpa.allocSentinel(u8, hdr.items.len, 0);
    @memcpy(glsl_z, hdr.items);
    return .{
        .glsl = glsl_z,
        .stage = stage,
        .inputs = inputs,
        .outputs = outputs,
        .cb_mask = cb_mask,
        .tex_bindings = try tlist.toOwnedSlice(gpa),
    };
}

test "translate minimal SM4 vertex DXBC to GLSL 420 core" {
    // Build minimal DXBC with ISGN (1 elem), OSGN (1 SV_Position elem), and SHDR (mov o0, v0; ret)
    var buf: [256]u8 = [_]u8{0} ** 256;
    @memcpy(buf[0..4], "DXBC");
    std.mem.writeInt(u32, buf[20..24], 1, .little);
    std.mem.writeInt(u32, buf[28..32], 3, .little); // 3 chunks
    // Chunk 0: ISGN at 44 (size 8+24+8 = 40)
    const isgn_off: usize = 44;
    std.mem.writeInt(u32, buf[32..36], isgn_off, .little);
    @memcpy(buf[isgn_off..][0..4], "ISGN");
    std.mem.writeInt(u32, buf[isgn_off + 4 ..][0..4], 40, .little);
    std.mem.writeInt(u32, buf[isgn_off + 8 ..][0..4], 1, .little);
    std.mem.writeInt(u32, buf[isgn_off + 12 ..][0..4], 8, .little);
    std.mem.writeInt(u32, buf[isgn_off + 16 ..][0..4], 32, .little); // name_off = 32
    std.mem.writeInt(u32, buf[isgn_off + 28 ..][0..4], 3, .little); // float
    buf[isgn_off + 36] = 0xF;
    @memcpy(buf[isgn_off + 40 ..][0..8], "POSITION");
    buf[isgn_off + 47] = 0;

    // Chunk 1: OSGN at 92 (size 48)
    const osgn_off: usize = 92;
    std.mem.writeInt(u32, buf[36..40], osgn_off, .little);
    @memcpy(buf[osgn_off..][0..4], "OSGN");
    std.mem.writeInt(u32, buf[osgn_off + 4 ..][0..4], 44, .little);
    std.mem.writeInt(u32, buf[osgn_off + 8 ..][0..4], 1, .little);
    std.mem.writeInt(u32, buf[osgn_off + 12 ..][0..4], 8, .little);
    std.mem.writeInt(u32, buf[osgn_off + 16 ..][0..4], 32, .little);
    std.mem.writeInt(u32, buf[osgn_off + 24 ..][0..4], 1, .little); // SV_Position
    std.mem.writeInt(u32, buf[osgn_off + 28 ..][0..4], 3, .little);
    buf[osgn_off + 36] = 0xF;
    @memcpy(buf[osgn_off + 40 ..][0..12], "SV_Position\x00");

    // Chunk 2: SHDR at 144: ver=VS4.0(0x00010040), len=8 dwords
    const shdr_off: usize = 144;
    std.mem.writeInt(u32, buf[40..44], shdr_off, .little);
    @memcpy(buf[shdr_off..][0..4], "SHDR");
    std.mem.writeInt(u32, buf[shdr_off + 4 ..][0..4], 32, .little);
    std.mem.writeInt(u32, buf[shdr_off + 8 ..][0..4], 0x00010040, .little);
    std.mem.writeInt(u32, buf[shdr_off + 12 ..][0..4], 8, .little);
    // mov (54=0x36), len=5: op_len=5 -> (5<<24)|0x36
    std.mem.writeInt(u32, buf[shdr_off + 16 ..][0..4], (5 << 24) | 0x36, .little);
    // dst o0.xyzw: num_comps=2, sel_mode=0 (mask=0xF<<4), op_type=2 (output<<12), index_dim=1 (1<<20)
    std.mem.writeInt(u32, buf[shdr_off + 20 ..][0..4], 2 | (0xF << 4) | (2 << 12) | (1 << 20), .little);
    std.mem.writeInt(u32, buf[shdr_off + 24 ..][0..4], 0, .little);
    // src v0.xyzw: num_comps=2, sel_mode=1 (swz=0xE4<<4), op_type=1 (input<<12), index_dim=1 (1<<20)
    std.mem.writeInt(u32, buf[shdr_off + 28 ..][0..4], 2 | (1 << 2) | (0xE4 << 4) | (1 << 12) | (1 << 20), .little);
    std.mem.writeInt(u32, buf[shdr_off + 32 ..][0..4], 0, .little);
    // ret (62=0x3e), len=1
    std.mem.writeInt(u32, buf[shdr_off + 36 ..][0..4], (1 << 24) | 0x3e, .little);

    var tr = try translate(std.testing.allocator, buf[0 .. shdr_off + 40]);
    defer tr.deinit(std.testing.allocator);
    try std.testing.expect(std.mem.indexOf(u8, tr.glsl, "vo0.xyzw = vi0.xyzw;") != null);
    try std.testing.expect(std.mem.indexOf(u8, tr.glsl, "gl_Position = vo0;") != null);
}

/// True the first time `reg` is seen (registers >= 64 are always emitted).
fn firstUseOfReg(seen: *u64, reg: anytype) bool {
    const r: u32 = @intCast(reg);
    if (r >= 64) return true;
    const bit = @as(u64, 1) << @intCast(r);
    if (seen.* & bit != 0) return false;
    seen.* |= bit;
    return true;
}

test "packed signature registers get one declaration" {
    var seen: u64 = 0;
    try std.testing.expect(firstUseOfReg(&seen, @as(u32, 3)));
    try std.testing.expect(!firstUseOfReg(&seen, @as(u32, 3)));
    try std.testing.expect(firstUseOfReg(&seen, @as(u32, 4)));
}
