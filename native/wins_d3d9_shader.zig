//! Direct3D 9 shader bytecode -> GLSL 1.20.
//!
//! The guest hands IDirect3DDevice9 compiled shader token streams (vs_1_1 ..
//! vs_3_0, ps_2_0 .. ps_3_0). The host GPU is driven through OpenGL, so each
//! stream is rewritten as a GLSL shader with the same register semantics:
//!
//!   * every D3D register is a vec4; write masks and swizzles are kept as they
//!     are in the bytecode;
//!   * vertex outputs and pixel inputs are linked by semantic, `var_<usage>_<n>`
//!     (shader model 1/2 registers oDn/oTn/vn/tn have fixed semantics
//!     COLORn/TEXCOORDn, shader model 3 states them with dcl);
//!   * float constants are `vs_c[]` / `ps_c[]` uniforms, except the ones the
//!     shader defines itself with `def`.
//!
//! Anything this translator does not implement is an error, never a guess: the
//! caller reports the shader and skips the draw.

const std = @import("std");

pub const Error = error{ Unsupported, Malformed, OutOfMemory };

pub const Usage = struct { usage: u8, index: u8 };

pub const Input = struct { reg: u16, usage: u8, index: u8 };

pub const SamplerKind = enum(u8) { none = 0, tex2d = 2, cube = 3, volume = 4 };

pub const Translated = struct {
    glsl: [:0]u8,
    is_pixel: bool,
    major: u8,
    minor: u8,
    /// Vertex shaders: the attributes, one per declared input register. The
    /// attribute is named `v<reg>` and is meant to be bound at location `reg`.
    inputs: []Input,
    /// Pixel shaders: the varyings read; a vertex shader paired with this pixel
    /// shader has to declare (and so define) all of them.
    varyings_in: []Usage,
    /// Sampler registers used and what they sample.
    samplers: [16]SamplerKind,
    /// Number of float constant registers the shader may read (0 = none).
    const_count: u16,
    /// What stopped the translation, when it failed (static string).
    pub fn deinit(self: *Translated, a: std.mem.Allocator) void {
        a.free(self.glsl);
        a.free(self.inputs);
        a.free(self.varyings_in);
    }
};

/// Set when translate() fails: a short reason for the log.
pub var last_error: []const u8 = "";

// Register types (d3d9types.h D3DSHADER_PARAM_REGISTER_TYPE).
const RT_TEMP = 0;
const RT_INPUT = 1;
const RT_CONST = 2;
const RT_ADDR_OR_TEXTURE = 3;
const RT_RASTOUT = 4;
const RT_ATTROUT = 5;
const RT_OUTPUT = 6; // TEXCRDOUT before shader model 3
const RT_CONSTINT = 7;
const RT_COLOROUT = 8;
const RT_DEPTHOUT = 9;
const RT_SAMPLER = 10;
const RT_CONSTBOOL = 14;
const RT_LOOP = 15;
const RT_MISC = 17;

const USAGE_POSITION = 0;
const USAGE_PSIZE = 4;
const USAGE_TEXCOORD = 5;
const USAGE_COLOR = 10;
const USAGE_FOG = 11;

const Op = enum(u16) {
    nop = 0, mov = 1, add = 2, sub = 3, mad = 4, mul = 5, rcp = 6, rsq = 7, dp3 = 8, dp4 = 9,
    min = 10, max = 11, slt = 12, sge = 13, exp = 14, log = 15, lit = 16, dst = 17, lrp = 18, frc = 19,
    m4x4 = 20, m4x3 = 21, m3x4 = 22, m3x3 = 23, m3x2 = 24, call = 25, callnz = 26, loop = 27, ret = 28,
    endloop = 29, label = 30, dcl = 31, pow = 32, crs = 33, sgn = 34, abs = 35, nrm = 36, sincos = 37,
    rep = 38, endrep = 39, @"if" = 40, ifc = 41, @"else" = 42, endif = 43, @"break" = 44, breakc = 45,
    mova = 46, defb = 47, defi = 48, texkill = 65, texld = 66, expp = 78, logp = 79, cnd = 80, def = 81,
    cmp = 88, dp2add = 90, dsx = 91, dsy = 92, texldd = 93, setp = 94, texldl = 95, breakp = 96,
    _,
};

/// Parameter tokens of an instruction in shader model 1 (later models carry
/// the length in the instruction token).
fn sm1Length(op: Op) ?u32 {
    return switch (op) {
        .nop => 0,
        .mov, .rcp, .rsq, .exp, .log, .lit, .frc, .expp, .logp, .dcl => 2,
        .add, .sub, .mul, .dp3, .dp4, .min, .max, .slt, .sge, .dst, .m4x4, .m4x3, .m3x4, .m3x3, .m3x2 => 3,
        .mad => 4,
        .def => 5,
        else => null,
    };
}

const Src = struct {
    rtype: u8,
    num: u16,
    swz: [4]u2,
    mod: u8,
    rel: bool = false,
    rel_type: u8 = 0,
    rel_num: u16 = 0,
    rel_comp: u2 = 0,
};

const Dst = struct {
    rtype: u8,
    num: u16,
    mask: u4,
    saturate: bool,
};

fn regType(tok: u32) u8 {
    return @intCast(((tok >> 28) & 7) | ((tok >> 8) & 0x18));
}

const Ctx = struct {
    arena: std.mem.Allocator,
    tokens: []const u32,
    is_pixel: bool,
    major: u8,
    minor: u8,
    out: std.ArrayList(u8) = .empty,
    body: std.ArrayList(u8) = .empty,
    indent: u32 = 1,
    temps: [32]bool = [_]bool{false} ** 32,
    def_f: [256]bool = [_]bool{false} ** 256,
    def_f_val: [256][4]f32 = undefined,
    def_i: [16]bool = [_]bool{false} ** 16,
    def_i_val: [16][4]i32 = undefined,
    def_b: [16]bool = [_]bool{false} ** 16,
    def_b_val: [16]bool = [_]bool{false} ** 16,
    const_max: u16 = 0,
    const_rel: bool = false,
    int_used: bool = false,
    bool_used: bool = false,
    samplers: [16]SamplerKind = [_]SamplerKind{.none} ** 16,
    sampler_used: [16]bool = [_]bool{false} ** 16,
    /// Shader model 3 vertex outputs / pixel inputs: register -> semantic.
    out_sem: [16]?Usage = [_]?Usage{null} ** 16,
    in_sem: [16]?Usage = [_]?Usage{null} ** 16,
    inputs: std.ArrayList(Input) = .empty,
    /// Varyings written (vertex) or read (pixel).
    varyings: std.ArrayList(Usage) = .empty,
    color_out: [4]bool = [_]bool{false} ** 4,
    uses_opos: bool = false,
    uses_fog: bool = false,
    uses_psize: bool = false,
    uses_depth: bool = false,
    uses_a0: bool = false,
    uses_al: bool = false,
    loop_depth: u32 = 0,

    fn fail(_: *Ctx, comptime why: []const u8) Error {
        last_error = why;
        return error.Unsupported;
    }

    fn emit(self: *Ctx, comptime f: []const u8, args: anytype) Error!void {
        const s = std.fmt.allocPrint(self.arena, f, args) catch return error.OutOfMemory;
        var i: u32 = 0;
        while (i < self.indent) : (i += 1) self.body.appendSlice(self.arena, "    ") catch return error.OutOfMemory;
        self.body.appendSlice(self.arena, s) catch return error.OutOfMemory;
        self.body.append(self.arena, '\n') catch return error.OutOfMemory;
    }

    fn head(self: *Ctx, comptime f: []const u8, args: anytype) Error!void {
        const s = std.fmt.allocPrint(self.arena, f, args) catch return error.OutOfMemory;
        self.out.appendSlice(self.arena, s) catch return error.OutOfMemory;
    }

    fn fmt(self: *Ctx, comptime f: []const u8, args: anytype) Error![]const u8 {
        return std.fmt.allocPrint(self.arena, f, args) catch error.OutOfMemory;
    }

    fn noteVarying(self: *Ctx, u: Usage) Error!void {
        for (self.varyings.items) |v| {
            if (v.usage == u.usage and v.index == u.index) return;
        }
        self.varyings.append(self.arena, u) catch return error.OutOfMemory;
    }

    fn parseSrc(self: *Ctx, pos: *usize) Error!Src {
        if (pos.* >= self.tokens.len) return error.Malformed;
        const t = self.tokens[pos.*];
        pos.* += 1;
        var s: Src = .{
            .rtype = regType(t),
            .num = @intCast(t & 0x7FF),
            .swz = .{ @intCast((t >> 16) & 3), @intCast((t >> 18) & 3), @intCast((t >> 20) & 3), @intCast((t >> 22) & 3) },
            .mod = @intCast((t >> 24) & 0xF),
        };
        if ((t & 0x2000) != 0) {
            s.rel = true;
            if (self.major >= 2) {
                if (pos.* >= self.tokens.len) return error.Malformed;
                const r = self.tokens[pos.*];
                pos.* += 1;
                s.rel_type = regType(r);
                s.rel_num = @intCast(r & 0x7FF);
                s.rel_comp = @intCast((r >> 16) & 3);
            } else {
                s.rel_type = RT_ADDR_OR_TEXTURE;
                s.rel_num = 0;
                s.rel_comp = 0;
            }
        }
        return s;
    }

    fn parseDst(self: *Ctx, pos: *usize) Error!Dst {
        if (pos.* >= self.tokens.len) return error.Malformed;
        const t = self.tokens[pos.*];
        pos.* += 1;
        if ((t & 0x2000) != 0) return self.fail("relative addressing on a destination register");
        if (((t >> 24) & 0xF) != 0) return self.fail("destination shift (ps_1_x)");
        return .{
            .rtype = regType(t),
            .num = @intCast(t & 0x7FF),
            .mask = @intCast((t >> 16) & 0xF),
            .saturate = (t & 0x00100000) != 0,
        };
    }

    /// GLSL lvalue/rvalue name of a register, without swizzle.
    fn regName(self: *Ctx, rtype: u8, num: u16, writing: bool) Error![]const u8 {
        switch (rtype) {
            RT_TEMP => {
                if (num >= 32) return self.fail("temporary register above r31");
                self.temps[num] = true;
                return self.fmt("r{d}", .{num});
            },
            RT_INPUT => {
                if (!self.is_pixel) return self.fmt("v{d}", .{num});
                const u: Usage = if (self.major >= 3)
                    (if (num < 16) self.in_sem[num] else null) orelse return self.fail("pixel input register without dcl")
                else
                    .{ .usage = USAGE_COLOR, .index = @intCast(num) };
                try self.noteVarying(u);
                return self.fmt("var_{d}_{d}", .{ u.usage, u.index });
            },
            RT_CONST => {
                if (num >= 256) return self.fail("float constant above c255");
                if (self.def_f[num]) return self.fmt("lc{d}", .{num});
                if (num + 1 > self.const_max) self.const_max = num + 1;
                return self.fmt("{s}_c[{d}]", .{ if (self.is_pixel) "ps" else "vs", num });
            },
            RT_ADDR_OR_TEXTURE => {
                if (self.is_pixel) {
                    const u: Usage = .{ .usage = USAGE_TEXCOORD, .index = @intCast(num) };
                    try self.noteVarying(u);
                    return self.fmt("var_{d}_{d}", .{ u.usage, u.index });
                }
                self.uses_a0 = true;
                return "a0";
            },
            RT_RASTOUT => switch (num) {
                0 => {
                    self.uses_opos = true;
                    return "oPos";
                },
                1 => {
                    self.uses_fog = true;
                    return "oFog";
                },
                2 => {
                    self.uses_psize = true;
                    return "oPts";
                },
                else => return self.fail("unknown rasterizer output register"),
            },
            RT_ATTROUT => {
                const u: Usage = .{ .usage = USAGE_COLOR, .index = @intCast(num) };
                try self.noteVarying(u);
                return self.fmt("var_{d}_{d}", .{ u.usage, u.index });
            },
            RT_OUTPUT => {
                if (self.is_pixel) return self.fail("output register in a pixel shader");
                if (self.major < 3) {
                    const u: Usage = .{ .usage = USAGE_TEXCOORD, .index = @intCast(num) };
                    try self.noteVarying(u);
                    return self.fmt("var_{d}_{d}", .{ u.usage, u.index });
                }
                const u = (if (num < 16) self.out_sem[num] else null) orelse return self.fail("vertex output register without dcl");
                if (u.usage == USAGE_POSITION and u.index == 0) {
                    self.uses_opos = true;
                    return "oPos";
                }
                if (u.usage == USAGE_PSIZE) {
                    self.uses_psize = true;
                    return "oPts";
                }
                if (u.usage == USAGE_FOG) {
                    self.uses_fog = true;
                    return "oFog";
                }
                try self.noteVarying(u);
                return self.fmt("var_{d}_{d}", .{ u.usage, u.index });
            },
            RT_CONSTINT => {
                if (num >= 16) return self.fail("integer constant above i15");
                if (self.def_i[num]) return self.fmt("li{d}", .{num});
                self.int_used = true;
                return self.fmt("{s}_i[{d}]", .{ if (self.is_pixel) "ps" else "vs", num });
            },
            RT_CONSTBOOL => {
                if (num >= 16) return self.fail("boolean constant above b15");
                if (self.def_b[num]) return if (self.def_b_val[num]) "true" else "false";
                self.bool_used = true;
                return self.fmt("{s}_b[{d}]", .{ if (self.is_pixel) "ps" else "vs", num });
            },
            RT_COLOROUT => {
                if (num >= 4) return self.fail("colour output above oC3");
                self.color_out[num] = true;
                return self.fmt("oC{d}", .{num});
            },
            RT_DEPTHOUT => {
                self.uses_depth = true;
                return "oDepth";
            },
            RT_LOOP => {
                self.uses_al = true;
                return "aL";
            },
            RT_MISC => {
                if (writing) return self.fail("write to a misc register");
                return switch (num) {
                    0 => "vec4(floor(gl_FragCoord.xy), 0.0, 0.0)",
                    1 => "vec4(gl_FrontFacing ? 1.0 : -1.0)",
                    else => self.fail("unknown misc register"),
                };
            },
            else => return self.fail("register type not implemented"),
        }
    }

    const letters = "xyzw";

    /// A source operand restricted to the swizzle components `sel` picks.
    fn src(self: *Ctx, s: Src, sel: []const u2) Error![]const u8 {
        var base: []const u8 = undefined;
        if (s.rel) {
            if (s.rtype != RT_CONST) return self.fail("relative addressing on a non-constant register");
            const idx_reg = try self.regName(s.rel_type, s.rel_num, false);
            self.const_rel = true;
            base = try self.fmt("{s}_c[{d} + int({s}.{c})]", .{ if (self.is_pixel) "ps" else "vs", s.num, idx_reg, letters[s.rel_comp] });
        } else base = try self.regName(s.rtype, s.num, false);
        var swz: [4]u8 = undefined;
        for (sel, 0..) |c, i| swz[i] = letters[s.swz[c]];
        const picked = if (base[0] == 'v' and base[1] == 'e')
            try self.fmt("({s}).{s}", .{ base, swz[0..sel.len] })
        else
            try self.fmt("{s}.{s}", .{ base, swz[0..sel.len] });
        return switch (s.mod) {
            0 => picked,
            1 => self.fmt("(-{s})", .{picked}),
            11 => self.fmt("abs({s})", .{picked}),
            12 => self.fmt("(-abs({s}))", .{picked}),
            else => self.fail("source modifier not implemented"),
        };
    }

    fn maskSel(mask: u4, buf: *[4]u2) []const u2 {
        var n: usize = 0;
        var i: u3 = 0;
        while (i < 4) : (i += 1) {
            if ((mask >> @intCast(i)) & 1 != 0) {
                buf[n] = @intCast(i);
                n += 1;
            }
        }
        return buf[0..n];
    }

    fn vecType(n: usize) []const u8 {
        return switch (n) {
            1 => "float",
            2 => "vec2",
            3 => "vec3",
            else => "vec4",
        };
    }

    /// `dst.mask = expr;` where expr already has as many components as the mask.
    fn assign(self: *Ctx, d: Dst, expr: []const u8) Error!void {
        const name = try self.regName(d.rtype, d.num, true);
        var buf: [4]u2 = undefined;
        const sel = maskSel(d.mask, &buf);
        if (sel.len == 0) return;
        var m: [4]u8 = undefined;
        for (sel, 0..) |c, i| m[i] = letters[c];
        if (d.saturate) {
            try self.emit("{s}.{s} = clamp({s}, 0.0, 1.0);", .{ name, m[0..sel.len], expr });
        } else try self.emit("{s}.{s} = {s};", .{ name, m[0..sel.len], expr });
    }

    /// `dst.mask = (vec4 expr).mask;`
    fn assignFromVec4(self: *Ctx, d: Dst, expr4: []const u8) Error!void {
        var buf: [4]u2 = undefined;
        const sel = maskSel(d.mask, &buf);
        if (sel.len == 0) return;
        var m: [4]u8 = undefined;
        for (sel, 0..) |c, i| m[i] = letters[c];
        try self.assign(d, try self.fmt("({s}).{s}", .{ expr4, m[0..sel.len] }));
    }

    /// `dst.mask = vecN(scalar);`
    fn assignScalar(self: *Ctx, d: Dst, scalar: []const u8) Error!void {
        var buf: [4]u2 = undefined;
        const n = maskSel(d.mask, &buf).len;
        if (n == 1) return self.assign(d, scalar);
        try self.assign(d, try self.fmt("{s}({s})", .{ vecType(n), scalar }));
    }

    fn cmpOp(self: *Ctx, cmp_code: u32) Error![]const u8 {
        return switch (cmp_code) {
            1 => ">",
            2 => "==",
            3 => ">=",
            4 => "<",
            5 => "!=",
            6 => "<=",
            else => self.fail("unknown comparison"),
        };
    }

    fn instruction(self: *Ctx, op: Op, tok: u32, start: usize, end: usize) Error!void {
        var p = start;
        const all: [4]u2 = .{ 0, 1, 2, 3 };
        const xyz = all[0..3];
        switch (op) {
            .nop => {},
            .dcl, .def, .defi, .defb => {}, // handled in the declaration pass
            .mov, .add, .sub, .mad, .mul, .rcp, .rsq, .min, .max, .slt, .sge, .exp, .log, .expp, .logp, .lrp, .frc, .pow, .sgn, .abs, .cmp, .dsx, .dsy, .mova => {
                const d = try self.parseDst(&p);
                var buf: [4]u2 = undefined;
                const sel = maskSel(d.mask, &buf);
                if (sel.len == 0) return;
                const vt = vecType(sel.len);
                var s: [3][]const u8 = undefined;
                var n: usize = 0;
                while (p < end and n < 3) : (n += 1) s[n] = try self.src(try self.parseSrc(&p), sel);
                const need: usize = switch (op) {
                    .mad, .lrp, .cmp => 3,
                    .add, .sub, .mul, .min, .max, .slt, .sge, .pow => 2,
                    else => 1,
                };
                if (n < need) return error.Malformed;
                const e: []const u8 = switch (op) {
                    .mov => blk: {
                        // vs_1_x writes the address register with mov: it truncates toward -inf.
                        if (d.rtype == RT_ADDR_OR_TEXTURE and !self.is_pixel) break :blk try self.fmt("floor({s})", .{s[0]});
                        break :blk s[0];
                    },
                    .mova => try self.fmt("floor({s} + 0.5)", .{s[0]}),
                    .add => try self.fmt("({s} + {s})", .{ s[0], s[1] }),
                    .sub => try self.fmt("({s} - {s})", .{ s[0], s[1] }),
                    .mul => try self.fmt("({s} * {s})", .{ s[0], s[1] }),
                    .mad => try self.fmt("({s} * {s} + {s})", .{ s[0], s[1], s[2] }),
                    .rcp => try self.fmt("(1.0 / {s})", .{s[0]}),
                    .rsq => try self.fmt("inversesqrt(abs({s}))", .{s[0]}),
                    .min => try self.fmt("min({s}, {s})", .{ s[0], s[1] }),
                    .max => try self.fmt("max({s}, {s})", .{ s[0], s[1] }),
                    .slt => if (sel.len == 1) try self.fmt("float({s} < {s})", .{ s[0], s[1] }) else try self.fmt("{s}(lessThan({s}, {s}))", .{ vt, s[0], s[1] }),
                    .sge => if (sel.len == 1) try self.fmt("float({s} >= {s})", .{ s[0], s[1] }) else try self.fmt("{s}(greaterThanEqual({s}, {s}))", .{ vt, s[0], s[1] }),
                    .exp, .expp => try self.fmt("exp2({s})", .{s[0]}),
                    .log, .logp => try self.fmt("log2(abs({s}))", .{s[0]}),
                    .lrp => try self.fmt("mix({s}, {s}, {s})", .{ s[2], s[1], s[0] }),
                    .frc => try self.fmt("fract({s})", .{s[0]}),
                    .pow => try self.fmt("pow(abs({s}), {s})", .{ s[0], s[1] }),
                    .sgn => try self.fmt("sign({s})", .{s[0]}),
                    .abs => try self.fmt("abs({s})", .{s[0]}),
                    .cmp => if (sel.len == 1)
                        try self.fmt("({s} >= 0.0 ? {s} : {s})", .{ s[0], s[1], s[2] })
                    else
                        try self.fmt("mix({s}, {s}, {s}(greaterThanEqual({s}, {s}(0.0))))", .{ s[2], s[1], vt, s[0], vt }),
                    .dsx => try self.fmt("dFdx({s})", .{s[0]}),
                    .dsy => try self.fmt("dFdy({s})", .{s[0]}),
                    else => unreachable,
                };
                try self.assign(d, e);
            },
            .dp3, .dp4 => {
                const d = try self.parseDst(&p);
                const sel: []const u2 = if (op == .dp3) xyz else all[0..4];
                const a = try self.src(try self.parseSrc(&p), sel);
                const b = try self.src(try self.parseSrc(&p), sel);
                try self.assignScalar(d, try self.fmt("dot({s}, {s})", .{ a, b }));
            },
            .dp2add => {
                const d = try self.parseDst(&p);
                const a = try self.src(try self.parseSrc(&p), all[0..2]);
                const b = try self.src(try self.parseSrc(&p), all[0..2]);
                const c = try self.src(try self.parseSrc(&p), all[0..1]);
                try self.assignScalar(d, try self.fmt("(dot({s}, {s}) + {s})", .{ a, b, c }));
            },
            .nrm => {
                const d = try self.parseDst(&p);
                const s0 = try self.parseSrc(&p);
                const v3 = try self.src(s0, xyz);
                const v4 = try self.src(s0, all[0..4]);
                // nrm scales every component, w included, by 1/|xyz|.
                try self.assignFromVec4(d, try self.fmt("({s} * inversesqrt(dot({s}, {s})))", .{ v4, v3, v3 }));
            },
            .crs => {
                const d = try self.parseDst(&p);
                const a = try self.src(try self.parseSrc(&p), xyz);
                const b = try self.src(try self.parseSrc(&p), xyz);
                try self.assignFromVec4(d, try self.fmt("vec4(cross({s}, {s}), 0.0)", .{ a, b }));
            },
            .lit => {
                const d = try self.parseDst(&p);
                const s0 = try self.parseSrc(&p);
                const x = try self.src(s0, all[0..1]);
                const y = try self.src(s0, all[1..2]);
                const w = try self.src(s0, all[3..4]);
                try self.assignFromVec4(d, try self.fmt("vec4(1.0, max({s}, 0.0), ({s} > 0.0 ? pow(max({s}, 0.0), clamp({s}, -127.9961, 127.9961)) : 0.0), 1.0)", .{ x, x, y, w }));
            },
            .dst => {
                const d = try self.parseDst(&p);
                const s0 = try self.parseSrc(&p);
                const s1 = try self.parseSrc(&p);
                try self.assignFromVec4(d, try self.fmt("vec4(1.0, {s} * {s}, {s}, {s})", .{
                    try self.src(s0, all[1..2]), try self.src(s1, all[1..2]), try self.src(s0, all[2..3]), try self.src(s1, all[3..4]),
                }));
            },
            .sincos => {
                const d = try self.parseDst(&p);
                const x = try self.src(try self.parseSrc(&p), all[0..1]);
                try self.assignFromVec4(d, try self.fmt("vec4(cos({s}), sin({s}), 0.0, 0.0)", .{ x, x }));
            },
            .m4x4, .m4x3, .m3x4, .m3x3, .m3x2 => {
                const d = try self.parseDst(&p);
                const v = try self.parseSrc(&p);
                var m = try self.parseSrc(&p);
                const rows: usize = switch (op) {
                    .m4x4, .m3x4 => 4,
                    .m4x3, .m3x3 => 3,
                    else => 2,
                };
                const sel: []const u2 = switch (op) {
                    .m4x4, .m4x3 => all[0..4],
                    else => xyz,
                };
                const vs = try self.src(v, sel);
                var parts: [4][]const u8 = .{ "0.0", "0.0", "0.0", "0.0" };
                for (0..rows) |r| {
                    parts[r] = try self.fmt("dot({s}, {s})", .{ vs, try self.src(m, sel) });
                    m.num += 1;
                }
                try self.assignFromVec4(d, try self.fmt("vec4({s}, {s}, {s}, {s})", .{ parts[0], parts[1], parts[2], parts[3] }));
            },
            .texld, .texldl, .texldd => {
                if (!self.is_pixel) return self.fail("texture sampling in a vertex shader");
                if (self.major < 2) return self.fail("ps_1_x texture instruction");
                const d = try self.parseDst(&p);
                const coord = try self.parseSrc(&p);
                const smp = try self.parseSrc(&p);
                if (smp.rtype != RT_SAMPLER or smp.num >= 16) return error.Malformed;
                self.sampler_used[smp.num] = true;
                const kind = self.samplers[smp.num];
                const flavour = (tok >> 16) & 0xFF; // 0 plain, 1 projected, 2 biased
                const c4 = try self.src(coord, all[0..4]);
                const c3 = try self.src(coord, xyz);
                const c2 = try self.src(coord, all[0..2]);
                const cw = try self.src(coord, all[3..4]);
                var call: []const u8 = undefined;
                if (op == .texldl) {
                    call = switch (kind) {
                        .cube => try self.fmt("textureCubeLod(ps_s{d}, {s}, {s})", .{ smp.num, c3, cw }),
                        .volume => try self.fmt("texture3DLod(ps_s{d}, {s}, {s})", .{ smp.num, c3, cw }),
                        else => try self.fmt("texture2DLod(ps_s{d}, {s}, {s})", .{ smp.num, c2, cw }),
                    };
                } else if (op == .texldd) {
                    const dx = try self.parseSrc(&p);
                    const dy = try self.parseSrc(&p);
                    call = switch (kind) {
                        .cube => try self.fmt("textureCubeGradARB(ps_s{d}, {s}, {s}, {s})", .{ smp.num, c3, try self.src(dx, xyz), try self.src(dy, xyz) }),
                        .volume => try self.fmt("texture3DGradARB(ps_s{d}, {s}, {s}, {s})", .{ smp.num, c3, try self.src(dx, xyz), try self.src(dy, xyz) }),
                        else => try self.fmt("texture2DGradARB(ps_s{d}, {s}, {s}, {s})", .{ smp.num, c2, try self.src(dx, all[0..2]), try self.src(dy, all[0..2]) }),
                    };
                } else switch (flavour) {
                    0 => call = switch (kind) {
                        .cube => try self.fmt("textureCube(ps_s{d}, {s})", .{ smp.num, c3 }),
                        .volume => try self.fmt("texture3D(ps_s{d}, {s})", .{ smp.num, c3 }),
                        else => try self.fmt("texture2D(ps_s{d}, {s})", .{ smp.num, c2 }),
                    },
                    1 => call = switch (kind) {
                        .cube => try self.fmt("textureCube(ps_s{d}, {s})", .{ smp.num, c3 }),
                        .volume => try self.fmt("texture3DProj(ps_s{d}, {s})", .{ smp.num, c4 }),
                        else => try self.fmt("texture2DProj(ps_s{d}, {s})", .{ smp.num, c4 }),
                    },
                    2 => call = switch (kind) {
                        .cube => try self.fmt("textureCube(ps_s{d}, {s}, {s})", .{ smp.num, c3, cw }),
                        .volume => try self.fmt("texture3D(ps_s{d}, {s}, {s})", .{ smp.num, c3, cw }),
                        else => try self.fmt("texture2D(ps_s{d}, {s}, {s})", .{ smp.num, c2, cw }),
                    },
                    else => return self.fail("unknown texld flavour"),
                }
                const sw: [4]u8 = .{ letters[smp.swz[0]], letters[smp.swz[1]], letters[smp.swz[2]], letters[smp.swz[3]] };
                try self.assignFromVec4(d, try self.fmt("{s}.{s}", .{ call, sw[0..] }));
            },
            .texkill => {
                const d = try self.parseDst(&p);
                const name = try self.regName(d.rtype, d.num, false);
                try self.emit("if (any(lessThan({s}.xyz, vec3(0.0)))) discard;", .{name});
            },
            .@"if" => {
                const s0 = try self.parseSrc(&p);
                const name = try self.regName(s0.rtype, s0.num, false);
                try self.emit("if ({s}{s}) {{", .{ if (s0.mod == 13) "!" else "", name });
                self.indent += 1;
            },
            .ifc => {
                const a = try self.src(try self.parseSrc(&p), all[0..1]);
                const b = try self.src(try self.parseSrc(&p), all[0..1]);
                try self.emit("if ({s} {s} {s}) {{", .{ a, try self.cmpOp((tok >> 16) & 7), b });
                self.indent += 1;
            },
            .@"else" => {
                if (self.indent > 1) self.indent -= 1;
                try self.emit("}} else {{", .{});
                self.indent += 1;
            },
            .endif, .endrep, .endloop => {
                if (self.indent > 1) self.indent -= 1;
                try self.emit("}}", .{});
            },
            .rep => {
                const s0 = try self.parseSrc(&p);
                const name = try self.regName(s0.rtype, s0.num, false);
                self.loop_depth += 1;
                try self.emit("for (int rep{d} = 0; rep{d} < {s}.x; rep{d}++) {{", .{ self.loop_depth, self.loop_depth, name, self.loop_depth });
                self.indent += 1;
            },
            .loop => {
                _ = try self.parseSrc(&p); // aL
                const s1 = try self.parseSrc(&p);
                const name = try self.regName(s1.rtype, s1.num, false);
                self.uses_al = true;
                self.loop_depth += 1;
                try self.emit("aL = vec4(float({s}.y)); for (int rep{d} = 0; rep{d} < {s}.x; rep{d}++, aL += vec4(float({s}.z))) {{", .{ name, self.loop_depth, self.loop_depth, name, self.loop_depth, name });
                self.indent += 1;
            },
            .@"break" => try self.emit("break;", .{}),
            .breakc => {
                const a = try self.src(try self.parseSrc(&p), all[0..1]);
                const b = try self.src(try self.parseSrc(&p), all[0..1]);
                try self.emit("if ({s} {s} {s}) break;", .{ a, try self.cmpOp((tok >> 16) & 7), b });
            },
            .call, .callnz, .label, .ret => return self.fail("subroutines (call/label/ret)"),
            .setp, .breakp => return self.fail("predicate register"),
            .cnd => return self.fail("cnd (ps_1_x)"),
            else => return self.fail("opcode not implemented"),
        }
    }

    fn declarations(self: *Ctx) Error!void {
        var pos: usize = 1;
        while (pos < self.tokens.len) {
            const tok = self.tokens[pos];
            const opcode: u16 = @intCast(tok & 0xFFFF);
            if (opcode == 0xFFFF) break;
            if (opcode == 0xFFFE) {
                pos += 1 + ((tok >> 16) & 0x7FFF);
                continue;
            }
            const op: Op = @enumFromInt(opcode);
            const len: u32 = if (self.major >= 2) (tok >> 24) & 0xF else sm1Length(op) orelse return self.fail("shader model 1 opcode not implemented");
            const start = pos + 1;
            if (start + len > self.tokens.len) return error.Malformed;
            switch (op) {
                .dcl => {
                    if (len < 2) return error.Malformed;
                    const info = self.tokens[start];
                    const reg = self.tokens[start + 1];
                    const rt = regType(reg);
                    const num: u16 = @intCast(reg & 0x7FF);
                    const u: Usage = .{ .usage = @intCast(info & 0x1F), .index = @intCast((info >> 16) & 0xF) };
                    if (rt == RT_SAMPLER) {
                        if (num >= 16) return error.Malformed;
                        self.samplers[num] = switch ((info >> 27) & 0xF) {
                            2 => .tex2d,
                            3 => .cube,
                            4 => .volume,
                            else => return self.fail("unknown sampler type"),
                        };
                    } else if (rt == RT_INPUT and !self.is_pixel) {
                        self.inputs.append(self.arena, .{ .reg = num, .usage = u.usage, .index = u.index }) catch return error.OutOfMemory;
                    } else if (rt == RT_INPUT and self.is_pixel and self.major >= 3) {
                        if (num < 16) self.in_sem[num] = u;
                    } else if (rt == RT_OUTPUT and !self.is_pixel and self.major >= 3) {
                        if (num < 16) self.out_sem[num] = u;
                    }
                },
                .def => {
                    if (len < 5) return error.Malformed;
                    const num = self.tokens[start] & 0x7FF;
                    if (num >= 256) return error.Malformed;
                    self.def_f[num] = true;
                    for (0..4) |i| self.def_f_val[num][i] = @bitCast(self.tokens[start + 1 + i]);
                },
                .defi => {
                    if (len < 5) return error.Malformed;
                    const num = self.tokens[start] & 0x7FF;
                    if (num >= 16) return error.Malformed;
                    self.def_i[num] = true;
                    for (0..4) |i| self.def_i_val[num][i] = @bitCast(self.tokens[start + 1 + i]);
                },
                .defb => {
                    if (len < 2) return error.Malformed;
                    const num = self.tokens[start] & 0x7FF;
                    if (num >= 16) return error.Malformed;
                    self.def_b[num] = true;
                    self.def_b_val[num] = self.tokens[start + 1] != 0;
                },
                else => {},
            }
            pos = start + len;
        }
    }

    fn code(self: *Ctx) Error!void {
        var pos: usize = 1;
        while (pos < self.tokens.len) {
            const tok = self.tokens[pos];
            const opcode: u16 = @intCast(tok & 0xFFFF);
            if (opcode == 0xFFFF) return;
            if (opcode == 0xFFFE) {
                pos += 1 + ((tok >> 16) & 0x7FFF);
                continue;
            }
            const op: Op = @enumFromInt(opcode);
            const len: u32 = if (self.major >= 2) (tok >> 24) & 0xF else sm1Length(op) orelse return self.fail("shader model 1 opcode not implemented");
            const start = pos + 1;
            if (start + len > self.tokens.len) return error.Malformed;
            try self.instruction(op, tok, start, start + len);
            pos = start + len;
        }
        return error.Malformed; // no END token
    }
};

fn glslFloat(arena: std.mem.Allocator, v: f32) Error![]const u8 {
    if (std.math.isNan(v)) return "(0.0 / 0.0)";
    if (std.math.isInf(v)) return if (v > 0) "(1.0 / 0.0)" else "(-1.0 / 0.0)";
    // {e} always carries an exponent, so GLSL reads it as a float literal.
    return std.fmt.allocPrint(arena, "{e}", .{v}) catch error.OutOfMemory;
}

/// Translate one shader. `link_in` (vertex shaders only) lists the varyings the
/// paired pixel shader reads: they are all declared and given a value, so the
/// pair always links.
pub fn translate(a: std.mem.Allocator, tokens: []const u32, link_in: []const Usage) Error!Translated {
    last_error = "";
    if (tokens.len < 2) return error.Malformed;
    const ver = tokens[0];
    const kind = ver >> 16;
    if (kind != 0xFFFF and kind != 0xFFFE) return error.Malformed;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    var ctx: Ctx = .{
        .arena = arena_state.allocator(),
        .tokens = tokens,
        .is_pixel = kind == 0xFFFF,
        .major = @intCast((ver >> 8) & 0xFF),
        .minor = @intCast(ver & 0xFF),
    };
    if (ctx.major < 1 or ctx.major > 3) return ctx.fail("shader model outside 1..3");
    if (ctx.is_pixel and ctx.major < 2) return ctx.fail("ps_1_x shaders are not implemented");

    try ctx.declarations();
    try ctx.code();
    if (ctx.indent != 1) return error.Malformed;

    const p: []const u8 = if (ctx.is_pixel) "ps" else "vs";
    try ctx.head("#version 130\n", .{});
    if (ctx.is_pixel) try ctx.head("#extension GL_ARB_shader_texture_lod : enable\n", .{});
    const const_count: u16 = if (ctx.const_rel) (if (ctx.is_pixel) 224 else 256) else ctx.const_max;
    if (const_count != 0) try ctx.head("uniform vec4 {s}_c[{d}];\n", .{ p, const_count });
    if (ctx.int_used) try ctx.head("uniform ivec4 {s}_i[16];\n", .{p});
    if (ctx.bool_used) try ctx.head("uniform bool {s}_b[16];\n", .{p});

    if (!ctx.is_pixel) {
        try ctx.head("uniform vec2 wins_half_pixel;\n", .{});
        try ctx.head("uniform vec4 wins_clip[8];\n", .{});
        try ctx.head("uniform int wins_clip_mask;\n", .{});
        for (ctx.inputs.items) |in| try ctx.head("attribute vec4 v{d};\n", .{in.reg});
        // Declare the union of what this shader writes and what the pixel shader reads.
        for (link_in) |u| try ctx.noteVarying(u);
    }
    for (ctx.varyings.items) |u| try ctx.head("varying vec4 var_{d}_{d};\n", .{ u.usage, u.index });
    if (ctx.is_pixel) {
        for (ctx.sampler_used, 0..) |used, i| {
            if (!used) continue;
            try ctx.head("uniform {s} ps_s{d};\n", .{ switch (ctx.samplers[i]) {
                .cube => "samplerCube",
                .volume => "sampler3D",
                else => "sampler2D",
            }, i });
        }
    }
    try ctx.head("void main() {{\n", .{});
    for (ctx.temps, 0..) |used, i| {
        if (used) try ctx.head("    vec4 r{d} = vec4(0.0);\n", .{i});
    }
    for (ctx.def_f, 0..) |used, i| {
        if (!used) continue;
        const v = ctx.def_f_val[i];
        try ctx.head("    vec4 lc{d} = vec4({s}, {s}, {s}, {s});\n", .{
            i, try glslFloat(ctx.arena, v[0]), try glslFloat(ctx.arena, v[1]), try glslFloat(ctx.arena, v[2]), try glslFloat(ctx.arena, v[3]),
        });
    }
    for (ctx.def_i, 0..) |used, i| {
        if (!used) continue;
        const v = ctx.def_i_val[i];
        try ctx.head("    ivec4 li{d} = ivec4({d}, {d}, {d}, {d});\n", .{ i, v[0], v[1], v[2], v[3] });
    }
    if (ctx.uses_a0) try ctx.head("    vec4 a0 = vec4(0.0);\n", .{});
    if (ctx.uses_al) try ctx.head("    vec4 aL = vec4(0.0);\n", .{});
    if (!ctx.is_pixel) {
        try ctx.head("    vec4 oPos = vec4(0.0, 0.0, 0.0, 1.0);\n", .{});
        if (ctx.uses_fog) try ctx.head("    vec4 oFog = vec4(0.0);\n", .{});
        if (ctx.uses_psize) try ctx.head("    vec4 oPts = vec4(1.0);\n", .{});
        for (ctx.varyings.items) |u| {
            // An output the shader never writes still needs a value: colours
            // default to opaque white, everything else to (0, 0, 0, 1).
            if (u.usage == USAGE_COLOR) {
                try ctx.head("    var_{d}_{d} = vec4(1.0);\n", .{ u.usage, u.index });
            } else try ctx.head("    var_{d}_{d} = vec4(0.0, 0.0, 0.0, 1.0);\n", .{ u.usage, u.index });
        }
    } else {
        for (ctx.color_out, 0..) |used, i| {
            if (used) try ctx.head("    vec4 oC{d} = vec4(0.0);\n", .{i});
        }
        if (ctx.uses_depth) try ctx.head("    vec4 oDepth = vec4(0.0);\n", .{});
    }
    ctx.out.appendSlice(ctx.arena, ctx.body.items) catch return error.OutOfMemory;
    if (!ctx.is_pixel) {
        // User clip planes in programmable vertex shaders are evaluated in clip space
        // on oPos before the half-pixel screen alignment offset.
        try ctx.head(
            \\    if (wins_clip_mask != 0) {{
            \\        gl_ClipDistance[0] = dot(oPos, wins_clip[0]);
            \\        gl_ClipDistance[1] = dot(oPos, wins_clip[1]);
            \\        gl_ClipDistance[2] = dot(oPos, wins_clip[2]);
            \\        gl_ClipDistance[3] = dot(oPos, wins_clip[3]);
            \\        gl_ClipDistance[4] = dot(oPos, wins_clip[4]);
            \\        gl_ClipDistance[5] = dot(oPos, wins_clip[5]);
            \\        gl_ClipDistance[6] = dot(oPos, wins_clip[6]);
            \\        gl_ClipDistance[7] = dot(oPos, wins_clip[7]);
            \\    }}
            \\    gl_Position = oPos;
            \\    gl_Position.xy += wins_half_pixel * gl_Position.w;
            \\
        , .{});
        if (ctx.uses_psize) try ctx.head("    gl_PointSize = oPts.x;\n", .{});
    } else {
        for (ctx.color_out, 0..) |used, i| {
            if (used) try ctx.head("    gl_FragData[{d}] = oC{d};\n", .{ i, i });
        }
        if (ctx.uses_depth) try ctx.head("    gl_FragDepth = oDepth.x;\n", .{});
    }
    try ctx.head("}}\n", .{});

    const glsl = a.allocSentinel(u8, ctx.out.items.len, 0) catch return error.OutOfMemory;
    errdefer a.free(glsl);
    @memcpy(glsl, ctx.out.items);
    const inputs = a.dupe(Input, ctx.inputs.items) catch return error.OutOfMemory;
    errdefer a.free(inputs);
    const varyings: []Usage = if (ctx.is_pixel) (a.dupe(Usage, ctx.varyings.items) catch return error.OutOfMemory) else (a.alloc(Usage, 0) catch return error.OutOfMemory);
    return .{
        .glsl = glsl,
        .is_pixel = ctx.is_pixel,
        .major = ctx.major,
        .minor = ctx.minor,
        .inputs = inputs,
        .varyings_in = varyings,
        .samplers = blk: {
            var s = ctx.samplers;
            for (&s, 0..) |*k, i| {
                if (!ctx.sampler_used[i]) k.* = .none;
            }
            break :blk s;
        },
        .const_count = const_count,
    };
}

// Shaders FalloutNV binds for its menu quads (captured from the device trace,
// 2026-11-14; they are compiler output for two trivial HLSL functions).
const test_vs_menu = [_]u32{
    0xfffe0101, 0x0000001f, 0x80000000, 0x900f0000, 0x0000001f, 0x80000005, 0x900f0001,
    0x00000009, 0xc0010000, 0xa0e40000, 0x90e40000, 0x00000009, 0xc0020000, 0xa0e40001,
    0x90e40000, 0x00000009, 0xc0040000, 0xa0e40002, 0x90e40000, 0x00000009, 0xc0080000,
    0xa0e40003, 0x90e40000, 0x00000001, 0xe0030000, 0x90e40001, 0x00000001, 0xe0030001,
    0x90e40001, 0x0000ffff,
};
const test_ps_menu = [_]u32{
    0xffff0201, 0x0200001f, 0x80000000, 0xb0030000, 0x0200001f, 0x90000000, 0xa00f0800,
    0x03000042, 0x800f0000, 0xb0e40000, 0xa0e40800, 0x03000005, 0x800f0000, 0x80e40000,
    0xa0e40000, 0x02000001, 0x800f0800, 0x80e40000, 0x0000ffff,
};

test "ps_2_a tint shader: texld * c0 -> oC0, one varying, one 2D sampler" {
    var t = try translate(std.testing.allocator, &test_ps_menu, &.{});
    defer t.deinit(std.testing.allocator);
    try std.testing.expect(t.is_pixel);
    try std.testing.expectEqual(@as(usize, 1), t.varyings_in.len);
    try std.testing.expectEqual(@as(u8, USAGE_TEXCOORD), t.varyings_in[0].usage);
    try std.testing.expectEqual(SamplerKind.tex2d, t.samplers[0]);
    try std.testing.expectEqual(@as(u16, 1), t.const_count);
    try std.testing.expect(std.mem.indexOf(u8, t.glsl, "r0.xyzw = (texture2D(ps_s0, var_5_0.xy).xyzw).xyzw;") != null);
    try std.testing.expect(std.mem.indexOf(u8, t.glsl, "r0.xyzw = (r0.xyzw * ps_c[0].xyzw);") != null);
    try std.testing.expect(std.mem.indexOf(u8, t.glsl, "gl_FragData[0] = oC0;") != null);
}

test "vs_1_1 transform shader: four dp4 rows into oPos, texcoords copied, pixel varyings declared" {
    var t = try translate(std.testing.allocator, &test_vs_menu, &.{.{ .usage = USAGE_COLOR, .index = 0 }});
    defer t.deinit(std.testing.allocator);
    try std.testing.expect(!t.is_pixel);
    try std.testing.expectEqual(@as(usize, 2), t.inputs.len);
    try std.testing.expectEqual(@as(u8, USAGE_TEXCOORD), t.inputs[1].usage);
    try std.testing.expectEqual(@as(u16, 4), t.const_count);
    try std.testing.expect(std.mem.indexOf(u8, t.glsl, "oPos.x = dot(vs_c[0].xyzw, v0.xyzw);") != null);
    try std.testing.expect(std.mem.indexOf(u8, t.glsl, "oPos.w = dot(vs_c[3].xyzw, v0.xyzw);") != null);
    try std.testing.expect(std.mem.indexOf(u8, t.glsl, "var_5_1.xy = v1.xy;") != null);
    try std.testing.expect(std.mem.indexOf(u8, t.glsl, "varying vec4 var_10_0;") != null);
}

test "unsupported shaders are refused, not guessed" {
    const ps11 = [_]u32{ 0xffff0101, 0x00000042, 0xb00f0000, 0x0000ffff };
    try std.testing.expectError(error.Unsupported, translate(std.testing.allocator, &ps11, &.{}));
    const truncated = [_]u32{ 0xfffe0200, 0x02000001, 0x800f0000 };
    try std.testing.expectError(error.Malformed, translate(std.testing.allocator, &truncated, &.{}));
}

test "vertex shaders emit #version 130 clip uniforms and gl_ClipDistance assignment" {
    var t = try translate(std.testing.allocator, &test_vs_menu, &.{});
    defer t.deinit(std.testing.allocator);
    try std.testing.expect(std.mem.indexOf(u8, t.glsl, "#version 130") != null);
    try std.testing.expect(std.mem.indexOf(u8, t.glsl, "uniform vec4 wins_clip[8];") != null);
    try std.testing.expect(std.mem.indexOf(u8, t.glsl, "uniform int wins_clip_mask;") != null);
    try std.testing.expect(std.mem.indexOf(u8, t.glsl, "gl_ClipDistance[0] = dot(oPos, wins_clip[0]);") != null);
}
