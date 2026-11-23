//! ID3DBlob and ID3D11ShaderReflection for winload64, built from the DXBC
//! container a game passes in (RDEF, ISGN/ISG1, OSGN/OSG1/OSG5, SHDR/SHEX).
//!
//! Two struct layouts exist and writing the wrong one corrupts the caller:
//! D3DCompiler_43 (June 2010 SDK, IID {0A233719-...}) has no
//! D3D11_SIGNATURE_PARAMETER_DESC::MinPrecision and no D3D11_SHADER_TYPE_DESC::Name;
//! D3DCompiler_47 (IID {8D536CA1-...}) has both. The requested IID selects it.
//! Lookups that miss return a shared invalid object whose GetDesc fails with
//! E_FAIL, exactly as the Windows implementation does (never NULL).
const std = @import("std");
const W: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

const S_OK: i32 = 0;
const E_FAIL: i32 = @bitCast(@as(u32, 0x80004005));
const E_INVALIDARG: i32 = @bitCast(@as(u32, 0x80070057));
const E_NOINTERFACE: i32 = @bitCast(@as(u32, 0x80004002));
const E_OUTOFMEMORY: i32 = @bitCast(@as(u32, 0x8007000E));
const E_POINTER: i32 = @bitCast(@as(u32, 0x80004003));

const gpa = std.heap.page_allocator;

// ======================================================================== blob
const BlobVtbl = extern struct {
    QueryInterface: *const fn (*Blob, ?*const anyopaque, ?*?*anyopaque) callconv(W) i32,
    AddRef: *const fn (*Blob) callconv(W) u32,
    Release: *const fn (*Blob) callconv(W) u32,
    GetBufferPointer: *const fn (*Blob) callconv(W) [*]u8,
    GetBufferSize: *const fn (*Blob) callconv(W) usize,
};
const Blob = extern struct { vtbl: *const BlobVtbl, refs: std.atomic.Value(u32), size: usize, data: [*]u8 };
fn blobQI(self: *Blob, riid: ?*const anyopaque, out: ?*?*anyopaque) callconv(W) i32 {
    _ = riid;
    const o = out orelse return E_POINTER;
    _ = self.refs.fetchAdd(1, .monotonic);
    o.* = self;
    return S_OK;
}
fn blobAddRef(self: *Blob) callconv(W) u32 {
    return self.refs.fetchAdd(1, .monotonic) + 1;
}
fn blobRelease(self: *Blob) callconv(W) u32 {
    const left = self.refs.fetchSub(1, .acq_rel) - 1;
    if (left == 0) {
        gpa.free(self.data[0..@max(self.size, 1)]);
        gpa.destroy(self);
    }
    return left;
}
fn blobPtr(self: *Blob) callconv(W) [*]u8 {
    return self.data;
}
fn blobSize(self: *Blob) callconv(W) usize {
    return self.size;
}
const blob_vtbl = BlobVtbl{ .QueryInterface = &blobQI, .AddRef = &blobAddRef, .Release = &blobRelease, .GetBufferPointer = &blobPtr, .GetBufferSize = &blobSize };

/// D3DCreateBlob: a zero-filled buffer of `size` bytes.
pub fn createBlob(size: usize, out: ?*?*anyopaque) callconv(W) i32 {
    const o = out orelse return E_POINTER;
    o.* = null;
    const mem = gpa.alloc(u8, @max(size, 1)) catch return E_OUTOFMEMORY;
    @memset(mem, 0);
    const b = gpa.create(Blob) catch {
        gpa.free(mem);
        return E_OUTOFMEMORY;
    };
    b.* = .{ .vtbl = &blob_vtbl, .refs = .init(1), .size = size, .data = mem.ptr };
    o.* = b;
    return S_OK;
}

// ======================================================================== DXBC model
const SigParam = struct { name: [:0]const u8, index: u32, reg: u32, sv: u32, comp: u32, mask: u8, rw: u8, stream: u32, min_prec: u32 };
const Member = struct { name: [:0]const u8, ty: *TypeObj, offset: u32 };
const TypeObj = struct {
    vtbl: *const TypeVtbl = &type_vtbl,
    valid: bool = true,
    class: u16 = 0,
    kind: u16 = 0,
    rows: u16 = 0,
    cols: u16 = 0,
    elements: u16 = 0,
    offset: u32 = 0,
    name: ?[:0]const u8 = null,
    members: []Member = &.{},
    owner: ?*Refl = null,
};
const VarObj = struct {
    vtbl: *const VarVtbl = &var_vtbl,
    valid: bool = true,
    name: [:0]const u8 = "",
    start: u32 = 0,
    size: u32 = 0,
    flags: u32 = 0,
    default: ?*const anyopaque = null,
    tex_start: u32 = 0xFFFFFFFF,
    tex_size: u32 = 0,
    samp_start: u32 = 0xFFFFFFFF,
    samp_size: u32 = 0,
    ty: *TypeObj = &invalid_type,
    cb: *CbObj = &invalid_cb,
};
const CbObj = struct {
    vtbl: *const CbVtbl = &cb_vtbl,
    valid: bool = true,
    name: [:0]const u8 = "",
    kind: u32 = 0,
    size: u32 = 0,
    flags: u32 = 0,
    vars: []VarObj = &.{},
};
const Binding = struct { name: [:0]const u8, kind: u32, ret: u32, dim: u32, samples: u32, point: u32, count: u32, flags: u32 };

const Refl = struct {
    vtbl: *const ReflVtbl = &refl_vtbl,
    refs: std.atomic.Value(u32) = .init(1),
    v47: bool,
    arena: std.heap.ArenaAllocator,
    version: u32 = 0,
    creator: [:0]const u8 = "",
    flags: u32 = 0,
    cbs: []CbObj = &.{},
    binds: []Binding = &.{},
    inputs: []SigParam = &.{},
    outputs: []SigParam = &.{},
    patch: []SigParam = &.{},
    stat: [32]u32 = @splat(0),
    has_stat: bool = false,
    gs_input_prim: u32 = 0,
    tg: [3]u32 = .{ 0, 0, 0 },
};

var invalid_type: TypeObj = .{ .valid = false };
var invalid_cb: CbObj = .{ .valid = false };
var invalid_var: VarObj = .{ .valid = false };

fn rd32(b: []const u8, off: usize) ?u32 {
    if (off + 4 > b.len) return null;
    return std.mem.readInt(u32, b[off..][0..4], .little);
}
fn rd16(b: []const u8, off: usize) ?u16 {
    if (off + 2 > b.len) return null;
    return std.mem.readInt(u16, b[off..][0..2], .little);
}
fn cstrAt(b: []const u8, off: usize) ?[:0]const u8 {
    if (off >= b.len) return null;
    const end = std.mem.indexOfScalarPos(u8, b, off, 0) orelse return null;
    return b[off..end :0];
}

const ParseError = error{ Malformed, OutOfMemory };

fn findChunk(dxbc: []const u8, tags: []const *const [4]u8) ?struct { tag: [4]u8, data: []const u8 } {
    const n = rd32(dxbc, 28) orelse return null;
    if (32 + @as(usize, n) * 4 > dxbc.len) return null;
    for (0..n) |k| {
        const off = rd32(dxbc, 32 + k * 4) orelse return null;
        const len = rd32(dxbc, off + 4) orelse return null;
        if (off + 8 + len > dxbc.len) return null;
        for (tags) |t| if (std.mem.eql(u8, dxbc[off..][0..4], t))
            return .{ .tag = t.*, .data = dxbc[off + 8 ..][0..len] };
    }
    return null;
}

fn parseSig(a: std.mem.Allocator, chunk: []const u8, tag: [4]u8) ParseError![]SigParam {
    const n = rd32(chunk, 0) orelse return error.Malformed;
    const with_stream = tag[3] == '5' or tag[3] == '1';
    const with_prec = tag[3] == '1';
    const stride: usize = if (with_prec) 32 else if (with_stream) 28 else 24;
    const out = try a.alloc(SigParam, n);
    for (out, 0..) |*p, k| {
        var o: usize = 8 + k * stride;
        const stream: u32 = if (with_stream) (rd32(chunk, o) orelse return error.Malformed) else 0;
        if (with_stream) o += 4;
        p.* = .{
            .name = cstrAt(chunk, rd32(chunk, o) orelse return error.Malformed) orelse return error.Malformed,
            .index = rd32(chunk, o + 4) orelse return error.Malformed,
            .sv = rd32(chunk, o + 8) orelse return error.Malformed,
            .comp = rd32(chunk, o + 12) orelse return error.Malformed,
            .reg = rd32(chunk, o + 16) orelse return error.Malformed,
            .mask = if (o + 20 < chunk.len) chunk[o + 20] else return error.Malformed,
            .rw = if (o + 21 < chunk.len) chunk[o + 21] else return error.Malformed,
            .stream = stream,
            .min_prec = if (with_prec) (rd32(chunk, o + 24) orelse return error.Malformed) else 0,
        };
    }
    return out;
}

fn parseType(a: std.mem.Allocator, rdef: []const u8, off: usize, sm5: bool, depth: u8) ParseError!*TypeObj {
    if (depth > 16) return error.Malformed;
    const t = try a.create(TypeObj);
    t.* = .{
        .class = rd16(rdef, off) orelse return error.Malformed,
        .kind = rd16(rdef, off + 2) orelse return error.Malformed,
        .rows = rd16(rdef, off + 4) orelse return error.Malformed,
        .cols = rd16(rdef, off + 6) orelse return error.Malformed,
        .elements = rd16(rdef, off + 8) orelse return error.Malformed,
    };
    const nmem = rd16(rdef, off + 10) orelse return error.Malformed;
    const moff = rd32(rdef, off + 12) orelse return error.Malformed;
    if (sm5) if (rd32(rdef, off + 32)) |name_off| if (name_off != 0) {
        t.name = cstrAt(rdef, name_off);
    };
    if (nmem != 0) {
        const ms = try a.alloc(Member, nmem);
        for (ms, 0..) |*m, k| {
            const e = moff + k * 12;
            m.* = .{
                .name = cstrAt(rdef, rd32(rdef, e) orelse return error.Malformed) orelse return error.Malformed,
                .ty = try parseType(a, rdef, rd32(rdef, e + 4) orelse return error.Malformed, sm5, depth + 1),
                .offset = rd32(rdef, e + 8) orelse return error.Malformed,
            };
            m.ty.offset = m.offset;
        }
        t.members = ms;
    }
    return t;
}

fn parse(r: *Refl, dxbc: []const u8) ParseError!void {
    const a = r.arena.allocator();
    if (dxbc.len < 32 or !std.mem.eql(u8, dxbc[0..4], "DXBC")) return error.Malformed;
    if (findChunk(dxbc, &.{ "SHEX", "SHDR" })) |c| {
        r.version = rd32(c.data, 0) orelse 0;
        // dcl_thread_group (opcode 0x9b) for compute shaders.
        var p: usize = 8;
        while (p + 4 <= c.data.len) {
            const tok = rd32(c.data, p).?;
            const op = tok & 0x7ff;
            var len: usize = (tok >> 24) & 0x7f;
            if (op == 0x35) len = rd32(c.data, p + 4) orelse break; // customdata: length in next dword
            if (op == 0x9b and p + 16 <= c.data.len) r.tg = .{ rd32(c.data, p + 4).?, rd32(c.data, p + 8).?, rd32(c.data, p + 12).? };
            if (len == 0) break;
            p += len * 4;
        }
    }
    if (findChunk(dxbc, &.{ "ISGN", "ISG1" })) |c| r.inputs = try parseSig(a, c.data, c.tag);
    if (findChunk(dxbc, &.{ "OSGN", "OSG1", "OSG5" })) |c| r.outputs = try parseSig(a, c.data, c.tag);
    if (findChunk(dxbc, &.{ "PCSG", "PSG1" })) |c| r.patch = try parseSig(a, c.data, c.tag);
    if (findChunk(dxbc, &.{"STAT"})) |c| {
        r.has_stat = true;
        for (0..@min(r.stat.len, c.data.len / 4)) |k| r.stat[k] = rd32(c.data, k * 4).?;
    }
    const rdef = (findChunk(dxbc, &.{"RDEF"}) orelse return).data;
    const ncb = rd32(rdef, 0) orelse return error.Malformed;
    const cboff = rd32(rdef, 4) orelse return error.Malformed;
    const nrb = rd32(rdef, 8) orelse return error.Malformed;
    const rboff = rd32(rdef, 12) orelse return error.Malformed;
    const major = if (rdef.len > 17) rdef[17] else return error.Malformed;
    r.flags = rd32(rdef, 20) orelse 0;
    r.creator = cstrAt(rdef, rd32(rdef, 24) orelse 0) orelse "";
    const sm5 = major >= 5;
    const var_stride: usize = if (sm5) 40 else 24;
    r.binds = try a.alloc(Binding, nrb);
    for (r.binds, 0..) |*b, k| {
        const o = rboff + k * 32;
        b.* = .{
            .name = cstrAt(rdef, rd32(rdef, o) orelse return error.Malformed) orelse return error.Malformed,
            .kind = rd32(rdef, o + 4) orelse return error.Malformed,
            .ret = rd32(rdef, o + 8) orelse return error.Malformed,
            .dim = rd32(rdef, o + 12) orelse return error.Malformed,
            .samples = rd32(rdef, o + 16) orelse return error.Malformed,
            .point = rd32(rdef, o + 20) orelse return error.Malformed,
            .count = rd32(rdef, o + 24) orelse return error.Malformed,
            .flags = rd32(rdef, o + 28) orelse return error.Malformed,
        };
    }
    r.cbs = try a.alloc(CbObj, ncb);
    for (r.cbs, 0..) |*cb, k| {
        const o = cboff + k * 24;
        cb.* = .{
            .name = cstrAt(rdef, rd32(rdef, o) orelse return error.Malformed) orelse return error.Malformed,
            .size = rd32(rdef, o + 12) orelse return error.Malformed,
            .flags = rd32(rdef, o + 16) orelse return error.Malformed,
            .kind = rd32(rdef, o + 20) orelse return error.Malformed,
        };
        const nv = rd32(rdef, o + 4) orelse return error.Malformed;
        const voff = rd32(rdef, o + 8) orelse return error.Malformed;
        cb.vars = try a.alloc(VarObj, nv);
        for (cb.vars, 0..) |*v, j| {
            const e = voff + j * var_stride;
            const def_off = rd32(rdef, e + 20) orelse return error.Malformed;
            v.* = .{
                .name = cstrAt(rdef, rd32(rdef, e) orelse return error.Malformed) orelse return error.Malformed,
                .start = rd32(rdef, e + 4) orelse return error.Malformed,
                .size = rd32(rdef, e + 8) orelse return error.Malformed,
                .flags = rd32(rdef, e + 12) orelse return error.Malformed,
                .ty = try parseType(a, rdef, rd32(rdef, e + 16) orelse return error.Malformed, sm5, 0),
                .default = if (def_off != 0 and def_off < rdef.len) @ptrCast(rdef.ptr + def_off) else null,
                .cb = cb,
            };
            if (sm5) {
                v.tex_start = rd32(rdef, e + 24) orelse return error.Malformed;
                v.tex_size = rd32(rdef, e + 28) orelse return error.Malformed;
                v.samp_start = rd32(rdef, e + 32) orelse return error.Malformed;
                v.samp_size = rd32(rdef, e + 36) orelse return error.Malformed;
            }
        }
    }
}

// ======================================================================== COM objects
const ReflVtbl = extern struct {
    QueryInterface: *const fn (*Refl, ?*const anyopaque, ?*?*anyopaque) callconv(W) i32,
    AddRef: *const fn (*Refl) callconv(W) u32,
    Release: *const fn (*Refl) callconv(W) u32,
    GetDesc: *const fn (*Refl, ?*anyopaque) callconv(W) i32,
    GetConstantBufferByIndex: *const fn (*Refl, u32) callconv(W) *CbObj,
    GetConstantBufferByName: *const fn (*Refl, ?[*:0]const u8) callconv(W) *CbObj,
    GetResourceBindingDesc: *const fn (*Refl, u32, ?*anyopaque) callconv(W) i32,
    GetInputParameterDesc: *const fn (*Refl, u32, ?*anyopaque) callconv(W) i32,
    GetOutputParameterDesc: *const fn (*Refl, u32, ?*anyopaque) callconv(W) i32,
    GetPatchConstantParameterDesc: *const fn (*Refl, u32, ?*anyopaque) callconv(W) i32,
    GetVariableByName: *const fn (*Refl, ?[*:0]const u8) callconv(W) *VarObj,
    GetResourceBindingDescByName: *const fn (*Refl, ?[*:0]const u8, ?*anyopaque) callconv(W) i32,
    GetMovInstructionCount: *const fn (*Refl) callconv(W) u32,
    GetMovcInstructionCount: *const fn (*Refl) callconv(W) u32,
    GetConversionInstructionCount: *const fn (*Refl) callconv(W) u32,
    GetBitwiseInstructionCount: *const fn (*Refl) callconv(W) u32,
    GetGSInputPrimitive: *const fn (*Refl) callconv(W) u32,
    IsSampleFrequencyShader: *const fn (*Refl) callconv(W) i32,
    GetNumInterfaceSlots: *const fn (*Refl) callconv(W) u32,
    GetMinFeatureLevel: *const fn (*Refl, ?*u32) callconv(W) i32,
    GetThreadGroupSize: *const fn (*Refl, ?*u32, ?*u32, ?*u32) callconv(W) u32,
    GetRequiresFlags: *const fn (*Refl) callconv(W) u64,
};

fn reflQI(self: *Refl, riid: ?*const anyopaque, out: ?*?*anyopaque) callconv(W) i32 {
    const o = out orelse return E_POINTER;
    o.* = null;
    const want = if (riid) |p| @as(*align(1) const [16]u8, @ptrCast(p)).* else return E_INVALIDARG;
    if (!std.mem.eql(u8, &want, &iid_unknown) and !std.mem.eql(u8, &want, if (self.v47) &iid_refl47 else &iid_refl43)) return E_NOINTERFACE;
    _ = self.refs.fetchAdd(1, .monotonic);
    o.* = self;
    return S_OK;
}
fn reflAddRef(self: *Refl) callconv(W) u32 {
    return self.refs.fetchAdd(1, .monotonic) + 1;
}
fn reflRelease(self: *Refl) callconv(W) u32 {
    const left = self.refs.fetchSub(1, .acq_rel) - 1;
    if (left == 0) {
        self.arena.deinit();
        gpa.destroy(self);
    }
    return left;
}

fn wr(comptime T: type, base: *anyopaque, off: usize, v: T) void {
    @as(*align(1) T, @ptrFromInt(@intFromPtr(base) + off)).* = v;
}

fn reflGetDesc(self: *Refl, d: ?*anyopaque) callconv(W) i32 {
    const p = d orelse return E_INVALIDARG;
    @memset(@as([*]u8, @ptrCast(p))[0..160], 0);
    wr(u32, p, 0, self.version);
    wr(usize, p, 8, @intFromPtr(self.creator.ptr));
    wr(u32, p, 16, self.flags);
    wr(u32, p, 20, @intCast(self.cbs.len));
    wr(u32, p, 24, @intCast(self.binds.len));
    wr(u32, p, 28, @intCast(self.inputs.len));
    wr(u32, p, 32, @intCast(self.outputs.len));
    if (self.has_stat) {
        // STAT dwords in D3D11_SHADER_DESC order from InstructionCount on
        // (InstructionCount, TempRegisterCount, DefCount, DclCount, ...).
        wr(u32, p, 36, self.stat[0]); // InstructionCount
        wr(u32, p, 40, self.stat[1]); // TempRegisterCount
        wr(u32, p, 48, self.stat[2]); // DefCount
        wr(u32, p, 52, self.stat[3]); // DclCount
        wr(u32, p, 76, self.stat[4]); // FloatInstructionCount
        wr(u32, p, 80, self.stat[5]); // IntInstructionCount
        wr(u32, p, 84, self.stat[6]); // UintInstructionCount
        wr(u32, p, 88, self.stat[7]); // StaticFlowControlCount
        wr(u32, p, 92, self.stat[8]); // DynamicFlowControlCount
    }
    wr(u32, p, 124, @intCast(self.patch.len)); // PatchConstantParameters
    return S_OK;
}
fn reflCbByIndex(self: *Refl, k: u32) callconv(W) *CbObj {
    return if (k < self.cbs.len) &self.cbs[k] else &invalid_cb;
}
fn reflCbByName(self: *Refl, name: ?[*:0]const u8) callconv(W) *CbObj {
    const n = std.mem.span(name orelse return &invalid_cb);
    for (self.cbs) |*cb| if (std.mem.eql(u8, cb.name, n)) return cb;
    return &invalid_cb;
}
fn writeBind(b: Binding, d: *anyopaque) void {
    @memset(@as([*]u8, @ptrCast(d))[0..40], 0);
    wr(usize, d, 0, @intFromPtr(b.name.ptr));
    wr(u32, d, 8, b.kind);
    wr(u32, d, 12, b.point);
    wr(u32, d, 16, b.count);
    wr(u32, d, 20, b.flags);
    wr(u32, d, 24, b.ret);
    wr(u32, d, 28, b.dim);
    wr(u32, d, 32, b.samples);
}
fn reflBindDesc(self: *Refl, k: u32, d: ?*anyopaque) callconv(W) i32 {
    const p = d orelse return E_INVALIDARG;
    if (k >= self.binds.len) return E_INVALIDARG;
    writeBind(self.binds[k], p);
    return S_OK;
}
fn reflBindDescByName(self: *Refl, name: ?[*:0]const u8, d: ?*anyopaque) callconv(W) i32 {
    const p = d orelse return E_INVALIDARG;
    const n = std.mem.span(name orelse return E_INVALIDARG);
    for (self.binds) |b| if (std.mem.eql(u8, b.name, n)) {
        writeBind(b, p);
        return S_OK;
    };
    return E_INVALIDARG;
}
fn writeSig(self: *Refl, list: []const SigParam, k: u32, d: ?*anyopaque) i32 {
    const p = d orelse return E_INVALIDARG;
    if (k >= list.len) return E_INVALIDARG;
    const s = list[k];
    const size: usize = if (self.v47) 40 else 32;
    @memset(@as([*]u8, @ptrCast(p))[0..size], 0);
    wr(usize, p, 0, @intFromPtr(s.name.ptr));
    wr(u32, p, 8, s.index);
    wr(u32, p, 12, s.reg);
    wr(u32, p, 16, s.sv);
    wr(u32, p, 20, s.comp);
    wr(u8, p, 24, s.mask);
    wr(u8, p, 25, s.rw);
    wr(u32, p, 28, s.stream);
    if (self.v47) wr(u32, p, 32, s.min_prec);
    return S_OK;
}
fn reflInput(self: *Refl, k: u32, d: ?*anyopaque) callconv(W) i32 {
    return writeSig(self, self.inputs, k, d);
}
fn reflOutput(self: *Refl, k: u32, d: ?*anyopaque) callconv(W) i32 {
    return writeSig(self, self.outputs, k, d);
}
fn reflPatch(self: *Refl, k: u32, d: ?*anyopaque) callconv(W) i32 {
    return writeSig(self, self.patch, k, d);
}
fn reflVarByName(self: *Refl, name: ?[*:0]const u8) callconv(W) *VarObj {
    const n = std.mem.span(name orelse return &invalid_var);
    for (self.cbs) |*cb| for (cb.vars) |*v| if (std.mem.eql(u8, v.name, n)) return v;
    return &invalid_var;
}
fn reflZero(self: *Refl) callconv(W) u32 {
    _ = self;
    return 0;
}
fn reflGsPrim(self: *Refl) callconv(W) u32 {
    return self.gs_input_prim;
}
fn reflSampleFreq(self: *Refl) callconv(W) i32 {
    _ = self;
    return 0;
}
fn reflMinFl(self: *Refl, out: ?*u32) callconv(W) i32 {
    const o = out orelse return E_INVALIDARG;
    const major = (self.version >> 4) & 0xf;
    o.* = if (major >= 5) 0xb000 else 0xa000; // D3D_FEATURE_LEVEL_11_0 / 10_0
    return S_OK;
}
fn reflTg(self: *Refl, x: ?*u32, y: ?*u32, z: ?*u32) callconv(W) u32 {
    if (x) |p| p.* = self.tg[0];
    if (y) |p| p.* = self.tg[1];
    if (z) |p| p.* = self.tg[2];
    return self.tg[0] * self.tg[1] * self.tg[2];
}
fn reflRequires(self: *Refl) callconv(W) u64 {
    _ = self;
    return 0;
}
const refl_vtbl = ReflVtbl{
    .QueryInterface = &reflQI,
    .AddRef = &reflAddRef,
    .Release = &reflRelease,
    .GetDesc = &reflGetDesc,
    .GetConstantBufferByIndex = &reflCbByIndex,
    .GetConstantBufferByName = &reflCbByName,
    .GetResourceBindingDesc = &reflBindDesc,
    .GetInputParameterDesc = &reflInput,
    .GetOutputParameterDesc = &reflOutput,
    .GetPatchConstantParameterDesc = &reflPatch,
    .GetVariableByName = &reflVarByName,
    .GetResourceBindingDescByName = &reflBindDescByName,
    .GetMovInstructionCount = &reflZero,
    .GetMovcInstructionCount = &reflZero,
    .GetConversionInstructionCount = &reflZero,
    .GetBitwiseInstructionCount = &reflZero,
    .GetGSInputPrimitive = &reflGsPrim,
    .IsSampleFrequencyShader = &reflSampleFreq,
    .GetNumInterfaceSlots = &reflZero,
    .GetMinFeatureLevel = &reflMinFl,
    .GetThreadGroupSize = &reflTg,
    .GetRequiresFlags = &reflRequires,
};

// ---- constant buffer (no IUnknown)
const CbVtbl = extern struct {
    GetDesc: *const fn (*CbObj, ?*anyopaque) callconv(W) i32,
    GetVariableByIndex: *const fn (*CbObj, u32) callconv(W) *VarObj,
    GetVariableByName: *const fn (*CbObj, ?[*:0]const u8) callconv(W) *VarObj,
};
fn cbGetDesc(self: *CbObj, d: ?*anyopaque) callconv(W) i32 {
    if (!self.valid) return E_FAIL;
    const p = d orelse return E_INVALIDARG;
    @memset(@as([*]u8, @ptrCast(p))[0..24], 0);
    wr(usize, p, 0, @intFromPtr(self.name.ptr));
    wr(u32, p, 8, self.kind);
    wr(u32, p, 12, @intCast(self.vars.len));
    wr(u32, p, 16, self.size);
    wr(u32, p, 20, self.flags);
    return S_OK;
}
fn cbVarByIndex(self: *CbObj, k: u32) callconv(W) *VarObj {
    return if (self.valid and k < self.vars.len) &self.vars[k] else &invalid_var;
}
fn cbVarByName(self: *CbObj, name: ?[*:0]const u8) callconv(W) *VarObj {
    const n = std.mem.span(name orelse return &invalid_var);
    for (self.vars) |*v| if (std.mem.eql(u8, v.name, n)) return v;
    return &invalid_var;
}
const cb_vtbl = CbVtbl{ .GetDesc = &cbGetDesc, .GetVariableByIndex = &cbVarByIndex, .GetVariableByName = &cbVarByName };

// ---- variable (no IUnknown)
const VarVtbl = extern struct {
    GetDesc: *const fn (*VarObj, ?*anyopaque) callconv(W) i32,
    GetType: *const fn (*VarObj) callconv(W) *TypeObj,
    GetBuffer: *const fn (*VarObj) callconv(W) *CbObj,
    GetInterfaceSlot: *const fn (*VarObj, u32) callconv(W) u32,
};
fn varGetDesc(self: *VarObj, d: ?*anyopaque) callconv(W) i32 {
    if (!self.valid) return E_FAIL;
    const p = d orelse return E_INVALIDARG;
    @memset(@as([*]u8, @ptrCast(p))[0..48], 0);
    wr(usize, p, 0, @intFromPtr(self.name.ptr));
    wr(u32, p, 8, self.start);
    wr(u32, p, 12, self.size);
    wr(u32, p, 16, self.flags);
    wr(usize, p, 24, @intFromPtr(self.default));
    wr(u32, p, 32, self.tex_start);
    wr(u32, p, 36, self.tex_size);
    wr(u32, p, 40, self.samp_start);
    wr(u32, p, 44, self.samp_size);
    return S_OK;
}
fn varGetType(self: *VarObj) callconv(W) *TypeObj {
    return self.ty;
}
fn varGetBuffer(self: *VarObj) callconv(W) *CbObj {
    return self.cb;
}
fn varSlot(self: *VarObj, k: u32) callconv(W) u32 {
    _ = self;
    _ = k;
    return 0xFFFFFFFF;
}
const var_vtbl = VarVtbl{ .GetDesc = &varGetDesc, .GetType = &varGetType, .GetBuffer = &varGetBuffer, .GetInterfaceSlot = &varSlot };

// ---- type (no IUnknown)
const TypeVtbl = extern struct {
    GetDesc: *const fn (*TypeObj, ?*anyopaque) callconv(W) i32,
    GetMemberTypeByIndex: *const fn (*TypeObj, u32) callconv(W) *TypeObj,
    GetMemberTypeByName: *const fn (*TypeObj, ?[*:0]const u8) callconv(W) *TypeObj,
    GetMemberTypeName: *const fn (*TypeObj, u32) callconv(W) ?[*:0]const u8,
    IsEqual: *const fn (*TypeObj, *TypeObj) callconv(W) i32,
    GetSubType: *const fn (*TypeObj) callconv(W) *TypeObj,
    GetBaseClass: *const fn (*TypeObj) callconv(W) *TypeObj,
    GetNumInterfaces: *const fn (*TypeObj) callconv(W) u32,
    GetInterfaceByIndex: *const fn (*TypeObj, u32) callconv(W) *TypeObj,
    IsOfType: *const fn (*TypeObj, *TypeObj) callconv(W) i32,
    ImplementsInterface: *const fn (*TypeObj, *TypeObj) callconv(W) i32,
};
/// Which layout to write is a property of the reflector; types reach it through
/// a process-wide flag set per D3DReflect call (types carry no back pointer).
threadlocal var t_type_desc_v47: bool = true;
fn typeGetDesc(self: *TypeObj, d: ?*anyopaque) callconv(W) i32 {
    if (!self.valid) return E_FAIL;
    const p = d orelse return E_INVALIDARG;
    const v47 = if (self.owner) |o| o.v47 else t_type_desc_v47;
    const size: usize = if (v47) 40 else 28;
    @memset(@as([*]u8, @ptrCast(p))[0..size], 0);
    wr(u32, p, 0, self.class);
    wr(u32, p, 4, self.kind);
    wr(u32, p, 8, self.rows);
    wr(u32, p, 12, self.cols);
    wr(u32, p, 16, self.elements);
    wr(u32, p, 20, @intCast(self.members.len));
    wr(u32, p, 24, self.offset);
    if (v47) wr(usize, p, 32, if (self.name) |n| @intFromPtr(n.ptr) else 0);
    return S_OK;
}
fn typeMemberByIndex(self: *TypeObj, k: u32) callconv(W) *TypeObj {
    return if (k < self.members.len) self.members[k].ty else &invalid_type;
}
fn typeMemberByName(self: *TypeObj, name: ?[*:0]const u8) callconv(W) *TypeObj {
    const n = std.mem.span(name orelse return &invalid_type);
    for (self.members) |m| if (std.mem.eql(u8, m.name, n)) return m.ty;
    return &invalid_type;
}
fn typeMemberName(self: *TypeObj, k: u32) callconv(W) ?[*:0]const u8 {
    return if (k < self.members.len) self.members[k].name.ptr else null;
}
fn typeIsEqual(self: *TypeObj, other: *TypeObj) callconv(W) i32 {
    if (!self.valid or !other.valid) return E_FAIL;
    const same = self.class == other.class and self.kind == other.kind and self.rows == other.rows and
        self.cols == other.cols and self.elements == other.elements and self.members.len == other.members.len;
    return if (same) S_OK else 1; // S_FALSE
}
fn typeInvalid(self: *TypeObj) callconv(W) *TypeObj {
    _ = self;
    return &invalid_type;
}
fn typeNumIf(self: *TypeObj) callconv(W) u32 {
    _ = self;
    return 0;
}
fn typeIfByIndex(self: *TypeObj, k: u32) callconv(W) *TypeObj {
    _ = self;
    _ = k;
    return &invalid_type;
}
fn typeFalse(self: *TypeObj, other: *TypeObj) callconv(W) i32 {
    _ = self;
    _ = other;
    return 1;
}
const type_vtbl = TypeVtbl{
    .GetDesc = &typeGetDesc,
    .GetMemberTypeByIndex = &typeMemberByIndex,
    .GetMemberTypeByName = &typeMemberByName,
    .GetMemberTypeName = &typeMemberName,
    .IsEqual = &typeIsEqual,
    .GetSubType = &typeInvalid,
    .GetBaseClass = &typeInvalid,
    .GetNumInterfaces = &typeNumIf,
    .GetInterfaceByIndex = &typeIfByIndex,
    .IsOfType = &typeFalse,
    .ImplementsInterface = &typeFalse,
};

fn setOwner(t: *TypeObj, r: *Refl) void {
    t.owner = r;
    for (t.members) |m| setOwner(m.ty, r);
}

// IID_IUnknown, IID_ID3D11ShaderReflection (_43, June 2010) and (_47).
const iid_unknown = [16]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 };
const iid_refl43 = [16]u8{ 0x19, 0x37, 0x23, 0x0a, 0x60, 0x39, 0x78, 0x45, 0x9d, 0x7c, 0x20, 0x3b, 0x8b, 0x1d, 0x9c, 0xc1 };
const iid_refl47 = [16]u8{ 0xa1, 0x6c, 0x53, 0x8d, 0xca, 0x0c, 0x56, 0x49, 0xa8, 0x37, 0x78, 0x69, 0x63, 0x75, 0x55, 0x84 };

/// D3DReflect(src, size, riid, out).
pub fn reflect(src: ?*const anyopaque, size: usize, riid: ?*const anyopaque, out: ?*?*anyopaque) callconv(W) i32 {
    const o = out orelse return E_INVALIDARG;
    o.* = null;
    const data: [*]const u8 = @ptrCast(src orelse return E_INVALIDARG);
    const want = if (riid) |p| @as(*align(1) const [16]u8, @ptrCast(p)).* else return E_INVALIDARG;
    const v47 = if (std.mem.eql(u8, &want, &iid_refl47)) true else if (std.mem.eql(u8, &want, &iid_refl43)) false else return E_NOINTERFACE;
    const r = gpa.create(Refl) catch return E_OUTOFMEMORY;
    r.* = .{ .v47 = v47, .arena = std.heap.ArenaAllocator.init(gpa) };
    // The reflection keeps its own copy: strings it hands out point into it.
    const copy = r.arena.allocator().dupe(u8, data[0..size]) catch {
        r.arena.deinit();
        gpa.destroy(r);
        return E_OUTOFMEMORY;
    };
    parse(r, copy) catch {
        r.arena.deinit();
        gpa.destroy(r);
        return E_INVALIDARG;
    };
    for (r.cbs) |*cb| for (cb.vars) |*v| setOwner(v.ty, r);
    o.* = r;
    return S_OK;
}

// ======================================================================== tests
fn buildTestDxbc(buf: []u8) []u8 {
    // RDEF (SM5) with one cbuffer "CB0" {float4 color @0} and one texture binding,
    // plus an ISGN with POSITION0.
    var rdef: [512]u8 = @splat(0);
    const put = struct {
        fn f(b: []u8, off: usize, v: u32) void {
            std.mem.writeInt(u32, b[off..][0..4], v, .little);
        }
    }.f;
    // header: cbCount, cbOff, rbCount, rbOff, minor/major/progtype, flags, creator
    put(&rdef, 0, 1);
    put(&rdef, 4, 60);
    put(&rdef, 8, 1);
    put(&rdef, 12, 84);
    rdef[16] = 0;
    rdef[17] = 5;
    std.mem.writeInt(u16, rdef[18..20], 0xFFFE, .little);
    put(&rdef, 24, 300); // creator
    @memcpy(rdef[28..32], "RD11");
    // cb @60: name, nvars, varoff, size, flags, type
    put(&rdef, 60, 310);
    put(&rdef, 64, 1);
    put(&rdef, 68, 116);
    put(&rdef, 72, 16);
    // rb @84: name, type(2=texture), ret, dim(4=2D), samples, point 3, count 1, flags
    put(&rdef, 84, 320);
    put(&rdef, 88, 2);
    put(&rdef, 92, 5);
    put(&rdef, 96, 4);
    put(&rdef, 100, 0xFFFFFFFF);
    put(&rdef, 104, 3);
    put(&rdef, 108, 1);
    // var @116 (40 bytes): name, start 0, size 16, flags 2, type @156, default 0, tex/samp
    put(&rdef, 116, 330);
    put(&rdef, 124, 16);
    put(&rdef, 128, 2);
    put(&rdef, 132, 156);
    put(&rdef, 140, 0xFFFFFFFF);
    put(&rdef, 148, 0xFFFFFFFF);
    // type @156 (36 bytes): class 1 (vector), type 3 (float), rows 1, cols 4, name @340
    std.mem.writeInt(u16, rdef[156..158], 1, .little);
    std.mem.writeInt(u16, rdef[158..160], 3, .little);
    std.mem.writeInt(u16, rdef[160..162], 1, .little);
    std.mem.writeInt(u16, rdef[162..164], 4, .little);
    put(&rdef, 188, 340);
    @memcpy(rdef[300..305], "test\x00");
    @memcpy(rdef[310..314], "CB0\x00");
    @memcpy(rdef[320..324], "tex\x00");
    @memcpy(rdef[330..336], "color\x00");
    @memcpy(rdef[340..347], "float4\x00");
    var isgn: [64]u8 = @splat(0);
    put(&isgn, 0, 1);
    put(&isgn, 4, 8);
    put(&isgn, 8, 32); // name
    put(&isgn, 12, 0);
    put(&isgn, 24, 0); // reg
    isgn[28] = 0xF;
    isgn[29] = 0x7;
    @memcpy(isgn[32..41], "POSITION\x00");
    // container
    @memset(buf, 0);
    @memcpy(buf[0..4], "DXBC");
    put(buf, 28, 2);
    const off_r: u32 = 40;
    const off_i: u32 = off_r + 8 + rdef.len;
    put(buf, 32, off_r);
    put(buf, 36, off_i);
    @memcpy(buf[off_r..][0..4], "RDEF");
    put(buf, off_r + 4, rdef.len);
    @memcpy(buf[off_r + 8 ..][0..rdef.len], &rdef);
    @memcpy(buf[off_i..][0..4], "ISGN");
    put(buf, off_i + 4, isgn.len);
    @memcpy(buf[off_i + 8 ..][0..isgn.len], &isgn);
    const total = off_i + 8 + isgn.len;
    put(buf, 24, total);
    return buf[0..total];
}

test "reflection reads RDEF and signatures, with per-SDK layouts" {
    var buf: [1024]u8 = undefined;
    const dxbc = buildTestDxbc(&buf);
    var out: ?*anyopaque = null;
    try std.testing.expectEqual(S_OK, reflect(dxbc.ptr, dxbc.len, &iid_refl43, &out));
    const r: *Refl = @ptrCast(@alignCast(out.?));
    var desc: [160]u8 = undefined;
    try std.testing.expectEqual(S_OK, r.vtbl.GetDesc(r, &desc));
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, desc[20..24], .little));
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, desc[24..28], .little));
    const cb = r.vtbl.GetConstantBufferByName(r, "CB0");
    var cbd: [24]u8 = undefined;
    try std.testing.expectEqual(S_OK, cb.vtbl.GetDesc(cb, &cbd));
    try std.testing.expectEqual(@as(u32, 16), std.mem.readInt(u32, cbd[16..20], .little));
    const v = cb.vtbl.GetVariableByName(cb, "color");
    var vd: [48]u8 = undefined;
    try std.testing.expectEqual(S_OK, v.vtbl.GetDesc(v, &vd));
    try std.testing.expectEqual(@as(u32, 16), std.mem.readInt(u32, vd[12..16], .little));
    // _43 type desc is 28 bytes: byte 28.. must stay untouched.
    var td: [40]u8 = @splat(0xAA);
    const t = v.vtbl.GetType(v);
    try std.testing.expectEqual(S_OK, t.vtbl.GetDesc(t, &td));
    try std.testing.expectEqual(@as(u32, 4), std.mem.readInt(u32, td[12..16], .little));
    try std.testing.expectEqual(@as(u8, 0xAA), td[28]);
    // _43 signature desc is 32 bytes.
    var sd: [40]u8 = @splat(0xAA);
    try std.testing.expectEqual(S_OK, r.vtbl.GetInputParameterDesc(r, 0, &sd));
    try std.testing.expectEqual(@as(u8, 0xF), sd[24]);
    try std.testing.expectEqual(@as(u8, 0xAA), sd[32]);
    var bd: [40]u8 = undefined;
    try std.testing.expectEqual(S_OK, r.vtbl.GetResourceBindingDescByName(r, "tex", &bd));
    try std.testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, bd[12..16], .little));
    // misses: invalid objects, never null
    const miss = r.vtbl.GetConstantBufferByName(r, "nope");
    try std.testing.expectEqual(E_FAIL, miss.vtbl.GetDesc(miss, &cbd));
    try std.testing.expectEqual(E_INVALIDARG, r.vtbl.GetInputParameterDesc(r, 5, &sd));
    _ = r.vtbl.Release(r);
    // unknown IID refused; malformed data refused
    try std.testing.expectEqual(E_NOINTERFACE, reflect(dxbc.ptr, dxbc.len, &iid_unknown, &out));
    try std.testing.expectEqual(E_INVALIDARG, reflect("DXBCxxxx", 8, &iid_refl47, &out));
}

test "blob owns a zeroed buffer of the requested size" {
    var out: ?*anyopaque = null;
    try std.testing.expectEqual(S_OK, createBlob(100, &out));
    const b: *Blob = @ptrCast(@alignCast(out.?));
    try std.testing.expectEqual(@as(usize, 100), b.vtbl.GetBufferSize(b));
    try std.testing.expectEqual(@as(u8, 0), b.vtbl.GetBufferPointer(b)[99]);
    try std.testing.expectEqual(@as(u32, 0), b.vtbl.Release(b));
}
