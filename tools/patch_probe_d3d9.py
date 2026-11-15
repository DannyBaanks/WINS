#!/usr/bin/env python3
"""Probe patch: trace every call the guest makes into the D3D9 module.

Two things are measured here.

First, the call sequence. The published module answers 104 of its 136
IDirect3D9/IDirect3DDevice9 methods with one shared stub function, and a
guest that then reads the caller's output structure finds whatever was on
its stack. The stub names no method, so the call flow is invisible: the
crash says a wild pointer was dereferenced, not which call produced it.
Each slot therefore gets its own wrapper, generated from the vtable's own
declaration, which prints the method and the address the guest called it
from.

Second, the calling convention. These are COM methods: __stdcall, so the
callee pops the arguments. A stub whose declaration does not match the
slot's arity pops the wrong number of bytes and leaves the guest's stack
drifting. The wrappers here reproduce the slot's exact signature, and they
print the guest's stack pointer on entry and exit, so the drift is visible
instead of being a mystery three thousand calls later.

Measurement only. Run by tools/build_probe.sh, against native/probe/
(gitignored). Nothing generated here is ever published.
"""
import re
import sys
import pathlib

probe_dir = pathlib.Path(sys.argv[1])
target = probe_dir / "wins_d3d9.zig"

NL = chr(92) + "n"
s = target.read_text()

RETURN_VALUE = {
    "HRESULT": "D3D_OK",
    "i32": "D3D_OK",
    "u32": "0",
    "usize": "0",
    "f32": "0.0",
    "void": None,
}


def parse_fields(struct_name):
    marker = "pub const " + struct_name + " = extern struct {"
    i = s.index(marker)
    j = s.index("\n};", i)
    body = s[i + len(marker) : j]
    fields = {}
    for line in body.splitlines():
        m = re.match(r"\s*(\w+): (\*const fn \(.*\) callconv\(W\) \w+),\s*$", line)
        if m:
            fields[m.group(1)] = m.group(2)
    return fields


def scalar_expr(t, n):
    if t == "f32":
        return "@as(u64, @as(u32, @bitCast(" + n + ")))"
    if t == "i32":
        return "@as(u64, @as(u32, @bitCast(" + n + ")))"
    return "@as(u64, " + n + ")"


def arg_expr(t, n):
    """A u64 rendering of one argument, whatever its declared type."""
    if t.startswith("?"):
        inner = t[1:]
        if inner.startswith("*"):
            return "if (" + n + ") |p| @intFromPtr(p) else 0"
        return "if (" + n + ") |v| " + scalar_expr(inner, "v") + " else 0"
    if t.startswith("*"):
        return "@intFromPtr(" + n + ")"
    return scalar_expr(t, n)


def ret_expr(t, n):
    if t == "void":
        return None
    if t == "f32":
        return "@as(u64, @as(u32, @bitCast(" + n + ")))"
    if t in ("HRESULT", "i32"):
        return "@as(u64, @as(u32, @bitCast(" + n + ")))"
    return "@as(u64, " + n + ")"


def patch_vtbl(vtbl_const, struct_name, stub_fn, prefix, tag):
    global s
    fields = parse_fields(struct_name)
    marker = "const " + vtbl_const + ": " + struct_name + " = .{"
    i = s.index(marker)
    j = s.index("\n};", i)
    block = s[i:j]

    # which slots are answered by the shared stub, and which are real
    slot_of = {}
    for line in block.splitlines():
        m = re.match(r"\s*\.(\w+) = (.+),\s*$", line)
        if m:
            slot_of[m.group(1)] = m.group(2)

    generated = []
    out = []
    for name, typ in fields.items():
        mm = re.match(r"\*const fn \((.*)\) callconv\(W\) (\w+)$", typ)
        assert mm, "cannot parse field type: " + typ
        raw_args, ret = mm.group(1), mm.group(2)
        arg_types = [a.strip() for a in raw_args.split(",")] if raw_args.strip() else []
        params = ", ".join("a%d: %s" % (k, t) for k, t in enumerate(arg_types))
        call_args = ", ".join("a%d" % k for k in range(len(arg_types)))
        fname = prefix + name
        is_stub = stub_fn in slot_of.get(name, "")

        if is_stub:
            # The shared stub has the wrong arity for a __stdcall slot: it
            # pops one argument while the guest pushed several. The probe
            # answers from a wrapper with the slot's own signature, so the
            # guest's stack stays where the guest expects it.
            gen = [
                "fn " + fname + "(" + params + ") callconv(W) " + ret + " {",
                '    std.debug.print("[WINS:D3D9] '
                + tag
                + ": "
                + name
                + '() from 0x{x}'
                + NL
                + '", .{@returnAddress()});',
                "    // shared stub slot: answered without writing any output",
            ]
            if arg_types:
                gen.append("    " + " ".join("_ = a%d;" % k for k in range(len(arg_types))))
            ret_value = RETURN_VALUE[ret]
            if ret_value is not None:
                gen.append("    return " + ret_value + ";")
            gen.append("}")
            gen.append("")
            generated.extend(gen)
            out.append("    ." + name + " = &" + fname + ",")
            continue

        # A real method: name it, show what the guest asked for, and show what
        # it got back. The return value is what the guest branches on, so a
        # method that answers a lie is visible right here.
        fmt = "[WINS:D3D9] " + tag + ": " + name + "() from 0x{x} esp=0x{x}"
        vals = ["@returnAddress()", "probe_guest_esp()"]
        for k, t in enumerate(arg_types):
            fmt += " a%d=0x{x}" % k
            vals.append(arg_expr(t, "a%d" % k))
        fmt += NL
        gen = [
            "fn " + fname + "(" + params + ") callconv(W) " + ret + " {",
            "    std.debug.print(\"" + fmt + "\", .{" + ", ".join(vals) + "});",
        ]
        if ret == "void":
            gen.append("    " + vtbl_const + "_orig." + name + "(" + call_args + ");")
            for extra in EXTRA.get((tag, name), []):
                gen.append(extra)
        else:
            gen.append("    const r = " + vtbl_const + "_orig." + name + "(" + call_args + ");")
            gen.append(
                '    std.debug.print("[WINS:D3D9] '
                + tag
                + ": "
                + name
                + '() -> 0x{x}'
                + NL
                + '", .{'
                + ret_expr(ret, "r")
                + "});"
            )
            for extra in EXTRA.get((tag, name), []):
                gen.append(extra)
            gen.append("    return r;")
        gen.append("}")
        gen.append("")
        generated.extend(gen)
        out.append("    ." + name + " = &" + fname + ",")

    new_block = "const " + vtbl_const + "_orig: " + struct_name + " = .{" + block[len("const " + vtbl_const + ": " + struct_name + " = .{") :]
    s = s[:i] + new_block + s[j:]
    # the new table replaces the original one, right after it
    insert_at = s.index("\n};", s.index(new_block[:40])) + len("\n};")
    table = (
        "\n\nconst "
        + vtbl_const
        + ": "
        + struct_name
        + " = .{\n"
        + "\n".join(out)
        + "\n};"
    )
    s = s[:insert_at] + table + s[insert_at:]
    # the wrappers go after the table
    insert_at = s.index("\n};", s.index("const " + vtbl_const + ": " + struct_name)) + len("\n};")
    s = s[:insert_at] + "\n\n" + "\n".join(generated) + s[insert_at:]


STATE_HELPER = """
/// The guest's engine object, and the arguments it passed to the renderer
/// selection function, read out of its own memory.
///
/// The swap that ends the D3D9 phase is 0xe69a60: it builds the engine
/// object (0x14 bytes), stores it at the guest global 0x126f0e8, and then
/// releases the IDirect3D9 reference it created it with. That Release is
/// the last point at which the guest's own structures are live and the
/// loader's frame can still see the guest's stack.
///
/// What has to be read, and why the earlier probe could not see it: the
/// engine holds the adapter count at +0x00, a pointer to the per-adapter
/// objects at +0x08, how many adapters it managed to probe at +0x0e, and
/// how many of those it supports at +0x10. The renderer selection that
/// follows drops the adapter when the index the game asked for is out of
/// range of that +0x0e count, and picks HAL against REF through a switch
/// on one of the fourteen arguments parked in the caller's frame. None of
/// that is a driver question, so it never shows up as a D3D9 call: it only
/// shows up here, read from the guest's memory.
const ENGINE_GLOBAL: usize = 0x126f0e8;
const SELECTION_RETURN: usize = 0xe762b7;

fn probe_read8(p: usize) u8 {
    const q: *align(1) const u8 = @ptrFromInt(p);
    return q.*;
}

fn probe_read16(p: usize) u16 {
    const q: *align(1) const u16 = @ptrFromInt(p);
    return q.*;
}

fn probe_read32(p: usize) u32 {
    const q: *align(1) const u32 = @ptrFromInt(p);
    return q.*;
}

/// The per-device-type object the engine built for one adapter.
///
/// The verdict byte at +0x140 is what the engine acts on, the capability
/// records it compared live in the list at +0x134, and the first word of
/// the D3DCAPS9 it asked the driver for sits at +0x04 -- the selection
/// treats that word as zero and drops the adapter.
fn probe_dump_adapter(label: []const u8, obj: usize) void {
    if (obj == 0) return;
    const list = probe_read32(obj + 0x134);
    const flag = probe_read8(obj + 0x140);
    const devtype = probe_read32(obj + 4);
    std.debug.print(
        "[WINS:Probe] {s}: obj=0x{x} caps.DeviceType=0x{x} verdict@0x140=0x{x} records@0x134=0x{x}\\n",
        .{ label, obj, devtype, flag, list },
    );
    var node = list;
    var guard: usize = 0;
    while (node != 0 and guard < 64) : (guard += 1) {
        const rec = probe_read32(node + 8);
        if (rec == 0) break;
        std.debug.print(
            "[WINS:Probe] {s}:   node=0x{x} next=0x{x} rec=0x{x} f0=0x{x} f1=0x{x} f4=0x{x} f5=0x{x}\\n",
            .{ label, node, probe_read32(node), rec, probe_read32(rec), probe_read8(rec + 1), probe_read8(rec + 4), probe_read8(rec + 5) },
        );
        node = probe_read32(node);
    }
}

fn probe_dump_engine() void {
    const eng = probe_read32(ENGINE_GLOBAL);
    if (eng == 0) {
        std.debug.print("[WINS:Probe] engine: global 0x{x} is empty\\n", .{ENGINE_GLOBAL});
        return;
    }
    const adapters = probe_read32(eng + 0x00);
    const array = probe_read32(eng + 0x08);
    const probed = probe_read16(eng + 0x0e);
    const supported = probe_read16(eng + 0x10);
    std.debug.print(
        "[WINS:Probe] engine=0x{x} GetAdapterCount=0x{x} array=0x{x} probed@0x0e=0x{x} supported@0x10=0x{x}\\n",
        .{ eng, adapters, array, probed, supported },
    );
    var i: usize = 0;
    // The array is allocated with slack; only the first `probed` entries
    // are real adapter objects. Walking past that reads the guest's own
    // free-list and prints pointer soup.
    const live = if (probed > 0 and probed < 4) probed else 1;
    while (i < live) : (i += 1) {
        const info = probe_read32(array + 4 * i);
        if (info == 0) continue;
        std.debug.print("[WINS:Probe] engine: adapter_info[{}] = 0x{x}\\n", .{ i, info });
        probe_dump_adapter("HAL", probe_read32(info + 0x460));
        probe_dump_adapter("REF", probe_read32(info + 0x464));
    }
}

/// The fourteen arguments the game handed the renderer selection function.
///
/// The function is still on the stack when the engine reference is dropped,
/// so walking up from this wrapper's ESP to its return address and reading
/// the words above it recovers exactly what the game asked for: argument 4
/// is the device type, argument 6 the adapter index, argument 7 the device
/// switch the engine then answers HAL or REF from.
///
/// The walk prints every return address it passes on the way up, because
/// the chain from the renderer to this wrapper is deep and the frame
/// distances in between are what tells us where the selection frame is.
/// Only addresses inside the engine's own code are interesting; the guest's
/// heap and its own objects are pointer soup.
fn probe_dump_selection_args() void {
    const base = probe_guest_esp();
    std.debug.print("[WINS:Probe] selection: walking the stack above 0x{x}\\n", .{base});
    var i: usize = 0;
    while (i < 0x400) : (i += 4) {
        const v = probe_read32(base + i);
        // The guest image spans 0x400000..0x147b000: code returns into that
        // window and its heap lives far above it, so this marks the frames.
        const is_code = v >= 0x400000 and v < 0x1480000;
        const kind: []const u8 = if (v == SELECTION_RETURN)
            "  <== selection frame"
        else if (is_code)
            "  (guest code)"
        else
            "";
        std.debug.print(
            "[WINS:Probe] selection:   +0x{x}: 0x{x}{s}\\n",
            .{ i, v, kind },
        );
    }
}


/// The renderer object, found relative to the engine object the loader can see.
///
/// The engine is reachable from a guest global, but the renderer that asked for
/// an adapter and a device type is not: it was allocated by the guest's own
/// allocator before the engine and the game keeps no global for it. Linux
/// places successive anonymous mappings below each other, so it is somewhere
/// under the engine, and it is recognisable by what it holds: a word at +0x5c4
/// that is the adapter index it asked for, and two heap pointers at +0x5d8 and
/// +0x5dc that only the selection writes -- the adapter object and the HAL/REF
/// device object it picked. Those two are the whole question: if they are zero
/// the renderer never accepted an adapter, and the engine's own verdict of 1
/// means the rejection is the game's, not the driver's.
pub fn probe_find_renderer() void {
    const eng = probe_read32(ENGINE_GLOBAL);
    if (eng == 0) return;
    var found: usize = 0;
    // Linux hands out anonymous mappings below each other, so the renderer --
    // allocated before the engine -- is normally underneath it. The window is
    // generous both ways and the shape is what identifies the object, not the
    // distance: a word at +0x5c4 that is an adapter index, and pointers or
    // zeroes at +0x5d8 and +0x5dc, which are the only fields the selection
    // writes after the engine it was handed back.
    const lo: usize = eng - 0x80000;
    const hi: usize = eng + 0x10000;
    var p: usize = lo;
    while (p < hi and found < 8) : (p += 4) {
        if (p < 0x1000 or p > 0xF0000000) continue;
        const idx = probe_read32(p + 0x5c4);
        if (idx > 4) continue;
        const a = probe_read32(p + 0x5d8);
        const b = probe_read32(p + 0x5dc);
        if (a > 0x1000 and (a < 0xd0000000 or a > 0xf0000000)) continue;
        if (b > 0x1000 and (b < 0xd0000000 or b > 0xf0000000)) continue;
        found += 1;
        std.debug.print(
            "[WINS:Probe] renderer: candidate #{} at 0x{x}\\n",
            .{ found, p },
        );
        std.debug.print(
            "[WINS:Probe] renderer:   vtable=0x{x} devtype@0x3bc=0x{x} adapter@0x5c4={d} switch@0x5c8=0x{x} count@0x5cc=0x{x}\\n",
            .{ probe_read32(p), probe_read32(p + 0x3bc), idx, probe_read32(p + 0x5c8), probe_read32(p + 0x5cc) },
        );
        std.debug.print(
            "[WINS:Probe] renderer:   adapter object@0x5d8=0x{x} device object@0x5dc=0x{x} caps.DeviceType=0x{x}\\n",
            .{ a, b, if (b > 0x1000) probe_read32(b + 4) else 0 },
        );
    }
    if (found == 0) std.debug.print("[WINS:Probe] renderer: no candidate around the engine at 0x{x}\\n", .{eng});
}

fn probe_dump_state() void {
    probe_dump_engine();
    probe_dump_selection_args();
    probe_find_renderer();
}
"""

# Per-method instrumentation: when the loader can still see both the
# guest's own structures and its stack, read them out.
#
# The guest drops the reference the engine was built with immediately after
# building it (return address 0xe69aa9); that is the one call where the
# engine object, the per-adapter objects and the selection frame are all
# live at once.
EXTRA = {
    ("IDirect3D9", "Release"): [
        "    if (@returnAddress() == 0xe69aa9) probe_dump_state();",
    ],
}

ESP_HELPER = """
/// The guest's stack pointer as it enters this frame.
///
/// These are COM methods: __stdcall, so the callee pops the arguments. A
/// slot whose answer does not pop as many words as the guest pushed leaves
/// the guest's stack drifting, and the drift only shows up thousands of
/// calls later as a wild jump. Reading the stack pointer on entry shows
/// the drift directly.
fn probe_guest_esp() usize {
    var sp: usize = undefined;
    asm volatile ("movl %%esp, %[out]"
        : [out] "=r" (sp),
    );
    return sp;
}
"""

patch_vtbl("g_d3d9_vtbl", "IDirect3D9Vtbl", "d3d9_Stub", "probe_d3d9_", "IDirect3D9")
patch_vtbl("g_device9_vtbl", "IDirect3DDevice9Vtbl", "dev9_Stub", "probe_dev9_", "IDirect3DDevice9")

s = s[: s.index("const g_d3d9_vtbl")] + STATE_HELPER + ESP_HELPER + "\n" + s[s.index("const g_d3d9_vtbl") :]

target.write_text(s)
print("probe: D3D9 call trace with the guest's call site and stack pointer")
