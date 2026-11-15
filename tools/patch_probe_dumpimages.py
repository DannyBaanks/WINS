#!/usr/bin/env python3
"""Probe patch: keep the evidence when the guest exits instead of crashing.

The crash handler dumps the live images, but it only runs when the guest
crashes. When the guest walks out on its own -- an error path, or a normal
exit -- the images it was running are still the interesting thing: the CEG
decrypts the guest image at runtime, so the file on disk is not the code that
ran.

This patch therefore dumps the same images from two moments -- the jump into
the guest, and the guest's exit -- so a change between them can be seen, and
it prints the words on the stack around the return address, so the chain that
led to the exit can be read without guessing.

It also logs every VirtualAlloc the guest makes. The loader honours a
caller-supplied address, so a guest that re-maps its own image is invisible
in the map file unless the allocation is written down.

Measurement only. Run by tools/build_probe.sh, against native/probe/
(gitignored). Nothing generated here is ever published.
"""
import sys
import pathlib

probe_dir = pathlib.Path(sys.argv[1])
target = probe_dir / "winrun32.zig"

NL = chr(92) + "n"
s = target.read_text()


def dump_block(path_expr, lo_expr, hi_expr, label):
    return [
        "        // PROBE ONLY: " + label,
        "        {",
        "            var name_buf: [256:0]u8 = undefined;",
        "            const out_path = " + path_expr + ";",
        "            const lo: usize = " + lo_expr + ";",
        "            const hi: usize = " + hi_expr + ";",
        "            const fd = linux.open(out_path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);",
        "            if (linux.errno(fd) == .SUCCESS) {",
        "                defer _ = linux.close(@intCast(fd));",
        "                const src: [*]const u8 = @ptrFromInt(lo);",
        "                const total = hi - lo;",
        "                var off: usize = 0;",
        "                while (off < total) {",
        "                    const chunk = @min(total - off, 1 << 20);",
        "                    const n = linux.write(@intCast(fd), src + off, chunk);",
        "                    if (n <= 0) break;",
        "                    off += @intCast(n);",
        "                }",
        '                std.debug.print("  [probe] ' + label + ' dumped: 0x{x} bytes -> {s}' + NL + '", .{ total, out_path });',
        "            } else {",
        '                std.debug.print("  [probe] could not open {s} for the dump' + NL + '", .{out_path});',
        "            }",
        "        }",
    ]


# ---------------------------------------------------------------------------
# 1. The dump itself, as a function the loader can call at two moments.
# ---------------------------------------------------------------------------
helper = [
    "/// PROBE ONLY: dump the images the guest was running, under a tag that says",
    "/// when it was taken.",
    "fn probeDumpImages(tag: []const u8) void {",
    '    std.debug.print("  [probe] dumping the live images ({s})' + NL + '", .{tag});',
    "    if (g_guest_base != 0 and g_guest_end > g_guest_base) {",
]
helper += dump_block(
    'std.fmt.bufPrintZ(&name_buf, "/tmp/opencode/wins-ceg/guest_image_{s}.bin", .{tag}) catch name_buf[0..0 :0]',
    "g_guest_base",
    "g_guest_end",
    "the live guest image (the CEG decrypts it at runtime)",
)
helper += [
    "    }",
    "    {",
]
helper += dump_block(
    'std.fmt.bufPrintZ(&name_buf, "/tmp/opencode/wins-ceg/stub_image_{s}.bin", .{tag}) catch name_buf[0..0 :0]',
    "0x10000000",
    "0x10063000",
    "the image the guest built at 0x10000000 (the CEG's own code)",
)
helper += [
    "    }",
    "}",
    "",
]

anchor = "fn ExitProcess(code: u32) callconv(W) noreturn {"
assert anchor in s, "ExitProcess anchor not found"
s = s.replace(anchor, "\n".join(helper) + anchor, 1)

# ---------------------------------------------------------------------------
# 2. ExitProcess: dump, then show the stack around the return address.
# ---------------------------------------------------------------------------
call = [
    "    // PROBE ONLY: the renderer writes its decision fields only after the",
    "    // engine the loader can see has been handed back, and releases them on",
    "    // the way out -- so the object is looked up here, one moment before.",
    "    d3d9.probe_find_renderer();",
    "    // PROBE ONLY: the evidence, and the chain that led here.",
    '    probeDumpImages("exit");',
    "    {",
    "        const ret = @returnAddress();",
    '        std.debug.print("[WINS:Probe] ExitProcess({d}): return address = 0x{x:0>8}' + NL + '", .{ code, ret });',
    "        var sp: usize = undefined;",
    '        asm volatile ("movl %%esp, %[s]" : [s] "=r" (sp));',
    "        var i: usize = 0;",
    "        while (i < 24) : (i += 1) {",
    "            const w = @as(*const u32, @ptrFromInt(sp + i * 4)).*;",
    '            std.debug.print("[WINS:Probe]   [+0x{x:0>2}] 0x{x:0>8}' + NL + '", .{ i * 4, w });',
    "        }",
    "        // The exit is a decision the guest made, and the decision lives in",
    "        // the frames above this one. The guest image spans 0x400000..0x147b000,",
    "        // so any word in that window on the way up is a return address into",
    "        // its own code: that names the chain that produced the exit.",
    "        //",
    "        // The walk starts at the wrapper's own ESP, not above the window",
    "        // already printed: the guest's return address sits at +0x44 and the",
    "        // frame it leads to at +0x4c, both below the 0x60 the window ends at.",
    "        var off: usize = 0;",
    "        while (off < 0x2000) : (off += 4) {",
    "            const w = @as(*const u32, @ptrFromInt(sp + off)).*;",
    "            if (w >= 0x400000 and w < 0x1480000) {",
    '                std.debug.print("[WINS:Probe] chain +0x{x:0>3}: 0x{x:0>8}' + NL + '", .{ off, w });',
    "            }",
    "        }",
    "    }",
]
