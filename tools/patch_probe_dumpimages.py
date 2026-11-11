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


def dump_block(out_path, lo_expr, hi_expr, label):
    return [
        "        // PROBE ONLY: " + label,
        "        {",
        '            const out_path = "' + out_path + '";',
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
    "/tmp/opencode/wins-ceg/guest_image_entry.bin",
    "g_guest_base",
    "g_guest_end",
    "the live guest image (the CEG decrypts it at runtime)",
)
helper += [
    "    }",
    "    {",
]
helper += dump_block(
    "/tmp/opencode/wins-ceg/stub_image_entry.bin",
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
    "    }",
]
call_anchor = "    const caller = @returnAddress();"
assert call_anchor in s, "caller anchor not found"
s = s.replace(call_anchor, "\n".join(call) + "\n" + call_anchor, 1)

# ---------------------------------------------------------------------------
# 3. The same dump at the moment the guest is entered, so a change between
#    entry and exit can be seen.
# ---------------------------------------------------------------------------
entry_anchor = "        brkGuestEntry();"
assert entry_anchor in s, "guest entry anchor not found"
s = s.replace(
    entry_anchor,
    '        probeDumpImages("entry");\n' + entry_anchor,
    1,
)

# ---------------------------------------------------------------------------
# 4. Every allocation the guest makes. The loader honours a caller-supplied
#    address, so a guest that re-maps its own image leaves no trace in the
#    map file unless the allocation is written down.
# ---------------------------------------------------------------------------
alloc_anchor = "fn VirtualAlloc(lpAddress: ?*anyopaque, dwSize: usize, flAllocationType: u32, flProtect: u32) callconv(W) ?*anyopaque {"
assert alloc_anchor in s, "VirtualAlloc anchor not found"
alloc_log = [
    "    // PROBE ONLY: what the guest asked the kernel for.",
    '    std.debug.print("[WINS:Probe] VirtualAlloc(addr=0x{x}, size={d}, prot=0x{x})' + NL + '", .{ @intFromPtr(lpAddress), dwSize, flProtect });',
]
s = s.replace(alloc_anchor, alloc_anchor + "\n" + "\n".join(alloc_log), 1)

# ---------------------------------------------------------------------------
# 5. A failed GetProcAddress names the module it came from; say which
#    mapping that address is in, so the asking code can be found.
# ---------------------------------------------------------------------------
not_found = "        g_last_error = 127; // ERROR_PROC_NOT_FOUND"
assert not_found in s, "GetProcAddress failure anchor not found"
s = s.replace(
    not_found,
    "        describeAddr(@returnAddress());\n" + not_found,
    1,
)

target.write_text(s)
print("probe: live image dumps (entry and exit) + allocation log patched in")
