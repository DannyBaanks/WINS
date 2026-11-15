#!/usr/bin/env python3
"""Probe patch: name the guest's call site and dump the guest's LIVE images.

Two measurements, both impossible from the file on disk:

1. The CEG decrypts parts of its own image at runtime, and the guest builds a
   second image at 0x10000000 that it runs from. The bytes on disk are not the
   bytes that ran, so the crash handler dumps the live mappings and the CEG can
   be disassembled as it ran.

2. The address the guest returns to after the ticket call is the exact
   instruction that made the call. The words sitting above it on the stack are
   the arguments the guest pushed, in push order: that is the call's real
   shape, measured, instead of a shape assumed from a header.

Measurement only. Run by tools/build_probe.sh, against native/probe/
(gitignored). Nothing generated here is ever published.
"""
import sys
import pathlib

probe_dir = pathlib.Path(sys.argv[1])
target = probe_dir / "winrun32.zig"

NL = chr(92) + "n"
s = target.read_text()

# ---------------------------------------------------------------------------
# 1. The live images, dumped from the crash handler.
#
# The dump runs BEFORE the frame-pointer walk: that walk reads memory through
# a register that is not a frame pointer in this crash, and when it faults the
# handler dies before the dump ever happens. Measurement order matters.
# ---------------------------------------------------------------------------
anchor = (
    '        std.debug.print("  ESI: 0x{x:0>8}  EDI: 0x{x:0>8}  EFLAGS: 0x{x:0>8}\\n", .{\n'
    "            uctx.uc_mcontext.esi, uctx.uc_mcontext.edi, uctx.uc_mcontext.eflags,\n"
    "        });"
)
assert anchor in s, "register dump anchor not found"


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


dump = []
# The image at 0x10000000 first: it holds the CEG code that made the ticket
# call, and it is the one that is certainly mapped start to finish.
dump += dump_block(
    "/tmp/opencode/wins-ceg/stub_image_runtime.bin",
    "0x10000000",
    "0x10063000",
    "the image the guest built at 0x10000000 (the ticket call came from inside it)",
)
dump += dump_block(
    "/tmp/opencode/wins-ceg/guest_image_runtime.bin",
    "g_guest_base",
    "g_guest_end",
    "the live guest image (the CEG decrypts it at runtime)",
)
s = s.replace(anchor, anchor + "\n" + "\n".join(dump), 1)

# ---------------------------------------------------------------------------
# 2. The guest's call site for the ticket, and the words it pushed.
# ---------------------------------------------------------------------------
sig = ") callconv(Tc) u32 {"
idx = s.find("fn sub_GetAppOwnershipTicketData(")
assert idx > 0, "sub_GetAppOwnershipTicketData not found"
end = s.find(sig, idx)
assert end > 0, "thunk signature not found"
insert_at = end + len(sig)

probe = [
    "",
    "    // PROBE ONLY: the call's real shape, measured from the guest's side.",
    "    // The return address is the guest's instruction after its call; the",
    "    // words above it on the stack are the arguments it pushed, in push",
    "    // order (last pushed first).",
    "    {",
    "        const ret = @returnAddress();",
    '        std.debug.print("[WINS:Probe] ticket call: guest return address = 0x{x:0>8}' + NL + '", .{ret});',
    "        var sp: usize = undefined;",
    '        asm volatile ("movl %%esp, %[s]" : [s] "=r" (sp));',
    "        var a = sp;",
    "        var slot: usize = 0;",
    "        // The frame is large (a 512-byte scratch buffer), so the return",
    "        // address sits well above ESP. Never read past the top of the",
    "        // guest's stack region.",
    "        var limit = sp + 0x600;",
    "        if (g_guest_stack_base != 0 and limit > g_guest_stack_base) limit = g_guest_stack_base;",
    "        while (a + 4 <= limit) : (a += 4) {",
    "            if (@as(*const u32, @ptrFromInt(a)).* == @as(u32, @truncate(ret))) {",
    "                slot = a;",
    "                break;",
    "            }",
    "        }",
    "        if (slot != 0) {",
    '            std.debug.print("[WINS:Probe]   caller frame (offset 0 = return address):' + NL + '", .{});',
    "            var i: usize = 0;",
    "            while (i < 24) : (i += 1) {",
    "                const w = @as(*const u32, @ptrFromInt(slot + i * 4)).*;",
    '                std.debug.print("[WINS:Probe]     [+0x{x:0>2}] 0x{x:0>8}' + NL + '", .{ i * 4, w });',
    "            }",
    "        } else {",
    '            std.debug.print("[WINS:Probe]   (return address slot not found above ESP)' + NL + '", .{});',
    "        }",
    "    }",
]
s = s[:insert_at] + "\n".join(probe) + s[insert_at:]

target.write_text(s)
print("probe: live image dumps + ticket call-site capture patched in")
