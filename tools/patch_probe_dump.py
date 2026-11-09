#!/usr/bin/env python3
"""Patch the local probe copy so the relayed Steam IPC object is dumped.

Measurement only: without this, what the guest writes into the object and what
the real client writes back is invisible, so the protocol would have to be
guessed. With it, the dump is the evidence the native implementation is built
from.

Run only by tools/build_probe.sh, against native/probe/ (gitignored).
"""
import sys
import pathlib

probe_dir = pathlib.Path(sys.argv[1])
target = probe_dir / "winrun32.zig"

# Built this way so the generated Zig source contains the two characters
# backslash-n inside a string literal, not a real newline.
NL = chr(92) + "n"

s = target.read_text()

# File-scope state, inserted just before MapViewOfFile.
anchor = "fn MapViewOfFile(hFileMappingObject: usize"
assert anchor in s, "MapViewOfFile anchor not found"
decls = (
    "// PROBE: the last relayed Steam IPC mapping, for the dump below.\n"
    "var g_last_relay_ptr: usize = 0;\n"
    "var g_last_relay_len: usize = 0;\n\n"
)
s = s.replace(anchor, decls + anchor, 1)

lines = s.split("\n")
for idx, line in enumerate(lines):
    if "Mapped Steam's IPC object" in line:
        lines.insert(idx + 1, "        g_last_relay_ptr = ptr;")
        lines.insert(idx + 2, "        g_last_relay_len = size;")
        lines.insert(idx + 3, '        std.debug.print("[probe] relayed object {d} bytes; non-zero dwords:", .{size});')
        lines.insert(idx + 4, "        var di: usize = 0;")
        lines.insert(idx + 5, "        var shown: usize = 0;")
        lines.insert(idx + 6, "        while (di < size and shown < 40) : (di += 4) {")
        lines.insert(idx + 7, "            const w: u32 = @as(*const u32, @ptrFromInt(ptr + di)).*;")
        lines.insert(idx + 8, "            if (w != 0) {")
        lines.insert(idx + 9, '                std.debug.print(" [+0x{x}=0x{x:0>8}]", .{ di, w });')
        lines.insert(idx + 10, "                shown += 1;")
        lines.insert(idx + 11, "            }")
        lines.insert(idx + 12, "        }")
        lines.insert(idx + 13, '        std.debug.print("' + NL + '", .{});')
        break
else:
    raise SystemExit("Mapped-anchor line not found")

s = "\n".join(lines)

# Also dump the two protocol regions at exit, so it is visible whether the guest
# ever wrote its request and whether the client answered.
for idx, line in enumerate(lines):
    if "ExitProcess called with code" in line:
        ins = [
            "    if (g_last_relay_ptr != 0 and code == 0) {",
            "        const obj: [*]const u8 = @ptrFromInt(g_last_relay_ptr);",
            '        std.debug.print("  [WINS:SteamBridge] guest block 0x90..0xb0:", .{});',
            "        var o: usize = 0x90;",
            "        while (o < 0xb0) : (o += 4) {",
            "            const w: u32 = @as(*const u32, @ptrFromInt(@intFromPtr(obj) + o)).*;",
            '            if (w != 0) std.debug.print(" [+0x{x}=0x{x:0>8}]", .{ o, w });',
            "        }",
            '        std.debug.print("' + NL + '  [WINS:SteamBridge] client block 0x00..0x70:", .{});',
            "        var q: usize = 0;",
            "        while (q < 0x70) : (q += 4) {",
            "            const w: u32 = @as(*const u32, @ptrFromInt(@intFromPtr(obj) + q)).*;",
            '            if (w != 0) std.debug.print(" [+0x{x}=0x{x:0>8}]", .{ q, w });',
            "        }",
            '        std.debug.print("' + NL + '", .{});',
            "    }",
        ]
        lines[idx + 1:idx + 1] = ins
        break
s = "\n".join(lines)

target.write_text(s)
print("probe: relayed-IPC dump patched in")
