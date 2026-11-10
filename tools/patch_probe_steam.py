#!/usr/bin/env python3
"""Patch the local probe copy: reflect the real client's readiness, then answer
the guest's request with a bare echo of its own token.

Laboratory only. What is measured:

1. Does the guest advance when the object reflects the real client readiness?
   (Already measured: yes -- it writes its request.)
2. Is the response validated, or only required to be present? That decides
   whether an honest bridge is possible at all.

The echo is NOT a credential and not a delivery mechanism; it is the instrument
that answers the question. Run only by tools/build_probe.sh, after
patch_probe_dump.py has already declared g_last_relay_ptr/_len and the exit
dump.
"""
import pathlib
import sys

probe_dir = pathlib.Path(sys.argv[1])
target = probe_dir / "winrun32.zig"

out = []
for line in target.read_text().split("\n"):
    out.append(line)
    if "Mapped Steam's IPC object" in line and "std.debug.print" in line:
        out += [
            "        g_last_relay_ptr = ptr;",
            "        g_last_relay_len = size;",
            '        std.debug.print("[probe] +0x90 before: {d}\\n", .{@as(*const u32, @ptrFromInt(ptr + 0x90)).*});',
            "        if (size > 0xb0) {",
            "            @as(*u32, @ptrFromInt(ptr + 0x90)).* = 2;",
            '            std.debug.print("[probe] +0x90 after reflect: 2\\n", .{});',
            "        }",
            "        const st: u32 = @as(*const u32, @ptrFromInt(ptr + 0x94)).*;",
            "        const tk: u32 = @as(*const u32, @ptrFromInt(ptr + 0xa4)).*;",
            "        const tg: u32 = @as(*const u32, @ptrFromInt(ptr + 0xac)).*;",
            '        std.debug.print("[probe] request seen at map: status={d} token=0x{x:0>8} target=0x{x:0>8}\\n", .{ st, tk, tg });',
            "        // PROBE (diagnostic): answer with a bare echo of the guest's own",
            "        // token. Deliberately not a credential. If the guest advances,",
            "        // the protocol is presence-only; if it still fails, the answer is",
            "        // validated and no honest bridge exists without the real client.",
            "        if (st == 2 and tk != 0 and tg != 0) {",
            "            @as(*u32, @ptrFromInt(tg)).* = tk;",
            "            @as(*u32, @ptrFromInt(ptr + 0x94)).* = 3;",
            '            std.debug.print("[probe] echoed token to 0x{x:0>8}, status=3\\n", .{tg});',
            "        }",
        ]

text = "\n".join(out)
if text and not text.endswith("\n"):
    text += "\n"
target.write_text(text)
print("probe: readiness reflection + echo diagnostic patched in")
