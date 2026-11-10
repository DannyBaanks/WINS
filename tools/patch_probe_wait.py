#!/usr/bin/env python3
"""Probe patch: make the wait real, and dump the whole relayed IPC object.

Measurement only. Two questions this answers, both of which the current run
cannot:

1. The wait shim answers WAIT_OBJECT_0 without waiting, so the guest is told
   "the client answered" before the client had any chance to answer. Real
   waiting gives the live client the seconds it needs to publish its response
   into the object it owns.

2. The exit dump only shows two 32-byte windows. The full object shows what
   the client actually wrote while the guest was waiting, which is the
   protocol, observed rather than guessed.

Run only by tools/build_probe.sh, against native/probe/ (gitignored).
"""
import sys
import pathlib

probe_dir = pathlib.Path(sys.argv[1])
target = probe_dir / "winrun32.zig"

NL = chr(92) + "n"

s = target.read_text()

# 1. Wait for real inside WaitForSingleObject.
fn_anchor = "fn WaitForSingleObject(hHandle: usize, dwMilliseconds: u32) callconv(W) u32 {"
assert fn_anchor in s, "WaitForSingleObject not found"
start = s.index(fn_anchor)
end = s.index("\n}\n", start)
body = s[start:end]
assert "return 0; // WAIT_OBJECT_0" in body, "WAIT_OBJECT_0 return not found in the wait shim"
body = body.replace(
    "return 0; // WAIT_OBJECT_0",
    "Sleep(dwMilliseconds); // PROBE: really wait, so the live client can answer.\n"
    "    return 0; // WAIT_OBJECT_0",
    1,
)
s = s[:start] + body + s[end:]

# 2. Dump every non-zero dword of the relayed object at exit.
lines = s.split("\n")
for idx, line in enumerate(lines):
    if "ExitProcess called with code" in line:
        ins = [
            "    if (g_last_relay_ptr != 0) {",
            '        std.debug.print("  [probe] full relayed object:", .{});',
            "        var fi: usize = 0;",
            "        var fshown: usize = 0;",
            "        while (fi < g_last_relay_len and fshown < 160) : (fi += 4) {",
            "            const w: u32 = @as(*const u32, @ptrFromInt(g_last_relay_ptr + fi)).*;",
            "            if (w != 0) {",
            '                std.debug.print(" [+0x{x}=0x{x:0>8}]", .{ fi, w });',
            "                fshown += 1;",
            "            }",
            "        }",
            '        std.debug.print("' + NL + '", .{});',
            "    }",
        ]
        lines[idx + 1:idx + 1] = ins
        break
else:
    raise SystemExit("ExitProcess anchor not found")

target.write_text("\n".join(lines))
print("probe: real wait + full object dump patched in")
