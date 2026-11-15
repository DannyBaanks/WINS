#!/usr/bin/env python3
"""Probe patch: log what the profile shim is asked for.

Measurement only. Run by tools/build_probe.sh, against native/probe/
(gitignored).

The shim reads the guest's own ini now, but it is still worth recording every
question it answers: the file the game names, the section and the key, and the
default the game passed in. That is what tells us which settings the game
actually consults -- and, when a value comes back as the default rather than
the file, that the file does not have it yet.

Nothing generated here is ever published.
"""
import sys
import pathlib

probe_dir = pathlib.Path(sys.argv[1])
target = probe_dir / "winrun32.zig"

NL = chr(92) + "n"
Q = chr(92) + chr(34)
D = chr(34)

s = target.read_text()

STRING_LOG = [
    "    // PROBE ONLY: name the file, the section and the key.",
    "    if (lpAppName != null and lpKeyName != null) {",
    '        std.debug.print("[WINS:IniProbe] GetPrivateProfileStringA(' + Q + "{s}" + Q + ", " + Q + "{s}" + Q + ", default=" + Q + "{s}" + Q + ", file=" + Q + "{s}" + Q + ")" + NL + '",',
    "            .{ std.mem.sliceTo(lpAppName.?, 0),",
    "                std.mem.sliceTo(lpKeyName.?, 0),",
    "                if (lpDefault) |d| std.mem.sliceTo(d, 0) else " + D + "(null)" + D + ",",
    "                if (lpFileName) |f| std.mem.sliceTo(f, 0) else " + D + "(null)" + D + " },",
    "        );",
    "    }",
]

INT_LOG = [
    "    // PROBE ONLY: name the file, the section and the key. The default is",
    "    // an int here, so it is printed as a number.",
    "    if (lpAppName != null and lpKeyName != null) {",
    '        std.debug.print("[WINS:IniProbe] GetPrivateProfileIntA(' + Q + "{s}" + Q + ", " + Q + "{s}" + Q + ", default={d}, file=" + Q + "{s}" + Q + ")" + NL + '",',
    "            .{ std.mem.sliceTo(lpAppName.?, 0), std.mem.sliceTo(lpKeyName.?, 0), nDefault,",
    "                if (lpFileName) |f| std.mem.sliceTo(f, 0) else " + D + "(null)" + D + " },",
    "        );",
    "    }",
]

# The anchors are the signature line plus the first line of the real body, so
# the log is inserted right after the opening brace.
STRING_ANCHOR = (
    "fn GetPrivateProfileStringA(lpAppName: ?[*:0]const u8, lpKeyName: ?[*:0]const u8, "
    "lpDefault: ?[*:0]const u8, lpReturnedString: ?[*]u8, nSize: u32, lpFileName: ?[*:0]const u8) callconv(W) u32 {\n"
    "    if (lpReturnedString == null or nSize == 0) return 0;"
)
assert STRING_ANCHOR in s, "GetPrivateProfileStringA anchor not found"
s = s.replace(
    STRING_ANCHOR,
    STRING_ANCHOR + "\n" + "\n".join(STRING_LOG),
    1,
)

INT_ANCHOR = (
    "fn GetPrivateProfileIntA(lpAppName: ?[*:0]const u8, lpKeyName: ?[*:0]const u8, "
    "nDefault: i32, lpFileName: ?[*:0]const u8) callconv(W) i32 {\n"
    "    if (lpAppName) |app| {"
)
assert INT_ANCHOR in s, "GetPrivateProfileIntA anchor not found"
s = s.replace(
    INT_ANCHOR,
    INT_ANCHOR + "\n" + "\n".join(INT_LOG),
    1,
)

target.write_text(s)
print("probe: profile call logging patched in")
