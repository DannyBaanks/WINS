#!/usr/bin/env python3
"""Probe patch: log the registry questions and the answers.

Measurement only. Run by tools/build_probe.sh, against native/probe/
(gitignored).

The loader answers some registry values from facts it can actually prove --
the running Steam client's PID, its executable and dll paths, read from
/proc -- and ERROR_FILE_NOT_FOUND for everything else, which is the correct
Win32 answer for a value the machine does not have. "Installed Path" is the
one value it answers with a directory it never measured, and the guest opens
exactly that key, for exactly that value, on its way out the door.

This records what the guest asked for and what it was handed, so the
difference between "the game gave up because the answer was wrong" and "the
game gave up for its own reasons" is measurable instead of arguable.

Nothing generated here is ever published.
"""
import sys
import pathlib

probe_dir = pathlib.Path(sys.argv[1])
target = probe_dir / "winrun32.zig"

NL = chr(92) + "n"

s = target.read_text()

# The probe reports the handle it was handed, so the parameter is no longer
# unused and a discard would be a lie about the call.
assert "    _ = hKey; _ = lpReserved;\n" in s
s = s.replace("    _ = hKey; _ = lpReserved;\n", "    _ = lpReserved;\n", 1)

# 1. The question: which handle, which value, how big a buffer.
anchor = "    var reg_type: u32 = REG_NONE;"
assert anchor in s, "RegQueryValueExA body anchor not found"
ask = [
    "    // PROBE ONLY: this is the first call the guest makes after the engine",
    "    // it built has been handed back, so the renderer object is alive and",
    "    // its decision fields are written. Look at it here, not at the exit,",
    "    // where the guest has already released the memory.",
    "    d3d9.probe_find_renderer();",
    "    // PROBE ONLY: the question, before any answer exists.",
    '    if (lpValueName != null) {',
    '        std.debug.print("[WINS:RegProbe] RegQueryValueExA(handle=0x{x}, \\"{s}\\", buffer={?d})' + NL + '",',
    "            .{ hKey, std.mem.sliceTo(lpValueName.?, 0), if (lpcbData) |cb| cb.* else null },",
    "        );",
    "    }",
]
s = s.replace(anchor, "\n".join(ask) + "\n" + anchor, 1)

# 2. Every answer, named. The bodies are left exactly as they were: the log
#    line is inserted in front of the return, never in place of anything.
for old, rc, note in (
    (
        "            return 2; // ERROR_FILE_NOT_FOUND",
        "2",
        "no such value on this machine",
    ),
    (
        "        return 2; // ERROR_FILE_NOT_FOUND",
        "2",
        "no such value on this machine",
    ),
    (
        "                return ERROR_SUCCESS;",
        "ERROR_SUCCESS",
        "the value it asked for",
    ),
    (
        "    return ERROR_MORE_DATA;",
        "ERROR_MORE_DATA",
        "the caller's buffer is too small",
    ),
):
    n = s.count(old)
    assert n >= 1, "return anchor not found: " + note
    # The rc goes inline: a named local would be redeclared the second time
    # the same return appears in the function.
    log = [
        "        // PROBE ONLY: " + note + ".",
        '        std.debug.print("[WINS:RegProbe]   -> {d} ({s})' + NL + '",',
        '            .{ @as(i32, ' + rc + '), "' + note + '" },',
        "        );",
    ]
    s = s.replace(old, "\n".join(log) + "\n" + old)

target.write_text(s)
print("probe: registry call logging patched in")
