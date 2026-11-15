#!/usr/bin/env python3
"""Probe patch: make the SteamStart shared-memory opens FAIL, as Proton does.

Measurement only, and switchable at RUN time:

    WINS_PROBE_NOSTART=1   the opens fail (as they do under Proton)
    (unset)                the opens keep the normal relay behaviour

Why the switch exists:

The guest's own bootstrap (the .bind section of FalloutNV.exe) opens two named
objects before it talks to the client:

    OpenEventA("Local\\SteamStart_SharedMemLock")
    OpenFileMappingA("Local\\SteamStart_SharedMemFile")

Measured on this machine, both encodings, whole tree:

  * "SteamStart_SharedMem" appears NOWHERE under Proton Experimental
    (files/, files/lib/wine/, the proton script itself).
  * It appears NOWHERE in the Linux client (linux32/steamclient.so).
  * The nearest real name is "Steam3Master_SharedMemLock", a different object,
    inside Proton's prefix steam.exe.

Measured behaviour of the guest, with the opens failing:

    [probe] OpenEventA(SteamStart_SharedMemLock) -> FAILED (as under Proton)
    [probe] OpenFileMappingA(SteamStart_SharedMemFile) -> FAILED (as under Proton)
    [WINS:MessageBoxA] [Steam Error] Application load error P:0000065432

So the guest needs that mapping and a readiness word at +0x90 before it will
publish its request. With the relay on and the word set, the guest does publish
its request and the real client does write into the same slot -- the client's
own pointer replaces the guest's at +0xac. Which field carries the answer is
still unknown; the before/after snapshots around the wait answer that.

This patch changes nothing in the published loader (native/winrun32.zig).

Run only by tools/build_probe.sh, against native/probe/ (gitignored).
"""
import pathlib
import sys

probe_dir = pathlib.Path(sys.argv[1])
target = probe_dir / "winrun32.zig"

s = target.read_text()

GUARD = '''
    if (std.mem.indexOf(u8, name, "SteamStart_SharedMem{name}") != null and
        getenv("WINS_PROBE_NOSTART") != null)
    {
        std.debug.print("[probe] Open{name}(SteamStart_SharedMem{name}) -> FAILED (as under Proton)\\n", .{});
        g_last_error = 2; // ERROR_FILE_NOT_FOUND
        return 0;
    }
'''

# --- 1. OpenEventA ----------------------------------------------------------
anchor_event = '''    std.debug.print("[WINS:Kernel32] OpenEventA(\\"{s}\\")\\n", .{name});'''
assert anchor_event in s, "OpenEventA print not found"
s = s.replace(
    anchor_event,
    anchor_event + GUARD.replace("{name}", "Lock"),
    1,
)

# --- 2. OpenFileMappingA ----------------------------------------------------
anchor_map = '''    std.debug.print("[WINS:Kernel32] OpenFileMappingA(\\"{s}\\")\\n", .{name});'''
assert anchor_map in s, "OpenFileMappingA print not found"
s = s.replace(
    anchor_map,
    anchor_map + GUARD.replace("{name}", "File"),
    1,
)

target.write_text(s)
print("probe: SteamStart opens fail only when WINS_PROBE_NOSTART=1")
