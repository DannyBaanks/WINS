#!/usr/bin/env bash
# Build the MEASUREMENT-ONLY probe loader. Not part of any published artifact.
#
# The public loader reports the APIs this probe implements as unsupported. That
# is the correct shipped behaviour. This script exists so the call flow of a
# target can be observed locally -- what it passes, what it reads back, what it
# calls on a returned object -- so the native Linux implementation can be derived
# from evidence instead of guessed.
#
# native/probe/ is gitignored. Nothing generated here is ever committed.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PROBE="$REPO/native/probe"
ZIG="${ZIG:-/home/danny/.local/opt/zig-x86_64-linux-0.16.0/zig}"
OUT="${1:-$PROBE/winrun32_probe}"

if [[ ! -f "$PROBE/instrumented_stubs.zig" ]]; then
    echo "error: $PROBE/instrumented_stubs.zig is missing." >&2
    echo "       It is local measurement instrumentation and is never published." >&2
    exit 1
fi

mkdir -p "$PROBE"
# The probe is the public loader copied verbatim, so a change to the loader can
# never silently diverge from what gets measured.
for src in winrun32.zig winrun_kernel32.zig winrun_msvcrt.zig winrun_extra_dlls.zig \
           winrun_ordinals.zig wins_d3d9.zig wins_graph.zig winrun_vorbis.zig wins_dsound.zig; do
    cp "$REPO/native/$src" "$PROBE/$src"
done

# Point the two "not available" branches at the instrumented stubs. The public
# sources are untouched; only the probe copy is rewritten.
python3 - "$PROBE" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1])

stub = p / "instrumented_stubs.zig"
k = p / "winrun32.zig"

s = k.read_text()
s = s.replace('const msvcrt_mod = @import("winrun_msvcrt.zig");',
              'const msvcrt_mod = @import("winrun_msvcrt.zig");\n'
              'const probe_mod = @import("instrumented_stubs.zig");', 1)
# DirectSound
s = s.replace('''        std.debug.print("[WINS:winmm] dsound!{s} is not available\\n", .{name});
        return null;''',
              '''        if (std.mem.eql(u8, name, "DirectSoundCreate8")) return @ptrCast(&probe_mod.DirectSoundCreate8);
        if (std.mem.eql(u8, name, "DirectSoundCreate")) return @ptrCast(&probe_mod.DirectSoundCreate);''', 1)
# libvorbisfile
s = s.replace('''        std.debug.print("[WINS:winmm] libvorbisfile!{s} is not available\\n", .{name});
        return null;''',
              '''        if (std.mem.eql(u8, name, "ov_clear")) return @ptrCast(&probe_mod.ov_clear);
        if (std.mem.eql(u8, name, "ov_seekable")) return @ptrCast(&probe_mod.ov_seekable);
        if (std.mem.eql(u8, name, "ov_pcm_total")) return @ptrCast(&probe_mod.ov_pcm_total);
        if (std.mem.eql(u8, name, "ov_info")) return @ptrCast(&probe_mod.ov_info);
        if (std.mem.eql(u8, name, "ov_read")) return @ptrCast(&probe_mod.ov_read);
        if (std.mem.eql(u8, name, "ov_open_callbacks")) return @ptrCast(&probe_mod.ov_open_callbacks);''', 1)
k.write_text(s)
print("probe sources rewritten")
PY

# The Steam gate is neutralised IN THE PROBE COPY ONLY. This is the lab being
# deliberately unsafe to observe a call flow; the public loader keeps the gate,
# and tools/separation_gate.sh proves the shipped artifact still has it.
python3 - "$PROBE" <<'PY2'
import sys, pathlib
p = pathlib.Path(sys.argv[1]) / "winrun32.zig"
s = p.read_text()
old = """fn steamClientLive() bool {"""
new = """fn steamClientLive() bool { return true; }  // PROBE ONLY: gate neutralised

fn steamClientLivePublic() bool {"""
assert old in s
s = s.replace(old, new, 1)
p.write_text(s)
print("probe: Steam gate neutralised (local copy only)")
PY2

python3 "$REPO/tools/patch_probe_nostart.py" "$PROBE"
python3 "$REPO/tools/patch_probe_steam.py" "$PROBE"
python3 "$REPO/tools/patch_probe_dump.py" "$PROBE"
python3 "$REPO/tools/patch_probe_wait.py" "$PROBE"
python3 "$REPO/tools/patch_probe_abort.py" "$PROBE"

# Dynamic glibc i386, not static: the honest bridge needs dlopen to load the
# REAL Steam client, and a static build cannot dlopen at all (measured:
# glibc answers "Dynamic loading not supported"). Verified equivalent to
# the static build on the 7zr oracle: byte-identical output.
#
# --image-base 0x2000000 is load-bearing, not cosmetic. The guest's PE image
# is mapped at 0x00400000 and is 16.5 MB wide, so it owns [0x400000, 0x147b000).
# The kernel places the process's brk heap at a RANDOMISED address just above
# the executable and grows it upward, so that heap lands inside the guest's
# window in roughly half of all runs -- and the guest's image is mapped
# MAP_FIXED, which silently replaces it. Measured: the real Steam client's
# heap was destroyed that way and the client aborted later inside its own
# malloc with "malloc(): unaligned tcache chunk detected".
# The kernel derives start_brk from the LAST PT_LOAD of the executable, so
# loading the loader itself above the guest's window puts start_brk -- and
# therefore the heap -- permanently above it.
"$ZIG" build-exe "$PROBE/winrun32.zig" -target x86-linux-gnu.2.39 -mcpu=i386 -O ReleaseFast -lc -dynamic \
    --image-base 0x2000000 --name winrun32_probe -femit-bin="$OUT"

echo "probe loader built: $OUT"
echo "NOTE: measurement only. Never publish native/probe/ or this binary."
