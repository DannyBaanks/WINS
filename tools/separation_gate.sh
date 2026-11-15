#!/usr/bin/env bash
# SEPARATION GATE: proves the published product does not depend on the
# measurement laboratory.
#
# .gitignore only stops accidental commits; it does not prove anything about the
# artifact. This gate checks the four things that actually matter:
#
#   G1  the public sources never reference native/probe/
#   G2  a clean build WITHOUT that directory still compiles
#   G3  the resulting binary contains no probe symbols or probe-only strings
#   G4  a clean build resolves what it implements, and its remaining limitation
#       stays stated (it does NOT claim a capability it lacks)
#
# If any gate fails, the published artifact still depends on the lab.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
ZIG="${ZIG:-zig}"
WORK="$(mktemp -d /tmp/wins-gate.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

fail=0
note() { printf '  %s\n' "$1"; }

echo "== G1: no public source references the probe directory"
if grep -rn "native/probe\|instrumented_stubs\|winrun32_probe\|\[probe\]" \
        "$REPO/native" "$REPO/tools" "$REPO/core" "$REPO/bin" \
        --include='*.zig' --include='*.py' --include='*.sh' 2>/dev/null \
        | grep -v '^'"$REPO"'/native/probe/' \
        | grep -v 'build_probe.sh' | grep -v 'separation_gate.sh' \
        | grep -v 'patch_probe' \
        | grep -q .; then
    note "FAIL: a public source mentions the lab"; grep -rn "native/probe\|instrumented_stubs" \
        "$REPO/native" --include='*.zig' | grep -v '/native/probe/' | head -5
    fail=1
else
    note "ok: no references outside the lab generator scripts"
fi

echo "== G2: clean build without native/probe/"
if [[ -d "$REPO/native/probe" ]]; then
    mv "$REPO/native/probe" "$WORK/probe-hidden"
    note "(probe directory temporarily moved away)"
fi
# The published artifact is the DYNAMIC glibc i386 build: the Steam bridge has
# to dlopen the real client, and a static build answers dlopen with "dynamic
# loading not supported". Measured; that was the reason an earlier conclusion
# recorded the client as unloadable. A build that is not dynamic cannot carry
# the bridge, so the gate builds what is shipped and asserts the linkage rather
# than assuming it.
# --image-base 0x2000000 must match the shipped build exactly (see
# tools/build_probe.sh for why it is load-bearing): the gate has to build what
# is shipped, not a variant of it.
if ! "$ZIG" build-exe "$REPO/native/winrun32.zig" -target x86-linux-gnu.2.39 -mcpu=i386 \
        -O ReleaseFast -lc -dynamic --image-base 0x2000000 --name winrun32 \
        -femit-bin="$WORK/winrun32" 2>"$WORK/build.log"; then
    note "FAIL: clean build does not compile"; head -8 "$WORK/build.log"; fail=1
else
    note "ok: compiles with the lab absent"
fi
if [[ -d "$WORK/probe-hidden" ]]; then
    mv "$WORK/probe-hidden" "$REPO/native/probe"
    note "(probe directory restored)"
fi
[[ -x "$WORK/winrun32" ]] || { note "FAIL: no binary produced"; exit 1; }

if ! readelf -l "$WORK/winrun32" 2>/dev/null | grep -q "/lib/ld-linux.so.2"; then
    note "FAIL: the shipped artifact is not dynamic glibc i386; the Steam bridge needs dlopen"
    fail=1
else
    note "ok: dynamic glibc i386, so the real client can be loaded"
fi

echo "== G3: the shipped binary carries no probe instrumentation"
# nm/strings run to a file first: with `set -o pipefail`, `producer | grep -q`
# reports 141 (SIGPIPE) as soon as grep finds the first match, which would make
# a PASSING check look like a failure.
nm "$WORK/winrun32" > "$WORK/nm.txt" 2>/dev/null || true
strings "$WORK/winrun32" > "$WORK/strings.txt" 2>/dev/null || true
if grep -qi "probe\|instrumented_stub" "$WORK/nm.txt"; then
    note "FAIL: probe symbols linked in"; grep -i probe "$WORK/nm.txt" | head -5; fail=1
else
    note "ok: no probe symbols"
fi
if grep -q '\[probe\]' "$WORK/strings.txt"; then
    note "FAIL: probe trace strings linked in"; grep '\[probe\]' "$WORK/strings.txt" | head -5; fail=1
else
    note "ok: no probe trace strings"
fi

echo "== G4: a clean build resolves what it implements, and claims nothing more"
out="$(cd "$WORK" && "$WORK/winrun32" --check \
        "$HOME/.local/share/Steam/steamapps/common/Fallout New Vegas/FalloutNV.exe" 2>&1)"
if printf '%s' "$out" | grep -q 'Check PASSED'; then
    note "ok: every import of the Steam exe resolves, DSOUND ordinal 11 included"
else
    note "FAIL: the clean build leaves imports unresolved"
    printf '%s\n' "$out" | grep 'UNRESOLVED' | head -5
    fail=1
fi
# What is implemented, and what the artifact is not allowed to claim.
#
# libvorbisfile is bridged to the REAL i386 library, so it is resolved.
# DirectSound is implemented (COM objects over memory-backed buffers) and so it
# resolves too -- but the claim must be backed by code inside the shipped
# binary, and the limitation that remains (no PCM reaches a device) must stay
# written down. A mute device presented as a working one is the same failure
# mode as the dummy Steam vtables the DRM rejected.
if printf '%s' "$out" | grep -qi 'UNRESOLVED libvorbisfile'; then
    note "FAIL: the vorbis bridge regressed; libvorbisfile is unresolved again"
    fail=1
else
    note "ok: libvorbisfile resolves to the real i386 library"
fi
if printf '%s' "$out" | grep -qi 'UNRESOLVED DSOUND\|UNRESOLVED dsound'; then
    note "FAIL: DirectSound regressed to unresolved"
    fail=1
else
    note "ok: DirectSound resolves"
fi
if grep -q 'wins_dsound\.DirectSoundCreate' "$WORK/nm.txt"; then
    note "ok: the wins_dsound implementation is linked (Create8 folds into Create; the ordinal proof is the PASS above)"
else
    note "FAIL: DirectSound is claimed but its implementation is not in the binary"
    fail=1
fi
# The module must keep saying what it does not implement (a DirectSound that looked
# complete would hide that capture, effects and notifications are missing). The
# header used to say playback was silent; it no longer does, because a mixer exists.
if grep -q 'What is NOT implemented' "$REPO/native/wins_dsound.zig" &&
   grep -q 'DSERR_NODRIVER' "$REPO/native/wins_dsound.zig" &&
   grep -q 'IDirectSoundNotify' "$REPO/native/wins_dsound.zig"; then
    note "ok: the DirectSound limitations (capture, notify, effects) are still documented"
else
    note "FAIL: the DirectSound limitation note was removed; the module would look complete"
    fail=1
fi

echo
if [[ $fail -eq 0 ]]; then
    echo "SEPARATION GATE: PASSED - the published artifact does not depend on native/probe/"
    exit 0
fi
echo "SEPARATION GATE: FAILED - the lab is still load-bearing; do not publish"
exit 1
