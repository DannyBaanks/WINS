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
#   G4  a clean build still reports the unimplemented APIs honestly (it does NOT
#       claim them as implemented)
#
# If any gate fails, the published artifact still depends on the lab.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
ZIG="${ZIG:-/home/danny/.local/opt/zig-x86_64-linux-0.16.0/zig}"
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
if ! "$ZIG" build-exe "$REPO/native/winrun32.zig" -target x86-linux-gnu.2.39 -mcpu=i386 \
        -O ReleaseFast -lc -dynamic --name winrun32 -femit-bin="$WORK/winrun32" 2>"$WORK/build.log"; then
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
if nm "$WORK/winrun32" 2>/dev/null | grep -qi "probe\|instrumented_stub"; then
    note "FAIL: probe symbols linked in"; nm "$WORK/winrun32" | grep -i probe | head -5; fail=1
else
    note "ok: no probe symbols"
fi
if strings "$WORK/winrun32" | grep -q '\[probe\]'; then
    note "FAIL: probe trace strings linked in"; strings "$WORK/winrun32" | grep '\[probe\]' | head -5; fail=1
else
    note "ok: no probe trace strings"
fi

echo "== G4: a clean build reports unimplemented APIs honestly"
out="$(cd "$WORK" && "$WORK/winrun32" --check \
        "/home/danny/.local/share/Steam/steamapps/common/Fallout New Vegas/FalloutNV.exe" 2>&1)"
if ! printf '%s' "$out" | grep -q 'Check FAILED'; then
    note "FAIL: the clean build does not report the unimplemented imports"
    fail=1
else
    missing="$(printf '%s' "$out" | grep -c 'UNRESOLVED' || true)"
    note "ok: reports Check FAILED with ${missing} unresolved slot(s) still listed"
fi
# What is implemented, and what the artifact is not allowed to claim.
#
# libvorbisfile is bridged to the REAL i386 library, so it is resolved. DirectSound
# is not implemented, so it must still be listed as unresolved: an artifact that
# claims a device it does not have is the same failure mode as the dummy Steam
# vtables the DRM rejected.
if printf '%s' "$out" | grep -qi 'UNRESOLVED libvorbisfile'; then
    note "FAIL: the vorbis bridge regressed; libvorbisfile is unresolved again"
    fail=1
else
    note "ok: libvorbisfile resolves to the real i386 library"
fi
if printf '%s' "$out" | grep -qi 'UNRESOLVED DSOUND\|UNRESOLVED dsound'; then
    note "ok: DirectSound still reported unresolved, not claimed"
else
    note "FAIL: the build claims DirectSound, which is not implemented"
    fail=1
fi
if printf '%s' "$out" | grep -qiE 'DirectSoundCreate8.*implemented|ov_read.*implemented'; then
    note "FAIL: the clean build claims a capability it does not have"
    fail=1
fi

echo
if [[ $fail -eq 0 ]]; then
    echo "SEPARATION GATE: PASSED - the published artifact does not depend on native/probe/"
    exit 0
fi
echo "SEPARATION GATE: FAILED - the lab is still load-bearing; do not publish"
exit 1
