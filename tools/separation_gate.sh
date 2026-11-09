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
        | grep -v '^'"$REPO"'/native/probe/' | grep -v 'build_probe.sh' | grep -v 'separation_gate.sh' | grep -v 'patch_probe_dump.py' | grep -q .; then
    note "FAIL: a public source mentions the lab"; grep -rn "native/probe\|instrumented_stubs" \
        "$REPO/native" --include='*.zig' | grep -v '/native/probe/' | head -5
    fail=1
else
    note "ok: no references outside tools/build_probe.sh"
fi

echo "== G2: clean build without native/probe/"
if [[ -d "$REPO/native/probe" ]]; then
    mv "$REPO/native/probe" "$WORK/probe-hidden"
    note "(probe directory temporarily moved away)"
fi
if ! "$ZIG" build-exe "$REPO/native/winrun32.zig" -target x86-linux -mcpu=i386 -O ReleaseFast \
        --name winrun32 -femit-bin="$WORK/winrun32" 2>"$WORK/build.log"; then
    note "FAIL: clean build does not compile"; head -8 "$WORK/build.log"; fail=1
else
    note "ok: compiles with the lab absent"
fi
if [[ -d "$WORK/probe-hidden" ]]; then
    mv "$WORK/probe-hidden" "$REPO/native/probe"
    note "(probe directory restored)"
fi
[[ -x "$WORK/winrun32" ]] || { note "FAIL: no binary produced"; exit 1; }

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
if printf '%s' "$out" | grep -qiE 'DirectSoundCreate8.*implemented|ov_read.*implemented'; then
    note "FAIL: the clean build claims a capability it does not have"
    fail=1
else
    note "ok: claims no implemented DirectSound/Vorbis capability"
fi

echo
if [[ $fail -eq 0 ]]; then
    echo "SEPARATION GATE: PASSED - the published artifact does not depend on native/probe/"
    exit 0
fi
echo "SEPARATION GATE: FAILED - the lab is still load-bearing; do not publish"
exit 1
