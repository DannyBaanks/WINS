#!/usr/bin/env bash
# Build the shipped WINS native binaries from the CURRENT sources into a NEW
# directory and record exactly what was built.
#
# Why this exists: build/ and bin/ held binaries older than their sources (e.g. a
# winrun32 four days behind its source), so measurements were taken against code
# that no longer existed. Every binary here is paired in MANIFEST.tsv with the
# git revision and the SHA-256 of its source, so "which code produced this?" has
# an answer.
#
# Usage: tools/build_all.sh OUT_DIR      (OUT_DIR must not exist or be empty)
#
# It never overwrites an existing build: point it at a new directory.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZIG="${ZIG:-zig}"
OUT="${1:-}"
[[ -n "$OUT" ]] || { echo "usage: $0 OUT_DIR (new or empty)" >&2; exit 2; }
if [[ -e "$OUT" ]] && [[ -n "$(ls -A "$OUT" 2>/dev/null)" ]]; then
    echo "refusing: $OUT exists and is not empty" >&2; exit 2
fi
mkdir -p "$OUT"

REV="$(git -C "$REPO" rev-parse --short HEAD)"
DIRTY="$(git -C "$REPO" status --porcelain -- native | wc -l)"
ZIGV="$("$ZIG" version)"
MAN="$OUT/MANIFEST.tsv"
printf 'binary\tsource\tsource_sha256\tgit_rev\tnative_dirty_files\tzig\n' > "$MAN"

ok=0; bad=0
build() { # name source [extra zig args...]
    local name="$1" src="$2"; shift 2
    if "$ZIG" build-exe "$REPO/$src" "$@" --name "$name" -femit-bin="$OUT/$name" 2>"$OUT/$name.build.log"; then
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$src" \
            "$(sha256sum "$REPO/$src" | cut -d' ' -f1)" "$REV" "$DIRTY" "$ZIGV" >> "$MAN"
        rm -f "$OUT/$name.build.log"; echo "ok    $name"; ok=$((ok+1))
    else
        echo "FAIL  $name (see $OUT/$name.build.log)" >&2; bad=$((bad+1))
    fi
}

# x86-64 PE loader and the PE/installer inspection tools.
# -lc: the loader's extra_dlls socket stack (std.c.getenv trace/appdata reads)
# needs libc, like every other loader recipe in this repo (winrun64 -lc -lX11,
# winrun32 -lc -dynamic).
build winrun      native/winrun.zig  -O ReleaseSafe -lc
# The x86-64 loader for programs with a window; needs libX11 for the host window.
build winrun_gui  native/winrun_gui.zig -O ReleaseSafe -lc -lX11
build wins-native native/main.zig    -O ReleaseSafe
build wins-compare native/compare.zig -O ReleaseSafe -lc
# i386 PE loader: flags must match tools/separation_gate.sh (the shipped build);
# --image-base 0x2000000 is load-bearing.
build winrun32    native/winrun32.zig -target x86-linux-gnu.2.39 -mcpu=i386 \
                  -O ReleaseFast -lc -dynamic --image-base 0x2000000

echo "built=$ok failed=$bad  manifest=$MAN"
[[ "$bad" -eq 0 ]]
