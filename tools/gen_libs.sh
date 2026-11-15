#!/usr/bin/env bash
# Regenerate libs/registry.json and libs/GAPS.md (and libs/gaps.tsv) from the loaders.
#
# What this answers: which Windows DLLs does WINS have a library for, and for the
# programs measured, which imports does it still lack. Every number comes from
# running the loaders on the given images; nothing is written by hand.
#
# Usage: tools/gen_libs.sh BUILD_DIR [PE ...]
#   BUILD_DIR  a directory made by tools/build_all.sh (needs winrun32 and winrun;
#              winrun_gui is used for windowed x86-64 programs when present).
#   PE ...     images to measure. Default: corpus/*.exe and corpus/*.dll that exist.
#
# Nothing measured is executed: winrun32 --imports and winrun --check only map the
# image and resolve its import table. Treat the images as untrusted data.
#
# Measured: i386 PE32 through winrun32 (every import slot); x86-64 PE32+ through
# winrun (console) or winrun_gui (window) with --check (the unresolved imports and
# the total). NOT measured: anything those loaders refuse before resolving imports
# (delay-import tables, DLLs, a missing sha), and anything that is not a PE; the
# report says which and why.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
B="${1:-}"
[[ -n "$B" && -x "$B/winrun32" && -x "$B/winrun" ]] || {
    echo "usage: $0 BUILD_DIR [PE ...]   (BUILD_DIR from tools/build_all.sh, with winrun32 and winrun)" >&2
    exit 2
}
B="$(cd "$B" && pwd)"
shift
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

if [[ $# -gt 0 ]]; then
    IMAGES=("$@")
else
    IMAGES=()
    for f in "$REPO"/corpus/*.exe "$REPO"/corpus/*.dll; do [[ -e "$f" ]] && IMAGES+=("$f"); done
fi

W="$(mktemp -d "${TMPDIR:-/tmp}/wins-libs.XXXXXX")"
trap 'rm -rf -- "$W"' EXIT

# 1. The registry, from the binary itself.
"$B/winrun32" --libs > "$W/registry.json"
jq -e '.libraries | length > 0' "$W/registry.json" >/dev/null
cp "$W/registry.json" "$REPO/libs/registry.json"

# dll -> library, version  (lowercase, with .dll)
jq -r '.libraries[] | .name as $n | .version as $v | .dlls[] | [., $n, $v] | @tsv' "$W/registry.json" > "$W/dllmap.tsv"

# 2. Measure.
: > "$W/rows.tsv"      # program sha loader dll symbol resolved(1|0)
: > "$W/programs.tsv"  # program sha loader result slots unresolved note
for img in "${IMAGES[@]}"; do
    [[ -f "$img" ]] || { echo "skip (not a file): $img" >&2; continue; }
    real="$(readlink -f -- "$img")"
    name="$(basename -- "$real")"
    sha="$(sha256sum -- "$real" | cut -c1-12)"
    full="$(sha256sum -- "$real" | cut -d' ' -f1)"
    out32="$(timeout 60 "$B/winrun32" --imports "$real" 2>&1 </dev/null || true)"
    if grep -q '^WINS_IMPORT ' <<<"$out32"; then
        grep '^WINS_IMPORT ' <<<"$out32" | sed 's/^WINS_IMPORT //' |
            jq -r --arg p "$name" --arg s "$sha" '[$p, $s, "winrun32", (.dll | ascii_downcase), .symbol, (if .resolved then "1" else "0" end)] | @tsv' >> "$W/rows.tsv"
        slots="$(grep -c '^WINS_IMPORT ' <<<"$out32")"
        unres="$(grep '^WINS_IMPORT ' <<<"$out32" | grep -c '"resolved":false' || true)"
        printf '%s\t%s\twinrun32\tmeasured\t%s\t%s\t\n' "$name" "$sha" "$slots" "$unres" >> "$W/programs.tsv"
        continue
    fi
    if grep -q 'expected i386' <<<"$out32"; then
        loader=winrun
        out64="$(timeout 60 "$B/winrun" --sha256 "$full" --check "$real" 2>&1 </dev/null || true)"
        if grep -q 'is not console' <<<"$out64" && [[ -x "$B/winrun_gui" ]]; then
            loader=winrun_gui
            out64="$(timeout 60 "$B/winrun_gui" --sha256 "$full" --check "$real" 2>&1 </dev/null || true)"
        fi
        if grep -q '^winrun: READY' <<<"$out64"; then
            n="$(sed -n 's/.*imports=\([0-9]*\).*/\1/p' <<<"$out64" | head -1)"
            printf '%s\t%s\t%s\tmeasured\t%s\t0\tall resolved; --check gives no per-DLL breakdown\n' "$name" "$sha" "$loader" "$n" >> "$W/programs.tsv"
        elif grep -q 'unresolved imports' <<<"$out64"; then
            grep -E '^  [^ ]+![^ ]+' <<<"$out64" | sed -E 's/^  //; s/ \(by ordinal\)$//' |
                awk -F'!' -v p="$name" -v s="$sha" -v l="$loader" '{ d=tolower($1); sym=$0; sub(/^[^!]*!/, "", sym); printf "%s\t%s\t%s\t%s\t%s\t0\n", p, s, l, d, sym }' >> "$W/rows.tsv"
            u="$(grep -cE '^  [^ ]+![^ ]+' <<<"$out64" || true)"
            printf '%s\t%s\t%s\tmeasured\t\t%s\tunresolved only; the total of resolved imports is not reported on this path\n' "$name" "$sha" "$loader" "$u" >> "$W/programs.tsv"
        else
            why="$(grep -m1 '^winrun:' <<<"$out64" | cut -c1-110 || true)"
            printf '%s\t%s\t%s\tnot measured\t\t\t%s\n' "$name" "$sha" "$loader" "${why:-no answer}" >> "$W/programs.tsv"
        fi
        continue
    fi
    why="$(grep -m1 -E 'Error|cannot read|Not a valid' <<<"$out32" | cut -c1-110 || true)"
    printf '%s\t%s\twinrun32\tnot measured\t\t\t%s\n' "$name" "$sha" "${why:-no answer}" >> "$W/programs.tsv"
done

# 3. Raw gap list: one row per distinct unresolved import.
awk -F'\t' 'BEGIN{OFS="\t"}
    NR==FNR { lib[$1]=$2; next }
    $6=="0" {
        d=$4; key=d "\t" $5
        if (!(key in seen)) { seen[key]=0; order[++n]=key }
        pk=key SUBSEP $1
        if (!(pk in pseen)) { pseen[pk]=1; seen[key]++ }
    }
    END {
        print "library", "dll", "symbol", "programs"
        for (i=1;i<=n;i++) { split(order[i], a, "\t"); l=(a[1] in lib)?lib[a[1]]:"(no WINS library)"; print l, a[1], a[2], seen[order[i]] }
    }' "$W/dllmap.tsv" "$W/rows.tsv" | { read -r head; echo "$head"; sort -t$'\t' -k1,1 -k2,2 -k3,3; } > "$REPO/libs/gaps.tsv"

# 4. The readable report.
REV="$(git -C "$REPO" rev-parse --short HEAD)"
{
    echo "# WINS library gaps"
    echo
    echo "Generated by \`tools/gen_libs.sh\` from WINS \`$REV\`. Do not edit: run the script. Every figure below"
    echo "was produced by running the loaders on the images listed; none is written by hand."
    echo
    echo "**What this is not.** A resolved import means WINS has an answer for that name, not that the program"
    echo "then behaves as on Windows (see \`status\` in \`registry.json\` for what has actually been run)."
    echo "An unresolved import means the loader refuses to run the image (or binds a null stub with"
    echo "\`--ignore-missing-imports\`)."
    echo
    echo "## Programs measured"
    echo
    echo "| program | sha256 (12) | loader | result | imports | unresolved | note |"
    echo "|---|---|---|---|---|---|---|"
    awk -F'\t' '{ printf "| %s | %s | %s | %s | %s | %s | %s |\n", $1, $2, $3, $4, ($5==""?"?":$5), ($6==""?"-":$6), $7 }' "$W/programs.tsv"
    echo
    echo "## Windows DLLs these programs import that WINS has no library for"
    echo
    echo "A DLL listed here is what is missing compared to Windows. \"Resolved by name\" counts imports of it that"
    echo "still resolved because the loader's fall-through tables answer by symbol name regardless of the DLL"
    echo "(the C runtime under another DLL name, for instance); those answers are unattributed."
    echo
    echo "| DLL | programs | import slots | resolved by name | unresolved |"
    echo "|---|---|---|---|---|"
    awk -F'\t' '
        NR==FNR { lib[$1]=1; next }
        !($4 in lib) {
            d=$4; slots[d]++; if ($6=="1") res[d]++; else un[d]++
            k=d SUBSEP $1; if (!(k in ps)) { ps[k]=1; progs[d]++ }
            if (!(d in seen)) { seen[d]=1; order[++n]=d }
        }
        END { for (i=1;i<=n;i++) { d=order[i]; printf "| `%s` | %d | %d | %d | %d |\n", d, progs[d], slots[d], res[d]+0, un[d]+0 } }
    ' "$W/dllmap.tsv" "$W/rows.tsv" | sort
    echo
    echo "An empty table does **not** mean nothing is missing: only i386 programs and x86-64 programs that have"
    echo "unresolved imports give a per-DLL view, and programs listed above as not measured contribute nothing."
    echo
    echo "## Unresolved imports of DLLs WINS has a library for"
    echo
    echo "The work list per library. The complete list is in \`libs/gaps.tsv\`."
    echo
    awk -F'\t' '
        NR==FNR { lib[$1]=$2 " " $3; next }
        $6=="0" && ($4 in lib) {
            l=lib[$4]; key=l SUBSEP $5
            if (!(key in seen)) { seen[key]=1; cnt[l]++; items[l]=items[l] "\n" $5 }
            if (!(l in lseen)) { lseen[l]=1; order[++n]=l }
        }
        END {
            for (i=1;i<=n;i++) {
                l=order[i]; printf "### %s — %d unresolved\n\n", l, cnt[l]
                m=split(items[l], a, "\n"); shown=0
                for (j=2;j<=m && shown<30;j++) { printf "- `%s`\n", a[j]; shown++ }
                if (cnt[l]>30) printf "- … and %d more\n", cnt[l]-30
                printf "\n"
            }
            if (n==0) print "None in the programs measured.\n"
        }
    ' "$W/dllmap.tsv" "$W/rows.tsv"
    echo "## Libraries"
    echo
    echo "| library | version | status | Windows DLLs | loaders |"
    echo "|---|---|---|---|---|"
    jq -r '.libraries[] | "| \(.name) | \(.version) | \(.status) | \(.dlls | map("`" + . + "`") | join(", ")) | \(.loaders | join(", ")) |"' "$W/registry.json"
} > "$REPO/libs/GAPS.md"

echo "wrote libs/registry.json, libs/GAPS.md, libs/gaps.tsv from $B (WINS $REV)"
