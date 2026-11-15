#!/usr/bin/env bash
# Check the library registry against the repository.
#
# Usage: tools/check_libs.sh BUILD_DIR     (BUILD_DIR from tools/build_all.sh)
#
# Fails (exit 1) when:
#   - a source file named in the registry does not exist, or
#   - libs/registry.json is not what `winrun32 --libs` prints (native/wins_libs.zig
#     was edited without regenerating: run tools/gen_libs.sh).
# Advises (exit 0) when a library's source files changed in git after the registry
# was last edited, which is when its version may need a bump.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
B="${1:-}"
[[ -n "$B" && -x "$B/winrun32" ]] || { echo "usage: $0 BUILD_DIR" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

fail=0
live="$("$B/winrun32" --libs)"

while IFS= read -r src; do
    [[ -e "$REPO/$src" ]] || { echo "FAIL missing source in registry: $src" >&2; fail=1; }
done < <(jq -r '.libraries[].sources[]' <<<"$live" | sort -u)

if ! diff -q <(jq -S . <<<"$live") <(jq -S . "$REPO/libs/registry.json") >/dev/null; then
    echo "FAIL libs/registry.json is stale: it differs from 'winrun32 --libs'. Run tools/gen_libs.sh." >&2
    fail=1
fi

reg_time="$(git -C "$REPO" log -1 --format=%ct -- native/wins_libs.zig 2>/dev/null || echo 0)"
stale=""
while IFS=$'\t' read -r name srcs; do
    # shellcheck disable=SC2086
    t="$(git -C "$REPO" log -1 --format=%ct -- $srcs 2>/dev/null || echo 0)"
    [[ -n "$t" && "$t" -gt "${reg_time:-0}" ]] && stale+="$name "
done < <(jq -r '.libraries[] | [.name, (.sources | join(" "))] | @tsv' <<<"$live")
[[ -z "$stale" ]] || echo "NOTE sources changed after the last registry edit (bump the version if behaviour changed): $stale"

[[ "$fail" -eq 0 ]] && echo "libs OK: $(jq '.libraries | length' <<<"$live") libraries, registry.json current"
exit "$fail"
