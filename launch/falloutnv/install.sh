#!/usr/bin/env bash
# Install the WINS Fallout: New Vegas Steam compatibility tool.
#
# Usage: launch/falloutnv/install.sh BUILD_DIR [COMPAT_TOOLS_DIR]
#   BUILD_DIR          a directory made by tools/build_all.sh (needs winrun32).
#   COMPAT_TOOLS_DIR   default: ~/.steam/root/compatibilitytools.d
#
# Installs into <COMPAT_TOOLS_DIR>/WINS-FalloutNV. Nothing is ever deleted: a file
# that would be replaced by different content is first copied to <name>.prev-<12
# hex of its sha256>. Restart Steam once after the first install so it finds the tool.
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
B="${1:-}"
[[ -n "$B" && -x "$B/winrun32" ]] || { echo "usage: $0 BUILD_DIR [COMPAT_TOOLS_DIR]   (BUILD_DIR from tools/build_all.sh)" >&2; exit 2; }
B="$(cd "$B" && pwd)"
root="${2:-${HOME:?HOME is not set}/.steam/root/compatibilitytools.d}"
dest="$root/WINS-FalloutNV"
mkdir -p "$dest/dist"

# install SRC DST MODE
install_file() {
    local src="$1" dst="$2" mode="$3"
    if [[ -e "$dst" ]] && ! cmp -s "$src" "$dst"; then
        local old
        old="$(sha256sum -- "$dst" | cut -c1-12)"
        cp -p -- "$dst" "$dst.prev-$old"
        echo "kept the previous $(basename "$dst") as $(basename "$dst").prev-$old"
    fi
    cp -- "$src" "$dst.new"
    chmod "$mode" "$dst.new"
    mv -f -- "$dst.new" "$dst"     # a running game keeps the old inode
}

install_file "$here/launch-falloutnv"       "$dest/launch-falloutnv"       755
install_file "$here/wins"                   "$dest/wins"                   755
install_file "$here/compatibilitytool.vdf"  "$dest/compatibilitytool.vdf"  644
install_file "$here/toolmanifest.vdf"       "$dest/toolmanifest.vdf"       644
install_file "$here/README.txt"             "$dest/README.txt"             644
install_file "$B/winrun32"                  "$dest/dist/winrun32"          755
[[ -f "$B/MANIFEST.tsv" ]] && install_file "$B/MANIFEST.tsv" "$dest/dist/MANIFEST.tsv" 644

echo "installed WINS-FalloutNV in $dest"
echo "loader: $(sha256sum -- "$dest/dist/winrun32" | cut -c1-12)  libraries: $("$dest/dist/winrun32" --libs | jq -r '[.libraries[] | select(.status == "exercised") | .name] | length') exercised"
echo "In Steam: Fallout: New Vegas > Properties > Compatibility > force 'WINS (Fallout: New Vegas)'."
