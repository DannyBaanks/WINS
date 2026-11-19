#!/usr/bin/env bash
# Install the WINS Cuphead Steam compatibility tool.
#
# Usage: launch/cuphead/install.sh BUILD_DIR [COMPAT_TOOLS_DIR]
#   BUILD_DIR          a directory containing the Win64 loader executable
#                      "winrun64" (see README.txt for the build command).
#   COMPAT_TOOLS_DIR   default: ~/.steam/root/compatibilitytools.d
#
# Installs into <COMPAT_TOOLS_DIR>/WINS-Cuphead. Nothing is ever deleted: a file
# that would be replaced by different content is first copied to <name>.prev-<12
# hex of its sha256>. Restart Steam once after the first install so it finds the
# tool.
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
B="${1:-}"
[[ -n "$B" && -x "$B/winrun64" ]] || {
    echo "usage: $0 BUILD_DIR [COMPAT_TOOLS_DIR]   (BUILD_DIR must contain winrun64)" >&2
    exit 2
}
B="$(cd -- "$B" && pwd)"
root="${2:-${HOME:?HOME is not set}/.steam/root/compatibilitytools.d}"
dest="$root/WINS-Cuphead"
mkdir -p "$dest/dist"

# install SRC DST MODE
install_file() {
    local src="$1" dst="$2" mode="$3"
    if [[ -e "$dst" ]] && ! cmp -s -- "$src" "$dst"; then
        local old
        old="$(sha256sum -- "$dst" | awk '{print substr($1,1,12)}')"
        cp -p -- "$dst" "$dst.prev-$old"
        echo "kept the previous $(basename -- "$dst") as $(basename -- "$dst").prev-$old"
    fi
    cp -- "$src" "$dst.new"
    chmod "$mode" "$dst.new"
    mv -f -- "$dst.new" "$dst"
}

install_file "$here/launch-cuphead"      "$dest/launch-cuphead"      755
install_file "$here/wins"                "$dest/wins"                755
install_file "$here/compatibilitytool.vdf" "$dest/compatibilitytool.vdf" 644
install_file "$here/toolmanifest.vdf"    "$dest/toolmanifest.vdf"    644
install_file "$here/README.txt"          "$dest/README.txt"          644
install_file "$B/winrun64"               "$dest/dist/winrun64"       755
if [[ -f "$B/MANIFEST.tsv" ]]; then
    install_file "$B/MANIFEST.tsv" "$dest/dist/MANIFEST.tsv" 644
else
    # Record the exact loader payload even when the repository-wide build did
    # not emit a library manifest. Generate it outside the destination and use
    # install_file so an existing manifest is backed up rather than replaced
    # without a recoverable copy.
    manifest_tmp="$(mktemp "$dest/dist/.MANIFEST.tsv.XXXXXX")"
    trap 'rm -f -- "$manifest_tmp"' EXIT
    printf 'winrun64\t%s\n' "$(sha256sum -- "$dest/dist/winrun64" | awk '{print $1}')" \
        > "$manifest_tmp"
    chmod 644 "$manifest_tmp"
    install_file "$manifest_tmp" "$dest/dist/MANIFEST.tsv" 644
    rm -f -- "$manifest_tmp"
    trap - EXIT
fi

echo "installed WINS-Cuphead in $dest"
echo "loader sha256: $(sha256sum -- "$dest/dist/winrun64" | awk '{print $1}')"
echo "In Steam: Cuphead > Properties > Compatibility > force 'WINS (Cuphead)'."
