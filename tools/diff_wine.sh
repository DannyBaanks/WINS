#!/usr/bin/env bash
# Differential check: run one Win32 console exe under Wine (the oracle) and under
# winrun32, and compare stdout and exit code byte for byte.
#
#   tools/diff_wine.sh LOADER EXE [WORKDIR]
#
# LOADER  a winrun32 built by tools/build_all.sh
# EXE     a deterministic console program (see native/testdata/thread_probe.c)
# WORKDIR scratch directory (default: a new directory under ~/.cache/wins-diff)
#
# Wine side: Proton's `proton run cmd.exe /c "EXE > C:\out & echo %errorlevel% > C:\rc"`
# inside a prefix you point at with WINS_ORACLE_COMPAT (STEAM_COMPAT_DATA_PATH) and
# WINS_ORACLE_PROTON (the proton script). Nothing outside WORKDIR and that prefix is
# written. WINS side: the exe runs inside bubblewrap with no network and a tmpfs /tmp.
set -u
LOADER="$(readlink -f "${1:?loader}")"; EXE="$(readlink -f "${2:?exe}")"
WORK="${3:-$HOME/.cache/wins-diff/$(date +%s)}"; mkdir -p "$WORK"
COMPAT="${WINS_ORACLE_COMPAT:?set WINS_ORACLE_COMPAT (STEAM_COMPAT_DATA_PATH of a scratch prefix)}"
PROTON="${WINS_ORACLE_PROTON:?set WINS_ORACLE_PROTON (path to the proton script)}"
STEAM="${WINS_ORACLE_STEAM:-$HOME/.local/share/Steam}"

# --- oracle ---
cp "$EXE" "$WORK/probe.exe"
rm -f "$COMPAT/pfx/drive_c/dw.out" "$COMPAT/pfx/drive_c/dw.rc"
STEAM_COMPAT_DATA_PATH="$COMPAT" STEAM_COMPAT_CLIENT_INSTALL_PATH="$STEAM" WINEDEBUG=-all \
  timeout 120 "$PROTON" run cmd.exe /c "Z:$(printf '%s' "$WORK/probe.exe" | tr / '\\') > C:\\dw.out & echo %errorlevel% > C:\\dw.rc" >/dev/null 2>&1
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$COMPAT/pfx/drive_c/dw.rc" ] && break; sleep 2; done
tr -d '\r' < "$COMPAT/pfx/drive_c/dw.out" > "$WORK/wine.out" 2>/dev/null
tr -d '\r\n ' < "$COMPAT/pfx/drive_c/dw.rc" > "$WORK/wine.rc" 2>/dev/null

# --- WINS ---
timeout 120 bwrap --unshare-all --die-with-parent --new-session --clearenv \
  --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
  --proc /proc --dev /dev --tmpfs /tmp --ro-bind "$LOADER" /work/winrun32 --ro-bind "$WORK/probe.exe" /work/probe.exe \
  --chdir /work /work/winrun32 --run /work/probe.exe > "$WORK/wins.out" 2> "$WORK/wins.err"
echo $? > "$WORK/wins.rc"

# --- verdict ---
if cmp -s "$WORK/wine.out" "$WORK/wins.out" && [ "$(cat "$WORK/wine.rc")" = "$(cat "$WORK/wins.rc")" ] && [ -s "$WORK/wine.out" ]; then
  echo "IDENTICAL: $(wc -l < "$WORK/wins.out") lines, exit $(cat "$WORK/wins.rc")  ($WORK)"; exit 0
fi
echo "DIFFERENT (exit wine=$(cat "$WORK/wine.rc") wins=$(cat "$WORK/wins.rc")); work dir: $WORK"
diff "$WORK/wine.out" "$WORK/wins.out" | head -40; exit 1
