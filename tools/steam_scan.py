#!/usr/bin/env python3
"""Discover Steam's installed games and connect each real exe to the WINS loader.

Read-only by design: it parses Steam's own manifests, finds the executables that
actually shipped, and asks the loader whether it can resolve that exe's imports.
It never edits a game directory, never patches an executable and never writes to
the Steam tree.

Why this exists: the game Steam maintains is the one Steam validates (CEG checks
the image, so a patched exe is refused). Launching WINS against the real exe is
the only path that keeps the DRM owner intact. That means WINS has to find the
exe itself instead of being pointed at a copy.

Usage:

    tools/steam_scan.py                       # every library, every app
    tools/steam_scan.py --app 22380           # one app
    tools/steam_scan.py --loader ./winrun32   # add the import-resolution check
    tools/steam_scan.py --json

The import check runs `<loader> --check "<exe>"` and reads the loader's own
verdict (PASS, or the number of unresolved import slots). Without --loader the
scan still reports what is installed, and says so instead of guessing.
"""
import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

# Installers and helpers that ship next to a game and are never the game.
NOISE = re.compile(
    r"(unins|setup|install|vc_?redist|dxsetup|dxwebsetup|dotnet|oalinst|"
    r"crashhandler|crashreport|updater|update|launcher_installer)",
    re.IGNORECASE,
)


def vdf_tokens(text):
    """Yield VDF tokens: quoted strings, braces, and bare words."""
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in " \t\r\n":
            i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
        elif c == "{":
            yield "{"
            i += 1
        elif c == "}":
            yield "}"
            i += 1
        elif c == '"':
            i += 1
            buf = []
            while i < n and text[i] != '"':
                if text[i] == "\\" and i + 1 < n:
                    buf.append(text[i + 1])
                    i += 2
                    continue
                buf.append(text[i])
                i += 1
            i += 1
            yield "".join(buf)
        else:
            start = i
            while i < n and text[i] not in ' \t\r\n{}"':
                i += 1
            yield text[start:i]


def vdf_parse(text):
    """Parse a VDF document into nested dicts. Later duplicate keys win."""
    stack = [{}]
    key = None
    for tok in vdf_tokens(text):
        if tok == "{":
            child = {}
            if key is not None:
                stack[-1][key] = child
            stack.append(child)
            key = None
        elif tok == "}":
            if len(stack) > 1:
                stack.pop()
            key = None
        else:
            if key is None:
                key = tok
            else:
                stack[-1][key] = tok
                key = None
    return stack[0]


def find_steam_roots(explicit):
    if explicit:
        return [pathlib.Path(explicit).expanduser()]
    roots = []
    env = os.environ.get("STEAM_ROOT")
    if env:
        roots.append(pathlib.Path(env).expanduser())
    roots += [
        pathlib.Path.home() / ".local/share/Steam",
        pathlib.Path.home() / ".steam/steam",
        pathlib.Path.home() / ".steam/root",
    ]
    seen, out = set(), []
    for r in roots:
        try:
            real = r.resolve()
        except OSError:
            continue
        if real.is_dir() and real not in seen:
            seen.add(real)
            out.append(r)
    return out


def library_paths(root):
    """Every library folder Steam knows about, the root included."""
    paths = [root]
    vdf = root / "steamapps/libraryfolders.vdf"
    if vdf.is_file():
        try:
            doc = vdf_parse(vdf.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            doc = {}
        libs = doc.get("libraryfolders", {}) or doc
        for key, val in libs.items():
            if isinstance(val, dict):
                p = val.get("path")
                if p:
                    paths.append(pathlib.Path(p))
            elif isinstance(val, str) and key.isdigit():
                paths.append(pathlib.Path(val))
    seen, out = set(), []
    for p in paths:
        try:
            real = p.expanduser().resolve()
        except OSError:
            continue
        if real not in seen and (real / "steamapps").is_dir():
            seen.add(real)
            out.append(real)
    return out


def read_apps(library):
    apps = []
    for acf in sorted((library / "steamapps").glob("appmanifest_*.acf")):
        try:
            doc = vdf_parse(acf.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        state = doc.get("AppState", doc)
        if not isinstance(state, dict):
            continue
        appid = state.get("appid") or acf.stem.split("_")[-1]
        apps.append(
            {
                "appid": str(appid),
                "name": state.get("name", ""),
                "installdir": state.get("installdir", ""),
                "stateflags": state.get("StateFlags", ""),
                "buildid": state.get("buildid", ""),
                "library": str(library),
                "manifest": str(acf),
            }
        )
    return apps


def candidates(app):
    """Executables shipped by the app, best guess first."""
    base = pathlib.Path(app["library"]) / "steamapps/common" / app["installdir"]
    if not base.is_dir():
        return []
    want = re.sub(r"[^a-z0-9]", "", (app["installdir"] or app["name"]).lower())
    found = []
    for path in base.rglob("*"):
        if path.suffix.lower() != ".exe" or not path.is_file():
            continue
        try:
            rel_depth = len(path.relative_to(base).parts)
        except ValueError:
            continue
        if rel_depth > 3:
            continue
        if NOISE.search(path.stem):
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        stem = re.sub(r"[^a-z0-9]", "", path.stem.lower())
        score = 0
        if want and (stem.startswith(want) or want.startswith(stem)):
            score += 100
        if "launcher" in stem:
            score -= 40
        if rel_depth == 1:
            score += 5
        # A game binary is normally the biggest thing in its directory.
        score += min(size // (8 * 1024 * 1024), 30)
        found.append({"path": str(path), "size": size, "score": score})
    found.sort(key=lambda c: (-c["score"], -c["size"], c["path"]))
    return found


def find_loader(explicit):
    if explicit:
        p = pathlib.Path(explicit).expanduser()
        return p if p.is_file() else None
    for cand in (
        pathlib.Path("winrun32"),
        pathlib.Path("zig-out/bin/winrun32"),
        pathlib.Path("build/winrun32"),
        pathlib.Path("/tmp/opencode/winrun32"),
    ):
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand.resolve()
    env = os.environ.get("WINS_LOADER")
    if env:
        p = pathlib.Path(env).expanduser()
        if p.is_file():
            return p
    return None


def loader_check(loader, exe):
    """Ask the loader's own --check whether it can resolve this exe."""
    if loader is None:
        return {"status": "skipped", "detail": "no loader given (--loader)"}
    try:
        proc = subprocess.run(
            [str(loader), "--check", exe],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "error", "detail": str(exc)}
    out = (proc.stdout or "") + (proc.stderr or "")
    if "Check OK" in out or "unresolved import slot(s): 0" in out:
        return {"status": "PASS", "detail": "imports resolve", "exit": proc.returncode}
    m = re.search(r"Check FAILED:\s*(\d+)\s*unresolved import slot", out)
    if m:
        return {
            "status": "FAIL",
            "detail": f"{m.group(1)} unresolved import slot(s)",
            "exit": proc.returncode,
        }
    return {
        "status": "unknown",
        "detail": (out.strip().splitlines() or ["no verdict"])[-1][:160],
        "exit": proc.returncode,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--steam-root", help="Steam install (default: the usual places)")
    ap.add_argument("--app", help="only this appid")
    ap.add_argument("--loader", help="WINS loader binary, enables the import check")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--all", action="store_true", help="list every exe, not just the best")
    args = ap.parse_args()

    roots = find_steam_roots(args.steam_root)
    if not roots:
        sys.exit("no Steam install found (use --steam-root)")
    loader = find_loader(args.loader)

    libraries = []
    for root in roots:
        for lib in library_paths(root):
            if lib not in libraries:
                libraries.append(lib)

    results = []
    for lib in libraries:
        for app in read_apps(lib):
            if args.app and app["appid"] != str(args.app):
                continue
            cands = candidates(app)
            if not cands:
                continue
            best = cands[0]
            check = loader_check(loader, best["path"])
            results.append(
                {
                    **app,
                    "exe": best["path"],
                    "exe_bytes": best["size"],
                    "other_exes": [c["path"] for c in cands[1:]],
                    "check": check,
                }
            )

    if args.json:
        print(json.dumps({"loader": str(loader) if loader else None,
                          "libraries": [str(l) for l in libraries],
                          "apps": results}, indent=2))
        return

    print(f"Steam libraries ({len(libraries)}):")
    for lib in libraries:
        print(f"  {lib}")
    print(f"loader: {loader if loader else '(none — import check skipped)'}")
    print()
    for r in results:
        flags = ""
        if r["stateflags"] not in ("", "4"):
            flags = f"  stateflags={r['stateflags']}"
        print(f"[{r['appid']}] {r['name']}{flags}")
        print(f"    exe   {r['exe']}  ({r['exe_bytes'] / 1048576:.1f} MiB)")
        c = r["check"]
        mark = {"PASS": "PASS", "FAIL": "FAIL", "skipped": "SKIP", "error": "ERR", "unknown": "?"}
        print(f"    check {mark.get(c['status'], c['status'])}  {c['detail']}")
        if args.all:
            for other in r["other_exes"]:
                print(f"    also  {other}")
        print(f"    run   SteamAppId={r['appid']} "
              f"{str(loader) if loader else '<loader>'} --run \"{r['exe']}\"")
    if not results:
        print("(no apps matched)")


if __name__ == "__main__":
    main()
