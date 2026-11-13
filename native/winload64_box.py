#!/usr/bin/env python3
"""Run winload64 inside a fresh bubblewrap cleanroom (no network, read-only inputs).

The DLL directory is bound read-only at /dlls; the root DLL must live in it.
All other arguments (--pin, --call, --arg, --ret, --check) pass through unchanged.

usage: winload64_box.py --loader build/winload64 --dll-dir DIR ROOT.dll [winload64 args...]
"""
import argparse
import os
import sys
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--loader', required=True, type=Path)
    p.add_argument('--dll-dir', required=True, type=Path)
    p.add_argument('root')
    p.add_argument('rest', nargs=argparse.REMAINDER)
    a = p.parse_args()
    loader = a.loader.resolve(strict=True)
    dll_dir = a.dll_dir.resolve(strict=True)
    if not (dll_dir / a.root).is_file():
        print(f'winload64-box: {a.root} is not in {dll_dir}', file=sys.stderr)
        return 2
    cmd = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
           '--setenv', 'WINS_WINRUN_BOX', '1', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
           '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
           '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
           '--ro-bind', str(loader), '/winload64', '--ro-bind', str(dll_dir), '/dlls',
           '--', '/winload64', '--dll-dir', '/dlls', f'/dlls/{a.root}', *a.rest]
    try:
        os.execvp(cmd[0], cmd)
    except OSError as exc:
        print(f'winload64-box: cannot start bubblewrap: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
