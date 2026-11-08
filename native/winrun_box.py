#!/usr/bin/env python3
"""Run winrun and its selected PE inside a fresh bubblewrap cleanroom."""
import argparse
import os
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--loader', required=True, type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('image', type=Path)
    args = parser.parse_args()
    loader = args.loader.resolve(strict=True)
    image = args.image.resolve(strict=True)
    command = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
               '--setenv', 'WINS_WINRUN_BOX', '1', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
               '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
               '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
               '--ro-bind', str(loader), '/winrun', '--ro-bind', str(image), '/image.exe',
               '--', '/winrun', '--sha256', args.sha256]
    if args.check:
        command.append('--check')
    command.append('/image.exe')
    try:
        os.execvp(command[0], command)
    except OSError as exc:
        print(f'winrun-box: cannot start bubblewrap: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
