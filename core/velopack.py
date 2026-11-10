"""Structural detection of a ZIP archive appended after a host image.

Velopack (and the older Squirrel.Windows) ship the application payload as a
NuGet package (`nupkg`, which is a ZIP) appended after the PE image of the
setup executable. The archive is self-contained: every offset inside the ZIP
is relative to the archive start, so it can be read in place.

Nothing here executes the host file.
"""
from __future__ import annotations

import io
import os
import struct
import zipfile
from typing import Any, Dict, List, Optional

EOCD_SIG = b"PK\x05\x06"
LOCAL_SIG = b"PK\x03\x04"
CENTRAL_SIG = b"PK\x01\x02"
MAX_COMMENT = 0xFFFF


def find_zip_overlay(path: str) -> Optional[Dict[str, Any]]:
    """Return the ZIP archive appended to `path`, or None.

    The archive must end at EOF and its central directory must resolve to a
    first local header, so random trailing data is not mistaken for a payload.
    """
    size = os.path.getsize(path)
    if size < 22:
        return None
    tail_len = min(size, MAX_COMMENT + 22 + 4096)
    with open(path, "rb") as handle:
        handle.seek(size - tail_len)
        tail = handle.read(tail_len)

    eocd = tail.rfind(EOCD_SIG)
    while eocd != -1:
        absolute = size - tail_len + eocd
        if absolute + 22 <= size:
            (
                _sig,
                disk,
                cd_disk,
                _entries_disk,
                entries_total,
                cd_size,
                cd_offset,
                comment_len,
            ) = struct.unpack("<IHHHHIIH", tail[eocd : eocd + 22])
            if (
                disk == 0
                and cd_disk == 0
                and comment_len == 0
                and absolute + 22 == size
                and cd_size > 0
                and cd_offset > 0
            ):
                cd_file_off = absolute - cd_size
                if cd_offset <= cd_file_off:
                    archive_start = cd_file_off - cd_offset
                    with open(path, "rb") as handle:
                        handle.seek(archive_start)
                        if handle.read(4) == LOCAL_SIG:
                            return {
                                "archive_offset": archive_start,
                                "archive_size": size - archive_start,
                                "entry_count": entries_total,
                                "central_directory_offset": cd_file_off,
                            }
        eocd = tail.rfind(EOCD_SIG, 0, eocd)
    return None


class _OverlayFile(io.RawIOBase):
    """Read-only view of the archive region of a host file."""

    def __init__(self, path: str, offset: int, size: int):
        self._handle = open(path, "rb")
        self._offset = offset
        self._size = size
        self._pos = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = self._size - self._pos
        size = max(0, min(size, self._size - self._pos))
        if size == 0:
            return b""
        self._handle.seek(self._offset + self._pos)
        data = self._handle.read(size)
        self._pos += len(data)
        return data

    def tell(self) -> int:
        return self._pos

    def readinto(self, buffer) -> int:
        data = self.read(len(buffer))
        count = len(data)
        buffer[:count] = data
        return count

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            self._pos = offset
        elif whence == io.SEEK_CUR:
            self._pos += offset
        elif whence == io.SEEK_END:
            self._pos = self._size + offset
        else:
            raise ValueError("invalid whence")
        self._pos = max(0, min(self._pos, self._size))
        return self._pos

    def close(self) -> None:
        try:
            self._handle.close()
        finally:
            super().close()


def open_overlay_zip(path: str, overlay: Dict[str, Any]) -> zipfile.ZipFile:
    """Open the appended archive as a ZipFile without copying it out."""
    stream = _OverlayFile(path, overlay["archive_offset"], overlay["archive_size"])
    return zipfile.ZipFile(io.BufferedReader(stream, buffer_size=1 << 20))


def overlay_entries(path: str, overlay: Dict[str, Any]) -> List[str]:
    with open_overlay_zip(path, overlay) as archive:
        return archive.namelist()


def read_overlay_entry(path: str, overlay: Dict[str, Any], name: str) -> bytes:
    with open_overlay_zip(path, overlay) as archive:
        return archive.read(name)


def nuspec_metadata(path: str, overlay: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """Read id/version/channel/rid from the nupkg's .nuspec, if present."""
    try:
        with open_overlay_zip(path, overlay) as archive:
            names = [n for n in archive.namelist() if n.endswith(".nuspec")]
            if not names:
                return {}
            text = archive.read(names[0]).decode("utf-8", "replace")
    except Exception:
        return {}

    import re

    meta: Dict[str, Optional[str]] = {}
    for tag in ("id", "version", "channel", "rid", "os", "mainExe", "runtimeDependencies"):
        match = re.search(rf"<{tag}>(.*?)</{tag}>", text, re.DOTALL)
        meta[tag] = match.group(1).strip() if match else None
    return meta
