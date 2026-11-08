"""Bethesda ESM4 master file parser for WINS (Fallout 3, Fallout New Vegas, Skyrim).

Parses hierarchical binary chunk structures (TES4, GRUP, WRLD, CELL, STAT, REFR)
without requiring Windows, Wine, or Creation Kit.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import os
from pathlib import Path
import struct
from typing import BinaryIO, Dict, Iterator, List, Optional, Tuple


TES4_HEADER_SIZE = 24
RECORD_HEADER_SIZE = 24
GROUP_HEADER_SIZE = 24


@dataclass
class Subrecord:
    tag: str
    size: int
    data: bytes

    @property
    def string_value(self) -> str:
        """Decode null-terminated or ASCII string."""
        return self.data.split(b"\x00")[0].decode("ascii", errors="replace")


@dataclass
class Record:
    tag: str
    data_size: int
    flags: int
    form_id: int
    version_control: int
    subrecords: List[Subrecord] = field(default_factory=list)

    def get_subrecord(self, tag: str) -> Optional[Subrecord]:
        for sub in self.subrecords:
            if sub.tag == tag:
                return sub
        return None

    def get_string(self, tag: str, default: str = "") -> str:
        sub = self.get_subrecord(tag)
        return sub.string_value if sub else default


@dataclass
class TopGroup:
    label: str
    size: int
    offset: int
    group_type: int


class EsmParser:
    """Stream parser for Bethesda ESM4 master files."""

    def __init__(self, esm_path: str | Path):
        self.esm_path = Path(esm_path)
        if not self.esm_path.exists():
            raise FileNotFoundError(f"ESM file not found: {self.esm_path}")

        self.file_size = self.esm_path.stat().st_size
        self.masters: List[str] = []
        self.author: str = ""
        self.description: str = ""
        self.top_groups: Dict[str, TopGroup] = {}

        self._read_header_and_index()

    def _read_header_and_index(self) -> None:
        with open(self.esm_path, "rb") as f:
            # First record must be TES4
            hdr = f.read(RECORD_HEADER_SIZE)
            if len(hdr) < RECORD_HEADER_SIZE:
                raise ValueError("File too short for ESM4 header")

            rec_type, data_size, flags, form_id, vc_info = struct.unpack("<4s4I", hdr[:20])
            tag = rec_type.decode("ascii", errors="replace")
            if tag != "TES4":
                raise ValueError(f"Expected TES4 header record, got {tag!r}")

            tes4_data = f.read(data_size)
            # Parse TES4 subrecords (HEDR, CNAM, SNAM, MAST)
            sp = 0
            while sp + 6 <= len(tes4_data):
                stag = tes4_data[sp : sp + 4].decode("ascii", errors="replace")
                ssize = struct.unpack("<H", tes4_data[sp + 4 : sp + 6])[0]
                sdata = tes4_data[sp + 6 : sp + 6 + ssize]
                sp += 6 + ssize

                if stag == "CNAM":
                    self.author = sdata.split(b"\x00")[0].decode("ascii", errors="replace")
                elif stag == "SNAM":
                    self.description = sdata.split(b"\x00")[0].decode("ascii", errors="replace")
                elif stag == "MAST":
                    self.masters.append(sdata.split(b"\x00")[0].decode("ascii", errors="replace"))

            # Scan top-level GRUP index
            while f.tell() < self.file_size:
                pos = f.tell()
                ghdr = f.read(GROUP_HEADER_SIZE)
                if len(ghdr) < GROUP_HEADER_SIZE:
                    break

                gtag, gsize, label_int, gtype = struct.unpack("<4s3I", ghdr[:16])
                if gtag != b"GRUP":
                    break

                label_str = struct.pack("<I", label_int).decode("ascii", errors="replace")
                top_grp = TopGroup(label=label_str, size=gsize, offset=pos, group_type=gtype)
                self.top_groups[label_str] = top_grp
                f.seek(pos + gsize)

    def iter_records(self, group_label: str) -> Iterator[Record]:
        """Iterate through records within a top-level group."""
        if group_label not in self.top_groups:
            return

        grp = self.top_groups[group_label]
        with open(self.esm_path, "rb") as f:
            f.seek(grp.offset + GROUP_HEADER_SIZE)
            end = grp.offset + grp.size

            while f.tell() < end:
                pos = f.tell()
                rhdr = f.read(RECORD_HEADER_SIZE)
                if len(rhdr) < RECORD_HEADER_SIZE:
                    break

                rtag_raw = rhdr[:4]
                if rtag_raw == b"GRUP":
                    # Sub-group: skip or step through
                    sub_gsize = struct.unpack("<I", rhdr[4:8])[0]
                    f.seek(pos + sub_gsize)
                    continue

                rsize, rflags, form_id, vc_info = struct.unpack("<4I", rhdr[4:20])
                tag = rtag_raw.decode("ascii", errors="replace")
                data = f.read(rsize)

                # Parse subrecords
                subrecords = []
                sp = 0
                while sp + 6 <= len(data):
                    stag = data[sp : sp + 4].decode("ascii", errors="replace")
                    ssize = struct.unpack("<H", data[sp + 4 : sp + 6])[0]
                    sdata = data[sp + 6 : sp + 6 + ssize]
                    sp += 6 + ssize
                    subrecords.append(Subrecord(tag=stag, size=ssize, data=sdata))

                yield Record(
                    tag=tag,
                    data_size=rsize,
                    flags=rflags,
                    form_id=form_id,
                    version_control=vc_info,
                    subrecords=subrecords,
                )

    def get_worldspaces(self) -> List[Tuple[int, str, str]]:
        """Return list of (form_id, edid, full_name) for all worldspaces."""
        results = []
        for rec in self.iter_records("WRLD"):
            if rec.tag == "WRLD":
                edid = rec.get_string("EDID")
                full = rec.get_string("FULL")
                results.append((rec.form_id, edid, full))
        return results

    def get_interior_cells(self, limit: int = 0) -> List[Tuple[int, str, str]]:
        """Return list of (form_id, edid, full_name) for interior cells."""
        results = []
        for rec in self.iter_records("CELL"):
            if rec.tag == "CELL":
                edid = rec.get_string("EDID")
                full = rec.get_string("FULL")
                if edid or full:
                    results.append((rec.form_id, edid, full))
                    if limit > 0 and len(results) >= limit:
                        break
        return results

    def get_static_meshes(self, limit: int = 0) -> List[Tuple[int, str, str]]:
        """Return list of (form_id, edid, nif_relative_path) for static 3D meshes."""
        results = []
        for rec in self.iter_records("STAT"):
            if rec.tag == "STAT":
                edid = rec.get_string("EDID")
                modl = rec.get_string("MODL")
                if modl:
                    results.append((rec.form_id, edid, modl))
                    if limit > 0 and len(results) >= limit:
                        break
        return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Bethesda ESM4 Parser (WINS Native)")
    parser.add_argument("esm", help="Path to .esm file")
    parser.add_argument("--info", action="store_true", help="Print header and metadata")
    parser.add_argument("--groups", action="store_true", help="List all top-level groups")
    parser.add_argument("--worldspaces", action="store_true", help="List all worldspaces")
    parser.add_argument("--cells", type=int, default=0, metavar="LIMIT", help="List interior cells up to LIMIT")
    parser.add_argument("--stats", type=int, default=0, metavar="LIMIT", help="List static mesh references up to LIMIT")

    args = parser.parse_args()
    esm = EsmParser(args.esm)

    if args.info or not any([args.groups, args.worldspaces, args.cells, args.stats]):
        print(f"File: {args.esm} ({esm.file_size / (1024*1024):.1f} MB)")
        print(f"Author: {esm.author or '(none)'}")
        print(f"Description: {esm.description or '(none)'}")
        print(f"Master dependencies: {', '.join(esm.masters) or '(root master)'}")
        print(f"Top-level groups: {len(esm.top_groups)}")

    if args.groups:
        print("\nTop-Level Record Groups:")
        for label, grp in esm.top_groups.items():
            print(f"  {label:6s} | Size: {grp.size:10d} bytes | Offset: 0x{grp.offset:08x}")

    if args.worldspaces:
        print("\nWorldspaces (WRLD):")
        for fid, edid, full in esm.get_worldspaces():
            print(f"  FormID: 0x{fid:08x} | EDID: {edid:25s} | Name: {full}")

    if args.cells > 0:
        print(f"\nInterior Cells (showing first {args.cells}):")
        for fid, edid, full in esm.get_interior_cells(limit=args.cells):
            print(f"  FormID: 0x{fid:08x} | EDID: {edid:25s} | Name: {full}")

    if args.stats > 0:
        print(f"\nStatic 3D Meshes (showing first {args.stats}):")
        for fid, edid, modl in esm.get_static_meshes(limit=args.stats):
            print(f"  FormID: 0x{fid:08x} | EDID: {edid:25s} | Model: {modl}")


if __name__ == "__main__":
    main()
