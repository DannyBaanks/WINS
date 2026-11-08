"""Bethesda SDP shader package extractor for WINS (Fallout 3, Fallout New Vegas).

Extracts compiled D3D9 vertex and pixel shaders (vs_2_0, vs_3_0, ps_2_0, ps_3_0)
and parses CTAB constant tables into structured metadata.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import struct
from typing import Dict, List, Optional, Tuple


@dataclass
class ShaderConstant:
    name: str
    register_set: int
    register_index: int
    register_count: int


@dataclass
class ShaderEntry:
    name: str
    size: int
    stage: str  # 'vertex' or 'pixel'
    model: str  # 'vs_2_0', 'vs_3_0', 'ps_2_0', 'ps_3_0', etc.
    bytecode: bytes
    constants: List[ShaderConstant]

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "size": self.size,
            "stage": self.stage,
            "model": self.model,
            "constants": [asdict(c) for c in self.constants],
        }


class SdpPackage:
    """Parser for Bethesda .sdp shader packages."""

    def __init__(self, sdp_path: str | Path):
        self.sdp_path = Path(sdp_path)
        if not self.sdp_path.exists():
            raise FileNotFoundError(f"SDP package not found: {self.sdp_path}")

        self.version: int = 0
        self.total_size: int = 0
        self.shaders: List[ShaderEntry] = []
        self._by_name: Dict[str, ShaderEntry] = {}

        self._read_package()

    def _read_package(self) -> None:
        with open(self.sdp_path, "rb") as f:
            header = f.read(12)
            if len(header) < 12:
                raise ValueError("File too short for SDP header")

            self.version, count, self.total_size = struct.unpack("<3I", header)
            if self.version != 100:
                # Still attempt parsing even if version is non-standard
                pass

            for _ in range(count):
                name_raw = f.read(256)
                if len(name_raw) < 256:
                    break
                name = name_raw.split(b"\x00")[0].decode("ascii", errors="replace")

                size_raw = f.read(4)
                if len(size_raw) < 4:
                    break
                shader_size = struct.unpack("<I", size_raw)[0]
                bytecode = f.read(shader_size)

                # Parse D3D9 version token
                stage = "unknown"
                model = "unknown"
                constants: List[ShaderConstant] = []

                if len(bytecode) >= 4:
                    token = struct.unpack("<I", bytecode[:4])[0]
                    is_pixel = (token >> 16) == 0xFFFF
                    stage = "pixel" if is_pixel else "vertex"
                    prefix = "ps" if is_pixel else "vs"
                    major = (token >> 8) & 0xFF
                    minor = token & 0xFF
                    model = f"{prefix}_{major}_{minor}"

                # Look for CTAB constant table
                ctab_idx = bytecode.find(b"CTAB")
                if ctab_idx != -1 and ctab_idx + 32 <= len(bytecode):
                    try:
                        c_size, c_creator, c_ver, c_count, c_info = struct.unpack(
                            "<5I", bytecode[ctab_idx + 4 : ctab_idx + 24]
                        )
                        for c in range(min(c_count, 128)):
                            coff = ctab_idx + c_info + c * 20
                            if coff + 10 <= len(bytecode):
                                cname_off, rset, ridx, rcount = struct.unpack("<IH2H", bytecode[coff : coff + 10])
                                str_start = ctab_idx + cname_off
                                if str_start < len(bytecode):
                                    cname = (
                                        bytecode[str_start:]
                                        .split(b"\x00")[0]
                                        .decode("ascii", errors="replace")
                                    )
                                    if cname:
                                        constants.append(
                                            ShaderConstant(
                                                name=cname,
                                                register_set=rset,
                                                register_index=ridx,
                                                register_count=rcount,
                                            )
                                        )
                    except Exception:
                        pass

                entry = ShaderEntry(
                    name=name,
                    size=shader_size,
                    stage=stage,
                    model=model,
                    bytecode=bytecode,
                    constants=constants,
                )
                self.shaders.append(entry)
                self._by_name[name.lower()] = entry

    def get_shader(self, name: str) -> Optional[ShaderEntry]:
        return self._by_name.get(name.lower())

    def extract_all(self, dest_dir: str | Path, write_manifest: bool = True) -> int:
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)

        manifest = []
        for s in self.shaders:
            out_file = dest / s.name
            out_file.write_bytes(s.bytecode)
            manifest.append(s.to_dict())

        if write_manifest:
            manifest_file = dest / f"{self.sdp_path.stem}_manifest.json"
            manifest_file.write_text(json.dumps(manifest, indent=2))

        return len(self.shaders)


def batch_extract_shaders(shaders_dir: str | Path, dest_dir: str | Path) -> Dict[str, int]:
    """Extract and catalogue all .sdp shader packages in a directory."""
    s_dir = Path(shaders_dir)
    d_dir = Path(dest_dir)
    d_dir.mkdir(parents=True, exist_ok=True)

    packages = sorted(s_dir.glob("*.sdp"))
    results = {}
    master_manifest = {}

    for pkg_path in packages:
        pkg = SdpPackage(pkg_path)
        pkg_out = d_dir / pkg_path.stem
        pkg.extract_all(pkg_out, write_manifest=True)
        results[pkg_path.name] = len(pkg.shaders)
        master_manifest[pkg_path.stem] = {
            "file": pkg_path.name,
            "version": pkg.version,
            "shader_count": len(pkg.shaders),
            "shaders": [s.to_dict() for s in pkg.shaders],
        }

    (d_dir / "all_shaders_manifest.json").write_text(json.dumps(master_manifest, indent=2))
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Bethesda SDP Shader Package Extractor (WINS Native)")
    parser.add_argument("sdp", nargs="?", help="Path to .sdp shader package")
    parser.add_argument("--list", action="store_true", help="List shaders in package")
    parser.add_argument("--extract-to", help="Directory to extract shaders to")
    parser.add_argument("--batch", help="Batch extract all .sdp packages from directory")

    args = parser.parse_args()

    if args.batch:
        dest = args.extract_to or "./extracted_shaders"
        print(f"Batch extracting all SDP packages from {args.batch} -> {dest}")
        res = batch_extract_shaders(args.batch, dest)
        total = sum(res.values())
        print(f"Successfully processed {len(res)} packages, total {total} shaders extracted!")
        for name, count in res.items():
            print(f"  {name}: {count} shaders")
        return

    if not args.sdp:
        parser.print_help()
        return

    pkg = SdpPackage(args.sdp)
    print(f"Package: {args.sdp}")
    print(f"Version: {pkg.version}, Total shaders: {len(pkg.shaders)}")

    if args.list or not args.extract_to:
        for s in pkg.shaders[:30]:
            print(f"  {s.name:20s} | {s.model:8s} | {s.size:5d} bytes | {len(s.constants)} constants")
        if len(pkg.shaders) > 30:
            print(f"  ... and {len(pkg.shaders) - 30} more")

    if args.extract_to:
        count = pkg.extract_all(args.extract_to)
        print(f"Extracted {count} shaders to {args.extract_to}")


if __name__ == "__main__":
    main()
