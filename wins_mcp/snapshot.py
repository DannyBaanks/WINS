"""L0 deterministic snapshot, draws.log, DXBC signature, and GLSL parser.

Parses real artifacts emitted by `native/wins_d3d11_gl.zig` (`snap_out/`):
  - `draws.log` (BEGIN, CLEAR_RTV, DISPATCH, D#..., CHG p#(...), PS t#(...), END)
  - `pXXXX_{vs,hs,ds,gs,ps}.{dxbc,glsl}`
  - `final.ppm` (P6 header metadata + SHA-256; never dumps base64 blobs)

All parsed log/shader content is treated strictly as untrusted telemetry data.
"""

from __future__ import annotations

import math
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .security import sha256_file

# ---- Regex patterns matching native/wins_d3d11_gl.zig snap output -----------

RE_BEGIN = re.compile(
    r"^BEGIN\s+after_present=(\d+)\s+bb=(\d+)x(\d+)\s+fmt=(\d+)"
)
RE_END = re.compile(
    r"^END\s+present=(\d+)\s+total_draws=(\d+)"
)
RE_CLEAR_RTV = re.compile(
    r"^CLEAR_RTV\s+gl=(\d+)\s+(\d+)x(\d+)\s+fmt=(\d+)\s+rgba=\(([^,]+),([^,]+),([^,]+),([^)]+)\)"
)
RE_DISPATCH = re.compile(
    r"^DISPATCH\s+prog=(\d+)\s+xyz=\((\d+),(\d+),(\d+)\)\s+ind=(true|false)"
)
RE_DRAW = re.compile(
    r"^D#(\d+)\s+prog=(\d+)\s+stg=([^\s]+)\s+topo=(\d+)\s+k=([^\s]+)\s+"
    r"cnt=(\d+)\s+inst=(\d+)\s+fb=(\d+)x(\d+)\s+nrt=(\d+)\s+"
    r"rt0=(\d+)\(f=(\d+),sw=(true|false)\)\s+dsv=(\d+)\(f=(\d+)\)\s+"
    r"bl=\(en=(true|false)\s+([0-9a-fA-F]+)/([0-9a-fA-F]+)->([0-9a-fA-F]+)/([0-9a-fA-F]+)\s+"
    r"op=([0-9a-fA-F]+)\s+m=([0-9a-fA-F]+)\s+ind=(true|false)\)\s+"
    r"ds=\((true|false)/(true|false)\s+fn=([0-9a-fA-F]+)\s+st=(true|false)\)\s+"
    r"rs=\(c=(\d+)\s+ccw=(true|false)\s+sc=(true|false)\s+clp=(true|false)\)"
)
RE_CHG = re.compile(
    r"^\s+CHG\s+p(\d+)\((\d+),(\d+)\):\s+\(([^,]+),([^,]+),([^,]+),([^)]+)\)\s+->\s+\(([^,]+),([^,]+),([^,]+),([^)]+)\)"
)
RE_PS_SRV = re.compile(
    r"^\s+PS\s+t(\d+)\(u(\d+),s(\d+)\)\s+tex=(\d+)\s+(\d+)x(\d+)\s+tf=(\d+)\s+vf=(\d+)\s+tgt=([0-9a-fA-F]+)\s+m=([^\s]+)\s+\|\s+smp=(\d+)\(([^)]*)\)"
)

# GLSL fallback extraction patterns
RE_GLSL_OUT = re.compile(
    r"layout\s*\(\s*location\s*=\s*(\d+)(?:\s*,\s*index\s*=\s*(\d+))?\s*\)\s*out\s+\w+\s+(\w+)\s*;"
)
RE_GLSL_IN = re.compile(
    r"layout\s*\(\s*location\s*=\s*(\d+)\s*\)\s*in\s+\w+\s+(\w+)\s*;"
)
RE_GLSL_SAMPLER = re.compile(
    r"layout\s*\(\s*binding\s*=\s*(\d+)\s*\)\s*uniform\s+(\w*sampler\w*)\s+(\w+)\s*;"
)
RE_GLSL_UBO = re.compile(
    r"layout\s*\(\s*std140\s*,\s*binding\s*=\s*(\d+)\s*\)\s*uniform\s+(\w+)"
)


def _parse_float(tok: str) -> float:
    s = tok.strip().lower()
    if s in ("nan", "-nan", "+nan"):
        return float("nan")
    if s in ("inf", "+inf", "infinity"):
        return float("inf")
    if s in ("-inf", "-infinity"):
        return float("-inf")
    return float(s)


def _float_to_json(v: float) -> Any:
    if math.isnan(v):
        return "NaN"
    if math.isinf(v):
        return "Inf" if v > 0 else "-Inf"
    return round(v, 6)


def _vec4_to_json(v: Tuple[float, float, float, float]) -> List[Any]:
    return [_float_to_json(x) for x in v]


@dataclass
class ClearRtvEvent:
    line_no: int
    order: int
    gl_id: int
    width: int
    height: int
    fmt: int
    rgba: Tuple[float, float, float, float]


@dataclass
class DispatchEvent:
    line_no: int
    order: int
    prog_id: int
    xyz: Tuple[int, int, int]
    indirect: bool


@dataclass
class ProbeChange:
    line_no: int
    probe_idx: int
    x: int
    y: int
    before: Tuple[float, float, float, float]
    after: Tuple[float, float, float, float]

    def has_non_finite(self) -> bool:
        return any(
            math.isnan(v) or math.isinf(v)
            for v in (*self.before, *self.after)
        )

    def delta_l1(self) -> Optional[float]:
        if self.has_non_finite():
            return None
        return sum(abs(a - b) for a, b in zip(self.after, self.before))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "probe_idx": self.probe_idx,
            "coord": [self.x, self.y],
            "before": _vec4_to_json(self.before),
            "after": _vec4_to_json(self.after),
            "non_finite": self.has_non_finite(),
            "delta_l1": round(self.delta_l1(), 6) if self.delta_l1() is not None else None,
            "evidence_id": f"draws.log:L{self.line_no}",
        }


@dataclass
class PsSrvBinding:
    line_no: int
    slot: int
    unit: int
    samp_slot: int
    tex_gl: int
    width: int
    height: int
    tex_fmt: int
    view_fmt: int
    target_hex: str
    mips: str
    sampler_gl: int
    sampler_desc: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "slot": f"t{self.slot}",
            "unit": self.unit,
            "samp_slot": f"s{self.samp_slot}",
            "tex_gl": self.tex_gl,
            "size": [self.width, self.height],
            "tex_fmt": self.tex_fmt,
            "view_fmt": self.view_fmt,
            "target": f"0x{self.target_hex}",
            "mips": self.mips,
            "sampler_gl": self.sampler_gl,
            "evidence_id": f"draws.log:L{self.line_no}",
        }


@dataclass
class DrawEvent:
    line_no: int
    order: int
    draw_id: int
    prog_id: int
    stages: str
    topo: int
    kind: str
    count: int
    instances: int
    fb_w: int
    fb_h: int
    nrt: int
    rt0_gl: int
    rt0_fmt: int
    rt0_swapchain: bool
    dsv_gl: int
    dsv_fmt: int
    blend_enable: bool
    blend_src_rgb: str
    blend_src_a: str
    blend_dst_rgb: str
    blend_dst_a: str
    blend_op: str
    write_mask: int
    independent_blend: bool
    depth_enable: bool
    depth_write: bool
    depth_func: str
    stencil_enable: bool
    cull_mode: int
    front_ccw: bool
    scissor_enable: bool
    depth_clip: bool
    probes: List[ProbeChange] = field(default_factory=list)
    ps_srvs: List[PsSrvBinding] = field(default_factory=list)

    def has_ps(self) -> bool:
        return len(self.stages) >= 5 and self.stages[4] == "P"

    def blend_summary(self) -> Dict[str, Any]:
        return {
            "enable": self.blend_enable,
            "src_rgb": f"0x{self.blend_src_rgb}",
            "src_a": f"0x{self.blend_src_a}",
            "dst_rgb": f"0x{self.blend_dst_rgb}",
            "dst_a": f"0x{self.blend_dst_a}",
            "op": f"0x{self.blend_op}",
            "write_mask": f"0x{self.write_mask:x}",
            "independent": self.independent_blend,
        }


@dataclass
class SigElement:
    name: str
    semantic_index: int
    sysval: int
    comp_type: int
    reg: int
    mask: int
    rw_mask: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "semantic_index": self.semantic_index,
            "sysval": self.sysval,
            "comp_type": self.comp_type,
            "reg": self.reg,
            "mask": f"0x{self.mask:x}",
            "rw_mask": f"0x{self.rw_mask:x}",
        }


@dataclass
class ShaderInfo:
    prog_id: int
    stage: str
    dxbc_path: Optional[Path] = None
    glsl_path: Optional[Path] = None
    isgn: List[SigElement] = field(default_factory=list)
    osgn: List[SigElement] = field(default_factory=list)
    glsl_outputs: List[Dict[str, Any]] = field(default_factory=list)
    glsl_inputs: List[Dict[str, Any]] = field(default_factory=list)
    samplers: List[Dict[str, Any]] = field(default_factory=list)
    ubos: List[Dict[str, Any]] = field(default_factory=list)
    source: str = "none"  # "dxbc+glsl" | "dxbc" | "glsl" | "none"
    parse_errors: List[str] = field(default_factory=list)

    def declared_rt_slots(self) -> Optional[List[int]]:
        """Return sorted SV_Target register indices (0..7) declared by a PS."""
        if self.stage != "ps":
            return None
        if self.osgn:
            slots = sorted({e.reg for e in self.osgn if e.reg < 8})
            return slots
        if self.glsl_outputs:
            slots = sorted({int(o["location"]) for o in self.glsl_outputs if int(o["location"]) < 8})
            return slots
        if self.glsl_path is not None or self.dxbc_path is not None:
            return []
        return None

    def ps_out_mask(self) -> Optional[int]:
        slots = self.declared_rt_slots()
        if slots is None:
            return None
        m = 0
        for s in slots:
            m |= (1 << s)
        return m


@dataclass
class SnapshotData:
    snap_dir: Path
    after_present: Optional[int] = None
    end_present: Optional[int] = None
    reported_total_draws: Optional[int] = None
    bb_width: Optional[int] = None
    bb_height: Optional[int] = None
    bb_fmt: Optional[int] = None
    log_complete: bool = False
    log_warnings: List[str] = field(default_factory=list)
    clears: List[ClearRtvEvent] = field(default_factory=list)
    dispatches: List[DispatchEvent] = field(default_factory=list)
    draws: List[DrawEvent] = field(default_factory=list)
    final_image_path: Optional[Path] = None
    final_image_dims: Optional[Tuple[int, int]] = None
    final_image_sha256: Optional[str] = None
    draws_log_sha256: Optional[str] = None
    shader_files: Dict[Tuple[int, str], Dict[str, Path]] = field(default_factory=dict)
    _shader_cache: Dict[Tuple[int, str], ShaderInfo] = field(default_factory=dict)

    def instrumented_probes(self) -> List[Dict[str, Any]]:
        seen: Dict[Tuple[int, int], int] = {}
        for d in self.draws:
            for p in d.probes:
                seen[(p.x, p.y)] = p.probe_idx
        return [
            {"probe_idx": idx, "coord": [x, y]}
            for (x, y), idx in sorted(seen.items(), key=lambda kv: kv[1])
        ]

    def get_shader(self, prog_id: int, stage: str = "ps") -> ShaderInfo:
        key = (prog_id, stage.lower())
        if key in self._shader_cache:
            return self._shader_cache[key]
        files = self.shader_files.get(key, {})
        info = inspect_shader_files(prog_id, stage.lower(), files.get("dxbc"), files.get("glsl"))
        self._shader_cache[key] = info
        return info


def parse_dxbc_signatures(data: bytes) -> Tuple[List[SigElement], List[SigElement], List[str]]:
    """Parse ISGN/ISG1 and OSGN/OSG5/OSG1 chunks from raw DXBC container bytes."""
    errors: List[str] = []
    if len(data) < 32 or data[:4] != b"DXBC":
        return [], [], ["Not a valid DXBC container (missing DXBC magic or truncated)."]
    chunk_count = struct.unpack_from("<I", data, 28)[0]
    if 32 + chunk_count * 4 > len(data):
        return [], [], ["DXBC chunk table exceeds file size."]
    offsets = struct.unpack_from(f"<{chunk_count}I", data, 32)

    isgn: List[SigElement] = []
    osgn: List[SigElement] = []

    def _parse_chunk(tag: bytes, chunk: bytes) -> List[SigElement]:
        if len(chunk) < 8:
            errors.append(f"Truncated {tag.decode('latin1')} chunk.")
            return []
        cnt = struct.unpack_from("<I", chunk, 0)[0]
        esz = 24 if tag in (b"ISGN", b"OSGN") else (28 if tag == b"OSG5" else 32)
        adj = 0 if tag in (b"ISGN", b"OSGN") else 4
        if 8 + cnt * esz > len(chunk):
            errors.append(f"Corrupt element count in {tag.decode('latin1')} chunk.")
            return []
        out: List[SigElement] = []
        for i in range(cnt):
            base = 8 + i * esz + adj
            name_off, sem_idx, sysval, comp_ty, reg = struct.unpack_from("<5I", chunk, base)
            mask = chunk[base + 20] & 0xF
            rw_mask = chunk[base + 21] & 0xF
            if name_off < len(chunk):
                end = chunk.find(b"\x00", name_off)
                raw_name = chunk[name_off:] if end == -1 else chunk[name_off:end]
                name = raw_name.decode("ascii", errors="replace")
            else:
                name = "UNKNOWN"
            out.append(SigElement(name, sem_idx, sysval, comp_ty, reg, mask, rw_mask))
        return out

    for off in offsets:
        if off + 8 > len(data):
            errors.append(f"Chunk offset {off} out of bounds.")
            continue
        tag = data[off : off + 4]
        sz = struct.unpack_from("<I", data, off + 4)[0]
        if off + 8 + sz > len(data):
            errors.append(f"Chunk {tag.decode('latin1', errors='replace')} size exceeds file.")
            continue
        chunk = data[off + 8 : off + 8 + sz]
        if tag in (b"ISGN", b"ISG1") and not isgn:
            isgn = _parse_chunk(tag, chunk)
        elif tag in (b"OSGN", b"OSG5", b"OSG1") and not osgn:
            osgn = _parse_chunk(tag, chunk)

    return isgn, osgn, errors


def parse_glsl_metadata(text: str) -> Dict[str, List[Dict[str, Any]]]:
    outs = []
    for m in RE_GLSL_OUT.finditer(text):
        entry: Dict[str, Any] = {"location": int(m.group(1)), "var": m.group(3)}
        if m.group(2) is not None:
            entry["index"] = int(m.group(2))
        outs.append(entry)
    ins = [{"location": int(m.group(1)), "var": m.group(2)} for m in RE_GLSL_IN.finditer(text)]
    samplers = [
        {"binding": int(m.group(1)), "type": m.group(2), "name": m.group(3)}
        for m in RE_GLSL_SAMPLER.finditer(text)
    ]
    ubos = [
        {"binding": int(m.group(1)), "block": m.group(2)}
        for m in RE_GLSL_UBO.finditer(text)
    ]
    return {"outputs": outs, "inputs": ins, "samplers": samplers, "ubos": ubos}


def inspect_shader_files(
    prog_id: int,
    stage: str,
    dxbc_path: Optional[Path],
    glsl_path: Optional[Path],
) -> ShaderInfo:
    info = ShaderInfo(prog_id=prog_id, stage=stage, dxbc_path=dxbc_path, glsl_path=glsl_path)
    has_dxbc = dxbc_path is not None and dxbc_path.is_file()
    has_glsl = glsl_path is not None and glsl_path.is_file()
    if has_dxbc:
        try:
            isgn, osgn, errs = parse_dxbc_signatures(dxbc_path.read_bytes())
            info.isgn = isgn
            info.osgn = osgn
            info.parse_errors.extend(errs)
        except OSError as exc:
            info.parse_errors.append(f"Failed reading DXBC: {exc}")
    if has_glsl:
        try:
            meta = parse_glsl_metadata(glsl_path.read_text(encoding="utf-8", errors="replace"))
            info.glsl_outputs = meta["outputs"]
            info.glsl_inputs = meta["inputs"]
            info.samplers = meta["samplers"]
            info.ubos = meta["ubos"]
        except OSError as exc:
            info.parse_errors.append(f"Failed reading GLSL: {exc}")
    if has_dxbc and has_glsl:
        info.source = "dxbc+glsl"
    elif has_dxbc:
        info.source = "dxbc"
    elif has_glsl:
        info.source = "glsl"
    return info


def parse_ppm_header(path: Path) -> Optional[Tuple[int, int]]:
    """Read width and height from a P6/P3 PPM header without loading pixels."""
    try:
        with open(path, "rb") as f:
            head = f.read(128)
        tokens: List[bytes] = []
        i = 0
        n = len(head)
        while i < n and len(tokens) < 4:
            if head[i : i + 1] == b"#":
                nl = head.find(b"\n", i)
                if nl == -1:
                    break
                i = nl + 1
                continue
            if head[i : i + 1].isspace():
                i += 1
                continue
            j = i
            while j < n and not head[j : j + 1].isspace() and head[j : j + 1] != b"#":
                j += 1
            tokens.append(head[i:j])
            i = j
        if len(tokens) >= 3 and tokens[0] in (b"P6", b"P3"):
            return int(tokens[1]), int(tokens[2])
    except (OSError, ValueError):
        return None
    return None


def parse_png_header(path: Path) -> Optional[Tuple[int, int]]:
    try:
        with open(path, "rb") as f:
            head = f.read(24)
        if len(head) >= 24 and head[:8] == b"\x89PNG\r\n\x1a\n":
            w, h = struct.unpack(">II", head[16:24])
            return w, h
    except OSError:
        return None
    return None


RE_SHADER_FILE = re.compile(r"^p(\d+)_(vs|hs|ds|gs|ps|cs)\.(dxbc|glsl)$")


def load_snapshot(snap_dir: Path) -> SnapshotData:
    """Load and parse a snapshot directory deterministically."""
    if not snap_dir.is_dir():
        raise FileNotFoundError(f"Snapshot directory not found: {snap_dir}")

    snap = SnapshotData(snap_dir=snap_dir)

    # Index shader artifacts
    for entry in sorted(snap_dir.iterdir()):
        if not entry.is_file():
            continue
        m = RE_SHADER_FILE.match(entry.name)
        if m:
            pid = int(m.group(1))
            stg = m.group(2)
            ext = m.group(3)
            snap.shader_files.setdefault((pid, stg), {})[ext] = entry

    # Locate final image (prefer final.png, fallback final.ppm)
    for img_name in ("final.png", "final.ppm"):
        cand = snap_dir / img_name
        if cand.is_file():
            snap.final_image_path = cand
            snap.final_image_sha256 = sha256_file(cand)
            if img_name.endswith(".ppm"):
                snap.final_image_dims = parse_ppm_header(cand)
            else:
                snap.final_image_dims = parse_png_header(cand)
            break

    draws_log = snap_dir / "draws.log"
    if not draws_log.is_file():
        snap.log_warnings.append("Missing draws.log in snapshot directory.")
        return snap

    snap.draws_log_sha256 = sha256_file(draws_log)
    current_draw: Optional[DrawEvent] = None
    order = 0

    with open(draws_log, "r", encoding="utf-8", errors="replace") as f:
        for line_no, raw in enumerate(f, start=1):
            line = raw.rstrip("\r\n")
            if not line:
                continue

            m = RE_BEGIN.match(line)
            if m:
                snap.after_present = int(m.group(1))
                snap.bb_width = int(m.group(2))
                snap.bb_height = int(m.group(3))
                snap.bb_fmt = int(m.group(4))
                continue

            m = RE_END.match(line)
            if m:
                snap.end_present = int(m.group(1))
                snap.reported_total_draws = int(m.group(2))
                snap.log_complete = True
                continue

            m = RE_CLEAR_RTV.match(line)
            if m:
                order += 1
                snap.clears.append(
                    ClearRtvEvent(
                        line_no=line_no,
                        order=order,
                        gl_id=int(m.group(1)),
                        width=int(m.group(2)),
                        height=int(m.group(3)),
                        fmt=int(m.group(4)),
                        rgba=(
                            _parse_float(m.group(5)),
                            _parse_float(m.group(6)),
                            _parse_float(m.group(7)),
                            _parse_float(m.group(8)),
                        ),
                    )
                )
                current_draw = None
                continue

            m = RE_DISPATCH.match(line)
            if m:
                order += 1
                snap.dispatches.append(
                    DispatchEvent(
                        line_no=line_no,
                        order=order,
                        prog_id=int(m.group(1)),
                        xyz=(int(m.group(2)), int(m.group(3)), int(m.group(4))),
                        indirect=(m.group(5) == "true"),
                    )
                )
                current_draw = None
                continue

            m = RE_DRAW.match(line)
            if m:
                order += 1
                current_draw = DrawEvent(
                    line_no=line_no,
                    order=order,
                    draw_id=int(m.group(1)),
                    prog_id=int(m.group(2)),
                    stages=m.group(3),
                    topo=int(m.group(4)),
                    kind=m.group(5),
                    count=int(m.group(6)),
                    instances=int(m.group(7)),
                    fb_w=int(m.group(8)),
                    fb_h=int(m.group(9)),
                    nrt=int(m.group(10)),
                    rt0_gl=int(m.group(11)),
                    rt0_fmt=int(m.group(12)),
                    rt0_swapchain=(m.group(13) == "true"),
                    dsv_gl=int(m.group(14)),
                    dsv_fmt=int(m.group(15)),
                    blend_enable=(m.group(16) == "true"),
                    blend_src_rgb=m.group(17),
                    blend_src_a=m.group(18),
                    blend_dst_rgb=m.group(19),
                    blend_dst_a=m.group(20),
                    blend_op=m.group(21),
                    write_mask=int(m.group(22), 16),
                    independent_blend=(m.group(23) == "true"),
                    depth_enable=(m.group(24) == "true"),
                    depth_write=(m.group(25) == "true"),
                    depth_func=m.group(26),
                    stencil_enable=(m.group(27) == "true"),
                    cull_mode=int(m.group(28)),
                    front_ccw=(m.group(29) == "true"),
                    scissor_enable=(m.group(30) == "true"),
                    depth_clip=(m.group(31) == "true"),
                )
                snap.draws.append(current_draw)
                continue

            m = RE_CHG.match(line)
            if m and current_draw is not None:
                current_draw.probes.append(
                    ProbeChange(
                        line_no=line_no,
                        probe_idx=int(m.group(1)),
                        x=int(m.group(2)),
                        y=int(m.group(3)),
                        before=(
                            _parse_float(m.group(4)),
                            _parse_float(m.group(5)),
                            _parse_float(m.group(6)),
                            _parse_float(m.group(7)),
                        ),
                        after=(
                            _parse_float(m.group(8)),
                            _parse_float(m.group(9)),
                            _parse_float(m.group(10)),
                            _parse_float(m.group(11)),
                        ),
                    )
                )
                continue

            m = RE_PS_SRV.match(line)
            if m and current_draw is not None:
                current_draw.ps_srvs.append(
                    PsSrvBinding(
                        line_no=line_no,
                        slot=int(m.group(1)),
                        unit=int(m.group(2)),
                        samp_slot=int(m.group(3)),
                        tex_gl=int(m.group(4)),
                        width=int(m.group(5)),
                        height=int(m.group(6)),
                        tex_fmt=int(m.group(7)),
                        view_fmt=int(m.group(8)),
                        target_hex=m.group(9),
                        mips=m.group(10),
                        sampler_gl=int(m.group(11)),
                        sampler_desc=m.group(12),
                    )
                )
                continue

    if not snap.log_complete:
        snap.log_warnings.append("draws.log is truncated (missing END marker).")
    elif snap.reported_total_draws is not None and snap.reported_total_draws != len(snap.draws):
        snap.log_warnings.append(
            f"draws.log draw count mismatch: END reports {snap.reported_total_draws}, parsed {len(snap.draws)}."
        )
    if snap.bb_width and snap.final_image_dims:
        if (snap.bb_width, snap.bb_height) != snap.final_image_dims:
            snap.log_warnings.append(
                f"Backbuffer dims {snap.bb_width}x{snap.bb_height} differ from final image {snap.final_image_dims[0]}x{snap.final_image_dims[1]}."
            )

    return snap


def read_glsl_slice(
    glsl_path: Path,
    *,
    start_line: int = 1,
    max_lines: int = 60,
    hard_cap: int = 200,
) -> Dict[str, Any]:
    lines = glsl_path.read_text(encoding="utf-8", errors="replace").splitlines()
    total = len(lines)
    start = max(1, int(start_line))
    count = max(1, min(int(max_lines), hard_cap))
    end = min(total, start + count - 1)
    snippet = "\n".join(f"{idx}: {lines[idx - 1]}" for idx in range(start, end + 1)) if start <= total else ""
    return {
        "start_line": start,
        "end_line": end if start <= total else start - 1,
        "total_lines": total,
        "truncated": end < total,
        "snippet": snippet,
    }
