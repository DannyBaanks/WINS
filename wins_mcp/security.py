"""Security boundaries, path allowlists, and output sanitization for wins-mcp.

Default security posture: read-only, untrusted-data framing, no arbitrary shell.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

SECRET_PATTERNS = [
    re.compile(r"(gh[pousr]_[A-Za-z0-9_]{20,})"),
    re.compile(r"(LEASE_TOKEN=[^\s]+)"),
    re.compile(r"(Bearer\s+[A-Za-z0-9._\-]{20,})", re.IGNORECASE),
    re.compile(r"((?:api[_-]?key|token|secret|password)\s*[=:]\s*['\"]?[^\s'\"]{12,})", re.IGNORECASE),
]


class SecurityError(PermissionError):
    """Raised when an operation violates wins-mcp path or permission boundaries."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_allowed_roots(extra_roots: Optional[Sequence[Path]] = None) -> List[Path]:
    """Authorized directory roots for read operations.

    Override/extend via WINS_MCP_ALLOWED_ROOTS (colon-separated absolute paths).
    """
    home = Path(os.environ.get("WINS_MCP_HOME") or os.path.expanduser("~")).resolve()
    roots: List[Path] = [
        repo_root().resolve(),
        (home / ".local" / "share" / "wins").resolve(),
        (home / ".local" / "state" / "wins").resolve(),
        (home / ".cache" / "wins").resolve(),
        (home / ".local" / "share" / "Steam" / "logs").resolve(),
        (home / ".local" / "share" / "Steam" / "compatibilitytools.d").resolve(),
    ]
    env_roots = os.environ.get("WINS_MCP_ALLOWED_ROOTS", "").strip()
    if env_roots:
        for raw in env_roots.split(os.pathsep):
            raw = raw.strip()
            if raw:
                roots.append(Path(raw).expanduser().resolve())
    if extra_roots:
        for r in extra_roots:
            roots.append(Path(r).expanduser().resolve())
    # Deduplicate preserving order
    seen = set()
    uniq: List[Path] = []
    for r in roots:
        s = str(r)
        if s not in seen:
            seen.add(s)
            uniq.append(r)
    return uniq


def validate_path(
    raw_path: str | Path,
    allowed_roots: Optional[Sequence[Path]] = None,
    *,
    must_exist: bool = False,
    allow_tmp_wins: bool = True,
) -> Path:
    """Resolve and validate that a path stays strictly inside authorized roots."""
    if not raw_path or not str(raw_path).strip():
        raise SecurityError("INVALID_PATH", "Path argument must be a non-empty string.")
    raw_str = str(raw_path)
    if "\x00" in raw_str:
        raise SecurityError("INVALID_PATH", "Path contains null byte.")

    resolved = Path(raw_str).expanduser().resolve(strict=False)
    roots = list(allowed_roots) if allowed_roots is not None else default_allowed_roots()

    authorized = False
    for root in roots:
        try:
            resolved.relative_to(root)
            authorized = True
            break
        except ValueError:
            continue

    if not authorized and allow_tmp_wins:
        tmp_base = Path("/tmp").resolve()
        try:
            rel = resolved.relative_to(tmp_base)
            if rel.parts and rel.parts[0].startswith("wins-"):
                authorized = True
        except ValueError:
            pass

    if not authorized:
        raise SecurityError(
            "UNAUTHORIZED_PATH",
            f"Path '{resolved}' is outside authorized WINS-MCP roots.",
        )

    if must_exist and not resolved.exists():
        raise FileNotFoundError(f"Path does not exist: {resolved}")

    return resolved


def sanitize_text(text: str, max_chars: int = 4000) -> str:
    """Redact accidental secrets and cap text length."""
    out = text
    for pat in SECRET_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    if len(out) > max_chars:
        out = out[:max_chars] + f"\n... [truncated {len(text) - max_chars} chars]"
    return out


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_rel_label(path: Path, base: Optional[Path] = None) -> str:
    """Return a clean label avoiding leaking unrelated private path prefixes."""
    if base is not None:
        try:
            return str(path.resolve().relative_to(base.resolve()))
        except ValueError:
            pass
    try:
        return str(path.resolve().relative_to(repo_root().resolve()))
    except ValueError:
        return path.name


def enforce_context_budget(
    items: Sequence,
    limit: int,
    *,
    hard_cap: int = 32,
) -> tuple[list, bool, int]:
    """Apply bounded slicing and report truncation explicitly."""
    effective = max(1, min(int(limit), hard_cap))
    total = len(items)
    sliced = list(items[:effective])
    return sliced, total > effective, total
