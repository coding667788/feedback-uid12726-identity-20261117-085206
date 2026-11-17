"""Byte exact source ingestion.

Every collection file is read **twice, from two independently opened file
objects**, and every line is sliced by absolute byte offsets tracked in
memory.  Each event record keeps its exact byte range so callers can re-read
the original bytes for a record, re-hash them, and prove the tool did not
modify the evidence.

The files are opened ``"rb"`` and only ever read; the module has no write
path.  Line splitting understands ``\\r\\n``, so byte ranges always include
their terminator, matching what ``cut``/``dd`` would extract.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .errors import Diagnostic, ToolError
from .integrity import sha256_bytes


@dataclass(frozen=True)
class SourceBytes:
    source_id: str
    path: str
    data: bytes
    sha256: str

    @property
    def size(self) -> int:
        return len(self.data)

    def digest(self) -> str:
        return sha256_bytes(self.data)


@dataclass(frozen=True)
class LineSlice:
    """One physical line of a source file, addressed by absolute bytes."""

    line: int            # 1 based line number
    byte_start: int      # inclusive
    byte_end: int        # exclusive, includes the line terminator
    data: bytes          # exact bytes of the line including terminator

    @property
    def text(self) -> bytes:
        """Line bytes without the terminator."""
        if self.data.endswith(b"\r\n"):
            return self.data[:-2]
        if self.data.endswith(b"\n"):
            return self.data[:-1]
        return self.data

    def to_json(self) -> dict:
        return {
            "line": self.line,
            "byte_start": self.byte_start,
            "byte_end": self.byte_end,
            "sha256": sha256_bytes(self.data),
            "bytes": len(self.data),
        }


def split_lines(data: bytes) -> list[LineSlice]:
    """Split raw bytes into newline terminated slices with byte offsets.

    A final line without a terminator is still returned.  ``\\n`` inside a
    multi-byte UTF-8 sequence cannot occur, so byte offsets stay aligned.
    """
    out: list[LineSlice] = []
    pos = 0
    line_no = 1
    size = len(data)
    while pos < size:
        nl = data.find(b"\n", pos)
        if nl == -1:
            out.append(LineSlice(line_no, pos, size, data[pos:]))
            break
        end = nl + 1
        out.append(LineSlice(line_no, pos, end, data[pos:end]))
        pos = end
        line_no += 1
    return out


def slice_bytes(source: SourceBytes, byte_start: int, byte_end: int) -> bytes:
    """Return the original bytes of a record, with bounds checking."""
    if byte_start < 0 or byte_end > source.size or byte_start > byte_end:
        raise ValueError(
            f"byte range [{byte_start},{byte_end}) is outside {source.source_id} (size {source.size})"
        )
    return source.data[byte_start:byte_end]


def read_source(source_id: str, path: str, root: str) -> tuple[SourceBytes, list[Diagnostic]]:
    """Read a source file twice and verify the two reads are byte identical.

    ``root`` is the directory the cases file came from; paths are resolved
    relative to it and must stay inside it.
    """
    resolved = resolve_inside(root, path)
    if not os.path.exists(resolved):
        raise ToolError("E_INPUT_MISSING", f"source file not found: {path}", path=path, resolved=resolved)
    if not os.path.isfile(resolved):
        raise ToolError("E_INPUT_MISSING", f"source path is not a regular file: {path}", path=path)

    first = _read_bytes(resolved, source_id)
    second = _read_bytes(resolved, source_id)
    if len(first) != len(second) or first != second:
        raise ToolError(
            "E_SOURCE_HASH",
            f"source {source_id} changed between the two reads",
            source=source_id,
            first_sha256=sha256_bytes(first),
            second_sha256=sha256_bytes(second),
        )
    return SourceBytes(source_id, resolved, first, sha256_bytes(first)), []


def _read_bytes(resolved: str, source_id: str) -> bytes:
    try:
        with open(resolved, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise ToolError("E_SOURCE_READ", f"cannot read source {source_id}: {exc.strerror or exc}") from None


def resolve_inside(root: str, path: str) -> str:
    """Resolve ``path`` relative to ``root`` and refuse to escape it."""
    root_abs = os.path.realpath(root)
    candidate = path if os.path.isabs(path) else os.path.join(root_abs, path)
    resolved = os.path.realpath(candidate)
    if resolved != root_abs and not resolved.startswith(root_abs + os.sep):
        raise ToolError(
            "E_PATH_OUTSIDE_ROOT",
            f"source path {path!r} escapes {root_abs}",
            path=path,
            root=root_abs,
        )
    return resolved


__all__ = [
    "LineSlice",
    "SourceBytes",
    "read_source",
    "resolve_inside",
    "sha256_bytes",
    "slice_bytes",
    "split_lines",
]
