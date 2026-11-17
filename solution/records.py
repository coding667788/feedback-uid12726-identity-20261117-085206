"""Parsing and validation of the event file format.

Format (JSON Lines, UTF-8, one object per line)::

    {"type":"host_key","host":"h1","public_key":"<hex 32B>"}
    {"type":"boot","host":"h1","boot_id":"b1","calibration":{"offset_lo_ms":..,"offset_hi_ms":..},
     "sig":"<hex 64B>","key":"<optional key id>"}
    {"type":"event","id":"e1","host":"h1","boot_id":"b1","seq":1,
     "mono_ns":1000000,"wall":"2026-01-01T00:00:01.000Z","kind":"send",
     "message_id":"m1","sig":"<hex 64B>"}
    {"type":"event","id":"e2",...,"kind":"recv","message_id":"m1"}

The signature covers the *canonical record*: the JSON object with the
``sig`` member removed, serialised with sorted keys, no whitespace and UTF-8.
That means whitespace and member order in the file are free, but any change
to a value, including a changed timestamp or sequence number, breaks the
signature.

Calibration semantics
---------------------
``wall_true = wall_stated - offset``, where ``offset`` is drawn from the
closed interval ``[offset_lo_ns, offset_hi_ns]``.  A symmetric calibration
therefore carries ``offset_lo = -bound``, ``offset_hi = +bound``.
``mono_earliest`` records the smallest ``mono_ns`` value already observed on
this boot (usually the boot start reading).  It is kept as evidence and shown
in the output, but it deliberately produces **no** time constraint: the anchor
it would provide is already implied by the wall-clock windows plus the
elapsed-monotonic constraints, and adding it can only make a rollback look
like an arithmetic error instead of a clock jump.  See the model module
docstring for the constraint list.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .integrity import canonical_json_bytes
from .timeutil import MS, TimestampError, parse_rfc3339_ns

EVENT_KINDS = frozenset({"send", "recv", "local"})
RECORD_TYPES = frozenset({"event", "boot", "host_key", "calibration"})


@dataclass
class Calibration:
    offset_lo_ns: int
    offset_hi_ns: int
    mono_earliest_ns: int | None = None

    def __post_init__(self) -> None:
        if self.offset_lo_ns > self.offset_hi_ns:
            raise ValueError("calibration offset_lo_ns > offset_hi_ns")

    def to_json(self) -> dict:
        out = {
            "offset_lo_ns": self.offset_lo_ns,
            "offset_hi_ns": self.offset_hi_ns,
        }
        if self.mono_earliest_ns is not None:
            out["mono_earliest_ns"] = self.mono_earliest_ns
        return out


@dataclass
class HostKey:
    host: str
    public_key: bytes
    raw: dict[str, Any]
    line: int


@dataclass
class BootRecord:
    host: str
    boot_id: str
    calibration: Calibration
    raw: dict[str, Any]
    line: int
    signature_ok: bool
    occurrence: dict[str, Any] | None = None


@dataclass
class EventRecord:
    id: str
    host: str
    boot_id: str
    seq: int
    mono_ns: int
    wall_ns: int
    kind: str
    message_id: str | None
    raw: dict[str, Any]
    line: int
    signature_ok: bool
    signature_absent: bool = False
    signature_present: bool = True

    @property
    def canonical_sha256(self) -> str:
        return canonical_digest(self.raw)


class RecordError(ValueError):
    """A record failed validation; carries a diagnostic code."""

    def __init__(self, code: str, message: str, **detail: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail


def canonical_digest(raw: dict[str, Any]) -> str:
    import hashlib

    unsigned = {k: v for k, v in raw.items() if k != "sig"}
    return hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()


def canonical_payload(raw: dict[str, Any]) -> bytes:
    """Bytes covered by a record signature."""
    unsigned = {k: v for k, v in raw.items() if k != "sig"}
    return canonical_json_bytes(unsigned)


def _require(obj: dict[str, Any], key: str, types: type | tuple[type, ...], where: str) -> Any:
    if key not in obj:
        raise RecordError("E_LINE_SCHEMA", f"{where}: missing required member {key!r}", member=key)
    value = obj[key]
    if isinstance(value, bool) and types is not bool:
        raise RecordError("E_LINE_SCHEMA", f"{where}: member {key!r} has the wrong type", member=key)
    if not isinstance(value, types):
        raise RecordError(
            "E_LINE_SCHEMA",
            f"{where}: member {key!r} has type {type(value).__name__}",
            member=key,
        )
    return value


def _require_int(obj: dict[str, Any], key: str, where: str) -> int:
    value = _require(obj, key, int, where)
    return value


def _require_str(obj: dict[str, Any], key: str, where: str) -> str:
    value = _require(obj, key, str, where)
    if not value:
        raise RecordError("E_LINE_SCHEMA", f"{where}: member {key!r} must not be empty", member=key)
    return value


def _parse_hex(value: Any, size: int, where: str, key: str) -> bytes:
    if not isinstance(value, str):
        raise RecordError("E_SIG_INVALID", f"{where}: {key} is not a hex string", member=key)
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise RecordError("E_SIG_INVALID", f"{where}: {key} is not valid hex", member=key) from None
    if len(raw) != size:
        raise RecordError(
            "E_SIG_INVALID",
            f"{where}: {key} must be {size} bytes, got {len(raw)}",
            member=key,
        )
    return raw


def parse_host_key(obj: dict[str, Any], where: str) -> HostKey:
    host = _require_str(obj, "host", where)
    public = _parse_hex(obj.get("public_key"), 32, where, "public_key")
    return HostKey(host=host, public_key=public, raw=obj, line=0)


def _parse_calibration(obj: dict[str, Any], where: str) -> Calibration:
    cal = obj.get("calibration")
    if cal is None:
        raise RecordError("E_LINE_SCHEMA", f"{where}: boot record has no calibration", member="calibration")
    if not isinstance(cal, dict):
        raise RecordError("E_LINE_SCHEMA", f"{where}: calibration must be an object", member="calibration")
    for key in ("offset_lo_ms", "offset_hi_ms"):
        if key not in cal:
            raise RecordError("E_CALIBRATION", f"{where}: calibration missing {key}", member=key)
        if isinstance(cal[key], bool) or not isinstance(cal[key], int):
            raise RecordError("E_CALIBRATION", f"{where}: calibration {key} must be an integer", member=key)
    lo = cal["offset_lo_ms"] * MS
    hi = cal["offset_hi_ms"] * MS
    if lo > hi:
        raise RecordError(
            "E_CALIBRATION",
            f"{where}: calibration offset_lo_ms > offset_hi_ms",
            member="calibration",
        )
    mono_earliest = None
    if "mono_earliest_ns" in cal:
        if isinstance(cal["mono_earliest_ns"], bool) or not isinstance(cal["mono_earliest_ns"], int):
            raise RecordError("E_CALIBRATION", f"{where}: mono_earliest_ns must be an integer", member="mono_earliest_ns")
        mono_earliest = cal["mono_earliest_ns"]
    return Calibration(offset_lo_ns=lo, offset_hi_ns=hi, mono_earliest_ns=mono_earliest)


def parse_boot(obj: dict[str, Any], where: str, signature_ok: bool) -> BootRecord:
    host = _require_str(obj, "host", where)
    boot_id = _require_str(obj, "boot_id", where)
    cal = _parse_calibration(obj, where)
    return BootRecord(host=host, boot_id=boot_id, calibration=cal, raw=obj, line=0, signature_ok=signature_ok)


def parse_event(obj: dict[str, Any], where: str, signature_ok: bool, signature_absent: bool) -> EventRecord:
    event_id = _require_str(obj, "id", where)
    host = _require_str(obj, "host", where)
    boot_id = _require_str(obj, "boot_id", where)
    seq = _require_int(obj, "seq", where)
    if seq < 0:
        raise RecordError("E_LINE_SCHEMA", f"{where}: seq must be >= 0", member="seq")
    mono = _require_int(obj, "mono_ns", where)
    wall_text = _require_str(obj, "wall", where)
    kind = _require_str(obj, "kind", where)
    if kind not in EVENT_KINDS:
        raise RecordError("E_LINE_SCHEMA", f"{where}: unknown kind {kind!r}", member="kind")
    message_id = obj.get("message_id")
    if message_id is not None and not isinstance(message_id, str):
        raise RecordError("E_LINE_SCHEMA", f"{where}: message_id must be a string", member="message_id")
    if kind in ("send", "recv") and not message_id:
        raise RecordError(
            "E_LINE_SCHEMA",
            f"{where}: a {kind} event requires a non-empty message_id",
            member="message_id",
        )
    if kind == "local" and message_id is not None:
        raise RecordError(
            "E_LINE_SCHEMA",
            f"{where}: a local event must not carry message_id",
            member="message_id",
        )
    try:
        wall_ns = parse_rfc3339_ns(wall_text)
    except TimestampError as exc:
        raise RecordError("E_TIMESTAMP", f"{where}: {exc}", member="wall") from None
    return EventRecord(
        id=event_id,
        host=host,
        boot_id=boot_id,
        seq=seq,
        mono_ns=mono,
        wall_ns=wall_ns,
        kind=kind,
        message_id=message_id,
        raw=obj,
        line=0,
        signature_ok=signature_ok,
        signature_absent=signature_absent,
        signature_present="sig" in obj,
    )


def type_of(obj: Any, where: str) -> str:
    if not isinstance(obj, dict):
        raise RecordError("E_LINE_JSON", f"{where}: line is not a JSON object")
    rtype = obj.get("type")
    if not isinstance(rtype, str) or rtype not in RECORD_TYPES:
        raise RecordError("E_LINE_SCHEMA", f"{where}: unknown or missing record type")
    return rtype


__all__ = [
    "BootRecord",
    "Calibration",
    "EventRecord",
    "HostKey",
    "RecordError",
    "canonical_digest",
    "canonical_payload",
    "parse_boot",
    "parse_event",
    "parse_host_key",
    "type_of",
]
