"""Collection of host event files into typed, provenance carrying records.

The collector is the only place that turns bytes into records.  For every
accepted record it keeps the source id, the 1 based line number and the exact
byte range, and it never writes to a source file.

Two passes
----------
A signature can only be verified once the host's public key is known, and
nothing requires the ``host_key`` record to come first (or in the same file as
the events it signed).  So ``add_source`` only decodes each line and remembers
it; ``finish`` registers every ``host_key`` record from every source, then
ingests boots and events.

Deduplication rule (deliberately narrow)
----------------------------------------
Two records are the same event only when their content is identical — the same
canonical digest *and* the same claimed id.  Duplicates merge into one node
that lists every physical occurrence, each keeping its own line number and
byte range.  A CRLF re-export of the same JSON still merges, because the
canonical digest ignores whitespace *outside* the record; a changed value does
not.

Records with the same id but different content are **conflicts**: they stay as
separate evidence, no variant is preferred, and the id is excluded from the
timeline because its wall clocks disagree.

Signature states
----------------
``valid``       verified against the host key collected in the same batch
``unverified``  no host key for that host was collected; recorded, not checked
``absent``      the record carries no ``sig`` member at all
``invalid``     the signature does not verify: the record is dropped
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from .crypto.ed25519 import verify as ed25519_verify
from .errors import Diagnostic
from .integrity import sha256_bytes
from .records import (
    BootRecord,
    HostKey,
    RecordError,
    canonical_digest,
    canonical_payload,
    parse_boot,
    parse_event,
    parse_host_key,
    type_of,
)
from .sources import LineSlice, SourceBytes, split_lines

SIG_VALID = "valid"
SIG_UNVERIFIED = "unverified"
SIG_ABSENT = "absent"


@dataclass
class Occurrence:
    """One physical copy of a record in one source file."""

    source_id: str
    line: int
    byte_start: int
    byte_end: int
    line_sha256: str
    host: str | None

    def to_json(self) -> dict[str, Any]:
        return {
            "source": self.source_id,
            "line": self.line,
            "byte_start": self.byte_start,
            "byte_end": self.byte_end,
            "line_sha256": self.line_sha256,
            "line_bytes": self.byte_end - self.byte_start,
        }

    @property
    def key(self) -> tuple[str, int]:
        return (self.source_id, self.line)


@dataclass
class EventNode:
    """A deduplicated event; may aggregate several identical occurrences."""

    id: str
    host: str
    boot_id: str
    seq: int
    mono_ns: int
    wall_ns: int
    kind: str
    message_id: str | None
    digest: str
    signature: str
    occurrences: list[Occurrence] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        from .timeutil import format_rfc3339_ns

        return {
            "id": self.id,
            "host": self.host,
            "boot_id": self.boot_id,
            "seq": self.seq,
            "mono_ns": self.mono_ns,
            "wall": format_rfc3339_ns(self.wall_ns),
            "kind": self.kind,
            "message_id": self.message_id,
            "content_sha256": self.digest,
            "signature": self.signature,
            "occurrences": [o.to_json() for o in self.occurrences],
        }


@dataclass
class ConflictGroup:
    """Several distinct contents claiming one event id."""

    id: str
    variants: list[EventNode]

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "variant_count": len(self.variants),
            "variants": [v.to_json() for v in self.variants],
        }


@dataclass
class Collection:
    sources: list[SourceBytes] = field(default_factory=list)
    host_keys: dict[str, HostKey] = field(default_factory=dict)
    boots: dict[tuple[str, str], BootRecord] = field(default_factory=dict)
    events: dict[str, EventNode] = field(default_factory=dict)
    conflicts: list[ConflictGroup] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    occurrences: dict[tuple[str, int], Occurrence] = field(default_factory=dict)
    # (source id, line) -> code, for every line that did not become a record
    rejected: dict[tuple[str, int], str] = field(default_factory=dict)
    # (source id, line) -> code, for every line that was accepted
    accepted: dict[tuple[str, int], str] = field(default_factory=dict)

    def add_diag(self, diag: Diagnostic) -> None:
        self.diagnostics.append(diag)


@dataclass
class _Row:
    source: SourceBytes
    line: LineSlice
    obj: dict[str, Any]
    rtype: str


class Collector:
    def __init__(self) -> None:
        self.collection = Collection()
        self._by_digest: dict[tuple[str, str], EventNode] = {}
        self._events_by_id: dict[str, list[EventNode]] = defaultdict(list)
        self._rows: list[_Row] = []

    # -- diagnostics -----------------------------------------------------
    def _fail(self, source: SourceBytes, line: LineSlice, code: str,
              message: str, **detail: Any) -> None:
        self.collection.rejected.setdefault((source.source_id, line.line), code)
        self.collection.add_diag(
            Diagnostic(
                code=code,
                message=f"{source.source_id}:{line.line}: {message}",
                source_id=source.source_id,
                line=line.line,
                byte_start=line.byte_start,
                byte_end=line.byte_end,
                detail=detail,
            )
        )

    def _note(self, source: SourceBytes, line: LineSlice, code: str,
              message: str, **detail: Any) -> None:
        self.collection.accepted.setdefault((source.source_id, line.line), code)
        self.collection.add_diag(
            Diagnostic(
                code=code,
                message=f"{source.source_id}:{line.line}: {message}",
                source_id=source.source_id,
                line=line.line,
                byte_start=line.byte_start,
                byte_end=line.byte_end,
                detail=detail,
            )
        )

    # -- pass 1: decode ------------------------------------------------
    def add_source(self, source: SourceBytes) -> None:
        self.collection.sources.append(source)
        for line in split_lines(source.data):
            raw = line.text
            if not raw.strip():
                continue
            try:
                decoded = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                self._fail(source, line, "E_LINE_ENCODING",
                           f"invalid UTF-8 at byte offset {exc.start} of the line")
                continue
            try:
                obj = json.loads(decoded)
            except json.JSONDecodeError as exc:
                self._fail(source, line, "E_LINE_JSON",
                           f"invalid JSON: {exc.msg} at column {exc.colno}")
                continue
            try:
                rtype = type_of(obj, f"{source.source_id}:{line.line}")
            except RecordError as exc:
                self._fail(source, line, exc.code, exc.message, **exc.detail)
                continue
            self._rows.append(_Row(source, line, obj, rtype))

    # -- pass 2: keys, then records ------------------------------------
    def finish(self) -> Collection:
        for row in self._rows:
            if row.rtype != "host_key":
                continue
            try:
                self._add_host_key(row.obj, f"{row.source.source_id}:{row.line.line}")
            except RecordError as exc:
                self._fail(row.source, row.line, exc.code, exc.message, **exc.detail)
        for row in self._rows:
            if row.rtype == "host_key":
                continue
            self._ingest_row(row)
        for event_id in sorted(self._events_by_id):
            nodes = self._events_by_id[event_id]
            if len(nodes) > 1:
                self._report_conflict(event_id, nodes)
        del self._rows
        return self.collection

    def _ingest_row(self, row: _Row) -> None:
        source, line, obj = row.source, row.line, row.obj
        where = f"{source.source_id}:{line.line}"
        signature, error = self._signature_state(obj, where)
        if signature is None:
            self._fail(source, line, error[0], error[1], **error[2])
            return
        if error is not None:
            self._fail(source, line, error[0], error[1], **error[2])
        try:
            if row.rtype == "boot":
                self._add_boot(obj, where, signature, source, line)
            elif row.rtype == "event":
                self._add_event(obj, where, signature, source, line)
            else:
                self._fail(source, line, "E_LINE_SCHEMA",
                           "a bare calibration record is not part of the schema")
        except RecordError as exc:
            self._fail(source, line, exc.code, exc.message, **exc.detail)

    def _signature_state(self, obj: dict[str, Any], where: str):
        """Return ``(state, error)``; ``state is None`` means the record is dropped."""
        host = obj.get("host")
        if "sig" not in obj:
            if isinstance(host, str) and host in self.collection.host_keys:
                return None, (
                    "E_SIG_MISSING",
                    f"a host key is known for {host!r} but this record carries no sig",
                    {"host": host},
                )
            return SIG_ABSENT, None
        sig_text = obj.get("sig")
        if not isinstance(sig_text, str):
            return None, ("E_SIG_INVALID", "sig must be a hex string", {})
        try:
            sig = bytes.fromhex(sig_text)
        except ValueError:
            return None, ("E_SIG_INVALID", "sig is not valid hex", {})
        if len(sig) != 64:
            return None, ("E_SIG_INVALID", f"sig must be 64 bytes, got {len(sig)}", {})
        key = self.collection.host_keys.get(host) if isinstance(host, str) else None
        if key is None:
            return SIG_UNVERIFIED, (
                "E_SIG_UNVERIFIED",
                f"no host_key record for host {host!r}; the signature is recorded but was not checked",
                {"host": host},
            )
        if not ed25519_verify(key.public_key, canonical_payload(obj), sig):
            return None, (
                "E_SIG_INVALID",
                "signature does not verify against the host key",
                {"host": host},
            )
        return SIG_VALID, None

    # -- record kinds ----------------------------------------------------
    def _add_host_key(self, obj: dict[str, Any], where: str) -> None:
        record = parse_host_key(obj, where)
        existing = self.collection.host_keys.get(record.host)
        if existing is not None and existing.public_key != record.public_key:
            raise RecordError(
                "E_LINE_SCHEMA",
                f"host {record.host!r} already has a different public key",
                host=record.host,
            )
        self.collection.host_keys[record.host] = record

    def _add_boot(self, obj: dict[str, Any], where: str, signature: str,
                  source: SourceBytes, line: LineSlice) -> None:
        record = parse_boot(obj, where, signature == SIG_VALID)
        record.line = line.line
        key = (record.host, record.boot_id)
        occurrence = Occurrence(
            source.source_id, line.line, line.byte_start, line.byte_end,
            _line_digest(line), record.host,
        )
        existing = self.collection.boots.get(key)
        if existing is not None:
            if existing.calibration != record.calibration:
                raise RecordError(
                    "E_BOOT_ID",
                    f"boot {record.boot_id!r} on {record.host!r} already has a different calibration",
                    host=record.host,
                    boot_id=record.boot_id,
                )
            if canonical_digest(existing.raw) != canonical_digest(obj):
                raise RecordError(
                    "E_ID_CONFLICT",
                    f"boot {record.boot_id!r} on {record.host!r} was collected with different content",
                    host=record.host,
                    boot_id=record.boot_id,
                )
            self.collection.occurrences[occurrence.key] = occurrence
            self._note(source, line, "E_DUPLICATE",
                       "identical boot record already collected, merged",
                       host=record.host, boot_id=record.boot_id,
                       first_occurrence=existing.occurrence)
            return
        self.collection.boots[key] = record
        record.occurrence = occurrence.to_json()
        self.collection.occurrences[occurrence.key] = occurrence

    def _add_event(self, obj: dict[str, Any], where: str, signature: str,
                   source: SourceBytes, line: LineSlice) -> None:
        record = parse_event(obj, where, signature == SIG_VALID, signature == SIG_ABSENT)
        record.line = line.line
        digest = canonical_digest(obj)
        occurrence = Occurrence(
            source.source_id, line.line, line.byte_start, line.byte_end,
            _line_digest(line), record.host,
        )
        self.collection.occurrences[occurrence.key] = occurrence
        node = self._by_digest.get((record.id, digest))
        if node is not None:
            node.occurrences.append(occurrence)
            self._note(source, line, "E_DUPLICATE",
                       f"content-identical duplicate of event {record.id!r}, merged",
                       event_id=record.id, content_sha256=digest,
                       first_occurrence=node.occurrences[0].to_json())
            return
        node = EventNode(
            id=record.id,
            host=record.host,
            boot_id=record.boot_id,
            seq=record.seq,
            mono_ns=record.mono_ns,
            wall_ns=record.wall_ns,
            kind=record.kind,
            message_id=record.message_id,
            digest=digest,
            signature=signature,
            occurrences=[occurrence],
        )
        self._by_digest[(record.id, digest)] = node
        self._events_by_id[record.id].append(node)
        self.collection.events[record.id] = node

    def _report_conflict(self, event_id: str, nodes: list[EventNode]) -> None:
        self.collection.conflicts.append(ConflictGroup(event_id, nodes))
        self.collection.add_diag(
            Diagnostic(
                code="E_ID_CONFLICT",
                message=(
                    f"event id {event_id!r} has {len(nodes)} different contents; "
                    "no variant is preferred and the id is excluded from the timeline"
                ),
                detail={
                    "event_id": event_id,
                    "variants": [
                        {
                            "content_sha256": node.digest,
                            "seq": node.seq,
                            "wall_ns": node.wall_ns,
                            "occurrences": [o.to_json() for o in node.occurrences],
                        }
                        for node in nodes
                    ],
                },
            )
        )


def _line_digest(line: LineSlice) -> str:
    return sha256_bytes(line.data)


def collect(sources: list[SourceBytes]) -> tuple[Collection, list[Diagnostic]]:
    collector = Collector()
    for source in sources:
        collector.add_source(source)
    collection = collector.finish()
    return collection, collection.diagnostics


__all__ = [
    "Collection",
    "Collector",
    "ConflictGroup",
    "EventNode",
    "Occurrence",
    "collect",
]
