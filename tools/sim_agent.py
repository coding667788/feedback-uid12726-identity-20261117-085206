"""A simulated host recorder that produces *signed* event files.

This stands in for the acquisition agent running on a simulated host.  It is
deterministic: given the same scenario description and the same seed it emits
byte-identical files, so sample data and tests are reproducible.

Clock model used by the simulator
---------------------------------
* ``true``      : the real UTC instant, an integer number of nanoseconds;
* ``offset``    : how far the host clock is off, ``stated = true + offset``;
* calibration   : the closed interval the administrator measured, which must
                  contain the real offset for the scenario to be honest;
* monotonic     : ``mono = mono_earliest + (true - boot_instant)``, reset on
                  every boot.  Nothing may compare it across boots.

Deliberately *not* modelled: the agent never lies about a reading, it only
records what its clock said.  A rollback is produced by changing ``offset``
mid-boot, which is how a real clock jump shows up.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from solution.crypto.ed25519 import private_key_from_seed, public_key_from_private, sign
from solution.integrity import canonical_json_bytes
from solution.timeutil import format_rfc3339_ns


@dataclass
class HostIdentity:
    host: str
    seed: bytes
    private_key: bytes = field(init=False)
    public_key: bytes = field(init=False)

    def __post_init__(self) -> None:
        self.private_key = private_key_from_seed(self.seed)
        self.public_key = public_key_from_private(self.private_key)

    @property
    def public_key_hex(self) -> str:
        return self.public_key.hex()

    @classmethod
    def from_label(cls, host: str) -> "HostIdentity":
        """Deterministic key from a host label (test/sample use only)."""
        import hashlib

        return cls(host, hashlib.sha256(f"sim-host-key:{host}".encode("utf-8")).digest())


@dataclass
class BootSession:
    """Bookkeeping for one boot so callers can place events on its timeline."""

    host: str
    boot_id: str
    boot_instant_ns: int
    mono_earliest_ns: int
    offset_ns: int
    offset_lo_ms: int
    offset_hi_ms: int
    drift_ppm: int
    follows: tuple[str, str] | None = None
    next_seq: int = 1

    def mono_at(self, true_ns: int) -> int:
        return self.mono_earliest_ns + (true_ns - self.boot_instant_ns)

    def true_from_mono(self, mono_ns: int) -> int:
        return self.boot_instant_ns + (mono_ns - self.mono_earliest_ns)


class HostRecorder:
    """Builds one signed event file for one host."""

    def __init__(self, identity: HostIdentity, *, crlf: bool = False) -> None:
        self.identity = identity
        self.records: list[dict[str, Any]] = []
        self.crlf = crlf
        self.records.append(
            {
                "type": "host_key",
                "host": identity.host,
                "public_key": identity.public_key_hex,
            }
        )

    # -- record constructors --------------------------------------------
    def boot(self, boot_id: str, *, offset_lo_ms: int, offset_hi_ms: int,
             mono_earliest_ns: int, follows: tuple[str, str] | None = None,
             drift_ppm: int | None = None, note: str | None = None) -> dict[str, Any]:
        record: dict[str, Any] = {
            "type": "boot",
            "host": self.identity.host,
            "boot_id": boot_id,
            "calibration": {
                "offset_lo_ms": offset_lo_ms,
                "offset_hi_ms": offset_hi_ms,
                "mono_earliest_ns": mono_earliest_ns,
            },
        }
        if follows is not None:
            record["follows"] = {"host": follows[0], "boot_id": follows[1]}
        if drift_ppm is not None:
            record["drift_ppm"] = drift_ppm
        if note is not None:
            record["note"] = note
        self.records.append(self._signed(record))
        return record

    def event(self, *, id: str, boot_id: str, seq: int, mono_ns: int, wall_ns: int,
              kind: str = "local", message_id: str | None = None,
              note: str | None = None) -> dict[str, Any]:
        record: dict[str, Any] = {
            "type": "event",
            "id": id,
            "host": self.identity.host,
            "boot_id": boot_id,
            "seq": seq,
            "mono_ns": mono_ns,
            "wall": format_rfc3339_ns(wall_ns),
            "kind": kind,
        }
        if message_id is not None:
            record["message_id"] = message_id
        if note is not None:
            record["note"] = note
        self.records.append(self._signed(record))
        return record

    def event_at(self, session: BootSession, *, id: str, true_ns: int,
                 kind: str = "local", message_id: str | None = None,
                 wall_override_ns: int | None = None, seq: int | None = None,
                 mono_override_ns: int | None = None,
                 note: str | None = None) -> dict[str, Any]:
        """Place an event at a true instant, deriving mono and wall from the boot."""
        mono = session.mono_at(true_ns) if mono_override_ns is None else mono_override_ns
        wall = (true_ns + session.offset_ns) if wall_override_ns is None else wall_override_ns
        use_seq = session.next_seq if seq is None else seq
        session.next_seq = max(session.next_seq + 1, use_seq + 1)
        return self.event(
            id=id,
            boot_id=session.boot_id,
            seq=use_seq,
            mono_ns=mono,
            wall_ns=wall,
            kind=kind,
            message_id=message_id,
            note=note,
        )

    # -- output ----------------------------------------------------------
    def _signed(self, record: dict[str, Any]) -> dict[str, Any]:
        payload = canonical_json_bytes(record)
        signature = sign(self.identity.private_key, payload)
        out = dict(record)
        out["sig"] = signature.hex()
        return out

    def serialize(self) -> bytes:
        newline = "\r\n" if self.crlf else "\n"
        lines = [json.dumps(r, ensure_ascii=False, sort_keys=False) for r in self.records]
        return (newline.join(lines) + newline).encode("utf-8")

    def write(self, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(self.serialize())


def resign_in_place(record: dict[str, Any], identity: HostIdentity) -> dict[str, Any]:
    """Re-sign a modified record (used to build *legitimately* different data)."""
    body = {k: v for k, v in record.items() if k != "sig"}
    return dict(body, sig=sign(identity.private_key, canonical_json_bytes(body)).hex())


def tamper(record: dict[str, Any], **changes: Any) -> dict[str, Any]:
    """Modify a signed record *without* re-signing: produces a bad signature."""
    out = dict(record)
    out.update(changes)
    return out


__all__ = [
    "BootSession",
    "HostIdentity",
    "HostRecorder",
    "resign_in_place",
    "tamper",
]
