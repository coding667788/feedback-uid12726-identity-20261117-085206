"""Test helpers: paths, fixed keys, and a tiny harness for building cases.

Nothing here touches the network or any path outside the project.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from solution.crypto.ed25519 import (  # noqa: E402
    private_key_from_seed,
    public_key_from_private,
    sign,
)
from solution.integrity import canonical_json_bytes  # noqa: E402
from solution.timeutil import format_rfc3339_ns  # noqa: E402

S = 1_000_000_000
MS = 1_000_000
BASE = 1_767_225_600 * S  # 2026-01-01T00:00:00Z

# Fixed seeds: every test that needs a signature uses these, so failures are
# reproducible byte for byte.
SEED_H1 = bytes.fromhex("11" * 32)
SEED_H2 = bytes.fromhex("22" * 32)
SEED_H3 = bytes.fromhex("33" * 32)


def public_key(seed: bytes) -> str:
    return public_key_from_private(private_key_from_seed(seed)).hex()


def sign_record(record: dict, seed: bytes) -> dict:
    body = {k: v for k, v in record.items() if k != "sig"}
    return dict(body, sig=sign(private_key_from_seed(seed), canonical_json_bytes(body)).hex())


class CaseBuilder:
    """Builds one signed event file in memory, then writes a case directory."""

    def __init__(self, host: str, seed: bytes, *, newline: str = "\n") -> None:
        self.host = host
        self.seed = seed
        self.newline = newline
        self.lines: list[str] = []
        self.add_host_key()

    def add_host_key(self) -> "CaseBuilder":
        record = {"type": "host_key", "host": self.host, "public_key": public_key(self.seed)}
        self.lines.append(json.dumps(record, sort_keys=False))
        return self

    def boot(self, boot_id: str, *, offset_lo_ms: int = -100, offset_hi_ms: int = 100,
             mono_earliest_ns: int = 0, follows: tuple[str, str] | None = None,
             drift_ppm: int | None = None, sig: str | None = None) -> "CaseBuilder":
        record = {
            "type": "boot",
            "host": self.host,
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
        self.lines.append(json.dumps(self._sign(record), sort_keys=False))
        return self

    def event(self, event_id: str, boot_id: str, seq: int, mono_ns: int,
              wall_ns: int, *, kind: str = "local", message_id: str | None = None,
              sign_it: bool = True) -> "CaseBuilder":
        record = {
            "type": "event",
            "id": event_id,
            "host": self.host,
            "boot_id": boot_id,
            "seq": seq,
            "mono_ns": mono_ns,
            "wall": format_rfc3339_ns(wall_ns),
            "kind": kind,
        }
        if message_id is not None:
            record["message_id"] = message_id
        self.lines.append(json.dumps(self._sign(record) if sign_it else record, sort_keys=False))
        return self

    def raw_line(self, text: str) -> "CaseBuilder":
        self.lines.append(text)
        return self

    def _sign(self, record: dict) -> dict:
        return sign_record(record, self.seed)

    def render(self) -> bytes:
        text = self.newline.join(self.lines) + self.newline
        return text.encode("utf-8")


class CaseDir:
    """A temporary directory holding sources plus ``cases.json``."""

    def __init__(self, testcase: unittest.TestCase) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="evidence-case-")
        testcase.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name
        self._stem = 0

    def write(self, name: str, data: bytes) -> str:
        path = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def write_json(self, name: str, value) -> str:
        return self.write(name, json.dumps(value, indent=2).encode("utf-8") + b"\n")

    def cases(self, sources: list[str], *, case_id: str = "test",
              drift_ppm: int = 0, manifest: str | None = None,
              seed: int = 0) -> str:
        payload = {
            "schema": "evidence-reconstruction/cases-v1",
            "case_id": case_id,
            "seed": seed,
            "drift_ppm": drift_ppm,
            "sources": [
                {"id": os.path.splitext(os.path.basename(p))[0], "path": p} for p in sources
            ],
        }
        if manifest is not None:
            payload["manifest"] = manifest
        return self.write_json("cases.json", payload)

    def path(self, name: str) -> str:
        return os.path.join(self.dir, name)


def sha256_file(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def load_json(path: str):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def pair(result: dict, a: str, b: str) -> dict:
    for entry in result["order"]["pairwise"]:
        if entry["a"] == a and entry["b"] == b:
            return entry
    raise AssertionError(f"pair ({a}, {b}) not in result")


def codes(result: dict) -> list[str]:
    return [d["code"] for d in result["diagnostics"]]


def timeline_event(result: dict, event_id: str) -> dict:
    for entry in result["timeline"]:
        if entry["id"] == event_id:
            return entry
    raise AssertionError(f"event {event_id} not in timeline")


class TempDirMixin(unittest.TestCase):
    def make_case_dir(self) -> CaseDir:
        return CaseDir(self)
