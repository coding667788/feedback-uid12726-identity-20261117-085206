"""Byte level integrity helpers: hashing, canonical JSON and the optional
tamper-evident seal around the collection manifest.

The manifest seal uses HMAC-SHA256 with a key supplied through the
environment (``EVIDENCE_SEAL_KEY``).  The key is deliberately *not* stored in
the project: without it the seal is only a self consistency marker, and the
tool says so.  This is the documented boundary between "proves the bytes did
not change since the tooling that sealed them" (HMAC with a key you control)
and "proves the host produced them" (per record host signatures).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

SEAL_KEY_ENV = "EVIDENCE_SEAL_KEY"
SEAL_ALG = "hmac-sha256"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    """Deterministic JSON encoding used for hashing and for the seal."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def manifest_digest(body: dict[str, Any]) -> str:
    """Digest of the manifest body (everything except ``seal``)."""
    return sha256_bytes(canonical_json_bytes(body))


def compute_seal(body: dict[str, Any], key: bytes) -> str:
    mac = hmac.new(key, canonical_json_bytes(body), hashlib.sha256)
    return f"{SEAL_ALG}:{mac.hexdigest()}"


def verify_seal(body: dict[str, Any], seal: str, key: bytes) -> bool:
    if not isinstance(seal, str) or not seal.startswith(SEAL_ALG + ":"):
        return False
    expected = compute_seal(body, key)
    return hmac.compare_digest(expected, seal)


def encode_line_ns(value: int) -> int:
    """Helper kept for symmetry with :mod:`solution.timeutil`."""
    return int(value)
