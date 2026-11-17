"""Collection manifest: what was collected, from where, and its digests.

The manifest is the acquisition record a responder would file alongside the
raw event files.  It lists every collected file with its expected SHA-256 and
size, so the reconstruction tool can prove that the bytes it analysed are the
bytes that were collected.

Optional seal
-------------
A manifest may carry ``seal`` = ``hmac-sha256:<hex>`` over its canonical body
(everything except ``seal``), keyed by ``EVIDENCE_SEAL_KEY``.  With the key,
the seal detects edits to the manifest.  Without the key (or without a seal)
the tool says so explicitly: a manifest is an *index*, not an attestation.
Record level authenticity comes from the per host Ed25519 signatures.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from .errors import Diagnostic, ToolError
from .integrity import SEAL_KEY_ENV, SEAL_ALG, canonical_json_bytes, compute_seal, sha256_bytes
from .timeutil import TimestampError, parse_rfc3339_ns

MANIFEST_SCHEMA = "evidence-collection/manifest-v1"


@dataclass
class ManifestEntry:
    id: str
    path: str
    sha256: str | None
    size: int | None
    host: str | None
    role: str | None

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "path": self.path,
            "sha256": self.sha256,
            "bytes": self.size,
            "host": self.host,
            "role": self.role,
        }


@dataclass
class Manifest:
    path: str
    schema: str
    case_id: str | None
    collector: str | None
    collected_at: str | None
    collected_at_ns: int | None
    notes: str | None
    entries: list[ManifestEntry]
    seal: str | None
    seal_state: str
    raw: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "schema": self.schema,
            "case_id": self.case_id,
            "collector": self.collector,
            "collected_at": self.collected_at,
            "notes": self.notes,
            "sources": [e.to_json() for e in self.entries],
            "seal": self.seal,
            "seal_state": self.seal_state,
        }


def parse_manifest_bytes(data: bytes, path: str, key: bytes | None) -> tuple[Manifest, list[Diagnostic]]:
    diagnostics: list[Diagnostic] = []
    try:
        raw = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ToolError("E_INPUT_JSON", f"manifest {path} is not valid JSON: {exc}") from None
    if not isinstance(raw, dict):
        raise ToolError("E_INPUT_SCHEMA", f"manifest {path} must be a JSON object")
    schema = raw.get("schema", MANIFEST_SCHEMA)
    if schema != MANIFEST_SCHEMA:
        raise ToolError(
            "E_INPUT_SCHEMA",
            f"manifest {path} has unsupported schema {schema!r} (expected {MANIFEST_SCHEMA})",
        )
    sources = raw.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ToolError("E_INPUT_SCHEMA", f"manifest {path} needs a non-empty 'sources' array")
    entries: list[ManifestEntry] = []
    seen: set[str] = set()
    for index, item in enumerate(sources):
        if not isinstance(item, dict):
            raise ToolError("E_INPUT_SCHEMA", f"manifest {path} sources[{index}] must be an object")
        source_id = item.get("id")
        source_path = item.get("path")
        if not isinstance(source_id, str) or not source_id:
            raise ToolError("E_INPUT_SCHEMA", f"manifest {path} sources[{index}] has no id")
        if not isinstance(source_path, str) or not source_path:
            raise ToolError("E_INPUT_SCHEMA", f"manifest {path} sources[{index}] has no path")
        if source_id in seen:
            raise ToolError("E_INPUT_SCHEMA", f"manifest {path} repeats source id {source_id!r}")
        seen.add(source_id)
        digest = item.get("sha256")
        if digest is not None and (not isinstance(digest, str) or len(digest) != 64):
            raise ToolError("E_INPUT_SCHEMA", f"manifest {path} sources[{index}].sha256 must be 64 hex chars")
        if digest is not None:
            try:
                bytes.fromhex(digest)
            except ValueError:
                raise ToolError("E_INPUT_SCHEMA", f"manifest {path} sources[{index}].sha256 is not hex") from None
        size = item.get("bytes")
        if size is not None and (isinstance(size, bool) or not isinstance(size, int) or size < 0):
            raise ToolError("E_INPUT_SCHEMA", f"manifest {path} sources[{index}].bytes must be a non-negative integer")
        entries.append(
            ManifestEntry(
                id=source_id,
                path=source_path,
                sha256=digest,
                size=size,
                host=item.get("host") if isinstance(item.get("host"), str) else None,
                role=item.get("role") if isinstance(item.get("role"), str) else None,
            )
        )

    collected_at = raw.get("collected_at")
    collected_ns = None
    if collected_at is not None:
        if not isinstance(collected_at, str):
            raise ToolError("E_INPUT_SCHEMA", f"manifest {path} collected_at must be a string")
        try:
            collected_ns = parse_rfc3339_ns(collected_at)
        except TimestampError as exc:
            raise ToolError("E_INPUT_SCHEMA", f"manifest {path} collected_at is invalid: {exc}") from None

    seal = raw.get("seal")
    seal_state = "absent"
    if seal is not None:
        if not isinstance(seal, str):
            raise ToolError("E_INPUT_SCHEMA", f"manifest {path} seal must be a string")
        body = {k: v for k, v in raw.items() if k != "seal"}
        if not seal.startswith(SEAL_ALG + ":"):
            seal_state = "unsupported"
        elif key is None:
            seal_state = "unverified_no_key"
            diagnostics.append(
                Diagnostic(
                    code="E_SEAL_UNVERIFIED",
                    message=(
                        f"manifest {path} carries a seal but {SEAL_KEY_ENV} is not set; "
                        "the seal is recorded but not checked"
                    ),
                    detail={"seal_algorithm": SEAL_ALG},
                )
            )
        else:
            expected = compute_seal(body, key)
            seal_state = "valid" if expected == seal else "invalid"
            if seal_state == "invalid":
                diagnostics.append(
                    Diagnostic(
                        code="E_SEAL_INVALID",
                        message=f"manifest {path} seal does not match its body",
                        detail={"expected": expected, "found": seal},
                    )
                )
    manifest = Manifest(
        path=path,
        schema=schema,
        case_id=raw.get("case_id") if isinstance(raw.get("case_id"), str) else None,
        collector=raw.get("collector") if isinstance(raw.get("collector"), str) else None,
        collected_at=collected_at,
        collected_at_ns=collected_ns,
        notes=raw.get("notes") if isinstance(raw.get("notes"), str) else None,
        entries=entries,
        seal=seal,
        seal_state=seal_state,
        raw=body_of(raw),
    )
    return manifest, diagnostics


def body_of(raw: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in raw.items() if k != "seal"}


def load_manifest(path: str, key: bytes | None) -> tuple[Manifest, list[Diagnostic]]:
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except FileNotFoundError:
        raise ToolError("E_INPUT_MISSING", f"manifest not found: {path}") from None
    except OSError as exc:
        raise ToolError("E_INPUT_IO", f"manifest could not be read: {exc.strerror or exc}") from None
    return parse_manifest_bytes(data, path, key)


def manifest_key_from_env() -> bytes | None:
    value = os.environ.get(SEAL_KEY_ENV)
    if not value:
        return None
    return value.encode("utf-8")


def digest_of_manifest_body(manifest: Manifest) -> str:
    return sha256_bytes(canonical_json_bytes(manifest.raw))
