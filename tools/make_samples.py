"""Generate the project samples and their ``cases.json`` files.

Run from the project root::

    python tools/make_samples.py

The generator is deterministic (no randomness at all), so re-running it must
produce byte-identical files.  ``tests/test_samples.py`` asserts exactly that.

Scenario layout under ``samples/``
----------------------------------
``samples/main/``
    Three simulated hosts (``web01``, ``db01``, ``jump01``), two boots on
    ``web01``, a schema valid collection manifest with digests, and a case
    that exercises: partial interval overlap, a message whose receive is
    logged before the send (contradiction), duplicate collection, a tampered
    record, and an id conflict.
``samples/scenarios/``
    One focused case per required acceptance scenario:

    ``clock_rollback``   wall clock jumps back mid boot; monotonic counter does not
    ``reboot``           counters reset; cross boot order only via calibration
    ``duplicate``        same event collected twice, once byte-identical, once not
    ``send_recv``        send/receive contradiction, plus a valid pair
    ``overlap``          partially overlapping calibration windows -> concurrent
    ``core_minimal``     a 3 constraint minimal core with a 2 constraint subset

Each ``.jsonl`` file is a *signed* host event file; ``keys.txt`` lists the
test key seeds so a reader can re-verify the signatures independently.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from solution.crypto.ed25519 import sign  # noqa: E402
from solution.integrity import compute_seal  # noqa: E402
from solution.timeutil import format_rfc3339_ns  # noqa: E402
from tools.sim_agent import BootSession, HostIdentity, HostRecorder, resign_in_place  # noqa: E402

S = 1_000_000_000
MS = 1_000_000

T0 = 1_767_225_600 * S  # 2026-01-01T00:00:00Z
T0_WEB = T0 + 3_600 * S  # web01 boot at 01:00Z

# A fixed, non-secret key for the manifest seal.  It is committed on purpose:
# the samples must be reproducible by anyone reading the repository.  Real
# deployments read the key from the environment and never commit it.
SAMPLE_SEAL_KEY = b"sample-only-seal-key-not-a-secret"


def _write(path: str, data: bytes) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)
    return hashlib.sha256(data).hexdigest()


def _write_json(path: str, value) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


# ---------------------------------------------------------------------------
# main three host sample


def build_main() -> None:
    base = os.path.join(ROOT, "samples", "main")
    web = HostIdentity.from_label("web01")
    db = HostIdentity.from_label("db01")
    jump = HostIdentity.from_label("jump01")

    # --- web01, boot b1: 01:00Z, clock 2 s fast with +-100 ms calibration
    rec = HostRecorder(web)
    rec.boot("b1", offset_lo_ms=1900, offset_hi_ms=2100,
             mono_earliest_ns=1_000 * S, note="uptime at boot")
    s1 = BootSession("web01", "b1", T0_WEB, 1_000 * S, 2_000 * MS, 1900, 2100, 0)
    rec.event_at(s1, id="web01-b1-001", true_ns=T0_WEB + 10 * S, kind="local",
                 note="service started")
    rec.event_at(s1, id="web01-b1-002", true_ns=T0_WEB + 20 * S, kind="send",
                 message_id="m-101", note="request to db01")
    rec.event_at(s1, id="web01-b1-003", true_ns=T0_WEB + 40 * S, kind="recv",
                 message_id="m-102", note="reply from db01")
    # interval overlap with db01-b1-001 (see below): 40 s..41 s vs 41 s..43 s
    rec.event_at(s1, id="web01-b1-004", true_ns=T0_WEB + 55 * S, kind="local",
                 note="session closed")
    web_b1 = rec.serialize()

    # --- web01, boot b2: reboot at 02:00Z, counters reset, clock now exact
    rec = HostRecorder(web)
    rec.boot("b2", offset_lo_ms=-50, offset_hi_ms=50,
             mono_earliest_ns=5_000 * S, follows=("web01", "b1"), note="after reboot")
    s2 = BootSession("web01", "b2", T0_WEB + 3_600 * S, 5_000 * S, 0, -50, 50, 0)
    rec.event_at(s2, id="web01-b2-001", true_ns=T0_WEB + 3_610 * S, kind="local")
    rec.event_at(s2, id="web01-b2-002", true_ns=T0_WEB + 3_620 * S, kind="send",
                 message_id="m-103")
    web_b2 = rec.serialize()

    # --- db01: clock 1 s slow, calibration +-200 ms, receives then replies
    rec = HostRecorder(db)
    rec.boot("b1", offset_lo_ms=-1200, offset_hi_ms=-800,
             mono_earliest_ns=250 * S, note="uptime at boot")
    d1 = BootSession("db01", "b1", T0_WEB + 5 * S, 250 * S, -1_000 * MS, -1200, -800, 0)
    rec.event_at(d1, id="db01-b1-001", true_ns=T0_WEB + 21 * S, kind="recv",
                 message_id="m-101", note="request from web01")
    rec.event_at(d1, id="db01-b1-002", true_ns=T0_WEB + 40 * S, kind="send",
                 message_id="m-102", note="reply to web01")
    # partially overlapping windows: [41s,43s] here vs [39s,41.2s] on jump01
    rec.event_at(d1, id="db01-b1-003", true_ns=T0_WEB + 42 * S, kind="local",
                 note="audit tick")
    db_b1 = rec.serialize()

    # --- jump01: clock 5 s fast, calibration +-1 s, no relation to the others
    rec = HostRecorder(jump)
    rec.boot("b1", offset_lo_ms=4000, offset_hi_ms=6000,
             mono_earliest_ns=9_000 * S)
    j1 = BootSession("jump01", "b1", T0_WEB - 60 * S, 9_000 * S, 5_000 * MS, 4000, 6000, 0)
    rec.event_at(j1, id="jump01-b1-001", true_ns=T0_WEB + 40 * S, kind="local",
                 note="login attempt")
    rec.event_at(j1, id="jump01-b1-002", true_ns=T0_WEB + 40 * S + 200 * MS,
                 kind="local", note="second attempt 200ms later")
    rec.event_at(j1, id="jump01-b1-003", true_ns=T0_WEB + 120 * S, kind="local")
    jump_b1 = rec.serialize()

    files = {
        "host_web01_b1.jsonl": web_b1,
        "host_web01_b2.jsonl": web_b2,
        "host_db01_b1.jsonl": db_b1,
        "host_jump01_b1.jsonl": jump_b1,
    }
    digests = {name: _write(os.path.join(base, name), data) for name, data in files.items()}

    # --- duplicated collection: an identical re-copy of db01's file
    dup_name = "host_db01_b1_copy.jsonl"
    digests[dup_name] = _write(os.path.join(base, dup_name), db_b1)

    # --- tampered record: same line, changed wall clock, signature NOT redone
    tampered_name = "host_jump01_b1_tampered.jsonl"
    lines = jump_b1.decode("utf-8").splitlines()
    obj = json.loads(lines[2])
    obj["wall"] = format_rfc3339_ns(T0_WEB + 130 * S)
    lines[2] = json.dumps(obj, ensure_ascii=False)
    tampered = ("\n".join(lines) + "\n").encode("utf-8")
    digests[tampered_name] = _write(os.path.join(base, tampered_name), tampered)

    # --- id conflict: a legitimately re-signed copy of web01-b1-001 with a
    #     different sequence number (so the *content* differs, both signatures
    #     are valid).  This is the "same id, different content" evidence clash.
    conflict_name = "host_web01_b1_conflict.jsonl"
    rec = HostRecorder(web)
    # The boot record is copied verbatim from the original file (same content,
    # and Ed25519 is deterministic, so the same signature), so the *only*
    # difference in this file is the event variant below.
    rec.records = [json.loads(line) for line in web_b1.decode("utf-8").splitlines()[:2]]
    original = json.loads(web_b1.decode("utf-8").splitlines()[2])
    altered = dict(original)
    altered["seq"] = 99
    altered["note"] = "same event id, different seq (re-exported by a second tool)"
    altered = resign_in_place(altered, web)
    rec.records.append(altered)
    conflict_bytes = rec.serialize()
    digests[conflict_name] = _write(os.path.join(base, conflict_name), conflict_bytes)

    # --- manifest: one entry per collected file, including the re-copies that
    #     the acquisition tool made.  Digests prove the tool sees the same bytes.
    manifest_entries = []
    for name in (
        "host_web01_b1.jsonl",
        "host_web01_b2.jsonl",
        "host_db01_b1.jsonl",
        "host_db01_b1_copy.jsonl",
        "host_jump01_b1.jsonl",
        "host_jump01_b1_tampered.jsonl",
        "host_web01_b1_conflict.jsonl",
    ):
        path = os.path.join(base, name)
        with open(path, "rb") as handle:
            payload = handle.read()
        manifest_entries.append(
            {
                "id": name[: -len(".jsonl")],
                "path": name,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
                "host": _host_of(name),
                "role": "event-log",
            }
        )
    manifest_body = {
        "schema": "evidence-collection/manifest-v1",
        "case_id": "sample-main",
        "collector": "sim-agent/1.0 (offline test harness)",
        "collected_at": "2026-01-01T03:00:00Z",
        "notes": "Three simulated hosts. Not from real devices.",
        "sources": manifest_entries,
    }
    manifest_body["seal"] = compute_seal(manifest_body, SAMPLE_SEAL_KEY)
    _write_json(os.path.join(base, "manifest.json"), manifest_body)

    cases = {
        "schema": "evidence-reconstruction/cases-v1",
        "case_id": "sample-main",
        "seed": 20260101,
        "drift_ppm": 0,
        "manifest": "manifest.json",
        "sources": [
            {"id": entry["id"], "path": entry["path"]} for entry in manifest_entries
        ],
    }
    _write_json(os.path.join(base, "cases.json"), cases)

    keys = {
        "note": "Simulation keys only. Never use these for anything real.",
        "sources": {
            host: {
                "seed_hex": identity.seed.hex(),
                "public_key_hex": identity.public_key_hex,
            }
            for host, identity in (("web01", web), ("db01", db), ("jump01", jump))
        },
        "manifest_seal": {
            "algorithm": "hmac-sha256",
            "env": "EVIDENCE_SEAL_KEY",
            "sample_value": SAMPLE_SEAL_KEY.decode("ascii"),
        },
    }
    _write_json(os.path.join(base, "keys.json"), keys)


def _host_of(name: str) -> str:
    for host in ("web01", "db01", "jump01"):
        if name.startswith("host_" + host):
            return host
    return "unknown"


# ---------------------------------------------------------------------------
# focused scenarios


def _cases_file(directory: str, case_id: str, sources: list[str], *, seed: int = 7,
                drift_ppm: int = 0, manifest: str | None = None) -> None:
    payload = {
        "schema": "evidence-reconstruction/cases-v1",
        "case_id": case_id,
        "seed": seed,
        "drift_ppm": drift_ppm,
        "sources": [{"id": os.path.splitext(os.path.basename(p))[0], "path": p} for p in sources],
    }
    if manifest:
        payload["manifest"] = manifest
    _write_json(os.path.join(directory, "cases.json"), payload)


def scenario_clock_rollback(directory: str) -> None:
    """The window's clock jumps 30 s backwards; monotonic time keeps going."""
    host = HostIdentity.from_label("web01")
    rec = HostRecorder(host)
    rec.boot("b1", offset_lo_ms=-100, offset_hi_ms=100, mono_earliest_ns=0)
    session = BootSession("web01", "b1", T0, 0, 0, -100, 100, 0)
    rec.event_at(session, id="roll-001", true_ns=T0 + 10 * S)
    rec.event_at(session, id="roll-002", true_ns=T0 + 20 * S)
    # At true +25 s the administrator sets the clock 30 s back: the recorded
    # wall time is now 5 s *before* the previous event, while mono keeps rising.
    rec.event_at(session, id="roll-003", true_ns=T0 + 25 * S,
                 wall_override_ns=T0 + 25 * S - 30 * S)
    rec.event_at(session, id="roll-004", true_ns=T0 + 25 * S + 3 * S,
                 wall_override_ns=T0 + 28 * S - 30 * S)
    path = "host_web01_b1.jsonl"
    _write(os.path.join(directory, path), rec.serialize())
    _cases_file(directory, "scenario-clock-rollback", [path], seed=11)


def scenario_reboot(directory: str) -> None:
    """Two boots; the second declares follows.  Counters reset to 0."""
    host = HostIdentity.from_label("db01")
    rec = HostRecorder(host)
    rec.boot("b1", offset_lo_ms=-500, offset_hi_ms=500, mono_earliest_ns=0)
    b1 = BootSession("db01", "b1", T0, 0, 0, -500, 500, 0)
    rec.event_at(b1, id="reboot-b1-001", true_ns=T0 + 5 * S)
    rec.event_at(b1, id="reboot-b1-002", true_ns=T0 + 30 * S)

    rec.boot("b2", offset_lo_ms=-500, offset_hi_ms=500, mono_earliest_ns=0,
             follows=("db01", "b1"))
    b2 = BootSession("db01", "b2", T0 + 600 * S, 0, 0, -500, 500, 0)
    rec.event_at(b2, id="reboot-b2-001", true_ns=T0 + 600 * S + 2 * S)
    rec.event_at(b2, id="reboot-b2-002", true_ns=T0 + 600 * S + 7 * S)

    # A third boot whose first event is *earlier* by wall clock: only the
    # declared 'follows' can order it, and without that declaration the pair
    # would stay concurrent.  b3 declares follows b2, so ordering is provable.
    rec.boot("b3", offset_lo_ms=-500, offset_hi_ms=500, mono_earliest_ns=0,
             follows=("db01", "b2"))
    b3 = BootSession("db01", "b3", T0 + 1_200 * S, 0, 0, -500, 500, 0)
    rec.event_at(b3, id="reboot-b3-001", true_ns=T0 + 1_200 * S)
    path = "host_db01.jsonl"
    _write(os.path.join(directory, path), rec.serialize())
    _cases_file(directory, "scenario-reboot", [path], seed=13)


def scenario_duplicate(directory: str) -> None:
    """Three copies of one event: identical, identical, content-changed."""
    host = HostIdentity.from_label("jump01")
    rec = HostRecorder(host)
    rec.boot("b1", offset_lo_ms=0, offset_hi_ms=0, mono_earliest_ns=0)
    session = BootSession("jump01", "b1", T0, 0, 0, 0, 0, 0)
    rec.event_at(session, id="dup-001", true_ns=T0 + S)
    rec.event_at(session, id="dup-002", true_ns=T0 + 2 * S)
    first = rec.serialize()

    # Second collection pass: same content, different bytes around it
    # (the agent re-exported with CRLF line endings).
    rec_crlf = HostRecorder(host, crlf=True)
    rec_crlf.records = list(rec.records)
    second = rec_crlf.serialize()

    # Third export: dup-001 has a genuinely different sequence number, re-signed
    # legitimately.  Different content -> evidence conflict, not a duplicate.
    third_rec = HostRecorder(host)
    third_rec.records = list(rec.records)
    altered = dict(third_rec.records[2])
    altered["seq"] = 5
    third_rec.records[2] = resign_in_place(altered, host)
    third = third_rec.serialize()

    _write(os.path.join(directory, "pass1.jsonl"), first)
    _write(os.path.join(directory, "pass2_crlf.jsonl"), second)
    _write(os.path.join(directory, "pass3_altered.jsonl"), third)
    _cases_file(directory, "scenario-duplicate",
                ["pass1.jsonl", "pass2_crlf.jsonl", "pass3_altered.jsonl"], seed=17)


def scenario_send_recv(directory: str) -> None:
    """One valid message pair and one impossible one."""
    web = HostIdentity.from_label("web01")
    db = HostIdentity.from_label("db01")
    rec_web = HostRecorder(web)
    rec_web.boot("b1", offset_lo_ms=0, offset_hi_ms=0, mono_earliest_ns=0)
    w = BootSession("web01", "b1", T0, 0, 0, 0, 0, 0)
    # valid pair: send at +10 s on web, receive at +11 s on db
    rec_web.event_at(w, id="sr-web-send-ok", true_ns=T0 + 10 * S, kind="send", message_id="m-ok")
    # contradiction: the reply is *sent* 5 s before it is *received*
    rec_web.event_at(w, id="sr-web-recv-bad", true_ns=T0 + 15 * S, kind="recv", message_id="m-bad")
    rec_web.event_at(w, id="sr-web-local", true_ns=T0 + 30 * S)

    rec_db = HostRecorder(db)
    rec_db.boot("b1", offset_lo_ms=0, offset_hi_ms=0, mono_earliest_ns=0)
    d = BootSession("db01", "b1", T0, 0, 0, 0, 0, 0)
    rec_db.event_at(d, id="sr-db-recv-ok", true_ns=T0 + 11 * S, kind="recv", message_id="m-ok")
    rec_db.event_at(d, id="sr-db-send-bad", true_ns=T0 + 20 * S, kind="send", message_id="m-bad")

    _write(os.path.join(directory, "host_web01.jsonl"), rec_web.serialize())
    _write(os.path.join(directory, "host_db01.jsonl"), rec_db.serialize())
    _cases_file(directory, "scenario-send-recv", ["host_web01.jsonl", "host_db01.jsonl"], seed=19)


def scenario_overlap(directory: str) -> None:
    """Two hosts whose calibration windows overlap without ordering each other."""
    web = HostIdentity.from_label("web01")
    db = HostIdentity.from_label("db01")
    # web sees the event at +10.000 s with a +-1500 ms calibration
    rec_web = HostRecorder(web)
    rec_web.boot("b1", offset_lo_ms=-1500, offset_hi_ms=1500, mono_earliest_ns=0)
    w = BootSession("web01", "b1", T0, 0, 0, -1500, 1500, 0)
    rec_web.event_at(w, id="ovl-web-001", true_ns=T0 + 10 * S)
    # db sees *its* event at +11.000 s with its own +-1500 ms window
    rec_db = HostRecorder(db)
    rec_db.boot("b1", offset_lo_ms=-1500, offset_hi_ms=1500, mono_earliest_ns=0)
    d = BootSession("db01", "b1", T0, 0, 0, -1500, 1500, 0)
    rec_db.event_at(d, id="ovl-db-001", true_ns=T0 + 11 * S)

    _write(os.path.join(directory, "host_web01.jsonl"), rec_web.serialize())
    _write(os.path.join(directory, "host_db01.jsonl"), rec_db.serialize())
    _cases_file(directory, "scenario-overlap", ["host_web01.jsonl", "host_db01.jsonl"], seed=23)


def scenario_core_minimal(directory: str) -> None:
    """A contradiction whose minimal core is two constraints, not five.

    web01-b1-002 sends m-1; db01-b1-002 receives it.
    db01-b1-001 is *before* the receive by sequence; web01-b1-001 is after the
    send.  A second message makes db01-b1-001 strictly before web01-b1-001
    *and* web01-b1-001 before db01-b1-001 via the wall windows, so the core
    contains only the two message/sequence constraints that actually clash.
    """
    web = HostIdentity.from_label("web01")
    db = HostIdentity.from_label("db01")

    rec_web = HostRecorder(web)
    rec_web.boot("b1", offset_lo_ms=0, offset_hi_ms=0, mono_earliest_ns=0)
    w = BootSession("web01", "b1", T0, 0, 0, 0, 0, 0)
    rec_web.event_at(w, id="core-web-001", true_ns=T0 + 10 * S, kind="send", message_id="m-a")
    rec_web.event_at(w, id="core-web-002", true_ns=T0 + 20 * S, kind="send", message_id="m-b")

    rec_db = HostRecorder(db)
    rec_db.boot("b1", offset_lo_ms=0, offset_hi_ms=0, mono_earliest_ns=0)
    d = BootSession("db01", "b1", T0, 0, 0, 0, 0, 0)
    rec_db.event_at(d, id="core-db-001", true_ns=T0 + 15 * S, kind="recv", message_id="m-b")
    rec_db.event_at(d, id="core-db-002", true_ns=T0 + 25 * S, kind="recv", message_id="m-a")

    _write(os.path.join(directory, "host_web01.jsonl"), rec_web.serialize())
    _write(os.path.join(directory, "host_db01.jsonl"), rec_db.serialize())
    _cases_file(directory, "scenario-core-minimal", ["host_web01.jsonl", "host_db01.jsonl"], seed=29)


SCENARIOS = {
    "clock_rollback": scenario_clock_rollback,
    "reboot": scenario_reboot,
    "duplicate": scenario_duplicate,
    "send_recv": scenario_send_recv,
    "overlap": scenario_overlap,
    "core_minimal": scenario_core_minimal,
}


def main(quiet: bool = False) -> int:
    build_main()
    for name, builder in SCENARIOS.items():
        directory = os.path.join(ROOT, "samples", "scenarios", name)
        builder(directory)
        if not quiet:
            print(f"wrote samples/scenarios/{name}")
    if not quiet:
        print("wrote samples/main")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
